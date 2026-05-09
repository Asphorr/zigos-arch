// Kernel-side wrapper around UEFI RuntimeServices.SetVariable, used to
// write LastBootStatus and LastCrashFp back to NVRAM after the bootloader
// has handed off. Mirrors `uefi/nvram.zig` (bootloader-side) — same
// vendor GUID, same variable names, same on-disk layout.
//
// Why kernel-side: the bootloader marks every boot as `in_progress`. Only
// the kernel knows whether boot actually succeeded or crashed, so the
// kernel must write `success` after reaching its boot-complete milestone
// and `crashed` from its panic handler. Without this, the bootloader's
// "previous boot didn't complete → fall back to Safe" recovery logic
// would trigger every single boot.
//
// We deliberately don't import `std.os.uefi` here — the kernel target is
// freestanding x86_64, and pulling UEFI types in tends to drag along
// other things. Instead we mirror just the fields we need from the
// RuntimeServices table at their UEFI-spec offsets, casting from a u64
// pointer the bootloader stashes in BootInfo.

const std = @import("std");
const boot_info_mod = @import("boot_info.zig");

// Microsoft x64 calling convention — UEFI on x86_64 uses MS ABI.
// In Zig 0.15.2 CallingConvention is a tagged union; the win64 variant
// carries CommonOptions which we leave at defaults.
const cc: std.builtin.CallingConvention = .{ .x86_64_win = .{} };

// 16-byte UEFI GUID. MUST match `uefi/nvram.zig:ZIGOS_VENDOR_GUID` exactly.
const Guid = extern struct {
    time_low: u32 align(8),
    time_mid: u16,
    time_high_and_version: u16,
    clock_seq_high_and_reserved: u8,
    clock_seq_low: u8,
    node: [6]u8,
};

const VENDOR_GUID = Guid{
    .time_low = 0x4F676953,
    .time_mid = 0x5A53,
    .time_high_and_version = 0x723A,
    .clock_seq_high_and_reserved = 0x63,
    .clock_seq_low = 0x68,
    .node = [_]u8{ 0x76, 0x69, 0x76, 0x6D, 0x00, 0x01 },
};

// VariableAttributes bit flags from the UEFI spec.
const ATTR_NON_VOLATILE: u32 = 0x01;
const ATTR_BOOTSERVICE_ACCESS: u32 = 0x02;
const ATTR_RUNTIME_ACCESS: u32 = 0x04;
const ATTRS_PERSIST: u32 = ATTR_NON_VOLATILE | ATTR_BOOTSERVICE_ACCESS | ATTR_RUNTIME_ACCESS;

// Header that prefixes every UEFI services table — 24 bytes, layout
// fixed by spec.
const TableHeader = extern struct {
    signature: u64,
    revision: u32,
    header_size: u32,
    crc32: u32,
    _reserved: u32,
};

// Minimal mirror of the UEFI RuntimeServices table. ALL preceding fields
// must be sized correctly so `_getVariable` and `_setVariable` land at
// the spec-mandated offsets. We only declare types for the function
// pointers we actually call; the rest are stored as opaque `usize`.
const RuntimeServices = extern struct {
    hdr: TableHeader,
    _getTime: usize,
    _setTime: usize,
    _getWakeupTime: usize,
    _setWakeupTime: usize,
    _setVirtualAddressMap: usize,
    _convertPointer: usize,
    _getVariable: *const fn (
        var_name: [*:0]const u16,
        vendor_guid: *const Guid,
        attributes: ?*u32,
        data_size: *usize,
        data: ?[*]u8,
    ) callconv(cc) usize,
    _getNextVariableName: usize,
    _setVariable: *const fn (
        var_name: [*:0]const u16,
        vendor_guid: *const Guid,
        attributes: u32,
        data_size: usize,
        data: [*]const u8,
    ) callconv(cc) usize,
    _getNextHighMonotonicCount: usize,
    _resetSystem: usize,
    _updateCapsule: usize,
    _queryCapsuleCapabilities: usize,
    _queryVariableInfo: usize,
};

var rs_ptr: ?*const RuntimeServices = null;

/// Status values matching `uefi/nvram.zig:BootStatus`. Kept in sync by hand.
pub const STATUS_UNKNOWN: u8 = 0;
pub const STATUS_IN_PROGRESS: u8 = 1;
pub const STATUS_SUCCESS: u8 = 2;
pub const STATUS_CRASHED: u8 = 3;

const NAME_BOOT_STATUS = std.unicode.utf8ToUtf16LeStringLiteral("ZigOSBootStatus");
const NAME_CRASH_FP = std.unicode.utf8ToUtf16LeStringLiteral("ZigOSCrashFp");
const NAME_BOOT_HISTORY = std.unicode.utf8ToUtf16LeStringLiteral("ZigOSBootHistory");

// --- Boot history ring mirror ------------------------------------------
//
// MUST stay byte-identical to `uefi/nvram.zig:BootHistoryRing` — both
// sides read/write the same NVRAM variable. Field reordering is a
// breaking change.

pub const HISTORY_MAGIC: u32 = 0x52494E47;
pub const HISTORY_DEPTH: u32 = 8;
pub const HISTORY_FP_CAP: u32 = 40;

pub const BootHistoryEntry = extern struct {
    bootloader_build_id: u64,
    kernel_build_id: u64,
    mode: u32,
    outcome: u8,
    crash_fp_len: u8,
    _pad: [2]u8 = .{ 0, 0 },
    crash_fp: [HISTORY_FP_CAP]u8,
};

comptime {
    if (@sizeOf(BootHistoryEntry) != 64) @compileError("BootHistoryEntry must be 64 bytes");
}

pub const BootHistoryRing = extern struct {
    magic: u32 = HISTORY_MAGIC,
    next: u32 = 0,
    entries: [HISTORY_DEPTH]BootHistoryEntry,
};

comptime {
    if (@sizeOf(BootHistoryRing) != 520) @compileError("BootHistoryRing must be 520 bytes");
}

// UEFI status code we treat as success (EFI_SUCCESS = 0).
const EFI_SUCCESS: usize = 0;

/// Read the ring from NVRAM into `out`. Returns true on success + magic
/// match; false on any UEFI error or magic mismatch (caller treats as
/// "no ring yet").
fn historyReadInto(out: *BootHistoryRing) bool {
    if (!rsCallable()) return false;
    const rs = rs_ptr.?;
    var size: usize = @sizeOf(BootHistoryRing);
    const buf: [*]u8 = @ptrCast(out);
    const status = rs._getVariable(NAME_BOOT_HISTORY, &VENDOR_GUID, null, &size, buf);
    if (status != EFI_SUCCESS) return false;
    if (size != @sizeOf(BootHistoryRing)) return false;
    if (out.magic != HISTORY_MAGIC) return false;
    return true;
}

fn historyWrite(ring: *const BootHistoryRing) void {
    if (!rsCallable()) return;
    const rs = rs_ptr.?;
    const buf: [*]const u8 = @ptrCast(ring);
    _ = rs._setVariable(NAME_BOOT_HISTORY, &VENDOR_GUID, ATTRS_PERSIST, @sizeOf(BootHistoryRing), buf);
}

/// Mutate the most-recent entry in the ring to record this boot's
/// outcome. Called from kmain at the success milestone with
/// (STATUS_SUCCESS, kernel_build_id, "") and from the panic handler with
/// (STATUS_CRASHED, kernel_build_id, fingerprint).
///
/// No-op if the ring doesn't exist (first boot of a kernel against an
/// older bootloader that hasn't pushed an entry yet) — callers also
/// continue writing the legacy singletons so behavior degrades gracefully.
pub fn historyMarkCurrent(status: u8, kernel_build_id: u64, fp: []const u8) void {
    if (rs_ptr == null) return;
    var ring: BootHistoryRing = undefined;
    if (!historyReadInto(&ring)) return;
    if (ring.next == 0) return;
    const idx: usize = @intCast((@as(u64, ring.next) -% 1) % HISTORY_DEPTH);
    ring.entries[idx].outcome = status;
    ring.entries[idx].kernel_build_id = kernel_build_id;
    const n = @min(fp.len, @as(usize, HISTORY_FP_CAP));
    ring.entries[idx].crash_fp_len = @intCast(n);
    var i: usize = 0;
    while (i < HISTORY_FP_CAP) : (i += 1) {
        ring.entries[idx].crash_fp[i] = if (i < n) fp[i] else 0;
    }
    historyWrite(&ring);
}

/// Initialize from BootInfo. Must be called once before any setBootStatus /
/// setCrashFp call; otherwise those calls become no-ops. Multiboot path
/// passes `runtime_services_addr = 0` so this stays disabled.
pub fn init(boot_info: *const boot_info_mod.BootInfo) void {
    if (boot_info.runtime_services_addr == 0) return;
    rs_ptr = @ptrFromInt(boot_info.runtime_services_addr);
}

pub fn isAvailable() bool {
    return rs_ptr != null;
}

/// True iff `rs_ptr` is still callable. UEFI runtime services live at a
/// low VA (firmware identity map) and the function pointers inside the
/// table also point at low-VA code. After `paging.dropLowIdentity` runs
/// in `desktop.taskEntry` (Phase 3), accessing them traps.
///
/// Without this gate the panic handler's NVRAM write at `main.panic`
/// would secondary-fault here and swallow the primary panic message —
/// invaluable for debugging real-HW crashes you can't reproduce in QEMU.
fn rsCallable() bool {
    const rs = rs_ptr orelse return false;
    const paging = @import("../mm/paging.zig");
    const rs_addr = @intFromPtr(rs);
    if (!paging.isMapped(rs_addr)) return false;
    // Also check the function-pointer slot we're about to call — the
    // UEFI table itself can be mapped while a callsite reaches a
    // function whose code page got unmapped. Pick offset 0x88
    // (SetVariable) since both setBootStatus and historyMarkCurrent
    // need it; if it's reachable, GetVariable at 0x48 typically is too
    // (same EFI runtime code segment).
    return paging.isMapped(rs_addr + 0x88);
}

fn writeRaw(name: [*:0]const u16, data: []const u8) void {
    if (!rsCallable()) return;
    const rs = rs_ptr.?;
    _ = rs._setVariable(name, &VENDOR_GUID, ATTRS_PERSIST, data.len, data.ptr);
}

/// Mark this boot as completed successfully. Call once when the kernel
/// reaches a milestone we'd consider "boot done" (typically right before
/// handing control to the desktop init task). Writes a single byte.
pub fn setBootStatus(status: u8) void {
    const buf = [1]u8{status};
    writeRaw(NAME_BOOT_STATUS, &buf);
}

/// Persist the crash fingerprint string emitted by kdbg.crashSummary so
/// the next boot's menu can show "Last boot: CRASHED in handleIRQ0+0x33BC".
/// Caller passes the raw `[crash-fp] ...` line; we trim/cap to 256 bytes.
pub fn setCrashFp(fp: []const u8) void {
    const trimmed = fp[0..@min(fp.len, 256)];
    writeRaw(NAME_CRASH_FP, trimmed);
}
