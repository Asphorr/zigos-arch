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
const debug = @import("../debug/debug.zig");

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
    // UEFI RS code lives in the low-half firmware map with U/S=1 — SMEP
    // would trap the `call` to _getVariable. Drop SMEP for the call.
    const protect = @import("../cpu/arch/protect.zig");
    const saved = protect.beginNonSmepCall();
    const status = rs._getVariable(NAME_BOOT_HISTORY, &VENDOR_GUID, null, &size, buf);
    protect.endNonSmepCall(saved);
    if (status != EFI_SUCCESS) return false;
    if (size != @sizeOf(BootHistoryRing)) return false;
    if (out.magic != HISTORY_MAGIC) return false;
    return true;
}

fn historyWrite(ring: *const BootHistoryRing) void {
    if (!rsCallable()) return;
    const rs = rs_ptr.?;
    const buf: [*]const u8 = @ptrCast(ring);
    const protect = @import("../cpu/arch/protect.zig");
    const saved = protect.beginNonSmepCall();
    _ = rs._setVariable(NAME_BOOT_HISTORY, &VENDOR_GUID, ATTRS_PERSIST, @sizeOf(BootHistoryRing), buf);
    protect.endNonSmepCall(saved);
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
    const protect = @import("../cpu/arch/protect.zig");
    const saved = protect.beginNonSmepCall();
    _ = rs._setVariable(name, &VENDOR_GUID, ATTRS_PERSIST, data.len, data.ptr);
    protect.endNonSmepCall(saved);
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

// =============================================================================
// Firmware boot entries — Boot#### / BootOrder (the installer's last step)
// =============================================================================
//
// Everything above talks to OUR variables under the ZigOS vendor GUID. Boot
// entries live under the spec's EFI_GLOBAL_VARIABLE GUID and carry a
// serialized EFI_LOAD_OPTION: attributes, a UTF-16 description, and a device
// path pinning WHICH partition and WHICH file to boot. The device path is
// the part firmware actually matches on — a HD() node naming the GPT
// partition by its unique GUID, then a FILEPATH node, then an end node.
//
// CAVEAT for the QEMU workflow: run-installer.sh refreshes OVMF_VARS every
// run precisely because Boot#### entries recorded under one virtual PCI
// layout make OVMF drop to the EFI Shell under another. The entry written
// here is validated by reading it back; whether the NEXT boot consumes it
// depends on the machine keeping its layout — real hardware does, a
// reshuffled QEMU invocation does not (it falls back to \EFI\BOOT\BOOTX64.EFI,
// which the installer also provides).

/// EFI_GLOBAL_VARIABLE — 8BE4DF61-93CA-11D2-AA0D-00E098032B8C.
const GLOBAL_GUID = Guid{
    .time_low = 0x8BE4DF61,
    .time_mid = 0x93CA,
    .time_high_and_version = 0x11D2,
    .clock_seq_high_and_reserved = 0xAA,
    .clock_seq_low = 0x0D,
    .node = [_]u8{ 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C },
};

const NAME_BOOT_ORDER = std.unicode.utf8ToUtf16LeStringLiteral("BootOrder");

const EFI_ERR_BIT: usize = 1 << 63;
const EFI_NOT_FOUND: usize = EFI_ERR_BIT | 14;

const LOAD_OPTION_ACTIVE: u32 = 0x1;

/// The GPT partition a boot entry points into. `partition_guid` is the
/// entry's unique GUID in raw on-disk byte order (gpt.Partition.unique_guid).
pub const BootEntryDisk = struct {
    /// 1-based slot number, the way tools display it.
    partition_number: u32,
    partition_start: u64,
    partition_sectors: u64,
    partition_guid: [16]u8,
};

/// True when a variable of this name exists under the global GUID. Probed
/// with a zero-length read: EFI_BUFFER_TOO_SMALL = exists, EFI_NOT_FOUND =
/// free slot. Caller has checked rsCallable.
fn globalVarExists(name: [*:0]const u16) bool {
    const rs = rs_ptr.?;
    var size: usize = 0;
    const protect = @import("../cpu/arch/protect.zig");
    const saved = protect.beginNonSmepCall();
    const status = rs._getVariable(name, &GLOBAL_GUID, null, &size, null);
    protect.endNonSmepCall(saved);
    return status != EFI_NOT_FOUND;
}

/// Register a Boot#### entry for \EFI\BOOT\BOOTX64.EFI on `disk` and put it
/// at the head of BootOrder. Returns the #### index, or null with the reason
/// logged — the installer surfaces failure but does not fail the install
/// over it (the removable-media fallback path still boots the disk).
pub fn addBootEntry(description: []const u8, disk: BootEntryDisk) ?u16 {
    if (!rsCallable()) {
        debug.klog("[nvram] runtime services unreachable — no boot entry\n", .{});
        return null;
    }

    // A free Boot#### slot. 64 is far past anything OVMF or a laptop hoards.
    var name_buf: [9]u16 = .{ 'B', 'o', 'o', 't', '0', '0', '0', '0', 0 };
    var idx: u16 = 0;
    const slot: u16 = while (idx < 64) : (idx += 1) {
        fillHex16(name_buf[4..8], idx);
        const nm: [*:0]const u16 = @ptrCast(&name_buf);
        if (!globalVarExists(nm)) break idx;
    } else {
        debug.klog("[nvram] no free Boot#### slot in 0..63\n", .{});
        return null;
    };

    // --- Serialize the EFI_LOAD_OPTION ---
    var buf: [256]u8 = undefined;
    var off: usize = 0;
    std.mem.writeInt(u32, buf[off..][0..4], LOAD_OPTION_ACTIVE, .little);
    off += 4;
    const fpl_len_at = off; // FilePathListLength backpatched below
    off += 2;
    // Description: UTF-16LE, NUL-terminated.
    for (description) |c| {
        std.mem.writeInt(u16, buf[off..][0..2], c, .little);
        off += 2;
    }
    std.mem.writeInt(u16, buf[off..][0..2], 0, .little);
    off += 2;

    const fpl_start = off;
    // HD() media device path node: type 4, subtype 1, 42 bytes.
    buf[off] = 0x04;
    buf[off + 1] = 0x01;
    std.mem.writeInt(u16, buf[off + 2 ..][0..2], 42, .little);
    std.mem.writeInt(u32, buf[off + 4 ..][0..4], disk.partition_number, .little);
    std.mem.writeInt(u64, buf[off + 8 ..][0..8], disk.partition_start, .little);
    std.mem.writeInt(u64, buf[off + 16 ..][0..8], disk.partition_sectors, .little);
    @memcpy(buf[off + 24 ..][0..16], &disk.partition_guid);
    buf[off + 40] = 0x02; // partition format: GPT
    buf[off + 41] = 0x02; // signature type: GUID
    off += 42;
    // FILEPATH node: type 4, subtype 4, header + UTF-16 path incl NUL.
    const path = std.unicode.utf8ToUtf16LeStringLiteral("\\EFI\\BOOT\\BOOTX64.EFI");
    const path_bytes: u16 = @intCast((path.len + 1) * 2);
    buf[off] = 0x04;
    buf[off + 1] = 0x04;
    std.mem.writeInt(u16, buf[off + 2 ..][0..2], 4 + path_bytes, .little);
    off += 4;
    for (path) |u| {
        std.mem.writeInt(u16, buf[off..][0..2], u, .little);
        off += 2;
    }
    std.mem.writeInt(u16, buf[off..][0..2], 0, .little);
    off += 2;
    // End-of-device-path node.
    buf[off] = 0x7F;
    buf[off + 1] = 0xFF;
    std.mem.writeInt(u16, buf[off + 2 ..][0..2], 4, .little);
    off += 4;
    std.mem.writeInt(u16, buf[fpl_len_at..][0..2], @intCast(off - fpl_start), .little);

    // --- Write Boot#### ---
    const rs = rs_ptr.?;
    const protect = @import("../cpu/arch/protect.zig");
    fillHex16(name_buf[4..8], slot);
    const var_name: [*:0]const u16 = @ptrCast(&name_buf);
    var saved = protect.beginNonSmepCall();
    const st_entry = rs._setVariable(var_name, &GLOBAL_GUID, ATTRS_PERSIST, off, &buf);
    protect.endNonSmepCall(saved);
    if (st_entry != EFI_SUCCESS) {
        debug.klog("[nvram] SetVariable Boot{X:0>4} failed: 0x{X}\n", .{ slot, st_entry });
        return null;
    }

    // --- Put it first in BootOrder (keeping everything else) ---
    var order: [65]u16 = undefined;
    const order_bytes: [*]u8 = @ptrCast(&order);
    var order_size: usize = 64 * 2; // read at most 64 existing entries
    saved = protect.beginNonSmepCall();
    const st_read = rs._getVariable(NAME_BOOT_ORDER, &GLOBAL_GUID, null, &order_size, order_bytes + 2);
    protect.endNonSmepCall(saved);
    var count: usize = if (st_read == EFI_SUCCESS) order_size / 2 else 0;
    // Drop a stale occurrence of our slot, then prepend it.
    var w: usize = 1;
    var r: usize = 1;
    while (r < 1 + count) : (r += 1) {
        if (order[r] != slot) {
            order[w] = order[r];
            w += 1;
        }
    }
    count = w - 1;
    order[0] = slot;
    saved = protect.beginNonSmepCall();
    const st_write = rs._setVariable(NAME_BOOT_ORDER, &GLOBAL_GUID, ATTRS_PERSIST, (count + 1) * 2, order_bytes);
    protect.endNonSmepCall(saved);
    if (st_write != EFI_SUCCESS) {
        debug.klog("[nvram] SetVariable BootOrder failed: 0x{X}\n", .{st_write});
        return null;
    }
    debug.klog("[nvram] Boot{X:0>4} \"{s}\" registered, first in BootOrder ({d} entries)\n", .{ slot, description, count + 1 });
    return slot;
}

/// Uppercase-hex the low 16 bits of `v` into 4 UTF-16 digits.
fn fillHex16(out: []u16, v: u16) void {
    const digits = "0123456789ABCDEF";
    out[0] = digits[(v >> 12) & 0xF];
    out[1] = digits[(v >> 8) & 0xF];
    out[2] = digits[(v >> 4) & 0xF];
    out[3] = digits[v & 0xF];
}
