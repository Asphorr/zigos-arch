// UEFI NVRAM persistence for ZigOS boot state.
//
// Uses UEFI Runtime Services (GetVariable/SetVariable) to store a small
// number of boot-time variables under the ZigOS vendor GUID. NVRAM is
// backed by OVMF's `ovmf_vars.fd` in our QEMU setup, by real firmware
// flash on bare metal — survives reboots and even power-off in both cases.
//
// Why: the boot menu used to forget what you picked the second you closed
// QEMU. With NVRAM-backed state we get:
//   1. Last-used boot mode auto-selected on the menu
//   2. Last-boot status (in_progress / success / crashed) so a crashing
//      kernel boots into Safe mode automatically next time
//   3. Last-crash fingerprint visible on the menu without serial.log
//
// This module is bootloader-side. The kernel-side equivalent (writing
// LastBootStatus = success after kmain finishes, or `crashed` from the
// panic handler) needs the runtime_services pointer plumbed through
// BootInfo — see Phase 2.
//
// All variables use NON_VOLATILE | BOOTSERVICE_ACCESS | RUNTIME_ACCESS
// so they're readable from both the bootloader (pre-ExitBootServices)
// and the kernel (post-ExitBootServices).

const std = @import("std");
const uefi = std.os.uefi;
const Guid = uefi.Guid;
const RuntimeServices = uefi.tables.RuntimeServices;

/// ZigOS vendor GUID. Hand-picked, not registered with anyone — collisions
/// would only matter if some other UEFI app on the same machine used the
/// same GUID, which is exceedingly unlikely. The bytes spell "ZigOS:rchvivm"
/// in ASCII (sort of) so it's recognizable in OVMF debug dumps.
pub const ZIGOS_VENDOR_GUID = Guid{
    .time_low = 0x4F676953, // 'ZigO' little-endian → SigZ → 0x4F676953 little is 'OgiZ'... we just need a unique value
    .time_mid = 0x5A53,
    .time_high_and_version = 0x723A,
    .clock_seq_high_and_reserved = 0x63,
    .clock_seq_low = 0x68,
    .node = [_]u8{ 0x76, 0x69, 0x76, 0x6D, 0x00, 0x01 },
};

const ATTRS_PERSIST = RuntimeServices.VariableAttributes{
    .non_volatile = true,
    .bootservice_access = true,
    .runtime_access = true,
};

// Variable names (UTF-16 little-endian, null-terminated). `String` literal
// helper from std.unicode produces the right shape for UEFI's [*:0]const u16.
const NAME_BOOT_MODE = std.unicode.utf8ToUtf16LeStringLiteral("ZigOSBootMode");
const NAME_BOOT_STATUS = std.unicode.utf8ToUtf16LeStringLiteral("ZigOSBootStatus");
const NAME_BOOT_TIMESTAMP = std.unicode.utf8ToUtf16LeStringLiteral("ZigOSBootTime");
const NAME_CRASH_FP = std.unicode.utf8ToUtf16LeStringLiteral("ZigOSCrashFp");
const NAME_CMDLINE = std.unicode.utf8ToUtf16LeStringLiteral("ZigOSCmdline");
const NAME_BOOT_HISTORY = std.unicode.utf8ToUtf16LeStringLiteral("ZigOSBootHistory");

/// Boot status enum. Stored as a single byte in NVRAM.
pub const BootStatus = enum(u8) {
    /// First boot ever, or NVRAM was reset.
    unknown = 0,
    /// Bootloader handed control to kernel; kernel never confirmed success.
    /// If we see this on entry, the previous boot wedged or crashed before
    /// it could write `success`.
    in_progress = 1,
    /// Kernel reached its "boot complete" milestone and wrote this back.
    success = 2,
    /// Kernel panic handler wrote this. Usually accompanied by a CrashFp.
    crashed = 3,
};

/// Read a u32 variable. Returns null if the variable doesn't exist (first
/// boot) or any UEFI error occurs (don't care — we just default).
pub fn readU32(rs: *RuntimeServices, name: [*:0]const u16) ?u32 {
    var buf: [4]u8 = undefined;
    const res_opt = rs.getVariable(name, &ZIGOS_VENDOR_GUID, &buf) catch return null;
    const res = res_opt orelse return null;
    if (res.@"0".len != 4) return null;
    return std.mem.readInt(u32, buf[0..4], .little);
}

pub fn writeU32(rs: *RuntimeServices, name: [*:0]const u16, value: u32) void {
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &buf, value, .little);
    rs.setVariable(name, &ZIGOS_VENDOR_GUID, ATTRS_PERSIST, &buf) catch {};
}

pub fn readU64(rs: *RuntimeServices, name: [*:0]const u16) ?u64 {
    var buf: [8]u8 = undefined;
    const res_opt = rs.getVariable(name, &ZIGOS_VENDOR_GUID, &buf) catch return null;
    const res = res_opt orelse return null;
    if (res.@"0".len != 8) return null;
    return std.mem.readInt(u64, buf[0..8], .little);
}

pub fn writeU64(rs: *RuntimeServices, name: [*:0]const u16, value: u64) void {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, value, .little);
    rs.setVariable(name, &ZIGOS_VENDOR_GUID, ATTRS_PERSIST, &buf) catch {};
}

pub fn readU8(rs: *RuntimeServices, name: [*:0]const u16) ?u8 {
    var buf: [1]u8 = undefined;
    const res_opt = rs.getVariable(name, &ZIGOS_VENDOR_GUID, &buf) catch return null;
    const res = res_opt orelse return null;
    if (res.@"0".len != 1) return null;
    return buf[0];
}

pub fn writeU8(rs: *RuntimeServices, name: [*:0]const u16, value: u8) void {
    const buf = [1]u8{value};
    rs.setVariable(name, &ZIGOS_VENDOR_GUID, ATTRS_PERSIST, &buf) catch {};
}

/// Read a fixed-cap string variable. Caller provides storage; returns the
/// number of bytes that were actually populated, or 0 on miss/error.
pub fn readString(rs: *RuntimeServices, name: [*:0]const u16, buf: []u8) usize {
    const res_opt = rs.getVariable(name, &ZIGOS_VENDOR_GUID, buf) catch return 0;
    const res = res_opt orelse return 0;
    return res.@"0".len;
}

pub fn writeString(rs: *RuntimeServices, name: [*:0]const u16, data: []const u8) void {
    rs.setVariable(name, &ZIGOS_VENDOR_GUID, ATTRS_PERSIST, data) catch {};
}

// --- High-level convenience wrappers (bootloader side) -----------------

pub fn getBootMode(rs: *RuntimeServices) u32 {
    return readU32(rs, NAME_BOOT_MODE) orelse 0;
}

pub fn setBootMode(rs: *RuntimeServices, mode: u32) void {
    writeU32(rs, NAME_BOOT_MODE, mode);
}

pub fn getBootStatus(rs: *RuntimeServices) BootStatus {
    const raw = readU8(rs, NAME_BOOT_STATUS) orelse 0;
    return std.enums.fromInt(BootStatus, raw) orelse .unknown;
}

pub fn setBootStatus(rs: *RuntimeServices, status: BootStatus) void {
    writeU8(rs, NAME_BOOT_STATUS, @intFromEnum(status));
}

pub fn getBootTimestamp(rs: *RuntimeServices) u64 {
    return readU64(rs, NAME_BOOT_TIMESTAMP) orelse 0;
}

pub fn setBootTimestamp(rs: *RuntimeServices, ts: u64) void {
    writeU64(rs, NAME_BOOT_TIMESTAMP, ts);
}

pub fn getCrashFp(rs: *RuntimeServices, buf: []u8) usize {
    return readString(rs, NAME_CRASH_FP, buf);
}

pub fn setCrashFp(rs: *RuntimeServices, fp: []const u8) void {
    writeString(rs, NAME_CRASH_FP, fp);
}

/// Kernel cmdline persisted across reboots. Returns the length actually
/// read (0 if unset). Caller passes a buffer; cap to 256 bytes is
/// recommended.
pub fn getCmdline(rs: *RuntimeServices, buf: []u8) usize {
    return readString(rs, NAME_CMDLINE, buf);
}

pub fn setCmdline(rs: *RuntimeServices, cmd: []const u8) void {
    writeString(rs, NAME_CMDLINE, cmd);
}

// --- Variable name handles (exposed for kernel-side code in Phase 2) ----
// Kernel will call setVariable directly using these names + the same GUID.

pub const var_boot_status: [*:0]const u16 = NAME_BOOT_STATUS;
pub const var_crash_fp: [*:0]const u16 = NAME_CRASH_FP;
pub const var_boot_history: [*:0]const u16 = NAME_BOOT_HISTORY;

// --- Boot history ring -------------------------------------------------
//
// A small ring of `{mode, bootloader_build_id, kernel_build_id, outcome,
// crash_fp}` records, written as a single ~520-byte UEFI variable. The
// bootloader pushes a fresh `in_progress` entry just before kernel handoff
// (so the ring captures what mode was attempted even if the kernel
// triple-faults before it can write back). The kernel mutates the
// most-recent entry in-place: success path updates outcome to `success`
// and stamps `kernel_build_id`; panic handler updates outcome to `crashed`
// and fills `crash_fp`.
//
// Why a ring rather than a single slot:
//   1. Pattern detection — three same-mode crashes in a row → escalate
//      default selection to Safe even if the user keeps picking Normal.
//   2. About-screen visibility — surfaces the last few boots so it's
//      obvious which kernel/bootloader build crashed without serial.log.
//   3. Build-id skew — comparing `bootloader_build_id` to `kernel_build_id`
//      flags running a kernel against a stale BOOTX64.efi (or vice-versa).
//
// Layout MUST stay ABI-stable across kernel/bootloader builds (both sides
// read it). Field reordering is a breaking change. New fields go in the
// `_pad` slot or a new versioned struct via `magic`.

pub const HISTORY_MAGIC: u32 = 0x52494E47; // 'GNIR' little-endian
pub const HISTORY_DEPTH: u32 = 8;
pub const HISTORY_FP_CAP: u32 = 40; // bytes; longer crash_fp is truncated

pub const BootHistoryEntry = extern struct {
    bootloader_build_id: u64,                    // bytes 0–7
    kernel_build_id: u64,                        // bytes 8–15
    mode: u32,                                   // bytes 16–19
    outcome: u8,                                 // byte 20 — BootStatus enum value
    crash_fp_len: u8,                            // byte 21 — 0..40
    _pad: [2]u8 = .{ 0, 0 },                     // bytes 22–23 (reserved for timestamps later)
    crash_fp: [HISTORY_FP_CAP]u8,                // bytes 24–63
};

comptime {
    if (@sizeOf(BootHistoryEntry) != 64) @compileError("BootHistoryEntry must be 64 bytes");
}

pub const BootHistoryRing = extern struct {
    magic: u32 = HISTORY_MAGIC,
    next: u32 = 0,                               // index where the next push will land
    entries: [HISTORY_DEPTH]BootHistoryEntry,    // ring buffer
};

comptime {
    // 8 + 8 × 64 = 520
    if (@sizeOf(BootHistoryRing) != 520) @compileError("BootHistoryRing must be 520 bytes");
}

/// Read the ring from NVRAM. Returns null if the variable doesn't exist
/// (first boot, post-`-bios-reset`, or NVRAM cleared) or if the magic
/// doesn't match (corrupted / older schema). Caller treats null as
/// "start a fresh ring".
pub fn historyRead(rs: *RuntimeServices) ?BootHistoryRing {
    var ring: BootHistoryRing = undefined;
    const buf: [*]u8 = @ptrCast(&ring);
    const slice = buf[0..@sizeOf(BootHistoryRing)];
    const res_opt = rs.getVariable(NAME_BOOT_HISTORY, &ZIGOS_VENDOR_GUID, slice) catch return null;
    const res = res_opt orelse return null;
    if (res.@"0".len != @sizeOf(BootHistoryRing)) return null;
    if (ring.magic != HISTORY_MAGIC) return null;
    return ring;
}

/// Write the entire ring back to NVRAM. UEFI vars rewrite atomically.
pub fn historyWrite(rs: *RuntimeServices, ring: *const BootHistoryRing) void {
    const buf: [*]const u8 = @ptrCast(ring);
    const slice = buf[0..@sizeOf(BootHistoryRing)];
    rs.setVariable(NAME_BOOT_HISTORY, &ZIGOS_VENDOR_GUID, ATTRS_PERSIST, slice) catch {};
}

/// Push a new entry as the current "in_progress" boot. Bootloader calls
/// this once per boot, just before handing off to the kernel. `mode` is
/// the menu-selected boot_mode; `bootloader_build_id` is the bootloader's
/// own compile-time build_id. The kernel will mutate this same slot
/// in-place to set outcome + kernel_build_id (+ crash_fp on panic).
pub fn historyPush(rs: *RuntimeServices, mode: u32, bootloader_build_id: u64) void {
    var ring: BootHistoryRing = historyRead(rs) orelse .{
        .magic = HISTORY_MAGIC,
        .next = 0,
        .entries = std.mem.zeroes([HISTORY_DEPTH]BootHistoryEntry),
    };
    const idx: usize = @intCast(ring.next % HISTORY_DEPTH);
    ring.entries[idx] = .{
        .bootloader_build_id = bootloader_build_id,
        .kernel_build_id = 0,
        .mode = mode,
        .outcome = @intFromEnum(BootStatus.in_progress),
        .crash_fp_len = 0,
        .crash_fp = std.mem.zeroes([HISTORY_FP_CAP]u8),
    };
    ring.next +%= 1;
    historyWrite(rs, &ring);
}

/// Index (0..HISTORY_DEPTH-1) of the last-written entry, or null if the
/// ring is empty. Both bootloader and kernel use this to find the
/// "current" entry for in-place mutation or display.
pub fn historyLastSlotIdx(ring: *const BootHistoryRing) ?usize {
    if (ring.next == 0) return null;
    return @intCast((ring.next -% 1) % HISTORY_DEPTH);
}

/// Walk the last `n` entries in chronological order (oldest first), invoking
/// `cb` for each. Used by the About screen to render the history list.
pub fn historyForLastN(
    ring: *const BootHistoryRing,
    n: usize,
    ctx: anytype,
    comptime cb: fn (@TypeOf(ctx), entry: *const BootHistoryEntry, position: usize) void,
) void {
    const total = @min(n, @as(usize, ring.next));
    if (total == 0) return;
    var i: usize = 0;
    while (i < total) : (i += 1) {
        const slot: usize = @intCast((@as(u64, ring.next) -% (total - i)) % HISTORY_DEPTH);
        cb(ctx, &ring.entries[slot], i);
    }
}
