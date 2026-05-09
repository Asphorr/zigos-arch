//! Per-path filesystem-handle cache. Saves the disk-roundtrip-heavy
//! directory walks done by `ext2.walkPath` and `fat32.walkPath` for paths
//! that have been opened recently.
//!
//! Two levels:
//!   • L1 — per-CPU, 4 slots in `CpuLocal.path_l1`. Lockless on hit;
//!     `cli` serializes against IRQ-driven schedule on the same CPU only
//!     (the slots are private to each CPU, so no cross-CPU coordination is
//!     needed). Pattern matches `pmm_cache` magazines.
//!   • L2 — global, 32 slots, one ticket-lock. Round-robin victim. Hit
//!     here promotes into the calling CPU's L1.
//!
//! Invalidation is coarse: any FS mutation calls `invalidateAll`, which
//!   1. bumps `global_epoch` (atomic) — every existing L1 entry's stored
//!      epoch becomes stale, so they invisibly miss without per-slot writes
//!   2. clears L2 under its lock.
//! L1 doesn't need a per-CPU sweep because the epoch check at lookup time
//! filters stale entries.
//!
//! Per-FS payload conventions (caller-defined, opaque to this module):
//!   ext2 — bytes [0..4]  : u32 inum (little-endian)
//!   fat32 — bytes [0..4] : u32 dir_cluster
//!           bytes [4..8] : u32 dir_index (short_index)
//!           bytes [8..12]: u32 first_cluster
//!           bytes [12..16]: u32 file_size

const std = @import("std");
const smp = @import("../cpu/smp.zig");
const SpinLock = @import("../proc/spinlock.zig").SpinLock;

pub const FsTag = enum(u8) {
    empty = 0,
    ext2 = 1,
    fat32 = 2,
};

const L2_SIZE: usize = 32;
const PAYLOAD_BYTES: usize = 16;

const Entry = smp.PathCacheEntry;

/// Bumped on every `invalidateAll`. Each L1 entry stores the epoch at
/// insertion; lookups compare and skip mismatches. Starts at 1 so the
/// default-zero (.tag=0, .epoch=0) state never accidentally hits.
var global_epoch: u64 = 1;

var l2: [L2_SIZE]Entry = [_]Entry{.{}} ** L2_SIZE;
var l2_next: u8 = 0;
var l2_lock: SpinLock = .{};

inline fn matches(e: *const Entry, tag: FsTag, path: []const u8) bool {
    if (e.tag != @intFromEnum(tag)) return false;
    if (e.path_len != path.len) return false;
    return std.mem.eql(u8, e.path[0..e.path_len], path);
}

inline fn writeEntry(e: *Entry, tag: FsTag, path: []const u8, payload: [PAYLOAD_BYTES]u8, epoch: u64) void {
    e.tag = @intFromEnum(tag);
    e.path_len = @intCast(path.len);
    @memcpy(e.path[0..path.len], path);
    e.payload = payload;
    e.epoch = epoch;
}

/// Drop every cached entry. Call from any FS mutation that could change a
/// path → handle mapping (rename, unlink, fat32 file size change).
pub fn invalidateAll() void {
    _ = @atomicRmw(u64, &global_epoch, .Add, 1, .seq_cst);
    const flags = l2_lock.acquireIrqSave();
    defer l2_lock.releaseIrqRestore(flags);
    for (&l2) |*e| e.tag = 0;
    l2_next = 0;
}

/// Look up a (tag, path) pair. Returns the 16-byte payload the caller
/// previously inserted, or null on miss. Touches the L1 first; on miss
/// promotes from L2.
pub fn lookup(tag: FsTag, path: []const u8) ?[PAYLOAD_BYTES]u8 {
    if (path.len == 0 or path.len > smp.PATH_CACHE_PATH_MAX) return null;
    const cur_epoch = @atomicLoad(u64, &global_epoch, .acquire);

    // L1 — per-CPU. cli around the read prevents IRQ-driven schedule from
    // letting another task on this CPU repurpose a slot mid-comparison.
    var rf: u64 = undefined;
    asm volatile ("pushfq\npopq %[rf]\ncli"
        : [rf] "=r" (rf),
        :
        : .{ .memory = true, .cc = true });
    {
        const cpu = smp.myCpu();
        for (&cpu.path_l1) |*e| {
            if (e.epoch != cur_epoch) continue;
            if (matches(e, tag, path)) {
                const out = e.payload;
                asm volatile ("pushq %[rf]\npopfq"
                    :
                    : [rf] "r" (rf),
                    : .{ .memory = true, .cc = true });
                return out;
            }
        }
    }
    asm volatile ("pushq %[rf]\npopfq"
        :
        : [rf] "r" (rf),
        : .{ .memory = true, .cc = true });

    // L2 — global, locked. Snapshot payload under the lock; promote
    // outside it so we don't take l2_lock + L1's cli-region nested.
    var l2_payload: ?[PAYLOAD_BYTES]u8 = null;
    {
        const flags = l2_lock.acquireIrqSave();
        defer l2_lock.releaseIrqRestore(flags);
        for (&l2) |*e| {
            if (matches(e, tag, path)) {
                l2_payload = e.payload;
                break;
            }
        }
    }
    if (l2_payload) |p| {
        promoteL1(tag, path, p, cur_epoch);
        return p;
    }
    return null;
}

/// Insert (or update if already present) a (tag, path) → payload mapping.
/// Writes to both L1 (this CPU) and L2 (global).
pub fn insert(tag: FsTag, path: []const u8, payload: [PAYLOAD_BYTES]u8) void {
    if (path.len == 0 or path.len > smp.PATH_CACHE_PATH_MAX) return;
    const cur_epoch = @atomicLoad(u64, &global_epoch, .acquire);

    promoteL1(tag, path, payload, cur_epoch);

    const flags = l2_lock.acquireIrqSave();
    defer l2_lock.releaseIrqRestore(flags);
    // Replace existing entry to avoid duplicates.
    for (&l2) |*e| {
        if (matches(e, tag, path)) {
            e.payload = payload;
            return;
        }
    }
    const victim = &l2[l2_next];
    l2_next = (l2_next + 1) % @as(u8, L2_SIZE);
    writeEntry(victim, tag, path, payload, cur_epoch);
}

fn promoteL1(tag: FsTag, path: []const u8, payload: [PAYLOAD_BYTES]u8, epoch: u64) void {
    var rf: u64 = undefined;
    asm volatile ("pushfq\npopq %[rf]\ncli"
        : [rf] "=r" (rf),
        :
        : .{ .memory = true, .cc = true });
    {
        const cpu = smp.myCpu();
        const idx = cpu.path_l1_next;
        cpu.path_l1_next = (cpu.path_l1_next + 1) % smp.PATH_L1_SIZE;
        writeEntry(&cpu.path_l1[idx], tag, path, payload, epoch);
    }
    asm volatile ("pushq %[rf]\npopfq"
        :
        : [rf] "r" (rf),
        : .{ .memory = true, .cc = true });
}

// === Per-FS encode/decode helpers ===

pub fn lookupExt2(path: []const u8) ?u32 {
    const p = lookup(.ext2, path) orelse return null;
    return std.mem.readInt(u32, p[0..4], .little);
}

pub fn insertExt2(path: []const u8, inum: u32) void {
    var p: [PAYLOAD_BYTES]u8 = [_]u8{0} ** PAYLOAD_BYTES;
    std.mem.writeInt(u32, p[0..4], inum, .little);
    insert(.ext2, path, p);
}

pub const Fat32Hit = struct {
    dir_cluster: u32,
    dir_index: u32,
    first_cluster: u32,
    file_size: u32,
};

pub fn lookupFat32(path: []const u8) ?Fat32Hit {
    const p = lookup(.fat32, path) orelse return null;
    return .{
        .dir_cluster = std.mem.readInt(u32, p[0..4], .little),
        .dir_index = std.mem.readInt(u32, p[4..8], .little),
        .first_cluster = std.mem.readInt(u32, p[8..12], .little),
        .file_size = std.mem.readInt(u32, p[12..16], .little),
    };
}

pub fn insertFat32(path: []const u8, hit: Fat32Hit) void {
    var p: [PAYLOAD_BYTES]u8 = undefined;
    std.mem.writeInt(u32, p[0..4], hit.dir_cluster, .little);
    std.mem.writeInt(u32, p[4..8], hit.dir_index, .little);
    std.mem.writeInt(u32, p[8..12], hit.first_cluster, .little);
    std.mem.writeInt(u32, p[12..16], hit.file_size, .little);
    insert(.fat32, path, p);
}
