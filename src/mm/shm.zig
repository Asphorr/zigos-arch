//! Shared anonymous memory: Linux mmap(MAP_SHARED|MAP_ANONYMOUS) and a
//! shared /dev/zero, the native shm call, io_uring's rings.
//!
//! An object is a run of pages that every address space attached to it maps
//! to the same frames. A page gets its frame when it is first touched
//! (frameFor) — or all of them at once for the kernel's own users, which
//! read the frames without a fault (create). The frames are named by a
//! two-level table: a directory with a leaf frame for each 512 pages.
//!
//! Every LazyRegion piece that names the object holds one reference
//! (LazyRegion.tailFrom takes one for a piece split off); the last release
//! frees the frames. A frame's own count is one for the object and one for
//! each mapping of it.
//!
//! The spinlock covers the slot table and the counts. Leaves and frames are
//! published by compare-and-swap and only while a reference is held, so
//! frameAt and frameFor take no lock.

const std = @import("std");
const pmm = @import("pmm.zig");
const heap = @import("heap.zig");
const debug = @import("../debug/debug.zig");
const Phys = @import("../util/addr.zig").Phys;

pub const MAX_SHM_REGIONS: u32 = 4096;
/// 4 GiB an object: a directory of 2048 leaves.
pub const MAX_PAGES_PER_REGION: u32 = 1 << 20;
pub const SHM_INVALID: u32 = 0xFFFFFFFF;

/// Pages a leaf names: a frame of 8-byte entries.
const LEAF_PAGES: u32 = 512;

const ShmRegion = struct {
    in_use: bool = false,
    /// 0 while the object is being taken apart.
    size_pages: u32 = 0,
    refcount: u32 = 0,
    /// The frame of each leaf, 0 until a page under it is touched. A leaf
    /// holds its pages' frames the same way.
    dir: ?[*]u64 = null,
};

var regions: [MAX_SHM_REGIONS]ShmRegion = [_]ShmRegion{.{}} ** MAX_SHM_REGIONS;
var lock: @import("../proc/spinlock.zig").SpinLock = .{};
/// No slot below it is free. Under `lock`.
var first_free: u32 = 0;

fn leafCount(size_pages: u32) u32 {
    return (size_pages + LEAF_PAGES - 1) / LEAF_PAGES;
}

/// A new object of `size_pages` pages, none with a frame yet, and one
/// reference to it: the caller's. Null: no slot, no memory, or too large.
pub fn createLazy(size_pages: u32) ?u32 {
    if (size_pages == 0 or size_pages > MAX_PAGES_PER_REGION) return null;
    const n = leafCount(size_pages);
    const raw = heap.kmallocAligned(n * @sizeOf(u64), @alignOf(u64)) orelse return null;
    const dir: [*]u64 = @ptrCast(@alignCast(raw));
    @memset(dir[0..n], 0);

    const flags = lock.acquireIrqSave();
    var id = first_free;
    while (id < MAX_SHM_REGIONS and regions[id].in_use) id += 1;
    if (id == MAX_SHM_REGIONS) {
        first_free = id;
        lock.releaseIrqRestore(flags);
        heap.kfree(raw);
        return null;
    }
    first_free = id + 1;
    regions[id] = .{ .in_use = true, .size_pages = size_pages, .refcount = 1, .dir = dir };
    lock.releaseIrqRestore(flags);
    return id;
}

/// The same with every frame there from the start: for the kernel's own
/// users, which read the frames without a fault.
pub fn create(size_pages: u32) ?u32 {
    const id = createLazy(size_pages) orelse return null;
    var i: u32 = 0;
    while (i < size_pages) : (i += 1) {
        if (frameFor(id, i) == null) {
            release(id);
            return null;
        }
    }
    return id;
}

/// One more reference: a fork's copy of a region, a piece split off one.
/// False for an id that names no live object.
pub fn acquire(id: u32) bool {
    if (id >= MAX_SHM_REGIONS) return false;
    const flags = lock.acquireIrqSave();
    defer lock.releaseIrqRestore(flags);
    const r = &regions[id];
    if (!r.in_use or r.refcount == 0 or r.refcount == std.math.maxInt(u32)) return false;
    r.refcount += 1;
    return true;
}

/// Drop a reference; the last one frees the frames and the slot.
pub fn release(id: u32) void {
    if (id >= MAX_SHM_REGIONS) return;
    var dir: [*]u64 = undefined;
    var n: u32 = 0;
    {
        const flags = lock.acquireIrqSave();
        defer lock.releaseIrqRestore(flags);
        const r = &regions[id];
        if (!r.in_use) return;
        if (r.refcount == 0) {
            debug.klog("[shm] release on already-zero refcount id={d}\n", .{id});
            return;
        }
        r.refcount -= 1;
        if (r.refcount > 0) return;
        // Nobody can reach it now. The slot stays taken (refcount 0: acquire
        // refuses it) until its memory is back.
        dir = r.dir.?;
        n = leafCount(r.size_pages);
        r.size_pages = 0;
        r.dir = null;
    }
    // Outside the lock: up to a million frames.
    for (dir[0..n]) |leaf_raw| {
        if (leaf_raw == 0) continue;
        const leaf = Phys.of(leaf_raw).toVirt().ptr([*]const u64);
        for (leaf[0..LEAF_PAGES]) |raw| {
            if (raw != 0) pmm.freeFrame(Phys.of(raw));
        }
        pmm.freeFrame(Phys.of(leaf_raw));
    }
    heap.kfree(@ptrCast(dir));
    const flags = lock.acquireIrqSave();
    regions[id].in_use = false;
    if (id < first_free) first_free = id;
    lock.releaseIrqRestore(flags);
}

/// Where the frame of page `page_idx` is recorded, if its leaf is there.
/// The caller holds a reference.
fn entryOf(id: u32, page_idx: u32) ?*u64 {
    const slot = leafSlot(id, page_idx) orelse return null;
    const leaf_raw = @atomicLoad(u64, slot, .acquire);
    if (leaf_raw == 0) return null;
    return &Phys.of(leaf_raw).toVirt().ptr([*]u64)[page_idx % LEAF_PAGES];
}

fn leafSlot(id: u32, page_idx: u32) ?*u64 {
    if (id >= MAX_SHM_REGIONS) return null;
    const r = &regions[id];
    if (!r.in_use or page_idx >= r.size_pages) return null;
    const dir = r.dir orelse return null;
    return &dir[page_idx / LEAF_PAGES];
}

/// A zeroed frame into the empty `slot`, unless another toucher's is there
/// by then. What the slot holds; null: out of memory.
fn fill(slot: *u64) ?u64 {
    const there = @atomicLoad(u64, slot, .acquire);
    if (there != 0) return there;
    const fresh = pmm.allocFrameUser() orelse return null;
    @memset(fresh.toVirt().ptr([*]u8)[0..4096], 0);
    if (@cmpxchgStrong(u64, slot, 0, fresh.raw(), .acq_rel, .acquire)) |winner| {
        pmm.freeFrame(fresh);
        return winner;
    }
    return fresh.raw();
}

/// The frame of page `page_idx`, null if the page has none (yet). The caller
/// holds a reference.
pub fn frameAt(id: u32, page_idx: u32) ?Phys {
    const entry = entryOf(id, page_idx) orelse return null;
    const raw = @atomicLoad(u64, entry, .acquire);
    return if (raw == 0) null else Phys.of(raw);
}

/// The frame of page `page_idx`, made (zeroed) if the page had none. Null:
/// out of memory, or no such page (sizePages tells which). The caller holds
/// a reference. Does not block.
pub fn frameFor(id: u32, page_idx: u32) ?Phys {
    const slot = leafSlot(id, page_idx) orelse return null;
    const leaf_raw = fill(slot) orelse return null;
    const entry = &Phys.of(leaf_raw).toVirt().ptr([*]u64)[page_idx % LEAF_PAGES];
    return Phys.of(fill(entry) orelse return null);
}

pub fn sizePages(id: u32) u32 {
    if (id >= MAX_SHM_REGIONS) return 0;
    if (!regions[id].in_use) return 0;
    return regions[id].size_pages;
}
