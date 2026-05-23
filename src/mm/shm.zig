//! Shared anonymous memory regions — POSIX MAP_SHARED|MAP_ANONYMOUS.
//!
//! A region is a fixed-size, eagerly-allocated set of physical frames that
//! multiple processes can attach to via their `LazyRegion` table. The page-
//! fault handler maps the requested page from `frames[]` instead of fresh-
//! allocating, so all attachers share the same physical pages byte-for-byte.
//!
//! Lifecycle:
//!   create(size_pages) — alloc frames, zero them, refcount = 1, return id.
//!   acquire(id)        — fork inheritance: child bumps refcount.
//!   release(id)        — munmap / exit: decrement; free frames at 0.
//!   frameAt(id, idx)   — fault handler looks up the phys for a given page.
//!
//! Lock discipline: a single SpinLock serializes the slot table and refcount
//! transitions. frameAt is safe without the lock because callers hold a
//! refcount (which keeps in_use=true and the frames[] entries stable).
//!
//! Sizing rationale (MAX_SHM_REGIONS=32, MAX_PAGES_PER_REGION=256 = 1 MB):
//! Phase 1 is fork-inherited only — most usage is "parent allocates N small
//! buffers, forks workers". 32 regions × 1 MB = 32 MB ceiling on shared anon
//! memory, well below the system RAM and the per-region cap matches typical
//! IPC buffer sizes (ring buffers, lock-free queues, command channels).

const std = @import("std");
const pmm = @import("pmm.zig");
const paging = @import("paging.zig");
const debug = @import("../debug/debug.zig");

pub const MAX_SHM_REGIONS: u32 = 32;
pub const MAX_PAGES_PER_REGION: u32 = 256;
pub const SHM_INVALID: u32 = 0xFFFFFFFF;

const ShmRegion = struct {
    in_use: bool = false,
    size_pages: u16 = 0,
    refcount: u16 = 0,
    frames: [MAX_PAGES_PER_REGION]u64 = [_]u64{0} ** MAX_PAGES_PER_REGION,
};

var regions: [MAX_SHM_REGIONS]ShmRegion = [_]ShmRegion{.{}} ** MAX_SHM_REGIONS;
var lock: @import("../proc/spinlock.zig").SpinLock = .{};

/// Allocate a new shared region of `size_pages` 4 KB pages. Frames are
/// zeroed (POSIX requires zero-initialized anon memory). Returns the
/// region id on success, null on full table / OOM / oversize.
pub fn create(size_pages: u32) ?u32 {
    if (size_pages == 0 or size_pages > MAX_PAGES_PER_REGION) return null;
    const flags = lock.acquireIrqSave();
    defer lock.releaseIrqRestore(flags);

    var id: u32 = 0;
    while (id < MAX_SHM_REGIONS) : (id += 1) {
        if (!regions[id].in_use) break;
    }
    if (id == MAX_SHM_REGIONS) return null;

    var allocated: u16 = 0;
    while (allocated < size_pages) : (allocated += 1) {
        const phys = pmm.allocFrameUser() orelse {
            while (allocated > 0) {
                allocated -= 1;
                pmm.freeFrame(regions[id].frames[allocated]);
                regions[id].frames[allocated] = 0;
            }
            return null;
        };
        const vptr: [*]u8 = @ptrFromInt(paging.physToVirt(phys));
        @memset(vptr[0..4096], 0);
        regions[id].frames[allocated] = phys;
    }

    regions[id].in_use = true;
    regions[id].size_pages = @intCast(size_pages);
    regions[id].refcount = 1;
    return id;
}

/// Bump refcount on an existing region. Called by fork() for each inherited
/// LazyRegion whose shm_id is set. Returns false if the id is invalid /
/// the region was already torn down (which would indicate a bug in the
/// lifecycle bookkeeping).
pub fn acquire(id: u32) bool {
    if (id >= MAX_SHM_REGIONS) return false;
    const flags = lock.acquireIrqSave();
    defer lock.releaseIrqRestore(flags);
    if (!regions[id].in_use) return false;
    regions[id].refcount += 1;
    return true;
}

/// Decrement refcount. At zero, free all frames and recycle the slot.
/// Called by munmap, process teardown, and exec's old-AS reclaim path.
pub fn release(id: u32) void {
    if (id >= MAX_SHM_REGIONS) return;
    const flags = lock.acquireIrqSave();
    defer lock.releaseIrqRestore(flags);
    if (!regions[id].in_use) return;
    if (regions[id].refcount == 0) {
        debug.klog("[shm] release on already-zero refcount id={d}\n", .{id});
        return;
    }
    regions[id].refcount -= 1;
    if (regions[id].refcount > 0) return;

    var i: u16 = 0;
    while (i < regions[id].size_pages) : (i += 1) {
        pmm.freeFrame(regions[id].frames[i]);
        regions[id].frames[i] = 0;
    }
    regions[id].in_use = false;
    regions[id].size_pages = 0;
}

/// Lookup the physical frame backing page `page_idx` of region `id`.
/// Caller must hold a refcount on the region (otherwise the lookup races
/// with release). The page-fault handler is the only legitimate caller
/// and runs in the context of a process whose LazyRegion holds the ref.
pub fn frameAt(id: u32, page_idx: u32) ?u64 {
    if (id >= MAX_SHM_REGIONS) return null;
    if (!regions[id].in_use) return null;
    if (page_idx >= regions[id].size_pages) return null;
    return regions[id].frames[page_idx];
}

pub fn sizePages(id: u32) u32 {
    if (id >= MAX_SHM_REGIONS) return 0;
    if (!regions[id].in_use) return 0;
    return regions[id].size_pages;
}
