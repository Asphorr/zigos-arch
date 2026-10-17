//! Linux memory-management syscalls for `.linux` processes: mmap, munmap,
//! mprotect, madvise, brk, mremap. They edit the process's region set
//! (PCB.regions, mm/vma.zig) under the write side of its as_lock; the page
//! tables follow — pages appear on first touch through the fault handler, and
//! an edit that takes pages away unmaps them and shoots the range down.
//!
//! Placement: MAP_FIXED / MAP_FIXED_NOREPLACE take the address as given, a free
//! hint is honored, everything else goes to the highest free gap below
//! LINUX_MMAP_TOP (above LINUX_MMAP_FLOOR first, then below it).
//!
//! Not modeled: mremap (always ENOMEM — musl's realloc falls back to copy),
//! mlock, MAP_HUGETLB, PROT_NONE on pages already present (they stay
//! readable; a fresh fault in a PROT_NONE region is refused).

const process = @import("../../proc/process.zig");
const vmm = @import("../../mm/vmm.zig");
const pmm = @import("../../mm/pmm.zig");
const paging = @import("../../mm/paging.zig");
const memmap = @import("../../mm/memmap.zig");
const shm = @import("../../mm/shm.zig");
const vfs = @import("../../fs/vfs.zig");
const ext2_inode = @import("../../fs/ext2/inode.zig");
const tlb = @import("../mmu/tlb.zig");
const config = @import("../../config.zig");
const Phys = @import("../../util/addr.zig").Phys;

const LazyRegion = process.LazyRegion;

const PAGE: u64 = 0x1000;

// Linux errno.
const EBADF: i64 = 9;
const ENOMEM: i64 = 12;
const EEXIST: i64 = 17;
const ENODEV: i64 = 19;
const EINVAL: i64 = 22;
const EOVERFLOW: i64 = 75;

inline fn err(e: i64) u64 {
    return @bitCast(-e);
}

// mmap prot / flags.
const PROT_MASK: u64 = 0x7; // READ | WRITE | EXEC; the rest (PROT_SEM, GROWS*) ignored
const MAP_SHARED: u64 = 0x01;
const MAP_PRIVATE: u64 = 0x02;
const MAP_SHARED_VALIDATE: u64 = 0x03;
const MAP_TYPE: u64 = 0x0f;
const MAP_FIXED: u64 = 0x10;
const MAP_ANONYMOUS: u64 = 0x20;
const MAP_FIXED_NOREPLACE: u64 = 0x100000;

// madvise advice that drops pages.
const MADV_DONTNEED: u64 = 4;
const MADV_FREE: u64 = 8;

/// Most MAP_SHARED file regions one munmap flushes after dropping the lock;
/// the rest wait for pgflushd.
const MAX_FLUSH_INODES: usize = 8;

fn pageUp(v: u64) ?u64 {
    const r = @addWithOverflow(v, PAGE - 1);
    if (r[1] != 0) return null;
    return r[0] & ~(PAGE - 1);
}

/// [start, start + len) lies inside the user window. `len` page aligned.
fn rangeOk(start: u64, len: u64) bool {
    if (start < memmap.USER_SPACE_START) return false;
    const r = @addWithOverflow(start, len);
    return r[1] == 0 and r[0] <= memmap.USER_SPACE_END;
}

fn lead() ?*process.PCB {
    const pcb = process.currentPCB() orelse return null;
    if (pcb.page_directory == null) return null;
    return process.leader(pcb);
}

/// What munmap and MAP_FIXED do to every piece they take out of the set:
/// unmap its pages and release what backs it. The pages' frames wait in
/// `rc` for the caller's shootdown; writeback of MAP_SHARED file pieces is
/// left to the caller, outside the lock.
const Release = struct {
    pd: [*]align(4096) u64,
    owner: *process.PCB,
    rc: vmm.Reclaim,
    /// Start of the range being taken out. Pieces come in ascending order,
    /// so everything in `rc` lies in [lo, the current piece's end).
    lo: u64,
    flush: [MAX_FLUSH_INODES]u32 = undefined,
    n_flush: usize = 0,

    fn init(owner: *process.PCB, lo: u64) Release {
        return .{ .pd = owner.page_directory.?, .owner = owner, .rc = .{ .pcid = owner.pcid }, .lo = lo };
    }

    pub fn removed(self: *Release, r: LazyRegion) void {
        _ = vmm.unmapUserRange(self.pd, r.start, r.end, &self.rc);
        if (r.unsplittable()) {
            // Its buffer or shm pages may go with this reference: no CPU
            // may still reach them, nor anything collected before them.
            tlb.shootdownRange(self.owner.pcid, self.lo, (r.end - self.lo) / PAGE);
            self.rc.release();
            if (r.shm_id != shm.SHM_INVALID) shm.release(r.shm_id);
            if (r.buf_owned) {
                if (r.source) |src| pmm.releaseContiguous(Phys.of(paging.virtToPhys(@intFromPtr(src)).?), r.buf_pages);
            }
        }
        if (r.cache_inode != 0 and r.cache_shared and self.n_flush < MAX_FLUSH_INODES) {
            self.flush[self.n_flush] = r.cache_inode;
            self.n_flush += 1;
        }
        if (r.start == self.owner.heap_start) self.owner.heap_start = 0;
    }

    fn writeBack(self: *const Release) void {
        for (self.flush[0..self.n_flush]) |inum| _ = vfs.syncCacheFile(inum, true);
    }
};

/// A region whose whole range shares one buffer or shm reference can only
/// be taken whole: false if [start, end) cuts through one.
fn splitsUnsplittable(owner: *process.PCB, start: u64, end: u64) bool {
    var it = owner.regions.atOrAbove(start);
    while (it) |r| : (it = owner.regions.atOrAbove(r.end)) {
        if (r.start >= end) break;
        if (r.unsplittable() and (r.start < start or r.end > end)) return true;
    }
    return false;
}

/// Take [start, end) out of the address space. Under the write side.
fn unmapLocked(owner: *process.PCB, rel: *Release, start: u64, end: u64) error{ OutOfMemory, Unsplittable }!void {
    if (splitsUnsplittable(owner, start, end)) return error.Unsplittable;
    // Also when remove fails part way: what it unmapped is in rel.rc.
    defer {
        tlb.shootdownRange(owner.pcid, start, (end - start) / PAGE);
        rel.rc.release();
    }
    try owner.regions.remove(start, end, rel);
}

pub fn mmap(addr: u64, len: u64, prot: u64, flags: u64, fd: u64, off: u64) u64 {
    if (len == 0) return err(EINVAL);
    const len_pg = pageUp(len) orelse return err(ENOMEM);
    if (off & (PAGE - 1) != 0) return err(EINVAL);
    const shared = switch (flags & MAP_TYPE) {
        MAP_SHARED, MAP_SHARED_VALIDATE => true,
        MAP_PRIVATE => false,
        else => return err(EINVAL),
    };
    const anon = flags & MAP_ANONYMOUS != 0;
    const p: u8 = @truncate(prot & PROT_MASK);

    const owner = lead() orelse return err(EINVAL);

    var region: LazyRegion = .{ .prot = p };
    if (anon) {
        if (!shared) region.flags = process.REGION_MERGEABLE;
    } else {
        // The fd table is the group's: the lead's.
        if (fd >= config.MAX_FDS or !owner.fd_table[fd].in_use) return err(EBADF);
        // File mappings go through the page cache, which only ext2 has,
        // and only for regular files.
        const fe = &owner.fd_table[fd];
        if (fe.fs_type != .ext2) return err(ENODEV);
        const ino = ext2_inode.readInode(fe.inode) orelse return err(EBADF);
        if (!ext2_inode.isReg(&ino)) return err(ENODEV);
        // The cache keys pages by file offset; every page's must be one.
        if (@as(i64, @bitCast(off)) < 0 or @addWithOverflow(off, len_pg)[1] != 0) return err(EOVERFLOW);
        region.cache_inode = fe.inode;
        region.cache_off = off;
        region.cache_shared = shared;
    }
    // Before anything is unmapped: MAP_FIXED must not fail after it took
    // the old mapping away for want of an shm object.
    if (anon and shared) {
        region.shm_id = shm.create(@intCast(len_pg / PAGE)) orelse return err(ENOMEM);
    }

    owner.as_lock.acquire();
    var rel = Release.init(owner, addr);
    const res = mapLocked(owner, &rel, &region, addr, len_pg, flags);
    owner.as_lock.release();
    rel.writeBack();
    return res catch |e| {
        if (region.shm_id != shm.SHM_INVALID) shm.release(region.shm_id);
        return err(switch (e) {
            error.NoMemory => ENOMEM,
            error.Exists => EEXIST,
            error.Invalid => EINVAL,
        });
    };
}

/// mmap's placement and insert, under the write side. `region` comes back
/// with its range set.
fn mapLocked(owner: *process.PCB, rel: *Release, region: *LazyRegion, addr: u64, len_pg: u64, flags: u64) error{ NoMemory, Exists, Invalid }!u64 {
    const at: u64 = if (flags & (MAP_FIXED | MAP_FIXED_NOREPLACE) != 0) at: {
        if (addr & (PAGE - 1) != 0) return error.Invalid;
        if (!rangeOk(addr, len_pg)) return error.NoMemory;
        if (flags & MAP_FIXED_NOREPLACE != 0) {
            if (!owner.regions.isFree(addr, addr + len_pg)) return error.Exists;
        } else {
            unmapLocked(owner, rel, addr, addr + len_pg) catch |e| return switch (e) {
                error.OutOfMemory => error.NoMemory,
                error.Unsplittable => error.Invalid,
            };
        }
        break :at addr;
    } else place(owner, addr, len_pg) orelse return error.NoMemory;

    region.start = at;
    region.end = at + len_pg;
    if (!process.addRegion(owner.tgid, region.*)) return error.NoMemory;
    return at;
}

/// Where a non-fixed mapping of `len` bytes goes: the hint if it is free,
/// else the highest gap below LINUX_MMAP_TOP. Under the write side.
fn place(owner: *process.PCB, hint: u64, len: u64) ?u64 {
    if (hint != 0) {
        const h = hint & ~(PAGE - 1);
        if (rangeOk(h, len) and owner.regions.isFree(h, h + len)) return h;
    }
    return owner.regions.gapTopDown(len, memmap.LINUX_MMAP_FLOOR, memmap.LINUX_MMAP_TOP) orelse
        owner.regions.gapTopDown(len, memmap.USER_SPACE_START, memmap.LINUX_MMAP_FLOOR);
}

pub fn munmap(addr: u64, len: u64) u64 {
    if (addr & (PAGE - 1) != 0 or len == 0) return err(EINVAL);
    const len_pg = pageUp(len) orelse return err(EINVAL);
    if (!rangeOk(addr, len_pg)) return err(EINVAL);
    const owner = lead() orelse return err(EINVAL);

    owner.as_lock.acquire();
    var rel = Release.init(owner, addr);
    const res = unmapLocked(owner, &rel, addr, addr + len_pg);
    owner.as_lock.release();
    rel.writeBack();
    res catch |e| return err(if (e == error.OutOfMemory) ENOMEM else EINVAL);
    return 0;
}

/// Region-set `update` context: new prot on each piece, and on its present
/// pages.
const Reprotect = struct {
    pd: [*]align(4096) u64,
    prot: u8,

    pub fn apply(self: Reprotect, r: *LazyRegion) void {
        r.prot = self.prot;
        // A private file page maps the shared cache frame: keep it read-only
        // and copy-on-write (cacheMapFlags) or a write would land in the cache.
        const flags = if (r.cache_inode != 0 and !r.cache_shared)
            vmm.cacheMapFlags(self.prot)
        else
            vmm.protToMapFlags(self.prot);
        vmm.reprotectUserRange(self.pd, r.start, r.end, flags);
    }
};

pub fn mprotect(addr: u64, len: u64, prot: u64) u64 {
    if (addr & (PAGE - 1) != 0) return err(EINVAL);
    if (len == 0) return 0;
    const len_pg = pageUp(len) orelse return err(ENOMEM);
    if (!rangeOk(addr, len_pg)) return err(ENOMEM);
    const owner = lead() orelse return err(EINVAL);
    const end = addr + len_pg;

    owner.as_lock.acquire();
    defer owner.as_lock.release();
    if (!owner.regions.covers(addr, end)) return err(ENOMEM);
    if (splitsUnsplittable(owner, addr, end)) return err(EINVAL);
    owner.regions.update(addr, end, Reprotect{ .pd = owner.page_directory.?, .prot = @truncate(prot & PROT_MASK) }) catch return err(ENOMEM);
    tlb.shootdownRange(owner.pcid, addr, len_pg / PAGE);
    return 0;
}

pub fn madvise(addr: u64, len: u64, advice: u64) u64 {
    if (addr & (PAGE - 1) != 0) return err(EINVAL);
    const len_pg = pageUp(len) orelse return err(EINVAL);
    if (len_pg == 0) return 0;
    if (!rangeOk(addr, len_pg)) return err(ENOMEM);
    if (advice != MADV_DONTNEED and advice != MADV_FREE) return 0; // hints only
    const owner = lead() orelse return err(EINVAL);

    // Dropping the pages is the whole effect: the next touch faults in a
    // zero page (private anon), the file's page (private file — the private
    // copy goes) or the same shared frame again (shm, MAP_SHARED file).
    owner.as_lock.acquire();
    defer owner.as_lock.release();
    var rc: vmm.Reclaim = .{ .pcid = owner.pcid };
    _ = vmm.unmapUserRange(owner.page_directory.?, addr, addr + len_pg, &rc);
    tlb.shootdownRange(owner.pcid, addr, len_pg / PAGE);
    rc.release();
    return 0;
}

/// brk(addr): move the break to `addr` and return it, or return the current
/// break unchanged when `addr` is 0, below the start, or the heap can't grow
/// there. The heap is one region from brk_base, page granular; the break
/// itself is byte exact, as on Linux.
pub fn brk(addr: u64) u64 {
    const owner = lead() orelse return 0;
    owner.as_lock.acquire();
    defer owner.as_lock.release();
    const cur = owner.user_brk;
    if (addr == 0 or addr < owner.brk_base) return cur;
    const new_pg = pageUp(addr) orelse return cur;
    const cur_pg = pageUp(cur) orelse return cur;
    if (!rangeOk(owner.brk_base, new_pg - owner.brk_base)) return cur;

    // The heap region, if munmap left it where brk put it.
    const heap: ?*LazyRegion = if (owner.heap_start == 0) null else blk: {
        const r = owner.regions.find(owner.heap_start) orelse break :blk null;
        break :blk if (r.start == owner.heap_start) r else null;
    };
    if (new_pg > cur_pg) {
        if (heap) |r| {
            if (!owner.regions.resizeEnd(r.start, new_pg)) return cur;
        } else {
            if (!process.addRegion(owner.tgid, .{ .start = cur_pg, .end = new_pg, .prot = process.PROT_RW })) return cur;
            owner.heap_start = cur_pg;
        }
    } else if (heap) |r| {
        // Shrink: drop the pages above the new break, never below the heap.
        const lo = @max(new_pg, r.start);
        const hi = r.end;
        if (lo < hi) {
            var rc: vmm.Reclaim = .{ .pcid = owner.pcid };
            _ = vmm.unmapUserRange(owner.page_directory.?, lo, hi, &rc);
            tlb.shootdownRange(owner.pcid, lo, (hi - lo) / PAGE);
            rc.release();
            if (lo == r.start) {
                const Drop = struct {
                    pub fn removed(_: @This(), _: LazyRegion) void {}
                };
                owner.regions.remove(lo, hi, Drop{}) catch unreachable; // whole region: no split
                owner.heap_start = 0;
            } else {
                _ = owner.regions.resizeEnd(r.start, lo);
            }
        }
    }
    owner.user_brk = addr;
    return addr;
}

/// mremap: not modeled. ENOMEM is the "can't do it in place or move it"
/// answer, and musl's realloc then copies into a fresh mapping.
pub fn mremap() u64 {
    return err(ENOMEM);
}
