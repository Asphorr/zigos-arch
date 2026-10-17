// ext2 mount state + block-level I/O through a write-back buffer cache.
//
// Every fs block a mount touches lives in a PMM frame keyed by (mount,
// block). A read miss fills it from disk together with the blocks after it
// (read-ahead, one pipelined command); a write changes the frame and marks
// it dirty, and nothing reaches the disk until `flush`: pgflushd every pass,
// fsync/shutdown on demand, a writer itself once dirty data passes
// dirtyLimit(). flush writes in block order and merges neighbours into one
// multi-sector command.
//
// Locking:
//   * Buffer CONTENTS of a mount are read and written under that mount's
//     lock (lockMount), so compound ops see them stable. flush is the one
//     exception: it reads contents with no mount lock (see flush).
//   * The index (hash chains, LRU, dirty/writeback bits, pins, counters) is
//     under `cache_lock`, a leaf spinlock. Order: mount lock -> cache_lock
//     -> pmm.
//   * A buffer that is pinned, dirty or under writeback is never evicted or
//     reclaimed. Block ops pin across their copy; flush marks writeback
//     across its I/O.
//   * Buffers reach the device only through flush, one flush at a time
//     (flush_lock), so two writes of one block never race in the device.

const std = @import("std");
const layout = @import("layout.zig");
const blkdev = @import("../../driver/block.zig");
const debug = @import("../../debug/debug.zig");
const pmm = @import("../../mm/pmm.zig");
const Phys = @import("../../util/addr.zig").Phys;
const spinlock = @import("../../proc/spinlock.zig");

const SECTOR_SIZE: u32 = 512;

// Function-pointer indirection: lets Phase 3 swap the underlying device
// (secondary → primary) without touching ext2/ internals. Same idea as
// the block driver's own backend dispatch.
const ReadFn = *const fn (lba: u32, count: u16, dest: [*]u8) bool;
const WriteFn = *const fn (lba: u32, count: u16, src: [*]const u8) bool;

// BGD table cache cap. 64 entries × 32 B = 2 KB per mount; covers ~8 GB at
// 4 KB blocks with 32K blocks/group. Larger disks would need PMM-allocated
// storage.
const MAX_BGD_CACHED: u32 = 64;

/// One frame per buffer; holds a block of any supported size (≤ 4 KiB).
const BUF_BYTES: u32 = 4096;
/// Blocks a read miss pulls in: the missing one and those after it. 512 KiB
/// at 4 KiB blocks: four 128 KiB commands in flight together, which the
/// device serves in about the time of one. A miss costs ~1 ms of command
/// latency under QEMU whatever it carries, so it should carry a lot.
const READAHEAD_BLOCKS: u32 = 128;
/// Most blocks one flush command carries (128 KiB at 4 KiB blocks).
const FLUSH_RUN_BLOCKS: u32 = 32;
/// Dirty buffers one flush round gathers, sorts and writes.
const FLUSH_BATCH: u32 = 512;
/// Buffers the cache can ever hold (256 MiB of frames). The live cap is lower
/// on small machines, see cap().
const MAX_BUFS: u32 = 65536;
const HASH_BUCKETS: u32 = 16384;
const NO_BUF: u32 = 0xFFFF_FFFF;
/// LRU entries an eviction looks at before giving up on finding a clean one.
const EVICT_SCAN_BUFS: u32 = 512;

comptime {
    if (HASH_BUCKETS & (HASH_BUCKETS - 1) != 0) @compileError("HASH_BUCKETS must be a power of two");
    if (FLUSH_RUN_BLOCKS * BUF_BYTES / SECTOR_SIZE > 0xFFFF) @compileError("flush run must fit a u16 sector count");
}

pub const Mount = struct {
    sb: layout.Superblock,
    block_size: u32,
    sectors_per_block: u32,
    inodes_per_block: u32,
    bgd_count: u32,
    bgd: []layout.BlockGroupDescriptor,
    /// Backing store `bgd` slices into — PER MOUNT, so a second mount (the
    /// installer's target) can't clobber the live root's descriptors, which
    /// is exactly what the old file-scope array would have done.
    bgd_store: [MAX_BGD_CACHED]layout.BlockGroupDescriptor align(8) = undefined,
    /// First LBA of the ext2 filesystem within the disk. 0 when the
    /// disk is one big ext2 fs (no partition table).
    partition_lba: u32,
    read_sectors: ReadFn,
    write_sectors: WriteFn,
    /// Read-ahead landing area for a miss; used under the mount lock.
    read_stage: [READAHEAD_BLOCKS * BUF_BYTES]u8 align(8) = undefined,

    /// Per-mount REENTRANT SLEEPING lock (2026-06-04). Buffer contents, the
    /// BGD table and the superblock above are shared mutable state with no
    /// other synchronization, but ext2 runs concurrently on every CPU (no big
    /// syscall lock). Every block op takes this first. SLEEPING because ops
    /// block on NVMe reads while holding it; REENTRANT because alloc/free
    /// nest (allocBlock -> writeBgdTable -> writeBlock). 0xFFFF owner = free.
    lock_owner: u16 = 0xFFFF, // (a) pid holding the lock
    lock_depth: u32 = 0, // recursion depth — only the owner mutates

    /// Metadata-update deferral. depth > 0 = a compound op (writeFile /
    /// truncate / unlink) is batching: writeBgdTable / writeSuperblock just
    /// set `meta_dirty` and return true, and the outermost endMetaDefer
    /// copies BGD + SB into their buffers once for the whole op. Guarded by
    /// the mount lock like the rest of this struct.
    meta_defer_depth: u32 = 0,
    meta_dirty: bool = false,
};

/// Acquire the per-mount lock (see Mount.lock_owner). No-op before the
/// scheduler is up (mount/boot reads run single-threaded with no current_pid).
///
/// PUBLIC since the compound-op locking round: the lock is REENTRANT
/// precisely so ext2.zig/inode.zig can hold it across whole read-modify-
/// write sequences (createFile, writeFile, bitmap RMW...) while the nested
/// per-block ops here just bump the depth. Block-op granularity alone
/// serialized single reads/writes but left every multi-step op racy:
/// concurrent creates could lose dirents (read-block / modify-stack-copy /
/// write-block interleave) and two allocInode calls could hand out the
/// SAME inum (bitmap read and write are separate lock sections).
/// Lock order: mount lock -> page_cache.lock, mount lock -> cache_lock.
pub fn lockMount(self: *Mount) void {
    const smp = @import("../../cpu/smp.zig");
    const sched = @import("../../proc/sched.zig");
    const me: u16 = if (smp.currentPid()) |p| @intCast(p) else return;
    if (@atomicLoad(u16, &self.lock_owner, .acquire) == me) {
        self.lock_depth += 1; // reentrant — we already hold it
        return;
    }
    const tid: u32 = @truncate(@intFromPtr(&self.lock_owner));
    while (true) {
        // CAS free(0xFFFF) -> me. cmpxchgStrong returns null on success.
        if (@cmpxchgStrong(u16, &self.lock_owner, 0xFFFF, me, .acq_rel, .acquire) == null) {
            self.lock_depth = 1;
            return;
        }
        sched.blockOnMutex(tid, &self.lock_owner); // sleep until released, then retry CAS
    }
}

pub fn unlockMount(self: *Mount) void {
    const smp = @import("../../cpu/smp.zig");
    const sched = @import("../../proc/sched.zig");
    const me: u16 = if (smp.currentPid()) |p| @intCast(p) else return;
    if (@atomicLoad(u16, &self.lock_owner, .acquire) != me) return; // not held by us (boot path)
    self.lock_depth -= 1;
    if (self.lock_depth == 0) {
        const tid: u32 = @truncate(@intFromPtr(&self.lock_owner));
        @atomicStore(u16, &self.lock_owner, 0xFFFF, .release);
        sched.wakeMutexWaiters(tid);
    }
}

/// Death-while-holding cleanup. Called from `tearDownTask`: if `pid` was killed
/// while holding the per-mount lock (e.g. blocked on NVMe I/O inside readBlock),
/// release it so the filesystem doesn't deadlock forever. The kill path parks
/// the pid off-CPU before teardown, so nothing races our reset of the owner.
pub fn releaseLockIfHeld(pid: u16) void {
    if (!mounted) return;
    const self = &mount_storage;
    if (@atomicLoad(u16, &self.lock_owner, .acquire) != pid) return;
    self.lock_depth = 0;
    // Died mid-compound-op: reset the defer depth or every future update
    // stays deferred forever. meta_dirty is left as-is — the next eager
    // writeBgdTable/writeSuperblock (any alloc/free outside a defer
    // scope) records current state, which subsumes the lost one.
    self.meta_defer_depth = 0;
    const tid: u32 = @truncate(@intFromPtr(&self.lock_owner));
    @atomicStore(u16, &self.lock_owner, 0xFFFF, .release);
    @import("../../proc/sched.zig").wakeMutexWaiters(tid);
}

/// Constant 4 KB zero block. Used as a source when a path needs to
/// write a fully-zeroed block (e.g. the partial-write zero-init in
/// writeFile) without burning a 4 KB stack buffer per call. Lives
/// in BSS, costs nothing at runtime.
pub const zero_block: [4096]u8 align(8) = [_]u8{0} ** 4096;

var mount_storage: Mount = undefined;
var mounted: bool = false;

pub fn isMounted() bool {
    return mounted;
}

pub fn getMount() ?*Mount {
    return if (mounted) &mount_storage else null;
}

/// Mount the ext2 filesystem on the ROOT disk starting at `partition_lba`
/// (0 for a whole-disk image) into the global mount slot. The root disk is
/// whatever driver/block.zig's secondary entry points currently route to —
/// see blkdev.setRootDisk and ext2.initAuto.
pub fn mount(partition_lba: u32) bool {
    if (!mountAt(&mount_storage, blkdev.readSectorsSecondary, blkdev.writeSectorsSecondary, partition_lba)) return false;
    mounted = true;
    return true;
}

/// The general form behind `mount`: mount through explicit sector accessors
/// into an explicit Mount slot. The installer uses this to hold a SECOND
/// mount (the freshly-formatted install target) without evicting the live
/// root. Nothing about `slot` is registered globally — the caller owns its
/// lifetime, flushes it (`flush(slot)`) when done writing, and the path-based
/// API in ext2.zig keeps addressing the global mount only. Buffers left from
/// an earlier mount in `slot` are dropped unwritten: the disk under it was
/// reformatted since. Returns false on bad magic, unsupported block size, or
/// BGD overflow.
pub fn mountAt(slot: *Mount, read_fn: ReadFn, write_fn: WriteFn, partition_lba: u32) bool {
    initCache();
    forget(slot);
    var sb: layout.Superblock = undefined;
    if (!readSuperblock(read_fn, partition_lba, &sb)) {
        debug.klog("[ext2] mount: superblock read failed at lba={d}\n", .{partition_lba});
        return false;
    }
    if (sb.magic != layout.MAGIC) {
        debug.klog("[ext2] mount: bad magic 0x{X} (expected 0x{X})\n", .{ sb.magic, layout.MAGIC });
        return false;
    }
    if (sb.log_block_size > 2) {
        debug.klog("[ext2] mount: unsupported log_block_size={d}\n", .{sb.log_block_size});
        return false;
    }

    const block_size: u32 = @as(u32, 1024) << @as(u5, @intCast(sb.log_block_size));

    // Validate the superblock fields that feed divisions / geometry below.
    // These are untrusted on-disk values; a zeroed or hostile field must
    // fail the mount, not divide-by-zero or overflow-trap the kernel.
    // (inode_size must divide block_size so inodes_per_block >= 1.)
    if (sb.inode_size == 0 or sb.inode_size > block_size or block_size % sb.inode_size != 0) {
        debug.klog("[ext2] mount: bad inode_size={d} for block_size={d}\n", .{ sb.inode_size, block_size });
        return false;
    }
    if (sb.blocks_per_group == 0 or sb.inodes_per_group == 0 or sb.blocks_count == 0) {
        debug.klog("[ext2] mount: zero blocks_count/blocks_per_group/inodes_per_group\n", .{});
        return false;
    }

    const sectors_per_block: u32 = block_size / SECTOR_SIZE;
    // Ceil-div as floor + remainder so `blocks_count + bpg - 1` can't
    // overflow u32 on a hostile blocks_count.
    const bgd_count: u32 = sb.blocks_count / sb.blocks_per_group +
        @intFromBool(sb.blocks_count % sb.blocks_per_group != 0);
    if (bgd_count > MAX_BGD_CACHED) {
        debug.klog("[ext2] mount: bgd_count={d} exceeds cache cap {d}\n", .{ bgd_count, MAX_BGD_CACHED });
        return false;
    }

    slot.* = .{
        .sb = sb,
        .block_size = block_size,
        .sectors_per_block = sectors_per_block,
        .inodes_per_block = block_size / sb.inode_size,
        .bgd_count = bgd_count,
        .bgd = &.{},
        .partition_lba = partition_lba,
        .read_sectors = read_fn,
        .write_sectors = write_fn,
    };
    // Self-referential slice, taken after the wholesale reset above settles.
    slot.bgd = slot.bgd_store[0..bgd_count];

    if (!readBgdTable(slot)) {
        debug.klog("[ext2] mount: BGD table read failed\n", .{});
        return false;
    }

    debug.klog(
        "[ext2] mounted: {d} blocks, {d} inodes, block_size={d}, {d} groups @ lba {d}\n",
        .{ sb.blocks_count, sb.inodes_count, block_size, bgd_count, partition_lba },
    );
    return true;
}

/// Read one fs block into `dst`. `dst.len` MUST equal `mount.block_size`.
pub fn readBlock(self: *Mount, block_num: u32, dst: []u8) bool {
    lockMount(self);
    defer unlockMount(self);
    if (block_num == 0 or block_num >= self.sb.blocks_count) return false;
    if (dst.len != self.block_size) return false;
    const i = getBuf(self, block_num, .read) orelse return false;
    @memcpy(dst, dataOf(i)[0..self.block_size]);
    unpin(i);
    return true;
}

/// Read up to `dst.len` bytes from absolute byte offset `byte_off` within
/// fs block `block_num`. Used by inode.zig for partial-block reads
/// (e.g., last block of a file that ends mid-block).
pub fn readBlockBytes(self: *Mount, block_num: u32, byte_off: u32, dst: []u8) bool {
    lockMount(self);
    defer unlockMount(self);
    if (block_num == 0 or block_num >= self.sb.blocks_count) return false;
    if (byte_off + dst.len > self.block_size) return false;
    const i = getBuf(self, block_num, .read) orelse return false;
    @memcpy(dst, dataOf(i)[byte_off .. byte_off + dst.len]);
    unpin(i);
    return true;
}

// =============================================================================
// Phase 2 — writes
// =============================================================================

/// Replace fs block `block_num` with `src` (must equal mount.block_size).
/// The block is not read first; it reaches the disk on the next flush.
pub fn writeBlock(self: *Mount, block_num: u32, src: []const u8) bool {
    lockMount(self);
    defer unlockMount(self);
    if (block_num == 0 or block_num >= self.sb.blocks_count) return false;
    if (src.len != self.block_size) return false;
    const i = getBuf(self, block_num, .overwrite) orelse return false;
    @memcpy(dataOf(i)[0..self.block_size], src);
    markDirtyUnpin(i);
    throttle(self);
    return true;
}

/// Write `src.len` bytes at `byte_off` within fs block `block_num`, the
/// rest of the block kept (read in first on a miss). Used for sub-block
/// updates (BGD entry, inode struct, dir entry, partial file block).
pub fn writeBlockBytes(self: *Mount, block_num: u32, byte_off: u32, src: []const u8) bool {
    lockMount(self);
    defer unlockMount(self);
    if (block_num == 0 or block_num >= self.sb.blocks_count) return false;
    if (byte_off + src.len > self.block_size) return false;
    if (!patchBlock(self, block_num, byte_off, src)) return false;
    throttle(self);
    return true;
}

/// Record the in-memory superblock in the buffer that holds it (bytes
/// 1024..2047 of the partition). Called after free_blocks_count /
/// free_inodes_count changes.
pub fn writeSuperblock(self: *Mount) bool {
    lockMount(self);
    defer unlockMount(self);
    if (self.meta_defer_depth > 0) {
        self.meta_dirty = true;
        return true;
    }
    return patchBlock(self, 1024 / self.block_size, 1024 % self.block_size, std.mem.asBytes(&self.sb));
}

/// Record the in-memory BGD table in its buffers. The cached array
/// (`bgd_store`) is the source of truth at runtime; this just copies it
/// out. With 64-entry cap and 32 B per entry, the table is at most 2 KB
/// (one block at 4 KB; partial block at 1 KB).
pub fn writeBgdTable(self: *Mount) bool {
    lockMount(self);
    defer unlockMount(self);
    if (self.meta_defer_depth > 0) {
        self.meta_dirty = true;
        return true;
    }
    const bgd_start_block: u32 = if (self.block_size == 1024) 2 else 1;
    const bytes_total: u32 = self.bgd_count * @sizeOf(layout.BlockGroupDescriptor);
    const blocks_needed: u32 = (bytes_total + self.block_size - 1) / self.block_size;
    const bgd_bytes: [*]const u8 = @ptrCast(self.bgd.ptr);
    for (0..blocks_needed) |i| {
        const block_num: u32 = bgd_start_block + @as(u32, @intCast(i));
        const dst_off: u32 = @as(u32, @intCast(i)) * self.block_size;
        const remain: u32 = bytes_total - dst_off;
        const take: u32 = if (remain >= self.block_size) self.block_size else remain;
        if (take == self.block_size) {
            if (!writeBlock(self, block_num, bgd_bytes[dst_off .. dst_off + self.block_size])) return false;
        } else {
            if (!writeBlockBytes(self, block_num, 0, bgd_bytes[dst_off .. dst_off + take])) return false;
        }
    }
    return true;
}

/// Enter a metadata-update deferral scope (see Mount.meta_defer_depth).
/// Nests like the mount lock; caller MUST pair with endMetaDefer before
/// releasing its mount-lock hold.
pub fn beginMetaDefer(self: *Mount) void {
    lockMount(self);
    defer unlockMount(self);
    self.meta_defer_depth += 1;
}

/// Leave a deferral scope; the outermost exit records the accumulated
/// BGD-table + superblock state once.
pub fn endMetaDefer(self: *Mount) void {
    lockMount(self);
    defer unlockMount(self);
    if (self.meta_defer_depth == 0) return; // unbalanced — be forgiving
    self.meta_defer_depth -= 1;
    if (self.meta_defer_depth == 0 and self.meta_dirty) {
        self.meta_dirty = false;
        // Attempt both even if the first fails — they cover disjoint blocks.
        const bgd_ok = writeBgdTable(self);
        const sb_ok = writeSuperblock(self);
        if (!bgd_ok or !sb_ok) {
            debug.klog("[ext2] endMetaDefer: deferred update failed (bgd={} sb={})\n", .{ bgd_ok, sb_ok });
        }
    }
}

/// Replace `n_blocks` CONTIGUOUS fs blocks from `src` — writeFile's
/// bulk-save path. flush merges them back into multi-sector commands.
pub fn writeBlockRun(self: *Mount, first_block: u32, n_blocks: u32, src: [*]const u8) bool {
    if (n_blocks == 0) return true;
    lockMount(self);
    defer unlockMount(self);
    if (first_block == 0 or first_block >= self.sb.blocks_count) return false;
    if (n_blocks > self.sb.blocks_count - first_block) return false;
    const bs = self.block_size;
    var k: u32 = 0;
    while (k < n_blocks) : (k += 1) {
        const i = getBuf(self, first_block + k, .overwrite) orelse return false;
        @memcpy(dataOf(i)[0..bs], src[k * bs ..][0..bs]);
        markDirtyUnpin(i);
    }
    throttle(self);
    return true;
}

/// Allocate one free data block, update the bitmap + group descriptor +
/// superblock counters, and return the global fs block number. Returns
/// null if the filesystem is full.
///
/// Bitmap layout: each group has a single block-bitmap block where bit `b`
/// represents fs block `first_data_block + group*blocks_per_group + b`.
/// Bits start cleared on a freshly-mkfs'd image except for the structural
/// blocks (superblock, BGD table, bitmaps, inode table).
pub fn allocBlock(self: *Mount) ?u32 {
    lockMount(self);
    defer unlockMount(self);
    var g: u32 = 0;
    while (g < self.bgd_count) : (g += 1) {
        if (self.bgd[g].free_blocks_count == 0) continue;
        if (allocBlockInGroup(self, g)) |bn| return bn;
    }
    return null;
}

/// Release one fs block back to its group's bitmap, bumping
/// `free_blocks_count` in both the BGD entry and the superblock. No-op
/// (returns false) if the block was already free — that's caller-side
/// double-free, surfaced as a klog so the bug is loud rather than silent
/// corruption. Reserved blocks (block_num == 0, or below first_data_block)
/// are likewise rejected. A freed block's unwritten contents are dropped.
pub fn freeBlock(self: *Mount, block_num: u32) bool {
    lockMount(self);
    defer unlockMount(self);
    if (block_num == 0 or block_num >= self.sb.blocks_count) return false;
    if (block_num < self.sb.first_data_block) return false;
    const rel: u32 = block_num - self.sb.first_data_block;
    const group: u32 = rel / self.sb.blocks_per_group;
    if (group >= self.bgd_count) return false;
    const block_in_group: u32 = rel % self.sb.blocks_per_group;
    const byte_idx: u32 = block_in_group / 8;
    const bit: u3 = @intCast(block_in_group % 8);
    const mask: u8 = @as(u8, 1) << bit;

    const bgd = &self.bgd[group];
    const bi = getBuf(self, bgd.block_bitmap, .read) orelse return false;
    const bitmap = dataOf(bi);
    if (bitmap[byte_idx] & mask == 0) {
        unpin(bi);
        debug.klog("[ext2] freeBlock: double-free of block {d} (bitmap bit clear)\n", .{block_num});
        return false;
    }
    bitmap[byte_idx] &= ~mask;
    markDirtyUnpin(bi);
    discard(self, block_num);
    bgd.free_blocks_count +%= 1;
    self.sb.free_blocks_count +%= 1;
    if (!writeBgdTable(self)) return false;
    if (!writeSuperblock(self)) return false;
    return true;
}

fn allocBlockInGroup(self: *Mount, group: u32) ?u32 {
    const bgd = &self.bgd[group];
    const bi = getBuf(self, bgd.block_bitmap, .read) orelse return null;
    const bitmap = dataOf(bi)[0..self.block_size];

    var byte_idx: u32 = 0;
    while (byte_idx < self.block_size) : (byte_idx += 1) {
        if (bitmap[byte_idx] == 0xFF) continue;
        var bit: u3 = 0;
        while (true) : (bit += 1) {
            const mask: u8 = @as(u8, 1) << bit;
            if (bitmap[byte_idx] & mask == 0) {
                const block_in_group: u32 = byte_idx * 8 + @as(u32, bit);
                const block_num: u32 = self.sb.first_data_block + group * self.sb.blocks_per_group + block_in_group;
                // Phantom-tail guard: bits past the group's real block count
                // represent fs blocks past sb.blocks_count. Per ext2 spec the
                // last group's tail bits should be pre-set to "allocated" by
                // mkfs, but a malformed image could leave them clear; without
                // this check we'd return a block number past EOF and the
                // subsequent write would land off-disk.
                if (block_num >= self.sb.blocks_count) {
                    if (bit == 7) break;
                    continue;
                }
                bitmap[byte_idx] |= mask;
                markDirtyUnpin(bi);
                bgd.free_blocks_count -|= 1;
                self.sb.free_blocks_count -|= 1;
                if (!writeBgdTable(self)) return null;
                if (!writeSuperblock(self)) return null;
                return block_num;
            }
            if (bit == 7) break;
        }
    }
    unpin(bi);
    return null;
}

// =============================================================================
// Buffer cache
// =============================================================================

const Buf = struct {
    /// null = descriptor free, holding no frame.
    mount: ?*Mount,
    blk: u32,
    frame: Phys,
    /// Bumped on every change to the contents. flush cleans a buffer only if
    /// it still has the generation flush copied out.
    gen: u32,
    pins: u16,
    dirty: bool,
    /// flush's copy of this buffer is on its way to the disk.
    writeback: bool,
    hash_next: u32,
    /// LRU neighbours; lru_head is the most recently used end. Free
    /// descriptors chain through lru_next.
    lru_prev: u32,
    lru_next: u32,
};

// All under cache_lock.
var bufs: [MAX_BUFS]Buf = undefined;
var buckets: [HASH_BUCKETS]u32 = undefined;
var free_desc: u32 = NO_BUF;
var lru_head: u32 = NO_BUF;
var lru_tail: u32 = NO_BUF;
/// Descriptors holding a frame.
var live: u32 = 0;
var dirty_count: u32 = 0;
var cache_ready: bool = false;
var cache_lock: spinlock.SpinLock = .{};

/// Serializes flushes; see flush. Registered, so a task killed mid-flush
/// doesn't keep it.
var flush_lock: spinlock.Mutex = .{};
/// Gathered dirty buffers of the running flush, with the generation each
/// had before its copy. Owned by the flush_lock holder.
var flush_batch: [FLUSH_BATCH]u32 = undefined;
var flush_gen: [FLUSH_BATCH]u32 = undefined;
var flush_stage: [FLUSH_RUN_BLOCKS * BUF_BYTES]u8 align(8) = undefined;

/// Counters for diagnostics (cache_lock).
pub const Stats = struct {
    live: u32 = 0,
    dirty: u32 = 0,
    hits: u64 = 0,
    misses: u64 = 0,
    read_blocks: u64 = 0,
    flushed_blocks: u64 = 0,
    flush_cmds: u64 = 0,
};
var counters: Stats = .{};

/// Snapshot of the cache counters.
pub fn stats() Stats {
    cache_lock.acquire();
    defer cache_lock.release();
    var s = counters;
    s.live = live;
    s.dirty = dirty_count;
    return s;
}

/// One-time setup, at the first mount (boot, single-threaded).
fn initCache() void {
    if (cache_ready) return;
    for (&buckets) |*b| b.* = NO_BUF;
    var i: u32 = 0;
    while (i < MAX_BUFS) : (i += 1) {
        bufs[i] = .{ .mount = null, .blk = 0, .frame = Phys.of(0), .gen = 0, .pins = 0, .dirty = false, .writeback = false, .hash_next = NO_BUF, .lru_prev = NO_BUF, .lru_next = if (i + 1 < MAX_BUFS) i + 1 else NO_BUF };
    }
    free_desc = 0;
    spinlock.registerLock("ext2.cache", &cache_lock);
    spinlock.registerMutex("ext2.flush", &flush_lock);
    pmm.registerReclaim(reclaim);
    cache_ready = true;
}

/// Buffers the cache grows to: a quarter of RAM, at most MAX_BUFS.
fn cap() u32 {
    return @min(MAX_BUFS, pmm.managedFrameCount() / 4);
}

/// Dirty buffers past which a writer flushes before going on.
fn dirtyLimit() u32 {
    return cap() / 2;
}

inline fn dataOf(i: u32) [*]u8 {
    return bufs[i].frame.toVirt().ptr([*]u8);
}

fn bucketOf(m: *const Mount, blk: u32) u32 {
    const h = ((@as(u64, @intFromPtr(m)) >> 4) *% 0x9E3779B97F4A7C15) ^ (@as(u64, blk) *% 0xC2B2AE3D27D4EB4F);
    return @intCast((h >> 29) & (HASH_BUCKETS - 1));
}

inline fn owns(i: u32, m: *const Mount) bool {
    return if (bufs[i].mount) |bm| bm == m else false;
}

fn find(m: *const Mount, blk: u32) ?u32 {
    // Index first: `buckets[bucketOf(..)]` copies the whole array onto the
    // stack to keep evaluation order around the call.
    const b = bucketOf(m, blk);
    var i = buckets[b];
    while (i != NO_BUF) : (i = bufs[i].hash_next) {
        if (owns(i, m) and bufs[i].blk == blk) return i;
    }
    return null;
}

fn hashInsert(i: u32) void {
    const b = bucketOf(bufs[i].mount.?, bufs[i].blk);
    bufs[i].hash_next = buckets[b];
    buckets[b] = i;
}

fn hashRemove(i: u32) void {
    const b = bucketOf(bufs[i].mount.?, bufs[i].blk);
    var link = &buckets[b];
    while (link.* != NO_BUF) : (link = &bufs[link.*].hash_next) {
        if (link.* == i) {
            link.* = bufs[i].hash_next;
            return;
        }
    }
}

fn lruUnlink(i: u32) void {
    const p = bufs[i].lru_prev;
    const n = bufs[i].lru_next;
    if (p != NO_BUF) bufs[p].lru_next = n else lru_head = n;
    if (n != NO_BUF) bufs[n].lru_prev = p else lru_tail = p;
    bufs[i].lru_prev = NO_BUF;
    bufs[i].lru_next = NO_BUF;
}

fn lruPushHead(i: u32) void {
    bufs[i].lru_prev = NO_BUF;
    bufs[i].lru_next = lru_head;
    if (lru_head != NO_BUF) bufs[lru_head].lru_prev = i else lru_tail = i;
    lru_head = i;
}

fn lruPushTail(i: u32) void {
    bufs[i].lru_next = NO_BUF;
    bufs[i].lru_prev = lru_tail;
    if (lru_tail != NO_BUF) bufs[lru_tail].lru_next = i else lru_head = i;
    lru_tail = i;
}

inline fn evictable(i: u32) bool {
    const b = &bufs[i];
    return b.pins == 0 and !b.dirty and !b.writeback;
}

/// Take a clean, idle buffer off the cold end of the LRU for reuse, frame
/// and all. Null when none is near the cold end.
fn evictOne() ?u32 {
    var i = lru_tail;
    var looked: u32 = 0;
    while (i != NO_BUF and looked < EVICT_SCAN_BUFS) : (looked += 1) {
        if (evictable(i)) {
            hashRemove(i);
            lruUnlink(i);
            return i;
        }
        i = bufs[i].lru_prev;
    }
    return null;
}

const Fill = enum { read, overwrite };

/// Buffer holding `blk` of `m`, pinned; on a miss read from disk when `fill`
/// is .read, left with stale bytes for the caller to overwrite when
/// .overwrite. Caller holds the mount lock and unpins. Null on a read error
/// or when no buffer can be had.
fn getBuf(m: *Mount, blk: u32, fill: Fill) ?u32 {
    if (pinCached(m, blk)) |i| return i;
    return switch (fill) {
        .read => readIn(m, blk),
        .overwrite => newBuf(m, blk),
    };
}

/// `blk` of `m` pinned and made most recent, if cached.
fn pinCached(m: *Mount, blk: u32) ?u32 {
    cache_lock.acquire();
    defer cache_lock.release();
    const i = find(m, blk) orelse {
        counters.misses += 1;
        return null;
    };
    bufs[i].pins += 1;
    lruUnlink(i);
    lruPushHead(i);
    counters.hits += 1;
    return i;
}

/// How many of the `n` blocks from `blk` on are uncached before the first
/// cached one (at least 1: `blk` itself is known uncached).
fn uncachedRun(m: *Mount, blk: u32, n: u32) u32 {
    cache_lock.acquire();
    defer cache_lock.release();
    var k: u32 = 1;
    while (k < n and find(m, blk + k) == null) k += 1;
    return k;
}

/// Read `blk` and the blocks after it, up to the first one already cached
/// (a cached block may be newer than the disk), and cache them all; the
/// read-ahead ones at the cold end, so they leave first unless used.
/// Returns `blk`'s buffer, pinned. Mount lock held: no one else adds
/// buffers of `m` meanwhile, so the window stays uncached.
fn readIn(m: *Mount, blk: u32) ?u32 {
    const n = uncachedRun(m, blk, @min(READAHEAD_BLOCKS, m.sb.blocks_count - blk));
    if (!m.read_sectors(blockLba(m, blk), @intCast(n * m.sectors_per_block), &m.read_stage)) return null;
    const bs = m.block_size;
    const first = newBuf(m, blk) orelse return null;
    @memcpy(dataOf(first)[0..bs], m.read_stage[0..bs]);
    var k: u32 = 1;
    while (k < n) : (k += 1) {
        // Read-ahead is a guess: never flush or overcommit for it.
        const i = claimBuf(m, blk + k, false) orelse break;
        @memcpy(dataOf(i)[0..bs], m.read_stage[k * bs ..][0..bs]);
        unpinCold(i);
    }
    cache_lock.acquire();
    counters.read_blocks += n;
    cache_lock.release();
    return first;
}

/// Unpin a read-ahead buffer and send it to the cold end of the LRU.
fn unpinCold(i: u32) void {
    cache_lock.acquire();
    defer cache_lock.release();
    bufs[i].pins -= 1;
    lruUnlink(i);
    lruPushTail(i);
}

/// A pinned buffer for `blk` of `m` (not cached before), its bytes stale.
/// Grows the cache while under cap() and memory is plentiful, else reuses
/// the coldest clean buffer; with nothing clean, flushes `m` and tries again,
/// and as a last resort takes a frame past the cap.
fn newBuf(m: *Mount, blk: u32) ?u32 {
    if (claimBuf(m, blk, false)) |i| return i;
    _ = flush(m);
    return claimBuf(m, blk, true);
}

fn claimBuf(m: *Mount, blk: u32, any_frame: bool) ?u32 {
    const free_floor = pmm.managedFrameCount() / 8;
    const grow = any_frame or (@atomicLoad(u32, &live, .monotonic) < cap() and pmm.freeFrameCount() > free_floor);
    var frame: ?Phys = if (grow) pmm.allocFrame() else null;
    cache_lock.acquire();
    defer cache_lock.release();
    var i: u32 = NO_BUF;
    if (frame != null and free_desc != NO_BUF) {
        i = free_desc;
        free_desc = bufs[i].lru_next;
        bufs[i].frame = frame.?;
        frame = null;
        live += 1;
    } else if (evictOne()) |e| {
        i = e;
    }
    if (frame) |f| pmm.releaseFrame(f); // no descriptor left for it
    if (i == NO_BUF) return null;
    const b = &bufs[i];
    b.mount = m;
    b.blk = blk;
    b.gen = 0;
    b.pins = 1;
    b.dirty = false;
    b.writeback = false;
    hashInsert(i);
    lruPushHead(i);
    return i;
}

fn unpin(i: u32) void {
    cache_lock.acquire();
    defer cache_lock.release();
    bufs[i].pins -= 1;
}

/// The caller changed buffer `i`'s contents: it now differs from the disk.
fn markDirtyUnpin(i: u32) void {
    cache_lock.acquire();
    defer cache_lock.release();
    const b = &bufs[i];
    b.gen +%= 1;
    if (!b.dirty) {
        b.dirty = true;
        dirty_count += 1;
    }
    b.pins -= 1;
}

/// Overwrite part of a block, reading the rest in on a miss. Mount lock held.
fn patchBlock(m: *Mount, blk: u32, off: u32, src: []const u8) bool {
    const i = getBuf(m, blk, .read) orelse return false;
    @memcpy(dataOf(i)[off .. off + src.len], src);
    markDirtyUnpin(i);
    return true;
}

/// `blk` was freed: whatever it held need not reach the disk.
fn discard(m: *Mount, blk: u32) void {
    cache_lock.acquire();
    defer cache_lock.release();
    const i = find(m, blk) orelse return;
    const b = &bufs[i];
    if (b.dirty and b.pins == 0) {
        b.dirty = false;
        b.gen +%= 1; // a flush already copying it must not count it written
        dirty_count -= 1;
    }
}

/// Too much dirty data: write `m` out before taking more. Mount lock held.
fn throttle(m: *Mount) void {
    if (@atomicLoad(u32, &dirty_count, .monotonic) > dirtyLimit()) _ = flush(m);
}

/// Write every dirty buffer of `only` (all mounts when null) to the disk;
/// returns how many blocks went out. Task context, may sleep on I/O, no
/// spinlock held; the mount lock may be held, flush takes none.
///
/// Contents are copied out with no mount lock, so a writer may change a
/// buffer while flush copies it. The writer bumps the buffer's generation
/// after every change, and flush marks a written buffer clean only if its
/// generation is still the one gathered; a torn copy is therefore always
/// followed by another write of that block.
pub fn flush(only: ?*Mount) u32 {
    if (!cache_ready) return 0;
    flush_lock.acquire();
    defer flush_lock.release();
    clearStaleWriteback();
    var written: u32 = 0;
    // Rounds enough for what is dirty now; a writer re-dirtying buffers as
    // fast as they go out must not keep the flush going forever.
    var rounds = @atomicLoad(u32, &dirty_count, .monotonic) / FLUSH_BATCH + 2;
    while (rounds > 0) : (rounds -= 1) {
        const n = gatherDirty(only);
        if (n == 0) break;
        sortBatch(n);
        var failed = false;
        var k: u32 = 0;
        while (k < n) {
            const first = &bufs[flush_batch[k]];
            const m = first.mount.?;
            var run: u32 = 1;
            while (k + run < n and run < FLUSH_RUN_BLOCKS) : (run += 1) {
                if (!owns(flush_batch[k + run], m) or bufs[flush_batch[k + run]].blk != first.blk + run) break;
            }
            const bs = m.block_size;
            for (0..run) |r| @memcpy(flush_stage[r * bs ..][0..bs], dataOf(flush_batch[k + r])[0..bs]);
            const ok = m.write_sectors(blockLba(m, first.blk), @intCast(run * m.sectors_per_block), &flush_stage);
            if (!ok) {
                failed = true;
                debug.klog("[ext2] flush: write of blocks {d}..{d} failed, kept dirty\n", .{ first.blk, first.blk + run - 1 });
            }
            finishRun(k, run, ok);
            if (ok) written += run;
            k += run;
        }
        if (failed or n < FLUSH_BATCH) break;
    }
    return written;
}

/// Writeback marks are set and cleared only by the flush_lock holder; one
/// seen at the start of a flush was left by a flush whose task died.
fn clearStaleWriteback() void {
    cache_lock.acquire();
    defer cache_lock.release();
    for (bufs[0..MAX_BUFS]) |*b| b.writeback = false;
}

/// Mark up to FLUSH_BATCH dirty buffers of `only` writeback into
/// flush_batch; returns how many.
fn gatherDirty(only: ?*Mount) u32 {
    cache_lock.acquire();
    defer cache_lock.release();
    var n: u32 = 0;
    if (dirty_count == 0) return 0;
    var i: u32 = 0;
    while (i < MAX_BUFS and n < FLUSH_BATCH) : (i += 1) {
        const b = &bufs[i];
        if (!b.dirty or b.writeback or b.mount == null) continue;
        if (only) |m| if (!owns(i, m)) continue;
        b.writeback = true;
        flush_batch[n] = i;
        n += 1;
    }
    return n;
}

/// Order the batch by (mount, block) and record each buffer's generation.
/// Any moment before the copy will do for the generation: a change that
/// lands after it bumps it again.
fn sortBatch(n: u32) void {
    const Ctx = struct {
        fn lessThan(_: void, a: u32, b: u32) bool {
            const ma = @intFromPtr(bufs[a].mount.?);
            const mb = @intFromPtr(bufs[b].mount.?);
            if (ma != mb) return ma < mb;
            return bufs[a].blk < bufs[b].blk;
        }
    };
    // Mount and block of a writeback buffer don't change: it can't be evicted.
    std.sort.pdq(u32, flush_batch[0..n], {}, Ctx.lessThan);
    cache_lock.acquire();
    defer cache_lock.release();
    var k: u32 = 0;
    while (k < n) : (k += 1) flush_gen[k] = bufs[flush_batch[k]].gen;
}

/// The run flush_batch[k..k+run] was written (ok) or not.
fn finishRun(k: u32, run: u32, ok: bool) void {
    cache_lock.acquire();
    defer cache_lock.release();
    var r: u32 = 0;
    while (r < run) : (r += 1) {
        const b = &bufs[flush_batch[k + r]];
        b.writeback = false;
        if (ok and b.dirty and b.gen == flush_gen[k + r]) {
            b.dirty = false;
            dirty_count -= 1;
        }
    }
    counters.flushed_blocks += if (ok) run else 0;
    counters.flush_cmds += 1;
}

/// Drop every buffer of `m` without writing it: the disk under `m` was
/// rewritten behind the cache (mkfs before a remount). Buffers of `m`
/// still pinned or under writeback stay; nothing uses an unmounted slot.
pub fn forget(m: *Mount) void {
    if (!cache_ready) return;
    cache_lock.acquire();
    defer cache_lock.release();
    var i: u32 = 0;
    while (i < MAX_BUFS) : (i += 1) {
        const b = &bufs[i];
        if (b.mount != m or b.pins != 0 or b.writeback) continue;
        if (b.dirty) dirty_count -= 1;
        hashRemove(i);
        lruUnlink(i);
        pmm.releaseFrame(b.frame);
        b.mount = null;
        b.dirty = false;
        b.lru_next = free_desc;
        free_desc = i;
        live -= 1;
    }
}

/// pmm reclaim hook: give back up to `needed` clean, idle buffers, coldest
/// first. Non-blocking (a page fault calls it); cache_lock -> pmm order.
fn reclaim(needed: u32) u32 {
    if (needed == 0 or !cache_ready) return 0;
    cache_lock.acquire();
    defer cache_lock.release();
    var freed: u32 = 0;
    var i = lru_tail;
    while (i != NO_BUF and freed < needed) {
        const prev = bufs[i].lru_prev;
        if (evictable(i)) {
            hashRemove(i);
            lruUnlink(i);
            pmm.releaseFrame(bufs[i].frame);
            bufs[i].mount = null;
            bufs[i].lru_next = free_desc;
            free_desc = i;
            live -= 1;
            freed += 1;
        }
        i = prev;
    }
    return freed;
}

// =============================================================================
// Internal
// =============================================================================

inline fn blockLba(self: *const Mount, block_num: u32) u32 {
    return self.partition_lba + block_num * self.sectors_per_block;
}

/// Bypass the block cache to read the SB. The cache isn't initialized yet
/// at this point and the SB only needs reading once per boot anyway.
fn readSuperblock(read_fn: ReadFn, partition_lba: u32, dst: *layout.Superblock) bool {
    var buf: [2 * SECTOR_SIZE]u8 align(8) = undefined;
    // SB lives at byte 1024..2048 within the FS → sectors 2..3.
    if (!read_fn(partition_lba + 2, 2, &buf)) return false;
    const src = std.mem.bytesAsValue(layout.Superblock, &buf);
    dst.* = src.*;
    return true;
}

/// BGD table sits in the block immediately after the primary SB.
/// At 1 KB blocks: SB is in block 1 → BGDs start at block 2.
/// At >=2 KB blocks: SB is in block 0 → BGDs start at block 1.
fn readBgdTable(self: *Mount) bool {
    const bgd_start_block: u32 = if (self.block_size == 1024) 2 else 1;
    const bytes_needed: u32 = self.bgd_count * @sizeOf(layout.BlockGroupDescriptor);
    const blocks_needed: u32 = (bytes_needed + self.block_size - 1) / self.block_size;

    const bgd_bytes: [*]u8 = @ptrCast(self.bgd.ptr);
    for (0..blocks_needed) |i| {
        const block_num: u32 = bgd_start_block + @as(u32, @intCast(i));
        const dst_off: u32 = @as(u32, @intCast(i)) * self.block_size;
        const remain: u32 = bytes_needed - dst_off;
        const take: u32 = if (remain >= self.block_size) self.block_size else remain;
        if (take == self.block_size) {
            if (!readBlock(self, block_num, bgd_bytes[dst_off..][0..self.block_size])) return false;
        } else {
            if (!readBlockBytes(self, block_num, 0, bgd_bytes[dst_off..][0..take])) return false;
        }
    }
    return true;
}
