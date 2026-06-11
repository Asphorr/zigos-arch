// ext2 mount state + block-level I/O. Reads pass through an aligned
// cache window — same shape as fat32's FAT cache, since the underlying
// block driver batches up to N sectors per call but only serves one
// byte range at a time.
//
// Cache size (2026-05-29): 256 sectors = 128 KiB = 4 x nvme's
// MAX_SECTORS_PER_CMD. Each cache fill spans 4 NVMe commands, which
// nvme.readSectorsPipelined submits CONCURRENTLY (QD4) instead of serially —
// the fix for the QD=1 serialization where ~95% of an ELF load was spent
// blocked one command at a time. History: 64 sectors / 32 KiB (one command
// per fill, fully serial) -> 128 / 64 KiB (QD2: measured the wait on a 942 KiB
// load drop 243M -> 32M cycles, ~95% -> 27% of load time) -> 256 / 128 KiB
// (QD4). The read_sectors count param was widened u8 -> u16 so a fill can
// exceed 255 sectors. Sequential file reads (the dominant ELF-load pattern)
// keep their high hit rate; the wider window just deepens the pipeline. To go
// to QD8, bump to 512 (u16 already fits; ATA chunks at 128 either way).
//
// At 4 KB ext2 blocks the cache covers 32 logical blocks per fill; at 1 KB it
// covers 128. Random-access workloads (directory walks, btree metadata)
// over-fetch by the cache size — now 128 KiB max per fill, 256 KiB across the
// 2 ways. That over-fetch is the reason we don't widen further by default: a
// metadata-hop workload that keeps missing both ways re-reads 128 KiB a time.
//
// Writes are implemented: writeBlock / writeBlockBytes + the bitmap
// alloc/free paths all funnel through the same cache window.

const std = @import("std");
const layout = @import("layout.zig");
const blkdev = @import("../../driver/block.zig");
const debug = @import("../../debug/debug.zig");

const SECTOR_SIZE: u32 = 512;
const CACHE_SECTORS: u32 = 256; // 128 KiB window = 4 pipelined NVMe cmds (QD4); see header. MUST stay a power of 2 (cacheBaseFor masks).
const CACHE_BYTES: u32 = CACHE_SECTORS * SECTOR_SIZE;

/// Number of independent cache windows. 2 is enough for the dominant
/// ext2 access pattern (inode lookup followed by data block read at a
/// far LBA): one way pins the inode-table block, the other holds the
/// sequential data window. Bumping to 4+ would help only on workloads
/// that hop across >2 metadata regions, which is rare. Each way costs
/// CACHE_BYTES in BSS (128 KB at the default).
const CACHE_WAYS: u32 = 2;

// Function-pointer indirection: lets Phase 3 swap the underlying device
// (secondary → primary) without touching ext2/ internals. Same idea as
// the block driver's own backend dispatch.
const ReadFn = *const fn (lba: u32, count: u16, dest: [*]u8) bool;
const WriteFn = *const fn (lba: u32, src: [*]const u8) void;

pub const Mount = struct {
    sb: layout.Superblock,
    block_size: u32,
    sectors_per_block: u32,
    inodes_per_block: u32,
    bgd_count: u32,
    bgd: []layout.BlockGroupDescriptor,
    /// First LBA of the ext2 filesystem within the disk. 0 when the
    /// disk is one big ext2 fs (no partition table).
    partition_lba: u32,
    read_sectors: ReadFn,
    write_sector: WriteFn,
    /// Set-associative cache: CACHE_WAYS independent windows, each
    /// CACHE_SECTORS-aligned. cache_base_lba[i] is in disk LBAs, not
    /// fs blocks. 0xFFFFFFFF = empty slot. `cache_next_evict` is a
    /// simple LRU bit for 2-way: on a hit at way X we set it to 1-X so
    /// the next miss evicts the older one. For CACHE_WAYS > 2 this
    /// would need expansion (e.g. per-way last_used counter); kept
    /// minimal because 2 ways covers the structural workload.
    cache_base_lba: [CACHE_WAYS]u32 = [_]u32{0xFFFFFFFF} ** CACHE_WAYS,
    cache_buf: [CACHE_WAYS][CACHE_BYTES]u8 align(8) = undefined,
    cache_next_evict: u8 = 0,

    /// Per-mount REENTRANT SLEEPING lock (2026-06-04). The block cache,
    /// BGD table, and superblock above are shared mutable state with NO
    /// other synchronization, but ext2 runs concurrently on every CPU
    /// (no big syscall lock; MAX_PROCS=64). Under SMP a write-back that
    /// races a concurrent cache-window refill wrote a shifted slice of one
    /// file over another's on-disk block — the redteam/cat "corrupt ELF on
    /// disk" bug. Every cache-touching block op (readBlock/writeBlock/
    /// alloc/free/bgd/sb) takes this first. SLEEPING because those ops block
    /// on NVMe I/O while holding it; REENTRANT because alloc/free nest
    /// (allocBlock -> writeBgdTable -> writeBlock). 0xFFFF owner = free.
    lock_owner: u16 = 0xFFFF, // (a) pid holding the lock
    lock_depth: u32 = 0, // recursion depth — only the owner mutates
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
/// Lock order: mount lock -> page_cache.lock (invalidate* under hold is
/// fine — page_cache never calls back into the fs while holding its lock).
pub fn lockMount(self: *Mount) void {
    const smp = @import("../../cpu/smp.zig");
    const sched = @import("../../proc/sched.zig");
    const me: u16 = if (smp.myCpu().current_pid) |p| @intCast(p) else return;
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
    const me: u16 = if (smp.myCpu().current_pid) |p| @intCast(p) else return;
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
    const tid: u32 = @truncate(@intFromPtr(&self.lock_owner));
    @atomicStore(u16, &self.lock_owner, 0xFFFF, .release);
    @import("../../proc/sched.zig").wakeMutexWaiters(tid);
}

// BGD table cache. 64 entries × 32 B = 2 KB; covers ~8 GB at 4 KB blocks
// with 32K blocks/group. Larger disks would need PMM-allocated storage.
const MAX_BGD_CACHED: u32 = 64;
var bgd_storage: [MAX_BGD_CACHED]layout.BlockGroupDescriptor align(8) = undefined;

/// Constant 4 KB zero block. Used as a source when a path needs to
/// write a fully-zeroed block to disk (e.g. the partial-write zero-init
/// in writeFile) without burning a 4 KB stack buffer per call. Lives
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

/// Mount the ext2 filesystem on the secondary disk starting at
/// `partition_lba`. Use partition_lba=0 for a whole-disk image.
/// Returns false on bad magic, unsupported block size, or BGD overflow.
pub fn mount(partition_lba: u32) bool {
    var sb: layout.Superblock = undefined;
    if (!readSuperblock(partition_lba, &sb)) {
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

    mount_storage = .{
        .sb = sb,
        .block_size = block_size,
        .sectors_per_block = sectors_per_block,
        .inodes_per_block = block_size / sb.inode_size,
        .bgd_count = bgd_count,
        .bgd = bgd_storage[0..bgd_count],
        .partition_lba = partition_lba,
        .read_sectors = blkdev.readSectorsSecondary,
        .write_sector = blkdev.writeSectorSecondary,
    };

    if (!readBgdTable(&mount_storage)) {
        debug.klog("[ext2] mount: BGD table read failed\n", .{});
        return false;
    }

    mounted = true;
    debug.klog(
        "[ext2] mounted: {d} blocks, {d} inodes, block_size={d}, {d} groups\n",
        .{ sb.blocks_count, sb.inodes_count, block_size, bgd_count },
    );
    return true;
}

/// Read one fs block into `dst`. `dst.len` MUST equal `mount.block_size`.
pub fn readBlock(self: *Mount, block_num: u32, dst: []u8) bool {
    lockMount(self);
    defer unlockMount(self);
    if (block_num == 0 or block_num >= self.sb.blocks_count) return false;
    if (dst.len != self.block_size) return false;
    const lba = blockLba(self, block_num);
    const way = ensureCacheLoaded(self, lba) orelse return false;
    const off = (lba - self.cache_base_lba[way]) * SECTOR_SIZE;
    @memcpy(dst, self.cache_buf[way][off .. off + self.block_size]);
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
    const lba = blockLba(self, block_num);
    const way = ensureCacheLoaded(self, lba) orelse return false;
    const off = (lba - self.cache_base_lba[way]) * SECTOR_SIZE + byte_off;
    @memcpy(dst, self.cache_buf[way][off .. off + dst.len]);
    return true;
}

// =============================================================================
// Phase 2 — writes
// =============================================================================

/// Write one fs block from `src` (must equal mount.block_size). Issues
/// `sectors_per_block` per-sector writes through the underlying block
/// driver; updates the read cache in-place if the cache currently covers
/// this block (no extra read needed). All write paths funnel through here
/// so a single cache-invalidation strategy covers everything.
pub fn writeBlock(self: *Mount, block_num: u32, src: []const u8) bool {
    lockMount(self);
    defer unlockMount(self);
    if (block_num == 0 or block_num >= self.sb.blocks_count) return false;
    if (src.len != self.block_size) return false;
    const lba = blockLba(self, block_num);
    var s: u32 = 0;
    while (s < self.sectors_per_block) : (s += 1) {
        const sec_off = s * SECTOR_SIZE;
        self.write_sector(lba + s, src.ptr + sec_off);
    }
    // Refresh whichever cache way currently covers this LBA window so a
    // subsequent read sees the new bytes without a re-fetch. With 2-way
    // LRU either way could hold the window; check both.
    const base = cacheBaseFor(lba);
    var w: u8 = 0;
    while (w < CACHE_WAYS) : (w += 1) {
        if (self.cache_base_lba[w] == base) {
            const off = (lba - self.cache_base_lba[w]) * SECTOR_SIZE;
            @memcpy(self.cache_buf[w][off .. off + self.block_size], src);
            break;
        }
    }
    return true;
}

/// Write `src.len` bytes at `byte_off` within fs block `block_num`. Reads
/// the block, patches it, writes it back. Used for sub-block updates
/// (BGD entry, inode struct, dir entry).
///
/// Patches the read cache in place rather than staging through a 4 KB
/// stack buffer — the cache IS authoritative until the next
/// `ensureCacheLoaded` for a different block, so writing back from the
/// cache is correct and saves 4 KB of kernel stack on every fwrite/
/// truncate path. Without this the fwrite call chain (sysFwrite →
/// writeFile → writeBlockBytes → driver) stacks two 4 KB scratch
/// buffers + syscall-entry frames and overflows a 16 KB kstack on
/// non-trivial saves.
pub fn writeBlockBytes(self: *Mount, block_num: u32, byte_off: u32, src: []const u8) bool {
    lockMount(self);
    defer unlockMount(self);
    if (block_num == 0 or block_num >= self.sb.blocks_count) return false;
    if (byte_off + src.len > self.block_size) return false;
    const lba = blockLba(self, block_num);
    const way = ensureCacheLoaded(self, lba) orelse return false;
    const cache_off_base = (lba - self.cache_base_lba[way]) * SECTOR_SIZE;
    @memcpy(
        self.cache_buf[way][cache_off_base + byte_off .. cache_off_base + byte_off + src.len],
        src,
    );
    var s: u32 = 0;
    while (s < self.sectors_per_block) : (s += 1) {
        const sec_off: u32 = cache_off_base + s * SECTOR_SIZE;
        self.write_sector(lba + s, @as([*]const u8, @ptrCast(&self.cache_buf[way])) + sec_off);
    }
    return true;
}

/// Persist the in-memory superblock to its on-disk slot (LBAs 2..3 within
/// the partition). Called after free_blocks_count / free_inodes_count
/// changes.
pub fn writeSuperblock(self: *Mount) bool {
    lockMount(self);
    defer unlockMount(self);
    const sb_bytes: [*]const u8 = @ptrCast(&self.sb);
    self.write_sector(self.partition_lba + 2, sb_bytes);
    self.write_sector(self.partition_lba + 3, sb_bytes + SECTOR_SIZE);
    return true;
}

/// Persist the in-memory BGD table back to disk. The cached array
/// (`bgd_storage`) is the source of truth at runtime; this just flushes
/// it. With 64-entry cap and 32 B per entry, the table is at most 2 KB
/// (one block at 4 KB; partial block at 1 KB).
pub fn writeBgdTable(self: *Mount) bool {
    lockMount(self);
    defer unlockMount(self);
    const bgd_start_block: u32 = if (self.block_size == 1024) 2 else 1;
    const bytes_total: u32 = self.bgd_count * @sizeOf(layout.BlockGroupDescriptor);
    const blocks_needed: u32 = (bytes_total + self.block_size - 1) / self.block_size;
    const bgd_bytes: [*]const u8 = @ptrCast(&bgd_storage);
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
/// are likewise rejected.
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
    const bitmap_lba = blockLba(self, bgd.block_bitmap);
    const way = ensureCacheLoaded(self, bitmap_lba) orelse return false;
    const cache_off_base = (bitmap_lba - self.cache_base_lba[way]) * SECTOR_SIZE;
    const slice = self.cache_buf[way][cache_off_base .. cache_off_base + self.block_size];

    if (slice[byte_idx] & mask == 0) {
        debug.klog("[ext2] freeBlock: double-free of block {d} (bitmap bit clear)\n", .{block_num});
        return false;
    }
    slice[byte_idx] &= ~mask;
    var s: u32 = 0;
    while (s < self.sectors_per_block) : (s += 1) {
        const sec_off: u32 = cache_off_base + s * SECTOR_SIZE;
        self.write_sector(bitmap_lba + s, @as([*]const u8, @ptrCast(&self.cache_buf[way])) + sec_off);
    }
    bgd.free_blocks_count +%= 1;
    self.sb.free_blocks_count +%= 1;
    if (!writeBgdTable(self)) return false;
    if (!writeSuperblock(self)) return false;
    return true;
}

fn allocBlockInGroup(self: *Mount, group: u32) ?u32 {
    const bgd = &self.bgd[group];

    // Load the bitmap block into the read cache and patch in place,
    // mirroring the same kstack-light pattern as writeBlockBytes. Note:
    // writeBgdTable + writeSuperblock below may evict the bitmap from
    // the cache, but we no longer need `slice` after the bitmap write.
    const bitmap_lba = blockLba(self, bgd.block_bitmap);
    const way = ensureCacheLoaded(self, bitmap_lba) orelse return null;
    const cache_off_base = (bitmap_lba - self.cache_base_lba[way]) * SECTOR_SIZE;
    const slice = self.cache_buf[way][cache_off_base .. cache_off_base + self.block_size];

    var byte_idx: u32 = 0;
    while (byte_idx < self.block_size) : (byte_idx += 1) {
        if (slice[byte_idx] == 0xFF) continue;
        var bit: u3 = 0;
        while (true) : (bit += 1) {
            const mask: u8 = @as(u8, 1) << bit;
            if (slice[byte_idx] & mask == 0) {
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
                slice[byte_idx] |= mask;
                // Persist the bitmap directly from the cache.
                var s: u32 = 0;
                while (s < self.sectors_per_block) : (s += 1) {
                    const sec_off: u32 = cache_off_base + s * SECTOR_SIZE;
                    self.write_sector(bitmap_lba + s, @as([*]const u8, @ptrCast(&self.cache_buf[way])) + sec_off);
                }
                bgd.free_blocks_count -|= 1;
                self.sb.free_blocks_count -|= 1;
                if (!writeBgdTable(self)) return null;
                if (!writeSuperblock(self)) return null;
                return block_num;
            }
            if (bit == 7) break;
        }
    }
    return null;
}

// =============================================================================
// Internal
// =============================================================================

inline fn blockLba(self: *const Mount, block_num: u32) u32 {
    return self.partition_lba + block_num * self.sectors_per_block;
}

/// Window-align an LBA to the cache boundary so adjacent blocks share fills.
inline fn cacheBaseFor(lba: u32) u32 {
    return lba & ~(CACHE_SECTORS - 1);
}

/// Ensure the cache contains the CACHE_SECTORS-aligned window covering
/// `lba`, returning the way index it sits in. Hits promote the OTHER
/// way to the eviction slot (2-way LRU). Misses evict the current
/// `cache_next_evict` slot, refill it from disk, then promote it as MRU.
///
/// Returns null on a propagated backend read failure (BUG 2 fix, 2026-06-04).
/// The NVMe backend's `read_sectors` now returns a real bool, so a failed
/// cache fill surfaces here as null instead of silently caching whatever
/// stale bytes the fill left behind. Every caller already does
/// `orelse return false/null`, so the failure flows the whole way up:
/// readBlock -> readInodeBytes (short) -> loadFile (short read) -> clean null.
fn ensureCacheLoaded(self: *Mount, lba: u32) ?u8 {
    const base = cacheBaseFor(lba);
    var i: u8 = 0;
    while (i < CACHE_WAYS) : (i += 1) {
        if (self.cache_base_lba[i] == base) {
            self.cache_next_evict = @intCast(1 - @as(u32, i));
            return i;
        }
    }
    const evict: u8 = self.cache_next_evict;
    if (!self.read_sectors(base, @intCast(CACHE_SECTORS), &self.cache_buf[evict])) {
        // I/O failure mid-fill: cache_buf[evict] is now partially overwritten.
        // Invalidate this way so a later lookup for the OLD base can't match a
        // corrupt window, and DON'T mark `base` valid. Propagate as a miss-fail.
        self.cache_base_lba[evict] = 0xFFFFFFFF;
        return null;
    }
    self.cache_base_lba[evict] = base;
    self.cache_next_evict = @intCast(1 - @as(u32, evict));
    return evict;
}

/// Bypass the block cache to read the SB. The cache isn't initialized yet
/// at this point and the SB only needs reading once per boot anyway.
fn readSuperblock(partition_lba: u32, dst: *layout.Superblock) bool {
    var buf: [2 * SECTOR_SIZE]u8 align(8) = undefined;
    // SB lives at byte 1024..2048 within the FS → sectors 2..3.
    if (!blkdev.readSectorsSecondary(partition_lba + 2, 2, &buf)) return false;
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

    var bgd_bytes: [*]u8 = @ptrCast(&bgd_storage);
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
