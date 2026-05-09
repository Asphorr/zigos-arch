// ext2 mount state + block-level I/O. Reads pass through an 8-sector
// (4 KB) aligned cache window — same shape as fat32's 8-sector FAT cache,
// since the underlying block driver batches up to N sectors per call but
// only serves one byte range at a time.
//
// At 4 KB ext2 blocks (the typical mkfs default) the cache holds exactly
// one block. At smaller blocks (1 KB / 2 KB) the cache holds 4 / 2
// blocks per fill, amortising disk latency across nearby blocks.
//
// Phase 1: read-only. The dirty mask + writeBlock land in Phase 2.

const std = @import("std");
const layout = @import("layout.zig");
const blkdev = @import("../../driver/block.zig");
const debug = @import("../../debug/debug.zig");

const SECTOR_SIZE: u32 = 512;
const CACHE_SECTORS: u32 = 8;
const CACHE_BYTES: u32 = CACHE_SECTORS * SECTOR_SIZE;

// Function-pointer indirection: lets Phase 3 swap the underlying device
// (secondary → primary) without touching ext2/ internals. Same idea as
// the block driver's own backend dispatch.
const ReadFn = *const fn (lba: u32, count: u8, dest: [*]u8) void;
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
    /// 8-sector aligned cache window. cache_base_lba is in disk LBAs,
    /// not fs blocks. 0xFFFFFFFF = empty.
    cache_base_lba: u32 = 0xFFFFFFFF,
    cache_buf: [CACHE_BYTES]u8 align(8) = undefined,
};

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
    const sectors_per_block: u32 = block_size / SECTOR_SIZE;
    const bgd_count: u32 = (sb.blocks_count + sb.blocks_per_group - 1) / sb.blocks_per_group;
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
    if (block_num == 0 or block_num >= self.sb.blocks_count) return false;
    if (dst.len != self.block_size) return false;
    const lba = blockLba(self, block_num);
    if (!ensureCacheLoaded(self, lba)) return false;
    const off = (lba - self.cache_base_lba) * SECTOR_SIZE;
    @memcpy(dst, self.cache_buf[off .. off + self.block_size]);
    return true;
}

/// Read up to `dst.len` bytes from absolute byte offset `byte_off` within
/// fs block `block_num`. Used by inode.zig for partial-block reads
/// (e.g., last block of a file that ends mid-block).
pub fn readBlockBytes(self: *Mount, block_num: u32, byte_off: u32, dst: []u8) bool {
    if (block_num == 0 or block_num >= self.sb.blocks_count) return false;
    if (byte_off + dst.len > self.block_size) return false;
    const lba = blockLba(self, block_num);
    if (!ensureCacheLoaded(self, lba)) return false;
    const off = (lba - self.cache_base_lba) * SECTOR_SIZE + byte_off;
    @memcpy(dst, self.cache_buf[off .. off + dst.len]);
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
    if (block_num == 0 or block_num >= self.sb.blocks_count) return false;
    if (src.len != self.block_size) return false;
    const lba = blockLba(self, block_num);
    var s: u32 = 0;
    while (s < self.sectors_per_block) : (s += 1) {
        const sec_off = s * SECTOR_SIZE;
        self.write_sector(lba + s, src.ptr + sec_off);
    }
    // Refresh the read cache in-place so a subsequent read sees the new
    // bytes without re-fetching from disk.
    const base = cacheBaseFor(lba);
    if (self.cache_base_lba == base) {
        const off = (lba - self.cache_base_lba) * SECTOR_SIZE;
        @memcpy(self.cache_buf[off .. off + self.block_size], src);
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
    if (block_num == 0 or block_num >= self.sb.blocks_count) return false;
    if (byte_off + src.len > self.block_size) return false;
    const lba = blockLba(self, block_num);
    if (!ensureCacheLoaded(self, lba)) return false;
    const cache_off_base = (lba - self.cache_base_lba) * SECTOR_SIZE;
    @memcpy(
        self.cache_buf[cache_off_base + byte_off .. cache_off_base + byte_off + src.len],
        src,
    );
    var s: u32 = 0;
    while (s < self.sectors_per_block) : (s += 1) {
        const sec_off: u32 = cache_off_base + s * SECTOR_SIZE;
        self.write_sector(lba + s, @as([*]const u8, @ptrCast(&self.cache_buf)) + sec_off);
    }
    return true;
}

/// Persist the in-memory superblock to its on-disk slot (LBAs 2..3 within
/// the partition). Called after free_blocks_count / free_inodes_count
/// changes.
pub fn writeSuperblock(self: *Mount) bool {
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
    var g: u32 = 0;
    while (g < self.bgd_count) : (g += 1) {
        if (self.bgd[g].free_blocks_count == 0) continue;
        if (allocBlockInGroup(self, g)) |bn| return bn;
    }
    return null;
}

fn allocBlockInGroup(self: *Mount, group: u32) ?u32 {
    const bgd = &self.bgd[group];

    // Load the bitmap block into the read cache and patch in place,
    // mirroring the same kstack-light pattern as writeBlockBytes. Note:
    // writeBgdTable + writeSuperblock below may evict the bitmap from
    // the cache, but we no longer need `slice` after the bitmap write.
    const bitmap_lba = blockLba(self, bgd.block_bitmap);
    if (!ensureCacheLoaded(self, bitmap_lba)) return null;
    const cache_off_base = (bitmap_lba - self.cache_base_lba) * SECTOR_SIZE;
    const slice = self.cache_buf[cache_off_base .. cache_off_base + self.block_size];

    var byte_idx: u32 = 0;
    while (byte_idx < self.block_size) : (byte_idx += 1) {
        if (slice[byte_idx] == 0xFF) continue;
        var bit: u3 = 0;
        while (true) : (bit += 1) {
            const mask: u8 = @as(u8, 1) << bit;
            if (slice[byte_idx] & mask == 0) {
                slice[byte_idx] |= mask;
                // Persist the bitmap directly from the cache.
                var s: u32 = 0;
                while (s < self.sectors_per_block) : (s += 1) {
                    const sec_off: u32 = cache_off_base + s * SECTOR_SIZE;
                    self.write_sector(bitmap_lba + s, @as([*]const u8, @ptrCast(&self.cache_buf)) + sec_off);
                }
                bgd.free_blocks_count -= 1;
                self.sb.free_blocks_count -|= 1;
                if (!writeBgdTable(self)) return null;
                if (!writeSuperblock(self)) return null;
                const block_in_group: u32 = byte_idx * 8 + @as(u32, bit);
                return self.sb.first_data_block + group * self.sb.blocks_per_group + block_in_group;
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

fn ensureCacheLoaded(self: *Mount, lba: u32) bool {
    const base = cacheBaseFor(lba);
    if (self.cache_base_lba == base) return true;
    self.read_sectors(base, @intCast(CACHE_SECTORS), &self.cache_buf);
    self.cache_base_lba = base;
    return true;
}

/// Bypass the block cache to read the SB. The cache isn't initialized yet
/// at this point and the SB only needs reading once per boot anyway.
fn readSuperblock(partition_lba: u32, dst: *layout.Superblock) bool {
    var buf: [2 * SECTOR_SIZE]u8 align(8) = undefined;
    // SB lives at byte 1024..2048 within the FS → sectors 2..3.
    blkdev.readSectorsSecondary(partition_lba + 2, 2, &buf);
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
