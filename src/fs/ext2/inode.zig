// Inode I/O + the block-pointer-tree walker. Read + write (Phase 2) paths.
//
// The inode cache holds 16 entries, evicted LRU on miss. Cached entries
// are returned BY VALUE (Inode is 128 B), so a caller's reference can't
// be invalidated by a later cache eviction. The cache lives in this file
// rather than block.zig because it's a per-inode concept; the disk block
// holding the inode flows through block.zig's 8-sector cache underneath.
//
// Inodes are 1-indexed; inode 0 means "none", inode 1 is bad-blocks,
// inode 2 is the root directory.

const std = @import("std");
const layout = @import("layout.zig");
const block = @import("block.zig");
const page_cache = @import("../../mm/page_cache.zig");

// =============================================================================
// Inode cache
// =============================================================================

const CACHE_LEN: u32 = 16;

const InodeCacheEntry = struct {
    inum: u32 = 0, // 0 = empty
    inode: layout.Inode = undefined,
    last_use: u32 = 0,
};

var cache: [CACHE_LEN]InodeCacheEntry = [_]InodeCacheEntry{.{}} ** CACHE_LEN;
var lru_counter: u32 = 0;

fn lookupCached(inum: u32) ?u32 {
    for (&cache, 0..) |*e, i| {
        if (e.inum == inum) return @intCast(i);
    }
    return null;
}

fn insertCache(inum: u32, ino: layout.Inode) void {
    lru_counter += 1;
    for (&cache) |*e| {
        if (e.inum == 0) {
            e.* = .{ .inum = inum, .inode = ino, .last_use = lru_counter };
            return;
        }
    }
    var min_use: u32 = std.math.maxInt(u32);
    var lru_idx: usize = 0;
    for (&cache, 0..) |*e, i| {
        if (e.last_use < min_use) {
            min_use = e.last_use;
            lru_idx = i;
        }
    }
    cache[lru_idx] = .{ .inum = inum, .inode = ino, .last_use = lru_counter };
}

/// Allocate one free inode bitmap bit, return its inum (1-based). Bumps
/// `used_dirs_count` in the group if `is_dir`. Does NOT initialize the
/// inode struct itself — caller fills the Inode then writeInode(inum, &ino).
/// Returns null when every group is full (free_inodes_count == 0 across).
///
/// Reserved inodes (inum 1..first_ino-1) are mkfs-marked-used in the
/// bitmap, so the linear first-free-bit scan walks past them naturally.
pub fn allocInode(is_dir: bool) ?u32 {
    const m = block.getMount() orelse return null;
    // Whole-op hold: the bitmap RMW below is readBlockBytes + writeBlockBytes
    // — two separate lock sections without this. Two concurrent allocInode
    // calls could both observe the same bit clear and return the SAME inum,
    // silently fusing two files into one inode.
    block.lockMount(m);
    defer block.unlockMount(m);
    var g: u32 = 0;
    while (g < m.bgd_count) : (g += 1) {
        if (m.bgd[g].free_inodes_count == 0) continue;
        if (allocInodeInGroup(m, g, is_dir)) |inum| return inum;
    }
    return null;
}

fn allocInodeInGroup(m: *block.Mount, group: u32, is_dir: bool) ?u32 {
    const bgd = &m.bgd[group];
    const bitmap_block = bgd.inode_bitmap;
    // Read the bitmap block into the cache via readBlockBytes — single-byte
    // RMW reads stay cache-light. Inodes per group is typically ~8K so the
    // bitmap is a single block well under 4 KB.
    const bs = m.block_size;
    const bytes_to_scan: u32 = (m.sb.inodes_per_group + 7) / 8;
    const limit: u32 = if (bytes_to_scan > bs) bs else bytes_to_scan;
    var byte_idx: u32 = 0;
    while (byte_idx < limit) : (byte_idx += 1) {
        var byte_buf: [1]u8 = undefined;
        if (!block.readBlockBytes(m, bitmap_block, byte_idx, &byte_buf)) return null;
        if (byte_buf[0] == 0xFF) continue;
        var bit: u3 = 0;
        while (true) : (bit += 1) {
            const mask: u8 = @as(u8, 1) << bit;
            if (byte_buf[0] & mask == 0) {
                const idx_in_group: u32 = byte_idx * 8 + @as(u32, bit);
                const inum: u32 = group * m.sb.inodes_per_group + idx_in_group + 1;
                // Phantom-tail guard: inum > sb.inodes_count means we picked
                // a bit past the filesystem's inode count (last group's
                // bitmap can have trailing clear bits in a malformed image).
                // Skip — allocating one would write a phantom inode the FS
                // doesn't claim to have.
                if (inum > m.sb.inodes_count) {
                    if (bit == 7) break;
                    continue;
                }
                byte_buf[0] |= mask;
                if (!block.writeBlockBytes(m, bitmap_block, byte_idx, &byte_buf)) return null;
                bgd.free_inodes_count -|= 1;
                if (is_dir) bgd.used_dirs_count +%= 1;
                m.sb.free_inodes_count -|= 1;
                if (!block.writeBgdTable(m)) return null;
                if (!block.writeSuperblock(m)) return null;
                return inum;
            }
            if (bit == 7) break;
        }
    }
    return null;
}

/// Release inum back to its group's inode bitmap. Bumps free_inodes_count
/// in both the BGD entry and the superblock; if `was_dir` is true, also
/// decrements `used_dirs_count` (the BGD field e2fsck uses for orinet
/// dir-balance reporting). Caller passes was_dir from the inode it just
/// finished tearing down — saves a re-read here. Inode 0 is invalid;
/// inodes 1..first_ino-1 are reserved and rejected. Caller is responsible
/// for clearing the inode struct (zeroing block pointers, setting dtime)
/// BEFORE calling this; we only flip the bitmap.
pub fn freeInode(inum: u32, was_dir: bool) bool {
    if (inum == 0) return false;
    const m = block.getMount() orelse return false;
    // Same whole-op hold as allocInode: the bitmap read-modify-write and the
    // BGD/SB counter updates must not interleave with a concurrent alloc/free.
    block.lockMount(m);
    defer block.unlockMount(m);
    if (m.sb.rev_level >= 1 and inum < m.sb.first_ino) return false;
    const group: u32 = (inum - 1) / m.sb.inodes_per_group;
    if (group >= m.bgd_count) return false;
    const idx_in_group: u32 = (inum - 1) % m.sb.inodes_per_group;
    const byte_idx: u32 = idx_in_group / 8;
    const bit: u3 = @intCast(idx_in_group % 8);
    const mask: u8 = @as(u8, 1) << bit;

    const bgd = &m.bgd[group];
    const bitmap_block = bgd.inode_bitmap;
    // Read-modify-write through writeBlockBytes — single byte change keeps
    // the rest of the bitmap intact. Could also patch via the cache like
    // allocBlockInGroup does, but the byte-granular write keeps freeInode
    // independent of cache state.
    var byte_buf: [1]u8 = undefined;
    if (!block.readBlockBytes(m, bitmap_block, byte_idx, &byte_buf)) return false;
    if (byte_buf[0] & mask == 0) {
        @import("../../debug/debug.zig").klog("[ext2] freeInode: double-free of inum {d} (bitmap bit clear)\n", .{inum});
        return false;
    }
    byte_buf[0] &= ~mask;
    if (!block.writeBlockBytes(m, bitmap_block, byte_idx, &byte_buf)) return false;

    bgd.free_inodes_count +%= 1;
    if (was_dir and bgd.used_dirs_count > 0) bgd.used_dirs_count -= 1;
    m.sb.free_inodes_count +%= 1;
    if (!block.writeBgdTable(m)) return false;
    if (!block.writeSuperblock(m)) return false;

    invalidate(inum);
    // Page-cache coherence + SECURITY: this inode may be reused by a new file;
    // drop its cached data pages so the new file can't read the deleted file's
    // contents (the cache keys on file_id = inode). Walk is cheap (unlink/rmdir
    // is rare) and a no-op when nothing of this inode was cached.
    _ = page_cache.invalidateFile(page_cache.ext2FileId(inum));
    return true;
}

/// Drop a cached inode by number. Phase 2 calls this on unlink so a
/// recycled inum doesn't return stale data. No-op if not cached.
pub fn invalidate(inum: u32) void {
    const m = block.getMount() orelse return;
    block.lockMount(m);
    defer block.unlockMount(m);
    if (lookupCached(inum)) |idx| {
        cache[idx].inum = 0;
    }
}

/// Write back inode `inum` to its on-disk slot in the inode table.
/// Updates the in-memory cache so a subsequent `readInode` sees the new
/// bytes without round-tripping the disk.
pub fn writeInode(inum: u32, ino: *const layout.Inode) bool {
    if (inum == 0) return false;
    const m = block.getMount() orelse return false;
    // Covers the disk write + the cache refresh as one unit (the cache has
    // no lock of its own — see readInode).
    block.lockMount(m);
    defer block.unlockMount(m);
    const group: u32 = (inum - 1) / m.sb.inodes_per_group;
    if (group >= m.bgd_count) return false;
    const idx_in_group: u32 = (inum - 1) % m.sb.inodes_per_group;
    const block_off: u32 = idx_in_group / m.inodes_per_block;
    const byte_off: u32 = (idx_in_group % m.inodes_per_block) * m.sb.inode_size;
    const table_block: u32 = m.bgd[group].inode_table + block_off;

    const src = std.mem.asBytes(ino);
    if (!block.writeBlockBytes(m, table_block, byte_off, src)) return false;

    // Refresh the cache so the next readInode sees the new bytes.
    if (lookupCached(inum)) |idx| {
        cache[idx].inode = ino.*;
    }
    return true;
}

// =============================================================================
// Public API
// =============================================================================

/// Read inode `inum` by value. Returns null if inum == 0 or the disk
/// read fails. The returned struct is independent of the cache — safe to
/// hold across other inode operations.
pub fn readInode(inum: u32) ?layout.Inode {
    if (inum == 0) return null;
    const m = block.getMount() orelse return null;
    // The 16-entry inode cache is shared mutable state with NO lock of its
    // own; the per-mount lock (reentrant, so already-holding compound ops
    // just nest) covers it. Without this, one CPU's insertCache/writeInode
    // could tear the 128-byte struct copy out from under another CPU's
    // read — torn inode = wild block pointers.
    block.lockMount(m);
    defer block.unlockMount(m);
    if (lookupCached(inum)) |idx| {
        lru_counter += 1;
        cache[idx].last_use = lru_counter;
        return cache[idx].inode;
    }
    const group: u32 = (inum - 1) / m.sb.inodes_per_group;
    if (group >= m.bgd_count) return null;
    const idx_in_group: u32 = (inum - 1) % m.sb.inodes_per_group;
    const block_off: u32 = idx_in_group / m.inodes_per_block;
    const byte_off: u32 = (idx_in_group % m.inodes_per_block) * m.sb.inode_size;
    const table_block: u32 = m.bgd[group].inode_table + block_off;

    var ino: layout.Inode = undefined;
    const dst = std.mem.asBytes(&ino);
    if (!block.readBlockBytes(m, table_block, byte_off, dst)) return null;
    insertCache(inum, ino);
    return ino;
}

/// Map a logical block number within `inode` to a physical fs block.
/// Returns null on a sparse hole (caller treats as "all zeros") or on
/// any indirect-block read failure.
pub fn blockMapLookup(inode: *const layout.Inode, logical: u32) ?u32 {
    const m = block.getMount() orelse return null;
    const ptrs_per_block: u32 = m.block_size / 4;
    switch (layout.classifyBlock(logical, ptrs_per_block)) {
        .direct => |d| return nonzero(inode.block[d.i]),
        .indirect => |ind| {
            const indir = nonzero(inode.block[layout.IND_BLOCK]) orelse return null;
            return readPointer(m, indir, ind.i);
        },
        .double => |dbl| {
            const dind = nonzero(inode.block[layout.DIND_BLOCK]) orelse return null;
            const indir = readPointer(m, dind, dbl.i) orelse return null;
            return readPointer(m, indir, dbl.j);
        },
        .triple => |tri| {
            const tind = nonzero(inode.block[layout.TIND_BLOCK]) orelse return null;
            const dind = readPointer(m, tind, tri.i) orelse return null;
            const indir = readPointer(m, dind, tri.j) orelse return null;
            return readPointer(m, indir, tri.k);
        },
    }
}

/// Read one fs block of inode data into `dst`. `dst.len` MUST equal
/// mount.block_size. Sparse holes return all zeros.
pub fn readInodeBlock(inode: *const layout.Inode, logical: u32, dst: []u8) bool {
    const m = block.getMount() orelse return false;
    if (dst.len != m.block_size) return false;
    if (blockMapLookup(inode, logical)) |phys| {
        return block.readBlock(m, phys, dst);
    }
    @memset(dst, 0);
    return true;
}

/// Read up to `dst.len` bytes from the file-data stream of `inum` starting
/// at byte `offset`. Returns the number of bytes actually read (clipped to
/// EOF). Returns 0 on offset >= size or on errors.
pub fn readInodeBytes(inum: u32, offset: u64, dst: []u8) usize {
    const m = block.getMount() orelse return 0;
    const ino = readInode(inum) orelse return 0;
    const fsize = fileSize(&ino);
    if (offset >= fsize) return 0;
    const want: u64 = @min(@as(u64, dst.len), fsize - offset);

    var block_buf: [4096]u8 align(8) = undefined;
    const bs = m.block_size;
    var done: usize = 0;
    var off = offset;
    while (done < want) {
        const lblk = off / bs;
        if (lblk > std.math.maxInt(u32)) return done; // logical block beyond u32 (hostile LARGE_FILE size)
        const logical: u32 = @intCast(lblk);
        const in_block_off: u32 = @intCast(off % bs);
        const can: u32 = bs - in_block_off;
        const remain: u64 = want - done;
        const take: u32 = if (remain < can) @intCast(remain) else can;
        if (!readInodeBlock(&ino, logical, block_buf[0..bs])) return done;
        @memcpy(dst[done .. done + take], block_buf[in_block_off .. in_block_off + take]);
        done += take;
        off += take;
    }
    return done;
}

/// File size in bytes. Honors the rev 1 LARGE_FILE feature, where regular
/// files store the high 32 bits of size in `dir_acl`. Directories,
/// symlinks, and devices always use just `size`.
pub fn fileSize(inode: *const layout.Inode) u64 {
    if ((inode.mode & layout.S_IFMT) == layout.S_IFREG) {
        return (@as(u64, inode.dir_acl) << 32) | @as(u64, inode.size);
    }
    return @as(u64, inode.size);
}

pub fn isDir(inode: *const layout.Inode) bool {
    return (inode.mode & layout.S_IFMT) == layout.S_IFDIR;
}

pub fn isReg(inode: *const layout.Inode) bool {
    return (inode.mode & layout.S_IFMT) == layout.S_IFREG;
}

pub fn isSymlink(inode: *const layout.Inode) bool {
    return (inode.mode & layout.S_IFMT) == layout.S_IFLNK;
}

// =============================================================================
// Phase 2 — write-side block-tree helpers
// =============================================================================

/// Map `logical` to a physical fs block number for a write operation,
/// allocating any missing intermediate (indirect/dindirect/tindirect)
/// blocks and the data block itself when needed. Mutates `ino` in memory:
/// updates ino.block[*] for newly-allocated direct/indirect-tree roots and
/// bumps ino.blocks (in 512-B units) for every freshly-allocated block
/// (data + indirect-tree). Caller is responsible for the eventual
/// `writeInode(inum, ino)` after all writes complete.
///
/// Indirect blocks are zeroed on alloc — they're block-pointer arrays, so
/// any non-zero garbage byte = pointer to a wrong block.
///
/// Returns null if the filesystem is full at any allocation step. Partial
/// allocations earlier in the call ARE persisted (bitmap + inode mutated)
/// — caller's writeInode at the end is the commit boundary.
///
/// PRECONDITION: caller holds the mount lock (all current callers are the
/// whole-op-locked compound mutators in ext2.zig). The indirect-pointer
/// get-or-allocate below is readPointer + writePointer — racy on its own.
pub fn ensurePhysicalBlock(m: *block.Mount, ino: *layout.Inode, logical: u32) ?u32 {
    const ptrs_per_block: u32 = m.block_size / 4;
    return switch (layout.classifyBlock(logical, ptrs_per_block)) {
        .direct => |d| ensureDirect(m, ino, d.i),
        .indirect => |ind| {
            const indir = ensureIndirectRoot(m, ino, layout.IND_BLOCK) orelse return null;
            return ensureLeafInIndirect(m, ino, indir, ind.i);
        },
        .double => |dbl| {
            const dind = ensureIndirectRoot(m, ino, layout.DIND_BLOCK) orelse return null;
            const indir = ensureChildIndirect(m, ino, dind, dbl.i) orelse return null;
            return ensureLeafInIndirect(m, ino, indir, dbl.j);
        },
        .triple => |tri| {
            const tind = ensureIndirectRoot(m, ino, layout.TIND_BLOCK) orelse return null;
            const dind = ensureChildIndirect(m, ino, tind, tri.i) orelse return null;
            const indir = ensureChildIndirect(m, ino, dind, tri.j) orelse return null;
            return ensureLeafInIndirect(m, ino, indir, tri.k);
        },
    };
}

fn ensureDirect(m: *block.Mount, ino: *layout.Inode, i: u32) ?u32 {
    if (ino.block[i] != 0) return ino.block[i];
    const new_block = block.allocBlock(m) orelse return null;
    ino.block[i] = new_block;
    ino.blocks +%= @intCast(m.sectors_per_block);
    return new_block;
}

/// Get-or-allocate the indirect block stored in `ino.block[root_slot]`.
/// Bumps ino.blocks when it actually allocates.
fn ensureIndirectRoot(m: *block.Mount, ino: *layout.Inode, root_slot: u32) ?u32 {
    if (ino.block[root_slot] != 0) return ino.block[root_slot];
    const indir = allocAndZeroIndirect(m) orelse return null;
    ino.block[root_slot] = indir;
    ino.blocks +%= @intCast(m.sectors_per_block);
    return indir;
}

/// Get-or-allocate the child indirect block at `idx` inside `parent_block`
/// (an existing indirect block already sitting one level above). Bumps
/// ino.blocks when it actually allocates.
fn ensureChildIndirect(m: *block.Mount, ino: *layout.Inode, parent_block: u32, idx: u32) ?u32 {
    if (readPointer(m, parent_block, idx)) |existing| return existing;
    const child = allocAndZeroIndirect(m) orelse return null;
    if (!writePointer(m, parent_block, idx, child)) {
        _ = block.freeBlock(m, child);
        return null;
    }
    ino.blocks +%= @intCast(m.sectors_per_block);
    return child;
}

/// Get-or-allocate the leaf DATA block at `leaf_idx` inside `indir_block`
/// (a single-indirect block). Bumps ino.blocks when it actually allocates.
fn ensureLeafInIndirect(m: *block.Mount, ino: *layout.Inode, indir_block: u32, leaf_idx: u32) ?u32 {
    if (readPointer(m, indir_block, leaf_idx)) |existing| return existing;
    const data_block = block.allocBlock(m) orelse return null;
    if (!writePointer(m, indir_block, leaf_idx, data_block)) {
        _ = block.freeBlock(m, data_block);
        return null;
    }
    ino.blocks +%= @intCast(m.sectors_per_block);
    return data_block;
}

/// Allocate one block and zero its contents (block-pointer arrays MUST be
/// zero-initialized so absent children read as null pointers, not garbage).
fn allocAndZeroIndirect(m: *block.Mount) ?u32 {
    const blk = block.allocBlock(m) orelse return null;
    if (!block.writeBlock(m, blk, block.zero_block[0..m.block_size])) {
        _ = block.freeBlock(m, blk);
        return null;
    }
    return blk;
}

/// Walk every block reachable from `ino`'s block-pointer tree (direct +
/// indirect + dindirect + tindirect) and return them all to the bitmap.
/// Resets ino.block[] = 0 and ino.blocks = 0. Caller must writeInode
/// after this to persist the cleared pointers. Used by truncate(0) and
/// (future) unlink.
///
/// Walks bottom-up: free leaf data blocks first, then their containing
/// indirect blocks, so an interrupted truncate can be resumed by re-
/// reading the inode and walking again (entries already freed are no-ops
/// after freeBlock's double-free klog, which logs but doesn't corrupt).
///
/// PRECONDITION: caller holds the mount lock (truncate/unlink/rmdir/mkdir
/// rollback — all whole-op-locked). Also non-reentrant with itself via the
/// shared `indir_scratch` BSS buffers below, which the lock now guarantees.
pub fn freeAllBlocks(m: *block.Mount, ino: *layout.Inode) void {
    // Direct.
    for (0..layout.N_DIRECT) |i| {
        if (ino.block[i] != 0) {
            _ = block.freeBlock(m, ino.block[i]);
            ino.block[i] = 0;
        }
    }
    // Single indirect: free leaves + indirect block itself.
    if (ino.block[layout.IND_BLOCK] != 0) {
        freeIndirectLevel(m, ino.block[layout.IND_BLOCK], 1);
        _ = block.freeBlock(m, ino.block[layout.IND_BLOCK]);
        ino.block[layout.IND_BLOCK] = 0;
    }
    if (ino.block[layout.DIND_BLOCK] != 0) {
        freeIndirectLevel(m, ino.block[layout.DIND_BLOCK], 2);
        _ = block.freeBlock(m, ino.block[layout.DIND_BLOCK]);
        ino.block[layout.DIND_BLOCK] = 0;
    }
    if (ino.block[layout.TIND_BLOCK] != 0) {
        freeIndirectLevel(m, ino.block[layout.TIND_BLOCK], 3);
        _ = block.freeBlock(m, ino.block[layout.TIND_BLOCK]);
        ino.block[layout.TIND_BLOCK] = 0;
    }
    ino.blocks = 0;
}

/// 3 BSS buffers (one per indirect-tree level) so freeIndirectLevel's
/// recursion doesn't push 4 KB onto the kstack at every level. Indexed
/// by `depth - 1` (depth 1 = single, 2 = double, 3 = triple). 12 KB total.
var indir_scratch: [3][4096]u8 align(8) = undefined;

fn freeIndirectLevel(m: *block.Mount, indir_block: u32, depth: u32) void {
    if (depth == 0 or depth > 3) return;
    const bs = m.block_size;
    const buf = indir_scratch[depth - 1][0..bs];
    if (!block.readBlock(m, indir_block, buf)) return;
    const ptrs_per_block: u32 = bs / 4;
    var i: u32 = 0;
    while (i < ptrs_per_block) : (i += 1) {
        const ptr = std.mem.readInt(u32, buf[i * 4 ..][0..4], .little);
        if (ptr == 0) continue;
        if (depth > 1) freeIndirectLevel(m, ptr, depth - 1);
        _ = block.freeBlock(m, ptr);
    }
}

// =============================================================================
// Internal helpers
// =============================================================================

inline fn nonzero(v: u32) ?u32 {
    return if (v == 0) null else v;
}

/// Read the u32 at `idx` within fs block `block_num`, treating it as a
/// little-endian block pointer. Returns null on read failure or zero
/// pointer (sparse).
pub fn readPointer(m: *block.Mount, block_num: u32, idx: u32) ?u32 {
    var buf: [4]u8 = undefined;
    if (!block.readBlockBytes(m, block_num, idx * 4, &buf)) return null;
    return nonzero(std.mem.readInt(u32, &buf, .little));
}

/// Write a u32 block pointer at `idx` within fs block `block_num`,
/// little-endian. Caller's responsibility to ensure block_num is an
/// indirect block, not a data block.
pub fn writePointer(m: *block.Mount, block_num: u32, idx: u32, value: u32) bool {
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &buf, value, .little);
    return block.writeBlockBytes(m, block_num, idx * 4, &buf);
}
