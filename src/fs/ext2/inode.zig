// Inode I/O + the block-pointer-tree walker. Phase 1: read paths only.
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
    for (cache, 0..) |e, i| {
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
    for (cache, 0..) |e, i| {
        if (e.last_use < min_use) {
            min_use = e.last_use;
            lru_idx = i;
        }
    }
    cache[lru_idx] = .{ .inum = inum, .inode = ino, .last_use = lru_counter };
}

/// Drop a cached inode by number. Phase 2 calls this on unlink so a
/// recycled inum doesn't return stale data. No-op if not cached.
pub fn invalidate(inum: u32) void {
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
    if (lookupCached(inum)) |idx| {
        lru_counter += 1;
        cache[idx].last_use = lru_counter;
        return cache[idx].inode;
    }
    const m = block.getMount() orelse return null;
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
        const logical: u32 = @intCast(off / bs);
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
// Internal helpers
// =============================================================================

inline fn nonzero(v: u32) ?u32 {
    return if (v == 0) null else v;
}

/// Read the u32 at `idx` within fs block `block_num`, treating it as a
/// little-endian block pointer. Returns null on read failure or zero
/// pointer (sparse).
fn readPointer(m: *block.Mount, block_num: u32, idx: u32) ?u32 {
    var buf: [4]u8 = undefined;
    if (!block.readBlockBytes(m, block_num, idx * 4, &buf)) return null;
    return nonzero(std.mem.readInt(u32, &buf, .little));
}
