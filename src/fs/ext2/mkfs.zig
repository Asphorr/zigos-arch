// mkfs.ext2 — create an empty ext2 filesystem in a partition.
//
// The counterpart to the rest of src/fs/ext2/, which could mount and modify a
// volume but never make one: every image the kernel has ever mounted was built
// on the host by genext2fs or mke2fs. That is fine for a disk handed to QEMU
// and useless for a disk the kernel is supposed to install itself onto.
//
// Geometry is fixed rather than tunable, and deliberately so — the parameters
// below are the ones `fs/ext2/block.zig` already mounts every boot, so a fresh
// volume exercises the same paths as the host-built one instead of opening a
// second, untested configuration:
//
//   block size      4096      (log_block_size 2 — the driver's clamp is <= 2)
//   inode size      128       (rev 0 layout; the driver reads the first 128 B)
//   blocks/group    32768     (8 * block_size — one block's worth of bitmap)
//   inodes/group    2048      (inode table = 64 blocks per group)
//   revision        1         (dynamic: first_ino/inode_size are meaningful)
//   features        FILETYPE  (dir entries carry FT_*; nothing else set)
//
// SPARSE_SUPER is deliberately NOT set, which means every block group carries
// a superblock backup and a full block-group-descriptor-table copy. That costs
// two blocks per group and buys a property worth more here: e2fsck can repair
// a trashed primary from any group, and we do not have to implement the
// "which groups get backups" power-of-3/5/7 rule to satisfy a checker that
// knows it perfectly.
//
// What a correct mkfs owes fsck, and what this file therefore does:
//   * inode tables ZEROED — an unzeroed table is a pile of garbage inodes with
//     plausible link counts, which fsck reads as catastrophic corruption
//   * bitmap PADDING BITS SET — bits past the end of a partial last group, and
//     past inodes_per_group in every inode bitmap, must read as allocated
//   * reserved inodes 1..10 marked used, first_ino = 11
//   * lost+found present — fsck offers to create it otherwise, which is a
//     non-clean result even when it is only a warning

const std = @import("std");

const block = @import("../../driver/block.zig");
const layout = @import("layout.zig");
const random = @import("../../crypto/random.zig");

const debug = @import("../../debug/debug.zig");

// =============================================================================
// Fixed geometry
// =============================================================================

const SECTOR_SIZE: u32 = 512;
const BLOCK_SIZE: u32 = 4096;
const LOG_BLOCK_SIZE: u32 = 2; // 1024 << 2 == 4096
const SECTORS_PER_BLOCK: u32 = BLOCK_SIZE / SECTOR_SIZE;

/// first_data_block is 0 for every block size above 1024: the superblock lives
/// at byte 1024, which is *inside* block 0 rather than after it.
const FIRST_DATA_BLOCK: u32 = 0;

/// One block's worth of bitmap covers 8 * BLOCK_SIZE blocks, and that is
/// exactly what a block group is defined to be.
const BLOCKS_PER_GROUP: u32 = 8 * BLOCK_SIZE;

const INODE_SIZE: u32 = 128;
const INODES_PER_GROUP: u32 = 2048;
const ITABLE_BLOCKS: u32 = INODES_PER_GROUP * INODE_SIZE / BLOCK_SIZE;

/// Inode 11 is the first non-reserved inode, and by universal convention it is
/// lost+found. Inodes 1..10 are reserved and marked used without existing.
const LOST_FOUND_INO: u32 = 11;
const FIRST_INO: u32 = 11;

/// Blocks of metadata every group carries before its data: superblock backup,
/// BGD table copy, block bitmap, inode bitmap, inode table.
fn groupOverheadBlocks(bgd_blocks: u32) u32 {
    return 1 + bgd_blocks + 2 + ITABLE_BLOCKS;
}

/// Upper bound on groups, matching the BGD cache in block.zig — formatting a
/// volume the mounter would then refuse is a failure we catch here instead.
const MAX_GROUPS: u32 = 64;

comptime {
    const a = std.debug.assert;
    a(BLOCK_SIZE == @as(u32, 1024) << @as(u5, @intCast(LOG_BLOCK_SIZE)));
    a(BLOCK_SIZE % INODE_SIZE == 0);
    a(INODES_PER_GROUP * INODE_SIZE % BLOCK_SIZE == 0);
    a(@sizeOf(layout.Superblock) == 1024);
    a(@sizeOf(layout.Inode) == INODE_SIZE);
}

// =============================================================================
// Geometry derived from the partition size
// =============================================================================

const Geometry = struct {
    total_blocks: u32,
    groups: u32,
    bgd_blocks: u32,
    inodes_count: u32,
    /// Block holding the root directory's single data block.
    root_dir_block: u32,
    /// Block holding lost+found's single data block.
    lost_found_block: u32,
    free_blocks: u32,
    free_inodes: u32,

    fn groupStart(self: Geometry, g: u32) u32 {
        _ = self;
        return FIRST_DATA_BLOCK + g * BLOCKS_PER_GROUP;
    }

    fn blocksInGroup(self: Geometry, g: u32) u32 {
        const start = self.groupStart(g);
        const remaining = self.total_blocks - start;
        return @min(BLOCKS_PER_GROUP, remaining);
    }

    fn blockBitmap(self: Geometry, g: u32) u32 {
        return self.groupStart(g) + 1 + self.bgd_blocks;
    }
    fn inodeBitmap(self: Geometry, g: u32) u32 {
        return self.blockBitmap(g) + 1;
    }
    fn inodeTable(self: Geometry, g: u32) u32 {
        return self.inodeBitmap(g) + 1;
    }
    /// First block in the group not consumed by group metadata.
    fn firstFree(self: Geometry, g: u32) u32 {
        return self.inodeTable(g) + ITABLE_BLOCKS;
    }
    /// Metadata + (in group 0) the two directory blocks we populate.
    fn usedInGroup(self: Geometry, g: u32) u32 {
        const meta = groupOverheadBlocks(self.bgd_blocks);
        return if (g == 0) meta + 2 else meta;
    }
};

fn computeGeometry(part_sectors: u32) ?Geometry {
    const total_blocks = part_sectors / SECTORS_PER_BLOCK;
    if (total_blocks < BLOCKS_PER_GROUP / 8) {
        debug.klog("[mkfs.ext2] partition too small: {d} blocks\n", .{total_blocks});
        return null;
    }

    const groups = (total_blocks - FIRST_DATA_BLOCK + BLOCKS_PER_GROUP - 1) / BLOCKS_PER_GROUP;
    if (groups > MAX_GROUPS) {
        debug.klog("[mkfs.ext2] {d} groups exceeds the mounter's cache cap {d}\n", .{ groups, MAX_GROUPS });
        return null;
    }
    const bgd_blocks = (groups * @sizeOf(layout.BlockGroupDescriptor) + BLOCK_SIZE - 1) / BLOCK_SIZE;

    var geo: Geometry = .{
        .total_blocks = total_blocks,
        .groups = groups,
        .bgd_blocks = bgd_blocks,
        .inodes_count = groups * INODES_PER_GROUP,
        .root_dir_block = 0,
        .lost_found_block = 0,
        .free_blocks = 0,
        .free_inodes = 0,
    };

    // The two directory blocks come straight after group 0's metadata.
    geo.root_dir_block = geo.firstFree(0);
    geo.lost_found_block = geo.root_dir_block + 1;

    // A group must be able to hold its own metadata; a tiny trailing group
    // that cannot is a layout we refuse rather than silently under-report.
    var g: u32 = 0;
    var free_blocks: u32 = 0;
    while (g < groups) : (g += 1) {
        const in_group = geo.blocksInGroup(g);
        const used = geo.usedInGroup(g);
        if (in_group <= used) {
            debug.klog("[mkfs.ext2] group {d} holds {d} blocks, needs {d} for metadata\n", .{ g, in_group, used });
            return null;
        }
        free_blocks += in_group - used;
    }
    geo.free_blocks = free_blocks;
    geo.free_inodes = geo.inodes_count - LOST_FOUND_INO;
    return geo;
}

// =============================================================================
// Block I/O
// =============================================================================

/// A partition to format: where it starts on the device and how long it is.
/// Both in 512-byte sectors, because that is what the block layer speaks and
/// converting at the boundary is where partition-offset bugs come from.
pub const Target = struct {
    dev: block.Device,
    part_lba: u32,
    part_sectors: u32,
};

fn writeBlockAt(t: Target, write: *const fn (u32, u32, [*]const u8) bool, block_no: u32, buf: *const [BLOCK_SIZE]u8) bool {
    const lba = t.part_lba + block_no * SECTORS_PER_BLOCK;
    if (!write(lba, SECTORS_PER_BLOCK, buf)) {
        debug.klog("[mkfs.ext2] write failed at block {d} (LBA {d})\n", .{ block_no, lba });
        return false;
    }
    return true;
}

/// Writes `count` zero blocks starting at `first`. Used for the inode tables,
/// which MUST read as zero — see the file banner. Batched through the block
/// layer rather than issued per block: an inode table is 64 blocks per group,
/// and per-command zeroing is what tripped an NVMe completion timeout in the
/// FAT32 formatter (block.ZERO_CHUNK_SECTORS carries that history).
fn zeroBlocks(t: Target, first: u32, count: u32) bool {
    const lba = t.part_lba + first * SECTORS_PER_BLOCK;
    if (!block.writeZeroRun(t.dev, lba, count * SECTORS_PER_BLOCK)) {
        debug.klog("[mkfs.ext2] zero-fill failed at block {d} (+{d})\n", .{ first, count });
        return false;
    }
    return true;
}

// =============================================================================
// Bitmaps
// =============================================================================

fn setBit(buf: []u8, bit: u32) void {
    buf[bit / 8] |= @as(u8, 1) << @intCast(bit % 8);
}

/// Block bitmap for group `g`: metadata blocks marked used, plus (in group 0)
/// the two directory blocks, plus every padding bit past the end of a partial
/// group. A padding bit left clear tells fsck there is free space outside the
/// filesystem, which it reports as corruption.
fn buildBlockBitmap(geo: Geometry, g: u32, buf: *[BLOCK_SIZE]u8) void {
    @memset(buf, 0);

    const used = geo.usedInGroup(g);
    var b: u32 = 0;
    while (b < used) : (b += 1) setBit(buf, b);

    // Bits beyond this group's real extent are permanently allocated.
    const in_group = geo.blocksInGroup(g);
    var pad = in_group;
    while (pad < BLOCKS_PER_GROUP) : (pad += 1) setBit(buf, pad);
}

/// Inode bitmap for group `g`. Group 0 owns the reserved inodes 1..10 plus
/// lost+found at 11; every other group starts empty. Bits past
/// INODES_PER_GROUP are padding and must read as allocated.
fn buildInodeBitmap(geo: Geometry, g: u32, buf: *[BLOCK_SIZE]u8) void {
    _ = geo;
    @memset(buf, 0);

    if (g == 0) {
        // Inode numbers are 1-based; inode N is bit N-1.
        var i: u32 = 0;
        while (i < LOST_FOUND_INO) : (i += 1) setBit(buf, i);
    }

    var pad = INODES_PER_GROUP;
    while (pad < BLOCK_SIZE * 8) : (pad += 1) setBit(buf, pad);
}

// =============================================================================
// Directory contents
// =============================================================================

/// Appends one directory entry at `off`, returning the new offset. `rec_len`
/// is passed explicitly because the last entry in a block must stretch to the
/// block's end — a directory whose final rec_len stops short leaves a hole
/// fsck reports as a corrupt directory.
fn putDirEntry(buf: *[BLOCK_SIZE]u8, off: u32, inode: u32, rec_len: u16, name: []const u8, file_type: u8) u32 {
    const e: *layout.DirEntry = @ptrCast(@alignCast(&buf[off]));
    e.* = .{
        .inode = inode,
        .rec_len = rec_len,
        .name_len = @intCast(name.len),
        .file_type = file_type,
    };
    @memcpy(buf[off + @as(u32, layout.DIR_ENTRY_HDR) ..][0..name.len], name);
    return off + @as(u32, rec_len);
}

fn buildRootDir(buf: *[BLOCK_SIZE]u8) void {
    @memset(buf, 0);
    var off: u32 = 0;
    off = putDirEntry(buf, off, layout.ROOT_INO, layout.dirEntryAlign(1), ".", layout.FT_DIR);
    off = putDirEntry(buf, off, layout.ROOT_INO, layout.dirEntryAlign(2), "..", layout.FT_DIR);
    // Last entry absorbs the rest of the block.
    _ = putDirEntry(buf, off, LOST_FOUND_INO, @intCast(BLOCK_SIZE - off), "lost+found", layout.FT_DIR);
}

fn buildLostFoundDir(buf: *[BLOCK_SIZE]u8) void {
    @memset(buf, 0);
    var off: u32 = 0;
    off = putDirEntry(buf, off, LOST_FOUND_INO, layout.dirEntryAlign(1), ".", layout.FT_DIR);
    _ = putDirEntry(buf, off, layout.ROOT_INO, @intCast(BLOCK_SIZE - off), "..", layout.FT_DIR);
}

/// A directory inode with exactly one data block.
fn dirInode(mode_perm: u16, data_block: u32, links: u16) layout.Inode {
    var ino: layout.Inode = std.mem.zeroes(layout.Inode);
    ino.mode = layout.S_IFDIR | mode_perm;
    ino.uid = 0;
    ino.gid = 0;
    ino.size = BLOCK_SIZE;
    ino.links_count = links;
    // `blocks` counts 512-byte sectors, not fs blocks — the field layout.zig's
    // banner calls the most-mispatterned in every ext2 port.
    ino.blocks = BLOCK_SIZE / 512;
    ino.block[0] = data_block;
    return ino;
}

// =============================================================================
// Entry point
// =============================================================================

/// Formats `t` as an empty ext2 filesystem. Every byte of the partition's
/// metadata region is rewritten; existing contents are lost.
///
/// Returns false, having logged why, on a read-only device, a partition too
/// small or too large for the fixed geometry, or any failed write. Geometry is
/// validated in full before the first write, so a rejected size leaves the
/// partition untouched.
///
/// Caller context: process context only — issues many blocking sector writes.
pub fn format(t: Target, volume_name: []const u8) bool {
    const write = t.dev.writeSectors orelse {
        debug.klog("[mkfs.ext2] device is read-only\n", .{});
        return false;
    };

    const geo = computeGeometry(t.part_sectors) orelse return false;

    debug.klog("[mkfs.ext2] {d} blocks, {d} groups, {d} inodes, root dir at block {d}\n", .{ geo.total_blocks, geo.groups, geo.inodes_count, geo.root_dir_block });

    // --- 1. Inode tables. Zeroed first so a later failure leaves an obviously
    //        unfinished volume rather than one with live-looking garbage.
    var g: u32 = 0;
    while (g < geo.groups) : (g += 1) {
        if (!zeroBlocks(t, geo.inodeTable(g), ITABLE_BLOCKS)) return false;
    }

    // --- 2. Bitmaps, one pair per group.
    g = 0;
    while (g < geo.groups) : (g += 1) {
        var buf: [BLOCK_SIZE]u8 = undefined;

        buildBlockBitmap(geo, g, &buf);
        if (!writeBlockAt(t, write, geo.blockBitmap(g), &buf)) return false;

        buildInodeBitmap(geo, g, &buf);
        if (!writeBlockAt(t, write, geo.inodeBitmap(g), &buf)) return false;
    }

    // --- 3. The two directories and their inodes.
    {
        var buf: [BLOCK_SIZE]u8 = undefined;
        buildRootDir(&buf);
        if (!writeBlockAt(t, write, geo.root_dir_block, &buf)) return false;
        buildLostFoundDir(&buf);
        if (!writeBlockAt(t, write, geo.lost_found_block, &buf)) return false;
    }
    {
        // Both live in group 0's inode table: inode 2 at slot 1, inode 11 at
        // slot 10, so a single first table block carries both (32 inodes per
        // 4 KiB block). Read-modify-write is unnecessary — we zeroed it above
        // and nothing else has touched it.
        var buf: [BLOCK_SIZE]u8 = .{0} ** BLOCK_SIZE;
        const table: [*]layout.Inode = @ptrCast(@alignCast(&buf));

        // Root's link count is 3: its own ".", its "..", and lost+found's "..".
        table[layout.ROOT_INO - 1] = dirInode(0o755, geo.root_dir_block, 3);
        // lost+found has "." and root's entry for it.
        table[LOST_FOUND_INO - 1] = dirInode(0o700, geo.lost_found_block, 2);

        if (!writeBlockAt(t, write, geo.inodeTable(0), &buf)) return false;
    }

    // --- 4. Block group descriptor table, then the superblock. Both are
    //        written to every group (no SPARSE_SUPER), so a trashed primary is
    //        recoverable from any backup.
    if (!writeBgdTable(t, write, geo)) return false;
    if (!writeSuperblocks(t, write, geo, volume_name)) return false;

    debug.klog("[mkfs.ext2] done: {d} free blocks, {d} free inodes\n", .{ geo.free_blocks, geo.free_inodes });
    return true;
}

fn writeBgdTable(t: Target, write: *const fn (u32, u32, [*]const u8) bool, geo: Geometry) bool {
    // The whole table fits one block for every group count we accept; asserted
    // rather than assumed, because the multi-block path below does not exist.
    if (geo.bgd_blocks != 1) {
        debug.klog("[mkfs.ext2] BGD table spans {d} blocks; only 1 is implemented\n", .{geo.bgd_blocks});
        return false;
    }

    var buf: [BLOCK_SIZE]u8 = .{0} ** BLOCK_SIZE;
    const bgds: [*]layout.BlockGroupDescriptor = @ptrCast(@alignCast(&buf));

    var g: u32 = 0;
    while (g < geo.groups) : (g += 1) {
        const in_group = geo.blocksInGroup(g);
        bgds[g] = .{
            .block_bitmap = geo.blockBitmap(g),
            .inode_bitmap = geo.inodeBitmap(g),
            .inode_table = geo.inodeTable(g),
            .free_blocks_count = @intCast(in_group - geo.usedInGroup(g)),
            .free_inodes_count = @intCast(if (g == 0) INODES_PER_GROUP - LOST_FOUND_INO else INODES_PER_GROUP),
            // Root and lost+found both live in group 0.
            .used_dirs_count = if (g == 0) 2 else 0,
            .pad = 0,
            ._reserved = [_]u8{0} ** 12,
        };
    }

    // One identical copy per group, immediately after that group's superblock.
    g = 0;
    while (g < geo.groups) : (g += 1) {
        if (!writeBlockAt(t, write, geo.groupStart(g) + 1, &buf)) return false;
    }
    return true;
}

fn writeSuperblocks(t: Target, write: *const fn (u32, u32, [*]const u8) bool, geo: Geometry, volume_name: []const u8) bool {
    var uuid: [16]u8 = undefined;
    if (!random.fillRandom(&uuid)) {
        debug.klog("[mkfs.ext2] UUID from degraded entropy source\n", .{});
    }

    var sb: layout.Superblock = std.mem.zeroes(layout.Superblock);
    sb.inodes_count = geo.inodes_count;
    sb.blocks_count = geo.total_blocks;
    // No reserved-for-root pool: this volume has no multi-user pressure to
    // protect against, and a non-zero value here only complicates the free
    // counts a reader has to reconcile.
    sb.r_blocks_count = 0;
    sb.free_blocks_count = geo.free_blocks;
    sb.free_inodes_count = geo.free_inodes;
    sb.first_data_block = FIRST_DATA_BLOCK;
    sb.log_block_size = LOG_BLOCK_SIZE;
    sb.log_frag_size = LOG_BLOCK_SIZE;
    sb.blocks_per_group = BLOCKS_PER_GROUP;
    sb.frags_per_group = BLOCKS_PER_GROUP;
    sb.inodes_per_group = INODES_PER_GROUP;
    // Timestamps stay 0. The kernel has a CMOS clock, but a wrong mkfs time is
    // worse than an absent one and fsck treats 0 as "never".
    sb.mtime = 0;
    sb.wtime = 0;
    sb.mnt_count = 0;
    // 0xFFFF is the "never force a check on mount count" convention.
    sb.max_mnt_count = 0xFFFF;
    sb.magic = layout.MAGIC;
    sb.state = layout.STATE_VALID;
    sb.errors = 1; // continue on error
    sb.minor_rev = 0;
    sb.lastcheck = 0;
    sb.checkinterval = 0;
    sb.creator_os = 0; // Linux
    sb.rev_level = layout.REV_DYNAMIC;
    sb.def_resuid = 0;
    sb.def_resgid = 0;
    sb.first_ino = FIRST_INO;
    sb.inode_size = @intCast(INODE_SIZE);
    sb.block_group_nr = 0; // overwritten per backup below
    sb.feature_compat = 0;
    // FILETYPE only: dir entries carry FT_*, which layout.zig's DirEntry
    // documents and the driver reads. Nothing else is claimed, so a host
    // e2fsck has no feature it must refuse.
    sb.feature_incompat = layout.FEATURE_INCOMPAT_FILETYPE;
    sb.feature_ro_compat = 0;
    sb.uuid = uuid;

    const vn = @min(volume_name.len, sb.volume_name.len);
    @memcpy(sb.volume_name[0..vn], volume_name[0..vn]);

    // The superblock sits at byte 1024 of the partition, i.e. inside block 0
    // for our block size. Backups sit at byte 0 of their group's first block.
    var g: u32 = 0;
    while (g < geo.groups) : (g += 1) {
        var buf: [BLOCK_SIZE]u8 = .{0} ** BLOCK_SIZE;
        // Each copy records which group it belongs to; fsck uses this to tell
        // a backup apart from the primary.
        sb.block_group_nr = @intCast(g);

        const off: usize = if (g == 0) layout.SUPERBLOCK_OFFSET else 0;
        @memcpy(buf[off..][0..@sizeOf(layout.Superblock)], std.mem.asBytes(&sb));

        if (!writeBlockAt(t, write, geo.groupStart(g), &buf)) return false;
    }
    return true;
}
