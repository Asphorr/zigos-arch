// On-disk layout for ext2 (rev 0 + rev 1 dynamic). Pure data definitions —
// no I/O, no runtime state. Imported by every other file in src/fs/ext2/.
//
// All multi-byte fields are little-endian on disk. x86_64 is little-endian,
// so `extern struct` with `align(1)` reads them directly — no swap calls.
//
// Inode numbers are 1-indexed: 0 means "no inode", 1 is reserved for
// bad-blocks tracking, 2 is the root directory.
//
// The `blocks` field on Inode is in 512-byte units, NOT fs blocks. This is
// the most-mispatterned field in every C ext2 port; it's a count of
// physical disk sectors consumed (data + indirect blocks).

const std = @import("std");

// =============================================================================
// Magic constants
// =============================================================================

pub const SUPERBLOCK_OFFSET: u64 = 1024;
pub const MAGIC: u16 = 0xEF53;

pub const ROOT_INO: u32 = 2;
pub const FIRST_NONRESERVED_INO_REV0: u32 = 11;

pub const STATE_VALID: u16 = 1;
pub const STATE_ERROR: u16 = 2;

// rev_level
pub const REV_GOOD_OLD: u32 = 0;
pub const REV_DYNAMIC: u32 = 1;

// feature flags we tolerate on read but never set
pub const FEATURE_INCOMPAT_FILETYPE: u32 = 0x0002; // dir entry has file_type byte
pub const FEATURE_RO_COMPAT_LARGE_FILE: u32 = 0x0002; // file size > 4 GB

// Mode bits (matches POSIX layout)
pub const S_IFMT: u16 = 0xF000;
pub const S_IFREG: u16 = 0x8000;
pub const S_IFDIR: u16 = 0x4000;
pub const S_IFLNK: u16 = 0xA000;
pub const S_IFCHR: u16 = 0x2000;
pub const S_IFBLK: u16 = 0x6000;
pub const S_IFIFO: u16 = 0x1000;
pub const S_IFSOCK: u16 = 0xC000;

// DirEntry.file_type (only valid when FEATURE_INCOMPAT_FILETYPE is set)
pub const FT_UNKNOWN: u8 = 0;
pub const FT_REG_FILE: u8 = 1;
pub const FT_DIR: u8 = 2;
pub const FT_CHRDEV: u8 = 3;
pub const FT_BLKDEV: u8 = 4;
pub const FT_FIFO: u8 = 5;
pub const FT_SOCK: u8 = 6;
pub const FT_SYMLINK: u8 = 7;

// Inode block-pointer layout
pub const N_DIRECT: u32 = 12;
pub const IND_BLOCK: u32 = 12;
pub const DIND_BLOCK: u32 = 13;
pub const TIND_BLOCK: u32 = 14;
pub const N_BLOCKS: u32 = 15;

// =============================================================================
// On-disk structs
// =============================================================================

/// 1024 bytes at byte offset 1024 of the partition. A backup copy lives at
/// the start of every block group when SPARSE_SUPER feature is set; we
/// only read the primary.
pub const Superblock = extern struct {
    inodes_count: u32 align(1),
    blocks_count: u32 align(1),
    r_blocks_count: u32 align(1),
    free_blocks_count: u32 align(1),
    free_inodes_count: u32 align(1),
    first_data_block: u32 align(1),
    log_block_size: u32 align(1), // block_size = 1024 << log_block_size
    log_frag_size: u32 align(1),
    blocks_per_group: u32 align(1),
    frags_per_group: u32 align(1),
    inodes_per_group: u32 align(1),
    mtime: u32 align(1),
    wtime: u32 align(1),
    mnt_count: u16 align(1),
    max_mnt_count: u16 align(1),
    magic: u16 align(1),
    state: u16 align(1),
    errors: u16 align(1),
    minor_rev: u16 align(1),
    lastcheck: u32 align(1),
    checkinterval: u32 align(1),
    creator_os: u32 align(1),
    rev_level: u32 align(1),
    def_resuid: u16 align(1),
    def_resgid: u16 align(1),
    // EXT2_DYNAMIC_REV (rev_level == 1) extension fields
    first_ino: u32 align(1),
    inode_size: u16 align(1), // 128 (rev 0 default) or 256
    block_group_nr: u16 align(1),
    feature_compat: u32 align(1),
    feature_incompat: u32 align(1),
    feature_ro_compat: u32 align(1),
    uuid: [16]u8,
    volume_name: [16]u8,
    last_mounted: [64]u8,
    algorithm_usage_bitmap: u32 align(1),
    // Padding fills to 1024 bytes.
    _reserved: [1024 - 204]u8,
};
comptime {
    // ext2 rev 1 dynamic superblock — 1024 bytes total at offset 1024.
    const a = std.debug.assert;
    a(@sizeOf(Superblock) == 1024);
    a(@offsetOf(Superblock, "inodes_count") == 0);
    a(@offsetOf(Superblock, "blocks_count") == 4);
    a(@offsetOf(Superblock, "log_block_size") == 24);
    a(@offsetOf(Superblock, "blocks_per_group") == 32);
    a(@offsetOf(Superblock, "inodes_per_group") == 40);
    a(@offsetOf(Superblock, "magic") == 56);
    a(@offsetOf(Superblock, "rev_level") == 76);
    a(@offsetOf(Superblock, "first_ino") == 84);
    a(@offsetOf(Superblock, "inode_size") == 88);
    a(@offsetOf(Superblock, "feature_compat") == 92);
    a(@offsetOf(Superblock, "feature_incompat") == 96);
    a(@offsetOf(Superblock, "feature_ro_compat") == 100);
    a(@offsetOf(Superblock, "uuid") == 104);
    a(@offsetOf(Superblock, "volume_name") == 120);
    a(@offsetOf(Superblock, "last_mounted") == 136);
}

/// 32 bytes per block group, packed back-to-back into the group descriptor
/// table (which itself starts at the block right after the primary
/// superblock — block 1 if block_size > 1024, block 2 if block_size == 1024).
pub const BlockGroupDescriptor = extern struct {
    block_bitmap: u32 align(1),
    inode_bitmap: u32 align(1),
    inode_table: u32 align(1),
    free_blocks_count: u16 align(1),
    free_inodes_count: u16 align(1),
    used_dirs_count: u16 align(1),
    pad: u16 align(1),
    _reserved: [12]u8,
};
comptime {
    // ext2 spec — block group descriptor is exactly 32 bytes.
    const a = std.debug.assert;
    a(@sizeOf(BlockGroupDescriptor) == 32);
    a(@offsetOf(BlockGroupDescriptor, "block_bitmap") == 0);
    a(@offsetOf(BlockGroupDescriptor, "inode_bitmap") == 4);
    a(@offsetOf(BlockGroupDescriptor, "inode_table") == 8);
    a(@offsetOf(BlockGroupDescriptor, "free_blocks_count") == 12);
    a(@offsetOf(BlockGroupDescriptor, "free_inodes_count") == 14);
    a(@offsetOf(BlockGroupDescriptor, "used_dirs_count") == 16);
}

/// 128 bytes (rev 0 layout). Rev 1 grows to 256 with extended attrs we
/// don't need; we read only the first 128. Inode 1 is bad-blocks, inode 2
/// is root dir, inodes 3..first_ino-1 are reserved.
pub const Inode = extern struct {
    mode: u16 align(1),
    uid: u16 align(1),
    /// Low 32 bits of file size. For regular files in rev 1 with
    /// LARGE_FILE feature, dir_acl below is the high 32 bits.
    size: u32 align(1),
    atime: u32 align(1),
    ctime: u32 align(1),
    mtime: u32 align(1),
    /// Set by destroy, read by e2fsck to validate the deletion.
    dtime: u32 align(1),
    gid: u16 align(1),
    links_count: u16 align(1),
    /// Disk sectors (512 B units), NOT fs blocks. Includes indirect blocks.
    blocks: u32 align(1),
    flags: u32 align(1),
    osd1: u32 align(1),
    /// 0..11 direct, 12 indirect, 13 dindirect, 14 tindirect.
    block: [N_BLOCKS]u32 align(1),
    generation: u32 align(1),
    file_acl: u32 align(1),
    /// For directories: extended ACL block. For regular files in rev 1
    /// LARGE_FILE: high 32 bits of size.
    dir_acl: u32 align(1),
    faddr: u32 align(1),
    osd2: [12]u8,
};
comptime {
    // ext2 rev 0 inode — 128 bytes; rev 1 with extended attrs grows but
    // we only read the first 128 (consistent with Inode struct).
    const a = std.debug.assert;
    a(@sizeOf(Inode) == 128);
    a(@offsetOf(Inode, "mode") == 0);
    a(@offsetOf(Inode, "size") == 4);
    a(@offsetOf(Inode, "atime") == 8);
    a(@offsetOf(Inode, "links_count") == 26);
    a(@offsetOf(Inode, "blocks") == 28);
    a(@offsetOf(Inode, "flags") == 32);
    a(@offsetOf(Inode, "block") == 40);
    a(@offsetOf(Inode, "generation") == 100);
    a(@offsetOf(Inode, "dir_acl") == 108);
}

/// Variable-length, 4-byte-aligned. Directories are streams of these
/// inside the directory file. The last entry's `rec_len` stretches to
/// the end of its containing block; insertion splits a slack entry.
/// The trailing `name[name_len]` is read by slicing the underlying
/// buffer, NOT as a struct field.
pub const DirEntry = extern struct {
    /// 0 means "unused" — the entry's slot has been merged into the
    /// previous entry's rec_len but cleanup hasn't happened yet.
    inode: u32 align(1),
    /// Total entry length including the 8-byte header and name, padded
    /// to a 4-byte boundary. Walk the dir by `pos += rec_len`.
    rec_len: u16 align(1),
    /// Rev 1 with FEATURE_INCOMPAT_FILETYPE: just the name length.
    /// Rev 0 (or rev 1 without that feature): low byte of a u16
    /// name_len; the next byte is part of the same field.
    name_len: u8,
    /// Rev 1 with FILETYPE: one of FT_*. Rev 0: high byte of name_len
    /// (0 in practice since names are < 256 bytes).
    file_type: u8,
};
comptime {
    // ext2 dir entry header — 8 bytes before the inline name.
    const a = std.debug.assert;
    a(@sizeOf(DirEntry) == 8);
    a(@offsetOf(DirEntry, "inode") == 0);
    a(@offsetOf(DirEntry, "rec_len") == 4);
    a(@offsetOf(DirEntry, "name_len") == 6);
    a(@offsetOf(DirEntry, "file_type") == 7);
    a(DIR_ENTRY_HDR == 8);
}

/// Header size before the inline name. dirInsert/Remove use this when
/// computing slack.
pub const DIR_ENTRY_HDR: u16 = 8;

/// Round up to a 4-byte boundary — required by ext2 spec for rec_len.
pub inline fn dirEntryAlign(name_len: u8) u16 {
    return (DIR_ENTRY_HDR + @as(u16, name_len) + 3) & ~@as(u16, 3);
}

// =============================================================================
// Block-pointer tree classifier
// =============================================================================

/// Classifies a logical block index into where it sits in the inode's
/// block-pointer tree. The walker in inode.zig uses this; using a
/// tagged union forces every level to be handled in the switch.
pub const BlockMapLevel = union(enum) {
    direct: struct { i: u32 }, // i in 0..11
    indirect: struct { i: u32 }, // i in 0..ptrs_per_block
    double: struct { i: u32, j: u32 }, // i*ptrs_per_block + j
    triple: struct { i: u32, j: u32, k: u32 },
};

/// `ptrs_per_block` is block_size / 4 — passed in because layout.zig is
/// pure-data and doesn't know the mount's block size.
pub fn classifyBlock(logical: u32, ptrs_per_block: u32) BlockMapLevel {
    if (logical < N_DIRECT) {
        return .{ .direct = .{ .i = logical } };
    }
    var rest = logical - N_DIRECT;
    if (rest < ptrs_per_block) {
        return .{ .indirect = .{ .i = rest } };
    }
    rest -= ptrs_per_block;
    const dind_capacity = ptrs_per_block * ptrs_per_block;
    if (rest < dind_capacity) {
        return .{ .double = .{ .i = rest / ptrs_per_block, .j = rest % ptrs_per_block } };
    }
    rest -= dind_capacity;
    return .{ .triple = .{
        .i = rest / (ptrs_per_block * ptrs_per_block),
        .j = (rest / ptrs_per_block) % ptrs_per_block,
        .k = rest % ptrs_per_block,
    } };
}

// =============================================================================
// Compile-time layout asserts
// =============================================================================
//
// Any future drift in the on-disk struct definitions becomes a build error
// instead of silent corruption. If a field is reordered or resized, every
// expected size and offset below must still hold.

comptime {
    if (@sizeOf(Superblock) != 1024) @compileError("Superblock != 1024");
    if (@sizeOf(BlockGroupDescriptor) != 32) @compileError("BlockGroupDescriptor != 32");
    if (@sizeOf(Inode) != 128) @compileError("Inode != 128");
    if (@sizeOf(DirEntry) != 8) @compileError("DirEntry header != 8");

    if (@offsetOf(Superblock, "magic") != 56) @compileError("Superblock.magic offset");
    if (@offsetOf(Superblock, "rev_level") != 76) @compileError("Superblock.rev_level offset");
    if (@offsetOf(Superblock, "first_ino") != 84) @compileError("Superblock.first_ino offset");
    if (@offsetOf(Superblock, "inode_size") != 88) @compileError("Superblock.inode_size offset");
    if (@offsetOf(Superblock, "feature_incompat") != 96) @compileError("Superblock.feature_incompat offset");
    if (@offsetOf(Superblock, "uuid") != 104) @compileError("Superblock.uuid offset");

    if (@offsetOf(BlockGroupDescriptor, "inode_table") != 8) @compileError("BGD.inode_table offset");
    if (@offsetOf(BlockGroupDescriptor, "free_blocks_count") != 12) @compileError("BGD.free_blocks_count offset");

    if (@offsetOf(Inode, "size") != 4) @compileError("Inode.size offset");
    if (@offsetOf(Inode, "blocks") != 28) @compileError("Inode.blocks offset");
    if (@offsetOf(Inode, "block") != 40) @compileError("Inode.block offset");
    if (@offsetOf(Inode, "dir_acl") != 108) @compileError("Inode.dir_acl offset (size_high for LARGE_FILE)");
}
