// ext2 public surface — the only file vfs.zig and syscall.zig need to
// import. Mirrors fat32's signature shapes (Handle by value, getFileStat
// taking *anyopaque, listDir/resolveDirInum split) so the VFS dispatch
// arms are mechanical.
//
// Phase 1: read-only. createFile / writeFile / unlink / mkdir / rmdir
// land in Phase 2.

const std = @import("std");
const layout = @import("layout.zig");
const block = @import("block.zig");
const inode = @import("inode.zig");
const path_cache = @import("../path_cache.zig");

/// Path-cached `walkPath`. Saves the full root → leaf directory walk on
/// repeat opens of the same path (httpd serving static files, shell
/// re-exec'ing the same /bin/* per command). Path → inum mapping is stable
/// across `writeFile` and `truncate` (the only ext2 mutations today), so
/// no invalidation is needed from this side.
fn cachedWalk(path: []const u8) ?u32 {
    if (path_cache.lookupExt2(path)) |inum| return inum;
    const inum = walkPath(path) orelse return null;
    path_cache.insertExt2(path, inum);
    return inum;
}

// =============================================================================
// Init
// =============================================================================

pub fn init() bool {
    return block.mount(0);
}

pub fn isInitialized() bool {
    return block.isMounted();
}

// =============================================================================
// Handle / file ops
// =============================================================================

pub const Handle = struct {
    inum: u32,
    file_size: u64,
    current_offset: u64 = 0,
};

pub fn openFile(path: []const u8) ?Handle {
    const inum = cachedWalk(path) orelse return null;
    const ino = inode.readInode(inum) orelse return null;
    if (!inode.isReg(&ino)) return null;
    return .{ .inum = inum, .file_size = inode.fileSize(&ino) };
}

/// Stateless read — caller updates handle.current_offset based on returned
/// byte count, same as fat32. Lets vfs.zig store the offset in FileDesc.
pub fn readFile(handle: Handle, buf: [*]u8, count: u32) usize {
    return inode.readInodeBytes(handle.inum, handle.current_offset, buf[0..count]);
}

pub fn closeFile(_: Handle) void {}

/// Overwrite or extend an existing file's contents at `handle.current_offset`.
/// Returns the number of bytes written. Allocates new direct blocks via the
/// block bitmap when the write extends past the current allocation.
///
/// Phase 2 limits — calls past the 12 direct-block boundary (= 48 KB at
/// 4 KB blocks) stop writing rather than fall over into the indirect tree.
/// /etc/zigos.conf and the editor's 32 KB buffer both fit comfortably.
pub fn writeFile(handle: *Handle, src: [*]const u8, count: u32) u32 {
    if (count == 0) return 0;
    const m = block.getMount() orelse return 0;
    var ino = inode.readInode(handle.inum) orelse return 0;
    if (!inode.isReg(&ino)) return 0;

    const bs = m.block_size;
    var done: u32 = 0;

    while (done < count) {
        const file_off: u64 = handle.current_offset + done;
        const logical: u32 = @intCast(file_off / bs);
        if (logical >= layout.N_DIRECT) break; // Indirect blocks not supported yet
        const in_block_off: u32 = @intCast(file_off % bs);
        const can: u32 = bs - in_block_off;
        const remain: u32 = count - done;
        const take: u32 = if (remain < can) remain else can;

        // Get or allocate the physical block for this logical slot.
        var phys = ino.block[logical];
        if (phys == 0) {
            const new_block = block.allocBlock(m) orelse break;
            phys = new_block;
            ino.block[logical] = phys;
            // `blocks` is in 512-B units, includes data + indirect blocks.
            ino.blocks += @intCast(m.sectors_per_block);
            // Zero the rest of the block we won't immediately overwrite — the
            // bitmap allocator hands out whatever was last on disk. Source
            // from the module-level zero block (BSS, not stack) so this
            // path doesn't add 4 KB to an already-tight kernel stack.
            if (in_block_off != 0 or take != bs) {
                _ = block.writeBlock(m, phys, block.zero_block[0..bs]);
            }
        }

        const ok = if (in_block_off == 0 and take == bs)
            block.writeBlock(m, phys, src[done .. done + take])
        else
            block.writeBlockBytes(m, phys, in_block_off, src[done .. done + take]);
        if (!ok) break;

        done += take;
    }

    const new_end: u64 = handle.current_offset + done;
    if (new_end > inode.fileSize(&ino)) {
        ino.size = @truncate(new_end);
    }
    if (!inode.writeInode(handle.inum, &ino)) return 0;

    handle.current_offset = new_end;
    handle.file_size = inode.fileSize(&ino);
    return done;
}

/// Reset an existing file's logical size to zero. Block pointers are kept
/// (storage leak until full unlink is added in a later phase) — the next
/// write reuses them via writeFile's `phys != 0` branch. Cheap and good
/// enough for editor save and config rewrite, where files are tiny.
pub fn truncate(inum: u32) bool {
    var ino = inode.readInode(inum) orelse return false;
    if (!inode.isReg(&ino)) return false;
    ino.size = 0;
    ino.dir_acl = 0; // size-high bits, kept in sync
    return inode.writeInode(inum, &ino);
}

pub fn fileSize(path: []const u8) ?u64 {
    const inum = cachedWalk(path) orelse return null;
    const ino = inode.readInode(inum) orelse return null;
    if (!inode.isReg(&ino)) return null;
    return inode.fileSize(&ino);
}

/// Whole-file load into `dest`. Returns total bytes read or null on miss.
pub fn loadFile(path: []const u8, dest: [*]align(4) u8) ?usize {
    const inum = cachedWalk(path) orelse return null;
    const ino = inode.readInode(inum) orelse return null;
    if (!inode.isReg(&ino)) return null;
    const sz = inode.fileSize(&ino);
    return inode.readInodeBytes(inum, 0, dest[0..@intCast(sz)]);
}

pub fn getFileStat(path: []const u8, stat_buf: *anyopaque) bool {
    const FileStat = extern struct {
        file_size: u32,
        is_directory: u32,
        create_time: u32,
        modify_time: u32,
    };
    const stat: *FileStat = @ptrCast(@alignCast(stat_buf));
    if (!isInitialized()) return false;

    var p = path;
    if (p.len > 0 and p[p.len - 1] == '/') p = p[0 .. p.len - 1];
    const target_inum: u32 = if (p.len == 0) layout.ROOT_INO else (cachedWalk(p) orelse return false);
    const ino = inode.readInode(target_inum) orelse return false;
    stat.file_size = @truncate(inode.fileSize(&ino));
    stat.is_directory = if (inode.isDir(&ino)) 1 else 0;
    stat.create_time = ino.ctime;
    stat.modify_time = ino.mtime;
    return true;
}

// =============================================================================
// Directory ops
// =============================================================================

/// Walk `path` and return its inum if it resolves to a directory.
/// Used by sysListDir to split path-resolution from listing.
pub fn resolveDirInum(path: []const u8) ?u32 {
    var p = path;
    if (p.len > 0 and p[p.len - 1] == '/') p = p[0 .. p.len - 1];
    const inum: u32 = if (p.len == 0) layout.ROOT_INO else (cachedWalk(p) orelse return null);
    const ino = inode.readInode(inum) orelse return null;
    if (!inode.isDir(&ino)) return null;
    return inum;
}

/// Anonymous extern struct that exactly matches syscall.FileEntry —
/// matches the pattern tarfs.listToBuffer uses to avoid an import cycle
/// with cpu/syscall.zig.
const FileEntry = extern struct {
    name: [32]u8,
    name_len: u8,
    file_size: u32 align(1),
    flags: u8,
    _pad: [10]u8,
};

/// Unified FileEntry flag bits — kept in sync with `lib/libc.zig` FE_FLAG_*.
const FLAG_IS_ELF: u8 = 0x01;
const FLAG_IS_DIR: u8 = 0x02;
const FLAG_FROM_EXT2: u8 = 0x08;

pub fn listDir(dir_inum: u32, entries: [*]FileEntry, max_entries: u32) u32 {
    const m = block.getMount() orelse return 0;
    const dir_ino = inode.readInode(dir_inum) orelse return 0;
    if (!inode.isDir(&dir_ino)) return 0;

    var count: u32 = 0;
    var block_buf: [4096]u8 align(4) = undefined;
    const total = inode.fileSize(&dir_ino);
    var lblock: u32 = 0;
    while (@as(u64, lblock) * m.block_size < total and count < max_entries) : (lblock += 1) {
        if (!inode.readInodeBlock(&dir_ino, lblock, block_buf[0..m.block_size])) return count;
        var off: u32 = 0;
        while (off + layout.DIR_ENTRY_HDR <= m.block_size and count < max_entries) {
            const e = std.mem.bytesAsValue(layout.DirEntry, block_buf[off .. off + 8]);
            if (e.rec_len == 0) break; // malformed — abandon block
            if (e.inode != 0 and e.name_len > 0) {
                const name = block_buf[off + 8 .. off + 8 + e.name_len];
                // Skip "." / ".." (sysListDir consumers don't show them) and
                // ext2's reserved `lost+found` directory (created by every
                // mkfs-equivalent for fsck recovery; clutters listings since
                // we never run fsck and the user has no use for it).
                if (!isDotEntry(name) and !isLostFound(name)) {
                    fillEntry(&entries[count], name, e.inode);
                    count += 1;
                }
            }
            off += e.rec_len;
        }
    }
    return count;
}

pub fn matchPrefix(prefix: []const u8, names: *[8][32]u8, lens: *[8]u8) u8 {
    var entries: [8]FileEntry = undefined;
    const total = listDir(layout.ROOT_INO, &entries, 8);
    var count: u8 = 0;
    for (entries[0..total]) |entry| {
        const nl = entry.name_len;
        if (nl < prefix.len) continue;
        if (prefix.len > 0 and !std.mem.eql(u8, entry.name[0..prefix.len], prefix)) continue;
        const copy_len = @min(nl, 32);
        @memcpy(names[count][0..copy_len], entry.name[0..copy_len]);
        lens[count] = @intCast(copy_len);
        count += 1;
        if (count == 8) break;
    }
    return count;
}

// =============================================================================
// Internal — path walking
// =============================================================================

fn walkPath(path: []const u8) ?u32 {
    if (!isInitialized()) return null;
    var inum: u32 = layout.ROOT_INO;
    var it = std.mem.tokenizeScalar(u8, path, '/');
    while (it.next()) |component| {
        const ino = inode.readInode(inum) orelse return null;
        if (!inode.isDir(&ino)) return null;
        inum = lookupInDir(&ino, component) orelse return null;
    }
    return inum;
}

fn lookupInDir(dir_ino: *const layout.Inode, name: []const u8) ?u32 {
    const m = block.getMount() orelse return null;
    var block_buf: [4096]u8 align(4) = undefined;
    const total = inode.fileSize(dir_ino);
    var lblock: u32 = 0;
    while (@as(u64, lblock) * m.block_size < total) : (lblock += 1) {
        if (!inode.readInodeBlock(dir_ino, lblock, block_buf[0..m.block_size])) return null;
        var off: u32 = 0;
        while (off + layout.DIR_ENTRY_HDR <= m.block_size) {
            const e = std.mem.bytesAsValue(layout.DirEntry, block_buf[off .. off + 8]);
            if (e.rec_len == 0) break;
            if (e.inode != 0 and e.name_len > 0) {
                const ent_name = block_buf[off + 8 .. off + 8 + e.name_len];
                if (std.mem.eql(u8, ent_name, name)) return e.inode;
            }
            off += e.rec_len;
        }
    }
    return null;
}

// =============================================================================
// Internal — entry construction
// =============================================================================

fn isDotEntry(name: []const u8) bool {
    return (name.len == 1 and name[0] == '.') or
        (name.len == 2 and name[0] == '.' and name[1] == '.');
}

fn isLostFound(name: []const u8) bool {
    return name.len == 10 and std.mem.eql(u8, name, "lost+found");
}

fn fillEntry(out: *FileEntry, name: []const u8, inum: u32) void {
    @memset(&out.name, 0);
    @memset(&out._pad, 0);
    const copy_len: u8 = @intCast(@min(name.len, 32));
    @memcpy(out.name[0..copy_len], name[0..copy_len]);
    out.name_len = copy_len;
    out.flags = FLAG_FROM_EXT2;
    if (isElfName(name)) out.flags |= FLAG_IS_ELF;
    // Read inode once to fill both is_dir flag and file_size.
    if (inode.readInode(inum)) |ino| {
        if (inode.isDir(&ino)) out.flags |= FLAG_IS_DIR;
        out.file_size = @truncate(inode.fileSize(&ino));
    } else {
        out.file_size = 0;
    }
}

fn isElfName(name: []const u8) bool {
    return name.len >= 4 and std.mem.eql(u8, name[name.len - 4 ..], ".elf");
}

