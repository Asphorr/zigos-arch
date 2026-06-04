// ext2 public surface — the only file vfs.zig and syscall.zig need to
// import. Mirrors fat32's signature shapes (Handle by value, getFileStat
// taking *anyopaque, listDir/resolveDirInum split) so the VFS dispatch
// arms are mechanical.
//
// Read + write: open/read/loadFile plus createFile / writeFile / unlink /
// mkdir / rmdir / truncate.

const std = @import("std");
const layout = @import("layout.zig");
const block = @import("block.zig");
const inode = @import("inode.zig");
const path_cache = @import("../path_cache.zig");
const time = @import("../../time/time.zig");
const debug = @import("../../debug/debug.zig");
const page_cache = @import("../../mm/page_cache.zig");

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
// Directory-entry walker + path split
// =============================================================================

/// Iterates the directory entries packed into a single directory-block
/// buffer, validating each against the block bounds before yielding it.
/// `rec_len` must cover the 8-byte header, fit within the block, and span
/// the entry's claimed `name_len`; any violation (including rec_len == 0)
/// ends the walk — a malformed or hostile block is truncated, never
/// over-read. (This is the on-disk twin of the ACPI MADT/DMAR entry walk:
/// the bounds check that used to be missing from every caller now lives
/// here once.) Yields EVERY structurally-valid entry, including empty
/// (inode == 0) slack slots so the insert/remove paths can see them; read
/// callers skip `inode == 0 or name.len == 0` themselves.
const DirWalk = struct {
    buf: []u8,
    off: u32 = 0,

    const Entry = struct {
        e: *align(1) layout.DirEntry,
        off: u32,
        name: []u8,
    };

    fn next(self: *DirWalk) ?Entry {
        if (self.off + layout.DIR_ENTRY_HDR > self.buf.len) return null;
        const e = std.mem.bytesAsValue(layout.DirEntry, self.buf[self.off .. self.off + layout.DIR_ENTRY_HDR]);
        const rl: u32 = e.rec_len;
        if (rl < layout.DIR_ENTRY_HDR or self.off + rl > self.buf.len) return null;
        if (layout.DIR_ENTRY_HDR + @as(u32, e.name_len) > rl) return null;
        const at = self.off;
        self.off += rl;
        return .{ .e = e, .off = at, .name = self.buf[at + layout.DIR_ENTRY_HDR ..][0..e.name_len] };
    }
};

const ParentLeaf = struct { parent: []const u8, leaf: []const u8 };

/// Split `path` at its last '/' into parent-directory + final component.
/// "a/b/c" → {"a/b", "c"}; "c" → {"", "c"}; "/c" → {"", "c"}. The caller
/// maps an empty `parent` to ROOT_INO.
fn splitParentLeaf(path: []const u8) ParentLeaf {
    if (std.mem.lastIndexOfScalar(u8, path, '/')) |slash| {
        return .{
            .parent = if (slash == 0) "" else path[0..slash],
            .leaf = path[slash + 1 ..],
        };
    }
    return .{ .parent = "", .leaf = path };
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

/// Whether `inum` is a regular file plus its size, in a single (cached) inode
/// read — the two facts vfs.readThroughCache needs to decide cache eligibility
/// (only regular-file data is cached + invalidated) and to clip at EOF.
/// is_reg=false (including an unreadable inode) tells the caller to bypass the
/// cache entirely.
pub const CacheReadInfo = struct { is_reg: bool, size: u64 };
pub fn cacheReadInfo(inum: u32) CacheReadInfo {
    const ino = inode.readInode(inum) orelse return .{ .is_reg = false, .size = 0 };
    return .{ .is_reg = inode.isReg(&ino), .size = inode.fileSize(&ino) };
}

pub fn closeFile(_: Handle) void {}

/// Overwrite or extend an existing file's contents at `handle.current_offset`.
/// Returns the number of bytes written. Allocates new data + indirect-tree
/// blocks via the block bitmap as needed, walking direct → single indirect
/// → double indirect → triple indirect (4 TB cap at 4 KB blocks). Returns
/// short if the filesystem fills up mid-write — caller's responsibility to
/// retry / propagate.
pub fn writeFile(handle: *Handle, src: [*]const u8, count: u32) u32 {
    if (count == 0) return 0;
    const m = block.getMount() orelse return 0;
    var ino = inode.readInode(handle.inum) orelse return 0;
    if (!inode.isReg(&ino)) return 0;

    // Captured before the loop: writeFile advances handle.current_offset to
    // new_end at the end, so we can't read the write's start offset there.
    const start_off = handle.current_offset;
    const bs = m.block_size;
    var done: u32 = 0;

    while (done < count) {
        const file_off: u64 = handle.current_offset + done;
        const lblk = file_off / bs;
        if (lblk > std.math.maxInt(u32)) break; // logical block beyond u32
        const logical: u32 = @intCast(lblk);
        const in_block_off: u32 = @intCast(file_off % bs);
        const can: u32 = bs - in_block_off;
        const remain: u32 = count - done;
        const take: u32 = if (remain < can) remain else can;

        // Detect first-use of this logical slot so we know whether to
        // pre-zero the block (alloc returns whatever was last on disk).
        const was_unallocated = (inode.blockMapLookup(&ino, logical) == null);
        const phys = inode.ensurePhysicalBlock(m, &ino, logical) orelse break;
        if (was_unallocated and (in_block_off != 0 or take != bs)) {
            // Zero the slack we won't immediately overwrite. zero_block
            // lives in BSS so this doesn't burn 4 KB of kernel stack.
            _ = block.writeBlock(m, phys, block.zero_block[0..bs]);
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
    if (done > 0) {
        const sec: u32 = @truncate(time.now().sec);
        ino.mtime = sec;
        ino.ctime = sec;
    }
    if (!inode.writeInode(handle.inum, &ino)) return 0;

    handle.current_offset = new_end;
    handle.file_size = inode.fileSize(&ino);
    // Page-cache coherence: drop cached pages overlapping the written range so a
    // later mmap fault / cached read re-fills from disk rather than serving the
    // pre-write bytes. No-op (quick misses) for files nothing has mmap'd.
    if (done > 0) _ = page_cache.invalidateRange(page_cache.ext2FileId(handle.inum), start_off, done);
    return done;
}

/// Persist one page (`src`, up to 4 KiB) of already-cached regular-file data
/// straight to its on-disk data blocks — the disk half of MAP_SHARED writeback
/// (Slice 3c), driven by vfs.syncCacheFile on msync/munmap.
///
/// Two deliberate differences from writeFile:
///   1. It does NOT invalidate the page cache. We are persisting the cache's OWN
///      live shared frame; dropping it (writeFile's coherence hook) would desync
///      every other mapper from disk and force a divergent re-read.
///   2. It NEVER grows the file. Only bytes within the inode's current size are
///      written (a shared mapping doesn't extend the file; bytes mapped past EOF
///      are simply not persisted). So `ino.size` is left untouched.
/// mtime/ctime are intentionally not bumped (that would cost an inode write per
/// page) — writeback is a pure data persist of blocks the file already owns.
/// `page_off` must be page-aligned. Returns bytes written.
pub fn writebackPage(inum: u32, page_off: u64, src: [*]const u8) u32 {
    const m = block.getMount() orelse return 0;
    var ino = inode.readInode(inum) orelse return 0;
    if (!inode.isReg(&ino)) return 0;
    const fsize = inode.fileSize(&ino);
    if (page_off >= fsize) return 0; // wholly past EOF — nothing on disk to update
    const want: u32 = @intCast(@min(@as(u64, 0x1000), fsize - page_off)); // clip at EOF
    const bs = m.block_size;
    var done: u32 = 0;
    var inode_grew = false; // a sparse-hole fill allocated a block → must persist ino
    while (done < want) {
        const file_off: u64 = page_off + done;
        const lblk = file_off / bs;
        if (lblk > std.math.maxInt(u32)) break;
        const logical: u32 = @intCast(lblk);
        const in_block_off: u32 = @intCast(file_off % bs);
        const can: u32 = bs - in_block_off;
        const remain: u32 = want - done;
        const take: u32 = if (remain < can) remain else can;

        // The data being written was originally READ from these blocks into the
        // cache, so they already exist and ensurePhysicalBlock returns the
        // existing mapping. Only a genuinely sparse file (a hole the mapping
        // wrote into) allocates here — correct, and flagged so we persist the
        // updated block map.
        const was_unallocated = (inode.blockMapLookup(&ino, logical) == null);
        const phys = inode.ensurePhysicalBlock(m, &ino, logical) orelse break;
        if (was_unallocated) {
            inode_grew = true;
            // Sparse-hole fill: zero the slack we won't immediately overwrite
            // (mirrors writeFile) so a later file growth can't expose stale
            // allocBlock contents. The slack here is strictly past our clipped
            // write, so reads at the current size never see it — belt-and-braces.
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
    // Persist the inode only if its block map changed (sparse-hole fill). The
    // common overwrite path leaves `ino` untouched, so we skip a redundant
    // inode write per page.
    if (inode_grew) _ = inode.writeInode(inum, &ino);
    return done;
}

// =============================================================================
// Phase 2 — file creation
// =============================================================================

/// Path-based wrapper matching fat32.createFile's shape — splits `path`
/// into parent dir + leaf name, walks the parent, then delegates to the
/// inum-based createFile below. Returns the new inum + an open Handle so
/// the caller (vfs.openFlags O_CREATE) can install an FD pointing at it
/// immediately, no second walk needed.
pub fn createFilePath(path: []const u8) ?Handle {
    if (path.len == 0 or path.len > 255) return null;
    const split = splitParentLeaf(path);
    const parent_path = split.parent;
    const leaf = split.leaf;
    if (leaf.len == 0) return null;

    const parent_inum = if (parent_path.len == 0) layout.ROOT_INO else (cachedWalk(parent_path) orelse return null);
    const new_inum = createFile(parent_inum, leaf) orelse return null;
    const ino = inode.readInode(new_inum) orelse return null;
    return .{ .inum = new_inum, .file_size = inode.fileSize(&ino) };
}

/// Create a new regular file `name` inside `parent_inum`. Returns the new
/// inum on success, null on bitmap-full / name-already-exists / parent-
/// not-a-directory. Initializes the inode with mode S_IFREG|0o644,
/// links_count=1, size=0, current epoch timestamps. Updates the path
/// cache (via invalidateAll — conservative; ext2 mutations are rare).
pub fn createFile(parent_inum: u32, name: []const u8) ?u32 {
    if (name.len == 0 or name.len > 255) return null;
    if (containsSlash(name)) return null;
    const m = block.getMount() orelse return null;
    var parent = inode.readInode(parent_inum) orelse return null;
    if (!inode.isDir(&parent)) return null;
    if (lookupInDir(&parent, name) != null) return null;

    const new_inum = inode.allocInode(false) orelse return null;
    var new_ino: layout.Inode = std.mem.zeroes(layout.Inode);
    const t = time.now();
    const sec: u32 = @truncate(t.sec);
    new_ino.mode = layout.S_IFREG | 0o644;
    new_ino.uid = 0;
    new_ino.gid = 0;
    new_ino.links_count = 1;
    new_ino.size = 0;
    new_ino.blocks = 0;
    new_ino.atime = sec;
    new_ino.ctime = sec;
    new_ino.mtime = sec;
    new_ino.dtime = 0;
    if (!inode.writeInode(new_inum, &new_ino)) {
        _ = inode.freeInode(new_inum, false);
        return null;
    }

    if (!dirInsert(m, parent_inum, &parent, name, new_inum, layout.FT_REG_FILE)) {
        // Roll back inode alloc on directory-insert failure.
        _ = inode.freeInode(new_inum, false);
        return null;
    }
    // Bump parent mtime/ctime — directory contents changed.
    parent.mtime = sec;
    parent.ctime = sec;
    if (!inode.writeInode(parent_inum, &parent)) return null;

    // Parent's path → inum mapping is unchanged, but a fresh path with
    // this `name` suffix needs to resolve. invalidateAll is the conservative
    // hammer; ext2 mutations are rare so the cache rebuild cost is fine.
    path_cache.invalidateAll();
    return new_inum;
}

/// Insert a directory entry into `dir_inum` (dir_ino read in by caller, may
/// be mutated for size/block changes). Walks each block of the directory,
/// looks for slack space in any existing entry, splits it. If no slack in
/// any existing block, allocates a new block and lays the entry as the
/// sole resident.
fn dirInsert(m: *block.Mount, dir_inum: u32, dir_ino: *layout.Inode, name: []const u8, child_inum: u32, file_type: u8) bool {
    const bs = m.block_size;
    const needed: u16 = layout.dirEntryAlign(@intCast(name.len));
    if (needed > bs) return false; // pathological — name fills whole block

    const total = inode.fileSize(dir_ino);
    var lblock: u32 = 0;
    var dir_buf: [4096]u8 align(8) = undefined;
    _ = dir_inum;
    while (@as(u64, lblock) * bs < total) : (lblock += 1) {
        if (!inode.readInodeBlock(dir_ino, lblock, dir_buf[0..bs])) return false;
        var w = DirWalk{ .buf = dir_buf[0..bs] };
        while (w.next()) |d| {
            const tight: u16 = if (d.e.inode == 0)
                layout.DIR_ENTRY_HDR // empty entry — all of rec_len is slack
            else
                layout.dirEntryAlign(d.e.name_len);
            if (d.e.rec_len >= tight + needed) {
                // Split this entry: shrink to tight, append new entry in slack.
                const new_off: u32 = d.off + tight;
                const slack: u16 = d.e.rec_len - tight;
                d.e.rec_len = tight;
                // Construct new entry in-place.
                const ne = std.mem.bytesAsValue(layout.DirEntry, dir_buf[new_off .. new_off + 8]);
                ne.inode = child_inum;
                ne.rec_len = slack;
                ne.name_len = @intCast(name.len);
                ne.file_type = file_type;
                @memcpy(dir_buf[new_off + 8 .. new_off + 8 + name.len], name);
                // Resolve the physical block for this logical and write the
                // whole block back.
                const phys = inode.blockMapLookup(dir_ino, lblock) orelse return false;
                if (!block.writeBlock(m, phys, dir_buf[0..bs])) return false;
                return true;
            }
        }
    }

    // No slack in any existing block — extend the directory by one block.
    const new_lblock = @as(u32, @intCast(total / bs));
    const new_phys = inode.ensurePhysicalBlock(m, dir_ino, new_lblock) orelse return false;
    @memset(dir_buf[0..bs], 0);
    const e = std.mem.bytesAsValue(layout.DirEntry, dir_buf[0..8]);
    e.inode = child_inum;
    e.rec_len = @intCast(bs);
    e.name_len = @intCast(name.len);
    e.file_type = file_type;
    @memcpy(dir_buf[8 .. 8 + name.len], name);
    if (!block.writeBlock(m, new_phys, dir_buf[0..bs])) return false;
    dir_ino.size = @intCast(total + bs);
    return true;
}

inline fn containsSlash(name: []const u8) bool {
    for (name) |c| if (c == '/') return true;
    return false;
}

/// Create an empty directory at `path`. Allocates a fresh inode marked
/// S_IFDIR, allocates one data block populated with "." (self-link) and
/// ".." (parent-link) dirents, inserts the entry into the parent dir, and
/// bumps the parent's links_count by 1 to account for the new ".." back-
/// pointer. Returns true on success.
pub fn mkdirPath(path: []const u8) bool {
    if (path.len == 0 or path.len > 255) return false;
    const split = splitParentLeaf(path);
    const parent_path = split.parent;
    const leaf = split.leaf;
    if (leaf.len == 0 or leaf.len > 255) return false;
    if (containsSlash(leaf)) return false;

    const m = block.getMount() orelse return false;
    const parent_inum = if (parent_path.len == 0) layout.ROOT_INO else (cachedWalk(parent_path) orelse return false);
    var parent = inode.readInode(parent_inum) orelse return false;
    if (!inode.isDir(&parent)) return false;
    if (lookupInDir(&parent, leaf) != null) return false;

    const new_inum = inode.allocInode(true) orelse return false;

    // Initialize the new directory inode.
    var new_ino: layout.Inode = std.mem.zeroes(layout.Inode);
    const t = time.now();
    const sec: u32 = @truncate(t.sec);
    new_ino.mode = layout.S_IFDIR | 0o755;
    new_ino.links_count = 2; // self ("." entry) + parent's pointer to us
    new_ino.atime = sec;
    new_ino.ctime = sec;
    new_ino.mtime = sec;
    new_ino.size = 0; // bumped to bs once we lay the . / .. block

    // Allocate the directory's first data block + write the . and ..
    // dirents that every dir starts with. Going through ensurePhysicalBlock
    // bumps new_ino.blocks for us.
    const data_block = inode.ensurePhysicalBlock(m, &new_ino, 0) orelse {
        _ = inode.freeInode(new_inum, true);
        return false;
    };

    const bs = m.block_size;
    var blkbuf: [4096]u8 align(8) = undefined;
    @memset(blkbuf[0..bs], 0);
    // "." entry — points to self.
    const dot = std.mem.bytesAsValue(layout.DirEntry, blkbuf[0..8]);
    const dot_rec: u16 = layout.dirEntryAlign(1);
    dot.inode = new_inum;
    dot.rec_len = dot_rec;
    dot.name_len = 1;
    dot.file_type = layout.FT_DIR;
    blkbuf[8] = '.';
    // ".." entry — points to parent. Stretches to end of block.
    const dotdot = std.mem.bytesAsValue(layout.DirEntry, blkbuf[dot_rec .. dot_rec + 8]);
    dotdot.inode = parent_inum;
    dotdot.rec_len = @intCast(bs - dot_rec);
    dotdot.name_len = 2;
    dotdot.file_type = layout.FT_DIR;
    blkbuf[dot_rec + 8] = '.';
    blkbuf[dot_rec + 9] = '.';
    if (!block.writeBlock(m, data_block, blkbuf[0..bs])) {
        // Roll back: free the data block + inode. freeAllBlocks handles
        // the data block since ensurePhysicalBlock already wired it in.
        inode.freeAllBlocks(m, &new_ino);
        _ = inode.freeInode(new_inum, true);
        return false;
    }
    new_ino.size = @intCast(bs);

    if (!inode.writeInode(new_inum, &new_ino)) {
        inode.freeAllBlocks(m, &new_ino);
        _ = inode.freeInode(new_inum, true);
        return false;
    }

    if (!dirInsert(m, parent_inum, &parent, leaf, new_inum, layout.FT_DIR)) {
        inode.freeAllBlocks(m, &new_ino);
        _ = inode.freeInode(new_inum, true);
        return false;
    }
    parent.links_count += 1; // the new dir's ".." points back to parent
    parent.mtime = sec;
    parent.ctime = sec;
    if (!inode.writeInode(parent_inum, &parent)) return false;

    path_cache.invalidateAll();
    return true;
}

/// Remove an empty directory at `path`. Refuses non-empty dirs (anything
/// besides "." and ".." present), regular files, or "/" (root). Frees the
/// directory's data block + inode and decrements the parent's links_count
/// by 1.
pub fn rmdirPath(path: []const u8) bool {
    if (path.len == 0 or path.len > 255) return false;
    const split = splitParentLeaf(path);
    const parent_path = split.parent;
    const leaf = split.leaf;
    if (leaf.len == 0) return false;

    const parent_inum = if (parent_path.len == 0) layout.ROOT_INO else (cachedWalk(parent_path) orelse return false);
    var parent = inode.readInode(parent_inum) orelse return false;
    if (!inode.isDir(&parent)) return false;
    const child_inum = lookupInDir(&parent, leaf) orelse return false;
    const child = inode.readInode(child_inum) orelse return false;
    if (!inode.isDir(&child)) return false;
    if (!dirIsEmpty(&child)) return false;

    return unlinkInDir(parent_inum, leaf, .dir_only);
}

/// Returns true if `dir_ino` contains nothing besides "." and ".." (the
/// two synthetic entries every directory has).
fn dirIsEmpty(dir_ino: *const layout.Inode) bool {
    const m = block.getMount() orelse return false;
    const bs = m.block_size;
    const total = inode.fileSize(dir_ino);
    var lblock: u32 = 0;
    var dir_buf: [4096]u8 align(8) = undefined;
    while (@as(u64, lblock) * bs < total) : (lblock += 1) {
        if (!inode.readInodeBlock(dir_ino, lblock, dir_buf[0..bs])) return false;
        var w = DirWalk{ .buf = dir_buf[0..bs] };
        while (w.next()) |d| {
            if (d.e.inode != 0 and d.name.len > 0 and !isDotEntry(d.name)) return false;
        }
    }
    return true;
}

/// Remove a regular file at `path` — drops the dirent from its parent and
/// (if links_count was 1) releases every data + indirect block plus the
/// inode bitmap bit. Returns true on success. Refuses to operate on
/// directories — use rmdir for those.
pub fn unlinkPath(path: []const u8) bool {
    if (path.len == 0 or path.len > 255) return false;
    const split = splitParentLeaf(path);
    const parent_path = split.parent;
    const leaf = split.leaf;
    if (leaf.len == 0) return false;

    const parent_inum = if (parent_path.len == 0) layout.ROOT_INO else (cachedWalk(parent_path) orelse return false);
    return unlinkInDir(parent_inum, leaf, .file_only);
}

const UnlinkPolicy = enum { file_only, dir_only };

/// Lower-level unlink: caller has parent_inum + leaf already resolved.
/// `policy` selects whether we expect a regular file (unlink) or a
/// directory (rmdir). Cross-violations return false.
pub fn unlinkInDir(parent_inum: u32, name: []const u8, policy: UnlinkPolicy) bool {
    const m = block.getMount() orelse return false;
    var parent = inode.readInode(parent_inum) orelse return false;
    if (!inode.isDir(&parent)) return false;
    const child_inum = lookupInDir(&parent, name) orelse return false;
    var child = inode.readInode(child_inum) orelse return false;
    switch (policy) {
        .file_only => if (inode.isDir(&child)) return false,
        .dir_only => if (!inode.isDir(&child)) return false,
    }
    // For dir_only: caller (rmdir) must have already verified the dir is
    // empty — we don't re-check here.

    if (!dirRemove(m, &parent, name)) return false;

    const t = time.now();
    const sec: u32 = @truncate(t.sec);

    // For directories, always free — caller (rmdir) already verified empty,
    // and the only remaining "links" are the self-reference via "." plus
    // the parent reference we're now removing. Nothing else can hold a
    // hardlink to a directory (POSIX forbids it).
    const free_inode_now = (policy == .dir_only) or (child.links_count <= 1);

    if (free_inode_now) {
        inode.freeAllBlocks(m, &child);
        var dead: layout.Inode = std.mem.zeroes(layout.Inode);
        dead.dtime = sec;
        if (!inode.writeInode(child_inum, &dead)) return false;
        _ = inode.freeInode(child_inum, policy == .dir_only);
    } else {
        child.links_count -= 1;
        child.ctime = sec;
        if (!inode.writeInode(child_inum, &child)) return false;
    }

    // Removing a directory drops the parent's links_count by 1 (the back-
    // pointer from the removed dir's ".." into us is gone).
    if (policy == .dir_only and parent.links_count > 0) {
        parent.links_count -= 1;
    }
    parent.mtime = sec;
    parent.ctime = sec;
    if (!inode.writeInode(parent_inum, &parent)) return false;

    path_cache.invalidateAll();
    return true;
}

/// Remove the dirent for `name` from `dir_ino`. If it's the first entry in
/// its block, set inode=0 (logical-delete in-place). Otherwise merge its
/// slot into the previous entry by bumping prev.rec_len. Returns false if
/// the name isn't found.
fn dirRemove(m: *block.Mount, dir_ino: *layout.Inode, name: []const u8) bool {
    const bs = m.block_size;
    const total = inode.fileSize(dir_ino);
    var lblock: u32 = 0;
    var dir_buf: [4096]u8 align(8) = undefined;
    while (@as(u64, lblock) * bs < total) : (lblock += 1) {
        if (!inode.readInodeBlock(dir_ino, lblock, dir_buf[0..bs])) return false;
        var w = DirWalk{ .buf = dir_buf[0..bs] };
        var prev: ?*align(1) layout.DirEntry = null;
        while (w.next()) |d| {
            if (d.e.inode != 0 and d.name.len == name.len and std.mem.eql(u8, d.name, name)) {
                if (prev) |prev_e| {
                    // Merge: prev.rec_len absorbs this entry's slot.
                    prev_e.rec_len += d.e.rec_len;
                } else {
                    // First entry in block — null its inode but keep rec_len so
                    // the dir walker still strides past it.
                    d.e.inode = 0;
                }
                const phys = inode.blockMapLookup(dir_ino, lblock) orelse return false;
                return block.writeBlock(m, phys, dir_buf[0..bs]);
            }
            prev = d.e;
        }
    }
    return false;
}

/// Reset an existing file's logical size to zero AND release every data /
/// indirect-tree block back to the bitmap. After this the file is empty
/// AND occupies zero physical blocks — the next write re-allocates via
/// ensurePhysicalBlock. Used by VFS open(O_TRUNC) and (future) unlink.
pub fn truncate(inum: u32) bool {
    // ETXTBSY: never truncate the text image of a running process. Covers both
    // O_TRUNC-on-open (vfs.openFlags) and any explicit ftruncate. This is the
    // path that took redteam.elf to size 0 and bricked its reload. (2026-06-04)
    if (@import("../../proc/process.zig").isTextBusy(inum)) return false;
    const m = block.getMount() orelse return false;
    var ino = inode.readInode(inum) orelse return false;
    if (!inode.isReg(&ino)) return false;
    inode.freeAllBlocks(m, &ino);
    ino.size = 0;
    ino.dir_acl = 0; // size-high bits, kept in sync
    const sec: u32 = @truncate(time.now().sec);
    ino.mtime = sec;
    ino.ctime = sec;
    // Page-cache coherence: every data page is gone — drop them all so a later
    // fault/read doesn't serve pre-truncate bytes.
    _ = page_cache.invalidateFile(page_cache.ext2FileId(inum));
    return inode.writeInode(inum, &ino);
}

pub fn fileSize(path: []const u8) ?u64 {
    const inum = cachedWalk(path) orelse return null; // genuinely-absent (e.g. tarfs file) — stay silent
    const ino = inode.readInode(inum) orelse {
        debug.klog("[ext2-fail] fileSize {s}: inum={d} readInode->null (inode-table block unreadable)\n", .{ path, inum });
        return null;
    };
    if (!inode.isReg(&ino)) {
        debug.klog("[ext2-fail] fileSize {s}: inum={d} not-a-regular-file (mode corrupt?)\n", .{ path, inum });
        return null;
    }
    return inode.fileSize(&ino);
}

/// Whole-file load into `dest`. Returns total bytes read or null on miss.
pub fn loadFile(path: []const u8, dest: []align(4) u8) ?usize {
    const r = loadFileInum(path, dest) orelse return null;
    return r.size;
}

/// Like `loadFile`, but also returns the resolved inode number — so a caller
/// that wants to cache-key on the file (ELF text sharing, Slice 3e) gets the
/// inum from the *same* resolution that read the bytes, with no chance of a
/// second `cachedWalk` diverging to a different file.
pub fn loadFileInum(path: []const u8, dest: []align(4) u8) ?struct { size: usize, inum: u32 } {
    const inum = cachedWalk(path) orelse return null;
    const ino = inode.readInode(inum) orelse {
        debug.klog("[ext2-fail] loadFileInum {s}: inum={d} readInode->null (inode-table block unreadable)\n", .{ path, inum });
        return null;
    };
    if (!inode.isReg(&ino)) {
        debug.klog("[ext2-fail] loadFileInum {s}: inum={d} not-a-regular-file (mode corrupt?)\n", .{ path, inum });
        return null;
    }
    const sz = inode.fileSize(&ino);
    // `sz` is an untrusted on-disk size — clamp to the caller's buffer so we
    // never write past `dest`.
    const want: usize = @intCast(@min(sz, @as(u64, dest.len)));
    const got = inode.readInodeBytes(inum, 0, dest[0..want]);
    if (got != want) debug.klog("[ext2-fail] loadFileInum {s}: inum={d} short block read got={d} want={d} (on-disk size={d})\n", .{ path, inum, got, want, sz });
    return .{ .size = got, .inum = inum };
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
        var w = DirWalk{ .buf = block_buf[0..m.block_size] };
        while (w.next()) |d| {
            if (count >= max_entries) break;
            if (d.e.inode == 0 or d.name.len == 0) continue;
            // Skip "." / ".." (sysListDir consumers don't show them) and
            // ext2's reserved `lost+found` directory (created by every
            // mkfs-equivalent for fsck recovery; clutters listings since
            // we never run fsck and the user has no use for it).
            if (!isDotEntry(d.name) and !isLostFound(d.name)) {
                fillEntry(&entries[count], d.name, d.e.inode);
                count += 1;
            }
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
    // Per-task scratch slot (4KB). Replaces a stack-local `[4096]u8` that
    // was tripping the deep-kstack watchpoint with 0xAA-fill noise and
    // eating significant frame depth on already-deep fs paths.
    const block_buf: *[4096]u8 = @import("../../proc/process.zig").currentIoScratch();
    const total = inode.fileSize(dir_ino);
    var lblock: u32 = 0;
    while (@as(u64, lblock) * m.block_size < total) : (lblock += 1) {
        if (!inode.readInodeBlock(dir_ino, lblock, block_buf[0..m.block_size])) return null;
        var w = DirWalk{ .buf = block_buf[0..m.block_size] };
        while (w.next()) |d| {
            if (d.e.inode != 0 and d.name.len > 0 and std.mem.eql(u8, d.name, name)) return d.e.inode;
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

