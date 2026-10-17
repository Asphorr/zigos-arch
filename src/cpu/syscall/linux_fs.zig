//! Linux file-system calls on names for `.linux` processes: open/openat,
//! close, the stat family (fstat, newfstatat, statx), getdents64, and the
//! *at calls that change the tree — mkdirat, unlinkat, renameat2 — plus
//! faccessat, readlinkat, ftruncate/truncate, flock and fsync.
//!
//! A path is absolute, relative to the cwd (vfs.resolvePath prefixes it),
//! or relative to a directory fd. A directory fd holds its ext2 inode, and
//! a path under one is made absolute with ext2.pathOf — the directory's
//! current path, found by walking ".." up — so every call goes through the
//! same path-based vfs and ext2 code, and a directory renamed while open
//! keeps working. Only the ext2 root has directory fds and a writable tree;
//! the other mounts (/dev, /proc, /tar) open and stat by name.
//!
//! The group shares one fd table and cwd, the lead's (proc()).

const std = @import("std");
const process = @import("../../proc/process.zig");
const vfs = @import("../../fs/vfs.zig");
const ext2 = @import("../../fs/ext2/ext2.zig");
const ext2_inode = @import("../../fs/ext2/inode.zig");
const common = @import("common.zig");

// Linux errno.
const ENOENT: i64 = 2;
const EIO: i64 = 5;
const EBADF: i64 = 9;
const EFAULT: i64 = 14;
const EEXIST: i64 = 17;
const EXDEV: i64 = 18;
const ENOTDIR: i64 = 20;
const EISDIR: i64 = 21;
const EINVAL: i64 = 22;
const EMFILE: i64 = 24;
const ETXTBSY: i64 = 26;
const ENOSPC: i64 = 28;
const EROFS: i64 = 30;
const ENAMETOOLONG: i64 = 36;
const ENOTEMPTY: i64 = 39;
const EOPNOTSUPP: i64 = 95;

inline fn err(e: i64) u64 {
    return @bitCast(-e);
}

fn errOf(e: ext2.Error) u64 {
    return err(switch (e) {
        error.NotFound => ENOENT,
        error.Exists => EEXIST,
        error.NotDir => ENOTDIR,
        error.IsDir => EISDIR,
        error.NotEmpty => ENOTEMPTY,
        error.NoSpace => ENOSPC,
        error.Busy => ETXTBSY,
        error.Invalid => EINVAL,
        error.Io => EIO,
    });
}

/// The process the calling thread belongs to: its group lead holds the fd
/// table and the cwd the group's threads share.
pub fn proc() ?*process.PCB {
    return process.leader(process.currentPCB() orelse return null);
}

pub const AT_FDCWD: u64 = 0xFFFF_FFFF_FFFF_FF9C; // -100
pub const AT_REMOVEDIR: u64 = 0x200;
const AT_EMPTY_PATH: u64 = 0x1000;

const O_ACCMODE: u64 = 3;
const O_RDONLY: u64 = 0;
const O_CREAT: u64 = 0x40;
const O_EXCL: u64 = 0x80;
const O_TRUNC: u64 = 0x200;
const O_APPEND: u64 = 0x400;
const O_DIRECTORY: u64 = 0x10000;
const O_TMPFILE: u64 = 0x410000; // includes O_DIRECTORY

const RENAME_NOREPLACE: u64 = 1;

// st_mode format bits (the ext2 on-disk i_mode values).
const S_IFCHR: u32 = 0o0020000;
const S_IFDIR: u32 = 0o0040000;
const S_IFREG: u32 = 0o0100000;

/// Linux x86-64 `struct stat`, 144 bytes (arch/x86/include/uapi/asm/stat.h).
pub const LinuxStat = extern struct {
    st_dev: u64 = 0,
    st_ino: u64 = 0,
    st_nlink: u64 = 0,
    st_mode: u32 = 0,
    st_uid: u32 = 0,
    st_gid: u32 = 0,
    __pad0: u32 = 0,
    st_rdev: u64 = 0,
    st_size: i64 = 0,
    st_blksize: i64 = 0,
    st_blocks: i64 = 0,
    st_atime: u64 = 0,
    st_atime_nsec: u64 = 0,
    st_mtime: u64 = 0,
    st_mtime_nsec: u64 = 0,
    st_ctime: u64 = 0,
    st_ctime_nsec: u64 = 0,
    __unused: [3]i64 = .{ 0, 0, 0 },
};

const StatxTime = extern struct { sec: i64 = 0, nsec: u32 = 0, __pad: u32 = 0 };

/// Linux `struct statx`, 256 bytes.
const Statx = extern struct {
    mask: u32 = 0,
    blksize: u32 = 0,
    attributes: u64 = 0,
    nlink: u32 = 0,
    uid: u32 = 0,
    gid: u32 = 0,
    mode: u16 = 0,
    __pad1: u16 = 0,
    ino: u64 = 0,
    size: u64 = 0,
    blocks: u64 = 0,
    attributes_mask: u64 = 0,
    atime: StatxTime = .{},
    btime: StatxTime = .{},
    ctime: StatxTime = .{},
    mtime: StatxTime = .{},
    rdev_major: u32 = 0,
    rdev_minor: u32 = 0,
    dev_major: u32 = 0,
    dev_minor: u32 = 0,
    __pad2: [14]u64 = [_]u64{0} ** 14,
};

comptime {
    std.debug.assert(@sizeOf(LinuxStat) == 144);
    std.debug.assert(@sizeOf(Statx) == 256);
}

const STATX_BASIC_STATS: u32 = 0x7ff;

// d_type values for getdents64.
const DT_UNKNOWN: u8 = 0;
const DT_FIFO: u8 = 1;
const DT_CHR: u8 = 2;
const DT_DIR: u8 = 4;
const DT_BLK: u8 = 6;
const DT_REG: u8 = 8;
const DT_LNK: u8 = 10;
const DT_SOCK: u8 = 12;

// ext2 directory-entry file types.
fn dtypeOf(ft: u8) u8 {
    return switch (ft) {
        1 => DT_REG,
        2 => DT_DIR,
        3 => DT_CHR,
        4 => DT_BLK,
        5 => DT_FIFO,
        6 => DT_SOCK,
        7 => DT_LNK,
        else => DT_UNKNOWN,
    };
}

// --- Names ---------------------------------------------------------------

pub const PathRead = union(enum) { path: []const u8, fail: u64 };

/// The NUL-terminated user string at `va`, in `out`: -EFAULT for a bad
/// pointer, -ENAMETOOLONG past 255 bytes, -ENOENT for "" unless
/// `allow_empty` (the AT_EMPTY_PATH forms).
pub fn readPath(va: u64, out: *[256]u8, allow_empty: bool) PathRead {
    if (va == 0) return .{ .fail = err(EFAULT) };
    var n: usize = 0;
    while (true) : (n += 1) {
        // Once per page; the first check bounds va below the user ceiling.
        const at = va + n;
        if ((n == 0 or at & 0xFFF == 0) and !common.validateUserPtr(at, 1)) return .{ .fail = err(EFAULT) };
        const ch = @as([*]const u8, @ptrFromInt(at))[0];
        if (ch == 0) break;
        if (n == 255) return .{ .fail = err(ENAMETOOLONG) };
        out[n] = ch;
    }
    if (n == 0 and !allow_empty) return .{ .fail = err(ENOENT) };
    return .{ .path = out[0..n] };
}

/// The open fd `fd` of `pcb`, or null.
pub fn fdEntry(pcb: *process.PCB, fd: u64) ?*process.FileDesc {
    if (fd >= pcb.fd_table.len or !pcb.fd_table[fd].in_use) return null;
    return &pcb.fd_table[fd];
}

/// `path` as the vfs takes it: as given when absolute or relative to the
/// cwd (AT_FDCWD), else made absolute under directory fd `dirfd`. An empty
/// path names the directory itself.
fn atPath(pcb: *process.PCB, dirfd: u64, path: []const u8, out: *[256]u8) PathRead {
    if ((path.len > 0 and path[0] == '/') or dirfd == AT_FDCWD) {
        if (path.len == 0) return .{ .fail = err(ENOENT) };
        return .{ .path = path };
    }
    const fe = fdEntry(pcb, dirfd) orelse return .{ .fail = err(EBADF) };
    if (fe.fs_type != .ext2) return .{ .fail = err(ENOTDIR) };
    const ino = ext2_inode.readInode(fe.inode) orelse return .{ .fail = err(EIO) };
    if (!ext2_inode.isDir(&ino)) return .{ .fail = err(ENOTDIR) };
    const base = ext2.pathOf(fe.inode, out) orelse return .{ .fail = err(ENOENT) };
    if (path.len == 0) return .{ .path = base };
    const sep: usize = if (base[base.len - 1] == '/') 0 else 1;
    if (base.len + sep + path.len > out.len) return .{ .fail = err(ENAMETOOLONG) };
    if (sep == 1) out[base.len] = '/';
    @memcpy(out[base.len + sep ..][0..path.len], path);
    return .{ .path = out[0 .. base.len + sep + path.len] };
}

/// A user path argument relative to `dirfd`, resolved: `bufs` holds the
/// two copies (as given, and made absolute).
const Bufs = struct { user: [256]u8 = undefined, full: [256]u8 = undefined };

fn userAtPath(pcb: *process.PCB, dirfd: u64, va: u64, bufs: *Bufs, allow_empty: bool) PathRead {
    const p = switch (readPath(va, &bufs.user, allow_empty)) {
        .path => |p| p,
        .fail => |e| return .{ .fail = e },
    };
    return atPath(pcb, dirfd, p, &bufs.full);
}

/// What a path names: an ext2 node, nothing on ext2, or something on
/// another mount (whose own open/stat decide).
const Node = union(enum) { ext2: u32, missing, other };

fn lookupNode(pcb: *process.PCB, path: []const u8) Node {
    var buf: [256]u8 = undefined;
    const r = vfs.resolvePath(pcb, path, &buf) orelse return .missing;
    if (r.fs != .ext2) return .other;
    return if (ext2.lookupPath(r.path)) |inum| .{ .ext2 = inum } else .missing;
}

/// `path` as a path inside the ext2 root, or the errno for a name that
/// isn't on it.
fn ext2Path(pcb: *process.PCB, path: []const u8, buf: *[256]u8) PathRead {
    const r = vfs.resolvePath(pcb, path, buf) orelse return .{ .fail = err(ENOENT) };
    if (r.fs != .ext2) return .{ .fail = err(EROFS) };
    return .{ .path = r.path };
}

fn isDirInode(inum: u32) bool {
    const ino = ext2_inode.readInode(inum) orelse return false;
    return ext2_inode.isDir(&ino);
}

// --- open / close ----------------------------------------------------------

fn freeFds(pcb: *process.PCB) bool {
    for (pcb.fd_table[3..]) |e| if (!e.in_use) return true;
    return false;
}

/// openat(dirfd, path, flags, mode); open is openat(AT_FDCWD, ...). The
/// mode is ignored: there are no permissions.
pub fn openat(dirfd: u64, path_va: u64, lflags: u64) u64 {
    const pcb = proc() orelse return err(EFAULT);
    var bufs: Bufs = .{};
    const path = switch (userAtPath(pcb, dirfd, path_va, &bufs, false)) {
        .path => |p| p,
        .fail => |e| return e,
    };
    if (lflags & O_TMPFILE == O_TMPFILE) return err(EOPNOTSUPP);
    const creat = lflags & O_CREAT != 0;
    switch (lookupNode(pcb, path)) {
        .other => {},
        .missing => if (!creat) return err(ENOENT),
        .ext2 => |inum| {
            if (creat and lflags & O_EXCL != 0) return err(EEXIST);
            if (isDirInode(inum)) {
                if (lflags & O_ACCMODE != O_RDONLY) return err(EISDIR);
                if (vfs.openDir(pcb, path)) |fd| return fd;
                return err(if (freeFds(pcb)) ENOENT else EMFILE);
            }
            if (lflags & O_DIRECTORY != 0) return err(ENOTDIR);
        },
    }
    var zflags: u32 = 0;
    if (creat) zflags |= vfs.O_CREATE;
    if (lflags & O_TRUNC != 0) zflags |= vfs.O_TRUNC;
    if (lflags & O_APPEND != 0) zflags |= vfs.O_APPEND;
    if (vfs.openFlags(pcb, path, zflags)) |fd| return fd;
    // A missing file whose directory is missing too, or a full table.
    return err(if (freeFds(pcb)) ENOENT else EMFILE);
}

pub fn close(fd: u64) u64 {
    const pcb = proc() orelse return err(EFAULT);
    if (fd >= pcb.fd_table.len) return err(EBADF);
    if (vfs.close(pcb, @intCast(fd)) != 0) return err(EBADF);
    return 0;
}

// --- stat ------------------------------------------------------------------

/// The facts the stat calls report.
const Facts = struct {
    ino: u64 = 0,
    mode: u32 = 0,
    nlink: u32 = 1,
    uid: u32 = 0,
    gid: u32 = 0,
    size: u64 = 0,
    blocks: u64 = 0,
    rdev: u64 = 0,
    atime: u64 = 0,
    mtime: u64 = 0,
    ctime: u64 = 0,
};

fn ext2Facts(inum: u32) ?Facts {
    const ino = ext2_inode.readInode(inum) orelse return null;
    return .{
        .ino = inum,
        .mode = ino.mode,
        .nlink = ino.links_count,
        .uid = ino.uid,
        .gid = ino.gid,
        .size = ext2_inode.fileSize(&ino),
        .blocks = ino.blocks, // ext2 i_blocks is in 512-byte units already
        .atime = ino.atime,
        .mtime = ino.mtime,
        .ctime = ino.ctime,
    };
}

const CONSOLE_FACTS = Facts{ .mode = S_IFCHR | 0o620, .rdev = 0x0500 };

/// Facts from the coarse vfs.statPath answer other mounts give.
fn pathFacts(pcb: *process.PCB, path: []const u8) ?Facts {
    var info: vfs.StatInfo = undefined;
    if (!vfs.statPath(pcb, path, &info)) return null;
    const size: u64 = info.file_size;
    return .{
        .mode = if (info.is_directory != 0) S_IFDIR | 0o755 else S_IFREG | 0o644,
        .size = size,
        .blocks = (size + 511) / 512,
        .atime = info.modify_time,
        .mtime = info.modify_time,
        .ctime = info.modify_time,
    };
}

pub const FactsRead = union(enum) { facts: Facts, fail: u64 };

pub fn fdFacts(pcb: *process.PCB, fd: u64) FactsRead {
    const fe = fdEntry(pcb, fd) orelse return .{ .fail = err(EBADF) };
    return switch (fe.fs_type) {
        .console => .{ .facts = CONSOLE_FACTS },
        .ext2 => if (ext2Facts(fe.inode)) |f| .{ .facts = f } else .{ .fail = err(EIO) },
        else => .{ .facts = .{ .mode = S_IFREG | 0o644 } },
    };
}

/// The facts for (dirfd, path) as the *stat*at calls name a file: the fd
/// itself for an empty path with AT_EMPTY_PATH.
fn atFacts(pcb: *process.PCB, dirfd: u64, path_va: u64, flags: u64) FactsRead {
    var bufs: Bufs = .{};
    const user = switch (readPath(path_va, &bufs.user, flags & AT_EMPTY_PATH != 0)) {
        .path => |p| p,
        .fail => |e| return .{ .fail = e },
    };
    if (user.len == 0) {
        if (dirfd == AT_FDCWD) {
            const cwd = pcb.cwd[0..pcb.cwd_len];
            return if (pathFacts(pcb, cwd)) |f| .{ .facts = f } else .{ .fail = err(ENOENT) };
        }
        return fdFacts(pcb, dirfd);
    }
    const path = switch (atPath(pcb, dirfd, user, &bufs.full)) {
        .path => |p| p,
        .fail => |e| return .{ .fail = e },
    };
    return switch (lookupNode(pcb, path)) {
        .ext2 => |inum| if (ext2Facts(inum)) |f| .{ .facts = f } else .{ .fail = err(EIO) },
        .missing => .{ .fail = err(ENOENT) },
        .other => if (pathFacts(pcb, path)) |f| .{ .facts = f } else .{ .fail = err(ENOENT) },
    };
}

fn toStat(f: Facts) LinuxStat {
    return .{
        .st_ino = f.ino,
        .st_nlink = f.nlink,
        .st_mode = f.mode,
        .st_uid = f.uid,
        .st_gid = f.gid,
        .st_rdev = f.rdev,
        .st_size = @intCast(f.size),
        .st_blksize = 4096,
        .st_blocks = @intCast(f.blocks),
        .st_atime = f.atime,
        .st_mtime = f.mtime,
        .st_ctime = f.ctime,
    };
}

fn putStat(va: u64, r: FactsRead) u64 {
    const f = switch (r) {
        .facts => |f| f,
        .fail => |e| return e,
    };
    if (!common.validateUserPtrWriteAligned(va, @sizeOf(LinuxStat), @alignOf(LinuxStat))) return err(EFAULT);
    @as(*LinuxStat, @ptrFromInt(va)).* = toStat(f);
    return 0;
}

pub fn fstat(fd: u64, statbuf_va: u64) u64 {
    const pcb = proc() orelse return err(EFAULT);
    return putStat(statbuf_va, fdFacts(pcb, fd));
}

/// newfstatat(dirfd, path, statbuf, flags); stat and lstat are it with
/// AT_FDCWD (no symlinks, so the two agree).
pub fn newfstatat(dirfd: u64, path_va: u64, statbuf_va: u64, flags: u64) u64 {
    const pcb = proc() orelse return err(EFAULT);
    return putStat(statbuf_va, atFacts(pcb, dirfd, path_va, flags));
}

fn statxTime(sec: u64) StatxTime {
    return .{ .sec = @intCast(sec) };
}

/// statx(dirfd, path, flags, mask, buf): every basic field, whatever the
/// mask asks for, as Linux may.
pub fn statx(dirfd: u64, path_va: u64, flags: u64, mask: u64, buf_va: u64) u64 {
    _ = mask;
    const pcb = proc() orelse return err(EFAULT);
    const f = switch (atFacts(pcb, dirfd, path_va, flags)) {
        .facts => |f| f,
        .fail => |e| return e,
    };
    if (!common.validateUserPtrWriteAligned(buf_va, @sizeOf(Statx), @alignOf(Statx))) return err(EFAULT);
    @as(*Statx, @ptrFromInt(buf_va)).* = .{
        .mask = STATX_BASIC_STATS,
        .blksize = 4096,
        .nlink = f.nlink,
        .uid = f.uid,
        .gid = f.gid,
        .mode = @truncate(f.mode),
        .ino = f.ino,
        .size = f.size,
        .blocks = f.blocks,
        .atime = statxTime(f.atime),
        .ctime = statxTime(f.ctime),
        .mtime = statxTime(f.mtime),
        .rdev_major = @truncate(f.rdev >> 8),
        .rdev_minor = @truncate(f.rdev & 0xFF),
    };
    return 0;
}

// --- Directories -----------------------------------------------------------

const DentSink = struct {
    out: [*]u8,
    cap: usize,
    used: usize = 0,

    fn put64(p: [*]u8, v: u64) void {
        @as(*align(1) u64, @ptrCast(p)).* = v;
    }

    pub fn take(self: *DentSink, it: ext2.DirItem) bool {
        const reclen = std.mem.alignForward(usize, 19 + it.name.len + 1, 8);
        if (self.used + reclen > self.cap) return false;
        const rec = self.out + self.used;
        put64(rec, it.inum); // d_ino
        put64(rec + 8, it.next); // d_off: where the next entry starts
        @as(*align(1) u16, @ptrCast(rec + 16)).* = @intCast(reclen);
        rec[18] = dtypeOf(it.file_type);
        @memcpy(rec[19..][0..it.name.len], it.name);
        @memset(rec[19 + it.name.len .. reclen], 0); // NUL + padding
        self.used += reclen;
        return true;
    }
};

/// getdents64(fd, buf, count) over an ext2 directory fd, with "." and "..".
/// The fd offset is the byte position of the next entry in the directory.
pub fn getdents64(fd: u64, buf_va: u64, count: u64) u64 {
    const pcb = proc() orelse return err(EFAULT);
    const fe = fdEntry(pcb, fd) orelse return err(EBADF);
    if (fe.fs_type != .ext2 or !isDirInode(fe.inode)) return err(ENOTDIR);
    // A record is at most 280 bytes; don't validate (and map) more buffer
    // than a few hundred of them need.
    const cap: usize = @intCast(@min(count, 64 * 1024));
    if (cap < 24) return err(EINVAL);
    if (!common.validateUserPtrWrite(buf_va, cap)) return err(EFAULT);
    var sink = DentSink{ .out = @ptrFromInt(buf_va), .cap = cap };
    const next = ext2.iterDir(fe.inode, fe.offset, &sink) orelse return err(EIO);
    if (sink.used == 0 and next < dirSize(fe.inode)) return err(EINVAL); // the next entry doesn't fit
    fe.offset = @intCast(next);
    return sink.used;
}

fn dirSize(inum: u32) u64 {
    const ino = ext2_inode.readInode(inum) orelse return 0;
    return ext2_inode.fileSize(&ino);
}

/// mkdirat(dirfd, path, mode).
pub fn mkdirat(dirfd: u64, path_va: u64) u64 {
    const pcb = proc() orelse return err(EFAULT);
    var bufs: Bufs = .{};
    const path = switch (userAtPath(pcb, dirfd, path_va, &bufs, false)) {
        .path => |p| p,
        .fail => |e| return e,
    };
    var rbuf: [256]u8 = undefined;
    const rel = switch (ext2Path(pcb, path, &rbuf)) {
        .path => |p| p,
        .fail => |e| return e,
    };
    ext2.mkdirAt(rel) catch |e| return errOf(e);
    return 0;
}

/// unlinkat(dirfd, path, flags): rmdir with AT_REMOVEDIR.
pub fn unlinkat(dirfd: u64, path_va: u64, flags: u64) u64 {
    if (flags & ~AT_REMOVEDIR != 0) return err(EINVAL);
    const pcb = proc() orelse return err(EFAULT);
    var bufs: Bufs = .{};
    const path = switch (userAtPath(pcb, dirfd, path_va, &bufs, false)) {
        .path => |p| p,
        .fail => |e| return e,
    };
    var rbuf: [256]u8 = undefined;
    const rel = switch (ext2Path(pcb, path, &rbuf)) {
        .path => |p| p,
        .fail => |e| return e,
    };
    if (flags & AT_REMOVEDIR != 0) {
        ext2.rmdirAt(rel) catch |e| return errOf(e);
    } else {
        ext2.unlinkAt(rel) catch |e| return errOf(e);
    }
    return 0;
}

/// renameat2(olddirfd, old, newdirfd, new, flags); rename and renameat are
/// it with AT_FDCWD and 0. RENAME_NOREPLACE is honoured, RENAME_EXCHANGE
/// and RENAME_WHITEOUT are not supported.
pub fn renameat2(old_dirfd: u64, old_va: u64, new_dirfd: u64, new_va: u64, flags: u64) u64 {
    if (flags & ~RENAME_NOREPLACE != 0) return err(EINVAL);
    const pcb = proc() orelse return err(EFAULT);
    var old_bufs: Bufs = .{};
    var new_bufs: Bufs = .{};
    const old_path = switch (userAtPath(pcb, old_dirfd, old_va, &old_bufs, false)) {
        .path => |p| p,
        .fail => |e| return e,
    };
    const new_path = switch (userAtPath(pcb, new_dirfd, new_va, &new_bufs, false)) {
        .path => |p| p,
        .fail => |e| return e,
    };
    var old_rbuf: [256]u8 = undefined;
    var new_rbuf: [256]u8 = undefined;
    const old_rel = switch (ext2Path(pcb, old_path, &old_rbuf)) {
        .path => |p| p,
        .fail => |e| return if (e == err(EROFS)) err(EXDEV) else e,
    };
    const new_rel = switch (ext2Path(pcb, new_path, &new_rbuf)) {
        .path => |p| p,
        .fail => |e| return if (e == err(EROFS)) err(EXDEV) else e,
    };
    if (flags & RENAME_NOREPLACE != 0 and ext2.lookupPath(new_rel) != null) return err(EEXIST);
    ext2.rename(old_rel, new_rel) catch |e| return errOf(e);
    return 0;
}

/// faccessat(dirfd, path, mode, flags); access is it with AT_FDCWD. Without
/// permissions, a file that exists may be accessed every way.
pub fn faccessat(dirfd: u64, path_va: u64) u64 {
    const pcb = proc() orelse return err(EFAULT);
    var bufs: Bufs = .{};
    const path = switch (userAtPath(pcb, dirfd, path_va, &bufs, false)) {
        .path => |p| p,
        .fail => |e| return e,
    };
    return switch (lookupNode(pcb, path)) {
        .ext2 => 0,
        .missing => err(ENOENT),
        .other => if (pathFacts(pcb, path) != null) 0 else err(ENOENT),
    };
}

/// The target of the /proc/<pid>/exe-style link `path` names, if it is one:
/// /proc/self/exe, /proc/thread-self/exe and /proc/<pid>/exe.
fn exeLink(pcb: *process.PCB, path: []const u8) ?[]const u8 {
    const prefix = "/proc/";
    const suffix = "/exe";
    if (!std.mem.startsWith(u8, path, prefix) or !std.mem.endsWith(u8, path, suffix)) return null;
    if (path.len <= prefix.len + suffix.len) return null;
    const who = path[prefix.len .. path.len - suffix.len];
    const owner: *process.PCB = if (std.mem.eql(u8, who, "self") or std.mem.eql(u8, who, "thread-self"))
        pcb
    else blk: {
        const pid = std.fmt.parseInt(u8, who, 10) catch return null;
        if (pid >= process.MAX_PROCS) return null;
        const s = process.procs[pid].state;
        if (s == .unused or s == .zombie) return null;
        break :blk process.leader(&process.procs[pid]);
    };
    return owner.exe_path[0..owner.exe_path_len];
}

/// readlinkat(dirfd, path, buf, size); readlink is it with AT_FDCWD. The
/// only links are /proc's exe links; any other file is EINVAL, as a
/// non-link is.
pub fn readlinkat(dirfd: u64, path_va: u64, buf_va: u64, size: u64) u64 {
    const want: i32 = @bitCast(@as(u32, @truncate(size)));
    if (want <= 0) return err(EINVAL);
    const pcb = proc() orelse return err(EFAULT);
    var bufs: Bufs = .{};
    const path = switch (userAtPath(pcb, dirfd, path_va, &bufs, false)) {
        .path => |p| p,
        .fail => |e| return e,
    };
    const target = exeLink(pcb, path) orelse return switch (lookupNode(pcb, path)) {
        .ext2 => err(EINVAL),
        .missing => err(ENOENT),
        .other => if (pathFacts(pcb, path) != null) err(EINVAL) else err(ENOENT),
    };
    if (target.len == 0) return err(ENOENT);
    const n = @min(target.len, @as(usize, @intCast(want)));
    if (!common.validateUserPtrWrite(buf_va, n)) return err(EFAULT);
    @memcpy(@as([*]u8, @ptrFromInt(buf_va))[0..n], target[0..n]);
    return n;
}

// --- File size, locks, sync --------------------------------------------------

/// ftruncate(fd, length).
pub fn ftruncate(fd: u64, length: u64) u64 {
    const pcb = proc() orelse return err(EFAULT);
    const fe = fdEntry(pcb, fd) orelse return err(EBADF);
    if (@as(i64, @bitCast(length)) < 0) return err(EINVAL);
    if (fe.fs_type != .ext2) return err(EINVAL);
    ext2.truncateTo(fe.inode, length) catch |e| return errOf(e);
    return 0;
}

/// truncate(path, length).
pub fn truncate(path_va: u64, length: u64) u64 {
    const pcb = proc() orelse return err(EFAULT);
    if (@as(i64, @bitCast(length)) < 0) return err(EINVAL);
    var bufs: Bufs = .{};
    const path = switch (userAtPath(pcb, AT_FDCWD, path_va, &bufs, false)) {
        .path => |p| p,
        .fail => |e| return e,
    };
    const inum = switch (lookupNode(pcb, path)) {
        .ext2 => |inum| inum,
        .missing => return err(ENOENT),
        .other => return err(EROFS),
    };
    ext2.truncateTo(inum, length) catch |e| return errOf(e);
    return 0;
}

const LOCK_SH: u64 = 1;
const LOCK_EX: u64 = 2;
const LOCK_NB: u64 = 4;
const LOCK_UN: u64 = 8;

/// flock(fd, op): granted at once. Nothing else takes the locks a compiler
/// cache uses while one process runs; locking between processes is still
/// to come.
pub fn flock(fd: u64, op: u64) u64 {
    const pcb = proc() orelse return err(EFAULT);
    _ = fdEntry(pcb, fd) orelse return err(EBADF);
    const kind = op & ~LOCK_NB;
    if (kind != LOCK_SH and kind != LOCK_EX and kind != LOCK_UN) return err(EINVAL);
    return 0;
}

/// fsync / fdatasync: write() data is on disk already (the ext2 block layer
/// writes through); what a MAP_SHARED mapping dirtied goes now.
pub fn fsync(fd: u64) u64 {
    const pcb = proc() orelse return err(EFAULT);
    const fe = fdEntry(pcb, fd) orelse return err(EBADF);
    if (fe.fs_type == .ext2) _ = vfs.syncCacheFile(fe.inode, false);
    return 0;
}
