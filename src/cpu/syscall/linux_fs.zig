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
const file = @import("../../fs/file.zig");
const ext2 = @import("../../fs/ext2/ext2.zig");
const ext2_inode = @import("../../fs/ext2/inode.zig");
const common = @import("common.zig");
const native_fs = @import("fs.zig");
const usercopy = @import("../arch/usercopy.zig");

// Linux errno.
const EPERM: i64 = 1;
const ENOENT: i64 = 2;
const EIO: i64 = 5;
const EACCES: i64 = 13;
const EBADF: i64 = 9;
const EFAULT: i64 = 14;
const EEXIST: i64 = 17;
const EXDEV: i64 = 18;
const ENOTDIR: i64 = 20;
const EISDIR: i64 = 21;
const EINVAL: i64 = 22;
const EMFILE: i64 = 24;
const ETXTBSY: i64 = 26;
const EFBIG: i64 = 27;
const ENOSPC: i64 = 28;
const EROFS: i64 = 30;
const ENAMETOOLONG: i64 = 36;
const ENOTEMPTY: i64 = 39;
const ELOOP: i64 = 40;
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
pub const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
const AT_SYMLINK_FOLLOW: u64 = 0x400;
const AT_EMPTY_PATH: u64 = 0x1000;

const O_ACCMODE: u64 = 3;
const O_RDONLY: u64 = 0;
const O_CREAT: u64 = 0x40;
const O_EXCL: u64 = 0x80;
const O_TRUNC: u64 = 0x200;
const O_APPEND: u64 = 0x400;
const O_NONBLOCK: u64 = 0x800;
const O_DIRECTORY: u64 = 0x10000;
const O_NOFOLLOW: u64 = 0x20000;
const O_TMPFILE: u64 = 0x410000; // includes O_DIRECTORY
const O_CLOEXEC: u64 = 0x80000;

const RENAME_NOREPLACE: u64 = 1;

// st_mode format bits (the ext2 on-disk i_mode values).
const S_IFIFO: u32 = 0o0010000;
const S_IFCHR: u32 = 0o0020000;
const S_IFDIR: u32 = 0o0040000;
const S_IFREG: u32 = 0o0100000;
const S_IFSOCK: u32 = 0o0140000;

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

/// The file behind the open fd `fd` of `pcb`, with a reference the caller
/// puts back (file.put), or null.
pub fn fdFile(pcb: *process.PCB, fd: u64) ?*file.File {
    return file.get(pcb, fd);
}

/// Is `fd` an open descriptor of `pcb`?
pub fn fdOpen(pcb: *process.PCB, fd: u64) bool {
    const f = file.get(pcb, fd) orelse return false;
    file.put(f);
    return true;
}

/// `path` as the vfs takes it: as given when absolute or relative to the
/// cwd (AT_FDCWD), else made absolute under directory fd `dirfd`. An empty
/// path names the directory itself.
fn atPath(pcb: *process.PCB, dirfd: u64, path: []const u8, out: *[256]u8) PathRead {
    if ((path.len > 0 and path[0] == '/') or dirfd == AT_FDCWD) {
        if (path.len == 0) return .{ .fail = err(ENOENT) };
        return .{ .path = path };
    }
    const fe = fdFile(pcb, dirfd) orelse return .{ .fail = err(EBADF) };
    defer file.put(fe);
    if (fe.kind != .ext2) return .{ .fail = err(ENOTDIR) };
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

/// Whether a symbolic link in a path's last component is followed (the ones
/// before it always are).
pub const Last = enum { follow, nofollow };

fn resolve(pcb: *process.PCB, path: []const u8, buf: *[256]u8, last: Last) ?vfs.ResolvedPath {
    return if (last == .follow) vfs.resolvePath(pcb, path, buf) else vfs.resolvePathNoFollow(pcb, path, buf);
}

fn lookupNode(pcb: *process.PCB, path: []const u8, last: Last) Node {
    var buf: [256]u8 = undefined;
    const r = resolve(pcb, path, &buf, last) orelse return .missing;
    if (r.fs != .ext2) return .other;
    return if (ext2.lookupPath(r.path)) |inum| .{ .ext2 = inum } else .missing;
}

/// `path` as a path inside the ext2 root, or the errno for a name that
/// isn't on it.
pub fn ext2Path(pcb: *process.PCB, path: []const u8, buf: *[256]u8, last: Last) PathRead {
    const r = resolve(pcb, path, buf, last) orelse return .{ .fail = err(ENOENT) };
    if (r.fs != .ext2) return .{ .fail = err(EROFS) };
    return .{ .path = r.path };
}

fn isLinkInode(inum: u32) bool {
    const ino = ext2_inode.readInode(inum) orelse return false;
    return ext2_inode.isSymlink(&ino);
}

fn isDirInode(inum: u32) bool {
    const ino = ext2_inode.readInode(inum) orelse return false;
    return ext2_inode.isDir(&ino);
}

// --- open / close ----------------------------------------------------------

fn freeFds(pcb: *process.PCB) bool {
    for (pcb.fd_table) |e| if (!e.inUse()) return true;
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
    // O_EXCL creates the name itself or fails, and O_NOFOLLOW refuses a
    // link there: both look at the last component as it is.
    const excl = creat and lflags & O_EXCL != 0;
    const last: Last = if (excl or lflags & O_NOFOLLOW != 0) .nofollow else .follow;
    switch (lookupNode(pcb, path, last)) {
        .other => {},
        .missing => if (!creat) return err(ENOENT),
        .ext2 => |inum| {
            if (excl) return err(EEXIST);
            if (last == .nofollow and isLinkInode(inum)) return err(if (lflags & O_DIRECTORY != 0) ENOTDIR else ELOOP);
            if (isDirInode(inum)) {
                if (lflags & O_ACCMODE != O_RDONLY) return err(EISDIR);
                if (vfs.openDir(pcb, path)) |fd| return opened(pcb, fd, lflags);
                return err(if (freeFds(pcb)) ENOENT else EMFILE);
            }
            if (lflags & O_DIRECTORY != 0) return err(ENOTDIR);
        },
    }
    var zflags: u32 = 0;
    if (creat) zflags |= vfs.O_CREATE;
    if (lflags & O_TRUNC != 0) zflags |= vfs.O_TRUNC;
    if (lflags & O_APPEND != 0) zflags |= vfs.O_APPEND;
    if (vfs.openFlags(pcb, path, zflags)) |fd| return opened(pcb, fd, lflags);
    // A missing file whose directory is missing too, or a full table.
    return err(if (freeFds(pcb)) ENOENT else EMFILE);
}

/// A new fd, its O_CLOEXEC and the file's O_NONBLOCK recorded.
fn opened(pcb: *process.PCB, fd: u32, lflags: u64) u64 {
    pcb.fd_table[fd].cloexec = lflags & O_CLOEXEC != 0;
    if (lflags & O_NONBLOCK != 0) {
        if (fdFile(pcb, fd)) |f| {
            f.nonblock = true;
            file.put(f);
        }
    }
    return fd;
}

pub fn close(fd: u64) u64 {
    const pcb = proc() orelse return err(EFAULT);
    if (fd >= pcb.fd_table.len) return err(EBADF);
    if (vfs.closeSlot(pcb, @intCast(fd)) != 0) return err(EBADF);
    return 0;
}

/// What execve runs: an ext2 file, and its absolute name.
pub const ExecTarget = struct { inum: u32, size: u64, path: []const u8 };
pub const ExecLookup = union(enum) { file: ExecTarget, fail: u64 };

/// The file execve's `path_va` names (relative to the cwd), its absolute
/// name in `out`.
pub fn execTarget(path_va: u64, out: *[256]u8) ExecLookup {
    const pcb = proc() orelse return .{ .fail = err(EFAULT) };
    var bufs: Bufs = .{};
    const path = switch (userAtPath(pcb, AT_FDCWD, path_va, &bufs, false)) {
        .path => |p| p,
        .fail => |e| return .{ .fail = e },
    };
    var rbuf: [256]u8 = undefined;
    const r = vfs.resolvePath(pcb, path, &rbuf) orelse return .{ .fail = err(ENOENT) };
    if (r.fs != .ext2) return .{ .fail = err(EACCES) };
    const inum = ext2.lookupPath(r.path) orelse return .{ .fail = err(ENOENT) };
    const ino = ext2_inode.readInode(inum) orelse return .{ .fail = err(EIO) };
    if (ext2_inode.isDir(&ino)) return .{ .fail = err(EACCES) };
    const rel = std.mem.trimLeft(u8, r.path, "/");
    if (rel.len + 1 > out.len) return .{ .fail = err(ENAMETOOLONG) };
    out[0] = '/';
    @memcpy(out[1..][0..rel.len], rel);
    return .{ .file = .{ .inum = inum, .size = ext2_inode.fileSize(&ino), .path = out[0 .. rel.len + 1] } };
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
    const fe = fdFile(pcb, fd) orelse return .{ .fail = err(EBADF) };
    defer file.put(fe);
    // A terminal window's pipe ends are a character device to its programs.
    if (@import("../../proc/tty.zig").get(fe.tty) != null) return .{ .facts = CONSOLE_FACTS };
    return switch (fe.kind) {
        .console => .{ .facts = CONSOLE_FACTS },
        .ext2 => if (ext2Facts(fe.inode)) |f| .{ .facts = f } else .{ .fail = err(EIO) },
        .pipe => .{ .facts = .{ .mode = S_IFIFO | 0o600 } },
        .socket => .{ .facts = .{ .mode = S_IFSOCK | 0o777 } },
        // Anonymous inodes, as an epoll set and an eventfd are on Linux.
        .epoll, .eventfd => .{ .facts = .{ .mode = 0o600 } },
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
    const last: Last = if (flags & AT_SYMLINK_NOFOLLOW != 0) .nofollow else .follow;
    return switch (lookupNode(pcb, path, last)) {
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
        if (rec[18] == DT_UNKNOWN) rec[18] = dtypeOfInode(it.inum);
        @memcpy(rec[19..][0..it.name.len], it.name);
        @memset(rec[19 + it.name.len .. reclen], 0); // NUL + padding
        self.used += reclen;
        return true;
    }
};

/// Most bytes of records one getdents64 call returns: its kernel-stack
/// buffer. A record is at most 280 bytes, so a call always makes progress.
const DENTS_CHUNK: usize = 4096;

/// getdents64(fd, buf, count) over an ext2 directory fd, with "." and "..".
/// The fd offset is the byte position of the next entry in the directory.
/// Records are built in a kernel buffer and copied out afterwards, so the
/// user buffer is never written while the directory is being read.
pub fn getdents64(fd: u64, buf_va: u64, count: u64) u64 {
    const pcb = proc() orelse return err(EFAULT);
    const fe = fdFile(pcb, fd) orelse return err(EBADF);
    defer file.put(fe);
    if (fe.kind != .ext2 or !isDirInode(fe.inode)) return err(ENOTDIR);
    const cap: usize = @intCast(@min(count, DENTS_CHUNK));
    if (cap < 24) return err(EINVAL);
    const at = fe.offset32() orelse return 0; // past any directory's end
    var kbuf: [DENTS_CHUNK]u8 = undefined;
    var sink = DentSink{ .out = &kbuf, .cap = cap };
    const next = ext2.iterDir(fe.inode, at, &sink) orelse return err(EIO);
    if (sink.used == 0 and next < dirSize(fe.inode)) return err(EINVAL); // the next entry doesn't fit
    if (!usercopy.copyToUser(buf_va, kbuf[0..sink.used])) return err(EFAULT);
    fe.offset = next;
    return sink.used;
}

/// d_type from the inode, for a directory whose entries carry no type (a
/// filesystem made without the filetype feature). Programs that walk trees
/// by d_type alone would otherwise see nothing they recognise.
fn dtypeOfInode(inum: u32) u8 {
    const ino = ext2_inode.readInode(inum) orelse return DT_UNKNOWN;
    return @truncate((ino.mode >> 12) & 0xF);
}

fn dirSize(inum: u32) u64 {
    const ino = ext2_inode.readInode(inum) orelse return 0;
    return ext2_inode.fileSize(&ino);
}

/// The user path (dirfd, path_va) as a path inside the ext2 root, in
/// `out`: what the calls that change the tree work on. EROFS for a name on
/// another mount.
fn userExt2Path(pcb: *process.PCB, dirfd: u64, path_va: u64, out: *[256]u8, last: Last) PathRead {
    var bufs: Bufs = .{};
    const path = switch (userAtPath(pcb, dirfd, path_va, &bufs, false)) {
        .path => |p| p,
        .fail => |e| return .{ .fail = e },
    };
    return ext2Path(pcb, path, out, last);
}

/// mkdirat(dirfd, path, mode).
pub fn mkdirat(dirfd: u64, path_va: u64) u64 {
    const pcb = proc() orelse return err(EFAULT);
    var rbuf: [256]u8 = undefined;
    const rel = switch (userExt2Path(pcb, dirfd, path_va, &rbuf, .nofollow)) {
        .path => |p| p,
        .fail => |e| return e,
    };
    // Whatever the name is — the root too, which `mkdir -p` starts from —
    // one that exists is EEXIST.
    if (ext2.lookupPath(rel) != null) return err(EEXIST);
    ext2.mkdirAt(rel) catch |e| return errOf(e);
    return 0;
}

/// unlinkat(dirfd, path, flags): rmdir with AT_REMOVEDIR. A symbolic link
/// is removed itself, not what it points at.
pub fn unlinkat(dirfd: u64, path_va: u64, flags: u64) u64 {
    if (flags & ~AT_REMOVEDIR != 0) return err(EINVAL);
    const pcb = proc() orelse return err(EFAULT);
    var rbuf: [256]u8 = undefined;
    const rel = switch (userExt2Path(pcb, dirfd, path_va, &rbuf, .nofollow)) {
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
    var old_rbuf: [256]u8 = undefined;
    var new_rbuf: [256]u8 = undefined;
    const old_rel = switch (userExt2Path(pcb, old_dirfd, old_va, &old_rbuf, .nofollow)) {
        .path => |p| p,
        .fail => |e| return if (e == err(EROFS)) err(EXDEV) else e,
    };
    const new_rel = switch (userExt2Path(pcb, new_dirfd, new_va, &new_rbuf, .nofollow)) {
        .path => |p| p,
        .fail => |e| return if (e == err(EROFS)) err(EXDEV) else e,
    };
    if (flags & RENAME_NOREPLACE != 0 and ext2.lookupPath(new_rel) != null) return err(EEXIST);
    ext2.rename(old_rel, new_rel) catch |e| return errOf(e);
    return 0;
}

/// symlinkat(target, newdirfd, linkpath); symlink is it with AT_FDCWD. The
/// target is kept as given: it need not exist.
pub fn symlinkat(target_va: u64, new_dirfd: u64, link_va: u64) u64 {
    const pcb = proc() orelse return err(EFAULT);
    var target_buf: [256]u8 = undefined;
    const target = switch (readPath(target_va, &target_buf, false)) {
        .path => |p| p,
        .fail => |e| return e,
    };
    var rbuf: [256]u8 = undefined;
    const rel = switch (userExt2Path(pcb, new_dirfd, link_va, &rbuf, .nofollow)) {
        .path => |p| p,
        .fail => |e| return e,
    };
    ext2.symlinkAt(target, rel) catch |e| return errOf(e);
    return 0;
}

/// linkat(olddirfd, old, newdirfd, new, flags); link is it with AT_FDCWD
/// and 0. A link named by `old` is linked itself unless AT_SYMLINK_FOLLOW.
pub fn linkat(old_dirfd: u64, old_va: u64, new_dirfd: u64, new_va: u64, flags: u64) u64 {
    if (flags & ~AT_SYMLINK_FOLLOW != 0) return err(EINVAL);
    const pcb = proc() orelse return err(EFAULT);
    var old_rbuf: [256]u8 = undefined;
    var new_rbuf: [256]u8 = undefined;
    const old_last: Last = if (flags & AT_SYMLINK_FOLLOW != 0) .follow else .nofollow;
    const old_rel = switch (userExt2Path(pcb, old_dirfd, old_va, &old_rbuf, old_last)) {
        .path => |p| p,
        .fail => |e| return if (e == err(EROFS)) err(EXDEV) else e,
    };
    const new_rel = switch (userExt2Path(pcb, new_dirfd, new_va, &new_rbuf, .nofollow)) {
        .path => |p| p,
        .fail => |e| return if (e == err(EROFS)) err(EXDEV) else e,
    };
    ext2.linkAt(old_rel, new_rel) catch |e| return if (e == error.IsDir) err(EPERM) else errOf(e);
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
    return switch (lookupNode(pcb, path, .follow)) {
        .ext2 => 0,
        .missing => err(ENOENT),
        .other => if (pathFacts(pcb, path) != null) 0 else err(ENOENT),
    };
}

/// chdir(path): the cwd of the process, shared by its threads.
pub fn chdir(path_va: u64) u64 {
    const pcb = proc() orelse return err(EFAULT);
    var buf: [256]u8 = undefined;
    const path = switch (readPath(path_va, &buf, false)) {
        .path => |p| p,
        .fail => |e| return e,
    };
    return chdirTo(pcb, path);
}

/// fchdir(fd): chdir to the directory `fd` has open.
pub fn fchdir(fd: u64) u64 {
    const pcb = proc() orelse return err(EFAULT);
    if (fd == AT_FDCWD) return err(EBADF);
    var buf: [256]u8 = undefined;
    const path = switch (atPath(pcb, fd, "", &buf)) {
        .path => |p| p,
        .fail => |e| return e,
    };
    return chdirTo(pcb, path);
}

fn chdirTo(pcb: *process.PCB, path: []const u8) u64 {
    native_fs.changeDir(pcb, path) catch |e| return err(switch (e) {
        error.NotFound => ENOENT,
        error.NotDir => ENOTDIR,
        error.Invalid => ENAMETOOLONG,
    });
    return 0;
}

const UTIME_NOW: i64 = 0x3FFF_FFFF;
const UTIME_OMIT: i64 = 0x3FFF_FFFE;
const Timespec = extern struct { sec: i64, nsec: i64 };

/// utimensat(dirfd, path, times, flags): a file's access and modification
/// times, to the second (ext2 keeps no more). A null `times` is now for
/// both; a null path is the file `dirfd` has open (futimens). The file has
/// to be there: touch goes by ENOENT to create it.
pub fn utimensat(dirfd: u64, path_va: u64, times_va: u64, flags: u64) u64 {
    const pcb = proc() orelse return err(EFAULT);
    const now: u32 = @truncate(@import("../../time/time.zig").now().sec);
    var atime: ?u32 = now;
    var mtime: ?u32 = now;
    if (times_va != 0) {
        var ts: [2]Timespec = undefined;
        if (!usercopy.copyFromUser(std.mem.asBytes(&ts), times_va)) return err(EFAULT);
        const picked = [2]?u32{ pickTime(ts[0], now), pickTime(ts[1], now) };
        atime = picked[0];
        mtime = picked[1];
    }
    const inum: u32 = if (path_va == 0) blk: {
        const f = fdFile(pcb, dirfd) orelse return err(EBADF);
        defer file.put(f);
        if (f.kind != .ext2) return 0;
        break :blk f.inode;
    } else blk: {
        var bufs: Bufs = .{};
        const path = switch (userAtPath(pcb, dirfd, path_va, &bufs, false)) {
            .path => |p| p,
            .fail => |e| return e,
        };
        const last: Last = if (flags & AT_SYMLINK_NOFOLLOW != 0) .nofollow else .follow;
        break :blk switch (lookupNode(pcb, path, last)) {
            .ext2 => |i| i,
            .missing => return err(ENOENT),
            .other => return 0,
        };
    };
    ext2.setTimes(inum, atime, mtime) catch |e| return errOf(e);
    return 0;
}

fn pickTime(ts: Timespec, now: u32) ?u32 {
    if (ts.nsec == UTIME_OMIT) return null;
    if (ts.nsec == UTIME_NOW or ts.sec < 0) return now;
    return @truncate(@as(u64, @intCast(ts.sec)));
}

/// chmod, chown and their kin: there are no owners or permission bits to
/// change, so a file that is there takes any. `path_va` relative to `dirfd`.
pub fn setAttr(dirfd: u64, path_va: u64, last_is_link: bool) u64 {
    const pcb = proc() orelse return err(EFAULT);
    var bufs: Bufs = .{};
    const path = switch (userAtPath(pcb, dirfd, path_va, &bufs, false)) {
        .path => |p| p,
        .fail => |e| return e,
    };
    return switch (lookupNode(pcb, path, if (last_is_link) .nofollow else .follow)) {
        .ext2 => 0,
        .missing => err(ENOENT),
        .other => if (pathFacts(pcb, path) != null) 0 else err(ENOENT),
    };
}

/// fchmod, fchown: setAttr for an open file.
pub fn setAttrFd(fd: u64) u64 {
    const pcb = proc() orelse return err(EFAULT);
    return if (fdOpen(pcb, fd)) 0 else err(EBADF);
}

/// struct statfs.
const Statfs = extern struct {
    type: i64,
    bsize: i64,
    blocks: u64,
    bfree: u64,
    bavail: u64,
    files: u64,
    ffree: u64,
    fsid: [2]i32 = .{ 0, 0 },
    namelen: i64 = 255,
    frsize: i64,
    flags: i64 = 0,
    spare: [4]i64 = .{ 0, 0, 0, 0 },
};
const EXT2_SUPER_MAGIC: i64 = 0xEF53;

fn writeStatfs(buf_va: u64) u64 {
    const u = ext2.usage() orelse return err(EIO);
    const st = Statfs{
        .type = EXT2_SUPER_MAGIC,
        .bsize = u.block_size,
        .blocks = u.blocks,
        .bfree = u.blocks_free,
        .bavail = u.blocks_free,
        .files = u.inodes,
        .ffree = u.inodes_free,
        .frsize = u.block_size,
    };
    if (!usercopy.copyToUser(buf_va, std.mem.asBytes(&st))) return err(EFAULT);
    return 0;
}

/// statfs(path, buf): every path answers for the root file system, the one
/// with blocks to count.
pub fn statfs(path_va: u64, buf_va: u64) u64 {
    const there = setAttr(AT_FDCWD, path_va, false);
    if (there != 0) return there;
    return writeStatfs(buf_va);
}

/// fstatfs(fd, buf).
pub fn fstatfs(fd: u64, buf_va: u64) u64 {
    const there = setAttrFd(fd);
    if (there != 0) return there;
    return writeStatfs(buf_va);
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
        const nr = std.fmt.parseInt(u32, who, 10) catch return null;
        const slot = @import("../../proc/pid_nr.zig").slotOf(nr) orelse return null;
        if (process.procs[slot].state == .zombie) return null;
        break :blk process.leader(&process.procs[slot]);
    };
    return owner.exe_path[0..owner.exe_path_len];
}

/// readlinkat(dirfd, path, buf, size); readlink is it with AT_FDCWD: the
/// target of an ext2 symbolic link or of one of /proc's exe links, cut to
/// `size` with no NUL. EINVAL for a name that is not a link.
pub fn readlinkat(dirfd: u64, path_va: u64, buf_va: u64, size: u64) u64 {
    const want: i32 = @bitCast(@as(u32, @truncate(size)));
    if (want <= 0) return err(EINVAL);
    const pcb = proc() orelse return err(EFAULT);
    var bufs: Bufs = .{};
    const path = switch (userAtPath(pcb, dirfd, path_va, &bufs, false)) {
        .path => |p| p,
        .fail => |e| return e,
    };
    var link_buf: [255]u8 = undefined;
    const target = exeLink(pcb, path) orelse switch (lookupNode(pcb, path, .nofollow)) {
        .ext2 => |inum| ext2_inode.readLink(inum, &link_buf) orelse return err(EINVAL),
        .missing => return err(ENOENT),
        .other => return if (pathFacts(pcb, path) != null) err(EINVAL) else err(ENOENT),
    };
    if (target.len == 0) return err(ENOENT);
    const n = @min(target.len, @as(usize, @intCast(want)));
    if (!usercopy.copyToUser(buf_va, target[0..n])) return err(EFAULT);
    return n;
}

// --- File size, locks, sync --------------------------------------------------

/// ftruncate(fd, length).
pub fn ftruncate(fd: u64, length: u64) u64 {
    const pcb = proc() orelse return err(EFAULT);
    const fe = fdFile(pcb, fd) orelse return err(EBADF);
    defer file.put(fe);
    if (@as(i64, @bitCast(length)) < 0) return err(EINVAL);
    if (fe.kind != .ext2) return err(EINVAL);
    if (length > ext2.maxFileSize()) return err(EFBIG);
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
    const inum = switch (lookupNode(pcb, path, .follow)) {
        .ext2 => |inum| inum,
        .missing => return err(ENOENT),
        .other => return err(EROFS),
    };
    if (length > ext2.maxFileSize()) return err(EFBIG);
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
    if (!fdOpen(pcb, fd)) return err(EBADF);
    const kind = op & ~LOCK_NB;
    if (kind != LOCK_SH and kind != LOCK_EX and kind != LOCK_UN) return err(EINVAL);
    return 0;
}

/// fsync / fdatasync: what a MAP_SHARED mapping dirtied goes to the block
/// cache, then the whole cache to the disk (not just this file's blocks).
/// sync(), syncfs(fd): what the file system holds back goes to the disk.
pub fn sync() u64 {
    ext2.sync();
    return 0;
}

pub fn fsync(fd: u64) u64 {
    const pcb = proc() orelse return err(EFAULT);
    const fe = fdFile(pcb, fd) orelse return err(EBADF);
    defer file.put(fe);
    if (fe.kind == .ext2) {
        _ = vfs.syncCacheFile(fe.inode, false);
        ext2.sync();
    }
    return 0;
}
