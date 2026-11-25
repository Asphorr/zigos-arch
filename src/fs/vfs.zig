// vfs — the filesystem dispatch hub: mount table (longest-prefix path
// resolution), per-process fd operations (open/read/write/close), the
// kernel-context loaders (loadFile/loadFileFresh), and the ext2 page-cache
// read + writeback orchestration (readThroughCache/syncCacheFile/
// flushAllDirty).
//
// Dispatch contract: path operations switch on the mount's FsType, and the
// switches are exhaustive on purpose — adding a filesystem is adding an enum
// variant, after which the compiler names every path dispatch point that
// still needs an arm. An open file carries its operations with it (file.zig's
// Ops; the tables of the kinds made here are below), so a new kind of file
// — one no path names — needs no arm at all.
//
// Error convention: fd ops return VFS_ERR for "bad fd / not permitted" and
// 0 for "nothing transferred" (write may also return an errno encoding —
// see ext2FileWrite); path helpers return null.

const std = @import("std");
const Phys = @import("../util/addr.zig").Phys;
const fat32 = @import("fat32/fat32.zig");
const tarfs = @import("tarfs.zig");
const devfs = @import("devfs.zig");
const procfs = @import("procfs.zig");
const ext2 = @import("ext2/ext2.zig");
const process = @import("../proc/process.zig");
const keyboard = @import("../driver.zig").keyboard;
const vga = @import("../driver.zig").vga;
const pipe = @import("../proc/pipe.zig");
const tty = @import("../tty/tty.zig");
const paging = @import("../mm/paging.zig");
const pmm = @import("../mm/pmm.zig");
const page_cache = @import("../mm/page_cache.zig");
const heap = @import("../mm/heap.zig");
const memmap = @import("../mm/memmap.zig");
const usercopy = @import("../cpu/arch/usercopy.zig");
const errno = @import("../proc/errno.zig");
const file = @import("file.zig");
const File = file.File;
const locks = @import("locks.zig");

pub const O_CREATE: u32 = 0x100;
pub const O_APPEND: u32 = 0x400; // start the fd's offset at file_size so writes append
pub const O_TRUNC: u32 = 0x200; // truncate to zero on open (writers replacing content)

/// fd-op failure sentinel — the u32 the syscall layer treats as -1. Distinct
/// from the errno encodings some arms return (write's ETXTBSY).
const VFS_ERR: u32 = 0xFFFFFFFF;

pub const FsType = enum { tarfs, fat32, devfs, procfs, ext2 };

pub const ResolvedPath = struct {
    fs: FsType,
    path: []const u8, // path within the filesystem (without mount prefix)
};

// --- Mount table ---
//
// Filesystems are addressed via a mount-prefix → fs mapping rather than a
// hardcoded chain of `if (startsWith(p, "/tar/"))` branches scattered through
// resolvePath. The table is small (max 8 entries), statically initialized at
// comptime, and `mount()` is exposed for future runtime registration. Path
// resolution finds the *longest* matching prefix so nested mounts (e.g.
// adding "/tar/lib/" later) resolve to the more specific mount.
//
// Default mounts cover the only filesystems the kernel currently supports.
// Adding a new filesystem (e.g. tmpfs) means: register an FsType variant
// above, an entry here, and a switch arm in `read`/`write`/`close`/`open`.
pub const Mount = struct {
    prefix: []const u8, // includes leading and trailing '/' — e.g. "/tar/"
    fs: FsType,
};

pub const MAX_MOUNTS: usize = 8;

/// Mount slot table. `pub` so procfs (and any future tooling) can iterate
/// without going through findMount's path-based lookup. Writes still go
/// through `mount()` to preserve replace-or-first-free semantics.
pub var mounts: [MAX_MOUNTS]?Mount = blk: {
    var m: [MAX_MOUNTS]?Mount = [_]?Mount{null} ** MAX_MOUNTS;
    // Root mount — ext2 lives at "/". Any path that doesn't match a more
    // specific prefix below falls through to ext2 (longest-prefix-wins in
    // findMount means "/dev/foo" still goes to devfs, "/foo.elf" goes to
    // ext2 with rel="foo.elf").
    m[0] = .{ .prefix = "/", .fs = .ext2 };
    // Legacy tarfs — kept as a fallback during the ext2 migration window
    // so old paths like "/tar/app.elf" don't hard-fail. Will be dropped
    // once every consumer has moved to the root layout.
    m[1] = .{ .prefix = "/tar/", .fs = .tarfs };
    m[2] = .{ .prefix = "/fat/", .fs = .fat32 };
    m[3] = .{ .prefix = "/dev/", .fs = .devfs };
    m[4] = .{ .prefix = "/proc/", .fs = .procfs };
    break :blk m;
};

/// Register a mount. Idempotent: replaces an existing entry with the same
/// prefix, otherwise takes the first free slot. Silently no-ops when the
/// table is full — call sites today are static so this is fine; if a future
/// runtime caller needs error reporting, switch the return type to bool.
pub fn mount(prefix: []const u8, fs: FsType) void {
    for (&mounts) |*slot| {
        if (slot.*) |m| {
            if (std.mem.eql(u8, m.prefix, prefix)) {
                slot.* = .{ .prefix = prefix, .fs = fs };
                return;
            }
        }
    }
    for (&mounts) |*slot| {
        if (slot.* == null) {
            slot.* = .{ .prefix = prefix, .fs = fs };
            return;
        }
    }
}

/// True if `path` is exactly a registered mount's prefix (e.g. "/tar/").
/// Used by sysChdir so that `cd /tar/` succeeds even though the mount root
/// itself doesn't appear as a file inside the fs — `resolvePath` rejects
/// bare-mount inputs because it requires a non-empty path *under* the mount.
pub fn isMountRoot(path: []const u8) bool {
    for (mounts) |m_opt| {
        if (m_opt) |m| if (std.mem.eql(u8, m.prefix, path)) return true;
    }
    return false;
}

/// Find the mount entry whose prefix is the longest prefix of `path`.
/// Returns null if no mount matches — caller treats this as ENOENT.
pub fn findMount(path: []const u8) ?Mount {
    var best: ?Mount = null;
    for (mounts) |m_opt| {
        if (m_opt) |m| {
            if (path.len >= m.prefix.len and std.mem.startsWith(u8, path, m.prefix)) {
                if (best == null or m.prefix.len > best.?.prefix.len) {
                    best = m;
                }
            }
        }
    }
    return best;
}

/// Resolve a path to a filesystem and the path inside it. A relative path
/// starts at the cwd; the mount is the one with the longest matching prefix.
/// Symbolic links on the way are replaced by their targets, the last
/// component's too.
pub fn resolvePath(pcb: *process.PCB, path: []const u8, path_buf: *[256]u8) ?ResolvedPath {
    return resolvePathOpt(pcb, path, path_buf, true);
}

/// resolvePath that leaves a symbolic link in the last component alone: for
/// what acts on the link itself (lstat, unlink, rename, readlink).
pub fn resolvePathNoFollow(pcb: *process.PCB, path: []const u8, path_buf: *[256]u8) ?ResolvedPath {
    return resolvePathOpt(pcb, path, path_buf, false);
}

fn resolvePathOpt(pcb: *process.PCB, path: []const u8, path_buf: *[256]u8, follow_last: bool) ?ResolvedPath {
    if (path.len == 0) return null;

    // The absolute form, in path_buf.
    var n: usize = 0;
    if (path[0] == '/') {
        if (path.len > path_buf.len) return null;
        moveBytes(path_buf[0..path.len], path);
        n = path.len;
    } else {
        var cwd_copy: [256]u8 = undefined;
        const cwd = cwd_copy[0..pcb.cwd_len];
        @memcpy(cwd, pcb.cwd[0..pcb.cwd_len]);
        if (cwd.len == 0) return null;
        const sep: usize = if (cwd[cwd.len - 1] == '/') 0 else 1;
        if (cwd.len + sep + path.len > path_buf.len) return null;
        moveBytes(path_buf[cwd.len + sep ..][0..path.len], path);
        @memcpy(path_buf[0..cwd.len], cwd);
        if (sep == 1) path_buf[cwd.len] = '/';
        n = cwd.len + sep + path.len;
    }

    n = expandLinks(path_buf, n, follow_last) orelse return null;
    const m = findMount(path_buf[0..n]) orelse return null;
    // Empty rel (the mount root itself, e.g. "/dev/") is allowed — caller
    // distinguishes; `open` will refuse, but `readdir` lists.
    const rel_len = n - m.prefix.len;
    std.mem.copyForwards(u8, path_buf[0..rel_len], path_buf[m.prefix.len..n]);
    return .{ .fs = m.fs, .path = path_buf[0..rel_len] };
}

/// Copy `src` to `dst`, which may overlap it either way.
fn moveBytes(dst: []u8, src: []const u8) void {
    if (@intFromPtr(dst.ptr) <= @intFromPtr(src.ptr)) {
        std.mem.copyForwards(u8, dst, src);
    } else {
        std.mem.copyBackwards(u8, dst, src);
    }
}

/// Most symbolic links one resolution follows (Linux's MAXSYMLINKS).
const MAX_LINK_HOPS: u8 = 40;

/// Replace the symbolic links in the absolute path `buf[0..len]` by their
/// targets, in place — the last component's only with `follow_last`.
/// Returns the new length, or null for a loop of links or a path that
/// outgrows the buffer. A name that doesn't exist ends the expansion: what
/// is there to that point is resolved, the rest is the caller's to miss or
/// create. Links live on ext2; a target may lead to another mount.
fn expandLinks(buf: *[256]u8, len: usize, follow_last: bool) ?usize {
    var n = len;
    var hops: u8 = 0;
    while (true) {
        const m = findMount(buf[0..n]) orelse return n;
        if (m.fs != .ext2) return n;
        const base = m.prefix.len;
        var target_buf: [255]u8 = undefined;
        const link = ext2.findLink(buf[base..n], follow_last, &target_buf) orelse return n;
        hops += 1;
        if (hops > MAX_LINK_HOPS) return null;
        // An absolute target replaces everything up to the link; a relative
        // one starts in the link's directory. What followed the link stays.
        const head: usize = if (link.target[0] == '/') 0 else base + link.start;
        const tail = base + link.end;
        const rest = n - tail;
        const new_tail = head + link.target.len;
        if (new_tail + rest > buf.len) return null;
        moveBytes(buf[new_tail..][0..rest], buf[tail..n]);
        @memcpy(buf[head..][0..link.target.len], link.target);
        n = new_tail + rest;
    }
}

pub fn open(pcb: *process.PCB, name: []const u8) ?u32 {
    return openFlags(pcb, name, 0);
}

pub fn openFlags(pcb: *process.PCB, name: []const u8, flags: u32) ?u32 {
    var path_buf: [256]u8 = undefined;
    const resolved = resolvePath(pcb, name, &path_buf) orelse return null;

    // Claim the fd index and the file object up front, so no fs-side open
    // (or truncate) can run for a process that can't take the file. This
    // ordering is load-bearing for O_TRUNC: the truncate used to run before
    // the fd allocation, so open() on a full table destroyed the file's
    // contents and then failed. A failed open hands both back below.
    const fd_idx = allocFd(pcb) orelse return null;
    const f = file.create(.{}) orelse {
        releaseFd(pcb, fd_idx);
        return null;
    };

    // Each arm resolves the fs-specific open to the file's fields, or null.
    // Exactly one install point below — per-arm fd bookkeeping is how the
    // truncate-before-alloc bug stayed hidden.
    const maybe_init: ?File = switch (resolved.fs) {
        .tarfs => blk: {
            const tar_idx = tarfs.openFile(resolved.path) orelse break :blk null;
            break :blk .{ .kind = .tarfs, .inode = tar_idx, .access = file.READ_WRITE };
        },
        .fat32 => blk: {
            if (fat32.openFile(resolved.path)) |handle| {
                // O_APPEND positions the offset at end-of-file so the first
                // write extends rather than overwrites. fat32.writeFile
                // already handles offset > file_size by allocating new
                // clusters as needed.
                break :blk .{
                    .kind = .fat32,
                    .inode = handle.dir_index,
                    .offset = if (flags & O_APPEND != 0) handle.file_size else 0,
                    .access = file.READ_WRITE,
                    .fat_dir_cluster = handle.dir_cluster,
                };
            }
            // Not found — create if O_CREATE flag set.
            if (flags & O_CREATE != 0) {
                if (fat32.createFile(resolved.path)) |handle| {
                    break :blk .{
                        .kind = .fat32,
                        .inode = handle.dir_index,
                        .access = file.READ_WRITE,
                        .fat_dir_cluster = handle.dir_cluster,
                    };
                }
            }
            break :blk null;
        },
        .devfs => blk: {
            const dev_idx = devfs.openFile(resolved.path) orelse break :blk null;
            break :blk .{ .kind = .devfs, .inode = dev_idx, .access = file.READ_WRITE };
        },
        .procfs => blk: {
            const inode = procfs.openFile(resolved.path) orelse break :blk null;
            break :blk .{ .kind = .procfs, .inode = inode, .access = file.READ };
        },
        .ext2 => blk: {
            const append = flags & O_APPEND != 0;
            // The inode is held from here to the file's release
            // (ext2Release), so an unlink leaves it for this file to use.
            if (ext2.openHeld(resolved.path)) |handle| {
                // O_TRUNC on an existing file: free all data + indirect-tree
                // blocks and reset size to 0. The next writeFile re-allocates.
                // Safe to do here — with the fd and the file already claimed,
                // nothing after this point can fail and turn the open into a
                // destructive no-op.
                if (flags & O_TRUNC != 0) _ = ext2.truncate(handle.inum);
                // An appending file's offset starts at the end as well, for
                // what reads it before the first write.
                const size: u64 = if (flags & O_TRUNC != 0) 0 else handle.file_size;
                break :blk .{
                    .kind = .ext2,
                    .inode = handle.inum,
                    .offset = if (append) size else 0,
                    .access = file.READ_WRITE,
                    .append = append,
                };
            }
            // Not found — create if O_CREATE flag set.
            if (flags & O_CREATE != 0) {
                if (ext2.createHeld(resolved.path)) |handle| {
                    break :blk .{ .kind = .ext2, .inode = handle.inum, .access = file.READ_WRITE, .append = append };
                }
            }
            break :blk null;
        },
    };
    const init = maybe_init orelse {
        file.put(f); // nothing held yet: the default ops release nothing
        releaseFd(pcb, fd_idx);
        return null;
    };
    setUp(f, init);
    file.install(pcb, fd_idx, f, false);
    return @intCast(fd_idx);
}

/// Give a file file.create made its fields and its kind's operations.
fn setUp(f: *File, init: File) void {
    f.* = init;
    f.refs = 1;
    f.static = false;
    f.ops = opsFor(init.kind);
}

/// A new file of `init`'s kind with its operations set, one reference held
/// by the caller. Null when memory is out.
pub fn newFile(init: File) ?*File {
    const f = file.create(.{}) orelse return null;
    setUp(f, init);
    return f;
}

/// A new file in the reserved descriptor `fd_idx`. On failure the
/// descriptor is handed back and nothing was created.
pub fn installNew(pcb: *process.PCB, fd_idx: usize, init: File, cloexec: bool) bool {
    const f = newFile(init) orelse {
        releaseFd(pcb, fd_idx);
        return false;
    };
    file.install(pcb, fd_idx, f, cloexec);
    return true;
}

/// Open a directory for getdents-style enumeration (ext2 only — the writable
/// root fs). Returns an fd whose file's `.inode` is the directory's inum and
/// `.kind == .ext2`. ext2.openFile rejects non-regular files, so a Linux
/// binary's openat(O_DIRECTORY) falls back to this when the regular-file open
/// path returns null. No "is-dir" bit is stored — getdents64 / fstat re-read
/// the inode to learn the type.
pub fn openDir(pcb: *process.PCB, name: []const u8) ?u32 {
    var path_buf: [256]u8 = undefined;
    const resolved = resolvePath(pcb, name, &path_buf) orelse return null;
    if (resolved.fs != .ext2) return null;
    const fd_idx = allocFd(pcb) orelse return null;
    const dir_inum = ext2.openDirHeld(resolved.path) orelse {
        releaseFd(pcb, fd_idx);
        return null;
    };
    if (!installNew(pcb, fd_idx, .{ .kind = .ext2, .inode = dir_inum, .access = file.READ }, false)) {
        ext2.release(dir_inum);
        return null;
    }
    return @intCast(fd_idx);
}

/// Shared stat shape (file_size / is_directory / times) used by the Linux
/// personality's newfstatat to reshape into a Linux `struct stat`.
pub const StatInfo = extern struct {
    file_size: u32,
    is_directory: u32,
    create_time: u32,
    modify_time: u32,
};

/// Path-based stat for the Linux personality (ext2 root fs only — where
/// unmodified Linux binaries actually operate). Fills `out`; caller reshapes.
pub fn statPath(pcb: *process.PCB, name: []const u8, out: *StatInfo) bool {
    var path_buf: [256]u8 = undefined;
    const resolved = resolvePath(pcb, name, &path_buf) orelse return false;
    if (resolved.fs != .ext2) return false;
    return ext2.getFileStat(resolved.path, out);
}

/// Rebuild the fat32 handle a file describes. read/write/close all need the
/// same reconstruction; one definition keeps the dir-cluster default ("0
/// means root" — see File.fat_dir_cluster) in a single place. Null when the
/// offset is past what fat32 counts.
fn fatHandle(f: *const File) ?fat32.Handle {
    const dc = if (f.fat_dir_cluster != 0) f.fat_dir_cluster else fat32.root_cluster;
    return .{
        .dir_cluster = dc,
        .dir_index = f.inode,
        .first_cluster = fat32.getFirstClusterAt(dc, f.inode),
        .file_size = fat32.getFileSizeAt(dc, f.inode),
        .current_offset = f.offset32() orelse return null,
    };
}

/// Read from descriptor `fd` of `pcb`'s table at the file's offset.
pub fn read(pcb: *process.PCB, fd: u32, buf: [*]u8, count: u32) u32 {
    const f = file.get(pcb, fd) orelse return VFS_ERR;
    defer file.put(f);
    return f.ops.read(f, pcb, buf, count);
}

// --- What each kind of file does ---------------------------------------------
//
// One Ops table per kind the file systems make; opsFor maps a kind to its
// table. A new kind of file brings its own table and needs no arm here.

pub fn opsFor(kind: process.FsType) *const file.Ops {
    return switch (kind) {
        .console => &console_ops,
        .fat32 => &fat_ops,
        .tarfs => &tar_ops,
        .pipe => &pipe_ops,
        .devfs => &dev_ops,
        .procfs => &proc_ops,
        .ext2 => &ext2_ops,
        .tcp_sock => &tcp_ops,
        .tcp_listener => &listener_ops,
        // Made by file.create with the table of their object.
        .socket, .epoll, .eventfd, .tty, .lproc => unreachable,
    };
}

pub const console_ops: file.Ops = .{ .read = consoleRead, .write = consoleWrite };
const fat_ops: file.Ops = .{ .read = fatRead, .write = fatWrite, .release = fatRelease, .release_sleeps = true };
const tar_ops: file.Ops = .{ .read = tarRead };
const pipe_ops: file.Ops = .{ .read = pipeRead, .write = pipeWrite, .release = pipeRelease };
const dev_ops: file.Ops = .{ .read = devRead, .write = devWrite };
const proc_ops: file.Ops = .{ .read = procRead };
const ext2_ops: file.Ops = .{ .read = ext2Read, .write = ext2FileWrite, .release = ext2Release, .release_sleeps = true };
const tcp_ops: file.Ops = .{ .read = tcpRead, .write = tcpWrite, .release = tcpRelease, .release_sleeps = true };
const listener_ops: file.Ops = .{ .release = listenerRelease };

fn consoleRead(f: *File, pcb: *process.PCB, buf: [*]u8, count: u32) u32 {
    if (f.access != file.READ) return 0;
    // Reads from the focused window's per-window event queue
    // (ui/events.zig). Lazy import to keep vfs ↔ desktop one-way.
    const desktop = @import("../ui/desktop.zig");
    const cur: u8 = @intCast(pcb.tgid);
    var bytes_read: u32 = 0;
    while (bytes_read < count) {
        if (desktop.popCharEvent(cur)) |ch| {
            buf[bytes_read] = ch;
            bytes_read += 1;
        } else break;
    }
    return bytes_read;
}

fn consoleWrite(f: *File, _: *process.PCB, buf: [*]const u8, count: u32) u32 {
    if (f.access == file.READ) return 0;
    // Mirrored to serial with an [app] prefix so kernel-side traces can
    // correlate user output with kernel events. In pieces: the formatters'
    // buffers are fixed and a write may be any length. serial.write holds
    // its lock with interrupts off, where a fault on the caller's page is
    // fatal: user memory goes out as a kernel copy.
    const serial = @import("../debug/serial.zig");
    serial.write("[app] ");
    const src_va = @intFromPtr(buf);
    const user = memmap.userDataRangeOk(src_va, count);
    var chunk: [256]u8 = undefined;
    var done: u32 = 0;
    while (done < count) {
        const n: u32 = @min(count - done, chunk.len);
        var part: []const u8 = buf[done..][0..n];
        if (user) {
            if (!usercopy.copyFromUser(chunk[0..n], src_va + done)) break;
            part = chunk[0..n];
        }
        vga.print("{s}", .{part});
        serial.write(part);
        done += n;
    }
    return count;
}

fn fatRead(f: *File, _: *process.PCB, buf: [*]u8, count: u32) u32 {
    const handle = fatHandle(f) orelse return 0;
    var new_cluster: u32 = 0;
    var new_off: u32 = 0;
    const bytes_read = fat32.readFileAt(handle, buf, count, f.fat_cluster, f.fat_cluster_off, &new_cluster, &new_off);
    f.offset += bytes_read;
    f.fat_cluster = new_cluster;
    f.fat_cluster_off = new_off;
    return @intCast(bytes_read);
}

fn fatWrite(f: *File, _: *process.PCB, buf: [*]const u8, count: u32) u32 {
    var handle = fatHandle(f) orelse return 0;
    const bytes_written = fat32.writeFile(&handle, buf, count);
    f.offset += bytes_written;
    return @intCast(bytes_written);
}

fn fatRelease(f: *File) void {
    if (fatHandle(f)) |h| fat32.closeFile(h);
}

fn tarRead(f: *File, _: *process.PCB, buf: [*]u8, count: u32) u32 {
    const off = f.offset32() orelse return 0;
    const bytes_read = tarfs.readAt(f.inode, off, buf, count);
    f.offset = @as(u64, off) + bytes_read;
    return bytes_read;
}

// A call a signal cut short before a byte moved: a Linux caller gets EINTR
// (its layer runs the call again or ends it so); a native one gets no bytes,
// as it always has. A write with no reader left is EPIPE to a Linux caller.
fn pipeRead(f: *File, pcb: *process.PCB, buf: [*]u8, count: u32) u32 {
    if (f.access != file.READ) return VFS_ERR;
    // A terminal's keys reach a Linux reader through its line discipline; a
    // native one takes them as the window sends them.
    if (f.tty != tty.NONE and pcb.personality == .linux) {
        var line: [256]u8 = undefined;
        switch (tty.read(f.tty, line[0..@min(count, line.len)], f.nonblock)) {
            .bytes => |n| {
                @memcpy(buf[0..n], line[0..n]);
                return @intCast(n);
            },
            .interrupted => return errno.err(.EINTR),
            .again => return errno.err(.EAGAIN),
            .io_error => return errno.err(.EIO),
        }
    }
    // O_NONBLOCK is a Linux caller's to set; a native one always waits.
    const wait = !(f.nonblock and pcb.personality == .linux);
    const n = pipe.readOpt(f.pipe_id, buf[0..count], wait);
    if (n == pipe.PIPE_INTR) return if (pcb.personality == .linux) errno.err(.EINTR) else 0;
    if (n == pipe.PIPE_AGAIN) return errno.err(.EAGAIN);
    return @intCast(n);
}

fn pipeWrite(f: *File, pcb: *process.PCB, buf: [*]const u8, count: u32) u32 {
    if (f.access != file.WRITE) return VFS_ERR;
    const wait = !(f.nonblock and pcb.personality == .linux);
    const n = pipe.writeOpt(f.pipe_id, buf[0..count], wait);
    if (n == pipe.PIPE_AGAIN) return errno.err(.EAGAIN);
    if (n == pipe.PIPE_INTR) return if (pcb.personality == .linux) errno.err(.EINTR) else 0;
    if (n == pipe.PIPE_CLOSED) return if (pcb.personality == .linux) errno.err(.EPIPE) else VFS_ERR;
    return @intCast(n);
}

fn pipeRelease(f: *File) void {
    if (f.access == file.READ) pipe.closeReader(f.pipe_id) else pipe.closeWriter(f.pipe_id);
}

fn devRead(f: *File, _: *process.PCB, buf: [*]u8, count: u32) u32 {
    // devfs.read advances the offset itself — kmsg's stream position has
    // to move past bytes that aged out of the ring, which is more than
    // just the count returned.
    var off = f.offset32() orelse return 0;
    const n = devfs.read(f.inode, &off, buf, count);
    f.offset = off;
    return n;
}

fn devWrite(f: *File, _: *process.PCB, buf: [*]const u8, count: u32) u32 {
    const off = f.offset32() orelse return VFS_ERR;
    const n = devfs.write(f.inode, off, buf, count);
    if (n != VFS_ERR) f.offset = @as(u64, off) + n;
    return n;
}

fn procRead(f: *File, _: *process.PCB, buf: [*]u8, count: u32) u32 {
    const off = f.offset32() orelse return 0;
    const n = procfs.read(f.inode, off, buf, count);
    f.offset = @as(u64, off) + n;
    return n;
}

fn ext2Read(f: *File, _: *process.PCB, buf: [*]u8, count: u32) u32 {
    if (!f.readable()) return errno.err(.EBADF);
    // Through the unified page cache (Slice 3b): a page read here is the
    // SAME physical frame a later mmap of this file maps, and vice versa.
    // Falls back to a private uncached read only under frame OOM.
    const off = f.offset;
    const n = readThroughCache(f.inode, off, buf, count);
    f.offset = off + n;
    return n;
}

fn ext2FileWrite(f: *File, _: *process.PCB, buf: [*]const u8, count: u32) u32 {
    if (!f.writable()) return errno.err(.EBADF);
    // ETXTBSY: refuse to overwrite the text image of a live process.
    // This is the choke-point the fuzzer hit — fwrite-ing into its own
    // /bin/redteam.elf while running. Inode-keyed, so the //bin//…
    // path alias is covered too. (2026-06-04)
    if (process.isTextBusy(f.inode)) return errno.err(.ETXTBSY);
    var handle = ext2.Handle{
        .inum = f.inode,
        .file_size = 0, // refreshed by writeFile
        .current_offset = f.offset,
        .append = f.append,
    };
    const bytes_written = ext2Write(&handle, buf, count);
    // The handle's offset is where the write ended, wherever an appending
    // one began.
    if (bytes_written < errno.ERR_SENTINEL_BASE and bytes_written > 0) f.offset = handle.current_offset;
    return bytes_written;
}

/// Every ext2 file holds its inode (ext2.openHeld and kin); the last holder
/// of one that was unlinked meanwhile frees it.
fn ext2Release(f: *File) void {
    ext2.release(f.inode);
}

fn tcpRead(f: *File, _: *process.PCB, buf: [*]u8, count: u32) u32 {
    // Non-blocking read on the conn ring. Pollers handle blocking
    // via OP_POLL; raw read() returns 0 when there's nothing yet
    // (mirrors sys#72 net_tcp_recv semantics).
    const net = @import("../net/net.zig");
    net.poll();
    return @intCast(net.tcpRecv(@intCast(f.inode), buf[0..count]));
}

fn tcpWrite(f: *File, _: *process.PCB, buf: [*]const u8, count: u32) u32 {
    const net = @import("../net/net.zig");
    if (!net.tcpSend(@intCast(f.inode), buf[0..count])) return VFS_ERR;
    return count;
}

fn tcpRelease(f: *File) void {
    @import("../net/net.zig").tcpClose(@intCast(f.inode));
}

fn listenerRelease(f: *File) void {
    @import("../net/net.zig").tcpUnlisten(@intCast(f.inode));
}

/// Demand-fill one page for the unified page cache: read up to one page (4 KiB)
/// at absolute byte `offset` from ext2 inode `inode` into `buf`, WITHOUT an fd
/// or File — a file mmap can outlive the fd that created it. Returns the
/// number of bytes read (clipped at EOF; the caller zero-fills the tail). ext2
/// only: sysMmap routes only ext2 fds through the cache, so this is the only
/// backing store the page-cache fault path needs today.
pub fn fillCachePage(inode: u32, offset: u64, buf: [*]u8) u32 {
    const handle = ext2.Handle{ .inum = inode, .file_size = 0, .current_offset = offset };
    return @intCast(ext2.readFile(handle, buf, 0x1000));
}

/// The page of ext2 file `inum` at `page_off` read into the caller's frame
/// `pf` (zero past the file's end) and published in the page cache. The
/// mount lock is held from the read to the publish, so no write to the file
/// falls between them: a fill under a steady writer is not refused as stale
/// time after time. May sleep; touches no user memory.
pub fn fillAndPublishCachePage(inum: u32, page_off: u64, pf: Phys) page_cache.Inserted {
    const file_id = page_cache.ext2FileId(inum);
    const dst = pf.toVirt().ptr([*]u8);
    ext2.lockMount();
    defer ext2.unlockMount();
    const gen = page_cache.fillBegin(file_id);
    const got: usize = @min(fillCachePage(inum, page_off, dst), 0x1000);
    if (got < 0x1000) @memset(dst[got..0x1000], 0);
    return page_cache.insertFilled(file_id, page_off, pf, gen);
}

/// Read up to `count` bytes from ext2 inode `inum` at byte `offset` into user
/// `buf`, THROUGH the unified page cache — the read() half of the cache
/// unification (Slice 3b). Each touched page is pinned on a hit, or read into a
/// private frame and published on a miss, so a page pulled in by read() is the
/// same physical frame a later mmap of this file maps (and vice versa). Mirrors
/// faultInCachePage's hit-or-fill, but copies to the user buffer instead of
/// mapping. Returns bytes read, clipped at EOF exactly like readInodeBytes; the
/// caller advances the fd offset by the return value.
///
/// The per-page copy is deliberately two-step: frame → kstack scratch while
/// holding the cache reference (kernel-to-kernel, so eviction can't free the
/// page and the copy can't fault-kill), then scratch → user AFTER dropping the
/// reference (so a malformed user buffer that #PFs can't leak the frame's
/// refcount). The 64 KB kstack swallows the 4 KB scratch with room to spare.
pub fn readThroughCache(inum: u32, offset: u64, buf: [*]u8, count: u32) u32 {
    if (count == 0) return 0;
    // Only REGULAR-file data rides the page cache — it's the sole thing the
    // write/truncate/free invalidation (Slice 3a) and the mmap path cover.
    // Directories, symlinks, devices (and an unreadable inode) bypass the cache
    // and read straight through, exactly as before, so e.g. a directory mutation
    // (which doesn't touch the page cache) can never serve stale dirents.
    const info = ext2.cacheReadInfo(inum);
    if (!info.is_reg)
        return @intCast(ext2.readFile(.{ .inum = inum, .file_size = 0, .current_offset = offset }, buf, count));
    // EOF clip from the inode's current size — the same source readInodeBytes
    // uses, so we stop where the old path did and never surface a cached page's
    // zero-filled past-EOF tail as data. info.size is NOT u32-bounded (ext2
    // LARGE_FILE reaches 2^48), so the `@as(u64, count)` is load-bearing — it
    // clamps want to count (<= u32max). Don't "simplify" it to a bare `count`.
    if (offset >= info.size) return 0;
    const want: u64 = @min(@as(u64, count), info.size - offset);

    const file_id = page_cache.ext2FileId(inum);
    var scratch: [0x1000]u8 align(8) = undefined;
    var done: u64 = 0;
    while (done < want) {
        const cur = offset + done;
        const page_off = cur & ~@as(u64, 0xFFF);
        const in_page: u64 = cur & 0xFFF;
        const chunk: u64 = @min(@as(u64, 0x1000) - in_page, want - done);
        const ip: usize = @intCast(in_page);
        const ck: usize = @intCast(chunk);
        const dst_off: usize = @intCast(done);

        const frame = page_cache.pin(file_id, page_off) orelse blk: {
            // Miss: fill a PRIVATE frame with NO cache lock held, then
            // publish it atomically.
            const pf = pmm.allocFrameUser() orelse {
                // Out of frames: finish the remainder with a direct uncached
                // read so the call still makes forward progress, then stop.
                const nread: u64 = @intCast(ext2.readFile(.{ .inum = inum, .file_size = 0, .current_offset = cur }, buf + dst_off, @intCast(want - done)));
                return @intCast(done + nread);
            };
            break :blk fillAndPublishCachePage(inum, page_off, pf).frame;
        };

        // frame -> kstack scratch, under the reference (cannot fault-kill).
        const src = frame.toVirt().ptr([*]const u8);
        @memcpy(scratch[0..ck], src[ip .. ip + ck]);
        pmm.releaseFrame(frame); // drop the pin / insertFilled ref BEFORE the user copy

        // scratch -> user (no cache ref held; a faulting user page is safe now).
        // Like the existing readInodeBytes path this user write isn't SMAP-
        // bracketed — it rides the syscall-context AC discipline, same as before.
        @memcpy((buf + dst_off)[0..ck], scratch[0..ck]);
        done += chunk;
    }
    return @intCast(done);
}

/// Diagnostics: each cached page page_cache found changed, beside its disk
/// copy — what differs, who freed the frame last, who maps it now.
pub fn reportCacheCorruption() void {
    const serial = @import("../debug/serial.zig");
    const symbols = @import("../debug/symbols.zig");
    while (page_cache.takeCorrupt()) |c| {
        defer if (c.pinned) pmm.releaseFrame(c.frame);
        const inum: u32 = @truncate(c.file_id);
        const fp = c.frame.raw();
        serial.print("[pc-verify] inode {d} off 0x{X} frame 0x{X}, refs now {d}\n", .{ inum, c.page_off, fp, pmm.frameRefCount(c.frame) });
        if (!c.pinned) continue;
        const tmp = pmm.allocFrame() orelse continue;
        defer pmm.freeFrame(tmp);
        const d = tmp.toVirt().ptr([*]u8);
        const n = @min(fillCachePage(inum, c.page_off, d), 0x1000);
        if (n < 0x1000) @memset(d[n..0x1000], 0);
        const disk = tmp.toVirt().ptr([*]const u64);
        const mem = c.frame.toVirt().ptr([*]const u64);
        var bad: u32 = 0;
        var first: usize = 512;
        var last: usize = 0;
        for (0..512) |j| {
            if (mem[j] == disk[j]) continue;
            bad += 1;
            if (first == 512) first = j;
            last = j;
        }
        serial.print("[pc-verify]   {d}/512 qwords differ from disk ({d} bytes read)", .{ bad, n });
        if (bad > 0) serial.print(", +0x{X}..+0x{X}", .{ first * 8, last * 8 + 8 });
        serial.print("\n", .{});
        var shown: u32 = 0;
        for (0..512) |j| {
            if (mem[j] == disk[j]) continue;
            serial.print("[pc-verify]   +0x{X:0>3}: now {X:0>16} disk {X:0>16}\n", .{ j * 8, mem[j], disk[j] });
            shown += 1;
            if (shown == 12) break;
        }
        if (bad > 0) {
            const pat = mem[first] ^ pmm.QUAR_MAGIC;
            if (pat & 0xFFF == 0 and pat < (1 << 36))
                serial.print("[pc-verify]   holds the quarantine fill of frame 0x{X}: freed while cached\n", .{pat});
        }
        if (@import("../debug/kdbg.zig").pmmFindLastFree(fp)) |ev| {
            serial.print("[pc-verify]   last freed by ", .{});
            if (symbols.resolveKernel(ev.caller_ra)) |r| serial.print("{s}+0x{X}", .{ r.name, r.offset }) else serial.print("0x{X}", .{ev.caller_ra});
            serial.print(" tsc=0x{X}\n", .{ev.tsc});
        } else {
            serial.print("[pc-verify]   no free of this frame in the ring\n", .{});
        }
        @import("../mm/vmm.zig").reportUafFrame(fp);
    }
}

/// Write one pinned dirty page of ext2 inode `inum` back and drop the pin;
/// `size` is the file's. With `clear`, a page no mapping holds any more
/// rejoins the evictable pool — or leaves the cache when it lies wholly past
/// EOF: nothing of it reaches the disk, and its bytes must not come back if
/// the file later grows over them. True if the page was written.
///
/// A page something still maps stays dirty and comes round again, so it is
/// written only when its bytes differ from the last ones written, going by
/// their checksum. A page nothing maps is about to be clean: it is written
/// whatever the checksum says, so a clean page never rests on it.
///
/// What goes to the disk is a copy of the page, and the checksum kept is
/// the copy's. The page turns clean only if it was written whole and, with
/// its last mapping gone, still holds those bytes: a store that landed
/// after the copy was taken keeps it dirty for the next flush.
fn flushDirtyPage(inum: u32, size: u64, page_off: u64, frame: Phys, clear: bool) bool {
    const file_id = page_cache.ext2FileId(inum);
    if (page_off >= size) {
        pmm.releaseFrame(frame); // the writeback pin, before the refcount-gated drop
        if (clear) _ = page_cache.dropIfCacheOnly(file_id, page_off);
        return false;
    }
    // More than the cache's reference and this pin: a mapping (or another
    // flush, which leaves the page to the next pass too).
    if (pmm.frameRefCount(frame) > 2 and page_cache.flushedAs(file_id, page_off, frame, page_cache.sumOf(frame))) {
        pmm.releaseFrame(frame);
        return false;
    }
    var copy: [0x1000]u8 align(8) = undefined;
    @memcpy(&copy, frame.toVirt().ptr([*]const u8)[0..0x1000]);
    const sum = page_cache.sumOfCopy(&copy);
    const want: u32 = @intCast(@min(@as(u64, 0x1000), size - page_off));
    const written = ext2.writebackPage(inum, page_off, frame, &copy) == want;
    if (written) page_cache.noteFlushed(file_id, page_off, frame, sum);
    pmm.releaseFrame(frame); // the writeback pin, before the refcount-gated clear
    if (clear and written) _ = page_cache.clearDirtyIfWritten(file_id, page_off, frame, sum);
    return written;
}

/// Write every dirty page of ext2 inode `inum` back to disk — the orchestration
/// half of MAP_SHARED writeback (Slice 3c). Drives page_cache.takeDirtyBatch
/// (which PINS each dirty page so the lockless writeback I/O can't race eviction
/// or a concurrent unmap freeing the frame) → ext2.writebackPage → releaseFrame,
/// looping on a strictly-increasing offset cursor so it always terminates.
///
/// `clear` clears the dirty flag on pages that are now cache-only (no remaining
/// writable mapper): munmap/teardown pass true (the mapping is gone, so the page
/// returns to the evictable pool); msync passes false (the mapping stays live —
/// its still-writable PTE means future writes won't re-fault to re-mark the page,
/// so the bit must stay set or those writes would never be flushed by a later
/// msync). The clear runs AFTER releaseFrame so clearDirtyIfCacheOnly's
/// refcount==1 test sees the true mapper count, not our transient writeback pin.
///
/// MUST be called with NO page_cache/as_lock spinlock held: writebackPage blocks
/// on NVMe I/O. Returns the number of pages written back.
pub fn syncCacheFile(inum: u32, clear: bool) u32 {
    const file_id = page_cache.ext2FileId(inum);
    var batch: [page_cache.DIRTY_BATCH]page_cache.DirtyPage = undefined;
    var off: u64 = 0;
    var written: u32 = 0;
    while (true) {
        const n = page_cache.takeDirtyBatch(file_id, off, &batch);
        if (n == 0) break;
        const size = ext2.cacheReadInfo(inum).size;
        for (batch[0..n]) |dp| {
            if (flushDirtyPage(inum, size, dp.page_off, dp.frame, clear)) written += 1;
        }
        off = batch[n - 1].page_off + page_cache.PAGE_SIZE; // advance cursor → guarantees termination
    }
    // Disk-truth trace for MAP_SHARED writeback (Slice 3c). Silent on the common
    // case (no dirty shared pages → written==0): only msync()/munmap() of a
    // writable file mapping reaches here with work to do, so this never fires on
    // ordinary read/write/exec workloads.
    if (written > 0)
        @import("../debug/serial.zig").print("[3c] writeback inum={d} pages={d} clear={}\n", .{ inum, written, clear });
    return written;
}

/// Background page-cache writeback (Slice 3d-2's worker half) — the global
/// analogue of syncCacheFile. Flushes EVERY dirty cache page to disk: the
/// pgflushd kernel thread (main.zig) calls this on a timer so MAP_SHARED writes
/// persist to disk periodically without an explicit msync — a live mapping's
/// pages are looked at every pass (refcount>1 keeps them dirty) and written
/// when their bytes changed (flushDirtyPage), bounding
/// crash / bare-exit data loss to one flush interval instead of all of it — and
/// so any orphaned refcount==1 dirty page is written back and then made
/// reclaimable. (Full bare-exit persistence of the final pre-exit window needs
/// the OOM-safe teardown change deferred to Slice 3d-2b.)
///
/// Same lock discipline as syncCacheFile: takeNextDirtyGlobal PINS each page
/// under page_cache.lock, then we drop the lock, do the blocking ext2 writeback,
/// releaseFrame, and refcount-gate the dirty clear. clearDirtyIfCacheOnly clears
/// only refcount==1 pages, so a still-live mapper's page stays dirty and is
/// looked at again next pass (periodic durability) while an orphaned page is cleaned
/// and becomes evictable. MUST run with NO spinlock held (writebackPage blocks on
/// NVMe I/O) — only from the daemon thread, never a syscall under a lock. Returns
/// the number of pages written back.
pub fn flushAllDirty() u32 {
    var cursor: u32 = 0;
    var written: u32 = 0;
    // Size of the file the last page belonged to: neighbours in the pool are
    // mostly one file's.
    var sized_inum: u32 = 0;
    var size: u64 = 0;
    while (page_cache.takeNextDirtyGlobal(cursor)) |dp| {
        cursor = dp.next_idx; // strictly advances -> the pass terminates
        // The cache is ext2-only, so a dirty page is always an ext2 file page; the
        // FILE_ID_EXT2 tag-check is defensive against a future fs that would need
        // its own writeback path.
        if (dp.file_id & page_cache.FILE_ID_EXT2 != 0) {
            const inum: u32 = @intCast(dp.file_id & ~page_cache.FILE_ID_EXT2);
            if (inum != sized_inum) {
                size = ext2.cacheReadInfo(inum).size;
                sized_inum = inum;
            }
            if (flushDirtyPage(inum, size, dp.page_off, dp.frame, true)) written += 1;
        } else {
            pmm.releaseFrame(dp.frame);
            _ = page_cache.clearDirtyIfCacheOnly(dp.file_id, dp.page_off);
        }
    }
    if (written > 0)
        @import("../debug/serial.zig").print("[3d] pgflushd wrote {d} dirty page(s)\n", .{written});
    return written;
}

/// Write to descriptor `fd` of `pcb`'s table at the file's offset.
pub fn write(pcb: *process.PCB, fd: u32, buf: [*]const u8, count: u32) u32 {
    const f = file.get(pcb, fd) orelse return VFS_ERR;
    defer file.put(f);
    return f.ops.write(f, pcb, buf, count);
}

/// Write `count` bytes into ext2 inode `inum` at `offset`, leaving every fd
/// offset alone (pwrite and its kin). Refuses a running program's text
/// as write() does.
pub fn writeAt(inum: u32, offset: u64, buf: [*]const u8, count: u32) u32 {
    if (process.isTextBusy(inum)) return @import("../proc/errno.zig").err(.ETXTBSY);
    var handle = ext2.Handle{ .inum = inum, .file_size = 0, .current_offset = offset };
    return ext2Write(&handle, buf, count);
}

/// Most user bytes one ext2.writeFile call takes through the kernel buffer.
const WRITE_BOUNCE: u32 = 64 * 1024;

/// ext2.writeFile for a source that may be user memory. The file system
/// reads its source under the mount lock, where a fault on a user page can't
/// be served (the page may need that same file system), so user bytes go
/// through a kernel buffer first. A write larger than the buffer is several
/// file-system writes: against another writer of the same range it is
/// atomic piece by piece only. Returns the bytes written, or EFAULT's
/// encoding when the source went away before any were.
fn ext2Write(handle: *ext2.Handle, src: [*]const u8, count: u32) u32 {
    const src_va = @intFromPtr(src);
    if (!memmap.userDataRangeOk(src_va, count)) return ext2.writeFile(handle, src, count);

    var small: [0x1000]u8 align(8) = undefined;
    var buf: []u8 = &small;
    const big: ?[*]u8 = if (count > small.len) heap.kmalloc(@min(count, WRITE_BOUNCE)) else null;
    defer if (big) |p| heap.kfree(p);
    if (big) |p| buf = p[0..@min(count, WRITE_BOUNCE)];

    var done: u32 = 0;
    while (done < count) {
        const chunk: u32 = @intCast(@min(count - done, buf.len));
        if (!usercopy.copyFromUser(buf[0..chunk], src_va + done)) {
            return if (done > 0) done else errno.err(.EFAULT);
        }
        const put = ext2.writeFile(handle, buf.ptr, chunk);
        done += put;
        if (put < chunk) break;
    }
    return done;
}

pub fn close(pcb: *process.PCB, fd: u32) u32 {
    if (fd < 3) return VFS_ERR; // can't close stdin/stdout/stderr
    return closeSlot(pcb, fd);
}

/// close() without the guard on 0..2: a Linux process may close and reuse
/// its standard fds.
pub fn closeSlot(pcb: *process.PCB, fd: u32) u32 {
    // The table gives up its reference under fd_lock: of two threads
    // closing one fd of a shared table, only one gets it to drop. The file
    // itself goes when the last sharer (a dup, a fork, a call in flight) does.
    const f = file.take(pcb, fd) orelse return VFS_ERR;
    closedBy(pcb, f);
    file.put(f);
    return 0;
}

/// `pcb`'s process closed a descriptor of `f`: its record locks on the
/// file go, whichever descriptor took them (POSIX).
pub fn closedBy(pcb: *const process.PCB, f: *const File) void {
    if (f.kind == .ext2) locks.closed(pcb.pid_nr, f.inode);
}

pub fn ls() void {
    tarfs.ls();
    fat32.listFiles();
}

// --- Kernel-context name resolution (loadFile / fileSize) -------------------
//
// Both loaders resolve a name the same way: absolute paths dispatch through
// the mount table; bare names walk the legacy fallback chain (ext2 root →
// ext2 /bin → tarfs → fat32). loadFileFresh sizes the file with one and
// reads it with the other, so if the two ever disagreed about WHICH file a
// name means, it would allocate the wrong buffer. That used to be a "keep
// the two paths in lock-step" comment; now the sequence exists once, in
// resolveFirst, and the two only differ in the per-fs operation applied —
// drift is structurally impossible (rule 5, aimed at control flow).

/// Walk the name-resolution sequence and return the first non-null result of
/// `op.run(fs, rel)`. `op` is duck-typed: any struct with
/// `fn run(self, fs: FsType, rel: []const u8) ?R`.
fn resolveFirst(comptime R: type, name: []const u8, op: anytype) ?R {
    // Absolute path → symbolic links replaced, then longest-prefix mount
    // dispatch, one candidate.
    if (name.len > 0 and name[0] == '/') {
        var buf: [256]u8 = undefined;
        if (name.len > buf.len) return null;
        @memcpy(buf[0..name.len], name);
        const n = expandLinks(&buf, name.len, true) orelse return null;
        const m = findMount(buf[0..n]) orelse return null;
        return op.run(m.fs, buf[m.prefix.len..n]);
    }
    // Bare-filename fallback for legacy callers (sysExec passing "cat.elf"
    // unqualified, KERNEL.SYM / BUILD.ID lookups). Resolution order:
    //   1. ext2 root  — for files at `/` like KERNEL.SYM, BUILD.ID
    //   2. ext2 /bin  — for shell-style `cat` → /bin/cat.elf (PATH analogue)
    //   3. tarfs      — legacy fallback during migration
    //   4. fat32      — only matters with /fat/ disk attached
    if (op.run(.ext2, name)) |r| return r;
    var bin_buf: [128]u8 = undefined;
    if (binPath(&bin_buf, name)) |bp| {
        if (op.run(.ext2, bp)) |r| return r;
        // A link in /bin (a busybox applet's name): what it leads to.
        var abs: [256]u8 = undefined;
        abs[0] = '/';
        @memcpy(abs[1..][0..bp.len], bp);
        if (expandLinks(&abs, bp.len + 1, true)) |n| {
            if (findMount(abs[0..n])) |m| {
                if (m.fs == .ext2 and !std.mem.eql(u8, abs[m.prefix.len..n], bp)) {
                    if (op.run(.ext2, abs[m.prefix.len..n])) |r| return r;
                }
            }
        }
    }
    if (op.run(.tarfs, name)) |r| return r;
    return op.run(.fat32, name);
}

/// "bin/" ++ name into `buf`, or null if it doesn't fit.
fn binPath(buf: *[128]u8, name: []const u8) ?[]const u8 {
    const prefix = "bin/";
    if (name.len + prefix.len > buf.len) return null;
    @memcpy(buf[0..prefix.len], prefix);
    @memcpy(buf[prefix.len..][0..name.len], name);
    return buf[0 .. prefix.len + name.len];
}

/// The loadFile operation: read the candidate into `dest`, reporting the ext2
/// inum through `out_inode` from the SAME resolution that read the bytes — so
/// it can never name a different file than the one whose contents landed.
const LoadOp = struct {
    dest: []align(4) u8,
    out_inode: ?*u32,

    fn run(self: @This(), fs: FsType, rel: []const u8) ?usize {
        return switch (fs) {
            .tarfs => tarfs.loadFile(rel, self.dest),
            .ext2 => blk: {
                const r = ext2.loadFileInum(rel, self.dest) orelse break :blk null;
                if (self.out_inode) |p| p.* = r.inum;
                break :blk r.size;
            },
            .fat32 => blk: {
                if (fat32.openFile(rel)) |handle| {
                    const size = handle.file_size;
                    if (size > 0) {
                        const want: u32 = @intCast(@min(@as(u64, size), self.dest.len));
                        const r = fat32.readFile(handle, @ptrCast(self.dest.ptr), want);
                        fat32.closeFile(handle);
                        if (r > 0) break :blk r;
                    } else {
                        fat32.closeFile(handle);
                    }
                }
                break :blk null;
            },
            // devfs/procfs aren't loadable as files (they're streamed) — kernel
            // load callers shouldn't be asking for them. fileSize DOES report
            // their sizes (SizeOp below), so a loadFileFresh of one sizes fine
            // and then fails here — wasteful but unreachable from real callers.
            .devfs, .procfs => null,
        };
    }
};

/// The fileSize operation. ext2/tarfs report u64 sizes (ext2 LARGE_FILE
/// reaches 2^48): a size that doesn't fit the u32 world of fd offsets and
/// loadFileFresh is "no usable size" (null), never a checked-cast panic —
/// the size is fs-image-provided data, and a corrupt image must not be able
/// to crash the kernel (the NVMe LBADS lesson).
const SizeOp = struct {
    fn run(_: @This(), fs: FsType, rel: []const u8) ?u32 {
        return switch (fs) {
            .tarfs => std.math.cast(u32, tarfs.fileSize(rel) orelse return null),
            .ext2 => std.math.cast(u32, ext2.fileSize(rel) orelse return null),
            .fat32 => blk: {
                if (fat32.openFile(rel)) |handle| {
                    const size = handle.file_size;
                    fat32.closeFile(handle);
                    break :blk size;
                }
                break :blk null;
            },
            .devfs => devfs.fileSize(rel),
            .procfs => procfs.fileSize(rel),
        };
    }
};

/// `out_inode`, if non-null, receives the ext2 inode number of the file that
/// was actually read — or 0 if the file came from a non-ext2 mount (tarfs/fat32)
/// or wasn't found. Callers that cache-key on the file (ELF text sharing, Slice
/// 3e) use it; everyone else passes null. Kernel-context load (no PCB, so no
/// cwd) — absolute paths plus the bare-name chain, see resolveFirst.
pub fn loadFile(name: []const u8, dest: []align(4) u8, out_inode: ?*u32) ?usize {
    if (out_inode) |p| p.* = 0; // default: no ext2 cache key
    return resolveFirst(usize, name, LoadOp{ .dest = dest, .out_inode = out_inode });
}

/// Size of the file `name` resolves to, via the SAME candidate sequence
/// loadFile reads through (resolveFirst) — the pairing loadFileFresh relies on.
pub fn fileSize(name: []const u8) ?u32 {
    return resolveFirst(u32, name, SizeOp{});
}

/// An ext2 regular file, for reading through the page cache.
pub const CachedFile = struct { inum: u32, size: u64 };

const CachedOp = struct {
    fn run(_: @This(), fs: FsType, rel: []const u8) ?CachedFile {
        if (fs != .ext2) return null;
        const f = ext2.lookupFile(rel) orelse return null;
        return .{ .inum = f.inum, .size = f.size };
    }
};

/// The ext2 file `name` resolves to, by the sequence loadFile reads through;
/// null when it resolves to another filesystem or to nothing.
pub fn lookupCached(name: []const u8) ?CachedFile {
    return resolveFirst(CachedFile, name, CachedOp{});
}

/// A PMM-allocated file buffer ready to hand to elf_loader.loadAndStart
/// (which takes ownership) or freed by the caller via `pmm.freeRange(phys,
/// fresh.pages)` on cleanup. Use `freeRange` (NOT a per-frame `freeFrame`
/// loop) — the buffer came from `pmm.allocContiguous`, which is the bulk
/// allocator; a per-frame free loop stamps a spurious canary onto every
/// page and produces fake UAF reports at the next allocation.
pub const FreshFile = struct {
    buf: [*]align(4) u8,
    size: usize,
    pages: u32,
    /// ext2 inode of the loaded file, or 0 if it came from a non-ext2 mount.
    /// The ELF loader uses it to cache-share read-only segments (Slice 3e);
    /// 0 makes the loader fall back to the private elf_buf path.
    inode: u32 = 0,
};

/// Architectural replacement for the `staging` pattern: size the file via
/// the directory entry, allocate from PMM (which excludes kernel image and
/// other reserved phys ranges), then read directly into that buffer. No
/// fixed-VA staging, so a growing kernel image can never collide with the
/// load destination — the bug class is impossible by construction.
///
/// Caller owns the returned buffer. Either pass it to
/// elf_loader.loadAndStart (which takes ownership), or call
/// `pmm.freeRange(phys_base, fresh.pages)` to release it. Per-frame
/// `freeFrame` loops are the wrong API pairing — see FreshFile doc.
pub fn loadFileFresh(name: []const u8) ?FreshFile {
    const perf = @import("../debug/perf.zig");
    const serial = @import("../debug/serial.zig");
    const nvme = @import("../driver.zig").nvme;
    // Per-syscall latency attribution — sysExec, sysExecAs, sysFsize, etc.
    // all bottom out here. Brackets the disk read so slow-sc shows the
    // disk-vs-other split instead of just total ms.
    const sp = @import("../debug/syscall_perf.zig").scope(.disk_read);
    defer sp.end();
    const t0 = perf.rdtsc();
    const size = fileSize(name) orelse {
        // [probe] which loadFileFresh early-exit fired — temporary diagnostic
        // for the redteam "can't re-launch its own inode" investigation.
        serial.print("[loadFresh-fail] {s}: fileSize -> null (name unresolvable / inode unreadable / not-regular)\n", .{name});
        return null;
    };
    const t1 = perf.rdtsc();
    if (size == 0) {
        serial.print("[loadFresh-fail] {s}: size == 0\n", .{name});
        return null;
    }
    const pages: u32 = @intCast((@as(usize, size) + 4095) / 4096);
    const phys = pmm.allocContiguous(pages) orelse {
        serial.print("[loadFresh-fail] {s}: allocContiguous({d} pages) -> null  (free={d} frames; fragmentation iff free >> pages)\n", .{ name, pages, pmm.freeFrameCount() });
        return null;
    };
    const t2 = perf.rdtsc();
    // Reach the PMM-allocated buffer through the kernel physmap.
    const buf: [*]align(4) u8 = @ptrFromInt(phys.toVirt().raw());

    // NVMe-stats snapshot — diff'd after loadFile to attribute calls/cycles
    // to this specific load rather than the global counters.
    const io_calls0 = nvme.io_call_count;
    const io_cyc0 = nvme.io_total_cycles;
    const io_wait0 = nvme.io_wait_cycles;
    const io_irq0 = nvme.irq_count;
    nvme.io_max_wait_cycles = 0; // local-max for this load only

    var inode_out: u32 = 0;
    if (loadFile(name, buf[0 .. @as(usize, pages) * 4096], &inode_out)) |got| {
        const t3 = perf.rdtsc();
        const io_calls = nvme.io_call_count - io_calls0;
        const io_cyc = nvme.io_total_cycles - io_cyc0;
        const io_wait = nvme.io_wait_cycles - io_wait0;
        const io_irqs = nvme.irq_count - io_irq0;
        const max_wait = nvme.io_max_wait_cycles;
        const per_call_avg = if (io_calls > 0) (io_cyc / io_calls) else 0;
        const per_wait_avg = if (io_calls > 0) (io_wait / io_calls) else 0;
        serial.print(
            "[vfs.timing] {s}: size={d} pages={d} fileSize={d}M alloc={d}M loadFile={d}M | nvme calls={d} cyc={d}M wait={d}M irqs={d} avg_call={d}c avg_wait={d}c max_wait={d}c\n",
            .{
                name,
                size,
                pages,
                (t1 -% t0) >> 20,
                (t2 -% t1) >> 20,
                (t3 -% t2) >> 20,
                io_calls,
                io_cyc >> 20,
                io_wait >> 20,
                io_irqs,
                per_call_avg,
                per_wait_avg,
                max_wait,
            },
        );
        if (got == size) return .{ .buf = buf, .size = size, .pages = pages, .inode = inode_out };
        serial.print("[loadFresh-fail] {s}: short read got={d} != size={d} (inode={d}) — data blocks unreadable\n", .{ name, got, size, inode_out });
    } else {
        serial.print("[loadFresh-fail] {s}: loadFile -> null (inode/blocks unreadable)\n", .{name});
    }
    pmm.freeRange(phys, @intCast(pages));
    return null;
}

/// Reserve a free fd index. A Linux process's
/// threads share their lead's table, so slots change hands under its
/// fd_lock; a reserved slot is closed to everyone until the caller installs
/// a file (installNew, file.install) or hands it back with releaseFd.
///
/// A Linux process gets the lowest free number, 0 to 2 included: `close(0)`
/// then `open` is how its programs redirect. A native one's standard three
/// are never handed out again (it can't close them either).
pub fn allocFd(pcb: *process.PCB) ?usize {
    return file.reserveFrom(pcb, if (pcb.personality == .linux) 0 else 3);
}

/// Hand back an fd allocFd reserved and nothing was installed into.
pub fn releaseFd(pcb: *process.PCB, fd_idx: usize) void {
    file.unreserve(pcb, fd_idx);
}
