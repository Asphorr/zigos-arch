//! Open files and the per-process table of them.
//!
//! A File is what an open (or pipe, or accept) makes and a file descriptor
//! refers to. dup and fork copy the reference, not the file: the copies
//! share one byte offset and one set of status flags, and what the file
//! holds (a pipe end, a connection) goes back when the last reference does.
//! A call that works on a file holds a reference of its own for its
//! duration (get / put), so a close on another thread of the group can't
//! pull the file from under it.
//!
//! What a kind of file does on read, write and release is its Ops table;
//! vfs.zig has the tables of the kinds the file systems make.

const std = @import("std");
const process = @import("../proc/process.zig");
const heap = @import("../mm/heap.zig");
const config = @import("../config.zig");
const SpinLock = @import("../proc/spinlock.zig").SpinLock;
const locks = @import("locks.zig");

pub const Kind = process.FsType;

/// Failure of an fd operation, as vfs returns it.
pub const ERR: u32 = 0xFFFFFFFF;

pub const Ops = struct {
    /// Up to `count` bytes at the file's offset into `buf`; the offset moves
    /// past them. Bytes read, or ERR / an errno encoding.
    read: *const fn (f: *File, pcb: *process.PCB, buf: [*]u8, count: u32) u32 = denyRead,
    write: *const fn (f: *File, pcb: *process.PCB, buf: [*]const u8, count: u32) u32 = denyWrite,
    /// The last reference is gone: give back what the file holds.
    release: *const fn (f: *File) void = noRelease,
    /// `release` may sleep. A task's teardown can't, and leaves such a file
    /// to the reaper (dropAll, reap).
    release_sleeps: bool = false,
    /// What the file is ready for now, as poll bits (fdpoll.POLL*), asked
    /// by `pcb`'s process. Never sleeps.
    poll: *const fn (f: *File, pcb: *process.PCB) u16 = pollByKind,
    /// A count that moves whenever the file may have become ready for
    /// more: what an edge-triggered watcher compares.
    events: *const fn (f: *File) u32 = eventsByKind,
};

fn pollByKind(f: *File, pcb: *process.PCB) u16 {
    return @import("../cpu/ipc/fdpoll.zig").maskOfFile(f, pcb);
}

fn eventsByKind(f: *File) u32 {
    return @import("../cpu/ipc/fdpoll.zig").eventsOfFile(f);
}

fn denyRead(_: *File, _: *process.PCB, _: [*]u8, _: u32) u32 {
    return ERR;
}

fn denyWrite(_: *File, _: *process.PCB, _: [*]const u8, _: u32) u32 {
    return ERR;
}

fn noRelease(_: *File) void {}

const no_ops: Ops = .{};

/// How the file was opened, as `File.access`.
pub const READ: u8 = 0;
pub const WRITE: u8 = 1;
pub const READ_WRITE: u8 = 2;

pub const File = struct {
    /// (a) Table slots and calls in flight that hold the file.
    refs: u32 = 1,
    kind: Kind = .console,
    ops: *const Ops = &no_ops,
    /// READ, WRITE or READ_WRITE. It also tells a pipe's two ends and the
    /// console's streams apart.
    access: u8 = READ,
    /// O_NONBLOCK, as F_GETFL reports it.
    nonblock: bool = false,
    /// O_APPEND: every write lands at the end of the file.
    append: bool = false,
    /// One of the console streams every process starts with: never freed.
    static: bool = false,
    /// Per kind: the ext2 inode number, a tarfs / devfs / procfs index, a
    /// fat32 directory index, a socket slot.
    inode: u32 = 0,
    pipe_id: u8 = 0xFF,
    /// The terminal this pipe end belongs to (proc/tty.zig), 0xFF for a
    /// file that is not one.
    tty: u8 = 0xFF,
    /// (a) An epoll set refers to this file by address (epoll.zig): the
    /// last reference tells it before the file is freed.
    watched: bool = false,
    /// The object of a kind that has one (a socket, an epoll set, an
    /// eventfd), owned by the file.
    obj: ?*anyopaque = null,
    /// Byte offset of the next read or write, shared by every descriptor on
    /// the file. Sharers that read or write at once race for it, as on any
    /// system without a position lock; each load and store is whole.
    offset: u64 = 0,
    /// fat32: the cluster a sequential read last reached, the byte offset
    /// it is for, and the directory that holds the entry (0 = the root).
    fat_cluster: u32 = 0,
    fat_cluster_off: u32 = 0,
    fat_dir_cluster: u32 = 0,
    /// (p:unreleased_lock) The next file awaiting its release (reap).
    next_unreleased: ?*File = null,

    /// The offset for kinds that count in 32 bits; null past their reach.
    pub fn offset32(self: *const File) ?u32 {
        return std.math.cast(u32, self.offset);
    }

    /// Opened for reading (READ or READ_WRITE).
    pub fn readable(self: *const File) bool {
        return self.access != WRITE;
    }

    /// Opened for writing (WRITE or READ_WRITE).
    pub fn writable(self: *const File) bool {
        return self.access != READ;
    }
};

/// One entry of a process's descriptor table.
pub const Slot = struct {
    file: ?*File = null,
    /// FD_CLOEXEC / O_CLOEXEC: closed by a Linux execve.
    cloexec: bool = false,
    /// Claimed by reserve, its file not installed yet.
    reserved: bool = false,

    pub fn inUse(self: *const Slot) bool {
        return self.file != null or self.reserved;
    }
};

pub const Table = [config.MAX_FDS]Slot;

/// The console's input and output, shared by every table that starts with
/// them.
pub var console_in: File = .{ .static = true, .access = READ, .ops = &@import("vfs.zig").console_ops };
pub var console_out: File = .{ .static = true, .access = WRITE, .ops = &@import("vfs.zig").console_ops };

/// The table a process starts with: stdin, stdout and stderr on the console.
pub fn initialTable() Table {
    var table: Table = [_]Slot{.{}} ** config.MAX_FDS;
    table[0] = .{ .file = &console_in };
    table[1] = .{ .file = &console_out };
    table[2] = .{ .file = &console_out };
    return table;
}

/// A new file with one reference, the caller's. Null when memory is out.
pub fn create(init: File) ?*File {
    const raw = heap.kmallocAligned(@sizeOf(File), @alignOf(File)) orelse return null;
    const f: *File = @ptrCast(@alignCast(raw));
    f.* = init;
    f.refs = 1;
    f.static = false;
    return f;
}

/// One more reference to a file the caller already holds one on, or reads
/// from a table under its lock.
pub fn ref(f: *File) void {
    if (f.static) return;
    _ = @atomicRmw(u32, &f.refs, .Add, 1, .monotonic);
}

/// Drop a reference; the last one releases the file. Task context: a
/// release may sleep.
pub fn put(f: *File) void {
    if (dropRef(f)) {
        f.ops.release(f);
        heap.kfree(@ptrCast(f));
    }
}

/// True when the caller dropped the last reference. No epoll set refers to
/// the file from then on, and the locks it owned (OFD, flock) are gone.
fn dropRef(f: *File) bool {
    if (f.static) return false;
    const before = @atomicRmw(u32, &f.refs, .Sub, 1, .acq_rel);
    if (before == 0) @panic("file: reference dropped twice");
    if (before != 1) return false;
    if (@atomicLoad(bool, &f.watched, .acquire)) @import("../cpu/ipc/epoll.zig").forget(f);
    locks.fileGone(@intFromPtr(f));
    return true;
}

/// A reference for the holder of a bare pointer to `f` (an epoll set),
/// taken under the lock `forget` takes; false when the last one is already
/// gone and the file is on its way out.
pub fn tryRef(f: *File) bool {
    if (f.static) return true;
    var n = @atomicLoad(u32, &f.refs, .monotonic);
    while (n != 0) {
        n = @cmpxchgWeak(u32, &f.refs, n, n + 1, .acq_rel, .monotonic) orelse return true;
    }
    return false;
}

/// The file behind `fd` of `pcb`'s table with a reference for the caller
/// (put it), or null for a closed or reserved descriptor.
pub fn get(pcb: *process.PCB, fd: u64) ?*File {
    if (fd >= pcb.fd_table.len) return null;
    pcb.fd_lock.acquire();
    defer pcb.fd_lock.release();
    const f = pcb.fd_table[@intCast(fd)].file orelse return null;
    ref(f);
    return f;
}

/// Claim the lowest free descriptor from `min` up; install or unreserve it.
pub fn reserveFrom(pcb: *process.PCB, min: usize) ?usize {
    pcb.fd_lock.acquire();
    defer pcb.fd_lock.release();
    var fd = min;
    while (fd < pcb.fd_table.len) : (fd += 1) {
        const s = &pcb.fd_table[fd];
        if (s.inUse()) continue;
        s.* = .{ .reserved = true };
        return fd;
    }
    return null;
}

/// Give a reserved descriptor its file; the table takes the caller's
/// reference.
pub fn install(pcb: *process.PCB, fd: usize, f: *File, cloexec: bool) void {
    pcb.fd_lock.acquire();
    defer pcb.fd_lock.release();
    pcb.fd_table[fd] = .{ .file = f, .cloexec = cloexec };
}

/// Hand back a descriptor reserve claimed and nothing was installed into.
pub fn unreserve(pcb: *process.PCB, fd: usize) void {
    pcb.fd_lock.acquire();
    defer pcb.fd_lock.release();
    if (pcb.fd_table[fd].reserved) pcb.fd_table[fd] = .{};
}

/// Empty descriptor `fd` and hand its file, with the table's reference, to
/// the caller; null if it held none.
pub fn take(pcb: *process.PCB, fd: u64) ?*File {
    if (fd >= pcb.fd_table.len) return null;
    pcb.fd_lock.acquire();
    defer pcb.fd_lock.release();
    const s = &pcb.fd_table[@intCast(fd)];
    const f = s.file orelse return null;
    s.* = .{};
    return f;
}

pub const Replaced = union(enum) { busy, was: ?*File };

/// Put `f` into descriptor `fd`, open or not, taking the caller's
/// reference; the file it displaces comes back for the caller to put.
/// `.busy`, with `f` not installed, when the descriptor is being opened.
pub fn replace(pcb: *process.PCB, fd: usize, f: *File, cloexec: bool) Replaced {
    pcb.fd_lock.acquire();
    defer pcb.fd_lock.release();
    const s = &pcb.fd_table[fd];
    if (s.reserved) return .busy;
    const old = s.file;
    s.* = .{ .file = f, .cloexec = cloexec };
    return .{ .was = old };
}

/// replace for a table nobody else is opening into (a process being set
/// up): `f` goes into `fd` with the caller's reference, and what the
/// descriptor held is put.
pub fn assign(pcb: *process.PCB, fd: usize, f: *File) void {
    switch (replace(pcb, fd, f, false)) {
        .was => |old| if (old) |o| put(o),
        .busy => put(f),
    }
}

/// `child`'s table as a copy of `parent`'s, each file with one more
/// reference (fork, a native thread). A descriptor being opened stays the
/// parent's.
pub fn copyTable(child: *process.PCB, parent: *process.PCB) void {
    parent.fd_lock.acquire();
    defer parent.fd_lock.release();
    for (&child.fd_table, &parent.fd_table) |*c, *p| {
        c.* = .{};
        const f = p.file orelse continue;
        ref(f);
        c.* = .{ .file = f, .cloexec = p.cloexec };
    }
}

/// put where sleeping isn't allowed (a dying task's teardown, a look taken
/// from inside a wait): a file whose release may sleep and that lost its
/// last reference here is queued for the reaper instead.
pub fn putNoSleep(f: *File) void {
    if (!dropRef(f)) return;
    // The last holder: the file's table can't change under us now.
    if (!f.ops.release_sleeps) {
        f.ops.release(f);
        heap.kfree(@ptrCast(f));
        return;
    }
    const flags = unreleased_lock.acquireIrqSave();
    f.next_unreleased = unreleased;
    unreleased = f;
    unreleased_lock.releaseIrqRestore(flags);
}

/// Empty `pcb`'s whole table: a dying task's.
pub fn dropAll(pcb: *process.PCB) void {
    for (0..pcb.fd_table.len) |fd| putNoSleep(take(pcb, fd) orelse continue);
}

/// Files putNoSleep left unreleased, newest first.
var unreleased: ?*File = null; // (p:unreleased_lock)
var unreleased_lock: SpinLock = .{};

/// Release every file putNoSleep queued. Task context: the releases may
/// sleep.
pub fn reap() void {
    while (true) {
        const flags = unreleased_lock.acquireIrqSave();
        const f = unreleased orelse {
            unreleased_lock.releaseIrqRestore(flags);
            return;
        };
        unreleased = f.next_unreleased;
        unreleased_lock.releaseIrqRestore(flags);
        f.ops.release(f);
        heap.kfree(@ptrCast(f));
    }
}

/// True when reap has work, without the lock: the reaper's cheap look
/// between sleeps.
pub fn reapPending() bool {
    return @atomicLoad(?*File, &unreleased, .monotonic) != null;
}
