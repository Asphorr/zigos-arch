//! Pseudo-terminals, and files on a terminal: /dev/ptmx, /dev/pts/N,
//! /dev/tty.
//!
//! A pty is a terminal (tty.zig) whose window is a program, the master.
//! What the master writes is typed at the terminal; what the terminal's
//! programs write, and its echo, the master reads. The two pipes are the
//! terminal's: keys go down `in_pipe`, output comes up `out_pipe`.
//!
//! Every end is a file of kind .tty. A slave end — /dev/pts/N, or /dev/tty
//! on whatever terminal the session has — reads through the line
//! discipline and writes the terminal's output; it holds a reader of the
//! keys and a writer of the output. The master holds the other two ends.
//! Until a slave first opens, the pty itself holds the slave's ends, so
//! the master's read waits rather than ending; once the last slave has
//! closed, it reads EIO, as on Linux. The master's close hangs the
//! terminal up: its readers see the end of input, its writers EIO, its
//! foreground group SIGHUP.

const std = @import("std");
const process = @import("process.zig");
const tty = @import("tty.zig");
const pipe = @import("pipe.zig");
const errno = @import("errno.zig");
const file = @import("../fs/file.zig");
const fdpoll = @import("../cpu/ipc/fdpoll.zig");
const usercopy = @import("../cpu/arch/usercopy.zig");
const SpinLock = @import("spinlock.zig").SpinLock;

/// Ptys at once; /dev/pts/N names one by its index.
pub const MAX: usize = 16;

const Pty = struct {
    in_use: bool = false,
    tty: u8 = tty.NONE,
    in_pipe: u8 = 0xFF,
    out_pipe: u8 = 0xFF,
    master: bool = false,
    slaves: u32 = 0,
    /// The pty holds the slave's pipe ends: none has opened yet.
    reserved: bool = false,
    /// unlockpt not called yet: a slave can't open.
    locked: bool = true,
};

var lock: SpinLock = .{};
var ptys: [MAX]Pty = [_]Pty{.{}} ** MAX; // (p:lock)

const master_ops: file.Ops = .{ .read = masterRead, .write = masterWrite, .release = masterRelease, .poll = masterPoll, .events = endEvents };
const slave_ops: file.Ops = .{ .read = slaveRead, .write = slaveWrite, .release = slaveRelease, .poll = slavePoll, .events = endEvents };

pub const Error = error{ NoRoom, NoDevice, Io };

fn ptyOf(f: *const file.File) ?*Pty {
    return @ptrCast(@alignCast(f.obj));
}

/// The pipes of an end: keys in `pipe_id`, output in `inode`.
fn keysOf(f: *const file.File) u8 {
    return f.pipe_id;
}

fn outOf(f: *const file.File) u8 {
    return @truncate(f.inode);
}

/// The terminal of an end while it is still the one the end was opened
/// on: a slot given to another terminal since has other pipes.
fn ttyOf(f: *const file.File) ?u8 {
    const t = tty.get(f.tty) orelse return null;
    if (t.in_pipe != keysOf(f) or t.out_pipe != outOf(f)) return null;
    return f.tty;
}

fn endFile(p: *const Pty, ops: *const file.Ops, nonblock: bool) ?*file.File {
    return file.create(.{
        .kind = .tty,
        .ops = ops,
        .tty = p.tty,
        .access = file.READ_WRITE,
        .nonblock = nonblock,
        .obj = @constCast(p),
        .pipe_id = p.in_pipe,
        .inode = p.out_pipe,
    });
}

/// /dev/ptmx: a new pty, its master end.
pub fn openMaster(nonblock: bool) Error!*file.File {
    const in_pipe = pipe.alloc() orelse return error.NoRoom;
    const out_pipe = pipe.alloc() orelse {
        freePipe(in_pipe);
        return error.NoRoom;
    };
    const id = tty.openPty(in_pipe, out_pipe);
    if (id == tty.NONE) {
        freePipe(in_pipe);
        freePipe(out_pipe);
        return error.NoRoom;
    }
    const p: *Pty = blk: {
        lock.acquire();
        defer lock.release();
        for (&ptys) |*q| {
            if (q.in_use) continue;
            q.* = .{ .in_use = true, .tty = id, .in_pipe = in_pipe, .out_pipe = out_pipe, .master = true, .reserved = true };
            break :blk q;
        }
        break :blk null;
    } orelse {
        tty.close(id);
        freePipe(in_pipe);
        freePipe(out_pipe);
        return error.NoRoom;
    };
    return endFile(p, &master_ops, nonblock) orelse {
        pipe.closeWriter(in_pipe);
        pipe.closeReader(out_pipe);
        masterGone(p);
        return error.NoRoom;
    };
}

fn freePipe(id: u8) void {
    pipe.closeReader(id);
    pipe.closeWriter(id);
}

/// The number /dev/pts/N names the pty of master `f` by (TIOCGPTN).
pub fn number(f: *const file.File) ?u32 {
    if (f.ops != &master_ops) return null;
    const p = ptyOf(f) orelse return null;
    return @intCast((@intFromPtr(p) - @intFromPtr(&ptys[0])) / @sizeOf(Pty));
}

/// The /dev/pts number of the pty whose terminal is `tty_id`.
pub fn ptsOfTty(tty_id: u8) ?u32 {
    lock.acquire();
    defer lock.release();
    for (&ptys, 0..) |*p, i| {
        if (p.in_use and p.tty == tty_id) return @intCast(i);
    }
    return null;
}

/// unlockpt (TIOCSPTLCK): a slave may open, or not.
pub fn setLocked(f: *const file.File, locked: bool) bool {
    if (f.ops != &master_ops) return false;
    const p = ptyOf(f) orelse return false;
    lock.acquire();
    defer lock.release();
    p.locked = locked;
    return true;
}

pub fn isMaster(f: *const file.File) bool {
    return f.kind == .tty and f.ops == &master_ops;
}

/// /dev/pts/`n`: a slave end of that pty.
pub fn openSlave(n: u32, nonblock: bool) Error!*file.File {
    if (n >= MAX) return error.NoDevice;
    const p = &ptys[n];
    var drop_reserved = false;
    {
        lock.acquire();
        defer lock.release();
        if (!p.in_use) return error.NoDevice;
        if (!p.master or p.locked) return error.Io;
        pipe.addReader(p.in_pipe);
        pipe.addWriter(p.out_pipe);
        p.slaves += 1;
        drop_reserved = p.reserved;
        p.reserved = false;
    }
    if (drop_reserved) {
        pipe.closeReader(p.in_pipe);
        pipe.closeWriter(p.out_pipe);
    }
    return endFile(p, &slave_ops, nonblock) orelse {
        pipe.closeReader(p.in_pipe);
        pipe.closeWriter(p.out_pipe);
        slaveGone(p);
        return error.NoRoom;
    };
}

/// /dev/tty: a slave end on the terminal session `sid` has.
pub fn openControlling(sid: u32, nonblock: bool) Error!*file.File {
    const id = tty.ofSession(sid) orelse return error.NoDevice;
    // A pty's: as /dev/pts/N.
    for (&ptys, 0..) |*p, n| {
        if (@atomicLoad(bool, &p.in_use, .acquire) and p.tty == id) return openSlave(@intCast(n), nonblock);
    }
    // A window's: its pipes held while the file is.
    const t = tty.get(id) orelse return error.NoDevice;
    pipe.addReader(t.in_pipe);
    pipe.addWriter(t.out_pipe);
    return file.create(.{
        .kind = .tty,
        .ops = &slave_ops,
        .tty = id,
        .access = file.READ_WRITE,
        .nonblock = nonblock,
        .pipe_id = t.in_pipe,
        .inode = t.out_pipe,
    }) orelse {
        pipe.closeReader(t.in_pipe);
        pipe.closeWriter(t.out_pipe);
        return error.NoRoom;
    };
}

// --- The master ------------------------------------------------------------------

fn masterRead(f: *file.File, _: *process.PCB, buf: [*]u8, count: u32) u32 {
    const n = pipe.readOpt(outOf(f), buf[0..count], !f.nonblock);
    return switch (n) {
        // Every slave has closed.
        0 => errno.err(.EIO),
        pipe.PIPE_AGAIN => errno.err(.EAGAIN),
        pipe.PIPE_INTR => errno.err(.EINTR),
        pipe.PIPE_ERR => errno.err(.EFAULT),
        else => @intCast(n),
    };
}

fn masterWrite(f: *file.File, _: *process.PCB, buf: [*]const u8, count: u32) u32 {
    const id = ttyOf(f) orelse return errno.err(.EIO);
    return feed(f, id, buf, count, tty.masterInput);
}

/// `count` bytes from user `buf` through `put` (a kernel chunk at a time):
/// the count taken, or the errno of a first chunk that went nowhere.
fn feed(f: *const file.File, id: u8, buf: [*]const u8, count: u32, comptime put: fn (u8, []const u8, bool) usize) u32 {
    var chunk: [256]u8 = undefined;
    var done: u32 = 0;
    while (done < count) {
        const len: u32 = @min(count - done, chunk.len);
        if (!usercopy.copyFromUser(chunk[0..len], @intFromPtr(buf) + done)) return if (done > 0) done else errno.err(.EFAULT);
        const n = put(id, chunk[0..len], !f.nonblock);
        if (n > len) {
            if (done > 0) return done;
            return switch (n) {
                pipe.PIPE_AGAIN => errno.err(.EAGAIN),
                pipe.PIPE_INTR => errno.err(.EINTR),
                else => errno.err(.EIO),
            };
        }
        done += @intCast(n);
        if (n < len) break;
    }
    return done;
}

fn masterRelease(f: *file.File) void {
    const p = ptyOf(f) orelse return;
    tty.hangup(p.tty);
    pipe.closeWriter(p.in_pipe);
    pipe.closeReader(p.out_pipe);
    masterGone(p);
}

/// The master is gone; the pty with it once no slave is left.
fn masterGone(p: *Pty) void {
    var reserved = false;
    var last = false;
    {
        lock.acquire();
        defer lock.release();
        p.master = false;
        reserved = p.reserved;
        p.reserved = false;
        last = p.slaves == 0;
    }
    if (reserved) {
        pipe.closeReader(p.in_pipe);
        pipe.closeWriter(p.out_pipe);
    }
    if (last) retire(p);
}

fn retire(p: *Pty) void {
    tty.close(p.tty);
    @atomicStore(bool, &p.in_use, false, .release);
}

fn masterPoll(f: *file.File, _: *process.PCB) u16 {
    var m: u16 = 0;
    const out = &pipe.pipes[outOf(f)];
    if (out.count > 0) m |= fdpoll.POLLIN | fdpoll.POLLRDNORM;
    if (out.writers == 0) m |= fdpoll.POLLIN | fdpoll.POLLHUP;
    const keys = &pipe.pipes[keysOf(f)];
    if (keys.count < pipe.PIPE_BUF_SIZE) m |= fdpoll.POLLOUT | fdpoll.POLLWRNORM;
    return m;
}

// --- A slave -----------------------------------------------------------------------

fn slaveRead(f: *file.File, _: *process.PCB, buf: [*]u8, count: u32) u32 {
    const id = ttyOf(f) orelse return 0;
    var line: [256]u8 = undefined;
    return switch (tty.read(id, line[0..@min(count, line.len)], f.nonblock)) {
        .bytes => |n| if (usercopy.copyToUser(@intFromPtr(buf), line[0..n])) @intCast(n) else errno.err(.EFAULT),
        .interrupted => errno.err(.EINTR),
        .again => errno.err(.EAGAIN),
        .io_error => errno.err(.EIO),
    };
}

fn slaveWrite(f: *file.File, _: *process.PCB, buf: [*]const u8, count: u32) u32 {
    const id = ttyOf(f) orelse return errno.err(.EIO);
    return feed(f, id, buf, count, tty.output);
}

fn slaveRelease(f: *file.File) void {
    pipe.closeReader(keysOf(f));
    pipe.closeWriter(outOf(f));
    if (ptyOf(f)) |p| slaveGone(p);
}

fn slaveGone(p: *Pty) void {
    var last = false;
    {
        lock.acquire();
        defer lock.release();
        p.slaves -= 1;
        last = p.slaves == 0 and !p.master;
    }
    if (last) retire(p);
}

fn slavePoll(f: *file.File, _: *process.PCB) u16 {
    var m: u16 = 0;
    const keys = &pipe.pipes[keysOf(f)];
    if (keys.count > 0 or (ttyOf(f) != null and tty.readable(f.tty))) m |= fdpoll.POLLIN | fdpoll.POLLRDNORM;
    if (keys.writers == 0) m |= fdpoll.POLLIN | fdpoll.POLLHUP;
    const out = &pipe.pipes[outOf(f)];
    if (out.count < pipe.PIPE_BUF_SIZE and out.readers > 0) m |= fdpoll.POLLOUT | fdpoll.POLLWRNORM;
    return m;
}

fn endEvents(f: *file.File) u32 {
    return fdpoll.pipeEvents(keysOf(f)) +% fdpoll.pipeEvents(outOf(f));
}
