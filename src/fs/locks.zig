//! Advisory file locks, as Linux keeps them: fcntl's record locks, owned by
//! a process (POSIX) or by an open file (OFD), and flock's whole-file locks,
//! owned by an open file. POSIX and OFD locks share one space per inode;
//! flock's are a space of their own. A lock binds only those who ask: reads
//! and writes never look at them.
//!
//! A process's record locks on an inode go when it closes any descriptor of
//! that inode, or dies (closed, processGone); an open file's locks when its
//! last reference goes (fileGone). A waiter sleeps in fdpoll's poll set and
//! every release wakes it to look again.

const std = @import("std");
const SpinLock = @import("../proc/spinlock.zig").SpinLock;
const fdpoll = @import("../cpu/ipc/fdpoll.zig");
const MAX_PROCS = @import("../config.zig").MAX_PROCS;

/// The last byte a range can reach (Linux's OFFSET_MAX): a lock "to the end
/// of the file" covers whatever the file grows to. Every bound fits an
/// off_t, so F_GETLK can report any lock.
pub const END: u64 = std.math.maxInt(i64);

/// Locks held at once, all files together; a request that needs more fails
/// (ENOLCK).
const MAX_LOCKS: usize = 1024;

/// How far the deadlock check follows owners waiting on owners (Linux's
/// MAX_DEADLK_ITERATIONS).
const MAX_DEADLK_HOPS: u32 = 10;

pub const Space = enum(u8) {
    /// fcntl's record locks, POSIX and OFD.
    record,
    /// flock's.
    whole,
};

pub const Owner = union(enum) {
    /// A process, by its pid number (POSIX locks).
    process: u32,
    /// An open file, by its address (OFD and flock locks).
    file: usize,

    fn eql(a: Owner, b: Owner) bool {
        return switch (a) {
            .process => |p| b == .process and b.process == p,
            .file => |f| b == .file and b.file == f,
        };
    }
};

pub const Kind = enum { read, write, unlock };

/// One lock, or what a call asks for: the bytes `start..end` (inclusive) of
/// ext2 inode `inode`.
pub const Request = struct {
    inode: u32,
    space: Space,
    owner: Owner,
    kind: Kind,
    start: u64,
    end: u64,
};

const Entry = struct {
    /// 0: a free entry.
    inode: u32 = 0,
    space: Space = .record,
    owner: Owner = .{ .process = 0 },
    write: bool = false,
    start: u64 = 0,
    end: u64 = 0,
};

var lock: SpinLock = .{};
var table: [MAX_LOCKS]Entry = [_]Entry{.{}} ** MAX_LOCKS; // (p:lock)
/// Entries in use; read without the lock only to skip a scan of an empty
/// table (a lock taken after the read belongs to a later call).
var used: u32 = 0; // (p:lock)
/// What each POSIX owner asleep in set() waits for, for the deadlock check.
/// One per task at most.
var waiters: [MAX_PROCS]?Request = [_]?Request{null} ** MAX_PROCS; // (p:lock)

fn overlaps(e: *const Entry, r: Request) bool {
    return e.start <= r.end and r.start <= e.end;
}

fn sameFile(e: *const Entry, r: Request) bool {
    return e.inode == r.inode and e.space == r.space;
}

/// Another owner's lock that keeps `r` from being granted, if any.
pub fn conflict(r: Request) ?Request {
    if (@atomicLoad(u32, &used, .monotonic) == 0) return null;
    lock.acquire();
    defer lock.release();
    return conflictLocked(r);
}

fn conflictLocked(r: Request) ?Request {
    // Giving a range back meets nobody.
    if (r.kind == .unlock) return null;
    for (&table) |*e| {
        if (e.inode == 0 or !sameFile(e, r) or e.owner.eql(r.owner)) continue;
        if (!overlaps(e, r) or !(e.write or r.kind == .write)) continue;
        return .{ .inode = e.inode, .space = e.space, .owner = e.owner, .kind = if (e.write) .write else .read, .start = e.start, .end = e.end };
    }
    return null;
}

pub const Error = error{ WouldBlock, Interrupted, NoRoom, Deadlock };

/// Take the lock `r` asks for, or give the range back (`.unlock`): the
/// owner's own locks in the range give way to it, split where they reach
/// past it. With `wait`, sleeps while another owner's lock is in the way,
/// until a signal the caller can take; a POSIX wait that would never end,
/// the holder waiting on the caller, fails. Task context.
pub fn set(r: Request, wait: bool) Error!void {
    std.debug.assert(r.inode != 0 and r.start <= r.end and r.end <= END);
    while (true) {
        if (try trySet(r)) return;
        if (!wait) return error.WouldBlock;
        const slot = try startWait(r);
        defer endWait(slot);
        if (fdpoll.waitFor(r, isFree, 0) == .interrupted) return error.Interrupted;
    }
}

fn isFree(r: Request) bool {
    return conflict(r) == null;
}

/// set without the wait: false when another owner's lock is in the way.
fn trySet(r: Request) Error!bool {
    var changed = false;
    var granted = true;
    {
        lock.acquire();
        defer lock.release();
        if (conflictLocked(r) != null) {
            // flock converts a lock by dropping the old one first, so two
            // holders of a shared lock that both ask for it exclusive don't
            // wait on each other for ever (Linux does the same).
            if (r.space == .whole) changed = clearLocked(r);
            granted = false;
        } else {
            try roomFor(r);
            changed = clearLocked(r);
            if (r.kind != .unlock) insertLocked(r);
        }
    }
    if (changed) fdpoll.notify();
    return granted;
}

/// Whether the table can take `r`: the new lock and a split tail at most,
/// less the owner's locks it covers whole. An owner's ranges never overlap,
/// so a split leaves no other lock of its in the range.
fn roomFor(r: Request) Error!void {
    var add: usize = @intFromBool(r.kind != .unlock);
    var freed: usize = 0;
    for (&table) |*e| {
        if (e.inode == 0 or !sameFile(e, r) or !e.owner.eql(r.owner) or !overlaps(e, r)) continue;
        if (e.start < r.start and e.end > r.end) {
            add += 1;
        } else if (e.start >= r.start and e.end <= r.end) {
            freed += 1;
        }
    }
    if (used + add > MAX_LOCKS + freed) return error.NoRoom;
}

/// Before a POSIX owner sleeps on `r`: Deadlock if the lock in the way is
/// held by an owner that waits, maybe by way of others, on the caller.
/// Otherwise its wait is noted (the slot to clear after); null when
/// nothing is noted. The check and the note go under one lock, so of two
/// owners about to wait on each other the second sees the first.
fn startWait(r: Request) Error!?usize {
    if (r.owner != .process) return null;
    lock.acquire();
    defer lock.release();
    var holder = (conflictLocked(r) orelse return null).owner;
    var hops: u32 = 0;
    while (hops < MAX_DEADLK_HOPS) : (hops += 1) {
        const w = waitingOf(holder) orelse break;
        holder = (conflictLocked(w) orelse break).owner;
        if (holder.eql(r.owner)) return error.Deadlock;
    }
    for (&waiters, 0..) |*w, i| {
        if (w.* != null) continue;
        w.* = r;
        return i;
    }
    return null;
}

fn endWait(slot: ?usize) void {
    const i = slot orelse return;
    lock.acquire();
    defer lock.release();
    waiters[i] = null;
}

/// What POSIX owner `o` waits for, if it does.
fn waitingOf(o: Owner) ?Request {
    if (o != .process) return null;
    for (&waiters) |*w| {
        const req = w.* orelse continue;
        if (req.owner.eql(o)) return req;
    }
    return null;
}

/// Cut the range of `r` out of its owner's locks on the file. True if any
/// lock shrank or went.
fn clearLocked(r: Request) bool {
    var changed = false;
    for (&table) |*e| {
        if (e.inode == 0 or !sameFile(e, r) or !e.owner.eql(r.owner) or !overlaps(e, r)) continue;
        changed = true;
        if (e.start < r.start and e.end > r.end) {
            // r.end < e.end <= END: r.end + 1 stays a bound.
            const tail: Entry = .{ .inode = e.inode, .space = e.space, .owner = e.owner, .write = e.write, .start = r.end + 1, .end = e.end };
            e.end = r.start - 1;
            putLocked(tail);
        } else if (e.start < r.start) {
            e.end = r.start - 1;
        } else if (e.end > r.end) {
            e.start = r.end + 1;
        } else {
            e.* = .{};
            used -= 1;
        }
    }
    return changed;
}

/// Add the lock `r` (its range already clear of the owner's own), joined
/// with the owner's locks of the same kind that touch it.
fn insertLocked(r: Request) void {
    var n: Entry = .{ .inode = r.inode, .space = r.space, .owner = r.owner, .write = r.kind == .write, .start = r.start, .end = r.end };
    for (&table) |*e| {
        if (e.inode == 0 or !sameFile(e, r) or !e.owner.eql(r.owner) or e.write != n.write) continue;
        const before = n.start != 0 and e.end == n.start - 1;
        const after = n.end != END and e.start == n.end + 1;
        if (!before and !after) continue;
        n.start = @min(n.start, e.start);
        n.end = @max(n.end, e.end);
        e.* = .{};
        used -= 1;
    }
    putLocked(n);
}

fn putLocked(n: Entry) void {
    for (&table) |*e| {
        if (e.inode != 0) continue;
        e.* = n;
        used += 1;
        return;
    }
    unreachable; // roomFor said there was
}

/// Drop every lock `match` picks; wake the waiters if any went.
fn dropWhere(ctx: anytype, comptime match: fn (@TypeOf(ctx), *const Entry) bool) void {
    if (@atomicLoad(u32, &used, .monotonic) == 0) return;
    var dropped = false;
    {
        lock.acquire();
        defer lock.release();
        for (&table) |*e| {
            if (e.inode == 0 or !match(ctx, e)) continue;
            e.* = .{};
            used -= 1;
            dropped = true;
        }
    }
    if (dropped) fdpoll.notify();
}

const Closed = struct { pid: u32, inode: u32 };

fn closedMatch(c: Closed, e: *const Entry) bool {
    return e.inode == c.inode and e.space == .record and e.owner == .process and e.owner.process == c.pid;
}

/// Process `pid` closed a descriptor of ext2 inode `inode`: its record
/// locks there go, whichever descriptor took them (POSIX). Never sleeps.
pub fn closed(pid: u32, inode: u32) void {
    dropWhere(Closed{ .pid = pid, .inode = inode }, closedMatch);
}

fn processMatch(pid: u32, e: *const Entry) bool {
    return e.owner == .process and e.owner.process == pid;
}

/// Process `pid` is gone: all its record locks go. Never sleeps; a dying
/// task's teardown calls it.
pub fn processGone(pid: u32) void {
    dropWhere(pid, processMatch);
}

fn fileMatch(f: usize, e: *const Entry) bool {
    return e.owner == .file and e.owner.file == f;
}

/// The open file at address `f` lost its last reference: its OFD and
/// flock locks go. Never sleeps.
pub fn fileGone(f: usize) void {
    dropWhere(f, fileMatch);
}
