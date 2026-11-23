//! epoll: a set of files a task waits on together.
//!
//! A set refers to its files by address, without a reference: a file that
//! is closed everywhere leaves every set it is in, as on Linux (file.zig's
//! last put calls forget). Whoever follows such a pointer does so under
//! `lock` and takes a reference of its own there (file.tryRef) before
//! letting go of the lock; forget takes the same lock before the file is
//! freed.
//!
//! Readiness is asked of the files outside the lock (File.ops.poll), so a
//! set may itself be watched by another. One level only: a set that
//! watches a set can't be watched, which keeps the asking from looping.
//!
//! Waiting is the poll(2) sleeper set (fdpoll): any event wakes every
//! waiter, and each looks at its own set again.

const std = @import("std");
const process = @import("../proc/process.zig");
const file = @import("../fs/file.zig");
const heap = @import("../mm/heap.zig");
const config = @import("../config.zig");
const fdpoll = @import("fdpoll.zig");
const SpinLock = @import("../proc/spinlock.zig").SpinLock;

pub const IN: u32 = 0x001;
pub const OUT: u32 = 0x004;
pub const ERR: u32 = 0x008;
pub const HUP: u32 = 0x010;
pub const EXCLUSIVE: u32 = 1 << 28;
pub const WAKEUP: u32 = 1 << 29;
pub const ONESHOT: u32 = 1 << 30;
pub const ET: u32 = 1 << 31;
/// The bits of an item's events that are conditions, not modes. They equal
/// poll's.
const CONDITIONS: u32 = 0xFFFF;

const MAX_ITEMS: usize = config.MAX_FDS;

const Item = struct {
    /// Null: a free slot.
    f: ?*file.File = null,
    /// Which item this slot holds: a new one for every add. A file freed
    /// and another made at its address is still a different item.
    serial: u32 = 0,
    fd: i32 = -1,
    events: u32 = 0,
    data: u64 = 0,
    /// EPOLLET: the file's event count at the last report, and whether
    /// there was one.
    seen: u32 = 0,
    reported: bool = false,
    /// EPOLLONESHOT fired: silent until a MOD.
    spent: bool = false,
};

pub const Set = struct {
    items: [MAX_ITEMS]Item = [_]Item{.{}} ** MAX_ITEMS,
    /// Sets among the items, and sets this one is an item of.
    children: u32 = 0,
    parents: u32 = 0,
    next: ?*Set = null,
};

/// Every set's items, the list of sets, the serials.
var lock: SpinLock = .{};
var sets: ?*Set = null;
var next_serial: u32 = 1;

pub const ops: file.Ops = .{ .release = opRelease, .poll = opPoll };

fn setOf(f: *file.File) ?*Set {
    if (f.kind != .epoll) return null;
    return @ptrCast(@alignCast(f.obj orelse return null));
}

/// A new set as a file with one reference. Null when memory is out.
pub fn create() ?*file.File {
    const raw = heap.kmallocAligned(@sizeOf(Set), @alignOf(Set)) orelse return null;
    const set: *Set = @ptrCast(@alignCast(raw));
    set.* = .{};
    const f = file.create(.{ .kind = .epoll, .ops = &ops, .obj = set, .access = file.READ_WRITE }) orelse {
        heap.kfree(raw);
        return null;
    };
    lock.acquire();
    set.next = sets;
    sets = set;
    lock.release();
    return f;
}

/// One item fewer in `set`. Lock held.
fn clear(set: *Set, item: *Item) void {
    if (item.f) |f| if (setOf(f)) |child| {
        child.parents -= 1;
        set.children -= 1;
    };
    item.* = .{};
}

fn opRelease(f: *file.File) void {
    const set = setOf(f).?;
    lock.acquire();
    for (&set.items) |*item| clear(set, item);
    var link: *?*Set = &sets;
    while (link.*) |x| {
        if (x == set) {
            link.* = x.next;
            break;
        }
        link = &x.next;
    }
    lock.release();
    heap.kfree(@ptrCast(set));
}

/// `f` lost its last reference: no set refers to it from here on.
pub fn forget(f: *file.File) void {
    lock.acquire();
    defer lock.release();
    var it = sets;
    while (it) |set| : (it = set.next) {
        for (&set.items) |*item| {
            if (item.f == f) clear(set, item);
        }
    }
}

pub const CtlError = error{ Exists, NotFound, Invalid, Loop, NoSpace, NotPollable };

pub const Op = enum { add, mod, del };

/// epoll_ctl on the set behind `epf`: `f` is the file of descriptor `fd`,
/// held by the caller.
pub fn ctl(epf: *file.File, op: Op, fd: i32, f: *file.File, events: u32, data: u64) CtlError!void {
    const set = setOf(epf) orelse return error.Invalid;
    if (f == epf) return error.Invalid;
    // What is always ready can't be waited on, as on Linux.
    switch (f.kind) {
        .ext2, .fat32, .tarfs, .procfs, .devfs => return error.NotPollable,
        else => {},
    }
    lock.acquire();
    defer lock.release();
    const found: ?*Item = for (&set.items) |*item| {
        if (item.f == f and item.fd == fd) break item;
    } else null;
    switch (op) {
        .add => {
            if (found != null) return error.Exists;
            if (setOf(f)) |child| {
                if (child.children != 0 or set.parents != 0) return error.Loop;
            }
            const slot: *Item = for (&set.items) |*item| {
                if (item.f == null) break item;
            } else return error.NoSpace;
            slot.* = .{ .f = f, .serial = next_serial, .fd = fd, .events = events, .data = data };
            next_serial +%= 1;
            if (setOf(f)) |child| {
                child.parents += 1;
                set.children += 1;
            }
            @atomicStore(bool, &f.watched, true, .release);
        },
        .mod => {
            const item = found orelse return error.NotFound;
            item.events = events;
            item.data = data;
            item.reported = false;
            item.spent = false;
        },
        .del => clear(set, found orelse return error.NotFound),
    }
    // A waiter may be asleep on the set as it was.
    fdpoll.notify();
}

pub const Event = struct { events: u32, data: u64 };

const Pin = struct { index: usize, serial: u32, f: *file.File, events: u32, data: u64, seen: u32, reported: bool };

/// The items of `set` that are ready, into `out`: how many. Marks what an
/// edge-triggered or one-shot item reported, unless `peek`.
fn collect(set: *Set, pcb: *process.PCB, out: []Event, peek: bool) usize {
    var pins: [MAX_ITEMS]Pin = undefined;
    var pinned: usize = 0;
    lock.acquire();
    for (&set.items, 0..) |*item, i| {
        const f = item.f orelse continue;
        if (item.spent or !file.tryRef(f)) continue;
        pins[pinned] = .{ .index = i, .serial = item.serial, .f = f, .events = item.events, .data = item.data, .seen = item.seen, .reported = item.reported };
        pinned += 1;
    }
    lock.release();

    var n: usize = 0;
    var told: [MAX_ITEMS]struct { index: usize, serial: u32, count: u32 } = undefined;
    for (pins[0..pinned]) |p| {
        // The count first: an event between the two reads shows as ready
        // now and as new next time, never as neither.
        const count = p.f.ops.events(p.f);
        const ready = @as(u32, p.f.ops.poll(p.f, pcb)) & ((p.events & CONDITIONS) | ERR | HUP);
        const stale = p.events & ET != 0 and p.reported and count == p.seen;
        if (ready != 0 and !stale and n < out.len) {
            out[n] = .{ .events = ready, .data = p.data };
            told[n] = .{ .index = p.index, .serial = p.serial, .count = count };
            n += 1;
        }
        // May be the last reference: the file was closed while we looked.
        // We are asked from inside a wait, where a release can't sleep.
        file.putNoSleep(p.f);
    }
    if (peek or n == 0) return n;

    // Mark what is reported. Another waiter on the set may have looked at
    // the same time: an edge or a one-shot it marked first is its own, and
    // drops out of ours.
    var kept: usize = 0;
    lock.acquire();
    for (told[0..n], 0..) |t, k| {
        const item = &set.items[t.index];
        // Still the item it was; one removed meanwhile is told as seen.
        if (item.f != null and item.serial == t.serial) {
            if (item.events & ONESHOT != 0) {
                if (item.spent) continue;
                item.spent = true;
            } else if (item.events & ET != 0 and item.reported and item.seen == t.count) {
                continue;
            }
            item.seen = t.count;
            item.reported = true;
        }
        out[kept] = out[k];
        kept += 1;
    }
    lock.release();
    return kept;
}

fn opPoll(f: *file.File, pcb: *process.PCB) u16 {
    var one: [1]Event = undefined;
    return if (collect(setOf(f).?, pcb, &one, true) != 0) fdpoll.POLLIN | fdpoll.POLLRDNORM else 0;
}

pub const Waited = union(enum) { ready: usize, interrupted };

const Waiting = struct { set: *Set, pcb: *process.PCB, out: []Event, n: usize = 0 };

fn anyReady(w: *Waiting) bool {
    w.n = collect(w.set, w.pcb, w.out, false);
    return w.n != 0;
}

/// Wait on the set behind `epf` until an item is ready, tick `deadline`
/// (0: none) or a signal; `poll_once` only looks. Fills `out`.
pub fn wait(epf: *file.File, pcb: *process.PCB, out: []Event, deadline: u64, poll_once: bool) ?Waited {
    const set = setOf(epf) orelse return null;
    var w = Waiting{ .set = set, .pcb = pcb, .out = out };
    if (poll_once) return .{ .ready = collect(set, pcb, out, false) };
    return switch (fdpoll.waitFor(&w, anyReady, deadline)) {
        .ready => .{ .ready = w.n },
        .timed_out => .{ .ready = 0 },
        .interrupted => .interrupted,
    };
}
