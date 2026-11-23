//! eventfd: a 64-bit counter as a file. A write adds to it; a read takes
//! it all (or one, as a semaphore) and waits while it is zero. Threads and
//! event loops use it to wake each other through poll.

const std = @import("std");
const process = @import("../proc/process.zig");
const file = @import("../fs/file.zig");
const heap = @import("../mm/heap.zig");
const errno = @import("../proc/errno.zig");
const fdpoll = @import("fdpoll.zig");
const usercopy = @import("../cpu/arch/usercopy.zig");
const SpinLock = @import("../proc/spinlock.zig").SpinLock;

/// The most the counter holds; a write that would pass it waits.
const MAX: u64 = std.math.maxInt(u64) - 1;

const Counter = struct {
    lock: SpinLock = .{},
    value: u64 = 0,
    semaphore: bool = false,
    events: u32 = 0,
};

pub const ops: file.Ops = .{ .read = opRead, .write = opWrite, .release = opRelease, .poll = opPoll, .events = opEvents };

fn counterOf(f: *file.File) *Counter {
    return @ptrCast(@alignCast(f.obj.?));
}

/// A new counter starting at `initial`, as a file with one reference.
pub fn create(initial: u64, semaphore: bool, nonblock: bool) ?*file.File {
    const raw = heap.kmallocAligned(@sizeOf(Counter), @alignOf(Counter)) orelse return null;
    const c: *Counter = @ptrCast(@alignCast(raw));
    c.* = .{ .value = initial, .semaphore = semaphore };
    return file.create(.{ .kind = .eventfd, .ops = &ops, .obj = c, .access = file.READ_WRITE, .nonblock = nonblock }) orelse {
        heap.kfree(raw);
        return null;
    };
}

fn opRelease(f: *file.File) void {
    heap.kfree(@ptrCast(counterOf(f)));
}

fn readable(c: *Counter) bool {
    return @atomicLoad(u64, &c.value, .monotonic) != 0;
}

fn opPoll(f: *file.File, _: *process.PCB) u16 {
    const v = @atomicLoad(u64, &counterOf(f).value, .monotonic);
    var m: u16 = 0;
    if (v != 0) m |= fdpoll.POLLIN | fdpoll.POLLRDNORM;
    if (v < MAX) m |= fdpoll.POLLOUT | fdpoll.POLLWRNORM;
    return m;
}

fn opEvents(f: *file.File) u32 {
    return @atomicLoad(u32, &counterOf(f).events, .monotonic);
}

fn opRead(f: *file.File, _: *process.PCB, buf: [*]u8, count: u32) u32 {
    if (count < 8) return errno.err(.EINVAL);
    const c = counterOf(f);
    while (true) {
        c.lock.acquire();
        const v = c.value;
        if (v != 0) {
            const taken: u64 = if (c.semaphore) 1 else v;
            c.value = v - taken;
            c.events +%= 1;
            c.lock.release();
            fdpoll.notify();
            if (!usercopy.copyToUser(@intFromPtr(buf), std.mem.asBytes(&taken))) return errno.err(.EFAULT);
            return 8;
        }
        c.lock.release();
        if (f.nonblock) return errno.err(.EAGAIN);
        if (fdpoll.waitFor(c, readable, 0) == .interrupted) return errno.err(.EINTR);
    }
}

const Adding = struct { c: *Counter, add: u64 };

fn hasRoom(a: *Adding) bool {
    return @atomicLoad(u64, &a.c.value, .monotonic) <= MAX - a.add;
}

fn opWrite(f: *file.File, _: *process.PCB, buf: [*]const u8, count: u32) u32 {
    if (count < 8) return errno.err(.EINVAL);
    var add: u64 = 0;
    if (!usercopy.copyFromUser(std.mem.asBytes(&add), @intFromPtr(buf))) return errno.err(.EFAULT);
    if (add == std.math.maxInt(u64)) return errno.err(.EINVAL);
    const c = counterOf(f);
    var adding = Adding{ .c = c, .add = add };
    while (true) {
        c.lock.acquire();
        if (c.value <= MAX - add) {
            c.value += add;
            c.events +%= 1;
            c.lock.release();
            fdpoll.notify();
            return 8;
        }
        c.lock.release();
        if (f.nonblock) return errno.err(.EAGAIN);
        if (fdpoll.waitFor(&adding, hasRoom, 0) == .interrupted) return errno.err(.EINTR);
    }
}
