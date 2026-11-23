//! Linux calls that wait on many files at once, beside poll (linux_proc.zig):
//! epoll, select, and the eventfd they are woken through. The objects are
//! ipc/epoll.zig and ipc/eventfd.zig.

const std = @import("std");
const process = @import("../proc/process.zig");
const file = @import("../fs/file.zig");
const vfs = @import("../fs/vfs.zig");
const epoll = @import("../cpu/ipc/epoll.zig");
const eventfd = @import("../cpu/ipc/eventfd.zig");
const fdpoll = @import("../cpu/ipc/fdpoll.zig");
const smp = @import("../cpu/smp.zig");
const usercopy = @import("../cpu/arch/usercopy.zig");
const linux_fs = @import("linux_fs.zig");
const linux_proc = @import("linux_proc.zig");
const linux_signal = @import("linux_signal.zig");
const linux_time = @import("linux_time.zig");

const EPERM: i64 = 1;
const ENOENT: i64 = 2;
const EBADF: i64 = 9;
const ENOMEM: i64 = 12;
const EFAULT: i64 = 14;
const EEXIST: i64 = 17;
const EINVAL: i64 = 22;
const EMFILE: i64 = 24;
const ENOSPC: i64 = 28;
const ELOOP: i64 = 40;

inline fn err(e: i64) u64 {
    return @bitCast(-e);
}

const O_NONBLOCK: u64 = 0x800;
const O_CLOEXEC: u64 = 0x80000;

/// A descriptor for the new file `f`, whose reference the table takes.
fn install(f: *file.File, cloexec: bool) u64 {
    const pcb = linux_fs.proc() orelse {
        file.put(f);
        return err(EFAULT);
    };
    const fd = vfs.allocFd(pcb) orelse {
        file.put(f);
        return err(EMFILE);
    };
    file.install(pcb, fd, f, cloexec);
    return fd;
}

/// The tick a wait of `ns` ends at: rounded up, one tick more.
fn deadlineAfter(ns: u64) u64 {
    const ticks = std.math.divCeil(u64, ns, linux_time.TICK_NS) catch unreachable;
    return process.tick_count +| ticks +| 1;
}

/// A signal mask a call waits under, when one is given.
fn underMask(mask_va: u64, mask_size: u64) u64 {
    if (mask_va == 0) return 0;
    if (mask_size != 8) return err(EINVAL);
    var mask: u64 = 0;
    if (!usercopy.copyFromUser(std.mem.asBytes(&mask), mask_va)) return err(EFAULT);
    linux_signal.waitUnderMask(process.currentPCB() orelse return err(EFAULT), mask);
    return 0;
}

// --- epoll ---------------------------------------------------------------------

const EPOLL_CTL_ADD: u64 = 1;
const EPOLL_CTL_DEL: u64 = 2;
const EPOLL_CTL_MOD: u64 = 3;

/// struct epoll_event on x86-64 is packed: 12 bytes.
const EVENT_SIZE: usize = 12;
/// Events copied out per call; a caller with more room asks again.
const MAX_EVENTS: usize = 64;

/// epoll_create1(flags); epoll_create(size) is this with no flags.
pub fn epollCreate(flags: u64) u64 {
    if (flags & ~O_CLOEXEC != 0) return err(EINVAL);
    const f = epoll.create() orelse return err(ENOMEM);
    return install(f, flags & O_CLOEXEC != 0);
}

/// epoll_ctl(epfd, op, fd, event).
pub fn epollCtl(epfd: u64, op_arg: u64, fd: u64, event_va: u64) u64 {
    const op: epoll.Op = switch (op_arg) {
        EPOLL_CTL_ADD => .add,
        EPOLL_CTL_MOD => .mod,
        EPOLL_CTL_DEL => .del,
        else => return err(EINVAL),
    };
    const pcb = linux_fs.proc() orelse return err(EFAULT);
    var raw: [EVENT_SIZE]u8 = [_]u8{0} ** EVENT_SIZE;
    if (op != .del and !usercopy.copyFromUser(&raw, event_va)) return err(EFAULT);
    const epf = linux_fs.fdFile(pcb, epfd) orelse return err(EBADF);
    defer file.put(epf);
    const f = linux_fs.fdFile(pcb, fd) orelse return err(EBADF);
    defer file.put(f);
    const events = std.mem.readInt(u32, raw[0..4], .little);
    const data = std.mem.readInt(u64, raw[4..12], .little);
    epoll.ctl(epf, op, @intCast(fd), f, events, data) catch |e| return err(switch (e) {
        error.Exists => EEXIST,
        error.NotFound => ENOENT,
        error.Invalid => EINVAL,
        error.Loop => ELOOP,
        error.NoSpace => ENOSPC,
        error.NotPollable => EPERM,
    });
    return 0;
}

/// The wait behind epoll_wait, epoll_pwait and epoll_pwait2. `timeout_ns`
/// null waits for good.
fn epollWaitFor(epfd: u64, events_va: u64, max_arg: u64, timeout_ns: ?u64) u64 {
    const max: i32 = @bitCast(@as(u32, @truncate(max_arg)));
    if (max <= 0) return err(EINVAL);
    const pcb = linux_fs.proc() orelse return err(EFAULT);
    const epf = linux_fs.fdFile(pcb, epfd) orelse return err(EBADF);
    defer file.put(epf);
    var out: [MAX_EVENTS]epoll.Event = undefined;
    const want = @min(@as(usize, @intCast(max)), MAX_EVENTS);
    const deadline: u64 = if (timeout_ns) |ns| deadlineAfter(ns) else 0;
    const once = if (timeout_ns) |ns| ns == 0 else false;
    const waited = epoll.wait(epf, pcb, out[0..want], deadline, once) orelse return err(EINVAL);
    const n = switch (waited) {
        .ready => |n| n,
        // EINTR after a handler; without one the wait runs again.
        .interrupted => return err(linux_signal.ERESTARTNOHAND),
    };
    for (out[0..n], 0..) |ev, i| {
        var raw: [EVENT_SIZE]u8 = undefined;
        std.mem.writeInt(u32, raw[0..4], ev.events, .little);
        std.mem.writeInt(u64, raw[4..12], ev.data, .little);
        if (!usercopy.copyToUser(events_va + i * EVENT_SIZE, &raw)) return err(EFAULT);
    }
    return n;
}

/// epoll_wait(epfd, events, maxevents, timeout_ms) and, with a mask,
/// epoll_pwait(..., sigmask, sigsetsize).
pub fn epollPwait(epfd: u64, events_va: u64, max: u64, timeout_arg: u64, mask_va: u64, mask_size: u64) u64 {
    const masked = underMask(mask_va, mask_size);
    if (masked != 0) return masked;
    const ms: i32 = @bitCast(@as(u32, @truncate(timeout_arg)));
    return epollWaitFor(epfd, events_va, max, if (ms < 0) null else @as(u64, @intCast(ms)) * 1_000_000);
}

/// epoll_pwait2(epfd, events, maxevents, timespec, sigmask, sigsetsize).
pub fn epollPwait2(epfd: u64, events_va: u64, max: u64, tmo_va: u64, mask_va: u64, mask_size: u64) u64 {
    const masked = underMask(mask_va, mask_size);
    if (masked != 0) return masked;
    if (tmo_va == 0) return epollWaitFor(epfd, events_va, max, null);
    return switch (linux_time.readTimespec(tmo_va)) {
        .ns => |ns| epollWaitFor(epfd, events_va, max, ns),
        .fail => |e| e,
    };
}

// --- eventfd -------------------------------------------------------------------

const EFD_SEMAPHORE: u64 = 1;

/// eventfd2(initval, flags); eventfd(initval) is this with no flags.
pub fn eventfd2(initial: u64, flags: u64) u64 {
    if (flags & ~(EFD_SEMAPHORE | O_NONBLOCK | O_CLOEXEC) != 0) return err(EINVAL);
    const f = eventfd.create(initial & 0xFFFF_FFFF, flags & EFD_SEMAPHORE != 0, flags & O_NONBLOCK != 0) orelse return err(ENOMEM);
    return install(f, flags & O_CLOEXEC != 0);
}

// --- select --------------------------------------------------------------------

const FD_SETSIZE: usize = 1024;
const SET_BYTES: usize = FD_SETSIZE / 8;
const FdSet = [SET_BYTES]u8;

fn isSet(set: *const FdSet, fd: usize) bool {
    return set[fd / 8] & (@as(u8, 1) << @intCast(fd % 8)) != 0;
}

fn setBit(set: *FdSet, fd: usize) void {
    set[fd / 8] |= @as(u8, 1) << @intCast(fd % 8);
}

/// The wait behind select and pselect6: the three sets as one poll.
fn selectFor(nfds_arg: u64, r_va: u64, w_va: u64, e_va: u64, timeout_ns: ?u64) u64 {
    const nfds_signed: i32 = @bitCast(@as(u32, @truncate(nfds_arg)));
    if (nfds_signed < 0 or nfds_signed > FD_SETSIZE) return err(EINVAL);
    const nfds: usize = @intCast(nfds_signed);
    const bytes = (nfds + 7) / 8;
    const vas = [3]u64{ r_va, w_va, e_va };
    var sets: [3]FdSet = undefined;
    for (&sets, vas) |*set, va| {
        @memset(set, 0);
        if (va != 0 and bytes != 0 and !usercopy.copyFromUser(set[0..bytes], va)) return err(EFAULT);
    }
    const me = smp.currentPid() orelse return err(EFAULT);
    const lead = linux_fs.proc() orelse return err(EFAULT);

    // Every fd named in a set, with what its sets ask of it.
    var fds: [@import("../config.zig").MAX_FDS]linux_proc.PollFd = undefined;
    var count: usize = 0;
    for (0..nfds) |fd| {
        var want: u16 = 0;
        if (isSet(&sets[0], fd)) want |= fdpoll.POLLIN;
        if (isSet(&sets[1], fd)) want |= fdpoll.POLLOUT;
        if (isSet(&sets[2], fd)) want |= fdpoll.POLLPRI;
        if (want == 0) continue;
        // A descriptor that isn't open fails the whole call.
        if (fd >= lead.fd_table.len or count == fds.len or !linux_fs.fdOpen(lead, fd)) return err(EBADF);
        fds[count] = .{ .fd = @intCast(fd), .events = @bitCast(want), .revents = 0 };
        count += 1;
    }
    _ = linux_proc.pollWait(me, fds[0..count], timeout_ns) orelse return err(linux_signal.ERESTARTNOHAND);

    for (&sets) |*set| @memset(set, 0);
    var ready: u64 = 0;
    for (fds[0..count]) |p| {
        const got: u16 = @bitCast(p.revents);
        const want: u16 = @bitCast(p.events);
        const fd: usize = @intCast(p.fd);
        // An end of file or an error makes a descriptor readable and
        // writable: the read or write that follows reports it.
        const broken = got & (fdpoll.POLLERR | fdpoll.POLLHUP | fdpoll.POLLNVAL) != 0;
        if (want & fdpoll.POLLIN != 0 and (got & fdpoll.POLLIN != 0 or broken)) {
            setBit(&sets[0], fd);
            ready += 1;
        }
        if (want & fdpoll.POLLOUT != 0 and (got & fdpoll.POLLOUT != 0 or got & fdpoll.POLLERR != 0)) {
            setBit(&sets[1], fd);
            ready += 1;
        }
        if (want & fdpoll.POLLPRI != 0 and got & fdpoll.POLLPRI != 0) {
            setBit(&sets[2], fd);
            ready += 1;
        }
    }
    for (&sets, vas) |*set, va| {
        if (va != 0 and bytes != 0 and !usercopy.copyToUser(va, set[0..bytes])) return err(EFAULT);
    }
    return ready;
}

const Timeval = extern struct { sec: i64, usec: i64 };

/// select(nfds, readfds, writefds, exceptfds, timeout). The timeout is left
/// as it was given.
pub fn select(nfds: u64, r_va: u64, w_va: u64, e_va: u64, tv_va: u64) u64 {
    if (tv_va == 0) return selectFor(nfds, r_va, w_va, e_va, null);
    var tv: Timeval = undefined;
    if (!usercopy.copyFromUser(std.mem.asBytes(&tv), tv_va)) return err(EFAULT);
    if (tv.sec < 0 or tv.usec < 0) return err(EINVAL);
    const ns = @as(u64, @intCast(tv.sec)) *| 1_000_000_000 +| @as(u64, @intCast(tv.usec)) *| 1000;
    return selectFor(nfds, r_va, w_va, e_va, ns);
}

/// pselect6(nfds, readfds, writefds, exceptfds, timespec, {sigmask, size}).
pub fn pselect6(nfds: u64, r_va: u64, w_va: u64, e_va: u64, ts_va: u64, sig_va: u64) u64 {
    if (sig_va != 0) {
        var sig: [2]u64 = undefined;
        if (!usercopy.copyFromUser(std.mem.asBytes(&sig), sig_va)) return err(EFAULT);
        const masked = underMask(sig[0], sig[1]);
        if (masked != 0) return masked;
    }
    if (ts_va == 0) return selectFor(nfds, r_va, w_va, e_va, null);
    return switch (linux_time.readTimespec(ts_va)) {
        .ns => |ns| selectFor(nfds, r_va, w_va, e_va, ns),
        .fail => |e| e,
    };
}
