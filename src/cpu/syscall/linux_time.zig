//! Linux clocks and sleeps for `.linux` processes: clock_gettime,
//! clock_getres, gettimeofday, time, nanosleep, clock_nanosleep; plus the
//! timespec reading the futex waits share.
//!
//! The realtime clocks are the RTC epoch latched at boot plus the HPET delta,
//! the monotonic ones the HPET delta alone (time.zig). The CPU-time clocks
//! count scheduler ticks, so they move in TICK_NS steps.

const std = @import("std");
const process = @import("../../proc/process.zig");
const time = @import("../../time/time.zig");
const common = @import("common.zig");
const native_proc = @import("proc.zig");
const usercopy = @import("../arch/usercopy.zig");
const linux_signal = @import("linux_signal.zig");

// Linux errno.
const EINTR: i64 = 4;
const EFAULT: i64 = 14;
const EINVAL: i64 = 22;

inline fn err(e: i64) u64 {
    return @bitCast(-e);
}

pub const NS_PER_SEC: u64 = 1_000_000_000;
/// One scheduler tick (100 Hz).
pub const TICK_NS: u64 = 10_000_000;

pub const Timespec = extern struct { sec: i64, nsec: i64 };
const Timeval = extern struct { sec: i64, usec: i64 };

pub const CLOCK_REALTIME: u64 = 0;
pub const CLOCK_MONOTONIC: u64 = 1;
const CLOCK_PROCESS_CPUTIME_ID: u64 = 2;
const CLOCK_THREAD_CPUTIME_ID: u64 = 3;
const CLOCK_MONOTONIC_RAW: u64 = 4;
const CLOCK_REALTIME_COARSE: u64 = 5;
const CLOCK_MONOTONIC_COARSE: u64 = 6;
const CLOCK_BOOTTIME: u64 = 7;
const CLOCK_TAI: u64 = 11;

const TIMER_ABSTIME: u64 = 1;

pub const groupCpuTicks = process.groupCpuTicks;

/// Now on `clock`, in nanoseconds; null for a clock we don't have.
pub fn clockNanos(clock: u64) ?u64 {
    return switch (clock) {
        CLOCK_REALTIME, CLOCK_REALTIME_COARSE, CLOCK_TAI => time.realtimeNanos(),
        CLOCK_MONOTONIC, CLOCK_MONOTONIC_RAW, CLOCK_MONOTONIC_COARSE, CLOCK_BOOTTIME => time.monotonicNanos(),
        CLOCK_PROCESS_CPUTIME_ID => groupCpuTicks((process.currentPCB() orelse return null).tgid) * TICK_NS,
        CLOCK_THREAD_CPUTIME_ID => process.cpuTicksOf(process.currentPCB() orelse return null) * TICK_NS,
        else => null,
    };
}

fn resolution(clock: u64) u64 {
    return switch (clock) {
        CLOCK_PROCESS_CPUTIME_ID, CLOCK_THREAD_CPUTIME_ID, CLOCK_REALTIME_COARSE, CLOCK_MONOTONIC_COARSE => TICK_NS,
        else => 1,
    };
}

fn toTimespec(ns: u64) Timespec {
    return .{ .sec = @intCast(ns / NS_PER_SEC), .nsec = @intCast(ns % NS_PER_SEC) };
}

pub const TimespecRead = union(enum) { ns: u64, fail: u64 };

/// The user timespec at `va` in nanoseconds (saturating): -EFAULT for a bad
/// pointer, -EINVAL for a negative or denormal one.
pub fn readTimespec(va: u64) TimespecRead {
    if (!common.validateUserPtrAligned(va, @sizeOf(Timespec), 8)) return .{ .fail = err(EFAULT) };
    const ts = @as(*const Timespec, @ptrFromInt(va)).*;
    if (ts.sec < 0 or ts.nsec < 0 or ts.nsec >= NS_PER_SEC) return .{ .fail = err(EINVAL) };
    const whole = std.math.mul(u64, @intCast(ts.sec), NS_PER_SEC) catch return .{ .ns = std.math.maxInt(u64) };
    return .{ .ns = whole +| @as(u64, @intCast(ts.nsec)) };
}

/// clock_gettime(clock, tp).
pub fn clockGettime(clock: u64, tp_va: u64) u64 {
    const ns = clockNanos(clock) orelse return err(EINVAL);
    if (!common.validateUserPtrWriteAligned(tp_va, @sizeOf(Timespec), 8)) return err(EFAULT);
    @as(*Timespec, @ptrFromInt(tp_va)).* = toTimespec(ns);
    return 0;
}

/// clock_getres(clock, res); a null `res` only checks the clock.
pub fn clockGetres(clock: u64, res_va: u64) u64 {
    _ = clockNanos(clock) orelse return err(EINVAL);
    if (res_va == 0) return 0;
    if (!common.validateUserPtrWriteAligned(res_va, @sizeOf(Timespec), 8)) return err(EFAULT);
    @as(*Timespec, @ptrFromInt(res_va)).* = toTimespec(resolution(clock));
    return 0;
}

/// gettimeofday(tv, tz). tz is { minutes west of UTC, DST kind }; no DST.
pub fn gettimeofday(tv_va: u64, tz_va: u64) u64 {
    if (tv_va != 0) {
        if (!common.validateUserPtrWriteAligned(tv_va, @sizeOf(Timeval), 8)) return err(EFAULT);
        const ns = time.realtimeNanos();
        @as(*Timeval, @ptrFromInt(tv_va)).* = .{ .sec = @intCast(ns / NS_PER_SEC), .usec = @intCast(ns % NS_PER_SEC / 1000) };
    }
    if (tz_va != 0) {
        if (!common.validateUserPtrWriteAligned(tz_va, 8, 4)) return err(EFAULT);
        @as(*[2]i32, @ptrFromInt(tz_va)).* = .{ -time.utcOffsetMinutes(), 0 };
    }
    return 0;
}

/// time(t): epoch seconds, also stored through `t` when it isn't null.
pub fn timeNow(t_va: u64) u64 {
    const sec = time.realtimeNanos() / NS_PER_SEC;
    if (t_va != 0) {
        if (!common.validateUserPtrWriteAligned(t_va, 8, 8)) return err(EFAULT);
        @as(*u64, @ptrFromInt(t_va)).* = sec;
    }
    return sec;
}

/// How a sleep a signal cuts short goes on when no handler runs.
const Resume = enum {
    /// restart_syscall sleeps on to the same deadline.
    rest,
    /// The call runs again as it was made: an absolute deadline.
    again,
};

/// Sleep until monotonic `deadline`: 0, or once a signal is pending the
/// time left in `rem_va` (when not null) and a restart code — EINTR when a
/// handler runs, else the sleep goes on (`how`).
fn sleepUntil(pcb: *process.PCB, deadline: u64, rem_va: u64, how: Resume) u64 {
    var now = time.monotonicNanos();
    while (now < deadline) {
        if (@import("../../proc/signals.zig").deliverable(pcb) != 0) {
            if (rem_va != 0) {
                const rem = toTimespec(deadline - now);
                _ = usercopy.copyToUser(rem_va, std.mem.asBytes(&rem));
            }
            if (how == .again) return err(linux_signal.ERESTARTNOHAND);
            pcb.restart_until = deadline;
            pcb.restart_rem = rem_va;
            return err(linux_signal.ERESTART_RESTARTBLOCK);
        }
        const us = std.math.divCeil(u64, deadline - now, 1000) catch unreachable;
        _ = native_proc.sysUsleep(@intCast(@min(us, std.math.maxInt(u32))));
        const later = time.monotonicNanos();
        if (later == now) break; // no clock running: one sleep is all there is
        now = later;
    }
    return 0;
}

fn sleepNanos(ns: u64, rem_va: u64) u64 {
    const pcb = process.currentPCB() orelse return err(EFAULT);
    return sleepUntil(pcb, time.monotonicNanos() +| ns, rem_va, .rest);
}

/// restart_syscall(): the rest of the sleep a signal with no handler cut
/// short; EINTR when there is none.
pub fn restartSyscall() u64 {
    const pcb = process.currentPCB() orelse return err(EFAULT);
    const until = pcb.restart_until;
    if (until == 0) return err(EINTR);
    pcb.restart_until = 0;
    return sleepUntil(pcb, until, pcb.restart_rem, .rest);
}

/// nanosleep(req, rem).
pub fn nanosleep(req_va: u64, rem_va: u64) u64 {
    return switch (readTimespec(req_va)) {
        .ns => |ns| sleepNanos(ns, rem_va),
        .fail => |e| e,
    };
}

/// clock_nanosleep(clock, flags, req, rem). An absolute request sleeps
/// until `clock` reaches it; the remaining time is reported only for a
/// relative one, as Linux does.
pub fn clockNanosleep(clock: u64, flags: u64, req_va: u64, rem_va: u64) u64 {
    if (clock == CLOCK_THREAD_CPUTIME_ID) return err(EINVAL);
    const now = clockNanos(clock) orelse return err(EINVAL);
    const ns = switch (readTimespec(req_va)) {
        .ns => |ns| ns,
        .fail => |e| return e,
    };
    if (flags & TIMER_ABSTIME != 0) {
        const pcb = process.currentPCB() orelse return err(EFAULT);
        return sleepUntil(pcb, time.monotonicNanos() +| (ns -| now), 0, .again);
    }
    return sleepNanos(ns, rem_va);
}
