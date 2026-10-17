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

/// CPU time of the caller's whole group, in ticks: its live threads' counts.
fn groupCpuTicks(tgid: u8) u64 {
    var sum: u64 = 0;
    for (&process.procs) |*p| {
        if (p.state == .unused or p.tgid != tgid) continue;
        sum += p.acct_cpu_ticks;
    }
    return sum;
}

/// Now on `clock`, in nanoseconds; null for a clock we don't have.
pub fn clockNanos(clock: u64) ?u64 {
    return switch (clock) {
        CLOCK_REALTIME, CLOCK_REALTIME_COARSE, CLOCK_TAI => time.realtimeNanos(),
        CLOCK_MONOTONIC, CLOCK_MONOTONIC_RAW, CLOCK_MONOTONIC_COARSE, CLOCK_BOOTTIME => time.monotonicNanos(),
        CLOCK_PROCESS_CPUTIME_ID => groupCpuTicks((process.currentPCB() orelse return null).tgid) * TICK_NS,
        CLOCK_THREAD_CPUTIME_ID => (process.currentPCB() orelse return null).acct_cpu_ticks * TICK_NS,
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

/// gettimeofday(tv, tz). The timezone is UTC, no DST.
pub fn gettimeofday(tv_va: u64, tz_va: u64) u64 {
    if (tv_va != 0) {
        if (!common.validateUserPtrWriteAligned(tv_va, @sizeOf(Timeval), 8)) return err(EFAULT);
        const ns = time.realtimeNanos();
        @as(*Timeval, @ptrFromInt(tv_va)).* = .{ .sec = @intCast(ns / NS_PER_SEC), .usec = @intCast(ns % NS_PER_SEC / 1000) };
    }
    if (tz_va != 0) {
        if (!common.validateUserPtrWriteAligned(tz_va, 8, 4)) return err(EFAULT);
        @as(*[2]i32, @ptrFromInt(tz_va)).* = .{ 0, 0 };
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

/// Sleep `ns` on the monotonic clock: 0, or -EINTR with the time left
/// written to `rem_va` (when not null) once a signal is pending.
fn sleepNanos(ns: u64, rem_va: u64) u64 {
    const pcb = process.currentPCB() orelse return err(EFAULT);
    var now = time.monotonicNanos();
    const deadline = now +| ns;
    while (now < deadline) {
        if ((@atomicLoad(u32, &pcb.pending_signals, .acquire) & ~pcb.signal_mask) != 0) {
            if (rem_va != 0 and common.validateUserPtrWriteAligned(rem_va, @sizeOf(Timespec), 8))
                @as(*Timespec, @ptrFromInt(rem_va)).* = toTimespec(deadline - now);
            return err(EINTR);
        }
        const us = std.math.divCeil(u64, deadline - now, 1000) catch unreachable;
        _ = native_proc.sysUsleep(@intCast(@min(us, std.math.maxInt(u32))));
        const later = time.monotonicNanos();
        if (later == now) break; // no clock running: one sleep is all there is
        now = later;
    }
    return 0;
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
    if (flags & TIMER_ABSTIME != 0) return sleepNanos(ns -| now, 0);
    return sleepNanos(ns, rem_va);
}
