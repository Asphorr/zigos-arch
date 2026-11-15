// Processes parked in sysWaitEvent, and the desktop's side of waking them.
//
// A waiter enters, looks at its queue once more, then parks. The desktop
// queues an event, then calls notify(). Both sides do a locked RMW on
// `waiters` between their write and their read, so either notify() sees
// the waiter's bit or the waiter's last look sees the event.

const std = @import("std");
const process = @import("../../proc/process.zig");

/// Pids in sysWaitEvent, as bits.
var waiters = std.atomic.Value(u64).init(0);

comptime {
    std.debug.assert(process.MAX_PROCS <= 64);
}

fn bit(pid: usize) u64 {
    return @as(u64, 1) << @intCast(pid);
}

pub fn enter(pid: usize) void {
    _ = waiters.fetchOr(bit(pid), .seq_cst);
}

pub fn leave(pid: usize) void {
    _ = waiters.fetchAnd(~bit(pid), .seq_cst);
}

/// Wake `pid` if it is in sysWaitEvent. Called after events were queued
/// for a window of its that it can read now.
pub fn notify(pid: u8) void {
    if (pid >= process.MAX_PROCS) return;
    if (waiters.fetchOr(0, .seq_cst) & bit(pid) != 0) process.wake(pid);
}
