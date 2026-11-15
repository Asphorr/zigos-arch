// Processes parked in sysWaitEvent, and the desktop's side of waking them.
//
// A waiter enters, looks at its queue once more, then parks. The desktop
// queues an event, then calls notify(). Both sides do a locked RMW on
// `waiters` between their write and their read, so either notify() sees
// the waiter's bit or the waiter's last look sees the event.

const process = @import("../../proc/process.zig");
const pid_set = @import("../../util/pid_set.zig");

/// Pids in sysWaitEvent.
var waiters: pid_set.AtomicPidSet = .{};

pub fn enter(pid: usize) void {
    waiters.enter(pid);
}

pub fn leave(pid: usize) void {
    waiters.leave(pid);
}

/// Wake `pid` if it is in sysWaitEvent. Called after events were queued
/// for a window of its that it can read now.
pub fn notify(pid: u8) void {
    if (pid >= process.MAX_PROCS) return;
    if (waiters.hasFenced(pid)) process.wake(pid);
}
