//! Process groups and sessions.
//!
//! A process (the lead task of a thread group) is in one process group, and
//! the group in one session. Each is named by the number (pid_nr.zig) of
//! the process that started it, and goes on by that name after the process
//! is gone. The ids are the lead's: a thread's own copies are what its group
//! had when it was made, and nothing reads them.

const process = @import("process.zig");

const PCB = process.PCB;

pub const Error = error{NotPermitted};

/// True for a slot that holds a process: a lead task, a zombie included
/// (it is in its group until reaped).
pub fn isProcess(slot: usize) bool {
    const p = &process.procs[slot];
    return p.state != .unused and p.state != .loading and p.tgid == slot;
}

/// True if a process other than `except` is in group `pgid` — of session
/// `sid`, when one is given.
pub fn groupHasMember(pgid: u32, sid: ?u32, except: ?*const PCB) bool {
    for (&process.procs, 0..) |*p, i| {
        if (!isProcess(i) or p == except or p.pgid != pgid) continue;
        if (sid == null or p.sid == sid.?) return true;
    }
    return false;
}

/// setsid: process `lead` starts a session and a group of its own, both of
/// its number, which is returned. Not while another process is in a group
/// of that number: the group would be carried into the new session.
pub fn startSession(lead: *PCB) Error!u32 {
    const nr = lead.pid_nr;
    if (groupHasMember(nr, null, lead)) return error.NotPermitted;
    lead.sid = nr;
    lead.pgid = nr;
    return nr;
}

/// setpgid: process `target` moves to group `pgid` of its session, which
/// must be `caller`'s. Its own number starts a group; any other must be a
/// group the session has.
pub fn setGroup(caller: *const PCB, target: *PCB, pgid: u32) Error!void {
    if (target.sid != caller.sid) return error.NotPermitted;
    if (pgid != target.pid_nr and !groupHasMember(pgid, target.sid, null)) return error.NotPermitted;
    target.pgid = pgid;
}
