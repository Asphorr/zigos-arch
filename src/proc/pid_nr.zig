//! Pid numbers.
//!
//! A task is found by its slot in process.procs, and a slot gets a new
//! occupant as soon as the last one is reaped. What programs know a task by
//! must not come back that fast: a pid a program still holds would name some
//! other process, and a process group or a session — named by the pid of
//! its first leader — goes on after that leader is gone. So every occupant
//! of a slot has a number of its own:
//!
//!     nr = slot + MAX_PROCS * generation
//!
//! The first occupant's number is the slot's, and the slot of any number is
//! its remainder: there is no table to search. Linux programs name tasks by
//! number, native ones by slot. Group and session ids are numbers for both;
//! the native calls show a live leader's slot in their place (nativeId).

const process = @import("process.zig");

const MAX_PROCS: u32 = process.MAX_PROCS;

/// Numbers stay under Linux's PID_MAX_LIMIT.
const GENERATIONS: u32 = (1 << 22) / MAX_PROCS;

pub const LIMIT: u32 = GENERATIONS * MAX_PROCS;

/// The generation the next occupant of each slot gets. Written by the task
/// that has claimed the slot.
var next_generation: [MAX_PROCS]u32 = [_]u32{0} ** MAX_PROCS;

/// The number for the new occupant of `slot`: called once, by whoever
/// claimed the slot. A number some group or session still goes by is passed
/// over (possible once a slot's generations have wrapped).
pub fn assign(slot: usize) u32 {
    while (true) {
        const gen = next_generation[slot];
        next_generation[slot] = (gen + 1) % GENERATIONS;
        const nr: u32 = @intCast(slot + MAX_PROCS * gen);
        if (!namesGroup(nr, slot)) return nr;
    }
}

fn namesGroup(nr: u32, claimed: usize) bool {
    for (&process.procs, 0..) |*p, i| {
        if (i == claimed or p.state == .unused) continue;
        if (p.pgid == nr or p.sid == nr) return true;
    }
    return false;
}

/// The number of the task in `slot`.
pub fn of(slot: usize) u32 {
    return process.procs[slot].pid_nr;
}

/// The slot of the task numbered `nr`, if there is one now. A task still
/// being put together has no number anyone was told.
pub fn slotOf(nr: u64) ?u8 {
    if (nr >= LIMIT) return null;
    const slot: u8 = @intCast(nr % MAX_PROCS);
    const p = &process.procs[slot];
    if (p.state == .unused or p.state == .loading or p.pid_nr != nr) return null;
    return slot;
}

/// A group or session id as the native calls give it: the slot of its
/// leader while that task lives, else the number itself.
pub fn nativeId(nr: u32) u32 {
    return slotOf(nr) orelse nr;
}

/// The group or session a native caller means by `id`: the number of the
/// task in that slot, or `id` itself when it is past the slots (a number
/// nativeId gave for a leader that is gone).
pub fn fromNativeId(id: u32) u32 {
    if (id >= MAX_PROCS) return id;
    return if (process.procs[id].state == .unused) id else process.procs[id].pid_nr;
}
