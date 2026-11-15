//! Sets of task ids, one bit per pid, for any MAX_PROCS.
//!
//! PidSet is plain data for a field that some lock already guards.
//!
//! AtomicPidSet is for the waiters pattern: a task enters the set, looks at
//! its condition once more and parks; a waker changes the condition and
//! wakes the pids in the set. Both sides do a locked RMW on the set between
//! their write and their read, so either the waker sees the bit or the
//! waiter's last look sees the change. A wake by pid that lands before the
//! park is kept (wake_pending).

const std = @import("std");
const config = @import("../config.zig");

pub const WORDS = (config.MAX_PROCS + 63) / 64;

fn bit(pid: usize) u64 {
    return @as(u64, 1) << @intCast(pid % 64);
}

pub const PidSet = struct {
    words: [WORDS]u64 = @splat(0),

    pub fn set(self: *PidSet, pid: usize) void {
        self.words[pid / 64] |= bit(pid);
    }

    pub fn clear(self: *PidSet, pid: usize) void {
        self.words[pid / 64] &= ~bit(pid);
    }

    pub fn has(self: *const PidSet, pid: usize) bool {
        return self.words[pid / 64] & bit(pid) != 0;
    }

    pub fn isEmpty(self: *const PidSet) bool {
        var any: u64 = 0;
        for (&self.words) |*w| any |= w.*;
        return any == 0;
    }
};

pub const AtomicPidSet = struct {
    words: [WORDS]std.atomic.Value(u64) = @splat(.init(0)),

    pub fn enter(self: *AtomicPidSet, pid: usize) void {
        _ = self.words[pid / 64].fetchOr(bit(pid), .seq_cst);
    }

    pub fn leave(self: *AtomicPidSet, pid: usize) void {
        _ = self.words[pid / 64].fetchAnd(~bit(pid), .seq_cst);
    }

    /// Whether `pid` is in the set, read behind a locked RMW: the waker's
    /// side of the pattern, for one pid.
    pub fn hasFenced(self: *AtomicPidSet, pid: usize) bool {
        return self.words[pid / 64].fetchOr(0, .seq_cst) & bit(pid) != 0;
    }

    /// The waker's side for every pid. The first word's RMW is the fence;
    /// a pid that enters a later word after that still sees the change.
    pub fn members(self: *AtomicPidSet) Iterator {
        return .{ .set = self };
    }

    pub const Iterator = struct {
        set: *AtomicPidSet,
        next_word: usize = 0,
        bits: u64 = 0,

        pub fn next(it: *Iterator) ?usize {
            while (it.bits == 0) {
                if (it.next_word == WORDS) return null;
                it.bits = it.set.words[it.next_word].fetchOr(0, .seq_cst);
                it.next_word += 1;
            }
            const b: usize = @ctz(it.bits);
            it.bits &= it.bits - 1;
            return (it.next_word - 1) * 64 + b;
        }
    };

    /// The words as they read now, for a diagnostic line.
    pub fn snapshot(self: *const AtomicPidSet) [WORDS]u64 {
        var out: [WORDS]u64 = undefined;
        for (&out, &self.words) |*o, *w| o.* = w.load(.monotonic);
        return out;
    }
};
