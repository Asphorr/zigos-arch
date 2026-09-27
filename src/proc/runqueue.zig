//! Per-CPU runqueue — the dispatch source.
//!
//! Each CpuLocal owns one Rq. An Rq holds three priority queues
//! (interactive / normal / background). A PCB is on AT MOST ONE rq's
//! priority queue at a time, exactly when its state == .ready.
//!
//! `sched.pickNext` dispatches from this CPU's rq (min vruntime within
//! the highest non-empty band); `sched.rqAudit` still cross-checks rq
//! membership against the PCB state bytes.
//!
//! Locking: rq.lock is per-Rq (per-CPU). Cross-CPU state writes (wake
//! or kill targeting a pid whose assigned_cpu != my cpu) acquire the
//! target's lock; same-CPU writes also acquire it for uniformity.
//! Migration takes both rq locks in cpu-index order (sched.migrate).

const config = @import("../config.zig");
const SpinLock = @import("spinlock.zig").SpinLock;

/// Fixed-cap FIFO of pids. count <= MAX_PROCS by construction (each
/// pid appears in at most one PriQueue at a time). Append at tail,
/// pop from head, linear-scan remove. O(MAX_PROCS) for remove is fine
/// at MAX_PROCS = 64.
///
/// Sentinel 0xFF in unused slots so a stale read past `count` is
/// obvious in debugger dumps (a real pid would be 0..MAX_PROCS-1).
pub const PriQueue = struct {
    pids: [config.MAX_PROCS]u8 = [_]u8{0xFF} ** config.MAX_PROCS,
    count: u8 = 0,

    pub fn pushBack(self: *PriQueue, pid: u8) void {
        if (self.count >= config.MAX_PROCS) return;
        self.pids[self.count] = pid;
        self.count += 1;
    }

    pub fn popFront(self: *PriQueue) ?u8 {
        if (self.count == 0) return null;
        const pid = self.pids[0];
        self.count -= 1;
        var i: usize = 0;
        while (i < self.count) : (i += 1) self.pids[i] = self.pids[i + 1];
        self.pids[self.count] = 0xFF;
        return pid;
    }

    pub fn remove(self: *PriQueue, pid: u8) bool {
        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            if (self.pids[i] == pid) {
                self.count -= 1;
                var j: usize = i;
                while (j < self.count) : (j += 1) self.pids[j] = self.pids[j + 1];
                self.pids[self.count] = 0xFF;
                return true;
            }
        }
        return false;
    }

    pub fn contains(self: *const PriQueue, pid: u8) bool {
        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            if (self.pids[i] == pid) return true;
        }
        return false;
    }
};

/// Per-CPU runqueue. Three priority queues + the cross-CPU lock + a
/// runnable counter for the cheap-audit fast path.
///
/// `min_vruntime` is per-priority-band — bands are isolated fairness
/// universes (a freshly-woken background task gets bumped to background's
/// min, not interactive's). Index by `@intFromEnum(Priority)` (0 =
/// background, 1 = normal, 2 = interactive). The scheduler bumps each
/// band's min monotonically as tasks accumulate vruntime; the sleeper-
/// bonus and migration-translation paths read it.
///
/// 64-byte aligned in CpuLocal so it shares no cache line with neighbors
/// — cross-CPU `lock.acquire` invalidates this rq's line but shouldn't
/// drag in pmm_cache_count or path_l1.
pub const Rq = struct {
    interactive: PriQueue = .{},
    normal: PriQueue = .{},
    background: PriQueue = .{},
    nr_runnable: u16 = 0,
    /// Per-band min vruntime — indexed by @intFromEnum(Priority).
    /// Used by setState's sleeper bonus + migrate's vruntime translation.
    /// Bumped monotonically by process.advanceMinVruntime; never decreases.
    min_vruntime: [3]u64 = .{ 0, 0, 0 },
    lock: SpinLock = .{},

    /// Highest-priority head pid, or null if all queues empty.
    /// Does not pop — caller decides whether to dispatch.
    pub fn peekHighest(self: *const Rq) ?u8 {
        if (self.interactive.count > 0) return self.interactive.pids[0];
        if (self.normal.count > 0) return self.normal.pids[0];
        if (self.background.count > 0) return self.background.pids[0];
        return null;
    }

    pub fn contains(self: *const Rq, pid: u8) bool {
        return self.interactive.contains(pid) or
            self.normal.contains(pid) or
            self.background.contains(pid);
    }

    /// Sum of all three priority counts. Cross-checked against
    /// `nr_runnable` in the audit; mismatch means a bookkeeping bug.
    pub fn totalCount(self: *const Rq) u16 {
        return @as(u16, self.interactive.count) +
            @as(u16, self.normal.count) +
            @as(u16, self.background.count);
    }
};
