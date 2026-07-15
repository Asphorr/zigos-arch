//! Scheduler core: per-CPU runqueue state, dispatch, IPI wake/kick, the
//! sleep/wake primitives (blockOn / blockOnInterruptible / blockOnFutex /
//! blockOnMutex / blockOnSwapEvict / wake), and the CPU load-balancer.
//! Split out of process.zig (#810).
//!
//! Owns:
//!   * setState — the centralized state-transition path that keeps rq
//!     membership coherent with the state byte. Two CAS sites (allocSlot
//!     in lifecycle.zig and the picker CAS in `schedule` here) flip the
//!     byte directly and call `rqOnLeaveReady` to mirror the rq side.
//!   * schedule / pickNext / pickMinVruntime — the dispatch loop. Per-CPU
//!     runqueue scan in priority-band order, CFS min-vruntime within each
//!     band, exit-requested + wait_kind filters, falls back to own-cpu idle.
//!   * accountRunningTick / checkPreempt — per-tick CFS vruntime
//!     maintenance and per-band min_vruntime floor advancement.
//!   * migrate / loadBalance / setAffinity / getAffinity / effectiveLoad /
//!     assignInitialCpu — CPU pin / load-balance plumbing. The balancer
//!     runs from the BSP timer IRQ at BALANCE_INTERVAL_TICKS cadence.
//!   * niceToWeight / NICE_WEIGHTS — Linux-style nice → weight table for
//!     CFS vruntime scaling, live in accountRunningTick (fixed-point
//!     VRUNTIME_SCALE units keep negative-nice weights from truncating
//!     a 1-tick delta to zero — the bug that forced the original disable).
//!   * killKickHandler / wakeOnlyHandler / initKillKickIpi / initWakeIpi /
//!     kickVector / wakeVector — the two cross-CPU IPI vectors. Kill-kick
//!     re-schedules the receiver (forces a context switch off a dying pid);
//!     wake-only is a no-op handler used as a "wake from hlt without
//!     preempting" primitive (e.g. virtio-gpu completion).
//!   * BlockResult / FutexResult / hasPendingDeliverable / blockOn /
//!     blockOnInterruptible / blockOnFutex / blockOnMutex / blockOnSwapEvict
//!     — the sleep-and-wake-recheck primitives. All five include the
//!     enroll-then-recheck-wake_pending handshake that closes the wake-
//!     during-enrollment lost-wake class (2026-05-19 + 2026-05-22).
//!   * wake / wakeMutexWaiters / wakeSwapEvictWaiters / wakeExpired /
//!     deliverDueAlarms / kernelSleepMs — the waker side. wakeExpired runs
//!     from the BSP timer IRQ and is the timeout source for sysSleep /
//!     kernelSleepMs / .gpu_io wake fallback.
//!   * enterFirstTask / enterFirstTaskAp / writeFsBase — first-dispatch
//!     bootstrap (BSP cuts over to the desktop kernel task; APs cut over
//!     to their per-CPU idle).
//!
//! Re-exported from process.zig so external callers keep using process.X
//! paths unchanged.
//!
//! Var-stay note: `kick_handler_runs` and `wake_handler_runs` STAY as
//! `pub var` in process.zig because external callers (cli.zig,
//! virtio_gpu.zig) read them via `process.X`. Zig's `pub const X = mod.X`
//! re-export copies a `var`'s value at comptime, breaking the mutable-
//! global semantic. The IPI handlers here bump them through
//! `process.kick_handler_runs[...]` / `process.wake_handler_runs[...]`.

const std = @import("std");

const vga = @import("../ui/vga.zig");
const gdt = @import("../cpu/arch/gdt.zig");
const debug = @import("../debug/debug.zig");
const pcid_mod = @import("../cpu/mmu/pcid.zig");
const smp = @import("../cpu/smp.zig");
const memmap = @import("../mm/memmap.zig");
const config = @import("../config.zig");
const signals = @import("signals.zig");
const runqueue = @import("runqueue.zig");
const swap = @import("../mm/swap.zig");
const SpinLock = @import("spinlock.zig").SpinLock;

const process = @import("process.zig");
const hrtimer = @import("hrtimer.zig");
const PCB = process.PCB;
const State = process.State;
const Priority = process.Priority;
const WaitKind = process.WaitKind;
const MAX_PROCS = process.MAX_PROCS;

/// Targeted scheduler-trace gate. When non-zero, every setState CAS,
/// rqEnter, rqLeave, and pickNext CAS for this pid prints a one-line
/// klog with caller RA + CPU. Set to 0 to disable. Used 2026-05-20 to
/// root out the "state=.running but no cpu.current_pid points here"
/// pcb-invariant panic on Q1 — the trace klog widened the picker
/// CAS→bracket window enough to make the latent race fire reliably,
/// pinpointing that `cpu.dispatching_in_pid = cand` happened AFTER
/// rather than BEFORE the state CAS in pickNext. Bracket order fixed
/// 2026-05-20; trace left in place (gated to 0) for next regression.
const TRACE_PID: u8 = 0;

// =============================================================================
// Phase 1: per-CPU runqueue parallel-tracking
// =============================================================================
//
// Centralized state-transition path. Every PCB state change SHOULD route
// through `setState` — it maintains the per-CPU runqueue's view of "which
// pids are .ready and assigned here" alongside the legacy state byte.
//
// The two CAS sites that can't go through setState (allocSlot's
// .unused→.loading CAS and schedule()'s pickNext-claim .ready→.running CAS)
// instead call the explicit one-side helpers (`rqOnLeaveReady` after they
// flip a pid out of .ready). Phase 1 is shadow-only — `pickNext` still
// scans procs[] — so the rq is purely audit material until Phase 2.

/// Phase 4 load-balancer thresholds. BALANCE_INTERVAL_TICKS gates how
/// often loadBalance() runs (BSP timer IRQ); BALANCE_THRESHOLD is the
/// minimum (busiest_load - idlest_load) delta that triggers a single-task
/// migration. 50 ticks × 10 ms = ~500 ms cadence; threshold 2 prevents
/// migration ping-pong when load differs by 1.
const BALANCE_INTERVAL_TICKS: u64 = 50;
const BALANCE_THRESHOLD: u16 = 2;

/// CFS-style scheduling tunables.
///
/// VRUNTIME_SCALE: fixed-point scale for vruntime — one timer tick (10 ms
///   at the 100 Hz LAPIC cadence) of nice=0 runtime adds exactly
///   VRUNTIME_SCALE units. Sub-tick resolution is what makes nice
///   weighting workable at tick granularity: accrual is
///   `delta_ticks * VRUNTIME_SCALE * NICE_0_WEIGHT / weight`, so even a
///   1-tick slice at nice=-20 (weight 88761) yields 11 units instead of
///   the 0 that bare `delta * 1024 / weight` integer math produces. That
///   truncation-to-zero is why the original nice re-enable starved
///   same-band peers: a nice<0 task never accrued vruntime, stayed
///   minimum in its band forever, and the picker pinned to it.
///   With every task at the default nice=0 the accrual is exactly
///   `delta * VRUNTIME_SCALE` — order-isomorphic to the old unweighted
///   per-tick accrual, so default-workload scheduling is unchanged.
/// SLEEPER_CREDIT: when a task wakes from .sleeping, it's bumped to
///   `max(vruntime, min_vruntime - SLEEPER_CREDIT)` so it runs soon
///   without strip-mining tasks that have been waiting at the floor.
///   3 tick-equivalents (half a 60 ms latency target — the standard CFS
///   heuristic).
///
/// (SCHED_LATENCY / MIN_GRANULARITY — the ideal_runtime slice-stretching
/// tunables — sat here for weeks consumed by NOTHING: the real preempt
/// cadence is simply every 10 ms tick via handleIRQ0. Removed rather than
/// left implying a slice policy that doesn't exist.)
const VRUNTIME_SCALE: u64 = 1024;
const SLEEPER_CREDIT: u64 = 3 * VRUNTIME_SCALE;

/// Linux-style nice → weight table (kernel/sched/core.c sched_prio_to_weight[]).
/// Indexed by `nice + 20` (so range -20..19 maps to indices 0..39).
/// The ratio between adjacent nice levels is ~1.25 (so each nice level changes
/// CPU share by ~25%), and nice=0 has weight NICE_0_WEIGHT (1024 on Linux —
/// our canonical "1 unit of vruntime per tick" baseline).
const NICE_0_WEIGHT: u64 = 1024;
const NICE_WEIGHTS = [40]u64{
    // nice -20..-11
    88761, 71755, 56483, 46273, 36291, 29154, 23254, 18705, 14949, 11916,
    // nice -10..-1
     9548,  7620,  6100,  4904,  3906,  3121,  2501,  1991,  1586,  1277,
    // nice 0..9
     1024,   820,   655,   526,   423,   335,   272,   215,   172,   137,
    // nice 10..19
      110,    87,    70,    56,    45,    36,    29,    23,    18,    15,
};

/// Atomically set a PCB's wait fields together. `pcb.wait_kind` and
/// `pcb.wait_target` are tagged `(a)` in process.zig because cross-CPU
/// readers (wake() on a remote CPU, wakeExpired() on any CPU) read them.
/// All blockOn entry paths use this; the .release ordering pairs with
/// the @atomicLoad(wake_pending, .acquire) re-check that follows.
inline fn setWait(pcb: *process.PCB, kind: process.WaitKind, target: u32) void {
    @atomicStore(u8, @as(*u8, @ptrCast(&pcb.wait_kind)), @intFromEnum(kind), .release);
    @atomicStore(u32, &pcb.wait_target, target, .release);
}

/// Atomically clear a PCB's wait fields. Used at every blockOn exit /
/// wake / wakeExpired path. Pairs with setWait + the lost-wake handshake.
inline fn clearWait(pcb: *process.PCB) void {
    @atomicStore(u8, @as(*u8, @ptrCast(&pcb.wait_kind)), @intFromEnum(process.WaitKind.none), .release);
    @atomicStore(u32, &pcb.wait_target, 0, .release);
}

/// Test whether this PCB is enrolled as a (kind, target) waiter, atomically.
/// All wake-helper fan-out loops (wakeMutexWaiters, wakeSwapEvictWaiters,
/// wakeIoUring*) use this so the read pairs with setWait's .release store.
inline fn waitsOn(t: *const process.PCB, kind: process.WaitKind, target: u32) bool {
    return @atomicLoad(u8, @as(*const u8, @ptrCast(&t.wait_kind)), .acquire) == @intFromEnum(kind)
        and @atomicLoad(u32, &t.wait_target, .acquire) == target;
}

/// Map a nice value (-20..19, clamped) to its weight. Out-of-range nice is
/// clamped to the nearest endpoint.
inline fn niceToWeight(nice: i8) u64 {
    const clamped: i8 = if (nice < -20) -20 else if (nice > 19) 19 else nice;
    const idx: usize = @intCast(@as(i32, clamped) + 20);
    return NICE_WEIGHTS[idx];
}

/// Cursor kept around for diagnostic continuity; load-balancer-driven
/// assignInitialCpu picks min effective load now, no round-robin needed.
var next_assignment_cpu: u8 = 0;

/// schedule()-call counter used to throttle `rqAudit` to every 64th call.
/// u32 wrap is harmless — only the low bits matter for the cadence test.
var sched_audit_counter: u32 = 0;

/// Effective scheduling load on a cpu — the runnable count plus 1 if a
/// non-idle task is currently dispatched. This counts the running task
/// as load (a CPU with one .ready and one .running has effective load 2,
/// not 1) so we don't preferentially place new tasks on a cpu that's
/// already pinned saturating something — desktop on cpu0 with empty rq
/// has effective load 1, not 0.
fn effectiveLoad(cpu_idx: usize) u16 {
    if (cpu_idx >= smp.MAX_CPUS) return std.math.maxInt(u16);
    if (!smp.cpus[cpu_idx].alive) return std.math.maxInt(u16);
    var load: u16 = smp.cpus[cpu_idx].runqueue.nr_runnable;
    if (smp.cpus[cpu_idx].current_pid) |cur| {
        if (cur < MAX_PROCS and !process.procs[cur].is_idle) load +%= 1;
    }
    return load;
}

/// Assign a freshly-created PCB to a CPU's runqueue. Called once per
/// PCB lifecycle, after the kstack/page-tables are set up but BEFORE
/// the first state→.ready transition (so the rqEnter triggered by
/// setState lands on the right rq).
///
/// Idempotent — repeated calls inside a single PCB lifetime no-op.
/// resetPcbExceptState resets `assigned_cpu` to 0xFF on slot recycle,
/// so the next create() lands a fresh assignment.
///
/// Phase 4: picks the cpu with the lowest effective load (vs the prior
/// "skip cpu0" hack). Combined with pickNext's exclude_prev fairness
/// and the periodic load balancer, this lets cpu0 share work with
/// desktop instead of being permanently dedicated.
pub fn assignInitialCpu(pid: usize) void {
    const pcb = &process.procs[pid];
    if (pcb.assigned_cpu != 0xFF) return;
    if (pcb.is_idle) {
        pcb.assigned_cpu = pcb.idle_cpu;
        return;
    }
    if (pcb.pinned_cpu != 0xFF) {
        pcb.assigned_cpu = pcb.pinned_cpu;
        return;
    }
    var best_cpu: u8 = 0;
    var best_load: u16 = std.math.maxInt(u16);
    var i: u8 = 0;
    while (i < smp.MAX_CPUS) : (i += 1) {
        if (!smp.cpus[i].alive) continue;
        const load = effectiveLoad(i);
        if (load < best_load) {
            best_load = load;
            best_cpu = i;
        }
    }
    pcb.assigned_cpu = best_cpu;
    next_assignment_cpu +%= 1; // diag-only cursor
}

/// Phase 4: move pid from its current assigned_cpu's runqueue to
/// new_cpu's. Atomic across both rq locks (acquired in cpu_id order to
/// avoid deadlock with concurrent migrate calls). Skips pinned/idle/
/// dead/already-there pids.
///
/// If pid is .ready (in the source rq), it's removed and pushed to the
/// target rq's matching priority queue. For other states (.running,
/// .sleeping, .loading), only assigned_cpu is updated — the next
/// state→.ready transition will rqEnter on the new cpu.
///
/// Returns true on a state-affecting move, false otherwise.
pub fn migrate(pid: u8, new_cpu: u8) bool {
    if (pid >= MAX_PROCS) return false;
    if (new_cpu >= smp.MAX_CPUS) return false;
    if (!smp.cpus[new_cpu].alive) return false;

    const pcb = &process.procs[pid];
    if (pcb.is_idle) return false;
    // Pinned tasks can only migrate TO their pin destination — load
    // balancer respects pinning, but sysSetAffinity sets pinned_cpu first
    // and then calls migrate() to move the task to its pin.
    if (pcb.pinned_cpu != 0xFF and pcb.pinned_cpu != new_cpu) return false;
    const old_cpu = pcb.assigned_cpu;
    if (old_cpu == new_cpu) return false;
    if (old_cpu == 0xFF or old_cpu >= smp.MAX_CPUS) return false;

    const lo: u8 = @min(old_cpu, new_cpu);
    const hi: u8 = @max(old_cpu, new_cpu);
    const lo_lock = &smp.cpus[lo].runqueue.lock;
    const hi_lock = &smp.cpus[hi].runqueue.lock;
    const f = lo_lock.acquireIrqSave();
    hi_lock.acquire();
    defer {
        hi_lock.release();
        lo_lock.releaseIrqRestore(f);
    }

    // Re-check under both locks — pid may have moved/died since our
    // pre-lock snapshot.
    if (pcb.assigned_cpu != old_cpu) return false;
    if (pcb.is_idle) return false;
    const state_byte = @atomicLoad(u8, @as(*const u8, @ptrCast(&pcb.state)), .acquire);
    if (state_byte == @intFromEnum(State.unused) or
        state_byte == @intFromEnum(State.zombie)) return false;

    // Cross-CPU dispatch race fix (task #713). Refuse migration if any CPU
    // still has `pid` as `current_pid` — that CPU may be mid-schedule,
    // having demoted prev to .ready (visible to us NOW), but not yet
    // updated prev's kernel_esp via switchTo's save. Picking prev up here
    // and dispatching elsewhere would resume from a stale kernel_esp →
    // stack corruption. Caller (loadBalance) retries next tick.
    for (0..smp.MAX_CPUS) |i| {
        if (i > 0 and !smp.cpus[i].alive) continue;
        if (smp.cpus[i].current_pid) |cur| {
            if (cur == pid) return false;
        }
    }

    const old_rq = &smp.cpus[old_cpu].runqueue;
    const new_rq = &smp.cpus[new_cpu].runqueue;

    var removed = false;
    if (old_rq.interactive.remove(pid)) {
        old_rq.nr_runnable -%= 1;
        removed = true;
    } else if (old_rq.normal.remove(pid)) {
        old_rq.nr_runnable -%= 1;
        removed = true;
    } else if (old_rq.background.remove(pid)) {
        old_rq.nr_runnable -%= 1;
        removed = true;
    }
    if (removed) {
        // CFS vruntime translation: preserve the task's "fairness debt"
        // (lag above the source floor) and re-anchor on the destination
        // floor. Linux place_entity-style. Saturating subtract: if
        // vruntime < old_floor (e.g., a task that fell behind while
        // sleeping), treat lag as 0 — the task is effectively at the
        // floor anyway. Without saturation, wrapping `-%` underflows
        // to ~u64-max and the task gets stuck never being picked
        // (vruntime > everyone else's, picker always passes it over).
        const band: usize = @intFromEnum(pcb.priority);
        const old_floor = old_rq.min_vruntime[band];
        const new_floor = new_rq.min_vruntime[band];
        const lag: u64 = if (pcb.vruntime > old_floor) pcb.vruntime - old_floor else 0;
        pcb.vruntime = new_floor +% lag;

        const target_q = switch (pcb.priority) {
            .interactive => &new_rq.interactive,
            .normal => &new_rq.normal,
            .background => &new_rq.background,
        };
        target_q.pushBack(pid);
        new_rq.nr_runnable +%= 1;
    }

    // Migration accounting (exposed via /proc/sched). Bump under both
    // rq locks so /proc/sched readers see a coherent in/out pair.
    // L6: atomic RMW — readers in procfs use @atomicLoad; writers under
    // the dual rq locks were plain but the tag-discipline mismatch could
    // hide tearing on future arch ports. Single writer per dual-lock
    // acquisition; .monotonic is sufficient.
    _ = @atomicRmw(u64, &smp.cpus[old_cpu].migrations_out, .Add, 1, .monotonic);
    _ = @atomicRmw(u64, &smp.cpus[new_cpu].migrations_in, .Add, 1, .monotonic);

    pcb.assigned_cpu = new_cpu;

    // TLB coherence across the move. migrate() does no per-page flush; it
    // relies on loadCr3's preserve-on-reload being safe. That holds only if
    // every present→change remap of this AS bumped the PCID generation — but
    // the COW and lazy-remap fault paths flush LOCAL-only (no shootdown, no
    // bump) on the assumption a single-threaded AS lives on one CPU. Moving it
    // violates that, so force a gen bump here: the next loadCr3(pcid) on the
    // destination (and on the source, when it next runs this AS) does a real
    // CR3-reload flush, dropping any stale (pcid, va) entry. Done under both rq
    // locks so it's ordered before the destination's pickNext observes the
    // task in new_rq. Cheap: one atomic increment; one flush per reload.
    pcid_mod.invalidateForMigration(pcb.pcid);
    return true;
}

/// Phase 7: pin/unpin a pid to a specific CPU.
///   cpu_id == 0xFF → unpin (load balancer regains discretion)
///   cpu_id < MAX_CPUS → pin to that cpu, migrate if needed
///
/// Behavior by current state of pid:
///   .ready: migrate() moves it to target cpu's rq immediately.
///   .running on different cpu: update assigned_cpu, IPI old cpu — its
///     next schedule's prev demote will rqEnter on the new assigned_cpu.
///   .sleeping / .loading: just update fields — when pid next becomes
///     .ready, rqEnter sees the new assigned_cpu and lands on it.
///
/// Returns false on invalid args (bad pid, bad cpu, idle PCB). Caller
/// (sysSetAffinity) is responsible for permission checks.
pub fn setAffinity(pid: u8, cpu_id: u8) bool {
    if (pid >= MAX_PROCS) return false;
    if (cpu_id != 0xFF) {
        if (cpu_id >= smp.MAX_CPUS) return false;
        if (!smp.cpus[cpu_id].alive) return false;
    }
    const pcb = &process.procs[pid];
    if (pcb.is_idle) return false; // idles can't be re-pinned

    pcb.pinned_cpu = cpu_id;
    if (cpu_id == 0xFF) {
        // Unpinning — leave assigned_cpu as is. Load balancer will
        // rebalance opportunistically if there's a load delta.
        return true;
    }

    // H2: Don't write assigned_cpu BEFORE migrate() — migrate snapshots
    // pcb.assigned_cpu as `old_cpu` and bails immediately if
    // old_cpu == new_cpu. Stomping assigned_cpu here would make migrate
    // a no-op; the pid would stay in its real (old) rq with assigned_cpu
    // pointing at the new (uninhabited-by-it) CPU. For .ready, migrate
    // itself updates assigned_cpu under both rq locks. For other states
    // there's no rq membership to move — write directly after the branch.
    const state_byte = @atomicLoad(u8, @as(*const u8, @ptrCast(&pcb.state)), .acquire);
    if (state_byte == @intFromEnum(State.ready)) {
        _ = migrate(pid, cpu_id);
    } else if (state_byte == @intFromEnum(State.running)) {
        pcb.assigned_cpu = cpu_id;
        // pid is dispatched somewhere — find that CPU and IPI it so its
        // schedule runs sooner. The prev demote in schedule will see the
        // updated assigned_cpu via setState→rqEnter.
        for (&smp.cpus) |*c| {
            if (!c.alive) continue;
            if (c.cpu_id == cpu_id) continue;
            if (c.current_pid) |cur| {
                if (cur == pid) {
                    if (kill_kick_vector) |v| {
                        const apic = @import("../time/apic.zig");
                        apic.sendIPI(c.lapic_id, v);
                    }
                    break;
                }
            }
        }
    } else {
        // .sleeping / .loading / .zombie / .unused — no rq membership to
        // move, no IPI to send. Write assigned_cpu directly so the next
        // state→.ready transition's rqEnter lands on the new CPU.
        pcb.assigned_cpu = cpu_id;
    }
    return true;
}

/// Phase 7 companion: read a pid's current affinity.
///   Returns pid's `pinned_cpu`: 0..MAX_CPUS-1 = pinned to that CPU,
///   0xFF = unpinned (load balancer has discretion).
/// Returns 0xFF for invalid pid (treat as unpinned).
pub fn getAffinity(pid: u8) u8 {
    if (pid >= MAX_PROCS) return 0xFF;
    return process.procs[pid].pinned_cpu;
}

/// Phase 4 BSP-driven periodic load balancer. Picks the busiest and
/// idlest cpus by effective load, migrates one task from busiest to
/// idlest if delta >= BALANCE_THRESHOLD. Single migration per call —
/// gradual convergence avoids migration storms.
///
/// Migration source preference: lowest priority queue (least
/// disruption to interactive/normal tasks); within a queue, TAIL
/// (least recently dispatched, less hot in cache).
///
/// Called from handleIRQ0 BSP block every BALANCE_INTERVAL_TICKS.
pub fn loadBalance() void {
    if (!smp.isBSP()) return;

    var busiest_cpu: u8 = 0xFF;
    var busiest_load: u16 = 0;
    var idlest_cpu: u8 = 0xFF;
    var idlest_load: u16 = std.math.maxInt(u16);

    var i: u8 = 0;
    while (i < smp.MAX_CPUS) : (i += 1) {
        if (!smp.cpus[i].alive) continue;
        const load = effectiveLoad(i);
        if (load > busiest_load) {
            busiest_load = load;
            busiest_cpu = i;
        }
        if (load < idlest_load) {
            idlest_load = load;
            idlest_cpu = i;
        }
    }
    if (busiest_cpu == 0xFF or idlest_cpu == 0xFF) return;
    if (busiest_cpu == idlest_cpu) return;
    if (busiest_load < idlest_load + BALANCE_THRESHOLD) return;

    // Pick a migration candidate from the busiest CPU and move it to the
    // idlest. pickMigrationCandidate takes the source rq.lock for the scan;
    // migrate() re-validates the pick under both rq locks.
    if (pickMigrationCandidate(busiest_cpu)) |p| {
        _ = migrate(p, idlest_cpu);
    }
}

/// Pick a migratable task from `cpu_idx`'s runqueue: lowest-priority band first
/// (least disruption to interactive/normal work), tail-end within the band
/// (least recently dispatched, coldest in cache). Skips idle, pinned, and
/// job-control-stopped pids. Takes the target rq.lock for the scan; the
/// returned pid is re-validated under both rq locks by migrate(), so a race
/// between this scan and the move is benign (migrate() just returns false).
/// Shared by loadBalance (periodic push) and tryStealWork (pull-on-idle).
fn pickMigrationCandidate(cpu_idx: u8) ?u8 {
    const rq = &smp.cpus[cpu_idx].runqueue;
    const f = rq.lock.acquireIrqSave();
    defer rq.lock.releaseIrqRestore(f);
    const queues = [_]*const runqueue.PriQueue{
        &rq.background, &rq.normal, &rq.interactive,
    };
    for (queues) |q| {
        if (q.count == 0) continue;
        var idx: i32 = @as(i32, @intCast(q.count)) - 1;
        while (idx >= 0) : (idx -= 1) {
            const candidate = q.pids[@intCast(idx)];
            if (candidate >= MAX_PROCS) continue;
            const pcb = &process.procs[candidate];
            if (pcb.is_idle) continue;
            if (pcb.pinned_cpu != 0xFF) continue;
            if (@atomicLoad(bool, &pcb.job_stopped, .acquire)) continue;
            return candidate;
        }
    }
    return null;
}

/// Pull-on-idle work stealing. Called from kernelIdle (lock-clean) when a CPU
/// has drained its runqueue and is about to sleep. If a peer is backed up, move
/// one of its queued tasks to THIS CPU and return true so the caller dispatches
/// it now — instead of sleeping while a peer churns through a backlog and we
/// wait up to a full BALANCE_INTERVAL_TICKS (~50 ticks) for the BSP's periodic,
/// one-task-at-a-time push. Reuses migrate()'s two-rq-lock atomicity and its
/// current_pid stale-`kernel_esp` guard, so a task another CPU is mid-dispatch
/// is never stolen. Returns false (→ caller sleeps as before) when we already
/// have local work, no peer has a surplus, or the chosen task slips away.
pub fn tryStealWork() bool {
    const self_cpu = smp.myCpu().cpu_id;
    if (self_cpu >= smp.MAX_CPUS) return false;
    // Only steal when genuinely idle: never pull a peer's task ahead of our own
    // runnable work. (A task can become .ready on us between schedule() picking
    // idle and this check; if so, fall through — the normal path runs it.)
    if (effectiveLoad(self_cpu) != 0) return false;

    // Find the busiest peer.
    var busiest_cpu: u8 = 0xFF;
    var busiest_load: u16 = 0;
    var i: u8 = 0;
    while (i < smp.MAX_CPUS) : (i += 1) {
        if (i == self_cpu) continue;
        if (!smp.cpus[i].alive) continue;
        const load = effectiveLoad(i);
        if (load > busiest_load) {
            busiest_load = load;
            busiest_cpu = i;
        }
    }
    if (busiest_cpu == 0xFF) return false;
    // Only steal a genuine surplus. effectiveLoad counts the running task, so
    // load >= BALANCE_THRESHOLD (2) means >= 1 task is queued behind it: we take
    // a queued one and leave the peer its current task. Same threshold the
    // periodic balancer uses, so the two can't fight over the last task.
    if (busiest_load < BALANCE_THRESHOLD) return false;

    const pick = pickMigrationCandidate(busiest_cpu) orelse return false;
    return migrate(pick, self_cpu);
}

/// Map a `Priority` enum value to the matching PriQueue inside an Rq.
/// Tiny wrapper so runqueue.zig stays free of process.Priority.
inline fn rqQueueFor(rq: *runqueue.Rq, prio: Priority) *runqueue.PriQueue {
    return switch (prio) {
        .interactive => &rq.interactive,
        .normal => &rq.normal,
        .background => &rq.background,
    };
}

/// Add a pid to its assigned CPU's runqueue. Caller must have already
/// transitioned the pid into a runnable state. Idle PCBs are never
/// enqueued — they're picked via the dedicated `cpu.idle_pid` slot,
/// not via the rq scan. Same for unassigned (assigned_cpu == 0xFF)
/// PCBs that haven't been through `assignInitialCpu` yet.
///
/// Idempotent across ALL queues — same reasoning as rqLeave's full
/// scan: an out-of-band priority bump after enqueue could leave the
/// pid in the OLD priority queue, and a subsequent rqEnter that only
/// checked the current priority would double-enqueue (incrementing
/// nr_runnable without being able to find the pid for removal later).
///
/// CFS sleeper bonus: callers passing `from_sleep=true` (setState's
/// .sleeping → .ready transition) get vruntime bumped to
/// `max(vruntime, min_vruntime[band] - SLEEPER_CREDIT)`. Newly-created
/// tasks (first rqEnter, vruntime == 0) are seeded to min_vruntime[band]
/// + 1 so they don't immediately monopolize their band.
fn rqEnter(pid: usize, from_sleep: bool) void {
    const pcb = &process.procs[pid];
    // Targeted scheduler-invariant trace: dump on every rq mutation for
    // TRACE_PID (Q1's expected pid). Find which transition leaves pid
    // stuck "state=sleeping + in_rq=true" by reading the linear sequence
    // of setState/rqEnter/rqLeave events that crossed the bad state.
    // Remove after the wedge is rooted out.
    if (TRACE_PID != 0 and pid == TRACE_PID) {
        const ra = @returnAddress();
        debug.klog("[trace pid={d} cpu={d}] rqEnter from_sleep={any} state_before={d} assigned_cpu={d} ra=0x{X}\n", .{
            pid, smp.myCpu().cpu_id, from_sleep, @intFromEnum(pcb.state), pcb.assigned_cpu, ra,
        });
    }
    if (pcb.is_idle) return;
    // H4: snapshot assigned_cpu BEFORE lock acquire, then re-check under the
    // lock. A concurrent migrate updates pcb.assigned_cpu while holding both
    // rq locks; if it ran between our load and our lock acquire, we'd
    // otherwise enrol the pid in the OLD rq with assigned_cpu pointing at
    // the NEW cpu — permanent nr_runnable drift + lost migration.
    const cpu_idx_snap = @atomicLoad(u8, &pcb.assigned_cpu, .acquire);
    if (cpu_idx_snap == 0xFF) return;
    if (cpu_idx_snap >= smp.MAX_CPUS) return;
    const rq = &smp.cpus[cpu_idx_snap].runqueue;
    const f = rq.lock.acquireIrqSave();
    if (@atomicLoad(u8, &pcb.assigned_cpu, .acquire) != cpu_idx_snap) {
        // Migrate moved us between snapshot and lock acquire. Release and
        // retry against the fresh assigned_cpu. Tail-recursion bounded by
        // the practical migrate rate (a single rqEnter call should never
        // see more than 1-2 concurrent migrates).
        rq.lock.releaseIrqRestore(f);
        return rqEnter(pid, from_sleep);
    }
    defer rq.lock.releaseIrqRestore(f);
    const pid_u8: u8 = @intCast(pid);
    if (rq.interactive.contains(pid_u8)) {
        if (TRACE_PID != 0 and pid == TRACE_PID) debug.klog("[trace pid={d} cpu={d}] rqEnter SKIP — already in interactive\n", .{ pid, smp.myCpu().cpu_id });
        return; // already enqueued — idempotent
    }
    if (rq.normal.contains(pid_u8)) {
        if (TRACE_PID != 0 and pid == TRACE_PID) debug.klog("[trace pid={d} cpu={d}] rqEnter SKIP — already in normal\n", .{ pid, smp.myCpu().cpu_id });
        return;
    }
    if (rq.background.contains(pid_u8)) {
        if (TRACE_PID != 0 and pid == TRACE_PID) debug.klog("[trace pid={d} cpu={d}] rqEnter SKIP — already in background\n", .{ pid, smp.myCpu().cpu_id });
        return;
    }

    // CFS placement under the rq's own lock so a concurrent picker on the
    // same rq can't race against the vruntime adjustment.
    const band: usize = @intFromEnum(pcb.priority);
    const floor = rq.min_vruntime[band];
    if (pcb.vruntime == 0) {
        // Fresh PCB — seed one tick-equivalent above the floor so it
        // doesn't outrank everyone in its band immediately (the same
        // offset the old tick-unit code expressed as +1), keeping strict
        // ordering with any task currently sitting AT min.
        pcb.vruntime = floor +% VRUNTIME_SCALE;
    } else if (from_sleep) {
        // Sleeper bonus: bump near floor so the woken task gets to run
        // soon, but cap at its own historical vruntime so a long-running
        // task that briefly slept doesn't get a free reset. Saturating
        // subtract: if floor < SLEEPER_CREDIT (e.g., a band that hasn't
        // been touched yet — interactive on cpu1 before any task ran
        // there), credited stays at 0. Wrapping `-%` would underflow to
        // ~u64-max and immediately set vruntime to that, starving the
        // task forever (picker always sees it as worst-vruntime). This
        // bug surfaced as "editor stops accepting input after a few
        // chars" once the editor migrated to cpu1 and tried to wake
        // there.
        const credited: u64 = if (floor > SLEEPER_CREDIT) floor - SLEEPER_CREDIT else 0;
        if (pcb.vruntime < credited) pcb.vruntime = credited;
    }
    // Demote-to-ready (state .running → .ready in schedule()) leaves
    // vruntime as-is; the task already accumulated its slice via
    // checkPreempt/schedule's slice-end accounting.

    rqQueueFor(rq, pcb.priority).pushBack(pid_u8);
    rq.nr_runnable +%= 1;
    @import("../debug/pid_act.zig").record(
        pid, .rq_enter, @intFromEnum(pcb.priority), 0xFF, @returnAddress(),
    );
    if (TRACE_PID != 0 and pid == TRACE_PID) {
        debug.klog("[trace pid={d} cpu={d}] rqEnter DONE — pushed to band={d} nr_runnable={d}\n", .{
            pid, smp.myCpu().cpu_id, @intFromEnum(pcb.priority), rq.nr_runnable,
        });
    }
}

/// Remove a pid from its assigned CPU's runqueue. Idempotent — if the
/// pid isn't there (already dispatched, or never was), this is a no-op.
///
/// Scans ALL THREE priority queues, not just the one matching the PCB's
/// current priority. Reason: several callsites mutate `pcb.priority`
/// directly after the PCB has been enqueued (smp.pollAppLoad bumps
/// background→interactive; sysExec / desktop.foreground likewise). If
/// rqLeave only consulted the current priority, it would miss the pid
/// in the OLD priority's queue and leave a phantom entry — the audit
/// drift class first reproduced as `pid=3 state=4 assigned_cpu=1
/// in_rq=true` (process slept after a priority bump). Three queues of
/// MAX_PROCS=32 entries each is trivial to scan.
fn rqLeave(pid: usize) void {
    const pcb = &process.procs[pid];
    if (TRACE_PID != 0 and pid == TRACE_PID) {
        const ra2 = @returnAddress();
        debug.klog("[trace pid={d} cpu={d}] rqLeave ENTRY state={d} assigned_cpu={d} ra=0x{X}\n", .{
            pid, smp.myCpu().cpu_id, @intFromEnum(pcb.state), pcb.assigned_cpu, ra2,
        });
    }
    if (pcb.is_idle) return;
    // H4: snapshot+recheck same as rqEnter — migrate can move us during
    // the lock-acquire window.
    const cpu_idx_snap = @atomicLoad(u8, &pcb.assigned_cpu, .acquire);
    if (cpu_idx_snap == 0xFF) return;
    if (cpu_idx_snap >= smp.MAX_CPUS) return;
    const rq = &smp.cpus[cpu_idx_snap].runqueue;
    const f = rq.lock.acquireIrqSave();
    if (@atomicLoad(u8, &pcb.assigned_cpu, .acquire) != cpu_idx_snap) {
        rq.lock.releaseIrqRestore(f);
        return rqLeave(pid);
    }
    defer rq.lock.releaseIrqRestore(f);
    const pid_u8: u8 = @intCast(pid);
    const ra = @returnAddress();
    const pid_act = @import("../debug/pid_act.zig");
    if (rq.interactive.remove(pid_u8)) {
        rq.nr_runnable -%= 1;
        pid_act.record(pid, .rq_leave, @intFromEnum(Priority.interactive), 0xFF, ra);
        if (TRACE_PID != 0 and pid == TRACE_PID) debug.klog("[trace pid={d} cpu={d}] rqLeave REMOVED from interactive nr_runnable={d}\n", .{ pid, smp.myCpu().cpu_id, rq.nr_runnable });
        return;
    }
    if (rq.normal.remove(pid_u8)) {
        rq.nr_runnable -%= 1;
        pid_act.record(pid, .rq_leave, @intFromEnum(Priority.normal), 0xFF, ra);
        if (TRACE_PID != 0 and pid == TRACE_PID) debug.klog("[trace pid={d} cpu={d}] rqLeave REMOVED from normal nr_runnable={d}\n", .{ pid, smp.myCpu().cpu_id, rq.nr_runnable });
        return;
    }
    if (rq.background.remove(pid_u8)) {
        rq.nr_runnable -%= 1;
        pid_act.record(pid, .rq_leave, @intFromEnum(Priority.background), 0xFF, ra);
        if (TRACE_PID != 0 and pid == TRACE_PID) debug.klog("[trace pid={d} cpu={d}] rqLeave REMOVED from background nr_runnable={d}\n", .{ pid, smp.myCpu().cpu_id, rq.nr_runnable });
        return;
    }
    if (TRACE_PID != 0 and pid == TRACE_PID) debug.klog("[trace pid={d} cpu={d}] rqLeave NO-OP — not in any queue\n", .{ pid, smp.myCpu().cpu_id });
}

/// Centralized state setter. ALL non-CAS state writes go through here so
/// rq membership stays in sync with the state byte. Skip-and-return when
/// new == old (no-op). Order matters: leave the rq BEFORE the state-byte
/// store on a runnable→non-runnable transition (so a concurrent picker
/// that sees us still .ready can also still find us in the rq); enter
/// the rq AFTER the state-byte store on the reverse (so an audit between
/// the two never sees "in rq but not .ready").
///
/// Phase 6: after rqEnter, fire a preempt IPI to the assigned CPU when
/// appropriate (target is idle or running a lower-priority task). Keeps
/// IPC wake latency at ~μs instead of waiting up to a 10 ms timer tick.
/// Per-pid bracket counter for the rq audit. Incremented at the top of
/// setState (BEFORE the state CAS); decremented at the bottom (AFTER the
/// rq op). Audit skips pids whose counter is non-zero, structurally
/// eliminating the "CAS landed but rqEnter hasn't" transient FP. Counter
/// (not bool) because the same pid can hit setState concurrently from
/// multiple CPUs — the CAS loop reconciles state, but each caller's
/// bracket must independently increment/decrement.
pub var setstate_in_flight: [MAX_PROCS]u8 = [_]u8{0} ** MAX_PROCS;

/// Per-pid setState serializing lock. Held across the CAS + rq op so a
/// concurrent setState on the SAME pid (e.g., cpu1's nvme IRQ wake doing
/// .sleeping→.ready while cpu0's preempt does .running→.ready) cannot
/// interleave the state byte write with the rq insert/remove. Without
/// this, a wake's `CAS .sleeping→.ready then rqEnter` could overlap with
/// a picker's `CAS .ready→.running then rqLeave`: picker's rqLeave finds
/// pid not yet in rq (no-op), wake's rqEnter then inserts pid AFTER
/// picker already dispatched it — pid ends up .running AND in rq. On the
/// next .running→.sleeping transition, was_ready=false skips rqLeave and
/// pid stays in rq as .sleeping forever; picker keeps fishing it out,
/// transitioning .sleeping→.running via CAS, dispatching, blockOn-yields
/// immediately — tight schedule-park loop, system wedges.
/// Caught 2026-05-19: audit reported `pid=2 state=3 in_rq=true want=false`
/// right before all four pids stalled on (.nvme_io, target=0x10000).
var setstate_locks: [MAX_PROCS]SpinLock = [_]SpinLock{.{}} ** MAX_PROCS;

// =============================================================================
// Mode-A wedge diagnostics — candidate-claim-loop spin tracking.
//
// schedule()'s claim loop (see below) re-picks a candidate whenever another CPU
// wins the CAS for the same PID first. Under a sched_yield storm + work
// stealing, two CPUs can fight over the same runqueue entries and one (cpu0,
// where the desktop is pinned) can livelock re-picking with IF=0 — starving its
// own 100Hz timer IRQ until the watchdog halts it. These per-CPU counters let
// the wedge autopsy SEE that spin: sched_loop_iters[cpu] is the retry count of
// the schedule() currently running on that CPU (reset to 0 between calls), and
// sched_loop_max[cpu] is the high-water mark ever observed. Only the owning CPU
// writes its own slots; the autopsy reads them cross-CPU with relaxed loads.
// Paired with the NMI profiler's spin-target histogram: a large in-flight value
// here + ZERO spin-target samples there = the claim loop is the live spin (not
// a SpinLock.acquire wait), which is exactly the Mode-A signature.
// =============================================================================
var sched_loop_iters: [smp.MAX_CPUS]u64 = [_]u64{0} ** smp.MAX_CPUS;
var sched_loop_max: [smp.MAX_CPUS]u64 = [_]u64{0} ** smp.MAX_CPUS;

/// The live candidate-claim retry count for `cpu` (0 if not currently in the
/// loop). Read cross-CPU by the watchdog's host-pause gate: a high value means
/// the CPU is livelocking schedule()'s claim loop with IF=0 (Mode-A) and must
/// be HALTED, not ridden out as a host pause.
pub fn claimLoopInFlight(cpu: usize) u64 {
    if (cpu >= smp.MAX_CPUS) return 0;
    return @atomicLoad(u64, &sched_loop_iters[cpu], .monotonic);
}

/// Dump per-CPU claim-loop retry counts. Called from the wedge autopsy. A large
/// in-flight value names the claim loop as the live, IF=0 spin; a large
/// max-ever with 0 in-flight says it spikes under contention but recovers.
pub fn dumpSchedLoopStats() void {
    const serial = @import("../debug/serial.zig");
    serial.print("[sched-loop] schedule() candidate-claim retry counts (in-flight = live spin):\n", .{});
    var c: usize = 0;
    var any = false;
    while (c < smp.MAX_CPUS) : (c += 1) {
        const inflight = @atomicLoad(u64, &sched_loop_iters[c], .monotonic);
        const mx = @atomicLoad(u64, &sched_loop_max[c], .monotonic);
        if (inflight == 0 and mx <= 1) continue;
        any = true;
        serial.print("  cpu{d}: in-flight={d} max-ever={d}{s}\n", .{
            c, inflight, mx,
            if (inflight > 64) "  <-- LIVELOCK (re-picking in the claim loop NOW, IF=0)" else "",
        });
    }
    if (!any) serial.print("  (no CPU has spun the claim loop more than once)\n", .{});
}

/// Classify a raw lock address as one of the scheduler's INTERNAL, normally-
/// unregistered locks — the ones the registry-based [lock-dump] can't name.
/// Writes the family index into `idx_out`. Returns a static family name or
/// null. Covers setstate_locks[] (per-PID, indexed) and each CPU's sched_lock
/// (lives in CpuLocal). Used by the wedge profiler to label a bare lock addr.
pub fn classifySchedLock(addr: usize, idx_out: *usize) ?[]const u8 {
    idx_out.* = 0;
    if (addr == 0) return null;
    const ss_base = @intFromPtr(&setstate_locks[0]);
    const ss_end = ss_base + @sizeOf(SpinLock) * setstate_locks.len;
    if (addr >= ss_base and addr < ss_end) {
        idx_out.* = (addr - ss_base) / @sizeOf(SpinLock);
        return "setstate_locks";
    }
    var c: usize = 0;
    while (c < smp.MAX_CPUS) : (c += 1) {
        if (addr == @intFromPtr(&smp.cpus[c].sched_lock)) {
            idx_out.* = c;
            return "sched_lock";
        }
    }
    return null;
}

pub fn setState(pid: usize, new_state: State) void {
    if (pid >= MAX_PROCS) return;
    const lock_flags = setstate_locks[pid].acquireIrqSave();
    defer setstate_locks[pid].releaseIrqRestore(lock_flags);
    _ = @atomicRmw(u8, &setstate_in_flight[pid], .Add, 1, .acquire);
    defer _ = @atomicRmw(u8, &setstate_in_flight[pid], .Sub, 1, .release);
    const pcb = &process.procs[pid];
    const state_ptr: *u8 = @as(*u8, @ptrCast(&pcb.state));

    // Atomically claim the state transition via CAS. Without this, two
    // concurrent setState calls (e.g., cpu0's wakeExpired doing
    // .sleeping→.ready while cpu1's killProcess does .running→.zombie)
    // could both pass the load-then-decide check based on the same
    // pre-transition state, then race in the rq op block: rqLeave runs
    // before rqEnter, finds no entry to remove, doesn't decrement, then
    // rqEnter adds and increments → permanent nr_runnable / queue
    // drift, and the pid gets stuck in .ready but invisible to the
    // picker (or vice versa).
    //
    // The CAS loop ensures exactly one setState call wins each transition
    // for a given old→new pair. Concurrent calls either find their
    // expected-old already changed and return (no-op) or retry. After
    // the CAS succeeds, only THIS caller does the rq ops for THIS
    // specific old→new transition.
    var old_byte: u8 = @atomicLoad(u8, state_ptr, .acquire);
    const new_byte: u8 = @intFromEnum(new_state);
    while (true) {
        if (old_byte == new_byte) {
            if (TRACE_PID != 0 and pid == TRACE_PID) {
                debug.klog("[trace pid={d} cpu={d}] setState NOOP old=={d} new=={d} ra=0x{X}\n", .{
                    pid, smp.myCpu().cpu_id, old_byte, new_byte, @returnAddress(),
                });
            }
            return; // already in this state
        }
        // H1: Terminal-state guard. Once a pid is .zombie or .unused, the
        // ONLY legitimate transition out is .zombie→.unused (reaper) or
        // .unused→.loading (allocator). All other transitions out of a
        // terminal state are races — wake() reads state=.sleeping plain,
        // a concurrent killer flips state to .zombie, then wake's
        // setState(.ready) here CAS-retries against the new .zombie value
        // and resurrects the zombie as .ready. Filter the retry path so
        // a peer's terminal-state flip absorbs cleanly.
        if (old_byte == @intFromEnum(State.zombie) and new_state != .unused) {
            if (TRACE_PID != 0 and pid == TRACE_PID) {
                debug.klog("[trace pid={d}] setState ABSORB zombie→{d} (terminal guard)\n", .{ pid, new_byte });
            }
            return;
        }
        if (old_byte == @intFromEnum(State.unused) and new_state != .loading) {
            if (TRACE_PID != 0 and pid == TRACE_PID) {
                debug.klog("[trace pid={d}] setState ABSORB unused→{d} (terminal guard)\n", .{ pid, new_byte });
            }
            return;
        }
        const cas = @cmpxchgStrong(u8, state_ptr, old_byte, new_byte, .acq_rel, .acquire);
        if (cas == null) break; // we own this transition
        old_byte = cas.?;        // someone else changed state — retry with their value
    }
    const old_state: State = @enumFromInt(old_byte);
    if (TRACE_PID != 0 and pid == TRACE_PID) {
        debug.klog("[trace pid={d} cpu={d}] setState CAS-OK {d}->{d} ra=0x{X}\n", .{
            pid, smp.myCpu().cpu_id, old_byte, new_byte, @returnAddress(),
        });
    }
    // Per-PID activity ring stamp. Logged AFTER the CAS succeeded so the
    // ring entry corresponds to a real transition (no-op early-returns
    // above leave no trace, by design).
    @import("../debug/pid_act.zig").record(
        pid, .setstate, old_byte, new_byte, @returnAddress(),
    );
    const was_ready = (old_state == .ready);
    const is_ready = (new_state == .ready);
    // Only .sleeping→.ready gets the CFS sleeper bonus. Demote
    // .running→.ready (preempt) keeps vruntime as-accumulated;
    // .loading→.ready (fresh task) gets the seed-to-min path inside
    // rqEnter (vruntime == 0 sentinel).
    const from_sleep = (old_state == .sleeping);

    // CFS: leaving .running for ANY reason (.ready preempt, .sleeping
    // block, .zombie exit) is a slice-end. Flush accumulated ticks
    // into vruntime now so the next picker sees a fair value.
    if (old_state == .running and new_state != .running) {
        accountRunningTick(pid, false);
    }

    if (was_ready and !is_ready) rqLeave(pid);
    if (!was_ready and is_ready) {
        rqEnter(pid, from_sleep);
        maybePreemptOnWake(pid);
    }
}

/// CFS: bump current.vruntime by ticks consumed since slice start, and
/// raise the per-band min_vruntime floor so a future sleeper bonus or
/// migration translation reflects this CPU's actual progress. Called
/// from schedule() at every preempt/yield point AND from checkPreempt()
/// once per timer tick.
///
/// `commit_slice_start` resets slice_start_tick to tick_count so the
/// next call accounts only the new sub-slice. Schedule passes false
/// when it's about to setState the task off-CPU (the slice is fully
/// flushed, no need to commit a fresh start); checkPreempt passes true
/// because the task continues running.
fn accountRunningTick(pid: usize, commit_slice_start: bool) void {
    const pcb = &process.procs[pid];
    if (pcb.is_idle) return;
    const now = process.tick_count;
    const start = pcb.slice_start_tick;
    if (now <= start) {
        if (commit_slice_start) pcb.slice_start_tick = now;
        return;
    }
    const delta = now - start;
    // Weighted CFS accrual in fixed-point VRUNTIME_SCALE units. The old
    // "TRIAGE: nice scaling temporarily disabled" state wasn't about the
    // multiply/divide being slow — the math itself was broken at tick
    // granularity: `delta * 1024 / weight` truncates to ZERO whenever
    // weight > delta*1024 (i.e. every negative nice at 1-tick deltas), so
    // a boosted task never accrued vruntime, stayed minimum in its band,
    // and starved its peers. The VRUNTIME_SCALE numerator keeps the
    // quotient non-zero (nice=-20, delta=1 → 11 units) while nice=0 stays
    // exact (delta * VRUNTIME_SCALE). This makes sys_setpriority and the
    // `nice` app actually do something — pcb.nice was user-settable but
    // scheduler-ignored the whole time the triage comment sat here.
    const weight = niceToWeight(pcb.nice);
    pcb.vruntime +%= (delta * VRUNTIME_SCALE * NICE_0_WEIGHT) / weight;
    if (commit_slice_start) pcb.slice_start_tick = now;

    // Bump per-band min_vruntime floor on this rq if the running task
    // pushed past it. (Other tasks on the rq advance their own vruntime
    // when they run; the floor monotonically follows the slowest one.)
    if (pcb.assigned_cpu < smp.MAX_CPUS) {
        const rq = &smp.cpus[pcb.assigned_cpu].runqueue;
        const band: usize = @intFromEnum(pcb.priority);
        // Floor = min over (running's vruntime, smallest queued vruntime).
        // Running pushes the floor up; queued tasks are at-or-above.
        const cur_floor = rq.min_vruntime[band];
        if (pcb.vruntime > cur_floor) {
            // Don't take rq.lock here — the floor is advisory (off-by-one
            // doesn't break correctness, only the precision of sleeper
            // bonuses). Atomic store keeps the read side coherent.
            @atomicStore(u64, &rq.min_vruntime[band], pcb.vruntime, .release);
        }
    }
}

/// CFS per-tick vruntime maintenance — called from handleIRQ0 on every
/// real (non-soft-yield) timer firing. Bumps the running task's vruntime
/// by ticks consumed since slice start and pushes the per-band
/// min_vruntime floor up. The actual preempt decision is *not* made
/// here — handleIRQ0's natural per-tick `from_user` schedule path
/// already preempts at every quantum, and pickNext now picks min-vruntime
/// within each band. So all checkPreempt needs to do is keep vruntime
/// accurate so pickNext's selection is fair.
///
/// (Previous draft set `cpu.pending_soft_yield = true` to force a
/// kernel-mode preempt; that breaks the next tick's `was_soft_yield`
/// inference and was scrapped. Kernel tasks like desktop run to their
/// natural yield points, which is correct behavior.)
pub fn checkPreempt() void {
    const cpu = smp.myCpu();
    const cur = cpu.current_pid orelse return;
    if (cur >= MAX_PROCS) return;
    const pcb = &process.procs[cur];
    if (pcb.is_idle) return;
    if (pcb.state != .running) return;
    accountRunningTick(cur, true);
}

/// Phase 6: fire a resched IPI to the woken pid's assigned CPU when:
///   - target is a different CPU than caller (same-cpu wakes get handled
///     by the local schedule loop on the next preempt, no IPI needed),
///   - AND target is currently running its idle PCB OR a strictly lower-
///     priority task.
///
/// Reuses kill_kick_vector — the handler is just `schedule()`, which on
/// the receiver checks exit_requested + demotes prev + pickNext, doing
/// exactly what a preempt-on-wake needs. (Naming: the vector handles
/// "any reason to reschedule NOW" — kill, wake, or future events.)
fn maybePreemptOnWake(pid: usize) void {
    const pcb = &process.procs[pid];
    if (pcb.is_idle) return;
    const target_cpu_id = pcb.assigned_cpu;
    if (target_cpu_id == 0xFF) return;
    if (target_cpu_id >= smp.MAX_CPUS) return;

    const my_cpu = smp.myCpu();
    if (target_cpu_id == my_cpu.cpu_id) return; // same-cpu, local schedule will pick

    const target_cpu = &smp.cpus[target_cpu_id];
    if (!target_cpu.alive) return;

    const should_preempt = blk: {
        const target_cur = target_cpu.current_pid orelse break :blk true;
        if (target_cur >= MAX_PROCS) break :blk false;
        if (process.procs[target_cur].is_idle) break :blk true;
        break :blk @intFromEnum(pcb.priority) > @intFromEnum(process.procs[target_cur].priority);
    };
    if (!should_preempt) return;

    if (kill_kick_vector) |v| {
        const apic = @import("../time/apic.zig");
        apic.sendIPI(target_cpu.lapic_id, v);
    }
}

/// Force `pid`'s owning CPU to take a reschedule decision NOW. Used by
/// job-control resume (signals.send clearing job_stopped on SIGCONT/SIGKILL):
/// the resumed task sits .ready-but-skipped in its runqueue, and if its CPU is
/// idle/tickless it won't re-pick it until the next timer fire. The kill-kick
/// IPI handler is schedule(), so this makes that CPU re-run pickNext at once.
/// No-op for the local CPU (the running schedule loop will pick it on the next
/// preempt) or a dead/out-of-range target. Mirrors maybePreemptOnWake's
/// remote-CPU guard but unconditional (no priority gate — resume always wants
/// the task reconsidered).
pub fn kickReschedule(pid: usize) void {
    if (pid >= MAX_PROCS) return;
    const target_cpu_id = process.procs[pid].assigned_cpu;
    if (target_cpu_id >= smp.MAX_CPUS) return;
    if (target_cpu_id == smp.myCpu().cpu_id) return; // same-cpu: local schedule picks it
    const target_cpu = &smp.cpus[target_cpu_id];
    if (!target_cpu.alive) return;
    if (kill_kick_vector) |v| {
        @import("../time/apic.zig").sendIPI(target_cpu.lapic_id, v);
    }
}

/// Two CAS sites (allocSlot's .unused→.loading and schedule()'s pickNext
/// claim .ready→.running) flip the state byte directly without going
/// through setState — they need atomicity that wraps both the read and
/// the write. Once the CAS succeeds they call this to keep the rq in
/// sync with the .ready→non-ready half of the transition.
fn rqOnLeaveReady(pid: usize) void {
    rqLeave(pid);
}

/// Per-tick audit. Two checks:
///   (1) Per-CPU rq internal consistency: `totalCount == nr_runnable`.
///       Both fields update under the rq.lock so no FP class applies; any
///       mismatch is a real bookkeeping bug.
///   (2) Per-pid cross-check: state==.ready ⟺ pid is in its assigned_cpu's
///       rq. This one is FP-prone — setState's state CAS happens BEFORE
///       rqEnter (deliberate ordering documented at setState — chosen to
///       avoid the *reverse* "in rq but not .ready" class). The per-pid
///       `setstate_in_flight[pid]` bracket counter is set BEFORE the CAS
///       and cleared AFTER the rq op; the cross-check skips bracketed
///       pids, structurally eliminating the FP. (Caught 2026-05-19 once
///       the pcb-invariant FP was suppressed and the rq drift became
///       visible — earlier "retry across N samples" approach reported
///       persistent drift but couldn't distinguish a real bug from a
///       slow-window transient.)
pub fn rqAudit() void {
    var i: usize = 0;
    while (i < smp.MAX_CPUS) : (i += 1) {
        if (!smp.cpus[i].alive) continue;
        const rq_count = smp.cpus[i].runqueue.totalCount();
        const rq_nr = smp.cpus[i].runqueue.nr_runnable;
        if (rq_count != rq_nr) {
            debug.klog("[rq-audit] cpu{d} totalCount={d} != nr_runnable={d}\n", .{ i, rq_count, rq_nr });
            rqAuditFull();
            return;
        }
    }
    rqAuditFull();
}

/// Slow walk that names the drifting pid(s). Skips any pid whose
/// `setstate_in_flight` counter is non-zero — that pid is mid-setState
/// on another CPU and the state-byte ↔ rq-membership cross-check would
/// fire spuriously inside the CAS-to-rqEnter window. The bracket is set
/// at the top of setState and cleared at the bottom; on no-CPU-in-flight
/// the cross-check is structurally consistent.
fn rqAuditFull() void {
    var p: usize = 0;
    while (p < MAX_PROCS) : (p += 1) {
        if (process.procs[p].is_idle) continue;
        if (@atomicLoad(u8, &setstate_in_flight[p], .acquire) > 0) continue;
        const s = @atomicLoad(u8, @as(*const u8, @ptrCast(&process.procs[p].state)), .acquire);
        const want_in_rq = (s == @intFromEnum(State.ready));
        const cpu_idx = process.procs[p].assigned_cpu;
        const in_rq = if (cpu_idx == 0xFF or cpu_idx >= smp.MAX_CPUS) false else
            smp.cpus[cpu_idx].runqueue.contains(@intCast(p));
        if (want_in_rq == in_rq) continue;
        // Re-check bracket after the in_rq load: a setState may have started
        // between our skip-check and the in_rq read. If now in-flight, skip.
        if (@atomicLoad(u8, &setstate_in_flight[p], .acquire) > 0) continue;
        debug.klog(
            "[rq-audit] pid={d} state={d} assigned_cpu={d} in_rq={any} want={any}\n",
            .{ p, s, cpu_idx, in_rq, want_in_rq },
        );
    }
}

/// Bootstrap the BSP's first dispatch. Creates the BSP idle + desktop
/// kernel task, then switches THIS context (kmain's bootstrap stack) into
/// the desktop task. kmain's stack is abandoned — we never come back. From
/// this point on, every CPU always has a real PCB as current; `schedule()`
/// no longer needs the legacy "scheduler context" path.
pub fn enterFirstTask(desktop_entry: usize) noreturn {
    // Disable IRQs across the BSP cutover. `cpu.current_pid = desktop_pid`
    // below makes the B.3 stack-alias detector expect desktop's kstack,
    // but RSP only swaps over to it inside `switchToCall`. A timer IRQ
    // landing in the gap saw kmain's boot-stack RSP under desktop's
    // expected slot and panicked. switchToCall uses `ret` (not iretq)
    // so EFLAGS isn't restored — desktop.taskEntry must `sti` after the
    // PML4[0] drop. Mirror in enterFirstTaskAp.
    asm volatile ("cli");

    // BSP idle (legacy `idle_pid` global also set).
    process.createIdleProcess();
    // Desktop needs a 64 KB kstack — its init+render path was sized for
    // the 32 KB boot stack and overflows the 16 KB pool slot.
    const desktop_pid = process.createKernelTask(desktop_entry, "desktop", 0, .interactive, 64 * 1024) orelse {
        @panic("enterFirstTask: failed to create desktop kernel task");
    };
    const cpu = smp.myCpu();
    // Mark desktop as running on this cpu BEFORE we switch — gdt.setTssRsp0
    // and the schedule machinery expect cpu.current_pid to track reality.
    // setState (.ready→.running) also rqLeave's the desktop pid so it
    // doesn't sit on the rq while it's actively dispatched.
    @import("../debug/pid_trace.zig").setCurrentPid(cpu, desktop_pid);
    setState(desktop_pid, .running);
    process.procs[desktop_pid].last_cpu = 0;
    gdt.setTssRsp0(desktop_pid, process.procs[desktop_pid].kernel_stack_top);

    // First dispatch — kmain's stack is abandoned. Pass null prev_save
    // so switchTo asm skips the save entirely (no PCB to write into).
    @import("sched_asm.zig").switchToCall(null, process.procs[desktop_pid].kernel_esp);
    unreachable;
}

/// AP-side counterpart to enterFirstTask. The caller (smp.apEntry) has
/// already called createKernelIdle and stashed the new pid into
/// cpus[my_id].idle_pid. We dispatch into that idle PCB so the AP runs
/// as a real kernel task from the very first instant — no apEntry-loop
/// "scheduler context" sitting on the trampoline stack. After this call
/// the AP trampoline's stack is abandoned (same fate as kmain's stack
/// after enterFirstTask).
pub fn enterFirstTaskAp(ap_idle_pid: usize) noreturn {
    // Same race as enterFirstTask — see comment there. kernelIdle's
    // `sti; hlt` re-enables IRQs on its first loop iteration, so no
    // explicit sti is needed downstream.
    asm volatile ("cli");

    const cpu = smp.myCpu();
    @import("../debug/pid_trace.zig").setCurrentPid(cpu, ap_idle_pid);
    // Idle PCB — rqLeave is a no-op (idles never enter the rq), but route
    // through setState anyway for path uniformity.
    setState(ap_idle_pid, .running);
    process.procs[ap_idle_pid].last_cpu = cpu.cpu_id;
    gdt.setTssRsp0(ap_idle_pid, process.procs[ap_idle_pid].kernel_stack_top);

    // First dispatch — trampoline stack is abandoned. Same null-prev_save
    // rationale as enterFirstTask: no PCB to write into.
    @import("sched_asm.zig").switchToCall(null, process.procs[ap_idle_pid].kernel_esp);
    unreachable;
}

/// Linear scan of a single priority queue picking the pid with the
/// smallest `vruntime`, skipping any that are doomed (exit_requested),
/// blocked (wait_kind != .none), or match `exclude_pid`. Returns null
/// if the queue has no eligible pid.
///
/// Ties broken by FIFO position (smaller index = earlier-enqueued).
/// O(N) where N <= MAX_PROCS = 32 per queue — fine without an rb-tree.
fn pickMinVruntime(q: *const runqueue.PriQueue, exclude_pid: ?u8) ?u8 {
    var best: ?u8 = null;
    var best_vr: u64 = std.math.maxInt(u64);
    var i: u8 = 0;
    while (i < q.count) : (i += 1) {
        const pid: u8 = q.pids[i];
        if (pid >= MAX_PROCS) continue;
        if (exclude_pid) |xp| if (pid == xp) continue;
        if (@atomicLoad(bool, &process.procs[pid].exit_requested, .acquire)) continue;
        // Atomic read — wait_kind is tagged (a): setWait stores it with
        // .release under the waiter's setstate lock, which this picker
        // does NOT hold (it holds rq.lock). Matches waitsOn's discipline.
        if (@atomicLoad(u8, @as(*const u8, @ptrCast(&process.procs[pid].wait_kind)), .acquire) != @intFromEnum(WaitKind.none)) continue;
        // Job-control stopped (SIGSTOP/SIGTSTP): skip so it consumes no CPU.
        // It sits .ready in the rq until SIGCONT/SIGKILL clears the flag (see
        // signals.stopForJobControl / send()); this is the single dispatch
        // chokepoint that realizes "stopped" — there is no other path to CPU.
        if (@atomicLoad(bool, &process.procs[pid].job_stopped, .acquire)) continue;
        const vr = process.procs[pid].vruntime;
        if (best == null or vr < best_vr) {
            best = pid;
            best_vr = vr;
        }
    }
    return best;
}

/// Pick the next runnable PCB from THIS CPU's per-CPU runqueue, in
/// priority-band order (interactive → normal → background). Within each
/// non-empty band, the pid with the smallest `vruntime` wins (CFS-style
/// fairness within a band) — no longer FIFO.
///
/// Phase 4's `exclude_pid` semantics are preserved: when set, Phase A
/// prefers any other runnable pid across ALL bands; only if no
/// alternative exists does Phase B fall back to a band containing
/// exclude_pid. Schedule passes `cpu.current_pid` here, so a task that
/// just finished its quantum doesn't immediately re-pick itself when
/// there's any other runnable work — even at lower priority.
///
/// Filters:
///   - `exit_requested`: pid is being killed; skip so pickNext can't
///     dispatch a doomed pid between kill signal and target's destroy.
///   - `wait_kind != .none`: defensive belt-and-suspenders. setState
///     removes blocked pids from the rq, so this shouldn't trip; if it
///     does, the audit at 1/64 already caught the drift and we'd rather
///     skip than dispatch into a wait.
///
/// CPU affinity is structural: a pid is in rq[pid.assigned_cpu] only.
/// No two-pass affinity scan; no idle filter (idles aren't enqueued).
pub fn pickNext(exclude_pid: ?u8) ?usize {
    smp.verifyEndCanary();
    @import("../debug/iretq_canary.zig").check(@src());

    const cpu = smp.myCpu();

    // Pre-suspend quiesce (S3 CP2b-2c): steer every AP to its idle PCB so its
    // current task is descheduled — switchTo saves the task's context into its PCB
    // (surviving S3 → re-dispatched on resume) — and the AP can reach kernelIdle's
    // lock-free park point instead of re-dispatching work into the suspend. The BSP
    // is exempt: it runs the shutdown syscall driving the suspend and must NOT be
    // steered away from it. Gated on the cheap quiesceRequested() bool, so normal
    // scheduling is untouched. Returns before taking rq.lock (the idle fallback
    // below doesn't need it either).
    if (smp.quiesceRequested() and !smp.isBSP()) {
        if (cpu.idle_pid) |idle| {
            if (process.procs[idle].idle_cpu == cpu.cpu_id) return idle;
        }
    }

    const rq = &cpu.runqueue;
    // M5: hold rq.lock across the pickMinVruntime walks. A peer CPU's
    // setState→rqEnter (waking a pid whose assigned_cpu = this cpu) can
    // mutate q.pids[]/q.count concurrently with our scan; without the
    // lock, q.count shifts under us and pickMinVruntime indexes past
    // the new count or reads a pid that was just shifted out.
    const f = rq.lock.acquireIrqSave();
    defer rq.lock.releaseIrqRestore(f);
    const queues = [_]*const runqueue.PriQueue{
        &rq.interactive,
        &rq.normal,
        &rq.background,
    };

    // Phase A: prefer the lowest-vruntime pid in each band, walking
    // bands highest-priority-first. Excludes exclude_pid in this pass.
    if (exclude_pid) |_| {
        for (queues) |q| {
            if (pickMinVruntime(q, exclude_pid)) |pid| return pid;
        }
    }

    // Phase B: no other candidate — accept exclude_pid (or scan when no
    // exclusion was specified).
    for (queues) |q| {
        if (pickMinVruntime(q, null)) |pid| return pid;
    }

    // Fallback: this CPU's own idle PCB.
    if (cpu.idle_pid) |idle| {
        if (process.procs[idle].idle_cpu == cpu.cpu_id) return idle;
    }
    return null;
}

// =============================================================================
// Kill-kick IPI: synchronous "evict pid from any CPU" primitive
// =============================================================================
//
// killProcessWithStatus tears down a process's address space, ELF buf, and
// PCB synchronously on the killer's CPU. If the victim pid is currently
// running on ANOTHER CPU (.running on cpu1 while cpu0 issues the kill), two
// races fire:
//
//   1. cpu1's next schedule() does `movq %rsp, &procs[pid].kernel_esp` (the
//      switchTo save) AFTER cpu0 zeroed expected_kstack_tops[pid]. The kesp
//      watch's whitelist requires expected != 0 → panic on a benign-looking
//      switchTo. Reproduced via test/stress_kill_race.zig (boot_mode=6).
//
//   2. cpu0's vmm.destroyAddressSpace frees PT pages while cpu1 is still
//      walking them on the dying CR3. Latent — TLB usually masks it but
//      a freed PT page reused for something else corrupts cpu1's view.
//
// Fix: before teardown, IPI any CPU running pid to force a context switch
// off it. The IPI handler just calls schedule() — landing in any IRQ +
// schedule's natural pickNext is enough to swap pid out (it's about to
// flip to .zombie/.unused, so even if pickNext sees it as .ready briefly,
// the wait loop re-IPIs). After the wait, no CPU is on pid's CR3 or
// kstack, and teardown is exclusive.
//
// Pairs with the schedule() defense-in-depth in prev_save selection:
// `expected_kstack_tops[cur] == 0` redirects to dead-letter rather than
// writing to a corpse PCB. That guard catches anything this IPI sync misses.
var kill_kick_vector: ?u8 = null;

fn killKickHandler() callconv(.c) void {
    const cpu = smp.myCpu();
    if (cpu.cpu_id < smp.MAX_CPUS) process.kick_handler_runs[cpu.cpu_id] +%= 1;
    // Receiving CPU: force a reschedule. The currently-running task may be
    // the kill target — schedule()'s exit_requested escalation tears it
    // down on its own kstack, and the killer's spin loop in
    // killProcessWithStatus (case 2) sees the state leave .running.
    //
    // Shape D: do NOT call schedule() directly here. This handler dispatches
    // through DynIrqStub, whose body now runs on the per-CPU isr_stack — a
    // direct schedule()/switchTo would save an isr_stack RSP into the
    // preempted task's kernel_esp (the IST=1-class corruption). Defer via the
    // per-CPU flag instead; DynIrqStub's epilogue (check_and_preempt_dynirq)
    // runs schedule() on the task kstack, in the same interrupt return, with
    // the correct RSP. Matches the nvme/virtio deferred-preempt discipline.
    cpu.dynirq_preempt_pending = true;
}

/// Allocate + register the dynamic IRQ vector for kill-kick. Must be called
/// AFTER smp.init() (so cpu.alive[] is populated). Falls back to "no IPI"
/// if vectors are exhausted; callers degrade to natural-preemption timing.
pub fn initKillKickIpi() void {
    const idt = @import("../cpu/idt.zig");
    const v = idt.allocDynVector() orelse {
        debug.klog("[kill] no dyn vector free — kill-kick disabled (degrades to natural preempt)\n", .{});
        return;
    };
    idt.registerIrq(v, killKickHandler);
    kill_kick_vector = v;
    debug.klog("[kill] IPI vector 0x{X} registered for kill-kick\n", .{v});
}

/// Expose the kill-kick vector to non-process callers (e.g. drivers
/// wanting to wake other CPUs from `sti; hlt`). Returns null before
/// `initKillKickIpi()` has run.
pub fn kickVector() ?u8 {
    return kill_kick_vector;
}

// =============================================================================
// Wake-only IPI vector — distinct from kill-kick because the latter calls
// schedule() which demotes the receiver's current task. For "wake the CPU
// out of hlt so it re-checks an in-memory flag" (e.g. virtio-gpu completion
// while a syscall waits in sti+hlt) we need the OPPOSITE: do not preempt
// the woken task; let iretq restore its hlt+1 RIP and let the wait loop
// re-poll. A no-op handler does exactly that.
// =============================================================================

var wake_ipi_vector: ?u8 = null;

fn wakeOnlyHandler() callconv(.c) void {
    const cpu_id = smp.myCpu().cpu_id;
    if (cpu_id < smp.MAX_CPUS) process.wake_handler_runs[cpu_id] +%= 1;
    // Intentionally empty — the IRQ delivery itself is the work. By NOT
    // calling schedule(), we don't demote the receiver's current task.
    // iretq pops the original kernel frame; if the receiver was in hlt,
    // execution resumes at hlt+1 and any wait loop above re-checks its
    // condition.
}

pub fn initWakeIpi() void {
    const idt = @import("../cpu/idt.zig");
    const v = idt.allocDynVector() orelse {
        debug.klog("[wake] no dyn vector free — wake-IPI disabled\n", .{});
        return;
    };
    idt.registerIrq(v, wakeOnlyHandler);
    wake_ipi_vector = v;
    debug.klog("[wake] IPI vector 0x{X} registered for wake-only\n", .{v});
}

pub fn wakeVector() ?u8 {
    return wake_ipi_vector;
}

/// Linux-style scheduler. Called as a regular function from anywhere that
/// wants to yield (handleIRQ0 on preemption, sysSleep / sysYield / pipe
/// block, sysExit, desktop.run main loop). Does not take or return an RSP
/// — context switching happens via `switchTo` (kernel→kernel `ret`).
///
/// Behavior: cpu.current_pid is always non-null (BSP runs desktop or its
/// idle, APs run their per-CPU idle). schedule picks the next ready task,
/// falling back to this CPU's idle PCB if no user/kernel task is ready;
/// when next == current, it short-circuits and returns immediately.
///
/// Locking: each CPU holds its own `sched_lock`; the .ready→.running CAS
/// keeps two CPUs from claiming the same PID. We MUST release the lock
/// before calling switchTo (otherwise we'd hold it across the switch and
/// deadlock the next dispatch).
pub fn schedule() void {
    // CpuLocal end-canary check (task #229). Wild writes into cpus[N]
    // would corrupt sched_lock that we're about to read; trip here with
    // the writer's call path on the stack instead of letting the bad
    // state cause a downstream #UD.
    smp.verifyEndCanary();
    // iretq-frame tripwire (task #230). schedule() runs from inside
    // every IRQ-driven preemption and every soft-yield syscall — if the
    // outgoing task's iretq frame got scribbled before we got here, we
    // catch it with schedule on the call stack.
    @import("../debug/iretq_canary.zig").check(@src());

    // Per-CPU schedule counter (exposed via /proc/sched). Done before
    // the audit / exit_requested branches so callers that bail early
    // still count toward "this cpu reached schedule()".
    smp.myCpu().schedule_count +%= 1;

    // Breadcrumb: schedule_enter, ctx = caller's current_pid (whichever
    // task is about to be replaced). Picked here rather than later so we
    // capture even early-bail paths.
    {
        const cur_now: u64 = if (smp.myCpu().current_pid) |p| @intCast(p) else 0xFF;
        @import("../debug/breadcrumb.zig").stamp(.schedule_enter, cur_now);
    }

    // Phase 1 rq audit (drift detector). Run every 64th schedule call so
    // it stays off the hot path — the audit itself is cheap (sum of
    // nr_runnable across CPUs vs count of .ready PCBs) but the kdbg log
    // on mismatch is verbose. Running it BEFORE the schedule body gives
    // us the cleanest snapshot of any drift introduced by an external
    // (cross-CPU) state write between the previous schedule and now.
    // L3: atomic Add — every CPU's schedule() increments concurrently,
    // plain `+%= 1` was a non-atomic RMW with lost-increment race that
    // made the audit cadence non-deterministic (anywhere from 1× to N×
    // the intended rate depending on which writes survived).
    const counter_after = @atomicRmw(u32, &sched_audit_counter, .Add, 1, .monotonic) +% 1;
    // Every 1024 schedules (~0.4 s at the observed 2800/s rate). Was every
    // 64 (~44/s) but the audit does an O(MAX_PROCS²) walk and runs at consumer
    // rate at idle — wasted cycles on a hot path. The audit catches drift
    // bugs over wall-clock seconds, not over micro-windows, so a coarser
    // cadence is structurally fine.
    if (counter_after & 0x3FF == 0) rqAudit();

    // Phase 3: cross-CPU kill via exit_requested. If the current task on
    // this CPU has been marked for exit by another CPU's killProcess,
    // tear ourselves down ON OUR OWN KSTACK rather than letting the killer
    // race against an in-flight switchTo asm save. destroyCurrentWithStatus
    // calls schedule() recursively at the end, so this check MUST run
    // BEFORE acquiring sched_lock — otherwise the recursive schedule's
    // acquireIrqSave deadlocks on the (non-recursive) ticket lock.
    //
    // Note: cur could be the idle PCB or a kernel task. Idles never receive
    // exit_requested (no one kills them); kernel tasks shouldn't either.
    // Defensive: only honor for non-idle PCBs.
    {
        const cpu_now = smp.myCpu();
        if (cpu_now.current_pid) |cur_pid| {
            // teardown_marked gate: once this pid's OWN teardown has started
            // (lifecycle.claimTeardown marks it first thing), exit_requested
            // is stale — teardown legitimately reaches schedule() (GPU
            // ctxDestroy contending ctrl_lock → blockOnMutex → yield), and
            // escalating again would restart teardown from the top, re-free
            // group resources the outer pass is still walking, and strand
            // the outer frame (the task dies inside the inner schedule()).
            if (!process.procs[cur_pid].is_idle and
                @atomicLoad(bool, &process.procs[cur_pid].exit_requested, .acquire) and
                !@atomicLoad(bool, &process.procs[cur_pid].teardown_marked, .acquire))
            {
                process.destroyCurrentWithStatus(process.procs[cur_pid].exit_status);
                unreachable;
            }
        }
    }

    const t = @import("../debug/perf.zig").enter();
    // The .schedule phase must measure the scheduler's pick + bookkeeping cost, NOT
    // the descheduled span. switchToCall (far below) freezes this stack frame until
    // the task is resumed, so a plain `defer leave()` fires on RESUME and clocks the
    // entire time the task sat idle/blocked (seconds) as if it were scheduling work —
    // which is exactly why `schedule` looked like 55% of wall. Stop the clock
    // explicitly right before the switch; this flag leaves the defer to cover only
    // the no-switch return paths (self-switch, pickNext-null), where the small
    // bookkeeping cost genuinely is the whole call.
    var sched_measured = false;
    defer if (!sched_measured) @import("../debug/perf.zig").leave(.schedule, t);
    const cpu = smp.myCpu();
    const paging = @import("../mm/paging.zig");

    // Acquire scheduler lock + disable interrupts for the bookkeeping
    // section. We MUST release before calling switchTo (the lock can't be
    // held across the kernel-to-kernel switch).
    const flags = cpu.sched_lock.acquireIrqSave();

    // Compute prev_save: the slot switchTo will write the prev RSP into,
    // or null to skip the save entirely. null when prev is .zombie/.unused
    // (PCB about to be reused by process.create — saving would scribble the
    // new init value) or when there's no current task at all (first dispatch
    // path / mid-destroy where current_pid was just cleared).
    //
    // Phase 5 collapsed the prior NONE_PID + dead_letter + save_in_flight_prev
    // tower into this single null. switchTo asm `testq rdi, rdi; jz skip`
    // handles the no-save case directly.
    const prev_save: ?*u64 = blk: {
        if (cpu.current_pid) |cur| {
            const cur_state_byte = @atomicLoad(u8, @as(*const u8, @ptrCast(&process.procs[cur].state)), .acquire);
            if (cur_state_byte == @intFromEnum(State.zombie) or
                cur_state_byte == @intFromEnum(State.unused))
            {
                break :blk null; // doomed — skip save
            }
            break :blk &process.procs[cur].kernel_esp;
        }
        break :blk null;
    };

    // Demote prev .running → .ready directly. Per-CPU rq dispatch (Phase 2)
    // means no other CPU can pick prev — only this cpu reads its own rq.
    // setState routes through rqEnter so prev appears in this cpu's rq
    // and gets dispatched fairly with anything else here. Sleeping /
    // zombie states are left alone — only .running needs the demote.
    //
    // CFS: setState's .running→non-running path flushes vruntime via
    // accountRunningTick — schedule doesn't need to do it directly.
    //
    // Transient-window bracket: between setState(.ready) and switchTo's
    // save below, prev.state==.ready but prev.kernel_esp is still STALE
    // (from the previous save) and prev is busily writing to its kstack
    // (often AAAA from Zig undefined-init). pcb_invariants reads this field
    // on every cpu and skips the saved-RIP check for any pid that matches
    // — without it it false-fires on transient stack residue (caught
    // 2026-05-19).
    // Cleared inside save_trace_record once switchTo's `movq %rsp,(%rdi)`
    // lands.
    var demoted_running_to_ready = false;
    if (cpu.current_pid) |cur| {
        // Set the scheduling_out bracket for EVERY yield path, not just
        // .running → .ready demotion. blockOn-style yields (state set to
        // .sleeping by the caller before invoking schedule) used to bypass
        // this bracket — leaving a transient window where the saved-RIP
        // mirror-compare false-fired on the schedule body's own `call
        // setTssRsp0` push (a stale-data read between two consecutive
        // pushes to the same kesp+48 slot). The bracket already covered
        // the .running-demote case; extending it to all yields closes the
        // detector race without changing schedule semantics.
        cpu.scheduling_out_pid = @intCast(cur);
        if (process.procs[cur].state == .running) {
            setState(cur, .ready);
            demoted_running_to_ready = true;
            @import("../debug/kdbg.zig").schedEvent(.preempt, @intCast(cur), @intFromEnum(State.running), @intFromEnum(State.ready), 0);
        }
    }

    // Pick a candidate and try to claim it via atomic CAS. Loop because two
    // CPUs could pick the same candidate; the loser retries with a fresh pick.
    // EXCEPTION: own-cpu idle (is_idle=true && idle_cpu==my_cpu) skips the
    // CAS — only this cpu ever dispatches its own idle, so no race possible
    // and the idle's state may be anything (.ready, .running). pickNext's
    // own gate-check (skip pids matching any cpu.save_in_flight_prev) keeps
    // prev out of the candidate set during the in-flight save.
    // Pass cur as exclude_pid so pickNext's Phase A prefers any other
    // runnable candidate first — relaxes strict priority just enough that
    // a cpu running an interactive task (e.g. desktop on cpu0) gives
    // its .normal-priority queueing a turn instead of immediately re-
    // dispatching itself. Falls back to cur if no alternative exists.
    const exclude: ?u8 = if (cpu.current_pid) |c| @intCast(c) else null;
    // Mode-A diagnostic: count re-picks so the wedge autopsy can SEE a
    // claim-loop livelock. Published to a per-CPU slot only once we re-pick
    // (loop_iters > 1) so the common single-pass dispatch pays nothing extra.
    var loop_iters: u64 = 0;
    const next_opt: ?usize = blk: while (true) {
        loop_iters +%= 1;
        if (loop_iters > 1 and cpu.cpu_id < smp.MAX_CPUS)
            @atomicStore(u64, &sched_loop_iters[cpu.cpu_id], loop_iters, .monotonic);
        const cand = pickNext(exclude) orelse break :blk null;
        const ready_val = @intFromEnum(State.ready);
        const running_val = @intFromEnum(State.running);
        const state_ptr: *u8 = @ptrCast(&process.procs[cand].state);
        if (process.procs[cand].is_idle and process.procs[cand].idle_cpu == cpu.cpu_id) {
            // Idle never enters the rq, so rqOnLeaveReady is a no-op,
            // but route through setState for path uniformity (and so a
            // future Phase 2 idle-in-rq variant just works).
            // Same dispatching_in_pid bracket as the CAS-success branch
            // below — even for idle, setState(.running) precedes the
            // setCurrentPid in the caller, so the running-but-no-owner
            // window exists.
            cpu.dispatching_in_pid = @intCast(cand);
            setState(cand, .running);
            @import("../debug/kdbg.zig").schedEvent(.dispatch, @intCast(cand), ready_val, running_val, 0);
            break :blk cand;
        }
        // Per-pid setState lock: serialize this direct CAS+rqLeave with
        // any concurrent setState on cand (e.g., a cross-CPU wake doing
        // .sleeping→.ready+rqEnter). Without it, picker's rqLeave can
        // run BEFORE wake's rqEnter (no entry to remove → no-op),
        // wake's rqEnter then inserts cand AFTER we already dispatched
        // it — cand ends up .running AND in rq, and any subsequent
        // .running→.sleeping skips rqLeave (was_ready=false), pinning
        // cand in rq as .sleeping forever. Caught 2026-05-19 by audit.
        const ss_flags = setstate_locks[cand].acquireIrqSave();
        // dispatching_in_pid bracket: declare intent to flip cand to
        // .running BEFORE the CAS, so any cross-CPU pcb_invariants scan
        // that observes state==.running sees a non-empty bracket and
        // skips. Setting AFTER the CAS leaves a window where state is
        // already .running but the bracket is still 0xFFFF — caught
        // 2026-05-20 by Q1 stress + a debug klog that widened the
        // window enough for cpu1's per-tick scan to land inside it,
        // panicking with "state==.running but no cpu.current_pid points
        // here." x86 TSO orders the prior store before the subsequent
        // locked CAS, so the reader will see the bracket if it sees
        // the post-CAS state.
        cpu.dispatching_in_pid = @intCast(cand);
        const prev = @cmpxchgStrong(u8, state_ptr, ready_val, running_val, .seq_cst, .seq_cst);
        if (TRACE_PID != 0 and cand == TRACE_PID) {
            debug.klog("[trace pid={d} cpu={d}] pickNext CAS .ready->.running result={any}\n", .{
                cand, cpu.cpu_id, prev,
            });
        }
        if (prev == null) {
            // CAS atomically claimed cand — sync the rq view (cand was
            // .ready, now .running, so it must leave its assigned_cpu's
            // rq). Holding setstate_locks[cand] across CAS + rqLeave
            // closes the dispatch / wake race documented above.
            // Per-PID activity ring: this is the OTHER state-byte writer
            // (not via setState). Without this stamp, the autopsy ring
            // would show ready→running mysteriously without a SETSTATE.
            @import("../debug/pid_act.zig").record(
                cand, .pick_cas, 0xFF, 0xFF, @returnAddress(),
            );
            rqOnLeaveReady(cand);
            // CFS: stamp slice_start so the next checkPreempt / schedule
            // measures only this run-slice. Sets even for idle path
            // above (skipped) — but accountRunningTick guards on is_idle.
            process.procs[cand].slice_start_tick = process.tick_count;
            @import("../debug/kdbg.zig").schedEvent(.dispatch, @intCast(cand), ready_val, running_val, 0);
            setstate_locks[cand].releaseIrqRestore(ss_flags);
            break :blk cand;
        }
        // CAS failed — another CPU claimed cand first. Clear the bracket
        // so a subsequent pcb_invariants scan doesn't ghost-skip cand on
        // an unrelated future running state.
        cpu.dispatching_in_pid = 0xFFFF;
        setstate_locks[cand].releaseIrqRestore(ss_flags);
        // CAS failed — another CPU got it first. Try again.
    };

    // Finalize the claim-loop spin diagnostic: bump the high-water mark and
    // clear the in-flight counter (so a cross-CPU autopsy read sees 0 = "not
    // currently spinning"). Only touch the in-flight slot if we actually
    // re-picked, to keep the single-pass fast path free of the extra store.
    if (cpu.cpu_id < smp.MAX_CPUS) {
        if (loop_iters > @atomicLoad(u64, &sched_loop_max[cpu.cpu_id], .monotonic))
            @atomicStore(u64, &sched_loop_max[cpu.cpu_id], loop_iters, .monotonic);
        if (loop_iters > 1) @atomicStore(u64, &sched_loop_iters[cpu.cpu_id], 0, .monotonic);
    }

    if (next_opt) |next| {
        // Self-switch guard (task #235). When pickNext falls back to own
        // idle and idle is already current, `next == current_pid`. Skip
        // the actual switchTo (no point), but undo the demote.
        if (cpu.current_pid) |cur| {
            if (cur == next) {
                if (demoted_running_to_ready) {
                    // setState(.running) reverses the demote AND rqLeave's
                    // cur (it was rqEnter'd by the demote's setState).
                    setState(cur, .running);
                }
                // Clear the transient bracket — no switchTo will run so
                // save_trace_record won't fire, leaving the field stale
                // would suppress real pcb-invariant hits on cur until the
                // NEXT schedule call.
                cpu.scheduling_out_pid = 0xFFFF;
                // M4: mirror dispatching_in_pid clear too. The self-switch
                // path returns BEFORE the pid_trace.setCurrentPid call that
                // would normally clear this bracket. Leaking it lets a peer
                // CPU's pcb_invariants scan skip cand's invariant check
                // until the next schedule that actually switches.
                cpu.dispatching_in_pid = 0xFFFF;
                cpu.sched_lock.releaseIrqRestore(flags);
                return;
            }
        }

        // -------- Switch to a user task --------
        // KCSAN-lite: just before we use procs[next].kernel_esp, watch
        // it for ~µs. If another CPU writes during this window, the race
        // is in switchTo's rsp-save vs another CPU's dispatch path.
        @import("../debug/kcsan.zig").checkU64("next.kernel_esp@dispatch", &process.procs[next].kernel_esp);
        // Hardware watchpoint on this task's iretq CS slot — DISABLED.
        // The "value must be 0x08 or 0x23" filter assumed only IRQ
        // machinery writes that slot, but syscall_entry's GPR pushes
        // legitimately reuse the same memory (RBX lands where CS would
        // be) and frequently write 0 there. We were drowning in false
        // positives that masked any real corruption. KCSAN's resample
        // protocol (src/debug/kcsan.zig) is the replacement.
        // const watch = @import("../debug/watch.zig");
        // const cs_slot_addr = procs[next].kernel_stack_top -% 32;
        // watch.armCsSlot(1, cs_slot_addr, "iretq_CS");
        process.procs[next].last_cpu = cpu.cpu_id;
        gdt.setTssRsp0(next, process.procs[next].kernel_stack_top);
        if (process.procs[next].page_dir_phys != 0) {
            pcid_mod.loadCr3(process.procs[next].page_dir_phys, process.procs[next].pcid, cpu.cpu_id);
        } else {
            pcid_mod.loadCr3(paging.getKernelPageDirPhys(), 0, cpu.cpu_id);
        }
        writeFsBase(process.procs[next].fs_base);

        // First-occurrence-per-(CPU,PID) trace — confirms which CPU
        // eventually dispatches each PID. Helps catch "PID never
        // scheduled" bugs.
        {
            const trace_dbg = struct {
                var seen: [@import("../cpu/smp.zig").MAX_CPUS][MAX_PROCS]bool =
                    [_][MAX_PROCS]bool{[_]bool{false} ** MAX_PROCS} ** @import("../cpu/smp.zig").MAX_CPUS;
            };
            if (cpu.cpu_id < @import("../cpu/smp.zig").MAX_CPUS and !trace_dbg.seen[cpu.cpu_id][next]) {
                trace_dbg.seen[cpu.cpu_id][next] = true;
                debug.klog("[sched] cpu{d} -> PID={d}\n", .{ cpu.cpu_id, next });
            }
        }

        // prev_save was determined at the top of schedule() — it's the
        // `?*u64` slot switchTo writes into, or null to skip the save.
        const next_kesp = process.procs[next].kernel_esp;

        // Wild-kernel_esp dispatch detector (2026-05-25 audit, secondary
        // probe). If next_kesp points outside next's own kstack body,
        // switchTo's `movq (%rsi), %rsp` would swap RSP to a foreign
        // kstack and the next `call setTssRsp0` would plant its RA at
        // the foreign location. The save-side detector in
        // save_trace_record is the primary catch (it preserves the
        // offending schedule's stack); this is the consumer-side
        // backstop in case the wild save happened before this code was
        // wired or via a path that bypasses save_trace_record.
        {
            const ktop_chk = process.procs[next].kernel_stack_top;
            if (ktop_chk != 0) {
                const body_lo = ktop_chk -| config.KSTACK_SIZE;
                if (next_kesp < body_lo or next_kesp >= ktop_chk) {
                    debug.klog("\n[wild-kesp-dispatch] !!! pid={d} kernel_esp points OUTSIDE its own kstack body !!!\n", .{next});
                    debug.klog("[wild-kesp-dispatch]   next_kesp = 0x{X:0>16}\n", .{next_kesp});
                    debug.klog("[wild-kesp-dispatch]   pid {d} kstack body = [0x{X:0>16}..0x{X:0>16})\n", .{ next, body_lo, ktop_chk });
                    const cur_pid: i32 = if (cpu.current_pid) |c| @intCast(c) else -1;
                    debug.klog("[wild-kesp-dispatch]   cpu = {d}  current_pid = {d}\n", .{ cpu.cpu_id, cur_pid });
                    @import("../debug/kdbg.zig").nmi_halt_after_snapshot = true;
                    @import("../debug/save_trace.zig").dumpAll();
                    @panic("dispatch with wild next_kesp (cross-stack-alias consumer)");
                }
            }
        }

        // P4: base-of-kstack canary. The kesp/RIP guards above watch the
        // switch frame near the TOP of the stack; this catches a deep
        // overflow or runaway write that walked DOWN and clobbered the base
        // qword (just above the guard page) — the class config.zig's 64 KB
        // bump was chasing. Check the OUTGOING task (caught in the act at
        // switch-out) and the INCOMING one (integrity before we resume it).
        // Self-gates to pool-backed, properly-created pids → no false
        // positives; compiles out when STACK_CANARY_ENABLE is false.
        if (process.STACK_CANARY_ENABLE) {
            var bad_pid: ?usize = null;
            var which: []const u8 = "incoming";
            if (cpu.current_pid) |cur| {
                if (!process.checkStackCanary(cur)) {
                    bad_pid = cur;
                    which = "outgoing";
                }
            }
            if (bad_pid == null and !process.checkStackCanary(next)) {
                bad_pid = next;
            }
            if (bad_pid) |b| {
                debug.klog("\n[stack-canary] !!! pid={d} ({s}) base-of-kstack canary CORRUPTED — deep overflow or wild write !!!\n", .{ b, which });
                const cbase = @intFromPtr(&process.kstack_pool[b]) + config.KSTACK_GUARD_SIZE;
                debug.klog("[stack-canary]   canary @ 0x{X:0>16} = 0x{X:0>16}  (expected 0x{X:0>16})\n", .{
                    cbase, @as(*const u64, @ptrFromInt(cbase)).*, process.stackCanaryValue(b),
                });
                debug.klog("[stack-canary]   kstack_top = 0x{X:0>16}  state = {s}  name = {s}\n", .{
                    process.procs[b].kernel_stack_top,
                    @tagName(process.procs[b].state),
                    process.procs[b].name[0..process.procs[b].name_len],
                });
                const from_pid_c: i32 = if (cpu.current_pid) |c| @intCast(c) else -1;
                debug.klog("[stack-canary]   cpu = {d}  from_pid = {d}\n", .{ cpu.cpu_id, from_pid_c });
                @import("../debug/kdbg.zig").nmi_halt_after_snapshot = true;
                @import("../debug/save_trace.zig").dumpAll();
                @atomicStore(u8, @as(*u8, @ptrCast(&process.procs[next].state)),
                    @intFromEnum(State.ready), .release);
                cpu.sched_lock.release();
                @panic("base-of-kstack canary corrupted");
            }
        }

        // Pre-dispatch saved-RIP guard. switchTo's `ret` will pop the
        // qword at [next_kesp + 48] (after 6 callee-save pops) as the
        // resume RIP. If it's 0, the dispatch lands at RIP=0 → faults
        // on instruction-fetch with no useful backtrace. Catch it here
        // with full diagnostics instead. Repro: `netstat` from shell
        // (2026-05-17) leads to desktop's saved-RIP slot being 0
        // post-pid-3-teardown.
        //
        // Skip the check if next_kesp + 48 isn't in the task's own
        // kstack range — defensive: a wild next_kesp would itself be
        // caught by the kesp watchdog (DR0-DR3), and reading random
        // memory here could itself fault.
        {
            const kstop = process.procs[next].kernel_stack_top;
            const rip_slot = next_kesp +% 48;
            if (rip_slot + 8 <= kstop and rip_slot >= kstop -% (4 * @import("../config.zig").KSTACK_SIZE)) {
                const saved_rip = @as(*const u64, @ptrFromInt(rip_slot)).*;
                // Plausibility: saved RIP from switchTo's ret must be in
                // kernel .text — either inside the image proper, OR the
                // retToUserStub address used for first-dispatch of new
                // tasks. Anything else (0, user VA, garbage) means kesp is
                // pointing at corrupt/stale data and we'd crash post-ret.
                const k_lo = memmap.KERNEL_VIRT_BASE;
                const k_hi = memmap.kernelEnd();
                const rip_in_text = saved_rip >= k_lo and saved_rip < k_hi;
                if (!rip_in_text) {
                    // P3(b): annotate the 0x….00000000 hi-half signature
                    // (low 32 bits zero, high bits set) — a structured clobber
                    // (a shifted or high-half value landing in the RIP slot),
                    // not random noise. Pure labelling on the already-failing
                    // path; the [k_lo,k_hi) range check above is what gates.
                    const structured = (saved_rip & 0xFFFFFFFF) == 0 and (saved_rip >> 32) != 0;
                    const cause: []const u8 = if (saved_rip == 0)
                        "RIP=0"
                    else if (structured)
                        "RIP outside kernel .text (structured garbage: low32=0 — looks like a hi-half/shifted value clobbering the slot)"
                    else
                        "RIP outside kernel .text";
                    debug.klog("[sched-rip-guard] about to dispatch pid={d} ({s}) with wild saved RIP=0x{X:0>16} ({s})\n", .{
                        next, process.procs[next].name[0..process.procs[next].name_len], saved_rip, cause,
                    });
                    debug.klog("[sched-rip-guard]   kernel_esp     = 0x{X:0>16}\n", .{next_kesp});
                    debug.klog("[sched-rip-guard]   kstack_top     = 0x{X:0>16}\n", .{kstop});
                    debug.klog("[sched-rip-guard]   expected_top   = 0x{X:0>16}\n", .{
                        @atomicLoad(usize, &process.expected_kstack_tops[next], .acquire),
                    });
                    debug.klog("[sched-rip-guard]   state          = {s}\n", .{@tagName(process.procs[next].state)});
                    const cur_pid: i32 = if (cpu.current_pid) |c| @intCast(c) else -1;
                    debug.klog("[sched-rip-guard]   from_pid       = {d}\n", .{cur_pid});
                    // Per-pid save mirror diagnostic (wild-RIP=0 hunt 2026-05-17):
                    // compare PCB.kernel_esp to what switchTo last saved, and the
                    // current memory at kesp+48 to what was saved there. Reveals
                    // whether the bug is "kesp value changed" or "kesp+48
                    // memory got overwritten after save".
                    const st = @import("../debug/save_trace.zig");
                    const saved_kesp = st.last_save_kesp[next];
                    const saved_plus48_then = st.last_save_plus48[next];
                    const saved_tsc = st.last_save_tsc[next];
                    const now_tsc: u64 = asm volatile (
                        "rdtsc\n\tshlq $32, %%rdx\n\torq %%rdx, %%rax"
                        : [r] "={rax}" (-> u64),
                        :: .{ .rdx = true });
                    debug.klog("[sched-rip-guard]   ---- save-mirror diagnostic ----\n", .{});
                    debug.klog("[sched-rip-guard]   last_save kesp    = 0x{X:0>16}\n", .{saved_kesp});
                    debug.klog("[sched-rip-guard]   last_save +48     = 0x{X:0>16}\n", .{saved_plus48_then});
                    debug.klog("[sched-rip-guard]   last_save tsc     = 0x{X:0>12}  (now=0x{X:0>12}, delta={d} cycles)\n", .{
                        saved_tsc, now_tsc, now_tsc -% saved_tsc,
                    });
                    if (saved_kesp != next_kesp) {
                        debug.klog("[sched-rip-guard]   *** PCB.kernel_esp DIFFERS from last save (changed by non-switchTo writer) ***\n", .{});
                    } else if (saved_plus48_then != saved_rip) {
                        debug.klog("[sched-rip-guard]   *** kesp+48 OVERWRITTEN since save: was=0x{X:0>16} now=0x{X:0>16} ***\n", .{
                            saved_plus48_then, saved_rip,
                        });
                    } else {
                        debug.klog("[sched-rip-guard]   *** save mirror MATCHES current — bug was present AT save time ***\n", .{});
                    }
                    debug.klog("[sched-rip-guard]   --------------------------------\n", .{});
                    // Dump 16 qwords at kernel_esp to see what the
                    // restore frame actually contains.
                    var i: usize = 0;
                    while (i < 16) : (i += 1) {
                        const a = next_kesp +% (i * 8);
                        if (a + 8 > kstop) break;
                        const v = @as(*const u64, @ptrFromInt(a)).*;
                        debug.klog("[sched-rip-guard]   +0x{X:0>2}: 0x{X:0>16}\n", .{ i * 8, v });
                    }
                    // Scan the full kstack body to tell "task never ran"
                    // (all zero) vs "task ran but kesp now points at unused
                    // zeros" (top region has data, bottom is zero).
                    const ktop_qwords: usize = (kstop - (kstop -% (4 * @import("../config.zig").KSTACK_SIZE))) / 8;
                    var nonzero_count: usize = 0;
                    var first_nonzero_off: usize = 0xFFFFFFFFFFFFFFFF;
                    var last_nonzero_off: usize = 0;
                    var q: usize = 0;
                    const scan_qwords: usize = if (ktop_qwords < 8192) ktop_qwords else 8192;
                    while (q < scan_qwords) : (q += 1) {
                        const a = kstop -% (8 * (q + 1));
                        const v = @as(*const u64, @ptrFromInt(a)).*;
                        if (v != 0) {
                            nonzero_count += 1;
                            const off = kstop - a;
                            if (off < first_nonzero_off) first_nonzero_off = off;
                            if (off > last_nonzero_off) last_nonzero_off = off;
                        }
                    }
                    debug.klog("[sched-rip-guard]   kstack scan: nonzero={d}/{d} qwords  first_nz_off=0x{X}  last_nz_off=0x{X}\n", .{
                        nonzero_count, scan_qwords, first_nonzero_off, last_nonzero_off,
                    });
                    // Dump 8 qwords near the top of kstack — the area a
                    // freshly-created task would have written to (sw_base
                    // entry, iretq frame).
                    debug.klog("[sched-rip-guard]   top-region dump (kstack_top-256 .. kstack_top):\n", .{});
                    var j: usize = 0;
                    while (j < 32) : (j += 1) {
                        const a = kstop -% (8 * (32 - j));
                        const v = @as(*const u64, @ptrFromInt(a)).*;
                        if (v != 0) {
                            debug.klog("[sched-rip-guard]     -0x{X:0>3}: 0x{X:0>16}\n", .{ (32 - j) * 8, v });
                        }
                    }
                    @import("../debug/kdbg.zig").nmi_halt_after_snapshot = true;
                    // Save-trace dump — shows the recent kesp saves that
                    // led to this dispatch. The bad save is typically
                    // a few entries back on `from_pid`'s CPU with a
                    // BAD-RIP verdict. Dump BEFORE @panic so we get it
                    // even if the panic path itself hiccups.
                    @import("../debug/save_trace.zig").dumpAll();
                    // Revert the pickNext .ready→.running CAS so the PCB
                    // invariant scanner (which checks state==.running ⟺
                    // some cpu owns it) doesn't false-positive on the
                    // mid-dispatch state. We're panicking, so leaving it
                    // .ready is harmless — nothing will dispatch.
                    @atomicStore(u8, @as(*u8, @ptrCast(&process.procs[next].state)),
                        @intFromEnum(State.ready), .release);
                    // Release sched_lock BEFORE panicking. Otherwise the
                    // panic-handler's autopsy walks (load balancer state,
                    // rq dumps) re-acquire and self-deadlock on the same
                    // CPU. Stale state in the running task is fine — we're
                    // panicking, not resuming.
                    cpu.sched_lock.release();
                    @panic("dispatch with wild saved RIP (not in kernel .text)");
                }
            } else if (kstop == 0 or next_kesp +% 56 > kstop) {
                // P3(a): the kesp+48 slot isn't inside this task's kstack
                // window, so we can't safely read it to validate the saved
                // RIP — pre-P3 this path was silently skipped. But a
                // kernel_esp within 56 bytes of (or above) kstack_top, or a
                // zero kstack_top at dispatch time, is itself corrupt:
                // switchTo pops 56 bytes (6 callee-save + ret), so a valid
                // kesp is always <= top-56. The wild-kesp detector earlier
                // only fires on kesp BELOW the body and is gated on
                // kstack_top != 0; this catches the too-high / unset end that
                // escaped both. Report + autopsy rather than dispatch blind
                // into a malformed restore frame.
                debug.klog("\n[sched-rip-guard] !!! pid={d} kernel_esp outside valid dispatch window — cannot validate saved RIP !!!\n", .{next});
                debug.klog("[sched-rip-guard]   kernel_esp   = 0x{X:0>16}\n", .{next_kesp});
                debug.klog("[sched-rip-guard]   kstack_top   = 0x{X:0>16}\n", .{kstop});
                debug.klog("[sched-rip-guard]   rip_slot     = 0x{X:0>16}  (need within [top-0x{X}, top-8])\n", .{ rip_slot, 4 * @import("../config.zig").KSTACK_SIZE });
                debug.klog("[sched-rip-guard]   expected_top = 0x{X:0>16}\n", .{
                    @atomicLoad(usize, &process.expected_kstack_tops[next], .acquire),
                });
                debug.klog("[sched-rip-guard]   state        = {s}\n", .{@tagName(process.procs[next].state)});
                const from_pid_w: i32 = if (cpu.current_pid) |c| @intCast(c) else -1;
                debug.klog("[sched-rip-guard]   from_pid     = {d}\n", .{from_pid_w});
                @import("../debug/kdbg.zig").nmi_halt_after_snapshot = true;
                @import("../debug/save_trace.zig").dumpAll();
                @atomicStore(u8, @as(*u8, @ptrCast(&process.procs[next].state)),
                    @intFromEnum(State.ready), .release);
                cpu.sched_lock.release();
                @panic("dispatch with kernel_esp outside valid kstack window");
            }
        }
        // Phase 3 retired the pre-load `next_kesp ∈ next's kstack range`
        // panic block. It defended cross-stack aliasing — a class that
        // required two CPUs to dispatch the same pid in different schedules
        // and stomp on each other's kernel_esp slot. Per-CPU rq (Phase 2)
        // makes this structurally impossible: only the assigned_cpu touches
        // a pid's kernel_esp, and only inside its own (single-threaded
        // wrt itself) schedule call. KASAN/iretq_canary/stack_alias
        // tripwires still catch wild writes from anywhere else.
        const from_pid_a: u8 = if (cpu.current_pid) |c| @intCast(c) else 0xFE; // 0xFE = dying task
        @import("../debug/pid_trace.zig").setCurrentPid(cpu, next);

        // Race fix (B.3 caught this): release the lock WITHOUT restoring IRQ
        // state. We must keep IRQs masked across switchToCall — otherwise an
        // IRQ landing in the gap between `cpu.current_pid = next` and the
        // actual rsp swap re-enters schedule() with current_pid=next but RSP
        // still on prev's stack, and saves prev's RSP into procs[next].
        // kernel_esp. That's the wild-RIP cross-stack-aliasing root cause.
        // After switchToCall returns (in the resumed context), restore the
        // ORIGINAL caller's IRQ state — `flags` lives on this schedule call's
        // own kernel stack, which is preserved across the switch.
        cpu.sched_lock.release();
        @import("../debug/kdbg.zig").schedEvent(.switch_in, from_pid_a, 0, 0, @intCast(next));
        // Breadcrumb: stamp the actual switch — ctx = next_kesp's low 48b
        // so the autopsy shows which kstack address we're about to load.
        @import("../debug/breadcrumb.zig").stamp(.switch_to, next_kesp);
        // hwbp disarm: pid 2/3's kesp+48 is watched while parked
        // (armed by save_trace_record with skip_value = legit RA).
        // Old pre-dispatch disarm of slots 2/3 removed 2026-05-25: the watch
        // entries at those slots are now kesp+48 mirror-compare watches with
        // an isPidRunningOrSchedulingOut guard (see watch.onDebugException
        // mirror_pid_plus1 branch). The structural guard already suppresses
        // the "first callq after switchTo's retq writes a different RA"
        // false positive, so disarming on every dispatch is unnecessary and
        // leaves slots permanently disarmed (the corrupter never gets caught
        // because by the time pid reparks, slot is still off).
        // Stop the .schedule clock HERE, before the context switch (see sched_measured
        // at the top of schedule()). Past this point the frame is suspended for the
        // task's entire descheduled duration — idle/wait time, not scheduler cost.
        @import("../debug/perf.zig").leave(.schedule, t);
        sched_measured = true;
        // LATE saved-RIP re-validation (2026-06-24 PID-recycle/dispatch race).
        // The pre-dispatch rip-guard above runs BEFORE setTssRsp0/loadCr3/
        // setCurrentPid and a window of other code; a #PF at RIP=0x1 with the
        // rip-guard CLEAN proved the restore frame is valid at guard time but
        // clobbered before switchTo's `ret` consumes [kesp+48] — a TOCTOU some
        // other agent wins inside this window (violates the "only assigned_cpu
        // touches kernel_esp" invariant the early guards rely on). Re-read it as
        // the very last act before the switch: a catch here carries the
        // save-mirror verdict (overwritten SINCE save? how many cycles ago?)
        // instead of a bare wild-RIP #PF with no backtrace. If this PASSES but
        // the ret still faults, the writer strikes inside switchTo's own few
        // instructions — itself a sharp clue. sched_lock is already released
        // (above), so we just panic; state stays .running (consistent with the
        // setCurrentPid already done) and nmi_halt_after_snapshot stops peers.
        {
            const rip_slot_l = next_kesp +% 48;
            const kstop_l = process.procs[next].kernel_stack_top;
            if (rip_slot_l + 8 <= kstop_l and rip_slot_l >= kstop_l -% (4 * @import("../config.zig").KSTACK_SIZE)) {
                const rip_l = @as(*const u64, @ptrFromInt(rip_slot_l)).*;
                if (rip_l < memmap.KERNEL_VIRT_BASE or rip_l >= memmap.kernelEnd()) {
                    const st = @import("../debug/save_trace.zig");
                    const now_tsc: u64 = asm volatile (
                        "rdtsc\n\tshlq $32, %%rdx\n\torq %%rdx, %%rax"
                        : [r] "={rax}" (-> u64),
                        :: .{ .rdx = true });
                    debug.klog("\n[sched-rip-LATE] !!! pid={d} saved RIP went WILD between guard and switchTo: 0x{X:0>16} (CAUGHT POST-GUARD = TOCTOU on restore frame) !!!\n", .{ next, rip_l });
                    debug.klog("[sched-rip-LATE]   kernel_esp = 0x{X:0>16}  from_pid = {d}  cpu = {d}\n", .{ next_kesp, from_pid_a, cpu.cpu_id });
                    debug.klog("[sched-rip-LATE]   last_save kesp = 0x{X:0>16}  last_save +48 = 0x{X:0>16}\n", .{ st.last_save_kesp[next], st.last_save_plus48[next] });
                    debug.klog("[sched-rip-LATE]   save tsc = 0x{X:0>12}  now = 0x{X:0>12}  delta = {d} cyc\n", .{ st.last_save_tsc[next], now_tsc, now_tsc -% st.last_save_tsc[next] });
                    if (st.last_save_kesp[next] != next_kesp) {
                        debug.klog("[sched-rip-LATE]   *** PCB.kernel_esp DIFFERS from last save (changed by a non-switchTo writer) ***\n", .{});
                    } else if (st.last_save_plus48[next] != rip_l) {
                        debug.klog("[sched-rip-LATE]   *** kesp+48 OVERWRITTEN since save — a racing writer hit this frame ***\n", .{});
                    } else {
                        debug.klog("[sched-rip-LATE]   *** save mirror MATCHES — frame was already wild at save time (missed by guard?) ***\n", .{});
                    }
                    @import("../debug/kdbg.zig").nmi_halt_after_snapshot = true;
                    @import("../debug/save_trace.zig").dumpAll();
                    @panic("dispatch with wild saved RIP (caught late — TOCTOU on restore frame)");
                }
            }
        }
        @import("sched_asm.zig").switchToCall(prev_save, next_kesp);
        // When we get here, this caller has been re-scheduled.
        @import("../debug/kdbg.zig").schedEvent(.switch_out, from_pid_a, 0, 0, @intCast(next));
        if ((flags & 0x200) != 0) asm volatile ("sti");
        return;
    }

    // pickNext returned null. Post-boot this is unreachable — every CPU has
    // an idle PCB created before its first dispatch (BSP via enterFirstTask,
    // APs via createKernelIdle in apEntry). The only window is a fault
    // arriving after sched bring-up but before idle creation; in that case,
    // releasing the lock and returning lets the caller (likely a panic path)
    // continue. Roll back the demote; otherwise prev would stay .ready
    // (pickable on next iteration).
    if (demoted_running_to_ready) {
        if (cpu.current_pid) |cur| {
            // setState(.running) reverses both the byte AND the rqEnter
            // that the demote's setState triggered.
            setState(cur, .running);
        }
        // Mirror the self-switch path: clear the transient bracket since
        // no switchTo will run on this branch either.
        cpu.scheduling_out_pid = 0xFFFF;
    }
    cpu.sched_lock.releaseIrqRestore(flags);
}

/// Write IA32_FS_BASE for the current CPU. Called from schedule() on
/// dispatch so each thread keeps its own TLS pointer. Cheap (a single
/// wrmsr); safe to call with value 0 (means "no TLS configured").
inline fn writeFsBase(val: u64) void {
    const IA32_FS_BASE: u32 = 0xC0000100;
    asm volatile ("wrmsr"
        :
        : [msr] "{ecx}" (IA32_FS_BASE),
          [lo] "{eax}" (@as(u32, @truncate(val))),
          [hi] "{edx}" (@as(u32, @truncate(val >> 32))));
}

/// Lazy min-deadline caches for `wakeExpired` / `deliverDueAlarms`. Setters
/// of `wake_tick` / `alarm_tick` must call the matching `register*Deadline`
/// so the 100 Hz scan-skip fast-path can detect "nothing is due yet" and
/// avoid walking MAX_PROCS PCBs. `maxInt` = no deadline pending.
///
/// Race tolerance: registrars only LOWER (never raise) the cached value via
/// cmpxchgWeak loop, so a stale too-low value forces a no-op scan — harmless.
/// wakeExpired/deliverDueAlarms recompute the new min from what actually
/// remains after their scan and store it back, so the cache self-corrects
/// every tick that crosses a deadline.
pub var earliest_wake_tick: std.atomic.Value(u64) = std.atomic.Value(u64).init(std.math.maxInt(u64));
pub var earliest_alarm_tick: std.atomic.Value(u64) = std.atomic.Value(u64).init(std.math.maxInt(u64));

// Earliest pending hi-res (TSC-absolute) usleep deadline across all PCBs — the
// min of every `.sleeping` PCB's `hires_wake_tsc`. `rearmTimerForCurrent` reads
// it to clamp the one-shot to the soonest usleep due-time; `wakeHiresExpired`
// gates its scan and recomputes it. hrtimer.NONE (maxInt) = nothing pending.
pub var earliest_hires_tsc: std.atomic.Value(u64) = std.atomic.Value(u64).init(hrtimer.NONE);

pub fn registerWakeDeadline(deadline: u64) void {
    var cur = earliest_wake_tick.load(.monotonic);
    while (deadline < cur) {
        cur = earliest_wake_tick.cmpxchgWeak(cur, deadline, .release, .monotonic) orelse return;
    }
}

/// Register a hi-res usleep deadline (absolute TSC). CAS-min into the cache so
/// the timer ISR's re-arm sees the soonest due-time. Mirrors
/// registerWakeDeadline; the caller has already stored it in pcb.hires_wake_tsc.
pub fn registerHiresWake(deadline: u64) void {
    var cur = earliest_hires_tsc.load(.monotonic);
    while (deadline < cur) {
        cur = earliest_hires_tsc.cmpxchgWeak(cur, deadline, .release, .monotonic) orelse return;
    }
}

/// Earliest pending hi-res deadline (absolute TSC), or hrtimer.NONE if none.
/// Read by rearmTimerForCurrent on every timer re-arm — kept O(1) via the cache
/// rather than rescanning the proc table each fire.
pub inline fn nextHiresTsc() u64 {
    return earliest_hires_tsc.load(.acquire);
}

pub fn registerAlarmDeadline(deadline: u64) void {
    var cur = earliest_alarm_tick.load(.monotonic);
    while (deadline < cur) {
        cur = earliest_alarm_tick.cmpxchgWeak(cur, deadline, .release, .monotonic) orelse return;
    }
}

/// Wake sleeping processes whose `sleep()` deadline has expired. Only
/// considers processes with wait_kind == .none (those blocked via
/// `sysSleep`) and .gpu_io (virtio-gpu safety-net) — futex/pipe/waitpid
/// sleepers leave wait_kind set and must be woken by their respective
/// explicit wake paths. Without the guard, every `.sleeping` PCB with the
/// default wake_tick=0 would race to .ready on the very next tick, breaking
/// blocking syscalls.
pub fn wakeExpired() void {
    // Fast path: nothing is due yet. Was: full MAX_PROCS scan + 2 atomic loads
    // per slot every tick. With the earliest cache + tick gating, idle ticks
    // skip the scan entirely. ~6,400 PCB atomic loads/sec eliminated at idle.
    if (process.tick_count < earliest_wake_tick.load(.acquire)) return;
    var new_earliest: u64 = std.math.maxInt(u64);
    for (0..MAX_PROCS) |i| {
        const pcb = &process.procs[i];
        if (pcb.state != .sleeping) {
            // Forward progress on this slot — clear any latched stuck
            // state so the NEXT incident logs fresh.
            stuck_last_seen_wait_kind[i] = null;
            continue;
        }
        // Hi-res usleep sleepers carry hires_wake_tsc (not wake_tick) and are
        // woken by wakeHiresExpired (#1006). Skip them here — otherwise their
        // wait_kind==.none + wake_tick==0 shape trips the orphan-sleep
        // diagnostic below.
        if (@atomicLoad(u64, &pcb.hires_wake_tsc, .acquire) != 0) {
            stuck_last_seen_wait_kind[i] = null;
            continue;
        }
        const wt = @atomicLoad(u64, &pcb.wake_tick, .acquire);
        // .gpu_io waiters set both wait_kind AND wake_tick as a safety
        // net: the primary waker is virtio_gpu's MSI-X IRQ walking the
        // PCB table, but QEMU CVE-2024-3446 occasionally drops the
        // notify. wake_tick guarantees the waiter re-runs and re-polls
        // usedIdx after a bounded delay even if no IRQ arrives. We
        // handle .gpu_io here (not in the .none branch) so the wake
        // clears wait_kind back to .none on the same path as the IRQ
        // wake — keeping a single "waiter resumed" code path.
        //
        // .desktop is deadline-woken on the same path: parkOrYield stores
        // wake_tick (the pending self-wake, else the 1 s liveness
        // backstop) before blocking, and the IRQ0 due-check retargets it
        // to "now" when an input/wake source turns up mid-park. This
        // branch is what makes both of those actually fire — it was
        // MISSING until 2026-07-16, so the desktop's only real waker was
        // the BSP idle loop after an input IRQ: freshly-launched windows
        // and terminal output sat unrendered until the user moved the
        // mouse, and the park backstop/self-wake deadlines were dead
        // letters (animations/toasts survived only because the idle loop
        // re-checked shouldResumeDesktop after every IRQ).
        if ((pcb.wait_kind == .gpu_io or pcb.wait_kind == .desktop) and wt != 0 and process.tick_count >= wt) {
            @atomicStore(u64, &pcb.wake_tick, 0, .release);
            clearWait(pcb);
            setState(i, .ready);
            stuck_last_seen_wait_kind[i] = null;
            continue;
        }
        if (pcb.wait_kind == .none and wt != 0 and process.tick_count >= wt) {
            // ORDER MATTERS: clear wake_tick BEFORE setState. setState
            // routes through rqEnter — once the pid is in the rq, an AP
            // (or this CPU on its next schedule()) can pick it, dispatch
            // it, run it, and call sysSleep AGAIN (fresh wake_tick) all
            // before our `wake_tick = 0` line if it came after setState.
            // That clobbers the fresh wake_tick to 0 → orphan sleep on
            // the NEXT block. Reproduced as "shell freezes after a few
            // keystrokes" — shell wakes from sysSleep, runs briefly,
            // calls pipe.read → blockOn, then wakeExpired's stale
            // wake_tick=0 store hits AFTER the new sleep. Clearing
            // wake_tick first means the worst-case race re-wakes us on
            // the next tick (we'd be sleeping with wake_tick=0 briefly,
            // skipped by wakeExpired guard, but the fresh sysSleep would
            // overwrite it before any harm).
            @atomicStore(u64, &pcb.wake_tick, 0, .release);
            setState(i, .ready);
            stuck_last_seen_wait_kind[i] = null;
            continue;
        }
        // Sleeper remains parked. If it has a future deadline this function
        // would honor (.gpu_io/.desktop or .none with wt > now), track it
        // for the post-scan earliest_wake_tick store. Other wait kinds are
        // woken by explicit paths and their wake_tick (if any) is
        // informational only.
        if ((pcb.wait_kind == .gpu_io or pcb.wait_kind == .desktop or pcb.wait_kind == .none)
            and wt > process.tick_count and wt < new_earliest)
        {
            new_earliest = wt;
        }
        // Diagnostic — pid is sleeping but neither wake path fires. Three cases:
        //   (a) wait_kind=.none AND wake_tick=0  : orphan sleep (no waker)
        //   (b) wait_kind=.none AND wake_tick>now : sleep still pending
        //   (c) wait_kind!=.none                  : explicit waker not firing
        // Per-pid latch keyed on (wait_kind, wait_target) so a permanently-
        // stuck pid emits exactly ONE line per incident. Replaces the old
        // every-200-ticks treadmill that drowned the log for the stuck shell
        // (272 identical dumps observed in serial.log 2026-05-26 before fix).
        if (process.tick_count -% wake_dbg_last_log < 200) continue;
        const kind = pcb.wait_kind;
        const target = pcb.wait_target;
        if (stuck_last_seen_wait_kind[i]) |last_kind| {
            if (last_kind == kind and stuck_last_seen_wait_target[i] == target) continue;
        }
        if (kind == .none) {
            if (wt == 0) {
                debug.klog("[wake-skip] pid={d} state=sleeping wait=none wake_tick=0 (orphan sleep)\n", .{i});
            } else if (process.tick_count < wt) {
                debug.klog("[wake-skip] pid={d} state=sleeping wait=none wake_tick={d} now={d} delta_future={d}\n", .{
                    i, wt, process.tick_count, wt - process.tick_count,
                });
            } else {
                continue; // race: wt became eligible, we'll wake on next pass
            }
        } else if (kind == .desktop and wt != 0 and process.tick_count < wt) {
            // Parked desktop with a live deadline — the branch above wakes
            // it at wt. Same shape as the .none "sleep still pending" case,
            // not a stuck waiter.
            continue;
        } else {
            debug.klog("[wake-skip] pid={d} state=sleeping wait_kind={d} wait_target=0x{x} (explicit waker not firing)\n", .{
                i, @intFromEnum(kind), target,
            });
            // Stuck-waiter detector: one-shot full state dump after the
            // pid has been parked on the same resource for ≥STUCK_TICKS.
            // Single permanent park is the bug pattern that `observe()`
            // can't catch — there are no repeated yields to compare.
            @import("../debug/yield_loop.zig").checkStuck(i, kind, target);
        }
        stuck_last_seen_wait_kind[i] = kind;
        stuck_last_seen_wait_target[i] = target;
        wake_dbg_last_log = process.tick_count;
    }
    // H5: Store-back the recomputed earliest, but only if no concurrent
    // registrar already lowered the cache below our value. An unconditional
    // store(new_earliest) would stomp a kernelSleepMs that registered a
    // deadline DURING our scan: pid 5 was .running at scan time so
    // contributed nothing to new_earliest, then registered D1 before our
    // store, then our store(maxInt) wipes D1 → fast-path returns early
    // forever, pid 5 sleeps with no waker. cmpxchg-only-if-larger preserves
    // any racing lower registration.
    var cur_earliest = earliest_wake_tick.load(.acquire);
    while (cur_earliest > new_earliest) {
        const r = earliest_wake_tick.cmpxchgWeak(cur_earliest, new_earliest, .release, .acquire);
        if (r == null) break;
        cur_earliest = r.?;
    }
}

/// Wake usleep sleepers whose hi-res (TSC-absolute) deadline has come due — the
/// TSC twin of wakeExpired (#1006). Called from the BSP timer ISR on EVERY
/// hardware fire, not just 10 ms tick boundaries: the one-shot is armed early
/// for sub-quantum deadlines, so this is where a precise usleep actually wakes.
/// `now_tsc` is rdtsc() read once by the handler. Only touches `.sleeping`,
/// wait_kind==.none PCBs carrying a non-zero hires_wake_tsc (set by sysUsleep);
/// tick-based sleepers keep wake_tick and are left to wakeExpired.
pub fn wakeHiresExpired(now_tsc: u64) void {
    // Fast path: nothing pending, or the soonest deadline isn't due yet. The
    // cache is the min of all pending hires deadlines and is only ever raised by
    // recomputing from the table (below) — so it can't read "not due" while a
    // real deadline is due (no missed wake). This runs every timer fire, so the
    // single-compare early-out matters. NONE must be checked explicitly:
    // due(now, NONE) is true (maxInt is "1 ahead" under wrapping).
    const earliest = earliest_hires_tsc.load(.acquire);
    if (earliest == hrtimer.NONE or !hrtimer.due(now_tsc, earliest)) return;

    var new_earliest: u64 = hrtimer.NONE;
    for (0..MAX_PROCS) |i| {
        const pcb = &process.procs[i];
        if (pcb.state != .sleeping) continue;
        const dl = @atomicLoad(u64, &pcb.hires_wake_tsc, .acquire);
        if (dl == 0) continue; // not a hi-res sleeper
        if (pcb.wait_kind == .none and hrtimer.due(now_tsc, dl)) {
            // ORDER: clear the deadline BEFORE setState — same orphan-sleep rule
            // as wakeExpired. setState routes into the run queue; the woken task
            // can run and usleep again before our store lands, and a late store
            // would clobber its fresh deadline, parking it with no waker.
            @atomicStore(u64, &pcb.hires_wake_tsc, 0, .release);
            setState(i, .ready);
            continue;
        }
        if (pcb.wait_kind == .none and dl < new_earliest) new_earliest = dl;
    }
    // Heal the cache to the recomputed earliest. CRITICAL difference from
    // wakeExpired's "only lower" store-back: THIS cache drives timer arming, so a
    // value stuck in the PAST makes armDelta re-fire the timer every tick — the
    // livelock that wedged the box (BSP fired ~67×/quantum, tick_count crawled).
    // A past cached value is therefore always stale (real deadlines are future)
    // and must be overwritten; a FUTURE value below new_earliest is a concurrent
    // registerHiresWake to preserve. So keep `cur` only when it's a sooner
    // *future* deadline — otherwise overwrite (this raises a stale-past value
    // back to NONE/next, which "only lower" never could).
    var cur = earliest_hires_tsc.load(.acquire);
    while (true) {
        const cur_future = cur != hrtimer.NONE and !hrtimer.due(now_tsc, cur);
        const want = if (cur_future and cur < new_earliest) cur else new_earliest;
        if (want == cur) break;
        if (earliest_hires_tsc.cmpxchgWeak(cur, want, .release, .acquire)) |actual| {
            cur = actual;
        } else break;
    }
}

var wake_dbg_last_log: u64 = 0;
// Per-pid latch for the wake-skip diagnostic. Holds the (wait_kind, wait_target)
// tuple last logged; cleared back to null when the pid leaves .sleeping. A
// permanently-stuck pid emits ONE line per (kind, target) incident instead
// of every 200 ticks forever.
var stuck_last_seen_wait_kind: [MAX_PROCS]?WaitKind = [_]?WaitKind{null} ** MAX_PROCS;
var stuck_last_seen_wait_target: [MAX_PROCS]u32 = [_]u32{0} ** MAX_PROCS;

/// Deliver SIGALRM to any process whose `alarm()` deadline has come due.
/// Called from the BSP timer IRQ alongside wakeExpired. Per-process — each
/// PCB has at most one alarm pending; setting a new alarm cancels the old.
pub fn deliverDueAlarms() void {
    // Fast path mirrors wakeExpired: skip the MAX_PROCS scan when no alarm
    // is due. Alarms are rare (sys_alarm only) so this is nearly always
    // the case at runtime.
    if (process.tick_count < earliest_alarm_tick.load(.acquire)) return;
    var new_earliest: u64 = std.math.maxInt(u64);
    for (0..MAX_PROCS) |i| {
        const at = @atomicLoad(u64, &process.procs[i].alarm_tick, .acquire);
        if (at != 0 and process.tick_count >= at) {
            // Claim-then-fire: only deliver if alarm_tick still holds the
            // value we judged due. The old plain `alarm_tick = 0` could
            // stomp a concurrent sys_alarm re-arm (the target's CPU storing
            // a fresh deadline between our read and our clear) — the fresh
            // alarm would be silently zeroed and never fire. Same lost-
            // deadline class as wakeExpired's clear-before-setState rule,
            // just on the other field. On CAS failure, fold the re-armed
            // value into the cache recompute so the fast-path gate stays
            // correct.
            if (@cmpxchgStrong(u64, &process.procs[i].alarm_tick, at, 0, .acq_rel, .acquire)) |fresh| {
                if (fresh != 0 and fresh < new_earliest) new_earliest = fresh;
            } else {
                _ = signals.send(@intCast(i), signals.SIGALRM);
            }
        } else if (at != 0 and at < new_earliest) {
            new_earliest = at;
        }
    }
    // H5: same cmpxchg-only-if-larger as wakeExpired — don't stomp a
    // racing registerAlarmDeadline that lowered the cache during our scan.
    var cur_earliest = earliest_alarm_tick.load(.acquire);
    while (cur_earliest > new_earliest) {
        const r = earliest_alarm_tick.cmpxchgWeak(cur_earliest, new_earliest, .release, .acquire);
        if (r == null) break;
        cur_earliest = r.?;
    }
}

/// Clear a process's wait flag so the scheduler considers it runnable again.
/// Block the current process for `ms` milliseconds, releasing CPU 0 (or
/// whichever CPU we're running on) to other runnable work. Same mechanism
/// as sysSleep (syscall 12), but callable from kernel context — used by
/// long-running syscall handlers (e.g. net.resolve, net.httpGet) that would
/// otherwise busy-spin and freeze the desktop because the BSP is locked out
/// of running anything else.
///
/// Why this lives here rather than in syscall.zig: it's process-state
/// manipulation (wake_tick + state + the rescheduling dance), and net.zig
/// can't import syscall.zig without a cycle.
pub fn kernelSleepMs(ms: u32) void {
    const cur = smp.myCpu().current_pid orelse return;
    const pcb = &process.procs[cur];
    const ticks = (ms + 9) / 10; // 100 Hz timer, round up
    const deadline = process.tick_count + ticks;
    @atomicStore(u64, &pcb.wake_tick, deadline, .release);
    registerWakeDeadline(deadline);
    setState(cur, .sleeping);
    smp.myCpu().pending_soft_yield = true;
    @import("sched_asm.zig").softYield();
}

/// Park the current process on `kind`/`target` until `wake()` flips it back
/// to .ready. Sets state=.sleeping atomically with the wait fields — required
/// because the int $0x20 yield path only reschedules when the current PID is
/// no longer .running (see idt.zig:yielded_from_kernel). On resume, wait_kind
/// and wait_target are auto-cleared.
///
/// Caller responsibilities:
///   - Record any per-resource wait bookkeeping (e.g. pipe.blocked_reader_pid,
///     perf_gap_cyc start) BEFORE calling — once we yield, the waker may race
///     in immediately.
///   - Re-check the underlying condition on resume. Wakes can be spurious
///     (signal delivery, parent destroy, EINTR-style cancel).
///
/// Returns when woken; does NOT loop.
/// Result of `blockOnInterruptible`. `.woke` means the wait completed
/// normally (caller's condition is presumed satisfied, or at least worth
/// re-checking). `.signalled` means a non-blocked signal arrived while we
/// were parked (or was already pending on entry); the caller must unwind
/// and return -EINTR rather than continuing the blocking operation —
/// otherwise the signal would only deliver after the syscall finishes,
/// which can be never for `accept`/`read` shapes.
pub const BlockResult = enum { woke, signalled };

inline fn hasPendingDeliverable(pcb: *const PCB) bool {
    const pending = @atomicLoad(u32, &pcb.pending_signals, .acquire);
    return (pending & ~pcb.signal_mask) != 0;
}

/// Like `blockOn`, but bails out (without parking, or while parked) when a
/// non-blocked signal is pending. Callers of the form
///
///     while (!cond) switch (process.blockOnInterruptible(.kind, t)) {
///         .woke => {},
///         .signalled => return E_INTR,
///     }
///
/// get correct EINTR semantics: any syscall they're in is interrupted
/// instead of resumed after handler delivery. Drivers doing kernel-internal
/// waits (NVMe completion, GPU command IRQ) should keep using `blockOn` —
/// interrupting them mid-DMA would leak hardware state.
pub fn blockOnInterruptible(kind: WaitKind, target: u32) BlockResult {
    const cur = smp.myCpu().current_pid orelse return .woke;
    const pcb = &process.procs[cur];
    // Signal already pending — don't even park. The deliver path on this
    // syscall's return will pick it up.
    if (hasPendingDeliverable(pcb)) return .signalled;
    blockOn(kind, target);
    if (hasPendingDeliverable(pcb)) return .signalled;
    return .woke;
}

pub fn blockOn(kind: WaitKind, target: u32) void {
    const cur = smp.myCpu().current_pid orelse return;
    const pcb = &process.procs[cur];
    // Captured for the yield-loop detector call below — taken here so the
    // trip dump names the high-level yield site (e.g.
    // nvme.waitCompletionAsync, pipe.read), not blockOn itself.
    const caller_ra = @returnAddress();
    // Wake-pending handshake. Atomically test-and-clear: if wake_pending
    // was ALREADY true on entry, a wake() ran between the caller's
    // condition check and our entry here — the wake event has been
    // delivered to us and the caller's next loop iteration will observe
    // its condition is satisfied. Return immediately without parking.
    //
    // The old `@atomicStore(false)` here was buggy: it unconditionally
    // stomped on a prior wake() that had set wake_pending=true,
    // causing permanent park. Caught 2026-05-19 by yield-loop:stuck:
    // desktop pid 2 stuck on nvme1 cid=0 with the waiter showing
    // completed=true while pid 2 was parked .sleeping. The fix
    // generalizes — every `while (!cond) blockOn(...)` pattern (pipe.read,
    // futex_wait, sysWaitpid, etc.) had the same race window.
    if (@atomicRmw(bool, &pcb.wake_pending, .Xchg, false, .acq_rel)) {
        return;
    }
    setWait(pcb, kind, target);
    setState(cur, .sleeping);
    // Race check: did a wake() land between our test-and-clear above
    // and the setState? If so, roll back to .running and return — the
    // caller's condition is satisfied and yielding would lose the wake.
    if (@atomicLoad(bool, &pcb.wake_pending, .acquire)) {
        clearWait(pcb);
        setState(cur, .running);
        return;
    }
    // Yield-loop detector: trips if this pid keeps actually parking with
    // identical (kind, target, caller_ra) in a tight window — fingerprint
    // of a wake-then-resleep loop on a non-progressing resource. Called
    // here (after both wake_pending early-returns) so only REAL yields
    // count; the fast-path returns from a satisfied caller condition
    // would otherwise produce false-positive trips.
    @import("../debug/yield_loop.zig").observe(cur, kind, target, caller_ra);
    smp.myCpu().pending_soft_yield = true;
    @import("sched_asm.zig").softYield();
    clearWait(pcb);
}


/// Result of blockOnFutex: woke normally, interrupted by a deliverable signal,
/// or the futex word changed during enrollment (caller returns EAGAIN).
pub const FutexResult = enum { woke, signalled, again };

/// Futex compare-and-sleep — mirrors blockOnMutex's register-then-recheck so a
/// racing FUTEX_WAKE can't be lost. `word` is the validated user *uaddr. We
/// enroll as a .futex waiter FIRST, then re-read *word and re-check wake_pending.
/// The old order ("read *uaddr THEN blockOn") dropped a wake that fired in the
/// gap — futex was the only waiter kind whose waker never set wake_pending, so
/// blockOn's re-check was structurally blind to it. setState(.sleeping)'s
/// internal atomic fences our enroll ahead of the *word re-read on x86 (same
/// assumption blockOnMutex relies on). Interruptible: .signalled on a pending
/// deliverable signal so a SIGINT/SIGTERM handler isn't stuck in the wait.
pub fn blockOnFutex(target: u32, word: *const volatile u32, val: u32) FutexResult {
    const cur = smp.myCpu().current_pid orelse return .woke;
    const pcb = &process.procs[cur];
    if (hasPendingDeliverable(pcb)) return .signalled;

    // H3: test-and-clear instead of unconditional store. A signal arriving
    // between hasPendingDeliverable and the wake_pending reset would set
    // wake_pending=true; an unconditional store(false) would stomp it and
    // Race A below (word != val) can't catch signal-driven wakes since
    // signals don't change the futex word. Mirrors the 2026-05-19 blockOn
    // lost-wake fix.
    if (@atomicRmw(bool, &pcb.wake_pending, .Xchg, false, .acq_rel)) {
        if (hasPendingDeliverable(pcb)) return .signalled;
        return .woke;
    }
    setWait(pcb, .futex, target);
    setState(cur, .sleeping);

    // Race A: the waker stored a new *uaddr before we enrolled. (Futex contract:
    // the waker changes *uaddr, THEN calls FUTEX_WAKE.) Seeing the new value
    // means the wake is already in flight / done — don't park.
    if (word.* != val) {
        clearWait(pcb);
        setState(cur, .running);
        return .again;
    }
    // Race B: a FUTEX_WAKE landed during enrollment — wake() set wake_pending.
    if (@atomicLoad(bool, &pcb.wake_pending, .acquire)) {
        clearWait(pcb);
        setState(cur, .running);
        return .woke;
    }

    smp.myCpu().pending_soft_yield = true;
    @import("sched_asm.zig").softYield(); // self-accounts the descheduled span
    clearWait(pcb);
    if (hasPendingDeliverable(pcb)) return .signalled;
    return .woke;
}

/// Called by pipe.write when waking a blocked reader, by pipe.read when waking
/// a blocked writer, and by killProcess/destroyCurrent when waking a parent
/// blocked in waitpid.
pub fn wake(pid: u8) void {
    if (pid >= MAX_PROCS) return;
    // Set wake_pending BEFORE clearing wait_kind / setStating .ready so a
    // racing blockOn (running on the target's own CPU between its wait_kind
    // store and its setState) can detect us via the re-check after setState.
    // Without this, the wake is silently lost and the task sleeps forever.
    @atomicStore(bool, &process.procs[pid].wake_pending, true, .release);
    clearWait(&process.procs[pid]);
    // pipe.read / pipe.write park themselves with state=.sleeping so the
    // int $0x20 yield actually reschedules (idt's yielded_from_kernel check
    // requires state != .running). Flip back to .ready here so the next
    // scheduler tick can pick us up. Don't touch .running or .zombie — wake
    // is meant to be a no-op for processes that aren't parked. setState
    // also rqEnter's pid on its assigned_cpu's runqueue.
    // M3: atomic-load state — `state` is `(a)` and a peer CPU may flip
    // it to .zombie between this read and setState's CAS. setState's H1
    // guard absorbs the race if it happens; the atomic load keeps the
    // compiler from hoisting the check across IRQ boundaries.
    const s = @atomicLoad(u8, @as(*const u8, @ptrCast(&process.procs[pid].state)), .acquire);
    if (s == @intFromEnum(State.sleeping)) setState(pid, .ready);
}

/// Compare-and-sleep primitive for Mutex.acquire. Enrolls the current
/// PCB as a .mutex waiter on `target_id` (= low-32 of the mutex's
/// owner_pid address), then re-reads `*owner_pid_ptr` atomically. If
/// the mutex became free between the caller's failed CAS-try and now,
/// returns without sleeping — the caller's next CAS-try will claim it.
/// Otherwise, sleeps until released. The dual race guard (re-check of
/// owner + wake_pending) closes the wake-during-enrollment window that
/// would otherwise lose a wakeup.
pub fn blockOnMutex(target_id: u32, owner_pid_ptr: *const u16) void {
    const cur = smp.myCpu().current_pid orelse return;
    const pcb = &process.procs[cur];
    // H3: test-and-clear. A wake() that arrived between caller's failed
    // CAS-try and our enrollment would set wake_pending=true; unconditional
    // store(false) here would stomp it. If we see true, return — caller
    // retries the CAS, which will see the (now-released) mutex.
    if (@atomicRmw(bool, &pcb.wake_pending, .Xchg, false, .acq_rel)) return;
    setWait(pcb, .mutex, target_id);
    setState(cur, .sleeping);
    // Race A: mutex got released between our caller's CAS-fail and our
    // enrollment. Don't sleep; caller will retry the CAS.
    if (@atomicLoad(u16, owner_pid_ptr, .acquire) == 0xFFFF) {
        clearWait(pcb);
        setState(cur, .running);
        return;
    }
    // Race B: a wake() landed between our wake_pending=false and now.
    if (@atomicLoad(bool, &pcb.wake_pending, .acquire)) {
        clearWait(pcb);
        setState(cur, .running);
        return;
    }
    smp.myCpu().pending_soft_yield = true;
    @import("sched_asm.zig").softYield();
    clearWait(pcb);
}

/// Wake every .sleeping PCB enrolled on exactly (kind, target). Shared
/// body of the four wake-fan-out entry points below — the state filter +
/// waitsOn + wake() triple was copy-pasted four times and had begun to
/// age independently. Thundering-herd by design: every matching waiter
/// re-checks its condition on resume; losers re-park (see each entry
/// point's contract).
fn wakeAllWaitingOn(kind: WaitKind, target: u32) void {
    for (0..MAX_PROCS) |i| {
        const t = &process.procs[i];
        if (@atomicLoad(u8, @as(*const u8, @ptrCast(&t.state)), .acquire) != @intFromEnum(State.sleeping)) continue;
        if (!waitsOn(t, kind, target)) continue;
        wake(@intCast(i));
    }
}

/// Wake every PCB sleeping on a Mutex with this target_id. Thundering-
/// herd wake: all waiters retry CAS in parallel, one wins, losers
/// re-blockOnMutex. Acceptable for low-contention locks (virtio-gpu
/// submit serializes one ~50ms wait at a time, contention is rare).
pub fn wakeMutexWaiters(target_id: u32) void {
    wakeAllWaitingOn(.mutex, target_id);
}

/// Wake every PCB blocked on a SWAP_INFLIGHT PTE whose leaf-PTE address
/// truncates to `target`. Called by `evictFrame` at the end of every
/// eviction (success or failure) so faulters can retry — they re-check the
/// PTE on resume and take the swap-in path (success) or re-fault the now-
/// PRESENT page (I/O failure restored the original PTE). Thundering-herd
/// is fine because the .swap_evict fan-in per page is small (typically
/// one or two threads of a MT process).
pub fn wakeSwapEvictWaiters(target: u32) void {
    wakeAllWaitingOn(.swap_evict, target);
}

/// Wake the single worker task blocked on .iouring_work with this instance id.
/// Called by io_uring_enter when userspace bumped sq_tail; the worker drains
/// pending Sqes on its next loop iteration.
pub fn wakeIoUringWorker(instance_id: u32) void {
    wakeAllWaitingOn(.iouring_work, instance_id);
}

/// Wake every task parked on io_uring_enter(min_complete > 0) for this
/// instance. Called by the worker after writing a CQE; the enter caller's
/// while-cq_count<min_complete loop re-checks on wake.
pub fn wakeIoUringCqWaiters(instance_id: u32) void {
    wakeAllWaitingOn(.iouring_cq, instance_id);
}


/// Block until the SWAP_INFLIGHT eviction at `pte_ptr` completes. Used by
/// `trySwapInPage` when a thread touches a page that another thread is
/// mid-evicting.
///
/// Uses the enroll-then-recheck pattern (mirrors blockOnMutex / blockOnFutex)
/// because `wakeSwapEvictWaiters` skips non-sleeping waiters: a naive
/// blockOn(.swap_evict, ..) race-window — wake fires between the pre-check
/// and our setState(.sleeping) — would silently lose the wake. The PTE is
/// re-checked AFTER enrolling .sleeping, with a release-fence-then-acquire
/// pairing the evictor's CAS so we can't read the stale in-flight encoding
/// after the eviction has already committed.
///
/// Returns once the PTE is in a settled state (SWAPPED commit / PRESENT abort
/// / 0 teardown). The caller re-dispatches based on the new state.
pub fn blockOnSwapEvict(pte_ptr: *const u64) void {
    const cur = smp.myCpu().current_pid orelse return;
    const pcb = &process.procs[cur];
    const target = swap.evictWaitTarget(pte_ptr);
    while (true) {
        if (!swap.pteIsInflight(@atomicLoad(u64, pte_ptr, .acquire))) return;
        // H3: test-and-clear. If a wake() landed between the pteIsInflight
        // check and now, treat as already-woken and loop to re-check the
        // PTE rather than stomping wake_pending and parking.
        if (@atomicRmw(bool, &pcb.wake_pending, .Xchg, false, .acq_rel)) continue;
        setWait(pcb, .swap_evict, target);
        setState(cur, .sleeping);
        // Race A: eviction committed/aborted between our pre-check and enroll.
        if (!swap.pteIsInflight(@atomicLoad(u64, pte_ptr, .acquire))) {
            clearWait(pcb);
            setState(cur, .running);
            return;
        }
        // Race B: wake() landed on us during enroll.
        if (@atomicLoad(bool, &pcb.wake_pending, .acquire)) {
            clearWait(pcb);
            setState(cur, .running);
            continue;
        }
        smp.myCpu().pending_soft_yield = true;
        @import("sched_asm.zig").softYield();
        clearWait(pcb);
        // Loop and re-check; the PTE may still be in-flight (spurious wake)
        // or settled (return on next iteration).
    }
}
