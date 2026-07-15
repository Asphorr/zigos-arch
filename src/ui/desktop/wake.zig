// Compositor wake primitive — replaces the legacy "wake every 80 ms /
// every 30 ms" unconditional fallback in `shouldResumeDesktop` with
// explicit signaling from work-producing sites.
//
// Two channels, both consumed once per desktop loop iteration:
//
//   * `wake_pending` — a level-triggered flag set by edge events
//     (sysPresent landed, a pipe got new bytes, a toast was shown,
//     an animation was started, an app crashed, config changed). The
//     desktop's `consume()` call at the top of each loop iteration
//     clears it; subsequent sets re-arm.
//
//   * `self_wake_due_at` — an absolute tick deadline written by the
//     loop body itself when it has tick-driven artifacts still in
//     flight (animation frames, cursor blink phase, bell flash
//     countdown, toast slide/fade). Multiple producers race-min into
//     a single slot via cmpxchg so the earliest deadline wins.
//
// `isDue()` is called from the timer IRQ on each tick and tells the
// scheduler whether to context-switch back to the desktop task or
// keep running user tasks. The win is: when neither flag is set, the
// desktop stays parked in `process.schedule()` and the CPU runs user
// work (or idles via MWAIT) instead of redrawing nothing 12.5 times
// per second.
//
// Legacy loop mode is preserved behind `event_driven = false` — flip
// it if event-driven mode misses a wake source and a window stops
// updating. shouldResumeDesktop honors the flag.

var wake_pending: bool = false;
var self_wake_due_at: u64 = 0;

/// Master gate. When false, `shouldResumeDesktop` reverts to the
/// pre-event-driven interval/3-tick fallbacks (legacy behaviour).
/// Flip to false at runtime via debugger / kernel cmdline to fall
/// back without recompiling.
pub var event_driven: bool = true;

/// Request an immediate wake. Safe from any context (IRQ, syscall,
/// kernel task, any CPU). Two stores:
///   1. wake_pending — the level-triggered flag shouldResumeDesktop reads.
///   2. a bump of the BSP's MWAIT monitor word — if the BSP idles in
///      mwait, the store pops it instantly and the idle loop's pre-/post-
///      sleep wake checks run. This is what makes an AP-side producer
///      (async app load, a task's pipe write) wake the compositor in µs
///      instead of "whenever the next input IRQ happens to arrive".
///      Harmless when the BSP is busy or hlt-idling (the timer catches
///      those within its ≤100 ms stretch cap).
pub fn requestWake() void {
    @atomicStore(bool, &wake_pending, true, .release);
    const smp = @import("../../cpu/smp.zig");
    _ = @atomicRmw(u32, &smp.cpus[0].idle_monitor_word, .Add, 1, .release);
}

/// Schedule a self-wake at `at_tick` (absolute tick count). Coalesces
/// with any earlier self-wake — the min wins. Called by the desktop
/// loop body for tick-driven artifacts that need a follow-up frame
/// (animations, toast countdown, cursor blink, bell flash).
pub fn requestSelfWake(at_tick: u64) void {
    while (true) {
        const cur = @atomicLoad(u64, &self_wake_due_at, .acquire);
        if (cur != 0 and cur <= at_tick) return;
        if (@cmpxchgWeak(u64, &self_wake_due_at, cur, at_tick, .release, .acquire) == null) return;
    }
}

/// True iff there's pending work or a self-wake came due. Read from
/// the timer IRQ in `shouldResumeDesktop`.
pub fn isDue(now: u64) bool {
    if (@atomicLoad(bool, &wake_pending, .acquire)) return true;
    const due = @atomicLoad(u64, &self_wake_due_at, .acquire);
    return due != 0 and now >= due;
}

/// Clear both channels. Called at the top of the desktop loop after
/// the task has been resumed; new work signals that arrive during
/// the loop body re-arm wake_pending so the next iteration runs.
pub fn consume() void {
    @atomicStore(bool, &wake_pending, false, .release);
    @atomicStore(u64, &self_wake_due_at, 0, .release);
}

/// Pending self-wake deadline (absolute tick), 0 = none. The desktop's
/// park path uses it as the wake_tick deadline so wakeExpired brings
/// the loop back exactly when the next animation/toast frame is due.
pub fn selfWakeAt() u64 {
    return @atomicLoad(u64, &self_wake_due_at, .acquire);
}
