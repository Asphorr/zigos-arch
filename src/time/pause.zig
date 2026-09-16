//! pause — the host-pause clock: TSC cycles this guest did NOT run.
//!
//! The TSC counts through every host pause (the guest's TSC is the host's,
//! offset), so a TSC budget measures WALL time — and wall time is the wrong
//! ruler for "did the device / the peer make progress": a 1 s Hyper-V pause
//! of the whole zigvm turns a 500 ms NVMe budget into a false "waitCompletion
//! timeout", a frozen-peer watchdog strike into a false halt (the 2026-08-22
//! and 2026-06-24 incidents). The [smi] classifier already NAMES these after
//! the fact (HOST-L0 / HOST-L1); this module turns the same evidence into an
//! ACCOUNT the timeouts subtract, so a budget measures guest-run time.
//!
//! Three feeds:
//!
//!   L1 — zigvm's KVM descheduled this vCPU thread. KVM publishes the
//!        cumulative ns per vCPU (MSR_KVM_STEAL_TIME, kvm.stealNs): exact,
//!        per-CPU, readable at any instant with no exit.
//!   L0 — Hyper-V paused the whole zigvm. Invisible to KVM's accounting (no
//!        runqueue wait ever happens), detectable only as guest NON-PROGRESS.
//!        Two observers, for two situations:
//!        · the BSP's IRQ0 gap (smi.tick): PM_TMR-measured, minus the armed
//!          interval, minus the L1 steal covering it, and only when no
//!          cli-hold of ours accounts for the gap — credited to ONE global
//!          accumulator at the first BSP tick after the pause. Bare-metal
//!          SMIs land here too, which is the correct meaning.
//!        · the waiter's own TSC jumps (Epoch, IF=0 only): with interrupts
//!          off nothing else can run on this CPU, so a jump of a full
//!          quantum or more between two consecutive poll iterations is time
//!          the vCPU did not execute. This is the ONLY L0 evidence a cli'd
//!          waiter can have — its own tick is held off, and the BSP-side
//!          gap it eventually produces measures the cli window, not a pause
//!          (smi.tick refuses to credit an OURS gap for that reason). The
//!          disk self-test's mkfs pour is exactly this shape.
//!
//! An `Epoch` snapshots the feeds at the start of a wait; `runElapsed()` is
//! the wall delta minus the pause accrued since — what a budget compares to.
//!
//! Granularity, by construction: L1 is exact. The BSP-side L0 is credited
//! at tick granularity, AFTER the pause, by the BSP; a waiter with IF=1 that
//! checks its budget in the microseconds between the VM resuming and the
//! BSP's pending IRQ0 landing still sees the gap uncredited — Deadline.live
//! asks `smi.tickOverdue()` for that window. The jump observer needs at
//! least two observations: a wait that is checked once, after the pause,
//! sees only wall time — poll loops check every iteration, so in practice
//! every pause inside a poll is bracketed.
//!
//! Conservative in one direction only: every rounding UNDER-credits pause
//! (the stall threshold's slop and sub-quantum jumps are not credited; a
//! jump is credited only when IRQs were off at BOTH of its ends; a waiter
//! found on another vCPU forfeits the steal credited so far and starts over
//! on the new one; no feed may claim more pause than wall time passed). An
//! under-credit can still let a budget misfire under a pause; an over-credit
//! would MASK a genuine wedge. The former is the pre-existing failure, only
//! rarer; the latter would be new.

const apic = @import("apic.zig");
const kvm = @import("../virt/kvm.zig");
const smp = @import("../cpu/smp.zig");
const serial = @import("../debug/serial.zig");

/// (a) TSC cycles the whole VM was paused (L0 + bare-metal SMI) as seen by
/// the BSP tick, cumulative since boot. Single writer — BSP IRQ0 via
/// smi.tick → creditL0(); readers on every CPU. The plain `+%` in the
/// writer is not a racy RMW for the same reason smi.stall_events' isn't:
/// one cli'd writer.
var l0_paused_tsc: u64 = 0;
/// (a) Number of gaps that fed the account — for the dump line.
var l0_credits: u64 = 0;

/// Credit `tsc_cycles` of whole-VM pause. BSP IRQ0 only (smi.tick).
pub fn creditL0(tsc_cycles: u64) void {
    @atomicStore(u64, &l0_paused_tsc, l0_paused_tsc +% tsc_cycles, .monotonic);
    @atomicStore(u64, &l0_credits, l0_credits +% 1, .monotonic);
}

/// Whole-VM pause since boot as seen by the BSP tick, TSC cycles.
pub fn l0PausedTsc() u64 {
    return @atomicLoad(u64, &l0_paused_tsc, .monotonic);
}

/// ns → TSC cycles at the calibrated rate (tscPerQuantumSane = cycles per
/// 10 ms quantum = per 10_000_000 ns; a quantum change must revisit the
/// divisors). Split ms/remainder math in u64 — no u128 libcall on a path
/// that runs per poll iteration — saturating so days of steal at a wild
/// (but sane-clamped) rate can't overflow-panic a diagnostic. 0 before
/// calibration, or when calibration reads stall-corrupted.
pub fn nsToTsc(ns: u64) u64 {
    const per_q = apic.tscPerQuantumSane();
    if (per_q == 0) return 0;
    const per_ms = per_q / 10;
    const whole_ms = ns / 1_000_000;
    const rem_ns = ns % 1_000_000;
    return (whole_ms *| per_ms) +| (rem_ns * per_ms / 1_000_000);
}

/// TSC cycles → ms for log lines. 0 before calibration.
pub fn tscToMs(cyc: u64) u64 {
    const per_ms = apic.tscPerQuantumSane() / 10;
    if (per_ms == 0) return 0;
    return cyc / per_ms;
}

/// KVM steal for `cpu_id` in TSC cycles — cumulative host preemption of that
/// vCPU (L1). 0 without KVM steal-time or before calibration.
pub fn stealTsc(cpu_id: u32) u64 {
    return nsToTsc(kvm.stealNs(cpu_id));
}

/// Everything `cpu_id` has been paused for since boot as far as the global
/// feeds know: BSP-observed whole-VM pauses plus its own vCPU's preemption.
pub fn pausedTsc(cpu_id: u32) u64 {
    return l0PausedTsc() +| stealTsc(cpu_id);
}

/// RFLAGS.IF of the calling CPU. Cheap (pushfq), no exit.
pub inline fn irqsEnabled() bool {
    const rflags = asm volatile ("pushfq; popq %[r]"
        : [r] "=r" (-> u64),
    );
    return (rflags & (1 << 9)) != 0;
}

/// How often an IF=1 observation re-reads the LAPIC id to notice that the
/// waiter now runs on another vCPU (every 256th observation, plus every
/// observation that follows a ≥ quantum gap — the scheduler ran). The read
/// is an MMIO/MSR exit under nested virt, so it is paced, not per poll;
/// between checks a migrated waiter is still credited the OLD vCPU's steal
/// — bounded by that vCPU's real preemption over ≤ 256 iterations.
const MIGRATION_RECHECK_MASK: u32 = 0xFF;

/// A capture of the feeds at the start of a wait. `runElapsed()` is the
/// ruler a timeout compares its budget against; call it (or `live()` in
/// Deadline) once per poll iteration so the jump observer sees every gap.
/// Context: any — task, IRQ, cli'd, early boot (guest RAM + TSC + RFLAGS;
/// no locks; the only exit after the capture is the paced LAPIC-id
/// re-check above, IF=1 waits only). Methods take `*Epoch`: observing is a
/// mutation.
pub const Epoch = struct {
    /// Wall TSC at capture.
    tsc: u64,
    /// l0_paused_tsc at capture.
    l0: u64,
    /// kvm.stealNs(cpu) at the capture — or at the last migration
    /// re-baseline — kept in ns and converted at read time, so a
    /// calibration landing mid-wait can't inflate the delta.
    steal_ns: u64,
    /// vCPU whose steal this wait is charged. Re-read at the paced
    /// re-check; on a change the steal feed re-baselines on the new vCPU,
    /// forfeiting what the old one had credited (under-credit, never a
    /// stranger's steal for the rest of the wait).
    cpu: u8,
    /// IRQs were off at capture OR at any observation since (sticky). Set ⇒
    /// this wait is the jump observer's case and the BSP-side account is
    /// ignored for it: a wait that ran cli'd may itself be the gap the BSP
    /// tick later measures, and must not subtract its own cli window.
    irqs_off: bool,
    /// IF at the previous observation. A jump is credited only when IRQs
    /// were off at BOTH ends of it: a loop that executes `sti; mwait` (the
    /// NVMe async idle path) or is otherwise preemptible would read every
    /// scheduler gap and every idle sleep as a "jump" under a capture-time
    /// verdict alone.
    last_irqs_off: bool,
    /// Previous observation, for the jump detector.
    last_tsc: u64,
    /// Steal baseline of the jump detector — advances only at credited
    /// jumps and at a migration re-baseline.
    last_steal_ns: u64,
    /// kvm.stealNs(cpu) as of the latest observation — read once per
    /// observation and shared by the jump credit and the steal feed, so
    /// both see the same instant.
    cur_steal_ns: u64,
    /// Self-observed pause (IF=0 jumps net of steal), TSC cycles.
    self_paused: u64,
    /// Observation counter, paces the migration re-check.
    obs: u32,

    /// The inert capture — for a Deadline in fallback mode (no clock).
    pub const zero: Epoch = .{
        .tsc = 0,
        .l0 = 0,
        .steal_ns = 0,
        .cpu = 0,
        .irqs_off = false,
        .last_irqs_off = false,
        .last_tsc = 0,
        .last_steal_ns = 0,
        .cur_steal_ns = 0,
        .self_paused = 0,
        .obs = 0,
    };

    pub fn now() Epoch {
        const cpu: u8 = smp.myCpu().cpu_id;
        const tsc = rdtsc();
        const steal_ns = kvm.stealNs(cpu);
        const off = !irqsEnabled();
        return .{
            .tsc = tsc,
            .l0 = l0PausedTsc(),
            .steal_ns = steal_ns,
            .cpu = cpu,
            .irqs_off = off,
            .last_irqs_off = off,
            .last_tsc = tsc,
            .last_steal_ns = steal_ns,
            .cur_steal_ns = steal_ns,
            .self_paused = 0,
            .obs = 0,
        };
    }

    /// Wall cycles since capture. 0 when the TSC reads below the capture
    /// (cross-CPU skew after a migration) rather than a wrapped huge value.
    pub fn wallElapsed(self: *const Epoch) u64 {
        return rdtsc() -| self.tsc;
    }

    /// One observation: with IF=0 at both this and the previous one, a jump
    /// of ≥ one quantum between them is time this vCPU did not run; the
    /// part KVM already explains as steal is left to the steal feed. With
    /// IF=1, the paced migration re-check. Returns `now`.
    fn observe(self: *Epoch) u64 {
        const t = rdtsc();
        const off_now = !irqsEnabled();
        const jump_min = apic.tscPerQuantumSane(); // 10 ms; 0 = uncalibrated, detector off
        const gap = t -| self.last_tsc;
        self.obs +%= 1;
        if (!off_now and ((jump_min != 0 and gap >= jump_min) or (self.obs & MIGRATION_RECHECK_MASK) == 0)) {
            const here: u8 = smp.myCpu().cpu_id;
            if (here != self.cpu) {
                const s = kvm.stealNs(here);
                self.cpu = here;
                self.steal_ns = s;
                self.last_steal_ns = s;
            }
        }
        const steal_t = kvm.stealNs(self.cpu);
        if (off_now) {
            self.irqs_off = true;
            if (self.last_irqs_off and jump_min != 0 and gap >= jump_min) {
                const steal_gap = nsToTsc(steal_t -| self.last_steal_ns);
                self.self_paused +|= gap -| steal_gap;
                self.last_steal_ns = steal_t;
            }
        }
        self.last_irqs_off = off_now;
        self.last_tsc = t;
        self.cur_steal_ns = steal_t;
        return t;
    }

    /// Pause accrued since capture as of the observation at `t`. Clamped to
    /// the wall delta: no feed may claim more pause than time has passed
    /// (the account's writers are conservative by construction, this is
    /// the reader's belt to their braces).
    fn pausedNoObserve(self: *const Epoch, t: u64) u64 {
        const steal = nsToTsc(self.cur_steal_ns -| self.steal_ns);
        const l0 = if (self.irqs_off) self.self_paused else l0PausedTsc() -| self.l0;
        return @min(l0 +| steal, t -| self.tsc);
    }

    /// Host-paused cycles accrued since capture (observes first).
    pub fn pausedSince(self: *Epoch) u64 {
        const t = self.observe();
        return self.pausedNoObserve(t);
    }

    /// Guest-run cycles since capture = wall − paused (observes first).
    pub fn runElapsed(self: *Epoch) u64 {
        const t = self.observe();
        return (t -| self.tsc) -| self.pausedNoObserve(t);
    }
};

inline fn rdtsc() u64 {
    return asm volatile (
        \\ rdtsc
        \\ shlq $32, %%rdx
        \\ orq %%rdx, %%rax
        : [r] "={rax}" (-> u64),
        :: .{ .rdx = true });
}

/// `[pause]` account dump — the BSP-observed whole-VM total and each vCPU's
/// steal. Called from perf.dumpAll (task/CLI context; serial.print takes
/// its lock). Self-observed jumps live in their Epochs and are printed by
/// the waits themselves.
pub fn dump() void {
    serial.print("[pause] host-pause clock: whole-VM (L0) paused {d} ms over {d} gap(s), BSP-tick view\n", .{
        tscToMs(l0PausedTsc()), @atomicLoad(u64, &l0_credits, .monotonic),
    });
    var c: u32 = 0;
    while (c < smp.MAX_CPUS) : (c += 1) {
        const ns = kvm.stealNs(c);
        if (ns != 0) serial.print("[pause]   steal cpu{d}: {d} ms host-preempted (L1, KVM ground truth)\n", .{ c, ns / 1_000_000 });
    }
}
