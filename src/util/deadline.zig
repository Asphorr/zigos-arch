//! deadline — wall-clock budgets for polled hardware waits.
//!
//! An iteration-count spin (`while (busy and spin < 5_000_000)`) measures
//! "some amount of time that depends on who is hosting us": ~100 ns per
//! port/MMIO read on bare metal, 5-10 µs per VM exit under nested QEMU —
//! the same constant is three orders of magnitude apart in wall time. Two
//! paid-for incidents in this class: the 1.028 s cli-hold in PS/2
//! reEnable (2026-05-24, caught by the SMI stall classifier) and the NVMe
//! waitCompletion "timeout" that was really a late completion under a
//! host stall (2026-08-22). A `Deadline` is the house replacement: the
//! constructor names the unit (rule 4), expiry is measured on the TSC,
//! and every wait leaves a per-CPU breadcrumb the wedge autopsy prints.
//!
//! The ruler (2026-09-16, steal-aware time): expiry is measured on
//! GUEST-RUN time — the TSC minus the host-pause account kept by
//! `time/pause.zig` (each vCPU's KVM steal + whole-VM gaps credited by
//! `smi.tick`). The TSC counts through a host pause; the budget must not.
//! A `Deadline.ms(500, ...)` therefore says "the guest waits 500 ms", and
//! a 1 s Hyper-V pause stretches the wall wait without expiring it — the
//! false-wedge class of this rig. `elapsedMs()` reports guest-run time;
//! `pausedMs()` what was subtracted, so a timeout line can show both. A
//! cli'd poll (IF=0) is credited by the Epoch's own jump observer, one
//! observation per `live()` — which is why `live()` belongs in the loop
//! condition, called every iteration, never hoisted.
//!
//! The TSC is treated as a system-wide wall clock — invariant and synced
//! across CPUs. That is the same assumption the NVMe soft/hard deadlines
//! and the watchdog already make; a wait that migrates mid-loop keeps a
//! valid deadline (steal stays credited to the capturing vCPU — see
//! `pause.Epoch.cpu`).

const std = @import("std");

// Core deps.
const perf = @import("../debug/perf.zig");
const apic = @import("../time/apic.zig");
const pause = @import("../time/pause.zig");
const smi = @import("../time/smi.zig");

// Diagnostics-only deps (the wait-site breadcrumbs + their dump).
const smp = @import("../cpu/smp.zig");
const serial = @import("../debug/serial.zig");

/// Fallback iteration budget per requested millisecond, used only before
/// APIC calibration lands (tscPerQuantum()==0 — first boot phase). Sized
/// by the PS/2 precedent: 40k iterations/ms ≈ 200 ms/ms wall worst-case
/// under nested virtualization (5 µs per exit), generous by design — the
/// fallback exists to bound the loop, not to be a precise clock.
const FALLBACK_ITERS_PER_MS: u64 = 40_000;

/// Hard cap on the fallback budget so a multi-second budget requested
/// pre-calibration (NVMe CSTS.RDY asks for seconds) cannot turn into a
/// tens-of-seconds spin: at ~1-5 µs per port read, 5M iterations is
/// already 5-25 s worst case — the ceiling is anti-wedge, not a clock.
const FALLBACK_ITERS_MAX: u64 = 5_000_000;

/// Calibration sanity: apic.tscPerQuantumSane() reads 0 when the 10 ms
/// calibration window was stall-corrupted (see the window constants
/// there) ⇒ treat as uncalibrated and use the iteration fallback.
fn sanePerQuantum() u64 {
    return apic.tscPerQuantumSane();
}

/// A wall-clock wait budget for a polled-hardware loop. Construct with
/// `Deadline.ms(n, "what")` / `.us(n, "what")`, then drive the poll with
/// `while (!ready and d.live()) {}` — the same shape as the old
/// iteration-count loops, so conversions are one-line. `live()` mutates
/// (fallback mode counts down), hence `var d`, not `const`.
///
/// Context: any — task, IRQ, cli'd, early boot. No locks taken, no
/// allocation. Before APIC calibration the TSC budget is unknown and the
/// wait degrades to a bounded iteration count (see FALLBACK_*).
pub const Deadline = struct {
    /// Guest-run TSC budget; 0 ⇒ fallback mode.
    budget_tsc: u64,
    /// Both clocks at construction — wall TSC and the host-pause account
    /// (time/pause.zig). All-zero in fallback mode.
    epoch: pause.Epoch,
    /// Remaining iteration budget, consumed only in fallback mode.
    iters_left: u64,
    /// Second-look grants (see live()): expiry checks overruled because the
    /// BSP's tick was overdue — an uncredited host pause in flight. Zero
    /// means "no grant yet", which is when the grant window opens.
    overdue_grants: u32,
    /// Wall cycles since capture at the first grant — the grant window is
    /// measured from here (see live()).
    grant_start_wall: u64,

    /// Budget in milliseconds. `what` names the wait for the per-CPU
    /// breadcrumb ("nvme csts-rdy", "ps2 input-buffer clear") — keep it
    /// short and grep-able; it is stored by pointer, so it must be a
    /// literal (comptime enforces that).
    pub fn ms(budget_ms: u64, comptime what: [:0]const u8) Deadline {
        return init(budget_ms * 1000, what);
    }

    /// Budget in microseconds, for sub-millisecond controller handshakes.
    pub fn us(budget_us: u64, comptime what: [:0]const u8) Deadline {
        return init(budget_us, what);
    }

    fn init(budget_us: u64, comptime what: [:0]const u8) Deadline {
        // tscPerQuantum() = TSC cycles per 10 ms scheduler quantum,
        // sanity-clamped (stall-corrupted calibration ⇒ fallback mode).
        const per_quantum = sanePerQuantum();
        const d: Deadline = if (per_quantum == 0) .{
            .budget_tsc = 0,
            .epoch = pause.Epoch.zero,
            .iters_left = @min(
                @max(budget_us * FALLBACK_ITERS_PER_MS / 1000, 1000),
                FALLBACK_ITERS_MAX,
            ),
            .overdue_grants = 0,
            .grant_start_wall = 0,
        } else .{
            .budget_tsc = per_quantum * budget_us / 10_000,
            .epoch = pause.Epoch.now(),
            .iters_left = 0,
            .overdue_grants = 0,
            .grant_start_wall = 0,
        };
        // Breadcrumb deadline is the WALL estimate (start + budget): a host
        // pause pushes the real expiry later, which dumpWaitSites labels
        // as "past" a little early — a diagnostic hint, not accounting.
        noteWaitStart(what, if (d.budget_tsc == 0) 0 else d.epoch.tsc + d.budget_tsc);
        // The breadcrumb write is the only side effect; the struct itself
        // is inert until live() is polled.
        return d;
    }

    /// True while the budget lasts. Designed as the AND-clause of the
    /// poll loop; after the loop, re-check the hardware condition (not
    /// the deadline) to distinguish success from timeout — the loop may
    /// exit with the condition satisfied on the final iteration.
    pub fn live(self: *Deadline) bool {
        if (self.budget_tsc == 0) {
            if (self.iters_left == 0) return false;
            self.iters_left -= 1;
            return true;
        }
        if (self.epoch.runElapsed() < self.budget_tsc) return true;
        // Expired on the guest-run ruler. Second look: is the BSP's own tick
        // overdue — a host pause in flight (or just ended) that smi.tick has
        // not yet measured and credited? Then the expiry is unproven: keep
        // waiting and re-decide once the credit lands (the next check sees
        // runElapsed drop back under budget) or the tick returns to schedule
        // (a genuine timeout stands). smi refuses this on a BSP with IF=0 —
        // a caller holding off its own tick can't cite that tick as
        // evidence — so a cli'd BSP poll still expires on wall time, as
        // before, with the watchdog's peer view as its backstop.
        //
        // The grants are bounded in WALL time from the first one: a credit
        // that is coming comes within microseconds of the resume (the BSP's
        // TSC-deadline passed during the pause and fires at once). A tick
        // that stays overdue longer is a BSP sitting in its own long IF=0
        // window (the mkfs pour holds the NVMe CQ lock for seconds) — not
        // a pause, and no reason for an AP to hold ITS budget open: e1000's
        // 2 ms per-packet budget IS its cli-hold bound. Window = min(budget,
        // two quanta): never more than doubles a short wait, ≤ 20 ms on a
        // long one.
        if (smi.tickOverdue()) {
            const wall = self.epoch.wallElapsed();
            if (self.overdue_grants == 0) self.grant_start_wall = wall;
            const window = @min(self.budget_tsc, 2 * sanePerQuantum());
            if (wall -| self.grant_start_wall <= window) {
                self.overdue_grants +|= 1;
                return true;
            }
        }
        return false;
    }

    /// Guest-run milliseconds since construction — for timeout log lines
    /// (pair with pausedMs() to show what was subtracted). Returns 0 in
    /// fallback mode (no clock to measure with). Cross-CPU TSC skew after
    /// a migration reads as 0 elapsed, not as a wrapped overflow.
    pub fn elapsedMs(self: *Deadline) u64 {
        if (self.budget_tsc == 0) return 0;
        return pause.tscToMs(self.epoch.runElapsed());
    }

    /// Host-paused milliseconds since construction — the part of the wall
    /// wait the budget did NOT count. 0 in fallback mode.
    pub fn pausedMs(self: *Deadline) u64 {
        if (self.budget_tsc == 0) return 0;
        return pause.tscToMs(self.epoch.pausedSince());
    }
};

// =============================================================================
// Per-CPU wait-site breadcrumbs.
//
// Every Deadline construction stamps its CPU's slot with what is being
// waited for and until when. Nothing ever clears a slot — the record is
// "the last hardware wait STARTED on this CPU", in the spirit of
// spinlock's spin_target: a momentarily-stale value is fine for a
// diagnostic, and requiring a paired clear would add a defer to every
// call site for no autopsy value. dumpWaitSites() marks entries whose
// deadline is in the past as such, so a stale-but-completed wait is
// visually distinct from a live one.
//
// Slots are own-CPU plain-written under no lock; the autopsy reads
// cross-CPU with .monotonic loads (aligned word-sized slots — no tearing
// on x86; ordering is irrelevant for a best-effort dump). A nested wait
// (IRQ handler polling hardware mid-task-wait) overwrites the task's
// entry — last-started wins, documented and acceptable.
// =============================================================================

/// == smp.MAX_CPUS; local mirror per rule 5 so the arrays below read as
/// this file's own bound.
const MAX_WAIT_CPUS: usize = 32;

comptime {
    if (MAX_WAIT_CPUS != smp.MAX_CPUS) {
        @compileError("MAX_WAIT_CPUS must equal smp.MAX_CPUS — wait-site slots are indexed by cpu id");
    }
}

/// @intFromPtr of the wait's `what` literal, 0 = no wait recorded yet.
/// Stored as usize so the cross-CPU load is a single atomic word.
var wait_what: [MAX_WAIT_CPUS]usize = [_]usize{0} ** MAX_WAIT_CPUS;
/// The wait's wall-estimate deadline TSC (0 for a fallback-mode wait).
var wait_deadline: [MAX_WAIT_CPUS]u64 = [_]u64{0} ** MAX_WAIT_CPUS;

fn noteWaitStart(comptime what: [:0]const u8, deadline_tsc: u64) void {
    const cpu = currentCpuId();
    if (cpu >= MAX_WAIT_CPUS) return;
    @atomicStore(u64, &wait_deadline[cpu], deadline_tsc, .monotonic);
    @atomicStore(usize, &wait_what[cpu], @intFromPtr(what.ptr), .monotonic);
}

/// LAPIC id as CPU index — the same aliasing spinlock's per-CPU slots
/// assume (lapic_id == cpu_id on this board).
fn currentCpuId() u8 {
    if (!apic.apic_active) return 0;
    return @as(u8, @truncate(apic.getLapicId()));
}

/// Wedge-autopsy companion to spinlock.dumpSpinTargets(): the last
/// hardware wait each CPU started, and whether its budget has already
/// passed. A CPU wedged inside a polled wait shows a live entry naming
/// the device; "(past)" entries are history, not evidence. Called from
/// the watchdog dump paths (task/IRQ context). NOT NMI-safe as-is:
/// serial.print takes write_lock unless emergency_mode is set — an NMI
/// caller must be on the watchdog.fire() emergency path, same caveat
/// as the neighbouring dumpSpinTargets.
pub fn dumpWaitSites() void {
    serial.print("[wait-sites] last polled-hardware wait started per CPU (stale entries marked past; wall estimate, host pause not subtracted):\n", .{});
    const now = perf.rdtsc();
    var any = false;
    var c: usize = 0;
    while (c < MAX_WAIT_CPUS) : (c += 1) {
        const what_addr = @atomicLoad(usize, &wait_what[c], .monotonic);
        if (what_addr == 0) continue;
        any = true;
        const what: [*:0]const u8 = @ptrFromInt(what_addr);
        const dl = @atomicLoad(u64, &wait_deadline[c], .monotonic);
        serial.print("  cpu{d} -> '{s}'", .{ c, std.mem.span(what) });
        if (dl == 0) {
            serial.print(" (pre-calibration fallback wait)\n", .{});
        } else if (now >= dl) {
            const per_quantum = sanePerQuantum();
            if (per_quantum != 0) {
                serial.print(" (past, ended {d} ms ago)\n", .{(now -% dl) * 10 / per_quantum});
            } else {
                serial.print(" (past)\n", .{});
            }
        } else {
            serial.print(" (LIVE — deadline not yet reached)\n", .{});
        }
    }
    if (!any) serial.print("  (no CPU has started a polled wait)\n", .{});
}
