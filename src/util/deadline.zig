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
//! The TSC is treated as a system-wide wall clock — invariant and synced
//! across CPUs. That is the same assumption the NVMe soft/hard deadlines
//! and the watchdog already make; a wait that migrates mid-loop keeps a
//! valid deadline.

const std = @import("std");

// Core deps.
const perf = @import("../debug/perf.zig");
const apic = @import("../time/apic.zig");

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
/// hundreds-of-millions-iteration spin. 10M matches the largest
/// iteration constant the old loops used.
const FALLBACK_ITERS_MAX: u64 = 10_000_000;

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
    /// TSC value after which the wait is over; 0 ⇒ fallback mode.
    deadline_tsc: u64,
    /// TSC at construction (0 in fallback mode) — for elapsedMs().
    start_tsc: u64,
    /// Remaining iteration budget, consumed only in fallback mode.
    iters_left: u64,

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
        // tscPerQuantum() = TSC cycles per 10 ms scheduler quantum.
        const per_quantum = apic.tscPerQuantum();
        const d: Deadline = if (per_quantum == 0) .{
            .deadline_tsc = 0,
            .start_tsc = 0,
            .iters_left = @min(
                @max(budget_us * FALLBACK_ITERS_PER_MS / 1000, 1000),
                FALLBACK_ITERS_MAX,
            ),
        } else blk: {
            const now = perf.rdtsc();
            break :blk .{
                .deadline_tsc = now + per_quantum * budget_us / 10_000,
                .start_tsc = now,
                .iters_left = 0,
            };
        };
        noteWaitStart(what, d.deadline_tsc);
        // The breadcrumb write is the only side effect; the struct itself
        // is inert until live() is polled.
        return d;
    }

    /// True while the budget lasts. Designed as the AND-clause of the
    /// poll loop; after the loop, re-check the hardware condition (not
    /// the deadline) to distinguish success from timeout — the loop may
    /// exit with the condition satisfied on the final iteration.
    pub fn live(self: *Deadline) bool {
        if (self.deadline_tsc == 0) {
            if (self.iters_left == 0) return false;
            self.iters_left -= 1;
            return true;
        }
        return perf.rdtsc() < self.deadline_tsc;
    }

    /// Milliseconds since construction — for timeout log lines. Returns 0
    /// in fallback mode (no clock to measure with).
    pub fn elapsedMs(self: *const Deadline) u64 {
        if (self.start_tsc == 0) return 0;
        const per_quantum = apic.tscPerQuantum();
        if (per_quantum == 0) return 0;
        return (perf.rdtsc() -% self.start_tsc) * 10 / per_quantum;
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
/// The wait's deadline_tsc (0 for a fallback-mode wait).
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
/// the watchdog dump paths; safe from NMI/IRQ context (serial prints
/// only, relaxed loads).
pub fn dumpWaitSites() void {
    serial.print("[wait-sites] last polled-hardware wait started per CPU (stale entries marked past):\n", .{});
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
            const per_quantum = apic.tscPerQuantum();
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
