// Per-CPU cycle-counter ring for kernel hot paths.
//
// Wrap any function with:
//     const t = perf.enter();
//     defer perf.leave(.<phase>, t);
// to accumulate the total cycles spent in that phase (rdtsc deltas), the call
// count, and the worst-case observed cost. Per-syscall-number counters are
// bumped from inside doSyscall so we can see which syscalls dominate.
//
// Cost: ~30 cycles per rdtsc, so ~60 cycles overhead per measured call. Phases
// that already cost thousands of cycles see <1% overhead. Don't sprinkle this
// inside tight inner loops — only at dispatch boundaries.
//
// Read with `perf` in the kernel CLI; reset with `perf reset`. Each CPU keeps
// its own counters to avoid contention on a shared cacheline.

const serial = @import("serial.zig");
const smp = @import("../cpu/smp.zig");

pub const Phase = enum(u8) {
    syscall,
    irq0_timer,
    irq1_kbd,
    irq12_mouse,
    dynirq,
    exception,
    schedule,
    present,
    flush_rect,
    // Compositor sub-step counters (mode 9 only). One per chunk of the
    // per-frame pipeline so we can see which dominates wall time.
    comp_sync,
    comp_fill_src,
    comp_vk_render,
    comp_corner_blit,
    /// Compositor's per-frame flushUnconditional call. Separate from
    /// global flush_rect so we can see if it's actually blocking on
    /// host vblank (~16ms) or returning instantly (the latter would
    /// be a tearing source — comment claims vsync, code may differ).
    comp_flush,
    /// Catch-all for samples whose measured span exceeds PAUSE_CEILING_CYC —
    /// almost certainly a host vCPU pause (nested Hyper-V de-schedules the whole
    /// guest CPU mid-measurement, so rdtsc jumps by seconds). Diverted here so it
    /// doesn't poison a real phase's mean/total/max; the bucket keeps the lost
    /// time visible. Never passed to leave() by a caller — set only internally by
    /// recordPause. (2026-06-05)
    host_pause,
    /// Samples whose [start,end] overlaps an smi-detected IRQ0 stall window
    /// (≥15ms PM_TMR gap). Catches what the magnitude ceilings can't: a
    /// 9-12ms L1-CFS vCPU-steal slice inside a µs-scale schedule() sample
    /// sits far below CEIL_COMPUTE yet inflates that phase's mean 1000×.
    /// cli'd phases get the verdict DEFERRED one tick (see the pending slot
    /// in leave()) because smi can only publish the window at the IRQ0
    /// AFTER the stall — which, for an IF=0 sample, is after leave() has
    /// already run. Never passed to leave() by a caller. (2026-06-10)
    smi_stall,
};

const PHASE_COUNT: usize = @typeInfo(Phase).@"enum".fields.len;

pub const phase_name: [PHASE_COUNT][]const u8 = .{
    "syscall",
    "irq0_timer",
    "irq1_kbd",
    "irq12_mouse",
    "dynirq",
    "exception",
    "schedule",
    "present",
    "flush_rect",
    "comp_sync",
    "comp_fill_src",
    "comp_vk_render",
    "comp_corner_blit",
    "comp_flush",
    "host_pause",
    "smi_stall",
};

pub const Counter = struct {
    total: u64 = 0,
    count: u64 = 0,
    max: u64 = 0,

    pub fn reset(self: *Counter) void {
        self.total = 0;
        self.count = 0;
        self.max = 0;
    }
};

const MAX_CPUS = smp.MAX_CPUS;
pub const SYSCALL_TABLE_SIZE: usize = 64; // covers current syscall numbers (>50)

pub var phases: [MAX_CPUS][PHASE_COUNT]Counter = blk: {
    var x: [MAX_CPUS][PHASE_COUNT]Counter = undefined;
    for (&x) |*row| row.* = [_]Counter{.{}} ** PHASE_COUNT;
    break :blk x;
};

pub var syscalls: [SYSCALL_TABLE_SIZE]Counter = [_]Counter{.{}} ** SYSCALL_TABLE_SIZE;

/// Per-CPU wall bounds. Each CPU records its own [first leave, last leave]
/// span using its own TSC, so dumpAll's % wall is computed against the
/// elapsed cycles ON THAT CPU. Earlier version used a single global
/// wall_start_tsc captured by whichever CPU happened to leave() first
/// and read by dumpAll's CPU at the end — across KVM-drifting TSCs this
/// produced %wall values >100% (cpu1 schedule % seen at 497).
var wall_start_tsc: [MAX_CPUS]u64 = [_]u64{0} ** MAX_CPUS;
var wall_last_tsc: [MAX_CPUS]u64 = [_]u64{0} ** MAX_CPUS;

pub inline fn rdtsc() u64 {
    var lo: u32 = undefined;
    var hi: u32 = undefined;
    asm volatile ("rdtsc"
        : [lo] "={eax}" (lo),
          [hi] "={edx}" (hi),
    );
    return (@as(u64, hi) << 32) | lo;
}

pub inline fn enter() u64 {
    return rdtsc();
}

// Per-phase host-pause ceilings. A measured span longer than its phase's ceiling is
// treated as host-pause-contaminated (a nested-Hyper-V vCPU de-schedule landing
// mid-measurement makes rdtsc jump by 0.3-64s) and diverted to host_pause rather
// than poisoning the phase. Tiered because the legitimate max on-CPU cost differs by
// phase, and a single global ceiling either clipped real flush frames or let pauses
// leak into schedule/irq0:
//   - compute/IRQ phases never legitimately run tens of ms on-CPU;
//   - a syscall CAN be genuinely CPU-bound (crypto, ELF load, a big checksum);
//   - display phases legitimately block on the host vblank (a multi-frame stall up
//     to ~217M cyc was observed as real).
// All three sit well below the observed pauses (~975M and up), so each catches its
// own pauses without clipping its own legit work.
const CEIL_COMPUTE: u64 = 100_000_000; // ~33ms — schedule, IRQ, exception, dynirq
const CEIL_SYSCALL: u64 = 400_000_000; // ~133ms — a heavy CPU-bound syscall
const CEIL_DISPLAY: u64 = 600_000_000; // ~200ms — vblank-blocking flush/compositor

fn pauseCeiling(phase: Phase) u64 {
    return switch (phase) {
        .syscall => CEIL_SYSCALL,
        .present, .flush_rect, .comp_sync, .comp_fill_src, .comp_vk_render, .comp_corner_blit, .comp_flush => CEIL_DISPLAY,
        else => CEIL_COMPUTE, // irq0_timer, irq1_kbd, irq12_mouse, dynirq, exception, schedule
    };
}

inline fn recordPause(cpu_id: usize, dt: u64) void {
    const c = &phases[cpu_id][@intFromEnum(Phase.host_pause)];
    c.total +%= dt;
    c.count +%= 1;
    if (dt > c.max) c.max = dt;
}

/// True when [start,end] overlaps smi's most-recent stall window — the
/// sample contains an smi-detected (≥15ms) IRQ0 gap and its dt is freeze
/// time, not on-CPU cost. Window vars are 0 until the first stall.
inline fn stallOverlaps(start: u64, end: u64) bool {
    const smi = @import("../time/smi.zig");
    const w_end = @atomicLoad(u64, &smi.stall_win_end_tsc, .acquire);
    if (w_end == 0) return false;
    const w_start = @atomicLoad(u64, &smi.stall_win_start_tsc, .monotonic);
    return start < w_end and w_start < end;
}

/// Final classification of a sample: stall-overlap quarantine first (precise),
/// then the magnitude ceiling (catch-all), then the real phase.
fn commitSample(cpu_id: usize, phase: Phase, start: u64, end: u64) void {
    const dt = end -% start;
    if (phase != .host_pause and phase != .smi_stall) {
        if (stallOverlaps(start, end)) {
            const c = &phases[cpu_id][@intFromEnum(Phase.smi_stall)];
            c.total +%= dt;
            c.count +%= 1;
            if (dt > c.max) c.max = dt;
            return;
        }
        if (dt > pauseCeiling(phase)) {
            recordPause(cpu_id, dt);
            return;
        }
    }
    const c = &phases[cpu_id][@intFromEnum(phase)];
    c.total +%= dt;
    c.count +%= 1;
    if (dt > c.max) c.max = dt;
}

/// Deferred-verdict slot, one per CPU. cli'd phases (the CEIL_COMPUTE set:
/// schedule + IRQ handlers + exceptions) run with IRQ0 masked, so a stall
/// inside them is only published by smi at the IRQ0 AFTER leave() ran — an
/// immediate stallOverlaps() check always misses. Suspicious samples
/// (≥SUSPECT_FLOOR — genuine sched/IRQ bodies are µs-scale, steal slices
/// are ms-scale) park here for ~3 quanta so smi's window can arrive, then
/// classify. Single-slot is enough: suspicious samples are a few/s even
/// mid-storm; an overflow just classifies immediately (worst case one
/// mis-binned sample). Owned by its CPU; pending_busy guards against a
/// nested leave() (IRQ landing inside a task-context leave) re-entering.
const Pending = struct {
    phase: Phase = .syscall,
    start: u64 = 0,
    end: u64 = 0,
    valid: bool = false,
};
var pending: [MAX_CPUS]Pending = [_]Pending{.{}} ** MAX_CPUS;
var pending_busy: [MAX_CPUS]bool = [_]bool{false} ** MAX_CPUS;

/// ~1.7ms at 3GHz. Genuine schedule/IRQ bodies are µs-scale; a sample this
/// long in a cli'd phase is steal-slice-shaped and worth holding one tick.
const SUSPECT_FLOOR: u64 = 5_000_000;

inline fn deferEligible(phase: Phase) bool {
    return pauseCeiling(phase) == CEIL_COMPUTE;
}

pub fn leave(phase: Phase, start_tsc: u64) void {
    const end = rdtsc();
    const dt = end -% start_tsc;

    const cpu_id = smp.myCpu().cpu_id;
    if (cpu_id >= MAX_CPUS) return;
    if (wall_start_tsc[cpu_id] == 0) wall_start_tsc[cpu_id] = start_tsc;
    wall_last_tsc[cpu_id] = end;

    if (pending_busy[cpu_id]) {
        // Nested inside this CPU's own pending-slot manipulation — classify
        // with whatever stall info exists now rather than touching the slot.
        commitSample(cpu_id, phase, start_tsc, end);
        return;
    }
    pending_busy[cpu_id] = true;
    defer pending_busy[cpu_id] = false;

    // Resolve an aged pending sample: 3 quanta past its end, smi has had
    // its post-stall tick (or there was no stall) — verdict is in.
    if (pending[cpu_id].valid) {
        const tpq = @import("../time/apic.zig").tscPerQuantum();
        if (tpq == 0 or end -% pending[cpu_id].end > 3 *% tpq) {
            const pd = pending[cpu_id];
            pending[cpu_id].valid = false;
            commitSample(cpu_id, pd.phase, pd.start, pd.end);
        }
    }

    // Park a suspicious cli'd-phase sample for the deferred verdict.
    // Over-ceiling samples skip the wait — commitSample diverts them anyway.
    if (deferEligible(phase) and dt >= SUSPECT_FLOOR and dt <= pauseCeiling(phase) and !pending[cpu_id].valid) {
        pending[cpu_id] = .{ .phase = phase, .start = start_tsc, .end = end, .valid = true };
        return;
    }
    commitSample(cpu_id, phase, start_tsc, end);
}

/// Bump the per-syscall-number counter. Called from doSyscall around the
/// dispatch — separate from `leave(.syscall, ...)` because we want both the
/// aggregate "all syscalls" cost AND a per-number breakdown.
pub fn syscallSample(num: u32, dt: u64) void {
    if (num >= SYSCALL_TABLE_SIZE) return;
    // Host-pause guard, same ceiling as the syscall phase in leave(): a span past
    // CEIL_SYSCALL is a paused vCPU, not real cost. Skip it (don't pollute the
    // per-number mean) — the paired leave(.syscall) already bucketed it into
    // host_pause, so recording here too would double-count.
    if (dt > CEIL_SYSCALL) return;
    // Stall-overlap guard: syscalls run IF=1, so a host pause inside one has
    // already latched-and-fired IRQ0 on resume → smi published the window
    // BEFORE the syscall returned. end≈now (called right after measurement;
    // µs of skew vs a ≥15ms window is noise), start = end - dt.
    const end = rdtsc();
    if (stallOverlaps(end -% dt, end)) return;
    const c = &syscalls[num];
    c.total +%= dt;
    c.count +%= 1;
    if (dt > c.max) c.max = dt;
}

pub fn resetAll() void {
    for (&phases) |*row| {
        for (row) |*c| c.reset();
    }
    for (&syscalls) |*c| c.reset();
    @memset(&wall_start_tsc, 0);
    @memset(&wall_last_tsc, 0);
    for (&pending) |*p| p.valid = false;
}

/// Print a formatted summary to serial. Caller is responsible for any preamble
/// (e.g., a CLI section header). One row per CPU per phase plus the syscall-
/// num breakdown for syscalls with a nonzero count.
pub fn dumpAll() void {
    serial.print("[perf] {s:11} {s:>3} {s:>10} {s:>14} {s:>11} {s:>10} {s:>6}\n", .{
        "phase", "cpu", "count", "total_cyc", "mean_cyc", "max_cyc", "%wall",
    });

    for (&phases, 0..) |*row, cpu_id| {
        // Per-CPU wall: span between this CPU's first and last leave().
        // Bounds %wall ≤100% by construction and avoids the cross-CPU TSC
        // drift that previously produced bogus 484% rows.
        const wall_cpu = wall_last_tsc[cpu_id] -% wall_start_tsc[cpu_id];
        for (row, 0..) |*c, p| {
            if (c.count == 0) continue;
            const mean = c.total / c.count;
            // host_pause is an overlap-summed diagnostic — one vCPU pause inflates
            // EVERY nested measurement it straddles (the `syscall` AND the
            // `schedule` running inside it both divert it), so its total can exceed
            // the wall window and a %wall would be meaningless. Show a marker. Real
            // phases now read an honest %wall ≤100 on their own, because the pause
            // spikes that used to push schedule past 200% are diverted out of their
            // totals before we get here.
            if (p == @intFromEnum(Phase.host_pause) or p == @intFromEnum(Phase.smi_stall)) {
                serial.print(
                    "[perf] {s:11} {d:>3} {d:>10} {d:>14} {d:>11} {d:>10}     --\n",
                    .{ phase_name[p], cpu_id, c.count, c.total, mean, c.max },
                );
                continue;
            }
            const pct_x100: u64 = if (wall_cpu == 0) 0 else (c.total *| 10000) / wall_cpu;
            serial.print(
                "[perf] {s:11} {d:>3} {d:>10} {d:>14} {d:>11} {d:>10} {d:>3}.{d:0>2}\n",
                .{
                    phase_name[p],
                    cpu_id,
                    c.count,
                    c.total,
                    mean,
                    c.max,
                    pct_x100 / 100,
                    pct_x100 % 100,
                },
            );
        }
    }

    serial.print("[perf] --- per-syscall ---\n", .{});
    for (&syscalls, 0..) |*c, n| {
        if (c.count == 0) continue;
        const mean = c.total / c.count;
        serial.print(
            "[perf] sys#{d:0>2}      {s:>3} {d:>10} {d:>14} {d:>11} {d:>10}\n",
            .{ n, "-", c.count, c.total, mean, c.max },
        );
    }
}
