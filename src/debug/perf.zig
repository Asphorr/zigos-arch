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

pub fn leave(phase: Phase, start_tsc: u64) void {
    const end = rdtsc();
    const dt = end -% start_tsc;

    const cpu_id = smp.myCpu().cpu_id;
    if (cpu_id >= MAX_CPUS) return;
    if (wall_start_tsc[cpu_id] == 0) wall_start_tsc[cpu_id] = start_tsc;
    wall_last_tsc[cpu_id] = end;
    const c = &phases[cpu_id][@intFromEnum(phase)];
    c.total +%= dt;
    c.count +%= 1;
    if (dt > c.max) c.max = dt;
}

/// Bump the per-syscall-number counter. Called from doSyscall around the
/// dispatch — separate from `leave(.syscall, ...)` because we want both the
/// aggregate "all syscalls" cost AND a per-number breakdown.
pub fn syscallSample(num: u32, dt: u64) void {
    if (num >= SYSCALL_TABLE_SIZE) return;
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
