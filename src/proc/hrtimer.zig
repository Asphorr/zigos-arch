//! Pure high-resolution-timer arithmetic for the precise-`usleep` path (#1006).
//!
//! Background: `sysUsleep` used to busy-wait its sub-tick remainder in a
//! `while (monotonicNanos() < target) pause;` loop — an HPET-MMIO poll that
//! pinned a core at 100% (and, on QEMU, took a VM exit every iteration). By the
//! kernel's own gap-adjusted perf counter that single syscall burned ~19.3
//! billion on-CPU cycles in one session — the #1 sink. The fix arms the LAPIC
//! TSC-deadline one-shot to fire exactly when the sleep is due and blocks the
//! task in between, so the core halts or runs other work instead of spinning.
//!
//! This module carries the bug-prone arithmetic of that fix — u64 TSC
//! wraparound, the microsecond→TSC conversion, the one-shot arm-delta clamp,
//! and the tick catch-up after an early/late fire. Every function takes its
//! state as explicit parameters and imports nothing but `std`, so the
//! off-target harness `tools/hrtimer-test` exercises every edge under
//! `zig test` in microseconds — same recipe as `tools/net-test`. The kernel
//! glue (`sysUsleep`, `sched.wakeHiresExpired`, irq0's tick body +
//! `rearmTimerForCurrent`) calls these; `rdtsc` / `wrmsr` / the proc-table scan
//! stay in the callers.

const std = @import("std");

/// Sentinel for "no pending hi-res deadline" — also the initial value of the
/// earliest-deadline cache. `maxInt` sorts after every real deadline, so a
/// `min`-style cache never picks it over a genuine one.
pub const NONE: u64 = std.math.maxInt(u64);

/// TSC ticks per microsecond, from the per-10 ms-quantum calibration
/// (`apic.tscPerQuantum()`). A quantum is 10_000 µs. Integer-truncating: at any
/// realistic TSC rate (≥10 MHz ⇒ ≥10 ticks/µs; modern CPUs are 1000–4000×
/// that) the truncation error is far below the timer's own fire jitter.
/// Returns 0 only before calibration has run.
pub inline fn tscPerUs(tsc_per_quantum: u64) u64 {
    return tsc_per_quantum / 10_000;
}

/// Absolute TSC value at which a `usleep(usec)` issued at `now_tsc` becomes due.
/// Wrapping arithmetic so a TSC near 2^64 doesn't trap; the wrap is undone
/// symmetrically by `due()`. `usec` is widened before the multiply so the
/// product can't overflow u32.
pub fn deadline(now_tsc: u64, usec: u32, tsc_per_quantum: u64) u64 {
    const per_us = tscPerUs(tsc_per_quantum);
    return now_tsc +% @as(u64, usec) *% per_us;
}

/// Has `deadline_tsc` arrived as of `now_tsc`? Wraparound-safe: the half of the
/// u64 ring *behind* `now` counts as "past". Correct as long as a pending
/// deadline is less than 2^63 TSC ticks out (≈ a century at 3 GHz), which every
/// real sleep is. This is the signed-difference trick written in unsigned form.
pub inline fn due(now_tsc: u64, deadline_tsc: u64) bool {
    return (now_tsc -% deadline_tsc) < (@as(u64, 1) << 63);
}

/// Delta to program the one-shot timer for, in the same unit `apic.armOneShot`
/// wants — TSC ticks, since the hi-res path is gated on TSC-deadline mode. The
/// result is the nearer of the normal `base` (one quantum, or the idle-AP
/// multiple) and the time remaining until a *future* `earliest_hires_tsc`.
///
/// A past-or-equal deadline returns `base`, NOT a tiny delta — this is the
/// anti-livelock invariant. `wakeHiresExpired` runs at the top of each timer
/// IRQ and wakes every due sleeper *before* the re-arm, so by the time we get
/// here a "due" value means the cache is momentarily stale (its sleeper already
/// woke). Arming `1` on a stale-past value would make the timer re-fire every
/// tick forever (≈67×/quantum was observed → tick_count crawls → watchdog). The
/// next regular `base` tick re-runs wakeHiresExpired, which heals the cache; a
/// genuinely-overdue sleeper is caught there too, at most one quantum late.
pub fn armDelta(base: u32, now_tsc: u64, earliest_hires_tsc: u64) u32 {
    if (earliest_hires_tsc == NONE) return base;
    if (due(now_tsc, earliest_hires_tsc)) return base; // past/stale → never livelock
    const d = earliest_hires_tsc -% now_tsc; // > 0 (genuinely in the future)
    if (d >= base) return base; // hi-res is further out than the quantum
    return @intCast(d); // 0 < d < base ≤ maxInt(u32)
}

/// Tick catch-up after a timer fire. The 100 Hz wallclock must advance by the
/// number of whole quanta that have actually elapsed (TSC-measured), NOT by one
/// per IRQ — because the hi-res path fires the one-shot EARLY for sub-quantum
/// deadlines, and those early fires must add 0 ticks (otherwise `tick_count`,
/// and every `sysSleep`/timeout keyed off it, would run fast). Returns how many
/// quanta to advance and the new `last_tick_tsc` watermark.
pub const MAX_CATCHUP: u32 = 100; // 1 s at 100 Hz — see ticksToAdvance

pub const Advance = struct { n: u32, last: u64 };

/// `now_tsc` — current TSC; `last_tick_tsc` — watermark of the last accounted
/// tick; `tsc_per_quantum` — TSC ticks per 10 ms. Normally returns n=1 (a real
/// tick boundary) or n=0 (an early hi-res fire). Caps the catch-up so a clock
/// jump (suspend/resume, recalibration) can't make the handler emit a flood of
/// ticks or spin: beyond `MAX_CATCHUP` it snaps the watermark to `now` and
/// reports the cap.
pub fn ticksToAdvance(now_tsc: u64, last_tick_tsc: u64, tsc_per_quantum: u64) Advance {
    if (tsc_per_quantum == 0) return .{ .n = 0, .last = last_tick_tsc };
    var n: u32 = 0;
    var last = last_tick_tsc;
    while (n < MAX_CATCHUP and due(now_tsc, last +% tsc_per_quantum)) {
        last +%= tsc_per_quantum;
        n += 1;
    }
    if (n >= MAX_CATCHUP) return .{ .n = MAX_CATCHUP, .last = now_tsc };
    return .{ .n = n, .last = last };
}
