# hrtimer pure-arithmetic test harness

Drives [`src/proc/hrtimer.zig`](../../src/proc/hrtimer.zig) under `zig test`,
off-target, in sub-seconds — no QEMU, no timer hardware, no scheduler.

## Why this exists

`sysUsleep` used to busy-wait its sub-tick remainder
(`while (monotonicNanos() < target) pause;`) — an HPET-MMIO poll that pinned a
core at 100% and, on QEMU, took a VM exit per iteration. By the kernel's own
gap-adjusted perf counter that one syscall burned **~19.3 billion on-CPU cycles**
in a single session — the #1 sink in the whole kernel (3× the next).

The fix arms the LAPIC **TSC-deadline one-shot** to fire exactly when the sleep
is due and *blocks* the task in between, so the core halts (or runs other work)
instead of spinning. `hrtimer.zig` holds the bug-prone arithmetic of that fix —
u64 TSC wraparound, the µs→TSC conversion, the one-shot arm-delta clamp, and the
tick catch-up that keeps the 100 Hz wallclock honest when the one-shot fires
*early* for a sub-quantum deadline. Those are exactly the things that are hard to
get right and impossible to see fail on a fast lossless boot, so they get pinned
here deterministically.

The module imports only `std` (no hardware, no globals), so there are no stub
modules. `run.sh` copies the live `src/proc/hrtimer.zig` in beside `test.zig`
(gitignored) — Zig 0.15 forbids an `@import` that escapes the harness module
path — so every run still tests current source.

## Run it

```sh
tools/hrtimer-test/run.sh
ZIG=~/Загрузки/zig-x86_64-linux-0.15.2/zig tools/hrtimer-test/run.sh
```

Expect:

```
All N tests passed.
EXIT=0
```

## What's pinned (`test.zig`)

| function | proves / pins |
|----------|---------------|
| `tscPerUs` | µs scale = `tsc_per_quantum / 10_000`; 0 before calibration |
| `deadline` | `now + usec*tscPerUs`, u32 `usec` widened so the multiply can't overflow; wrapping add near 2^64 doesn't trap |
| `due` | wraparound-safe past/future/exact compare (signed-difference trick) |
| `armDelta` | NONE → quantum; hi-res further → quantum; hi-res nearer → the smaller delta; already-due → 1 (fire ASAP, **never 0**) |
| `ticksToAdvance` | exactly 1 quantum → 1; **early sub-quantum fire → 0** (the wallclock-corruption guard); 3.5 quanta → 3; absurd gap → cap + snap; zero calibration → no spin; watermark wrap across 2^64 |

Every test pins a property the kernel glue (`sysUsleep`,
`sched.wakeHiresExpired`, irq0's tick body + `rearmTimerForCurrent`) depends on.
