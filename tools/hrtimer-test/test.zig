//! Off-target unit tests for `src/proc/hrtimer.zig` — the pure TSC arithmetic
//! behind the precise-`usleep` (#1006) hrtimer path. Runs under `zig test` in
//! microseconds: no QEMU, no NIC, no real clock.
//!
//! `hrtimer.zig` imports only `std`, so — unlike `tools/net-test` — there are no
//! stub modules. `run.sh` copies the live `src/proc/hrtimer.zig` in beside this
//! file (gitignored) so the import stays inside the module path (Zig 0.15
//! forbids `@import` escaping it); it always tests current source.

const std = @import("std");
const hrt = @import("hrtimer.zig");

const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;

// Representative calibration: 3 GHz ⇒ 30,000,000 TSC ticks per 10 ms quantum.
const Q: u64 = 30_000_000;

test "tscPerUs: quantum / 10_000" {
    try expectEqual(@as(u64, 3000), hrt.tscPerUs(Q)); // 3000 ticks/µs at 3 GHz
    try expectEqual(@as(u64, 0), hrt.tscPerUs(0)); // pre-calibration
    try expectEqual(@as(u64, 100), hrt.tscPerUs(1_000_000)); // 100 MHz floor
}

test "deadline: now + usec*tscPerUs, overflow-safe" {
    try expectEqual(@as(u64, 1000 + 500 * 3000), hrt.deadline(1000, 500, Q));
    // usec at u32 max must not overflow the multiply (widened to u64 first).
    const big = hrt.deadline(0, std.math.maxInt(u32), Q);
    try expectEqual(@as(u64, @as(u64, std.math.maxInt(u32)) * 3000), big);
    // wrapping add near 2^64 must not trap.
    _ = hrt.deadline(std.math.maxInt(u64) - 10, 1_000_000, Q);
}

test "due: wraparound-safe past / future / exact" {
    try expect(hrt.due(1000, 1000)); // exactly now → due
    try expect(hrt.due(1001, 1000)); // just past → due
    try expect(!hrt.due(999, 1000)); // just before → not due
    try expect(!hrt.due(0, 1000)); // well before → not due
    // `now` has wrapped ~10 ticks past a deadline that sat just under 2^64.
    try expect(hrt.due(5, std.math.maxInt(u64) - 4));
    // a genuine far-future deadline is never "due".
    try expect(!hrt.due(std.math.maxInt(u64) - 4, 5));
}

test "armDelta: NONE → base unchanged" {
    try expectEqual(@as(u32, 100), hrt.armDelta(100, 5000, hrt.NONE));
}

test "armDelta: hi-res further out than base → base" {
    // deadline 3 quanta out, base one quantum → arm the quantum.
    try expectEqual(@as(u32, @intCast(Q)), hrt.armDelta(@intCast(Q), 0, 3 * Q));
}

test "armDelta: hi-res nearer than base → the smaller delta" {
    // deadline 2 ms out (6,000,000 TSC), base 10 ms quantum → arm 6,000,000.
    const now: u64 = 1_000_000;
    try expectEqual(@as(u32, 6_000_000), hrt.armDelta(@intCast(Q), now, now + 6_000_000));
}

test "armDelta: past/stale deadline → base, NEVER a tiny delta (anti-livelock)" {
    // Regression for the freeze: a stale-past cached deadline must arm the full
    // base quantum, not 1 tick. Arming a tiny delta on a past value re-fires the
    // timer every tick forever (≈67×/quantum observed → tick_count crawls →
    // watchdog wedge). wakeHiresExpired heals the cache on the next base tick.
    const base: u32 = @intCast(Q);
    try expectEqual(base, hrt.armDelta(base, 5000, 5000)); // exactly due
    try expectEqual(base, hrt.armDelta(base, 5001, 5000)); // just past
    try expectEqual(base, hrt.armDelta(base, 1_000_000_000, 5000)); // long stale-past
}

test "ticksToAdvance: exactly one quantum → 1" {
    const r = hrt.ticksToAdvance(Q, 0, Q);
    try expectEqual(@as(u32, 1), r.n);
    try expectEqual(Q, r.last);
}

test "ticksToAdvance: early hi-res fire (sub-quantum) → 0, watermark unmoved" {
    const r = hrt.ticksToAdvance(Q - 1, 0, Q); // not a full quantum yet
    try expectEqual(@as(u32, 0), r.n);
    try expectEqual(@as(u64, 0), r.last);
}

test "ticksToAdvance: 3.5 quanta elapsed → 3, watermark at 3Q" {
    const r = hrt.ticksToAdvance(Q * 7 / 2, 0, Q);
    try expectEqual(@as(u32, 3), r.n);
    try expectEqual(@as(u64, 3 * Q), r.last);
}

test "ticksToAdvance: absurd gap caps at MAX_CATCHUP and snaps watermark to now" {
    const now = Q * 100_000; // ~1000 s worth, far past the cap
    const r = hrt.ticksToAdvance(now, 0, Q);
    try expectEqual(hrt.MAX_CATCHUP, r.n);
    try expectEqual(now, r.last); // snapped to now, not 100*Q
}

test "ticksToAdvance: zero calibration → no advance (no div-by-zero / spin)" {
    const r = hrt.ticksToAdvance(123456, 0, 0);
    try expectEqual(@as(u32, 0), r.n);
    try expectEqual(@as(u64, 0), r.last);
}

test "ticksToAdvance: watermark wraps across 2^64 cleanly → 1" {
    const last = std.math.maxInt(u64) - Q / 2; // half a quantum before wrap
    const now = last +% Q; // one full quantum later, wrapped past 0
    const r = hrt.ticksToAdvance(now, last, Q);
    try expectEqual(@as(u32, 1), r.n);
    try expectEqual(last +% Q, r.last);
}
