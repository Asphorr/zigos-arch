//! Load averages for /proc/loadavg: how many tasks are running or ready to,
//! damped over 1, 5 and 15 minutes the way Linux does it (fixed point, one
//! sample every 5 seconds).
//!
//! `sample` is called about once a second by a kernel thread (filed); it
//! is the only writer. Readers load the three words one by one.

const process = @import("process.zig");
const time = @import("../time/time.zig");

const FIXED_1: u64 = 1 << 11;
/// exp(-5 s / 1 min), exp(-5 s / 5 min), exp(-5 s / 15 min) in FIXED_1.
const DECAY = [3]u64{ 1884, 2014, 2037 };
const SAMPLE_NS: u64 = 5_000_000_000;
/// A gap longer than this many samples is made up only this far.
const CATCH_UP: u64 = 360;

var avg = [3]u64{ 0, 0, 0 };
var next_ns: u64 = 0;

/// Tasks running or ready, the caller and the idle tasks apart.
fn active() u64 {
    const me = process.getCurrentPid();
    var n: u64 = 0;
    for (&process.procs, 0..) |*p, i| {
        if (i == me or p.is_idle) continue;
        if (p.state == .running or p.state == .ready) n += 1;
    }
    return n;
}

/// Take the samples that are due.
pub fn sample() void {
    const now = time.monotonicNanos();
    if (next_ns == 0) next_ns = now + SAMPLE_NS;
    if (now < next_ns) return;
    if (now - next_ns > CATCH_UP * SAMPLE_NS) next_ns = now - CATCH_UP * SAMPLE_NS;
    const load = active() * FIXED_1;
    while (now >= next_ns) : (next_ns += SAMPLE_NS) {
        for (&avg, DECAY) |*a, decay| {
            var v = a.* * decay + load * (FIXED_1 - decay);
            // Rounded up while rising, so a steady load is reached.
            if (load >= a.*) v += FIXED_1 - 1;
            @atomicStore(u64, a, v / FIXED_1, .monotonic);
        }
    }
}

/// The three averages in hundredths.
pub fn hundredths() [3]u64 {
    var out: [3]u64 = undefined;
    for (&out, &avg) |*o, *a| {
        o.* = (@atomicLoad(u64, a, .monotonic) + FIXED_1 / 200) * 100 / FIXED_1;
    }
    return out;
}
