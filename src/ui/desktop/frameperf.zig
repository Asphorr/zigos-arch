// Compositor frame-time percentiles — the "where does a frame actually go"
// instrument. Every desktop-loop iteration that renders is split into three
// phases and recorded into allocation-free log2-bucket histograms; a
// [frameperf] block with p50/p90/p99/max per phase prints every ~30 s.
//
//   prep   — parkOrYield return → render dispatch: input drain, pipe drain,
//            animations, GUI recomposite (renderWindow into backbuf).
//   flush  — time inside display.flush/flushRect (the virtio-gpu or GOP
//            round-trip), accumulated across however many rect flushes the
//            frame issued. Instrumented in display.zig so every dirty-kind
//            arm is covered without per-site stamps.
//   render — the dispatch span minus flush: renderScene + blitToScreen +
//            cursor bake, i.e. the CPU compositing cost.
//
// Iterations that wake and find nothing to draw (dirty == .none) don't
// pollute the percentiles — they count as idle_wakes, which is itself a
// health metric for the event-driven wake system (a high idle_wakes/frames
// ratio means some producer requests wakes with no work attached).
//
// Log2 buckets give ×2 resolution — coarse, but stable, allocation-free,
// and plenty to tell "flush-bound at 8ms" from "composite-bound at 1ms".
// Percentiles report the bucket's UPPER bound (`p50<512us`).
//
// Threading: all state is desktop-task-only (BSP). display.flush is also
// callable from the mode-9 GPU-compositor task; flushBegin returns 0 unless
// the desktop is mid-frame, and the desktop never runs concurrently with
// its own frame, so cross-task attribution noise is limited to the rare
// case of a flush-blocked frame interleaving with the compositor task —
// acceptable for a diagnostic.

const debug = @import("../../debug/debug.zig");
const perf = @import("../../debug/perf.zig");
const apic = @import("../../time/apic.zig");

const N_BUCKETS = 26; // bucket k covers [2^(k-1), 2^k) µs; last = everything above
const N_PHASES = 4; // prep, render, flush, total
const PHASE_NAMES = [N_PHASES][]const u8{ "prep  ", "render", "flush ", "total " };
const DUMP_INTERVAL_TICKS: u64 = 3000; // ~30 s at 100 Hz

pub const Kind = enum(u3) { none, cursor, text, gui, drag, full };
const KIND_COUNT = 6;

var in_frame: bool = false;
var t_frame_start: u64 = 0;
var t_prep_done: u64 = 0;
var flush_tsc_accum: u64 = 0;

var hist: [N_PHASES][N_BUCKETS]u64 = .{.{0} ** N_BUCKETS} ** N_PHASES;
var max_us: [N_PHASES]u64 = .{0} ** N_PHASES;
var frames: u64 = 0;
var idle_wakes: u64 = 0;
var kind_counts: [KIND_COUNT]u64 = .{0} ** KIND_COUNT;
var last_dump_tick: u64 = 0;

/// Loop iteration owns the CPU (parkOrYield returned). Stamp frame start.
pub fn frameBegin() void {
    t_frame_start = perf.rdtsc();
    t_prep_done = t_frame_start;
    flush_tsc_accum = 0;
    in_frame = true;
}

/// All pre-render work done; the dirty dispatch starts now.
pub fn prepDone() void {
    t_prep_done = perf.rdtsc();
}

/// Called by display.flush/flushRect on entry. 0 = not a desktop frame.
pub fn flushBegin() u64 {
    if (!in_frame) return 0;
    return perf.rdtsc();
}

pub fn flushEnd(t0: u64) void {
    if (t0 == 0) return;
    flush_tsc_accum +%= perf.rdtsc() -% t0;
}

/// Frame complete. Records histograms (or idle_wakes for a no-op wake) and
/// prints the periodic dump.
pub fn frameEnd(kind: Kind, now_tick: u64) void {
    const t_end = perf.rdtsc();
    in_frame = false;

    if (kind == .none) {
        idle_wakes += 1;
    } else {
        const tpq = apic.tscPerQuantum(); // TSC ticks per 10ms quantum
        if (tpq != 0) {
            const prep_us = tscToUs(t_prep_done -% t_frame_start, tpq);
            const total_us = tscToUs(t_end -% t_frame_start, tpq);
            const flush_us = tscToUs(flush_tsc_accum, tpq);
            const dispatch_us = tscToUs(t_end -% t_prep_done, tpq);
            const render_us = if (dispatch_us > flush_us) dispatch_us - flush_us else 0;
            record(0, prep_us);
            record(1, render_us);
            record(2, flush_us);
            record(3, total_us);
            frames += 1;
            kind_counts[@intFromEnum(kind)] += 1;
        }
    }

    if (last_dump_tick == 0) last_dump_tick = now_tick;
    if (now_tick -% last_dump_tick >= DUMP_INTERVAL_TICKS) {
        dump(now_tick -% last_dump_tick);
        reset(now_tick);
    }
}

fn tscToUs(delta: u64, tpq: u64) u64 {
    // quantum = 10ms = 10_000µs. delta*10_000 overflows u64 only past
    // ~50 years of TSC; frame spans are ms-class.
    return (delta *% 10_000) / tpq;
}

fn record(phase: usize, us: u64) void {
    hist[phase][bucketOf(us)] += 1;
    if (us > max_us[phase]) max_us[phase] = us;
}

fn bucketOf(us: u64) usize {
    if (us == 0) return 0;
    const bits: usize = 64 - @as(usize, @clz(us));
    return @min(bits, N_BUCKETS - 1);
}

/// Upper-bound µs of the bucket holding the q-th percentile.
fn percentile(phase: usize, q: u64) u64 {
    const need = (frames * q + 99) / 100;
    var cum: u64 = 0;
    for (0..N_BUCKETS) |b| {
        cum += hist[phase][b];
        if (cum >= need) return @as(u64, 1) << @intCast(b);
    }
    return max_us[phase];
}

fn dump(window_ticks: u64) void {
    if (frames == 0) {
        debug.klog("[frameperf] {d}t window: 0 frames, idle_wakes={d}\n", .{ window_ticks, idle_wakes });
        return;
    }
    debug.klog(
        "[frameperf] {d}t window: frames={d} (full={d} drag={d} gui={d} text={d} cur={d}) idle_wakes={d}\n",
        .{
            window_ticks,                        frames,
            kind_counts[@intFromEnum(Kind.full)], kind_counts[@intFromEnum(Kind.drag)],
            kind_counts[@intFromEnum(Kind.gui)],  kind_counts[@intFromEnum(Kind.text)],
            kind_counts[@intFromEnum(Kind.cursor)], idle_wakes,
        },
    );
    for (0..N_PHASES) |p| {
        debug.klog(
            "[frameperf]   {s} p50<{d}us p90<{d}us p99<{d}us max={d}us\n",
            .{ PHASE_NAMES[p], percentile(p, 50), percentile(p, 90), percentile(p, 99), max_us[p] },
        );
    }
}

fn reset(now_tick: u64) void {
    hist = .{.{0} ** N_BUCKETS} ** N_PHASES;
    max_us = .{0} ** N_PHASES;
    frames = 0;
    idle_wakes = 0;
    kind_counts = .{0} ** KIND_COUNT;
    last_dump_tick = now_tick;
}
