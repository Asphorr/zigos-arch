// Cross-CPU wake-IPI latency test.
//
// Activated by booting with menu entry "Stress: wake-IPI" (boot_mode=10).
// Hunts the bug where setState(.ready) on a remote CPU's PCB doesn't
// reliably IPI the remote CPU out of idle.
//
// Design v2: worker self-measures, driver only emits wakes on a slow
// cadence with real sleeps in between. v1 had the driver pause-spinning
// while polling iter_done — under Hyper-V that starves the cpu0 vCPU of
// scheduling time and the test wedges itself (today's run: cpu0 frozen
// at the `cmp tick_count` instruction in the pause-spin while cpu1's
// watchdog fired). Tight kernel pause-spin loops are a hostile
// environment for hypervisor co-scheduling — don't.
//
// Layout: driver runs on cpu0 (we're the boot task), worker pinned to
// cpu1 via createKernelTask. Each iteration:
//   1. Driver stamps send_tsc, calls wake(worker_pid).
//   2. Driver kernelSleepMs(SLEEP) — gives both vCPUs scheduler slack
//      AND gives worker time to wake, measure, and re-block.
//   3. Worker, inside blockOn return, stamps resume_tsc and computes
//      latency = resume_tsc - send_tsc. It buckets the latency itself.
//   4. Worker re-blocks before driver's sleep expires.
//
// TSC cross-CPU compare assumes invariant TSC (true on every host CPU
// since Nehalem). If you see negative or absurd latencies in the
// summary, suspect the host paused TSC during VMEXIT — that's a
// separate issue and the result still tells us shapes (instant vs tick
// vs broken).
//
// Reading the histogram:
//   instant/fast (< 1M cycles, ~280μs) — wake-IPI fired, μs-scale wake
//   tick   (< 50M cyc, ~14ms)          — woken by next 100Hz tick,
//                                         IPI didn't fire but timer
//                                         rescued cpu1
//   slow/broken (>= 50M cyc)           — multi-tick stall or wake-IPI
//                                         outright dead. Real bug.
//   no_wake_count > 0                  — wake() returned but worker
//                                         didn't run within SLEEP_MS:
//                                         confirmed wedge or worker
//                                         deeper than SLEEP_MS to wake.

const std = @import("std");
const process = @import("../proc/process.zig");
const smp = @import("../cpu/smp.zig");
const serial = @import("../debug/serial.zig");
const debug = @import("../debug/debug.zig");
const perf = @import("../debug/perf.zig");

const ITERATIONS: u32 = 1_000;
const SLEEP_MS: u32 = 50; // Per-iter pause; lets host co-schedule
const WORKER_KSTACK: usize = 8 * 1024;
const TARGET_CPU: u8 = 1;

// Shared state. Driver writes send_tsc + iter_index; worker reads
// send_tsc, writes resume_tsc + iter_done + histogram. Pure atomic
// access — no locks.
var worker_pid: u8 = 0xFF;
var send_tsc: u64 = 0;
var iter_index: u32 = 0; // Bumped by driver before each wake; worker
// reads this to know which iteration's send_tsc
// it just consumed.
var iter_done: u32 = 0; // Bumped by worker after recording latency.
var worker_should_exit: u32 = 0;

// Histogram — written by worker only (single-writer, multi-reader for
// driver's progress print). Atomic for the cross-CPU read by driver.
var hist_instant: u32 = 0; // < 100k cyc  (~28 μs)
var hist_fast: u32 = 0; // < 1M cyc    (~280 μs)
var hist_tick: u32 = 0; // < 50M cyc   (~14 ms)
var hist_slow: u32 = 0; // < 500M cyc  (~140 ms)
var hist_broken: u32 = 0; // >= 500M cyc
var hist_neg: u32 = 0; // negative (TSC went backward across CPUs)
var hist_spurious: u32 = 0; // same iter_index seen twice (double wake)
var max_latency: u64 = 0;
var sum_latency: u64 = 0;

fn workerEntry() callconv(.c) noreturn {
    var counter: u32 = 0;
    var last_iter: u32 = 0xFFFF_FFFF;
    while (@atomicLoad(u32, &worker_should_exit, .acquire) == 0) {
        const target: u32 = @truncate(@intFromPtr(&iter_done));
        process.blockOn(.futex, target);
        const tsc = perf.rdtsc();
        // The SHUTDOWN wake must not be measured: it arrives with a stale
        // send_tsc from the last real iteration, so it used to book one
        // bogus slow/broken tally — a perfect run still summarized 1001
        // wakes for 1000 driven, with 1 "broken" scaring the reader.
        if (@atomicLoad(u32, &worker_should_exit, .acquire) != 0) break;
        // Spurious-wake dedup: a doubled delivery (wake_pending latched
        // while we hadn't re-blocked yet) re-measures the SAME iteration
        // against the same send_tsc, second time with inflated latency.
        // iter_index is written by the driver before each wake precisely
        // for this; the worker just never read it until now.
        const cur_iter = @atomicLoad(u32, &iter_index, .acquire);
        if (cur_iter == last_iter) {
            hist_spurious +%= 1;
        } else {
            last_iter = cur_iter;
            const send = @atomicLoad(u64, &send_tsc, .acquire);

            // Treat backward TSC (host paused TSC during VMEXIT, or cross-
            // CPU skew) as a separate bucket. Don't fold it into instant —
            // the read would be misleading.
            if (send > tsc) {
                hist_neg +%= 1;
            } else {
                const latency = tsc - send;
                sum_latency +%= latency;
                if (latency > max_latency) max_latency = latency;
                if (latency < 100_000) {
                    hist_instant +%= 1;
                } else if (latency < 1_000_000) {
                    hist_fast +%= 1;
                } else if (latency < 50_000_000) {
                    hist_tick +%= 1;
                } else if (latency < 500_000_000) {
                    hist_slow +%= 1;
                } else {
                    hist_broken +%= 1;
                }
            }
        }
        counter +%= 1;
        @atomicStore(u32, &iter_done, counter, .release);
    }
    while (true) asm volatile ("cli; hlt");
}

pub fn taskEntry() callconv(.c) noreturn {
    serial.print("[wake-ipi] cross-CPU wake latency test (v2)\n", .{});
    serial.print("[wake-ipi] worker pinned to cpu{d}; {d} iters, {d}ms per iter\n", .{ TARGET_CPU, ITERATIONS, SLEEP_MS });

    // A cross-CPU wake test needs the cross CPU. Booted single-CPU
    // (safe mode / no-APIC), the worker would be created pinned to a CPU
    // that never runs it: 1000 silent no_wakes and a "broken" verdict
    // about a bug that isn't there.
    if (smp.cpu_count <= TARGET_CPU) {
        serial.print("[wake-ipi] FATAL: needs cpu{d} online (cpu_count={d}) — boot full SMP\n", .{ TARGET_CPU, smp.cpu_count });
        while (true) asm volatile ("cli; hlt");
    }

    const w_pid_opt = process.createKernelTask(
        @intFromPtr(&workerEntry),
        "wake-w",
        TARGET_CPU,
        .interactive,
        WORKER_KSTACK,
    );
    const w_pid: u8 = if (w_pid_opt) |p| @intCast(p) else {
        serial.print("[wake-ipi] FATAL: createKernelTask failed\n", .{});
        while (true) asm volatile ("cli; hlt");
    };
    @atomicStore(u8, &worker_pid, w_pid, .release);

    // Let worker schedule, reach its first blockOn.
    process.kernelSleepMs(100);
    serial.print("[wake-ipi] worker pid={d} parked; starting wake loop\n", .{w_pid});

    var no_wake_count: u32 = 0;

    var iter: u32 = 0;
    while (iter < ITERATIONS) : (iter += 1) {
        const prev_done = @atomicLoad(u32, &iter_done, .acquire);
        const send = perf.rdtsc();
        @atomicStore(u64, &send_tsc, send, .release);
        @atomicStore(u32, &iter_index, iter, .release);
        process.wake(w_pid);

        // No spin — just sleep. SLEEP_MS chosen so the worker has
        // plenty of slack to wake, measure, and re-block.
        process.kernelSleepMs(SLEEP_MS);

        const new_done = @atomicLoad(u32, &iter_done, .acquire);
        if (new_done <= prev_done) {
            no_wake_count += 1;
            if (no_wake_count <= 8) {
                serial.print("[wake-ipi] iter={d}: worker didn't wake within {d}ms\n", .{ iter, SLEEP_MS });
            }
        }

        if ((iter > 0) and ((iter % 100) == 0)) {
            serial.print("[wake-ipi] iter={d}/{d} instant={d} fast={d} tick={d} slow={d} broken={d} neg={d} no_wake={d}\n", .{
                iter, ITERATIONS,
                @atomicLoad(u32, &hist_instant, .acquire),
                @atomicLoad(u32, &hist_fast, .acquire),
                @atomicLoad(u32, &hist_tick, .acquire),
                @atomicLoad(u32, &hist_slow, .acquire),
                @atomicLoad(u32, &hist_broken, .acquire),
                @atomicLoad(u32, &hist_neg, .acquire),
                no_wake_count,
            });
        }
    }

    @atomicStore(u32, &worker_should_exit, 1, .release);
    process.wake(w_pid);
    process.kernelSleepMs(100);

    const fi = @atomicLoad(u32, &hist_instant, .acquire);
    const ff = @atomicLoad(u32, &hist_fast, .acquire);
    const ft = @atomicLoad(u32, &hist_tick, .acquire);
    const fs = @atomicLoad(u32, &hist_slow, .acquire);
    const fb = @atomicLoad(u32, &hist_broken, .acquire);
    const fn_ = @atomicLoad(u32, &hist_neg, .acquire);
    const counted: u32 = fi + ff + ft + fs + fb;
    const avg: u64 = if (counted > 0) sum_latency / counted else 0;
    serial.print("\n[wake-ipi] ===== summary =====\n", .{});
    serial.print("[wake-ipi] driven iterations  = {d}\n", .{ITERATIONS});
    serial.print("[wake-ipi] worker wakes counted = {d}\n", .{counted});
    serial.print("[wake-ipi] instant <100k cyc   = {d} ({d}%)\n", .{ fi, pct(fi, counted) });
    serial.print("[wake-ipi] fast    <1M  cyc    = {d} ({d}%)\n", .{ ff, pct(ff, counted) });
    serial.print("[wake-ipi] tick    <50M cyc    = {d} ({d}%)\n", .{ ft, pct(ft, counted) });
    serial.print("[wake-ipi] slow    <500M cyc   = {d} ({d}%)\n", .{ fs, pct(fs, counted) });
    serial.print("[wake-ipi] broken >=500M cyc   = {d} ({d}%)\n", .{ fb, pct(fb, counted) });
    serial.print("[wake-ipi] negative (TSC skew) = {d}\n", .{fn_});
    serial.print("[wake-ipi] spurious (dup wake, deduped) = {d}\n", .{@atomicLoad(u32, &hist_spurious, .acquire)});
    serial.print("[wake-ipi] no_wake (driver didn't see iter_done bump) = {d}\n", .{no_wake_count});
    serial.print("[wake-ipi] avg latency = {d} cyc, max = {d} cyc\n", .{ avg, max_latency });
    serial.print("[wake-ipi] Reading the result:\n", .{});
    serial.print("[wake-ipi]   * mostly instant/fast -> wake-IPI working\n", .{});
    serial.print("[wake-ipi]   * mostly tick -> wake-IPI not firing; worker woken by 100Hz timer\n", .{});
    serial.print("[wake-ipi]   * slow/broken -> deep wake-IPI bug\n", .{});
    serial.print("[wake-ipi]   * no_wake>0 -> confirmed missed wake (worker stayed sleeping)\n", .{});
    while (true) asm volatile ("cli; hlt");
}

fn pct(n: u32, total: u32) u32 {
    return if (total == 0) 0 else (n * 100) / total;
}
