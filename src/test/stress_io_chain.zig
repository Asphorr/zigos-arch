// stress_io_chain — reproduce the chain that led to the 2026-05-19
// watchdog cpu1-wedge.
//
// Activated by boot_mode=11. Observed chain from the failing log:
//   * Multiple processes doing sequential NVMe reads (yields/sec ≥100).
//   * Desktop driving virtio_gpu flushes through the new
//     sendSimpleCmdPair batched path (ctrl_lock held across blockOn
//     .gpu_io, ~20-100 ms per flush).
//   * Heavy schedule churn from both — pid bouncing between cpu0/cpu1.
//   * Watchdog fired on cpu1 stuck in kernelIdle for 3+s; cause unclear
//     between code and host-SMI freeze.
//
// Strategy: max the same load patterns deliberately and see whether the
// wedge surfaces. If it does → real bug, narrow it down. If 50 sec of
// hammering completes clean → strong evidence the wedge is host-SMI.
//
//   1. Spawn N=4 worker kernel tasks. Each loops:
//        vfs.loadFileFresh(file_i) → free pages → repeat.
//      Cycles through a short file list so allocCid sees varied cids.
//   2. Main task issues a dirty-rect virtio_gpu flush every iter,
//      driving sendSimpleCmdPair under ctrl_lock pressure.
//   3. Main task yields ~5 ms between iters so workers run.
//   4. Progress is logged every 256 iters; final summary at end.

const std = @import("std");
const process = @import("../proc/process.zig");
const vfs = @import("../fs/vfs.zig");
const pmm = @import("../mm/pmm.zig");
const paging = @import("../mm/paging.zig");
const smp = @import("../cpu/smp.zig");
const serial = @import("../debug/serial.zig");
const debug = @import("../debug/debug.zig");
const virtio_gpu = @import("../driver/virtio_gpu.zig");

const WORKERS: u32 = 4;
const ITERATIONS: u32 = 5000;
const WORKER_KSTACK: usize = 16 * 1024;

const TEST_FILES = [_][]const u8{
    "/bin/files.elf",
    "/bin/editor.elf",
    "/bin/sysmon.elf",
    "/bin/fastfetch.elf",
};

var stop_requested: bool = false;
var worker_iter: [WORKERS]u64 align(8) = [_]u64{0} ** WORKERS;
var worker_failed: [WORKERS]u64 align(8) = [_]u64{0} ** WORKERS;

fn workerEntry() callconv(.c) noreturn {
    // Each worker gets a unique slot via current_pid — we use that as
    // the worker index modulo WORKERS for stat bookkeeping. The actual
    // pid is fine, we just need a stable bucket per task.
    const cur = smp.myCpu().current_pid orelse {
        while (true) asm volatile ("cli; hlt");
    };
    const slot: usize = cur % WORKERS;
    var idx: u32 = 0;
    while (!@atomicLoad(bool, &stop_requested, .acquire)) : (idx +%= 1) {
        const fname = TEST_FILES[idx % TEST_FILES.len];
        if (vfs.loadFileFresh(fname)) |fresh| {
            const buf_virt: usize = @intFromPtr(fresh.buf);
            const buf_phys = paging.virtToPhys(buf_virt);
            if (buf_phys) |phys| pmm.freeContiguous(phys, fresh.pages);
            _ = @atomicRmw(u64, &worker_iter[slot], .Add, 1, .acq_rel);
        } else {
            _ = @atomicRmw(u64, &worker_failed[slot], .Add, 1, .acq_rel);
        }
        // Brief yield so other workers + desktop get CPU time. Without
        // this, a single worker monopolises cpu0 and the chain doesn't
        // exercise multi-pid contention.
        process.kernelSleepMs(0);
    }
    // Cooperative stop. PID destroy is handled by the main task post-
    // loop via killProcess; we just halt.
    while (true) asm volatile ("cli; hlt");
}

pub fn taskEntry() callconv(.c) noreturn {
    serial.print(
        "[stress-iochain] mode=11 workers={d} iters={d}\n",
        .{ WORKERS, ITERATIONS },
    );

    // Spawn the workers. Distribute across CPUs by leaving cpu_id=0xFF
    // (no pin) so the scheduler places them where it likes — drives
    // migration pressure.
    var worker_pids: [WORKERS]u8 = [_]u8{0xFF} ** WORKERS;
    for (0..WORKERS) |i| {
        const pid_opt = process.createKernelTask(
            @intFromPtr(&workerEntry),
            "stress-io-worker",
            0xFF,
            .normal,
            WORKER_KSTACK,
        );
        if (pid_opt) |pid| {
            worker_pids[i] = @intCast(pid);
            serial.print("[stress-iochain] worker {d} pid={d}\n", .{ i, pid });
        } else {
            serial.print("[stress-iochain] failed to spawn worker {d}\n", .{i});
        }
    }

    var iter: u32 = 0;
    var flushes_attempted: u64 = 0;
    while (iter < ITERATIONS) : (iter += 1) {
        // GPU pressure — flush a small dirty rect every iter. Drives
        // sendSimpleCmdPair under contention with worker NVMe loads.
        // Even when nothing changed visually the cmds still go out;
        // that's exactly the contention we want.
        if (virtio_gpu.active) {
            virtio_gpu.flushRectUnconditional(0, 0, 64, 64);
            flushes_attempted +%= 1;
        }

        if ((iter & 0xFF) == 0) {
            var total_iter: u64 = 0;
            var total_fail: u64 = 0;
            for (worker_iter) |w| total_iter +%= w;
            for (worker_failed) |w| total_fail +%= w;
            serial.print(
                "[stress-iochain] iter {d}/{d} flushes={d} workers_done={d} workers_fail={d}\n",
                .{ iter, ITERATIONS, flushes_attempted, total_iter, total_fail },
            );
        }

        // Pace ~ 200/sec so we don't starve workers entirely.
        process.kernelSleepMs(5);
    }

    serial.print("[stress-iochain] main loop done — signalling workers\n", .{});
    @atomicStore(bool, &stop_requested, true, .release);

    // Give workers a beat to notice, then kill any stragglers.
    process.kernelSleepMs(50);
    for (worker_pids) |pid| {
        if (pid != 0xFF) process.killProcess(pid);
    }
    _ = process.reapStaleZombies(0);

    var total_iter: u64 = 0;
    var total_fail: u64 = 0;
    for (worker_iter) |w| total_iter +%= w;
    for (worker_failed) |w| total_fail +%= w;
    serial.print(
        "[stress-iochain] DONE: {d} flushes, {d} worker loads, {d} fails — no wedge\n",
        .{ flushes_attempted, total_iter, total_fail },
    );

    while (true) asm volatile ("cli; hlt");
}
