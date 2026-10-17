//! Boot mode 19: the Linux-personality test programs (linux-tests/*.c —
//! static musl, stamped ELFOSABI_LINUX by build.zig), run headless from
//! /bin as children of this kernel task.
//!
//! A case passes when its program exits 0 (the programs exit with the number
//! of their first failed check) on every run and the free-frame count comes
//! back after the counted runs. The programs' stdout reaches the serial log
//! through the Linux layer's writev mirror, so a failure names its check.
//!
//! Verdict line: "[linuxtest] PASS" or "[linuxtest] FAIL".

const std = @import("std");
const process = @import("../proc/process.zig");
const elf_loader = @import("../proc/elf_loader.zig");
const vfs = @import("../fs/vfs.zig");
const pmm = @import("../mm/pmm.zig");
const nvme = @import("../driver/nvme.zig");
const boot_phase = @import("../boot/boot_phase.zig");
const serial = @import("../debug/serial.zig");
const lprof = @import("../debug/linux_prof.zig");
const time = @import("../time/time.zig");

const Case = struct {
    path: []const u8,
    /// argv[1..], space separated.
    args: []const u8 = "",
    timeout_ms: u32 = 60_000,
    /// Not built with the kernel: skipped when the image doesn't have it.
    optional: bool = false,
};

const CASES = [_]Case{
    .{ .path = "/bin/lt_basic.elf", .args = "one two three" },
    .{ .path = "/bin/lt_mm.elf" },
    .{ .path = "/bin/lt_thread.elf" },
    .{ .path = "/bin/lt_fs.elf" },
    // The official Zig compiler (static musl, 172 MB), stamped OSABI 3 and
    // written into ext2.img by hand.
    .{ .path = "/bin/zig", .args = "version", .timeout_ms = 120_000, .optional = true },
};

const WARMUP_RUNS: u32 = 1;
const COUNTED_RUNS: u32 = 2;
/// Two CPUs' PMM magazines plus slack, as in mode 18.
const DRIFT_LIMIT: u32 = 2 * pmm.CACHE_SIZE + 32;

var failures: u32 = 0;

const Outcome = union(enum) {
    exited: u32,
    spawn_failed,
    timed_out,
};

/// "/bin/lt_mm.elf" → "lt_mm".
fn progName(path: []const u8) []const u8 {
    var start: usize = 0;
    for (path, 0..) |ch, i| {
        if (ch == '/') start = i + 1;
    }
    const base = path[start..];
    const ext = ".elf";
    if (base.len > ext.len and std.mem.eql(u8, base[base.len - ext.len ..], ext)) return base[0 .. base.len - ext.len];
    return base;
}

fn runOnce(c: Case) Outcome {
    var raw_buf: [256]u8 = undefined;
    const raw = if (c.args.len == 0)
        c.path
    else
        std.fmt.bufPrint(&raw_buf, "{s} {s}", .{ c.path, c.args }) catch return .spawn_failed;
    const launch = elf_loader.LaunchInfo{
        .name = progName(c.path),
        .raw = raw,
        .fname_len = c.path.len,
        .start_held = true,
    };
    const pid = elf_loader.spawnPath(c.path, launch) orelse return .spawn_failed;
    // Parent it here so the exit leaves a zombie holding the status.
    process.getPCB(pid).parent_pid = @intCast(process.getCurrentPid());
    process.assignInitialCpu(pid);
    process.setState(pid, .ready);

    // Done when the lead is a zombie and no thread of the group is left.
    var waited: u32 = 0;
    var timed_out = false;
    while (process.procs[pid].state != .zombie or process.countThreadsInGroup(@intCast(pid)) != 0) : (waited += 10) {
        if (!timed_out and waited >= c.timeout_ms) {
            // Every thread: a lead killed alone leaves its workers running.
            process.killThreadGroup(@intCast(pid), 0xDEAD0000 | 9);
            timed_out = true;
        }
        if (timed_out and waited >= c.timeout_ms + 10_000) return .timed_out; // the kill didn't take
        process.kernelSleepMs(10);
    }
    const status = process.procs[pid].exit_status;
    process.reapZombie(@intCast(pid));
    if (timed_out) return .timed_out;
    return .{ .exited = status };
}

fn check(c: Case, run: u32) void {
    // Let the last report drain out first, outside this run's time and
    // counters (~0.1 s of UART for a report; the virtio console is instant).
    process.kernelSleepMs(300);
    lprof.reset();
    const t0 = time.monotonicNanos();
    const outcome = runOnce(c);
    serial.print("[linuxtest] {s} run {d}: {d} ms\n", .{ c.path, run, (time.monotonicNanos() - t0) / 1_000_000 });
    lprof.dumpAndReset(progName(c.path));
    switch (outcome) {
        .exited => |st| if (st != 0) {
            serial.print("[linuxtest] FAIL {s} run {d}: exit status {d}\n", .{ c.path, run, st });
            failures += 1;
        },
        .spawn_failed => {
            serial.print("[linuxtest] FAIL {s} run {d}: spawn failed\n", .{ c.path, run });
            failures += 1;
        },
        .timed_out => {
            serial.print("[linuxtest] FAIL {s} run {d}: no exit within {d} ms, killed\n", .{ c.path, run, c.timeout_ms });
            failures += 1;
        },
    }
}

/// What a clock read and a VM exit cost on this machine.
fn probeClock() void {
    const perf = @import("../debug/perf.zig");
    const per_q = @import("../time/apic.zig").tscPerQuantumSane();
    if (per_q == 0) return;
    const reads: u64 = 1000;
    const t0 = perf.rdtsc();
    var i: u64 = 0;
    while (i < reads) : (i += 1) _ = time.monotonicNanos();
    const cycles = perf.rdtsc() - t0;
    serial.print("[linuxtest] clock read: {d} ns\n", .{cycles * 10_000_000 / per_q / reads});

    // A port write, to the POST port (0x80) nothing listens on: a VM exit.
    const outs: u64 = 200;
    const t1 = perf.rdtsc();
    i = 0;
    while (i < outs) : (i += 1) @import("../io.zig").outb(0x80, 0);
    serial.print("[linuxtest] port write: {d} ns\n", .{(perf.rdtsc() - t1) * 10_000_000 / per_q / outs});
}

/// What one root-disk read costs on an idle system, by size.
fn probeDisk() void {
    const perf = @import("../debug/perf.zig");
    const per_q = @import("../time/apic.zig").tscPerQuantumSane();
    if (per_q == 0) return;
    const S = struct {
        var buf: [128 * 1024]u8 align(4096) = undefined;
    };
    for ([_]u16{ 8, 64, 256 }) |sectors| {
        const reads: u64 = 32;
        nvme.lat_device_cycles = 0;
        nvme.lat_wake_cycles = 0;
        nvme.lat_irq_cycles = 0;
        nvme.lat_count = 0;
        const t0 = perf.rdtsc();
        var i: u32 = 0;
        while (i < reads) : (i += 1) {
            // Spread over the first 256 MiB, away from each other.
            const lba: u32 = (i * 7919 * 256) % (512 * 1024);
            if (!nvme.readSectorsSecondary(lba, sectors, &S.buf)) {
                serial.print("[linuxtest] disk probe: read failed\n", .{});
                return;
            }
        }
        const cycles = perf.rdtsc() - t0;
        const n = @max(nvme.lat_count, 1);
        serial.print("[linuxtest] disk read {d} KiB: {d} us ({d} commands: to irq {d} us, irq to reap {d} us, reap to waiter {d} us each)\n", .{
            sectors / 2,
            cycles * 10_000 / per_q / reads,
            nvme.lat_count,
            nvme.lat_irq_cycles * 10_000 / per_q / n,
            (nvme.lat_device_cycles -| nvme.lat_irq_cycles) * 10_000 / per_q / n,
            nvme.lat_wake_cycles * 10_000 / per_q / n,
        });
    }
}

pub fn taskEntry() callconv(.c) noreturn {
    // Steady state, as the desktop's first task enters it (async NVMe I/O).
    boot_phase.markComplete();
    nvme.enableAsync();
    probeClock();
    probeDisk();
    serial.print("[linuxtest] {d} program(s), {d} warm-up + {d} counted runs each\n", .{ CASES.len, WARMUP_RUNS, COUNTED_RUNS });

    for (CASES) |c| {
        if (c.optional and vfs.lookupCached(c.path) == null) {
            serial.print("[linuxtest] SKIP {s}: not in the image\n", .{c.path});
            continue;
        }
        var run: u32 = 0;
        while (run < WARMUP_RUNS) : (run += 1) check(c, run);
        process.kernelSleepMs(50);
        const before = pmm.freeFrameCount();
        while (run < WARMUP_RUNS + COUNTED_RUNS) : (run += 1) check(c, run);
        process.kernelSleepMs(50);
        const after = pmm.freeFrameCount();
        const drift: u32 = before -| after;
        serial.print("[linuxtest] {s}: free frames {d} -> {d} over {d} runs (drift {d}, limit {d})\n", .{ c.path, before, after, COUNTED_RUNS, drift, DRIFT_LIMIT });
        if (drift > DRIFT_LIMIT) {
            serial.print("[linuxtest] FAIL {s}: frames leak across runs\n", .{c.path});
            failures += 1;
        }
    }

    // What the programs wrote is read back from the image on the host.
    @import("../fs/ext2/ext2.zig").sync();
    if (failures == 0) {
        serial.print("[linuxtest] PASS\n", .{});
    } else {
        serial.print("[linuxtest] FAIL ({d} failure(s))\n", .{failures});
    }
    while (true) process.kernelSleepMs(1000);
}
