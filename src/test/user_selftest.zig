//! Boot mode 18: user-space test programs, run headless.
//!
//! This kernel task spawns each program as its parent, waits for it to exit
//! and checks the exit status. Two warm-up runs settle the caches, then the
//! free-frame count must come back after the counted runs: a kernel buffer
//! that fork shares and nobody frees shows up as drift.
//!
//! Verdict line: "[usertest] PASS" or "[usertest] FAIL".

const process = @import("../proc/process.zig");
const elf_loader = @import("../proc/elf_loader.zig");
const vfs = @import("../fs/vfs.zig");
const pmm = @import("../mm/pmm.zig");
const serial = @import("../debug/serial.zig");

const Case = struct {
    path: []const u8,
    name: []const u8,
    ok_status: u32,
};

// /tar/ keeps the loader on the private elf_buf path, so fork shares that
// buffer too, not only forktest's own file mapping.
const CASES = [_]Case{
    .{ .path = "/tar/forktest.elf", .name = "forktest", .ok_status = 0xCAFE0042 },
};

const WARMUP_RUNS: u32 = 2;
const COUNTED_RUNS: u32 = 10;
const RUN_TIMEOUT_MS: u32 = 30_000;
/// Two CPUs' PMM magazines (2 x CACHE_SIZE) plus slack. One run of forktest
/// leaks 16 frames if its two file buffers are never released.
const DRIFT_LIMIT: u32 = 2 * pmm.CACHE_SIZE + 32;

var failures: u32 = 0;

const Outcome = union(enum) {
    exited: u32,
    spawn_failed,
    timed_out,
};

fn runOnce(c: Case) Outcome {
    const fresh = vfs.loadFileFresh(c.path) orelse return .spawn_failed;
    const launch = elf_loader.LaunchInfo{
        .name = c.name,
        .raw = c.path,
        .fname_len = c.path.len,
        .start_held = true,
    };
    // loadAndStart owns the buffer from here, including on failure.
    const pid = elf_loader.loadAndStart(fresh.buf, fresh.size, fresh.pages, fresh.inode, launch) orelse return .spawn_failed;
    // Parent it here so the exit leaves a zombie holding the status.
    process.getPCB(pid).parent_pid = @intCast(process.getCurrentPid());
    process.assignInitialCpu(pid);
    process.setState(pid, .ready);

    var waited: u32 = 0;
    while (process.procs[pid].state != .zombie) : (waited += 10) {
        if (waited >= RUN_TIMEOUT_MS) {
            process.killProcess(@intCast(pid));
            return .timed_out;
        }
        process.kernelSleepMs(10);
    }
    const status = process.procs[pid].exit_status;
    process.reapZombie(@intCast(pid));
    return .{ .exited = status };
}

fn check(c: Case, run: u32) void {
    switch (runOnce(c)) {
        .exited => |st| if (st != c.ok_status) {
            serial.print("[usertest] FAIL {s} run {d}: exit status 0x{X}, want 0x{X}\n", .{ c.path, run, st, c.ok_status });
            failures += 1;
        },
        .spawn_failed => {
            serial.print("[usertest] FAIL {s} run {d}: spawn failed\n", .{ c.path, run });
            failures += 1;
        },
        .timed_out => {
            serial.print("[usertest] FAIL {s} run {d}: no exit within {d} ms, killed\n", .{ c.path, run, RUN_TIMEOUT_MS });
            failures += 1;
        },
    }
}

pub fn taskEntry() callconv(.c) noreturn {
    serial.print("[usertest] {d} program(s), {d} warm-up + {d} counted runs each\n", .{ CASES.len, WARMUP_RUNS, COUNTED_RUNS });

    for (CASES) |c| {
        var run: u32 = 0;
        while (run < WARMUP_RUNS) : (run += 1) check(c, run);
        process.kernelSleepMs(50);
        const before = pmm.freeFrameCount();
        while (run < WARMUP_RUNS + COUNTED_RUNS) : (run += 1) check(c, run);
        process.kernelSleepMs(50);
        const after = pmm.freeFrameCount();
        const drift: u32 = before -| after;
        serial.print("[usertest] {s}: free frames {d} -> {d} over {d} runs (drift {d}, limit {d})\n", .{ c.path, before, after, COUNTED_RUNS, drift, DRIFT_LIMIT });
        if (drift > DRIFT_LIMIT) {
            serial.print("[usertest] FAIL {s}: frames leak across runs\n", .{c.path});
            failures += 1;
        }
    }

    if (!pmm.validateIndex()) {
        serial.print("[usertest] FAIL: PMM frame index disagrees with the bitmap\n", .{});
        failures += 1;
    }

    if (failures == 0) {
        serial.print("[usertest] PASS\n", .{});
    } else {
        serial.print("[usertest] FAIL ({d} failure(s))\n", .{failures});
    }
    while (true) process.kernelSleepMs(1000);
}
