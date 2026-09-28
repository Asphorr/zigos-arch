//! Boot mode 18: user-space test programs, run headless, then the kernel
//! heap's pool growth and kalloc's vmalloc path.
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
const heap = @import("../mm/heap.zig");
const vmalloc = @import("../mm/vmalloc.zig");
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

/// 1.5 MB blocks can't share a 2 MB pool, so each one past what the base
/// pool holds makes the heap grow from PMM; freeing them must hand all but
/// one empty grown pool back.
fn heapPools() void {
    const BIG: usize = 1536 * 1024;
    const before = heap.snapshot();
    const frames_before = pmm.freeFrameCount();
    var ptrs: [3][*]u8 = undefined;
    var n: usize = 0;
    while (n < ptrs.len) : (n += 1) {
        ptrs[n] = heap.kmalloc(BIG) orelse break;
        @memset(ptrs[n][0..BIG], @intCast(0xA0 + n));
    }
    const mid = heap.snapshot();
    var intact = true;
    for (ptrs[0..n], 0..) |p, i| {
        const tag: u8 = @intCast(0xA0 + i);
        if (p[0] != tag or p[BIG / 2] != tag or p[BIG - 1] != tag) intact = false;
        heap.kfree(p);
    }
    const after = heap.snapshot();
    const frames_after = pmm.freeFrameCount();
    const grows = mid.pools_grown - before.pools_grown;
    const returns = after.pools_returned - before.pools_returned;
    serial.print("[usertest] heap pools: {d} x {d} KB allocated, grew {d}, returned {d}; pools {d} -> {d} -> {d}, total {d} -> {d} -> {d} KB; free frames {d} -> {d}\n", .{
        n,                      BIG / 1024,              grows,         returns,
        before.pools,           mid.pools,               after.pools,   before.total_bytes / 1024,
        mid.total_bytes / 1024, after.total_bytes / 1024, frames_before, frames_after,
    });
    const valid = heap.validateHeap() and heap.validateInvariants() and heap.validateFreelists();
    if (n != ptrs.len or !intact or grows < 2 or returns + 1 < grows or
        after.total_bytes > before.total_bytes + 2 * 1024 * 1024 or !valid)
    {
        serial.print("[usertest] FAIL heap pools: allocated {d}/{d}, intact {}, grows {d}, returns {d}, validators {}\n", .{ n, ptrs.len, intact, grows, returns, valid });
        failures += 1;
    }
}

/// kalloc's large path: vmalloc regions, freed with both CPUs up so the TLB
/// flush runs. The rounds take ~18000 pages in all against a 16384-page
/// arena, so pages that never come back run it dry.
fn vmallocRounds() void {
    const SIZES = [_]usize{ 16 * 1024, 36 * 1024, 300 * 1024 };
    const ROUNDS: u32 = 200;
    const pages_before = vmalloc.pagesInUse();
    const regions_before = vmalloc.liveRegions();
    const frames_before = pmm.freeFrameCount();
    var bad: u32 = 0;
    var round: u32 = 0;
    while (round < ROUNDS) : (round += 1) {
        var ptrs = [_]?[*]u8{null} ** SIZES.len;
        for (SIZES, 0..) |sz, i| {
            const p = heap.kalloc(sz) orelse {
                bad += 1;
                continue;
            };
            if (!vmalloc.contains(@intFromPtr(p))) bad += 1;
            @memset(p[0..sz], @intCast(0x30 + i));
            ptrs[i] = p;
        }
        for (ptrs, SIZES, 0..) |maybe, sz, i| {
            const p = maybe orelse continue;
            const tag: u8 = @intCast(0x30 + i);
            if (p[0] != tag or p[sz / 2] != tag or p[sz - 1] != tag) bad += 1;
            heap.kfreeAuto(p);
        }
    }
    const pages_after = vmalloc.pagesInUse();
    const regions_after = vmalloc.liveRegions();
    const frames_after = pmm.freeFrameCount();
    const drift: u32 = frames_before -| frames_after;
    serial.print("[usertest] vmalloc: {d} rounds x {d} regions, {d} bad; arena pages {d} -> {d}, regions {d} -> {d}; free frames {d} -> {d} (drift {d}, limit {d})\n", .{
        ROUNDS,       SIZES.len,     bad,            pages_before, pages_after, regions_before,
        regions_after, frames_before, frames_after, drift,        DRIFT_LIMIT,
    });
    if (bad != 0 or pages_after != pages_before or regions_after != regions_before or drift > DRIFT_LIMIT) {
        serial.print("[usertest] FAIL vmalloc rounds\n", .{});
        failures += 1;
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

    heapPools();
    vmallocRounds();

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
