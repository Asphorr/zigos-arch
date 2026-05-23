// mtswap — MT eviction stress test.
//
// Spawns N threads that all sweep the SAME large buffer whose working set
// exceeds free RAM. Concurrent faults on the same swapped VAs exercise the
// MT eviction hardening landed in commit bd36828:
//
//   - swapInFrame CAS: two threads PF on the same SWAPPED VA at once. Only
//     one wins the PRESENT install; the loser re-reads the PTE, sees
//     PRESENT, and returns success instead of OOM-killing the process.
//
//   - .swap_evict wait: thread B faults on a VA that thread A's evictor
//     just stamped SWAP_INFLIGHT. B parks via blockOnSwapEvict; wakes when
//     A's writePage completes and the PTE flips to SWAPPED, then retries
//     the swap-in.
//
//   - tearDownTask slot reclaim: not exercised by this test (no kill
//     mid-evict); the structural fix is reviewer-verified.
//
// Pass criterion: 0 corrupted byte-0 reads across all threads × all sweeps.
// Before the hardening, the same workload would race the original
// reclaimViaSwap CAS-less sequence and produce either spurious double
// evictions, PRESENT/SWAPPED PTE corruption, or a use-after-free of the
// frame that was about to be written to disk.

const std = @import("std");
const libc = @import("libc");

// Workload sizing is the tricky part: too big and the test thrashes for
// minutes (4 threads × cold-page count × ~5 ms/swap-in compounds fast); too
// small and the buffer fits in RAM with no eviction, so we don't exercise the
// path at all. We pick the smallest buffer that STILL forces eviction
// (free + 8 MiB) and one sweep per thread.
const N_THREADS: u32 = 2;
const SWEEPS_PER_THREAD: u32 = 1;

const Job = extern struct {
    id: u32,
    bad: u32 = 0,
};

var buf: []u8 = &[_]u8{};
var pages: usize = 0;

fn pat(p: usize) u8 {
    return @truncate(p *% 7 +% 13);
}

// NOTE: don't use std.fmt here. The kernel's sysClone sets the new thread's
// RSP to (stack_top) which is 16-byte aligned; the x86-64 SysV ABI requires
// RSP at function entry to be `8 mod 16` so that `call` aligns to 16 before
// movaps. Any function the LLVM backend chooses to spill XMM at the prologue
// (std.fmt.bufPrint suffices — integer formatting is heavy enough) GPFs at
// the first movaps. Until kernel/clone fixes RSP, keep thread bodies free of
// SSE-spilling code paths and use libc helpers that don't trigger it.
fn scanner(arg: ?*anyopaque) callconv(.c) ?*anyopaque {
    const job: *Job = @ptrCast(@alignCast(arg.?));
    libc.klog("[mtswap] scanner START\n");
    var sweep: u32 = 0;
    while (sweep < SWEEPS_PER_THREAD) : (sweep += 1) {
        var p: usize = 0;
        while (p < pages) : (p += 1) {
            if (buf[p * 4096] != pat(p)) job.bad +%= 1;
        }
    }
    libc.klog("[mtswap] scanner END\n");
    return null;
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    const mi = libc.meminfo();
    const free_bytes: usize = @as(usize, mi.free_frames) * 4096;
    // Only exceed free RAM by 4 MiB (~1k pages must live on swap). swaptest
    // overshoots by 48 MiB to stress capacity; the MT race is exercised on
    // any concurrent fault, not only at high cold-page counts. Keep total
    // work bounded so the test actually finishes (QEMU NVMe ~5 ms per I/O
    // under contention compounds badly with sweep × thread × cold-set).
    var target: usize = free_bytes + 4 * 1024 * 1024;
    const CAP: usize = 220 * 1024 * 1024;
    if (target > CAP) target = CAP;

    libc.print("mtswap: free RAM = ");
    libc.printNum(@intCast(free_bytes / (1024 * 1024)));
    libc.print(" MiB; allocating ");
    libc.printNum(@intCast(target / (1024 * 1024)));
    libc.print(" MiB; ");
    libc.printNum(N_THREADS);
    libc.print(" threads x ");
    libc.printNum(SWEEPS_PER_THREAD);
    libc.print(" sweeps\n");

    buf = libc.mmap(target) orelse {
        libc.print("mtswap: mmap FAILED\n");
        libc.exit();
    };
    pages = buf.len / 4096;

    // Stamp every page from the main thread so each scanner has a per-page
    // expected value. By the time the scanners run, many of these pages will
    // already have been evicted to swap (mmap pressure + scanner-induced
    // faults), so byte-0 reads will fault them back in.
    var p: usize = 0;
    while (p < pages) : (p += 1) {
        buf[p * 4096] = pat(p);
    }
    libc.print("mtswap: stamped ");
    libc.printNum(@intCast(pages));
    libc.print(" pages; racing scanners\n");

    var jobs: [N_THREADS]Job = undefined;
    var tcbs: [N_THREADS]?*libc.Tcb = .{null} ** N_THREADS;
    var i: u32 = 0;
    while (i < N_THREADS) : (i += 1) {
        jobs[i] = .{ .id = i };
        tcbs[i] = libc.pthreadCreate(scanner, &jobs[i]);
        if (tcbs[i] == null) {
            libc.print("\x1b[31mmtswap: pthreadCreate failed at i=\x1b[0m");
            libc.printNum(i);
            libc.print("\n");
            libc.exit();
        }
    }

    i = 0;
    while (i < N_THREADS) : (i += 1) {
        if (tcbs[i]) |tcb| _ = libc.pthreadJoin(tcb);
    }

    var total_bad: u64 = 0;
    i = 0;
    while (i < N_THREADS) : (i += 1) total_bad += jobs[i].bad;

    var msgbuf: [192]u8 = undefined;
    if (total_bad == 0) {
        const out = std.fmt.bufPrint(
            &msgbuf,
            "mtswap: PASS - {d} threads x {d} sweeps x {d} pages, 0 corrupt\n",
            .{ N_THREADS, SWEEPS_PER_THREAD, pages },
        ) catch "mtswap: PASS\n";
        libc.print(out);
        libc.klog(out);
    } else {
        const out = std.fmt.bufPrint(
            &msgbuf,
            "\x1b[31mmtswap: FAIL - {d} corrupt reads across {d} threads\x1b[0m\n",
            .{ total_bad, N_THREADS },
        ) catch "mtswap: FAIL\n";
        libc.print(out);
        libc.klog(out);
    }
    libc.exit();
}
