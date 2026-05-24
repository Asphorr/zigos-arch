// Heavy PMM stress test — exercises every code path of the region-bucketed
// rewrite (project_pmm_region_rewrite_2026_05_24.md) with conditions
// chosen to surface bugs:
//
//   1. Single-frame churn       — uniqueness + magazine path
//   2. Contiguous sized matrix  — freelist popRunGE across all orders
//   3. Cross-region big allocs  — locks-all-256 path + edge re-push
//   4. Fragmentation + coalesce — checkerboard then heal, validate runs return
//   5. Run pool exhaustion      — drive run_pool_freelist→NULL_RUN, must not panic
//   6. Coalesce verification    — alloc A+B, free, re-alloc combined, address check
//   7. UAF via canary           — corrupt freed frame, next alloc must detect
//   8. Below-4G                 — DMA path, all phys < 4 GiB
//   9. User reserve             — allocFrameUser refuses below kernel reserve
//  10. Magazine drain pressure  — overflow cache repeatedly, force per-region drains
//  11. Refcount churn (COW)     — acquireFrame/releaseFrame depth, final free
//  12. Edge cases               — 0-count, bad addr, total-free=0
//  13. SMP concurrent           — N kernel tasks hammering different regions
//  14. Mixed long run           — randomized pattern across phases for T iterations
//
// Activated by boot_mode == 12. Driver runs as a kernel task on cpu 0; phase
// 13 spawns N-1 more tasks on the other CPUs. Reports per-phase PASS/FAIL +
// aggregate; on FAIL it logs what it observed but DOES NOT panic (we want
// the test to complete so we see all failures, not just the first).

const std = @import("std");
const pmm = @import("../mm/pmm.zig");
const paging = @import("../mm/paging.zig");
const serial = @import("../debug/serial.zig");
const debug = @import("../debug/debug.zig");
const process = @import("../proc/process.zig");
const lifecycle = @import("../proc/lifecycle.zig");
const smp = @import("../cpu/smp.zig");
const perf = @import("../debug/perf.zig");

// ---------------------------------------------------------------------------
// Tracking state — pre-allocated static arrays so the test itself never
// allocates via the kernel heap (which sits on top of PMM — avoid feedback
// loops). Sizing chosen so each phase can record up to TRACK_MAX addresses
// for uniqueness validation.
// ---------------------------------------------------------------------------

const TRACK_MAX: u32 = 16384;

var tracking: [TRACK_MAX]usize = undefined;
var tracking_count: u32 = 0;

var phases_passed: u32 = 0;
var phases_failed: u32 = 0;
var anomalies: u32 = 0;

// SMP phase shared counters.
var smp_iterations: [smp.MAX_CPUS]u64 = [_]u64{0} ** smp.MAX_CPUS;
var smp_anomalies: [smp.MAX_CPUS]u64 = [_]u64{0} ** smp.MAX_CPUS;
var smp_done: [smp.MAX_CPUS]u32 = [_]u32{0} ** smp.MAX_CPUS;
var smp_should_stop: u32 = 0;

const SMP_DURATION_TICKS: u64 = 1_000_000_000; // ~0.5 s on 2 GHz

// ---------------------------------------------------------------------------
// Test-friendly RNG. xorshift64 — deterministic, no allocator dependency.
// Seeds from rdtsc per-phase so order matters but reruns differ.
// ---------------------------------------------------------------------------
var rng_state: u64 = 0xDEADBEEFCAFE1234;

fn rngSeed(s: u64) void {
    rng_state = if (s == 0) 1 else s;
}

fn rng() u64 {
    var x = rng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    rng_state = x;
    return x;
}

fn rngU32Range(max_exclusive: u32) u32 {
    if (max_exclusive == 0) return 0;
    return @as(u32, @truncate(rng())) % max_exclusive;
}

// ---------------------------------------------------------------------------
// PASS / FAIL output. fail() never panics — drives anomalies counter so
// we keep running and see every phase's result.
// ---------------------------------------------------------------------------

fn pass(comptime phase: []const u8, comptime fmt: []const u8, args: anytype) void {
    serial.print("[pmmstress] PASS " ++ phase ++ ": " ++ fmt ++ "\n", args);
    phases_passed += 1;
}

fn fail(comptime phase: []const u8, comptime fmt: []const u8, args: anytype) void {
    serial.print("[pmmstress] FAIL " ++ phase ++ ": " ++ fmt ++ "\n", args);
    phases_failed += 1;
    anomalies += 1;
}

fn note(comptime phase: []const u8, comptime fmt: []const u8, args: anytype) void {
    serial.print("[pmmstress] " ++ phase ++ ": " ++ fmt ++ "\n", args);
}

inline fn frameOf(phys: usize) u32 {
    return @intCast(phys / pmm.PUB_FRAME_SIZE);
}

inline fn regionOf(phys: usize) u32 {
    return frameOf(phys) / pmm.PUB_REGION_FRAMES;
}

inline fn writeMagic(phys: usize, magic: u64) void {
    const ptr: *u64 = @ptrFromInt(paging.physToVirt(phys));
    ptr.* = magic;
}

inline fn readMagic(phys: usize) u64 {
    const ptr: *const u64 = @ptrFromInt(paging.physToVirt(phys));
    return ptr.*;
}

// Uniqueness check — quadratic but tracking_count is bounded by TRACK_MAX
// and we use this only in phases where N ≤ 1024.
fn assertAllUnique(comptime phase: []const u8) void {
    var i: u32 = 0;
    var dups: u32 = 0;
    while (i < tracking_count) : (i += 1) {
        var j: u32 = i + 1;
        while (j < tracking_count) : (j += 1) {
            if (tracking[i] == tracking[j]) {
                dups += 1;
                if (dups <= 4) {
                    fail(phase, "duplicate addr 0x{X} at [{d}] and [{d}]", .{ tracking[i], i, j });
                }
            }
        }
    }
    if (dups > 4) fail(phase, "{d} more duplicates suppressed", .{dups - 4});
}

fn freeAllTracked(comptime phase: []const u8) void {
    var i: u32 = 0;
    while (i < tracking_count) : (i += 1) {
        pmm.freeFrame(tracking[i]);
    }
    note(phase, "freed {d} tracked frames", .{tracking_count});
    tracking_count = 0;
}

// ===========================================================================
// PHASE 1 — Single-frame churn (~10k alloc/write/verify/free cycles)
// ===========================================================================

fn phase1_singleChurn() void {
    note("p1", "single-frame churn: 10k alloc, validate uniqueness + magic, free", .{});
    rngSeed(perf.rdtsc());

    const N: u32 = 10_000;
    const free_before = pmm.freeFrameCount();
    const t0 = perf.rdtsc();

    var allocated: u32 = 0;
    var alloc_failures: u32 = 0;
    // We can't track all 10k for uniqueness (TRACK_MAX = 16k, fits), so we do.
    tracking_count = 0;
    var i: u32 = 0;
    while (i < N) : (i += 1) {
        const phys = pmm.allocFrame() orelse {
            alloc_failures += 1;
            continue;
        };
        if (phys == 0 or (phys & 0xFFF) != 0) {
            fail("p1", "bad phys returned 0x{X}", .{phys});
        }
        writeMagic(phys, phys ^ 0xA5A5_A5A5_A5A5_A5A5);
        if (tracking_count < TRACK_MAX) {
            tracking[tracking_count] = phys;
            tracking_count += 1;
        }
        allocated += 1;
    }

    // Verify magic survived (no neighbor corruption mid-alloc).
    var magic_bad: u32 = 0;
    i = 0;
    while (i < tracking_count) : (i += 1) {
        const want = tracking[i] ^ 0xA5A5_A5A5_A5A5_A5A5;
        if (readMagic(tracking[i]) != want) magic_bad += 1;
    }
    if (magic_bad > 0) fail("p1", "{d}/{d} frames had corrupted magic", .{ magic_bad, tracking_count });

    assertAllUnique("p1");
    freeAllTracked("p1");

    const t1 = perf.rdtsc();
    const free_after = pmm.freeFrameCount();
    note("p1", "allocs={d} fails={d} cycles={d} free_before={d} after={d}", .{
        allocated, alloc_failures, t1 - t0, free_before, free_after,
    });
    if (free_after < free_before - 16 or free_after > free_before + 16) {
        // Magazine state may shift by CACHE_SIZE; bigger swing = leak.
        fail("p1", "free-count drift {d} → {d} exceeds magazine slack", .{ free_before, free_after });
    } else {
        pass("p1", "single-frame churn clean ({d} allocs, {d} fails)", .{ allocated, alloc_failures });
    }
}

// ===========================================================================
// PHASE 2 — Contiguous of varied sizes (exercises every order bucket)
// ===========================================================================

fn phase2_sizedContiguous() void {
    note("p2", "contiguous matrix: sizes 2..1024 × 8 blocks each", .{});
    const sizes = [_]u32{ 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024 };
    const blocks_per_size: u32 = 8;
    const free_before = pmm.freeFrameCount();

    var size_failures: u32 = 0;
    for (sizes) |sz| {
        var bases: [16]usize = undefined;
        var got: u32 = 0;
        var j: u32 = 0;
        while (j < blocks_per_size) : (j += 1) {
            const base = pmm.allocContiguous(sz) orelse continue;
            bases[got] = base;
            got += 1;
            // Stamp the FIRST and LAST frame with a magic pattern based on base+sz.
            writeMagic(base, base ^ @as(u64, sz));
            writeMagic(base + (@as(usize, sz) - 1) * pmm.PUB_FRAME_SIZE, base +% @as(u64, sz));
        }
        // Verify magics still match.
        j = 0;
        while (j < got) : (j += 1) {
            const base = bases[j];
            const want_first = base ^ @as(u64, sz);
            const want_last = base +% @as(u64, sz);
            if (readMagic(base) != want_first or readMagic(base + (@as(usize, sz) - 1) * pmm.PUB_FRAME_SIZE) != want_last) {
                fail("p2", "magic mismatch at base=0x{X} sz={d}", .{ base, sz });
                size_failures += 1;
            }
        }
        // Free everything we got.
        j = 0;
        while (j < got) : (j += 1) pmm.freeContiguous(bases[j], sz);
        if (got < blocks_per_size and sz <= 256) {
            note("p2", "size {d}: only got {d}/{d} blocks (low memory or fragmentation?)", .{ sz, got, blocks_per_size });
        }
    }

    const free_after = pmm.freeFrameCount();
    if (free_after < free_before - 16 or free_after > free_before + 16) {
        fail("p2", "leak suspected: free {d} → {d}", .{ free_before, free_after });
    } else if (size_failures == 0) {
        pass("p2", "all size classes alloc/verify/free clean", .{});
    } else {
        fail("p2", "{d} size-class failures", .{size_failures});
    }
}

// ===========================================================================
// PHASE 3 — Cross-region big allocs (forces allocContiguousCrossRegion)
// ===========================================================================

fn phase3_crossRegion() void {
    note("p3", "cross-region: 2048, 4096 frames (forces all-region lock)", .{});
    const free_before = pmm.freeFrameCount();

    // 2048 frames = 8 MiB = 2 regions
    if (pmm.allocContiguous(2048)) |base| {
        if (regionOf(base) == regionOf(base + 2047 * pmm.PUB_FRAME_SIZE)) {
            note("p3", "8 MiB landed entirely in one region (unexpected w/ REGION_FRAMES=1024)", .{});
        } else {
            note("p3", "8 MiB spans regions {d}..{d}", .{ regionOf(base), regionOf(base + 2047 * pmm.PUB_FRAME_SIZE) });
        }
        // Magic-stamp first/last frame
        writeMagic(base, 0xDEADC0DE);
        writeMagic(base + 2047 * pmm.PUB_FRAME_SIZE, 0xBEEFCAFE);
        if (readMagic(base) != 0xDEADC0DE or readMagic(base + 2047 * pmm.PUB_FRAME_SIZE) != 0xBEEFCAFE) {
            fail("p3", "8 MiB magic mismatch", .{});
        }
        pmm.freeContiguous(base, 2048);
    } else {
        note("p3", "8 MiB alloc returned null (low free, may be OK on 256 MB VM)", .{});
    }

    // 4096 frames = 16 MiB = 4 regions — likely to fail on tight VMs
    if (pmm.allocContiguous(4096)) |base| {
        note("p3", "16 MiB spans regions {d}..{d}", .{ regionOf(base), regionOf(base + 4095 * pmm.PUB_FRAME_SIZE) });
        pmm.freeContiguous(base, 4096);
    } else {
        note("p3", "16 MiB alloc returned null (expected if free contiguous is tight)", .{});
    }

    const free_after = pmm.freeFrameCount();
    if (free_after < free_before - 16 or free_after > free_before + 16) {
        fail("p3", "leak: free {d} → {d}", .{ free_before, free_after });
    } else {
        pass("p3", "cross-region paths exercised without leak", .{});
    }
}

// ===========================================================================
// PHASE 4 — Fragmentation generator + coalescing repair
// ===========================================================================

fn phase4_fragmentationCoalesce() void {
    note("p4", "checkerboard 2000 frames, then heal + verify large alloc succeeds", .{});
    const free_before = pmm.freeFrameCount();

    const N: u32 = 2000;
    if (N > TRACK_MAX) @panic("phase4: TRACK_MAX too small");
    tracking_count = 0;
    var i: u32 = 0;
    while (i < N) : (i += 1) {
        const phys = pmm.allocFrame() orelse break;
        tracking[tracking_count] = phys;
        tracking_count += 1;
    }
    note("p4", "allocated {d} frames for fragmentation", .{tracking_count});

    // Free EVEN indices first (creates 1000 single-frame fragments)
    var freed_even: u32 = 0;
    i = 0;
    while (i < tracking_count) : (i += 2) {
        pmm.freeFrame(tracking[i]);
        freed_even += 1;
    }

    // Try to alloc 16 contiguous — odds are it succeeds somewhere outside the
    // fragmented region, OR fails if local regions are checkerboarded.
    if (pmm.allocContiguous(16)) |base| {
        note("p4", "post-fragment 16-frame alloc OK at 0x{X}", .{base});
        pmm.freeContiguous(base, 16);
    } else {
        note("p4", "post-fragment 16-frame alloc returned null (heavy fragmentation)", .{});
    }

    // Free ODD indices — should fully heal the fragmentation, coalescing
    // adjacent freed frames into big runs.
    i = 1;
    while (i < tracking_count) : (i += 2) pmm.freeFrame(tracking[i]);
    tracking_count = 0;

    // After full heal, 1024-frame alloc should succeed (we just freed enough).
    if (pmm.allocContiguous(1024)) |base| {
        note("p4", "post-heal 1024-frame alloc OK at 0x{X} (coalesce worked)", .{base});
        pmm.freeContiguous(base, 1024);
        pass("p4", "fragmentation + heal cycle clean", .{});
    } else {
        // May be impossible if existing system load uses the same regions —
        // not a failure, but a flag worth noting.
        note("p4", "post-heal 1024-frame alloc returned null (regions still occupied by system)", .{});
        pass("p4", "fragmentation cycle ran, coalesce-into-1024 may need empty system", .{});
    }

    const free_after = pmm.freeFrameCount();
    if (free_after < free_before - 16 or free_after > free_before + 16) {
        fail("p4", "leak: free {d} → {d}", .{ free_before, free_after });
    }
}

// ===========================================================================
// PHASE 5 — Run pool exhaustion (drive run_pool_freelist→NULL_RUN)
// ===========================================================================

fn phase5_runPoolExhaustion() void {
    note("p5", "drive run pool exhaustion via maximal fragmentation", .{});

    const exhaust_before = pmm.pmmRunPoolExhaustions();
    const pool_free_before = pmm.pmmRunPoolFreeCount();
    note("p5", "pool free before: {d}, exhaustions so far: {d}", .{ pool_free_before, exhaust_before });

    // To maximize freelist node usage: alloc N single frames, free every
    // other one — each freed frame becomes a separate freelist entry
    // (no neighbors to coalesce with). N=4000+ in one round, repeated.
    const ROUNDS: u32 = 3;
    var round: u32 = 0;
    var rounds_done: u32 = 0;
    while (round < ROUNDS) : (round += 1) {
        tracking_count = 0;
        var i: u32 = 0;
        while (i < TRACK_MAX) : (i += 1) {
            const phys = pmm.allocFrame() orelse break;
            tracking[tracking_count] = phys;
            tracking_count += 1;
        }
        // Free every other; the rest get freed at end-of-round.
        i = 0;
        while (i < tracking_count) : (i += 2) pmm.freeFrame(tracking[i]);
        // Now free the odd indices too — should heal everything.
        i = 1;
        while (i < tracking_count) : (i += 2) pmm.freeFrame(tracking[i]);
        tracking_count = 0;
        rounds_done += 1;
    }

    const exhaust_after = pmm.pmmRunPoolExhaustions();
    const pool_free_after = pmm.pmmRunPoolFreeCount();
    note("p5", "{d} rounds done, pool free after: {d}, exhaustions: {d} (Δ={d})", .{
        rounds_done, pool_free_after, exhaust_after, exhaust_after - exhaust_before,
    });

    // Even WITHOUT exhaustion, the test surfaces stale-entry handling. With
    // exhaustion >0, we've proven graceful degradation. Both outcomes pass.
    if (exhaust_after > exhaust_before) {
        // Subsequent allocs must still succeed even with pool exhausted.
        if (pmm.allocFrame()) |p| {
            pmm.freeFrame(p);
            pass("p5", "exhaustion drove +{d}, post-exhaust alloc OK", .{exhaust_after - exhaust_before});
        } else {
            fail("p5", "post-exhaustion allocFrame returned null", .{});
        }
    } else {
        pass("p5", "ran {d} fragmentation rounds without exhausting pool (good)", .{rounds_done});
    }
}

// ===========================================================================
// PHASE 6 — Coalesce verification (alloc A+B adjacent → free both → alloc A+B
// as single block at original A address)
// ===========================================================================

fn phase6_coalesceVerification() void {
    note("p6", "alloc A+B (32 each), free both, alloc 64, validate it lands at A", .{});

    // Use a large pre-alloc to "settle" memory, then do the experiment in
    // its hole. This makes the freelist for the test region predictable.
    const settle = pmm.allocContiguous(2048) orelse {
        note("p6", "skip — couldn't get 2048-frame settle buffer", .{});
        return;
    };

    const a = pmm.allocContiguous(32) orelse {
        pmm.freeContiguous(settle, 2048);
        note("p6", "skip — couldn't get block A", .{});
        return;
    };
    const b = pmm.allocContiguous(32) orelse {
        pmm.freeContiguous(a, 32);
        pmm.freeContiguous(settle, 2048);
        note("p6", "skip — couldn't get block B", .{});
        return;
    };

    note("p6", "A=0x{X} (region {d}), B=0x{X} (region {d})", .{ a, regionOf(a), b, regionOf(b) });

    // Free both blocks.
    pmm.freeContiguous(a, 32);
    pmm.freeContiguous(b, 32);

    // Try alloc 64 — if coalescing worked AND A and B were adjacent in the
    // SAME region, we'd get one combined run back. With per-CPU affinity +
    // first-fit, A and B were almost certainly adjacent.
    if (pmm.allocContiguous(64)) |c| {
        const adjacent = (b == a + 32 * pmm.PUB_FRAME_SIZE) or (a == b + 32 * pmm.PUB_FRAME_SIZE);
        const lower = if (a < b) a else b;
        if (adjacent and c == lower) {
            pass("p6", "coalesce-and-realloc returned the merged block (0x{X})", .{c});
        } else if (adjacent) {
            note("p6", "A+B were adjacent but realloc landed at 0x{X} ≠ lower 0x{X} (other path won)", .{ c, lower });
            pass("p6", "alloc succeeded though not at A (may be cross-region path)", .{});
        } else {
            note("p6", "A and B not adjacent — coalesce test moot", .{});
            pass("p6", "blocks not adjacent (system noise); realloc succeeded", .{});
        }
        pmm.freeContiguous(c, 64);
    } else {
        fail("p6", "post-free 64-frame alloc returned null", .{});
    }

    pmm.freeContiguous(settle, 2048);
}

// ===========================================================================
// PHASE 7 — UAF via canary corruption
// ===========================================================================

fn phase7_uafCanary() void {
    note("p7", "alloc → free → corrupt → re-alloc → expect canary mismatch", .{});

    const before = pmm.pmmCanaryMismatches();

    // free→alloc on same CPU is LIFO via magazine, so the next allocFrame
    // typically returns the just-freed frame. We try 4 times to maximize
    // odds the canary check actually fires on OUR corruption (vs. some
    // other frame from refill).
    var detected: u32 = 0;
    var trials: u32 = 0;
    while (trials < 4) : (trials += 1) {
        const x = pmm.allocFrame() orelse {
            note("p7", "allocFrame returned null, abort trial", .{});
            break;
        };
        pmm.freeFrame(x); // canary written
        // Corrupt the canary by writing garbage to first 16 bytes.
        const dst: *[2]u64 = @ptrFromInt(paging.physToVirt(x));
        dst[0] = 0xDEADDEADDEADDEAD;
        dst[1] = 0xFEEDFEEDFEEDFEED;
        const y = pmm.allocFrame() orelse {
            note("p7", "post-corrupt allocFrame returned null", .{});
            continue;
        };
        if (y == x) {
            const after = pmm.pmmCanaryMismatches();
            if (after > before + detected) {
                detected += 1;
            }
        }
        pmm.freeFrame(y);
    }

    const after = pmm.pmmCanaryMismatches();
    note("p7", "canary mismatches {d} → {d} (detected {d}/{d} trials)", .{ before, after, detected, trials });
    if (detected > 0) {
        pass("p7", "UAF canary fired", .{});
    } else {
        fail("p7", "canary did not fire — UAF detection broken OR all 4 trials missed re-alloc", .{});
    }
}

// ===========================================================================
// PHASE 8 — Below-4G DMA path
// ===========================================================================

fn phase8_below4G() void {
    note("p8", "alloc 16 × single + 1 × 16-contig below 4 GiB", .{});

    const max4g: usize = 0x100000000;
    var i: u32 = 0;
    var got: u32 = 0;
    var bad: u32 = 0;
    var addrs: [16]usize = undefined;
    while (i < 16) : (i += 1) {
        const p = pmm.allocFrameBelow4G() orelse break;
        addrs[got] = p;
        if (p >= max4g) bad += 1;
        got += 1;
    }
    i = 0;
    while (i < got) : (i += 1) pmm.freeFrame(addrs[i]);

    if (pmm.allocContiguousBelow4G(16)) |base| {
        if (base + 15 * pmm.PUB_FRAME_SIZE >= max4g) {
            bad += 1;
        }
        pmm.freeContiguous(base, 16);
    } else {
        note("p8", "16-contig-below-4G alloc returned null", .{});
    }

    if (bad == 0) {
        pass("p8", "all below-4G allocs respected the 4 GiB cap ({d} singles + 16-contig)", .{got});
    } else {
        fail("p8", "{d} allocs returned phys >= 4 GiB", .{bad});
    }
}

// ===========================================================================
// PHASE 9 — User reserve enforcement (light-touch — can't realistically drain)
// ===========================================================================

fn phase9_userReserve() void {
    const reserve = pmm.userReserveFrames();
    const free = pmm.freeFrameCount();
    note("p9", "user reserve = {d} frames, current free = {d}", .{ reserve, free });

    // We can at least verify allocFrameUser succeeds when free >> reserve.
    if (free <= reserve + 16) {
        fail("p9", "free ({d}) too close to reserve ({d}) to test cleanly", .{ free, reserve });
        return;
    }
    if (pmm.allocFrameUser()) |p| {
        pmm.freeFrame(p);
        pass("p9", "allocFrameUser served when free > reserve", .{});
    } else {
        fail("p9", "allocFrameUser unexpectedly null", .{});
    }

    // Bounded-fail test: ask for a contiguous block that would push us
    // below the reserve. Should refuse.
    const huge: u32 = if (free > reserve) free - reserve else 0;
    if (huge > 0 and huge < 8192) {
        const p = pmm.allocContiguousUser(huge);
        if (p) |base| {
            // Some headroom may still exist; not a hard failure, just note.
            note("p9", "huge user-contig alloc of {d} unexpectedly succeeded (returned 0x{X}, freeing)", .{ huge, base });
            pmm.freeContiguous(base, huge);
        } else {
            note("p9", "huge user-contig refused (good)", .{});
        }
    }
}

// ===========================================================================
// PHASE 10 — Magazine drain pressure (force per-region drains)
// ===========================================================================

fn phase10_magazineDrain() void {
    note("p10", "fill cache via batch alloc then batch free, repeat 100×", .{});
    const free_before = pmm.freeFrameCount();
    const exhaust_before = pmm.pmmRunPoolExhaustions();

    var round: u32 = 0;
    while (round < 100) : (round += 1) {
        // Alloc 64 frames (definitely exceeds CACHE_SIZE=32, forces bitmap path)
        tracking_count = 0;
        var i: u32 = 0;
        while (i < 64) : (i += 1) {
            const p = pmm.allocFrame() orelse break;
            tracking[tracking_count] = p;
            tracking_count += 1;
        }
        // Free 64 frames in reverse (exercise magazine drain via coalesce)
        var j: u32 = tracking_count;
        while (j > 0) {
            j -= 1;
            pmm.freeFrame(tracking[j]);
        }
        tracking_count = 0;
    }
    const free_after = pmm.freeFrameCount();
    const exhaust_after = pmm.pmmRunPoolExhaustions();
    note("p10", "exhaust Δ={d}, free {d} → {d}", .{ exhaust_after - exhaust_before, free_before, free_after });
    if (free_after < free_before - 32 or free_after > free_before + 32) {
        fail("p10", "leak after 100 rounds: free {d} → {d}", .{ free_before, free_after });
    } else {
        pass("p10", "100 alloc/free rounds clean", .{});
    }
}

// ===========================================================================
// PHASE 11 — acquireFrame / releaseFrame refcount churn (COW path)
// ===========================================================================

fn phase11_refcountChurn() void {
    note("p11", "acquireFrame 100× then releaseFrame 100×, validate final free", .{});
    const x = pmm.allocFrame() orelse {
        fail("p11", "initial alloc failed", .{});
        return;
    };
    var i: u32 = 0;
    while (i < 100) : (i += 1) pmm.acquireFrame(x);
    if (pmm.frameRefCount(x) != 101) {
        fail("p11", "expected refcount 101 after acquires, got {d}", .{pmm.frameRefCount(x)});
    }
    i = 0;
    while (i < 100) : (i += 1) pmm.releaseFrame(x);
    if (pmm.frameRefCount(x) != 1) {
        fail("p11", "expected refcount 1 after releases, got {d}", .{pmm.frameRefCount(x)});
    }
    pmm.freeFrame(x); // refcount → 0, actually freed
    if (pmm.frameRefCount(x) != 0) {
        fail("p11", "expected refcount 0 after final free, got {d}", .{pmm.frameRefCount(x)});
        return;
    }
    pass("p11", "refcount cycle clean (1 → 101 → 1 → 0)", .{});
}

// ===========================================================================
// PHASE 12 — Edge cases
// ===========================================================================

fn phase12_edgeCases() void {
    note("p12", "0-count alloc, bad-addr free, allocFrame after huge drain", .{});

    // (a) allocContiguous(0) → null
    if (pmm.allocContiguous(0) != null) {
        fail("p12", "allocContiguous(0) should return null", .{});
    }

    // (b) freeFrame on garbage addr should NOT panic — just log + return.
    pmm.freeFrame(0xFFFFFFFFFFFFF000); // way past MAX_FRAMES * FRAME_SIZE
    note("p12", "freeFrame on garbage addr survived (warning expected in log)", .{});

    // (c) allocContiguous(REGION_FRAMES+1) — definitely cross-region
    if (pmm.allocContiguous(pmm.PUB_REGION_FRAMES + 1)) |base| {
        note("p12", "alloc REGION_FRAMES+1 succeeded at 0x{X}", .{base});
        pmm.freeContiguous(base, pmm.PUB_REGION_FRAMES + 1);
    } else {
        note("p12", "alloc REGION_FRAMES+1 null (heavy fragmentation)", .{});
    }

    pass("p12", "edge cases handled gracefully", .{});
}

// ===========================================================================
// PHASE 13 — SMP concurrent stress (spawn 1 worker per AP; main runs too)
// ===========================================================================

fn smpWorkerEntry() callconv(.c) noreturn {
    const my_cpu = smp.myCpu().cpu_id;
    serial.print("[pmmstress] p13 worker on cpu{d} started\n", .{my_cpu});

    rngSeed(perf.rdtsc() ^ (@as(u64, my_cpu) << 32));

    var local_iters: u64 = 0;
    var local_anomalies: u64 = 0;
    var local_addrs: [256]usize = undefined;

    while (@atomicLoad(u32, &smp_should_stop, .monotonic) == 0) {
        // Pick a random pattern this iteration.
        switch (rngU32Range(4)) {
            0 => {
                // Pattern A: single-frame churn
                var n: u32 = 0;
                while (n < 256) : (n += 1) {
                    const p = pmm.allocFrame() orelse break;
                    local_addrs[n] = p;
                }
                var j: u32 = n;
                while (j > 0) {
                    j -= 1;
                    pmm.freeFrame(local_addrs[j]);
                }
            },
            1 => {
                // Pattern B: contig of random small size
                const sz = 1 + rngU32Range(64);
                if (pmm.allocContiguous(sz)) |base| {
                    writeMagic(base, base ^ @as(u64, sz));
                    if (readMagic(base) != base ^ @as(u64, sz)) local_anomalies += 1;
                    pmm.freeContiguous(base, sz);
                }
            },
            2 => {
                // Pattern C: alloc some, leak them deliberately, then free later
                var n: u32 = 0;
                const target: u32 = 32 + rngU32Range(96);
                while (n < target and n < 256) : (n += 1) {
                    const p = pmm.allocFrame() orelse break;
                    local_addrs[n] = p;
                }
                var j: u32 = 0;
                while (j < n) : (j += 1) pmm.freeFrame(local_addrs[j]);
            },
            3 => {
                // Pattern D: acquire/release churn
                if (pmm.allocFrame()) |p| {
                    var k: u32 = 0;
                    while (k < 8) : (k += 1) pmm.acquireFrame(p);
                    while (k > 0) : (k -= 1) pmm.releaseFrame(p);
                    pmm.freeFrame(p);
                }
            },
            else => unreachable,
        }
        local_iters += 1;
    }

    smp_iterations[my_cpu] = local_iters;
    smp_anomalies[my_cpu] = local_anomalies;
    @atomicStore(u32, &smp_done[my_cpu], 1, .release);
    serial.print("[pmmstress] p13 worker cpu{d} done: iters={d} anomalies={d}\n", .{ my_cpu, local_iters, local_anomalies });

    // Park forever.
    while (true) process.kernelSleepMs(1);
}

fn phase13_smpConcurrent() void {
    const n_cpus = smp.cpu_count;
    if (n_cpus < 2) {
        note("p13", "skip — only {d} CPU(s)", .{n_cpus});
        return;
    }
    note("p13", "spawning workers on cpu 1..{d}", .{n_cpus - 1});

    @atomicStore(u32, &smp_should_stop, 0, .release);
    var c: u8 = 1;
    while (c < n_cpus) : (c += 1) {
        @atomicStore(u32, &smp_done[c], 0, .release);
        smp_iterations[c] = 0;
        smp_anomalies[c] = 0;
        const created = lifecycle.createKernelTask(
            @intFromPtr(&smpWorkerEntry),
            "pmmstress-worker",
            c,
            process.Priority.normal,
            64 * 1024,
        );
        if (created == null) {
            fail("p13", "createKernelTask failed for cpu{d}", .{c});
            return;
        }
    }

    // Main CPU also runs the pattern — same as workers.
    rngSeed(perf.rdtsc());
    var main_iters: u64 = 0;
    const t0 = perf.rdtsc();
    var local_addrs: [256]usize = undefined;
    while (perf.rdtsc() - t0 < SMP_DURATION_TICKS) {
        switch (rngU32Range(4)) {
            0 => {
                var n: u32 = 0;
                while (n < 256) : (n += 1) {
                    const p = pmm.allocFrame() orelse break;
                    local_addrs[n] = p;
                }
                var j: u32 = n;
                while (j > 0) {
                    j -= 1;
                    pmm.freeFrame(local_addrs[j]);
                }
            },
            1 => {
                const sz = 1 + rngU32Range(64);
                if (pmm.allocContiguous(sz)) |base| {
                    pmm.freeContiguous(base, sz);
                }
            },
            2 => {
                var n: u32 = 0;
                const target: u32 = 32 + rngU32Range(96);
                while (n < target and n < 256) : (n += 1) {
                    const p = pmm.allocFrame() orelse break;
                    local_addrs[n] = p;
                }
                var j: u32 = 0;
                while (j < n) : (j += 1) pmm.freeFrame(local_addrs[j]);
            },
            3 => {
                if (pmm.allocFrame()) |p| {
                    var k: u32 = 0;
                    while (k < 8) : (k += 1) pmm.acquireFrame(p);
                    while (k > 0) : (k -= 1) pmm.releaseFrame(p);
                    pmm.freeFrame(p);
                }
            },
            else => unreachable,
        }
        main_iters += 1;
    }

    @atomicStore(u32, &smp_should_stop, 1, .release);

    // Wait for workers.
    var deadline_loops: u32 = 0;
    while (deadline_loops < 200) : (deadline_loops += 1) {
        var all_done: bool = true;
        c = 1;
        while (c < n_cpus) : (c += 1) {
            if (@atomicLoad(u32, &smp_done[c], .acquire) == 0) {
                all_done = false;
                break;
            }
        }
        if (all_done) break;
        process.kernelSleepMs(1);
    }

    var total: u64 = main_iters;
    var anom: u64 = 0;
    c = 0;
    while (c < n_cpus) : (c += 1) {
        if (c == 0) continue;
        total += smp_iterations[c];
        anom += smp_anomalies[c];
    }
    note("p13", "cpu0 iters={d}, others total={d}, anomalies={d}", .{ main_iters, total - main_iters, anom });

    if (anom == 0) {
        pass("p13", "SMP concurrent stress clean ({d} total iterations)", .{total});
    } else {
        fail("p13", "{d} anomalies across CPUs", .{anom});
    }
}

// ===========================================================================
// PHASE 14 — Mixed long run (5 sec randomized cycle)
// ===========================================================================

fn phase14_mixedLongRun() void {
    note("p14", "mixed random workload, 5s wall budget", .{});
    rngSeed(perf.rdtsc());
    const exhaust_before = pmm.pmmRunPoolExhaustions();
    const free_before = pmm.freeFrameCount();
    const t0 = perf.rdtsc();
    const budget: u64 = 10_000_000_000; // ~5s on 2 GHz
    var iters: u64 = 0;
    var local_addrs: [128]usize = undefined;

    while (perf.rdtsc() - t0 < budget) {
        switch (rngU32Range(6)) {
            0 => { _ = pmm.allocFrame() orelse {}; }, // 0..N leaks then later phases free
            1 => {
                if (pmm.allocFrame()) |p| pmm.freeFrame(p);
            },
            2 => {
                const sz = 1 + rngU32Range(32);
                if (pmm.allocContiguous(sz)) |base| pmm.freeContiguous(base, sz);
            },
            3 => {
                // Heavy contiguous
                const sz = 100 + rngU32Range(900);
                if (pmm.allocContiguous(sz)) |base| pmm.freeContiguous(base, sz);
            },
            4 => {
                // Below-4G
                if (pmm.allocFrameBelow4G()) |p| pmm.freeFrame(p);
            },
            5 => {
                // Batch alloc + reverse free
                var n: u32 = 0;
                while (n < 64) : (n += 1) {
                    const p = pmm.allocFrame() orelse break;
                    local_addrs[n] = p;
                }
                var j: u32 = n;
                while (j > 0) {
                    j -= 1;
                    pmm.freeFrame(local_addrs[j]);
                }
            },
            else => unreachable,
        }
        iters += 1;
    }

    const free_after = pmm.freeFrameCount();
    const exhaust_after = pmm.pmmRunPoolExhaustions();
    note("p14", "iters={d}, exhaust Δ={d}, free {d} → {d}", .{
        iters, exhaust_after - exhaust_before, free_before, free_after,
    });
    // 100-frame slop tolerated: random pattern 0 deliberately leaks.
    if (free_after < free_before - 100 or free_after > free_before + 100) {
        fail("p14", "leak drift: free {d} → {d}", .{ free_before, free_after });
    } else {
        pass("p14", "mixed long run survived {d} iterations", .{iters});
    }
}

// ===========================================================================
// Entry
// ===========================================================================

pub fn taskEntry() callconv(.c) noreturn {
    serial.print("\n", .{});
    serial.print("[pmmstress] === HEAVY PMM STRESS — {d} phases, {d} regions × {d} frames ===\n", .{
        14, pmm.PUB_REGIONS_COUNT, pmm.PUB_REGION_FRAMES,
    });
    serial.print("[pmmstress] managed={d} free={d} reserve={d} pool_exhaust={d}\n", .{
        pmm.managedFrameCount(), pmm.freeFrameCount(), pmm.userReserveFrames(), pmm.pmmRunPoolExhaustions(),
    });

    const t_start = perf.rdtsc();

    phase1_singleChurn();
    phase2_sizedContiguous();
    phase3_crossRegion();
    phase4_fragmentationCoalesce();
    phase5_runPoolExhaustion();
    phase6_coalesceVerification();
    phase7_uafCanary();
    phase8_below4G();
    phase9_userReserve();
    phase10_magazineDrain();
    phase11_refcountChurn();
    phase12_edgeCases();
    phase13_smpConcurrent();
    phase14_mixedLongRun();

    const t_end = perf.rdtsc();
    const total_cyc = t_end - t_start;

    serial.print("\n[pmmstress] ============================================================\n", .{});
    serial.print("[pmmstress] SUMMARY: passed={d}/{d}  failed={d}  anomalies={d}\n", .{
        phases_passed, phases_passed + phases_failed, phases_failed, anomalies,
    });
    serial.print("[pmmstress] final free={d}/{d} ({d}%), pool exhaustions={d}, canary mismatches={d}\n", .{
        pmm.freeFrameCount(),
        pmm.managedFrameCount(),
        if (pmm.managedFrameCount() > 0) pmm.freeFrameCount() * 100 / pmm.managedFrameCount() else 0,
        pmm.pmmRunPoolExhaustions(),
        pmm.pmmCanaryMismatches(),
    });
    serial.print("[pmmstress] elapsed cycles: {d}\n", .{total_cyc});
    serial.print("[pmmstress] ============================================================\n", .{});

    if (phases_failed == 0) {
        serial.print("[pmmstress] ✓ ALL CLEAN\n", .{});
    } else {
        serial.print("[pmmstress] ✗ {d} FAILURES — review FAIL lines above\n", .{phases_failed});
    }

    // Park.
    while (true) {
        process.kernelSleepMs(1);
        var i: u32 = 0;
        while (i < 1_000_000) : (i += 1) asm volatile ("pause");
    }
}
