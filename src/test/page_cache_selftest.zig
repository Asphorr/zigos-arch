// Page cache self-test — boot_mode = 14 entry.
//
// Proves mm/page_cache.zig's core invariants in ISOLATION, before any
// fault-handler or read()-path integration exists (that's slices 2 and 3). A
// clean boot never touches the cache yet, so — exactly like the WITNESS
// self-test — there'd be no evidence the data structure is correct unless
// something deliberately drives it. This is that something.
//
// Five tests, each on a freshly init()'d cache:
//   1  hit/miss + fresh-allocation accounting
//   2  set-associative eviction (a full set's oldest unpinned way is evicted)
//   3  a refcount-PINNED page survives eviction; an unpinned peer goes instead
//   4  a fully-pinned set refuses a new page (getOrAlloc -> null, uncached)
//   5  no frame leak: invalidate drops the cache's ref and the frame is freed
//
// Determinism trick: tests 2-4 need several keys that land in the SAME set.
// We compute them up front via page_cache.setIndexFor (collectSameSet), so the
// round-robin eviction order is predictable. Eviction is checked by KEY
// PRESENCE (lookup hit/miss), never by frame identity — pmm.allocFrame may hand
// the just-freed victim frame straight back to the next insert, which would
// make a naive "evicted frame is now free" assertion flap.
//
// Run with boot_mode = 14 (menu: Tests > Test: page cache). PASS criterion:
//   [pgcache] PASS — all checks green ...
// appears in serial.log, then the box idles so the log can be read at leisure.

const serial = @import("../debug/serial.zig");
const page_cache = @import("../mm/page_cache.zig");
const pmm = @import("../mm/pmm.zig");

const WAYS = page_cache.WAYS; // 8
const PG = page_cache.PAGE_SIZE;

var fail_count: u32 = 0;

fn check(cond: bool, msg: []const u8) void {
    if (!cond) {
        serial.print("[pgcache] FAIL: {s}\n", .{msg});
        fail_count += 1;
    }
}

/// Fill `out` with byte-offsets (of `fid`) that all hash to `target` set.
fn collectSameSet(fid: u64, target: u32, out: []u64) u32 {
    var found: u32 = 0;
    var i: u64 = 0;
    while (found < out.len and i < 200_000) : (i += 1) {
        const off = i * PG;
        if (page_cache.setIndexFor(fid, off) == target) {
            out[found] = off;
            found += 1;
        }
    }
    return found;
}

pub fn taskEntry() callconv(.c) noreturn {
    serial.print("\n[pgcache] === page cache self-test start ===\n", .{});

    test1HitMiss();
    test2Eviction();
    test3PinSurvives();
    test4FullyPinned();
    test5NoLeak();

    if (fail_count == 0) {
        serial.print("[pgcache] PASS — all checks green (hit/miss, eviction frees victim, pin survives eviction, full-set skip, no leak)\n", .{});
    } else {
        serial.print("[pgcache] FAIL — {d} check(s) failed (see [pgcache] FAIL lines above)\n", .{fail_count});
    }
    serial.print("[pgcache] === end; idling ===\n", .{});
    idle();
}

// --- 1: hit/miss + fresh accounting ----------------------------------------
fn test1HitMiss() void {
    serial.print("[pgcache] test 1: hit/miss + fresh alloc\n", .{});
    page_cache.init();
    const fid: u64 = 1;
    var frames: [4]usize = undefined;

    var i: u64 = 0;
    while (i < 4) : (i += 1) {
        const r = page_cache.getOrAlloc(fid, i * PG) orelse {
            check(false, "test1 getOrAlloc returned null");
            return;
        };
        check(r.fresh, "test1 first insert of a key should be fresh");
        check(pmm.frameRefCount(r.frame) == 1, "test1 a fresh cache frame should be refcount 1");
        frames[i] = r.frame;
    }
    check(frames[0] != frames[1] and frames[1] != frames[2] and frames[2] != frames[3], "test1 distinct keys must get distinct frames");

    // Re-get the same keys -> hits, same frames, NOT fresh.
    i = 0;
    while (i < 4) : (i += 1) {
        const r = page_cache.getOrAlloc(fid, i * PG) orelse {
            check(false, "test1 re-get returned null");
            return;
        };
        check(!r.fresh, "test1 re-get of a resident key should be a hit (not fresh)");
        check(r.frame == frames[i], "test1 re-get should return the same frame");
    }
    check(page_cache.lookup(fid, 0) != null, "test1 lookup of a present key should hit");
    check(page_cache.lookup(2, 0) == null, "test1 lookup of an absent key should miss");

    page_cache.init(); // frees the 4 frames
}

// --- 2: set eviction --------------------------------------------------------
fn test2Eviction() void {
    serial.print("[pgcache] test 2: set-associative eviction\n", .{});
    page_cache.init();
    const fid: u64 = 0x2000;
    var keys: [16]u64 = undefined;
    const n = collectSameSet(fid, page_cache.setIndexFor(fid, 0), keys[0 .. WAYS + 1]);
    if (n < WAYS + 1) {
        check(false, "test2 could not collect WAYS+1 same-set keys");
        return;
    }

    const ev_before = page_cache.stat_evictions;
    var i: u32 = 0;
    while (i < WAYS + 1) : (i += 1) _ = page_cache.getOrAlloc(fid, keys[i]);

    check(page_cache.stat_evictions == ev_before + 1, "test2 filling WAYS+1 should evict exactly once");
    check(page_cache.lookup(fid, keys[0]) == null, "test2 the oldest key (k0) should have been the victim");

    var hits: u32 = 0;
    i = 1;
    while (i < WAYS + 1) : (i += 1) {
        if (page_cache.lookup(fid, keys[i]) != null) hits += 1;
    }
    check(hits == WAYS, "test2 every key except k0 should still be resident");

    page_cache.init();
}

// --- 3: pinned page survives eviction ---------------------------------------
fn test3PinSurvives() void {
    serial.print("[pgcache] test 3: refcount-pinned page survives eviction\n", .{});
    page_cache.init();
    const fid: u64 = 0x3000;
    var keys: [16]u64 = undefined;
    const n = collectSameSet(fid, page_cache.setIndexFor(fid, 0), keys[0 .. WAYS + 1]);
    if (n < WAYS + 1) {
        check(false, "test3 could not collect same-set keys");
        return;
    }

    var i: u32 = 0;
    while (i < WAYS) : (i += 1) _ = page_cache.getOrAlloc(fid, keys[i]); // fill the set

    // Pin k0 — the round-robin victim. It must now be skipped by eviction.
    const pinned = page_cache.pin(fid, keys[0]) orelse {
        check(false, "test3 pin(k0) missed a resident key");
        return;
    };
    check(pmm.frameRefCount(pinned) == 2, "test3 a pinned cache frame should be refcount 2");

    _ = page_cache.getOrAlloc(fid, keys[WAYS]); // forces an eviction; k0 pinned -> k1 goes

    check(page_cache.lookup(fid, keys[0]) != null, "test3 the pinned page (k0) must survive eviction");
    check(page_cache.lookup(fid, keys[1]) == null, "test3 an unpinned peer (k1) should be evicted instead");
    check(page_cache.lookup(fid, keys[WAYS]) != null, "test3 the newly inserted page should be resident");

    pmm.releaseFrame(pinned); // drop our pin so init() can reclaim it
    page_cache.init();
}

// --- 4: fully-pinned set refuses a new page ---------------------------------
fn test4FullyPinned() void {
    serial.print("[pgcache] test 4: fully-pinned set -> uncached\n", .{});
    page_cache.init();
    const fid: u64 = 0x4000;
    var keys: [16]u64 = undefined;
    const n = collectSameSet(fid, page_cache.setIndexFor(fid, 0), keys[0 .. WAYS + 1]);
    if (n < WAYS + 1) {
        check(false, "test4 could not collect same-set keys");
        return;
    }

    var pins: [16]usize = undefined;
    var i: u32 = 0;
    while (i < WAYS) : (i += 1) {
        _ = page_cache.getOrAlloc(fid, keys[i]);
        pins[i] = page_cache.pin(fid, keys[i]) orelse {
            check(false, "test4 pin of a resident key missed");
            return;
        };
    }

    const skip_before = page_cache.stat_full_skips;
    const r = page_cache.getOrAlloc(fid, keys[WAYS]);
    check(r == null, "test4 getOrAlloc into a fully-pinned set should return null (uncached)");
    check(page_cache.stat_full_skips == skip_before + 1, "test4 a fully-pinned set should record one full_skip");

    i = 0;
    while (i < WAYS) : (i += 1) pmm.releaseFrame(pins[i]); // unpin all
    page_cache.init();
}

// --- 5: no frame leak after invalidate --------------------------------------
fn test5NoLeak() void {
    serial.print("[pgcache] test 5: no frame leak after invalidate\n", .{});
    page_cache.init();
    const fid: u64 = 0x5000;
    var frames: [4]usize = undefined;

    var i: u64 = 0;
    while (i < 4) : (i += 1) {
        const r = page_cache.getOrAlloc(fid, i * PG) orelse {
            check(false, "test5 getOrAlloc returned null");
            return;
        };
        frames[i] = r.frame;
    }

    // Invalidate each -> the cache drops its sole reference -> the frame frees.
    // No allocFrame runs between the invalidates, so no reuse can mask a leak.
    i = 0;
    while (i < 4) : (i += 1) check(page_cache.invalidate(fid, i * PG), "test5 invalidate of a present key should return true");
    i = 0;
    while (i < 4) : (i += 1) check(pmm.frameRefCount(frames[i]) == 0, "test5 an invalidated frame must be freed (refcount 0) — leak otherwise");

    check(page_cache.residentCount() == 0, "test5 residentCount should be 0 after invalidating everything");
}

fn idle() noreturn {
    while (true) asm volatile ("hlt");
}
