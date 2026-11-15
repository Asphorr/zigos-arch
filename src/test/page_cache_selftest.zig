// Page cache self-test — boot_mode = 14 entry.
//
// Proves mm/page_cache.zig's core invariants in ISOLATION, before any
// fault-handler or read()-path integration exists (that's slices 2 and 3). A
// clean boot never touches the cache yet, so — exactly like the WITNESS
// self-test — there'd be no evidence the data structure is correct unless
// something deliberately drives it. This is that something.
//
// Seven tests, each on a freshly init()'d cache:
//   1  hit/miss + fresh-allocation accounting
//   2  eviction at the resident limit (the oldest unpinned page goes)
//   3  a refcount-PINNED page survives eviction; an unpinned peer goes instead
//   4  a cache full of pinned pages refuses a new one (getOrAlloc -> null)
//   5  no frame leak: invalidate drops the cache's ref and the frame is freed
//   6  per-file walks: invalidateFile and a long invalidateRange take one
//      file's pages and leave another's
//   7  dirty batches: the lowest dirty pages come out in order and pinned,
//      however far apart; a cache-only page can be dropped, a mapped one not
//
// Tests 2-4 lower the resident limit to LIMIT pages (page_cache.limitForTest)
// so eviction starts after a handful of inserts; on a fresh cache the sweep
// meets pages in the order they were cached. Eviction is checked by KEY
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
const Phys = @import("../util/addr.zig").Phys;

/// Resident limit for the eviction tests.
const LIMIT: u32 = 8;
const PG = page_cache.PAGE_SIZE;

var fail_count: u32 = 0;

fn check(cond: bool, msg: []const u8) void {
    if (!cond) {
        serial.print("[pgcache] FAIL: {s}\n", .{msg});
        fail_count += 1;
    }
}

pub fn taskEntry() callconv(.c) noreturn {
    serial.print("\n[pgcache] === page cache self-test start ===\n", .{});

    test1HitMiss();
    test2Eviction();
    test3PinSurvives();
    test4FullyPinned();
    test5NoLeak();
    test6PerFile();
    test7DirtyBatches();

    if (fail_count == 0) {
        serial.print("[pgcache] PASS — all checks green (hit/miss, eviction frees victim, pin survives eviction, full-cache skip, no leak, per-file walks, dirty batches)\n", .{});
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
    var frames: [4]Phys = undefined;

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

// --- 2: eviction at the limit -----------------------------------------------
fn test2Eviction() void {
    serial.print("[pgcache] test 2: eviction at the resident limit\n", .{});
    page_cache.init();
    page_cache.limitForTest(LIMIT);
    const fid: u64 = 0x2000;

    const ev_before = page_cache.statsSnapshot().evictions;
    var i: u64 = 0;
    while (i < LIMIT + 1) : (i += 1) _ = page_cache.getOrAlloc(fid, i * PG);

    check(page_cache.statsSnapshot().evictions == ev_before + 1, "test2 filling LIMIT+1 should evict exactly once");
    check(page_cache.lookup(fid, 0) == null, "test2 the oldest key (k0) should have been the victim");
    check(page_cache.residentCount() == LIMIT, "test2 the cache should hold exactly LIMIT pages");

    var hits: u32 = 0;
    i = 1;
    while (i < LIMIT + 1) : (i += 1) {
        if (page_cache.lookup(fid, i * PG) != null) hits += 1;
    }
    check(hits == LIMIT, "test2 every key except k0 should still be resident");

    page_cache.init();
}

// --- 3: pinned page survives eviction ---------------------------------------
fn test3PinSurvives() void {
    serial.print("[pgcache] test 3: refcount-pinned page survives eviction\n", .{});
    page_cache.init();
    page_cache.limitForTest(LIMIT);
    const fid: u64 = 0x3000;

    var i: u64 = 0;
    while (i < LIMIT) : (i += 1) _ = page_cache.getOrAlloc(fid, i * PG); // fill to the limit

    // Pin k0 — the sweep's first candidate. Eviction must now skip it.
    const pinned = page_cache.pin(fid, 0) orelse {
        check(false, "test3 pin(k0) missed a resident key");
        return;
    };
    check(pmm.frameRefCount(pinned) == 2, "test3 a pinned cache frame should be refcount 2");

    _ = page_cache.getOrAlloc(fid, LIMIT * PG); // forces an eviction; k0 pinned -> k1 goes

    check(page_cache.lookup(fid, 0) != null, "test3 the pinned page (k0) must survive eviction");
    check(page_cache.lookup(fid, PG) == null, "test3 an unpinned peer (k1) should be evicted instead");
    check(page_cache.lookup(fid, LIMIT * PG) != null, "test3 the newly inserted page should be resident");

    pmm.releaseFrame(pinned); // drop our pin so init() can reclaim it
    page_cache.init();
}

// --- 4: a cache full of pinned pages refuses a new one ----------------------
fn test4FullyPinned() void {
    serial.print("[pgcache] test 4: every page pinned -> not cached\n", .{});
    page_cache.init();
    page_cache.limitForTest(LIMIT);
    const fid: u64 = 0x4000;

    var pins: [LIMIT]Phys = undefined;
    var i: u32 = 0;
    while (i < LIMIT) : (i += 1) {
        _ = page_cache.getOrAlloc(fid, @as(u64, i) * PG);
        pins[i] = page_cache.pin(fid, @as(u64, i) * PG) orelse {
            check(false, "test4 pin of a resident key missed");
            return;
        };
    }

    const skip_before = page_cache.statsSnapshot().full_skips;
    const r = page_cache.getOrAlloc(fid, LIMIT * PG);
    check(r == null, "test4 getOrAlloc with every page pinned should return null");
    check(page_cache.statsSnapshot().full_skips == skip_before + 1, "test4 a full cache should record one full_skip");
    check(page_cache.residentCount() == LIMIT, "test4 the pinned pages should all still be resident");

    i = 0;
    while (i < LIMIT) : (i += 1) pmm.releaseFrame(pins[i]); // unpin all
    page_cache.init();
}

// --- 5: no frame leak after invalidate --------------------------------------
fn test5NoLeak() void {
    serial.print("[pgcache] test 5: no frame leak after invalidate\n", .{});
    page_cache.init();
    const fid: u64 = 0x5000;
    var frames: [4]Phys = undefined;

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

// --- 6: per-file walks ------------------------------------------------------
fn test6PerFile() void {
    serial.print("[pgcache] test 6: per-file walks\n", .{});
    page_cache.init();
    const a: u64 = 0x6000;
    const b: u64 = 0x6001;
    const pages: u64 = 600; // more than one offset-probe range

    var i: u64 = 0;
    while (i < pages) : (i += 1) {
        if (page_cache.getOrAlloc(a, i * PG) == null or page_cache.getOrAlloc(b, i * PG) == null) {
            check(false, "test6 getOrAlloc returned null");
            page_cache.init();
            return;
        }
    }
    check(page_cache.residentCount() == 2 * pages, "test6 both files' pages should be resident");

    // A long range of `a` (walked by file), then a short one (probed).
    check(page_cache.invalidateRange(a, 100 * PG, 400 * PG) == 400, "test6 a long invalidateRange should drop exactly its pages");
    check(page_cache.invalidateRange(a, 0, 10 * PG) == 10, "test6 a short invalidateRange should drop exactly its pages");
    check(page_cache.lookup(a, 99 * PG) != null and page_cache.lookup(a, 100 * PG) == null, "test6 the range's lower edge");
    check(page_cache.lookup(a, 499 * PG) == null and page_cache.lookup(a, 500 * PG) != null, "test6 the range's upper edge");
    check(page_cache.residentCount() == 2 * pages - 410, "test6 the other file must be untouched by a range drop");

    check(page_cache.invalidateFile(b) == pages, "test6 invalidateFile should drop every page of the file");
    check(page_cache.lookup(b, 0) == null and page_cache.lookup(a, 50 * PG) != null, "test6 only that file's pages go");
    check(page_cache.residentCount() == pages - 410, "test6 what is left is the first file's remainder");

    page_cache.init();
    check(page_cache.residentCount() == 0, "test6 init should empty the cache");
}

// --- 7: dirty batches -------------------------------------------------------
fn unpin(batch: []const page_cache.DirtyPage) void {
    for (batch) |dp| pmm.releaseFrame(dp.frame);
}

fn test7DirtyBatches() void {
    serial.print("[pgcache] test 7: dirty batches\n", .{});
    page_cache.init();
    const a: u64 = 0x7000;
    const b: u64 = 0x7001;
    // Dirty pages of `a`: a run with a gap near the start, then three far
    // apart, cached highest first so the file's list is not in order.
    const near = [_]u64{ 0, PG, 2 * PG, 40 * PG };
    const far = [_]u64{ 1 << 40, 1 << 30, 5 << 20 };
    for (far ++ near) |off| {
        if (page_cache.getOrAlloc(a, off) == null) {
            check(false, "test7 getOrAlloc returned null");
            page_cache.init();
            return;
        }
        page_cache.markDirty(a, off);
    }
    // Neither a clean page of `a` nor a dirty page of `b` belongs in a batch.
    _ = page_cache.getOrAlloc(a, 3 * PG);
    _ = page_cache.getOrAlloc(b, 0);
    page_cache.markDirty(b, 0);

    var out: [4]page_cache.DirtyPage = undefined;
    var n = page_cache.takeDirtyBatch(a, 0, &out);
    check(n == 4 and out[0].page_off == 0 and out[1].page_off == PG and out[2].page_off == 2 * PG and out[3].page_off == 40 * PG, "test7 the first batch is the run near the start, in order");
    if (n > 0) check(pmm.frameRefCount(out[0].frame) == 2, "test7 a page of a batch is pinned");
    unpin(out[0..n]);

    n = page_cache.takeDirtyBatch(a, 41 * PG, &out);
    check(n == 3 and out[0].page_off == 5 << 20 and out[1].page_off == 1 << 30 and out[2].page_off == 1 << 40, "test7 pages far apart come out lowest first");
    unpin(out[0..n]);

    var two: [2]page_cache.DirtyPage = undefined;
    n = page_cache.takeDirtyBatch(a, 41 * PG, &two);
    check(n == 2 and two[0].page_off == 5 << 20 and two[1].page_off == 1 << 30, "test7 a short batch keeps the lowest pages");
    unpin(two[0..n]);

    check(page_cache.takeDirtyBatch(a, (1 << 40) + PG, &out) == 0, "test7 nothing is left past the last dirty page");

    const pinned = page_cache.pin(a, 0) orelse {
        check(false, "test7 pin missed a resident key");
        page_cache.init();
        return;
    };
    check(!page_cache.dropIfCacheOnly(a, 0), "test7 a page something holds must not be dropped");
    pmm.releaseFrame(pinned);
    check(page_cache.dropIfCacheOnly(a, 0) and page_cache.lookup(a, 0) == null, "test7 a cache-only page is dropped, dirty or not");

    page_cache.init();
}

fn idle() noreturn {
    while (true) asm volatile ("hlt");
}
