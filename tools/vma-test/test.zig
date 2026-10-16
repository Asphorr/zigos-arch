//! Off-target tests for src/mm/vma.zig (copied in by run.sh). The oracle is a
//! page-granular model of the address space: every page is either unmapped
//! or carries the attributes of the region holding it (prot, and the "file
//! offset" a start-relative field such as cache_off gives that page). After
//! every operation each page must resolve to a region with exactly the
//! model's attributes, the set must stay sorted and disjoint, and the pieces
//! `remove` reports must tile what the model unmapped.

const std = @import("std");
const vma = @import("vma.zig");

const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;

const PAGE: usize = 0x1000;
const PAGES: usize = 256;
const BASE: usize = 0x400000;

const R = struct {
    start: usize,
    end: usize,
    prot: u8,
    mergeable: bool,
    off: usize,
    // The kernel's LazyRegion is ~88 bytes; a region this size is passed
    // and returned through memory the way the real one is.
    pad: [8]u64 = [_]u64{0} ** 8,

    pub fn tailFrom(r: R, at: usize) R {
        var t = r;
        t.off += at - r.start;
        t.start = at;
        return t;
    }

    pub fn canMerge(lo: R, hi: R) bool {
        return lo.mergeable and hi.mergeable and lo.prot == hi.prot and
            lo.off + (lo.end - lo.start) == hi.off;
    }
};

/// Fails every allocation once `fail_after` reaches zero (negative = never).
var fail_after: i64 = -1;

const TestAlloc = struct {
    pub fn alloc(n: usize) ?[*]R {
        if (fail_after == 0) return null;
        if (fail_after > 0) fail_after -= 1;
        const s = std.testing.allocator.alloc(R, n) catch return null;
        return s.ptr;
    }
    pub fn free(p: [*]R, n: usize) void {
        std.testing.allocator.free(p[0..n]);
    }
};

const Set = vma.Set(R, TestAlloc);

const Page = struct {
    mapped: bool = false,
    prot: u8 = 0,
    mergeable: bool = false,
    off: usize = 0,
};

const Model = struct {
    pages: [PAGES]Page = [_]Page{.{}} ** PAGES,

    fn va(p: usize) usize {
        return BASE + p * PAGE;
    }
    fn idx(a: usize) usize {
        return (a - BASE) / PAGE;
    }
};

fn checkInvariants(set: *const Set) !void {
    const s = set.slice();
    for (s, 0..) |r, i| {
        try expect(r.start < r.end);
        try expect(r.start % PAGE == 0 and r.end % PAGE == 0);
        if (i > 0) try expect(s[i - 1].end <= r.start);
    }
    try expect(set.len <= set.cap);
}

fn checkAgainst(set: *const Set, m: *const Model) !void {
    try checkInvariants(set);
    for (m.pages, 0..) |pg, p| {
        const a = Model.va(p);
        const found = set.find(a);
        if (!pg.mapped) {
            try expect(found == null);
            continue;
        }
        const r = found orelse return error.MissingRegion;
        try expectEqual(pg.prot, r.prot);
        try expectEqual(pg.mergeable, r.mergeable);
        try expectEqual(pg.off, r.off + (a - r.start));
    }
    // Nothing mapped outside the modeled window.
    for (set.slice()) |r| {
        try expect(r.start >= BASE and r.end <= BASE + PAGES * PAGE);
    }
}

const Collect = struct {
    pieces: [PAGES]R = undefined,
    n: usize = 0,
    pub fn removed(self: *Collect, r: R) void {
        self.pieces[self.n] = r;
        self.n += 1;
    }
};

const SetProt = struct {
    prot: u8,
    pub fn apply(self: SetProt, r: *R) void {
        r.prot = self.prot;
    }
};

fn modelFree(m: *const Model, lo: usize, hi: usize) bool {
    for (lo..hi) |p| if (m.pages[p].mapped) return false;
    return true;
}

fn modelCovers(m: *const Model, lo: usize, hi: usize) bool {
    for (lo..hi) |p| if (!m.pages[p].mapped) return false;
    return true;
}

fn modelGapTopDown(m: *const Model, len_pages: usize, lo: usize, hi: usize) ?usize {
    if (len_pages == 0 or hi <= lo or hi - lo < len_pages) return null;
    var top = hi;
    while (top >= lo + len_pages) : (top -= 1) {
        if (modelFree(m, top - len_pages, top)) return top - len_pages;
    }
    return null;
}

fn randRange(rng: std.Random, max_len: usize) [2]usize {
    const lo = rng.uintLessThan(usize, PAGES);
    const len = 1 + rng.uintLessThan(usize, @min(max_len, PAGES - lo));
    return .{ lo, lo + len };
}

fn runRandom(seed: u64, ops: usize) !void {
    var prng = std.Random.DefaultPrng.init(seed);
    const rng = prng.random();
    var set: Set = .{};
    defer set.deinit();
    var m: Model = .{};

    var op: usize = 0;
    while (op < ops) : (op += 1) {
        switch (rng.uintLessThan(u8, 9)) {
            0, 1, 2 => { // insert
                const rr = randRange(rng, 24);
                const r = R{
                    .start = Model.va(rr[0]),
                    .end = Model.va(rr[1]),
                    .prot = rng.uintLessThan(u8, 3),
                    .mergeable = rng.boolean(),
                    // Small offsets so mergeable neighbors line up now and then.
                    .off = rng.uintLessThan(usize, 4) * PAGE * 8,
                };
                const free = modelFree(&m, rr[0], rr[1]);
                const before = set.len;
                if (set.insert(r)) |_| {
                    try expect(free);
                    for (rr[0]..rr[1]) |p| m.pages[p] = .{
                        .mapped = true,
                        .prot = r.prot,
                        .mergeable = r.mergeable,
                        .off = r.off + (Model.va(p) - r.start),
                    };
                    try expect(set.len <= before + 1);
                } else |e| {
                    try expectEqual(error.Overlap, e);
                    try expect(!free);
                    try expectEqual(before, set.len);
                }
            },
            3, 4 => { // remove
                const rr = randRange(rng, 40);
                var c: Collect = .{};
                try set.remove(Model.va(rr[0]), Model.va(rr[1]), &c);
                // The pieces tile exactly the mapped pages of the range, with
                // each page's attributes.
                var seen = [_]bool{false} ** PAGES;
                for (c.pieces[0..c.n]) |piece| {
                    try expect(piece.start >= Model.va(rr[0]) and piece.end <= Model.va(rr[1]));
                    var a = piece.start;
                    while (a < piece.end) : (a += PAGE) {
                        const p = Model.idx(a);
                        try expect(!seen[p]);
                        seen[p] = true;
                        try expect(m.pages[p].mapped);
                        try expectEqual(m.pages[p].prot, piece.prot);
                        try expectEqual(m.pages[p].off, piece.off + (a - piece.start));
                    }
                }
                for (rr[0]..rr[1]) |p| {
                    try expectEqual(m.pages[p].mapped, seen[p]);
                    m.pages[p] = .{};
                }
            },
            5, 6 => { // update prot
                const rr = randRange(rng, 40);
                const prot = rng.uintLessThan(u8, 3);
                try set.update(Model.va(rr[0]), Model.va(rr[1]), SetProt{ .prot = prot });
                for (rr[0]..rr[1]) |p| {
                    if (m.pages[p].mapped) m.pages[p].prot = prot;
                }
            },
            7 => { // resizeEnd of a random region
                if (set.len == 0) continue;
                const r = set.slice()[rng.uintLessThan(u32, set.len)];
                const s = Model.idx(r.start);
                const new_end = s + 1 + rng.uintLessThan(usize, PAGES - s);
                const old_end = Model.idx(r.end);
                const ok = set.resizeEnd(r.start, Model.va(new_end));
                const want = new_end <= old_end or modelFree(&m, old_end, new_end);
                try expectEqual(want, ok);
                if (ok) {
                    if (new_end < old_end) {
                        for (new_end..old_end) |p| m.pages[p] = .{};
                    } else {
                        for (old_end..new_end) |p| m.pages[p] = .{
                            .mapped = true,
                            .prot = r.prot,
                            .mergeable = r.mergeable,
                            .off = r.off + (Model.va(p) - r.start),
                        };
                    }
                }
            },
            8 => { // queries
                const rr = randRange(rng, 40);
                try expectEqual(modelFree(&m, rr[0], rr[1]), set.isFree(Model.va(rr[0]), Model.va(rr[1])));
                try expectEqual(modelCovers(&m, rr[0], rr[1]), set.covers(Model.va(rr[0]), Model.va(rr[1])));
                const len = 1 + rng.uintLessThan(usize, 16);
                const want = modelGapTopDown(&m, len, rr[0], rr[1]);
                const got = set.gapTopDown(len * PAGE, Model.va(rr[0]), Model.va(rr[1]));
                if (want) |w| {
                    try expectEqual(@as(?usize, Model.va(w)), got);
                } else {
                    try expect(got == null);
                }
                // atOrAbove: the lowest region ending above the address.
                const a = Model.va(rr[0]);
                var expect_idx: ?usize = null;
                for (rr[0]..PAGES) |p| if (m.pages[p].mapped) {
                    expect_idx = p;
                    break;
                };
                if (set.atOrAbove(a)) |r| {
                    try expect(r.end > a);
                    const e = expect_idx orelse return error.UnexpectedRegion;
                    try expect(r.start <= Model.va(e) and Model.va(e) < r.end);
                } else {
                    try expect(expect_idx == null);
                }
            },
            else => unreachable,
        }
        try checkAgainst(&set, &m);
    }

    // clone is an independent copy.
    var copy = try set.clone();
    defer copy.deinit();
    try checkAgainst(&copy, &m);
    var c: Collect = .{};
    try copy.remove(BASE, BASE + PAGES * PAGE, &c);
    try expectEqual(@as(u32, 0), copy.len);
    try checkAgainst(&set, &m);
}

test "random operations against a page model" {
    const seeds = [_]u64{ 1, 2, 3, 0xC0FFEE, 0xDEADBEEF, 42 };
    for (seeds) |s| try runRandom(s, 6000);
}

test "insert merges with both neighbors" {
    var set: Set = .{};
    defer set.deinit();
    const a = R{ .start = BASE, .end = BASE + PAGE, .prot = 1, .mergeable = true, .off = 0 };
    const c = R{ .start = BASE + 2 * PAGE, .end = BASE + 3 * PAGE, .prot = 1, .mergeable = true, .off = 2 * PAGE };
    try set.insert(a);
    try set.insert(c);
    try expectEqual(@as(u32, 2), set.len);
    const b = R{ .start = BASE + PAGE, .end = BASE + 2 * PAGE, .prot = 1, .mergeable = true, .off = PAGE };
    try set.insert(b);
    try expectEqual(@as(u32, 1), set.len);
    try expectEqual(BASE + 3 * PAGE, set.slice()[0].end);
}

test "punching a hole splits one region in two" {
    var set: Set = .{};
    defer set.deinit();
    try set.insert(.{ .start = BASE, .end = BASE + 8 * PAGE, .prot = 1, .mergeable = false, .off = 100 * PAGE });
    var c: Collect = .{};
    try set.remove(BASE + 2 * PAGE, BASE + 3 * PAGE, &c);
    try expectEqual(@as(u32, 2), set.len);
    try expectEqual(@as(usize, 1), c.n);
    try expectEqual(BASE + 2 * PAGE, c.pieces[0].start);
    try expectEqual(@as(usize, 102 * PAGE), c.pieces[0].off);
    try expectEqual(@as(usize, 103 * PAGE), set.slice()[1].off);
}

test "a failed allocation leaves the set unchanged" {
    var set: Set = .{};
    defer set.deinit();
    // Fill the initial capacity exactly; the first region is three pages.
    try set.insert(.{ .start = BASE, .end = BASE + 3 * PAGE, .prot = 1, .mergeable = false, .off = 0 });
    var i: usize = 1;
    while (i < 8) : (i += 1) {
        try set.insert(.{ .start = BASE + i * 4 * PAGE, .end = BASE + (i * 4 + 1) * PAGE, .prot = 1, .mergeable = false, .off = 0 });
    }
    try expectEqual(@as(u32, 8), set.cap);
    fail_after = 0;
    defer fail_after = -1;
    // Each of these needs another slot.
    try std.testing.expectError(error.OutOfMemory, set.insert(.{ .start = BASE + 64 * PAGE, .end = BASE + 65 * PAGE, .prot = 1, .mergeable = false, .off = 0 }));
    var c: Collect = .{};
    try std.testing.expectError(error.OutOfMemory, set.remove(BASE + PAGE, BASE + 2 * PAGE, &c));
    try std.testing.expectError(error.OutOfMemory, set.update(BASE + PAGE, BASE + 2 * PAGE, SetProt{ .prot = 2 }));
    try expectEqual(@as(u32, 8), set.len);
    try expectEqual(@as(usize, 0), c.n);
    try expectEqual(BASE + 3 * PAGE, set.slice()[0].end);
    try expectEqual(@as(u8, 1), set.slice()[0].prot);
    // Removing a whole region needs no room.
    try set.remove(BASE + 4 * PAGE, BASE + 5 * PAGE, &c);
    try expectEqual(@as(u32, 7), set.len);
}

test "gapTopDown picks the highest hole" {
    var set: Set = .{};
    defer set.deinit();
    try set.insert(.{ .start = BASE + 10 * PAGE, .end = BASE + 20 * PAGE, .prot = 1, .mergeable = false, .off = 0 });
    try set.insert(.{ .start = BASE + 30 * PAGE, .end = BASE + 40 * PAGE, .prot = 1, .mergeable = false, .off = 0 });
    try expectEqual(@as(?usize, BASE + 40 * PAGE), set.gapTopDown(10 * PAGE, BASE, BASE + 50 * PAGE));
    try expectEqual(@as(?usize, BASE + 20 * PAGE), set.gapTopDown(10 * PAGE, BASE, BASE + 45 * PAGE));
    try expectEqual(@as(?usize, BASE + 20 * PAGE), set.gapTopDown(10 * PAGE, BASE, BASE + 35 * PAGE));
    try expectEqual(@as(?usize, BASE), set.gapTopDown(10 * PAGE, BASE, BASE + 29 * PAGE));
    try expectEqual(@as(?usize, null), set.gapTopDown(11 * PAGE, BASE + 5 * PAGE, BASE + 35 * PAGE));
}
