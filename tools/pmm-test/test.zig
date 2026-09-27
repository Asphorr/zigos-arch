//! Off-target tests for src/mm/frame_index.zig (copied in by run.sh).
//! The oracle is a plain [FRAMES]bool: every mutation is mirrored into it
//! and the index (words + summary) is compared against it after each step.

const std = @import("std");
const fi = @import("frame_index.zig");

const FRAMES = fi.FRAMES;
const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;

const Model = struct {
    words: [fi.WORDS]u32 = [_]u32{0} ** fi.WORDS,
    s: fi.Summary = .{},
    used: [FRAMES]bool = [_]bool{false} ** FRAMES,

    fn init() Model {
        var m: Model = .{};
        m.s = fi.rebuild(&m.words);
        return m;
    }

    fn setOracle(self: *Model, start: u32, n: u32, v: bool) u32 {
        var changed: u32 = 0;
        for (start..start + n) |f| {
            if (self.used[f] != v) changed += 1;
            self.used[f] = v;
        }
        return changed;
    }

    fn freeInOracle(self: *const Model, start: u32, n: u32) bool {
        for (start..start + n) |f| if (self.used[f]) return false;
        return true;
    }

    fn longestFree(self: *const Model) u32 {
        var best: u32 = 0;
        var cur: u32 = 0;
        for (self.used) |u| {
            cur = if (u) 0 else cur + 1;
            best = @max(best, cur);
        }
        return best;
    }

    fn check(self: *const Model) !void {
        try expect(fi.verify(&self.words, self.s));
        for (0..FRAMES) |f| {
            const bit = (self.words[f / 32] >> @intCast(f % 32)) & 1 == 1;
            try expectEqual(self.used[f], bit);
        }
        var lead: u32 = 0;
        while (lead < FRAMES and !self.used[lead]) lead += 1;
        try expectEqual(lead, fi.leadingFree(&self.words, self.s));
        var trail: u32 = 0;
        while (trail < FRAMES and !self.used[FRAMES - 1 - trail]) trail += 1;
        try expectEqual(trail, fi.trailingFree(&self.words, self.s));
    }
};

fn naiveRunStart(m: u32, n: u32) ?u32 {
    var b: u32 = 0;
    while (b + n <= 32) : (b += 1) {
        var ok = true;
        for (b..b + n) |i| {
            if ((m >> @intCast(i)) & 1 == 0) ok = false;
        }
        if (ok) return b;
    }
    return null;
}

test "runStart matches brute force" {
    var prng = std.Random.DefaultPrng.init(1);
    const r = prng.random();
    const edge = [_]u32{ 0, 0xFFFF_FFFF, 1, 0x8000_0000, 0x7FFF_FFFF, 0xFFFF_FFFE, 0x0000_FFFF, 0xFFFF_0000, 0xF0F0_F0F0, 0x0FFF_FFF0 };
    for (edge) |m| {
        for (1..33) |n| try expectEqual(naiveRunStart(m, @intCast(n)), fi.runStart(m, @intCast(n)));
    }
    for (0..20_000) |_| {
        // Sparse, dense and random masks all matter for the doubling trick.
        const a = r.int(u32);
        const m = switch (r.uintLessThan(u8, 3)) {
            0 => a,
            1 => a | r.int(u32) | r.int(u32),
            else => a & r.int(u32),
        };
        const n = r.intRangeAtMost(u32, 1, 32);
        try expectEqual(naiveRunStart(m, n), fi.runStart(m, n));
    }
}

test "single frames come from partially used words first" {
    var m = Model.init();
    // Word 3 partly used; every other word fully free.
    _ = fi.markUsed(&m.words, &m.s, 3 * 32, 5);
    _ = m.setOracle(3 * 32, 5, true);
    const f = fi.allocOne(&m.words, &m.s).?;
    try expectEqual(@as(u32, 3 * 32 + 5), f);
    _ = m.setOracle(f, 1, true);
    try m.check();
    // No partial word left anywhere: word 0 gets broken.
    _ = fi.markUsed(&m.words, &m.s, 3 * 32, 32);
    _ = m.setOracle(3 * 32, 32, true);
    try expectEqual(@as(u32, 0), fi.allocOne(&m.words, &m.s).?);
    _ = m.setOracle(0, 1, true);
    try m.check();
}

test "short runs prefer the inside of partial words" {
    var m = Model.init();
    // Word 5 has exactly frames 8..11 free; word 0 is fully free.
    _ = fi.markUsed(&m.words, &m.s, 5 * 32, 32);
    _ = fi.markFree(&m.words, &m.s, 5 * 32 + 8, 4);
    _ = m.setOracle(5 * 32, 32, true);
    _ = m.setOracle(5 * 32 + 8, 4, false);
    try expectEqual(@as(?u32, 5 * 32 + 8), fi.findRun(&m.words, m.s, 3));
    try expectEqual(@as(?u32, 5 * 32 + 8), fi.findRun(&m.words, m.s, 4));
    // Five frames don't fit in word 5: first fit from frame 0.
    try expectEqual(@as(?u32, 0), fi.findRun(&m.words, m.s, 5));
    try m.check();
}

test "runs straddle words and span the whole region" {
    var m = Model.init();
    try expectEqual(@as(?u32, 0), fi.allocRun(&m.words, &m.s, FRAMES));
    _ = m.setOracle(0, FRAMES, true);
    try m.check();
    try expectEqual(@as(?u32, null), fi.allocOne(&m.words, &m.s));
    // Free 30..99 (crosses words 0..3), take a 70-frame run exactly there.
    try expectEqual(@as(u32, 70), fi.markFree(&m.words, &m.s, 30, 70));
    _ = m.setOracle(30, 70, false);
    try expectEqual(@as(?u32, null), fi.findRun(&m.words, m.s, 71));
    try expectEqual(@as(?u32, 30), fi.allocRun(&m.words, &m.s, 70));
    _ = m.setOracle(30, 70, true);
    try m.check();
}

/// Weighted run length: mostly small, sometimes a whole region.
fn pickLen(r: std.Random) u32 {
    return switch (r.uintLessThan(u8, 20)) {
        0...11 => r.intRangeAtMost(u32, 1, 8),
        12...16 => r.intRangeAtMost(u32, 9, 64),
        17...18 => r.intRangeAtMost(u32, 65, 512),
        else => r.intRangeAtMost(u32, 513, FRAMES),
    };
}

test "random operations agree with the oracle" {
    for ([_]u64{ 2, 3, 4, 5, 6, 7 }) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        const r = prng.random();
        var m = Model.init();
        for (0..20_000) |_| {
            // Keep the region churning around half full.
            const low = m.s.free_count < FRAMES / 3;
            const high = m.s.free_count > FRAMES * 2 / 3;
            const op = r.uintLessThan(u8, 10);
            if (!low and (high or op < 4)) {
                if (r.boolean()) {
                    const had_free = m.s.free_count > 0;
                    const got = fi.allocOne(&m.words, &m.s);
                    try expectEqual(had_free, got != null);
                    if (got) |f| {
                        try expect(!m.used[f]);
                        _ = m.setOracle(f, 1, true);
                    }
                } else {
                    const n = pickLen(r);
                    const fits = m.longestFree() >= n;
                    const got = fi.allocRun(&m.words, &m.s, n);
                    // Complete: null exactly when no run of n exists.
                    try expectEqual(fits, got != null);
                    if (got) |start| {
                        try expect(start + n <= FRAMES);
                        try expect(m.freeInOracle(start, n));
                        _ = m.setOracle(start, n, true);
                    }
                }
            } else if (op < 8) {
                const n = @min(pickLen(r), FRAMES);
                const start = r.uintAtMost(u32, FRAMES - n);
                try expectEqual(m.freeInOracle(start, n), fi.rangeFree(&m.words, start, n));
                const want = m.setOracle(start, n, false);
                try expectEqual(want, fi.markFree(&m.words, &m.s, start, n));
            } else {
                const n = r.intRangeAtMost(u32, 1, 64);
                const start = r.uintAtMost(u32, FRAMES - n);
                const want = m.setOracle(start, n, true);
                try expectEqual(want, fi.markUsed(&m.words, &m.s, start, n));
            }
            try m.check();
        }
    }
}
