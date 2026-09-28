//! Off-target tests for src/mm/tlsf.zig (copied in by run.sh). The oracle
//! is the set of live allocations: each one's bytes carry its own pattern,
//! so allocator metadata straying into user data (or the reverse) shows
//! up; the three validators must pass after every step, and every freed
//! pointer must read as a double free until something reuses its bytes.
//! The pool tests grow and shrink the allocator over an arena of slots the
//! way heap.zig does over PMM chunks.

const std = @import("std");
const tlsf = @import("tlsf.zig");

const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;

const Quiet = struct {
    pub fn print(comptime _: []const u8, _: anytype) void {}
};
const Loud = struct {
    pub fn print(comptime fmt: []const u8, args: anytype) void {
        std.debug.print(fmt, args);
    }
};

const REGION: usize = 1 << 20;
var region: [REGION]u8 align(4096) = undefined;

/// A fresh allocator over stale bytes: nothing may trust uninitialized memory.
fn fresh(t: *tlsf.Tlsf) void {
    @memset(&region, 0xA5);
    t.init();
    std.debug.assert(t.addPool(@intFromPtr(&region), REGION));
}

fn valid(t: *const tlsf.Tlsf) bool {
    return t.validateBlocks(Loud) and t.validateCounters(Loud) and t.validateFreelists(Loud);
}

fn alloc(t: *tlsf.Tlsf, size: usize, alignment: usize) !?usize {
    return switch (try t.alloc(size, alignment)) {
        .ok => |p| p,
        .oom => null,
    };
}

fn free(t: *tlsf.Tlsf, p: usize) !void {
    const loc = t.locate(p);
    try expect(loc == .block);
    try expect(t.tailFault(loc.block, p) == null);
    _ = try t.release(loc.block, p);
}

fn pristine(t: *const tlsf.Tlsf) !void {
    try expectEqual(@as(u32, 1), t.free_blocks);
    try expectEqual(@as(u64, REGION - tlsf.MIN_BLOCK_SIZE), t.free_bytes);
}

test "init: one free block before the wall" {
    var t: tlsf.Tlsf = undefined;
    fresh(&t);
    try expect(valid(&t));
    try pristine(&t);
}

test "every alignment: aligned, located, both layouts, full coalesce" {
    var t: tlsf.Tlsf = undefined;
    fresh(&t);
    var live: [256]usize = undefined;
    var n: usize = 0;
    var natural: u32 = 0;
    var buried: u32 = 0;
    const sizes = [_]usize{ 1, 15, 16, 17, 100, 4000 };
    var shift: u6 = 0;
    while (shift <= 12) : (shift += 1) {
        const a = @as(usize, 1) << shift;
        for (sizes) |s| {
            const p = (try alloc(&t, s, a)).?;
            try expect(p % @max(a, tlsf.BLOCK_ALIGN) == 0);
            const loc = t.locate(p);
            try expect(loc == .block);
            if (p - loc.block == tlsf.USER_OFFSET) natural += 1 else buried += 1;
            try expectEqual(s, tlsf.Tlsf.userSize(p));
            @memset(@as([*]u8, @ptrFromInt(p))[0..s], 0x5C);
            try expect(valid(&t));
            live[n] = p;
            n += 1;
        }
    }
    try expect(natural > 0 and buried > 0);
    // Free in an interleaved order so both merge directions run.
    var i: usize = 0;
    while (i < n) : (i += 2) try free(&t, live[i]);
    i = 1;
    while (i < n) : (i += 2) try free(&t, live[i]);
    try expect(valid(&t));
    try pristine(&t);
}

const Live = struct { p: usize, size: usize, tag: u8 };

fn checkPattern(l: Live) !void {
    const bytes = @as([*]const u8, @ptrFromInt(l.p))[0..l.size];
    for (bytes) |b| try expectEqual(l.tag, b);
}

test "random operations keep the oracle" {
    var t: tlsf.Tlsf = undefined;
    const seeds = [_]u64{ 1, 2, 3, 0xC0FFEE, 0xDEADBEEF, 42 };
    var ooms: u32 = 0;
    for (seeds) |seed| {
        fresh(&t);
        var prng = std.Random.DefaultPrng.init(seed);
        const rnd = prng.random();
        var live: [512]Live = undefined;
        var n: usize = 0;
        for (0..6000) |step| {
            const do_alloc = n == 0 or (n < live.len and rnd.uintLessThan(u8, 10) < 6);
            if (do_alloc) {
                const size: usize = switch (rnd.uintLessThan(u8, 20)) {
                    0 => rnd.intRangeAtMost(usize, 4097, 65536),
                    1...5 => rnd.intRangeAtMost(usize, 257, 4096),
                    else => rnd.intRangeAtMost(usize, 1, 256),
                };
                const alignment: usize = if (rnd.uintLessThan(u8, 5) == 0)
                    @as(usize, 1) << rnd.intRangeAtMost(u6, 5, 12)
                else
                    16;
                switch (try t.alloc(size, alignment)) {
                    .ok => |p| {
                        try expect(p % alignment == 0);
                        try expect(p >= t.pools[0].start and p + size <= t.pools[0].wall());
                        for (live[0..n]) |l| try expect(p + size <= l.p or l.p + l.size <= p);
                        const tag: u8 = @truncate(step *% 131 +% 7);
                        @memset(@as([*]u8, @ptrFromInt(p))[0..size], tag);
                        live[n] = .{ .p = p, .size = size, .tag = tag };
                        n += 1;
                    },
                    .oom => |o| {
                        // TLSF guarantee: a block of the rounded class
                        // would have been found.
                        ooms += 1;
                        try expect(o.largest < tlsf.mappingAllocRoundUp(o.search));
                        try expect(!t.canServe(o.search));
                    },
                }
            } else {
                const k = rnd.uintLessThan(usize, n);
                const l = live[k];
                try checkPattern(l);
                try free(&t, l.p);
                try expect(t.locate(l.p) == .double_free);
                live[k] = live[n - 1];
                n -= 1;
            }
            if (!valid(&t)) {
                std.debug.print("seed {d} step {d}: validators failed\n", .{ seed, step });
                return error.TestUnexpectedResult;
            }
        }
        for (live[0..n]) |l| {
            try checkPattern(l);
            try free(&t, l.p);
        }
        try pristine(&t);
    }
    try expect(ooms > 0); // the exhaustion guarantee was exercised
}

test "double free: merged into a free predecessor, and heading its run" {
    var t: tlsf.Tlsf = undefined;
    fresh(&t);
    const a = (try alloc(&t, 48, 16)).?;
    const b = (try alloc(&t, 48, 16)).?;
    const c = (try alloc(&t, 48, 16)).?;
    try free(&t, a);
    try free(&t, b); // b's header survives inside a's merged block
    try expect(t.locate(b) == .double_free);
    try expect(t.locate(a) == .double_free);
    try expect(t.locate(c) == .block);
    try free(&t, c);
    try pristine(&t);
}

test "a buried pad's garbage grain never reads as a free header" {
    var t: tlsf.Tlsf = undefined;
    fresh(&t);
    // align 32 from a 32-aligned block start leaves exactly one dead grain.
    var p: usize = 0;
    for (0..8) |_| {
        const q = (try alloc(&t, 8, 32)).?;
        if (q - t.locate(q).block == tlsf.USER_OFFSET + tlsf.BLOCK_ALIGN) {
            p = q;
            break;
        }
    }
    try expect(p != 0);
    const block = p - tlsf.USER_OFFSET - tlsf.BLOCK_ALIGN;
    // Dead grain [block+16, block+24): plant "free, size 64".
    @as(*usize, @ptrFromInt(block + 16)).* = 64 | 1;
    const loc = t.locate(p);
    try expect(loc == .block and loc.block == block);
}

test "wild pointers" {
    var t: tlsf.Tlsf = undefined;
    fresh(&t);
    const p = (try alloc(&t, 64, 16)).?;
    @memset(@as([*]u8, @ptrFromInt(p))[0..64], 0);
    try expect(t.locate(p + 16) == .wild);
    try expect(t.locate(p + 1) == .wild);
    try expect(t.locate(t.pools[0].start) == .wild);
    try expect(t.locate(t.pools[0].wall()) == .wild);
    try expect(t.locate(t.pools[0].start + REGION) == .wild);
}

test "use-after-free write over the links is caught at unlink" {
    var t: tlsf.Tlsf = undefined;
    fresh(&t);
    _ = (try alloc(&t, 48, 16)).?;
    const b = (try alloc(&t, 48, 16)).?;
    _ = (try alloc(&t, 48, 16)).?;
    try free(&t, b); // b's block: its own free run, links at b-8..b+8
    @as(*usize, @ptrFromInt(b)).* = 0x4141_4141; // obj[0..8] = prev link
    try std.testing.expectError(error.Corrupt, t.alloc(48, 16));
    try expect(t.fault == .links);
    try expectEqual(b - tlsf.USER_OFFSET, t.fault.links.block);
}

test "tail canary and user_size are bounded by the block" {
    var t: tlsf.Tlsf = undefined;
    fresh(&t);
    const p = (try alloc(&t, 20, 16)).?;
    const block = t.locate(p).block;
    try expect(t.tailFault(block, p) == null);
    const tail: *u8 = @ptrFromInt(p + 20);
    tail.* ^= 1;
    try expect(t.tailFault(block, p).? == .canary);
    tail.* ^= 1;
    const us: *u32 = @ptrFromInt(p - 8);
    us.* = 0x7FFF_FFFF;
    try expect(t.tailFault(block, p).? == .size_overflows_block);
    us.* = 20;
    try free(&t, p);
    try pristine(&t);
}

test "a shredded footer is caught before the merge" {
    var t: tlsf.Tlsf = undefined;
    fresh(&t);
    const a = (try alloc(&t, 48, 16)).?;
    const b = (try alloc(&t, 48, 16)).?;
    _ = (try alloc(&t, 48, 16)).?;
    try free(&t, a); // b's header now says PREV_FREE; a's footer sits below b
    const b_block = t.locate(b).block;
    @as(*usize, @ptrFromInt(b_block - tlsf.FOOTER_SIZE)).* = 0xFFFF_FFFF_0000;
    try std.testing.expectError(error.Corrupt, t.release(b_block, b));
    try expect(t.fault == .footer);
}

test "a free block whose size runs past its wall is caught before use" {
    var t: tlsf.Tlsf = undefined;
    fresh(&t);
    const big = t.pools[0].start; // the one free block
    const hdr: *usize = @ptrFromInt(big);
    hdr.* += 2 * tlsf.MIN_BLOCK_SIZE; // keeps the flag bits
    try std.testing.expectError(error.Corrupt, t.alloc(48, 16));
    try expect(t.fault == .size);
    try expectEqual(big, t.fault.size.block);
}

test "a merge never trusts a free neighbour's size" {
    var t: tlsf.Tlsf = undefined;
    // The pool is the first half; the second half is a guard that a merge
    // writing its footer past the wall would hit.
    const half = REGION / 2;
    @memset(&region, 0xA5);
    t.init();
    std.debug.assert(t.addPool(@intFromPtr(&region), half));
    const a = (try alloc(&t, 48, 16)).?;
    const b = (try alloc(&t, 48, 16)).?;
    const c = (try alloc(&t, 48, 16)).?;
    _ = (try alloc(&t, 48, 16)).?;
    const a_block = t.locate(a).block;
    const b_block = t.locate(b).block;
    const c_block = t.locate(c).block;
    try free(&t, b); // a | free b | c
    const b_hdr: *usize = @ptrFromInt(b_block);
    const b_saved = b_hdr.*;

    // Forward merge from a: b claims to reach past the wall, then under the minimum.
    b_hdr.* = b_saved + half;
    try std.testing.expectError(error.Corrupt, t.release(a_block, a));
    try expect(t.fault == .size);
    try expectEqual(b_block, t.fault.size.block);
    b_hdr.* = b_saved & 0xF; // flags kept, size 0
    try std.testing.expectError(error.Corrupt, t.release(a_block, a));
    try expect(t.fault == .size);

    // Backward merge from c: c's footer finds b, whose size doesn't end at c.
    b_hdr.* = b_saved + half;
    try std.testing.expectError(error.Corrupt, t.release(c_block, c));
    try expect(t.fault == .footer);
    try expectEqual(c_block, t.fault.footer.block);

    for (region[half..]) |byte| try expectEqual(@as(u8, 0xA5), byte);
    // Nothing was unlinked: with b's size back, the free list is whole.
    b_hdr.* = b_saved;
    try expect(t.validateFreelists(Loud) and t.validateCounters(Loud));
}

// === Pools ===

const SLOT: usize = 64 * 1024;
const SLOTS: usize = 64;
var arena: [SLOT * SLOTS]u8 align(4096) = undefined;

fn slotAddr(i: usize) usize {
    return @intFromPtr(&arena) + i * SLOT;
}

fn freshArena(t: *tlsf.Tlsf) void {
    @memset(&arena, 0x5A);
    t.init();
}

test "adjacent pools stay apart, each reports empty on its own" {
    var t: tlsf.Tlsf = undefined;
    freshArena(&t);
    try expect(t.addPool(slotAddr(1), SLOT)); // out of order on purpose
    try expect(t.addPool(slotAddr(0), SLOT));
    try expectEqual(slotAddr(0), t.pools[0].start);
    try expectEqual(@as(u32, 2), t.free_blocks);
    try expect(valid(&t));

    // Half a pool each: the second can't fit beside the first.
    const p = (try alloc(&t, SLOT / 2, 16)).?;
    const q = (try alloc(&t, SLOT / 2, 16)).?;
    const pp = t.poolOf(p).?;
    const qp = t.poolOf(q).?;
    try expect(pp != qp);
    try expect(valid(&t));

    const lp = t.locate(p);
    try expectEqual(@as(?u32, pp), try t.release(lp.block, p));
    try expect(t.poolIsEmpty(pp) and !t.poolIsEmpty(qp));
    try expect(valid(&t));
    const lq = t.locate(q);
    try expectEqual(@as(?u32, qp), try t.release(lq.block, q));
    try expect(valid(&t));

    _ = try t.removePool(1);
    _ = try t.removePool(0);
    try expectEqual(@as(u32, 0), t.pool_count);
    try expectEqual(@as(u64, 0), t.total_bytes);
    try expectEqual(@as(u64, 0), t.free_bytes);
    try expectEqual(@as(u32, 0), t.free_blocks);
    try expect(valid(&t));
    try expect((try t.alloc(16, 16)) == .oom);
}

test "the pool table fills up" {
    var t: tlsf.Tlsf = undefined;
    freshArena(&t);
    for (0..tlsf.MAX_POOLS) |i| try expect(t.addPool(slotAddr(i % SLOTS) + (i / SLOTS) * 4096, 2 * tlsf.MIN_BLOCK_SIZE));
    try expect(!t.addPool(slotAddr(SLOTS - 1) + SLOT / 2, 2 * tlsf.MIN_BLOCK_SIZE));
    try expect(valid(&t));
}

test "canServe agrees with alloc on the OOM search" {
    var t: tlsf.Tlsf = undefined;
    freshArena(&t);
    try expect(t.addPool(slotAddr(0), SLOT));
    try expect(t.canServe(1000));
    const search = while (true) {
        switch (try t.alloc(1000, 16)) {
            .ok => {},
            .oom => |o| break o.search,
        }
    };
    try expect(!t.canServe(search));
    try expect(t.addPool(slotAddr(2), SLOT));
    try expect(t.canServe(search));
    try expect((try t.alloc(1000, 16)) == .ok);
}

test "gaps between pools are wild, links into them are caught" {
    var t: tlsf.Tlsf = undefined;
    freshArena(&t);
    try expect(t.addPool(slotAddr(0), SLOT));
    try expect(t.addPool(slotAddr(2), SLOT));
    const gap = slotAddr(1) + 4 * tlsf.BLOCK_ALIGN;
    try expect(t.locate(gap) == .wild);
    try expect(!t.inBlockSpace(gap));
    try expect(t.poolOf(gap) == null);
    try expect(t.poolOf(slotAddr(1)) == null); // one past pool 0's end
    try expectEqual(@as(?u32, 0), t.poolOf(slotAddr(1) - 1));

    _ = (try alloc(&t, 48, 16)).?;
    const b = (try alloc(&t, 48, 16)).?;
    _ = (try alloc(&t, 48, 16)).?;
    try free(&t, b);
    @as(*usize, @ptrFromInt(b)).* = gap; // prev link into the gap
    try std.testing.expectError(error.Corrupt, t.alloc(48, 16));
    try expect(t.fault == .links);
}

/// Slot bookkeeping for the random test: pools are runs of free slots, placed
/// at random so some end up adjacent and some leave gaps.
const Slots = struct {
    used: [SLOTS]bool = [_]bool{false} ** SLOTS,

    fn grow(self: *Slots, t: *tlsf.Tlsf, rnd: std.Random, need: usize) !bool {
        const k = @max(1, (need + tlsf.MIN_BLOCK_SIZE + SLOT - 1) / SLOT);
        if (k > SLOTS) return false;
        const first = rnd.uintLessThan(usize, SLOTS);
        for (0..SLOTS) |d| {
            const s = (first + d) % SLOTS;
            if (s + k > SLOTS) continue;
            const run_free = for (self.used[s .. s + k]) |u| {
                if (u) break false;
            } else true;
            if (!run_free) continue;
            if (!t.addPool(slotAddr(s), k * SLOT)) return false;
            @memset(self.used[s .. s + k], true);
            return true;
        }
        return false;
    }

    fn shrink(self: *Slots, t: *tlsf.Tlsf, i: u32) !void {
        const p = try t.removePool(i);
        const s = (p.start - @intFromPtr(&arena)) / SLOT;
        @memset(self.used[s .. s + p.size / SLOT], false);
    }

    fn freeSlotAddr(self: *const Slots, rnd: std.Random) ?usize {
        const first = rnd.uintLessThan(usize, SLOTS);
        for (0..SLOTS) |d| {
            const s = (first + d) % SLOTS;
            if (!self.used[s]) return slotAddr(s) + 4 * tlsf.BLOCK_ALIGN;
        }
        return null;
    }
};

test "random operations while pools grow and shrink" {
    var t: tlsf.Tlsf = undefined;
    const seeds = [_]u64{ 7, 11, 0xFEED, 0xBADC0DE };
    var grown: u32 = 0;
    var shrunk: u32 = 0;
    var no_room: u32 = 0;
    for (seeds) |seed| {
        freshArena(&t);
        var slots: Slots = .{};
        var prng = std.Random.DefaultPrng.init(seed);
        const rnd = prng.random();
        var live: [768]Live = undefined;
        var n: usize = 0;
        for (0..6000) |step| {
            const do_alloc = n == 0 or (n < live.len and rnd.uintLessThan(u8, 10) < 6);
            if (do_alloc) {
                const size: usize = switch (rnd.uintLessThan(u8, 40)) {
                    0 => rnd.intRangeAtMost(usize, 65536, 200_000), // needs a multi-slot pool
                    1 => rnd.intRangeAtMost(usize, 4097, 65536),
                    2...8 => rnd.intRangeAtMost(usize, 257, 4096),
                    else => rnd.intRangeAtMost(usize, 1, 256),
                };
                const alignment: usize = if (rnd.uintLessThan(u8, 5) == 0)
                    @as(usize, 1) << rnd.intRangeAtMost(u6, 5, 12)
                else
                    16;
                var res = try t.alloc(size, alignment);
                if (res == .oom) {
                    // heap.grow's race check: never "served" on a real OOM.
                    try expect(!t.canServe(res.oom.search));
                    if (try slots.grow(&t, rnd, tlsf.mappingAllocRoundUp(res.oom.search))) {
                        grown += 1;
                        try expect(t.canServe(res.oom.search));
                        res = try t.alloc(size, alignment);
                        // A pool that holds the searched class always serves it.
                        try expect(res == .ok);
                    } else no_room += 1;
                }
                if (res == .ok) {
                    const p = res.ok;
                    try expect(p % alignment == 0);
                    const pi = t.poolOf(p).?;
                    try expect(p + size <= t.pools[pi].wall());
                    for (live[0..n]) |l| try expect(p + size <= l.p or l.p + l.size <= p);
                    const tag: u8 = @truncate(step *% 131 +% 7);
                    @memset(@as([*]u8, @ptrFromInt(p))[0..size], tag);
                    live[n] = .{ .p = p, .size = size, .tag = tag };
                    n += 1;
                }
            } else {
                const k = rnd.uintLessThan(usize, n);
                const l = live[k];
                try checkPattern(l);
                const loc = t.locate(l.p);
                try expect(loc == .block);
                try expect(t.tailFault(loc.block, l.p) == null);
                if (try t.release(loc.block, l.p)) |pi| {
                    try expect(t.poolIsEmpty(pi));
                    // Keep some empty pools around, like heap.zig's spare.
                    if (rnd.uintLessThan(u8, 4) != 0) {
                        try slots.shrink(&t, pi);
                        shrunk += 1;
                    }
                } else {
                    try expect(t.locate(l.p) == .double_free);
                }
                live[k] = live[n - 1];
                n -= 1;
            }
            if (rnd.uintLessThan(u8, 50) == 0) {
                if (slots.freeSlotAddr(rnd)) |gap| {
                    try expect(t.locate(gap) == .wild);
                    try expect(!t.inBlockSpace(gap));
                }
            }
            if (!valid(&t)) {
                std.debug.print("seed {d} step {d}: validators failed\n", .{ seed, step });
                return error.TestUnexpectedResult;
            }
        }
        for (live[0..n]) |l| {
            try checkPattern(l);
            try free(&t, l.p);
        }
        var i: u32 = t.pool_count;
        while (i > 0) {
            i -= 1;
            try expect(t.poolIsEmpty(i));
            try slots.shrink(&t, i);
        }
        try expectEqual(@as(u64, 0), t.total_bytes);
        try expectEqual(@as(u32, 0), t.free_blocks);
        try expect(valid(&t));
    }
    try expect(grown > 0 and shrunk > 0 and no_room > 0);
}
