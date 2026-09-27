//! Off-target tests for src/mm/tlsf.zig (copied in by run.sh). The oracle
//! is the set of live allocations: each one's bytes carry its own pattern,
//! so allocator metadata straying into user data (or the reverse) shows
//! up; the three validators must pass after every step, and every freed
//! pointer must read as a double free until something reuses its bytes.

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
    t.init(@intFromPtr(&region), REGION);
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
    try t.release(loc.block, p);
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
                        try expect(p >= t.start and p + size <= t.wall);
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
    try expect(t.locate(t.start) == .wild);
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
