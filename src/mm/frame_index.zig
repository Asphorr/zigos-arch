//! Per-region free-frame index over the PMM bitmap. Pure (std only, no
//! locks, no globals): pmm.zig owns the storage and the region locks,
//! tools/pmm-test drives this file against a naive oracle.
//!
//! A region is WORDS bitmap words, bit set = frame used. Two masks are
//! derived from the words and kept in step by every mutator here:
//!   nonfull — bit w ⇔ words[w] has a free frame
//!   allfree — bit w ⇔ words[w] == 0
//! A free frame is two ctz away. Single frames and short runs come from
//! partially used words first, so fully free words stay whole for
//! contiguous requests. Unlike a separate run list, nothing here can go
//! stale against the bitmap: `verify` recomputes the masks and the count
//! from the words.

const std = @import("std");

pub const WORDS: u32 = 32;
pub const FRAMES: u32 = WORDS * 32;
const FULL: u32 = 0xFFFF_FFFF;

comptime {
    // nonfull/allfree are one bit per word and the edge helpers read
    // them with ctz/clz over all 32 bits.
    if (WORDS != 32) @compileError("frame_index: WORDS must be exactly 32");
}

pub const Summary = struct {
    nonfull: u32 = 0,
    allfree: u32 = 0,
    free_count: u32 = 0,
};

inline fn wordBit(w: u32) u32 {
    return @as(u32, 1) << @intCast(w);
}

inline fn refresh(words: *const [WORDS]u32, s: *Summary, w: u32) void {
    const v = words[w];
    if (v != FULL) s.nonfull |= wordBit(w) else s.nonfull &= ~wordBit(w);
    if (v == 0) s.allfree |= wordBit(w) else s.allfree &= ~wordBit(w);
}

/// Summary recomputed from the words: init, and the verifier's reference.
pub fn rebuild(words: *const [WORDS]u32) Summary {
    var s: Summary = .{};
    for (words, 0..) |v, wi| {
        const w: u32 = @intCast(wi);
        if (v != FULL) s.nonfull |= wordBit(w);
        if (v == 0) s.allfree |= wordBit(w);
        s.free_count += 32 - @as(u32, @popCount(v));
    }
    return s;
}

pub fn verify(words: *const [WORDS]u32, s: Summary) bool {
    const r = rebuild(words);
    return r.nonfull == s.nonfull and r.allfree == s.allfree and r.free_count == s.free_count;
}

/// Claim one free frame; returns its index in the region.
pub fn allocOne(words: *[WORDS]u32, s: *Summary) ?u32 {
    const partial = s.nonfull & ~s.allfree;
    const pick = if (partial != 0) partial else s.nonfull;
    if (pick == 0) return null;
    const w: u32 = @ctz(pick);
    const b: u32 = @ctz(~words[w]);
    words[w] |= wordBit(b);
    refresh(words, s, w);
    s.free_count -= 1;
    return w * 32 + b;
}

/// Lowest bit index where `n` (1..32) consecutive set bits of `m` start.
/// Doubling: after `x &= x >> len`, bit i ⇔ bits i..i+2·len-1 all set.
pub fn runStart(m: u32, n: u32) ?u32 {
    std.debug.assert(n >= 1 and n <= 32);
    var x = m;
    var len: u32 = 1;
    while (len * 2 <= n) : (len *= 2) x &= x >> @intCast(len);
    if (len < n) x &= x >> @intCast(n - len);
    return if (x == 0) null else @ctz(x);
}

/// Start of a free run of `n` (1..FRAMES) frames, or null if the region
/// has none. Runs of ≤32 look inside partially used words first; after
/// that it is lowest-address first fit, which may straddle words or use
/// fully free ones. Complete: null only if no such run exists.
pub fn findRun(words: *const [WORDS]u32, s: Summary, n: u32) ?u32 {
    if (n == 0 or n > s.free_count) return null;
    if (n <= 32) {
        var partial = s.nonfull & ~s.allfree;
        while (partial != 0) : (partial &= partial - 1) {
            const w: u32 = @ctz(partial);
            if (runStart(~words[w], n)) |b| return w * 32 + b;
        }
    }
    var run_start: u32 = 0;
    var run_len: u32 = 0;
    for (words, 0..) |used, wi| {
        const w: u32 = @intCast(wi);
        if (used == 0) {
            if (run_len == 0) run_start = w * 32;
            run_len += 32;
            if (run_len >= n) return run_start;
            continue;
        }
        // A run coming up from the words below continues into the low
        // free bits of this one.
        if (run_len > 0 and run_len + @ctz(used) >= n) return run_start;
        if (n <= 32) if (runStart(~used, n)) |b| return w * 32 + b;
        const trail: u32 = @clz(used);
        run_len = trail;
        run_start = w * 32 + 32 - trail;
    }
    return null;
}

/// Claim `n` contiguous free frames (see findRun); returns the first index.
pub fn allocRun(words: *[WORDS]u32, s: *Summary, n: u32) ?u32 {
    if (n == 1) return allocOne(words, s);
    const start = findRun(words, s.*, n) orelse return null;
    _ = markUsed(words, s, start, n);
    return start;
}

inline fn spanMask(b: u32, span: u32) u32 {
    const ones: u32 = if (span == 32) FULL else (@as(u32, 1) << @intCast(span)) - 1;
    return ones << @intCast(b);
}

/// True if every frame in [start, start+n) is free.
pub fn rangeFree(words: *const [WORDS]u32, start: u32, n: u32) bool {
    std.debug.assert(start + n <= FRAMES);
    var f = start;
    const end = start + n;
    while (f < end) {
        const b = f % 32;
        const mask = spanMask(b, @min(32 - b, end - f));
        if (words[f / 32] & mask != 0) return false;
        f += @popCount(mask);
    }
    return true;
}

/// Mark [start, start+n) used. Returns how many of them were free.
pub fn markUsed(words: *[WORDS]u32, s: *Summary, start: u32, n: u32) u32 {
    std.debug.assert(start + n <= FRAMES);
    var changed: u32 = 0;
    var f = start;
    const end = start + n;
    while (f < end) {
        const w = f / 32;
        const b = f % 32;
        const mask = spanMask(b, @min(32 - b, end - f));
        changed += @popCount(mask & ~words[w]);
        words[w] |= mask;
        refresh(words, s, w);
        f += @popCount(mask);
    }
    s.free_count -= changed;
    return changed;
}

/// Mark [start, start+n) free. Returns how many of them were used.
pub fn markFree(words: *[WORDS]u32, s: *Summary, start: u32, n: u32) u32 {
    std.debug.assert(start + n <= FRAMES);
    var changed: u32 = 0;
    var f = start;
    const end = start + n;
    while (f < end) {
        const w = f / 32;
        const b = f % 32;
        const mask = spanMask(b, @min(32 - b, end - f));
        changed += @popCount(mask & words[w]);
        words[w] &= ~mask;
        refresh(words, s, w);
        f += @popCount(mask);
    }
    s.free_count += changed;
    return changed;
}

/// Free frames at the region's low end (frame 0 upward) — the tail of a
/// run that starts in the region below.
pub fn leadingFree(words: *const [WORDS]u32, s: Summary) u32 {
    const whole: u32 = @ctz(~s.allfree);
    if (whole >= WORDS) return FRAMES;
    return whole * 32 + @ctz(words[whole]);
}

/// Free frames at the region's high end — the head of a run that
/// continues into the region above.
pub fn trailingFree(words: *const [WORDS]u32, s: Summary) u32 {
    const whole: u32 = @clz(~s.allfree);
    if (whole >= WORDS) return FRAMES;
    return whole * 32 + @clz(words[WORDS - 1 - whole]);
}
