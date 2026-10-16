//! The regions (VMAs) of a process's user address space, sorted by start and
//! never overlapping. mmap, munmap, mprotect and brk edit the set; the page-
//! fault handler resolves a user address against it. One array: lookups are
//! binary searches, edits shift its tail.
//!
//! Imports only std — generic over the region type and the allocator — so
//! tools/vma-test drives it under `zig test`. The kernel instance is
//! process.RegionSet.
//!
//! `R` is a struct with `start` and `end` (usize, page aligned, end
//! exclusive) and:
//!   fn tailFrom(r: R, at: usize) R    r cut down to [at, r.end), with any
//!                                     offset counted from `start` advanced
//!   fn canMerge(lo: R, hi: R) bool    lo and hi (lo.end == hi.start) may be
//!                                     one region that keeps lo's fields
//! `A` has `fn alloc(n: usize) ?[*]R` and `fn free(p: [*]R, n: usize) void`.
//!
//! No locking here: the owner's PCB.as_lock covers the set, read side for
//! lookups and write side for edits.

const std = @import("std");

/// Regions one address space may hold (Linux's vm.max_map_count is 65530).
pub const MAX_REGIONS: u32 = 16384;
const MIN_CAPACITY: u32 = 8;

pub const Error = error{ OutOfMemory, Overlap };

pub fn Set(comptime R: type, comptime A: type) type {
    return struct {
        const Self = @This();

        items: [*]R = undefined,
        len: u32 = 0,
        cap: u32 = 0,

        pub fn slice(self: *const Self) []R {
            return self.items[0..self.len];
        }

        /// Index of the first region ending above `va`: the one holding
        /// `va`, else the next one up; `len` if there is none.
        fn indexAbove(self: *const Self, va: usize) u32 {
            var lo: u32 = 0;
            var hi: u32 = self.len;
            while (lo < hi) {
                const mid = lo + (hi - lo) / 2;
                if (self.items[mid].end <= va) lo = mid + 1 else hi = mid;
            }
            return lo;
        }

        /// The region holding `va`, or null.
        pub fn find(self: *const Self, va: usize) ?*R {
            const i = self.indexAbove(va);
            if (i < self.len and self.items[i].start <= va) return &self.items[i];
            return null;
        }

        /// The region holding `va`, else the lowest one above it, or null.
        pub fn atOrAbove(self: *const Self, va: usize) ?*R {
            const i = self.indexAbove(va);
            return if (i < self.len) &self.items[i] else null;
        }

        /// No region overlaps [start, end).
        pub fn isFree(self: *const Self, start: usize, end: usize) bool {
            const i = self.indexAbove(start);
            return i == self.len or self.items[i].start >= end;
        }

        /// Every byte of [start, end) lies in some region.
        pub fn covers(self: *const Self, start: usize, end: usize) bool {
            var pos = start;
            var i = self.indexAbove(start);
            while (pos < end) : (i += 1) {
                if (i == self.len or self.items[i].start > pos) return false;
                pos = self.items[i].end;
            }
            return true;
        }

        /// Room for `n` regions. Every edit reserves before it changes
        /// anything, so a failed allocation leaves the set as it was.
        fn reserve(self: *Self, n: u32) error{OutOfMemory}!void {
            if (n <= self.cap) return;
            if (n > MAX_REGIONS) return error.OutOfMemory;
            const want = @min(@max(n, self.cap * 2, MIN_CAPACITY), MAX_REGIONS);
            const fresh = A.alloc(want) orelse return error.OutOfMemory;
            if (self.cap != 0) {
                @memcpy(fresh[0..self.len], self.items[0..self.len]);
                A.free(self.items, self.cap);
            }
            self.items = fresh;
            self.cap = want;
        }

        fn insertAt(self: *Self, i: u32, r: R) void {
            std.debug.assert(self.len < self.cap);
            var k = self.len;
            while (k > i) : (k -= 1) self.items[k] = self.items[k - 1];
            self.items[i] = r;
            self.len += 1;
        }

        fn removeAt(self: *Self, i: u32, n: u32) void {
            if (n == 0) return;
            var k = i;
            while (k + n < self.len) : (k += 1) self.items[k] = self.items[k + n];
            self.len -= n;
        }

        fn splitAt(self: *Self, i: u32, at: usize) void {
            const tail = R.tailFrom(self.items[i], at);
            self.items[i].end = at;
            self.insertAt(i + 1, tail);
        }

        /// Join mergeable neighbors among items[lo..hi] (inclusive, clamped).
        fn mergeRange(self: *Self, lo: u32, hi: u32) void {
            var k = lo;
            var last = hi;
            while (k < last and k + 1 < self.len) {
                const a = &self.items[k];
                const b = self.items[k + 1];
                if (a.end == b.start and R.canMerge(a.*, b)) {
                    a.end = b.end;
                    self.removeAt(k + 1, 1);
                    last -= 1;
                } else {
                    k += 1;
                }
            }
        }

        /// Add `r`, which must not overlap any region; it joins a neighbor
        /// when R.canMerge allows, so `r` need not stay a region of its own.
        pub fn insert(self: *Self, r: R) Error!void {
            std.debug.assert(r.start < r.end);
            const i = self.indexAbove(r.start);
            if (i < self.len and self.items[i].start < r.end) return error.Overlap;
            try self.reserve(self.len + 1);
            self.insertAt(i, r);
            self.mergeRange(if (i > 0) i - 1 else 0, i + 1);
        }

        /// Take [start, end) out of the set, splitting the regions that
        /// straddle either edge. `ctx.removed(piece)` sees every removed
        /// piece, with the fields its region had (tailFrom-adjusted when the
        /// piece doesn't start at the region's start). Gaps are skipped.
        pub fn remove(self: *Self, start: usize, end: usize, ctx: anytype) error{OutOfMemory}!void {
            if (start >= end) return;
            var i = self.indexAbove(start);
            if (i == self.len or self.items[i].start >= end) return;
            // A hole punched in one region leaves two pieces of it: the only
            // removal that grows the set.
            if (self.items[i].start < start and self.items[i].end > end) {
                try self.reserve(self.len + 1);
                const r = self.items[i];
                var mid = R.tailFrom(r, start);
                mid.end = end;
                self.items[i].end = start;
                self.insertAt(i + 1, R.tailFrom(r, end));
                ctx.removed(mid);
                return;
            }
            if (self.items[i].start < start) {
                ctx.removed(R.tailFrom(self.items[i], start));
                self.items[i].end = start;
                i += 1;
            }
            var j = i;
            while (j < self.len and self.items[j].end <= end) : (j += 1) ctx.removed(self.items[j]);
            if (j < self.len and self.items[j].start < end) {
                var head = self.items[j];
                head.end = end;
                ctx.removed(head);
                // Two steps: R.tailFrom may get items[j] by reference, and a
                // result written straight into items[j] would clobber it.
                const tail = R.tailFrom(self.items[j], end);
                self.items[j] = tail;
            }
            self.removeAt(i, j - i);
        }

        /// Split the regions at `start` and `end` so pieces cover the mapped
        /// parts of [start, end) exactly, then `ctx.apply(piece)` on each; it
        /// may change any field but start and end. Neighbors that become
        /// mergeable afterwards are joined.
        pub fn update(self: *Self, start: usize, end: usize, ctx: anytype) error{OutOfMemory}!void {
            if (start >= end) return;
            try self.reserve(self.len + 2);
            var i = self.indexAbove(start);
            if (i < self.len and self.items[i].start < start) {
                self.splitAt(i, start);
                i += 1;
            }
            var j = i;
            while (j < self.len and self.items[j].start < end) : (j += 1) {
                if (self.items[j].end > end) self.splitAt(j, end);
                ctx.apply(&self.items[j]);
            }
            self.mergeRange(if (i > 0) i - 1 else 0, j);
        }

        /// Move the end of the region starting at `start` to `new_end`
        /// (above `start`), if no other region is in the way. False when no
        /// region starts there or growing would overlap the next one.
        pub fn resizeEnd(self: *Self, start: usize, new_end: usize) bool {
            if (new_end <= start) return false;
            const i = self.indexAbove(start);
            if (i == self.len or self.items[i].start != start) return false;
            if (i + 1 < self.len and self.items[i + 1].start < new_end) return false;
            self.items[i].end = new_end;
            return true;
        }

        /// Start of the highest free `len`-byte span inside [lo, hi), or null.
        pub fn gapTopDown(self: *const Self, len: usize, lo: usize, hi: usize) ?usize {
            if (len == 0 or hi <= lo or hi - lo < len) return null;
            var k = self.indexAbove(hi);
            var top = hi;
            if (k < self.len and self.items[k].start < top) top = self.items[k].start;
            while (true) {
                const below: usize = if (k > 0) self.items[k - 1].end else 0;
                const hole_lo = @max(below, lo);
                if (top > hole_lo and top - hole_lo >= len) return top - len;
                if (k == 0 or below <= lo) return null;
                k -= 1;
                top = self.items[k].start;
            }
        }

        /// A copy with its own storage (fork).
        pub fn clone(self: *const Self) error{OutOfMemory}!Self {
            var copy: Self = .{};
            if (self.len == 0) return copy;
            try copy.reserve(self.len);
            @memcpy(copy.items[0..self.len], self.items[0..self.len]);
            copy.len = self.len;
            return copy;
        }

        /// Drop every region and the storage.
        pub fn deinit(self: *Self) void {
            if (self.cap != 0) A.free(self.items, self.cap);
            self.* = .{};
        }
    };
}
