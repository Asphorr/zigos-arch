//! TLSF (Two-Level Segregated Fit) allocator core over a set of pools
//! (disjoint contiguous regions): block layout, free lists, kfree's
//! corruption detectors and the validators. Imports only std, so
//! tools/heap-test drives it under `zig test`; heap.zig owns the kernel
//! instance, its lock, where pools come from, the stats, the kasan/kdbg
//! hooks and every panic.
//!
//! Properties:
//!   - Bounded O(1) alloc and free (bitmap-indexed free lists; @ctz/@clz for
//!     bucket search).
//!   - Bounded internal fragmentation (worst case ~1/SL_INDEX_COUNT per class).
//!   - Boundary-tag coalescing in both directions on free, also O(1).
//!
//! Block layout (all blocks 16-byte aligned, sizes multiples of 16):
//!
//!   Allocated block:
//!     [0..8]:    header   (size << 4 | flags)   <- THIS_FREE clear
//!     [8..12]:   user_size (u32, requested bytes)
//!     [12..16]:  canary_head (u32 = 0xDEADBEEF; CANARY_FREED once freed)
//!     [16..16+user_size]:  user data            <- user_ptr returned here
//!     [+0..+4]:  canary_tail (u32 = 0xCAFEBABE)
//!     [pad to total_size]
//!
//!   Free block:
//!     [0..8]:    header   (size << 4 | flags)   <- THIS_FREE set
//!     [8..16]:   next_free (ptr to next block in same (FL,SL) free list)
//!     [16..24]:  prev_free (ptr to prev block in same (FL,SL) free list)
//!     [24..size-8]: unused
//!     [size-8..size]: footer (size duplicate, lets prev-coalesce find us)
//!
//! Header low 4 bits (size is always 16-multiple → low 4 bits free for flags):
//!   bit 0: THIS_FREE
//!   bit 1: PREV_FREE  (mirror of the physically previous block's THIS_FREE;
//!                      flipped by alloc/free on the NEXT block's header)
//!   bits 2-3: reserved
//!
//! User pointer is at block_addr + USER_OFFSET (=16) for naturally-aligned
//! allocs. For alignment > 16, the user pointer is shifted further into the
//! block (padding stays as dead bytes inside the allocation); user_size and
//! canary_head always sit in the 8 bytes right below it. The last
//! MIN_BLOCK_SIZE bytes of each pool are a permanently-allocated sentinel
//! "wall", so coalesce-forward always stops on an in-bounds, non-free
//! neighbour and blocks never merge across pools. A pool's first block
//! has PREV_FREE clear, so coalesce-backward stops at the pool start.

const std = @import("std");

// === Block layout constants ===

pub const BLOCK_ALIGN: usize = 16;
pub const BLOCK_ALIGN_MASK: usize = BLOCK_ALIGN - 1;
pub const HEADER_SIZE: usize = 8;
pub const FOOTER_SIZE: usize = 8;
// Per-alloc prefix (header + user_size + canary_head):
pub const USER_OFFSET: usize = 16;
pub const CANARY_TAIL_SIZE: usize = 4;
// Min total block size: header + next + prev + footer = 32. Shrinking this
// would silently overlap the prev pointer (offset 16) with the footer
// (offset size-8) — see prevFreePtr.
pub const MIN_BLOCK_SIZE: usize = 32;
comptime {
    if (MIN_BLOCK_SIZE < 32) @compileError("MIN_BLOCK_SIZE < 32 overlaps prev pointer with footer");
}

const FLAG_THIS_FREE: usize = 1 << 0;
const FLAG_PREV_FREE: usize = 1 << 1;
const SIZE_MASK: usize = ~@as(usize, 0xF);

pub const CANARY_HEAD: u32 = 0xDEADBEEF;
pub const CANARY_TAIL: u32 = 0xCAFEBABE;
// release() overwrites canary_head with this: a block merged into a free
// predecessor keeps its header inside the merged block, and a second free
// would otherwise find it intact.
pub const CANARY_FREED: u32 = 0xF4EEF4EE;

// === TLSF parameters ===

// Sizes [MIN_BLOCK_SIZE .. 1 << FL_INDEX_SHIFT) live in FL=0, subdivided
// linearly by SL. FL_INDEX_SHIFT must be >= SL_INDEX_LOG2 + log2(BLOCK_ALIGN)
// so the second-level step is at least one allocation grain.
const FL_INDEX_SHIFT: u6 = 8;
const SL_INDEX_LOG2: u6 = 4;
pub const SL_INDEX_COUNT: usize = 1 << SL_INDEX_LOG2;
const SL_INDEX_MASK: usize = SL_INDEX_COUNT - 1;
// Largest mapped block class is 2^26 (64 MB): one full FL above the largest
// pool (MAX_REGION), so mappingAllocRoundUp never carries past the last
// bucket.
const FL_INDEX_MAX_LOG2: u6 = 26;
pub const FL_INDEX_COUNT: usize = FL_INDEX_MAX_LOG2 - FL_INDEX_SHIFT + 1; // 19
pub const MAX_REGION: usize = @as(usize, 1) << (FL_INDEX_MAX_LOG2 - 1);
pub const MAX_POOLS: usize = 64;

// === Raw block accessors (addresses, not instance state) ===

inline fn headerPtr(addr: usize) *usize {
    return @ptrFromInt(addr);
}
pub inline fn blockSize(addr: usize) usize {
    return headerPtr(addr).* & SIZE_MASK;
}
pub inline fn blockIsFree(addr: usize) bool {
    return (headerPtr(addr).* & FLAG_THIS_FREE) != 0;
}
inline fn blockPrevFree(addr: usize) bool {
    return (headerPtr(addr).* & FLAG_PREV_FREE) != 0;
}
inline fn writeHeader(addr: usize, size: usize, this_free: bool, prev_free: bool) void {
    var v = size & SIZE_MASK;
    if (this_free) v |= FLAG_THIS_FREE;
    if (prev_free) v |= FLAG_PREV_FREE;
    headerPtr(addr).* = v;
}
inline fn setPrevFreeFlag(addr: usize, prev_free: bool) void {
    var v = headerPtr(addr).*;
    if (prev_free) v |= FLAG_PREV_FREE else v &= ~FLAG_PREV_FREE;
    headerPtr(addr).* = v;
}
inline fn writeFooter(addr: usize) void {
    const sz = blockSize(addr);
    const f: *usize = @ptrFromInt(addr + sz - FOOTER_SIZE);
    f.* = sz;
}
inline fn readFooterAt(footer_addr: usize) usize {
    const f: *const usize = @ptrFromInt(footer_addr);
    return f.*;
}

// Free-block links live in the user-data region; safe to overlay because
// the block is free. Plain `usize` with 0 as the null sentinel: `?usize` is
// 16 bytes wide and would overlap next_free@+8 with prev_free@+16 (the
// 2026-05-28 #PF cr2=0x10 in removeFreeBlock).
pub inline fn nextFreePtr(addr: usize) *usize {
    return @ptrFromInt(addr + 8);
}
pub inline fn prevFreePtr(addr: usize) *usize {
    return @ptrFromInt(addr + 16);
}

// Physically-prev block addr (only valid if PREV_FREE set in our header).
// Wrapping: a shredded footer must reach release()'s range check, not an
// overflow panic.
inline fn prevPhysAddr(addr: usize) usize {
    const prev_size = readFooterAt(addr - FOOTER_SIZE);
    return addr -% (prev_size & SIZE_MASK);
}

inline fn alignUp(addr: usize, alignment: usize) usize {
    if (alignment == 0) return addr;
    return (addr + alignment - 1) & ~(alignment - 1);
}

// === Size → (FL, SL) mapping ===

/// Round a request up so the bucket it maps to only holds blocks at least
/// that large: add (1 << (log2(size) - SL_INDEX_LOG2)) - 1 so a size not on
/// a class boundary moves into the next SL slot.
pub fn mappingAllocRoundUp(size: usize) usize {
    if (size < (1 << FL_INDEX_SHIFT)) return size;
    const log2: u6 = @intCast(63 - @clz(size));
    const round: usize = (@as(usize, 1) << (log2 - SL_INDEX_LOG2)) - 1;
    return size + round;
}

pub const FlSl = struct { fl: usize, sl: usize };

/// Map a size to (fl, sl). For sizes < 1 << FL_INDEX_SHIFT, fl=0 and sl is
/// linear in size.
pub fn mapping(size: usize) FlSl {
    if (size < (1 << FL_INDEX_SHIFT)) {
        const small_shift: u6 = FL_INDEX_SHIFT - SL_INDEX_LOG2;
        return .{ .fl = 0, .sl = size >> small_shift };
    }
    const log2: u6 = @intCast(63 - @clz(size));
    const fl: usize = log2 - FL_INDEX_SHIFT + 1;
    const sl: usize = (size >> (log2 - SL_INDEX_LOG2)) & SL_INDEX_MASK;
    return .{ .fl = fl, .sl = sl };
}

// === Results ===

pub const OomInfo = struct {
    need_block: usize,
    search: usize,
    fl_bitmap: u32,
    free_blocks: u32,
    free_bytes: u64,
    largest: usize,
};

pub const AllocResult = union(enum) {
    ok: usize,
    oom: OomInfo,
};

pub const Located = union(enum) {
    block: usize,
    double_free,
    wild,
};

/// Why a live block's user_size / tail canary can't be trusted.
pub const TailFault = enum { size_overflows_block, canary };

/// Structural corruption found while unlinking or coalescing. The operation
/// stops at the fault, leaving the pools as it found them past that point;
/// the kernel panics on it.
pub const Fault = union(enum) {
    /// A free block's neighbours don't point back at it (use-after-free
    /// write over its links).
    links: struct { block: usize, next: usize, prev: usize },
    /// The footer below `block` decodes to an impossible predecessor, or to
    /// a free block that doesn't end at `block` (heap underflow over the
    /// previous block's tail).
    footer: struct { block: usize, prev: usize },
    /// A free block's header claims a size its pool can't hold: past the
    /// wall, or under the minimum (an overflow of the block below rewrote
    /// it).
    size: struct { block: usize, size: usize },
};

pub const Corrupt = error{Corrupt};

/// One contiguous region: blocks over [start, wall), the sentinel wall
/// over [wall, start + size).
pub const Pool = struct {
    start: usize,
    size: usize,

    pub inline fn wall(p: Pool) usize {
        return p.start + p.size - MIN_BLOCK_SIZE;
    }
};

// === The allocator ===

pub const Tlsf = struct {
    /// Sorted by start, disjoint.
    pools: [MAX_POOLS]Pool,
    pool_count: u32,
    /// Sum of pool sizes, walls included.
    total_bytes: u64,

    // Bitmaps: bit i in fl_bitmap set iff sl_bitmaps[i] != 0.
    //          bit j in sl_bitmaps[i] set iff free_lists[i][j] != 0.
    fl_bitmap: u32,
    sl_bitmaps: [FL_INDEX_COUNT]u16,
    free_lists: [FL_INDEX_COUNT][SL_INDEX_COUNT]usize,

    free_bytes: u64,
    free_blocks: u32,
    /// Upper bound between recomputes: insertFreeBlock grows it, nothing
    /// shrinks it on alloc. Consumers that need the true value call
    /// recomputeLargestFreeBlock first.
    largest_free: usize,

    /// Set whenever an operation returns error.Corrupt.
    fault: Fault,

    /// No pools: every alloc reports oom until addPool.
    pub fn init(self: *Tlsf) void {
        self.* = .{
            .pools = undefined,
            .pool_count = 0,
            .total_bytes = 0,
            .fl_bitmap = 0,
            .sl_bitmaps = [_]u16{0} ** FL_INDEX_COUNT,
            .free_lists = [_][SL_INDEX_COUNT]usize{[_]usize{0} ** SL_INDEX_COUNT} ** FL_INDEX_COUNT,
            .free_bytes = 0,
            .free_blocks = 0,
            .largest_free = 0,
            .fault = undefined,
        };
    }

    /// Add [start, start+size) as one free block before its wall. `start`
    /// 16-aligned, `size` a 16-multiple in [2 * MIN_BLOCK_SIZE, MAX_REGION],
    /// disjoint from every pool. False (nothing written) if the table is full.
    pub fn addPool(self: *Tlsf, start: usize, size: usize) bool {
        std.debug.assert(start & BLOCK_ALIGN_MASK == 0 and size & BLOCK_ALIGN_MASK == 0);
        std.debug.assert(size >= 2 * MIN_BLOCK_SIZE and size <= MAX_REGION);
        if (self.pool_count == MAX_POOLS) return false;
        const at = self.firstPoolAfter(start);
        if (at > 0) std.debug.assert(self.pools[at - 1].start + self.pools[at - 1].size <= start);
        if (at < self.pool_count) std.debug.assert(start + size <= self.pools[at].start);
        var i: u32 = self.pool_count;
        while (i > at) : (i -= 1) self.pools[i] = self.pools[i - 1];
        const pool: Pool = .{ .start = start, .size = size };
        self.pools[at] = pool;
        self.pool_count += 1;
        self.total_bytes += size;

        const big_size = pool.wall() - start;
        writeHeader(start, big_size, true, false);
        writeFooter(start);
        // Wall: allocated, never freed, PREV_FREE set (the big block in
        // front of it is free).
        writeHeader(pool.wall(), MIN_BLOCK_SIZE, false, true);
        self.free_bytes += big_size;
        self.insertFreeBlock(start);
        return true;
    }

    /// Index of the first pool starting above `addr` (pool_count if none).
    fn firstPoolAfter(self: *const Tlsf, addr: usize) u32 {
        var lo: u32 = 0;
        var hi: u32 = self.pool_count;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (self.pools[mid].start <= addr) lo = mid + 1 else hi = mid;
        }
        return lo;
    }

    /// Index of the pool whose [start, start + size) holds `addr`. The
    /// `addr >= start` test is redundant under the owner's lock; it keeps an
    /// unlocked diagnostic read of a table mid-shift from underflowing.
    pub fn poolOf(self: *const Tlsf, addr: usize) ?u32 {
        const after = self.firstPoolAfter(addr);
        if (after == 0) return null;
        const p = self.pools[after - 1];
        return if (addr >= p.start and addr - p.start < p.size) after - 1 else null;
    }

    /// `addr` lies before some pool's wall: where blocks and user bytes live.
    pub fn inBlockSpace(self: *const Tlsf, addr: usize) bool {
        const i = self.poolOf(addr) orelse return false;
        return addr < self.pools[i].wall();
    }

    /// Pool `i` holds nothing: one free block from its start to its wall.
    pub fn poolIsEmpty(self: *const Tlsf, i: u32) bool {
        const p = self.pools[i];
        return blockIsFree(p.start) and blockSize(p.start) == p.wall() - p.start;
    }

    /// Take empty pool `i` out; its memory is the caller's again.
    pub fn removePool(self: *Tlsf, i: u32) Corrupt!Pool {
        std.debug.assert(i < self.pool_count and self.poolIsEmpty(i));
        const p = self.pools[i];
        try self.removeFreeBlock(p.start);
        self.free_bytes -= p.wall() - p.start;
        self.total_bytes -= p.size;
        var j: u32 = i;
        while (j + 1 < self.pool_count) : (j += 1) self.pools[j] = self.pools[j + 1];
        self.pool_count -= 1;
        return p;
    }

    // Find the smallest non-empty (fl, sl) >= the input, or null.
    fn searchSuitableBlock(self: *const Tlsf, fl_in: usize, sl_in: usize) ?FlSl {
        if (fl_in >= FL_INDEX_COUNT) return null;
        const sl_map: u16 = self.sl_bitmaps[fl_in] & (@as(u16, 0xFFFF) << @intCast(sl_in));
        if (sl_map != 0) return .{ .fl = fl_in, .sl = @ctz(sl_map) };
        const shift_amt: u5 = @intCast(fl_in + 1);
        if (shift_amt >= 32) return null;
        const fl_map: u32 = self.fl_bitmap & (@as(u32, 0xFFFFFFFF) << shift_amt);
        if (fl_map == 0) return null;
        const fl: usize = @ctz(fl_map);
        if (fl >= FL_INDEX_COUNT) return null;
        return .{ .fl = fl, .sl = @ctz(self.sl_bitmaps[fl]) };
    }

    fn insertFreeBlock(self: *Tlsf, addr: usize) void {
        const sz = blockSize(addr);
        const m = mapping(sz);
        const head = self.free_lists[m.fl][m.sl];
        nextFreePtr(addr).* = head;
        prevFreePtr(addr).* = 0;
        if (head != 0) prevFreePtr(head).* = addr;
        self.free_lists[m.fl][m.sl] = addr;
        self.sl_bitmaps[m.fl] |= (@as(u16, 1) << @intCast(m.sl));
        self.fl_bitmap |= (@as(u32, 1) << @intCast(m.fl));
        self.free_blocks += 1;
        if (sz > self.largest_free) self.largest_free = sz;
    }

    inline fn linkInRegion(self: *const Tlsf, p: usize) bool {
        return (p & BLOCK_ALIGN_MASK) == 0 and self.inBlockSpace(p);
    }

    /// Both neighbours of free block `addr` point back at it. The links are
    /// the first bytes of a freed allocation, so a use-after-free write lands
    /// on them; unlinking through a bad one would scribble wherever it points.
    pub fn linksIntact(self: *const Tlsf, addr: usize) bool {
        const next = nextFreePtr(addr).*;
        const prev = prevFreePtr(addr).*;
        if (next != 0 and !(self.linkInRegion(next) and prevFreePtr(next).* == addr)) return false;
        if (prev == 0) {
            const m = mapping(blockSize(addr));
            return self.free_lists[m.fl][m.sl] == addr;
        }
        return self.linkInRegion(prev) and nextFreePtr(prev).* == addr;
    }

    fn removeFreeBlock(self: *Tlsf, addr: usize) Corrupt!void {
        const next = nextFreePtr(addr).*;
        const prev = prevFreePtr(addr).*;
        if (!self.linksIntact(addr)) {
            self.fault = .{ .links = .{ .block = addr, .next = next, .prev = prev } };
            return error.Corrupt;
        }
        const m = mapping(blockSize(addr));
        if (next != 0) prevFreePtr(next).* = prev;
        if (prev != 0) {
            nextFreePtr(prev).* = next;
        } else {
            // We were the head.
            self.free_lists[m.fl][m.sl] = next;
            if (next == 0) {
                self.sl_bitmaps[m.fl] &= ~(@as(u16, 1) << @intCast(m.sl));
                if (self.sl_bitmaps[m.fl] == 0) {
                    self.fl_bitmap &= ~(@as(u32, 1) << @intCast(m.fl));
                }
            }
        }
        if (self.free_blocks > 0) self.free_blocks -= 1;
    }

    /// A free block exists that an alloc searching `search` bytes (as in
    /// AllocResult.oom) would take.
    pub fn canServe(self: *const Tlsf, search: usize) bool {
        const m = mapping(mappingAllocRoundUp(search));
        return self.searchSuitableBlock(m.fl, m.sl) != null;
    }

    /// Allocate `size` bytes aligned to `alignment`; returns the user
    /// pointer. Caller validated 0 < size <= MAX_REGION and a power-of-two
    /// alignment <= MAX_REGION. Alignments up to BLOCK_ALIGN are natural;
    /// higher ones carve a front pad off a larger block.
    pub fn alloc(self: *Tlsf, size: usize, alignment: usize) Corrupt!AllocResult {
        // Block size including the 16-byte prefix and the 4-byte tail
        // canary, 16-aligned, at least MIN_BLOCK_SIZE.
        const min_user_block = alignUp(USER_OFFSET + size + CANARY_TAIL_SIZE, BLOCK_ALIGN);
        const need_block = if (min_user_block < MIN_BLOCK_SIZE) MIN_BLOCK_SIZE else min_user_block;

        // For alignment > 16, room to carve a front pad so the user pointer
        // lands aligned: worst case alignment + MIN_BLOCK_SIZE (a split-off
        // front needs MIN_BLOCK_SIZE to be its own free block).
        const search_size = if (alignment > BLOCK_ALIGN)
            need_block + alignment + MIN_BLOCK_SIZE
        else
            need_block;

        const m = mapping(mappingAllocRoundUp(search_size));
        const found = self.searchSuitableBlock(m.fl, m.sl) orelse {
            // largest_free is a stale upper bound between recomputes —
            // refresh it so the OOM post-mortem shows the real ceiling.
            self.recomputeLargestFreeBlock();
            return .{ .oom = .{
                .need_block = need_block,
                .search = search_size,
                .fl_bitmap = self.fl_bitmap,
                .free_blocks = self.free_blocks,
                .free_bytes = self.free_bytes,
                .largest = self.largest_free,
            } };
        };

        const block_addr = self.free_lists[found.fl][found.sl];
        const block_sz = blockSize(block_addr);
        // Every write below stays inside [block_addr, block_addr + block_sz]
        // (the header after it included), so that range must end at or
        // before its pool's wall.
        const room: usize = if (self.poolOf(block_addr)) |pi| self.pools[pi].wall() -| block_addr else 0;
        if (block_sz < MIN_BLOCK_SIZE or block_sz > room) {
            self.fault = .{ .size = .{ .block = block_addr, .size = block_sz } };
            return error.Corrupt;
        }
        try self.removeFreeBlock(block_addr);

        // User pointer: naturally block_addr + USER_OFFSET. For higher
        // alignment, shift up; the bytes between USER_OFFSET and the aligned
        // user pointer are dead inside the allocation.
        var user_ptr: usize = block_addr + USER_OFFSET;
        var alloc_block_addr: usize = block_addr;
        if (alignment > BLOCK_ALIGN) {
            const aligned = alignUp(user_ptr, alignment);
            const front_size: usize = (aligned - USER_OFFSET) - block_addr;
            if (front_size >= MIN_BLOCK_SIZE) {
                // Split: the front becomes a free block (inheriting this
                // block's PREV_FREE), the back is our alloc.
                const new_block = aligned - USER_OFFSET;
                const back_size = block_sz - front_size;
                writeHeader(block_addr, front_size, true, blockPrevFree(block_addr));
                writeFooter(block_addr);
                writeHeader(new_block, back_size, false, true);
                self.insertFreeBlock(block_addr);
                alloc_block_addr = new_block;
                user_ptr = aligned;
            } else {
                // Front pad too small to split (exactly one 16-byte grain):
                // bury it inside the allocation.
                user_ptr = aligned;
            }
        }

        const cur_block_sz = blockSize(alloc_block_addr);

        // Split off the tail if the remainder is its own block.
        const consumed = (user_ptr - alloc_block_addr) + size + CANARY_TAIL_SIZE;
        const consumed_aligned = alignUp(consumed, BLOCK_ALIGN);
        const consumed_clamped = if (consumed_aligned < MIN_BLOCK_SIZE) MIN_BLOCK_SIZE else consumed_aligned;
        const final_block_size: usize = blk: {
            const alloc_prev_free = blockPrevFree(alloc_block_addr);
            if (cur_block_sz >= consumed_clamped + MIN_BLOCK_SIZE) {
                const remainder = cur_block_sz - consumed_clamped;
                const tail_addr = alloc_block_addr + consumed_clamped;
                writeHeader(alloc_block_addr, consumed_clamped, false, alloc_prev_free);
                // Tail: a new free block; its predecessor (us) is allocated.
                writeHeader(tail_addr, remainder, true, false);
                writeFooter(tail_addr);
                self.insertFreeBlock(tail_addr);
                // The next block (at worst the wall) exists: checked above.
                setPrevFreeFlag(tail_addr + remainder, true);
                break :blk consumed_clamped;
            } else {
                writeHeader(alloc_block_addr, cur_block_sz, false, alloc_prev_free);
                setPrevFreeFlag(alloc_block_addr + cur_block_sz, false);
                break :blk cur_block_sz;
            }
        };

        // user_size + canary_head right below the user pointer (block+8..16
        // for natural alignment), so free finds them at a fixed offset.
        const us_ptr: *u32 = @ptrFromInt(user_ptr - 8);
        const ch_ptr: *u32 = @ptrFromInt(user_ptr - 4);
        us_ptr.* = @intCast(size);
        ch_ptr.* = CANARY_HEAD;
        // Tail canary right after user data (may be unaligned).
        const tail_ptr: *align(1) u32 = @ptrFromInt(user_ptr + size);
        tail_ptr.* = CANARY_TAIL;

        self.free_bytes -= final_block_size;
        return .{ .ok = user_ptr };
    }

    /// The allocated block whose user pointer is `addr`, for any `addr`
    /// (outside every pool's block space it is wild).
    ///
    /// Scans back from (addr - USER_OFFSET) at 16-byte grains. TWO grains
    /// suffice, provably: alloc yields exactly two layouts. Natural
    /// (alignment <= 16, or an over-aligned request whose front pad reached
    /// MIN_BLOCK_SIZE and was split off as its own free block): user_ptr =
    /// block + USER_OFFSET — header on the first probe. Buried pad (over-
    /// aligned, pad too small to split): the pad is a nonzero 16-multiple <
    /// MIN_BLOCK_SIZE=32, i.e. exactly 16 — header one grain lower. A miss
    /// within two grains is a wild pointer; keeping the limit tight fails
    /// wild frees fast and gives stale user bytes no room to masquerade as a
    /// header.
    pub fn locate(self: *const Tlsf, addr: usize) Located {
        // Every user pointer is 16-aligned (natural, or aligned further);
        // this also keeps the u32 reads at addr-8 / addr-4 aligned.
        if (addr & BLOCK_ALIGN_MASK != 0) return .wild;
        const pi = self.poolOf(addr) orelse return .wild;
        const pool = self.pools[pi];
        const wall = pool.wall();
        if (addr >= wall) return .wild;
        const SCAN_LIMIT: usize = 2 * BLOCK_ALIGN;
        var block_addr: usize = (addr -% USER_OFFSET) & ~BLOCK_ALIGN_MASK;
        var scanned: usize = 0;
        while (scanned < SCAN_LIMIT) : (scanned += BLOCK_ALIGN) {
            if (block_addr < pool.start or block_addr >= wall) break;
            const hdr_raw = headerPtr(block_addr).*;
            const sz = hdr_raw & SIZE_MASK;
            const this_free = (hdr_raw & FLAG_THIS_FREE) != 0;
            // Containment: the user pointer must actually live inside this
            // candidate block — else a stale ptr whose addr-4 happens to be
            // CANARY_HEAD could free the wrong block.
            if (!this_free and sz >= MIN_BLOCK_SIZE and sz <= wall - block_addr and
                addr >= block_addr + USER_OFFSET and addr < block_addr + sz)
            {
                const ch: *const u32 = @ptrFromInt(addr - 4);
                if (ch.* == CANARY_HEAD) return .{ .block = block_addr };
            }
            if (block_addr <= pool.start) break; // next step would leave the pool
            block_addr -= BLOCK_ALIGN;
        }
        // Not live. Only now tell a repeated free from a wild pointer: the
        // probes above may read a buried pad's garbage grain, which must
        // never decide.
        if (addr < pool.start + USER_OFFSET) return .wild;
        // Merged into a free predecessor (or a buried block heading its
        // run): canary_head still holds release()'s poison.
        if (@as(*const u32, @ptrFromInt(addr - 4)).* == CANARY_FREED) return .double_free;
        // A natural block heading its free run: the links overwrote the
        // poison, but its own header now says free.
        const b = addr - USER_OFFSET;
        const sz = blockSize(b);
        if (blockIsFree(b) and sz >= MIN_BLOCK_SIZE and sz <= wall - b) return .double_free;
        return .wild;
    }

    /// Why the user_size / tail canary of live block `block_addr` (user
    /// pointer `addr`) can't be trusted, or null if both check out. The tail
    /// must end inside the block: a corrupt user_size must not steer the
    /// check into a neighbour.
    pub fn tailFault(self: *const Tlsf, block_addr: usize, addr: usize) ?TailFault {
        _ = self;
        const user_size: usize = userSize(addr);
        const room = block_addr + blockSize(block_addr) - addr;
        if (user_size > room or room - user_size < CANARY_TAIL_SIZE) return .size_overflows_block;
        const tail_ptr: *align(1) const u32 = @ptrFromInt(addr + user_size);
        if (tail_ptr.* != CANARY_TAIL) return .canary;
        return null;
    }

    pub inline fn userSize(addr: usize) usize {
        return @as(*const u32, @ptrFromInt(addr - 8)).*;
    }

    /// Free live block `block_addr` (user pointer `addr`), both already
    /// checked by locate + tailFault: poison canary_head, coalesce with free
    /// neighbours, relist. Returns the block's pool index when that pool is
    /// now empty (poolIsEmpty), else null.
    pub fn release(self: *Tlsf, block_addr: usize, addr: usize) Corrupt!?u32 {
        const pi = self.poolOf(block_addr).?;
        const pool = self.pools[pi];
        const wall = pool.wall();
        @as(*u32, @ptrFromInt(addr - 4)).* = CANARY_FREED;

        // Only `freed_size` joins free_bytes: merged neighbours were already
        // counted while free (the 2026-05-24 double count showed 233546 KB
        // free on a 16 MB heap).
        const freed_size: usize = blockSize(block_addr);
        // Both neighbours' sizes are checked before anything is unlinked:
        // a merge trusting a rewritten size writes its footer outside the
        // pool, into whatever PMM gave out next to it.
        var prev_free: ?usize = null;
        if (blockPrevFree(block_addr)) {
            const prev_addr = prevPhysAddr(block_addr);
            // The footer borders the previous block's user region — a heap
            // underflow shreds it and prev_addr becomes garbage.
            if (prev_addr < pool.start or prev_addr >= block_addr or
                (prev_addr & BLOCK_ALIGN_MASK) != 0 or
                (blockIsFree(prev_addr) and blockSize(prev_addr) != block_addr - prev_addr))
            {
                self.fault = .{ .footer = .{ .block = block_addr, .prev = prev_addr } };
                return error.Corrupt;
            }
            if (blockIsFree(prev_addr)) prev_free = prev_addr;
        }
        // The wall is never free, so the forward merge stops at it.
        const next_addr = block_addr + freed_size;
        var next_free: ?usize = null;
        if (next_addr < wall and blockIsFree(next_addr)) {
            const next_size = blockSize(next_addr);
            if (next_size < MIN_BLOCK_SIZE or next_size > wall - next_addr) {
                self.fault = .{ .size = .{ .block = next_addr, .size = next_size } };
                return error.Corrupt;
            }
            next_free = next_addr;
        }

        var merge_addr = block_addr;
        var merge_size = freed_size;
        if (prev_free) |p| {
            try self.removeFreeBlock(p);
            merge_addr = p;
            merge_size += block_addr - p;
        }
        if (next_free) |n| {
            try self.removeFreeBlock(n);
            merge_size += blockSize(n);
        }

        writeHeader(merge_addr, merge_size, true, blockPrevFree(merge_addr));
        writeFooter(merge_addr);
        self.insertFreeBlock(merge_addr);
        self.free_bytes += freed_size;
        const after = merge_addr + merge_size;
        if (after <= wall) setPrevFreeFlag(after, true);
        return if (merge_addr == pool.start and after == wall) pi else null;
    }

    pub fn recomputeLargestFreeBlock(self: *Tlsf) void {
        var best: usize = 0;
        for (0..FL_INDEX_COUNT) |i| {
            if ((self.fl_bitmap & (@as(u32, 1) << @intCast(i))) == 0) continue;
            for (0..SL_INDEX_COUNT) |j| {
                var p = self.free_lists[i][j];
                while (p != 0) : (p = nextFreePtr(p).*) {
                    best = @max(best, blockSize(p));
                }
            }
        }
        self.largest_free = best;
    }

    // === Validators — `Log` is any type with `pub fn print(comptime fmt, args)` ===

    /// Walk every block of every pool: header consistency, the canaries of
    /// every allocated block (both layouts; walls are the one exemption),
    /// PREV_FREE agreement, each walk ending exactly on its wall.
    pub fn validateBlocks(self: *const Tlsf, comptime Log: type) bool {
        var errors: u32 = 0;
        for (self.pools[0..self.pool_count]) |pool| {
            if (!validatePoolBlocks(pool, Log)) errors += 1;
        }
        return errors == 0;
    }

    fn validatePoolBlocks(pool: Pool, comptime Log: type) bool {
        var errors: u32 = 0;
        const end = pool.start + pool.size;
        var addr: usize = pool.start;
        var prev_was_free: bool = false;
        while (addr < end) {
            const sz = blockSize(addr);
            if (sz < MIN_BLOCK_SIZE or (sz & BLOCK_ALIGN_MASK) != 0 or addr + sz > end or
                (addr < pool.wall() and addr + sz > pool.wall()))
            {
                Log.print("[tlsf] validate: bad size {d} at 0x{X:0>16}\n", .{ sz, addr });
                errors += 1;
                break;
            }
            if (addr == pool.wall() and blockIsFree(addr)) {
                Log.print("[tlsf] validate: wall at 0x{X:0>16} is marked free\n", .{addr});
                errors += 1;
                break;
            }
            const pf = blockPrevFree(addr);
            if (pf != prev_was_free) {
                Log.print("[tlsf] validate: prev-free flag mismatch at 0x{X:0>16} (have {} want {})\n", .{ addr, pf, prev_was_free });
                errors += 1;
            }
            if (blockIsFree(addr)) {
                const f = readFooterAt(addr + sz - FOOTER_SIZE) & SIZE_MASK;
                if (f != sz) {
                    Log.print("[tlsf] validate: footer mismatch at 0x{X:0>16}: {d} vs {d}\n", .{ addr, f, sz });
                    errors += 1;
                }
                prev_was_free = true;
            } else if (addr != pool.wall()) {
                // Natural layout first: for buried blocks +12 holds the upper
                // half of a stale link, stale user bytes or CANARY_FREED —
                // never CANARY_HEAD — so the order can't misattribute. Both
                // probe offsets sit inside the block (sz >= 32).
                const BURIED_USER_OFFSET: usize = USER_OFFSET + BLOCK_ALIGN;
                const ch_nat: *const u32 = @ptrFromInt(addr + USER_OFFSET - 4);
                const ch_pad: *const u32 = @ptrFromInt(addr + BURIED_USER_OFFSET - 4);
                const user_off: usize = if (ch_nat.* == CANARY_HEAD)
                    USER_OFFSET
                else if (ch_pad.* == CANARY_HEAD)
                    BURIED_USER_OFFSET
                else blk: {
                    Log.print("[tlsf] validate: head canary missing at 0x{X:0>16} (sz={d})\n", .{ addr, sz });
                    errors += 1;
                    break :blk 0;
                };
                if (user_off != 0) {
                    const user_size = userSize(addr + user_off);
                    if (user_off + user_size + CANARY_TAIL_SIZE > sz) {
                        Log.print("[tlsf] validate: user_size {d} overflows block at 0x{X:0>16} (sz={d})\n", .{ user_size, addr, sz });
                        errors += 1;
                    } else {
                        const tail: *align(1) const u32 = @ptrFromInt(addr + user_off + user_size);
                        if (tail.* != CANARY_TAIL) {
                            Log.print("[tlsf] validate: tail canary at 0x{X:0>16}: got 0x{X:0>8} want 0x{X:0>8}\n", .{ addr + user_off + user_size, tail.*, CANARY_TAIL });
                            errors += 1;
                        }
                    }
                }
                prev_was_free = false;
            } else {
                prev_was_free = false;
            }
            addr += sz;
        }
        return errors == 0;
    }

    /// Re-derive free_bytes / free_blocks / largest_free from a block walk
    /// and compare with the incrementally-maintained counters; the pool
    /// table must be sorted, disjoint and sum to total_bytes.
    pub fn validateCounters(self: *const Tlsf, comptime Log: type) bool {
        var walked_free_bytes: u64 = 0;
        var walked_free_blocks: u32 = 0;
        var walked_largest: usize = 0;
        var walked_alloc_bytes: u64 = 0;
        var pool_bytes: u64 = 0;
        for (self.pools[0..self.pool_count], 0..) |pool, i| {
            if (i > 0) {
                const below = self.pools[i - 1];
                if (below.start + below.size > pool.start) {
                    Log.print("[tlsf] inv: pool {d} at 0x{X:0>16} overlaps or precedes pool {d}\n", .{ i, pool.start, i - 1 });
                    return false;
                }
            }
            pool_bytes += pool.size;
            const end = pool.start + pool.size;
            var addr: usize = pool.start;
            while (addr < end) {
                const sz = blockSize(addr);
                if (sz < MIN_BLOCK_SIZE or addr + sz > end) {
                    Log.print("[tlsf] inv: walk derailed at 0x{X:0>16} (sz={d}) — structural corruption, can't audit\n", .{ addr, sz });
                    return false;
                }
                if (blockIsFree(addr)) {
                    walked_free_bytes += sz;
                    walked_free_blocks += 1;
                    walked_largest = @max(walked_largest, sz);
                } else {
                    walked_alloc_bytes += sz;
                }
                addr += sz;
            }
        }

        var ok = true;
        if (pool_bytes != self.total_bytes) {
            Log.print("[tlsf] inv: total_bytes={d} but pools sum to {d}\n", .{ self.total_bytes, pool_bytes });
            ok = false;
        }
        if (walked_free_bytes != self.free_bytes) {
            Log.print("[tlsf] inv: free_bytes={d} but walk says {d}\n", .{ self.free_bytes, walked_free_bytes });
            ok = false;
        }
        if (walked_free_blocks != self.free_blocks) {
            Log.print("[tlsf] inv: free_blocks={d} but walk says {d}\n", .{ self.free_blocks, walked_free_blocks });
            ok = false;
        }
        // largest_free is an upper bound between recomputes: only a value
        // SMALLER than the real maximum lies about available space.
        if (self.largest_free < walked_largest) {
            Log.print("[tlsf] inv: largest_free={d} but walk found {d}\n", .{ self.largest_free, walked_largest });
            ok = false;
        }
        // Walls are counted in walked_alloc_bytes.
        if (walked_free_bytes + walked_alloc_bytes != pool_bytes) {
            Log.print("[tlsf] inv: walked free+alloc={d} but the pools hold {d}\n", .{ walked_free_bytes + walked_alloc_bytes, pool_bytes });
            ok = false;
        }
        return ok;
    }

    /// Walk every free list: blocks in a pool and aligned, THIS_FREE set,
    /// block in its mapped bucket, back-link symmetry, bitmap bits ⇔
    /// non-empty lists, visited count == free_blocks (cycle-capped).
    pub fn validateFreelists(self: *const Tlsf, comptime Log: type) bool {
        var ok = true;
        var visited: u32 = 0;
        // Cap at free_blocks + slack so a lying counter still completes and
        // reports instead of spinning on a cycle.
        const max_visit: u32 = self.free_blocks + 16;

        for (0..FL_INDEX_COUNT) |fl| {
            const fl_set = (self.fl_bitmap & (@as(u32, 1) << @intCast(fl))) != 0;
            const sl_word = self.sl_bitmaps[fl];
            if (fl_set != (sl_word != 0)) {
                Log.print("[tlsf] fl-inv: fl_bitmap[{d}]={any} but sl_bitmaps[{d}]=0x{X}\n", .{ fl, fl_set, fl, sl_word });
                ok = false;
            }
            for (0..SL_INDEX_COUNT) |sl| {
                const sl_set = (sl_word & (@as(u16, 1) << @intCast(sl))) != 0;
                const head = self.free_lists[fl][sl];
                if (sl_set != (head != 0)) {
                    Log.print("[tlsf] fl-inv: sl_bitmaps[{d}][{d}]={any} but head=0x{X}\n", .{ fl, sl, sl_set, head });
                    ok = false;
                    continue;
                }
                var prev: usize = 0;
                var cur: usize = head;
                while (cur != 0) {
                    visited += 1;
                    if (visited > max_visit) {
                        Log.print("[tlsf] fl-inv: bucket [{d}][{d}] over visit cap (cycle? count={d})\n", .{ fl, sl, self.free_blocks });
                        return false;
                    }
                    if (!self.inBlockSpace(cur)) {
                        Log.print("[tlsf] fl-inv: bucket [{d}][{d}] block 0x{X} outside every pool\n", .{ fl, sl, cur });
                        return false;
                    }
                    if ((cur & BLOCK_ALIGN_MASK) != 0) {
                        Log.print("[tlsf] fl-inv: bucket [{d}][{d}] block 0x{X} misaligned\n", .{ fl, sl, cur });
                        ok = false;
                    }
                    if (!blockIsFree(cur)) {
                        Log.print("[tlsf] fl-inv: bucket [{d}][{d}] block 0x{X} on freelist but THIS_FREE clear\n", .{ fl, sl, cur });
                        ok = false;
                    }
                    const sz = blockSize(cur);
                    if (sz < MIN_BLOCK_SIZE or sz > self.pools[self.poolOf(cur).?].wall() - cur) {
                        Log.print("[tlsf] fl-inv: bucket [{d}][{d}] block 0x{X} bad size {d}\n", .{ fl, sl, cur, sz });
                        return false;
                    }
                    const want = mapping(sz);
                    if (want.fl != fl or want.sl != sl) {
                        Log.print("[tlsf] fl-inv: block 0x{X} sz={d} mapped to [{d}][{d}] but is in [{d}][{d}]\n", .{ cur, sz, want.fl, want.sl, fl, sl });
                        ok = false;
                    }
                    const cur_prev = prevFreePtr(cur).*;
                    if (cur_prev != prev) {
                        Log.print("[tlsf] fl-inv: block 0x{X} prev_free=0x{X} but list-prev=0x{X}\n", .{ cur, cur_prev, prev });
                        ok = false;
                    }
                    prev = cur;
                    cur = nextFreePtr(cur).*;
                }
            }
        }

        if (visited != self.free_blocks) {
            Log.print("[tlsf] fl-inv: walked {d} blocks across all freelists but counter says {d}\n", .{ visited, self.free_blocks });
            ok = false;
        }
        return ok;
    }
};
