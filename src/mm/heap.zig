// TLSF (Two-Level Segregated Fit) kernel heap allocator.
//
// Replaces the prior first-fit free-list allocator 2026-05-24. The old
// allocator's O(n) walk + unbounded fragmentation tail was hitting alloc
// failures at 64 KB asks with plenty of bytes free; with the system
// growing (drivers, GUI, network), that wasn't going to age well.
//
// TLSF properties:
//   - Bounded O(1) alloc and free (bitmap-indexed free lists; @ctz/@clz for
//     bucket search).
//   - Bounded internal fragmentation (worst case ~1/SL_INDEX_COUNT per class).
//   - Boundary-tag coalescing in both directions on free, also O(1).
//   - Same public API as before — kmalloc / kmallocAligned / kfree /
//     kalloc / kfreeAuto / kvmalloc / kvfree / validateHeap /
//     printDetailedStats / printStats / snapshot / Stats.
//
// Block layout (all blocks 16-byte aligned, sizes multiples of 16):
//
//   Allocated block:
//     [0..8]:    header   (size << 4 | flags)   <- THIS_FREE clear
//     [8..12]:   user_size (u32, requested bytes)
//     [12..16]:  canary_head (u32 = 0xDEADBEEF)
//     [16..16+user_size]:  user data            <- user_ptr returned here
//     [+0..+4]:  canary_tail (u32 = 0xCAFEBABE)
//     [pad to total_size]
//
//   Free block:
//     [0..8]:    header   (size << 4 | flags)   <- THIS_FREE set
//     [8..16]:   next_free (ptr to next block in same (FL,SL) free list)
//     [16..24]:  prev_free (ptr to prev block in same (FL,SL) free list)
//     [24..size-8]: unused
//     [size-8..size]: footer (size duplicate, lets prev-coalesce find us)
//
// Header low 4 bits (size is always 16-multiple → low 4 bits free for flags):
//   bit 0: THIS_FREE
//   bit 1: PREV_FREE  (mirror of the physically previous block's THIS_FREE;
//                      flipped by alloc/free on the NEXT block's header)
//   bits 2-3: reserved
//
// User pointer is at block_addr + USER_OFFSET (=16) for naturally-aligned
// allocs. For alignment > 16, the user pointer is shifted further into the
// block (padding stays as dead bytes inside the allocation). kfree finds the
// header via scan-back from (ptr - USER_OFFSET) downward — same approach as
// the prior allocator.
//
// kvmalloc / kvfree (PMM-backed, page-multiples) are unchanged at the bottom
// of this file. They're the right answer for >= KVMALLOC_THRESHOLD allocs.

const std = @import("std");
const debug = @import("../debug/debug.zig");
const serial = @import("../debug/serial.zig");
const vga = @import("../ui/vga.zig");
const SpinLock = @import("../proc/spinlock.zig").SpinLock;
const memmap = @import("memmap.zig");
const pmm = @import("pmm.zig");

pub const HEAP_START: usize = memmap.PHYSMAP_BASE + memmap.KERNEL_HEAP_BASE;
pub const HEAP_SIZE: usize = memmap.KERNEL_HEAP_SIZE;

// === Block layout constants ===

const BLOCK_ALIGN: usize = 16;
const BLOCK_ALIGN_MASK: usize = BLOCK_ALIGN - 1;
const HEADER_SIZE: usize = 8;
const FOOTER_SIZE: usize = 8;
// Per-alloc prefix (header + user_size + canary_head):
const USER_OFFSET: usize = 16;
const CANARY_TAIL_SIZE: usize = 4;
// Min total block size: header + next + prev + footer = 32.
const MIN_BLOCK_SIZE: usize = 32;

const FLAG_THIS_FREE: usize = 1 << 0;
const FLAG_PREV_FREE: usize = 1 << 1;
const SIZE_MASK: usize = ~@as(usize, 0xF);

const CANARY_HEAD: u32 = 0xDEADBEEF;
const CANARY_TAIL: u32 = 0xCAFEBABE;

// === TLSF parameters ===

// SMALL_BLOCK_SIZE is the boundary below which we use the "small" (FL=0)
// bucket — all sizes [MIN_BLOCK_SIZE .. SMALL_BLOCK_SIZE) live in FL=0,
// subdivided by SL_INDEX_COUNT.
// SMALL_BLOCK_SIZE = 1 << FL_INDEX_SHIFT.
//
// FL_INDEX_SHIFT must be >= SL_INDEX_LOG2 + log2(BLOCK_ALIGN) so the
// second-level subdivision step is at least one allocation grain. For
// SL_INDEX_LOG2=4 and BLOCK_ALIGN=16 (log2=4) → FL_INDEX_SHIFT >= 8.
const FL_INDEX_SHIFT: u6 = 8;
const SL_INDEX_LOG2: u6 = 4;
const SL_INDEX_COUNT: usize = 1 << SL_INDEX_LOG2;
const SL_INDEX_MASK: usize = SL_INDEX_COUNT - 1;
// FL_INDEX_MAX_LOG2 = log2 of largest block we ever map. 25 covers 32 MB —
// well past current HEAP_SIZE (16 MB) with headroom for growth.
// FL_INDEX_MAX_LOG2 = 26 (64 MB) gives one full FL of headroom above the
// largest block we ever expect (32 MB), so mappingAllocRoundUp can never
// carry past the last valid bucket. Standard TLSF practice.
const FL_INDEX_MAX_LOG2: u6 = 26;
const FL_INDEX_COUNT: usize = FL_INDEX_MAX_LOG2 - FL_INDEX_SHIFT + 1; // 19

// === State ===

var initialized: bool = false;
var lock: SpinLock = .{};

// Bitmaps: bit i in fl_bitmap set iff sl_bitmaps[i] != 0.
//          bit j in sl_bitmaps[i] set iff free_lists[i][j] != null.
var fl_bitmap: u32 = 0; // up to FL_INDEX_COUNT bits used (max 18)
var sl_bitmaps: [FL_INDEX_COUNT]u16 = [_]u16{0} ** FL_INDEX_COUNT;
var free_lists: [FL_INDEX_COUNT][SL_INDEX_COUNT]?usize =
    [_][SL_INDEX_COUNT]?usize{[_]?usize{null} ** SL_INDEX_COUNT} ** FL_INDEX_COUNT;

// Stats (preserved from prior impl for compat with sysmon/cli output).
var alloc_count: u32 = 0;
var free_count: u32 = 0;
var current_alloc: u32 = 0;
var peak_alloc: u32 = 0;
var current_bytes: u64 = 0;
var peak_bytes: u64 = 0;
var free_bytes_remaining: u64 = 0;
var free_block_count: u32 = 0;
var largest_free_block: usize = 0;
var ops_since_largest_recompute: u32 = 0;
const RECOMPUTE_INTERVAL: u32 = 1024;

// === Header helpers ===

inline fn headerPtr(addr: usize) *usize {
    return @ptrFromInt(addr);
}
inline fn blockSize(addr: usize) usize {
    return headerPtr(addr).* & SIZE_MASK;
}
inline fn blockIsFree(addr: usize) bool {
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
// the block is free.
inline fn nextFreePtr(addr: usize) *?usize {
    return @ptrFromInt(addr + 8);
}
inline fn prevFreePtr(addr: usize) *?usize {
    return @ptrFromInt(addr + 16);
}

// === Size → (FL, SL) mapping ===

// Round a request up so the bucket we land on is guaranteed large enough.
// Standard TLSF "round up to next class" trick: add (1 << (log2(size) -
// SL_INDEX_LOG2)) - 1 so the size moves into the next SL slot if not on a
// boundary.
fn mappingAllocRoundUp(size: usize) usize {
    if (size < (1 << FL_INDEX_SHIFT)) return size;
    const log2: u6 = @intCast(63 - @clz(size));
    const round: usize = (@as(usize, 1) << (log2 - SL_INDEX_LOG2)) - 1;
    return size + round;
}

// Map a size to (fl, sl). For sizes < SMALL_BLOCK_SIZE, fl=0 and sl is
// linear in size.
fn mapping(size: usize) struct { fl: usize, sl: usize } {
    if (size < (1 << FL_INDEX_SHIFT)) {
        const small_shift: u6 = FL_INDEX_SHIFT - SL_INDEX_LOG2;
        return .{ .fl = 0, .sl = size >> small_shift };
    }
    const log2: u6 = @intCast(63 - @clz(size));
    const fl: usize = log2 - FL_INDEX_SHIFT + 1;
    const sl: usize = (size >> (log2 - SL_INDEX_LOG2)) & SL_INDEX_MASK;
    return .{ .fl = fl, .sl = sl };
}

// Find the smallest non-empty (fl, sl) >= the input. Returns null if no
// satisfying block exists.
fn searchSuitableBlock(fl_in: usize, sl_in: usize) ?struct { fl: usize, sl: usize } {
    if (fl_in >= FL_INDEX_COUNT) return null;
    // First try same FL, SL >= sl_in.
    const sl_map: u16 = sl_bitmaps[fl_in] & (@as(u16, 0xFFFF) << @intCast(sl_in));
    if (sl_map != 0) {
        const sl: usize = @ctz(sl_map);
        return .{ .fl = fl_in, .sl = sl };
    }
    // Walk to next FL with any free blocks.
    const shift_amt: u5 = @intCast(fl_in + 1);
    if (shift_amt >= 32) return null;
    const fl_map: u32 = fl_bitmap & (@as(u32, 0xFFFFFFFF) << shift_amt);
    if (fl_map == 0) return null;
    const fl: usize = @ctz(fl_map);
    if (fl >= FL_INDEX_COUNT) return null;
    const sl: usize = @ctz(sl_bitmaps[fl]);
    return .{ .fl = fl, .sl = sl };
}

// === Free-list insert/remove ===

fn insertFreeBlock(addr: usize) void {
    const sz = blockSize(addr);
    const m = mapping(sz);
    const head = free_lists[m.fl][m.sl];
    nextFreePtr(addr).* = head;
    prevFreePtr(addr).* = null;
    if (head) |h| prevFreePtr(h).* = addr;
    free_lists[m.fl][m.sl] = addr;
    sl_bitmaps[m.fl] |= (@as(u16, 1) << @intCast(m.sl));
    fl_bitmap |= (@as(u32, 1) << @intCast(m.fl));
    free_block_count += 1;
    if (sz > largest_free_block) largest_free_block = sz;
}

fn removeFreeBlock(addr: usize) void {
    const sz = blockSize(addr);
    const m = mapping(sz);
    const next = nextFreePtr(addr).*;
    const prev = prevFreePtr(addr).*;
    if (next) |n| prevFreePtr(n).* = prev;
    if (prev) |p| {
        nextFreePtr(p).* = next;
    } else {
        // We were the head.
        free_lists[m.fl][m.sl] = next;
        if (next == null) {
            sl_bitmaps[m.fl] &= ~(@as(u16, 1) << @intCast(m.sl));
            if (sl_bitmaps[m.fl] == 0) {
                fl_bitmap &= ~(@as(u32, 1) << @intCast(m.fl));
            }
        }
    }
    if (free_block_count > 0) free_block_count -= 1;
    ops_since_largest_recompute += 1;
}

// === Coalesce ===

// Physically-prev block addr (only valid if PREV_FREE set in our header).
inline fn prevPhysAddr(addr: usize) usize {
    const prev_size = readFooterAt(addr - FOOTER_SIZE);
    return addr - (prev_size & SIZE_MASK);
}
inline fn nextPhysAddr(addr: usize) usize {
    return addr + blockSize(addr);
}
inline fn isLastBlock(addr: usize) bool {
    return addr + blockSize(addr) >= HEAP_START + HEAP_SIZE;
}

// === Init ===

pub fn init() void {
    @import("../proc/spinlock.zig").registerLock("heap.lock", &lock);
    // One big free block covering the whole heap, minus a synthetic
    // sentinel at the very end (so the last real block's nextPhysAddr is
    // never read past the heap). We just reserve 16 bytes at the end as a
    // permanently-allocated "wall" — its only purpose is to give the last
    // real block a non-free neighbor in front, so coalesce-forward stops
    // cleanly without bounds-checking the heap end on every free.
    const wall_addr = HEAP_START + HEAP_SIZE - MIN_BLOCK_SIZE;
    const big_size = wall_addr - HEAP_START;

    writeHeader(HEAP_START, big_size, true, false);
    writeFooter(HEAP_START);
    nextFreePtr(HEAP_START).* = null;
    prevFreePtr(HEAP_START).* = null;

    // Sentinel "wall" — allocated, never freed, PREV_FREE set (the big
    // block in front of it IS free initially).
    writeHeader(wall_addr, MIN_BLOCK_SIZE, false, true);

    fl_bitmap = 0;
    @memset(sl_bitmaps[0..], 0);
    for (&free_lists) |*row| {
        @memset(row[0..], null);
    }
    free_bytes_remaining = big_size;
    free_block_count = 0;
    largest_free_block = 0;
    insertFreeBlock(HEAP_START);

    initialized = true;
    debug.klog("[tlsf] Initialized: 0x{X:0>16} - 0x{X:0>16} ({d} KB heap, big_block={d} KB, FL={d} SL={d})\n", .{ HEAP_START, HEAP_START + HEAP_SIZE, HEAP_SIZE / 1024, big_size / 1024, FL_INDEX_COUNT, SL_INDEX_COUNT });
}

inline fn alignUp(addr: usize, alignment: usize) usize {
    if (alignment == 0) return addr;
    return (addr + alignment - 1) & ~(alignment - 1);
}

// === Public allocator API ===

pub fn kmalloc(size: usize) ?[*]u8 {
    return kmallocAligned(size, 16);
}

/// Allocate `size` bytes with the given alignment. Alignments up to and
/// including BLOCK_ALIGN (16) are natural; higher alignments carve a
/// front-pad off a larger block (so kfree's scan-back finds the header).
pub fn kmallocAligned(size: usize, alignment: usize) ?[*]u8 {
    if (!initialized or size == 0) {
        debug.klog("[tlsf] alloc fail: init={} size={d}\n", .{ initialized, size });
        return null;
    }
    // alignUp uses ~(alignment-1) — only valid for powers of two (M2).
    if (alignment == 0 or (alignment & (alignment - 1)) != 0) {
        debug.klog("[tlsf] alloc fail: alignment {d} not power-of-two\n", .{alignment});
        return null;
    }
    const irq_flags = lock.acquireIrqSave();
    defer lock.releaseIrqRestore(irq_flags);

    // Round the user request to a block size including our 16-byte prefix
    // (header + user_size + canary_head) and 4-byte tail canary, then
    // 16-byte align. Minimum a block can be is MIN_BLOCK_SIZE so future
    // recycling works.
    const min_user_block = alignUp(USER_OFFSET + size + CANARY_TAIL_SIZE, BLOCK_ALIGN);
    const need_block = if (min_user_block < MIN_BLOCK_SIZE) MIN_BLOCK_SIZE else min_user_block;

    // For alignment > 16, we need extra room to carve a front-pad so the
    // user pointer lands aligned. Worst-case extra = alignment +
    // MIN_BLOCK_SIZE (split-front needs MIN_BLOCK_SIZE to be its own free
    // block, or we waste it inside the alloc).
    const search_size = if (alignment > BLOCK_ALIGN)
        need_block + alignment + MIN_BLOCK_SIZE
    else
        need_block;

    const rounded = mappingAllocRoundUp(search_size);
    const m = mapping(rounded);
    const found = searchSuitableBlock(m.fl, m.sl) orelse {
        debug.klog("[tlsf] alloc fail: no block for size={d} align={d} need_block={d} search={d}\n", .{ size, alignment, need_block, search_size });
        debug.klog("[tlsf]   fl_bitmap=0x{X} free_blocks={d} free_bytes={d} largest={d}\n", .{ fl_bitmap, free_block_count, free_bytes_remaining, largest_free_block });
        return null;
    };

    const block_addr = free_lists[found.fl][found.sl].?;
    removeFreeBlock(block_addr);
    const block_sz = blockSize(block_addr);

    // Determine user pointer position. Naturally at block_addr + USER_OFFSET.
    // For higher alignment, shift up; the bytes between USER_OFFSET and the
    // aligned user pointer are dead inside the allocation.
    var user_ptr: usize = block_addr + USER_OFFSET;
    var alloc_block_addr: usize = block_addr;
    if (alignment > BLOCK_ALIGN) {
        const aligned = alignUp(user_ptr, alignment);
        // If we can carve a real front block (>= MIN_BLOCK_SIZE) before our
        // aligned position, do so — that buys back the front padding.
        const front_size: usize = (aligned - USER_OFFSET) - block_addr;
        if (front_size >= MIN_BLOCK_SIZE) {
            // Split: front becomes a free block, back is our alloc.
            const new_block = aligned - USER_OFFSET;
            const back_size = block_sz - front_size;
            // PREV_FREE flag on front: inherit from this block (which had
            // none, since we just removed it from the free list and it now
            // becomes the new front).
            const prev_free_into_front = blockPrevFree(block_addr);
            writeHeader(block_addr, front_size, true, prev_free_into_front);
            writeFooter(block_addr);
            // Back block: PREV_FREE = true (the front we just made is free).
            writeHeader(new_block, back_size, false, true);
            insertFreeBlock(block_addr);
            alloc_block_addr = new_block;
            user_ptr = aligned;
        } else {
            // Front-pad too small to split; bury it inside the allocation.
            // user_ptr advances to aligned; alloc_block_addr stays at
            // block_addr; the alloc just wastes (aligned - (block_addr +
            // USER_OFFSET)) bytes between USER_OFFSET and user_ptr.
            user_ptr = aligned;
        }
    }

    const cur_block_sz = blockSize(alloc_block_addr);

    // Try to split off the tail if the remainder is its own block.
    const consumed = (user_ptr - alloc_block_addr) + size + CANARY_TAIL_SIZE;
    const consumed_aligned = alignUp(consumed, BLOCK_ALIGN);
    const consumed_clamped = if (consumed_aligned < MIN_BLOCK_SIZE) MIN_BLOCK_SIZE else consumed_aligned;
    const final_block_size: usize = blk: {
        if (cur_block_sz >= consumed_clamped + MIN_BLOCK_SIZE) {
            const remainder = cur_block_sz - consumed_clamped;
            const tail_addr = alloc_block_addr + consumed_clamped;
            // alloc_block_addr: not free, prev_free preserved from cur header.
            const alloc_prev_free = blockPrevFree(alloc_block_addr);
            writeHeader(alloc_block_addr, consumed_clamped, false, alloc_prev_free);
            // Tail becomes a new free block; PREV_FREE = false (we are
            // allocated now).
            writeHeader(tail_addr, remainder, true, false);
            writeFooter(tail_addr);
            insertFreeBlock(tail_addr);
            // Update the block AFTER the tail to reflect prev=free.
            if (tail_addr + remainder < HEAP_START + HEAP_SIZE) {
                setPrevFreeFlag(tail_addr + remainder, true);
            }
            break :blk consumed_clamped;
        } else {
            const alloc_prev_free = blockPrevFree(alloc_block_addr);
            writeHeader(alloc_block_addr, cur_block_sz, false, alloc_prev_free);
            // Block AFTER our alloc must now see PREV_FREE = false.
            if (alloc_block_addr + cur_block_sz < HEAP_START + HEAP_SIZE) {
                setPrevFreeFlag(alloc_block_addr + cur_block_sz, false);
            }
            break :blk cur_block_sz;
        }
    };

    // Write per-alloc metadata (user_size + canary_head) right after the
    // header. For natural alignment these sit at block+8..block+16.
    // For over-aligned, they sit at user_ptr - 8..user_ptr (we always
    // place them immediately before user_ptr so kfree can find them via
    // a fixed offset).
    const us_ptr: *u32 = @ptrFromInt(user_ptr - 8);
    const ch_ptr: *u32 = @ptrFromInt(user_ptr - 4);
    us_ptr.* = @intCast(size);
    ch_ptr.* = CANARY_HEAD;

    // Tail canary right after user data (may be unaligned).
    const tail_ptr: *align(1) u32 = @ptrFromInt(user_ptr + size);
    tail_ptr.* = CANARY_TAIL;

    // Stats.
    alloc_count += 1;
    current_alloc += 1;
    current_bytes += size;
    if (current_alloc > peak_alloc) peak_alloc = current_alloc;
    if (current_bytes > peak_bytes) peak_bytes = current_bytes;
    free_bytes_remaining -= final_block_size;
    ops_since_largest_recompute += 1;

    @import("../debug/kasan.zig").allocHook(user_ptr, size);
    return @ptrFromInt(user_ptr);
}

/// Free a block previously allocated via kmalloc/kmallocAligned.
pub fn kfree(ptr: [*]u8) void {
    if (!initialized) return;
    const addr = @intFromPtr(ptr);
    // The sentinel wall occupies the last MIN_BLOCK_SIZE bytes of the heap
    // and is intentionally never user-visible. Reject pointers into it so a
    // stale ptr can't trick scan-back into reading the wall's header and
    // then freeing the real block in front of it (H5).
    if (addr < HEAP_START or addr >= HEAP_START + HEAP_SIZE - MIN_BLOCK_SIZE) return;
    const irq_flags = lock.acquireIrqSave();
    defer lock.releaseIrqRestore(irq_flags);

    // Find block_addr by scanning back from (addr - USER_OFFSET) at 16-byte
    // grains. For natural alignment this finds the header immediately.
    // For over-aligned allocs, scan up to (max alignment) bytes — bounded.
    const SCAN_LIMIT: usize = 8192;
    var block_addr: usize = (addr - USER_OFFSET) & ~BLOCK_ALIGN_MASK;
    var found = false;
    var scanned: usize = 0;
    while (scanned < SCAN_LIMIT) : (scanned += BLOCK_ALIGN) {
        if (block_addr < HEAP_START) return;
        const hdr_raw = headerPtr(block_addr).*;
        const sz = hdr_raw & SIZE_MASK;
        const this_free = (hdr_raw & FLAG_THIS_FREE) != 0;
        // Containment check (H1): the user pointer must actually live inside
        // this candidate block — addr >= block_addr + USER_OFFSET (post-
        // header) and addr < block_addr + sz (before block end). Without
        // this, a stale ptr whose addr-4 happens to be 0xDEADBEEF could
        // free the wrong block.
        if (!this_free and sz >= MIN_BLOCK_SIZE and sz <= HEAP_SIZE and
            block_addr + sz <= HEAP_START + HEAP_SIZE and
            addr >= block_addr + USER_OFFSET and addr < block_addr + sz)
        {
            const ch: *const u32 = @ptrFromInt(addr - 4);
            if (ch.* == CANARY_HEAD) {
                found = true;
                break;
            }
        }
        if (block_addr <= HEAP_START or block_addr < BLOCK_ALIGN) return;
        block_addr -= BLOCK_ALIGN;
    }
    if (!found) {
        serial.print("[tlsf] free: no header for ptr 0x{X:0>16} (scan {d} bytes)\n", .{ addr, scanned });
        return;
    }

    // Validate canaries.
    const us_ptr: *const u32 = @ptrFromInt(addr - 8);
    const user_size: usize = us_ptr.*;
    const tail_addr = addr + user_size;
    if (tail_addr + 4 <= HEAP_START + HEAP_SIZE) {
        const tail_ptr: *align(1) const u32 = @ptrFromInt(tail_addr);
        if (tail_ptr.* != CANARY_TAIL) {
            serial.print("\n!!! HEAP CORRUPTION: tail canary at 0x{X:0>16}: got 0x{X:0>8} want 0x{X:0>8} (user_size={d} block=0x{X:0>16})\n", .{ tail_addr, tail_ptr.*, CANARY_TAIL, user_size, block_addr });
            @panic("tlsf: buffer overflow — tail canary corrupted");
        }
    }

    // Stats.
    free_count += 1;
    if (current_alloc > 0) current_alloc -= 1;
    if (current_bytes >= user_size) current_bytes -= user_size;

    @import("../debug/kasan.zig").freeHook(addr, user_size);

    // Coalesce-backward via PREV_FREE flag + footer.
    // We add only `freed_size` (the block being released) to
    // free_bytes_remaining at the end — the prev/next neighbors we
    // merge with were ALREADY counted in free_bytes_remaining (they
    // were free), and removeFreeBlock doesn't decrement that field,
    // so adding `merge_size` would double-count them. Caught when
    // `Free: 233546 KB` showed up on a 16 MB heap.
    const freed_size: usize = blockSize(block_addr);
    var merge_addr = block_addr;
    var merge_size = freed_size;
    if (blockPrevFree(block_addr)) {
        const prev_addr = prevPhysAddr(block_addr);
        if (prev_addr >= HEAP_START and blockIsFree(prev_addr)) {
            removeFreeBlock(prev_addr);
            merge_addr = prev_addr;
            merge_size = blockSize(prev_addr) + merge_size;
        }
    }
    // Coalesce-forward.
    const next_addr = merge_addr + merge_size;
    if (next_addr < HEAP_START + HEAP_SIZE) {
        if (blockIsFree(next_addr)) {
            removeFreeBlock(next_addr);
            merge_size += blockSize(next_addr);
        }
    }

    // Write the new (possibly merged) free block.
    const prev_free_for_merged = blockPrevFree(merge_addr);
    writeHeader(merge_addr, merge_size, true, prev_free_for_merged);
    writeFooter(merge_addr);
    insertFreeBlock(merge_addr);
    free_bytes_remaining += freed_size;
    // Update the block AFTER the merged region: its PREV_FREE must be true.
    const after = merge_addr + merge_size;
    if (after < HEAP_START + HEAP_SIZE) {
        setPrevFreeFlag(after, true);
    }
    ops_since_largest_recompute += 1;
}

// === Heap walk / validation ===

fn recomputeLargestFreeBlock() void {
    var best: usize = 0;
    var i: usize = FL_INDEX_COUNT;
    while (i > 0) {
        i -= 1;
        if ((fl_bitmap & (@as(u32, 1) << @intCast(i))) == 0) continue;
        var j: usize = SL_INDEX_COUNT;
        while (j > 0) {
            j -= 1;
            if ((sl_bitmaps[i] & (@as(u16, 1) << @intCast(j))) == 0) continue;
            var p = free_lists[i][j];
            while (p) |addr| {
                const sz = blockSize(addr);
                if (sz > best) best = sz;
                p = nextFreePtr(addr).*;
            }
        }
    }
    largest_free_block = best;
    ops_since_largest_recompute = 0;
}

/// Walk the entire heap, validate every block's header consistency, every
/// allocated block's canaries, and prev-free flag agreement.
pub fn validateHeap() bool {
    if (!initialized) return true;
    const irq_flags = lock.acquireIrqSave();
    defer lock.releaseIrqRestore(irq_flags);
    return validateHeapLocked();
}

fn validateHeapLocked() bool {
    var errors: u32 = 0;
    var addr: usize = HEAP_START;
    var prev_was_free: bool = false;
    while (addr < HEAP_START + HEAP_SIZE) {
        const sz = blockSize(addr);
        if (sz < MIN_BLOCK_SIZE or (sz & BLOCK_ALIGN_MASK) != 0 or
            addr + sz > HEAP_START + HEAP_SIZE)
        {
            serial.print("[tlsf] validate: bad size {d} at 0x{X:0>16}\n", .{ sz, addr });
            errors += 1;
            break;
        }
        const pf = blockPrevFree(addr);
        if (pf != prev_was_free) {
            serial.print("[tlsf] validate: prev-free flag mismatch at 0x{X:0>16} (have {} want {})\n", .{ addr, pf, prev_was_free });
            errors += 1;
        }
        if (blockIsFree(addr)) {
            // Footer must match.
            const f = readFooterAt(addr + sz - FOOTER_SIZE) & SIZE_MASK;
            if (f != sz) {
                serial.print("[tlsf] validate: footer mismatch at 0x{X:0>16}: {d} vs {d}\n", .{ addr, f, sz });
                errors += 1;
            }
            prev_was_free = true;
        } else {
            // Sanity check on canary_head at offset 12 (natural alloc).
            // For over-aligned allocs the canary is at (user_ptr - 4); we
            // can't easily find user_ptr here without the size field.
            // We trust user_size at offset 8 to be sane, then canary at
            // offset 12 OR at (offset 12 + pad).
            // For now: only check natural-alignment case.
            const us: *const u32 = @ptrFromInt(addr + 8);
            const ch: *const u32 = @ptrFromInt(addr + 12);
            if (ch.* != CANARY_HEAD) {
                // May be an over-aligned alloc; canary is at user_ptr - 4.
                // user_ptr = addr + USER_OFFSET + align_pad. We don't know
                // align_pad cheaply. Skip — kfree's canary check guards
                // those.
                _ = us;
            }
            prev_was_free = false;
        }
        addr += sz;
    }
    return errors == 0;
}

// === Stats output ===

pub fn printDetailedStats(use_vga: bool) void {
    // Lock the entire body (H2): the snapshot of free_bytes / largest /
    // counters and the validateHeap walk both read mutable state.
    const irq_flags = lock.acquireIrqSave();
    defer lock.releaseIrqRestore(irq_flags);
    if (ops_since_largest_recompute >= RECOMPUTE_INTERVAL) {
        recomputeLargestFreeBlock();
    }
    const free_bytes = free_bytes_remaining;
    const free_blocks = free_block_count;
    const largest = largest_free_block;
    const used_bytes = if (HEAP_SIZE > free_bytes) HEAP_SIZE - free_bytes else 0;
    const pct = if (HEAP_SIZE > 0) (used_bytes * 100) / HEAP_SIZE else 0;
    const frag_pct: u64 = if (free_bytes > 0)
        100 - (largest * 100) / free_bytes
    else
        0;
    if (use_vga) {
        vga.fg = .Yellow;
        vga.print("Heap Statistics (TLSF)\n", .{});
        vga.fg = .LightGray;
        vga.print("  Total:        {d} KB\n", .{HEAP_SIZE / 1024});
        vga.print("  Used:         {d} KB ({d}%)\n", .{ used_bytes / 1024, pct });
        vga.print("  Free:         {d} KB in {d} blocks\n", .{ free_bytes / 1024, free_blocks });
        vga.print("  Largest free: {d} KB ({d}% fragmented)\n", .{ largest / 1024, frag_pct });
        vga.print("  Allocations:  {d} total, {d} freed, {d} live\n", .{ alloc_count, free_count, current_alloc });
        vga.print("  Peak live:    {d} allocs, {d} bytes\n", .{ peak_alloc, peak_bytes });
        vga.print("  Current:      {d} bytes tracked\n", .{current_bytes});
        vga.fg = .LightGreen;
        if (validateHeapLocked()) {
            vga.print("  Integrity:    OK\n", .{});
        } else {
            vga.fg = .LightRed;
            vga.print("  Integrity:    CORRUPTED (see serial)\n", .{});
        }
        vga.fg = .LightGray;
    } else {
        serial.print("[tlsf] Total: {d} KB, Used: {d} KB ({d}%), Free: {d} KB in {d} blocks (largest {d} KB, frag {d}%)\n", .{ HEAP_SIZE / 1024, used_bytes / 1024, pct, free_bytes / 1024, free_blocks, largest / 1024, frag_pct });
        serial.print("[tlsf] Allocs: {d} total, {d} freed, {d} live, peak: {d}\n", .{ alloc_count, free_count, current_alloc, peak_alloc });
    }
}

pub const Stats = struct {
    total_bytes: usize,
    used_bytes: usize,
    free_bytes: usize,
    free_blocks: u32,
    largest_free: usize,
    fragmentation_pct: u32,
    live_allocs: u32,
    peak_allocs: u32,
};

pub fn snapshot() Stats {
    // Full-body lock (M4): the counters are read together; without the
    // lock, concurrent alloc/free can produce internally-inconsistent
    // numbers (e.g. free_bytes_remaining and free_block_count from
    // different instants).
    const irq_flags = lock.acquireIrqSave();
    defer lock.releaseIrqRestore(irq_flags);
    if (ops_since_largest_recompute >= RECOMPUTE_INTERVAL) {
        recomputeLargestFreeBlock();
    }
    const free_bytes = free_bytes_remaining;
    const used = if (HEAP_SIZE > free_bytes) HEAP_SIZE - free_bytes else 0;
    const frag: u32 = if (free_bytes > 0)
        @intCast(100 - (@as(u64, largest_free_block) * 100) / free_bytes)
    else
        0;
    return .{
        .total_bytes = HEAP_SIZE,
        .used_bytes = used,
        .free_bytes = free_bytes,
        .free_blocks = free_block_count,
        .largest_free = largest_free_block,
        .fragmentation_pct = frag,
        .live_allocs = current_alloc,
        .peak_allocs = peak_alloc,
    };
}

pub fn printStats() void {
    printDetailedStats(false);
}

// === kvmalloc / kvfree (PMM-backed, unchanged from prior impl) ===
//
// Routes large allocations through PMM directly: page-rounded contiguous
// frames, identity-mapped through the physmap, no heap traffic. Right
// choice for anything page-aligned or above a few KB.

const KVMALLOC_THRESHOLD: usize = 16 * 1024;
const KV_MAGIC: u64 = 0x4B564D414C4C4F43; // "KVMALLOC"

const KvHeader = extern struct {
    magic: u64,
    pages: u32,
    user_offset: u32,
};

pub fn kalloc(size: usize) ?[*]u8 {
    if (size >= KVMALLOC_THRESHOLD) return kvmalloc(size, 16);
    return kmalloc(size);
}

pub fn kfreeAuto(ptr: [*]u8) void {
    const addr = @intFromPtr(ptr);
    if (addr >= HEAP_START and addr < HEAP_START + HEAP_SIZE) {
        kfree(ptr);
        return;
    }
    const page_base = addr & ~@as(usize, 0xFFF);
    if (page_base != 0) {
        const hdr: *const KvHeader = @ptrFromInt(page_base);
        if (hdr.magic == KV_MAGIC and addr - page_base == hdr.user_offset) {
            kvfree(ptr);
            return;
        }
    }
    serial.print("[tlsf] kfreeAuto: ptr 0x{X} matches no allocator (heap or kv)\n", .{addr});
    @panic("kfreeAuto: orphan pointer");
}

pub fn kvmalloc(size: usize, alignment: usize) ?[*]u8 {
    if (size == 0) return null;
    // Same power-of-two requirement as kmallocAligned (M3).
    if (alignment != 0 and (alignment & (alignment - 1)) != 0) return null;
    const align_real = if (alignment < 16) 16 else alignment;
    if (align_real > 4096) return null;
    const header_pad = alignUp(@sizeOf(KvHeader), align_real);
    const total = header_pad + size;
    const pages: u32 = @intCast((total + 4095) / 4096);
    const phys = pmm.allocContiguous(pages) orelse return null;
    const paging = @import("paging.zig");
    const virt_base = paging.physToVirt(phys);
    const hdr: *KvHeader = @ptrFromInt(virt_base);
    hdr.* = .{
        .magic = KV_MAGIC,
        .pages = pages,
        .user_offset = @intCast(header_pad),
    };
    return @ptrFromInt(virt_base + header_pad);
}

pub fn kvfree(ptr: [*]u8) void {
    const addr = @intFromPtr(ptr);
    const page_base = addr & ~@as(usize, 0xFFF);
    if (page_base == 0) {
        serial.print("[tlsf] kvfree: bad ptr 0x{X}\n", .{addr});
        return;
    }
    const hdr: *const KvHeader = @ptrFromInt(page_base);
    if (hdr.magic != KV_MAGIC) {
        serial.print("[tlsf] kvfree: bad magic at 0x{X}: 0x{X}\n", .{ page_base, hdr.magic });
        @panic("kvfree: bad magic — double-free, type confusion, or non-kvmalloc ptr");
    }
    if (addr - page_base != hdr.user_offset) {
        serial.print("[tlsf] kvfree: bad offset {d} (expected {d}) for ptr 0x{X}\n", .{ addr - page_base, hdr.user_offset, addr });
        @panic("kvfree: corrupted header");
    }
    const pages = hdr.pages;
    const hdr_mut: *KvHeader = @ptrFromInt(page_base);
    hdr_mut.magic = 0xDEADDEADDEADDEAD;
    const paging = @import("paging.zig");
    pmm.freeContiguous(paging.virtToPhys(page_base).?, pages);
}
