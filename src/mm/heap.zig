// Kernel heap: the TLSF core (tlsf.zig — block layout, free lists,
// corruption detectors, validators) over pools of PMM frames reached
// through the physmap, under one IRQ-safe spinlock. This file is the kernel
// side: where pools come from, the lock, the kmalloc/kfree API, stats,
// kasan/kdbg hooks, the panics on corruption, the boot self-test, and
// kvmalloc (vmalloc-backed).
//
// Pools: BASE_POOL_BYTES at init, kept for good; on OOM a GROW_BYTES pool
// (bigger for one large request) is taken from PMM outside the lock. A
// grown pool that empties goes back to PMM unless it is the only empty one.
//
// TLSF replaced a first-fit free-list allocator 2026-05-24: its O(n) walk
// and fragmentation tail failed 64 KB asks with plenty of bytes free.
//
// Public API: kmalloc / kmallocAligned / kfree / kalloc / kfreeAuto /
// kvmalloc / kvfree / contains / validateHeap / validateInvariants /
// validateFreelists / printDetailedStats / printStats / snapshot / Stats /
// selfTest.

// Core:
const std = @import("std");
const pmm = @import("pmm.zig");
const vmalloc = @import("vmalloc.zig");
const paging = @import("paging.zig");
const tlsf = @import("tlsf.zig");
const Phys = @import("../util/addr.zig").Phys;
const spinlock = @import("../proc/spinlock.zig");
const SpinLock = spinlock.SpinLock;
// Diagnostics:
const debug = @import("../debug/debug.zig");
const serial = @import("../debug/serial.zig");
const vga = @import("../ui/vga.zig");
const kasan = @import("../debug/kasan.zig");
const kdbg = @import("../debug/kdbg.zig");
const layout = @import("../debug/layout.zig");

const BASE_POOL_BYTES: usize = 2 * 1024 * 1024;
const GROW_BYTES: usize = 2 * 1024 * 1024;
/// Largest single kmalloc; bigger buffers belong in vmalloc.
pub const MAX_ALLOC: usize = 8 * 1024 * 1024;

comptime {
    // A pool sized for MAX_ALLOC at the largest alignment must fit one pool.
    if (poolBytesFor(tlsf.mappingAllocRoundUp(MAX_ALLOC + MAX_ALLOC + 2 * tlsf.MIN_BLOCK_SIZE + 64)) > tlsf.MAX_REGION)
        @compileError("MAX_ALLOC too large for tlsf.MAX_REGION");
    if (BASE_POOL_BYTES % 4096 != 0 or GROW_BYTES % 4096 != 0) @compileError("pools are whole frames");
    // Hand-overlaid block storage: if any field widens, the user pointer /
    // free-list math breaks silently (the 2026-05-28 `?usize` link overlap
    // — see debug/layout.zig).
    layout.assertFieldsExactFill(&.{
        .{ .name = "header",      .offset = 0,  .size = tlsf.HEADER_SIZE },
        .{ .name = "user_size",   .offset = 8,  .size = @sizeOf(u32) },
        .{ .name = "canary_head", .offset = 12, .size = @sizeOf(u32) },
    }, tlsf.USER_OFFSET);
    layout.assertFieldsNonOverlap(&.{
        .{ .name = "header",    .offset = 0,                         .size = tlsf.HEADER_SIZE },
        .{ .name = "next_free", .offset = 8,                         .size = @sizeOf(@TypeOf(tlsf.nextFreePtr(0).*)) },
        .{ .name = "prev_free", .offset = 16,                        .size = @sizeOf(@TypeOf(tlsf.prevFreePtr(0).*)) },
        .{ .name = "footer",    .offset = tlsf.MIN_BLOCK_SIZE - 8,   .size = tlsf.FOOTER_SIZE },
    }, tlsf.MIN_BLOCK_SIZE);
}

// === State ===

var initialized: bool = false;
var lock: SpinLock = .{};
var core: tlsf.Tlsf = undefined;
/// The pool init() took; never handed back.
var base_pool_start: usize = 0;

// Stats (sysmon/cli output).
var alloc_count: u32 = 0;
var free_count: u32 = 0;
var current_alloc: u32 = 0;
var peak_alloc: u32 = 0;
var current_bytes: u64 = 0;
var peak_bytes: u64 = 0;
var pools_grown: u32 = 0;
var pools_returned: u32 = 0;

/// After pmm.init: the base pool comes from PMM.
pub fn init() void {
    spinlock.registerLock("heap.lock", &lock);
    core.init();
    const phys = pmm.allocContiguous(BASE_POOL_BYTES / 4096) orelse @panic("heap: no frames for the base pool");
    base_pool_start = phys.toVirt().raw();
    if (!core.addPool(base_pool_start, BASE_POOL_BYTES)) unreachable;
    initialized = true;
    debug.klog("[tlsf] Initialized: base pool 0x{X:0>16} ({d} KB), grows by {d} KB pools from PMM (FL={d} SL={d})\n", .{ base_pool_start, BASE_POOL_BYTES / 1024, GROW_BYTES / 1024, tlsf.FL_INDEX_COUNT, tlsf.SL_INDEX_COUNT });
}

inline fn alignUp(addr: usize, alignment: usize) usize {
    return (addr + alignment - 1) & ~(alignment - 1);
}

/// A pool whose one free block serves a search of `search` bytes (already
/// rounded to its class by tlsf.mappingAllocRoundUp).
fn poolBytesFor(search: usize) usize {
    return @max(GROW_BYTES, alignUp(search + tlsf.MIN_BLOCK_SIZE, GROW_BYTES));
}

/// Take a pool from PMM for an allocation that searched `search` bytes and
/// add it to the core. Called without the heap lock: PMM has its own. When
/// PMM is too fragmented for a GROW_BYTES run, a pool of just the pages this
/// request needs still lets it through. True when the caller should retry.
fn grow(search: usize) bool {
    const rounded = tlsf.mappingAllocRoundUp(search);
    var bytes = poolBytesFor(rounded);
    const phys = pmm.allocContiguous(@intCast(bytes / 4096)) orelse blk: {
        const least = alignUp(rounded + tlsf.MIN_BLOCK_SIZE, 4096);
        debug.klog("[tlsf] grow: PMM has no {d} KB run, trying {d} KB\n", .{ bytes / 1024, least / 1024 });
        bytes = least;
        break :blk pmm.allocContiguous(@intCast(bytes / 4096)) orelse {
            debug.klog("[tlsf] grow: PMM has no {d} KB run either\n", .{bytes / 1024});
            return false;
        };
    };
    const pages: u32 = @intCast(bytes / 4096);
    const start = phys.toVirt().raw();
    const irq_flags = lock.acquireIrqSave();
    // A CPU that hit the same OOM may have grown the heap meanwhile; a
    // second pool would sit empty, never emptied by a free to hand back.
    const raced = core.canServe(search);
    const added = !raced and core.addPool(start, bytes);
    if (added) pools_grown += 1;
    const pools = core.pool_count;
    const total = core.total_bytes;
    lock.releaseIrqRestore(irq_flags);
    if (raced) {
        pmm.freeContiguous(phys, pages);
        return true;
    }
    if (!added) {
        pmm.freeContiguous(phys, pages);
        debug.klog("[tlsf] grow: pool table full ({d} pools)\n", .{tlsf.MAX_POOLS});
        return false;
    }
    debug.klog("[tlsf] grew: +{d} KB pool at 0x{X:0>16} for a {d}-byte search ({d} pools, {d} KB)\n", .{ bytes / 1024, start, search, pools, total / 1024 });
    return true;
}

/// Pool `pi` just emptied. The base pool and one empty grown pool stay (so
/// an alloc/free pair at a pool's edge doesn't bounce frames through PMM);
/// any other comes out of the core for the caller to hand back.
fn takeSurplusPool(pi: u32) tlsf.Corrupt!?tlsf.Pool {
    if (core.pools[pi].start == base_pool_start) return null;
    var empty_grown: u32 = 0;
    for (core.pools[0..core.pool_count], 0..) |p, i| {
        if (p.start != base_pool_start and core.poolIsEmpty(@intCast(i))) empty_grown += 1;
    }
    if (empty_grown <= 1) return null;
    pools_returned += 1;
    return try core.removePool(pi);
}

/// Return a pool taken out by takeSurplusPool. Without the heap lock.
fn givePoolBack(p: tlsf.Pool) void {
    const pages: u32 = @intCast(p.size / 4096);
    pmm.freeContiguous(Phys.of(paging.virtToPhys(p.start).?), pages);
    debug.klog("[tlsf] returned: {d} KB pool at 0x{X:0>16} to PMM\n", .{ p.size / 1024, p.start });
}

/// The heap pool holding `addr`, read WITHOUT the lock — for diagnostics
/// that may run while the lock is held (panic autopsy). A racing pool
/// change can make the answer stale, never unsafe: only the table is read.
pub fn poolForDiag(addr: usize) ?tlsf.Pool {
    if (!initialized) return null;
    const i = core.poolOf(addr) orelse return null;
    return core.pools[i];
}

/// `addr` is inside a heap pool, before its wall.
pub fn contains(addr: usize) bool {
    if (!initialized) return false;
    const irq_flags = lock.acquireIrqSave();
    defer lock.releaseIrqRestore(irq_flags);
    return core.inBlockSpace(addr);
}

/// Report structural corruption the core stopped at (core.fault), drop the
/// lock and panic. Releasing first keeps the lock-dump autopsy clean: Zig's
/// @panic does not unwind, so a deferred release would never run.
fn corruptPanic(irq_flags: u64) noreturn {
    switch (core.fault) {
        .links => |f| {
            serial.print("\n!!! HEAP CORRUPTION: free block 0x{X:0>16} links next=0x{X} prev=0x{X} don't point back (use-after-free write?)\n", .{ f.block, f.next, f.prev });
            kdbg.attributeHeapCorruptor(f.block + 8);
            lock.releaseIrqRestore(irq_flags);
            @panic("tlsf: free-list links corrupted");
        },
        .footer => |f| {
            serial.print("\n!!! HEAP CORRUPTION: footer before 0x{X:0>16} decodes to prev=0x{X:0>16}\n", .{ f.block, f.prev });
            kdbg.attributeHeapCorruptor(f.block - tlsf.FOOTER_SIZE);
            lock.releaseIrqRestore(irq_flags);
            @panic("tlsf: prev-block footer corrupted — heap underflow");
        },
        .size => |f| {
            serial.print("\n!!! HEAP CORRUPTION: free block 0x{X:0>16} claims size {d}, which its pool can't hold (overflow from below?)\n", .{ f.block, f.size });
            kdbg.attributeHeapCorruptor(f.block);
            lock.releaseIrqRestore(irq_flags);
            @panic("tlsf: free block size corrupted");
        },
    }
}

// === Public allocator API ===

pub fn kmalloc(size: usize) ?[*]u8 {
    return kmallocAligned(size, 16);
}

/// Allocate `size` bytes with the given alignment. Alignments up to and
/// including 16 are natural; higher alignments carve a front pad off a
/// larger block (so kfree's scan-back finds the header).
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
    // Reject absurd requests up front: nothing past this point can succeed,
    // and the size arithmetic (prefix sums, the u32 user_size store) would
    // otherwise trip ReleaseSafe overflow panics instead of log + null.
    if (size > MAX_ALLOC or alignment > MAX_ALLOC) {
        debug.klog("[tlsf] alloc fail: size={d} align={d} exceeds MAX_ALLOC ({d})\n", .{ size, alignment, MAX_ALLOC });
        return null;
    }
    var grown: u32 = 0;
    while (true) {
        const irq_flags = lock.acquireIrqSave();
        const r = core.alloc(size, alignment) catch corruptPanic(irq_flags);
        if (r == .ok) {
            alloc_count += 1;
            current_alloc += 1;
            current_bytes += size;
            if (current_alloc > peak_alloc) peak_alloc = current_alloc;
            if (current_bytes > peak_bytes) peak_bytes = current_bytes;
            kasan.allocHook(r.ok, size);
        }
        lock.releaseIrqRestore(irq_flags);
        switch (r) {
            .ok => |user_ptr| return @ptrFromInt(user_ptr),
            .oom => |o| {
                // Another CPU can use up a new pool before the retry: two
                // tries, then give up.
                if (grown < 2 and grow(o.search)) {
                    grown += 1;
                    continue;
                }
                // Logged after the unlock: serial output with IRQs off stalls
                // every CPU that wants the heap.
                debug.klog("[tlsf] alloc fail: no block for size={d} align={d} need_block={d} search={d}\n", .{ size, alignment, o.need_block, o.search });
                debug.klog("[tlsf]   fl_bitmap=0x{X} free_blocks={d} free_bytes={d} largest={d}\n", .{ o.fl_bitmap, o.free_blocks, o.free_bytes, o.largest });
                return null;
            },
        }
    }
}

/// Free a block previously allocated via kmalloc/kmallocAligned.
pub fn kfree(ptr: [*]u8) void {
    if (!initialized) return;
    const addr = @intFromPtr(ptr);
    const irq_flags = lock.acquireIrqSave();
    // Pointers into a wall are rejected too, so a stale ptr can't trick
    // scan-back into reading the wall's header and freeing the real block
    // in front of it (H5). Checked under the lock: pools come and go.
    if (!core.inBlockSpace(addr)) {
        lock.releaseIrqRestore(irq_flags);
        const ra = @returnAddress();
        if (@import("../debug/symbols.zig").resolveKernelNearest(@as(u64, ra))) |sym| {
            serial.print("[tlsf] kfree: ptr 0x{X} outside the heap — ignored (caller {s}+0x{X})\n", .{ addr, sym.name, sym.offset });
        } else {
            serial.print("[tlsf] kfree: ptr 0x{X} outside the heap — ignored (caller RA 0x{X})\n", .{ addr, ra });
        }
        return;
    }

    // Each @panic below releases the lock first — see corruptPanic.
    const block_addr = switch (core.locate(addr)) {
        .block => |b| b,
        .double_free => {
            serial.print("\n!!! HEAP: double free of ptr 0x{X:0>16}\n", .{addr});
            kdbg.attributeHeapCorruptor(addr);
            lock.releaseIrqRestore(irq_flags);
            @panic("tlsf: double free");
        },
        .wild => {
            // No live block starts here: kfree(p + offset), a stack/static
            // pointer, or a block already reused after its free. A real
            // kernel bug either way — loud, like every heap-corruption class.
            serial.print("[tlsf] free: no header for ptr 0x{X:0>16}\n", .{addr});
            // Auto-bisect — what alloc/free events touched this frame
            // recently? Often "the kernel heap tore through whoever owns
            // this page".
            kdbg.attributeHeapCorruptor(addr);
            lock.releaseIrqRestore(irq_flags);
            @panic("tlsf: kfree on non-heap or non-block-aligned pointer");
        },
    };

    const user_size = tlsf.Tlsf.userSize(addr);
    if (core.tailFault(block_addr, addr)) |f| {
        switch (f) {
            .size_overflows_block => serial.print("\n!!! HEAP CORRUPTION: user_size={d} overflows block 0x{X:0>16} (size {d}, ptr 0x{X:0>16})\n", .{ user_size, block_addr, tlsf.blockSize(block_addr), addr }),
            .canary => serial.print("\n!!! HEAP CORRUPTION: tail canary at 0x{X:0>16}: got 0x{X:0>8} want 0x{X:0>8} (user_size={d} block=0x{X:0>16})\n", .{ addr + user_size, @as(*align(1) const u32, @ptrFromInt(addr + user_size)).*, tlsf.CANARY_TAIL, user_size, block_addr }),
        }
        // Auto-bisect: the most-recent alloc/free for this frame and a
        // window-event count, so the strongest culprit shows immediately.
        kdbg.attributeHeapCorruptor(if (f == .canary) addr + user_size else addr - 8);
        lock.releaseIrqRestore(irq_flags);
        @panic(if (f == .canary) "tlsf: buffer overflow — tail canary corrupted" else "tlsf: user_size corrupted");
    }

    free_count += 1;
    if (current_alloc > 0) current_alloc -= 1;
    if (current_bytes >= user_size) current_bytes -= user_size;
    kasan.freeHook(addr, user_size);

    const emptied = core.release(block_addr, addr) catch corruptPanic(irq_flags);
    const surplus = if (emptied) |pi| takeSurplusPool(pi) catch corruptPanic(irq_flags) else null;
    lock.releaseIrqRestore(irq_flags);
    if (surplus) |p| givePoolBack(p);
}

// === Validation ===

/// Walk the entire heap, validate every block's header consistency, every
/// allocated block's canaries, and prev-free flag agreement.
pub fn validateHeap() bool {
    if (!initialized) return true;
    const irq_flags = lock.acquireIrqSave();
    defer lock.releaseIrqRestore(irq_flags);
    return core.validateBlocks(serial);
}

/// Re-derive the free-pool counters from a full block walk and compare with
/// the incrementally-maintained ones. Catches counter drift that is silent
/// until someone notices a weird number (the 2026-05-24 double count
/// reported Free: 233546 KB on a 16 MB heap).
pub fn validateInvariants() bool {
    if (!initialized) return true;
    const irq_flags = lock.acquireIrqSave();
    defer lock.releaseIrqRestore(irq_flags);
    return core.validateCounters(serial);
}

/// Walk every free list: links, THIS_FREE, bucket membership, back-links,
/// bitmaps, visit count vs the counter.
pub fn validateFreelists() bool {
    if (!initialized) return true;
    const irq_flags = lock.acquireIrqSave();
    defer lock.releaseIrqRestore(irq_flags);
    return core.validateFreelists(serial);
}

/// Boot self-test of kfree's corruption detectors. Probes locate, tailFault
/// and linksIntact directly, so nothing panics; every probe that writes
/// restores the byte before the lock drops.
pub fn selfTest() void {
    const a = kmalloc(48) orelse return selfTestFail("kmalloc a");
    const b = kmalloc(48) orelse return selfTestFail("kmalloc b");
    const c = kmalloc(48) orelse return selfTestFail("kmalloc c");
    @memset(c[0..48], 0); // no stale header/canary bytes in c's user area
    kfree(a);
    kfree(b); // after a: merges backward when the two are neighbours
    const pa = @intFromPtr(a);
    const pb = @intFromPtr(b);
    const pc = @intFromPtr(c);

    const bad: ?[]const u8 = blk: {
        const flags = lock.acquireIrqSave();
        defer lock.releaseIrqRestore(flags);
        if (core.locate(pb) != .double_free) break :blk "second free of b not caught";
        if (core.locate(pa) != .double_free) break :blk "second free of a not caught";
        const lc = core.locate(pc);
        if (lc != .block) break :blk "live c not located";
        if (core.locate(pc + 16) != .wild) break :blk "interior pointer not wild";

        const cb = lc.block;
        const us: *u32 = @ptrFromInt(pc - 8);
        const saved_us = us.*;
        us.* = 0x10000;
        const f_size = core.tailFault(cb, pc);
        us.* = saved_us;
        if (f_size == null or f_size.? != .size_overflows_block) break :blk "oversized user_size passed";
        const tail: *align(1) u32 = @ptrFromInt(pc + 48);
        const saved_tail = tail.*;
        tail.* = saved_tail ^ 1;
        const f_tail = core.tailFault(cb, pc);
        tail.* = saved_tail;
        if (f_tail == null or f_tail.? != .canary) break :blk "tail canary flip passed";
        if (core.tailFault(cb, pc) != null) break :blk "intact c reported corrupt";

        // Any listed free block (a's run at least is one).
        if (core.fl_bitmap == 0) break :blk "no free block listed";
        const fl: usize = @ctz(core.fl_bitmap);
        const fb = core.free_lists[fl][@ctz(core.sl_bitmaps[fl])];
        if (!core.linksIntact(fb)) break :blk "intact links reported corrupt";
        const saved_prev = tlsf.prevFreePtr(fb).*;
        tlsf.prevFreePtr(fb).* = fb; // a UAF write of the block's own address
        const links_caught = !core.linksIntact(fb);
        tlsf.prevFreePtr(fb).* = saved_prev;
        if (!links_caught) break :blk "corrupt prev link passed";
        break :blk null;
    };
    kfree(c);
    if (bad) |what| return selfTestFail(what);
    if (!validateHeap() or !validateInvariants() or !validateFreelists()) return selfTestFail("heap validators after the test");
    debug.klog("[tlsf] self-test: double free (merged + heading its run), wild interior pointer, user_size bound, tail canary, free-list links — VERIFIED\n", .{});
}

fn selfTestFail(what: []const u8) void {
    debug.klog("[tlsf] self-test: FAIL — {s}\n", .{what});
}

// === Stats output ===

/// Fragmentation % = share of free bytes outside the largest free block.
/// Guarded so an inflated `largest` can never underflow the subtraction.
fn fragPct(largest: usize, free_bytes: u64) u32 {
    if (free_bytes == 0) return 0;
    const ratio = (@as(u64, largest) * 100) / free_bytes;
    if (ratio >= 100) return 0;
    return @intCast(100 - ratio);
}

pub fn printDetailedStats(use_vga: bool) void {
    // Lock the entire body (H2): the counter snapshot and the validator
    // walks both read mutable state.
    const irq_flags = lock.acquireIrqSave();
    defer lock.releaseIrqRestore(irq_flags);
    // largest_free is an upper bound between recomputes; displays want the
    // real value. O(free_blocks), trivial for an observability path.
    core.recomputeLargestFreeBlock();
    const total = core.total_bytes;
    const free_bytes = core.free_bytes;
    const free_blocks = core.free_blocks;
    const largest = core.largest_free;
    const used_bytes = if (total > free_bytes) total - free_bytes else 0;
    const pct = if (total > 0) (used_bytes * 100) / total else 0;
    const frag_pct = fragPct(largest, free_bytes);
    if (use_vga) {
        vga.fg = .Yellow;
        vga.print("Heap Statistics (TLSF)\n", .{});
        vga.fg = .LightGray;
        vga.print("  Total:        {d} KB in {d} pools ({d} grown, {d} returned)\n", .{ total / 1024, core.pool_count, pools_grown, pools_returned });
        vga.print("  Used:         {d} KB ({d}%)\n", .{ used_bytes / 1024, pct });
        vga.print("  Free:         {d} KB in {d} blocks\n", .{ free_bytes / 1024, free_blocks });
        vga.print("  Largest free: {d} KB ({d}% fragmented)\n", .{ largest / 1024, frag_pct });
        vga.print("  Allocations:  {d} total, {d} freed, {d} live\n", .{ alloc_count, free_count, current_alloc });
        vga.print("  Peak live:    {d} allocs, {d} bytes\n", .{ peak_alloc, peak_bytes });
        vga.print("  Current:      {d} bytes tracked\n", .{current_bytes});
        vga.fg = .LightGreen;
        if (core.validateBlocks(serial)) {
            vga.print("  Integrity:    OK\n", .{});
        } else {
            vga.fg = .LightRed;
            vga.print("  Integrity:    CORRUPTED (see serial)\n", .{});
        }
        if (core.validateCounters(serial)) {
            vga.fg = .LightGreen;
            vga.print("  Invariants:   OK\n", .{});
        } else {
            vga.fg = .LightRed;
            vga.print("  Invariants:   MISMATCH (see serial)\n", .{});
        }
        vga.fg = .LightGray;
    } else {
        serial.print("[tlsf] Total: {d} KB in {d} pools ({d} grown, {d} returned), Used: {d} KB ({d}%), Free: {d} KB in {d} blocks (largest {d} KB, frag {d}%)\n", .{ total / 1024, core.pool_count, pools_grown, pools_returned, used_bytes / 1024, pct, free_bytes / 1024, free_blocks, largest / 1024, frag_pct });
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
    pools: u32,
    pools_grown: u32,
    pools_returned: u32,
};

pub fn snapshot() Stats {
    // Full-body lock (M4): the counters are read together; unlocked,
    // concurrent alloc/free could mix values from different instants.
    const irq_flags = lock.acquireIrqSave();
    defer lock.releaseIrqRestore(irq_flags);
    core.recomputeLargestFreeBlock();
    const total = core.total_bytes;
    const free_bytes = core.free_bytes;
    return .{
        .total_bytes = total,
        .used_bytes = if (total > free_bytes) total - free_bytes else 0,
        .free_bytes = free_bytes,
        .free_blocks = core.free_blocks,
        .largest_free = core.largest_free,
        .fragmentation_pct = fragPct(core.largest_free, free_bytes),
        .live_allocs = current_alloc,
        .peak_allocs = peak_alloc,
        .pools = core.pool_count,
        .pools_grown = pools_grown,
        .pools_returned = pools_returned,
    };
}

pub fn printStats() void {
    printDetailedStats(false);
}

// === kvmalloc / kvfree (vmalloc-backed) ===
//
// Large buffers go to vmalloc: whole pages mapped virtually contiguous over
// scattered frames, so they need neither a contiguous PMM run nor room in a
// heap pool. CPU-only memory — nothing here may be handed to a device.
// Freeing one waits for a TLB flush on every CPU: kvfree, and kfreeAuto on
// a kalloc of KVMALLOC_THRESHOLD or more, need interrupts on and no
// spinlock held (see vmalloc.free).

const KVMALLOC_THRESHOLD: usize = 16 * 1024;

pub fn kalloc(size: usize) ?[*]u8 {
    if (size >= KVMALLOC_THRESHOLD) return kvmalloc(size);
    return kmalloc(size);
}

pub fn kfreeAuto(ptr: [*]u8) void {
    const addr = @intFromPtr(ptr);
    if (vmalloc.contains(addr)) return kvfree(ptr);
    if (contains(addr)) return kfree(ptr);
    serial.print("[tlsf] kfreeAuto: ptr 0x{X} matches no allocator (heap or vmalloc)\n", .{addr});
    @panic("kfreeAuto: orphan pointer");
}

/// `size` bytes, 16-aligned, from vmalloc.
pub fn kvmalloc(size: usize) ?[*]u8 {
    return vmalloc.alloc(size);
}

pub fn kvfree(ptr: [*]u8) void {
    vmalloc.free(ptr);
}
