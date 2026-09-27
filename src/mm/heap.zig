// Kernel heap: the TLSF core (tlsf.zig — block layout, free lists,
// corruption detectors, validators) over the fixed physmap window at
// KERNEL_HEAP_BASE, under one IRQ-safe spinlock. This file is the kernel
// side: the lock, the kmalloc/kfree API, stats, kasan/kdbg hooks, the
// panics on corruption, the boot self-test, and kvmalloc (PMM-backed).
//
// TLSF replaced a first-fit free-list allocator 2026-05-24: its O(n) walk
// and fragmentation tail failed 64 KB asks with plenty of bytes free.
//
// Public API: kmalloc / kmallocAligned / kfree / kalloc / kfreeAuto /
// kvmalloc / kvfree / validateHeap / validateInvariants / validateFreelists /
// printDetailedStats / printStats / snapshot / Stats / selfTest.

// Core:
const std = @import("std");
const memmap = @import("memmap.zig");
const pmm = @import("pmm.zig");
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

pub const HEAP_START: usize = memmap.PHYSMAP_BASE + memmap.KERNEL_HEAP_BASE;
pub const HEAP_SIZE: usize = memmap.KERNEL_HEAP_SIZE;
// Sentinel wall: the last MIN_BLOCK_SIZE bytes, never user-visible.
const WALL_ADDR: usize = HEAP_START + HEAP_SIZE - tlsf.MIN_BLOCK_SIZE;

comptime {
    if (HEAP_SIZE > tlsf.MAX_REGION) @compileError("KERNEL_HEAP_SIZE exceeds tlsf.MAX_REGION");
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

// Stats (sysmon/cli output).
var alloc_count: u32 = 0;
var free_count: u32 = 0;
var current_alloc: u32 = 0;
var peak_alloc: u32 = 0;
var current_bytes: u64 = 0;
var peak_bytes: u64 = 0;

pub fn init() void {
    spinlock.registerLock("heap.lock", &lock);
    core.init(HEAP_START, HEAP_SIZE);
    initialized = true;
    debug.klog("[tlsf] Initialized: 0x{X:0>16} - 0x{X:0>16} ({d} KB heap, big_block={d} KB, FL={d} SL={d})\n", .{ HEAP_START, HEAP_START + HEAP_SIZE, HEAP_SIZE / 1024, core.free_bytes / 1024, tlsf.FL_INDEX_COUNT, tlsf.SL_INDEX_COUNT });
}

inline fn alignUp(addr: usize, alignment: usize) usize {
    return (addr + alignment - 1) & ~(alignment - 1);
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
    if (size > HEAP_SIZE or alignment > HEAP_SIZE) {
        debug.klog("[tlsf] alloc fail: size={d} align={d} exceeds heap ({d})\n", .{ size, alignment, HEAP_SIZE });
        return null;
    }
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
            // Logged after the unlock: serial output with IRQs off stalls
            // every CPU that wants the heap.
            debug.klog("[tlsf] alloc fail: no block for size={d} align={d} need_block={d} search={d}\n", .{ size, alignment, o.need_block, o.search });
            debug.klog("[tlsf]   fl_bitmap=0x{X} free_blocks={d} free_bytes={d} largest={d}\n", .{ o.fl_bitmap, o.free_blocks, o.free_bytes, o.largest });
            return null;
        },
    }
}

/// Free a block previously allocated via kmalloc/kmallocAligned.
pub fn kfree(ptr: [*]u8) void {
    if (!initialized) return;
    const addr = @intFromPtr(ptr);
    // Pointers into the wall are rejected too, so a stale ptr can't trick
    // scan-back into reading the wall's header and freeing the real block
    // in front of it (H5).
    if (addr < HEAP_START or addr >= WALL_ADDR) {
        const ra = @returnAddress();
        if (@import("../debug/symbols.zig").resolveKernelNearest(@as(u64, ra))) |sym| {
            serial.print("[tlsf] kfree: ptr 0x{X} outside the heap — ignored (caller {s}+0x{X})\n", .{ addr, sym.name, sym.offset });
        } else {
            serial.print("[tlsf] kfree: ptr 0x{X} outside the heap — ignored (caller RA 0x{X})\n", .{ addr, ra });
        }
        return;
    }
    const irq_flags = lock.acquireIrqSave();

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

    core.release(block_addr, addr) catch corruptPanic(irq_flags);
    lock.releaseIrqRestore(irq_flags);
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
    const free_bytes = core.free_bytes;
    const free_blocks = core.free_blocks;
    const largest = core.largest_free;
    const used_bytes = if (HEAP_SIZE > free_bytes) HEAP_SIZE - free_bytes else 0;
    const pct = if (HEAP_SIZE > 0) (used_bytes * 100) / HEAP_SIZE else 0;
    const frag_pct = fragPct(largest, free_bytes);
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
    // Full-body lock (M4): the counters are read together; unlocked,
    // concurrent alloc/free could mix values from different instants.
    const irq_flags = lock.acquireIrqSave();
    defer lock.releaseIrqRestore(irq_flags);
    core.recomputeLargestFreeBlock();
    const free_bytes = core.free_bytes;
    return .{
        .total_bytes = HEAP_SIZE,
        .used_bytes = if (HEAP_SIZE > free_bytes) HEAP_SIZE - free_bytes else 0,
        .free_bytes = free_bytes,
        .free_blocks = core.free_blocks,
        .largest_free = core.largest_free,
        .fragmentation_pct = fragPct(core.largest_free, free_bytes),
        .live_allocs = current_alloc,
        .peak_allocs = peak_alloc,
    };
}

pub fn printStats() void {
    printDetailedStats(false);
}

// === kvmalloc / kvfree (PMM-backed) ===
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
    // The KvHeader lives at the start of the page containing (addr - 1) —
    // NOT the page containing addr: a 4096-aligned kvmalloc places the user
    // pointer exactly one page past the header, and `addr & ~0xFFF` would
    // land on the user's own first page and read their data as a header
    // (legit free → "orphan pointer" panic).
    if (addr != 0) {
        const page_base = (addr - 1) & ~@as(usize, 0xFFF);
        if (page_base != 0) {
            const hdr: *const KvHeader = @ptrFromInt(page_base);
            if (hdr.magic == KV_MAGIC and addr - page_base == hdr.user_offset) {
                kvfree(ptr);
                return;
            }
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
    // 4096 is the hard ceiling: kvfree finds the header at the start of the
    // page containing (user_ptr - 1), which only works while the header pad
    // is at most one page.
    if (align_real > 4096) return null;
    const header_pad = alignUp(@sizeOf(KvHeader), align_real);
    const total = header_pad + size;
    const pages: u32 = @intCast((total + 4095) / 4096);
    const phys = pmm.allocContiguous(pages) orelse return null;
    const virt_base = phys.toVirt().raw();
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
    // Header page = the page containing (addr - 1). See kfreeAuto for why
    // this is NOT `addr & ~0xFFF`: a 4096-aligned kvmalloc puts the user
    // pointer exactly one page past the header.
    if (addr == 0) {
        serial.print("[tlsf] kvfree: bad ptr 0x{X}\n", .{addr});
        return;
    }
    const page_base = (addr - 1) & ~@as(usize, 0xFFF);
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
    pmm.freeContiguous(Phys.of(paging.virtToPhys(page_base).?), pages);
}
