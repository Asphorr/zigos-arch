const debug = @import("../debug/debug.zig");
const serial = @import("../debug/serial.zig");
const vga = @import("../ui/vga.zig");
const SpinLock = @import("../proc/spinlock.zig").SpinLock;
const memmap = @import("memmap.zig");

// Heap lives at phys 0x800000 (memmap.KERNEL_HEAP_BASE) but the kernel
// addresses it through the physmap window (PML4[256]). HEAP_START is the
// VA, the PMM reservation in pmm.zig still uses the phys base. Without the
// physmap translation, every heap access would depend on PML4[0] (the
// legacy low identity) staying alive — which Phase 3 drops.
pub const HEAP_START: usize = memmap.PHYSMAP_BASE + memmap.KERNEL_HEAP_BASE;
pub const HEAP_SIZE: usize = memmap.KERNEL_HEAP_SIZE;

const FreeBlock = struct {
    size: usize,
    next: ?*FreeBlock,
};

// Allocation header: overlaps same 16 bytes as FreeBlock
const AllocHeader = struct {
    total_size: usize, // offset 0: same position as FreeBlock.size (backward scan works)
    user_size: u32, // offset 8: actual requested size
    canary_head: u32, // offset 12: 0xDEADBEEF
};

const CANARY_HEAD: u32 = 0xDEADBEEF;
const CANARY_TAIL: u32 = 0xCAFEBABE;

var initialized: bool = false;
var free_head: ?*FreeBlock = null;
var lock: SpinLock = .{};

// Statistics
var alloc_count: u32 = 0;
var free_count: u32 = 0;
var current_alloc: u32 = 0;
var peak_alloc: u32 = 0;
var current_bytes: u64 = 0;
var peak_bytes: u64 = 0;

// Incrementally-maintained free-list summary. Keeps printDetailedStats /
// printStats / snapshot O(1) instead of walking the whole list per call —
// the old code did an O(blocks) walk per stat read. largest_free_block is a
// conservative upper bound between recomputes; lazy refresh kicks in once
// every RECOMPUTE_INTERVAL ops to correct any drift.
var free_bytes_remaining: u64 = 0;
var free_block_count: u32 = 0;
var largest_free_block: usize = 0;
var ops_since_largest_recompute: u32 = 0;
const RECOMPUTE_INTERVAL: u32 = 1024;

pub fn init() void {
    @import("../proc/spinlock.zig").registerLock("heap.lock", &lock);
    const block: *FreeBlock = @ptrFromInt(HEAP_START);
    block.size = HEAP_SIZE;
    block.next = null;
    free_head = block;
    free_bytes_remaining = HEAP_SIZE;
    free_block_count = 1;
    largest_free_block = HEAP_SIZE;
    initialized = true;
    debug.klog("[heap] Initialized: 0x{X:0>8} - 0x{X:0>8} ({d} KB)\n", .{ HEAP_START, HEAP_START + HEAP_SIZE, HEAP_SIZE / 1024 });
}

fn recomputeLargestFreeBlock() void {
    var best: usize = 0;
    var fb = free_head;
    while (fb) |f| {
        if (f.size > best) best = f.size;
        fb = f.next;
    }
    largest_free_block = best;
    ops_since_largest_recompute = 0;
}

/// Allocate `size` bytes from the kernel heap using first-fit.
pub fn kmalloc(size: usize) ?[*]u8 {
    return kmallocAligned(size, 4);
}

/// Allocate `size` bytes with specified alignment.
pub fn kmallocAligned(size: usize, alignment: usize) ?[*]u8 {
    if (!initialized or size == 0) {
        debug.klog("[heap] alloc fail: init={} size={d}\n", .{ initialized, size });
        return null;
    }
    const irq_flags = lock.acquireIrqSave();
    defer lock.releaseIrqRestore(irq_flags);

    const header_size = @sizeOf(FreeBlock);
    // Need room for user data + 4-byte tail canary, minimum FreeBlock size for reuse
    const with_canary = size + 4;
    const raw_alloc = if (with_canary < header_size) header_size else with_canary;
    const min_alloc = alignUp(raw_alloc, @alignOf(FreeBlock));

    var prev: ?*FreeBlock = null;
    var current = free_head;

    while (current) |block| {
        const block_addr = @intFromPtr(block);
        const data_start = block_addr + header_size;
        const aligned_start = alignUp(data_start, alignment);
        const padding = aligned_start - data_start;
        const total_needed = header_size + padding + min_alloc;

        if (block.size >= total_needed) {
            var actual_total: usize = undefined;
            const remainder = block.size - total_needed;
            if (remainder >= header_size + 16) {
                // Split: create new free block after allocation
                const new_block: *FreeBlock = @ptrFromInt(block_addr + total_needed);
                new_block.size = remainder;
                new_block.next = block.next;

                if (prev) |p| {
                    p.next = new_block;
                } else {
                    free_head = new_block;
                }
                actual_total = total_needed;
                free_bytes_remaining -= total_needed;
            } else {
                // Use entire block
                if (prev) |p| {
                    p.next = block.next;
                } else {
                    free_head = block.next;
                }
                actual_total = block.size;
                free_bytes_remaining -= block.size;
                if (free_block_count > 0) free_block_count -= 1;
            }

            // Write allocation header with canary
            const hdr: *AllocHeader = @ptrFromInt(block_addr);
            hdr.* = .{
                .total_size = actual_total,
                .user_size = @intCast(size),
                .canary_head = CANARY_HEAD,
            };

            // Write tail canary after user data (may be unaligned)
            const tail_addr = aligned_start + size;
            const tail_ptr: *align(1) u32 = @ptrFromInt(tail_addr);
            tail_ptr.* = CANARY_TAIL;

            // Update stats
            alloc_count += 1;
            current_alloc += 1;
            current_bytes += size;
            if (current_alloc > peak_alloc) peak_alloc = current_alloc;
            if (current_bytes > peak_bytes) peak_bytes = current_bytes;
            ops_since_largest_recompute += 1;

            @import("../debug/kasan.zig").allocHook(aligned_start, size);
            return @ptrFromInt(aligned_start);
        }

        prev = block;
        current = block.next;
    }

    debug.klog("[heap] alloc fail: no block for size={d} align={d} min_alloc={d} free_head={}\n", .{ size, alignment, min_alloc, free_head != null });
    if (free_head) |fh| {
        debug.klog("[heap]   free_head.size={d} at 0x{X}\n", .{ fh.size, @intFromPtr(fh) });
    }
    return null;
}

/// Free a previously allocated block.
pub fn kfree(ptr: [*]u8) void {
    if (!initialized) return;
    const addr = @intFromPtr(ptr);
    if (addr < HEAP_START or addr >= HEAP_START + HEAP_SIZE) return;
    const irq_flags = lock.acquireIrqSave();
    defer lock.releaseIrqRestore(irq_flags);

    const header_size = @sizeOf(FreeBlock);

    // Find the block header by scanning back from the data pointer
    const align_mask = ~(@as(usize, @alignOf(FreeBlock)) - 1);
    var block_addr = (addr - header_size) & align_mask;
    var found = false;
    while (block_addr >= HEAP_START) {
        const stored_size: *usize = @ptrFromInt(block_addr);
        if (stored_size.* >= header_size and
            stored_size.* <= HEAP_SIZE and
            block_addr + stored_size.* <= HEAP_START + HEAP_SIZE)
        {
            found = true;
            break;
        }
        if (block_addr < @alignOf(FreeBlock)) return;
        block_addr -= @alignOf(FreeBlock);
        if (addr - block_addr > 4096) return;
    }
    if (!found or block_addr < HEAP_START) return;

    // Verify canaries
    const hdr: *AllocHeader = @ptrFromInt(block_addr);
    if (hdr.canary_head != CANARY_HEAD) {
        serial.print("\n!!! HEAP CORRUPTION: bad head canary at 0x{X:0>8} !!!\n", .{block_addr});
        serial.print("  Expected 0x{X:0>8}, got 0x{X:0>8}\n", .{ CANARY_HEAD, hdr.canary_head });
        serial.print("  Free ptr: 0x{X:0>8}\n", .{addr});
        @panic("heap: invalid free — head canary corrupted");
    }

    // Check tail canary
    const data_start = block_addr + header_size;
    const aligned_start = alignUp(data_start, 4); // default alignment
    const padding = aligned_start - data_start;
    _ = padding;
    const user_size: usize = hdr.user_size;
    const tail_addr = addr + user_size;
    if (tail_addr + 4 <= HEAP_START + HEAP_SIZE) {
        const tail_ptr: *align(1) const u32 = @ptrFromInt(tail_addr);
        if (tail_ptr.* != CANARY_TAIL) {
            serial.print("\n!!! HEAP CORRUPTION: buffer overflow detected !!!\n", .{});
            serial.print("  Block at 0x{X:0>8}, user_size={d}\n", .{ block_addr, user_size });
            serial.print("  Tail canary at 0x{X:0>8}: expected 0x{X:0>8}, got 0x{X:0>8}\n", .{ tail_addr, CANARY_TAIL, tail_ptr.* });
            @panic("heap: buffer overflow — tail canary corrupted");
        }
    }

    // Update stats
    free_count += 1;
    if (current_alloc > 0) current_alloc -= 1;
    if (current_bytes >= user_size) current_bytes -= user_size;

    @import("../debug/kasan.zig").freeHook(addr, user_size);

    const size = hdr.total_size;

    // Insert into free list in address order, then coalesce
    const new_block: *FreeBlock = @ptrFromInt(block_addr);
    new_block.size = size;

    var prev: ?*FreeBlock = null;
    var current = free_head;

    while (current) |cur| {
        if (@intFromPtr(cur) > block_addr) break;
        prev = cur;
        current = cur.next;
    }

    new_block.next = current;
    if (prev) |p| {
        p.next = new_block;
    } else {
        free_head = new_block;
    }
    free_bytes_remaining += size;
    free_block_count += 1;

    // Coalesce with next block
    if (new_block.next) |next| {
        if (block_addr + new_block.size == @intFromPtr(next)) {
            new_block.size += next.size;
            new_block.next = next.next;
            if (free_block_count > 0) free_block_count -= 1;
        }
    }

    // Coalesce with previous block
    if (prev) |p| {
        if (@intFromPtr(p) + p.size == block_addr) {
            p.size += new_block.size;
            p.next = new_block.next;
            if (free_block_count > 0) free_block_count -= 1;
            if (p.size > largest_free_block) largest_free_block = p.size;
        } else {
            if (new_block.size > largest_free_block) largest_free_block = new_block.size;
        }
    } else {
        if (new_block.size > largest_free_block) largest_free_block = new_block.size;
    }
    ops_since_largest_recompute += 1;
}

/// Walk the entire heap and validate all allocation canaries.
pub fn validateHeap() bool {
    if (!initialized) return true;

    var errors: u32 = 0;
    var block_addr: usize = HEAP_START;

    while (block_addr < HEAP_START + HEAP_SIZE) {
        // Check if this address is in the free list
        var is_free = false;
        var free_size: usize = 0;
        var fb = free_head;
        while (fb) |f| {
            if (@intFromPtr(f) == block_addr) {
                is_free = true;
                free_size = f.size;
                break;
            }
            fb = f.next;
        }

        if (is_free) {
            block_addr += free_size;
            continue;
        }

        // Allocated block — check canaries
        const hdr: *const AllocHeader = @ptrFromInt(block_addr);

        // Validate total_size
        if (hdr.total_size < @sizeOf(FreeBlock) or
            hdr.total_size > HEAP_SIZE or
            block_addr + hdr.total_size > HEAP_START + HEAP_SIZE)
        {
            serial.print("[heap] validate: invalid total_size {d} at 0x{X:0>8}\n", .{ hdr.total_size, block_addr });
            errors += 1;
            break; // Can't continue — don't know block size
        }

        if (hdr.canary_head != CANARY_HEAD) {
            serial.print("[heap] validate: bad head canary at 0x{X:0>8}: 0x{X:0>8}\n", .{ block_addr, hdr.canary_head });
            errors += 1;
        }

        block_addr += hdr.total_size;
    }

    return errors == 0;
}

/// Print detailed heap statistics. O(1) — uses incrementally-maintained
/// counters; lazy refresh of largest_free_block kicks in occasionally.
pub fn printDetailedStats(use_vga: bool) void {
    if (ops_since_largest_recompute >= RECOMPUTE_INTERVAL) recomputeLargestFreeBlock();

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
        vga.print("Heap Statistics\n", .{});
        vga.fg = .LightGray;
        vga.print("  Total:        {d} KB\n", .{HEAP_SIZE / 1024});
        vga.print("  Used:         {d} KB ({d}%)\n", .{ used_bytes / 1024, pct });
        vga.print("  Free:         {d} KB in {d} blocks\n", .{ free_bytes / 1024, free_blocks });
        vga.print("  Largest free: {d} KB ({d}% fragmented)\n", .{ largest / 1024, frag_pct });
        vga.print("  Allocations:  {d} total, {d} freed, {d} live\n", .{ alloc_count, free_count, current_alloc });
        vga.print("  Peak live:    {d} allocs, {d} bytes\n", .{ peak_alloc, peak_bytes });
        vga.print("  Current:      {d} bytes tracked\n", .{current_bytes});

        vga.fg = .LightGreen;
        if (validateHeap()) {
            vga.print("  Integrity:    OK\n", .{});
        } else {
            vga.fg = .LightRed;
            vga.print("  Integrity:    CORRUPTED (see serial)\n", .{});
        }
        vga.fg = .LightGray;
    } else {
        serial.print("[heap] Total: {d} KB, Used: {d} KB ({d}%), Free: {d} KB in {d} blocks (largest {d} KB, frag {d}%)\n", .{ HEAP_SIZE / 1024, used_bytes / 1024, pct, free_bytes / 1024, free_blocks, largest / 1024, frag_pct });
        serial.print("[heap] Allocs: {d} total, {d} freed, {d} live, peak: {d}\n", .{ alloc_count, free_count, current_alloc, peak_alloc });
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

/// Cheap snapshot of the heap counters. Useful for sysmon / dmesg-style read-out
/// without printing.
pub fn snapshot() Stats {
    if (ops_since_largest_recompute >= RECOMPUTE_INTERVAL) recomputeLargestFreeBlock();
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

fn alignUp(addr: usize, alignment: usize) usize {
    if (alignment == 0) return addr;
    return (addr + alignment - 1) & ~(alignment - 1);
}

// ----- kvmalloc: large-allocation wrapper that bypasses the small kernel heap -----
//
// The kernel heap is 4 MB. Allocations above KVMALLOC_THRESHOLD bytes consume
// a disproportionate slice and accelerate fragmentation — e.g. a 36 KB
// TerminalData is ~1% of the heap and after a few terminal opens + closes the
// heap is full of holes. kvmalloc routes these through PMM directly: page-
// rounded contiguous frames, identity-mapped, no heap traffic.

const pmm = @import("pmm.zig");

const KVMALLOC_THRESHOLD: usize = 16 * 1024;
const KV_MAGIC: u64 = 0x4B564D414C4C4F43; // "KVMALLOC"

const KvHeader = extern struct {
    magic: u64,
    pages: u32,
    user_offset: u32,
};

/// Allocate `size` bytes. Routes to kmalloc for small requests and to PMM
/// for large ones. Returns a byte-pointer suitable for the requested size +
/// 16 alignment (PMM-backed allocs are 4 KB aligned, more than enough).
pub fn kalloc(size: usize) ?[*]u8 {
    if (size >= KVMALLOC_THRESHOLD) return kvmalloc(size, 16);
    return kmalloc(size);
}

/// Free a block previously returned by `kalloc` / `kvmalloc` / `kmalloc`.
/// Disambiguates by address range — heap pointers fall in [HEAP_START,
/// HEAP_START + HEAP_SIZE), kvmalloc'd ones live anywhere else (PMM).
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
    serial.print("[heap] kfreeAuto: ptr 0x{X} matches no allocator (heap or kv)\n", .{addr});
    @panic("kfreeAuto: orphan pointer");
}

/// Allocate ≥`size` bytes from PMM as `ceil(size / 4 KB)` contiguous frames.
pub fn kvmalloc(size: usize, alignment: usize) ?[*]u8 {
    if (size == 0) return null;
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

/// Free a kvmalloc'd block. Validates the KvHeader magic to catch
/// double-frees and bad pointers; panics rather than silently leaking.
pub fn kvfree(ptr: [*]u8) void {
    const addr = @intFromPtr(ptr);
    const page_base = addr & ~@as(usize, 0xFFF);
    if (page_base == 0) {
        serial.print("[heap] kvfree: bad ptr 0x{X}\n", .{addr});
        return;
    }
    const hdr: *const KvHeader = @ptrFromInt(page_base);
    if (hdr.magic != KV_MAGIC) {
        serial.print("[heap] kvfree: bad magic at 0x{X}: 0x{X}\n", .{ page_base, hdr.magic });
        @panic("kvfree: bad magic — double-free, type confusion, or non-kvmalloc ptr");
    }
    if (addr - page_base != hdr.user_offset) {
        serial.print("[heap] kvfree: bad offset {d} (expected {d}) for ptr 0x{X}\n", .{ addr - page_base, hdr.user_offset, addr });
        @panic("kvfree: corrupted header");
    }
    const pages = hdr.pages;
    const hdr_mut: *KvHeader = @ptrFromInt(page_base);
    hdr_mut.magic = 0xDEADDEADDEADDEAD;
    // page_base is a physmap-VA; PMM expects phys, so reverse-translate.
    const paging = @import("paging.zig");
    pmm.freeContiguous(paging.virtToPhys(page_base).?, pages);
}

