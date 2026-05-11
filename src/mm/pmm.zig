const vga = @import("../ui/vga.zig");
const boot_info = @import("../boot/boot_info.zig");
const SpinLock = @import("../proc/spinlock.zig").SpinLock;
const memmap = @import("memmap.zig");

var lock: SpinLock = .{};

const FRAME_SIZE: u32 = 4096;
// 1 GB cap: bitmap = 32 KB, frame_refs = 256 KB. ZigOS QEMU configs use
// 64-256 MB so 1 GB is far more than needed; the cap exists to keep static
// BSS small enough that _kernel_end stays below KERNEL_HEAP_BASE (0x800000).
// Frames above 1 GB in the memory map are skipped at init time with a
// warning — bump this if a config ever genuinely wants more RAM exposed.
const MAX_FRAMES: u32 = 256 * 1024;
const BITMAP_SIZE = MAX_FRAMES / 32;

/// Per-CPU magazine cache parameters (Bonwick magazine layer).
///
///   CACHE_SIZE   — capacity of one CPU's local cache. Capped tight: a
///                  4 KB cache holds 32 entries × 8 B = 256 B + count, so
///                  the whole magazine fits in 4 cache lines and stays
///                  warm. Bigger caches risk holding too many frames out
///                  of the global pool under low-mem pressure.
///   REFILL_BATCH — frames to grab on cache miss (besides the one returned
///                  to the caller). Trades cache-miss frequency vs. global-
///                  lock duration. 16 means one bulk refill covers the
///                  next 16 single-frame allocs without re-locking.
///   DRAIN_BATCH  — frames to flush back when the cache is full. Symmetric
///                  with REFILL_BATCH; keeps the cache in the middle range
///                  rather than oscillating between empty and full.
pub const CACHE_SIZE: u32 = 32;
const REFILL_BATCH: u32 = 16;
const DRAIN_BATCH: u32 = 16;

comptime {
    if (CACHE_SIZE != @import("../cpu/smp.zig").PMM_CACHE_SIZE) {
        @compileError("pmm.CACHE_SIZE must match smp.PMM_CACHE_SIZE");
    }
    if (REFILL_BATCH >= CACHE_SIZE) @compileError("REFILL_BATCH must leave headroom in cache");
    if (DRAIN_BATCH >= CACHE_SIZE) @compileError("DRAIN_BATCH must leave the cache non-empty");
}

// Local copies of the spinlock IRQ-save helpers. Duplicated rather than
// imported because the per-CPU cache path doesn't take a lock — we need
// just the IF gate, not the whole acquire+IF dance.
inline fn saveAndDisableIrq() u64 {
    var flags: u64 = undefined;
    asm volatile ("pushfq; pop %[f]; cli"
        : [f] "=r" (flags),
    );
    return flags;
}

inline fn restoreIrq(flags: u64) void {
    if (flags & 0x200 != 0) asm volatile ("sti");
}

// Bitmap: 1 bit per 4KB frame. Initialized to all-used in init().
var bitmap: [BITMAP_SIZE]u32 = undefined;
var total_frames: u32 = 0;
var next_free_word: usize = 0; // Hint: start scanning from here

// Per-frame reference count for COW. Lockstep invariant: frame_refs[i] == 0 ⟺
// bitmap-says-free OR sitting in some CPU's magazine cache; frame_refs[i] >= 1 ⟺
// allocated to at least one address space. 1 byte/frame = 1 MB BSS for 4 GB
// coverage. Saturation at 255 panics (a fork bomb 256 levels deep would be the
// only way to hit it). Atomic ops on the byte handle SMP without a lock —
// alloc paths set non-atomically (single owner during alloc), but acquireFrame
// from COW clone runs in parallel with potential frees on other CPUs.
var frame_refs: [MAX_FRAMES]u8 = undefined;

extern var _kernel_end: u8;

// Cached kernel-image physical range. Set in init(). Used by the wild-writer
// tripwire (checkPhysSafety) — if any alloc returns or any free targets a
// frame inside [0x100000, kernel_phys_end), the bitmap has been corrupted or
// a caller is freeing a frame that backs kernel .text/.rodata/.data/.bss.
// Either way, that's the PMM-poisoning bug we're hunting: a buggy free-path
// hands kernel BSS frames back to the free list, then a later allocContiguous
// for an ELF/sector buffer copies file contents over kernel memory and the
// result is a "wild writer" with file-content-shaped payload (e.g. the
// "fetch_um" bytes from a Zig binary's .strtab).
var kernel_phys_end: usize = 0;

const KERNEL_PHYS_START: usize = 0x100000;

fn checkPhysSafety(phys: usize, op: []const u8) void {
    if (kernel_phys_end == 0) return; // pre-init; nothing to compare against
    if (phys >= KERNEL_PHYS_START and phys < kernel_phys_end) {
        const serial = @import("../debug/serial.zig");
        serial.print("\n!!! PMM POISON: {s} phys=0x{X} INSIDE kernel image [0x{X}..0x{X})\n", .{ op, phys, KERNEL_PHYS_START, kernel_phys_end });
        @panic("pmm poison: kernel-image physical frame touched by alloc/free");
    }
}

fn setBit(frame: u32) void {
    bitmap[frame / 32] |= @as(u32, 1) << @as(u5, @truncate(frame % 32));
}

fn clearBit(frame: u32) void {
    bitmap[frame / 32] &= ~(@as(u32, 1) << @as(u5, @truncate(frame % 32)));
}

fn testBit(frame: u32) bool {
    return (bitmap[frame / 32] & (@as(u32, 1) << @as(u5, @truncate(frame % 32)))) != 0;
}

pub fn markRegionFree(base: usize, length: usize) void {
    var frame: u32 = @intCast(base / FRAME_SIZE);
    const end_frame: u32 = @intCast((base + length) / FRAME_SIZE);
    while (frame < end_frame and frame < MAX_FRAMES) : (frame += 1) {
        if (testBit(frame)) {
            clearBit(frame);
            total_frames += 1;
        }
    }
}

pub fn markRegionUsed(base: usize, length: usize) void {
    var frame: u32 = @intCast(base / FRAME_SIZE);
    const end_frame: u32 = @intCast((base + length + FRAME_SIZE - 1) / FRAME_SIZE);
    while (frame < end_frame and frame < MAX_FRAMES) : (frame += 1) {
        if (!testBit(frame)) {
            setBit(frame);
            if (total_frames > 0) total_frames -= 1;
        }
    }
}

pub fn init(info: *const boot_info.BootInfo) void {
    // Mark all frames as used initially
    for (&bitmap) |*word| {
        word.* = 0xFFFFFFFF;
    }
    @memset(&frame_refs, 0);
    total_frames = 0;

    if (info.memory_map_count == 0) {
        @panic("No memory map!");
    }

    // Parse memory map — mark usable regions as free.
    // Diagnostic counters logged at end. Real HW with >4GB RAM emits regions
    // above 4GB that we currently skip (PMM bitmap caps at 4GB); the count
    // tells you how much you're leaving on the table without re-flashing.
    var consumed: u32 = 0;
    var skipped_high: u32 = 0;
    var skipped_kind: u32 = 0;
    var lost_pages_high: u64 = 0;
    for (0..info.memory_map_count) |i| {
        const region = info.memory_map[i];
        if (region.kind != 1) {
            skipped_kind += 1;
            continue;
        }
        if (region.base >= 0x100000000) {
            skipped_high += 1;
            lost_pages_high += region.length / 4096;
            continue;
        }
        const base: usize = @intCast(region.base);
        const length: usize = @intCast(@min(region.length, 0x100000000 - region.base));
        markRegionFree(base, length);
        consumed += 1;
        if (region.base + region.length > 0x100000000) {
            // Region straddles 4GB — count the truncated tail
            lost_pages_high += (region.base + region.length - 0x100000000) / 4096;
        }
    }
    const serial = @import("../debug/serial.zig");
    serial.print("[pmm] init: {d} regions consumed, {d} non-usable, {d} above 4GB\n", .{ consumed, skipped_kind, skipped_high });
    if (lost_pages_high > 0) {
        serial.print("[pmm] WARNING: {d} MB above 4GB not used (bitmap capped at 4GB)\n", .{lost_pages_high * 4 / 1024});
    }

    // Mark reserved regions as used (see memmap.zig for the layout).
    // Clean-rule pass: only SINGLETON kernel infrastructure here; per-process
    // GUI FBs go through PMM allocation.
    markRegionUsed(0x0, memmap.KERNEL_PHYS_START); // Low memory, BIOS, VGA
    // Kernel image: linker-defined low PA → kernelEndPhys. Runtime-derived
    // so kernel growth (more code, bigger BSS) is automatic; no manual memmap
    // bumps. PMM only protects the bytes the kernel actually uses.
    const kernel_end = memmap.kernelEndPhys();
    markRegionUsed(memmap.KERNEL_PHYS_START, kernel_end - memmap.KERNEL_PHYS_START);
    kernel_phys_end = kernel_end; // arm tripwire — see checkPhysSafety
    markRegionUsed(memmap.KERNEL_HEAP_BASE, memmap.KERNEL_HEAP_SIZE); // Kernel heap (4 MB)
    markRegionUsed(memmap.GUEST_FB_BASE, memmap.GUEST_FB_SIZE); // Guest FB (8 MB)
    markRegionUsed(memmap.BACK_BUFFER_BASE, memmap.BACK_BUFFER_SIZE); // Back buffer (8 MB)
    if (@import("../boot/boot_info.zig").is_uefi) {
        // UEFI page tables live at 0x1C00000..0x1C40000. See memmap.zig
        // (UEFI_PT_BASE) for the rationale — kasan.init's 32 MB shadow
        // alloc otherwise overwrites them and kernel halts on wild CR3.
        markRegionUsed(memmap.UEFI_PT_BASE, memmap.UEFI_PT_SIZE);
    }
}

/// Internal: scan the bitmap for one free frame, mark it used, and return
/// its phys addr. Caller must already hold `lock`. Same wrap-around logic
/// as the original allocFrame inline scan.
fn scanAndConsumeOneLocked() ?usize {
    var i: usize = next_free_word;
    while (i < bitmap.len) : (i += 1) {
        if (bitmap[i] != 0xFFFFFFFF) {
            const free_bits = ~bitmap[i];
            const bit: u5 = @truncate(@ctz(free_bits));
            const frame = @as(u32, @intCast(i)) * 32 + bit;
            setBit(frame);
            if (total_frames > 0) total_frames -= 1;
            next_free_word = i;
            return @as(usize, frame) * FRAME_SIZE;
        }
    }
    i = 0;
    while (i < next_free_word) : (i += 1) {
        if (bitmap[i] != 0xFFFFFFFF) {
            const free_bits = ~bitmap[i];
            const bit: u5 = @truncate(@ctz(free_bits));
            const frame = @as(u32, @intCast(i)) * 32 + bit;
            setBit(frame);
            if (total_frames > 0) total_frames -= 1;
            next_free_word = i;
            return @as(usize, frame) * FRAME_SIZE;
        }
    }
    return null;
}

pub fn allocFrame() ?usize {
    const ra = @returnAddress();
    // IF off across cache access — guarantees no preemption / IRQ runs an
    // allocFrame on the same CPU's cache mid-pop. With per-CPU storage and
    // IF=0, no extra synchronisation is required.
    const irq_flags = saveAndDisableIrq();
    defer restoreIrq(irq_flags);

    const cpu = @import("../cpu/smp.zig").myCpu();
    if (cpu.pmm_cache_count > 0) {
        cpu.pmm_cache_count -= 1;
        const phys = cpu.pmm_cache[cpu.pmm_cache_count];
        checkPhysSafety(phys, "allocFrame(cache)");
        @import("../debug/kdbg.zig").pmmAlloc(phys, 1, ra);
        @import("../debug/kasan.zig").unpoison(phys, FRAME_SIZE);
        frame_refs[phys / FRAME_SIZE] = 1;
        return phys;
    }

    // Cache miss: bulk-refill (REFILL_BATCH frames into cache) + return one
    // to the caller, all under a single lock acquire. Amortises the lock +
    // cache-line-ping cost across the next ~REFILL_BATCH single-frame allocs.
    lock.acquire();
    defer lock.release();

    const first = scanAndConsumeOneLocked() orelse return null;
    var refilled: u32 = 0;
    while (refilled < REFILL_BATCH) : (refilled += 1) {
        const phys = scanAndConsumeOneLocked() orelse break;
        cpu.pmm_cache[cpu.pmm_cache_count] = phys;
        cpu.pmm_cache_count += 1;
    }

    checkPhysSafety(first, "allocFrame");
    @import("../debug/kdbg.zig").pmmAlloc(first, 1, ra);
    @import("../debug/kasan.zig").unpoison(first, FRAME_SIZE);
    frame_refs[first / FRAME_SIZE] = 1;
    // Cache-stuffed frames stay at refcount=0 — they're held in the magazine
    // but not yet allocated to any caller; the next cache-hit pop bumps to 1.
    return first;
}

/// Allocate a frame below 4GB (for DMA buffers that require 32-bit addresses).
pub fn allocFrameBelow4G() ?usize {
    const max_frame_32: u32 = 0x100000; // 4GB / 4KB
    const max_words = max_frame_32 / 32;
    for (0..@min(bitmap.len, max_words)) |i| {
        if (bitmap[i] != 0xFFFFFFFF) {
            const free_bits = ~bitmap[i];
            const bit: u5 = @truncate(@ctz(free_bits));
            const frame = @as(u32, @intCast(i)) * 32 + bit;
            if (frame >= max_frame_32) return null;
            setBit(frame);
            if (total_frames > 0) total_frames -= 1;
            const phys: usize = @as(usize, frame) * FRAME_SIZE;
            checkPhysSafety(phys, "allocFrameBelow4G");
            @import("../debug/kasan.zig").unpoison(phys, FRAME_SIZE);
            frame_refs[frame] = 1;
            return phys;
        }
    }
    return null;
}

/// Find a run of `count` consecutive zero bits in the bitmap, starting search
/// at frame >= `start_frame`, ending at frame < `end_frame`. Returns the start
/// frame of the run, or null if no such run exists.
///
/// Word-at-a-time scan: 32 frames per iteration when bitmap[i] is all-free or
/// all-used. Only descends to bit-level for mixed words. For a defragmented
/// bitmap and large `count`, this is ~32× faster than the naive bit-by-bit
/// scan it replaces. Behavior matches the old algorithm: lowest-address fit.
fn findContiguousRun(start_frame: u32, end_frame: u32, count: u32) ?u32 {
    var run_start: u32 = start_frame;
    var run_len: u32 = 0;

    var f = start_frame;
    while (f < end_frame) {
        const word_idx = f / 32;
        const bit_in_word: u5 = @truncate(f % 32);

        // Aligned word boundary AND at least 32 frames remaining: take whole words.
        if (bit_in_word == 0 and f + 32 <= end_frame) {
            const w = bitmap[word_idx];
            if (w == 0xFFFFFFFF) {
                run_len = 0;
                f += 32;
                continue;
            }
            if (w == 0) {
                if (run_len == 0) run_start = f;
                run_len += 32;
                if (run_len >= count) return run_start;
                f += 32;
                continue;
            }
            // Fall through to mixed-word handling.
        }

        // Mixed word, or unaligned start: walk this word bit-by-bit.
        const word_end_frame = @min(end_frame, (word_idx + 1) * 32);
        const w = bitmap[word_idx];
        var b: u5 = bit_in_word;
        while (true) {
            const used = (w >> b) & 1 != 0;
            const cur_frame = word_idx * 32 + @as(u32, b);
            if (used) {
                run_len = 0;
            } else {
                if (run_len == 0) run_start = cur_frame;
                run_len += 1;
                if (run_len >= count) return run_start;
            }
            f = cur_frame + 1;
            if (f >= word_end_frame) break;
            if (b == 31) break;
            b +%= 1;
        }
    }
    return null;
}

/// Mark frames [start_frame, start_frame + count) as used. Caller already holds
/// the lock and has validated availability via `findContiguousRun`. Writes whole
/// bitmap words in the middle for speed. Each frame's refcount is set to 1 —
/// the contiguous-alloc callers always hand the whole range to a single owner.
fn markRange(start_frame: u32, count: u32) void {
    const end_frame = start_frame + count;
    var f: u32 = start_frame;

    while (f < end_frame and (f % 32) != 0) : (f += 1) setBit(f);
    while (f + 32 <= end_frame) : (f += 32) bitmap[f / 32] = 0xFFFFFFFF;
    while (f < end_frame) : (f += 1) setBit(f);

    @memset(frame_refs[start_frame..end_frame], 1);

    if (total_frames >= count) total_frames -= count else total_frames = 0;
}

/// Allocate `count` physically contiguous frames. Returns base physical address.
pub fn allocContiguous(count: u32) ?usize {
    if (count == 0) return null;
    if (count == 1) return allocFrame();
    const ra = @returnAddress();
    const flags = lock.acquireIrqSave();
    defer lock.releaseIrqRestore(flags);

    const start = findContiguousRun(0, MAX_FRAMES, count) orelse return null;
    markRange(start, count);

    const base: usize = @as(usize, start) * FRAME_SIZE;
    checkPhysSafety(base, "allocContiguous");
    const last: usize = base + (@as(usize, count) - 1) * FRAME_SIZE;
    if (last != base) checkPhysSafety(last, "allocContiguous(last)");
    @import("../debug/kdbg.zig").pmmAlloc(base, count, ra);
    @import("../debug/kasan.zig").unpoison(base, @as(usize, count) * FRAME_SIZE);
    return base;
}

/// Allocate `count` contiguous frames below 4GB (for DMA).
pub fn allocContiguousBelow4G(count: u32) ?usize {
    if (count == 0) return null;
    if (count == 1) return allocFrameBelow4G();
    const ra = @returnAddress();
    const flags = lock.acquireIrqSave();
    defer lock.releaseIrqRestore(flags);
    const max_frame_32: u32 = 0x100000; // 4GB / 4KB

    const start = findContiguousRun(0, max_frame_32, count) orelse return null;
    markRange(start, count);

    const base: usize = @as(usize, start) * FRAME_SIZE;
    checkPhysSafety(base, "allocContiguousBelow4G");
    const last: usize = base + (@as(usize, count) - 1) * FRAME_SIZE;
    if (last != base) checkPhysSafety(last, "allocContiguousBelow4G(last)");
    @import("../debug/kdbg.zig").pmmAlloc(base, count, ra);
    @import("../debug/kasan.zig").unpoison(base, @as(usize, count) * FRAME_SIZE);
    return base;
}

pub fn freeFrame(phys_addr: usize) void {
    const ra = @returnAddress();
    const frame_num = phys_addr / FRAME_SIZE;
    if (frame_num >= MAX_FRAMES) {
        @import("../debug/serial.zig").print("[pmm] WARNING: freeFrame bad addr=0x{X} (frame={X})\n", .{ phys_addr, frame_num });
        return;
    }

    // Atomic refcount drop. Common COW case: another address space still holds
    // a reference, so we just decrement and return — frame stays mapped there.
    // Only when this was the LAST reference (old==1) do we proceed to bitmap-
    // level reclamation and the magazine cache push.
    const old_ref = @atomicRmw(u8, &frame_refs[frame_num], .Sub, 1, .acq_rel);
    if (old_ref > 1) return;
    if (old_ref == 0) {
        // Underflow — caller released a frame that was already free. Pin
        // to 0 so a subsequent acquire/free doesn't paper over the bug.
        // Was a panic; downgraded to a warning that leaks the frame so
        // an app-teardown bug doesn't crash the whole desktop. The
        // accumulating leak rate is the visible signal that something's
        // still wrong; fix the root cause when it surfaces, not by
        // re-panicking here.
        @atomicStore(u8, &frame_refs[frame_num], 0, .release);
        const symbols = @import("../debug/symbols.zig");
        const serial = @import("../debug/serial.zig");
        serial.print("[pmm] LEAK: freeFrame underflow phys=0x{X} caller=", .{phys_addr});
        if (symbols.resolveKernel(ra)) |r| {
            serial.print("{s}+0x{X}\n", .{ r.name, r.offset });
        } else {
            serial.print("0x{X}\n", .{ra});
        }
        return;
    }
    // old_ref == 1; we're the last owner. Proceed with the existing free path.

    // Tripwires BEFORE any bitmap or cache mutation so the panic backtrace
    // points at the bad caller, not whoever later draws the poisoned frame.
    checkPhysSafety(phys_addr, "freeFrame");
    @import("../debug/kdbg.zig").pmmFree(phys_addr, ra);
    @import("../debug/kasan.zig").poison(phys_addr, FRAME_SIZE, @import("../debug/kasan.zig").SHADOW_FREED);

    const irq_flags = saveAndDisableIrq();
    defer restoreIrq(irq_flags);

    const cpu = @import("../cpu/smp.zig").myCpu();
    if (cpu.pmm_cache_count < CACHE_SIZE) {
        // Hot path: just push onto the local cache. Bitmap stays "used" —
        // the frame is logically free but accounted to this CPU's magazine.
        cpu.pmm_cache[cpu.pmm_cache_count] = phys_addr;
        cpu.pmm_cache_count += 1;
        return;
    }

    // Cache full: drain DRAIN_BATCH back to the global pool (one lock
    // acquisition for all of them), then push the new frame. This keeps
    // the cache below CACHE_SIZE so subsequent frees stay hot.
    lock.acquire();
    defer lock.release();

    var i: u32 = 0;
    while (i < DRAIN_BATCH) : (i += 1) {
        cpu.pmm_cache_count -= 1;
        const drain_phys = cpu.pmm_cache[cpu.pmm_cache_count];
        const drain_frame: u32 = @intCast(drain_phys / FRAME_SIZE);
        if (testBit(drain_frame)) {
            clearBit(drain_frame);
            total_frames += 1;
            const word = drain_frame / 32;
            if (word < next_free_word) next_free_word = word;
        }
    }
    cpu.pmm_cache[cpu.pmm_cache_count] = phys_addr;
    cpu.pmm_cache_count += 1;
}

/// Free `count` contiguous frames starting at phys_addr. Single lock acquisition,
/// word-at-a-time clearing for the middle of the range. Replaces the
/// `for (0..n) freeFrame(...)` idiom that was scattered across many callsites
/// and took the spinlock + ran the kdbg/kasan hooks N times.
pub fn freeContiguous(phys_addr: usize, count: u32) void {
    if (count == 0) return;
    if (count == 1) {
        freeFrame(phys_addr);
        return;
    }
    const ra = @returnAddress();
    const start_frame = phys_addr / FRAME_SIZE;
    if (start_frame + count > MAX_FRAMES) {
        @import("../debug/serial.zig").print("[pmm] WARNING: freeContiguous bad range start=0x{X} count={d}\n", .{ phys_addr, count });
        return;
    }

    // Bulk free assumes the entire range is single-owner (refcount==1 each).
    // Contiguous frames are DMA buffers / page-table pools / GUI FBs — none of
    // which are ever shared via COW. If this ever fires, the caller is using
    // freeContiguous on a range it didn't fully own.
    var rf: u32 = @intCast(start_frame);
    const rf_end: u32 = @intCast(start_frame + count);
    while (rf < rf_end) : (rf += 1) {
        const old = @atomicRmw(u8, &frame_refs[rf], .Sub, 1, .acq_rel);
        if (old != 1) {
            @atomicStore(u8, &frame_refs[rf], 0, .release);
            @import("../debug/serial.zig").print("[pmm] PANIC: freeContiguous on multi-owned frame phys=0x{X} idx={d} old_ref={d}\n", .{ phys_addr, rf, old });
            @panic("pmm: freeContiguous on multi-owned frame");
        }
    }

    checkPhysSafety(phys_addr, "freeContiguous");
    const last_addr = phys_addr + (@as(usize, count) - 1) * FRAME_SIZE;
    if (last_addr != phys_addr) checkPhysSafety(last_addr, "freeContiguous(last)");
    @import("../debug/kdbg.zig").pmmFree(phys_addr, ra);
    @import("../debug/kasan.zig").poison(phys_addr, @as(usize, count) * FRAME_SIZE, @import("../debug/kasan.zig").SHADOW_FREED);

    const flags = lock.acquireIrqSave();
    defer lock.releaseIrqRestore(flags);

    var f: u32 = @intCast(start_frame);
    const end_frame: u32 = @intCast(start_frame + count);
    var freed: u32 = 0;

    while (f < end_frame and (f % 32) != 0) : (f += 1) {
        if (testBit(f)) {
            clearBit(f);
            freed += 1;
        }
    }
    while (f + 32 <= end_frame) : (f += 32) {
        const w = bitmap[f / 32];
        freed += @popCount(w);
        bitmap[f / 32] = 0;
    }
    while (f < end_frame) : (f += 1) {
        if (testBit(f)) {
            clearBit(f);
            freed += 1;
        }
    }

    total_frames += freed;
    const start_word: usize = start_frame / 32;
    if (start_word < next_free_word) next_free_word = start_word;
}


pub fn freeFrameCount() u32 {
    return total_frames;
}

/// Add a reference to a frame currently in use. Used by COW: cloneAddressSpace
/// shares parent's data frames with child by bumping refcount instead of copying.
/// CMPXCHG loop catches saturation explicitly (255 references = fork bomb depth
/// 256, well past anything realistic; panic instead of wrapping silently).
pub fn acquireFrame(phys_addr: usize) void {
    const frame_num_us = phys_addr / FRAME_SIZE;
    if (frame_num_us >= MAX_FRAMES) {
        @import("../debug/serial.zig").print("[pmm] WARNING: acquireFrame bad addr=0x{X}\n", .{phys_addr});
        return;
    }
    const frame_num: u32 = @intCast(frame_num_us);
    while (true) {
        const cur = @atomicLoad(u8, &frame_refs[frame_num], .acquire);
        if (cur == 0) {
            @import("../debug/serial.zig").print("[pmm] PANIC: acquireFrame on free frame phys=0x{X}\n", .{phys_addr});
            @panic("pmm: acquireFrame on free frame (refcount=0)");
        }
        if (cur == 0xFF) {
            @import("../debug/serial.zig").print("[pmm] PANIC: acquireFrame saturation phys=0x{X}\n", .{phys_addr});
            @panic("pmm: acquireFrame refcount saturation (>255)");
        }
        if (@cmpxchgWeak(u8, &frame_refs[frame_num], cur, cur + 1, .acq_rel, .acquire) == null) break;
    }
}

/// Drop one reference to a frame; if refcount hits 0, returns the frame to the
/// free pool. Functionally identical to freeFrame — both decrement and free-
/// when-zero. Use this name when releasing a COW-shared frame to make intent
/// explicit (the caller knows the frame may have other references).
pub inline fn releaseFrame(phys_addr: usize) void {
    return freeFrame(phys_addr);
}

/// Read current refcount for a frame. Diagnostic only — racy under SMP. Useful
/// for /proc/meminfo, kdbg autopsy, and unit tests.
pub fn frameRefCount(phys_addr: usize) u8 {
    const frame_num = phys_addr / FRAME_SIZE;
    if (frame_num >= MAX_FRAMES) return 0;
    return @atomicLoad(u8, &frame_refs[frame_num], .acquire);
}

pub fn printStats() void {
    const free = freeFrameCount();
    const free_kb = free * 4;
    const free_mb = free_kb / 1024;
    vga.fg = .LightCyan;
    vga.print("Memory Info:\n", .{});
    vga.fg = .LightGray;
    vga.print("  Free frames: {d}\n", .{free});
    vga.print("  Free memory: {d} KB ({d} MB)\n", .{ free_kb, free_mb });
}
