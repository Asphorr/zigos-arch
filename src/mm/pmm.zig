const std = @import("std");
const vga = @import("../ui/vga.zig");
const boot_info = @import("../boot/boot_info.zig");
const Guarded = @import("../util/guarded.zig").Guarded;
const memmap = @import("memmap.zig");
const smp = @import("../cpu/smp.zig");
/// pub: boot-plumbing callers (pmem.registerDeviceRange) reach the type as
/// `pmm.Phys` instead of adding an @import edge of their own — a new edge
/// re-rolls the LLVM Invalid-type dice (round 7, 2026-09-16).
pub const Phys = @import("../util/addr.zig").Phys;

const FRAME_SIZE: u32 = 4096;
// 1 GB cap: bitmap = 32 KB, frame_refs = 256 KB. ZigOS QEMU configs use
// 64-256 MB so 1 GB is far more than needed; the cap exists to keep static
// BSS small enough that _kernel_end stays below KERNEL_HEAP_BASE (0x800000).
// Frames above 1 GB in the memory map are skipped at init time with a
// warning — bump this if a config ever genuinely wants more RAM exposed.
const MAX_FRAMES: u32 = 256 * 1024;
const BITMAP_SIZE = MAX_FRAMES / 32;

// === Region-bucketed bitmap with per-CPU affinity + a per-region index ===
//
// The bitmap is the ground truth (canary/kasan/refcount/kstack tripwires
// all key off it). Around it:
//
//   1. REGIONS — physical memory split into REGIONS_COUNT regions of
//      REGION_FRAMES frames each, each behind its own lock. SMP allocs and
//      frees on different regions proceed in parallel.
//
//   2. INDEX — per region, two masks over its bitmap words (nonfull,
//      allfree) plus the free count, all derived from the words and kept
//      in step by src/mm/frame_index.zig (host-tested: tools/pmm-test).
//      A free frame or a free run is found with a few ctz/AND steps, and
//      the index cannot go stale against the bitmap the way the old
//      run-list layer could (orphaned or overlapping runs).
//
//   3. PER-CPU PREFERRED REGION — derived from cpu_id, not stored. Magazine
//      refill and contiguous alloc start at the preferred region and walk
//      outward over the regions that hold RAM, skipping full ones by hint.
const REGION_FRAMES: u32 = 1024; // 4 MB per region
const REGIONS_COUNT: u32 = MAX_FRAMES / REGION_FRAMES; // 256
const REGION_WORDS: u32 = REGION_FRAMES / 32; // bitmap words per region

const fi = @import("frame_index.zig");

comptime {
    if (MAX_FRAMES % REGION_FRAMES != 0) {
        @compileError("MAX_FRAMES must be a multiple of REGION_FRAMES");
    }
    if (REGION_WORDS != fi.WORDS or REGION_FRAMES != fi.FRAMES) {
        @compileError("a pmm region must be exactly one frame_index region");
    }
    // Every managed frame is a 32-bit DMA address, so the Below4G entry
    // points are plain allocations. Growing MAX_FRAMES past 4 GiB needs
    // them to filter again.
    if (@as(u64, MAX_FRAMES) * FRAME_SIZE > 1 << 32) {
        @compileError("MAX_FRAMES past 4 GiB: allocFrameBelow4G must filter");
    }
}

/// Per-region index, behind its lock as Guarded(fi.Summary)
/// (util/guarded.zig): reaching it takes a token, so "caller must hold the
/// region's lock" is a type, not a comment.
///
/// Each region owns a REGION_FRAMES-frame slice of the GLOBAL bitmap
/// (`regionWords`). The slice is touched only under this region's lock,
/// exactly like the summary, but it cannot move into the blob: one array,
/// region-striped.
var regions: [REGIONS_COUNT]Guarded(fi.Summary) = blk: {
    var arr: [REGIONS_COUNT]Guarded(fi.Summary) = undefined;
    for (&arr) |*r| r.* = .init(.{});
    break :blk arr;
};

inline fn regionWords(region_idx: u32) *[REGION_WORDS]u32 {
    return bitmap[region_idx * REGION_WORDS ..][0..REGION_WORDS];
}

/// Free frames per region, stored under the region lock and read without
/// it: the allocation walks skip a region whose hint says it cannot help.
/// Only a hint — every walk that comes up empty repeats with the locks.
var free_hint: [REGIONS_COUNT]u16 = [_]u16{0} ** REGIONS_COUNT;

comptime {
    if (REGION_FRAMES > std.math.maxInt(u16)) @compileError("free_hint is u16");
}

inline fn publishHint(region_idx: u32, s: *const fi.Summary) void {
    @atomicStore(u16, &free_hint[region_idx], @intCast(s.free_count), .monotonic);
}

inline fn hintFree(region_idx: u32) u32 {
    return @atomicLoad(u16, &free_hint[region_idx], .monotonic);
}

/// Regions that hold managed RAM: [0, regions_live). Set at the end of
/// init(); the walks never visit the phantom regions above it (with
/// `-m 256`, 192 of the 256).
var regions_live: u32 = 0;

inline fn regionForFrame(frame: u32) u32 {
    return frame / REGION_FRAMES;
}

inline fn regionStartFrame(region_idx: u32) u32 {
    return region_idx * REGION_FRAMES;
}

/// Map a CPU id to its preferred region: CPUs spread at stride
/// REGIONS_COUNT / MAX_CPUS (cpu 1 → region 8), folded into the regions
/// that hold RAM. The walks go outward from there and wrap.
inline fn preferredRegion(cpu_id: u8) u32 {
    const stride: u32 = REGIONS_COUNT / @import("../cpu/smp.zig").MAX_CPUS;
    return (@as(u32, cpu_id) * stride) % regions_live;
}

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

// === S5: PMM frame canary (free→alloc tripwire) ===
//
// On every freeFrame we write a self-referencing canary at offset 0..16 of
// the freed frame; on every allocFrame we check it before handing the
// frame back. A mismatch means SOMEONE wrote to a freed frame — the
// silent-corruption class that bit us today (FB zero-fill clobbering
// PML4). Self-referencing (`phys ^ MAGIC` + ones-complement) means random
// data is extremely unlikely to satisfy both 8-byte halves, and we don't
// need a side-table to know "this frame was canaried."
//
// Logging only — no panic — because the very first allocations after
// boot come from bitmap-direct frames that were never freed (so the
// canary will mismatch benignly). After warm-up, mismatches at the same
// `phys` indicate UAF; sporadic single mismatches are boot-frame
// artifacts. The line includes the most-recent freer's caller_ra (from
// the existing `kdbg` pmm event ring) so investigation has a target.
const CANARY_PMM_MAGIC: u64 = 0x4646524545504D4D; // "FFREEPMM"
var canary_mismatch_count: u64 = 0;
// Per-frame "canary is valid for this frame" bitmap. Set by freeFrame's
// canary write, cleared by allocFrame's canary check (whether it matches
// or not — the next free→alloc cycle writes a fresh canary). Without
// this side-table the check fired on every first-use of high-PA frames
// that were FREE from boot but never freed (765 spam hits in the
// 2026-05-24 mtswap run). 1 bit per FRAME_SIZE PA = 32 KB BSS.
var canary_present: [BITMAP_SIZE]u32 = [_]u32{0} ** BITMAP_SIZE;

// Atomic RmW so concurrent free / alloc on different CPUs don't lose
// canary marks. A torn set or clear would produce false-negative UAF
// detection (mark dropped) or false-positive next-alloc check.
inline fn canaryBitSet(frame: u32) void {
    const bit: u32 = @as(u32, 1) << @intCast(frame & 31);
    _ = @atomicRmw(u32, &canary_present[frame / 32], .Or, bit, .monotonic);
}
inline fn canaryBitClear(frame: u32) void {
    const mask: u32 = ~(@as(u32, 1) << @intCast(frame & 31));
    _ = @atomicRmw(u32, &canary_present[frame / 32], .And, mask, .monotonic);
}
inline fn canaryBitGet(frame: u32) bool {
    const w = @atomicLoad(u32, &canary_present[frame / 32], .monotonic);
    return (w & (@as(u32, 1) << @intCast(frame & 31))) != 0;
}

/// Bulk-clear canary-present bits for a contiguous frame range. Used by
/// allocContiguous + freeContiguous to keep the canary state-machine
/// consistent across single-frame ↔ contiguous transitions. Without this,
/// a frame that bounces freeFrame → allocContiguous → contiguous-user-write
/// → freeContiguous → allocFrame keeps the canary-present bit set from the
/// first freeFrame (no path clears it), so the second allocFrame's check
/// fires on overwritten contiguous-user content — a flood of false-positive
/// UAFs (see 2026-05-25 ELF-page run, ~40 spurious hits in one boot).
inline fn canaryBitClearRange(start_frame: u32, count: u32) void {
    var f = start_frame;
    const end = start_frame + count;
    while (f < end) : (f += 1) {
        canaryBitClear(f);
    }
}

pub fn pmmCanaryMismatches() u64 {
    return @atomicLoad(u64, &canary_mismatch_count, .monotonic);
}

// === Public introspection for diagnostics + stress tests ===

/// Exposed region geometry so stress tests can compute the per-CPU
/// affinity score (frame → region → expected-region match).
pub const PUB_REGION_FRAMES: u32 = REGION_FRAMES;
pub const PUB_REGIONS_COUNT: u32 = REGIONS_COUNT;
pub const PUB_MAX_FRAMES: u32 = MAX_FRAMES;
pub const PUB_FRAME_SIZE: u32 = FRAME_SIZE;

/// Best-effort snapshot of a region's free count (the lock-free hint), for
/// "did this region get most of CPU N's allocs" affinity scoring. Returns
/// 0 for out-of-range region_idx.
pub fn pmmRegionFreeCount(region_idx: u32) u32 {
    if (region_idx >= REGIONS_COUNT) return 0;
    return hintFree(region_idx);
}

/// Regions [0, n) hold managed RAM; the rest are never walked.
pub fn pmmRegionsLive() u32 {
    return regions_live;
}

/// Free frames by the region hints. Equals freeFrameCount() whenever no
/// allocation or free is in flight.
pub fn indexFreeFrames() u32 {
    var sum: u32 = 0;
    for (0..regions_live) |ri| sum += hintFree(@intCast(ri));
    return sum;
}

// Tail-canary location: last 16 bytes of the frame (offset 0xFF0..0xFFF).
// Paired with the head canary at offset 0..15 so we can tell HEAD-only
// overwrites (struct header written at frame start) from FULL-FRAME
// overwrites (someone refilled the whole page) — different bug shapes.
const CANARY_TAIL_OFFSET: usize = FRAME_SIZE - 16;
const CANARY_TAIL_MAGIC: u64 = 0x4C49415446524545; // "EERFTAIL" reversed for "TAILFREE"

inline fn pmmCanaryWrite(phys: usize) void {
    const base = @import("paging.zig").physToVirt(phys);
    const head: *[2]u64 = @ptrFromInt(base);
    const tail: *[2]u64 = @ptrFromInt(base + CANARY_TAIL_OFFSET);
    const head_lo = phys ^ CANARY_PMM_MAGIC;
    const tail_lo = phys ^ CANARY_TAIL_MAGIC;
    head[0] = head_lo;
    head[1] = ~head_lo;
    tail[0] = tail_lo;
    tail[1] = ~tail_lo;
    canaryBitSet(@intCast(phys / FRAME_SIZE));
}

inline fn pmmCanaryCheck(phys: usize, callsite: []const u8, alloc_ra: usize) void {
    const frame: u32 = @intCast(phys / FRAME_SIZE);
    // Only check if a canary was actually written for this frame.
    // Eliminates the "boot-pristine high-PA frame" false-positive class
    // entirely; only frames that went through freeFrame are audited.
    if (!canaryBitGet(frame)) return;
    canaryBitClear(frame);
    const base = @import("paging.zig").physToVirt(phys);
    const head: *const [2]u64 = @ptrFromInt(base);
    const tail: *const [2]u64 = @ptrFromInt(base + CANARY_TAIL_OFFSET);
    const want_head_lo = phys ^ CANARY_PMM_MAGIC;
    const want_tail_lo = phys ^ CANARY_TAIL_MAGIC;
    const got_lo = head[0];
    const got_hi = head[1];
    const head_ok = (got_lo == want_head_lo and got_hi == ~want_head_lo);
    const tail_ok = (tail[0] == want_tail_lo and tail[1] == ~want_tail_lo);
    if (!head_ok or !tail_ok) {
        _ = @atomicRmw(u64, &canary_mismatch_count, .Add, 1, .monotonic);
        const serial = @import("../debug/serial.zig");
        const symbols = @import("../debug/symbols.zig");
        // head_ok / tail_ok distinguishes bug shape:
        //   HEAD bad + TAIL ok  → header-only overwrite (struct write at frame
        //                         start; small, targeted). Suspect: PT/PD entry
        //                         writes, slab-meta writes, FreshFile header.
        //   HEAD ok  + TAIL bad → tail-only overwrite (stack-bottom adjacency,
        //                         bottom-up scribble). Suspect: kstack overflow.
        //   HEAD bad + TAIL bad → full-frame rewrite. Suspect: DMA replay,
        //                         memcpy-into-freed-frame, page-recycled-but-
        //                         caller-still-has-ptr (UAF via large write).
        const shape = if (!head_ok and !tail_ok) "FULL" else if (!head_ok) "HEAD" else "TAIL";
        serial.print("[pmm-canary] !!! UAF !!! shape={s} phys=0x{X:0>16} from {s} (got lo=0x{X:0>16} hi=0x{X:0>16}) — alloc caller=", .{ shape, phys, callsite, got_lo, got_hi });
        if (symbols.resolveKernel(alloc_ra)) |r| {
            serial.print("{s}+0x{X}\n", .{ r.name, r.offset });
        } else {
            serial.print("0x{X}\n", .{alloc_ra});
        }
        // Walk the kdbg pmm_free_ring backwards (most-recent first) and
        // print the latest freer-RA for this phys. Tells us WHICH path freed
        // the frame whose contents now mismatch the canary — the missing
        // half of the UAF triangulation. Bounded scan, called only at the
        // moment of mismatch so cost is irrelevant.
        const kdbg = @import("../debug/kdbg.zig");
        const ring = &kdbg.pmm_free_ring;
        const n = ring.count();
        var found: bool = false;
        var idx: usize = n;
        while (idx > 0) {
            idx -= 1;
            const ev = ring.at(idx);
            if (ev.phys == phys) {
                serial.print("[pmm-canary]   last freer for this phys=", .{});
                if (symbols.resolveKernel(ev.caller_ra)) |r| {
                    serial.print("{s}+0x{X}\n", .{ r.name, r.offset });
                } else {
                    serial.print("0x{X}\n", .{ev.caller_ra});
                }
                found = true;
                break;
            }
        }
        if (!found) serial.print("[pmm-canary]   no freer event in ring for this phys (rotated out)\n", .{});
    }
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
/// Misnamed for historical reasons — this is the *currently free* frame
/// count, decremented on alloc and incremented on free. The post-init
/// snapshot is held in `managed_frames` so /proc/meminfo can report a
/// stable "total" without subtracting current usage from a moving target.
///
/// Atomic because per-region locks no longer serialize total_frames across
/// regions — a free in region A and an alloc in region B race on this u32.
/// Native-aligned u32 RmW (LOCK XADD) is cheap on x86 and serializes the
/// read-modify-write cleanly. Adjusted inside the same region critical
/// section that flips the bits: a freed frame is counted before any CPU can
/// take it, so satSubTotal never has to clamp.
var total_frames: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);

/// Saturating atomic subtraction: subtract `n` but clamp at 0 instead of
/// underflowing. Defensive — region accounting should keep total_frames
/// >= sum-of-subs at all times, but a single accounting bug shouldn't
/// flip the visible count to ~4 billion. CAS loop is uncontended in
/// practice (only the loser of a concurrent free races).
fn satSubTotal(n: u32) void {
    while (true) {
        const cur = total_frames.load(.monotonic);
        const new: u32 = if (cur >= n) cur - n else 0;
        if (cur == new) return;
        if (total_frames.cmpxchgWeak(cur, new, .monotonic, .monotonic) == null) return;
    }
}
/// Snapshot of the free-frame count at the moment PMM init finishes —
/// effectively the size of the usable PMM pool (free + about-to-be-allocated
/// kernel structures). Stable for the lifetime of the OS; used by meminfo.
var managed_frames: u32 = 0;

/// Kernel emergency reserve — number of frames that allocFrameUser refuses
/// to dip below, so user-driven faulting can never starve the kernel of
/// frames it needs for page tables, kstacks, etc. Set to 5% of managed
/// in init(). Kernel-internal callers use allocFrame() which doesn't check
/// the reserve; user-faulting paths use allocFrameUser() which does.
var pmm_user_reserve: u32 = 0;

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

// Highest usable-RAM end address consumed by init(), clamped to what the
// bitmap covers (MAX_FRAMES), so it is also the ceiling on any frame
// allocFrame can ever return.
// The IOMMU sizes its DMA identity-map span from this — a device must be
// able to reach every frame a driver can hand it.
var highest_usable_phys: usize = 0;

/// End of the highest usable RAM region PMM manages (exclusive). 0 before
/// init(). Every allocFrame result lies strictly below this.
pub fn highestUsablePhys() usize {
    return highest_usable_phys;
}

const KERNEL_PHYS_START: usize = 0x100000;

fn checkPhysSafety(phys: usize, op: []const u8) void {
    if (kernel_phys_end == 0) return; // pre-init; nothing to compare against
    if (phys >= KERNEL_PHYS_START and phys < kernel_phys_end) {
        const serial = @import("../debug/serial.zig");
        serial.print("\n!!! PMM POISON: {s} phys=0x{X} INSIDE kernel image [0x{X}..0x{X})\n", .{ op, phys, KERNEL_PHYS_START, kernel_phys_end });
        @panic("pmm poison: kernel-image physical frame touched by alloc/free");
    }
}

/// Mark [base, base+length) as free in the bitmap and the region indexes.
/// Used at init (single-threaded, no contention) AND at runtime by
/// paging.freeBackBuffer / paging.freeGuestFB (rare). Splits the range
/// per region; locks each region briefly.
pub fn markRegionFree(base: Phys, length: usize) void {
    markRegionFreeRaw(base.raw(), length);
}

/// Raw-address body of markRegionFree. init() calls this directly for the
/// boot memory map (raw firmware addresses; keeping the giant init body
/// free of Phys.of injections — LLVM Invalid-type round 7).
fn markRegionFreeRaw(base: usize, length: usize) void {
    var frame: u32 = @intCast(@min(base / FRAME_SIZE, MAX_FRAMES));
    const end_frame: u32 = @intCast(@min((base + length) / FRAME_SIZE, MAX_FRAMES));
    while (frame < end_frame) {
        const region_idx = regionForFrame(frame);
        const reg_start = regionStartFrame(region_idx);
        const chunk_end = @min(end_frame, reg_start + REGION_FRAMES);
        const h = regions[region_idx].acquireIrqSave();
        const freed = fi.markFree(regionWords(region_idx), h.ptr, frame - reg_start, chunk_end - frame);
        publishHint(region_idx, h.ptr);
        if (freed > 0) _ = total_frames.fetchAdd(freed, .monotonic);
        h.release();
        frame = chunk_end;
    }
}

/// Mark [base, base+length) as used in the bitmap and the region indexes.
/// Used at init AND at runtime by paging.allocBackBuffer /
/// paging.allocGuestFB.
pub fn markRegionUsed(base: Phys, length: usize) void {
    markRegionUsedRaw(base.raw(), length);
}

/// Raw-address body of markRegionUsed — see markRegionFreeRaw.
fn markRegionUsedRaw(base: usize, length: usize) void {
    var frame: u32 = @intCast(@min(base / FRAME_SIZE, MAX_FRAMES));
    const end_frame: u32 = @intCast(@min((base + length + FRAME_SIZE - 1) / FRAME_SIZE, MAX_FRAMES));
    while (frame < end_frame) {
        const region_idx = regionForFrame(frame);
        const reg_start = regionStartFrame(region_idx);
        const chunk_end = @min(end_frame, reg_start + REGION_FRAMES);
        const h = regions[region_idx].acquireIrqSave();
        const used = fi.markUsed(regionWords(region_idx), h.ptr, frame - reg_start, chunk_end - frame);
        publishHint(region_idx, h.ptr);
        if (used > 0) satSubTotal(used);
        h.release();
        frame = chunk_end;
    }
}

pub fn init(info: *const boot_info.BootInfo) void {
    // Register one representative region lock so the spinlock holder dump
    // can name it in a deadlock report. The 256 region locks are
    // intentionally anonymous — naming each one would clutter the
    // registry, and the lock-diag falls back to printing the pointer for
    // unregistered locks anyway.
    const spinlock = @import("../proc/spinlock.zig");
    spinlock.registerLock("pmm.r0", &regions[0].lock); // the Guarded's inner lock

    // Mark all frames as used initially
    for (&bitmap) |*word| {
        word.* = 0xFFFFFFFF;
    }
    @memset(&frame_refs, 0);
    total_frames.store(0, .monotonic);

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
    var lost_pages_cap: u64 = 0;
    const cap_bytes: u64 = @as(u64, MAX_FRAMES) * FRAME_SIZE;
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
        markRegionFreeRaw(base, length);
        // Only what the bitmap covers is usable: the IOMMU sizes its
        // identity span from this, and regions_live bounds every walk.
        const end: u64 = @min(@as(u64, base) + length, cap_bytes);
        if (end > @as(u64, base) and end > highest_usable_phys) highest_usable_phys = @intCast(end);
        if (@as(u64, base) + length > cap_bytes) lost_pages_cap += (@as(u64, base) + length - @max(@as(u64, base), cap_bytes)) / 4096;
        consumed += 1;
        if (region.base + region.length > 0x100000000) {
            // Region straddles 4GB — count the truncated tail
            lost_pages_high += (region.base + region.length - 0x100000000) / 4096;
        }
    }
    regions_live = @intCast(@min((highest_usable_phys / FRAME_SIZE + REGION_FRAMES - 1) / REGION_FRAMES, REGIONS_COUNT));
    const serial = @import("../debug/serial.zig");
    serial.print("[pmm] init: {d} regions consumed, {d} non-usable, {d} above 4GB; {d}/{d} pmm regions hold RAM\n", .{ consumed, skipped_kind, skipped_high, regions_live, REGIONS_COUNT });
    if (lost_pages_high > 0) {
        serial.print("[pmm] WARNING: {d} MB above 4GB not used (bitmap capped at 4GB)\n", .{lost_pages_high * 4 / 1024});
    }
    if (lost_pages_cap > 0) {
        serial.print("[pmm] WARNING: {d} MB above the {d} MB MAX_FRAMES cap not used\n", .{ lost_pages_cap * 4 / 1024, cap_bytes >> 20 });
    }
    if (regions_live == 0) @panic("pmm: no usable RAM below the MAX_FRAMES cap");

    // Mark reserved regions as used (see memmap.zig for the layout).
    // Clean-rule pass: only SINGLETON kernel infrastructure here; per-process
    // GUI FBs go through PMM allocation.
    markRegionUsedRaw(0x0, memmap.KERNEL_PHYS_START); // Low memory, BIOS, VGA
    // Kernel image: linker-defined low PA → kernelEndPhys. Runtime-derived
    // so kernel growth (more code, bigger BSS) is automatic; no manual memmap
    // bumps. PMM only protects the bytes the kernel actually uses.
    const kernel_end = memmap.kernelEndPhys();
    markRegionUsedRaw(memmap.KERNEL_PHYS_START, kernel_end - memmap.KERNEL_PHYS_START);
    kernel_phys_end = kernel_end; // arm tripwire — see checkPhysSafety
    markRegionUsedRaw(memmap.KERNEL_HEAP_BASE, memmap.KERNEL_HEAP_SIZE); // Kernel heap (16 MB)
    markRegionUsedRaw(memmap.GUEST_FB_BASE, memmap.GUEST_FB_SIZE); // Guest FB (8 MB)
    markRegionUsedRaw(memmap.BACK_BUFFER_BASE, memmap.BACK_BUFFER_SIZE); // Back buffer (8 MB)
    if (@import("../boot/boot_info.zig").is_uefi) {
        // UEFI page tables live at 0x1C00000..0x1C40000. See memmap.zig
        // (UEFI_PT_BASE) for the rationale — kasan.init's 32 MB shadow
        // alloc otherwise overwrites them and kernel halts on wild CR3.
        markRegionUsedRaw(memmap.UEFI_PT_BASE, memmap.UEFI_PT_SIZE);
    }

    // Lock in the post-markings free-frame count as the static "total" we
    // hand back from meminfo. Reservations done after this point (e.g.
    // KASAN shadow when enabled) will be accounted for as "used" against
    // this baseline rather than disappearing from the total.
    managed_frames = total_frames.load(.monotonic);

    // 5% of managed frames, capped at a sane absolute (don't tie up
    // 50 MB on a 1 GB host but also don't shrink below 256 frames =
    // 1 MB on a 24 MB host — that's where kernel page-table churn
    // alone can eat).
    const five_pct: u32 = managed_frames / 20;
    pmm_user_reserve = if (five_pct < 256) 256 else if (five_pct > 4096) 4096 else five_pct;
    @import("../debug/serial.zig").print("[pmm] kernel reserve = {d} frames ({d} KB)\n", .{ pmm_user_reserve, pmm_user_reserve * 4 });
}

/// Magazine-refilling alloc from one region. Caller passes its CpuLocal so
/// up to REFILL_BATCH extra frames land in the per-CPU magazine (capped by
/// its free room). Returns the phys addr of the frame given to the caller,
/// or null if the region has nothing to offer.
fn allocAndRefillFromRegion(region_idx: u32, cpu: *smp.CpuLocal) ?usize {
    const h = regions[region_idx].acquireIrqSave();
    defer h.release();
    const words = regionWords(region_idx);
    const base: usize = @as(usize, regionStartFrame(region_idx)) * FRAME_SIZE;

    const first = fi.allocOne(words, h.ptr) orelse return null;
    var taken: u32 = 1;
    while (taken <= REFILL_BATCH and cpu.pmm_cache_count < CACHE_SIZE) {
        const f = fi.allocOne(words, h.ptr) orelse break;
        cpu.pmm_cache[cpu.pmm_cache_count] = base + @as(usize, f) * FRAME_SIZE;
        cpu.pmm_cache_count += 1;
        taken += 1;
    }
    publishHint(region_idx, h.ptr);
    satSubTotal(taken);
    return base + @as(usize, first) * FRAME_SIZE;
}

/// Walk the regions that hold RAM from `start`, wrapping, and return the
/// first non-null `try_region` result. The first pass skips regions whose
/// free hint is below `need`; if it finds nothing, a second pass tries
/// every region under its lock, so a stale hint costs time, never a
/// spurious failure.
fn walkRegions(start: u32, need: u32, ctx: anytype, comptime try_region: fn (u32, @TypeOf(ctx)) ?usize) ?usize {
    const n = regions_live;
    if (n == 0) return null;
    for ([_]bool{ true, false }) |use_hint| {
        var off: u32 = 0;
        while (off < n) : (off += 1) {
            const ri = (start + off) % n;
            if (use_hint and hintFree(ri) < need) continue;
            if (try_region(ri, ctx)) |p| return p;
        }
    }
    return null;
}

pub fn allocFrame() ?Phys {
    const ra = @returnAddress();
    // IF off across cache access — guarantees no preemption / IRQ runs an
    // allocFrame on the same CPU's cache mid-pop. With per-CPU storage and
    // IF=0, no extra synchronisation is required. Per-region locks below
    // re-disable (no-op when already off) and pair release with the same
    // restore-to-off state.
    const irq_flags = saveAndDisableIrq();
    defer restoreIrq(irq_flags);

    const cpu = @import("../cpu/smp.zig").myCpu();
    if (cpu.pmm_cache_count > 0) {
        cpu.pmm_cache_count -= 1;
        const phys = cpu.pmm_cache[cpu.pmm_cache_count];
        checkPhysSafety(phys, "allocFrame(cache)");
        checkKstackOverlap(phys, 1, "allocFrame(cache)", ra);
        pmmCanaryCheck(phys, "allocFrame(cache)", ra);
        @import("../debug/kdbg.zig").pmmAlloc(phys, 1, ra);
        @import("../debug/kasan.zig").unpoison(phys, FRAME_SIZE);
        frame_refs[phys / FRAME_SIZE] = 1;
        return Phys.of(phys);
    }

    // Cache miss: preferred region first (per-CPU affinity = cache locality
    // on the bitmap line), then outward over the regions holding RAM.
    if (regions_live == 0) return null;
    const first = walkRegions(preferredRegion(cpu.cpu_id), 1, cpu, allocAndRefillFromRegion) orelse return null;

    checkPhysSafety(first, "allocFrame");
    checkKstackOverlap(first, 1, "allocFrame", ra);
    pmmCanaryCheck(first, "allocFrame(bitmap)", ra);
    @import("../debug/kdbg.zig").pmmAlloc(first, 1, ra);
    @import("../debug/kasan.zig").unpoison(first, FRAME_SIZE);
    frame_refs[first / FRAME_SIZE] = 1;
    return Phys.of(first);
}

/// Allocate a frame below 4GB (for DMA buffers that require 32-bit
/// addresses). Every managed frame is (comptime-checked above), so this is
/// allocFrame — with its canary/kstack/kdbg hooks, which the old
/// region-0-upward walk here skipped.
pub inline fn allocFrameBelow4G() ?Phys {
    // inline: allocFrame's @returnAddress keeps naming the real caller.
    return allocFrame();
}

/// Tripwire: does this phys range overlap kstack_pool? Used on the FREE
/// path — passing a kstack phys to freeFrame/freeContiguous marks the
/// underlying frame "free" so the next alloc returns it; the new owner
/// then zeroes/uses the page, clobbering a live kstack. There is no
/// legitimate path that frees a kstack frame (the pool's PMM block is
/// allocated once at boot in initKstackGuards and never freed), so any hit
/// is unambiguously a bug — @panic to catch the buggy caller in the backtrace.
fn checkKstackNotFreed(base: usize, count: u32, site: []const u8, ra: usize) void {
    const process_mod = @import("../proc/process.zig");
    // kstack_pool is PMM-backed in the physmap now; use its recorded phys base
    // + region size. Skip while 0 = the bootstrap window before initKstackGuards
    // has allocated the pool (the pool's OWN allocContiguous runs through here).
    const ks_phys_start = process_mod.kstack_pool_phys_base;
    if (ks_phys_start == 0) return;
    const ks_phys_end = ks_phys_start + process_mod.KSTACK_POOL_BYTES;
    const free_end = base + @as(usize, count) * FRAME_SIZE;
    if (base < ks_phys_end and free_end > ks_phys_start) {
        const symbols = @import("../debug/symbols.zig");
        const ser = @import("../debug/serial.zig");
        ser.print("\n[pmm-bad-free] !!! {s} releasing phys 0x{X}..0x{X} INSIDE kstack_pool [0x{X}..0x{X}) !!!\n", .{
            site, base, free_end, ks_phys_start, ks_phys_end,
        });
        if (symbols.resolveKernelNearest(@as(u64, ra))) |sym| {
            ser.print("[pmm-bad-free]   caller: {s}+0x{X}\n", .{ sym.name, sym.offset });
        } else {
            ser.print("[pmm-bad-free]   caller RA: 0x{X}\n", .{ra});
        }
        @panic("freeFrame on kstack_pool — kstack frame being treated as PMM-managed");
    }
}

/// Tripwire: does this phys range overlap kstack_pool (the PMM block,
/// allocated once at boot and never freed, that PMM must NEVER hand out
/// again — kstacks live there)? Range comes from kstack_pool_phys_base.
/// On hit, log the caller's RA + the bad phys; the next @memset via
/// physmap on this range will zero a live kstack — exactly the
/// netstat-desktop bug class.
fn checkKstackOverlap(base: usize, count: u32, site: []const u8, ra: usize) void {
    const process_mod = @import("../proc/process.zig");
    // kstack_pool is PMM-backed in the physmap now; use its recorded phys base
    // + region size. Skip while 0 = the bootstrap window before initKstackGuards
    // has allocated the pool (the pool's OWN allocContiguous runs through here).
    const ks_phys_start = process_mod.kstack_pool_phys_base;
    if (ks_phys_start == 0) return;
    const ks_phys_end = ks_phys_start + process_mod.KSTACK_POOL_BYTES;
    const alloc_end = base + @as(usize, count) * FRAME_SIZE;
    if (base < ks_phys_end and alloc_end > ks_phys_start) {
        const symbols = @import("../debug/symbols.zig");
        const ser = @import("../debug/serial.zig");
        ser.print("\n[pmm-bad-alloc] !!! {s} returned phys 0x{X}..0x{X} overlapping kstack_pool [0x{X}..0x{X}) !!!\n", .{
            site, base, alloc_end, ks_phys_start, ks_phys_end,
        });
        if (symbols.resolveKernelNearest(@as(u64, ra))) |sym| {
            ser.print("[pmm-bad-alloc]   caller: {s}+0x{X}\n", .{ sym.name, sym.offset });
        } else {
            ser.print("[pmm-bad-alloc]   caller RA: 0x{X}\n", .{ra});
        }
    }
}

/// Try to satisfy a contiguous alloc of `count` frames entirely within
/// `region_idx`. Returns base phys, or null if the region can't fit it.
fn allocContiguousFromRegion(region_idx: u32, count: u32) ?usize {
    const h = regions[region_idx].acquireIrqSave();
    defer h.release();
    const off = fi.allocRun(regionWords(region_idx), h.ptr, count) orelse return null;
    publishHint(region_idx, h.ptr);
    const start_frame = regionStartFrame(region_idx) + off;
    @memset(frame_refs[start_frame .. start_frame + count], 1);
    satSubTotal(count);
    return @as(usize, start_frame) * FRAME_SIZE;
}

/// Free frames at both ends of a region, for chaining runs across region
/// boundaries. One region lock, briefly.
const RegionEdges = struct { lead: u32, trail: u32 };

/// `.hinted` skips regions whose hint says empty and locks the rest one at a
/// time; `.held` reads regions the caller already holds (lockSpan).
const EdgeRead = enum { hinted, held };

fn regionEdges(region_idx: u32, how: EdgeRead) RegionEdges {
    const words = regionWords(region_idx);
    if (how == .held) {
        const s = regions[region_idx].refHeld();
        return .{ .lead = fi.leadingFree(words, s.*), .trail = fi.trailingFree(words, s.*) };
    }
    if (hintFree(region_idx) == 0) return .{ .lead = 0, .trail = 0 };
    const h = regions[region_idx].acquireIrqSave();
    defer h.release();
    return .{ .lead = fi.leadingFree(words, h.ptr.*), .trail = fi.trailingFree(words, h.ptr.*) };
}

/// Lock regions first..last in ascending order. The only multi-lock order in
/// the PMM (every other path holds one region lock), so deadlock-free. The
/// locks are taken directly (tokens for a whole span would burn kernel
/// stack); the state is reached through refHeld, which assertHeld-checks in
/// safe builds.
fn lockSpan(first: u32, last: u32) u64 {
    const flags = regions[first].lock.acquireIrqSave();
    var r: u32 = first + 1;
    while (r <= last) : (r += 1) regions[r].lock.acquire();
    return flags;
}

fn unlockSpan(first: u32, last: u32, flags: u64) void {
    var r: u32 = last;
    while (r > first) : (r -= 1) regions[r].lock.release();
    regions[first].lock.releaseIrqRestore(flags);
}

/// Lock the regions [start, start+count) spans and claim it. False if a
/// racing allocation got there first.
fn claimSpan(start: u32, count: u32) bool {
    const first = regionForFrame(start);
    const last = regionForFrame(start + count - 1);
    const flags = lockSpan(first, last);
    defer unlockSpan(first, last, flags);
    return claimHeld(start, count);
}

/// Claim [start, start+count) if all of it is still free. Caller holds every
/// region it spans.
fn claimHeld(start: u32, count: u32) bool {
    const first = regionForFrame(start);
    const last = regionForFrame(start + count - 1);
    const end = start + count;
    var r: u32 = first;
    while (r <= last) : (r += 1) {
        const rs = regionStartFrame(r);
        const lo = @max(start, rs);
        const hi = @min(end, rs + REGION_FRAMES);
        if (!fi.rangeFree(regionWords(r), lo - rs, hi - lo)) return false;
    }
    r = first;
    while (r <= last) : (r += 1) {
        const rs = regionStartFrame(r);
        const lo = @max(start, rs);
        const hi = @min(end, rs + REGION_FRAMES);
        const s = regions[r].refHeld();
        _ = fi.markUsed(regionWords(r), s, lo - rs, hi - lo);
        publishHint(r, s);
    }
    @memset(frame_refs[start..end], 1);
    satSubTotal(count);
    return true;
}

/// Contiguous allocation across region boundaries: every request larger
/// than a region, and smaller ones no single region could hold. Chains
/// per-region edge snapshots (one lock at a time) into a lowest-address
/// candidate, then claims just the regions it spans. A candidate lost to a
/// racing allocation restarts the scan. An empty scan or a third loss falls
/// back to scanning and claiming with every region held, so null means no
/// boundary-spanning run existed in one consistent state — per-CPU refills
/// that keep taking a candidate's head frames cannot fail the call.
fn allocContiguousCrossRegion(count: u32, max_frame: u32) ?usize {
    const end_region = @min(regions_live, (max_frame + REGION_FRAMES - 1) / REGION_FRAMES);
    if (end_region == 0) return null;
    // Near exhaustion most calls end here, before any lock.
    if (total_frames.load(.monotonic) < count) return null;
    var losses: u32 = 0;
    while (losses < 3) : (losses += 1) {
        const cand = findCrossRun(count, end_region, max_frame, .hinted) orelse break;
        if (claimSpan(cand, count)) return @as(usize, cand) * FRAME_SIZE;
    }
    _ = cross_held_scans.fetchAdd(1, .monotonic);
    const flags = lockSpan(0, end_region - 1);
    defer unlockSpan(0, end_region - 1, flags);
    const cand = findCrossRun(count, end_region, max_frame, .held) orelse return null;
    const claimed = claimHeld(cand, count);
    std.debug.assert(claimed); // edges and words come from one held state
    return @as(usize, cand) * FRAME_SIZE;
}

var cross_held_scans = std.atomic.Value(u32).init(0);

/// Cross-region allocations that needed the all-regions-held scan.
pub fn pmmCrossHeldScans() u32 {
    return cross_held_scans.load(.monotonic);
}

fn findCrossRun(count: u32, end_region: u32, max_frame: u32, how: EdgeRead) ?u32 {
    var run_start: u32 = 0;
    var run_len: u32 = 0;
    var ri: u32 = 0;
    while (ri < end_region) : (ri += 1) {
        const e = regionEdges(ri, how);
        const rs = regionStartFrame(ri);
        if (e.lead == REGION_FRAMES) {
            if (run_len == 0) run_start = rs;
            run_len += REGION_FRAMES;
        } else {
            // The run from below continues into this region's low frames.
            if (run_len > 0 and run_len + e.lead >= count) break;
            run_len = e.trail;
            run_start = rs + REGION_FRAMES - e.trail;
        }
        if (run_len >= count) break;
    } else return null;
    if (run_start + count > max_frame) return null;
    return run_start;
}

pub fn allocContiguous(count: u32) ?Phys {
    if (count == 0) return null;
    if (count == 1) return allocFrame();
    const ra = @returnAddress();

    var base_opt: ?usize = null;
    if (count <= REGION_FRAMES and regions_live != 0) {
        const pref = preferredRegion(smp.myCpu().cpu_id);
        base_opt = walkRegions(pref, count, count, allocContiguousFromRegion);
    }
    if (base_opt == null) {
        base_opt = allocContiguousCrossRegion(count, MAX_FRAMES);
    }
    const base = base_opt orelse return null;

    checkPhysSafety(base, "allocContiguous");
    const last: usize = base + (@as(usize, count) - 1) * FRAME_SIZE;
    if (last != base) checkPhysSafety(last, "allocContiguous(last)");
    checkKstackOverlap(base, count, "allocContiguous", ra);
    canaryBitClearRange(@intCast(base / FRAME_SIZE), count);
    @import("../debug/kdbg.zig").pmmAlloc(base, count, ra);
    @import("../debug/kasan.zig").unpoison(base, @as(usize, count) * FRAME_SIZE);
    return Phys.of(base);
}

/// Allocate `count` contiguous frames below 4GB (for DMA).
pub inline fn allocContiguousBelow4G(count: u32) ?Phys {
    // Every managed frame is below 4 GiB — see allocFrameBelow4G.
    return allocContiguous(count);
}

// Device-memory window (e.g. an NVDIMM's DAX frames) that is NOT PMM-managed
// and must never be reclaimed. When such frames are mapped into a user address
// space (DAX mmap) and that AS is torn down, unmapUserRange/destroyAddressSpace
// call freeFrame on every present leaf — including these. freeFrame consults
// this window (before its MAX_FRAMES bounds gate) and treats those frees as
// silent no-ops. Registered once at boot by pmem.init via registerDeviceRange.
var device_lo: usize = 0;
var device_hi: usize = 0;

/// Register a physical range as device memory that freeFrame must silently
/// ignore (not warn about). Used for NVDIMM DAX frames mapped into user space.
pub fn registerDeviceRange(base: Phys, len: usize) void {
    device_lo = base.raw();
    device_hi = base.raw() +| len;
}

pub fn freeFrame(phys: Phys) void {
    const ra = @returnAddress();
    const phys_addr: usize = phys.raw();
    const frame_num = phys_addr / FRAME_SIZE;
    // Registered device memory (NVDIMM DAX frames, etc.) is never PMM-managed —
    // ignore frees of it regardless of where the window sits relative to the RAM
    // bitmap. Checked BEFORE the MAX_FRAMES gate so a device range placed below
    // the RAM ceiling can't fall through into the normal refcount path and
    // corrupt the bitmap. The device_hi==0 short-circuit keeps this free when no
    // device range is registered (the common case).
    if (device_hi != 0 and phys_addr >= device_lo and phys_addr < device_hi) return;
    if (frame_num >= MAX_FRAMES) {
        @import("../debug/serial.zig").print("[pmm] WARNING: freeFrame bad addr=0x{X} (frame={X})\n", .{ phys_addr, frame_num });
        return;
    }
    checkKstackNotFreed(phys_addr, 1, "freeFrame", ra);

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
        const kdbg = @import("../debug/kdbg.zig");
        serial.print("[pmm] LEAK: freeFrame underflow phys=0x{X} caller=", .{phys_addr});
        if (symbols.resolveKernel(ra)) |r| {
            serial.print("{s}+0x{X}\n", .{ r.name, r.offset });
        } else {
            serial.print("0x{X}\n", .{ra});
        }
        // Walk the free/alloc rings to name the prior frees and last alloc.
        // Mass-double-free patterns (like 29 consecutive frames at exit) all
        // share one root: a stale parent table pointing into PMM-managed
        // memory that was reallocated to someone else. The ring tells us
        // WHO freed it the first time and WHO last allocated it.
        if (kdbg.pmmFindLastFree(phys_addr)) |prev| {
            serial.print("[pmm] LEAK:   prior-free caller=", .{});
            if (symbols.resolveKernel(prev.caller_ra)) |r| {
                serial.print("{s}+0x{X}", .{ r.name, r.offset });
            } else {
                serial.print("0x{X}", .{prev.caller_ra});
            }
            serial.print(" tsc=0x{X}\n", .{prev.tsc});
        } else {
            serial.print("[pmm] LEAK:   no prior-free event in ring\n", .{});
        }
        if (kdbg.pmmFindLastAlloc(phys_addr)) |alloc_ev| {
            serial.print("[pmm] LEAK:   last-alloc caller=", .{});
            if (symbols.resolveKernel(alloc_ev.caller_ra)) |r| {
                serial.print("{s}+0x{X}", .{ r.name, r.offset });
            } else {
                serial.print("0x{X}", .{alloc_ev.caller_ra});
            }
            serial.print(" tsc=0x{X} count={d}\n", .{ alloc_ev.tsc, alloc_ev.count });
        }
        return;
    }
    // old_ref == 1; we're the last owner. Proceed with the existing free path.

    // Tripwires BEFORE any bitmap or cache mutation so the panic backtrace
    // points at the bad caller, not whoever later draws the poisoned frame.
    checkPhysSafety(phys_addr, "freeFrame");
    @import("../debug/kdbg.zig").pmmFree(phys_addr, ra);
    @import("../debug/kasan.zig").poison(phys_addr, FRAME_SIZE, @import("../debug/kasan.zig").SHADOW_FREED);
    // S5 canary: stamp self-referencing magic at offset 0. If anyone
    // writes to this frame while it's free, the next alloc detects it.
    pmmCanaryWrite(phys_addr);

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

    // Cache full: drain DRAIN_BATCH back to their regions. Each drained
    // frame is routed to its source region (by phys) under that region's
    // lock, so drains to different regions don't serialize.
    var i: u32 = 0;
    while (i < DRAIN_BATCH) : (i += 1) {
        cpu.pmm_cache_count -= 1;
        const drain_phys = cpu.pmm_cache[cpu.pmm_cache_count];
        const drain_frame: u32 = @intCast(drain_phys / FRAME_SIZE);
        if (drain_frame >= MAX_FRAMES) continue;
        const region_idx = regionForFrame(drain_frame);
        const h = regions[region_idx].acquire();
        const freed = fi.markFree(regionWords(region_idx), h.ptr, drain_frame - regionStartFrame(region_idx), 1);
        publishHint(region_idx, h.ptr);
        if (freed > 0) _ = total_frames.fetchAdd(freed, .monotonic);
        h.release();
    }
    cpu.pmm_cache[cpu.pmm_cache_count] = phys_addr;
    cpu.pmm_cache_count += 1;
}

/// Free `count` contiguous frames starting at phys_addr. Single lock acquisition,
/// word-at-a-time clearing for the middle of the range. Replaces the
/// `for (0..n) freeFrame(...)` idiom that was scattered across many callsites
/// and took the spinlock + ran the kdbg/kasan hooks N times.
pub fn freeContiguous(phys: Phys, count: u32) void {
    if (count == 0) return;
    if (count == 1) {
        freeFrame(phys);
        return;
    }
    const ra = @returnAddress();
    const phys_addr: usize = phys.raw();
    const start_frame = phys_addr / FRAME_SIZE;
    if (start_frame + count > MAX_FRAMES) {
        @import("../debug/serial.zig").print("[pmm] WARNING: freeContiguous bad range start=0x{X} count={d}\n", .{ phys_addr, count });
        return;
    }
    checkKstackNotFreed(phys_addr, count, "freeContiguous", ra);

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
    canaryBitClearRange(@intCast(start_frame), count);
    @import("../debug/kdbg.zig").pmmFree(phys_addr, ra);
    @import("../debug/kasan.zig").poison(phys_addr, @as(usize, count) * FRAME_SIZE, @import("../debug/kasan.zig").SHADOW_FREED);

    // Split the range per region and free each chunk under its region's
    // lock. Most contiguous frees come from a single region (DMA buffer,
    // page-table pool, GUI FB slice); a run spanning a boundary is just two
    // chunks — the index needs no coalescing across them.
    var f: u32 = @intCast(start_frame);
    const end_frame: u32 = @intCast(start_frame + count);
    while (f < end_frame) {
        const region_idx = regionForFrame(f);
        const rs = regionStartFrame(region_idx);
        const chunk_end = @min(end_frame, rs + REGION_FRAMES);
        const h = regions[region_idx].acquireIrqSave();
        const freed = fi.markFree(regionWords(region_idx), h.ptr, f - rs, chunk_end - f);
        publishHint(region_idx, h.ptr);
        if (freed > 0) _ = total_frames.fetchAdd(freed, .monotonic);
        h.release();
        f = chunk_end;
    }
}

/// Free a range whose size is held as a `pages: u32` field — i.e. anything
/// that came back from `allocContiguous`, `allocContiguousBelow4G`, or
/// `allocContiguousUser`, OR a `FreshFile.buf` whose `.pages` count we
/// already know. Delegates to `freeContiguous` (which itself routes
/// `count==1` through `freeFrame`). The named purpose: lift the choice
/// "freeFrame in a loop vs freeContiguous" off the caller — the wrong
/// choice (loop) silently stamps spurious PMM canaries onto every page
/// of the bulk-allocated range and shows up later as fake UAF reports.
/// THIS IS THE CANONICAL "free a `pages: u32` block" API; reach for it
/// instead of writing a per-page free loop.
pub inline fn freeRange(phys_base: Phys, count: u32) void {
    freeContiguous(phys_base, count);
}

/// Add an owner to a contiguous run (a kernel buffer that fork hands to the
/// child). The owner count lives on the head frame; the rest stay at 1, so
/// freeContiguous still trips on a run released more times than it was owned.
pub fn shareContiguous(phys: Phys) void {
    acquireFrame(phys);
}

/// Drop one owner of a run from allocContiguous*; the last owner frees it
/// exactly as freeContiguous does. Inline so the free is attributed to the
/// real caller.
pub inline fn releaseContiguous(phys: Phys, count: u32) void {
    const head = phys.raw() / FRAME_SIZE;
    if (count > 1 and head < MAX_FRAMES) {
        while (true) {
            const cur = @atomicLoad(u8, &frame_refs[head], .acquire);
            if (cur <= 1) break;
            if (@cmpxchgWeak(u8, &frame_refs[head], cur, cur - 1, .acq_rel, .acquire) == null) return;
        }
    }
    freeContiguous(phys, count);
}

pub fn freeFrameCount() u32 {
    return total_frames.load(.monotonic);
}

/// The kernel emergency reserve, in frames: allocFrameUser refuses to allocate
/// once free <= this. Exposed so the swap reclaim path can evict ENOUGH cold
/// pages to lift free back ACROSS the reserve — a fresh user fault otherwise
/// can't allocate after swap-ins (which use the reserve-exempt allocFrame)
/// have driven free below it.
pub fn userReserveFrames() u32 {
    return pmm_user_reserve;
}

/// User-faulting variant of allocFrame. Refuses to dip below the kernel
/// emergency reserve so a runaway user app can't exhaust PMM to the
/// point where the kernel itself can't allocate page tables / kstacks
/// / etc., which is when we previously saw mapUserPage wedge while
/// spinning under PMM contention. Returns null when the would-be
/// post-alloc free count is at or below the reserve — caller must
/// surface that as ENOMEM to userspace and let the process die.
pub fn allocFrameUser() ?Phys {
    if (total_frames.load(.monotonic) <= pmm_user_reserve) return null;
    return allocFrame();
}

/// User-faulting variant of allocContiguous. Same reserve check —
/// big mmap-with-fd requests fail cleanly when PMM is tight rather
/// than starving the kernel.
pub fn allocContiguousUser(count: u32) ?Phys {
    if (total_frames.load(.monotonic) <= pmm_user_reserve + count) return null;
    return allocContiguous(count);
}

/// Total frames managed by PMM, snapshotted at end of init(). Stable for
/// the OS lifetime — every later alloc/free moves frames between "free"
/// and "in use" but never changes this number.
pub fn managedFrameCount() u32 {
    return managed_frames;
}

/// Add a reference to a frame currently in use. Used by COW: cloneAddressSpace
/// shares parent's data frames with child by bumping refcount instead of copying.
/// CMPXCHG loop catches saturation explicitly (255 references = fork bomb depth
/// 256, well past anything realistic; panic instead of wrapping silently).
pub fn acquireFrame(phys: Phys) void {
    const phys_addr: usize = phys.raw();
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

/// Conditional acquireFrame: bump the refcount ONLY if the frame is currently
/// live (refcount >= 1); return false — count untouched — when it is free.
/// For lock-free walkers that sampled a PTE and must take a reference on the
/// frame it named WITHOUT trusting the sample to still be current
/// (cloneAddressSpace vs a concurrent eviction: plain acquireFrame would
/// panic on the freed frame — or worse, silently bump a reallocated
/// STRANGER's frame). Contract: after a `true` return the caller re-validates
/// its PTE sample and releases on mismatch; a `true` + unchanged-PTE pair
/// proves continuous ownership (every unmap/evict path rewrites the PTE
/// before dropping its reference). Saturation panics, same as acquireFrame.
pub fn acquireFrameIfLive(phys: Phys) bool {
    const phys_addr: usize = phys.raw();
    const frame_num_us = phys_addr / FRAME_SIZE;
    if (frame_num_us >= MAX_FRAMES) return false;
    const frame_num: u32 = @intCast(frame_num_us);
    while (true) {
        const cur = @atomicLoad(u8, &frame_refs[frame_num], .acquire);
        if (cur == 0) return false;
        if (cur == 0xFF) {
            @import("../debug/serial.zig").print("[pmm] PANIC: acquireFrameIfLive saturation phys=0x{X}\n", .{phys_addr});
            @panic("pmm: acquireFrame refcount saturation (>255)");
        }
        if (@cmpxchgWeak(u8, &frame_refs[frame_num], cur, cur + 1, .acq_rel, .acquire) == null) return true;
    }
}

/// Drop one reference to a frame; if refcount hits 0, returns the frame to the
/// free pool. Functionally identical to freeFrame — both decrement and free-
/// when-zero. Use this name when releasing a COW-shared frame to make intent
/// explicit (the caller knows the frame may have other references).
pub inline fn releaseFrame(phys: Phys) void {
    return freeFrame(phys);
}

/// Read current refcount for a frame. Diagnostic only — racy under SMP. Useful
/// for /proc/meminfo, kdbg autopsy, and unit tests.
pub fn frameRefCount(phys: Phys) u8 {
    const phys_addr: usize = phys.raw();
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

// =============================================================================
// Reclaim registry — modules with reclaimable caches (GUI back-buffers,
// scrollback rings, etc.) register a callback that PMM can invoke when
// a caller hits an allocation failure. Each callback returns the number
// of frames it freed; PMM totals them and the caller decides whether to
// retry the alloc or escalate to OOM-kill.
//
// Why opt-in by caller and not inside allocFrame/allocContiguous: the
// allocator holds its own internal lock, and reclaim callbacks may
// re-enter the allocator via freeContiguous. Caller-driven reclaim runs
// outside the alloc-lock critical section, sidestepping the recursion.
// Callers that don't care about reclaim (boot-time, kernel-internal)
// just see the orelse return as before.
//
// Registration is one-shot per module at boot — typically from main.zig
// after the subsystem (desktop, fs, etc.) is up.
// =============================================================================

pub const ReclaimFn = *const fn (needed: u32) u32;

const MAX_RECLAIMERS: usize = 4;
var reclaim_fns: [MAX_RECLAIMERS]?ReclaimFn = [_]?ReclaimFn{null} ** MAX_RECLAIMERS;
var reclaim_count: u8 = 0;

pub fn registerReclaim(f: ReclaimFn) void {
    if (reclaim_count >= MAX_RECLAIMERS) return;
    reclaim_fns[reclaim_count] = f;
    reclaim_count += 1;
}

/// Walk every registered reclaim callback, return total frames freed.
/// Stops early if a callback frees more than `needed`. Logs the result
/// so post-mortems can see whether reclaim was effective.
pub fn tryReclaim(needed: u32) u32 {
    var freed: u32 = 0;
    var i: u8 = 0;
    while (i < reclaim_count) : (i += 1) {
        const f = reclaim_fns[i] orelse continue;
        if (freed >= needed) break;
        freed += f(needed -| freed);
    }
    if (freed > 0) {
        const debug = @import("../debug/debug.zig");
        debug.klog("[reclaim] needed={d} freed={d} pmm_free now {d}/{d}\n", .{
            needed, freed, freeFrameCount(), managedFrameCount(),
        });
    }
    return freed;
}

/// Every region's index against its bitmap words: the summary recomputed
/// from the words must equal the stored one (frame_index.verify), and the
/// lock-free hint must equal the stored free count. Exact, unlike the
/// run-list validator this replaces, which could only spot-check run
/// endpoints and never saw overlapping or orphaned runs. One region lock
/// at a time, briefly; regions without RAM must stay all-used and empty
/// (checked without the rebuild — pcb_invariants runs this every second).
pub fn validateIndex() bool {
    const serial = @import("../debug/serial.zig");
    var ok = true;
    var ri: u32 = 0;
    while (ri < REGIONS_COUNT) : (ri += 1) {
        const h = regions[ri].acquireIrqSave();
        const stored = h.ptr.*;
        const want: fi.Summary = if (ri < regions_live) fi.rebuild(regionWords(ri)) else .{};
        const hint = hintFree(ri);
        h.release();
        if (want.nonfull != stored.nonfull or want.allfree != stored.allfree or want.free_count != stored.free_count) {
            serial.print("[pmm] index-inv: region {d} stored nonfull=0x{X} allfree=0x{X} free={d}, words say 0x{X} 0x{X} {d}\n", .{
                ri, stored.nonfull, stored.allfree, stored.free_count, want.nonfull, want.allfree, want.free_count,
            });
            ok = false;
        }
        if (hint != stored.free_count) {
            serial.print("[pmm] index-inv: region {d} hint={d} but free={d}\n", .{ ri, hint, stored.free_count });
            ok = false;
        }
        if (ri >= regions_live and stored.free_count != 0) {
            serial.print("[pmm] index-inv: region {d} beyond RAM has {d} free frames\n", .{ ri, stored.free_count });
            ok = false;
        }
    }
    return ok;
}
