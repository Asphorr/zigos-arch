const std = @import("std");
const vga = @import("../driver.zig").vga;
const Guarded = @import("../util/guarded.zig").Guarded;
const memmap = @import("memmap.zig");
const smp = @import("../cpu/smp.zig");
/// pub: boot-plumbing callers (pmem.registerDeviceRange) reach the type as
/// `pmm.Phys` instead of adding an @import edge of their own — a new edge
/// re-rolls the LLVM Invalid-type dice (round 7, 2026-09-16).
pub const Phys = @import("../util/addr.zig").Phys;

const FRAME_SIZE: u32 = 4096;

// === Region-bucketed bitmap with per-CPU affinity + a per-region index ===
//
// The bitmap is the ground truth (canary/kasan/refcount/kstack tripwires
// all key off it). Around it:
//
//   1. REGIONS — physical memory, from address 0 to the end of the highest
//      usable RAM, split into regions of REGION_FRAMES frames, each behind
//      its own lock. SMP allocs and frees on different regions proceed in
//      parallel. A region over a hole in the memory map simply has no free
//      frame, ever.
//
//   2. INDEX — per region, two masks over its bitmap words (nonfull,
//      allfree) plus the free count, all derived from the words and kept
//      in step by src/mm/frame_index.zig (host-tested: tools/pmm-test).
//      A free frame or a free run is found with a few ctz/AND steps, and
//      the index cannot go stale against the bitmap the way the old
//      run-list layer could (orphaned or overlapping runs).
//
//   3. ZONES — the regions below 4 GiB (`low`) and the rest (`high`). A
//      request that does not care is served from `high` while it has
//      frames, so the frames a 32-bit DMA address reaches last for the
//      callers that ask for them (the Below4G entry points).
//
//   4. PER-CPU PREFERRED REGION — derived from cpu_id, not stored. Magazine
//      refill and contiguous alloc start at the preferred region of a zone
//      and walk outward over it, skipping full regions by hint.
//
// Nothing here is sized at build time: init() reads the top of RAM from the
// memory map and has memmap place one block for all the tables below.
const REGION_FRAMES: u32 = 1024; // 4 MB per region
const REGION_WORDS: u32 = REGION_FRAMES / 32; // bitmap words per region

/// The physmap is how the kernel reaches a frame; RAM past it is not used.
const MAX_PHYS: u64 = memmap.PHYSMAP_SIZE;
/// First region of the `high` zone, when RAM reaches that far.
const LOW_END_REGION: u32 = @intCast(memmap.LOW_LIMIT / FRAME_SIZE / REGION_FRAMES);

const fi = @import("frame_index.zig");

comptime {
    if (REGION_WORDS != fi.WORDS or REGION_FRAMES != fi.FRAMES) {
        @compileError("a pmm region must be exactly one frame_index region");
    }
    if (memmap.LOW_LIMIT % (@as(u64, REGION_FRAMES) * FRAME_SIZE) != 0) {
        @compileError("the zones split on a region boundary");
    }
    // Frame numbers are u32.
    if (MAX_PHYS / FRAME_SIZE > std.math.maxInt(u32)) @compileError("frame numbers are u32");
}

/// One past the last frame the tables describe; a multiple of REGION_FRAMES.
/// 0 before init().
var frames_end: u32 = 0;

/// Per-region index, behind its lock as Guarded(fi.Summary)
/// (util/guarded.zig): reaching it takes a token, so "caller must hold the
/// region's lock" is a type, not a comment.
///
/// Each region owns a REGION_FRAMES-frame slice of the GLOBAL bitmap
/// (`regionWords`). The slice is touched only under this region's lock,
/// exactly like the summary, but it cannot move into the blob: one array,
/// region-striped.
var regions: []Guarded(fi.Summary) = &.{};

inline fn regionWords(region_idx: u32) *[REGION_WORDS]u32 {
    return bitmap[region_idx * REGION_WORDS ..][0..REGION_WORDS];
}

/// Free frames per region, stored under the region lock and read without
/// it: the allocation walks skip a region whose hint says it cannot help.
/// Only a hint — every walk that comes up empty repeats with the locks.
var free_hint: []u16 = &.{};

comptime {
    if (REGION_FRAMES > std.math.maxInt(u16)) @compileError("free_hint is u16");
}

inline fn publishHint(region_idx: u32, s: *const fi.Summary) void {
    @atomicStore(u16, &free_hint[region_idx], @intCast(s.free_count), .monotonic);
}

inline fn hintFree(region_idx: u32) u32 {
    return @atomicLoad(u16, &free_hint[region_idx], .monotonic);
}

/// The regions: [0, regions_live). Set in init().
var regions_live: u32 = 0;

inline fn regionForFrame(frame: u32) u32 {
    return frame / REGION_FRAMES;
}

inline fn regionStartFrame(region_idx: u32) u32 {
    return region_idx * REGION_FRAMES;
}

/// Regions [first, end).
const Zone = struct {
    first: u32,
    end: u32,

    inline fn len(self: Zone) u32 {
        return self.end - self.first;
    }
};

/// Below 4 GiB.
inline fn lowZone() Zone {
    return .{ .first = 0, .end = @min(regions_live, LOW_END_REGION) };
}

/// From 4 GiB up; empty on a machine whose RAM ends below.
inline fn highZone() Zone {
    return .{ .first = @min(regions_live, LOW_END_REGION), .end = regions_live };
}

inline fn allZones() Zone {
    return .{ .first = 0, .end = regions_live };
}

/// Which frames a request may be given.
const Reach = enum {
    /// Any frame; `high` first.
    any,
    /// Below 4 GiB only: the address goes into a 32-bit register or
    /// descriptor field.
    low,

    /// The zones to try, in order.
    inline fn zones(self: Reach) [2]Zone {
        return switch (self) {
            .any => .{ highZone(), lowZone() },
            .low => .{ lowZone(), .{ .first = 0, .end = 0 } },
        };
    }
};

/// Regions between the preferred regions of two neighbouring CPUs: 128 MB.
const CPU_STRIDE: u32 = 32;

/// A CPU's preferred region in a zone: CPUs spread CPU_STRIDE apart, folded
/// into the zone. The walks go outward from there and wrap. `zone` is not
/// empty.
inline fn preferredRegion(cpu_id: u8, zone: Zone) u32 {
    return zone.first + (@as(u32, cpu_id) * CPU_STRIDE) % zone.len();
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
// 2026-05-24 mtswap run). 1 bit per frame.
var canary_present: []u32 = &.{};

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
pub const PUB_FRAME_SIZE: u32 = FRAME_SIZE;

/// Best-effort snapshot of a region's free count (the lock-free hint), for
/// "did this region get most of CPU N's allocs" affinity scoring. Returns
/// 0 for out-of-range region_idx.
pub fn pmmRegionFreeCount(region_idx: u32) u32 {
    if (region_idx >= regions_live) return 0;
    return hintFree(region_idx);
}

/// The regions are [0, n).
pub fn pmmRegionsLive() u32 {
    return regions_live;
}

/// Of them, [0, n) are below 4 GiB.
pub fn pmmRegionsLow() u32 {
    return lowZone().end;
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
        @import("vmm.zig").reportUafFrame(phys);
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
var bitmap: []u32 = &.{};
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

// Per-frame reference count. Lockstep invariant: frame_refs[i] == 0 ⟺
// bitmap-says-free OR sitting in some CPU's magazine cache; frame_refs[i] >= 1 ⟺
// allocated, with that many owners (address spaces mapping it, the page
// cache, a reader's pin). Atomic ops handle SMP without a lock — alloc paths
// set non-atomically (single owner during alloc), but acquireFrame from COW
// clone runs in parallel with potential frees on other CPUs.
//
// 32 bits so that no workload can run it out: every mapping of a frame is a
// VMA page, and all the VMAs of all the processes are far fewer than 2^32.
pub const RefCount = u32;
var frame_refs: []RefCount = &.{};

extern var _kernel_end: u8;

// Cached kernel-image physical range. Set in init(). Used by the wild-writer
// tripwire (checkPhysSafety) — if any alloc returns or any free targets a
// frame inside it, the bitmap has been corrupted or
// a caller is freeing a frame that backs kernel .text/.rodata/.data/.bss.
// Either way, that's the PMM-poisoning bug we're hunting: a buggy free-path
// hands kernel BSS frames back to the free list, then a later allocContiguous
// for an ELF/sector buffer copies file contents over kernel memory and the
// result is a "wild writer" with file-content-shaped payload (e.g. the
// "fetch_um" bytes from a Zig binary's .strtab).
var kernel_image: memmap.Range = .{};

// End of the highest usable RAM init() took, so also the ceiling on any
// frame allocFrame can ever return.
// The IOMMU sizes its DMA identity-map span from this — a device must be
// able to reach every frame a driver can hand it.
var highest_usable_phys: usize = 0;

/// End of the highest usable RAM region PMM manages (exclusive). 0 before
/// init(). Every allocFrame result lies strictly below this.
pub fn highestUsablePhys() usize {
    return highest_usable_phys;
}

fn checkPhysSafety(phys: usize, op: []const u8) void {
    // Empty before init: contains nothing.
    if (kernel_image.contains(phys)) {
        const serial = @import("../debug/serial.zig");
        serial.print("\n!!! PMM POISON: {s} phys=0x{X} INSIDE kernel image [0x{X}..0x{X})\n", .{ op, phys, kernel_image.base, kernel_image.end() });
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
    var frame: u32 = @intCast(@min(base / FRAME_SIZE, frames_end));
    const end_frame: u32 = @intCast(@min((base + length) / FRAME_SIZE, frames_end));
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
    var frame: u32 = @intCast(@min(base / FRAME_SIZE, frames_end));
    const end_frame: u32 = @intCast(@min((base + length + FRAME_SIZE - 1) / FRAME_SIZE, frames_end));
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

/// Where each table sits in the one block init() has memmap place.
const TableLayout = struct {
    words: usize, // of the bitmap, and of canary_present
    region_count: usize,
    canary_off: usize,
    refs_off: usize,
    regions_off: usize,
    hints_off: usize,
    bytes: usize,

    fn of(frames: u32) TableLayout {
        const Region = Guarded(fi.Summary);
        const words: usize = frames / 32;
        const region_count: usize = frames / REGION_FRAMES;
        const canary_off = words * @sizeOf(u32); // the bitmap is first
        const refs_off = canary_off + words * @sizeOf(u32);
        const regions_off = std.mem.alignForward(usize, refs_off + @as(usize, frames) * @sizeOf(RefCount), @alignOf(Region));
        const hints_off = regions_off + region_count * @sizeOf(Region);
        return .{
            .words = words,
            .region_count = region_count,
            .canary_off = canary_off,
            .refs_off = refs_off,
            .regions_off = regions_off,
            .hints_off = hints_off,
            .bytes = std.mem.alignForward(usize, hints_off + region_count * @sizeOf(u16), FRAME_SIZE),
        };
    }
};

/// After memmap.init: the memory map and what the kernel already holds come
/// from there.
pub fn init() void {
    const serial = @import("../debug/serial.zig");
    const map = memmap.bootMap();
    if (map.len == 0) @panic("No memory map!");

    // The top of usable RAM is how far the tables go.
    var top: u64 = 0;
    var usable_regions: u32 = 0;
    var high_bytes: u64 = 0;
    var unreachable_bytes: u64 = 0;
    for (map) |region| {
        if (region.kind != .usable) continue;
        usable_regions += 1;
        // Wholly above the physmap: not ours, and not the top of anything.
        if (region.base >= MAX_PHYS) {
            unreachable_bytes += region.length;
            continue;
        }
        const end: u64 = region.base +| region.length;
        if (end > MAX_PHYS) unreachable_bytes += end - MAX_PHYS;
        const reach: u64 = @min(end, MAX_PHYS);
        if (reach > memmap.LOW_LIMIT) high_bytes += reach - @max(region.base, memmap.LOW_LIMIT);
        top = @max(top, reach);
    }
    if (top <= memmap.LOW_MEMORY_END) @panic("pmm: no usable RAM");
    highest_usable_phys = @intCast(top);
    regions_live = @intCast((top / FRAME_SIZE + REGION_FRAMES - 1) / REGION_FRAMES);
    frames_end = regions_live * REGION_FRAMES;

    const layout = TableLayout.of(frames_end);
    const block = memmap.claim("pmm-tables", layout.bytes, .high) orelse @panic("pmm: no usable RAM for the frame tables");
    const tables = @import("paging.zig").physToVirt(block.base);
    bitmap = @as([*]u32, @ptrFromInt(tables))[0..layout.words];
    canary_present = @as([*]u32, @ptrFromInt(tables + layout.canary_off))[0..layout.words];
    frame_refs = @as([*]RefCount, @ptrFromInt(tables + layout.refs_off))[0..frames_end];
    regions = @as([*]Guarded(fi.Summary), @ptrFromInt(tables + layout.regions_off))[0..layout.region_count];
    free_hint = @as([*]u16, @ptrFromInt(tables + layout.hints_off))[0..layout.region_count];

    // Every frame used until the map says otherwise.
    @memset(bitmap, 0xFFFF_FFFF);
    @memset(canary_present, 0);
    @memset(frame_refs, 0);
    for (regions) |*r| r.* = .init(.{});
    @memset(free_hint, 0);
    total_frames.store(0, .monotonic);

    // Register one representative region lock so the spinlock holder dump
    // can name it in a deadlock report. The region locks are intentionally
    // anonymous — naming each one would clutter the registry, and the
    // lock-diag falls back to printing the pointer for unregistered locks
    // anyway.
    const spinlock = @import("../proc/spinlock.zig");
    spinlock.registerLock("pmm.r0", &regions[0].lock); // the Guarded's inner lock

    for (map) |region| {
        if (region.kind != .usable) continue;
        // Whole frames only: a map entry need not start or end on one.
        const first: u64 = std.mem.alignForward(u64, region.base, FRAME_SIZE);
        const last: u64 = @min(region.base +| region.length, MAX_PHYS);
        if (last > first) markRegionFreeRaw(@intCast(first), @intCast(last - first));
    }
    serial.print("[pmm] init: {d} usable regions up to 0x{X}, {d} MB of them above 4 GiB; {d} regions ({d} low), tables {d} KB at 0x{X}\n", .{
        usable_regions, top, high_bytes >> 20, regions_live, lowZone().end, layout.bytes >> 10, block.base,
    });
    if (unreachable_bytes > 0) {
        serial.print("[pmm] WARNING: {d} MB above the physmap's {d} GB not used\n", .{ unreachable_bytes >> 20, MAX_PHYS >> 30 });
    }

    // What the map calls usable but the kernel holds for its whole life
    // (memmap.zig): the image, the loader's page tables (a kasan shadow
    // allocated over them is a wild CR3 with no panic), the graphics
    // buffers, these tables. Per-process GUI FBs are allocated.
    markRegionUsedRaw(0x0, memmap.LOW_MEMORY_END);
    kernel_image = memmap.kernelImagePhys(); // arms checkPhysSafety
    for (memmap.held()) |h| markRegionUsedRaw(h.range.base, h.range.size);

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

/// One frame from one region, nothing for the magazine.
fn allocOneFromRegion(region_idx: u32, _: void) ?usize {
    const h = regions[region_idx].acquireIrqSave();
    defer h.release();
    const f = fi.allocOne(regionWords(region_idx), h.ptr) orelse return null;
    publishHint(region_idx, h.ptr);
    satSubTotal(1);
    return (@as(usize, regionStartFrame(region_idx)) + f) * FRAME_SIZE;
}

/// Walk a zone from this CPU's preferred region, wrapping, and return the
/// first non-null `try_region` result. `by_hint` skips the regions whose
/// free hint is below `need`, without taking their locks.
fn walkZone(zone: Zone, need: u32, by_hint: bool, ctx: anytype, comptime try_region: fn (u32, @TypeOf(ctx)) ?usize) ?usize {
    const n = zone.len();
    if (n == 0) return null;
    const start = preferredRegion(smp.myCpu().cpu_id, zone) - zone.first;
    var off: u32 = 0;
    while (off < n) : (off += 1) {
        const ri = zone.first + (start + off) % n;
        if (by_hint and hintFree(ri) < need) continue;
        if (try_region(ri, ctx)) |p| return p;
    }
    return null;
}

/// walkZone over the zones `reach` allows, in its order: by hint over all
/// of them, and only if that finds nothing, every region under its lock —
/// a stale hint costs time, never a spurious failure. A full zone ahead of
/// one with room is thus passed at the price of reading its hints.
fn walkReach(reach: Reach, need: u32, ctx: anytype, comptime try_region: fn (u32, @TypeOf(ctx)) ?usize) ?usize {
    for ([_]bool{ true, false }) |by_hint| {
        for (reach.zones()) |zone| {
            if (walkZone(zone, need, by_hint, ctx, try_region)) |p| return p;
        }
    }
    return null;
}

/// The checks and bookkeeping every single frame gets on its way out.
inline fn handOut(phys: usize, comptime site: []const u8, ra: usize) Phys {
    checkPhysSafety(phys, site);
    checkKstackOverlap(phys, 1, site, ra);
    pmmCanaryCheck(phys, site, ra);
    @import("../debug/kdbg.zig").pmmAlloc(phys, 1, ra);
    @import("../debug/kasan.zig").unpoison(phys, FRAME_SIZE);
    frame_refs[phys / FRAME_SIZE] = 1;
    return Phys.of(phys);
}

fn allocOne(reach: Reach, ra: usize) ?Phys {
    // IF off across cache access — guarantees no preemption / IRQ runs an
    // allocFrame on the same CPU's cache mid-pop. With per-CPU storage and
    // IF=0, no extra synchronisation is required. Per-region locks below
    // re-disable (no-op when already off) and pair release with the same
    // restore-to-off state.
    const irq_flags = saveAndDisableIrq();
    defer restoreIrq(irq_flags);

    // The magazine holds frames from anywhere, so a `low` request passes it
    // by on a machine that has a `high` zone. Rare: a driver's rings, once.
    if (reach == .low and highZone().len() != 0) {
        const phys = walkReach(.low, 1, {}, allocOneFromRegion) orelse return null;
        return handOut(phys, "allocFrame(low)", ra);
    }

    const cpu = smp.myCpu();
    if (cpu.pmm_cache_count > 0) {
        cpu.pmm_cache_count -= 1;
        return handOut(cpu.pmm_cache[cpu.pmm_cache_count], "allocFrame(cache)", ra);
    }

    // Cache miss: preferred region first (per-CPU affinity = cache locality
    // on the bitmap line), then outward over the zone, then the next zone.
    const first = walkReach(.any, 1, cpu, allocAndRefillFromRegion) orelse return null;
    return handOut(first, "allocFrame(bitmap)", ra);
}

pub fn allocFrame() ?Phys {
    return allocOne(.any, @returnAddress());
}

/// A frame below 4 GiB: its address goes into a 32-bit register or
/// descriptor field of a device.
pub fn allocFrameBelow4G() ?Phys {
    return allocOne(.low, @returnAddress());
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

/// Regions the fallback of allocContiguousCrossRegion holds at once: 1 GB.
const HELD_WINDOW: u32 = 256;

/// Contiguous allocation across region boundaries inside `zone`: every
/// request larger than a region, and smaller ones no single region could
/// hold. Chains per-region edge snapshots (one lock at a time) into a
/// lowest-address candidate, then claims just the regions it spans. A
/// candidate lost to a racing allocation restarts the scan. An empty scan
/// or a third loss falls back to scanning and claiming with the regions
/// held, a window of them at a time, so null means no window held such a
/// run in one consistent state — per-CPU refills that keep taking a
/// candidate's head frames cannot fail the call.
fn allocContiguousCrossRegion(count: u32, zone: Zone) ?usize {
    if (zone.len() == 0) return null;
    // Near exhaustion most calls end here, before any lock.
    if (total_frames.load(.monotonic) < count) return null;
    var losses: u32 = 0;
    while (losses < 3) : (losses += 1) {
        const cand = findCrossRun(count, zone, .hinted) orelse break;
        if (claimSpan(cand, count)) return @as(usize, cand) * FRAME_SIZE;
    }
    _ = cross_held_scans.fetchAdd(1, .monotonic);
    // A run of `count` frames touches at most `span` regions. Windows
    // overlap by that much, so every run lies whole in one of them.
    const span: u32 = (count - 1) / REGION_FRAMES + 2;
    const window: u32 = @max(HELD_WINDOW, 2 * span);
    var next = zone.first;
    while (true) {
        const held: Zone = .{ .first = next, .end = @min(zone.end, next +| window) };
        const flags = lockSpan(held.first, held.end - 1);
        defer unlockSpan(held.first, held.end - 1, flags);
        if (findCrossRun(count, held, .held)) |cand| {
            const claimed = claimHeld(cand, count);
            std.debug.assert(claimed); // edges and words come from one held state
            return @as(usize, cand) * FRAME_SIZE;
        }
        if (held.end == zone.end) return null;
        next = held.end - span;
    }
}

var cross_held_scans = std.atomic.Value(u32).init(0);

/// Cross-region allocations that needed the regions-held scan.
pub fn pmmCrossHeldScans() u32 {
    return cross_held_scans.load(.monotonic);
}

/// Lowest run of `count` free frames made of whole regions of `zone` and the
/// free edges of the two around them.
fn findCrossRun(count: u32, zone: Zone, how: EdgeRead) ?u32 {
    var run_start: u32 = 0;
    var run_len: u32 = 0;
    var ri: u32 = zone.first;
    while (ri < zone.end) : (ri += 1) {
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
    return run_start;
}

fn allocRun(count: u32, reach: Reach, ra: usize) ?Phys {
    if (count == 0) return null;
    if (count == 1) return allocOne(reach, ra);

    var base_opt: ?usize = null;
    if (count <= REGION_FRAMES) base_opt = walkReach(reach, count, count, allocContiguousFromRegion);
    if (base_opt == null) {
        // `high` alone first, then everything `reach` allows: a run may
        // straddle the two zones.
        if (reach == .any) base_opt = allocContiguousCrossRegion(count, highZone());
        if (base_opt == null) base_opt = allocContiguousCrossRegion(count, if (reach == .any) allZones() else lowZone());
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

pub fn allocContiguous(count: u32) ?Phys {
    return allocRun(count, .any, @returnAddress());
}

/// `count` contiguous frames below 4 GiB — see allocFrameBelow4G.
pub fn allocContiguousBelow4G(count: u32) ?Phys {
    return allocRun(count, .low, @returnAddress());
}

/// `count` contiguous frames a device will be given the address of.
/// `addr64`: the device takes a 64-bit address there — the driver read the
/// controller's capability bit. Where the protocol has only one width, call
/// allocContiguous or allocContiguousBelow4G.
pub fn allocForDevice(count: u32, addr64: bool) ?Phys {
    return allocRun(count, if (addr64) .any else .low, @returnAddress());
}

// Device memory that user address spaces map (an NVDIMM's DAX frames, the
// virtio-gpu host-memory window): not PMM-managed, never refcounted, never
// reclaimed. Tearing such a mapping down calls freeFrame on every present
// leaf like any other; freeFrame consults these ranges before its frames_end
// gate, so one below the RAM ceiling cannot reach the refcounts either.
// Entries are written once and never change; the count is published after.
const MAX_DEVICE_RANGES = 4;
var device_ranges: [MAX_DEVICE_RANGES][2]usize = @splat(.{ 0, 0 }); // [lo, hi)
var device_range_count: u8 = 0;

/// Register [base, base+len) as device memory. A driver calls it once for
/// each window it lets user space map (again with the same range is fine).
pub fn registerDeviceRange(base: Phys, len: usize) void {
    const lo = base.raw();
    const hi = lo +| len;
    if (hi <= lo) return;
    const n = @atomicLoad(u8, &device_range_count, .acquire);
    for (device_ranges[0..n]) |r| {
        if (r[0] == lo and r[1] == hi) return;
    }
    if (n == MAX_DEVICE_RANGES) {
        @import("../debug/serial.zig").print("[pmm] WARNING: no room for device range 0x{X}..0x{X}\n", .{ lo, hi });
        return;
    }
    device_ranges[n] = .{ lo, hi };
    @atomicStore(u8, &device_range_count, n + 1, .release);
}

fn inDeviceRange(phys_addr: usize) bool {
    const n = @atomicLoad(u8, &device_range_count, .acquire);
    for (device_ranges[0..n]) |r| {
        if (phys_addr >= r[0] and phys_addr < r[1]) return true;
    }
    return false;
}

/// A frame this allocator owns and refcounts. False for device memory and
/// for anything past the RAM bitmap: such a frame is only ever mapped.
pub fn isManaged(phys: Phys) bool {
    const phys_addr = phys.raw();
    return phys_addr / FRAME_SIZE < frames_end and !inDeviceRange(phys_addr);
}

pub fn freeFrame(phys: Phys) void {
    const ra = @returnAddress();
    const phys_addr: usize = phys.raw();
    const frame_num = phys_addr / FRAME_SIZE;
    // Device memory is not ours to free, wherever its window sits relative
    // to the RAM bitmap (see device_ranges).
    if (inDeviceRange(phys_addr)) return;
    if (frame_num >= frames_end) {
        @import("../debug/serial.zig").print("[pmm] WARNING: freeFrame bad addr=0x{X} (frame={X})\n", .{ phys_addr, frame_num });
        return;
    }
    checkKstackNotFreed(phys_addr, 1, "freeFrame", ra);

    // Atomic refcount drop. Common COW case: another address space still holds
    // a reference, so we just decrement and return — frame stays mapped there.
    // Only when this was the LAST reference (old==1) do we proceed to bitmap-
    // level reclamation and the magazine cache push.
    const old_ref = @atomicRmw(RefCount, &frame_refs[frame_num], .Sub, 1, .acq_rel);
    if (old_ref > 1) return;
    if (old_ref == 0) {
        // Underflow — caller released a frame that was already free. Pin
        // to 0 so a subsequent acquire/free doesn't paper over the bug.
        // Was a panic; downgraded to a warning that leaks the frame so
        // an app-teardown bug doesn't crash the whole desktop. The
        // accumulating leak rate is the visible signal that something's
        // still wrong; fix the root cause when it surfaces, not by
        // re-panicking here.
        @atomicStore(RefCount, &frame_refs[frame_num], 0, .release);
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
    @import("../cpu/mmu/pcid.zig").reportIfLoaded(phys_addr, ra);
    // Parked; the oldest parked frame is freed in its place.
    const free_phys = quarantineSwap(phys_addr, ra) orelse return;
    // S5 canary: stamp self-referencing magic at offset 0. If anyone
    // writes to this frame while it's free, the next alloc detects it.
    pmmCanaryWrite(free_phys);

    const irq_flags = saveAndDisableIrq();
    defer restoreIrq(irq_flags);

    const cpu = @import("../cpu/smp.zig").myCpu();
    if (cpu.pmm_cache_count < CACHE_SIZE) {
        // Hot path: just push onto the local cache. Bitmap stays "used" —
        // the frame is logically free but accounted to this CPU's magazine.
        cpu.pmm_cache[cpu.pmm_cache_count] = free_phys;
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
        if (drain_frame >= frames_end) continue;
        const region_idx = regionForFrame(drain_frame);
        const h = regions[region_idx].acquire();
        const freed = fi.markFree(regionWords(region_idx), h.ptr, drain_frame - regionStartFrame(region_idx), 1);
        publishHint(region_idx, h.ptr);
        if (freed > 0) _ = total_frames.fetchAdd(freed, .monotonic);
        h.release();
    }
    cpu.pmm_cache[cpu.pmm_cache_count] = free_phys;
    cpu.pmm_cache_count += 1;
}

/// Freed frames wait here, oldest out first, before the allocator gets
/// them: a write through a stale pointer or mapping lands in a frame nobody
/// owns, and the check on the way out sees the whole page.
const QUARANTINE = false;
const QUAR_FRAMES: u32 = 8192;
pub const QUAR_MAGIC: u64 = 0x5155415252414E54; // "QUARRANT"
const QuarSlot = struct { phys: u64, ra: u64 };
var quar: [QUAR_FRAMES]QuarSlot = undefined;
var quar_len: u32 = 0; // (p:quar_lock)
var quar_next: u32 = 0; // (p:quar_lock) oldest slot once full
var quar_lock: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);

/// Park `phys` (filled with its pattern) and return the frame to free in
/// its place: the oldest parked one, checked, or null while filling up.
fn quarantineSwap(phys: u64, ra: u64) ?u64 {
    if (!QUARANTINE) return phys;
    const page: [*]u64 = @ptrFromInt(@import("paging.zig").physToVirt(phys));
    const pat = phys ^ QUAR_MAGIC;
    for (0..512) |j| page[j] = pat;
    var out: ?QuarSlot = null;
    const flags = saveAndDisableIrq();
    while (quar_lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
    if (quar_len < QUAR_FRAMES) {
        quar[quar_len] = .{ .phys = phys, .ra = ra };
        quar_len += 1;
    } else {
        out = quar[quar_next];
        quar[quar_next] = .{ .phys = phys, .ra = ra };
        quar_next = (quar_next + 1) % QUAR_FRAMES;
    }
    quar_lock.store(0, .release);
    restoreIrq(flags);
    const o = out orelse return null;
    quarantineCheck(o);
    return o.phys;
}

fn quarantineCheck(s: QuarSlot) void {
    const page: [*]const u64 = @ptrFromInt(@import("paging.zig").physToVirt(s.phys));
    const pat = s.phys ^ QUAR_MAGIC;
    var bad: u32 = 0;
    var first: usize = 512;
    for (0..512) |j| {
        if (page[j] == pat) continue;
        bad += 1;
        if (first == 512) first = j;
    }
    if (bad == 0) return;
    const serial = @import("../debug/serial.zig");
    const symbols = @import("../debug/symbols.zig");
    serial.print("[pmm-quar] !!! freed frame 0x{X} written: {d}/512 qwords, first at +0x{X}: {X} {X} {X} {X}; freed by ", .{
        s.phys, bad, first * 8, page[first], page[@min(first + 1, 511)], page[@min(first + 2, 511)], page[@min(first + 3, 511)],
    });
    if (symbols.resolveKernel(s.ra)) |r| serial.print("{s}+0x{X}\n", .{ r.name, r.offset }) else serial.print("0x{X}\n", .{s.ra});
    @import("vmm.zig").reportUafFrame(s.phys);
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
    if (start_frame + count > frames_end) {
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
        const old = @atomicRmw(RefCount, &frame_refs[rf], .Sub, 1, .acq_rel);
        if (old != 1) {
            @atomicStore(RefCount, &frame_refs[rf], 0, .release);
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
    if (count > 1 and head < frames_end) {
        while (true) {
            const cur = @atomicLoad(RefCount, &frame_refs[head], .acquire);
            if (cur <= 1) break;
            if (@cmpxchgWeak(RefCount, &frame_refs[head], cur, cur - 1, .acq_rel, .acquire) == null) return;
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
/// The count cannot run out (see RefCount); the CMPXCHG loop panics rather
/// than wrap if it somehow does.
pub fn acquireFrame(phys: Phys) void {
    const phys_addr: usize = phys.raw();
    const frame_num_us = phys_addr / FRAME_SIZE;
    if (frame_num_us >= frames_end) {
        @import("../debug/serial.zig").print("[pmm] WARNING: acquireFrame bad addr=0x{X}\n", .{phys_addr});
        return;
    }
    const frame_num: u32 = @intCast(frame_num_us);
    while (true) {
        const cur = @atomicLoad(RefCount, &frame_refs[frame_num], .acquire);
        if (cur == 0) {
            @import("../debug/serial.zig").print("[pmm] PANIC: acquireFrame on free frame phys=0x{X}\n", .{phys_addr});
            @panic("pmm: acquireFrame on free frame (refcount=0)");
        }
        if (cur == std.math.maxInt(RefCount)) {
            @import("../debug/serial.zig").print("[pmm] PANIC: acquireFrame saturation phys=0x{X}\n", .{phys_addr});
            @panic("pmm: acquireFrame refcount saturation");
        }
        if (@cmpxchgWeak(RefCount, &frame_refs[frame_num], cur, cur + 1, .acq_rel, .acquire) == null) break;
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
    if (frame_num_us >= frames_end) return false;
    const frame_num: u32 = @intCast(frame_num_us);
    while (true) {
        const cur = @atomicLoad(RefCount, &frame_refs[frame_num], .acquire);
        if (cur == 0) return false;
        if (cur == std.math.maxInt(RefCount)) {
            @import("../debug/serial.zig").print("[pmm] PANIC: acquireFrameIfLive saturation phys=0x{X}\n", .{phys_addr});
            @panic("pmm: acquireFrame refcount saturation");
        }
        if (@cmpxchgWeak(RefCount, &frame_refs[frame_num], cur, cur + 1, .acq_rel, .acquire) == null) return true;
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
pub fn frameRefCount(phys: Phys) RefCount {
    const phys_addr: usize = phys.raw();
    const frame_num = phys_addr / FRAME_SIZE;
    if (frame_num >= frames_end) return 0;
    return @atomicLoad(RefCount, &frame_refs[frame_num], .acquire);
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

/// Regions one validateIndex call checks: 4 GB worth.
const VALIDATE_BATCH: u32 = 1024;
var validate_cursor = std.atomic.Value(u32).init(0);

/// A region's index against its bitmap words: the summary recomputed from
/// the words must equal the stored one (frame_index.verify), and the
/// lock-free hint must equal the stored free count. Exact, unlike the
/// run-list validator this replaces, which could only spot-check run
/// endpoints and never saw overlapping or orphaned runs. One region lock
/// at a time, briefly. pcb_invariants runs this every second: a call
/// checks the next VALIDATE_BATCH regions, so every region on a machine
/// that has no more, and all of them in turn on a bigger one.
pub fn validateIndex() bool {
    const serial = @import("../debug/serial.zig");
    var ok = true;
    const batch = @min(VALIDATE_BATCH, regions_live);
    if (batch == 0) return true;
    const from = validate_cursor.fetchAdd(batch, .monotonic);
    var step: u32 = 0;
    while (step < batch) : (step += 1) {
        const ri = (from +% step) % regions_live;
        const h = regions[ri].acquireIrqSave();
        const stored = h.ptr.*;
        const want = fi.rebuild(regionWords(ri));
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
    }
    return ok;
}
