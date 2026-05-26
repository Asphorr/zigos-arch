const std = @import("std");
const vga = @import("../ui/vga.zig");
const boot_info = @import("../boot/boot_info.zig");
const SpinLock = @import("../proc/spinlock.zig").SpinLock;
const memmap = @import("memmap.zig");

const FRAME_SIZE: u32 = 4096;
// 1 GB cap: bitmap = 32 KB, frame_refs = 256 KB. ZigOS QEMU configs use
// 64-256 MB so 1 GB is far more than needed; the cap exists to keep static
// BSS small enough that _kernel_end stays below KERNEL_HEAP_BASE (0x800000).
// Frames above 1 GB in the memory map are skipped at init time with a
// warning — bump this if a config ever genuinely wants more RAM exposed.
const MAX_FRAMES: u32 = 256 * 1024;
const BITMAP_SIZE = MAX_FRAMES / 32;

// === Region-bucketed bitmap with per-CPU affinity + per-region order freelists ===
//
// The bitmap remains the ground truth (canary/kasan/refcount/kstack tripwires
// all key off it). Around it we layer:
//
//   1. REGIONS — physical memory split into REGIONS_COUNT regions of
//      REGION_FRAMES frames each. Each region carries its own lock,
//      free-frame count, scan hint, and per-order freelist of contiguous
//      free runs inside the region. Splitting the global lock into per-
//      region locks lets SMP allocs/frees on different regions proceed
//      in parallel; per-CPU magazine refill biases toward the CPU's
//      preferred region to keep bitmap cache-lines hot per CPU.
//
//   2. RUN POOL — pre-allocated pool of `Run` nodes (start_frame, count,
//      next index). Per-order freelists are intrusive linked lists through
//      this pool. Fixed pool size: exhaustion gracefully degrades to
//      "no freelist available for this push" — bitmap remains authoritative
//      so future allocs still find the frames via scan, just slower.
//
//   3. PER-CPU PREFERRED REGION — derived from cpu_id, not stored. CPU `c`
//      prefers region `c * (REGIONS_COUNT / MAX_CPUS)`. Magazine refill /
//      single-frame fallback / contiguous alloc all start at the preferred
//      region and walk outward. Anti-fragmentation: a CPU consistently
//      allocates from the same region, so its working set stays contiguous.
const REGION_FRAMES: u32 = 1024; // 4 MB per region
const REGIONS_COUNT: u32 = MAX_FRAMES / REGION_FRAMES; // 256
const REGION_WORDS: u32 = REGION_FRAMES / 32; // bitmap words per region

comptime {
    if (MAX_FRAMES % REGION_FRAMES != 0) {
        @compileError("MAX_FRAMES must be a multiple of REGION_FRAMES");
    }
    if (REGION_FRAMES % 32 != 0) {
        @compileError("REGION_FRAMES must be a multiple of 32");
    }
}

// MAX_ORDER must cover REGION_FRAMES: 2^MAX_ORDER >= REGION_FRAMES.
// REGION_FRAMES=1024 → MAX_ORDER=10 (2^10 = 1024). Plus order 0 = 1 frame.
const MAX_ORDER: u5 = 10;

/// A free contiguous run [start_frame, start_frame+count) entirely inside
/// one region. Lives in `run_pool`; `next` is the next index in the order
/// freelist (or NULL_RUN for tail).
const Run = extern struct {
    start_frame: u32,
    count: u32,
    next: u32,
};

/// Run pool sizing: worst-case fragmentation = 1 run per 2 frames =
/// MAX_FRAMES/2 = 128K runs. Realistic = far fewer; 4096 covers heavy
/// fragmentation comfortably and stays at 48 KB BSS (12 B × 4096).
/// Pool exhaustion is non-fatal — coalesceAndPush logs a warning and skips
/// the freelist push; the bitmap is still authoritative.
const RUN_POOL_SIZE: u32 = 4096;
const NULL_RUN: u32 = 0xFFFFFFFF;

var run_pool: [RUN_POOL_SIZE]Run = undefined;
var run_pool_freelist: u32 = NULL_RUN;
var run_pool_exhaustions: u64 = 0;

/// Per-region metadata. Each region owns a REGION_FRAMES-frame slice of the
/// global bitmap (no allocation — bitmap is shared, region.lock guards
/// access to its slice). free_count + next_free_word + freelist_heads are
/// region-local.
const Region = struct {
    // Access-tag legend (see docs/STYLE.md). All mutable region state is
    // guarded by `lock`; the global bitmap slice this region owns is the
    // same — touched only under this lock.
    lock: SpinLock = .{},
    free_count: u32 = 0, // (p:lock)
    /// Word index into the global bitmap, RELATIVE to the region's start.
    /// Range: 0..REGION_WORDS. Hints where the next scan should begin.
    next_free_word: u32 = 0, // (p:lock)
    /// Per-order freelist heads. Index into `run_pool`; NULL_RUN = empty.
    /// freelist_heads[k] holds runs of size [2^k, 2^(k+1)) (except the
    /// top-most bucket which is open-ended).
    freelist_heads: [MAX_ORDER + 1]u32 = [_]u32{NULL_RUN} ** (MAX_ORDER + 1), // (p:lock)
};

var regions: [REGIONS_COUNT]Region = blk: {
    var arr: [REGIONS_COUNT]Region = undefined;
    for (&arr) |*r| r.* = .{};
    break :blk arr;
};

inline fn regionForFrame(frame: u32) u32 {
    return frame / REGION_FRAMES;
}

inline fn regionStartFrame(region_idx: u32) u32 {
    return region_idx * REGION_FRAMES;
}

/// Map a CPU id to its preferred region. With REGIONS_COUNT=256 and
/// MAX_CPUS=32, each CPU's primary region is at stride 8: cpu 0 → region 0,
/// cpu 1 → region 8, ..., cpu 31 → region 248. The cpu's scan walks
/// outward from there.
inline fn preferredRegion(cpu_id: u8) u32 {
    const stride: u32 = REGIONS_COUNT / @import("../cpu/smp.zig").MAX_CPUS;
    return @as(u32, cpu_id) * stride;
}

/// floor(log2(count)) — order bucket for a run of `count` frames. Runs of
/// size 1 land in order 0; size 1024 lands in order 10.
inline fn orderForSize(count: u32) u5 {
    if (count <= 1) return 0;
    const o = @as(u5, @truncate(31 - @clz(count)));
    return if (o > MAX_ORDER) MAX_ORDER else o;
}

// === Run pool — fixed-size pool of Run nodes for per-region freelists ===
//
// Single-threaded init followed by lock-protected use (each push/pop runs
// under its owning region's lock). The pool's free-chain is implicitly
// protected by the same locks: only the region that has the lock can
// alloc/free a Run, and the lock chain prevents two regions from racing.
// One global pool because runs migrate ownership (free into region A may
// coalesce frames originally from region B's perspective? No — coalescing
// is region-local), and per-region pools would over-provision.
//
// Race note: `run_pool_freelist` is touched by every region. We protect it
// with a tiny dedicated spinlock — uncontended in practice because the
// push/pop happens under a region lock and only briefly touches the pool.

var run_pool_lock: SpinLock = .{};

fn runPoolInit() void {
    var i: u32 = 0;
    while (i + 1 < RUN_POOL_SIZE) : (i += 1) {
        run_pool[i].next = i + 1;
    }
    run_pool[RUN_POOL_SIZE - 1].next = NULL_RUN;
    run_pool_freelist = 0;
}

/// Acquire one Run node from the pool. Returns null on exhaustion — caller
/// degrades gracefully (skip the freelist push; bitmap remains authoritative).
fn allocRun() ?u32 {
    run_pool_lock.acquire();
    defer run_pool_lock.release();
    if (run_pool_freelist == NULL_RUN) {
        run_pool_exhaustions +%= 1;
        return null;
    }
    const idx = run_pool_freelist;
    run_pool_freelist = run_pool[idx].next;
    return idx;
}

fn freeRunNode(idx: u32) void {
    run_pool_lock.acquire();
    defer run_pool_lock.release();
    run_pool[idx].next = run_pool_freelist;
    run_pool_freelist = idx;
}

// === Per-region freelist operations — caller must hold region's lock ===

/// Push a run [start_frame, start_frame+count) into the region's order bucket.
/// Returns false if the Run pool is exhausted (caller should not consider
/// this an error — bitmap still authoritative).
fn pushRunLocked(region_idx: u32, start_frame: u32, count: u32) bool {
    const idx = allocRun() orelse return false;
    run_pool[idx].start_frame = start_frame;
    run_pool[idx].count = count;
    const order = orderForSize(count);
    const r = &regions[region_idx];
    run_pool[idx].next = r.freelist_heads[order];
    r.freelist_heads[order] = idx;
    return true;
}

/// Remove ALL freelist entries that overlap [range_start, range_end). Used
/// by markRegionFree/Used when the range may contain pre-existing entries
/// whose state is unknown (rare runtime call paths: paging.allocBackBuffer
/// / freeBackBuffer, GFB allocate/free). Walks every order bucket; cost is
/// O(K) in the per-region freelist length. Caller must hold the region's
/// lock.
fn removeRunsInRangeLocked(region_idx: u32, range_start: u32, range_count: u32) void {
    const range_end = range_start + range_count;
    const r = &regions[region_idx];
    var order: u5 = 0;
    while (order <= MAX_ORDER) : (order += 1) {
        var prev: u32 = NULL_RUN;
        var cur = r.freelist_heads[order];
        while (cur != NULL_RUN) {
            const cs = run_pool[cur].start_frame;
            const ce = cs + run_pool[cur].count;
            if (cs < range_end and ce > range_start) {
                const next = run_pool[cur].next;
                if (prev == NULL_RUN) {
                    r.freelist_heads[order] = next;
                } else {
                    run_pool[prev].next = next;
                }
                freeRunNode(cur);
                cur = next;
                continue;
            }
            prev = cur;
            cur = run_pool[cur].next;
        }
    }
}

/// Remove a specific run [start_frame, start_frame+count) from the region's
/// freelist. Returns true if found+removed. Used by coalesceAndPushLocked
/// to drop neighbor entries before pushing the merged run.
fn removeRunLocked(region_idx: u32, start_frame: u32, count: u32) bool {
    const order = orderForSize(count);
    const r = &regions[region_idx];
    var prev: u32 = NULL_RUN;
    var cur = r.freelist_heads[order];
    while (cur != NULL_RUN) {
        if (run_pool[cur].start_frame == start_frame and run_pool[cur].count == count) {
            const next = run_pool[cur].next;
            if (prev == NULL_RUN) {
                r.freelist_heads[order] = next;
            } else {
                run_pool[prev].next = next;
            }
            freeRunNode(cur);
            return true;
        }
        prev = cur;
        cur = run_pool[cur].next;
    }
    return false;
}

/// Pop the smallest-order run of size ≥ `count` from this region's freelists.
/// Returns the run's start_frame and original count, or null if no run fits.
/// Caller takes the first `count` frames and is responsible for pushing the
/// remainder (count - needed) back via `pushRunLocked` if any.
fn popRunGEInRegionLocked(region_idx: u32, count: u32) ?struct { start_frame: u32, run_count: u32 } {
    const r = &regions[region_idx];
    var order = orderForSize(count);
    while (order <= MAX_ORDER) : (order += 1) {
        var prev: u32 = NULL_RUN;
        var cur = r.freelist_heads[order];
        while (cur != NULL_RUN) {
            if (run_pool[cur].count >= count) {
                const start = run_pool[cur].start_frame;
                const rc = run_pool[cur].count;
                if (prev == NULL_RUN) {
                    r.freelist_heads[order] = run_pool[cur].next;
                } else {
                    run_pool[prev].next = run_pool[cur].next;
                }
                freeRunNode(cur);
                return .{ .start_frame = start, .run_count = rc };
            }
            prev = cur;
            cur = run_pool[cur].next;
        }
    }
    return null;
}

/// Coalesce a just-freed range [start_frame, start_frame+count) with its
/// left+right free neighbors (within the same region) and push the merged
/// run to the region's freelist. Caller must hold the region's lock AND
/// have already cleared the range's bits in the bitmap. Both neighbor scans
/// stop at region boundaries — coalescing across regions is intentionally
/// skipped to keep the freelist single-region (cross-region runs still
/// reachable via bitmap scan fallback in allocContiguous).
fn coalesceAndPushLocked(region_idx: u32, start_frame: u32, count: u32) void {
    const region_start = regionStartFrame(region_idx);
    const region_end = region_start + REGION_FRAMES;

    var new_start = start_frame;
    var new_count = count;

    // Extend left: walk bitmap leftward while bits are clear AND we stay
    // inside the region. Count how many frames we absorb so we can locate
    // the left neighbor's freelist entry (if any).
    var left_count: u32 = 0;
    while (new_start > region_start and !testBit(new_start - 1)) {
        new_start -= 1;
        new_count += 1;
        left_count += 1;
    }

    // Extend right: walk bitmap rightward while bits are clear AND inside
    // the region.
    var right_count: u32 = 0;
    while (new_start + new_count < region_end and !testBit(new_start + new_count)) {
        new_count += 1;
        right_count += 1;
    }

    // Drop left+right neighbor freelist entries (they're subsumed by the
    // merged run). Each removeRunLocked walks ONE order bucket — cheap.
    // Missing entry isn't an error: pool exhaustion when the neighbor was
    // freed left the bitmap correct but no freelist node, so there's nothing
    // to remove.
    if (left_count > 0) _ = removeRunLocked(region_idx, new_start, left_count);
    if (right_count > 0) _ = removeRunLocked(region_idx, start_frame + count, right_count);

    if (!pushRunLocked(region_idx, new_start, new_count)) {
        // Pool exhausted. Bitmap is still authoritative; allocs will find
        // these frames via scan. Log once per 4K exhaustions to avoid spam.
        if ((run_pool_exhaustions & 0xFFF) == 1) {
            @import("../debug/serial.zig").print(
                "[pmm] run pool exhausted ({d} total); coalesce push skipped for {d} frames at frame {d}\n",
                .{ run_pool_exhaustions, new_count, new_start },
            );
        }
    }
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

/// Snapshot count of times allocRun has hit `run_pool_freelist == NULL_RUN`.
/// Stress tests can drive this number up to validate graceful degradation.
pub fn pmmRunPoolExhaustions() u64 {
    return @atomicLoad(u64, &run_pool_exhaustions, .monotonic);
}

/// Best-effort snapshot of region.free_count. Racy (no region lock), but
/// adequate for "did this region get most of CPU N's allocs" affinity
/// scoring. Returns 0 for out-of-range region_idx.
pub fn pmmRegionFreeCount(region_idx: u32) u32 {
    if (region_idx >= REGIONS_COUNT) return 0;
    return regions[region_idx].free_count;
}

/// Count of free Run nodes in the pool. Walks the freelist briefly under
/// the pool lock — O(RUN_POOL_SIZE) worst case but typically O(K) where
/// K = free nodes. Diagnostic only.
pub fn pmmRunPoolFreeCount() u32 {
    run_pool_lock.acquire();
    defer run_pool_lock.release();
    var n: u32 = 0;
    var cur = run_pool_freelist;
    while (cur != NULL_RUN and n < RUN_POOL_SIZE) : (n += 1) {
        cur = run_pool[cur].next;
    }
    return n;
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
/// read-modify-write cleanly.
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
// Per-region scan hint lives in `Region.next_free_word`; no global hint.

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

/// Mark [base, base+length) as free in the bitmap, update per-region free
/// counts, and push the freed range into the affected regions' freelists.
/// Used at init (single-threaded, no contention) AND at runtime by
/// paging.freeBackBuffer / paging.freeGuestFB (rare). Splits the range
/// per region; locks each region briefly.
pub fn markRegionFree(base: usize, length: usize) void {
    var frame: u32 = @intCast(base / FRAME_SIZE);
    const end_frame: u32 = @intCast(@min((base + length) / FRAME_SIZE, MAX_FRAMES));
    while (frame < end_frame) {
        const region_idx = regionForFrame(frame);
        const region_end = (region_idx + 1) * REGION_FRAMES;
        const chunk_end = @min(end_frame, region_end);
        const r = &regions[region_idx];
        const flags = r.lock.acquireIrqSave();
        const chunk_start = frame;
        var chunk_freed: u32 = 0;
        while (frame < chunk_end) : (frame += 1) {
            if (testBit(frame)) {
                clearBit(frame);
                chunk_freed += 1;
            }
        }
        if (chunk_freed > 0) {
            r.free_count += chunk_freed;
            _ = total_frames.fetchAdd(chunk_freed, .monotonic);
            // Range may contain pre-existing freelist entries (already-free
            // frames). Scrub them, then coalesce+push the now-fully-free
            // chunk. Scrub is a no-op when the range was all-used (the
            // common case: init + back-buffer/GFB unmark).
            removeRunsInRangeLocked(region_idx, chunk_start, chunk_end - chunk_start);
            coalesceAndPushLocked(region_idx, chunk_start, chunk_end - chunk_start);
            // Region's scan hint may now point past free frames in this chunk.
            const chunk_first_word = (chunk_start - regionStartFrame(region_idx)) / 32;
            if (chunk_first_word < r.next_free_word) r.next_free_word = chunk_first_word;
        }
        r.lock.releaseIrqRestore(flags);
    }
}

/// Mark [base, base+length) as used in the bitmap. Updates per-region free
/// counts and removes any freelist entries that overlap. Used at init AND
/// at runtime by paging.allocBackBuffer / paging.allocGuestFB.
pub fn markRegionUsed(base: usize, length: usize) void {
    var frame: u32 = @intCast(base / FRAME_SIZE);
    const end_frame: u32 = @intCast(@min((base + length + FRAME_SIZE - 1) / FRAME_SIZE, MAX_FRAMES));
    while (frame < end_frame) {
        const region_idx = regionForFrame(frame);
        const region_end = (region_idx + 1) * REGION_FRAMES;
        const chunk_end = @min(end_frame, region_end);
        const r = &regions[region_idx];
        const flags = r.lock.acquireIrqSave();
        const chunk_start = frame;
        var chunk_used: u32 = 0;
        while (frame < chunk_end) : (frame += 1) {
            if (!testBit(frame)) {
                setBit(frame);
                chunk_used += 1;
            }
        }
        if (chunk_used > 0) {
            if (r.free_count >= chunk_used) r.free_count -= chunk_used else r.free_count = 0;
            satSubTotal(chunk_used);
            // Drop any freelist entries that included these now-used frames.
            // A previously-free run may have spanned the chunk; after the
            // mark, part of it (or all of it) is used, so the entry is stale.
            // Re-push any free fragments left at the edges.
            removeRunsInRangeLocked(region_idx, chunk_start, chunk_end - chunk_start);
            // Left fragment: any free frames immediately before chunk_start
            // that were part of the removed run.
            var left_start = chunk_start;
            var left_count: u32 = 0;
            const reg_start = regionStartFrame(region_idx);
            while (left_start > reg_start and !testBit(left_start - 1)) {
                left_start -= 1;
                left_count += 1;
            }
            if (left_count > 0) {
                _ = pushRunLocked(region_idx, left_start, left_count);
            }
            // Right fragment: free frames immediately after chunk_end.
            var right_count: u32 = 0;
            while (chunk_end + right_count < region_end and !testBit(chunk_end + right_count)) {
                right_count += 1;
            }
            if (right_count > 0) {
                _ = pushRunLocked(region_idx, chunk_end, right_count);
            }
        }
        r.lock.releaseIrqRestore(flags);
    }
}

pub fn init(info: *const boot_info.BootInfo) void {
    runPoolInit();
    // Register the run-pool lock + one representative region lock so the
    // spinlock holder dump can name them in a deadlock report. The 256
    // region locks are intentionally anonymous — naming each one would
    // clutter the registry, and the lock-diag falls back to printing the
    // pointer for unregistered locks anyway.
    const spinlock = @import("../proc/spinlock.zig");
    spinlock.registerLock("pmm.run_pool", &run_pool_lock);
    spinlock.registerLock("pmm.r0", &regions[0].lock);

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

/// Scan one region's bitmap slice for a free frame, claim it, return phys
/// addr. Caller must hold `regions[region_idx].lock`. Wraps within region;
/// null if region is full. This is the BITMAP FALLBACK — callers should
/// try popRunGEInRegionLocked first; scan only runs when the region's
/// freelist is empty (e.g., post-pool-exhaustion orphaned free frames).
///
/// Invariant: when this returns frame F, no freelist entry contains F.
/// That holds because (a) the freelist try happened first and returned null,
/// meaning no entry of any order had count≥1 in this region, and (b)
/// coalesceAndPush always merges adjacent free frames into one entry, so
/// "no entry" means "no entry covers any free frame in this region".
fn scanInRegionLocked(region_idx: u32) ?usize {
    const region_base_word: u32 = region_idx * REGION_WORDS;
    const region_end_word: u32 = region_base_word + REGION_WORDS;
    const r = &regions[region_idx];
    var w: u32 = region_base_word + r.next_free_word;
    while (w < region_end_word) : (w += 1) {
        if (bitmap[w] != 0xFFFFFFFF) {
            return takeFrameFromWordLocked(region_idx, w);
        }
    }
    w = region_base_word;
    const stop = region_base_word + r.next_free_word;
    while (w < stop) : (w += 1) {
        if (bitmap[w] != 0xFFFFFFFF) {
            return takeFrameFromWordLocked(region_idx, w);
        }
    }
    return null;
}

/// Claim one free bit from `bitmap[word_idx]`, update region/global counts,
/// advance the region's scan hint, return phys addr. Caller holds the region
/// lock and has verified `bitmap[word_idx] != 0xFFFFFFFF`.
fn takeFrameFromWordLocked(region_idx: u32, word_idx: u32) usize {
    const free_bits = ~bitmap[word_idx];
    const bit: u5 = @truncate(@ctz(free_bits));
    const frame = word_idx * 32 + @as(u32, bit);
    setBit(frame);
    const r = &regions[region_idx];
    if (r.free_count > 0) r.free_count -= 1;
    satSubTotal(1);
    r.next_free_word = word_idx - region_idx * REGION_WORDS;
    return @as(usize, frame) * FRAME_SIZE;
}

/// Magazine-refilling alloc from one region. Caller passes its CpuLocal so
/// any extra frames (beyond the one returned to caller) land in the per-CPU
/// magazine. Tries the region's freelist (one pop yields up to REFILL_BATCH+1
/// frames); falls back to bitmap scan inside the region. Returns the phys
/// addr of the frame given to the caller (frame is bit-set; remainder is
/// in the magazine), or null if region has nothing to offer.
fn allocAndRefillFromRegion(region_idx: u32, cpu: anytype) ?usize {
    const r = &regions[region_idx];
    const flags = r.lock.acquireIrqSave();
    defer r.lock.releaseIrqRestore(flags);

    // Freelist path: one pop may satisfy caller + refill batch in one op.
    if (popRunGEInRegionLocked(region_idx, 1)) |run| {
        // Cap `take` by what the magazine can actually hold so a partly-full
        // cache doesn't drop the trailing setBit'd frames. With the current
        // callers (cache miss path enters with count==0) this is always
        // REFILL_BATCH+1, but the floor below is the defensive invariant.
        const cache_room: u32 = if (CACHE_SIZE > cpu.pmm_cache_count)
            CACHE_SIZE - cpu.pmm_cache_count
        else
            0;
        const want: u32 = @min(REFILL_BATCH + 1, cache_room + 1); // +1 for caller's own frame
        const take: u32 = if (run.run_count > want) want else run.run_count;
        const start_frame = run.start_frame;
        var i: u32 = 0;
        while (i < take) : (i += 1) setBit(start_frame + i);
        if (r.free_count >= take) r.free_count -= take else r.free_count = 0;
        satSubTotal(take);
        if (run.run_count > take) {
            _ = pushRunLocked(region_idx, start_frame + take, run.run_count - take);
        }
        // Frame 0 → caller. Frames 1..take → magazine.
        const caller_phys: usize = @as(usize, start_frame) * FRAME_SIZE;
        var j: u32 = 1;
        while (j < take and cpu.pmm_cache_count < CACHE_SIZE) : (j += 1) {
            cpu.pmm_cache[cpu.pmm_cache_count] = caller_phys + @as(usize, j) * FRAME_SIZE;
            cpu.pmm_cache_count += 1;
        }
        return caller_phys;
    }

    // Bitmap-scan fallback: freelist is empty (or pool-exhausted) for this
    // region. Find one frame, then refill cache from same region.
    const caller = scanInRegionLocked(region_idx) orelse return null;
    var refilled: u32 = 0;
    while (refilled < REFILL_BATCH and cpu.pmm_cache_count < CACHE_SIZE) : (refilled += 1) {
        const phys = scanInRegionLocked(region_idx) orelse break;
        cpu.pmm_cache[cpu.pmm_cache_count] = phys;
        cpu.pmm_cache_count += 1;
    }
    return caller;
}

pub fn allocFrame() ?usize {
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
        return phys;
    }

    // Cache miss: try preferred region first (per-CPU affinity = cache
    // locality on the bitmap line, anti-fragmentation), then walk outward.
    const pref = preferredRegion(cpu.cpu_id);
    var first_phys: ?usize = allocAndRefillFromRegion(pref, cpu);
    if (first_phys == null) {
        // Walk other regions in ascending order from preferred+1, wrapping.
        var off: u32 = 1;
        while (off < REGIONS_COUNT) : (off += 1) {
            const ri = (pref + off) % REGIONS_COUNT;
            if (allocAndRefillFromRegion(ri, cpu)) |p| {
                first_phys = p;
                break;
            }
        }
    }
    const first = first_phys orelse return null;

    checkPhysSafety(first, "allocFrame");
    checkKstackOverlap(first, 1, "allocFrame", ra);
    pmmCanaryCheck(first, "allocFrame(bitmap)", ra);
    @import("../debug/kdbg.zig").pmmAlloc(first, 1, ra);
    @import("../debug/kasan.zig").unpoison(first, FRAME_SIZE);
    frame_refs[first / FRAME_SIZE] = 1;
    return first;
}

/// Allocate a frame below 4GB (for DMA buffers that require 32-bit addresses).
/// Walks only regions whose end frame is below the 4GB boundary.
pub fn allocFrameBelow4G() ?usize {
    const max_frame_32: u32 = 0x100000; // 4GB / 4KB
    const max_region: u32 = max_frame_32 / REGION_FRAMES; // exclusive upper

    const irq_flags = saveAndDisableIrq();
    defer restoreIrq(irq_flags);

    var ri: u32 = 0;
    while (ri < max_region) : (ri += 1) {
        const r = &regions[ri];
        const flags = r.lock.acquireIrqSave();
        defer r.lock.releaseIrqRestore(flags);

        // Single-frame: try freelist, then bitmap scan, both region-local.
        if (popRunGEInRegionLocked(ri, 1)) |run| {
            const start_frame = run.start_frame;
            setBit(start_frame);
            if (r.free_count > 0) r.free_count -= 1;
            satSubTotal(1);
            if (run.run_count > 1) {
                _ = pushRunLocked(ri, start_frame + 1, run.run_count - 1);
            }
            const phys: usize = @as(usize, start_frame) * FRAME_SIZE;
            checkPhysSafety(phys, "allocFrameBelow4G");
            @import("../debug/kasan.zig").unpoison(phys, FRAME_SIZE);
            frame_refs[start_frame] = 1;
            return phys;
        }
        if (scanInRegionLocked(ri)) |phys| {
            checkPhysSafety(phys, "allocFrameBelow4G");
            @import("../debug/kasan.zig").unpoison(phys, FRAME_SIZE);
            frame_refs[phys / FRAME_SIZE] = 1;
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

    satSubTotal(count);
}

/// Tripwire: does this phys range overlap kstack_pool? Used on the FREE
/// path — passing a kstack phys to freeFrame/freeContiguous marks the
/// underlying frame "free" so the next alloc returns it; the new owner
/// then zeroes/uses the page, clobbering a live kstack. There is no
/// legitimate path that frees a kstack frame (kstack_pool is BSS, never
/// PMM-managed), so any hit is unambiguously a bug — @panic to catch
/// the buggy caller in the backtrace.
fn checkKstackNotFreed(base: usize, count: u32, site: []const u8, ra: usize) void {
    const process_mod = @import("../proc/process.zig");
    const KERNEL_VIRT_BASE: usize = 0xFFFFFFFF80000000;
    const ks_va = @intFromPtr(&process_mod.kstack_pool);
    const ks_phys_start = ks_va - KERNEL_VIRT_BASE;
    const ks_phys_end = ks_phys_start + @sizeOf(@TypeOf(process_mod.kstack_pool));
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

/// Tripwire: does this phys range overlap kstack_pool (a kernel .bss
/// region that PMM should NEVER hand out — kstacks live there at fixed
/// addresses)? Symbol-derived so it tracks kernel growth automatically.
/// On hit, log the caller's RA + the bad phys; the next @memset via
/// physmap on this range will zero a live kstack — exactly the
/// netstat-desktop bug class.
fn checkKstackOverlap(base: usize, count: u32, site: []const u8, ra: usize) void {
    const process_mod = @import("../proc/process.zig");
    const KERNEL_VIRT_BASE: usize = 0xFFFFFFFF80000000;
    const ks_va = @intFromPtr(&process_mod.kstack_pool);
    const ks_phys_start = ks_va - KERNEL_VIRT_BASE;
    const ks_phys_end = ks_phys_start + @sizeOf(@TypeOf(process_mod.kstack_pool));
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

/// Allocate `count` physically contiguous frames. Returns base physical address.
/// Try to satisfy a contiguous alloc of `count` frames entirely within
/// `region_idx`. Returns base phys, or null if region can't fit. Tries
/// freelist (O(1) common path) then in-region bitmap scan (orphaned-by-
/// pool-exhaustion fallback).
fn allocContiguousFromRegion(region_idx: u32, count: u32) ?usize {
    const r = &regions[region_idx];
    const flags = r.lock.acquireIrqSave();
    defer r.lock.releaseIrqRestore(flags);

    if (popRunGEInRegionLocked(region_idx, count)) |run| {
        const start_frame = run.start_frame;
        var i: u32 = 0;
        while (i < count) : (i += 1) setBit(start_frame + i);
        @memset(frame_refs[start_frame .. start_frame + count], 1);
        if (r.free_count >= count) r.free_count -= count else r.free_count = 0;
        satSubTotal(count);
        if (run.run_count > count) {
            _ = pushRunLocked(region_idx, start_frame + count, run.run_count - count);
        }
        return @as(usize, start_frame) * FRAME_SIZE;
    }

    // Bitmap-scan fallback (orphaned free frames not in freelist).
    const region_start = regionStartFrame(region_idx);
    const region_end = region_start + REGION_FRAMES;
    if (findContiguousRun(region_start, region_end, count)) |start_frame| {
        markRange(start_frame, count);
        if (r.free_count >= count) r.free_count -= count else r.free_count = 0;
        return @as(usize, start_frame) * FRAME_SIZE;
    }
    return null;
}

/// Cross-region contiguous allocation. Used when `count > REGION_FRAMES`
/// (no single region can hold) or when every per-region attempt failed.
/// Locks ALL regions in ascending order (deadlock-safe ordering) and walks
/// the full bitmap. Holds per-region locks for the duration of the scan +
/// markup — heavy, but the path is rare. `max_frame` caps the scan (for
/// allocContiguousBelow4G, this is the 4 GB frame index).
fn allocContiguousCrossRegion(count: u32, max_frame: u32) ?usize {
    // Lock all regions in ascending order — consistent ordering avoids
    // deadlock against any concurrent per-region acquirer (which holds
    // exactly one lock at a time). Use acquireIrqSave on regions[0] so
    // the cli-hold tracker arms (a slow full-bitmap scan + 256-lock fan-
    // out is exactly the kind of long cli-held section we want surfaced
    // in `[cli-hold]`); the remaining 255 use plain acquire because IF
    // is already off after the first save.
    const flags = regions[0].lock.acquireIrqSave();
    var i: u32 = 1;
    while (i < REGIONS_COUNT) : (i += 1) regions[i].lock.acquire();
    defer {
        var j: u32 = REGIONS_COUNT;
        while (j > 1) {
            j -= 1;
            regions[j].lock.release();
        }
        regions[0].lock.releaseIrqRestore(flags);
    }

    const start_frame = findContiguousRun(0, max_frame, count) orelse return null;
    markRange(start_frame, count);

    // Update per-region free_counts + scrub freelist entries in the marked
    // range. Re-push any free fragments at the edges (a removed entry that
    // extended beyond our take needs its tail back).
    const end_frame = start_frame + count;
    var ri: u32 = start_frame / REGION_FRAMES;
    const end_region = (end_frame - 1) / REGION_FRAMES;
    while (ri <= end_region) : (ri += 1) {
        const reg_start = ri * REGION_FRAMES;
        const reg_end = reg_start + REGION_FRAMES;
        const overlap_start = @max(start_frame, reg_start);
        const overlap_end = @min(end_frame, reg_end);
        const overlap = overlap_end - overlap_start;
        const rr = &regions[ri];
        if (rr.free_count >= overlap) rr.free_count -= overlap else rr.free_count = 0;
        removeRunsInRangeLocked(ri, overlap_start, overlap);

        // Re-push left edge fragment if any free frames immediately precede
        // overlap_start (still in this region).
        if (overlap_start > reg_start) {
            var ls = overlap_start;
            var lc: u32 = 0;
            while (ls > reg_start and !testBit(ls - 1)) {
                ls -= 1;
                lc += 1;
            }
            if (lc > 0) _ = pushRunLocked(ri, ls, lc);
        }
        // Right edge fragment.
        if (overlap_end < reg_end) {
            var rc: u32 = 0;
            while (overlap_end + rc < reg_end and !testBit(overlap_end + rc)) {
                rc += 1;
            }
            if (rc > 0) _ = pushRunLocked(ri, overlap_end, rc);
        }
    }
    return @as(usize, start_frame) * FRAME_SIZE;
}

pub fn allocContiguous(count: u32) ?usize {
    if (count == 0) return null;
    if (count == 1) return allocFrame();
    const ra = @returnAddress();

    var base_opt: ?usize = null;
    if (count <= REGION_FRAMES) {
        const cpu = @import("../cpu/smp.zig").myCpu();
        const pref = preferredRegion(cpu.cpu_id);
        base_opt = allocContiguousFromRegion(pref, count);
        if (base_opt == null) {
            var off: u32 = 1;
            while (off < REGIONS_COUNT) : (off += 1) {
                const ri = (pref + off) % REGIONS_COUNT;
                if (allocContiguousFromRegion(ri, count)) |p| {
                    base_opt = p;
                    break;
                }
            }
        }
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
    return base;
}

/// Allocate `count` contiguous frames below 4GB (for DMA).
pub fn allocContiguousBelow4G(count: u32) ?usize {
    if (count == 0) return null;
    if (count == 1) return allocFrameBelow4G();
    const ra = @returnAddress();
    const max_frame_32: u32 = 0x100000; // 4GB / 4KB
    const max_region: u32 = max_frame_32 / REGION_FRAMES;

    var base_opt: ?usize = null;
    if (count <= REGION_FRAMES) {
        var ri: u32 = 0;
        while (ri < max_region) : (ri += 1) {
            if (allocContiguousFromRegion(ri, count)) |p| {
                base_opt = p;
                break;
            }
        }
    }
    if (base_opt == null) {
        base_opt = allocContiguousCrossRegion(count, max_frame_32);
    }
    const base = base_opt orelse return null;

    checkPhysSafety(base, "allocContiguousBelow4G");
    const last: usize = base + (@as(usize, count) - 1) * FRAME_SIZE;
    if (last != base) checkPhysSafety(last, "allocContiguousBelow4G(last)");
    checkKstackOverlap(base, count, "allocContiguousBelow4G", ra);
    canaryBitClearRange(@intCast(base / FRAME_SIZE), count);
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

    // Cache full: drain DRAIN_BATCH back to the per-region freelists.
    // Each drained frame is routed to its source region (by phys), the
    // region's lock acquired briefly, bit cleared, coalesce-and-push into
    // the order freelist. With per-region locks instead of one global,
    // drains to different regions don't serialize, and the coalesce path
    // grows the freelist's contiguous runs as adjacent frees arrive.
    var i: u32 = 0;
    while (i < DRAIN_BATCH) : (i += 1) {
        cpu.pmm_cache_count -= 1;
        const drain_phys = cpu.pmm_cache[cpu.pmm_cache_count];
        const drain_frame: u32 = @intCast(drain_phys / FRAME_SIZE);
        if (drain_frame >= MAX_FRAMES) continue;
        const region_idx = regionForFrame(drain_frame);
        const r = &regions[region_idx];
        r.lock.acquire();
        if (testBit(drain_frame)) {
            clearBit(drain_frame);
            r.free_count += 1;
            _ = total_frames.fetchAdd(1, .monotonic);
            coalesceAndPushLocked(region_idx, drain_frame, 1);
            const word_in_region = (drain_frame - region_idx * REGION_FRAMES) / 32;
            if (word_in_region < r.next_free_word) r.next_free_word = word_in_region;
        }
        r.lock.release();
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

    // Split the range per region, lock each region briefly, clear bits and
    // coalesce+push the chunk into the region's freelist. Most contiguous
    // frees come from a single region (DMA buffer, page-table pool, GUI FB
    // slice). The rare cross-region case (e.g. a 2 MB run spanning a region
    // boundary) handles each region's chunk independently — coalescing stops
    // at the boundary, but allocs across the boundary still find the runs
    // via per-region freelist when they fit; oversized requests use
    // allocContiguousCrossRegion's bitmap scan.
    var f: u32 = @intCast(start_frame);
    const end_frame: u32 = @intCast(start_frame + count);
    while (f < end_frame) {
        const region_idx = regionForFrame(f);
        const region_end = (region_idx + 1) * REGION_FRAMES;
        const chunk_end = @min(end_frame, region_end);
        const r = &regions[region_idx];
        const flags = r.lock.acquireIrqSave();
        const chunk_start = f;
        var chunk_freed: u32 = 0;
        // Word-at-a-time clear in the middle of the chunk for speed.
        while (f < chunk_end and (f % 32) != 0) : (f += 1) {
            if (testBit(f)) {
                clearBit(f);
                chunk_freed += 1;
            }
        }
        while (f + 32 <= chunk_end) : (f += 32) {
            const w = bitmap[f / 32];
            chunk_freed += @popCount(w);
            bitmap[f / 32] = 0;
        }
        while (f < chunk_end) : (f += 1) {
            if (testBit(f)) {
                clearBit(f);
                chunk_freed += 1;
            }
        }
        if (chunk_freed > 0) {
            r.free_count += chunk_freed;
            _ = total_frames.fetchAdd(chunk_freed, .monotonic);
            coalesceAndPushLocked(region_idx, chunk_start, chunk_end - chunk_start);
            const word_in_region = (chunk_start - region_idx * REGION_FRAMES) / 32;
            if (word_in_region < r.next_free_word) r.next_free_word = word_in_region;
        }
        r.lock.releaseIrqRestore(flags);
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
pub inline fn freeRange(phys_base: usize, count: u32) void {
    freeContiguous(phys_base, count);
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
pub fn allocFrameUser() ?usize {
    if (total_frames.load(.monotonic) <= pmm_user_reserve) return null;
    return allocFrame();
}

/// User-faulting variant of allocContiguous. Same reserve check —
/// big mmap-with-fd requests fail cleanly when PMM is tight rather
/// than starving the kernel.
pub fn allocContiguousUser(count: u32) ?usize {
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
