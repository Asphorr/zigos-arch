// src/mm/swap.zig — swap backing store + page-slot allocator.
//
// Phase 1 of the swap subsystem: own a dedicated raw NVMe disk (controller
// #2, the `swap.img` device) and provide page-granular read/write to it plus
// a free-slot allocator. There is NO eviction or swap-in yet — that is Phase
// 2/3, which hook into the page-fault / OOM path. This file is self-contained
// and proves the backing store works via a boot-time round-trip self-test.
//
// Layout: the swap device is a flat array of 4 KiB slots. Slot N occupies
// LBAs [N*8, N*8+8) (8 × 512-byte sectors per page). A bitmap tracks which
// slots currently hold a live evicted page.
//
// Backing-store choice: a dedicated disk (not a swap file on ext2) so there's
// zero filesystem-corruption risk and no FS dependency — the swap device is
// entirely ours. It's the 3rd `-device nvme` in run-uefi-ext2.sh and
// enumerates as NVMe controller index SWAP_CTRL_IDX.

const std = @import("std");
const debug = @import("../debug/debug.zig");
const pmm = @import("pmm.zig");
const paging = @import("paging.zig");
const nvme = @import("../driver/nvme.zig");
const tlb = @import("../cpu/mmu/tlb.zig");
const smp = @import("../cpu/smp.zig");
const process = @import("../proc/process.zig");
const spinlock = @import("../proc/spinlock.zig");
const SpinLock = spinlock.SpinLock;

// The swap device is the 3rd NVMe controller (0 = tarfs, 1 = ext2, 2 = swap).
const SWAP_CTRL_IDX: usize = 2;
const PAGE_SIZE: usize = 4096;
const SECTORS_PER_PAGE: u32 = 8; // 4096 / 512

// Swap capacity. MUST be <= the swap.img size in run-uefi-ext2.sh (currently
// 128 MiB). It's a constant because the NVMe Controller doesn't yet expose
// namespace capacity; a later phase can read Identify-Namespace and drop this
// assumption. 128 MiB / 4 KiB = 32768 slots.
const SWAP_BYTES: usize = 128 * 1024 * 1024;
const NUM_SLOTS: usize = SWAP_BYTES / PAGE_SIZE; // 32768

pub var available: bool = false;                                // (c) set in init() on swap-NVMe present; RO afterwards
var slot_used: [NUM_SLOTS / 8]u8 = [_]u8{0} ** (NUM_SLOTS / 8); // (p:slot_lock) free-slot bitmap
var used_count: usize = 0;                                       // (a) bumped by alloc/freeSlot; consumers may read outside slot_lock
var next_scan: usize = 0;                                        // (p:slot_lock) round-robin hint for allocSlot
// Per-slot generation tag, embedded in every SWAPPED PTE (see makeSwapPte) and
// bumped on every freeSlot. Kills the slot-reuse ABA in swapInFrame: it loads
// the PTE (slot S), does a BLOCKING readPage(S), then commit-CASes — if in that
// window another thread swapped the page in (freeing S), the user modified the
// page, and it was re-evicted INTO S again (round-robin wrap), the PTE would be
// bit-identical and the stale CAS would install pre-modification bytes: silent
// user-data corruption. With the tag, a freed+reused slot can never reproduce
// the old PTE, so the stale commit loses and the loser re-faults. A u8 wraps
// only after 256 free+reuse cycles of the SAME slot within one load-to-CAS
// window (each cycle a full evict+swap-in round trip) — not physical.
// Writes are atomic RMW under slot_lock; makeSwapPte reads with @atomicLoad
// monotonic (the slot's owner allocSlot'd it through the lock, which publishes
// every prior bump; nobody can bump an owned slot's gen).
var slot_gen: [NUM_SLOTS]u8 = [_]u8{0} ** NUM_SLOTS;
// Guards slot_used + next_scan. Evict / swap-in run in the page-fault handler
// on any CPU, so allocSlot/freeSlot must be serialized. NVMe I/O is done
// OUTSIDE this lock (no I/O is held under it).
var slot_lock: SpinLock = .{};

// Stats. All bumped from multi-CPU evict/swap-in/discard/reclaim — atomic RMW
// only, never plain `+=`. Milestone klog lines use the fetchAdd return value so
// the "every 4096th" trigger is per-callsite stable.
pub var pages_out: u64 = 0;            // (a) eviction counter; multi-CPU
pub var pages_in: u64 = 0;             // (a) swap-in counter; multi-CPU
pub var pages_second_chance: u64 = 0;  // (a) clock skips; bumped from fault.zig reclaimViaSwap
pub var pages_discarded: u64 = 0;      // (a) discardFrame counter; multi-CPU

inline fn bitGet(slot: usize) bool {
    slot_lock.assertHeld();
    return (slot_used[slot >> 3] & (@as(u8, 1) << @as(u3, @intCast(slot & 7)))) != 0;
}
inline fn bitSet(slot: usize) void {
    slot_lock.assertHeld();
    slot_used[slot >> 3] |= (@as(u8, 1) << @as(u3, @intCast(slot & 7)));
}
inline fn bitClear(slot: usize) void {
    slot_lock.assertHeld();
    slot_used[slot >> 3] &= ~(@as(u8, 1) << @as(u3, @intCast(slot & 7)));
}

/// Reserve a free swap slot. Returns its index, or null if swap is full or
/// unavailable. Locking: acquires `slot_lock` internally.
pub fn allocSlot() ?u32 {
    if (!available) return null;
    slot_lock.acquire();
    defer slot_lock.release();
    if (@atomicLoad(usize, &used_count, .monotonic) >= NUM_SLOTS) return null;
    var scanned: usize = 0;
    var s = next_scan;
    while (scanned < NUM_SLOTS) : (scanned += 1) {
        if (!bitGet(s)) {
            bitSet(s);
            _ = @atomicRmw(usize, &used_count, .Add, 1, .monotonic);
            next_scan = (s + 1) % NUM_SLOTS;
            return @intCast(s);
        }
        s = (s + 1) % NUM_SLOTS;
    }
    return null;
}

/// Release a swap slot (after its page was read back in, or its owner died).
/// Locking: acquires `slot_lock` internally. Out-of-range and double-free
/// paths warn via `kwarn` so a caller's bookkeeping bug is observable rather
/// than silently absorbed (mtswap-style stress would otherwise hide drift).
pub fn freeSlot(slot: u32) void {
    if (slot >= NUM_SLOTS) {
        debug.kwarn(@src(), "freeSlot out-of-range slot={d} NUM_SLOTS={d}", .{ slot, NUM_SLOTS });
        return;
    }
    slot_lock.acquire();
    defer slot_lock.release();
    if (!bitGet(slot)) {
        debug.kwarn(@src(), "freeSlot double-free slot={d}", .{slot});
        return;
    }
    bitClear(slot);
    // Retire this slot's SWAPPED-PTE encoding (ABA guard — see slot_gen).
    _ = @atomicRmw(u8, &slot_gen[slot], .Add, 1, .monotonic);
    _ = @atomicRmw(usize, &used_count, .Sub, 1, .monotonic);
}

/// Write a 4 KiB physical frame out to swap slot `slot`. `frame_phys` is a
/// PMM frame's physical address. Returns false if swap is unavailable or the
/// NVMe write reports failure. Locking: holds no kernel lock; may block on
/// async NVMe completion.
pub fn writePage(slot: u32, frame_phys: usize) bool {
    if (!available or slot >= NUM_SLOTS) return false;
    const va = paging.physToVirt(frame_phys);
    return nvme.writeSectorsOn(SWAP_CTRL_IDX, slot * SECTORS_PER_PAGE, SECTORS_PER_PAGE, @ptrFromInt(va));
}

/// Read swap slot `slot` back into a 4 KiB physical frame. Locking: same as
/// `writePage`.
pub fn readPage(slot: u32, frame_phys: usize) bool {
    if (!available or slot >= NUM_SLOTS) return false;
    const va = paging.physToVirt(frame_phys);
    return nvme.readSectorsOn(SWAP_CTRL_IDX, slot * SECTORS_PER_PAGE, SECTORS_PER_PAGE, @ptrFromInt(va));
}

pub fn slotsUsed() usize {
    return @atomicLoad(usize, &used_count, .monotonic);
}
pub fn slotsTotal() usize {
    return NUM_SLOTS;
}

/// One-shot init. Call after nvme.init(). No-op (available stays false) if the
/// dedicated swap controller isn't present. Runs a round-trip self-test.
pub fn init() void {
    if (nvme.controllerCount() <= SWAP_CTRL_IDX) {
        debug.klog("[swap] no swap device (need NVMe controller #{d}; found {d}) — swap disabled\n", .{ SWAP_CTRL_IDX, nvme.controllerCount() });
        return;
    }
    available = true;
    // WITNESS: track the slot-allocator lock (taken in the page-fault evict /
    // swap-in path) vs other subsystem locks. Registered only when swap is
    // actually live — past the no-device early return above.
    spinlock.registerLock("swap.slots", &slot_lock);
    // Self-test runs SYNCHRONOUSLY because nvme.enableAsync() hasn't fired yet
    // at this point in init — async_mode is false on every controller. Once
    // enableAsync() flips this controller too (we no longer markSyncOnly), all
    // post-boot swap I/O routes through ioCommandAsync → blockOn(.nvme_io).
    //
    // Why async is safe here even though swap I/O runs in the page-fault path:
    //   1. Ring-3 user faults hold no kernel spinlock, so blockOn parks the
    //      thread cleanly and the NVMe IRQ reaper wakes it (same shape as a
    //      blocking read() syscall on the FS controllers — proven pattern).
    //   2. Kernel-context swap-ins (validateUserPtr → prefaultUserRange) run
    //      at syscall entry BEFORE the handler takes any lock, so blocking
    //      there is equivalent to a normal blocking syscall.
    //   3. evictFrame/swapInFrame hold no lock across writePage/readPage (the
    //      slot_lock is taken inside allocSlot/freeSlot only, never spanning
    //      the I/O). So eviction during reclaim can yield freely.
    // The single narrow concern — a mid-syscall kernel access to a user page
    // that was re-evicted between prefault and access — is bounded by the
    // refcount==1 guard in evictFrame (won't touch shared pages) and the fact
    // that syscall handlers don't hold spinlocks across user copies. Reviewed.
    debug.klog("[swap] swap device = NVMe ctrl #{d}, {d} slots ({d} MiB), async I/O\n", .{ SWAP_CTRL_IDX, NUM_SLOTS, SWAP_BYTES / (1024 * 1024) });
    selfTest();
}

/// Phase 1 proof: alloc a slot, write a known pattern from one frame, read it
/// back into a second frame, verify byte-for-byte, then free everything. This
/// confirms the whole NVMe-backed page path before Phase 2 relies on it under
/// memory pressure.
fn selfTest() void {
    const src = pmm.allocFrame() orelse {
        debug.klog("[swap] self-test skipped — no frame for src\n", .{});
        return;
    };
    defer pmm.freeFrame(src);
    const dst = pmm.allocFrame() orelse {
        debug.klog("[swap] self-test skipped — no frame for dst\n", .{});
        return;
    };
    defer pmm.freeFrame(dst);

    // Fill src with a recognizable, position-dependent pattern.
    const src_bytes: [*]u8 = @ptrFromInt(paging.physToVirt(src));
    var i: usize = 0;
    while (i < PAGE_SIZE) : (i += 1) src_bytes[i] = @truncate(i *% 31 +% 7);

    const slot = allocSlot() orelse {
        debug.klog("[swap] self-test FAILED — allocSlot returned null\n", .{});
        return;
    };
    defer freeSlot(slot);

    // Poison dst so a no-op read can't accidentally "pass".
    const dst_bytes: [*]u8 = @ptrFromInt(paging.physToVirt(dst));
    @memset(dst_bytes[0..PAGE_SIZE], 0xA5);

    if (!writePage(slot, src) or !readPage(slot, dst)) {
        debug.klog("[swap] self-test FAILED — NVMe I/O error on slot {d}\n", .{slot});
        return;
    }

    i = 0;
    while (i < PAGE_SIZE) : (i += 1) {
        if (src_bytes[i] != dst_bytes[i]) {
            debug.klog("[swap] self-test FAILED — mismatch at byte {d}: wrote 0x{X} read 0x{X}\n", .{ i, src_bytes[i], dst_bytes[i] });
            return;
        }
    }
    debug.klog("[swap] self-test PASSED — 4 KiB round-trip through slot {d} verified\n", .{slot});
}

// --- Phase 2: swapped-PTE encoding + evict / swap-in mechanism ---------
//
// PTE state machine for a swap-eligible user page:
//
//   PRESENT       (bit 0  set)   = mapped, addressable by user.
//   SWAP_INFLIGHT (bit 11 set, PRESENT=0) = evict-in-progress. Frame phys is
//                                            in the top bits. Any user access
//                                            faults; the handler waits on
//                                            .swap_evict until the eviction
//                                            CASes the PTE to SWAPPED.
//   SWAPPED       (bit 10 set, PRESENT=0) = page is on the swap disk. Slot
//                                            index in bits 12+, slot generation
//                                            tag above it (ABA guard, slot_gen).
//   0                            = never faulted / discarded; first-fault path.
//
// COW is bit 9 — never collides with SWAPPED (10) or SWAP_INFLIGHT (11). The
// CPU ignores all bits when PRESENT=0, so the markers are software-only.
//
// CAS-on-every-PTE-rewrite (added 2026-05-23 for MT hardening): every state
// transition in evict/swap-in/discard uses @cmpxchgStrong on the PTE so two
// CPUs racing on the same VA can't both "win" — exactly one transition
// succeeds, the loser unwinds (free slot, free local frame) and bails.
const SWAPPED: u64 = 1 << 10;
const SWAP_INFLIGHT: u64 = 1 << 11;
const SLOT_SHIFT: u6 = 12;

// Bits needed to encode every slot index, derived from NUM_SLOTS so the mask
// can't silently lag a future capacity bump (would lop off high slot bits and
// silently corrupt swap-in). Asserted to stay inside the architectural 52-bit
// physical-address field, since the SWAPPED PTE encoding lives there.
const SLOT_BITS: u6 = @intCast(@bitSizeOf(usize) - @clz(@as(usize, NUM_SLOTS - 1)));
const SLOT_MASK: u64 = (@as(u64, 1) << SLOT_BITS) - 1;
// The slot's generation tag sits directly above the slot field (see slot_gen).
// Only PTE bit-equality consumes it — nothing ever decodes it back out.
const GEN_SHIFT: u6 = SLOT_SHIFT + SLOT_BITS;
comptime {
    std.debug.assert(GEN_SHIFT + 8 <= 52); // gen tag inside the 52-bit phys field
    std.debug.assert((@as(usize, 1) << SLOT_BITS) >= NUM_SLOTS);
}

inline fn makeSwapPte(slot: u32) u64 {
    // Gen read is lock-free: the caller OWNS `slot` (between its allocSlot and
    // freeSlot), and only freeSlot bumps a slot's gen — so the value is stable
    // here. allocSlot's lock acquire published any prior owner's bump.
    const gen = @atomicLoad(u8, &slot_gen[slot], .monotonic);
    return (@as(u64, gen) << GEN_SHIFT) | (@as(u64, slot) << SLOT_SHIFT) | SWAPPED;
}

inline fn makeInflightPte(frame_phys: usize) u64 {
    // Frame is page-aligned (low 12 bits zero) so SWAP_INFLIGHT (bit 11) and
    // the frame address don't overlap. PRESENT (bit 0) stays 0 by construction.
    return frame_phys | SWAP_INFLIGHT;
}

inline fn inflightFrame(pte: u64) usize {
    return @intCast(pte & paging.PAGE_MASK);
}

/// True if `pte` encodes a page that is currently out on swap.
pub inline fn pteIsSwapped(pte: u64) bool {
    return (pte & paging.PRESENT) == 0 and (pte & SWAPPED) != 0;
}

/// True if `pte` encodes a page that is mid-eviction (writePage in flight).
/// Faulters that hit this state must wait on `.swap_evict` until the
/// evicting thread CASes the PTE to SWAPPED (or back, on I/O failure).
pub inline fn pteIsInflight(pte: u64) bool {
    return (pte & paging.PRESENT) == 0 and (pte & SWAP_INFLIGHT) != 0;
}

/// Wait-target encoding for `.swap_evict`. Each leaf PTE lives at a unique
/// kernel VA (per-process page tables), so truncating that VA to u32 gives a
/// stable identifier for the (process, page) pair. Cross-VA collisions only
/// cause spurious wakes — the faulter re-reads the PTE on resume and rolls
/// back into blockOn if the eviction hasn't completed.
pub inline fn evictWaitTarget(pte_ptr: *const u64) u32 {
    return @truncate(@intFromPtr(pte_ptr));
}

inline fn pteSlot(pte: u64) u32 {
    return @intCast((pte >> SLOT_SHIFT) & SLOT_MASK);
}

/// Race-aware teardown for non-PRESENT PTEs. CAS-claims the PTE to 0 and
/// releases the backing resource (slot for SWAPPED, frame for SWAP_INFLIGHT).
/// Retries on CAS loss until the PTE is 0 or in an encoding we don't manage.
/// Returns true if any work was done.
///
/// Why CAS instead of plain store: an evicting thread may concurrently flip
/// SWAP_INFLIGHT → SWAPPED on the same PTE (or restore it on I/O failure).
/// Without CAS, teardown could (a) freeFrame on the in-flight frame, then
/// evictor's CAS succeeds and it tries to freeFrame again from a stale read,
/// or (b) overwrite SWAPPED with 0 between evictor's CAS and teardown's
/// release-slot, leaking the slot. The CAS-winner pattern ensures exactly one
/// party performs each cleanup.
pub fn teardownNonPresent(pte_ptr: *u64) bool {
    while (true) {
        const cur = @atomicLoad(u64, pte_ptr, .acquire);
        if (cur == 0) return false;
        if ((cur & paging.PRESENT) != 0) return false; // caller handles
        if (!pteIsSwapped(cur) and !pteIsInflight(cur)) return false;
        if (@cmpxchgStrong(u64, pte_ptr, cur, 0, .seq_cst, .seq_cst) != null) {
            continue; // CAS lost — re-read
        }
        if (pteIsSwapped(cur)) {
            freeSlot(pteSlot(cur));
        } else { // pteIsInflight
            pmm.freeFrame(inflightFrame(cur));
        }
        return true;
    }
}

/// Evict one present user page to swap, freeing its physical frame. `pte_ptr`
/// points at the live (present) leaf PTE; `va` is its user virtual address;
/// `pcid` is the owning address space's PCID (for the TLB shootdown). Returns
/// true iff the frame was freed and the PTE rewritten to a swapped entry; on
/// any failure (swap full / NVMe error / lost CAS race) the PTE and frame are
/// left in a consistent state and the caller can retry.
///
/// Three-phase MT-safe sequence (added 2026-05-23):
///   1. CAS the live PTE to SWAP_INFLIGHT encoding (frame_phys + marker bit,
///      PRESENT=0). Shootdown so peers can no longer write via stale TLB.
///      Any thread that now touches the page faults and waits on .swap_evict
///      via `blockOnSwapEvict` until phase 3 completes.
///   2. writePage may block (async NVMe). The frame's contents are stable
///      because no PTE in any AS still maps the frame (refcount==1 guard +
///      shootdown).
///   3. CAS the in-flight PTE to SWAPPED (slot index). Wake waiters and free
///      the frame.
///
/// Failure paths:
///   - allocSlot returns null → no PTE change, return false.
///   - Phase-1 CAS fails → another CPU is evicting (or the PTE changed e.g.
///     teardown). freeSlot, return false. PTE untouched by us.
///   - writePage fails → CAS the PTE back to its original value; freeSlot;
///     wake waiters; return false. If the back-CAS itself fails the process
///     was torn down — the inflight teardown handler already freed the frame.
///   - Phase-3 CAS fails → teardownNonPresent (or unmapUserRange's racing
///     PRESENT-branch) wiped the PTE and already freed the frame. freeSlot,
///     wake waiters, return false — no freeFrame here.
pub fn evictFrame(pte_ptr: *u64, va: usize, pcid: u16) bool {
    // Non-atomic snapshot is fine because the CAS below rejects a stale
    // sample, but promote to atomicLoad for consistency with the sibling
    // @atomicLoad sites in teardownNonPresent / swapInFrame's CAS-loss path.
    const original = @atomicLoad(u64, pte_ptr, .acquire);
    if ((original & paging.PRESENT) == 0) return false; // nothing present to evict
    const frame = original & paging.PAGE_MASK;
    // [mtswap-trace] gated to stress-test pids (current_pid >= 4). evictFrame
    // is on the hot reclaim path; ungated logging would drown the log under
    // normal swap activity.
    const evict_pid: u32 = if (smp.myCpu().current_pid) |p| @intCast(p) else 0xFF;
    const etrace = evict_pid >= 4;
    const ecpu = smp.myCpu().cpu_id;
    // Refcount guard: only evict a frame this address space SOLELY owns. A
    // refcount > 1 means the frame is dual-owned — e.g. the GUI framebuffer
    // (mapped into the app AND held by the kernel compositor via
    // pmm.acquireFrame). Evicting it would mark the app's PTE swapped while
    // the compositor keeps using the physical frame; swap-in would then hand
    // the app a fresh frame with stale contents -> silent FB corruption. Same
    // refcount==1 predicate the COW handler trusts. (zig-osdev-reviewer catch.)
    if (pmm.frameRefCount(frame) != 1) return false;
    const slot = allocSlot() orelse {
        if (etrace) debug.klog("[mtswap-trace] pid={d} cpu{d} evict_no_slot va=0x{X}\n", .{ evict_pid, ecpu, va });
        return false;
    };

    // --- Phase 1: claim the page via CAS to the in-flight encoding ---
    const inflight = makeInflightPte(frame);
    if (@cmpxchgStrong(u64, pte_ptr, original, inflight, .seq_cst, .seq_cst)) |_| {
        // Lost the race — another CPU evicted, the page was unmapped, or it
        // got modified between the read and the CAS. Bail with no side effects
        // beyond the slot bookkeeping.
        if (etrace) debug.klog("[mtswap-trace] pid={d} cpu{d} evict_p1_cas_lost va=0x{X}\n", .{ evict_pid, ecpu, va });
        freeSlot(slot);
        return false;
    }
    // Publish the in-flight slot to the calling thread's PCB so process
    // teardown can free it if this thread is killed mid-writePage. Cleared
    // again at phase-3 commit / writePage-fail rollback.
    process.setInflightSlot(slot);
    if (etrace) debug.klog("[mtswap-trace] pid={d} cpu{d} evict_p2_shootdown_begin va=0x{X} slot={d}\n", .{ evict_pid, ecpu, va, slot });
    // Shootdown BEFORE writePage so peers' TLBs can't satisfy writes via the
    // pre-CAS PRESENT entry. After shootdownPage returns, every CPU has
    // observed PRESENT=0; further writes fault and the handler will block.
    tlb.shootdownPage(pcid, va);
    if (etrace) debug.klog("[mtswap-trace] pid={d} cpu{d} evict_p2_shootdown_end va=0x{X}\n", .{ evict_pid, ecpu, va });

    // --- Phase 2: write the frame contents to swap (may block under async) ---
    if (etrace) debug.klog("[mtswap-trace] pid={d} cpu{d} evict_p2_writePage_begin slot={d} frame=0x{X}\n", .{ evict_pid, ecpu, slot, frame });
    const wok = writePage(slot, frame);
    if (etrace) debug.klog("[mtswap-trace] pid={d} cpu{d} evict_p2_writePage_end ok={any}\n", .{ evict_pid, ecpu, wok });
    if (!wok) {
        // Restore the PTE so userspace re-enters with the page resident. If
        // a concurrent writer (teardownNonPresent or unmapUserRange's
        // PRESENT-branch race) wiped our in-flight entry while we were in
        // writePage, they already freed the frame and the back-CAS fails —
        // bail without double-freeing.
        if (@cmpxchgStrong(u64, pte_ptr, inflight, original, .seq_cst, .seq_cst) == null) {
            tlb.shootdownPage(pcid, va);
        }
        process.clearInflightSlot();
        freeSlot(slot);
        wakeSwapEvictWaiters(evictWaitTarget(pte_ptr));
        return false;
    }

    // --- Phase 3: commit by transitioning in-flight → SWAPPED ---
    if (etrace) debug.klog("[mtswap-trace] pid={d} cpu{d} evict_p3_commit_begin\n", .{ evict_pid, ecpu });
    if (@cmpxchgStrong(u64, pte_ptr, inflight, makeSwapPte(slot), .seq_cst, .seq_cst)) |_| {
        // Phase-3 CAS failed → PTE was cleared by either teardownNonPresent or
        // unmapUserRange's PRESENT-branch race (which already freed the frame).
        // Don't double-free. The slot holds data nobody will ever read; free it.
        if (etrace) debug.klog("[mtswap-trace] pid={d} cpu{d} evict_p3_cas_lost\n", .{ evict_pid, ecpu });
        process.clearInflightSlot();
        freeSlot(slot);
        wakeSwapEvictWaiters(evictWaitTarget(pte_ptr));
        return false;
    }
    // Frame is no longer referenced by any PTE; release it. No shootdown
    // needed here — phase 1's shootdown already cleared the present mapping,
    // and the in-flight→SWAPPED transition keeps PRESENT=0.
    process.clearInflightSlot();
    pmm.freeFrame(frame);
    wakeSwapEvictWaiters(evictWaitTarget(pte_ptr));
    if (etrace) debug.klog("[mtswap-trace] pid={d} cpu{d} evict_done slot={d}\n", .{ evict_pid, ecpu, slot });
    const out = @atomicRmw(u64, &pages_out, .Add, 1, .monotonic) + 1;
    if (out == 1 or out % 4096 == 0)
        debug.klog("[swap] out={d} in={d} sc={d} dc={d} slots={d}/{d}\n", .{
            out,
            @atomicLoad(u64, &pages_in, .monotonic),
            @atomicLoad(u64, &pages_second_chance, .monotonic),
            @atomicLoad(u64, &pages_discarded, .monotonic),
            @atomicLoad(usize, &used_count, .monotonic),
            NUM_SLOTS,
        });
    return true;
}

/// Wake every thread blocked on `.swap_evict` with this target. Mirrors
/// `wakeMutexWaiters`; thin dispatch into the proc subsystem.
fn wakeSwapEvictWaiters(target: u32) void {
    process.wakeSwapEvictWaiters(target);
}

/// Discard a clean, file-backed page: zero the PTE, shootdown, free the frame.
/// No swap I/O — the lazy-fault path will re-read from the region's `source`
/// buffer on next touch (handleUserPageFault loads the file image just as on
/// the first fault). Returns false (PTE untouched) if the frame is shared
/// (refcount > 1) — same conservatism as `evictFrame`, to keep the dual-owned
/// frame class (GUI framebuffer pages, etc.) out of reclaim.
///
/// Caller must have already verified that (a) the page is file-backed (the
/// owning lazy_region has `source != null`) and (b) the PTE's DIRTY bit is
/// clear. With those preconditions the page is byte-identical to what
/// re-loading from `source` would produce, so dropping it is lossless. If
/// DIRTY is set the page has user modifications and MUST go through
/// `evictFrame` (preserve via swap) instead of being discarded.
pub fn discardFrame(pte_ptr: *u64, va: usize, pcid: u16) bool {
    const original = @atomicLoad(u64, pte_ptr, .acquire);
    if ((original & paging.PRESENT) == 0) return false;
    const frame = original & paging.PAGE_MASK;
    if (pmm.frameRefCount(frame) != 1) return false;
    // CAS to 0 so a concurrent evictor / teardown of the same VA can't both
    // try to free the frame. Loser of the race returns false without touching
    // anything. PTE = 0 returns the slot to the "never-faulted" state;
    // handleUserPageFault will reload from `source` on next touch.
    if (@cmpxchgStrong(u64, pte_ptr, original, 0, .seq_cst, .seq_cst)) |_| {
        return false;
    }
    tlb.shootdownPage(pcid, va);
    pmm.freeFrame(frame);
    const dc = @atomicRmw(u64, &pages_discarded, .Add, 1, .monotonic) + 1;
    if (dc == 1 or dc % 4096 == 0)
        debug.klog("[swap] out={d} in={d} sc={d} dc={d} slots={d}/{d}\n", .{
            @atomicLoad(u64, &pages_out, .monotonic),
            @atomicLoad(u64, &pages_in, .monotonic),
            @atomicLoad(u64, &pages_second_chance, .monotonic),
            dc,
            @atomicLoad(usize, &used_count, .monotonic),
            NUM_SLOTS,
        });
    return true;
}

/// Page a swapped-out entry back in. `pte_ptr` must satisfy pteIsSwapped();
/// `flags` are the leaf flags to OR with PRESENT (USER | RW? | NX, from the
/// region's prot). Allocates a fresh frame, reads the slot into it, installs
/// the present mapping, frees the slot, and flushes the VA. Returns false
/// (PTE untouched, slot retained) if no frame is available or the read fails —
/// the caller should free a frame (evict) and retry, or fall through.
pub fn swapInFrame(pte_ptr: *u64, va: usize, flags: u64, pcid: u16) bool {
    const original = @atomicLoad(u64, pte_ptr, .acquire);
    if (!pteIsSwapped(original)) {
        // Race-with-winner: between trySwapInPage's pteIsSwapped check
        // and our re-read here, another thread completed the swap-in
        // (PTE now PRESENT) or the process is tearing down (PTE → 0).
        // Either way, NOT an OOM — caller's PF-handler-retry path will
        // re-attempt the user access and find a usable mapping (or
        // re-fault into the lazy-region path on PTE=0).
        //
        // This is the SAME class of bug fixed for the CAS-loser case
        // below 2026-05-23 — the early-exit here was missed in that
        // sweep. Caught 2026-05-24 by [mtswap-trace] when pid 5 won
        // the CAS for va=0x713D000 and pid 6's swapInFrame returned
        // false here → trySwapInPage → .oom → OOM-killed pid 6.
        return true;
    }
    const slot = pteSlot(original);
    // [mtswap-trace] for the parked MT-stress wedge — see fault.zig.
    const cur_pid: u32 = if (smp.myCpu().current_pid) |p| @intCast(p) else 0xFF;
    if (cur_pid >= 4) debug.klog("[mtswap-trace] pid={d} cpu{d} swapIn slot={d} alloc...\n", .{
        cur_pid, smp.myCpu().cpu_id, slot,
    });
    // allocFrame (not allocFrameUser): swap-in is high priority — failing it
    // means data loss / a killed process — so it may use the reserve the
    // user allocator protects. Deliberate.
    const frame = pmm.allocFrame() orelse {
        if (cur_pid >= 4) debug.klog("[mtswap-trace] pid={d} cpu{d} swapIn FAIL_NO_FRAME\n", .{
            cur_pid, smp.myCpu().cpu_id,
        });
        return false;
    };
    if (cur_pid >= 4) debug.klog("[mtswap-trace] pid={d} cpu{d} swapIn readPage frame=0x{X}...\n", .{
        cur_pid, smp.myCpu().cpu_id, frame,
    });
    if (!readPage(slot, frame)) {
        if (cur_pid >= 4) debug.klog("[mtswap-trace] pid={d} cpu{d} swapIn readPage FAILED\n", .{
            cur_pid, smp.myCpu().cpu_id,
        });
        pmm.freeFrame(frame);
        return false;
    }
    if (cur_pid >= 4) debug.klog("[mtswap-trace] pid={d} cpu{d} swapIn readPage OK, CAS...\n", .{
        cur_pid, smp.myCpu().cpu_id,
    });
    // CAS so two threads racing to swap-in the same VA don't both install
    // PTEs / free the slot. The loser frees its freshly-read frame; the
    // slot was already freed by whoever moved the PTE on.
    const new_pte = (frame & paging.PAGE_MASK) | flags | paging.PRESENT;
    if (@cmpxchgStrong(u64, pte_ptr, original, new_pte, .seq_cst, .seq_cst)) |_| {
        pmm.freeFrame(frame);
        if (cur_pid >= 4) debug.klog("[mtswap-trace] pid={d} cpu{d} swapIn CAS_LOST post=0x{X}\n", .{
            cur_pid, smp.myCpu().cpu_id, @atomicLoad(u64, pte_ptr, .acquire),
        });
        // CAS loss ⇒ another thread made progress on this PTE since our read.
        // Every possible current state resolves through the caller's re-fault:
        // PRESENT (winner installed — access just works), 0 (teardown/munmap —
        // lazy reload or SIGSEGV, both correct), SWAPPED again (winner + user
        // write + re-evict — next fault swaps it back in), SWAP_INFLIGHT
        // (re-evict in progress — faulter blocks on .swap_evict). So report
        // success unconditionally; only OUR OWN alloc/IO failures may return
        // false. The old `post & PRESENT` filter wrongly cascaded the 0 and
        // re-SWAPPED shapes to trySwapInPage → .oom → OOM-kill of an innocent
        // process — the same CAS-loss regression class as 2026-05-23/24, one
        // more spot those sweeps missed.
        return true;
    }
    if (cur_pid >= 4) debug.klog("[mtswap-trace] pid={d} cpu{d} swapIn CAS_WON shootdown va=0x{X}\n", .{
        cur_pid, smp.myCpu().cpu_id, va,
    });
    // Flush the stale not-present entry on peers AND this CPU (shootdownPage's
    // flushLocalForMode INVLPG backstop) so the freshly-installed frame is
    // visible immediately on the faulting CPU.
    tlb.shootdownPage(pcid, va);
    freeSlot(slot);
    if (cur_pid >= 4) debug.klog("[mtswap-trace] pid={d} cpu{d} swapIn DONE\n", .{
        cur_pid, smp.myCpu().cpu_id,
    });
    const in_n = @atomicRmw(u64, &pages_in, .Add, 1, .monotonic) + 1;
    if (in_n == 1 or in_n % 4096 == 0)
        debug.klog("[swap] out={d} in={d} sc={d} dc={d} slots={d}/{d}\n", .{
            @atomicLoad(u64, &pages_out, .monotonic),
            in_n,
            @atomicLoad(u64, &pages_second_chance, .monotonic),
            @atomicLoad(u64, &pages_discarded, .monotonic),
            @atomicLoad(usize, &used_count, .monotonic),
            NUM_SLOTS,
        });
    return true;
}
