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

const debug = @import("../debug/debug.zig");
const pmm = @import("pmm.zig");
const paging = @import("paging.zig");
const nvme = @import("../driver/nvme.zig");
const tlb = @import("../cpu/tlb.zig");
const SpinLock = @import("../proc/spinlock.zig").SpinLock;

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

pub var available: bool = false;
var slot_used: [NUM_SLOTS / 8]u8 = [_]u8{0} ** (NUM_SLOTS / 8);
var used_count: usize = 0;
var next_scan: usize = 0; // round-robin hint for allocSlot
// Guards the slot bitmap. Phase 2's evict / swap-in run in the page-fault
// handler on any CPU, so allocSlot/freeSlot must be serialized. NVMe I/O is
// done OUTSIDE this lock (no I/O is held under it).
var slot_lock: SpinLock = .{};

// Stats (Phase 2/3 will bump these).
pub var pages_out: u64 = 0; // pages written to swap (evictions)
pub var pages_in: u64 = 0; // pages read back (swap-ins)
pub var pages_second_chance: u64 = 0; // candidates spared by the clock (A bit set) — bumped by reclaimViaSwap

inline fn bitGet(slot: usize) bool {
    return (slot_used[slot >> 3] & (@as(u8, 1) << @as(u3, @intCast(slot & 7)))) != 0;
}
inline fn bitSet(slot: usize) void {
    slot_used[slot >> 3] |= (@as(u8, 1) << @as(u3, @intCast(slot & 7)));
}
inline fn bitClear(slot: usize) void {
    slot_used[slot >> 3] &= ~(@as(u8, 1) << @as(u3, @intCast(slot & 7)));
}

/// Reserve a free swap slot. Returns its index, or null if swap is full or
/// unavailable. (Not yet locked — Phase 1's only caller is the boot self-test;
/// Phase 2 adds a lock when the page-fault path calls this concurrently.)
pub fn allocSlot() ?u32 {
    if (!available) return null;
    slot_lock.acquire();
    defer slot_lock.release();
    if (used_count >= NUM_SLOTS) return null;
    var scanned: usize = 0;
    var s = next_scan;
    while (scanned < NUM_SLOTS) : (scanned += 1) {
        if (!bitGet(s)) {
            bitSet(s);
            used_count += 1;
            next_scan = (s + 1) % NUM_SLOTS;
            return @intCast(s);
        }
        s = (s + 1) % NUM_SLOTS;
    }
    return null;
}

/// Release a swap slot (after its page was read back in, or its owner died).
pub fn freeSlot(slot: u32) void {
    if (slot >= NUM_SLOTS) return;
    slot_lock.acquire();
    defer slot_lock.release();
    if (!bitGet(slot)) return; // double-free guard
    bitClear(slot);
    used_count -= 1;
}

/// Write a 4 KiB physical frame out to swap slot `slot`. `frame_phys` is a
/// PMM frame's physical address. Returns false if swap is unavailable or the
/// NVMe write reports failure.
pub fn writePage(slot: u32, frame_phys: usize) bool {
    if (!available or slot >= NUM_SLOTS) return false;
    const va = paging.physToVirt(frame_phys);
    return nvme.writeSectorsOn(SWAP_CTRL_IDX, slot * SECTORS_PER_PAGE, SECTORS_PER_PAGE, @ptrFromInt(va));
}

/// Read swap slot `slot` back into a 4 KiB physical frame.
pub fn readPage(slot: u32, frame_phys: usize) bool {
    if (!available or slot >= NUM_SLOTS) return false;
    const va = paging.physToVirt(frame_phys);
    return nvme.readSectorsOn(SWAP_CTRL_IDX, slot * SECTORS_PER_PAGE, SECTORS_PER_PAGE, @ptrFromInt(va));
}

pub fn slotsUsed() usize {
    return used_count;
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
// A swapped-out page's PTE has PRESENT=0, the SWAPPED marker (bit 10 — COW is
// bit 9, so they never collide), and the swap slot index in bits 12+. This is
// distinguishable from a never-mapped PTE (all zero) and any present mapping.
// The CPU ignores every bit when PRESENT=0, so only our swap-in path reads it.
const SWAPPED: u64 = 1 << 10;
const SLOT_SHIFT: u6 = 12;

inline fn makeSwapPte(slot: u32) u64 {
    return (@as(u64, slot) << SLOT_SHIFT) | SWAPPED;
}

/// True if `pte` encodes a page that is currently out on swap.
pub inline fn pteIsSwapped(pte: u64) bool {
    return (pte & paging.PRESENT) == 0 and (pte & SWAPPED) != 0;
}

inline fn pteSlot(pte: u64) u32 {
    return @intCast((pte >> SLOT_SHIFT) & 0xF_FFFF); // 20-bit field covers all NUM_SLOTS
}

/// If `pte` encodes a swapped-out page, release its backing swap slot and
/// return true; no-op (returns false) for any other PTE. Call during
/// address-space teardown (destroyAddressSpace) and munmap (unmapUserRange) so
/// an evicted page's slot isn't leaked when its owner goes away without ever
/// faulting it back in. Without this, a process that exits or unmaps while
/// holding swapped pages permanently consumes those slots until reboot.
/// NOTE: this only releases the slot — it does NOT zero the PTE. Callers that
/// keep the page table around (unmapUserRange) must zero the PTE themselves so
/// the empty-PT reclamation doesn't see a dangling swapped entry.
pub fn releaseIfSwapped(pte: u64) bool {
    if (!pteIsSwapped(pte)) return false;
    freeSlot(pteSlot(pte));
    return true;
}

/// Evict one present user page to swap, freeing its physical frame. `pte_ptr`
/// points at the live (present) leaf PTE; `va` is its user virtual address;
/// `pcid` is the owning address space's PCID (for the TLB shootdown). Returns
/// true iff the frame was freed and the PTE rewritten to a swapped entry; on
/// any failure (swap full / NVMe error) the PTE and frame are left untouched.
///
/// Ordering: copy the still-present page out, THEN rewrite the PTE to
/// not-present + shootdown, THEN free the frame — so no CPU can reach the
/// frame through a stale TLB entry once it is freed.
///
/// Multi-thread caveat (widened by async swap I/O 2026-05-23): a concurrent
/// write to this exact page on another CPU between the writePage copy and
/// the PTE rewrite could be lost. Pre-async this window was ~50-200 µs
/// (sync poll); post-async it's up to a full scheduling slice (ms-scale)
/// because writePage now yields. The PTE rewrite is also a plain store,
/// not CAS — two CPUs hitting the same VA race to install a swap slot and
/// one slot leaks. Both are tolerated for now because (a) Phase 2 evicts
/// only cold pages of single-threaded workloads, and (b) the refcount==1
/// guard below already refuses shared-frame eviction. Per-page I/O lock +
/// CAS rewrite is the proper hardening — deferred.
pub fn evictFrame(pte_ptr: *u64, va: usize, pcid: u16) bool {
    const pte = pte_ptr.*;
    if ((pte & paging.PRESENT) == 0) return false; // nothing present to evict
    const frame = pte & paging.PAGE_MASK;
    // Refcount guard: only evict a frame this address space SOLELY owns. A
    // refcount > 1 means the frame is dual-owned — e.g. the GUI framebuffer
    // (mapped into the app AND held by the kernel compositor via
    // pmm.acquireFrame). Evicting it would mark the app's PTE swapped while
    // the compositor keeps using the physical frame; swap-in would then hand
    // the app a fresh frame with stale contents -> silent FB corruption. Same
    // refcount==1 predicate the COW handler trusts. (zig-osdev-reviewer catch.)
    if (pmm.frameRefCount(frame) != 1) return false;
    const slot = allocSlot() orelse return false;
    if (!writePage(slot, frame)) {
        freeSlot(slot);
        return false;
    }
    pte_ptr.* = makeSwapPte(slot);
    // Drops the stale present mapping on peers AND this CPU. shootdownPage's
    // local flush (flushLocalForMode, tlb.zig) includes an INVLPG backstop that
    // reliably clears THIS CPU's (pcid, va) entry under nested virt — where
    // INVPCID type-0 under-invalidates — BEFORE we free the frame, so no TLB
    // entry can reach the freed (and soon recycled) frame.
    tlb.shootdownPage(pcid, va);
    pmm.freeFrame(frame);
    pages_out += 1;
    if (pages_out == 1 or pages_out % 4096 == 0)
        debug.klog("[swap] out={d} in={d} sc={d} slots={d}/{d}\n", .{ pages_out, pages_in, pages_second_chance, used_count, NUM_SLOTS });
    return true;
}

/// Page a swapped-out entry back in. `pte_ptr` must satisfy pteIsSwapped();
/// `flags` are the leaf flags to OR with PRESENT (USER | RW? | NX, from the
/// region's prot). Allocates a fresh frame, reads the slot into it, installs
/// the present mapping, frees the slot, and flushes the VA. Returns false
/// (PTE untouched, slot retained) if no frame is available or the read fails —
/// the caller should free a frame (evict) and retry, or fall through.
pub fn swapInFrame(pte_ptr: *u64, va: usize, flags: u64, pcid: u16) bool {
    const pte = pte_ptr.*;
    if (!pteIsSwapped(pte)) return false;
    const slot = pteSlot(pte);
    // allocFrame (not allocFrameUser): swap-in is high priority — failing it
    // means data loss / a killed process — so it may use the reserve the
    // user allocator protects. Deliberate.
    const frame = pmm.allocFrame() orelse return false;
    if (!readPage(slot, frame)) {
        pmm.freeFrame(frame);
        return false;
    }
    pte_ptr.* = (frame & paging.PAGE_MASK) | flags | paging.PRESENT;
    // Flush the stale not-present entry on peers AND this CPU (shootdownPage's
    // flushLocalForMode INVLPG backstop) so the freshly-installed frame is
    // visible immediately on the faulting CPU.
    tlb.shootdownPage(pcid, va);
    freeSlot(slot);
    pages_in += 1;
    if (pages_in == 1 or pages_in % 4096 == 0)
        debug.klog("[swap] out={d} in={d} sc={d} slots={d}/{d}\n", .{ pages_out, pages_in, pages_second_chance, used_count, NUM_SLOTS });
    return true;
}
