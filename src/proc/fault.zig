//! Page-fault + lazy-region + swap-in path. Split out of process.zig (#810).
//!
//! Owns the kernel's response to user-mode #PF (handleUserPageFault), the
//! cooperative kernel-side prefault (prefaultUserRange + ensureUserRangeWritable
//! for SMAP/signal-frame work), the lazy-region registry (addLazyRegion*), and
//! the reclaim/swap-in plumbing (reclaimViaSwap, trySwapInPage).
//!
//! Re-exported from process.zig so external callers keep using process.X
//! paths unchanged.

const std = @import("std");

const debug = @import("../debug/debug.zig");
const vmm = @import("../mm/vmm.zig");
const pmm = @import("../mm/pmm.zig");
const swap = @import("../mm/swap.zig");
const smp = @import("../cpu/smp.zig");

const process = @import("process.zig");
const PCB = process.PCB;
const MAX_PROCS = process.MAX_PROCS;
const MAX_LAZY_REGIONS = process.MAX_LAZY_REGIONS;
const leader = process.leader;

/// Register a lazy region — pages in [start, end) get allocated on first
/// touch via the page-fault handler. Returns false if the table is full or
/// the bounds are invalid. Pages still allocate-and-zero on miss; this just
/// avoids paying for them upfront.
pub fn addLazyRegion(pid: usize, start: usize, end: usize, flags: u8) bool {
    if (end <= start) return false;
    const pcb = &process.procs[pid];
    if (pcb.lazy_count >= MAX_LAZY_REGIONS) return false;
    pcb.lazy_regions[pcb.lazy_count] = .{ .start = start, .end = end, .flags = flags };
    pcb.lazy_count += 1;
    return true;
}

/// Register a lazy region backed by a kernel buffer (used for demand-paged
/// ELF segments). On first touch of any page in [start, end), the page-fault
/// handler allocates+zeros a frame, then copies bytes from
/// `source[src_offset + (page_va - src_va_base)]` for the intersection of the
/// page with [src_va_base, src_va_base + src_size). Bytes outside that
/// intersection (BSS, segment alignment padding) stay zero.
pub fn addLazyRegionWithSource(
    pid: usize,
    start: usize,
    end: usize,
    flags: u8,
    source: [*]const u8,
    src_va_base: usize,
    src_size: usize,
    src_offset: usize,
) bool {
    if (end <= start) return false;
    const pcb = &process.procs[pid];
    if (pcb.lazy_count >= MAX_LAZY_REGIONS) return false;
    pcb.lazy_regions[pcb.lazy_count] = .{
        .start = start,
        .end = end,
        .flags = flags,
        .source = source,
        .src_va_base = src_va_base,
        .src_size = src_size,
        .src_offset = src_offset,
    };
    pcb.lazy_count += 1;
    return true;
}

/// Walk PML4→PT for `va` and return a writable pointer to its 4 KB PTE,
/// or null if the path is missing or the address is covered by a huge page.
/// Used by the COW handler to mutate the PTE in place after copying.
fn findUserPte(pml4: [*]align(4096) u64, va: usize) ?*u64 {
    const paging = @import("../mm/paging.zig");
    const PRESENT_F: u64 = 1;
    const PAGE_SIZE_F: u64 = 1 << 7;
    const MASK: u64 = 0x000FFFFFFFFFF000;

    if (pml4[(va >> 39) & 0x1FF] & PRESENT_F == 0) return null;
    const pdpt: [*]u64 = @ptrFromInt(paging.physToVirt(pml4[(va >> 39) & 0x1FF] & MASK));
    const pdpte = pdpt[(va >> 30) & 0x1FF];
    if (pdpte & PRESENT_F == 0 or pdpte & PAGE_SIZE_F != 0) return null;
    const pd: [*]u64 = @ptrFromInt(paging.physToVirt(pdpte & MASK));
    const pde = pd[(va >> 21) & 0x1FF];
    if (pde & PRESENT_F == 0 or pde & PAGE_SIZE_F != 0) return null;
    const pt: [*]u64 = @ptrFromInt(paging.physToVirt(pde & MASK));
    return &pt[(va >> 12) & 0x1FF];
}

/// Copy-on-write fault path. Triggered when a user write hits a present PTE
/// that has the COW software bit set (cloneAddressSpace marks both parent and
/// child PTEs this way). Allocates a private frame for the faulting AS,
/// copies the shared frame's contents in, swaps the PTE to point at the new
/// frame R/W, and drops one refcount on the shared frame. If we were the only
/// owner (refcount==1), skip the copy and just promote in place.
fn handleCowFault(pml4: [*]align(4096) u64, cr2: usize) bool {
    const paging = @import("../mm/paging.zig");
    const va_aligned = cr2 & ~@as(usize, 0xFFF);
    const pte_p = findUserPte(pml4, va_aligned) orelse return false;
    const pte = pte_p.*;
    if (pte & paging.COW == 0) return false;

    // Shared-anon escape hatch: cloneAddressSpace marks every writable PTE COW
    // without knowing about lazy regions, so a fork'd shared-anon page lands
    // here on first write. We must NOT copy — that would break sharing. Clear
    // COW + restore W and bail; the frame stays mapped at the same phys in
    // both ASs, preserving POSIX MAP_SHARED semantics.
    {
        const cur = smp.myCpu().current_pid orelse return false;
        const pcb = &process.procs[cur];
        const lead = leader(pcb);
        const shm = @import("../mm/shm.zig");
        var i: u8 = 0;
        while (i < lead.lazy_count) : (i += 1) {
            const r = lead.lazy_regions[i];
            if (r.shm_id == shm.SHM_INVALID) continue;
            if (va_aligned < r.start or va_aligned >= r.end) continue;
            pte_p.* = (pte & ~paging.COW) | paging.READ_WRITE;
            asm volatile ("invlpg (%[addr])"
                :
                : [addr] "r" (va_aligned),
                : .{ .memory = true }
            );
            return true;
        }
    }

    const old_phys = pte & paging.PAGE_MASK;

    // Sole-owner promote-in-place. Refcount may race against another CPU's
    // releaseFrame on the same shared frame, but the only outcome of being
    // wrong here is taking the slow path unnecessarily — never incorrect.
    if (pmm.frameRefCount(old_phys) == 1) {
        pte_p.* = (pte & ~paging.COW) | paging.READ_WRITE;
        asm volatile ("invlpg (%[addr])"
            :
            : [addr] "r" (va_aligned),
            : .{ .memory = true }
        );
        return true;
    }

    // Multiple owners — alloc a private copy. Use the user-reserve-
    // aware allocator: a runaway COW fault storm during memory pressure
    // shouldn't be allowed to deplete the kernel's emergency pool.
    const new_phys = pmm.allocFrameUser() orelse return false;
    const src: [*]const u8 = @ptrFromInt(paging.physToVirt(old_phys));
    const dst: [*]u8 = @ptrFromInt(paging.physToVirt(new_phys));
    @memcpy(dst[0..0x1000], src[0..0x1000]);

    // Replace phys field, clear COW, restore R/W. Other flag bits (USER, NX,
    // accessed/dirty) are inherited from the COW PTE.
    pte_p.* = (pte & ~paging.PAGE_MASK & ~paging.COW) | new_phys | paging.READ_WRITE;

    pmm.releaseFrame(old_phys);

    asm volatile ("invlpg (%[addr])"
        :
        : [addr] "r" (va_aligned),
        : .{ .memory = true }
    );
    return true;
}

/// Ensure every page overlapping [va, va+len) in the CURRENT process's user
/// address space is present AND writable, performing the same lazy fault-in +
/// copy-on-write break the ring-3 #PF path does — but proactively, WITHOUT
/// taking a fault. Returns false if any page can't be made writable (no lazy
/// region covers it, or OOM).
///
/// WHY this exists: signal delivery writes the handler frame DIRECTLY to the
/// user stack inside a SMAP `stac` bracket. This kernel's #PF handler only
/// services ring-3 faults (idt.zig gates lazy/COW on `saved_cs & 3`), so a
/// kernel-mode (stac'd) write to a not-yet-faulted-in or still-COW stack page
/// would hit the kernel-fault autopsy and PANIC instead of paging in. The
/// realistic triggers are a freshly fork()'d process whose stack is still COW,
/// and a frame that spans into a lower stack page not yet lazily mapped.
/// Pre-resolving the frame's pages here removes the fault entirely.
///
/// Mirrors handleUserPageFault's COW (handleCowFault) + lazy (allocAndMapUserPage)
/// dispatch, but keyed on the live PTE state rather than a fault error code.
/// Adds an explicit invlpg after a fresh map: mapUserPage only flushes on the
/// remap path (the fault path relies on the faulting instruction's re-walk,
/// which a proactive caller doesn't have).
pub fn ensureUserRangeWritable(va: usize, len: usize) bool {
    if (len == 0) return true;
    const cur = smp.myCpu().current_pid orelse return false;
    const pcb = &process.procs[cur];
    const pd = pcb.page_directory orelse return false;
    const lead = leader(pcb);

    var p = va & ~@as(usize, 0xFFF);
    const end_excl = va +% len;
    while (p < end_excl) : (p += 0x1000) {
        if (vmm.resolveUserPhys(pd, p) != null) {
            // Present — break COW if needed. handleCowFault breaks + invlpg's a
            // COW page, and is a safe no-op on a non-COW page.
            _ = handleCowFault(pd, p);
            // A present page that is STILL read-only (e.g. an app that
            // mprotect'd its own stack region read-only) can't take our write —
            // fail delivery so the caller kills it (≈ SIGSEGV) rather than
            // panic on the kernel-mode #PF this kernel's ring-3-only handler
            // won't service.
            const paging = @import("../mm/paging.zig");
            const pte_ptr = findUserPte(pd, p) orelse return false;
            if (pte_ptr.* & paging.READ_WRITE == 0) return false;
        } else {
            // Not present — lazy fault-in via the owning region.
            var mapped = false;
            var i: u8 = 0;
            while (i < lead.lazy_count) : (i += 1) {
                const r = lead.lazy_regions[i];
                if (p < r.start or p >= r.end) continue;
                _ = vmm.allocAndMapUserPage(pd, p, vmm.protToMapFlags(r.prot)) catch return false;
                asm volatile ("invlpg (%[addr])"
                    :
                    : [addr] "r" (p),
                    : .{ .memory = true });
                mapped = true;
                break;
            }
            if (!mapped) return false; // no lazy region covers this page
        }
    }
    return true;
}

/// Free up to `want` physical frames by evicting cold, present, non-COW pages
/// of `lead`'s lazy regions out to swap (Phase 2: intra-process only). A
/// per-lead clock cursor (`swap_clock_va`) resumes the scan where it left off
/// so a linear >RAM workload stays O(n), and ITER_CAP bounds per-call work.
/// Skips `skip_va` (the page currently being faulted in). Returns frames freed;
/// no-op if swap is unavailable.
fn reclaimViaSwap(pml4: [*]align(4096) u64, lead: *PCB, skip_va: usize, pcid: u16, want: usize) usize {
    if (!swap.available or lead.lazy_count == 0) return 0;
    const paging = @import("../mm/paging.zig");
    var freed: usize = 0;
    var iters: usize = 0;
    const ITER_CAP: usize = 16384; // bounds total work (pages examined + gap hops)
    // [mtswap-trace] probes inside the loop are gated to stress-test pids
    // (the user-spawned mtswap workers) so regular reclaim stays quiet.
    const trace_pid: u32 = if (smp.myCpu().current_pid) |p| @intCast(p) else 0xFF;
    const rtrace = trace_pid >= 4;
    const trace_cpu = smp.myCpu().cpu_id;
    if (rtrace) debug.klog("[mtswap-trace] pid={d} cpu{d} reclaim_loop_enter va=0x{X} lazy_count={d}\n", .{
        trace_pid, trace_cpu, lead.swap_clock_va, lead.lazy_count,
    });
    // Second-chance (clock) aging: a recently-accessed page gets its A bit
    // cleared and is skipped this sweep rather than evicted. skip_budget bounds
    // how many such reprieves we hand out so an all-hot working set still makes
    // progress (once spent, we evict regardless of A) — without this bound a
    // freshly-touched buffer (every page A=1) would clear A's and evict nothing,
    // and the OOM caller would mistake freed==0 for genuine exhaustion.
    var skipped: usize = 0;
    const skip_budget: usize = want * 2;
    var va = lead.swap_clock_va;
    while (freed < want and iters < ITER_CAP) : (iters += 1) {
        // Is va inside a (non-empty) lazy region? Phase 3: we evict ANY private
        // user page — anonymous OR file-backed. File-backed pages used to be
        // skipped because (a) they're clean and re-faultable from `source`, and
        // (b) a swapped (not-present) PTE made kernel-side pointer validation
        // (validateUserPtr) return E_FAULT. (b) is now fixed — trySwapInPage
        // pages a swapped entry back in on the kernel user-access path too — so
        // eviction is transparent to syscalls and the restriction is lifted.
        // (Later optimization: DISCARD clean file-backed pages rather than
        // writing them to swap; they re-read from `source` for free.)
        var in_region = false;
        var region_has_source = false;
        var k: u8 = 0;
        while (k < lead.lazy_count) : (k += 1) {
            const r = lead.lazy_regions[k];
            if (r.end > r.start and va >= r.start and va < r.end) {
                in_region = true;
                region_has_source = r.source != null;
                break;
            }
        }
        if (!in_region) {
            // Jump to the next region start above va, else wrap to the lowest.
            var next_start: usize = 0;
            var found = false;
            var lo: usize = 0;
            var any = false;
            var j: u8 = 0;
            while (j < lead.lazy_count) : (j += 1) {
                const r = lead.lazy_regions[j];
                if (r.end <= r.start) continue;
                if (!any or r.start < lo) {
                    lo = r.start;
                    any = true;
                }
                if (r.start > va and (!found or r.start < next_start)) {
                    next_start = r.start;
                    found = true;
                }
            }
            if (!any) break; // no non-empty regions
            va = if (found) next_start else lo;
            continue;
        }
        if (va != skip_va) {
            if (vmm.userPtePtr(pml4, va)) |pte_ptr| {
                const pte = pte_ptr.*;
                if ((pte & paging.PRESENT) != 0 and (pte & paging.COW) == 0) {
                    if ((pte & paging.ACCESSED) != 0 and skipped < skip_budget) {
                        // Recently used: clear A and give it another sweep
                        // instead of evicting. CAS so a concurrent evictor's
                        // PRESENT→INFLIGHT write isn't clobbered by our
                        // non-atomic A-clear — pre-CAS this was a 2× eviction-
                        // count race (sc=2×out in the log) that wedged the MT
                        // stress test. If the CAS fails another thread changed
                        // the PTE; skip aging on this iteration (loop continues).
                        if (@cmpxchgStrong(u64, pte_ptr, pte, pte & ~paging.ACCESSED, .seq_cst, .seq_cst) == null) {
                            asm volatile ("invlpg (%[v])"
                                :
                                : [v] "r" (va),
                                : .{ .memory = true });
                            skipped += 1;
                        }
                    } else if (region_has_source and (pte & paging.DIRTY) == 0) {
                        if (rtrace) debug.klog("[mtswap-trace] pid={d} cpu{d} discard_call va=0x{X}\n", .{
                            trace_pid, trace_cpu, va,
                        });
                        const dok = swap.discardFrame(pte_ptr, va, pcid);
                        if (rtrace) debug.klog("[mtswap-trace] pid={d} cpu{d} discard_ret ok={any}\n", .{
                            trace_pid, trace_cpu, dok,
                        });
                        // Clean file-backed page: drop the PTE, no NVMe write.
                        // handleUserPageFault will reload from `source` on next
                        // touch. Skipping the swap-out is the whole point of
                        // the discard path — saves an NVMe round-trip per page
                        // for code segments, RO data, and any unwritten file
                        // mapping (which is most of an app's working set).
                        if (dok) {
                            freed += 1;
                        } else {
                            if (rtrace) debug.klog("[mtswap-trace] pid={d} cpu{d} evict_call va=0x{X}\n", .{
                                trace_pid, trace_cpu, va,
                            });
                            const eok = swap.evictFrame(pte_ptr, va, pcid);
                            if (rtrace) debug.klog("[mtswap-trace] pid={d} cpu{d} evict_ret ok={any}\n", .{
                                trace_pid, trace_cpu, eok,
                            });
                            if (eok) freed += 1;
                        }
                    } else {
                        if (rtrace) debug.klog("[mtswap-trace] pid={d} cpu{d} evict_call va=0x{X}\n", .{
                            trace_pid, trace_cpu, va,
                        });
                        const eok = swap.evictFrame(pte_ptr, va, pcid);
                        if (rtrace) debug.klog("[mtswap-trace] pid={d} cpu{d} evict_ret ok={any}\n", .{
                            trace_pid, trace_cpu, eok,
                        });
                        if (eok) freed += 1;
                    }
                }
            }
        }
        va += 0x1000;
        if (rtrace and (iters & 1023) == 0 and iters != 0) {
            debug.klog("[mtswap-trace] pid={d} cpu{d} reclaim_iter iters={d} freed={d} skipped={d} va=0x{X}\n", .{
                trace_pid, trace_cpu, iters, freed, skipped, va,
            });
        }
    }
    if (rtrace) debug.klog("[mtswap-trace] pid={d} cpu{d} reclaim_loop_exit iters={d} freed={d} skipped={d}\n", .{
        trace_pid, trace_cpu, iters, freed, skipped,
    });
    lead.swap_clock_va = va;
    swap.pages_second_chance +%= skipped;
    return freed;
}

/// Outcome of attempting a swap-in for one page.
///   not_swapped — PTE wasn't a swapped entry; caller proceeds normally.
///   paged_in    — page is now resident.
///   oom         — it WAS swapped but no frame could be obtained even after
///                 reclaim (genuine exhaustion); caller should fail/kill.
const SwapInOutcome = enum { not_swapped, paged_in, oom };

/// If `va`'s leaf PTE encodes a swapped page, page it back in — reclaiming cold
/// frames first if memory is tight. Shared by the page-fault handler AND the
/// kernel-side pointer prefault (validateUserPtr -> prefaultUserRange) so a
/// swapped-out user buffer handed to a syscall is paged in rather than failing
/// validation with E_FAULT. This is what makes evicting ANY user page (not just
/// Phase 2's anon-only subset) safe: the kernel can always fault it back in.
fn trySwapInPage(pd: [*]align(4096) u64, lead: *PCB, va: usize, prot: u8, pcid: u16) SwapInOutcome {
    if (!swap.available) return .not_swapped;
    const sp = vmm.userPtePtr(pd, va) orelse return .not_swapped;
    // [mtswap-trace] gated to the INTERESTING cases only — common
    // first-touch lazy-fault (pte=0) was producing 40k+ lines per run
    // and drowning the log. We only emit when this is an actual swap
    // candidate (pte non-zero and either in_flight or pteIsSwapped).
    const initial_pte = sp.*;
    const is_swap_candidate = initial_pte != 0 and
        (swap.pteIsInflight(initial_pte) or swap.pteIsSwapped(initial_pte));
    const cur_pid: u32 = if (smp.myCpu().current_pid) |p| @intCast(p) else 0xFF;
    const trace = is_swap_candidate and cur_pid >= 4;
    if (trace) debug.klog("[mtswap-trace] pid={d} cpu{d} swap_try va=0x{X} pte=0x{X}\n", .{
        cur_pid, smp.myCpu().cpu_id, va, initial_pte,
    });
    // MT case: another thread is mid-evicting this exact page. Wait until the
    // eviction commits (PTE → SWAPPED), aborts (→ PRESENT restored), or the
    // process is torn down (→ 0). The faulter is in a blockable context
    // (#PF runs IST=0 on its own kstack) so this is identical in shape to
    // the .nvme_io wait inside ioCommandAsync.
    if (swap.pteIsInflight(sp.*)) {
        if (trace) debug.klog("[mtswap-trace] pid={d} cpu{d} blockOnSwapEvict pte=0x{X}\n", .{
            cur_pid, smp.myCpu().cpu_id, sp.*,
        });
        process.blockOnSwapEvict(sp);
        if (trace) debug.klog("[mtswap-trace] pid={d} cpu{d} woke pte=0x{X}\n", .{
            cur_pid, smp.myCpu().cpu_id, sp.*,
        });
    }

    const pte = sp.*;
    // Eviction aborted and restored the original mapping while we waited —
    // page is resident now, the fault was caused by the eviction's shootdown.
    // Tell the caller to retry the user access.
    const paging = @import("../mm/paging.zig");
    if ((pte & paging.PRESENT) != 0) {
        if (trace) debug.klog("[mtswap-trace] pid={d} cpu{d} race_won_by_other paged_in\n", .{
            cur_pid, smp.myCpu().cpu_id,
        });
        return .paged_in;
    }
    if (!swap.pteIsSwapped(pte)) return .not_swapped;

    // Make sure a frame is free for the read-in; evict cold pages of this
    // process if memory is exhausted. skip_va = va so reclaim never re-targets
    // the very page we're about to swap in.
    const free_pre = pmm.freeFrameCount();
    if (free_pre < 64) {
        if (trace) debug.klog("[mtswap-trace] pid={d} cpu{d} reclaim_begin free={d}\n", .{
            cur_pid, smp.myCpu().cpu_id, free_pre,
        });
        const freed = reclaimViaSwap(pd, lead, va, pcid, 64);
        if (trace) debug.klog("[mtswap-trace] pid={d} cpu{d} reclaim_end freed={d} free_post={d}\n", .{
            cur_pid, smp.myCpu().cpu_id, freed, pmm.freeFrameCount(),
        });
    }
    if (trace) debug.klog("[mtswap-trace] pid={d} cpu{d} swapInFrame_begin\n", .{
        cur_pid, smp.myCpu().cpu_id,
    });
    const ok = swap.swapInFrame(sp, va, vmm.protToMapFlags(prot), pcid);
    if (trace) debug.klog("[mtswap-trace] pid={d} cpu{d} swapInFrame_end ok={any}\n", .{
        cur_pid, smp.myCpu().cpu_id, ok,
    });
    if (ok) return .paged_in;
    return .oom;
}

pub fn handleUserPageFault(cr2: usize, error_code: u64) bool {
    // Must be user-mode access (U=1, bit 2). Both non-present (P=0) and
    // protection violations (P=1) are valid lazy-fault triggers — the
    // latter happens because createAddressSpace strips USER from inherited
    // kernel-identity pages, so user access hits "present but no USER" PT
    // entries until we replace them with a fresh USER-bit mapping below.
    if ((error_code & 4) == 0) return false;
    const cur = smp.myCpu().current_pid orelse return false;
    const pcb = &process.procs[cur];
    // Accounting: count every user-mode page fault (handled or not) so the
    // counter reflects the load this PCB puts on the fault path. If we
    // counted only successful lazy fault-ins, "app keeps page-faulting on
    // an unmapped address" wouldn't show up.
    pcb.acct_pf_count +%= 1;
    const pd = pcb.page_directory orelse return false;

    // COW path: write fault on a present user page (P=1, W=1, U=1). Walk the
    // PT and dispatch handleCowFault if the PTE has the COW software bit set.
    // Lazy-region faults are P=0 (non-present); COW faults are P=1 and W=1.
    if ((error_code & 0x3) == 0x3) {
        if (handleCowFault(pd, cr2)) {
            @import("../debug/kdbg.zig").pfEvent(@intCast(cur), cr2, @truncate(error_code), 0, true);
            return true;
        }
    }
    // Lazy regions live on the lead thread (per-process resource). For
    // single-threaded processes this aliases pcb itself; for cloned
    // threads we read the parent's regions so mmap'd VAs are visible.
    const lead = leader(pcb);

    var i: u8 = 0;
    while (i < lead.lazy_count) : (i += 1) {
        const r = lead.lazy_regions[i];
        if (cr2 < r.start or cr2 >= r.end) continue;
        const va_aligned = cr2 & ~@as(usize, 0xFFF);

        // Shared-anon shortcut: map the precomputed phys from the shm region.
        // No swap, no fresh-alloc — the frame is owned by the shm registry and
        // shared across every attached AS. Same phys mapped into N AS's = N
        // PRESENT PTEs of the same frame; refcount management is in
        // forkCurrent/munmap/tearDown via shm.acquire/release.
        const shm = @import("../mm/shm.zig");
        if (r.shm_id != shm.SHM_INVALID) {
            const page_idx: u32 = @intCast((va_aligned - r.start) / 0x1000);
            const phys = shm.frameAt(r.shm_id, page_idx) orelse {
                debug.klog("[shm] frameAt miss id={d} pi={d} on fault — region torn down?\n", .{ r.shm_id, page_idx });
                return false;
            };
            vmm.mapUserPage(pd, va_aligned, phys, vmm.protToMapFlags(r.prot)) catch |e| {
                debug.klog("[shm] mapUserPage failed va=0x{X} phys=0x{X} err={s}\n", .{ va_aligned, phys, @errorName(e) });
                return false;
            };
            // Bump the PMM refcount so the frame survives even if one
            // attacher's destroyAddressSpace walks the PT and tries to free
            // present pages — the shm registry owns the original alloc and
            // calls freeFrame at release(refcount==0). Frame thus has
            // (N attachers + 1 shm-owned) refcount; munmap path drops the
            // attacher count, shm.release drops the +1.
            pmm.acquireFrame(phys);
            @import("../debug/kdbg.zig").pfEvent(@intCast(cur), cr2, @truncate(error_code), 0, true);
            return true;
        }

        // Swap-in: if this VA was evicted to swap, page it back in instead of
        // fresh-allocating a zero page (which would discard its contents and
        // leak the swap slot). The lazy region still exists; only the physical
        // frame was reclaimed. swap_failed => genuine OOM swapping in; skip the
        // fresh-alloc and fall through to the OOM-kill.
        var swap_failed = false;
        switch (trySwapInPage(pd, lead, va_aligned, r.prot, lead.pcid)) {
            .paged_in => {
                @import("../debug/kdbg.zig").pfEvent(@intCast(cur), cr2, @truncate(error_code), 0, true);
                return true;
            },
            .oom => {
                debug.klog("[swap] swap-in FAILED pid={d} va=0x{X} — out of memory, killing\n", .{ cur, va_aligned });
                swap_failed = true;
            },
            .not_swapped => {},
        }

        // Gap #1+#5 (2026-05-20): allocAndMapUserPage now returns a named
        // MapError instead of null. Oom is the only retry-worthy variant
        // (caches might free under pressure); BadVA / KernelHeap mean the
        // lazy region's start..end is malformed — no amount of reclaim
        // helps, fall straight through to OOM-kill (with a distinct log
        // line so the autopsy knows it wasn't memory pressure).
        var frame_opt: ?usize = null;
        if (!swap_failed) {
            if (vmm.allocAndMapUserPage(pd, va_aligned, vmm.protToMapFlags(r.prot))) |f| {
                frame_opt = f;
            } else |e1| {
                if (e1 == error.Oom) {
                    // Memory pressure response: ask registered modules to
                    // shed reclaimable caches (GUI back-buffers etc.), then
                    // retry the alloc ONCE.
                    if (pmm.tryReclaim(1) > 0) {
                        if (vmm.allocAndMapUserPage(pd, va_aligned, vmm.protToMapFlags(r.prot))) |f2| {
                            frame_opt = f2;
                        } else |_| {}
                    }
                    // Still nothing? Evict cold pages of this process out to
                    // swap and retry — THIS is what lets a process run past
                    // physical RAM instead of being OOM-killed. The batch must
                    // be big enough to climb back ACROSS the reserve-aware
                    // user-alloc floor: swap-ins use the reserve-EXEMPT
                    // allocFrame and can leave free FAR below the reserve, so a
                    // fixed small batch (the old 64) can't lift this
                    // allocFrameUser back over it -> spurious OOM-kill. Reclaim
                    // the actual deficit (reserve - free, + margin for the data
                    // page and its PT/PD/PDPT levels). Loop a few times in case
                    // one scan only partially fills the gap or a peer races us;
                    // reclaimViaSwap returning 0 means nothing left to evict =
                    // genuine OOM, so stop.
                    var rtries: u8 = 0;
                    while (frame_opt == null and rtries < 8) : (rtries += 1) {
                        const reserve = pmm.userReserveFrames();
                        const free_now = pmm.freeFrameCount();
                        const want: usize = if (free_now <= reserve) (reserve - free_now) + 16 else 16;
                        if (reclaimViaSwap(pd, lead, va_aligned, lead.pcid, want) == 0) break;
                        if (vmm.allocAndMapUserPage(pd, va_aligned, vmm.protToMapFlags(r.prot))) |f3| {
                            frame_opt = f3;
                        } else |_| {}
                    }
                } else {
                    debug.klog("[vmm] lazy fault REJECTED virt=0x{X} {s} — region[{d}] (0x{X}..0x{X}) prot=0x{X}\n", .{
                        va_aligned, @errorName(e1), i, r.start, r.end, r.prot,
                    });
                }
            }
        }
        const frame = frame_opt orelse {
            @import("../debug/kdbg.zig").pfEvent(@intCast(cur), cr2, @truncate(error_code), 0, false);
            // OOM kill path. The region IS valid (cr2 fell in r.start..r.end);
            // we just don't have a physical frame left. That's not a bug in
            // the user app — it's resource exhaustion — and the right
            // response is to SIGKILL THIS process and let the rest of the
            // system keep running, NOT to run the full crashSummary
            // (register dump, backtrace, dumpAll, fat32 writeCrashLog). The
            // heavy dump is fine for a programmer-error fault but here it's
            // both useless (we know why: OOM) and risky — fat32 writes
            // re-enter the allocator under the same pressure, and the long
            // print stream stalls the compositor on the BSP for hundreds of
            // ms. Take the lightweight route instead and the system stays
            // responsive even with photo / paint / etc. running into their
            // memory caps.
            debug.klog("[oom] killing PID={d} '{s}' — region[{d}] (0x{X}..0x{X}) needed page at cr2=0x{X}, pmm free={d}/{d}\n", .{
                cur,
                pcb.name[0..@min(pcb.name_len, pcb.name.len)],
                i,
                r.start,
                r.end,
                cr2,
                pmm.freeFrameCount(),
                pmm.managedFrameCount(),
            });
            // Memory autopsy: enumerate every lazy region so we can see
            // WHICH range consumed the frames before OOM hit. Without
            // this the OOM line names only the fault site, not the leak
            // site. Added 2026-05-20 during Q1 memory-budget audit.
            debug.klog("[oom]   lazy_count={d} user_brk=0x{X} heap_lazy_idx={d}\n", .{
                lead.lazy_count, lead.user_brk, lead.heap_lazy_idx,
            });
            var ri: u8 = 0;
            while (ri < lead.lazy_count) : (ri += 1) {
                const rr = lead.lazy_regions[ri];
                const size_kb: usize = (rr.end - rr.start) / 1024;
                const tag: []const u8 = if (rr.source != null)
                    "FILE-BACKED"
                else if (lead.heap_lazy_idx >= 0 and ri == @as(u8, @intCast(lead.heap_lazy_idx)))
                    "SBRK-HEAP"
                else
                    "ANON";
                debug.klog("[oom]   region[{d}] 0x{X:0>9}..0x{X:0>9} size={d}KB prot=0x{X} {s}\n", .{
                    ri, rr.start, rr.end, size_kb, rr.prot, tag,
                });
            }
            // Dump the kdbg pmm_alloc + pmm_free rings — they name which
            // call sites have been (de)allocating frames most recently.
            // For the Q1 audit (2026-05-20): lazy regions sum to 17 MB
            // but PMM dropped ~200 MB; the ring tells us who took the
            // other 183 MB.
            @import("../debug/kdbg.zig").dumpPmmAllocRing();
            process.dumpSyscallRing(@intCast(cur));
            // Desktop notification so the user sees WHY the app vanished
            // without having to scroll serial.log.
            const desktop = @import("../ui/desktop.zig");
            if (desktop.active) desktop.showNotification("App killed: out of memory");
            // tearDown + schedule. schedule() never returns when we just
            // marked current_pid null (dead-letter eats the outgoing rsp);
            // the `unreachable` below is for the type system.
            process.destroyCurrent();
            process.schedule();
            unreachable;
        };
        @import("../debug/kdbg.zig").pfEvent(@intCast(cur), cr2, @truncate(error_code), 0, true);
        // For ELF demand paging: copy the intersection of this page with the
        // segment's file-backed range from the kernel buffer. Untouched bytes
        // (alignment padding, BSS) stay zero from allocAndMapUserPage.
        if (r.source) |src| {
            const page_end = va_aligned + 0x1000;
            const src_va_end = r.src_va_base + r.src_size;
            const copy_start = @max(va_aligned, r.src_va_base);
            const copy_end = @min(page_end, src_va_end);
            if (copy_end > copy_start) {
                const dest_offset = copy_start - va_aligned;
                const src_byte_offset = r.src_offset + (copy_start - r.src_va_base);
                const len = copy_end - copy_start;
                const dest: [*]u8 = @ptrFromInt(@import("../mm/paging.zig").physToVirt(frame + dest_offset));
                @memcpy(dest[0..len], src[src_byte_offset .. src_byte_offset + len]);
            }
        }
        // Invalidate TLB on this CPU. Other CPUs don't share user PDs.
        asm volatile ("invlpg (%[addr])"
            :
            : [addr] "r" (va_aligned),
            : .{ .memory = true }
        );
        // Diagnostic: log first fault-in per (PID, 4KB page) so we see every
        // unique page a process touches, not just the first per region. Lets
        // us spot "process keeps faulting same page" loops vs "process moved
        // on to different pages and got stuck mid-execution." The seen-array
        // is bounded; once full we silently stop logging to avoid flooding.
        const dbg = struct {
            const MAX_LOG_PAGES = 64;
            var pages: [MAX_PROCS][MAX_LOG_PAGES]usize =
                [_][MAX_LOG_PAGES]usize{[_]usize{0} ** MAX_LOG_PAGES} ** MAX_PROCS;
            var counts: [MAX_PROCS]u8 = [_]u8{0} ** MAX_PROCS;
        };
        if (cur < MAX_PROCS) {
            // Defensive clamp: cnt is loaded from BSS and SHOULD always be
            // <= MAX_LOG_PAGES (the increment below is gated). If it's
            // larger, something corrupted the array — log and reset rather
            // than tripping a slice OOB panic that masks the real bug.
            const raw_cnt = dbg.counts[cur];
            if (raw_cnt > dbg.MAX_LOG_PAGES) {
                @import("../debug/serial.zig").print("[corrupt] dbg.counts[{d}]={d} > {d} — reset (BSS scribbled?)\n", .{ cur, raw_cnt, dbg.MAX_LOG_PAGES });
                dbg.counts[cur] = 0;
            }
            const cnt = @min(raw_cnt, dbg.MAX_LOG_PAGES);
            var already_seen = false;
            for (dbg.pages[cur][0..cnt]) |seen_va| {
                if (seen_va == va_aligned) {
                    already_seen = true;
                    break;
                }
            }
            if (!already_seen and cnt < dbg.MAX_LOG_PAGES) {
                dbg.pages[cur][cnt] = va_aligned;
                dbg.counts[cur] = cnt + 1;
                debug.klog("[pf] PID={d} lazy fault-in 0x{X} region={d}\n", .{ cur, va_aligned, i });
            }
        }
        // Accounting: this fault successfully populated a fresh user page,
        // so the process's resident set grew by one. Track peak too —
        // useful for OOM heuristics + sysmon's "max ever used" column.
        // Charge against the LEAD thread because lazy regions are shared.
        lead.acct_current_rss +%= 1;
        if (lead.acct_current_rss > lead.acct_peak_rss) {
            lead.acct_peak_rss = lead.acct_current_rss;
        }
        return true;
    }
    // No region matched. Diagnostic: dump lazy region table so we can see
    // whether the fault address is past the heap end, in an unexpected
    // gap between regions, or in territory we never mapped. Throttled
    // per-pid (one dump per crashing PCB) so a wild pointer in a loop
    // doesn't drown serial.
    const dbg2 = struct {
        var dumped: [MAX_PROCS]bool = [_]bool{false} ** MAX_PROCS;
    };
    if (cur < MAX_PROCS and !dbg2.dumped[cur]) {
        dbg2.dumped[cur] = true;
        debug.klog("[pf-miss] PID={d} cr2=0x{X} err=0x{X} — no lazy region matches; user_brk=0x{X}, heap_idx={d}, count={d}\n", .{
            cur, cr2, error_code, lead.user_brk, lead.heap_lazy_idx, lead.lazy_count,
        });
        var j: u8 = 0;
        while (j < lead.lazy_count) : (j += 1) {
            const r = lead.lazy_regions[j];
            debug.klog("[pf-miss]   region[{d}] start=0x{X} end=0x{X} prot=0x{X}\n", .{
                j, r.start, r.end, r.prot,
            });
        }
    }
    return false;
}

/// Force-fault-in any lazy region pages in [addr, addr+len). Used by syscalls
/// before reading user memory — without this, kernel-mode reads bypass the
/// USER bit check and return whatever's in the inherited 2MB identity map
/// (i.e. random kernel data) instead of the app's lazy-loaded data.
pub fn prefaultUserRange(addr: usize, len: usize) void {
    if (len == 0) return;
    const cur = smp.myCpu().current_pid orelse return;
    const pcb = &process.procs[cur];
    const pd = pcb.page_directory orelse return;
    const lead = leader(pcb);

    var page = addr & ~@as(usize, 0xFFF);
    const end = addr + len;
    while (page < end) : (page += 0x1000) {
        // Walk the regions for this page; if it's lazy, ensure its real PTE
        // is installed (which overrides the inherited 2MB mapping).
        var i: u8 = 0;
        while (i < lead.lazy_count) : (i += 1) {
            const r = lead.lazy_regions[i];
            if (page < r.start or page >= r.end) continue;

            // If a real 4K PTE is already installed (has USER bit), nothing
            // to do. Otherwise allocate + map + (optionally) copy from src.
            if (pageHasRealMapping(pd, page)) break;

            // If the page was evicted to swap, page it back in rather than
            // mapping a fresh zero page over the swapped PTE (which would lose
            // its contents AND leak the slot). This is the kernel-side swap-in
            // that lets validateUserPtr accept a pointer into a swapped buffer.
            // NOTE: prefault covers the WHOLE syscall (ptr,len) range, so a
            // syscall handed a large fully-swapped buffer swaps every page in
            // here (evict<->swap-in thrash if it exceeds RAM). Fine for normal
            // syscall buffers; a per-call swap-in cap is the fix if it bites.
            switch (trySwapInPage(pd, lead, page, r.prot, lead.pcid)) {
                .paged_in => break, // resident now (swapInFrame flushed this CPU)
                .oom => break, // leave unmapped — allCurrentUserPagesMapped() then fails -> clean E_FAULT
                .not_swapped => {}, // never-faulted page: fall through to fresh alloc + src copy
            }

            const frame = vmm.allocAndMapUserPage(pd, page, vmm.protToMapFlags(r.prot)) catch return;
            if (r.source) |src| {
                const page_end = page + 0x1000;
                const src_va_end = r.src_va_base + r.src_size;
                const copy_start = @max(page, r.src_va_base);
                const copy_end = @min(page_end, src_va_end);
                if (copy_end > copy_start) {
                    const dest_offset = copy_start - page;
                    const src_byte_offset = r.src_offset + (copy_start - r.src_va_base);
                    const clen = copy_end - copy_start;
                    const dest: [*]u8 = @ptrFromInt(@import("../mm/paging.zig").physToVirt(frame + dest_offset));
                    @memcpy(dest[0..clen], src[src_byte_offset .. src_byte_offset + clen]);
                }
            }
            asm volatile ("invlpg (%[addr])"
                :
                : [addr] "r" (page),
                : .{ .memory = true }
            );
            break;
        }
    }
}

/// True if every 4 KB page in [addr, addr+len) of the current process's
/// address space has a present USER PTE (or sits under an inherited 1GB/2MB
/// page). Use after `prefaultUserRange` to confirm a user pointer is safe
/// to dereference from kernel context — prefault only maps pages registered
/// in lazy_regions, leaving pointers to scratch user VAs unmapped, and the
/// kernel's bare `@memcpy` then page-faults. validateUserPtr in syscall.zig
/// chains prefault → this helper to refuse the call cleanly.
pub fn allCurrentUserPagesMapped(addr: usize, len: usize) bool {
    if (len == 0) return true;
    const cur = smp.myCpu().current_pid orelse return false;
    const pcb = &process.procs[cur];
    const pd = pcb.page_directory orelse return false;

    var page = addr & ~@as(usize, 0xFFF);
    const end = addr + len;
    while (page < end) : (page += 0x1000) {
        if (!pageHasRealMapping(pd, page)) return false;
    }
    return true;
}

/// Variant that walks an explicitly-provided PML4 rather than the current
/// task's. Used by io_uring's worker, which runs as a kernel task but needs
/// to validate user pointers in the OWNER's address space (after swapping
/// CR3). The fault handler can't service a missed page on the worker — its
/// currentPCB is the worker, with no lazy regions — so the worker must
/// pre-validate every page is honestly mapped.
pub fn allUserPagesMappedFor(pml4: [*]align(4096) u64, addr: usize, len: usize) bool {
    if (len == 0) return true;
    var page = addr & ~@as(usize, 0xFFF);
    const end = addr + len;
    while (page < end) : (page += 0x1000) {
        if (!pageHasRealMapping(pml4, page)) return false;
    }
    return true;
}

/// Foreign-PCB variant of `ensureUserRangeWritable`. The owner PCB is
/// passed explicitly so this works from a non-current task — specifically,
/// the io_uring worker, which runs as a kernel task on its own pid but
/// needs to make sure the OWNER's user-VA range is mapped + writable
/// before doing a memcpy into it. Closes the HIGH "COW write-fault"
/// reviewer flagged 2026-05-24: pageHasRealMapping only checks PRESENT+
/// USER, leaving COW pages (READ_WRITE=0) to trap as kernel-mode #PF
/// when the worker writes through them.
///
/// PRECONDITION: caller has loaded `owner_pcb`'s CR3 — INVLPG after
/// allocAndMapUserPage flushes the CURRENT CPU's TLB view, which must
/// match the PML4 we're modifying. handleCompletion satisfies this by
/// switching to owner CR3 before calling us.
///
/// Acquiring the owner's `as_lock` BEFORE calling this (and holding it
/// across the subsequent memcpy) is the caller's responsibility — that's
/// what serializes us vs concurrent sysMunmap/sysMprotect on the owner's
/// own thread.
pub fn ensureUserRangeWritableFor(owner_pcb: *process.PCB, va: usize, len: usize) bool {
    if (len == 0) return true;
    const pd = owner_pcb.page_directory orelse return false;
    const lead = leader(owner_pcb);

    const paging = @import("../mm/paging.zig");
    var p = va & ~@as(usize, 0xFFF);
    const end_excl = va +% len;
    while (p < end_excl) : (p += 0x1000) {
        if (vmm.resolveUserPhys(pd, p) != null) {
            _ = handleCowFault(pd, p);
            const pte_ptr = findUserPte(pd, p) orelse return false;
            if (pte_ptr.* & paging.READ_WRITE == 0) return false;
        } else {
            var mapped = false;
            var i: u8 = 0;
            while (i < lead.lazy_count) : (i += 1) {
                const r = lead.lazy_regions[i];
                if (p < r.start or p >= r.end) continue;
                _ = vmm.allocAndMapUserPage(pd, p, vmm.protToMapFlags(r.prot)) catch return false;
                asm volatile ("invlpg (%[addr])"
                    :
                    : [addr] "r" (p),
                    : .{ .memory = true });
                mapped = true;
                break;
            }
            if (!mapped) return false;
        }
    }
    return true;
}

/// Walk PML4→PDPT→PD→PT and report whether `va` resolves through a 4K PTE
/// with the USER bit set (i.e. an honest per-process mapping). Returns false
/// if the address falls through an inherited 2MB / 1GB page or isn't mapped.
fn pageHasRealMapping(pml4: [*]align(4096) u64, va: usize) bool {
    const PRESENT: u64 = 1;
    const USER: u64 = 1 << 2;
    const PAGE_SIZE_FLAG: u64 = 1 << 7;
    const MASK: u64 = 0x000FFFFFFFFFF000;
    const paging = @import("../mm/paging.zig");

    const pml4_idx = (va >> 39) & 0x1FF;
    const e1 = pml4[pml4_idx];
    if (e1 & PRESENT == 0) return false;
    const pdpt: [*]const u64 = @ptrFromInt(paging.physToVirt(e1 & MASK));

    const pdpt_idx = (va >> 30) & 0x1FF;
    const e2 = pdpt[pdpt_idx];
    if (e2 & PRESENT == 0) return false;
    if (e2 & PAGE_SIZE_FLAG != 0) return false; // 1GB page — inherited
    const pd: [*]const u64 = @ptrFromInt(paging.physToVirt(e2 & MASK));

    const pd_idx = (va >> 21) & 0x1FF;
    const e3 = pd[pd_idx];
    if (e3 & PRESENT == 0) return false;
    if (e3 & PAGE_SIZE_FLAG != 0) return false; // 2MB page — inherited
    const pt: [*]const u64 = @ptrFromInt(paging.physToVirt(e3 & MASK));

    const pt_idx = (va >> 12) & 0x1FF;
    const e4 = pt[pt_idx];
    return (e4 & PRESENT != 0) and (e4 & USER != 0);
}
