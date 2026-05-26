// Cross-CPU TLB shootdown.
//
// When CPU A unmaps a page (or reduces permissions, or COW-splits), CPU B's
// TLB might still have a stale entry mapping that VA to the freed/old frame.
// On x86 the local `invlpg` only flushes the calling CPU; cross-CPU flush
// requires an IPI. Without this, a freed page could be observed live on
// another CPU until its TLB happens to evict the entry — a race that's
// catastrophic if PMM has already handed the frame to a new owner.
//
// Design: global serializing lock + broadcast-IPI-to-all-others + per-mode
// flush on each target.
//
// Modes (set in `current_mode` under the lock, read by handler on the IPI):
//   .full          — `mov cr3, cr3`. Flushes all non-global entries for the
//                    currently-loaded PCID only. Used as fallback when
//                    INVPCID is unsupported.
//   .single_context — INVPCID type 1: flushes ALL entries for the named
//                    PCID on this CPU, even if it's not the currently
//                    loaded one. Other PCIDs' TLB working sets survive.
//                    Drop-in replacement for `.full` on INVPCID-capable
//                    hardware. Used by `shootdownAll`.
//   .single_page   — INVPCID type 0: flushes ONE (PCID, VA) tuple.
//                    Cheapest option for single-page operations
//                    (mprotect of one page, single-page unmap).
//                    Used by `shootdownPage`.
//
// IPI fan-out narrowing (Linux-style per-mm cpumask):
//   For affected_pcid != 0, the IPI is sent only to CPUs that have loaded
//   this PCID's CR3 at least once (tracked in `pcid_cpumask` — set in
//   `pcid.loadCr3`, cleared in `pcid.free`). CPUs that have never run the
//   AS are guaranteed to have no entries for this PCID, so their TLB needs
//   no shootdown. For affected_pcid == 0 (kernel-global mappings) all
//   CPUs may have stale GLOBAL entries — fall back to broadcasting to
//   every alive CPU.
//
// Still-open future work:
//   - Eager mask clear on context-switch-out (currently lazy: bit stays
//     set until `pcid.free`). Would shrink IPI fan-out further when a PCID
//     is short-lived on a CPU but the AS is long-lived.
//   - Per-mm sequence numbers so concurrent shootdowns don't have to
//     serialize through `shootdown_lock` (would also let us drop the
//     global lock entirely).

const std = @import("std");
const apic = @import("../time/apic.zig");
const smp = @import("smp.zig");
const debug = @import("../debug/debug.zig");
const perf = @import("../debug/perf.zig");
const pcid = @import("pcid.zig");
const protect = @import("protect.zig");
const hyperv = @import("../virt/hyperv.zig");

// Slow-shootdown threshold (cycles). At Kaby Lake 2.4 GHz nominal TSC,
// 2.5M cycles ≈ 1 ms — well above the few-μs IPI round-trip budget.
// Crossing it means a target CPU was cli'd or wedged long enough that
// the sender stalled noticeably; log it so we can correlate with which
// driver was holding cli.
const SLOW_SHOOTDOWN_THRESHOLD_CYC: u64 = 2_500_000;

/// IDT vector reserved for TLB-shootdown IPIs. Chosen above the dynamic
/// MSI-X range (`DYN_IRQ_BASE..+DYN_IRQ_COUNT` = 0x40..0x4F) and below the
/// syscall vector (0x80). The naked stub `isr_tlb_shootdown` calls into
/// `handleTlbShootdown`, which lives in this file.
pub const TLB_VECTOR: u8 = 0x50;

/// (a) Outstanding shootdown ack from each CPU. Sender does `fetchAdd(.acq_rel)`
/// for each target before broadcasting; target's IPI handler `fetchSub(.acq_rel)`
/// on completion; sender's wait loop `load(.acquire)`. Serialized externally
/// by `shootdown_lock` so a sender's pre-broadcast count never races with a
/// concurrent sender's increment.
var ack_pending: [smp.MAX_CPUS]std.atomic.Value(u32) = blk: {
    var arr: [smp.MAX_CPUS]std.atomic.Value(u32) = undefined;
    for (&arr) |*v| v.* = std.atomic.Value(u32).init(0);
    break :blk arr;
};

/// (a) Global serialization. Only one shootdown can be broadcast-and-awaited at
/// a time. Without it, two concurrent senders both decrementing the same
/// target's slot would cause one to observe ack_pending==0 prematurely and
/// proceed to free the underlying frame while the other CPU still holds a
/// stale TLB entry. Per-mm shootdown masks (the Linux model) would lift this
/// restriction; keep it global until profiling shows contention.
var shootdown_lock: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);

/// Shootdown mode + parameters. Set by the sender under `shootdown_lock`
/// before broadcasting; read by `handleTlbShootdown` on each target. The
/// lock serializes one shootdown at a time, but does NOT by itself drain
/// the sender's store buffer before the IPI fires — see the explicit
/// `@fence(.seq_cst)` in `doShootdown` between publishing stores and
/// `apic.sendIPI`. x2APIC's `wrmsr 0x830` is NOT a serializing instruction
/// (SDM Vol 3A §10.12.3) so the fence is load-bearing on every modern host
/// (Hyper-V, KVM, SNB+ where x2apic is active). xAPIC's MMIO path drains
/// implicitly via UC ordering, but x2APIC supplants it on modern hardware.
const Mode = enum(u32) {
    full = 0,
    single_context = 1,
    single_page = 2,
};
var current_mode: Mode = .full;  // (p:shootdown_lock) publisher-fenced before IPI broadcast
var current_pcid: u16 = 0;       // (p:shootdown_lock) publisher-fenced before IPI broadcast
var current_va: u64 = 0;         // (p:shootdown_lock) publisher-fenced before IPI broadcast

// Telemetry — surfaces in `[slow-tlb]` lines + readable by sysmon. All bumped
// from multi-CPU senders, so atomic-RMW only (never plain `+=` / `+%=`).
pub var n_shootdowns_full: u64 = 0;            // (a)
pub var n_shootdowns_context: u64 = 0;         // (a)
pub var n_shootdowns_page: u64 = 0;            // (a)
pub var n_shootdowns_via_hypercall: u64 = 0;   // (a)
/// (a) Count of skipped peer-CPU slots (NOT shootdown events) due to the
/// per-mm cpumask narrowing. A 32-CPU host where every shootdown narrows
/// down to 2 targets would accumulate ~30 per shootdown. High values mean
/// the narrowing is paying off; near-zero means most processes touch every
/// CPU and the mask isn't helping. Accumulated only on IPI-path shootdowns
/// (skipped on hypercall path).
pub var n_shootdowns_cpumask_skipped: u64 = 0; // (a)

inline fn flushLocalTlb() void {
    asm volatile (
        \\ movq %%cr3, %%rax
        \\ movq %%rax, %%cr3
        ::: .{ .rax = true, .memory = true });
}

/// Full local flush INCLUDING global (PGE) entries — toggles CR4.PGE off
/// then on. A plain `mov cr3,cr3` (flushLocalTlb) PRESERVES global entries,
/// so it cannot evict a stale kernel-master / physmap translation. Required
/// on peers (and the sender) for a `.full` shootdown whose target is a
/// kernel-global mapping (signalled by current_pcid == 0). Mirrors
/// paging.flushTLBGlobal(); kept inline here to avoid a paging<->tlb import.
inline fn flushLocalTlbIncludingGlobal() void {
    asm volatile (
        \\ movq %%cr4, %%rcx
        \\ movq %%rcx, %%rax
        \\ btrq $7, %%rax
        \\ movq %%rax, %%cr4
        \\ movq %%rcx, %%cr4
        ::: .{ .rax = true, .rcx = true, .memory = true });
}

inline fn pause() void {
    asm volatile ("pause");
}

/// Read RFLAGS.IF (bit 9). Used to decide whether a CLI'd caller needs the
/// IF-aware spin: if we entered with IF=0 we must temporarily enable IRQs
/// while spinning to acquire `shootdown_lock`, otherwise a peer that's the
/// current lock-holder will never get its IPI ack from us and we deadlock.
inline fn readIf() bool {
    var rflags: u64 = undefined;
    asm volatile (
        \\ pushfq
        \\ pop %[rf]
        : [rf] "=r" (rflags),
    );
    return (rflags & 0x200) != 0;
}

/// Local-CPU flush honoring the current shootdown mode. Used by both
/// the IPI handler (peers) and the sender's own post-broadcast flush.
inline fn flushLocalForMode() void {
    switch (current_mode) {
        // pcid == 0 marks a kernel-master mutation whose PTEs are GLOBAL
        // (PGE); a CR3 reload preserves global entries, so toggle CR4.PGE to
        // actually evict them. pcid != 0 (user AS, INVPCID absent) keeps
        // globals — the cheaper CR3 reload is correct there.
        .full => if (current_pcid == 0) flushLocalTlbIncludingGlobal() else flushLocalTlb(),
        .single_context => {
            // INVPCID type 1: flush all entries for `current_pcid` on this
            // CPU, even if it's not the loaded one. Other PCIDs survive.
            if (protect.invpcid_supported and current_pcid != 0) {
                pcid.invpcid(.single_context, current_pcid, 0);
            } else {
                flushLocalTlb();
            }
        },
        .single_page => {
            // INVPCID type 0: flush one (pcid, va). If unsupported,
            // fall back to a full flush (correct but wider than needed).
            if (protect.invpcid_supported and current_pcid != 0) {
                pcid.invpcid(.address, current_pcid, current_va);
            } else {
                flushLocalTlb();
            }
            // INVLPG backstop for the CURRENTLY-LOADED PCID. INVPCID type-0 has
            // been observed to under-invalidate under nested virt, leaving a
            // stale entry. INVLPG reliably flushes current_va for whatever PCID
            // is loaded on THIS CPU right now — covering (a) the SENDER, always
            // running the affected AS, and (b) a PEER concurrently running it
            // (the multi-threaded case the PCID gen-bump can't reach, since that
            // peer never reloads CR3). A peer loaded with a DIFFERENT PCID gets
            // a harmless flush of an unrelated VA; its dormant stale entry for
            // the affected PCID is cleared by the gen-bump on the CR3 load that
            // migrates that AS onto it. Surgical (one page) — no working-set
            // loss. Subsumes the old per-call-site tlb.flushPageLocal.
            asm volatile ("invlpg (%[v])"
                :
                : [v] "r" (current_va),
                : .{ .memory = true });
        },
    }
}

/// IPI handler — invoked on the target CPU via vector 0x50. Performs a
/// mode-appropriate local flush, decrements this CPU's ack-pending
/// counter, then issues EOI. Idempotent.
pub export fn handleTlbShootdown() callconv(.c) void {
    flushLocalForMode();
    const me_full = apic.getLapicId();
    if (me_full < smp.MAX_CPUS) {
        _ = ack_pending[me_full].fetchSub(1, .acq_rel);
    } else {
        // Should be impossible — smp.init filters MADT entries with apic_id
        // >= MAX_CPUS. If we ever get here the sender will spin forever
        // waiting for this CPU's ack; surface the diagnostic.
        debug.kwarn(@src(), "IPI on CPU with lapic_id={d} >= MAX_CPUS; sender will hang", .{me_full});
    }
    apic.eoi();
}

/// Run a mode-parameterized shootdown: acquire lock, publish mode/pcid/va,
/// broadcast IPI, wait for acks, do local flush, release lock. Hot path
/// for both `shootdownAll` (single_context / full) and `shootdownPage`
/// (single_page).
fn doShootdown(mode: Mode, affected_pcid: u16, va: u64) void {
    const me_full = apic.getLapicId();
    if (me_full >= smp.MAX_CPUS) {
        // Cannot recover safely: the `else 0` fallback below would make us
        // self-IPI cpu 0 and double-flush an unrelated slot. smp.init should
        // have rejected this MADT entry; surface the diagnostic before the wedge.
        debug.kwarn(@src(), "doShootdown sender lapic_id={d} >= MAX_CPUS; treating as cpu 0", .{me_full});
    }
    const me: u8 = if (me_full < smp.MAX_CPUS) @intCast(me_full) else 0;
    const t_enter = perf.rdtsc();

    // Acquire global shootdown lock. Held until all acks are in. Spin with
    // pause; on contention the wait is bounded by one in-flight shootdown.
    //
    // IF-aware spin: if the caller entered CLI'd (#PF handler, exception
    // dispatch, etc.) AND a peer is currently the lock-holder broadcasting
    // IPIs to us, we'd deadlock — peer waits forever for our IPI ack, we
    // can't service the IPI because IF=0. Snapshot caller's IF; if it was
    // off, temporarily sti while spinning, then cli before publishing mode
    // (the rest of the critical section runs at caller's IF state).
    //
    // Re-entry safety contract for the sti'd window: servicing an inbound
    // shootdown IPI is safe (handleTlbShootdown just flushes our local TLB
    // + decrements our ack slot + EOI; no locks touched). But ANY OTHER
    // vector firing here re-enters kernel paths the caller didn't expect —
    // LAPIC timer (-> schedule), MSI-X disk IRQ, dynirq, NMI watchdog.
    // Known-safe callers entering with IF=0: #PF handler (sti's before this
    // point on its own; see fault.zig:464-466), exception dispatch, swap
    // eviction's CAS-restore back-path. Any NEW caller entering with IF=0
    // MUST audit re-entry safety for those other vectors firing mid-spin.
    const caller_if = readIf();
    if (!caller_if) asm volatile ("sti");
    while (shootdown_lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) pause();
    if (!caller_if) asm volatile ("cli");
    const t_locked = perf.rdtsc();

    // Publish mode under the lock so peer handlers see a consistent
    // (mode, pcid, va) triple. The seq_cst fence drains the store buffer
    // before x2APIC IPI delivery — `wrmsr 0x830` is NOT a serializing
    // instruction (SDM Vol 3A §10.12.3), so without the fence a peer IPI
    // handler could observe stale values from a previous shootdown that's
    // already lock-released. xAPIC's MMIO path drains implicitly via UC
    // ordering, but x2APIC is active on every modern host (Hyper-V, KVM,
    // SNB+) so this is load-bearing in practice.
    current_mode = mode;
    current_pcid = affected_pcid;
    current_va = va;
    asm volatile ("mfence" ::: .{ .memory = true });

    // Hyper-V fast path: HvCallFlushVirtualAddressSpace flushes all VPs
    // (including self) for the given address space in one hypercall —
    // skipping the IPI fan-out and the wait-for-ack spin. Only used for
    // whole-AS flushes (.full / .single_context); .single_page still goes
    // through the IPI path because we'd need HvCallFlushVirtualAddressList
    // to express a single VA, which isn't wired yet.
    //
    // On success: skip the IPI block and the local flush (the hypercall
    // covered self too). Still bump the PCID gen counter so peers lazy-
    // flush again on their next CR3 load (belt-and-suspenders).
    var via_hypercall = false;
    // Exclude kernel-global flushes (affected_pcid == 0): the per-address-
    // space hypercall isn't guaranteed to evict GLOBAL translations on every
    // VP. Force the IPI path below, which toggles CR4.PGE explicitly. (Moot on
    // KVM — hasHypercalls() is false — but correct under Hyper-V.)
    if ((mode == .full or mode == .single_context) and affected_pcid != 0 and hyperv.hasHypercalls()) {
        const cr3 = asm volatile ("movq %%cr3, %[ret]"
            : [ret] "=r" (-> u64),
        );
        if (hyperv.flushAllProcessors(cr3)) {
            via_hypercall = true;
            _ = @atomicRmw(u64, &n_shootdowns_via_hypercall, .Add, 1, .monotonic);
        }
    }

    // IPI fan-out path. Skipped entirely when the hypercall above already
    // flushed all VPs. `i` and `n_targets` are scoped to the whole block
    // so the broadcast loop can reuse the same iterator.
    //
    // Per-mm cpumask narrowing: when `affected_pcid != 0`, only CPUs whose
    // bit is set in `pcid.cpumaskOf(affected_pcid)` can possibly hold (PCID, *)
    // TLB entries — IPI just those. Skipped CPUs are tallied into
    // `n_shootdowns_cpumask_skipped` for visibility. For `affected_pcid == 0`
    // (kernel-global mappings via PGE) every CPU may hold stale entries, so
    // the mask is set to all-1s to preserve broadcast semantics.
    var n_targets: u32 = 0;
    if (!via_hypercall) {
        const target_mask: u32 = if (affected_pcid != 0)
            pcid.cpumaskOf(affected_pcid)
        else
            ~@as(u32, 0);
        var n_skipped: u32 = 0;
        // Record the exact set of CPUs we bumped ack_pending for. The
        // broadcast + wait loops then iterate THIS local snapshot rather
        // than re-reading (alive, target_mask) — independent of any
        // concurrent mutation in pcid_cpumask. Today the mask is
        // monotonic-grow during a shootdown so re-reading would also be
        // correct, but the planned "eager clear on context-switch-out"
        // optimization (pcid.zig TODO) would let bits clear mid-shootdown
        // and silently break the wait loop: we'd skip waiting for a CPU
        // we incremented for, leaking the increment so the next sender
        // either spins forever on its slot or observes ack_pending==0
        // prematurely. Tracking inflight_mask locally closes that hole
        // structurally. Skip self — sender does its own flush at the end
        // without bouncing through an IPI.
        var inflight_mask: u32 = 0;
        var i: u8 = 0;
        while (i < smp.MAX_CPUS) : (i += 1) {
            if (i == me) continue;
            if (!smp.cpus[i].alive) continue;
            if ((target_mask & (@as(u32, 1) << @as(u5, @intCast(i)))) == 0) {
                n_skipped += 1;
                continue;
            }
            inflight_mask |= (@as(u32, 1) << @as(u5, @intCast(i)));
            _ = ack_pending[i].fetchAdd(1, .acq_rel);
            n_targets += 1;
        }
        _ = @atomicRmw(u64, &n_shootdowns_cpumask_skipped, .Add, n_skipped, .monotonic);

        if (n_targets > 0) {
            // Broadcast — iterate the local inflight_mask snapshot. Tiny cost
            // (~10 ICR writes max with MAX_CPUS=32). icrSend doesn't have an
            // "all-except-self" shorthand wired up, so unicast-loop targeting
            // each LAPIC ID we incremented for.
            i = 0;
            while (i < smp.MAX_CPUS) : (i += 1) {
                if ((inflight_mask & (@as(u32, 1) << @as(u5, @intCast(i)))) == 0) continue;
                apic.sendIPI(i, TLB_VECTOR);
            }

            // Wait for each target to ack. Bounded — worst case the target
            // is running with cli; once it sti's, the queued IPI fires and
            // the ack lands. Tens of microseconds typical, never milliseconds
            // unless something is wedged (in which case the watchdog catches it).
            i = 0;
            while (i < smp.MAX_CPUS) : (i += 1) {
                if ((inflight_mask & (@as(u32, 1) << @as(u5, @intCast(i)))) == 0) continue;
                while (ack_pending[i].load(.acquire) != 0) pause();
            }
        }
    }

    const t_acked = perf.rdtsc();

    // Local flush in the same mode the peers used. Then bump the PCID
    // generation counter so peers lazy-flush this PCID on their next CR3
    // load.
    //
    // Why .single_page is bumped too (it used to be excluded): the peer IPI
    // handler flushes a single_page shootdown via INVPCID type-0
    // (flushLocalForMode), and under nested virt — this kernel always runs as
    // an L2 guest — INVPCID type-0 has been observed to UNDER-invalidate,
    // leaving a stale PRESENT entry for (pcid, va) on a peer. If a single-
    // threaded process then migrates to that peer, it would read the freed-
    // and-reused frame through the stale entry without faulting (silent
    // corruption — the swap-eviction data-loss bug). Bumping the gen forces
    // the peer to full-flush this PCID on the CR3 load that brings the process
    // back, so the stale entry can never be USED. The sender's own CPU is
    // covered by flushLocalForMode's INVLPG backstop (.single_page branch), and
    // the bump catches local_gen up so the sender doesn't redundantly full-
    // flush on its next reload. Cost is one PCID flush per migration (bumps
    // between migrations collapse to one), not per shootdown.
    //
    // The concurrent case — two threads of the SAME pcid on both CPUs, where
    // the peer is mid-execution and won't reload CR3 (so the gen bump can't
    // reach it) — is handled by that same INVLPG: it runs in the peer's IPI
    // handler against the peer's loaded (== affected) pcid, reliably dropping
    // the stale (pcid, va) entry. So both migration and concurrent access are
    // now closed.
    //
    // Hypercall path already flushed self via FLUSH_ALL_PROCESSORS, so skip
    // the local flush there — but still bump PCID gen for the same reason.
    if (!via_hypercall) flushLocalForMode();
    if (affected_pcid != 0) {
        pcid.bumpAfterShootdown(affected_pcid, me);
    }

    switch (mode) {
        .full => _ = @atomicRmw(u64, &n_shootdowns_full, .Add, 1, .monotonic),
        .single_context => _ = @atomicRmw(u64, &n_shootdowns_context, .Add, 1, .monotonic),
        .single_page => _ = @atomicRmw(u64, &n_shootdowns_page, .Add, 1, .monotonic),
    }

    shootdown_lock.store(0, .release);

    // Slow-shootdown diagnostic. lock_cyc = time to acquire the global
    // shootdown_lock (contention from another in-flight shootdown).
    // wait_cyc = time from broadcast to all acks (target CPUs not
    // processing the IPI fast — typically because they're cli'd in a
    // driver poll loop). Identifies which side is the bottleneck.
    const total = t_acked -% t_enter;
    if (total > SLOW_SHOOTDOWN_THRESHOLD_CYC) {
        debug.klog(
            "[slow-tlb] cpu{d} mode={s} targets={d} total_cyc={d} lock_cyc={d} wait_cyc={d}\n",
            .{ me, @tagName(mode), n_targets, total, t_locked -% t_enter, t_acked -% t_locked },
        );
    }
}

/// Broadcast a whole-address-space TLB shootdown for `affected_pcid`.
/// Use after a batch of page-table writes (multi-page munmap, fork
/// teardown, mprotect of a range). Picks INVPCID type-1 on capable
/// hardware (peer CPUs only lose entries for the affected PCID) and
/// falls back to `mov cr3, cr3` otherwise.
///
/// `affected_pcid == 0` means a kernel-only modification with no PCID
/// tagging — use the full-flush path.
pub fn shootdownAll(affected_pcid: u16) void {
    const mode: Mode = if (affected_pcid != 0 and protect.invpcid_supported)
        .single_context
    else
        .full;
    doShootdown(mode, affected_pcid, 0);
}

/// Broadcast a single-page TLB shootdown for `(affected_pcid, va)`.
/// Use after modifying exactly one PTE (mprotect of one page, COW
/// promote, single-page free). Surgical strike — peer CPUs lose only
/// that one (PCID, VA) translation. Falls back to `shootdownAll` on
/// PCID=0 or when INVPCID isn't supported (correct but wider).
pub fn shootdownPage(affected_pcid: u16, va: u64) void {
    if (affected_pcid == 0 or !protect.invpcid_supported) {
        // No PCID tagging or no INVPCID — full flush is the only safe
        // option. (`invlpg` on the IPI target would only work if that
        // CPU has the affected PCID loaded, which we can't guarantee.)
        shootdownAll(affected_pcid);
        return;
    }
    if (va & 0xFFF != 0) {
        // Caller passed a non-aligned VA. We mask it down to a page
        // boundary below, but the caller's PTE mutation may have been
        // at a different VA — masking the wrong bug. Surface it.
        debug.kwarn(@src(), "shootdownPage va=0x{X} not page-aligned", .{va});
    }
    doShootdown(.single_page, affected_pcid, va & ~@as(u64, 0xFFF));
}
