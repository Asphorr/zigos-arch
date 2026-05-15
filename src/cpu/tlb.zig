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
// Optimization paths (later, if shootdowns are hot):
//   - Skip CPUs that don't have this PML4 loaded (require per-CPU
//     `active_pml4_phys` tracking — currently not maintained).
//   - Linux-style per-mm cpumask + sequence numbers so concurrent
//     shootdowns don't have to serialize through one global lock.

const std = @import("std");
const apic = @import("../time/apic.zig");
const smp = @import("smp.zig");
const debug = @import("../debug/debug.zig");
const perf = @import("../debug/perf.zig");
const pcid = @import("pcid.zig");
const protect = @import("protect.zig");

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

/// Outstanding shootdown ack from each CPU. Sender increments the slot
/// for each target before broadcasting; target's IPI handler decrements
/// its own slot on completion. Sender spin-waits until all slots == 0.
/// Serialized externally by `shootdown_lock` so a sender's pre-broadcast
/// count never races with a concurrent sender's increment.
var ack_pending: [smp.MAX_CPUS]std.atomic.Value(u32) = blk: {
    var arr: [smp.MAX_CPUS]std.atomic.Value(u32) = undefined;
    for (&arr) |*v| v.* = std.atomic.Value(u32).init(0);
    break :blk arr;
};

/// Global serialization. Only one shootdown can be broadcast-and-awaited at
/// a time. Without it, two concurrent senders both decrementing the same
/// target's slot would cause one to observe ack_pending==0 prematurely and
/// proceed to free the underlying frame while the other CPU still holds a
/// stale TLB entry. Per-mm shootdown masks (the Linux model) would lift this
/// restriction; keep it global until profiling shows contention.
var shootdown_lock: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);

/// Shootdown mode + parameters. Set by the sender under `shootdown_lock`
/// before broadcasting; read by `handleTlbShootdown` on each target.
/// Safe without per-field atomics because the lock serializes one
/// shootdown at a time, and the IPI handlers complete (and ack) before
/// the lock is released.
const Mode = enum(u32) {
    full = 0,
    single_context = 1,
    single_page = 2,
};
var current_mode: Mode = .full;
var current_pcid: u16 = 0;
var current_va: u64 = 0;

// Telemetry — surfaces in `[slow-tlb]` lines + can be read by sysmon later.
pub var n_shootdowns_full: u64 = 0;
pub var n_shootdowns_context: u64 = 0;
pub var n_shootdowns_page: u64 = 0;

inline fn flushLocalTlb() void {
    asm volatile (
        \\ movq %%cr3, %%rax
        \\ movq %%rax, %%cr3
        ::: .{ .rax = true, .memory = true });
}

inline fn pause() void {
    asm volatile ("pause");
}

/// Local-CPU flush honoring the current shootdown mode. Used by both
/// the IPI handler (peers) and the sender's own post-broadcast flush.
inline fn flushLocalForMode() void {
    switch (current_mode) {
        .full => flushLocalTlb(),
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
    }
    apic.eoi();
}

/// Run a mode-parameterized shootdown: acquire lock, publish mode/pcid/va,
/// broadcast IPI, wait for acks, do local flush, release lock. Hot path
/// for both `shootdownAll` (single_context / full) and `shootdownPage`
/// (single_page).
fn doShootdown(mode: Mode, affected_pcid: u16, va: u64) void {
    const me_full = apic.getLapicId();
    const me: u8 = if (me_full < smp.MAX_CPUS) @intCast(me_full) else 0;
    const t_enter = perf.rdtsc();

    // Acquire global shootdown lock. Held until all acks are in. Spin with
    // pause; on contention the wait is bounded by one in-flight shootdown.
    while (shootdown_lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) pause();
    const t_locked = perf.rdtsc();

    // Publish mode under the lock so peer handlers see a consistent
    // (mode, pcid, va) triple.
    current_mode = mode;
    current_pcid = affected_pcid;
    current_va = va;

    // Bump ack-pending for each live target. Skip self — sender does its
    // own flush at the end without bouncing through an IPI.
    var n_targets: u32 = 0;
    var i: u8 = 0;
    while (i < smp.MAX_CPUS) : (i += 1) {
        if (i == me) continue;
        if (!smp.cpus[i].alive) continue;
        _ = ack_pending[i].fetchAdd(1, .acq_rel);
        n_targets += 1;
    }

    if (n_targets > 0) {
        // Broadcast. icrSend doesn't have an "all-except-self" shorthand
        // wired up, so unicast-loop targeting each live CPU's LAPIC ID.
        // Tiny cost (~10 ICR writes max with MAX_CPUS=32).
        i = 0;
        while (i < smp.MAX_CPUS) : (i += 1) {
            if (i == me) continue;
            if (!smp.cpus[i].alive) continue;
            apic.sendIPI(i, TLB_VECTOR);
        }

        // Wait for each target to ack. Bounded — worst case the target is
        // running with cli; once it sti's, the queued IPI fires and the
        // ack lands. Tens of microseconds typical, never milliseconds
        // unless something is wedged (in which case the watchdog catches it).
        i = 0;
        while (i < smp.MAX_CPUS) : (i += 1) {
            if (i == me) continue;
            if (!smp.cpus[i].alive) continue;
            while (ack_pending[i].load(.acquire) != 0) pause();
        }
    }

    const t_acked = perf.rdtsc();

    // Local flush in the same mode the peers used. Then optionally bump
    // the PCID generation counter (only for whole-context flushes — for
    // single-page mode we just removed one entry, the rest of the PCID
    // is still valid and peers should NOT lazy-flush on next CR3 load).
    flushLocalForMode();
    if ((mode == .single_context or mode == .full) and affected_pcid != 0) {
        pcid.bumpAfterShootdown(affected_pcid, me);
    }

    switch (mode) {
        .full => n_shootdowns_full +%= 1,
        .single_context => n_shootdowns_context +%= 1,
        .single_page => n_shootdowns_page +%= 1,
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
    doShootdown(.single_page, affected_pcid, va & ~@as(u64, 0xFFF));
}
