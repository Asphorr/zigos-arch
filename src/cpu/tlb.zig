// Cross-CPU TLB shootdown.
//
// When CPU A unmaps a page (or reduces permissions, or COW-splits), CPU B's
// TLB might still have a stale entry mapping that VA to the freed/old frame.
// On x86 the local `invlpg` only flushes the calling CPU; cross-CPU flush
// requires an IPI. Without this, a freed page could be observed live on
// another CPU until its TLB happens to evict the entry — a race that's
// catastrophic if PMM has already handed the frame to a new owner.
//
// First-cut design: global serializing lock + broadcast-IPI-to-all-others +
// full TLB flush on each target (mov cr3, cr3). Slower than per-VA invlpg
// but minimal complexity. Optimization paths (later, if shootdowns are hot):
//   - Per-CPU mailbox so the IPI carries a target VA → use `invlpg` instead
//     of full flush. ~80 cycles vs ~thousands for the broadcast cr3.
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

inline fn flushLocalTlb() void {
    asm volatile (
        \\ movq %%cr3, %%rax
        \\ movq %%rax, %%cr3
        ::: .{ .rax = true, .memory = true });
}

inline fn pause() void {
    asm volatile ("pause");
}

/// IPI handler — invoked on the target CPU via vector 0x50. Performs a
/// full local TLB flush, decrements this CPU's ack-pending counter,
/// then issues EOI. Idempotent (cr3 reload always safe).
pub export fn handleTlbShootdown() callconv(.c) void {
    flushLocalTlb();
    const me_full = apic.getLapicId();
    if (me_full < smp.MAX_CPUS) {
        _ = ack_pending[me_full].fetchSub(1, .acq_rel);
    }
    apic.eoi();
}

/// Broadcast TLB-shootdown IPI to every other live CPU and wait for them
/// all to acknowledge. Use after any page-table write that could leave
/// stale TLB entries on another CPU (unmap, mprotect tighten, COW write).
/// Also flushes the calling CPU's TLB on the way out.
///
/// `affected_pcid` is the PCID of the address space whose page tables
/// just got modified. Pass 0 if the caller isn't running on a tagged
/// PCID (kernel-only modifications). When non-zero, we bump the global
/// PCID generation so peer CPUs holding stale TLB entries for that PCID
/// lazy-flush on their next CR3 load of it (gen mismatch in pcid.loadCr3).
///
/// Single-CPU systems (no APs yet) skip the IPI broadcast and just do a
/// local flush. Same fast-path when called from a CPU before SMP brings
/// up the other cores.
pub fn shootdownAll(affected_pcid: u16) void {
    const me_full = apic.getLapicId();
    const me: u8 = if (me_full < smp.MAX_CPUS) @intCast(me_full) else 0;
    const t_enter = perf.rdtsc();

    // Acquire global shootdown lock. Held until all acks are in. Spin with
    // pause; on contention the wait is bounded by one in-flight shootdown.
    while (shootdown_lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) pause();
    const t_locked = perf.rdtsc();

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

    // Local flush + PCID generation bump so peer CPUs running on a
    // different PCID (and therefore unaffected by their handler's
    // flushLocalTlb of the loaded PCID) still see a gen mismatch when
    // they next pcid.loadCr3 this PCID, and force-flush at that point.
    flushLocalTlb();
    if (affected_pcid != 0) {
        pcid.bumpAfterShootdown(affected_pcid, me);
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
            "[slow-tlb] cpu{d} targets={d} total_cyc={d} lock_cyc={d} wait_cyc={d}\n",
            .{ me, n_targets, total, t_locked -% t_enter, t_acked -% t_locked },
        );
    }
}
