// Per-process address-space tagging via CR4.PCIDE.
//
// CR4.PCIDE is flipped in `protect.applyEarlyCr4`; this module owns the
// per-process PCID allocator + the CR3-write helper that preserves TLB
// entries across context switches.
//
// Layout:
//   PCID 0 is reserved for kernel-only CR3 loads (boot, idle, kernel
//   tasks, and any CR3 write that doesn't go through `loadCr3` here).
//   User processes get a PCID in [1, MAX_PCID-1] from `alloc`, freed via
//   `free` at destroyAddressSpace time. CR3 writes for PCID > 0 set bit
//   63 (the "do-not-flush" hint) when the loaded PCID's TLB is known
//   coherent on this CPU; the generation-counter dance below tracks
//   that.
//
// Generation counters: a freed PCID can be reused by a new process,
// and that new process must not inherit the previous owner's TLB
// entries. We bump `global_gen[pcid]` on every alloc/free and compare
// against `local_gen[cpu_id][pcid]` on every CR3 load. A mismatch
// forces bit-63=0 (flush) once; matching values let subsequent loads
// preserve the TLB. Cross-CPU TLB shootdowns also bump the generation
// (see `bumpAfterShootdown`) so peers lazily flush before next load.
//
// Sizing: MAX_PCID = 128 covers MAX_PROCS=32 with plenty of headroom
// even under heavy fork/exec churn. Memory cost: 128 × 4 = 0.5 KB
// global generation + 32 × 128 × 4 = 16 KB per-CPU generation. Cheap.

const std = @import("std");
const protect = @import("protect.zig");
const smp = @import("smp.zig");
const debug = @import("../debug/debug.zig");
const spinlock = @import("../proc/spinlock.zig");

pub const MAX_PCID: u16 = 128;

var alloc_lock: spinlock.SpinLock = .{};
var in_use: [MAX_PCID]bool = [_]bool{false} ** MAX_PCID;
var next_hint: u16 = 1; // round-robin; PCID 0 reserved

var global_gen: [MAX_PCID]std.atomic.Value(u32) = blk: {
    var arr: [MAX_PCID]std.atomic.Value(u32) = undefined;
    var i: usize = 0;
    while (i < MAX_PCID) : (i += 1) {
        arr[i] = std.atomic.Value(u32).init(0);
    }
    break :blk arr;
};

var local_gen: [smp.MAX_CPUS][MAX_PCID]u32 =
    [_][MAX_PCID]u32{[_]u32{0} ** MAX_PCID} ** smp.MAX_CPUS;

/// Per-PCID bitmask of CPUs that have loaded this PCID's CR3 at least once
/// since the PCID was allocated. A bit at position `cpu_id` means "this CPU
/// may have cached (PCID, *) TLB entries" — used by `tlb.doShootdown` to
/// narrow IPI fan-out to only the CPUs that could possibly need flushing.
/// Other CPUs are guaranteed to have no entries for this PCID (they never
/// loaded it, or they switched away from it and eager-cleared their bit),
/// so their TLB needs no shootdown.
///
/// Sized as `u32` because MAX_CPUS == 32. SET in `loadCr3` BEFORE the CR3
/// write so a concurrent sender that reads the mask after our `or` sees us;
/// a sender that reads before our set still wins because our PT walks haven't
/// started yet (TLB for this PCID still empty on us). CLEARED in `loadCr3`
/// AFTER an `invpcid(.single_context, old_pcid)` flushes the entries we're
/// abandoning on switch-out (eager clear, gated on INVPCID support). Also
/// cleared wholesale in `free` when the PCID is recycled.
///
/// Race with a concurrent shootdown sender during eager clear: if the sender
/// reads the mask BEFORE our `fetchAnd`, we get included in the IPI fan-out
/// and our handler runs a no-op flush (TLB was already drained by our
/// INVPCID) and acks. If the sender reads AFTER our `fetchAnd`, we're
/// skipped — also fine because our TLB has no entries for that PCID. The
/// sender's wait loop uses `inflight_mask` (the snapshot at increment time,
/// see tlb.zig:doShootdown) rather than re-reading this mask, so a
/// clear-during-shootdown cannot cause a missed ack.
var pcid_cpumask: [MAX_PCID]std.atomic.Value(u32) = blk: {
    var arr: [MAX_PCID]std.atomic.Value(u32) = undefined;
    var i: usize = 0;
    while (i < MAX_PCID) : (i += 1) {
        arr[i] = std.atomic.Value(u32).init(0);
    }
    break :blk arr;
};

// Stats — surfaced by procfs/sysmon for visibility.
pub var alloc_count: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
pub var free_count: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
pub var preserve_hits: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
pub var flush_misses: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
/// Count of switch-out eager clears: a CPU loaded a CR3 with a different
/// user PCID, INVPCID-flushed the old PCID's entries on this CPU, and
/// removed its bit from old_pcid's cpumask. Each clear narrows future
/// IPI fan-out for old_pcid by one CPU. Compare against the total
/// shootdown count to gauge the optimization's payoff.
pub var eager_clears: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

/// Read the per-PCID cpumask. Returns 0 for invalid PCIDs (caller treats as
/// "nobody has loaded this PCID" — sender does its local flush and skips the
/// IPI block entirely). `tlb.doShootdown` is the sole consumer.
pub inline fn cpumaskOf(p: u16) u32 {
    if (p == 0 or p >= MAX_PCID) return 0;
    return pcid_cpumask[p].load(.acquire);
}

/// Allocate a fresh PCID. Returns 0 if PCID is unsupported on this CPU
/// (PCB.pcid stays 0 and loadCr3 falls back to plain CR3 writes).
pub fn alloc() u16 {
    if (!protect.pcid_supported) return 0;
    alloc_lock.acquire();
    defer alloc_lock.release();

    var attempts: u16 = 0;
    var p: u16 = next_hint;
    while (attempts < MAX_PCID) : (attempts += 1) {
        if (p == 0) p = 1;
        if (!in_use[p]) {
            in_use[p] = true;
            _ = global_gen[p].fetchAdd(1, .acq_rel);
            next_hint = if (p + 1 >= MAX_PCID) 1 else p + 1;
            _ = alloc_count.fetchAdd(1, .monotonic);
            return p;
        }
        p = if (p + 1 >= MAX_PCID) 1 else p + 1;
    }
    debug.klog("[pcid] alloc exhausted (MAX_PCID={d}); falling back to PCID 0\n", .{MAX_PCID});
    return 0;
}

pub fn free(p: u16) void {
    if (p == 0 or p >= MAX_PCID) return;
    alloc_lock.acquire();
    defer alloc_lock.release();
    if (!in_use[p]) return;
    in_use[p] = false;
    _ = global_gen[p].fetchAdd(1, .acq_rel);
    // Clear the cpumask: any CPU that loaded this PCID will see the gen
    // mismatch on its next CR3 load of a REUSED slot and full-flush, so the
    // old entries don't leak into the new owner's working set. Resetting the
    // mask to 0 lets the new owner's cpumask grow organically from its own
    // loads.
    pcid_cpumask[p].store(0, .release);
    _ = free_count.fetchAdd(1, .monotonic);
}

inline fn writeCr3(value: u64) void {
    asm volatile ("movq %[v], %%cr3"
        :
        : [v] "r" (value),
        : .{ .memory = true });
}

/// Write CR3 with PCID tagging + preserve-TLB hint.
/// `pml4_phys` should be 4 KiB aligned; the low 12 bits are forced to
/// `pcid` and bit 63 is set when the per-CPU generation says this PCID's
/// TLB entries are still coherent.
pub fn loadCr3(pml4_phys: u64, pcid: u16, cpu_id: u8) void {
    const aligned = pml4_phys & ~@as(u64, 0xFFF);

    // Eager clear on switch-out. If we're moving to a different user PCID
    // (or to kernel-PCID 0) and we previously ran some other user PCID on
    // this CPU, INVPCID-flush its entries and remove our bit from its
    // cpumask. Shrinks future IPI fan-out for the old PCID: shootdowns
    // for it will skip us since we no longer hold any (old_pcid, *) entries.
    //
    // Gated on `invpcid_supported` because INVPCID type-1 is what makes the
    // flush selective; without it we'd have to `mov cr3, cr3` (loses ALL
    // PCIDs' entries on this CPU), which costs more than the optimization
    // saves. Lazy clear falls back automatically.
    //
    // Flush BEFORE clearing the bit so any shootdown sender that snapshots
    // the mask before our `fetchAnd` includes us in the IPI fan-out and
    // gets a correct no-op ack (our TLB is already empty for that PCID).
    if (protect.pcid_supported and protect.invpcid_supported and cpu_id < smp.MAX_CPUS) {
        const old_cr3 = asm volatile ("movq %%cr3, %[ret]"
            : [ret] "=r" (-> u64),
        );
        const old_pcid: u16 = @truncate(old_cr3 & 0xFFF);
        if (old_pcid != 0 and old_pcid != pcid and old_pcid < MAX_PCID) {
            invpcid(.single_context, old_pcid, 0);
            const bit = @as(u32, 1) << @as(u5, @intCast(cpu_id));
            _ = pcid_cpumask[old_pcid].fetchAnd(~bit, .acq_rel);
            _ = eager_clears.fetchAdd(1, .monotonic);
        }
    }

    if (!protect.pcid_supported or pcid == 0 or pcid >= MAX_PCID) {
        writeCr3(aligned);
        return;
    }
    // Record our presence in this PCID's cpumask BEFORE writing CR3. A
    // concurrent sender of a shootdown for `pcid` that reads the mask after
    // our `fetchOr` will include us in its IPI fan-out and flush any TLB
    // entries we then cache. A sender that reads BEFORE our fetchOr misses
    // us, but our TLB for this PCID is still empty at that instant (no PT
    // walks for this AS have happened on this CPU yet), so safe.
    if (cpu_id < smp.MAX_CPUS) {
        const bit = @as(u32, 1) << @as(u5, @intCast(cpu_id));
        _ = pcid_cpumask[pcid].fetchOr(bit, .acq_rel);
    }
    var preserve: u64 = (@as(u64, 1) << 63);
    if (cpu_id < smp.MAX_CPUS) {
        const g = global_gen[pcid].load(.acquire);
        if (local_gen[cpu_id][pcid] != g) {
            local_gen[cpu_id][pcid] = g;
            preserve = 0;
            _ = flush_misses.fetchAdd(1, .monotonic);
        } else {
            _ = preserve_hits.fetchAdd(1, .monotonic);
        }
    } else {
        preserve = 0;
    }
    writeCr3(aligned | @as(u64, pcid) | preserve);
}

/// Restore a saved CR3 value (`mov %cr3, %rax` snapshot). The saved value
/// already encodes PCID in bits[11:0]; we re-derive bit 63 from the
/// per-CPU generation tracker since CR3 reads don't return bit 63.
pub fn restoreSaved(saved_cr3: u64, cpu_id: u8) void {
    const pml4_phys = saved_cr3 & ~@as(u64, 0xFFF);
    const pcid: u16 = @truncate(saved_cr3 & 0xFFF);
    loadCr3(pml4_phys, pcid, cpu_id);
}

/// Bump global generation for `pcid` after a cross-CPU TLB shootdown
/// invalidated mappings in that address space. Peer CPUs holding stale
/// TLB entries for this PCID will see the gen mismatch on their next
/// `loadCr3(pcid, ...)` and flush. Also catches the local CPU up so its
/// next reload (post-flushLocalTlb) sets bit 63 = 1.
///
/// For .single_context (INVPCID type 1) the peer flush is reliable and this
/// is merely belt-and-suspenders. For .single_page (INVPCID type 0) it is
/// LOAD-BEARING under nested virt: type-0 has been observed to under-
/// invalidate on a peer, and this lazy full-PCID flush on the peer's next
/// CR3 load is what guarantees a migrated process never reads through the
/// stale (pcid, va) entry. See doShootdown for the full rationale. Cost is
/// one atomic increment per shootdown.
pub fn bumpAfterShootdown(pcid: u16, cpu_id: u8) void {
    if (!protect.pcid_supported or pcid == 0 or pcid >= MAX_PCID) return;
    const new_gen = global_gen[pcid].fetchAdd(1, .acq_rel) + 1;
    if (cpu_id < smp.MAX_CPUS) {
        local_gen[cpu_id][pcid] = new_gen;
    }
}

// ---------------------------------------------------------------------------
// INVPCID — selective TLB invalidation
// ---------------------------------------------------------------------------
//
// INVPCID gives us per-(PCID, VA) and per-PCID flushes without the
// blunt-instrument cost of `mov cr3, cr3` (which flushes all non-global
// entries for the currently-loaded PCID and leaves other PCIDs' entries
// stale).
//
// The descriptor is a 16-byte memory operand: bits[11:0] of the first
// qword carry the PCID, bits[63:12] are reserved (must be zero); the
// second qword is the linear address (only used by type 0). The "type"
// is passed in a register operand (1..3 are the documented values).
//
// Spec ref: Intel SDM Vol 2 — INVPCID instruction.

pub const InvpcidType = enum(u64) {
    /// Type 0: invalidate one (PCID, linear-address) mapping. Cheapest;
    /// other entries for the same PCID survive.
    address = 0,
    /// Type 1: invalidate all entries for the named PCID (except globals).
    /// Drop-in replacement for `mov cr3, cr3` that doesn't touch other
    /// PCIDs' TLB working sets on the target CPU.
    single_context = 1,
    /// Type 2: invalidate all entries across all PCIDs INCLUDING globals.
    /// Kernel-mapping changes only.
    all_with_globals = 2,
    /// Type 3: invalidate all entries across all PCIDs EXCEPT globals.
    /// Equivalent to a CR3 toggle that lands back on the same PML4.
    all_except_globals = 3,
};

const InvpcidDescriptor = extern struct {
    pcid_and_reserved: u64,
    linear_address: u64,
};

/// Issue an INVPCID. Caller is responsible for checking
/// `protect.invpcid_supported`; this function does NOT gate on it
/// (#UD on unsupported CPUs).
pub inline fn invpcid(t: InvpcidType, p: u16, va: u64) void {
    var desc: InvpcidDescriptor = .{
        .pcid_and_reserved = @as(u64, p) & 0xFFF,
        .linear_address = va,
    };
    const ty: u64 = @intFromEnum(t);
    asm volatile ("invpcid (%[d]), %[t]"
        :
        : [d] "r" (&desc),
          [t] "r" (ty),
        : .{ .memory = true });
}
