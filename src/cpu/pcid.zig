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

// Stats — surfaced by procfs/sysmon for visibility.
pub var alloc_count: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
pub var free_count: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
pub var preserve_hits: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
pub var flush_misses: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

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
    if (!protect.pcid_supported or pcid == 0 or pcid >= MAX_PCID) {
        writeCr3(aligned);
        return;
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
/// Kept as belt-and-suspenders even when INVPCID is in use: INVPCID
/// type 1 explicitly flushes the named PCID's entries on the peer CPU,
/// so the lazy-flush mechanism is redundant in that path. The cost is
/// one atomic increment per shootdown — cheap enough to keep as
/// defense against a stray entry slipping past the INVPCID issue.
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
