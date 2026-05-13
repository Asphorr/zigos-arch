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
pub fn bumpAfterShootdown(pcid: u16, cpu_id: u8) void {
    if (!protect.pcid_supported or pcid == 0 or pcid >= MAX_PCID) return;
    const new_gen = global_gen[pcid].fetchAdd(1, .acq_rel) + 1;
    if (cpu_id < smp.MAX_CPUS) {
        local_gen[cpu_id][pcid] = new_gen;
    }
}
