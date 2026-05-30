// WITNESS-lite — proactive lock-order reversal (LOR) detector.
//
// ZigOS already has *reactive* lock diagnostics (spinlock.zig: [lock-spin]
// NMI autopsy, [cli-hold], [lock-dump], Mutex recursive-acquire panic). They
// fire once a wedge has *already* happened. WITNESS is the proactive half:
// it watches the ORDER in which locks are taken and warns the first time an
// acquisition order could deadlock — before the timing stars align to make
// it actually hang. Modeled on FreeBSD's witness(4), trimmed to what ZigOS
// needs.
//
// Three multi-day wedges in this kernel's history would have been a one-line
// [witness] warning on first boot: the nvme cli-hold cascade, the dual-#PF
// TLB-shootdown deadlock, and the sleep-aware Mutex split. (See MEMORY.)
//
// --- What it tracks -------------------------------------------------------
//
// A "class" is a registered named lock (spinlock.registerLock/registerMutex
// hands each one a sequential index 0..MAX_CLASSES-1). UNregistered locks
// keep witness_class == 0xFF and are skipped entirely — registration is the
// coverage knob. Each class is a single lock instance, so a per-class BIT in
// a bitmask exactly represents "is this lock held."
//
// The held-set of the currently-executing context is:
//     spin_held[this_cpu]  ∪  mutex_held[this_pid]
// Spin locks are never held across a context switch (the ticket lock would
// deadlock), so they live in a per-CPU mask. Mutexes CAN be held across a
// blockOn() sleep, so they follow the thread in a per-PID mask. That split
// is exactly FreeBSD's td_sleeplocks vs per-CPU spinlock list, and it means
// WITNESS needs nothing in the PCB.
//
// --- How a reversal is detected -------------------------------------------
//
// `before[i] & bit(j)` set  ⇔  class i has been observed acquired-before
// class j (directly or transitively). The matrix is monotonic — bits are
// only ever set — so reads are lock-free and only edge INSERTION needs the
// internal graph lock. Acquiring C while holding P establishes "P before C":
//   * if `before[C] & bit(P)` is already set, "C before P" is known, so
//     P-before-C now closes a cycle → LOR. Warn; don't add (keep it acyclic).
//   * otherwise insert P→C and re-close the transitive order.
//
// Separately: acquiring a sleepable Mutex while THIS cpu holds any spinlock
// is flagged immediately (no prior edge needed) — sleeping with a spinlock
// held strands every spinner on it.

const std = @import("std");
const serial = @import("serial.zig");
const symbols = @import("symbols.zig");
const config = @import("../config.zig");

/// Number of trackable lock classes. KEEP IN SYNC with
/// spinlock.MAX_NAMED_LOCKS — every registered lock maps 1:1 to a class.
pub const MAX_CLASSES: u8 = 32;
/// KEEP IN SYNC with smp.MAX_CPUS. (Imported indirectly would cycle:
/// witness ← spinlock ← smp, and smp embeds a SpinLock by value.)
const MAX_CPUS: usize = 32;
const MAX_PROCS: usize = config.MAX_PROCS;

/// Compile-time master switch. Tracks under Debug/ReleaseSafe (the dev
/// builds, where runtime_safety is on); the hooks dead-strip entirely under
/// ReleaseFast/ReleaseSmall. Same gate spinlock.assertHeld uses.
pub const enabled: bool = std.debug.runtime_safety;

/// Make a detected reversal fatal instead of a warning. Off by default —
/// warn-and-continue so a single benign reversal during bring-up doesn't
/// wedge the box; flip on to halt at the first LOR (FreeBSD WITNESS_KDB).
const panic_on_lor: bool = false;

pub const ClassKind = enum(u8) { spin, mutex };

comptime {
    if (MAX_CLASSES > 32) @compileError("MAX_CLASSES > 32 won't fit a u32 bitmask row");
}

// --- registry mirror (populated at boot via registerClass) ----------------
var class_names: [MAX_CLASSES][]const u8 = [_][]const u8{""} ** MAX_CLASSES;
var class_kind: [MAX_CLASSES]ClassKind = [_]ClassKind{.spin} ** MAX_CLASSES;
var class_count: u8 = 0;

// --- order graph (transitively closed, monotonic) -------------------------
var before: [MAX_CLASSES]u32 = [_]u32{0} ** MAX_CLASSES;
/// Per-edge "already warned" flood guard for reversals.
var reported: [MAX_CLASSES]u32 = [_]u32{0} ** MAX_CLASSES;
/// Per-mutex-class "already warned" flood guard for sleep-with-spinlock-held.
var reported_sleep: u32 = 0;

// --- held sets -------------------------------------------------------------
// Each CPU's spin held-set lives on its OWN cache line. The per-acquire atomic
// RMW (.Or/.And) on one CPU's word would otherwise invalidate every other
// CPU's cached copy of a shared line (false sharing). Negligible for the
// original pmm/heap/nvme locks, but sched_lock — registered as a per-CPU class
// — updates this on every context switch on every CPU, so the padding keeps
// that hot path free of cross-CPU coherence traffic.
const CACHELINE: usize = 64;
const HeldWord = extern struct {
    bits: u32 = 0,
    _pad: [CACHELINE - @sizeOf(u32)]u8 = [_]u8{0} ** (CACHELINE - @sizeOf(u32)),
};
comptime {
    if (@sizeOf(HeldWord) != CACHELINE) @compileError("HeldWord must be exactly one cache line");
}
var spin_held: [MAX_CPUS]HeldWord align(CACHELINE) = [_]HeldWord{.{}} ** MAX_CPUS;
// Per-PID mutex held-set. NOT cache-line padded: Mutex is reserved for
// low-contention long-wait locks (see spinlock.zig), so these hooks are cold
// and false sharing here doesn't matter.
var mutex_held: [MAX_PROCS]u32 = [_]u32{0} ** MAX_PROCS;

// --- internal graph lock ---------------------------------------------------
// A bare ticket lock, deliberately NOT a spinlock.SpinLock: (a) avoids an
// import cycle, and (b) guarantees the graph lock can never recurse into the
// WITNESS hooks. Taken only on new-edge insertion — never on the read-only
// steady-state path.
var glock_next: u32 = 0;
var glock_serving: u32 = 0;

fn glockAcquire() void {
    const t = @atomicRmw(u32, &glock_next, .Add, 1, .seq_cst);
    while (@atomicLoad(u32, &glock_serving, .acquire) != t) asm volatile ("pause");
}

fn glockRelease() void {
    _ = @atomicRmw(u32, &glock_serving, .Add, 1, .release);
}

inline fn bit(c: u8) u32 {
    return @as(u32, 1) << @as(u5, @intCast(c));
}

inline fn orInto(slot: *u32, mask: u32) void {
    _ = @atomicRmw(u32, slot, .Or, mask, .release);
}

inline fn andClear(slot: *u32, mask: u32) void {
    _ = @atomicRmw(u32, slot, .And, ~mask, .release);
}

fn className(c: u8) []const u8 {
    if (c < MAX_CLASSES and class_names[c].len != 0) return class_names[c];
    return "?";
}

// --- registration ----------------------------------------------------------

/// Mirror a registered lock into the class table. Called from
/// spinlock.registerLock / registerMutex with the index the lock received.
pub fn registerClass(index: u8, name: []const u8, kind: ClassKind) void {
    if (comptime !enabled) return;
    if (index >= MAX_CLASSES) return;
    class_names[index] = name;
    class_kind[index] = kind;
    if (index + 1 > class_count) class_count = index + 1;
}

// --- held-set + order check ------------------------------------------------

inline fn heldMask(cpu: usize, pid: ?usize) u32 {
    var m: u32 = 0;
    if (cpu < MAX_CPUS) m |= @atomicLoad(u32, &spin_held[cpu].bits, .acquire);
    if (pid) |p| {
        if (p < MAX_PROCS) m |= @atomicLoad(u32, &mutex_held[p], .acquire);
    }
    return m;
}

/// For class C being acquired while `held` is the current held-set, record
/// "P before C" for every held P, and warn on any reversal.
fn checkOrder(c: u8, held: u32, ra: usize) void {
    const cbit = bit(c);
    var h = held & ~cbit; // a class never orders against itself
    while (h != 0) {
        const p: u8 = @intCast(@ctz(h));
        h &= h - 1; // clear lowest set bit
        // "P before C" already known (directly or transitively)? Done.
        if (@atomicLoad(u32, &before[p], .acquire) & cbit != 0) continue;
        // "C before P" already known? Then P-before-C now is a reversal.
        if (@atomicLoad(u32, &before[c], .acquire) & bit(p) != 0) {
            reportLor(p, c, ra);
            continue;
        }
        addEdge(p, c, ra);
    }
}

/// Insert edge P→C and re-establish transitive closure, under the graph
/// lock with a re-check (another CPU may have raced us).
fn addEdge(p: u8, c: u8, ra: usize) void {
    var reversal = false;
    {
        glockAcquire();
        defer glockRelease();
        const cbit = bit(c);
        const pbit = bit(p);
        if (before[p] & cbit != 0) return; // edge appeared meanwhile
        if (before[c] & pbit != 0) {
            reversal = true; // became a reversal meanwhile
        } else {
            // P now reaches C and everything C reaches.
            orInto(&before[p], cbit | @atomicLoad(u32, &before[c], .acquire));
            // Everyone who reached P now reaches everything P reaches.
            const preach = @atomicLoad(u32, &before[p], .acquire);
            var x: u8 = 0;
            while (x < class_count) : (x += 1) {
                if (@atomicLoad(u32, &before[x], .acquire) & pbit != 0) orInto(&before[x], preach);
            }
        }
    }
    if (reversal) reportLor(p, c, ra); // report outside the lock
}

// --- public hooks (called from spinlock.zig) -------------------------------

/// A registered SpinLock was just acquired on `cpu` (current pid `pid`).
pub fn spinAcquire(class: u8, cpu: usize, pid: ?usize, ra: usize) void {
    if (comptime !enabled) return;
    if (class >= MAX_CLASSES) return;
    checkOrder(class, heldMask(cpu, pid), ra);
    if (cpu < MAX_CPUS) orInto(&spin_held[cpu].bits, bit(class));
}

/// A registered SpinLock is about to be released on `cpu`.
pub fn spinRelease(class: u8, cpu: usize) void {
    if (comptime !enabled) return;
    if (class < MAX_CLASSES and cpu < MAX_CPUS) andClear(&spin_held[cpu].bits, bit(class));
}

/// A registered Mutex acquire is starting on `cpu` for `pid`. Called BEFORE
/// the (possibly blocking) CAS loop so the sleep-with-spinlock-held check
/// fires before any actual sleep.
pub fn mutexAcquire(class: u8, cpu: usize, pid: usize, ra: usize) void {
    if (comptime !enabled) return;
    if (class >= MAX_CLASSES) return;
    if (cpu < MAX_CPUS and @atomicLoad(u32, &spin_held[cpu].bits, .acquire) != 0) {
        reportSleepWithSpin(class, cpu, ra);
    }
    checkOrder(class, heldMask(cpu, pid), ra);
    if (pid < MAX_PROCS) orInto(&mutex_held[pid], bit(class));
}

/// A registered Mutex is about to be released by `pid`.
pub fn mutexRelease(class: u8, pid: usize) void {
    if (comptime !enabled) return;
    if (class < MAX_CLASSES and pid < MAX_PROCS) andClear(&mutex_held[pid], bit(class));
}

/// A task is being torn down — drop any mutex-held bookkeeping for its pid
/// so a force-released lock (spinlock.releaseMutexesOwnedBy) doesn't leave a
/// stale held bit that taints the next task to reuse the slot.
pub fn threadExit(pid: usize) void {
    if (comptime !enabled) return;
    if (pid < MAX_PROCS) @atomicStore(u32, &mutex_held[pid], 0, .release);
}

// --- reporting -------------------------------------------------------------

/// Claim the first-report right for a reversal (p,c). Lock-free so it's safe
/// to call both on the steady-state path and from inside addEdge.
fn claimReport(p: u8, c: u8) bool {
    const prev = @atomicRmw(u32, &reported[p], .Or, bit(c), .acq_rel);
    return prev & bit(c) == 0;
}

fn reportLor(p: u8, c: u8, ra: usize) void {
    if (!claimReport(p, c)) return;
    serial.print(
        "\n[witness] LOR: acquiring {s} while holding {s}\n",
        .{ className(c), className(p) },
    );
    serial.print(
        "[witness]   known order is {s} -> ... -> {s}; this acquire reverses it\n",
        .{ className(c), className(p) },
    );
    printSite(ra);
    if (panic_on_lor) @panic("WITNESS: lock-order reversal");
}

fn reportSleepWithSpin(mutex_class: u8, cpu: usize, ra: usize) void {
    const prev = @atomicRmw(u32, &reported_sleep, .Or, bit(mutex_class), .acq_rel);
    if (prev & bit(mutex_class) != 0) return;
    serial.print(
        "\n[witness] SLEEP-WITH-SPINLOCK: acquiring mutex {s} while cpu{d} holds spinlock(s):\n",
        .{ className(mutex_class), cpu },
    );
    if (cpu < MAX_CPUS) printHeldSpins(@atomicLoad(u32, &spin_held[cpu].bits, .acquire));
    printSite(ra);
    if (panic_on_lor) @panic("WITNESS: sleepable lock acquired with spinlock held");
}

fn printSite(ra: usize) void {
    if (symbols.resolveKernel(ra)) |r| {
        serial.print("[witness]   at {s}+0x{X}\n", .{ r.name, r.offset });
    } else {
        serial.print("[witness]   at 0x{X}\n", .{ra});
    }
}

fn printHeldSpins(mask: u32) void {
    var m = mask;
    while (m != 0) : (m &= m - 1) {
        const idx: u8 = @intCast(@ctz(m));
        serial.print("[witness]     - {s}\n", .{className(idx)});
    }
}

// --- autopsy ---------------------------------------------------------------

/// Dump the observed lock-order graph and current held-sets. Safe to call
/// from a panic/wedge autopsy (lock-free reads only; no allocation).
pub fn dump() void {
    if (comptime !enabled) return;
    serial.print("[witness] {d} tracked classes; observed order edges:\n", .{class_count});
    var i: u8 = 0;
    while (i < class_count) : (i += 1) {
        var j: u8 = 0;
        while (j < class_count) : (j += 1) {
            if (i != j and before[i] & bit(j) != 0) {
                serial.print("[witness]   {s} -> {s}\n", .{ className(i), className(j) });
            }
        }
    }
    var cpu: usize = 0;
    while (cpu < MAX_CPUS) : (cpu += 1) {
        const m = @atomicLoad(u32, &spin_held[cpu].bits, .acquire);
        if (m == 0) continue;
        serial.print("[witness] cpu{d} holds spinlock(s):\n", .{cpu});
        printHeldSpins(m);
    }
    var pid: usize = 0;
    while (pid < MAX_PROCS) : (pid += 1) {
        const m = @atomicLoad(u32, &mutex_held[pid], .acquire);
        if (m == 0) continue;
        serial.print("[witness] pid{d} holds mutex(es):\n", .{pid});
        printHeldSpins(m);
    }
}
