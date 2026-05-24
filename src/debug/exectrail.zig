// Per-CPU "where am I now" execution trail.
//
// Each CPU has a 128-entry ring of (tsc, rip) samples recorded on every
// IRQ0 firing — captures wherever the CPU was interrupted at that moment.
// Also recorded at syscall entry, with the syscall number encoded as a
// special marker so we can distinguish "RIP X was executing user/kernel
// code" from "RIP marker N indicates entry to syscall #N".
//
// Dumped from the panic / watchdog autopsy. Useful when:
//   - The stack walk is corrupted (bad rbp chain) and we need ANY
//     execution context to figure out what the CPU was doing.
//   - The freeze is in code with no useful backtrace (idle loop, NMI
//     handler that never returned, deadlock spin in a leaf function).
//   - You want to see the recent execution history leading up to the
//     fault, not just the final frame.
//
// Cost: one rdtsc + one mov per IRQ0 entry. Bounded by ring size, no
// allocation. Lives in BSS keyed by cpu_id rather than embedded in
// CpuLocal so the cache line in CpuLocal doesn't grow.

const smp = @import("../cpu/smp.zig");
const symbols = @import("symbols.zig");
const serial = @import("serial.zig");
const perf = @import("perf.zig");

pub const TRAIL_ENTRIES: u8 = 128;

/// Sentinel RIP values for synthetic "I entered XXX" markers. Anything
/// >= MARKER_BASE is decoded as `(syscall N entry)` instead of resolved
/// as a normal kernel RIP. Picked to be unmistakably-not-a-real-RIP
/// (above the canonical user range, below the kernel high half).
pub const MARKER_BASE: u64 = 0x0000_8000_0000_0000;
pub const MARKER_SYSCALL_BIT: u64 = 0x0001_0000_0000_0000;

const TrailEntry = struct {
    tsc: u64,
    rip: u64,
};

const ZERO: TrailEntry = .{ .tsc = 0, .rip = 0 };

var trails: [smp.MAX_CPUS][TRAIL_ENTRIES]TrailEntry =
    [_][TRAIL_ENTRIES]TrailEntry{[_]TrailEntry{ZERO} ** TRAIL_ENTRIES} ** smp.MAX_CPUS;
var trail_head: [smp.MAX_CPUS]u8 = [_]u8{0} ** smp.MAX_CPUS;

/// Record the saved RIP at IRQ0 entry. Called from handleIRQ0 — runs
/// with cli held, so the per-CPU ring write needs no synchronization.
pub fn recordIrq(saved_rip: u64) void {
    const cpu_id = smp.myCpu().cpu_id;
    if (cpu_id >= smp.MAX_CPUS) return;
    const head = trail_head[cpu_id];
    trails[cpu_id][head] = .{ .tsc = perf.rdtsc(), .rip = saved_rip };
    trail_head[cpu_id] = (head + 1) % TRAIL_ENTRIES;
}

/// Record syscall entry. Encodes sys_num into a sentinel RIP so the
/// dumper can decode it as "(syscall N entry)" instead of trying to
/// resolve as a kernel address.
pub fn recordSyscall(sys_num: u32) void {
    const cpu_id = smp.myCpu().cpu_id;
    if (cpu_id >= smp.MAX_CPUS) return;
    const head = trail_head[cpu_id];
    const marker = MARKER_BASE | MARKER_SYSCALL_BIT | @as(u64, sys_num);
    trails[cpu_id][head] = .{ .tsc = perf.rdtsc(), .rip = marker };
    trail_head[cpu_id] = (head + 1) % TRAIL_ENTRIES;
}

/// Peek at the most-recent recorded entry for `cpu_id`. Returns the
/// saved RIP (or syscall marker) — caller can decode marker bits via
/// MARKER_BASE / MARKER_SYSCALL_BIT. Returns null if the ring is empty
/// or cpu_id is out of range.
///
/// Used by smi.tick() classification: at SMI-tick time the head-1 entry
/// holds the saved_rip from the PREVIOUS IRQ0 (this tick's recordIrq
/// hasn't run yet — see idt.zig ordering), which tells us whether the
/// CPU was in user code, idle, or kernel work during the stall gap.
pub fn peekHeadMinusOne(cpu_id: u8) ?u64 {
    if (cpu_id >= smp.MAX_CPUS) return null;
    const head = trail_head[cpu_id];
    const idx = (head + TRAIL_ENTRIES - 1) % TRAIL_ENTRIES;
    const e = trails[cpu_id][idx];
    if (e.tsc == 0) return null;
    return e.rip;
}

/// Dump the last `n` entries of `cpu_id`'s ring, newest first. Used by
/// crash / watchdog autopsy. Cap n at TRAIL_ENTRIES.
pub fn dump(cpu_id: u8, n: u8) void {
    if (cpu_id >= smp.MAX_CPUS) return;
    const want: u8 = if (n > TRAIL_ENTRIES) TRAIL_ENTRIES else n;
    serial.print("[trail cpu{d}] last {d} samples (newest first):\n", .{ cpu_id, want });

    const head = trail_head[cpu_id];
    var i: u8 = 0;
    while (i < want) : (i += 1) {
        // Walk backward from (head - 1).
        const idx = (head + TRAIL_ENTRIES - 1 - i) % TRAIL_ENTRIES;
        const e = trails[cpu_id][idx];
        if (e.tsc == 0) continue; // never written
        if (e.rip >= MARKER_BASE) {
            const sys_num = e.rip & 0xFFFF;
            serial.print("  tsc={d} (syscall #{d} entry)\n", .{ e.tsc, sys_num });
        } else if (symbols.resolveKernel(e.rip)) |r| {
            serial.print("  tsc={d} {s}+0x{X}\n", .{ e.tsc, r.name, r.offset });
        } else if (symbols.resolveKernelNearest(e.rip)) |r| {
            if (r.offset < 0x4000) {
                serial.print("  tsc={d} (near {s}+0x{X})\n", .{ e.tsc, r.name, r.offset });
            } else {
                serial.print("  tsc={d} 0x{X:0>16}\n", .{ e.tsc, e.rip });
            }
        } else {
            serial.print("  tsc={d} 0x{X:0>16}\n", .{ e.tsc, e.rip });
        }
    }
}

/// Dump trails for every alive CPU. Called from autopsy.
pub fn dumpAll(n: u8) void {
    for (&smp.cpus) |*cpu| {
        if (!cpu.alive) continue;
        dump(cpu.cpu_id, n);
    }
}
