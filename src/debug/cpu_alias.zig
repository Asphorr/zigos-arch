// Cross-CPU aliasing detector — verifies that no two alive CPUs share
// the per-CPU state that distinguishes them. The per_cpu_asm_alias bug
// class (and its recurrence detected by B.3) shows up as two CPUs with
// the same:
//
//   - idle_pid              (both think they should run the same idle PCB)
//   - tss.rsp0              (both IDT-gate AND syscall entries land on
//                            the same kstack — see syscall_entry.zig:
//                            the LSTAR stub loads from cpus[N].tss.rsp0,
//                            the same memory hardware reads on ring
//                            transitions, so these two paths can no
//                            longer disagree)
//   - current_pid           (both dispatching the same task — the killer)
//
// All of these should be UNIQUE across alive CPUs at any moment. This
// module exposes one cheap scan that walks alive CPUs and asserts the
// invariant; called from the same periodic site as pcb_invariants
// (handleIRQ0 every ~1s) AND once at the end of SMP init.
//
// On detection: klog + panic with the colliding pair's full state.
// Same one-shot-flag treatment as pcb_invariants so a non-halting panic
// doesn't drown the log.

const std = @import("std");
const smp = @import("../cpu/smp.zig");
const serial = @import("serial.zig");

var reported: bool = false;

// Snapshot buffers MUST be file-scope, not function locals. scan() runs
// from handleIRQ0 on whichever task's kstack happens to be current. Stack-
// local arrays here ate ~800 bytes per call; their zero/-1 init memset
// landed on top of whatever data was already in the kstack body, including
// the saved-RIP slot (kesp+48) of any prior switchTo save that happened
// to sit in that range. The result was that every cpu_alias.scan call
// silently zeroed a sleeping task's saved RA → next dispatch popped 0
// as RIP → wild-RIP crash. (Detected by the kesp+48 watchpoint pointing
// straight at cpu_alias.scan+0x186 as the writer 2026-05-17 — this is
// also a likely explanation for the original netstat-desktop bug class.)
// scan() is gated to BSP-only in handleIRQ0, so a single static buffer
// has no concurrency exposure.
var snap_alive: [smp.MAX_CPUS]bool = [_]bool{false} ** smp.MAX_CPUS;
var snap_idle_pid: [smp.MAX_CPUS]i32 = [_]i32{-1} ** smp.MAX_CPUS;
var snap_cur_pid: [smp.MAX_CPUS]i32 = [_]i32{-1} ** smp.MAX_CPUS;
var snap_rsp0: [smp.MAX_CPUS]u64 = [_]u64{0} ** smp.MAX_CPUS;

const Violation = struct {
    field: []const u8,
    cpu_a: u8,
    cpu_b: u8,
    value_a: u64,
    value_b: u64,
};

inline fn fail(v: Violation) noreturn {
    serial.print("\n[cpu-alias] FAIL — two CPUs share '{s}':\n", .{v.field});
    serial.print("[cpu-alias]   cpu{d}: 0x{X:0>16}\n", .{ v.cpu_a, v.value_a });
    serial.print("[cpu-alias]   cpu{d}: 0x{X:0>16}\n", .{ v.cpu_b, v.value_b });
    // Drop a per-CPU snapshot for context (current_pid / idle_pid / tss).
    for (0..smp.MAX_CPUS) |i| {
        const cpu = &smp.cpus[i];
        if (i > 0 and !cpu.alive) continue;
        const cur: i32 = if (cpu.current_pid) |p| @intCast(p) else -1;
        const idle: i32 = if (cpu.idle_pid) |p| @intCast(p) else -1;
        serial.print(
            "[cpu-alias]   cpu{d} alive={any} cur={d} idle={d} tss.rsp0=0x{X}\n",
            .{ i, cpu.alive, cur, idle, cpu.tss.rsp0 },
        );
    }
    @import("kdbg.zig").nmi_halt_after_snapshot = true;
    @import("save_trace.zig").dumpAll();
    @import("pid_trace.zig").dumpAll();
    @panic("cpu-alias detector: two CPUs share per-CPU state");
}

/// Walk alive CPUs, comparing pairwise on the four uniqueness fields.
/// Cost is O(N²) but N is at most MAX_CPUS=32 — well under 1µs total.
pub fn scan() void {
    if (@atomicLoad(bool, &reported, .acquire)) return;
    // Reset the static snapshot in-place (cheap: ~800 stores). Reusing
    // file-scope buffers across calls — see comment on snap_* above for
    // why these can't be function locals.
    for (0..smp.MAX_CPUS) |i| {
        snap_alive[i] = false;
        snap_idle_pid[i] = -1;
        snap_cur_pid[i] = -1;
        snap_rsp0[i] = 0;
    }
    for (0..smp.MAX_CPUS) |i| {
        const cpu = &smp.cpus[i];
        if (i > 0 and !cpu.alive) continue;
        snap_alive[i] = true;
        if (cpu.idle_pid) |p| snap_idle_pid[i] = @intCast(p);
        if (cpu.current_pid) |p| snap_cur_pid[i] = @intCast(p);
        snap_rsp0[i] = cpu.tss.rsp0;
    }

    for (0..smp.MAX_CPUS) |a| {
        if (!snap_alive[a]) continue;
        for (a + 1..smp.MAX_CPUS) |b| {
            if (!snap_alive[b]) continue;
            if (snap_idle_pid[a] != -1 and snap_idle_pid[a] == snap_idle_pid[b]) {
                @atomicStore(bool, &reported, true, .release);
                fail(.{
                    .field = "idle_pid",
                    .cpu_a = @intCast(a), .cpu_b = @intCast(b),
                    .value_a = @intCast(snap_idle_pid[a]),
                    .value_b = @intCast(snap_idle_pid[b]),
                });
            }
            // current_pid sharing is the killer race. .running task
            // should be owned by exactly one CPU; per-CPU dispatch
            // (Phase 2) guarantees this except for the brief window
            // around schedule(). A periodic scan catching it == bug.
            if (snap_cur_pid[a] != -1 and snap_cur_pid[a] == snap_cur_pid[b]) {
                @atomicStore(bool, &reported, true, .release);
                fail(.{
                    .field = "current_pid",
                    .cpu_a = @intCast(a), .cpu_b = @intCast(b),
                    .value_a = @intCast(snap_cur_pid[a]),
                    .value_b = @intCast(snap_cur_pid[b]),
                });
            }
            if (snap_rsp0[a] != 0 and snap_rsp0[a] == snap_rsp0[b]) {
                @atomicStore(bool, &reported, true, .release);
                fail(.{
                    .field = "tss.rsp0",
                    .cpu_a = @intCast(a), .cpu_b = @intCast(b),
                    .value_a = snap_rsp0[a], .value_b = snap_rsp0[b],
                });
            }
        }
        // (Removed: same-CPU tss.rsp0 != syscall_stack_top check. The
        // second field no longer exists — syscall_entry's LSTAR stub
        // loads RSP from cpus[N].tss.rsp0 directly, so there is no
        // mirror that can drift.)
    }
}

/// One-shot post-SMP-init validation. Same scan, but logged on success
/// so the boot log records "no cross-CPU aliasing detected at boot" —
/// future drift then shows as a runtime detection by the periodic scan.
pub fn checkAtBoot() void {
    scan();
    serial.print("[cpu-alias] OK at boot — {d} alive CPUs, no aliasing\n", .{smp.aliveCpuCount()});
}
