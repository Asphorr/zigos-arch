// Per-CPU ring buffer of cpu.current_pid transitions.
//
// The per_cpu_asm_alias bug class is: two CPUs end up with current_pid
// pointing at the same pid simultaneously — both then dispatch it,
// both run on the same kstack, last-writer-wins corrupts the saved
// kesp. By the time the resulting crash surfaces (usually as a
// wild-RIP dispatch or a stack-overflow guard hit) the cross-CPU
// race is over and we have no record of which CPUs raced.
//
// This trace records every assignment to `cpu.current_pid` with TSC,
// cpu_id, old_pid, new_pid, and the caller's return address. To find
// a race: scan the rings for two CPUs that both have entries with
// the same new_pid at close-by TSC values. The caller_ra points
// at the schedule() callsite (or enterFirstTask{,Ap} / setCurrentPid
// caller) that did the assignment.
//
// Cost: same as save_trace — rdtsc + ~6 stores, per-CPU, no atomics.
// Hot path is `cpu.current_pid = next` in schedule() (~once per tick
// per cpu).

const std = @import("std");
const smp = @import("../cpu/smp.zig");
const config = @import("../config.zig");
const process = @import("../proc/process.zig");
const serial = @import("serial.zig");
const symbols = @import("symbols.zig");

pub const RING_SIZE: usize = 32;

pub const Entry = extern struct {
    tsc: u64 = 0,
    /// caller's @returnAddress — symbolizes to the schedule() / enter
    /// callsite that did the assignment. Most diagnostic field.
    caller_ra: u64 = 0,
    /// 0xFF = null
    old_pid: u8 = 0xFF,
    /// 0xFF = null
    new_pid: u8 = 0xFF,
    cpu_id: u8 = 0xFF,
    _pad: [5]u8 = .{ 0, 0, 0, 0, 0 },
};

const Ring = struct {
    entries: [RING_SIZE]Entry = [_]Entry{.{}} ** RING_SIZE,
    head: u32 = 0,
};

var rings: [smp.MAX_CPUS]Ring align(64) = [_]Ring{.{}} ** smp.MAX_CPUS;

inline fn rdtsc() u64 {
    return asm volatile (
        \\ rdtsc
        \\ shlq $32, %%rdx
        \\ orq %%rdx, %%rax
        : [r] "={rax}" (-> u64),
        :: .{ .rdx = true });
}

inline fn pidOrSentinel(p: ?usize) u8 {
    if (p) |v| {
        if (v >= config.MAX_PROCS) return 0xFE;
        return @intCast(v);
    }
    return 0xFF;
}

/// Record-only — does NOT mutate cpu.current_pid. The setter below
/// performs the assignment AND records; use this directly only if you
/// can't go through the setter (e.g. an existing direct-write site
/// you want to keep but observe). Records caller_ra = the call site.
pub fn record(cpu_id: u8, old: ?usize, new: ?usize) void {
    if (cpu_id >= smp.MAX_CPUS) return;
    const ring = &rings[cpu_id];
    const slot: usize = ring.head % RING_SIZE;
    ring.head +%= 1;
    ring.entries[slot] = .{
        .tsc = rdtsc(),
        .caller_ra = @returnAddress(),
        .old_pid = pidOrSentinel(old),
        .new_pid = pidOrSentinel(new),
        .cpu_id = cpu_id,
    };
}

/// Wrapped setter — call this instead of writing `cpu.current_pid =`
/// directly. Records the transition before doing the assignment. The
/// caller_ra captured here is the schedule() / enterFirstTask /
/// destroyCurrent call site that wanted the change.
pub inline fn setCurrentPid(cpu: *smp.CpuLocal, new: ?usize) void {
    const old = cpu.current_pid;
    record(cpu.cpu_id, old, new);
    // Per-PID activity ring stamp — both the outgoing and incoming pid
    // get an entry so each pid's autopsy ring shows the full handoff.
    const pid_act = @import("pid_act.zig");
    const ra = @returnAddress();
    if (old) |op| {
        const next_pid: u8 = if (new) |np| @intCast(np) else 0xFF;
        pid_act.record(op, .setcurpid_out, next_pid, 0xFF, ra);
    }
    if (new) |np| {
        const prev_pid: u8 = if (old) |op| @intCast(op) else 0xFF;
        pid_act.record(np, .setcurpid_in, prev_pid, 0xFF, ra);
    }
    cpu.current_pid = new;
    // Release the inbound-dispatch bracket: from here on, cpu.current_pid
    // matches the running-state pid (or null for outbound-only paths),
    // so pcb_invariants' "state==.running but no owner" check is safe.
    cpu.dispatching_in_pid = 0xFFFF;
}

fn fmtPid(buf: []u8, p: u8) []const u8 {
    if (p == 0xFF) return "null";
    if (p == 0xFE) return "OOB";
    return std.fmt.bufPrint(buf, "{d}", .{p}) catch "?";
}

/// Dump every CPU's pid-transition ring oldest-first. Output is
/// grep-friendly. Look for two CPUs with identical new_pid at close TSC
/// values — that's a same-pid race.
pub fn dumpAll() void {
    serial.print("\n[pid-trace] last {d} current_pid changes per CPU:\n", .{RING_SIZE});
    for (0..smp.MAX_CPUS) |i| {
        const cpu = &smp.cpus[i];
        if (i > 0 and !cpu.alive) continue;
        const r = &rings[i];
        const total = r.head;
        const count: usize = @min(@as(usize, total), RING_SIZE);
        if (count == 0) {
            serial.print("  cpu{d}: (no transitions recorded)\n", .{i});
            continue;
        }
        serial.print("  cpu{d}: {d} changes (showing last {d}):\n", .{ i, total, count });
        var k: usize = 0;
        var ob: [8]u8 = undefined;
        var nb: [8]u8 = undefined;
        while (k < count) : (k += 1) {
            const slot: usize = (r.head -% @as(u32, @intCast(count - k))) % RING_SIZE;
            const e = r.entries[slot];
            const old_s = fmtPid(&ob, e.old_pid);
            const new_s = fmtPid(&nb, e.new_pid);
            serial.print(
                "    [{d:0>2}] tsc=0x{X:0>12} cpu{d}: {s}→{s}",
                .{ slot, e.tsc, e.cpu_id, old_s, new_s },
            );
            if (symbols.resolveKernel(e.caller_ra)) |sym| {
                serial.print(" via {s}+0x{X}\n", .{ sym.name, sym.offset });
            } else {
                serial.print(" via 0x{X:0>16}\n", .{e.caller_ra});
            }
        }
    }
}
