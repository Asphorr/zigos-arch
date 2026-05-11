// Per-syscall latency attribution.
//
// The existing `[slow-sc]` log line tells us a syscall took N ms but
// nothing about WHERE the time went. Was it disk wait? Lock contention?
// GPU wait? validateUserPtr's per-page walk? This module lets hot
// kernel paths declare a "phase" — a named segment of work — and
// accumulates time per phase across the syscall. At syscall exit, if
// total runtime crossed the slow-sc threshold, dump the phase
// breakdown so the operator can see "847 ms = 720 ms gpu_wait + 50 ms
// disk_read + 70 ms user_copy + 7 ms misc".
//
// Design choices:
//   - Comptime-known phase names: cheap (one u8 enum, fixed array),
//     and the set we care about is small. New phases require an
//     enum entry — intentional friction so the log stays grep-able.
//   - Single active phase at a time per CPU: nesting an inner phase
//     pauses the outer (outer's accumulated time stops, inner runs,
//     when inner ends outer doesn't auto-resume — caller is expected
//     to keep phase scopes flat for clarity). Records what was
//     measured, not what wasn't.
//   - Per-CPU storage indexed by cpu_id: no atomic ops, cli-protected
//     by the syscall handler.
//
// API: prefer `scope(.gpu_wait)` + `defer s.end()` over manual
// enter/exit pairs — guarantees pairing across early returns / errdefer.

const std = @import("std");
const smp = @import("../cpu/smp.zig");
const perf = @import("perf.zig");
const serial = @import("serial.zig");
const apic = @import("../time/apic.zig");

pub const Phase = enum(u8) {
    /// validateUserPtr / allCurrentUserPagesMapped — PT walk for every page.
    /// Hot since today's user-pointer hardening sweep.
    user_ptr_walk,
    /// Bare @memcpy / explicit copy_to_user style operations.
    user_copy,
    /// virtio-gpu sendCmd wait (pause-poll + hlt).
    gpu_wait,
    /// vfs.loadFile / loadFileFresh — disk read path.
    disk_read,
    /// Path resolution + mount-table dispatch.
    fs_lookup,
    /// Network blocking (tcp recv, http get, dns resolve).
    net_wait,
    /// Spinlock acquire wait time.
    lock_wait,
};

const PHASE_COUNT = @typeInfo(Phase).@"enum".fields.len;

const PhaseData = struct {
    /// Accumulated TSC cycles per phase, since the last reset().
    cycles: [PHASE_COUNT]u64 = [_]u64{0} ** PHASE_COUNT,
    /// Currently running phase (null = not in any tracked phase).
    active: ?Phase = null,
    /// rdtsc at active phase start.
    active_start: u64 = 0,
    /// Total samples (enter calls) since reset — for "did we even
    /// instrument anything?" dumb check.
    sample_count: u32 = 0,
};

var state: [smp.MAX_CPUS]PhaseData = [_]PhaseData{.{}} ** smp.MAX_CPUS;

/// RAII scope. Use as `const s = syscall_perf.scope(.X); defer s.end();`
/// to guarantee enter/exit pairing across early returns and panics.
pub const Scope = struct {
    p: Phase,
    pub inline fn end(self: Scope) void {
        exit(self.p);
    }
};

pub inline fn scope(p: Phase) Scope {
    enter(p);
    return Scope{ .p = p };
}

pub fn enter(p: Phase) void {
    const cpu_id = smp.myCpu().cpu_id;
    if (cpu_id >= smp.MAX_CPUS) return;
    const s = &state[cpu_id];

    // Pause any previously-active phase (no nesting: the outer's clock
    // stops, doesn't auto-resume on exit).
    if (s.active) |outer| {
        const dt = perf.rdtsc() -% s.active_start;
        s.cycles[@intFromEnum(outer)] +%= dt;
    }
    s.active = p;
    s.active_start = perf.rdtsc();
    s.sample_count +%= 1;
}

pub fn exit(p: Phase) void {
    const cpu_id = smp.myCpu().cpu_id;
    if (cpu_id >= smp.MAX_CPUS) return;
    const s = &state[cpu_id];

    // Mismatch (e.g., scope dropped twice or out of order) — silently
    // ignore. Phase breakdown will under-attribute but no crash.
    if (s.active) |active| {
        if (active != p) return;
    } else {
        return;
    }

    const dt = perf.rdtsc() -% s.active_start;
    s.cycles[@intFromEnum(p)] +%= dt;
    s.active = null;
}

/// Zero this CPU's phase state. Call at syscall entry.
pub fn reset() void {
    const cpu_id = smp.myCpu().cpu_id;
    if (cpu_id >= smp.MAX_CPUS) return;
    state[cpu_id] = .{};
}

/// Dump the current CPU's phase breakdown. Call at syscall exit when
/// total dt crossed the slow-sc threshold. Format mirrors the per-syscall
/// `[slow-sc]` log line so they stay together when grepping.
pub fn dump() void {
    const cpu_id = smp.myCpu().cpu_id;
    if (cpu_id >= smp.MAX_CPUS) return;
    const s = &state[cpu_id];

    if (s.sample_count == 0) return; // no instrumented sites hit

    serial.print("[slow-sc/phases]", .{});
    inline for (@typeInfo(Phase).@"enum".fields, 0..) |f, i| {
        const cyc = s.cycles[i];
        if (cyc != 0) {
            const ms = apic.tscToMs(cyc);
            serial.print(" {s}={d}ms", .{ f.name, ms });
        }
    }
    serial.print(" samples={d}\n", .{s.sample_count});
}
