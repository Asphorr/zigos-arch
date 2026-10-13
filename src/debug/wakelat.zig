//! Wake latency, as `[wakelat]` lines with every perf dump. Two measures:
//!   run   — a woken task sits .ready until a CPU dispatches it; split by
//!           wake source, by whether the waker ran on the task's CPU, and
//!           by whether that CPU was busy with another task at the wake.
//!   late  — a timed wake readies its task after the moment it was due
//!           (usleep deadline, virtio-gpu completion IRQ); also the
//!           reschedule IPI's send-to-handler time.
//! Log2-µs histograms, reset at each dump. Observability only: nothing in
//! the scheduler reads them.

const std = @import("std");
const config = @import("../config.zig");
const smp = @import("../cpu/smp.zig");
const apic = @import("../time/apic.zig");
const perf = @import("perf.zig");
const serial = @import("serial.zig");

const MAX_PROCS = config.MAX_PROCS;

pub const Src = enum(u8) { other, explicit, hires, tick, gpu_io, parked };
const N_SRC = @typeInfo(Src).@"enum".fields.len;

pub const Late = enum(u8) { hires, gpu_irq, ipi };
const N_LATE = @typeInfo(Late).@"enum".fields.len;

/// <8µs, <16µs, ... <16ms, >=16ms.
const N_BUCKETS = 13;
const BUCKET_NAMES = [N_BUCKETS][]const u8{ "<8u", "<16u", "<32u", "<64u", "<128u", "<256u", "<512u", "<1m", "<2m", "<4m", "<8m", "<16m", ">16m" };

const Hist = struct {
    b: [N_BUCKETS]u64 = .{0} ** N_BUCKETS,
    n: u64 = 0,
    sum_us: u64 = 0,
    max_us: u64 = 0,
};

/// [src][where]: where = remote*2 + busy, +4 for a remote wake that sent
/// no reschedule IPI.
const N_WHERE = 6;
var run_h: [N_SRC][N_WHERE]Hist = [_][N_WHERE]Hist{[_]Hist{.{}} ** N_WHERE} ** N_SRC;
var late_h: [N_LATE]Hist = [_]Hist{.{}} ** N_LATE;

/// The waker's tag for the next .sleeping→.ready of the pid.
var hint: [MAX_PROCS]u8 = .{0} ** MAX_PROCS;
/// Stamped at .ready, consumed at dispatch; 0 = none.
var ready_tsc: [MAX_PROCS]u64 = .{0} ** MAX_PROCS;
var ready_tag: [MAX_PROCS]u8 = .{0} ** MAX_PROCS;
/// virtio-gpu completion IRQ time for a parked .gpu_io waiter.
var irq_tsc: [MAX_PROCS]u64 = .{0} ** MAX_PROCS;

inline fn perUs() u64 {
    return apic.tscPerQuantum() / 10_000;
}

fn bucket(us: u64) usize {
    if (us < 8) return 0;
    const lg: usize = 63 - @clz(us);
    return @min(N_BUCKETS - 1, lg - 2);
}

fn record(h: *Hist, cycles: u64) void {
    const per_us = perUs();
    if (per_us == 0) return;
    const us = cycles / per_us;
    _ = @atomicRmw(u64, &h.b[bucket(us)], .Add, 1, .monotonic);
    _ = @atomicRmw(u64, &h.n, .Add, 1, .monotonic);
    _ = @atomicRmw(u64, &h.sum_us, .Add, us, .monotonic);
    _ = @atomicRmw(u64, &h.max_us, .Max, us, .monotonic);
}

pub inline fn hintWake(pid: usize, src: Src) void {
    if (pid >= MAX_PROCS) return;
    @atomicStore(u8, &hint[pid], @intFromEnum(src), .monotonic);
}

/// sched.wake's tag; keeps a more specific one its caller set.
pub inline fn hintWakeDefault(pid: usize, src: Src) void {
    if (pid >= MAX_PROCS) return;
    _ = @cmpxchgStrong(u8, &hint[pid], 0, @intFromEnum(src), .monotonic, .monotonic);
}

/// setState, .sleeping→.ready, before the pid enters a run queue.
pub fn noteReady(pid: usize, assigned_cpu: u8, target_busy: bool) void {
    if (pid >= MAX_PROCS) return;
    const src = @atomicRmw(u8, &hint[pid], .Xchg, 0, .monotonic);
    const remote: u8 = @intFromBool(assigned_cpu != smp.myCpu().cpu_id);
    const now = perf.rdtsc();
    @atomicStore(u8, &ready_tag[pid], src * N_WHERE + remote * 2 + @intFromBool(target_busy), .monotonic);
    @atomicStore(u64, &ready_tsc[pid], now, .release);
    if (src == @intFromEnum(Src.gpu_io)) {
        const t = @atomicRmw(u64, &irq_tsc[pid], .Xchg, 0, .acquire);
        if (t != 0 and now >= t) noteLate(.gpu_irq, now - t);
    }
}

/// schedule(), `pid` picked to run on this CPU.
pub fn noteRun(pid: usize) void {
    if (pid >= MAX_PROCS) return;
    const t = @atomicRmw(u64, &ready_tsc[pid], .Xchg, 0, .acquire);
    if (t == 0) return;
    const now = perf.rdtsc();
    if (now < t) return;
    const tag = @atomicLoad(u8, &ready_tag[pid], .monotonic);
    if (tag / N_WHERE >= N_SRC) return;
    record(&run_h[tag / N_WHERE][tag % N_WHERE], now - t);
}

/// maybePreemptOnWake decided against an IPI for this remote wake.
pub fn noteNoIpi(pid: usize) void {
    if (pid >= MAX_PROCS) return;
    const tag = @atomicLoad(u8, &ready_tag[pid], .monotonic);
    if (tag % N_WHERE < 4) @atomicStore(u8, &ready_tag[pid], tag + 2, .monotonic);
}

/// A pid leaving .ready without running (kill): its stamp must not be
/// charged to the slot's next occupant.
pub fn drop(pid: usize) void {
    if (pid >= MAX_PROCS) return;
    @atomicStore(u64, &ready_tsc[pid], 0, .release);
}

pub fn noteLate(which: Late, cycles: u64) void {
    record(&late_h[@intFromEnum(which)], cycles);
}

/// virtio-gpu completion IRQ for a .gpu_io waiter; noteReady measures from it.
pub fn noteGpuIrq(pid: usize) void {
    if (pid >= MAX_PROCS) return;
    @atomicStore(u64, &irq_tsc[pid], perf.rdtsc(), .release);
}

/// IPI send → handler entry on the target, per target CPU.
var ipi_tsc: [smp.MAX_CPUS]u64 = .{0} ** smp.MAX_CPUS;

pub fn noteIpiSent(cpu: u8) void {
    if (cpu >= smp.MAX_CPUS) return;
    @atomicStore(u64, &ipi_tsc[cpu], perf.rdtsc(), .release);
}

pub fn noteIpiRecv(cpu: u8) void {
    if (cpu >= smp.MAX_CPUS) return;
    const t = @atomicRmw(u64, &ipi_tsc[cpu], .Xchg, 0, .acquire);
    if (t == 0) return;
    const now = perf.rdtsc();
    if (now >= t) noteLate(.ipi, now - t);
}

fn dumpHist(comptime kind: []const u8, name: []const u8, where: []const u8, h: *Hist) void {
    const n = @atomicRmw(u64, &h.n, .Xchg, 0, .monotonic);
    const sum = @atomicRmw(u64, &h.sum_us, .Xchg, 0, .monotonic);
    const max = @atomicRmw(u64, &h.max_us, .Xchg, 0, .monotonic);
    var counts: [N_BUCKETS]u64 = undefined;
    for (&counts, &h.b) |*c, *b| c.* = @atomicRmw(u64, b, .Xchg, 0, .monotonic);
    if (n == 0) return;
    serial.print("[wakelat] " ++ kind ++ " {s}{s} n={d} avg={d}us max={d}us |", .{ name, where, n, sum / n, max });
    for (counts, 0..) |c, i| {
        if (c != 0) serial.print(" {s}:{d}", .{ BUCKET_NAMES[i], c });
    }
    serial.print("\n", .{});
}

pub fn dump() void {
    const wheres = [N_WHERE][]const u8{ " local/idle", " local/busy", " remote/idle", " remote/busy", " remote/idle no-ipi", " remote/busy no-ipi" };
    for (&run_h, 0..) |*per_src, s| {
        const name = @tagName(@as(Src, @enumFromInt(s)));
        for (per_src, 0..) |*h, w| dumpHist("run", name, wheres[w], h);
    }
    for (&late_h, 0..) |*h, l| dumpHist("late", @tagName(@as(Late, @enumFromInt(l))), "", h);
}
