//! Where a Linux-personality program spends its kernel time: wall cycles per
//! syscall number (sleeps included) and per user page fault. Boot mode 19
//! prints and resets the table after every run.

const serial = @import("serial.zig");
const perf = @import("perf.zig");
const apic = @import("../time/apic.zig");
const nvme = @import("../driver/nvme.zig");
const smp = @import("../cpu/smp.zig");
const process = @import("../proc/process.zig");
const symbols = @import("symbols.zig");
const ext2_block = @import("../fs/ext2/block.zig");

const SLOTS: usize = 512;

const Stat = struct {
    count: u64 = 0,
    cycles: u64 = 0,
    max: u64 = 0,

    fn add(self: *Stat, dt: u64) void {
        _ = @atomicRmw(u64, &self.count, .Add, 1, .monotonic);
        _ = @atomicRmw(u64, &self.cycles, .Add, dt, .monotonic);
        _ = @atomicRmw(u64, &self.max, .Max, dt, .monotonic);
    }

    fn take(self: *Stat) Stat {
        return .{
            .count = @atomicRmw(u64, &self.count, .Xchg, 0, .monotonic),
            .cycles = @atomicRmw(u64, &self.cycles, .Xchg, 0, .monotonic),
            .max = @atomicRmw(u64, &self.max, .Xchg, 0, .monotonic),
        };
    }
};

var syscalls: [SLOTS]Stat = [_]Stat{.{}} ** SLOTS;
var faults: Stat = .{};

/// CPU time by what ran: a Linux program (user and kernel), an idle task,
/// anything else. Charged at each switch to the task switched away from.
const Ran = enum { linux, idle, other };
var ran_cycles: [@typeInfo(Ran).@"enum".fields.len]u64 = @splat(0);
var switch_tsc: [smp.MAX_CPUS]u64 = @splat(0);

/// schedule(), IF=0, about to switch CPU `cpu` away from `from` (0xFE: a
/// task that is dying).
pub fn noteSwitch(cpu: u8, from: u8) void {
    if (cpu >= smp.MAX_CPUS) return;
    const now_tsc = perf.rdtsc();
    const last = switch_tsc[cpu];
    switch_tsc[cpu] = now_tsc;
    if (last == 0) return;
    const ran: Ran = if (from >= process.MAX_PROCS) .other else if (process.procs[from].is_idle) .idle else if (process.procs[from].personality == .linux) .linux else .other;
    _ = @atomicRmw(u64, &ran_cycles[@intFromEnum(ran)], .Add, now_tsc -% last, .monotonic);
    if (ran == .other and from < process.MAX_PROCS) _ = @atomicRmw(u64, &other_cycles[from], .Add, now_tsc -% last, .monotonic);
}

/// The `.other` time per pid.
var other_cycles: [process.MAX_PROCS]u64 = @splat(0);

/// Time in each softirq handler, by vector.
var softirq_cycles: [8]u64 = @splat(0);

var softirq_calls: [8]u64 = @splat(0);

pub fn softirq(nr: u8, t0: u64) void {
    if (nr >= softirq_cycles.len) return;
    _ = @atomicRmw(u64, &softirq_cycles[nr], .Add, perf.rdtsc() -% t0, .monotonic);
    _ = @atomicRmw(u64, &softirq_calls[nr], .Add, 1, .monotonic);
}

/// Where timer ticks find Linux tasks: user mode, or which kernel function.
var tick_user: u64 = 0;
var tick_kernel: u64 = 0;
const TICK_FNS: usize = 512;
/// Open-addressed by function start; a slot's key is claimed with a CAS.
var tick_fn: [TICK_FNS]u64 = @splat(0);
var tick_fn_n: [TICK_FNS]u64 = @splat(0);

/// IRQ0, IF=0: the tick interrupted `pid` at `rip` with code segment `cs`.
pub fn tick(pid: ?usize, rip: u64, cs: u64) void {
    const p = pid orelse return;
    if (p >= process.MAX_PROCS or process.procs[p].personality != .linux) return;
    if (cs & 3 == 3) {
        _ = @atomicRmw(u64, &tick_user, .Add, 1, .monotonic);
        return;
    }
    _ = @atomicRmw(u64, &tick_kernel, .Add, 1, .monotonic);
    const r = symbols.resolveKernel(rip) orelse return;
    const f = rip - r.offset;
    var i: usize = @intCast((f >> 4) % TICK_FNS);
    var probes: usize = 0;
    while (probes < TICK_FNS) : (probes += 1) {
        const k = @atomicLoad(u64, &tick_fn[i], .monotonic);
        if (k == f or (k == 0 and (@cmpxchgStrong(u64, &tick_fn[i], 0, f, .monotonic, .monotonic) == null or @atomicLoad(u64, &tick_fn[i], .monotonic) == f))) {
            _ = @atomicRmw(u64, &tick_fn_n[i], .Add, 1, .monotonic);
            return;
        }
        i = (i + 1) % TICK_FNS;
    }
}

/// How futex calls end.
pub const FutexEnd = enum { wait_woke, wait_changed, wait_timed_out, wake_some, wake_none };
var futex_ends: [@typeInfo(FutexEnd).@"enum".fields.len]u64 = @splat(0);

pub fn futex(e: FutexEnd) void {
    _ = @atomicRmw(u64, &futex_ends[@intFromEnum(e)], .Add, 1, .monotonic);
}

pub inline fn now() u64 {
    return perf.rdtsc();
}

pub fn syscall(num: u32, t0: u64) void {
    if (num >= SLOTS) return;
    syscalls[num].add(perf.rdtsc() -% t0);
}

pub fn fault(t0: u64) void {
    faults.add(perf.rdtsc() -% t0);
}

fn us(cycles: u64) u64 {
    const per_q = apic.tscPerQuantumSane();
    if (per_q == 0) return 0;
    return cycles * 10_000 / per_q;
}

fn name(num: usize) []const u8 {
    return switch (num) {
        0 => "read",
        1 => "write",
        3 => "close",
        8 => "lseek",
        9 => "mmap",
        10 => "mprotect",
        11 => "munmap",
        12 => "brk",
        17 => "pread64",
        18 => "pwrite64",
        19 => "readv",
        20 => "writev",
        25 => "mremap",
        28 => "madvise",
        56 => "clone",
        72 => "fcntl",
        73 => "flock",
        77 => "ftruncate",
        79 => "getcwd",
        202 => "futex",
        217 => "getdents64",
        257 => "openat",
        258 => "mkdirat",
        262 => "newfstatat",
        263 => "unlinkat",
        264 => "renameat",
        295 => "preadv",
        296 => "pwritev",
        316 => "renameat2",
        326 => "copy_file_range",
        332 => "statx",
        else => "?",
    };
}

/// dumpAndReset's copy; 12 KB is too much for a kernel task's stack.
var snap: [SLOTS]Stat = undefined;
var last_io_calls: u64 = 0;
var last_io_wait: u64 = 0;
var last_bc: ext2_block.Stats = .{};
var last_klog_bytes: u64 = 0;

/// Zero everything without printing. One caller at a time.
pub fn reset() void {
    quiet = true;
    defer quiet = false;
    dumpAndReset("");
}

var quiet = false;

fn out(comptime fmt: []const u8, args: anytype) void {
    if (!quiet) serial.print(fmt, args);
}

/// Print the table (busiest first) and zero it. One caller at a time.
pub noinline fn dumpAndReset(label: []const u8) void {
    var total: u64 = 0;
    for (&snap, &syscalls) |*d, *s| {
        d.* = s.take();
        total += d.cycles;
    }
    const pf = faults.take();
    out("[lprof] {s}: syscalls {d} us total, page faults {d} in {d} us (max {d} us)\n", .{ label, us(total), pf.count, us(pf.cycles), us(pf.max) });
    const io_calls = nvme.io_call_count -% last_io_calls;
    const io_wait = nvme.io_wait_cycles -% last_io_wait;
    last_io_calls = nvme.io_call_count;
    last_io_wait = nvme.io_wait_cycles;
    out("[lprof]   nvme: {d} commands, wait {d} us, avg {d} us, max {d} us\n", .{ io_calls, us(io_wait), if (io_calls == 0) 0 else us(io_wait / io_calls), us(nvme.io_max_wait_cycles) });
    nvme.io_max_wait_cycles = 0;
    var rc: [ran_cycles.len]u64 = undefined;
    for (&rc, &ran_cycles) |*d, *s| d.* = @atomicRmw(u64, s, .Xchg, 0, .monotonic);
    out("[lprof]   cpu time: linux {d} us, idle {d} us, other {d} us\n", .{ us(rc[0]), us(rc[1]), us(rc[2]) });
    for (&other_cycles, 0..) |*c, pid| {
        const v = @atomicRmw(u64, c, .Xchg, 0, .monotonic);
        if (us(v) < 10_000) continue;
        const p = &process.procs[pid];
        out("[lprof]     other: pid {d} {s}: {d} us\n", .{ pid, p.name[0..p.name_len], us(v) });
    }
    const tu = @atomicRmw(u64, &tick_user, .Xchg, 0, .monotonic);
    const tk = @atomicRmw(u64, &tick_kernel, .Xchg, 0, .monotonic);
    out("[lprof]   ticks: user {d}, kernel {d}\n", .{ tu, tk });
    var shown_fns: u32 = 0;
    while (shown_fns < 12) : (shown_fns += 1) {
        var best: usize = TICK_FNS;
        for (&tick_fn_n, 0..) |*n, i| {
            if (n.* == 0) continue;
            if (best == TICK_FNS or n.* > tick_fn_n[best]) best = i;
        }
        if (best == TICK_FNS) break;
        const fname = if (symbols.resolveKernel(tick_fn[best])) |r| r.name else "?";
        out("[lprof]     tick in {s}: {d}\n", .{ fname, tick_fn_n[best] });
        tick_fn_n[best] = 0;
    }
    for (&tick_fn, &tick_fn_n) |*k, *n| {
        k.* = 0;
        n.* = 0;
    }
    var sc: [softirq_cycles.len]u64 = undefined;
    for (&sc, &softirq_cycles) |*d, *s| d.* = @atomicRmw(u64, s, .Xchg, 0, .monotonic);
    const klog_bytes = serial.drained_bytes -% last_klog_bytes;
    last_klog_bytes = serial.drained_bytes;
    var scn: [softirq_calls.len]u64 = undefined;
    for (&scn, &softirq_calls) |*d, *s| d.* = @atomicRmw(u64, s, .Xchg, 0, .monotonic);
    out("[lprof]   softirq: nvme {d} us/{d}, gpu {d} us/{d}, hid {d} us/{d}, klog {d} us/{d} ({d} bytes), perf {d} us\n", .{ us(sc[0]), scn[0], us(sc[1]), scn[1], us(sc[2]), scn[2], us(sc[3]), scn[3], klog_bytes, us(sc[4]) });
    var fe: [futex_ends.len]u64 = undefined;
    for (&fe, &futex_ends) |*d, *s| d.* = @atomicRmw(u64, s, .Xchg, 0, .monotonic);
    out("[lprof]   futex: wait woke {d}, changed {d}, timed out {d}; wake some {d}, none {d}\n", .{ fe[0], fe[1], fe[2], fe[3], fe[4] });
    const bc = ext2_block.stats();
    out("[lprof]   ext2 cache: {d} buffers ({d} dirty), {d} hits, {d} misses, {d} blocks read, {d} blocks flushed in {d} commands\n", .{ bc.live, bc.dirty, bc.hits -% last_bc.hits, bc.misses -% last_bc.misses, bc.read_blocks -% last_bc.read_blocks, bc.flushed_blocks -% last_bc.flushed_blocks, bc.flush_cmds -% last_bc.flush_cmds });
    last_bc = bc;
    var shown: u32 = 0;
    while (shown < 24) : (shown += 1) {
        var best: usize = SLOTS;
        for (&snap, 0..) |*s, i| {
            if (s.count == 0) continue;
            if (best == SLOTS or s.cycles > snap[best].cycles) best = i;
        }
        if (best == SLOTS) break;
        const s = snap[best];
        out("[lprof]   {s}#{d}: {d} calls, {d} us, avg {d} us, max {d} us\n", .{ name(best), best, s.count, us(s.cycles), us(s.cycles / s.count), us(s.max) });
        snap[best].count = 0;
    }
}
