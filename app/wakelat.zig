// wakelat — wake-latency bench. usleep overshoot and futex ping-pong round
// trips, on idle CPUs and with a spinner on the woken thread's CPU.
// Results go to the terminal and to serial as "[wakelat-app] ...".

const std = @import("std");
const libc = @import("libc");

const N_SLEEP: usize = 100;
const N_PP: usize = 400;

var per_us: u64 = 1;
var samples: [N_PP]u32 = undefined;

fn rdtsc() u64 {
    var lo: u32 = undefined;
    var hi: u32 = undefined;
    asm volatile ("rdtsc"
        : [lo] "={eax}" (lo),
          [hi] "={edx}" (hi),
    );
    return @as(u64, lo) | (@as(u64, hi) << 32);
}

fn out(comptime fmt: []const u8, args: anytype) void {
    var buf: [200]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, "[wakelat-app] " ++ fmt ++ "\n", args) catch return;
    libc.print(s);
    libc.klog(s);
}

fn usSince(t0: u64) u32 {
    return @intCast(@min((rdtsc() -% t0) / per_us, std.math.maxInt(u32)));
}

fn calibrate() void {
    const t0 = libc.gettimeofday();
    const c0 = rdtsc();
    while (true) {
        const t = libc.gettimeofday();
        const us = (t.sec -% t0.sec) * 1_000_000 + t.usec -% t0.usec;
        if (us >= 100_000) {
            per_us = @max(1, (rdtsc() -% c0) / us);
            return;
        }
    }
}

fn report(name: []const u8, s: []u32) void {
    std.mem.sort(u32, s, {}, std.sort.asc(u32));
    var sum: u64 = 0;
    for (s) |v| sum += v;
    out("{s}: n={d} avg={d}us p50={d} p90={d} p99={d} max={d}", .{
        name,         s.len,             sum / s.len,
        s[s.len / 2], s[s.len * 9 / 10], s[s.len * 99 / 100],
        s[s.len - 1],
    });
}

// ------------------------------------------------------------------ spinner
var spin_run: u32 = 0;
var spin_cpu: i32 = 0;

fn spinner(_: ?*anyopaque) callconv(.c) ?*anyopaque {
    _ = libc.sched_setaffinity(0, spin_cpu);
    libc.yield();
    while (@atomicLoad(u32, &spin_run, .acquire) != 0) asm volatile ("pause");
    return null;
}

fn startSpinner(cpu: i32) ?*libc.Tcb {
    spin_cpu = cpu;
    @atomicStore(u32, &spin_run, 1, .release);
    const t = libc.pthreadCreate(spinner, null) orelse return null;
    libc.usleep(20_000);
    return t;
}

fn stopSpinner(t: ?*libc.Tcb) void {
    @atomicStore(u32, &spin_run, 0, .release);
    if (t) |tt| _ = libc.pthreadJoin(tt);
}

// ------------------------------------------------------------------- usleep
var sleep_cpu: i32 = 0;
var sleep_us: u32 = 0;
var sleep_name: []const u8 = "";

fn sleeper(_: ?*anyopaque) callconv(.c) ?*anyopaque {
    _ = libc.sched_setaffinity(0, sleep_cpu);
    libc.yield();
    for (samples[0..N_SLEEP]) |*s| {
        const t0 = rdtsc();
        libc.usleep(sleep_us);
        s.* = usSince(t0) -| sleep_us;
    }
    report(sleep_name, samples[0..N_SLEEP]);
    return null;
}

fn sleepTest(name: []const u8, cpu: i32, us: u32) void {
    sleep_cpu = cpu;
    sleep_us = us;
    sleep_name = name;
    const t = libc.pthreadCreate(sleeper, null) orelse return out("{s}: thread create failed", .{name});
    _ = libc.pthreadJoin(t);
}

// ---------------------------------------------------------------- ping-pong
var sem_a: libc.Sem = .{};
var sem_b: libc.Sem = .{};
var pp_cpu_l: i32 = 0;
var pp_cpu_r: i32 = 0;

fn ppRight(_: ?*anyopaque) callconv(.c) ?*anyopaque {
    _ = libc.sched_setaffinity(0, pp_cpu_r);
    libc.yield();
    for (0..N_PP) |_| {
        sem_a.wait();
        sem_b.post();
    }
    return null;
}

fn ppLeft(_: ?*anyopaque) callconv(.c) ?*anyopaque {
    _ = libc.sched_setaffinity(0, pp_cpu_l);
    libc.yield();
    libc.usleep(20_000);
    for (&samples) |*s| {
        const t0 = rdtsc();
        sem_a.post();
        sem_b.wait();
        s.* = usSince(t0);
    }
    return null;
}

fn pingPong(name: []const u8, cpu_l: i32, cpu_r: i32) void {
    sem_a.init(0);
    sem_b.init(0);
    pp_cpu_l = cpu_l;
    pp_cpu_r = cpu_r;
    const r = libc.pthreadCreate(ppRight, null) orelse return out("{s}: thread create failed", .{name});
    const l = libc.pthreadCreate(ppLeft, null) orelse {
        // Let the right thread run its loop out before the next test
        // re-initialises the semaphores under it.
        for (0..N_PP) |_| sem_a.post();
        _ = libc.pthreadJoin(r);
        return out("{s}: thread create failed", .{name});
    };
    _ = libc.pthreadJoin(l);
    _ = libc.pthreadJoin(r);
    report(name, &samples);
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    calibrate();
    var stats: [8]libc.CpuStat = undefined;
    const n_cpu = libc.cpuStats(&stats);
    out("start: {d} cpus, {d} tsc/us", .{ n_cpu, per_us });
    if (n_cpu < 2 or n_cpu > stats.len) {
        out("needs at least 2 cpus", .{});
        libc.exitWith(1);
    }

    sleepTest("usleep 200 cpu1 idle", 1, 200);
    sleepTest("usleep 1000 cpu1 idle", 1, 1000);
    sleepTest("usleep 3000 cpu1 idle", 1, 3000);
    sleepTest("usleep 1000 cpu0", 0, 1000);

    pingPong("pingpong rtt same cpu1", 1, 1);
    pingPong("pingpong rtt cpu0<->cpu1", 0, 1);

    const sp = startSpinner(1);
    sleepTest("usleep 1000 cpu1 +spinner", 1, 1000);
    pingPong("pingpong rtt cpu0<->cpu1 +spinner on cpu1", 0, 1);
    stopSpinner(sp);

    out("done", .{});
    libc.exitWith(0);
}
