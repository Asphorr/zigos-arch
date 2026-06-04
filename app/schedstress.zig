// schedstress — userspace SMP scheduler stress harness.
//
// WHY: the "10-hour" scheduler symptom in serial.log turned out to be HOST
// vCPU pauses (nested virt) mislabeled "OURS at schedule" by the old [smi]
// heuristic — NOT a guest bug, and not reproducible from inside the guest
// (the classifier in src/time/smi.zig was fixed to tell the two apart).
// This harness does the complementary thing: it pounds the EXACT race
// surface inside schedule()/blockOn so that if a *real* latent guest
// scheduler bug exists (a lost wakeup, an rqEnter/rqLeave accounting drift,
// a dispatch-vs-teardown race, or a CAS-pick / cross-CPU-wake livelock) it
// surfaces in minutes of max-rate churn instead of ~10h of light load.
//
// STRATEGY — run a CONCURRENT MIX (maximum interleaving diversity) of:
//   yield-storm   tight yield() loops            → peak schedule() call rate
//   herd          N threads park on ONE Cond;    → thundering-herd cross-CPU
//                 a driver broadcasts ~every     wake races — the exact
//                 HERD_BROADCAST_US              .sleeping→.ready+rqEnter vs
//                                                picker rqLeave race that
//                                                sched.zig:1394 documents
//   ping-pong     thread pairs pass a token      → 1:1 block/wake handoff,
//                 back & forth via two Sems      frequently cross-CPU
//   sleeper-storm many tiny randomized usleep()  → hrtimer/sleeper-queue churn
//   thread-churn  create→exit→join in a loop     → PCB slot + per-CPU rq reuse
//                                                + cross-CPU thread teardown
//   proc-churn    main forks a do-nothing child  → process create/destroy +
//                 (opt-in)  → child exits → reap   reap path
//
// ORACLE = the kernel's own detectors (rqAudit drift, the P4 base-of-kstack
// canaries, pcb_invariants, the watchdog, and the now-corroborated [smi]
// OURS verdict) PLUS this harness's monitor thread: a per-pool progress
// heartbeat to serial.log every HEARTBEAT_MS. Two failure signatures:
//   * heartbeats STOP entirely  → the scheduler wedged (the monitor itself
//                                  got starved) — the smoking gun, timestamped.
//   * one pool flatlines while   → that pool hit a lost wakeup / stuck-blocked
//     others keep moving           bug (e.g. a herd waiter that missed a
//                                  broadcast and never re-ran).
//
// Tunables are consts below. DURATION_MS = 0 runs until killed. This app is
// NOT auto-launched — run `schedstress` from the shell when you want to hunt.

const std = @import("std");
const libc = @import("libc");

// ----------------------------- tunables ------------------------------------
// THREAD BUDGET: the real ceiling is NOT MAX_PROCS (global PCB slots, now 64)
// — it's MAX_LAZY_REGIONS (config.zig), the per-process VMA table. Every
// pthread stack is its own mmap region in the shared address space
// (pthreadCreate → mmap → procs[tgid].lazy_regions), so a process holds only
// (MAX_LAZY_REGIONS − ~5 base regions: 3 ELF segments + main stack + heap)
// live threads. At MAX_LAZY_REGIONS=16 that was 11 — this harness's churn/
// sleeper/yielder pools silently failed to spawn (pthreadCreate → null; the
// unspawned PCB slots stayed .unused, so it LOOKED like slot exhaustion but
// never was). Raised to 32 → ~27 threads/proc. Defaults below total ~15
// worker threads + main + monitor ≈ 18 tasks → ~16 regions + ~5 base = 21,
// comfortably under 32. Bump pool sizes (and MAX_LAZY_REGIONS to match) for a
// heavier mix.
const DURATION_MS: u64 = 300_000; // 5 min bounded run (clean summary + exit); set 0 to run until killed, or bump way up for an overnight hunt
const HEARTBEAT_MS: u32 = 500;
const N_YIELDERS: usize = 2;
const N_HERD: usize = 4;
const HERD_BROADCAST_US: u32 = 800;
const N_PP_PAIRS: usize = 2;
const N_SLEEPERS: usize = 2;
const N_CHURNERS: usize = 1;
// proc-churn forks from the (multi-threaded) main thread. The child does
// NOTHING but exit — it never touches a mutex another thread might hold — so
// it's safe, but it does lean on fork-from-threaded-parent support. Default
// off so the thread-only mix is the clean baseline; flip on to add process
// create/teardown pressure.
const ENABLE_PROC_CHURN: bool = false;

// --------------------------- run flag + counters ---------------------------
var g_run: u32 = 1;
inline fn running() bool {
    return @atomicLoad(u32, &g_run, .acquire) != 0;
}
inline fn bump(p: *u64) void {
    _ = @atomicRmw(u64, p, .Add, 1, .monotonic);
}
inline fn load(p: *u64) u64 {
    return @atomicLoad(u64, p, .monotonic);
}

var c_yield: u64 = 0;
var c_herd: u64 = 0;
var c_pp: u64 = 0;
var c_sleep: u64 = 0;
var c_churn: u64 = 0;
var c_proc: u64 = 0;
var c_createfail: u64 = 0;

// How many threads each pool ACTUALLY got (≤ requested if we hit the slot
// cap). The monitor only flatline-warns about a pool that has live threads —
// otherwise "0 progress" would false-fire on a pool that simply never spawned.
var n_yield: usize = 0;
var n_herd: usize = 0;
var n_pp: usize = 0;
var n_sleep: usize = 0;
var n_churn: usize = 0;

// -------------------------------- herd -------------------------------------
var herd_mu: libc.Mutex = .{};
var herd_cv: libc.Cond = .{};
var herd_gen: u64 = 0; // generation; a waiter re-runs each time this advances

fn herdWaiter(_: ?*anyopaque) callconv(.c) ?*anyopaque {
    var seen: u64 = 0;
    while (running()) {
        herd_mu.lock();
        // Predicate loop keyed on a GENERATION counter, not a bare flag: even
        // if a broadcast is missed, the waiter still observes herd_gen moved
        // and proceeds — so a stuck herd pool is a KERNEL lost-wakeup, never a
        // harness artifact.
        while (running() and herd_gen == seen) herd_cv.wait(&herd_mu);
        seen = herd_gen;
        herd_mu.unlock();
        bump(&c_herd);
    }
    return null;
}

fn herdDriver(_: ?*anyopaque) callconv(.c) ?*anyopaque {
    while (running()) {
        libc.usleep(HERD_BROADCAST_US);
        herd_mu.lock();
        herd_gen +%= 1;
        herd_cv.broadcast(); // wake ALL waiters at once → the thundering herd
        herd_mu.unlock();
    }
    // Shutdown kick so any still-parked waiter wakes, sees !running, exits.
    herd_mu.lock();
    herd_gen +%= 1;
    herd_cv.broadcast();
    herd_mu.unlock();
    return null;
}

// ------------------------------ ping-pong ----------------------------------
// Two sems per pair: left waits A / posts B; right waits B / posts A. One
// kickoff post on A starts the loop. A token bounces forever → a continuous
// stream of block/wake handoffs the kernel often splits across both CPUs.
var pp_a: [N_PP_PAIRS]libc.Sem = .{libc.Sem{}} ** N_PP_PAIRS;
var pp_b: [N_PP_PAIRS]libc.Sem = .{libc.Sem{}} ** N_PP_PAIRS;

fn ppLeft(arg: ?*anyopaque) callconv(.c) ?*anyopaque {
    const i: usize = @intFromPtr(arg);
    while (running()) {
        pp_a[i].wait();
        if (!running()) break;
        pp_b[i].post();
        bump(&c_pp);
    }
    return null;
}
fn ppRight(arg: ?*anyopaque) callconv(.c) ?*anyopaque {
    const i: usize = @intFromPtr(arg);
    while (running()) {
        pp_b[i].wait();
        if (!running()) break;
        pp_a[i].post();
    }
    return null;
}

// ------------------------------- sleeper -----------------------------------
fn sleeper(arg: ?*anyopaque) callconv(.c) ?*anyopaque {
    var x: u32 = @truncate(@intFromPtr(arg) *% 2654435761 +% 1); // per-thread seed
    while (running()) {
        x = x *% 1103515245 +% 12345; // LCG — no shared RNG, no syscall needed
        const us: u32 = 40 + (x >> 16) % 460; // 40..499 µs
        libc.usleep(us);
        bump(&c_sleep);
    }
    return null;
}

// ----------------------------- thread churn --------------------------------
fn churnBody(_: ?*anyopaque) callconv(.c) ?*anyopaque {
    return null; // exists only to be created and immediately torn down
}
fn churner(_: ?*anyopaque) callconv(.c) ?*anyopaque {
    while (running()) {
        const t = libc.pthreadCreate(churnBody, null);
        if (t) |tt| {
            _ = libc.pthreadJoin(tt);
            bump(&c_churn);
        } else {
            bump(&c_createfail); // slot exhaustion / leak signal
            libc.usleep(300);
        }
    }
    return null;
}

// ------------------------------- yielder -----------------------------------
fn yielder(_: ?*anyopaque) callconv(.c) ?*anyopaque {
    while (running()) {
        libc.yield();
        bump(&c_yield);
    }
    return null;
}

// ------------------------------- monitor -----------------------------------
fn monitor(_: ?*anyopaque) callconv(.c) ?*anyopaque {
    var elapsed: u64 = 0;
    var p_yield: u64 = 0;
    var p_herd: u64 = 0;
    var p_pp: u64 = 0;
    var p_sleep: u64 = 0;
    var p_churn: u64 = 0;
    var p_proc: u64 = 0;
    var buf: [256]u8 = undefined;
    while (true) {
        libc.sleep(HEARTBEAT_MS);
        elapsed +%= HEARTBEAT_MS;

        const y = load(&c_yield);
        const h = load(&c_herd);
        const pp = load(&c_pp);
        const sl = load(&c_sleep);
        const ch = load(&c_churn);
        const pr = load(&c_proc);
        const cf = load(&c_createfail);

        const line = std.fmt.bufPrint(&buf, "[schedstress] t={d}ms d:yield={d} herd={d} pp={d} sleep={d} churn={d} proc={d} | cfail={d}\n", .{
            elapsed, y -% p_yield, h -% p_herd, pp -% p_pp, sl -% p_sleep, ch -% p_churn, pr -% p_proc, cf,
        }) catch "[schedstress] hb\n";
        libc.klog(line);

        // Per-pool flatline flags. Every pool should advance every interval on
        // a healthy scheduler; a 0 delta while OTHER pools move = a stuck pool
        // (lost wakeup / never-redispatched). Whole-system wedge shows as the
        // heartbeat simply STOPPING (this thread can't run either).
        // Atomic loads so the optimizer can't hoist a stale 0 from before main
        // finished spawning (we run concurrently with the spawn loop).
        if (@atomicLoad(usize, &n_yield, .acquire) > 0 and y == p_yield) libc.klog("[schedstress] WARN yield pool 0 progress\n");
        if (@atomicLoad(usize, &n_herd, .acquire) > 0 and h == p_herd) libc.klog("[schedstress] WARN herd pool 0 wakes (lost wakeup?)\n");
        if (@atomicLoad(usize, &n_pp, .acquire) > 0 and pp == p_pp) libc.klog("[schedstress] WARN pingpong 0 hops (stuck handoff?)\n");
        if (@atomicLoad(usize, &n_sleep, .acquire) > 0 and sl == p_sleep) libc.klog("[schedstress] WARN sleeper pool 0 progress (timer-wake stuck?)\n");
        if (@atomicLoad(usize, &n_churn, .acquire) > 0 and ch == p_churn) libc.klog("[schedstress] WARN thread-churn 0 progress\n");

        p_yield = y;
        p_herd = h;
        p_pp = pp;
        p_sleep = sl;
        p_churn = ch;
        p_proc = pr;

        if (DURATION_MS != 0 and elapsed >= DURATION_MS) break;
    }
    @atomicStore(u32, &g_run, 0, .release);
    libc.klog("[schedstress] monitor: duration reached, draining workers\n");
    return null;
}

// --------------------------------- main ------------------------------------
fn joinAll(arr: []?*libc.Tcb) void {
    for (arr) |t| {
        if (t) |tt| _ = libc.pthreadJoin(tt);
    }
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    libc.print("[schedstress] starting concurrent scheduler stress mix\n");
    libc.klog("[schedstress] START (yield+herd+pingpong+sleeper+churn)\n");

    var i: usize = 0;
    while (i < N_PP_PAIRS) : (i += 1) {
        pp_a[i].init(0);
        pp_b[i].init(0);
    }

    var yld: [N_YIELDERS]?*libc.Tcb = .{null} ** N_YIELDERS;
    var hrd: [N_HERD]?*libc.Tcb = .{null} ** N_HERD;
    var ppl: [N_PP_PAIRS]?*libc.Tcb = .{null} ** N_PP_PAIRS;
    var ppr: [N_PP_PAIRS]?*libc.Tcb = .{null} ** N_PP_PAIRS;
    var slp: [N_SLEEPERS]?*libc.Tcb = .{null} ** N_SLEEPERS;
    var chn: [N_CHURNERS]?*libc.Tcb = .{null} ** N_CHURNERS;

    // Monitor FIRST so it's guaranteed a scheduler slot — it owns the
    // heartbeat (the liveness oracle) and the duration clock. Driver next.
    const mon = libc.pthreadCreate(monitor, null);
    if (mon == null) libc.klog("[schedstress] WARN monitor failed to spawn — no heartbeat oracle!\n");
    const driver = libc.pthreadCreate(herdDriver, null);

    // Spawn order = race-value priority. Under MAX_PROCS=32 pressure the LAST
    // pools lose their slots, so the highest-value race surfaces go FIRST and
    // the yielders (raw schedule rate, intra-CPU, lowest race value) are the
    // sacrificial pool. churn (PCB-slot reuse + teardown-vs-dispatch — the
    // accumulation surface a long-uptime wedge would live in) was getting 0
    // slots under the old yield-first order; now it leads.
    var got: usize = 0;
    i = 0;
    while (i < N_CHURNERS) : (i += 1) {
        chn[i] = libc.pthreadCreate(churner, null);
        if (chn[i] != null) got += 1 else bump(&c_createfail);
    }
    @atomicStore(usize, &n_churn, got, .release);
    got = 0;
    i = 0;
    while (i < N_HERD) : (i += 1) {
        hrd[i] = libc.pthreadCreate(herdWaiter, null);
        if (hrd[i] != null) got += 1 else bump(&c_createfail);
    }
    @atomicStore(usize, &n_herd, got, .release);
    got = 0;
    i = 0;
    while (i < N_PP_PAIRS) : (i += 1) {
        ppl[i] = libc.pthreadCreate(ppLeft, @ptrFromInt(@as(usize, i)));
        ppr[i] = libc.pthreadCreate(ppRight, @ptrFromInt(@as(usize, i)));
        if (ppl[i] != null and ppr[i] != null) {
            got += 1; // one fully-live pair
            pp_a[i].post(); // kick the token into motion
        } else {
            if (ppl[i] == null) bump(&c_createfail);
            if (ppr[i] == null) bump(&c_createfail);
        }
    }
    @atomicStore(usize, &n_pp, got, .release);
    got = 0;
    i = 0;
    while (i < N_SLEEPERS) : (i += 1) {
        slp[i] = libc.pthreadCreate(sleeper, @ptrFromInt(@as(usize, i +% 1)));
        if (slp[i] != null) got += 1 else bump(&c_createfail);
    }
    @atomicStore(usize, &n_sleep, got, .release);
    got = 0;
    i = 0;
    while (i < N_YIELDERS) : (i += 1) {
        yld[i] = libc.pthreadCreate(yielder, null);
        if (yld[i] != null) got += 1 else bump(&c_createfail);
    }
    @atomicStore(usize, &n_yield, got, .release);

    {
        var sbuf: [192]u8 = undefined;
        const sline = std.fmt.bufPrint(&sbuf, "[schedstress] spawned yield={d} herd={d} pp-pairs={d} sleep={d} churn={d} driver={d} mon={d} cfail={d}\n", .{
            @atomicLoad(usize, &n_yield, .acquire),  @atomicLoad(usize, &n_herd, .acquire),
            @atomicLoad(usize, &n_pp, .acquire),     @atomicLoad(usize, &n_sleep, .acquire),
            @atomicLoad(usize, &n_churn, .acquire),  @as(u8, if (driver != null) 1 else 0),
            @as(u8, if (mon != null) 1 else 0),      load(&c_createfail),
        }) catch "[schedstress] spawned\n";
        libc.print(sline);
        libc.klog(sline);
    }

    // Main thread: optional process-level churn, else just idle until the
    // monitor clears g_run (the workers do all the real stress).
    if (ENABLE_PROC_CHURN) {
        while (running()) {
            const pid = libc.fork();
            if (pid == 0) {
                libc.exitWith(0x5A); // child: nothing but exit — touches no inherited lock
            } else if (pid == 0xFFFFFFFA) {
                bump(&c_createfail); // EAGAIN: proc-slot pressure
                libc.usleep(500);
            } else {
                var st: u32 = 0;
                _ = libc.waitpid(pid, &st);
                bump(&c_proc);
            }
        }
    } else {
        while (running()) libc.sleep(50);
    }

    // Shutdown: g_run is already 0. Release every blocked worker so the joins
    // below can complete. (Driver also broadcasts on its way out; belt+braces.)
    herd_mu.lock();
    herd_gen +%= 1;
    herd_cv.broadcast();
    herd_mu.unlock();
    i = 0;
    while (i < N_PP_PAIRS) : (i += 1) {
        pp_a[i].post();
        pp_b[i].post();
    }

    joinAll(yld[0..]);
    joinAll(hrd[0..]);
    joinAll(ppl[0..]);
    joinAll(ppr[0..]);
    joinAll(slp[0..]);
    joinAll(chn[0..]);
    if (driver) |t| _ = libc.pthreadJoin(t);
    if (mon) |t| _ = libc.pthreadJoin(t);

    var buf: [256]u8 = undefined;
    const sum = std.fmt.bufPrint(&buf, "[schedstress] DONE yield={d} herd={d} pp={d} sleep={d} churn={d} proc={d} cfail={d}\n", .{
        load(&c_yield), load(&c_herd), load(&c_pp), load(&c_sleep), load(&c_churn), load(&c_proc), load(&c_createfail),
    }) catch "[schedstress] DONE\n";
    libc.print(sum);
    libc.klog(sum);
    libc.exit();
}
