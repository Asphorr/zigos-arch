// Cross-CPU hang detector.
//
// Each CPU bumps `cpu.irq_tick_count` on every IRQ0. From its own IRQ0
// handler, every WATCHDOG_CHECK_INTERVAL ticks (~1s), each CPU samples its
// "next" peer's tick. If the peer hasn't advanced in WATCHDOG_STRIKES
// consecutive checks (~3s), the peer is wedged — kernel running with cli
// held in a tight loop, no log output, no heartbeats. Trigger a
// panic-style autopsy: set kdbg.nmi_halt_after_snapshot, broadcast NMI to
// dump all CPU snapshots, then halt.
//
// Why peer-watch instead of self-check: self-check is tautological — if
// you can run the check, your timer fires, so you're not wedged. Only a
// different CPU can detect that THIS CPU has stopped progressing.
//
// Coverage caveats:
//   - 2-CPU system: cpu0 watches cpu1 and vice versa. If both wedge in the
//     same window, no detection. Vanishingly rare in practice.
//   - APs in TSC-deadline idle may have very long inter-IRQ gaps (deadline
//     set to next sleeper expiry). We DON'T treat that as a wedge — the
//     check only fires from BSP, which has reliable 100 Hz IRQ0. So in
//     practice BSP detects wedged APs; APs detect wedged BSP only when
//     they happen to wake (which is "soon enough" for our purposes).
//
// Reproducer (manual): drop `asm volatile ("cli; 1: jmp 1b");` in any
// fuzzer-reachable syscall path. Within ~3s, the watchdog fires from the
// other CPU and dumps state.

const smp = @import("../cpu/smp.zig");
const serial = @import("serial.zig");
const kdbg = @import("kdbg.zig");
const apic = @import("../time/apic.zig");

/// Ticks between peer checks. 100 Hz IRQ0 × 100 ticks = 1 second.
const WATCHDOG_CHECK_INTERVAL: u64 = 100;
/// Consecutive missed checks before we SUSPECT a wedge (~3s frozen).
const WATCHDOG_STRIKES: u8 = 3;
/// Once suspect, how many more 1s windows we wait for the peer's tick to
/// RESUME before declaring a genuine wedge and halting. A host vCPU pause /
/// long SMI / live-migration stall always resumes once the host reschedules
/// us; only a real cli-wedge stays frozen. Generous when the peer holds no
/// lock (host-pause very likely, system keeps running degraded meanwhile);
/// short when it holds a cli-lock (a real wedge there risks deadlock-
/// propagating to the watcher before it can autopsy).
const WATCHDOG_GRACE_FREE: u8 = 7; // ~10s total before halting a lockless freeze
const WATCHDOG_GRACE_LOCKED: u8 = 2; // ~5s total when a cli-lock is held

var armed: bool = false;
var fired: bool = false;

// Per-watcher host-pause discrimination state, indexed by the WATCHING cpu's
// id. Lives here rather than in CpuLocal because that struct's field layout is
// cache-line-sensitive (tss.rsp0 must not straddle a line — see the comptime
// check in smp.zig) and adding fields to it perturbs that. After a peer is
// frozen WATCHDOG_STRIKES checks we don't halt — we SUSPECT and watch whether
// its tick RESUMES (host vCPU pause / long SMI → always does) vs stays frozen
// (genuine cli-wedge → halt). suspect_tick = the frozen value we wait to move.
var wd_suspecting: [smp.MAX_CPUS]bool = [_]bool{false} ** smp.MAX_CPUS;
var wd_suspect_tick: [smp.MAX_CPUS]u64 = [_]u64{0} ** smp.MAX_CPUS;
var wd_suspect_age: [smp.MAX_CPUS]u8 = [_]u8{0} ** smp.MAX_CPUS;

/// Enable the watchdog. Call after smp.init() so peer CPUs exist. No-op
/// before that; the per-CPU tick fields default to 0, and a freshly-zeroed
/// peer would falsely register as "not advancing" on the first check.
pub fn arm() void {
    armed = true;
    serial.print("[watchdog] armed (interval={d} ticks, strikes={d})\n", .{ WATCHDOG_CHECK_INTERVAL, WATCHDOG_STRIKES });
}

/// Public read accessor — used by src/debug/diag.zig for the boot
/// manifest. Cheap; reads a plain bool that's set once at arm().
pub fn isArmed() bool {
    return armed;
}

/// Called from each CPU's handleIRQ0 after its own tick is bumped. Cheap
/// fast-path: most ticks return immediately on the modulo gate. The actual
/// peer read fires once per second per CPU.
pub fn peerCheck(self: *smp.CpuLocal) void {
    if (!armed or fired) return;
    if (self.irq_tick_count % WATCHDOG_CHECK_INTERVAL != 0) return;

    // Pick the peer to watch — round-robin to the next alive CPU. On a
    // 2-CPU system this just toggles cpu0↔cpu1.
    const peer = nextAlivePeer(self) orelse return;

    // False-positive guard: if peer is currently in its idle PCB AND
    // its runqueue is empty, it's legitimately not advancing —
    // TSC-deadline mode lets idle APs sleep until the next sleeper
    // expiry, which can be seconds or longer.
    //
    // BUT — "idle with a ready task on the rq" is the real wedge we
    // want to catch. That happens when setState(.ready) added a task
    // to the peer's runqueue but no wake-IPI fired, so the peer
    // stays in deep idle while work piles up. Symptom from the
    // 2026-05-16 session: cpu1 stuck at 0% with `nr_run=1 (i=1)`
    // and PID 3's event queue overflowing; OS kept running on cpu0
    // and watchdog never saw it as a wedge because the old guard
    // matched on idle_pid alone. Now we require an empty rq too.
    if (peer.current_pid != null and peer.idle_pid != null and
        peer.current_pid.? == peer.idle_pid.? and
        peer.runqueue.nr_runnable == 0)
    {
        self.watchdog_peer_last_tick = peer.irq_tick_count;
        self.watchdog_peer_strikes = 0;
        wd_suspecting[self.cpu_id] = false;
        wd_suspect_age[self.cpu_id] = 0;
        return;
    }

    const peer_tick = @atomicLoad(u64, &peer.irq_tick_count, .acquire);

    // ---- SUSPECT mode: we flagged this peer ~3s ago and are probing whether
    // it's a host vCPU pause (its tick will resume) or a real cli-wedge (it
    // never will). The tick-resume test is the only fully reliable
    // discriminator — a descheduled vCPU ALWAYS resumes once the host
    // reschedules it; a wedged CPU never does. (Same blind spot the [smi]
    // classifier had: "peer not ticking" ≠ "peer wedged".)
    if (wd_suspecting[self.cpu_id]) {
        if (peer_tick != wd_suspect_tick[self.cpu_id]) {
            const frozen_s: u32 = @as(u32, WATCHDOG_STRIKES) + wd_suspect_age[self.cpu_id];
            serial.print("[watchdog] cpu{d} RESUMED after ~{d}s frozen (tick advanced) — host vCPU pause / long SMI, NOT a guest wedge; not halting\n", .{ peer.cpu_id, frozen_s });
            wd_suspecting[self.cpu_id] = false;
            wd_suspect_age[self.cpu_id] = 0;
            self.watchdog_peer_last_tick = peer_tick;
            self.watchdog_peer_strikes = 0;
            return;
        }
        // Still frozen. Wait up to the grace window — shorter if the peer is
        // sitting on a cli-lock (a real wedge there can propagate to us).
        wd_suspect_age[self.cpu_id] +|= 1;
        const grace: u8 = if (@import("../proc/spinlock.zig").cpuHoldsAnyLock(peer.cpu_id))
            WATCHDOG_GRACE_LOCKED
        else
            WATCHDOG_GRACE_FREE;
        if (wd_suspect_age[self.cpu_id] < grace) return;
        // Never resumed through the full grace window → genuine wedge.
        // Race-free single-fire via CAS: first detector dumps, others bail.
        if (@cmpxchgStrong(bool, &fired, false, true, .acq_rel, .acquire) != null) return;
        fire(self, peer);
        return;
    }

    if (peer_tick != self.watchdog_peer_last_tick) {
        // Peer made progress since last check. Reset strikes.
        self.watchdog_peer_last_tick = peer_tick;
        self.watchdog_peer_strikes = 0;
        return;
    }

    // Peer's tick hasn't moved AND peer isn't in idle.
    self.watchdog_peer_strikes +|= 1;
    if (self.watchdog_peer_strikes < WATCHDOG_STRIKES) return;

    // ~3s frozen. DON'T halt yet — a host vCPU pause looks identical here.
    // Enter SUSPECT; the resume probe above decides on the next checks.
    wd_suspecting[self.cpu_id] = true;
    wd_suspect_tick[self.cpu_id] = peer_tick;
    wd_suspect_age[self.cpu_id] = 0;
    const locked = @import("../proc/spinlock.zig").cpuHoldsAnyLock(peer.cpu_id);
    serial.print("\n[watchdog] cpu{d} tick frozen ~{d}s (holds_lock={any}) — probing host-pause vs wedge before halting\n", .{ peer.cpu_id, WATCHDOG_STRIKES, locked });
    // Name what the frozen peer is spinning on RIGHT NOW. Catches the
    // unregistered setstate_locks[]/rq.lock contention even on a freeze that
    // later RESUMES — so we get the lock without needing a hard watchdog halt
    // (which only fires on the minority of bursts that don't self-recover). A
    // spin_target of 0 here also discriminates a genuine host-pause (peer
    // descheduled, not spinning) from a cli-spin livelock.
    @import("../proc/spinlock.zig").dumpSpinTargets();
    // Claim-loop retry counts too — caught even on a freeze that later
    // self-recovers, so we get the Mode-A signature without needing a hard halt.
    @import("../proc/sched.zig").dumpSchedLoopStats();
}

fn nextAlivePeer(self: *smp.CpuLocal) ?*smp.CpuLocal {
    var i: usize = 1;
    while (i < smp.MAX_CPUS) : (i += 1) {
        const idx = (self.cpu_id + i) % smp.MAX_CPUS;
        const peer = &smp.cpus[idx];
        if (peer.alive) return peer;
    }
    return null;
}

fn fire(self: *smp.CpuLocal, peer: *smp.CpuLocal) void {
    // Pin the wedge BEFORE halting peers: RIP-sample the stuck CPU via NMI (it
    // IRETs back after each sample) to locate the spin loop. LBR would be ideal
    // but it's masked under nested virt; this histogram is the substitute. MUST
    // run before nmi_halt_after_snapshot is set below — once that's set, the
    // first sample NMI would halt the target instead of returning it for
    // re-sampling.
    kdbg.profileWedgedCpu(@as(u32, peer.lapic_id), 32);

    // FIRST broadcast NMI with halt-after so peers stop running BEFORE we
    // print the autopsy. Otherwise the wedge log byte-interleaves with
    // whatever the peer was klog'ing (slow-sc, perf, etc.) and the
    // crash summary becomes illegible — exactly what we saw in the
    // 2026-05-16 wallpaper/paint wedge. The peer's own snapshot still
    // gets dumped via nmiSnapshot before it halts, just on top of the
    // critical section we'll claim below.
    kdbg.nmi_halt_after_snapshot = true;
    kdbg.broadcastNMI();

    serial.print("\n!!! WATCHDOG: cpu{d} wedged !!! (last tick=0x{X}, observed unchanged for ~{d}s by cpu{d})\n", .{
        peer.cpu_id,
        self.watchdog_peer_last_tick,
        WATCHDOG_STRIKES,
        self.cpu_id,
    });

    // Same shape as a real panic: persist crash hint to NVRAM, dump
    // crashSummary. Peers are already halted by the NMI above so the
    // output below has exclusive serial-port access.
    {
        const nvram = @import("../boot/uefi_nvram.zig");
        const bo = @import("build_options");
        const fp = "watchdog: peer wedged";
        nvram.historyMarkCurrent(nvram.STATUS_CRASHED, bo.build_id, fp);
        nvram.setBootStatus(nvram.STATUS_CRASHED);
        nvram.setCrashFp(fp);
    }

    kdbg.enterCritical();

    const rsp = asm volatile ("movq %%rsp, %[ret]"
        : [ret] "=r" (-> u64),
    );

    kdbg.crashSummary(.{
        .int_no = 254, // distinct from @panic's 255 so dashboards can split
        .crash_rip = null,
        .kernel_rsp = rsp,
        .msg = "watchdog: peer CPU wedged",
    });

    // Wedge-victim context dump. The peer's [nmi-snap cpuN] line above
    // already printed its current RIP + PCB name + wait_kind, but
    // those rings tell us "what was it doing leading up to the wedge"
    // (last N IRQs / syscalls / RIPs). Together they distinguish
    // "stuck in tight loop X" from "blocked in syscall Y forever".
    serial.print("[wedge] peer cpu{d} context follows:\n", .{peer.cpu_id});
    @import("exectrail.zig").dump(peer.cpu_id, 32);
    // Decode the peer's current PCB if any.
    if (peer.current_pid) |peer_pid| {
        const process = @import("../proc/process.zig");
        if (peer_pid < process.MAX_PROCS) {
            const pcb = &process.procs[peer_pid];
            const name_slice = pcb.name[0..@min(pcb.name_len, pcb.name.len)];
            serial.print("[wedge] peer pid={d} name='{s}' state={d} wait_kind={d} wait_target=0x{X} kernel_esp=0x{X:0>16} kstack_top=0x{X:0>16}\n", .{
                peer_pid, name_slice,
                @intFromEnum(pcb.state),
                @intFromEnum(pcb.wait_kind),
                pcb.wait_target,
                pcb.kernel_esp,
                pcb.kernel_stack_top,
            });
            // Last 8 syscalls the wedged PID made. Often the smoking
            // gun: "stuck doing sys#10 (fread)", "looping on sys#08
            // (sleep)", "blocked in sys#92 (fork) then sys#41 (clone)".
            process.dumpSyscallRing(@intCast(peer_pid));
        }
    }

    // Dump every registered lock. Wedges often trace to one CPU
    // holding a lock the other is spinning on; this names the holder
    // by symbol so we don't have to puzzle over raw return addresses.
    @import("../proc/spinlock.zig").dumpAllLocks();
    // ...and the lock each CPU is CURRENTLY spinning to acquire — names the
    // contended lock even when it's unregistered (setstate_locks[]/rq.lock) or
    // free again by now, which is exactly the schedstress-wedge case.
    @import("../proc/spinlock.zig").dumpSpinTargets();
    // ...and per-CPU schedule() claim-loop retry counts. A large in-flight
    // value here = the wedged CPU is livelocked re-picking a candidate with
    // IF=0 (Mode-A), the thing the spin-target dump can't show because the
    // claim loop isn't a single SpinLock spin.
    @import("../proc/sched.zig").dumpSchedLoopStats();

    // Last-N kdbg ring entries (sched / irq / proc events across all
    // CPUs). The sched ring especially captures "who picked what when"
    // which often pinpoints a race window the rest of the dump doesn't.
    kdbg.dumpAll();

    serial.print("  SYSTEM HALTED (watchdog).\n", .{});
    while (true) asm volatile ("cli; hlt");
}
