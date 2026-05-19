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
/// Consecutive missed checks before declaring a wedge.
const WATCHDOG_STRIKES: u8 = 3;

var armed: bool = false;
var fired: bool = false;

/// Enable the watchdog. Call after smp.init() so peer CPUs exist. No-op
/// before that; the per-CPU tick fields default to 0, and a freshly-zeroed
/// peer would falsely register as "not advancing" on the first check.
pub fn arm() void {
    armed = true;
    serial.print("[watchdog] armed (interval={d} ticks, strikes={d})\n", .{ WATCHDOG_CHECK_INTERVAL, WATCHDOG_STRIKES });
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
        return;
    }

    const peer_tick = @atomicLoad(u64, &peer.irq_tick_count, .acquire);
    if (peer_tick != self.watchdog_peer_last_tick) {
        // Peer made progress since last check. Reset strikes.
        self.watchdog_peer_last_tick = peer_tick;
        self.watchdog_peer_strikes = 0;
        return;
    }

    // Peer's tick hasn't moved AND peer isn't in idle.
    self.watchdog_peer_strikes +|= 1;
    if (self.watchdog_peer_strikes < WATCHDOG_STRIKES) return;

    // Threshold crossed — wedge confirmed. Race-free single-fire via
    // compare-exchange: only the first CPU to detect dumps; others bail.
    if (@cmpxchgStrong(bool, &fired, false, true, .acq_rel, .acquire) != null) return;

    fire(self, peer);
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

    // Last-N kdbg ring entries (sched / irq / proc events across all
    // CPUs). The sched ring especially captures "who picked what when"
    // which often pinpoints a race window the rest of the dump doesn't.
    kdbg.dumpAll();

    serial.print("  SYSTEM HALTED (watchdog).\n", .{});
    while (true) asm volatile ("cli; hlt");
}
