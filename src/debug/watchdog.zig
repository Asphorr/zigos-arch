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

    // False-positive guard: if peer is currently in its idle PCB, it's
    // legitimately not advancing — TSC-deadline mode lets idle APs sleep
    // until the next sleeper expiry, which can be seconds or longer. A
    // wedged CPU stuck in cli'd kernel code would still have current_pid
    // pointing at the real (non-idle) process it was running, so we
    // distinguish on that. Reset strikes too so the next non-idle window
    // starts fresh.
    if (peer.current_pid != null and peer.idle_pid != null and
        peer.current_pid.?  == peer.idle_pid.?)
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
    serial.print("\n!!! WATCHDOG: cpu{d} wedged !!! (last tick=0x{X}, observed unchanged for ~{d}s by cpu{d})\n", .{
        peer.cpu_id,
        self.watchdog_peer_last_tick,
        WATCHDOG_STRIKES,
        self.cpu_id,
    });

    // Same shape as a real panic: persist crash hint to NVRAM, dump
    // crashSummary, broadcast NMI to all peers (with halt-after so the
    // wedged CPU's snapshot RIP captures the actual stuck instruction
    // and no CPU continues running on possibly-corrupt state).
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

    kdbg.nmi_halt_after_snapshot = true;
    kdbg.broadcastNMI();

    serial.print("  SYSTEM HALTED (watchdog).\n", .{});
    while (true) asm volatile ("cli; hlt");
}
