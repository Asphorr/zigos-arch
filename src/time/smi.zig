// SMI / scheduler stall detector.
//
// Real-HW BIOSes fire System Management Interrupts (SMIs) for things like
// USB legacy emulation, fan control, thermal throttling, and ACPI events.
// SMM runs at a higher privilege than the OS and can hold all CPUs for
// 5-80 ms with no notification. Symptom: the desktop hitches every few
// seconds even though "nothing" is happening.
//
// Detection works because:
//   - BSP IRQ0 (timer) fires deterministically every 10 ms when IRQs are
//     unmasked.
//   - ACPI PM_TMR is a 24- or 32-bit free-running counter at 3.579545 MHz,
//     accessed via I/O port from FADT.pm_tmr_blk.
//   - Between two consecutive BSP IRQ0 entries, PM_TMR should advance by
//     ~35795 ticks (= 10 ms × 3.579545 MHz). If we see significantly more,
//     the OS lost time — either to SMM or to a long-disabled IRQ window.
//
// This module is also the sole PRINTER for spinlock's cli-hold records:
// cliHoldCheck records into per-CPU seqlock slots and tick() drains them
// under a rate budget (flushCliHolds). Printing used to happen inline at
// release time — under a Hyper-V host-pause storm that flooded thousands
// of misattributed [cli-hold] lines per boot (see spinlock.zig's
// vm_alive_pulse block comment for the full story).
//
// Cost: one I/O port read (~1 µs on real HW, near zero on QEMU+KVM) per
// BSP IRQ0 = ~100 µs/sec = 0.01% CPU. Negligible.

const acpi = @import("../acpi/acpi.zig");
const apic = @import("apic.zig");
const debug = @import("../debug/debug.zig");
const io = @import("../io.zig");
const exectrail = @import("../debug/exectrail.zig");
const symbols = @import("../debug/symbols.zig");
const spinlock = @import("../proc/spinlock.zig");
const kvm = @import("../virt/kvm.zig");

const PM_TMR_HZ: u64 = 3_579_545;
const QUANTUM_MS: u64 = 10;
// Threshold: anything above 15 ms between BSP IRQ0 ticks counts as a
// stall. 5 ms slop above the expected 10 ms — KVM scheduling jitter alone
// can hit 1-3 ms; SMM stalls start at 5+ ms.
const STALL_THRESHOLD_PM: u64 = 15 * PM_TMR_HZ / 1000;

var pm_tmr_port: u16 = 0;
var pm_tmr_mask: u32 = 0;
var initialized: bool = false;

/// Most-recent stall window in BSP TSC, published for perf.zig's sample
/// quarantine (a perf sample whose [start,end] overlaps this window was
/// host-pause-contaminated, regardless of its magnitude). start is derived
/// from the PM_TMR gap via tsc_per_quantum — approximate, which is fine:
/// this drives quarantine decisions, not accounting. end published LAST
/// with .release so a reader that observes it sees the matching start.
/// Published unconditionally per detected stall (NOT behind the 1/s log
/// rate-limit) — perf needs every window.
pub var stall_win_start_tsc: u64 = 0;
pub var stall_win_end_tsc: u64 = 0;

var last_pm: u32 = 0;
var sample_count: u64 = 0;
/// KVM steal-time reading at the previous tick (ns); 0 = not sampled yet.
/// BSP-only like everything here (tick() is BSP IRQ0).
var last_steal_ns: u64 = 0;
pub var stall_events: u64 = 0;
/// Subset of stall_events with duration ≥ BIG_STALL_US — the only stalls
/// that can swallow a key-release long enough to fabricate a phantom
/// 200ms "hold" (keyboard typematic quarantine trigger). The 15-50ms
/// drizzle of nested-virt vCPU-steal slices freezes the tick clock along
/// with the input path (one-shot timer → ~1 late tick per stall), so it
/// can't manufacture phantom holds — quarantining on every drizzle event
/// starved legit auto-repeat ("hold-to-delete is slow", 2026-06-10: 84%
/// of one boot's 991 stalls were <50ms).
pub var big_stall_events: u64 = 0;
const BIG_STALL_US: u64 = 50_000;
pub var max_stall_us: u64 = 0;
var last_log_tick: u64 = 0;

pub fn init() void {
    const f = acpi.getFadt() orelse return;
    if (f.pm_tmr_blk == 0 or f.pm_tmr_len == 0) return;
    pm_tmr_port = @truncate(f.pm_tmr_blk);
    // FADT.flags bit 8 = TMR_VAL_EXT. When set, PM_TMR is 32-bit; otherwise
    // 24-bit (and bits [31:24] read zero). Wraparound is at 1.2 hr in 32-bit
    // mode and 4.6 sec in 24-bit mode — both fine for our 10 ms windows.
    const ext_32 = (f.flags & (1 << 8)) != 0;
    pm_tmr_mask = if (ext_32) 0xFFFFFFFF else 0xFFFFFF;
    initialized = true;
    debug.klog("[smi] PM_TMR detector ready: port=0x{x} {s}-bit\n", .{ pm_tmr_port, if (ext_32) "32" else "24" });
}

/// True once the PM_TMR detector is armed. spinlock.cliHoldCheck uses this
/// to decide whether tick() will drain its hold slots or it must fall back
/// to printing directly (no-FADT boards).
pub fn isActive() bool {
    return initialized;
}

/// Called from BSP IRQ0 (timer). Reads PM_TMR, computes elapsed-since-last
/// in PM ticks, flags windows that exceeded the stall threshold. Also
/// drains spinlock's cli-hold slots every tick (see flushCliHolds).
///
/// Don't call from APs — their IRQ0 is irregular (idle hlt suppresses it)
/// and would trigger constant false positives. Don't call before APIC
/// timer is calibrated and running, or last_pm is meaningless.
pub fn tick() void {
    if (!initialized) return;
    const now: u32 = io.inl(pm_tmr_port) & pm_tmr_mask;
    sample_count +%= 1;
    if (last_pm == 0) {
        last_pm = now;
        return;
    }
    const delta = pmDelta(last_pm, now);
    last_pm = now;

    // KVM steal across this tick window. Sampled EVERY tick so a stall
    // tick's delta spans exactly its gap — the ground truth that splits
    // host pauses into layers: steal covering the gap = L1 (zigvm's
    // scheduler descheduled our vCPU thread); steal ≈ 0 with a big gap =
    // L0 (Hyper-V paused all of zigvm — invisible to KVM's accounting,
    // no L1 runqueue wait ever happens). Cheap: seqlock read of a
    // guest-RAM struct, no exit. 0 on bare metal / pre-arm.
    const cur_steal_ns = kvm.stealNs(@import("../cpu/smp.zig").myCpu().cpu_id);
    const steal_delta_ns = if (last_steal_ns == 0) 0 else cur_steal_ns -% last_steal_ns;
    last_steal_ns = cur_steal_ns;

    const tsc_per_quantum = apic.tscPerQuantum();
    var now_tsc: u64 = 0;
    if (tsc_per_quantum > 0) {
        now_tsc = rdtsc();
        // Drain recorded cli-holds EVERY tick, not only on stall ticks: a
        // hold on an AP never delays BSP IRQ0, and a 5-15ms BSP hold stays
        // under the stall threshold — both must still surface.
        flushCliHolds(tsc_per_quantum);
    }

    if (delta < STALL_THRESHOLD_PM) return;
    // Atomic store: keyboard.pollRepeat reads this cross-CPU (desktop loop
    // may run on an AP) to quarantine typematic repeat across host pauses.
    // The plain read in the +% is fine — BSP IRQ0 is the ONLY writer, so
    // this is not a racy RMW; don't "fix" it into @atomicRmw or a lock.
    @atomicStore(u64, &stall_events, stall_events +% 1, .monotonic);
    const us = delta * 1_000_000 / PM_TMR_HZ;
    if (us >= BIG_STALL_US) {
        @atomicStore(u64, &big_stall_events, big_stall_events +% 1, .monotonic);
    }
    if (us > max_stall_us) max_stall_us = us;
    if (tsc_per_quantum > 0) {
        // PM ticks per 10ms quantum = PM_TMR_HZ/100; gap in TSC ≈
        // delta * tsc_per_quantum / that. Publish for perf's quarantine.
        const delta_tsc = delta * tsc_per_quantum / (PM_TMR_HZ / 100);
        @atomicStore(u64, &stall_win_start_tsc, now_tsc -% delta_tsc, .monotonic);
        @atomicStore(u64, &stall_win_end_tsc, now_tsc, .release);
    }
    // Rate limit: log at most once per second (every 100 BSP IRQ0s).
    if (sample_count - last_log_tick < 100) return;
    last_log_tick = sample_count;

    var cli_us: u64 = 0;
    var cli_ra: u64 = 0;
    var cli_vm_frozen = false;
    if (tsc_per_quantum > 0) {
        // Lock-attribution: any lock CURRENTLY held >5ms (half the 10ms
        // LAPIC quantum) — catches a PEER cpu still sitting on one
        // (orthogonal to cpu0's own gap, corroborated below). One
        // [smi-cause] line per lock, ABOVE the classifier verdict.
        spinlock.dumpHeldLocksOlderThan(now_tsc, tsc_per_quantum / 2);
        // Corroboration for cpu0's gap: did THIS cpu record a cli-hold
        // ending just before this IRQ0? A real cli-hold is recorded µs
        // before the pending IRQ0 re-fires; an unrelated stale record
        // fails the end-within-a-quantum check. Same-cpu so a peer's hold
        // can't masquerade as ours. The record also carries the
        // freeze-vs-hold verdict: a vm_frozen window must NOT be blamed
        // OURS — its TSC delta counted host freeze time, not kernel work.
        const my_cpu: u8 = @truncate(apic.getLapicId());
        var rec: spinlock.CliHoldRecord = undefined;
        if (spinlock.sampleHold(my_cpu, &rec)) |seq| {
            if (seq != 0 and now_tsc >= rec.end_tsc and (now_tsc - rec.end_tsc) < tsc_per_quantum) {
                cli_us = rec.dur_tsc * 10_000 / tsc_per_quantum; // tsc_per_quantum = TSC/10ms = TSC/10_000µs
                cli_ra = rec.ra;
                cli_vm_frozen = rec.verdict == .vm_frozen;
            }
        }
    }

    // prev_rip (in classifyAndLog) = what cpu0 was doing at the PREVIOUS
    // IRQ0 boundary (exectrail head-1; handleIRQ0 calls smi.tick() BEFORE
    // exectrail.recordIrq()). The verdict is decided by cli_us — an ACTUAL
    // recorded cli-hold — not guessed from prev_rip; prev_rip is only
    // context for where a host pause happened to sample us.
    classifyAndLog(us, cli_us, cli_ra, cli_vm_frozen, steal_delta_ns / 1000);
}

inline fn rdtsc() u64 {
    return asm volatile (
        \\ rdtsc
        \\ shlq $32, %%rdx
        \\ orq %%rdx, %%rax
        : [r] "={rax}" (-> u64),
        :: .{ .rdx = true });
}

/// Wraparound-safe delta on the masked counter. Returns the number of PM
/// ticks elapsed from `prev` to `now`. Caller already masked both with
/// `pm_tmr_mask`.
fn pmDelta(prev: u32, now: u32) u64 {
    if (now >= prev) return now - prev;
    // Wrapped: distance is (mask - prev) + now + 1.
    return (@as(u64, pm_tmr_mask) - prev) + now + 1;
}

// ---------------------------------------------------------------------------
// cli-hold drain — sole printer for spinlock's per-CPU hold records.
// ---------------------------------------------------------------------------

/// Budget: at most this many [cli-hold] lines per ~1s window. A host-pause
/// storm generates one record per freeze-inside-cli; without the budget
/// that's still hundreds of lines/minute. Anything over budget (or
/// overwritten in a slot before we drained it) is counted and reported
/// once per window — the data degrades to a count, never to silence.
const HOLD_LINES_PER_WINDOW: u32 = 4;

var hold_last_seen: [spinlock.MAX_HOLD_CPUS]u32 = [_]u32{0} ** spinlock.MAX_HOLD_CPUS;
var hold_window_start_sample: u64 = 0;
var hold_printed_this_window: u32 = 0;
var hold_suppressed_this_window: u64 = 0;

fn flushCliHolds(tsc_per_quantum: u64) void {
    // ~1s window (100 BSP ticks at 10ms) — same cadence as the [smi] limiter.
    if (sample_count -% hold_window_start_sample >= 100) {
        if (hold_suppressed_this_window > 0) {
            debug.klog("[cli-hold] +{d} hold(s) suppressed ({d}/s print budget)\n", .{ hold_suppressed_this_window, HOLD_LINES_PER_WINDOW });
        }
        hold_window_start_sample = sample_count;
        hold_printed_this_window = 0;
        hold_suppressed_this_window = 0;
    }
    var cpu: usize = 0;
    while (cpu < spinlock.MAX_HOLD_CPUS) : (cpu += 1) {
        var rec: spinlock.CliHoldRecord = undefined;
        const seq = spinlock.sampleHold(cpu, &rec) orelse continue; // torn → retry next tick
        if (seq == hold_last_seen[cpu]) continue; // nothing new (incl. never-written 0)
        const missed: u32 = (seq -% hold_last_seen[cpu]) / 2 -| 1;
        hold_last_seen[cpu] = seq;
        if (hold_printed_this_window >= HOLD_LINES_PER_WINDOW) {
            hold_suppressed_this_window += @as(u64, missed) + 1;
            continue;
        }
        hold_printed_this_window += 1;
        hold_suppressed_this_window += missed;
        const us = rec.dur_tsc * 10_000 / tsc_per_quantum;
        if (symbols.resolveKernel(rec.ra)) |r| {
            debug.klog("[cli-hold] cpu{d} lock@0x{X} {d}us at {s}+0x{X}", .{ cpu, rec.lock_addr, us, r.name, r.offset });
        } else {
            debug.klog("[cli-hold] cpu{d} lock@0x{X} {d}us ra=0x{X}", .{ cpu, rec.lock_addr, us, rec.ra });
        }
        switch (rec.verdict) {
            .vm_frozen => debug.klog(" — VM SILENT thru window: host freeze, NOT a kernel hold", .{}),
            .vm_alive => debug.klog(" — VM alive (pulses={d}): genuine hold or 1-vCPU steal", .{rec.pulse_delta}),
            .unverified => {},
        }
        if (missed > 0) debug.klog(" (+{d} earlier unlogged)", .{missed});
        debug.klog("\n", .{});
        // Held-path backtrace captured at release time. vm_frozen records
        // carry none (skipped at capture — the frames would be stale
        // host-storm noise, the 2026-06-09 misattribution).
        if (rec.verdict != .vm_frozen) {
            for (rec.path, 0..) |p, i| {
                if (p == 0) continue;
                if (symbols.resolveKernel(p)) |r2| {
                    debug.klog("[cli-hold]   held-path #{d}: {s}+0x{X}\n", .{ i, r2.name, r2.offset });
                }
            }
        }
    }
}

const KERNEL_HIGH_HALF: u64 = 0xFFFF800000000000;

// Decide OURS vs HOST from cli_us — the duration of an ACTUAL cpu-local
// cli-hold that ended just before this IRQ0 (0 if none). A gap is OURS only
// when a recorded hold covers at least half of it AND the hold's window
// wasn't itself a whole-VM freeze (cli_vm_frozen). The old code guessed
// "OURS" from prev_rip alone, so every host pause that happened to sample
// schedule() — the hottest kernel code — was mislabeled "OURS at schedule";
// then the corroboration rework still mislabeled host-freezes-inside-cli as
// OURS because the TSC counts through a freeze. cli_ra is the hold's
// acquire site = the authoritative location.
fn classifyAndLog(us: u64, cli_us: u64, cli_ra: u64, cli_vm_frozen: bool, steal_us: u64) void {
    const accounted = cli_us != 0 and cli_us * 2 >= us;

    // Layer split for host verdicts, from KVM's own accounting (ground
    // truth, not a heuristic): steal covering ≥half the gap = the L1
    // zigvm scheduler descheduled our vCPU thread; steal ≈ 0 against a
    // big gap = L0 Hyper-V paused all of zigvm (KVM never sees a runqueue
    // wait, so steal stays flat — the 2026-06-12 52ms-steal-vs-307ms-stall
    // decomposition). "HOST?" when steal isn't armed (bare metal: PM_TMR
    // gaps there are real SMIs, which steal can't speak to either way).
    const steal_armed = last_steal_ns != 0;
    const host_tag: []const u8 = if (!steal_armed)
        "HOST?"
    else if (steal_us * 2 >= us)
        "HOST-L1 (zigvm steal)"
    else
        "HOST-L0 (hypervisor pause)";

    if (accounted) {
        if (cli_vm_frozen) {
            // The recorded hold covers the gap, but the whole VM was silent
            // through it (vm_alive_pulse unchanged): the host froze us
            // INSIDE the cli window. Freeze time, not kernel work.
            if (symbols.resolveKernel(cli_ra)) |r| {
                debug.klog("[smi] stall: {d}us — {s} (froze {d}us inside cli window at {s}+0x{X}; VM silent; steal={d}us) — events={d} max={d}us\n", .{ us, host_tag, cli_us, r.name, r.offset, steal_us, stall_events, max_stall_us });
            } else {
                debug.klog("[smi] stall: {d}us — {s} (froze {d}us inside cli window at ra=0x{X:0>16}; VM silent; steal={d}us) — events={d} max={d}us\n", .{ us, host_tag, cli_us, cli_ra, steal_us, stall_events, max_stall_us });
            }
            return;
        }
        // OURS — but a nonzero steal here means the hold itself was
        // stretched by L1 preemption mid-window; the printed steal lets
        // the reader subtract before blaming the acquire site.
        if (symbols.resolveKernel(cli_ra)) |r| {
            debug.klog("[smi] stall: {d}us — OURS (cli-hold {d}us at {s}+0x{X}; steal={d}us) — events={d} max={d}us\n", .{ us, cli_us, r.name, r.offset, steal_us, stall_events, max_stall_us });
        } else {
            debug.klog("[smi] stall: {d}us — OURS (cli-hold {d}us at ra=0x{X:0>16}; steal={d}us) — events={d} max={d}us\n", .{ us, cli_us, cli_ra, steal_us, stall_events, max_stall_us });
        }
        return;
    }

    // No cli-hold accounts for the gap → host pause; host_tag carries the
    // L0/L1 layer verdict. Report WHERE cpu0 was sampled (prev_rip) as
    // context, plus cli-acct (the largest hold we did see, ~0) to make
    // the "nothing actually held cli" basis explicit.
    const prev_rip_opt = exectrail.peekHeadMinusOne(0);
    if (prev_rip_opt == null) {
        debug.klog("[smi] stall: {d}us — {s} (steal={d}us cli-acct={d}us) — no trail (events={d} max={d}us)\n", .{ us, host_tag, steal_us, cli_us, stall_events, max_stall_us });
        return;
    }
    const prev_rip = prev_rip_opt.?;

    // Syscall marker (low canonical half; a real kernel RIP 0xFFFF8000.. is
    // >= MARKER_BASE but lacks the bit-47/48 pattern, hence the high bound).
    // CPU was mid-syscall when the pause began.
    if (prev_rip >= exectrail.MARKER_BASE and prev_rip < KERNEL_HIGH_HALF) {
        const sys_num = prev_rip & 0xFFFF;
        debug.klog("[smi] stall: {d}us — {s} (was in sc#{d}; steal={d}us cli-acct={d}us) — events={d} max={d}us\n", .{ us, host_tag, sys_num, steal_us, cli_us, stall_events, max_stall_us });
        return;
    }

    // User-space RIP — IRQs were unmasked, so it can't be our cli-hold → host.
    if (prev_rip < KERNEL_HIGH_HALF) {
        debug.klog("[smi] stall: {d}us — {s} (user RIP 0x{X:0>16}; steal={d}us) — events={d} max={d}us\n", .{ us, host_tag, prev_rip, steal_us, stall_events, max_stall_us });
        return;
    }

    // Kernel RIP, no cli-hold corroborated. idle/hlt = expected host wait;
    // anything else = host starvation that sampled us mid-kernel.
    if (symbols.resolveKernel(prev_rip)) |r| {
        const is_idle = std.mem.indexOf(u8, r.name, "idle") != null or
            std.mem.indexOf(u8, r.name, "Idle") != null;
        const why = if (is_idle) "kernel idle/hlt" else "vCPU pause";
        debug.klog("[smi] stall: {d}us — {s} ({s}; was at {s}+0x{X}; steal={d}us cli-acct={d}us) — events={d} max={d}us\n", .{ us, host_tag, why, r.name, r.offset, steal_us, cli_us, stall_events, max_stall_us });
    } else {
        debug.klog("[smi] stall: {d}us — {s} (kernel RIP 0x{X:0>16} unresolved; steal={d}us cli-acct={d}us) — events={d} max={d}us\n", .{ us, host_tag, prev_rip, steal_us, cli_us, stall_events, max_stall_us });
    }
}

const std = @import("std");
