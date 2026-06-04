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
// We don't distinguish SMI from "we held cli too long" — both look like
// "elapsed PM_TMR > expected since last IRQ." On a clean kernel the only
// way to lose 5+ ms is SMI; if we ever start triggering this from our own
// kernel paths, that itself is a useful signal that something is wrong.
//
// Cost: one I/O port read (~1 µs on real HW, near zero on QEMU+KVM) per
// BSP IRQ0 = ~100 µs/sec = 0.01% CPU. Negligible.

const acpi = @import("../acpi/acpi.zig");
const apic = @import("apic.zig");
const debug = @import("../debug/debug.zig");
const io = @import("../io.zig");
const exectrail = @import("../debug/exectrail.zig");
const symbols = @import("../debug/symbols.zig");

const PM_TMR_HZ: u64 = 3_579_545;
const QUANTUM_MS: u64 = 10;
// Threshold: anything above 15 ms between BSP IRQ0 ticks counts as a
// stall. 5 ms slop above the expected 10 ms — KVM scheduling jitter alone
// can hit 1-3 ms; SMM stalls start at 5+ ms.
const STALL_THRESHOLD_PM: u64 = 15 * PM_TMR_HZ / 1000;

var pm_tmr_port: u16 = 0;
var pm_tmr_mask: u32 = 0;
var initialized: bool = false;

var last_pm: u32 = 0;
var sample_count: u64 = 0;
pub var stall_events: u64 = 0;
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

/// Called from BSP IRQ0 (timer). Reads PM_TMR, computes elapsed-since-last
/// in PM ticks, flags windows that exceeded the stall threshold.
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
    if (delta < STALL_THRESHOLD_PM) return;
    stall_events +%= 1;
    const us = delta * 1_000_000 / PM_TMR_HZ;
    if (us > max_stall_us) max_stall_us = us;
    // Rate limit: log at most once per second (every 100 BSP IRQ0s).
    if (sample_count - last_log_tick < 100) return;
    last_log_tick = sample_count;

    // Lock-attribution: walk registered SpinLocks for any whose acquire_tsc
    // shows it has been held for >5ms. Emits one [smi-cause] line per such
    // lock ABOVE the main [smi] classifier line, so a "blame the host"
    // verdict can be immediately checked against actual cli-held locks.
    // Directly answers user memory feedback: "[smi] stall can be us — check
    // pid_act / slow-sc / yield-loop first" — now the lock dump joins
    // those signals at fire time, not after the fact. (Proposal P4 in the
    // debug infra survey 2026-05-28.)
    const tsc_per_quantum = apic.tscPerQuantum();
    var cli_us: u64 = 0;
    var cli_ra: u64 = 0;
    if (tsc_per_quantum > 0) {
        const now_tsc: u64 = asm volatile (
            \\ rdtsc
            \\ shlq $32, %%rdx
            \\ orq %%rdx, %%rax
            : [r] "={rax}" (-> u64),
            :: .{ .rdx = true });
        const sl = @import("../proc/spinlock.zig");
        // 5ms = half of the 10ms LAPIC quantum. Existing [smi-cause] dump of
        // any lock CURRENTLY held >5ms — catches a PEER cpu still sitting on
        // one (orthogonal to cpu0's own gap, which we corroborate below).
        sl.dumpHeldLocksOlderThan(now_tsc, tsc_per_quantum / 2);
        // Corroboration for cpu0's gap: did THIS cpu release a cli-hold of
        // comparable size just before this IRQ0? A real cli-hold is recorded
        // µs ago (now-end is tiny); a host pause leaves the record stale (it
        // ended ~`us` ago, when the pause began). Require same-cpu so a
        // peer's hold can't masquerade as ours. .acquire pairs with the
        // .release publish so dur is consistent with end_tsc.
        const my_cpu: u8 = @truncate(apic.getLapicId());
        const end = @atomicLoad(u64, &sl.last_clihold_end_tsc, .acquire);
        const hold_cpu = @atomicLoad(u8, &sl.last_clihold_cpu, .monotonic);
        if (end != 0 and hold_cpu == my_cpu and now_tsc >= end and (now_tsc - end) < tsc_per_quantum) {
            const dur = @atomicLoad(u64, &sl.last_clihold_dur_tsc, .monotonic);
            cli_ra = @atomicLoad(u64, &sl.last_clihold_ra, .monotonic);
            cli_us = dur * 10_000 / tsc_per_quantum; // tsc_per_quantum = TSC/10ms = TSC/10_000µs
        }
    }

    // prev_rip (in classifyAndLog) = what cpu0 was doing at the PREVIOUS
    // IRQ0 boundary (exectrail head-1; handleIRQ0 calls smi.tick() BEFORE
    // exectrail.recordIrq()). The verdict is now decided by cli_us — an
    // ACTUAL recorded cli-hold — not guessed from prev_rip; prev_rip is
    // only context for where a host pause happened to sample us.
    classifyAndLog(us, cli_us, cli_ra);
}

/// Wraparound-safe delta on the masked counter. Returns the number of PM
/// ticks elapsed from `prev` to `now`. Caller already masked both with
/// `pm_tmr_mask`.
fn pmDelta(prev: u32, now: u32) u64 {
    if (now >= prev) return now - prev;
    // Wrapped: distance is (mask - prev) + now + 1.
    return (@as(u64, pm_tmr_mask) - prev) + now + 1;
}

const KERNEL_HIGH_HALF: u64 = 0xFFFF800000000000;

// Decide OURS vs HOST from cli_us — the duration of an ACTUAL cpu-local
// cli-hold that ended just before this IRQ0 (0 if none). A gap is OURS only
// when a recorded hold covers at least half of it; otherwise it's a host
// vCPU pause that merely SAMPLED cpu0 somewhere (prev_rip). The old code
// guessed "OURS" from prev_rip alone, so every host pause that happened to
// sample schedule() — the hottest kernel code — was mislabeled "OURS at
// schedule" while the real cli-holds were only ≤17ms and the gaps ran to
// 1.3s. cli_ra is the hold's acquire site = the authoritative location.
fn classifyAndLog(us: u64, cli_us: u64, cli_ra: u64) void {
    const accounted = cli_us != 0 and cli_us * 2 >= us;

    if (accounted) {
        if (symbols.resolveKernel(cli_ra)) |r| {
            debug.klog("[smi] stall: {d}us — OURS (cli-hold {d}us at {s}+0x{X}) — events={d} max={d}us\n", .{ us, cli_us, r.name, r.offset, stall_events, max_stall_us });
        } else {
            debug.klog("[smi] stall: {d}us — OURS (cli-hold {d}us at ra=0x{X:0>16}) — events={d} max={d}us\n", .{ us, cli_us, cli_ra, stall_events, max_stall_us });
        }
        return;
    }

    // No cli-hold accounts for the gap → host vCPU pause. Report WHERE cpu0
    // was sampled (prev_rip) as context, plus cli-acct (the largest hold we
    // did see, ~0) to make the "nothing actually held cli" basis explicit.
    const prev_rip_opt = exectrail.peekHeadMinusOne(0);
    if (prev_rip_opt == null) {
        debug.klog("[smi] stall: {d}us — likely HOST (vCPU pause; cli-acct={d}us) — no trail (events={d} max={d}us)\n", .{ us, cli_us, stall_events, max_stall_us });
        return;
    }
    const prev_rip = prev_rip_opt.?;

    // Syscall marker (low canonical half; a real kernel RIP 0xFFFF8000.. is
    // >= MARKER_BASE but lacks the bit-47/48 pattern, hence the high bound).
    // CPU was mid-syscall when the pause began.
    if (prev_rip >= exectrail.MARKER_BASE and prev_rip < KERNEL_HIGH_HALF) {
        const sys_num = prev_rip & 0xFFFF;
        debug.klog("[smi] stall: {d}us — likely HOST (vCPU pause; was in sc#{d}, cli-acct={d}us) — events={d} max={d}us\n", .{ us, sys_num, cli_us, stall_events, max_stall_us });
        return;
    }

    // User-space RIP — IRQs were unmasked, so it can't be our cli-hold → host.
    if (prev_rip < KERNEL_HIGH_HALF) {
        debug.klog("[smi] stall: {d}us — likely HOST (user RIP 0x{X:0>16}) — events={d} max={d}us\n", .{ us, prev_rip, stall_events, max_stall_us });
        return;
    }

    // Kernel RIP, no cli-hold corroborated. idle/hlt = expected host wait;
    // anything else = host starvation that sampled us mid-kernel.
    if (symbols.resolveKernel(prev_rip)) |r| {
        const is_idle = std.mem.indexOf(u8, r.name, "idle") != null or
            std.mem.indexOf(u8, r.name, "Idle") != null;
        const why = if (is_idle) "kernel idle/hlt" else "vCPU pause";
        debug.klog("[smi] stall: {d}us — likely HOST ({s}; was at {s}+0x{X}, cli-acct={d}us) — events={d} max={d}us\n", .{ us, why, r.name, r.offset, cli_us, stall_events, max_stall_us });
    } else {
        debug.klog("[smi] stall: {d}us — likely HOST (vCPU pause; kernel RIP 0x{X:0>16} unresolved, cli-acct={d}us) — events={d} max={d}us\n", .{ us, prev_rip, cli_us, stall_events, max_stall_us });
    }
}

const std = @import("std");
