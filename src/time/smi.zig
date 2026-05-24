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

const acpi = @import("acpi.zig");
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
    // Attribution: snapshot what cpu0 was doing at the PREVIOUS IRQ0 boundary.
    // exectrail's head-1 holds that saved_rip because handleIRQ0 calls smi.tick()
    // BEFORE exectrail.recordIrq() (see src/cpu/idt.zig:1232 vs :1258).
    // Classification heuristic:
    //   - syscall marker → kernel syscall path held cli (or schedule blocked)
    //   - kernel RIP in idle's halt loop → likely host SMI (CPU was halted)
    //   - kernel RIP elsewhere → kernel-cli-too-long
    //   - user RIP (< 0x800000_0000_0000 and < kernel high half) → likely host SMI
    classifyAndLog(us);
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

fn classifyAndLog(us: u64) void {
    const prev_rip_opt = exectrail.peekHeadMinusOne(0);
    if (prev_rip_opt == null) {
        debug.klog("[smi] stall: {d}us (events={d}, max={d}us) — no trail data\n", .{ us, stall_events, max_stall_us });
        return;
    }
    const prev_rip = prev_rip_opt.?;

    // Decode syscall marker (the PREVIOUS IRQ0 sampled CPU mid-syscall).
    if (prev_rip >= exectrail.MARKER_BASE) {
        const sys_num = prev_rip & 0xFFFF;
        debug.klog("[smi] stall: {d}us — likely OURS (sc#{d} held cli) — events={d} max={d}us\n", .{ us, sys_num, stall_events, max_stall_us });
        return;
    }

    // User-space RIP — IRQs were unmasked just before; stall is almost
    // certainly host SMI (we can't hold cli in user mode).
    if (prev_rip < KERNEL_HIGH_HALF) {
        debug.klog("[smi] stall: {d}us — likely HOST (user RIP 0x{X:0>16}) — events={d} max={d}us\n", .{ us, prev_rip, stall_events, max_stall_us });
        return;
    }

    // Kernel RIP — symbolize and let the caller judge. Idle/hlt path
    // = host; anywhere else = us.
    if (symbols.resolveKernel(prev_rip)) |r| {
        const name = r.name;
        // Heuristic: any "idle" symbol is the halt path → host-side.
        const is_idle = std.mem.indexOf(u8, name, "idle") != null or
            std.mem.indexOf(u8, name, "Idle") != null;
        const verdict = if (is_idle) "likely HOST (kernel idle/hlt)" else "likely OURS (kernel held cli)";
        debug.klog("[smi] stall: {d}us — {s} at {s}+0x{X} — events={d} max={d}us\n", .{ us, verdict, name, r.offset, stall_events, max_stall_us });
    } else {
        debug.klog("[smi] stall: {d}us — kernel RIP 0x{X:0>16} (unresolved) — events={d} max={d}us\n", .{ us, prev_rip, stall_events, max_stall_us });
    }
}

const std = @import("std");
