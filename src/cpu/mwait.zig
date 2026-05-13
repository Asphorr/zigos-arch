// MONITOR/MWAIT idle support.
//
// MWAIT is a C-state-aware halt: the CPU sleeps until either (a) a write
// to the monitored cache line lands, or (b) an interrupt fires (with
// ECX[0]=1, even when EFLAGS.IF=0). vs HLT it's:
//   - faster wake on cross-CPU IPI (no full IRQ vector decode round-trip),
//   - eligible for deeper C-states (C1E, C3, C6) if the hint allows,
//   - usable by spinlock waiters that want to wake without an IRQ at all
//     (write the monitored line from another CPU).
//
// We use it from `kernelIdle` only — every CPU's idle loop sets up MONITOR
// on its per-CPU `idle_monitor_word` and issues MWAIT with hint=C1 + ECX[0]
// = 1. Wakes still come predominantly from IRQs (LAPIC timer, MSI-X);
// future cross-CPU "wake idle without IPI" paths can just write the
// monitor word.
//
// CPUID gating: CPUID.01H:ECX.MONITOR (bit 3) must be 1. Kaby Lake (our
// dev box) has it. On AMD older CPUs lack it; the detect() fallback
// keeps idle on plain HLT.

const std = @import("std");
const debug = @import("../debug/debug.zig");

pub var mwait_supported: bool = false;
pub var monitor_line_size: u32 = 64; // CPUID.05H:EAX[15:0] smallest

// Hint encoding for the MWAIT EAX register (Intel SDM Vol. 2B):
//   Bits 7:4 = sub-C-state
//   Bits 3:0 = C-state hint (0 = C1, 1 = C1E, ...). C0 is just MWAIT-wake-
//              on-interrupt with no power saving; we use C1.
pub const HINT_C1: u32 = 0x00;
pub const HINT_C1E: u32 = 0x01;

pub var default_hint: u32 = HINT_C1;

inline fn cpuid(leaf: u32, sub: u32) struct { eax: u32, ebx: u32, ecx: u32, edx: u32 } {
    var eax: u32 = undefined;
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    var edx: u32 = undefined;
    asm volatile ("cpuid"
        : [_] "={eax}" (eax),
          [_] "={ebx}" (ebx),
          [_] "={ecx}" (ecx),
          [_] "={edx}" (edx),
        : [_] "{eax}" (leaf),
          [_] "{ecx}" (sub),
    );
    return .{ .eax = eax, .ebx = ebx, .ecx = ecx, .edx = edx };
}

pub fn detect() void {
    const r1 = cpuid(1, 0);
    if ((r1.ecx & (1 << 3)) == 0) {
        debug.klog("[mwait] CPUID.01H:ECX.MONITOR=0 — idle stays on HLT\n", .{});
        return;
    }
    const max_leaf = cpuid(0, 0).eax;
    if (max_leaf < 5) {
        debug.klog("[mwait] max CPUID leaf {d} < 5 — no MWAIT enum\n", .{max_leaf});
        return;
    }
    const r5 = cpuid(5, 0);
    monitor_line_size = r5.eax & 0xFFFF;
    const max_line = (r5.ebx & 0xFFFF);
    const ecx0 = (r5.ecx & 1) != 0; // enumeration of MWAIT extensions
    const ecx1 = (r5.ecx & 2) != 0; // break on EFLAGS.IF=0 supported
    debug.klog(
        "[mwait] line_size={d}..{d} enum_ext={s} brk_int_off={s} substates={X}\n",
        .{
            monitor_line_size,
            max_line,
            if (ecx0) "y" else "n",
            if (ecx1) "y" else "n",
            r5.edx,
        },
    );
    mwait_supported = true;
}

/// Arm MONITOR on `addr` then enter MWAIT with the default C-state hint.
/// `addr` must point at a cache line nothing else writes spuriously
/// (otherwise mwait wakes immediately). Callers typically use a per-CPU
/// `idle_monitor_word`.
///
/// ECX[0]=1 makes interrupt break wake mwait even with EFLAGS.IF=0,
/// matching the `sti; hlt` semantics the caller wraps this in.
pub inline fn idleWait(addr: *volatile u32) void {
    const a = @intFromPtr(addr);
    asm volatile (
        \\monitor
        :
        : [a] "{rax}" (a),
          [c] "{rcx}" (@as(u64, 0)),
          [d] "{rdx}" (@as(u64, 0)),
    );
    asm volatile (
        \\mwait
        :
        : [a] "{rax}" (default_hint),
          [c] "{rcx}" (@as(u64, 1)),
    );
}
