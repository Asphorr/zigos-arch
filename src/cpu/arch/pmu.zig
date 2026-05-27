// PMU (Performance Monitoring Unit) sampling profiler.
//
// Architectural PMU (Intel SDM Vol. 3B Ch. 18): CPUID.0AH:EAX[7:0] gives
// PMU version. v1+ provides IA32_PMC0..N (general-purpose counters)
// + IA32_PERFEVTSEL0..N (event selectors). Overflow generates a PMI
// (Performance Monitor Interrupt), routed through LAPIC.LVT_PMI to a
// kernel-defined vector.
//
// Sampling model: we configure PMC0 to count `INSTRUCTIONS_RETIRED`
// (event 0xC0, umask 0x00), preset PMC0 so it overflows after N events,
// arm the LVT_PMI mask, and let the kernel PMI handler timestamp +
// dump the saved RIP/RBP/symbol on each sample. Output goes to the
// serial ring; a separate userland tool can post-process.
//
// PMI vector: 0xFE (just below the spurious 0xFF, above the dynamic
// MSI-X 0x40..0x4F range, no clash with the syscall 0x80 or tlb 0x50).
// IDT slot is set up alongside the existing IRQs in idt.init.
//
// Per-CPU init runs once per CPU after applyEarlyCr4 — each CPU has
// its own PMC0/PERFEVTSEL0 MSRs, so this can't be a one-shot BSP call.

const std = @import("std");
const debug = @import("../../debug/debug.zig");
const serial = @import("../../debug/serial.zig");
const apic = @import("../../time/apic.zig");

const MSR_IA32_PMC0: u32 = 0xC1;
const MSR_IA32_PERFEVTSEL0: u32 = 0x186;
const MSR_IA32_PERF_GLOBAL_CTRL: u32 = 0x38F;
const MSR_IA32_PERF_GLOBAL_OVF_CTRL: u32 = 0x390;
const MSR_IA32_DEBUGCTL: u32 = 0x1D9;

// PERFEVTSEL fields.
const SEL_USR: u64 = 1 << 16;
const SEL_OS: u64 = 1 << 17;
const SEL_INT: u64 = 1 << 20; // raise PMI on overflow
const SEL_EN: u64 = 1 << 22;

// INSTRUCTIONS_RETIRED, all umasks. Arch perf v1 event (SDM Table 19-1).
const EVT_INST_RETIRED: u64 = 0xC0;

pub const PMI_VECTOR: u8 = 0xFE;

pub var version: u8 = 0;
pub var num_counters: u8 = 0;
pub var counter_width: u8 = 0;
pub var supported: bool = false;
pub var sampling_active: bool = false;
pub var sample_period: u64 = 1_000_000; // 1M instructions/sample
pub var samples_taken: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

inline fn rdmsr(msr: u32) u64 {
    var lo: u32 = undefined;
    var hi: u32 = undefined;
    asm volatile ("rdmsr"
        : [_] "={eax}" (lo),
          [_] "={edx}" (hi),
        : [_] "{ecx}" (msr),
    );
    return (@as(u64, hi) << 32) | lo;
}

inline fn wrmsr(msr: u32, value: u64) void {
    asm volatile ("wrmsr"
        :
        : [_] "{ecx}" (msr),
          [_] "{eax}" (@as(u32, @truncate(value))),
          [_] "{edx}" (@as(u32, @truncate(value >> 32))),
    );
}

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
    const max_leaf = cpuid(0, 0).eax;
    if (max_leaf < 0xA) {
        debug.klog("[pmu] max CPUID leaf {d} < 0xA — no arch PMU\n", .{max_leaf});
        return;
    }
    const r = cpuid(0xA, 0);
    version = @truncate(r.eax & 0xFF);
    num_counters = @truncate((r.eax >> 8) & 0xFF);
    counter_width = @truncate((r.eax >> 16) & 0xFF);
    if (version == 0 or num_counters == 0) {
        debug.klog("[pmu] CPUID.0AH version={d} counters={d} — disabled\n", .{ version, num_counters });
        return;
    }
    supported = true;
    debug.klog(
        "[pmu] version={d} counters={d} width={d}\n",
        .{ version, num_counters, counter_width },
    );
}

/// Per-CPU initialization. Clears PMC0/PERFEVTSEL0 to a known-disabled
/// state. Each CPU has its own LVT_PMI which we'll mask until sampling
/// is explicitly started via `start()`.
pub fn perCpuInit() void {
    if (!supported) return;
    wrmsr(MSR_IA32_PERFEVTSEL0, 0);
    wrmsr(MSR_IA32_PMC0, 0);
    // Mask the LAPIC LVT.PMI entry initially; `start` unmasks.
    apic.maskLvtPmi();
}

/// Begin sampling on this CPU. `period_instructions` is the number of
/// retired instructions between samples; smaller = higher overhead but
/// finer-grained profile. Each PMI dumps RIP + caller for post-processing.
/// Call from any CPU you want to profile; APs+BSP can sample independently.
pub fn start(period_instructions: u64) void {
    if (!supported) return;
    sample_period = period_instructions;
    sampling_active = true;
    // PMC0 counts up from `init`; an overflow fires PMI when bit
    // [counter_width-1] transitions past the sign. Preset = -period.
    const init_val: u64 = (~@as(u64, 0)) - period_instructions + 1;
    wrmsr(MSR_IA32_PMC0, init_val);
    // Route PMI to our vector before enabling counter.
    apic.programLvtPmi(PMI_VECTOR);
    wrmsr(MSR_IA32_PERFEVTSEL0, EVT_INST_RETIRED | SEL_OS | SEL_USR | SEL_INT | SEL_EN);
    if (version >= 2) wrmsr(MSR_IA32_PERF_GLOBAL_CTRL, 1);
}

pub fn stop() void {
    if (!supported) return;
    sampling_active = false;
    wrmsr(MSR_IA32_PERFEVTSEL0, 0);
    if (version >= 2) wrmsr(MSR_IA32_PERF_GLOBAL_CTRL, 0);
    apic.maskLvtPmi();
}

/// PMI handler — called from the LVT_PMI ISR. Logs a one-line sample then
/// re-arms PMC0 for the next overflow.
pub fn onSample(rip: u64) void {
    if (!sampling_active) {
        // Spurious — mask + EOI.
        apic.eoi();
        return;
    }
    const n = samples_taken.fetchAdd(1, .monotonic) + 1;
    // Throttle log output: dump every sample is too noisy when period is
    // small. Print every Nth, with N = max(1, samples_taken / 4096).
    const log_stride: u64 = blk: {
        var s: u64 = n >> 12;
        if (s == 0) s = 1;
        break :blk s;
    };
    if (n % log_stride == 0) {
        serial.print("[pmu] sample #{d} rip=0x{X:0>16}\n", .{ n, rip });
    }
    // Re-arm: preset PMC0 to overflow again after `sample_period` events,
    // clear OVF status, EOI the LAPIC.
    const init_val: u64 = (~@as(u64, 0)) - sample_period + 1;
    wrmsr(MSR_IA32_PMC0, init_val);
    if (version >= 2) wrmsr(MSR_IA32_PERF_GLOBAL_OVF_CTRL, 1);
    apic.eoi();
}
