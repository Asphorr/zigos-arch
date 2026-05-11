// Hyper-V (TLFS) enlightenment detection.
//
// QEMU/KVM exposes a Hyper-V-compatible CPUID interface when launched with
// `-cpu host,hv-time,hv-frequencies,...`. The signature lives at CPUID
// 0x40000000.{EBX,ECX,EDX} = "Microsoft Hv". We currently use just one
// enlightenment: the HV_X64_MSR_TSC_FREQUENCY / HV_X64_MSR_APIC_FREQUENCY
// MSR pair (gated by feature bit 11 in CPUID 0x40000003.EAX). Reading
// these is one rdmsr each, vs the HPET-gated 10 ms calibration window in
// apic.calibrateTimerHpet — saves ~10 ms of wall time at boot per timer
// reference and removes a busy-wait gate.
//
// Future enlightenments (synthetic timers, hypercall-based IPIs, TLB
// shootdown via HvCallFlushVirtualAddressSpace, reference TSC page) all
// hang off the same detection — light up `available` here and add the
// per-feature MSR/hypercall code in their own callers.
//
// Reference: Microsoft Hypervisor TLFS, ch.2 (CPUID), ch.3 (MSR map).

const std = @import("std");
const debug = @import("../debug/debug.zig");

const HV_CPUID_VENDOR_AND_MAX = 0x40000000;
const HV_CPUID_FEATURES = 0x40000003;

const HV_MSR_TSC_FREQUENCY = 0x40000022;
const HV_MSR_APIC_FREQUENCY = 0x40000023;

/// CPUID 0x40000003.EAX feature bits we care about. Add as we light up
/// new enlightenments.
const HV_FEATURE_FREQUENCY_MSRS: u32 = 1 << 11;

var available: bool = false;
var has_frequency_msrs: bool = false;

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

inline fn rdmsr(msr: u32) u64 {
    var lo: u32 = undefined;
    var hi: u32 = undefined;
    asm volatile ("rdmsr"
        : [_] "={eax}" (lo),
          [_] "={edx}" (hi),
        : [_] "{ecx}" (msr),
    );
    return (@as(u64, hi) << 32) | @as(u64, lo);
}

/// Check the standard hypervisor-present bit (CPUID 1.ECX[31]). When this
/// is clear, the hypervisor leaves at 0x40000000+ are not architecturally
/// guaranteed to be readable — some real CPUs return junk for unknown
/// CPUID leaves. Skip detection entirely on bare metal.
fn hypervisorPresent() bool {
    return (cpuid(1, 0).ecx & (1 << 31)) != 0;
}

/// One-shot detection. Safe to call multiple times. Logs the signature
/// and the features we recognize. Call before `apic.init()` so timer
/// calibration can use Hyper-V frequency MSRs instead of the HPET gate.
pub fn detect() void {
    if (!hypervisorPresent()) {
        debug.klog("[hyperv] no hypervisor (CPUID 1.ECX bit 31 clear) — running on bare metal\n", .{});
        return;
    }

    const r = cpuid(HV_CPUID_VENDOR_AND_MAX, 0);
    var sig: [12]u8 = undefined;
    inline for (.{ r.ebx, r.ecx, r.edx }, 0..) |reg, i| {
        sig[i * 4 + 0] = @truncate(reg);
        sig[i * 4 + 1] = @truncate(reg >> 8);
        sig[i * 4 + 2] = @truncate(reg >> 16);
        sig[i * 4 + 3] = @truncate(reg >> 24);
    }

    debug.klog("[hyperv] cpuid 0x40000000: vendor=\"{s}\" max_leaf=0x{X}\n", .{ sig, r.eax });

    if (!std.mem.eql(u8, &sig, "Microsoft Hv")) {
        debug.klog("[hyperv] not Microsoft Hv — Hyper-V emulation disabled (try -cpu host,hv-passthrough)\n", .{});
        return;
    }
    available = true;

    if (r.eax < HV_CPUID_FEATURES) {
        debug.klog("[hyperv] features leaf 0x{X} not exposed (max_leaf=0x{X})\n", .{ HV_CPUID_FEATURES, r.eax });
        return;
    }

    const feat = cpuid(HV_CPUID_FEATURES, 0);
    has_frequency_msrs = (feat.eax & HV_FEATURE_FREQUENCY_MSRS) != 0;
    debug.klog("[hyperv] features.eax=0x{X} frequency_msrs={s}\n", .{
        feat.eax,
        if (has_frequency_msrs) "yes" else "no",
    });
}

pub fn isAvailable() bool {
    return available;
}

pub fn hasFrequencyMsrs() bool {
    return has_frequency_msrs;
}

/// Guest TSC frequency in Hz. Only valid when `hasFrequencyMsrs()` is true.
/// Reading it on a host that lacks the MSR will #GP.
pub fn tscFrequencyHz() u64 {
    return rdmsr(HV_MSR_TSC_FREQUENCY);
}

/// LAPIC bus frequency in Hz (the rate the LAPIC counter decrements at,
/// before the divide-by-N stage in LAPIC_TIMER_DCR).
pub fn apicFrequencyHz() u64 {
    return rdmsr(HV_MSR_APIC_FREQUENCY);
}
