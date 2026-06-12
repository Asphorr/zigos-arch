// src/virt/kvm.zig — KVM paravirt interface detection (guest side).
//
// KVM publishes its PV feature leaf at CPUID 0x40000000 ("KVMKVMKVM\0\0\0"
// in EBX/ECX/EDX), but QEMU RELOCATES it when any Hyper-V enlightenment
// (`-cpu host,hv-*`) is on the command line: 0x40000000 then carries
// "Microsoft Hv" (consumed by virt/hyperv.zig) and KVM moves up to
// 0x40000100 so both interfaces stay discoverable. Linux handles this by
// scanning bases 0x40000000..0x40010000 in 0x100 steps; we do the same.
//
// Feature bits live at base+1 EAX (KVM API docs, "KVM CPUID bits"). This
// module only DETECTS and reports — each consumer (PV EOI, steal time,
// PV unhalt, ...) activates its own feature in a later, separate step,
// gated on the getters below.
//
// Reference: Documentation/virt/kvm/cpuid.rst in the Linux tree.

const std = @import("std");
const debug = @import("../debug/debug.zig");

// KVM_CPUID_FEATURES (base+1) EAX bits we care about.
const KVM_FEATURE_CLOCKSOURCE: u32 = 1 << 0; // MSR_KVM_SYSTEM_TIME (legacy)
const KVM_FEATURE_CLOCKSOURCE2: u32 = 1 << 3; // MSR_KVM_SYSTEM_TIME_NEW
const KVM_FEATURE_STEAL_TIME: u32 = 1 << 5; // MSR_KVM_STEAL_TIME
const KVM_FEATURE_PV_EOI: u32 = 1 << 6; // MSR_KVM_PV_EOI_EN
const KVM_FEATURE_PV_UNHALT: u32 = 1 << 7; // KVM_HC_KICK_CPU hypercall
const KVM_FEATURE_PV_TLB_FLUSH: u32 = 1 << 9; // flush via steal_time.preempted
const KVM_FEATURE_PV_SEND_IPI: u32 = 1 << 11; // KVM_HC_SEND_IPI hypercall
const KVM_FEATURE_PV_SCHED_YIELD: u32 = 1 << 13; // KVM_HC_SCHED_YIELD hypercall
const KVM_FEATURE_CLOCKSOURCE_STABLE: u32 = 1 << 24; // no need to re-read on migrate

var base: u32 = 0; // 0 = KVM leaf not found
var features_eax: u32 = 0;

inline fn cpuid(leaf: u32) struct { eax: u32, ebx: u32, ecx: u32, edx: u32 } {
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
          [_] "{ecx}" (@as(u32, 0)),
    );
    return .{ .eax = eax, .ebx = ebx, .ecx = ecx, .edx = edx };
}

/// One-shot detection; call on the BSP after hyperv.detect(). Pure CPUID
/// reads, no MSR writes — safe everywhere including bare metal (gated on
/// the hypervisor-present bit like hyperv.detect()).
pub fn detect() void {
    if ((cpuid(1).ecx & (1 << 31)) == 0) return; // bare metal: leaves 0x4xxxxxxx undefined

    var b: u32 = 0x40000000;
    while (b <= 0x40010000) : (b += 0x100) {
        const r = cpuid(b);
        var sig: [12]u8 = undefined;
        inline for (.{ r.ebx, r.ecx, r.edx }, 0..) |reg, i| {
            sig[i * 4 + 0] = @truncate(reg);
            sig[i * 4 + 1] = @truncate(reg >> 8);
            sig[i * 4 + 2] = @truncate(reg >> 16);
            sig[i * 4 + 3] = @truncate(reg >> 24);
        }
        if (std.mem.eql(u8, sig[0..9], "KVMKVMKVM")) {
            base = b;
            break;
        }
        // An all-zero EBX means "no more hypervisor leaves here" on real
        // KVM/QEMU stacks, but Hyper-V pads its range — keep scanning the
        // full window; it's 256 CPUIDs once at boot.
    }

    if (base == 0) {
        debug.klog("[kvm] no KVM signature in 0x40000000..0x40010000 (not under KVM, or masked)\n", .{});
        return;
    }

    features_eax = cpuid(base + 1).eax;
    const f = features_eax;
    debug.klog(
        "[kvm] leaf @0x{X} features=0x{X}: clock2={s} stable={s} steal={s} pv_eoi={s} unhalt={s} pv_tlb={s} pv_ipi={s} sched_yield={s}\n",
        .{
            base,                                              f,
            if (f & KVM_FEATURE_CLOCKSOURCE2 != 0) "y" else "n",
            if (f & KVM_FEATURE_CLOCKSOURCE_STABLE != 0) "y" else "n",
            if (f & KVM_FEATURE_STEAL_TIME != 0) "y" else "n",
            if (f & KVM_FEATURE_PV_EOI != 0) "y" else "n",
            if (f & KVM_FEATURE_PV_UNHALT != 0) "y" else "n",
            if (f & KVM_FEATURE_PV_TLB_FLUSH != 0) "y" else "n",
            if (f & KVM_FEATURE_PV_SEND_IPI != 0) "y" else "n",
            if (f & KVM_FEATURE_PV_SCHED_YIELD != 0) "y" else "n",
        },
    );

    // One-line x2APIC/TSC-deadline capability summary while we're here —
    // the L1 zigvm host hides x2APIC from its own /proc/cpuinfo, but KVM's
    // in-kernel LAPIC emulates it for guests regardless; this line settles
    // what WE actually see.
    const c1 = cpuid(1).ecx;
    debug.klog("[kvm] cpuid.1.ecx: x2apic={s} tsc_deadline={s}\n", .{
        if (c1 & (1 << 21) != 0) "y" else "n",
        if (c1 & (1 << 24) != 0) "y" else "n",
    });
}

pub fn isAvailable() bool {
    return base != 0;
}

/// CPUID base the KVM leaf was found at (0x40000000 or relocated).
/// Needed by consumers that issue KVM hypercalls or read base-relative
/// leaves. 0 when KVM wasn't detected.
pub fn leafBase() u32 {
    return base;
}

pub fn hasPvEoi() bool {
    return features_eax & KVM_FEATURE_PV_EOI != 0;
}

pub fn hasStealTime() bool {
    return features_eax & KVM_FEATURE_STEAL_TIME != 0;
}

pub fn hasPvUnhalt() bool {
    return features_eax & KVM_FEATURE_PV_UNHALT != 0;
}

pub fn hasPvSendIpi() bool {
    return features_eax & KVM_FEATURE_PV_SEND_IPI != 0;
}

pub fn hasClocksource2() bool {
    return features_eax & KVM_FEATURE_CLOCKSOURCE2 != 0;
}
