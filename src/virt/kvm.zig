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

// Named return type — the anonymous-struct-in-call-graph LLVM bitcode trap.
const CpuidRegs = struct { eax: u32, ebx: u32, ecx: u32, edx: u32 };

inline fn cpuid(leaf: u32) CpuidRegs {
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

// --- Per-CPU PV areas: steal time + PV EOI + kvmclock -------------------
//
// One PMM frame, carved into 128-byte per-CPU strides: the 64-byte
// steal-time struct at +0 (KVM requires 64-byte alignment), the PV EOI
// flag byte at +64 (second cacheline — KVM and this CPU both write it)
// and the 32-byte pvclock at +96 (same second cacheline: every writer of
// this stride is this vCPU's own KVM thread, so there is nothing to
// false-share with).
//
//   kvmclock (MSR 0x4B564D01 = pa|1, pvclock_vcpu_time_info): KVM keeps
//   (tsc_timestamp, system_time, mul, shift) current for this vCPU;
//   clockNs() extrapolates ns = system_time + (rdtsc - tsc_timestamp)
//   scaled — the same clock Linux runs on under KVM, host-authoritative
//   wall time with NO exit. It counts through host pauses exactly like
//   the TSC and PM_TMR do (system_time is the L1 host's boottime ns; the
//   extrapolation term is the TSC). The BSP tick's stall detector
//   (time/smi.zig) reads slot 0 in place of PM_TMR: the PIIX4 timer port
//   is emulated in QEMU userspace, so a single `inl` is a KVM_EXIT_IO
//   round trip through QEMU — under nested Hyper-V ~100k+ cycles, and
//   the tick paid two per 10 ms.
//
//   Steal time (MSR 0x4B564D03 = pa|1): KVM continuously publishes
//   nanoseconds this vCPU spent preempted (host descheduled it). This
//   is GROUND TRUTH for the host_pause/smi_stall quarantine heuristics
//   in debug/perf.zig — a measured gap minus the steal delta is real
//   guest-side stall.
//
//   PV EOI (MSR 0x4B564D04 = pa|1): before injecting an interrupt for
//   which an EOI exit would be pure overhead (edge-triggered, no IOAPIC
//   notify needed), KVM sets bit 0 of the flag. apic.eoi() test-and-
//   clears it and skips the EOI register write — host completes the EOI
//   on the next natural entry. One locked byte-op replaces one vmexit
//   per interrupt. Level-triggered IRQs (e.g. ACPI SCI) never get the
//   bit, so they still take the real EOI path by construction.
//
// S3 clears both MSRs with the rest of CPU state; re-arming rides the
// shared resume paths (apInitPerCpu for APs, reinitForS3Resume for the
// BSP). Until a CPU re-arms, its flag byte stays 0 and eoi() falls
// through to the real write — degraded, never wrong.

const MSR_KVM_SYSTEM_TIME_NEW: u32 = 0x4B564D01;
const MSR_KVM_STEAL_TIME: u32 = 0x4B564D03;
const MSR_KVM_PV_EOI_EN: u32 = 0x4B564D04;

const PV_STRIDE: u32 = 128;
const PV_EOI_OFF: u32 = 64;
const PV_CLOCK_OFF: u32 = 96;
const PV_MAX_CPUS: u32 = 4096 / PV_STRIDE;

/// pvclock_vcpu_time_info — KVM's per-vCPU clock record (kvmclock).
/// `version` is a seqlock (odd = host mid-update; 0 = never written).
const PvClock = extern struct {
    version: u32,
    pad0: u32,
    tsc_timestamp: u64,
    system_time: u64, // ns on the L1 host's boottime basis, at tsc_timestamp
    tsc_to_system_mul: u32, // ns per TSC tick × 2^32, after the shift
    tsc_shift: i8,
    flags: u8, // bit 0 PVCLOCK_TSC_STABLE_BIT, bit 1 PVCLOCK_GUEST_STOPPED
    pad1: [2]u8,
};
comptime {
    if (@sizeOf(PvClock) != 32) @compileError("KVM pvclock_vcpu_time_info must be exactly 32 bytes");
    if (PV_EOI_OFF + 1 > PV_CLOCK_OFF or PV_CLOCK_OFF % 32 != 0 or PV_CLOCK_OFF + @sizeOf(PvClock) > PV_STRIDE)
        @compileError("PV stride layout: eoi byte, then a 32-byte-aligned pvclock, inside one stride");
}

const StealTime = extern struct {
    steal: u64, // ns preempted, monotonic; torn-read-guarded by `version`
    version: u32, // seqlock: odd = host mid-update
    flags: u32,
    preempted: u8,
    pad0: [3]u8,
    pad1: [44]u8,
};
comptime {
    if (@sizeOf(StealTime) != 64) @compileError("KVM steal_time struct must be exactly 64 bytes");
}

var pv_page_va: usize = 0;
var pv_page_pa: u64 = 0;
/// Becomes true once ANY CPU armed PV EOI. Gates the eoi() fast path;
/// CPUs that haven't armed yet just see a permanently-zero flag byte.
var pv_eoi_armed: bool = false;

inline fn wrmsr(msr: u32, value: u64) void {
    asm volatile ("wrmsr"
        :
        : [_] "{ecx}" (msr),
          [_] "{eax}" (@as(u32, @truncate(value))),
          [_] "{edx}" (@as(u32, @truncate(value >> 32))),
    );
}

/// BSP-once: allocate the shared PV frame and arm the calling CPU.
/// Quiet no-op when KVM (or both features) is absent.
pub fn initPerCpuPv() void {
    if (base == 0 or pv_page_pa != 0) return;
    if (!hasStealTime() and !hasPvEoi()) return;
    const pmm = @import("../mm/pmm.zig");
    const phys = pmm.allocFrame() orelse {
        debug.klog("[kvm] initPerCpuPv: PMM exhausted, PV areas disabled\n", .{});
        return;
    };
    pv_page_va = phys.toVirt().raw();
    @memset(@as([*]u8, @ptrFromInt(pv_page_va))[0..4096], 0);
    pv_page_pa = phys.raw();
    enablePerCpuPv(@import("../cpu/smp.zig").myCpu().cpu_id);
}

/// Arm steal time + PV EOI for THIS CPU (caller passes its own cpu_id;
/// the MSRs are per-CPU). Also the S3-resume re-arm path — S3 resets
/// both MSRs. Idempotent.
pub fn enablePerCpuPv(cpu_id: u32) void {
    if (pv_page_pa == 0 or cpu_id >= PV_MAX_CPUS) return;
    const stride_pa = pv_page_pa + cpu_id * PV_STRIDE;
    if (hasStealTime()) wrmsr(MSR_KVM_STEAL_TIME, stride_pa | 1);
    if (hasPvEoi()) {
        wrmsr(MSR_KVM_PV_EOI_EN, (stride_pa + PV_EOI_OFF) | 1);
        @atomicStore(bool, &pv_eoi_armed, true, .release);
    }
    // kvmclock: KVM fills the record before it re-enters the guest after
    // the MSR write (KVM_REQ_CLOCK_UPDATE is serviced on the entry path),
    // so a read right here is the proof — version even and nonzero, a
    // nonzero multiplier. A hypervisor that swallowed the write leaves
    // the zeroed record, and the BSP slot's readiness flag stays down:
    // smi.tick then stays on PM_TMR instead of reading a dead clock.
    var clock_ok = false;
    if (hasClocksource2()) {
        wrmsr(MSR_KVM_SYSTEM_TIME_NEW, (stride_pa + PV_CLOCK_OFF) | 1);
        clock_ok = clockNs(cpu_id) != null;
        if (cpu_id == 0) @atomicStore(bool, &pvclock_bsp_ready, clock_ok, .release);
    }
    debug.klog("[kvm] cpu{d} PV armed: steal_time={s} pv_eoi={s} kvmclock={s}\n", .{
        cpu_id,
        if (hasStealTime()) "y" else "n",
        if (hasPvEoi()) "y" else "n",
        if (!hasClocksource2()) "n" else if (clock_ok) "y" else "REFUSED (record unwritten after the MSR write)",
    });
}

/// (a) The BSP's pvclock record is armed and read back sane — the gate
/// smi.tick latches its ruler on. Written by the BSP's enablePerCpuPv
/// (boot and S3 re-arm), read by any CPU.
var pvclock_bsp_ready: bool = false;

/// True once the BSP's kvmclock record has been armed and proven.
pub fn clockReady() bool {
    return @atomicLoad(bool, &pvclock_bsp_ready, .acquire);
}

/// `lfence; rdtsc` — the TSC read must not be hoisted above the pvclock
/// field loads it is paired with (Linux's rdtsc_ordered). Same two-output
/// asm signature as apic.readTsc.
inline fn rdtscOrdered() u64 {
    var lo: u32 = undefined;
    var hi: u32 = undefined;
    asm volatile ("lfence; rdtsc"
        : [lo] "={eax}" (lo),
          [hi] "={edx}" (hi),
    );
    return (@as(u64, hi) << 32) | lo;
}

/// kvmclock nanoseconds as published in `slot`'s record, extrapolated
/// with THIS CPU's TSC: system_time + ((rdtsc - tsc_timestamp) << shift)
/// * mul >> 32, all in u64 (split multiply — no u128 libcall on the BSP
/// tick). Any CPU may read any slot: the vCPUs share one TSC offset, so
/// slot 0 read from an AP is the BSP's clock to within the extrapolation
/// slope. Bounded seqlock like stealNs; null when the record is torn for
/// the whole bound, never written (version 0 / mul 0 — the MSR write was
/// refused or this slot never armed), or kvmclock is absent. A caller
/// that gets null skips its measurement — a stale clock value is no
/// lower bound of anything, unlike stale steal.
pub fn clockNs(slot: u32) ?u64 {
    if (pv_page_va == 0 or !hasClocksource2() or slot >= PV_MAX_CPUS) return null;
    const pc: *volatile PvClock = @ptrFromInt(pv_page_va + slot * PV_STRIDE + PV_CLOCK_OFF);
    var tries: u32 = 0;
    while (tries < STEAL_SEQLOCK_TRIES) : (tries += 1) {
        const v1 = pc.version;
        asm volatile ("" ::: .{ .memory = true });
        const tsc_ts = pc.tsc_timestamp;
        const sys = pc.system_time;
        const mul: u64 = pc.tsc_to_system_mul;
        const shift = pc.tsc_shift;
        const tsc = rdtscOrdered();
        asm volatile ("" ::: .{ .memory = true });
        const v2 = pc.version;
        if (v1 == v2 and (v1 & 1) == 0) {
            if (v1 == 0 or mul == 0) return null;
            var delta = tsc -| tsc_ts;
            if (shift > 0) {
                delta <<= @intCast(@min(@as(i16, shift), 63));
            } else if (shift < 0) {
                delta >>= @intCast(@min(-@as(i16, shift), 63));
            }
            const hi = (delta >> 32) *| mul;
            const lo = ((delta & 0xFFFF_FFFF) * mul) >> 32;
            return sys +| hi +| lo;
        }
        asm volatile ("pause");
    }
    return null;
}

/// EOI fast path: returns true when KVM marked the in-service interrupt
/// EOI-elidable and we claimed it — caller must then SKIP the real EOI
/// write. IRQ-context-safe (myCpu is GS-based, no exits). The unlocked
/// peek avoids the locked RMW when the bit is clear: only this CPU
/// clears the byte, and KVM only sets it before injecting into this
/// CPU, so a clear peek can't race into a missed claim.
pub inline fn pvEoiClaimSelf() bool {
    if (!@atomicLoad(bool, &pv_eoi_armed, .acquire)) return false;
    const cpu_id = @import("../cpu/smp.zig").myCpu().cpu_id;
    if (cpu_id >= PV_MAX_CPUS) return false;
    const p: *volatile u8 = @ptrFromInt(pv_page_va + cpu_id * PV_STRIDE + PV_EOI_OFF);
    if (p.* & 1 == 0) return false;
    const old = @atomicRmw(u8, @volatileCast(p), .And, 0xFE, .acq_rel);
    return (old & 1) != 0;
}

/// Nanoseconds `cpu_id` has spent host-preempted, per KVM's accounting.
/// Seqlock read (version odd = host mid-update). 0 when unavailable.
pub fn stealNs(cpu_id: u32) u64 {
    if (pv_page_va == 0 or !hasStealTime() or cpu_id >= PV_MAX_CPUS) return 0;
    const st: *volatile StealTime = @ptrFromInt(pv_page_va + cpu_id * PV_STRIDE);
    // Bounded seqlock: the host writes version/steal/version around each
    // update, and if it is preempted between the two version writes the
    // reader would spin for that whole preemption — with IF=0 in IRQ0
    // (watchdog.peerCheck, smi.tick) and per poll iteration in every
    // pause.Epoch observation. After the bound, the last value this vCPU's
    // slot was read consistently at: steal is cumulative and monotonic, so
    // a stale reading is a LOWER bound — every consumer under-credits by
    // the torn window and none sees a wrapped delta or a bogus 0 baseline
    // (a 0 at an Epoch capture would charge the whole boot's steal to that
    // wait).
    var tries: u32 = 0;
    while (tries < STEAL_SEQLOCK_TRIES) : (tries += 1) {
        const v1 = st.version;
        asm volatile ("" ::: .{ .memory = true });
        const s = st.steal;
        asm volatile ("" ::: .{ .memory = true });
        const v2 = st.version;
        if (v1 == v2 and (v1 & 1) == 0) {
            @atomicStore(u64, &steal_last_good[cpu_id], s, .monotonic);
            return s;
        }
        asm volatile ("pause");
    }
    return @atomicLoad(u64, &steal_last_good[cpu_id], .monotonic);
}

/// ~100 µs of `pause` spins before stealNs settles for the last good value.
const STEAL_SEQLOCK_TRIES: u32 = 1024;
/// (a) Last consistently-read steal per vCPU slot — stealNs's answer on a
/// torn read. Any CPU may read any slot (the watchdog reads peers'), hence
/// atomic accesses; the values only ever grow.
var steal_last_good: [PV_MAX_CPUS]u64 = [_]u64{0} ** PV_MAX_CPUS;
