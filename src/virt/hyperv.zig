// Hyper-V (TLFS) enlightenment detection + the four features we actually
// use. QEMU/KVM exposes a Hyper-V-compatible CPUID interface when launched
// with `-cpu host,hv-time,hv-frequencies,hv-vapic,...`. The signature lives
// at CPUID 0x40000000.{EBX,ECX,EDX} = "Microsoft Hv".
//
// Active features (each gated on its own CPUID feature bit):
//
//   1. Frequency MSRs (CPUID 0x40000003.EAX bit 11)
//      HV_X64_MSR_TSC_FREQUENCY / APIC_FREQUENCY — one rdmsr each instead
//      of the 10ms HPET calibration gate. See apic.calibrateTimerHpet.
//
//   2. Crash MSRs (CPUID 0x40000003.EDX bit 10)
//      P0..P4 hold context (panic origin, msg, rsp); writing CRASH_CTL with
//      bit 63 set tells the host to surface a BugCheck event in the Hyper-V
//      Event Viewer. Wired into main.zig panic() so a kernel crash on a
//      real Hyper-V box is post-mortem-readable from the host.
//
//   3. Hypercall page (CPUID 0x40000003.EAX bit 5)
//      Required infrastructure for any actual hypercall. We allocate a 4KB
//      frame, write its GPA | Enable into HV_X64_MSR_HYPERCALL; the host
//      overlays the VMCALL/VMMCALL thunk into the page. Callers invoke it
//      with the RCX/RDX/R8 ABI from TLFS § 3.10.
//
//   4. HvCallFlushVirtualAddressSpace (call code 0x0002, requires #3)
//      Single hypercall flushes all VPs' TLBs for a given address space —
//      replaces our IPI fan-out in tlb.shootdownAll. Falls back to the IPI
//      path when the hypercall isn't installed.
//
//   5. Reset MSR (CPUID 0x40000003.EAX bit 7)
//      HV_X64_MSR_RESET = 1 triggers a clean hypervisor-mediated reboot —
//      preferred over PCI 0xCF9 / 8042 KBD pulse / triple-fault.
//
// Reference: Microsoft Hypervisor Top-Level Functional Specification
// (TLFS) §§ 2 (CPUID), 3 (MSR map + hypercall ABI), 7 (privileges),
// 8 (call codes), 12.7 (crash MSRs).

const std = @import("std");
const debug = @import("../debug/debug.zig");

const HV_CPUID_VENDOR_AND_MAX = 0x40000000;
const HV_CPUID_FEATURES = 0x40000003;

// Synthetic MSRs (TLFS § 3.4 & 12.7)
const HV_MSR_GUEST_OS_ID = 0x40000000;
const HV_MSR_HYPERCALL = 0x40000001;
const HV_MSR_RESET = 0x40000003;
const HV_MSR_TSC_FREQUENCY = 0x40000022;
const HV_MSR_APIC_FREQUENCY = 0x40000023;
const HV_MSR_CRASH_P0 = 0x40000100;
const HV_MSR_CRASH_P1 = 0x40000101;
const HV_MSR_CRASH_P2 = 0x40000102;
const HV_MSR_CRASH_P3 = 0x40000103;
const HV_MSR_CRASH_P4 = 0x40000104;
const HV_MSR_CRASH_CTL = 0x40000105;
const HV_CRASH_CTL_NOTIFY: u64 = 1 << 63;

// Partition-privilege bits in CPUID 0x40000003.EAX (TLFS § 7.4).
const HV_FEATURE_HYPERCALL_MSR: u32 = 1 << 5;
const HV_FEATURE_RESET_MSR: u32 = 1 << 7;
const HV_FEATURE_FREQUENCY_MSRS: u32 = 1 << 11;

// Misc features in CPUID 0x40000003.EDX.
const HV_FEATURE_CRASH_MSRS_EDX: u32 = 1 << 10;

// Hypercall call codes (TLFS § 8.1).
const HV_CALL_FLUSH_VIRTUAL_ADDRESS_SPACE: u64 = 0x0002;

// HV_INPUT_FLUSH_VIRTUAL_ADDRESS_SPACE flags (TLFS § 8.4).
pub const HV_FLUSH_ALL_PROCESSORS: u64 = 1 << 0;
pub const HV_FLUSH_ALL_VIRTUAL_ADDRESS_SPACES: u64 = 1 << 1;
pub const HV_FLUSH_NON_GLOBAL_MAPPINGS_ONLY: u64 = 1 << 2;

var available: bool = false;
var has_frequency_msrs: bool = false;
var has_hypercall_msrs: bool = false;
var has_reset_msr: bool = false;
var has_crash_msrs: bool = false;

// Hypercall plumbing. `hypercall_page` is a kernel VA aliased onto the
// hypercall-thunk frame; calling into it issues VMCALL/VMMCALL with the
// RCX/RDX/R8 ABI. `flush_input_*` is a per-shootdown input struct;
// serialized externally by tlb.shootdown_lock so one shared page works.
var hypercall_page: usize = 0;
var flush_input_va: usize = 0;
var flush_input_pa: u64 = 0;

const FlushInput = extern struct {
    address_space: u64,
    flags: u64,
    processor_mask: u64,
};

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

inline fn wrmsr(msr: u32, value: u64) void {
    const lo: u32 = @truncate(value);
    const hi: u32 = @truncate(value >> 32);
    asm volatile ("wrmsr"
        :
        : [_] "{ecx}" (msr),
          [_] "{eax}" (lo),
          [_] "{edx}" (hi),
    );
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
    has_hypercall_msrs = (feat.eax & HV_FEATURE_HYPERCALL_MSR) != 0;
    has_reset_msr = (feat.eax & HV_FEATURE_RESET_MSR) != 0;
    has_crash_msrs = (feat.edx & HV_FEATURE_CRASH_MSRS_EDX) != 0;
    debug.klog(
        "[hyperv] features.eax=0x{X} edx=0x{X} freq={s} hcall={s} reset={s} crash={s}\n",
        .{
            feat.eax, feat.edx,
            if (has_frequency_msrs) "yes" else "no",
            if (has_hypercall_msrs) "yes" else "no",
            if (has_reset_msr) "yes" else "no",
            if (has_crash_msrs) "yes" else "no",
        },
    );
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

// --- Crash MSRs (TLFS § 12.7) ----------------------------------------

/// Surface a kernel panic on the host's Hyper-V crash channel. P0..P4 are
/// freeform context words; writing CRASH_CTL with the NOTIFY bit set tells
/// the host a crash has been published — on Windows this becomes a BugCheck
/// entry in Event Viewer (source: "Hyper-V-Hypervisor"). No-op when crash
/// MSRs aren't exposed (KVM-TCG, real hardware). Safe to call from @panic:
/// no allocations, no locks, just five wrmsrs.
pub fn writeCrash(p0: u64, p1: u64, p2: u64, p3: u64, p4: u64) void {
    if (!has_crash_msrs) return;
    wrmsr(HV_MSR_CRASH_P0, p0);
    wrmsr(HV_MSR_CRASH_P1, p1);
    wrmsr(HV_MSR_CRASH_P2, p2);
    wrmsr(HV_MSR_CRASH_P3, p3);
    wrmsr(HV_MSR_CRASH_P4, p4);
    wrmsr(HV_MSR_CRASH_CTL, HV_CRASH_CTL_NOTIFY);
}

// --- Hypercall page + flush hypercall --------------------------------

/// Pack up to 8 bytes of `msg` starting at `offset` into a u64 (LE),
/// zero-padded past the end of the message. Used by panic() to fit the
/// message into the crash MSR context words (P3 = offset 0, P4 = offset 8).
pub fn packMsg(msg: []const u8, offset: usize) u64 {
    var out: u64 = 0;
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        const src_i = offset + i;
        if (src_i >= msg.len) break;
        out |= @as(u64, msg[src_i]) << @intCast(i * 8);
    }
    return out;
}

/// Install the hypercall page + flush-input scratch frame. Call once
/// from BSP after PMM is up. Idempotent: subsequent calls are no-ops.
/// Quiet no-op if Hyper-V isn't present or doesn't expose hypercalls.
pub fn enableHypercalls() void {
    if (!available or !has_hypercall_msrs or hypercall_page != 0) return;

    const pmm = @import("../mm/pmm.zig");
    const paging = @import("../mm/paging.zig");

    // GUEST_OS_ID — required write before HYPERCALL MSR (TLFS § 3.6).
    // Format: Vendor[63:48] | OSType[47:40] | OSVer[39:0]. We claim vendor=1
    // (Microsoft-OS sentinel — works on QEMU+KVM) + a unique OSType so the
    // host's Event Viewer can tell us apart from Linux/Windows guests.
    const guest_id: u64 = (@as(u64, 1) << 48) | (@as(u64, 0x5A) << 40) | 0x1;
    wrmsr(HV_MSR_GUEST_OS_ID, guest_id);

    // Allocate the thunk page. Physmap pages are mapped with NX clear
    // (boot.asm uses 0x183 = G|RW|PS|P, no bit 63) so calling into it
    // via paging.physToVirt(phys) is legal.
    const phys_call = pmm.allocFrame() orelse {
        debug.klog("[hyperv] enableHypercalls: PMM exhausted, hypercalls disabled\n", .{});
        return;
    };
    const call_va = paging.physToVirt(phys_call);
    @memset(@as([*]u8, @ptrFromInt(call_va))[0..4096], 0);

    // Enable: write phys | bit 0. Host overlays the VMCALL/VMMCALL thunk
    // into the page; subsequent calls into call_va issue the hypercall.
    wrmsr(HV_MSR_HYPERCALL, phys_call | 1);
    hypercall_page = call_va;

    // Pre-allocate the flush input struct page (24-byte struct lives in
    // it; the rest of the page is wasted but a frame is the smallest
    // unit we can pin). Single shared instance is fine because the TLB
    // shootdown caller already holds tlb.shootdown_lock.
    const phys_in = pmm.allocFrame() orelse {
        debug.klog("[hyperv] enableHypercalls: PMM exhausted for input page\n", .{});
        return;
    };
    flush_input_va = paging.physToVirt(phys_in);
    flush_input_pa = phys_in;
    @memset(@as([*]u8, @ptrFromInt(flush_input_va))[0..4096], 0);

    debug.klog("[hyperv] hypercall page @ gpa=0x{X} input @ gpa=0x{X}\n", .{ phys_call, phys_in });
}

pub fn hasHypercalls() bool {
    return hypercall_page != 0;
}

/// Invoke a slow hypercall. RCX = call_code, RDX = input GPA, R8 = output
/// GPA. R9-R11 are clobbered per TLFS § 3.10. Returns HV_STATUS in the
/// low 16 bits of RAX (0 == success).
///
/// RCX/RDX/R8 are declared as OUTPUTS too (same-register in+out, the
/// pattern cpuid() above uses): the hypercall ABI makes them volatile —
/// the hypervisor may hand them back clobbered — so passing them as plain
/// inputs would promise LLVM they survive the call, a latent miscompile
/// the moment the optimizer reuses one afterwards. (Linux's
/// hv_do_hypercall marks them "+c"/"+d" for the same reason.)
inline fn hypercall(call_code: u64, input_gpa: u64, output_gpa: u64) u64 {
    var status: u64 = undefined;
    var rcx_out: u64 = undefined;
    var rdx_out: u64 = undefined;
    var r8_out: u64 = undefined;
    asm volatile ("callq *%[page]"
        : [_] "={rax}" (status),
          [_] "={rcx}" (rcx_out),
          [_] "={rdx}" (rdx_out),
          [_] "={r8}" (r8_out),
        : [_] "{rcx}" (call_code),
          [_] "{rdx}" (input_gpa),
          [_] "{r8}" (output_gpa),
          [page] "r" (hypercall_page),
        : .{ .r9 = true, .r10 = true, .r11 = true, .memory = true, .cc = true });
    return status;
}

/// Flush ALL entries (global included — NON_GLOBAL_MAPPINGS_ONLY is not
/// set) for `address_space_cr3` on every VP in the partition via a single
/// hypercall — replaces the per-CPU IPI fan-out in tlb.shootdownAll.
/// Caller must hold tlb.shootdown_lock (we share one input page).
///
/// Returns true on success; false means caller should fall back to IPI.
/// Possible failure modes: hypercall page not installed, host returned
/// non-zero HV_STATUS.
pub fn flushAllProcessors(address_space_cr3: u64) bool {
    if (hypercall_page == 0 or flush_input_va == 0) return false;
    const inp: *FlushInput = @ptrFromInt(flush_input_va);
    inp.address_space = address_space_cr3;
    inp.flags = HV_FLUSH_ALL_PROCESSORS;
    inp.processor_mask = 0;
    const status = hypercall(HV_CALL_FLUSH_VIRTUAL_ADDRESS_SPACE, flush_input_pa, 0);
    return (status & 0xFFFF) == 0;
}

// --- Reset MSR --------------------------------------------------------

/// Trigger a clean hypervisor-mediated reboot. Per TLFS § 3.5 the write
/// is synchronous: we don't return if the MSR is honored. Returns false
/// when the MSR isn't available so the caller can fall back to ACPI /
/// PCI 0xCF9 / 8042 KBD pulse.
pub fn tryReset() bool {
    if (!has_reset_msr) return false;
    wrmsr(HV_MSR_RESET, 1);
    // Reaching this line at all means the host ignored the write (an
    // honored reset never returns) — report failure so the caller's
    // fallback chain (ACPI / 0xCF9 / 8042) keeps going.
    return false;
}
