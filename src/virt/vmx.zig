// src/virt/vmx.zig — Intel VT-x (VMX) hypervisor support.
//
// This is the HOST side of virtualization: ZigOS running a guest under
// ITSELF. It is the mirror of virt/hyperv.zig, which is the GUEST side
// (ZigOS running under someone else's hypervisor). Together they close the
// loop — the OS that knows how to be virtualized learns how to virtualize.
//
// === Phase 0 (this file, for now): capability detection ONLY ===
//
// We probe whether VMX is actually usable and log a verdict. We do NOT
// execute VMXON yet — that, plus VMCS setup, EPT, and the first VMLAUNCH,
// is Phase 1+, gated on this probe coming back USABLE. Phase 0 is pure
// CPUID + capability-MSR reads: no writes, no state change, safe to call
// unconditionally at boot, and cannot fault on any Intel part that
// advertises VMX (it short-circuits on everything else).
//
// Whether VMX even reaches us is a property of the layers BELOW ZigOS:
//   * QEMU must run with `-cpu host` (so the vmx feature passes through), and
//   * the host KVM must have nested virt on (modprobe kvm_intel nested=1), and
//   * if zigvm is itself a Hyper-V guest, that VM needs
//     `Set-VMProcessor -ExposeVirtualizationExtensions $true`.
// If any layer withholds VMX, CPUID.1:ECX.VMX reads 0 and we log that — no
// harm done, we just can't be a hypervisor in this environment.
//
// References: Intel SDM Vol 3C ch. 23-24 (VMX/VMCS), Appendix A (the
// capability-MSR map decoded below).

const debug = @import("../debug/debug.zig");
const pmm = @import("../mm/pmm.zig");
const paging = @import("../mm/paging.zig");

// --- CPUID / MSR encodings -------------------------------------------

const CPUID_1_ECX_VMX: u32 = 1 << 5; // VT-x present (Intel; AMD-V is elsewhere)

const MSR_IA32_FEATURE_CONTROL: u32 = 0x3A;
const FC_LOCK: u64 = 1 << 0; // bit 0: settings locked by firmware
const FC_VMXON_OUTSIDE_SMX: u64 = 1 << 2; // bit 2: VMXON allowed outside SMX

// VMX capability MSRs (SDM Vol 3D, App. A). All defined when VMX=1, so the
// reads below are safe once we've confirmed the CPUID bit — except the two
// noted as conditional, which we gate explicitly.
const MSR_IA32_VMX_BASIC: u32 = 0x480;
const MSR_IA32_VMX_PROCBASED_CTLS: u32 = 0x482;
const MSR_IA32_VMX_PROCBASED_CTLS2: u32 = 0x48B; // present iff primary bit 31 allowed

// Phase 1: CR fixed-bit MSRs (SDM 23.8 / App. A.7-A.8) + CR4.VMXE bit.
// Before VMXON, CR0/CR4 must have VMX's must-be-1 bits set (FIXED0) and its
// must-be-0 bits clear (FIXED1 enumerates the allowed-1 set), and CR4.VMXE
// must be 1.
const MSR_IA32_VMX_CR0_FIXED0: u32 = 0x486;
const MSR_IA32_VMX_CR0_FIXED1: u32 = 0x487;
const MSR_IA32_VMX_CR4_FIXED0: u32 = 0x488;
const MSR_IA32_VMX_CR4_FIXED1: u32 = 0x489;
const CR4_VMXE: u64 = 1 << 13;

// IA32_VMX_BASIC bit 55: the "true" control MSRs (0x48D..0x490) are present.
const BASIC_TRUE_CTLS_BIT: u6 = 55;
// IA32_VMX_PROCBASED_CTLS allowed-1 for "activate secondary controls" is
// bit 31 of the primary controls == bit 63 of the 64-bit capability MSR.
const PROC_SECONDARY_BIT: u6 = 63;
// In PROCBASED_CTLS2 the allowed-1 set is the high dword: EPT is bit 1 and
// unrestricted-guest is bit 7, i.e. 32+1 / 32+7 in the 64-bit MSR.
const PROC2_EPT_BIT: u6 = 32 + 1;
const PROC2_UNRESTRICTED_BIT: u6 = 32 + 7;

// --- Probed state (consumed by Phase 1 later) ------------------------

pub var vmx_present: bool = false; // CPUID says VT-x exists
pub var usable: bool = false; // present AND firmware permits VMXON-outside-SMX
pub var feature_control_locked: bool = false;
pub var vmcs_revision: u32 = 0;
pub var vmcs_region_size: u32 = 0;
pub var has_true_ctls: bool = false;
pub var has_ept: bool = false;
pub var has_unrestricted_guest: bool = false;

// Phase 1 state: the VMXON region (one page, revision-stamped) and whether
// the BSP is currently in VMX root operation. The region is allocated once
// and retained for Phase 2 (it stays the VMXON region for VMX's lifetime).
var vmxon_region_phys: usize = 0;
var vmxon_region_va: usize = 0;
pub var in_vmx_operation: bool = false;

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

inline fn yn(b: bool) []const u8 {
    return if (b) "yes" else "no";
}

/// One-shot VMX capability probe. Call once on the BSP at boot, after CPUID
/// feature detection. Logs a one-line verdict and sets the module `pub var`s
/// for Phase 1 to consume. Reads only — never faults on an Intel part that
/// advertises VMX, and returns early on anything that doesn't.
pub fn detect() void {
    // 1. Is VT-x exposed to us at all? A clear bit just means "not VMX"
    //    (AMD-V advertises through a different leaf), so don't probe further.
    if ((cpuid(1, 0).ecx & CPUID_1_ECX_VMX) == 0) {
        debug.klog("[vmx] CPUID.1:ECX.VMX clear — VT-x not exposed to ZigOS. " ++
            "Need `-cpu host` + nested KVM (kvm_intel nested=1)" ++
            ", and ExposeVirtualizationExtensions if zigvm is a Hyper-V guest.\n", .{});
        return;
    }
    vmx_present = true;

    // 2. Firmware lock. IA32_FEATURE_CONTROL (0x3A) is architectural on every
    //    VMX-capable Intel part, so this rdmsr is safe now.
    //      locked + VMXON-outside-SMX set -> good, use as-is.
    //      unlocked                       -> Phase 1 sets+locks it itself.
    //      locked WITHOUT that bit         -> VMX disabled below us, dead end.
    const fc = rdmsr(MSR_IA32_FEATURE_CONTROL);
    feature_control_locked = (fc & FC_LOCK) != 0;
    const vmxon_allowed = (fc & FC_VMXON_OUTSIDE_SMX) != 0;

    // 3. VMCS geometry (revision id + region byte size) — Phase 1 stamps the
    //    revision into the VMXON region and every VMCS, and sizes them here.
    const basic = rdmsr(MSR_IA32_VMX_BASIC);
    vmcs_revision = @truncate(basic & 0x7FFF_FFFF);
    vmcs_region_size = @truncate((basic >> 32) & 0x1FFF);
    has_true_ctls = (basic & (@as(u64, 1) << BASIC_TRUE_CTLS_BIT)) != 0;

    // 4. Does the "real-mode guest" first milestone exist? It wants secondary
    //    proc-based controls -> EPT + unrestricted guest. Probe safely: only
    //    read PROCBASED_CTLS2 if the primary controls allow activating
    //    secondary controls, else that MSR can #GP.
    const procbased = rdmsr(MSR_IA32_VMX_PROCBASED_CTLS);
    if ((procbased & (@as(u64, 1) << PROC_SECONDARY_BIT)) != 0) {
        const proc2 = rdmsr(MSR_IA32_VMX_PROCBASED_CTLS2);
        has_ept = (proc2 & (@as(u64, 1) << PROC2_EPT_BIT)) != 0;
        has_unrestricted_guest = (proc2 & (@as(u64, 1) << PROC2_UNRESTRICTED_BIT)) != 0;
    }

    // VMX is usable iff present AND (firmware permits VMXON-outside-SMX, or
    // hasn't locked the MSR yet — in which case Phase 1 can enable it).
    usable = !feature_control_locked or vmxon_allowed;

    debug.klog("[vmx] VT-x present. feature_ctl=0x{X} (locked={s} vmxon_outside_smx={s}) " ++
        "vmcs_rev=0x{X} vmcs_size={d}B true_ctls={s} ept={s} unrestricted_guest={s}\n", .{
        fc,                  yn(feature_control_locked), yn(vmxon_allowed),
        vmcs_revision,       vmcs_region_size,           yn(has_true_ctls),
        yn(has_ept),         yn(has_unrestricted_guest),
    });
    debug.klog("[vmx] verdict: {s}\n", .{
        if (usable)
            (if (has_ept and has_unrestricted_guest)
                "USABLE — Phase 1 can target a real-mode guest (EPT + unrestricted guest available)"
            else
                "USABLE — but no EPT/unrestricted-guest; first guest must run in protected mode")
        else
            "BLOCKED — IA32_FEATURE_CONTROL locked with VMX off; can't enable from here",
    });
}

pub fn isUsable() bool {
    return usable;
}

// --- Phase 1: enter/exit VMX root operation (VMXON / VMXOFF) ----------

inline fn readCr0() u64 {
    return asm volatile ("mov %%cr0, %[ret]"
        : [ret] "=r" (-> u64),
    );
}
inline fn writeCr0(v: u64) void {
    asm volatile ("mov %[val], %%cr0"
        :
        : [val] "r" (v),
    );
}
inline fn readCr4() u64 {
    return asm volatile ("mov %%cr4, %[ret]"
        : [ret] "=r" (-> u64),
    );
}
inline fn writeCr4(v: u64) void {
    asm volatile ("mov %[val], %%cr4"
        :
        : [val] "r" (v),
    );
}

/// Phase 1: enter and then cleanly exit VMX root operation on the BSP,
/// proving the VMXON/VMXOFF cycle works end-to-end. Gated on the Phase 0
/// verdict (`usable`); BSP-only by call site (single-threaded boot, before
/// AP startup); idempotent. Keeps the VMXON region + CR4.VMXE for Phase 2,
/// and restores everything else.
///
/// HIGH-BLAST-RADIUS: writes CR4 (and possibly CR0) and executes VMXON. A
/// wrong fixed-bit or a malformed region is a #GP/#UD or a VMfail. We force
/// CR0/CR4 to VMX-legal values via IA32_VMX_CRx_FIXED0/1 and set CR4.VMXE
/// first, then check CF — the only failure signal before a VMCS exists.
pub fn enableBsp() void {
    if (!usable) {
        debug.klog("[vmx] enableBsp: skipped — Phase 0 verdict not USABLE\n", .{});
        return;
    }
    if (vmxon_region_phys != 0) return; // already done

    // 1. Force CR0/CR4 to VMX-legal values and set CR4.VMXE.
    const cr0_f0 = rdmsr(MSR_IA32_VMX_CR0_FIXED0);
    const cr0_f1 = rdmsr(MSR_IA32_VMX_CR0_FIXED1);
    const cr4_f0 = rdmsr(MSR_IA32_VMX_CR4_FIXED0);
    const cr4_f1 = rdmsr(MSR_IA32_VMX_CR4_FIXED1);

    const orig_cr0 = readCr0();
    const new_cr0 = (orig_cr0 | cr0_f0) & cr0_f1;
    if (new_cr0 != orig_cr0) writeCr0(new_cr0);

    const orig_cr4 = readCr4();
    const new_cr4 = ((orig_cr4 | cr4_f0) & cr4_f1) | CR4_VMXE;
    writeCr4(new_cr4);
    // Diagnostic: if the FIXED1 mask cleared any CR4 bit the kernel relies on
    // (SMEP/SMAP/PCIDE/PGE/...), it shows up as a dropped bit here.
    debug.klog("[vmx] CR0 0x{X}->0x{X}  CR4 0x{X}->0x{X} (VMXE set)\n", .{
        orig_cr0, new_cr0, orig_cr4, new_cr4,
    });

    // 2. VMXON region: 4KB-aligned (a PMM frame is page-aligned), zeroed,
    //    first dword = VMCS revision id (bit 31 = 0; already masked in detect).
    //    A frame always fits: vmcs_region_size is architecturally <= 4KB
    //    (Phase 0 logged 4096). Phase 2 must apply the same bound to the VMCS.
    const phys = pmm.allocFrame() orelse {
        debug.klog("[vmx] enableBsp: PMM exhausted — cannot allocate VMXON region\n", .{});
        writeCr4(orig_cr4);
        if (new_cr0 != orig_cr0) writeCr0(orig_cr0);
        return;
    };
    const va = paging.physToVirt(phys);
    @memset(@as([*]u8, @ptrFromInt(va))[0..4096], 0);
    @as(*volatile u32, @ptrFromInt(va)).* = vmcs_revision;

    // 3. VMXON. The operand is a memory location holding the region's
    //    PHYSICAL address. CF=1 => VMfailInvalid (no current VMCS yet, so CF
    //    is the only failure indication).
    const pa: u64 = phys; // VMXON reads the phys addr FROM this memory slot
    var cf: u8 = undefined;
    asm volatile (
        \\vmxon %[pa]
        \\setc %[cf]
        : [cf] "=r" (cf),
        : [pa] "m" (pa),
        : .{ .cc = true, .memory = true });

    if (cf != 0) {
        debug.klog("[vmx] VMXON FAILED (VMfailInvalid). region_pa=0x{X} cr4=0x{X}\n", .{ phys, new_cr4 });
        pmm.freeFrame(phys);
        writeCr4(orig_cr4);
        if (new_cr0 != orig_cr0) writeCr0(orig_cr0);
        return;
    }
    in_vmx_operation = true;
    debug.klog("[vmx] VMXON OK — CPU is in VMX root operation (region pa=0x{X})\n", .{phys});

    // Phase 1 milestone reached. Leave VMX root operation cleanly so the
    // running kernel carries no lingering VMX state; Phase 2 will VMXON again
    // and stay. Retain the region + CR4.VMXE for reuse.
    asm volatile ("vmxoff" ::: .{ .cc = true, .memory = true });
    in_vmx_operation = false;
    vmxon_region_phys = phys;
    vmxon_region_va = va;
    debug.klog("[vmx] VMXOFF OK — exited cleanly. Phase 1 complete (region retained for Phase 2).\n", .{});
}
