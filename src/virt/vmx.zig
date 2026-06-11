// src/virt/vmx.zig — Intel VT-x (VMX) hypervisor support.
//
// This is the HOST side of virtualization: ZigOS running a guest under
// ITSELF. It is the mirror of virt/hyperv.zig, which is the GUEST side
// (ZigOS running under someone else's hypervisor). Together they close the
// loop — the OS that knows how to be virtualized learns how to virtualize.
//
// Phases (all run back-to-back from enableBsp() at boot, BSP only):
//   0  detect()        — CPUID + capability-MSR probe, read-only, logs verdict
//   1  VMXON/VMXOFF    — enter/exit VMX root operation (region retained)
//   2a vmcsRoundtrip() — VMCLEAR/VMPTRLD/VMWRITE/VMREAD lifecycle proof
//   2b launchGuest()   — full VMCS + EPT, one-shot real-mode `cpuid` guest,
//                        first VMLAUNCH + VMEXIT (reason 10)
//   2c runEchoGuest()  — resident VMCS + trap-and-emulate dispatch loop:
//                        guest does console I/O (OUT 0xE9) + CPUID, host
//                        emulates each exit and VMRESUMEs; vendor spoofed
//                        to "ZigOSInside!" and printed back by the guest.
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

// --- Phase 2: VMCS instruction wrappers ------------------------------
//
// VMX instructions report failure in RFLAGS, not via #UD: CF=1 is
// VMfailInvalid (no current VMCS / bad operand), ZF=1 is VMfailValid (a
// current VMCS exists; the VM-instruction-error field 0x4400 says why). We
// capture both after every instruction and map to this status.
//
// CRITICAL (nested-Hyper-V): every VMX instruction with a MEMORY operand
// (VMXON/VMCLEAR/VMPTRLD/VMPTRST, and VMREAD/VMWRITE if their data operand is
// in memory) MUST use REGISTER-INDIRECT addressing `(%reg)`. KVM reflected
// under Hyper-V mis-reconstructs a base+displacement operand GVA — the exact
// bug that broke VMXON, where it read ~0x3c8 off &operand. A bare register
// pointer has no displacement to mis-decode. VMREAD/VMWRITE below keep BOTH the
// field and the value in registers for the same reason.
const VmxStatus = enum { ok, fail_invalid, fail_valid };

inline fn vmxStatus(cf: u8, zf: u8) VmxStatus {
    if (cf != 0) return .fail_invalid;
    if (zf != 0) return .fail_valid;
    return .ok;
}

inline fn vmclear(region_phys_ptr: *const u64) VmxStatus {
    var cf: u8 = undefined;
    var zf: u8 = undefined;
    asm volatile (
        \\vmclear (%[ptr])
        \\setc %[cf]
        \\setz %[zf]
        : [cf] "=r" (cf),
          [zf] "=r" (zf),
        : [ptr] "r" (region_phys_ptr),
        : .{ .cc = true, .memory = true });
    return vmxStatus(cf, zf);
}

inline fn vmptrld(region_phys_ptr: *const u64) VmxStatus {
    var cf: u8 = undefined;
    var zf: u8 = undefined;
    asm volatile (
        \\vmptrld (%[ptr])
        \\setc %[cf]
        \\setz %[zf]
        : [cf] "=r" (cf),
          [zf] "=r" (zf),
        : [ptr] "r" (region_phys_ptr),
        : .{ .cc = true, .memory = true });
    return vmxStatus(cf, zf);
}

/// VMWRITE field <- value. Both operands in registers (no memory operand →
/// immune to the nested base+disp mis-decode).
inline fn vmwrite(field: u64, value: u64) VmxStatus {
    var cf: u8 = undefined;
    var zf: u8 = undefined;
    asm volatile (
        \\vmwrite %[value], %[field]
        \\setc %[cf]
        \\setz %[zf]
        : [cf] "=r" (cf),
          [zf] "=r" (zf),
        : [field] "r" (field),
          [value] "r" (value),
        : .{ .cc = true });
    return vmxStatus(cf, zf);
}

/// VMREAD field -> value. Field and destination both in registers.
inline fn vmread(field: u64) struct { value: u64, status: VmxStatus } {
    var value: u64 = undefined;
    var cf: u8 = undefined;
    var zf: u8 = undefined;
    asm volatile (
        \\vmread %[field], %[value]
        \\setc %[cf]
        \\setz %[zf]
        : [value] "=r" (value),
          [cf] "=r" (cf),
          [zf] "=r" (zf),
        : [field] "r" (field),
        : .{ .cc = true });
    return .{ .value = value, .status = vmxStatus(cf, zf) };
}

/// Phase 2a: prove the VMCS instruction lifecycle inside VMX root operation.
/// Allocates a revision-stamped VMCS page, VMCLEARs it (init + mark "clear"),
/// VMPTRLDs it (make it current), then VMWRITEs a sentinel to GUEST_RIP and
/// VMREADs it back. A matching roundtrip proves the loaded VMCS is live and the
/// field-access path works end-to-end. Clears and frees the probe VMCS on the
/// way out. MUST be called while in VMX operation (between VMXON and VMXOFF).
fn vmcsRoundtrip() bool {
    const phys = pmm.allocFrame() orelse {
        debug.klog("[vmx] phase2a: PMM exhausted — no VMCS region\n", .{});
        return false;
    };
    defer pmm.freeFrame(phys);
    const va = paging.physToVirt(phys);
    @memset(@as([*]u8, @ptrFromInt(va))[0..4096], 0);
    // First dword = VMCS revision id (bit 31 clear = ordinary VMCS, not a
    // shadow VMCS). Same revision as the VMXON region.
    @as(*volatile u32, @ptrFromInt(va)).* = vmcs_revision;

    const pa: u64 = phys; // memory slot the register-indirect operand points at

    {
        const st = vmclear(&pa);
        if (st != .ok) {
            debug.klog("[vmx] phase2a: VMCLEAR failed ({s})\n", .{@tagName(st)});
            return false;
        }
    }
    {
        const st = vmptrld(&pa);
        if (st != .ok) {
            debug.klog("[vmx] phase2a: VMPTRLD failed ({s})\n", .{@tagName(st)});
            return false;
        }
    }

    // GUEST_RIP (0x681E) is a natural-width guest-state field with no VMWRITE-
    // time constraints — a clean target for a write/read roundtrip.
    const FIELD_GUEST_RIP: u64 = 0x681E;
    const sentinel: u64 = 0xCAFE_F00D_DEAD_BEEF;

    const wst = vmwrite(FIELD_GUEST_RIP, sentinel);
    if (wst != .ok) {
        debug.klog("[vmx] phase2a: VMWRITE GUEST_RIP failed ({s})\n", .{@tagName(wst)});
        _ = vmclear(&pa);
        return false;
    }
    const rd = vmread(FIELD_GUEST_RIP);
    if (rd.status != .ok) {
        debug.klog("[vmx] phase2a: VMREAD GUEST_RIP failed ({s})\n", .{@tagName(rd.status)});
        _ = vmclear(&pa);
        return false;
    }

    const match = rd.value == sentinel;
    debug.klog("[vmx] phase2a: VMCS roundtrip wrote=0x{X} read=0x{X} -> {s}\n", .{
        sentinel, rd.value, if (match) "MATCH" else "MISMATCH",
    });

    // Drop the current-VMCS pointer before this frame is freed by `defer`.
    _ = vmclear(&pa);
    return match;
}

// --- Phase 2b: first guest (VMCS + EPT + VMLAUNCH) -------------------
//
// Goal: build a complete VMCS for a one-instruction real-mode guest, map its
// code through EPT, VMLAUNCH it, and catch the resulting VMEXIT. The guest is
// a single `cpuid`, which VM-exits UNCONDITIONALLY (independent of any control
// bit) — the most robust possible "the guest actually executed" signal.
// Exit reason 10 (EXIT_REASON_CPUID) == success.

inline fn readCr3() u64 {
    return asm volatile ("mov %%cr3, %[ret]"
        : [ret] "=r" (-> u64),
    );
}

// VMX control-MSR adjustment: a bit set in the low dword (allowed-0) must be 1;
// a bit clear in the high dword (allowed-1) must be 0. So the legal value for a
// desired control word is `(desired | low) & high`.
inline fn adjustCtl(desired: u32, msr: u32) u32 {
    const v = rdmsr(msr);
    const lo: u32 = @truncate(v);
    const hi: u32 = @truncate(v >> 32);
    return (desired | lo) & hi;
}

// "True" control-capability MSRs (BASIC bit 55 set; detect() logged true_ctls).
const MSR_IA32_VMX_TRUE_PINBASED_CTLS: u32 = 0x48D;
const MSR_IA32_VMX_TRUE_PROCBASED_CTLS: u32 = 0x48E;
const MSR_IA32_VMX_TRUE_EXIT_CTLS: u32 = 0x48F;
const MSR_IA32_VMX_TRUE_ENTRY_CTLS: u32 = 0x490;

const MSR_IA32_EFER: u32 = 0xC000_0080;
const MSR_FS_BASE: u32 = 0xC000_0100;
const MSR_GS_BASE: u32 = 0xC000_0101;
const MSR_IA32_SYSENTER_CS: u32 = 0x174;
const MSR_IA32_SYSENTER_ESP: u32 = 0x175;
const MSR_IA32_SYSENTER_EIP: u32 = 0x176;

// Control bits we want on.
const CPU_BASED_HLT_EXITING: u32 = 1 << 7; // guest's final hlt -> VMEXIT reason 12
const CPU_BASED_UNCOND_IO_EXITING: u32 = 1 << 24; // every IN/OUT -> VMEXIT reason 30
const CPU_BASED_ACTIVATE_SECONDARY: u32 = 1 << 31;
const SECONDARY_ENABLE_EPT: u32 = 1 << 1;
const SECONDARY_UNRESTRICTED_GUEST: u32 = 1 << 7;
const VM_EXIT_HOST_ADDR_SPACE_SIZE: u32 = 1 << 9; // return to 64-bit host
const VM_EXIT_LOAD_IA32_EFER: u32 = 1 << 21;
const VM_ENTRY_LOAD_IA32_EFER: u32 = 1 << 15;
// (deliberately NOT VM_ENTRY_IA32E_MODE (1<<9): the guest is 16-bit real mode.)

// VMCS field encodings (SDM Vol 3D, App. B).
const F_PIN_BASED_CTLS: u64 = 0x4000;
const F_CPU_BASED_CTLS: u64 = 0x4002;
const F_SECONDARY_CTLS: u64 = 0x401E;
const F_EXIT_CTLS: u64 = 0x400C;
const F_ENTRY_CTLS: u64 = 0x4012;
const F_EXCEPTION_BITMAP: u64 = 0x4004;
const F_PF_EC_MASK: u64 = 0x4006;
const F_PF_EC_MATCH: u64 = 0x4008;
const F_CR3_TARGET_COUNT: u64 = 0x400A;
const F_EXIT_MSR_STORE_COUNT: u64 = 0x400E;
const F_EXIT_MSR_LOAD_COUNT: u64 = 0x4010;
const F_ENTRY_MSR_LOAD_COUNT: u64 = 0x4014;
const F_ENTRY_INTR_INFO: u64 = 0x4016;

const F_VMCS_LINK_PTR: u64 = 0x2800;
const F_GUEST_IA32_DEBUGCTL: u64 = 0x2802;
const F_EPT_POINTER: u64 = 0x201A;
const F_GUEST_IA32_EFER: u64 = 0x2806;
const F_HOST_IA32_EFER: u64 = 0x2C02;

const F_CR0_MASK: u64 = 0x6000;
const F_CR4_MASK: u64 = 0x6002;
const F_CR0_READ_SHADOW: u64 = 0x6004;
const F_CR4_READ_SHADOW: u64 = 0x6006;

const F_HOST_CR0: u64 = 0x6C00;
const F_HOST_CR3: u64 = 0x6C02;
const F_HOST_CR4: u64 = 0x6C04;
const F_HOST_FS_BASE: u64 = 0x6C06;
const F_HOST_GS_BASE: u64 = 0x6C08;
const F_HOST_TR_BASE: u64 = 0x6C0A;
const F_HOST_GDTR_BASE: u64 = 0x6C0C;
const F_HOST_IDTR_BASE: u64 = 0x6C0E;
const F_HOST_SYSENTER_ESP: u64 = 0x6C10;
const F_HOST_SYSENTER_EIP: u64 = 0x6C12;
const F_HOST_SYSENTER_CS: u64 = 0x4C00;
const F_HOST_ES_SEL: u64 = 0x0C00;
const F_HOST_CS_SEL: u64 = 0x0C02;
const F_HOST_SS_SEL: u64 = 0x0C04;
const F_HOST_DS_SEL: u64 = 0x0C06;
const F_HOST_FS_SEL: u64 = 0x0C08;
const F_HOST_GS_SEL: u64 = 0x0C0A;
const F_HOST_TR_SEL: u64 = 0x0C0C;

const F_GUEST_CR0: u64 = 0x6800;
const F_GUEST_CR3: u64 = 0x6802;
const F_GUEST_CR4: u64 = 0x6804;
const F_GUEST_DR7: u64 = 0x681A;
const F_GUEST_RSP: u64 = 0x681C;
const F_GUEST_RIP: u64 = 0x681E;
const F_GUEST_RFLAGS: u64 = 0x6820;
const F_GUEST_ES_SEL: u64 = 0x0800;
const F_GUEST_CS_SEL: u64 = 0x0802;
const F_GUEST_SS_SEL: u64 = 0x0804;
const F_GUEST_DS_SEL: u64 = 0x0806;
const F_GUEST_FS_SEL: u64 = 0x0808;
const F_GUEST_GS_SEL: u64 = 0x080A;
const F_GUEST_LDTR_SEL: u64 = 0x080C;
const F_GUEST_TR_SEL: u64 = 0x080E;
const F_GUEST_ES_LIMIT: u64 = 0x4800;
const F_GUEST_CS_LIMIT: u64 = 0x4802;
const F_GUEST_SS_LIMIT: u64 = 0x4804;
const F_GUEST_DS_LIMIT: u64 = 0x4806;
const F_GUEST_FS_LIMIT: u64 = 0x4808;
const F_GUEST_GS_LIMIT: u64 = 0x480A;
const F_GUEST_LDTR_LIMIT: u64 = 0x480C;
const F_GUEST_TR_LIMIT: u64 = 0x480E;
const F_GUEST_ES_AR: u64 = 0x4814;
const F_GUEST_CS_AR: u64 = 0x4816;
const F_GUEST_SS_AR: u64 = 0x4818;
const F_GUEST_DS_AR: u64 = 0x481A;
const F_GUEST_FS_AR: u64 = 0x481C;
const F_GUEST_GS_AR: u64 = 0x481E;
const F_GUEST_LDTR_AR: u64 = 0x4820;
const F_GUEST_TR_AR: u64 = 0x4822;
const F_GUEST_ES_BASE: u64 = 0x6806;
const F_GUEST_CS_BASE: u64 = 0x6808;
const F_GUEST_SS_BASE: u64 = 0x680A;
const F_GUEST_DS_BASE: u64 = 0x680C;
const F_GUEST_FS_BASE: u64 = 0x680E;
const F_GUEST_GS_BASE: u64 = 0x6810;
const F_GUEST_LDTR_BASE: u64 = 0x6812;
const F_GUEST_TR_BASE: u64 = 0x6814;
const F_GUEST_GDTR_LIMIT: u64 = 0x4810;
const F_GUEST_IDTR_LIMIT: u64 = 0x4812;
const F_GUEST_GDTR_BASE: u64 = 0x6816;
const F_GUEST_IDTR_BASE: u64 = 0x6818;
const F_GUEST_ACTIVITY_STATE: u64 = 0x4826;
const F_GUEST_INTERRUPTIBILITY: u64 = 0x4824;
const F_GUEST_PENDING_DBG: u64 = 0x6822;
const F_GUEST_SYSENTER_CS: u64 = 0x482A;
const F_GUEST_SYSENTER_ESP: u64 = 0x6824;
const F_GUEST_SYSENTER_EIP: u64 = 0x6826;

// Read-only exit-info fields.
const F_VM_INSTRUCTION_ERROR: u64 = 0x4400;
const F_VM_EXIT_REASON: u64 = 0x4402;
const F_VM_EXIT_INSTRUCTION_LEN: u64 = 0x440C;
const F_EXIT_QUALIFICATION: u64 = 0x6400;

// Basic exit reasons (SDM Vol 3D, App. C) used by the Phase 2c dispatcher.
const EXIT_CPUID: u16 = 10;
const EXIT_HLT: u16 = 12;
const EXIT_IO: u16 = 30;
const EXIT_EPT_VIOLATION: u16 = 48;
const EXIT_EPT_MISCONFIG: u16 = 49;

// The guest's emulated "console": any OUT to this port is captured by the
// host and appended to the guest's output buffer (a virtual debug port,
// mirroring the bochs/QEMU 0xE9 convention but serviced entirely by us).
const GUEST_CONSOLE_PORT: u64 = 0xE9;

// Real-mode descriptor-cache access-rights bytes (the classic values the CPU
// holds in real mode; unrestricted-guest VM-entry accepts these with PE=0).
const AR_CODE: u64 = 0x9B; // present, S=1, type=0xB (exec/read/accessed)
const AR_DATA: u64 = 0x93; // present, S=1, type=0x3 (read/write/accessed)
const AR_LDTR_UNUSABLE: u64 = 0x1_0000; // bit16 = unusable
const AR_TR: u64 = 0x8B; // present, S=0, type=0xB (32-bit busy TSS)

/// Read a 16-bit segment selector. Generic over the segment name via a tiny
/// asm literal so we don't repeat the boilerplate six times.
inline fn readSeg(comptime mnemonic: []const u8) u16 {
    return asm volatile ("mov %%" ++ mnemonic ++ ", %[ret]"
        : [ret] "=r" (-> u16),
    );
}

// --- Shared VMCS construction (Phase 2b one-shot + Phase 2c loop) ------

const DescPtr = packed struct { limit: u16, base: u64 };

/// Everything the VMCS host-state area needs, snapshotted from the running
/// kernel. The gdtr/idtr copies double as the lgdt/lidt operands for
/// restoring the table limits that a VM exit maxes to 0xFFFF (SDM 28.5.1).
const HostState = struct {
    cr0: u64,
    cr3: u64,
    cr4: u64,
    efer: u64,
    cs: u64,
    ss: u64,
    ds: u64,
    es: u64,
    fs: u64,
    gs: u64,
    tr_sel: u64,
    tr_base: u64,
    gdtr: DescPtr,
    idtr: DescPtr,
    se_cs: u64,
    se_esp: u64,
    se_eip: u64,
    fs_base: u64,
    gs_base: u64,
};

fn captureHostState() HostState {
    var hs: HostState = undefined;
    hs.cr0 = readCr0();
    hs.cr3 = readCr3();
    hs.cr4 = readCr4();
    hs.efer = rdmsr(MSR_IA32_EFER);
    hs.cs = readSeg("cs") & 0xFFF8;
    hs.ss = readSeg("ss") & 0xFFF8;
    hs.ds = readSeg("ds") & 0xFFF8;
    hs.es = readSeg("es") & 0xFFF8;
    hs.fs = readSeg("fs") & 0xFFF8;
    hs.gs = readSeg("gs") & 0xFFF8;
    const tr_raw = asm volatile ("str %[ret]"
        : [ret] "=r" (-> u16),
    );
    hs.tr_sel = tr_raw & 0xFFF8;
    // Asm output operands must be plain identifiers — stage through locals.
    var gdtr: DescPtr = undefined;
    var idtr: DescPtr = undefined;
    asm volatile ("sgdt %[g]"
        : [g] "=m" (gdtr),
    );
    asm volatile ("sidt %[i]"
        : [i] "=m" (idtr),
    );
    hs.gdtr = gdtr;
    hs.idtr = idtr;
    // Decode the TR base out of its 16-byte system descriptor in the GDT.
    const tdesc = hs.gdtr.base + hs.tr_sel;
    const dlo = @as(*const u64, @ptrFromInt(tdesc)).*;
    const dhi = @as(*const u64, @ptrFromInt(tdesc + 8)).*;
    hs.tr_base = ((dlo >> 16) & 0xFFFFFF) | (((dlo >> 56) & 0xFF) << 24) | ((dhi & 0xFFFF_FFFF) << 32);
    hs.se_cs = rdmsr(MSR_IA32_SYSENTER_CS);
    hs.se_esp = rdmsr(MSR_IA32_SYSENTER_ESP);
    hs.se_eip = rdmsr(MSR_IA32_SYSENTER_EIP);
    hs.fs_base = rdmsr(MSR_FS_BASE);
    hs.gs_base = rdmsr(MSR_GS_BASE);
    return hs;
}

const Ctls = struct { pin: u32, proc: u32, proc2: u32, exit: u32, entry: u32 };

/// Write the full VMCS field set for a real-mode guest entered at CS:IP =
/// 0:0 (guest-physical 0 via EPT): controls, host state from `hs`, and
/// clean real-mode guest state (segments base 0 / limit 0xFFFF, PE=PG=0).
/// HOST_RSP / HOST_RIP are NOT written here — the launch asm writes those
/// itself with the live values. Returns the number of rejected VMWRITEs
/// (0 = success). Requires the target VMCS to be current.
fn populateVmcs(hs: *const HostState, ctls: Ctls, eptp: u64, guest_rsp: u64) u32 {
    // Guest CR0/CR4 (real mode: PE=0, PG=0; unrestricted guest exempts both
    // from the fixed-bit requirement).
    const cr0_f0 = rdmsr(MSR_IA32_VMX_CR0_FIXED0);
    const cr0_f1 = rdmsr(MSR_IA32_VMX_CR0_FIXED1);
    const cr4_f0 = rdmsr(MSR_IA32_VMX_CR4_FIXED0);
    const cr4_f1 = rdmsr(MSR_IA32_VMX_CR4_FIXED1);
    const PE_PG: u64 = 1 | (@as(u64, 1) << 31);
    const guest_cr0 = (cr0_f0 & cr0_f1) & ~PE_PG;
    const guest_cr4 = cr4_f0 & cr4_f1;

    const W = struct { f: u64, v: u64 };
    const writes = [_]W{
        // controls
        .{ .f = F_PIN_BASED_CTLS, .v = ctls.pin },
        .{ .f = F_CPU_BASED_CTLS, .v = ctls.proc },
        .{ .f = F_SECONDARY_CTLS, .v = ctls.proc2 },
        .{ .f = F_EXIT_CTLS, .v = ctls.exit },
        .{ .f = F_ENTRY_CTLS, .v = ctls.entry },
        .{ .f = F_EXCEPTION_BITMAP, .v = 0 },
        .{ .f = F_PF_EC_MASK, .v = 0 },
        .{ .f = F_PF_EC_MATCH, .v = 0 },
        .{ .f = F_CR3_TARGET_COUNT, .v = 0 },
        .{ .f = F_EXIT_MSR_STORE_COUNT, .v = 0 },
        .{ .f = F_EXIT_MSR_LOAD_COUNT, .v = 0 },
        .{ .f = F_ENTRY_MSR_LOAD_COUNT, .v = 0 },
        .{ .f = F_ENTRY_INTR_INFO, .v = 0 },
        // 64-bit controls
        .{ .f = F_VMCS_LINK_PTR, .v = 0xFFFF_FFFF_FFFF_FFFF },
        .{ .f = F_GUEST_IA32_DEBUGCTL, .v = 0 },
        .{ .f = F_EPT_POINTER, .v = eptp },
        .{ .f = F_GUEST_IA32_EFER, .v = 0 },
        .{ .f = F_HOST_IA32_EFER, .v = hs.efer },
        // CR mask/shadow
        .{ .f = F_CR0_MASK, .v = 0 },
        .{ .f = F_CR4_MASK, .v = 0 },
        .{ .f = F_CR0_READ_SHADOW, .v = guest_cr0 },
        .{ .f = F_CR4_READ_SHADOW, .v = guest_cr4 },
        // host state
        .{ .f = F_HOST_CR0, .v = hs.cr0 },
        .{ .f = F_HOST_CR3, .v = hs.cr3 },
        .{ .f = F_HOST_CR4, .v = hs.cr4 },
        .{ .f = F_HOST_CS_SEL, .v = hs.cs },
        .{ .f = F_HOST_SS_SEL, .v = hs.ss },
        .{ .f = F_HOST_DS_SEL, .v = hs.ds },
        .{ .f = F_HOST_ES_SEL, .v = hs.es },
        .{ .f = F_HOST_FS_SEL, .v = hs.fs },
        .{ .f = F_HOST_GS_SEL, .v = hs.gs },
        .{ .f = F_HOST_TR_SEL, .v = hs.tr_sel },
        .{ .f = F_HOST_FS_BASE, .v = hs.fs_base },
        .{ .f = F_HOST_GS_BASE, .v = hs.gs_base },
        .{ .f = F_HOST_TR_BASE, .v = hs.tr_base },
        .{ .f = F_HOST_GDTR_BASE, .v = hs.gdtr.base },
        .{ .f = F_HOST_IDTR_BASE, .v = hs.idtr.base },
        .{ .f = F_HOST_SYSENTER_CS, .v = hs.se_cs },
        .{ .f = F_HOST_SYSENTER_ESP, .v = hs.se_esp },
        .{ .f = F_HOST_SYSENTER_EIP, .v = hs.se_eip },
        // guest control/regs
        .{ .f = F_GUEST_CR0, .v = guest_cr0 },
        .{ .f = F_GUEST_CR3, .v = 0 },
        .{ .f = F_GUEST_CR4, .v = guest_cr4 },
        .{ .f = F_GUEST_DR7, .v = 0x400 },
        .{ .f = F_GUEST_RSP, .v = guest_rsp },
        .{ .f = F_GUEST_RIP, .v = 0 },
        .{ .f = F_GUEST_RFLAGS, .v = 0x2 },
        // guest segments (real mode: base = sel<<4 = 0, limit 0xFFFF)
        .{ .f = F_GUEST_ES_SEL, .v = 0 },
        .{ .f = F_GUEST_CS_SEL, .v = 0 },
        .{ .f = F_GUEST_SS_SEL, .v = 0 },
        .{ .f = F_GUEST_DS_SEL, .v = 0 },
        .{ .f = F_GUEST_FS_SEL, .v = 0 },
        .{ .f = F_GUEST_GS_SEL, .v = 0 },
        .{ .f = F_GUEST_LDTR_SEL, .v = 0 },
        .{ .f = F_GUEST_TR_SEL, .v = 0 },
        .{ .f = F_GUEST_ES_LIMIT, .v = 0xFFFF },
        .{ .f = F_GUEST_CS_LIMIT, .v = 0xFFFF },
        .{ .f = F_GUEST_SS_LIMIT, .v = 0xFFFF },
        .{ .f = F_GUEST_DS_LIMIT, .v = 0xFFFF },
        .{ .f = F_GUEST_FS_LIMIT, .v = 0xFFFF },
        .{ .f = F_GUEST_GS_LIMIT, .v = 0xFFFF },
        .{ .f = F_GUEST_LDTR_LIMIT, .v = 0 },
        .{ .f = F_GUEST_TR_LIMIT, .v = 0xFFFF },
        .{ .f = F_GUEST_ES_AR, .v = AR_DATA },
        .{ .f = F_GUEST_CS_AR, .v = AR_CODE },
        .{ .f = F_GUEST_SS_AR, .v = AR_DATA },
        .{ .f = F_GUEST_DS_AR, .v = AR_DATA },
        .{ .f = F_GUEST_FS_AR, .v = AR_DATA },
        .{ .f = F_GUEST_GS_AR, .v = AR_DATA },
        .{ .f = F_GUEST_LDTR_AR, .v = AR_LDTR_UNUSABLE },
        .{ .f = F_GUEST_TR_AR, .v = AR_TR },
        .{ .f = F_GUEST_ES_BASE, .v = 0 },
        .{ .f = F_GUEST_CS_BASE, .v = 0 },
        .{ .f = F_GUEST_SS_BASE, .v = 0 },
        .{ .f = F_GUEST_DS_BASE, .v = 0 },
        .{ .f = F_GUEST_FS_BASE, .v = 0 },
        .{ .f = F_GUEST_GS_BASE, .v = 0 },
        .{ .f = F_GUEST_LDTR_BASE, .v = 0 },
        .{ .f = F_GUEST_TR_BASE, .v = 0 },
        .{ .f = F_GUEST_GDTR_LIMIT, .v = 0xFFFF },
        .{ .f = F_GUEST_IDTR_LIMIT, .v = 0xFFFF },
        .{ .f = F_GUEST_GDTR_BASE, .v = 0 },
        .{ .f = F_GUEST_IDTR_BASE, .v = 0 },
        .{ .f = F_GUEST_ACTIVITY_STATE, .v = 0 },
        .{ .f = F_GUEST_INTERRUPTIBILITY, .v = 0 },
        .{ .f = F_GUEST_PENDING_DBG, .v = 0 },
        .{ .f = F_GUEST_SYSENTER_CS, .v = 0 },
        .{ .f = F_GUEST_SYSENTER_ESP, .v = 0 },
        .{ .f = F_GUEST_SYSENTER_EIP, .v = 0 },
    };
    var bad: u32 = 0;
    for (writes) |wv| {
        if (vmwrite(wv.f, wv.v) != .ok) {
            debug.klog("[vmx] populate: VMWRITE field=0x{X} val=0x{X} REJECTED\n", .{ wv.f, wv.v });
            bad += 1;
        }
    }
    return bad;
}

/// Phase 2b: build a VMCS for a minimal real-mode guest (`cpuid; hlt` mapped at
/// guest-physical 0 through a fresh 4-level EPT), VMLAUNCH it, and report the
/// VMEXIT. Returns true iff the guest executed and exited (any exit reason);
/// false on a VM-entry failure (with the VM-instruction-error / entry-failure
/// reason logged). Must be called in VMX operation, BSP, interrupts effectively
/// off (boot context). Frees every page it allocates.
fn launchGuest() bool {
    if (!has_ept or !has_unrestricted_guest) {
        debug.klog("[vmx] phase2b: skipped — needs EPT + unrestricted guest\n", .{});
        return false;
    }

    // --- 1. Control words, adjusted through the capability MSRs ----------
    const pin = adjustCtl(0, MSR_IA32_VMX_TRUE_PINBASED_CTLS);
    const proc = adjustCtl(CPU_BASED_ACTIVATE_SECONDARY | CPU_BASED_HLT_EXITING, MSR_IA32_VMX_TRUE_PROCBASED_CTLS);
    const proc2 = adjustCtl(SECONDARY_ENABLE_EPT | SECONDARY_UNRESTRICTED_GUEST, MSR_IA32_VMX_PROCBASED_CTLS2);
    const exit_ctl = adjustCtl(VM_EXIT_HOST_ADDR_SPACE_SIZE | VM_EXIT_LOAD_IA32_EFER, MSR_IA32_VMX_TRUE_EXIT_CTLS);
    const entry_ctl = adjustCtl(VM_ENTRY_LOAD_IA32_EFER, MSR_IA32_VMX_TRUE_ENTRY_CTLS);
    debug.klog("[vmx] phase2b: ctls pin=0x{X} proc=0x{X} proc2=0x{X} exit=0x{X} entry=0x{X}\n", .{ pin, proc, proc2, exit_ctl, entry_ctl });

    // --- 2+3. Guest CRs + host-state snapshot live in populateVmcs() / hs
    const hs = captureHostState();

    // --- 4. Allocate VMCS + EPT tables + guest code page ----------------
    const vmcs_frame = pmm.allocFrame() orelse return allocFail("VMCS");
    defer pmm.freeFrame(vmcs_frame);
    const ept_pml4 = pmm.allocFrame() orelse return allocFail("EPT PML4");
    defer pmm.freeFrame(ept_pml4);
    const ept_pdpt = pmm.allocFrame() orelse return allocFail("EPT PDPT");
    defer pmm.freeFrame(ept_pdpt);
    const ept_pd = pmm.allocFrame() orelse return allocFail("EPT PD");
    defer pmm.freeFrame(ept_pd);
    const ept_pt = pmm.allocFrame() orelse return allocFail("EPT PT");
    defer pmm.freeFrame(ept_pt);
    const code_frame = pmm.allocFrame() orelse return allocFail("guest code");
    defer pmm.freeFrame(code_frame);

    // Guest code at guest-physical 0: cpuid (0F A2), then hlt (F4) as a fence.
    const code = @as([*]u8, @ptrFromInt(paging.physToVirt(code_frame)));
    @memset(code[0..4096], 0);
    code[0] = 0x0F;
    code[1] = 0xA2; // cpuid
    code[2] = 0xF4; // hlt

    // EPT: PML4[0]→PDPT[0]→PD[0]→PT[0]→code_frame. Non-leaf entries carry RWX
    // (bits 2:0); the PT leaf adds memory-type WB (6<<3). EPTP = pml4 | WB |
    // (4 levels − 1)<<3.
    zeroFrame(ept_pml4);
    zeroFrame(ept_pdpt);
    zeroFrame(ept_pd);
    zeroFrame(ept_pt);
    eptEntry(ept_pml4, 0, ept_pdpt | 0x7);
    eptEntry(ept_pdpt, 0, ept_pd | 0x7);
    eptEntry(ept_pd, 0, ept_pt | 0x7);
    eptEntry(ept_pt, 0, code_frame | 0x37);
    const eptp = ept_pml4 | 0x1E;

    // --- 5. Make the VMCS current (register-indirect operands!) ----------
    zeroFrame(vmcs_frame);
    @as(*volatile u32, @ptrFromInt(paging.physToVirt(vmcs_frame))).* = vmcs_revision;
    const vmcs_pa: u64 = vmcs_frame;
    var loaded = false;
    defer if (loaded) {
        _ = vmclear(&vmcs_pa); // drop current-VMCS pointer before the frame is freed
    };
    if (vmclear(&vmcs_pa) != .ok) {
        debug.klog("[vmx] phase2b: VMCLEAR(guest VMCS) failed\n", .{});
        return false;
    }
    if (vmptrld(&vmcs_pa) != .ok) {
        debug.klog("[vmx] phase2b: VMPTRLD(guest VMCS) failed\n", .{});
        return false;
    }
    loaded = true;

    // --- 6. Populate every field, logging any VMWRITE that rejects -------
    const bad = populateVmcs(&hs, .{
        .pin = pin,
        .proc = proc,
        .proc2 = proc2,
        .exit = exit_ctl,
        .entry = entry_ctl,
    }, eptp, 0);
    if (bad != 0) {
        debug.klog("[vmx] phase2b: {d} VMWRITE(s) rejected — aborting before VMLAUNCH\n", .{bad});
        return false;
    }

    // --- 7. VMLAUNCH ------------------------------------------------------
    // HOST_RSP / HOST_RIP are written from inside the asm (RSP must be the
    // value live at launch; RIP is the local VMEXIT label). All GPRs the guest
    // could trash are push/pop-balanced around the launch, so the compiler's
    // frame survives; the only result we read out is `exited` in RAX (0 = VM
    // entry never happened / VMfail; 1 = a VMEXIT brought us back). The VMCS
    // stays current across VMEXIT, so the reason fields are read afterwards.
    var exited: u64 = 0;
    asm volatile (
        \\ push %%rbp
        \\ push %%rbx
        \\ push %%r12
        \\ push %%r13
        \\ push %%r14
        \\ push %%r15
        \\ pushfq
        \\ cli
        \\ mov %%rsp, %%rax
        \\ mov $0x6C14, %%rdx
        \\ vmwrite %%rax, %%rdx
        \\ lea 1f(%%rip), %%rax
        \\ mov $0x6C16, %%rdx
        \\ vmwrite %%rax, %%rdx
        \\ vmlaunch
        \\ xor %%eax, %%eax
        \\ jmp 3f
        \\1:
        \\ mov $1, %%eax
        \\3:
        \\ popfq
        \\ pop %%r15
        \\ pop %%r14
        \\ pop %%r13
        \\ pop %%r12
        \\ pop %%rbx
        \\ pop %%rbp
        : [exited] "={rax}" (exited),
        :
        : .{ .rcx = true, .rdx = true, .rsi = true, .rdi = true, .r8 = true, .r9 = true, .r10 = true, .r11 = true, .cc = true, .memory = true });

    // A VM exit forces GDTR.limit and IDTR.limit to 0xFFFF — the VMCS host
    // area carries the table BASES but no LIMIT fields (SDM 28.5.1), so the
    // CPU reloads our bases but maxes the limits. Restore the kernel's real
    // limits from the snapshot, or later descriptor-table-limit checks (e.g.
    // the boot ABI self-test) see a bogus 0xFFFF. Harmless if no VMEXIT
    // happened (VMfail fall-through leaves the tables untouched) — idempotent.
    //
    // Register-INDIRECT operand `lgdt (%reg)`, NOT `lgdt %[m]`: passing the
    // packed pseudo-descriptor as a memory constraint makes LLVM rebuild it
    // field-by-field into a temp with the WRONG m16:64 layout (base landed at
    // offset 0, limit scattered elsewhere) → lgdt loaded a non-canonical base
    // → #GP. The `&gdtr` here points at the struct sgdt already filled with the
    // correct layout, so the CPU reads exactly those 10 bytes. (Same footgun,
    // same fix, as the VMXON operand.)
    asm volatile ("lgdt (%[p])"
        :
        : [p] "r" (&hs.gdtr),
    );
    asm volatile ("lidt (%[p])"
        :
        : [p] "r" (&hs.idtr),
    );

    // --- 8. Interpret the outcome ---------------------------------------
    if (exited == 0) {
        const err = vmread(F_VM_INSTRUCTION_ERROR);
        debug.klog("[vmx] phase2b: VMLAUNCH did NOT enter guest (VMfail) — VM-instruction-error={d}\n", .{err.value});
        return false;
    }
    const reason = vmread(F_VM_EXIT_REASON).value;
    const qual = vmread(F_EXIT_QUALIFICATION).value;
    const basic: u16 = @truncate(reason & 0xFFFF);
    const entry_fail = (reason >> 31) & 1;
    debug.klog("[vmx] phase2b: *** VMEXIT *** reason=0x{X} basic={d}{s} qual=0x{X}\n", .{
        reason, basic, if (entry_fail == 1) " (VM-ENTRY-FAILURE)" else "", qual,
    });
    if (entry_fail == 1) {
        debug.klog("[vmx] phase2b: entry-failure exit (basic {d}: 33=guest-state 34=MSR-load 41=machine-check) — fields need fixing\n", .{basic});
        return false;
    }
    if (basic == 10) {
        debug.klog("[vmx] phase2b: *** GUEST EXECUTED CPUID — first ZigOS guest instruction ran in VMX non-root! ***\n", .{});
    } else {
        debug.klog("[vmx] phase2b: guest exited on reason {d} (not the expected CPUID=10), but it RAN\n", .{basic});
    }
    return true;
}

fn allocFail(comptime what: []const u8) bool {
    debug.klog("[vmx] phase2b: PMM exhausted allocating " ++ what ++ "\n", .{});
    return false;
}

inline fn zeroFrame(phys: usize) void {
    @memset(@as([*]u8, @ptrFromInt(paging.physToVirt(phys)))[0..4096], 0);
}

inline fn eptEntry(table_phys: usize, index: usize, value: u64) void {
    const t = @as([*]volatile u64, @ptrFromInt(paging.physToVirt(table_phys)));
    t[index] = value;
}

// --- Phase 2c: resident VMCS + VMEXIT dispatch loop --------------------
//
// 2b proved one guest instruction can run; 2c makes ZigOS a real (tiny)
// VMM: the guest below executes a few hundred instructions natively and
// VM-exits only on its privileged touches — every OUT to its console port
// and one CPUID — each of which the dispatch loop emulates before
// VMRESUMEing the same (resident) VMCS. That is the trap-and-emulate cycle
// every production hypervisor runs. The guest prints via OUT 0xE9 (the host
// accumulates bytes and klogs whole lines) and queries CPUID leaf 0, which
// the host answers with the spoofed vendor "ZigOSInside!" — which the guest
// then prints, proving its reality is host-fabricated.
//
// GPR handling: the VMCS holds guest RIP/RSP/RFLAGS but NOT the GPRs. The
// trampoline swaps the full register file between host and the save area
// around every entry/exit. The save area and the two flags are `export var`
// so the asm can address them RIP-relative BY SYMBOL: at VMEXIT every GPR
// except RSP holds guest state, so there is no free register to carry a
// pointer in.

/// Guest register file: rax,rbx,rcx,rdx,rsi,rdi,rbp,r8..r15 at byte offsets
/// 0,8,..,112. Offsets are load-bearing — the trampoline hardcodes them.
export var vmx_guest_gprs: [15]u64 = [_]u64{0} ** 15;
/// 0 = next entry is VMLAUNCH, 1 = VMRESUME (VMCS already in launched state).
export var vmx_do_resume: u8 = 0;
/// Set to 1 by the trampoline when VMLAUNCH/VMRESUME falls through (VMfail).
export var vmx_entry_fail: u8 = 0;

const GPR_RAX = 0;
const GPR_RBX = 1;
const GPR_RCX = 2;
const GPR_RDX = 3;
const GPR_RSI = 4;
const GPR_RDI = 5;

/// What the guest believes its CPU is. 12 bytes, the classic vendor shape.
const GUEST_VENDOR = "ZigOSInside!";

fn vendorWord(comptime off: usize) u64 {
    return @as(u64, GUEST_VENDOR[off]) |
        @as(u64, GUEST_VENDOR[off + 1]) << 8 |
        @as(u64, GUEST_VENDOR[off + 2]) << 16 |
        @as(u64, GUEST_VENDOR[off + 3]) << 24;
}

/// Enter the guest once (VMLAUNCH or VMRESUME per `vmx_do_resume`) and
/// return when a VMEXIT brings us back. Loads the guest GPR file before
/// entry, saves it after exit. Returns false iff the entry itself VMfailed
/// (no guest execution happened); the VM-instruction-error field says why.
///
/// The cmp on vmx_do_resume happens BEFORE the guest register file is
/// loaded (we lose every scratch register to guest state) — MOV does not
/// touch RFLAGS, so the result survives to the jne. HOST_RSP/HOST_RIP are
/// re-written every entry since the live RSP differs per call.
fn vmEnterGuest() bool {
    vmx_entry_fail = 0;
    asm volatile (
        \\ push %%rbp
        \\ push %%rbx
        \\ push %%r12
        \\ push %%r13
        \\ push %%r14
        \\ push %%r15
        \\ pushfq
        \\ cli
        \\ mov %%rsp, %%rax
        \\ mov $0x6C14, %%rdx
        \\ vmwrite %%rax, %%rdx
        \\ lea 3f(%%rip), %%rax
        \\ mov $0x6C16, %%rdx
        \\ vmwrite %%rax, %%rdx
        \\ cmpb $0, vmx_do_resume(%%rip)
        \\ mov vmx_guest_gprs+0(%%rip), %%rax
        \\ mov vmx_guest_gprs+8(%%rip), %%rbx
        \\ mov vmx_guest_gprs+16(%%rip), %%rcx
        \\ mov vmx_guest_gprs+24(%%rip), %%rdx
        \\ mov vmx_guest_gprs+32(%%rip), %%rsi
        \\ mov vmx_guest_gprs+40(%%rip), %%rdi
        \\ mov vmx_guest_gprs+48(%%rip), %%rbp
        \\ mov vmx_guest_gprs+56(%%rip), %%r8
        \\ mov vmx_guest_gprs+64(%%rip), %%r9
        \\ mov vmx_guest_gprs+72(%%rip), %%r10
        \\ mov vmx_guest_gprs+80(%%rip), %%r11
        \\ mov vmx_guest_gprs+88(%%rip), %%r12
        \\ mov vmx_guest_gprs+96(%%rip), %%r13
        \\ mov vmx_guest_gprs+104(%%rip), %%r14
        \\ mov vmx_guest_gprs+112(%%rip), %%r15
        \\ jne 1f
        \\ vmlaunch
        \\ movb $1, vmx_entry_fail(%%rip)
        \\ jmp 3f
        \\1:
        \\ vmresume
        \\ movb $1, vmx_entry_fail(%%rip)
        \\3:
        \\ mov %%rax, vmx_guest_gprs+0(%%rip)
        \\ mov %%rbx, vmx_guest_gprs+8(%%rip)
        \\ mov %%rcx, vmx_guest_gprs+16(%%rip)
        \\ mov %%rdx, vmx_guest_gprs+24(%%rip)
        \\ mov %%rsi, vmx_guest_gprs+32(%%rip)
        \\ mov %%rdi, vmx_guest_gprs+40(%%rip)
        \\ mov %%rbp, vmx_guest_gprs+48(%%rip)
        \\ mov %%r8, vmx_guest_gprs+56(%%rip)
        \\ mov %%r9, vmx_guest_gprs+64(%%rip)
        \\ mov %%r10, vmx_guest_gprs+72(%%rip)
        \\ mov %%r11, vmx_guest_gprs+80(%%rip)
        \\ mov %%r12, vmx_guest_gprs+88(%%rip)
        \\ mov %%r13, vmx_guest_gprs+96(%%rip)
        \\ mov %%r14, vmx_guest_gprs+104(%%rip)
        \\ mov %%r15, vmx_guest_gprs+112(%%rip)
        \\ popfq
        \\ pop %%r15
        \\ pop %%r14
        \\ pop %%r13
        \\ pop %%r12
        \\ pop %%rbx
        \\ pop %%rbp
        :
        :
        : .{ .rax = true, .rcx = true, .rdx = true, .rsi = true, .rdi = true, .r8 = true, .r9 = true, .r10 = true, .r11 = true, .cc = true, .memory = true });
    return vmx_entry_fail == 0;
}

/// The Phase 2c guest, hand-assembled 16-bit real-mode code entered at
/// CS:IP = 0:0. Prints two NUL-terminated strings char-by-char via OUT
/// 0xE9, asks CPUID leaf 0 for its vendor, stores EBX/EDX/ECX to memory,
/// prints those 12 bytes + '\n', then HLTs. Each OUT and the CPUID
/// VM-exit; everything else (loads, stores, branches) runs natively.
const guest_program = [_]u8{
    0xBE, 0x80, 0x00, //             00: mov  si, 0x80   ; msg1
    0xAC, //                         03: lodsb
    0x84, 0xC0, //                   04: test al, al
    0x74, 0x06, //                   06: jz   0x0E
    0xBA, 0xE9, 0x00, //             08: mov  dx, 0xE9
    0xEE, //                         0B: out  dx, al
    0xEB, 0xF5, //                   0C: jmp  0x03
    0xBE, 0xA0, 0x00, //             0E: mov  si, 0xA0   ; msg2
    0xAC, //                         11: lodsb
    0x84, 0xC0, //                   12: test al, al
    0x74, 0x06, //                   14: jz   0x1C
    0xBA, 0xE9, 0x00, //             16: mov  dx, 0xE9
    0xEE, //                         19: out  dx, al
    0xEB, 0xF5, //                   1A: jmp  0x11
    0x66, 0x31, 0xC0, //             1C: xor  eax, eax
    0x0F, 0xA2, //                   1F: cpuid           ; leaf 0 -> spoofed vendor
    0x66, 0x89, 0x1E, 0xC0, 0x00, // 21: mov  [0xC0], ebx
    0x66, 0x89, 0x16, 0xC4, 0x00, // 26: mov  [0xC4], edx
    0x66, 0x89, 0x0E, 0xC8, 0x00, // 2B: mov  [0xC8], ecx
    0xBE, 0xC0, 0x00, //             30: mov  si, 0xC0
    0xB9, 0x0C, 0x00, //             33: mov  cx, 12
    0xAC, //                         36: lodsb
    0xBA, 0xE9, 0x00, //             37: mov  dx, 0xE9
    0xEE, //                         3A: out  dx, al
    0xE2, 0xF9, //                   3B: loop 0x36
    0xB0, 0x0A, //                   3D: mov  al, 0x0A
    0xEE, //                         3F: out  dx, al
    0xF4, //                         40: hlt
};
const guest_msg1 = "Hello from the ZigOS guest VM!\n"; // at 0x80 (31B + page-zero NUL)
const guest_msg2 = "My CPU vendor: "; // at 0xA0 (15B + NUL); vendor scratch at 0xC0

fn advanceGuestRip() void {
    const rip = vmread(F_GUEST_RIP).value;
    const len = vmread(F_VM_EXIT_INSTRUCTION_LEN).value;
    _ = vmwrite(F_GUEST_RIP, rip + len);
}

/// Phase 2c entry: build VMCS + EPT for the echo guest (2b's configuration
/// plus unconditional IO exiting), then run the dispatch loop until the
/// guest HLTs. Must be called in VMX operation, BSP, boot context. Frees
/// everything it allocates.
fn runEchoGuest() bool {
    const ctls = Ctls{
        .pin = adjustCtl(0, MSR_IA32_VMX_TRUE_PINBASED_CTLS),
        .proc = adjustCtl(CPU_BASED_ACTIVATE_SECONDARY | CPU_BASED_HLT_EXITING | CPU_BASED_UNCOND_IO_EXITING, MSR_IA32_VMX_TRUE_PROCBASED_CTLS),
        .proc2 = adjustCtl(SECONDARY_ENABLE_EPT | SECONDARY_UNRESTRICTED_GUEST, MSR_IA32_VMX_PROCBASED_CTLS2),
        .exit = adjustCtl(VM_EXIT_HOST_ADDR_SPACE_SIZE | VM_EXIT_LOAD_IA32_EFER, MSR_IA32_VMX_TRUE_EXIT_CTLS),
        .entry = adjustCtl(VM_ENTRY_LOAD_IA32_EFER, MSR_IA32_VMX_TRUE_ENTRY_CTLS),
    };
    const hs = captureHostState();

    const vmcs_frame = pmm.allocFrame() orelse return allocFail("2c VMCS");
    defer pmm.freeFrame(vmcs_frame);
    const ept_pml4 = pmm.allocFrame() orelse return allocFail("2c EPT PML4");
    defer pmm.freeFrame(ept_pml4);
    const ept_pdpt = pmm.allocFrame() orelse return allocFail("2c EPT PDPT");
    defer pmm.freeFrame(ept_pdpt);
    const ept_pd = pmm.allocFrame() orelse return allocFail("2c EPT PD");
    defer pmm.freeFrame(ept_pd);
    const ept_pt = pmm.allocFrame() orelse return allocFail("2c EPT PT");
    defer pmm.freeFrame(ept_pt);
    const code_frame = pmm.allocFrame() orelse return allocFail("2c guest code");
    defer pmm.freeFrame(code_frame);

    // Guest page: program at 0, msg1 at 0x80, msg2 at 0xA0, vendor scratch
    // at 0xC0, guest stack top at 0xF00 (unused — no pushes — but legal).
    const code = @as([*]u8, @ptrFromInt(paging.physToVirt(code_frame)));
    @memset(code[0..4096], 0);
    @memcpy(code[0..guest_program.len], &guest_program);
    @memcpy(code[0x80 .. 0x80 + guest_msg1.len], guest_msg1);
    @memcpy(code[0xA0 .. 0xA0 + guest_msg2.len], guest_msg2);

    zeroFrame(ept_pml4);
    zeroFrame(ept_pdpt);
    zeroFrame(ept_pd);
    zeroFrame(ept_pt);
    eptEntry(ept_pml4, 0, ept_pdpt | 0x7);
    eptEntry(ept_pdpt, 0, ept_pd | 0x7);
    eptEntry(ept_pd, 0, ept_pt | 0x7);
    eptEntry(ept_pt, 0, code_frame | 0x37);
    const eptp = ept_pml4 | 0x1E;

    zeroFrame(vmcs_frame);
    @as(*volatile u32, @ptrFromInt(paging.physToVirt(vmcs_frame))).* = vmcs_revision;
    const vmcs_pa: u64 = vmcs_frame;
    var loaded = false;
    defer if (loaded) {
        _ = vmclear(&vmcs_pa);
    };
    if (vmclear(&vmcs_pa) != .ok) {
        debug.klog("[vmx] phase2c: VMCLEAR failed\n", .{});
        return false;
    }
    if (vmptrld(&vmcs_pa) != .ok) {
        debug.klog("[vmx] phase2c: VMPTRLD failed\n", .{});
        return false;
    }
    loaded = true;

    const bad = populateVmcs(&hs, ctls, eptp, 0xF00);
    if (bad != 0) {
        debug.klog("[vmx] phase2c: {d} VMWRITE(s) rejected — aborting\n", .{bad});
        return false;
    }

    // --- The dispatch loop: enter, classify the exit, emulate, resume ----
    vmx_guest_gprs = [_]u64{0} ** 15;
    vmx_do_resume = 0;
    var out_buf: [96]u8 = undefined;
    var out_len: usize = 0;
    var exits: u32 = 0;
    var io_exits: u32 = 0;
    var cpuid_exits: u32 = 0;
    var ok = false;

    while (exits < 4096) {
        if (!vmEnterGuest()) {
            const err = vmread(F_VM_INSTRUCTION_ERROR).value;
            debug.klog("[vmx] phase2c: {s} VMfail — VM-instruction-error={d}\n", .{
                if (vmx_do_resume == 1) "VMRESUME" else "VMLAUNCH", err,
            });
            break;
        }
        vmx_do_resume = 1;
        exits += 1;

        const reason = vmread(F_VM_EXIT_REASON).value;
        const basic: u16 = @truncate(reason & 0xFFFF);
        if ((reason >> 31) != 0) {
            debug.klog("[vmx] phase2c: VM-entry failure exit, basic reason {d}\n", .{basic});
            break;
        }
        switch (basic) {
            EXIT_CPUID => {
                cpuid_exits += 1;
                const leaf: u32 = @truncate(vmx_guest_gprs[GPR_RAX] & 0xFFFF_FFFF);
                if (leaf == 0) {
                    // The guest's universe is ours to define.
                    vmx_guest_gprs[GPR_RAX] = 1;
                    vmx_guest_gprs[GPR_RBX] = vendorWord(0);
                    vmx_guest_gprs[GPR_RDX] = vendorWord(4);
                    vmx_guest_gprs[GPR_RCX] = vendorWord(8);
                } else {
                    const sub: u32 = @truncate(vmx_guest_gprs[GPR_RCX] & 0xFFFF_FFFF);
                    const r = cpuid(leaf, sub);
                    vmx_guest_gprs[GPR_RAX] = r.eax;
                    vmx_guest_gprs[GPR_RBX] = r.ebx;
                    vmx_guest_gprs[GPR_RCX] = r.ecx;
                    vmx_guest_gprs[GPR_RDX] = r.edx;
                }
                advanceGuestRip();
            },
            EXIT_IO => {
                io_exits += 1;
                const qual = vmread(F_EXIT_QUALIFICATION).value;
                const port: u16 = @truncate((qual >> 16) & 0xFFFF);
                if ((qual & 0x8) != 0) {
                    // IN: emulate an open bus.
                    vmx_guest_gprs[GPR_RAX] |= 0xFF;
                } else if (port == GUEST_CONSOLE_PORT) {
                    const ch: u8 = @truncate(vmx_guest_gprs[GPR_RAX] & 0xFF);
                    if (ch == '\n') {
                        debug.klog("[vmx] guest: {s}\n", .{out_buf[0..out_len]});
                        out_len = 0;
                    } else if (out_len < out_buf.len) {
                        out_buf[out_len] = ch;
                        out_len += 1;
                    }
                }
                advanceGuestRip();
            },
            EXIT_HLT => {
                if (out_len > 0) {
                    debug.klog("[vmx] guest: {s}\n", .{out_buf[0..out_len]});
                    out_len = 0;
                }
                debug.klog("[vmx] phase2c: *** guest ran to HLT — {d} VMEXITs dispatched ({d} io, {d} cpuid) — trap-and-emulate loop works ***\n", .{
                    exits, io_exits, cpuid_exits,
                });
                ok = true;
                break;
            },
            else => {
                const qual = vmread(F_EXIT_QUALIFICATION).value;
                const grip = vmread(F_GUEST_RIP).value;
                debug.klog("[vmx] phase2c: unhandled exit reason {d} qual=0x{X} guest_rip=0x{X} — stopping\n", .{ basic, qual, grip });
                break;
            },
        }
    }
    if (exits >= 4096) {
        debug.klog("[vmx] phase2c: exit-storm guard tripped (4096 exits) — guest abandoned\n", .{});
    }

    // Every VMEXIT maxed GDTR/IDTR limits to 0xFFFF; restore the kernel's
    // real limits once, now that the loop is done (same footnote as 2b —
    // register-indirect operand, see the comment there).
    asm volatile ("lgdt (%[p])"
        :
        : [p] "r" (&hs.gdtr),
    );
    asm volatile ("lidt (%[p])"
        :
        : [p] "r" (&hs.idtr),
    );
    return ok;
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

    // 3. VMXON. The operand is a memory location holding the region's PHYSICAL
    //    address. On failure with no current VMCS, VMXON sets CF=1
    //    (VMfailInvalid); a current VMCS would instead give ZF=1 (VMfailValid).
    //    We capture BOTH so the log names which, and dump ground-truth state
    //    first — chasing a nested-KVM VMfail on an architecturally-correct
    //    region.
    const pa: u64 = phys; // VMXON reads the phys addr FROM this memory slot

    // --- VMXON-failure chase diagnostics (read-only) ---------------------
    // region_rev is what VMXON ACTUALLY reads at `phys`; if it isn't
    // vmcs_revision the write didn't land where KVM looks (coherence bug).
    // cr4_now re-reads CR4 to confirm VMXE truly stuck (KVM could refuse it).
    // maxphyaddr: if `phys >> maxphyaddr != 0`, KVM's page_address_valid
    // VMfails — here 0x..00 is ~44MB so any sane width passes, but log it.
    const basic_raw = rdmsr(MSR_IA32_VMX_BASIC);
    const cr4_now = readCr4();
    const region_rev = @as(*volatile u32, @ptrFromInt(va)).*;
    const maxphyaddr: u8 = @truncate(cpuid(0x8000_0008, 0).eax & 0xFF);
    debug.klog("[vmx] pre-VMXON: region_rev=0x{X} (want 0x{X}) cr4=0x{X} vmxe={s} " ++
        "maxphyaddr={d}b basic=0x{X} region_pa=0x{X}\n", .{
        region_rev, vmcs_revision, cr4_now, yn((cr4_now & CR4_VMXE) != 0),
        maxphyaddr, basic_raw,     phys,
    });

    // Operand addressing: register-INDIRECT `vmxon (%[ptr])` instead of the
    // RBP+disp stack form. The v2 KVM trace (eVMCS off) showed KVM
    // reconstructing the operand GVA as RBP-0x2618=0x2a3d9b8 and reading the
    // WRONG 8 bytes there (0x2a3d5f0 — a stale stack pointer, not `phys`),
    // i.e. the nested base+disp reconstruction landed ~0x3c8 off the true
    // &pa. A register-direct address removes base-register/displacement
    // reconstruction entirely: KVM reads the pointer register's value and
    // dereferences it, so the operand GVA is exactly &pa. The diagnostic
    // prints &pa + its content so we can correlate against the bpftrace
    // decode line (gva must now equal &pa, value must equal phys).
    debug.klog("[vmx] operand: &pa=0x{X} *(&pa)=0x{X}\n", .{ @intFromPtr(&pa), pa });

    var cf: u8 = undefined;
    var zf: u8 = undefined;
    asm volatile (
        \\vmxon (%[ptr])
        \\setc %[cf]
        \\setz %[zf]
        : [cf] "=r" (cf),
          [zf] "=r" (zf),
        : [ptr] "r" (&pa),
        : .{ .cc = true, .memory = true });

    if (cf != 0 or zf != 0) {
        debug.klog("[vmx] VMXON FAILED ({s}). region_pa=0x{X} cr4=0x{X} cf={d} zf={d}\n", .{
            if (cf != 0) "VMfailInvalid" else "VMfailValid", phys, new_cr4, cf, zf,
        });
        pmm.freeFrame(phys);
        writeCr4(orig_cr4);
        if (new_cr0 != orig_cr0) writeCr0(orig_cr0);
        return;
    }
    in_vmx_operation = true;
    debug.klog("[vmx] VMXON OK — CPU is in VMX root operation (region pa=0x{X})\n", .{phys});

    // Phase 2a: now that we're in VMX root operation, prove the VMCS
    // instruction lifecycle (VMCLEAR / VMPTRLD / VMWRITE / VMREAD) before we
    // VMXOFF. This is the plumbing every later step builds on.
    const round_ok = vmcsRoundtrip();

    // Phase 2b: build a full VMCS + EPT for a one-instruction real-mode guest
    // and VMLAUNCH it. Only attempt this if 2a's plumbing is sound.
    const guest_ok = if (round_ok) launchGuest() else false;

    // Phase 2c: the resident-VMCS trap-and-emulate dispatch loop — a guest
    // that runs hundreds of instructions, VM-exiting per console OUT and
    // CPUID, each emulated and VMRESUMEd. Only after 2b's one-shot proved
    // entry works.
    const echo_ok = if (guest_ok) runEchoGuest() else false;

    // Leave VMX root operation cleanly so the running kernel carries no
    // lingering VMX state; the full-guest phase will VMXON again and stay.
    // Retain the VMXON region + CR4.VMXE for reuse.
    asm volatile ("vmxoff" ::: .{ .cc = true, .memory = true });
    in_vmx_operation = false;
    vmxon_region_phys = phys;
    vmxon_region_va = va;
    debug.klog("[vmx] VMXOFF OK — exited cleanly. Phase 1+2a {s}, 2b {s}, 2c {s} (region retained).\n", .{
        if (round_ok) "ok" else "FAILED",
        if (guest_ok) "GUEST RAN" else "not yet",
        if (echo_ok) "DISPATCH LOOP OK" else "not yet",
    });
}
