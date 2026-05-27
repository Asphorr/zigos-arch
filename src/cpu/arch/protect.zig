// SMEP / SMAP / UMIP — CR4 hardening + STAC/CLAC helpers.
//
//   SMEP  (CR4.20) — supervisor cannot execute pages with U/S=1. Closes
//                    "kernel jumps into userspace .text" (CPL-confusion
//                    after a corrupted RIP, ROP into user .text, etc).
//   SMAP  (CR4.21) — supervisor data access to U/S=1 pages traps unless
//                    RFLAGS.AC=1. With AC cleared by default, kernel code
//                    outside our explicit STAC/CLAC bracket is caught at
//                    the hardware level the instant it touches user mem.
//   UMIP  (CR4.11) — userspace gets #GP on SGDT/SIDT/SLDT/SMSW/STR. These
//                    leak kernel-VA pointers usable to fingerprint the
//                    kernel layout / defeat KASLR.
//
// SMAP model: `validateUserPtr` does STAC when validation succeeds (the
// caller is about to deref the pointer). doSyscall's `defer` clears AC
// on syscall exit so the AC=1 window is bounded to a single syscall.
// Every interrupt/exception entry path clears AC explicitly because the
// CPU does NOT clear AC on interrupt — it inherits whatever the
// interrupted code had. IRET pops RFLAGS so AC restores naturally.
//
// SYSCALL entry: SFMASK has bit 18 (AC) set in `applyPerCpu`, so SYSCALL
// always clears RFLAGS.AC regardless of what userspace had. Belt-and-
// braces with the validateUserPtr STAC convention.

const std = @import("std");
const serial = @import("../../debug/serial.zig");

pub var smep_enabled: bool = false;
pub var smap_enabled: bool = false;
pub var umip_enabled: bool = false;
pub var pcid_supported: bool = false;
pub var invpcid_supported: bool = false;

inline fn cpuidLeaf(leaf: u32, subleaf: u32) struct { eax: u32, ebx: u32, ecx: u32, edx: u32 } {
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
          [_] "{ecx}" (subleaf),
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

/// Probe CPUID.07H for SMEP/SMAP/UMIP support. Call once on the BSP before
/// any AP starts — the resulting bools are read by inline asm helpers on
/// every syscall, so they must be set before secondary CPUs go online.
pub fn detectFeatures() void {
    const max_leaf = cpuidLeaf(0, 0).eax;
    if (max_leaf < 7) {
        serial.print("[protect] CPUID max leaf {d} < 7 — no SMEP/SMAP/UMIP probe\n", .{max_leaf});
        return;
    }
    const r = cpuidLeaf(7, 0);
    smep_enabled = (r.ebx & (1 << 7)) != 0;
    smap_enabled = (r.ebx & (1 << 20)) != 0;
    umip_enabled = (r.ecx & (1 << 2)) != 0;
    invpcid_supported = (r.ebx & (1 << 10)) != 0;
    // PCID lives on CPUID.01H:ECX bit 17, not leaf 7. Probe separately.
    const r1 = cpuidLeaf(1, 0);
    pcid_supported = (r1.ecx & (1 << 17)) != 0;
    serial.print("[protect] CPUID: SMEP={s} SMAP={s} UMIP={s} PCID={s} INVPCID={s}\n", .{
        if (smep_enabled) "y" else "n",
        if (smap_enabled) "y" else "n",
        if (umip_enabled) "y" else "n",
        if (pcid_supported) "y" else "n",
        if (invpcid_supported) "y" else "n",
    });
}

/// Per-CPU: enable SMEP + UMIP only. Safe to call from BSP early-init even
/// though the kernel boot stack lives in the low-half identity map under
/// UEFI — SMEP checks only instruction fetches against U/S=1 pages and
/// the kernel runs from -2 GB which has U/S=0. UMIP only affects CPL=3.
///
/// SMAP is NOT touched here because the boot stack (low-half identity, USER
/// bit set) is currently the active rsp: enabling SMAP here triple-faults
/// on the next push. See `enableSmapPerCpu` for the late-stage enable that
/// runs after `paging.dropLowIdentity`.
pub fn applyEarlyCr4() void {
    if (!smep_enabled and !umip_enabled and !pcid_supported) return;
    var cr4 = asm volatile ("mov %%cr4, %[ret]"
        : [ret] "=r" (-> u64),
    );
    const before = cr4;
    if (smep_enabled) cr4 |= (1 << 20);
    if (umip_enabled) cr4 |= (1 << 11);
    // CR4.PCIDE (bit 17). Phase-1: just enable the feature; current CR3
    // writes leave bits[11:0]=0 so every TLB entry is tagged PCID=0,
    // which is functionally identical to PCIDE=off. Phase 2+ will
    // allocate per-process PCIDs and embed them in CR3 + use
    // INVPCID-by-PCID in the shootdown handler. Order: must enable
    // BEFORE any CR3 write with PCID!=0 (current code uses PCID=0
    // always, so this is safe to flip at boot).
    if (pcid_supported) cr4 |= (1 << 17);
    // CR4.PGE (bit 7) — Page Global Enable. Honors PTE.G=1 on leaf
    // entries; those entries survive CR3 reloads. Kernel mappings
    // (PML4[256] physmap + PML4[511] image) get G=1 at boot so kernel
    // TLB working set persists across user-process context switches.
    // Prerequisite for PCID giving any perf win — without PGE, the
    // kernel runs cold-TLB on every CR3 reload regardless of PCID.
    cr4 |= (1 << 7);
    if (cr4 != before) {
        asm volatile ("mov %[val], %%cr4"
            :
            : [val] "r" (cr4),
        );
    }
}

/// Per-CPU: flip CR4.SMAP and OR RFLAGS.AC into IA32_FMASK so SYSCALL
/// clears AC on entry. Call only after the active rsp is in a U/S=0 page
/// (BSP: after `paging.dropLowIdentity` swaps off the UEFI boot stack;
/// AP: any time after entry, since the AP stack is already physmap-VA).
pub fn enableSmapPerCpu() void {
    if (!smap_enabled) return;
    var cr4 = asm volatile ("mov %%cr4, %[ret]"
        : [ret] "=r" (-> u64),
    );
    if (cr4 & (1 << 21) == 0) {
        cr4 |= (1 << 21);
        asm volatile ("mov %[val], %%cr4"
            :
            : [val] "r" (cr4),
        );
    }
    const MSR_SFMASK: u32 = 0xC0000084;
    const cur = rdmsr(MSR_SFMASK);
    const want = cur | (1 << 18); // AC
    if (cur != want) wrmsr(MSR_SFMASK, want);
}

/// Save CR4 and temporarily clear SMEP **and** SMAP. Used to bracket
/// calls into UEFI runtime services — firmware code AND data live in
/// the low-half identity map with U/S=1, so SMEP traps `call` to those
/// pages and SMAP traps the firmware's reads of its own data structs.
/// Returns the original CR4; pass it back to `endNonSmepCall` to undo.
/// Linux uses the same pattern in efi_call_phys_prolog / _epilog.
///
/// Sentinel: returning 0 means "neither was on, nothing to restore".
/// We OR a high bit on a non-zero CR4 to distinguish "real saved CR4"
/// from "no-op". Caller treats the returned value as opaque.
pub fn beginNonSmepCall() u64 {
    if (!smep_enabled and !smap_enabled) return 0;
    const cr4 = asm volatile ("mov %%cr4, %[ret]"
        : [ret] "=r" (-> u64),
    );
    var cleared = cr4;
    if (smep_enabled) cleared &= ~(@as(u64, 1) << 20);
    if (smap_enabled) cleared &= ~(@as(u64, 1) << 21);
    asm volatile ("mov %[val], %%cr4"
        :
        : [val] "r" (cleared),
    );
    return cr4 | (@as(u64, 1) << 63);
}

/// Restore CR4 after `beginNonSmepCall`. No-op if neither was on.
pub fn endNonSmepCall(saved: u64) void {
    if (saved == 0) return;
    const real = saved & ~(@as(u64, 1) << 63);
    asm volatile ("mov %[val], %%cr4"
        :
        : [val] "r" (real),
    );
}

/// Allow kernel access to user pages. Pair with `disallowUserAccess()`.
/// Idempotent — re-stac on already-AC=1 is a no-op.
pub inline fn allowUserAccess() void {
    if (smap_enabled) asm volatile ("stac" ::: .{ .cc = true });
}

/// Disable kernel access to user pages.
pub inline fn disallowUserAccess() void {
    if (smap_enabled) asm volatile ("clac" ::: .{ .cc = true });
}

/// Read RFLAGS.AC. Used by the page-fault handler to distinguish a SMAP
/// violation (supervisor #PF with AC=0, cr2 in user space, page present)
/// from a regular kernel-mode #PF.
pub inline fn readAC() bool {
    const rflags = asm volatile ("pushfq\npopq %[r]"
        : [r] "=r" (-> u64),
    );
    return (rflags & (1 << 18)) != 0;
}
