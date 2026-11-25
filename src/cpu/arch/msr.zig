// Model-specific registers: the one place that executes rdmsr/wrmsr.
//
// `read`/`write` are the bare instructions. `readSafe`/`writeSafe` take the
// #GP of a register the CPU does not have and report it, for registers whose
// presence can only be probed.
//
// The registers of the CPU's own architectural state are named here, with
// their bits. A family that belongs to one feature (machine-check banks, PMU
// counters, the x2APIC block, VMX capabilities, a hypervisor's own) is named
// by the module that programs it.
//
// ── Fault-tolerant access ───────────────────────────────────────────────
// rdmsr/wrmsr raise #GP when the MSR isn't implemented on the platform (a
// model-specific register absent on this stepping, or a hypervisor that
// injects #GP for MSRs it doesn't emulate). In kernel context that #GP is
// a panic — there is no other recovery path in this tree. Callers have had
// to gate every risky read behind coarse heuristics ("only on bare metal",
// "only on these CPU models") to avoid a fault. This primitive replaces the
// guessing with a *probe*: attempt the access, and learn from whether it
// faulted.
//
// ── How the recovery works ──────────────────────────────────────────────
// Each accessor performs its rdmsr/wrmsr at a fixed instruction site, and
// publishes two addresses into module globals: the fault site (the rdmsr
// instruction itself) and a fixup landing pad just past it. On a #GP the
// exception handler (cpu/idt/exception.zig) calls `fixupRip(saved_rip)`;
// if it matches a published fault site, the handler rewrites the saved RIP
// to the fixup and returns, so the accessor resumes at the landing pad —
// which records "failed" and returns null/false instead of faulting.
//
// The table is two entries (one rdmsr site, one wrmsr site). Their
// addresses are link-time invariants — identical on every CPU, never
// changing — so the table needs NO per-CPU state, NO arm/disarm around the
// access, and NO interrupt masking: a fault at the rdmsr site always
// redirects to the same fixup regardless of which CPU or context (IRQ, NMI,
// nested probe) raised it. The globals are written to the same constant
// value on every call, so concurrent writers never disagree.
//
// This is the standard kernel "exception table" idea (Linux __ex_table),
// specialized to the two MSR instruction sites and carrying its fixup
// targets in data rather than a linker section.

const debug = @import("../../debug/debug.zig");

pub const TSC: u32 = 0x10;

pub const APIC_BASE: u32 = 0x1B;
pub const ApicBase = struct {
    pub const X2APIC: u64 = 1 << 10;
    pub const ENABLE: u64 = 1 << 11;
};

pub const DEBUGCTL: u32 = 0x1D9;
pub const Debugctl = struct {
    pub const LBR: u64 = 1 << 0;
};

pub const PAT: u32 = 0x277;

pub const EFER: u32 = 0xC000_0080;
pub const Efer = struct {
    /// SYSCALL/SYSRET.
    pub const SCE: u64 = 1 << 0;
    pub const LME: u64 = 1 << 8;
    pub const LMA: u64 = 1 << 10;
    /// Bit 63 of a PTE means no-execute; with NXE clear it is a reserved
    /// bit, and touching such a page faults.
    pub const NXE: u64 = 1 << 11;
};

/// SYSCALL: CS = STAR[47:32], SS = that + 8. SYSRET to 64-bit code:
/// CS = STAR[63:48] + 16, SS = STAR[63:48] + 8, both with RPL 3.
pub const STAR: u32 = 0xC000_0081;
/// RIP of the SYSCALL entry.
pub const LSTAR: u32 = 0xC000_0082;
/// RFLAGS bits SYSCALL clears.
pub const SFMASK: u32 = 0xC000_0084;

pub const FS_BASE: u32 = 0xC000_0100;
pub const GS_BASE: u32 = 0xC000_0101;
/// What SWAPGS exchanges GS_BASE with.
pub const KERNEL_GS_BASE: u32 = 0xC000_0102;
/// What RDTSCP and RDPID return in ECX.
pub const TSC_AUX: u32 = 0xC000_0103;

/// RDMSR. A register this CPU does not have is a #GP: `readSafe` to probe.
pub inline fn read(msr: u32) u64 {
    var low: u32 = undefined;
    var high: u32 = undefined;
    asm volatile ("rdmsr"
        : [_] "={eax}" (low),
          [_] "={edx}" (high),
        : [_] "{ecx}" (msr),
    );
    return (@as(u64, high) << 32) | low;
}

/// WRMSR. A missing register or a reserved bit is a #GP: `writeSafe` to
/// probe.
pub inline fn write(msr: u32, value: u64) void {
    asm volatile ("wrmsr"
        :
        : [_] "{ecx}" (msr),
          [_] "{eax}" (@as(u32, @truncate(value))),
          [_] "{edx}" (@as(u32, @truncate(value >> 32))),
    );
}

// Published fault/fixup instruction addresses. Zero until the corresponding
// accessor runs once; each accessor republishes (idempotently) on entry, so
// the values are live before that call's own faulting instruction executes.
var rd_fault_rip: u64 = 0;
var rd_fixup_rip: u64 = 0;
var wr_fault_rip: u64 = 0;
var wr_fixup_rip: u64 = 0;

/// Consulted by the #GP handler. Returns the fixup RIP to resume at if
/// `rip` is a registered safe-MSR fault site, else null (let the fault take
/// its normal course). Cheap: two compares, no locks.
pub fn fixupRip(rip: u64) ?u64 {
    if (rd_fault_rip != 0 and rip == rd_fault_rip) return rd_fixup_rip;
    if (wr_fault_rip != 0 and rip == wr_fault_rip) return wr_fixup_rip;
    return null;
}

/// Read `msr`, returning null if the access raised #GP (MSR not present /
/// not emulated). Never panics.
///
/// Exactly ONE register output (`val`); `ok` and the fixup publishes are
/// `=m`. Zig 0.15.2 builds an asm's LLVM return struct over ALL its
/// outputs but fills only the register ones, so ≥2 register outputs next
/// to any `=m` output leave struct fields typed from uninitialized
/// compiler memory — "Invalid type" when the garbage points forward in the
/// type table, a silently wrong type when it doesn't (tools/asm_lint
/// rejects the shape). With one register output the return type is that
/// output's own, no struct. The value is folded from edx:eax inside the
/// asm for the same reason. On a #GP at label 1 the handler redirects to
/// label 2 (ok=0); the success path sets ok=1. %r8 is the address scratch
/// so the MSR-input register (ecx) is untouched. Modelled on vmx.zig's
/// vmlaunch fixup asm.
///
/// noinline is load-bearing: the "fixed instruction site" premise dies if
/// the compiler inlines this into multiple callers — each instance would
/// republish ITS OWN addresses into the shared globals, and two instances
/// racing on different CPUs leave one of them unmatched at fault time
/// (= unrecovered #GP panic). One pinned copy keeps the site link-time
/// invariant for real. Same rule in usercopy.zig / extable.zig.
pub noinline fn readSafe(msr: u32) ?u64 {
    var value: u64 = undefined;
    var ok: u64 = undefined;
    asm volatile (
        \\ leaq 1f(%rip), %r8
        \\ movq %r8, %[frip]
        \\ leaq 2f(%rip), %r8
        \\ movq %r8, %[fxup]
        \\1: rdmsr
        \\ shlq $32, %rdx
        \\ orq %rdx, %rax
        \\ movq %rax, %[val]
        \\ movq $1, %[ok]
        \\ jmp 3f
        \\2: movq $0, %[ok]
        \\3:
        : [val] "=r" (value),
          [ok] "=m" (ok),
          [frip] "=m" (rd_fault_rip),
          [fxup] "=m" (rd_fixup_rip),
        : [msr] "{ecx}" (msr),
        : .{ .rax = true, .rdx = true, .r8 = true, .memory = true }
    );
    if (ok == 0) return null;
    return value;
}

/// Write `value` to `msr`, returning false if the access raised #GP (MSR
/// not present / reserved-bit violation / not emulated). Never panics.
/// noinline: see readSafe.
pub noinline fn writeSafe(msr: u32, value: u64) bool {
    var ok: u64 = undefined;
    const lo: u32 = @truncate(value);
    const hi: u32 = @truncate(value >> 32);
    asm volatile (
        \\ leaq 1f(%rip), %r8
        \\ movq %r8, %[frip]
        \\ leaq 2f(%rip), %r8
        \\ movq %r8, %[fxup]
        \\1: wrmsr
        \\ movq $1, %[ok]
        \\ jmp 3f
        \\2: movq $0, %[ok]
        \\3:
        : [ok] "=r" (ok),
          [frip] "=m" (wr_fault_rip),
          [fxup] "=m" (wr_fixup_rip),
        : [msr] "{ecx}" (msr),
          [lo] "{eax}" (lo),
          [hi] "{edx}" (hi),
        : .{ .r8 = true, .memory = true }
    );
    return ok != 0;
}

/// Present-check helper: true iff `msr` reads back without faulting.
pub fn present(msr: u32) bool {
    return readSafe(msr) != null;
}

/// Boot self-test: prove the #GP fixup actually recovers a faulting MSR
/// access, and that it does NOT over-fire on a valid one. Reads a reserved
/// MSR that must #GP (a working fixup → null); if the host instead tolerates
/// it (KVM ignore_msrs, or the address happening to decode), we can't
/// exercise the fault here and say so — the log then distinguishes "verified"
/// from "present but not exercised on this host". On real hardware the
/// reserved read always #GPs, so this is a definitive check there.
/// Requires the IDT (with the exception fixup hook) to be live.
pub fn selfTest() void {
    const RESERVED: u32 = 0xFFFF_FFFF;
    if (readSafe(RESERVED)) |v| {
        debug.klog("[msr] fixup present but NOT exercised — host tolerated rdmsr(0x{X})=0x{X}\n", .{ RESERVED, v });
    } else {
        debug.klog("[msr] safe-MSR fixup VERIFIED — rdmsr(0x{X}) #GP recovered to null\n", .{RESERVED});
    }
    // Over-fire guard: a valid architectural MSR (IA32_TSC) must still
    // read back non-null. A null here would mean the fixup is redirecting
    // every rdmsr, not just the faulting one.
    if (readSafe(TSC) == null) {
        debug.klog("[msr] WARNING: readSafe(IA32_TSC) returned null — fixup OVER-FIRING\n", .{});
    }
}
