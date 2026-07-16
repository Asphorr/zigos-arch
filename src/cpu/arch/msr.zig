// Fault-tolerant MSR access — rdmsrSafe / wrmsrSafe.
//
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
/// The value is folded from edx:eax into one `=r` output *inside* the asm,
/// rather than the usual pmu.zig-style split `={eax}`/`={edx}` outputs
/// combined in Zig. That split form is cleaner, but binding the two
/// register-specific outputs alongside the `=m` fixup-address publishes and
/// the internal labels miscompiles on this toolchain (Zig 0.15.2 + LLVM 20:
/// "Invalid TYPE table: Only named structs can be forward referenced"). The
/// single-register combine sidesteps it; the perf difference is nil (MSR
/// access isn't hot). The two `=m` publishes mirror fp.zig's fxsave. On a
/// #GP at label 1 the handler redirects to label 2 (ok=0); the success path
/// sets ok=1. %r8 is the address scratch so the MSR-input register (ecx) is
/// untouched. Modelled on vmx.zig's vmlaunch fixup asm.
pub fn rdmsrSafe(msr: u32) ?u64 {
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
          [ok] "=r" (ok),
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
pub fn wrmsrSafe(msr: u32, value: u64) bool {
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
pub fn msrPresent(msr: u32) bool {
    return rdmsrSafe(msr) != null;
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
    if (rdmsrSafe(RESERVED)) |v| {
        debug.klog("[msr] fixup present but NOT exercised — host tolerated rdmsr(0x{X})=0x{X}\n", .{ RESERVED, v });
    } else {
        debug.klog("[msr] safe-MSR fixup VERIFIED — rdmsr(0x{X}) #GP recovered to null\n", .{RESERVED});
    }
    // Over-fire guard: a valid architectural MSR (IA32_TSC, 0x10) must still
    // read back non-null. A null here would mean the fixup is redirecting
    // every rdmsr, not just the faulting one.
    if (rdmsrSafe(0x10) == null) {
        debug.klog("[msr] WARNING: rdmsrSafe(IA32_TSC) returned null — fixup OVER-FIRING\n", .{});
    }
}
