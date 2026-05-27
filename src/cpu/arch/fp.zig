// FPU/SSE context save/restore plumbing.
//
// On every user↔kernel transition we fxsave (or fxrstor) a 512-byte block on
// the kernel stack so user processes don't see each other's XMM state — and
// don't see kernel-side SSE spills leaking into their registers.
//
// Layout details:
//   * 512 bytes, 16-byte aligned (fxsave/fxrstor requirement).
//   * Format defined by Intel SDM Vol 1 §10.5.1 (FXSAVE save area).
//
// This module owns the canonical "init" FP state — captured once at boot via
// `fninit; fxsave64` — that retToUserStub (sched_asm.zig) fxrstors directly
// from this .data symbol on first dispatch. It is read-only after boot and
// shared by every new process; nothing copies it onto the kstack.
//
// Why .data, not kstack? Earlier we copied init_template into a 512B block at
// stack_top - 672 on every new process. That put MXCSR at stack_top - 648 —
// the same address where the syscall-entry / IRQ-stub `call` instruction
// later pushes its return address. If anything re-stamped the init bytes on
// a live kstack (slot reuse, mid-flight re-init, etc.), the saved ret addr
// turned into 0x0000FFFF00001F80 (MXCSR + MXCSR_MASK) and the next `ret`
// faulted in kernel mode. Eliminating the kstack copy removes the alias.

/// Canonical "init" FXSAVE state, captured at boot from a clean FPU. Loaded
/// directly via `fxrstorq init_template(%rip)` in retToUserStub for the first
/// user-mode dispatch (gives a defined FPU/MXCSR for new tasks). Exported so
/// the linker symbol is visible to inline asm.
///
/// 16-byte aligned because fxsave/fxrstor #GP on misaligned destinations.
pub export var init_template: [512]u8 align(16) = [_]u8{0} ** 512;

/// Capture the FPU/SSE "init" state once at boot. Run after enableSSE() so
/// CR0.MP/CR4.OSFXSR are set, otherwise fxsave traps #UD or #NM.
///
/// `init_template` is a single global shared by all CPUs — there are no
/// per-CPU templates because `fninit` is deterministic across cores of the
/// same microarch, so any CPU would capture the same bytes. Call from the
/// BSP only; APs read the same buffer.
pub fn captureInitTemplate() void {
    asm volatile (
        \\ fninit
        \\ fxsaveq %[buf]
        : [buf] "=m" (init_template),
    );

    // Sanity-check MXCSR (FXSAVE offset 24, 4 bytes). Expected value is the
    // x86 reset default 0x1F80: all six FP exceptions masked, round-to-
    // nearest, no flush-to-zero. Any other value here means either (a) the
    // CPU/firmware came up with a non-standard MXCSR, or (b) some earlier
    // boot code touched MXCSR before we got to capture the "clean" state.
    // Both turn into baffling FP-rounding/exception bugs in user mode that
    // are nearly impossible to reproduce without this anchor — fail loud
    // here instead.
    const mxcsr: u32 = @as(*const u32, @ptrCast(@alignCast(&init_template[24]))).*;
    if (mxcsr != 0x1F80) {
        @panic("fp.captureInitTemplate: unexpected MXCSR (FPU init state polluted before capture)");
    }
}
