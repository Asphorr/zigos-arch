//! Low-level context-switch and kernel→user primitives.
//!
//! `switchTo` is the kernel↔kernel context-switch primitive. It uses the
//! `ret` instruction — never `iretq` — so every task spends its switched-
//! out time paused inside `switchTo` (or wherever it last yielded via
//! `schedule()`) and resumes from that exact point when re-scheduled.
//! Every dispatch except a task's first one flows through `switchTo`.
//!
//! `retToUserStub` is the SOLE iretq site in the entire dispatch path.
//! It's planted as the synthetic "ret target" for newly-created tasks
//! (process.create / forkCurrent / cloneCurrent) and reached on first
//! dispatch when `switchTo` rets into it. After that single iretq the
//! task lives in user mode; the next IRQ/syscall pushes a new frame on
//! its kstack, and any subsequent dispatch resumes via `switchTo`'s ret
//! at the schedule() call site — NOT via this stub.
//!
//! Together these replace the legacy `enterUserMode` + `returnToKernel`
//! pair (deleted in the Linux-style dispatch refactor — one iretq site
//! for first-dispatch only, kernel↔kernel via plain `ret`). The legacy
//! names live on only as tombstone comments in this file and idt.zig
//! marking removed crash-diagnostic state that depended on them.

const std = @import("std");

/// Save the calling task's kernel context (6 callee-saves + RSP) and
/// switch to `next_kesp`'s kernel context. The next task resumes at
/// wherever it last called `switchTo` from. When THIS task is later
/// re-scheduled, `switchTo` "returns" to its caller as if nothing
/// happened.
///
/// Caller convention (SysV first/second args):
///   RDI = &prev.kernel_esp or NULL — current task's kernel_esp slot
///         to save into. NULL means "skip the save" (used when prev is
///         being torn down — destroyCurrentWithStatus's schedule call
///         clears cpu.current_pid first, then schedule() passes null
///         here so we don't write into a doomed PCB slot — and on the
///         first-dispatch paths enterFirstTask{,Ap} where there's no
///         PCB to save into).
///   RSI = next.kernel_esp — next task's saved RSP value.
///
/// (Phase 5 retired: the third `save_in_flight_clear` arg + the asm-side
/// `movl $-1, (%%rdx)` clear. Per-CPU dispatch (Phase 2) eliminated the
/// cross-CPU dispatch race; exit_requested + schedule's prev_save→null
/// when state is .zombie/.unused (Phase 3) eliminated the kill-vs-save
/// race. The save_in_flight_prev gate had no remaining readers.)
///
/// Callers must already have:
///   - committed CR3 to the next task's address space (vmm.switchAddressSpace)
///   - updated TSS.RSP0 to next task's kstack top (gdt.setTssRsp0)
///   - claimed the next task's state (.ready → .running CAS)
pub fn switchTo() callconv(.naked) void {
    asm volatile (
        \\ pushq %%rbp
        \\ pushq %%rbx
        \\ pushq %%r12
        \\ pushq %%r13
        \\ pushq %%r14
        \\ pushq %%r15
        // Save prev's RSP — but skip if RDI==0 (doomed-prev / first-dispatch).
        \\ testq %%rdi, %%rdi
        \\ jz 1f
        \\ movq %%rsp, (%%rdi)
        \\ 1:
        \\ movq %%rsi, %%rsp
        \\ popq %%r15
        \\ popq %%r14
        \\ popq %%r13
        \\ popq %%r12
        \\ popq %%rbx
        \\ popq %%rbp
        \\ retq
    );
}

/// Inline wrapper to call the naked `switchTo` from regular Zig code.
/// Sets RDI/RSI per SysV ABI, then does an indirect call into the naked
/// function. Clobber list matches what switchTo (and any code between
/// switch-out and switch-back) may touch — caller is allowed to rely on
/// saved/restored callee-saves only via Zig's normal frame, which the
/// indirect call preserves because it goes through the standard
/// call+ret pattern.
pub inline fn switchToCall(prev_save: ?*u64, next_kesp: u64) void {
    asm volatile ("callq *%[addr]"
        :
        : [addr] "r" (@intFromPtr(&switchTo)),
          [_] "{rdi}" (if (prev_save) |p| @intFromPtr(p) else @as(usize, 0)),
          [_] "{rsi}" (next_kesp),
        : .{
            .rax = true, .rcx = true, .rdx = true,
            .rsi = true, .rdi = true,
            .r8 = true, .r9 = true, .r10 = true, .r11 = true,
            .memory = true,
        }
    );
}

/// Soft-yield to the scheduler via `int $0x20` (the LAPIC timer vector,
/// which `handleIRQ0` knows how to fold into a reschedule when
/// `cpu.pending_soft_yield` is set).
///
/// The CPU pushes 5 qwords (RIP/CS/RFLAGS/RSP/SS) at `int`, so RSP must
/// be 16-byte aligned at the int instruction or the downstream
/// `call handleIRQ0` enters with RSP misaligned. The save/align/restore
/// dance does this without trusting whatever the caller's prologue
/// (or Zig's codegen) left in RSP.
///
/// Caller responsibilities BEFORE calling:
///   - Call `process.setState(pid, .sleeping)` (or other non-.running) so
///     schedule() will pick someone else. setState routes through the
///     per-CPU runqueue book-keeping (Phase 1 parallel-track). Without
///     the state flip the IRQ0 path resumes the same PCB after a tick.
///   - Set `cpu.pending_soft_yield = true` so handleIRQ0 distinguishes
///     this from a real hardware timer firing.
///   - Set any wait_kind / wait_target / wake_tick the caller depends on
///     for the wake-back-up signal.
pub fn softYield() void {
    asm volatile (
        \\ movq %%rsp, %%rax
        \\ andq $-16, %%rsp
        \\ int $0x20
        \\ movq %%rax, %%rsp
        ::: .{ .rax = true, .memory = true });
}

/// Common pre-iretq sanity check shared by `retToUserStub` (sched_asm.zig),
/// `isr_irq0`, `isr_common_exc`, and the dynamic-IRQ stubs (idt.zig).
///
/// Asserts that the iretq frame at the top of the kernel stack is
/// well-formed before letting the CPU consume it:
///   - RIP (RSP+0) >= 0x1000 — wild values like 0x3, 0x40, 0x37F
///     fail this. (CS=0x08 alone is insufficient — the wild-iretq-frame
///     bug hit with valid CS but RIP=0x3.)
///   - CS (RSP+8) is 0x08 (kernel) or 0x23 (user) — anything else is
///     a corrupt frame.
///
/// On match: `iretq`. On mismatch: `jmp isr_iretq_corrupt_panic`, which
/// dumps the bad frame and halts. Numeric labels 1f/2f are local to each
/// `asm volatile` block, so concatenating this constant into multiple
/// stubs doesn't cause symbol clashes.
pub const SAFE_IRETQ = "\n" ++
    \\ cmpq $0x1000, 0(%%rsp)
    \\ jb 2f
    \\ cmpq $0x08, 8(%%rsp)
    \\ je 1f
    \\ cmpq $0x23, 8(%%rsp)
    \\ je 1f
    \\ 2:
    \\ jmp isr_iretq_corrupt_panic
    \\ 1:
    \\ iretq
++ "\n";

/// Iretq stub used as the synthetic "ret target" for newly created tasks.
/// NOT called via `call` — reached via `ret` from `switchTo` popping this
/// function's address from the new task's kstack.
///
/// Stack layout at entry (RSP = pcb.kernel_esp + 56 after switchTo's ret):
///   [RSP+0    .. RSP+120] : 15 GPR slots (zeroed for new task)
///   [RSP+120  .. RSP+160] : iretq frame  (RIP, CS, RFLAGS, user RSP, user SS)
///
/// FP state is loaded from the global `init_template` (.data) via RIP-relative
/// fxrstor. Earlier versions copied init_template onto the kstack at
/// stack_top - 672 and fxrstor'd from (%rsp); that put MXCSR exactly at
/// stack_top - 648, aliasing the saved ret-addr slot of every subsequent
/// syscall/IRQ on the same kstack. Loading from .data eliminates the alias.
///
/// Restores FP, pops GPRs, iretqs to user. No path back here on this
/// task — subsequent dispatches resume at the schedule() call site.
pub fn retToUserStub() callconv(.naked) void {
    asm volatile (
        \\ fxrstorq init_template(%%rip)
        \\ popq %%r15
        \\ popq %%r14
        \\ popq %%r13
        \\ popq %%r12
        \\ popq %%r11
        \\ popq %%r10
        \\ popq %%r9
        \\ popq %%r8
        \\ popq %%rdi
        \\ popq %%rsi
        \\ popq %%rbp
        \\ popq %%rbx
        \\ popq %%rdx
        \\ popq %%rcx
        \\ popq %%rax
        // Pre-iretq sanity check — corrupt frame here means the planted
        // iretq frame from process.create is wrong from the start or got
        // scribbled before first dispatch.
        ++ SAFE_IRETQ);
}
