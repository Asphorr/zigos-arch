//! Dynamic IRQ dispatch — vectors 0x40..0x4F backed by per-vector naked
//! stubs (`DynIrqStub`) and a registry of installable Zig handlers
//! (`dyn_handlers`). Drivers grab a vector via `allocDynVector`, point an
//! MSI-X capability at it, then install their callback via `registerIrq`.
//!
//! Shape D — handler bodies run on the per-CPU `isr_stack` (not the
//! interrupted task's kstack), so reapCq + proc.wake chains can't corrupt
//! a parked task's saved RIP at kesp+48. We switch BACK to the task
//! kstack before `check_and_preempt_dynirq` so schedule() saves the
//! correct RSP into kernel_esp.

const std = @import("std");
const debug = @import("../../debug/debug.zig");
const serial = @import("../../debug/serial.zig");
const apic = @import("../../time/apic.zig");

pub const DYN_IRQ_BASE: u8 = 0x40;
pub const DYN_IRQ_COUNT: u8 = 16;

pub const DynHandler = *const fn () callconv(.c) void;

/// Dyn-IRQ stub stack-canary magic — pushed before `call handleDynIrq` and
/// verified afterwards. Catches IPI handlers (and their callees) writing
/// past their stack frame and into the stub's. Single named source;
/// `DYNIRQ_CANARY_STR` below embeds it into the inline asm so the literal
/// can't drift between the pushed and checked values.
pub const DYNIRQ_CANARY: u64 = 0x0C0FFEE0BA0BEDA0;

pub const DYNIRQ_CANARY_STR = std.fmt.comptimePrint("0x{X}", .{DYNIRQ_CANARY});

/// (a) Per-vector dyn-IRQ handler dispatch table. Slot value is the
/// fn-pointer stored as usize (0 = unregistered sentinel). Stored as a
/// scalar u64 — NOT `?DynHandler` — because a `?fn-pointer` is a 16-byte
/// fat type whose tag + payload would tear under concurrent read+install,
/// while a usize is a single 8-byte atomic load/store on x86_64.
///
/// Writers: registerIrq (BSP boot-time only — the boot_phase guard in
/// setGate would catch a post-boot rewrite if it ever happened).
/// Readers: handleDynIrq from any CPU that an MSI-X message steers to,
/// allocDynVector from BSP boot.
///
/// Ordering: registerIrq uses .release so a peer CPU that observes the
/// non-null slot (acquire-loaded in handleDynIrq) also observes the
/// handler-function memory it points at. Pairs naturally with the IPI
/// that the device's mask-write generates after registerIrq returns.
var dyn_handlers: [DYN_IRQ_COUNT]usize = .{0} ** DYN_IRQ_COUNT;

/// Reserve a free dynamic IRQ vector. Returns null if all 16 slots are in
/// use. Caller must `registerIrq(vec, handler)` immediately to install the
/// dispatch target — the slot is "taken" once the handler is non-zero.
pub fn allocDynVector() ?u8 {
    for (&dyn_handlers, 0..) |*slot, i| {
        if (@atomicLoad(usize, slot, .acquire) == 0) return DYN_IRQ_BASE + @as(u8, @intCast(i));
    }
    return null;
}

/// Bind a Zig handler to a previously-allocated dynamic vector. Subsequent
/// MSI-X messages for that vector arrive at the handler with interrupts
/// disabled; LAPIC EOI is issued automatically after the handler returns.
pub fn registerIrq(vec: u8, handler: DynHandler) void {
    if (vec < DYN_IRQ_BASE or vec >= DYN_IRQ_BASE + DYN_IRQ_COUNT) {
        debug.kwarn(@src(), "registerIrq vec=0x{X} outside dynirq range [0x{X}..0x{X})", .{ vec, DYN_IRQ_BASE, DYN_IRQ_BASE + DYN_IRQ_COUNT });
        return;
    }
    @atomicStore(usize, &dyn_handlers[vec - DYN_IRQ_BASE], @intFromPtr(handler), .release);
}

export fn handleDynIrq(vec: u32) callconv(.c) void {
    @import("../arch/protect.zig").disallowUserAccess();
    const t = @import("../../debug/perf.zig").enter();
    defer @import("../../debug/perf.zig").leave(.dynirq, t);
    // Breadcrumb: (vec << 16) | pid. cpu.current_pid read once.
    {
        const pid_now: u64 = if (@import("../smp.zig").myCpu().current_pid) |p| @intCast(p) else 0xFF;
        @import("../../debug/breadcrumb.zig").stamp(.irq_dynamic, (@as(u64, vec) << 16) | pid_now);
    }

    // Range-check: a vector below DYN_IRQ_BASE means the DynIrqStub's
    // baked vec_str immediate is wrong (or someone wired a non-dynirq
    // vector through this entry by mistake). Don't silently EOI — that
    // hides the bug.
    if (vec < DYN_IRQ_BASE or vec >= DYN_IRQ_BASE + DYN_IRQ_COUNT) {
        debug.kwarn(@src(), "handleDynIrq vec=0x{X} out of dynirq range — bogus stub immediate?", .{vec});
        if (apic.apic_active) apic.eoi();
        return;
    }

    const idx: usize = @intCast(vec - DYN_IRQ_BASE);
    const h_raw = @atomicLoad(usize, &dyn_handlers[idx], .acquire);
    if (h_raw != 0) {
        const h: DynHandler = @ptrFromInt(h_raw);
        h();
    } else {
        // Spurious-on-this-CPU: vector fired before registerIrq ran, or
        // after teardown. EOI'ing silently would let the device wedge
        // with no log; kwarn pings the audit-rate counter once.
        debug.kwarn(@src(), "dynirq vec=0x{X} fired with no handler installed", .{vec});
    }
    if (apic.apic_active) apic.eoi();
}

/// Shape C preempt-check: called from DynIrqStub's epilogue (after the IRQ
/// handler returned and the canary was popped, but BEFORE FXSAVE/GPR pops).
/// If a handler set `cpu.dynirq_preempt_pending`, run `schedule()` from
/// here — RSP at this point is inside the stub's own frame, sitting on the
/// task whose kstack the IRQ landed on; schedule's switchTo save lands at
/// a well-defined offset that has a valid post-`callq` RA at +48, the
/// next dispatch resumes correctly.
///
/// Why not let nvmeIrqHandler call schedule directly: when an IRQ inherits
/// the RSP of a task that is NOT current_pid (cross-stack-aliasing window
/// in the dispatch transition), schedule would save RSP into the WRONG
/// PCB's kernel_esp. Deferring to the stub epilogue doesn't fix that
/// underlying invariant, but the schedule-from-stub path has historically
/// been audit-checked and lock-clean, so this is the safer place to call
/// it while Shape D (per-CPU IRQ trampoline stack) is still pending.
pub export fn check_and_preempt_dynirq() callconv(.c) void {
    const smp_mod = @import("../smp.zig");
    const cpu = smp_mod.myCpu();
    if (cpu.dynirq_preempt_pending) {
        cpu.dynirq_preempt_pending = false;
        @import("../../proc/process.zig").schedule();
    }
}

/// Shape D: top of this CPU's dedicated IRQ-handler stack. DynIrqStub switches
/// RSP here for the `call handleDynIrq` window so device-IRQ handler bodies
/// (reapCq + proc.wake chains) never run on — and thus never corrupt — the
/// kstack of whatever task the IRQ happened to land on. Reuses `isr_stack`,
/// which is otherwise unused at runtime: tss.rsp0 is repointed to the current
/// task's kstack by setTssRsp0, and no IDT vector uses ist1. 16-aligned (the
/// buffer is `align(16)`, len 16384). Called with IF=0 (no nesting), so a
/// single per-CPU stack with no depth tracking is sufficient.
pub export fn dynirqIrqStackTop() callconv(.c) usize {
    const cpu = @import("../smp.zig").myCpu();
    return @intFromPtr(&cpu.isr_stack) + cpu.isr_stack.len;
}

// Per-vector naked stub. Each instantiation hardcodes its own vector # into
// the `mov $N, %edi` immediately before `call handleDynIrq` — that's how
// the dispatcher knows which IRQ fired without scanning ISR bits.
//
// Alignment math at `call handleDynIrq`:
//   CPU frame = 40 bytes, 9 GPRs = 72 bytes, FXSAVE = 512 bytes → 624B ≡ 0 mod 16 ✓
pub fn DynIrqStub(comptime vec: u8) type {
    const vec_str = std.fmt.comptimePrint("{d}", .{vec});
    return struct {
        pub fn handler() callconv(.naked) void {
            asm volatile ("pushq %%rax\n" ++
                    "pushq %%rcx\n" ++
                    "pushq %%rdx\n" ++
                    "pushq %%rdi\n" ++
                    "pushq %%rsi\n" ++
                    "pushq %%r8\n" ++
                    "pushq %%r9\n" ++
                    "pushq %%r10\n" ++
                    "pushq %%r11\n" ++
                    "subq $512, %%rsp\n" ++
                    "fxsaveq (%%rsp)\n" ++
                    // Shape D — run handleDynIrq on the per-CPU isr_stack
                    // instead of the interrupted task's kstack. This ends the
                    // cross-stack-aliasing class structurally: the handler
                    // body (reapCq + proc.wake) can no longer push onto
                    // whatever task kstack the IRQ landed on and clobber a
                    // parked task's saved RIP at kesp+48. We switch BACK to the
                    // task kstack before check_and_preempt_dynirq, so
                    // schedule()'s switchTo still saves the correct (task) RSP
                    // into kernel_esp — that selectivity is why a blanket IST=1
                    // wedged here before. Dyn-IRQ handlers run with IF=0 and
                    // never sti, so the single per-CPU stack can't be re-entered.
                    // Frame on isr_stack: [rsp+8]=saved task RSP, [rsp+0]=canary.
                    "call dynirqIrqStackTop\n" ++ // rax = this CPU's isr_stack top (16-aligned)
                    "movq %%rsp, %%rcx\n" ++ // rcx = task RSP (where the IRQ landed)
                    "movq %%rax, %%rsp\n" ++ // switch to the dedicated IRQ stack
                    "subq $16, %%rsp\n" ++ // 16-aligned scratch frame
                    "movq %%rcx, 8(%%rsp)\n" ++ // stash task RSP for the return switch
                    "movabsq $" ++ DYNIRQ_CANARY_STR ++ ", %%rax\n" ++
                    "movq %%rax, 0(%%rsp)\n" ++ // canary
                    "movl $" ++ vec_str ++ ", %%edi\n" ++ // arg (edi was clobbered by the call above)
                    "test $0xF, %%rsp\n" ++
                    "jnz isr_dynirq_align_panic\n" ++
                    "call handleDynIrq\n" ++
                    "movabsq $" ++ DYNIRQ_CANARY_STR ++ ", %%rax\n" ++
                    "cmpq %%rax, 0(%%rsp)\n" ++
                    "jne isr_dynirq_canary_panic\n" ++
                    "movq 8(%%rsp), %%rcx\n" ++ // reload saved task RSP
                    "movq %%rcx, %%rsp\n" ++ // back on the task kstack (discard IRQ-stack frame)
                    // Shape C: deferred-preempt check. If a handler called
                    // proc.wake() and set cpu.dynirq_preempt_pending, run
                    // schedule() from here (stub frame, sound RSP discipline)
                    // instead of from inside the handler. RSP is currently
                    // 16-aligned at top of FXSAVE area, so the call is ABI-
                    // clean. After return, fall through to fxrstor + GPR
                    // pops + iretq as if no preempt happened.
                    "call check_and_preempt_dynirq\n" ++
                    "fxrstorq (%%rsp)\n" ++
                    "addq $512, %%rsp\n" ++
                    "popq %%r11\n" ++
                    "popq %%r10\n" ++
                    "popq %%r9\n" ++
                    "popq %%r8\n" ++
                    "popq %%rsi\n" ++
                    "popq %%rdi\n" ++
                    "popq %%rdx\n" ++
                    "popq %%rcx\n" ++
                    "popq %%rax\n" ++
                    // Pre-iretq sanity check — shared with isr_irq0,
                    // isr_common_exc, retToUserStub. See SAFE_IRETQ.
                    @import("../../proc/sched_asm.zig").SAFE_IRETQ);
        }
    };
}

pub export fn isr_dynirq_align_panic() callconv(.c) noreturn {
    @panic("dynirq stub: RSP misaligned at call handleDynIrq — recount pushes");
}

/// Stack canary around `call handleDynIrq` got clobbered. The slot at
/// %rsp+8 was 0xC0FFEE0BA0BEDA0 before the call and is something else
/// now, meaning the IPI handler (or its callees) wrote past their stack
/// frame and into ours. Captures kstack snapshot for autopsy — most
/// useful: which value did the slot get overwritten with? That hints at
/// the source (a misaligned write, a return-frame computation, etc).
pub export fn isr_dynirq_canary_panic() callconv(.c) noreturn {
    const sym = @import("../../debug/symbols.zig");
    const rsp_now: u64 = asm volatile ("mov %%rsp, %[r]"
        : [r] "=r" (-> u64),
    );
    const slots: [*]const u64 = @ptrFromInt(rsp_now);
    serial.print("\n!!! DYNIRQ STACK CANARY CLOBBERED — IPI handler smashed stack !!!\n", .{});
    serial.print("  expected canary 0x{X:0>16} at 0x{X:0>16}+8\n", .{ DYNIRQ_CANARY, rsp_now });
    serial.print("  got 0x{X:0>16}", .{slots[1]});
    if (sym.resolveKernel(slots[1])) |r| {
        serial.print("  // {s}+0x{X}", .{ r.name, r.offset });
    }
    serial.print("\n  surrounding stack (32 qwords):\n", .{});
    @import("../../debug/kdbg.zig").crashAutopsy(.{ .kernel_rsp = rsp_now });
    @panic("dynirq canary clobbered — IPI handler corrupted stack");
}
