//! Stack-alias detector — Tier B.3.
//!
//! Fires every timer IRQ on every CPU. Verifies the IRQ-entry RSP is inside
//! `cpu.current_pid`'s expected kstack slot. If it isn't, we've caught the
//! cross-stack aliasing state LIVE — a CPU running with RSP in a different
//! PCB's kstack — instead of waiting for the downstream switchTo save to
//! catch the symptom.
//!
//! Why this exists separate from the C.1 kernel_esp DR watchpoint:
//!   - C.1 catches `switchTo`'s save-instruction writing a cross-slot value
//!     into a PCB. That's the SYMPTOM (the wrong RSP got saved).
//!   - B.3 catches the wrong RSP itself, the moment a timer IRQ samples it.
//!     That's the LIVE STATE (a CPU is currently on the wrong kstack).
//!
//! Cost: one expected_top load + two compares per timer IRQ (~5 ns). No
//! IPIs, no per-CPU stash.

const config = @import("../config.zig");
const process = @import("../proc/process.zig");
const smp = @import("../cpu/smp.zig");
const debug = @import("debug.zig");

pub const ENABLE: bool = true;

/// Called from handleIRQ0 with the IRQ-entry RSP. Returns silently when:
///   - feature disabled
///   - cpu.current_pid is null (scheduler context — no expected slot)
///   - cpu.current_pid's expected_kstack_top is 0 (PCB still being created)
///   - RSP is inside cpu.current_pid's allow-range (the normal case)
///   - RSP is inside this CPU's IST1 stack AND the iretq frame's saved
///     RSP (the actual preempted task's RSP) is inside the allow-range,
///     because IRQ0/dyn IRQs route through IST=1 (see idt.zig setGateIst)
///     so the handler entry RSP is always IST1, not the task kstack.
///   - RSP is inside this CPU's IST1 AND the preempted CS was user
///     (the preempted task was in userspace; no kstack RSP to validate).
///
/// Panics with full kdbg dump when the check fails — the cross-stack
/// aliasing live state. The panic is what we want: at this moment we
/// still have the bad RSP on the kernel stack so the crash autopsy
/// walks meaningful memory; if we let it continue, the next switchTo
/// save would corrupt yet another PCB.
pub fn checkOwnRsp(rsp: u64) void {
    if (!ENABLE) return;

    const cpu = smp.myCpu();
    const cur = cpu.current_pid orelse return;
    if (cur >= config.MAX_PROCS) return;

    const expected_top = @atomicLoad(usize, &process.expected_kstack_tops[cur], .acquire);
    if (expected_top == 0) return;

    // Allow-window matches the C.1 predicate: 4×KSTACK_SIZE below
    // expected_top, covering both pool slots (KSTACK_SIZE body) and
    // heap kstacks up to 4× that size (desktop's 64 KB at the time of
    // writing).
    const allow_lo = expected_top -% (config.KSTACK_SIZE * 4);

    // Determine the RSP we actually want to validate. If `rsp` is on
    // this CPU's IST1 stack, IRQ0 routed through IST=1 — the handler
    // entry RSP isn't the preempted task's RSP. The iretq frame's
    // saved RSP is what we should check instead.
    const isr_lo = @intFromPtr(&cpu.isr_stack);
    const isr_hi = isr_lo + cpu.isr_stack.len;
    const on_ist1 = rsp >= isr_lo and rsp < isr_hi;

    var rsp_to_check = rsp;
    if (on_ist1) {
        // isr_irq0 hands the handler a `rsp` pointing at GPR_start (bottom of
        // the 15 GPRs). The iretq frame lives ABOVE the GPRs at offsets
        // 120..160 from `rsp`. With IST=1 the CPU pushes the full 5-qword
        // frame even on kernel→kernel transitions.
        //   rsp[15] = RIP
        //   rsp[16] = CS
        //   rsp[17] = RFLAGS
        //   rsp[18] = saved RSP  (always populated under IST)
        //   rsp[19] = SS
        const frame: [*]const u64 = @ptrFromInt(rsp);
        const saved_cs = frame[16];
        const saved_rsp = frame[18];
        // CS bits 0..1 = RPL; RPL=3 means user. Skip kstack check then.
        if ((saved_cs & 0x3) == 3) return;
        rsp_to_check = saved_rsp;
    }

    if (rsp_to_check >= allow_lo and rsp_to_check < expected_top) return;

    // RSP is outside cur's expected slot — live cross-stack aliasing.
    debug.klog(
        "[stack-alias] LIVE cpu{d} entry_rsp=0x{X:0>16} check_rsp=0x{X:0>16} on_ist1={any} pid={d} expected=[{X:0>16}..{X:0>16})\n",
        .{ cpu.cpu_id, rsp, rsp_to_check, on_ist1, cur, allow_lo, expected_top },
    );
    debug.klog(
        "  procs[{d}].kernel_esp=0x{X:0>16} kernel_stack_top=0x{X:0>16}\n",
        .{ cur, process.procs[cur].kernel_esp, process.procs[cur].kernel_stack_top },
    );
    @import("kdbg.zig").enterCritical();
    @import("kdbg.zig").dumpAll();
    @panic("stack_alias: CPU running on wrong kstack — cross-stack aliasing live state");
}
