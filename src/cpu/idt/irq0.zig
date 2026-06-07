//! LAPIC timer IRQ (vector 0x20) — the hot path:
//!   - isr_irq0          : naked asm trampoline (push GPRs + FXSAVE + call)
//!   - handleIRQ0        : the Zig body — wallclock advance, watchdog peer
//!                         check, schedule + preempt decision, signal
//!                         delivery
//!   - deliverPendingToReturnFrame, rearmTimerForCurrent : helpers
//!   - hb_state_count_page : 4KB-isolated BSP heartbeat counter
//!   - isr_irq0_align_panic, isr_irq0_canary_panic       : exported targets
//!
//! See cpu/idt.zig for the IDT entry-table layout and the init() wiring.

const std = @import("std");
const io = @import("../../io.zig");
const apic = @import("../../time/apic.zig");
const process = @import("../../proc/process.zig");
const debug = @import("../../debug/debug.zig");
const serial = @import("../../debug/serial.zig");
const desktop = @import("../../ui/desktop.zig");
const xhci = @import("../../driver/xhci.zig");
const signals = @import("../../proc/signals.zig");
const perf = @import("../../debug/perf.zig");
const hrtimer = @import("../../proc/hrtimer.zig");

// TSC watermark for the elapsed-time wallclock advance (#1006). BSP-only,
// mutated solely inside handleIRQ0's `!was_soft_yield` block with IRQs off — no
// atomics needed (same single-writer regime as hb_state_count_page). The hires
// one-shot fires the timer EARLY for sub-quantum usleep deadlines, so the 100 Hz
// `tick_count` must advance by real elapsed quanta (hrtimer.ticksToAdvance), not
// one per fire, or every tick-keyed timeout would run fast.
var last_tick_tsc: u64 = 0;
var tick_tsc_seeded: bool = false;

/// IRQ0 stack-canary magic — pushed below the 15 GPRs at IRQ entry, verified
/// before iretq. Used by both the isr_irq0 asm (literal embedded for the
/// pushq immediate / cmpq immediate via comptimePrint) AND
/// isr_irq0_canary_panic's printed banner. Single named source.
pub const IRQ0_CANARY: u64 = 0x7B0FF1CE;

const IRQ0_CANARY_STR = std.fmt.comptimePrint("0x{X}", .{IRQ0_CANARY});

/// 4KB-isolated heartbeat counter. Lives in its own page so the MMU
/// write-watch (paging.installWriteWatch) catches ANY writer to the page —
/// the only legitimate writer is handleIRQ0 below. Earlier the count shared
/// a page with vga.col/row/bg, so the page-coarse watch fired on every
/// vga.print and drowned out the wild writer we're hunting.
pub var hb_state_count_page: struct {
    /// (u: BSP IRQ0 only) Bumped on every non-soft-yield IRQ0 on BSP, under
    /// cli. No cross-CPU reader of `.count` itself (the MMU write-watch
    /// uses the PAGE-protection bit, not the value). If you add a remote
    /// reader, retag this `(a)` and switch to @atomicStore/@atomicLoad —
    /// the +=  here would race with the read on x86_64-aligned u64 it
    /// won't tear, but a future LICM hoist could freeze the displayed
    /// value.
    count: u64 = 0,
    _pad: [4088]u8 = [_]u8{0} ** 4088,
} align(4096) = .{};

/// Forensic bisect — flip BISECT_ENABLED=true during a wild-writer hunt to
/// dump a serial line whenever the iretq-frame CS or SS differs from the
/// snapshot we took at entry. Comptime-gated so it costs nothing in normal
/// builds. Was load-bearing during the 2026-05-17 iretq-corruption hunt;
/// structurally fixed by the IST=1 / per-CPU isr_stack rework (Shape D).
const BISECT_ENABLED = false;
inline fn bisectPoint(comptime label: []const u8, frame: [*]const u64, snap: @import("../../debug/kdbg.zig").IretqSnap) void {
    if (comptime !BISECT_ENABLED) return;
    if (frame[16] == snap.cs and frame[19] == snap.ss) return;
    serial.print("[bisect] CORRUPTED AT: {s}\n", .{label});
    @import("../../debug/kdbg.zig").iretqValidate(frame, snap);
}

/// EOI helper — LAPIC path when apic_active, legacy-PIC fallback. Local
/// copy because putting it in idt.zig (the façade) would create a circular
/// import; misc_irq.zig has its own copy for the same reason.
fn sendEOI() void {
    if (apic.apic_active) {
        apic.eoi();
    } else {
        io.outb(0x20, 0x20);
    }
}

export fn handleIRQ0(rsp: u64) callconv(.c) void {
    // SMAP: timer IRQ during a syscall body inherits AC=1; clear it so the
    // scheduler / schedulable kernel work runs with SMAP enforcement. IRET
    // pops RFLAGS so AC is restored on return.
    @import("../arch/protect.zig").disallowUserAccess();

    // KASAN: same invariant as handleException — the saved-state region
    // must be on a live kstack. If we entered IRQ0 on a kstack whose owner
    // already exited, the body has been poisoned by markPcbDead and we trip
    // here with backtrace pointing at handleIRQ0's caller.
    @import("../../debug/kasan.zig").expectValid(rsp, 160);

    // Tier B.3: stack-alias live detector. Verifies our IRQ-entry RSP is
    // inside cpu.current_pid's expected kstack slot. Catches the cross-
    // stack aliasing state (e.g. cat running with RSP in idle1's slot)
    // BEFORE it propagates downstream into a switchTo save.
    @import("../../debug/stack_alias.zig").checkOwnRsp(rsp);

    // CpuLocal end-canary check (task #229). Any wild write that landed
    // anywhere past the live CpuLocal fields should have clobbered
    // magic_end, and we trap with the writer's call path still live.
    @import("../smp.zig").verifyEndCanary();

    // Snapshot iretq frame's CS/SS/RIP IMMEDIATELY (before perf, before
    // smp.myCpu(), before anything else). The snap is a STACK-LOCAL —
    // tasks migrate between CPUs across schedule(), so a per-CPU global
    // would compare against the wrong IRQ when the task wakes up on a
    // different CPU. Stack-local travels with the task.
    const frame_for_validate: [*]const u64 = @ptrFromInt(rsp);
    const irq_snap = @import("../../debug/kdbg.zig").iretqSnapshot(frame_for_validate);
    defer @import("../../debug/kdbg.zig").iretqValidate(frame_for_validate, irq_snap);

    // Wild-RIP hunt (task #224). Validate the saved RIP is in the user VA
    // range whenever we're about to iretq back to user mode. If something
    // wrote 0x80000C (or any non-user value) into frame[15] during this IRQ,
    // we panic HERE with the kernel stack still loaded — instead of letting
    // the bad RIP cause a #GP after iretq, by which point the kernel call
    // path that wrote it is gone.
    defer @import("../../debug/kdbg.zig").validateUserReturnIretq(frame_for_validate, 15, 16);

    // iretq-frame tripwire (task #230). Snapshot the iretq frame into the
    // current PCB so any kernel function calling
    // `iretq_canary.check(@src())` can detect mid-handler corruption with
    // the offending fn name. capture() also arms DR0 on the iretq RIP
    // slot (write-only, panic_dump) so the writer's instruction is caught
    // SYNCHRONOUSLY via #DB. invalidate() disarms DR0 and clears the
    // snapshot just before the iretq instruction.
    @import("../../debug/iretq_canary.zig").capture(frame_for_validate, 15);
    defer @import("../../debug/iretq_canary.zig").invalidate();

    // Software snap+validate for the `call handleIRQ0` saved-return-address
    // slot (different from the iretq frame at top of kstack — see task #224).
    // Read the slot's value at entry, compare at exit. If corruption hits,
    // panic with full diagnostic. Catches WHEN corruption happens; doesn't
    // identify the writer's RIP (use GDB hw watchpoint for that).
    const ret_addr_snap = @import("../../debug/kdbg.zig").snapshotHandleIRQ0RetAddr(rsp);
    defer @import("../../debug/kdbg.zig").validateHandleIRQ0RetAddr(rsp, ret_addr_snap);

    const t = @import("../../debug/perf.zig").enter();
    defer @import("../../debug/perf.zig").leave(.irq0_timer, t);
    const smp = @import("../smp.zig");
    const cpu = smp.myCpu();

    bisectPoint("entry", frame_for_validate, irq_snap);

    // Record this IRQ entry into the kdbg ring so post-mortem (if we DON'T
    // catch corruption via the validate above) shows what was running on
    // each CPU at each tick.
    {
        const pid_now: u8 = if (cpu.current_pid) |p| @intCast(p) else 0xFF;
        @import("../../debug/kdbg.zig").irqEvent(0, pid_now, frame_for_validate[15], @truncate(frame_for_validate[16]));
        // Breadcrumb: stamp BEFORE invariant scan so if the scan panics
        // the autopsy reflects we were in the IRQ0 path on this CPU.
        @import("../../debug/breadcrumb.zig").stamp(.irq0_timer, pid_now);
    }
    // PCB invariant scanner — every SCAN_PERIOD_TICKS (~1s). Cheap noop
    // on non-trigger ticks; on a trigger tick walks all alive PCBs and
    // panics on the first violation with the offending pid/field named.
    // Catches cross-stack-aliasing / kesp-clobber / kstack_top mismatch
    // shortly after they happen instead of after they manifest downstream.
    @import("../../debug/pcb_invariants.zig").maybeScan();
    // Cross-CPU aliasing scan — runs every 100 ticks (~1s) on BSP only.
    // (cheaper than per-CPU, since the state it checks is global). Catches
    // current_pid / idle_pid / tss.rsp0 collisions that would otherwise
    // show up as wild-RIP dispatches seconds later.
    // Was every tick during the 2026-05-17 netstat hunt; restored to 100
    // after IST=1 structural fix landed so compositor isn't starved.
    if (smp.isBSP() and (process.tick_count % 100) == 0) {
        @import("../../debug/cpu_alias.zig").scan();
    }

    // NVMe lost-IRQ sweeper (gap nvme#1, 2026-05-20). Every LAPIC tick on
    // BSP, drain any CQ entries the MSI-X-driven reapCq missed. Catches
    // the two race classes the in-code comment in nvme.tickSweep names:
    // (1) MSI-X message lost during mask/unmask retarget, (2) PCIe
    // posted-write ordering hiding the CQE from the IRQ-time read.
    // Closes the recurring SW-reaper-missed wedge the yield-loop
    // detector flagged on 2026-05-19 + 2026-05-20.
    //
    // virtio-gpu equivalent (gap virtio_gpu#3, 2026-05-20). Same
    // structural problem: the GPU's MSI-X can be dropped under
    // CVE-2024-3446 reentrancy, leaving the compositor parked in
    // blockOn(.gpu_io) forever even though the host already completed
    // the cmd. tickSweep wakes the parked waiter so its loop re-checks
    // (and with gap virtio_gpu#1's clflush, actually observes the
    // advanced used_idx instead of a stale L1 line).
    // NVMe + virtio-gpu lost-IRQ backstop sweeps used to run here, inline on
    // EVERY handleIRQ0 — including the soft-yield `int $0x20` path. They now
    // run in ksoftirqd (bottom-half, IF=1), raised from the real-hardware-tick
    // block below (gated on !was_soft_yield + a cadence), NOT here. Raising on
    // the soft-yield path would re-wake ksoftirqd through its OWN blockOn-driven
    // int $0x20 and spin it solid — caught in boot-verify as ~1600 drains/tick
    // with tick_count frozen.
    bisectPoint("after irqEvent", frame_for_validate, irq_snap);

    // Sync this CPU's DR0-DR3+DR7 from the watch manager's canonical state.
    // Cheap (5 mov-to-DRn) and gives us "global" semantics without a
    // dedicated IPI vector: arm/disarm on any CPU, every other CPU picks
    // it up within one timer tick (~10ms).
    @import("../../debug/watch.zig").applyLocal();
    bisectPoint("after applyLocal", frame_for_validate, irq_snap);

    // Read+clear the soft-yield flag set by the int $0x20 issuer (sysYield,
    // sysSleep, sysWaitpid, pipe block). We use this to distinguish a real
    // hardware LAPIC timer IRQ from a software resched — both come through
    // vector 0x20 with no other architectural difference. Previously this
    // was inferred from `from_user`, which conflated "kernel-mode preempted
    // by hardware timer" with "software int $0x20" and stopped tick_count
    // advancing during long kernel-mode work.
    const was_soft_yield = cpu.pending_soft_yield;
    cpu.pending_soft_yield = false;

    // BSP heartbeat: count hardware IRQ firings (skip soft yields so the
    // count tracks wallclock). Print every 200 firings (~2s at 100Hz) to
    // confirm BSP timer is alive. If the heartbeat stops advancing in
    // serial.log during a hang, BSP timer is dead — interrupts off, or a
    // triple-fault before IRET.
    if (cpu.cpu_id == 0 and !was_soft_yield) {
        hb_state_count_page.count += 1;
        if (hb_state_count_page.count % 200 == 0) {
            serial.print("[hb] cpu0 irq#{d} tick={d}\n", .{ hb_state_count_page.count, process.tick_count });
        }
        // SMI / stall detector: BSP-only because APs IRQ0 is irregular
        // (hlt suppression). Samples PM_TMR once per real (non-soft-yield)
        // BSP timer tick; logs windows >15 ms.
        @import("../../time/smi.zig").tick();
        // S10 heartbeat — proves the trap checkers are actually running.
        // Self-rate-limits to one log per ~60s.
        @import("../../debug/diag.zig").maybeHeartbeat(process.tick_count);
    }

    // Per-CPU tick — counted on EVERY IRQ0 (including soft yields) so the
    // watchdog peer-check sees forward progress regardless of cause. Bumped
    // BEFORE the peer check so a CPU that's only running soft yields still
    // shows up alive. cli is held throughout handleIRQ0 so the read+store is
    // race-free against this CPU's other code; @atomicStore is used so peer
    // @atomicLoad readers (watchdog, menubar, sys.cpustat) see ordered
    // values that the compiler can't hoist across IRQ entry.
    @atomicStore(u64, &cpu.irq_tick_count, cpu.irq_tick_count +% 1, .release);
    // Charge this tick as "idle" if the CPU was running its kernel idle PCB
    // at the moment of the IRQ. The /proc/cpustat consumer subtracts idle
    // from total to get utilization. Done under the same cli as irq_tick,
    // so a reader on another CPU never sees idle > irq.
    if (cpu.current_pid) |pid| {
        if (pid < process.procs.len and process.procs[pid].is_idle) {
            @atomicStore(u64, &cpu.idle_tick_count, cpu.idle_tick_count +% 1, .release);
        }
    }
    @import("../../debug/watchdog.zig").peerCheck(cpu);

    // Per-CPU execution trail — record where this CPU was interrupted.
    // Dumped from panic / watchdog autopsy so we can see recent execution
    // history even when stack walking is impossible (corrupt rbp, leaf
    // function freeze, NMI-handler-never-returned). saved_rip is at
    // stack[15] (15 GPRs pushed before RIP). 128-entry per-CPU ring,
    // ~1.3s of history at 100 Hz.
    @import("../../debug/exectrail.zig").recordIrq(frame_for_validate[15]);

    const stack: [*]const u64 = @ptrFromInt(rsp);
    const saved_cs = stack[16]; // 15 GPRs [0..14] + RIP [15] + CS [16]
    const from_user = (saved_cs & 3) != 0;

    // BSP-only wallclock work: tick_count advance, expired-sleep wake-ups,
    // HID polling, sound mixer pump, GDB break check. Gated on hardware IRQ
    // (NOT a software int $0x20) so soft yields stay cheap. Crucially this
    // is NOT gated on from_user — kernel-mode hardware-timer firings count
    // towards wallclock too. Previously we missed them, so tick stalled
    // whenever BSP was in long kernel work (FAT32 read, gpu flush) and the
    // UI/sleep timing went haywire.
    if (cpu.cpu_id == 0 and !was_soft_yield) {
        // Advance the 100 Hz wallclock by ELAPSED TSC, not one tick per fire:
        // the hires one-shot (#1006) fires the timer EARLY for sub-quantum
        // usleep deadlines, and those early fires must add 0 ticks — else every
        // tick-keyed sleep/timeout runs fast. TSC-deadline off ⇒ no early fires,
        // so keep the simple one-per-fire advance.
        var n_ticks: u32 = 1;
        const tpq = apic.tscPerQuantum();
        if (apic.tsc_deadline_active and tpq != 0) {
            const now_tsc = perf.rdtsc();
            if (!tick_tsc_seeded) {
                last_tick_tsc = now_tsc -% tpq; // first fire counts as one quantum
                tick_tsc_seeded = true;
            }
            const adv = hrtimer.ticksToAdvance(now_tsc, last_tick_tsc, tpq);
            last_tick_tsc = adv.last;
            n_ticks = adv.n;
            // Wake precise-usleep sleepers on EVERY fire, including the early
            // sub-quantum ones — arming the one-shot early is the whole point.
            process.wakeHiresExpired(now_tsc);
        }
        if (n_ticks > 0) {
            process.tick_count += n_ticks;
            bisectPoint("after tick++", frame_for_validate, irq_snap);
            process.wakeExpired();
            bisectPoint("after wakeExpired", frame_for_validate, irq_snap);
            process.deliverDueAlarms();
            bisectPoint("after deliverDueAlarms", frame_for_validate, irq_snap);
            // HID drain deferred to ksoftirqd (Inc 2b). The PRIMARY path is now
            // event-driven — xhciIrqHandler raises .hid on each HID MSI-X — so
            // normal input is no longer quantized to this tick. This every-real-
            // tick raise is the dropped-MSI-X backstop, kept at the old 100 Hz
            // pollHID cadence so worst-case input latency doesn't regress. raise()
            // returns false only before ksoftirqd exists (early boot) → inline
            // pollHID fallback so input is never dropped. Single-consumer holds:
            // .hid is only ever raised on the BSP (here + the BSP-directed xHCI
            // IRQ), so only the BSP's ksoftirqd (or this BSP tick) drains it.
            if (!@import("../../proc/softirq.zig").raise(.hid)) xhci.pollHID();
            bisectPoint("after pollHID", frame_for_validate, irq_snap);
            @import("../../driver/sound.zig").tick();
            bisectPoint("after sound.tick", frame_for_validate, irq_snap);

            // NVMe + virtio-gpu lost-IRQ backstop sweeps, deferred to ksoftirqd
            // (bottom-half, IF=1) instead of run inline here at IF=0. This block
            // is !was_soft_yield, so we raise ONLY on real hardware ticks — never
            // on ksoftirqd's own blockOn-driven soft yield (which would re-wake
            // it and spin). ~10 Hz: a dropped-MSI-X backstop needs no more, and a
            // low rate keeps ksoftirqd parked rather than churning the scheduler.
            // raise() returns false only before ksoftirqd exists (early boot) →
            // inline-sweep fallback so the backstop is never dropped.
            if (process.tick_count % 10 == 0) {
                const softirq = @import("../../proc/softirq.zig");
                if (!softirq.raise(.nvme)) @import("../../driver/nvme.zig").tickSweep();
                if (!softirq.raise(.virtio_gpu)) @import("../../driver/virtio_gpu.zig").tickSweep();
            }

            @import("../../debug/gdb_stub.zig").checkForBreak();
            bisectPoint("after gdb checkForBreak", frame_for_validate, irq_snap);
            // Auto-dump perf counters every ~5 seconds (500 ticks at 100Hz). The
            // counters survive the dump (no implicit reset) so the next dump shows
            // accumulated cost since boot. Use `perf reset` from the CLI to zero.
            if (process.tick_count % 500 == 0 and process.tick_count > 0) {
                @import("../../debug/perf.zig").dumpAll();
            }

            // Tier C.1: rotate DR0-DR3 across procs[].kernel_esp slots so any
            // wild writer (cross-CPU stack-aliasing source) trips with full RIP.
            // BSP-only update of canonical entries[]; APs pick up via lazy
            // applyLocal at their next IRQ entry. Cadence chosen to avoid
            // IPI-flood heisendetector — see watch.rotateKernelEspWatches docs.
            const watch_mod = @import("../../debug/watch.zig");
            if (process.tick_count % watch_mod.KESP_REROTATE_TICKS == 0 and
                process.tick_count > 0)
            {
                watch_mod.rotateKernelEspWatches();
            }

            // Phase 4 load balancer. Migrates one task per call from busiest
            // → idlest cpu when delta >= threshold. ~500 ms cadence keeps the
            // overhead minimal while still converging within a few balance
            // rounds after a load shift.
            if (process.tick_count % 50 == 0 and process.tick_count > 0) {
                process.loadBalance();
            }
        }
    }
    bisectPoint("after BSP wallclock", frame_for_validate, irq_snap);

    // CFS preemption check — re-enabled 2026-05-10 after the wake-race
    // fixes (project_wake_race_fixes.md) resolved the shell-freeze. The
    // input freeze was orphan-sleep, not checkPreempt contamination.
    // checkPreempt fires every tick on every CPU and accountRunningTick
    // mutates vruntime + slice_start_tick — required for CFS per-tick
    // fairness accounting; without it, vruntime is only updated at
    // preempt boundaries (via setState's .running→non-running path) which
    // works but is less timely.
    if (!was_soft_yield) process.checkPreempt();
    bisectPoint("after checkPreempt", frame_for_validate, irq_snap);

    // Decide whether to run the scheduler. Three cases:
    //   1. Real LAPIC timer fired while user code was running (from_user) →
    //      preempt as usual.
    //   2. Real LAPIC timer fired while kernel was running (Ring 0,
    //      !from_user, !was_soft_yield) → don't preempt the kernel mid-task.
    //   3. Software int $0x20 from sysYield/sysSleep/pipe block → reschedule.
    //      `was_soft_yield` is set explicitly by the caller; we no longer
    //      infer it from process state.
    if (from_user or was_soft_yield) {
        // Track per-process time usage (real-timer case only — yields are
        // voluntary and shouldn't penalize the slice budget).
        if (from_user) {
            if (cpu.current_pid) |pid| {
                process.getPCB(pid).ticks_used += 1;
                // Accounting tick — separate from `ticks_used` (which is
                // a slice-budget counter that resets each schedule). This
                // one accumulates across the lifetime of the PCB so
                // sysmon can show "%CPU since spawn".
                process.getPCB(pid).acct_cpu_ticks += 1;
            }
        }

        // Hardware IRQ needs an EOI; software int $0x20 doesn't (LAPIC ISR
        // bit was never set), but EOI on a non-asserted vector is harmless.
        if (!was_soft_yield) sendEOI();
        bisectPoint("after sendEOI", frame_for_validate, irq_snap);
        if (!was_soft_yield) rearmTimerForCurrent(cpu);
        bisectPoint("after rearmTimer", frame_for_validate, irq_snap);

        // Desktop force-yield only on BSP and only when preempting user
        // code. desktop is now a normal interactive-priority kernel task,
        // so schedule() will pick it ahead of normal/background user tasks
        // when it's ready — exactly the "give CPU back to desktop NOW"
        // semantic the legacy switchToScheduler had.
        if (cpu.cpu_id == 0 and from_user) {
            const force_yield = if (cpu.current_pid) |pid| process.getPCB(pid).ticks_used >= 4 else false;
            if (desktop.active and (desktop.shouldResumeDesktop() or force_yield)) {
                if (cpu.current_pid) |pid| process.getPCB(pid).ticks_used = 0;
                deliverPendingToReturnFrame(cpu, rsp);
                bisectPoint("after force_yield deliverSignals", frame_for_validate, irq_snap);
                process.schedule();
                bisectPoint("after force_yield schedule RESUME", frame_for_validate, irq_snap);
                // When this task is later re-dispatched, schedule returns.
                // Fall through to normal exit below.
                return;
            }
        }
        bisectPoint("after force_yield branch", frame_for_validate, irq_snap);

        // Deliver pending signals on the way back to user. We deliver here
        // (before schedule) so that the signal-frame mutation targets THIS
        // task's iretq frame on its own kstack — exactly the frame our
        // isr_irq0 will pop after handleIRQ0 returns. Skip when returning
        // to kernel mode or for tasks already in a handler.
        deliverPendingToReturnFrame(cpu, rsp);
        bisectPoint("after deliverPendingToReturnFrame", frame_for_validate, irq_snap);

        // Run the scheduler. schedule() may switch to another task via
        // switchTo (kernel-to-kernel ret) and eventually return here when
        // THIS task is re-scheduled. After it returns, we fall through to
        // isr_irq0's pop-and-iretq, which exits to wherever this task was
        // running before the IRQ.
        process.schedule();
        bisectPoint("after schedule RESUME", frame_for_validate, irq_snap);
        return;
    }

    sendEOI();
    bisectPoint("kernel-mode after sendEOI", frame_for_validate, irq_snap);
    rearmTimerForCurrent(cpu);
    bisectPoint("kernel-mode after rearmTimer", frame_for_validate, irq_snap);
    deliverPendingToReturnFrame(cpu, rsp);
    bisectPoint("kernel-mode after deliverPending", frame_for_validate, irq_snap);
}

/// If the process about to be resumed via iretq is heading back to user mode
/// AND has a deliverable signal, mutate its iretq frame so iretq lands inside
/// the user's signal handler. No-op for kernel-mode preemptions and for
/// processes already mid-handler.
///
/// Invariant: MUST be called from the CPU where `cpu.current_pid` is the
/// PCB's owning thread (cpu == myCpu()). `signal_mask` and
/// `in_signal_handler` are read PLAIN — only safe because no other CPU
/// mutates this thread's per-thread state. `pending_signals` IS multi-CPU-
/// mutated by signals.send() and is atomic-loaded below.
fn deliverPendingToReturnFrame(cpu: *@import("../smp.zig").CpuLocal, new_rsp: u64) void {
    const cur_pid = cpu.current_pid orelse return;
    const pcb = process.getPCB(cur_pid);
    if ((@atomicLoad(u32, &pcb.pending_signals, .acquire) & ~pcb.signal_mask) == 0) return;
    if (pcb.in_signal_handler) return;
    const frame: *signals.IrqFrame = @ptrFromInt(new_rsp);
    if ((frame.cs & 3) == 0) return; // returning to kernel — no handler call
    signals.deliverFromIrqFrame(pcb, frame);
}

/// Re-arm LAPIC for the right deadline based on what's about to run.
/// APs running idle sleep ~10x longer (≈100ms) — no useful work to wake for.
/// Everyone else gets one quantum (≈10ms).
fn rearmTimerForCurrent(cpu: *@import("../smp.zig").CpuLocal) void {
    const quantum = apic.timerQuantum();
    const is_ap_idle = cpu.cpu_id != 0 and blk: {
        const cur = cpu.current_pid orelse break :blk false;
        break :blk process.procs[cur].is_idle;
    };
    const base = if (is_ap_idle) quantum *| 10 else quantum;
    // BSP clamps the one-shot to the soonest precise-usleep deadline so it fires
    // exactly when a usleep is due (#1006). Only BSP runs wakeHiresExpired, so
    // only BSP needs the early fire. Gated on TSC-deadline mode: our deadlines
    // are absolute TSC ticks, the unit armOneShot wants only in that mode.
    if (cpu.cpu_id == 0 and apic.tsc_deadline_active) {
        apic.armOneShot(hrtimer.armDelta(base, perf.rdtsc(), process.nextHiresTsc()));
        return;
    }
    apic.armOneShot(base);
}

// Timer IRQ stub — push 15 GPRs, call handleIRQ0 (context switch),
// In the new (Linux-style) model, isr_irq0 does NOT swap rsp mid-function.
// Context switching is handled inside handleIRQ0 → schedule() → switchTo,
// which uses kernel-to-kernel `ret` to land THIS isr_irq0 instance back on
// the same kstack it started on (just paused while another task ran).
// When isr_irq0 resumes, it pops fxsave+GPRs from the SAME kstack that the
// pt_regs were saved on (i.e., the caller task's kstack), and iretq exits
// to wherever that task was running.
//
// KASAN frame canary: IRQ0_CANARY is pushed BEFORE the GPRs at IRQ entry
// and verified BEFORE iretq on exit. If a wild writer scribbles within
// ~528 bytes of the iretq frame between entry and exit, the canary slot
// is overwritten and isr_irq0_canary_panic fires with kdbg autopsy. The
// 8B canary push forces an 8B alignment compensation in the FXSAVE
// scratch (520 instead of 512) to keep `call handleIRQ0` 16-byte aligned
// per SysV ABI.
//
// Alignment math at `call handleIRQ0`:
//   CPU frame = 40 bytes, 15 GPRs = 120 bytes, FXSAVE = 512 bytes → 672B ≡ 0 ✓
pub fn isr_irq0() callconv(.naked) void {
    asm volatile (
        \\ pushq %%rax
        \\ pushq %%rcx
        \\ pushq %%rdx
        \\ pushq %%rbx
        \\ pushq %%rbp
        \\ pushq %%rsi
        \\ pushq %%rdi
        \\ pushq %%r8
        \\ pushq %%r9
        \\ pushq %%r10
        \\ pushq %%r11
        \\ pushq %%r12
        \\ pushq %%r13
        \\ pushq %%r14
        \\ pushq %%r15
        // KASAN canary, sits BELOW the 15 GPRs so iretq-frame indices in iretqValidate stay unchanged
        ++ "\npushq $" ++ IRQ0_CANARY_STR ++ "\n" ++
        \\ movw $0x10, %%ax
        \\ movw %%ax, %%ds
        \\ movw %%ax, %%es
        \\ subq $520, %%rsp          // FXSAVE 512 + 8 padding to keep `call` 16-byte aligned (canary push added 8B)
        \\ fxsaveq (%%rsp)
        \\ leaq 528(%%rsp), %%rdi    // GPR_start = skip FXSAVE (520) + canary slot (8)
        \\ test $0xF, %%rsp
        \\ jnz isr_irq0_align_panic
        \\ call handleIRQ0
        \\ fxrstorq (%%rsp)
        \\ addq $520, %%rsp          // back to canary slot
        // canary must be intact — slot still holds IRQ0_CANARY
        ++ "\ncmpq $" ++ IRQ0_CANARY_STR ++ ", (%%rsp)\n" ++
        \\ jne isr_irq0_canary_panic
        \\ addq $8, %%rsp            // pop canary
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
        // Pre-iretq sanity check — wild-iretq-frame bug hits with valid
        // CS=0x08 but wild RIP=0x3, so checking CS alone is insufficient.
        // sched_asm.SAFE_IRETQ asserts RIP >= 0x1000 AND CS in {0x08, 0x23}.
        ++ @import("../../proc/sched_asm.zig").SAFE_IRETQ);
}

pub export fn isr_irq0_align_panic() callconv(.c) noreturn {
    @panic("isr_irq0: RSP misaligned at call handleIRQ0 — recount pushes");
}

/// Reached via `jne` from isr_irq0 epilogue when the canary slot just below
/// the iretq frame doesn't match the magic we pushed at entry. Stack layout
/// at jump time: %rsp points at the corrupted canary slot; iretq frame
/// (RIP, CS, RFLAGS, RSP, SS) sits at %rsp+8..%rsp+48. The function reads
/// both and reports them; if the iretq RIP itself looks bad too, the writer
/// hit a wider span than just the canary.
pub export fn isr_irq0_canary_panic() callconv(.c) noreturn {
    const sym = @import("../../debug/symbols.zig");

    const rsp_now: u64 = asm volatile ("mov %%rsp, %[r]"
        : [r] "=r" (-> u64),
    );
    // Layout from rsp_now (canary slot) going UP toward kstack top:
    //   slots[0]      = canary slot
    //   slots[1..16]  = 15 saved GPRs in push order: r15, r14, r13, r12, r11,
    //                   r10, r9, r8, rdi, rsi, rbp, rbx, rdx, rcx, rax
    //   slots[16..21] = iretq frame: RIP, CS, RFLAGS, RSP, SS
    const slots: [*]const u64 = @ptrFromInt(rsp_now);
    const got_canary = slots[0];

    serial.print("\n!!! isr_irq0 CANARY CLOBBERED — wild writer scribbled IRQ frame !!!\n", .{});
    serial.print("  canary slot 0x{X:0>16}: expected 0x{X:0>16}, got 0x{X:0>16}\n", .{ rsp_now, IRQ0_CANARY, got_canary });

    serial.print("  saved GPRs (push order, bottom→top):\n", .{});
    const gpr_names = [_][]const u8{ "r15", "r14", "r13", "r12", "r11", "r10", "r9 ", "r8 ", "rdi", "rsi", "rbp", "rbx", "rdx", "rcx", "rax" };
    for (gpr_names, 0..) |name, i| {
        serial.print("    {s} = 0x{X:0>16}\n", .{ name, slots[1 + i] });
    }

    serial.print("  iretq frame:\n", .{});
    serial.print("    RIP   =0x{X:0>16}", .{slots[16]});
    if (sym.resolveKernel(slots[16])) |r| {
        serial.print("  ({s}+0x{X})", .{ r.name, r.offset });
    }
    serial.print("\n    CS    =0x{X:0>4}\n", .{slots[17]});
    serial.print("    RFLAGS=0x{X:0>16}\n", .{slots[18]});
    serial.print("    RSP   =0x{X:0>16}\n", .{slots[19]});
    serial.print("    SS    =0x{X:0>4}\n", .{slots[20]});

    @import("../../debug/kdbg.zig").crashAutopsy(.{ .kernel_rsp = rsp_now });
    @panic("isr_irq0 canary clobbered — wild writer caught");
}
