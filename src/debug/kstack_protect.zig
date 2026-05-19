// Kstack page-protection — catches cross-task kstack writes.
//
// The netstat-desktop bug (2026-05-17): when pid=4 (netstat) exits, the
// destroy path somehow zeros the kstacks of pid=2 (desktop) and pid=3
// (shell), leaving wild RIPs at their saved-RIP slots. Hardware
// watchpoints (DR0-DR3) can't catch this reliably: too few slots, plus
// false-positive noise from legit same-kstack writes (memcpy from disk
// into a stack-local buffer, IRQ entry FXSAVE pushes).
//
// This module: mark a target task's kstack pages R/W=0 via PTE bit. ANY
// kernel write to those pages then traps as #PF with CR2 = the wild
// address and RIP = the writer's instruction. The CPU does the filtering
// for us — only writes to those specific pages trap, no software filter
// needed. Pattern matches Linux's CONFIG_DEBUG_PAGEALLOC / KFENCE.
//
// SMP correctness: this version uses `tlb.shootdownAll(0)` to broadcast
// the PTE change to every CPU. The previous local-invlpg-only design
// triple-faulted when pid=2 was protected from cpu0 while running on
// cpu1 — cpu1's stale TLB let the write through, then a follow-up
// kstack write during IRQ entry actually trapped on cpu1 with no
// stack to push the exception frame onto. Broadcast shootdown closes
// that gap.
//
// Window: the protection is intended to be ACTIVE only during the
// destroy-of-another-task critical section (destroyCurrentWithStatus
// → tearDownTask). Outside that window, the kstacks are RW as normal.
// Tasks in PROTECTED_PIDS that are CURRENTLY running on any CPU are
// skipped (we'd brick that CPU). A wakeup mid-window is handled by
// `unprotectPidIfProtected` in the schedule path.

const std = @import("std");
const process = @import("../proc/process.zig");
const paging = @import("../mm/paging.zig");
const config = @import("../config.zig");
const smp = @import("../cpu/smp.zig");
const tlb = @import("../cpu/tlb.zig");
const serial = @import("serial.zig");

/// Pids whose kstacks get protected during another-task's destroy window.
/// These are the netstat-desktop victims (desktop=2, shell=3). Update
/// the list if the kstack-corruption symptom moves to other pids.
pub const PROTECTED_PIDS = [_]u8{ 2, 3 };

/// Currently-protected bitmask (1 bit per PROTECTED_PIDS slot). Lets the
/// schedule-side `unprotectPidIfProtected` skip the broadcast shootdown
/// when nothing actually needs unprotecting (the common case — protection
/// only spans the destroy critical section, not every dispatch). Read
/// non-atomically here because the only writers are the BSP-side destroy
/// path (protectAll/unprotectAll); the schedule path readers tolerate a
/// briefly-stale view (worst case: extra shootdown, never missed one).
var protected_mask: u32 = 0;

inline fn isInProtectedList(pid: usize) bool {
    for (PROTECTED_PIDS) |p| {
        if (@as(usize, p) == pid) return true;
    }
    return false;
}

inline fn slotOf(pid: usize) ?u5 {
    inline for (PROTECTED_PIDS, 0..) |p, i| {
        if (@as(usize, p) == pid) return @intCast(i);
    }
    return null;
}

/// True if `pid` is `.current_pid` on any CPU right now. Used to skip
/// protection — marking a running task's kstack RO would brick that CPU
/// the next time it tries to use the kstack (IRQ entry, syscall return,
/// ordinary push).
inline fn isRunningAnywhere(pid: usize) bool {
    for (&smp.cpus, 0..) |*c, i| {
        if (i != 0 and !c.alive) continue;
        if (c.current_pid) |cur| {
            if (cur == pid) return true;
        }
    }
    return false;
}

/// Walk all 4KB pages of `pid`'s kstack and mark R/W=0 via PTE bit.
/// No-op if the witness top is unset (PCB not yet alive) or if `pid`
/// is currently running on any CPU. PTE write only — caller batches
/// shootdowns via `protectAll`.
fn protectKstackNoFlush(pid: usize) bool {
    if (isRunningAnywhere(pid)) return false;
    const top = @atomicLoad(usize, &process.expected_kstack_tops[pid], .acquire);
    if (top == 0) return false;
    var page = top - config.KSTACK_SIZE;
    while (page < top) : (page += 4096) {
        _ = paging.installWriteWatchNoFlush(page);
    }
    return true;
}

/// Walk all 4KB pages of `pid`'s kstack and mark R/W=1 via PTE bit.
/// PTE write only — caller batches shootdowns.
fn unprotectKstackNoFlush(pid: usize) bool {
    const top = @atomicLoad(usize, &process.expected_kstack_tops[pid], .acquire);
    if (top == 0) return false;
    var page = top - config.KSTACK_SIZE;
    while (page < top) : (page += 4096) {
        paging.setWriteWatchRWNoFlush(page, true);
    }
    return true;
}

/// Protect all eligible PROTECTED_PIDS kstacks + ONE broadcast shootdown.
/// Call at the start of destroyCurrentWithStatus so the destroy path
/// catches any wild write into a blocked task's kstack on any CPU.
pub fn protectAll() void {
    const dying_pid = if (smp.myCpu().current_pid) |p| p else 999;
    var any = false;
    inline for (PROTECTED_PIDS, 0..) |p, i| {
        const pid: usize = @as(usize, p);
        const running = isRunningAnywhere(pid);
        const top = @atomicLoad(usize, &process.expected_kstack_tops[pid], .acquire);
        if (protectKstackNoFlush(pid)) {
            any = true;
            protected_mask |= (@as(u32, 1) << @intCast(i));
            serial.print("[kstack-protect] protected pid={d} top=0x{X} (dying={d})\n", .{ pid, top, dying_pid });
        } else {
            serial.print("[kstack-protect] SKIP pid={d} running={any} top=0x{X} (dying={d})\n", .{ pid, running, top, dying_pid });
        }
    }
    if (any) tlb.shootdownAll(0);
}

/// Restore R/W to all PROTECTED_PIDS kstacks + ONE broadcast shootdown.
/// Call at the end of destroyCurrentWithStatus (BEFORE schedule()) so the
/// next dispatch doesn't brick the dispatched CPU.
pub fn unprotectAll() void {
    var any = false;
    inline for (PROTECTED_PIDS, 0..) |p, i| {
        const bit = @as(u32, 1) << @intCast(i);
        if ((protected_mask & bit) != 0) {
            if (unprotectKstackNoFlush(@as(usize, p))) any = true;
            protected_mask &= ~bit;
        }
    }
    if (any) tlb.shootdownAll(0);
}

/// Master enable for per-save kstack protection. Off by default until
/// explicitly enabled — protecting on every save adds a TLB shootdown
/// per yield of pid 2/3, which is real (but bounded) overhead. Flip to
/// true after boot completes (set by desktop.zig after the splash screen
/// is fully up) so we don't trap on boot-time activity.
pub var per_save_protect_enabled: bool = false;

/// Called from `save_trace_record` immediately after the per-pid mirror
/// is updated. If `pid` is in PROTECTED_PIDS AND has had at least one
/// real switchTo save AND isn't currently running on any OTHER cpu, mark
/// its kstack pages RO and broadcast the shootdown. Any subsequent
/// kernel-mode WRITE to those pages traps in the #PF handler with CR2 =
/// the wild byte and saved_rip = the writer's instruction (the smoking
/// gun for the netstat-desktop wild-RIP=0 hunt).
///
/// Safety against bricking the current CPU:
///   - save_trace_record is called inside switchTo's body, BEFORE the
///     RSP swap to next's kstack. The CPU's current RSP is still on
///     pid's kstack — but after this call the only remaining accesses
///     to pid's kstack are: popq %rsi (read — RO allows reads), ret
///     from save_trace_record (read), then `movq %rsi, %rsp` swaps to
///     next's stack. No further writes to pid's kstack on this CPU.
pub fn protectOnSave(pid: usize) void {
    if (!@atomicLoad(bool, &per_save_protect_enabled, .acquire)) return;
    const slot = slotOf(pid) orelse return;
    const bit = @as(u32, 1) << slot;
    if ((protected_mask & bit) != 0) return; // already protected
    const st = @import("save_trace.zig");
    if (!@atomicLoad(bool, &st.pcb_has_been_saved[pid], .acquire)) return;
    if (isRunningAnywhere(pid)) return;
    // LOCAL-ONLY flush — we're called from inside switchTo under the
    // sched_lock with IRQs disabled. tlb.shootdownAll would IPI peers
    // and spin for ack; if a peer is ALSO in schedule (IRQs off), its
    // IPI handler can't run → wedge. Local invlpg per page covers the
    // most likely writer case (writer on same CPU as the parked victim,
    // e.g. netstat-on-cpu0 corrupting desktop-also-on-cpu0). Cross-CPU
    // writers slip through but the evidence pointed at same-CPU.
    const top = @atomicLoad(usize, &process.expected_kstack_tops[pid], .acquire);
    if (top == 0) return;
    var page = top - config.KSTACK_SIZE;
    while (page < top) : (page += 4096) {
        _ = paging.installWriteWatchNoFlush(page);
        asm volatile ("invlpg (%[a])" :: [a] "r" (page) : .{ .memory = true });
    }
    protected_mask |= bit;
}

/// If `pid` is a protected pid AND its kstack is currently marked RO by
/// an in-flight destroy window, unprotect it and broadcast the shootdown
/// so it's safe to dispatch. The mask check makes this a few-cycle no-op
/// on the hot dispatch path when no destroy is in flight (the common
/// case). Idempotent.
pub fn unprotectPidIfProtected(pid: usize) void {
    const slot = slotOf(pid) orelse return;
    const bit = @as(u32, 1) << slot;
    if ((protected_mask & bit) == 0) return;
    // LOCAL-ONLY flush — same deadlock-avoidance as protectOnSave. Called
    // from schedule() (sched_lock held, IRQs off) and from #PF handler
    // (auto-recover from a caught wild write). Peer CPUs with stale RO
    // TLB entries would trap on a legit write; the #PF handler also runs
    // this path, so the peer would just recover after one spurious trap.
    const top = @atomicLoad(usize, &process.expected_kstack_tops[pid], .acquire);
    if (top != 0) {
        var page = top - config.KSTACK_SIZE;
        while (page < top) : (page += 4096) {
            paging.setWriteWatchRWNoFlush(page, true);
            asm volatile ("invlpg (%[a])" :: [a] "r" (page) : .{ .memory = true });
        }
    }
    protected_mask &= ~bit;
}

/// Test if a fault address lies within a PROTECTED pid's kstack. Returns
/// the pid if so. Called from the #PF handler (vec 14) to recognize a
/// protected-kstack write trap; on a hit we have the writer's RIP in the
/// saved frame and CR2 = the exact byte that was written — the smoking
/// gun for the netstat wild-writer hunt.
pub fn faultBelongsToProtectedKstack(fault_va: usize) ?u8 {
    for (PROTECTED_PIDS) |pid| {
        const top = @atomicLoad(usize, &process.expected_kstack_tops[@as(usize, pid)], .acquire);
        if (top == 0) continue;
        const bottom = top - config.KSTACK_SIZE;
        if (fault_va >= bottom and fault_va < top) return pid;
    }
    return null;
}

/// Continuous flip-detector. Called every IRQ0 tick on BSP. Reads the
/// saved-RIP slot (kesp+48) of every PROTECTED_PIDS pid; on a non-zero
/// → zero transition since the previous tick, logs the running pid on
/// every CPU at the moment of detection. The tick the flip is observed
/// is at most one tick (10 ms) after the writer fired — narrows the
/// suspect window to whatever code ran on either CPU in that window.
/// Cheap (4 memory reads, 2 comparisons). Returns silently when nothing
/// to report. Static last-seen array; no allocation.
/// Atomic claim-bit per pid so concurrent BSP+AP tickMonitor calls produce
/// exactly one log block per corruption (the loser's CAS fails). Bool is
/// fine for u8 cmpxchg; we never reset (one-shot per boot).
var flip_logged: [PROTECTED_PIDS.len]bool = [_]bool{false} ** PROTECTED_PIDS.len;

/// Tighter version: compares live memory at kesp+48 to the per-pid mirror
/// in save_trace. Only fires when the task is PARKED (not running on any
/// CPU AND not mid-schedule-out) — a running task's PCB.kernel_esp is
/// stale and kesp+48 is just reused stack memory, so checks there are
/// pure noise. The scheduling-out transient between setState(.ready) and
/// switchTo's save has the same property: pcb.kernel_esp still points at
/// the previous save's slot, and the still-running prev task is busily
/// writing there (often AAAA from Zig undefined-init). A truly parked
/// task SHOULD have kesp+48 == last_save_plus48[pid] until the next
/// dispatch reads & consumes it. Any divergence is the bug.
pub fn tickMonitor() void {
    const save_trace = @import("save_trace.zig");
    inline for (PROTECTED_PIDS, 0..) |pid, i| {
        const upid: usize = @as(usize, pid);
        const top = @atomicLoad(usize, &process.expected_kstack_tops[upid], .acquire);
        if (top == 0) {
            flip_logged[i] = false;
        } else if (!save_trace.isPidRunningOrSchedulingOut(pid) and !@atomicLoad(bool, &flip_logged[i], .acquire)) {
            const pcb = process.getPCB(pid);
            const kesp = pcb.kernel_esp;
            const valid_kesp = kesp != 0 and kesp >= (top - config.KSTACK_SIZE) and kesp < top;
            if (valid_kesp) {
                const slot: *volatile u64 = @ptrFromInt(kesp + 48);
                const cur = slot.*;
                const expected = save_trace.last_save_plus48[upid];
                const saved_kesp = save_trace.last_save_kesp[upid];
                // Only meaningful if the mirror tracks THIS kesp (else the mirror
                // is for an older save and we'd false-alarm on legit overwrites
                // from subsequent runtime activity at that address).
                if (saved_kesp == kesp and expected != 0 and cur != expected and
                    @cmpxchgStrong(bool, &flip_logged[i], false, true, .acq_rel, .acquire) == null)
                {
                    serial.print("\n[mirror-flip] !!! pid={d} kesp+48 corrupted while PARKED !!!\n", .{pid});
                    serial.print("[mirror-flip]   kesp=0x{X}  expected=0x{X:0>16}  actual=0x{X:0>16}\n", .{
                        kesp, expected, cur,
                    });
                    serial.print("[mirror-flip]   victim kstack=[0x{X}..0x{X})\n", .{
                        top - config.KSTACK_SIZE, top,
                    });
                    for (&smp.cpus, 0..) |*c, ci| {
                        if (ci == 0 or c.alive) {
                            const cur_pid: i32 = if (c.current_pid) |p| @intCast(p) else -1;
                            serial.print("[mirror-flip]   cpu{d}: current_pid={d}\n", .{ ci, cur_pid });
                        }
                    }
                    // Dump save_trace ring right now — recent entries will show
                    // who was saving on each CPU around the corruption window.
                    save_trace.dumpAll();
                }
            }
        }
    }
}

/// Bisection logger. Print the saved-RIP slot (kesp+48) of every
/// PROTECTED_PIDS pid, tagged with a label. Sprinkle calls through any
/// teardown path that's a wild-writer suspect; the checkpoint immediately
/// BEFORE the values flip to 0 narrows the writer to the next step.
/// Cheap (one cli/sti + handful of memory reads); safe in any kernel
/// context as long as the target PCBs are alive. Reads via volatile so
/// the optimizer doesn't hoist or cache across calls.
pub fn checkpoint(label: []const u8) void {
    serial.print("[chkpt {s}]", .{label});
    inline for (PROTECTED_PIDS) |pid| {
        const upid: usize = @as(usize, pid);
        const top = @atomicLoad(usize, &process.expected_kstack_tops[upid], .acquire);
        if (top == 0) {
            serial.print(" pid={d}:(no top)", .{pid});
        } else {
            const pcb = process.getPCB(pid);
            const kesp = pcb.kernel_esp;
            if (kesp == 0 or kesp < (top - config.KSTACK_SIZE) or kesp >= top) {
                serial.print(" pid={d}: kesp=0x{X}(BAD)", .{ pid, kesp });
            } else {
                const slot: *volatile u64 = @ptrFromInt(kesp + 48);
                serial.print(" pid={d}: kesp=0x{X} +48=0x{X}", .{ pid, kesp, slot.* });
            }
        }
    }
    serial.print("\n", .{});
}

/// Log a protected-kstack fault with writer's context. Called from the
/// #PF handler immediately on detection so the dump precedes any
/// follow-up panic / triple-fault risk. `victim_pid` came from
/// faultBelongsToProtectedKstack, `writer_rip` from the saved IDT frame.
pub fn dumpFault(victim_pid: u8, fault_va: usize, writer_rip: usize, writer_pid: ?usize) void {
    const top = @atomicLoad(usize, &process.expected_kstack_tops[@as(usize, victim_pid)], .acquire);
    const offset_from_top: isize = @as(isize, @intCast(top)) - @as(isize, @intCast(fault_va));
    serial.print("\n[kstack-protect] !!! WILD WRITE CAUGHT !!!\n", .{});
    serial.print("[kstack-protect]   victim pid={d} kstack=[0x{X:0>16}..0x{X:0>16})\n", .{
        victim_pid, top - config.KSTACK_SIZE, top,
    });
    serial.print("[kstack-protect]   fault_va  = 0x{X:0>16}  (top - {d} bytes)\n", .{
        fault_va, offset_from_top,
    });
    serial.print("[kstack-protect]   writer RIP = 0x{X:0>16}\n", .{writer_rip});
    if (writer_pid) |p| {
        serial.print("[kstack-protect]   writer pid = {d} (current_pid on this CPU)\n", .{p});
    } else {
        serial.print("[kstack-protect]   writer pid = (none — kernel task / IRQ)\n", .{});
    }
    // Resolve writer RIP to a symbol if possible.
    if (@import("symbols.zig").resolveKernelNearest(@as(u64, writer_rip))) |sym| {
        serial.print("[kstack-protect]   writer fn  = {s}+0x{X}\n", .{ sym.name, sym.offset });
    }
}
