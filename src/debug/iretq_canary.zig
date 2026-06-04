// iretq-frame snapshot tripwire (task #230).
//
// The bug we're hunting: kernel-mode work between IRQ entry and iretq
// scribbles the saved iretq frame at the top of the kstack, so iretq
// returns to a wild RIP and the CPU faults. Existing diagnostics catch
// the corruption *at* iretq exit (validateUserReturnIretq) — too late to
// know which kernel function did it.
//
// This module: snapshot the iretq frame into the *current PCB* on IRQ
// entry, then expose `check(@src())` — call it from any kernel function
// to compare the on-stack iretq frame against the snapshot. On mismatch,
// print the @src() location, dump the diff, and panic with the kernel
// call path still intact.
//
// Why per-PCB and not per-CPU: tasks migrate between CPUs across
// schedule(). The snap travels with the task naturally if it lives in
// the PCB. Per-CPU snap would compare against the wrong handler after
// migration.
//
// Why @src(): comptime fn-name capture is free in Zig. One-line
// instrumentation per checkpoint, automatic location tagging.
//
// Cost: capture = 6 word-stores into PCB. check = 6 cmps from PCB.
// Both run on hot paths (IRQ entry, schedule, pickNext, top of suspect
// syscalls). Total overhead < 100 cycles per IRQ — well below the noise
// floor of an actual IRQ + handler dispatch.

const std = @import("std");
const builtin = @import("builtin");
const serial = @import("serial.zig");
const process = @import("../proc/process.zig");

/// Master switch. Set to false in fully-shipping builds. The check()
/// path is `inline` and compiles to nothing when this is false.
pub const ENABLE: bool = true;

/// PER-IRQ DR0 arm/disarm (legacy). When true, capture()/invalidate()
/// arm/disarm DR0 around every IRQ. The side-effect IPIs from broadcastSync
/// flood the system (~thousands/sec/CPU) and unintentionally suppress the
/// cross-CPU iretq race we're trying to catch — a heisendetector. Toggle
/// ON only if you want to *suppress* the bug for triage; toggle OFF for
/// active hunting (task #233).
///
/// The cleaner alternative — `armPermanentWatchpoints()` below — arms
/// once at boot and never re-arms, giving DR-level catch power with no
/// per-IRQ IPI perturbation.
pub const DR_WATCHPOINT: bool = false;
const DR_SLOT: u2 = 0;

/// Snapshots the FULL saved-state region: 15 GPRs (RAX..R15) + iretq
/// frame (RIP/CS/RFL/RSP/SS) = 20 u64s = 160 bytes. The iretq frame
/// alone isn't enough — observed corruption (0xAAAA fill at kstack
/// offsets 0x70/0x78) sits in the GPR region, BELOW the iretq frame.
/// We snapshot the whole region so any wild-write into ANY of the
/// 20 saved slots gets caught.
///
/// IRQ0 layout below kernel_stack_top, low → high address:
///   top - 0xA0: r15  ← gpr[0]  (last GPR pushed = lowest addr)
///   top - 0x98: r14
///    ...
///   top - 0x30: rax  ← gpr[14] (first GPR pushed)
///   top - 0x28: rip  ← iretq[0]
///   top - 0x20: cs
///   top - 0x18: rflags
///   top - 0x10: rsp
///   top - 0x08: ss
///
/// Exception layout adds int_no + err_code between GPRs and iretq frame
/// (so GPR base is at top - 0xB0 instead of top - 0xA0). Stash the
/// absolute gpr_base address in the snap to handle both uniformly.
pub const Snap = extern struct {
    gpr: [15]u64 = [_]u64{0} ** 15,
    rip: u64 = 0,
    cs: u64 = 0,
    rflags: u64 = 0,
    rsp: u64 = 0,
    ss: u64 = 0,
    /// Absolute address of frame_base[0] (R15 slot) on the kstack at
    /// capture time. IRQ0 has GPRs at kstack_top - 0xA0; exceptions add
    /// 16 bytes (int_no + err_code) so GPRs start at kstack_top - 0xB0.
    /// Stash the absolute address rather than recomputing — handles
    /// both layouts uniformly.
    gpr_base: u64 = 0,
    /// 0 = no active snapshot; 1 = handler is mid-execution.
    valid: u8 = 0,
    _pad: [7]u8 = [_]u8{0} ** 7,
};

/// Capture saved-state region at handler entry. `rip_index` is the u64
/// offset from `frame_base` to the saved RIP (15 for handleIRQ0, 17 for
/// handleException — exception ISRs push int_no + error_code first).
///
/// Snapshots 15 GPRs + iretq frame (20 u64s total). GPR base is
/// `rip_index - 15` (right below the iretq frame).
///
/// Only captures when CS == 0x23 (returning to Ring 3). Kernel-mode
/// preemption (CS == 0x08) has nothing to validate against.
pub fn capture(frame_base: [*]const u64, comptime rip_index: usize) void {
    if (!ENABLE) return;
    const pcb = process.currentPCB() orelse return;
    const cs = frame_base[rip_index + 1];
    if (cs != 0x23) {
        // Kernel-mode IRQ/exception entry. The iretq frame at this CPU's
        // current RSP belongs to this nested kernel-mode entry, NOT to the
        // top-of-kstack iretq slot the canary watches. The top-of-kstack
        // slot may by now hold leftover bytes from a SyscallFrame the
        // process pushed earlier (LSTAR stub starts pushes at top-8 and
        // naturally lands fields in the iretq slots — perfectly legitimate
        // because the previous iretq-from-user-IRQ has already happened
        // and freed those bytes).
        //
        // Clear any stale snap that survived the previous user-mode IRQ
        // (defers don't run if the previous handleIRQ0 was suspended via
        // schedule() and the task got killed before resume).
        // Without this, a check() in this handleIRQ0 would compare a
        // user-state snap against current SyscallFrame leftovers and
        // false-positive — exactly what we observed in pollHID.
        pcb.iretq_snap.valid = 0;
        return;
    }
    var snap: Snap = .{
        .rip = frame_base[rip_index],
        .cs = cs,
        .rflags = frame_base[rip_index + 2],
        .rsp = frame_base[rip_index + 3],
        .ss = frame_base[rip_index + 4],
        .gpr_base = @intFromPtr(frame_base),
        .valid = 1,
    };
    // GPRs always sit at frame_base[0..14] — both isr_irq0 and
    // isr_common_exc hand the handler its rdi pointing to GPR start.
    // Exception layout has int_no/err_code BETWEEN GPRs and iretq
    // frame; hence rip_index varies but GPR base is uniform.
    inline for (0..15) |i| {
        snap.gpr[i] = frame_base[i];
    }
    pcb.iretq_snap = snap;

    // Arm DR0 hardware watchpoint on the iretq RIP slot. The previous
    // canary check() approach catches corruption AFTER the writer; DR0
    // catches it SYNCHRONOUSLY (#DB fires on the offending instruction,
    // saved RIP IS the writer). Per-CPU only — cross-CPU writers within
    // the ~10ms applyLocal() resync window are still detected via the
    // canary as fallback.
    if (DR_WATCHPOINT) {
        const top = pcb.kernel_stack_top;
        if (top != 0) {
            const watch = @import("watch.zig");
            watch.arm(DR_SLOT, top - 0x28, .write, .eight, .panic_dump, "iretq_RIP");
        }
    }
}

/// Clear the snapshot at handler exit (just before iretq). Prevents
/// false positives during the brief window where the next handler is
/// about to overwrite the slot. Also disarms DR0 so the legitimate
/// hardware iretq frame pop doesn't fire #DB.
pub fn invalidate() void {
    if (!ENABLE) return;
    if (DR_WATCHPOINT) {
        @import("watch.zig").disarm(DR_SLOT);
    }
    const pcb = process.currentPCB() orelse return;
    pcb.iretq_snap.valid = 0;
}

/// Refresh the snapshot from the current on-stack frame state. Call
/// this after LEGITIMATE modifications of the iretq frame or GPR save
/// area (signal-frame injection, fork/clone parent-side rewrites) so
/// subsequent check() calls don't false-positive on the deliberate
/// change. No-op if no snap is active.
pub fn refresh() void {
    if (!ENABLE) return;
    const pcb = process.currentPCB() orelse return;
    if (pcb.iretq_snap.valid == 0) return;
    const top = pcb.kernel_stack_top;
    const gpr_base = pcb.iretq_snap.gpr_base;
    if (top == 0 or gpr_base == 0) return;
    const gpr_now: *const [15]u64 = @ptrFromInt(gpr_base);
    const iretq_now: *const [5]u64 = @ptrFromInt(top - 0x28);
    inline for (0..15) |i| pcb.iretq_snap.gpr[i] = gpr_now[i];
    pcb.iretq_snap.rip = iretq_now[0];
    pcb.iretq_snap.cs = iretq_now[1];
    pcb.iretq_snap.rflags = iretq_now[2];
    pcb.iretq_snap.rsp = iretq_now[3];
    pcb.iretq_snap.ss = iretq_now[4];
}

/// Check the iretq frame against the snapshot. Call with `@src()` from
/// any kernel function — on mismatch, prints the source location, the
/// diff, and panics. No-op when no snapshot is active.
///
/// Inline so the !ENABLE path compiles to nothing.
pub inline fn check(comptime where: std.builtin.SourceLocation) void {
    if (!ENABLE) return;
    @call(.never_inline, checkSlow, .{where});
}

fn checkSlow(comptime where: std.builtin.SourceLocation) void {
    const pcb = process.currentPCB() orelse return;
    const snap = pcb.iretq_snap;
    if (snap.valid == 0) return;
    const top = pcb.kernel_stack_top;
    if (top == 0 or snap.gpr_base == 0) return;
    // Read GPRs from snap.gpr_base (handles IRQ0 and exception layouts
    // uniformly); read iretq frame from kstack_top - 0x28 (always
    // there in both layouts because CPU pushes it last).
    const gpr_now: *const [15]u64 = @ptrFromInt(snap.gpr_base);
    const iretq_now: *const [5]u64 = @ptrFromInt(top - 0x28);

    // Self-validation (task #240). The slot at top-0x28 is the "active"
    // iretq frame ONLY when:
    //   (a) The current frame's CS slot still reads 0x23 (returning to
    //       user). If it doesn't, the slot may hold leftover bytes from
    //       a syscall push or other kstack reuse, and snap-vs-current
    //       comparison is meaningless.
    //   (b) Our current kernel RSP is reasonably close to the top of
    //       the kstack — i.e., we ARE on the call path that originally
    //       pushed the iretq frame. If RSP is deep below top-0x28, the
    //       iretq slot belongs to some unrelated, defunct return path.
    // If either check fails, skip the comparison; the snap was real but
    // the slot is no longer semantically the "live" iretq frame.
    if (iretq_now[1] != 0x23) return;
    const cur_rsp = asm volatile ("movq %%rsp, %[r]" : [r] "=r" (-> u64));
    // Allow up to ~3 KB below top — covers normal handleIRQ0 nesting +
    // signal delivery + bisectPoint locals. Anything deeper means the
    // top-0x28 slot is stale from a much earlier context.
    if (cur_rsp < top -% 0xC00) return;
    var match: bool = true;
    inline for (0..15) |i| {
        if (gpr_now[i] != snap.gpr[i]) match = false;
    }
    if (iretq_now[0] != snap.rip) match = false;
    if (iretq_now[1] != snap.cs) match = false;
    if (iretq_now[2] != snap.rflags) match = false;
    if (iretq_now[3] != snap.rsp) match = false;
    if (iretq_now[4] != snap.ss) match = false;
    if (match) return;
    var combined: [20]u64 = undefined;
    inline for (0..15) |i| combined[i] = gpr_now[i];
    combined[15] = iretq_now[0];
    combined[16] = iretq_now[1];
    combined[17] = iretq_now[2];
    combined[18] = iretq_now[3];
    combined[19] = iretq_now[4];
    report(where, combined, snap, top);
}

// ISR stub pushes RAX..R15 in order (RAX first, R15 last). Push lowers
// RSP, so R15 ends up at the LOWEST address = frame_base[0]. RAX at
// the highest GPR address = frame_base[14], just below the iretq frame.
const GPR_NAMES: [15][]const u8 = .{
    "r15", "r14", "r13", "r12", "r11", "r10", "r9",  "r8",
    "rdi", "rsi", "rbp", "rbx", "rdx", "rcx", "rax",
};

fn report(
    comptime where: std.builtin.SourceLocation,
    cur: [20]u64,
    snap: Snap,
    kstack_top: u64,
) noreturn {
    asm volatile ("cli");
    // Re-entry guard: if reporting itself triggers a re-entry (which
    // would walk back through serial.print → check), latch and halt.
    const guard = struct {
        var tripped: bool = false;
    };
    if (guard.tripped) {
        while (true) asm volatile ("hlt");
    }
    guard.tripped = true;

    // Enter the panic critical section so this CPU's full report prints
    // sequentially without byte-interleaving with the other CPU's panic
    // output. Idempotent per-CPU; @panic below will re-enter (no-op).
    @import("kdbg.zig").enterCritical();

    serial.print("\n!!! SAVED-STATE CORRUPTION DETECTED !!!\n", .{});
    serial.print("  at: {s}:{d}\n", .{ where.file, where.line });
    serial.print("  fn: {s}\n", .{where.fn_name});
    serial.print("  kstack_top:    0x{X:0>16}\n", .{kstack_top});
    serial.print("  gpr_base:      0x{X:0>16}  (kstack_top - 0xA0)\n", .{kstack_top - 0xA0});
    serial.print("  iretq_base:    0x{X:0>16}  (kstack_top - 0x28)\n", .{kstack_top - 0x28});
    serial.print("  --- diff (snapshot vs now) ---\n", .{});
    inline for (0..15) |i| {
        if (cur[i] != snap.gpr[i]) {
            serial.print("    {s}:    0x{X:0>16} -> 0x{X:0>16}  <-- changed\n",
                .{ GPR_NAMES[i], snap.gpr[i], cur[i] });
        }
    }
    if (cur[15] != snap.rip) {
        serial.print("    rip:    0x{X:0>16} -> 0x{X:0>16}  <-- changed\n", .{ snap.rip, cur[15] });
    }
    if (cur[16] != snap.cs) {
        serial.print("    cs:     0x{X:0>16} -> 0x{X:0>16}  <-- changed\n", .{ snap.cs, cur[16] });
    }
    if (cur[17] != snap.rflags) {
        serial.print("    rflags: 0x{X:0>16} -> 0x{X:0>16}  <-- changed\n", .{ snap.rflags, cur[17] });
    }
    if (cur[18] != snap.rsp) {
        serial.print("    rsp:    0x{X:0>16} -> 0x{X:0>16}  <-- changed\n", .{ snap.rsp, cur[18] });
    }
    if (cur[19] != snap.ss) {
        serial.print("    ss:     0x{X:0>16} -> 0x{X:0>16}  <-- changed\n", .{ snap.ss, cur[19] });
    }

    // Pattern match the corruption type — useful for narrowing the cause.
    serial.print("  --- pattern hint ---\n", .{});
    var saw_aa: bool = false;
    var saw_noncanon_top16: bool = false;
    inline for (0..20) |i| {
        const v = cur[i];
        if ((v & 0xFFFF) == 0xAAAA) saw_aa = true;
        if (v >= 0xFFFF000000000000 and v < 0xFFFF800000000000) saw_noncanon_top16 = true;
    }
    if (saw_aa) {
        serial.print("    Found 0xAAAA pattern — Zig undefined-fill bleed-over.\n", .{});
        serial.print("    A function with `var x: [N]T = undefined` had its memset(0xAA)\n", .{});
        serial.print("    reach this kstack region. Look for large undefined locals on\n", .{});
        serial.print("    the call path between handler entry and {s}.\n", .{where.fn_name});
    }
    if (saw_noncanon_top16) {
        serial.print("    Found non-canonical value with high u16 = 0xFFFF — partial\n", .{});
        serial.print("    64-bit write where high half came from elsewhere.\n", .{});
    }

    @import("kdbg.zig").dumpAll();
    @panic("saved-state corrupted at checkpoint");
}

// -----------------------------------------------------------------------------
// Permanent DR-watchpoint arming (KStackWatch-inspired, task #233 hunt)
//
// The original per-IRQ arm/disarm in capture()/invalidate() floods the system
// with broadcastSync IPIs (~2k/sec/CPU). Those IPIs perturb timing enough that
// the cross-CPU iretq race never lines up, so the watchpoint never fires —
// even though the *implementation* is right. Heisendetector.
//
// Better: arm once at boot, never re-arm. kstack_pool is a static BSS array
// (process.zig:39), so PCB N's iretq RIP slot has a known compile-time address:
//   &kstack_pool[N] + KSTACK_SLOT_SIZE - 0x28
// We arm DR0..DR3 against the iretq RIP slots of PIDs 3..6 (typical user PIDs:
// shell + first 3 spawned children — covers `cat | wc` since shell=3, cat=4,
// wc=5). value_threshold=0x1000 filters out legitimate large-RIP writes from
// hardware iretq pushes; only wild small values (<0x1000) like 0x3 / 0x40 /
// 0x37F (the observed corruption pattern) trigger panic_dump.
//
// Cost: 4 IPI bursts at boot (one per arm). After that, zero overhead — DR
// registers stay set, no further IPIs, hardware does the watching. Steady-
// state timing is identical to no-watchpoint, so the bug fires normally.
//
// Caveat: only watches 4 PCBs. If the wild write hits a different PID, miss.
// Mitigation: PIDs 3..6 cover shell + the typical 3-app cluster. For deeper
// coverage, swap the watched PIDs based on the suspected reproducer.
pub fn armPermanentWatchpoints() void {
    if (!ENABLE) return;
    const watch = @import("watch.zig");
    // process.kstack_pool is already a pointer-to-region; don't take its
    // address again (that would be a double pointer and mis-index below).
    const kstack_pool = process.kstack_pool;
    const slot_size = @sizeOf(@TypeOf(kstack_pool.*[0]));

    const PIDS_TO_WATCH = [_]u8{ 3, 4, 5, 6 };
    inline for (PIDS_TO_WATCH, 0..) |pid, dr_idx| {
        const slot_top = @intFromPtr(&kstack_pool[pid]) + slot_size;
        const rip_addr = slot_top - 0x28;
        const dr: u2 = @intCast(dr_idx);
        watch.armValueThreshold(
            dr,
            rip_addr,
            .eight,
            .panic_dump,
            "iretq_RIP_perm",
            0x1000,
        );
        serial.print("[iretq_canary] DR{d} -> PID {d} iretq RIP @ 0x{X:0>16} (threshold <0x1000)\n",
            .{ dr_idx, pid, rip_addr });
    }
    serial.print("[iretq_canary] permanent watchpoints armed (one-time IPI burst, no per-IRQ flood)\n", .{});
}
