// Per-CPU ring buffer of every switchTo save to procs[i].kernel_esp.
//
// The cross-stack-aliasing / kesp-clobber bug class (per_cpu_asm_alias,
// bsp_per_cpu_gdt, netstat-desktop 2026-05-17) plants a bad value in
// procs[X].kernel_esp seconds before it ever crashes — typically on the
// NEXT dispatch of pid X. By then the writer's call stack is long gone
// and we're left guessing whose schedule() call corrupted the slot.
//
// This trace records every save at the moment switchTo writes to *RDI.
// On panic / rip-guard / pcb-invariant we dump the rings sorted-by-TSC.
// The bad save jumps out: an entry where saved_rip_at_plus48 is 0 or
// not in kernel .text, with the writing cpu's id + the new kesp value.
// From there we know which cpu's schedule() did it and roughly when.
//
// Cost: one rdtsc + ~8 stores per save, no atomics (per-CPU). Hot path
// adds ~30ns. Ring size 32 keeps full coverage of typical
// dispatch bursts (every preempt is 1 entry) without blowing cache.

const std = @import("std");
const process = @import("../proc/process.zig");
const config = @import("../config.zig");
const smp = @import("../cpu/smp.zig");
const memmap = @import("../mm/memmap.zig");
const serial = @import("serial.zig");
const symbols = @import("symbols.zig");
const watch = @import("watch.zig");

/// HWBP arm on kesp+48 with DYNAMIC skip_value = just-observed legit
/// saved RA. Each save: peek *(kesp+48), arm DR2/DR3 with skip_value
/// set to that value. While parked, ANY write whose value differs
/// from the recorded legit RA fires the watch.
///
/// Earlier attempts (value_threshold = 0x1000, then KERNEL_VIRT_BASE)
/// failed to catch the observed cross-CPU stack aliasing signature —
/// the corruption flips one canonical kernel RA to ANOTHER canonical
/// kernel RA (mirror-flip detector 2026-05-19 saw pid 3's kesp+48
/// flip from schedule+0x2C47 to schedule:2363, both kernel .text).
/// Both values pass any value-range filter. skip_value = the actual
/// legit RA is the only filter that distinguishes them.
///
/// Dual-VA arming was tried 2026-05-19 (DR2 kernel VA + DR3 physmap
/// VA) and caused IPI flood livelock. Single-slot per pid restores
/// the working baseline IPI cost.
///
/// Toggle off if false positives become noisy.
pub var hwbp_save_arm_enabled: bool = true;
const HWBP_SLOT_PID2: u2 = 2;
const HWBP_SLOT_PID3: u2 = 3;

pub const RING_SIZE: usize = 32;

pub const Entry = extern struct {
    tsc: u64 = 0,
    new_kesp: u64 = 0,
    /// The qword at *(kesp+48) — switchTo's ret will pop this as RIP.
    /// Should ALWAYS be a kernel .text address (the RA pushed by
    /// `callq *%[addr]` inside switchToCall). A zero / user-VA / garbage
    /// value here means the save is corrupt and the next dispatch will
    /// jump to that garbage.
    saved_rip_at_plus48: u64 = 0,
    /// Caller of recordSave — always within switchTo's body, so symbolized
    /// it's "switchTo+offset". Mostly there for forensics if we ever add
    /// more than one record site.
    self_ra: u64 = 0,
    cpu_id: u8 = 0xFF,
    pid: u8 = 0xFF,
    /// Padding so the struct is 8-byte aligned & easy to memcpy/cache.
    _pad: u16 = 0,
    /// Was kesp+48 readable (in this pid's kstack body)? If false the
    /// saved_rip field is the sentinel 0xDEADBEEF_DEADBEEF.
    rip_in_body: u8 = 0,
    _pad2: [3]u8 = .{ 0, 0, 0 },
};

const Ring = struct {
    entries: [RING_SIZE]Entry = [_]Entry{.{}} ** RING_SIZE,
    head: u32 = 0,
};

/// Per-CPU ring. cacheline-aligned to avoid false sharing of `head`
/// across CPUs (each CPU only touches its own ring on the hot path).
var rings: [smp.MAX_CPUS]Ring align(64) = [_]Ring{.{}} ** smp.MAX_CPUS;

/// Per-pid mirror of the MOST RECENT switchTo save's metadata. Survives
/// ring rollover (the per-CPU ring keeps only 32 entries; a busy task can
/// have its trace entries overwritten by other saves before we panic).
/// At sched-rip-guard time, compare PCB.kernel_esp to last_save_kesp[pid]
/// and the current memory at kesp+48 to last_save_plus48[pid] to learn:
///   (a) whether kesp changed since last save (it shouldn't — only switchTo
///       and create-paths write kernel_esp), and
///   (b) whether the qword at kesp+48 was overwritten after the save was
///       recorded (= the bug we're hunting).
pub var last_save_kesp: [config.MAX_PROCS]u64 = [_]u64{0} ** config.MAX_PROCS;
pub var last_save_plus48: [config.MAX_PROCS]u64 = [_]u64{0} ** config.MAX_PROCS;
pub var last_save_tsc: [config.MAX_PROCS]u64 = [_]u64{0} ** config.MAX_PROCS;

/// Per-PID flag set the first time switchTo saves this PCB. Until set, the
/// PCB's *(kesp+48) is NOT a saved RIP from any switchTo — it's either
/// the synthetic entry_fn_addr from createKernelTask (immediately after
/// dispatch ret) OR whatever the task's entry prologue (`push rbp`) wrote
/// when it ran (= popped saved-rbp from the synthetic frame = usually 0).
/// So pcb_invariants' "kesp+48 must be in kernel .text" check is only valid
/// once `pcb_has_been_saved[pid]` is true. False positives caused a
/// premature panic on desktop's very first blockOn (2026-05-17) — that path
/// sets state=.sleeping but desktop hasn't yet gone through switchTo, so
/// kesp+48 is whatever taskEntry's prologue smeared there.
pub var pcb_has_been_saved: [config.MAX_PROCS]bool = [_]bool{false} ** config.MAX_PROCS;

/// Reset the flag for a slot that's being recycled. Call from process
/// create-paths so a re-used pid starts as "not yet saved".
pub fn resetPid(pid: u8) void {
    if (pid < config.MAX_PROCS) {
        @atomicStore(bool, &pcb_has_been_saved[pid], false, .release);
    }
}

/// Convert a kesp_ptr (= &procs[i].kernel_esp) back to its pid index,
/// or null if it doesn't point inside the procs[] array. switchTo always
/// passes a pointer that came from `&procs[cur].kernel_esp`, so this
/// matches in normal operation. Returns 0xFF (sentinel) if conversion
/// fails — easier for downstream code than ?u8.
fn pidFromKespPtr(kesp_ptr: usize) u8 {
    const base = @intFromPtr(&process.procs[0]);
    if (kesp_ptr < base) return 0xFF;
    const off = kesp_ptr - base;
    const pcb_size = @sizeOf(process.PCB);
    const kesp_offset = @offsetOf(process.PCB, "kernel_esp");
    if (off % pcb_size != kesp_offset) return 0xFF;
    const i = off / pcb_size;
    if (i >= config.MAX_PROCS) return 0xFF;
    return @intCast(i);
}

inline fn rdtsc() u64 {
    return asm volatile (
        \\ rdtsc
        \\ shlq $32, %%rdx
        \\ orq %%rdx, %%rax
        : [r] "={rax}" (-> u64),
        :: .{ .rdx = true });
}

/// Called from inside switchTo's asm right after `movq %rsp, (%rdi)`.
/// RDI carries the kesp slot pointer that was just written, RSI carries
/// next_kesp (caller preserved both around the call).
///
/// Lives outside the asm block as a regular Zig fn so we get full Zig
/// safety + can call into other modules (smp, symbols). The asm-side
/// preamble has already aligned RSP for the SysV call.
///
/// Exported so the inline asm in sched_asm.zig can reference it by name.
pub export fn save_trace_record(kesp_ptr: usize) callconv(.c) void {
    const cpu_id = smp.myCpu().cpu_id;
    if (cpu_id >= smp.MAX_CPUS) return;
    // Clear schedule's transient-window bracket. We've just performed the
    // save that updates procs[prev].kernel_esp; from here on prev is fully
    // parked and pcb_invariants / kstack_protect.tickMonitor can safely
    // validate its kesp+48. Done before the ring-buffer record so a panic
    // inside the record path doesn't leave the bracket set.
    smp.cpus[cpu_id].scheduling_out_pid = 0xFFFF;
    const ring = &rings[cpu_id];
    const slot: usize = ring.head % RING_SIZE;
    ring.head +%= 1;

    const new_kesp: u64 = @as(*const u64, @ptrFromInt(kesp_ptr)).*;
    const pid = pidFromKespPtr(kesp_ptr);

    // Peek the qword at kesp+48 — that's the RA `ret` will pop on the
    // next dispatch. Bounds-check against the pid's kstack body so a
    // bogus kesp_ptr doesn't fault.
    var saved_rip: u64 = 0xDEADBEEF_DEADBEEF;
    var rip_in_body: u8 = 0;
    if (pid < config.MAX_PROCS) {
        const top = @atomicLoad(usize, &process.expected_kstack_tops[pid], .acquire);
        if (top != 0) {
            const rip_slot = new_kesp +% 48;
            const body_lo = top -| config.KSTACK_SIZE;
            if (rip_slot >= body_lo and rip_slot + 8 <= top) {
                saved_rip = @as(*const u64, @ptrFromInt(rip_slot)).*;
                rip_in_body = 1;
            }
        }
    }

    ring.entries[slot] = .{
        .tsc = rdtsc(),
        .new_kesp = new_kesp,
        .saved_rip_at_plus48 = saved_rip,
        .self_ra = @returnAddress(),
        .cpu_id = cpu_id,
        .pid = pid,
        .rip_in_body = rip_in_body,
    };
    // Latch the per-PID "saw a real switchTo save" flag. Once set,
    // pcb_invariants is free to assert *(kesp+48) is a kernel .text RA;
    // before set, kesp+48 is whatever the task's entry prologue wrote
    // (or the synthetic entry_fn_addr) and a check there false-fires.
    if (pid < config.MAX_PROCS) {
        @atomicStore(bool, &pcb_has_been_saved[pid], true, .release);
        // Per-pid mirror so sched-rip-guard can correlate "what we saved"
        // vs. "what we see at dispatch" without depending on the per-CPU
        // ring (which may have rolled over). Non-atomic — single writer is
        // this CPU's switchTo, single reader is whichever CPU's schedule
        // will dispatch the pid next. Relaxed-store/relaxed-load semantics
        // are fine for forensics.
        last_save_kesp[pid] = new_kesp;
        last_save_plus48[pid] = saved_rip;
        last_save_tsc[pid] = rings[cpu_id].entries[slot].tsc;
        // (Per-save page-protect was tried 2026-05-18 — wedges silently
        // even with local-only invlpg + no cross-CPU shootdown; possibly
        // splitToPte allocator lock or TLB-cascade through schedule's
        // critical section. Kept the protectOnSave function in
        // kstack_protect.zig for later research but it's no-op until
        // `per_save_protect_enabled` is flipped manually + the wedge
        // is debugged.)

        // HWBP arm: catch any write to kesp+48 whose value ≠ the
        // just-observed legit saved RA. Disarm in process.schedule
        // when pid is dispatched (first callq after switchTo's retq
        // legitimately overwrites this slot with a different RA).
        if (hwbp_save_arm_enabled and rip_in_body == 1) {
            const rip_slot = new_kesp +% 48;
            if (pid == 2) {
                watch.armSkipValue(
                    HWBP_SLOT_PID2,
                    rip_slot,
                    .eight,
                    .panic_dump,
                    "kesp48_pid2",
                    saved_rip,
                );
            } else if (pid == 3) {
                watch.armSkipValue(
                    HWBP_SLOT_PID3,
                    rip_slot,
                    .eight,
                    .panic_dump,
                    "kesp48_pid3",
                    saved_rip,
                );
            }
        }
    }
}

fn isKernelText(addr: u64) bool {
    return addr >= memmap.KERNEL_VIRT_BASE and addr < memmap.kernelEnd();
}

fn isPidRunningAnywhere(pid: u8) bool {
    for (&smp.cpus, 0..) |*c, i| {
        if (i != 0 and !c.alive) continue;
        if (c.current_pid) |cur| {
            if (cur == @as(usize, pid)) return true;
        }
    }
    return false;
}

/// Returns true if any CPU is currently mid-schedule with this pid as the
/// outgoing task (= between `setState(.ready)` and switchTo's save). During
/// that window the pid's PCB is .ready / .sleeping but kernel_esp is STALE
/// and *(kesp+48) holds whatever the still-running prev wrote there last —
/// often 0xAAAAAAAAAAAAAAAA from Zig's undefined-init pattern. Any scanner
/// reading kesp+48 here would false-fire on transient stack residue.
/// Bracket maintained by process.schedule() + save_trace_record.
pub fn isPidSchedulingOutAnywhere(pid: u8) bool {
    for (&smp.cpus, 0..) |*c, i| {
        if (i != 0 and !c.alive) continue;
        if (c.scheduling_out_pid == @as(u16, pid)) return true;
    }
    return false;
}

/// Mirror of `isPidSchedulingOutAnywhere` for the inbound direction. True
/// if any CPU is mid-dispatch on this pid (between pickNext's PICK_CAS
/// and `setCurrentPid`'s `cpu.current_pid = next` write). In that window
/// the pid's state byte already says .running but no CPU's
/// `current_pid` field claims it yet — `pcb_invariants` would otherwise
/// false-fire on this transient.
pub fn isPidDispatchingInAnywhere(pid: u8) bool {
    for (&smp.cpus, 0..) |*c, i| {
        if (i != 0 and !c.alive) continue;
        if (c.dispatching_in_pid == @as(u16, pid)) return true;
    }
    return false;
}

/// Combined gate used by saved-RIP validators: skip the check if the pid
/// is currently running OR mid-schedule on any CPU. The running case is
/// obvious (kesp+48 is stale free-stack); the scheduling-out case is the
/// transient demote window.
pub fn isPidRunningOrSchedulingOut(pid: u8) bool {
    if (isPidRunningAnywhere(pid)) return true;
    if (isPidSchedulingOutAnywhere(pid)) return true;
    return false;
}

/// Non-intrusive corruption check: returns true if pid's kesp+48 memory
/// still matches the per-pid save mirror, false if it diverged. Skips
/// (returns true) when checking would false-fire:
///   - pid hasn't had a real switchTo save yet
///   - pid is currently RUNNING or mid-schedule (kesp+48 is stale free-
///     stack memory in both cases — the transient demote window between
///     setState(.ready) and switchTo's save has the same property)
///   - pcb.kernel_esp differs from last_save_kesp (a newer save landed;
///     mirror plus48 hasn't caught up — race, not corruption)
/// Caller decides what to do with the result. Hot-path safe (~10 loads,
/// no allocations, no locks). Used to bracket suspect kernel paths and
/// pinpoint the syscall / handler that corrupts a parked task's saved RA.
pub fn mirrorIntact(pid: u8) bool {
    if (pid >= config.MAX_PROCS) return true;
    if (!@atomicLoad(bool, &pcb_has_been_saved[pid], .acquire)) return true;
    if (isPidRunningOrSchedulingOut(pid)) return true;
    const pcb = &process.procs[pid];
    const kesp = pcb.kernel_esp;
    if (kesp != last_save_kesp[pid]) return true; // mirror stale, not bug
    const top = pcb.kernel_stack_top;
    if (top == 0 or kesp < (top - config.KSTACK_SIZE) or kesp >= top) return true;
    const slot: *volatile u64 = @ptrFromInt(kesp + 48);
    return slot.* == last_save_plus48[pid];
}

/// Dump every CPU's ring oldest-first. Marks each entry with a verdict:
/// `OK` (saved_rip in kernel .text), `BAD-RIP` (kesp+48 not a kernel
/// address — this is the bug signature), `OOB` (kesp+48 outside the
/// pid's kstack body — already-corrupt kesp).
pub fn dumpAll() void {
    serial.print("\n[save-trace] last {d} kesp saves per CPU:\n", .{RING_SIZE});
    for (0..smp.MAX_CPUS) |i| {
        const cpu = &smp.cpus[i];
        if (i > 0 and !cpu.alive) continue;
        const r = &rings[i];
        const total = r.head;
        const count: usize = @min(@as(usize, total), RING_SIZE);
        if (count == 0) {
            serial.print("  cpu{d}: (no saves recorded)\n", .{i});
            continue;
        }
        serial.print("  cpu{d}: {d} saves (showing last {d}):\n", .{ i, total, count });
        // Oldest-first ordering: oldest is at head - count.
        var k: usize = 0;
        while (k < count) : (k += 1) {
            const slot: usize = (r.head -% @as(u32, @intCast(count - k))) % RING_SIZE;
            const e = r.entries[slot];
            const verdict = blk: {
                if (e.rip_in_body == 0) break :blk "OOB";
                if (isKernelText(e.saved_rip_at_plus48)) break :blk "OK";
                break :blk "BAD-RIP";
            };
            const name = blk: {
                if (e.pid >= config.MAX_PROCS) break :blk "?";
                const p = &process.procs[e.pid];
                if (p.name_len == 0) break :blk "(unnamed)";
                break :blk p.name[0..@min(p.name_len, p.name.len)];
            };
            serial.print(
                "    [{d:0>2}] tsc=0x{X:0>12} cpu{d} pid={d}({s}) kesp=0x{X:0>16} +48=0x{X:0>16} [{s}]",
                .{ slot, e.tsc, e.cpu_id, e.pid, name, e.new_kesp, e.saved_rip_at_plus48, verdict },
            );
            if (e.rip_in_body != 0 and isKernelText(e.saved_rip_at_plus48)) {
                if (symbols.resolveKernel(e.saved_rip_at_plus48)) |sym| {
                    serial.print(" {s}+0x{X}\n", .{ sym.name, sym.offset });
                } else {
                    serial.print("\n", .{});
                }
            } else {
                serial.print("\n", .{});
            }
        }
    }
}
