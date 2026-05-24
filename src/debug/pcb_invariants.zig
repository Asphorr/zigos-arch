// PCB invariant scanner — periodic correctness audit of every live PCB slot.
//
// Many of the cross-stack-aliasing / kesp-clobber / TSS-mismatch bugs we've
// hunted (per_cpu_asm_alias_recurrence, bsp_per_cpu_gdt, netstat-desktop
// crash 2026-05-17) leave the system in an inconsistent state for *many*
// scheduling ticks before the dispatch downstream actually crashes. By the
// time the crash fires, the writer's call stack is gone and we're left
// guessing.
//
// This scanner runs from handleIRQ0 every SCAN_PERIOD_TICKS (~1s at 100Hz)
// and walks all alive PCBs, validating cheap-to-check invariants. On the
// first miss, klog + panic with a full process snapshot. Diagnostic value:
// the panic backtrace points at the timer IRQ that detected the corruption,
// but the [pcb-invariant] line names which pid / which field failed —
// usually enough to narrow the writer to a recent code change.
//
// Cost budget: walking MAX_PROCS=32 alive slots is ~64 atomic loads + ~10
// comparisons per slot, well under 10 µs. Running every 1s makes overhead
// trivial (<0.001% CPU).

const std = @import("std");
const process = @import("../proc/process.zig");
const smp = @import("../cpu/smp.zig");
const config = @import("../config.zig");
const debug = @import("debug.zig");
const serial = @import("serial.zig");

/// Tick cadence. 100 = every ~1s at 100Hz. Diagnostic is cheap enough
/// to run continuously now that the cpu_alias.scan stack-locals were
/// moved to file-scope statics and the 2026-05-17 setTssRsp0 cli/sti
/// patch fixed the most prominent kesp+48 corruption source. Lower to
/// 1 during active hunting of a new corruption class.
pub const SCAN_PERIOD_TICKS: u64 = 100;

/// Bumped on every panicking violation; lets us bail if we somehow loop
/// (e.g. the panic path itself re-enters this).
var violations: u32 = 0;

/// One-shot guard. Once we report a violation we don't keep re-firing on
/// subsequent ticks — the panic path may not fully halt (timer keeps firing
/// handleIRQ0), and a re-fire just adds duplicate log noise that buries the
/// initial useful autopsy.
var reported: bool = false;

/// Convert a kstack_top to its owning pool-slot index, or null for heap-
/// allocated kstacks. Used to validate kesp lands inside the SAME slot as
/// kernel_stack_top (cross-stack aliasing detector).
fn poolSlotForTop(top: usize) ?usize {
    const base = @intFromPtr(&process.kstack_pool[0]);
    const total = config.MAX_PROCS * config.KSTACK_SLOT_SIZE;
    if (top <= base or top > base + total) return null;
    const off = top - base;
    if (off % config.KSTACK_SLOT_SIZE != 0) return null;
    return (off / config.KSTACK_SLOT_SIZE) - 1;
}

/// One PCB's invariants. Returns the failing field name, or null on pass.
fn checkPcb(pid: usize) ?[]const u8 {
    const p = &process.procs[pid];
    if (p.state == .unused) return null;

    // ---- kstack_top must match the immutable per-PID witness ----
    const expected_top = @atomicLoad(usize, &process.expected_kstack_tops[pid], .acquire);
    if (expected_top == 0) {
        // Slot in .loading state pre-witness-stamp? Skip; the create path
        // sets witness BEFORE setState(.ready), so any non-unused PCB
        // visible to the scheduler should have a witness.
        if (p.state == .loading) return null;
        return "expected_kstack_tops[pid]==0 for non-loading PCB";
    }
    if (p.kernel_stack_top != expected_top) {
        return "kernel_stack_top != expected_kstack_tops[pid]";
    }

    // ---- kesp must point INSIDE this PCB's own kstack body OR inside
    //      some CPU's IST1 stack ----
    // Body = [kstack_top - KSTACK_SIZE, kstack_top). Guard page (4KB below
    // body) is unmapped on Multiboot and accessing it would #PF. On UEFI
    // it's mapped-but-BSS-zero. Either way kesp should never land there.
    // IST1 case: with IRQ0/dyn IRQs on TSS.IST=1, a task preempted inside
    // an IRQ handler has its kesp saved at an IST1 address. Resume reads
    // back from IST1 and eventually iretqs back to the task's own stack.
    const body_lo = expected_top -| config.KSTACK_SIZE;
    const body_hi = expected_top;
    const kesp_in_body = p.kernel_esp >= body_lo and p.kernel_esp < body_hi;
    const kesp_in_ist1 = blk: {
        for (0..smp.MAX_CPUS) |i| {
            const cpu = &smp.cpus[i];
            if (i > 0 and !cpu.alive) continue;
            const isr_lo = @intFromPtr(&cpu.isr_stack);
            const isr_hi = isr_lo + cpu.isr_stack.len;
            if (p.kernel_esp >= isr_lo and p.kernel_esp < isr_hi) break :blk true;
        }
        break :blk false;
    };
    if (!kesp_in_body and !kesp_in_ist1) {
        return "kernel_esp outside kstack body and not in any IST1";
    }

    // ---- For pool kstacks, kesp must be in the SAME slot ----
    // (heap kstacks live wherever kmalloc returned; can't validate by slot)
    if (poolSlotForTop(expected_top)) |slot| {
        if (slot != pid) {
            // Witness top doesn't even match this pid's slot — earlier
            // check should have caught this if the witness was right.
            return "kstack_top's pool slot != pid";
        }
    }

    // ---- Saved RIP plausibility (only for non-running PCBs THAT HAVE
    //      BEEN THROUGH switchTo's save path at least once) ----
    // For any task NOT currently running on a CPU, kesp+48 holds the saved
    // RIP that switchTo's `ret` will pop. It must be a kernel .text address:
    //   - real save  → return address from switchToCall's `call` (in .text)
    //   - first dispatch of fresh task → retToUserStub (in .text)
    //   - first dispatch of fresh kernel task → entry_fn_addr (in .text)
    //
    // Gate on pcb_has_been_saved: before a task's first switchTo save,
    // *(kesp+48) is whatever the task's entry prologue (`push rbp`) wrote
    // — the popped rbp from the synthetic 6-zero frame is 0, so kesp+48
    // becomes 0 IMMEDIATELY after first dispatch. That's normal, not
    // corruption. False-fired on desktop's first blockOn 2026-05-17.
    //
    // Today's netstat-desktop bug surfaces here AFTER the gate: kesp
    // shallow, kstack body has real save data deeper, kesp+48 is BSS-zero
    // despite save_trace having recorded saves with valid RAs.
    // Skip idle PCBs: they transit through .ready briefly during schedule's
    // demote-then-re-promote pattern (setState(cur, .ready) at the top of
    // schedule, then setState(cur, .running) on the self-switch path). While
    // idle is actually running, its kstack is in active use — kesp+48 doesn't
    // hold a saved RA from any switchTo save, and the check false-fires when
    // observed from another CPU during the transient .ready window. The
    // current_pid identity check at line 168 (`!p.is_idle` clause) follows
    // the same reasoning. (Exposed 2026-05-19 by NVMe async I/O's schedule()
    // from IRQ context which increased the window-catch rate.)
    //
    // NON-IDLE pids hit the SAME transient: between setState(prev, .ready)
    // and switchTo's save, prev's PCB has state=.ready but kernel_esp is
    // STALE (from previous save) and *(kesp+48) holds whatever the still-
    // running prev wrote there last — frequently 0xAAAAAAAAAAAAAAAA from
    // Zig's ReleaseSafe undefined-init pattern. isPidRunningOrSchedulingOut
    // catches this by reading the cpu.scheduling_out_pid bracket-marker
    // set by schedule() and cleared in save_trace_record. (Caught 2026-05-19
    // pcb-invariant panic on pid 2 *(kesp+48)=AAAA — a transient FP, not
    // real corruption.)
    if (!p.is_idle and (p.state == .ready or p.state == .sleeping)) {
        const save_trace = @import("save_trace.zig");
        if (save_trace.isPidRunningOrSchedulingOut(@intCast(pid))) {
            // skip the saved-RIP body check — see comment above
        } else if (@atomicLoad(bool, &save_trace.pcb_has_been_saved[pid], .acquire)) {
            const rip_slot = p.kernel_esp +% 48;
            // Allow rip_slot in body OR in any IST1 — matches the kesp range
            // accepted above. Resume-via-IST1 still has the saved RA on IST1.
            const slot_in_body = rip_slot >= body_lo and rip_slot + 8 <= body_hi;
            const slot_in_ist1 = blk: {
                if (!kesp_in_ist1) break :blk false;
                // Find which IST1 holds kesp and verify rip_slot fits.
                for (0..smp.MAX_CPUS) |i| {
                    const cpu = &smp.cpus[i];
                    if (i > 0 and !cpu.alive) continue;
                    const isr_lo = @intFromPtr(&cpu.isr_stack);
                    const isr_hi = isr_lo + cpu.isr_stack.len;
                    if (rip_slot >= isr_lo and rip_slot + 8 <= isr_hi) break :blk true;
                }
                break :blk false;
            };
            if (slot_in_body or slot_in_ist1) {
                const saved_rip = @as(*const u64, @ptrFromInt(rip_slot)).*;
                const memmap = @import("../mm/memmap.zig");
                const in_text = saved_rip >= memmap.KERNEL_VIRT_BASE and
                    saved_rip < memmap.kernelEnd();
                if (!in_text) return "saved RIP at kesp+48 not in kernel .text";
            }
        }
    }

    // ---- pinned_cpu / assigned_cpu sanity ----
    if (p.pinned_cpu != 0xFF and p.pinned_cpu >= smp.MAX_CPUS) {
        return "pinned_cpu out of range";
    }
    if (p.assigned_cpu != 0xFF and p.assigned_cpu >= smp.MAX_CPUS) {
        return "assigned_cpu out of range";
    }

    // ---- state == .running ⟺ some cpu has current_pid == pid ----
    // (Skip for is_idle — idle PCBs may have state==.running while their
    // cpu's current_pid points at them, but the bookkeeping uses idle_pid
    // separately; checked elsewhere.)
    if (!p.is_idle and p.state == .running) {
        // Transient inbound-dispatch window: pickNext's PICK_CAS set the
        // state byte to .running but the dispatching CPU hasn't yet
        // executed setCurrentPid. Skip — `dispatching_in_pid` is the
        // load-bearing bracket. Caught 2026-05-19 by cross-CPU scan of
        // pid 4 mid-sysSleep/wake cycle.
        if (@import("save_trace.zig").isPidDispatchingInAnywhere(@intCast(pid))) {
            return null;
        }
        // Transient outbound-destroy window: destroyCurrent cleared
        // cpu.current_pid before setState(.zombie/.unused); state stays
        // .running in between. Symmetric partner of the inbound case;
        // `dispatching_out_pid` is the load-bearing bracket. Added
        // 2026-05-20 as the long-planned symmetric fix exposed during
        // Q1 port stress.
        if (@import("save_trace.zig").isPidDispatchingOutAnywhere(@intCast(pid))) {
            return null;
        }
        var found = false;
        for (0..smp.MAX_CPUS) |i| {
            const cpu = &smp.cpus[i];
            if (i > 0 and !cpu.alive) continue;
            if (cpu.current_pid) |cp| {
                if (cp == pid) {
                    found = true;
                    break;
                }
            }
        }
        if (!found) {
            return "state==.running but no cpu.current_pid points here";
        }
    }

    return null;
}

/// Walk every alive PCB. On the first invariant miss, klog + panic.
/// Cheap: ~64 reads/PCB × MAX_PROCS = ~2K loads. Safe to call from inside
/// handleIRQ0 (cli is held). Returns the count of violations found (0 on
/// pass — the panic path doesn't return).
pub fn scan() void {
    // S7: GDT/IDT/TSS post-init hash verification. Re-derive FNV hash and
    // compare to the baseline captured at end of smp.init. ~5 KB to hash,
    // microseconds; lifecycle is decoupled from PCB scan but the cadence
    // is the same so we piggyback rather than wiring a second timer.
    _ = @import("cpu_struct_hash.zig").verify();
    for (0..config.MAX_PROCS) |pid| {
        const failure = checkPcb(pid) orelse continue;
        // Latch the one-shot flag so subsequent ticks don't re-fire.
        @atomicStore(bool, &reported, true, .release);
        violations += 1;
        if (violations > 4) {
            // Recursive failure — stop trying to panic gracefully.
            asm volatile ("cli\nhlt" ::: .{ .memory = true });
            unreachable;
        }
        const p = &process.procs[pid];
        const expected_top = @atomicLoad(usize, &process.expected_kstack_tops[pid], .acquire);
        const name = if (p.name_len == 0) "(unnamed)" else p.name[0..@min(p.name_len, p.name.len)];
        const tsc: u64 = asm volatile (
            \\ rdtsc
            \\ shlq $32, %%rdx
            \\ orq %%rdx, %%rax
            : [r] "={rax}" (-> u64),
            :: .{ .rdx = true });
        serial.print(
            "\n[pcb-invariant] FAIL pid={d} ({s}) field='{s}' tsc=0x{X:0>12}\n",
            .{ pid, name, failure, tsc },
        );
        serial.print("[pcb-invariant]   state          = {s}\n", .{@tagName(p.state)});
        serial.print("[pcb-invariant]   kernel_esp     = 0x{X:0>16}\n", .{p.kernel_esp});
        serial.print("[pcb-invariant]   kernel_stack_top = 0x{X:0>16}\n", .{p.kernel_stack_top});
        serial.print("[pcb-invariant]   expected_top   = 0x{X:0>16}\n", .{expected_top});
        serial.print("[pcb-invariant]   pinned_cpu     = {d}\n", .{p.pinned_cpu});
        serial.print("[pcb-invariant]   assigned_cpu   = {d}\n", .{p.assigned_cpu});
        serial.print("[pcb-invariant]   is_idle        = {any}\n", .{p.is_idle});
        // Breadcrumb dump — tells us what each CPU was doing AT THE TICK
        // we detected corruption. With per-tick scanning, the writer's
        // CPU should be in its trace at the breadcrumb-stamping site.
        @import("breadcrumb.zig").dump();

        // Save-trace dump — the bad save is usually within the last
        // few entries on the CPU that last touched this pid's kesp.
        @import("save_trace.zig").dumpAll();

        // Per-PID activity ring for the failing pid — one place to see
        // SETSTATE / PICK_CAS / SETCURPID / RQ_ENTER/LEAVE for THIS pid
        // in time order across all CPUs. Disambiguates dispatch-window
        // FPs from real ordering bugs.
        @import("pid_act.zig").dump(pid);
        @import("kdbg.zig").nmi_halt_after_snapshot = true;
        @panic("pcb-invariant scanner detected corruption");
    }
}

/// Tick-driven entry. Call from handleIRQ0; runs the scan once every
/// SCAN_PERIOD_TICKS. Cheap (~10ns) when not the trigger tick.
pub fn maybeScan() void {
    if (@atomicLoad(bool, &reported, .acquire)) return;
    const t = @atomicLoad(u64, &process.tick_count, .monotonic);
    if (t == 0 or (t % SCAN_PERIOD_TICKS) != 0) return;
    scan();
}
