//! Exception handlers (vectors 0..31) + isr_common_exc asm + the crashlog
//! writers. The retired MMU write-watch state (WwEntry / ww_entries) lives
//! here because handleException's #PF / #DB hooks still reference it; with
//! all entries zeroed those branches are dead. See cpu/idt.zig for IDT
//! table layout, setGate, and init() wiring.

const std = @import("std");
const debug = @import("../../debug/debug.zig");
const serial = @import("../../debug/serial.zig");
const symbols = @import("../../debug/symbols.zig");
const process = @import("../../proc/process.zig");
const signals = @import("../../proc/signals.zig");
const memmap = @import("../../mm/memmap.zig");
const apic = @import("../../time/apic.zig");
const desktop = @import("../../ui/desktop.zig");
const elf_loader = @import("../../proc/elf_loader.zig");
const vga = @import("../../ui/vga.zig");

// --- Comptime exception stub generation ---

pub const ExcInfo = struct { num: u8, has_error_code: bool };

pub const exceptions = [_]ExcInfo{
    .{ .num = 0, .has_error_code = false }, // Division By Zero
    .{ .num = 1, .has_error_code = false }, // Debug
    .{ .num = 2, .has_error_code = false }, // Non-Maskable Interrupt
    .{ .num = 3, .has_error_code = false }, // Breakpoint
    .{ .num = 4, .has_error_code = false }, // Overflow
    .{ .num = 5, .has_error_code = false }, // Bound Range Exceeded
    .{ .num = 6, .has_error_code = false }, // Invalid Opcode
    .{ .num = 7, .has_error_code = false }, // Device Not Available
    .{ .num = 8, .has_error_code = true }, // Double Fault
    .{ .num = 10, .has_error_code = true }, // Invalid TSS
    .{ .num = 11, .has_error_code = true }, // Segment Not Present
    .{ .num = 12, .has_error_code = true }, // Stack-Segment Fault
    .{ .num = 13, .has_error_code = true }, // General Protection Fault
    .{ .num = 14, .has_error_code = true }, // Page Fault
    .{ .num = 16, .has_error_code = false }, // x87 Floating-Point
    .{ .num = 17, .has_error_code = true }, // Alignment Check
    .{ .num = 18, .has_error_code = false }, // Machine Check
    .{ .num = 19, .has_error_code = false }, // SIMD Floating-Point
};

pub fn ExcStub(comptime info: ExcInfo) type {
    return struct {
        pub fn handler() callconv(.naked) void {
            asm volatile ((if (!info.has_error_code) "pushq $0\n " else "") ++
                    "pushq $" ++ std.fmt.comptimePrint("{d}", .{info.num}) ++
                    "\n jmp isr_common_exc");
        }
    };
}

// Exception names for display
const exception_names = [_][]const u8{
    "Division By Zero", // 0
    "Debug", // 1
    "Non-Maskable Interrupt", // 2
    "Breakpoint", // 3
    "Overflow", // 4
    "Bound Range Exceeded", // 5
    "Invalid Opcode", // 6
    "Device Not Available", // 7
    "Double Fault", // 8
    "Reserved", // 9
    "Invalid TSS", // 10
    "Segment Not Present", // 11
    "Stack-Segment Fault", // 12
    "General Protection Fault", // 13
    "Page Fault", // 14
    "Reserved", // 15
    "x87 Floating-Point", // 16
    "Alignment Check", // 17
    "Machine Check", // 18
    "SIMD Floating-Point", // 19
};

// Resolve `addr` against the per-process symbol table and print
// "name+0xOFFSET", or "??" when no resolution is available. Used by the
// crash report to label RIP, return addresses, and stack-scan candidates.
fn printSym(addr: u64, app_syms: ?*const symbols.SymTable) void {
    if (app_syms) |st| {
        if (symbols.resolveUser(st, addr)) |r| {
            serial.print("{s}+0x{X}", .{ r.name, r.offset });
            return;
        }
    }
    serial.print("??", .{});
}

// CR2 holds the faulting linear address after a #PF. Stable for the whole
// handler: every deref the dump paths perform is isMapped-gated, so nothing
// in here can re-fault and overwrite it before the last reader.
inline fn readCr2() u64 {
    return asm volatile ("movq %%cr2, %[ret]"
        : [ret] "=r" (-> u64),
    );
}

// Walk a kernel RBP chain and print symbolized frames. Per-frame validity:
// the legacy low boot window [0x100000, 0x4000000) (boot stack — only alive
// pre-enterFirstTask) OR the canonical high half, where every kstack now
// lives (kstack_pool + heap kstacks in the physmap at 0xFFFF8000_...., the
// per-CPU isr_stack in kernel-image BSS at 0xFFFFFFFF8...). The high half
// contains unmapped holes (kstack guard pages, unbacked physmap), so both
// frame words are isMapped-gated — a corrupt rbp must degrade the backtrace,
// never #PF the crash dump itself. Mirrors the watch.zig / main.zig walkers;
// this file predated the kstack pool's BSS→physmap move (2026-06-04) and its
// low-only range silently printed ZERO frames for any crash on a pool kstack.
fn printKernelBacktrace(start_rbp: u64, max_depth: u32) void {
    const paging_mod = @import("../../mm/paging.zig");
    var rbp = start_rbp;
    var depth: u32 = 0;
    while (depth < max_depth) : (depth += 1) {
        const in_low = rbp >= 0x100000 and rbp < 0x4000000;
        const in_high = rbp >= 0xFFFF_8000_0000_0000;
        if (!in_low and !in_high) break;
        if ((rbp & 7) != 0) break; // misaligned — corrupt chain (and a
        // ReleaseSafe @ptrFromInt alignment panic-in-panic without this)
        if (!paging_mod.isMapped(rbp) or !paging_mod.isMapped(rbp + 8)) break;
        const frame: [*]const u64 = @ptrFromInt(rbp);
        const ret_addr = frame[1];
        if (ret_addr == 0) break;
        if (symbols.resolveKernel(ret_addr)) |r| {
            serial.print("    [{d}] {s}+0x{X} (0x{X:0>16})\n", .{ depth, r.name, r.offset, ret_addr });
        } else {
            serial.print("    [{d}] 0x{X:0>16}\n", .{ depth, ret_addr });
        }
        const next = frame[0];
        if (next <= rbp) break; // frames must climb
        rbp = next;
    }
}
// Unified exception handler — called from isr_common_exc
// Stack layout (RSP points to):
//   [0]  r15  [1]  r14  [2]  r13  [3]  r12
//   [4]  r11  [5]  r10  [6]  r9   [7]  r8
//   [8]  rdi  [9]  rsi  [10] rbp  [11] rbx
//   [12] rdx  [13] rcx  [14] rax
//   [15] int_no  [16] error_code


// --- MMU write-watch state (RETIRED) -----------------------------------------
// (u: dead) Retained as a reference for the write-watch protocol; no caller
// currently arms a watch (see project_mmu_watch_obsolete in memory). The
// underlying #PF / #DB hooks below still read ww_pending_reprotect_page and
// ww_entries[], but with all entries zeroed those branches are dead. If you
// rearm this, note that the existing plain-store discipline is racy across
// CPUs — multiple #PFs can clobber ww_pending_reprotect_page; wrap in
// std.atomic.Value(u64) and document one-shot exclusivity per page.
//
// Page-granular wild-write detector. Up to 4 simultaneous protected pages,
// each with its own legit-writer whitelist (symbol name + max offset within
// the function). On a kernel-mode write to a watched page: if RIP is in the
// whitelisted function, unprotect + set TF, let the inc complete, then BS
// reprotects. Anything else is THE bug → dump and panic.
//
// Why per-page whitelists: the wild writer hits different BSS pages on
// different runs (kernel_rsp_page one run, hb_state_count_page another).
// One watch is a coin flip; covering all known victims simultaneously
// guarantees a hit on the next misbehavior.
pub const WwEntry = struct {
    page: u64 = 0,
    whitelist_sym: []const u8 = "",
    max_offset: u32 = 0,
};
pub var ww_entries: [4]WwEntry = [_]WwEntry{.{}} ** 4;
pub var ww_pending_reprotect_page: u64 = 0;

/// Install MMU write-watch on the page containing `addr`, with the given
/// whitelist symbol/offset for the legit writer. Caller must have already
/// enabled CR0.WP=1 (paging.enableCR0WriteProtect) and loaded kernel symbols.
pub fn armWriteWatch(addr: u64, whitelist_sym: []const u8, max_offset: u32) void {
    const paging_mod = @import("../../mm/paging.zig");
    for (&ww_entries) |*e| {
        if (e.page == 0) {
            const page = paging_mod.installWriteWatch(@intCast(addr)) orelse {
                serial.print("[ww] failed to install MMU write-watch on 0x{X}\n", .{addr});
                return;
            };
            e.page = page;
            e.whitelist_sym = whitelist_sym;
            e.max_offset = max_offset;
            serial.print("[ww] MMU write-watch armed: page=0x{X} sym={s} max_off=0x{X}\n", .{ page, whitelist_sym, max_offset });
            return;
        }
    }
    serial.print("[ww] all 4 watch slots full — cannot arm 0x{X}\n", .{addr});
}
//   [17] rip  [18] cs  [19] rflags  [20] rsp  [21] ss  (pushed by CPU)
export fn handleException(rsp: u64) callconv(.c) void {
    const t = @import("../../debug/perf.zig").enter();
    defer @import("../../debug/perf.zig").leave(.exception, t);
    asm volatile ("cli");
    // SMAP: an exception during a syscall body inherits AC=1 from the
    // syscall; clear it so kernel-mode handler code runs with SMAP
    // enforcement. IRET pops RFLAGS so AC is restored on return.
    @import("../arch/protect.zig").disallowUserAccess();

    // Sanity-check the rsp arg: a non-canonical or NULL pointer here means
    // the IRQ stub's leaq fed us garbage (e.g., TSS.RSP0 was clobbered or
    // setTssRsp0 wrote a wrong address). Print and bail before deref'ing
    // garbage and triple-faulting in the dump.
    if (rsp < 0x1000 or (rsp >= 0x0000_8000_0000_0000 and rsp < 0xFFFF_8000_0000_0000)) {
        @import("../../debug/serial.zig").print("[exc] BOGUS rsp=0x{X} — TSS.RSP0 corrupted before entry?\n", .{rsp});
        @panic("handleException: noncanonical rsp — TSS.RSP0 corrupted before entry");
    }

    // KASAN: the saved-register area + iretq frame above us must be on a
    // *live* kstack. If it's been poisoned (process exited / kstack returned
    // to pool while still in use), KASAN trips here with the writer's
    // backtrace ahead of the eventual ret-to-garbage crash. 176 = 15 GPRs
    // (120) + int_no/error_code (16) + the 5-qword iretq frame (40) — in
    // 64-bit mode the CPU pushes SS:RSP unconditionally, so the frame is
    // always the full 40 bytes.
    @import("../../debug/kasan.zig").expectValid(rsp, 176);

    // CpuLocal end-canary check (task #229).
    @import("../smp.zig").verifyEndCanary();

    const stack: [*]const u64 = @ptrFromInt(rsp);
    const int_no = stack[15];
    const error_code = stack[16];
    const saved_cs = stack[18];
    const saved_rip = stack[17];

    // Safe-MSR exception fixup (rdmsrSafe/wrmsrSafe). A #GP (13) at a
    // registered MSR-probe instruction site, in kernel mode, is recovered
    // by redirecting the saved RIP to the accessor's fixup landing pad —
    // which returns "failed" to the caller instead of panicking. The sites
    // are link-time invariants, so this needs no per-CPU state and is safe
    // under reentrancy/SMP. Must precede the panic/user-signal dispatch.
    // Kernel-CS gate: a ring-3 #GP can never sit at a kernel probe address,
    // but gating is belt-and-braces and keeps user faults on their path.
    if (int_no == 13 and (saved_cs & 3) == 0) {
        if (@import("../arch/msr.zig").fixupRip(saved_rip)) |fixup| {
            const wframe: [*]u64 = @ptrFromInt(rsp);
            wframe[17] = fixup;
            return;
        }
    }

    // Breadcrumb: vec in high 32, pid in low 32. Stamped before the NMI
    // fast-path return so even NMI-snapshotted CPUs leave a trace.
    {
        const pid_now: u64 = if (@import("../smp.zig").myCpu().current_pid) |p| @intCast(p) else 0xFF;
        @import("../../debug/breadcrumb.zig").stamp(.exception_entry, (int_no << 32) | pid_now);
    }

    // NMI snapshot fast-path (task #247). When debug.kdbg.broadcastNMI()
    // sets nmi_snapshot_mode, every other CPU receives an NMI. We dump
    // a one-line state digest and IRET back. This is the ONLY way to
    // observe a CPU that's stuck with IF=0 (kernel critical section,
    // hlt loop, infinite loop without IRQs) — used for "OS frozen but
    // no panic" debugging.
    if (int_no == 2) {
        @import("../../debug/kdbg.zig").nmiSnapshot(rsp, saved_rip, saved_cs);
        return;
    }

    // Machine Check (vector 18). Walk MC banks, log + clear; resume on
    // recoverable status, panic only when PCC (processor-context-corrupt)
    // is set. Without this dispatch the generic exception path treats
    // every #MC as a panic, losing the per-bank decode.
    if (int_no == 18) {
        const outcome = @import("../arch/mce.zig").handle();
        if (outcome == .recovered) return;
        // Fatal — fall through to the standard panic dump below.
        serial.print("[mce] FATAL: PCC set on at least one bank — kernel state corrupt\n", .{});
    }

    // Wild-RIP hunt (task #224). Same idea as handleIRQ0: validate the saved
    // RIP just before iretq returns to user mode. Exception frame has RIP at
    // index 17 (vs 15 for IRQs) because the ISR stub pushed int_no and
    // error_code onto the kernel stack first.
    defer @import("../../debug/kdbg.zig").validateUserReturnIretq(stack, 17, 18);

    // iretq-frame tripwire (task #230) — exception version. RIP slot at 17
    // (after int_no + error_code pushes). See handleIRQ0 for design notes.
    @import("../../debug/iretq_canary.zig").capture(stack, 17);
    defer @import("../../debug/iretq_canary.zig").invalidate();

    // ---- DR0-DR3 watchpoint dispatch --------------------------------------
    // The watchpoint manager owns DR0-DR3 + DR7. On a #DB it inspects DR6,
    // routes to the slot's policy (panic/log/silent), and clears the sticky
    // bits. Returns true if a watchpoint actually fired — in that case we
    // skip the rest of the #DB path (gdb stub, signal redirect, etc.) since
    // the manager already handled it (or panicked).
    //
    // Legacy MMU-watch BS reprotect path stays below: it's gated on
    // `ww_pending_reprotect_page != 0`, which is never set since the MMU
    // write-watch was retired (see project_mmu_watch_obsolete.md), so it's
    // dead but cheap insurance if someone re-enables it.
    if (int_no == 1) {
        if (@import("../../debug/watch.zig").onDebugException(rsp, saved_rip)) {
            return;
        }
        const dr6 = @import("../../debug/watch.zig").readDr6();
        if ((dr6 & (1 << 14)) != 0 and ww_pending_reprotect_page != 0) {
            @import("../../mm/paging.zig").setWriteWatchRW(@intCast(ww_pending_reprotect_page), false);
            ww_pending_reprotect_page = 0;
            const stack_w: [*]volatile u64 = @ptrFromInt(rsp);
            stack_w[19] &= ~@as(u64, 1 << 8); // clear TF
            asm volatile ("mov $0, %%rax\n mov %%rax, %%dr6\n"
                ::: .{ .rax = true });
            return;
        }
    }
    // ---- end watchpoint dispatch ------------------------------------------

    // ---- MMU write-watch trap (page-protected wild-writer detector) -------
    // Catches writes that DR0 missed (anything outside the watched 4 bytes).
    // Scans ww_entries[]; on a hit, applies that page's whitelist.
    if (int_no == 14) {
        const cr2 = readCr2();
        const w_bit = (error_code >> 1) & 1;
        const u_bit = (error_code >> 2) & 1;
        if (w_bit != 0 and u_bit == 0) {
            for (ww_entries) |e| {
                if (e.page == 0) continue;
                if (cr2 < e.page or cr2 >= e.page + 0x1000) continue;
                // Hit watched page e
                const sym_mod = @import("../../debug/symbols.zig");
                const is_legit = blk: {
                    const r = sym_mod.resolveKernel(saved_rip) orelse break :blk false;
                    if (!std.mem.eql(u8, r.name, e.whitelist_sym)) break :blk false;
                    if (r.offset > e.max_offset) break :blk false;
                    break :blk true;
                };
                if (is_legit) {
                    @import("../../mm/paging.zig").setWriteWatchRW(@intCast(e.page), true);
                    const stack_w: [*]volatile u64 = @ptrFromInt(rsp);
                    stack_w[19] |= (1 << 8); // set TF — single-step the inc
                    ww_pending_reprotect_page = e.page;
                    return;
                }
                // Wild writer caught at the scene.
                const r15 = stack[0];
                serial.print("\n!!! WILD WRITER (MMU) CAUGHT !!!\n", .{});
                serial.print("  CR2 = 0x{X:0>16}  (in watched page 0x{X:0>16})\n", .{ cr2, e.page });
                serial.print("  RIP = 0x{X:0>16}\n", .{saved_rip});
                if (sym_mod.resolveKernel(saved_rip)) |r| {
                    serial.print("  Site: {s}+0x{X}\n", .{ r.name, r.offset });
                }
                serial.print("  ERR=0x{X:0>2} (write from supervisor)\n", .{error_code});
                serial.print("  RAX=0x{X:0>16} RCX=0x{X:0>16}\n", .{ stack[14], stack[13] });
                serial.print("  RDX=0x{X:0>16} RBX=0x{X:0>16}\n", .{ stack[12], stack[11] });
                serial.print("  RSI=0x{X:0>16} RDI=0x{X:0>16}\n", .{ stack[9], stack[8] });
                serial.print("  RBP=0x{X:0>16} R15=0x{X:0>16}\n", .{ stack[10], r15 });
                serial.print("  R8 =0x{X:0>16} R9 =0x{X:0>16}\n", .{ stack[7], stack[6] });
                serial.print("  R10=0x{X:0>16} R11=0x{X:0>16}\n", .{ stack[5], stack[4] });
                serial.print("  R12=0x{X:0>16} R13=0x{X:0>16}\n", .{ stack[3], stack[2] });
                serial.print("  R14=0x{X:0>16}\n", .{stack[1]});
                const rip_page_end = (saved_rip & ~@as(u64, 0xFFF)) + 0x1000;
                const safe_len: u64 = @min(16, rip_page_end - saved_rip);
                const code: [*]const u8 = @ptrFromInt(saved_rip);
                serial.print("  Code:", .{});
                for (0..@intCast(safe_len)) |i| serial.print(" {X:0>2}", .{code[i]});
                serial.print("\n", .{});
                serial.print("  Backtrace:\n", .{});
                printKernelBacktrace(stack[10], 16);
                // Disarm all watches so panic's own writes don't recurse.
                for (&ww_entries) |*entry| {
                    if (entry.page != 0) @import("../../mm/paging.zig").setWriteWatchRW(@intCast(entry.page), true);
                    entry.page = 0;
                }
                @panic("WILD WRITER (MMU) caught — see RIP/CR2 above");
            }
        }
    }
    // ---- end MMU write-watch trap -----------------------------------------

    // Tripwire: log EVERY exception entry, including user-mode PFs that
    // would otherwise be silenced by the heuristic below. Once-per-vector
    // per-PID so the channel doesn't drown in lazy fault-ins. If a process
    // hangs and we never see this line for the suspected fault, the CPU
    // isn't actually delivering the exception (IDT corruption, stale
    // shadow gate, recursive #DF that immediately reset). If we DO see it
    // but never see the matching iretq-back log, the handler itself is
    // wedging on a lock/loop with IRQs off.
    {
        const exc_entry_state = struct {
            var seen: [256][32]bool = [_][32]bool{[_]bool{false} ** 32} ** 256;
        };
        const cur_pid_for_trace: u8 = blk: {
            const cp = process.getCurrentPid();
            if (cp >= 32) break :blk 0;
            break :blk @intCast(cp);
        };
        if (int_no < 256 and !exc_entry_state.seen[@intCast(int_no)][cur_pid_for_trace]) {
            exc_entry_state.seen[@intCast(int_no)][cur_pid_for_trace] = true;
            @import("../../debug/serial.zig").print("[exc-entry] vec={d} pid={d} cs=0x{X} rip=0x{X}\n", .{ int_no, cur_pid_for_trace, saved_cs, saved_rip });
        }
    }

    // Always-on diagnostic for hard exceptions: prints BEFORE any other handler
    // logic, so a bug that triple-faults the rest of the dispatch path still
    // leaves a clue in serial.log. Filtered to keep noise down:
    //   * Kernel-mode (CS=0x08) → ALWAYS print. These should never happen.
    //   * User-mode (CS&3==3) → print non-PF only. User-mode #PFs are nearly
    //     always lazy fault-ins which `process.handleUserPageFault` logs via
    //     `[pf] PID=N lazy fault-in ...`; double-logging here would drown out
    //     the genuinely-interesting cases.
    //   * vec < 6 (debug/breakpoint/etc.) skipped — handled elsewhere.
    if (int_no >= 6) {
        const from_user = (saved_cs & 3) != 0;
        if (!from_user or int_no != 14) {
            @import("../../debug/serial.zig").print("[exc] vec={d} err=0x{X} rip=0x{X} cs=0x{X} cr2=0x{X}\n", .{ int_no, error_code, saved_rip, saved_cs, readCr2() });
        }
    }


    const name = if (int_no < exception_names.len)
        exception_names[int_no]
    else
        "Unknown";

    // GDB stub intercept: exceptions 1 (debug) and 3 (breakpoint)
    const gdb_stub = @import("../../debug/gdb_stub.zig");
    if (int_no == 1 or int_no == 3) {
        if (gdb_stub.isActive()) {
            gdb_stub.enterStub(@ptrFromInt(rsp), @intCast(int_no));
            return;
        }
    }

    // Check if exception came from Ring 3 (user process)
    if (saved_cs & 3 != 0) {
        // Page fault: try lazy fault-in before treating as a crash. Resolves
        // any access to a registered lazy region (currently the user stack).
        if (int_no == 14) {
            const cr2 = readCr2();
            if (process.handleUserPageFault(@intCast(cr2), error_code)) {
                asm volatile ("sti");
                return;
            }
        }

        // Synchronous-signal route: if the user has a handler installed for
        // the corresponding signal, redirect the exception trap frame to the
        // handler instead of killing. SIGKILL/SIGSTOP can't be caught so they
        // never end up here; SIG_DFL/SIG_IGN fall through to the kill path.
        const sig: u32 = switch (int_no) {
            0 => signals.SIGFPE, // #DE divide error
            1 => signals.SIGTRAP, // #DB debug
            3 => signals.SIGTRAP, // #BP breakpoint
            4 => signals.SIGSEGV, // #OF overflow
            5 => signals.SIGSEGV, // #BR bound range
            6 => signals.SIGILL, // #UD invalid opcode
            7 => signals.SIGFPE, // #NM device-not-available (FPU)
            13 => signals.SIGSEGV, // #GP general protection
            12 => signals.SIGSEGV, // #SS stack segment
            14 => signals.SIGSEGV, // #PF page fault (after lazy-fault-in failed)
            16 => signals.SIGFPE, // #MF x87 floating-point
            17 => signals.SIGBUS, // #AC alignment check
            19 => signals.SIGFPE, // #XF SIMD floating-point
            else => 0,
        };
        if (sig != 0) {
            if (process.currentPCB()) |pcb| {
                // ExcFrame layout matches the GPR_start handed to handleException
                // — see the layout comment a few hundred lines up.
                const exc_frame: *signals.ExcFrame = @ptrFromInt(rsp);
                // For SIGSEGV from #PF, surface cr2 as si_addr and pick a
                // si_code based on error-code bit 0 (P=1 means present-page
                // permission violation, 0 means missing mapping). Other
                // exceptions don't have a meaningful faulting address.
                var fault_addr: u64 = 0;
                var si_code: u32 = signals.SI_KERNEL;
                if (int_no == 14) {
                    fault_addr = readCr2();
                    si_code = if ((error_code & 1) == 0) signals.SEGV_MAPERR else signals.SEGV_ACCERR;
                } else if (int_no == 6) {
                    fault_addr = saved_rip;
                    si_code = signals.ILL_ILLOPC;
                } else if (int_no == 0) {
                    fault_addr = saved_rip;
                    si_code = signals.FPE_INTDIV;
                } else if (int_no == 3 or int_no == 1) {
                    fault_addr = saved_rip;
                    si_code = signals.TRAP_BRKPT;
                }
                if (signals.deliverFromExcFrame(pcb, exc_frame, sig, fault_addr, si_code)) {
                    asm volatile ("sti");
                    return;
                }
            }
        }

        // Ring 3 crash — kill process, log to serial + crashlog, return to desktop
        const pid = process.getCurrentPid();
        // Detect stack overflow specifically: page fault inside the guard zone
        // immediately below the user stack base. 16KB ≈ enough margin to catch
        // a single function with large locals overflowing past the lazy stack.
        var is_stack_overflow = false;
        if (int_no == 14) {
            const cr2 = readCr2();
            if (process.currentPCB()) |pcb| {
                const guard_size: usize = 16 * 4096;
                if (pcb.stack_base != 0 and cr2 < pcb.stack_base and
                    cr2 + guard_size >= pcb.stack_base)
                {
                    is_stack_overflow = true;
                    serial.print("\n[STACK OVERFLOW] PID={d} CR2={X:0>16} stack_base={X:0>16} RSP={X:0>16}\n", .{ pid, cr2, pcb.stack_base, stack[20] });
                }
            }
        }
        if (!is_stack_overflow) {
            serial.print("\n[CRASH] PID={d} Exception {d}: {s}\n", .{ pid, int_no, name });
        }
        // (Per-CPU last iretq RIP diagnostic removed with the legacy
        // enterUserMode/returnToKernel pair. In the new model the only
        // iretq site is retToUserStub for first dispatch; subsequent
        // dispatches go through switchTo which uses kernel-to-kernel ret.)

        const app_syms = if (process.currentPCB()) |pcb| pcb.sym_table else null;
        const saved_rbp = stack[10];
        const saved_rsp = stack[20];

        // RIP + symbol on the same line. saved_rip is the faulting instruction
        // address; the resolver may legitimately return null for inlined or
        // unloaded code.
        serial.print("  RIP=0x{X:0>16}  ", .{saved_rip});
        printSym(saved_rip, app_syms);
        serial.print("\n", .{});
        serial.print("  RSP=0x{X:0>16}  RBP=0x{X:0>16}\n", .{ saved_rsp, saved_rbp });

        if (int_no == 14) {
            const cr2 = readCr2();
            const p_bit = error_code & 1;
            const w_bit = (error_code >> 1) & 1;
            const u_bit = (error_code >> 2) & 1;
            const i_bit = (error_code >> 4) & 1;
            const kind = if (p_bit == 0) "non-present" else "protection";
            const op = if (i_bit != 0) "exec" else if (w_bit != 0) "write" else "read";
            const mode = if (u_bit != 0) "user" else "supervisor";
            serial.print("  CR2=0x{X:0>16}  ERR=0x{X:0>2} ({s} {s} from {s})\n", .{ cr2, error_code, kind, op, mode });
        } else {
            serial.print("  ERR=0x{X:0>16}\n", .{error_code});
        }

        // Register dump. Indices match the layout comment at the top of the
        // function: stack[14]=rax, [13]=rcx, [12]=rdx, [11]=rbx, [9]=rsi,
        // [8]=rdi, [10]=rbp, [7]=r8, [6]=r9, [5]=r10, [4]=r11, [3]=r12,
        // [2]=r13, [1]=r14, [0]=r15.
        serial.print("  RAX=0x{X:0>16} RBX=0x{X:0>16} RCX=0x{X:0>16} RDX=0x{X:0>16}\n", .{ stack[14], stack[11], stack[13], stack[12] });
        serial.print("  RSI=0x{X:0>16} RDI=0x{X:0>16} R8 =0x{X:0>16} R9 =0x{X:0>16}\n", .{ stack[9], stack[8], stack[7], stack[6] });
        serial.print("  R10=0x{X:0>16} R11=0x{X:0>16} R12=0x{X:0>16} R13=0x{X:0>16}\n", .{ stack[5], stack[4], stack[3], stack[2] });
        serial.print("  R14=0x{X:0>16} R15=0x{X:0>16}\n", .{ stack[1], stack[0] });

        // Code bytes at RIP (up to next page boundary, capped at 16). For
        // most exceptions RIP is mapped (we got here by executing it), but
        // for #PF on instruction fetch (vec=14, error_code bit 4 set) the
        // page IS the unmapped one — dereffing here would double-fault.
        // Walk the PT first; if not mapped, skip the dump.
        if (saved_rip != 0) {
            if (!@import("../../mm/paging.zig").isMapped(saved_rip)) {
                serial.print("  Code:  <RIP page not mapped — likely instruction-fetch #PF>\n", .{});
            } else {
                const rip_page_end = (saved_rip & ~@as(u64, 0xFFF)) + 0x1000;
                const safe_len: u64 = @min(16, rip_page_end - saved_rip);
                const code: [*]const u8 = @ptrFromInt(saved_rip);
                // User RIP is below the kernel half — bracket the read with
                // STAC/CLAC so SMAP doesn't double-fault us here.
                const is_user_rip = saved_rip < 0xFFFF800000000000;
                const protect_mod = @import("../arch/protect.zig");
                if (is_user_rip) protect_mod.allowUserAccess();
                serial.print("  Code:", .{});
                for (0..@intCast(safe_len)) |i| serial.print(" {X:0>2}", .{code[i]});
                serial.print("\n", .{});
                // Decode the faulting instruction so the user doesn't have to
                // pull up objdump just to figure out what we hit.
                serial.print("  Insn: ", .{});
                @import("../../debug/disasm.zig").printOne(code[0..@intCast(safe_len)]);
                serial.print("\n", .{});
                if (is_user_rip) protect_mod.disallowUserAccess();
            }
        }

        // RBP-walked backtrace. The RBP comes from user space, so reading
        // through it needs STAC. Without it SMAP traps the kernel on the
        // first frame[1] dereference and we never see the backtrace.
        var bt_frames: u32 = 0;
        if (saved_rbp > 0x100000 and saved_rbp < 0x600000) {
            serial.print("  Backtrace (rbp):\n", .{});
            const protect_bt = @import("../arch/protect.zig");
            protect_bt.allowUserAccess();
            var rbp: usize = @intCast(saved_rbp);
            var depth: u32 = 0;
            while (rbp >= 0x100000 and rbp < 0x600000 and depth < 16) : (depth += 1) {
                // Don't fault the handler: if this frame's page isn't mapped, a
                // SECONDARY #PF reading through it would escalate a survivable
                // user fault into a kernel panic. Stop the walk instead. (Same
                // isMapped guard the Code-bytes dump above already uses.) We
                // read frame[0] (at rbp) AND frame[1] (at rbp+8), so a corrupt
                // rbp 8 bytes shy of a page edge could straddle into the next,
                // non-present page — gate both. (rbp < 0x600000 here, so rbp+8
                // can't overflow.)
                if (!@import("../../mm/paging.zig").isMapped(rbp) or
                    !@import("../../mm/paging.zig").isMapped(rbp + 8)) break;
                const frame: [*]const usize = @ptrFromInt(rbp);
                const ret_addr: u64 = @intCast(frame[1]);
                if (ret_addr == 0) break;
                serial.print("    [{d}] 0x{X:0>16}  ", .{ depth, ret_addr });
                printSym(ret_addr, app_syms);
                serial.print("\n", .{});
                bt_frames += 1;
                const next_rbp: usize = @intCast(frame[0]);
                if (next_rbp <= rbp or next_rbp >= 0x600000) break; // sanity: must climb
                rbp = next_rbp;
            }
            protect_bt.disallowUserAccess();
        }

        // Stack-scan fallback when the rbp walk is short or empty (e.g.,
        // -fomit-frame-pointer code, clobbered RBP). Scan up to 64 stack words
        // looking for values that look like return addresses into a known
        // user code segment, and dedupe.
        if (bt_frames < 2 and saved_rsp >= 0x100000 and saved_rsp < 0x600000 and
            @import("../../mm/paging.zig").isMapped(saved_rsp))
        {
            serial.print("  Stack scan candidates:\n", .{});
            const stack_page_end = (saved_rsp & ~@as(u64, 0xFFF)) + 0x1000;
            const sp: [*]const u64 = @ptrFromInt(saved_rsp);
            const max_words: u64 = @min(64, (stack_page_end - saved_rsp) / 8);
            const protect_ss = @import("../arch/protect.zig");
            protect_ss.allowUserAccess();
            var printed: u32 = 0;
            var prev: u64 = 0;
            for (0..@intCast(max_words)) |i| {
                const v = sp[i];
                if (v < 0x401000 or v >= 0x4F0000) continue; // text region heuristic
                if (v == prev) continue;
                prev = v;
                if (app_syms) |st| {
                    if (symbols.resolveUser(st, v)) |r| {
                        serial.print("    [SP+0x{X:0>3}] 0x{X:0>16}  {s}+0x{X}\n", .{ i * 8, v, r.name, r.offset });
                        printed += 1;
                        if (printed >= 8) break;
                    }
                }
            }
            protect_ss.disallowUserAccess();
            if (printed == 0) serial.print("    (no resolvable candidates)\n", .{});
        }

        // kdbg post-mortem: PT walk for CR2, frame provenance, ring dumps.
        // Adds context that the line-by-line crash dump above can't surface
        // — e.g. "shell faulted at 0x25 because RDI was 0x25, and frame
        // X under shell's PT[1] was last allocated by Y three events ago."
        if (int_no == 14) {
            const cr2 = readCr2();
            const cur_pd = if (process.currentPCB()) |pcb| pcb.page_dir_phys else 0;
            @import("../../debug/kdbg.zig").walkUserPT(cur_pd, cr2);
            // Hex dump of the bytes around RSP — most useful when the RBP
            // walk is short (e.g. memcpy clobbered RBP via prologue or the
            // crash is in -fomit-frame-pointer code). 64 bytes covers the
            // typical "saved args + return slot" window of a small frame.
            if (saved_rsp >= 0x100000 and saved_rsp < 0x600000 and
                @import("../../mm/paging.zig").isMapped(saved_rsp))
            {
                serial.print("  Stack hex (64B from RSP):\n", .{});
                const stack_page_end = (saved_rsp & ~@as(u64, 0xFFF)) + 0x1000;
                const sp: [*]const u8 = @ptrFromInt(saved_rsp);
                const dump_bytes: u64 = @min(64, stack_page_end - saved_rsp);
                const protect_sh = @import("../arch/protect.zig");
                protect_sh.allowUserAccess();
                var off: u64 = 0;
                while (off < dump_bytes) : (off += 16) {
                    serial.print("    [SP+0x{X:0>3}] ", .{off});
                    var bi: u64 = 0;
                    while (bi < 16 and off + bi < dump_bytes) : (bi += 1) {
                        serial.print("{X:0>2} ", .{sp[off + bi]});
                    }
                    serial.print("\n", .{});
                }
                protect_sh.disallowUserAccess();
            }
            // Provenance: who handed out the frame that backs CR2's page?
            // Useful when CR2 is a "real" user VA (not near-NULL like 0x25).
            if (cr2 >= 0x400000 and cr2 < 0x10000000) {
                @import("../../debug/kdbg.zig").findFrame(cr2 & ~@as(u64, 0xFFF));
            }
        }
        // Always dump the rings on a Ring-3 crash — small (≈5 KB) and
        // routinely the difference between "I have no idea" and "obvious".
        @import("../../debug/kdbg.zig").dumpAll();

        // Last 8 syscalls the dying PID made. Frequently the smoking
        // gun for "app crashed for no obvious reason" — often it was
        // mid-sysCreateWindow, mid-fread, etc.
        process.dumpSyscallRing(@intCast(pid));

        // Write crash to FAT32 crashlog (only if FAT32 is ready)
        const fat32 = @import("../../fs/fat32.zig");
        if (fat32.isInitialized()) {
            writeCrashLog(pid, int_no, error_code, saved_rip, name);
        }

        // Show notification on desktop
        if (desktop.active) {
            desktop.showNotification("App crashed! See crashlog");
        }

        // Kill the faulting process and yield. destroyCurrent sets
        // state=.zombie/.unused + clears cpu.current_pid; schedule() then
        // picks the next ready task and never returns here.
        //
        // NO `sti` between destroyCurrent and schedule. destroyCurrent's
        // .unused branch poisons the kstack via markPcbDead — if a timer
        // IRQ fires before schedule() swaps off this stack, the IRQ stub
        // pushes 160 bytes onto the now-poisoned region and handleIRQ0's
        // expectValid trips. schedule()'s acquireIrqSave saves the current
        // (disabled) flags; the new task resumes with its OWN flags via
        // its own schedule call's restore.
        process.destroyCurrent();
        process.schedule();
        unreachable;
    }

    // Ring 0 exception — kernel panic with full register dump
    //
    // Enter the panic critical section FIRST so this CPU's full register
    // dump + autopsy + ring dumps print sequentially without byte-interleaving
    // with the other CPU's concurrent panic output. Idempotent per-CPU.
    @import("../../debug/kdbg.zig").enterCritical();

    // Halt peer CPUs BEFORE we print anything. Otherwise the exception
    // banner / register dump / backtrace below byte-interleave with
    // whatever the peers were klog'ing (slow-sc, perf, heartbeats). Each
    // peer still emits its own [nmi-snap cpuN] line before halting, so
    // we don't lose the cross-CPU snapshot.
    @import("../../debug/kdbg.zig").nmi_halt_after_snapshot = true;
    @import("../../debug/kdbg.zig").broadcastNMI();

    serial.print("\n!!! EXCEPTION {d}: {s} !!!\n", .{ int_no, name });
    serial.print("  RIP={X:0>16} CS={X:0>4} ERR={X:0>16}\n", .{ saved_rip, saved_cs, error_code });
    serial.print("  RSP={X:0>16} SS={X:0>4} RFLAGS={X:0>16}\n", .{ stack[20], stack[21], stack[19] });

    // Control registers (read early for crash classifier)
    const cr2 = readCr2();
    const cr3 = asm volatile ("movq %%cr3, %[ret]"
        : [ret] "=r" (-> u64),
    );

    // Crash classifier hint — helps narrow down the likely cause before diving
    // into register dumps. For #PF, pass CR2; for others it's ignored.
    const hint = debug.classifyCrash(int_no, saved_rip, cr2, stack[20]);
    serial.print("  {s}\n", .{hint});

    // Dump all saved GPRs
    serial.print("  RAX={X:0>16} RBX={X:0>16} RCX={X:0>16} RDX={X:0>16}\n", .{ stack[14], stack[11], stack[13], stack[12] });
    serial.print("  RSI={X:0>16} RDI={X:0>16} RBP={X:0>16}\n", .{ stack[9], stack[8], stack[10] });
    serial.print("  R8 ={X:0>16} R9 ={X:0>16} R10={X:0>16} R11={X:0>16}\n", .{ stack[7], stack[6], stack[5], stack[4] });
    serial.print("  R12={X:0>16} R13={X:0>16} R14={X:0>16} R15={X:0>16}\n", .{ stack[3], stack[2], stack[1], stack[0] });

    serial.print("  CR2={X:0>16} CR3={X:0>16}\n", .{ cr2, cr3 });

    if (int_no == 14) {
        // Page fault decode: P=present, W=write, U=user, R=reserved, I=instruction
        serial.print("  Page fault: {s}{s}{s}{s} addr=0x{X}\n", .{
            if (error_code & 1 != 0) "protection " else "not-present ",
            if (error_code & 2 != 0) "write " else "read ",
            if (error_code & 4 != 0) "user " else "kernel ",
            if (error_code & 16 != 0) "instruction-fetch" else "",
            cr2,
        });

        // SMAP-violation classifier — supervisor #PF on a present page in
        // user-VA range almost certainly means kernel touched user memory
        // without STAC (i.e. outside an active syscall validateUserPtr
        // bracket). Names the bug class so we don't have to puzzle over
        // "kernel-mode #PF on a present page".
        const protect = @import("../arch/protect.zig");
        if (protect.smap_enabled and
            (error_code & 4) == 0 and
            (error_code & 1) != 0 and
            cr2 >= memmap.USER_SPACE_START and cr2 < memmap.USER_SPACE_END and
            (error_code & 16) == 0)
        {
            serial.print("  [SMAP] kernel touched user page without STAC — validate user pointer first\n", .{});
        }
        // SMEP-violation classifier — supervisor instruction-fetch #PF on
        // a present user-VA page = kernel jumped into user .text. Usually
        // means RIP got corrupted via stack overflow / wild-write / ROP.
        if (protect.smep_enabled and
            (error_code & 4) == 0 and
            (error_code & 1) != 0 and
            cr2 >= memmap.USER_SPACE_START and cr2 < memmap.USER_SPACE_END and
            (error_code & 16) != 0)
        {
            serial.print("  [SMEP] kernel tried to fetch from user page — corrupted RIP / ROP\n", .{});
        }
    }

    // #DF decode: if the faulting RSP sits inside the kstack pool, name the
    // slot — and when it's in the slot's guard page, that's THE kernel-stack-
    // overflow signature (a push into the guard #PFs; the #PF frame push then
    // fails on the same dead RSP; the CPU escalates to #DF). Vector 8 only
    // reaches this dump at all because its gate runs on IST1 (see idt.init) —
    // with IST=0 the same push failure escalates straight to triple fault.
    if (int_no == 8 and process.kstack_pool_phys_base != 0) {
        const cfg = @import("../../config.zig");
        const pool_base = @intFromPtr(process.kstack_pool);
        const fault_rsp = stack[20];
        if (fault_rsp >= pool_base and fault_rsp < pool_base + process.KSTACK_POOL_BYTES) {
            const slot = (fault_rsp - pool_base) / cfg.KSTACK_SLOT_SIZE;
            const off = (fault_rsp - pool_base) % cfg.KSTACK_SLOT_SIZE;
            serial.print("  [#DF] RSP in kstack slot {d} off=0x{X}{s}\n", .{
                slot,
                off,
                if (off < cfg.KSTACK_GUARD_SIZE) " — GUARD page: kernel stack overflow" else "",
            });
        }
    }

    // Stack backtrace with symbol resolution (follow RBP chain)
    serial.print("  Backtrace:\n", .{});
    // Resolve crash RIP
    if (symbols.resolveKernel(saved_rip)) |r| {
        serial.print("  Crash in: {s}+0x{X}\n", .{ r.name, r.offset });
    }
    printKernelBacktrace(stack[10], 16);

    // Full kdbg autopsy: cross-CPU snapshot, all-PCB state, ring dumps,
    // hex dump near the kernel RSP, optional PT walk for #PF. Newly added
    // to the Ring-0 path (used to be Ring-3 only) — without this the
    // recent iretq=0x{8410,7410} #GP gave us no usable diagnostic data.
    @import("../../debug/kdbg.zig").crashAutopsy(.{
        .cr2 = if (int_no == 14) cr2 else null,
        .kernel_rsp = stack[20],
        .int_no = int_no,
        .crash_rip = saved_rip,
    });

    // (NMI broadcast moved up — peers halted BEFORE any serial output.)

    serial.print("\n  SYSTEM HALTED.\n", .{});

    // Paint the panic screen FIRST, before the GDB stub potentially
    // blocks the CPU forever waiting for a connection. Without this
    // order, attach_on_kernel_exception=true (default) means every
    // crash hangs the screen on black until someone telnets to COM2 —
    // useless on a real machine where there's no remote dev box.
    // Stub still serves debugger sessions; user just sees the panic
    // UI while waiting.
    @import("../../ui/boot_screen.zig").disable();
    @import("../../ui/early_fb.zig").release();
    @import("../../debug/panic_screen.zig").draw(.{
        .int_no = int_no,
        .crash_rip = saved_rip,
        .cr2 = if (int_no == 14) cr2 else null,
        .error_code = error_code,
    });

    // Optionally drop into GDB stub for live inspection. Two cases:
    //   1. stub is initialized AND a GDB is already attached (gdb_connected) —
    //      enter unconditionally so the user can poke around at the crash site.
    //   2. stub is initialized AND `attach_on_kernel_exception` is set — enter
    //      so a GDB attaching for the first time lands here. User must connect.
    // Otherwise, fall through to halt loop.
    if (gdb_stub.isActive() and (gdb_stub.isConnected() or gdb_stub.attachOnKernelException())) {
        serial.print("\n[gdb] entering stub — connect GDB to COM2 (TCP :1235) and resume\n", .{});
        gdb_stub.enterStub(@ptrFromInt(rsp), @intCast(int_no));
        // If GDB resumes us we'll come back here. Fall through to halt anyway —
        // a Ring 0 exception is unrecoverable; further execution would be unsafe.
    }
    while (true) asm volatile ("hlt");
}

fn writeCrashLog(pid: u32, int_no: u64, error_code: u64, rip: u64, name: []const u8) void {
    const fat32 = @import("../../fs/fat32.zig");
    var handle = fat32.openFile("CRASHLOG") orelse fat32.createFile("CRASHLOG") orelse return;

    // Seek to end (append)
    handle.current_offset = handle.file_size;

    // Format crash info into a buffer
    var buf: [256]u8 = undefined;
    var pos: usize = 0;

    // "PID=X Exception N: Name\n"
    pos += writeStr(&buf, pos, "PID=");
    pos += writeNum(&buf, pos, pid);
    pos += writeStr(&buf, pos, " Exception ");
    pos += writeNum(&buf, pos, @as(u32, @truncate(int_no)));
    pos += writeStr(&buf, pos, ": ");
    pos += writeStr(&buf, pos, name);
    pos += writeStr(&buf, pos, "\n RIP=");
    pos += writeHex64(&buf, pos, rip);
    pos += writeStr(&buf, pos, " ERR=");
    pos += writeHex64(&buf, pos, error_code);
    if (int_no == 14) {
        pos += writeStr(&buf, pos, " CR2=");
        pos += writeHex64(&buf, pos, readCr2());
    }
    pos += writeStr(&buf, pos, "\n---\n");

    _ = fat32.writeFile(&handle, &buf, @intCast(pos));
    fat32.closeFile(handle);
}

fn writeStr(buf: []u8, pos: usize, s: []const u8) usize {
    const len = @min(s.len, buf.len - pos);
    @memcpy(buf[pos..][0..len], s[0..len]);
    return len;
}

fn writeNum(buf: []u8, pos: usize, n: u32) usize {
    if (pos >= buf.len) return 0;
    var val = n;
    var digits: [10]u8 = undefined;
    var dlen: usize = 0;
    if (val == 0) {
        buf[pos] = '0';
        return 1;
    }
    while (val > 0) {
        digits[dlen] = '0' + @as(u8, @truncate(val % 10));
        dlen += 1;
        val /= 10;
    }
    var written: usize = 0;
    while (dlen > 0 and pos + written < buf.len) {
        dlen -= 1;
        buf[pos + written] = digits[dlen];
        written += 1;
    }
    return written;
}

fn writeHex64(buf: []u8, pos: usize, n: u64) usize {
    const hex = "0123456789ABCDEF";
    var written: usize = 0;
    if (pos + 18 > buf.len) return 0;
    buf[pos] = '0';
    buf[pos + 1] = 'x';
    written = 2;
    var i: u8 = 16;
    while (i > 0) {
        i -= 1;
        buf[pos + written] = hex[@as(u4, @truncate(n >> (@as(u6, @intCast(i * 4)))))];
        written += 1;
    }
    return written;
}


// === ISR stubs (assembly) ===

// Common exception stub: push 15 GPRs, set kernel data segments, call handleException
// handleException returns for Ring 3 faults (after killing the process)
// or halts for Ring 0 faults (kernel panic)
//
// Stack on entry (after exception stub pushq $int_no / pushq $0):
//   SS, RSP, RFLAGS, CS, RIP  (pushed by CPU)
//   error_code                 (pushed by CPU or stub)
//   int_no                     (pushed by stub)
//   <-- RSP here, we push 15 GPRs below -->
//
// Layout we hand to handleException (pointed at GPR_start, *above* the FXSAVE
// block): the handler's stack[15..] indexing is unchanged. The FXSAVE block
// sits 512 bytes below the handler's view of RSP — recovered on exit via
// `fxrstor (%rsp); add $512, %rsp` before popping GPRs.
//
// Alignment math at `call handleException`:
//   CPU frame  =  5 qwords = 40 bytes
//   stub-pushed (err + intno) = 16 bytes
//   15 GPR pushes = 120 bytes
//   FXSAVE block (sub $512)  = 512 bytes
//   Total = 688 bytes ≡ 0 mod 16 — call enters callee with RSP%16==8 ✓
// 16-alignment of the FXSAVE dest at (%rsp) holds (688 ≡ 0 mod 16). If you
// EVER change the push count above without adjusting padding here, the
// runtime guard below traps it instantly.
export fn isr_common_exc() callconv(.naked) void {
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
        \\ movw $0x10, %%ax
        \\ movw %%ax, %%ds
        \\ movw %%ax, %%es
        \\ subq $512, %%rsp
        \\ fxsaveq (%%rsp)
        \\ leaq 512(%%rsp), %%rdi    // hand handler the GPR_start (skip FXSAVE)
        \\ test $0xF, %%rsp
        \\ jnz isr_common_exc_align_panic
        \\ call handleException
        \\ fxrstorq (%%rsp)
        \\ addq $512, %%rsp
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
        \\ addq $16, %%rsp
        // Pre-iretq sanity check — see sched_asm.SAFE_IRETQ for the
        // shared logic (also used by isr_irq0, retToUserStub, DynIrqStub).
        ++ @import("../../proc/sched_asm.zig").SAFE_IRETQ);
}

// Alignment-violation panic target for isr_common_exc. Reaching here means
// the push count in the exception stub got out of sync with the SysV 16-byte
// stack-alignment requirement for `call`.
pub export fn isr_common_exc_align_panic() callconv(.c) noreturn {
    @panic("isr_common_exc: RSP misaligned at call handleException — recount pushes");
}
