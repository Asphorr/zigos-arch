const std = @import("std");
const io = @import("../io.zig");
const pic = @import("../time/pic.zig");
const keyboard = @import("../driver/keyboard.zig");
const mouse = @import("../driver/mouse.zig");
const syscall = @import("syscall.zig");
const process = @import("../proc/process.zig");
const vga = @import("../ui/vga.zig");
const debug = @import("../debug/debug.zig");
const serial = @import("../debug/serial.zig");
const desktop = @import("../ui/desktop.zig");
const xhci = @import("../driver/xhci.zig");
const elf_loader = @import("../proc/elf_loader.zig");
const apic = @import("../time/apic.zig");
const symbols = @import("../debug/symbols.zig");
const signals = @import("../proc/signals.zig");
const memmap = @import("../mm/memmap.zig");

// x86_64 IDT entry: 16 bytes (128 bits)
const Entry = packed struct(u128) {
    offset_low: u16, // Bits 0..15 of handler address
    selector: u16, // Code segment selector
    ist: u3, // Interrupt Stack Table index (0 = don't switch)
    reserved0: u5, // Must be zero
    type_attr: u8, // Type and attributes (P, DPL, gate type)
    offset_mid: u16, // Bits 16..31 of handler address
    offset_high: u32, // Bits 32..63 of handler address
    reserved1: u32, // Must be zero
};

const Ptr = packed struct {
    limit: u16,
    base: u64,
};

// Layout invariants the asm trampolines and `lidt` instruction depend on.
// If any of these fail at compile time, look for accidental field reorders
// or u128 → u64 packing changes.
comptime {
    if (@sizeOf(Entry) != 16) @compileError("IDT Entry must be 16 bytes (x86_64 long mode)");
    // Ptr is packed struct with u16 + u64 = 10 bytes, but Zig may pad to 16.
    // The lidt instruction reads exactly 10 bytes (2-byte limit + 8-byte base).
    // As long as the fields are in the right order and contiguous, it works.
    // CpuState (in debug.zig) is dereferenced as `state.field` from asm-built
    // stack frames in handleException. 22 fields × 8 bytes = 176 bytes.
    if (@sizeOf(debug.CpuState) != 22 * 8)
        @compileError("debug.CpuState size must equal 22×8 bytes; asm stack layout assumes this");
}

var entries: [256]Entry = undefined;
var ptr: Ptr = undefined;

fn setGate(num: u8, handler: usize, flags: u8) void {
    setGateIst(num, handler, flags, 0);
}

/// Same as setGate but with an explicit IST (Interrupt Stack Table) index.
/// IST=0 means "don't switch stacks" (use TSS.RSP0 on privilege change, or
/// keep the current RSP on same-privilege interrupts). IST=1..7 names a
/// TSS.ISTn slot — CPU AUTOMATICALLY loads RSP from TSS.ISTn on this
/// vector, regardless of CPL transition.
///
/// Use case: IRQ handlers that may call schedule() and consume stack must
/// NOT corrupt the preempted task's kstack (netstat-desktop crash class
/// 2026-05-17 — schedule's pushfq wrote RFLAGS onto desktop's saved
/// kesp+48). Putting IRQs on IST=1 isolates them on a per-CPU stack.
///
/// Constraint: a single IST slot is shared across all vectors that use it.
/// If two vectors use the same IST and one preempts the other, the second
/// CPU push reuses the same physical address → corrupts the in-flight
/// frame. Mitigation: IRQ handlers cli-on-entry (interrupt-gate type 0x8E
/// auto-clears IF) so no nesting on the same IST happens.
fn setGateIst(num: u8, handler: usize, flags: u8, ist: u3) void {
    entries[num] = .{
        .offset_low = @as(u16, @truncate(handler & 0xFFFF)),
        .selector = 0x08,
        .ist = ist,
        .reserved0 = 0,
        .type_attr = flags,
        .offset_mid = @as(u16, @truncate((handler >> 16) & 0xFFFF)),
        .offset_high = @as(u32, @truncate((handler >> 32) & 0xFFFFFFFF)),
        .reserved1 = 0,
    };
}

// --- Comptime exception stub generation ---

const ExcInfo = struct { num: u8, has_error_code: bool };

const exceptions = [_]ExcInfo{
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

fn ExcStub(comptime info: ExcInfo) type {
    return struct {
        fn handler() callconv(.naked) void {
            asm volatile ((if (!info.has_error_code) "pushq $0\n " else "") ++
                    "pushq $" ++ std.fmt.comptimePrint("{d}", .{info.num}) ++
                    "\n jmp isr_common_exc");
        }
    };
}

pub fn init() void {
    @memset(std.mem.asBytes(&entries), 0);

    // Exception handlers (comptime-generated stubs)
    inline for (exceptions) |exc| {
        setGate(exc.num, @intFromPtr(&ExcStub(exc).handler), 0x8E);
    }

    // IRQs
    // IRQ0 (timer) + dynamic IRQs use IST=1. They feed handleIRQ0/handleDynIrq
    // which may call schedule() and consume significant stack (~1-2 KB for
    // CFS pickNext + load balance). On non-IST entry, that stack would land
    // on the preempted task's kstack and could overwrite the saved kesp+48
    // slot from a previous switchTo (netstat-desktop crash 2026-05-17 — the
    // kesp+48 watchpoint named schedule's pushfq as the writer corrupting
    // desktop's saved RA). IST=1 = per-CPU cpu.isr_stack (set up by
    // initPerCpuGdt). IRQ1/IRQ12 stay on IST=0 — they don't reschedule and
    // their handler chains are tiny.
    // IRQ0 stays on IST=0 (preempted task's kstack). IST=1 was tried
    // 2026-05-17 as a structural fix for kesp+48 corruption, but wedged
    // virtio-gpu — isr_irq0's kernel-to-kernel-ret model requires entry
    // state on the task's kstack so it survives task switches. See
    // memory/feedback_ist1_irq0_incompatible.md.
    setGateIst(32, @intFromPtr(&isr_irq0), 0x8E, 0);
    setGate(33, @intFromPtr(&isr_irq1), 0x8E);
    setGate(44, @intFromPtr(&isr_irq12), 0x8E); // Mouse

    // TLB shootdown IPI (vector 0x50). Receiver: full local TLB flush + ack.
    setGate(@import("tlb.zig").TLB_VECTOR, @intFromPtr(&isr_tlb_shootdown), 0x8E);

    // PMI (Performance Monitor Interrupt). LAPIC LVT.PMI delivers to this
    // vector when PMC0 overflows. Stub forwards saved RIP to pmu.onSample.
    setGate(@import("pmu.zig").PMI_VECTOR, @intFromPtr(&isr_pmi), 0x8E);

    // Syscall (DPL=3: callable from Ring 3)
    setGate(128, @intFromPtr(&syscall.isr_syscall), 0xEE);

    // APIC spurious interrupt (vector 0xFF) — silently ignore
    setGate(0xFF, @intFromPtr(&isr_spurious), 0x8E);

    // Dynamic IRQ slots for MSI-X-driven device drivers (vectors 0x40..0x4F).
    // Each stub is a comptime-generated naked thunk that calls handleDynIrq
    // with its own vector number — see DynIrqStub below.
    //
    // IST=0 (use preempted task's kstack, not IST1). Briefly flipped to IST=1
    // on 2026-05-17 alongside the IRQ0 fix, but that wedged virtio-gpu IRQ
    // delivery — dyn IRQ count froze at 560 after wallpaper.elf finished,
    // desktop sat in blockOn(.gpu_io) forever. Reverted to IST=0 here while
    // IRQ0 stays on IST=1 (the kesp+48 corruption class only ever hit via
    // the timer ISR path). If a dyn-IRQ handler ever needs IST=1, do it
    // per-vector after isolating the path.
    inline for (0..DYN_IRQ_COUNT) |i| {
        const v: u8 = DYN_IRQ_BASE + @as(u8, @intCast(i));
        setGateIst(v, @intFromPtr(&DynIrqStub(v).handler), 0x8E, 0);
    }

    ptr.limit = @sizeOf(@TypeOf(entries)) - 1;
    ptr.base = @intFromPtr(&entries);

    pic.init();
    asm volatile ("lidt (%[p])"
        :
        : [p] "r" (&ptr),
    );
}

/// Load the shared IDT on an AP (no PIC init, just lidt)
pub fn loadIdtForAP() void {
    asm volatile ("lidt (%[p])"
        :
        : [p] "r" (&ptr),
    );
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

// Unified exception handler — called from isr_common_exc
// Stack layout (RSP points to):
//   [0]  r15  [1]  r14  [2]  r13  [3]  r12
//   [4]  r11  [5]  r10  [6]  r9   [7]  r8
//   [8]  rdi  [9]  rsi  [10] rbp  [11] rbx
//   [12] rdx  [13] rcx  [14] rax
//   [15] int_no  [16] error_code

/// 4KB-isolated heartbeat counter. Lives in its own page so the MMU
/// write-watch (paging.installWriteWatch) catches ANY writer to the page —
/// the only legitimate writer is handleIRQ0 below. Earlier the count shared
/// a page with vga.col/row/bg, so the page-coarse watch fired on every
/// vga.print and drowned out the wild writer we're hunting.
pub var hb_state_count_page: struct {
    count: u64 = 0,
    _pad: [4088]u8 = [_]u8{0} ** 4088,
} align(4096) = .{};

// --- MMU write-watch state ---------------------------------------------------
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
    const paging_mod = @import("../mm/paging.zig");
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
    const t = @import("../debug/perf.zig").enter();
    defer @import("../debug/perf.zig").leave(.exception, t);
    asm volatile ("cli");
    // SMAP: an exception during a syscall body inherits AC=1 from the
    // syscall; clear it so kernel-mode handler code runs with SMAP
    // enforcement. IRET pops RFLAGS so AC is restored on return.
    @import("protect.zig").disallowUserAccess();

    // Sanity-check the rsp arg: a non-canonical or NULL pointer here means
    // the IRQ stub's leaq fed us garbage (e.g., TSS.RSP0 was clobbered or
    // setTssRsp0 wrote a wrong address). Print and bail before deref'ing
    // garbage and triple-faulting in the dump.
    if (rsp < 0x1000 or (rsp >= 0x0000_8000_0000_0000 and rsp < 0xFFFF_8000_0000_0000)) {
        @import("../debug/serial.zig").print("[exc] BOGUS rsp=0x{X} — skipping dump\n", .{rsp});
        while (true) asm volatile ("hlt");
    }

    // KASAN: the saved-register area + iretq frame above us must be on a
    // *live* kstack. If it's been poisoned (process exited / kstack returned
    // to pool while still in use), KASAN trips here with the writer's
    // backtrace ahead of the eventual ret-to-garbage crash.
    @import("../debug/kasan.zig").expectValid(rsp, 160);

    // CpuLocal end-canary check (task #229).
    @import("smp.zig").verifyEndCanary();

    const stack: [*]const u64 = @ptrFromInt(rsp);
    const int_no = stack[15];
    const error_code = stack[16];
    const saved_cs = stack[18];
    const saved_rip = stack[17];

    // Breadcrumb: vec in high 32, pid in low 32. Stamped before the NMI
    // fast-path return so even NMI-snapshotted CPUs leave a trace.
    {
        const pid_now: u64 = if (@import("smp.zig").myCpu().current_pid) |p| @intCast(p) else 0xFF;
        @import("../debug/breadcrumb.zig").stamp(.exception_entry, (int_no << 32) | pid_now);
    }

    // NMI snapshot fast-path (task #247). When debug.kdbg.broadcastNMI()
    // sets nmi_snapshot_mode, every other CPU receives an NMI. We dump
    // a one-line state digest and IRET back. This is the ONLY way to
    // observe a CPU that's stuck with IF=0 (kernel critical section,
    // hlt loop, infinite loop without IRQs) — used for "OS frozen but
    // no panic" debugging.
    if (int_no == 2) {
        @import("../debug/kdbg.zig").nmiSnapshot(rsp, saved_rip, saved_cs);
        return;
    }

    // Machine Check (vector 18). Walk MC banks, log + clear; resume on
    // recoverable status, panic only when PCC (processor-context-corrupt)
    // is set. Without this dispatch the generic exception path treats
    // every #MC as a panic, losing the per-bank decode.
    if (int_no == 18) {
        const outcome = @import("mce.zig").handle();
        if (outcome == .recovered) return;
        // Fatal — fall through to the standard panic dump below.
        serial.print("[mce] FATAL: PCC set on at least one bank — kernel state corrupt\n", .{});
    }

    // Wild-RIP hunt (task #224). Same idea as handleIRQ0: validate the saved
    // RIP just before iretq returns to user mode. Exception frame has RIP at
    // index 17 (vs 15 for IRQs) because the ISR stub pushed int_no and
    // error_code onto the kernel stack first.
    defer @import("../debug/kdbg.zig").validateUserReturnIretq(stack, 17, 18);

    // iretq-frame tripwire (task #230) — exception version. RIP slot at 17
    // (after int_no + error_code pushes). See handleIRQ0 for design notes.
    @import("../debug/iretq_canary.zig").capture(stack, 17);
    defer @import("../debug/iretq_canary.zig").invalidate();

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
        if (@import("../debug/watch.zig").onDebugException(rsp, saved_rip)) {
            return;
        }
        const dr6 = @import("../debug/watch.zig").readDr6();
        if ((dr6 & (1 << 14)) != 0 and ww_pending_reprotect_page != 0) {
            @import("../mm/paging.zig").setWriteWatchRW(@intCast(ww_pending_reprotect_page), false);
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
        const cr2 = asm volatile ("movq %%cr2, %[ret]"
            : [ret] "=r" (-> u64),
        );
        const w_bit = (error_code >> 1) & 1;
        const u_bit = (error_code >> 2) & 1;
        if (w_bit != 0 and u_bit == 0) {
            for (ww_entries) |e| {
                if (e.page == 0) continue;
                if (cr2 < e.page or cr2 >= e.page + 0x1000) continue;
                // Hit watched page e
                const sym_mod = @import("../debug/symbols.zig");
                const is_legit = blk: {
                    const r = sym_mod.resolveKernel(saved_rip) orelse break :blk false;
                    if (!std.mem.eql(u8, r.name, e.whitelist_sym)) break :blk false;
                    if (r.offset > e.max_offset) break :blk false;
                    break :blk true;
                };
                if (is_legit) {
                    @import("../mm/paging.zig").setWriteWatchRW(@intCast(e.page), true);
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
                const saved_rbp = stack[10];
                if (saved_rbp >= 0x100000 and saved_rbp < 0x4000000) {
                    serial.print("  Backtrace:\n", .{});
                    var rbp: usize = @intCast(saved_rbp);
                    var depth: u32 = 0;
                    while (rbp >= 0x100000 and rbp < 0x4000000 and depth < 16) : (depth += 1) {
                        const frame: [*]const usize = @ptrFromInt(rbp);
                        const ret_addr: u64 = @intCast(frame[1]);
                        if (ret_addr == 0) break;
                        serial.print("    [{d}] 0x{X:0>16}", .{ depth, ret_addr });
                        if (sym_mod.resolveKernel(ret_addr)) |r| {
                            serial.print("  {s}+0x{X}", .{ r.name, r.offset });
                        }
                        serial.print("\n", .{});
                        const next_rbp: usize = @intCast(frame[0]);
                        if (next_rbp <= rbp) break;
                        rbp = next_rbp;
                    }
                }
                // Disarm all watches so panic's own writes don't recurse.
                for (&ww_entries) |*entry| {
                    if (entry.page != 0) @import("../mm/paging.zig").setWriteWatchRW(@intCast(entry.page), true);
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
            @import("../debug/serial.zig").print("[exc-entry] vec={d} pid={d} cs=0x{X} rip=0x{X}\n", .{ int_no, cur_pid_for_trace, saved_cs, saved_rip });
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
            const cr2 = asm volatile ("movq %%cr2, %[ret]"
                : [ret] "=r" (-> u64),
            );
            @import("../debug/serial.zig").print("[exc] vec={d} err=0x{X} rip=0x{X} cs=0x{X} cr2=0x{X}\n", .{ int_no, error_code, saved_rip, saved_cs, cr2 });
        }
    }


    const name = if (int_no < exception_names.len)
        exception_names[int_no]
    else
        "Unknown";

    // GDB stub intercept: exceptions 1 (debug) and 3 (breakpoint)
    const gdb_stub = @import("../debug/gdb_stub.zig");
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
            const cr2 = asm volatile ("movq %%cr2, %[ret]"
                : [ret] "=r" (-> u64),
            );
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
                if (signals.deliverFromExcFrame(pcb, exc_frame, sig)) {
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
            const cr2 = asm volatile ("movq %%cr2, %[ret]"
                : [ret] "=r" (-> u64),
            );
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
            const cr2 = asm volatile ("movq %%cr2, %[ret]"
                : [ret] "=r" (-> u64),
            );
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
            if (!@import("../mm/paging.zig").isMapped(saved_rip)) {
                serial.print("  Code:  <RIP page not mapped — likely instruction-fetch #PF>\n", .{});
            } else {
                const rip_page_end = (saved_rip & ~@as(u64, 0xFFF)) + 0x1000;
                const safe_len: u64 = @min(16, rip_page_end - saved_rip);
                const code: [*]const u8 = @ptrFromInt(saved_rip);
                // User RIP is below the kernel half — bracket the read with
                // STAC/CLAC so SMAP doesn't double-fault us here.
                const is_user_rip = saved_rip < 0xFFFF800000000000;
                const protect_mod = @import("protect.zig");
                if (is_user_rip) protect_mod.allowUserAccess();
                serial.print("  Code:", .{});
                for (0..@intCast(safe_len)) |i| serial.print(" {X:0>2}", .{code[i]});
                serial.print("\n", .{});
                // Decode the faulting instruction so the user doesn't have to
                // pull up objdump just to figure out what we hit.
                serial.print("  Insn: ", .{});
                @import("../debug/disasm.zig").printOne(code[0..@intCast(safe_len)]);
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
            const protect_bt = @import("protect.zig");
            protect_bt.allowUserAccess();
            var rbp: usize = @intCast(saved_rbp);
            var depth: u32 = 0;
            while (rbp >= 0x100000 and rbp < 0x600000 and depth < 16) : (depth += 1) {
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
        if (bt_frames < 2 and saved_rsp >= 0x100000 and saved_rsp < 0x600000) {
            serial.print("  Stack scan candidates:\n", .{});
            const stack_page_end = (saved_rsp & ~@as(u64, 0xFFF)) + 0x1000;
            const sp: [*]const u64 = @ptrFromInt(saved_rsp);
            const max_words: u64 = @min(64, (stack_page_end - saved_rsp) / 8);
            const protect_ss = @import("protect.zig");
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
            const cr2 = asm volatile ("movq %%cr2, %[ret]"
                : [ret] "=r" (-> u64),
            );
            const cur_pd = if (process.currentPCB()) |pcb| pcb.page_dir_phys else 0;
            @import("../debug/kdbg.zig").walkUserPT(cur_pd, cr2);
            // Hex dump of the bytes around RSP — most useful when the RBP
            // walk is short (e.g. memcpy clobbered RBP via prologue or the
            // crash is in -fomit-frame-pointer code). 64 bytes covers the
            // typical "saved args + return slot" window of a small frame.
            if (saved_rsp >= 0x100000 and saved_rsp < 0x600000) {
                serial.print("  Stack hex (64B from RSP):\n", .{});
                const stack_page_end = (saved_rsp & ~@as(u64, 0xFFF)) + 0x1000;
                const sp: [*]const u8 = @ptrFromInt(saved_rsp);
                const dump_bytes: u64 = @min(64, stack_page_end - saved_rsp);
                const protect_sh = @import("protect.zig");
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
                @import("../debug/kdbg.zig").findFrame(cr2 & ~@as(u64, 0xFFF));
            }
        }
        // Always dump the rings on a Ring-3 crash — small (≈5 KB) and
        // routinely the difference between "I have no idea" and "obvious".
        @import("../debug/kdbg.zig").dumpAll();

        // Last 8 syscalls the dying PID made. Frequently the smoking
        // gun for "app crashed for no obvious reason" — often it was
        // mid-sysCreateWindow, mid-fread, etc.
        process.dumpSyscallRing(@intCast(pid));

        // Write crash to FAT32 crashlog (only if FAT32 is ready)
        const fat32 = @import("../fs/fat32.zig");
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
    @import("../debug/kdbg.zig").enterCritical();

    // Halt peer CPUs BEFORE we print anything. Otherwise the exception
    // banner / register dump / backtrace below byte-interleave with
    // whatever the peers were klog'ing (slow-sc, perf, heartbeats). Each
    // peer still emits its own [nmi-snap cpuN] line before halting, so
    // we don't lose the cross-CPU snapshot.
    @import("../debug/kdbg.zig").nmi_halt_after_snapshot = true;
    @import("../debug/kdbg.zig").broadcastNMI();

    serial.print("\n!!! EXCEPTION {d}: {s} !!!\n", .{ int_no, name });
    serial.print("  RIP={X:0>16} CS={X:0>4} ERR={X:0>16}\n", .{ saved_rip, saved_cs, error_code });
    serial.print("  RSP={X:0>16} SS={X:0>4} RFLAGS={X:0>16}\n", .{ stack[20], stack[21], stack[19] });

    // Control registers (read early for crash classifier)
    const cr2 = asm volatile ("movq %%cr2, %[ret]"
        : [ret] "=r" (-> u64),
    );
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

        // Kstack-protect smoking gun: kernel-mode write #PF on a present
        // page that belongs to a PROTECTED_PIDS kstack. CR2 = the exact
        // byte the wild writer aimed at; saved_rip = the writer's
        // instruction. Logged BEFORE the rest of the autopsy so it lands
        // even if a follow-up step itself faults.
        if ((error_code & 4) == 0 and (error_code & 2) != 0 and (error_code & 1) != 0) {
            if (@import("../debug/kstack_protect.zig").faultBelongsToProtectedKstack(@intCast(cr2))) |victim| {
                const writer_pid: ?usize = if (@import("smp.zig").myCpu().current_pid) |p| p else null;
                @import("../debug/kstack_protect.zig").dumpFault(
                    victim,
                    @intCast(cr2),
                    @intCast(saved_rip),
                    writer_pid,
                );
                // Auto-unprotect so the panic path / autopsy chain doesn't
                // double-fault on the same RO page. We already have the
                // smoking gun (writer's RIP + CR2 + writer pid).
                @import("../debug/kstack_protect.zig").unprotectPidIfProtected(@as(usize, victim));
            }
        }
        // SMAP-violation classifier — supervisor #PF on a present page in
        // user-VA range almost certainly means kernel touched user memory
        // without STAC (i.e. outside an active syscall validateUserPtr
        // bracket). Names the bug class so we don't have to puzzle over
        // "kernel-mode #PF on a present page".
        const protect = @import("protect.zig");
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

    // Stack backtrace with symbol resolution (follow RBP chain)
    serial.print("  Backtrace:\n", .{});
    // Resolve crash RIP
    if (symbols.resolveKernel(saved_rip)) |r| {
        serial.print("  Crash in: {s}+0x{X}\n", .{ r.name, r.offset });
    }
    var rbp: usize = @intCast(stack[10]); // saved RBP
    var depth: u32 = 0;
    while (rbp > 0x100000 and rbp < 0x4000000 and depth < 10) : (depth += 1) {
        const frame: [*]const usize = @ptrFromInt(rbp);
        const ret_addr: u64 = @intCast(frame[1]);
        if (symbols.resolveKernel(ret_addr)) |r| {
            serial.print("    [{d}] {s}+0x{X} (0x{X:0>16})\n", .{ depth, r.name, r.offset, ret_addr });
        } else {
            serial.print("    [{d}] 0x{X:0>16}\n", .{ depth, ret_addr });
        }
        rbp = frame[0];
    }

    // Full kdbg autopsy: cross-CPU snapshot, all-PCB state, ring dumps,
    // hex dump near the kernel RSP, optional PT walk for #PF. Newly added
    // to the Ring-0 path (used to be Ring-3 only) — without this the
    // recent iretq=0x{8410,7410} #GP gave us no usable diagnostic data.
    @import("../debug/kdbg.zig").crashAutopsy(.{
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
    @import("../ui/boot_screen.zig").disable();
    @import("../ui/early_fb.zig").release();
    @import("../debug/panic_screen.zig").draw(.{
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
    const fat32 = @import("../fs/fat32.zig");
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
        const cr2 = asm volatile ("movq %%cr2, %[ret]"
            : [ret] "=r" (-> usize),
        );
        pos += writeStr(&buf, pos, " CR2=");
        pos += writeHex64(&buf, pos, cr2);
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

// --- IRQ handlers ---

/// Timer IRQ — preemptive scheduler + periodic desktop resume.
/// Stack layout for IRQ0 (no error code / int_no pushed):
///   RSP points to 15 GPRs: r15,r14,r13,r12,r11,r10,r9,r8,rdi,rsi,rbp,rbx,rdx,rcx,rax
///   Then CPU-pushed: RIP, CS, RFLAGS, RSP, SS
///   CS is at stack[16] (index 15 for last GPR + 0=rip, 1=cs => stack[15+1]=stack[16])
///   Wait: 15 GPRs at [0]..[14], then [15]=RIP, [16]=CS
/// Software-bisect helper for the iretq-frame corruption hunt (task #224).
/// Compares CS+SS against the IRQ-entry snapshot. If they match, returns
/// silently — zero log noise on the happy path. If they don't, prints
/// `[bisect] CORRUPTED AT: <label>` and falls through to iretqValidate's
/// full diagnostic+panic. Callers sprinkle these between sub-routines in
/// handleIRQ0 — the first label printed names the sub-routine that wrote
/// to the iretq frame between the previous checkpoint and this one.
inline fn bisectPoint(comptime label: []const u8, frame: [*]const u64, snap: @import("../debug/kdbg.zig").IretqSnap) void {
    if (frame[16] == snap.cs and frame[19] == snap.ss) return;
    @import("../debug/serial.zig").print("[bisect] CORRUPTED AT: {s}\n", .{label});
    @import("../debug/kdbg.zig").iretqValidate(frame, snap);
}

export fn handleIRQ0(rsp: u64) callconv(.c) void {
    // SMAP: timer IRQ during a syscall body inherits AC=1; clear it so the
    // scheduler / schedulable kernel work runs with SMAP enforcement. IRET
    // pops RFLAGS so AC is restored on return.
    @import("protect.zig").disallowUserAccess();

    // KASAN: same invariant as handleException — the saved-state region
    // must be on a live kstack. If we entered IRQ0 on a kstack whose owner
    // already exited, the body has been poisoned by markPcbDead and we trip
    // here with backtrace pointing at handleIRQ0's caller.
    @import("../debug/kasan.zig").expectValid(rsp, 160);

    // Tier B.3: stack-alias live detector. Verifies our IRQ-entry RSP is
    // inside cpu.current_pid's expected kstack slot. Catches the cross-
    // stack aliasing state (e.g. cat running with RSP in idle1's slot)
    // BEFORE it propagates downstream into a switchTo save.
    @import("../debug/stack_alias.zig").checkOwnRsp(rsp);

    // CpuLocal end-canary check (task #229). Any wild write that landed
    // anywhere past the live CpuLocal fields should have clobbered
    // magic_end, and we trap with the writer's call path still live.
    @import("smp.zig").verifyEndCanary();

    // Snapshot iretq frame's CS/SS/RIP IMMEDIATELY (before perf, before
    // smp.myCpu(), before anything else). The snap is a STACK-LOCAL —
    // tasks migrate between CPUs across schedule(), so a per-CPU global
    // would compare against the wrong IRQ when the task wakes up on a
    // different CPU. Stack-local travels with the task.
    const frame_for_validate: [*]const u64 = @ptrFromInt(rsp);
    const irq_snap = @import("../debug/kdbg.zig").iretqSnapshot(frame_for_validate);
    defer @import("../debug/kdbg.zig").iretqValidate(frame_for_validate, irq_snap);

    // Wild-RIP hunt (task #224). Validate the saved RIP is in the user VA
    // range whenever we're about to iretq back to user mode. If something
    // wrote 0x80000C (or any non-user value) into frame[15] during this IRQ,
    // we panic HERE with the kernel stack still loaded — instead of letting
    // the bad RIP cause a #GP after iretq, by which point the kernel call
    // path that wrote it is gone.
    defer @import("../debug/kdbg.zig").validateUserReturnIretq(frame_for_validate, 15, 16);

    // iretq-frame tripwire (task #230). Snapshot the iretq frame into the
    // current PCB so any kernel function calling
    // `iretq_canary.check(@src())` can detect mid-handler corruption with
    // the offending fn name. capture() also arms DR0 on the iretq RIP
    // slot (write-only, panic_dump) so the writer's instruction is caught
    // SYNCHRONOUSLY via #DB. invalidate() disarms DR0 and clears the
    // snapshot just before the iretq instruction.
    @import("../debug/iretq_canary.zig").capture(frame_for_validate, 15);
    defer @import("../debug/iretq_canary.zig").invalidate();

    // Software snap+validate for the `call handleIRQ0` saved-return-address
    // slot (different from the iretq frame at top of kstack — see task #224).
    // Read the slot's value at entry, compare at exit. If corruption hits,
    // panic with full diagnostic. Catches WHEN corruption happens; doesn't
    // identify the writer's RIP (use GDB hw watchpoint for that).
    const ret_addr_snap = @import("../debug/kdbg.zig").snapshotHandleIRQ0RetAddr(rsp);
    defer @import("../debug/kdbg.zig").validateHandleIRQ0RetAddr(rsp, ret_addr_snap);

    const t = @import("../debug/perf.zig").enter();
    defer @import("../debug/perf.zig").leave(.irq0_timer, t);
    const smp = @import("smp.zig");
    const cpu = smp.myCpu();

    bisectPoint("entry", frame_for_validate, irq_snap);

    // Record this IRQ entry into the kdbg ring so post-mortem (if we DON'T
    // catch corruption via the validate above) shows what was running on
    // each CPU at each tick.
    {
        const pid_now: u8 = if (cpu.current_pid) |p| @intCast(p) else 0xFF;
        @import("../debug/kdbg.zig").irqEvent(0, pid_now, frame_for_validate[15], @truncate(frame_for_validate[16]));
        // Breadcrumb: stamp BEFORE invariant scan so if the scan panics
        // the autopsy reflects we were in the IRQ0 path on this CPU.
        @import("../debug/breadcrumb.zig").stamp(.irq0_timer, pid_now);
    }
    // PCB invariant scanner — every SCAN_PERIOD_TICKS (~1s). Cheap noop
    // on non-trigger ticks; on a trigger tick walks all alive PCBs and
    // panics on the first violation with the offending pid/field named.
    // Catches cross-stack-aliasing / kesp-clobber / kstack_top mismatch
    // shortly after they happen instead of after they manifest downstream.
    @import("../debug/pcb_invariants.zig").maybeScan();
    // Per-tick kstack saved-RIP mirror-flip monitor (see kstack_protect.zig).
    // Runs on EVERY CPU's IRQ0, not just BSP — the netstat hunt found that
    // the victim is typically on cpu1 (shell) while BSP runs desktop, so a
    // BSP-only check never sees pid=3 in a parked state. Per-pid flip_logged
    // dedup makes concurrent fires from BSP+AP harmless (worst case one
    // extra log line). Narrows the writer window to ~10 ms.
    @import("../debug/kstack_protect.zig").tickMonitor();
    // (Per-save kstack protection auto-arm removed — wedges silently when
    // the protect fires inside switchTo. Function kept in kstack_protect
    // for manual experimentation. See save_trace.zig for context.)
    // Cross-CPU aliasing scan — runs every 100 ticks (~1s) on BSP only.
    // (cheaper than per-CPU, since the state it checks is global). Catches
    // current_pid / idle_pid / tss.rsp0 collisions that would otherwise
    // show up as wild-RIP dispatches seconds later.
    // Was every tick during the 2026-05-17 netstat hunt; restored to 100
    // after IST=1 structural fix landed so compositor isn't starved.
    if (smp.isBSP() and (process.tick_count % 100) == 0) {
        @import("../debug/cpu_alias.zig").scan();
    }
    bisectPoint("after irqEvent", frame_for_validate, irq_snap);

    // Sync this CPU's DR0-DR3+DR7 from the watch manager's canonical state.
    // Cheap (5 mov-to-DRn) and gives us "global" semantics without a
    // dedicated IPI vector: arm/disarm on any CPU, every other CPU picks
    // it up within one timer tick (~10ms).
    @import("../debug/watch.zig").applyLocal();
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
            @import("../debug/serial.zig").print("[hb] cpu0 irq#{d} tick={d}\n", .{ hb_state_count_page.count, process.tick_count });
        }
        // SMI / stall detector: BSP-only because APs IRQ0 is irregular
        // (hlt suppression). Samples PM_TMR once per real (non-soft-yield)
        // BSP timer tick; logs windows >15 ms.
        @import("../time/smi.zig").tick();
    }

    // Per-CPU tick — counted on EVERY IRQ0 (including soft yields) so the
    // watchdog peer-check sees forward progress regardless of cause. Bumped
    // BEFORE the peer check so a CPU that's only running soft yields still
    // shows up alive. cli is held throughout handleIRQ0 so a plain += is
    // safe; peer reads use volatile.
    cpu.irq_tick_count +%= 1;
    // Charge this tick as "idle" if the CPU was running its kernel idle PCB
    // at the moment of the IRQ. The /proc/cpustat consumer subtracts idle
    // from total to get utilization. Done under the same cli as irq_tick,
    // so a reader on another CPU never sees idle > irq.
    if (cpu.current_pid) |pid| {
        if (pid < process.procs.len and process.procs[pid].is_idle) {
            cpu.idle_tick_count +%= 1;
        }
    }
    @import("../debug/watchdog.zig").peerCheck(cpu);

    // Per-CPU execution trail — record where this CPU was interrupted.
    // Dumped from panic / watchdog autopsy so we can see recent execution
    // history even when stack walking is impossible (corrupt rbp, leaf
    // function freeze, NMI-handler-never-returned). saved_rip is at
    // stack[15] (15 GPRs pushed before RIP). 128-entry per-CPU ring,
    // ~1.3s of history at 100 Hz.
    @import("../debug/exectrail.zig").recordIrq(frame_for_validate[15]);

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
        process.tick_count += 1;
        bisectPoint("after tick++", frame_for_validate, irq_snap);
        process.wakeExpired();
        bisectPoint("after wakeExpired", frame_for_validate, irq_snap);
        process.deliverDueAlarms();
        bisectPoint("after deliverDueAlarms", frame_for_validate, irq_snap);
        xhci.pollHID();
        bisectPoint("after pollHID", frame_for_validate, irq_snap);
        @import("../driver/sound.zig").tick();
        bisectPoint("after sound.tick", frame_for_validate, irq_snap);
        @import("../debug/gdb_stub.zig").checkForBreak();
        bisectPoint("after gdb checkForBreak", frame_for_validate, irq_snap);
        // Auto-dump perf counters every ~5 seconds (500 ticks at 100Hz). The
        // counters survive the dump (no implicit reset) so the next dump shows
        // accumulated cost since boot. Use `perf reset` from the CLI to zero.
        if (process.tick_count % 500 == 0 and process.tick_count > 0) {
            @import("../debug/perf.zig").dumpAll();
        }

        // Tier C.1: rotate DR0-DR3 across procs[].kernel_esp slots so any
        // wild writer (cross-CPU stack-aliasing source) trips with full RIP.
        // BSP-only update of canonical entries[]; APs pick up via lazy
        // applyLocal at their next IRQ entry. Cadence chosen to avoid
        // IPI-flood heisendetector — see watch.rotateKernelEspWatches docs.
        const watch_mod = @import("../debug/watch.zig");
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
fn deliverPendingToReturnFrame(cpu: *@import("smp.zig").CpuLocal, new_rsp: u64) void {
    const cur_pid = cpu.current_pid orelse return;
    const pcb = process.getPCB(cur_pid);
    if ((pcb.pending_signals & ~pcb.signal_mask) == 0) return;
    if (pcb.in_signal_handler) return;
    const frame: *signals.IrqFrame = @ptrFromInt(new_rsp);
    if ((frame.cs & 3) == 0) return; // returning to kernel — no handler call
    signals.deliverFromIrqFrame(pcb, frame);
}

/// Re-arm LAPIC for the right deadline based on what's about to run.
/// APs running idle sleep ~10x longer (≈100ms) — no useful work to wake for.
/// Everyone else gets one quantum (≈10ms).
fn rearmTimerForCurrent(cpu: *@import("smp.zig").CpuLocal) void {
    const quantum = apic.timerQuantum();
    const is_ap_idle = cpu.cpu_id != 0 and blk: {
        const cur = cpu.current_pid orelse break :blk false;
        break :blk process.procs[cur].is_idle;
    };
    apic.armOneShot(if (is_ap_idle) quantum *| 10 else quantum);
}

export fn handleIRQ1() callconv(.c) void {
    @import("protect.zig").disallowUserAccess();
    const t = @import("../debug/perf.zig").enter();
    defer @import("../debug/perf.zig").leave(.irq1_kbd, t);
    const scancode = io.inb(0x60);
    keyboard.handleScancode(scancode);
    sendEOI();
}

export fn handleIRQ12() callconv(.c) void {
    @import("protect.zig").disallowUserAccess();
    const t = @import("../debug/perf.zig").enter();
    defer @import("../debug/perf.zig").leave(.irq12_mouse, t);
    mouse.handleIRQ();
    if (!apic.apic_active) {
        io.outb(0xA0, 0x20); // Slave PIC EOI (only needed for legacy PIC)
    }
    sendEOI();
}

fn sendEOI() void {
    if (apic.apic_active) {
        apic.eoi();
    } else {
        io.outb(0x20, 0x20);
    }
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
        ++ @import("../proc/sched_asm.zig").SAFE_IRETQ);
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
// KASAN frame canary: a magic word (0x7B0FF1CE) is pushed BEFORE the GPRs
// at IRQ entry and verified BEFORE iretq on exit. If a wild writer
// scribbles within ~528 bytes of the iretq frame between entry and exit,
// the canary slot is overwritten and isr_irq0_canary_panic fires with
// kdbg autopsy. The 8B canary push forces an 8B alignment compensation
// in the FXSAVE scratch (520 instead of 512) to keep `call handleIRQ0`
// 16-byte aligned per SysV ABI.
//
// Alignment math at `call handleIRQ0`:
//   CPU frame = 40 bytes, 15 GPRs = 120 bytes, FXSAVE = 512 bytes → 672B ≡ 0 ✓
fn isr_irq0() callconv(.naked) void {
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
        \\ pushq $0x7B0FF1CE         // KASAN canary, sits BELOW the 15 GPRs so iretq-frame indices in iretqValidate stay unchanged
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
        \\ cmpq $0x7B0FF1CE, (%%rsp) // canary must be intact
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
        ++ @import("../proc/sched_asm.zig").SAFE_IRETQ);
}

// Keyboard IRQ stub — push caller-saved regs, call handler, pop, iretq.
// No context switch happens here, so the simple `fxrstor (%rsp); add $512`
// pattern restores FP state and frees the block before popping GPRs.
//
// Alignment math at `call handleIRQ1`:
//   CPU frame = 40, 9 GPRs = 72, FXSAVE = 512 → 624B ≡ 0 mod 16 ✓
fn isr_irq1() callconv(.naked) void {
    asm volatile (
        \\ pushq %%rax
        \\ pushq %%rcx
        \\ pushq %%rdx
        \\ pushq %%rdi
        \\ pushq %%rsi
        \\ pushq %%r8
        \\ pushq %%r9
        \\ pushq %%r10
        \\ pushq %%r11
        \\ subq $512, %%rsp
        \\ fxsaveq (%%rsp)
        \\ test $0xF, %%rsp
        \\ jnz isr_irq1_align_panic
        \\ call handleIRQ1
        \\ fxrstorq (%%rsp)
        \\ addq $512, %%rsp
        \\ popq %%r11
        \\ popq %%r10
        \\ popq %%r9
        \\ popq %%r8
        \\ popq %%rsi
        \\ popq %%rdi
        \\ popq %%rdx
        \\ popq %%rcx
        \\ popq %%rax
        \\ iretq
    );
}

// Mouse IRQ stub — same pattern as keyboard.
// Alignment math: 40 + 72 + 512 = 624B ≡ 0 mod 16 ✓
fn isr_irq12() callconv(.naked) void {
    asm volatile (
        \\ pushq %%rax
        \\ pushq %%rcx
        \\ pushq %%rdx
        \\ pushq %%rdi
        \\ pushq %%rsi
        \\ pushq %%r8
        \\ pushq %%r9
        \\ pushq %%r10
        \\ pushq %%r11
        \\ subq $512, %%rsp
        \\ fxsaveq (%%rsp)
        \\ test $0xF, %%rsp
        \\ jnz isr_irq12_align_panic
        \\ call handleIRQ12
        \\ fxrstorq (%%rsp)
        \\ addq $512, %%rsp
        \\ popq %%r11
        \\ popq %%r10
        \\ popq %%r9
        \\ popq %%r8
        \\ popq %%rsi
        \\ popq %%rdi
        \\ popq %%rdx
        \\ popq %%rcx
        \\ popq %%rax
        \\ iretq
    );
}

fn isr_spurious() callconv(.naked) void {
    asm volatile ("iretq"); // No EOI for spurious interrupts
}

// TLB-shootdown IPI stub (vector 0x50). Same caller-saved pattern as
// isr_irq1; handler just does cr3 reload + ack decrement + eoi, so a full
// fxsave isn't strictly required, but the alignment math is easier if we
// match the IRQ stubs' shape. Alignment: 40 + 72 + 512 = 624B ≡ 0 mod 16 ✓
fn isr_tlb_shootdown() callconv(.naked) void {
    asm volatile (
        \\ pushq %%rax
        \\ pushq %%rcx
        \\ pushq %%rdx
        \\ pushq %%rdi
        \\ pushq %%rsi
        \\ pushq %%r8
        \\ pushq %%r9
        \\ pushq %%r10
        \\ pushq %%r11
        \\ subq $512, %%rsp
        \\ fxsaveq (%%rsp)
        \\ test $0xF, %%rsp
        \\ jnz isr_tlb_shootdown_align_panic
        \\ call handleTlbShootdown
        \\ fxrstorq (%%rsp)
        \\ addq $512, %%rsp
        \\ popq %%r11
        \\ popq %%r10
        \\ popq %%r9
        \\ popq %%r8
        \\ popq %%rsi
        \\ popq %%rdi
        \\ popq %%rdx
        \\ popq %%rcx
        \\ popq %%rax
        \\ iretq
    );
}

pub export fn isr_tlb_shootdown_align_panic() callconv(.c) noreturn {
    @panic("isr_tlb_shootdown: RSP misaligned at call handleTlbShootdown");
}

// PMI (Performance Monitoring Interrupt) stub — vector 0xFE. LAPIC's
// LVT.PMI delivers here when PMC0 overflows. Same caller-saved + fxsave
// shape as isr_tlb_shootdown. Reads the saved RIP off the iretq frame
// to hand to pmu.onSample for one-line "where did the sample land" log
// output. Alignment: 8 (RIP arg) + 40 (5 pushes after rsp align test)
// + ... — we just compute RIP from the frame and call.
fn isr_pmi() callconv(.naked) void {
    asm volatile (
        \\ pushq %%rax
        \\ pushq %%rcx
        \\ pushq %%rdx
        \\ pushq %%rdi
        \\ pushq %%rsi
        \\ pushq %%r8
        \\ pushq %%r9
        \\ pushq %%r10
        \\ pushq %%r11
        \\ subq $512, %%rsp
        \\ fxsaveq (%%rsp)
        \\ test $0xF, %%rsp
        \\ jnz isr_pmi_align_panic
        \\ movq 584(%%rsp), %%rdi
        \\ call handlePmi
        \\ fxrstorq (%%rsp)
        \\ addq $512, %%rsp
        \\ popq %%r11
        \\ popq %%r10
        \\ popq %%r9
        \\ popq %%r8
        \\ popq %%rsi
        \\ popq %%rdi
        \\ popq %%rdx
        \\ popq %%rcx
        \\ popq %%rax
        \\ iretq
    );
}

pub export fn isr_pmi_align_panic() callconv(.c) noreturn {
    @panic("isr_pmi: RSP misaligned at call handlePmi");
}

export fn handlePmi(rip: u64) callconv(.c) void {
    @import("pmu.zig").onSample(rip);
}

// --- Dynamic IRQ vectors (MSI-X) ---------------------------------------------
// 16 reusable vectors above the legacy IRQ block. Drivers call
// `idt.registerIrq(vec, handler)` after parking a free vector via
// `idt.allocDynVector()`. The naked stub mirrors the keyboard/mouse pattern
// (9 caller-saved GPRs + FXSAVE) and passes the static vector number to
// handleDynIrq, which dispatches to the registered Zig handler and writes
// LAPIC EOI.

pub const DYN_IRQ_BASE: u8 = 0x40;
pub const DYN_IRQ_COUNT: u8 = 16;

pub const DynHandler = *const fn () callconv(.c) void;
var dyn_handlers: [DYN_IRQ_COUNT]?DynHandler = .{null} ** DYN_IRQ_COUNT;

/// Reserve a free dynamic IRQ vector. Returns null if all 16 slots are in
/// use. Caller must `registerIrq(vec, handler)` immediately to install the
/// dispatch target — the slot is "taken" once the handler is non-null.
pub fn allocDynVector() ?u8 {
    for (&dyn_handlers, 0..) |*slot, i| {
        if (slot.* == null) return DYN_IRQ_BASE + @as(u8, @intCast(i));
    }
    return null;
}

/// Bind a Zig handler to a previously-allocated dynamic vector. Subsequent
/// MSI-X messages for that vector arrive at the handler with interrupts
/// disabled; LAPIC EOI is issued automatically after the handler returns.
pub fn registerIrq(vec: u8, handler: DynHandler) void {
    if (vec < DYN_IRQ_BASE or vec >= DYN_IRQ_BASE + DYN_IRQ_COUNT) return;
    dyn_handlers[vec - DYN_IRQ_BASE] = handler;
}

export fn handleDynIrq(vec: u32) callconv(.c) void {
    @import("protect.zig").disallowUserAccess();
    const t = @import("../debug/perf.zig").enter();
    defer @import("../debug/perf.zig").leave(.dynirq, t);
    // Breadcrumb: (vec << 16) | pid. cpu.current_pid read once.
    {
        const pid_now: u64 = if (@import("smp.zig").myCpu().current_pid) |p| @intCast(p) else 0xFF;
        @import("../debug/breadcrumb.zig").stamp(.irq_dynamic, (@as(u64, vec) << 16) | pid_now);
    }
    const idx: usize = @intCast(vec - DYN_IRQ_BASE);
    if (idx < DYN_IRQ_COUNT) {
        if (dyn_handlers[idx]) |h| h();
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
    const smp_mod = @import("smp.zig");
    const cpu = smp_mod.myCpu();
    if (cpu.dynirq_preempt_pending) {
        cpu.dynirq_preempt_pending = false;
        @import("../proc/process.zig").schedule();
    }
}

// Per-vector naked stub. Each instantiation hardcodes its own vector # into
// the `mov $N, %edi` immediately before `call handleDynIrq` — that's how
// the dispatcher knows which IRQ fired without scanning ISR bits.
//
// Alignment math at `call handleDynIrq`:
//   CPU frame = 40 bytes, 9 GPRs = 72 bytes, FXSAVE = 512 bytes → 624B ≡ 0 mod 16 ✓
fn DynIrqStub(comptime vec: u8) type {
    const vec_str = std.fmt.comptimePrint("{d}", .{vec});
    return struct {
        fn handler() callconv(.naked) void {
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
                    "movl $" ++ vec_str ++ ", %%edi\n" ++
                    // Stack canary around `call handleDynIrq` (task #233).
                    // Push 16B (canary + pad) so RSP stays 16-aligned across
                    // the call. Verify on return — if the canary slot is
                    // clobbered, the IRQ handler (or anything it called)
                    // smashed our stack frame in this exact window.
                    "subq $16, %%rsp\n" ++
                    "movabsq $0xC0FFEE0BA0BEDA0, %%rax\n" ++
                    "movq %%rax, 8(%%rsp)\n" ++
                    "test $0xF, %%rsp\n" ++
                    "jnz isr_dynirq_align_panic\n" ++
                    "call handleDynIrq\n" ++
                    "movabsq $0xC0FFEE0BA0BEDA0, %%rax\n" ++
                    "cmpq %%rax, 8(%%rsp)\n" ++
                    "jne isr_dynirq_canary_panic\n" ++
                    "addq $16, %%rsp\n" ++
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
                    @import("../proc/sched_asm.zig").SAFE_IRETQ);
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
    const sym = @import("../debug/symbols.zig");
    const rsp_now: u64 = asm volatile ("mov %%rsp, %[r]"
        : [r] "=r" (-> u64),
    );
    const slots: [*]const u64 = @ptrFromInt(rsp_now);
    serial.print("\n!!! DYNIRQ STACK CANARY CLOBBERED — IPI handler smashed stack !!!\n", .{});
    serial.print("  expected canary 0x0C0FFEE0BA0BEDA0 at 0x{X:0>16}+8\n", .{rsp_now});
    serial.print("  got 0x{X:0>16}", .{slots[1]});
    if (sym.resolveKernel(slots[1])) |r| {
        serial.print("  // {s}+0x{X}", .{ r.name, r.offset });
    }
    serial.print("\n  surrounding stack (32 qwords):\n", .{});
    @import("../debug/kdbg.zig").crashAutopsy(.{ .kernel_rsp = rsp_now });
    @panic("dynirq canary clobbered — IPI handler corrupted stack");
}

// Alignment-violation panic targets for the trampolines above. Reaching any
// of these means the push count in the corresponding stub got out of sync
// with the SysV 16-byte stack-alignment requirement for `call`. The named
// targets let the panic message point at the exact stub instead of just
// dumping a generic crash.
pub export fn isr_common_exc_align_panic() callconv(.c) noreturn {
    @panic("isr_common_exc: RSP misaligned at call handleException — recount pushes");
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
    const sym = @import("../debug/symbols.zig");

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
    serial.print("  canary slot 0x{X:0>16}: expected 0x000000007B0FF1CE, got 0x{X:0>16}\n", .{ rsp_now, got_canary });

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

    @import("../debug/kdbg.zig").crashAutopsy(.{ .kernel_rsp = rsp_now });
    @panic("isr_irq0 canary clobbered — wild writer caught");
}
/// Pre-iretq sanity panic. Reached when an iretq site is about to pop a
/// frame whose CS slot isn't 0x08 (kernel) or 0x23 (user). Catches the
/// "wild iretq frame" class of corruption BEFORE iretq fires, so the
/// kstack is still intact for autopsy. Without this, the corrupt frame
/// would iretq to garbage and the next #UD/#GP would be in a context
/// detached from the actual writer.
///
/// Stack layout at jump time: %rsp points at the iretq frame's RIP slot.
/// slots[0]=RIP, slots[1]=CS, slots[2]=RFLAGS, slots[3]=RSP, slots[4]=SS.
pub export fn isr_iretq_corrupt_panic() callconv(.c) noreturn {
    const sym = @import("../debug/symbols.zig");
    const rsp_now: u64 = asm volatile ("mov %%rsp, %[r]"
        : [r] "=r" (-> u64),
    );
    const slots: [*]const u64 = @ptrFromInt(rsp_now);

    serial.print("\n!!! IRETQ FRAME CORRUPTED — caught BEFORE iretq fired !!!\n", .{});
    serial.print("  iretq frame at 0x{X:0>16}:\n", .{rsp_now});
    serial.print("    RIP   =0x{X:0>16}", .{slots[0]});
    if (sym.resolveKernel(slots[0])) |r| {
        serial.print("  ({s}+0x{X})", .{ r.name, r.offset });
    }
    serial.print("\n    CS    =0x{X:0>4}     <-- expected 0x08 (kernel) or 0x23 (user)\n", .{slots[1]});
    serial.print("    RFLAGS=0x{X:0>16}\n", .{slots[2]});
    serial.print("    RSP   =0x{X:0>16}", .{slots[3]});
    if (sym.resolveKernel(slots[3])) |r| {
        serial.print("  (kernel addr! — {s}+0x{X})", .{ r.name, r.offset });
    }
    serial.print("\n    SS    =0x{X:0>4}\n", .{slots[4]});
    serial.print("  Surrounding stack (32 qwords from RSP):\n", .{});
    @import("../debug/kdbg.zig").crashAutopsy(.{ .kernel_rsp = rsp_now });
    @panic("iretq frame corrupted — caller jumped here from CS-validation in isr stub");
}

pub export fn isr_irq1_align_panic() callconv(.c) noreturn {
    @panic("isr_irq1: RSP misaligned at call handleIRQ1 — recount pushes");
}
pub export fn isr_irq12_align_panic() callconv(.c) noreturn {
    @panic("isr_irq12: RSP misaligned at call handleIRQ12 — recount pushes");
}
