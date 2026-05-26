// POSIX-style signals on x86_64 long mode.
//
// Delivery model: per-PCB pending/mask u32 bitmasks. `send` sets a bit (and
// wakes the target if it's parked); the kernel's exit-to-user transitions
// (syscall return, IRQ-return-to-user, exception-return-to-user) walk the
// pending set, pick the lowest-numbered non-blocked signal, and either apply
// the default action (term/core/ignore/stop/cont) or set up a handler frame
// on the user stack so sysret/iretq lands inside the user's handler.
//
// The handler frame is `[trampoline RA | MContext]` — when the handler ret's
// it pops the trampoline RA, jumps to libc's __sigreturn, which issues the
// `sigreturn` syscall. The kernel's sigreturn handler reads the MContext
// from user RSP and rewrites the saved kernel-stack frame so the next
// sysret restores all GPRs + RIP + RFLAGS + user RSP to pre-signal values.
//
// Three trap-frame shapes are involved:
//   SyscallFrame — saved by the per-CPU LSTAR stub at `call doSyscall` time.
//                  Fewer fields (rdi/rsi/rdx are the syscall args, restored
//                  via the matching pop sequence on return).
//   IrqFrame    — saved by isr_irq0; full 15 GPRs + iretq frame.
//   ExcFrame    — saved by isr_common_exc; same as IRQ plus int_no + err_code.
//
// All three share the same delivery primitive: write MContext to user stack,
// rewrite the trap frame's RIP/RSP/RDI/RSI/RDX, return. The handler's RAX
// is undefined on entry (the handler doesn't observe it; it observes its
// args via rdi/rsi/rdx per SysV).

const std = @import("std");
const process = @import("process.zig");
const debug = @import("../debug/debug.zig");
const smp = @import("../cpu/smp.zig");
const memmap = @import("../mm/memmap.zig");
const config = @import("../config.zig");
const protect = @import("../cpu/protect.zig");

pub const NSIG: u32 = config.NSIG;

// Standard POSIX signal numbers (Linux/x86_64 ABI). Keep these literal — the
// libc-side mirror in lib/signal.zig must match exactly.
pub const SIGHUP: u32 = 1;
pub const SIGINT: u32 = 2;
pub const SIGQUIT: u32 = 3;
pub const SIGILL: u32 = 4;
pub const SIGTRAP: u32 = 5;
pub const SIGABRT: u32 = 6;
pub const SIGBUS: u32 = 7;
pub const SIGFPE: u32 = 8;
pub const SIGKILL: u32 = 9;
pub const SIGUSR1: u32 = 10;
pub const SIGSEGV: u32 = 11;
pub const SIGUSR2: u32 = 12;
pub const SIGPIPE: u32 = 13;
pub const SIGALRM: u32 = 14;
pub const SIGTERM: u32 = 15;
pub const SIGCHLD: u32 = 17;
pub const SIGCONT: u32 = 18;
pub const SIGSTOP: u32 = 19;
pub const SIGTSTP: u32 = 20;

pub const SIG_DFL: u64 = 0;
pub const SIG_IGN: u64 = 1;

pub const SA_RESTART: u32 = 0x10000000;
pub const SA_NODEFER: u32 = 0x40000000;
pub const SA_RESETHAND: u32 = 0x80000000;
// Linux value (0x4). When set, the kernel calls the handler with three
// args: (signo, *Siginfo, *ucontext). When clear, the handler still gets
// three slots filled but rsi (siginfo) is NULL — apps with a 1-arg
// `void(int)` signature only read rdi, so the extra slots are harmless
// under SysV.
pub const SA_SIGINFO: u32 = 0x00000004;

pub const SIG_BLOCK: u32 = 0;
pub const SIG_UNBLOCK: u32 = 1;
pub const SIG_SETMASK: u32 = 2;

pub const Action = enum(u8) { term, core, ignore, stop, cont };

/// Default action per signal — POSIX-mandated. Slot 0 unused. Anything past
/// the standard set defaults to `term`. Stop/cont are accepted but currently
/// no-op (job control isn't wired up yet — the scheduler has no .stopped state).
pub const default_actions: [NSIG]Action = blk: {
    var a: [NSIG]Action = [_]Action{.term} ** NSIG;
    a[0] = .ignore;
    a[SIGHUP] = .term;
    a[SIGINT] = .term;
    a[SIGQUIT] = .core;
    a[SIGILL] = .core;
    a[SIGTRAP] = .core;
    a[SIGABRT] = .core;
    a[SIGBUS] = .core;
    a[SIGFPE] = .core;
    a[SIGKILL] = .term;
    a[SIGUSR1] = .term;
    a[SIGSEGV] = .core;
    a[SIGUSR2] = .term;
    a[SIGPIPE] = .term;
    a[SIGALRM] = .term;
    a[SIGTERM] = .term;
    a[16] = .ignore;
    a[SIGCHLD] = .ignore;
    a[SIGCONT] = .cont;
    a[SIGSTOP] = .stop;
    a[SIGTSTP] = .stop;
    break :blk a;
};

/// User-installed disposition for a signal. `handler` is SIG_DFL (0),
/// SIG_IGN (1), or a u64 user-space function pointer. `restorer` is the
/// libc trampoline that issues sigreturn on handler return — kernel pushes
/// it as the handler's return address.
pub const SigAction = extern struct {
    handler: u64 = SIG_DFL,
    flags: u32 = 0,
    mask: u32 = 0,
    restorer: u64 = 0,
};

/// Magic word at the head of every kernel-pushed MContext. The sigreturn
/// syscall refuses to act on anything else — bogus `mov $62, %eax; syscall`
/// from a malicious app shouldn't be able to forge an arbitrary register
/// state. ASCII "ZOSMCTX_" (little-endian).
pub const MCONTEXT_MAGIC: u64 = 0x5F58_5443_4D53_4F5A;

/// Subset of POSIX `siginfo_t`. Field order chosen to match Linux's binary
/// layout for the first three slots (signo/errno/code) so userland headers
/// can be a drop-in; the rest are kept minimal — we don't track si_uid /
/// si_band / sigval right now.
pub const Siginfo = extern struct {
    si_signo: u32,
    si_errno: u32, // currently always 0; reserved for future use
    si_code: u32,
    _pad0: u32, // align si_pid + si_addr nicely
    si_pid: u32, // sender pid for kill()/raise(); 0 for kernel-synthesized
    si_uid: u32, // currently always 0; uids aren't modeled yet
    si_addr: u64, // faulting address (SIGSEGV/SIGBUS/SIGFPE) or 0
    si_status: u32, // exit status (SIGCHLD); 0 otherwise
    _pad1: u32,
};

// si_code values. POSIX defines a small set of "source" codes (SI_USER,
// SI_KERNEL, SI_TIMER, ...) plus per-signal sub-codes (SEGV_MAPERR for
// SIGSEGV-with-unmapped-VA, FPE_INTDIV, etc). We include the ones we
// actually produce; apps that read these can branch on them.
pub const SI_USER: u32 = 0;
pub const SI_KERNEL: u32 = 0x80;
pub const SEGV_MAPERR: u32 = 1; // address not mapped to object
pub const SEGV_ACCERR: u32 = 2; // invalid permissions for mapped object
pub const ILL_ILLOPC: u32 = 1; // illegal opcode
pub const FPE_INTDIV: u32 = 1; // integer divide by zero
pub const TRAP_BRKPT: u32 = 1; // breakpoint

/// Saved user state stored on the user stack at signal delivery and read back
/// by sigreturn. The handler receives a pointer to this as its 3rd arg
/// (`void *ucontext`) — well-behaved handlers leave it alone, and SysV
/// signature handlers that take `(int signo, siginfo_t *info, ucontext_t *uc)`
/// can cast and inspect it.
pub const MContext = extern struct {
    magic: u64,
    saved_mask: u32,
    signo: u32,
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    rbp: u64,
    rsp: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rip: u64,
    rflags: u64,
};

/// Mirror of the syscall-asm trampoline's saved frame at `call doSyscall`.
/// Field order must match the push sequence in syscall_entry.zig — first
/// field = lowest address = last push. Alignment: 15 pushes + 520 FXSAVE
/// = 640, +call = 648 mod 16 = 8.
pub const SyscallFrame = extern struct {
    r10: u64,
    r9: u64,
    r8: u64,
    rdx: u64, // user's syscall arg3 (pre-shuffle)
    rsi: u64, // user's syscall arg2
    rdi: u64, // user's syscall arg1
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    rbp: u64,
    rbx: u64,
    rcx: u64, // saved user RIP (syscall instruction stashes it here)
    r11: u64, // saved user RFLAGS
    // Saved user RSP. Pushed to the kernel stack as the FIRST push at syscall
    // entry (so it lands at the HIGHEST address among the 15 pushes — matches
    // the trailing position in this struct). Popped back into %rsp as the
    // LAST step before sysretq.
    //
    // Why on the kernel stack instead of per_cpu_user_rsp[cpu]?
    // per_cpu_user_rsp is per-CPU, not per-thread. If a thread blocks mid-syscall
    // (futex/pipe/waitpid), schedule() runs another thread on the same CPU;
    // that thread's syscall entry overwrites the per-CPU slot with ITS user RSP.
    // When the original thread is rescheduled, sysret reads the OVERWRITTEN
    // value and lands on the wrong stack. Symptom: threadtest's main thread
    // crashed with RSP pointing into a worker's mmap'd thread stack.
    // Putting user_rsp on the kernel stack ties its lifetime to the kernel
    // stack itself, which IS per-thread (kstack_pool[pid]).
    user_rsp: u64,
};

/// Mirror of isr_irq0's saved frame at `call handleIRQ0`. The leading 15 GPRs
/// match the push order in idt.zig; the trailing 5 are the iretq frame the
/// CPU pushed on entry. Used for IRQ-return-to-user signal delivery.
pub const IrqFrame = extern struct {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rdi: u64,
    rsi: u64,
    rbp: u64,
    rbx: u64,
    rdx: u64,
    rcx: u64,
    rax: u64,
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,
};

/// Mirror of isr_common_exc's saved frame. Same as IrqFrame but with the
/// stub-pushed (int_no, error_code) sandwiched between GPRs and iretq.
pub const ExcFrame = extern struct {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rdi: u64,
    rsi: u64,
    rbp: u64,
    rbx: u64,
    rdx: u64,
    rcx: u64,
    rax: u64,
    int_no: u64,
    error_code: u64,
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,
};

// Lowest legitimate user VA for signal frames. This MUST be USER_SPACE_START,
// not USER_VA_FLOOR: the user *stack* lives in [USER_SPACE_START, USER_VA_FLOOR)
// (the 1 MB reserve just under the ELF load base — see memmap.zig), and we write
// the handler frame / read the sigreturn MContext on that stack. Using
// USER_VA_FLOOR (the code load base) rejected every RSP in the stack region, so
// layoutHandlerFrame failed and we KILLED any process that had a real SIGINT
// handler (shell, httpd, …) with 0xDEAD0002 instead of running its handler —
// the long-standing "Ctrl+C does nothing / kills the shell" bug.
const USER_BASE: u64 = memmap.USER_SPACE_START;
const USER_END: u64 = memmap.USER_SPACE_END;

fn validateUserRange(addr: u64, len: u64) bool {
    if (addr < USER_BASE) return false;
    if (addr +% len > USER_END) return false;
    if (addr +% len < addr) return false;
    return true;
}

pub fn isCatchable(signo: u32) bool {
    return signo != SIGKILL and signo != SIGSTOP;
}

fn pidIndexOfPcb(pcb: *const process.PCB) usize {
    const base = @intFromPtr(&process.procs[0]);
    const off = @intFromPtr(pcb) - base;
    return off / @sizeOf(process.PCB);
}

/// Mark `signo` pending on `target` and wake the target if it's parked. Idempotent
/// — sending the same signal twice between deliveries collapses to one bit.
/// Returns false on bad inputs (out-of-range pid, signo >= NSIG, dead target).
/// Returns true even if the target's disposition makes the signal a no-op
/// (SIG_IGN / default-ignore) — caller can't observe the difference.
///
/// signo == 0 is the POSIX "existence/permission probe": returns true if the
/// target is a live, signalable PCB and false otherwise. No bit is set, no
/// wake is sent.
pub fn send(target: u8, signo: u32) bool {
    if (target >= process.MAX_PROCS) return false;
    if (signo >= NSIG) return false;
    const pcb = &process.procs[target];
    if (pcb.state == .unused or pcb.state == .zombie) return false;

    // Existence probe — `kill(pid, 0)` returns success iff target is live.
    if (signo == 0) return true;

    // Catchable signals that are explicitly ignored short-circuit — no need
    // to wake the target or set a pending bit. SIGKILL/SIGSTOP can't be
    // ignored, so they always set the bit.
    if (isCatchable(signo)) {
        const sa = &pcb.sigactions[signo];
        if (sa.handler == SIG_IGN) return true;
        if (sa.handler == SIG_DFL and default_actions[signo] == .ignore) return true;
    }

    // Atomic OR — two CPUs sending different signals to the same pid (or
    // a sender vs the deliver-clear path) must not lose bits via a torn
    // RMW. seq_cst pairs with the matching @atomicRmw .And in delivery.
    _ = @atomicRmw(u32, &pcb.pending_signals, .Or, @as(u32, 1) << @intCast(signo), .seq_cst);

    // Make sure parked processes notice. wake() is a no-op for .running and
    // .ready, so this is safe to call unconditionally.
    if (pcb.state == .sleeping or pcb.wait_kind != .none) {
        process.wake(target);
    }
    return true;
}

fn pickSignal(pcb: *const process.PCB) ?u32 {
    // Atomic load — sender on another CPU could be mid-OR; we want a
    // coherent snapshot. signal_mask is per-thread (only mutated by this
    // CPU's syscall paths) so a plain read is fine.
    const pending = @atomicLoad(u32, &pcb.pending_signals, .acquire);
    const deliverable = pending & ~pcb.signal_mask;
    if (deliverable == 0) return null;
    var s: u32 = 1;
    while (s < NSIG) : (s += 1) {
        if ((deliverable & (@as(u32, 1) << @intCast(s))) != 0) return s;
    }
    return null;
}

/// Atomically clear `signo`'s pending bit. Used by the deliver paths
/// (syscall/IRQ/exception return) after a signal has been picked for
/// delivery. Pairs with the .Or in send() so concurrent sends/picks
/// can't race.
fn clearPending(pcb: *process.PCB, signo: u32) void {
    _ = @atomicRmw(u32, &pcb.pending_signals, .And, ~(@as(u32, 1) << @intCast(signo)), .seq_cst);
}

fn applyDefault(pcb: *process.PCB, signo: u32) void {
    const action = default_actions[signo];
    switch (action) {
        .ignore, .stop, .cont => {
            // .stop/.cont currently no-op — job control needs a .stopped
            // scheduler state we don't have yet.
        },
        .term, .core => {
            // POSIX exit_group: for a multi-threaded process, a fatal default
            // action kills EVERY thread in the group, not just `pcb`. The
            // current-CPU thread is handled inside killThreadGroup's self-
            // phase (destroyCurrentWithStatus there, same dance as before).
            // For single-threaded processes pcb.tgid == self_pid and the
            // group-walk hits exactly one slot — identical behavior to the
            // pre-tgid path.
            const status: u32 = 0xDEAD0000 | signo;
            process.killThreadGroup(pcb.tgid, status);
            if (smp.myCpu().current_pid) |cur| {
                if (cur == pidIndexOfPcb(pcb)) {
                    // If pcb wasn't in its own group (shouldn't happen — clone
                    // sets tgid before .ready) the killThreadGroup self-phase
                    // is a no-op; fall back to schedule() to drop our frame.
                    process.schedule();
                    unreachable;
                }
            }
        },
    }
}

fn applyHandlerMaskUpdate(pcb: *process.PCB, signo: u32, sa: *const SigAction) void {
    pcb.saved_signal_mask = pcb.signal_mask;
    pcb.signal_mask |= sa.mask;
    if ((sa.flags & SA_NODEFER) == 0) {
        pcb.signal_mask |= (@as(u32, 1) << @intCast(signo));
    }
    pcb.in_signal_handler = true;
}

/// Frame layout we lay down on the user stack at signal delivery, growing
/// downward from the saved user RSP:
///
///   [ ... pre-signal stack ... ]   ← old RSP
///   [ Siginfo (40 B)         ]   ← optional, only when SA_SIGINFO
///   [ MContext (~170 B)      ]
///   [ trampoline RA (8 B)    ]   ← new RSP at handler entry
///
/// Returned struct holds the VAs the trap-frame mutators need so we don't
/// duplicate the layout math across the three deliverFrom* entry points.
const HandlerLayout = struct {
    ra_va: u64,
    mctx_va: u64,
    siginfo_va: u64, // 0 when SA_SIGINFO not set
};

fn layoutHandlerFrame(user_rsp: u64, want_siginfo: bool) ?HandlerLayout {
    const sinfo_size: u64 = if (want_siginfo) @sizeOf(Siginfo) else 0;
    const sinfo_va = (user_rsp -% sinfo_size) & ~@as(u64, 0xF);
    const mctx_va = (sinfo_va -% @sizeOf(MContext)) & ~@as(u64, 0xF);
    const ra_va = mctx_va -% 8;
    const total_span = (user_rsp -% ra_va);
    if (!validateUserRange(ra_va, total_span)) return null;
    return .{
        .ra_va = ra_va,
        .mctx_va = mctx_va,
        .siginfo_va = if (want_siginfo) sinfo_va else 0,
    };
}

fn writeSiginfo(layout: HandlerLayout, signo: u32, code: u32, addr: u64) void {
    if (layout.siginfo_va == 0) return;
    const sp: *Siginfo = @ptrFromInt(layout.siginfo_va);
    sp.* = .{
        .si_signo = signo,
        .si_errno = 0,
        .si_code = code,
        ._pad0 = 0,
        .si_pid = 0,
        .si_uid = 0,
        .si_addr = addr,
        .si_status = 0,
        ._pad1 = 0,
    };
}

/// Try to deliver one pending signal at syscall-return. Mutates `frame` so
/// sysret lands in the handler. `retval` is the dispatcher's return value;
/// when no handler runs we return it back unchanged so the asm path can
/// place it in user RAX. When a handler IS invoked, the user observes the
/// handler — the original retval is preserved in MContext.rax and restored
/// by sigreturn.
///
/// Loops because: (1) SIG_IGN and default-ignore disposed signals get
/// dropped silently and we should re-check for the next pending one;
/// (2) default-action term/core kills the process and the call doesn't
/// return (handled by the early `if cur == pid` branch in applyDefault).
pub fn deliverFromSyscallFrame(pcb: *process.PCB, frame: *SyscallFrame, retval: u32) u32 {
    if (pcb.in_signal_handler) return retval;
    while (true) {
        const sig = pickSignal(pcb) orelse return retval;
        clearPending(pcb, sig);

        if (!isCatchable(sig)) {
            applyDefault(pcb, sig);
            return retval;
        }

        const sa = &pcb.sigactions[sig];
        if (sa.handler == SIG_IGN) continue;
        if (sa.handler == SIG_DFL) {
            applyDefault(pcb, sig);
            // If applyDefault killed us, control already left the function.
            // For ignore/stop/cont we keep checking pending.
            continue;
        }

        // User handler. The saved user RSP lives at frame.user_rsp (per-thread,
        // pushed onto the kernel stack at syscall entry — see SyscallFrame
        // doc and syscall_entry.zig). Push MContext + optional Siginfo +
        // trampoline RA at the user's stack and rewrite frame.user_rsp so
        // sysret lands on the handler's freshly-prepared frame.
        const old_user_rsp = frame.user_rsp;
        const want_si = (sa.flags & SA_SIGINFO) != 0;
        const layout = layoutHandlerFrame(old_user_rsp, want_si) orelse {
            // User stack is hosed (recursive overflow into guard, e.g.) —
            // can't deliver. Force terminate with a recognizable status.
            process.destroyCurrentWithStatus(0xDEAD0000 | sig);
            return retval;
        };

        // The handler frame goes DIRECTLY onto the user stack (unlike syscall
        // arg copies, which go through the physmap), so under CR4.SMAP we must:
        //  1. Pre-resolve the frame's pages (lazy fault-in + COW break) NOW. A
        //     kernel-mode write that faults here is NOT serviced by this
        //     kernel's ring-3-only #PF path — it would panic. (Triggers: a
        //     freshly-forked process with a still-COW stack, or a frame
        //     spanning into a lower stack page not yet lazily mapped.)
        //  2. Bracket the writes — mctx, writeSiginfo, RA, and the mctx.rflags
        //     read-back below — with stac/clac so SMAP permits kernel access.
        if (!process.ensureUserRangeWritable(layout.ra_va, old_user_rsp - layout.ra_va)) {
            process.destroyCurrentWithStatus(0xDEAD0000 | sig);
            return retval;
        }
        protect.allowUserAccess();
        const mctx_ptr: *MContext = @ptrFromInt(layout.mctx_va);
        mctx_ptr.* = .{
            .magic = MCONTEXT_MAGIC,
            .saved_mask = pcb.signal_mask,
            .signo = sig,
            .rax = retval,
            .rbx = frame.rbx,
            .rcx = frame.rcx,
            .rdx = frame.rdx,
            .rsi = frame.rsi,
            .rdi = frame.rdi,
            .rbp = frame.rbp,
            .rsp = old_user_rsp,
            .r8 = frame.r8,
            .r9 = frame.r9,
            .r10 = frame.r10,
            .r11 = frame.r11,
            .r12 = frame.r12,
            .r13 = frame.r13,
            .r14 = frame.r14,
            .r15 = frame.r15,
            .rip = frame.rcx, // syscall instruction stashed user RIP in RCX
            .rflags = frame.r11,
        };
        // Async signal (no fault address) — si_code = SI_USER for the
        // best-effort common case; the kernel doesn't track sender pid yet,
        // so si_pid stays 0.
        writeSiginfo(layout, sig, SI_USER, 0);
        const ra_ptr: *u64 = @ptrFromInt(layout.ra_va);
        ra_ptr.* = sa.restorer;

        // Rewrite the saved syscall frame so the asm-side pop sequence loads
        // handler args into user RDI/RSI/RDX and sysret jumps to handler.
        frame.rcx = sa.handler; // sysret RIP
        frame.r11 = (mctx_ptr.rflags & ~@as(u64, 0x100)) | 0x202; // clear TF, ensure IF
        frame.rdi = sig;
        frame.rsi = layout.siginfo_va; // 0 when SA_SIGINFO not set
        frame.rdx = layout.mctx_va;
        frame.user_rsp = layout.ra_va;
        protect.disallowUserAccess(); // end user-frame access (covers the rflags read-back above)

        applyHandlerMaskUpdate(pcb, sig, sa);
        if ((sa.flags & SA_RESETHAND) != 0) sa.handler = SIG_DFL;

        // Handler entry doesn't observe RAX — return value is irrelevant.
        return 0;
    }
}

/// Deliver one pending signal on IRQ-return-to-user. Modifies the iretq
/// portion of `frame` plus the rdi/rsi/rdx GPR slots so iretq lands in the
/// handler.
pub fn deliverFromIrqFrame(pcb: *process.PCB, frame: *IrqFrame) void {
    if (pcb.in_signal_handler) return;
    while (true) {
        const sig = pickSignal(pcb) orelse return;
        clearPending(pcb, sig);

        if (!isCatchable(sig)) {
            applyDefault(pcb, sig);
            return;
        }

        const sa = &pcb.sigactions[sig];
        if (sa.handler == SIG_IGN) continue;
        if (sa.handler == SIG_DFL) {
            applyDefault(pcb, sig);
            continue;
        }

        const old_user_rsp = frame.rsp;
        const want_si = (sa.flags & SA_SIGINFO) != 0;
        const layout = layoutHandlerFrame(old_user_rsp, want_si) orelse {
            process.destroyCurrentWithStatus(0xDEAD0000 | sig);
            return;
        };

        // SMAP: pre-resolve frame pages (no-fault lazy/COW) + bracket the
        // direct user-stack frame writes. See deliverFromSyscallFrame.
        if (!process.ensureUserRangeWritable(layout.ra_va, old_user_rsp - layout.ra_va)) {
            process.destroyCurrentWithStatus(0xDEAD0000 | sig);
            return;
        }
        protect.allowUserAccess();
        const mctx_ptr: *MContext = @ptrFromInt(layout.mctx_va);
        mctx_ptr.* = .{
            .magic = MCONTEXT_MAGIC,
            .saved_mask = pcb.signal_mask,
            .signo = sig,
            .rax = frame.rax,
            .rbx = frame.rbx,
            .rcx = frame.rcx,
            .rdx = frame.rdx,
            .rsi = frame.rsi,
            .rdi = frame.rdi,
            .rbp = frame.rbp,
            .rsp = old_user_rsp,
            .r8 = frame.r8,
            .r9 = frame.r9,
            .r10 = frame.r10,
            .r11 = frame.r11,
            .r12 = frame.r12,
            .r13 = frame.r13,
            .r14 = frame.r14,
            .r15 = frame.r15,
            .rip = frame.rip,
            .rflags = frame.rflags,
        };
        writeSiginfo(layout, sig, SI_USER, 0);
        const ra_ptr: *u64 = @ptrFromInt(layout.ra_va);
        ra_ptr.* = sa.restorer;

        frame.rip = sa.handler;
        frame.rsp = layout.ra_va;
        frame.rflags = (frame.rflags & ~@as(u64, 0x100)) | 0x202;
        frame.rdi = sig;
        frame.rsi = layout.siginfo_va;
        frame.rdx = layout.mctx_va;
        protect.disallowUserAccess(); // end user-frame access

        // iretq-canary refresh (task #230). We just legitimately rewrote the
        // saved RIP/RSP/RFLAGS plus the rdi/rsi/rdx GPR slots to redirect
        // iretq into the user signal handler. Without this refresh, the
        // canary check at schedule() would false-positive on these
        // deliberate changes. Refresh re-syncs the snap with the post-mutate
        // state.
        @import("../debug/iretq_canary.zig").refresh();

        applyHandlerMaskUpdate(pcb, sig, sa);
        if ((sa.flags & SA_RESETHAND) != 0) sa.handler = SIG_DFL;
        return;
    }
}

/// Synchronous signal raised from an exception handler (PF/UD/DE/etc.). If
/// the user has a handler installed, deliver to it via the exception trap
/// frame. Otherwise return false so the caller can fall through to the
/// existing crash-log + kill path.
///
/// `signo` is the signal we're raising on the user's behalf. `frame` is the
/// exception trap frame whose RIP/RSP/RDI/RSI/RDX we may rewrite to redirect
/// to the user handler. `fault_addr` is propagated into siginfo.si_addr when
/// the user installed an SA_SIGINFO handler — pass cr2 for #PF, the faulting
/// instruction RIP for #UD/#DE, or 0 when no meaningful address exists.
/// `si_code` is the per-signal subcode (e.g. SEGV_MAPERR vs SEGV_ACCERR).
pub fn deliverFromExcFrame(pcb: *process.PCB, frame: *ExcFrame, signo: u32, fault_addr: u64, si_code: u32) bool {
    if (signo == 0 or signo >= NSIG) return false;

    const sa = &pcb.sigactions[signo];
    // Fast paths: SIG_IGN on a synchronous signal is dangerous — the faulting
    // instruction will just refault. Match Linux: treat as default action
    // (i.e. don't actually ignore #SEGV/#FPE/etc.).
    if (sa.handler == SIG_DFL or sa.handler == SIG_IGN) return false;
    if (!isCatchable(signo)) return false;
    if (pcb.in_signal_handler) {
        // Nested fault inside a handler — we'd loop forever. Force-kill with
        // the synchronous-signal status; matches Linux's "force_sig" path
        // when the user already has the signal blocked or is mid-handler.
        return false;
    }

    const old_user_rsp = frame.rsp;
    const want_si = (sa.flags & SA_SIGINFO) != 0;
    const layout = layoutHandlerFrame(old_user_rsp, want_si) orelse return false;

    // SMAP: pre-resolve frame pages (no-fault lazy/COW) + bracket the direct
    // user-stack frame writes. See deliverFromSyscallFrame.
    if (!process.ensureUserRangeWritable(layout.ra_va, old_user_rsp - layout.ra_va)) {
        process.destroyCurrentWithStatus(0xDEAD0000 | signo);
        return false;
    }
    protect.allowUserAccess();
    const mctx_ptr: *MContext = @ptrFromInt(layout.mctx_va);
    mctx_ptr.* = .{
        .magic = MCONTEXT_MAGIC,
        .saved_mask = pcb.signal_mask,
        .signo = signo,
        .rax = frame.rax,
        .rbx = frame.rbx,
        .rcx = frame.rcx,
        .rdx = frame.rdx,
        .rsi = frame.rsi,
        .rdi = frame.rdi,
        .rbp = frame.rbp,
        .rsp = old_user_rsp,
        .r8 = frame.r8,
        .r9 = frame.r9,
        .r10 = frame.r10,
        .r11 = frame.r11,
        .r12 = frame.r12,
        .r13 = frame.r13,
        .r14 = frame.r14,
        .r15 = frame.r15,
        .rip = frame.rip,
        .rflags = frame.rflags,
    };
    writeSiginfo(layout, signo, si_code, fault_addr);
    const ra_ptr: *u64 = @ptrFromInt(layout.ra_va);
    ra_ptr.* = sa.restorer;

    frame.rip = sa.handler;
    frame.rsp = layout.ra_va;
    frame.rflags = (frame.rflags & ~@as(u64, 0x100)) | 0x202;
    frame.rdi = signo;
    frame.rsi = layout.siginfo_va;
    frame.rdx = layout.mctx_va;
    protect.disallowUserAccess(); // end user-frame access

    applyHandlerMaskUpdate(pcb, signo, sa);
    if ((sa.flags & SA_RESETHAND) != 0) sa.handler = SIG_DFL;
    return true;
}

/// Implementation of the sigreturn syscall. Reads MContext from user RSP
/// (where the sigreturn-trampoline `syscall` left it after the handler's
/// `ret` popped the trampoline RA), validates it, restores the saved frame
/// + signal mask, and returns the user's saved rax. The kernel asm path
/// will place that in user RAX via the normal syscall return.
pub fn sigreturn(pcb: *process.PCB, frame: *SyscallFrame) u32 {
    // user_rsp now lives on the kernel stack as part of the SyscallFrame —
    // it's the handler's RSP at the moment it called sys_sigreturn, which
    // points at the MContext we pushed in deliverFromSyscallFrame.
    const user_rsp = frame.user_rsp;
    if (!validateUserRange(user_rsp, @sizeOf(MContext))) {
        debug.klog("[sig] sigreturn: user rsp 0x{X} out of range\n", .{user_rsp});
        process.destroyCurrentWithStatus(0xDEAD000B);
        return 0;
    }
    const mctx_ptr: *const MContext = @ptrFromInt(user_rsp);
    // SMAP: reading the saved MContext back off the user stack also needs AC.
    protect.allowUserAccess();
    const magic = mctx_ptr.magic;
    if (magic != MCONTEXT_MAGIC) {
        protect.disallowUserAccess();
        debug.klog("[sig] sigreturn: bad MContext magic 0x{X} at 0x{X}\n", .{ magic, user_rsp });
        process.destroyCurrentWithStatus(0xDEAD000B);
        return 0;
    }

    // Rewrite the saved syscall frame so sysret restores the pre-signal
    // user state. RAX is the syscall return value, which the asm path takes
    // from doSyscall's return — so we return mctx.rax to the caller and let
    // them stash it in %rax.
    frame.rbx = mctx_ptr.rbx;
    frame.rdx = mctx_ptr.rdx;
    frame.rsi = mctx_ptr.rsi;
    frame.rdi = mctx_ptr.rdi;
    frame.rbp = mctx_ptr.rbp;
    frame.r8 = mctx_ptr.r8;
    frame.r9 = mctx_ptr.r9;
    frame.r10 = mctx_ptr.r10;
    frame.r12 = mctx_ptr.r12;
    frame.r13 = mctx_ptr.r13;
    frame.r14 = mctx_ptr.r14;
    frame.r15 = mctx_ptr.r15;
    frame.rcx = mctx_ptr.rip;
    frame.r11 = mctx_ptr.rflags;
    frame.user_rsp = mctx_ptr.rsp;
    const saved_mask = mctx_ptr.saved_mask;
    const ret_rax = mctx_ptr.rax;
    protect.disallowUserAccess(); // end user-frame access

    pcb.signal_mask = saved_mask;
    pcb.in_signal_handler = false;

    return @truncate(ret_rax);
}

/// True if the calling process has any pending non-blocked signal whose
/// disposition isn't ignore. Used by sigsuspend / pause to decide whether
/// to park or return immediately.
pub fn hasDeliverable(pcb: *const process.PCB) bool {
    return pickSignal(pcb) != null;
}
