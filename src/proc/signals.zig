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
const protect = @import("../cpu/arch/protect.zig");
const SpinLock = @import("spinlock.zig").SpinLock;
const linux_signal = @import("../cpu/syscall/linux_signal.zig");

pub const NSIG: u32 = config.NSIG;

/// What the native calls take: signals 1..31, the ones a u32 set holds.
pub const NATIVE_NSIG: u32 = 32;

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
pub const SIGTTIN: u32 = 21;
pub const SIGTTOU: u32 = 22;
pub const SIGURG: u32 = 23;
pub const SIGXCPU: u32 = 24;
pub const SIGXFSZ: u32 = 25;
pub const SIGVTALRM: u32 = 26;
pub const SIGPROF: u32 = 27;
pub const SIGWINCH: u32 = 28;
pub const SIGIO: u32 = 29;
pub const SIGPWR: u32 = 30;
pub const SIGSYS: u32 = 31;

/// The bit of signal `signo` (1..64) in a pending set or a mask.
pub inline fn bit(signo: u32) u64 {
    return @as(u64, 1) << @intCast(signo - 1);
}

/// A native call's u32 set (bit N for signal N) as a kernel set, and back.
pub inline fn fromNativeSet(set: u32) u64 {
    return set >> 1;
}

pub inline fn toNativeSet(set: u64) u32 {
    return @truncate(set << 1);
}

/// SIGKILL and SIGSTOP: never blocked, caught or ignored.
pub const UNBLOCKABLE: u64 = bit(SIGKILL) | bit(SIGSTOP);

pub const SIG_DFL: u64 = 0;
pub const SIG_IGN: u64 = 1;

pub const SA_NOCLDSTOP: u32 = 0x00000001;
pub const SA_NOCLDWAIT: u32 = 0x00000002;
pub const SA_RESTORER: u32 = 0x04000000;
pub const SA_ONSTACK: u32 = 0x08000000;
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
/// the standard set defaults to `term`. `.stop`/`.cont` ARE wired now: a `.stop`
/// signal (SIGSTOP/SIGTSTP) suspends the process via the `job_stopped` flag that
/// pickNext skips, and SIGCONT/SIGKILL resume it (see send() + stopForJobControl);
/// only the waitpid(WUNTRACED/WCONTINUED) reporting of stops is still a follow-up.
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
    a[SIGTTIN] = .stop;
    a[SIGTTOU] = .stop;
    a[SIGURG] = .ignore;
    a[SIGXCPU] = .core;
    a[SIGXFSZ] = .core;
    a[SIGWINCH] = .ignore;
    a[SIGSYS] = .core;
    break :blk a;
};

/// A signal's disposition as the native sigaction call passes it: the
/// native ABI. `handler` is SIG_DFL (0), SIG_IGN (1), or a user function;
/// `restorer` is the libc trampoline that issues sigreturn on handler
/// return — the kernel pushes it as the handler's return address. `mask`
/// has bit N for signal N.
pub const SigAction = extern struct {
    handler: u64 = SIG_DFL,
    flags: u32 = 0,
    mask: u32 = 0,
    restorer: u64 = 0,
};

/// A signal's disposition as the kernel keeps it, for either personality.
pub const Disposition = struct {
    handler: u64 = SIG_DFL,
    flags: u32 = 0,
    restorer: u64 = 0,
    /// Blocked while the handler runs, on top of the signal itself.
    mask: u64 = 0,

    pub fn fromNative(sa: SigAction) Disposition {
        return .{ .handler = sa.handler, .flags = sa.flags, .restorer = sa.restorer, .mask = fromNativeSet(sa.mask) };
    }

    pub fn toNative(self: Disposition) SigAction {
        return .{ .handler = self.handler, .flags = self.flags, .mask = toNativeSet(self.mask), .restorer = self.restorer };
    }
};

/// What comes with a pending signal.
pub const Info = extern struct {
    /// SI_USER, SI_TKILL, SI_KERNEL..., or the signal's own code (CLD_*).
    code: i32 = SI_KERNEL_CODE,
    /// The sender's number (kill, tkill) or the child's (SIGCHLD).
    pid: u32 = 0,
    /// The child's exit code or ending signal (SIGCHLD); a queued value.
    value: u64 = 0,
};

pub const SI_USER_CODE: i32 = 0;
pub const SI_KERNEL_CODE: i32 = 0x80;
pub const SI_TKILL_CODE: i32 = -6;
pub const CLD_EXITED: i32 = 1;
pub const CLD_KILLED: i32 = 2;
pub const CLD_DUMPED: i32 = 3;
pub const CLD_STOPPED: i32 = 5;
pub const CLD_CONTINUED: i32 = 6;

/// The stack a Linux process set with sigaltstack; size 0 is none.
pub const AltStack = struct {
    sp: u64 = 0,
    size: u64 = 0,
    /// SS_AUTODISARM: off while a handler runs on it.
    autodisarm: bool = false,

    pub fn holds(self: AltStack, addr: u64) bool {
        return self.size != 0 and addr > self.sp and addr <= self.sp + self.size;
    }
};

/// The exit status of a Linux process a signal ended: the signal, flagged
/// (linux_proc.waitStatus turns it into a wait status). No core is dumped,
/// so none is reported.
pub const KILLED_BY: u32 = 0x4000_0000;

/// The exit status of process `pcb` ended by `signo`'s default action.
pub fn fatalStatus(pcb: *const process.PCB, signo: u32) u32 {
    return if (pcb.personality == .linux) KILLED_BY | signo else 0xDEAD0000 | signo;
}

/// The dispositions `pcb` goes by: a Linux process's threads share the
/// lead's; a native task has its own (a thread starts with a copy).
pub fn dispositions(pcb: *process.PCB) *[NSIG]Disposition {
    return if (pcb.personality == .linux) &process.leader(pcb).sigactions else &pcb.sigactions;
}

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
/// field = lowest address = last push. Alignment: 15 pushes + the 536 bytes
/// under the frame = 656, +call = 664 mod 16 = 8.
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

    // Under the frame the entry stub keeps three words and, below them, the
    // caller's FXSAVE image (536 bytes in all):
    //   -8   r11 for a full restore
    //   -16  rcx for a full restore
    //   -24  exit mode: 0 leaves by sysret, which loads rip and rflags from
    //        the rcx and r11 slots and so can't give those two registers
    //        back; 1 leaves by iretq with every register restored.
    const FULL_R11: usize = 8;
    const FULL_RCX: usize = 16;
    const EXIT_MODE: usize = 24;
    const FPU_BELOW: usize = 536;

    /// The caller's FP/SSE state, fxsave'd by the entry stub and loaded
    /// back on the way out.
    pub fn userFpu(self: *const SyscallFrame) *align(16) const [512]u8 {
        return @ptrFromInt(@intFromPtr(self) - FPU_BELOW);
    }

    fn word(self: *const SyscallFrame, below: usize) *u64 {
        return @ptrFromInt(@intFromPtr(self) - below);
    }

    /// Leave the syscall with every register as the frame has it, and
    /// `rcx` and `r11` in those two: rcx and r11 of the frame hold rip and
    /// rflags.
    pub fn setFullRestore(self: *SyscallFrame, rcx: u64, r11: u64) void {
        self.word(FULL_RCX).* = rcx;
        self.word(FULL_R11).* = r11;
        self.word(EXIT_MODE).* = 1;
    }

    pub fn clearFullRestore(self: *SyscallFrame) void {
        self.word(EXIT_MODE).* = 0;
    }

    /// The rcx and r11 a full restore is set to load, if one is set.
    pub fn fullRestore(self: *const SyscallFrame) ?struct { rcx: u64, r11: u64 } {
        if (self.word(EXIT_MODE).* == 0) return null;
        return .{ .rcx = self.word(FULL_RCX).*, .r11 = self.word(FULL_R11).* };
    }
};

/// How far under an IrqFrame and an ExcFrame their stubs keep the FXSAVE
/// image of the interrupted code (isr_irq0: 512 + padding + its canary).
pub const IRQ0_FP_BELOW: usize = 528;
pub const EXC_FP_BELOW: usize = 512;

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
    // Routed through the single data/stack range predicate (layout.zig). Same
    // accept/reject as before on every reachable input; the unified helper
    // additionally rejects the degenerate addr==USER_SPACE_END, len==0 edge
    // (never a real signal frame) and saturates the length add.
    return memmap.userDataRangeOk(addr, len);
}

pub fn isCatchable(signo: u32) bool {
    return signo != SIGKILL and signo != SIGSTOP;
}

fn pidIndexOfPcb(pcb: *const process.PCB) usize {
    const base = @intFromPtr(&process.procs[0]);
    const off = @intFromPtr(pcb) - base;
    return off / @sizeOf(process.PCB);
}

/// Serializes a pending bit with the info that goes with it: a sender writes
/// the info and sets the bit under it, a taker clears the bit and reads the
/// info under it. Senders run in interrupt context too.
var info_lock: SpinLock = .{};

/// Record `info` for `signo` and set its bit in `set`.
fn post(set: *u64, infos: *[NSIG]Info, signo: u32, info: Info) void {
    const f = info_lock.acquireIrqSave();
    defer info_lock.releaseIrqRestore(f);
    infos[signo] = info;
    _ = @atomicRmw(u64, set, .Or, bit(signo), .seq_cst);
}

/// True if `pcb`'s process does nothing with `signo` and so needs neither
/// the bit nor a wake. A Linux task that blocks the signal keeps it: its
/// disposition may change before it is unblocked, and sigwait takes it.
fn dropsAtSend(pcb: *process.PCB, signo: u32) bool {
    if (!isCatchable(signo)) return false;
    if (pcb.personality == .linux and pcb.signal_mask & bit(signo) != 0) return false;
    const d = &dispositions(pcb)[signo];
    return d.handler == SIG_IGN or (d.handler == SIG_DFL and default_actions[signo] == .ignore);
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
    return sendInfo(target, signo, .{});
}

/// send, with what the signal carries.
pub fn sendInfo(target: u8, signo: u32, info: Info) bool {
    if (target >= process.MAX_PROCS) return false;
    if (signo >= NSIG) return false;
    const pcb = &process.procs[target];
    if (pcb.state == .unused or pcb.state == .zombie) return false;

    // Existence probe — `kill(pid, 0)` returns success iff target is live.
    if (signo == 0) return true;

    // Catchable signals that are explicitly ignored short-circuit — no need
    // to wake the target or set a pending bit. SIGKILL/SIGSTOP can't be
    // ignored, so they always set the bit.
    if (dropsAtSend(pcb, signo)) return true;

    post(&pcb.pending_signals, &pcb.sig_info, signo, info);
    afterPost(pcb, target, signo);
    return true;
}

/// A signal for a process as a whole: kill, SIGCHLD, the terminal's. `slot`
/// is any task of it. A Linux process keeps it on the lead for whichever
/// thread doesn't block it; a native one's task `slot` gets it, as with
/// send.
pub fn sendProcess(slot: u8, signo: u32, info: Info) bool {
    if (slot >= process.MAX_PROCS) return false;
    const task = &process.procs[slot];
    if (task.state == .unused or task.state == .loading) return false;
    if (task.personality != .linux) return sendInfo(slot, signo, info);
    if (signo >= NSIG) return false;
    const lead = process.leader(task);
    if (lead.state == .unused) return false;
    if (signo == 0) return true;
    if (dropsAtSend(lead, signo)) return true;

    post(&lead.shared_pending, &lead.shared_info, signo, info);
    // The thread to take it: the lead if it doesn't block the signal, else
    // any thread that doesn't. With none, it waits for an unblock.
    var taker: u8 = lead.tgid;
    if (lead.signal_mask & bit(signo) != 0 or lead.state == .zombie) {
        for (&process.procs, 0..) |*p, i| {
            if (p.state == .unused or p.state == .zombie or p.state == .loading) continue;
            if (p.tgid != lead.tgid or p.signal_mask & bit(signo) != 0) continue;
            taker = @intCast(i);
            break;
        }
    }
    afterPost(&process.procs[taker], taker, signo);
    return true;
}

/// True if `signo` is to end Linux process `lead` and can be taken now: no
/// handler, a default that ends the process, and `only` (or, without one,
/// some thread of it) not blocking it. SIGKILL always.
fn endsNow(lead: *process.PCB, signo: u32, only: ?*const process.PCB) bool {
    if (signo == SIGKILL) return true;
    if (lead.sigactions[signo].handler != SIG_DFL) return false;
    const action = default_actions[signo];
    if (action != .term and action != .core) return false;
    if (only) |t| return t.signal_mask & bit(signo) == 0;
    for (&process.procs) |*t| {
        if (t.state == .unused or t.state == .loading or t.state == .zombie or t.tgid != lead.tgid) continue;
        if (t.signal_mask & bit(signo) == 0) return true;
    }
    return false;
}

/// kill(): sendProcess from a task that may end another. A Linux process
/// the signal is to end is ended here, not at its next return to user
/// code: it may be asleep in a wait that no signal breaks. Task context
/// only — when the process is the caller's own, there is no return.
pub fn killProcess(slot: u8, signo: u32, info: Info) bool {
    if (slot >= process.MAX_PROCS or signo >= NSIG) return false;
    const task = &process.procs[slot];
    if (task.state == .unused or task.state == .loading or task.state == .zombie) return false;
    if (signo != 0 and task.personality == .linux) {
        const lead = process.leader(task);
        if (endsNow(lead, signo, null)) {
            process.killThreadGroup(lead.tgid, fatalStatus(lead, signo));
            return true;
        }
    }
    return sendProcess(slot, signo, info);
}

/// tkill(): killProcess for a signal meant for the one task `slot`.
pub fn killTask(slot: u8, signo: u32, info: Info) bool {
    if (slot >= process.MAX_PROCS or signo >= NSIG) return false;
    const task = &process.procs[slot];
    if (task.state == .unused or task.state == .loading or task.state == .zombie) return false;
    if (signo != 0 and task.personality == .linux) {
        const lead = process.leader(task);
        if (endsNow(lead, signo, task)) {
            process.killThreadGroup(lead.tgid, fatalStatus(lead, signo));
            return true;
        }
    }
    return sendInfo(slot, signo, info);
}

/// A bit for `signo` was just set where task `target` will find it: what a
/// stopped or sleeping target needs to see it.
fn afterPost(pcb: *process.PCB, target: u8, signo: u32) void {
    // The pending bit is set FIRST. Besides the wake handshake (see wake() below),
    // this ordering is load-bearing for job control: it is the SEND-side write
    // of a seq_cst store-load (Dekker) handshake with stopForJobControl. A
    // target mid-delivering a SIGSTOP on another CPU stores job_stopped=true and
    // then RE-READS pending; pairing that against our {write pending → read
    // job_stopped} below guarantees at least one side observes the other, so a
    // SIGKILL/SIGCONT can never be lost into a task that is concurrently
    // stopping (which would otherwise strand it unkillable, or with a lost
    // continue — a silent, undiagnosable hang, since pickNext skips it forever
    // and the stuck-waiter detector is .sleeping-only).
    //
    // Job-control transitions that must take effect at SEND time, because a
    // stopped target is parked off-CPU (pickNext-skipped) and can't reach a
    // signal-delivery point on its own to act on the bit we just set:
    //   - SIGCONT (default action .cont): resume now, and annihilate any
    //     still-pending stop signals (POSIX). The SIGCONT bit set above stays
    //     pending so an installed SIGCONT *handler* runs once the task resumes.
    //   - SIGKILL: resume so the task can run far enough to hit a delivery
    //     point and die (a stopped, unschedulable task is otherwise unkillable).
    // resumeFromStop's seq_cst load of job_stopped is the READ half of the
    // handshake above. No-op when the target wasn't stopped; only a real resume
    // kicks its CPU (which may be idle/tickless and otherwise slow to re-pick).
    // A Linux process stops and continues as a whole: every thread of it.
    const continues = default_actions[signo] == .cont;
    if (continues or signo == SIGKILL) {
        if (pcb.personality == .linux) {
            const lead = process.leader(pcb);
            if (continues) _ = @atomicRmw(u64, &lead.shared_pending, .And, ~STOP_SIGMASK, .seq_cst);
            for (&process.procs, 0..) |*t, i| {
                if (t.state == .unused or t.state == .loading or t.tgid != lead.tgid) continue;
                if (continues) _ = @atomicRmw(u64, &t.pending_signals, .And, ~STOP_SIGMASK, .seq_cst);
                if (resumeFromStop(t)) process.kickReschedule(@intCast(i));
            }
        } else {
            if (continues) _ = @atomicRmw(u64, &pcb.pending_signals, .And, ~STOP_SIGMASK, .seq_cst);
            if (resumeFromStop(pcb)) process.kickReschedule(target);
        }
    }

    // Make sure parked — or PARKING — processes notice. The old conditional
    // (`if .sleeping or wait_kind != .none`) raced with a target between its
    // caller-side condition check and blockOn's setWait/setState: we observed
    // .running + wait_kind==.none, skipped the wake, and the target parked
    // having missed the signal. For waits with no second waker (sigsuspend,
    // pause: wake_tick=maxInt) that's park-forever — wakeExpired only logs
    // [wake-skip], it never re-delivers. Unconditional wake() closes it:
    // wake_pending is latched even for .running targets, and every
    // blockOn-family parker re-checks wake_pending after its setState
    // (Dekker: the seq_cst OR above + wake's store vs the parker's setState).
    // State-wise wake() is still a no-op for .running/.ready, and a stale
    // latched wake_pending costs one spurious early-return at the target's
    // next blockOn — which re-checks its condition by contract.
    process.wake(target);
}

/// The signals pending for `pcb` — its own and, for a Linux task, its
/// process's — that it doesn't block.
pub fn deliverable(pcb: *const process.PCB) u64 {
    // Atomic loads — a sender on another CPU could be mid-OR. signal_mask is
    // per-thread (only mutated by this thread's syscall paths) so a plain
    // read is fine.
    var pending = @atomicLoad(u64, &pcb.pending_signals, .acquire);
    if (pcb.personality == .linux) pending |= @atomicLoad(u64, &process.procs[pcb.tgid].shared_pending, .acquire);
    return pending & ~pcb.signal_mask;
}

/// A signal taken for delivery.
pub const Taken = struct { signo: u32, info: Info };

/// Take the lowest-numbered signal `pcb` can be delivered, its own before
/// its process's: the bit is cleared and the info read as one step, so of
/// two threads only one takes a process's signal.
pub fn take(pcb: *process.PCB) ?Taken {
    return takeFrom(pcb, ~pcb.signal_mask);
}

/// Take the lowest-numbered pending signal of `set`, whether `pcb` blocks
/// it or not: what sigwait does. Its own before its process's.
pub fn takeFrom(pcb: *process.PCB, set: u64) ?Taken {
    const f = info_lock.acquireIrqSave();
    defer info_lock.releaseIrqRestore(f);
    const own = @atomicLoad(u64, &pcb.pending_signals, .acquire) & set;
    if (own != 0) {
        const signo: u32 = @ctz(own) + 1;
        _ = @atomicRmw(u64, &pcb.pending_signals, .And, ~bit(signo), .seq_cst);
        return .{ .signo = signo, .info = pcb.sig_info[signo] };
    }
    if (pcb.personality != .linux) return null;
    const lead = process.leader(pcb);
    const shared = @atomicLoad(u64, &lead.shared_pending, .acquire) & set;
    if (shared == 0) return null;
    const signo: u32 = @ctz(shared) + 1;
    _ = @atomicRmw(u64, &lead.shared_pending, .And, ~bit(signo), .seq_cst);
    return .{ .signo = signo, .info = lead.shared_info[signo] };
}

/// Put a taken signal back: its handler frame couldn't be written yet (the
/// address-space lock was busy and this path can't sleep for it), so the
/// next return to user delivers it. It comes back as the task's own.
pub fn repend(pcb: *process.PCB, t: Taken) void {
    post(&pcb.pending_signals, &pcb.sig_info, t.signo, t.info);
}

/// Drop every pending instance of `signo` in `pcb`'s process: what setting
/// a signal to be ignored does to the ones already sent.
pub fn discardPending(pcb: *process.PCB, signo: u32) void {
    const lead = process.leader(pcb);
    _ = @atomicRmw(u64, &lead.shared_pending, .And, ~bit(signo), .seq_cst);
    for (&process.procs) |*t| {
        if (t.state == .unused or t.tgid != lead.tgid) continue;
        _ = @atomicRmw(u64, &t.pending_signals, .And, ~bit(signo), .seq_cst);
    }
}

// =============================================================================
// Job control (POSIX stop/cont)
// =============================================================================

/// Bitmask of every signal whose default action is `.stop`
/// (SIGSTOP/SIGTSTP/SIGTTIN/SIGTTOU). Used to annihilate pending stop signals
/// when a SIGCONT arrives, and vice-versa — POSIX: a stop and a continue posted
/// to the same target before either is consumed cancel each other.
const STOP_SIGMASK: u64 = blk: {
    var m: u64 = 0;
    var s: u32 = 1;
    while (s < NSIG) : (s += 1) {
        if (default_actions[s] == .stop) m |= bit(s);
    }
    break :blk m;
};
const CONT_BIT: u64 = bit(SIGCONT);
const KILL_BIT: u64 = bit(SIGKILL);

/// The pending signals that undo a stop, wherever `pcb` would find them.
fn pendingResume(pcb: *const process.PCB) bool {
    var pending = @atomicLoad(u64, &pcb.pending_signals, .seq_cst);
    if (pcb.personality == .linux) pending |= @atomicLoad(u64, &process.procs[pcb.tgid].shared_pending, .seq_cst);
    return pending & (KILL_BIT | CONT_BIT) != 0;
}

/// Realize a job-control stop on the CURRENT task — the `.stop` arm of
/// applyDefault, reached when a stop signal is delivered with default
/// disposition. We deschedule cooperatively: set `job_stopped` (pickNext skips
/// it) and leave the task in its normal runnable state. It keeps running until
/// the next timer tick demotes .running→.ready, where it then sits in the
/// runqueue burning zero CPU until SIGCONT or SIGKILL clears the flag in send().
/// We deliberately do NOT touch `state` here (see the PCB.job_stopped comment
/// for the running-but-marked-sleeping hazard, and why the IRQ-return delivery
/// path forbids a real park). Reschedule latency: on the IRQ-return delivery
/// path handleIRQ0 reschedules immediately after delivery; on the syscall-return
/// path there is no in-line reschedule, so a *self*-stopped task runs at most
/// one more quantum (≤1 timer tick) before the next `from_user` preempt
/// deschedules it — bounded latency, never a hang.
fn stopForJobControl(pcb: *process.PCB, signo: u32) void {
    pcb.stop_signo = @intCast(signo);
    // Store job_stopped, THEN re-read pending — the stop side of a seq_cst
    // store-load (Dekker) handshake with send(). A SIGKILL or SIGCONT that
    // landed in the window between this delivery clearing the stop's pending bit
    // and this store read job_stopped==false, so its send-side resume no-op'd;
    // the recheck below catches that and undoes our stop, so we never strand the
    // task stopped-with-a-pending-kill (unkillable — pickNext skips it forever,
    // and the stuck-waiter detector is .sleeping-only, so it is a SILENT hang)
    // or stopped-with-a-lost-continue.
    @atomicStore(bool, &pcb.job_stopped, true, .seq_cst);
    if (pendingResume(pcb)) {
        // A resume raced us: undo the stop and let delivery proceed / the task
        // die. The racing SIGKILL/SIGCONT owns the outcome — annihilate nothing.
        pcb.stop_signo = 0;
        @atomicStore(bool, &pcb.job_stopped, false, .seq_cst);
        return;
    }
    // No concurrent resume: safe to annihilate any stale pending SIGCONT
    // (POSIX stop⊥cont — only NOW, after the recheck, so we can't erase a racing
    // resumer's CONT bit before it's observed) and notify the parent.
    _ = @atomicRmw(u64, &pcb.pending_signals, .And, ~CONT_BIT, .seq_cst);
    notifyParentStateChange(pcb, CLD_STOPPED, signo);
}

/// Clear a job-control stop. Returns true iff the task was actually stopped
/// (so the caller can fire a reschedule kick only when it did real work).
/// Called from send() on SIGCONT (resume) / SIGKILL (so a stopped task can run
/// far enough to die), and from applyDefault's `.cont` residual arm.
fn resumeFromStop(pcb: *process.PCB) bool {
    // seq_cst load — the READ half of the Dekker handshake in send()/
    // stopForJobControl. Must pair with the seq_cst pending write that precedes
    // every send()-side call and the seq_cst job_stopped store on the stop side.
    if (!@atomicLoad(bool, &pcb.job_stopped, .seq_cst)) return false;
    @atomicStore(bool, &pcb.job_stopped, false, .release);
    pcb.stop_signo = 0;
    // One notice for a process: its lead's (every thread of it resumes).
    if (pcb.personality != .linux or pcb == process.leader(pcb)) notifyParentStateChange(pcb, CLD_CONTINUED, SIGCONT);
    return true;
}

/// stopForJobControl for a Linux process: the stop is the whole process's,
/// so every thread of it is marked. The others run on until their next
/// deschedule and are not picked again.
fn stopProcess(pcb: *process.PCB, signo: u32) void {
    const lead = process.leader(pcb);
    for (&process.procs) |*t| {
        if (t.state == .unused or t.state == .loading or t.state == .zombie or t.tgid != lead.tgid) continue;
        t.stop_signo = @intCast(signo);
        @atomicStore(bool, &t.job_stopped, true, .seq_cst);
    }
    // The same store-then-look as stopForJobControl: a SIGKILL or SIGCONT
    // that passed the marking undoes it.
    var raced = false;
    for (&process.procs) |*t| {
        if (t.state == .unused or t.tgid != lead.tgid) continue;
        if (pendingResume(t)) raced = true;
    }
    for (&process.procs) |*t| {
        if (t.state == .unused or t.tgid != lead.tgid) continue;
        if (raced) {
            t.stop_signo = 0;
            @atomicStore(bool, &t.job_stopped, false, .seq_cst);
        } else {
            _ = @atomicRmw(u64, &t.pending_signals, .And, ~CONT_BIT, .seq_cst);
        }
    }
    if (raced) return;
    _ = @atomicRmw(u64, &lead.shared_pending, .And, ~CONT_BIT, .seq_cst);
    notifyParentStateChange(lead, CLD_STOPPED, signo);
}

/// POSIX: a child stopping or continuing posts SIGCHLD to its parent. Sent
/// regardless of whether the parent is in waitpid — a parent on the default
/// (ignore) disposition sees no effect; one with a handler is notified, and
/// send() wakes it if the handler makes the signal deliverable. The
/// waitpid(WUNTRACED/WCONTINUED) reporting path is a separate, ABI-touching
/// follow-up (sysWaitpid has no options arg today). One level of send()
/// recursion: SIGCHLD is neither `.cont` nor SIGKILL, so it never re-enters the
/// job-control branch.
fn notifyParentStateChange(pcb: *process.PCB, code: i32, signo: u32) void {
    const parent = pcb.parent_pid;
    if (parent == 0 or parent >= process.MAX_PROCS) return;
    const ps = &process.procs[parent];
    if (ps.state == .unused or ps.state == .zombie) return;
    _ = sendProcess(parent, SIGCHLD, .{ .code = code, .pid = process.leader(pcb).pid_nr, .value = signo });
}

/// What `signo` does to `pcb` with no handler and not ignored. Does not
/// return when that ends the calling task's process.
pub fn applyDefault(pcb: *process.PCB, signo: u32) void {
    const action = default_actions[signo];
    switch (action) {
        .ignore => {},
        .stop => if (pcb.personality == .linux) stopProcess(pcb, signo) else stopForJobControl(pcb, signo),
        .cont => {
            // Default SIGCONT delivered to a RUNNING task. The prompt resume of
            // a *stopped* task happens at send() time (a stopped task is parked
            // off-CPU and can't reach this delivery point on its own), so this
            // arm is normally a no-op; it just covers the harmless residual case
            // and keeps the cont path symmetric. A user SIGCONT *handler*, if
            // installed, is run by the catchable-signal path before we ever get
            // here, so reaching this arm means default disposition.
            _ = resumeFromStop(pcb);
        },
        .term, .core => {
            // POSIX exit_group: for a multi-threaded process, a fatal default
            // action kills EVERY thread in the group, not just `pcb`. The
            // current-CPU thread is handled inside killThreadGroup's self-
            // phase (destroyCurrentWithStatus there, same dance as before).
            // For single-threaded processes pcb.tgid == self_pid and the
            // group-walk hits exactly one slot — identical behavior to the
            // pre-tgid path.
            process.killThreadGroup(pcb.tgid, fatalStatus(pcb, signo));
            if (smp.currentPid()) |cur| {
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

fn applyHandlerMaskUpdate(pcb: *process.PCB, signo: u32, sa: *const Disposition) void {
    pcb.saved_signal_mask = pcb.signal_mask;
    pcb.signal_mask |= sa.mask & ~UNBLOCKABLE;
    if ((sa.flags & SA_NODEFER) == 0) {
        pcb.signal_mask |= bit(signo) & ~UNBLOCKABLE;
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
        const taken = take(pcb) orelse return retval;
        const sig = taken.signo;

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
        switch (process.ensureSignalFrameWritable(layout.ra_va, old_user_rsp - layout.ra_va)) {
            .ok => {},
            .busy => {
                repend(pcb, taken);
                return retval;
            },
            .fault => {
                process.destroyCurrentWithStatus(0xDEAD0000 | sig);
                return retval;
            },
        }
        protect.allowUserAccess();
        const mctx_ptr: *MContext = @ptrFromInt(layout.mctx_va);
        mctx_ptr.* = .{
            .magic = MCONTEXT_MAGIC,
            .saved_mask = toNativeSet(pcb.signal_mask),
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
    if (pcb.personality == .linux) return linux_signal.irqReturn(pcb, frame);
    if (pcb.in_signal_handler) return;
    while (true) {
        const taken = take(pcb) orelse return;
        const sig = taken.signo;

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
        switch (process.ensureSignalFrameWritable(layout.ra_va, old_user_rsp - layout.ra_va)) {
            .ok => {},
            .busy => {
                repend(pcb, taken);
                return;
            },
            .fault => {
                process.destroyCurrentWithStatus(0xDEAD0000 | sig);
                return;
            },
        }
        protect.allowUserAccess();
        const mctx_ptr: *MContext = @ptrFromInt(layout.mctx_va);
        mctx_ptr.* = .{
            .magic = MCONTEXT_MAGIC,
            .saved_mask = toNativeSet(pcb.signal_mask),
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
    if (pcb.personality == .linux) return linux_signal.userFault(pcb, frame, signo, fault_addr, si_code);
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
    switch (process.ensureSignalFrameWritable(layout.ra_va, old_user_rsp - layout.ra_va)) {
        .ok => {},
        // Lock busy: return to the faulting instruction unchanged. It faults
        // again and this delivery retries; a fault's signal must not be left
        // pending to land after the instruction instead. SIGTRAP comes from
        // traps, which resume past the instruction: that one does wait.
        .busy => {
            if (signo == SIGTRAP) repend(pcb, .{ .signo = signo, .info = .{} });
            return true;
        },
        .fault => {
            process.destroyCurrentWithStatus(0xDEAD0000 | signo);
            return false;
        },
    }
    protect.allowUserAccess();
    const mctx_ptr: *MContext = @ptrFromInt(layout.mctx_va);
    mctx_ptr.* = .{
        .magic = MCONTEXT_MAGIC,
        .saved_mask = toNativeSet(pcb.signal_mask),
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

    pcb.signal_mask = fromNativeSet(saved_mask) & ~UNBLOCKABLE;
    pcb.in_signal_handler = false;

    return @truncate(ret_rax);
}

/// True if the calling process has any pending non-blocked signal whose
/// disposition isn't ignore. Used by sigsuspend / pause to decide whether
/// to park or return immediately.
pub fn hasDeliverable(pcb: *const process.PCB) bool {
    return deliverable(pcb) != 0;
}
