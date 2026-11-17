//! Linux signals: the calls that set dispositions, masks and the alternate
//! stack, and delivery to a handler in Linux's frame.
//!
//! Sending, the pending sets, the default actions and job control are the
//! signal core's (proc/signals.zig), shared with native programs. What a
//! Linux process has of its own is here:
//!
//! - Its handler gets an rt_sigframe on the user stack — the return address
//!   (the libc's restorer, which calls rt_sigreturn), a ucontext with every
//!   register and the mask as they were, a siginfo — below the 128-byte red
//!   zone, or on the sigaltstack; the FXSAVE image sits above it. The image
//!   is the one the kernel entry stub saved under its trap frame, and the
//!   handler starts with the FP state as it was.
//! - Handlers nest: only the mask holds a signal back.
//! - rt_sigreturn puts back every register, rcx and r11 too, which sysret
//!   can't: it marks the syscall frame for the entry stub's iretq exit.
//! - A call a handler interrupts returns EINTR, or runs again after the
//!   handler when it is restartable and the handler has SA_RESTART; one no
//!   handler interrupts runs again at once.

const std = @import("std");
const process = @import("../../proc/process.zig");
const signals = @import("../../proc/signals.zig");
const memmap = @import("../../mm/memmap.zig");
const usercopy = @import("../arch/usercopy.zig");
const fp = @import("../arch/fp.zig");
const sched = @import("../../proc/sched.zig");
const linux_time = @import("linux_time.zig");
const debug = @import("../../debug/debug.zig");
const perf = @import("../../debug/perf.zig");

const PCB = process.PCB;

const EINTR: i64 = 4;
const EAGAIN: i64 = 11;
const ENOMEM: i64 = 12;
const EFAULT: i64 = 14;
const EINVAL: i64 = 22;
const EPERM: i64 = 1;

inline fn err(e: i64) u64 {
    return @bitCast(-e);
}

// What a syscall body returns to say a signal cut it short, and how it may
// run again. Never seen by user code: syscallExit turns each into EINTR or
// a second run.
/// Runs again after a handler with SA_RESTART, or with no handler; else EINTR.
pub const ERESTARTSYS: i64 = 512;
/// Always runs again.
pub const ERESTARTNOINTR: i64 = 513;
/// Runs again only when no handler ran; else EINTR.
pub const ERESTARTNOHAND: i64 = 514;
/// With no handler, restart_syscall goes on with what the call left
/// (PCB.restart_until); else EINTR.
pub const ERESTART_RESTARTBLOCK: i64 = 516;
const SYS_restart_syscall: u64 = 219;

// --- User structures (x86-64) --------------------------------------------------

/// struct sigaction as the kernel takes it.
const KSigaction = extern struct { handler: u64, flags: u64, restorer: u64, mask: u64 };

const StackT = extern struct { sp: u64, flags: i32, _pad: u32 = 0, size: u64 };
const SS_ONSTACK: i32 = 1;
const SS_DISABLE: i32 = 2;
const SS_AUTODISARM: i32 = @bitCast(@as(u32, 1 << 31));
const MINSIGSTKSZ: u64 = 2048;

/// struct sigcontext: the registers, in the kernel's order.
const Sigcontext = extern struct {
    r8: u64 = 0,
    r9: u64 = 0,
    r10: u64 = 0,
    r11: u64 = 0,
    r12: u64 = 0,
    r13: u64 = 0,
    r14: u64 = 0,
    r15: u64 = 0,
    rdi: u64 = 0,
    rsi: u64 = 0,
    rbp: u64 = 0,
    rbx: u64 = 0,
    rdx: u64 = 0,
    rax: u64 = 0,
    rcx: u64 = 0,
    rsp: u64 = 0,
    rip: u64 = 0,
    eflags: u64 = 0,
    cs: u16 = USER_CS,
    gs: u16 = 0,
    fs: u16 = 0,
    ss: u16 = USER_SS,
    err: u64 = 0,
    trapno: u64 = 0,
    oldmask: u64 = 0,
    cr2: u64 = 0,
    fpstate: u64 = 0,
    reserved1: [8]u64 = [_]u64{0} ** 8,
};

const Ucontext = extern struct {
    flags: u64 = 0,
    link: u64 = 0,
    stack: StackT,
    mcontext: Sigcontext,
    sigmask: u64,
};

/// siginfo_t: three ints, then fields by the kind of signal.
const Siginfo = extern struct {
    signo: i32,
    errno: i32 = 0,
    code: i32,
    _pad: i32 = 0,
    fields: [14]u64 = [_]u64{0} ** 14,
};

const RtSigframe = extern struct {
    pretcode: u64,
    uc: Ucontext,
    info: Siginfo,
};

comptime {
    std.debug.assert(@sizeOf(Sigcontext) == 256);
    std.debug.assert(@sizeOf(Ucontext) == 304);
    std.debug.assert(@sizeOf(Siginfo) == 128);
    std.debug.assert(@sizeOf(RtSigframe) == 440);
}

const USER_CS: u16 = 0x23;
const USER_SS: u16 = 0x1B;
const RED_ZONE: u64 = 128;
const FP_BYTES: u64 = 512;

// With AVX the frame's FP state is laid out as Linux's XSAVE one: the
// FXSAVE image, whose software bytes (from SW_AT) say what follows, the
// XSAVE header, the AVX component, and MAGIC2 after the lot.
const FP_XSTATE_MAGIC1: u32 = 0x46505853;
const FP_XSTATE_MAGIC2: u32 = 0x46505845;
/// FXSAVE writes nothing from here on.
const FX_USED: usize = 416;
const SW_AT: usize = 464;
const XHEADER_AT: usize = 512;
const YMM_AT: usize = 576;
/// The XSAVE layout's size, legacy region to the end of the AVX component.
const XSTATE_BYTES: usize = YMM_AT + fp.UPPER_BYTES;
const XFRAME_BYTES: usize = XSTATE_BYTES + 4;
/// x87, SSE and AVX: the features in that layout.
const XFEATURES: u64 = 0b111;
const XFEATURE_AVX: u64 = 1 << 2;
/// uc_flags: the FP state has the XSAVE layout.
const UC_FP_XSTATE: u64 = 1;

const userFlags = signals.userFlags;

// --- rt_sigaction, rt_sigprocmask, rt_sigpending, sigaltstack -----------------

fn ignoredNow(signo: u32, handler: u64) bool {
    return handler == signals.SIG_IGN or (handler == signals.SIG_DFL and signals.default_actions[signo] == .ignore);
}

/// rt_sigaction(sig, act, oldact, sigsetsize). The dispositions are the
/// process's: every thread of it sees them.
pub fn rtSigaction(sig: u64, act_va: u64, old_va: u64, size: u64) u64 {
    if (size != 8 or sig == 0 or sig >= signals.NSIG) return err(EINVAL);
    const signo: u32 = @intCast(sig);
    const pcb = process.currentPCB() orelse return err(EFAULT);
    const slot = &signals.dispositions(pcb)[signo];
    var new: KSigaction = undefined;
    if (act_va != 0) {
        if (!signals.isCatchable(signo)) return err(EINVAL);
        if (!usercopy.copyFromUser(std.mem.asBytes(&new), act_va)) return err(EFAULT);
    }
    if (old_va != 0) {
        const old = slot.*;
        const out = KSigaction{ .handler = old.handler, .flags = old.flags, .restorer = old.restorer, .mask = old.mask };
        if (!usercopy.copyToUser(old_va, std.mem.asBytes(&out))) return err(EFAULT);
    }
    if (act_va != 0) {
        slot.* = .{
            .handler = new.handler,
            .flags = @truncate(new.flags),
            .restorer = new.restorer,
            .mask = new.mask & ~signals.UNBLOCKABLE,
        };
        // A signal set to be ignored takes the ones already sent with it.
        if (ignoredNow(signo, new.handler)) signals.discardPending(pcb, signo);
    }
    return 0;
}

const SIG_BLOCK: u64 = 0;
const SIG_UNBLOCK: u64 = 1;
const SIG_SETMASK: u64 = 2;

/// rt_sigprocmask(how, set, oldset, sigsetsize): the calling thread's mask.
/// A signal it unblocks is delivered on the way out of the call.
pub fn rtSigprocmask(how: u64, set_va: u64, old_va: u64, size: u64) u64 {
    if (size != 8) return err(EINVAL);
    const pcb = process.currentPCB() orelse return err(EFAULT);
    const old = pcb.signal_mask;
    if (set_va != 0) {
        var set: u64 = 0;
        if (!usercopy.copyFromUser(std.mem.asBytes(&set), set_va)) return err(EFAULT);
        set &= ~signals.UNBLOCKABLE;
        const new = switch (how) {
            SIG_BLOCK => old | set,
            SIG_UNBLOCK => old & ~set,
            SIG_SETMASK => set,
            else => return err(EINVAL),
        };
        if (old_va != 0 and !usercopy.copyToUser(old_va, std.mem.asBytes(&old))) return err(EFAULT);
        pcb.signal_mask = new;
        return 0;
    }
    if (old_va != 0 and !usercopy.copyToUser(old_va, std.mem.asBytes(&old))) return err(EFAULT);
    return 0;
}

/// rt_sigpending(set, sigsetsize): what is pending for the thread and
/// blocked by it.
pub fn rtSigpending(set_va: u64, size: u64) u64 {
    if (size > 8) return err(EINVAL);
    const pcb = process.currentPCB() orelse return err(EFAULT);
    var pending = @atomicLoad(u64, &pcb.pending_signals, .acquire);
    pending |= @atomicLoad(u64, &process.leader(pcb).shared_pending, .acquire);
    pending &= pcb.signal_mask;
    if (!usercopy.copyToUser(set_va, std.mem.asBytes(&pending)[0..@intCast(size)])) return err(EFAULT);
    return 0;
}

fn stackOf(alt: signals.AltStack, user_rsp: u64) StackT {
    if (alt.size == 0) return .{ .sp = 0, .flags = SS_DISABLE, .size = 0 };
    var flags: i32 = if (alt.holds(user_rsp)) SS_ONSTACK else 0;
    if (alt.autodisarm) flags |= SS_AUTODISARM;
    return .{ .sp = alt.sp, .flags = flags, .size = alt.size };
}

/// sigaltstack(ss, old_ss): the calling thread's stack for SA_ONSTACK
/// handlers. `user_rsp` is where the caller runs: not to be changed from a
/// handler on that stack.
pub fn sigaltstack(ss_va: u64, old_va: u64, user_rsp: u64) u64 {
    const pcb = process.currentPCB() orelse return err(EFAULT);
    const now = pcb.alt_stack;
    var new: StackT = undefined;
    if (ss_va != 0) {
        if (!usercopy.copyFromUser(std.mem.asBytes(&new), ss_va)) return err(EFAULT);
        if (new.flags & ~(SS_DISABLE | SS_AUTODISARM) != 0) return err(EINVAL);
        if (now.holds(user_rsp)) return err(EPERM);
        if (new.flags & SS_DISABLE == 0) {
            if (new.size < MINSIGSTKSZ) return err(ENOMEM);
            if (!memmap.userDataRangeOk(new.sp, new.size)) return err(EFAULT);
        }
    }
    if (old_va != 0) {
        const old = stackOf(now, user_rsp);
        if (!usercopy.copyToUser(old_va, std.mem.asBytes(&old))) return err(EFAULT);
    }
    if (ss_va != 0) {
        pcb.alt_stack = if (new.flags & SS_DISABLE != 0)
            .{}
        else
            .{ .sp = new.sp, .size = new.size, .autodisarm = new.flags & SS_AUTODISARM != 0 };
    }
    return 0;
}

// --- Waiting for a signal -----------------------------------------------------

/// Sleep until the caller has a signal to take. Only a sender wakes it
/// (signals' afterPost): the wait is a poll of nothing.
fn sleepUntilSignal(pcb: *PCB) void {
    defer @atomicStore(u64, &pcb.wake_tick, 0, .release);
    while (signals.deliverable(pcb) == 0) sched.blockOnDeadline(.poll, 0, 0);
}

/// pause(): until a handler has run (then EINTR) or a signal ends the
/// process.
pub fn pause() u64 {
    const pcb = process.currentPCB() orelse return err(EFAULT);
    sleepUntilSignal(pcb);
    return err(ERESTARTNOHAND);
}

/// rt_sigsuspend(mask, sigsetsize): pause() with `mask` as the thread's mask
/// for the wait, and the old one back when the handler returns.
pub fn rtSigsuspend(mask_va: u64, size: u64) u64 {
    if (size != 8) return err(EINVAL);
    const pcb = process.currentPCB() orelse return err(EFAULT);
    var mask: u64 = 0;
    if (!usercopy.copyFromUser(std.mem.asBytes(&mask), mask_va)) return err(EFAULT);
    waitUnderMask(pcb, mask);
    sleepUntilSignal(pcb);
    return err(ERESTARTNOHAND);
}

const Timespec = extern struct { sec: i64, nsec: i64 };

/// rt_sigtimedwait(set, info, timeout, sigsetsize): take a pending signal of
/// `set` — one the caller blocks, as a rule — without running a handler;
/// wait for one up to `timeout` (null: for good). Returns its number.
pub fn rtSigtimedwait(set_va: u64, info_va: u64, timeout_va: u64, size: u64) u64 {
    if (size != 8) return err(EINVAL);
    const pcb = process.currentPCB() orelse return err(EFAULT);
    var set: u64 = 0;
    if (!usercopy.copyFromUser(std.mem.asBytes(&set), set_va)) return err(EFAULT);
    set &= ~signals.UNBLOCKABLE;
    var deadline: u64 = 0;
    var poll_only = false;
    if (timeout_va != 0) {
        var ts: Timespec = undefined;
        if (!usercopy.copyFromUser(std.mem.asBytes(&ts), timeout_va)) return err(EFAULT);
        if (ts.sec < 0 or ts.nsec < 0 or ts.nsec >= 1_000_000_000) return err(EINVAL);
        const ns = @as(u64, @intCast(ts.sec)) *| 1_000_000_000 +| @as(u64, @intCast(ts.nsec));
        poll_only = ns == 0;
        const ticks = std.math.divCeil(u64, ns, linux_time.TICK_NS) catch unreachable;
        deadline = process.tick_count +| ticks +| 1;
    }

    // While it waits, the caller counts as taking these: a process's signal
    // of the set is sent its way (signals.sendProcess picks a thread that
    // doesn't block it). No handler runs meanwhile — the mask is back
    // before the call's way out.
    // sigwait_set goes up first and comes down last: a sender that finds
    // the signal unblocked here also finds the wait that takes it.
    const mask = pcb.signal_mask;
    @atomicStore(u64, &pcb.sigwait_set, set, .seq_cst);
    @atomicStore(u64, &pcb.signal_mask, mask & ~set, .release);
    defer {
        @atomicStore(u64, &pcb.signal_mask, mask, .release);
        @atomicStore(u64, &pcb.sigwait_set, 0, .seq_cst);
        @atomicStore(u64, &pcb.wake_tick, 0, .release);
    }
    while (true) {
        if (signals.takeFrom(pcb, set)) |t| {
            if (info_va != 0) {
                const si = siginfoOf(t, .{});
                if (!usercopy.copyToUser(info_va, std.mem.asBytes(&si))) return err(EFAULT);
            }
            return t.signo;
        }
        if (poll_only or (deadline != 0 and process.tick_count >= deadline)) return err(EAGAIN);
        // A signal outside the set, with a handler to run.
        if (signals.deliverable(pcb) & ~set & ~mask != 0) return err(EINTR);
        sched.blockOnDeadline(.poll, 0, deadline);
    }
}

// --- alarm, setitimer ------------------------------------------------------------

const TICK_USEC: u64 = linux_time.TICK_NS / 1000;
const Timeval = extern struct { sec: i64, usec: i64 };
const Itimerval = extern struct { interval: Timeval, value: Timeval };
const ITIMER_REAL: u64 = 0;

fn ticksOf(tv: Timeval) ?u64 {
    if (tv.sec < 0 or tv.usec < 0 or tv.usec >= 1_000_000) return null;
    const usec = @as(u64, @intCast(tv.sec)) *| 1_000_000 +| @as(u64, @intCast(tv.usec));
    return std.math.divCeil(u64, usec, TICK_USEC) catch unreachable;
}

fn timevalOf(ticks: u64) Timeval {
    const usec = ticks *| TICK_USEC;
    return .{ .sec = @intCast(usec / 1_000_000), .usec = @intCast(usec % 1_000_000) };
}

/// The process's real-time timer as it stands: ticks to the next SIGALRM
/// (0: not armed) and between the ones after.
fn timerNow(lead: *PCB) struct { left: u64, every: u64 } {
    const at = @atomicLoad(u64, &lead.alarm_tick, .acquire);
    const now = process.tick_count;
    return .{
        .left = if (at == 0) 0 else if (at > now) at - now else 1,
        .every = @atomicLoad(u64, &lead.alarm_interval, .acquire),
    };
}

/// Arm the timer: SIGALRM for the process in `first` ticks (0: disarm), then
/// every `every` (0: once).
fn armTimer(lead: *PCB, first: u64, every: u64) void {
    @atomicStore(u64, &lead.alarm_interval, if (first == 0) 0 else every, .release);
    if (first == 0) {
        @atomicStore(u64, &lead.alarm_tick, 0, .release);
        return;
    }
    const deadline = process.tick_count + first;
    @atomicStore(u64, &lead.alarm_tick, deadline, .release);
    sched.registerAlarmDeadline(deadline);
}

/// alarm(seconds): SIGALRM for the process in `seconds`, 0 to call it off.
/// Returns the seconds the last alarm had left.
pub fn alarm(seconds: u64) u64 {
    const lead = process.leader(process.currentPCB() orelse return 0);
    const was = timerNow(lead);
    const ticks_per_sec = 1_000_000 / TICK_USEC;
    armTimer(lead, (seconds & 0xFFFF_FFFF) * ticks_per_sec, 0);
    return std.math.divCeil(u64, was.left, ticks_per_sec) catch unreachable;
}

/// setitimer(which, new, old): the real-time timer, the one that counts
/// wall time and sends SIGALRM. The others (process CPU time) are not kept.
pub fn setitimer(which: u64, new_va: u64, old_va: u64) u64 {
    if (which != ITIMER_REAL) return err(EINVAL);
    const lead = process.leader(process.currentPCB() orelse return err(EFAULT));
    var new: Itimerval = undefined;
    if (new_va != 0 and !usercopy.copyFromUser(std.mem.asBytes(&new), new_va)) return err(EFAULT);
    const first = if (new_va != 0) (ticksOf(new.value) orelse return err(EINVAL)) else 0;
    const every = if (new_va != 0) (ticksOf(new.interval) orelse return err(EINVAL)) else 0;
    if (old_va != 0) {
        const was = timerNow(lead);
        const old = Itimerval{ .interval = timevalOf(was.every), .value = timevalOf(was.left) };
        if (!usercopy.copyToUser(old_va, std.mem.asBytes(&old))) return err(EFAULT);
    }
    armTimer(lead, first, every);
    return 0;
}

/// getitimer(which, value).
pub fn getitimer(which: u64, cur_va: u64) u64 {
    if (which != ITIMER_REAL) return err(EINVAL);
    const lead = process.leader(process.currentPCB() orelse return err(EFAULT));
    const now = timerNow(lead);
    const cur = Itimerval{ .interval = timevalOf(now.every), .value = timevalOf(now.left) };
    if (!usercopy.copyToUser(cur_va, std.mem.asBytes(&cur))) return err(EFAULT);
    return 0;
}

// --- The frame ----------------------------------------------------------------

/// A handler to run: the signal taken for it and the disposition as it was
/// then.
const Delivery = struct { taken: signals.Taken, disp: signals.Disposition };

/// What a fault adds to the frame.
const Fault = struct { addr: u64 = 0, err: u64 = 0, trapno: u64 = 0 };

/// Where a pushed frame is: the handler's stack pointer and its arguments.
const Entry = struct { rsp: u64, info: u64, uc: u64 };

const Push = union(enum) { ok: Entry, busy, fault };

/// The next signal that has a handler to run. Those ignored are dropped and
/// those with no handler take their default on the way — which may end the
/// process: no return then.
fn nextHandler(pcb: *PCB, may_park: bool) ?Delivery {
    while (true) {
        const t = signals.take(pcb) orelse return null;
        const d = signals.dispositions(pcb)[t.signo];
        if (!signals.isCatchable(t.signo) or d.handler == signals.SIG_DFL) {
            signals.applyDefault(pcb, t.signo);
            if (may_park) waitWhileStopped(pcb);
            continue;
        }
        if (d.handler == signals.SIG_IGN) continue;
        return .{ .taken = t, .disp = d };
    }
}

/// A stopped task runs no more of its code: it stays off the CPU here (the
/// pickers skip it) until SIGCONT or SIGKILL, and then takes what is pending.
/// Task context only; an interrupt's way out reschedules on its own.
fn waitWhileStopped(pcb: *PCB) void {
    if (!@atomicLoad(bool, &pcb.job_stopped, .acquire)) return;
    // The stop is not the syscall's time.
    const t0 = perf.rdtsc();
    while (@atomicLoad(bool, &pcb.job_stopped, .acquire)) process.schedule();
    pcb.perf_gap_cyc +%= perf.rdtsc() -% t0;
}

fn siginfoOf(t: signals.Taken, fault: Fault) Siginfo {
    var si = Siginfo{ .signo = @intCast(t.signo), .code = t.info.code };
    switch (t.signo) {
        // si_addr.
        signals.SIGSEGV, signals.SIGBUS, signals.SIGILL, signals.SIGFPE, signals.SIGTRAP => if (t.info.code > 0) {
            si.fields[0] = fault.addr;
            return si;
        },
        // si_pid and si_uid, si_status.
        signals.SIGCHLD => {
            si.fields[0] = t.info.pid;
            si.fields[1] = t.info.value & 0xFFFF_FFFF;
            return si;
        },
        else => {},
    }
    // si_pid and si_uid, si_value.
    si.fields[0] = t.info.pid;
    si.fields[1] = t.info.value;
    return si;
}

/// Lay the frame for `d` on the user stack of a task interrupted with the
/// registers `regs` and the FP state `fp_image`; `mask` is the one the
/// handler's return puts back. `.busy`: the address-space lock couldn't be
/// had in this context; nothing is written.
fn pushFrame(pcb: *PCB, regs: *const Sigcontext, fp_image: *const [512]u8, d: Delivery, fault: Fault, mask: u64) Push {
    const alt = pcb.alt_stack;
    const switch_stack = d.disp.flags & signals.SA_ONSTACK != 0 and alt.size != 0 and !alt.holds(regs.rsp);
    const top: u64 = if (switch_stack) alt.sp + alt.size else regs.rsp -% RED_ZONE;
    const fp_len: u64 = if (fp.avx) XFRAME_BYTES else FP_BYTES;
    const fp_va = (top -% fp_len) & ~@as(u64, 63);
    // The handler is entered as by a call: its rsp + 8 is 16-aligned.
    const frame_va = ((fp_va -% @sizeOf(RtSigframe)) & ~@as(u64, 15)) -% 8;
    // Under two kilobytes whatever rsp was; the range check takes care of
    // a stack pointer that points nowhere.
    const span = (fp_va +% fp_len) -% frame_va;
    if (!memmap.userDataRangeOk(frame_va, span)) return .fault;
    switch (process.ensureSignalFrameWritable(frame_va, span)) {
        .ok => {},
        .busy => return .busy,
        .fault => return .fault,
    }

    var frame = RtSigframe{
        .pretcode = d.disp.restorer,
        .uc = .{
            .stack = stackOf(alt, regs.rsp),
            .mcontext = regs.*,
            .sigmask = mask,
        },
        .info = siginfoOf(d.taken, fault),
    };
    frame.uc.mcontext.err = fault.err;
    frame.uc.mcontext.trapno = fault.trapno;
    frame.uc.mcontext.cr2 = fault.addr;
    frame.uc.mcontext.oldmask = mask;
    frame.uc.mcontext.fpstate = fp_va;
    if (fp.avx) frame.uc.flags = UC_FP_XSTATE;

    var fp_buf: [XFRAME_BYTES]u8 = undefined;
    const fp_state = fpState(&fp_buf, fp_image);
    std.debug.assert(fp_state.len == fp_len);

    // The pages were just made present and writable; one taken away since
    // (a sibling's munmap) cuts the copy short, and the signal can't be
    // delivered.
    if (usercopy.copyToUserRaw(fp_va, fp_state) != fp_len) return .fault;
    if (usercopy.copyToUserRaw(frame_va, std.mem.asBytes(&frame)) != @sizeOf(RtSigframe)) return .fault;

    if (switch_stack and alt.autodisarm) pcb.alt_stack = .{};
    return .{ .ok = .{
        .rsp = frame_va,
        .info = frame_va + @offsetOf(RtSigframe, "info"),
        .uc = frame_va + @offsetOf(RtSigframe, "uc"),
    } };
}

/// The frame's FP state, built in `buf` from the entry's FXSAVE image and,
/// with AVX, the live upper YMM halves: the calling task's, as the kernel
/// leaves them alone.
fn fpState(buf: *[XFRAME_BYTES]u8, fx: *const [512]u8) []const u8 {
    // The rest of the image is whatever the kernel stack held.
    @memcpy(buf[0..FX_USED], fx[0..FX_USED]);
    @memset(buf[FX_USED..XFRAME_BYTES], 0);
    if (!fp.avx) return buf[0..FP_BYTES];
    std.mem.writeInt(u32, buf[SW_AT..][0..4], FP_XSTATE_MAGIC1, .little);
    std.mem.writeInt(u32, buf[SW_AT + 4 ..][0..4], XFRAME_BYTES, .little);
    std.mem.writeInt(u64, buf[SW_AT + 8 ..][0..8], XFEATURES, .little);
    std.mem.writeInt(u32, buf[SW_AT + 16 ..][0..4], XSTATE_BYTES, .little);
    const in_use = fp.saveUpper(buf[YMM_AT..][0..fp.UPPER_BYTES]);
    const bv: u64 = if (in_use) XFEATURES else XFEATURES & ~XFEATURE_AVX;
    std.mem.writeInt(u64, buf[XHEADER_AT..][0..8], bv, .little);
    std.mem.writeInt(u32, buf[XSTATE_BYTES..][0..4], FP_XSTATE_MAGIC2, .little);
    return buf;
}

/// A handler starts with the FP state of a new image, as on Linux; the one
/// it interrupted is in its frame.
fn freshFp(image: *[512]u8) void {
    @memcpy(image, &fp.init_template);
    fp.loadUpper(null);
}

/// The handler for `d` is about to run on its frame: its mask goes on, and
/// a one-shot disposition goes back to the default.
fn enterHandler(pcb: *PCB, d: Delivery) void {
    var add = d.disp.mask;
    if (d.disp.flags & signals.SA_NODEFER == 0) add |= signals.bit(d.taken.signo);
    pcb.signal_mask |= add & ~signals.UNBLOCKABLE;
    if (d.disp.flags & signals.SA_RESETHAND != 0) {
        const slot = &signals.dispositions(pcb)[d.taken.signo];
        if (slot.handler == d.disp.handler) slot.* = .{};
    }
}

/// A frame that can't be written — no stack left, or not a stack at all —
/// ends the process as a SIGSEGV nothing caught does.
fn frameLost(pcb: *PCB, signo: u32) noreturn {
    debug.klog("[linux] pid={d} no room for the frame of signal {d}'s handler — killing the process\n", .{ process.getCurrentPid(), signo });
    process.killThreadGroup(pcb.tgid, signals.fatalStatus(pcb, signals.SIGSEGV));
    process.schedule();
    unreachable;
}

// --- Delivery at the three ways back to user code -----------------------------

fn restartable(ret: u64) i64 {
    const e: i64 = -@as(i64, @bitCast(ret));
    return if (e == ERESTARTSYS or e == ERESTARTNOINTR or e == ERESTARTNOHAND or e == ERESTART_RESTARTBLOCK) e else 0;
}

/// The length of the `syscall` instruction: what a call that runs again
/// steps back over.
const SYSCALL_INSN: u64 = 2;

/// The call is over with no handler to run: a mask it waited under gives
/// way to the caller's.
fn endOwnMask(pcb: *PCB) void {
    if (!pcb.restore_mask) return;
    pcb.restore_mask = false;
    pcb.signal_mask = pcb.saved_signal_mask;
}

/// For the rest of the call the thread's mask is `mask`; syscallExit puts
/// the caller's back — after the handler, when one runs.
pub fn waitUnderMask(pcb: *PCB, mask: u64) void {
    pcb.saved_signal_mask = pcb.signal_mask;
    pcb.restore_mask = true;
    pcb.signal_mask = mask & ~signals.UNBLOCKABLE;
}

/// No handler runs. A call a signal cut short (`again`) is run again: the
/// caller returns to its `syscall` instruction with the call's number.
fn runAgain(frame: *signals.SyscallFrame, sys_num: u32, ret: u64, again: i64) u64 {
    if (again == 0) return ret;
    frame.rcx -%= SYSCALL_INSN;
    return if (again == ERESTART_RESTARTBLOCK) SYS_restart_syscall else sys_num;
}

/// The way out of Linux syscall `sys_num`, which returned `ret`: deliver a
/// pending signal to its handler, and settle a call a signal cut short
/// (`ret` is taken for one of the restart codes only with `may_restart`:
/// rt_sigreturn's is a register it put back). Returns what goes to the
/// caller's rax. Called with interrupts on.
pub fn syscallExit(pcb: *PCB, frame: *signals.SyscallFrame, sys_num: u32, ret: u64, may_restart: bool) u64 {
    // Another thread stopped the process while this one was in the call.
    waitWhileStopped(pcb);
    const again = if (may_restart) restartable(ret) else 0;
    if (again == 0 and signals.deliverable(pcb) == 0) {
        endOwnMask(pcb);
        return ret;
    }

    const d = nextHandler(pcb, true) orelse {
        endOwnMask(pcb);
        return runAgain(frame, sys_num, ret, again);
    };
    // A call that waited under a mask of its own (rt_sigsuspend, ppoll): the
    // handler runs under that mask still, and returns to the caller's.
    const back_to_mask = if (pcb.restore_mask) pcb.saved_signal_mask else pcb.signal_mask;

    // The interrupted state is the caller's just after the call returned —
    // or just before it, for one that runs again when the handler is done.
    // After rt_sigreturn it is the state that call put back.
    const full = frame.fullRestore();
    var regs = Sigcontext{
        .r8 = frame.r8,
        .r9 = frame.r9,
        .r10 = frame.r10,
        .r11 = if (full) |f| f.r11 else frame.r11,
        .r12 = frame.r12,
        .r13 = frame.r13,
        .r14 = frame.r14,
        .r15 = frame.r15,
        .rdi = frame.rdi,
        .rsi = frame.rsi,
        .rbp = frame.rbp,
        .rbx = frame.rbx,
        .rdx = frame.rdx,
        .rax = ret,
        .rcx = if (full) |f| f.rcx else frame.rcx,
        .rsp = frame.user_rsp,
        .rip = frame.rcx,
        .eflags = frame.r11,
    };
    if (again != 0) {
        const runs_again = again == ERESTARTNOINTR or
            (again == ERESTARTSYS and d.disp.flags & signals.SA_RESTART != 0);
        if (runs_again) {
            regs.rip -%= SYSCALL_INSN;
            regs.rax = sys_num;
        } else {
            regs.rax = err(EINTR);
        }
    }

    const entry = switch (pushFrame(pcb, &regs, frame.userFpu(), d, .{}, back_to_mask)) {
        .ok => |e| e,
        // Not with interrupts on, where the lock is waited for; were it to
        // happen, the signal waits for the next way out.
        .busy => {
            signals.repend(pcb, d.taken);
            endOwnMask(pcb);
            return runAgain(frame, sys_num, ret, again);
        },
        .fault => frameLost(pcb, d.taken.signo),
    };
    pcb.restore_mask = false;
    enterHandler(pcb, d);
    freshFp(@constCast(frame.userFpu()));
    // The handler is entered by sysret: rcx and r11 are its to lose.
    frame.clearFullRestore();
    frame.rcx = d.disp.handler;
    frame.r11 = userFlags(frame.r11) & ~@as(u64, 0x500); // TF and DF off
    frame.rdi = d.taken.signo;
    frame.rsi = entry.info;
    frame.rdx = entry.uc;
    frame.user_rsp = entry.rsp;
    return 0;
}

/// A timer interrupt is about to return to user code of `pcb`, which has a
/// signal to take.
pub fn irqReturn(pcb: *PCB, frame: *signals.IrqFrame) void {
    const d = nextHandler(pcb, false) orelse return;
    const regs = Sigcontext{
        .r8 = frame.r8,
        .r9 = frame.r9,
        .r10 = frame.r10,
        .r11 = frame.r11,
        .r12 = frame.r12,
        .r13 = frame.r13,
        .r14 = frame.r14,
        .r15 = frame.r15,
        .rdi = frame.rdi,
        .rsi = frame.rsi,
        .rbp = frame.rbp,
        .rbx = frame.rbx,
        .rdx = frame.rdx,
        .rax = frame.rax,
        .rcx = frame.rcx,
        .rsp = frame.rsp,
        .rip = frame.rip,
        .eflags = frame.rflags,
    };
    const fp_image: *[512]u8 = @ptrFromInt(@intFromPtr(frame) - signals.IRQ0_FP_BELOW);
    const entry = switch (pushFrame(pcb, &regs, fp_image, d, .{}, pcb.signal_mask)) {
        .ok => |e| e,
        // Interrupts are off here and the lock is held: the next return to
        // user code tries again.
        .busy => return signals.repend(pcb, d.taken),
        .fault => frameLost(pcb, d.taken.signo),
    };
    enterHandler(pcb, d);
    freshFp(fp_image);
    frame.rip = d.disp.handler;
    frame.rsp = entry.rsp;
    frame.rflags = userFlags(frame.rflags) & ~@as(u64, 0x500);
    frame.rdi = d.taken.signo;
    frame.rsi = entry.info;
    frame.rdx = entry.uc;
    frame.rax = 0;
    // The frame the interrupt returns through was rewritten on purpose.
    @import("../../debug/iretq_canary.zig").refresh();
}

/// A fault in user code of `pcb` raised `signo`. True if its handler was
/// set up to run; false if there is none to — the signal is blocked,
/// ignored or left to its default, each of which ends the process for a
/// fault — or its frame couldn't be written.
pub fn userFault(pcb: *PCB, frame: *signals.ExcFrame, signo: u32, addr: u64, code: u32) bool {
    if (signo == 0 or signo >= signals.NSIG or !signals.isCatchable(signo)) return false;
    const disp = signals.dispositions(pcb)[signo];
    if (disp.handler == signals.SIG_DFL or disp.handler == signals.SIG_IGN) return false;
    if (pcb.signal_mask & signals.bit(signo) != 0) return false;

    const d = Delivery{
        .taken = .{ .signo = signo, .info = .{ .code = @bitCast(code) } },
        .disp = disp,
    };
    const regs = Sigcontext{
        .r8 = frame.r8,
        .r9 = frame.r9,
        .r10 = frame.r10,
        .r11 = frame.r11,
        .r12 = frame.r12,
        .r13 = frame.r13,
        .r14 = frame.r14,
        .r15 = frame.r15,
        .rdi = frame.rdi,
        .rsi = frame.rsi,
        .rbp = frame.rbp,
        .rbx = frame.rbx,
        .rdx = frame.rdx,
        .rax = frame.rax,
        .rcx = frame.rcx,
        .rsp = frame.rsp,
        .rip = frame.rip,
        .eflags = frame.rflags,
    };
    const fp_image: *[512]u8 = @ptrFromInt(@intFromPtr(frame) - signals.EXC_FP_BELOW);
    const what = Fault{ .addr = addr, .err = frame.error_code, .trapno = frame.int_no };
    const entry = switch (pushFrame(pcb, &regs, fp_image, d, what, pcb.signal_mask)) {
        .ok => |e| e,
        // The caller turned interrupts on, so the lock was waited for.
        .busy, .fault => return false,
    };
    enterHandler(pcb, d);
    freshFp(fp_image);
    frame.rip = disp.handler;
    frame.rsp = entry.rsp;
    frame.rflags = userFlags(frame.rflags) & ~@as(u64, 0x500);
    frame.rdi = signo;
    frame.rsi = entry.info;
    frame.rdx = entry.uc;
    frame.rax = 0;
    return true;
}

// --- rt_sigreturn -------------------------------------------------------------

/// MXCSR bits a program may set; fxrstor faults on the others.
fn mxcsrMask() u32 {
    const m = std.mem.readInt(u32, fp.init_template[28..32], .little);
    return if (m == 0) 0xFFBF else m;
}

/// What a frame's FP state gives the upper YMM halves.
const Upper = enum { given, init, bad };

/// The upper YMM halves from the frame's FP state at `va`, whose FXSAVE
/// image is `fx`: into `ymm` (.given), or the init state — an image with
/// no XSAVE layout after it or no AVX in it, which Linux takes for an
/// FXSAVE-only one. `.bad`: a part that can't be read.
fn upperOf(va: u64, fx: *const [512]u8, ymm: *[fp.UPPER_BYTES]u8) Upper {
    if (std.mem.readInt(u32, fx[SW_AT..][0..4], .little) != FP_XSTATE_MAGIC1) return .init;
    const extended = std.mem.readInt(u32, fx[SW_AT + 4 ..][0..4], .little);
    const features = std.mem.readInt(u64, fx[SW_AT + 8 ..][0..8], .little);
    const size = std.mem.readInt(u32, fx[SW_AT + 16 ..][0..4], .little);
    if (size < YMM_AT or size > XSTATE_BYTES or size > extended) return .init;
    var magic2: [4]u8 = undefined;
    if (!usercopy.copyFromUser(&magic2, va +% size)) return .bad;
    if (std.mem.readInt(u32, &magic2, .little) != FP_XSTATE_MAGIC2) return .init;
    if (features & XFEATURE_AVX == 0 or size < XSTATE_BYTES) return .init;
    var bv: [8]u8 = undefined;
    if (!usercopy.copyFromUser(&bv, va +% XHEADER_AT)) return .bad;
    if (std.mem.readInt(u64, &bv, .little) & XFEATURE_AVX == 0) return .init;
    if (!usercopy.copyFromUser(ymm, va +% YMM_AT)) return .bad;
    return .given;
}

/// rt_sigreturn(): the handler is done. Its frame, at the caller's stack
/// pointer less the return address the handler's `ret` took, says what to
/// go back to: registers, FP state, mask. Returns the rax to go back with;
/// the frame is marked for the stub's full-restore exit.
pub fn rtSigreturn(pcb: *PCB, frame: *signals.SyscallFrame) u64 {
    const frame_va = frame.user_rsp -% 8;
    var uc: Ucontext = undefined;
    if (!usercopy.copyFromUser(std.mem.asBytes(&uc), frame_va + @offsetOf(RtSigframe, "uc"))) return badFrame(pcb, frame_va);
    const mc = &uc.mcontext;
    // iretq to a non-canonical address faults in the kernel.
    if (mc.rip >= memmap.USER_SPACE_END or mc.rsp >= memmap.USER_SPACE_END) return badFrame(pcb, frame_va);

    const fpu: *[512]u8 = @constCast(frame.userFpu());
    if (mc.fpstate == 0) {
        // No FP state to go back to: the init one, as Linux does.
        freshFp(fpu);
    } else {
        var image: [512]u8 align(16) = undefined;
        if (!usercopy.copyFromUser(&image, mc.fpstate)) return badFrame(pcb, frame_va);
        var ymm: [fp.UPPER_BYTES]u8 = undefined;
        const upper: Upper = if (fp.avx) upperOf(mc.fpstate, &image, &ymm) else .init;
        if (upper == .bad) return badFrame(pcb, frame_va);
        const mxcsr = std.mem.readInt(u32, image[24..28], .little) & mxcsrMask();
        std.mem.writeInt(u32, image[24..28], mxcsr, .little);
        @memcpy(fpu, &image);
        fp.loadUpper(if (upper == .given) &ymm else null);
    }

    pcb.signal_mask = uc.sigmask & ~signals.UNBLOCKABLE;
    // A handler ran: a restart_syscall now ends in EINTR, as on Linux.
    pcb.restart_until = 0;
    // SS_AUTODISARM took the alternate stack away for the handler.
    if (uc.stack.flags & SS_AUTODISARM != 0 and uc.stack.flags & SS_DISABLE == 0 and pcb.alt_stack.size == 0) {
        pcb.alt_stack = .{ .sp = uc.stack.sp, .size = uc.stack.size, .autodisarm = true };
    }

    frame.r8 = mc.r8;
    frame.r9 = mc.r9;
    frame.r10 = mc.r10;
    frame.r12 = mc.r12;
    frame.r13 = mc.r13;
    frame.r14 = mc.r14;
    frame.r15 = mc.r15;
    frame.rdi = mc.rdi;
    frame.rsi = mc.rsi;
    frame.rbp = mc.rbp;
    frame.rbx = mc.rbx;
    frame.rdx = mc.rdx;
    frame.user_rsp = mc.rsp;
    // rip and rflags go where sysret would take them from; the stub's
    // full-restore exit moves them to an iretq frame and loads rcx and r11
    // from the two words set here.
    frame.rcx = mc.rip;
    frame.r11 = userFlags(mc.eflags);
    frame.setFullRestore(mc.rcx, mc.r11);
    return mc.rax;
}

fn badFrame(pcb: *PCB, frame_va: u64) u64 {
    debug.klog("[linux] pid={d} rt_sigreturn: no usable frame at 0x{X} — killing the process\n", .{ process.getCurrentPid(), frame_va });
    process.killThreadGroup(pcb.tgid, signals.fatalStatus(pcb, signals.SIGSEGV));
    process.schedule();
    unreachable;
}
