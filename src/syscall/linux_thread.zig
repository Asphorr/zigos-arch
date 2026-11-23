//! Linux threads for `.linux` processes: clone of the pthread shape, futex,
//! set_tid_address, and the two exits — exit (one thread) and exit_group
//! (all of them).
//!
//! A thread is a task in its creator's group (lifecycle.cloneLinuxThread): it
//! shares the address space, and the Linux layer resolves fds and the cwd
//! through the group lead, so threads share those too (CLONE_FILES,
//! CLONE_FS). Its tid is its pid; getpid answers the lead's.
//!
//! Futexes are keyed by (tgid, VA) whatever the PRIVATE flag says, so a
//! futex in memory shared between processes doesn't work across them.
//! REQUEUE wakes the waiters it would move: a futex waiter must take a
//! spurious wake anyway, and moving them only spares the target word a herd.

const std = @import("std");
const process = @import("../proc/process.zig");
const signals = @import("../proc/signals.zig");
const memmap = @import("../mm/memmap.zig");
const debug = @import("../debug/debug.zig");
const time = @import("../time/time.zig");
const common = @import("common.zig");
const linux_time = @import("linux_time.zig");
const linux_signal = @import("linux_signal.zig");
const lprof = @import("../debug/linux_prof.zig");
const shm = @import("../mm/shm.zig");

// Linux errno.
const EPERM: i64 = 1;
const EINTR: i64 = 4;
const EAGAIN: i64 = 11;
const EFAULT: i64 = 14;
const EINVAL: i64 = 22;
const ENOSYS: i64 = 38;
const ETIMEDOUT: i64 = 110;

inline fn err(e: i64) u64 {
    return @bitCast(-e);
}

const CLONE_VM: u64 = 0x100;
const CLONE_FS: u64 = 0x200;
const CLONE_FILES: u64 = 0x400;
const CLONE_SIGHAND: u64 = 0x800;
const CLONE_THREAD: u64 = 0x10000;
const CLONE_SYSVSEM: u64 = 0x40000;
const CLONE_SETTLS: u64 = 0x80000;
const CLONE_PARENT_SETTID: u64 = 0x100000;
const CLONE_CHILD_CLEARTID: u64 = 0x200000;
const CLONE_DETACHED: u64 = 0x400000;
const CLONE_CHILD_SETTID: u64 = 0x1000000;

/// What a thread shares with its creator; all of it, always.
const THREAD_SHARES = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD;
/// What else a thread clone may ask for. The low byte (exit signal) must be 0.
const THREAD_EXTRAS = CLONE_SYSVSEM | CLONE_SETTLS | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID | CLONE_DETACHED | CLONE_CHILD_SETTID;

/// A tid word: a u32 the kernel writes, inside the user window.
fn tidWordOk(va: u64) bool {
    return common.validateUserPtrWriteAligned(va, 4, 4);
}

/// The fork shape of clone: a new process, nothing shared; the low byte is
/// the exit signal (SIGCHLD, or none).
const SIGCHLD: u64 = 17;
const CLONE_VFORK: u64 = 0x4000;

/// clone(flags, stack, ptid, ctid, tls): the thread shape, as
/// pthread_create issues it, or a fork shape. Returns the new tid; the
/// thread itself returns 0 on `stack`.
///
/// CLONE_VM | CLONE_VFORK with a stack is posix_spawn's fork: a child that
/// borrows the caller's memory until it execs. It gets a copy instead, and
/// the caller is not held up for it — which neither can tell as long as
/// the child reports to its parent through a file, as musl's does (a pipe
/// that closes on exec).
pub fn clone(frame: *signals.SyscallFrame, flags: u64, stack: u64, ptid: u64, ctid: u64, tls: u64) u64 {
    if (flags & CLONE_THREAD == 0) {
        const sig = flags & 0xFF;
        // The tid words go with either fork shape: glibc's fork asks for
        // the child's.
        const tid_words = CLONE_PARENT_SETTID | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID;
        const shape = flags & ~@as(u64, 0xFF) & ~tid_words;
        if ((shape == 0 or shape == CLONE_VM | CLONE_VFORK) and (sig == SIGCHLD or sig == 0)) {
            if (stack >= memmap.USER_SPACE_END) return err(EINVAL);
            if (flags & CLONE_PARENT_SETTID != 0 and !tidWordOk(ptid)) return err(EFAULT);
            const child = @import("linux_proc.zig").forkWith(frame, .{
                .stack = stack,
                .set_tid = if (flags & CLONE_CHILD_SETTID != 0) ctid else 0,
                .clear_tid = if (flags & CLONE_CHILD_CLEARTID != 0 and ctid & 3 == 0 and ctid < memmap.USER_SPACE_END) ctid else 0,
            });
            if (flags & CLONE_PARENT_SETTID != 0 and @as(i64, @bitCast(child)) > 0) {
                const tid: u32 = @truncate(child);
                _ = @import("../cpu/arch/usercopy.zig").copyToUser(ptid, std.mem.asBytes(&tid));
            }
            return child;
        }
        debug.klog("[linux] pid={d} clone flags 0x{X}: only threads and forks\n", .{ process.getCurrentPid(), flags });
        return err(ENOSYS);
    }
    if (flags & THREAD_SHARES != THREAD_SHARES or flags & ~(THREAD_SHARES | THREAD_EXTRAS) != 0) return err(EINVAL);
    if (stack >= memmap.USER_SPACE_END) return err(EINVAL);
    // wrmsr #GPs on a non-canonical base, as for arch_prctl(ARCH_SET_FS).
    if (flags & CLONE_SETTLS != 0 and tls >= memmap.USER_SPACE_END) return err(EPERM);
    if (flags & CLONE_PARENT_SETTID != 0 and !tidWordOk(ptid)) return err(EFAULT);
    if (flags & CLONE_CHILD_SETTID != 0 and !tidWordOk(ctid)) return err(EFAULT);
    if (flags & CLONE_CHILD_CLEARTID != 0 and (ctid & 3 != 0 or ctid >= memmap.USER_SPACE_END)) return err(EFAULT);
    const me = process.currentPCB() orelse return err(EFAULT);

    const spec = process.LinuxThreadSpec{
        .stack = stack,
        .fs_base = if (flags & CLONE_SETTLS != 0) tls else me.fs_base,
        .clear_tid = if (flags & CLONE_CHILD_CLEARTID != 0) ctid else 0,
        .parent_tid = if (flags & CLONE_PARENT_SETTID != 0) ptid else 0,
        .child_tid = if (flags & CLONE_CHILD_SETTID != 0) ctid else 0,
    };
    // never_inline: watch.zig names cloneLinuxThread as a kernel_esp writer.
    const tid = @call(.never_inline, process.cloneLinuxThread, .{ frame, spec }) orelse return err(EAGAIN);
    return tid;
}

/// set_tid_address(tidptr): the word to clear and wake at this thread's
/// exit. Returns the tid.
pub fn setTidAddress(tidptr: u64) u64 {
    const me = process.currentPCB() orelse return err(EFAULT);
    me.clear_child_tid = if (tidptr & 3 == 0 and tidptr < memmap.USER_SPACE_END) tidptr else 0;
    return me.pid_nr;
}

/// exit(code): this thread only. A joiner waits on its clear-tid word.
pub fn exitThread(code: u64) u64 {
    const me = process.currentPCB() orelse return err(EFAULT);
    const tid_word = me.clear_child_tid;
    if (tid_word != 0) {
        me.clear_child_tid = 0;
        if (tidWordOk(tid_word)) {
            @atomicStore(u32, @as(*u32, @ptrFromInt(tid_word)), 0, .release);
            // A joiner may wait without FUTEX_PRIVATE_FLAG, on a word in
            // shared memory.
            const at = futexAt(me, tid_word, false);
            _ = process.wakeFutexAt(at.obj, me.tgid, at.off, 1);
        }
    }
    process.destroyCurrentGraceful(@truncate(code & 0xFF));
    return 0; // not reached
}

/// exit_group(code): the whole process.
pub fn exitGroup(code: u64) u64 {
    process.exitThreadGroup(@truncate(code & 0xFF));
    return 0; // not reached
}

const FUTEX_WAIT: u64 = 0;
const FUTEX_WAKE: u64 = 1;
const FUTEX_REQUEUE: u64 = 3;
const FUTEX_CMP_REQUEUE: u64 = 4;
const FUTEX_WAIT_BITSET: u64 = 9;
const FUTEX_WAKE_BITSET: u64 = 10;
const FUTEX_PRIVATE_FLAG: u64 = 128;
const FUTEX_CLOCK_REALTIME: u64 = 256;

/// A futex count argument (an int): negative is EINVAL, as Linux.
fn futexCount(v: u64) ?u32 {
    const n: i32 = @bitCast(@as(u32, @truncate(v)));
    if (n < 0) return null;
    return @intCast(n);
}

/// The tick at which a wait ending `ns` from now times out: rounded up and
/// one tick more, so the wait lasts at least `ns`.
fn deadlineAfter(ns: u64) u64 {
    const ticks = std.math.divCeil(u64, ns, linux_time.TICK_NS) catch unreachable;
    return process.tick_count +| ticks +| 1;
}

/// Where a futex word is, for a wake to find its waiters. `obj` 0: at VA
/// `off` of the caller's process. Else `off` is its place in what backs
/// memory that processes share, the same in each of them.
const FutexAt = struct { obj: u64, off: usize };

const SHARED_ANON: u64 = 1 << 32;
const SHARED_FILE: u64 = 2 << 32;

/// The word at `uaddr`. Without FUTEX_PRIVATE_FLAG it may lie in a shared
/// mapping: the region says which, under the read side of the map.
fn futexAt(me: *process.PCB, uaddr: u64, private: bool) FutexAt {
    if (private) return .{ .obj = 0, .off = uaddr };
    const lead = process.leader(me);
    lead.as_lock.acquireRead();
    defer lead.as_lock.releaseRead();
    const r = lead.regions.find(uaddr) orelse return .{ .obj = 0, .off = uaddr };
    const in = uaddr - r.start;
    if (r.shm_id != shm.SHM_INVALID) return .{ .obj = SHARED_ANON | r.shm_id, .off = @as(usize, r.shm_off) * 0x1000 + in };
    if (r.cache_inode != 0 and r.cache_shared) return .{ .obj = SHARED_FILE | r.cache_inode, .off = r.cache_off + in };
    return .{ .obj = 0, .off = uaddr };
}

/// Sleep while the word at `uaddr` holds `want`, at most `rel` ns. A signal
/// with no handler to run does not end the wait: the call is made again, a
/// timed one to the same end through restart_syscall.
fn futexWait(me: *process.PCB, at: FutexAt, uaddr: u64, private: bool, want: u32, rel: ?u64) u64 {
    if (!common.validateUserPtr(uaddr, 4)) return err(EFAULT);
    const word: *const volatile u32 = @ptrFromInt(uaddr);
    if (word.* != want) {
        lprof.futex(.wait_changed);
        return err(EAGAIN);
    }
    if (rel) |ns| if (ns == 0) return err(ETIMEDOUT);
    // The clock only for a timed wait: reading it costs a VM exit.
    const start = if (rel != null) time.monotonicNanos() else 0;
    const end = start +| (rel orelse 0);
    var left = rel;
    while (true) {
        switch (process.blockOnFutexAt(at.obj, at.off, word, want, if (left) |ns| deadlineAfter(ns) else 0)) {
            .woke => {
                lprof.futex(.wait_woke);
                return 0;
            },
            .again => {
                lprof.futex(.wait_changed);
                return err(EAGAIN);
            },
            .signalled => {
                if (rel == null) return err(linux_signal.ERESTARTSYS);
                me.restart_until = end;
                me.restart_futex = uaddr;
                me.restart_futex_val = want;
                me.restart_futex_private = private;
                return err(linux_signal.ERESTART_RESTARTBLOCK);
            },
            .timed_out => lprof.futex(.wait_timed_out),
        }
        // tick_count can trail the clock (a tickless CPU catches up in
        // steps), so a tick deadline may come early: wait out the rest by
        // the monotonic clock.
        const now = time.monotonicNanos();
        // now == start: no clock running, the ticks are all there is.
        if (now >= end or now == start) return err(ETIMEDOUT);
        left = end - now;
    }
}

/// restart_syscall for a timed futex wait: on, to the monotonic `end`.
pub fn futexWaitAgain(me: *process.PCB, uaddr: u64, private: bool, want: u32, end: u64) u64 {
    return futexWait(me, futexAt(me, uaddr, private), uaddr, private, want, end -| time.monotonicNanos());
}

/// futex(uaddr, op, val, timeout | val2, uaddr2, val3).
pub fn futex(uaddr: u64, op: u64, val: u64, timeout: u64, uaddr2: u64, val3: u64) u64 {
    _ = uaddr2;
    const cmd = op & ~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);
    if (uaddr & 3 != 0) return err(EINVAL);
    const me = process.currentPCB() orelse return err(EFAULT);
    const at = futexAt(me, uaddr, op & FUTEX_PRIVATE_FLAG != 0);
    switch (cmd) {
        FUTEX_WAIT, FUTEX_WAIT_BITSET => {
            if (cmd == FUTEX_WAIT_BITSET and @as(u32, @truncate(val3)) == 0) return err(EINVAL);
            // FUTEX_WAIT counts its timeout from now; WAIT_BITSET's is a time
            // on the monotonic clock, or the realtime one with the flag.
            var rel: ?u64 = null;
            if (timeout != 0) {
                const ns = switch (linux_time.readTimespec(timeout)) {
                    .ns => |ns| ns,
                    .fail => |e| return e,
                };
                rel = if (cmd == FUTEX_WAIT) ns else blk: {
                    const clock = if (op & FUTEX_CLOCK_REALTIME != 0) linux_time.CLOCK_REALTIME else linux_time.CLOCK_MONOTONIC;
                    break :blk ns -| (linux_time.clockNanos(clock) orelse 0);
                };
            }
            return futexWait(me, at, uaddr, op & FUTEX_PRIVATE_FLAG != 0, @truncate(val), rel);
        },
        FUTEX_WAKE, FUTEX_WAKE_BITSET => {
            if (cmd == FUTEX_WAKE_BITSET and @as(u32, @truncate(val3)) == 0) return err(EINVAL);
            const n = futexCount(val) orelse return err(EINVAL);
            const woken = process.wakeFutexAt(at.obj, me.tgid, at.off, n);
            lprof.futex(if (woken == 0) .wake_none else .wake_some);
            return woken;
        },
        FUTEX_REQUEUE, FUTEX_CMP_REQUEUE => {
            const wake_n = futexCount(val) orelse return err(EINVAL);
            const move_n = futexCount(timeout) orelse return err(EINVAL);
            if (cmd == FUTEX_CMP_REQUEUE) {
                if (!common.validateUserPtr(uaddr, 4)) return err(EFAULT);
                const word: *const volatile u32 = @ptrFromInt(uaddr);
                if (word.* != @as(u32, @truncate(val3))) return err(EAGAIN);
            }
            return process.wakeFutexAt(at.obj, me.tgid, at.off, wake_n +| move_n);
        },
        else => {
            debug.klog("[linux] pid={d} futex op {d} unsupported\n", .{ process.getCurrentPid(), op });
            return err(ENOSYS);
        },
    }
}
