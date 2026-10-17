//! Linux processes and the plumbing between them: fork, execve, wait4 and
//! kill; pipes, dup and poll; and the small calls a build driver makes
//! around its children (process_vm_readv on itself, sysinfo, utimensat).
//!
//! A Linux process's children are the process's (lifecycle.forkCurrent
//! makes the group its parent), so any of its threads may wait4 for them.
//! execve builds the new image in a held slot with the loader every launch
//! uses, then trades address spaces with it (lifecycle.takeExecImage): the
//! slot leaves with the old one, through the ordinary teardown. A failure
//! before that trade leaves the caller as it was.
//!
//! No Linux signal delivery yet: kill ends a process for the signals whose
//! default is to, and ignores the rest.

const std = @import("std");
const process = @import("../../proc/process.zig");
const lifecycle = @import("../../proc/lifecycle.zig");
const sched = @import("../../proc/sched.zig");
const signals = @import("../../proc/signals.zig");
const pipe = @import("../../proc/pipe.zig");
const elf_loader = @import("../../proc/elf_loader.zig");
const vfs = @import("../../fs/vfs.zig");
const heap = @import("../../mm/heap.zig");
const pmm = @import("../../mm/pmm.zig");
const fdpoll = @import("../ipc/fdpoll.zig");
const smp = @import("../smp.zig");
const common = @import("common.zig");
const linux_fs = @import("linux_fs.zig");
const linux_time = @import("linux_time.zig");
const debug = @import("../../debug/debug.zig");

// Linux errno.
const EPERM: i64 = 1;
const ENOENT: i64 = 2;
const ESRCH: i64 = 3;
const E2BIG: i64 = 7;
const ENOEXEC: i64 = 8;
const EBADF: i64 = 9;
const ECHILD: i64 = 10;
const EAGAIN: i64 = 11;
const ENOMEM: i64 = 12;
const EFAULT: i64 = 14;
const EINVAL: i64 = 22;
const ENFILE: i64 = 23;
const EMFILE: i64 = 24;

inline fn err(e: i64) u64 {
    return @bitCast(-e);
}

const O_NONBLOCK: u64 = 0x800;
const O_DIRECT: u64 = 0x4000;
const O_CLOEXEC: u64 = 0x80000;

// --- fork ------------------------------------------------------------------

/// fork(), vfork() and clone() of the fork shape: the child returns 0 from
/// the same syscall with the caller's registers and FP state.
pub fn fork(frame: *signals.SyscallFrame) u64 {
    // never_inline: watch.zig names forkCurrent as a kernel_esp writer.
    return @call(.never_inline, process.forkCurrent, .{frame}) orelse err(EAGAIN);
}

// --- execve ----------------------------------------------------------------

/// Most bytes execve's argv and envp strings may take, and most pointers.
const MAX_EXEC_STRINGS: usize = 120 * 1024;
const MAX_EXEC_PTRS: usize = 4096;

/// execve(path, argv, envp).
pub fn execve(frame: *signals.SyscallFrame, path_va: u64, argv_va: u64, envp_va: u64) u64 {
    const me = smp.currentPid() orelse return err(EFAULT);
    // From another thread, Linux moves the caller into the lead's place
    // first; not done here.
    if (process.procs[me].tgid != me) return err(EINVAL);

    var path_buf: [256]u8 = undefined;
    const target = switch (linux_fs.execTarget(path_va, &path_buf)) {
        .file => |f| f,
        .fail => |e| return e,
    };

    const strings = heap.kmalloc(MAX_EXEC_STRINGS) orelse return err(ENOMEM);
    defer heap.kfree(strings);
    var args: elf_loader.ExecArgs = .{ .strings = &.{}, .argc = 0, .envc = 0 };
    var used: usize = 0;
    args.argc = switch (copyStrings(argv_va, strings[0..MAX_EXEC_STRINGS], &used)) {
        .count => |n| n,
        .fail => |e| return e,
    };
    args.envc = switch (copyStrings(envp_va, strings[0..MAX_EXEC_STRINGS], &used)) {
        .count => |n| n,
        .fail => |e| return e,
    };
    args.strings = strings[0..used];

    // The image is built and the old one dropped with no kill in between:
    // a kill now would strand the held slot. It lands on the way out.
    process.noKillEnter();
    defer process.noKillLeave();

    const name = std.fs.path.basename(target.path);
    const img = elf_loader.loadForExec(target.inum, target.size, .{
        .name = name[0..@min(name.len, 15)],
        .raw = name,
        .fname_len = name.len,
        .exe_path = target.path,
        .exec_args = &args,
    }) orelse return err(ENOEXEC);

    // Past here the call can't fail: it returns into the new image.
    lifecycle.killOtherThreads();
    @import("../ipc/iouring.zig").releaseAllForPid(@intCast(me));
    const entry_rsp = imageEntry(img);
    lifecycle.takeExecImage(img);
    closeOnExec();
    enterImage(frame, entry_rsp);
    return 0;
}

/// RIP and RSP the image built in `img` starts at (its first-dispatch frame).
const EntryRsp = struct { rip: u64, rsp: u64 };

fn imageEntry(img: usize) EntryRsp {
    const fspec = @import("../../proc/frames.zig").dispatch;
    const f: [*]const u64 = @ptrFromInt(process.procs[img].kernel_stack_top - fspec.pt_regs_bytes);
    return .{ .rip = f[fspec.iretq.rip.at()], .rsp = f[fspec.iretq.rsp.at()] };
}

/// The syscall returns into the new image: at its entry, on its stack, the
/// other registers zero (rdx too: no atexit hook), the FP state fresh, no
/// TLS.
fn enterImage(frame: *signals.SyscallFrame, e: EntryRsp) void {
    frame.* = std.mem.zeroes(signals.SyscallFrame);
    frame.rcx = e.rip;
    frame.user_rsp = e.rsp;
    frame.r11 = 0x202; // RFLAGS: IF
    const fpu: *align(16) [512]u8 = @constCast(frame.userFpu());
    fpu.* = @import("../arch/fp.zig").init_template;
    const pcb = process.currentPCB() orelse return;
    pcb.fs_base = 0;
    asm volatile ("wrmsr"
        :
        : [msr] "{ecx}" (@as(u32, 0xC000_0100)),
          [lo] "{eax}" (@as(u32, 0)),
          [hi] "{edx}" (@as(u32, 0)),
    );
}

/// Close the caller's FD_CLOEXEC fds.
fn closeOnExec() void {
    const pcb = linux_fs.proc() orelse return;
    for (0..pcb.fd_table.len) |fd| {
        if (pcb.fd_table[fd].in_use and pcb.fd_table[fd].cloexec) _ = vfs.closeSlot(pcb, @intCast(fd));
    }
}

const StringsRead = union(enum) { count: u32, fail: u64 };

/// Append the NUL-terminated strings of the user pointer array at `va`
/// (NULL-terminated; a null array is empty) to `buf` from `used.*` on.
fn copyStrings(va: u64, buf: []u8, used: *usize) StringsRead {
    if (va == 0) return .{ .count = 0 };
    var n: u32 = 0;
    while (true) : (n += 1) {
        if (n == MAX_EXEC_PTRS) return .{ .fail = err(E2BIG) };
        const at = va + @as(u64, n) * 8;
        if (!common.validateUserPtr(at, 8)) return .{ .fail = err(EFAULT) };
        const s = @as(*align(1) const u64, @ptrFromInt(at)).*;
        if (s == 0) return .{ .count = n };
        var k: usize = 0;
        while (true) : (k += 1) {
            const c_at = s + k;
            if ((k == 0 or c_at & 0xFFF == 0) and !common.validateUserPtr(c_at, 1)) return .{ .fail = err(EFAULT) };
            if (used.* == buf.len) return .{ .fail = err(E2BIG) };
            const c = @as(*const u8, @ptrFromInt(c_at)).*;
            buf[used.*] = c;
            used.* += 1;
            if (c == 0) break;
        }
    }
}

// --- wait4 / kill ----------------------------------------------------------

const WNOHANG: u64 = 1;
const RUSAGE_BYTES: usize = 144;
const SIGKILL: u32 = 9;

/// The exit status of a process kill() ended: the signal, flagged.
const KILLED_BY: u32 = 0x4000_0000;

/// A process's exit status as wait4 reports it: an exit code (0..255)
/// shifted up, or the signal that ended it in the low bits — what kill()
/// recorded, else SIGKILL (a fault, an out-of-memory kill).
fn waitStatus(s: u32) u32 {
    if (s <= 0xFF) return s << 8;
    if (s & KILLED_BY != 0) return s & 0x7F;
    return SIGKILL;
}

/// wait4(pid, status, options, rusage). pid > 0 names a child; any other
/// value waits for any child (no process groups). rusage comes back zeroed.
pub fn wait4(pid_arg: u64, status_va: u64, options: u64, rusage_va: u64) u64 {
    const me = smp.currentPid() orelse return err(EFAULT);
    const group: u8 = process.procs[me].tgid;
    const pid: i32 = @bitCast(@as(u32, @truncate(pid_arg)));
    const target: u32 = if (pid > 0) @intCast(pid) else 0xFFFF_FFFF;
    if (status_va != 0 and !common.validateUserPtrWriteAligned(status_va, 4, 4)) return err(EFAULT);
    if (rusage_va != 0 and !common.validateUserPtrWrite(rusage_va, RUSAGE_BYTES)) return err(EFAULT);
    // Registered before the first look, so a child dying after it wakes us.
    lifecycle.childWaitEnter(me);
    defer lifecycle.childWaitLeave(me);
    while (true) {
        if (process.findZombieChild(group, target)) |z| {
            const st = waitStatus(process.procs[z].exit_status);
            if (status_va != 0) @as(*u32, @ptrFromInt(status_va)).* = st;
            if (rusage_va != 0) @memset(@as([*]u8, @ptrFromInt(rusage_va))[0..RUSAGE_BYTES], 0);
            process.reapZombie(z);
            return z;
        }
        if (!hasChild(group, target)) return err(ECHILD);
        if (options & WNOHANG != 0) return 0;
        process.blockOn(.waitpid, target);
    }
}

fn hasChild(group: u8, target: u32) bool {
    for (0..process.MAX_PROCS) |i| {
        if (process.procs[i].state == .unused or process.procs[i].parent_pid != group) continue;
        if (target == 0xFFFF_FFFF or i == target) return true;
    }
    return false;
}

/// Signals whose default action is to do nothing (or to stop, which there
/// is no job control for).
fn defaultIgnored(sig: u32) bool {
    return switch (sig) {
        17, 18, 19, 20, 21, 22, 23, 28 => true, // CHLD CONT STOP TSTP TTIN TTOU URG WINCH
        else => false,
    };
}

/// kill(pid, sig): ends process `pid` (any thread of it named) for a
/// signal whose default does; 0 checks it exists. No process groups.
pub fn kill(pid_arg: u64, sig_arg: u64) u64 {
    const pid: i32 = @bitCast(@as(u32, @truncate(pid_arg)));
    const sig: u32 = @truncate(sig_arg);
    if (sig >= 65) return err(EINVAL);
    if (pid <= 0) return err(EINVAL);
    if (pid >= process.MAX_PROCS) return err(ESRCH);
    const t = &process.procs[@intCast(pid)];
    if (t.state == .unused or t.state == .zombie or t.state == .loading) return err(ESRCH);
    if (t.is_idle or t.page_dir_phys == 0) return err(EPERM);
    if (sig == 0 or defaultIgnored(sig)) return 0;
    lifecycle.killThreadGroup(t.tgid, KILLED_BY | sig);
    return 0;
}

// --- pipes and fds -----------------------------------------------------------

/// pipe2(fds, flags); pipe is pipe2(fds, 0).
pub fn pipe2(fds_va: u64, flags: u64) u64 {
    if (flags & ~(O_NONBLOCK | O_CLOEXEC | O_DIRECT) != 0) return err(EINVAL);
    if (!common.validateUserPtrWriteAligned(fds_va, 8, 4)) return err(EFAULT);
    const pcb = linux_fs.proc() orelse return err(EFAULT);
    const id = pipe.alloc() orelse return err(ENFILE);
    const r = vfs.allocFd(pcb) orelse return pipeFail(id, null, pcb);
    const w = vfs.allocFd(pcb) orelse return pipeFail(id, r, pcb);
    const cloexec = flags & O_CLOEXEC != 0;
    const nonblock = flags & O_NONBLOCK != 0;
    vfs.installFd(pcb, r, .{ .in_use = true, .fs_type = .pipe, .pipe_id = id, .flags = 0, .cloexec = cloexec, .nonblock = nonblock });
    vfs.installFd(pcb, w, .{ .in_use = true, .fs_type = .pipe, .pipe_id = id, .flags = 1, .cloexec = cloexec, .nonblock = nonblock });
    const out: *[2]i32 = @ptrFromInt(fds_va);
    out[0] = @intCast(r);
    out[1] = @intCast(w);
    return 0;
}

fn pipeFail(id: u8, reserved: ?usize, pcb: *process.PCB) u64 {
    if (reserved) |fd| vfs.releaseFd(pcb, fd);
    pipe.closeReader(id);
    pipe.closeWriter(id);
    return err(EMFILE);
}

/// dup(old): the lowest free fd.
pub fn dup(old: u64) u64 {
    return dupFrom(old, 0, false);
}

/// dup2(old, new).
pub fn dup2(old: u64, new: u64) u64 {
    const pcb = linux_fs.proc() orelse return err(EFAULT);
    if (old == new) return if (linux_fs.fdEntry(pcb, old) != null) new else err(EBADF);
    return dupAt(pcb, old, new, false);
}

/// dup3(old, new, flags).
pub fn dup3(old: u64, new: u64, flags: u64) u64 {
    if (flags & ~O_CLOEXEC != 0 or old == new) return err(EINVAL);
    const pcb = linux_fs.proc() orelse return err(EFAULT);
    return dupAt(pcb, old, new, flags & O_CLOEXEC != 0);
}

/// fd `old` into slot `new`, whatever `new` held closed after.
fn dupAt(pcb: *process.PCB, old: u64, new: u64, cloexec: bool) u64 {
    if (new >= pcb.fd_table.len) return err(EBADF);
    var victim: process.FileDesc = .{};
    {
        pcb.fd_lock.acquire();
        defer pcb.fd_lock.release();
        if (old >= pcb.fd_table.len or !pcb.fd_table[old].in_use) return err(EBADF);
        var copy = pcb.fd_table[old];
        if (!vfs.refEntry(&copy)) return err(EINVAL);
        copy.cloexec = cloexec;
        victim = pcb.fd_table[new];
        pcb.fd_table[new] = copy;
    }
    if (victim.in_use) vfs.releaseEntry(&victim);
    return new;
}

/// fd `old` into the lowest free slot at or above `min` (dup, F_DUPFD).
pub fn dupFrom(old: u64, min: u64, cloexec: bool) u64 {
    const pcb = linux_fs.proc() orelse return err(EFAULT);
    pcb.fd_lock.acquire();
    defer pcb.fd_lock.release();
    if (old >= pcb.fd_table.len or !pcb.fd_table[old].in_use) return err(EBADF);
    var slot: usize = @intCast(@min(min, pcb.fd_table.len));
    while (slot < pcb.fd_table.len and pcb.fd_table[slot].in_use) slot += 1;
    if (slot == pcb.fd_table.len) return err(EMFILE);
    var copy = pcb.fd_table[old];
    if (!vfs.refEntry(&copy)) return err(EINVAL);
    copy.cloexec = cloexec;
    pcb.fd_table[slot] = copy;
    return slot;
}

// --- poll ------------------------------------------------------------------

const PollFd = extern struct { fd: i32, events: i16, revents: i16 };
const POLLNVAL: u16 = 0x20;

/// poll(fds, nfds, timeout_ms); a negative timeout waits for good.
pub fn poll(fds_va: u64, nfds: u64, timeout_arg: u64) u64 {
    const ms: i32 = @bitCast(@as(u32, @truncate(timeout_arg)));
    return pollFor(fds_va, nfds, if (ms < 0) null else @as(u64, @intCast(ms)) * 1_000_000);
}

/// ppoll(fds, nfds, timeout, sigmask, sigsetsize): the mask is moot without
/// signal delivery.
pub fn ppoll(fds_va: u64, nfds: u64, tmo_va: u64) u64 {
    if (tmo_va == 0) return pollFor(fds_va, nfds, null);
    return switch (linux_time.readTimespec(tmo_va)) {
        .ns => |ns| pollFor(fds_va, nfds, ns),
        .fail => |e| e,
    };
}

fn pollFor(fds_va: u64, nfds: u64, timeout_ns: ?u64) u64 {
    if (nfds > 1024) return err(EINVAL);
    const n: usize = @intCast(nfds);
    if (n > 0 and !common.validateUserPtrWrite(fds_va, n * @sizeOf(PollFd))) return err(EFAULT);
    const me = smp.currentPid() orelse return err(EFAULT);
    const pcb = &process.procs[me];
    const group: u8 = pcb.tgid;
    const fds: [*]align(1) PollFd = @ptrFromInt(fds_va);
    const deadline: u64 = if (timeout_ns) |ns| deadlineAfter(ns) else 0;
    // Registered before the first look, so an fd event after it wakes us.
    fdpoll.sleeperEnter(me);
    defer {
        fdpoll.sleeperLeave(me);
        @atomicStore(u64, &pcb.wake_tick, 0, .release);
    }
    while (true) {
        var ready: u64 = 0;
        for (0..n) |i| {
            const fd = fds[i].fd;
            if (fd < 0) {
                fds[i].revents = 0;
                continue;
            }
            const want: u16 = @bitCast(fds[i].events);
            const lead = &process.procs[group];
            const mask: u16 = if (fd >= lead.fd_table.len or !lead.fd_table[@intCast(fd)].in_use)
                POLLNVAL
            else
                fdpoll.pollMask(group, @intCast(fd)) & (want | fdpoll.POLLERR | fdpoll.POLLHUP);
            fds[i].revents = @bitCast(mask);
            if (mask != 0) ready += 1;
        }
        if (ready > 0) return ready;
        if (timeout_ns) |ns| if (ns == 0 or process.tick_count >= deadline) return 0;
        @atomicStore(u64, &pcb.wake_tick, deadline, .release);
        if (deadline != 0) sched.registerWakeDeadline(deadline);
        process.blockOn(.poll, 0);
    }
}

/// The tick a wait of `ns` ends at: rounded up, one tick more.
fn deadlineAfter(ns: u64) u64 {
    const ticks = std.math.divCeil(u64, ns, linux_time.TICK_NS) catch unreachable;
    return process.tick_count +| ticks +| 1;
}

// --- the rest ----------------------------------------------------------------

const Iovec = extern struct { base: u64, len: u64 };

/// process_vm_readv(pid, local, liovcnt, remote, riovcnt, flags) of the
/// caller's own process (a debug-info reader probing its memory): copies
/// the remote segments into the local ones in turn. An unreadable remote
/// byte ends it, short, or with -EFAULT if nothing was copied.
pub fn processVmReadv(pid: u64, local_va: u64, liovcnt: u64, remote_va: u64, riovcnt: u64, flags: u64) u64 {
    if (flags != 0 or liovcnt > 1024 or riovcnt > 1024) return err(EINVAL);
    const me = smp.currentPid() orelse return err(EFAULT);
    if (pid != process.procs[me].tgid and pid != me) return err(EPERM);
    if (!common.validateUserPtr(local_va, liovcnt * @sizeOf(Iovec))) return err(EFAULT);
    if (!common.validateUserPtr(remote_va, riovcnt * @sizeOf(Iovec))) return err(EFAULT);
    const local: [*]align(1) const Iovec = @ptrFromInt(local_va);
    const remote: [*]align(1) const Iovec = @ptrFromInt(remote_va);
    var li: usize = 0;
    var loff: u64 = 0;
    var total: u64 = 0;
    for (0..riovcnt) |ri| {
        var roff: u64 = 0;
        while (roff < remote[ri].len) {
            while (li < liovcnt and loff == local[li].len) : (li += 1) loff = 0;
            if (li == liovcnt) return total;
            const n = @min(remote[ri].len - roff, local[li].len - loff, 4096 - ((remote[ri].base + roff) & 0xFFF));
            const src = remote[ri].base + roff;
            const dst = local[li].base + loff;
            if (!common.validateUserPtr(src, n) or !common.validateUserPtrWrite(dst, n))
                return if (total > 0) total else err(EFAULT);
            @memcpy(@as([*]u8, @ptrFromInt(dst))[0..n], @as([*]const u8, @ptrFromInt(src))[0..n]);
            roff += n;
            loff += n;
            total += n;
        }
    }
    return total;
}

/// Linux x86-64 `struct sysinfo`.
const SysInfo = extern struct {
    uptime: i64 = 0,
    loads: [3]u64 = .{ 0, 0, 0 },
    totalram: u64 = 0,
    freeram: u64 = 0,
    sharedram: u64 = 0,
    bufferram: u64 = 0,
    totalswap: u64 = 0,
    freeswap: u64 = 0,
    procs: u16 = 0,
    pad: u16 = 0,
    totalhigh: u64 = 0,
    freehigh: u64 = 0,
    mem_unit: u32 = 0,
};

comptime {
    std.debug.assert(@sizeOf(SysInfo) == 112);
}

/// sysinfo(info): memory and uptime, in bytes (mem_unit 1).
pub fn sysinfo(va: u64) u64 {
    if (!common.validateUserPtrWrite(va, @sizeOf(SysInfo))) return err(EFAULT);
    var live: u16 = 0;
    for (0..process.MAX_PROCS) |i| {
        if (process.procs[i].state != .unused) live += 1;
    }
    const info: SysInfo = .{
        .uptime = @intCast(process.tick_count / 100),
        .totalram = @as(u64, pmm.managedFrameCount()) * 4096,
        .freeram = @as(u64, pmm.freeFrameCount()) * 4096,
        .procs = live,
        .mem_unit = 1,
    };
    @as(*align(1) SysInfo, @ptrFromInt(va)).* = info;
    return 0;
}

/// utimensat(dirfd, path, times, flags): accepted; ext2 times aren't kept
/// to the nanosecond, and nothing here reads them back to decide.
pub fn utimensat() u64 {
    return 0;
}
