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
//! kill, tkill and tgkill send through the signal core (proc/signals.zig);
//! handlers and masks are linux_signal.zig's.

const std = @import("std");
const process = @import("../../proc/process.zig");
const lifecycle = @import("../../proc/lifecycle.zig");
const sched = @import("../../proc/sched.zig");
const signals = @import("../../proc/signals.zig");
const pid_nr = @import("../../proc/pid_nr.zig");
const session = @import("../../proc/session.zig");
const pipe = @import("../../proc/pipe.zig");
const elf_loader = @import("../../proc/elf_loader.zig");
const vfs = @import("../../fs/vfs.zig");
const file = @import("../../fs/file.zig");
const heap = @import("../../mm/heap.zig");
const pmm = @import("../../mm/pmm.zig");
const fdpoll = @import("../ipc/fdpoll.zig");
const smp = @import("../smp.zig");
const usercopy = @import("../arch/usercopy.zig");
const common = @import("common.zig");
const linux_fs = @import("linux_fs.zig");
const linux_signal = @import("linux_signal.zig");
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
const EBUSY: i64 = 16;
const ELOOP: i64 = 40;

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
    return forkWith(frame, .{});
}

/// fork as clone asks for it: on a stack of the child's own, with tid
/// words. `spec.child_nr` is this function's to set.
pub fn forkWith(frame: *signals.SyscallFrame, spec: process.ForkSpec) u64 {
    var child: u32 = 0;
    var full = spec;
    full.child_nr = &child;
    // never_inline: watch.zig names forkCurrent as a kernel_esp writer.
    _ = @call(.never_inline, process.forkCurrent, .{ frame, full }) orelse return err(EAGAIN);
    return child;
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

    // Two in turn: a script's interpreter is looked up while the script's
    // path is still read.
    var path_bufs: [2][256]u8 = undefined;
    var target = switch (linux_fs.execTarget(path_va, &path_bufs[0])) {
        .file => |f| f,
        .fail => |e| return e,
    };
    // The process is named after what was asked for, a script included.
    var name_buf: [15]u8 = undefined;
    const asked = std.fs.path.basename(target.path);
    const name_len = @min(asked.len, name_buf.len);
    @memcpy(name_buf[0..name_len], asked[0..name_len]);

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

    // A script names the program that runs it on its first line,
    // `#!interpreter [argument]`: that program runs instead, the script's
    // path after its own name and argument, the script's argv[1..] after.
    var depth: u8 = 0;
    while (true) {
        var head: [SCRIPT_LINE_MAX]u8 = undefined;
        const line = scriptLine(target, &head) orelse break;
        if (depth == MAX_SCRIPT_DEPTH) return err(ELOOP);
        depth += 1;
        if (line.interp.len == 0) return err(ENOEXEC);
        used = switch (scriptArgs(strings[0..MAX_EXEC_STRINGS], used, &args, line, target.path)) {
            .count => |n| n,
            .fail => |e| return e,
        };
        const pcb = linux_fs.proc() orelse return err(EFAULT);
        target = switch (linux_fs.execTargetAt(pcb, line.interp, &path_bufs[depth % 2])) {
            .file => |f| f,
            .fail => |e| return e,
        };
    }
    args.strings = strings[0..used];

    // The image is built and the old one dropped with no kill in between:
    // a kill now would strand the held slot. It lands on the way out.
    process.noKillEnter();
    defer process.noKillLeave();

    const img = elf_loader.loadForExec(target.inum, target.size, .{
        .name = name_buf[0..name_len],
        .raw = name_buf[0..name_len],
        .fname_len = name_len,
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
        if (pcb.fd_table[fd].file != null and pcb.fd_table[fd].cloexec) _ = vfs.closeSlot(pcb, @intCast(fd));
    }
}

/// Most bytes of a script's first line looked at (Linux's BINPRM_BUF_SIZE).
const SCRIPT_LINE_MAX: usize = 256;
/// Scripts run by scripts, at most.
const MAX_SCRIPT_DEPTH: u8 = 4;

const ScriptLine = struct { interp: []const u8, arg: ?[]const u8 };

/// The `#!` line of `target`, its parts slices of `head`; null if the file
/// isn't a script. What follows the interpreter is one argument, blanks
/// inside it kept, as on Linux.
fn scriptLine(target: linux_fs.ExecTarget, head: *[SCRIPT_LINE_MAX]u8) ?ScriptLine {
    const want: u32 = @intCast(@min(target.size, head.len));
    if (want < 2) return null;
    const n = vfs.readThroughCache(target.inum, 0, head, want);
    if (n < 2 or head[0] != '#' or head[1] != '!') return null;
    var line: []const u8 = head[2..n];
    if (std.mem.indexOfScalar(u8, line, '\n')) |end| line = line[0..end];
    const blank = " \t";
    line = std.mem.trim(u8, line, blank);
    const cut = std.mem.indexOfAny(u8, line, blank) orelse return .{ .interp = line, .arg = null };
    const arg = std.mem.trim(u8, line[cut..], blank);
    return .{ .interp = line[0..cut], .arg = if (arg.len == 0) null else arg };
}

const LenRead = union(enum) { count: usize, fail: u64 };

/// The argv the interpreter of `script` gets: its own name, the line's
/// argument if any, the script's path, then the script's argv[1..]; the
/// environment stays. Rewrites the strings `buf[0..used]` in place.
fn scriptArgs(buf: []u8, used: usize, args: *elf_loader.ExecArgs, line: ScriptLine, script: []const u8) LenRead {
    // The bytes of argv[0], which the new names replace.
    const old0: usize = if (args.argc == 0) 0 else (std.mem.indexOfScalar(u8, buf[0..used], 0) orelse return .{ .fail = err(EFAULT) }) + 1;
    var prefix: [3 * (SCRIPT_LINE_MAX + 1)]u8 = undefined;
    var p: usize = 0;
    var names: u32 = 0;
    for ([_]?[]const u8{ line.interp, line.arg, script }) |part| {
        const s = part orelse continue;
        @memcpy(prefix[p..][0..s.len], s);
        prefix[p + s.len] = 0;
        p += s.len + 1;
        names += 1;
    }
    const rest = used - old0;
    if (p + rest > buf.len) return .{ .fail = err(E2BIG) };
    // The rest moves to just after the new names; the ranges may overlap.
    if (p > old0) {
        std.mem.copyBackwards(u8, buf[p..][0..rest], buf[old0..used]);
    } else {
        std.mem.copyForwards(u8, buf[p..][0..rest], buf[old0..used]);
    }
    @memcpy(buf[0..p], prefix[0..p]);
    args.argc = args.argc - @intFromBool(args.argc != 0) + names;
    return .{ .count = p + rest };
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

/// A process's exit status as wait4 reports it: an exit code (0..255)
/// shifted up, or the signal that ended it in the low bits — the one a
/// signal's default or a fault recorded (signals.fatalStatus), else SIGKILL
/// (the kernel's own kills: out of memory, a fault under a lock).
fn waitStatus(s: u32) u32 {
    if (s <= 0xFF) return s << 8;
    if (s & signals.KILLED_BY != 0) return s & 0x7F;
    return SIGKILL;
}

/// The children a wait4 is for: all, the one in a slot, or those of a
/// process group.
const Awaited = union(enum) {
    any,
    slot: u8,
    group: u32,

    fn has(self: Awaited, slot: usize) bool {
        return switch (self) {
            .any => true,
            .slot => |s| s == slot,
            .group => |g| process.procs[slot].pgid == g,
        };
    }
};

const ANY_CHILD: u32 = 0xFFFF_FFFF;

/// wait4(pid, status, options, rusage). pid > 0 names a child, -1 is any
/// child, 0 the children in the caller's process group and below -1 those
/// in group -pid. Returns the child's pid; rusage comes back zeroed.
pub fn wait4(pid_arg: u64, status_va: u64, options: u64, rusage_va: u64) u64 {
    const me = smp.currentPid() orelse return err(EFAULT);
    const group: u8 = process.procs[me].tgid;
    const pid: i32 = @bitCast(@as(u32, @truncate(pid_arg)));
    const awaited: Awaited = if (pid > 0)
        .{ .slot = pid_nr.slotOf(@intCast(pid)) orelse return err(ECHILD) }
    else if (pid == -1)
        .any
    else if (pid == 0)
        .{ .group = process.procs[group].pgid }
    else
        .{ .group = @intCast(-@as(i64, pid)) };
    // What a dying child wakes: a waiter for its slot, or for any.
    const wake_on: u32 = switch (awaited) {
        .slot => |s| s,
        else => ANY_CHILD,
    };
    if (status_va != 0 and !common.validateUserPtrWriteAligned(status_va, 4, 4)) return err(EFAULT);
    if (rusage_va != 0 and !common.validateUserPtrWrite(rusage_va, RUSAGE_BYTES)) return err(EFAULT);
    // Registered before the first look, so a child dying after it wakes us.
    lifecycle.childWaitEnter(me);
    defer lifecycle.childWaitLeave(me);
    while (true) {
        var st: u32 = 0;
        if (reapChild(group, awaited, &st)) |child| {
            // Faultable copies: the pages were checked before the wait, and
            // a sibling thread's fork since makes them copy-on-write again.
            if (status_va != 0 and !usercopy.copyToUser(status_va, std.mem.asBytes(&st))) return err(EFAULT);
            if (rusage_va != 0) {
                const zero = [_]u8{0} ** RUSAGE_BYTES;
                if (!usercopy.copyToUser(rusage_va, &zero)) return err(EFAULT);
            }
            return child;
        }
        if (!hasChild(group, awaited)) return err(ECHILD);
        if (options & WNOHANG != 0) return 0;
        // A signal for the caller ends the wait, after the look above: a
        // child ready with it (SIGCHLD's own) is still reaped by this call.
        if (signals.deliverable(&process.procs[me]) != 0) return err(linux_signal.ERESTARTSYS);
        process.blockOn(.waitpid, wake_on);
    }
}

/// Two threads of a process may wait4 for the same child: one reaps it.
var reap_lock: @import("../../proc/spinlock.zig").SpinLock = .{};

/// Reap a zombie child of `group` among the `awaited`, its wait status in
/// `status`. Returns the child's number; null if none is reapable now.
fn reapChild(group: u8, awaited: Awaited, status: *u32) ?u32 {
    reap_lock.acquire();
    defer reap_lock.release();
    const z: u8 = switch (awaited) {
        .any => process.findZombieChild(group, ANY_CHILD),
        .slot => |s| process.findZombieChild(group, s),
        .group => blk: {
            for (0..process.MAX_PROCS) |i| {
                if (!awaited.has(i)) continue;
                if (process.findZombieChild(group, @intCast(i))) |z| break :blk z;
            }
            break :blk null;
        },
    } orelse return null;
    status.* = waitStatus(process.procs[z].exit_status);
    const nr = process.procs[z].pid_nr;
    process.reapZombie(z);
    return nr;
}

fn hasChild(group: u8, awaited: Awaited) bool {
    for (0..process.MAX_PROCS) |i| {
        if (process.procs[i].state == .unused or process.procs[i].parent_pid != group) continue;
        if (awaited.has(i)) return true;
    }
    return false;
}

/// What a signal the caller sends carries: `code` and the caller's pid.
fn fromCaller(code: i32) signals.Info {
    const me = linux_fs.proc() orelse return .{ .code = code };
    return .{ .code = code, .pid = me.pid_nr };
}

/// Signal `sig` for the process the task in `slot` belongs to; 0 only
/// checks that it is there.
fn signalProcess(slot: u8, sig: u32) u64 {
    const t = &process.procs[slot];
    if (t.state == .unused or t.state == .zombie or t.state == .loading) return err(ESRCH);
    if (t.is_idle or t.page_dir_phys == 0) return err(EPERM);
    if (!signals.killProcess(slot, sig, fromCaller(signals.SI_USER_CODE))) return err(ESRCH);
    return 0;
}

/// kill(pid, sig). pid > 0 is one process (any thread of it named), 0 the
/// caller's process group, below -1 the group -pid, and -1 every Linux
/// process but the caller's (native programs are not its to signal).
pub fn kill(pid_arg: u64, sig_arg: u64) u64 {
    const pid: i32 = @bitCast(@as(u32, @truncate(pid_arg)));
    const sig: u32 = @truncate(sig_arg);
    if (sig >= 65) return err(EINVAL);
    if (pid > 0) return signalProcess(pid_nr.slotOf(@intCast(pid)) orelse return err(ESRCH), sig);

    const me = linux_fs.proc() orelse return err(EFAULT);
    const everyone = pid == -1;
    const group: u32 = if (pid == 0) me.pgid else @intCast(-@as(i64, pid));
    var found = false;
    var self = false;
    for (0..process.MAX_PROCS) |i| {
        const p = &process.procs[i];
        if (!session.isProcess(i) or p.state == .zombie or p.is_idle or p.page_dir_phys == 0) continue;
        if (everyone) {
            if (p == me or p.personality != .linux) continue;
        } else if (p.pgid != group) continue;
        found = true;
        // The caller's own process goes last: its end ends this loop.
        if (p == me) self = true else _ = signalProcess(@intCast(i), sig);
    }
    if (self) return signalProcess(me.tgid, sig);
    return if (found) 0 else err(ESRCH);
}

/// tkill(tid, sig): a signal for one thread — only it takes it. abort()
/// and raise() send theirs this way.
pub fn tkill(tid: u64, sig: u64) u64 {
    const tid32: i32 = @bitCast(@as(u32, @truncate(tid)));
    if (tid32 <= 0) return err(EINVAL);
    if (sig >= 65) return err(EINVAL);
    const slot = pid_nr.slotOf(@intCast(tid32)) orelse return err(ESRCH);
    const t = &process.procs[slot];
    if (t.state == .zombie) return err(ESRCH);
    if (t.is_idle or t.page_dir_phys == 0) return err(EPERM);
    if (!signals.killTask(slot, @truncate(sig), fromCaller(signals.SI_TKILL_CODE))) return err(ESRCH);
    return 0;
}

/// tgkill(tgid, tid, sig): tkill that also names the thread's process.
pub fn tgkill(tgid: u64, tid: u64, sig: u64) u64 {
    const tid32: i32 = @bitCast(@as(u32, @truncate(tid)));
    const tgid32: i32 = @bitCast(@as(u32, @truncate(tgid)));
    if (tid32 <= 0 or tgid32 <= 0) return err(EINVAL);
    const slot = pid_nr.slotOf(@intCast(tid32)) orelse return err(ESRCH);
    if (pid_nr.of(process.procs[slot].tgid) != @as(u32, @intCast(tgid32))) return err(ESRCH);
    return tkill(tid, sig);
}

// --- process groups and sessions ---------------------------------------------

/// The process Linux pid `pid` names (0: the caller's `me`), or null.
fn processOf(pid: u64, me: *process.PCB) ?*process.PCB {
    const nr: u32 = @truncate(pid);
    if (nr == 0) return me;
    return process.leader(&process.procs[pid_nr.slotOf(nr) orelse return null]);
}

/// getpgid(pid); getpgrp is getpgid(0).
pub fn getpgid(pid: u64) u64 {
    const me = linux_fs.proc() orelse return err(EFAULT);
    return (processOf(pid, me) orelse return err(ESRCH)).pgid;
}

/// getsid(pid).
pub fn getsid(pid: u64) u64 {
    const me = linux_fs.proc() orelse return err(EFAULT);
    return (processOf(pid, me) orelse return err(ESRCH)).sid;
}

/// setpgid(pid, pgid): the caller or one of its children moves to a group
/// of the caller's session; pgid 0 (or the process's own pid) starts one.
pub fn setpgid(pid: u64, pgid_arg: u64) u64 {
    const me = linux_fs.proc() orelse return err(EFAULT);
    const want: i32 = @bitCast(@as(u32, @truncate(pgid_arg)));
    if (want < 0 or @as(i32, @bitCast(@as(u32, @truncate(pid)))) < 0) return err(EINVAL);
    const target = processOf(pid, me) orelse return err(ESRCH);
    if (target != me and target.parent_pid != me.tgid) return err(ESRCH);
    // A session's leader stays in the group it started.
    if (target.sid == target.pid_nr) return err(EPERM);
    const pgid: u32 = if (want == 0) target.pid_nr else @intCast(want);
    session.setGroup(me, target, pgid) catch return err(EPERM);
    return 0;
}

/// setsid(): a new session and group, both of the caller's pid. Not for a
/// process that leads a group: the group would lose it to the new session.
pub fn setsid() u64 {
    const me = linux_fs.proc() orelse return err(EFAULT);
    if (me.pgid == me.pid_nr) return err(EPERM);
    return session.startSession(me) catch err(EPERM);
}

// --- pipes and fds -----------------------------------------------------------

/// pipe2(fds, flags); pipe is pipe2(fds, 0).
pub fn pipe2(fds_va: u64, flags: u64) u64 {
    if (flags & ~(O_NONBLOCK | O_CLOEXEC | O_DIRECT) != 0) return err(EINVAL);
    if (!common.validateUserPtrWriteAligned(fds_va, 8, 4)) return err(EFAULT);
    const pcb = linux_fs.proc() orelse return err(EFAULT);
    const cloexec = flags & O_CLOEXEC != 0;
    const nonblock = flags & O_NONBLOCK != 0;
    const id = pipe.alloc() orelse return err(ENFILE);
    // Each file owns its end of the pipe from here: putting it closes the end.
    const rf = vfs.newFile(.{ .kind = .pipe, .pipe_id = id, .access = file.READ, .nonblock = nonblock }) orelse {
        pipe.closeReader(id);
        pipe.closeWriter(id);
        return err(ENFILE);
    };
    const wf = vfs.newFile(.{ .kind = .pipe, .pipe_id = id, .access = file.WRITE, .nonblock = nonblock }) orelse {
        file.put(rf);
        pipe.closeWriter(id);
        return err(ENFILE);
    };
    const r = vfs.allocFd(pcb) orelse return pipeFail(rf, wf, null, pcb);
    const w = vfs.allocFd(pcb) orelse return pipeFail(rf, wf, r, pcb);
    file.install(pcb, r, rf, cloexec);
    file.install(pcb, w, wf, cloexec);
    const out: *[2]i32 = @ptrFromInt(fds_va);
    out[0] = @intCast(r);
    out[1] = @intCast(w);
    return 0;
}

fn pipeFail(rf: *file.File, wf: *file.File, reserved: ?usize, pcb: *process.PCB) u64 {
    if (reserved) |fd| vfs.releaseFd(pcb, fd);
    file.put(rf);
    file.put(wf);
    return err(EMFILE);
}

/// dup(old): the lowest free fd.
pub fn dup(old: u64) u64 {
    return dupFrom(old, 0, false);
}

/// dup2(old, new).
pub fn dup2(old: u64, new: u64) u64 {
    const pcb = linux_fs.proc() orelse return err(EFAULT);
    if (old == new) return if (linux_fs.fdOpen(pcb, old)) new else err(EBADF);
    return dupAt(pcb, old, new, false);
}

/// dup3(old, new, flags).
pub fn dup3(old: u64, new: u64, flags: u64) u64 {
    if (flags & ~O_CLOEXEC != 0 or old == new) return err(EINVAL);
    const pcb = linux_fs.proc() orelse return err(EFAULT);
    return dupAt(pcb, old, new, flags & O_CLOEXEC != 0);
}

/// fd `old`'s file into slot `new` as well, whatever `new` held closed
/// after. The two share the file: one offset, one set of status flags.
fn dupAt(pcb: *process.PCB, old: u64, new: u64, cloexec: bool) u64 {
    if (new >= pcb.fd_table.len) return err(EBADF);
    const f = file.get(pcb, old) orelse return err(EBADF);
    switch (file.replace(pcb, @intCast(new), f, cloexec)) {
        // Being opened by another thread: its install would overwrite us.
        .busy => {
            file.put(f);
            return err(EBUSY);
        },
        .was => |victim| if (victim) |v| file.put(v),
    }
    return new;
}

/// fd `old`'s file into the lowest free slot at or above `min` as well
/// (dup, F_DUPFD).
pub fn dupFrom(old: u64, min: u64, cloexec: bool) u64 {
    const pcb = linux_fs.proc() orelse return err(EFAULT);
    const f = file.get(pcb, old) orelse return err(EBADF);
    const slot = file.reserveFrom(pcb, @intCast(@min(min, pcb.fd_table.len))) orelse {
        file.put(f);
        return err(EMFILE);
    };
    file.install(pcb, slot, f, cloexec);
    return slot;
}

// --- poll ------------------------------------------------------------------

pub const PollFd = extern struct { fd: i32, events: i16, revents: i16 };
const POLLNVAL: u16 = fdpoll.POLLNVAL;

/// poll(fds, nfds, timeout_ms); a negative timeout waits for good.
pub fn poll(fds_va: u64, nfds: u64, timeout_arg: u64) u64 {
    const ms: i32 = @bitCast(@as(u32, @truncate(timeout_arg)));
    return pollFor(fds_va, nfds, if (ms < 0) null else @as(u64, @intCast(ms)) * 1_000_000);
}

/// ppoll(fds, nfds, timeout, sigmask, sigsetsize): poll under `sigmask`
/// when one is given.
pub fn ppoll(fds_va: u64, nfds: u64, tmo_va: u64, mask_va: u64, mask_size: u64) u64 {
    if (mask_va != 0) {
        if (mask_size != 8) return err(EINVAL);
        var mask: u64 = 0;
        if (!usercopy.copyFromUser(std.mem.asBytes(&mask), mask_va)) return err(EFAULT);
        linux_signal.waitUnderMask(process.currentPCB() orelse return err(EFAULT), mask);
    }
    if (tmo_va == 0) return pollFor(fds_va, nfds, null);
    return switch (linux_time.readTimespec(tmo_va)) {
        .ns => |ns| pollFor(fds_va, nfds, ns),
        .fail => |e| e,
    };
}

/// Poll sets up to this size are copied to the stack, larger ones to the heap.
const POLL_STACK_FDS: usize = 32;

fn pollFor(fds_va: u64, nfds: u64, timeout_ns: ?u64) u64 {
    if (nfds > 1024) return err(EINVAL);
    const n: usize = @intCast(nfds);
    const bytes = n * @sizeOf(PollFd);
    if (n > 0 and !common.validateUserPtrWrite(fds_va, bytes)) return err(EFAULT);
    const me = smp.currentPid() orelse return err(EFAULT);
    // The set is read once and written back once, by faultable copies on
    // either side of the wait. A park can outlive the pages proven above
    // (swap, a sibling's munmap), and bringing one back blocks, which
    // inside the wait would eat the wake of an fd event.
    var on_stack: [POLL_STACK_FDS]PollFd = undefined;
    const on_heap: ?[*]u8 = if (n > POLL_STACK_FDS) (heap.kmalloc(bytes) orelse return err(ENOMEM)) else null;
    defer if (on_heap) |p| heap.kfree(p);
    const fds: []PollFd = if (on_heap) |p| @as([*]PollFd, @ptrCast(@alignCast(p)))[0..n] else on_stack[0..n];
    if (!usercopy.copyFromUser(std.mem.sliceAsBytes(fds), fds_va)) return err(EFAULT);
    // Cut short by a signal: EINTR if its handler runs, else the poll runs
    // again.
    const ready = pollWait(me, fds, timeout_ns) orelse return err(linux_signal.ERESTARTNOHAND);
    // Only revents goes back: a sibling's edit of fd or events during the
    // wait is the caller's to keep.
    for (fds, 0..) |*p, i| {
        const va = fds_va + i * @sizeOf(PollFd) + @offsetOf(PollFd, "revents");
        if (!usercopy.copyToUser(va, std.mem.asBytes(&p.revents))) return err(EFAULT);
    }
    return ready;
}

/// Fill revents in `fds`, waiting until an entry is ready or the timeout
/// passes; returns how many are ready, or null when a signal for the caller
/// ended the wait. Touches no user memory.
pub fn pollWait(me: usize, fds: []PollFd, timeout_ns: ?u64) ?u64 {
    const pcb = &process.procs[me];
    const group: u8 = pcb.tgid;
    const deadline: u64 = if (timeout_ns) |ns| deadlineAfter(ns) else 0;
    // Registered before the first look, so an fd event after it wakes us.
    fdpoll.sleeperEnter(me);
    defer {
        fdpoll.sleeperLeave(me);
        @atomicStore(u64, &pcb.wake_tick, 0, .release);
    }
    while (true) {
        var ready: u64 = 0;
        for (fds) |*p| {
            const fd = p.fd;
            if (fd < 0) {
                p.revents = 0;
                continue;
            }
            const want: u16 = @bitCast(p.events);
            const lead = &process.procs[group];
            // The file is held while it is asked: a close on another thread
            // can't take it from under its own answer. If ours is then the
            // last reference, the release can't sleep here.
            const mask: u16 = if (file.get(lead, @intCast(fd))) |f| blk: {
                defer file.putNoSleep(f);
                break :blk f.ops.poll(f, lead) & (want | fdpoll.POLLERR | fdpoll.POLLHUP);
            } else POLLNVAL;
            p.revents = @bitCast(mask);
            if (mask != 0) ready += 1;
        }
        if (ready > 0) return ready;
        if (timeout_ns) |ns| if (ns == 0 or process.tick_count >= deadline) return 0;
        if (signals.deliverable(pcb) != 0) return null;
        sched.blockOnDeadline(.poll, 0, deadline);
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
    const slot = pid_nr.slotOf(pid) orelse return err(ESRCH);
    if (process.procs[slot].tgid != process.procs[me].tgid) return err(EPERM);
    if (!common.validateUserPtr(local_va, liovcnt * @sizeOf(Iovec))) return err(EFAULT);
    if (!common.validateUserPtr(remote_va, riovcnt * @sizeOf(Iovec))) return err(EFAULT);
    // Each iovec read once into a local: the caller's other threads may
    // rewrite the arrays meanwhile.
    const local: [*]align(1) const volatile Iovec = @ptrFromInt(local_va);
    const remote: [*]align(1) const volatile Iovec = @ptrFromInt(remote_va);
    var li: usize = 0;
    var lv: Iovec = .{ .base = 0, .len = 0 };
    var loff: u64 = 0;
    var total: u64 = 0;
    for (0..riovcnt) |ri| {
        const rv = remote[ri];
        var roff: u64 = 0;
        while (roff < rv.len) {
            while (loff == lv.len) {
                if (li == liovcnt) return total;
                lv = local[li];
                li += 1;
                loff = 0;
            }
            const n = @min(rv.len - roff, lv.len - loff, 4096 - ((rv.base +% roff) & 0xFFF));
            const src = rv.base +% roff;
            const dst = lv.base +% loff;
            if (!common.validateUserPtr(src, n) or !common.validateUserPtrWrite(dst, n))
                return if (total > 0) total else err(EFAULT);
            // Both sides are the caller's memory, so they may overlap.
            const d: [*]u8 = @ptrFromInt(dst);
            const s: [*]const u8 = @ptrFromInt(src);
            if (dst <= src) std.mem.copyForwards(u8, d[0..n], s[0..n]) else std.mem.copyBackwards(u8, d[0..n], s[0..n]);
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

/// times(buf): the caller's CPU time in clock ticks (100 a second), all of
/// it booked as user time; its children's is not kept. Returns the ticks
/// since boot.
pub fn times(buf_va: u64) u64 {
    const me = linux_fs.proc() orelse return err(EFAULT);
    if (buf_va != 0) {
        const tms = [4]i64{ @intCast(me.ticks_used), 0, 0, 0 };
        if (!usercopy.copyToUser(buf_va, std.mem.asBytes(&tms))) return err(EFAULT);
    }
    return process.tick_count;
}

/// getrusage(who, usage): zeros but for the user time.
pub fn getrusage(usage_va: u64) u64 {
    const me = linux_fs.proc() orelse return err(EFAULT);
    var ru = [_]i64{0} ** (RUSAGE_BYTES / 8);
    ru[0] = @intCast(me.ticks_used / 100);
    ru[1] = @intCast((me.ticks_used % 100) * 10_000);
    if (!usercopy.copyToUser(usage_va, std.mem.asBytes(&ru))) return err(EFAULT);
    return 0;
}

const PR_SET_NAME: u64 = 15;
const PR_GET_NAME: u64 = 16;

/// prctl(option, arg2, ...): the thread's name; nothing else is kept.
pub fn prctl(option: u64, arg2: u64) u64 {
    const me = process.currentPCB() orelse return err(EFAULT);
    switch (option) {
        PR_SET_NAME => {
            var name: [16]u8 = [_]u8{0} ** 16;
            const len = usercopy.strnlenUser(arg2, 15) orelse return err(EFAULT);
            if (!usercopy.copyFromUser(name[0..len], arg2)) return err(EFAULT);
            me.name = name;
            me.name_len = @intCast(len);
            return 0;
        },
        PR_GET_NAME => {
            var name: [16]u8 = [_]u8{0} ** 16;
            @memcpy(name[0..me.name_len], me.name[0..me.name_len]);
            if (!usercopy.copyToUser(arg2, &name)) return err(EFAULT);
            return 0;
        },
        else => return err(EINVAL),
    }
}

/// getresuid and getresgid: three zeros (everything runs as root).
pub fn getresid(a_va: u64, b_va: u64, c_va: u64) u64 {
    const zero: u32 = 0;
    for ([_]u64{ a_va, b_va, c_va }) |va| {
        if (!usercopy.copyToUser(va, std.mem.asBytes(&zero))) return err(EFAULT);
    }
    return 0;
}
