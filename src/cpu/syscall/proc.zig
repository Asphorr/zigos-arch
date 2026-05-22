//! Syscall handlers (proc) — split out of syscall.zig (#797).
//! Dispatched from cpu/syscall.zig doSyscallInner; named in SYSCALLS.

const std = @import("std");
const vga = @import("../../ui/vga.zig");
const elf_loader = @import("../../proc/elf_loader.zig");
const keyboard = @import("../../driver/keyboard.zig");
const process = @import("../../proc/process.zig");
const vmm = @import("../../mm/vmm.zig");
const pmm = @import("../../mm/pmm.zig");
const paging = @import("../../mm/paging.zig");
const bga = @import("../../ui/bga.zig");
const vfs = @import("../../fs/vfs.zig");
const desktop = @import("../../ui/desktop.zig");
const xhci = @import("../../driver/xhci.zig");
const debug = @import("../../debug/debug.zig");
const perf = @import("../../debug/perf.zig");
const pipe = @import("../../proc/pipe.zig");
const memmap = @import("../../mm/memmap.zig");
const config = @import("../../config.zig");
const smp = @import("../smp.zig");
const signals = @import("../../proc/signals.zig");
const errno = @import("../../proc/errno.zig");
const sched_asm = @import("../../proc/sched_asm.zig");
const apic = @import("../../time/apic.zig");

const common = @import("common.zig");
const validateUserPtr = common.validateUserPtr;
const validateUserPtrAligned = common.validateUserPtrAligned;
const USER_SPACE_START = common.USER_SPACE_START;
const USER_SPACE_END = common.USER_SPACE_END;
const E_INVAL = common.E_INVAL;
const E_NOENT = common.E_NOENT;
const E_FAULT = common.E_FAULT;
const E_BADF = common.E_BADF;
const E_NOMEM = common.E_NOMEM;
const E_AGAIN = common.E_AGAIN;
const E_BUSY = common.E_BUSY;
const E_NAMETOOLONG = common.E_NAMETOOLONG;
const E_PIPE = common.E_PIPE;
const E_SRCH = common.E_SRCH;
const E_NOSYS = common.E_NOSYS;
const E_PERM = common.E_PERM;
const E_CHILD = common.E_CHILD;
const E_INTR = common.E_INTR;

pub fn sysExit() u32 {
    process.destroyCurrent();
    process.schedule();
    unreachable;
}

pub fn sysGetpid() u32 {
    return process.getCurrentPid();
}

pub fn sysYield() u32 {
    // handleIRQ0 funnels into schedule() which can dispatch a different
    // process. See process.zig State enum / switchTo asm for why we don't
    // pre-set state=.ready here.
    const t_pause = perf.rdtsc();
    smp.myCpu().pending_soft_yield = true;
    sched_asm.softYield();
    const t_resume = perf.rdtsc();
    if (process.currentPCB()) |pcb| pcb.perf_gap_cyc +%= t_resume -% t_pause;
    return 0;
}

pub fn sysUptime() u32 {
    return @truncate(process.tick_count);
}

pub fn sysExitStatus(arg1: u32) u32 {
    process.destroyCurrentWithStatus(arg1);
    process.schedule();
    unreachable;
}

pub fn sysGetArgc() u32 {
    const pcb = process.currentPCB() orelse return 0;
    return pcb.argc;
}

pub fn sysExitThread(arg1: u32) u32 {
    process.destroyCurrentWithStatus(arg1);
    return 0;
}

/// Stub registered in the SYSCALLS table so syscallName(92) returns "fork".
/// Never actually dispatched — case 92 in doSyscallInner intercepts before
/// reaching the table-driven path. Returns E_NOSYS as a safety net.
pub fn sysForkPlaceholder() u32 {
    return E_NOSYS;
}

/// fork() — clone the current process. Parent gets the child's PID, child
/// gets 0 in RAX when the scheduler eventually dispatches it.
///
/// `@call(.never_inline)` discipline: the kernel_esp watchpoint
/// (debug/watch.zig isLegitKernelEspWriter) whitelists writes by symbol name.
/// If forkCurrent inlines into sysFork, the kesp store gets attributed to
/// `cpu.syscall.sysFork` and panics as a wild writer. Same gotcha as
/// cloneCurrent's caller — see memory note `feedback_watch_whitelist_inlining`.
pub fn sysFork(frame: *signals.SyscallFrame) u32 {
    if (@call(.never_inline, process.forkCurrent, .{frame})) |child_pid| {
        return @intCast(child_pid);
    }
    return E_AGAIN;
}

// --- Sessions / process groups (#93..#97) ----------------------------------

/// setsid() — promote the caller to leader of a new session AND a new
/// process group. Returns the new sid (== caller's pid) on success.
///
/// EPERM is returned if the caller is already a process group leader of
/// any group — POSIX rule, prevents an existing pgid from being
/// "stranded" (its current leader would silently lose ownership of the
/// group). The classic daemon double-fork sidesteps this by always
/// calling setsid in a freshly-forked CHILD, which has its own pid
/// distinct from any pgid in the system.
pub fn sysSetsid() u32 {
    const pcb = process.currentPCB() orelse return E_FAULT;
    const my_pid: u8 = @intCast(process.getCurrentPid());
    // Group-leader check: scan for any other live process whose pgid ==
    // my_pid. If found, refuse — we'd orphan that group otherwise.
    var i: u8 = 0;
    while (i < process.MAX_PROCS) : (i += 1) {
        if (i == my_pid) continue;
        const st = process.getStateRaw(i);
        if (st == @intFromEnum(process.State.unused)) continue;
        if (process.getPCB(i).pgid == my_pid) return E_PERM;
    }
    pcb.sid = my_pid;
    pcb.pgid = my_pid;
    return my_pid;
}

/// setpgid(pid, pgid) — move process `pid` (or self if pid==0) into the
/// process group `pgid` (or create a new group equal to its own pid if
/// pgid==0). Both must be in the caller's session. Returns 0 on success.
///
/// Restrictions (POSIX):
///   * Target must be self or a child (we don't enforce parent_pid here
///     since we lack a privilege model — this is a single-user OS — but
///     we keep the same-session check below).
///   * Target's session must equal caller's session (you can't yank a
///     process out of its session via pgid changes; that needs setsid).
///   * `pgid`, if nonzero, must already exist as some process's pgid in
///     the caller's session, OR equal `pid` (creating a fresh group led
///     by the target).
pub fn sysSetpgid(arg_pid: u32, arg_pgid: u32) u32 {
    if (arg_pid >= process.MAX_PROCS) return E_INVAL;
    if (arg_pgid >= process.MAX_PROCS) return E_INVAL;
    const caller = process.currentPCB() orelse return E_FAULT;
    const my_pid: u8 = @intCast(process.getCurrentPid());

    const target_pid: u8 = if (arg_pid == 0) my_pid else @intCast(arg_pid);
    const target = process.getPCB(target_pid);
    const tst = process.getStateRaw(target_pid);
    if (tst == @intFromEnum(process.State.unused)) return E_SRCH;
    if (target.sid != caller.sid) return E_PERM;

    const new_pgid: u8 = if (arg_pgid == 0) target_pid else @intCast(arg_pgid);
    if (new_pgid != target_pid) {
        // Group must exist in caller's session.
        var found: bool = false;
        var i: u8 = 0;
        while (i < process.MAX_PROCS) : (i += 1) {
            const st = process.getStateRaw(i);
            if (st == @intFromEnum(process.State.unused)) continue;
            const p = process.getPCB(i);
            if (p.pgid == new_pgid and p.sid == caller.sid) {
                found = true;
                break;
            }
        }
        if (!found) return E_PERM;
    }
    target.pgid = new_pgid;
    return 0;
}

/// getpgrp() — return the caller's pgid. Cannot fail (well, except if
/// somehow currentPCB is null, in which case 0 is the same answer the
/// kernel idle PCB would give).
pub fn sysGetpgrp() u32 {
    const pcb = process.currentPCB() orelse return 0;
    return pcb.pgid;
}

/// getpgid(pid) — return process `pid`'s pgid (or self if pid==0).
pub fn sysGetpgid(arg_pid: u32) u32 {
    if (arg_pid >= process.MAX_PROCS) return E_INVAL;
    const target_pid: u8 = if (arg_pid == 0)
        @intCast(process.getCurrentPid())
    else
        @intCast(arg_pid);
    const st = process.getStateRaw(target_pid);
    if (st == @intFromEnum(process.State.unused)) return E_SRCH;
    return process.getPCB(target_pid).pgid;
}

/// getsid(pid) — return process `pid`'s sid (or self if pid==0).
pub fn sysGetsid(arg_pid: u32) u32 {
    if (arg_pid >= process.MAX_PROCS) return E_INVAL;
    const target_pid: u8 = if (arg_pid == 0)
        @intCast(process.getCurrentPid())
    else
        @intCast(arg_pid);
    const st = process.getStateRaw(target_pid);
    if (st == @intFromEnum(process.State.unused)) return E_SRCH;
    return process.getPCB(target_pid).sid;
}

/// Spawn a new thread that shares the calling process's address space.
/// `entry` is the user-mode RIP, `stack_top` is the new RSP, `arg` is
/// passed in RDI. fs_base / TLS is left at 0 — the new thread should
/// call sysSetTls(addr) before any %fs:NN access.
pub fn sysClone(entry: u32, stack_top: u32, arg: u32) u32 {
    if (entry < memmap.USER_VA_FLOOR) return E_INVAL;
    if (stack_top == 0) return E_INVAL;
    // never_inline keeps the kernel_esp stores inside cloneCurrent's symbol —
    // watch.zig:isLegitKernelEspWriter whitelists the create-path by symbol
    // name, so inlining cloneCurrent into sysClone makes the watchpoint
    // false-positive on its kesp writes.
    const tid = @call(.never_inline, process.cloneCurrent, .{
        @as(usize, @intCast(entry)),
        @as(usize, @intCast(stack_top)),
        @as(usize, @intCast(arg)),
        @as(u64, 0),
    }) orelse return E_INVAL;
    return @intCast(tid);
}

/// Set this thread's IA32_FS_BASE — the architectural %fs base used by
/// libc for thread-local storage (`__thread` variables, errno, the
/// pthread struct pointer). Stored in PCB.fs_base so context switches
/// re-apply it. Writes the MSR immediately so the calling thread sees
/// the new TLS without waiting for a reschedule.
pub fn sysSetTls(fs_base: u32) u32 {
    const pcb = process.currentPCB() orelse return E_FAULT;
    // We accept a 32-bit value because syscall args are u32; user TLS
    // VAs are below 4 GiB in our user-space layout, so this is fine.
    pcb.fs_base = @intCast(fs_base);
    const IA32_FS_BASE: u32 = 0xC0000100;
    asm volatile ("wrmsr"
        :
        : [msr] "{ecx}" (IA32_FS_BASE),
          [lo] "{eax}" (fs_base),
          [hi] "{edx}" (@as(u32, 0)));
    return 0;
}

const FUTEX_WAIT: u32 = 0;
const FUTEX_WAKE: u32 = 1;

/// Userspace synchronisation primitive — building block for libc
/// pthread_mutex / pthread_cond. Two ops:
///   WAIT(uaddr, val): if *uaddr == val, sleep on the address; else
///     return EAGAIN immediately. The compare-and-sleep is the whole
///     point of futex — it's how mutexes avoid lost-wakeup races.
///   WAKE(uaddr, n): wake up to n threads currently waiting on uaddr.
/// `uaddr` must be 4-byte aligned and inside the calling process's
/// address space; the kernel keys the wait queue by raw user VA, which
/// is fine because all threads share the same CR3.
pub fn sysFutex(uaddr: u32, op: u32, val: u32) u32 {
    if (uaddr == 0 or (uaddr & 3) != 0) return E_INVAL;
    if (!validateUserPtr(uaddr, 4)) return E_FAULT;

    switch (op) {
        FUTEX_WAIT => {
            // Compare-and-sleep. Fast EAGAIN check, then hand off to
            // blockOnFutex, which RE-CHECKS *uaddr only AFTER enrolling as a
            // waiter — so a FUTEX_WAKE racing our enrollment is never lost. The
            // old order (read *uaddr → blockOnInterruptible) dropped such a wake
            // and left the thread parked forever (the threadtest-teardown wedge:
            // [futex.wake.miss] then [wake-skip] explicit waker not firing).
            const word: *const volatile u32 = @ptrFromInt(@as(usize, uaddr));
            if (word.* != val) return E_INVAL; // EAGAIN
            _ = process.currentPCB() orelse return E_FAULT;
            return switch (process.blockOnFutex(uaddr, word, val)) {
                .again => E_INVAL, // *uaddr changed during enroll
                .signalled => E_INTR,
                .woke => 0,
            };
        },
        FUTEX_WAKE => {
            var woken: u32 = 0;
            for (0..process.MAX_PROCS) |i| {
                if (woken >= val) break;
                const t = &process.procs[i];
                if (t.wait_kind != .futex or t.wait_target != uaddr) continue;
                if (t.state == .unused or t.state == .zombie) continue;
                // Route through wake(): it sets wake_pending (so a waiter still
                // mid-enroll in blockOnFutex catches us via its Race B re-check)
                // and flips .sleeping->.ready. Matching futex waiters that
                // haven't reached .sleeping yet closes the enroll window the old
                // .sleeping-only scan dropped.
                process.wake(@intCast(i));
                woken += 1;
            }
            // woken == 0 is normal (an uncontended wake with no current waiter);
            // the old [futex.wake.miss] PCB dump was a lost-wake tripwire that
            // the enroll-window fix makes obsolete. The wakeExpired [wake-skip]
            // detector still catches any genuinely stuck waiter.
            return woken;
        },
        else => return 0xFFFFFFFF,
    }
}

pub fn sysSleep(ms: u32) u32 {
    const cur_pid = smp.myCpu().current_pid orelse return E_FAULT;
    const pcb = &process.procs[cur_pid];
    // Convert ms to ticks (100 Hz timer -> 10ms per tick). Widen to u64
    // BEFORE the +9 add — `(ms + 9) / 10` in u32 overflows for any
    // ms > 0xFFFFFFF6, which trivially-fuzzable input triggers.
    // Caught by redteam fuzzer hitting sysSleep with random u32.
    const ticks = (@as(u64, ms) + 9) / 10;
    pcb.wake_tick = process.tick_count +% ticks;
    process.setState(cur_pid, .sleeping);
    // Force the scheduler to actually deschedule us. Same alignment dance as
    // sys#07 — see comments there. wakeExpired() flips us back to .ready once
    // tick_count >= wake_tick.
    const t_pause = perf.rdtsc();
    smp.myCpu().pending_soft_yield = true;
    sched_asm.softYield();
    const t_resume = perf.rdtsc();
    if (process.currentPCB()) |p| p.perf_gap_cyc +%= t_resume -% t_pause;
    return 0;
}

pub fn sysExec(name_ptr: u32, name_len: u32) u32 {
    const actual_len = @min(name_len, 100);
    if (!validateUserPtr(name_ptr, actual_len)) return E_FAULT;
    const name_bytes: [*]const u8 = @ptrFromInt(@as(usize, name_ptr));

    // Copy full string to kernel stack BEFORE switching page directories
    var name_buf: [100]u8 = undefined;
    @memcpy(name_buf[0..actual_len], name_bytes[0..actual_len]);

    // Diag: log the requested name + first few bytes in hex so we can tell
    // when the shell is sending well-formed names vs corrupted bytes.
    {
        var hex: [32]u8 = undefined;
        const hexlen: usize = @min(actual_len, 8);
        const hexchars = "0123456789abcdef";
        for (0..hexlen) |k| {
            hex[k * 2] = hexchars[name_buf[k] >> 4];
            hex[k * 2 + 1] = hexchars[name_buf[k] & 0x0F];
        }
        @import("../../debug/debug.zig").klog("[sysExec] name='{s}' hex={s}\n", .{ name_buf[0..actual_len], hex[0 .. hexlen * 2] });
        // PMM diagnostic: free frames at every exec. If this drifts down
        // across runs of the same app, something isn't getting freed on
        // exit (process teardown or kernel-side caches).
        const pmm_diag = @import("../../mm/pmm.zig");
        @import("../../debug/debug.zig").klog("[pmm-diag] exec free={d}/{d}\n", .{ pmm_diag.freeFrameCount(), pmm_diag.managedFrameCount() });
    }

    // Split on first space: "editor.elf myfile.txt" -> filename + arg
    const fname_len = std.mem.indexOfScalar(u8, name_buf[0..actual_len], ' ') orelse actual_len;

    // Switch to kernel PD -- user PD doesn't map all kernel memory
    const caller_pd = if (process.currentPCB()) |pcb| pcb.page_dir_phys else 0;
    const caller_pcid = if (process.currentPCB()) |pcb| pcb.pcid else 0;
    @import("../pcid.zig").loadCr3(paging.getKernelPageDirPhys(), 0, @import("../smp.zig").myCpu().cpu_id);

    var pid: u32 = 0xFFFFFFFF;
    if (vfs.loadFileFresh(name_buf[0..fname_len])) |fresh| {
        if (elf_loader.loadAndStart(fresh.buf, fresh.size, fresh.pages)) |p| {
            pid = @intCast(p);
            // Set process name + exec arg
            const nlen = @min(fname_len, 16);
            var clean_name: [16]u8 = undefined;
            @memcpy(clean_name[0..nlen], name_buf[0..nlen]);
            // Strip .elf extension for name
            var nl = nlen;
            if (nl >= 4 and clean_name[nl - 4] == '.') nl -= 4;
            process.setName(@intCast(p), clean_name[0..nl]);
            // Promote to interactive immediately so the new process isn't
            // starved by an already-running interactive app — same fix as
            // desktop.launchShortcut and smp.pollAppLoad.
            process.getPCB(@intCast(p)).priority = .interactive;
            // Track parent for waitpid (Task #73). 0 means kernel-spawned;
            // we use the current process's pid here, which is non-zero for
            // any user-mode caller (idle is pid 0 and never calls exec).
            process.getPCB(@intCast(p)).parent_pid = @intCast(process.getCurrentPid());
            const child_pcb = process.getPCB(@intCast(p));
            // Inherit stdio (fd 0/1/2) from the caller. Without this, every
            // child boots with fd 0/1/2 = .console (see process.initFdTable),
            // which routes writes through vga.print — invisible in graphics
            // mode. Inheriting from the parent means a shell-spawned child
            // gets the shell's terminal pipes, and pipeline children inherit
            // the shell's stdout, so e.g. `wc`'s output reaches the terminal
            // even when its fd 1 isn't explicitly remapped. sysExecAs remaps
            // run after this and can replace any of these slots.
            //
            // Same loop also inherits the parent's cwd — without this every
            // child boots at "/tar/" (the field default), so a future `cd`
            // builtin in the shell would silently not affect children. Same
            // shape as the fd inheritance: copy bytes + length.
            if (process.currentPCB()) |parent| {
                // Defensive: if loadAndStart returned the caller's own PID
                // (which means create() found the caller's slot .unused —
                // a bug, but don't kernel-panic on it), skip inheritance
                // so @memcpy doesn't trip on aliasing args.
                if (parent != child_pcb) {
                    inline for ([_]u32{ 0, 1, 2 }) |fd| {
                        const psrc = parent.fd_table[fd];
                        if (psrc.in_use) {
                            child_pcb.fd_table[fd] = psrc;
                            if (psrc.fs_type == .pipe) {
                                if (psrc.flags == 0) pipe.addReader(psrc.pipe_id) else pipe.addWriter(psrc.pipe_id);
                            }
                        }
                    }
                    const cwd_n = parent.cwd_len;
                    @memcpy(child_pcb.cwd[0..cwd_n], parent.cwd[0..cwd_n]);
                    child_pcb.cwd_len = cwd_n;
                    // Inherit session and process group — POSIX semantics
                    // for spawn-as-fork+exec. Without this, every shell-
                    // launched app would land in its OWN session+group, so
                    // Ctrl+C from the shell could only signal the shell
                    // itself, never the foreground child. setsid() in the
                    // child still escapes (e.g. a daemon double-fork).
                    child_pcb.pgid = parent.pgid;
                    child_pcb.sid = parent.sid;
                    // CFS: inherit nice + pinned_cpu so `taskset CPU prog`
                    // and `nice N prog` (which fork → set → exec) actually
                    // affect the new program's slot, not just the short-
                    // lived nice/taskset wrapper. Without this, the
                    // wrapper's setaffinity/setnice was a no-op for the
                    // actual workload.
                    //
                    // pinned_cpu inheritance is two-step: loadAndStart
                    // already called assignInitialCpu (which saw the
                    // default pinned_cpu=0xFF and picked min-load CPU),
                    // so we now have to migrate the child to the actual
                    // pin destination if it differs.
                    child_pcb.nice = parent.nice;
                    child_pcb.pinned_cpu = parent.pinned_cpu;
                    if (parent.pinned_cpu != 0xFF and child_pcb.assigned_cpu != parent.pinned_cpu) {
                        _ = process.migrate(@intCast(p), parent.pinned_cpu);
                    }
                } else {
                    @import("../../debug/debug.zig").klog("[sysExec] WARN: child_pid == parent_pid={d} — inheritance skipped\n", .{process.getCurrentPid()});
                }
            }
            // Populate argv. argv[0] = program name (without the `.elf`
            // extension, matching how `setName` derives the kernel-side name).
            // argv[1..argc] = whitespace-split tokens from the rest of the
            // exec string, capped at MAX_ARGS-1 user args.
            populateArgv(child_pcb, clean_name[0..nl], name_buf[0..actual_len], fname_len);
        }
    }

    // Switch back to caller's PD (PCID-aware so caller's TLB is preserved).
    if (caller_pd != 0) {
        @import("../pcid.zig").loadCr3(caller_pd, caller_pcid, @import("../smp.zig").myCpu().cpu_id);
    }

    return pid;
}

/// Fill `child_pcb.argv` from a program name + the raw exec string. argv[0]
/// is the bare program name (no `.elf`); argv[1..] are space-separated
/// tokens from the input string starting after `fname_len`. Tokens longer
/// than MAX_ARG_LEN are truncated; argc is capped at MAX_ARGS.
pub fn populateArgv(
    child_pcb: *process.PCB,
    prog_name: []const u8,
    raw: []const u8,
    fname_len: usize,
) void {
    // argv[0]
    const n0 = @min(prog_name.len, config.MAX_ARG_LEN);
    @memcpy(child_pcb.argv[0][0..n0], prog_name[0..n0]);
    child_pcb.arg_lens[0] = @intCast(n0);
    child_pcb.argc = 1;

    // argv[1..]: walk the bytes after the program name, splitting on spaces.
    var i: usize = if (fname_len < raw.len) fname_len + 1 else raw.len;
    while (i < raw.len and child_pcb.argc < config.MAX_ARGS) {
        while (i < raw.len and raw[i] == ' ') : (i += 1) {}
        if (i >= raw.len) break;
        const start = i;
        while (i < raw.len and raw[i] != ' ') : (i += 1) {}
        const tok_len = @min(i - start, @as(usize, config.MAX_ARG_LEN));
        const slot = child_pcb.argc;
        @memcpy(child_pcb.argv[slot][0..tok_len], raw[start..][0..tok_len]);
        child_pcb.arg_lens[slot] = @intCast(tok_len);
        child_pcb.argc += 1;
    }
}

pub fn sysGetExecArg(buf_ptr: u32) u32 {
    if (!validateUserPtr(buf_ptr, 64)) return E_FAULT;
    const pcb = process.currentPCB() orelse return 0;
    if (pcb.argc <= 1) return 0;
    const buf: [*]u8 = @ptrFromInt(@as(usize, buf_ptr));
    // Backward-compat shim: existing apps (cat/echo/grep/head/editor) call
    // getExecArg expecting a 64-byte buffer with the user-supplied args
    // joined by single spaces — i.e. the byte-for-byte image of what came
    // after the first space in the original exec string. Reconstruct that
    // by joining argv[1..argc] with ' '. Truncates silently at 64 bytes.
    var written: usize = 0;
    var i: u8 = 1;
    while (i < pcb.argc and written < 64) : (i += 1) {
        if (i > 1 and written < 64) {
            buf[written] = ' ';
            written += 1;
        }
        const tok = pcb.argv[i][0..pcb.arg_lens[i]];
        const room = 64 - written;
        const tok_len = @min(tok.len, room);
        @memcpy(buf[written..][0..tok_len], tok[0..tok_len]);
        written += tok_len;
    }
    return @intCast(written);
}

pub fn sysGetArgv(idx: u32, buf_ptr: u32, buf_size: u32) u32 {
    const pcb = process.currentPCB() orelse return E_FAULT;
    if (idx >= pcb.argc) return E_INVAL;
    if (buf_size == 0) return E_INVAL;
    if (!validateUserPtr(buf_ptr, buf_size)) return E_FAULT;
    const tok = pcb.argv[idx][0..pcb.arg_lens[idx]];
    const n = @min(tok.len, buf_size);
    const dst: [*]u8 = @ptrFromInt(@as(usize, buf_ptr));
    @memcpy(dst[0..n], tok[0..n]);
    return @intCast(n);
}

pub fn sysSetPriority(priority: u32) u32 {
    const pcb = process.currentPCB() orelse return E_FAULT;

    // Validate priority value (0=background, 1=normal, 2=interactive)
    if (priority > 2) return E_INVAL;

    pcb.priority = @enumFromInt(@as(u8, @intCast(priority)));
    return 0;
}

/// sched_setaffinity(target_pid, cpu_id) — pin a thread to a specific
/// CPU, or unpin it.
///   target_pid == 0 → self (the calling thread)
///   target_pid > 0  → another thread, MUST share our tgid (security:
///                     can't pin other processes' threads)
///   cpu_id == 0xFFFFFFFF → unpin (load balancer takes over)
///   cpu_id < MAX_CPUS    → pin to that CPU; immediate migrate if .ready,
///                          deferred (preempt-IPI) if .running on another cpu.
/// Returns 0 on success, E_INVAL/E_FAULT/E_PERM on error.
pub fn sysSetAffinity(target_pid: u32, cpu_id: u32) u32 {
    const me_pcb = process.currentPCB() orelse return E_FAULT;
    const me_pid: u8 = @intCast(process.getCurrentPid());

    const target: u8 = if (target_pid == 0) me_pid else blk: {
        if (target_pid >= process.MAX_PROCS) return E_INVAL;
        break :blk @intCast(target_pid);
    };

    // Same-tgid permission check — only own threads (pthread-style).
    if (process.procs[target].tgid != me_pcb.tgid) return E_PERM;

    const cpu_u8: u8 = if (cpu_id == 0xFFFFFFFF) 0xFF else blk: {
        if (cpu_id >= 0xFF) return E_INVAL;
        break :blk @intCast(cpu_id);
    };

    if (!process.setAffinity(target, cpu_u8)) return E_INVAL;
    return 0;
}

/// sched_getaffinity(target_pid) — read a thread's affinity pin.
///   target_pid == 0 → self.
///   target_pid > 0  → another thread, must share our tgid.
///
/// Return encoding (offset-by-1 to disambiguate from small errno values
/// like E_INVAL=1, which would otherwise alias CPU id 0):
///   0           → unpinned (load balancer has discretion)
///   1..MAX_CPUS → pinned to CPU (return - 1)
///   0xFFFFFFFF  → error (E_INVAL bad pid, E_PERM different tgid,
///                 E_FAULT no caller PCB)
pub fn sysGetAffinity(target_pid: u32) u32 {
    const me_pcb = process.currentPCB() orelse return 0xFFFFFFFF;
    const me_pid: u8 = @intCast(process.getCurrentPid());

    const target: u8 = if (target_pid == 0) me_pid else blk: {
        if (target_pid >= process.MAX_PROCS) return 0xFFFFFFFF;
        break :blk @intCast(target_pid);
    };

    if (process.procs[target].tgid != me_pcb.tgid) return 0xFFFFFFFF;

    const pin = process.getAffinity(target);
    if (pin == 0xFF) return 0; // unpinned
    return @as(u32, pin) + 1;
}

/// sched_setnice(target_pid, new_nice) — Linux-style nice(2) for a single
/// thread. Range -20..19; out-of-range is clamped (Linux returns EINVAL,
/// but our ABI prefers "best effort within band" since unprivileged
/// userspace is the only caller).
///   target_pid == 0 → self.
///   target_pid > 0  → another thread, must share our tgid.
/// `new_nice` is encoded as i32 over the wire (cast to i8 internally).
/// Returns 0 on success, E_INVAL/E_PERM/E_FAULT on error.
pub fn sysSetNice(target_pid: u32, new_nice: u32) u32 {
    const me_pcb = process.currentPCB() orelse return E_FAULT;
    const me_pid: u8 = @intCast(process.getCurrentPid());

    const target: u8 = if (target_pid == 0) me_pid else blk: {
        if (target_pid >= process.MAX_PROCS) return E_INVAL;
        break :blk @intCast(target_pid);
    };

    if (process.procs[target].tgid != me_pcb.tgid) return E_PERM;

    // Decode i32-over-u32 → i8 with clamp. Userspace passes the signed
    // value bit-cast to u32; we sign-extend through i32 first.
    const nice_i32: i32 = @bitCast(new_nice);
    const clamped: i8 = if (nice_i32 < -20) -20 else if (nice_i32 > 19) 19 else @intCast(nice_i32);
    process.procs[target].nice = clamped;
    return 0;
}

/// sched_getnice(target_pid) — read current nice value as a u32 over the
/// wire (sign-extended from i8). target_pid == 0 = self; others gated on
/// same-tgid.
///
/// Encoding: returns nice + 21 (so 1..40 = nice -20..+19) so the success
/// space is disjoint from the error sentinel 0xFFFFFFFF. Caller subtracts
/// 21 to recover. (Linux returns 20-nice; we use a different offset to
/// keep "0 = error" reserved if we ever reuse that.)
pub fn sysGetNice(target_pid: u32) u32 {
    const me_pcb = process.currentPCB() orelse return 0xFFFFFFFF;
    const me_pid: u8 = @intCast(process.getCurrentPid());

    const target: u8 = if (target_pid == 0) me_pid else blk: {
        if (target_pid >= process.MAX_PROCS) return 0xFFFFFFFF;
        break :blk @intCast(target_pid);
    };

    if (process.procs[target].tgid != me_pcb.tgid) return 0xFFFFFFFF;

    const nice = process.procs[target].nice;
    return @intCast(@as(i32, nice) + 21);
}

// --- Clipboard (syscalls #103, #104) ---
//
// Single global byte buffer + length. Set overwrites previous contents;
// Get copies current contents into a user buffer and returns the actual
// length (caller passes max_len; we copy min(actual, max_len) so the
// user can detect truncation by comparing return value to their buffer
// size). No notifications, no MIME types, no multi-format — minimal
// shape for "editor copy → editor paste" and "shell `wc -l`-style
// paste into another window" to work. Future expansion (MIME, history)
// stays additive.

/// waitpid(pid, status_ptr) — block until a child of the calling process has
/// exited, then write its exit status to *status_ptr and return the reaped pid.
/// pid == 0xFFFFFFFF: any child. Otherwise: that exact child only.
/// Returns 0xFFFFFFFF if there is no such child (or the target isn't ours).
pub fn sysWaitpid(target_pid: u32, status_ptr: u32) u32 {
    if (status_ptr != 0 and !validateUserPtr(status_ptr, 4)) return E_INVAL;
    const me_pcb = process.currentPCB() orelse return E_FAULT;
    const me: u8 = @intCast(process.getCurrentPid());

    // Validate target — if a specific pid was named, it must be a child of us
    // and either alive or already a zombie. Otherwise the wait would never
    // succeed.
    if (target_pid != 0xFFFFFFFF) {
        if (target_pid >= process.MAX_PROCS) return E_INVAL;
        const child = &process.procs[@intCast(target_pid)];
        if (child.parent_pid != me) return E_INVAL;
        if (child.state == .unused) return E_INVAL;
    } else {
        // "any child" — make sure at least one child exists. If no children
        // exist at all, return immediately rather than blocking forever.
        var any: bool = false;
        for (0..process.MAX_PROCS) |i| {
            if (process.procs[i].state != .unused and process.procs[i].parent_pid == me) {
                any = true;
                break;
            }
        }
        if (!any) return E_INVAL;
    }

    while (true) {
        if (process.findZombieChild(me, target_pid)) |zpid| {
            const status = process.procs[zpid].exit_status;
            if (status_ptr != 0) {
                // != 0 guards the cast against null; aligned variant also
                // catches misaligned u32 (Zig safety panics on @ptrFromInt
                // to *u32 with non-4-byte-aligned int) and unmapped pages.
                if (!validateUserPtrAligned(status_ptr, 4, 4)) return E_FAULT;
                const sp: *u32 = @ptrFromInt(@as(usize, status_ptr));
                sp.* = status;
            }
            process.reapZombie(zpid);
            return zpid;
        }

        // Block until a child becomes a zombie (woken by killProcess/destroy
        // OR by a signal posted with signals.send). blockOnInterruptible
        // returns .signalled when a non-blocked signal is pending — either
        // on entry or arriving while parked — and we propagate -EINTR so the
        // handler delivery path on syscall-return doesn't fight a syscall
        // that would otherwise re-park immediately.
        const t_pause = perf.rdtsc();
        const br = process.blockOnInterruptible(.waitpid, target_pid);
        const t_resume = perf.rdtsc();
        me_pcb.perf_gap_cyc +%= t_resume -% t_pause;
        if (br == .signalled) return E_INTR;
    }
}

/// kill(pid, sig) — post `sig` to `pid`. SIGKILL/SIGSTOP can't be caught;
/// other signals go through the normal pending → handler / default-action
/// path. pid == self IS allowed (raise()) — the signal is delivered on the
/// way out of THIS syscall via deliverFromSyscallFrame.
pub fn sysKill(target_pid: u32, sig: u32) u32 {
    if (target_pid == 0 or target_pid >= process.MAX_PROCS) return E_INVAL;
    if (sig == 0 or sig >= signals.NSIG) return E_INVAL;
    if (!signals.send(@intCast(target_pid), sig)) return E_INVAL;
    return 0;
}

/// sigaction(signum, *new, *old) — install a signal handler. `new` and `old`
/// are pointers to user-space SigAction structs (or 0 to skip). SIGKILL and
/// SIGSTOP are silently ignored — caller can read the old action but can't
/// change the disposition.
pub fn sysSigaction(signum: u32, new_ptr: u32, old_ptr: u32) u32 {
    if (signum == 0 or signum >= signals.NSIG) return E_INVAL;
    const pcb = process.currentPCB() orelse return E_FAULT;
    const slot = &pcb.sigactions[signum];

    if (old_ptr != 0) {
        if (!validateUserPtrAligned(old_ptr, @sizeOf(signals.SigAction), @alignOf(signals.SigAction))) return E_INVAL;
        const op: *signals.SigAction = @ptrFromInt(@as(usize, old_ptr));
        op.* = slot.*;
    }
    if (new_ptr != 0) {
        if (!validateUserPtrAligned(new_ptr, @sizeOf(signals.SigAction), @alignOf(signals.SigAction))) return E_INVAL;
        const np: *const signals.SigAction = @ptrFromInt(@as(usize, new_ptr));
        // SIGKILL / SIGSTOP keep their default disposition no matter what.
        if (signum == signals.SIGKILL or signum == signals.SIGSTOP) return 0;
        slot.* = np.*;
    }
    return 0;
}

/// sigprocmask(how, *set, *oldset) — block/unblock/replace the signal mask.
/// SIGKILL/SIGSTOP can't be blocked even if the user asks (Linux silently
/// strips them; we do the same).
pub fn sysSigprocmask(how: u32, set_ptr: u32, old_ptr: u32) u32 {
    const pcb = process.currentPCB() orelse return E_FAULT;
    if (old_ptr != 0) {
        if (!validateUserPtrAligned(old_ptr, 4, 4)) return E_FAULT;
        const op: *u32 = @ptrFromInt(@as(usize, old_ptr));
        op.* = pcb.signal_mask;
    }
    if (set_ptr != 0) {
        if (!validateUserPtrAligned(set_ptr, 4, 4)) return E_FAULT;
        const sp: *const u32 = @ptrFromInt(@as(usize, set_ptr));
        const new_set = sp.*;
        const filter = ~((@as(u32, 1) << @intCast(signals.SIGKILL)) |
            (@as(u32, 1) << @intCast(signals.SIGSTOP)));
        switch (how) {
            signals.SIG_BLOCK => pcb.signal_mask |= new_set & filter,
            signals.SIG_UNBLOCK => pcb.signal_mask &= ~new_set,
            signals.SIG_SETMASK => pcb.signal_mask = new_set & filter,
            else => return 0xFFFFFFFF,
        }
    }
    return 0;
}

/// sigpending(*set) — write the bitmap of pending-but-blocked signals.
pub fn sysSigpending(set_ptr: u32) u32 {
    if (set_ptr == 0) return E_INVAL;
    if (!validateUserPtrAligned(set_ptr, 4, 4)) return E_FAULT;
    const pcb = process.currentPCB() orelse return E_FAULT;
    const sp: *u32 = @ptrFromInt(@as(usize, set_ptr));
    sp.* = pcb.pending_signals & pcb.signal_mask;
    return 0;
}

/// sigsuspend(*mask) — atomically replace mask with `*mask` and sleep until
/// any non-blocked signal becomes deliverable. Always returns 0xFFFFFFFF
/// (interrupted) per POSIX; the handler runs on the way back to user.
///
/// Caveat: the original mask isn't restored after the handler returns —
/// sigreturn will restore to the suspend-time mask, not pre-suspend. Mature
/// POSIX would track a "saved mask" flag; deferred until a real user shows up.
pub fn sysSigsuspend(mask_ptr: u32) u32 {
    if (mask_ptr == 0) return E_INVAL;
    if (!validateUserPtrAligned(mask_ptr, 4, 4)) return E_FAULT;
    const pcb = process.currentPCB() orelse return E_FAULT;
    const mp: *const u32 = @ptrFromInt(@as(usize, mask_ptr));
    const filter = ~((@as(u32, 1) << @intCast(signals.SIGKILL)) |
        (@as(u32, 1) << @intCast(signals.SIGSTOP)));
    pcb.signal_mask = mp.* & filter;

    // Park until a deliverable signal lands. Same idiom as sysSleep: state =
    // .sleeping + int $0x20; signals.send → process.wake → re-check.
    const cur_pid = smp.myCpu().current_pid orelse return E_FAULT;
    while (!signals.hasDeliverable(pcb)) {
        process.setState(cur_pid, .sleeping);
        pcb.wake_tick = std.math.maxInt(u64); // sleep "forever" — only signals wake us
        const t_pause = perf.rdtsc();
        smp.myCpu().pending_soft_yield = true;
        sched_asm.softYield();
        const t_resume = perf.rdtsc();
        pcb.perf_gap_cyc +%= t_resume -% t_pause;
    }
    return E_INVAL;
}

/// pause() — sleep until any signal is delivered. Equivalent to sigsuspend
/// with the current mask. Returns 0xFFFFFFFF (interrupted) when the handler
/// has run.
pub fn sysPause() u32 {
    const cur_pid = smp.myCpu().current_pid orelse return E_FAULT;
    const pcb = &process.procs[cur_pid];
    while (!signals.hasDeliverable(pcb)) {
        process.setState(cur_pid, .sleeping);
        pcb.wake_tick = std.math.maxInt(u64);
        const t_pause = perf.rdtsc();
        smp.myCpu().pending_soft_yield = true;
        sched_asm.softYield();
        const t_resume = perf.rdtsc();
        pcb.perf_gap_cyc +%= t_resume -% t_pause;
    }
    return E_INVAL;
}

/// Layout of one entry as user-space sees it. Must match libc's ProcInfo
/// extern struct exactly — kernel writes raw bytes via @memcpy.
const ProcInfoUser = extern struct {
    pid: u8,
    state: u8, // 0=unused, 1=ready, 2=running, 3=sleeping, 4=zombie
    parent_pid: u8,
    priority: u8, // 0=background, 1=normal, 2=interactive
    last_cpu: u8,
    name_len: u8,
    _pad: [2]u8 = .{ 0, 0 },
    ticks_used: u32,
    user_brk: u32,
    name: [16]u8,
    // Accounting (kernel-side mirror of acct_* PCB fields).
    cpu_ticks: u64 align(1) = 0,
    pf_count: u32 align(1) = 0,
    syscall_count: u64 align(1) = 0,
    peak_rss_pages: u32 align(1) = 0,
    current_rss_pages: u32 align(1) = 0,
    start_tick: u64 align(1) = 0,
    // Threads + sessions/groups. Appended after the accounting block so
    // older readers that don't know about these fields still see the same
    // header layout.
    tgid: u8 = 0,
    pgid: u8 = 0,
    sid: u8 = 0,
    // CFS scheduler fields (added 2026-05-10). Consume the prior _pad2
    // slack — old readers saw zeros here, new readers get the actual
    // nice/affinity/vruntime values for top-style displays.
    nice: i8 = 0,
    assigned_cpu: u8 = 0xFF, // current per-CPU rq this PCB is enqueued on
    pinned_cpu: u8 = 0xFF,   // sched_setaffinity pin (0xFF = unpinned)
    _pad2: [2]u8 = .{ 0, 0 },
    vruntime: u64 align(1) = 0,
    _pad3: [4]u8 = .{ 0, 0, 0, 0 }, // pad to 88 bytes (multiple of 8)
};

/// process_list(buf, max) — fill the user buffer with one ProcInfoUser per
/// active (non-unused) process slot. Returns the count written. The caller
/// passes max_entries = buf.len / sizeof(ProcInfoUser); we cap at MAX_PROCS
/// internally so a too-small buffer just returns a partial list.
pub fn sysProcessList(buf_ptr: u32, max_entries: u32) u32 {
    const ENTRY_SIZE = @sizeOf(ProcInfoUser);
    if (max_entries == 0 or max_entries > process.MAX_PROCS) return 0;
    if (!validateUserPtr(buf_ptr, max_entries * ENTRY_SIZE)) return 0;

    const dst: [*]u8 = @ptrFromInt(@as(usize, buf_ptr));
    var count: u32 = 0;

    for (0..process.MAX_PROCS) |i| {
        if (count >= max_entries) break;
        const pcb = &process.procs[i];
        if (pcb.state == .unused) continue;

        var info: ProcInfoUser = .{
            .pid = @intCast(i),
            .state = @intFromEnum(pcb.state),
            .parent_pid = pcb.parent_pid,
            .priority = @intFromEnum(pcb.priority),
            .last_cpu = pcb.last_cpu,
            .name_len = pcb.name_len,
            .ticks_used = pcb.ticks_used,
            .user_brk = @truncate(pcb.user_brk),
            .name = pcb.name,
            .cpu_ticks = pcb.acct_cpu_ticks,
            .pf_count = pcb.acct_pf_count,
            .syscall_count = pcb.acct_syscall_count,
            .peak_rss_pages = pcb.acct_peak_rss,
            .current_rss_pages = pcb.acct_current_rss,
            .start_tick = pcb.acct_start_tick,
            .tgid = pcb.tgid,
            .pgid = pcb.pgid,
            .sid = pcb.sid,
            .nice = pcb.nice,
            .assigned_cpu = pcb.assigned_cpu,
            .pinned_cpu = pcb.pinned_cpu,
            .vruntime = pcb.vruntime,
        };

        const off = count * ENTRY_SIZE;
        const src_bytes: [*]const u8 = @ptrCast(&info);
        for (0..ENTRY_SIZE) |k| dst[off + k] = src_bytes[k];
        count += 1;
    }
    return count;
}

/// alarm(seconds) — schedule SIGALRM after `seconds`. Returns the seconds
/// remaining on the previous alarm (0 if none / canceled). seconds == 0
/// cancels any pending alarm without scheduling a new one. The 100 Hz timer
/// IRQ delivers via process.deliverDueAlarms.
pub fn sysAlarm(seconds: u32) u32 {
    const pcb = process.currentPCB() orelse return 0;
    const now = process.tick_count;
    const prev_remaining: u32 = if (pcb.alarm_tick == 0)
        0
    else if (pcb.alarm_tick > now)
        @truncate((pcb.alarm_tick - now) / 100)
    else
        0;
    if (seconds == 0) {
        pcb.alarm_tick = 0;
    } else {
        pcb.alarm_tick = now + @as(u64, seconds) * 100;
    }
    return prev_remaining;
}

/// Layout of one entry in the user-supplied remap array.
const FdRemap = extern struct {
    parent_fd: u8,
    child_fd: u8,
    _pad: u16 = 0,
};

const FD_REMAP_MAX: usize = config.FD_REMAP_MAX;
const FD_SENTINEL: u8 = 0xFF;

/// exec_as(name_ptr, name_len, remap_ptr) — spawn `name` as a child, but
/// before letting it run, copy a few of the current process's fd_table entries
/// into the child's fd_table at caller-specified slots (typically used to wire
/// stdin/stdout to a pipe). remap_ptr points to a sentinel-terminated array
/// of FdRemap (max FD_REMAP_MAX entries; sentinel = parent_fd == 0xFF).
pub fn sysExecAs(name_ptr: u32, name_len: u32, remap_ptr: u32) u32 {
    // Copy up to FD_REMAP_MAX remap entries from the user buffer into kernel
    // memory before we switch address spaces. A sentinel ends the list.
    var remap: [FD_REMAP_MAX]FdRemap = undefined;
    var n_remap: usize = 0;
    if (remap_ptr != 0) {
        if (!validateUserPtrAligned(remap_ptr, FD_REMAP_MAX * @sizeOf(FdRemap), @alignOf(FdRemap))) return E_INVAL;
        const src: [*]const FdRemap = @ptrFromInt(@as(usize, remap_ptr));
        while (n_remap < FD_REMAP_MAX) : (n_remap += 1) {
            if (src[n_remap].parent_fd == FD_SENTINEL) break;
            remap[n_remap] = src[n_remap];
        }
    }

    const parent_pcb = process.currentPCB() orelse return E_FAULT;
    const parent_pid: u8 = @intCast(process.getCurrentPid());

    // Validate every remap parent_fd points at a real, in-use fd in the parent.
    for (0..n_remap) |i| {
        const pf = remap[i].parent_fd;
        const cf = remap[i].child_fd;
        if (pf >= parent_pcb.fd_table.len or cf >= parent_pcb.fd_table.len) return E_INVAL;
        if (!parent_pcb.fd_table[pf].in_use) return E_INVAL;
    }

    // Run the existing exec path. It returns a child pid (or 0xFFFFFFFF).
    @import("../../debug/serial.zig").print("[execAs] before sysExec name_len={d} n_remap={d}\n", .{ name_len, n_remap });
    const child_pid = sysExec(name_ptr, name_len);
    @import("../../debug/serial.zig").print("[execAs] sysExec returned pid={d}\n", .{child_pid});
    if (child_pid == 0xFFFFFFFF) return E_INVAL;

    // Apply remaps + bump pipe refcounts so parent-side closes don't drop the
    // last reference while the child is still using the inherited fd. sysExec
    // already inherited fd 0/1/2 from the parent above, so a remap targeting
    // one of those slots may be replacing an inherited pipe — drop its
    // refcount before installing the new entry, otherwise we leak.
    const child = process.getPCB(@intCast(child_pid));
    child.parent_pid = parent_pid;
    @import("../../debug/serial.zig").print("[execAs] set parent_pid done\n", .{});
    for (0..n_remap) |i| {
        const pf = remap[i].parent_fd;
        const cf = remap[i].child_fd;
        @import("../../debug/serial.zig").print("[execAs] remap[{d}] pf={d} cf={d}\n", .{ i, pf, cf });
        const old = child.fd_table[cf];
        if (old.in_use and old.fs_type == .pipe) {
            if (old.flags == 0) pipe.closeReader(old.pipe_id) else pipe.closeWriter(old.pipe_id);
        }
        const src = parent_pcb.fd_table[pf];
        @import("../../debug/serial.zig").print("[execAs] read parent fd_table[{d}] in_use={} fs_type={} pipe_id={d} flags={d}\n", .{ pf, src.in_use, src.fs_type, src.pipe_id, src.flags });
        child.fd_table[cf] = src;
        @import("../../debug/serial.zig").print("[execAs] wrote child fd_table[{d}]\n", .{cf});
        if (src.fs_type == .pipe) {
            if (src.flags == 0) pipe.addReader(src.pipe_id) else pipe.addWriter(src.pipe_id);
            @import("../../debug/serial.zig").print("[execAs] bumped pipe refcount\n", .{});
        }
    }

    @import("../../debug/serial.zig").print("[execAs] returning pid={d}\n", .{child_pid});
    return child_pid;
}

// --- Wall-clock time + microsecond sleep (Task #74) ---

/// gettimeofday(buf_ptr) — write { u64 sec, u32 usec } to user buffer. sec is
/// Unix epoch seconds; usec is microseconds within the current second.
/// Returns 0 on success.
pub fn sysGettimeofday(buf_ptr: u32) u32 {
    if (!validateUserPtr(buf_ptr, 16)) return E_FAULT;
    const time = @import("../../time/time.zig");
    const t = time.now();
    const out: [*]u8 = @ptrFromInt(@as(usize, buf_ptr));
    // Write u64 sec at offset 0, u32 usec at offset 8. Pad u32 at 12 stays
    // whatever was there — caller only reads the first 12 bytes meaningfully.
    const sec_ptr: *align(1) u64 = @ptrCast(out);
    const usec_ptr: *align(1) u32 = @ptrCast(out + 8);
    sec_ptr.* = t.sec;
    usec_ptr.* = t.usec;
    return 0;
}

/// usleep(usec) — sleep for `usec` microseconds. Tiered:
///   * usec <  10000  : pure HPET busy-wait (sub-tick precision matters more
///                       than CPU efficiency for sub-10ms sleeps).
///   * usec >= 10000  : descheduled sleep down to a 10ms tick boundary, then
///                       HPET busy-wait the remainder. Avoids burning CPU on
///                       long sleeps while keeping ~µs precision at the end.
pub fn sysUsleep(usec: u32) u32 {
    if (usec == 0) return 0;
    const time = @import("../../time/time.zig");
    const target = time.monotonicNanos() + @as(u64, usec) * 1000;

    // Coarse phase: tick-based deschedule for the bulk of long sleeps.
    if (usec >= 10_000) {
        const ms = (usec - 5_000) / 1_000; // leave ~5ms for fine spin
        if (ms > 0) {
            _ = sysSleep(ms);
        }
    }

    // Fine phase: HPET busy-wait until target. `pause` hints the CPU we're in
    // a spin loop — saves power on real hardware and avoids some pipeline
    // stalls. On QEMU it's a no-op but harmless.
    while (time.monotonicNanos() < target) {
        asm volatile ("pause");
    }
    return 0;
}

// === TLS 1.3 syscalls (107-110) ======================================
//
// Userspace wrappers around the kernel TlsConn pool. The kernel does
// the full handshake (X25519, HKDF, AEAD record framing) + cert
// verification + Mozilla NSS trust anchor lookup. Apps only push and
// pull plaintext.

