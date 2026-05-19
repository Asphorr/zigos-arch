const std = @import("std");
const vga = @import("../ui/vga.zig");
const elf_loader = @import("../proc/elf_loader.zig");
const keyboard = @import("../driver/keyboard.zig");
const process = @import("../proc/process.zig");
const vmm = @import("../mm/vmm.zig");
const pmm = @import("../mm/pmm.zig");
const paging = @import("../mm/paging.zig");
const bga = @import("../ui/bga.zig");
const vfs = @import("../fs/vfs.zig");
const desktop = @import("../ui/desktop.zig");
const xhci = @import("../driver/xhci.zig");
const debug = @import("../debug/debug.zig");
const perf = @import("../debug/perf.zig");
const pipe = @import("../proc/pipe.zig");
const memmap = @import("../mm/memmap.zig");
const config = @import("../config.zig");
const smp = @import("smp.zig");
const signals = @import("../proc/signals.zig");
const errno = @import("../proc/errno.zig");
const sched_asm = @import("../proc/sched_asm.zig");
const apic = @import("../time/apic.zig");

/// Slow-syscall sentinel threshold: any single syscall taking longer than
/// this prints `[slow-sc]` with sys#, pid, dt, args. 5ms catches the
/// "single submit blocks for seconds" class without spamming for normal
/// blocking primitives (those have their `perf_gap_cyc` adjustment so
/// only on-CPU time counts). Tunable; raise if too noisy in practice.
const SLOW_SYSCALL_THRESHOLD_MS: u64 = 5;

const E_INVAL: u32 = errno.err(.EINVAL);
const E_NOENT: u32 = errno.err(.ENOENT);
const E_FAULT: u32 = errno.err(.EFAULT);
const E_BADF: u32 = errno.err(.EBADF);
const E_NOMEM: u32 = errno.err(.ENOMEM);
const E_AGAIN: u32 = errno.err(.EAGAIN);
const E_BUSY: u32 = errno.err(.EBUSY);
const E_NAMETOOLONG: u32 = errno.err(.ENAMETOOLONG);
const E_PIPE: u32 = errno.err(.EPIPE);
const E_SRCH: u32 = errno.err(.ESRCH);
const E_NOSYS: u32 = errno.err(.ENOSYS);
const E_PERM: u32 = errno.err(.EPERM);
const E_CHILD: u32 = errno.err(.ECHILD);

// memmap.USER_SPACE_START sits below USER_VA_FLOOR to cover the user
// stack region (16 pages just under 0x500000). Earlier this was a local
// `= memmap.USER_VA_FLOOR` shadow, which silently drifted when memmap
// added the stack reserve — every syscall taking a stack-buffer arg
// (e.g. sysGetScreenSize) returned EFAULT, and apps tripped on the
// uninitialized (0xAAAAAAAA) buffer they assumed the kernel had filled.
const USER_SPACE_START: usize = memmap.USER_SPACE_START;
const USER_SPACE_END: usize = memmap.USER_SPACE_END;

/// Validate that a user pointer + length is within user address space, and
/// pre-fault any demand-paged pages in the range. Without the pre-fault, a
/// kernel-mode read of e.g. an app's .rodata string would bypass the USER
/// bit check and return inherited 2MB-page data (random kernel memory)
/// instead of the app's content.
fn validateUserPtr(ptr: usize, len: usize) bool {
    if (ptr < USER_SPACE_START or ptr >= USER_SPACE_END) return false;
    if (len > 0 and ptr + len > USER_SPACE_END) return false;
    if (len > 0 and ptr + len < ptr) return false; // overflow
    // Instrument the slow part — prefault + per-page PT walk. Cheap range
    // checks above don't need bracketing; the meaningful cost starts here.
    const sp = @import("../debug/syscall_perf.zig").scope(.user_ptr_walk);
    defer sp.end();
    if (len > 0) process.prefaultUserRange(ptr, len);
    // prefaultUserRange only maps pages inside registered lazy_regions; a
    // pointer to scratch user-VA stays unmapped and the kernel's @memcpy
    // would #PF in supervisor mode. Verify every page is actually present
    // before letting the syscall body dereference it. Found by redteam
    // fuzzer hitting sysGetcwd with a random user-range pointer.
    if (len > 0 and !process.allCurrentUserPagesMapped(ptr, len)) return false;
    // Validation succeeded — caller is about to deref. STAC unlocks user
    // memory access for the remainder of this syscall; doSyscall's defer
    // CLACs on exit. Cheap: with SMAP off this is a noop branch.
    @import("protect.zig").allowUserAccess();
    return true;
}

/// validateUserPtr + alignment check. Use whenever the caller is about to
/// `@ptrFromInt` to `*T` or `[*]T` with `@alignOf(T) > 1` — Zig's runtime
/// safety panics on misaligned cast (separate bug class from null/unmapped).
/// Found by redteam fuzzer hitting sysSigprocmask with an unaligned u32 ptr.
fn validateUserPtrAligned(ptr: usize, len: usize, comptime align_to: usize) bool {
    if (align_to > 1 and ptr & (align_to - 1) != 0) return false;
    return validateUserPtr(ptr, len);
}

export fn doSyscall(sys_num: u32, arg1: u32, arg2: u32, arg3: u32, frame_raw: *anyopaque) callconv(.c) u32 {
    // Per-CPU breadcrumb — stamp BEFORE everything else so even if we panic
    // mid-syscall, the autopsy reflects what this CPU was doing.
    @import("../debug/breadcrumb.zig").stamp(.syscall_entry, sys_num);
    // Unconditional, first-line, no-allocation entry trace — if we ever stop
    // seeing [sc-entry] for a process, doSyscall isn't being reached, so the
    // wedge is in syscall_entry.zig's per-CPU entry stub (RSP swap, RIP-rel
    // load of cpus[N].tss.rsp0) before we get here. Pre-PCB-lookup so a
    // corrupted PCB can't suppress it.
    {
        const enter_state = struct {
            var seen: [256]bool = [_]bool{false} ** 256;
        };
        if (sys_num < 256 and !enter_state.seen[sys_num]) {
            enter_state.seen[sys_num] = true;
            @import("../debug/serial.zig").print("[sc-entry] sys#{d}\n", .{sys_num});
        }
    }
    // Execution trail — record syscall entry into the per-CPU ring so
    // the autopsy can show "the last 32 things this CPU did" instead of
    // just the final stack frame. Encoded as a sentinel RIP, decoded
    // back to a syscall number by the trail dumper.
    @import("../debug/exectrail.zig").recordSyscall(sys_num);
    // Snap-clear: the LSTAR stub just pushed 15 SyscallFrame qwords starting
    // at top-8 down, naturally overwriting the iretq slots at top-40..top.
    // Any iretq_canary snapshot taken at the previous user-mode IRQ entry is
    // now compared against SyscallFrame leftovers and false-positives. Clear
    // it here so subsequent check()s during this syscall return early; the
    // next user-mode IRQ refreshes the snap from a real iretq frame.
    @import("../debug/iretq_canary.zig").invalidate();

    if (process.currentPCB()) |pcb| {
        pcb.perf_gap_cyc = 0;
        // Accounting: increment per-syscall counter. Bumped here (outer
        // doSyscall) rather than doSyscallInner so even rejected/unknown
        // syscall numbers count — they still cost dispatch overhead and
        // we want sysmon to show "this app is hammering syscalls".
        pcb.acct_syscall_count +%= 1;
        // Diagnostic ring: last 8 syscall numbers. Dumped on panic /
        // watchdog wedge to answer "what was this PID doing leading up
        // to the freeze?". Truncate sys_num to u16 (current max is
        // ~120, leaves headroom).
        process.recordSyscall(pcb, @truncate(sys_num));
    }
    // First-occurrence per (PID, syscall) trace — surfaces "is this process
    // making any syscalls at all" at near-zero runtime cost.
    {
        const cur_pid = process.getCurrentPid();
        const trace_dbg = struct {
            var seen: [process.MAX_PROCS][256]bool =
                [_][256]bool{[_]bool{false} ** 256} ** process.MAX_PROCS;
        };
        if (cur_pid < process.MAX_PROCS and sys_num < 256 and !trace_dbg.seen[cur_pid][sys_num]) {
            trace_dbg.seen[cur_pid][sys_num] = true;
            debug.klog("[sc] PID={d} sys#{d}\n", .{ cur_pid, sys_num });
        }
    }
    const t_enter = perf.enter();
    // Reset per-syscall phase tracker. Instrumented hot paths (validateUserPtr,
    // virtio_gpu wait, vfs read, ...) accumulate cycles into named phases;
    // dumped on slow-sc threshold so the operator sees WHERE the time went.
    @import("../debug/syscall_perf.zig").reset();
    // SMAP: ensure AC is cleared on syscall exit even if validateUserPtr
    // already STAC'd. The bracketing is per-syscall, not per-access — once
    // a syscall has unlocked user access for one buffer it stays unlocked
    // until return, but no other kernel path runs with AC=1.
    defer @import("protect.zig").disallowUserAccess();
    defer {
        // Subtract any descheduled-time gap recorded by blocking primitives
        // (yield/sleep) so the syscall counter reflects CPU time, not wall.
        const gap = if (process.currentPCB()) |pcb| pcb.perf_gap_cyc else 0;
        const adjusted_t_enter = t_enter +% gap;
        const t_end = perf.rdtsc();
        const dt = t_end -% adjusted_t_enter;
        perf.leave(.syscall, adjusted_t_enter);
        perf.syscallSample(sys_num, dt);

        // Slow-syscall sentinel. tscToMs returns 0 until APIC calibration
        // completes, which suppresses early-boot noise naturally. We log
        // CPU time (gap-adjusted), so a deliberate sleep(1s) won't fire —
        // only a syscall that ran on-CPU for >threshold does, which is the
        // signal we actually want for "what's blocking ctrl_lock for 10s".
        const dt_ms = apic.tscToMs(dt);
        if (dt_ms >= SLOW_SYSCALL_THRESHOLD_MS) {
            const cur_pid = process.getCurrentPid();
            debug.klog(
                "[slow-sc] sys#{d} pid={d} dt={d}ms args=0x{x} 0x{x} 0x{x}\n",
                .{ sys_num, cur_pid, dt_ms, arg1, arg2, arg3 },
            );
            // Per-phase breakdown — only fires when at least one
            // instrumented site recorded something.
            @import("../debug/syscall_perf.zig").dump();
        }
    }

    // Cast the asm-supplied frame pointer to its strongly-typed form. Field
    // layout matches the push order in syscall_entry.zig — see signals.zig.
    const frame: *signals.SyscallFrame = @ptrCast(@alignCast(frame_raw));

    // Sigreturn (#62) MUST short-circuit normal dispatch + signal-on-return —
    // it has its own special return semantics (returns the user's saved RAX,
    // and rewrites the caller's saved frame so sysret resumes pre-signal user
    // state). Routing it through the regular path would re-deliver any still-
    // pending signal before user code runs the post-handler instruction.
    if (sys_num == 62) {
        if (process.currentPCB()) |pcb| return signals.sigreturn(pcb, frame);
        return 0;
    }

    const ret = doSyscallInner(sys_num, arg1, arg2, arg3, frame);

    // Check pending signals on the way out. Skips if the dispatcher already
    // killed the process (currentPCB returns null after destroyCurrent), and
    // is a no-op when the process is mid-handler (in_signal_handler == true).
    if (process.currentPCB()) |pcb| {
        if ((pcb.pending_signals & ~pcb.signal_mask) != 0) {
            return signals.deliverFromSyscallFrame(pcb, frame, ret);
        }
    }
    return ret;
}

// ===========================================================================
// Syscall registry — single source of truth for the system-call ABI.
// To add a syscall: write a `sysFoo` helper anywhere in this file, then
// append an entry to SYSCALLS below. The dispatch table is built at
// comptime; doSyscallInner is a single array lookup. `wrap` adapts
// handlers of any arity (0..3) to the uniform Handler type.
// ===========================================================================

const Handler = *const fn (u32, u32, u32) u32;

/// Generate per-`f` thunk types. CRITICAL: each call to `Wrap(f)` returns
/// a fresh anonymous struct type because `f` is a comptime parameter — Zig
/// keys generic types by their parameter values. If we instead defined the
/// thunks inline as `&(struct { fn r(...) { return f(...); } }).r`, Zig's
/// anonymous-struct deduplication would unify all 1-arity thunks (all
/// bodies `return f(a1)` look identical), and every 1-arity syscall would
/// dispatch through whichever `f` got bound last — symptom: sysGetScreenSize
/// silently invokes some other handler that rejects the buffer with E_FAULT.
fn Wrap(comptime f: anytype) type {
    return struct {
        fn r0(_: u32, _: u32, _: u32) u32 {
            return f();
        }
        fn r1(a1: u32, _: u32, _: u32) u32 {
            return f(a1);
        }
        fn r2(a1: u32, a2: u32, _: u32) u32 {
            return f(a1, a2);
        }
        fn r3(a1: u32, a2: u32, a3: u32) u32 {
            return f(a1, a2, a3);
        }
    };
}

fn wrap(comptime f: anytype) Handler {
    const arity = @typeInfo(@TypeOf(f)).@"fn".params.len;
    const W = Wrap(f);
    return switch (arity) {
        0 => &W.r0,
        1 => &W.r1,
        2 => &W.r2,
        3 => &W.r3,
        else => @compileError("wrap: unsupported syscall arity"),
    };
}

const SyscallSpec = struct { num: u32, name: []const u8, handler: Handler };

const SYSCALLS = [_]SyscallSpec{
    .{ .num = 1,  .name = "print",                .handler = wrap(sysPrint) },
    .{ .num = 2,  .name = "clear",                .handler = wrap(sysClear) },
    .{ .num = 3,  .name = "exit",                 .handler = wrap(sysExit) },
    .{ .num = 4,  .name = "read",                 .handler = wrap(sysRead) },
    .{ .num = 5,  .name = "sbrk",                 .handler = wrap(sysSbrk) },
    .{ .num = 6,  .name = "getpid",               .handler = wrap(sysGetpid) },
    .{ .num = 7,  .name = "yield",                .handler = wrap(sysYield) },
    .{ .num = 8,  .name = "sleep",                .handler = wrap(sysSleep) },
    .{ .num = 9,  .name = "open",                 .handler = wrap(sysOpen) },
    .{ .num = 10, .name = "fread",                .handler = wrap(sysFread) },
    .{ .num = 11, .name = "fwrite",               .handler = wrap(sysFwrite) },
    .{ .num = 12, .name = "close",                .handler = wrap(sysClose) },
    .{ .num = 13, .name = "create_window",        .handler = wrap(sysCreateWindow) },
    .{ .num = 14, .name = "present",              .handler = wrap(sysPresent) },
    .{ .num = 15, .name = "get_mouse",            .handler = wrap(sysGetMouse) },
    .{ .num = 16, .name = "destroy_window",       .handler = wrap(sysDestroyWindow) },
    .{ .num = 17, .name = "uptime",               .handler = wrap(sysUptime) },
    .{ .num = 18, .name = "meminfo",              .handler = wrap(sysMeminfo) },
    .{ .num = 19, .name = "set_config",           .handler = wrap(sysSetConfig) },
    .{ .num = 20, .name = "notify",               .handler = wrap(sysNotify) },
    .{ .num = 21, .name = "listdir",              .handler = wrap(sysListDir) },
    .{ .num = 22, .name = "exec",                 .handler = wrap(sysExec) },
    .{ .num = 23, .name = "get_screen_size",      .handler = wrap(sysGetScreenSize) },
    .{ .num = 24, .name = "get_window_size",      .handler = wrap(sysGetWindowSize) },
    .{ .num = 25, .name = "get_exec_arg",         .handler = wrap(sysGetExecArg) },
    .{ .num = 26, .name = "get_key_state",        .handler = wrap(sysGetKeyState) },
    .{ .num = 27, .name = "set_cursor_visible",   .handler = wrap(sysSetCursorVisible) },
    .{ .num = 28, .name = "center_mouse",         .handler = wrap(sysCenterMouse) },
    .{ .num = 29, .name = "fsize",                .handler = wrap(sysFsize) },
    .{ .num = 30, .name = "gpu_ctx_create",       .handler = wrap(sysGpuCtxCreate) },
    .{ .num = 31, .name = "gpu_submit_3d",        .handler = wrap(sysGpuSubmit3D) },
    .{ .num = 32, .name = "gpu_ctx_destroy",      .handler = wrap(sysGpuCtxDestroy) },
    .{ .num = 33, .name = "gpu_get_capset_info",  .handler = wrap(sysGpuGetCapsetInfo) },
    .{ .num = 34, .name = "gpu_create_blob",      .handler = wrap(sysGpuCreateBlob) },
    .{ .num = 35, .name = "gpu_resource_create_3d", .handler = wrap(sysGpuResourceCreate3D) },
    .{ .num = 36, .name = "gpu_transfer_to_host_3d", .handler = wrap(sysGpuTransferToHost3D) },
    .{ .num = 37, .name = "gpu_map_blob",         .handler = wrap(sysGpuMapBlob) },
    .{ .num = 38, .name = "audio_write",          .handler = wrap(sysAudioWrite) },
    .{ .num = 39, .name = "chdir",                .handler = wrap(sysChdir) },
    .{ .num = 40, .name = "getcwd",               .handler = wrap(sysGetcwd) },
    .{ .num = 41, .name = "mkdir",                .handler = wrap(sysMkdir) },
    .{ .num = 42, .name = "readdir",              .handler = wrap(sysReaddir) },
    .{ .num = 43, .name = "unlink",               .handler = wrap(sysUnlink) },
    .{ .num = 44, .name = "stat",                 .handler = wrap(sysStat) },
    .{ .num = 45, .name = "rename",               .handler = wrap(sysRename) },
    .{ .num = 46, .name = "rmdir",                .handler = wrap(sysRmdir) },
    .{ .num = 47, .name = "setpriority",          .handler = wrap(sysSetPriority) },
    .{ .num = 48, .name = "exit_status",          .handler = wrap(sysExitStatus) },
    .{ .num = 49, .name = "waitpid",              .handler = wrap(sysWaitpid) },
    .{ .num = 50, .name = "kill",                 .handler = wrap(sysKill) },
    .{ .num = 51, .name = "pipe",                 .handler = wrap(sysPipe) },
    .{ .num = 52, .name = "exec_as",              .handler = wrap(sysExecAs) },
    .{ .num = 53, .name = "gettimeofday",         .handler = wrap(sysGettimeofday) },
    .{ .num = 54, .name = "usleep",               .handler = wrap(sysUsleep) },
    .{ .num = 55, .name = "get_argc",             .handler = wrap(sysGetArgc) },
    .{ .num = 56, .name = "get_argv",             .handler = wrap(sysGetArgv) },
    .{ .num = 57, .name = "mmap",                 .handler = wrap(sysMmap) },
    .{ .num = 58, .name = "munmap",               .handler = wrap(sysMunmap) },
    .{ .num = 59, .name = "mprotect",             .handler = wrap(sysMprotect) },
    .{ .num = 60, .name = "rt_sigaction",         .handler = wrap(sysSigaction) },
    .{ .num = 61, .name = "rt_sigprocmask",       .handler = wrap(sysSigprocmask) },
    // 62 (sigreturn) is intercepted in doSyscall outer, never dispatched.
    .{ .num = 63, .name = "sigpending",           .handler = wrap(sysSigpending) },
    .{ .num = 64, .name = "sigsuspend",           .handler = wrap(sysSigsuspend) },
    .{ .num = 65, .name = "pause",                .handler = wrap(sysPause) },
    .{ .num = 66, .name = "alarm",                .handler = wrap(sysAlarm) },
    .{ .num = 67, .name = "klog",                 .handler = wrap(sysKlog) },
    .{ .num = 68, .name = "net_resolve",          .handler = wrap(sysNetResolve) },
    .{ .num = 69, .name = "net_http_get",         .handler = wrap(sysNetHttpGet) },
    .{ .num = 70, .name = "net_tcp_connect",      .handler = wrap(sysNetTcpConnect) },
    .{ .num = 71, .name = "net_tcp_send",         .handler = wrap(sysNetTcpSend) },
    .{ .num = 72, .name = "net_tcp_recv",         .handler = wrap(sysNetTcpRecv) },
    .{ .num = 73, .name = "net_tcp_close",        .handler = wrap(sysNetTcpClose) },
    .{ .num = 74, .name = "net_tcp_status",       .handler = wrap(sysNetTcpStatus) },
    .{ .num = 75, .name = "net_tcp_listen",       .handler = wrap(sysNetTcpListen) },
    .{ .num = 76, .name = "net_tcp_unlisten",     .handler = wrap(sysNetTcpUnlisten) },
    .{ .num = 77, .name = "net_tcp_accept",       .handler = wrap(sysNetTcpAccept) },
    .{ .num = 78, .name = "process_list",         .handler = wrap(sysProcessList) },
    .{ .num = 79, .name = "usb_info",             .handler = wrap(sysUsbInfo) },
    .{ .num = 80, .name = "usb_read_sector",      .handler = wrap(sysUsbReadSector) },
    .{ .num = 81, .name = "usb_write_sector",     .handler = wrap(sysUsbWriteSector) },
    .{ .num = 82, .name = "shutdown",             .handler = wrap(sysShutdown) },
    .{ .num = 83, .name = "clone",                .handler = wrap(sysClone) },
    .{ .num = 84, .name = "set_tls",              .handler = wrap(sysSetTls) },
    .{ .num = 85, .name = "futex",                .handler = wrap(sysFutex) },
    .{ .num = 86, .name = "exit_thread",          .handler = wrap(sysExitThread) },
    .{ .num = 87, .name = "gpu_transfer_from_host_3d", .handler = wrap(sysGpuTransferFromHost3D) },
    .{ .num = 88, .name = "gpu_set_scanout_blob",    .handler = wrap(sysGpuSetScanoutBlob) },
    .{ .num = 89, .name = "gpu_resource_flush",      .handler = wrap(sysGpuResourceFlush) },
    .{ .num = 90, .name = "poll_event",              .handler = wrap(sysPollEvent) },
    .{ .num = 91, .name = "gpu_create_guest_blob",   .handler = wrap(sysGpuCreateGuestBlob) },
    // 92 (fork) is dispatched directly in doSyscallInner — it needs the saved
    // SyscallFrame to seed child's kstack, which `wrap()` doesn't pass through.
    // Name is registered here so syscallName() / klog still resolve "fork".
    .{ .num = 92, .name = "fork",                    .handler = wrap(sysForkPlaceholder) },
    .{ .num = 93, .name = "setsid",                  .handler = wrap(sysSetsid) },
    .{ .num = 94, .name = "setpgid",                 .handler = wrap(sysSetpgid) },
    .{ .num = 95, .name = "getpgrp",                 .handler = wrap(sysGetpgrp) },
    .{ .num = 96, .name = "getpgid",                 .handler = wrap(sysGetpgid) },
    .{ .num = 97, .name = "getsid",                  .handler = wrap(sysGetsid) },
    .{ .num = 98, .name = "set_wallpaper",            .handler = wrap(sysSetWallpaper) },
    .{ .num = 99, .name = "set_affinity",             .handler = wrap(sysSetAffinity) },
    .{ .num = 100, .name = "get_affinity",            .handler = wrap(sysGetAffinity) },
    .{ .num = 101, .name = "set_nice",                .handler = wrap(sysSetNice) },
    .{ .num = 102, .name = "get_nice",                .handler = wrap(sysGetNice) },
    .{ .num = 103, .name = "set_clipboard",           .handler = wrap(sysSetClipboard) },
    .{ .num = 104, .name = "get_clipboard",           .handler = wrap(sysGetClipboard) },
    .{ .num = 105, .name = "cpu_stats",               .handler = wrap(sysCpuStats) },
    .{ .num = 106, .name = "net_info",                .handler = wrap(sysNetInfo) },
    .{ .num = 107, .name = "tls_connect",             .handler = wrap(sysTlsConnect) },
    .{ .num = 108, .name = "tls_send",                .handler = wrap(sysTlsSend) },
    .{ .num = 109, .name = "tls_recv",                .handler = wrap(sysTlsRecv) },
    .{ .num = 110, .name = "tls_close",               .handler = wrap(sysTlsClose) },
    .{ .num = 111, .name = "seek",                    .handler = wrap(sysSeek) },
};

const MAX_SYSCALL: u32 = 111;
const dispatch: [MAX_SYSCALL + 1]?Handler = blk: {
    var t: [MAX_SYSCALL + 1]?Handler = [_]?Handler{null} ** (MAX_SYSCALL + 1);
    for (SYSCALLS) |s| t[s.num] = s.handler;
    break :blk t;
};

/// Returns the registered name for a syscall number, or null if not registered.
/// Useful for diagnostic output (sysmon, dmesg, kdbg autopsy).
pub fn syscallName(num: u32) ?[]const u8 {
    for (SYSCALLS) |s| if (s.num == num) return s.name;
    return null;
}

// --- Lifted helpers for cases that were previously inline in the switch ---

fn sysPrint(arg1: u32, arg2: u32) u32 {
    if (!validateUserPtr(arg1, arg2)) return E_FAULT;
    const ptr: [*]const u8 = @ptrFromInt(@as(usize, arg1));
    const msg = ptr[0..arg2];
    vga.print("{s}", .{msg});
    @import("../debug/serial.zig").print("[app] {s}", .{msg});
    return 0;
}

fn sysClear() u32 {
    vga.clear();
    return 0;
}

fn sysExit() u32 {
    process.destroyCurrent();
    process.schedule();
    unreachable;
}

fn sysRead() u32 {
    const pcb = process.currentPCB() orelse return 0;
    const fd0 = &pcb.fd_table[0];
    if (!fd0.in_use) return 0;
    switch (fd0.fs_type) {
        .console => {
            // Reads from the focused window's per-window event queue
            // (see ui/events.zig). The queue is filled only when this
            // window is focused, so background apps' polling loops
            // naturally see nothing rather than stealing input.
            const cur: u8 = @intCast(process.getCurrentPid());
            if (desktop.popCharEvent(cur)) |ch| return @as(u32, ch);
            return 0;
        },
        .pipe => {
            var buf: [1]u8 = .{0};
            const n = @import("../proc/pipe.zig").tryRead(fd0.pipe_id, &buf);
            if (n == 0) return 0;
            return buf[0];
        },
        else => return 0,
    }
}

fn sysGetpid() u32 {
    return process.getCurrentPid();
}

fn sysYield() u32 {
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

fn sysUptime() u32 {
    return @truncate(process.tick_count);
}

fn sysGetKeyState(arg1: u32) u32 {
    if (arg1 < 256) return @intFromBool(keyboard.key_state[arg1]);
    return 0;
}

/// poll_event(buf_ptr): drain one event from the focused window's queue
/// into the user-space `Event` (16 bytes) at `buf_ptr`. Returns the
/// event kind on success, 0 if no events / not focused / etc. Apps that
/// want non-blocking input call this in their loop and dispatch on
/// the returned kind.
///
/// Replaces the patchwork of `getKeyState`-polling-plus-readChar that
/// existing apps use for input. Existing apps keep working — sysRead
/// is now a thin wrapper around the same per-window queue, so each
/// keystroke is delivered exactly once whether you read via fd 0 or
/// poll_event (apps must pick one — mixing both will lose events).
fn sysPollEvent(buf_ptr: u32) u32 {
    if (buf_ptr == 0) return 0;
    if (!validateUserPtrAligned(buf_ptr, @sizeOf(desktop.Event), @alignOf(desktop.Event))) return 0;
    var ev: desktop.Event = .{ .kind = 0 };
    const cur: u8 = @intCast(process.getCurrentPid());
    if (!desktop.popEvent(cur, &ev)) return 0;
    const dst: *desktop.Event = @ptrFromInt(@as(usize, buf_ptr));
    dst.* = ev;
    return ev.kind;
}

fn sysSetCursorVisible(arg1: u32) u32 {
    const pid: u8 = @intCast(process.getCurrentPid());
    desktop.setCursorHidden(pid, arg1 == 0);
    return 0;
}

fn sysCenterMouse() u32 {
    const pid: u8 = @intCast(process.getCurrentPid());
    desktop.centerMouse(pid);
    return 0;
}

fn sysExitStatus(arg1: u32) u32 {
    process.destroyCurrentWithStatus(arg1);
    process.schedule();
    unreachable;
}

fn sysGetArgc() u32 {
    const pcb = process.currentPCB() orelse return 0;
    return pcb.argc;
}

fn sysExitThread(arg1: u32) u32 {
    process.destroyCurrentWithStatus(arg1);
    return 0;
}

fn doSyscallInner(sys_num: u32, arg1: u32, arg2: u32, arg3: u32, frame: *signals.SyscallFrame) u32 {
    // sigreturn (#62) is intercepted in doSyscall outer; fork (#92) needs the
    // frame to seed child's kstack; everything else uses arg1..arg3 only.
    // Explicit switch dispatch — A/B-tested against the comptime
    // wrap/dispatch table in zigos-arch-oldsyscalls and proven stable.
    // Each handler is called directly with the exact arity it declares so
    // there's no thunk layer, no function-pointer indirection, and no
    // possibility of arity mismatch.
    //
    // The SYSCALLS table above is now used ONLY for syscallName() lookups
    // (klog/debug), not for dispatch — keep it in sync with this switch
    // when adding/removing syscalls. A failure to do so means the syscall
    // will dispatch correctly here but show as "?" in klog.
    return switch (sys_num) {
        1 => sysPrint(arg1, arg2),
        2 => sysClear(),
        3 => sysExit(),
        4 => sysRead(),
        5 => sysSbrk(arg1),
        6 => sysGetpid(),
        7 => sysYield(),
        8 => sysSleep(arg1),
        9 => sysOpen(arg1, arg2),
        10 => sysFread(arg1, arg2, arg3),
        11 => sysFwrite(arg1, arg2, arg3),
        12 => sysClose(arg1),
        13 => sysCreateWindow(arg1, arg2, arg3),
        14 => sysPresent(),
        15 => sysGetMouse(arg1),
        16 => sysDestroyWindow(),
        17 => sysUptime(),
        18 => sysMeminfo(arg1),
        19 => sysSetConfig(arg1, arg2),
        20 => sysNotify(arg1, arg2),
        21 => sysListDir(arg1, arg2),
        22 => sysExec(arg1, arg2),
        23 => sysGetScreenSize(arg1),
        24 => sysGetWindowSize(arg1),
        25 => sysGetExecArg(arg1),
        26 => sysGetKeyState(arg1),
        27 => sysSetCursorVisible(arg1),
        28 => sysCenterMouse(),
        29 => sysFsize(arg1),
        30 => sysGpuCtxCreate(arg1),
        31 => sysGpuSubmit3D(arg1, arg2),
        32 => sysGpuCtxDestroy(),
        33 => sysGpuGetCapsetInfo(arg1, arg2),
        34 => sysGpuCreateBlob(arg1, arg2, arg3),
        35 => sysGpuResourceCreate3D(arg1),
        36 => sysGpuTransferToHost3D(arg1, arg2),
        37 => sysGpuMapBlob(arg1, arg2),
        38 => sysAudioWrite(arg1, arg2),
        39 => sysChdir(arg1),
        40 => sysGetcwd(arg1, arg2),
        41 => sysMkdir(arg1),
        42 => sysReaddir(arg1, arg2, arg3),
        43 => sysUnlink(arg1, arg2),
        44 => sysStat(arg1, arg2, arg3),
        45 => sysRename(arg1, arg2, arg3),
        46 => sysRmdir(arg1, arg2),
        47 => sysSetPriority(arg1),
        48 => sysExitStatus(arg1),
        49 => sysWaitpid(arg1, arg2),
        50 => sysKill(arg1, arg2),
        51 => sysPipe(arg1),
        52 => sysExecAs(arg1, arg2, arg3),
        53 => sysGettimeofday(arg1),
        54 => sysUsleep(arg1),
        55 => sysGetArgc(),
        56 => sysGetArgv(arg1, arg2, arg3),
        57 => sysMmap(arg1, arg2, arg3),
        58 => sysMunmap(arg1, arg2),
        59 => sysMprotect(arg1, arg2, arg3),
        60 => sysSigaction(arg1, arg2, arg3),
        61 => sysSigprocmask(arg1, arg2, arg3),
        // 62 (sigreturn) is intercepted in doSyscall outer, never dispatched.
        63 => sysSigpending(arg1),
        64 => sysSigsuspend(arg1),
        65 => sysPause(),
        66 => sysAlarm(arg1),
        67 => sysKlog(arg1, arg2),
        68 => sysNetResolve(arg1, arg2, arg3),
        69 => sysNetHttpGet(arg1, arg2, arg3),
        70 => sysNetTcpConnect(arg1, arg2),
        71 => sysNetTcpSend(arg1, arg2, arg3),
        72 => sysNetTcpRecv(arg1, arg2, arg3),
        73 => sysNetTcpClose(arg1),
        74 => sysNetTcpStatus(arg1),
        75 => sysNetTcpListen(arg1),
        76 => sysNetTcpUnlisten(arg1),
        77 => sysNetTcpAccept(arg1),
        78 => sysProcessList(arg1, arg2),
        79 => sysUsbInfo(arg1),
        80 => sysUsbReadSector(arg1, arg2),
        81 => sysUsbWriteSector(arg1, arg2),
        82 => sysShutdown(arg1),
        83 => sysClone(arg1, arg2, arg3),
        84 => sysSetTls(arg1),
        85 => sysFutex(arg1, arg2, arg3),
        86 => sysExitThread(arg1),
        87 => sysGpuTransferFromHost3D(arg1, arg2),
        88 => sysGpuSetScanoutBlob(arg1, arg2),
        89 => sysGpuResourceFlush(arg1, arg2),
        90 => sysPollEvent(arg1),
        91 => sysGpuCreateGuestBlob(arg1, arg2),
        92 => sysFork(frame),
        93 => sysSetsid(),
        94 => sysSetpgid(arg1, arg2),
        95 => sysGetpgrp(),
        96 => sysGetpgid(arg1),
        97 => sysGetsid(arg1),
        98 => sysSetWallpaper(arg1, arg2, arg3),
        99 => sysSetAffinity(arg1, arg2),
        100 => sysGetAffinity(arg1),
        101 => sysSetNice(arg1, arg2),
        102 => sysGetNice(arg1),
        103 => sysSetClipboard(arg1, arg2),
        104 => sysGetClipboard(arg1, arg2),
        105 => sysCpuStats(arg1, arg2),
        106 => sysNetInfo(arg1),
        107 => sysTlsConnect(arg1),
        108 => sysTlsSend(arg1, arg2, arg3),
        109 => sysTlsRecv(arg1, arg2, arg3),
        110 => sysTlsClose(arg1),
        111 => sysSeek(arg1, arg2, arg3),
        else => E_NOSYS,
    };
}

/// Stub registered in the SYSCALLS table so syscallName(92) returns "fork".
/// Never actually dispatched — case 92 in doSyscallInner intercepts before
/// reaching the table-driven path. Returns E_NOSYS as a safety net.
fn sysForkPlaceholder() u32 {
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
fn sysFork(frame: *signals.SyscallFrame) u32 {
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
fn sysSetsid() u32 {
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
fn sysSetpgid(arg_pid: u32, arg_pgid: u32) u32 {
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
fn sysGetpgrp() u32 {
    const pcb = process.currentPCB() orelse return 0;
    return pcb.pgid;
}

/// getpgid(pid) — return process `pid`'s pgid (or self if pid==0).
fn sysGetpgid(arg_pid: u32) u32 {
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
fn sysGetsid(arg_pid: u32) u32 {
    if (arg_pid >= process.MAX_PROCS) return E_INVAL;
    const target_pid: u8 = if (arg_pid == 0)
        @intCast(process.getCurrentPid())
    else
        @intCast(arg_pid);
    const st = process.getStateRaw(target_pid);
    if (st == @intFromEnum(process.State.unused)) return E_SRCH;
    return process.getPCB(target_pid).sid;
}

/// Push an RGBA8 wallpaper image into the desktop's background module.
/// Pass `(0, 0, 0)` to clear the wallpaper and fall back to the gradient.
/// Pixel format must match what the screen expects (B8G8R8A8 packed u32
/// on x86 little-endian). Caller is responsible for any decoding +
/// pixel-format conversion (e.g. RGBA→BGRA from stb_image output).
fn sysSetWallpaper(buf_ptr: u32, w: u32, h: u32) u32 {
    const background = @import("../ui/desktop/background.zig");
    const dirty = @import("../ui/desktop/dirty.zig");
    const pmm_diag = @import("../mm/pmm.zig");
    const free_entry = pmm_diag.freeFrameCount();
    debug.klog("[sysSetWallpaper] buf=0x{X} w={d} h={d} pmm_free={d}\n", .{ buf_ptr, w, h, free_entry });
    if (w == 0 and h == 0 and buf_ptr == 0) {
        background.clearWallpaper();
        dirty.force_full_kind = true;
        desktop.wake.requestWake();
        debug.klog("[sysSetWallpaper] cleared pmm_free={d} delta={d}\n", .{ pmm_diag.freeFrameCount(), pmm_diag.freeFrameCount() -% free_entry });
        return 0;
    }
    if (w == 0 or h == 0 or w > 4096 or h > 4096) {
        debug.klog("[sysSetWallpaper] EINVAL dims\n", .{});
        return E_INVAL;
    }
    const total: usize = @as(usize, w) * @as(usize, h) * 4;
    if (!validateUserPtrAligned(buf_ptr, total, 4)) {
        debug.klog("[sysSetWallpaper] EFAULT validateUserPtr({d} bytes)\n", .{total});
        return E_FAULT;
    }
    const free_before_clear = pmm_diag.freeFrameCount();
    // allocateWallpaper internally calls clearWallpaper() first; we want
    // to see frees + allocs broken apart, so do clear here explicitly.
    background.clearWallpaper();
    const free_after_clear = pmm_diag.freeFrameCount();
    if (!background.allocateWallpaper(w, h)) {
        debug.klog("[sysSetWallpaper] ENOMEM allocateWallpaper({d}x{d})\n", .{ w, h });
        return E_NOMEM;
    }
    const free_after_alloc = pmm_diag.freeFrameCount();
    debug.klog("[wallpaper-diag] before_clear={d} after_clear={d} (freed={d}) after_alloc={d} (consumed={d})\n", .{
        free_before_clear, free_after_clear, free_after_clear -% free_before_clear,
        free_after_alloc, free_after_clear -% free_after_alloc,
    });
    const dst = background.wallpaperSlice() orelse {
        debug.klog("[sysSetWallpaper] wallpaperSlice() null after alloc\n", .{});
        return E_INVAL;
    };
    const src: [*]const u32 = @ptrFromInt(@as(usize, buf_ptr));
    @memcpy(dst, src[0..dst.len]);
    dirty.force_full_kind = true;
    desktop.wake.requestWake();
    debug.klog("[sysSetWallpaper] OK installed {d}x{d}, force_full=true\n", .{ w, h });
    return 0;
}

fn sysAudioWrite(buf_ptr: u32, num_samples: u32) u32 {
    if (num_samples == 0 or num_samples > 8192) return E_INVAL;
    if (!validateUserPtrAligned(buf_ptr, num_samples * 4, 2)) return E_FAULT; // stereo i16 = 4 bytes/sample, 2-byte aligned
    const sound = @import("../driver/sound.zig");
    if (!sound.isReady()) return E_INVAL;
    const src: [*]const i16 = @ptrFromInt(@as(usize, buf_ptr));
    sound.writeSamples(src, num_samples);
    return 0;
}

fn sysNotify(text_ptr: u32, len: u32) u32 {
    const actual_len = @min(len, 64);
    if (!validateUserPtr(text_ptr, actual_len)) return E_FAULT;
    const src: [*]const u8 = @ptrFromInt(@as(usize, text_ptr));
    desktop.showNotification(src[0..actual_len]);
    return 0;
}

fn sysSetConfig(key: u32, value: u32) u32 {
    const val: u8 = @truncate(value);
    switch (key) {
        0 => { // resolution: 0=720p, 1=1080p
            if (val <= 1) desktop.conf.resolution = val;
        },
        1 => { // background: 0=blue, 1=purple, 2=green, 3=red
            if (val <= 3) desktop.conf.bg = val;
        },
        2 => { // theme: 0=light, 1=dark
            if (val <= 1) desktop.conf.theme = val;
        },
        3 => { // mouse speed: 0=slow, 1=normal, 2=fast
            if (val <= 2) desktop.conf.mouse_speed = val;
        },
        4 => { // dock position: 0=bottom, 1=top
            if (val <= 1) desktop.conf.dock_pos = val;
        },
        255 => { // apply
            desktop.config_changed = true;
            // Wake the event-driven compositor so the apply path runs
            // promptly instead of waiting for the next input event.
            desktop.wake.requestWake();
        },
        else => return 0xFFFFFFFF,
    }
    return 0;
}

fn sysSbrk(increment: u32) u32 {
    const pcb = process.currentPCB() orelse return E_FAULT;
    _ = pcb.page_directory orelse return E_FAULT;
    // sbrk and the heap lazy region are per-process — sysClone members
    // grow the same heap. Same indirection pattern as sysMmap.
    const lead = process.leader(pcb);

    const old_brk = lead.user_brk;
    if (increment == 0) return @intCast(old_brk);

    const new_brk = old_brk + increment;
    if (new_brk > USER_SPACE_END or new_brk < old_brk) return E_INVAL;

    // Lazy heap: register (or extend) a lazy region instead of eagerly mapping
    // every page. The page-fault handler allocates+zeros pages on first touch.
    // Reuse the existing heap region if it still ends at old_brk; otherwise
    // (first sbrk, or gpu_map_blob bumped user_brk past it) register a new one.
    const reuse = lead.heap_lazy_idx >= 0 and
        lead.lazy_regions[@intCast(lead.heap_lazy_idx)].end == old_brk;

    if (reuse) {
        lead.lazy_regions[@intCast(lead.heap_lazy_idx)].end = new_brk;
    } else {
        if (!process.addLazyRegion(@intCast(lead.tgid), old_brk, new_brk, 0)) return E_INVAL;
        lead.heap_lazy_idx = @intCast(lead.lazy_count - 1);
    }

    lead.user_brk = new_brk;
    return @intCast(old_brk);
}

/// mmap a region of user VA. Demand-paged in either flavor — the page-fault
/// handler resolves the registered LazyRegion on first touch, allocating one
/// 4KB user page at a time.
///
/// Anonymous (`fd == 0xFFFFFFFF`):
///   Zero-filled. Same machinery sbrk uses; ~free given the existing lazy-
///   region path.
///
/// File-backed (valid `fd`):
///   The kernel reads `len` bytes starting at `offset` from the file into a
///   PMM-allocated contiguous buffer. The lazy region's `source` points at
///   that buffer; on page fault, `handleUserPageFault` copies the relevant
///   slice into the freshly-mapped user page (so each user page is an
///   independent copy, not a shared mapping — true MAP_SHARED requires a
///   page-cache and is a v2 problem). Bytes past EOF stay zero.
///
///   The fd's offset is saved/restored across the read so the caller's
///   sequential file-position state isn't disturbed. FAT cluster cache is
///   reset because changing offset invalidates it.
///
/// VAs grow downward from `pcb.mmap_top` (initially USER_SPACE_END) so they
/// stay clear of upward-growing sbrk and the ELF load area.
fn sysMmap(len: u32, fd: u32, offset: u32) u32 {
    if (len == 0) return E_INVAL;
    const pcb = process.currentPCB() orelse return E_FAULT;
    _ = pcb.page_directory orelse return E_FAULT;
    const lead = process.leader(pcb);
    if (lead.lazy_count >= process.MAX_LAZY_REGIONS) return E_INVAL;

    const len_pg: usize = (@as(usize, len) + 0xFFF) & ~@as(usize, 0xFFF);
    if (len_pg > lead.mmap_top) return E_INVAL;
    const new_top = lead.mmap_top - len_pg;
    if (new_top < lead.user_brk) return E_INVAL;

    const lead_pid: u32 = lead.tgid;

    if (fd == 0xFFFFFFFF) {
        if (!process.addLazyRegion(lead_pid, new_top, lead.mmap_top, 0)) return E_INVAL;
        lead.lazy_regions[lead.lazy_count - 1].prot = process.PROT_RW;
    } else {
        if (fd >= config.MAX_FDS) return E_INVAL;
        if (!pcb.fd_table[fd].in_use) return E_INVAL;

        const num_pages: u32 = @intCast(len_pg / 0x1000);
        // User-driven fd-backed mmap — respect the PMM reserve so a
        // big mmap can't deplete the kernel emergency pool.
        const buf_phys = pmm.allocContiguousUser(num_pages) orelse return E_NOMEM;
        const buf_ptr: [*]u8 = @ptrFromInt(paging.physToVirt(buf_phys));

        const saved_off = pcb.fd_table[fd].offset;
        pcb.fd_table[fd].offset = offset;
        pcb.fd_table[fd].fat_cluster = 0;
        pcb.fd_table[fd].fat_cluster_off = 0;
        const n = vfs.read(pcb, fd, buf_ptr, len);
        pcb.fd_table[fd].offset = saved_off;
        pcb.fd_table[fd].fat_cluster = 0;
        pcb.fd_table[fd].fat_cluster_off = 0;

        if (n == 0xFFFFFFFF) {
            pmm.freeContiguous(buf_phys, @intCast(num_pages));
            return E_INVAL;
        }
        if (n < len_pg) {
            const tail: [*]u8 = @ptrFromInt(paging.physToVirt(buf_phys + n));
            @memset(tail[0 .. len_pg - n], 0);
        }

        if (!process.addLazyRegionWithSource(
            lead_pid,
            new_top,
            lead.mmap_top,
            0,
            buf_ptr,
            new_top,
            len_pg,
            0,
        )) {
            pmm.freeContiguous(buf_phys, @intCast(num_pages));
            return E_INVAL;
        }
        const ridx = lead.lazy_count - 1;
        lead.lazy_regions[ridx].buf_owned = true;
        lead.lazy_regions[ridx].buf_pages = @intCast(num_pages);
        lead.lazy_regions[ridx].prot = process.PROT_RW;
    }

    lead.mmap_top = new_top;
    return @intCast(new_top);
}

/// Free a previously-mmapped region. `va` must match the start of a registered
/// region exactly and `len` must match its length (rounded up to page) — partial
/// unmaps are rejected. Walks the page table releasing each present 4KB frame
/// back to the PMM, then removes the lazy-region entry.
///
/// VA recovery: when the freed region is the topmost (its start equals the
/// current mmap_top), mmap_top is advanced upward to the next existing mmap
/// region's start — this also reclaims any contiguous holes below that were
/// freed earlier in non-stack order. Middle holes between still-allocated
/// regions are NOT reclaimed; that needs a real free-range list and is
/// deferred until the lazy_count cap (16) actually starts hurting.
fn sysMunmap(va: u32, len: u32) u32 {
    if (len == 0) return E_INVAL;
    const pcb = process.currentPCB() orelse return E_FAULT;
    const pd = pcb.page_directory orelse return E_FAULT;
    const lead = process.leader(pcb);

    const start: usize = @as(usize, va) & ~@as(usize, 0xFFF);
    const len_pg: usize = (@as(usize, len) + 0xFFF) & ~@as(usize, 0xFFF);
    const end = start + len_pg;
    if (end <= start) return E_INVAL;

    var found_idx: ?usize = null;
    for (lead.lazy_regions[0..lead.lazy_count], 0..) |r, i| {
        if (r.start == start and r.end == end) {
            found_idx = i;
            break;
        }
    }
    const idx = found_idx orelse return E_INVAL;
    const removed = lead.lazy_regions[idx];

    var page = start;
    while (page < end) : (page += 0x1000) {
        if (vmm.unmapUserPage(pd, page)) |frame| pmm.freeFrame(frame);
    }
    // Single cross-CPU TLB shootdown for the whole range. unmapUserPage
    // only does a local invlpg per page; without this call, other CPUs
    // would still cache the freed pages' translations and could read /
    // write into now-recycled PMM frames. Doing it once at batch end
    // rather than inside unmapUserPage cuts the IPI count by len/4096×.
    // For range==1 page, use INVPCID type-0 (single-page) so peer CPUs
    // only lose that one TLB entry; for larger ranges, use type-1
    // (whole-PCID flush) which is cheaper than emitting N type-0 calls.
    const tlb = @import("tlb.zig");
    if ((end - start) == 0x1000) {
        tlb.shootdownPage(lead.pcid, start);
    } else {
        tlb.shootdownAll(lead.pcid);
    }

    // Compact the lazy_regions array. heap_lazy_idx is sbrk's pointer; if it
    // happens to be above the removed slot, shift it down by one to keep
    // pointing at the same region.
    for (idx + 1..lead.lazy_count) |j| lead.lazy_regions[j - 1] = lead.lazy_regions[j];
    lead.lazy_count -= 1;
    lead.lazy_regions[lead.lazy_count] = .{};
    if (lead.heap_lazy_idx >= 0 and @as(usize, @intCast(lead.heap_lazy_idx)) > idx) {
        lead.heap_lazy_idx -= 1;
    }

    // VA reclaim: if we just freed the topmost mmap region, slide mmap_top up
    // to the next still-allocated mmap region's start (or USER_SPACE_END).
    // Filter `r.start > lead.mmap_top` excludes the heap region (which sits
    // far below in user space) and naturally picks only mmap-managed regions.
    if (removed.start == lead.mmap_top) {
        var new_top: usize = memmap.USER_SPACE_END;
        for (lead.lazy_regions[0..lead.lazy_count]) |r| {
            if (r.start > lead.mmap_top and r.start < new_top) new_top = r.start;
        }
        lead.mmap_top = new_top;
    }

    // File-backed mmap allocates a per-region kernel buffer; release it after
    // the user-side teardown so a fault hitting the just-removed region (e.g.
    // a stale TLB entry) can't read freed memory. `source` is a physmap virt
    // pointer (see sysMmap line 942) — translate back to phys for PMM.
    if (removed.buf_owned) {
        if (removed.source) |src| {
            const phys = paging.virtToPhys(@intFromPtr(src)).?;
            pmm.freeContiguous(phys, removed.buf_pages);
        }
    }

    return 0;
}

/// Spawn a new thread that shares the calling process's address space.
/// `entry` is the user-mode RIP, `stack_top` is the new RSP, `arg` is
/// passed in RDI. fs_base / TLS is left at 0 — the new thread should
/// call sysSetTls(addr) before any %fs:NN access.
fn sysClone(entry: u32, stack_top: u32, arg: u32) u32 {
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
fn sysSetTls(fs_base: u32) u32 {
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
fn sysFutex(uaddr: u32, op: u32, val: u32) u32 {
    if (uaddr == 0 or (uaddr & 3) != 0) return E_INVAL;
    if (!validateUserPtr(uaddr, 4)) return E_FAULT;

    switch (op) {
        FUTEX_WAIT => {
            // Compare-and-sleep. The user's read of *uaddr happened to
            // be `val` from the calling thread's perspective; we re-read
            // here under (effectively) the kernel's lock to detect a
            // racing WAKE that already changed *uaddr.
            const word: *const volatile u32 = @ptrFromInt(@as(usize, uaddr));
            if (word.* != val) return E_INVAL; // EAGAIN

            _ = process.currentPCB() orelse return E_FAULT;
            // process.blockOn handles wait_kind/state/yield/clear. WAKE
            // also clears, so the post-resume clear is idempotent.
            process.blockOn(.futex, uaddr);
            return 0;
        },
        FUTEX_WAKE => {
            var woken: u32 = 0;
            for (0..process.MAX_PROCS) |i| {
                if (woken >= val) break;
                const t = &process.procs[i];
                if (t.state != .sleeping) continue;
                if (t.wait_kind != .futex) continue;
                if (t.wait_target != uaddr) continue;
                t.wait_kind = .none;
                t.wait_target = 0;
                // setState routes through the rq book-keeping (rqEnter on
                // .ready) so the parallel-tracked runqueue stays in sync.
                process.setState(i, .ready);
                woken += 1;
            }
            // Diag: when no waiter found, dump every live PCB's state +
            // wait fields so we can compare to the wake's uaddr.
            if (woken == 0) {
                const cur_pid_dbg = process.getCurrentPid();
                debug.klog("[futex.wake.miss] pid={d} uaddr=0x{x}\n", .{ cur_pid_dbg, uaddr });
                for (0..process.MAX_PROCS) |i| {
                    const t = &process.procs[i];
                    if (t.state == .unused) continue;
                    debug.klog("  pid={d} state={d} wait_kind={d} wait_target=0x{x} tgid={d}\n", .{ i, @intFromEnum(t.state), @intFromEnum(t.wait_kind), t.wait_target, t.tgid });
                }
            }
            return woken;
        },
        else => return 0xFFFFFFFF,
    }
}

/// Change page-protection on an existing mmap region. The range must match
/// a registered region exactly — partial mprotect (split a region in two on
/// a sub-range) is a v2 problem; for now the simpler all-or-nothing semantic
/// is enough for the W^X baseline and JIT-style use.
///
/// Updates the lazy region's `prot` (so future first-touch fault-ins use the
/// new bits) AND walks the existing PTEs in the range, rewriting flags on
/// any present pages. Pages that haven't faulted in yet are no-ops here —
/// they pick up the new prot when handleUserPageFault eventually runs.
fn sysMprotect(va: u32, len: u32, prot: u32) u32 {
    if (len == 0) return E_INVAL;
    const pcb = process.currentPCB() orelse return E_FAULT;
    const pd = pcb.page_directory orelse return E_FAULT;

    const start: usize = @as(usize, va) & ~@as(usize, 0xFFF);
    const len_pg: usize = (@as(usize, len) + 0xFFF) & ~@as(usize, 0xFFF);
    const end = start + len_pg;
    if (end <= start) return E_INVAL;

    var found_idx: ?usize = null;
    for (pcb.lazy_regions[0..pcb.lazy_count], 0..) |r, i| {
        if (r.start == start and r.end == end) {
            found_idx = i;
            break;
        }
    }
    const idx = found_idx orelse return E_INVAL;

    // Mask off non-prot bits the user might have passed; we own the encoding.
    const new_prot: u8 = @as(u8, @truncate(prot)) & process.PROT_RWX;
    pcb.lazy_regions[idx].prot = new_prot;

    const new_flags = vmm.protToMapFlags(new_prot);
    var page = start;
    while (page < end) : (page += 0x1000) {
        // changePageProt returns false for not-yet-faulted-in pages — that's
        // fine, the region's prot field is updated so the eventual fault-in
        // sees the new bits.
        _ = vmm.changePageProt(pd, page, new_flags);
    }

    // Cross-CPU TLB shootdown. changePageProt only does a local invlpg per
    // page; without this, another CPU's TLB still caches the OLD prot bits
    // and an mprotect(RW→RO) wouldn't actually block writes from that CPU
    // until its TLB happens to evict the entry.
    // Single-page case uses type-0 INVPCID (surgical, leaves the rest of
    // the PCID's TLB intact); ranges fall through to the whole-PCID type-1
    // flush.
    const tlb = @import("tlb.zig");
    if (len_pg == 0x1000) {
        tlb.shootdownPage(pcb.pcid, start);
    } else {
        tlb.shootdownAll(pcb.pcid);
    }
    return 0;
}

fn sysSleep(ms: u32) u32 {
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

fn sysOpen(name_ptr: u32, flags: u32) u32 {
    if (!validateUserPtr(name_ptr, 1)) return E_FAULT;

    const pcb = process.currentPCB() orelse return E_FAULT;

    // Read filename from user space (null-terminated, max 100 chars)
    const name_bytes: [*]const u8 = @ptrFromInt(@as(usize, name_ptr));
    var name_len: usize = 0;
    while (name_len < 100 and name_bytes[name_len] != 0) : (name_len += 1) {}
    if (name_len == 0) return E_INVAL;

    return vfs.openFlags(pcb, name_bytes[0..name_len], flags) orelse 0xFFFFFFFF;
}

fn sysFread(fd: u32, buf_ptr: u32, count: u32) u32 {
    if (count == 0) return 0;
    if (!validateUserPtr(buf_ptr, count)) return E_FAULT;

    const pcb = process.currentPCB() orelse return E_FAULT;
    const buf: [*]u8 = @ptrFromInt(@as(usize, buf_ptr));
    return vfs.read(pcb, fd, buf, count);
}

fn sysFwrite(fd: u32, buf_ptr: u32, count: u32) u32 {
    if (count == 0) return 0;
    if (!validateUserPtr(buf_ptr, count)) return E_FAULT;

    const pcb = process.currentPCB() orelse return E_FAULT;
    const buf: [*]const u8 = @ptrFromInt(@as(usize, buf_ptr));
    return vfs.write(pcb, fd, buf, count);
}

fn sysClose(fd: u32) u32 {
    const pcb = process.currentPCB() orelse return E_FAULT;
    return vfs.close(pcb, fd);
}

/// Reposition an fd's read/write cursor. whence: 0=SET (absolute),
/// 1=CUR (relative to current offset). SEEK_END is intentionally
/// omitted — file_size lookup is fs-specific and userland can get it
/// via sysFsize for the rare case it matters. Quake's pak loader only
/// needs SEEK_SET.
///
/// Returns the new offset on success, or 0xFFFFFFFF on bad fd / overflow.
fn sysSeek(fd: u32, offset: u32, whence: u32) u32 {
    const pcb = process.currentPCB() orelse return E_FAULT;
    if (fd >= pcb.fd_table.len or !pcb.fd_table[fd].in_use) return 0xFFFFFFFF;
    if (fd < 3) return 0xFFFFFFFF;
    const fd_entry = &pcb.fd_table[fd];
    const new_off: u32 = switch (whence) {
        0 => offset,
        1 => fd_entry.offset +% offset,
        else => return 0xFFFFFFFF,
    };
    fd_entry.offset = new_off;
    return new_off;
}

// --- Graphics syscalls ---

const GUI_FB_BASE: usize = 0x08000000; // User GUI FB virtual address
const GUI_MAX_SIZE: u32 = 8 * 1024 * 1024;
const GUI_FB_PER_PID: usize = memmap.GUI_FB_PER_PID_SIZE; // per-window size cap

fn sysCreateWindow(alloc_width_in: u32, alloc_height: u32, display_wh: u32) u32 {
    if (alloc_width_in == 0 or alloc_height == 0 or alloc_width_in > 1920 or alloc_height > 1080) {
        debug.klog("[sysCW] reject dims w={d} h={d}\n", .{ alloc_width_in, alloc_height });
        return E_INVAL;
    }
    // The kernel must NOT silently round alloc_width — the app already
    // chose its row stride and uses it directly via Canvas.init(fb,
    // alloc_w, alloc_h). Any kernel-side rounding (e.g. up to 16 for
    // Lavapipe alignment) creates a stride mismatch: app writes at
    // stride 712, kernel-side renderWindow + slot image read at stride
    // 720, content shears diagonally across rows. Slot allocation that
    // *needs* 16-aligned alloc_w gets rejected by allocateWindowImage's
    // pre-check (mem_w & 15) instead, which falls back to the legacy
    // PMM path silently — apps that want the slot fast-path can opt in
    // by passing 16-aligned dims themselves.
    const alloc_width: u32 = alloc_width_in;
    const fb_size: u64 = @as(u64, alloc_width) * alloc_height * 4;
    if (fb_size > GUI_MAX_SIZE) {
        debug.klog("[sysCW] reject fb_size={d} > GUI_MAX_SIZE={d}\n", .{ fb_size, GUI_MAX_SIZE });
        return E_INVAL;
    }

    // Display size: if arg3 is 0, use alloc size; otherwise unpack.
    // disp dims are independent of alloc dims (smaller visible region).
    var disp_w = alloc_width;
    var disp_h = alloc_height;
    if (display_wh != 0) {
        disp_w = display_wh & 0xFFFF;
        disp_h = display_wh >> 16;
        if (disp_w > alloc_width) disp_w = alloc_width;
        if (disp_h > alloc_height) disp_h = alloc_height;
    }
    // disp_w must also be 16-aligned for the B.2 image extent to match
    // the slot's row stride (mem_w must equal image_w padded to 16).
    // If disp_w == alloc_width — typical case — they're already aligned
    // because alloc_width was rounded above. If they differ, we just
    // use alloc_width as the image width too (safe but sampler reads
    // the alloc-width column-extent, with the visible-rect rendering
    // doing the right thing because gui_w is what determines the
    // window's screen rect anyway).
    if ((disp_w & 15) != 0) disp_w = alloc_width;

    const pcb = process.currentPCB() orelse {
        debug.klog("[sysCW] reject: no current PCB\n", .{});
        return E_INVAL;
    };
    const pd = pcb.page_directory orelse {
        debug.klog("[sysCW] reject: pcb.page_directory is null\n", .{});
        return E_INVAL;
    };

    const pid: u8 = @intCast(process.getCurrentPid());
    if (fb_size > GUI_FB_PER_PID) {
        debug.klog("[sysCW] reject fb_size={d} > GUI_FB_PER_PID={d}\n", .{ fb_size, GUI_FB_PER_PID });
        return E_INVAL;
    }
    const fb_size_u: usize = @intCast(fb_size); // Safe: checked <= GUI_MAX_SIZE (8MB)
    const num_pages: u32 = @intCast((fb_size_u + 4095) / 4096);
    const fb_pixels: u32 = @intCast(fb_size_u / 4);

    // Auto-focus policy: don't yank focus from a terminal whose shell
    // spawned this process. The user is typing into the shell; a
    // background-launched GUI app appearing on top of the z-stack but
    // unfocused matches what every modern desktop does. Shortcut/dock
    // launches go through a different (non-shell-parent) chain so they
    // still get focus as the user expects.
    const auto_focus = !desktop.focusedShellSpawnedPid(pid);

    // Step 9.4 Phase B.2: try to allocate a Venus dmabuf slot. If it
    // works, the dmabuf IS gui_fb — user-space maps directly at the
    // BAR-phys, so app writes go straight into the texture the
    // compositor samples. No PMM allocation, no triple-buffer copy.
    var gpu_slot: ?u8 = null;
    var kern_fb: [*]volatile u32 = undefined;
    const kern_fb_backs: [3]?[*]volatile u32 = .{ null, null, null };
    {
        const gpu_comp = @import("../ui/gpu_compositor.zig");
        if (gpu_comp.isReady()) {
            gpu_slot = gpu_comp.allocateWindowImage(disp_w, disp_h, alloc_width, alloc_height);
        }
    }

    if (gpu_slot) |idx| {
        const gpu_comp = @import("../ui/gpu_compositor.zig");
        const sl = &gpu_comp.window_slots[idx];
        const slot_phys = sl.phys;
        const slot_pages: u32 = @intCast((sl.mem_bytes + 4095) / 4096);
        // Map the dmabuf into user-space at GUI_FB_BASE. The phys is
        // in the SHM BAR range — vmm.mapUserPage just sets PTE flags,
        // any phys works.
        for (0..slot_pages) |i| {
            vmm.mapUserPage(pd, GUI_FB_BASE + i * 4096, slot_phys + i * 4096, paging.READ_WRITE | paging.USER);
        }
        asm volatile ("movq %%cr3, %%rax\n movq %%rax, %%cr3" ::: .{ .rax = true });
        // Zero the dmabuf so the compositor's first sample doesn't
        // read uninitialized pixels.
        const kfb_u8: [*]volatile u8 = sl.kernel_ptr.?;
        @memset(kfb_u8[0..@intCast(sl.mem_bytes)], 0);
        kern_fb = @ptrCast(@alignCast(sl.kernel_ptr.?));
        // No PMM allocation, no triple-buffer backs. Apps that call
        // sysPresent on a slot-backed window still bump
        // gui_present_pending — that's fine; sysPresent's snapshot
        // step is a no-op when gui_fb_backs[0] is null.
        // pmm_phys_base stays 0 — sysDestroyWindow path checks this
        // and skips PMM unmap for slot-backed windows.
    } else {
        // Legacy PMM path — compositor not ready or slot alloc failed.
        // Allocate ONLY the front buffer (num_pages). Triple back-buffers
        // (3 × num_pages) are allocated lazily on first sysPresent in
        // desktop.snapshotGuiFb. Apps that never call sysPresent (sysmon,
        // any direct-fb GUI app relying on auto-refresh) save 3× their
        // framebuffer in PMM — at 1920×1080 alloc that's 24 MB saved per
        // such window. On a 95 MB system that's the difference between
        // "OOM at three apps" and "OOM at six". Compositor's renderWindow
        // handles `gui_fb_backs[i] == null` by falling back to gui_fb
        // (see desktop.zig: `if (w.has_presented) backs[pub] else
        // gui_fb`), so visual output is identical until the app actually
        // presents.
        const phys_base = pmm.allocContiguous(num_pages) orelse {
            debug.klog("[sysCW] reject: pmm.allocContiguous({d} pages = {d} KB) FAILED\n", .{ num_pages, num_pages * 4 });
            return E_INVAL;
        };
        for (0..num_pages) |i| {
            const phys = phys_base + i * 4096;
            vmm.mapUserPage(pd, GUI_FB_BASE + i * 4096, phys, paging.READ_WRITE | paging.USER);
            // Dual-owner refcount bump: front-buffer pages live in BOTH the
            // user PML4 (released by destroyAddressSpace on process exit) AND
            // the kernel desktop's gui_fb_phys_base table (released by
            // unmapGuiFB on window destroy). Without the extra acquire, the
            // second owner's release underflows. Back-buffer pages stay
            // single-owner (kernel-only, never mapped to user).
            pmm.acquireFrame(phys);
            const ptr: [*]u8 = @ptrFromInt(paging.physToVirt(phys));
            @memset(ptr[0..4096], 0);
        }
        paging.registerGuiFB(pid, phys_base);
        asm volatile ("movq %%cr3, %%rax\n movq %%rax, %%cr3" ::: .{ .rax = true });
        kern_fb = @ptrFromInt(paging.physToVirt(phys_base));
        // kern_fb_backs stays { null, null, null } — snapshotGuiFb will
        // populate on first present (or skip cleanly on alloc failure,
        // leaving the compositor on the gui_fb fallback path).
    }

    if (desktop.createGuiWindow(pid, kern_fb, kern_fb_backs, fb_pixels, disp_w, disp_h, alloc_width, alloc_height, auto_focus, gpu_slot) == null) {
        debug.klog("[syscall] Failed to create GUI window\n", .{});
        return E_INVAL;
    }

    // GUI apps get interactive priority automatically
    pcb.priority = .interactive;

    // Re-bind fd 0 to the console keyboard ring. GUI apps launched from
    // the shell inherit shell's kb_pipe as fd 0; once focus shifts to
    // their window, the desktop stops writing to that pipe and the GUI
    // app's readChar() spins on an empty pipe forever (e.g. threadbrot's
    // 1/2/4/8 hotkeys silently dropped). Console-fd0 reads from the
    // global keyboard ring, which the desktop deliberately leaves alone
    // for non-terminal focus, so the GUI app's readChar() pops it
    // directly. Apps that genuinely want pipe-stdin can re-open fd 0.
    pcb.fd_table[0] = .{ .in_use = true, .inode = 0, .offset = 0, .flags = 0, .fs_type = .console };

    debug.klog("[syscall] GUI window created: {d}x{d} (alloc {d}x{d}) pid={d}\n", .{ disp_w, disp_h, alloc_width, alloc_height, pid });
    return @intCast(GUI_FB_BASE);
}

fn sysPresent() u32 {
    const t = perf.enter();
    defer perf.leave(.present, t);
    // Snapshot the user-writable front buffer into the kernel back buffer.
    // The compositor reads gui_fb_back; without this copy we'd race against
    // the app's next-frame writes and tear. See window.gui_fb_back doc.
    desktop.snapshotGuiFb(@intCast(process.getCurrentPid()));
    desktop.markGuiPresent(@intCast(process.getCurrentPid()));
    // Do NOT pre-set state=.ready — schedule() owns the
    // .running → .switching_out → .ready handoff so another CPU
    // can't dispatch this PCB while its kstack is still in use.
    return 0;
}

fn sysGetMouse(buf_ptr: u32) u32 {
    if (!validateUserPtrAligned(buf_ptr, 20, 4)) return E_FAULT; // 5 u32s = 20 bytes
    const pid: u8 = @intCast(process.getCurrentPid());
    const buf: [*]u32 = @ptrFromInt(@as(usize, buf_ptr));
    desktop.getMouseRelative(pid, buf);
    // DEBUG: log every edge-press button event (rising edge of left button) per PID
    const dbg = struct {
        var counts: [16]u8 = [_]u8{0} ** 16;
        var prev_btn: [16]u8 = [_]u8{0} ** 16;
    };
    if (pid < 16) {
        const cur: u8 = @intCast(buf[2] & 0xFF);
        const edge = (cur & 1) != 0 and (dbg.prev_btn[pid] & 1) == 0;
        dbg.prev_btn[pid] = cur;
        if (edge and dbg.counts[pid] < 30) {
            dbg.counts[pid] += 1;
            const x: i32 = @bitCast(buf[0]);
            const y: i32 = @bitCast(buf[1]);
            const focused_pid = desktop.focusedPid();
            debug.klog("[click#{d}] PID={d} relx={d} rely={d} btn={X} focusPID={d}\n", .{ dbg.counts[pid], pid, x, y, buf[2], focused_pid });
        }
    }
    return 0;
}

fn sysDestroyWindow() u32 {
    const pid: u8 = @intCast(process.getCurrentPid());
    desktop.destroyGuiWindow(pid);
    return 0;
}

fn sysMeminfo(buf_ptr: u32) u32 {
    if (!validateUserPtrAligned(buf_ptr, 8, 4)) return E_FAULT;
    const buf: [*]u32 = @ptrFromInt(@as(usize, buf_ptr));
    buf[0] = pmm.freeFrameCount();
    buf[1] = pmm.managedFrameCount();
    return 0;
}

/// Per-CPU tick stats — `(irq_ticks, idle_ticks)` u64 pair per alive CPU,
/// packed sequentially. Caller passes a buffer sized for `max_cpus` entries
/// (16 bytes each); we fill up to the alive count and return the actual
/// count written. Returns E_FAULT on bad user pointer or buf too small.
///
/// Used by sysmon / top-style tools: compute `(d_irq - d_idle) / d_irq * 100`
/// across two snapshots to get instantaneous utilization per CPU.
const CpuStat = extern struct {
    irq_ticks: u64,
    idle_ticks: u64,
};

fn sysCpuStats(buf_ptr: u32, max_cpus: u32) u32 {
    if (max_cpus == 0) return E_INVAL;
    const byte_len: u32 = max_cpus * @sizeOf(CpuStat);
    if (!validateUserPtrAligned(buf_ptr, byte_len, @alignOf(CpuStat))) return E_FAULT;
    const buf: [*]CpuStat = @ptrFromInt(@as(usize, buf_ptr));
    var written: u32 = 0;
    for (&smp.cpus) |*c| {
        if (!c.alive) continue;
        if (written >= max_cpus) break;
        buf[written] = .{
            .irq_ticks = c.irq_tick_count,
            .idle_ticks = c.idle_tick_count,
        };
        written += 1;
    }
    return written;
}

/// Snapshot of the active L3 configuration, copied out in one shot so
/// userspace doesn't need to syscall once per field. `dhcp_configured`
/// distinguishes a real DHCP lease from the static SLIRP fallback.
const NetInfo = extern struct {
    local_ip: [4]u8,
    gateway_ip: [4]u8,
    dns_ip: [4]u8,
    subnet_mask: [4]u8,
    mac: [6]u8,
    /// Padding so `dhcp_configured` lands on a natural alignment boundary
    /// — extern structs don't auto-pad and we want a stable wire layout.
    _pad: [2]u8 = .{ 0, 0 },
    dhcp_configured: u32,
    dhcp_lease_secs: u32,
    nic_present: u32,
};

fn sysNetInfo(buf_ptr: u32) u32 {
    if (!validateUserPtrAligned(buf_ptr, @sizeOf(NetInfo), @alignOf(NetInfo))) return E_FAULT;
    const net = @import("../net/net.zig");
    const nic = @import("../driver/nic.zig");
    const info: *NetInfo = @ptrFromInt(@as(usize, buf_ptr));
    info.* = .{
        .local_ip = net.local_ip,
        .gateway_ip = net.gateway_ip,
        .dns_ip = net.dns_ip,
        .subnet_mask = net.subnet_mask,
        .mac = nic.getMac(),
        .dhcp_configured = if (net.dhcp_configured) 1 else 0,
        .dhcp_lease_secs = net.dhcp_lease_secs,
        .nic_present = if (nic.isReady()) 1 else 0,
    };
    return 0;
}

// --- Directory listing syscall ---

const FileEntry = extern struct {
    name: [32]u8,
    name_len: u8,
    file_size: u32 align(1),
    flags: u8, // bit 0 = is_elf, bit 1 = from_fat32
    _pad: [10]u8,
};

fn sysListDir(buf_ptr: u32, buf_size: u32) u32 {
    const entry_size: u32 = @sizeOf(FileEntry);
    const max_entries = buf_size / entry_size;
    if (max_entries == 0) return E_INVAL;
    if (!validateUserPtrAligned(buf_ptr, buf_size, @alignOf(FileEntry))) return E_FAULT;
    const entries: [*]FileEntry = @ptrFromInt(@as(usize, buf_ptr));

    // Dispatch by cwd → mount table. Previously hardcoded to FAT32 root,
    // which silently returned 0 entries when running with ext2.img on IDE2
    // (FAT32 disk.img unmapped). Default cwd is "/tar/" so an unmodified
    // shell launching files.elf gets tarfs contents — matching what the
    // boot tar holds.
    const pcb = process.currentPCB() orelse return E_FAULT;
    const cwd = pcb.cwd[0..pcb.cwd_len];
    if (cwd.len == 0) return 0;

    const m = vfs.findMount(cwd) orelse return 0;
    return switch (m.fs) {
        .tarfs => blk: {
            const tarfs = @import("../fs/tarfs.zig");
            break :blk tarfs.listToBuffer(@ptrCast(entries), max_entries);
        },
        .fat32 => blk: {
            const fat32 = @import("../fs/fat32.zig");
            break :blk listFatDir(fat32.root_cluster, entries, max_entries);
        },
        .ext2 => blk: {
            // ext2 has its own FileEntry type with the same layout —
            // @ptrCast across the type boundary (Zig treats identical
            // extern structs as distinct types). Walk cwd-relative path
            // (cwd[mount_prefix.len..]) to the right directory inode so
            // `cd /bin; ls` actually lists /bin and not the ext2 root.
            const ext2 = @import("../fs/ext2/ext2.zig");
            const layout = @import("../fs/ext2/layout.zig");
            const rel = cwd[m.prefix.len..];
            const dir_inum = if (rel.len == 0) layout.ROOT_INO else (ext2.resolveDirInum(rel) orelse layout.ROOT_INO);
            break :blk ext2.listDir(dir_inum, @ptrCast(entries), max_entries);
        },
        // devfs/procfs don't have a buffer-fill listing API yet — return
        // 0 entries; not an error, just an empty directory.
        .devfs, .procfs => 0,
    };
}

/// Fill `entries` with one FileEntry per non-deleted entry in the FAT32
/// directory rooted at `dir_cluster`. LFN-aware; `.` / `..` and the volume
/// label are filtered out. Subdirectory entries are *included* (with the
/// `is_dir` flag set) so user space can render them in listings.
///
/// `flags` byte layout (see lib/libc.zig FE_FLAG_*):
///   bit 0 = is_elf
///   bit 1 = is_directory
///   bit 2 = from_fat32 (always set here)
///   bit 3 = from_ext2
fn listFatDir(dir_cluster: u32, entries: [*]FileEntry, max_entries: u32) u32 {
    const fat32 = @import("../fs/fat32.zig");
    var count: u32 = 0;
    var lfn_buf: [255]u8 = undefined;
    var lfn_len: usize = 0;
    var lfn_active: bool = false;
    const lfn_offsets = [13]u8{ 1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30 };

    var fi: u32 = 0;
    while (fi < 4096 and count < max_entries) : (fi += 1) {
        const raw = fat32.readDirEntryRawAt(dir_cluster, fi) orelse break;
        if (raw[0] == 0) break;
        if (raw[0] == 0xE5) { lfn_active = false; continue; }

        if (raw[11] & 0x0F == 0x0F) {
            const seq = raw[0] & 0x1F;
            if (seq == 0 or seq > 20) { lfn_active = false; continue; }
            if (raw[0] & 0x40 != 0) { lfn_len = 0; lfn_active = true; }
            if (!lfn_active) continue;
            const pos_base = (@as(usize, seq) - 1) * 13;
            for (lfn_offsets, 0..) |off, ci| {
                const lo = raw[off];
                const hi = raw[off + 1];
                if (lo == 0 and hi == 0) break;
                if (lo == 0xFF and hi == 0xFF) break;
                const p = pos_base + ci;
                if (p < 255) {
                    lfn_buf[p] = if (hi == 0) lo else '?';
                    if (p + 1 > lfn_len) lfn_len = p + 1;
                }
            }
            continue;
        }

        if (raw[11] & 0x08 != 0) { lfn_active = false; continue; } // volume ID

        const is_dir = (raw[11] & 0x10) != 0;
        const de: *const fat32.DirEntry = @ptrCast(@alignCast(&raw));
        var entry: FileEntry = undefined;
        @memset(&entry.name, 0);
        @memset(&entry._pad, 0);

        if (lfn_active and lfn_len > 0) {
            const copy_len = @min(lfn_len, 32);
            @memcpy(entry.name[0..copy_len], lfn_buf[0..copy_len]);
            entry.name_len = @intCast(copy_len);
        } else {
            var pos: u8 = 0;
            var base_end: u8 = 8;
            while (base_end > 0 and de.name[base_end - 1] == ' ') base_end -= 1;
            for (0..base_end) |j| { entry.name[pos] = toLower(de.name[j]); pos += 1; }
            var ext_end: u8 = 3;
            while (ext_end > 0 and de.name[8 + ext_end - 1] == ' ') ext_end -= 1;
            if (ext_end > 0) {
                entry.name[pos] = '.'; pos += 1;
                for (0..ext_end) |j| { entry.name[pos] = toLower(de.name[8 + j]); pos += 1; }
            }
            entry.name_len = pos;
        }

        // Skip `.` and `..` self/parent links — most tools don't want them.
        if (entry.name_len == 1 and entry.name[0] == '.') { lfn_active = false; continue; }
        if (entry.name_len == 2 and entry.name[0] == '.' and entry.name[1] == '.') { lfn_active = false; continue; }

        entry.file_size = de.file_size;
        // Unified flag layout — see lib/libc.zig FE_FLAG_*.
        //   bit0 = is_elf, bit1 = is_dir, bit2 = from_fat32, bit3 = from_ext2.
        var f: u8 = 0x04; // from_fat32
        if (isElfName(entry.name[0..entry.name_len])) f |= 0x01;
        if (is_dir) f |= 0x02;
        entry.flags = f;
        entries[count] = entry;
        count += 1;
        lfn_active = false;
    }
    return count;
}

fn toLower(c: u8) u8 {
    if (c >= 'A' and c <= 'Z') return c + 32;
    return c;
}

fn isElfName(name: []const u8) bool {
    if (name.len < 4) return false;
    const ext = name[name.len - 4 ..];
    return (ext[0] == '.' and (ext[1] == 'e' or ext[1] == 'E') and
        (ext[2] == 'l' or ext[2] == 'L') and (ext[3] == 'f' or ext[3] == 'F'));
}

fn sysExec(name_ptr: u32, name_len: u32) u32 {
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
        @import("../debug/debug.zig").klog("[sysExec] name='{s}' hex={s}\n", .{ name_buf[0..actual_len], hex[0 .. hexlen * 2] });
        // PMM diagnostic: free frames at every exec. If this drifts down
        // across runs of the same app, something isn't getting freed on
        // exit (process teardown or kernel-side caches).
        const pmm_diag = @import("../mm/pmm.zig");
        @import("../debug/debug.zig").klog("[pmm-diag] exec free={d}/{d}\n", .{ pmm_diag.freeFrameCount(), pmm_diag.managedFrameCount() });
    }

    // Split on first space: "editor.elf myfile.txt" -> filename + arg
    const fname_len = std.mem.indexOfScalar(u8, name_buf[0..actual_len], ' ') orelse actual_len;

    // Switch to kernel PD -- user PD doesn't map all kernel memory
    const caller_pd = if (process.currentPCB()) |pcb| pcb.page_dir_phys else 0;
    const caller_pcid = if (process.currentPCB()) |pcb| pcb.pcid else 0;
    @import("pcid.zig").loadCr3(paging.getKernelPageDirPhys(), 0, @import("smp.zig").myCpu().cpu_id);

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
                    @import("../debug/debug.zig").klog("[sysExec] WARN: child_pid == parent_pid={d} — inheritance skipped\n", .{process.getCurrentPid()});
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
        @import("pcid.zig").loadCr3(caller_pd, caller_pcid, @import("smp.zig").myCpu().cpu_id);
    }

    return pid;
}

/// Fill `child_pcb.argv` from a program name + the raw exec string. argv[0]
/// is the bare program name (no `.elf`); argv[1..] are space-separated
/// tokens from the input string starting after `fname_len`. Tokens longer
/// than MAX_ARG_LEN are truncated; argc is capped at MAX_ARGS.
fn populateArgv(
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

fn sysGetScreenSize(buf_ptr: u32) u32 {
    if (!validateUserPtrAligned(buf_ptr, 8, 4)) return E_FAULT;
    const buf: [*]u32 = @ptrFromInt(@as(usize, buf_ptr));
    const gfx = @import("../ui/gfx.zig");
    buf[0] = gfx.screen_w;
    buf[1] = gfx.screen_h;
    return 0;
}

fn sysGetExecArg(buf_ptr: u32) u32 {
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

fn sysGetArgv(idx: u32, buf_ptr: u32, buf_size: u32) u32 {
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

fn sysFsize(name_ptr: u32) u32 {
    if (!validateUserPtr(name_ptr, 1)) return E_FAULT;
    const name_bytes: [*]const u8 = @ptrFromInt(@as(usize, name_ptr));
    var name_len: usize = 0;
    while (name_len < 100 and name_bytes[name_len] != 0) : (name_len += 1) {}
    if (name_len == 0) return E_INVAL;
    return vfs.fileSize(name_bytes[0..name_len]) orelse 0xFFFFFFFF;
}

// --- GPU 3D syscalls ---

var next_gpu_ctx_id: u32 = 1;

fn sysGpuCtxCreate(capset_id: u32) u32 {
    const virtio_gpu = @import("../driver/virtio_gpu.zig");
    if (!virtio_gpu.has_virgl) {
        debug.klog("[gpu] ctx_create: no virgl support\n", .{});
        return E_INVAL;
    }

    const pcb = process.currentPCB() orelse return E_FAULT;
    if (pcb.gpu_has_ctx) {
        debug.klog("[gpu] ctx_create: reusing ctx_id={d}\n", .{pcb.gpu_ctx_id});
        return pcb.gpu_ctx_id;
    }

    // Atomic fetch-and-add: two CPUs concurrently entering this syscall must
    // not both grab the same ID. Without this the GPU sees duplicate context
    // IDs and the second ctxCreate silently corrupts the first's state.
    const ctx_id = @atomicRmw(u32, &next_gpu_ctx_id, .Add, 1, .acq_rel);

    if (!virtio_gpu.ctxCreate(ctx_id, capset_id, "app")) {
        debug.klog("[gpu] ctx_create FAILED ctx_id={d} capset={d}\n", .{ ctx_id, capset_id });
        return E_INVAL;
    }

    pcb.gpu_ctx_id = ctx_id;
    pcb.gpu_has_ctx = true;
    debug.klog("[gpu] ctx_create OK ctx_id={d} capset={d}\n", .{ ctx_id, capset_id });
    return ctx_id;
}

fn sysGpuSubmit3D(buf_ptr: u32, buf_len: u32) u32 {
    const virtio_gpu = @import("../driver/virtio_gpu.zig");
    if (buf_len == 0 or buf_len > 15 * 4096) return E_INVAL;
    if (!validateUserPtr(buf_ptr, buf_len)) return E_FAULT;

    const pcb = process.currentPCB() orelse return E_FAULT;
    if (!pcb.gpu_has_ctx) return E_INVAL;

    const src: [*]const u8 = @ptrFromInt(@as(usize, buf_ptr));
    if (virtio_gpu.submit3D(pcb.gpu_ctx_id, src[0..buf_len])) {
        debug.klog("[gpu] submit_3d OK ctx={d} len={d} bytes\n", .{ pcb.gpu_ctx_id, buf_len });
        return 0;
    } else {
        debug.klog("[gpu] submit_3d FAILED ctx={d} len={d}\n", .{ pcb.gpu_ctx_id, buf_len });
        return E_INVAL;
    }
}

fn sysGpuCtxDestroy() u32 {
    const virtio_gpu = @import("../driver/virtio_gpu.zig");
    const pcb = process.currentPCB() orelse return E_FAULT;
    if (!pcb.gpu_has_ctx) return 0;

    _ = virtio_gpu.ctxDestroy(pcb.gpu_ctx_id);
    pcb.gpu_has_ctx = false;
    pcb.gpu_ctx_id = 0;
    return 0;
}

fn sysGpuGetCapsetInfo(index: u32, buf_ptr: u32) u32 {
    // Returns [capset_id: u32, max_version: u32, max_size: u32] to user buffer
    if (!validateUserPtrAligned(buf_ptr, 12, 4)) {
        debug.klog("[gpu] capset_info[{d}] FAIL: bad user ptr 0x{X}\n", .{ index, buf_ptr });
        return E_INVAL;
    }
    const virtio_gpu = @import("../driver/virtio_gpu.zig");
    if (!virtio_gpu.has_virgl) {
        debug.klog("[gpu] capset_info[{d}] FAIL: no virgl\n", .{index});
        return E_INVAL;
    }

    var cmd = virtio_gpu.GetCapsetInfo{ .hdr = .{ .cmd_type = 0x0108 }, .capset_index = index };
    var resp: virtio_gpu.RespCapsetInfo = undefined;
    @memset(@as([*]u8, @ptrCast(&resp))[0..@sizeOf(virtio_gpu.RespCapsetInfo)], 0);

    if (!virtio_gpu.sendCmd(
        @as([*]const u8, @ptrCast(&cmd)),
        @sizeOf(virtio_gpu.GetCapsetInfo),
        @as([*]u8, @ptrCast(&resp)),
        @sizeOf(virtio_gpu.RespCapsetInfo),
    )) {
        debug.klog("[gpu] capset_info[{d}] FAIL: sendCmd\n", .{index});
        return E_INVAL;
    }

    if (resp.hdr.cmd_type != 0x1102) {
        debug.klog("[gpu] capset_info[{d}] FAIL: resp.cmd_type=0x{X} (id={d} size={d})\n", .{
            index, resp.hdr.cmd_type, resp.capset_id, resp.capset_max_size,
        });
        return E_INVAL;
    }

    const buf: [*]u32 = @ptrFromInt(@as(usize, buf_ptr));
    buf[0] = resp.capset_id;
    buf[1] = resp.capset_max_version;
    buf[2] = resp.capset_max_size;
    debug.klog("[gpu] capset_info[{d}]: id={d} ver={d} size={d}\n", .{
        index, resp.capset_id, resp.capset_max_version, resp.capset_max_size,
    });
    return 0;
}

fn sysGpuCreateBlob(blob_mem: u32, size: u32, blob_id_arg: u32) u32 {
    const virtio_gpu = @import("../driver/virtio_gpu.zig");
    if (!virtio_gpu.has_blob) return E_INVAL;

    const pcb = process.currentPCB() orelse return E_FAULT;
    if (!pcb.gpu_has_ctx) return E_INVAL;

    const resource_id = virtio_gpu.alloc3DResourceId();
    const blob_id: u64 = blob_id_arg;
    if (!virtio_gpu.resourceCreateBlob(
        pcb.gpu_ctx_id,
        resource_id,
        blob_mem,
        if (blob_id_arg != 0) 5 else 1, // MAPPABLE + CROSS_DEVICE for VkDeviceMemory blobs
        blob_id,
        size,
    )) return E_INVAL;

    return resource_id;
}

fn sysGpuMapBlob(resource_id: u32, size: u32) u32 {
    const virtio_gpu = @import("../driver/virtio_gpu.zig");
    debug.klog("[gpu] mapBlob: res={d} size={d}\n", .{ resource_id, size });
    if (!virtio_gpu.has_blob) {
        debug.klog("[gpu] mapBlob: no blob support\n", .{});
        return E_INVAL;
    }

    const pcb = process.currentPCB() orelse return E_FAULT;
    if (!pcb.gpu_has_ctx) return E_INVAL;
    const pd = pcb.page_directory orelse return E_FAULT;

    // Attach resource to context first
    if (!virtio_gpu.ctxAttachResource(pcb.gpu_ctx_id, resource_id)) {
        debug.klog("[gpu] mapBlob: ctxAttach failed\n", .{});
        return E_INVAL;
    }

    // Map blob in SHM BAR — get physical address
    const phys = virtio_gpu.resourceMapBlob(resource_id, size) orelse {
        debug.klog("[gpu] mapBlob: resourceMapBlob failed\n", .{});
        return E_INVAL;
    };

    // Ensure kernel can access the SHM BAR pages. Use the WB variant
    // (NOT mapMMIO!): virtio-gpu BLOB memory is host DRAM exposed through
    // the SHM BAR — not MMIO registers — and the host's mmap of the
    // backing dma-buf is WB. Mapping UC on the guest side breaks MESI
    // coherency across the KVM boundary (guest reads stale DRAM until
    // the host CPU flushes its caches), and pegs reads to ~1.5 GB/s.
    paging.mapWBRange(phys, size);

    // Map into user space at the process brk region. Same WB-everywhere
    // rationale — both kernel and user mappings of the same physical
    // pages must agree on cacheability or x86 calls it undefined.
    const pages = (size + 4095) / 4096;
    const base_virt = pcb.user_brk;
    for (0..pages) |i| {
        const virt = base_virt + i * 0x1000;
        const p = phys + i * 0x1000;
        vmm.mapUserPage(pd, virt, p, paging.PRESENT | paging.READ_WRITE | paging.USER);
    }
    pcb.user_brk = base_virt + pages * 0x1000;

    debug.klog("[gpu] map_blob: res={d} phys=0x{X} virt=0x{X} size={d}\n", .{ resource_id, phys, base_virt, size });
    return @intCast(base_virt);
}

/// Allocate guest physical pages, create a virtio-gpu BLOB_MEM_GUEST
/// resource backed by them, attach to context, and map into user space.
/// Returns the user VA where the pages are mapped; writes the
/// resource_id to *out_resource_id (so the caller can pass it into a
/// Venus `vkAllocateMemory` chained with `VkImportMemoryResourceInfoMESA`).
///
/// The resulting memory IS shared bidirectionally with the host's Venus
/// renderer: Lavapipe writes go to the same physical pages the user
/// reads. This is the path that actually delivers Vulkan-rendered
/// pixels to the guest, unlike BLOB_MEM_HOST3D which gives Lavapipe a
/// disconnected allocation.
fn sysGpuCreateGuestBlob(size: u32, out_resource_id_ptr: u32) u32 {
    const virtio_gpu = @import("../driver/virtio_gpu.zig");
    if (!virtio_gpu.has_blob) return E_INVAL;
    if (size == 0 or size > 32 * 1024 * 1024) return E_INVAL;
    if (!validateUserPtrAligned(out_resource_id_ptr, 4, 4)) return E_FAULT;

    const pcb = process.currentPCB() orelse return E_FAULT;
    if (!pcb.gpu_has_ctx) return E_INVAL;
    const pd = pcb.page_directory orelse return E_FAULT;

    const num_pages = (size + 4095) / 4096;
    const phys_base = pmm.allocContiguous(num_pages) orelse {
        debug.klog("[gpu] createGuestBlob: pmm.allocContiguous({d} pages) FAILED\n", .{num_pages});
        return E_INVAL;
    };

    // Zero the pages so callers don't observe stale heap garbage. The
    // pages are guest physical, mapped into kernel via physToVirt
    // (PHYSMAP_BASE + phys, kernel can reach any phys frame).
    const kvirt: [*]u8 = @ptrFromInt(paging.physToVirt(phys_base));
    @memset(kvirt[0 .. num_pages * 4096], 0);

    const resource_id = virtio_gpu.alloc3DResourceId();
    // MAPPABLE | SHAREABLE: guest mmaps it, virgl shares it with Lavapipe.
    if (!virtio_gpu.resourceCreateGuestBlob(
        pcb.gpu_ctx_id,
        resource_id,
        0x03,
        phys_base,
        @as(u64, size),
    )) {
        debug.klog("[gpu] createGuestBlob: resourceCreateGuestBlob FAILED\n", .{});
        return E_INVAL;
    }

    if (!virtio_gpu.ctxAttachResource(pcb.gpu_ctx_id, resource_id)) {
        debug.klog("[gpu] createGuestBlob: ctxAttachResource FAILED\n", .{});
        return E_INVAL;
    }

    const base_virt = pcb.user_brk;
    for (0..num_pages) |i| {
        const virt = base_virt + i * 0x1000;
        const phys = phys_base + i * 0x1000;
        vmm.mapUserPage(pd, virt, phys, paging.READ_WRITE | paging.USER);
    }
    pcb.user_brk = base_virt + num_pages * 0x1000;

    const out_ptr: *u32 = @ptrFromInt(@as(usize, out_resource_id_ptr));
    out_ptr.* = resource_id;

    debug.klog("[gpu] createGuestBlob: res={d} phys=0x{X} virt=0x{X} pages={d}\n",
        .{ resource_id, phys_base, base_virt, num_pages });
    return @intCast(base_virt);
}

fn sysGpuResourceCreate3D(params_ptr: u32) u32 {
    const virtio_gpu = @import("../driver/virtio_gpu.zig");
    if (!virtio_gpu.has_virgl) return E_INVAL;

    const pcb = process.currentPCB() orelse return E_FAULT;
    if (!pcb.gpu_has_ctx) return E_INVAL;
    if (!validateUserPtrAligned(params_ptr, 20, 4)) return E_FAULT;

    const params: [*]const u32 = @ptrFromInt(@as(usize, params_ptr));
    const resource_id = virtio_gpu.alloc3DResourceId();
    debug.klog("[gpu] resource_create_3d: id={d} {d}x{d} fmt={d} bind=0x{x}\n", .{
        resource_id, params[3], params[4], params[1], params[2],
    });

    if (!virtio_gpu.resourceCreate3D(
        pcb.gpu_ctx_id,
        resource_id,
        params[0],
        params[1],
        params[2],
        params[3],
        params[4],
    )) {
        debug.klog("[gpu] resource_create_3d FAILED\n", .{});
        return E_INVAL;
    }

    if (!virtio_gpu.ctxAttachResource(pcb.gpu_ctx_id, resource_id)) {
        debug.klog("[gpu] ctx_attach_resource FAILED\n", .{});
        return E_INVAL;
    }

    debug.klog("[gpu] resource_create_3d OK id={d}\n", .{resource_id});
    return resource_id;
}

fn sysGpuTransferToHost3D(resource_id: u32, params_ptr: u32) u32 {
    const virtio_gpu = @import("../driver/virtio_gpu.zig");
    if (!virtio_gpu.has_virgl) return E_INVAL;

    const pcb = process.currentPCB() orelse return E_FAULT;
    if (!pcb.gpu_has_ctx) return E_INVAL;
    if (!validateUserPtrAligned(params_ptr, 12, 4)) return E_FAULT;

    // params: [width, height, stride]
    const params: [*]const u32 = @ptrFromInt(@as(usize, params_ptr));
    if (!virtio_gpu.transferToHost3D(
        pcb.gpu_ctx_id,
        resource_id,
        params[0], // width
        params[1], // height
        params[2], // stride
    )) return E_INVAL;

    return 0;
}

/// Symmetric counterpart of sysGpuTransferToHost3D. Pulls a host-side 3D
/// resource (e.g. a Lavapipe-rendered VkImage exposed as a virtio-gpu
/// resource) into the guest-mmapped blob backing it. Required when auto-
/// dmabuf-sharing isn't engaged and Lavapipe writes don't reach the guest
/// blob on their own — call after vkDeviceWaitIdle, before reading pixels.
fn sysGpuTransferFromHost3D(resource_id: u32, params_ptr: u32) u32 {
    const virtio_gpu = @import("../driver/virtio_gpu.zig");
    if (!virtio_gpu.has_virgl) return E_INVAL;

    const pcb = process.currentPCB() orelse return E_FAULT;
    if (!pcb.gpu_has_ctx) return E_INVAL;
    if (!validateUserPtrAligned(params_ptr, 12, 4)) return E_FAULT;

    // params: [width, height, stride]
    const params: [*]const u32 = @ptrFromInt(@as(usize, params_ptr));
    if (!virtio_gpu.transferFromHost3D(
        pcb.gpu_ctx_id,
        resource_id,
        params[0], // width
        params[1], // height
        params[2], // stride
    )) return E_INVAL;

    return 0;
}

/// Point a scanout slot at a blob resource — used by Vulkan apps that
/// want their rendered output displayed directly, sidestepping the
/// (broken-on-this-stack) blob readback path. params: [scanout_id,
/// width, height, format, stride].
fn sysGpuSetScanoutBlob(resource_id: u32, params_ptr: u32) u32 {
    const virtio_gpu = @import("../driver/virtio_gpu.zig");
    if (!virtio_gpu.has_virgl) return E_INVAL;
    if (!validateUserPtrAligned(params_ptr, 20, 4)) return E_FAULT;

    const params: [*]const u32 = @ptrFromInt(@as(usize, params_ptr));
    if (!virtio_gpu.setScanoutBlob(
        params[0], // scanout_id
        resource_id,
        params[1], // width
        params[2], // height
        params[3], // format
        params[4], // stride
    )) return E_INVAL;

    return 0;
}

/// Force a re-display of a scanned-out resource. Pair with
/// setScanoutBlob — call this after every render to push new contents.
fn sysGpuResourceFlush(resource_id: u32, params_ptr: u32) u32 {
    const virtio_gpu = @import("../driver/virtio_gpu.zig");
    if (!virtio_gpu.has_virgl) return E_INVAL;
    if (!validateUserPtrAligned(params_ptr, 8, 4)) return E_FAULT;

    const params: [*]const u32 = @ptrFromInt(@as(usize, params_ptr));
    if (!virtio_gpu.resourceFlush(resource_id, params[0], params[1])) return E_INVAL;

    return 0;
}

fn sysGetWindowSize(buf_ptr: u32) u32 {
    if (!validateUserPtrAligned(buf_ptr, 8, 4)) return E_FAULT;
    const buf: [*]u32 = @ptrFromInt(@as(usize, buf_ptr));
    const pid: u8 = @intCast(process.getCurrentPid());
    desktop.getWindowContentSize(pid, buf);
    return 0;
}

pub fn isr_syscall() callconv(.naked) void {
    asm volatile (
    // Switch to kernel data segments (preserve RAX = syscall number)
        \\ pushq %%rax
        \\ movw $0x10, %%ax
        \\ movw %%ax, %%ds
        \\ movw %%ax, %%es
        \\ popq %%rax
        // Save all GPRs
        \\ pushq %%r15
        \\ pushq %%r14
        \\ pushq %%r13
        \\ pushq %%r12
        \\ pushq %%r11
        \\ pushq %%r10
        \\ pushq %%r9
        \\ pushq %%r8
        \\ pushq %%rbp
        \\ pushq %%rdi
        \\ pushq %%rsi
        \\ pushq %%rbx
        \\ pushq %%rdx
        \\ pushq %%rcx
        \\ pushq %%rax
        // Set up doSyscall args (SysV: RDI=num, RSI=arg1, RDX=arg2, RCX=arg3)
        \\ movl %%eax, %%edi
        \\ movl %%ebx, %%esi
        \\ movl %%ecx, %%r8d
        \\ movl %%edx, %%ecx
        \\ movl %%r8d, %%edx
        \\ call doSyscall
        \\ movq %%rax, (%%rsp)
        // Restore all GPRs
        \\ popq %%rax
        \\ popq %%rcx
        \\ popq %%rdx
        \\ popq %%rbx
        \\ popq %%rsi
        \\ popq %%rdi
        \\ popq %%rbp
        \\ popq %%r8
        \\ popq %%r9
        \\ popq %%r10
        \\ popq %%r11
        \\ popq %%r12
        \\ popq %%r13
        \\ popq %%r14
        \\ popq %%r15
        // Restore user data segments (preserve RAX = return value)
        \\ pushq %%rax
        \\ movw $0x23, %%ax
        \\ movw %%ax, %%ds
        \\ movw %%ax, %%es
        \\ popq %%rax
        \\ iretq
    );
}

fn sysChdir(path_ptr: u32) u32 {
    const pcb = process.currentPCB() orelse return E_FAULT;
    // Pre-cast guard: same null-cast safety check as sysMkdir.
    if (!validateUserPtr(path_ptr, 1)) return E_INVAL;

    // Read NUL-terminated path from user space.
    var path_buf: [256]u8 = undefined;
    var path_len: usize = 0;
    const src: [*]const u8 = @ptrFromInt(@as(usize, path_ptr));
    while (path_len < 256) : (path_len += 1) {
        if (!validateUserPtr(path_ptr + @as(u32, @intCast(path_len)), 1)) return E_INVAL;
        const ch = src[path_len];
        if (ch == 0) break;
        path_buf[path_len] = ch;
    }
    if (path_len == 0 or path_len >= 256) return E_NAMETOOLONG;

    // Build the absolute candidate. Relative paths get the current cwd
    // prepended (cwd is stored with a trailing '/' so concatenation is
    // straightforward — see the trailing-slash invariant below).
    var abs: [256]u8 = undefined;
    var abs_len: usize = 0;
    if (path_buf[0] == '/') {
        @memcpy(abs[0..path_len], path_buf[0..path_len]);
        abs_len = path_len;
    } else {
        const cwd = pcb.cwd[0..pcb.cwd_len];
        if (cwd.len == 0) return E_INVAL;
        const need_sep = cwd[cwd.len - 1] != '/';
        const need = cwd.len + path_len + (if (need_sep) @as(usize, 1) else 0);
        if (need > 256) return E_INVAL;
        @memcpy(abs[0..cwd.len], cwd);
        abs_len = cwd.len;
        if (need_sep) {
            abs[abs_len] = '/';
            abs_len += 1;
        }
        @memcpy(abs[abs_len..][0..path_len], path_buf[0..path_len]);
        abs_len += path_len;
    }

    // Normalize: strip duplicate slashes, drop "." components, and resolve
    // ".." by popping the previous component. ".." at or above the first
    // component is clamped (stays at the mount root) instead of escaping
    // up to "/", which has no mount and would always fail.
    abs_len = normalizePath(&abs, abs_len);
    if (abs_len == 0) return E_INVAL;

    // Trailing-slash invariant: cwd always ends with '/' so resolvePath's
    // relative-path concat ("cwd + child") doesn't produce missing or
    // doubled separators.
    if (abs[abs_len - 1] != '/') {
        if (abs_len >= 256) return E_INVAL;
        abs[abs_len] = '/';
        abs_len += 1;
    }

    // Validate. Two acceptable shapes:
    //   1. abs is a mount root exactly (e.g. "/tar/") — resolvePath rejects
    //      these because it requires a non-empty rel under the mount.
    //   2. abs (sans trailing '/') resolves under some mount, AND the
    //      resolved fs confirms the path is an existing directory.
    if (!vfs.isMountRoot(abs[0..abs_len])) {
        var rb: [256]u8 = undefined;
        const r = vfs.resolvePath(pcb, abs[0 .. abs_len - 1], &rb) orelse return E_NOENT;
        // Per-fs existence check. tarfs is flat (no real subdirs) so we
        // accept any junk and let later opens fail — matches historical
        // behavior. Other filesystems can verify, so they do.
        switch (r.fs) {
            .tarfs => {},
            .fat32 => {
                const fat32 = @import("../fs/fat32.zig");
                if (fat32.resolveDirCluster(r.path) == null) return E_INVAL;
            },
            .devfs => {
                // devfs has no subdirectories — any non-empty path is a file.
                return E_INVAL;
            },
            .procfs => {
                const procfs = @import("../fs/procfs.zig");
                if (!procfs.isDirectory(r.path)) return E_INVAL;
            },
            .ext2 => {
                const ext2 = @import("../fs/ext2/ext2.zig");
                if (ext2.resolveDirInum(r.path) == null) return E_INVAL;
            },
        }
    }

    if (abs_len > pcb.cwd.len) return E_INVAL;
    @memcpy(pcb.cwd[0..abs_len], abs[0..abs_len]);
    pcb.cwd_len = @intCast(abs_len);
    return 0;
}

/// Collapse `.` and `..` components and duplicate slashes in an absolute
/// path. Mutates `buf` in place; returns the new length. ".." that would
/// pop the first (mount-name) component is silently dropped — `cd ..`
/// from `/tar/` should stay at `/tar/` rather than escape to `/`.
fn normalizePath(buf: *[256]u8, in_len: usize) usize {
    if (in_len == 0 or buf[0] != '/') return in_len;

    // Component table — offset/length within the input. 32 components is
    // way more than any realistic path; if exceeded we punt and return
    // the original length unchanged (callers will see the long path and
    // fail downstream).
    var comp_off: [32]u8 = undefined;
    var comp_len: [32]u8 = undefined;
    var n: usize = 0;

    var i: usize = 1;
    while (i < in_len) {
        var j = i;
        while (j < in_len and buf[j] != '/') j += 1;
        const len = j - i;
        if (len == 0) {
            // empty component (// in path) — skip
        } else if (len == 1 and buf[i] == '.') {
            // "." — skip
        } else if (len == 2 and buf[i] == '.' and buf[i + 1] == '.') {
            // ".." — pop, but never the first (mount) component
            if (n > 1) n -= 1;
        } else {
            if (n >= 32) return in_len;
            comp_off[n] = @intCast(i);
            comp_len[n] = @intCast(len);
            n += 1;
        }
        i = j + 1;
    }

    // Rebuild via a scratch buffer so we don't read-after-write issues —
    // comp_off points into `buf`, and we rewrite `buf` from the start.
    var out: [256]u8 = undefined;
    var out_len: usize = 1;
    out[0] = '/';
    for (0..n) |k| {
        const off = comp_off[k];
        const len = comp_len[k];
        if (out_len + len + 1 > out.len) return in_len;
        @memcpy(out[out_len..][0..len], buf[off..][0..len]);
        out_len += len;
        out[out_len] = '/';
        out_len += 1;
    }
    @memcpy(buf[0..out_len], out[0..out_len]);
    return out_len;
}

fn sysGetcwd(buf_ptr: u32, size: u32) u32 {
    const pcb = process.currentPCB() orelse return E_FAULT;

    const cwd_len = pcb.cwd_len;
    if (size < cwd_len + 1) return E_INVAL; // need space for null terminator
    if (!validateUserPtr(buf_ptr, cwd_len + 1)) return E_FAULT;

    const dest: [*]u8 = @ptrFromInt(@as(usize, buf_ptr));
    @memcpy(dest[0..cwd_len], pcb.cwd[0..cwd_len]);
    dest[cwd_len] = 0; // null terminator

    return cwd_len;
}

fn sysMkdir(path_ptr: u32) u32 {
    const pcb = process.currentPCB() orelse return E_FAULT;
    // Pre-cast guard. `[*]const u8 = @ptrFromInt(0)` triggers Zig's runtime
    // null-cast safety check before we ever reach the per-byte
    // validateUserPtr in the loop below — caught by redteam fuzzer hitting
    // sysMkdir with arg1=0. Validate at least the first byte upfront so the
    // cast itself is safe.
    if (!validateUserPtr(path_ptr, 1)) return E_INVAL;

    // Read path from user space
    var path_buf: [256]u8 = undefined;
    var path_len: usize = 0;
    const src: [*]const u8 = @ptrFromInt(@as(usize, path_ptr));

    while (path_len < 256) : (path_len += 1) {
        if (!validateUserPtr(path_ptr + @as(u32, @intCast(path_len)), 1)) return E_INVAL;
        const ch = src[path_len];
        if (ch == 0) break;
        path_buf[path_len] = ch;
    }

    if (path_len == 0 or path_len >= 256) return E_NAMETOOLONG;

    // Resolve path
    var resolve_buf: [256]u8 = undefined;
    const resolved = vfs.resolvePath(pcb, path_buf[0..path_len], &resolve_buf) orelse return E_NOENT;

    switch (resolved.fs) {
        .fat32 => {
            const fat32 = @import("../fs/fat32.zig");
            return if (fat32.createDirectory(resolved.path)) 0 else E_INVAL;
        },
        .ext2 => {
            const ext2 = @import("../fs/ext2/ext2.zig");
            return if (ext2.mkdirPath(resolved.path)) 0 else E_INVAL;
        },
        else => return E_INVAL,
    }
}

fn sysReaddir(path_ptr: u32, buf_ptr: u32, buf_size: u32) u32 {
    const pcb = process.currentPCB() orelse return E_FAULT;
    // Pre-cast guard: same null-cast safety check as sysMkdir.
    if (!validateUserPtr(path_ptr, 1)) return E_INVAL;

    // Read path from user space
    var path_buf: [256]u8 = undefined;
    var path_len: usize = 0;
    const src: [*]const u8 = @ptrFromInt(@as(usize, path_ptr));

    while (path_len < 256) : (path_len += 1) {
        if (!validateUserPtr(path_ptr + @as(u32, @intCast(path_len)), 1)) return E_INVAL;
        const ch = src[path_len];
        if (ch == 0) break;
        path_buf[path_len] = ch;
    }

    if (path_len == 0 or path_len >= 256) return E_NAMETOOLONG;
    if (!validateUserPtrAligned(buf_ptr, buf_size, @alignOf(FileEntry))) return E_FAULT;

    const entry_size: u32 = @sizeOf(FileEntry);
    const max_entries = buf_size / entry_size;
    if (max_entries == 0) return E_INVAL;

    const entries: [*]FileEntry = @ptrFromInt(@as(usize, buf_ptr));

    // Resolve path
    var resolve_buf: [256]u8 = undefined;
    const resolved = vfs.resolvePath(pcb, path_buf[0..path_len], &resolve_buf) orelse return E_NOENT;

    switch (resolved.fs) {
        .tarfs => {
            // List all files in tarfs index
            const tarfs = @import("../fs/tarfs.zig");
            const count = tarfs.listToBuffer(@ptrCast(entries), max_entries);
            return count;
        },
        .fat32 => {
            const fat32 = @import("../fs/fat32.zig");
            const dc = fat32.resolveDirCluster(resolved.path) orelse return E_INVAL;
            return listFatDir(dc, entries, max_entries);
        },
        .devfs => {
            const devfs = @import("../fs/devfs.zig");
            return devfs.listToBuffer(@ptrCast(@alignCast(entries)), max_entries);
        },
        .procfs => {
            const procfs = @import("../fs/procfs.zig");
            return procfs.listToBuffer(resolved.path, @ptrCast(@alignCast(entries)), max_entries);
        },
        .ext2 => {
            const ext2 = @import("../fs/ext2/ext2.zig");
            const dir_inum = ext2.resolveDirInum(resolved.path) orelse return E_INVAL;
            return ext2.listDir(dir_inum, @ptrCast(@alignCast(entries)), max_entries);
        },
    }
}

fn sysUnlink(path_ptr: u32, path_len: u32) u32 {
    const pcb = process.currentPCB() orelse return E_FAULT;

    if (path_len == 0 or path_len > 256) return E_NAMETOOLONG;
    if (!validateUserPtr(path_ptr, path_len)) return E_FAULT;

    // Read path from user space
    var path_buf: [256]u8 = undefined;
    const src: [*]const u8 = @ptrFromInt(@as(usize, path_ptr));
    @memcpy(path_buf[0..path_len], src[0..path_len]);

    // Resolve path
    var resolve_buf: [256]u8 = undefined;
    const resolved = vfs.resolvePath(pcb, path_buf[0..path_len], &resolve_buf) orelse return E_NOENT;

    switch (resolved.fs) {
        .tarfs => {
            // tarfs is read-only
            return E_INVAL;
        },
        .fat32 => {
            const fat32 = @import("../fs/fat32.zig");
            if (fat32.deleteFile(resolved.path)) {
                return 0;
            }
            return E_INVAL;
        },
        .devfs => {
            // Can't delete device files
            return E_INVAL;
        },
        .procfs => return 0xFFFFFFFF,
        .ext2 => {
            const ext2 = @import("../fs/ext2/ext2.zig");
            return if (ext2.unlinkPath(resolved.path)) 0 else E_INVAL;
        },
    }
}

const FileStat = extern struct {
    file_size: u32,
    is_directory: u32,
    create_time: u32,
    modify_time: u32,
};

fn sysStat(path_ptr: u32, path_len: u32, stat_buf_ptr: u32) u32 {
    const pcb = process.currentPCB() orelse return E_FAULT;

    if (path_len == 0 or path_len > 256) return E_NAMETOOLONG;
    if (!validateUserPtr(path_ptr, path_len)) return E_FAULT;
    if (!validateUserPtrAligned(stat_buf_ptr, @sizeOf(FileStat), @alignOf(FileStat))) return E_INVAL;

    // Read path from user space
    var path_buf: [256]u8 = undefined;
    const src: [*]const u8 = @ptrFromInt(@as(usize, path_ptr));
    @memcpy(path_buf[0..path_len], src[0..path_len]);

    // Resolve path
    var resolve_buf: [256]u8 = undefined;
    const resolved = vfs.resolvePath(pcb, path_buf[0..path_len], &resolve_buf) orelse return E_NOENT;

    const stat_buf: *FileStat = @ptrFromInt(@as(usize, stat_buf_ptr));

    switch (resolved.fs) {
        .tarfs => {
            const tarfs = @import("../fs/tarfs.zig");
            if (tarfs.getFileStat(resolved.path, stat_buf)) {
                return 0;
            }
            return E_INVAL;
        },
        .fat32 => {
            const fat32 = @import("../fs/fat32.zig");
            if (fat32.getFileStat(resolved.path, stat_buf)) {
                return 0;
            }
            return E_INVAL;
        },
        .devfs => {
            const devfs = @import("../fs/devfs.zig");
            const idx = devfs.openFile(resolved.path) orelse return E_INVAL;
            const sz = devfs.deviceSize(idx);
            stat_buf.file_size = if (sz > 0xFFFFFFFF) 0xFFFFFFFF else @intCast(sz);
            stat_buf.is_directory = 0;
            stat_buf.create_time = 0;
            stat_buf.modify_time = 0;
            return 0;
        },
        .procfs => {
            const procfs = @import("../fs/procfs.zig");
            if (procfs.isDirectory(resolved.path)) {
                stat_buf.file_size = 0;
                stat_buf.is_directory = 1;
                stat_buf.create_time = 0;
                stat_buf.modify_time = 0;
                return 0;
            }
            if (procfs.openFile(resolved.path)) |_| {
                stat_buf.file_size = 0;
                stat_buf.is_directory = 0;
                stat_buf.create_time = 0;
                stat_buf.modify_time = 0;
                return 0;
            }
            return E_INVAL;
        },
        .ext2 => {
            const ext2 = @import("../fs/ext2/ext2.zig");
            if (ext2.getFileStat(resolved.path, stat_buf)) return 0;
            return E_INVAL;
        },
    }
}

fn sysRename(old_path_ptr: u32, old_len: u32, new_path_ptr: u32) u32 {
    const pcb = process.currentPCB() orelse return E_FAULT;

    if (old_len == 0 or old_len > 256) return E_NAMETOOLONG;
    if (!validateUserPtr(old_path_ptr, old_len)) return E_FAULT;

    // Read new path length from user space (stored at new_path_ptr as u32)
    if (!validateUserPtrAligned(new_path_ptr, 4, 4)) return E_FAULT;
    const new_len_ptr: *const u32 = @ptrFromInt(@as(usize, new_path_ptr));
    const new_len = new_len_ptr.*;

    if (new_len == 0 or new_len > 256) return E_NAMETOOLONG;
    if (!validateUserPtr(new_path_ptr + 4, new_len)) return E_FAULT;

    // Read old path
    var old_path_buf: [256]u8 = undefined;
    const old_src: [*]const u8 = @ptrFromInt(@as(usize, old_path_ptr));
    @memcpy(old_path_buf[0..old_len], old_src[0..old_len]);

    // Read new path (skip the length prefix)
    var new_path_buf: [256]u8 = undefined;
    const new_src: [*]const u8 = @ptrFromInt(@as(usize, new_path_ptr + 4));
    @memcpy(new_path_buf[0..new_len], new_src[0..new_len]);

    // Resolve old path
    var old_resolve_buf: [256]u8 = undefined;
    const old_resolved = vfs.resolvePath(pcb, old_path_buf[0..old_len], &old_resolve_buf) orelse return E_NOENT;

    // Resolve new path
    var new_resolve_buf: [256]u8 = undefined;
    const new_resolved = vfs.resolvePath(pcb, new_path_buf[0..new_len], &new_resolve_buf) orelse return E_NOENT;

    // Must be same filesystem
    if (@intFromEnum(old_resolved.fs) != @intFromEnum(new_resolved.fs)) return E_INVAL;

    switch (old_resolved.fs) {
        .tarfs => {
            // tarfs is read-only
            return E_INVAL;
        },
        .fat32 => {
            const fat32 = @import("../fs/fat32.zig");
            if (fat32.renameFile(old_resolved.path, new_resolved.path)) {
                return 0;
            }
            return E_INVAL;
        },
        .devfs => {
            // Can't rename device files
            return E_INVAL;
        },
        .procfs => return 0xFFFFFFFF,
        .ext2 => return E_INVAL, // Phase 2 will implement rename
    }
}

fn sysRmdir(path_ptr: u32, path_len: u32) u32 {
    const pcb = process.currentPCB() orelse return E_FAULT;

    if (path_len == 0 or path_len > 256) return E_NAMETOOLONG;
    if (!validateUserPtr(path_ptr, path_len)) return E_FAULT;

    // Read path from user space
    var path_buf: [256]u8 = undefined;
    const src: [*]const u8 = @ptrFromInt(@as(usize, path_ptr));
    @memcpy(path_buf[0..path_len], src[0..path_len]);

    // Resolve path
    var resolve_buf: [256]u8 = undefined;
    const resolved = vfs.resolvePath(pcb, path_buf[0..path_len], &resolve_buf) orelse return E_NOENT;

    switch (resolved.fs) {
        .tarfs => {
            // tarfs is read-only
            return E_INVAL;
        },
        .fat32 => {
            const fat32 = @import("../fs/fat32.zig");
            if (fat32.removeDirectory(resolved.path)) {
                return 0;
            }
            return E_INVAL;
        },
        .devfs => {
            // Can't remove device directories
            return E_INVAL;
        },
        .procfs => return 0xFFFFFFFF,
        .ext2 => {
            const ext2 = @import("../fs/ext2/ext2.zig");
            return if (ext2.rmdirPath(resolved.path)) 0 else E_INVAL;
        },
    }
}

fn sysSetPriority(priority: u32) u32 {
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
fn sysSetAffinity(target_pid: u32, cpu_id: u32) u32 {
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
fn sysGetAffinity(target_pid: u32) u32 {
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
fn sysSetNice(target_pid: u32, new_nice: u32) u32 {
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
fn sysGetNice(target_pid: u32) u32 {
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

pub const CLIPBOARD_MAX: u32 = 64 * 1024;
var clipboard_buf: [CLIPBOARD_MAX]u8 = [_]u8{0} ** CLIPBOARD_MAX;
var clipboard_len: u32 = 0;
var clipboard_lock: @import("../proc/spinlock.zig").SpinLock = .{};

fn sysSetClipboard(buf_ptr: u32, len: u32) u32 {
    if (len == 0) {
        clipboard_lock.acquire();
        defer clipboard_lock.release();
        clipboard_len = 0;
        return 0;
    }
    if (len > CLIPBOARD_MAX) return E_INVAL;
    if (!validateUserPtr(buf_ptr, len)) return E_FAULT;
    const src: [*]const u8 = @ptrFromInt(@as(usize, buf_ptr));
    clipboard_lock.acquire();
    defer clipboard_lock.release();
    @memcpy(clipboard_buf[0..len], src[0..len]);
    clipboard_len = len;
    return len;
}

fn sysGetClipboard(buf_ptr: u32, max_len: u32) u32 {
    clipboard_lock.acquire();
    defer clipboard_lock.release();
    const actual = clipboard_len;
    if (actual == 0 or max_len == 0) return 0;
    const copy_n = @min(actual, max_len);
    if (!validateUserPtr(buf_ptr, copy_n)) return E_FAULT;
    const dst: [*]u8 = @ptrFromInt(@as(usize, buf_ptr));
    @memcpy(dst[0..copy_n], clipboard_buf[0..copy_n]);
    return actual;
}

// --- Process tree + IPC syscalls (Task #73) ---

/// waitpid(pid, status_ptr) — block until a child of the calling process has
/// exited, then write its exit status to *status_ptr and return the reaped pid.
/// pid == 0xFFFFFFFF: any child. Otherwise: that exact child only.
/// Returns 0xFFFFFFFF if there is no such child (or the target isn't ours).
fn sysWaitpid(target_pid: u32, status_ptr: u32) u32 {
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

        // Pending signal — bail out as EINTR. The signal will be delivered
        // on the syscall return path before user code resumes; without this
        // bail, we'd re-park forever even after wake() flipped us to .ready.
        if (signals.hasDeliverable(me_pcb)) return E_INVAL;

        // Block until a child becomes a zombie (woken by killProcess/destroy
        // OR by a signal posted with signals.send). process.blockOn handles
        // the wait_kind/state/yield/clear dance.
        const t_pause = perf.rdtsc();
        process.blockOn(.waitpid, target_pid);
        const t_resume = perf.rdtsc();
        me_pcb.perf_gap_cyc +%= t_resume -% t_pause;
    }
}

/// kill(pid, sig) — post `sig` to `pid`. SIGKILL/SIGSTOP can't be caught;
/// other signals go through the normal pending → handler / default-action
/// path. pid == self IS allowed (raise()) — the signal is delivered on the
/// way out of THIS syscall via deliverFromSyscallFrame.
fn sysKill(target_pid: u32, sig: u32) u32 {
    if (target_pid == 0 or target_pid >= process.MAX_PROCS) return E_INVAL;
    if (sig == 0 or sig >= signals.NSIG) return E_INVAL;
    if (!signals.send(@intCast(target_pid), sig)) return E_INVAL;
    return 0;
}

/// sigaction(signum, *new, *old) — install a signal handler. `new` and `old`
/// are pointers to user-space SigAction structs (or 0 to skip). SIGKILL and
/// SIGSTOP are silently ignored — caller can read the old action but can't
/// change the disposition.
fn sysSigaction(signum: u32, new_ptr: u32, old_ptr: u32) u32 {
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
fn sysSigprocmask(how: u32, set_ptr: u32, old_ptr: u32) u32 {
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
fn sysSigpending(set_ptr: u32) u32 {
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
fn sysSigsuspend(mask_ptr: u32) u32 {
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
fn sysPause() u32 {
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

/// klog(buf, len) — write `buf[0..len]` directly to kernel serial, prefixed
/// with the calling PID. Bypasses the fd table, so apps whose stdout is wired
/// to a pipe (children of the shell, GUI launches that go through a terminal
/// host) can still emit traceable diagnostics that show up in serial.log.
/// Truncates len to 256 to keep the kernel from spending serial bandwidth on
/// runaway output.
fn sysKlog(buf_ptr: u32, len: u32) u32 {
    if (len == 0) return 0;
    const safe_len: u32 = @min(len, 256);
    if (!validateUserPtr(buf_ptr, safe_len)) return E_FAULT;
    const ptr: [*]const u8 = @ptrFromInt(@as(usize, buf_ptr));
    const pid = process.getCurrentPid();
    @import("../debug/serial.zig").print("[klog pid={d}] {s}", .{ pid, ptr[0..safe_len] });
    return 0;
}

/// resolve(hostname) — kernel-side DNS lookup. host_ptr/host_len describe a
/// user-space hostname (max 255 bytes); ip_out_ptr is a 4-byte user buffer
/// the resolved IPv4 address gets copied into. Returns 0 on success and
/// 0xFFFFFFFF on any failure (network down, lookup timeout, bad input).
fn sysNetResolve(host_ptr: u32, host_len: u32, ip_out_ptr: u32) u32 {
    if (host_len == 0 or host_len > 255) return E_NAMETOOLONG;
    if (!validateUserPtr(host_ptr, host_len)) return E_FAULT;
    if (!validateUserPtr(ip_out_ptr, 4)) return E_FAULT;

    var hbuf: [256]u8 = undefined;
    const src: [*]const u8 = @ptrFromInt(@as(usize, host_ptr));
    @memcpy(hbuf[0..host_len], src[0..host_len]);

    const net = @import("../net/net.zig");
    const ip = net.resolve(hbuf[0..host_len]) orelse return E_INVAL;

    const dst: [*]u8 = @ptrFromInt(@as(usize, ip_out_ptr));
    @memcpy(dst[0..4], &ip);
    return 0;
}

/// http_get(url, response_buf) — synchronous HTTP/1.0 GET. Returns the full
/// response (status line + headers + body) into the user's response buffer
/// and returns the byte count, or 0xFFFFFFFF on failure. Internally caps
/// at 10s wall-clock via tick deadlines, so the caller will return either
/// with data or with a failure rather than blocking indefinitely.
///
/// The 4 logical parameters don't fit in 3 syscall arg slots, so the caller
/// packs `{u32 buf_ptr, u32 buf_len}` into a small struct passed as `req_ptr`.
fn sysNetHttpGet(url_ptr: u32, url_len: u32, req_ptr: u32) u32 {
    if (url_len == 0 or url_len > 1024) return E_NAMETOOLONG;
    if (!validateUserPtr(url_ptr, url_len)) return E_FAULT;

    const HttpReq = extern struct { buf_ptr: u32, buf_len: u32 };
    if (!validateUserPtrAligned(req_ptr, @sizeOf(HttpReq), @alignOf(HttpReq))) return E_FAULT;
    const req: *const HttpReq = @ptrFromInt(@as(usize, req_ptr));
    if (req.buf_len == 0 or req.buf_len > 1024 * 1024) return E_INVAL;
    if (!validateUserPtr(req.buf_ptr, req.buf_len)) return E_FAULT;

    var url_buf: [1024]u8 = undefined;
    const url_src: [*]const u8 = @ptrFromInt(@as(usize, url_ptr));
    @memcpy(url_buf[0..url_len], url_src[0..url_len]);

    const buf: [*]u8 = @ptrFromInt(@as(usize, req.buf_ptr));
    const buf_slice = buf[0..req.buf_len];

    const net = @import("../net/net.zig");
    const n = net.httpGet(url_buf[0..url_len], buf_slice) orelse return E_INVAL;
    return @intCast(n);
}

/// tcp_connect(ip[4], port) — perform the TCP three-way handshake to
/// `ip:port`. Blocks for up to 5s (kernel-side, with sleep yields). Returns
/// a slot id (0..TCP_MAX_CONNS-1) on success, or 0xFFFFFFFF on failure.
fn sysNetTcpConnect(ip_ptr: u32, port: u32) u32 {
    if (port == 0 or port > 65535) return E_INVAL;
    if (!validateUserPtr(ip_ptr, 4)) return E_FAULT;

    var ip: [4]u8 = undefined;
    const src: [*]const u8 = @ptrFromInt(@as(usize, ip_ptr));
    @memcpy(ip[0..4], src[0..4]);

    const net = @import("../net/net.zig");
    const slot = net.tcpConnect(ip, @intCast(port)) orelse return E_INVAL;
    return slot;
}

/// tcp_send(slot, buf, len) — send `len` bytes synchronously over the TCP
/// connection at `slot`. Splits into MSS-sized segments internally. Returns
/// 0 on success, 0xFFFFFFFF on any failure (bad slot, not connected, send
/// queue full, peer closed mid-send).
fn sysNetTcpSend(slot: u32, buf_ptr: u32, buf_len: u32) u32 {
    if (slot > 255) return E_INVAL;
    if (buf_len == 0) return 0;
    if (buf_len > 64 * 1024) return E_INVAL;
    if (!validateUserPtr(buf_ptr, buf_len)) return E_FAULT;

    const buf: [*]const u8 = @ptrFromInt(@as(usize, buf_ptr));
    const net = @import("../net/net.zig");
    if (!net.tcpSend(@intCast(slot), buf[0..buf_len])) return E_INVAL;
    return 0;
}

/// tcp_recv(slot, buf, len) — copy up to `len` bytes from the connection's
/// RX ring into the user's buffer. Non-blocking: returns 0 if no data is
/// ready yet (callers poll). Closed peer with empty RX returns 0 too —
/// distinguish by checking tcp_status's peer_closed bit.
///
/// We `net.poll()` first to drain the virtio-net RX queue into the per-
/// connection buffers; without this, packets sit in the device queue and
/// the conn buffer reads as empty until some other path happens to call
/// poll() (e.g. a busy-loop in resolve / httpGet).
fn sysNetTcpRecv(slot: u32, buf_ptr: u32, buf_len: u32) u32 {
    if (slot > 255) return 0;
    if (buf_len == 0) return 0;
    if (buf_len > 64 * 1024) return 0;
    if (!validateUserPtr(buf_ptr, buf_len)) return 0;

    const buf: [*]u8 = @ptrFromInt(@as(usize, buf_ptr));
    const net = @import("../net/net.zig");
    net.poll();
    return @intCast(net.tcpRecv(@intCast(slot), buf[0..buf_len]));
}

/// tcp_close(slot) — close the connection at `slot`, sending FIN and
/// (synchronously) waiting up to 1s for the peer's FIN-ACK. Always returns 0;
/// the slot is freed regardless of whether the peer cleanly tore down.
fn sysNetTcpClose(slot: u32) u32 {
    if (slot > 255) return 0;
    const net = @import("../net/net.zig");
    net.tcpClose(@intCast(slot));
    return 0;
}

/// tcp_status(slot) — non-blocking status check. Returns a bitmask:
///   bit 0 (1)  : connection is established and active
///   bit 1 (2)  : peer has sent FIN (we may still have data to drain)
///
/// poll() runs first so the FIN bit reflects the freshest state — without it,
/// nc would never notice the peer closed unless tcpRecv happened to drain a
/// packet that included data along with the FIN.
fn sysNetTcpStatus(slot: u32) u32 {
    if (slot > 255) return 0;
    const net = @import("../net/net.zig");
    net.poll();
    const s: u8 = @intCast(slot);
    var status: u32 = 0;
    if (net.tcpIsConnected(s)) status |= 1;
    if (net.tcpPeerClosed(s)) status |= 2;
    return status;
}

/// tcp_listen(port) — bind a server-side TCP socket to `port`. Returns the
/// listener slot id (0..TCP_MAX_LISTENERS-1), or 0xFFFFFFFF on failure
/// (port already bound, slot pool full, port == 0).
fn sysNetTcpListen(port: u32) u32 {
    if (port == 0 or port > 65535) return E_INVAL;
    const net = @import("../net/net.zig");
    const slot = net.tcpListen(@intCast(port)) orelse return E_INVAL;
    return slot;
}

/// tcp_unlisten(listener_slot) — release the listener slot. Already-accepted
/// conns keep working; only the door for new SYNs closes. Returns 0.
fn sysNetTcpUnlisten(listener_slot: u32) u32 {
    if (listener_slot > 255) return 0;
    const net = @import("../net/net.zig");
    net.tcpUnlisten(@intCast(listener_slot));
    return 0;
}

/// tcp_accept(listener_slot) — pop one ESTABLISHED conn from the listener's
/// accept queue. Returns the conn slot id, or 0xFFFFFFFF if nothing is
/// queued yet. poll() runs first to land any pending handshakes.
fn sysNetTcpAccept(listener_slot: u32) u32 {
    if (listener_slot > 255) return E_INVAL;
    const net = @import("../net/net.zig");
    net.poll();
    const conn = net.tcpAccept(@intCast(listener_slot)) orelse return E_INVAL;
    return conn;
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
fn sysProcessList(buf_ptr: u32, max_entries: u32) u32 {
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

/// shutdown(mode) — flush filesystem caches and ask the platform to power
/// off (mode 0) or reboot (mode 1). For poweroff: prefers FADT.PM1a_CNT
/// (and PM1b_CNT if present) so real hardware is supported, then falls
/// back to the legacy QEMU/Bochs/VBox port magic for environments where
/// ACPI parsing failed. Reboot uses the standard PCI reset register
/// (0xCF9) with an 8042 fallback. Never returns on success.
///
/// SLP_TYPa = 5 (S5 — soft off) is hardcoded. The "right" way is to read
/// the value from DSDT's `\_S5_` package, but that requires an AML
/// interpreter; every BIOS we've ever seen uses 5 here, and QEMU
/// accepts any SLP_TYP when SLP_EN=1.
fn sysShutdown(mode: u32) u32 {
    const io = @import("../io.zig");
    const fat32 = @import("../fs/fat32.zig");
    const acpi = @import("../time/acpi.zig");

    // Best-effort: flush dirty FS caches before yanking the power.
    if (fat32.isInitialized()) fat32.flushAll();
    // Then commit any in-flight NVMe writes to non-volatile storage —
    // without this, the device write cache can lose recent writes on
    // power-off even after fat32.flushAll has drained the OS-side caches.
    @import("../driver/nvme.zig").flushAll();

    if (mode == 1) {
        // Reboot path, preferred order:
        //   1. Hyper-V reset MSR — clean hypervisor-mediated reset on QEMU
        //      with `-cpu host,hv-reset` or real Hyper-V. Synchronous; we
        //      don't return if the host honors it. Skipped when the MSR
        //      isn't exposed.
        //   2. ACPI reset register (FADT.reset_reg + reset_value). Modern
        //      Intel ME / AMD PSP hold reset state in a way only ACPI's
        //      preferred reset path clears cleanly. No-op when the BIOS
        //      didn't fill in FADT.reset_reg (older systems).
        //   3. PCI reset register (port 0xCF9, bit 1 = system reset,
        //      bit 2 pulsed = full reset) — modern QEMU honors this.
        //   4. 8042 keyboard controller pulse — bare-metal fallback that
        //      works on every PC since the AT, but is occasionally
        //      ignored by VMs.
        // Each attempt does nothing if the previous already triggered;
        // the kernel just keeps writing reset registers until something
        // takes.
        const hyperv = @import("../virt/hyperv.zig");
        _ = hyperv.tryReset();
        acpi.tryReset();
        io.outb(0xCF9, 0x06);
        var spin: u32 = 0;
        while ((io.inb(0x64) & 0x02) != 0 and spin < 100000) : (spin += 1) {}
        io.outb(0x64, 0xFE);
    } else {
        // SLP_TYPa=5, SLP_EN=1 → bit pattern 0x3400. Writing this to
        // PM1a_CNT (and PM1b_CNT if non-zero) is the spec-mandated
        // way to enter S5.
        const sleep_word: u16 = (@as(u16, 5) << 10) | (1 << 13);
        if (acpi.getFadt()) |f| {
            if (f.pm1a_cnt_blk != 0) io.outw(@truncate(f.pm1a_cnt_blk), sleep_word);
            if (f.pm1b_cnt_blk != 0) io.outw(@truncate(f.pm1b_cnt_blk), sleep_word);
        }
        // Belt-and-suspenders for hosts where FADT was unparseable or
        // the FADT-named port isn't actually wired (some emulator
        // configs leave PM1a_CNT_BLK as zero and rely on the port magic).
        io.outw(0x604, 0x2000); // QEMU
        io.outw(0xB004, 0x2000); // Bochs
        io.outw(0x4004, 0x3400); // VirtualBox
    }

    // If we're still alive, halt forever.
    while (true) asm volatile ("cli; hlt");
}

/// User-visible USB MSC info struct. Layout matches libc's UsbInfo.
const UsbInfoUser = extern struct {
    present: u8,
    _pad: [3]u8 = .{ 0, 0, 0 },
    block_size: u32,
    block_count: u32,
};

/// usb_info(info_ptr) — fill `info_ptr` with the present/size of the first
/// USB Mass Storage device. Returns 0 if a device exists, 0xFFFFFFFF if no
/// MSC device is connected. Either way the struct is zero-initialised first
/// so callers can read `present` to be sure.
fn sysUsbInfo(info_ptr: u32) u32 {
    if (!validateUserPtrAligned(info_ptr, @sizeOf(UsbInfoUser), @alignOf(UsbInfoUser))) return E_INVAL;
    const dst: *UsbInfoUser = @ptrFromInt(@as(usize, info_ptr));
    dst.* = .{ .present = 0, .block_size = 0, .block_count = 0 };
    if (!xhci.hasMscDevice()) return E_INVAL;
    dst.* = .{
        .present = 1,
        .block_size = xhci.getMscBlockSize(),
        .block_count = xhci.getMscBlockCount(),
    };
    return 0;
}

/// usb_read_sector(lba, buf) — read one MSC block (typically 512 B) from
/// `lba` into the user buffer. Caller is responsible for sizing the buffer
/// to match the device's reported block_size — we only validate the page
/// containing the buffer pointer; mistaken caller sizing risks overflowing
/// later memory. Returns 0 on success.
fn sysUsbReadSector(lba: u32, buf_ptr: u32) u32 {
    if (!xhci.hasMscDevice()) return E_INVAL;
    const block_size = xhci.getMscBlockSize();
    if (block_size == 0 or block_size > 4096) return E_INVAL;
    if (!validateUserPtr(buf_ptr, block_size)) return E_FAULT;
    const buf: [*]u8 = @ptrFromInt(@as(usize, buf_ptr));
    if (!xhci.mscReadSectors(lba, 1, buf)) return E_INVAL;
    return 0;
}

/// usb_write_sector(lba, buf) — write one MSC block. Same sizing contract
/// as `sysUsbReadSector`. Returns 0 on success, 0xFFFFFFFF if no device or
/// the underlying SCSI WRITE(10) failed.
fn sysUsbWriteSector(lba: u32, buf_ptr: u32) u32 {
    if (!xhci.hasMscDevice()) return E_INVAL;
    const block_size = xhci.getMscBlockSize();
    if (block_size == 0 or block_size > 4096) return E_INVAL;
    if (!validateUserPtr(buf_ptr, block_size)) return E_FAULT;
    const buf: [*]const u8 = @ptrFromInt(@as(usize, buf_ptr));
    if (!xhci.mscWriteSectors(lba, 1, buf)) return E_INVAL;
    return 0;
}

/// alarm(seconds) — schedule SIGALRM after `seconds`. Returns the seconds
/// remaining on the previous alarm (0 if none / canceled). seconds == 0
/// cancels any pending alarm without scheduling a new one. The 100 Hz timer
/// IRQ delivers via process.deliverDueAlarms.
fn sysAlarm(seconds: u32) u32 {
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

/// pipe(fds_ptr) — allocate an anonymous pipe and write [read_fd, write_fd]
/// (two u32s) into the user buffer. Returns 0 on success, 0xFFFFFFFF if the
/// pipe pool or fd table is full.
fn sysPipe(fds_ptr: u32) u32 {
    if (!validateUserPtrAligned(fds_ptr, 8, 4)) return E_FAULT;
    const pcb = process.currentPCB() orelse return E_FAULT;

    const id = pipe.alloc() orelse return E_INVAL;

    // Find two free fd slots
    var read_fd: i32 = -1;
    var write_fd: i32 = -1;
    for (3..pcb.fd_table.len) |i| {
        if (pcb.fd_table[i].in_use) continue;
        if (read_fd < 0) {
            read_fd = @intCast(i);
        } else {
            write_fd = @intCast(i);
            break;
        }
    }
    if (read_fd < 0 or write_fd < 0) {
        // Roll back the pipe allocation
        pipe.closeReader(id);
        pipe.closeWriter(id);
        return E_INVAL;
    }

    pcb.fd_table[@intCast(read_fd)] = .{
        .in_use = true,
        .fs_type = .pipe,
        .pipe_id = id,
        .flags = 0, // read end
    };
    pcb.fd_table[@intCast(write_fd)] = .{
        .in_use = true,
        .fs_type = .pipe,
        .pipe_id = id,
        .flags = 1, // write end
    };

    const out: [*]u32 = @ptrFromInt(@as(usize, fds_ptr));
    out[0] = @intCast(read_fd);
    out[1] = @intCast(write_fd);
    return 0;
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
fn sysExecAs(name_ptr: u32, name_len: u32, remap_ptr: u32) u32 {
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
    @import("../debug/serial.zig").print("[execAs] before sysExec name_len={d} n_remap={d}\n", .{ name_len, n_remap });
    const child_pid = sysExec(name_ptr, name_len);
    @import("../debug/serial.zig").print("[execAs] sysExec returned pid={d}\n", .{child_pid});
    if (child_pid == 0xFFFFFFFF) return E_INVAL;

    // Apply remaps + bump pipe refcounts so parent-side closes don't drop the
    // last reference while the child is still using the inherited fd. sysExec
    // already inherited fd 0/1/2 from the parent above, so a remap targeting
    // one of those slots may be replacing an inherited pipe — drop its
    // refcount before installing the new entry, otherwise we leak.
    const child = process.getPCB(@intCast(child_pid));
    child.parent_pid = parent_pid;
    @import("../debug/serial.zig").print("[execAs] set parent_pid done\n", .{});
    for (0..n_remap) |i| {
        const pf = remap[i].parent_fd;
        const cf = remap[i].child_fd;
        @import("../debug/serial.zig").print("[execAs] remap[{d}] pf={d} cf={d}\n", .{ i, pf, cf });
        const old = child.fd_table[cf];
        if (old.in_use and old.fs_type == .pipe) {
            if (old.flags == 0) pipe.closeReader(old.pipe_id) else pipe.closeWriter(old.pipe_id);
        }
        const src = parent_pcb.fd_table[pf];
        @import("../debug/serial.zig").print("[execAs] read parent fd_table[{d}] in_use={} fs_type={} pipe_id={d} flags={d}\n", .{ pf, src.in_use, src.fs_type, src.pipe_id, src.flags });
        child.fd_table[cf] = src;
        @import("../debug/serial.zig").print("[execAs] wrote child fd_table[{d}]\n", .{cf});
        if (src.fs_type == .pipe) {
            if (src.flags == 0) pipe.addReader(src.pipe_id) else pipe.addWriter(src.pipe_id);
            @import("../debug/serial.zig").print("[execAs] bumped pipe refcount\n", .{});
        }
    }

    @import("../debug/serial.zig").print("[execAs] returning pid={d}\n", .{child_pid});
    return child_pid;
}

// --- Wall-clock time + microsecond sleep (Task #74) ---

/// gettimeofday(buf_ptr) — write { u64 sec, u32 usec } to user buffer. sec is
/// Unix epoch seconds; usec is microseconds within the current second.
/// Returns 0 on success.
fn sysGettimeofday(buf_ptr: u32) u32 {
    if (!validateUserPtr(buf_ptr, 16)) return E_FAULT;
    const time = @import("../time/time.zig");
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
fn sysUsleep(usec: u32) u32 {
    if (usec == 0) return 0;
    const time = @import("../time/time.zig");
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

const tls_conn = @import("../crypto/tls/conn.zig");

/// On-wire layout of the tls_connect args struct (kernel & userspace
/// agree). Packed into a single user pointer because syscalls have a
/// 3-arg limit and we need ip + port + variable-length SNI.
const TlsConnectArgs = extern struct {
    ip: [4]u8,
    port: u16,
    _pad: u16,
    sni_ptr: u32,
    sni_len: u32,
};

/// tls_connect(args_ptr) — open a TLS 1.3 connection. Performs the
/// TCP handshake, full TLS 1.3 handshake (X25519/ChaCha20-Poly1305),
/// certificate validation against Mozilla NSS, and CertificateVerify
/// check. Returns the kernel-side TLS slot id on success, or
/// 0xFFFFFFFF on any failure. Blocks for the duration of the
/// handshake (typically <2s on local network, longer on real
/// internet).
fn sysTlsConnect(args_ptr: u32) u32 {
    if (!validateUserPtrAligned(args_ptr, @sizeOf(TlsConnectArgs), @alignOf(TlsConnectArgs))) return E_FAULT;
    var args: TlsConnectArgs = undefined;
    const args_src: [*]const u8 = @ptrFromInt(@as(usize, args_ptr));
    @memcpy(@as([*]u8, @ptrCast(&args))[0..@sizeOf(TlsConnectArgs)], args_src[0..@sizeOf(TlsConnectArgs)]);

    if (args.port == 0 or args.sni_len > 255) return E_INVAL;
    if (!validateUserPtr(args.sni_ptr, args.sni_len)) return E_FAULT;

    var sni_buf: [256]u8 = undefined;
    const sni_src: [*]const u8 = @ptrFromInt(@as(usize, args.sni_ptr));
    @memcpy(sni_buf[0..args.sni_len], sni_src[0..args.sni_len]);

    const slot = tls_conn.tlsConnect(args.ip, args.port, sni_buf[0..args.sni_len]) orelse return E_INVAL;
    return @as(u32, slot);
}

/// tls_send(slot, buf, len) — encrypt `len` bytes as one TLS 1.3
/// application_data record and send it. Returns bytes sent (= len on
/// success), or 0xFFFFFFFF on failure.
fn sysTlsSend(slot: u32, buf_ptr: u32, buf_len: u32) u32 {
    if (slot > 255) return E_INVAL;
    if (buf_len == 0) return 0;
    if (buf_len > 16 * 1024) return E_INVAL;
    if (!validateUserPtr(buf_ptr, buf_len)) return E_FAULT;
    const buf: [*]const u8 = @ptrFromInt(@as(usize, buf_ptr));
    const sent = tls_conn.tlsSend(@intCast(slot), buf[0..buf_len]);
    if (sent < 0) return E_INVAL;
    return @intCast(sent);
}

/// tls_recv(slot, buf, len) — drain up to `len` bytes of plaintext
/// from the conn. Blocks until at least one record arrives or the
/// peer closes. Returns bytes read (>0), 0 on graceful close, or
/// 0xFFFFFFFF on error. Use tls_status (TODO) to disambiguate.
fn sysTlsRecv(slot: u32, buf_ptr: u32, buf_len: u32) u32 {
    if (slot > 255) return E_INVAL;
    if (buf_len == 0) return 0;
    if (!validateUserPtr(buf_ptr, buf_len)) return E_FAULT;
    const buf: [*]u8 = @ptrFromInt(@as(usize, buf_ptr));
    const got = tls_conn.tlsRecv(@intCast(slot), buf[0..buf_len]);
    if (got < 0) return E_INVAL;
    return @intCast(got);
}

/// tls_close(slot) — send TLS close_notify alert, tear down TCP,
/// release the slot. Idempotent.
fn sysTlsClose(slot: u32) u32 {
    if (slot > 255) return 0;
    tls_conn.tlsClose(@intCast(slot));
    return 0;
}
