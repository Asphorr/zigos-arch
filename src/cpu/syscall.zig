//! System-call dispatch — the ABI entry point (doSyscall), the dispatch
//! switch (doSyscallInner), the SYSCALLS naming table, and the syscall ISR
//! stub (isr_syscall). Handler bodies live in syscall/<domain>.zig; this
//! file maps numbers -> handlers. TWO sites must stay in sync when adding a
//! syscall: the SYSCALLS table (naming) and the doSyscallInner switch
//! (dispatch). validateUserPtr + errno constants live in syscall/common.zig.

const std = @import("std");
const process = @import("../proc/process.zig");
const perf = @import("../debug/perf.zig");
const debug = @import("../debug/debug.zig");
const signals = @import("../proc/signals.zig");
const apic = @import("../time/apic.zig");

const common = @import("syscall/common.zig");
const E_NOSYS: u32 = common.E_NOSYS;

// Per-domain handler modules. doSyscallInner dispatches into these.
const proc = @import("syscall/proc.zig");
const mem = @import("syscall/mem.zig");
const fs = @import("syscall/fs.zig");
const window = @import("syscall/window.zig");
const gpu = @import("syscall/gpu.zig");
const net = @import("syscall/net.zig");
const sys = @import("syscall/sys.zig");

/// Slow-syscall sentinel threshold (ms): any single syscall exceeding this
/// prints [slow-sc] with sys#, pid, dt, args. 5ms catches the "single submit
/// blocks for seconds" class without spamming normal blocking primitives.
const SLOW_SYSCALL_THRESHOLD_MS: u64 = 5;

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
    defer @import("arch/protect.zig").disallowUserAccess();
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
        if ((@atomicLoad(u32, &pcb.pending_signals, .acquire) & ~pcb.signal_mask) != 0) {
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
    .{ .num = 1,  .name = "print",                .handler = wrap(window.sysPrint) },
    .{ .num = 2,  .name = "clear",                .handler = wrap(window.sysClear) },
    .{ .num = 3,  .name = "exit",                 .handler = wrap(proc.sysExit) },
    .{ .num = 4,  .name = "read",                 .handler = wrap(window.sysRead) },
    .{ .num = 5,  .name = "sbrk",                 .handler = wrap(mem.sysSbrk) },
    .{ .num = 6,  .name = "getpid",               .handler = wrap(proc.sysGetpid) },
    .{ .num = 7,  .name = "yield",                .handler = wrap(proc.sysYield) },
    .{ .num = 8,  .name = "sleep",                .handler = wrap(proc.sysSleep) },
    .{ .num = 9,  .name = "open",                 .handler = wrap(fs.sysOpen) },
    .{ .num = 10, .name = "fread",                .handler = wrap(fs.sysFread) },
    .{ .num = 11, .name = "fwrite",               .handler = wrap(fs.sysFwrite) },
    .{ .num = 12, .name = "close",                .handler = wrap(fs.sysClose) },
    .{ .num = 13, .name = "create_window",        .handler = wrap(window.sysCreateWindow) },
    .{ .num = 14, .name = "present",              .handler = wrap(window.sysPresent) },
    .{ .num = 15, .name = "get_mouse",            .handler = wrap(window.sysGetMouse) },
    .{ .num = 16, .name = "destroy_window",       .handler = wrap(window.sysDestroyWindow) },
    .{ .num = 17, .name = "uptime",               .handler = wrap(proc.sysUptime) },
    .{ .num = 18, .name = "meminfo",              .handler = wrap(sys.sysMeminfo) },
    .{ .num = 19, .name = "set_config",           .handler = wrap(sys.sysSetConfig) },
    .{ .num = 20, .name = "notify",               .handler = wrap(window.sysNotify) },
    .{ .num = 21, .name = "listdir",              .handler = wrap(fs.sysListDir) },
    .{ .num = 22, .name = "exec",                 .handler = wrap(proc.sysExec) },
    .{ .num = 23, .name = "get_screen_size",      .handler = wrap(window.sysGetScreenSize) },
    .{ .num = 24, .name = "get_window_size",      .handler = wrap(window.sysGetWindowSize) },
    .{ .num = 25, .name = "get_exec_arg",         .handler = wrap(proc.sysGetExecArg) },
    .{ .num = 26, .name = "get_key_state",        .handler = wrap(window.sysGetKeyState) },
    .{ .num = 27, .name = "set_cursor_visible",   .handler = wrap(window.sysSetCursorVisible) },
    .{ .num = 28, .name = "center_mouse",         .handler = wrap(window.sysCenterMouse) },
    .{ .num = 29, .name = "fsize",                .handler = wrap(fs.sysFsize) },
    .{ .num = 30, .name = "gpu_ctx_create",       .handler = wrap(gpu.sysGpuCtxCreate) },
    .{ .num = 31, .name = "gpu_submit_3d",        .handler = wrap(gpu.sysGpuSubmit3D) },
    .{ .num = 32, .name = "gpu_ctx_destroy",      .handler = wrap(gpu.sysGpuCtxDestroy) },
    .{ .num = 33, .name = "gpu_get_capset_info",  .handler = wrap(gpu.sysGpuGetCapsetInfo) },
    .{ .num = 34, .name = "gpu_create_blob",      .handler = wrap(gpu.sysGpuCreateBlob) },
    .{ .num = 35, .name = "gpu_resource_create_3d", .handler = wrap(gpu.sysGpuResourceCreate3D) },
    .{ .num = 36, .name = "gpu_transfer_to_host_3d", .handler = wrap(gpu.sysGpuTransferToHost3D) },
    .{ .num = 37, .name = "gpu_map_blob",         .handler = wrap(gpu.sysGpuMapBlob) },
    .{ .num = 38, .name = "audio_write",          .handler = wrap(sys.sysAudioWrite) },
    .{ .num = 39, .name = "chdir",                .handler = wrap(fs.sysChdir) },
    .{ .num = 40, .name = "getcwd",               .handler = wrap(fs.sysGetcwd) },
    .{ .num = 41, .name = "mkdir",                .handler = wrap(fs.sysMkdir) },
    .{ .num = 42, .name = "readdir",              .handler = wrap(fs.sysReaddir) },
    .{ .num = 43, .name = "unlink",               .handler = wrap(fs.sysUnlink) },
    .{ .num = 44, .name = "stat",                 .handler = wrap(fs.sysStat) },
    .{ .num = 45, .name = "rename",               .handler = wrap(fs.sysRename) },
    .{ .num = 46, .name = "rmdir",                .handler = wrap(fs.sysRmdir) },
    .{ .num = 47, .name = "setpriority",          .handler = wrap(proc.sysSetPriority) },
    .{ .num = 48, .name = "exit_status",          .handler = wrap(proc.sysExitStatus) },
    .{ .num = 49, .name = "waitpid",              .handler = wrap(proc.sysWaitpid) },
    .{ .num = 50, .name = "kill",                 .handler = wrap(proc.sysKill) },
    .{ .num = 51, .name = "pipe",                 .handler = wrap(fs.sysPipe) },
    .{ .num = 52, .name = "exec_as",              .handler = wrap(proc.sysExecAs) },
    .{ .num = 53, .name = "gettimeofday",         .handler = wrap(proc.sysGettimeofday) },
    .{ .num = 54, .name = "usleep",               .handler = wrap(proc.sysUsleep) },
    .{ .num = 55, .name = "get_argc",             .handler = wrap(proc.sysGetArgc) },
    .{ .num = 56, .name = "get_argv",             .handler = wrap(proc.sysGetArgv) },
    .{ .num = 57, .name = "mmap",                 .handler = wrap(mem.sysMmap) },
    .{ .num = 58, .name = "munmap",               .handler = wrap(mem.sysMunmap) },
    .{ .num = 59, .name = "mprotect",             .handler = wrap(mem.sysMprotect) },
    .{ .num = 60, .name = "rt_sigaction",         .handler = wrap(proc.sysSigaction) },
    .{ .num = 61, .name = "rt_sigprocmask",       .handler = wrap(proc.sysSigprocmask) },
    // 62 (sigreturn) is intercepted in doSyscall outer, never dispatched.
    .{ .num = 63, .name = "sigpending",           .handler = wrap(proc.sysSigpending) },
    .{ .num = 64, .name = "sigsuspend",           .handler = wrap(proc.sysSigsuspend) },
    .{ .num = 65, .name = "pause",                .handler = wrap(proc.sysPause) },
    .{ .num = 66, .name = "alarm",                .handler = wrap(proc.sysAlarm) },
    .{ .num = 67, .name = "klog",                 .handler = wrap(sys.sysKlog) },
    .{ .num = 68, .name = "net_resolve",          .handler = wrap(net.sysNetResolve) },
    .{ .num = 69, .name = "net_http_get",         .handler = wrap(net.sysNetHttpGet) },
    .{ .num = 70, .name = "net_tcp_connect",      .handler = wrap(net.sysNetTcpConnect) },
    .{ .num = 71, .name = "net_tcp_send",         .handler = wrap(net.sysNetTcpSend) },
    .{ .num = 72, .name = "net_tcp_recv",         .handler = wrap(net.sysNetTcpRecv) },
    // 73 (net_tcp_close) removed 2026-05-26 — use close(fd); .tcp_sock arm in vfs.close.
    .{ .num = 74, .name = "net_tcp_status",       .handler = wrap(net.sysNetTcpStatus) },
    .{ .num = 75, .name = "net_tcp_listen",       .handler = wrap(net.sysNetTcpListen) },
    // 76 (net_tcp_unlisten) removed 2026-05-26 — use close(fd); .tcp_listener arm in vfs.close.
    .{ .num = 77, .name = "net_tcp_accept",       .handler = wrap(net.sysNetTcpAccept) },
    .{ .num = 78, .name = "process_list",         .handler = wrap(proc.sysProcessList) },
    .{ .num = 79, .name = "usb_info",             .handler = wrap(sys.sysUsbInfo) },
    .{ .num = 80, .name = "usb_read_sector",      .handler = wrap(sys.sysUsbReadSector) },
    .{ .num = 81, .name = "usb_write_sector",     .handler = wrap(sys.sysUsbWriteSector) },
    .{ .num = 82, .name = "shutdown",             .handler = wrap(sys.sysShutdown) },
    .{ .num = 83, .name = "clone",                .handler = wrap(proc.sysClone) },
    .{ .num = 84, .name = "set_tls",              .handler = wrap(proc.sysSetTls) },
    .{ .num = 85, .name = "futex",                .handler = wrap(proc.sysFutex) },
    .{ .num = 86, .name = "exit_thread",          .handler = wrap(proc.sysExitThread) },
    .{ .num = 87, .name = "gpu_transfer_from_host_3d", .handler = wrap(gpu.sysGpuTransferFromHost3D) },
    .{ .num = 88, .name = "gpu_set_scanout_blob",    .handler = wrap(gpu.sysGpuSetScanoutBlob) },
    .{ .num = 89, .name = "gpu_resource_flush",      .handler = wrap(gpu.sysGpuResourceFlush) },
    .{ .num = 90, .name = "poll_event",              .handler = wrap(window.sysPollEvent) },
    .{ .num = 91, .name = "gpu_create_guest_blob",   .handler = wrap(gpu.sysGpuCreateGuestBlob) },
    // 92 (fork) is dispatched directly in doSyscallInner — it needs the saved
    // SyscallFrame to seed child's kstack, which `wrap()` doesn't pass through.
    // Name is registered here so syscallName() / klog still resolve "fork".
    .{ .num = 92, .name = "fork",                    .handler = wrap(proc.sysForkPlaceholder) },
    .{ .num = 93, .name = "setsid",                  .handler = wrap(proc.sysSetsid) },
    .{ .num = 94, .name = "setpgid",                 .handler = wrap(proc.sysSetpgid) },
    .{ .num = 95, .name = "getpgrp",                 .handler = wrap(proc.sysGetpgrp) },
    .{ .num = 96, .name = "getpgid",                 .handler = wrap(proc.sysGetpgid) },
    .{ .num = 97, .name = "getsid",                  .handler = wrap(proc.sysGetsid) },
    .{ .num = 98, .name = "set_wallpaper",            .handler = wrap(window.sysSetWallpaper) },
    .{ .num = 99, .name = "set_affinity",             .handler = wrap(proc.sysSetAffinity) },
    .{ .num = 100, .name = "get_affinity",            .handler = wrap(proc.sysGetAffinity) },
    .{ .num = 101, .name = "set_nice",                .handler = wrap(proc.sysSetNice) },
    .{ .num = 102, .name = "get_nice",                .handler = wrap(proc.sysGetNice) },
    .{ .num = 103, .name = "set_clipboard",           .handler = wrap(window.sysSetClipboard) },
    .{ .num = 104, .name = "get_clipboard",           .handler = wrap(window.sysGetClipboard) },
    .{ .num = 105, .name = "cpu_stats",               .handler = wrap(sys.sysCpuStats) },
    .{ .num = 106, .name = "net_info",                .handler = wrap(net.sysNetInfo) },
    .{ .num = 107, .name = "tls_connect",             .handler = wrap(net.sysTlsConnect) },
    .{ .num = 108, .name = "tls_send",                .handler = wrap(net.sysTlsSend) },
    .{ .num = 109, .name = "tls_recv",                .handler = wrap(net.sysTlsRecv) },
    .{ .num = 110, .name = "tls_close",               .handler = wrap(net.sysTlsClose) },
    .{ .num = 111, .name = "seek",                    .handler = wrap(fs.sysSeek) },
    .{ .num = 112, .name = "get_window_alloc",        .handler = wrap(window.sysGetWindowAlloc) },
    .{ .num = 113, .name = "read_blocking",           .handler = wrap(window.sysReadBlocking) },
    .{ .num = 114, .name = "mmap_shared_anon",        .handler = wrap(mem.sysMmapSharedAnon) },
    .{ .num = 115, .name = "io_uring_setup",          .handler = wrap(sys_iouring_setup) },
    .{ .num = 116, .name = "io_uring_enter",          .handler = wrap(sys_iouring_enter) },
    .{ .num = 117, .name = "debug_crash",             .handler = wrap(sys.sysDebugCrash) },
};

// Thin shims so the dispatch table can route into the iouring module
// without giving SYSCALLS a hard dependency on it.
fn sys_iouring_setup(entries: u32) u32 {
    return @import("ipc/iouring.zig").setup(entries);
}
fn sys_iouring_enter(user_va: u32, to_submit: u32, min_complete: u32) u32 {
    return @import("ipc/iouring.zig").enter(user_va, to_submit, min_complete);
}

/// Returns the registered name for a syscall number, or null if not registered.
/// Useful for diagnostic output (sysmon, dmesg, kdbg autopsy).
pub fn syscallName(num: u32) ?[]const u8 {
    for (SYSCALLS) |s| if (s.num == num) return s.name;
    return null;
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
        1 => window.sysPrint(arg1, arg2),
        2 => window.sysClear(),
        3 => proc.sysExit(),
        4 => window.sysRead(),
        113 => window.sysReadBlocking(),
        114 => mem.sysMmapSharedAnon(arg1),
        115 => sys_iouring_setup(arg1),
        116 => sys_iouring_enter(arg1, arg2, arg3),
        117 => sys.sysDebugCrash(arg1),
        5 => mem.sysSbrk(arg1),
        6 => proc.sysGetpid(),
        7 => proc.sysYield(),
        8 => proc.sysSleep(arg1),
        9 => fs.sysOpen(arg1, arg2),
        10 => fs.sysFread(arg1, arg2, arg3),
        11 => fs.sysFwrite(arg1, arg2, arg3),
        12 => fs.sysClose(arg1),
        13 => window.sysCreateWindow(arg1, arg2, arg3),
        112 => window.sysGetWindowAlloc(arg1),
        14 => window.sysPresent(),
        15 => window.sysGetMouse(arg1),
        16 => window.sysDestroyWindow(),
        17 => proc.sysUptime(),
        18 => sys.sysMeminfo(arg1),
        19 => sys.sysSetConfig(arg1, arg2),
        20 => window.sysNotify(arg1, arg2),
        21 => fs.sysListDir(arg1, arg2),
        22 => proc.sysExec(arg1, arg2),
        23 => window.sysGetScreenSize(arg1),
        24 => window.sysGetWindowSize(arg1),
        25 => proc.sysGetExecArg(arg1),
        26 => window.sysGetKeyState(arg1),
        27 => window.sysSetCursorVisible(arg1),
        28 => window.sysCenterMouse(),
        29 => fs.sysFsize(arg1),
        30 => gpu.sysGpuCtxCreate(arg1),
        31 => gpu.sysGpuSubmit3D(arg1, arg2),
        32 => gpu.sysGpuCtxDestroy(),
        33 => gpu.sysGpuGetCapsetInfo(arg1, arg2),
        34 => gpu.sysGpuCreateBlob(arg1, arg2, arg3),
        35 => gpu.sysGpuResourceCreate3D(arg1),
        36 => gpu.sysGpuTransferToHost3D(arg1, arg2),
        37 => gpu.sysGpuMapBlob(arg1, arg2),
        38 => sys.sysAudioWrite(arg1, arg2),
        39 => fs.sysChdir(arg1),
        40 => fs.sysGetcwd(arg1, arg2),
        41 => fs.sysMkdir(arg1),
        42 => fs.sysReaddir(arg1, arg2, arg3),
        43 => fs.sysUnlink(arg1, arg2),
        44 => fs.sysStat(arg1, arg2, arg3),
        45 => fs.sysRename(arg1, arg2, arg3),
        46 => fs.sysRmdir(arg1, arg2),
        47 => proc.sysSetPriority(arg1),
        48 => proc.sysExitStatus(arg1),
        49 => proc.sysWaitpid(arg1, arg2),
        50 => proc.sysKill(arg1, arg2),
        51 => fs.sysPipe(arg1),
        52 => proc.sysExecAs(arg1, arg2, arg3),
        53 => proc.sysGettimeofday(arg1),
        54 => proc.sysUsleep(arg1),
        55 => proc.sysGetArgc(),
        56 => proc.sysGetArgv(arg1, arg2, arg3),
        57 => mem.sysMmap(arg1, arg2, arg3),
        58 => mem.sysMunmap(arg1, arg2),
        59 => mem.sysMprotect(arg1, arg2, arg3),
        60 => proc.sysSigaction(arg1, arg2, arg3),
        61 => proc.sysSigprocmask(arg1, arg2, arg3),
        // 62 (sigreturn) is intercepted in doSyscall outer, never dispatched.
        63 => proc.sysSigpending(arg1),
        64 => proc.sysSigsuspend(arg1),
        65 => proc.sysPause(),
        66 => proc.sysAlarm(arg1),
        67 => sys.sysKlog(arg1, arg2),
        68 => net.sysNetResolve(arg1, arg2, arg3),
        69 => net.sysNetHttpGet(arg1, arg2, arg3),
        70 => net.sysNetTcpConnect(arg1, arg2),
        71 => net.sysNetTcpSend(arg1, arg2, arg3),
        72 => net.sysNetTcpRecv(arg1, arg2, arg3),
        74 => net.sysNetTcpStatus(arg1),
        75 => net.sysNetTcpListen(arg1),
        77 => net.sysNetTcpAccept(arg1),
        78 => proc.sysProcessList(arg1, arg2),
        79 => sys.sysUsbInfo(arg1),
        80 => sys.sysUsbReadSector(arg1, arg2),
        81 => sys.sysUsbWriteSector(arg1, arg2),
        82 => sys.sysShutdown(arg1),
        83 => proc.sysClone(arg1, arg2, arg3),
        84 => proc.sysSetTls(arg1),
        85 => proc.sysFutex(arg1, arg2, arg3),
        86 => proc.sysExitThread(arg1),
        87 => gpu.sysGpuTransferFromHost3D(arg1, arg2),
        88 => gpu.sysGpuSetScanoutBlob(arg1, arg2),
        89 => gpu.sysGpuResourceFlush(arg1, arg2),
        90 => window.sysPollEvent(arg1),
        91 => gpu.sysGpuCreateGuestBlob(arg1, arg2),
        92 => proc.sysFork(frame),
        93 => proc.sysSetsid(),
        94 => proc.sysSetpgid(arg1, arg2),
        95 => proc.sysGetpgrp(),
        96 => proc.sysGetpgid(arg1),
        97 => proc.sysGetsid(arg1),
        98 => window.sysSetWallpaper(arg1, arg2, arg3),
        99 => proc.sysSetAffinity(arg1, arg2),
        100 => proc.sysGetAffinity(arg1),
        101 => proc.sysSetNice(arg1, arg2),
        102 => proc.sysGetNice(arg1),
        103 => window.sysSetClipboard(arg1, arg2),
        104 => window.sysGetClipboard(arg1, arg2),
        105 => sys.sysCpuStats(arg1, arg2),
        106 => net.sysNetInfo(arg1),
        107 => net.sysTlsConnect(arg1),
        108 => net.sysTlsSend(arg1, arg2, arg3),
        109 => net.sysTlsRecv(arg1, arg2, arg3),
        110 => net.sysTlsClose(arg1),
        111 => fs.sysSeek(arg1, arg2, arg3),
        else => E_NOSYS,
    };
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
