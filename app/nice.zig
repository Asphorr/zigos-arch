// nice — set or query a process's CFS nice value (-20..+19).
//
// Lower nice = larger weight = more CPU share within its priority band.
// Cross-band scheduling is unchanged (interactive ALWAYS beats normal
// beats background — that's `setpriority`, not `nice`).
//
// Usage:
//   nice N prog [args...]   spawn `prog args...` at nice N
//   nice -p N PID           set nice of running PID to N
//   nice PID                print PID's current nice value
//
// N is a signed decimal: -20..19. Out-of-range values are clamped by
// the kernel. Same-tgid restriction applies (kernel returns E_PERM
// when targeting another process's threads).

const libc = @import("libc");

fn parseInt(s: []const u8) ?i32 {
    if (s.len == 0) return null;
    var i: usize = 0;
    var neg: bool = false;
    if (s[0] == '-') { neg = true; i = 1; }
    else if (s[0] == '+') { i = 1; }
    if (i >= s.len) return null;
    var v: u32 = 0;
    while (i < s.len) : (i += 1) {
        const c = s[i];
        if (c < '0' or c > '9') return null;
        v = v *% 10 +% @as(u32, c - '0');
    }
    if (neg) return -@as(i32, @intCast(v));
    return @intCast(v);
}

fn parseU32(s: []const u8) ?u32 {
    if (s.len == 0) return null;
    var v: u32 = 0;
    for (s) |c| {
        if (c < '0' or c > '9') return null;
        v = v *% 10 +% @as(u32, c - '0');
    }
    return v;
}

fn argvCopy(idx: u32, buf: []u8) ?[]const u8 {
    const n = libc.getArgv(idx, buf);
    if (n == 0xFFFFFFFF or n == 0) return null;
    if (n > buf.len) return null;
    return buf[0..n];
}

fn printSigned(v: i32) void {
    if (v < 0) {
        libc.printChar('-');
        libc.printNum(@intCast(-v));
    } else {
        libc.printNum(@intCast(v));
    }
}

fn usage() noreturn {
    libc.print(
        \\usage:
        \\  nice N prog [args...]   spawn at nice N
        \\  nice -p N PID           set PID's nice value
        \\  nice PID                print PID's nice value
        \\
        \\N is a decimal integer in -20..+19 (clamped at the kernel side).
        \\
    );
    libc.exit();
}

fn cmdPrint(pid: u32) void {
    const r = libc.sched_getnice(pid);
    if (r == -100) {
        libc.print("nice: error reading nice (bad pid or different tgid)\n");
        libc.exit();
    }
    libc.print("pid ");
    libc.printNum(pid);
    libc.print(" nice=");
    printSigned(r);
    libc.printChar('\n');
}

fn cmdSet(pid: u32, value: i32) void {
    if (libc.sched_setnice(pid, value) != 0) {
        libc.print("nice: sched_setnice failed (E_INVAL or E_PERM — only own-tgid threads)\n");
        libc.exit();
    }
    libc.print("pid ");
    libc.printNum(pid);
    libc.print(" nice=");
    printSigned(value);
    libc.printChar('\n');
}

fn cmdSpawn(value: i32, prog_argv_start: u32) void {
    var exec_buf: [256]u8 = undefined;
    var written: usize = 0;

    const argc = libc.getArgc();
    var idx: u32 = prog_argv_start;
    var arg_buf: [32]u8 = undefined;
    while (idx < argc) : (idx += 1) {
        const arg = argvCopy(idx, &arg_buf) orelse break;
        if (idx > prog_argv_start) {
            if (written + 1 > exec_buf.len) {
                libc.print("nice: exec line too long\n");
                libc.exit();
            }
            exec_buf[written] = ' ';
            written += 1;
        }
        if (written + arg.len > exec_buf.len) {
            libc.print("nice: exec line too long\n");
            libc.exit();
        }
        @memcpy(exec_buf[written .. written + arg.len], arg);
        written += arg.len;
    }
    if (written == 0) {
        libc.print("nice: missing program name\n");
        libc.exit();
    }

    // fork → child: set self-nice, then exec. Parent: waitpid for status.
    // Same fork-then-pin-then-exec pattern as taskset; setting nice
    // before exec means the new program lands at the requested nice
    // on its first dispatch (sysExec preserves the PCB slot, so the
    // nice field carries through).
    const r = libc.fork();
    if (r == 0xFFFFFFFF) {
        libc.print("nice: fork failed\n");
        libc.exit();
    }
    if (r == 0) {
        if (libc.sched_setnice(0, value) != 0) {
            libc.print("nice: child sched_setnice failed\n");
            libc.exit();
        }
        // sysExec is posix_spawn-style: spawns a NEW process with parent's
        // nice/pinned_cpu inheritance (kernel handles that), returns the
        // grandchild pid or 0xFFFFFFFF on failure. The child (this nice
        // wrapper) keeps running afterwards and must exit, so the original
        // parent's waitpid returns. Don't wait on the grandchild here —
        // it's now an independent process; the shell isn't waiting for it.
        const ec = libc.exec(exec_buf[0..written]);
        if (ec == 0xFFFFFFFF) {
            libc.print("nice: exec failed (program not found?)\n");
        }
        libc.exit();
    }
    var status: u32 = 0;
    _ = libc.waitpid(r, &status);
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    const argc = libc.getArgc();
    if (argc < 2) usage();

    var arg_buf: [32]u8 = undefined;
    const arg1 = argvCopy(1, &arg_buf) orelse usage();

    // Variant: `nice -p N PID`
    if (arg1.len == 2 and arg1[0] == '-' and arg1[1] == 'p') {
        if (argc < 4) usage();
        var v_buf: [32]u8 = undefined;
        const v_s = argvCopy(2, &v_buf) orelse usage();
        var p_buf: [32]u8 = undefined;
        const p_s = argvCopy(3, &p_buf) orelse usage();
        const value = parseInt(v_s) orelse usage();
        const pid = parseU32(p_s) orelse usage();
        cmdSet(pid, value);
        libc.exit();
    }

    // Variant: `nice PID` (single non-negative numeric arg → print).
    // Distinguish from `nice N prog` by checking argc: if just one arg,
    // treat as PID; if two+ args and arg1 parses as a signed int, treat
    // as nice value + prog name.
    if (argc == 2) {
        // Could be PID-only print, or a nice value alone (no program).
        // Prefer print if it's a non-negative small number (likely a pid).
        const as_pid = parseU32(arg1) orelse {
            // Not a pure positive int — try as nice value, but no prog name
            // means nothing to spawn.
            usage();
        };
        cmdPrint(as_pid);
        libc.exit();
    }

    // Variant: `nice N prog [args...]` (spawn at nice N).
    const value = parseInt(arg1) orelse usage();
    cmdSpawn(value, 2);
    libc.exit();
}
