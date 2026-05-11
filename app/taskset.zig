// taskset — pin a process or command to a specific CPU.
//
// Usage:
//   taskset CPU prog [args...]   spawn `prog args...` pinned to CPU
//   taskset -p CPU PID           pin running PID to CPU
//   taskset -u PID               unpin PID (load balancer regains discretion)
//   taskset PID                  print PID's current affinity
//
// CPU is a 0-based integer (0..MAX_CPUS-1). Self-affinity is pid==0.
// The kernel only allows operating on threads sharing your tgid (pthread-
// style permission), so spawn-mode is the natural way to pin another
// process — fork-then-pin-self-then-exec.

const libc = @import("libc");

fn parseU32(s: []const u8) ?u32 {
    if (s.len == 0) return null;
    var v: u32 = 0;
    for (s) |c| {
        if (c < '0' or c > '9') return null;
        v = v *% 10 +% @as(u32, c - '0');
    }
    return v;
}

fn printU32(n: u32) void {
    libc.printNum(n);
}

fn argvCopy(idx: u32, buf: []u8) ?[]const u8 {
    const n = libc.getArgv(idx, buf);
    if (n == 0xFFFFFFFF or n == 0) return null;
    if (n > buf.len) return null;
    return buf[0..n];
}

fn usage() noreturn {
    libc.print(
        \\usage:
        \\  taskset CPU prog [args...]   spawn pinned to CPU
        \\  taskset -p CPU PID           pin PID to CPU
        \\  taskset -u PID               unpin PID
        \\  taskset PID                  print PID's affinity
        \\
    );
    libc.exit();
}

fn cmdPrint(pid: u32) void {
    const r = libc.sched_getaffinity(pid);
    if (r == -2) {
        libc.print("taskset: error reading affinity (bad pid or different tgid)\n");
        libc.exit();
    }
    libc.print("pid ");
    printU32(pid);
    if (r == libc.AFFINITY_UNPINNED) {
        libc.print(" unpinned\n");
    } else {
        libc.print(" pinned to cpu ");
        printU32(@intCast(r));
        libc.printChar('\n');
    }
}

fn cmdPin(pid: u32, cpu: i32) void {
    if (libc.sched_setaffinity(pid, cpu) != 0) {
        libc.print("taskset: sched_setaffinity failed (E_INVAL or E_PERM — only own-tgid threads)\n");
        libc.exit();
    }
    if (cpu < 0) {
        libc.print("pid ");
        printU32(pid);
        libc.print(" unpinned\n");
    } else {
        libc.print("pid ");
        printU32(pid);
        libc.print(" -> cpu ");
        printU32(@intCast(cpu));
        libc.printChar('\n');
    }
}

fn cmdSpawn(cpu: i32, prog_argv_start: u32) void {
    // Build the exec string: "prog arg1 arg2 ...".
    // libc.exec takes a single space-separated string; the kernel parses
    // it into argv slots. Our buffer is sized for typical "cmd a b c".
    var exec_buf: [256]u8 = undefined;
    var written: usize = 0;

    const argc = libc.getArgc();
    var idx: u32 = prog_argv_start;
    var arg_buf: [32]u8 = undefined;
    while (idx < argc) : (idx += 1) {
        const arg = argvCopy(idx, &arg_buf) orelse break;
        if (idx > prog_argv_start) {
            if (written + 1 > exec_buf.len) {
                libc.print("taskset: exec line too long\n");
                libc.exit();
            }
            exec_buf[written] = ' ';
            written += 1;
        }
        if (written + arg.len > exec_buf.len) {
            libc.print("taskset: exec line too long\n");
            libc.exit();
        }
        @memcpy(exec_buf[written .. written + arg.len], arg);
        written += arg.len;
    }
    if (written == 0) {
        libc.print("taskset: missing program name\n");
        libc.exit();
    }

    // fork → child: pin self, then exec. Parent: waitpid for child status.
    const r = libc.fork();
    if (r == 0xFFFFFFFF) {
        libc.print("taskset: fork failed\n");
        libc.exit();
    }
    if (r == 0) {
        // Child — pin self to the requested CPU, then exec. sysExec is
        // posix_spawn-style: the kernel inherits our pinned_cpu into the
        // new program's PCB (handled in sysExec), so by setting affinity
        // on self BEFORE exec, the spawned program lands on the right
        // CPU. After exec returns we exit so the shell's waitpid on this
        // wrapper returns; the spawned grandchild runs independently.
        if (libc.sched_setaffinity(0, cpu) != 0) {
            libc.print("taskset: child sched_setaffinity failed\n");
            libc.exit();
        }
        const ec = libc.exec(exec_buf[0..written]);
        if (ec == 0xFFFFFFFF) {
            libc.print("taskset: exec failed (program not found?)\n");
        }
        libc.exit();
    }
    // Parent — wait for child so the shell sees the right exit status.
    var status: u32 = 0;
    _ = libc.waitpid(r, &status);
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    const argc = libc.getArgc();
    if (argc < 2) usage();

    var arg_buf: [32]u8 = undefined;

    const arg1 = argvCopy(1, &arg_buf) orelse usage();

    // Variant: `taskset -u PID`
    if (arg1.len == 2 and arg1[0] == '-' and arg1[1] == 'u') {
        if (argc < 3) usage();
        var pid_buf: [32]u8 = undefined;
        const pid_s = argvCopy(2, &pid_buf) orelse usage();
        const pid = parseU32(pid_s) orelse usage();
        cmdPin(pid, libc.AFFINITY_UNPINNED);
        libc.exit();
    }

    // Variant: `taskset -p CPU PID`
    if (arg1.len == 2 and arg1[0] == '-' and arg1[1] == 'p') {
        if (argc < 4) usage();
        var cpu_buf: [32]u8 = undefined;
        const cpu_s = argvCopy(2, &cpu_buf) orelse usage();
        var pid_buf: [32]u8 = undefined;
        const pid_s = argvCopy(3, &pid_buf) orelse usage();
        const cpu = parseU32(cpu_s) orelse usage();
        const pid = parseU32(pid_s) orelse usage();
        cmdPin(pid, @intCast(cpu));
        libc.exit();
    }

    // Variant: `taskset PID` (single numeric arg, print)
    if (argc == 2) {
        const pid = parseU32(arg1) orelse usage();
        cmdPrint(pid);
        libc.exit();
    }

    // Variant: `taskset CPU prog [args...]` (spawn pinned)
    const cpu = parseU32(arg1) orelse usage();
    cmdSpawn(@intCast(cpu), 2);
    libc.exit();
}
