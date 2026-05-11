// ps — print the live process table.
//
// Columns:
//   PID    process slot id (matches what waitpid / kill take)
//   PPID   parent process slot id (0 = kernel-spawned)
//   STATE  unused / ready / running / sleep / zombie
//   PRIO   background / normal / interactive (CFS priority band)
//   NI     nice value (-20..+19; lower = more CPU share within band)
//   CPU    last CPU the process was scheduled on
//   PIN    sched_setaffinity pin (cN if pinned, '-' if unpinned)
//   CPU%   lifetime CPU usage (cpu_ticks / process_uptime_ticks)
//   PF     user-mode page faults handled
//   SYS    total syscalls dispatched
//   RSS    currently resident pages (KB) — peak in parens
//   NAME   program name without the .elf suffix

const libc = @import("libc");

fn stateName(s: u8) []const u8 {
    return switch (s) {
        libc.PROC_STATE_UNUSED => "unused",
        libc.PROC_STATE_READY => "ready",
        libc.PROC_STATE_RUNNING => "running",
        libc.PROC_STATE_SLEEPING => "sleep",
        libc.PROC_STATE_ZOMBIE => "zombie",
        else => "?",
    };
}

fn prioName(p: u8) []const u8 {
    return switch (p) {
        libc.PROC_PRIO_BACKGROUND => "bg",
        libc.PROC_PRIO_NORMAL => "norm",
        libc.PROC_PRIO_INTERACTIVE => "intr",
        else => "?",
    };
}

fn padField(s: []const u8, width: usize) void {
    libc.print(s);
    if (s.len < width) {
        var i: usize = s.len;
        while (i < width) : (i += 1) libc.printChar(' ');
    }
}

fn padSignedNice(nice: i8, width: usize) void {
    var buf: [4]u8 = undefined;
    var len: usize = 0;
    var v: u32 = if (nice < 0) @intCast(@as(i32, -@as(i32, nice))) else @intCast(@as(i32, nice));
    if (nice < 0) {
        buf[0] = '-';
        len = 1;
    } else if (nice > 0) {
        buf[0] = '+';
        len = 1;
    }
    if (v == 0) {
        buf[len] = '0';
        len += 1;
    } else {
        var tmp: [3]u8 = undefined;
        var t: usize = 0;
        while (v > 0) : (t += 1) {
            tmp[t] = '0' + @as(u8, @intCast(v % 10));
            v /= 10;
        }
        var k: usize = 0;
        while (k < t) : (k += 1) {
            buf[len] = tmp[t - 1 - k];
            len += 1;
        }
    }
    if (len < width) {
        var i: usize = len;
        while (i < width) : (i += 1) libc.printChar(' ');
    }
    libc.print(buf[0..len]);
}

fn padPin(pinned_cpu: u8, width: usize) void {
    var buf: [4]u8 = undefined;
    var len: usize = 0;
    if (pinned_cpu == 0xFF) {
        buf[0] = '-';
        len = 1;
    } else {
        buf[0] = 'c';
        len = 1;
        if (pinned_cpu < 10) {
            buf[1] = '0' + pinned_cpu;
            len = 2;
        } else {
            buf[1] = '0' + (pinned_cpu / 10);
            buf[2] = '0' + (pinned_cpu % 10);
            len = 3;
        }
    }
    if (len < width) {
        var i: usize = len;
        while (i < width) : (i += 1) libc.printChar(' ');
    }
    libc.print(buf[0..len]);
}

fn padNum(n: u32, width: usize) void {
    var buf: [12]u8 = undefined;
    var len: usize = 0;
    if (n == 0) {
        buf[0] = '0';
        len = 1;
    } else {
        var v = n;
        var tmp: [10]u8 = undefined;
        var t: usize = 0;
        while (v > 0) : (t += 1) {
            tmp[t] = '0' + @as(u8, @intCast(v % 10));
            v /= 10;
        }
        for (0..t) |j| buf[j] = tmp[t - 1 - j];
        len = t;
    }
    if (len < width) {
        var i: usize = len;
        while (i < width) : (i += 1) libc.printChar(' ');
    }
    libc.print(buf[0..len]);
}

fn padHex(n: u32, width: usize) void {
    var buf: [10]u8 = undefined;
    const hex = "0123456789abcdef";
    var i: usize = 0;
    var leading = true;
    var k: i32 = 7;
    while (k >= 0) : (k -= 1) {
        const nib: u4 = @intCast((n >> @intCast(k * 4)) & 0xF);
        if (nib != 0 or !leading or k == 0) {
            buf[i] = hex[nib];
            i += 1;
            leading = false;
        }
    }
    if (i < width) {
        var j: usize = i;
        while (j < width) : (j += 1) libc.printChar(' ');
    }
    libc.print(buf[0..i]);
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    var procs: [32]libc.ProcInfo = undefined;
    const n = libc.processList(&procs);
    if (n == 0) {
        libc.print("ps: no processes (or syscall failed)\n");
        libc.exit();
    }

    // Snapshot uptime in ticks for CPU% denominator. uptime() returns ms,
    // ticks are ~10 ms apart, so / 10 gives ticks. Matches the kernel's
    // 100 Hz LAPIC tick rate; off by a small constant if the rate ever
    // changes — accuracy isn't critical here, this is a diagnostic display.
    const uptime_ticks: u64 = @max(1, libc.uptime() / 10);

    libc.print("\x1b[1m");
    padField("PID", 4);
    padField("PPID", 5);
    padField("STATE", 8);
    padField("PRIO", 5);
    padField("NI", 4);
    padField("CPU", 4);
    padField("PIN", 4);
    padField("CPU%", 5);
    padField("PF", 6);
    padField("SYS", 7);
    padField("RSS", 12);
    libc.print("NAME\x1b[0m\n");

    for (0..n) |i| {
        const p = procs[i];
        padNum(p.pid, 3);
        libc.printChar(' ');
        padNum(p.parent_pid, 4);
        libc.printChar(' ');

        // State, with color hint by category.
        const color: []const u8 = switch (p.state) {
            libc.PROC_STATE_RUNNING => "\x1b[32m",
            libc.PROC_STATE_READY => "\x1b[36m",
            libc.PROC_STATE_SLEEPING => "\x1b[33m",
            libc.PROC_STATE_ZOMBIE => "\x1b[31m",
            else => "\x1b[2m",
        };
        libc.print(color);
        padField(stateName(p.state), 7);
        libc.print("\x1b[0m ");
        padField(prioName(p.priority), 4);
        libc.printChar(' ');
        padSignedNice(p.nice, 3);
        libc.printChar(' ');
        padNum(p.last_cpu, 3);
        libc.printChar(' ');
        padPin(p.pinned_cpu, 3);
        libc.printChar(' ');

        // CPU% = cpu_ticks / process_uptime_ticks * 100. Process uptime
        // is current uptime minus when the PCB started — we approximate
        // by using the global uptime as upper bound, which is correct
        // for processes that have been alive the whole time and a slight
        // overestimate (i.e., underestimate of %) for late starters. The
        // alternative (do (uptime_ticks - start_tick)) needs another
        // syscall round-trip per process; not worth it for ps.
        const proc_age = if (uptime_ticks > p.start_tick)
            uptime_ticks - p.start_tick
        else
            uptime_ticks;
        const denom: u64 = if (proc_age > 0) proc_age else 1;
        const cpu_pct: u32 = @intCast(@min(@as(u64, 999), p.cpu_ticks * 100 / denom));
        padNum(cpu_pct, 4);
        libc.printChar(' ');
        padNum(p.pf_count, 5);
        libc.printChar(' ');
        // Syscall count can grow large fast — show in K (thousands) once
        // it crosses 10K to keep the column narrow.
        if (p.syscall_count >= 10_000) {
            padNum(@intCast(p.syscall_count / 1000), 5);
            libc.print("K ");
        } else {
            padNum(@intCast(p.syscall_count), 6);
            libc.printChar(' ');
        }
        // RSS in KB (4 KB per page), with peak in parens. Two numbers
        // formatted as "current(peak)" — fits an ~11-char column for
        // typical app sizes (a few hundred KB).
        const rss_kb: u32 = p.current_rss_pages * 4;
        const peak_kb: u32 = p.peak_rss_pages * 4;
        padNum(rss_kb, 4);
        libc.print("(");
        padNum(peak_kb, 4);
        libc.print(") ");

        if (p.name_len > 0 and p.name_len <= 16) {
            libc.print(p.name[0..p.name_len]);
        } else {
            libc.print("?");
        }
        libc.printChar('\n');
    }

    libc.exit();
}
