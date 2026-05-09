// Smoke + isolation test for setsid/setpgid + libc.daemon().
//
// Three scenarios:
//   1. setpgid(0, 0) in a fork'd child — child's pgid changes to its own pid;
//      parent's pgid stays put. Verifies setpgid + non-aliasing of PCB fields.
//   2. setsid() in a fork'd child — child's sid AND pgid both flip to its
//      own pid. Verifies setsid + the pgid==self_pid side-effect.
//   3. daemon(true, true) — full double-fork+setsid path. We can't waitpid on
//      the grandchild (it's reparented to PID 1 by then), so this scenario
//      prints diagnostic markers to serial: the parent must see "[daemontest]
//      d1 ok", "[daemontest] d2 ok", and the grandchild's "[daemontest] dgc
//      pid=N sid=N pgid=N" — sid and pgid should both equal the grandchild's
//      pid, AND should be different from the original parent's session.
//
// Auto-launched from boot menu / shell. "[daemontest] OK" appears on success.

const libc = @import("libc");

fn printVal(label: []const u8, v: u32) void {
    libc.print(label);
    libc.printNum(v);
    libc.print("\n");
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    libc.print("[daemontest] starting\n");
    const my_pid = libc.getpid();
    const my_pgid0 = libc.getpgrp();
    const my_sid0 = libc.getsid(0);
    printVal("[daemontest] parent pid=", my_pid);
    printVal("[daemontest] parent pgid=", my_pgid0);
    printVal("[daemontest] parent sid=", my_sid0);

    // --- Scenario 1: setpgid(0, 0) in child ---
    const r1 = libc.fork();
    if (r1 == 0xFFFFFFFF or r1 == 0xFFFFFFFA) {
        libc.print("[daemontest] FAIL s1: fork\n");
        libc.exitWith(0xDEAD0001);
    }
    if (r1 == 0) {
        const inherited_pgid = libc.getpgrp();
        const inherited_sid = libc.getsid(0);
        if (inherited_pgid != my_pgid0) libc.exitWith(0xDEAD0002);
        if (inherited_sid != my_sid0) libc.exitWith(0xDEAD0003);
        // Move into a fresh group named after self.
        const rc = libc.setpgid(0, 0);
        if (rc != 0) libc.exitWith(0xDEAD0004);
        const child_pid = libc.getpid();
        if (libc.getpgrp() != child_pid) libc.exitWith(0xDEAD0005);
        // sid must NOT have changed — only setsid touches sid.
        if (libc.getsid(0) != my_sid0) libc.exitWith(0xDEAD0006);
        libc.exitWith(0x42);
    }
    {
        var st: u32 = 0;
        _ = libc.waitpid(r1, &st);
        if ((st & 0xFF) != 0x42) {
            libc.print("[daemontest] FAIL s1: child status\n");
            libc.exitWith(0xDEAD0007);
        }
        // Parent's pgid must NOT have been affected by child's setpgid.
        if (libc.getpgrp() != my_pgid0) {
            libc.print("[daemontest] FAIL s1: parent pgid bled\n");
            libc.exitWith(0xDEAD0008);
        }
        libc.print("[daemontest] s1 OK (setpgid)\n");
    }

    // --- Scenario 2: setsid in child ---
    const r2 = libc.fork();
    if (r2 == 0xFFFFFFFF or r2 == 0xFFFFFFFA) {
        libc.print("[daemontest] FAIL s2: fork\n");
        libc.exitWith(0xDEAD0011);
    }
    if (r2 == 0) {
        const new_sid = libc.setsid();
        const child_pid = libc.getpid();
        if (new_sid != child_pid) libc.exitWith(0xDEAD0012);
        if (libc.getsid(0) != child_pid) libc.exitWith(0xDEAD0013);
        if (libc.getpgrp() != child_pid) libc.exitWith(0xDEAD0014);
        libc.exitWith(0x55);
    }
    {
        var st: u32 = 0;
        _ = libc.waitpid(r2, &st);
        if ((st & 0xFF) != 0x55) {
            libc.print("[daemontest] FAIL s2: child status\n");
            libc.exitWith(0xDEAD0015);
        }
        if (libc.getsid(0) != my_sid0) {
            libc.print("[daemontest] FAIL s2: parent sid bled\n");
            libc.exitWith(0xDEAD0016);
        }
        libc.print("[daemontest] s2 OK (setsid)\n");
    }

    // --- Scenario 3: full daemon() double-fork ---
    // We fork once so the test parent can waitpid on the immediate child
    // (which becomes daemon()'s first parent and exits cleanly). The
    // grandchild detaches; we can only verify it ran by checking serial.
    const r3 = libc.fork();
    if (r3 == 0xFFFFFFFF or r3 == 0xFFFFFFFA) {
        libc.print("[daemontest] FAIL s3: fork\n");
        libc.exitWith(0xDEAD0021);
    }
    if (r3 == 0) {
        // Inside the daemon() call:
        //   - first fork parent exits(0)
        //   - middle child setsid + second fork; middle exits(0)
        //   - grandchild returns from daemon()
        const drc = libc.daemon(true, true);
        if (drc != 0) libc.exitWith(0xDEAD0022);
        // If we're here we're the detached grandchild. POSIX double-fork
        // semantics: the grandchild is NOT a session leader (its sid was
        // inherited from the middle child AFTER the middle child's setsid,
        // so sid == middle_child.pid != gc_pid). This is intentional —
        // a non-leader can never reacquire a controlling terminal.
        const gc_pid = libc.getpid();
        const gc_sid = libc.getsid(0);
        const gc_pgid = libc.getpgrp();
        printVal("[daemontest] dgc pid=", gc_pid);
        printVal("[daemontest] dgc sid=", gc_sid);
        printVal("[daemontest] dgc pgid=", gc_pgid);
        // Grandchild MUST be in a new session (escaped parent's session).
        if (gc_sid == my_sid0) libc.exitWith(0xDEAD0023);
        // Grandchild MUST NOT be a session leader — that's the whole point
        // of the second fork.
        if (gc_sid == gc_pid) libc.exitWith(0xDEAD0024);
        // Grandchild's pgid must equal sid (both inherited from the middle
        // child's post-setsid state, which made sid == pgid == middle.pid).
        if (gc_pgid != gc_sid) libc.exitWith(0xDEAD0025);
        libc.exitWith(0xD0CAFE);
    }
    {
        var st: u32 = 0;
        _ = libc.waitpid(r3, &st);
        // The immediate child is daemon()'s first-fork parent — it exits 0.
        if ((st & 0xFF) != 0) {
            libc.print("[daemontest] FAIL s3: immediate child status\n");
            libc.exitWith(0xDEAD0026);
        }
        libc.print("[daemontest] s3 immediate OK; check serial for [daemontest] dgc lines and 0xD0CAFE destroy\n");
    }

    libc.print("[daemontest] OK\n");
    libc.exitWith(0xCAFE0044);
}
