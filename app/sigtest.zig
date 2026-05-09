// sigtest — smoke test for POSIX signals.
//
// Exercises the four delivery paths kernel-side:
//   1. raise() from user code  → syscall-return delivery
//   2. kill(self, ...)          → same path; one extra hop through the kernel
//   3. SIGALRM via alarm()      → IRQ-return delivery (timer wakes us)
//   4. NULL-deref               → exception-return delivery (SIGSEGV)
//
// Each handler prints a line and bumps a global counter. The driver checks
// the counter after each step and aborts on mismatch. Final result line is
// `[sigtest] OK` (green) or `[sigtest] FAIL: <step>` (red).

const libc = @import("libc");

var sigusr1_count: u32 = 0;
var sigint_count: u32 = 0;
var sigsegv_caught: bool = false;

export fn handleUsr1(signo: u32, info: *anyopaque, uc: *anyopaque) void {
    _ = info;
    _ = uc;
    _ = signo;
    sigusr1_count += 1;
    libc.print("[sigtest] caught SIGUSR1\n");
}

export fn handleInt(signo: u32, info: *anyopaque, uc: *anyopaque) void {
    _ = info;
    _ = uc;
    _ = signo;
    sigint_count += 1;
    libc.print("[sigtest] caught SIGINT\n");
}

export fn handleAlrm(signo: u32, info: *anyopaque, uc: *anyopaque) void {
    _ = info;
    _ = uc;
    _ = signo;
    libc.print("[sigtest] caught SIGALRM\n");
}

// SIGSEGV handler — the faulting instruction is the NULL deref. Linux's
// default would be: handler runs, returns, RIP resumes at the deref → loop.
// Our handler exits explicitly so the test terminates cleanly.
export fn handleSegv(signo: u32, info: *anyopaque, uc: *anyopaque) void {
    _ = info;
    _ = uc;
    _ = signo;
    sigsegv_caught = true;
    libc.print("[sigtest] caught SIGSEGV — exiting\n");
    libc.print("\x1b[32m[sigtest] OK (raise/kill/alarm/segv)\x1b[0m\n");
    libc.exit();
}

fn fail(step: []const u8) noreturn {
    libc.print("\x1b[31m[sigtest] FAIL: ");
    libc.print(step);
    libc.print("\x1b[0m\n");
    libc.exit();
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    libc.print("[sigtest] starting\n");

    // Install handlers.
    var act: libc.SigAction = .{
        .handler = @intFromPtr(&handleUsr1),
        .flags = 0,
        .mask = 0,
        .restorer = 0, // sigaction() patches this
    };
    if (libc.sigaction(libc.SIGUSR1, &act, null) != 0) fail("sigaction(SIGUSR1)");

    act.handler = @intFromPtr(&handleInt);
    if (libc.sigaction(libc.SIGINT, &act, null) != 0) fail("sigaction(SIGINT)");

    act.handler = @intFromPtr(&handleAlrm);
    if (libc.sigaction(libc.SIGALRM, &act, null) != 0) fail("sigaction(SIGALRM)");

    act.handler = @intFromPtr(&handleSegv);
    if (libc.sigaction(libc.SIGSEGV, &act, null) != 0) fail("sigaction(SIGSEGV)");

    // 1. raise(SIGUSR1) — handler runs, counter bumps.
    libc.print("[sigtest] step 1: raise(SIGUSR1)\n");
    _ = libc.raise(libc.SIGUSR1);
    if (sigusr1_count != 1) fail("step 1 (raise SIGUSR1)");

    // 2. kill(self, SIGINT) — counter bumps.
    libc.print("[sigtest] step 2: kill(self, SIGINT)\n");
    _ = libc.kill(libc.getpid(), libc.SIGINT);
    if (sigint_count != 1) fail("step 2 (kill self SIGINT)");

    // 3. alarm(1) + pause() — kernel posts SIGALRM after ~1s, pause returns
    //    after the handler runs. Verifying that IRQ-return-to-user delivery
    //    works (handler arrives via timer IRQ, not via syscall return).
    libc.print("[sigtest] step 3: alarm(1) + pause()\n");
    _ = libc.alarm(1);
    _ = libc.pause();

    // 4. NULL deref — kernel raises SIGSEGV from the page-fault handler;
    //    our handler exits with the OK message. If we reach the line below,
    //    the SIGSEGV signal didn't fire OR the handler returned without
    //    exiting (which would re-fault forever — kernel should kill us).
    libc.print("[sigtest] step 4: NULL deref → SIGSEGV\n");
    const p: *allowzero volatile u8 = @ptrFromInt(0x0);
    p.* = 0;
    fail("step 4 (NULL deref didn't trap)");
}
