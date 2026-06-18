// stoptest — end-to-end test for POSIX job control (SIGSTOP / SIGCONT).
//
// Wires the previously-no-op stop/cont default actions. A child spins a counter
// in a MAP_SHARED|ANON page (survives fork as truly-shared memory); the parent
// drives the child through the job-control state machine and asserts the shared
// counter behaves:
//
//   1. running   — counter advances after fork.
//   2. SIGSTOP   — counter FREEZES (child off-CPU; pickNext skips it).
//   3. SIGCONT   — counter advances again (child resumed).
//   4. SIGSTOP   — freezes again.
//   5. SIGKILL while stopped — child is reaped (a stopped task must still be
//      killable: send() un-stops it so it can run far enough to die).
//
// On success: green `[stoptest] OK` to stdout + klog. On failure: a red message
// naming the step, also klog'd, so serial.log localizes the regression.

const libc = @import("libc");

// Tunables. Settle waits must exceed (child usleep period + one ~10ms scheduler
// tick + stop-delivery latency); 80ms is generous. Observe windows are long
// enough that a running child clearly advances the counter.
const SPIN_US: u32 = 2000; // child increments every ~2ms
const SETTLE_MS: u32 = 80; // wait for a stop to take hold
const OBSERVE_MS: u32 = 160; // window over which a running child advances

fn fail(step: []const u8) noreturn {
    libc.print("\x1b[31m[stoptest] FAIL: ");
    libc.print(step);
    libc.print("\x1b[0m\n");
    libc.klog("[stoptest] FAIL\n");
    libc.exitWith(0xDEAD0001);
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    libc.print("[stoptest] starting: SIGSTOP/SIGCONT job control\n");

    // Shared counter — one page, truly shared across fork (POSIX MAP_SHARED|ANON).
    const shared = libc.mmapSharedAnon(4096) orelse fail("mmapSharedAnon");
    const counter: *volatile u32 = @ptrCast(@alignCast(shared.ptr));
    counter.* = 0;

    const child = libc.fork();
    if (child == 0xFFFFFFFA) fail("fork EAGAIN");

    if (child == 0) {
        // Child: increment the shared counter forever, sleeping briefly each
        // iteration so (a) it's gentle on the CPU and (b) it hits a syscall
        // return — a signal-delivery point — every ~2ms, bounding stop latency.
        // The parent ends our life with SIGKILL.
        while (true) {
            counter.* +%= 1;
            libc.usleep(SPIN_US);
        }
        libc.exitWith(0); // unreachable; defensive
    }

    // Parent.
    // 1. Confirm the child is running (counter advances).
    libc.sleep(OBSERVE_MS);
    const c1 = counter.*;
    if (c1 == 0) fail("child never advanced counter (not running?)");
    libc.print("[stoptest]  step1 ok: child running, counter advancing\n");

    // 2. SIGSTOP → counter must freeze.
    if (libc.kill(child, libc.SIGSTOP) != 0) fail("kill(SIGSTOP)");
    libc.sleep(SETTLE_MS);
    const c2 = counter.*; // sampled once the stop has taken hold
    libc.sleep(OBSERVE_MS);
    const c3 = counter.*;
    if (c3 != c2) fail("counter advanced while STOPPED (stop didn't freeze)");
    libc.print("[stoptest]  step2 ok: SIGSTOP froze the child\n");

    // 3. SIGCONT → counter must advance again.
    if (libc.kill(child, libc.SIGCONT) != 0) fail("kill(SIGCONT)");
    libc.sleep(OBSERVE_MS);
    const c4 = counter.*;
    if (c4 == c3) fail("counter still frozen after SIGCONT (no resume)");
    libc.print("[stoptest]  step3 ok: SIGCONT resumed the child\n");

    // 4. SIGSTOP again → freezes again (re-stop after a continue).
    if (libc.kill(child, libc.SIGSTOP) != 0) fail("kill(SIGSTOP) #2");
    libc.sleep(SETTLE_MS);
    const c5 = counter.*;
    libc.sleep(OBSERVE_MS);
    const c6 = counter.*;
    if (c6 != c5) fail("re-STOP did not freeze the child");
    libc.print("[stoptest]  step4 ok: child re-stopped\n");

    // 5. SIGKILL while stopped → child must be reaped. Proves send() un-stops a
    //    stopped target so it can run to its death (otherwise unkillable).
    if (libc.kill(child, libc.SIGKILL) != 0) fail("kill(SIGKILL)");
    var st: u32 = 0;
    const reaped = libc.waitpid(child, &st);
    if (reaped != child) fail("waitpid did not reap the killed (stopped) child");
    if ((st & 0xFF) != libc.SIGKILL) fail("reaped child status not SIGKILL");
    libc.print("[stoptest]  step5 ok: SIGKILL reaped the stopped child\n");

    libc.print("\x1b[32m[stoptest] OK (stop freeze / cont resume / re-stop / kill-while-stopped)\x1b[0m\n");
    libc.klog("[stoptest] OK\n");
    libc.exitWith(0xCAFE0043);
}
