// threadtest — smoke test for sysClone / sysFutex / sysSetTls.
//
// Spawns 4 worker threads. Each worker increments a shared `counter`
// 10000 times under a mutex, then returns. The parent joins all 4 and
// verifies the final value is 4 * 10000 = 40000. A correct value proves:
//   - sysClone built a usable trap frame and the new thread reached
//     start_routine
//   - the child's CR3 is shared with the parent (counter is observed)
//   - the futex-mutex serialises the increments (no torn updates)
//   - pthread_join wakes when the worker sets `done`
//   - the new thread's TLS / fs_base was set up by the trampoline
//
// On success: prints `[threadtest] OK total=40000`. Mismatch -> red.

const std = @import("std");
const libc = @import("libc");

const ITERS: u32 = 10000;
const N_THREADS: u32 = 4;

var mu: libc.Mutex = .{};
var counter: u32 = 0;

fn worker(arg: ?*anyopaque) callconv(.c) ?*anyopaque {
    _ = arg;
    var i: u32 = 0;
    while (i < ITERS) : (i += 1) {
        mu.lock();
        counter += 1;
        mu.unlock();
    }
    return null;
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    libc.print("[threadtest] spawning workers\n");

    var tcbs: [N_THREADS]?*libc.Tcb = .{null} ** N_THREADS;
    var i: u32 = 0;
    while (i < N_THREADS) : (i += 1) {
        tcbs[i] = libc.pthreadCreate(worker, null);
        if (tcbs[i] == null) {
            libc.print("\x1b[31m[threadtest] pthreadCreate failed\x1b[0m\n");
            libc.exit();
        }
    }

    i = 0;
    while (i < N_THREADS) : (i += 1) {
        if (tcbs[i]) |tcb| _ = libc.pthreadJoin(tcb);
    }

    var buf: [64]u8 = undefined;
    if (counter == ITERS * N_THREADS) {
        const out = std.fmt.bufPrint(&buf, "[threadtest] OK total={d}\n", .{counter}) catch "OK\n";
        libc.print(out);
        libc.klog(out); // mirror to serial so we can confirm print fired
    } else {
        const out = std.fmt.bufPrint(&buf, "\x1b[31m[threadtest] FAIL total={d} expected={d}\x1b[0m\n", .{ counter, ITERS * N_THREADS }) catch "FAIL\n";
        libc.print(out);
        libc.klog(out);
    }

    libc.exit();
}
