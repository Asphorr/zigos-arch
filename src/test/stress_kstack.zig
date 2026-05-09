// Kernel-task spawn/exit/reap stress test — kstack UAF hunt.
//
// Activated by booting with menu entry "Stress: kstack churn" (boot_mode=3).
// Replaces the desktop kernel task; instead of starting the GUI, this loop
// spawns trivial kernel tasks that exit immediately and gets them reaped, in
// a tight loop, while cpu1 sits in idle servicing timer IRQs.
//
// Why this exists: the open kstack-pool UAF (memory note "task #267") fires
// when a process is killed and a stale pointer into its now-FREED kstack is
// dereferenced one tick later — we caught it organically once by clicking
// around the desktop. The conditions that reproduce it are racy, so a
// dedicated harness that hammers the spawn/kill/reap cycle is the right tool
// to make the bug *show up on demand*. KASAN's poisoning of freed kstacks is
// the catcher: any deref into FB-tagged memory traps with full forensics.
//
// What we expect, in order of preference:
//
//   1. KASAN trips during the loop → we get a crash autopsy with the offset
//      into kstack_pool[N] and a backtrace of the freer/reader. Enough info
//      to root-cause the stale reference.
//   2. The loop completes without trip → the bug is timing-sensitive in a
//      way this harness doesn't recreate (e.g. needs user-process page
//      faults, GUI updates, etc.). At that point we add the kstack
//      *quarantine* (delay reuse for N ticks) so any future trip is louder.
//   3. The loop hangs / a soft-deadlock fires → also a useful signal; means
//      the spawn-or-reap path has a serialization issue we missed.
//
// Implementation notes:
//   - We yield via kernelSleepMs(0) which is a real reschedule — gives the
//     spawned worker a chance to run + exit before we move on.
//   - reapStaleZombies(0) drops the age threshold to zero so a freshly-exited
//     worker is reaped on this iteration, not 30 s later.
//   - Workers run on whatever CPU the scheduler picks. Using cpu_id=0xFF
//     ("any cpu") lets cpu1 take some of the load if it's idle, which is
//     exactly the race window we care about.
//   - Tasks #267-style stale ptr lives in scheduler/wait-queue/parent-link
//     metadata; cpu1's timer IRQ walks one of those tables and dereferences
//     into the freed slot. We don't try to be clever about reproducing —
//     just churn slots and let the timer IRQ do its thing.

const process = @import("../proc/process.zig");
const debug = @import("../debug/debug.zig");
const serial = @import("../debug/serial.zig");

/// Total spawn/exit/reap cycles to run before declaring the loop complete.
/// 10 000 takes a few seconds at 100 Hz scheduler tick — short enough that
/// you can run it interactively, long enough that any 1-in-1000 race fires.
const ITERATIONS: u32 = 10_000;

/// Worker entry: exit immediately. The whole point is to drop the kstack
/// slot back into the pool as fast as possible. `destroyCurrent` flips the
/// task state to .zombie + does the heavy teardown; the caller side reaps.
fn workerExit() callconv(.c) noreturn {
    process.destroyCurrent();
    // destroyCurrent doesn't return; keep the compiler happy.
    while (true) asm volatile ("hlt");
}

/// Stress-test kernel task entry. Replaces desktop in boot_mode=3.
pub fn taskEntry() callconv(.c) noreturn {
    serial.print("[stress-kstack] starting churn loop ({d} iterations)\n", .{ITERATIONS});
    serial.print("[stress-kstack] each iter = createKernelTask -> yield -> reap\n", .{});
    serial.print("[stress-kstack] cpu1 timer IRQs run concurrently — they're the\n", .{});
    serial.print("[stress-kstack] expected reader of any stale kstack pointer.\n", .{});

    var spawned: u64 = 0;
    var spawn_failures: u64 = 0;

    var i: u32 = 0;
    while (i < ITERATIONS) : (i += 1) {
        // Spawn a one-shot worker. cpu_id=0xFF lets the scheduler pick — we
        // want cpu1 to take some, since the original UAF read fired on cpu1.
        const pid = process.createKernelTask(
            @intFromPtr(&workerExit),
            "kchurn",
            0xFF,
            .normal,
            16 * 1024,
        );
        if (pid == null) {
            // PCB table full — wait for a few zombies to drain.
            spawn_failures += 1;
            _ = process.reapStaleZombies(0);
            process.kernelSleepMs(0);
            continue;
        }
        spawned += 1;

        // Yield so the worker actually runs and self-destroys.
        process.kernelSleepMs(0);
        // Reap aggressively. max_age_ticks=0 means "any zombie is fair game"
        // so we get the slot back into the pool this tick.
        _ = process.reapStaleZombies(0);

        // Verbose every-iter trace so a hang shows the exact iteration we
        // got stuck on. Cheap (one serial print per spawn/exit cycle).
        serial.print(
            "[stress-kstack] iter {d}: spawned={d} fail={d}\n",
            .{ i, spawned, spawn_failures },
        );
    }

    serial.print("[stress-kstack] DONE: {d} iterations, spawned={d}, spawn_fail={d}\n", .{ ITERATIONS, spawned, spawn_failures });
    serial.print("[stress-kstack] no KASAN trip — bug is either fixed,\n", .{});
    serial.print("[stress-kstack] timing-sensitive in a way this harness misses,\n", .{});
    serial.print("[stress-kstack] or in a code path we didn't exercise.\n", .{});
    serial.print("[stress-kstack] Next step: add kstack quarantine (delay reuse).\n", .{});

    // Halt — we replaced the desktop, so there's nothing to fall back to.
    // User can power-cycle the VM. (We don't reboot to avoid wedging the
    // crashloop machinery.)
    while (true) asm volatile ("cli; hlt");
}
