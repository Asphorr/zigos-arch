// WITNESS self-test — boot_mode=13 entry.
//
// Proves the lock-order reversal detector (src/debug/witness.zig) actually
// FIRES, end to end. A clean boot exercises the WITNESS hooks only on the hot
// path (heap/pmm/nvme/gpu), where — by construction — no reversal exists, so
// the warning path is never taken. Silence on a clean boot therefore can't be
// distinguished from a dead detector unless something deliberately drives the
// warning path at least once. This is that something.
//
// It registers THROWAWAY locks (they take the next free class indices and do
// not displace any real lock's coverage; nothing else ever acquires them) and:
//
//   Part 1  acquire A then B          → teaches WITNESS the order  A -> B
//                                        (no warning expected)
//   Part 2  acquire B then A          → reverses it → expect a
//                                        [witness] LOR line
//   Part 3  hold a spinlock, then
//           acquire a mutex           → expect a
//                                        [witness] SLEEP-WITH-SPINLOCK line
//
// Every acquire is uncontended and released immediately, and the Part 3 mutex
// is free so its acquire CAS-wins without sleeping — the WITNESS hook fires
// BEFORE the CAS loop, so the warning is produced with zero risk of an actual
// park-with-spinlock-held wedge. The locks exist only to drive the detector.
//
// Run with boot_mode=13. PASS = both [witness] lines below appear by name:
//   [witness] LOR: acquiring wtest.lock_a while holding wtest.lock_b
//   [witness] SLEEP-WITH-SPINLOCK: acquiring mutex wtest.sleepy ...
// then the box idles so serial.log can be read at leisure.

const serial = @import("../debug/serial.zig");
const spinlock = @import("../proc/spinlock.zig");
const witness = @import("../debug/witness.zig");

// Throwaway lock instances. They get whatever class indices follow the real
// registered locks; the test refers to them by object, never by index, so the
// exact numbering doesn't matter.
var lock_a: spinlock.SpinLock = .{};
var lock_b: spinlock.SpinLock = .{};
var sleep_guard: spinlock.SpinLock = .{};
var sleepy: spinlock.Mutex = .{};

pub fn taskEntry() callconv(.c) noreturn {
    serial.print("\n[wtest] === WITNESS self-test start ===\n", .{});

    if (comptime !witness.enabled) {
        // ReleaseFast/ReleaseSmall: the hooks dead-strip, so there is nothing
        // to prove and no [witness] line can ever appear. Say so and idle.
        serial.print("[wtest] witness disabled in this build (runtime_safety off) — nothing to prove\n", .{});
        idle();
    }

    // Registration appends to the lock registry (the real locks registered at
    // boot are single-threaded; this runs as the first kernel task with no
    // other registrar active, so the append races nothing).
    spinlock.registerLock("wtest.lock_a", &lock_a);
    spinlock.registerLock("wtest.lock_b", &lock_b);
    spinlock.registerLock("wtest.sleep_guard", &sleep_guard);
    spinlock.registerMutex("wtest.sleepy", &sleepy);

    // --- Part 1: teach the order  lock_a -> lock_b (no warning) -----------
    serial.print("[wtest] part 1: A then B — teaches order A->B, expect NO warning\n", .{});
    lock_a.acquire();
    lock_b.acquire();
    lock_b.release();
    lock_a.release();

    // --- Part 2: reverse it -> expect an LOR ------------------------------
    serial.print("[wtest] part 2: B then A — reversal, expect a [witness] LOR line next:\n", .{});
    lock_b.acquire();
    lock_a.acquire(); // <-- WITNESS fires here: A-before-B is known, this reverses it
    lock_a.release();
    lock_b.release();

    // --- Part 3: sleepable lock under a spinlock -> expect a warning ------
    serial.print("[wtest] part 3: mutex while holding spinlock — expect a [witness] SLEEP-WITH-SPINLOCK line next:\n", .{});
    sleep_guard.acquire();
    sleepy.acquire(); // uncontended: returns without sleeping, but the hook still fires
    sleepy.release();
    sleep_guard.release();

    serial.print("[wtest] === triggers done; observed lock-order graph: ===\n", .{});
    witness.dump();
    serial.print("[wtest] PASS = exactly one LOR (wtest.lock_a while holding wtest.lock_b)\n", .{});
    serial.print("[wtest]        + one SLEEP-WITH-SPINLOCK (mutex wtest.sleepy under wtest.sleep_guard)\n", .{});
    serial.print("[wtest] === WITNESS self-test end; idling ===\n", .{});

    idle();
}

fn idle() noreturn {
    while (true) asm volatile ("hlt");
}
