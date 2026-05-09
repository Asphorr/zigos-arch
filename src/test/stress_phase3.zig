// Phase-3 cleanup-path stress harness.
//
// Activated by boot_mode=5 ("Stress: Phase 3 cleanup" in the UEFI menu).
// Replaces the desktop kernel task; spawns a user process, kills it,
// reaps it, repeat — driving `destroyAddressSpace`, `freeElfBuf`, and
// the lazy-region cleanup loop in process.zig on every iteration.
//
// Why this exists: Phase 3 dropped PML4[0] in the kernel master, which
// made several formerly-OK low-VA shortcuts blow up:
//   * `destroyAddressSpace` compared user PDPT entries against the
//     kernel master's PDPT[0] for COW detection. After Phase 3 the
//     master PML4[0] is zero; the lookup deref'd `physToVirt(0)` =
//     BIOS data, and a stray bit-51 in there produced a u64 overflow
//     in the next physToVirt → ReleaseSafe panic.
//   * `freeElfBuf` and the lazy_regions cleanup passed the kernel
//     pointer (now a physmap VA) straight to `pmm.freeContiguous`,
//     which expects a phys address. PMM rejected with [pmm] WARNING
//     up front, but the leak was real.
//   * `symbols.zig:loadKernelSymbols` did the same with `freeFrame` on
//     each page of the loaded `KERNEL.SYM` buffer.
//
// All of those are gone now (process.zig + symbols.zig + vmm.zig fixes
// in this session). This harness is the regression catcher: any future
// change that re-introduces a "phys vs physmap-VA" confusion in those
// paths reproduces here within a few seconds.
//
// What we expect, in order of preference:
//
//   1. `[pmm] WARNING: free*` lines during the run → PMM is being
//      handed bad addresses by one of the cleanup paths. Find which
//      caller from the warning message and check its arithmetic.
//   2. KERNEL PANIC during destroyAddressSpace / killProcess →
//      regression in vmm.zig's user-PDPT walk (probably re-introduced
//      kernel master comparison or a similar high-bits-set foot-gun).
//   3. PMM free-count drifts down monotonically → leak: an alloc
//      somewhere in the spawn path isn't being freed on kill. The
//      printout every 32 iters lets us spot the slope.
//   4. Loop completes with stable free-count → all good. The exact
//      value isn't compared (kernel internals fragment differently
//      between iterations), but the trajectory should be flat.
//
// Implementation notes:
//   - We use `iretq_spin.elf` because it's small, exists in the tar,
//     and intentionally never exits. We kill it ourselves; we never
//     wait for it to terminate. That keeps the loop deterministic
//     and exercises the *forced-kill* destroy path (the one that
//     bit us in the original log).
//   - `kernelSleepMs(0)` between spawn and kill yields long enough
//     for the spinner's first lazy fault-in to install at least one
//     PT page. Without it `destroyAddressSpace` walks an empty PDPT
//     and we miss the page-table teardown coverage.
//   - We `reapStaleZombies(0)` after each kill so PCB slots return to
//     `.unused` immediately; otherwise we'd hit MAX_PROCS within a
//     few iterations and start counting spawn failures instead of
//     real cleanup activity.

const std = @import("std");
const process = @import("../proc/process.zig");
const elf_loader = @import("../proc/elf_loader.zig");
const vfs = @import("../fs/vfs.zig");
const pmm = @import("../mm/pmm.zig");
const serial = @import("../debug/serial.zig");

const APP_BIN = "iretq_spin.elf";
const ITERATIONS: u32 = 200;
const REPORT_EVERY: u32 = 32;

pub fn taskEntry() callconv(.c) noreturn {
    const free_at_start = pmm.freeFrameCount();
    serial.print(
        "[stress-phase3] starting cleanup-path stress: {d} spawn/kill/reap iters\n",
        .{ITERATIONS},
    );
    serial.print(
        "[stress-phase3] target = {s}, pmm_free at start = {d} pages ({d} MB)\n",
        .{ APP_BIN, free_at_start, free_at_start / 256 },
    );

    var spawned: u64 = 0;
    var spawn_failures: u64 = 0;
    var killed: u64 = 0;
    var lowest_free: u32 = free_at_start;

    var iter: u32 = 0;
    while (iter < ITERATIONS) : (iter += 1) {
        // --- Spawn: pulls vfs.loadFileFresh + elf_loader.loadAndStart.
        // loadAndStart on success transfers ownership of `fresh.buf` to
        // the new PCB's `elf_buf` field. On failure it frees internally,
        // so we never call freePmmRange ourselves.
        const fresh = vfs.loadFileFresh(APP_BIN) orelse {
            spawn_failures += 1;
            // Drain zombies and back off — without this, MAX_PROCS-full
            // wedges the loop.
            _ = process.reapStaleZombies(0);
            process.kernelSleepMs(0);
            continue;
        };
        const pid_or_null = elf_loader.loadAndStart(fresh.buf, fresh.size, fresh.pages);
        if (pid_or_null == null) {
            spawn_failures += 1;
            _ = process.reapStaleZombies(0);
            process.kernelSleepMs(0);
            continue;
        }
        const pid: u8 = @intCast(pid_or_null.?);
        spawned += 1;

        // --- Yield: let the spinner take one timer IRQ + take its
        // entry-point lazy fault. Without this, destroyAddressSpace
        // sees an empty PDPT and we don't exercise the PT teardown.
        process.kernelSleepMs(0);

        // --- Kill: drives killProcessWithStatus → destroyAddressSpace
        // → freeElfBuf → lazy_regions cleanup. This is the path that
        // panicked before the Phase 3 follow-up fixes landed.
        process.killProcess(pid);
        killed += 1;

        // --- Reap: returns the PCB slot to .unused, frees kstack
        // poisoning hooks, decrements active counters.
        _ = process.reapStaleZombies(0);

        // Periodic free-frame snapshot. On a leak this trends downward;
        // on a clean cycle it bounces around a small steady-state.
        if ((iter % REPORT_EVERY) == 0) {
            const free_now = pmm.freeFrameCount();
            if (free_now < lowest_free) lowest_free = free_now;
            serial.print(
                "[stress-phase3] iter {d}/{d}: spawn={d} kill={d} fail={d} pmm_free={d}\n",
                .{ iter, ITERATIONS, spawned, killed, spawn_failures, free_now },
            );
        }
    }

    const free_at_end = pmm.freeFrameCount();
    const drift: i32 = @as(i32, @intCast(free_at_end)) - @as(i32, @intCast(free_at_start));
    serial.print(
        "[stress-phase3] DONE: {d} iters, spawned={d} killed={d} fail={d}\n",
        .{ ITERATIONS, spawned, killed, spawn_failures },
    );
    serial.print(
        "[stress-phase3] pmm_free start={d} end={d} drift={d} lowest={d} pages\n",
        .{ free_at_start, free_at_end, drift, lowest_free },
    );
    if (drift < -16) {
        serial.print(
            "[stress-phase3] WARN: free-frame count dropped by {d} pages — possible leak\n",
            .{-drift},
        );
    } else {
        serial.print("[stress-phase3] OK: no panic, no PMM warning, drift within tolerance\n", .{});
    }

    // Halt — we replaced the desktop, so there's nothing to fall back to.
    while (true) asm volatile ("cli; hlt");
}
