// switchTo+0x0 cr2=0x46 race harness — async-launch repro path.
//
// Activated by booting with menu entry "Stress: async exec race" (boot_mode=8).
// Targets the wild kernel RIP=0x46 page-fault that fired when files.elf
// launched editor.elf via the desktop shortcut mechanism, with rapid task
// migration cpu0→cpu1→cpu0.
//
// Why this and not stress_kill_race or stress_iretq:
//
//   * stress_kill_race v3 spawns + immediately kills via direct
//     `loadAndStart` — caller is in kernel context already, no async
//     queue, no CR3 dance.
//   * stress_iretq spawns ring-3 spinners but also via direct
//     loadAndStart, then drives kchurn.
//   * The crashing path was: desktop shortcut click →
//     `smp.requestAppLoad("editor.elf")` → AP idle drains queue, runs
//     `vfs.loadFileFresh` on its own CR3 → BSP `pollAppLoad` switches
//     to kernel CR3, calls `loadAndStart`, restores caller CR3. The
//     spawned PID then migrates between cpu0 and cpu1 picking up timer
//     IRQs. Somewhere in there, switchTo's retq pops 0x46.
//
// Strategy: combine all four signal generators on one workload —
//
//   1. Async launches via requestAppLoad (drives the AP-load CR3 dance
//      that the killing trace had on the call stack).
//   2. Poll-loop in this kernel task that mirrors the desktop main
//      loop's pollAppLoad cadence (drives the BSP-create path).
//   3. Active set of N spinner pids that take real timer IRQs and
//      migrate (drives switchTo dispatches across cpu0↔cpu1).
//   4. Periodic kill of the oldest active pid + immediate respawn
//      (recycles kstack slots while peers are mid-dispatch).
//
// Expected outcome: within a few hundred iterations either we trip the
// schedule() pre-load `BAD next_kesp` panic (kstack out of slot, the
// cross-stack-aliasing root) or we get the wild-RIP autopsy from kdbg.
// If neither: the race may need user-mode timing specifically — try a
// chainexec.elf victim or move the harness into a real user app.

const std = @import("std");
const process = @import("../proc/process.zig");
const elf_loader = @import("../proc/elf_loader.zig");
const vfs = @import("../fs/vfs.zig");
const smp = @import("../cpu/smp.zig");
const serial = @import("../debug/serial.zig");
const debug = @import("../debug/debug.zig");

// Tunables. ITERATIONS chosen for a few-minute run; raise if the race
// doesn't surface. ACTIVE_TARGET keeps roughly that many spinners alive
// at once — enough to keep both CPUs busy without filling MAX_PROCS.
const ITERATIONS: u32 = 4_000;
const ACTIVE_TARGET: u32 = 6;
const VICTIM_BIN: []const u8 = "iretq_spin.elf";

// Bounded poll budget per requestAppLoad — pollAppLoad returns null
// until the AP has finished disk I/O. ~200 ms at 100 Hz is plenty for
// a 16 KB ELF; if we time out, the request is stuck (probably the AP
// idle is lost on a different harness path) and we abort.
const POLL_BUDGET_TICKS: u32 = 20;

var active: [ACTIVE_TARGET]u8 = [_]u8{0xFF} ** ACTIVE_TARGET;
var rotor: u32 = 0;

/// Issue one async load, poll until BSP creates the process, return its pid.
/// Returns null if the request couldn't be queued (already in flight) or
/// the load failed mid-air.
fn asyncSpawn() ?u8 {
    if (!smp.requestAppLoad(VICTIM_BIN)) {
        // Another in-flight request — bail; caller retries next iter.
        return null;
    }
    // Mimic the desktop main loop: yield, poll, repeat. The AP idle
    // drains the queue while we sleep; BSP picks up the loaded buffer
    // when we call pollAppLoad and turns it into a PCB.
    var ticks: u32 = 0;
    while (ticks < POLL_BUDGET_TICKS) : (ticks += 1) {
        process.kernelSleepMs(10);
        if (smp.pollAppLoad()) |pid| return @intCast(pid);
    }
    return null;
}

pub fn taskEntry() callconv(.c) noreturn {
    serial.print("[stress-asx] hunting switchTo+0x0 cr2=0x46 race via async exec\n", .{});
    serial.print(
        "[stress-asx] iterations={d}, active_target={d}, victim={s}\n",
        .{ ITERATIONS, ACTIVE_TARGET, VICTIM_BIN },
    );

    // Switch to kernel CR3 — defensive, like stress_kill_race v3 does.
    // Without this, if our boot dispatch left us on a page directory
    // that doesn't fully cover all of kernel, the first internal
    // `loadAndStart` walk could fault.
    const vmm = @import("../mm/vmm.zig");
    const paging = @import("../mm/paging.zig");
    vmm.switchAddressSpace(paging.getKernelPageDirPhys());

    var spawned: u64 = 0;
    var kills: u64 = 0;
    var spawn_fails: u64 = 0;
    var poll_timeouts: u64 = 0;

    var iter: u32 = 0;
    while (iter < ITERATIONS) : (iter += 1) {
        // Slot-rotor: kill whatever's in this slot, then refill.
        const slot = rotor % ACTIVE_TARGET;
        rotor +%= 1;

        if (active[slot] != 0xFF) {
            const old = active[slot];
            // The victim may already be a zombie (self-exited from a
            // crash, or reaped by the auto-orphan path). killProcess
            // is a no-op on .unused / .zombie, so this is safe.
            process.killProcess(old);
            kills += 1;
            active[slot] = 0xFF;
        }

        // Always reap stale zombies first — keeps the PCB table from
        // filling with corpses while a parent (us) ignores them.
        _ = process.reapStaleZombies(0);

        if (asyncSpawn()) |pid| {
            active[slot] = pid;
            // Promote to interactive — same priority desktop sets on
            // freshly launched apps so the new PID is preferentially
            // picked by both CPUs (= more migration pressure).
            process.getPCB(pid).priority = .interactive;
            process.setName(pid, "asxv");
            spawned += 1;
        } else {
            spawn_fails += 1;
            // If pollAppLoad timed out vs requestAppLoad refused, we
            // can't tell from here — distinguish via a separate counter
            // by checking the load_req state, but cheap to just count
            // both as "fail" for now.
            poll_timeouts += 1;
        }

        // Yield once per iter so we don't monopolize cpu0. Without
        // this, the harness would starve the per-CPU idle on cpu0,
        // pollAppLoad never sees the loaded state (because BSP runs
        // pollAppLoad inside *us*, not on idle), and async spawns
        // never complete past the first one.
        process.kernelSleepMs(0);

        if ((iter % 64) == 0) {
            const live = countLive();
            serial.print(
                "[stress-asx] iter {d}/{d}: spawned={d} kills={d} fails={d} timeouts={d} live={d}\n",
                .{ iter, ITERATIONS, spawned, kills, spawn_fails, poll_timeouts, live },
            );
        }
    }

    // Final cleanup so the next run (if any) starts with an empty
    // active set. Not strictly required — we're about to halt — but
    // useful when running several harness modes back-to-back.
    for (&active) |*pid| {
        if (pid.* != 0xFF) {
            process.killProcess(pid.*);
            pid.* = 0xFF;
        }
    }
    _ = process.reapStaleZombies(0);

    serial.print(
        "[stress-asx] DONE: {d} iters, spawned={d}, kills={d}, fails={d}\n",
        .{ ITERATIONS, spawned, kills, spawn_fails },
    );
    serial.print("[stress-asx] no panic — race not surfaced this run.\n", .{});
    serial.print("[stress-asx] Next moves if it stays silent:\n", .{});
    serial.print("[stress-asx]   * raise ITERATIONS or ACTIVE_TARGET (more contention)\n", .{});
    serial.print("[stress-asx]   * try a chainexec.elf victim (user-mode driver)\n", .{});
    serial.print("[stress-asx]   * boot under SMP=2 vs 4 — ratio of pickers matters\n", .{});

    while (true) asm volatile ("cli; hlt");
}

fn countLive() u32 {
    var n: u32 = 0;
    for (active) |pid| {
        if (pid != 0xFF) n += 1;
    }
    return n;
}
