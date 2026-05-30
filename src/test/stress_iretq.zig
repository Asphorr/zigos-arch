// Cross-CPU iretq-frame race stress harness.
//
// Activated by booting with menu entry "Stress: iretq race" (boot_mode=4).
// Replaces the desktop kernel task; instead of starting the GUI, this loop
// spawns ring-3 spinners (iretq_spin.elf) and rapidly churns kernel tasks
// + respawns user processes to drive cross-CPU schedule activity.
//
// Why this exists: memory note `project_iretq_race_ipi_fix.md` documents
// the wild-iretq cascade that fires after ~5 paint clicks. Setting
// iretq_canary.DR_WATCHPOINT=true broadcasts an IPI on every Ring-3 IRQ
// entry/exit, which incidentally suppresses the race via cross-CPU sync —
// "working fix, not root-cause fix." With DR_WATCHPOINT=false, the bug
// reproduces in seconds of paint clicking. The desktop+paint workload is
// awkward to drive in a loop, so this harness reproduces the same essential
// shape *without* the GUI:
//
//   - N CPU-busy ring-3 processes take many timer IRQs across CPUs
//   - Each spinner sleeps 1 ms / iteration → exercises wake-from-sleep,
//     the path the original repro hit (shell waking on click events)
//   - Kernel-task spawn/exit churn forces schedule() through the picker
//   - Periodic kill + respawn rotates kstack slots while peers run
//
// What we expect, in order of preference:
//
//   1. Wild-iretq panic / kdbg autopsy → race surfaces, we get the
//      handleIRQ0 RIP and corrupted iretq frame.
//   2. KASAN trip → some adjacent UAF/aliasing that the kstack churn
//      uncovered (already fixed once, but worth catching regressions).
//   3. Loop completes → bug is not in this exact workload. Either the
//      DR-rotating kernel_esp watchpoints (C.1, see main.zig) provide
//      enough sync to suppress, or the race needs paint's specific
//      window-update + cursor-redraw timing. Next move: re-enable
//      DR_WATCHPOINT for a control run, then disable C.1's rotation
//      and re-run.
//
// Implementation notes:
//   - cpu_id=0xFF on createKernelTask lets the scheduler pick — we want
//     both CPUs taking part in the dispatch dance.
//   - kernelSleepMs(0) is a real reschedule (sets state=.sleeping with
//     wake_tick=now). The scheduler picks the spinners up; they take
//     their timer IRQs; eventually they hit libc.sleep(1) and we get
//     control back via reap-and-respawn.
//   - reapStaleZombies(0) drains workers/dead spinners on the same tick.
//   - We don't `enableUserMode` ourselves — `loadAndStart` builds the
//     iretq frame for the spinner, scheduler dispatches it normally.

const std = @import("std");
const process = @import("../proc/process.zig");
const elf_loader = @import("../proc/elf_loader.zig");
const vfs = @import("../fs/vfs.zig");
const iretq_canary = @import("../debug/iretq_canary.zig");
const serial = @import("../debug/serial.zig");

const SPINNERS: u32 = 6;
const ITERATIONS: u32 = 5_000;
const RESPAWN_EVERY: u32 = 32;
const SPINNER_BIN = "iretq_spin.elf";

fn workerExit() callconv(.c) noreturn {
    process.destroyCurrent();
    while (true) asm volatile ("hlt");
}

fn spawnSpinner() ?u8 {
    const fresh = vfs.loadFileFresh(SPINNER_BIN) orelse return null;
    const pid = elf_loader.loadAndStart(fresh.buf, fresh.size, fresh.pages, fresh.inode) orelse return null;
    process.setName(@intCast(pid), "spin");
    return @intCast(pid);
}

pub fn taskEntry() callconv(.c) noreturn {
    serial.print("[stress-iretq] hunting cross-CPU iretq frame race\n", .{});
    serial.print(
        "[stress-iretq] iretq_canary.DR_WATCHPOINT={} (must be false to NOT suppress race)\n",
        .{iretq_canary.DR_WATCHPOINT},
    );
    if (iretq_canary.DR_WATCHPOINT) {
        serial.print("[stress-iretq] WARN: DR_WATCHPOINT=true — IPI flood will mask the race.\n", .{});
        serial.print("[stress-iretq] Set src/debug/iretq_canary.zig DR_WATCHPOINT=false and rebuild.\n", .{});
    }

    serial.print("[stress-iretq] spawning {d} ring-3 spinners ({s})\n", .{ SPINNERS, SPINNER_BIN });
    var spinners = [_]?u8{null} ** SPINNERS;
    for (0..SPINNERS) |s| {
        spinners[s] = spawnSpinner();
        if (spinners[s]) |pid| {
            serial.print("[stress-iretq]   spinner #{d} -> pid {d}\n", .{ s, pid });
        } else {
            serial.print(
                "[stress-iretq] FAIL: cannot spawn spinner #{d} (PCB full or {s} missing)\n",
                .{ s, SPINNER_BIN },
            );
        }
    }

    var iter: u32 = 0;
    var kchurn: u64 = 0;
    var respawns: u64 = 0;
    var respawn_fail: u64 = 0;

    while (iter < ITERATIONS) : (iter += 1) {
        if (process.createKernelTask(@intFromPtr(&workerExit), "kchurn", 0xFF, .normal, 16 * 1024)) |_| {
            kchurn += 1;
        }

        process.kernelSleepMs(0);
        _ = process.reapStaleZombies(0);

        if ((iter % RESPAWN_EVERY) == 0 and iter > 0) {
            const slot: u32 = (iter / RESPAWN_EVERY) % SPINNERS;
            if (spinners[slot]) |old| process.killProcess(old);
            _ = process.reapStaleZombies(0);
            if (spawnSpinner()) |new_pid| {
                spinners[slot] = new_pid;
                respawns += 1;
            } else {
                spinners[slot] = null;
                respawn_fail += 1;
            }
        }

        if ((iter % 256) == 0) {
            serial.print(
                "[stress-iretq] iter {d}/{d}: kchurn={d} respawn={d}/{d}\n",
                .{ iter, ITERATIONS, kchurn, respawns, respawn_fail },
            );
        }
    }

    serial.print(
        "[stress-iretq] DONE: {d} iters, kchurn={d}, respawns={d}, respawn_fail={d}\n",
        .{ ITERATIONS, kchurn, respawns, respawn_fail },
    );
    serial.print("[stress-iretq] no panic — race not surfaced. Next moves:\n", .{});
    serial.print("[stress-iretq]   * verify DR_WATCHPOINT and armPermanentWatchpoints both off\n", .{});
    serial.print("[stress-iretq]   * raise SPINNERS / ITERATIONS\n", .{});
    serial.print("[stress-iretq]   * disable kernel_esp rotation (main.zig comment) and re-run\n", .{});

    while (true) asm volatile ("cli; hlt");
}
