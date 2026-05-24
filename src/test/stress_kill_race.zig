// Schedule-vs-kill race harness — chases the setTssRsp0 mismatch panic.
//
// Activated by booting with menu entry "Stress: kill race" (boot_mode=6).
// The bug we're hunting: scheduler picks a PID for dispatch, then between
// pickNext() and setTssRsp0() the same PID gets killed on another CPU
// (expected_kstack_tops[pid] cleared to 0), and setTssRsp0 detects the
// mismatch and panics with `rsp0 mismatch — pcb.kernel_stack_top corrupted`.
//
// Strategy v3: USER processes (was: kernel tasks).
//
// v1/v2 used createKernelTask, which skipped most of the user-process kill
// path: no address-space tear-down, no GUI window destroy, no symbol-table
// free, no lazy-region cleanup, no ELF buffer free. The original `about.elf`
// crash walked through every one of those. So v3 spawns small user apps
// the same way `sysExec` does (`vfs.loadFileFresh` + `elf_loader.loadAndStart`),
// then kills them mid-startup. cpu1 may still be page-faulting in lazy
// regions when cpu0 tears the address space apart — exactly the race shape
// the original panic reported.
//
// Trade-off: each spawn is ~ms (disk read + ELF parse + PT setup), so
// iterations are lower than v2. Still hot enough to trip the race in a
// few minutes if it's a real timing window.

const process = @import("../proc/process.zig");
const debug = @import("../debug/debug.zig");
const serial = @import("../debug/serial.zig");
const vfs = @import("../fs/vfs.zig");
const elf_loader = @import("../proc/elf_loader.zig");
const pmm = @import("../mm/pmm.zig");
const paging = @import("../mm/paging.zig");
const vmm = @import("../mm/vmm.zig");

const ITERATIONS: u32 = 1_000;
const BATCH: u32 = 4;

/// The victim — a tiny user app we spawn and kill repeatedly. Pick something
/// small so the spawn cost is bounded; `yes.elf` busy-loops printing 'y',
/// which means it will actually try to make progress (page faults, sysCalls)
/// while we're killing it — that's the race surface we want exercised.
const VICTIM_NAME: []const u8 = "yes.elf";

pub fn taskEntry() callconv(.c) noreturn {
    serial.print("[killrace] v3: USER processes via {s}\n", .{VICTIM_NAME});
    serial.print("[killrace] BATCH={d}, ITERATIONS={d}\n", .{ BATCH, ITERATIONS });
    serial.print("[killrace] strategy: spawn user app -> kill mid-startup, x BATCH\n", .{});

    // Driver runs in kernel context with kernel CR3 already active (kernel
    // tasks share the master PD). loadAndStart needs to walk + write to
    // the kernel master PD; defensively switch to be sure.
    @import("../cpu/pcid.zig").loadCr3(paging.getKernelPageDirPhys(), 0, @import("../cpu/smp.zig").myCpu().cpu_id);

    var spawned: u64 = 0;
    var spawn_failures: u64 = 0;
    var killed: u64 = 0;

    var pids: [BATCH]u8 = undefined;

    var i: u32 = 0;
    while (i < ITERATIONS) : (i += 1) {
        // Spawn the batch back-to-back. Each loadAndStart returns a fresh
        // pid that's been queued for dispatch. cpu1 will pick it up and
        // start running (page-faulting in the user .text/.data on access).
        var n_spawned: u32 = 0;
        var b: u32 = 0;
        while (b < BATCH) : (b += 1) {
            const fresh = vfs.loadFileFresh(VICTIM_NAME) orelse {
                pids[b] = 0xFF;
                spawn_failures += 1;
                continue;
            };
            if (elf_loader.loadAndStart(fresh.buf, fresh.size, fresh.pages)) |p| {
                pids[b] = @intCast(p);
                n_spawned += 1;
                spawned += 1;
                process.setName(@intCast(p), "krv");
                // Don't promote to interactive — we want the default
                // .normal priority so cpu1 dispatches it through the
                // ordinary path. interactive priority would short-circuit
                // some scheduler corners.
            } else {
                // ELF load failed — release the buffer back to PMM. Same
                // dance as sysExec's failure branch. Use freeRange (the
                // allocContiguous pair) — per-frame freeFrame loops stamp
                // spurious canaries on every page.
                pids[b] = 0xFF;
                spawn_failures += 1;
                const phys_base = paging.virtToPhys(@intFromPtr(fresh.buf)).?;
                pmm.freeRange(phys_base, fresh.pages);
            }
        }

        // Kill the batch back-to-back, no yields. cpu1 may still be
        // mid-dispatch, mid-page-fault, or mid-syscall on these pids.
        // Each killProcess walks the user kill path: vmm.destroyAddressSpace,
        // freeElfBuf, lazy_regions cleanup. expected_kstack_tops[pid] = 0
        // store fires somewhere in there.
        b = 0;
        while (b < BATCH) : (b += 1) {
            if (pids[b] != 0xFF) {
                process.killProcess(pids[b]);
                killed += 1;
            }
        }

        _ = process.reapStaleZombies(0);

        if (i % 25 == 0) {
            serial.print("[killrace] iter={d} batch_spawned={d} total_spawned={d} killed={d} fail={d}\n", .{ i, n_spawned, spawned, killed, spawn_failures });
        }
    }

    serial.print("[killrace] DONE: {d} iters, spawned={d}, killed={d}, fail={d}\n", .{ ITERATIONS, spawned, killed, spawn_failures });
    serial.print("[killrace] no setTssRsp0 panic — race didn't fire this run.\n", .{});
    serial.print("[killrace] If still no fire: the bug may need GUI window\n", .{});
    serial.print("[killrace] interaction (mouse, focus, draw) which this harness\n", .{});
    serial.print("[killrace] doesn't simulate. Try running heavy GUI workload manually.\n", .{});

    while (true) asm volatile ("cli; hlt");
}
