//! Software-interrupt (bottom-half) engine.
//!
//! Hard-IRQ handlers in this kernel run with IF=0, and the heaviest device
//! handlers (NVMe `reapCq` + its up-to-16 `proc.wake` storm, the virtio-gpu
//! completion sweep) currently run *in that context* — either from the
//! `DynIrqStub` body on the per-CPU `isr_stack`, or polled inline from the
//! IRQ0 timer tick (`handleIRQ0`). Both stretch interrupt-disabled time and
//! force `sched_lock` acquisitions from a context where the cross-stack /
//! lock-order hazards are sharpest (see the comments in nvme.reapCq and the
//! Shape-C/D machinery in cpu/idt/dynirq.zig).
//!
//! This module gives that work a proper home: a per-CPU `ksoftirqd` kernel
//! task. A top-half (a hard-IRQ handler, or the timer tick) calls
//! `raise(nr)` — atomically set one bit in this CPU's `softirq_pending` mask
//! and `wake` the local `ksoftirqd`. That's cheap and IF=0-safe (a bit + one
//! wake). The actual work then runs inside `ksoftirqd` in *normal schedulable
//! context* (IF=1, on its own kstack), where taking `sched_lock` and waking
//! a pile of blocked tasks is routine.
//!
//! This is the threaded-bottom-half model rather than a classic irq-exit
//! `do_softirq`: this kernel's single per-CPU `isr_stack` is safe ONLY
//! because IF=0 never nests there (dynirq.zig), so re-enabling interrupts in
//! the IRQ epilogue to drain softirqs would reintroduce exactly the nesting
//! hazard that a blanket IST=1 hit in the past. Deferring to a real task
//! leans on the (already solid) per-CPU CFS scheduler instead.
//!
//! Increment 1 scope: the engine + per-CPU `ksoftirqd`, and the two IRQ0-tick
//! lost-IRQ backstop sweeps (NVMe, virtio-gpu) cut over to it. The primary
//! MSI-X completion paths are unchanged; a later increment moves their heavy
//! drain here too (and then the tick no longer needs to poll devices at all —
//! the prerequisite for a tickless idle).

const std = @import("std");

const smp = @import("../cpu/smp.zig");
const process = @import("process.zig");
const serial = @import("../debug/serial.zig");

/// Bottom-half identifiers. Each maps to one bit of `CpuLocal.softirq_pending`
/// via its integer value, so keep the count <= 32 (the mask is a u32). Append
/// only — the integer values are the bit positions.
pub const Softirq = enum(u5) {
    /// NVMe completion-queue drain (reapCq lost-IRQ backstop).
    nvme = 0,
    /// virtio-gpu completion sweep + parked-compositor wake.
    virtio_gpu = 1,
    /// xHCI HID event-ring drain (keyboard/mouse). Always raised on the BSP —
    /// the xHCI MSI-X is BSP-directed and the tick raise runs in the BSP block —
    /// so the BSP's ksoftirqd is the sole consumer and pollHID's assertBSP holds.
    hid = 2,
    /// Deferred serial-port drain (klog ring → UART). Raised only from the
    /// BSP tick when bytes are pending, so the BSP's ksoftirqd is the sole
    /// drainer — serial.drain_pos needs exactly one consumer.
    klog = 3,
    // room for: net (NAPI), block, tasklet, ...
};

/// Number of softirq vectors — drives the handler table + drain loop. Derived
/// from the enum so it can't drift.
const NR_SOFTIRQS = std.meta.fields(Softirq).len;

/// Handler bodies run in `ksoftirqd` context (IF=1). Plain `fn () void` so the
/// existing driver sweep functions (nvme.tickSweep, virtio_gpu.tickSweep) plug
/// in directly — they're called normally from `drain`, not as an IRQ entry.
const HandlerFn = *const fn () void;

/// Per-softirq handler dispatch table. Index = `@intFromEnum(nr)`. Slot value
/// is the fn-pointer as usize (0 = unregistered). Written once at init by
/// `register()` on the BSP while single-threaded; read in drain context. A
/// scalar usize (not `?HandlerFn`) keeps the read a single load.
var handlers: [NR_SOFTIRQS]usize = .{0} ** NR_SOFTIRQS;

/// Bind a handler to a softirq vector. BSP/init-time only (no atomics — there
/// is no concurrent writer, and the readers don't start until the ksoftirqd
/// tasks are first scheduled, well after `startAll` returns).
pub fn register(nr: Softirq, handler: HandlerFn) void {
    handlers[@intFromEnum(nr)] = @intFromPtr(handler);
}

inline fn maskBit(nr: Softirq) u32 {
    return @as(u32, 1) << @intFromEnum(nr);
}

/// Mark `nr` pending on the CURRENT CPU and kick its `ksoftirqd`. Safe from
/// hard-IRQ context (IF=0): an atomic OR plus one `wake`. Returns true if a
/// `ksoftirqd` was actually kicked; false during the early-boot window before
/// `startAll` has run, so a caller acting as its own backstop (the IRQ0 tick)
/// can fall back to doing the work inline until the task exists.
pub fn raise(nr: Softirq) bool {
    const cpu = smp.myCpu();
    _ = @atomicRmw(u32, &cpu.softirq_pending, .Or, maskBit(nr), .release);
    if (cpu.ksoftirqd_pid) |pid| {
        process.wake(@intCast(pid));
        return true;
    }
    return false;
}

/// Upper bound on drain rounds per ksoftirqd wakeup. A handler that re-raises
/// its own softirq (or a device that keeps completing) can't livelock the
/// task — leftover pending bits ride the next `raise`/tick wakeup. 8 rounds is
/// far more than any real fan-in needs.
const MAX_DRAIN_ROUNDS: u8 = 8;

/// Run every pending bottom-half on `cpu`. The pending mask is read-and-
/// cleared atomically each round, so a `raise` that lands mid-drain isn't lost
/// — it re-sets the bit and the next round (or the wakeup it also issued)
/// catches it. Returns the number of handler invocations (0 = nothing was
/// pending), used only for the liveness heartbeat.
fn drain(cpu: *smp.CpuLocal) u32 {
    var ran: u32 = 0;
    var round: u8 = 0;
    while (round < MAX_DRAIN_ROUNDS) : (round += 1) {
        const pending = @atomicRmw(u32, &cpu.softirq_pending, .Xchg, 0, .acq_rel);
        if (pending == 0) break;
        inline for (std.meta.fields(Softirq)) |f| {
            if ((pending & (@as(u32, 1) << f.value)) != 0) {
                const h = handlers[f.value];
                if (h != 0) {
                    const fp: HandlerFn = @ptrFromInt(h);
                    fp();
                    ran += 1;
                }
            }
        }
    }
    return ran;
}

/// Per-CPU `ksoftirqd` entry. Drains pending bottom-halves, then parks on
/// `WaitKind.softirq` until `raise` kicks it. Pinned to one CPU, so `myCpu()`
/// is stable across the park/resume. Never returns.
fn ksoftirqdEntry() callconv(.c) noreturn {
    // The BSP drainer flips serial output into deferred mode the moment it
    // first gets CPU time — NOT in startAll. startAll runs well before the
    // scheduler's first pick, and the boot init spew between those points
    // (~48KB of GPU/desktop/PCI lines, memcpy-fast once deferred) lapped
    // the kmsg ring with nobody draining — a real boot lost 15KB of boot
    // diagnostics. Flipping here keeps boot output synchronous until the
    // drainer is provably live.
    if (smp.myCpu().cpu_id == 0) {
        @atomicStore(bool, &serial.deferred, true, .release);
        serial.print("[klog] serial port drain deferred to ksoftirqd\n", .{});
    }
    var drained_runs: u64 = 0;
    while (true) {
        const cpu = smp.myCpu();
        if (drain(cpu) != 0) {
            drained_runs += 1;
            // Liveness proof for the first cutover: confirm the bottom-half
            // actually executes (right CPU, IF=1) without flooding the log.
            if (drained_runs == 1 or (drained_runs % 1000) == 0) {
                serial.print("[softirq] cpu{d} ksoftirqd drained (runs={d})\n", .{ cpu.cpu_id, drained_runs });
            }
        }
        // Park only if nothing is still pending. The wake_pending handshake
        // inside blockOn closes the race against a `raise` that lands between
        // this check and the park (raise sets the bit, then wake()s us, and
        // blockOn's test-and-clear returns immediately instead of sleeping).
        if (@atomicLoad(u32, &cpu.softirq_pending, .acquire) == 0) {
            process.blockOn(.softirq, cpu.cpu_id);
        }
    }
}

/// Stand up the bottom-half engine: register the built-in device softirqs and
/// spawn one pinned `ksoftirqd` per alive CPU. Call once from `smp.init`,
/// after the APs are up (BSP, single-threaded). Idempotent.
pub fn startAll() void {
    // Already started? (smp.init reaches here on both the SMP and safe-mode
    // paths; the guard makes a double-call harmless.)
    if (smp.myCpu().ksoftirqd_pid != null) return;

    // Built-in handlers — registered before any task can drain so the first
    // raise dispatches correctly. These are the existing driver sweep
    // functions, now run from ksoftirqd instead of the IRQ0 tick.
    register(.nvme, @import("../driver/nvme.zig").tickSweep);
    register(.virtio_gpu, @import("../driver/virtio_gpu.zig").tickSweep);
    register(.hid, @import("../driver/xhci.zig").pollHID);
    register(.klog, serial.drainToPort);

    var id: u8 = 0;
    while (id < smp.MAX_CPUS) : (id += 1) {
        if (!@atomicLoad(bool, &smp.cpus[id].alive, .acquire)) continue;
        const pid = process.createKernelTask(
            @intFromPtr(&ksoftirqdEntry),
            "ksoftirqd",
            id,
            .interactive, // run promptly when raised, ahead of normal work
            16 * 1024,
        ) orelse {
            serial.print("[softirq] FAILED to create ksoftirqd for cpu{d}\n", .{id});
            continue;
        };
        smp.cpus[id].ksoftirqd_pid = pid;
        serial.print("[softirq] ksoftirqd pid={d} pinned to cpu{d}\n", .{ pid, id });
    }

    // Serial deferred mode is enabled by the BSP ksoftirqd itself on its
    // first run (see ksoftirqdEntry) — flipping it here, before the
    // scheduler ever picks the drainer, let boot spew lap the ring.
}
