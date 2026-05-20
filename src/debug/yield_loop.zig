// Yield-Loop Detector.
//
// Catches the structural pattern of "pid yields with identical
// (wait_kind, wait_target, blockOn_caller_ra) in a tight cycle" — the
// fingerprint of a wake-then-resleep loop where the I/O resource never
// makes progress.
//
// Each `blockOn` call observes the trio (kind, target, caller_ra) for
// the current pid. If consecutive observations match within a short
// window (default 100 timer ticks ≈ 1 sec at 100 Hz), an internal
// counter increments. Once `TRIP_COUNT` consecutive matches land inside
// a single window, the detector trips and dumps:
//
//   * the decoded blockOn caller (addr2line via symbols.resolveKernel)
//   * resource-specific state via a kind-driven dispatch
//       (.nvme_io => nvme.dumpWaiterForTarget, etc.)
//   * the pid's recent activity ring (pid_act.dump)
//
// Why this catches what the existing diagnostics miss:
//   * `flush_rect frozen` only fires on the compositor; `wake-skip` is
//     a per-tick line in the log. Neither correlates back to the resource.
//   * A wake-then-resleep loop with the same target IS the failure
//     mode for "I/O wait that never gets a real completion". This
//     module recognizes that pattern directly and dumps the resource's
//     view in the same breath.
//
// Cost: 1 load + a few compares per blockOn. ~50 bytes per pid in BSS.

const std = @import("std");
const config = @import("../config.zig");
const process = @import("../proc/process.zig");
const serial = @import("serial.zig");
const symbols = @import("symbols.zig");

const TRIP_COUNT: u16 = 5;
const WINDOW_TICKS: u64 = 100;
/// `checkStuck` trips after this many ticks of continuous sleep on the
/// same (kind, target) with no wake observed in between. 500 ticks at
/// 100 Hz = 5 seconds — well past any legitimate I/O.
const STUCK_TICKS: u64 = 500;

const Slot = struct {
    wait_kind: u8 = 0xFF,
    wait_target: u32 = 0,
    caller_ra: u64 = 0,
    count: u16 = 0,
    first_tick: u64 = 0,
    last_tick: u64 = 0,
    fired: bool = false,
};

var slots: [config.MAX_PROCS]Slot align(64) = [_]Slot{.{}} ** config.MAX_PROCS;
var disabled: bool = false;

/// Reset a pid's state. Called from `resetPcbExceptState` so a recycled
/// pid slot starts clean.
pub fn resetPid(pid: usize) void {
    if (pid >= config.MAX_PROCS) return;
    slots[pid] = .{};
}

/// Globally suppress trips. Used by panic paths to prevent recursive
/// dumping if a yield-loop fires during another panic's autopsy.
pub fn disable() void {
    disabled = true;
}

/// Observe a `blockOn` call. Caller is responsible for passing
/// `@returnAddress()` as `caller_ra` so the dump can name the yield
/// site at the level above blockOn.
pub fn observe(pid: usize, kind: process.WaitKind, target: u32, caller_ra: u64) void {
    if (disabled) return;
    if (pid >= config.MAX_PROCS) return;
    // Earlier we disabled .nvme_io / .gpu_io thinking allocCid recycling
    // produced FPs — the "FPs" turned out to be REAL state/rq race trips
    // (pid stuck .sleeping in rq → picker repeatedly transitions
    // .sleeping→.running via direct CAS → blockOn immediately re-parks).
    // The setState serializing lock fixes the underlying race; re-enabling
    // observe() here means a future regression in the dispatch path
    // resurfaces immediately instead of masquerading as a wedge.
    const s = &slots[pid];
    if (s.fired) return;

    const tick = process.tick_count;
    const new_kind = @intFromEnum(kind);
    const same = s.wait_kind == new_kind and
        s.wait_target == target and
        s.caller_ra == caller_ra;
    if (same) {
        s.count +%= 1;
        s.last_tick = tick;
        if (s.count >= TRIP_COUNT and (tick -% s.first_tick) <= WINDOW_TICKS) {
            s.fired = true;
            trip(pid, kind, target, caller_ra, s.count, tick -% s.first_tick);
        }
        return;
    }
    s.wait_kind = new_kind;
    s.wait_target = target;
    s.caller_ra = caller_ra;
    s.count = 1;
    s.first_tick = tick;
    s.last_tick = tick;
}

/// Stuck-waiter detector. Called from `wakeExpired`'s explicit-waker-
/// not-firing branch when a pid has been continuously `.sleeping` with
/// a non-`.none` `wait_kind` for at least one wake-skip interval (200
/// ticks). Trips ONCE per pid after STUCK_TICKS since the first
/// observed yield on this (kind, target). Pattern: the bug we're
/// hunting is a single blockOn that never gets a wake — no repeated
/// yields for `observe` to see, just a permanent park.
///
/// `slots[pid].first_tick` was set by `observe()` when the yielding
/// pid called blockOn. If the slot still matches `(kind, target)` and
/// hasn't yet fired, and the gap since first_tick exceeds STUCK_TICKS,
/// dump.
pub fn checkStuck(pid: usize, kind: process.WaitKind, target: u32) void {
    if (disabled) return;
    if (pid >= config.MAX_PROCS) return;
    const s = &slots[pid];
    if (s.fired) return;
    const new_kind = @intFromEnum(kind);
    if (s.wait_kind != new_kind or s.wait_target != target) return;
    const tick = process.tick_count;
    if ((tick -% s.first_tick) < STUCK_TICKS) return;
    s.fired = true;
    tripStuck(pid, kind, target, s.caller_ra, tick -% s.first_tick);
}

fn tripStuck(pid: usize, kind: process.WaitKind, target: u32, caller_ra: u64, span_ticks: u64) void {
    serial.print(
        "\n!!! [yield-loop:stuck] pid={d} parked on {s} target=0x{X} span={d}t (no wake) !!!\n",
        .{ pid, waitKindName(kind), target, span_ticks },
    );
    if (caller_ra != 0) {
        if (symbols.resolveKernel(caller_ra)) |sym| {
            serial.print("  blockOn caller: {s}+0x{X}\n", .{ sym.name, sym.offset });
        } else {
            serial.print("  blockOn caller: 0x{X:0>16}\n", .{caller_ra});
        }
    }
    switch (kind) {
        .nvme_io => {
            @import("../driver/nvme.zig").dumpWaiterForTarget(target);
        },
        .gpu_io => {
            @import("../driver/virtio_gpu.zig").dumpWaiterForTarget(target);
        },
        else => {},
    }
    @import("pid_act.zig").dump(pid);
    serial.print("[yield-loop:stuck] -- end pid={d} dump --\n\n", .{pid});
}

fn waitKindName(k: process.WaitKind) []const u8 {
    return switch (k) {
        .none => "none",
        .waitpid => "waitpid",
        .pipe_read => "pipe_read",
        .pipe_write => "pipe_write",
        .futex => "futex",
        .gpu_io => "gpu_io",
        .mutex => "mutex",
        .nvme_io => "nvme_io",
    };
}

fn trip(pid: usize, kind: process.WaitKind, target: u32, caller_ra: u64, count: u16, span_ticks: u64) void {
    serial.print(
        "\n!!! [yield-loop] pid={d} stuck on {s} target=0x{X} count={d} span={d}t !!!\n",
        .{ pid, waitKindName(kind), target, count, span_ticks },
    );
    if (symbols.resolveKernel(caller_ra)) |sym| {
        serial.print("  yield site (blockOn caller): {s}+0x{X}\n", .{ sym.name, sym.offset });
    } else {
        serial.print("  yield site (blockOn caller): 0x{X:0>16}\n", .{caller_ra});
    }
    switch (kind) {
        .nvme_io => {
            @import("../driver/nvme.zig").dumpWaiterForTarget(target);
        },
        .gpu_io => {
            @import("../driver/virtio_gpu.zig").dumpWaiterForTarget(target);
        },
        else => {},
    }
    @import("pid_act.zig").dump(pid);
    serial.print("[yield-loop] -- end pid={d} dump --\n\n", .{pid});
}
