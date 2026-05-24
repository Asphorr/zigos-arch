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
    // S3: include the parker's PCB state, especially wake_pending (the
    // 2026-05-19 lost-wake handshake field). A common failure mode is
    // "waker fired but didn't set wake_pending → wakeExpired skips".
    if (pid < config.MAX_PROCS) {
        const p = &process.procs[pid];
        const name = p.name[0..@min(p.name_len, p.name.len)];
        serial.print("  pid={d} name='{s}' state={s} wake_pending={}\n", .{
            pid, name, @tagName(p.state), p.wake_pending,
        });
    }
    if (caller_ra != 0) {
        if (symbols.resolveKernel(caller_ra)) |sym| {
            serial.print("  blockOn caller: {s}+0x{X}\n", .{ sym.name, sym.offset });
        } else {
            serial.print("  blockOn caller: 0x{X:0>16}\n", .{caller_ra});
        }
    }
    dumpResourceState(pid, kind, target);
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
        .swap_evict => "swap_evict",
        .iouring_work => "iouring_work",
        .iouring_cq => "iouring_cq",
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
    dumpResourceState(pid, kind, target);
    @import("pid_act.zig").dump(pid);
    serial.print("[yield-loop] -- end pid={d} dump --\n\n", .{pid});
}

/// S3: per-wait-kind context dump. The blockOn caller_ra tells us WHERE
/// the waiter parked; this tells us WHAT it was waiting on and the
/// current state of that resource. Common diagnosis pattern is to
/// compare expected-waker-state vs actual: e.g. child IS zombie but
/// waitpid still parked → the wake didn't fire, OR pipe has 0 writers
/// but reader still parked → EOF wasn't signaled.
fn dumpResourceState(pid: usize, kind: process.WaitKind, target: u32) void {
    switch (kind) {
        .none => serial.print("  (no resource — wait_kind=.none)\n", .{}),
        .waitpid => dumpWaitpid(pid, target),
        .pipe_read => dumpPipe(target, true),
        .pipe_write => dumpPipe(target, false),
        .futex => dumpFutex(pid, target),
        .mutex => dumpMutex(pid, target),
        .nvme_io => @import("../driver/nvme.zig").dumpWaiterForTarget(target),
        .gpu_io => @import("../driver/virtio_gpu.zig").dumpWaiterForTarget(target),
        .swap_evict => serial.print("  swap_evict low32-of-pte=0x{X:0>8} — wait for evictFrame commit/abort\n", .{target}),
        .iouring_work => serial.print("  iouring_work instance={d} (worker idle, wake from io_uring_enter or NVMe IRQ callback)\n", .{target}),
        .iouring_cq => serial.print("  iouring_cq instance={d} (enter() parked, wake from worker after CQE)\n", .{target}),
    }
}

fn dumpWaitpid(pid: usize, target: u32) void {
    if (target == 0xFFFFFFFF) {
        serial.print("  waitpid: ANY CHILD (target=0xFFFFFFFF)\n", .{});
    } else {
        serial.print("  waitpid: specific pid={d}\n", .{target});
    }
    var found: u32 = 0;
    for (0..config.MAX_PROCS) |i| {
        const p = &process.procs[i];
        if (p.state == .unused) continue;
        if (p.parent_pid != @as(u8, @intCast(pid))) continue;
        if (target != 0xFFFFFFFF and target != i) continue;
        const name = p.name[0..@min(p.name_len, p.name.len)];
        serial.print("    child pid={d} name='{s}' state={s} wake_pending={}\n", .{
            i, name, @tagName(p.state), p.wake_pending,
        });
        if (p.state == .zombie) {
            serial.print("      ** child IS zombie — waker SHOULD have fired sysExit→reapChildren wake\n", .{});
        }
        found += 1;
    }
    if (found == 0) {
        serial.print("    (no matching children in proc table — parent is waiting on ghosts)\n", .{});
    }
}

fn dumpPipe(target: u32, is_read: bool) void {
    const pipe = @import("../proc/pipe.zig");
    if (target >= pipe.MAX_PIPES) {
        serial.print("  pipe id {d} OUT OF RANGE (max {d})\n", .{ target, pipe.MAX_PIPES });
        return;
    }
    const p = &pipe.pipes[target];
    serial.print("  pipe[{d}]: in_use={} head={d} tail={d} count={d} readers={d} writers={d}\n", .{
        target, p.in_use, p.head, p.tail, p.count, p.readers, p.writers,
    });
    serial.print("    blocked_reader_pid={d} blocked_writer_pid={d}\n", .{
        p.blocked_reader_pid, p.blocked_writer_pid,
    });
    if (is_read and p.count == 0 and p.writers == 0) {
        serial.print("    ** reader parked but pipe empty + writers=0 → EOF should have been signaled\n", .{});
    }
    if (!is_read and p.count == pipe.PIPE_BUF_SIZE and p.readers == 0) {
        serial.print("    ** writer parked but pipe full + readers=0 → write should have returned EPIPE\n", .{});
    }
}

fn dumpFutex(pid: usize, target: u32) void {
    // *uaddr lives in user space — reading from kernel context requires the
    // owner's CR3 to be loaded. Skip the value, but enumerate co-waiters.
    serial.print("  futex uaddr=0x{X:0>8} (value not safely readable from kernel ctx)\n", .{target});
    var others: u32 = 0;
    for (0..config.MAX_PROCS) |i| {
        if (i == pid) continue;
        const p = &process.procs[i];
        if (p.state == .sleeping and p.wait_kind == .futex and p.wait_target == target) {
            serial.print("    co-waiter pid={d}\n", .{i});
            others += 1;
        }
    }
    if (others == 0) {
        serial.print("    no other waiters at this uaddr — FUTEX_WAKE may have raced past blockOn\n", .{});
    }
}

fn dumpMutex(pid: usize, target: u32) void {
    serial.print("  mutex (low32-of-&owner_pid)=0x{X:0>8}\n", .{target});
    var waiters: u32 = 0;
    for (0..config.MAX_PROCS) |i| {
        const p = &process.procs[i];
        if (p.state == .sleeping and p.wait_kind == .mutex and p.wait_target == target) {
            serial.print("    waiter pid={d}{s}\n", .{ i, if (i == pid) " (this trip)" else "" });
            waiters += 1;
        }
    }
    if (waiters == 0) {
        serial.print("    NO waiters found — release-then-wake race may have left this stuck\n", .{});
    } else {
        serial.print("    {d} total waiters — owner should release; check who calls Mutex.release\n", .{waiters});
    }
}
