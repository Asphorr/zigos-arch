//! Per-fd readiness predicate + waiter registry. Underpins io_uring's
//! OP_POLL opcode — the multiplexing primitive that lets one task wait on
//! many fds at once (POSIX poll/select shape, just expressed over the ring).
//!
//! Two halves:
//!   1. `pollMask(pid, fd)` — synchronous readiness check. Returns the
//!      bitwise OR of POLL{IN,OUT,ERR,HUP} bits that are TRUE NOW for the
//!      given fd. Dispatches by FsType — pipes consult ring fill, console
//!      consults the focused-window event queue, file-backed kinds are
//!      always ready (synchronous reads).
//!   2. Waiter registry + `wakePollers(kind, id)` — when an fd transitions
//!      to "more ready" (pipe.write, console keystroke, etc.), the relevant
//!      subsystem calls wakePollers. fdpoll walks the registry, re-checks
//!      pollMask for each waiter, and completes any whose requested events
//!      are now satisfied by calling back into iouring.
//!
//! Why a centralized registry: pipes/console/etc don't need per-fd-type
//! waiter lists — the registry is single source of truth, freed in one
//! place on process teardown, and matched by (kind, id) so cross-process
//! pollers (parent + child sharing a pipe) all wake.
//!
//! Why callback registration vs direct iouring import: avoids the
//! iouring↔fdpoll module cycle. iouring registers `completion_callback`
//! at boot; fdpoll fires it on a satisfied waiter without knowing what
//! iouring is.

const std = @import("std");
const process = @import("../proc/process.zig");
const pipe = @import("../proc/pipe.zig");
const SpinLock = @import("../proc/spinlock.zig").SpinLock;
const pid_set = @import("../util/pid_set.zig");
const debug = @import("../debug/debug.zig");
const file = @import("../fs/file.zig");
const tty = @import("../tty/tty.zig");
const signals = @import("../proc/signals.zig");
const sched = @import("../proc/sched.zig");
const smp = @import("../cpu/smp.zig");

// POSIX poll bit values (match Linux). Apps observe these as CQE.res on
// a satisfied OP_POLL — they should be ABI-stable across libc updates.
pub const POLLIN: u16 = 0x0001;
pub const POLLPRI: u16 = 0x0002;
pub const POLLOUT: u16 = 0x0004;
pub const POLLERR: u16 = 0x0008;
pub const POLLHUP: u16 = 0x0010;
pub const POLLNVAL: u16 = 0x0020;
pub const POLLRDNORM: u16 = 0x0040;
pub const POLLWRNORM: u16 = 0x0100;
/// The peer shut its sending side (a stream socket).
pub const POLLRDHUP: u16 = 0x2000;

/// Identifier of the underlying fd object, resolved from (pid, fd) at
/// register-time. The wake side keys by this — never by (pid, fd) —
/// because a pipe shared across fork() lives in multiple fd tables but
/// is one Pipe slot. Cross-pid wake fan-out is automatic.
///
/// `id` semantics by kind:
///   .pipe    — `pipe_id` (0..MAX_PIPES)
///   .console — focused-window slot index when registered (matches
///              what desktop.popEvent uses); 0xFFFF if no focus yet
///   files    — unused; only the FsType matters since files are
///              instantly ready, no wake required
pub const FdHandle = struct {
    kind: process.FsType,
    id: u16,
};

const Waiter = struct {
    in_use: bool = false,
    inst_id: u8 = 0xFF, // io_uring instance index back-pointer
    slot_idx: u8 = 0xFF, // pending[] slot inside that instance
    pid: u8 = 0xFF,
    handle: FdHandle = .{ .kind = .console, .id = 0xFFFF },
    events: u16 = 0,
    /// Generation counter captured from the iouring PendingOp at register
    /// time. Fired back to iouring through the callback so the callback
    /// can detect recycled-slot wakes (the lifecycle race from 2026-05-24:
    /// wakePollers snapshots the waiter + drops the lock, worker drains
    /// the slot, allocPendingSlot reassigns it, then the deferred cb
    /// would have landed on the WRONG op). Compare-on-fire skips the
    /// wake if `p.gen != expected_gen`.
    expected_gen: u16 = 0,
};

// Sized for the worst realistic case (16 io_uring instances × ~4 polls
// each). Lookups are linear; if this grows past ~256 we'd want a hash.
const MAX_WAITERS: usize = 64;
var waiters: [MAX_WAITERS]Waiter = [_]Waiter{.{}} ** MAX_WAITERS;
var lock: SpinLock = .{};

/// iouring registers this at boot. fdpoll fires it on a satisfied
/// waiter. Receives the back-pointer + the events mask that's actually
/// ready (POSIX poll convention — handler decides what to do with it).
/// Signature must match iouring's poll-completion helper exactly.
pub var completion_callback: ?*const fn (inst_id: u8, slot_idx: u8, expected_gen: u16, ready_mask: u16) void = null;

/// Compute the current readiness mask for `pcb.fd_table[fd]`. Returns
/// the bitwise OR of POLLIN/POLLOUT/POLLHUP/POLLERR bits true RIGHT NOW.
/// Returns 0 for a closed/invalid fd (the caller can decide whether
/// that's POLLNVAL or just a non-match).
///
/// Pipe / console wiring goes in #890 / #892; for now stubs return 0
/// so the iouring side compiles and the smoke test (#894) can probe
/// the always-ready file kinds.
pub fn pollMask(pid: u8, fd: u8) u16 {
    const h = resolveFd(pid, fd) orelse return 0;
    return pollMaskHandle(pid, h);
}

/// Same as `pollMask` but takes a pre-resolved `FdHandle`. Used by the
/// wake path which captured the handle at register-time (the fd may
/// have been closed in the meantime, but the underlying pipe/window
/// can still be polled until the LAST holder closes it).
pub fn pollMaskHandle(pid: u8, h: FdHandle) u16 {
    return switch (h.kind) {
        .pipe => pollMaskPipe(h.id),
        .console => pollMaskConsole(pid, h.id),
        // File kinds (fat32, tarfs, ext2, devfs, procfs) read synchronously
        // — always ready. POLLOUT is meaningless for read-only mounts but
        // returning it is harmless (writes happen via separate paths).
        .fat32, .tarfs, .ext2, .devfs, .procfs, .lproc => POLLIN | POLLOUT,
        .tcp_sock => @import("../net/net.zig").tcpPollMask(@intCast(h.id)),
        .tcp_listener => @import("../net/net.zig").tcpListenerPollMask(@intCast(h.id)),
        // Objects answer through their file's own poll (File.ops), which a
        // handle can't reach.
        .socket, .epoll, .eventfd, .tty => 0,
    };
}

/// Resolve (pid, fd) into a stable `FdHandle`. Called at register-time
/// so the wake path doesn't need to re-walk the pcb after the fd may
/// have been closed.
pub fn resolveFd(pid: u8, fd: u8) ?FdHandle {
    if (pid >= process.MAX_PROCS) return null;
    const f = file.get(&process.procs[pid], fd) orelse return null;
    defer file.put(f);
    return handleOf(f);
}

fn handleOf(f: *const file.File) FdHandle {
    return switch (f.kind) {
        .pipe => .{ .kind = .pipe, .id = f.pipe_id },
        .console => .{ .kind = .console, .id = 0xFFFF }, // focus may change; use 0xFFFF as a "current focus" sentinel
        .tcp_sock, .tcp_listener => .{ .kind = f.kind, .id = @intCast(f.inode) },
        else => .{ .kind = f.kind, .id = 0 },
    };
}

// --- Readiness by file -------------------------------------------------
//
// What File.ops.poll and File.ops.events answer for the kinds that keep no
// table of their own.

/// The readiness of `f` for `pcb`'s process. A terminal may hold keys its
/// pipe no longer does: the rest of an arrow key's sequence, a line typed
/// ahead.
pub fn maskOfFile(f: *file.File, pcb: *process.PCB) u16 {
    var mask = pollMaskHandle(pcb.tgid, handleOf(f));
    if (f.tty != tty.NONE and f.access == file.READ and tty.readable(f.tty)) mask |= POLLIN;
    return mask;
}

/// (a) Bumped by every wake for the pipe: what was written, read or closed.
var pipe_events: [pipe.MAX_PIPES]u32 = [_]u32{0} ** pipe.MAX_PIPES;
/// (a) Bumped by every console wake.
var console_events: u32 = 0;

/// Pipe `id`'s event count (a terminal end counts its two pipes').
pub fn pipeEvents(id: u8) u32 {
    return if (id < pipe.MAX_PIPES) @atomicLoad(u32, &pipe_events[id], .monotonic) else 0;
}

/// `f`'s event count; a constant for the kinds that are always ready.
pub fn eventsOfFile(f: *const file.File) u32 {
    return switch (f.kind) {
        .pipe => if (f.pipe_id < pipe.MAX_PIPES) @atomicLoad(u32, &pipe_events[f.pipe_id], .monotonic) else 0,
        .console => @atomicLoad(u32, &console_events, .monotonic),
        else => 0,
    };
}

fn countEvent(kind: process.FsType, id: u16) void {
    switch (kind) {
        .pipe => if (id < pipe.MAX_PIPES) {
            _ = @atomicRmw(u32, &pipe_events[id], .Add, 1, .monotonic);
        },
        .console => _ = @atomicRmw(u32, &console_events, .Add, 1, .monotonic),
        else => {},
    }
}

// --- Per-kind readiness (stubs filled in by #890 / #892) ---------------

fn pollMaskPipe(id: u16) u16 {
    if (id >= pipe.MAX_PIPES) return POLLERR;
    const p = &pipe.pipes[id];
    if (!p.in_use) return POLLERR;
    var mask: u16 = 0;
    // POLLIN: data available OR write side fully closed (next read returns
    // 0/EOF without blocking — Linux semantics).
    if (p.count > 0 or p.writers == 0) mask |= POLLIN;
    // POLLOUT: ring has space AND someone is still reading. Without a
    // reader, the write would EPIPE — we surface that as POLLERR below
    // and DON'T claim POLLOUT (a poll for "writable" shouldn't be lied to).
    if (p.count < pipe.PIPE_BUF_SIZE and p.readers > 0) mask |= POLLOUT;
    if (p.writers == 0) mask |= POLLHUP;
    if (p.readers == 0) mask |= POLLERR;
    return mask;
}

fn pollMaskConsole(pid: u8, _: u16) u16 {
    // Imported lazily to avoid a top-of-file desktop↔fdpoll cycle at
    // declaration time. `consoleReadable` mirrors `popCharEvent`'s
    // gates (focus, visibility, terminal-mode, ownership) so a "ready"
    // verdict means the next sysRead/popCharEvent will succeed.
    const desktop = @import("../ui/desktop.zig");
    if (desktop.consoleReadable(pid)) return POLLIN;
    return 0;
}

// --- poll(2) sleepers --------------------------------------------------
//
// A task in a Linux poll is in this set from before it first checks its
// fds until it returns, and any fd event wakes every such task by pid; each
// re-checks its own fds. By pid, a wake that lands before the task parks is
// kept for it (wake_pending), so none is lost. A herd, but there are few
// pollers.

var sleepers: pid_set.AtomicPidSet = .{};

pub fn sleeperEnter(pid: usize) void {
    sleepers.enter(pid);
}

pub fn sleeperLeave(pid: usize) void {
    sleepers.leave(pid);
}

/// The pids in poll(2) now, as bits (diagnostics).
pub fn sleeperMask() [pid_set.WORDS]u64 {
    return sleepers.snapshot();
}

fn wakeSleepers() void {
    var it = sleepers.members();
    while (it.next()) |pid| process.wake(@intCast(pid));
}

/// Something changed on an object no handle names (a socket, an eventfd):
/// the tasks in poll look again.
pub fn notify() void {
    wakeSleepers();
}

pub const Waited = enum { ready, interrupted, timed_out };

/// Sleep until `ready(ctx)`, a signal the caller can be delivered, or tick
/// `deadline` (0: none). What makes `ready` true must end in wakePollers or
/// notify. `ready` is asked without any lock and must not sleep.
pub fn waitFor(ctx: anytype, comptime ready: fn (@TypeOf(ctx)) bool, deadline: u64) Waited {
    const me = smp.currentPid() orelse return .interrupted;
    const pcb = &process.procs[me];
    // In the set before the first look, so an event after it wakes us.
    sleeperEnter(me);
    defer {
        sleeperLeave(me);
        @atomicStore(u64, &pcb.wake_tick, 0, .release);
    }
    while (true) {
        if (ready(ctx)) return .ready;
        if (deadline != 0 and process.tick_count >= deadline) return .timed_out;
        if (signals.interrupts(pcb)) return .interrupted;
        sched.blockOnDeadline(.poll, 0, deadline);
    }
}

// --- Registry --------------------------------------------------------

/// Reserve a waiter slot. Returns the waiter index (opaque to caller —
/// pass back to unregister). null = registry full; iouring should
/// surface this as ENOMEM on the CQE.
pub fn register(inst_id: u8, slot_idx: u8, pid: u8, h: FdHandle, events: u16, gen: u16) ?u8 {
    // IrqSave on every acquisition of this lock: wakePollers runs in
    // NIC-IRQ context (net.rxPush off the virtio-net RX path). A plain
    // acquire here would let that IRQ land while THIS CPU holds the lock
    // and spin cli'd against its own interrupted holder forever — the
    // same deadlock class as nvme ioCommand 2026-05-20.
    const f = lock.acquireIrqSave();
    defer lock.releaseIrqRestore(f);
    for (&waiters, 0..) |*w, i| {
        if (w.in_use) continue;
        w.* = .{
            .in_use = true,
            .inst_id = inst_id,
            .slot_idx = slot_idx,
            .pid = pid,
            .handle = h,
            .events = events,
            .expected_gen = gen,
        };
        return @intCast(i);
    }
    return null;
}

/// Release a previously-registered slot. Idempotent — calling twice is
/// a no-op rather than a panic, so the io_uring teardown paths can
/// blindly unregister all slots without tracking which ones are live.
pub fn unregister(idx: u8) void {
    if (idx >= MAX_WAITERS) return;
    const f = lock.acquireIrqSave();
    defer lock.releaseIrqRestore(f);
    waiters[idx].in_use = false;
}

/// Drop every waiter belonging to `pid`. Called from process teardown
/// (tearDownTask) so a dying process can't leak entries.
pub fn releaseAllForPid(pid: u8) void {
    const f = lock.acquireIrqSave();
    defer lock.releaseIrqRestore(f);
    for (&waiters) |*w| {
        if (w.in_use and w.pid == pid) w.in_use = false;
    }
}

/// Notify pollers that fd-object `(kind, id)` has potentially changed
/// readiness. Walks the registry, re-checks pollMaskHandle for each
/// matching waiter, and if the resulting mask intersects the requested
/// events fires the completion callback + drops the waiter.
///
/// Multiple wakes for the same fd between submit and completion are
/// fine — re-checking pollMaskHandle keeps the result coherent with
/// the post-wake state.
pub fn wakePollers(kind: process.FsType, id: u16) void {
    countEvent(kind, id);
    wakeSleepers();
    const cb = completion_callback orelse return;
    // Snapshot which slots to complete under the lock, then call out
    // without holding it — completion may take long enough that we
    // don't want to block fresh register() calls behind it.
    var to_fire: [MAX_WAITERS]struct { inst_id: u8, slot_idx: u8, expected_gen: u16, mask: u16 } = undefined;
    var n: usize = 0;
    const f = lock.acquireIrqSave();
    for (&waiters, 0..) |*w, i| {
        if (!w.in_use) continue;
        if (w.handle.kind != kind) continue;
        // .console uses 0xFFFF "current focus" sentinel — wake any
        // console poller regardless of which window id woke us.
        if (kind != .console and w.handle.id != id) continue;
        const ready = pollMaskHandle(w.pid, w.handle);
        const matched = ready & w.events;
        if (matched == 0) continue;
        to_fire[n] = .{ .inst_id = w.inst_id, .slot_idx = w.slot_idx, .expected_gen = w.expected_gen, .mask = matched };
        n += 1;
        w.in_use = false;
        _ = i;
    }
    lock.releaseIrqRestore(f);
    for (to_fire[0..n]) |entry| cb(entry.inst_id, entry.slot_idx, entry.expected_gen, entry.mask);
}
