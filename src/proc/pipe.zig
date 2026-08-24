// Static pool of POSIX-style anonymous pipes. Each pipe is a 4KB ring buffer
// with reader/writer refcounts. Read blocks if the buffer is empty (and there's
// still a writer); write blocks if the buffer is full. Blocking is implemented
// by setting the calling process's wait_kind/wait_target and yielding via
// `int $0x20`; the other end clears the flag via process.wake when it makes
// progress, and the scheduler resumes the blocked process.
//
// "Static pool" means: no heap allocation. Allocate-on-first-use is via a
// `pipes[i].in_use` flag scan. Pool size and per-pipe ring size are both in
// config.zig — bump them there if more concurrent pipes are needed.
//
// Ring↔caller copies in the blocking read()/write() go through the faultable
// usercopy site (cpu/arch/usercopy.zig): the caller's buffer is usually USER
// memory, and a validated page can be swap-evicted while the syscall is
// parked — the copy truncates at the fault and the page is faulted back in
// OUTSIDE the lock instead of the old bare @memcpy panicking inside it.

const std = @import("std");
const process = @import("process.zig");
const debug = @import("../debug/debug.zig");
const config = @import("../config.zig");
const fdpoll = @import("../cpu/ipc/fdpoll.zig");
const spinlock = @import("spinlock.zig");
const slot_table = @import("../util/slot_table.zig");
const usercopy = @import("../cpu/arch/usercopy.zig");

pub const PIPE_BUF_SIZE: u32 = config.PIPE_BUF_SIZE;
pub const MAX_PIPES: u8 = config.MAX_PIPES;

/// Error sentinel returned by write() (EPIPE: read side fully closed) and by
/// read()/write() on an unresolvable caller-buffer fault with zero progress
/// (EFAULT — only reachable with a user buffer). Numerically identical to
/// vfs.VFS_ERR, so the vfs pipe arms' @intCast passes it straight through.
pub const PIPE_ERR: usize = 0xFFFF_FFFF;

pub const Pipe = struct {
    /// Ring contents are contract-undefined while the slot is unclaimed
    /// — slot_table.claim skips resetting them (see claim_skip_reset).
    pub const claim_skip_reset = .{"buf"};

    buf: [PIPE_BUF_SIZE]u8 = undefined,
    head: u32 = 0, // next write offset
    tail: u32 = 0, // next read offset
    count: u32 = 0, // bytes available
    readers: u8 = 0, // refcount of read-side fds
    writers: u8 = 0, // refcount of write-side fds
    in_use: bool = false,
    blocked_reader_pid: u8 = 0xFF, // 0xFF = none
    blocked_writer_pid: u8 = 0xFF,
    /// Set on pipes whose read end is drained by the desktop loop's
    /// non-blocking tryRead poll (terminal window out_pipes). When a
    /// write lands on such a pipe, the desktop's event-driven sleep
    /// needs an explicit wake — without this, the shell's stdout
    /// would queue bytes that the desktop never sees until the next
    /// keyboard/mouse event. Set by `setDesktopDrain(id)` after the
    /// pipe is wired into a window. Default false; process-to-process
    /// pipes never touch this path.
    wake_desktop_on_write: bool = false,

    /// Per-pipe ticket spinlock serialising ALL pipe state: the ring
    /// (head / tail / count / buf), the reader/writer refcounts, the
    /// blocked_*_pid registrations, and the in_use lifecycle (alloc claim
    /// + close free). Added 2026-06-04 after the fuzzer tripped
    /// pcb_invariants' pipe.validate with `count=0 but head=N tail=N-1`.
    /// The ring was being mutated lock-free from two CPUs — the shell's
    /// blocking write() vs the desktop's non-blocking tryRead() draining
    /// a terminal out_pipe (the shell→desktop drain path) — so a
    /// `count += n` and a `count -= n` could race and lose an update, and
    /// the IRQ0 validator on the other CPU could sample a torn (head
    /// bumped, count not yet) intermediate and false-panic. Refcounts and
    /// blocked pids were brought under it 2026-07-16: closeWriter reading
    /// blocked_reader_pid unlocked could interleave with a parking reader
    /// such that neither the EOF-check nor the wake fired (permanent park
    /// on ordinary `a | b` teardown), and the unlocked `readers -= 1`
    /// RMWs could lose updates under concurrent close/spawn (premature
    /// slot free while an fd still referenced it).
    /// Held with interrupts OFF (acquireIrqSave) across only the ring copy +
    /// counter update (the copy is the faultable usercopy site, so a user
    /// page fault truncates instead of wedging the cli window — resolution
    /// happens outside) — NEVER across blockOnInterruptible, process.wake,
    /// or serial logging — so it stays a leaf lock and a CPU's own IRQ0
    /// validator can never interrupt a holder on that CPU and
    /// self-deadlock. validate() takes the same lock to read a consistent
    /// snapshot. Left unregistered (no WITNESS class) — 32 pipes would
    /// blow the named-lock budget, and the lock acquires nothing else
    /// while held so order tracking is moot.
    lock: spinlock.SpinLock = .{},
};

pub var pipes: [MAX_PIPES]Pipe = [_]Pipe{.{}} ** MAX_PIPES;

/// Allocate a new pipe. Returns the pipe id. Both refcounts start at 1 — the
/// caller is expected to install one read fd and one write fd into the
/// process's fd_table.
pub fn alloc() ?u8 {
    // The four-invariant claim dance (unlocked filter, locked re-check,
    // field reset that leaves `lock` alone, in_use published LAST with
    // .release) lives in slot_table.claim now — this function only adds
    // what is pipe-specific: both refcounts start at 1, the caller is
    // expected to install one read fd and one write fd.
    const c = slot_table.claim(Pipe, &pipes) orelse return null;
    c.slot.readers = 1;
    c.slot.writers = 1;
    c.publish();
    return @intCast(c.idx);
}

/// Mark a pipe as a desktop-drain pipe. Writes will trigger an explicit
/// compositor wake so the desktop's poll loop runs and pulls the bytes
/// out. Idempotent.
pub fn setDesktopDrain(id: u8) void {
    if (id >= MAX_PIPES) return;
    const p = &pipes[id];
    const flags = p.lock.acquireIrqSave();
    if (p.in_use) p.wake_desktop_on_write = true;
    p.lock.releaseIrqRestore(flags);
}

/// Read up to `out.len` bytes from pipe `id`. Blocks if the ring is empty and
/// there's still at least one writer. Returns the number of bytes read; 0
/// indicates EOF (writer side fully closed); PIPE_ERR means `out` faulted
/// unresolvably with nothing yet copied (EFAULT). If bytes were already
/// copied when the buffer went bad, that partial count is returned instead
/// (POSIX: transferred data wins) and the error surfaces on the next call.
/// Caller is the current process.
pub fn read(id: u8, out: []u8) usize {
    if (id >= MAX_PIPES) return 0;
    const p = &pipes[id];
    if (!p.in_use) return 0;

    var copied: usize = 0;
    var freed_space = false;
    var fault_tries: u8 = 0;
    while (copied < out.len) {
        const flags = p.lock.acquireIrqSave();
        if (p.count > 0) {
            const wanted = out.len - copied;
            const remaining = p.count;
            // Copy up to min(wanted, remaining, contiguous-in-ring)
            const contiguous = @min(remaining, PIPE_BUF_SIZE - p.tail);
            const n = @min(wanted, contiguous);
            // Ring → caller buffer through the faultable copy site. `out`
            // is usually a USER slice (sysFread): validated at entry, but
            // a blocking read parks for arbitrarily long, and swap eviction
            // (even by a sibling thread of this process) can take a
            // validated page away meanwhile — a bare @memcpy would then eat
            // an unrecoverable kernel #PF inside this cli'd leaf lock. The
            // raw copy truncates at the fault; the ring consumes exactly
            // the bytes that landed, and the missing page is faulted back
            // in below, OUTSIDE the lock (fault-in can block on swap-in
            // disk I/O, which must never happen under a spinlock).
            const done = usercopy.copyToUserRaw(@intFromPtr(out.ptr) + copied, p.buf[p.tail..][0..n]);
            p.tail = (p.tail + @as(u32, @intCast(done))) % PIPE_BUF_SIZE;
            p.count -= @intCast(done);
            copied += done;
            if (done > 0) freed_space = true;

            // Capture the blocked writer, then drop the lock BEFORE waking:
            // process.wake may take sched_lock, which must never nest under
            // the (cli-held) pipe lock. Steal the registration only when the
            // copy made progress — clearing it on a zero-progress fault and
            // then bailing on EFAULT would leave the writer parked with
            // nobody left to wake it.
            var w: u8 = 0xFF;
            if (done > 0 and p.blocked_writer_pid != 0xFF) {
                w = p.blocked_writer_pid;
                p.blocked_writer_pid = 0xFF;
            }
            p.lock.releaseIrqRestore(flags);
            if (w != 0xFF) process.wake(w);
            if (done < n) {
                // Copy faulted — resolve outside the lock, or give up.
                fault_tries += 1;
                if (fault_tries > usercopy.MAX_FAULT_RETRIES or
                    !usercopy.faultInWritable(@intFromPtr(out.ptr) + copied, out.len - copied))
                {
                    if (freed_space) fdpoll.wakePollers(.pipe, id);
                    return if (copied > 0) copied else PIPE_ERR;
                }
            }
            continue;
        }

        // Ring empty
        if (p.writers == 0) {
            // EOF — no more writers, no more data
            p.lock.releaseIrqRestore(flags);
            if (freed_space) fdpoll.wakePollers(.pipe, id);
            return copied;
        }

        // If the caller already got something, return early — POSIX read
        // semantics: a partial read is valid, the caller can loop.
        if (copied > 0) {
            p.lock.releaseIrqRestore(flags);
            fdpoll.wakePollers(.pipe, id);
            return copied;
        }

        // Sleep until a writer pushes data (or all writers close). The
        // .signalled branch returns the partial count (zero or otherwise)
        // and lets the syscall-return signal-delivery path run; without
        // this we'd loop forever (process.wake flips state but the signal
        // stays pending until exit-to-user). Set blocked_reader_pid UNDER
        // the lock (so a racing writer's wake-check observes it), then
        // release before parking — blockOnInterruptible must never run
        // with the pipe lock (or cli) held.
        const my_pid: u8 = @intCast(process.getCurrentPid());
        const displaced = p.blocked_reader_pid;
        p.blocked_reader_pid = my_pid;
        p.lock.releaseIrqRestore(flags);
        // Single-slot waiter registry: a second parked reader displaces the
        // first, which then sleeps until a signal or writer-close. No
        // workload parks two readers on one pipe today (pipelines are 1:1;
        // a shell waits in waitpid while its child owns stdin) — logged
        // AFTER the lock drop (serial takes its own lock; this one is a
        // leaf) so it's loud if that ever changes.
        if (displaced != 0xFF and displaced != my_pid) {
            debug.klog("[pipe] WARN: reader wait-slot collision pipe={d} displaced pid={d} by pid={d}\n", .{ id, displaced, my_pid });
        }
        const br = process.blockOnInterruptible(.pipe_read, id);
        if (br == .signalled) {
            const f2 = p.lock.acquireIrqSave();
            // Clear only OUR registration — a waker may have already
            // cleared it and a different reader re-registered meanwhile;
            // stomping that would strand them.
            if (p.blocked_reader_pid == my_pid) p.blocked_reader_pid = 0xFF;
            p.lock.releaseIrqRestore(f2);
            if (freed_space) fdpoll.wakePollers(.pipe, id);
            return copied;
        }
        // Loop: re-check for data
    }
    if (freed_space) fdpoll.wakePollers(.pipe, id);
    return copied;
}

/// Non-blocking read. Drains up to `out.len` bytes from pipe `id` and returns
/// immediately. Used by the desktop main loop to poll a terminal's stdout
/// pipe each frame without parking the desktop process. Unlike `read`, never
/// touches wait_kind / yields. Returns 0 if the ring is empty (caller can
/// poll again next tick) — does not signal EOF specially because the desktop
/// owns the write side and can detect close itself.
/// `out` must be KERNEL memory: this path keeps the bare @memcpy (no fault
/// recovery), which is fine for its only callers (desktop drain_buf, the
/// window.zig fd0 poll) — all kernel statics/stack. Route user buffers
/// through read().
pub fn tryRead(id: u8, out: []u8) usize {
    if (id >= MAX_PIPES) return 0;
    const p = &pipes[id];
    if (!p.in_use) return 0;
    var copied: usize = 0;
    var wake_w: u8 = 0xFF;
    const flags = p.lock.acquireIrqSave();
    while (copied < out.len and p.count > 0) {
        const wanted = out.len - copied;
        const remaining = p.count;
        const contiguous = @min(remaining, PIPE_BUF_SIZE - p.tail);
        const n = @min(wanted, contiguous);
        @memcpy(out[copied..][0..n], p.buf[p.tail..][0..n]);
        p.tail = (p.tail + @as(u32, @intCast(n))) % PIPE_BUF_SIZE;
        p.count -= @intCast(n);
        copied += n;
        if (p.blocked_writer_pid != 0xFF) {
            wake_w = p.blocked_writer_pid;
            p.blocked_writer_pid = 0xFF;
        }
    }
    p.lock.releaseIrqRestore(flags);
    if (wake_w != 0xFF) process.wake(wake_w);
    if (copied > 0) fdpoll.wakePollers(.pipe, id);
    return copied;
}

/// Write up to `data.len` bytes to pipe `id`. Blocks if the ring is full and
/// there's still at least one reader. Returns bytes written, or PIPE_ERR if
/// the read side has fully closed (EPIPE — caller should treat as a fatal
/// error and not retry) or if `data` faulted unresolvably with nothing yet
/// written (EFAULT). A partial count is returned if bytes were already
/// pushed before the buffer went bad — those bytes are real ring data.
pub fn write(id: u8, data: []const u8) usize {
    if (id >= MAX_PIPES) return 0;
    const p = &pipes[id];
    if (!p.in_use) return PIPE_ERR;

    var written: usize = 0;
    var pushed_data = false;
    var fault_tries: u8 = 0;
    while (written < data.len) {
        const flags = p.lock.acquireIrqSave();
        if (p.readers == 0) {
            // No one to read this. Treat as EPIPE.
            p.lock.releaseIrqRestore(flags);
            if (pushed_data) fdpoll.wakePollers(.pipe, id);
            return PIPE_ERR;
        }

        if (p.count < PIPE_BUF_SIZE) {
            const free = PIPE_BUF_SIZE - p.count;
            const wanted = data.len - written;
            const contiguous = @min(free, PIPE_BUF_SIZE - p.head);
            const n = @min(wanted, contiguous);
            // Caller buffer → ring through the faultable copy site — see
            // read() for the full rationale. Source-side fault: the bytes
            // that DID land before the fault are real data and stay
            // published; the missing tail is faulted back in below,
            // outside the lock.
            const done = usercopy.copyFromUserRaw(p.buf[p.head..][0..n], @intFromPtr(data.ptr) + written);
            p.head = (p.head + @as(u32, @intCast(done))) % PIPE_BUF_SIZE;
            p.count += @intCast(done);
            written += done;
            if (done > 0) pushed_data = true;

            // Capture wake targets, drop the lock, THEN wake — keep
            // process.wake / the compositor wake out of the cli section.
            // Registration stolen only on progress — see read().
            var r: u8 = 0xFF;
            if (done > 0 and p.blocked_reader_pid != 0xFF) {
                r = p.blocked_reader_pid;
                p.blocked_reader_pid = 0xFF;
            }
            const wake_desktop = p.wake_desktop_on_write and done > 0;
            p.lock.releaseIrqRestore(flags);
            if (r != 0xFF) process.wake(r);
            if (wake_desktop) @import("../ui/desktop/wake.zig").requestWake();
            if (done < n) {
                // Copy faulted — resolve outside the lock, or give up.
                fault_tries += 1;
                if (fault_tries > usercopy.MAX_FAULT_RETRIES or
                    !usercopy.faultInReadable(@intFromPtr(data.ptr) + written, data.len - written))
                {
                    if (pushed_data) fdpoll.wakePollers(.pipe, id);
                    return if (written > 0) written else PIPE_ERR;
                }
            }
            continue;
        }

        // Ring full — sleep until reader drains. Bail on pending signal
        // with whatever partial count we have so the syscall-return
        // delivery path runs. Caller can retry after handler returns.
        // blocked_writer_pid set under the lock, released before parking.
        const my_pid: u8 = @intCast(process.getCurrentPid());
        const displaced = p.blocked_writer_pid;
        p.blocked_writer_pid = my_pid;
        p.lock.releaseIrqRestore(flags);
        // Same single-slot collision diagnostic as read() — see there.
        if (displaced != 0xFF and displaced != my_pid) {
            debug.klog("[pipe] WARN: writer wait-slot collision pipe={d} displaced pid={d} by pid={d}\n", .{ id, displaced, my_pid });
        }
        const br = process.blockOnInterruptible(.pipe_write, id);
        if (br == .signalled) {
            const f2 = p.lock.acquireIrqSave();
            // Clear only OUR registration — see read()'s .signalled path.
            if (p.blocked_writer_pid == my_pid) p.blocked_writer_pid = 0xFF;
            p.lock.releaseIrqRestore(f2);
            if (pushed_data) fdpoll.wakePollers(.pipe, id);
            return written;
        }
    }
    if (pushed_data) fdpoll.wakePollers(.pipe, id);
    return written;
}

/// Non-blocking write. Pushes up to `data.len` bytes into pipe `id` and
/// returns immediately. Used by the desktop to push keystrokes into a
/// terminal's stdin pipe without parking the desktop process. Returns the
/// byte count written; 0 means the ring is full (or pipe has no readers) —
/// caller decides whether to drop or retry. Like tryRead, never touches
/// wait_kind / yields, and like tryRead `data` must be KERNEL memory (bare
/// @memcpy, no fault recovery — the desktop keystroke buffers all are).
pub fn tryWrite(id: u8, data: []const u8) usize {
    if (id >= MAX_PIPES) return 0;
    const p = &pipes[id];
    if (!p.in_use) return 0;
    if (p.readers == 0) return 0; // EPIPE-ish — drop the write
    var written: usize = 0;
    var wake_r: u8 = 0xFF;
    const flags = p.lock.acquireIrqSave();
    while (written < data.len and p.count < PIPE_BUF_SIZE) {
        const free = PIPE_BUF_SIZE - p.count;
        const wanted = data.len - written;
        const contiguous = @min(free, PIPE_BUF_SIZE - p.head);
        const n = @min(wanted, contiguous);
        @memcpy(p.buf[p.head..][0..n], data[written..][0..n]);
        p.head = (p.head + @as(u32, @intCast(n))) % PIPE_BUF_SIZE;
        p.count += @intCast(n);
        written += n;
        if (p.blocked_reader_pid != 0xFF) {
            wake_r = p.blocked_reader_pid;
            p.blocked_reader_pid = 0xFF;
        }
    }
    const wake_desktop = p.wake_desktop_on_write;
    p.lock.releaseIrqRestore(flags);
    if (wake_r != 0xFF) process.wake(wake_r);
    if (written > 0) {
        if (wake_desktop) @import("../ui/desktop/wake.zig").requestWake();
        fdpoll.wakePollers(.pipe, id);
    }
    return written;
}

/// Decrement the reader refcount. If it hits zero AND no writers remain, free
/// the pipe slot. Wakes any blocked writer (so it sees readers==0 and returns
/// EPIPE instead of sleeping forever).
///
/// Runs under the pipe lock (2026-07-16). Unlocked, this raced the writer's
/// park in write(): the closer could read blocked_writer_pid before the
/// writer published it, while the writer read readers==1 before the
/// decrement landed — a plain interleaving where neither the EPIPE-check
/// nor the wake fires, leaving the writer parked forever. The lock forces
/// the ordering: either the closer sees the registration (and wakes), or
/// the parking side sees the new refcount (and returns EPIPE/EOF). It also
/// makes the `readers -= 1` RMW atomic against a concurrent close/addReader
/// on another CPU (lost update → premature free or slot leak).
pub fn closeReader(id: u8) void {
    if (id >= MAX_PIPES) return;
    const p = &pipes[id];
    const flags = p.lock.acquireIrqSave();
    if (!p.in_use) {
        p.lock.releaseIrqRestore(flags);
        return;
    }
    if (p.readers > 0) p.readers -= 1;
    // Capture the wake target under the lock, wake AFTER release —
    // process.wake may take sched_lock, which must never nest under the
    // (cli-held) pipe leaf lock. Same pattern as read()/write().
    var w: u8 = 0xFF;
    if (p.blocked_writer_pid != 0xFF) {
        w = p.blocked_writer_pid;
        p.blocked_writer_pid = 0xFF;
    }
    if (p.readers == 0 and p.writers == 0) {
        p.in_use = false;
    }
    p.lock.releaseIrqRestore(flags);
    if (w != 0xFF) process.wake(w);

    // readers→0 means any POLLOUT poller now has to see POLLERR (next
    // write would EPIPE). Wake regardless of whether refcount actually
    // hit zero — pollers may have been racing in.
    fdpoll.wakePollers(.pipe, id);
}

/// Decrement the writer refcount. If it hits zero AND no readers remain, free
/// the pipe slot. Wakes any blocked reader (so it sees writers==0 and returns
/// 0 / EOF instead of sleeping forever).
///
/// Locking rationale: see closeReader. This side is the one ordinary
/// pipeline teardown exercises — the producer of `a | b` exiting (lifecycle
/// closePipeFds) while the consumer is parked in read() on another CPU.
pub fn closeWriter(id: u8) void {
    if (id >= MAX_PIPES) return;
    const p = &pipes[id];
    const flags = p.lock.acquireIrqSave();
    if (!p.in_use) {
        p.lock.releaseIrqRestore(flags);
        return;
    }
    if (p.writers > 0) p.writers -= 1;
    var r: u8 = 0xFF;
    if (p.blocked_reader_pid != 0xFF) {
        r = p.blocked_reader_pid;
        p.blocked_reader_pid = 0xFF;
    }
    if (p.readers == 0 and p.writers == 0) {
        p.in_use = false;
    }
    p.lock.releaseIrqRestore(flags);
    if (r != 0xFF) process.wake(r);

    // writers→0 means any POLLIN poller now sees POLLHUP (next read
    // returns 0/EOF). Wake unconditionally — same reasoning as closeReader.
    fdpoll.wakePollers(.pipe, id);
}

/// Bump the reader refcount — used by sysExecAs when a parent's read-end fd
/// is inherited by a child (logical "dup"), so that the parent later closing
/// its end doesn't drop the count to zero while the child is still reading.
/// Locked: the +|= RMW racing a concurrent closeReader's -= on another CPU
/// (spawn inheriting while a sibling exits) could lose the increment —
/// refcount hits zero early, slot frees and gets reallocated while this
/// process's fd still points at it.
pub fn addReader(id: u8) void {
    if (id >= MAX_PIPES) return;
    const p = &pipes[id];
    const flags = p.lock.acquireIrqSave();
    if (p.in_use) p.readers +|= 1;
    p.lock.releaseIrqRestore(flags);
}

/// Bump the writer refcount — same idea, for write-side inheritance.
pub fn addWriter(id: u8) void {
    if (id >= MAX_PIPES) return;
    const p = &pipes[id];
    const flags = p.lock.acquireIrqSave();
    if (p.in_use) p.writers +|= 1;
    p.lock.releaseIrqRestore(flags);
}

/// Walk every in-use pipe and verify ring invariants:
///   - head, tail < PIPE_BUF_SIZE
///   - count <= PIPE_BUF_SIZE
///   - count == (head - tail) mod PIPE_BUF_SIZE
///   - if count > 0, readers > 0 or writers > 0 (no orphaned data)
/// Returns true if all invariants hold; logs to serial otherwise.
///
/// Catches: ring wraparound bugs, count-vs-position drift (alloc/free
/// arithmetic on count drifted from the actual head/tail-distance — same
/// shape as the 2026-05-24 TLSF double-count-on-coalesce class).
pub fn validate() bool {
    const serial = @import("../debug/serial.zig");
    var ok = true;
    for (&pipes, 0..) |*p, i| {
        if (!p.in_use) continue;
        // Take the SAME per-pipe lock the ring ops hold, so we read a
        // CONSISTENT snapshot of head/tail/count rather than a torn
        // intermediate. Without this the IRQ0 scanner (on another CPU)
        // could catch write() mid-update — head bumped, count not yet —
        // and false-panic on a healthy pipe (the 2026-06-04 fuzzer hit).
        // Self-deadlock-safe: ring ops hold this lock with interrupts OFF,
        // so this CPU's IRQ0 can never interrupt a holder on THIS cpu; a
        // holder on another CPU releases within one memcpy.
        const flags = p.lock.acquireIrqSave();
        // Re-check in_use under the lock: the unlocked check above can race
        // a concurrent close freeing the slot, and a freed slot legally
        // retains count>0 with readers==writers==0 (undrained data at
        // close) — sampling that would false-flag the orphan invariant.
        if (!p.in_use) {
            p.lock.releaseIrqRestore(flags);
            continue;
        }
        const head = p.head;
        const tail = p.tail;
        const count = p.count;
        const readers = p.readers;
        const writers = p.writers;
        p.lock.releaseIrqRestore(flags);

        if (head >= PIPE_BUF_SIZE) {
            serial.print("[pipe] inv: pipe {d} head={d} >= PIPE_BUF_SIZE={d}\n", .{ i, head, PIPE_BUF_SIZE });
            ok = false;
        }
        if (tail >= PIPE_BUF_SIZE) {
            serial.print("[pipe] inv: pipe {d} tail={d} >= PIPE_BUF_SIZE={d}\n", .{ i, tail, PIPE_BUF_SIZE });
            ok = false;
        }
        if (count > PIPE_BUF_SIZE) {
            serial.print("[pipe] inv: pipe {d} count={d} > PIPE_BUF_SIZE={d}\n", .{ i, count, PIPE_BUF_SIZE });
            ok = false;
        }
        if (head < PIPE_BUF_SIZE and tail < PIPE_BUF_SIZE) {
            const expected_count: u32 = if (head >= tail)
                head - tail
            else
                PIPE_BUF_SIZE - tail + head;
            // When the ring is exactly full, head == tail but count == PIPE_BUF_SIZE,
            // so the head>=tail branch returns 0; accept either 0 (empty) or PIPE_BUF_SIZE.
            const matches = if (head == tail)
                (count == 0 or count == PIPE_BUF_SIZE)
            else
                (count == expected_count);
            if (!matches) {
                serial.print("[pipe] inv: pipe {d} count={d} but head={d} tail={d} (expected {d})\n", .{ i, count, head, tail, expected_count });
                ok = false;
            }
        }
        if (count > 0 and readers == 0 and writers == 0) {
            serial.print("[pipe] inv: pipe {d} has {d} bytes but no readers/writers\n", .{ i, count });
            ok = false;
        }
    }
    return ok;
}
