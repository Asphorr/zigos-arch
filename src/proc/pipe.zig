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

const std = @import("std");
const process = @import("process.zig");
const debug = @import("../debug/debug.zig");
const config = @import("../config.zig");
const fdpoll = @import("../cpu/fdpoll.zig");

pub const PIPE_BUF_SIZE: u32 = config.PIPE_BUF_SIZE;
pub const MAX_PIPES: u8 = config.MAX_PIPES;

pub const Pipe = struct {
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
};

pub var pipes: [MAX_PIPES]Pipe = [_]Pipe{.{}} ** MAX_PIPES;

/// Allocate a new pipe. Returns the pipe id. Both refcounts start at 1 — the
/// caller is expected to install one read fd and one write fd into the
/// process's fd_table.
pub fn alloc() ?u8 {
    for (0..MAX_PIPES) |i| {
        if (!pipes[i].in_use) {
            pipes[i] = .{
                .in_use = true,
                .readers = 1,
                .writers = 1,
            };
            return @intCast(i);
        }
    }
    return null;
}

/// Mark a pipe as a desktop-drain pipe. Writes will trigger an explicit
/// compositor wake so the desktop's poll loop runs and pulls the bytes
/// out. Idempotent.
pub fn setDesktopDrain(id: u8) void {
    if (id >= MAX_PIPES) return;
    if (!pipes[id].in_use) return;
    pipes[id].wake_desktop_on_write = true;
}

/// Read up to `out.len` bytes from pipe `id`. Blocks if the ring is empty and
/// there's still at least one writer. Returns the number of bytes read; 0
/// indicates EOF (writer side fully closed). Caller is the current process.
pub fn read(id: u8, out: []u8) usize {
    if (id >= MAX_PIPES) return 0;
    const p = &pipes[id];
    if (!p.in_use) return 0;

    var copied: usize = 0;
    var freed_space = false;
    while (copied < out.len) {
        if (p.count > 0) {
            const wanted = out.len - copied;
            const remaining = p.count;
            // Copy up to min(wanted, remaining, contiguous-in-ring)
            const contiguous = @min(remaining, PIPE_BUF_SIZE - p.tail);
            const n = @min(wanted, contiguous);
            @memcpy(out[copied..][0..n], p.buf[p.tail..][0..n]);
            p.tail = (p.tail + @as(u32, @intCast(n))) % PIPE_BUF_SIZE;
            p.count -= @intCast(n);
            copied += n;
            freed_space = true;

            // Wake any writer waiting on this pipe
            if (p.blocked_writer_pid != 0xFF) {
                const w = p.blocked_writer_pid;
                p.blocked_writer_pid = 0xFF;
                process.wake(w);
            }
            continue;
        }

        // Ring empty
        if (p.writers == 0) {
            // EOF — no more writers, no more data
            if (freed_space) fdpoll.wakePollers(.pipe, id);
            return copied;
        }

        // If the caller already got something, return early — POSIX read
        // semantics: a partial read is valid, the caller can loop.
        if (copied > 0) {
            fdpoll.wakePollers(.pipe, id);
            return copied;
        }

        // Sleep until a writer pushes data (or all writers close). The
        // .signalled branch returns the partial count (zero or otherwise)
        // and lets the syscall-return signal-delivery path run; without
        // this we'd loop forever (process.wake flips state but the signal
        // stays pending until exit-to-user).
        const my_pid: u8 = @intCast(process.getCurrentPid());
        p.blocked_reader_pid = my_pid;
        const br = process.blockOnInterruptible(.pipe_read, id);
        if (br == .signalled) {
            p.blocked_reader_pid = 0xFF;
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
pub fn tryRead(id: u8, out: []u8) usize {
    if (id >= MAX_PIPES) return 0;
    const p = &pipes[id];
    if (!p.in_use) return 0;
    var copied: usize = 0;
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
            const w = p.blocked_writer_pid;
            p.blocked_writer_pid = 0xFF;
            process.wake(w);
        }
    }
    if (copied > 0) fdpoll.wakePollers(.pipe, id);
    return copied;
}

/// Write up to `data.len` bytes to pipe `id`. Blocks if the ring is full and
/// there's still at least one reader. Returns bytes written, or 0xFFFFFFFF
/// if the read side has fully closed (analogous to EPIPE — caller should treat
/// as a fatal error and not retry).
pub fn write(id: u8, data: []const u8) usize {
    if (id >= MAX_PIPES) return 0;
    const p = &pipes[id];
    if (!p.in_use) return 0xFFFFFFFF;

    var written: usize = 0;
    var pushed_data = false;
    while (written < data.len) {
        if (p.readers == 0) {
            // No one to read this. Treat as EPIPE.
            if (pushed_data) fdpoll.wakePollers(.pipe, id);
            return 0xFFFFFFFF;
        }

        if (p.count < PIPE_BUF_SIZE) {
            const free = PIPE_BUF_SIZE - p.count;
            const wanted = data.len - written;
            const contiguous = @min(free, PIPE_BUF_SIZE - p.head);
            const n = @min(wanted, contiguous);
            @memcpy(p.buf[p.head..][0..n], data[written..][0..n]);
            p.head = (p.head + @as(u32, @intCast(n))) % PIPE_BUF_SIZE;
            p.count += @intCast(n);
            written += n;
            pushed_data = true;

            if (p.blocked_reader_pid != 0xFF) {
                const r = p.blocked_reader_pid;
                p.blocked_reader_pid = 0xFF;
                process.wake(r);
            }
            if (p.wake_desktop_on_write) @import("../ui/desktop/wake.zig").requestWake();
            continue;
        }

        // Ring full — sleep until reader drains. Bail on pending signal
        // with whatever partial count we have so the syscall-return
        // delivery path runs. Caller can retry after handler returns.
        const my_pid: u8 = @intCast(process.getCurrentPid());
        p.blocked_writer_pid = my_pid;
        const br = process.blockOnInterruptible(.pipe_write, id);
        if (br == .signalled) {
            p.blocked_writer_pid = 0xFF;
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
/// wait_kind / yields.
pub fn tryWrite(id: u8, data: []const u8) usize {
    if (id >= MAX_PIPES) return 0;
    const p = &pipes[id];
    if (!p.in_use) return 0;
    if (p.readers == 0) return 0; // EPIPE-ish — drop the write
    var written: usize = 0;
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
            const r = p.blocked_reader_pid;
            p.blocked_reader_pid = 0xFF;
            process.wake(r);
        }
    }
    if (written > 0) {
        if (p.wake_desktop_on_write) @import("../ui/desktop/wake.zig").requestWake();
        fdpoll.wakePollers(.pipe, id);
    }
    return written;
}

/// Decrement the reader refcount. If it hits zero AND no writers remain, free
/// the pipe slot. Wakes any blocked writer (so it sees readers==0 and returns
/// EPIPE instead of sleeping forever).
pub fn closeReader(id: u8) void {
    if (id >= MAX_PIPES) return;
    const p = &pipes[id];
    if (!p.in_use) return;
    if (p.readers > 0) p.readers -= 1;

    if (p.blocked_writer_pid != 0xFF) {
        const w = p.blocked_writer_pid;
        p.blocked_writer_pid = 0xFF;
        process.wake(w);
    }

    // readers→0 means any POLLOUT poller now has to see POLLERR (next
    // write would EPIPE). Wake regardless of whether refcount actually
    // hit zero — pollers may have been racing in.
    fdpoll.wakePollers(.pipe, id);

    if (p.readers == 0 and p.writers == 0) {
        p.in_use = false;
    }
}

/// Decrement the writer refcount. If it hits zero AND no readers remain, free
/// the pipe slot. Wakes any blocked reader (so it sees writers==0 and returns
/// 0 / EOF instead of sleeping forever).
pub fn closeWriter(id: u8) void {
    if (id >= MAX_PIPES) return;
    const p = &pipes[id];
    if (!p.in_use) return;
    if (p.writers > 0) p.writers -= 1;

    if (p.blocked_reader_pid != 0xFF) {
        const r = p.blocked_reader_pid;
        p.blocked_reader_pid = 0xFF;
        process.wake(r);
    }

    // writers→0 means any POLLIN poller now sees POLLHUP (next read
    // returns 0/EOF). Wake unconditionally — same reasoning as closeReader.
    fdpoll.wakePollers(.pipe, id);

    if (p.readers == 0 and p.writers == 0) {
        p.in_use = false;
    }
}

/// Bump the reader refcount — used by sysExecAs when a parent's read-end fd
/// is inherited by a child (logical "dup"), so that the parent later closing
/// its end doesn't drop the count to zero while the child is still reading.
pub fn addReader(id: u8) void {
    if (id >= MAX_PIPES) return;
    if (!pipes[id].in_use) return;
    pipes[id].readers +|= 1;
}

/// Bump the writer refcount — same idea, for write-side inheritance.
pub fn addWriter(id: u8) void {
    if (id >= MAX_PIPES) return;
    if (!pipes[id].in_use) return;
    pipes[id].writers +|= 1;
}
