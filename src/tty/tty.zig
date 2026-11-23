//! Terminals.
//!
//! A terminal window talks to its programs through two pipes: keys go down
//! one, output comes up the other (ui/desktop.zig). That is all a native
//! program sees of it — it reads the window's key codes raw and echoes for
//! itself. A Linux program expects a tty there: a line it can edit before it
//! is read, echo, a size, modes to change (termios), a foreground process
//! group that Ctrl+C reaches. A `Tty` is that state for one window. The
//! files on the window's two pipe ends carry its id (File.tty); the Linux
//! layer reads through `read` here and answers ioctl from it. Output needs
//! nothing: the window takes "\n" as a new line already.
//!
//! The line is put together in the reader's context, a key at a time from
//! the pipe, so no one but the reading process waits in here. Ctrl+C is the
//! exception: the keyboard interrupt sends SIGINT itself (signalForeground),
//! whether or not anyone is reading.

const std = @import("std");
const process = @import("../proc/process.zig");
const signals = @import("../proc/signals.zig");
const session = @import("../proc/session.zig");
const pipe = @import("../proc/pipe.zig");
const keyboard = @import("../driver.zig").keyboard;
const SpinLock = @import("../proc/spinlock.zig").SpinLock;

/// File.tty of a file that is not a terminal.
pub const NONE: u8 = 0xFF;

const MAX: usize = 16;
const LINE_MAX: usize = 256;
const READY_MAX: usize = 512;
/// Keys one turn of a raw-mode pty's read takes from its pipe.
const KEYS_MAX: usize = 256;

comptime {
    // A line cut short by the change to raw mode and a turn's keys after
    // it fit `ready` together.
    std.debug.assert(LINE_MAX + KEYS_MAX <= READY_MAX);
}

/// struct termios as TCGETS and TCSETS pass it.
pub const Termios = extern struct {
    iflag: u32,
    oflag: u32,
    cflag: u32,
    lflag: u32,
    line: u8 = 0,
    cc: [19]u8,
};

comptime {
    std.debug.assert(@sizeOf(Termios) == 36);
}

// c_iflag
const ICRNL: u32 = 0o400;
const IXON: u32 = 0o2000;
// c_oflag
const OPOST: u32 = 0o1;
const ONLCR: u32 = 0o4;
// c_lflag
const ISIG: u32 = 0o1;
const ICANON: u32 = 0o2;
const ECHO: u32 = 0o10;
const ECHOE: u32 = 0o20;
const ECHOK: u32 = 0o40;
const NOFLSH: u32 = 0o200;
const ECHOCTL: u32 = 0o1000;
const ECHOKE: u32 = 0o4000;
const IEXTEN: u32 = 0o100000;
// c_cc
const VINTR = 0;
const VQUIT = 1;
const VERASE = 2;
const VKILL = 3;
const VEOF = 4;
const VMIN = 6;
const VSUSP = 10;
const VEOL = 11;

/// What `stty sane` gives: a line edited and echoed, signals from keys.
const sane = Termios{
    .iflag = ICRNL | IXON,
    .oflag = OPOST | ONLCR,
    .cflag = 0o277, // B38400 | CS8 | CREAD
    .lflag = ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHOCTL | ECHOKE | IEXTEN,
    .cc = .{ 0x03, 0x1C, 0x7F, 0x15, 0x04, 0, 1, 0, 0x11, 0x13, 0x1A, 0, 0x12, 0x0F, 0x17, 0x16, 0, 0, 0 },
};

pub const Tty = struct {
    in_use: bool = false,
    in_pipe: u8 = 0xFF,
    out_pipe: u8 = 0xFF,
    /// The window's own shell: it gets Ctrl+C the way it always has while
    /// its group is the foreground one.
    owner: u8 = 0xFF,
    termios: Termios = sane,
    rows: u16 = 25,
    cols: u16 = 80,
    /// The process group keys' signals go to, and the session it is of.
    fg_pgid: u32 = 0, // (a)
    sid: u32 = 0,
    /// The line being typed (canonical mode), not yet anyone's to read.
    line: [LINE_MAX]u8 = undefined,
    line_len: usize = 0,
    /// Bytes a read may take: finished lines, or keys as they came.
    ready: [READY_MAX]u8 = undefined,
    ready_head: usize = 0,
    ready_len: usize = 0,
    /// Ctrl+D on an empty line: the next read returns 0.
    eof: bool = false,
    /// A pseudo-terminal (pty.zig): a program is its window, and output
    /// goes to it as a terminal sends it ("\r\n" for "\n" under ONLCR).
    pty: bool = false,
    lock: SpinLock = .{},
};

var ttys: [MAX]Tty = [_]Tty{.{}} ** MAX;
var table_lock: SpinLock = .{};

pub fn get(id: u8) ?*Tty {
    if (id >= MAX or !ttys[id].in_use) return null;
    return &ttys[id];
}

/// A terminal over the window's two pipes, `owner` its shell.
pub fn open(in_pipe: u8, out_pipe: u8, owner: u8, rows: u16, cols: u16) u8 {
    table_lock.acquire();
    defer table_lock.release();
    for (&ttys, 0..) |*t, i| {
        if (t.in_use) continue;
        const o = &process.procs[owner];
        t.* = .{
            .in_use = true,
            .in_pipe = in_pipe,
            .out_pipe = out_pipe,
            .owner = owner,
            .rows = rows,
            .cols = cols,
            .fg_pgid = o.pgid,
            .sid = o.sid,
        };
        return @intCast(i);
    }
    return NONE;
}

/// A pseudo-terminal over its two pipes (pty.zig): no window shell, and no
/// session until one takes it as its controlling terminal.
pub fn openPty(in_pipe: u8, out_pipe: u8) u8 {
    table_lock.acquire();
    defer table_lock.release();
    for (&ttys, 0..) |*t, i| {
        if (t.in_use) continue;
        t.* = .{ .in_use = true, .in_pipe = in_pipe, .out_pipe = out_pipe, .pty = true };
        return @intCast(i);
    }
    return NONE;
}

/// The terminal session `sid` has for its controlling one (/dev/tty).
pub fn ofSession(sid: u32) ?u8 {
    if (sid == 0) return null;
    for (&ttys, 0..) |*t, i| {
        if (t.in_use and t.sid == sid) return @intCast(i);
    }
    return null;
}

/// Session `sid` takes terminal `id` as its controlling one, its group
/// `pgid` in the foreground (TIOCSCTTY, or a session leader's open). A
/// terminal another session has is refused.
pub fn takeControl(id: u8, sid: u32, pgid: u32) bool {
    const t = get(id) orelse return false;
    t.lock.acquire();
    defer t.lock.release();
    // A pty whose session leader is gone is no session's any more.
    if (t.sid != 0 and t.sid != sid and (!t.pty or leaderOf(t.sid) != null)) return false;
    t.sid = sid;
    @atomicStore(u32, &t.fg_pgid, pgid, .release);
    return true;
}

/// True if the process in lead slot `i` has ended: a zombie, unless only
/// its lead's thread ended and other threads of it live on (a main thread
/// that exited first, an execve from another thread).
fn ended(i: usize) bool {
    return process.procs[i].state == .zombie and !process.pinnedLead(i);
}

/// The slot of session `sid`'s leader, a Linux process, while it lives.
fn leaderOf(sid: u32) ?u8 {
    if (sid == 0) return null;
    for (0..process.MAX_PROCS) |i| {
        const p = &process.procs[i];
        if (!session.isProcess(i) or ended(i) or p.personality != .linux) continue;
        if (p.pid_nr == sid and p.sid == sid) return @intCast(i);
    }
    return null;
}

/// The other side of the terminal is gone (a pty's master closed): its
/// session's leader gets SIGHUP, its foreground group SIGHUP and SIGCONT,
/// as on Linux.
pub fn hangup(id: u8) void {
    const t = get(id) orelse return;
    if (leaderOf(t.sid)) |lead| {
        if (process.procs[lead].pgid != @atomicLoad(u32, &t.fg_pgid, .acquire)) {
            _ = signals.sendProcess(lead, signals.SIGHUP, .{});
        }
    }
    signalForeground(id, signals.SIGHUP);
    signalForeground(id, signals.SIGCONT);
}

/// The window is gone. Files that still carry the id read end-of-file from
/// the closed pipe; the slot is free for another window.
pub fn close(id: u8) void {
    const t = get(id) orelse return;
    table_lock.acquire();
    defer table_lock.release();
    t.in_use = false;
}

/// `signo` for the terminal's foreground group: Ctrl+C from the keyboard
/// interrupt, the other keys' from a reader. The window's own shell is
/// signalled by slot, as it was before there were terminals, and passes it
/// on to its native children itself; Linux processes of the group get it
/// each. Interrupt context is fine.
pub fn signalForeground(id: u8, signo: u32) void {
    const t = get(id) orelse return;
    var pgid = @atomicLoad(u32, &t.fg_pgid, .acquire);
    const owner = t.owner;
    // A shell that died without handing the terminal back leaves it to a
    // group with nobody in it: it goes back to the window's shell.
    if (owner < process.MAX_PROCS and process.procs[owner].state != .unused and !session.groupHasMember(pgid, null, null)) {
        pgid = process.procs[owner].pgid;
        @atomicStore(u32, &t.fg_pgid, pgid, .release);
    }
    if (owner < process.MAX_PROCS and process.procs[owner].state != .unused and process.procs[owner].pgid == pgid) {
        _ = signals.sendProcess(owner, signo, .{});
    }
    signalLinuxGroup(pgid, signo, owner);
}

/// `signo` for each Linux process of group `pgid` but `skip`'s slot.
fn signalLinuxGroup(pgid: u32, signo: u32, skip: ?u8) void {
    for (0..process.MAX_PROCS) |i| {
        const p = &process.procs[i];
        if ((skip != null and i == skip.?) or !session.isProcess(i) or ended(i)) continue;
        if (p.personality != .linux or p.pgid != pgid) continue;
        _ = signals.sendProcess(@intCast(i), signo, .{});
    }
}

/// Ctrl+C was pressed in the terminal's window (keyboard interrupt). True:
/// its foreground group got SIGINT. False: the terminal's reader has turned
/// key signals off (an editor in raw mode) and takes the key as a byte.
pub fn interruptKey(id: u8) bool {
    const t = get(id) orelse return false;
    if (t.termios.lflag & ISIG == 0) return false;
    signalForeground(id, signals.SIGINT);
    return true;
}

/// Ctrl+Z or Ctrl+\ pressed in the terminal's window (keyboard interrupt):
/// SIGTSTP or SIGQUIT for a Linux job in the foreground, sent here so a job
/// that never reads the terminal stops too. False: the key is a byte like
/// any other — key signals are off, it is neither key, or the window's own
/// shell is in front, which knows neither signal.
pub fn jobKey(id: u8, ch: u8) bool {
    const t = get(id) orelse return false;
    if (t.termios.lflag & ISIG == 0 or ch == 0) return false;
    const signo: u32 = if (ch == t.termios.cc[VSUSP])
        signals.SIGTSTP
    else if (ch == t.termios.cc[VQUIT])
        signals.SIGQUIT
    else
        return false;
    const owner = t.owner;
    const fg = @atomicLoad(u32, &t.fg_pgid, .acquire);
    if (owner < process.MAX_PROCS and process.procs[owner].state != .unused and process.procs[owner].pgid == fg) return false;
    signalForeground(id, signo);
    return true;
}

/// True while a Linux program runs in the terminal's session: the window
/// then sends every control key down, not only the ones its native shell
/// knows.
pub fn hasLinuxProgram(id: u8) bool {
    const t = get(id) orelse return false;
    for (0..process.MAX_PROCS) |i| {
        const p = &process.procs[i];
        if (session.isProcess(i) and !ended(i) and p.personality == .linux and p.sid == t.sid) return true;
    }
    return false;
}

/// The window now shows `rows` by `cols`: SIGWINCH for the foreground group
/// if that changed.
pub fn setSize(id: u8, rows: u16, cols: u16) void {
    const t = get(id) orelse return;
    if (t.rows == rows and t.cols == cols) return;
    t.rows = rows;
    t.cols = cols;
    signalForeground(id, signals.SIGWINCH);
}

// --- Reading -------------------------------------------------------------------

pub const ReadResult = union(enum) {
    bytes: usize,
    /// A signal for the reader came before any byte.
    interrupted,
    /// Nothing to read and the reader won't wait.
    again,
    /// A reader outside the foreground group that SIGTTIN can't stop.
    io_error,
};

/// A read from a process of the terminal's session that is not of its
/// foreground group: SIGTTIN for the reader's group, which stops it, and
/// the read runs again once it goes on (`.interrupted`); `.io_error` when
/// the signal is blocked or ignored, as on Linux. Null: the read may go on.
fn backgroundRead(t: *Tty) ?ReadResult {
    const me = process.currentPCB() orelse return null;
    const lead = process.leader(me);
    const fg = @atomicLoad(u32, &t.fg_pgid, .acquire);
    if (lead.sid != t.sid or lead.pgid == fg) return null;
    // Stopped by the last SIGTTIN, the read running again: off the CPU
    // until SIGCONT (the picker skips it), then a look again — not another
    // SIGTTIN for every turn round the restart.
    if (@atomicLoad(bool, &me.job_stopped, .acquire)) {
        process.schedule();
        return .interrupted;
    }
    const handler = signals.dispositions(me)[signals.SIGTTIN].handler;
    if (me.signal_mask & signals.bit(signals.SIGTTIN) != 0 or handler == signals.SIG_IGN) return .io_error;
    signalLinuxGroup(lead.pgid, signals.SIGTTIN, null);
    return .interrupted;
}

/// What a key with no byte of its own sends, as a terminal would.
fn keySequence(code: u8) ?[]const u8 {
    return switch (code) {
        keyboard.KEY_UP => "\x1b[A",
        keyboard.KEY_DOWN => "\x1b[B",
        keyboard.KEY_RIGHT => "\x1b[C",
        keyboard.KEY_LEFT => "\x1b[D",
        keyboard.KEY_HOME => "\x1b[H",
        keyboard.KEY_END => "\x1b[F",
        keyboard.KEY_PGUP => "\x1b[5~",
        keyboard.KEY_PGDN => "\x1b[6~",
        keyboard.KEY_DELETE => "\x1b[3~",
        else => null,
    };
}

fn echo(t: *Tty, bytes: []const u8) void {
    if (t.termios.lflag & ECHO == 0) return;
    var rest = bytes;
    if (crlf(t)) {
        while (std.mem.indexOfScalar(u8, rest, '\n')) |nl| {
            _ = pipe.tryWrite(t.out_pipe, rest[0..nl]);
            _ = pipe.tryWrite(t.out_pipe, "\r\n");
            rest = rest[nl + 1 ..];
        }
    }
    _ = pipe.tryWrite(t.out_pipe, rest);
}

/// Output is a terminal's: "\n" goes out as "\r\n". A window takes "\n"
/// as a new line itself; a pty's master gets what a terminal would send.
fn crlf(t: *const Tty) bool {
    return t.pty and t.termios.oflag & (OPOST | ONLCR) == (OPOST | ONLCR);
}

/// What a program writes to terminal `id`, `chunk` in kernel memory, on to
/// its window or master. Returns the bytes of `chunk` taken, or a pipe code
/// (pipe.writeOpt's) when none were.
pub fn output(id: u8, chunk: []const u8, block: bool) usize {
    const t = get(id) orelse return pipe.PIPE_CLOSED;
    if (!crlf(t)) return pipe.writeOpt(t.out_pipe, chunk, block);
    var done: usize = 0;
    while (done < chunk.len) {
        const nl = std.mem.indexOfScalarPos(u8, chunk, done, '\n') orelse chunk.len;
        if (nl > done) {
            const n = pipe.writeOpt(t.out_pipe, chunk[done..nl], block);
            if (n > chunk.len) return if (done > 0) done else n;
            done += n;
            if (done < nl) return done;
        }
        if (nl == chunk.len) break;
        const n = pipe.writeOpt(t.out_pipe, "\r\n", block);
        if (n > 2) return if (done > 0) done else n;
        if (n < 2) {
            // Half of the pair went: the rest has to follow.
            if (n == 1) _ = pipe.writeOpt(t.out_pipe, "\n", true);
            if (n == 0) return done;
        }
        done += 1;
    }
    return done;
}

/// Keys from a pty's master, `chunk` in kernel memory. A key that sends a
/// signal sends it now, as the window's keyboard does, whether or not the
/// foreground job reads; the rest wait in the pipe for the reader's line
/// discipline. Returns the bytes of `chunk` taken, or a pipe code.
pub fn masterInput(id: u8, chunk: []const u8, block: bool) usize {
    const t = get(id) orelse return pipe.PIPE_CLOSED;
    var done: usize = 0;
    while (done < chunk.len) {
        var end = done;
        var signo: u32 = 0;
        while (end < chunk.len) : (end += 1) {
            signo = signalOf(t, chunk[end]);
            if (signo != 0) break;
        }
        if (end > done) {
            const n = pipe.writeOpt(t.in_pipe, chunk[done..end], block);
            if (n > chunk.len) return if (done > 0) done else n;
            done += n;
            if (done < end) return done;
        }
        if (signo == 0) break;
        {
            t.lock.acquire();
            defer t.lock.release();
            echoByte(t, chunk[end]);
            if (t.termios.lflag & NOFLSH == 0) discardLocked(t);
        }
        signalForeground(id, signo);
        done += 1;
    }
    return done;
}

/// The signal key `b` sends at terminal `t`, 0 for none.
fn signalOf(t: *const Tty, b: u8) u32 {
    if (t.termios.lflag & ISIG == 0 or b == 0) return 0;
    if (b == t.termios.cc[VINTR]) return signals.SIGINT;
    if (b == t.termios.cc[VQUIT]) return signals.SIGQUIT;
    if (b == t.termios.cc[VSUSP]) return signals.SIGTSTP;
    return 0;
}

/// Echo one typed byte: itself, or ^X for a control character.
fn echoByte(t: *Tty, b: u8) void {
    if (b >= 0x20 or b == '\n' or b == '\t') return echo(t, &[1]u8{b});
    if (t.termios.lflag & ECHOCTL != 0) echo(t, &[2]u8{ '^', b + 0x40 });
}

fn pushReady(t: *Tty, bytes: []const u8) void {
    // Slide what is left to the front when the tail runs out.
    if (t.ready_len + bytes.len > READY_MAX and t.ready_head > 0) {
        std.mem.copyForwards(u8, t.ready[0 .. t.ready_len - t.ready_head], t.ready[t.ready_head..t.ready_len]);
        t.ready_len -= t.ready_head;
        t.ready_head = 0;
    }
    const room = READY_MAX - t.ready_len;
    const n = @min(room, bytes.len); // typed past a reader that never reads: dropped
    @memcpy(t.ready[t.ready_len..][0..n], bytes[0..n]);
    t.ready_len += n;
}

fn eraseOne(t: *Tty) void {
    if (t.line_len == 0) return;
    t.line_len -= 1;
    const gone = t.line[t.line_len];
    // A control character was echoed as two columns.
    if (gone < 0x20 and gone != '\t' and t.termios.lflag & ECHOCTL != 0) echo(t, "\x08 \x08");
    echo(t, "\x08 \x08");
}

/// One byte from the keyboard side, under the lock.
fn inputByte(t: *Tty, typed: u8, sig: *u32) void {
    const tio = &t.termios;
    var b = typed;
    if (b == '\r' and tio.iflag & ICRNL != 0) b = '\n';

    if (tio.lflag & ISIG != 0 and b != 0) {
        const signo: u32 = if (b == tio.cc[VINTR])
            signals.SIGINT
        else if (b == tio.cc[VQUIT])
            signals.SIGQUIT
        else if (b == tio.cc[VSUSP])
            signals.SIGTSTP
        else
            0;
        if (signo != 0) {
            echoByte(t, b);
            if (tio.lflag & NOFLSH == 0) {
                t.line_len = 0;
                t.ready_head = 0;
                t.ready_len = 0;
            }
            sig.* = signo;
            return;
        }
    }

    if (tio.lflag & ICANON == 0) {
        pushReady(t, &[1]u8{b});
        echoByte(t, b);
        return;
    }
    // The window's Backspace key sends ^H; a terminal's sends DEL.
    if (b == tio.cc[VERASE] or b == 0x08) return eraseOne(t);
    if (b == tio.cc[VKILL] and b != 0) {
        while (t.line_len > 0) eraseOne(t);
        return;
    }
    if (b == tio.cc[VEOF] and b != 0) {
        if (t.line_len == 0) {
            t.eof = true;
        } else {
            pushReady(t, t.line[0..t.line_len]);
            t.line_len = 0;
        }
        return;
    }
    const ends = b == '\n' or (b == tio.cc[VEOL] and b != 0);
    // The last place is kept for what ends the line.
    if (t.line_len < LINE_MAX - 1 or (ends and t.line_len < LINE_MAX)) {
        t.line[t.line_len] = b;
        t.line_len += 1;
        echoByte(t, b);
    }
    if (ends) {
        pushReady(t, t.line[0..t.line_len]);
        t.line_len = 0;
    }
}

/// Up to `out.len` bytes a read may have: all that came (raw mode), or one
/// line (canonical).
fn takeReady(t: *Tty, out: []u8) usize {
    const have = t.ready[t.ready_head..t.ready_len];
    if (have.len == 0) return 0;
    var n = @min(have.len, out.len);
    if (t.termios.lflag & ICANON != 0) {
        if (std.mem.indexOfScalar(u8, have[0..n], '\n')) |nl| n = nl + 1;
    }
    @memcpy(out[0..n], have[0..n]);
    t.ready_head += n;
    if (t.ready_head == t.ready_len) {
        t.ready_head = 0;
        t.ready_len = 0;
    }
    return n;
}

/// A Linux read of terminal `id` into `out` (kernel memory): what the mode
/// makes of the keys, waiting for them unless `nonblock` or the mode says
/// not to (VMIN 0).
pub fn read(id: u8, out: []u8, nonblock: bool) ReadResult {
    const t = get(id) orelse return .{ .bytes = 0 };
    if (backgroundRead(t)) |r| return r;
    if (out.len == 0) return .{ .bytes = 0 };
    while (true) {
        var no_wait = nonblock;
        var raw = false;
        {
            t.lock.acquire();
            defer t.lock.release();
            const n = takeReady(t, out);
            if (n > 0) return .{ .bytes = n };
            if (t.eof) {
                t.eof = false;
                return .{ .bytes = 0 };
            }
            raw = t.termios.lflag & ICANON == 0;
            if (raw and t.termios.cc[VMIN] == 0) no_wait = true;
        }
        // More keys, with no lock held: this may sleep. One at a time as a
        // rule: a window's next key may be its native shell's to read, and
        // a line's end or Ctrl+D is this read's to return at. A pty in raw
        // mode takes as many as `ready`, empty here, has room for.
        var keys: [KEYS_MAX]u8 = undefined;
        const batch = keys[0..if (t.pty and raw) KEYS_MAX else 1];
        const got = if (no_wait) pipe.tryRead(t.in_pipe, batch) else pipe.read(t.in_pipe, batch);
        if (got == pipe.PIPE_INTR) return .interrupted;
        if (got == 0 or got > batch.len) {
            // No key: the reader doesn't wait, or the window is gone.
            return if (nonblock and no_wait) .again else .{ .bytes = 0 };
        }
        var at: usize = 0;
        while (at < got) {
            var signo: u32 = 0;
            {
                t.lock.acquire();
                defer t.lock.release();
                while (at < got and signo == 0) : (at += 1) {
                    var key = batch[at];
                    if (!t.pty) {
                        // The window's Enter key is a line feed; a
                        // terminal's sends a carriage return, which ICRNL
                        // makes a line feed again and a program in raw mode
                        // wants as it is. Its other keys are codes: a pty's
                        // bytes are what they are.
                        if (key == '\n') key = '\r';
                        if (keySequence(key)) |seq| {
                            for (seq) |b| inputByte(t, b, &signo);
                            continue;
                        }
                    }
                    inputByte(t, key, &signo);
                }
            }
            // The reader is of the foreground group as a rule: the signal
            // ends its read on the next turn (pipe.read sees it pending).
            if (signo != 0) signalForeground(id, signo);
        }
    }
}

/// True if a read would not wait: a line or a key is ready, or the end of
/// input is.
pub fn readable(id: u8) bool {
    const t = get(id) orelse return true;
    return t.ready_len > t.ready_head or t.eof;
}

/// Bytes a read could take now (FIONREAD). A pty in raw mode counts what
/// its master sent and no read has looked at yet: a byte each.
pub fn pending(id: u8) usize {
    const t = get(id) orelse return 0;
    // Under the lock: pushReady moves the two counts one after the other.
    t.lock.acquire();
    defer t.lock.release();
    var n = t.ready_len - t.ready_head;
    if (t.pty and t.termios.lflag & ICANON == 0) n += pipe.pending(t.in_pipe);
    return n;
}

/// New modes; `flush` drops what was typed and not yet read (TCSETSF).
pub fn setTermios(id: u8, new: Termios, flush: bool) void {
    const t = get(id) orelse return;
    t.lock.acquire();
    defer t.lock.release();
    // Leaving canonical mode: the line typed so far is input like the rest.
    if (t.termios.lflag & ICANON != 0 and new.lflag & ICANON == 0 and t.line_len > 0) {
        pushReady(t, t.line[0..t.line_len]);
        t.line_len = 0;
    }
    t.termios = new;
    if (flush) discardLocked(t);
}

/// Drop what was typed and not read.
pub fn discardInput(id: u8) void {
    const t = get(id) orelse return;
    t.lock.acquire();
    defer t.lock.release();
    discardLocked(t);
}

fn discardLocked(t: *Tty) void {
    t.line_len = 0;
    t.ready_head = 0;
    t.ready_len = 0;
    t.eof = false;
    var sink: [64]u8 = undefined;
    while (pipe.tryRead(t.in_pipe, &sink) == sink.len) {}
}
