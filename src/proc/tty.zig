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
const process = @import("process.zig");
const signals = @import("signals.zig");
const session = @import("session.zig");
const pipe = @import("pipe.zig");
const keyboard = @import("../driver/keyboard.zig");
const SpinLock = @import("spinlock.zig").SpinLock;

/// File.tty of a file that is not a terminal.
pub const NONE: u8 = 0xFF;

const MAX: usize = 16;
const LINE_MAX: usize = 256;
const READY_MAX: usize = 512;

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
    for (0..process.MAX_PROCS) |i| {
        const p = &process.procs[i];
        if (i == owner or !session.isProcess(i) or p.state == .zombie) continue;
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

/// True while a Linux program runs in the terminal's session: the window
/// then sends every control key down, not only the ones its native shell
/// knows.
pub fn hasLinuxProgram(id: u8) bool {
    const t = get(id) orelse return false;
    for (0..process.MAX_PROCS) |i| {
        const p = &process.procs[i];
        if (session.isProcess(i) and p.state != .zombie and p.personality == .linux and p.sid == t.sid) return true;
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
};

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
    _ = pipe.tryWrite(t.out_pipe, bytes);
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
    if (out.len == 0) return .{ .bytes = 0 };
    while (true) {
        var no_wait = nonblock;
        {
            t.lock.acquire();
            defer t.lock.release();
            const n = takeReady(t, out);
            if (n > 0) return .{ .bytes = n };
            if (t.eof) {
                t.eof = false;
                return .{ .bytes = 0 };
            }
            if (t.termios.lflag & ICANON == 0 and t.termios.cc[VMIN] == 0) no_wait = true;
        }
        // One more key from the window, with no lock held: this may sleep.
        var key: [1]u8 = undefined;
        const got = if (no_wait) pipe.tryRead(t.in_pipe, &key) else pipe.read(t.in_pipe, &key);
        if (got == pipe.PIPE_INTR) return .interrupted;
        if (got != 1) {
            // No key: the reader doesn't wait, or the window is gone.
            return if (nonblock and no_wait) .again else .{ .bytes = 0 };
        }
        var signo: u32 = 0;
        {
            t.lock.acquire();
            defer t.lock.release();
            if (keySequence(key[0])) |seq| {
                for (seq) |b| inputByte(t, b, &signo);
            } else {
                inputByte(t, key[0], &signo);
            }
        }
        // The reader is of the foreground group as a rule: the signal ends
        // its read on the next turn (pipe.read sees it pending).
        if (signo != 0) signalForeground(id, signo);
    }
}

/// True if a read would not wait: a line or a key is ready, or the end of
/// input is.
pub fn readable(id: u8) bool {
    const t = get(id) orelse return true;
    return t.ready_len > t.ready_head or t.eof;
}

/// Bytes a read could take now (FIONREAD).
pub fn pending(id: u8) usize {
    const t = get(id) orelse return 0;
    return t.ready_len - t.ready_head;
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
