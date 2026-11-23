//! Linux ioctl: the terminal's calls (proc/tty.zig holds the terminal), and
//! FIONREAD for what else has bytes to count. Every other fd and request is
//! ENOTTY — which is also how isatty() learns a file is not a terminal.

const std = @import("std");
const process = @import("../proc/process.zig");
const tty = @import("../tty/tty.zig");
const pty = @import("../tty/pty.zig");
const file = @import("../fs/file.zig");
const socket = @import("../net/socket.zig");
const usercopy = @import("../cpu/arch/usercopy.zig");
const linux_fs = @import("linux_fs.zig");

const EBADF: i64 = 9;
const EFAULT: i64 = 14;
const EINVAL: i64 = 22;
const ENOTTY: i64 = 25;

inline fn err(e: i64) u64 {
    return @bitCast(-e);
}

const TCGETS: u64 = 0x5401;
const TCSETS: u64 = 0x5402;
const TCSETSW: u64 = 0x5403;
const TCSETSF: u64 = 0x5404;
const TCSBRK: u64 = 0x5409;
const TCXONC: u64 = 0x540A;
const TCFLSH: u64 = 0x540B;
const TIOCSCTTY: u64 = 0x540E;
const TIOCGPGRP: u64 = 0x540F;
const TIOCSPGRP: u64 = 0x5410;
const TIOCOUTQ: u64 = 0x5411;
const TIOCGWINSZ: u64 = 0x5413;
const TIOCSWINSZ: u64 = 0x5414;
const FIONREAD: u64 = 0x541B;
const FIONBIO: u64 = 0x5421;
const TIOCNOTTY: u64 = 0x5422;
const TIOCGSID: u64 = 0x5429;
const TIOCGPTN: u64 = 0x80045430;
const TIOCSPTLCK: u64 = 0x40045431;

const EPERM: i64 = 1;

const Winsize = extern struct { rows: u16, cols: u16, xpixel: u16 = 0, ypixel: u16 = 0 };

fn put(va: u64, value: anytype) u64 {
    return if (usercopy.copyToUser(va, std.mem.asBytes(&value))) 0 else err(EFAULT);
}

/// ioctl(fd, request, arg).
pub fn ioctl(fd: u64, request: u64, arg: u64) u64 {
    const pcb = linux_fs.proc() orelse return err(EFAULT);
    const f = linux_fs.fdFile(pcb, fd) orelse return err(EBADF);
    defer file.put(f);
    // FIONBIO is fcntl's O_NONBLOCK by another name, for any file.
    if (request & 0xFFFF_FFFF == FIONBIO) {
        var on: i32 = 0;
        if (!usercopy.copyFromUser(std.mem.asBytes(&on), arg)) return err(EFAULT);
        f.nonblock = on != 0;
        return 0;
    }
    if (socket.of(f)) |s| return @import("linux_net.zig").ioctl(s, request, arg);
    const id = f.tty;
    // A pipe that is no terminal's has its bytes to count and nothing else.
    if (id == 0xFF and f.kind == .pipe and request & 0xFFFF_FFFF == FIONREAD) {
        return put(arg, @as(i32, @intCast(@import("../proc/pipe.zig").pending(f.pipe_id))));
    }
    const t = tty.get(id) orelse return err(ENOTTY);
    switch (request & 0xFFFF_FFFF) {
        TCGETS => return put(arg, t.termios),
        TCSETS, TCSETSW, TCSETSF => {
            var new: tty.Termios = undefined;
            if (!usercopy.copyFromUser(std.mem.asBytes(&new), arg)) return err(EFAULT);
            tty.setTermios(id, new, request == TCSETSF);
            return 0;
        },
        TIOCGWINSZ => return put(arg, Winsize{ .rows = t.rows, .cols = t.cols }),
        // The window is the size it is; what a program says of it is kept
        // for the next to ask.
        TIOCSWINSZ => {
            var ws: Winsize = undefined;
            if (!usercopy.copyFromUser(std.mem.asBytes(&ws), arg)) return err(EFAULT);
            if (ws.rows != 0 and ws.cols != 0) tty.setSize(id, ws.rows, ws.cols);
            return 0;
        },
        TIOCGPGRP => return put(arg, @as(i32, @intCast(@atomicLoad(u32, &t.fg_pgid, .acquire)))),
        // A shell with job control hands the terminal to each job's group
        // and takes it back.
        TIOCSPGRP => {
            var pgid: i32 = 0;
            if (!usercopy.copyFromUser(std.mem.asBytes(&pgid), arg)) return err(EFAULT);
            if (pgid <= 0) return err(EINVAL);
            @atomicStore(u32, &t.fg_pgid, @intCast(pgid), .release);
            return 0;
        },
        TIOCGSID => return put(arg, @as(i32, @intCast(t.sid))),
        // A session leader takes the terminal for its session (a window's
        // is its shell's session's from the start).
        TIOCSCTTY => {
            if (pcb.pid_nr != pcb.sid) return err(EPERM);
            return if (tty.takeControl(id, pcb.sid, pcb.pgid)) 0 else err(EPERM);
        },
        TIOCNOTTY => return 0,
        // A pty's number, for ptsname, and unlockpt.
        TIOCGPTN => return put(arg, @as(u32, pty.number(f) orelse return err(ENOTTY))),
        TIOCSPTLCK => {
            var locked: i32 = 0;
            if (!usercopy.copyFromUser(std.mem.asBytes(&locked), arg)) return err(EFAULT);
            return if (pty.setLocked(f, locked != 0)) 0 else err(ENOTTY);
        },
        FIONREAD => return put(arg, @as(i32, @intCast(tty.pending(id)))),
        TCFLSH => {
            tty.discardInput(id);
            return 0;
        },
        TIOCOUTQ => return put(arg, @as(i32, 0)),
        TCSBRK, TCXONC => return 0,
        else => return err(ENOTTY),
    }
}
