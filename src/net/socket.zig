//! Sockets: what a file of kind `.socket` holds.
//!
//! An internet stream socket sits on a TCP connection or listener slot of
//! net.zig, a datagram socket on one of its UDP sockets, a Unix-domain one
//! on a unix.zig socket. This layer owns what the three have in common: the
//! socket's state, waiting, and the copies to and from the caller's memory.
//!
//! Nothing below waits. A call that has to sleeps here on the readiness the
//! layer below reports (fdpoll.waitFor) and tries again, so a signal, a
//! timeout and O_NONBLOCK are handled in one place.

const std = @import("std");
const net = @import("net.zig");
const unix = @import("unix.zig");
const file = @import("../fs/file.zig");
const process = @import("../proc/process.zig");
const heap = @import("../mm/heap.zig");
const errno = @import("../proc/errno.zig");
const fdpoll = @import("../cpu/ipc/fdpoll.zig");
const usercopy = @import("../cpu/arch/usercopy.zig");
const Mutex = @import("../proc/spinlock.zig").Mutex;

pub const Family = enum(u8) { inet, unix };
pub const Type = enum(u8) { stream, dgram, seqpacket };

pub const Error = error{
    Again,
    Interrupted,
    InProgress,
    Already,
    IsConnected,
    NotConnected,
    Refused,
    Reset,
    TimedOut,
    Unreachable,
    AddrInUse,
    AddrNotAvail,
    Invalid,
    Pipe,
    NoMem,
    NoBufs,
    Fault,
    MsgSize,
    DestAddrRequired,
    NotSupported,
};

const NONE: u8 = 0xFF;

pub const Socket = struct {
    family: Family,
    type: Type,
    /// Serializes the calls that change what the socket is: bind, connect,
    /// listen. Reads and writes go by the fields as they find them.
    setup: Mutex = .{},
    /// inet stream: the connection, once connect or accept gave it one.
    conn: u8 = NONE,
    /// inet stream: the listener, once listen made it one.
    listener: u8 = NONE,
    /// inet datagram: its UDP socket.
    udp: u8 = NONE,
    /// inet: the port bind asked for (a stream uses it at listen or
    /// connect; a datagram socket's is the UDP socket's).
    bound_port: u16 = 0,
    bound: bool = false,
    /// inet datagram: where connect pointed it.
    peer: ?net.Endpoint = null,
    rd_shut: bool = false,
    wr_shut: bool = false,
    /// A failed connection's error was reported once (SO_ERROR).
    error_taken: bool = false,
    ux: ?*unix.Sock = null,
    /// SO_RCVTIMEO and SO_SNDTIMEO in ticks, 0 for none.
    rcv_timeout: u64 = 0,
    snd_timeout: u64 = 0,
    /// Options that are kept and reported, and change nothing.
    reuse_addr: bool = false,
    keep_alive: bool = false,
    no_delay: bool = false,
    broadcast: bool = false,
};

/// A new socket. `owner` is the making process's pid number.
pub fn create(family: Family, kind: Type, owner: u32) Error!*Socket {
    if (family == .inet and kind == .seqpacket) return error.NotSupported;
    const raw = heap.kmallocAligned(@sizeOf(Socket), @alignOf(Socket)) orelse return error.NoMem;
    const s: *Socket = @ptrCast(@alignCast(raw));
    s.* = .{ .family = family, .type = kind };
    errdefer heap.kfree(raw);
    switch (family) {
        .inet => if (kind == .dgram) {
            s.udp = net.udpOpen() orelse return error.NoBufs;
        },
        .unix => s.ux = unix.create(switch (kind) {
            .stream => .stream,
            .dgram => .dgram,
            .seqpacket => .seqpacket,
        }, owner) orelse return error.NoMem,
    }
    return s;
}

/// A socket around what accept took off a listener.
fn wrap(init: Socket) Error!*Socket {
    const raw = heap.kmallocAligned(@sizeOf(Socket), @alignOf(Socket)) orelse return error.NoMem;
    const s: *Socket = @ptrCast(@alignCast(raw));
    s.* = init;
    return s;
}

/// The last reference is gone. A connection finishes its close in the
/// background (net.tcpRelease). May sleep when the socket holds a path name.
pub fn destroy(s: *Socket) void {
    if (s.conn != NONE) net.tcpRelease(s.conn);
    if (s.listener != NONE) net.tcpUnlisten(s.listener);
    if (s.udp != NONE) net.udpClose(s.udp);
    if (s.ux) |u| {
        const inum = unix.destroy(u);
        if (inum != 0) @import("../fs/ext2/ext2.zig").release(inum);
    }
    heap.kfree(@ptrCast(s));
}

// --- The file -------------------------------------------------------------

pub const ops: file.Ops = .{ .read = opRead, .write = opWrite, .release = opRelease, .poll = opPoll, .events = opEvents };
/// The table of a socket bound to a path: letting go of the inode may sleep.
pub const ops_named: file.Ops = .{ .read = opRead, .write = opWrite, .release = opRelease, .release_sleeps = true, .poll = opPoll, .events = opEvents };

pub fn of(f: *file.File) ?*Socket {
    if (f.kind != .socket) return null;
    return @ptrCast(@alignCast(f.obj orelse return null));
}

/// A file for `s`, with one reference; the file owns the socket from here.
pub fn newFile(s: *Socket, nonblock: bool) ?*file.File {
    return file.create(.{ .kind = .socket, .ops = &ops, .obj = s, .access = file.READ_WRITE, .nonblock = nonblock });
}

fn opRead(f: *file.File, _: *process.PCB, buf: [*]u8, count: u32) u32 {
    const span = [1]Span{.{ .va = @intFromPtr(buf), .len = count }};
    const r = recv(of(f).?, &span, .{ .dontwait = f.nonblock }, null) catch |e| return encode(e);
    return @intCast(r.len);
}

fn opWrite(f: *file.File, _: *process.PCB, buf: [*]const u8, count: u32) u32 {
    const span = [1]Span{.{ .va = @intFromPtr(buf), .len = count }};
    const n = send(of(f).?, &span, .{ .dontwait = f.nonblock }, .none) catch |e| return encode(e);
    return @intCast(n);
}

fn opRelease(f: *file.File) void {
    destroy(of(f).?);
}

fn opPoll(f: *file.File, _: *process.PCB) u16 {
    return pollMask(of(f).?);
}

fn opEvents(f: *file.File) u32 {
    return events(of(f).?);
}

/// A failure as read and write return it through the file layer.
fn encode(e: Error) u32 {
    return errno.err(switch (e) {
        error.Again => .EAGAIN,
        error.Interrupted => .EINTR,
        error.NotConnected => .ENOTCONN,
        error.Refused => .ECONNREFUSED,
        error.Reset => .ECONNRESET,
        error.TimedOut => .ETIMEDOUT,
        error.Unreachable => .EHOSTUNREACH,
        error.Pipe => .EPIPE,
        error.NoMem, error.NoBufs => .ENOMEM,
        error.Fault => .EFAULT,
        error.MsgSize => .EMSGSIZE,
        error.DestAddrRequired => .EDESTADDRREQ,
        error.NotSupported => .EOPNOTSUPP,
        else => .EINVAL,
    });
}

// --- Readiness and waiting -------------------------------------------------

const IN_BITS: u16 = fdpoll.POLLIN | fdpoll.POLLRDNORM;
const OUT_BITS: u16 = fdpoll.POLLOUT | fdpoll.POLLWRNORM;

pub fn pollMask(s: *Socket) u16 {
    if (s.ux) |u| return unix.mask(u);
    if (s.udp != NONE) {
        return OUT_BITS | (if (net.udpReadable(s.udp) or s.rd_shut) IN_BITS else 0);
    }
    if (s.listener != NONE) {
        return if (net.tcpListenerPollMask(s.listener) & fdpoll.POLLIN != 0) IN_BITS else 0;
    }
    // Not connected: a write would fail at once, and nothing will arrive.
    if (s.conn == NONE) return fdpoll.POLLOUT | fdpoll.POLLHUP;
    const v = net.tcpView(s.conn);
    if (v.connecting) return 0;
    var m: u16 = 0;
    if (v.readable or v.eof or s.rd_shut) m |= IN_BITS;
    if (v.eof) m |= fdpoll.POLLRDHUP;
    if (v.writable or s.wr_shut) m |= OUT_BITS;
    // A failed connection is ready both ways: the read or write gets the error.
    if (v.failed) m |= fdpoll.POLLERR | IN_BITS | OUT_BITS;
    if (v.eof and s.wr_shut) m |= fdpoll.POLLHUP;
    return m;
}

pub fn events(s: *Socket) u32 {
    if (s.ux) |u| return unix.events(u);
    if (s.udp != NONE) return net.udpEvents(s.udp);
    if (s.listener != NONE) return net.tcpListenerEvents(s.listener);
    if (s.conn != NONE) return net.tcpView(s.conn).events;
    return 0;
}

fn canRead(s: *Socket) bool {
    return pollMask(s) & (fdpoll.POLLIN | fdpoll.POLLERR | fdpoll.POLLHUP) != 0;
}

fn canWrite(s: *Socket) bool {
    return pollMask(s) & (fdpoll.POLLOUT | fdpoll.POLLERR | fdpoll.POLLHUP) != 0;
}

fn connectSettled(s: *Socket) bool {
    return s.conn == NONE or !net.tcpView(s.conn).connecting;
}

/// Sleep until `ready(ctx)`. A timeout (`ticks`, 0 for none) is EAGAIN, as
/// SO_RCVTIMEO and SO_SNDTIMEO have it.
fn wait(ctx: anytype, comptime ready: fn (@TypeOf(ctx)) bool, ticks: u64) Error!void {
    const deadline = if (ticks == 0) 0 else process.tick_count +| ticks +| 1;
    return switch (fdpoll.waitFor(ctx, ready, deadline)) {
        .ready => {},
        .interrupted => error.Interrupted,
        .timed_out => error.Again,
    };
}

/// A kernel buffer for one call's bytes on their way to or from user
/// memory: the caller's small array, or the heap for more.
const Bounce = struct {
    buf: []u8,
    from_heap: bool,

    const MAX: usize = 16 * 1024;

    fn init(small: []u8, want: usize) Error!Bounce {
        if (want <= small.len) return .{ .buf = small[0..want], .from_heap = false };
        const size = @min(want, MAX);
        const p = heap.kmalloc(size) orelse return error.NoMem;
        return .{ .buf = p[0..size], .from_heap = true };
    }

    fn deinit(self: *Bounce) void {
        if (self.from_heap) heap.kfree(self.buf.ptr);
    }
};

// --- Setting up ---------------------------------------------------------------

fn ourAddress(ip: [4]u8) bool {
    return std.mem.eql(u8, &ip, &[4]u8{ 0, 0, 0, 0 }) or net.isLocal(ip);
}

/// 0.0.0.0 as a destination is this machine.
fn destination(ep: net.Endpoint) net.Endpoint {
    if (std.mem.eql(u8, &ep.ip, &[4]u8{ 0, 0, 0, 0 })) return .{ .ip = .{ 127, 0, 0, 1 }, .port = ep.port };
    return ep;
}

pub fn bindInet(s: *Socket, ep: net.Endpoint) Error!void {
    if (s.family != .inet) return error.Invalid;
    if (!ourAddress(ep.ip)) return error.AddrNotAvail;
    s.setup.acquire();
    defer s.setup.release();
    if (s.bound or s.conn != NONE or s.listener != NONE) return error.Invalid;
    if (s.udp != NONE) {
        if (net.udpPort(s.udp) != 0) return error.Invalid;
        if (!net.udpBind(s.udp, ep.port)) return error.AddrInUse;
    } else {
        // The port is taken at listen; one a listener has is refused here.
        if (ep.port != 0 and net.tcpPortListening(ep.port)) return error.AddrInUse;
        s.bound_port = ep.port;
    }
    s.bound = true;
}

/// Bind a Unix socket: `shown` is the address as written, `inum` the socket
/// inode the caller made for a path (0 for an abstract name).
pub fn bindUnix(s: *Socket, shown: []const u8, inum: u32) Error!void {
    const u = s.ux orelse return error.Invalid;
    unix.bind(u, shown, inum) catch |e| return switch (e) {
        error.AddrInUse => error.AddrInUse,
        error.Invalid => error.Invalid,
        error.NoBufs => error.NoBufs,
    };
}

pub fn listen(s: *Socket) Error!void {
    if (s.type == .dgram) return error.NotSupported;
    if (s.ux) |u| {
        if (!unix.listen(u)) return error.Invalid;
        return;
    }
    s.setup.acquire();
    defer s.setup.release();
    if (s.listener != NONE) return;
    if (s.conn != NONE) return error.Invalid;
    s.listener = (if (s.bound_port != 0) net.tcpListen(s.bound_port) else net.tcpListenAny()) orelse return error.AddrInUse;
    s.bound_port = net.tcpListenerPort(s.listener);
    s.bound = true;
}

fn failureOf(why: net.TcpFail) Error {
    return switch (why) {
        .refused => error.Refused,
        .timed_out => error.TimedOut,
        .reset, .none => error.Reset,
    };
}

pub fn connectInet(s: *Socket, to: net.Endpoint, nonblock: bool) Error!void {
    if (s.family != .inet) return error.Invalid;
    const ep = destination(to);
    if (s.udp != NONE) {
        s.peer = ep;
        return;
    }
    {
        s.setup.acquire();
        defer s.setup.release();
        if (s.listener != NONE) return error.Invalid;
        const started = s.conn != NONE and net.tcpView(s.conn).connecting;
        if (started) {
            // A connect a signal cut short and that runs again waits on;
            // one that wouldn't wait is told the first is still out.
            if (nonblock) return error.Already;
        } else {
            if (s.conn != NONE and !net.tcpView(s.conn).failed) return error.IsConnected;
            if (ep.port == 0) return error.AddrNotAvail;
            s.error_taken = false;
            s.rd_shut = false;
            s.wr_shut = false;
            if (s.conn != NONE) {
                // A connection that failed: a new attempt, in its slot.
                if (!net.tcpReconnect(s.conn, ep.ip, ep.port, s.bound_port)) return error.Unreachable;
            } else {
                s.conn = net.tcpConnectStart(ep.ip, ep.port, s.bound_port) orelse return error.Unreachable;
            }
        }
    }
    if (!connectSettled(s)) {
        if (nonblock) return error.InProgress;
        // Interrupted, the handshake goes on: the next connect is EALREADY.
        try wait(s, connectSettled, s.snd_timeout);
    }
    const v = net.tcpView(s.conn);
    if (v.failed) {
        s.error_taken = true;
        return failureOf(v.fail);
    }
}

pub fn connectUnix(s: *Socket, t: unix.Target) Error!void {
    const u = s.ux orelse return error.Invalid;
    unix.connect(u, t) catch |e| return switch (e) {
        error.Refused => error.Refused,
        error.NoMem => error.NoMem,
        error.Again => error.Again,
        error.IsConnected => error.IsConnected,
        error.Invalid => error.Invalid,
    };
}

/// Join two new Unix sockets (socketpair).
pub fn pair(a: *Socket, b: *Socket) void {
    unix.pair(a.ux.?, b.ux.?);
}

fn canAccept(s: *Socket) bool {
    return pollMask(s) & fdpoll.POLLIN != 0;
}

/// The next connection at listener `s`, as a socket of its own.
pub fn accept(s: *Socket, nonblock: bool) Error!*Socket {
    while (true) {
        if (s.ux) |u| {
            if (!unix.isListening(u)) return error.Invalid;
            if (unix.accept(u)) |q| {
                return wrap(.{ .family = .unix, .type = s.type, .ux = q }) catch |e| {
                    _ = unix.destroy(q);
                    return e;
                };
            }
        } else {
            if (s.listener == NONE) return error.Invalid;
            if (net.tcpAccept(s.listener)) |slot| {
                return wrap(.{ .family = .inet, .type = .stream, .conn = slot, .bound = true }) catch |e| {
                    net.tcpRelease(slot);
                    return e;
                };
            }
        }
        if (nonblock) return error.Again;
        try wait(s, canAccept, s.rcv_timeout);
    }
}

pub fn shutdown(s: *Socket, rd: bool, wr: bool) Error!void {
    if (s.ux) |u| {
        unix.shutdown(u, rd, wr);
    } else if (s.udp == NONE) {
        if (s.conn == NONE) return error.NotConnected;
        if (wr) net.tcpShutdownWrite(s.conn);
    }
    if (rd) s.rd_shut = true;
    if (wr) s.wr_shut = true;
    fdpoll.notify();
}

// --- Addresses ---------------------------------------------------------------

pub const Addr = union(enum) {
    /// No address: an unnamed Unix socket.
    none,
    inet: net.Endpoint,
    unix: unix.Name,
};

pub fn localAddr(s: *Socket) Addr {
    if (s.ux) |u| {
        const n = unix.nameOf(u);
        return if (n.len == 0) .none else .{ .unix = n };
    }
    if (s.udp != NONE) return .{ .inet = .{ .ip = .{ 0, 0, 0, 0 }, .port = net.udpPort(s.udp) } };
    if (s.conn != NONE) return .{ .inet = net.tcpLocal(s.conn) };
    return .{ .inet = .{ .ip = .{ 0, 0, 0, 0 }, .port = s.bound_port } };
}

pub fn peerAddr(s: *Socket) Error!Addr {
    if (s.ux) |u| {
        const p = unix.peerOf(u) orelse return error.NotConnected;
        return if (p.name.len == 0) .none else .{ .unix = p.name };
    }
    if (s.udp != NONE) return .{ .inet = s.peer orelse return error.NotConnected };
    if (s.conn == NONE) return error.NotConnected;
    const v = net.tcpView(s.conn);
    if (v.connecting or v.failed) return error.NotConnected;
    return .{ .inet = net.tcpRemote(s.conn) };
}

/// The pid number of the process at the other end of a Unix socket.
pub fn peerOwner(s: *Socket) ?u32 {
    const u = s.ux orelse return null;
    return (unix.peerOf(u) orelse return null).owner;
}

/// The error a connection attempt ended with, once (SO_ERROR).
pub fn takeError(s: *Socket) ?Error {
    if (s.conn == NONE or s.error_taken) return null;
    const v = net.tcpView(s.conn);
    if (!v.failed) return null;
    s.error_taken = true;
    return failureOf(v.fail);
}

pub fn isListening(s: *Socket) bool {
    if (s.ux) |u| return unix.isListening(u);
    return s.listener != NONE;
}

/// Bytes a read would get now (FIONREAD).
pub fn pending(s: *Socket) usize {
    if (s.ux) |u| return unix.pending(u);
    if (s.udp != NONE) return net.udpNextLen(s.udp);
    if (s.conn != NONE) return net.tcpView(s.conn).rx_bytes;
    return 0;
}

// --- Data ---------------------------------------------------------------------

pub const RecvFlags = struct {
    dontwait: bool = false,
    peek: bool = false,
    /// A stream read goes on until the whole length is there.
    waitall: bool = false,
};

pub const Received = struct {
    /// Bytes copied to the caller.
    len: usize,
    /// A message's own length, when more than was asked for (MSG_TRUNC).
    whole: usize = 0,
};

pub const SendFlags = struct { dontwait: bool = false };

pub const Dest = union(enum) {
    /// Where the socket is connected to.
    none,
    inet: net.Endpoint,
    unix: unix.Target,
};

/// A piece of the caller's memory: one buffer, or one element of an iovec.
pub const Span = struct { va: usize, len: usize };

/// A position in a list of spans, moved by the copies to and from them.
const Cursor = struct {
    spans: []const Span,
    index: usize = 0,
    /// Bytes of spans[index] already used.
    used: usize = 0,

    fn total(self: *const Cursor) usize {
        var n: usize = 0;
        for (self.spans) |sp| n +|= sp.len;
        return n;
    }

    /// Copy `bytes` out to the spans; false when the caller's memory is bad.
    fn put(self: *Cursor, bytes: []const u8) bool {
        var done: usize = 0;
        while (done < bytes.len and self.index < self.spans.len) {
            const sp = self.spans[self.index];
            const n = @min(bytes.len - done, sp.len - self.used);
            if (n != 0 and !usercopy.copyToUser(sp.va + self.used, bytes[done..][0..n])) return false;
            done += n;
            self.used += n;
            if (self.used == sp.len) {
                self.index += 1;
                self.used = 0;
            }
        }
        return true;
    }

    /// Fill `out` from the spans; false when the caller's memory is bad.
    fn take(self: *Cursor, out: []u8) bool {
        var done: usize = 0;
        while (done < out.len and self.index < self.spans.len) {
            const sp = self.spans[self.index];
            const n = @min(out.len - done, sp.len - self.used);
            if (n != 0 and !usercopy.copyFromUser(out[done..][0..n], sp.va + self.used)) return false;
            done += n;
            self.used += n;
            if (self.used == sp.len) {
                self.index += 1;
                self.used = 0;
            }
        }
        return true;
    }
};

/// Receive into the caller's memory `spans`; the sender goes to `from` when
/// one is asked for and known.
pub fn recv(s: *Socket, spans: []const Span, fl: RecvFlags, from: ?*Addr) Error!Received {
    if (from) |a| a.* = .none;
    var cursor = Cursor{ .spans = spans };
    const io = &cursor;
    const len = io.total();
    if (s.ux) |u| return if (s.type == .stream) recvUnixStream(s, u, io, len, fl) else recvUnixMessage(s, u, io, len, fl, from);
    if (s.udp != NONE) return recvUdp(s, io, len, fl, from);
    return recvTcp(s, io, len, fl);
}

/// Send the caller's memory `spans`. A stream takes all of it unless told
/// not to wait; a message goes whole or not at all.
pub fn send(s: *Socket, spans: []const Span, fl: SendFlags, to: Dest) Error!usize {
    if (s.wr_shut) return error.Pipe;
    var cursor = Cursor{ .spans = spans };
    const io = &cursor;
    const len = io.total();
    if (s.ux) |u| return if (s.type == .stream) sendUnixStream(s, u, io, len, fl) else sendUnixMessage(s, u, io, len, fl, to);
    if (s.udp != NONE) return sendUdp(s, io, len, to);
    return sendTcp(s, io, len, fl);
}

/// The handshake of a connect that didn't wait must be over before bytes move.
fn settle(s: *Socket, dontwait: bool, ticks: u64) Error!void {
    if (s.conn == NONE) return error.NotConnected;
    if (connectSettled(s)) return;
    if (dontwait) return error.Again;
    try wait(s, connectSettled, ticks);
}

fn recvTcp(s: *Socket, io: *Cursor, len: usize, fl: RecvFlags) Error!Received {
    try settle(s, fl.dontwait, s.rcv_timeout);
    if (len == 0) return .{ .len = 0 };
    var small: [512]u8 = undefined;
    var bounce = try Bounce.init(&small, len);
    defer bounce.deinit();
    var total: usize = 0;
    while (true) {
        if (s.rd_shut) return .{ .len = total };
        const want = @min(len - total, bounce.buf.len);
        const n = if (fl.peek) net.tcpPeek(s.conn, bounce.buf[0..want]) else net.tcpRecv(s.conn, bounce.buf[0..want]);
        if (n > 0) {
            if (!io.put(bounce.buf[0..n])) return if (total > 0) .{ .len = total } else error.Fault;
            total += n;
            if (fl.peek or !fl.waitall or total == len) return .{ .len = total };
            continue;
        }
        const v = net.tcpView(s.conn);
        if (v.readable) continue;
        if (total > 0 and (!fl.waitall or v.failed or v.eof)) return .{ .len = total };
        if (v.failed) return failureOf(v.fail);
        if (v.eof) return .{ .len = 0 };
        if (fl.dontwait) return error.Again;
        wait(s, canRead, s.rcv_timeout) catch |e| return if (total > 0) .{ .len = total } else e;
    }
}

fn sendTcp(s: *Socket, io: *Cursor, len: usize, fl: SendFlags) Error!usize {
    try settle(s, fl.dontwait, s.snd_timeout);
    var small: [512]u8 = undefined;
    var bounce = try Bounce.init(&small, len);
    defer bounce.deinit();
    var total: usize = 0;
    while (total < len) {
        const want = @min(len - total, bounce.buf.len);
        if (!io.take(bounce.buf[0..want])) return if (total > 0) total else error.Fault;
        var off: usize = 0;
        while (off < want) {
            switch (net.tcpSendSome(s.conn, bounce.buf[off..want])) {
                .bytes => |n| off += n,
                .full => {
                    if (fl.dontwait) return if (total + off > 0) total + off else error.Again;
                    wait(s, canWrite, s.snd_timeout) catch |e| return if (total + off > 0) total + off else e;
                },
                .closed => {
                    if (total + off > 0) return total + off;
                    const v = net.tcpView(s.conn);
                    return if (v.failed) failureOf(v.fail) else error.Pipe;
                },
            }
        }
        total += want;
    }
    return total;
}

fn recvUdp(s: *Socket, io: *Cursor, len: usize, fl: RecvFlags, from: ?*Addr) Error!Received {
    var small: [512]u8 = undefined;
    var bounce = try Bounce.init(&small, @min(len, net.UDP_MAX_PAYLOAD));
    defer bounce.deinit();
    while (true) {
        // A connected socket hears its peer alone.
        if (net.udpRecv(s.udp, bounce.buf, fl.peek, s.peer)) |d| {
            const n = @min(d.len, bounce.buf.len);
            if (!io.put(bounce.buf[0..n])) return error.Fault;
            if (from) |a| a.* = .{ .inet = .{ .ip = d.src_ip, .port = d.src_port } };
            return .{ .len = n, .whole = d.len };
        }
        if (s.rd_shut) return .{ .len = 0 };
        if (fl.dontwait) return error.Again;
        try wait(s, canRead, s.rcv_timeout);
    }
}

fn sendUdp(s: *Socket, io: *Cursor, len: usize, to: Dest) Error!usize {
    const ep = switch (to) {
        .inet => |e| destination(e),
        .none => s.peer orelse return error.DestAddrRequired,
        .unix => return error.Invalid,
    };
    if (len > net.UDP_MAX_PAYLOAD) return error.MsgSize;
    var small: [512]u8 = undefined;
    var bounce = try Bounce.init(&small, len);
    defer bounce.deinit();
    if (!io.take(bounce.buf[0..len])) return error.Fault;
    if (!net.udpSendFrom(s.udp, ep.ip, ep.port, bounce.buf[0..len])) return error.Unreachable;
    s.bound = true;
    return len;
}

fn recvUnixStream(s: *Socket, u: *unix.Sock, io: *Cursor, len: usize, fl: RecvFlags) Error!Received {
    if (len == 0) return .{ .len = 0 };
    var small: [512]u8 = undefined;
    var bounce = try Bounce.init(&small, len);
    defer bounce.deinit();
    var total: usize = 0;
    while (true) {
        const want = @min(len - total, bounce.buf.len);
        switch (unix.recvStream(u, bounce.buf[0..want], fl.peek)) {
            .bytes => |n| {
                if (!io.put(bounce.buf[0..n])) return if (total > 0) .{ .len = total } else error.Fault;
                total += n;
                if (fl.peek or !fl.waitall or total == len) return .{ .len = total };
            },
            .eof => return .{ .len = total },
            .not_connected => return error.NotConnected,
            .empty => {
                if (total > 0 and !fl.waitall) return .{ .len = total };
                if (fl.dontwait) return if (total > 0) .{ .len = total } else error.Again;
                wait(s, canRead, s.rcv_timeout) catch |e| return if (total > 0) .{ .len = total } else e;
            },
        }
    }
}

fn sendUnixStream(s: *Socket, u: *unix.Sock, io: *Cursor, len: usize, fl: SendFlags) Error!usize {
    var small: [512]u8 = undefined;
    var bounce = try Bounce.init(&small, len);
    defer bounce.deinit();
    var total: usize = 0;
    while (total < len) {
        const want = @min(len - total, bounce.buf.len);
        if (!io.take(bounce.buf[0..want])) return if (total > 0) total else error.Fault;
        var off: usize = 0;
        while (off < want) {
            switch (unix.sendStream(u, bounce.buf[off..want])) {
                .bytes => |n| off += n,
                .full => {
                    if (fl.dontwait) return if (total + off > 0) total + off else error.Again;
                    wait(s, canWrite, s.snd_timeout) catch |e| return if (total + off > 0) total + off else e;
                },
                .broken => return if (total + off > 0) total + off else error.Pipe,
                .not_connected => return error.NotConnected,
                .refused, .too_big => return error.Invalid,
            }
        }
        total += want;
    }
    return total;
}

fn recvUnixMessage(s: *Socket, u: *unix.Sock, io: *Cursor, len: usize, fl: RecvFlags, from: ?*Addr) Error!Received {
    var small: [512]u8 = undefined;
    var bounce = try Bounce.init(&small, len);
    defer bounce.deinit();
    var name: unix.Name = .{};
    while (true) {
        switch (unix.recvMessage(u, bounce.buf, fl.peek, &name.bytes, &name.len)) {
            .bytes => |whole| {
                const n = @min(whole, bounce.buf.len);
                if (!io.put(bounce.buf[0..n])) return error.Fault;
                if (from) |a| a.* = if (name.len == 0) .none else .{ .unix = name };
                return .{ .len = n, .whole = whole };
            },
            .eof => return .{ .len = 0 },
            .not_connected => return error.NotConnected,
            .empty => {
                if (fl.dontwait) return error.Again;
                try wait(s, canRead, s.rcv_timeout);
            },
        }
    }
}

const Room = struct { u: *unix.Sock, to: ?unix.Target, len: usize };

fn roomFor(r: *Room) bool {
    return unix.messageWouldGo(r.u, r.to, r.len);
}

fn sendUnixMessage(s: *Socket, u: *unix.Sock, io: *Cursor, len: usize, fl: SendFlags, to: Dest) Error!usize {
    const target: ?unix.Target = switch (to) {
        .unix => |t| t,
        .none => null,
        .inet => return error.Invalid,
    };
    if (len > Bounce.MAX) return error.MsgSize;
    var small: [512]u8 = undefined;
    var bounce = try Bounce.init(&small, len);
    defer bounce.deinit();
    if (!io.take(bounce.buf[0..len])) return error.Fault;
    // Waits for room for this message: poll's POLLOUT is a rougher answer.
    var room = Room{ .u = u, .to = target, .len = len };
    while (true) {
        switch (unix.sendMessage(u, target, bounce.buf[0..len])) {
            .bytes => |n| return n,
            .full => {
                if (fl.dontwait) return error.Again;
                try wait(&room, roomFor, s.snd_timeout);
            },
            .broken => return error.Pipe,
            .not_connected => return if (s.type == .dgram) error.DestAddrRequired else error.NotConnected,
            .refused => return error.Refused,
            .too_big => return error.MsgSize,
        }
    }
}
