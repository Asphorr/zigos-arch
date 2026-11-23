//! Linux sockets: the calls, their addresses, flags and options. The
//! sockets themselves are net/socket.zig's; this file is the ABI.
//!
//! AF_INET (TCP and UDP over net/net.zig) and AF_UNIX (net/unix.zig). A
//! Unix socket's path is an ext2 socket inode bind makes and holds, so stat,
//! unlink and a second bind see what they would on Linux.

const std = @import("std");
const process = @import("../proc/process.zig");
const signals = @import("../proc/signals.zig");
const socket = @import("../net/socket.zig");
const net = @import("../net/net.zig");
const unix = @import("../net/unix.zig");
const vfs = @import("../fs/vfs.zig");
const file = @import("../fs/file.zig");
const ext2 = @import("../fs/ext2/ext2.zig");
const ext2_inode = @import("../fs/ext2/inode.zig");
const heap = @import("../mm/heap.zig");
const debug = @import("../debug/debug.zig");
const usercopy = @import("../cpu/arch/usercopy.zig");
const linux_fs = @import("linux_fs.zig");
const linux_signal = @import("linux_signal.zig");
const linux_time = @import("linux_time.zig");

const ENOENT: i64 = 2;
const EBADF: i64 = 9;
const EAGAIN: i64 = 11;
const ENOMEM: i64 = 12;
const EFAULT: i64 = 14;
const EINVAL: i64 = 22;
const EMFILE: i64 = 24;
const ENOTTY: i64 = 25;
const EPIPE: i64 = 32;
const ENOTSOCK: i64 = 88;
const EDESTADDRREQ: i64 = 89;
const EMSGSIZE: i64 = 90;
const ENOPROTOOPT: i64 = 92;
const EPROTONOSUPPORT: i64 = 93;
const ESOCKTNOSUPPORT: i64 = 94;
const EOPNOTSUPP: i64 = 95;
const EAFNOSUPPORT: i64 = 97;
const EADDRINUSE: i64 = 98;
const EADDRNOTAVAIL: i64 = 99;
const ENETUNREACH: i64 = 101;
const ECONNRESET: i64 = 104;
const ENOBUFS: i64 = 105;
const EISCONN: i64 = 106;
const ENOTCONN: i64 = 107;
const ETIMEDOUT: i64 = 110;
const ECONNREFUSED: i64 = 111;
const EALREADY: i64 = 114;
const EINPROGRESS: i64 = 115;

inline fn err(e: i64) u64 {
    return @bitCast(-e);
}

fn errOf(e: socket.Error) u64 {
    return err(switch (e) {
        error.Again => EAGAIN,
        // Run again after the handler, or EINTR: the signal layer decides.
        error.Interrupted => linux_signal.ERESTARTSYS,
        error.InProgress => EINPROGRESS,
        error.Already => EALREADY,
        error.IsConnected => EISCONN,
        error.NotConnected => ENOTCONN,
        error.Refused => ECONNREFUSED,
        error.Reset => ECONNRESET,
        error.TimedOut => ETIMEDOUT,
        error.Unreachable => ENETUNREACH,
        error.AddrInUse => EADDRINUSE,
        error.AddrNotAvail => EADDRNOTAVAIL,
        error.Invalid => EINVAL,
        error.Pipe => EPIPE,
        error.NoMem => ENOMEM,
        error.NoBufs => ENOBUFS,
        error.Fault => EFAULT,
        error.MsgSize => EMSGSIZE,
        error.DestAddrRequired => EDESTADDRREQ,
        error.NotSupported => EOPNOTSUPP,
    });
}

const AF_UNSPEC: u16 = 0;
const AF_UNIX: u16 = 1;
const AF_INET: u16 = 2;

const SOCK_STREAM: u64 = 1;
const SOCK_DGRAM: u64 = 2;
const SOCK_SEQPACKET: u64 = 5;
const SOCK_TYPE_MASK: u64 = 0xF;
const SOCK_NONBLOCK: u64 = 0x800;
const SOCK_CLOEXEC: u64 = 0x80000;

const IPPROTO_TCP: u64 = 6;
const IPPROTO_UDP: u64 = 17;

const MSG_PEEK: u64 = 0x2;
const MSG_TRUNC: u64 = 0x20;
const MSG_DONTWAIT: u64 = 0x40;
const MSG_WAITALL: u64 = 0x100;
const MSG_NOSIGNAL: u64 = 0x4000;

const SockaddrIn = extern struct { family: u16, port_be: u16, addr: [4]u8, zero: [8]u8 = [_]u8{0} ** 8 };
/// The family, then the path: sizeof(sockaddr_un).
const UNIX_ADDR_MAX: usize = 2 + unix.NAME_MAX;

// --- Files ---------------------------------------------------------------------

const Held = struct {
    f: *file.File,
    s: *socket.Socket,

    fn put(self: Held) void {
        file.put(self.f);
    }
};

const HeldRead = union(enum) { sock: Held, fail: u64 };

/// The socket behind `fd`, its file held for the call.
fn sockOf(fd: u64) HeldRead {
    const pcb = linux_fs.proc() orelse return .{ .fail = err(EFAULT) };
    const f = linux_fs.fdFile(pcb, fd) orelse return .{ .fail = err(EBADF) };
    const s = socket.of(f) orelse {
        file.put(f);
        return .{ .fail = err(ENOTSOCK) };
    };
    return .{ .sock = .{ .f = f, .s = s } };
}

/// A descriptor for the new socket `s`, which the file owns from here.
fn install(pcb: *process.PCB, s: *socket.Socket, nonblock: bool, cloexec: bool) u64 {
    const f = socket.newFile(s, nonblock) orelse {
        socket.destroy(s);
        return err(ENOMEM);
    };
    const fd = vfs.allocFd(pcb) orelse {
        file.put(f);
        return err(EMFILE);
    };
    file.install(pcb, fd, f, cloexec);
    return fd;
}

const Shape = struct { family: socket.Family, kind: socket.Type };
const ShapeRead = union(enum) { shape: Shape, fail: u64 };

fn shapeOf(domain: u64, type_arg: u64, protocol: u64) ShapeRead {
    if (type_arg & ~(SOCK_TYPE_MASK | SOCK_NONBLOCK | SOCK_CLOEXEC) != 0) return .{ .fail = err(EINVAL) };
    const family: socket.Family = switch (domain) {
        AF_UNIX => .unix,
        AF_INET => .inet,
        // IPv6, netlink, packet sockets: a program that can do without tries
        // the next family.
        else => return .{ .fail = err(EAFNOSUPPORT) },
    };
    const kind: socket.Type = switch (type_arg & SOCK_TYPE_MASK) {
        SOCK_STREAM => .stream,
        SOCK_DGRAM => .dgram,
        SOCK_SEQPACKET => if (family == .unix) .seqpacket else return .{ .fail = err(ESOCKTNOSUPPORT) },
        else => return .{ .fail = err(ESOCKTNOSUPPORT) },
    };
    const proto_ok = switch (family) {
        .unix => protocol == 0,
        .inet => protocol == 0 or protocol == (if (kind == .stream) IPPROTO_TCP else IPPROTO_UDP),
    };
    if (!proto_ok) return .{ .fail = err(EPROTONOSUPPORT) };
    return .{ .shape = .{ .family = family, .kind = kind } };
}

/// socket(domain, type, protocol).
pub fn sysSocket(domain: u64, type_arg: u64, protocol: u64) u64 {
    const shape = switch (shapeOf(domain, type_arg, protocol)) {
        .shape => |sh| sh,
        .fail => |e| return e,
    };
    const pcb = linux_fs.proc() orelse return err(EFAULT);
    const s = socket.create(shape.family, shape.kind, pcb.pid_nr) catch |e| return errOf(e);
    return install(pcb, s, type_arg & SOCK_NONBLOCK != 0, type_arg & SOCK_CLOEXEC != 0);
}

/// socketpair(domain, type, protocol, sv): two connected Unix sockets.
pub fn sysSocketpair(domain: u64, type_arg: u64, protocol: u64, sv_va: u64) u64 {
    const shape = switch (shapeOf(domain, type_arg, protocol)) {
        .shape => |sh| sh,
        .fail => |e| return e,
    };
    if (shape.family != .unix) return err(EOPNOTSUPP);
    const pcb = linux_fs.proc() orelse return err(EFAULT);
    const nonblock = type_arg & SOCK_NONBLOCK != 0;
    const cloexec = type_arg & SOCK_CLOEXEC != 0;
    const a = socket.create(.unix, shape.kind, pcb.pid_nr) catch |e| return errOf(e);
    const b = socket.create(.unix, shape.kind, pcb.pid_nr) catch |e| {
        socket.destroy(a);
        return errOf(e);
    };
    socket.pair(a, b);
    const fa = install(pcb, a, nonblock, cloexec);
    if (@as(i64, @bitCast(fa)) < 0) {
        socket.destroy(b);
        return fa;
    }
    const fb = install(pcb, b, nonblock, cloexec);
    if (@as(i64, @bitCast(fb)) < 0) {
        _ = linux_fs.close(fa);
        return fb;
    }
    const fds = [2]i32{ @intCast(fa), @intCast(fb) };
    if (!usercopy.copyToUser(sv_va, std.mem.asBytes(&fds))) {
        _ = linux_fs.close(fa);
        _ = linux_fs.close(fb);
        return err(EFAULT);
    }
    return 0;
}

// --- Addresses -----------------------------------------------------------------

const UnixName = struct { bytes: [unix.NAME_MAX]u8 = undefined, len: usize = 0 };

const AddrRead = union(enum) {
    inet: net.Endpoint,
    /// sun_path as written: a path without its terminator, or an abstract
    /// name with its leading zero byte.
    unix: UnixName,
    unspec,
    fail: u64,
};

/// The sockaddr of `len` bytes at `va`.
fn readAddr(va: u64, len: u64) AddrRead {
    if (len < 2 or len > UNIX_ADDR_MAX) return .{ .fail = err(EINVAL) };
    var raw: [UNIX_ADDR_MAX]u8 = undefined;
    if (!usercopy.copyFromUser(raw[0..len], va)) return .{ .fail = err(EFAULT) };
    const family = std.mem.readInt(u16, raw[0..2], .little);
    switch (family) {
        AF_INET => {
            if (len < @sizeOf(SockaddrIn)) return .{ .fail = err(EINVAL) };
            return .{ .inet = .{ .ip = raw[4..8].*, .port = std.mem.readInt(u16, raw[2..4], .big) } };
        },
        AF_UNIX => {
            const path = raw[2..len];
            if (path.len == 0) return .{ .fail = err(EINVAL) };
            var name = UnixName{};
            // A path ends at its first zero byte; an abstract name is every
            // byte of the address.
            name.len = if (path[0] == 0) path.len else std.mem.indexOfScalar(u8, path, 0) orelse path.len;
            @memcpy(name.bytes[0..name.len], path[0..name.len]);
            return .{ .unix = name };
        },
        AF_UNSPEC => return .unspec,
        else => return .{ .fail = err(EAFNOSUPPORT) },
    }
}

/// Write `addr` as a sockaddr to the buffer at `va`, whose size the u32 at
/// `len_va` gives and which gets the address's whole size back. A null
/// `va` asks for nothing.
fn writeAddr(addr: socket.Addr, family: socket.Family, va: u64, len_va: u64) u64 {
    if (va == 0 or len_va == 0) return 0;
    var room: u32 = 0;
    if (!usercopy.copyFromUser(std.mem.asBytes(&room), len_va)) return err(EFAULT);
    var raw: [UNIX_ADDR_MAX]u8 = undefined;
    var size: u32 = 2;
    switch (addr) {
        .inet => |ep| {
            const in = SockaddrIn{ .family = AF_INET, .port_be = std.mem.nativeToBig(u16, ep.port), .addr = ep.ip };
            @memcpy(raw[0..@sizeOf(SockaddrIn)], std.mem.asBytes(&in));
            size = @sizeOf(SockaddrIn);
        },
        .unix => |n| {
            std.mem.writeInt(u16, raw[0..2], AF_UNIX, .little);
            @memcpy(raw[2..][0..n.len], n.bytes[0..n.len]);
            size = 2 + @as(u32, n.len);
            // A path is written with its terminator when there is room.
            if (n.len != 0 and n.bytes[0] != 0 and size < UNIX_ADDR_MAX) {
                raw[size] = 0;
                size += 1;
            }
        },
        .none => std.mem.writeInt(u16, raw[0..2], if (family == .unix) AF_UNIX else AF_INET, .little),
    }
    if (!usercopy.copyToUser(va, raw[0..@min(room, size)])) return err(EFAULT);
    if (!usercopy.copyToUser(len_va, std.mem.asBytes(&size))) return err(EFAULT);
    return 0;
}

const TargetRead = union(enum) { target: unix.Target, fail: u64 };

/// What a Unix address names for connect and sendto. `name` must outlive
/// the target.
fn unixTarget(pcb: *process.PCB, name: *const UnixName) TargetRead {
    if (name.bytes[0] == 0) return .{ .target = .{ .abstract = name.bytes[1..name.len] } };
    var buf: [256]u8 = undefined;
    const path = switch (linux_fs.ext2Path(pcb, name.bytes[0..name.len], &buf, .follow)) {
        .path => |p| p,
        .fail => |e| return .{ .fail = e },
    };
    const inum = ext2.lookupPath(path) orelse return .{ .fail = err(ENOENT) };
    const ino = ext2_inode.readInode(inum) orelse return .{ .fail = err(ENOENT) };
    if (!ext2_inode.isSock(&ino)) return .{ .fail = err(ECONNREFUSED) };
    return .{ .target = .{ .inum = inum } };
}

/// bind(fd, addr, addrlen).
pub fn sysBind(fd: u64, addr_va: u64, addr_len: u64) u64 {
    const h = switch (sockOf(fd)) {
        .sock => |h| h,
        .fail => |e| return e,
    };
    defer h.put();
    switch (readAddr(addr_va, addr_len)) {
        .fail => |e| return e,
        .unspec => return err(EAFNOSUPPORT),
        .inet => |ep| {
            if (h.s.family != .inet) return err(EAFNOSUPPORT);
            socket.bindInet(h.s, ep) catch |e| return errOf(e);
            return 0;
        },
        .unix => |name| {
            if (h.s.family != .unix) return err(EAFNOSUPPORT);
            const shown = name.bytes[0..name.len];
            if (shown[0] == 0) {
                socket.bindUnix(h.s, shown, 0) catch |e| return errOf(e);
                return 0;
            }
            const pcb = linux_fs.proc() orelse return err(EFAULT);
            var buf: [256]u8 = undefined;
            const path = switch (linux_fs.ext2Path(pcb, shown, &buf, .nofollow)) {
                .path => |p| p,
                .fail => |e| return e,
            };
            // The name must be new: a socket file left by an earlier run is
            // in the way until it is unlinked.
            if (ext2.lookupPath(path) != null) return err(EADDRINUSE);
            const inum = ext2.createSocketHeld(path) orelse return err(ENOENT);
            socket.bindUnix(h.s, shown, inum) catch |e| {
                _ = ext2.unlinkPath(path);
                ext2.release(inum);
                return errOf(e);
            };
            // Letting go of the inode at the last close may sleep.
            h.f.ops = &socket.ops_named;
            return 0;
        },
    }
}

/// connect(fd, addr, addrlen).
pub fn sysConnect(fd: u64, addr_va: u64, addr_len: u64) u64 {
    const h = switch (sockOf(fd)) {
        .sock => |h| h,
        .fail => |e| return e,
    };
    defer h.put();
    switch (readAddr(addr_va, addr_len)) {
        .fail => |e| return e,
        // Only a datagram socket can be taken apart again; not needed yet.
        .unspec => return err(EAFNOSUPPORT),
        .inet => |ep| {
            if (h.s.family != .inet) return err(EAFNOSUPPORT);
            socket.connectInet(h.s, ep, h.f.nonblock) catch |e| return errOf(e);
            return 0;
        },
        .unix => |name| {
            if (h.s.family != .unix) return err(EAFNOSUPPORT);
            const pcb = linux_fs.proc() orelse return err(EFAULT);
            const target = switch (unixTarget(pcb, &name)) {
                .target => |t| t,
                .fail => |e| return e,
            };
            socket.connectUnix(h.s, target) catch |e| return errOf(e);
            return 0;
        },
    }
}

/// listen(fd, backlog). The queue has the length it has.
pub fn sysListen(fd: u64) u64 {
    const h = switch (sockOf(fd)) {
        .sock => |h| h,
        .fail => |e| return e,
    };
    defer h.put();
    socket.listen(h.s) catch |e| return errOf(e);
    return 0;
}

/// accept4(fd, addr, addrlen, flags); accept is accept4 with no flags.
pub fn sysAccept4(fd: u64, addr_va: u64, len_va: u64, flags: u64) u64 {
    if (flags & ~(SOCK_NONBLOCK | SOCK_CLOEXEC) != 0) return err(EINVAL);
    const h = switch (sockOf(fd)) {
        .sock => |h| h,
        .fail => |e| return e,
    };
    defer h.put();
    const pcb = linux_fs.proc() orelse return err(EFAULT);
    const conn = socket.accept(h.s, h.f.nonblock) catch |e| return errOf(e);
    const peer = socket.peerAddr(conn) catch socket.Addr.none;
    const new_fd = install(pcb, conn, flags & SOCK_NONBLOCK != 0, flags & SOCK_CLOEXEC != 0);
    if (@as(i64, @bitCast(new_fd)) < 0) return new_fd;
    const wrote = writeAddr(peer, h.s.family, addr_va, len_va);
    if (wrote != 0) {
        _ = linux_fs.close(new_fd);
        return wrote;
    }
    return new_fd;
}

/// getsockname(fd, addr, addrlen).
pub fn sysGetsockname(fd: u64, addr_va: u64, len_va: u64) u64 {
    const h = switch (sockOf(fd)) {
        .sock => |h| h,
        .fail => |e| return e,
    };
    defer h.put();
    if (addr_va == 0 or len_va == 0) return err(EFAULT);
    return writeAddr(socket.localAddr(h.s), h.s.family, addr_va, len_va);
}

/// getpeername(fd, addr, addrlen).
pub fn sysGetpeername(fd: u64, addr_va: u64, len_va: u64) u64 {
    const h = switch (sockOf(fd)) {
        .sock => |h| h,
        .fail => |e| return e,
    };
    defer h.put();
    if (addr_va == 0 or len_va == 0) return err(EFAULT);
    const peer = socket.peerAddr(h.s) catch |e| return errOf(e);
    return writeAddr(peer, h.s.family, addr_va, len_va);
}

/// shutdown(fd, how).
pub fn sysShutdown(fd: u64, how: u64) u64 {
    if (how > 2) return err(EINVAL);
    const h = switch (sockOf(fd)) {
        .sock => |h| h,
        .fail => |e| return e,
    };
    defer h.put();
    socket.shutdown(h.s, how != 1, how != 0) catch |e| return errOf(e);
    return 0;
}

// --- Data ----------------------------------------------------------------------

const Iovec = extern struct { base: u64, len: u64 };
const MAX_IOV: usize = 64;

/// The end of a send that failed: EPIPE raises SIGPIPE unless the caller
/// asked for none.
fn sendFailed(e: socket.Error, flags: u64) u64 {
    if (e == error.Pipe and flags & MSG_NOSIGNAL == 0) {
        if (process.currentPCB()) |me| {
            _ = signals.sendInfo(@intCast(process.getCurrentPid()), signals.SIGPIPE, .{
                .code = signals.SI_USER_CODE,
                .pid = process.leader(me).pid_nr,
            });
        }
    }
    return errOf(e);
}

const DestRead = union(enum) { dest: socket.Dest, fail: u64 };

/// Where a send with an address goes. `name` is storage for a Unix one.
fn destOf(h: Held, addr_va: u64, addr_len: u64, name: *UnixName) DestRead {
    if (addr_va == 0) return .{ .dest = .none };
    switch (readAddr(addr_va, addr_len)) {
        .fail => |e| return .{ .fail = e },
        .unspec => return .{ .fail = err(EAFNOSUPPORT) },
        .inet => |ep| {
            if (h.s.family != .inet) return .{ .fail = err(EAFNOSUPPORT) };
            // A stream is where it is connected to, whatever the address says.
            return .{ .dest = if (h.s.type == .stream) .none else .{ .inet = ep } };
        },
        .unix => |n| {
            if (h.s.family != .unix) return .{ .fail = err(EAFNOSUPPORT) };
            if (h.s.type == .stream) return .{ .dest = .none };
            name.* = n;
            const pcb = linux_fs.proc() orelse return .{ .fail = err(EFAULT) };
            return switch (unixTarget(pcb, name)) {
                .target => |t| .{ .dest = .{ .unix = t } },
                .fail => |e| .{ .fail = e },
            };
        },
    }
}

fn recvFlags(h: Held, flags: u64) socket.RecvFlags {
    return .{
        .dontwait = h.f.nonblock or flags & MSG_DONTWAIT != 0,
        .peek = flags & MSG_PEEK != 0,
        .waitall = flags & MSG_WAITALL != 0,
    };
}

/// sendto(fd, buf, len, flags, addr, addrlen); send is sendto with no address.
pub fn sysSendto(fd: u64, buf_va: u64, len: u64, flags: u64, addr_va: u64, addr_len: u64) u64 {
    const h = switch (sockOf(fd)) {
        .sock => |h| h,
        .fail => |e| return e,
    };
    defer h.put();
    var name: UnixName = .{};
    const dest = switch (destOf(h, addr_va, addr_len, &name)) {
        .dest => |d| d,
        .fail => |e| return e,
    };
    const span = [1]socket.Span{.{ .va = buf_va, .len = len }};
    const fl = socket.SendFlags{ .dontwait = h.f.nonblock or flags & MSG_DONTWAIT != 0 };
    return socket.send(h.s, &span, fl, dest) catch |e| sendFailed(e, flags);
}

/// recvfrom(fd, buf, len, flags, addr, addrlen); recv is recvfrom with no address.
pub fn sysRecvfrom(fd: u64, buf_va: u64, len: u64, flags: u64, addr_va: u64, len_va: u64) u64 {
    const h = switch (sockOf(fd)) {
        .sock => |h| h,
        .fail => |e| return e,
    };
    defer h.put();
    const span = [1]socket.Span{.{ .va = buf_va, .len = len }};
    var from: socket.Addr = .none;
    const got = socket.recv(h.s, &span, recvFlags(h, flags), &from) catch |e| return errOf(e);
    // A stream has no sender to name: the length comes back zero.
    if (h.s.type != .stream or h.s.family == .unix) {
        const wrote = writeAddr(from, h.s.family, addr_va, len_va);
        if (wrote != 0) return wrote;
    }
    return if (flags & MSG_TRUNC != 0 and got.whole > got.len) got.whole else got.len;
}

const Msghdr = extern struct {
    name: u64,
    namelen: u32,
    _pad0: u32 = 0,
    iov: u64,
    iovlen: u64,
    control: u64,
    controllen: u64,
    flags: i32,
    _pad1: u32 = 0,
};

const SOL_SOCKET: i32 = 1;
const SCM_RIGHTS: i32 = 1;
const Cmsghdr = extern struct { len: u64, level: i32, type: i32 };

const SpansRead = union(enum) { count: usize, fail: u64 };

/// The iovec of a message as spans.
fn readSpans(iov_va: u64, iovlen: u64, out: *[MAX_IOV]socket.Span) SpansRead {
    if (iovlen > MAX_IOV) return .{ .fail = err(EMSGSIZE) };
    const n: usize = @intCast(iovlen);
    var iov: [MAX_IOV]Iovec = undefined;
    if (n != 0 and !usercopy.copyFromUser(std.mem.sliceAsBytes(iov[0..n]), iov_va)) return .{ .fail = err(EFAULT) };
    for (iov[0..n], 0..) |v, i| out[i] = .{ .va = v.base, .len = v.len };
    return .{ .count = n };
}

/// True if the control data of `msg` passes descriptors, which no socket
/// here carries yet.
fn passesFds(msg: *const Msghdr) bool {
    if (msg.control == 0) return false;
    // The lengths are the program's: nothing here may overflow on them.
    var at: u64 = 0;
    while (msg.controllen -| at >= @sizeOf(Cmsghdr)) {
        var c: Cmsghdr = undefined;
        if (!usercopy.copyFromUser(std.mem.asBytes(&c), msg.control +% at)) return false;
        if (c.len < @sizeOf(Cmsghdr)) return false;
        if (c.level == SOL_SOCKET and c.type == SCM_RIGHTS) return true;
        at +|= (c.len +| 7) & ~@as(u64, 7);
    }
    return false;
}

fn sendOne(h: Held, msg: *const Msghdr, flags: u64) u64 {
    if (passesFds(msg)) {
        debug.klog("[linux] pid={d} sendmsg with SCM_RIGHTS: not carried yet\n", .{process.getCurrentPid()});
        return err(EOPNOTSUPP);
    }
    var name: UnixName = .{};
    const dest = switch (destOf(h, msg.name, msg.namelen, &name)) {
        .dest => |d| d,
        .fail => |e| return e,
    };
    var spans: [MAX_IOV]socket.Span = undefined;
    const n = switch (readSpans(msg.iov, msg.iovlen, &spans)) {
        .count => |c| c,
        .fail => |e| return e,
    };
    const fl = socket.SendFlags{ .dontwait = h.f.nonblock or flags & MSG_DONTWAIT != 0 };
    return socket.send(h.s, spans[0..n], fl, dest) catch |e| sendFailed(e, flags);
}

/// Receive one message into `msg`, whose name length, control length and
/// flags are updated in the copy; the caller writes it back.
fn recvOne(h: Held, msg: *Msghdr, msg_va: u64, flags: u64) u64 {
    var spans: [MAX_IOV]socket.Span = undefined;
    const n = switch (readSpans(msg.iov, msg.iovlen, &spans)) {
        .count => |c| c,
        .fail => |e| return e,
    };
    var from: socket.Addr = .none;
    const got = socket.recv(h.s, spans[0..n], recvFlags(h, flags), &from) catch |e| return errOf(e);
    if (msg.name != 0) {
        const named = h.s.type != .stream or h.s.family == .unix;
        if (named) {
            const wrote = writeAddr(from, h.s.family, msg.name, msg_va + @offsetOf(Msghdr, "namelen"));
            if (wrote != 0) return wrote;
        } else {
            const zero: u32 = 0;
            if (!usercopy.copyToUser(msg_va + @offsetOf(Msghdr, "namelen"), std.mem.asBytes(&zero))) return err(EFAULT);
        }
    }
    const no_control: u64 = 0;
    const out_flags: i32 = if (got.whole > got.len) @intCast(MSG_TRUNC) else 0;
    if (!usercopy.copyToUser(msg_va + @offsetOf(Msghdr, "controllen"), std.mem.asBytes(&no_control))) return err(EFAULT);
    if (!usercopy.copyToUser(msg_va + @offsetOf(Msghdr, "flags"), std.mem.asBytes(&out_flags))) return err(EFAULT);
    return if (flags & MSG_TRUNC != 0 and got.whole > got.len) got.whole else got.len;
}

/// sendmsg(fd, msg, flags).
pub fn sysSendmsg(fd: u64, msg_va: u64, flags: u64) u64 {
    const h = switch (sockOf(fd)) {
        .sock => |h| h,
        .fail => |e| return e,
    };
    defer h.put();
    var msg: Msghdr = undefined;
    if (!usercopy.copyFromUser(std.mem.asBytes(&msg), msg_va)) return err(EFAULT);
    return sendOne(h, &msg, flags);
}

/// recvmsg(fd, msg, flags).
pub fn sysRecvmsg(fd: u64, msg_va: u64, flags: u64) u64 {
    const h = switch (sockOf(fd)) {
        .sock => |h| h,
        .fail => |e| return e,
    };
    defer h.put();
    var msg: Msghdr = undefined;
    if (!usercopy.copyFromUser(std.mem.asBytes(&msg), msg_va)) return err(EFAULT);
    return recvOne(h, &msg, msg_va, flags);
}

const Mmsghdr = extern struct { hdr: Msghdr, len: u32, _pad: u32 = 0 };

/// sendmmsg(fd, msgvec, vlen, flags): messages sent, or the first one's error.
pub fn sysSendmmsg(fd: u64, vec_va: u64, vlen: u64, flags: u64) u64 {
    const h = switch (sockOf(fd)) {
        .sock => |h| h,
        .fail => |e| return e,
    };
    defer h.put();
    var sent: u64 = 0;
    while (sent < @min(vlen, 1024)) : (sent += 1) {
        const at = vec_va + sent * @sizeOf(Mmsghdr);
        var m: Mmsghdr = undefined;
        if (!usercopy.copyFromUser(std.mem.asBytes(&m), at)) return if (sent > 0) sent else err(EFAULT);
        const r = sendOne(h, &m.hdr, flags);
        if (@as(i64, @bitCast(r)) < 0) return if (sent > 0) sent else r;
        const len: u32 = @intCast(r);
        if (!usercopy.copyToUser(at + @offsetOf(Mmsghdr, "len"), std.mem.asBytes(&len))) return err(EFAULT);
    }
    return sent;
}

/// recvmmsg(fd, msgvec, vlen, flags, timeout): the first message is waited
/// for as recvmsg would; the rest are taken only if already there.
pub fn sysRecvmmsg(fd: u64, vec_va: u64, vlen: u64, flags: u64) u64 {
    const h = switch (sockOf(fd)) {
        .sock => |h| h,
        .fail => |e| return e,
    };
    defer h.put();
    var got: u64 = 0;
    while (got < @min(vlen, 1024)) : (got += 1) {
        const at = vec_va + got * @sizeOf(Mmsghdr);
        var m: Mmsghdr = undefined;
        if (!usercopy.copyFromUser(std.mem.asBytes(&m), at)) return if (got > 0) got else err(EFAULT);
        const r = recvOne(h, &m.hdr, at, if (got == 0) flags else flags | MSG_DONTWAIT);
        if (@as(i64, @bitCast(r)) < 0) return if (got > 0) got else r;
        const len: u32 = @intCast(r);
        if (!usercopy.copyToUser(at + @offsetOf(Mmsghdr, "len"), std.mem.asBytes(&len))) return err(EFAULT);
    }
    return got;
}

// --- Options -------------------------------------------------------------------

const SO_REUSEADDR: u64 = 2;
const SO_TYPE: u64 = 3;
const SO_ERROR: u64 = 4;
const SO_BROADCAST: u64 = 6;
const SO_SNDBUF: u64 = 7;
const SO_RCVBUF: u64 = 8;
const SO_KEEPALIVE: u64 = 9;
const SO_LINGER: u64 = 13;
const SO_REUSEPORT: u64 = 15;
const SO_PEERCRED: u64 = 17;
const SO_RCVTIMEO: u64 = 20;
const SO_SNDTIMEO: u64 = 21;
const SO_ACCEPTCONN: u64 = 30;
const SO_PROTOCOL: u64 = 38;
const SO_DOMAIN: u64 = 39;
const TCP_NODELAY: u64 = 1;

const Timeval = extern struct { sec: i64, usec: i64 };
const Ucred = extern struct { pid: i32, uid: u32, gid: u32 };
/// What SO_SNDBUF and SO_RCVBUF answer: the rings are the size they are.
const BUFFER_SIZE: i32 = 16 * 1024;

fn ticksOf(tv: Timeval) ?u64 {
    if (tv.sec < 0 or tv.usec < 0 or tv.usec >= 1_000_000) return null;
    const ns = @as(u64, @intCast(tv.sec)) *| 1_000_000_000 +| @as(u64, @intCast(tv.usec)) * 1000;
    return std.math.divCeil(u64, ns, linux_time.TICK_NS) catch unreachable;
}

fn timevalOf(ticks: u64) Timeval {
    const us = ticks *| (linux_time.TICK_NS / 1000);
    return .{ .sec = @intCast(us / 1_000_000), .usec = @intCast(us % 1_000_000) };
}

/// setsockopt(fd, level, optname, optval, optlen). What changes nothing
/// here — buffer sizes, lingering, quality of service — is accepted.
pub fn sysSetsockopt(fd: u64, level: u64, name: u64, val_va: u64, len: u64) u64 {
    const h = switch (sockOf(fd)) {
        .sock => |h| h,
        .fail => |e| return e,
    };
    defer h.put();
    if (level == SOL_SOCKET and (name == SO_RCVTIMEO or name == SO_SNDTIMEO)) {
        var tv: Timeval = undefined;
        if (len < @sizeOf(Timeval)) return err(EINVAL);
        if (!usercopy.copyFromUser(std.mem.asBytes(&tv), val_va)) return err(EFAULT);
        const ticks = ticksOf(tv) orelse return err(EINVAL);
        if (name == SO_RCVTIMEO) h.s.rcv_timeout = ticks else h.s.snd_timeout = ticks;
        return 0;
    }
    var int_val: i32 = 0;
    if (len >= 4 and !usercopy.copyFromUser(std.mem.asBytes(&int_val), val_va)) return err(EFAULT);
    const on = int_val != 0;
    if (level == SOL_SOCKET) switch (name) {
        SO_REUSEADDR, SO_REUSEPORT => h.s.reuse_addr = on,
        SO_KEEPALIVE => h.s.keep_alive = on,
        SO_BROADCAST => h.s.broadcast = on,
        else => {},
    } else if (level == IPPROTO_TCP and name == TCP_NODELAY) {
        h.s.no_delay = on;
    }
    return 0;
}

/// getsockopt(fd, level, optname, optval, optlen).
pub fn sysGetsockopt(fd: u64, level: u64, name: u64, val_va: u64, len_va: u64) u64 {
    const h = switch (sockOf(fd)) {
        .sock => |h| h,
        .fail => |e| return e,
    };
    defer h.put();
    var room: u32 = 0;
    if (!usercopy.copyFromUser(std.mem.asBytes(&room), len_va)) return err(EFAULT);
    const s = h.s;
    var tv: Timeval = undefined;
    var cred: Ucred = undefined;
    var int_val: i32 = 0;
    var bytes: []const u8 = std.mem.asBytes(&int_val);
    if (level == SOL_SOCKET) {
        switch (name) {
            SO_ERROR => int_val = if (socket.takeError(s)) |e| @intCast(-@as(i64, @bitCast(errOf(e)))) else 0,
            SO_TYPE => int_val = switch (s.type) {
                .stream => 1,
                .dgram => 2,
                .seqpacket => 5,
            },
            SO_DOMAIN => int_val = if (s.family == .unix) AF_UNIX else AF_INET,
            SO_PROTOCOL => int_val = if (s.family == .unix) 0 else if (s.type == .stream) 6 else 17,
            SO_ACCEPTCONN => int_val = @intFromBool(socket.isListening(s)),
            SO_REUSEADDR, SO_REUSEPORT => int_val = @intFromBool(s.reuse_addr),
            SO_KEEPALIVE => int_val = @intFromBool(s.keep_alive),
            SO_BROADCAST => int_val = @intFromBool(s.broadcast),
            SO_SNDBUF, SO_RCVBUF => int_val = BUFFER_SIZE,
            SO_RCVTIMEO, SO_SNDTIMEO => {
                tv = timevalOf(if (name == SO_RCVTIMEO) s.rcv_timeout else s.snd_timeout);
                bytes = std.mem.asBytes(&tv);
            },
            SO_PEERCRED => {
                const pid = socket.peerOwner(s) orelse return err(ENOTCONN);
                cred = .{ .pid = @intCast(pid), .uid = 0, .gid = 0 };
                bytes = std.mem.asBytes(&cred);
            },
            SO_LINGER => {
                const linger = [2]i32{ 0, 0 };
                if (!usercopy.copyToUser(val_va, std.mem.asBytes(&linger)[0..@min(room, 8)])) return err(EFAULT);
                const size: u32 = @min(room, 8);
                return if (usercopy.copyToUser(len_va, std.mem.asBytes(&size))) 0 else err(EFAULT);
            },
            else => return err(ENOPROTOOPT),
        }
    } else if (level == IPPROTO_TCP and name == TCP_NODELAY) {
        int_val = @intFromBool(s.no_delay);
    } else {
        return err(ENOPROTOOPT);
    }
    const size: u32 = @intCast(@min(room, bytes.len));
    if (!usercopy.copyToUser(val_va, bytes[0..size])) return err(EFAULT);
    return if (usercopy.copyToUser(len_va, std.mem.asBytes(&size))) 0 else err(EFAULT);
}

const FIONREAD: u64 = 0x541B;

/// ioctl on a socket: the bytes waiting. The rest (interface lists, routes)
/// is not here.
pub fn ioctl(s: *socket.Socket, request: u64, arg: u64) u64 {
    switch (request & 0xFFFF_FFFF) {
        FIONREAD => {
            const n: i32 = @intCast(@min(socket.pending(s), std.math.maxInt(i32)));
            return if (usercopy.copyToUser(arg, std.mem.asBytes(&n))) 0 else err(EFAULT);
        },
        else => return err(ENOTTY),
    }
}
