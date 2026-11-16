//! Unix-domain sockets: byte streams, datagrams and sequenced packets
//! between the processes of this machine, joined as a pair or by name.
//!
//! A socket receives into its own ring; the sender writes there. A stream
//! is two sockets that name each other as `peer`; a datagram socket names
//! the one it is connected to, if any. A name is a path — an ext2 socket
//! inode the caller made, held while the socket is bound — or an abstract
//! string.
//!
//! One lock covers every socket here: a peer is only ever followed under
//! it, and a socket going away clears every pointer to it first (destroy).
//! Bytes go in and out of kernel buffers under the lock; the callers copy
//! to and from user memory outside it, and wait outside it.

const std = @import("std");
const heap = @import("../mm/heap.zig");
const SpinLock = @import("../proc/spinlock.zig").SpinLock;
const fdpoll = @import("../cpu/ipc/fdpoll.zig");

pub const Kind = enum(u8) { stream, dgram, seqpacket };

/// sizeof(sockaddr_un.sun_path).
pub const NAME_MAX: usize = 108;

const RING: u32 = 32 * 1024;
const BACKLOG: usize = 16;
const MAX_BOUND: usize = 32;
/// A message's header in a ring: its length (u32) and the length of the
/// sender's name (u8), which follows it.
const MSG_HDR: u32 = 5;

pub const Sock = struct {
    kind: Kind,
    ring: [*]u8,
    head: u32 = 0,
    used: u32 = 0,
    /// The other end of a stream; what a connected datagram socket sends to.
    peer: ?*Sock = null,
    /// A peer there was is gone: nothing more arrives, and sends fail.
    peer_gone: bool = false,
    /// The peer shut its sending side (or is gone): reads end once the
    /// ring is empty.
    peer_done: bool = false,
    rd_shut: bool = false,
    wr_shut: bool = false,
    /// It was connected, by connect, accept or pair.
    was_connected: bool = false,
    listening: bool = false,
    backlog: [BACKLOG]?*Sock = [_]?*Sock{null} ** BACKLOG,
    backlog_head: u8 = 0,
    backlog_count: u8 = 0,
    name: [NAME_MAX]u8 = undefined,
    name_len: u8 = 0,
    bound: bool = false,
    /// The ext2 inode a path name stands on; 0 for none or an abstract one.
    inum: u32 = 0,
    /// What arrived, what left room, who connected or went: what an
    /// edge-triggered watcher compares.
    events: u32 = 0,
    /// The process that made it, as a pid number (SO_PEERCRED).
    owner: u32 = 0,
    /// Every socket there is, for destroy's sweep.
    next: ?*Sock = null,
};

var lock: SpinLock = .{};
var all: ?*Sock = null;
var bound: [MAX_BOUND]?*Sock = [_]?*Sock{null} ** MAX_BOUND;

/// A new socket, joined to nothing. Null when memory is out.
pub fn create(kind: Kind, owner: u32) ?*Sock {
    const raw = heap.kmallocAligned(@sizeOf(Sock), @alignOf(Sock)) orelse return null;
    const ring = heap.kmalloc(RING) orelse {
        heap.kfree(raw);
        return null;
    };
    const s: *Sock = @ptrCast(@alignCast(raw));
    s.* = .{ .kind = kind, .ring = ring, .owner = owner };
    lock.acquire();
    s.next = all;
    all = s;
    lock.release();
    return s;
}

/// Take `s` off the list and clear every pointer to it. Lock held.
fn detach(s: *Sock) void {
    var link: *?*Sock = &all;
    while (link.*) |x| {
        if (x == s) {
            link.* = x.next;
            break;
        }
        link = &x.next;
    }
    var it = all;
    while (it) |x| : (it = x.next) {
        if (x.peer != s) continue;
        x.peer = null;
        x.peer_gone = true;
        x.peer_done = true;
        x.events +%= 1;
    }
    for (&bound) |*b| {
        if (b.* == s) b.* = null;
    }
}

fn free(s: *Sock) void {
    heap.kfree(s.ring);
    heap.kfree(@ptrCast(s));
}

/// `s` is closed: its peers see the end, the connections nobody accepted
/// are dropped with it. Returns the inode its name held (0: none), for the
/// caller to let go of — that may sleep, this doesn't.
pub fn destroy(s: *Sock) u32 {
    var unaccepted: [BACKLOG]?*Sock = [_]?*Sock{null} ** BACKLOG;
    lock.acquire();
    var n: usize = 0;
    while (s.backlog_count > 0) : (n += 1) {
        const q = s.backlog[s.backlog_head].?;
        s.backlog_head = @intCast((s.backlog_head + 1) % BACKLOG);
        s.backlog_count -= 1;
        detach(q);
        unaccepted[n] = q;
    }
    detach(s);
    lock.release();
    for (unaccepted[0..n]) |q| free(q.?);
    const inum = s.inum;
    free(s);
    fdpoll.notify();
    return inum;
}

/// Join `a` and `b` as a connected pair (socketpair).
pub fn pair(a: *Sock, b: *Sock) void {
    lock.acquire();
    defer lock.release();
    a.peer = b;
    b.peer = a;
    a.was_connected = true;
    b.was_connected = true;
}

pub const Target = union(enum) {
    /// The socket inode a path names.
    inum: u32,
    /// An abstract name, without its leading zero byte.
    abstract: []const u8,
};

/// Lock held.
fn lookup(t: Target) ?*Sock {
    for (bound) |b| {
        const s = b orelse continue;
        switch (t) {
            .inum => |i| if (s.inum == i) return s,
            .abstract => |name| if (s.inum == 0 and s.name_len >= 1 and std.mem.eql(u8, s.name[1..s.name_len], name)) return s,
        }
    }
    return null;
}

pub const BindError = error{ AddrInUse, Invalid, NoBufs };

/// Give `s` a name: `shown` is the address as the program wrote it (what
/// getsockname returns; an abstract one starts with a zero byte), `inum`
/// the socket inode a path stands on, 0 for an abstract name.
pub fn bind(s: *Sock, shown: []const u8, inum: u32) BindError!void {
    if (shown.len == 0 or shown.len > NAME_MAX) return error.Invalid;
    lock.acquire();
    defer lock.release();
    if (s.bound) return error.Invalid;
    if (inum == 0 and lookup(.{ .abstract = shown[1..] }) != null) return error.AddrInUse;
    const slot = for (&bound) |*b| {
        if (b.* == null) break b;
    } else return error.NoBufs;
    @memcpy(s.name[0..shown.len], shown);
    s.name_len = @intCast(shown.len);
    s.inum = inum;
    s.bound = true;
    slot.* = s;
}

pub fn listen(s: *Sock) bool {
    lock.acquire();
    defer lock.release();
    if (!s.bound or s.kind == .dgram or s.peer != null) return false;
    s.listening = true;
    return true;
}

pub const ConnectError = error{ Refused, NoMem, Again, IsConnected, Invalid };

/// Connect `s` to the socket `t` names. A stream gets a new socket at the
/// listener as its other end, queued there for accept; it is connected from
/// this moment, as on Linux. A datagram socket only takes `t` as where its
/// sends go.
pub fn connect(s: *Sock, t: Target) ConnectError!void {
    if (s.kind == .dgram) {
        lock.acquire();
        defer lock.release();
        const to = lookup(t) orelse return error.Refused;
        if (to.kind != .dgram) return error.Refused;
        s.peer = to;
        s.peer_gone = false;
        s.peer_done = false;
        s.was_connected = true;
        return;
    }
    const srv = create(s.kind, 0) orelse return error.NoMem;
    const fail: ConnectError = blk: {
        lock.acquire();
        defer lock.release();
        if (s.peer != null or s.was_connected or s.listening) break :blk error.IsConnected;
        const l = lookup(t) orelse break :blk error.Refused;
        if (!l.listening or l.kind != s.kind) break :blk error.Refused;
        if (l.backlog_count == BACKLOG) break :blk error.Again;
        srv.owner = l.owner;
        // The accepted end answers getsockname with the listener's name.
        @memcpy(srv.name[0..l.name_len], l.name[0..l.name_len]);
        srv.name_len = l.name_len;
        srv.peer = s;
        srv.was_connected = true;
        s.peer = srv;
        s.was_connected = true;
        l.backlog[(l.backlog_head + l.backlog_count) % BACKLOG] = srv;
        l.backlog_count += 1;
        l.events +%= 1;
        fdpoll.notify();
        return;
    };
    _ = destroy(srv);
    return fail;
}

/// The next connection waiting at listener `l`; null for none.
pub fn accept(l: *Sock) ?*Sock {
    lock.acquire();
    defer lock.release();
    if (l.backlog_count == 0) return null;
    const q = l.backlog[l.backlog_head].?;
    l.backlog[l.backlog_head] = null;
    l.backlog_head = @intCast((l.backlog_head + 1) % BACKLOG);
    l.backlog_count -= 1;
    return q;
}

fn ringPut(s: *Sock, at: u32, bytes: []const u8) void {
    const pos = at % RING;
    const first = @min(bytes.len, RING - pos);
    @memcpy(s.ring[pos..][0..first], bytes[0..first]);
    @memcpy(s.ring[0 .. bytes.len - first], bytes[first..]);
}

fn ringGet(s: *const Sock, at: u32, out: []u8) void {
    const pos = at % RING;
    const first = @min(out.len, RING - pos);
    @memcpy(out[0..first], s.ring[pos..][0..first]);
    @memcpy(out[first..], s.ring[0 .. out.len - first]);
}

pub const Sent = union(enum) {
    bytes: usize,
    /// The receiver's ring has no room: wait for it.
    full,
    /// The other end is gone, or our sending side is shut.
    broken,
    not_connected,
    /// Nobody has the name the message was sent to.
    refused,
    /// A message larger than a ring can ever hold.
    too_big,
};

/// What fits of `bytes` (kernel memory) into the other end of stream `s`.
pub fn sendStream(s: *Sock, bytes: []const u8) Sent {
    lock.acquire();
    defer lock.release();
    if (s.wr_shut or s.peer_gone) return .broken;
    const p = s.peer orelse return .not_connected;
    if (p.rd_shut) return .broken;
    const room = RING - p.used;
    if (room == 0) return .full;
    const n: u32 = @intCast(@min(bytes.len, room));
    ringPut(p, p.head + p.used, bytes[0..n]);
    p.used += n;
    p.events +%= 1;
    fdpoll.notify();
    return .{ .bytes = n };
}

/// One whole message from `s` to `to`, or to what `s` is connected to.
pub fn sendMessage(s: *Sock, to: ?Target, bytes: []const u8) Sent {
    const need = MSG_HDR + @as(u32, s.name_len) + @as(u32, @intCast(@min(bytes.len, RING)));
    if (bytes.len > RING or need > RING) return .too_big;
    lock.acquire();
    defer lock.release();
    if (s.wr_shut) return .broken;
    const p = if (to) |t|
        lookup(t) orelse return .refused
    else
        s.peer orelse return if (s.peer_gone) .refused else .not_connected;
    if (p.kind != s.kind or p.rd_shut) return .refused;
    if (p.used + need > RING) return .full;
    var hdr: [MSG_HDR]u8 = undefined;
    std.mem.writeInt(u32, hdr[0..4], @intCast(bytes.len), .little);
    hdr[4] = s.name_len;
    var at = p.head + p.used;
    ringPut(p, at, &hdr);
    at += MSG_HDR;
    ringPut(p, at, s.name[0..s.name_len]);
    at += s.name_len;
    ringPut(p, at, bytes);
    p.used += need;
    p.events +%= 1;
    fdpoll.notify();
    return .{ .bytes = bytes.len };
}

/// Whether sendMessage of `len` bytes would go now, or fail rather than
/// wait: what a sender it told .full waits for.
pub fn messageWouldGo(s: *Sock, to: ?Target, len: usize) bool {
    const need = MSG_HDR + @as(u32, s.name_len) + @as(u32, @intCast(@min(len, RING)));
    lock.acquire();
    defer lock.release();
    if (s.wr_shut) return true;
    const p = if (to) |t| lookup(t) orelse return true else s.peer orelse return true;
    if (p.kind != s.kind or p.rd_shut) return true;
    return p.used + need <= RING;
}

pub const Received = union(enum) {
    /// Bytes put into `out`; a message's whole length, which may be more.
    bytes: usize,
    /// Nothing waits: wait for it.
    empty,
    /// Nothing waits and nothing will.
    eof,
    not_connected,
};

/// The end of what `s` can read, when its ring is empty. Lock held.
fn drained(s: *const Sock) Received {
    if (s.rd_shut or s.peer_done) return .eof;
    if (s.kind != .dgram and !s.was_connected) return .not_connected;
    return .empty;
}

/// Up to `out.len` bytes of stream `s` (kernel memory), left in place with
/// `peek`.
pub fn recvStream(s: *Sock, out: []u8, peek: bool) Received {
    lock.acquire();
    defer lock.release();
    if (s.used == 0) return drained(s);
    const n: u32 = @intCast(@min(out.len, s.used));
    ringGet(s, s.head, out[0..n]);
    if (!peek) {
        s.head = (s.head + n) % RING;
        s.used -= n;
        // Room for the writer at the other end.
        if (s.peer) |p| p.events +%= 1;
        fdpoll.notify();
    }
    return .{ .bytes = n };
}

/// The next message of `s`: as much as fits into `out`, the sender's name
/// into `from` (its length is returned through `from_len`).
pub fn recvMessage(s: *Sock, out: []u8, peek: bool, from: *[NAME_MAX]u8, from_len: *u8) Received {
    lock.acquire();
    defer lock.release();
    if (s.used == 0) return drained(s);
    var hdr: [MSG_HDR]u8 = undefined;
    ringGet(s, s.head, &hdr);
    const len = std.mem.readInt(u32, hdr[0..4], .little);
    const name_len = hdr[4];
    ringGet(s, s.head + MSG_HDR, from[0..name_len]);
    from_len.* = name_len;
    const take = @min(out.len, len);
    ringGet(s, s.head + MSG_HDR + name_len, out[0..take]);
    if (!peek) {
        const whole = MSG_HDR + name_len + len;
        s.head = (s.head + whole) % RING;
        s.used -= whole;
        // Room for whoever sends here; they are found by name, not by a
        // pointer, so there is no counter of theirs to move.
        fdpoll.notify();
    }
    return .{ .bytes = len };
}

pub fn shutdown(s: *Sock, rd: bool, wr: bool) void {
    lock.acquire();
    defer lock.release();
    if (rd) s.rd_shut = true;
    if (wr and !s.wr_shut) {
        s.wr_shut = true;
        if (s.kind != .dgram) if (s.peer) |p| {
            p.peer_done = true;
            p.events +%= 1;
        };
    }
    s.events +%= 1;
    fdpoll.notify();
}

/// What `s` is ready for, as poll bits.
pub fn mask(s: *Sock) u16 {
    lock.acquire();
    defer lock.release();
    if (s.listening) return if (s.backlog_count > 0) fdpoll.POLLIN | fdpoll.POLLRDNORM else 0;
    var m: u16 = 0;
    if (s.used > 0 or s.rd_shut or s.peer_done) m |= fdpoll.POLLIN | fdpoll.POLLRDNORM;
    if (s.peer_done) m |= fdpoll.POLLRDHUP;
    if (s.kind == .dgram) {
        // A datagram send waits only on a ring that is full now.
        const room = if (s.peer) |p| p.used < RING / 2 else true;
        if (room) m |= fdpoll.POLLOUT | fdpoll.POLLWRNORM;
        return m;
    }
    if (s.peer) |p| {
        if (s.wr_shut or p.used < RING) m |= fdpoll.POLLOUT | fdpoll.POLLWRNORM;
    } else {
        // Never connected, or the other end is gone: a write fails at once.
        m |= fdpoll.POLLOUT | fdpoll.POLLHUP;
    }
    return m;
}

pub fn events(s: *const Sock) u32 {
    return @atomicLoad(u32, &s.events, .monotonic);
}

/// Bytes a read would find now (FIONREAD); a message socket's next message.
pub fn pending(s: *Sock) usize {
    lock.acquire();
    defer lock.release();
    if (s.used == 0) return 0;
    if (s.kind == .stream) return s.used;
    var hdr: [MSG_HDR]u8 = undefined;
    ringGet(s, s.head, &hdr);
    return std.mem.readInt(u32, hdr[0..4], .little);
}

pub const Name = struct { bytes: [NAME_MAX]u8 = undefined, len: u8 = 0 };

pub fn nameOf(s: *Sock) Name {
    lock.acquire();
    defer lock.release();
    var n = Name{ .len = s.name_len };
    @memcpy(n.bytes[0..s.name_len], s.name[0..s.name_len]);
    return n;
}

pub const Peer = struct { name: Name, owner: u32 };

/// The other end's name and owner; null when there is none.
pub fn peerOf(s: *Sock) ?Peer {
    lock.acquire();
    defer lock.release();
    const p = s.peer orelse return null;
    var n = Name{ .len = p.name_len };
    @memcpy(n.bytes[0..p.name_len], p.name[0..p.name_len]);
    return .{ .name = n, .owner = p.owner };
}

pub fn isListening(s: *const Sock) bool {
    return s.listening;
}
