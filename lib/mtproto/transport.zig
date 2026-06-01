// MTProto "intermediate" TCP transport.
//
// After TCP connect the client sends the 4-byte magic 0xeeeeeeee once;
// thereafter every message is framed as: 4-byte little-endian length, then
// that many payload bytes. (Abridged uses 0xef + len/4; intermediate is
// simpler and byte-granular, which suits us.)
//
// Sits directly on libc's TCP sockets. No DNS needed — Telegram DC IPs are
// well-known, and SLIRP NATs outbound TCP fine.

const std = @import("std");
const libc = @import("libc");

pub const Error = error{ ConnectFailed, SendFailed, RecvFailed, Closed, TooLarge };

pub const Conn = struct {
    fd: u32,
    // Non-blocking framed-receive state for `pollFrame`. A frame can arrive
    // split across several polls; we accumulate header then body and only
    // surface a complete payload. Separate from the blocking `recv` path
    // (they're never used on the same in-flight frame).
    fr_hdr: [4]u8 = undefined,
    fr_hdr_got: u8 = 0,
    fr_body_len: u32 = 0,
    fr_body_got: u32 = 0,
    fr_in_body: bool = false,
    // Bytes still to discard from a frame too big for the caller's buffer. A
    // single oversized frame must NOT wedge the stream, so we drain+drop it.
    fr_drain: u32 = 0,

    pub fn connect(ip: [4]u8, port: u16) Error!Conn {
        const fd = libc.tcpConnect(ip, port) orelse return error.ConnectFailed;
        const magic = [_]u8{ 0xee, 0xee, 0xee, 0xee }; // intermediate transport
        if (!libc.tcpSend(fd, &magic)) {
            libc.tcpClose(fd);
            return error.SendFailed;
        }
        return .{ .fd = fd };
    }

    pub fn close(self: *Conn) void {
        libc.tcpClose(self.fd);
    }

    /// Frame and send one message: u32 LE length + payload.
    pub fn send(self: *Conn, payload: []const u8) Error!void {
        var hdr: [4]u8 = undefined;
        std.mem.writeInt(u32, &hdr, @intCast(payload.len), .little);
        if (!libc.tcpSend(self.fd, &hdr)) return error.SendFailed;
        if (payload.len > 0 and !libc.tcpSend(self.fd, payload)) return error.SendFailed;
    }

    /// Receive one framed message into `buf`; returns the payload slice.
    /// A 4-byte payload is the transport's way of signalling an error code.
    pub fn recv(self: *Conn, buf: []u8) Error![]u8 {
        var hdr: [4]u8 = undefined;
        try self.readExact(&hdr);
        const n = std.mem.readInt(u32, &hdr, .little);
        if (n > buf.len) return error.TooLarge;
        if (n == 0) return buf[0..0];
        try self.readExact(buf[0..n]);
        return buf[0..n];
    }

    fn resetFrame(self: *Conn) void {
        self.fr_hdr_got = 0;
        self.fr_in_body = false;
        self.fr_body_got = 0;
        self.fr_body_len = 0;
    }

    /// Discard buffered bytes of an oversized frame. Returns true once the whole
    /// frame has been dropped (or the peer closed); false if it would block and
    /// the caller should poll again. Non-blocking.
    fn drainSome(self: *Conn) bool {
        var scratch: [2048]u8 = undefined;
        while (self.fr_drain > 0) {
            const want: usize = @min(self.fr_drain, scratch.len);
            const k = libc.tcpRecv(self.fd, scratch[0..want]);
            if (k == 0) {
                const st = libc.tcpStatus(self.fd);
                if ((st & libc.TCP_STATUS_PEER_CLOSED) != 0) {
                    self.fr_drain = 0; // give up — the header read will surface Closed
                    return true;
                }
                return false; // would block — resume on the next poll
            }
            self.fr_drain -= @intCast(k);
        }
        return true;
    }

    /// Non-blocking framed receive. Returns the payload of the next complete
    /// frame, `null` if no full frame is buffered yet (caller should go do
    /// other work and poll again), or `error.Closed` on peer close. Partial
    /// frames are retained across calls — pass the SAME `buf` each time, and
    /// don't read from it until a non-null payload is returned. This lets an
    /// event loop pump MTProto without ever blocking on the network.
    pub fn pollFrame(self: *Conn, buf: []u8) Error!?[]u8 {
        // Finish discarding an oversized frame before reading anything new, so
        // one big frame can't permanently block the stream.
        if (self.fr_drain > 0) {
            if (!self.drainSome()) return null; // would-block / closed — resume later
        }
        if (!self.fr_in_body) {
            while (self.fr_hdr_got < 4) {
                const k = libc.tcpRecv(self.fd, self.fr_hdr[self.fr_hdr_got..4]);
                if (k == 0) {
                    const st = libc.tcpStatus(self.fd);
                    if ((st & libc.TCP_STATUS_PEER_CLOSED) != 0) return error.Closed;
                    return null; // would block — no header bytes yet
                }
                self.fr_hdr_got += @intCast(k);
            }
            self.fr_body_len = std.mem.readInt(u32, &self.fr_hdr, .little);
            if (self.fr_body_len > buf.len) {
                // Too big to deliver — drop it (over the next polls) instead of
                // re-reading the same header forever. Report it once via TooLarge.
                self.fr_drain = self.fr_body_len;
                self.fr_hdr_got = 0;
                self.fr_in_body = false;
                self.fr_body_got = 0;
                return error.TooLarge;
            }
            self.fr_in_body = true;
            self.fr_body_got = 0;
            if (self.fr_body_len == 0) {
                self.resetFrame();
                return buf[0..0];
            }
        }
        while (self.fr_body_got < self.fr_body_len) {
            const k = libc.tcpRecv(self.fd, buf[self.fr_body_got..self.fr_body_len]);
            if (k == 0) {
                const st = libc.tcpStatus(self.fd);
                if ((st & libc.TCP_STATUS_PEER_CLOSED) != 0) return error.Closed;
                return null; // would block mid-body — resume next poll
            }
            self.fr_body_got += @intCast(k);
        }
        const out = buf[0..self.fr_body_len];
        self.resetFrame();
        return out;
    }

    /// Blocking read of exactly dst.len bytes. libc.tcpRecv is non-blocking
    /// (returns 0 when nothing is buffered), so poll with a short backoff and
    /// honour peer-close. ~16s ceiling so a dead DC can't wedge us forever.
    fn readExact(self: *Conn, dst: []u8) Error!void {
        var got: usize = 0;
        var spins: u32 = 0;
        while (got < dst.len) {
            const k = libc.tcpRecv(self.fd, dst[got..]);
            if (k > 0) {
                got += k;
                spins = 0;
                continue;
            }
            const st = libc.tcpStatus(self.fd);
            if ((st & libc.TCP_STATUS_PEER_CLOSED) != 0) {
                const k2 = libc.tcpRecv(self.fd, dst[got..]);
                if (k2 > 0) {
                    got += k2;
                    continue;
                }
                return error.Closed;
            }
            spins += 1;
            libc.usleep(if (spins < 64) 200 else 2000);
            if (spins > 8000) return error.RecvFailed;
        }
    }
};
