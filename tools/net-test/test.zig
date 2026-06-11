// Off-target test harness for src/net/net.zig — the TCP/IP stack.
//
// Model: net.zig is the System Under Test (one TCP endpoint). This file plays
// the remote peer + the wire + the clock:
//   * outbound frames are captured by the nic stub (nic.txPop / txCount);
//   * inbound frames are hand-built here and injected via net.handleRxFrame;
//   * the virtual clock (process.tick_count) is advanced by hand to fire timers.
//
// Connections are established via the PASSIVE path (listen -> SYN -> SYN-ACK ->
// ACK -> accept), which is fully test-driven and non-blocking — unlike
// tcpConnect, which blocks on a poll deadline. Inbound frames are not
// checksum-validated by net.zig, so the scripted peer leaves checksums zero.
//
// Each test uses a unique listener port + client port so leftover connections
// from earlier tests (the stack has no public reset) can't be confused for this
// test's traffic — frames are matched by destination port when popping.

const std = @import("std");
const net = @import("src/net/net.zig");
const nic = @import("src/driver/nic.zig");
const process = @import("src/proc/process.zig");

const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;

// TCP flag bits (mirror net.zig).
const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const PSH: u8 = 0x08;
const ACK: u8 = 0x10;

// A clock advance comfortably beyond any RTO, used to force a retransmit.
const RETX_TICKS: u64 = 300;

// --- big-endian helpers ---
fn wbe16(d: []u8, v: u16) void {
    d[0] = @intCast(v >> 8);
    d[1] = @intCast(v & 0xFF);
}
fn wbe32(d: []u8, v: u32) void {
    d[0] = @intCast(v >> 24);
    d[1] = @intCast((v >> 16) & 0xFF);
    d[2] = @intCast((v >> 8) & 0xFF);
    d[3] = @intCast(v & 0xFF);
}
fn rbe16(d: []const u8) u16 {
    return (@as(u16, d[0]) << 8) | d[1];
}
fn rbe32(d: []const u8) u32 {
    return (@as(u32, d[0]) << 24) | (@as(u32, d[1]) << 16) | (@as(u32, d[2]) << 8) | d[3];
}

// Inject a frame into the stack's RX path (mirrors how net.zig itself re-injects
// loopback frames: cast to a volatile slice).
fn deliver(frame: []u8) void {
    const v: [*]volatile u8 = @ptrCast(frame.ptr);
    net.handleRxFrame(v[0..frame.len]);
}

// Build Ethernet+IPv4+TCP (20-byte headers, no options) from the peer toward us.
// Returns the total frame length.
fn buildSeg(
    buf: []u8,
    peer_ip: [4]u8,
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    payload: []const u8,
) usize {
    // Ethernet
    @memset(buf[0..6], 0x52); // dst mac = us (not checked)
    @memset(buf[6..12], 0xAA); // src mac = peer
    buf[12] = 0x08;
    buf[13] = 0x00; // EtherType IPv4
    // IPv4
    const ip = buf[14..34];
    const ip_total: u16 = @intCast(20 + 20 + payload.len);
    ip[0] = 0x45;
    ip[1] = 0x00;
    wbe16(ip[2..4], ip_total);
    wbe16(ip[4..6], 0);
    ip[6] = 0x40; // don't fragment
    ip[7] = 0x00;
    ip[8] = 64; // TTL
    ip[9] = 6; // proto TCP
    ip[10] = 0;
    ip[11] = 0; // header checksum (inbound not validated)
    @memcpy(ip[12..16], &peer_ip);
    @memcpy(ip[16..20], &net.local_ip);
    // TCP
    const tcp = buf[34..54];
    wbe16(tcp[0..2], sport);
    wbe16(tcp[2..4], dport);
    wbe32(tcp[4..8], seq);
    wbe32(tcp[8..12], ack);
    tcp[12] = 5 << 4; // data offset = 5 words (20 bytes)
    tcp[13] = flags;
    wbe16(tcp[14..16], window);
    tcp[16] = 0;
    tcp[17] = 0; // checksum
    tcp[18] = 0;
    tcp[19] = 0; // urgent
    @memcpy(buf[54..][0..payload.len], payload);
    return 54 + payload.len;
}

// Parsed view of a captured outbound TCP segment.
const Seg = struct {
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    payload: []u8,
    dst_ip: [4]u8,
};

fn parse(frame: []u8) Seg {
    const ip = frame[14..];
    const ihl: usize = @as(usize, ip[0] & 0x0F) * 4;
    const ip_total: usize = rbe16(ip[2..4]);
    const tcp = frame[14 + ihl ..];
    const doff: usize = @as(usize, tcp[12] >> 4) * 4;
    return .{
        .sport = rbe16(tcp[0..2]),
        .dport = rbe16(tcp[2..4]),
        .seq = rbe32(tcp[4..8]),
        .ack = rbe32(tcp[8..12]),
        .flags = tcp[13],
        .window = rbe16(tcp[14..16]),
        .payload = frame[14 + ihl + doff .. 14 + ip_total],
        .dst_ip = .{ ip[16], ip[17], ip[18], ip[19] },
    };
}

// Pop the next captured frame addressed to `dport`, skipping (discarding) any
// frames belonging to other connections. Returns null if none match.
fn popFor(dport: u16) ?Seg {
    while (nic.txPop()) |f| {
        const s = parse(f);
        if (s.dport == dport) return s;
    }
    return null;
}

// Teach net.zig the gateway MAC by injecting an ARP reply, so non-loopback sends
// don't block in arpResolveGateway. Idempotent and produces no TX.
fn resolveGateway() void {
    var b: [42]u8 = undefined;
    @memset(b[0..6], 0x52); // dst mac = us
    @memset(b[6..12], 0xAA); // src mac = gateway
    b[12] = 0x08;
    b[13] = 0x06; // EtherType ARP
    const a = b[14..42];
    a[0] = 0;
    a[1] = 1; // HW type Ethernet
    a[2] = 0x08;
    a[3] = 0x00; // proto IPv4
    a[4] = 6; // HW len
    a[5] = 4; // proto len
    a[6] = 0;
    a[7] = 2; // opcode REPLY
    @memset(a[8..14], 0xAA); // sender mac = gateway
    @memcpy(a[14..18], &net.gateway_ip); // sender ip = gateway
    @memset(a[18..24], 0x52); // target mac = us
    @memcpy(a[24..28], &net.local_ip); // target ip = us
    deliver(b[0..42]);
}

const Established = struct {
    srv: u8,
    lst: u8,
    siss: u32, // server's initial send sequence (read off the SYN-ACK)
    client_port: u16,
    peer: [4]u8,
};

// Drive a passive open to ESTABLISHED and return the accepted server slot.
fn establishServer(port: u16, peer: [4]u8, client_port: u16, ciss: u32) !Established {
    const lst = net.tcpListen(port) orelse return error.ListenFailed;
    var b: [1600]u8 = undefined;

    // peer -> SYN
    deliver(b[0..buildSeg(&b, peer, client_port, port, ciss, 0, SYN, 16384, "")]);

    // us -> SYN-ACK
    const sa = popFor(client_port) orelse return error.NoSynAck;
    try expect(sa.flags & (SYN | ACK) == (SYN | ACK));
    try expectEqual(ciss +% 1, sa.ack);
    const siss = sa.seq;

    // peer -> ACK (completes the handshake)
    deliver(b[0..buildSeg(&b, peer, client_port, port, ciss +% 1, siss +% 1, ACK, 16384, "")]);

    const srv = net.tcpAccept(lst) orelse return error.AcceptFailed;
    return .{ .srv = srv, .lst = lst, .siss = siss, .client_port = client_port, .peer = peer };
}

// =====================================================================
// Scenarios
// =====================================================================

test "passive open: SYN -> SYN-ACK -> ACK establishes; accept() hands it out" {
    resolveGateway();
    nic.txClear();
    const peer = [4]u8{ 10, 0, 2, 99 };
    const e = try establishServer(8080, peer, 40000, 12000);
    defer net.tcpUnlisten(e.lst);
    try expect(net.tcpIsConnected(e.srv));
}

test "inbound data is delivered to tcpRecv and ACKed" {
    resolveGateway();
    nic.txClear();
    const peer = [4]u8{ 10, 0, 2, 99 };
    const e = try establishServer(8084, peer, 40004, 13000);
    defer net.tcpUnlisten(e.lst);
    nic.txClear();

    var b: [1600]u8 = undefined;
    // server rcv_nxt == 13001; send in-order data there.
    deliver(b[0..buildSeg(&b, peer, e.client_port, 8084, 13000 +% 1, e.siss +% 1, ACK | PSH, 16384, "hello world")]);

    var rb: [64]u8 = undefined;
    try expectEqual(@as(usize, 11), net.tcpRecv(e.srv, &rb));
    try expect(std.mem.eql(u8, rb[0..11], "hello world"));

    // The stack should have ACKed the 11 bytes (ack == 13001 + 11).
    const a = popFor(e.client_port) orelse return error.NoAck;
    try expect(a.flags & ACK != 0);
    try expectEqual(@as(u32, 13000 +% 1 +% 11), a.ack);
}

test "receiver reassembles out-of-order data and dup-ACKs the gap" {
    resolveGateway();
    nic.txClear();
    const peer = [4]u8{ 10, 0, 2, 99 };
    const e = try establishServer(8083, peer, 40003, 11000);
    defer net.tcpUnlisten(e.lst);
    nic.txClear();

    var b: [1600]u8 = undefined;
    // Segment B arrives first, out of order (7 bytes ahead of rcv_nxt == 11001).
    deliver(b[0..buildSeg(&b, peer, e.client_port, 8083, 11000 +% 1 +% 7, e.siss +% 1, ACK | PSH, 16384, "HIJKLMN")]);
    var rb: [64]u8 = undefined;
    try expectEqual(@as(usize, 0), net.tcpRecv(e.srv, &rb)); // gap not yet filled

    // A duplicate ACK should have been emitted, still at the cumulative point.
    const da = popFor(e.client_port) orelse return error.NoDupAck;
    try expect(da.flags & ACK != 0);
    try expectEqual(@as(u32, 11000 +% 1), da.ack);
    nic.txClear();

    // Segment A fills the gap; both segments now deliver in order, reassembled.
    deliver(b[0..buildSeg(&b, peer, e.client_port, 8083, 11000 +% 1, e.siss +% 1, ACK | PSH, 16384, "ABCDEFG")]);
    try expectEqual(@as(usize, 14), net.tcpRecv(e.srv, &rb));
    try expect(std.mem.eql(u8, rb[0..14], "ABCDEFGHIJKLMN"));

    // The cumulative ACK now covers all 14 bytes.
    const a2 = popFor(e.client_port) orelse return error.NoAck;
    try expectEqual(@as(u32, 11000 +% 1 +% 14), a2.ack);
}

test "tcpSend segments the stream at peer_mss with contiguous seqs" {
    resolveGateway();
    nic.txClear();
    const peer = [4]u8{ 10, 0, 2, 99 };
    const e = try establishServer(8081, peer, 40001, 7000);
    defer net.tcpUnlisten(e.lst);
    nic.txClear();

    var payload: [1300]u8 = undefined;
    for (&payload, 0..) |*x, i| x.* = @intCast(i & 0xFF);
    try expect(net.tcpSend(e.srv, &payload));

    // No MSS option in our SYN => peer_mss defaults to 536 => 536, 536, 228.
    var want_seq: u32 = e.siss +% 1;
    var total: usize = 0;
    var nseg: usize = 0;
    while (popFor(e.client_port)) |t| {
        try expect(t.flags & PSH != 0);
        try expectEqual(want_seq, t.seq);
        try expect(t.payload.len <= 536);
        try expect(std.mem.eql(u8, t.payload, payload[total..][0..t.payload.len]));
        want_seq +%= @intCast(t.payload.len);
        total += t.payload.len;
        nseg += 1;
    }
    try expectEqual(@as(usize, 1300), total);
    try expect(nseg >= 3);
}

test "loss recovery: RTO resends the first unacked bytes; full ACK drains the ring" {
    resolveGateway();
    nic.txClear();
    const peer = [4]u8{ 10, 0, 2, 99 };
    const e = try establishServer(8082, peer, 40002, 9000);
    defer net.tcpUnlisten(e.lst);
    nic.txClear();

    var payload: [1700]u8 = undefined;
    for (&payload, 0..) |*x, i| x.* = @intCast((i *% 7) & 0xFF);
    try expect(net.tcpSend(e.srv, &payload)); // 536, 536, 536, 92 => 4 segments

    var first_seq: u32 = 0;
    var count: usize = 0;
    while (popFor(e.client_port)) |t| {
        if (count == 0) first_seq = t.seq;
        count += 1;
    }
    try expect(count >= 3);
    try expectEqual(e.siss +% 1, first_seq);

    // Peer ACKs ONLY the first segment; segments 2..N are "lost".
    var b: [1600]u8 = undefined;
    deliver(b[0..buildSeg(&b, peer, e.client_port, 8082, 9000 +% 1, first_seq +% 536, ACK, 16384, "")]);
    nic.txClear();

    // Fire the retransmit timer.
    process.tick_count +%= RETX_TICKS + 1;
    net.poll();

    // The retransmission must be the FIRST UNACKED segment (seq first_seq+536),
    // carrying the correct payload bytes — proof the send ring resends the right
    // octets, not whatever happened to go out last (the old last_tx behavior).
    const r = popFor(e.client_port) orelse return error.NoRetransmit;
    try expectEqual(first_seq +% 536, r.seq);
    try expectEqual(@as(usize, 536), r.payload.len);
    try expect(std.mem.eql(u8, r.payload, payload[536..][0..536]));

    // Peer now ACKs everything; the send ring must drain so the next timer tick
    // has nothing left to retransmit.
    deliver(b[0..buildSeg(&b, peer, e.client_port, 8082, 9000 +% 1, first_seq +% 1700, ACK, 16384, "")]);
    nic.txClear();
    process.tick_count +%= RETX_TICKS + 1;
    net.poll();
    try expect(popFor(e.client_port) == null);
}

test "flow control: small window throttles, window update flushes the rest" {
    resolveGateway();
    nic.txClear();
    const peer = [4]u8{ 10, 0, 2, 99 };
    const e = try establishServer(8086, peer, 40006, 31000);
    defer net.tcpUnlisten(e.lst);

    // Shrink the peer's advertised window to ~1 segment (a pure ACK, no advance).
    var b: [1600]u8 = undefined;
    deliver(b[0..buildSeg(&b, peer, e.client_port, 8086, 31000 +% 1, e.siss +% 1, ACK, 600, "")]);
    nic.txClear();

    var payload: [1500]u8 = undefined;
    for (&payload, 0..) |*x, i| x.* = @intCast((i *% 3) & 0xFF);
    try expect(net.tcpSend(e.srv, &payload));

    // Only the ~600-byte window may be in flight; the rest stays buffered.
    var sent: usize = 0;
    while (popFor(e.client_port)) |t| sent += t.payload.len;
    try expect(sent <= 600);
    try expect(sent < 1500);

    // Pure window update: ack stays at siss+1 (snd_una doesn't advance) but the
    // window re-opens. The buffered remainder must now flush — the case that
    // deadlocks without the window-update flush.
    deliver(b[0..buildSeg(&b, peer, e.client_port, 8086, 31000 +% 1, e.siss +% 1, ACK, 16384, "")]);
    var more: usize = 0;
    while (popFor(e.client_port)) |t| more += t.payload.len;
    try expect(more > 0);
    try expectEqual(@as(usize, 1500), sent + more);
}

test "RTO adapts to measured RTT (Jacobson/Karn), not a fixed timer" {
    resolveGateway();
    nic.txClear();
    const peer = [4]u8{ 10, 0, 2, 99 };
    const e = try establishServer(8087, peer, 40007, 51000);
    defer net.tcpUnlisten(e.lst);
    nic.txClear();

    // First send: one segment, ACKed after a measured ~30-tick round trip.
    // The first RTT sample sets RTO = SRTT + 4*RTTVAR = R + 4*(R/2) = 3R = 90.
    try expect(net.tcpSend(e.srv, "first chunk"));
    const s1 = popFor(e.client_port) orelse return error.NoSeg;
    nic.txClear();
    process.tick_count +%= 30; // round-trip time = 30 ticks
    var b: [1600]u8 = undefined;
    deliver(b[0..buildSeg(&b, peer, e.client_port, 8087, 51000 +% 1, s1.seq +% @as(u32, @intCast(s1.payload.len)), ACK, 16384, "")]);

    // Second send: withhold the ACK and watch when the retransmit fires.
    try expect(net.tcpSend(e.srv, "second chunk"));
    nic.txClear();
    // 40 ticks elapsed < RTO(~90): nothing retransmitted yet.
    process.tick_count +%= 40;
    net.poll();
    try expect(popFor(e.client_port) == null);
    // +60 more (100 elapsed > RTO~90): now it fires. The old fixed 300-tick
    // timer would NOT have fired by here — proof the RTO tracked the RTT.
    process.tick_count +%= 60;
    net.poll();
    try expect(popFor(e.client_port) != null);
}

test "slow start: cwnd throttles the opening burst, ACKs open it up" {
    resolveGateway();
    nic.txClear();
    const peer = [4]u8{ 10, 0, 2, 99 };
    const e = try establishServer(8088, peer, 40008, 61000);
    defer net.tcpUnlisten(e.lst);
    nic.txClear();

    var payload: [3000]u8 = undefined;
    for (&payload, 0..) |*x, i| x.* = @intCast(i & 0xFF);
    try expect(net.tcpSend(e.srv, &payload));

    // The opening burst is bounded by the initial cwnd (a few MSS), not 3000.
    var first_seq: u32 = 0;
    var sent: usize = 0;
    var n0: usize = 0;
    while (popFor(e.client_port)) |t| {
        if (n0 == 0) first_seq = t.seq;
        sent += t.payload.len;
        n0 += 1;
    }
    try expect(sent >= 536);
    try expect(sent < 3000); // throttled by cwnd — not the whole payload at once

    // Cumulative ACKs grow cwnd (slow start) and flush the remainder.
    var b: [1600]u8 = undefined;
    var guard: usize = 0;
    while (sent < 3000 and guard < 12) : (guard += 1) {
        deliver(b[0..buildSeg(&b, peer, e.client_port, 8088, 61000 +% 1, first_seq +% @as(u32, @intCast(sent)), ACK, 16384, "")]);
        while (popFor(e.client_port)) |t| sent += t.payload.len;
    }
    try expectEqual(@as(usize, 3000), sent);
}

test "fast retransmit: 3 duplicate ACKs resend immediately, before any RTO" {
    resolveGateway();
    nic.txClear();
    const peer = [4]u8{ 10, 0, 2, 99 };
    const e = try establishServer(8089, peer, 40009, 71000);
    defer net.tcpUnlisten(e.lst);
    nic.txClear();

    var payload: [2000]u8 = undefined;
    for (&payload, 0..) |*x, i| x.* = @intCast(i & 0xFF);
    try expect(net.tcpSend(e.srv, &payload));
    var first_seq: u32 = 0;
    var n0: usize = 0;
    while (popFor(e.client_port)) |t| {
        if (n0 == 0) first_seq = t.seq;
        n0 += 1;
    }
    try expect(n0 >= 2);
    nic.txClear();

    // First segment "lost": the peer keeps ACKing first_seq (its rcv_nxt). No
    // clock advance — so a retransmit here can only be the fast path, not the RTO.
    var b: [1600]u8 = undefined;
    var k: usize = 0;
    while (k < 3) : (k += 1) {
        deliver(b[0..buildSeg(&b, peer, e.client_port, 8089, 71000 +% 1, first_seq, ACK, 16384, "")]);
    }
    const r = popFor(e.client_port) orelse return error.NoFastRetransmit;
    try expectEqual(first_seq, r.seq);
    try expect(r.payload.len > 0);
}

test "lying data offset is dropped, not parsed (header bytes used to leak into the stream)" {
    resolveGateway();
    nic.txClear();
    const peer = [4]u8{ 10, 0, 2, 99 };
    const e = try establishServer(8090, peer, 40010, 81000);
    defer net.tcpUnlisten(e.lst);
    nic.txClear();

    var b: [1600]u8 = undefined;
    // In-order segment whose data-offset nibble is 0 (claims an 0-byte TCP
    // header). Pre-guard, payload_len = tcp.len -| 0 = 20 swallowed the TCP
    // HEADER as stream data (and a nibble > tcp.len/4 walked options past
    // the segment end — ReleaseSafe panic). Both must be dropped now.
    const n = buildSeg(&b, peer, e.client_port, 8090, 81000 +% 1, e.siss +% 1, ACK | PSH, 16384, "");
    b[14 + 20 + 12] = 0; // doff = 0 words
    deliver(b[0..n]);

    var rb: [64]u8 = undefined;
    try expectEqual(@as(usize, 0), net.tcpRecv(e.srv, &rb));

    // And the oversized variant: doff = 24 with only 20 bytes on the wire.
    const n2 = buildSeg(&b, peer, e.client_port, 8090, 81000 +% 1, e.siss +% 1, ACK | PSH, 16384, "");
    b[14 + 20 + 12] = 6 << 4; // doff = 24 > tcp.len = 20
    deliver(b[0..n2]);
    try expectEqual(@as(usize, 0), net.tcpRecv(e.srv, &rb));
}

test "seq wrap: peer ISS at 0xFFFFFFFE establishes and FINs across the wrap" {
    resolveGateway();
    nic.txClear();
    const peer = [4]u8{ 10, 0, 2, 99 };
    // rcv_nxt after the SYN = 0xFFFFFFFF; the FIN below sits exactly on the
    // wrap point. Pre-fix, the non-wrapping `rcv_nxt += 1` was a ReleaseSafe
    // overflow panic — a peer-controlled remote crash.
    const e = try establishServer(8091, peer, 40011, 0xFFFF_FFFE);
    defer net.tcpUnlisten(e.lst);
    nic.txClear();

    var b: [1600]u8 = undefined;
    deliver(b[0..buildSeg(&b, peer, e.client_port, 8091, 0xFFFF_FFFF, e.siss +% 1, ACK | FIN, 16384, "")]);
    try expect(net.tcpPeerClosed(e.srv));
    const a = popFor(e.client_port) orelse return error.NoFinAck;
    try expect(a.flags & ACK != 0);
    try expectEqual(@as(u32, 0), a.ack); // 0xFFFFFFFF +% 1
}

test "FIN beyond a reassembly gap is not consumed early" {
    resolveGateway();
    nic.txClear();
    const peer = [4]u8{ 10, 0, 2, 99 };
    const e = try establishServer(8092, peer, 40012, 91000);
    defer net.tcpUnlisten(e.lst);
    nic.txClear();

    var b: [1600]u8 = undefined;
    // Data+FIN arrives 7 bytes AHEAD of rcv_nxt (gap). Pre-fix the FIN was
    // consumed unconditionally: rcv_nxt jumped the hole and peer_closed went
    // up while the gap data was still missing (silent truncation).
    deliver(b[0..buildSeg(&b, peer, e.client_port, 8092, 91000 +% 1 +% 7, e.siss +% 1, ACK | PSH | FIN, 16384, "XYZ")]);
    try expect(!net.tcpPeerClosed(e.srv));
    const da = popFor(e.client_port) orelse return error.NoDupAck;
    try expectEqual(@as(u32, 91000 +% 1), da.ack); // still at the gap

    // Gap fills -> data reassembles -> NOW the retransmitted FIN counts.
    deliver(b[0..buildSeg(&b, peer, e.client_port, 8092, 91000 +% 1, e.siss +% 1, ACK | PSH, 16384, "ABCDEFG")]);
    var rb: [64]u8 = undefined;
    try expectEqual(@as(usize, 10), net.tcpRecv(e.srv, &rb));
    try expect(std.mem.eql(u8, rb[0..10], "ABCDEFGXYZ"));
    nic.txClear();
    deliver(b[0..buildSeg(&b, peer, e.client_port, 8092, 91000 +% 1 +% 10, e.siss +% 1, ACK | FIN, 16384, "")]);
    try expect(net.tcpPeerClosed(e.srv));
}

test "IP fragments are dropped (no reassembly, no mis-parse)" {
    resolveGateway();
    nic.txClear();
    const peer = [4]u8{ 10, 0, 2, 99 };
    const e = try establishServer(8093, peer, 40013, 95000);
    defer net.tcpUnlisten(e.lst);
    nic.txClear();

    var b: [1600]u8 = undefined;
    // In-order data but flagged More-Fragments: must be ignored wholesale.
    const n = buildSeg(&b, peer, e.client_port, 8093, 95000 +% 1, e.siss +% 1, ACK | PSH, 16384, "FRAG");
    b[14 + 6] = 0x20; // MF set, offset 0
    deliver(b[0..n]);
    var rb: [64]u8 = undefined;
    try expectEqual(@as(usize, 0), net.tcpRecv(e.srv, &rb));
    try expect(popFor(e.client_port) == null); // no ACK either

    // Non-first fragment (offset != 0): also dropped.
    const n2 = buildSeg(&b, peer, e.client_port, 8093, 95000 +% 1, e.siss +% 1, ACK | PSH, 16384, "FRAG");
    b[14 + 6] = 0x00;
    b[14 + 7] = 0x05; // fragment offset 5*8 bytes
    deliver(b[0..n2]);
    try expectEqual(@as(usize, 0), net.tcpRecv(e.srv, &rb));
}

test "RST on a half-open conn frees the slot (40 SYN+RST cycles never exhaust the table)" {
    resolveGateway();
    nic.txClear();
    const peer = [4]u8{ 10, 0, 2, 77 };
    const lst = net.tcpListen(8094) orelse return error.ListenFailed;
    defer net.tcpUnlisten(lst);

    var b: [1600]u8 = undefined;
    var i: u16 = 0;
    while (i < 40) : (i += 1) {
        const cport: u16 = 41000 + i;
        deliver(b[0..buildSeg(&b, peer, cport, 8094, 50000 +% i, 0, SYN, 16384, "")]);
        // Pre-fix, each RST below left an active SYN-RECEIVED corpse; after
        // the table filled (16 slots), SYN-ACKs stopped forever.
        _ = popFor(cport) orelse return error.TableExhausted;
        deliver(b[0..buildSeg(&b, peer, cport, 8094, 50000 +% i +% 1, 0, RST, 16384, "")]);
    }
}
