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

// net.zig's fixed retransmit interval (TCP_RETRANSMIT_TICKS is private).
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

test "receiver drops out-of-order data (no reassembly yet)" {
    resolveGateway();
    nic.txClear();
    const peer = [4]u8{ 10, 0, 2, 99 };
    const e = try establishServer(8083, peer, 40003, 11000);
    defer net.tcpUnlisten(e.lst);
    nic.txClear();

    var b: [1600]u8 = undefined;
    // Gap: server rcv_nxt == 11001, but this segment starts 10 bytes ahead.
    deliver(b[0..buildSeg(&b, peer, e.client_port, 8083, 11000 +% 1 +% 10, e.siss +% 1, ACK | PSH, 16384, "OUTOFORDER")]);
    var rb: [64]u8 = undefined;
    try expectEqual(@as(usize, 0), net.tcpRecv(e.srv, &rb)); // dropped, not buffered

    // In-order data that fills the front of the gap is still accepted...
    deliver(b[0..buildSeg(&b, peer, e.client_port, 8083, 11000 +% 1, e.siss +% 1, ACK | PSH, 16384, "INORDER")]);
    try expectEqual(@as(usize, 7), net.tcpRecv(e.srv, &rb));
    try expect(std.mem.eql(u8, rb[0..7], "INORDER"));
    // ...but the earlier out-of-order bytes are gone for good — the cost the
    // reassembly task (#1001) will remove.
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
