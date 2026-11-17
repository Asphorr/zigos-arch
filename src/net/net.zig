const std = @import("std");
const vga = @import("../ui/vga.zig");
const nic = @import("../driver/nic.zig");
const debug = @import("../debug/debug.zig");
const process = @import("../proc/process.zig");
const SpinLock = @import("../proc/spinlock.zig").SpinLock;

/// Serializes ALL mutable net state (tcp_conns, tcp_listeners, udp_listeners,
/// the ARP cache, ip_id, rx counters). The live virtio-net driver runs the
/// ENTIRE RX path — handleRxFrame → handleTcpPacket → ACK synthesis/flush —
/// in NIC-IRQ context, racing task-side syscalls (tcpSend/tcpRecv/poll) that
/// can run on ANY CPU; before this lock the two sides did unprotected
/// read-modify-writes on the same rings (snd_buf_len, rx_count, snd_nxt...).
/// Discipline:
///   * public entry points acquire IrqSave; internal helpers (emitSegment,
///     flushSnd, receiveData, tcpTick, handle*Packet...) assume it's held;
///   * NEVER held across kernelSleepMs — blocking APIs unlock around their
///     poll+sleep loops (spinlock-held-across-schedule = deadlock class);
///   * read-only probes (tcpPollMask, tcpIsConnected, tcpPeerClosed,
///     renderProc*) stay LOCK-FREE: fdpoll.wakePollers calls tcpPollMask
///     while net_lock is already held by the RX path.
var net_lock: SpinLock = .{};

// --- Ethernet ---
const ETH_ALEN = 6;
const ETH_HDR_SIZE = 14;
const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_IPV4: u16 = 0x0800;
const BROADCAST_MAC = [_]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

// --- ARP ---
const ARP_HDR_SIZE = 28;
const ARP_REQUEST: u16 = 1;
const ARP_REPLY: u16 = 2;

// --- IPv4 ---
const IPV4_HDR_SIZE = 20;
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

// --- ICMP ---
const ICMP_ECHO_REPLY: u8 = 0;
const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_HDR_SIZE = 8;

// --- UDP ---
const UDP_HDR_SIZE = 8;

// --- TCP ---
const TCP_HDR_SIZE = 20;
const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_PSH: u8 = 0x08;
const TCP_ACK: u8 = 0x10;
const TCP_MAX_CONNS = 32;
const TCP_MAX_LISTENERS = 8;
/// Receive and send rings, powers of two. A connection takes a block from
/// the pool (ring_pool, filled from vmalloc in task context) when one is
/// idle — a large receive ring, then a large send ring — else it uses its
/// small inline pair.
const TCP_RX_RING: u32 = 256 * 1024;
const TCP_RX_SMALL: u32 = 8192;
const TCP_TX_RING: u32 = 256 * 1024;
const TCP_SND_SMALL: u32 = 8192;
/// Segments one flushSnd puts out: the lock and the interrupts are held
/// meanwhile. Their ACKs start the next run.
const TCP_FLUSH_BURST: u32 = 32;
/// In-order segments one ACK may answer inside a receive batch (RFC 1122
/// §4.2.3.2: at least every second one).
const TCP_ACK_EVERY: u8 = 2;
/// Out-of-order data waits in the receive ring at its own place; these are
/// its runs, which SACK blocks also report.
const TCP_OOO_RUNS = 4;
/// A serial line per received segment: a trace for hunts. At download
/// speed it outruns the serial drainer and takes a CPU.
const TRACE_RX = false;
// Retransmit timeout, in 10 ms ticks, derived per-conn from RTT (Jacobson/Karn).
const TCP_INIT_RTO_TICKS: u32 = 100; // 1 s, until the first RTT sample (RFC 6298)
const TCP_MIN_RTO_TICKS: u32 = 20; // 200 ms floor (cf. Linux TCP_RTO_MIN)
const TCP_MAX_RTO_TICKS: u32 = 6000; // 60 s ceiling + exponential-backoff cap
const TCP_INIT_CWND_SEGS: u32 = 4; // initial congestion window, in MSS-sized segments
const TCP_MAX_CWND: u32 = TCP_TX_RING; // congestion-window ceiling (bytes)
const TCP_MAX_RETRIES: u8 = 3;
const TCP_NO_LISTENER: u8 = 0xFF;
// Per-listener ring of accepted-but-not-yet-handed-out connection slots.
const TCP_ACCEPT_RING_SIZE: u8 = 16;
/// The peer hears of a receive window that opened by this much (two full
/// segments, RFC 1122's rule against silly windows).
const TCP_WINDOW_UPDATE: u32 = 2 * 1460;
/// How long a connection whose socket is gone may take to finish its close.
const TCP_ORPHAN_TICKS: u64 = 1000;
/// How long a closed connection lingers for stray segments (10 ms ticks).
const TCP_TIME_WAIT_TICKS: u64 = 200;

// Active network config. Initial values match QEMU SLIRP — the user-mode
// networking DHCP server offers exactly these — so the stack still works
// without DHCP (e.g. if `dhcp.acquire` is skipped or times out). Replaced
// at boot by `applyDhcpLease()` once DHCP completes.
pub var local_ip: [4]u8 = .{ 10, 0, 2, 15 };
pub var gateway_ip: [4]u8 = .{ 10, 0, 2, 2 };
pub var dns_ip: [4]u8 = .{ 10, 0, 2, 3 };
pub var subnet_mask: [4]u8 = .{ 255, 255, 255, 0 };
/// True once `applyDhcpLease()` has been called at least once. `false`
/// means we're running on the static SLIRP defaults — visible to netstat /
/// fastfetch / etc.
pub var dhcp_configured: bool = false;
/// Seconds remaining on the current lease, when known. 0 = unknown / static.
pub var dhcp_lease_secs: u32 = 0;

// ARP cache
var gateway_mac: [6]u8 = .{ 0, 0, 0, 0, 0, 0 };
var gateway_mac_valid: bool = false;

/// Called by the DHCP module on a successful lease. Replaces the active
/// triple; also invalidates the cached gateway MAC because the new gateway
/// might be on a different L2 host. Subnet mask is stored for future
/// route-table work but unused today (we route everything via the gateway).
pub fn applyDhcpLease(new_ip: [4]u8, new_gw: [4]u8, new_mask: [4]u8, new_dns: [4]u8, lease_secs: u32) void {
    local_ip = new_ip;
    gateway_ip = new_gw;
    subnet_mask = new_mask;
    dns_ip = new_dns;
    dhcp_configured = true;
    dhcp_lease_secs = lease_secs;
    gateway_mac_valid = false;
    gateway_mac = .{ 0, 0, 0, 0, 0, 0 };
}

// IP identification counter
var ip_id: u16 = 1;

// === Byte order helpers ===

fn htons(v: u16) u16 { return @byteSwap(v); }
fn ntohs(v: u16) u16 { return @byteSwap(v); }
fn htonl(v: u32) u32 { return @byteSwap(v); }
fn ntohl(v: u32) u32 { return @byteSwap(v); }

fn readU16BE(d: []const volatile u8) u16 {
    return @as(u16, d[0]) << 8 | @as(u16, d[1]);
}
fn readU32BE(d: []const volatile u8) u32 {
    return @as(u32, d[0]) << 24 | @as(u32, d[1]) << 16 | @as(u32, d[2]) << 8 | @as(u32, d[3]);
}
fn writeU16BE(d: []u8, v: u16) void {
    d[0] = @intCast(v >> 8);
    d[1] = @intCast(v & 0xFF);
}
fn writeU32BE(d: []u8, v: u32) void {
    d[0] = @intCast((v >> 24) & 0xFF);
    d[1] = @intCast((v >> 16) & 0xFF);
    d[2] = @intCast((v >> 8) & 0xFF);
    d[3] = @intCast(v & 0xFF);
}

// === Packet building ===

fn buildEthHeader(buf: []u8, dst: [6]u8, src: [6]u8, ethertype: u16) void {
    @memcpy(buf[0..6], &dst);
    @memcpy(buf[6..12], &src);
    buf[12] = @intCast(ethertype >> 8);
    buf[13] = @intCast(ethertype & 0xFF);
}

fn internetChecksum(data: []const u8) u16 {
    var sum: u32 = 0;
    var i: usize = 0;
    while (i + 1 < data.len) : (i += 2) {
        sum += @as(u32, data[i]) << 8 | @as(u32, data[i + 1]);
    }
    if (i < data.len) sum += @as(u32, data[i]) << 8;
    while (sum >> 16 != 0) sum = (sum & 0xFFFF) + (sum >> 16);
    return @intCast(~sum & 0xFFFF);
}

/// True if the address is in 127.0.0.0/8. Loopback bypasses ARP and the
/// NIC entirely — packets are stamped with src = dst (so both endpoints
/// see themselves as the peer 127.x address) and re-injected into the RX
/// dispatcher. Without the src-rewrite, the 4-tuple TCP conn lookup on
/// the originator side wouldn't match the reply (it would see src=
/// local_ip but its `remote_ip` is 127.x).
pub fn isLoopback(ip: [4]u8) bool {
    return ip[0] == 127;
}

/// True for an address of this machine — loopback or the interface's own:
/// what is sent there never touches the wire.
pub fn isLocal(ip: [4]u8) bool {
    return isLoopback(ip) or std.mem.eql(u8, &ip, &local_ip);
}

/// Pick the IP to stamp as src on an outbound packet. For loopback we
/// mirror the destination so the receive side's conn-tuple match works
/// in both directions.
fn outboundSrcIp(dst_ip: [4]u8) [4]u8 {
    return if (isLoopback(dst_ip)) dst_ip else local_ip;
}

fn buildIPv4Header(buf: []u8, protocol: u8, dst_ip: [4]u8, payload_len: u16) void {
    const total_len: u16 = IPV4_HDR_SIZE + payload_len;
    buf[0] = 0x45;
    buf[1] = 0;
    writeU16BE(buf[2..4], total_len);
    writeU16BE(buf[4..6], ip_id);
    ip_id +%= 1;
    buf[6] = 0x40; // Don't fragment
    buf[7] = 0;
    buf[8] = 64; // TTL
    buf[9] = protocol;
    buf[10] = 0;
    buf[11] = 0;
    const src_ip = outboundSrcIp(dst_ip);
    @memcpy(buf[12..16], &src_ip);
    @memcpy(buf[16..20], &dst_ip);
    const csum = internetChecksum(buf[0..IPV4_HDR_SIZE]);
    buf[10] = @intCast(csum >> 8);
    buf[11] = @intCast(csum & 0xFF);
}

/// Final send-side hop: loopback addresses bypass the NIC and recurse
/// straight into the RX dispatcher; everything else hits the wire.
/// Used by udpSend and sendTcpPacket so the loopback policy lives in
/// exactly one place. Caller has already built the full Ethernet+IP+L4
/// frame in `pkt`.
fn dispatchPacket(dst_ip: [4]u8, pkt: []u8) bool {
    if (isLocal(dst_ip)) return deliverLocal(pkt);
    return nic.send(pkt);
}

// Frames for this machine wait here until the holder of net_lock lets go
// (netUnlock): the sender has finished its own bookkeeping by then — a
// segment's ACK finds snd_nxt already past it — and a local exchange is a
// loop at the top of one call, not a recursion a segment deep per segment.
// Empty whenever the lock is free. (p:net_lock)
const LOCAL_QUEUE: usize = 32;
var local_frames: [LOCAL_QUEUE][1514]u8 = undefined;
var local_lens: [LOCAL_QUEUE]u16 = [_]u16{0} ** LOCAL_QUEUE;
var local_head: usize = 0;
var local_count: usize = 0;

/// Queue a frame for this machine's own receive path. False when the queue
/// is full and the frame is dropped (TCP sends it again).
fn deliverLocal(pkt: []u8) bool {
    if (local_count == LOCAL_QUEUE or pkt.len > 1514) return false;
    const at = (local_head + local_count) % LOCAL_QUEUE;
    @memcpy(local_frames[at][0..pkt.len], pkt);
    local_lens[at] = @intCast(pkt.len);
    local_count += 1;
    return true;
}

/// Process the queued local frames, and what their processing queues.
fn drainLocal() void {
    while (local_count > 0) {
        // In place: what this frame's processing queues lands behind it.
        const frame: [*]volatile u8 = @ptrCast(&local_frames[local_head]);
        processReceivedPacket(frame[0..local_lens[local_head]]);
        local_head = (local_head + 1) % LOCAL_QUEUE;
        local_count -= 1;
    }
}

/// Every release of net_lock: the local frames the holder sent go through
/// the receive path first.
fn netUnlock(saved: u64) void {
    drainLocal();
    net_lock.releaseIrqRestore(saved);
}

fn tcpChecksum(src_ip: [4]u8, dst_ip: [4]u8, tcp_data: []const u8) u16 {
    var sum: u32 = 0;
    sum += @as(u32, src_ip[0]) << 8 | src_ip[1];
    sum += @as(u32, src_ip[2]) << 8 | src_ip[3];
    sum += @as(u32, dst_ip[0]) << 8 | dst_ip[1];
    sum += @as(u32, dst_ip[2]) << 8 | dst_ip[3];
    sum += IPPROTO_TCP;
    sum += @as(u32, @intCast(tcp_data.len));
    var i: usize = 0;
    while (i + 1 < tcp_data.len) : (i += 2) {
        sum += @as(u32, tcp_data[i]) << 8 | @as(u32, tcp_data[i + 1]);
    }
    if (i < tcp_data.len) sum += @as(u32, tcp_data[i]) << 8;
    while (sum >> 16 != 0) sum = (sum & 0xFFFF) + (sum >> 16);
    return @intCast(~sum & 0xFFFF);
}

// === UDP ===

const UdpListener = struct {
    port: u16 = 0,
    active: bool = false,
    data: [512]u8 = undefined,
    data_len: u16 = 0,
    has_data: bool = false,
    src_ip: [4]u8 = .{ 0, 0, 0, 0 },
    src_port: u16 = 0,
};
var udp_listeners: [4]UdpListener = [_]UdpListener{.{}} ** 4;

pub fn udpListen(port: u16) ?u8 {
    const lk = net_lock.acquireIrqSave();
    defer netUnlock(lk);
    for (&udp_listeners, 0..) |*l, i| {
        if (!l.active) {
            l.port = port;
            l.has_data = false;
            l.active = true;
            return @intCast(i);
        }
    }
    return null;
}

pub fn udpUnlisten(slot: u8) void {
    const lk = net_lock.acquireIrqSave();
    defer netUnlock(lk);
    if (slot < 4) udp_listeners[slot].active = false;
}

/// True if a packet has been buffered and not yet consumed. Caller can
/// then read via `udpData()` and free the buffer via `udpConsume()`.
/// Three-step (has/data/consume) instead of one-shot so the buffer stays
/// pinned during the caller's parse — handleUdpPacket only writes when
/// `!has_data`, so leaving has_data true keeps subsequent packets out.
/// udpHasData/udpData stay lock-free: the has_data flag is a classic SPSC
/// handoff (writer fills data THEN sets the flag; x86-TSO keeps the order)
/// and the consumer's parse of the pinned buffer couldn't be covered by a
/// lock anyway.
pub fn udpHasData(slot: u8) bool {
    if (slot >= udp_listeners.len) return false;
    return udp_listeners[slot].has_data;
}

pub fn udpData(slot: u8) []const u8 {
    if (slot >= udp_listeners.len) return &[_]u8{};
    const l = &udp_listeners[slot];
    if (!l.has_data) return &[_]u8{};
    return l.data[0..l.data_len];
}

pub fn udpConsume(slot: u8) void {
    if (slot >= udp_listeners.len) return;
    // Plain store: flag-clear is the consumer's half of the SPSC handoff.
    udp_listeners[slot].has_data = false;
}

/// The most a datagram carries: one frame, there is no fragmenting.
pub const UDP_MAX_PAYLOAD: usize = 1500 - IPV4_HDR_SIZE - UDP_HDR_SIZE;

pub fn udpSend(dst_ip: [4]u8, dst_port: u16, src_port: u16, payload: []const u8) bool {
    if (payload.len > UDP_MAX_PAYLOAD) return false;
    const loop = isLocal(dst_ip);
    // Blocking ARP resolution OUTSIDE the lock (it polls + sleeps).
    if (!loop and !arpResolveGateway()) return false;
    const lk = net_lock.acquireIrqSave();
    defer netUnlock(lk);
    var pkt: [1514]u8 = undefined;
    const src_mac = nic.getMac();
    const dst_mac = if (loop) src_mac else gateway_mac;
    buildEthHeader(&pkt, dst_mac, src_mac, ETHERTYPE_IPV4);
    const udp_total: u16 = @intCast(UDP_HDR_SIZE + payload.len);
    buildIPv4Header(pkt[ETH_HDR_SIZE..], IPPROTO_UDP, dst_ip, udp_total);
    const udp = pkt[ETH_HDR_SIZE + IPV4_HDR_SIZE ..];
    writeU16BE(udp[0..2], src_port);
    writeU16BE(udp[2..4], dst_port);
    writeU16BE(udp[4..6], udp_total);
    udp[6] = 0;
    udp[7] = 0; // checksum optional for IPv4
    @memcpy(udp[UDP_HDR_SIZE..][0..payload.len], payload);
    const total: usize = ETH_HDR_SIZE + IPV4_HDR_SIZE + udp_total;
    return dispatchPacket(dst_ip, pkt[0..total]);
}

/// L2/L3 broadcast send: dst MAC = ff:ff:ff:ff:ff:ff, src IP = 0.0.0.0,
/// dst IP = 255.255.255.255. Bypasses `arpResolveGateway()` because DHCP
/// DISCOVER runs before we know the gateway. Used by `dhcp.zig` only —
/// every other UDP send path should go through `udpSend()`.
pub fn udpSendBroadcast(src_port: u16, dst_port: u16, payload: []const u8) bool {
    if (payload.len > 1400) return false;
    const lk = net_lock.acquireIrqSave();
    defer netUnlock(lk);
    var pkt: [1514]u8 = undefined;
    const src_mac = nic.getMac();
    buildEthHeader(&pkt, BROADCAST_MAC, src_mac, ETHERTYPE_IPV4);

    const udp_total: u16 = @intCast(UDP_HDR_SIZE + payload.len);
    const ip = pkt[ETH_HDR_SIZE..];
    ip[0] = 0x45;
    ip[1] = 0;
    writeU16BE(ip[2..4], IPV4_HDR_SIZE + udp_total);
    writeU16BE(ip[4..6], ip_id);
    ip_id +%= 1;
    ip[6] = 0x40;
    ip[7] = 0;
    ip[8] = 64;
    ip[9] = IPPROTO_UDP;
    ip[10] = 0; ip[11] = 0;
    @memset(ip[12..16], 0);    // src = 0.0.0.0
    @memset(ip[16..20], 0xFF); // dst = 255.255.255.255
    const csum = internetChecksum(ip[0..IPV4_HDR_SIZE]);
    ip[10] = @intCast(csum >> 8);
    ip[11] = @intCast(csum & 0xFF);

    const udp = pkt[ETH_HDR_SIZE + IPV4_HDR_SIZE ..];
    writeU16BE(udp[0..2], src_port);
    writeU16BE(udp[2..4], dst_port);
    writeU16BE(udp[4..6], udp_total);
    udp[6] = 0; udp[7] = 0;
    @memcpy(udp[UDP_HDR_SIZE..][0..payload.len], payload);
    return nic.send(pkt[0 .. ETH_HDR_SIZE + IPV4_HDR_SIZE + udp_total]);
}

fn handleUdpPacket(ip_data: []volatile u8, ihl: usize) void {
    const udp = ip_data[ihl..];
    if (udp.len < UDP_HDR_SIZE) return;
    const dst_port = readU16BE(udp[2..4]);
    const src_port = readU16BE(udp[0..2]);
    const payload_len = readU16BE(udp[4..6]);
    debug.klog("[udp] RX src_port={d} dst_port={d} len={d}\n", .{ src_port, dst_port, payload_len });
    if (payload_len < UDP_HDR_SIZE) return;
    const data_len = payload_len - UDP_HDR_SIZE;
    if (udp.len < UDP_HDR_SIZE + data_len) return;

    for (&udp_listeners, 0..) |*l, li| {
        if (l.active and l.port == dst_port and !l.has_data) {
            debug.klog("[udp] Matched listener {d} port {d}\n", .{ li, l.port });
            const copy_len = @min(data_len, 512);
            // Bulk copy via @memcpy. The volatile qualifier on `udp` came
            // from the NIC RX path's annotation that the device might still
            // be writing — but by the time handleRxFrame fires, the IRQ
            // implies the device finished the descriptor write, so the
            // bytes are stable DRAM. @volatileCast strips the qualifier
            // so @memcpy can do a vectorised bulk copy instead of the
            // 1-byte-per-iteration loop this used to be.
            const src: [*]const u8 = @volatileCast(udp[UDP_HDR_SIZE..].ptr);
            @memcpy(l.data[0..copy_len], src[0..copy_len]);
            l.data_len = @intCast(copy_len);
            const ip_src: [*]const u8 = @volatileCast(ip_data[12..].ptr);
            @memcpy(l.src_ip[0..4], ip_src[0..4]);
            l.src_port = readU16BE(udp[0..2]);
            l.has_data = true;
            return;
        }
    }
    for (&udp_socks) |*s| {
        if (!s.active or s.port != dst_port) continue;
        const src: [*]const u8 = @volatileCast(udp[UDP_HDR_SIZE..].ptr);
        udpQueue(s, .{ ip_data[12], ip_data[13], ip_data[14], ip_data[15] }, src_port, src[0..data_len]);
        return;
    }
}

// === UDP sockets ===
//
// A socket's port and the datagrams waiting on it, each stored in the ring
// as a header (length, source port, source address) and its payload. The
// ring is the socket's from udpOpen to udpClose and written by the receive
// path under net_lock.

const UDP_SOCKS: usize = 16;
const UDP_RING: u32 = 16 * 1024;
const UDP_REC_HDR: u32 = 8;
// Ports handed to sockets that ask for none. The kernel's own resolver
// counts up from 49152, clear of these.
const UDP_EPHEMERAL_FIRST: u16 = 32768;
const UDP_EPHEMERAL_LAST: u16 = 49151;

const UdpSock = struct {
    active: bool = false,
    /// 0: not bound yet.
    port: u16 = 0,
    ring: [*]u8 = undefined,
    head: u32 = 0,
    used: u32 = 0,
    /// Datagrams queued so far: what an edge-triggered watcher compares.
    events: u32 = 0,
    dropped: u32 = 0,
};
var udp_socks: [UDP_SOCKS]UdpSock = [_]UdpSock{.{}} ** UDP_SOCKS;
var udp_next_ephemeral: u16 = UDP_EPHEMERAL_FIRST;

fn udpRingPut(s: *UdpSock, at: u32, bytes: []const u8) void {
    var pos = at % UDP_RING;
    for (bytes) |b| {
        s.ring[pos] = b;
        pos = (pos + 1) % UDP_RING;
    }
}

fn udpRingGet(s: *const UdpSock, at: u32, out: []u8) void {
    var pos = at % UDP_RING;
    for (out) |*o| {
        o.* = s.ring[pos];
        pos = (pos + 1) % UDP_RING;
    }
}

/// Queue a received datagram on `s`; one that doesn't fit is dropped, as
/// UDP allows. Lock held.
fn udpQueue(s: *UdpSock, src_ip: [4]u8, src_port: u16, payload: []const u8) void {
    const need: u32 = UDP_REC_HDR + @as(u32, @intCast(payload.len));
    if (s.used + need > UDP_RING) {
        s.dropped +%= 1;
        return;
    }
    var hdr: [UDP_REC_HDR]u8 = undefined;
    writeU16BE(hdr[0..2], @intCast(payload.len));
    writeU16BE(hdr[2..4], src_port);
    @memcpy(hdr[4..8], &src_ip);
    const at = s.head + s.used;
    udpRingPut(s, at, &hdr);
    udpRingPut(s, at + UDP_REC_HDR, payload);
    s.used += need;
    s.events +%= 1;
    @import("../cpu/ipc/fdpoll.zig").notify();
}

fn udpPortTaken(port: u16) bool {
    for (&udp_socks) |*s| {
        if (s.active and s.port == port) return true;
    }
    for (&udp_listeners) |*l| {
        if (l.active and l.port == port) return true;
    }
    return false;
}

/// A new UDP socket, not bound. Null when the table or memory is out.
pub fn udpOpen() ?u8 {
    const heap = @import("../mm/heap.zig");
    const ring = heap.kmalloc(UDP_RING) orelse return null;
    {
        const lk = net_lock.acquireIrqSave();
        defer netUnlock(lk);
        for (&udp_socks, 0..) |*s, i| {
            if (s.active) continue;
            s.* = .{ .active = true, .ring = ring };
            return @intCast(i);
        }
    }
    heap.kfree(ring);
    return null;
}

pub fn udpClose(slot: u8) void {
    if (slot >= UDP_SOCKS) return;
    var ring: ?[*]u8 = null;
    {
        const lk = net_lock.acquireIrqSave();
        defer netUnlock(lk);
        const s = &udp_socks[slot];
        if (!s.active) return;
        ring = s.ring;
        s.* = .{};
    }
    if (ring) |r| @import("../mm/heap.zig").kfree(r);
}

/// Give socket `slot` the port `port`, or with 0 one nobody has. False if
/// the port is taken or the socket already has one.
pub fn udpBind(slot: u8, port: u16) bool {
    if (slot >= UDP_SOCKS) return false;
    const lk = net_lock.acquireIrqSave();
    defer netUnlock(lk);
    const s = &udp_socks[slot];
    if (!s.active or s.port != 0) return false;
    if (port != 0) {
        if (udpPortTaken(port)) return false;
        s.port = port;
        return true;
    }
    var tries: u32 = 0;
    while (tries <= UDP_EPHEMERAL_LAST - UDP_EPHEMERAL_FIRST) : (tries += 1) {
        const candidate = udp_next_ephemeral;
        udp_next_ephemeral = if (candidate == UDP_EPHEMERAL_LAST) UDP_EPHEMERAL_FIRST else candidate + 1;
        if (udpPortTaken(candidate)) continue;
        s.port = candidate;
        return true;
    }
    return false;
}

/// The socket's port, 0 before it has one.
pub fn udpPort(slot: u8) u16 {
    if (slot >= UDP_SOCKS) return 0;
    return udp_socks[slot].port;
}

/// Send a datagram from socket `slot`, which gets a port now if it has
/// none. Task context: finding the gateway may sleep.
pub fn udpSendFrom(slot: u8, dst_ip: [4]u8, dst_port: u16, payload: []const u8) bool {
    if (slot >= UDP_SOCKS) return false;
    if (udp_socks[slot].port == 0 and !udpBind(slot, 0)) return false;
    return udpSend(dst_ip, dst_port, udp_socks[slot].port, payload);
}

pub const UdpDatagram = struct {
    /// The datagram's whole length; more than was asked for was cut off.
    len: usize,
    src_ip: [4]u8,
    src_port: u16,
};

/// The oldest datagram waiting on `slot` into `out` (kernel memory), taken
/// off the queue unless `peek`. With `only`, datagrams from anyone else are
/// dropped on the way (a connected socket). Null when none waits.
pub fn udpRecv(slot: u8, out: []u8, peek: bool, only: ?Endpoint) ?UdpDatagram {
    if (slot >= UDP_SOCKS) return null;
    const lk = net_lock.acquireIrqSave();
    defer netUnlock(lk);
    const s = &udp_socks[slot];
    if (!s.active) return null;
    while (s.used != 0) {
        var hdr: [UDP_REC_HDR]u8 = undefined;
        udpRingGet(s, s.head, &hdr);
        const len: u32 = readU16BE(hdr[0..2]);
        const d = UdpDatagram{ .len = len, .src_ip = hdr[4..8].*, .src_port = readU16BE(hdr[2..4]) };
        const wanted = if (only) |p| std.mem.eql(u8, &p.ip, &d.src_ip) and p.port == d.src_port else true;
        if (wanted) {
            udpRingGet(s, s.head + UDP_REC_HDR, out[0..@min(@as(usize, len), out.len)]);
            if (peek) return d;
        }
        s.head = (s.head + UDP_REC_HDR + len) % UDP_RING;
        s.used -= UDP_REC_HDR + len;
        if (wanted) return d;
    }
    return null;
}

/// Lock-free: a datagram waits on `slot`.
pub fn udpReadable(slot: u8) bool {
    if (slot >= UDP_SOCKS) return false;
    return udp_socks[slot].used != 0;
}

pub fn udpEvents(slot: u8) u32 {
    if (slot >= UDP_SOCKS) return 0;
    return udp_socks[slot].events;
}

/// The length of the datagram a read would take next, 0 for none (FIONREAD).
pub fn udpNextLen(slot: u8) usize {
    if (slot >= UDP_SOCKS) return 0;
    const lk = net_lock.acquireIrqSave();
    defer netUnlock(lk);
    const s = &udp_socks[slot];
    if (!s.active or s.used == 0) return 0;
    var hdr: [UDP_REC_HDR]u8 = undefined;
    udpRingGet(s, s.head, &hdr);
    return readU16BE(hdr[0..2]);
}

// === DNS ===

const DNS_PORT: u16 = 53;
var dns_local_port: u16 = 49152;

pub fn resolve(hostname: []const u8) ?[4]u8 {
    if (!nic.isReady()) return null;
    const slot = udpListen(dns_local_port) orelse return null;
    defer udpUnlisten(slot);
    dns_local_port +%= 1;
    if (dns_local_port < 49152) dns_local_port = 49152;

    // Build DNS query
    var query: [256]u8 = undefined;
    var qlen: usize = 12; // header
    // Header: ID=0x1234, flags=0x0100 (recursion desired), QDCOUNT=1
    writeU16BE(query[0..2], 0x1234);
    writeU16BE(query[2..4], 0x0100);
    writeU16BE(query[4..6], 1); // questions
    writeU16BE(query[6..8], 0); // answers
    writeU16BE(query[8..10], 0); // authority
    writeU16BE(query[10..12], 0); // additional

    // Encode hostname as labels
    var start: usize = 0;
    for (hostname, 0..) |c, i| {
        if (c == '.') {
            const label_len = i - start;
            if (label_len == 0 or label_len > 63 or qlen + 1 + label_len > 250) return null;
            query[qlen] = @intCast(label_len);
            qlen += 1;
            @memcpy(query[qlen..][0..label_len], hostname[start..i]);
            qlen += label_len;
            start = i + 1;
        }
    }
    // Last label
    const last_len = hostname.len - start;
    if (last_len > 0 and last_len <= 63 and qlen + 1 + last_len < 250) {
        query[qlen] = @intCast(last_len);
        qlen += 1;
        @memcpy(query[qlen..][0..last_len], hostname[start..]);
        qlen += last_len;
    }
    query[qlen] = 0; // root label
    qlen += 1;
    writeU16BE(query[qlen..][0..2], 1); // QTYPE A
    qlen += 2;
    writeU16BE(query[qlen..][0..2], 1); // QCLASS IN
    qlen += 2;

    debug.klog("[dns] Sending query for {s} on port {d}, len={d}\n", .{ hostname, dns_local_port -% 1, qlen });
    if (!udpSend(dns_ip, DNS_PORT, dns_local_port -% 1, query[0..qlen])) {
        debug.klog("[dns] UDP send failed\n", .{});
        return null;
    }

    // Poll for response. Tick-based deadline (5 seconds) and a 10ms kernel
    // sleep between polls so the BSP isn't monopolised — the desktop and
    // other apps stay responsive during the lookup.
    const dns_deadline: u64 = process.tick_count + 500;
    while (process.tick_count < dns_deadline) {
        poll();
        if (udp_listeners[slot].has_data) {
            const resp = &udp_listeners[slot].data;
            const rlen = udp_listeners[slot].data_len;
            if (rlen < 12) return null;
            const ancount = readU16BE(resp[6..8]);
            if (ancount == 0) return null;
            // Skip question section
            var pos: usize = 12;
            // Skip QNAME
            while (pos < rlen) {
                if (resp[pos] == 0) { pos += 1; break; }
                if (resp[pos] & 0xC0 == 0xC0) { pos += 2; break; }
                pos += 1 + resp[pos];
            }
            pos += 4; // QTYPE + QCLASS
            // Parse first answer
            var ai: u16 = 0;
            while (ai < ancount and pos + 12 <= rlen) : (ai += 1) {
                // Skip name (compression or labels)
                if (resp[pos] & 0xC0 == 0xC0) {
                    pos += 2;
                } else {
                    while (pos < rlen and resp[pos] != 0) pos += 1 + resp[pos];
                    pos += 1;
                }
                if (pos + 10 > rlen) return null;
                const rtype = readU16BE(resp[pos..][0..2]);
                const rdlength = readU16BE(resp[pos + 8 ..][0..2]);
                pos += 10;
                if (rtype == 1 and rdlength == 4 and pos + 4 <= rlen) {
                    return .{ resp[pos], resp[pos + 1], resp[pos + 2], resp[pos + 3] };
                }
                pos += rdlength;
            }
            return null;
        }
        process.kernelSleepMs(10);
    }
    return null;
}

pub fn nslookupCommand(hostname: []const u8) void {
    if (!nic.isReady()) {
        vga.fg = .LightRed;
        vga.print("Network not available\n", .{});
        vga.fg = .LightGray;
        return;
    }
    vga.print("Looking up {s}...\n", .{hostname});
    if (resolve(hostname)) |ip| {
        vga.fg = .LightGreen;
        vga.print("{s} -> {d}.{d}.{d}.{d}\n", .{ hostname, ip[0], ip[1], ip[2], ip[3] });
        vga.fg = .LightGray;
    } else {
        vga.fg = .LightRed;
        vga.print("DNS lookup failed\n", .{});
        vga.fg = .LightGray;
    }
}

// === TCP ===

const TcpState = enum { closed, listen, syn_sent, syn_received, established, fin_wait_1, fin_wait_2, time_wait, close_wait, last_ack };

// TcpConn / TcpListener slots are protected by `net_lock` (top of file).
// The two access paths — (a) NIC-RX via net.handleRxFrame in driver IRQ
// context (the live virtio-net mode) and (b) syscall handlers on ANY CPU
// going through the public tcp*/udp*/poll API — were NOT actually
// single-threaded relative to each other as this comment used to claim:
// an IRQ landing mid-tcpSend (same CPU) or running in parallel with a
// task on an AP could tear snd_buf_len/rx_count read-modify-writes and
// double-run flushSnd. Field annotations: (p:net_lock) unless marked.
const TcpConn = struct {
    state: TcpState = .closed,
    active: bool = false,
    local_port: u16 = 0,
    remote_port: u16 = 0,
    remote_ip: [4]u8 = .{ 0, 0, 0, 0 },
    snd_nxt: u32 = 0,
    snd_una: u32 = 0,
    snd_iss: u32 = 0,
    snd_wnd: u32 = 0, // peer's most-recently advertised receive window
    // Ring of outbound data we may still have to retransmit. The byte at
    // snd_buf[snd_buf_head] corresponds to sequence number snd_una; the ring
    // holds snd_buf_len bytes spanning [snd_una, snd_una+snd_buf_len). Of those,
    // [snd_una, snd_nxt) are sent-but-unacked and the rest are buffered-unsent.
    snd_small: [TCP_SND_SMALL]u8 = undefined,
    /// snd_small or the send half of the pooled block (attachRing).
    snd_buf: [*]u8 = undefined,
    snd_mask: u32 = TCP_SND_SMALL - 1,
    snd_buf_head: u32 = 0,
    snd_buf_len: u32 = 0,
    /// One past the highest sequence number sent (sndTop): above snd_nxt
    /// while a timeout sends again from snd_una.
    snd_max: u32 = 0,
    /// Fast recovery lasts until this is acked, and dup ACKs below it start
    /// none (RFC 6582).
    recover: u32 = 0,
    /// The socket went with data still in the send ring: the block returns
    /// to the pool once the ring is empty.
    detach_due: bool = false,
    /// In-order data segments taken and not answered yet (a receive batch
    /// holds ACKs back; rxBatchEnd and tcpTick send what is left).
    ack_due: u8 = 0,
    // RTT estimation (Jacobson/Karn) -> adaptive retransmit timeout, in ticks.
    srtt: u32 = 0, // smoothed RTT (0 = no sample yet)
    rttvar: u32 = 0, // RTT variation
    rto: u32 = TCP_INIT_RTO_TICKS, // current retransmit timeout
    rtt_pending: bool = false, // timing a sample right now?
    rtt_seq: u32 = 0, // sample completes once snd_una reaches this seq
    rtt_start: u64 = 0, // tick the timed segment was sent
    rcv_nxt: u32 = 0,
    /// Out-of-order runs already in the receive ring past rcv_nxt: sorted,
    /// apart from each other.
    ooo: [TCP_OOO_RUNS]SeqRun = undefined,
    n_ooo: u8 = 0,
    /// The run the latest out-of-order segment went to: the first SACK block.
    ooo_recent: u8 = 0,
    // Congestion control (Reno): cwnd/ssthresh in bytes, dup-ACK counter.
    cwnd: u32 = 2144, // 4*536; refined to 4*peer_mss at established
    ssthresh: u32 = TCP_MAX_CWND,
    dup_acks: u8 = 0,
    in_recovery: bool = false,
    rx_small: [TCP_RX_SMALL]u8 = undefined,
    /// rx_small or the slot's large ring, chosen when the slot is taken
    /// (attachRing). rx_write is where the byte at rcv_nxt goes.
    rx_buf: [*]u8 = undefined,
    rx_mask: u32 = TCP_RX_SMALL - 1,
    rx_write: u32 = 0,
    rx_count: u32 = 0,
    last_send_tick: u64 = 0,
    retransmit_count: u8 = 0,
    last_tx: [1514]u8 = undefined,
    last_tx_len: u16 = 0,
    peer_mss: u16 = 536,
    error_flag: bool = false,
    peer_closed: bool = false,
    /// If this conn was accepted by a listener, points back at the listener
    /// slot so we know where to enqueue ourselves on the established
    /// transition. TCP_NO_LISTENER for outbound (tcpConnect) connections.
    listener_slot: u8 = TCP_NO_LISTENER,
    /// The receive window the peer was last told, in bytes, and the
    /// furthest right edge it was ever told (rcvWindowField).
    adv_wnd: u32 = 0,
    adv_edge: u32 = 0,
    /// Window scaling (RFC 7323), in force once both SYNs carried it: our
    /// shift and the peer's. SACK blocks (RFC 2018) go out once the peer's
    /// SYN allowed them.
    rcv_wscale: u8 = 0,
    snd_wscale: u8 = 0,
    ws_ok: bool = false,
    sack_ok: bool = false,
    /// What came in, for the dumps and the line a big transfer leaves at
    /// its close (reportConn): data segments; bytes taken in order; segments
    /// put past a gap, wholly old, cut at the window's edge, or leaving
    /// less than a segment free; the most bytes the reader left waiting;
    /// the tick of the first.
    st_segs: u32 = 0,
    st_bytes: u64 = 0,
    st_ooo: u32 = 0,
    st_old: u32 = 0,
    st_cut: u32 = 0,
    st_full: u32 = 0,
    st_peak: u32 = 0,
    st_start: u64 = 0,
    /// Why error_flag is set, for the socket's SO_ERROR.
    fail: TcpFail = .none,
    /// Our side has no more to send: the FIN goes out once the send ring is
    /// acked empty (maybeSendFin).
    fin_wanted: bool = false,
    fin_sent: bool = false,
    /// Nobody will read: what the peer still sends is acked and dropped.
    rd_closed: bool = false,
    /// Its socket is gone (tcpRelease): the slot frees itself when the
    /// close is done, or at orphan_deadline.
    orphan: bool = false,
    orphan_deadline: u64 = 0,
    /// Counts data, send space, the peer's close and failure: what an
    /// edge-triggered watcher compares.
    events: u32 = 0,
};

pub const TcpFail = enum(u8) { none, refused, reset, timed_out };

/// Sequence numbers [lo, hi).
const SeqRun = struct { lo: u32, hi: u32 };

fn seqLt(a: u32, b: u32) bool {
    return @as(i32, @bitCast(a -% b)) < 0;
}

fn seqLe(a: u32, b: u32) bool {
    return @as(i32, @bitCast(a -% b)) <= 0;
}

const TcpListener = struct {
    active: bool = false,
    port: u16 = 0,
    /// Ring of established conn slot ids waiting to be handed out by accept().
    /// SYN-RECEIVED conns are NOT in here; the entry is appended only on
    /// transition to ESTABLISHED so accept() always returns a usable conn.
    accept_ring: [TCP_ACCEPT_RING_SIZE]u8 = [_]u8{0xFF} ** TCP_ACCEPT_RING_SIZE,
    accept_head: u8 = 0,
    accept_tail: u8 = 0,
    /// Connections queued so far.
    events: u32 = 0,
};

var tcp_conns: [TCP_MAX_CONNS]TcpConn = [_]TcpConn{.{}} ** TCP_MAX_CONNS;
var tcp_listeners: [TCP_MAX_LISTENERS]TcpListener = [_]TcpListener{.{}} ** TCP_MAX_LISTENERS;
var next_ephemeral: u16 = 49200;

/// The large ring blocks (receive ring, then send ring), from vmalloc, never
/// freed. One is taken while a live connection uses it (its rx_buf is the
/// block); a connection gives it back when its socket goes and its send
/// ring is empty (detachRing), or when the slot is let go. So the pool grows
/// to the most sockets open at once, not to the slots that linger.
/// (p:net_lock)
var ring_pool: [TCP_MAX_CONNS]?[*]u8 = [_]?[*]u8{null} ** TCP_MAX_CONNS;

/// The smallest window shift whose scaled window covers a ring of `size`.
fn wscaleFor(size: u32) u8 {
    var s: u5 = 0;
    while ((size >> s) > 0xFFFF) s += 1;
    return s;
}

/// A pooled block no live connection uses. Lock held, or a guess.
fn idleRing() ?[*]u8 {
    pool: for (ring_pool) |slot| {
        const r = slot orelse continue;
        for (&tcp_conns) |*c| {
            if (c.active and c.rx_buf == r) continue :pool;
        }
        return r;
    }
    return null;
}

/// Give a connection just taken (active, fields reset, both rings empty)
/// its rings and the window shift its SYN offers. Lock held.
fn attachRing(c: *TcpConn) void {
    // `c` is active already: a stale rx_buf of its own must not count.
    c.rx_buf = &c.rx_small;
    c.snd_buf = &c.snd_small;
    if (idleRing()) |r| {
        c.rx_buf = r;
        c.rx_mask = TCP_RX_RING - 1;
        c.snd_buf = r + TCP_RX_RING;
        c.snd_mask = TCP_TX_RING - 1;
    } else {
        c.rx_mask = TCP_RX_SMALL - 1;
        c.snd_mask = TCP_SND_SMALL - 1;
    }
    c.rcv_wscale = wscaleFor(c.rx_mask + 1);
}

/// Nobody will read `c` again: its block goes back to the pool, the unread
/// bytes with it; what still comes lands in the small ring. Bytes still to
/// send move to the small send ring; more of them than it holds keep the
/// block until enough are acked (processAck calls again). Lock held.
fn detachRing(c: *TcpConn) void {
    if (c.rx_buf == @as([*]u8, &c.rx_small)) return;
    c.detach_due = c.snd_buf_len > TCP_SND_SMALL;
    if (c.detach_due) return;
    readSnd(c, c.snd_una, c.snd_small[0..c.snd_buf_len]);
    c.snd_buf = &c.snd_small;
    c.snd_mask = TCP_SND_SMALL - 1;
    c.snd_buf_head = 0;
    c.rx_buf = &c.rx_small;
    c.rx_mask = TCP_RX_SMALL - 1;
    c.rx_count = 0;
    c.n_ooo = 0;
}

/// A slot no connection holds. Lock held.
fn freeSlot() ?u8 {
    for (&tcp_conns, 0..) |*c, i| {
        if (!c.active) return @intCast(i);
    }
    return null;
}

/// Before a connection starts: make sure an idle ring block waits for it.
/// Task context with interrupts on, net_lock not held: vmalloc can't run
/// under it, so this allocates, then places.
fn provisionRing() void {
    if (!@import("../time/pause.zig").irqsEnabled()) return;
    if (idleRing() != null) return;
    const heap = @import("../mm/heap.zig");
    const mem = heap.kvmalloc(TCP_RX_RING + TCP_TX_RING) orelse return;
    const placed = blk: {
        const lk = net_lock.acquireIrqSave();
        defer netUnlock(lk);
        if (idleRing() != null) break :blk false;
        for (&ring_pool) |*slot| {
            if (slot.* != null) continue;
            slot.* = mem;
            break :blk true;
        }
        break :blk false;
    };
    if (!placed) heap.kvfree(mem);
}

/// Idle blocks netd leaves in the pool for the next connections.
pub const TCP_RING_SPARE: usize = 2;

/// Give idle ring blocks beyond `spare` back to vmalloc. Task context with
/// interrupts on, net_lock not held (vmalloc can't run under it): netd, and
/// whoever counts free memory and wants the pool out of the count.
pub fn trimRings(spare: usize) void {
    if (!@import("../time/pause.zig").irqsEnabled()) return;
    while (true) {
        const gone: ?[*]u8 = blk: {
            const lk = net_lock.acquireIrqSave();
            defer netUnlock(lk);
            var idle: usize = 0;
            pool: for (&ring_pool) |*slot| {
                const r = slot.* orelse continue;
                for (&tcp_conns) |*c| {
                    if (c.active and c.rx_buf == r) continue :pool;
                }
                idle += 1;
                if (idle > spare) {
                    slot.* = null;
                    break :blk r;
                }
            }
            break :blk null;
        };
        @import("../mm/heap.zig").kvfree(gone orelse return);
    }
}

const SynOptions = struct { mss: u16 = 536, wscale: ?u8 = null, sack_ok: bool = false };

/// The options of a SYN or SYN-ACK; the caller checked data_offset against
/// the segment.
fn parseSynOptions(tcp: []volatile u8, data_offset: usize) SynOptions {
    var o: SynOptions = .{};
    var pos: usize = TCP_HDR_SIZE;
    while (pos < data_offset) {
        const kind = tcp[pos];
        if (kind == 0) break;
        if (kind == 1) {
            pos += 1;
            continue;
        }
        if (pos + 1 >= data_offset) break;
        const len = tcp[pos + 1];
        if (len < 2 or pos + len > data_offset) break;
        switch (kind) {
            2 => if (len == 4) {
                const mss = readU16BE(tcp[pos + 2 ..][0..2]);
                o.mss = if (mss > 1460) 1460 else if (mss < 100) 536 else mss;
            },
            3 => if (len == 3) {
                o.wscale = @min(tcp[pos + 2], 14);
            },
            4 => if (len == 2) {
                o.sack_ok = true;
            },
            else => {},
        }
        pos += len;
    }
    return o;
}

fn connSlotIndex(c: *const TcpConn) u8 {
    const base = @intFromPtr(&tcp_conns[0]);
    const off = @intFromPtr(c) - base;
    return @intCast(off / @sizeOf(TcpConn));
}

fn listenerSlotIndex(l: *const TcpListener) u8 {
    const base = @intFromPtr(&tcp_listeners[0]);
    const off = @intFromPtr(l) - base;
    return @intCast(off / @sizeOf(TcpListener));
}

/// False if the ring is full — the caller must then drop the conn slot
/// entirely; an ESTABLISHED conn that never reaches accept() has no owner
/// and would leak its slot forever.
fn enqueueAccepted(lst: *TcpListener, conn_slot: u8) bool {
    const ring_size = TCP_ACCEPT_RING_SIZE;
    const next = (lst.accept_head + 1) % ring_size;
    if (next == lst.accept_tail) return false; // ring full
    lst.accept_ring[lst.accept_head] = conn_slot;
    lst.accept_head = next;
    lst.events +%= 1;
    return true;
}

/// Something a waiter on `c` may care about happened. Lock held.
fn tcpNotify(c: *TcpConn) void {
    c.events +%= 1;
    @import("../cpu/ipc/fdpoll.zig").wakePollers(.tcp_sock, @as(u16, connSlotIndex(c)));
}

fn tcpFailWith(c: *TcpConn, why: TcpFail) void {
    debug.klog("[tcp] fail {s}: port {d} -> {d}.{d}.{d}.{d}:{d} state={s} out={d} queued={d} wnd={d} tries={d}\n", .{
        @tagName(why),
        c.local_port,
        c.remote_ip[0],
        c.remote_ip[1],
        c.remote_ip[2],
        c.remote_ip[3],
        c.remote_port,
        @tagName(c.state),
        sndTop(c) -% c.snd_una,
        c.snd_buf_len,
        c.snd_wnd,
        c.retransmit_count,
    });
    c.error_flag = true;
    c.fail = why;
    c.state = .closed;
    tcpNotify(c);
}

/// The window field of our next segment: the ring's free space, scaled,
/// never pulling back a right edge the peer was already given (RFC 7323
/// §2.4). Records what it tells. Lock held.
fn rcvWindowField(c: *TcpConn, syn: bool) u16 {
    const free = (c.rx_mask + 1) - c.rx_count;
    // A SYN's window is never scaled.
    const s: u5 = if (c.ws_ok and !syn) @intCast(c.rcv_wscale) else 0;
    var field: u32 = @min(free >> s, 0xFFFF);
    const want = c.adv_edge -% c.rcv_nxt;
    if (!syn and seqLt(c.rcv_nxt +% (field << s), c.adv_edge) and want <= free + (@as(u32, 1) << s)) {
        field = @min((want + (@as(u32, 1) << s) - 1) >> s, 0xFFFF);
    }
    c.adv_wnd = field << s;
    const edge = c.rcv_nxt +% c.adv_wnd;
    if (syn or seqLt(c.adv_edge, edge)) c.adv_edge = edge;
    return @intCast(field);
}

/// The window has opened past what the peer was last told by enough to say
/// so unasked (receiver SWS avoidance, RFC 9293 §3.8.6.2.2). Lock held.
fn windowOpened(c: *const TcpConn) bool {
    const size = c.rx_mask + 1;
    const s: u5 = if (c.ws_ok) @intCast(c.rcv_wscale) else 0;
    const field: u32 = @min((size - c.rx_count) >> s, 0xFFFF);
    const grew = (c.rcv_nxt +% (field << s)) -% c.adv_edge;
    return @as(i32, @bitCast(grew)) >= @as(i32, @intCast(@min(TCP_WINDOW_UPDATE, size / 2)));
}

/// Our options for a segment: what a SYN or SYN-ACK offers, or the SACK
/// blocks of a bare ACK. Returns their length, a multiple of 4.
fn buildOptions(c: *const TcpConn, flags: u8, has_payload: bool, out: *[40]u8) u8 {
    if (flags & TCP_SYN != 0) {
        out[0..4].* = .{ 2, 4, 1460 >> 8, 1460 & 0xFF };
        var n: u8 = 4;
        // A SYN-ACK answers what the peer's SYN offered; our SYN offers both.
        const answer = flags & TCP_ACK != 0;
        if (!answer or c.ws_ok) {
            out[n..][0..4].* = .{ 1, 3, 3, c.rcv_wscale };
            n += 4;
        }
        if (!answer or c.sack_ok) {
            out[n..][0..4].* = .{ 1, 1, 4, 2 };
            n += 4;
        }
        return n;
    }
    if (!c.sack_ok or c.n_ooo == 0 or has_payload or flags & TCP_ACK == 0) return 0;
    out[0..4].* = .{ 1, 1, 5, 2 + 8 * c.n_ooo };
    var n: u8 = 4;
    // The run the latest segment joined goes first (RFC 2018 §4).
    const first = @min(c.ooo_recent, c.n_ooo - 1);
    writeU32BE(out[n..][0..4], c.ooo[first].lo);
    writeU32BE(out[n + 4 ..][0..4], c.ooo[first].hi);
    n += 8;
    for (c.ooo[0..c.n_ooo], 0..) |r, i| {
        if (i == first) continue;
        writeU32BE(out[n..][0..4], r.lo);
        writeU32BE(out[n + 4 ..][0..4], r.hi);
        n += 8;
    }
    return n;
}

/// Build and transmit a single TCP segment stamped with an explicit sequence
/// number. `sendTcpPacket` wraps this at conn.snd_nxt for the common case; the
/// data path passes an explicit seq so a retransmission can re-send the oldest
/// unacked bytes (seq == snd_una) rather than whatever went out last.
fn emitSegment(conn: *TcpConn, seq: u32, flags: u8, payload: ?[]const u8) bool {
    const loop = isLocal(conn.remote_ip);
    // Non-blocking gateway check. Blocking resolution (poll + sleep) happens
    // in the task-context prologues (tcpConnect/tcpSend/udpSend); this
    // function also runs in NIC-IRQ context (ACK/SYN-ACK synthesis off the
    // RX path), where arpResolveGateway's kernelSleepMs would schedule from
    // an IRQ — and its poll() would self-deadlock on net_lock besides. Fire
    // one request so the cache warms by the peer's retransmit.
    if (!loop and !gateway_mac_valid) {
        arpRequestGateway();
        return false;
    }
    var pkt: [1514]u8 = undefined;
    const src_mac = nic.getMac();
    const dst_mac = if (loop) src_mac else gateway_mac;
    buildEthHeader(&pkt, dst_mac, src_mac, ETHERTYPE_IPV4);

    const payload_len: u16 = if (payload) |p| @intCast(p.len) else 0;
    var opts: [40]u8 = undefined;
    const opt_len = buildOptions(conn, flags, payload_len > 0, &opts);
    const tcp_hdr_len: u16 = TCP_HDR_SIZE + @as(u16, opt_len);
    buildIPv4Header(pkt[ETH_HDR_SIZE..], IPPROTO_TCP, conn.remote_ip, tcp_hdr_len + payload_len);

    const tcp = pkt[ETH_HDR_SIZE + IPV4_HDR_SIZE ..];
    writeU16BE(tcp[0..2], conn.local_port);
    writeU16BE(tcp[2..4], conn.remote_port);
    writeU32BE(tcp[4..8], seq);
    writeU32BE(tcp[8..12], if (flags & TCP_ACK != 0) conn.rcv_nxt else 0);
    tcp[12] = @intCast((tcp_hdr_len / 4) << 4); // data offset
    tcp[13] = flags;
    // The free space of the receive ring: a reader slow to drain it
    // throttles the peer instead of losing what it sends.
    writeU16BE(tcp[14..16], rcvWindowField(conn, flags & TCP_SYN != 0));
    tcp[16] = 0;
    tcp[17] = 0; // checksum placeholder
    tcp[18] = 0;
    tcp[19] = 0; // urgent pointer
    @memcpy(tcp[TCP_HDR_SIZE..][0..opt_len], opts[0..opt_len]);

    if (payload) |p| {
        const off: usize = tcp_hdr_len;
        @memcpy(tcp[off..][0..p.len], p);
    }

    // TCP checksum uses the IP-layer src/dst — for loopback that's the
    // mirrored 127.x address, not local_ip. Matches what buildIPv4Header
    // just stamped so the receiver's pseudo-header checksum validates.
    const tcp_total: usize = tcp_hdr_len + payload_len;
    const src_for_csum = outboundSrcIp(conn.remote_ip);
    const csum = tcpChecksum(src_for_csum, conn.remote_ip, tcp[0..tcp_total]);
    tcp[16] = @intCast(csum >> 8);
    tcp[17] = @intCast(csum & 0xFF);

    const total: usize = ETH_HDR_SIZE + IPV4_HDR_SIZE + tcp_total;

    // Control segments (SYN/SYN-ACK/FIN) consume a sequence number and are
    // retransmitted verbatim from last_tx; data segments are retransmitted from
    // the snd_buf ring instead, so they must not clobber a pending SYN/FIN here.
    if (flags & (TCP_SYN | TCP_FIN) != 0) {
        @memcpy(conn.last_tx[0..total], pkt[0..total]);
        conn.last_tx_len = @intCast(total);
    }
    // Arm the retransmit timer whenever we put retransmittable octets on the
    // wire — anything that consumes sequence space (data, SYN or FIN).
    if ((payload != null and payload.?.len > 0) or flags & (TCP_SYN | TCP_FIN) != 0) {
        conn.last_send_tick = process.tick_count;
    }
    // Every segment with ACK set answers all that came. Before the send: a
    // local peer's reply is processed inside it.
    if (flags & TCP_ACK != 0) conn.ack_due = 0;

    return dispatchPacket(conn.remote_ip, pkt[0..total]);
}

/// One past the highest sequence number sent.
fn sndTop(c: *const TcpConn) u32 {
    return if (seqLt(c.snd_nxt, c.snd_max)) c.snd_max else c.snd_nxt;
}

/// Send a segment at the top of what was sent — the common path for control
/// segments and bare ACKs. (While a timeout resends from below, snd_nxt is
/// not it, and the peer would drop an ACK stamped there as old.)
fn sendTcpPacket(conn: *TcpConn, flags: u8, payload: ?[]const u8) bool {
    return emitSegment(conn, sndTop(conn), flags, payload);
}

/// The next port for an outbound connection or a listener that asked for
/// none. Lock held.
fn ephemeralPort() u16 {
    const port = next_ephemeral;
    next_ephemeral +%= 1;
    if (next_ephemeral < 49200) next_ephemeral = 49200;
    return port;
}

/// Start a connection to `dst_ip:dst_port` from `local_port` (0: any). The
/// SYN is out when this returns the slot; tcpView tells how it went. Task
/// context: finding the gateway may sleep.
pub fn tcpConnectStart(dst_ip: [4]u8, dst_port: u16, local_port: u16) ?u8 {
    return connectIn(null, dst_ip, dst_port, local_port);
}

/// tcpConnectStart in `slot`, a connection of the caller's that failed: a
/// socket connecting again keeps its slot, so a thread still using the
/// slot's number reaches the socket's new connection, never someone else's.
/// False if it can't start; the slot stays the caller's, failed.
pub fn tcpReconnect(slot: u8, dst_ip: [4]u8, dst_port: u16, local_port: u16) bool {
    return connectIn(slot, dst_ip, dst_port, local_port) != null;
}

fn connectIn(reuse: ?u8, dst_ip: [4]u8, dst_port: u16, local_port: u16) ?u8 {
    // Resolve the gateway up front, outside the lock — it blocks (poll +
    // sleep); emitSegment's own gateway check is non-blocking by design.
    if (!isLocal(dst_ip) and !arpResolveGateway()) return null;
    if (reuse) |r| {
        if (r >= TCP_MAX_CONNS) return null;
    }
    provisionRing();

    const lk = net_lock.acquireIrqSave();
    defer netUnlock(lk);

    const slot: u8 = if (reuse) |r| blk: {
        if (!tcp_conns[r].active or !tcp_conns[r].error_flag) return null;
        break :blk r;
    } else freeSlot() orelse return null;

    const conn = &tcp_conns[slot];
    // An edge-triggered watcher of a reused slot must see a change.
    const events = conn.events +% 1;
    conn.* = .{};
    conn.events = events;
    conn.active = true;
    attachRing(conn);
    conn.state = .syn_sent;
    conn.local_port = if (local_port != 0) local_port else ephemeralPort();
    conn.remote_port = dst_port;
    conn.remote_ip = dst_ip;
    conn.snd_iss = @truncate(process.tick_count *% 1103515245 +% 12345);
    conn.snd_una = conn.snd_iss;
    // The SYN takes one sequence number. Counted before it is sent: a local
    // peer's answer is processed inside the send.
    conn.snd_nxt = conn.snd_iss +% 1;
    conn.snd_max = conn.snd_nxt;
    conn.recover = conn.snd_iss;
    if (!emitSegment(conn, conn.snd_iss, TCP_SYN, null)) {
        if (reuse == null) conn.active = false else tcpFailWith(conn, .timed_out);
        return null;
    }
    return slot;
}

pub fn tcpConnect(dst_ip: [4]u8, dst_port: u16) ?u8 {
    const slot = tcpConnectStart(dst_ip, dst_port, 0) orelse return null;
    const conn = &tcp_conns[slot];

    // Wait for SYN-ACK, unlocked — state/error_flag are single-byte reads
    // and the RX path owns the transitions. Tick-based 5s deadline + 10ms
    // sleep between polls so the BSP isn't locked during a slow handshake.
    const syn_deadline: u64 = process.tick_count + 500;
    while (process.tick_count < syn_deadline) {
        poll();
        if (conn.state == .established) return slot;
        if (conn.error_flag) break;
        process.kernelSleepMs(10);
    }
    const lk = net_lock.acquireIrqSave();
    conn.active = false;
    netUnlock(lk);
    return null;
}

/// Build the half-open server side of a connection from a freshly-arrived
/// SYN. Allocates a free TcpConn slot, fills it with the peer's IP/port and
/// our chosen ISS, and immediately replies with SYN+ACK. The slot stays in
/// SYN-RECEIVED until the peer's ACK promotes it to ESTABLISHED — only then
/// does it become visible to user-space accept().
/// False when nobody listens on the port: the caller answers with a reset.
fn tryAcceptIncomingSyn(ip_data: []volatile u8, ihl: usize, local_port: u16, remote_port: u16, peer_seq: u32) bool {
    var listener: ?*TcpListener = null;
    for (&tcp_listeners) |*l| {
        if (l.active and l.port == local_port) {
            listener = l;
            break;
        }
    }
    const lst = listener orelse return false;

    // Out of slots: drop the SYN, the peer sends it again.
    const slot = freeSlot() orelse return true;

    const peer_ip: [4]u8 = .{ ip_data[12], ip_data[13], ip_data[14], ip_data[15] };

    var conn = &tcp_conns[slot];
    conn.* = .{};
    conn.active = true;
    attachRing(conn);
    conn.state = .syn_received;
    conn.local_port = local_port;
    conn.remote_port = remote_port;
    conn.remote_ip = peer_ip;
    conn.snd_iss = @truncate(process.tick_count *% 1103515245 +% 12345 +% @as(u64, slot) *% 7919);
    conn.snd_una = conn.snd_iss;
    // Our SYN takes one sequence number, counted before the SYN-ACK is
    // sent: a local peer's ACK of it is processed inside the send.
    conn.snd_nxt = conn.snd_iss +% 1;
    conn.snd_max = conn.snd_nxt;
    conn.recover = conn.snd_iss;
    conn.rcv_nxt = peer_seq +% 1; // peer's SYN consumes one seq number
    conn.listener_slot = listenerSlotIndex(lst);

    // What the SYN offers: its MSS bounds our segments; window scaling and
    // SACK hold if it asks, and the SYN-ACK says so. The real ihl: TCP
    // options extend data_offset, IP options shift the header itself
    // (handleTcpPacket checked data_offset).
    const tcp = ip_data[ihl..];
    const o = parseSynOptions(tcp, @as(usize, tcp[12] >> 4) * 4);
    conn.peer_mss = o.mss;
    if (o.wscale) |s| {
        conn.ws_ok = true;
        conn.snd_wscale = s;
    } else conn.rcv_wscale = 0;
    conn.sack_ok = o.sack_ok;

    if (!emitSegment(conn, conn.snd_iss, TCP_SYN | TCP_ACK, null)) conn.active = false;
    return true;
}

/// Answer a segment no connection or listener takes with a reset (RFC 793):
/// a connect to a port nobody listens on is refused at once instead of
/// timing out, and a peer still talking to a connection that is gone
/// learns it. Lock held.
fn sendReset(ip_data: []volatile u8, ihl: usize) void {
    const tcp = ip_data[ihl..];
    const flags = tcp[13];
    if (flags & TCP_RST != 0) return;
    const peer_ip: [4]u8 = .{ ip_data[12], ip_data[13], ip_data[14], ip_data[15] };
    const to_ip: [4]u8 = .{ ip_data[16], ip_data[17], ip_data[18], ip_data[19] };
    if (!isLocal(to_ip)) return;
    const local = isLocal(peer_ip);
    if (!local and !gateway_mac_valid) return;

    const data_offset = @as(usize, tcp[12] >> 4) * 4;
    const payload_len: u32 = @intCast(tcp.len -| data_offset);
    var seq: u32 = 0;
    var ack: u32 = 0;
    var out_flags: u8 = TCP_RST;
    if (flags & TCP_ACK != 0) {
        seq = readU32BE(tcp[8..12]);
    } else {
        ack = readU32BE(tcp[4..8]) +% payload_len +% @intFromBool(flags & TCP_SYN != 0) +% @intFromBool(flags & TCP_FIN != 0);
        out_flags |= TCP_ACK;
    }

    var pkt: [ETH_HDR_SIZE + IPV4_HDR_SIZE + TCP_HDR_SIZE]u8 = undefined;
    const src_mac = nic.getMac();
    buildEthHeader(&pkt, if (local) src_mac else gateway_mac, src_mac, ETHERTYPE_IPV4);
    buildIPv4Header(pkt[ETH_HDR_SIZE..], IPPROTO_TCP, peer_ip, TCP_HDR_SIZE);
    const out = pkt[ETH_HDR_SIZE + IPV4_HDR_SIZE ..];
    @memset(out, 0);
    writeU16BE(out[0..2], readU16BE(tcp[2..4]));
    writeU16BE(out[2..4], readU16BE(tcp[0..2]));
    writeU32BE(out[4..8], seq);
    writeU32BE(out[8..12], ack);
    out[12] = 5 << 4;
    out[13] = out_flags;
    const csum = tcpChecksum(outboundSrcIp(peer_ip), peer_ip, out[0..TCP_HDR_SIZE]);
    out[16] = @intCast(csum >> 8);
    out[17] = @intCast(csum & 0xFF);
    _ = dispatchPacket(peer_ip, &pkt);
}

/// Bind a server-side TCP socket to `port`. Returns the listener slot id, or
/// null if all listener slots are taken or the port is already bound.
/// Inbound SYNs whose dst_port matches a listener's port spawn a new TcpConn
/// in SYN-RECEIVED; once it reaches ESTABLISHED the conn slot id appears in
/// the listener's accept ring for `tcpAccept` to consume.
pub fn tcpListen(port: u16) ?u8 {
    if (port == 0) return null;
    // Connections a listener takes start in NIC-IRQ context, which can't
    // allocate: a ring waits for the first.
    provisionRing();
    const lk = net_lock.acquireIrqSave();
    defer netUnlock(lk);
    // Reject duplicates so accept rings stay sane.
    for (tcp_listeners) |l| {
        if (l.active and l.port == port) return null;
    }
    for (&tcp_listeners, 0..) |*l, idx| {
        if (l.active) continue;
        l.* = .{
            .active = true,
            .port = port,
        };
        return @intCast(idx);
    }
    return null;
}

pub fn tcpUnlisten(listen_slot: u8) void {
    if (listen_slot >= TCP_MAX_LISTENERS) return;
    const lk = net_lock.acquireIrqSave();
    defer netUnlock(lk);
    const l = &tcp_listeners[listen_slot];
    if (!l.active) return;
    // What nobody accepted has no owner: the queued connections close, the
    // handshakes in progress are dropped.
    while (l.accept_head != l.accept_tail) {
        const slot = l.accept_ring[l.accept_tail];
        l.accept_tail = (l.accept_tail + 1) % TCP_ACCEPT_RING_SIZE;
        if (slot < TCP_MAX_CONNS) releaseConn(&tcp_conns[slot]);
    }
    for (&tcp_conns) |*c| {
        if (c.active and c.state == .syn_received and c.listener_slot == listen_slot) c.active = false;
    }
    l.* = .{};
}

/// The port listener `listen_slot` is on.
/// True if a listener has `port`: a bind to it is refused.
pub fn tcpPortListening(port: u16) bool {
    const lk = net_lock.acquireIrqSave();
    defer netUnlock(lk);
    for (tcp_listeners) |l| {
        if (l.active and l.port == port) return true;
    }
    return false;
}

pub fn tcpListenerPort(listen_slot: u8) u16 {
    if (listen_slot >= TCP_MAX_LISTENERS) return 0;
    return tcp_listeners[listen_slot].port;
}

pub fn tcpListenerEvents(listen_slot: u8) u32 {
    if (listen_slot >= TCP_MAX_LISTENERS) return 0;
    return tcp_listeners[listen_slot].events;
}

/// Bind a listener to a port nobody listens on, chosen here.
pub fn tcpListenAny() ?u8 {
    var tries: u32 = 0;
    while (tries < 64) : (tries += 1) {
        const port = blk: {
            const lk = net_lock.acquireIrqSave();
            defer netUnlock(lk);
            break :blk ephemeralPort();
        };
        if (tcpListen(port)) |slot| return slot;
    }
    return null;
}

/// Pop one ESTABLISHED conn slot from the listener's accept ring, or null if
/// nothing is queued yet. Non-blocking — the caller polls.
pub fn tcpAccept(listen_slot: u8) ?u8 {
    if (listen_slot >= TCP_MAX_LISTENERS) return null;
    provisionRing(); // for the connection after this one
    const lk = net_lock.acquireIrqSave();
    defer netUnlock(lk);
    const l = &tcp_listeners[listen_slot];
    if (!l.active) return null;
    if (l.accept_head == l.accept_tail) return null; // ring empty
    const slot = l.accept_ring[l.accept_tail];
    l.accept_ring[l.accept_tail] = 0xFF;
    l.accept_tail = (l.accept_tail + 1) % TCP_ACCEPT_RING_SIZE;
    return slot;
}

// === send buffer (snd_buf ring) ===

/// Most unacked bytes we may keep in flight: the peer's advertised window
/// and the congestion window bound it (the ring bounds what there is to send).
fn effectiveWindow(conn: *const TcpConn) u32 {
    return @min(conn.snd_wnd, conn.cwnd);
}

/// Free bytes in the send ring.
fn sndSpace(conn: *const TcpConn) u32 {
    // Saturating: a look without the lock may pair a new mask with an old length.
    return (conn.snd_mask + 1) -| conn.snd_buf_len;
}

/// Append `bytes` at the ring tail (sequence snd_una+snd_buf_len). The caller
/// guarantees bytes.len <= free space.
fn appendSnd(conn: *TcpConn, bytes: []const u8) void {
    const pos = (conn.snd_buf_head +% conn.snd_buf_len) & conn.snd_mask;
    const first = @min(bytes.len, (conn.snd_mask + 1) - pos);
    @memcpy(conn.snd_buf[pos..][0..first], bytes[0..first]);
    @memcpy(conn.snd_buf[0 .. bytes.len - first], bytes[first..]);
    conn.snd_buf_len += @intCast(bytes.len);
}

/// Copy out.len bytes from the ring starting at sequence number `seq`, which
/// must lie within [snd_una, snd_una+snd_buf_len).
fn readSnd(conn: *const TcpConn, seq: u32, out: []u8) void {
    const pos = (conn.snd_buf_head +% (seq -% conn.snd_una)) & conn.snd_mask;
    const first = @min(out.len, (conn.snd_mask + 1) - pos);
    @memcpy(out[0..first], conn.snd_buf[pos..][0..first]);
    @memcpy(out[first..], conn.snd_buf[0 .. out.len - first]);
}

/// Send the first unacked segment again, from the ring, whatever the
/// windows say.
fn resendFirst(c: *TcpConn) void {
    const out = sndTop(c) -% c.snd_una;
    const seg = @min(@min(out, c.snd_buf_len), @as(u32, c.peer_mss));
    if (seg == 0) return;
    var tmp: [1460]u8 = undefined;
    readSnd(c, c.snd_una, tmp[0..seg]);
    _ = emitSegment(c, c.snd_una, TCP_PSH | TCP_ACK, tmp[0..seg]);
}

/// All that is out counts as lost: sending starts over at the first unacked
/// byte. What was out stays known (snd_max): it is not timed as new, and
/// its duplicate ACKs start no fast retransmit.
fn goBackN(c: *TcpConn) void {
    c.snd_max = sndTop(c);
    c.recover = c.snd_max;
    c.snd_nxt = c.snd_una;
    c.dup_acks = 0;
    c.in_recovery = false;
}

/// The peer's window is shut with data waiting: one byte past it. The
/// answer carries the window; the byte counts as sent, so an ACK of it is
/// taken.
fn probeWindow(c: *TcpConn) void {
    var b: [1]u8 = undefined;
    readSnd(c, c.snd_una, &b);
    if (!emitSegment(c, c.snd_una, TCP_PSH | TCP_ACK, &b)) return;
    c.snd_nxt = c.snd_una +% 1;
    if (seqLt(c.snd_max, c.snd_nxt)) c.snd_max = c.snd_nxt;
}

/// Fold a new RTT sample into the smoothed estimate and recompute the
/// retransmit timeout (RFC 6298 integer form). All quantities are in ticks.
fn updateRto(c: *TcpConn, sample: u64) void {
    const r: u32 = @intCast(@min(sample, @as(u64, TCP_MAX_RTO_TICKS)));
    if (c.srtt == 0) {
        c.srtt = r;
        c.rttvar = r / 2;
    } else {
        const err = if (c.srtt > r) c.srtt - r else r - c.srtt;
        c.rttvar = c.rttvar - (c.rttvar >> 2) + (err >> 2);
        c.srtt = c.srtt - (c.srtt >> 3) + (r >> 3);
    }
    c.rto = estimatedRto(c);
}

/// The timeout the RTT estimate gives, with no backoff on it.
fn estimatedRto(c: *const TcpConn) u32 {
    const rto = c.srtt + @max(@as(u32, 1), c.rttvar << 2);
    return @min(@max(rto, TCP_MIN_RTO_TICKS), TCP_MAX_RTO_TICKS);
}

/// Reset the congestion window for a freshly-established connection: a small
/// initial window and a high ssthresh, so we begin in slow start.
fn initCwnd(c: *TcpConn) void {
    c.cwnd = TCP_INIT_CWND_SEGS * @as(u32, c.peer_mss);
    c.ssthresh = TCP_MAX_CWND;
    c.dup_acks = 0;
    c.in_recovery = false;
}

/// Grow the congestion window on an ACK of `acked` new bytes: slow start (one
/// MSS per ACK) below ssthresh, congestion avoidance (~one MSS per RTT) above.
/// Leaving fast recovery deflates cwnd back to ssthresh.
fn ackCwnd(c: *TcpConn, acked: u32) void {
    const mss: u32 = c.peer_mss;
    if (c.in_recovery) {
        c.cwnd = c.ssthresh;
        c.in_recovery = false;
    } else if (c.cwnd < c.ssthresh) {
        c.cwnd += @min(acked, mss);
    } else {
        c.cwnd += @max(@as(u32, 1), (mss *% mss) / c.cwnd);
    }
    if (c.cwnd > TCP_MAX_CWND) c.cwnd = TCP_MAX_CWND;
}

/// Three duplicate ACKs: halve ssthresh, drop cwnd to it, and retransmit the
/// first unacked segment immediately instead of waiting for the RTO. The
/// recovery lasts until all that is out now is acked: an ACK short of that
/// names the next hole (processAck).
fn fastRetransmit(c: *TcpConn) void {
    const mss: u32 = c.peer_mss;
    c.ssthresh = @max(c.cwnd / 2, 2 * mss);
    c.cwnd = c.ssthresh;
    c.in_recovery = true;
    c.recover = sndTop(c);
    resendFirst(c);
    c.rtt_pending = false;
}

/// Emit MSS-sized segments from snd_nxt as the send window allows, at most
/// TCP_FLUSH_BURST of them, advancing snd_nxt over [snd_nxt,
/// snd_una+snd_buf_len): bytes never sent, or after a timeout pulled
/// snd_nxt back, bytes sent before.
fn flushSnd(conn: *TcpConn) void {
    const wnd = effectiveWindow(conn);
    var burst: u32 = 0;
    while (burst < TCP_FLUSH_BURST) : (burst += 1) {
        const unsent = (conn.snd_una +% conn.snd_buf_len) -% conn.snd_nxt;
        if (unsent == 0) break;
        const inflight = conn.snd_nxt -% conn.snd_una;
        if (inflight >= wnd) break; // window full
        const allow = wnd - inflight;
        const seg = @min(@min(unsent, @as(u32, conn.peer_mss)), allow);
        if (seg == 0) break;
        var tmp: [1460]u8 = undefined;
        readSnd(conn, conn.snd_nxt, tmp[0..seg]);
        if (!emitSegment(conn, conn.snd_nxt, TCP_PSH | TCP_ACK, tmp[0..seg])) break;
        const first_time = !seqLt(conn.snd_nxt, conn.snd_max);
        conn.snd_nxt +%= seg;
        if (seqLt(conn.snd_max, conn.snd_nxt)) conn.snd_max = conn.snd_nxt;
        // Begin an RTT sample for this segment if one isn't already timing.
        // Karn: never from bytes sent before.
        if (first_time and !conn.rtt_pending) {
            conn.rtt_pending = true;
            conn.rtt_start = process.tick_count;
            conn.rtt_seq = conn.snd_nxt;
        }
    }
}

pub fn tcpSend(slot: u8, data: []const u8) bool {
    if (slot >= TCP_MAX_CONNS) return false;
    const conn = &tcp_conns[slot];
    if (!conn.active or conn.state != .established) return false;
    // Blocking gateway resolution up front, outside the lock — emitSegment
    // itself must never block (it also runs in NIC-IRQ context).
    if (!isLocal(conn.remote_ip) and !arpResolveGateway()) return false;

    var off: usize = 0;
    while (off < data.len) {
        // Append + flush under the lock; space is recomputed under the lock
        // so an IRQ-side ACK between iterations can only GROW it.
        {
            const lk = net_lock.acquireIrqSave();
            defer netUnlock(lk);
            if (conn.error_flag or conn.state != .established) return false;
            const space: usize = sndSpace(conn);
            if (space > 0) {
                const chunk = @min(data.len - off, space);
                appendSnd(conn, data[off..][0..chunk]);
                off += chunk;
                flushSnd(conn);
                continue;
            }
        }
        // Ring full: wait (unlocked, bounded) for ACKs to drain it — via the
        // NIC IRQ in IRQ-driven mode, via poll() in polled mode. The deadline
        // keeps a stalled peer from wedging the caller forever.
        poll();
        const deadline = process.tick_count + 500;
        var have_space = false;
        while (process.tick_count < deadline) {
            if (conn.error_flag or conn.state != .established) return false;
            if (sndSpace(conn) != 0) {
                have_space = true;
                break;
            }
            process.kernelSleepMs(10);
            poll();
        }
        if (!have_space) return false; // timed out
    }
    return true;
}

pub fn tcpRecv(slot: u8, buf: []u8) usize {
    if (slot >= TCP_MAX_CONNS) return 0;
    const conn = &tcp_conns[slot];
    const lk = net_lock.acquireIrqSave();
    defer netUnlock(lk);
    if (!conn.active) return 0;
    if (conn.rx_count == 0) return 0;

    const avail = @min(conn.rx_count, @as(u32, @intCast(@min(buf.len, std.math.maxInt(u32)))));
    ringRead(conn, buf[0..avail]);
    conn.rx_count -= avail;

    // If the window has opened a meaningful amount past what the peer was
    // last told, tell it with an empty ACK. Without this, a sender that
    // throttled against a small or zero window would sit idle until the
    // next normal ACK we send (which only happens when the peer sends more
    // data — chicken-and-egg). Measured against the advertised edge, not
    // this one read: a reader taking a little at a time opens it just as
    // far in the end.
    const receiving = conn.state == .established or conn.state == .fin_wait_1 or conn.state == .fin_wait_2;
    if (receiving and windowOpened(conn)) {
        _ = sendTcpPacket(conn, TCP_ACK, null);
    }
    return avail;
}

/// Diagnostics: every live connection, one line each.
pub fn dumpTcp() void {
    const serial = @import("../debug/serial.zig");
    const now = process.tick_count;
    const lk = net_lock.acquireIrqSave();
    defer netUnlock(lk);
    serial.print("[tcp-dump] frames in {d} ({d} bytes), TCP segments for no connection {d}\n", .{ rx_frame_count, rx_frame_total_bytes, tcp_unmatched });
    for (&tcp_conns, 0..) |*c, i| {
        if (!c.active) continue;
        serial.print("[tcp-dump] slot {d} {s} :{d} -> {d}.{d}.{d}.{d}:{d}; rcv_nxt {d} rx {d}/{d} adv {d} ooo runs {d}; ws {s} {d}/{d}, sack {s}; in {d} segs {d} bytes, ooo {d} old {d} cut {d} full {d} peak {d};", .{
            i,              @tagName(c.state),             c.local_port,
            c.remote_ip[0], c.remote_ip[1],                c.remote_ip[2],
            c.remote_ip[3], c.remote_port,                 c.rcv_nxt,
            c.rx_count,     c.rx_mask + 1,                 c.adv_wnd,
            c.n_ooo,        if (c.ws_ok) "on" else "off",  c.rcv_wscale,
            c.snd_wscale,   if (c.sack_ok) "on" else "off", c.st_segs,
            c.st_bytes,     c.st_ooo,                      c.st_old,
            c.st_cut,       c.st_full,                     c.st_peak,
        });
        serial.print(" snd una {d} nxt {d} buf {d} wnd {d} cwnd {d} rto {d} retx {d}; last tx {d} ticks ago; events {d}{s}{s}{s}{s}\n", .{
            c.snd_una,                             c.snd_nxt,                        c.snd_buf_len,
            c.snd_wnd,                             c.cwnd,                           c.rto,
            c.retransmit_count,                    now -| c.last_send_tick,          c.events,
            if (c.peer_closed) " peer-closed" else "", if (c.rd_closed) " rd-closed" else "", if (c.orphan) " orphan" else "",
            if (c.error_flag) " error" else "",
        });
    }
}

pub fn tcpClose(slot: u8) void {
    if (slot >= TCP_MAX_CONNS) return;
    var conn = &tcp_conns[slot];
    if (!conn.active) return;

    // Drain the send ring (bounded) BEFORE the FIN. Close used to abandon
    // any buffered-but-unsent tail: the FIN went out at snd_nxt, the bytes
    // beyond it were never flushed, and tcpTick's retransmit logic only
    // re-sent the FIN — classic send-then-close data loss.
    const drain_deadline: u64 = process.tick_count + 200;
    while (process.tick_count < drain_deadline) {
        var pending = false;
        {
            const lk = net_lock.acquireIrqSave();
            defer netUnlock(lk);
            if ((conn.state == .established or conn.state == .close_wait) and
                !conn.error_flag and conn.snd_buf_len > 0)
            {
                flushSnd(conn);
                pending = conn.snd_buf_len > 0;
            }
        }
        if (!pending) break;
        poll();
        process.kernelSleepMs(10);
    }

    var sent_fin = false;
    {
        const lk = net_lock.acquireIrqSave();
        defer netUnlock(lk);
        if (conn.state == .established or conn.state == .close_wait) {
            // Past all that was sent, acked or not (the drain above gave up).
            const fin_seq = sndTop(conn);
            _ = emitSegment(conn, fin_seq, TCP_FIN | TCP_ACK, null);
            conn.snd_nxt = fin_seq +% 1;
            conn.state = if (conn.state == .close_wait) .last_ack else .fin_wait_1;
            sent_fin = true;
        }
    }
    if (sent_fin) {
        // Wait up to 1s for FIN-ACK with 10ms sleeps (unlocked; state is a
        // single-byte read). The peer almost always ACKs within one RTT.
        const close_deadline: u64 = process.tick_count + 100;
        while (process.tick_count < close_deadline) {
            poll();
            if (conn.state == .closed or conn.state == .time_wait) break;
            process.kernelSleepMs(10);
        }
    }
    const lk = net_lock.acquireIrqSave();
    reportConn(conn);
    conn.active = false;
    conn.state = .closed;
    netUnlock(lk);
}

// --- What a socket does with a connection ------------------------------------
//
// None of these wait: the socket layer sleeps on the readiness tcpView
// reports and tries again. A slot a socket holds is freed by tcpRelease
// alone (at once, or when the close it starts is done); the legacy calls
// above free theirs in tcpClose.

/// Send our FIN if one is wanted and everything before it is acked. The
/// state and snd_nxt move first: a local peer's ACK is processed inside the
/// send. Lock held.
fn maybeSendFin(c: *TcpConn) void {
    if (!c.fin_wanted or c.fin_sent) return;
    if (c.state != .established and c.state != .close_wait) return;
    if (c.snd_buf_len != 0) return;
    const seq = c.snd_nxt;
    c.fin_sent = true;
    c.snd_nxt +%= 1;
    c.state = if (c.state == .close_wait) .last_ack else .fin_wait_1;
    _ = emitSegment(c, seq, TCP_FIN | TCP_ACK, null);
}

/// A transfer of a megabyte or more leaves one line when its socket goes:
/// how fast it came and what the receive path saw. Lock held.
fn reportConn(c: *const TcpConn) void {
    if (c.st_bytes < 1 << 20) return;
    const ticks = @max(process.tick_count -% c.st_start, 1);
    @import("../debug/serial.zig").print("[tcp] slot {d} from {d}.{d}.{d}.{d}:{d}: {d} bytes in {d} segments over {d} ms = {d} KiB/s; ring {d}, reader left at most {d}; out of order {d}, old {d}, cut {d}, window full {d}; scaling {s}, sack {s}\n", .{
        connSlotIndex(c),      c.remote_ip[0], c.remote_ip[1],         c.remote_ip[2],
        c.remote_ip[3],        c.remote_port,  c.st_bytes,             c.st_segs,
        ticks * 10,            c.st_bytes * 100 / ticks / 1024,        c.rx_mask + 1, c.st_peak,
        c.st_ooo,              c.st_old,       c.st_cut,               c.st_full,
        if (c.ws_ok) "on" else "off", if (c.sack_ok) "on" else "off",
    });
}

/// A socket that goes with its connection unfinished leaves one line: no
/// handshake, data not acked, or never a byte from the peer. Lock held.
fn reportUnfinished(c: *const TcpConn) void {
    if (c.error_flag or c.state == .closed or c.state == .listen) return;
    const out = sndTop(c) -% c.snd_una;
    const heard = c.st_bytes != 0 or c.peer_closed;
    if (c.state != .syn_sent and out == 0 and c.snd_buf_len == 0 and heard) return;
    debug.klog("[tcp] left {s}: port {d} -> {d}.{d}.{d}.{d}:{d} sent={d} out={d} queued={d} wnd={d} cwnd={d} tries={d} rto={d} got={d} unread={d} idle={d} ticks\n", .{
        @tagName(c.state),
        c.local_port,
        c.remote_ip[0],
        c.remote_ip[1],
        c.remote_ip[2],
        c.remote_ip[3],
        c.remote_port,
        c.snd_nxt -% c.snd_iss,
        out,
        c.snd_buf_len,
        c.snd_wnd,
        c.cwnd,
        c.retransmit_count,
        c.rto,
        c.st_bytes,
        c.rx_count,
        process.tick_count -% c.last_send_tick,
    });
}

/// The owner of `c` is gone. Lock held.
fn releaseConn(c: *TcpConn) void {
    if (!c.active) return;
    reportConn(c);
    reportUnfinished(c);
    detachRing(c);
    c.rd_closed = true;
    // Nothing to finish: never connected, failed, or closed both ways.
    if (c.error_flag or c.state == .closed or c.state == .syn_sent or c.state == .syn_received) {
        c.active = false;
        c.state = .closed;
        return;
    }
    c.orphan = true;
    c.orphan_deadline = process.tick_count + TCP_ORPHAN_TICKS;
    c.fin_wanted = true;
    maybeSendFin(c);
}

/// The socket of connection `slot` is gone. What it sent is still
/// delivered and the close completed, in the background; the slot frees
/// itself after. Never sleeps.
pub fn tcpRelease(slot: u8) void {
    if (slot >= TCP_MAX_CONNS) return;
    const lk = net_lock.acquireIrqSave();
    defer netUnlock(lk);
    releaseConn(&tcp_conns[slot]);
}

/// No more will be sent on `slot`: the peer reads an end of stream after
/// what is already queued. Receiving goes on.
pub fn tcpShutdownWrite(slot: u8) void {
    if (slot >= TCP_MAX_CONNS) return;
    const lk = net_lock.acquireIrqSave();
    defer netUnlock(lk);
    const c = &tcp_conns[slot];
    if (!c.active) return;
    c.fin_wanted = true;
    maybeSendFin(c);
}

pub const TcpSent = union(enum) {
    /// This many bytes went into the send ring.
    bytes: usize,
    /// The ring is full: wait for `writable`.
    full,
    /// The connection can't send: failed, or our side is shut.
    closed,
};

/// Take what fits of `data` (kernel memory) into the send ring and send on.
pub fn tcpSendSome(slot: u8, data: []const u8) TcpSent {
    if (slot >= TCP_MAX_CONNS) return .closed;
    const lk = net_lock.acquireIrqSave();
    defer netUnlock(lk);
    const c = &tcp_conns[slot];
    if (!c.active or c.error_flag or c.fin_wanted) return .closed;
    if (c.state != .established and c.state != .close_wait) return .closed;
    const space: usize = sndSpace(c);
    if (space == 0) return .full;
    const chunk = @min(data.len, space);
    appendSnd(c, data[0..chunk]);
    flushSnd(c);
    return .{ .bytes = chunk };
}

/// tcpRecv that leaves the bytes in place (MSG_PEEK).
pub fn tcpPeek(slot: u8, buf: []u8) usize {
    if (slot >= TCP_MAX_CONNS) return 0;
    const c = &tcp_conns[slot];
    const lk = net_lock.acquireIrqSave();
    defer netUnlock(lk);
    if (!c.active) return 0;
    const avail = @min(c.rx_count, @as(u32, @intCast(@min(buf.len, std.math.maxInt(u32)))));
    ringRead(c, buf[0..avail]);
    return avail;
}

/// Where a connection stands, read without the lock (each field is one
/// load; a poll that looks a moment early looks again on the next event).
pub const TcpView = struct {
    /// The handshake is still out.
    connecting: bool = false,
    /// Reset, refused or timed out; `fail` says which.
    failed: bool = false,
    fail: TcpFail = .none,
    /// Bytes wait to be read.
    readable: bool = false,
    /// The peer sent its FIN and everything before it was read.
    eof: bool = false,
    /// The send ring has room.
    writable: bool = false,
    /// Bytes a read would get now.
    rx_bytes: u32 = 0,
    events: u32 = 0,
};

pub fn tcpView(slot: u8) TcpView {
    if (slot >= TCP_MAX_CONNS) return .{ .failed = true, .eof = true };
    const c = &tcp_conns[slot];
    if (!c.active) return .{ .eof = true };
    const rx = c.rx_count;
    const open = c.state == .established or c.state == .close_wait;
    return .{
        .connecting = c.state == .syn_sent and !c.error_flag,
        .failed = c.error_flag,
        .fail = c.fail,
        .readable = rx > 0,
        .eof = rx == 0 and c.peer_closed,
        .writable = open and !c.error_flag and !c.fin_wanted and sndSpace(c) != 0,
        .rx_bytes = rx,
        .events = c.events,
    };
}

pub const Endpoint = struct { ip: [4]u8, port: u16 };

/// Our end of connection `slot`. A local connection has the peer's address
/// on both ends (outboundSrcIp).
pub fn tcpLocal(slot: u8) Endpoint {
    if (slot >= TCP_MAX_CONNS) return .{ .ip = .{ 0, 0, 0, 0 }, .port = 0 };
    const c = &tcp_conns[slot];
    return .{ .ip = outboundSrcIp(c.remote_ip), .port = c.local_port };
}

pub fn tcpRemote(slot: u8) Endpoint {
    if (slot >= TCP_MAX_CONNS) return .{ .ip = .{ 0, 0, 0, 0 }, .port = 0 };
    const c = &tcp_conns[slot];
    return .{ .ip = c.remote_ip, .port = c.remote_port };
}

/// True while any connection or datagram socket is in use: the
/// housekeeping task ticks faster.
pub fn busy() bool {
    for (&tcp_conns) |*c| {
        if (c.active) return true;
    }
    for (&udp_socks) |*s| {
        if (s.active) return true;
    }
    return false;
}

// tcpIsConnected/tcpPeerClosed/tcpPollMask/tcpListenerPollMask are LOCK-FREE
// readiness probes by design: every field they touch is a single-byte/u32
// load (momentary staleness is inherent to polling), and tcpPollMask is
// called by fdpoll.wakePollers WHILE the RX path holds net_lock — taking
// the lock here would self-deadlock.
pub fn tcpIsConnected(slot: u8) bool {
    if (slot >= TCP_MAX_CONNS) return false;
    return tcp_conns[slot].active and tcp_conns[slot].state == .established;
}

pub fn tcpPeerClosed(slot: u8) bool {
    if (slot >= TCP_MAX_CONNS) return true;
    return !tcp_conns[slot].active or tcp_conns[slot].peer_closed or tcp_conns[slot].error_flag;
}

// POSIX poll bits — duplicated from fdpoll.zig (single source if/when we
// add more wakers; net.zig avoids importing fdpoll at top level to dodge
// the iouring↔fdpoll↔net cycle through fdpoll.completion_callback).
const POLLIN_BIT: u16 = 0x0001;
const POLLOUT_BIT: u16 = 0x0004;
const POLLERR_BIT: u16 = 0x0008;
const POLLHUP_BIT: u16 = 0x0010;

/// Readiness mask for a connection slot. Consumed by fdpoll.pollMaskHandle
/// when an OP_POLL is submitted against a .tcp_sock fd. Free-window check
/// for POLLOUT mirrors send-side: established connections with in-flight
/// bytes below the rx window count as writable (the kernel splits into
/// MSS-sized segments internally, so userspace doesn't need to know the
/// exact byte budget).
pub fn tcpPollMask(slot: u8) u16 {
    if (slot >= TCP_MAX_CONNS) return POLLERR_BIT;
    const c = &tcp_conns[slot];
    if (!c.active) return POLLERR_BIT;
    var mask: u16 = 0;
    if (c.rx_count > 0 or c.peer_closed) mask |= POLLIN_BIT;
    if (c.state == .established) mask |= POLLOUT_BIT;
    if (c.error_flag) mask |= POLLERR_BIT;
    if (c.peer_closed and c.rx_count == 0) mask |= POLLHUP_BIT;
    return mask;
}

/// Readiness mask for a listener slot. POLLIN means accept() won't block.
pub fn tcpListenerPollMask(slot: u8) u16 {
    if (slot >= TCP_MAX_LISTENERS) return POLLERR_BIT;
    const l = &tcp_listeners[slot];
    if (!l.active) return POLLERR_BIT;
    if (l.accept_head != l.accept_tail) return POLLIN_BIT;
    return 0;
}

/// Put `data` into the receive ring where the byte `off` past rcv_nxt
/// belongs: at most two copies around the wrap. The caller keeps it within
/// the free space.
fn ringWrite(c: *TcpConn, off: u32, data: []const u8) void {
    const at = (c.rx_write +% off) & c.rx_mask;
    const first = @min(data.len, (c.rx_mask + 1) - at);
    @memcpy(c.rx_buf[at..][0..first], data[0..first]);
    if (data.len > first) @memcpy(c.rx_buf[0 .. data.len - first], data[first..]);
}

/// The oldest out.len bytes the reader hasn't taken, copied out.
fn ringRead(c: *const TcpConn, out: []u8) void {
    const at = (c.rx_write -% c.rx_count) & c.rx_mask;
    const first = @min(out.len, (c.rx_mask + 1) - at);
    @memcpy(out[0..first], c.rx_buf[at..][0..first]);
    if (out.len > first) @memcpy(out[first..], c.rx_buf[0 .. out.len - first]);
}

/// `n` bytes at rcv_nxt, already in the ring, become the reader's.
fn rxAdvance(c: *TcpConn, n: u32) void {
    c.rx_write +%= n;
    c.rx_count += n;
    c.rcv_nxt +%= n;
    c.st_bytes += n;
    if (c.rx_count > c.st_peak) c.st_peak = c.rx_count;
}

fn oooRemove(c: *TcpConn, i: u8) void {
    var j = i;
    while (j + 1 < c.n_ooo) : (j += 1) c.ooo[j] = c.ooo[j + 1];
    c.n_ooo -= 1;
    if (c.ooo_recent > i) c.ooo_recent -= 1 else if (c.ooo_recent == i) c.ooo_recent = 0;
}

/// Note [lo, hi), just written to the ring past a gap: joined with every
/// run it touches. With no room for another run it goes unnoted, and the
/// peer sends it again.
fn oooAdd(c: *TcpConn, lo: u32, hi: u32) void {
    var run: SeqRun = .{ .lo = lo, .hi = hi };
    var i: u8 = 0;
    while (i < c.n_ooo) {
        const r = c.ooo[i];
        if (seqLe(r.lo, run.hi) and seqLe(run.lo, r.hi)) {
            if (seqLt(r.lo, run.lo)) run.lo = r.lo;
            if (seqLt(run.hi, r.hi)) run.hi = r.hi;
            oooRemove(c, i);
            continue;
        }
        i += 1;
    }
    if (c.n_ooo == TCP_OOO_RUNS) return;
    var at: u8 = 0;
    while (at < c.n_ooo and seqLt(c.ooo[at].lo, run.lo)) at += 1;
    var j = c.n_ooo;
    while (j > at) : (j -= 1) c.ooo[j] = c.ooo[j - 1];
    c.ooo[at] = run;
    c.n_ooo += 1;
    c.ooo_recent = at;
}

/// rcv_nxt has moved: runs it reached join the stream, their bytes already
/// in place (a byte's spot in the ring follows from its sequence number).
fn oooMerge(c: *TcpConn) void {
    while (c.n_ooo > 0) {
        const r = c.ooo[0];
        if (seqLt(c.rcv_nxt, r.lo)) return; // a gap is left
        if (seqLt(c.rcv_nxt, r.hi)) rxAdvance(c, r.hi -% c.rcv_nxt);
        oooRemove(c, 0);
    }
}

/// Take a segment's payload: what lies in the window goes into the ring at
/// its place, in order or not. Always ACKs: a non-advancing ACK is the
/// duplicate ACK the peer's fast retransmit keys on, and its SACK blocks
/// say what came past the gap.
fn receiveData(c: *TcpConn, seq: u32, tcp: []volatile u8, data_offset: usize, payload_len: usize) void {
    if (payload_len == 0) return;
    if (c.st_segs == 0) c.st_start = process.tick_count;
    c.st_segs +%= 1;
    // DMA is done by the time the RX path runs: plain memory now.
    const src: [*]const u8 = @volatileCast(tcp[data_offset..].ptr);
    var data = src[0..payload_len];
    var start = seq;
    // Bytes before rcv_nxt came already.
    const old = c.rcv_nxt -% start;
    if (@as(i32, @bitCast(old)) > 0) {
        if (old >= data.len) {
            c.st_old +%= 1;
            _ = sendTcpPacket(c, TCP_ACK, null);
            return;
        }
        data = data[old..];
        start = c.rcv_nxt;
    }
    // Bytes past the free space don't fit: the window never offered them.
    const off = start -% c.rcv_nxt;
    const room = (c.rx_mask + 1) - c.rx_count;
    if (off < room) {
        if (data.len > room - off) {
            data = data[0 .. room - off];
            c.st_cut +%= 1;
        }
        ringWrite(c, off, data);
        if (off == 0) {
            const gap = c.n_ooo != 0;
            rxAdvance(c, @intCast(data.len));
            oooMerge(c);
            if ((c.rx_mask + 1) - c.rx_count < 1460) c.st_full +%= 1;
            tcpNotify(c);
            // Inside a receive batch one ACK answers TCP_ACK_EVERY segments
            // that came in order with nothing waiting past a gap; the
            // batch's end sends what is still owed (rxBatchEnd).
            if (rx_batch and !gap) {
                c.ack_due +|= 1;
                if (c.ack_due < TCP_ACK_EVERY) return;
            }
        } else {
            c.st_ooo +%= 1;
            oooAdd(c, start, start +% @as(u32, @intCast(data.len)));
        }
    } else c.st_cut +%= 1;
    _ = sendTcpPacket(c, TCP_ACK, null);
}

fn handleTcpPacket(ip_data: []volatile u8, ihl: usize) void {
    const tcp = ip_data[ihl..];
    if (tcp.len < TCP_HDR_SIZE) return;

    const src_port = readU16BE(tcp[0..2]);
    const dst_port = readU16BE(tcp[2..4]);
    const seq = readU32BE(tcp[4..8]);
    const ack = readU32BE(tcp[8..12]);
    const data_offset = @as(usize, tcp[12] >> 4) * 4;
    const flags = tcp[13];

    // Reject lying headers up front. data_offset < 20 would alias header
    // bytes into the payload; data_offset > tcp.len (claimed options that
    // aren't on the wire) would index past the segment end in the MSS
    // option walk below — a remote ReleaseSafe panic via a short SYN-ACK
    // carrying a fat data-offset nibble. (The server-side walk in
    // tryAcceptIncomingSyn already bounded this; the client side didn't.)
    if (data_offset < TCP_HDR_SIZE or data_offset > tcp.len) return;
    const payload_len = tcp.len - data_offset;

    // Find matching connection (full 4-tuple match)
    var conn: ?*TcpConn = null;
    for (&tcp_conns) |*c0| {
        if (c0.active and c0.local_port == dst_port and c0.remote_port == src_port and
            c0.remote_ip[0] == ip_data[12] and c0.remote_ip[1] == ip_data[13] and
            c0.remote_ip[2] == ip_data[14] and c0.remote_ip[3] == ip_data[15])
        {
            conn = c0;
            break;
        }
    }

    // No matching conn. If this is a fresh SYN (no ACK), look for a listener
    // bound to dst_port — that's the inbound-handshake path.
    const c = conn orelse {
        tcp_unmatched +%= 1;
        const fresh_syn = (flags & TCP_SYN) != 0 and (flags & TCP_ACK) == 0;
        if (!(fresh_syn and tryAcceptIncomingSyn(ip_data, ihl, dst_port, src_port, seq))) sendReset(ip_data, ihl);
        return;
    };

    if (flags & TCP_RST != 0) {
        // A SYN-RECEIVED conn was never handed to accept(): no owner exists
        // to close() it, so free the slot here — RST-killed handshakes used
        // to leak conn slots until the table was permanently full.
        if (c.state == .syn_received) {
            c.* = .{};
            return;
        }
        tcpFailWith(c, if (c.state == .syn_sent) .refused else .reset);
        return;
    }

    if (TRACE_RX) debug.klog("[tcp] RX state={d} flags=0x{X:0>2} seq={d} ack={d} payload={d}\n", .{ @intFromEnum(c.state), flags, seq, ack, payload_len });

    // Track the peer's advertised receive window for send-side flow control;
    // a SYN's is never scaled.
    const wnd_field: u32 = readU16BE(tcp[14..16]);
    const was_shut = c.snd_wnd == 0;
    c.snd_wnd = if (c.ws_ok and flags & TCP_SYN == 0) wnd_field << @intCast(c.snd_wscale) else wnd_field;
    // A window update — including one re-opening from a (near-)zero window — can
    // let buffered-but-unsent data move even when this segment's ACK didn't
    // advance snd_una. Flush here too, not only on the snd_una-advancing path,
    // or a slow reader could wedge the sender until the next data-bearing ACK.
    if ((c.state == .established or c.state == .close_wait) and c.snd_buf_len > 0) {
        // Opened from shut: what was out, the probe's byte at least, was
        // dropped at the shut window. It all goes again, at the timeout
        // the probing had backed off from.
        if (was_shut and c.snd_wnd != 0 and c.snd_nxt != c.snd_una) {
            goBackN(c);
            c.rto = estimatedRto(c);
            c.retransmit_count = 0;
        }
        if ((c.snd_una +% c.snd_buf_len) != c.snd_nxt) flushSnd(c);
    }

    switch (c.state) {
        .syn_received => {
            // Peer is finishing the handshake we started in tryAcceptIncomingSyn.
            // Any in-window ACK promotes us to ESTABLISHED and queues the slot
            // on the listener's accept ring. The peer is allowed to bundle data
            // into this same segment — fall through into the established arm if
            // there's a payload after the state transition.
            if ((flags & TCP_ACK) != 0 and ack == c.snd_nxt) {
                c.snd_una = ack;
                c.state = .established;
                c.retransmit_count = 0;
                initCwnd(c);
                if (c.listener_slot != TCP_NO_LISTENER and c.listener_slot < TCP_MAX_LISTENERS) {
                    if (!enqueueAccepted(&tcp_listeners[c.listener_slot], connSlotIndex(c))) {
                        // Accept ring full: this conn can never be handed
                        // out — drop it whole (the peer RTOs and retries)
                        // instead of leaking the slot as an ESTABLISHED
                        // orphan nobody can ever close.
                        c.* = .{};
                        return;
                    }
                    @import("../cpu/ipc/fdpoll.zig").wakePollers(.tcp_listener, @as(u16, c.listener_slot));
                }
                // Bundled data on the ACK that completes the handshake.
                receiveData(c, seq, tcp, data_offset, payload_len);
            }
        },
        .syn_sent => {
            if (flags & TCP_SYN != 0 and flags & TCP_ACK != 0) {
                if (ack == c.snd_nxt) {
                    // All sequence math is +% — seq numbers wrap by design,
                    // and a peer ISS of 0xFFFFFFFF used to be a ReleaseSafe
                    // overflow panic here (remote crash, peer-controlled).
                    c.rcv_nxt = seq +% 1;
                    c.snd_una = ack;
                    // Our SYN offered scaling and SACK; what the answer
                    // takes up holds.
                    const o = parseSynOptions(tcp, data_offset);
                    c.peer_mss = o.mss;
                    if (o.wscale) |s| {
                        c.ws_ok = true;
                        c.snd_wscale = s;
                    } else c.rcv_wscale = 0;
                    c.sack_ok = o.sack_ok;
                    // Our SYN's window, now that its left edge is known.
                    c.adv_edge = c.rcv_nxt +% c.adv_wnd;
                    c.state = .established;
                    c.retransmit_count = 0;
                    initCwnd(c);
                    _ = sendTcpPacket(c, TCP_ACK, null);
                    tcpNotify(c);
                }
            }
        },
        .established => {
            if (flags & TCP_ACK != 0) processAck(c, ack, payload_len);
            // Data: in-order, out-of-order (buffered), or duplicate. receiveData
            // always ACKs, so a gap yields the duplicate ACKs fast-retransmit needs.
            receiveData(c, seq, tcp, data_offset, payload_len);
            // FIN — only consume it when it's IN ORDER: the FIN's own seq is
            // seq+payload_len, which must equal rcv_nxt after receiveData
            // accepted the payload. A FIN beyond a reassembly gap, a stale
            // duplicate, or one whose payload only partially fit the rx ring
            // must wait for the peer's retransmit; consuming it eagerly used
            // to bump rcv_nxt past a hole and flip peer_closed while the gap
            // data was still missing (silent stream truncation for the app).
            if (flags & TCP_FIN != 0 and c.rcv_nxt == seq +% @as(u32, @intCast(payload_len))) {
                c.rcv_nxt +%= 1;
                c.peer_closed = true;
                _ = sendTcpPacket(c, TCP_ACK, null);
                if (c.state == .established) {
                    c.state = .close_wait;
                    maybeSendFin(c);
                } else {
                    // processAck above sent our FIN: both sides closed at once.
                    enterTimeWait(c);
                }
                tcpNotify(c);
            }
        },
        // The peer is done sending; ours still goes out and is acked.
        .close_wait => {
            if (flags & TCP_ACK != 0) processAck(c, ack, payload_len);
        },
        // Our FIN is out. fin_wait_2 needs it acked (ack == snd_nxt) — any
        // old ACK used to advance the state with the FIN still
        // unacknowledged, after which nothing would ever retransmit it.
        .fin_wait_1, .fin_wait_2 => {
            if (c.state == .fin_wait_1 and finAcked(c, flags, ack)) c.state = .fin_wait_2;
            if (c.rd_closed) {
                // Closed both ways: what the peer still sends is dropped,
                // but our final ACK must cover it, or the peer sends its
                // FIN again until its own timeout. Lenient about a FIN that
                // doesn't ack ours (a simultaneous close); time_wait bounds it.
                if (flags & TCP_FIN != 0) {
                    c.rcv_nxt = seq +% @as(u32, @intCast(payload_len)) +% 1;
                    _ = sendTcpPacket(c, TCP_ACK, null);
                    enterTimeWait(c);
                }
            } else {
                // Only our sending side is shut: the peer's data and its
                // FIN are taken as on an open connection.
                receiveData(c, seq, tcp, data_offset, payload_len);
                if (flags & TCP_FIN != 0 and c.rcv_nxt == seq +% @as(u32, @intCast(payload_len))) {
                    c.rcv_nxt +%= 1;
                    c.peer_closed = true;
                    _ = sendTcpPacket(c, TCP_ACK, null);
                    enterTimeWait(c);
                    tcpNotify(c);
                }
            }
        },
        .last_ack => {
            if (finAcked(c, flags, ack)) {
                c.state = .closed;
                // A socket that still holds the slot frees it (tcpRelease).
                if (c.orphan or c.rd_closed) c.active = false;
            }
        },
        else => {},
    }
}

/// In a state our FIN is out in: the segment acks it, nothing is left in
/// flight and the retransmit timer stops. The FIN is the octet past the
/// send ring, which processAck doesn't count. Lock held.
fn finAcked(c: *TcpConn, flags: u8, ack: u32) bool {
    if (flags & TCP_ACK == 0 or ack != c.snd_nxt) return false;
    c.snd_una = ack;
    c.retransmit_count = 0;
    return true;
}

fn enterTimeWait(c: *TcpConn) void {
    c.state = .time_wait;
    c.last_send_tick = process.tick_count;
}

/// An ACK on a connection that may have data out: free what it covers from
/// the send ring, send what the freed window allows, then a FIN that waited
/// for the ring to empty. Lock held.
fn processAck(c: *TcpConn, ack: u32, payload_len: usize) void {
    const adv = @as(i32, @bitCast(ack -% c.snd_una));
    // Sent at some time and not acked: snd_nxt may be below it (tcpTick).
    const out = sndTop(c) -% c.snd_una;
    // Accept only ACKs that advance snd_una without acking data we never
    // sent. Free the acked bytes from the send ring, restart the retransmit
    // timer, and let the freed window push more out.
    if (adv > 0 and @as(u32, @bitCast(adv)) <= out and @as(u32, @bitCast(adv)) <= c.snd_buf_len) {
        const acked: u32 = @bitCast(adv);
        c.snd_buf_head = (c.snd_buf_head +% acked) & c.snd_mask;
        c.snd_buf_len -= acked;
        c.snd_una = ack;
        // The peer held more than a timeout's resend had reached again.
        if (seqLt(c.snd_nxt, ack)) c.snd_nxt = ack;
        if (c.in_recovery and seqLt(ack, c.recover)) {
            // A partial ACK (RFC 6582): the next hole starts at it. Send
            // that segment and stay in recovery.
            resendFirst(c);
        } else {
            ackCwnd(c, acked); // grow cwnd / exit fast recovery
        }
        // Kept at the edge: left behind, it would wrap past snd_una and
        // hold fast retransmit off.
        if (seqLt(c.recover, ack)) c.recover = ack;
        c.dup_acks = 0;
        // Karn: only sample RTT from a segment that wasn't retransmitted
        // (rtt_pending is cleared on retransmit).
        if (c.rtt_pending and @as(i32, @bitCast(ack -% c.rtt_seq)) >= 0) {
            updateRto(c, process.tick_count -% c.rtt_start);
            c.rtt_pending = false;
        }
        c.retransmit_count = 0;
        c.last_send_tick = process.tick_count;
        flushSnd(c);
        maybeSendFin(c);
        if (c.detach_due) detachRing(c);
        // Room in the send ring: a writer waiting for it goes on.
        tcpNotify(c);
    } else if (adv == 0 and c.snd_wnd == 0) {
        // Heard from a peer whose window is shut, a probe's answer or its
        // own data: it is there. Not a loss, and the probing goes on.
        c.retransmit_count = 0;
    } else if (adv == 0 and payload_len == 0 and out > 0) {
        // Duplicate ACK: three of them trigger fast retransmit, unless they
        // answer what a recovery or a timeout already sent again.
        c.dup_acks +|= 1;
        if (c.dup_acks == 3 and seqLe(c.recover, c.snd_una)) fastRetransmit(c);
    }
}

fn tcpTick() void {
    for (&tcp_conns) |*c| {
        if (!c.active) continue;
        // A connection whose socket is gone frees itself: when its close is
        // done, when it failed, or when the close has taken too long. One a
        // socket still holds stays, whatever its state (tcpRelease).
        if (c.orphan) {
            const lingered = c.state == .time_wait and process.tick_count -% c.last_send_tick > TCP_TIME_WAIT_TICKS;
            if (lingered or c.error_flag or c.state == .closed or process.tick_count >= c.orphan_deadline) {
                c.state = .closed;
                c.active = false;
                continue;
            }
        }
        if (c.state == .time_wait) continue;
        // An ACK a receive batch held back and nothing sent since. Owed
        // once: one that cannot go (no gateway address) is not retried
        // every tick, the peer's next segment asks again.
        if (c.ack_due != 0) {
            _ = sendTcpPacket(c, TCP_ACK, null);
            c.ack_due = 0;
        }
        const sending = (c.state == .established or c.state == .close_wait) and c.snd_buf_len > 0;
        // Data queued with nothing in flight: a send that found no gateway
        // address yet. Nothing else would start it.
        if (sending and c.snd_una == sndTop(c)) flushSnd(c);
        // The peer's window is shut with data waiting: only a probe hears
        // of its opening, should the update be lost. Probes go at the
        // timeout's pace for as long as the peer answers them (processAck).
        const persist = sending and c.snd_wnd == 0;
        // Retransmission: fire when the oldest unacked octet has gone
        // unacknowledged for the timeout.
        if ((c.snd_una != sndTop(c) or persist) and
            process.tick_count -% c.last_send_tick >= c.rto)
        {
            if (c.retransmit_count >= TCP_MAX_RETRIES) {
                // An orphaned server-side handshake (SYN-RECEIVED never
                // promoted to the accept ring) has no owner to close() it —
                // free the slot or dead half-opens accumulate forever.
                if (c.state == .syn_received) {
                    c.* = .{};
                    continue;
                }
                tcpFailWith(c, .timed_out);
                continue;
            }
            // Congestion response to a timeout: collapse to one segment and set
            // ssthresh to half the flight size (RFC 5681). A shut window is
            // no loss.
            if (!persist) {
                c.ssthresh = @max(c.cwnd / 2, 2 * @as(u32, c.peer_mss));
                c.cwnd = c.peer_mss;
            }
            c.dup_acks = 0;
            c.in_recovery = false;
            // Karn: back off the timeout exponentially and don't sample RTT from
            // the retransmitted (ambiguous) segment.
            c.rto = @min(c.rto * 2, TCP_MAX_RTO_TICKS);
            c.rtt_pending = false;
            c.retransmit_count += 1;
            c.last_send_tick = process.tick_count;
            debug.klog("[tcp] timeout {d}: port {d} -> {d}.{d}.{d}.{d}:{d} state={s} out={d} queued={d} wnd={d} next rto={d}{s}\n", .{
                c.retransmit_count,
                c.local_port,
                c.remote_ip[0],
                c.remote_ip[1],
                c.remote_ip[2],
                c.remote_ip[3],
                c.remote_port,
                @tagName(c.state),
                sndTop(c) -% c.snd_una,
                c.snd_buf_len,
                c.snd_wnd,
                c.rto,
                if (persist) " (window probe)" else "",
            });
            if (sending) {
                // All that is out counts as lost: back to the first unacked
                // byte. One segment goes now (cwnd), the rest as its ACKs
                // open the window; one a segment at a time would cost a
                // timeout per lost segment.
                goBackN(c);
                if (persist) probeWindow(c) else flushSnd(c);
            } else if (c.last_tx_len > 0) {
                // Control segment (SYN / SYN-ACK / FIN) retransmit.
                _ = dispatchPacket(c.remote_ip, c.last_tx[0..c.last_tx_len]);
            }
        }
    }
}

// === HTTP ===

const UrlParts = struct { host: []const u8, path: []const u8 };

fn parseUrl(url: []const u8) ?UrlParts {
    var s = url;
    if (s.len > 7 and s[0] == 'h' and s[1] == 't' and s[2] == 't' and s[3] == 'p' and s[4] == ':' and s[5] == '/' and s[6] == '/') {
        s = s[7..];
    }
    // Find first /
    for (s, 0..) |c, i| {
        if (c == '/') return .{ .host = s[0..i], .path = s[i..] };
    }
    return .{ .host = s, .path = "/" };
}

pub fn httpGet(url: []const u8, response_buf: []u8) ?usize {
    const parsed = parseUrl(url) orelse return null;

    // Resolve hostname
    const ip = resolve(parsed.host) orelse {
        // Try as raw IP
        if (parseIp(parsed.host)) |raw_ip| {
            return httpGetIp(raw_ip, parsed.host, parsed.path, response_buf);
        }
        return null;
    };
    return httpGetIp(ip, parsed.host, parsed.path, response_buf);
}

fn httpGetIp(ip: [4]u8, host: []const u8, path: []const u8, response_buf: []u8) ?usize {
    const conn_idx = tcpConnect(ip, 80) orelse return null;
    defer tcpClose(conn_idx);

    // Build HTTP request
    var req: [512]u8 = undefined;
    var rlen: usize = 0;
    const parts = [_][]const u8{ "GET ", path, " HTTP/1.0\r\nHost: ", host, "\r\nConnection: close\r\n\r\n" };
    for (parts) |part| {
        if (rlen + part.len > req.len) return null;
        @memcpy(req[rlen..][0..part.len], part);
        rlen += part.len;
    }

    if (!tcpSend(conn_idx, req[0..rlen])) return null;

    // Receive response. 10s tick deadline, refreshed each time bytes arrive
    // (so a slow trickle doesn't get killed). 10ms kernel sleep between polls
    // keeps the BSP free for the desktop and other processes.
    var total: usize = 0;
    var deadline: u64 = process.tick_count + 1000;
    while (process.tick_count < deadline) {
        poll();
        const n = tcpRecv(conn_idx, response_buf[total..]);
        if (n > 0) {
            total += n;
            deadline = process.tick_count + 1000;
            if (total >= response_buf.len) break;
        }
        if (tcpPeerClosed(conn_idx) and tcp_conns[conn_idx].rx_count == 0) break;
        process.kernelSleepMs(10);
    }
    if (total == 0) return null;
    return total;
}

pub fn wgetCommand(url: []const u8) void {
    if (!nic.isReady()) {
        vga.fg = .LightRed;
        vga.print("Network not available\n", .{});
        vga.fg = .LightGray;
        return;
    }
    vga.print("Fetching {s}...\n", .{url});

    var response: [8192]u8 = undefined;
    const len = httpGet(url, &response) orelse {
        vga.fg = .LightRed;
        vga.print("Request failed\n", .{});
        vga.fg = .LightGray;
        return;
    };

    // Find end of headers
    var body_start: usize = 0;
    var i: usize = 0;
    while (i + 3 < len) : (i += 1) {
        if (response[i] == '\r' and response[i + 1] == '\n' and
            response[i + 2] == '\r' and response[i + 3] == '\n')
        {
            body_start = i + 4;
            break;
        }
    }

    // Print status line
    for (response[0..@min(len, 200)], 0..) |c, si| {
        if (c == '\r' or c == '\n') {
            vga.fg = .LightCyan;
            vga.print("{s}\n", .{response[0..si]});
            vga.fg = .LightGray;
            break;
        }
    }

    // Print body
    if (body_start > 0 and body_start < len) {
        const print_len = @min(len - body_start, 4096);
        vga.print("{s}\n", .{response[body_start..][0..print_len]});
    }
    vga.print("\n({d} bytes received)\n", .{len});
}

// === ICMP (existing, refactored) ===

var ping_got_reply: bool = false;
var ping_reply_seq: u16 = 0;

fn handleIcmpPacket(ip_data: []volatile u8, ihl: usize) void {
    const icmp = ip_data[ihl..];
    if (icmp.len < ICMP_HDR_SIZE) return;

    if (icmp[0] == ICMP_ECHO_REPLY) {
        ping_reply_seq = readU16BE(icmp[6..8]);
        ping_got_reply = true;
    } else if (icmp[0] == ICMP_ECHO_REQUEST) {
        // Only answer requests addressed to US — without this we replied to
        // broadcast pings and to other hosts' packets leaking through
        // promiscuous/bridged reception (smurf-amplifier behavior).
        if (!(ip_data[16] == local_ip[0] and ip_data[17] == local_ip[1] and
            ip_data[18] == local_ip[2] and ip_data[19] == local_ip[3])) return;
        var reply: [1514]u8 = undefined;
        // Reconstruct full frame including eth header
        const eth_start = @intFromPtr(ip_data.ptr) - ETH_HDR_SIZE;
        const full_data: [*]volatile u8 = @ptrFromInt(eth_start);
        const pkt_len = ETH_HDR_SIZE + ip_data.len;
        if (pkt_len > 1514) return;
        for (0..pkt_len) |j| reply[j] = full_data[j];

        const src_mac = nic.getMac();
        @memcpy(reply[0..6], reply[6..12]);
        @memcpy(reply[6..12], &src_mac);
        var tmp_ip: [4]u8 = undefined;
        @memcpy(&tmp_ip, reply[ETH_HDR_SIZE + 12 ..][0..4]);
        @memcpy(reply[ETH_HDR_SIZE + 12 ..][0..4], reply[ETH_HDR_SIZE + 16 ..][0..4]);
        @memcpy(reply[ETH_HDR_SIZE + 16 ..][0..4], &tmp_ip);
        reply[ETH_HDR_SIZE + ihl] = ICMP_ECHO_REPLY;
        reply[ETH_HDR_SIZE + ihl + 2] = 0;
        reply[ETH_HDR_SIZE + ihl + 3] = 0;
        const icmp_total_len = pkt_len - ETH_HDR_SIZE - ihl;
        const csum = internetChecksum(reply[ETH_HDR_SIZE + ihl ..][0..icmp_total_len]);
        reply[ETH_HDR_SIZE + ihl + 2] = @intCast(csum >> 8);
        reply[ETH_HDR_SIZE + ihl + 3] = @intCast(csum & 0xFF);
        _ = nic.send(reply[0..pkt_len]);
    }
}

// === IPv4 dispatcher ===

fn handleIPv4Packet(data: []volatile u8) void {
    if (data.len < ETH_HDR_SIZE + IPV4_HDR_SIZE) return;
    const ip = data[ETH_HDR_SIZE..];
    if (ip[0] & 0xF0 != 0x40) return;
    const ihl = @as(usize, ip[0] & 0x0F) * 4;
    if (ihl < IPV4_HDR_SIZE) return; // header can't be shorter than 20
    // No reassembly: drop fragments. A non-first fragment (offset != 0)
    // would have its payload parsed as an L4 header; a first fragment
    // (MF set) would be processed as if complete. DF (0x4000) passes.
    if (readU16BE(ip[6..8]) & 0x3FFF != 0) return;
    // Use IP total length to avoid Ethernet padding being counted as payload
    const ip_total_len: usize = readU16BE(ip[2..4]);
    if (ip_total_len < ihl or ip_total_len > ip.len) return;
    const protocol = ip[9];
    const ip_pkt = ip[0..ip_total_len];

    switch (protocol) {
        IPPROTO_ICMP => handleIcmpPacket(ip_pkt, ihl),
        IPPROTO_UDP => handleUdpPacket(ip_pkt, ihl),
        IPPROTO_TCP => handleTcpPacket(ip_pkt, ihl),
        else => {},
    }
}

// === ARP ===

fn handleArpPacket(data: []volatile u8) void {
    if (data.len < ETH_HDR_SIZE + ARP_HDR_SIZE) return;
    const arp = data[ETH_HDR_SIZE..];
    const op = @as(u16, arp[6]) << 8 | @as(u16, arp[7]);

    if (op == ARP_REPLY) {
        if (arp[24] == local_ip[0] and arp[25] == local_ip[1] and
            arp[26] == local_ip[2] and arp[27] == local_ip[3])
        {
            const sender_ip = arp[14..18];
            if (sender_ip[0] == gateway_ip[0] and sender_ip[1] == gateway_ip[1] and
                sender_ip[2] == gateway_ip[2] and sender_ip[3] == gateway_ip[3])
            {
                for (0..6) |j| gateway_mac[j] = arp[8 + j];
                gateway_mac_valid = true;
            }
        }
    } else if (op == ARP_REQUEST) {
        const target_ip = arp[24..28];
        if (target_ip[0] == local_ip[0] and target_ip[1] == local_ip[1] and
            target_ip[2] == local_ip[2] and target_ip[3] == local_ip[3])
        {
            var reply: [ETH_HDR_SIZE + ARP_HDR_SIZE]u8 = undefined;
            const src_mac = nic.getMac();
            var sender_mac: [6]u8 = undefined;
            for (0..6) |j| sender_mac[j] = arp[8 + j];
            buildEthHeader(&reply, sender_mac, src_mac, ETHERTYPE_ARP);
            const r = reply[ETH_HDR_SIZE..];
            r[0] = 0; r[1] = 1;
            r[2] = 0x08; r[3] = 0x00;
            r[4] = 6; r[5] = 4;
            r[6] = 0; r[7] = 2;
            @memcpy(r[8..14], &src_mac);
            @memcpy(r[14..18], &local_ip);
            @memcpy(r[18..24], &sender_mac);
            for (0..4) |j| r[24 + j] = arp[14 + j];
            _ = nic.send(&reply);
        }
    }
}

fn processReceivedPacket(data: []volatile u8) void {
    if (data.len < ETH_HDR_SIZE) return;
    rx_frame_count +%= 1;
    rx_frame_total_bytes +%= data.len;
    const ethertype = @as(u16, data[12]) << 8 | @as(u16, data[13]);
    switch (ethertype) {
        ETHERTYPE_ARP => handleArpPacket(data),
        ETHERTYPE_IPV4 => handleIPv4Packet(data),
        else => {},
    }
}

/// IRQ-driven RX entrypoint. NIC drivers that drain their own RX ring
/// from the interrupt handler call this for each received frame instead
/// of going via nic.recv() / net.poll(). Side-effects (ARP/ICMP replies,
/// TCP ACKs) reach the wire via nic.send() which holds tx_lock IrqSave —
/// safe to call with IRQs disabled.
/// RX-frame counter. Incremented by every NIC IRQ callback regardless
/// of the protocol/conn the frame belongs to. Useful to distinguish
/// "frames not arriving" from "frames arriving but our TCP dispatcher
/// dropping them". Lives on BSS so it's safe to read from anywhere.
pub var rx_frame_count: u64 = 0;
pub var rx_frame_total_bytes: u64 = 0;
/// TCP segments that matched no connection (answered with a reset).
pub var tcp_unmatched: u64 = 0;

pub fn handleRxFrame(data: []volatile u8) void {
    // Typically NIC-IRQ context (IF already 0); IrqSave also covers the
    // polled-mode drivers calling in from task context.
    const lk = net_lock.acquireIrqSave();
    defer netUnlock(lk);
    processReceivedPacket(data);
}

/// A driver is handing over a run of frames and will call rxBatchEnd after
/// the last: receiveData may hold ACKs back until then. A hint only: one
/// held back by mistake still goes out at the next tcpTick. (p:net_lock)
var rx_batch: bool = false;

pub fn rxBatchBegin() void {
    const lk = net_lock.acquireIrqSave();
    defer netUnlock(lk);
    rx_batch = true;
}

/// The run is over: send the ACKs it held back.
pub fn rxBatchEnd() void {
    const lk = net_lock.acquireIrqSave();
    defer netUnlock(lk);
    rx_batch = false;
    for (&tcp_conns) |*c| {
        if (c.active and c.ack_due != 0) _ = sendTcpPacket(c, TCP_ACK, null);
    }
}

pub fn poll() void {
    const lk = net_lock.acquireIrqSave();
    defer netUnlock(lk);
    while (nic.recv()) |data| {
        processReceivedPacket(data);
        nic.rxRelease();
    }
    tcpTick();
}

/// Fire one ARP request for the gateway without waiting. IRQ-safe (no
/// sleep, no poll, no net_lock) — emitSegment uses it when the cache is
/// cold so the peer's retransmit finds the MAC resolved.
fn arpRequestGateway() void {
    var pkt: [ETH_HDR_SIZE + ARP_HDR_SIZE]u8 = undefined;
    const src_mac = nic.getMac();
    buildEthHeader(&pkt, BROADCAST_MAC, src_mac, ETHERTYPE_ARP);
    const a = pkt[ETH_HDR_SIZE..];
    a[0] = 0; a[1] = 1; a[2] = 0x08; a[3] = 0x00;
    a[4] = 6; a[5] = 4; a[6] = 0; a[7] = 1;
    @memcpy(a[8..14], &src_mac);
    @memcpy(a[14..18], &local_ip);
    @memset(a[18..24], 0);
    @memcpy(a[24..28], &gateway_ip);
    _ = nic.send(pkt[0 .. ETH_HDR_SIZE + ARP_HDR_SIZE]);
}

/// Blocking gateway resolution — TASK CONTEXT ONLY (sleeps, and poll()
/// takes net_lock). Public senders call this in their prologue, BEFORE
/// taking net_lock.
fn arpResolveGateway() bool {
    if (gateway_mac_valid) return true;
    arpRequestGateway();

    // 2-second tick deadline; 10ms sleep between polls so ARP doesn't lock
    // up the BSP either (lookups during boot used to spin here for ~1.5s).
    const arp_deadline: u64 = process.tick_count + 200;
    while (process.tick_count < arp_deadline) {
        poll();
        if (gateway_mac_valid) return true;
        process.kernelSleepMs(10);
    }
    return false;
}

pub fn parseIp(s: []const u8) ?[4]u8 {
    var ip: [4]u8 = undefined;
    var octet: u16 = 0;
    var part: u8 = 0;
    var digits: u8 = 0;
    for (s) |c| {
        if (c == '.') {
            if (digits == 0 or part >= 3) return null;
            if (octet > 255) return null;
            ip[part] = @intCast(octet);
            part += 1;
            octet = 0;
            digits = 0;
        } else if (c >= '0' and c <= '9') {
            octet = octet * 10 + (c - '0');
            digits += 1;
        } else return null;
    }
    if (digits == 0 or part != 3 or octet > 255) return null;
    ip[3] = @intCast(octet);
    return ip;
}

fn buildIcmpEchoRequest(buf: []u8, dst_mac: [6]u8, dst_ip: [4]u8, seq: u16) usize {
    const src_mac = nic.getMac();
    buildEthHeader(buf, dst_mac, src_mac, ETHERTYPE_IPV4);
    const icmp_len: u16 = ICMP_HDR_SIZE + 32;
    buildIPv4Header(buf[ETH_HDR_SIZE..], IPPROTO_ICMP, dst_ip, icmp_len);
    const icmp = buf[ETH_HDR_SIZE + IPV4_HDR_SIZE ..];
    icmp[0] = ICMP_ECHO_REQUEST;
    icmp[1] = 0;
    icmp[2] = 0; icmp[3] = 0;
    icmp[4] = 0; icmp[5] = 1;
    writeU16BE(icmp[6..8], seq);
    for (0..32) |j| icmp[ICMP_HDR_SIZE + j] = @intCast(j & 0xFF);
    const csum = internetChecksum(icmp[0..icmp_len]);
    icmp[2] = @intCast(csum >> 8);
    icmp[3] = @intCast(csum & 0xFF);
    return ETH_HDR_SIZE + IPV4_HDR_SIZE + icmp_len;
}

// === procfs renderers ===
//
// Procfs delegates `/proc/netinfo`, `/proc/netsock`, and `/proc/netarp`
// to these. Keeping the formatting here (instead of in procfs.zig) lets
// the renderers reach private fields like tcp_conns / udp_listeners /
// gateway_mac without exposing them publicly.

fn maskPrefixLen(mask: [4]u8) u8 {
    var bits: u8 = 0;
    for (mask) |b| {
        var bit: u8 = 0x80;
        while (bit != 0) : (bit >>= 1) {
            if (b & bit != 0) bits += 1 else return bits;
        }
    }
    return bits;
}

fn fmtBuf(buf: []u8, pos: *usize, comptime f: []const u8, args: anytype) void {
    const out = std.fmt.bufPrint(buf[pos.*..], f, args) catch return;
    pos.* += out.len;
}

pub fn renderProcInfo(buf: []u8) usize {
    var n: usize = 0;
    const mac = nic.getMac();
    fmtBuf(buf, &n, "nic:    {s}  mac {x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}\n", .{
        nic.name(), mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
    });
    fmtBuf(buf, &n, "ip:     {d}.{d}.{d}.{d}/{d}  via {d}.{d}.{d}.{d}\n", .{
        local_ip[0], local_ip[1], local_ip[2], local_ip[3], maskPrefixLen(subnet_mask),
        gateway_ip[0], gateway_ip[1], gateway_ip[2], gateway_ip[3],
    });
    fmtBuf(buf, &n, "dns:    {d}.{d}.{d}.{d}\n", .{
        dns_ip[0], dns_ip[1], dns_ip[2], dns_ip[3],
    });
    if (dhcp_configured) {
        fmtBuf(buf, &n, "lease:  DHCP, {d}s remaining\n", .{dhcp_lease_secs});
    } else {
        fmtBuf(buf, &n, "lease:  static (no DHCP)\n", .{});
    }
    if (!nic.isReady()) {
        fmtBuf(buf, &n, "state:  DOWN — no NIC backend\n", .{});
    }
    return n;
}

fn stateName(s: TcpState) []const u8 {
    return switch (s) {
        .closed => "CLOSED",
        .listen => "LISTEN",
        .syn_sent => "SYN_SENT",
        .syn_received => "SYN_RCVD",
        .established => "ESTABLISHED",
        .fin_wait_1 => "FIN_WAIT_1",
        .fin_wait_2 => "FIN_WAIT_2",
        .time_wait => "TIME_WAIT",
        .close_wait => "CLOSE_WAIT",
        .last_ack => "LAST_ACK",
    };
}

pub fn renderProcSock(buf: []u8) usize {
    var n: usize = 0;
    fmtBuf(buf, &n, "proto  local           remote               state\n", .{});
    // By-pointer iteration: `for (tcp_conns) |c|` would copy the entire
    // ~156 KB array onto the kstack, overflowing pid 4 (netstat)'s 64 KB
    // kstack slot into pid 2 (desktop)'s adjacent slot — caught by DR2
    // hwbp on kesp+48 (netstat-desktop crash, 2026-05-19).
    for (&tcp_listeners) |*l| {
        if (!l.active) continue;
        fmtBuf(buf, &n, "tcp    *:{d:<11}    *:*                  LISTEN\n", .{l.port});
    }
    for (&tcp_conns) |*c| {
        if (!c.active) continue;
        fmtBuf(buf, &n, "tcp    *:{d:<11}    {d}.{d}.{d}.{d}:{d:<5}  {s}\n", .{
            c.local_port,
            c.remote_ip[0], c.remote_ip[1], c.remote_ip[2], c.remote_ip[3],
            c.remote_port,
            stateName(c.state),
        });
    }
    for (&udp_listeners) |*l| {
        if (!l.active) continue;
        fmtBuf(buf, &n, "udp    *:{d:<11}    *:*                  -\n", .{l.port});
    }
    return n;
}

pub fn renderProcArp(buf: []u8) usize {
    var n: usize = 0;
    fmtBuf(buf, &n, "ip              mac                state\n", .{});
    if (gateway_mac_valid) {
        fmtBuf(buf, &n, "{d}.{d}.{d}.{d:<8}  {x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}  cached (gateway)\n", .{
            gateway_ip[0], gateway_ip[1], gateway_ip[2], gateway_ip[3],
            gateway_mac[0], gateway_mac[1], gateway_mac[2], gateway_mac[3], gateway_mac[4], gateway_mac[5],
        });
    } else {
        fmtBuf(buf, &n, "{d}.{d}.{d}.{d:<8}  --:--:--:--:--:--  pending (gateway)\n", .{
            gateway_ip[0], gateway_ip[1], gateway_ip[2], gateway_ip[3],
        });
    }
    return n;
}

pub fn pingCommand(ip_str: []const u8) void {
    if (!nic.isReady()) {
        vga.fg = .LightRed;
        vga.print("Network not available (no virtio-net)\n", .{});
        vga.fg = .LightGray;
        return;
    }
    const target_ip = parseIp(ip_str) orelse {
        vga.fg = .LightRed;
        vga.print("Invalid IP address: {s}\n", .{ip_str});
        vga.fg = .LightGray;
        return;
    };
    vga.print("PING {d}.{d}.{d}.{d}\n", .{ target_ip[0], target_ip[1], target_ip[2], target_ip[3] });
    if (!arpResolveGateway()) {
        vga.fg = .LightRed;
        vga.print("ARP: gateway unreachable\n", .{});
        vga.fg = .LightGray;
        return;
    }
    var sent: u16 = 0;
    var received: u16 = 0;
    while (sent < 4) : (sent += 1) {
        var pkt: [ETH_HDR_SIZE + IPV4_HDR_SIZE + ICMP_HDR_SIZE + 32]u8 = undefined;
        const plen = buildIcmpEchoRequest(&pkt, gateway_mac, target_ip, sent + 1);
        ping_got_reply = false;
        if (!nic.send(pkt[0..plen])) {
            vga.fg = .LightRed;
            vga.print("  send failed\n", .{});
            vga.fg = .LightGray;
            continue;
        }
        // Tick deadline + sleep, not a pause-spin — tight kernel spin loops
        // starve sibling vCPUs under Hyper-V (same lesson as the DNS/ARP/TCP
        // waits, which were converted earlier; this one was missed).
        const reply_deadline: u64 = process.tick_count + 100;
        while (process.tick_count < reply_deadline) {
            poll();
            if (ping_got_reply and ping_reply_seq == sent + 1) {
                received += 1;
                vga.fg = .LightGreen;
                vga.print("  reply from {d}.{d}.{d}.{d} seq={d}\n", .{ target_ip[0], target_ip[1], target_ip[2], target_ip[3], sent + 1 });
                vga.fg = .LightGray;
                break;
            }
            process.kernelSleepMs(10);
        }
        if (!ping_got_reply) vga.print("  request timeout seq={d}\n", .{sent + 1});
    }
    vga.print("{d} packets sent, {d} received\n", .{ sent, received });
}
