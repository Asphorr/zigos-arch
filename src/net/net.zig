const std = @import("std");
const vga = @import("../ui/vga.zig");
const nic = @import("../driver/nic.zig");
const debug = @import("../debug/debug.zig");
const process = @import("../proc/process.zig");

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
const TCP_MAX_CONNS = 16;
const TCP_MAX_LISTENERS = 4;
const TCP_RX_BUF_SIZE = 8192;
const TCP_RETRANSMIT_TICKS: u64 = 300;
const TCP_MAX_RETRIES: u8 = 3;
const TCP_NO_LISTENER: u8 = 0xFF;
// Per-listener ring of accepted-but-not-yet-handed-out connection slots.
const TCP_ACCEPT_RING_SIZE: u8 = 4;

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
    if (isLoopback(dst_ip)) {
        const vptr: [*]volatile u8 = @ptrCast(pkt.ptr);
        handleRxFrame(vptr[0..pkt.len]);
        return true;
    }
    return nic.send(pkt);
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
    for (&udp_listeners, 0..) |*l, i| {
        if (!l.active) {
            l.active = true;
            l.port = port;
            l.has_data = false;
            return @intCast(i);
        }
    }
    return null;
}

pub fn udpUnlisten(slot: u8) void {
    if (slot < 4) udp_listeners[slot].active = false;
}

/// True if a packet has been buffered and not yet consumed. Caller can
/// then read via `udpData()` and free the buffer via `udpConsume()`.
/// Three-step (has/data/consume) instead of one-shot so the buffer stays
/// pinned during the caller's parse — handleUdpPacket only writes when
/// `!has_data`, so leaving has_data true keeps subsequent packets out.
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
    udp_listeners[slot].has_data = false;
}

pub fn udpSend(dst_ip: [4]u8, dst_port: u16, src_port: u16, payload: []const u8) bool {
    if (payload.len > 1400) return false;
    const loop = isLoopback(dst_ip);
    if (!loop and !arpResolveGateway()) return false;
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

// TcpConn / TcpListener slots carry no per-table lock today. The two
// access paths are (a) NIC-RX, driven by net.handleRxFrame called from
// driver IRQ handlers + net.poll() in syscall context; (b) syscall
// handlers in cpu/syscall/net.zig that read/write a specific slot.
// Both currently run effectively single-threaded relative to each
// other — NIC IRQs land on BSP and syscalls touch slots only at
// well-defined points — so there's no fine-grained protection. The
// day NIC IRQs get distributed across CPUs, this table needs a lock
// (and these annotations should change from blank to (p:tcp_lock)).
// See docs/STYLE.md.
const TcpConn = struct {
    state: TcpState = .closed,
    active: bool = false,
    local_port: u16 = 0,
    remote_port: u16 = 0,
    remote_ip: [4]u8 = .{ 0, 0, 0, 0 },
    snd_nxt: u32 = 0,
    snd_una: u32 = 0,
    snd_iss: u32 = 0,
    rcv_nxt: u32 = 0,
    rx_buf: [TCP_RX_BUF_SIZE]u8 = undefined,
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
};

const TcpListener = struct {
    active: bool = false,
    port: u16 = 0,
    /// Ring of established conn slot ids waiting to be handed out by accept().
    /// SYN-RECEIVED conns are NOT in here; the entry is appended only on
    /// transition to ESTABLISHED so accept() always returns a usable conn.
    accept_ring: [TCP_ACCEPT_RING_SIZE]u8 = [_]u8{0xFF} ** TCP_ACCEPT_RING_SIZE,
    accept_head: u8 = 0,
    accept_tail: u8 = 0,
};

var tcp_conns: [TCP_MAX_CONNS]TcpConn = [_]TcpConn{.{}} ** TCP_MAX_CONNS;
var tcp_listeners: [TCP_MAX_LISTENERS]TcpListener = [_]TcpListener{.{}} ** TCP_MAX_LISTENERS;
var next_ephemeral: u16 = 49200;

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

fn enqueueAccepted(lst: *TcpListener, conn_slot: u8) void {
    const ring_size = TCP_ACCEPT_RING_SIZE;
    const next = (lst.accept_head + 1) % ring_size;
    if (next == lst.accept_tail) return; // ring full — drop (peer will retry SYN-ACK timeout style)
    lst.accept_ring[lst.accept_head] = conn_slot;
    lst.accept_head = next;
}

fn sendTcpPacket(conn: *TcpConn, flags: u8, payload: ?[]const u8, include_mss: bool) bool {
    const loop = isLoopback(conn.remote_ip);
    if (!loop and !arpResolveGateway()) return false;
    var pkt: [1514]u8 = undefined;
    const src_mac = nic.getMac();
    const dst_mac = if (loop) src_mac else gateway_mac;
    buildEthHeader(&pkt, dst_mac, src_mac, ETHERTYPE_IPV4);

    const tcp_hdr_len: u16 = if (include_mss) 24 else 20;
    const payload_len: u16 = if (payload) |p| @intCast(p.len) else 0;
    buildIPv4Header(pkt[ETH_HDR_SIZE..], IPPROTO_TCP, conn.remote_ip, tcp_hdr_len + payload_len);

    const tcp = pkt[ETH_HDR_SIZE + IPV4_HDR_SIZE ..];
    writeU16BE(tcp[0..2], conn.local_port);
    writeU16BE(tcp[2..4], conn.remote_port);
    writeU32BE(tcp[4..8], conn.snd_nxt);
    writeU32BE(tcp[8..12], if (flags & TCP_ACK != 0) conn.rcv_nxt else 0);
    tcp[12] = if (include_mss) (6 << 4) else (5 << 4); // data offset
    tcp[13] = flags;
    // Advertise the actual current free space in the receive ring. Static
    // 4 KB used to silently truncate streams when the app was slow to drain
    // (peer happily kept sending, packets after the ring fill were dropped).
    // Now: if the app drained from 8 KB→4 KB, the next ACK we send tells the
    // peer the window is 4 KB; if it's full, the peer back-pressures.
    const free_window: u16 = @intCast(TCP_RX_BUF_SIZE - conn.rx_count);
    writeU16BE(tcp[14..16], free_window);
    tcp[16] = 0;
    tcp[17] = 0; // checksum placeholder
    tcp[18] = 0;
    tcp[19] = 0; // urgent pointer

    if (include_mss) {
        tcp[20] = 2; // MSS option kind
        tcp[21] = 4; // MSS option length
        writeU16BE(tcp[22..24], 1460); // MSS value
    }

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

    // Save for retransmission
    @memcpy(conn.last_tx[0..total], pkt[0..total]);
    conn.last_tx_len = @intCast(total);
    conn.last_send_tick = process.tick_count;

    return dispatchPacket(conn.remote_ip, pkt[0..total]);
}

pub fn tcpConnect(dst_ip: [4]u8, dst_port: u16) ?u8 {
    // Find free connection slot
    var slot: u8 = 0;
    while (slot < TCP_MAX_CONNS) : (slot += 1) {
        if (!tcp_conns[slot].active) break;
    }
    if (slot >= TCP_MAX_CONNS) return null;

    var conn = &tcp_conns[slot];
    conn.* = .{};
    conn.active = true;
    conn.state = .syn_sent;
    conn.local_port = next_ephemeral;
    next_ephemeral +%= 1;
    if (next_ephemeral < 49200) next_ephemeral = 49200;
    conn.remote_port = dst_port;
    conn.remote_ip = dst_ip;
    conn.snd_iss = @truncate(process.tick_count *% 1103515245 +% 12345);
    conn.snd_nxt = conn.snd_iss;
    conn.snd_una = conn.snd_iss;

    // Send SYN
    if (!sendTcpPacket(conn, TCP_SYN, null, true)) {
        conn.active = false;
        return null;
    }
    conn.snd_nxt += 1; // SYN consumes one seq number

    // Wait for SYN-ACK. Tick-based 5s deadline + 10ms sleep between polls so
    // the BSP isn't locked while we're waiting on a possibly-slow handshake.
    const syn_deadline: u64 = process.tick_count + 500;
    while (process.tick_count < syn_deadline) {
        poll();
        if (conn.state == .established) return slot;
        if (conn.error_flag) { conn.active = false; return null; }
        process.kernelSleepMs(10);
    }
    conn.active = false;
    return null;
}

/// Build the half-open server side of a connection from a freshly-arrived
/// SYN. Allocates a free TcpConn slot, fills it with the peer's IP/port and
/// our chosen ISS, and immediately replies with SYN+ACK. The slot stays in
/// SYN-RECEIVED until the peer's ACK promotes it to ESTABLISHED — only then
/// does it become visible to user-space accept().
fn tryAcceptIncomingSyn(ip_data: []volatile u8, local_port: u16, remote_port: u16, peer_seq: u32) void {
    var listener: ?*TcpListener = null;
    for (&tcp_listeners) |*l| {
        if (l.active and l.port == local_port) {
            listener = l;
            break;
        }
    }
    const lst = listener orelse return; // no one listening on this port

    var slot: u8 = 0;
    while (slot < TCP_MAX_CONNS) : (slot += 1) {
        if (!tcp_conns[slot].active) break;
    }
    if (slot >= TCP_MAX_CONNS) return; // out of slots — drop SYN, peer will retransmit

    const peer_ip: [4]u8 = .{ ip_data[12], ip_data[13], ip_data[14], ip_data[15] };

    var conn = &tcp_conns[slot];
    conn.* = .{};
    conn.active = true;
    conn.state = .syn_received;
    conn.local_port = local_port;
    conn.remote_port = remote_port;
    conn.remote_ip = peer_ip;
    conn.snd_iss = @truncate(process.tick_count *% 1103515245 +% 12345);
    conn.snd_nxt = conn.snd_iss;
    conn.snd_una = conn.snd_iss;
    conn.rcv_nxt = peer_seq +% 1; // peer's SYN consumes one seq number
    conn.listener_slot = listenerSlotIndex(lst);

    // Parse the incoming SYN's options for MSS so subsequent server-side
    // sends respect what the peer advertised. Without this we'd cap our
    // segment payloads at the default 536 even when the peer (e.g. a
    // local Linux client) is happy to take 1460. Same option-walk shape
    // as the client-side parser in the .syn_sent branch of
    // handleTcpPacket — kept in sync by hand.
    const tcp = ip_data[20..]; // assume ihl=20; SYN with options never extends ihl
    if (tcp.len >= TCP_HDR_SIZE) {
        const data_offset = @as(usize, tcp[12] >> 4) * 4;
        if (data_offset > 20 and data_offset <= tcp.len) {
            var opt_pos: usize = 20;
            while (opt_pos + 1 < data_offset) {
                const kind = tcp[opt_pos];
                if (kind == 0) break;
                if (kind == 1) { opt_pos += 1; continue; }
                if (opt_pos + 1 >= data_offset) break;
                const olen = tcp[opt_pos + 1];
                if (olen < 2) break;
                if (kind == 2 and olen == 4 and opt_pos + 4 <= data_offset) {
                    conn.peer_mss = readU16BE(tcp[opt_pos + 2 ..][0..2]);
                    if (conn.peer_mss > 1460) conn.peer_mss = 1460;
                    if (conn.peer_mss < 100) conn.peer_mss = 536;
                }
                opt_pos += olen;
            }
        }
    }

    if (!sendTcpPacket(conn, TCP_SYN | TCP_ACK, null, true)) {
        conn.active = false;
        return;
    }
    conn.snd_nxt += 1; // our SYN consumes one
}

/// Bind a server-side TCP socket to `port`. Returns the listener slot id, or
/// null if all listener slots are taken or the port is already bound.
/// Inbound SYNs whose dst_port matches a listener's port spawn a new TcpConn
/// in SYN-RECEIVED; once it reaches ESTABLISHED the conn slot id appears in
/// the listener's accept ring for `tcpAccept` to consume.
pub fn tcpListen(port: u16) ?u8 {
    if (port == 0) return null;
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
    const l = &tcp_listeners[listen_slot];
    if (!l.active) return;
    l.* = .{}; // accepted-but-undelivered conns stay live; user can still close them
}

/// Pop one ESTABLISHED conn slot from the listener's accept ring, or null if
/// nothing is queued yet. Non-blocking — the caller polls.
pub fn tcpAccept(listen_slot: u8) ?u8 {
    if (listen_slot >= TCP_MAX_LISTENERS) return null;
    const l = &tcp_listeners[listen_slot];
    if (!l.active) return null;
    if (l.accept_head == l.accept_tail) return null; // ring empty
    const slot = l.accept_ring[l.accept_tail];
    l.accept_ring[l.accept_tail] = 0xFF;
    l.accept_tail = (l.accept_tail + 1) % TCP_ACCEPT_RING_SIZE;
    return slot;
}

pub fn tcpSend(slot: u8, data: []const u8) bool {
    if (slot >= TCP_MAX_CONNS) return false;
    var conn = &tcp_conns[slot];
    if (!conn.active or conn.state != .established) return false;

    var sent: usize = 0;
    while (sent < data.len) {
        const chunk = @min(data.len - sent, conn.peer_mss);
        if (!sendTcpPacket(conn, TCP_PSH | TCP_ACK, data[sent..][0..chunk], false)) return false;
        conn.snd_nxt += @intCast(chunk);
        sent += chunk;
        // Brief poll to process ACKs
        poll();
    }
    return true;
}

pub fn tcpRecv(slot: u8, buf: []u8) usize {
    if (slot >= TCP_MAX_CONNS) return 0;
    const conn = &tcp_conns[slot];
    if (!conn.active) return 0;
    if (conn.rx_count == 0) return 0;

    const avail = @min(conn.rx_count, @as(u32, @intCast(buf.len)));
    const read_pos = (conn.rx_write -% conn.rx_count) % TCP_RX_BUF_SIZE;
    var i: u32 = 0;
    while (i < avail) : (i += 1) {
        buf[i] = conn.rx_buf[(read_pos + i) % TCP_RX_BUF_SIZE];
    }
    conn.rx_count -= avail;

    // If the drain re-opened a meaningful chunk of the receive window,
    // tell the peer with an empty ACK. Without this, a sender that
    // throttled against a 0-window advertisement would sit idle until
    // the next normal ACK we send (which only happens when the peer
    // sends more data — chicken-and-egg). 25% of the ring is the
    // threshold; smaller drains piggyback on the next data-driven ACK.
    if (conn.state == .established and avail >= TCP_RX_BUF_SIZE / 4) {
        _ = sendTcpPacket(conn, TCP_ACK, null, false);
    }
    return avail;
}

pub fn tcpClose(slot: u8) void {
    if (slot >= TCP_MAX_CONNS) return;
    var conn = &tcp_conns[slot];
    if (!conn.active) return;
    if (conn.state == .established or conn.state == .close_wait) {
        _ = sendTcpPacket(conn, TCP_FIN | TCP_ACK, null, false);
        conn.snd_nxt += 1;
        conn.state = if (conn.state == .close_wait) .last_ack else .fin_wait_1;
        // Wait up to 1s for FIN-ACK with 10ms sleeps. The peer almost always
        // ACKs within a single RTT so this rarely runs to the deadline.
        const close_deadline: u64 = process.tick_count + 100;
        while (process.tick_count < close_deadline) {
            poll();
            if (conn.state == .closed or conn.state == .time_wait) break;
            process.kernelSleepMs(10);
        }
    }
    conn.active = false;
    conn.state = .closed;
}

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

/// Bulk-copy TCP payload bytes into the connection's ring buffer.
/// Returns the number of bytes actually copied (capped by ring free space).
/// Handles the ring's wrap point with at most two @memcpy calls — replaces
/// a 1500-byte byte-by-byte loop with two vectorised copies, each ~50 ns
/// for an MTU-sized segment vs. ~3 µs for the previous loop. The source's
/// volatile qualifier is shed via @volatileCast: by the time handleRxFrame
/// runs, the NIC's descriptor IRQ implies the device finished the DMA, so
/// the payload is stable DRAM (no benefit from per-byte volatile reads).
fn ringPushTcpData(c: *TcpConn, tcp: []volatile u8, data_offset: usize, payload_len: usize) usize {
    const room = TCP_RX_BUF_SIZE - c.rx_count;
    const to_copy = @min(payload_len, room);
    if (to_copy == 0) return 0;

    const src: [*]const u8 = @volatileCast(tcp[data_offset..].ptr);
    const w0: u32 = c.rx_write % TCP_RX_BUF_SIZE;
    const tail: u32 = TCP_RX_BUF_SIZE - w0;
    if (to_copy <= tail) {
        @memcpy(c.rx_buf[w0..][0..to_copy], src[0..to_copy]);
    } else {
        @memcpy(c.rx_buf[w0..][0..tail], src[0..tail]);
        @memcpy(c.rx_buf[0..][0 .. to_copy - tail], src[tail..to_copy]);
    }
    c.rx_write +%= @intCast(to_copy);
    c.rx_count += @intCast(to_copy);
    @import("../cpu/ipc/fdpoll.zig").wakePollers(.tcp_sock, @as(u16, connSlotIndex(c)));
    return to_copy;
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
    const payload_len = tcp.len -| data_offset;

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
        if ((flags & TCP_SYN) != 0 and (flags & TCP_ACK) == 0) {
            tryAcceptIncomingSyn(ip_data, dst_port, src_port, seq);
        }
        return;
    };

    if (flags & TCP_RST != 0) {
        c.error_flag = true;
        c.state = .closed;
        return;
    }

    debug.klog("[tcp] RX state={d} flags=0x{X:0>2} seq={d} ack={d} payload={d}\n", .{ @intFromEnum(c.state), flags, seq, ack, payload_len });

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
                if (c.listener_slot != TCP_NO_LISTENER and c.listener_slot < TCP_MAX_LISTENERS) {
                    enqueueAccepted(&tcp_listeners[c.listener_slot], connSlotIndex(c));
                    @import("../cpu/ipc/fdpoll.zig").wakePollers(.tcp_listener, @as(u16, c.listener_slot));
                }
                // Bundled data on the ACK that completes the handshake.
                if (payload_len > 0 and seq == c.rcv_nxt) {
                    const copied = ringPushTcpData(c, tcp, data_offset, payload_len);
                    c.rcv_nxt += @intCast(copied);
                    _ = sendTcpPacket(c, TCP_ACK, null, false);
                }
            }
        },
        .syn_sent => {
            if (flags & TCP_SYN != 0 and flags & TCP_ACK != 0) {
                if (ack == c.snd_nxt) {
                    c.rcv_nxt = seq + 1;
                    c.snd_una = ack;
                    // Parse MSS from options
                    if (data_offset > 20) {
                        var opt_pos: usize = 20;
                        while (opt_pos + 1 < data_offset) {
                            const kind = tcp[opt_pos];
                            if (kind == 0) break; // end
                            if (kind == 1) { opt_pos += 1; continue; } // NOP
                            if (opt_pos + 1 >= data_offset) break;
                            const olen = tcp[opt_pos + 1];
                            if (kind == 2 and olen == 4 and opt_pos + 4 <= data_offset) {
                                c.peer_mss = readU16BE(tcp[opt_pos + 2 ..][0..2]);
                                if (c.peer_mss > 1460) c.peer_mss = 1460;
                                if (c.peer_mss < 100) c.peer_mss = 536;
                            }
                            opt_pos += olen;
                        }
                    }
                    c.state = .established;
                    c.retransmit_count = 0;
                    _ = sendTcpPacket(c, TCP_ACK, null, false);
                    @import("../cpu/ipc/fdpoll.zig").wakePollers(.tcp_sock, @as(u16, connSlotIndex(c)));
                }
            }
        },
        .established => {
            // ACK processing
            if (flags & TCP_ACK != 0) {
                if (@as(i32, @bitCast(ack -% c.snd_una)) > 0) {
                    c.snd_una = ack;
                    c.retransmit_count = 0;
                }
            }
            // Data
            if (payload_len > 0 and seq == c.rcv_nxt) {
                const copied = ringPushTcpData(c, tcp, data_offset, payload_len);
                c.rcv_nxt += @intCast(copied);
                _ = sendTcpPacket(c, TCP_ACK, null, false);
            }
            // FIN
            if (flags & TCP_FIN != 0) {
                c.rcv_nxt += 1;
                c.peer_closed = true;
                _ = sendTcpPacket(c, TCP_ACK, null, false);
                c.state = .close_wait;
                @import("../cpu/ipc/fdpoll.zig").wakePollers(.tcp_sock, @as(u16, connSlotIndex(c)));
            }
        },
        .fin_wait_1 => {
            if (flags & TCP_ACK != 0) {
                if (flags & TCP_FIN != 0) {
                    c.rcv_nxt = seq + 1;
                    _ = sendTcpPacket(c, TCP_ACK, null, false);
                    c.state = .time_wait;
                } else {
                    c.state = .fin_wait_2;
                }
            }
        },
        .fin_wait_2 => {
            if (flags & TCP_FIN != 0) {
                c.rcv_nxt = seq + 1;
                _ = sendTcpPacket(c, TCP_ACK, null, false);
                c.state = .time_wait;
            }
        },
        .last_ack => {
            if (flags & TCP_ACK != 0) {
                c.state = .closed;
                c.active = false;
            }
        },
        else => {},
    }
}

fn tcpTick() void {
    for (&tcp_conns) |*c| {
        if (!c.active) continue;
        if (c.state == .time_wait) {
            // Auto-close after brief wait
            if (process.tick_count -% c.last_send_tick > 200) {
                c.state = .closed;
                c.active = false;
            }
            continue;
        }
        // Retransmission
        if (c.snd_una != c.snd_nxt and c.last_tx_len > 0 and
            process.tick_count -% c.last_send_tick >= TCP_RETRANSMIT_TICKS)
        {
            if (c.retransmit_count >= TCP_MAX_RETRIES) {
                c.error_flag = true;
                c.state = .closed;
                continue;
            }
            _ = dispatchPacket(c.remote_ip, c.last_tx[0..c.last_tx_len]);
            c.retransmit_count += 1;
            c.last_send_tick = process.tick_count;
        }
    }
}

// === HTTP ===

fn parseUrl(url: []const u8) ?struct { host: []const u8, path: []const u8 } {
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

pub fn handleRxFrame(data: []volatile u8) void {
    processReceivedPacket(data);
}

pub fn poll() void {
    while (nic.recv()) |data| {
        processReceivedPacket(data);
        nic.rxRelease();
    }
    tcpTick();
}

fn arpResolveGateway() bool {
    if (gateway_mac_valid) return true;
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
        var timeout: u32 = 0;
        while (timeout < 200000) : (timeout += 1) {
            poll();
            if (ping_got_reply and ping_reply_seq == sent + 1) {
                received += 1;
                vga.fg = .LightGreen;
                vga.print("  reply from {d}.{d}.{d}.{d} seq={d}\n", .{ target_ip[0], target_ip[1], target_ip[2], target_ip[3], sent + 1 });
                vga.fg = .LightGray;
                break;
            }
            var j: u32 = 0;
            while (j < 1000) : (j += 1) asm volatile ("pause");
        }
        if (!ping_got_reply) vga.print("  request timeout seq={d}\n", .{sent + 1});
    }
    vga.print("{d} packets sent, {d} received\n", .{ sent, received });
}
