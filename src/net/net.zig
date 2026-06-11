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
const TCP_MAX_CONNS = 16;
const TCP_MAX_LISTENERS = 4;
const TCP_RX_BUF_SIZE = 8192;
const TCP_SND_BUF_SIZE = 8192; // per-conn ring of unacked+unsent outbound data
const TCP_OOO_BUF_SIZE = 4096; // per-conn buffer for one out-of-order segment run
// Retransmit timeout, in 10 ms ticks, derived per-conn from RTT (Jacobson/Karn).
const TCP_INIT_RTO_TICKS: u32 = 100; // 1 s, until the first RTT sample (RFC 6298)
const TCP_MIN_RTO_TICKS: u32 = 20; // 200 ms floor (cf. Linux TCP_RTO_MIN)
const TCP_MAX_RTO_TICKS: u32 = 6000; // 60 s ceiling + exponential-backoff cap
const TCP_INIT_CWND_SEGS: u32 = 4; // initial congestion window, in MSS-sized segments
const TCP_MAX_CWND: u32 = 65535; // congestion-window ceiling (bytes)
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
        // Direct call, NOT handleRxFrame: every dispatchPacket caller already
        // holds net_lock (public-API discipline) and the ticket lock is not
        // reentrant — re-acquiring here would self-deadlock loopback sends.
        processReceivedPacket(vptr[0..pkt.len]);
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
    const lk = net_lock.acquireIrqSave();
    defer net_lock.releaseIrqRestore(lk);
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
    defer net_lock.releaseIrqRestore(lk);
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

pub fn udpSend(dst_ip: [4]u8, dst_port: u16, src_port: u16, payload: []const u8) bool {
    if (payload.len > 1400) return false;
    const loop = isLoopback(dst_ip);
    // Blocking ARP resolution OUTSIDE the lock (it polls + sleeps).
    if (!loop and !arpResolveGateway()) return false;
    const lk = net_lock.acquireIrqSave();
    defer net_lock.releaseIrqRestore(lk);
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
    defer net_lock.releaseIrqRestore(lk);
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
    snd_buf: [TCP_SND_BUF_SIZE]u8 = undefined,
    snd_buf_head: u32 = 0,
    snd_buf_len: u32 = 0,
    // RTT estimation (Jacobson/Karn) -> adaptive retransmit timeout, in ticks.
    srtt: u32 = 0, // smoothed RTT (0 = no sample yet)
    rttvar: u32 = 0, // RTT variation
    rto: u32 = TCP_INIT_RTO_TICKS, // current retransmit timeout
    rtt_pending: bool = false, // timing a sample right now?
    rtt_seq: u32 = 0, // sample completes once snd_una reaches this seq
    rtt_start: u64 = 0, // tick the timed segment was sent
    rcv_nxt: u32 = 0,
    // Single out-of-order reassembly region: bytes [ooo_seq, ooo_seq+ooo_len)
    // held until the preceding gap fills (ooo_len 0 = empty).
    ooo_buf: [TCP_OOO_BUF_SIZE]u8 = undefined,
    ooo_seq: u32 = 0,
    ooo_len: u32 = 0,
    // Congestion control (Reno): cwnd/ssthresh in bytes, dup-ACK counter.
    cwnd: u32 = 2144, // 4*536; refined to 4*peer_mss at established
    ssthresh: u32 = TCP_MAX_CWND,
    dup_acks: u8 = 0,
    in_recovery: bool = false,
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

/// False if the ring is full — the caller must then drop the conn slot
/// entirely; an ESTABLISHED conn that never reaches accept() has no owner
/// and would leak its slot forever.
fn enqueueAccepted(lst: *TcpListener, conn_slot: u8) bool {
    const ring_size = TCP_ACCEPT_RING_SIZE;
    const next = (lst.accept_head + 1) % ring_size;
    if (next == lst.accept_tail) return false; // ring full
    lst.accept_ring[lst.accept_head] = conn_slot;
    lst.accept_head = next;
    return true;
}

/// Build and transmit a single TCP segment stamped with an explicit sequence
/// number. `sendTcpPacket` wraps this at conn.snd_nxt for the common case; the
/// data path passes an explicit seq so a retransmission can re-send the oldest
/// unacked bytes (seq == snd_una) rather than whatever went out last.
fn emitSegment(conn: *TcpConn, seq: u32, flags: u8, payload: ?[]const u8, include_mss: bool) bool {
    const loop = isLoopback(conn.remote_ip);
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

    const tcp_hdr_len: u16 = if (include_mss) 24 else 20;
    const payload_len: u16 = if (payload) |p| @intCast(p.len) else 0;
    buildIPv4Header(pkt[ETH_HDR_SIZE..], IPPROTO_TCP, conn.remote_ip, tcp_hdr_len + payload_len);

    const tcp = pkt[ETH_HDR_SIZE + IPV4_HDR_SIZE ..];
    writeU16BE(tcp[0..2], conn.local_port);
    writeU16BE(tcp[2..4], conn.remote_port);
    writeU32BE(tcp[4..8], seq);
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

    return dispatchPacket(conn.remote_ip, pkt[0..total]);
}

/// Send a segment at the connection's current snd_nxt — the common path for
/// control segments and bare ACKs.
fn sendTcpPacket(conn: *TcpConn, flags: u8, payload: ?[]const u8, include_mss: bool) bool {
    return emitSegment(conn, conn.snd_nxt, flags, payload, include_mss);
}

pub fn tcpConnect(dst_ip: [4]u8, dst_port: u16) ?u8 {
    // Resolve the gateway up front, outside the lock — it blocks (poll +
    // sleep); emitSegment's own gateway check is non-blocking by design.
    if (!isLoopback(dst_ip) and !arpResolveGateway()) return null;

    var slot: u8 = 0;
    var conn: *TcpConn = undefined;
    {
        const lk = net_lock.acquireIrqSave();
        defer net_lock.releaseIrqRestore(lk);

        // Find free connection slot
        while (slot < TCP_MAX_CONNS) : (slot += 1) {
            if (!tcp_conns[slot].active) break;
        }
        if (slot >= TCP_MAX_CONNS) return null;

        conn = &tcp_conns[slot];
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
        conn.snd_nxt +%= 1; // SYN consumes one seq number
    }

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
    net_lock.releaseIrqRestore(lk);
    return null;
}

/// Build the half-open server side of a connection from a freshly-arrived
/// SYN. Allocates a free TcpConn slot, fills it with the peer's IP/port and
/// our chosen ISS, and immediately replies with SYN+ACK. The slot stays in
/// SYN-RECEIVED until the peer's ACK promotes it to ESTABLISHED — only then
/// does it become visible to user-space accept().
fn tryAcceptIncomingSyn(ip_data: []volatile u8, ihl: usize, local_port: u16, remote_port: u16, peer_seq: u32) void {
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
    //
    // Use the REAL ihl: the old hardcoded [20..] confused TCP options
    // (which extend data_offset, not ihl) with IP options — a SYN carrying
    // IP options had its TCP header parsed 4+ bytes early.
    const tcp = ip_data[ihl..];
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
    conn.snd_nxt +%= 1; // our SYN consumes one
}

/// Bind a server-side TCP socket to `port`. Returns the listener slot id, or
/// null if all listener slots are taken or the port is already bound.
/// Inbound SYNs whose dst_port matches a listener's port spawn a new TcpConn
/// in SYN-RECEIVED; once it reaches ESTABLISHED the conn slot id appears in
/// the listener's accept ring for `tcpAccept` to consume.
pub fn tcpListen(port: u16) ?u8 {
    if (port == 0) return null;
    const lk = net_lock.acquireIrqSave();
    defer net_lock.releaseIrqRestore(lk);
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
    defer net_lock.releaseIrqRestore(lk);
    const l = &tcp_listeners[listen_slot];
    if (!l.active) return;
    l.* = .{}; // accepted-but-undelivered conns stay live; user can still close them
}

/// Pop one ESTABLISHED conn slot from the listener's accept ring, or null if
/// nothing is queued yet. Non-blocking — the caller polls.
pub fn tcpAccept(listen_slot: u8) ?u8 {
    if (listen_slot >= TCP_MAX_LISTENERS) return null;
    const lk = net_lock.acquireIrqSave();
    defer net_lock.releaseIrqRestore(lk);
    const l = &tcp_listeners[listen_slot];
    if (!l.active) return null;
    if (l.accept_head == l.accept_tail) return null; // ring empty
    const slot = l.accept_ring[l.accept_tail];
    l.accept_ring[l.accept_tail] = 0xFF;
    l.accept_tail = (l.accept_tail + 1) % TCP_ACCEPT_RING_SIZE;
    return slot;
}

// === send buffer (snd_buf ring) ===

/// Most unacked bytes we may keep in flight: bounded by both the peer's
/// advertised window and our own ring. (A congestion window joins this later.)
fn effectiveWindow(conn: *const TcpConn) u32 {
    return @min(@min(conn.snd_wnd, conn.cwnd), @as(u32, TCP_SND_BUF_SIZE));
}

/// Append `bytes` at the ring tail (sequence snd_una+snd_buf_len). The caller
/// guarantees bytes.len <= free space.
fn appendSnd(conn: *TcpConn, bytes: []const u8) void {
    var pos = (conn.snd_buf_head + conn.snd_buf_len) % TCP_SND_BUF_SIZE;
    for (bytes) |b| {
        conn.snd_buf[pos] = b;
        pos = (pos + 1) % TCP_SND_BUF_SIZE;
    }
    conn.snd_buf_len += @intCast(bytes.len);
}

/// Copy out.len bytes from the ring starting at sequence number `seq`, which
/// must lie within [snd_una, snd_una+snd_buf_len).
fn readSnd(conn: *const TcpConn, seq: u32, out: []u8) void {
    var pos = (conn.snd_buf_head + (seq -% conn.snd_una)) % TCP_SND_BUF_SIZE;
    for (out) |*o| {
        o.* = conn.snd_buf[pos];
        pos = (pos + 1) % TCP_SND_BUF_SIZE;
    }
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
    var rto = c.srtt + @max(@as(u32, 1), c.rttvar << 2);
    if (rto < TCP_MIN_RTO_TICKS) rto = TCP_MIN_RTO_TICKS;
    if (rto > TCP_MAX_RTO_TICKS) rto = TCP_MAX_RTO_TICKS;
    c.rto = rto;
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
/// first unacked segment immediately instead of waiting for the RTO.
fn fastRetransmit(c: *TcpConn) void {
    const mss: u32 = c.peer_mss;
    c.ssthresh = @max(c.cwnd / 2, 2 * mss);
    c.cwnd = c.ssthresh;
    c.in_recovery = true;
    if (c.snd_buf_len > 0) {
        const inflight = c.snd_nxt -% c.snd_una;
        const seg = @min(inflight, mss);
        var tmp: [1460]u8 = undefined;
        readSnd(c, c.snd_una, tmp[0..seg]);
        _ = emitSegment(c, c.snd_una, TCP_PSH | TCP_ACK, tmp[0..seg], false);
    }
    c.rtt_pending = false;
}

/// Emit as many new MSS-sized segments as the send window allows, advancing
/// snd_nxt. Sends only buffered-but-unsent bytes: [snd_nxt, snd_una+snd_buf_len).
fn flushSnd(conn: *TcpConn) void {
    const wnd = effectiveWindow(conn);
    var guard: u32 = 0;
    while (guard < TCP_SND_BUF_SIZE) : (guard += 1) {
        const unsent = (conn.snd_una +% conn.snd_buf_len) -% conn.snd_nxt;
        if (unsent == 0) break;
        const inflight = conn.snd_nxt -% conn.snd_una;
        if (inflight >= wnd) break; // window full
        const allow = wnd - inflight;
        const seg = @min(@min(unsent, @as(u32, conn.peer_mss)), allow);
        if (seg == 0) break;
        var tmp: [1460]u8 = undefined;
        readSnd(conn, conn.snd_nxt, tmp[0..seg]);
        if (!emitSegment(conn, conn.snd_nxt, TCP_PSH | TCP_ACK, tmp[0..seg], false)) break;
        conn.snd_nxt +%= seg;
        // Begin an RTT sample for this segment if one isn't already timing.
        if (!conn.rtt_pending) {
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
    if (!isLoopback(conn.remote_ip) and !arpResolveGateway()) return false;

    var off: usize = 0;
    while (off < data.len) {
        // Append + flush under the lock; space is recomputed under the lock
        // so an IRQ-side ACK between iterations can only GROW it.
        {
            const lk = net_lock.acquireIrqSave();
            defer net_lock.releaseIrqRestore(lk);
            if (conn.error_flag or conn.state != .established) return false;
            const space: usize = TCP_SND_BUF_SIZE - conn.snd_buf_len;
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
            if (conn.snd_buf_len < TCP_SND_BUF_SIZE) {
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
    defer net_lock.releaseIrqRestore(lk);
    if (!conn.active) return 0;
    if (conn.rx_count == 0) return 0;

    const avail = @min(conn.rx_count, @as(u32, @intCast(buf.len)));
    const read_pos = (conn.rx_write -% conn.rx_count) % TCP_RX_BUF_SIZE;
    var i: u32 = 0;
    while (i < avail) : (i += 1) {
        buf[i] = conn.rx_buf[(read_pos + i) % TCP_RX_BUF_SIZE];
    }
    conn.rx_count -= avail;
    // Freed receive space may let buffered out-of-order data move in.
    oooDrain(conn);

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

    // Drain the send ring (bounded) BEFORE the FIN. Close used to abandon
    // any buffered-but-unsent tail: the FIN went out at snd_nxt, the bytes
    // beyond it were never flushed, and tcpTick's retransmit logic only
    // re-sent the FIN — classic send-then-close data loss.
    const drain_deadline: u64 = process.tick_count + 200;
    while (process.tick_count < drain_deadline) {
        var pending = false;
        {
            const lk = net_lock.acquireIrqSave();
            defer net_lock.releaseIrqRestore(lk);
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
        defer net_lock.releaseIrqRestore(lk);
        if (conn.state == .established or conn.state == .close_wait) {
            _ = sendTcpPacket(conn, TCP_FIN | TCP_ACK, null, false);
            conn.snd_nxt +%= 1;
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
    conn.active = false;
    conn.state = .closed;
    net_lock.releaseIrqRestore(lk);
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

/// Bulk-copy TCP payload bytes into the connection's ring buffer.
/// Returns the number of bytes actually copied (capped by ring free space).
/// Handles the ring's wrap point with at most two @memcpy calls — replaces
/// a 1500-byte byte-by-byte loop with two vectorised copies, each ~50 ns
/// for an MTU-sized segment vs. ~3 µs for the previous loop. The source's
/// volatile qualifier is shed via @volatileCast: by the time handleRxFrame
/// runs, the NIC's descriptor IRQ implies the device finished the DMA, so
/// the payload is stable DRAM (no benefit from per-byte volatile reads).
/// Copy `len` bytes from a plain source into the receive ring (capped by free
/// space). Updates counters and wakes pollers. Returns bytes copied.
fn rxPush(c: *TcpConn, src: [*]const u8, len: usize) usize {
    const room = TCP_RX_BUF_SIZE - c.rx_count;
    const to_copy = @min(len, room);
    if (to_copy == 0) return 0;
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

/// Push the in-order payload of a received segment (volatile NIC buffer) into
/// the receive ring.
fn ringPushTcpData(c: *TcpConn, tcp: []volatile u8, data_offset: usize, payload_len: usize) usize {
    const src: [*]const u8 = @volatileCast(tcp[data_offset..].ptr);
    return rxPush(c, src, payload_len);
}

/// Buffer an out-of-order segment in the single OOO region. Stores it if the
/// region is empty, extends it if the new segment abuts the end, otherwise drops
/// it (a second disjoint gap — the peer retransmits; single-region by design).
fn oooStore(c: *TcpConn, seq: u32, tcp: []volatile u8, data_offset: usize, payload_len: usize) void {
    const src: [*]const u8 = @volatileCast(tcp[data_offset..].ptr);
    if (c.ooo_len == 0) {
        const n: u32 = @intCast(@min(payload_len, @as(usize, TCP_OOO_BUF_SIZE)));
        @memcpy(c.ooo_buf[0..n], src[0..n]);
        c.ooo_seq = seq;
        c.ooo_len = n;
    } else if (seq == c.ooo_seq +% c.ooo_len) {
        const space = TCP_OOO_BUF_SIZE - c.ooo_len;
        const n: u32 = @intCast(@min(payload_len, @as(usize, space)));
        @memcpy(c.ooo_buf[c.ooo_len..][0..n], src[0..n]);
        c.ooo_len += n;
    }
}

/// After rcv_nxt advances, splice any now-contiguous OOO bytes into the receive
/// ring and advance rcv_nxt over them.
fn oooDrain(c: *TcpConn) void {
    if (c.ooo_len == 0) return;
    // Drop any leading OOO bytes already covered by rcv_nxt.
    const lead = c.rcv_nxt -% c.ooo_seq;
    if (@as(i32, @bitCast(lead)) > 0) {
        const skip = @min(lead, c.ooo_len);
        var i: u32 = 0;
        while (i + skip < c.ooo_len) : (i += 1) c.ooo_buf[i] = c.ooo_buf[i + skip];
        c.ooo_seq +%= skip;
        c.ooo_len -= skip;
    }
    if (c.ooo_len == 0 or c.ooo_seq != c.rcv_nxt) return; // still a gap
    const pushed: u32 = @intCast(rxPush(c, c.ooo_buf[0..].ptr, c.ooo_len));
    c.rcv_nxt +%= pushed;
    if (pushed >= c.ooo_len) {
        c.ooo_len = 0;
    } else {
        const rem = c.ooo_len - pushed; // rx ring filled first; keep the rest
        var i: u32 = 0;
        while (i < rem) : (i += 1) c.ooo_buf[i] = c.ooo_buf[i + pushed];
        c.ooo_seq +%= pushed;
        c.ooo_len = rem;
    }
}

/// Handle an inbound data segment: in-order delivery (then drain OOO), out-of-
/// order buffering, or a duplicate. Always ACKs — a non-advancing ACK is the
/// duplicate ACK the peer's fast-retransmit keys on.
fn receiveData(c: *TcpConn, seq: u32, tcp: []volatile u8, data_offset: usize, payload_len: usize) void {
    if (payload_len == 0) return;
    if (seq == c.rcv_nxt) {
        const copied = ringPushTcpData(c, tcp, data_offset, payload_len);
        c.rcv_nxt +%= @intCast(copied);
        oooDrain(c);
        _ = sendTcpPacket(c, TCP_ACK, null, false);
    } else if (@as(i32, @bitCast(seq -% c.rcv_nxt)) > 0 and (seq -% c.rcv_nxt) < TCP_OOO_BUF_SIZE) {
        oooStore(c, seq, tcp, data_offset, payload_len);
        _ = sendTcpPacket(c, TCP_ACK, null, false); // duplicate ACK (gap remains)
    } else {
        _ = sendTcpPacket(c, TCP_ACK, null, false); // old/duplicate: re-ACK
    }
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
        if ((flags & TCP_SYN) != 0 and (flags & TCP_ACK) == 0) {
            tryAcceptIncomingSyn(ip_data, ihl, dst_port, src_port, seq);
        }
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
        c.error_flag = true;
        c.state = .closed;
        return;
    }

    debug.klog("[tcp] RX state={d} flags=0x{X:0>2} seq={d} ack={d} payload={d}\n", .{ @intFromEnum(c.state), flags, seq, ack, payload_len });

    // Track the peer's advertised receive window for send-side flow control.
    c.snd_wnd = readU16BE(tcp[14..16]);
    // A window update — including one re-opening from a (near-)zero window — can
    // let buffered-but-unsent data move even when this segment's ACK didn't
    // advance snd_una. Flush here too, not only on the snd_una-advancing path,
    // or a slow reader could wedge the sender until the next data-bearing ACK.
    if ((c.state == .established or c.state == .close_wait) and
        (c.snd_una +% c.snd_buf_len) != c.snd_nxt)
    {
        flushSnd(c);
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
                    initCwnd(c);
                    _ = sendTcpPacket(c, TCP_ACK, null, false);
                    @import("../cpu/ipc/fdpoll.zig").wakePollers(.tcp_sock, @as(u16, connSlotIndex(c)));
                }
            }
        },
        .established => {
            // ACK processing
            if (flags & TCP_ACK != 0) {
                const adv = @as(i32, @bitCast(ack -% c.snd_una));
                const inflight = c.snd_nxt -% c.snd_una;
                // Accept only ACKs that advance snd_una without acking data we
                // never sent. Free the acked bytes from the send ring, restart
                // the retransmit timer, and let the freed window push more out.
                if (adv > 0 and @as(u32, @bitCast(adv)) <= inflight) {
                    const acked: u32 = @bitCast(adv);
                    c.snd_buf_head = (c.snd_buf_head + acked) % TCP_SND_BUF_SIZE;
                    c.snd_buf_len -= acked;
                    c.snd_una = ack;
                    ackCwnd(c, acked); // grow cwnd / exit fast recovery
                    c.dup_acks = 0;
                    // Karn: only sample RTT from a segment that wasn't
                    // retransmitted (rtt_pending is cleared on retransmit).
                    if (c.rtt_pending and @as(i32, @bitCast(ack -% c.rtt_seq)) >= 0) {
                        updateRto(c, process.tick_count -% c.rtt_start);
                        c.rtt_pending = false;
                    }
                    c.retransmit_count = 0;
                    c.last_send_tick = process.tick_count;
                    flushSnd(c);
                } else if (adv == 0 and payload_len == 0 and inflight > 0) {
                    // Duplicate ACK: three of them trigger fast retransmit.
                    c.dup_acks += 1;
                    if (c.dup_acks == 3) fastRetransmit(c);
                }
            }
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
                _ = sendTcpPacket(c, TCP_ACK, null, false);
                c.state = .close_wait;
                @import("../cpu/ipc/fdpoll.zig").wakePollers(.tcp_sock, @as(u16, connSlotIndex(c)));
            }
        },
        .fin_wait_1 => {
            // fin_wait_2 needs OUR FIN acked (ack == snd_nxt) — any old ACK
            // used to advance the state with the FIN still unacknowledged,
            // after which nothing would ever retransmit it. The FIN-bearing
            // branch stays lenient (simultaneous close / FIN-without-full-ACK
            // still tears down; time_wait bounds it). rcv_nxt accounts for
            // any payload riding along with the peer's FIN — data sent after
            // our close is discarded, but our final ACK must cover it or the
            // peer retransmits the FIN until its own timeout.
            if (flags & TCP_FIN != 0) {
                c.rcv_nxt = seq +% @as(u32, @intCast(payload_len)) +% 1;
                _ = sendTcpPacket(c, TCP_ACK, null, false);
                c.state = .time_wait;
            } else if (flags & TCP_ACK != 0 and ack == c.snd_nxt) {
                c.state = .fin_wait_2;
            }
        },
        .fin_wait_2 => {
            if (flags & TCP_FIN != 0) {
                c.rcv_nxt = seq +% @as(u32, @intCast(payload_len)) +% 1;
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
        // Retransmission: fire when the oldest unacked octet has gone
        // unacknowledged for the timeout.
        if (c.snd_una != c.snd_nxt and
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
                c.error_flag = true;
                c.state = .closed;
                continue;
            }
            if ((c.state == .established or c.state == .close_wait) and c.snd_buf_len > 0) {
                // Resend the FIRST unacked segment, rebuilt from the send ring —
                // not whatever happened to go out last.
                const inflight = c.snd_nxt -% c.snd_una;
                const seg = @min(inflight, @as(u32, c.peer_mss));
                var tmp: [1460]u8 = undefined;
                readSnd(c, c.snd_una, tmp[0..seg]);
                _ = emitSegment(c, c.snd_una, TCP_PSH | TCP_ACK, tmp[0..seg], false);
            } else if (c.last_tx_len > 0) {
                // Control segment (SYN / SYN-ACK / FIN) retransmit.
                _ = dispatchPacket(c.remote_ip, c.last_tx[0..c.last_tx_len]);
            }
            // Congestion response to a timeout: collapse to one segment and set
            // ssthresh to half the flight size (RFC 5681).
            c.ssthresh = @max(c.cwnd / 2, 2 * @as(u32, c.peer_mss));
            c.cwnd = c.peer_mss;
            c.dup_acks = 0;
            c.in_recovery = false;
            // Karn: back off the timeout exponentially and don't sample RTT from
            // the retransmitted (ambiguous) segment.
            c.rto = @min(c.rto * 2, TCP_MAX_RTO_TICKS);
            c.rtt_pending = false;
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

pub fn handleRxFrame(data: []volatile u8) void {
    // Typically NIC-IRQ context (IF already 0); IrqSave also covers the
    // polled-mode drivers calling in from task context.
    const lk = net_lock.acquireIrqSave();
    defer net_lock.releaseIrqRestore(lk);
    processReceivedPacket(data);
}

pub fn poll() void {
    const lk = net_lock.acquireIrqSave();
    defer net_lock.releaseIrqRestore(lk);
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
