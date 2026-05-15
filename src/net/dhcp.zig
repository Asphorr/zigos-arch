// DHCPv4 client — boot-time only. RFC 2131 short-form: DISCOVER → OFFER →
// REQUEST → ACK, no T1/T2 renewal, no DHCPDECLINE on conflict. We trust the
// first OFFER, lock the lease, and never re-acquire — if the lease expires
// at runtime everything silently breaks. Good enough for now because most
// LAN leases are >= 1 hour and ZigOS doesn't yet run unattended that long.
//
// Implementation notes:
//   - Sends use `net.udpSendBroadcast` (no ARP, src = 0.0.0.0). The L2 dst
//     is ff:ff:ff:ff:ff:ff so the request hits the local DHCP server even
//     when the server is on a separate VLAN-style segment.
//   - Receive uses the existing UDP listener machinery: udpListen(68) →
//     handleUdpPacket → listener.has_data. We don't filter on xid in
//     `handleUdpPacket` (the listener has no concept of xid); we filter
//     here on parse.
//   - Magic cookie + option-53 (message type) are validated before parsing
//     any other option, so a malformed BOOTP reply can't promote us off
//     the static SLIRP defaults.

const std = @import("std");
const debug = @import("../debug/debug.zig");
const nic = @import("../driver/nic.zig");
const process = @import("../proc/process.zig");
const net = @import("net.zig");

// DHCP option-53 message types.
const DHCPDISCOVER: u8 = 1;
const DHCPOFFER: u8 = 2;
const DHCPREQUEST: u8 = 3;
const DHCPACK: u8 = 5;
const DHCPNAK: u8 = 6;

const MAGIC_COOKIE = [_]u8{ 0x63, 0x82, 0x53, 0x63 };
const CLIENT_PORT: u16 = 68;
const SERVER_PORT: u16 = 67;
const BOOTP_HDR_SIZE: usize = 240;

const DhcpOffer = struct {
    yiaddr: [4]u8,
    server_id: [4]u8,
    subnet_mask: [4]u8,
    router: [4]u8,
    dns: [4]u8,
    lease_secs: u32,
};

fn writeBeU16(buf: []u8, off: usize, v: u16) void {
    buf[off] = @intCast(v >> 8);
    buf[off + 1] = @intCast(v & 0xFF);
}

fn writeBeU32(buf: []u8, off: usize, v: u32) void {
    buf[off] = @intCast((v >> 24) & 0xFF);
    buf[off + 1] = @intCast((v >> 16) & 0xFF);
    buf[off + 2] = @intCast((v >> 8) & 0xFF);
    buf[off + 3] = @intCast(v & 0xFF);
}

fn readBeU32(buf: []const u8) u32 {
    return @as(u32, buf[0]) << 24 | @as(u32, buf[1]) << 16 |
        @as(u32, buf[2]) << 8 | @as(u32, buf[3]);
}

fn buildBootpHeader(buf: []u8, mac: [6]u8, xid: u32) void {
    @memset(buf[0..BOOTP_HDR_SIZE], 0);
    buf[0] = 1;     // op = BOOTREQUEST
    buf[1] = 1;     // htype = Ethernet
    buf[2] = 6;     // hlen
    // buf[3] = hops = 0
    writeBeU32(buf, 4, xid);
    // buf[8..10] = secs = 0
    buf[10] = 0x80; // flags.B = 1 → server should broadcast reply
    buf[11] = 0;
    // ciaddr/yiaddr/siaddr/giaddr = 0 (no IP yet)
    @memcpy(buf[28..34], &mac); // chaddr — first 6 bytes are the MAC
    // sname (64) + file (128) stay zero
    @memcpy(buf[236..240], &MAGIC_COOKIE);
}

/// Append one TLV option. Returns the new write offset.
fn writeOption(buf: []u8, off: usize, tag: u8, data: []const u8) usize {
    buf[off] = tag;
    buf[off + 1] = @intCast(data.len);
    @memcpy(buf[off + 2 ..][0..data.len], data);
    return off + 2 + data.len;
}

fn writeOptionEnd(buf: []u8, off: usize) usize {
    buf[off] = 0xFF;
    return off + 1;
}

/// Standard parameter-request list: subnet mask, router, DNS server,
/// lease time, broadcast address. We don't use all of them today but
/// asking for them is free and futureproofs the dispatch when we add
/// route-table support.
const PARAM_REQ_LIST = [_]u8{ 1, 3, 6, 51, 28 };
const HOSTNAME = "zigos";

fn buildDiscover(buf: []u8, mac: [6]u8, xid: u32) usize {
    buildBootpHeader(buf, mac, xid);
    var off: usize = BOOTP_HDR_SIZE;
    off = writeOption(buf, off, 53, &[_]u8{DHCPDISCOVER});
    off = writeOption(buf, off, 55, &PARAM_REQ_LIST);
    off = writeOption(buf, off, 12, HOSTNAME);
    off = writeOptionEnd(buf, off);
    return off;
}

fn buildRequest(buf: []u8, mac: [6]u8, xid: u32, requested_ip: [4]u8, server_id: [4]u8) usize {
    buildBootpHeader(buf, mac, xid);
    var off: usize = BOOTP_HDR_SIZE;
    off = writeOption(buf, off, 53, &[_]u8{DHCPREQUEST});
    off = writeOption(buf, off, 50, &requested_ip);
    off = writeOption(buf, off, 54, &server_id);
    off = writeOption(buf, off, 55, &PARAM_REQ_LIST);
    off = writeOption(buf, off, 12, HOSTNAME);
    off = writeOptionEnd(buf, off);
    return off;
}

/// Iterate the option block (everything after the 240-byte BOOTP header)
/// and return a slice into the payload for the requested tag. Handles
/// 0x00 (pad) and 0xFF (end) as documented in RFC 2132.
fn findOption(payload: []const u8, tag: u8) ?[]const u8 {
    if (payload.len < BOOTP_HDR_SIZE + 4) return null;
    if (!std.mem.eql(u8, payload[236..240], &MAGIC_COOKIE)) return null;
    var pos: usize = BOOTP_HDR_SIZE;
    while (pos < payload.len) {
        const t = payload[pos];
        if (t == 0xFF) return null;
        if (t == 0x00) { pos += 1; continue; }
        if (pos + 1 >= payload.len) return null;
        const len: usize = payload[pos + 1];
        if (pos + 2 + len > payload.len) return null;
        if (t == tag) return payload[pos + 2 .. pos + 2 + len];
        pos += 2 + len;
    }
    return null;
}

/// Parse a DHCP packet (BOOTREPLY) and return the offered lease if it
/// passes the xid + chaddr + message-type checks. `expected_type` is
/// DHCPOFFER or DHCPACK depending on which transaction step we're in.
fn parseReply(payload: []const u8, expected_xid: u32, our_mac: [6]u8, expected_type: u8) ?DhcpOffer {
    if (payload.len < BOOTP_HDR_SIZE) return null;
    if (payload[0] != 2) return null; // op = BOOTREPLY
    const xid = readBeU32(payload[4..8]);
    if (xid != expected_xid) return null;
    if (!std.mem.eql(u8, payload[28..34], &our_mac)) return null;

    const msg_type_opt = findOption(payload, 53) orelse return null;
    if (msg_type_opt.len != 1) return null;
    if (msg_type_opt[0] == DHCPNAK) {
        debug.klog("[dhcp] server sent NAK\n", .{});
        return null;
    }
    if (msg_type_opt[0] != expected_type) return null;

    var offer = DhcpOffer{
        .yiaddr = .{ payload[16], payload[17], payload[18], payload[19] },
        .server_id = .{ 0, 0, 0, 0 },
        .subnet_mask = .{ 255, 255, 255, 0 },
        .router = .{ 0, 0, 0, 0 },
        .dns = .{ 0, 0, 0, 0 },
        .lease_secs = 3600,
    };

    if (findOption(payload, 54)) |sid| { if (sid.len == 4) @memcpy(&offer.server_id, sid); }
    if (findOption(payload, 1))  |m|   { if (m.len == 4)   @memcpy(&offer.subnet_mask, m); }
    if (findOption(payload, 3))  |r|   { if (r.len >= 4)   @memcpy(&offer.router, r[0..4]); }
    if (findOption(payload, 6))  |d|   { if (d.len >= 4)   @memcpy(&offer.dns, d[0..4]); }
    if (findOption(payload, 51)) |lt|  { if (lt.len == 4)  offer.lease_secs = readBeU32(lt); }
    return offer;
}

/// Wait up to `deadline_tick` for a UDP packet on `slot` that parses as
/// `expected_type` (OFFER or ACK). Returns the parsed offer or null on
/// timeout / no-match. Polls every 10ms so the BSP stays responsive
/// (mirrors the DNS resolve loop's cadence).
fn waitForReply(slot: u8, deadline_tick: u64, expected_xid: u32, our_mac: [6]u8, expected_type: u8) ?DhcpOffer {
    while (process.tick_count < deadline_tick) {
        net.poll();
        if (net.udpHasData(slot)) {
            const payload = net.udpData(slot);
            const parsed = parseReply(payload, expected_xid, our_mac, expected_type);
            net.udpConsume(slot);
            if (parsed) |o| return o;
            // Wrong xid / not OFFER / NAK — keep waiting in case another
            // server on the LAN is faster (we accept the first valid one).
        }
        process.kernelSleepMs(10);
    }
    return null;
}

/// Run a DISCOVER → OFFER → REQUEST → ACK exchange. Retries DISCOVER
/// twice with 1.5s windows before giving up. On success, writes the
/// lease into net.zig globals via `net.applyDhcpLease()` and returns
/// true. On any failure, returns false and the caller falls back to the
/// hardcoded SLIRP defaults already set in net.zig.
pub fn acquire(total_deadline_tick: u64) bool {
    if (!nic.isReady()) {
        debug.klog("[dhcp] NIC not ready, skipping\n", .{});
        return false;
    }
    const our_mac = nic.getMac();
    // xid: cheap pseudo-random from boot ticks + MAC tail. Doesn't have to
    // be cryptographically random — just unique per DHCP exchange so we
    // can disambiguate replies from concurrent clients on the same LAN.
    var xid: u32 = @intCast(process.tick_count & 0xFFFF);
    xid = (xid << 16) | (@as(u32, our_mac[4]) << 8) | our_mac[5];

    const slot = net.udpListen(CLIENT_PORT) orelse {
        debug.klog("[dhcp] no UDP listener slot free\n", .{});
        return false;
    };
    defer net.udpUnlisten(slot);

    var pkt: [400]u8 = undefined;
    var attempt: u8 = 0;
    while (attempt < 3) : (attempt += 1) {
        if (process.tick_count >= total_deadline_tick) break;

        const disc_len = buildDiscover(&pkt, our_mac, xid +% attempt);
        debug.klog("[dhcp] sending DISCOVER (attempt {d}, xid=0x{x})\n", .{ attempt + 1, xid +% attempt });
        if (!net.udpSendBroadcast(CLIENT_PORT, SERVER_PORT, pkt[0..disc_len])) {
            debug.klog("[dhcp] DISCOVER send failed\n", .{});
            continue;
        }

        // Per-attempt 1.5s window, capped by the outer deadline.
        var window: u64 = process.tick_count + 150;
        if (window > total_deadline_tick) window = total_deadline_tick;
        const offer = waitForReply(slot, window, xid +% attempt, our_mac, DHCPOFFER) orelse {
            debug.klog("[dhcp] no OFFER within window\n", .{});
            continue;
        };

        debug.klog("[dhcp] OFFER ip={d}.{d}.{d}.{d} gw={d}.{d}.{d}.{d} dns={d}.{d}.{d}.{d} lease={d}s\n", .{
            offer.yiaddr[0], offer.yiaddr[1], offer.yiaddr[2], offer.yiaddr[3],
            offer.router[0], offer.router[1], offer.router[2], offer.router[3],
            offer.dns[0],    offer.dns[1],    offer.dns[2],    offer.dns[3],
            offer.lease_secs,
        });

        const req_len = buildRequest(&pkt, our_mac, xid +% attempt, offer.yiaddr, offer.server_id);
        if (!net.udpSendBroadcast(CLIENT_PORT, SERVER_PORT, pkt[0..req_len])) {
            debug.klog("[dhcp] REQUEST send failed\n", .{});
            continue;
        }

        var ack_window: u64 = process.tick_count + 150;
        if (ack_window > total_deadline_tick) ack_window = total_deadline_tick;
        const ack = waitForReply(slot, ack_window, xid +% attempt, our_mac, DHCPACK) orelse {
            debug.klog("[dhcp] no ACK within window\n", .{});
            continue;
        };

        net.applyDhcpLease(ack.yiaddr, ack.router, ack.subnet_mask, ack.dns, ack.lease_secs);
        debug.klog("[dhcp] lease applied — IP {d}.{d}.{d}.{d}/{d}.{d}.{d}.{d} via {d}.{d}.{d}.{d}\n", .{
            ack.yiaddr[0], ack.yiaddr[1], ack.yiaddr[2], ack.yiaddr[3],
            ack.subnet_mask[0], ack.subnet_mask[1], ack.subnet_mask[2], ack.subnet_mask[3],
            ack.router[0], ack.router[1], ack.router[2], ack.router[3],
        });
        return true;
    }

    debug.klog("[dhcp] giving up after 3 attempts, keeping SLIRP defaults\n", .{});
    return false;
}
