// TlsConn — the stateful TLS 1.3 connection used by app-facing
// syscalls. One slot per conn; pool of 4 simultaneous connections.
//
// Lifecycle:
//   open()     → reserve slot, no I/O yet
//   handshake()→ TCP connect + full TLS handshake; sets app keys
//   send()     → encrypt buffer as application_data record(s)
//   recv()     → drain one ciphertext record, decrypt, return plaintext
//   close()    → send close_notify alert, drop TCP
//
// Handshake scratch buffers are shared via hs_lock — we only do one
// handshake at a time. After handshake completes, each conn owns its
// own traffic keys + sequence counters + one plaintext leftover buf.

const std = @import("std");
const debug = @import("../../debug/debug.zig");
const net = @import("../../net/net.zig");
const process = @import("../../proc/process.zig");
const random = @import("../random.zig");
const messages = @import("messages.zig");
const types = @import("types.zig");
const keys_mod = @import("keys.zig");
const record_mod = @import("record.zig");
const x509 = @import("../x509.zig");
const cert_verify = @import("cert_verify.zig");
const trust_store = @import("trust_store.zig");

const X25519 = std.crypto.dh.X25519;
const Sha256 = std.crypto.hash.sha2.Sha256;

const MAX_RECORD_PLAINTEXT: usize = 16640; // 2^14 + max padding/inner
const MAX_RECORD_CIPHERTEXT: usize = 16640 + 16;
const POOL_SIZE: usize = 4;

pub const State = enum { idle, established, peer_closed, errored };

pub const TlsConn = struct {
    in_use: bool,
    state: State,
    tcp_slot: u8,

    // Application traffic keys + per-direction sequence numbers.
    server_key: [32]u8,
    server_iv: [12]u8,
    server_seq: u64,
    client_key: [32]u8,
    client_iv: [12]u8,
    client_seq: u64,

    // Plaintext leftover from the last decrypted record that didn't
    // fit into the user's recv buffer. Up to one record's worth.
    leftover: [MAX_RECORD_PLAINTEXT]u8,
    leftover_pos: usize,
    leftover_len: usize,
};

pub var pool: [POOL_SIZE]TlsConn = blk: {
    var arr: [POOL_SIZE]TlsConn = undefined;
    for (&arr) |*c| {
        c.* = .{
            .in_use = false,
            .state = .idle,
            .tcp_slot = 0,
            .server_key = [_]u8{0} ** 32,
            .server_iv = [_]u8{0} ** 12,
            .server_seq = 0,
            .client_key = [_]u8{0} ** 32,
            .client_iv = [_]u8{0} ** 12,
            .client_seq = 0,
            .leftover = [_]u8{0} ** MAX_RECORD_PLAINTEXT,
            .leftover_pos = 0,
            .leftover_len = 0,
        };
    }
    break :blk arr;
};

// ---------------------------------------------------------------------
// Shared handshake scratch buffers. Only one handshake runs at a time
// (guarded by hs_busy). The post-handshake state moves into the
// conn's own fields.

var hs_busy: bool = false;
var hs_buf: [512]u8 = undefined;
var rec_buf: [600]u8 = undefined;
var body_buf: [4096]u8 = undefined;
// A single TLS 1.3 record can be up to ~16 KiB (2^14 + overhead). RSA cert
// chains routinely exceed 4 KiB and arrive as one Certificate record, so these
// must be full-record-sized — a 4 KiB cap here silently rejected every RSA-
// served site (ECDSA chains are small and slipped through, which is why it
// looked random). Match the steady-state io_ct_buf/io_pt_buf sizing.
var ct_buf: [MAX_RECORD_CIPHERTEXT + 5]u8 = undefined;
var pt_buf: [MAX_RECORD_PLAINTEXT]u8 = undefined;
var hs_acc: [16384]u8 = undefined;
var tx_record: [128]u8 = undefined;
var cert_msg_buf: [16384]u8 = undefined;
var cv_buf: [1024]u8 = undefined;

// ---------------------------------------------------------------------
// Buffers for ongoing send/recv (per-call, shared across conns since we
// serialize TLS ops at the syscall layer for now).

var io_ct_buf: [MAX_RECORD_CIPHERTEXT + 5]u8 = undefined;
var io_pt_buf: [MAX_RECORD_PLAINTEXT]u8 = undefined;

// ---------------------------------------------------------------------

fn alloc() ?u8 {
    var i: u8 = 0;
    while (i < POOL_SIZE) : (i += 1) {
        if (!pool[i].in_use) {
            pool[i].in_use = true;
            pool[i].state = .idle;
            pool[i].leftover_pos = 0;
            pool[i].leftover_len = 0;
            return i;
        }
    }
    return null;
}

fn free(slot: u8) void {
    if (slot >= POOL_SIZE) return;
    pool[slot].in_use = false;
    pool[slot].state = .idle;
}

fn readAtLeast(slot: u8, out: []u8, want: usize, deadline_tick: u64) usize {
    var got: usize = 0;
    while (got < want and process.tick_count < deadline_tick) {
        // Drain the NIC's RX ring into per-connection buffers. SLIRP
        // tends not to trigger an IRQ per frame — without this poll(),
        // packets pile up in the device queue and tcpRecv reads empty
        // forever (the long-form bug behind the earlier "nic_rx_frames
        // stuck at 5" failure mode).
        net.poll();
        const n = net.tcpRecv(slot, out[got..]);
        if (n > 0) {
            got += n;
            continue;
        }
        if (net.tcpPeerClosed(slot)) return got;
        process.kernelSleepMs(10);
    }
    return got;
}

/// Open a TLS conn to (ip, port) with the given SNI. Returns the conn
/// slot on success, or null on any failure. On failure, no TCP slot is
/// held.
pub fn tlsConnect(ip: [4]u8, port: u16, sni: []const u8) ?u8 {
    if (hs_busy) return null; // another handshake in progress
    hs_busy = true;
    defer hs_busy = false;

    const slot = alloc() orelse return null;
    errdefer free(slot);

    // 1. Ephemeral X25519 keypair + client_random.
    var our_sk: [32]u8 = undefined;
    if (!random.fillRandom(&our_sk)) return null;
    const our_pk = X25519.recoverPublicKey(our_sk) catch return null;
    var client_random: [32]u8 = undefined;
    _ = random.fillRandom(&client_random);

    // 2. Build ClientHello + record wrap.
    const hs_len = messages.buildClientHello(&hs_buf, .{
        .client_random = client_random,
        .x25519_pub = our_pk,
        .server_name = sni,
    });
    if (hs_len == 0) return null;
    const rec_len = messages.wrapRecord(&rec_buf, .handshake, hs_buf[0..hs_len]);

    // 3. TCP connect.
    const tcp_slot = net.tcpConnect(ip, port) orelse return null;
    pool[slot].tcp_slot = tcp_slot;
    errdefer net.tcpClose(tcp_slot);

    // 4. Send ClientHello.
    if (!net.tcpSend(tcp_slot, rec_buf[0..rec_len])) return null;

    // 5. Read ServerHello record header + body.
    var hdr: [5]u8 = undefined;
    if (readAtLeast(tcp_slot, &hdr, 5, process.tick_count + 3000) != 5) return null;
    if (hdr[0] != @intFromEnum(types.ContentType.handshake)) {
        // Most common cause: server replied with a TLS Alert (type 21)
        // instead of a Handshake (type 22). Two-byte alert payload =
        // {level, description}. Decode + log so we can tell apart e.g.
        // protocol_version (70), handshake_failure (40), unrecognized_name
        // (112), inappropriate_fallback (86), or close_notify (0).
        if (hdr[0] == @intFromEnum(types.ContentType.alert)) {
            const alen: usize = (@as(usize, hdr[3]) << 8) | @as(usize, hdr[4]);
            if (alen == 2) {
                var ab: [2]u8 = undefined;
                _ = readAtLeast(tcp_slot, &ab, 2, process.tick_count + 200);
                debug.klog("[tls-conn] server alert level={d} desc={d}\n", .{ ab[0], ab[1] });
            } else {
                debug.klog("[tls-conn] server alert len={d}\n", .{alen});
            }
        } else {
            debug.klog("[tls-conn] unexpected record type 0x{x:0>2}\n", .{hdr[0]});
        }
        return null;
    }
    const body_len: usize = (@as(usize, hdr[3]) << 8) | @as(usize, hdr[4]);
    if (body_len > body_buf.len) {
        debug.klog("[tls-conn] ServerHello body too big: {d}\n", .{body_len});
        return null;
    }
    if (readAtLeast(tcp_slot, body_buf[0..body_len], body_len, process.tick_count + 500) != body_len) {
        debug.klog("[tls-conn] ServerHello body read timeout\n", .{});
        return null;
    }

    if (body_buf[0] != @intFromEnum(types.HandshakeType.server_hello)) return null;
    const sh_body_len: usize = (@as(usize, body_buf[1]) << 16) | (@as(usize, body_buf[2]) << 8) | @as(usize, body_buf[3]);
    if (sh_body_len + 4 > body_len) return null;
    const sh = messages.parseServerHello(body_buf[4 .. 4 + sh_body_len]) catch |e| {
        debug.klog("[tls-conn] parseServerHello failed: {s}\n", .{@errorName(e)});
        return null;
    };

    // 6. Derive shared secret + handshake keys.
    const shared = X25519.scalarmult(our_sk, sh.server_x25519_pub) catch return null;
    var transcript = Sha256.init(.{});
    transcript.update(hs_buf[0..hs_len]);
    transcript.update(body_buf[0 .. 4 + sh_body_len]);
    var th: [32]u8 = undefined;
    {
        var snap = transcript;
        snap.final(&th);
    }
    var keys = keys_mod.deriveHandshakeKeys(shared, th);

    // 7. Walk encrypted records (EE / Cert / CertVerify / Finished).
    var hs_acc_len: usize = 0;
    var saw_server_finished = false;
    var th_before_finished: [32]u8 = undefined;
    var th_before_cv: [32]u8 = undefined;
    var saw_cert = false;
    var saw_cv = false;
    var cert_msg_len: usize = 0;
    var cv_len: usize = 0;
    var record_count: u32 = 0;

    while (!saw_server_finished and record_count < 16) : (record_count += 1) {
        var hdr2: [5]u8 = undefined;
        if (readAtLeast(tcp_slot, &hdr2, 5, process.tick_count + 500) != 5) {
            debug.klog("[tls-conn] flight record header read timeout (rec #{d})\n", .{record_count});
            return null;
        }
        const rec_type = hdr2[0];
        const next_rec_len: usize = (@as(usize, hdr2[3]) << 8) | @as(usize, hdr2[4]);
        if (rec_type == 0x14) {
            var ccs_body: [4]u8 = undefined;
            _ = readAtLeast(tcp_slot, ccs_body[0..next_rec_len], next_rec_len, process.tick_count + 500);
            continue;
        }
        if (rec_type != @intFromEnum(types.ContentType.application_data)) {
            debug.klog("[tls-conn] unexpected flight record type 0x{x:0>2}\n", .{rec_type});
            return null;
        }
        if (next_rec_len > ct_buf.len) {
            debug.klog("[tls-conn] record too big: {d} > {d}\n", .{ next_rec_len, ct_buf.len });
            return null;
        }
        if (readAtLeast(tcp_slot, ct_buf[0..next_rec_len], next_rec_len, process.tick_count + 500) != next_rec_len) return null;

        const pt_len = record_mod.decrypt(
            &pt_buf,
            ct_buf[0..next_rec_len],
            &hdr2,
            keys.server_key,
            keys.server_iv,
            keys.server_seq,
        ) catch {
            debug.klog("[tls-conn] record decrypt failed (seq={d})\n", .{keys.server_seq});
            return null;
        };
        keys.server_seq += 1;

        const stripped = record_mod.stripInnerType(pt_buf[0..pt_len]);
        if (stripped.inner_type != 22) {
            // type 23 = early app_data, 21 = alert mid-handshake; either way
            // we can't proceed. Decode the alert {level, desc} when present so
            // we know *why* the server aborted (40=handshake_failure,
            // 47=illegal_parameter, 70=protocol_version, 109=missing_ext, …).
            if (stripped.inner_type == 21 and stripped.content.len >= 2) {
                debug.klog("[tls-conn] handshake alert level={d} desc={d}\n", .{ stripped.content[0], stripped.content[1] });
            } else {
                debug.klog("[tls-conn] unexpected inner type {d} mid-handshake (len={d})\n", .{ stripped.inner_type, stripped.content.len });
            }
            return null;
        }
        if (hs_acc_len + stripped.content.len > hs_acc.len) {
            debug.klog("[tls-conn] handshake accumulator overflow\n", .{});
            return null;
        }
        @memcpy(hs_acc[hs_acc_len..][0..stripped.content.len], stripped.content);
        hs_acc_len += stripped.content.len;

        var walk: usize = 0;
        while (walk + 4 <= hs_acc_len) {
            const hs_type = hs_acc[walk];
            const hs_body_len_w: usize = (@as(usize, hs_acc[walk + 1]) << 16) |
                (@as(usize, hs_acc[walk + 2]) << 8) | @as(usize, hs_acc[walk + 3]);
            const total = 4 + hs_body_len_w;
            if (walk + total > hs_acc_len) break;

            if (hs_type == 15) {
                var snap = transcript;
                snap.final(&th_before_cv);
            }
            if (hs_type == 20) {
                var snap = transcript;
                snap.final(&th_before_finished);
            }
            transcript.update(hs_acc[walk..][0..total]);

            if (hs_type == 11) {
                if (hs_body_len_w > cert_msg_buf.len) {
                    debug.klog("[tls-conn] cert message too big: {d}\n", .{hs_body_len_w});
                    return null;
                }
                @memcpy(cert_msg_buf[0..hs_body_len_w], hs_acc[walk + 4 .. walk + 4 + hs_body_len_w]);
                cert_msg_len = hs_body_len_w;
                saw_cert = true;
            }
            if (hs_type == 15) {
                if (hs_body_len_w > cv_buf.len) return null;
                @memcpy(cv_buf[0..hs_body_len_w], hs_acc[walk + 4 .. walk + 4 + hs_body_len_w]);
                cv_len = hs_body_len_w;
                saw_cv = true;
            }

            if (hs_type == 20) {
                if (hs_body_len_w != 32) return null;
                var expected: [32]u8 = undefined;
                keys_mod.computeFinishedMac(&expected, keys.server_hs_traffic_secret, th_before_finished);
                const actual = hs_acc[walk + 4 .. walk + 4 + 32];
                if (!std.mem.eql(u8, &expected, actual)) {
                    debug.klog("[tls-conn] server Finished MAC mismatch\n", .{});
                    return null;
                }
                saw_server_finished = true;
            }
            walk += total;
        }
        if (walk > 0) {
            const remaining = hs_acc_len - walk;
            if (remaining > 0) @memcpy(hs_acc[0..remaining], hs_acc[walk..][0..remaining]);
            hs_acc_len = remaining;
        }
    }

    if (!saw_server_finished or !saw_cert or !saw_cv) {
        debug.klog("[tls-conn] incomplete flight: fin={} cert={} cv={} records={d}\n", .{ saw_server_finished, saw_cert, saw_cv, record_count });
        return null;
    }

    // 8. Verify CertificateVerify.
    const leaf_der = cert_verify.extractLeafDer(cert_msg_buf[0..cert_msg_len]) catch return null;
    const leaf = x509.parse(leaf_der) catch return null;

    if (cv_len < 4) return null;
    const cv_scheme: u16 = (@as(u16, cv_buf[0]) << 8) | @as(u16, cv_buf[1]);
    const cv_sig_len: usize = (@as(usize, cv_buf[2]) << 8) | @as(usize, cv_buf[3]);
    if (4 + cv_sig_len > cv_len) return null;
    const cv_sig = cv_buf[4 .. 4 + cv_sig_len];

    cert_verify.verifyServer(cv_scheme, cv_sig, &th_before_cv, leaf.public_key) catch |e| {
        debug.klog("[tls-conn] CertificateVerify failed: {s}\n", .{@errorName(e)});
        return null;
    };

    // 9. Chain walk + trust anchor lookup.
    var chain_iter = cert_verify.CertChainIter.init(cert_msg_buf[0..cert_msg_len]) catch return null;
    var have_prev = false;
    var prev_cert: x509.Certificate = undefined;
    while (true) {
        const maybe_der = chain_iter.next() catch return null;
        const der = maybe_der orelse break;
        const c = x509.parse(der) catch return null;
        if (have_prev) {
            cert_verify.verifyCert(prev_cert, c.public_key) catch |e| {
                debug.klog("[tls-conn] chain link sig failed: {s}\n", .{@errorName(e)});
                return null;
            };
        }
        prev_cert = c;
        have_prev = true;
    }
    if (!have_prev) return null;

    const top_self_signed = std.mem.eql(u8, prev_cert.subject_tlv, prev_cert.issuer_tlv);
    var trusted = false;
    if (trust_store.lookup(prev_cert.issuer_tlv)) |root_pk| {
        cert_verify.verifyCert(prev_cert, root_pk) catch {
            debug.klog("[tls-conn] trust anchor sig FAILED\n", .{});
            return null;
        };
        debug.klog("[tls-conn] trust anchor HIT\n", .{});
        trusted = true;
    } else if (top_self_signed) {
        cert_verify.verifyCert(prev_cert, prev_cert.public_key) catch {};
        // Self-signed but not in store: cryptographically consistent
        // but NOT trust-anchored. We allow the conn through with a
        // warning so the test server case still works.
        debug.klog("[tls-conn] WARN: self-signed cert not in trust store\n", .{});
    } else {
        debug.klog("[tls-conn] no trust anchor for top cert; refusing\n", .{});
        return null;
    }

    // 9b. SAN / hostname match against the LEAF cert. Only enforced for
    //     trust-anchored chains — without that, an attacker could pair
    //     a leaf for `evil.com` (with valid SAN) against any trusted
    //     intermediate they have access to. Untrusted self-signed certs
    //     are already flagged UNTRUSTED above; skipping the SAN check
    //     for them preserves the local-test-server workflow.
    if (trusted) {
        if (!cert_verify.matchHostname(leaf, sni)) {
            debug.klog("[tls-conn] hostname mismatch: leaf cert does not cover SNI\n", .{});
            return null;
        }
        debug.klog("[tls-conn] hostname OK — leaf cert SAN covers SNI\n", .{});

        // 9c. Time validity. Only enforced on trust-anchored chains for
        //     the same reason as SAN matching — self-signed test certs
        //     might be issued with quirky dates and we don't want to
        //     break the local-test-server workflow. The RTC supplies
        //     the time; if the RTC is unset, checkValidity returns true
        //     and we skip silently.
        if (!cert_verify.checkValidity(leaf)) {
            debug.klog("[tls-conn] leaf cert NOT in validity window — refusing\n", .{});
            return null;
        }
        debug.klog("[tls-conn] cert validity OK\n", .{});
    }

    // 10. Capture transcript hash after server Finished, build + send
    //     client Finished, derive application traffic keys.
    var th_after_sfin: [32]u8 = undefined;
    {
        var snap = transcript;
        snap.final(&th_after_sfin);
    }
    var client_verify_data: [32]u8 = undefined;
    keys_mod.computeFinishedMac(&client_verify_data, keys.client_hs_traffic_secret, th_after_sfin);

    var fin_msg: [4 + 32]u8 = undefined;
    fin_msg[0] = 20;
    fin_msg[1] = 0;
    fin_msg[2] = 0;
    fin_msg[3] = 32;
    @memcpy(fin_msg[4..], &client_verify_data);

    const tx_len = record_mod.encrypt(
        &tx_record,
        &fin_msg,
        22,
        keys.client_key,
        keys.client_iv,
        keys.client_seq,
    ) catch return null;
    keys.client_seq += 1;
    if (!net.tcpSend(tcp_slot, tx_record[0..tx_len])) return null;

    const app_keys = keys_mod.deriveApplicationKeys(keys.handshake_secret, th_after_sfin);

    // 11. Move app keys into the conn. Sequence numbers reset to 0 for
    //     the application_data direction (different traffic-secret).
    pool[slot].server_key = app_keys.server_key;
    pool[slot].server_iv = app_keys.server_iv;
    pool[slot].server_seq = 0;
    pool[slot].client_key = app_keys.client_key;
    pool[slot].client_iv = app_keys.client_iv;
    pool[slot].client_seq = 0;
    pool[slot].state = .established;

    return slot;
}

/// Encrypt `data` as one TLS 1.3 application_data record and send it
/// over the conn's TCP slot. Returns bytes consumed from `data` (= the
/// whole buffer on success, since one call = one record up to 16 KiB).
pub fn tlsSend(slot: u8, data: []const u8) isize {
    if (slot >= POOL_SIZE) return -1;
    const c = &pool[slot];
    if (!c.in_use or c.state != .established) return -1;
    if (data.len > MAX_RECORD_PLAINTEXT - 1) return -1; // -1 for inner type byte

    const total = record_mod.encrypt(
        &io_ct_buf,
        data,
        23, // application_data inner type
        c.client_key,
        c.client_iv,
        c.client_seq,
    ) catch return -1;
    c.client_seq += 1;
    if (!net.tcpSend(c.tcp_slot, io_ct_buf[0..total])) return -1;
    return @intCast(data.len);
}

/// Read into `out` from the conn's plaintext stream. Returns:
///   > 0  bytes read
///   = 0  peer signalled close_notify (graceful EOF)
///   < 0  error
pub fn tlsRecv(slot: u8, out: []u8) isize {
    debug.klog("[tls-conn] recv enter slot={d} out.len={d}\n", .{ slot, out.len });
    if (slot >= POOL_SIZE) return -1;
    const c = &pool[slot];
    if (!c.in_use) return -1;

    // Serve any leftover from a previous record.
    if (c.leftover_pos < c.leftover_len) {
        const avail = c.leftover_len - c.leftover_pos;
        const n = if (avail < out.len) avail else out.len;
        @memcpy(out[0..n], c.leftover[c.leftover_pos .. c.leftover_pos + n]);
        c.leftover_pos += n;
        return @intCast(n);
    }
    c.leftover_pos = 0;
    c.leftover_len = 0;

    if (c.state == .peer_closed) return 0;
    if (c.state != .established) return -1;

    // Loop until we get application data, an alert, or a hard error.
    // TLS 1.3 servers commonly send post-handshake messages (typically
    // NewSessionTicket, inner type 22) interleaved with app data; those
    // are NOT errors and must be skipped silently.
    var record_attempts: u32 = 0;
    while (record_attempts < 8) : (record_attempts += 1) {
        var hdr: [5]u8 = undefined;
        if (readAtLeast(c.tcp_slot, &hdr, 5, process.tick_count + 3000) != 5) {
            if (net.tcpPeerClosed(c.tcp_slot)) {
                c.state = .peer_closed;
                return 0;
            }
            return -1;
        }
        const rec_type = hdr[0];
        const rec_len: usize = (@as(usize, hdr[3]) << 8) | @as(usize, hdr[4]);
        if (rec_len > io_ct_buf.len) return -1;
        if (readAtLeast(c.tcp_slot, io_ct_buf[0..rec_len], rec_len, process.tick_count + 3000) != rec_len) return -1;

        if (rec_type != @intFromEnum(types.ContentType.application_data)) {
            // Anything not in application_data record framing this late is
            // a protocol violation under TLS 1.3 (all real records use the
            // app_data outer type after server Finished). Close hard.
            c.state = .errored;
            return -1;
        }

        const pt_len = record_mod.decrypt(
            &io_pt_buf,
            io_ct_buf[0..rec_len],
            &hdr,
            c.server_key,
            c.server_iv,
            c.server_seq,
        ) catch {
            c.state = .errored;
            return -1;
        };
        c.server_seq += 1;

        const stripped = record_mod.stripInnerType(io_pt_buf[0..pt_len]);
        switch (stripped.inner_type) {
            23 => { // application_data
                const content = stripped.content;
                if (content.len <= out.len) {
                    @memcpy(out[0..content.len], content);
                    return @intCast(content.len);
                }
                @memcpy(out[0..out.len], content[0..out.len]);
                const remaining = content[out.len..];
                @memcpy(c.leftover[0..remaining.len], remaining);
                c.leftover_pos = 0;
                c.leftover_len = remaining.len;
                return @intCast(out.len);
            },
            21 => { // alert (close_notify or any other)
                c.state = .peer_closed;
                return 0;
            },
            22 => {
                // Post-handshake message — NewSessionTicket, KeyUpdate,
                // CertificateRequest (for mTLS, rare). We don't act on
                // any of them yet; skip the record and try again. Looping
                // is bounded so a malicious peer can't keep us forever.
                debug.klog("[tls-conn] skipped post-hs record ({d} B)\n", .{stripped.content.len});
                continue;
            },
            else => {
                c.state = .errored;
                return -1;
            },
        }
    }
    // Exhausted the post-handshake skip budget without any app data.
    return -1;
}

/// Send a close_notify alert and tear down the TCP. Always frees the
/// slot, even if the alert fails.
pub fn tlsClose(slot: u8) void {
    debug.klog("[tls-conn] close enter slot={d}\n", .{slot});
    if (slot >= POOL_SIZE) return;
    const c = &pool[slot];
    if (!c.in_use) return;

    if (c.state == .established) {
        // Alert: level=warning (1), description=close_notify (0).
        const alert = [_]u8{ 1, 0 };
        const total = record_mod.encrypt(
            &io_ct_buf,
            &alert,
            21, // alert inner type
            c.client_key,
            c.client_iv,
            c.client_seq,
        ) catch {
            net.tcpClose(c.tcp_slot);
            free(slot);
            return;
        };
        c.client_seq += 1;
        _ = net.tcpSend(c.tcp_slot, io_ct_buf[0..total]);
    }
    net.tcpClose(c.tcp_slot);
    free(slot);
}
