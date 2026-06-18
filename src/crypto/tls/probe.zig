// TLS handshake probe (TLS arc step 2).
//
// One-shot end-to-end test: open TCP to a known TLS 1.3 server, send a
// hand-built ClientHello, receive the ServerHello, parse it, derive the
// X25519 shared secret. klog the result. Does NOT yet handle the
// encrypted records that follow ServerHello — that's step 3 (HKDF key
// schedule + record decryption).
//
// Target is hardcoded: 1.1.1.1:443 (Cloudflare DNS-over-HTTPS endpoint).
// Reasons: stable IP, public, supports TLS 1.3 with ChaCha20-Poly1305,
// accepts our SNI. No DNS path needed since the IP is literal.

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

// Big buffers pinned to BSS so probe.run's stack frame stays lean (KSTACK
// is 16 KB; the probe is called once from boot, so static is fine).
// Without these moves the frame approached 14 KB and overflowed silently
// — symptoms looked like "server didn't respond" because corrupt state
// crashed the receive path. See feedback_kstack_lean_syscall_paths.
var hs_buf_static: [512]u8 = undefined;
var rec_buf_static: [600]u8 = undefined;
var body_static: [4096]u8 = undefined;
var ct_static: [4096]u8 = undefined;
var pt_static: [4096]u8 = undefined;
/// Accumulator for handshake messages that arrive across multiple
/// encrypted records, or get packed multiple-per-record. Walked
/// type+length-prefix-style until exhausted; leftover bytes shift back
/// to the start for the next record's append.
var hs_acc: [16384]u8 = undefined;
/// Scratch for the client Finished record we emit at the end.
var tx_record: [128]u8 = undefined;
/// Captured Certificate handshake message body (everything after the
/// 4-byte type+length prefix). Sized for ~6 KB chains; the openssl
/// s_server self-signed leaf is ~770 B.
var cert_msg_buf: [16384]u8 = undefined;
var cert_msg_len: usize = 0;
/// Captured CertificateVerify body. 2 (scheme) + 2 (length) + up to
/// 512 (RSA-4096 sig).
var cv_buf: [1024]u8 = undefined;
var cv_len: usize = 0;

/// Probe target: the openssl s_server running on the QEMU host
/// (zigvm) on port 4433 with a self-signed CN=zigvm cert. SLIRP NATs
/// 10.0.2.2:port to the host's 127.0.0.1:port. Local round-trip
/// isolates kernel/protocol bugs from internet routing latency —
/// once steps 2-3 stabilize on this target we'll switch back to a
/// real internet TLS endpoint.
const TARGET_IP: [4]u8 = .{ 10, 0, 2, 2 };
const TARGET_PORT: u16 = 4433;
const TARGET_SNI: []const u8 = "zigvm";

fn klogHex(label: []const u8, buf: []const u8) void {
    debug.klog("[tls] {s} = ", .{label});
    for (buf) |b| debug.klog("{x:0>2}", .{b});
    debug.klog("\n", .{});
}

/// Drain `count` bytes from `slot` into `out`, with a tick-based
/// deadline. Returns the actual byte count read. Polls every 10 ms so
/// the BSP isn't pinned. Returns 0 on conn dead or deadline.
fn readAtLeast(slot: u8, out: []u8, want: usize, deadline_tick: u64) usize {
    var got: usize = 0;
    var iters: u32 = 0;
    while (got < want and process.tick_count < deadline_tick) {
        // SLIRP doesn't always raise an IRQ per arriving frame; explicit
        // poll keeps the device RX ring drained. Without this, packets
        // pile in the device queue and tcpRecv reads empty forever.
        net.poll();
        const n = net.tcpRecv(slot, out[got..]);
        if (n > 0) {
            debug.klog("[tls] read +{d} bytes (total {d}/{d})\n", .{ n, got + n, want });
            got += n;
            continue;
        }
        if (net.tcpPeerClosed(slot)) {
            debug.klog("[tls] peer closed after {d} bytes\n", .{got});
            return got;
        }
        iters += 1;
        if (iters % 50000 == 0) {
            debug.klog("[tls] still waiting (iter {d}, got {d}/{d}, tick {d}/{d}, nic_rx_frames={d} bytes={d})\n", .{
                iters, got, want, process.tick_count, deadline_tick,
                net.rx_frame_count, net.rx_frame_total_bytes,
            });
        }
        process.kernelSleepMs(10);
    }
    return got;
}

pub fn run() void {
    debug.klog("[tls] === handshake probe to {d}.{d}.{d}.{d}:{d} ===\n", .{
        TARGET_IP[0], TARGET_IP[1], TARGET_IP[2], TARGET_IP[3], TARGET_PORT,
    });

    if (!net.dhcp_configured and net.local_ip[0] == 10 and net.local_ip[1] == 0) {
        // SLIRP defaults reach the internet via host NAT; we're fine.
    }

    // 1) Ephemeral X25519 keypair. Real implementations also keep the
    //    private key around for the shared-secret step; we stash it on
    //    the stack since the probe runs to completion in one call.
    var our_sk: [32]u8 = undefined;
    if (!random.fillRandom(&our_sk)) {
        debug.klog("[tls] aborting: random source degraded\n", .{});
        return;
    }
    // X25519 wants the secret key clamped per RFC 7748 §5; std.crypto
    // does the clamping internally on scalarMult, but we still need to
    // recover the matching public key.
    const our_pk = X25519.recoverPublicKey(our_sk) catch {
        debug.klog("[tls] X25519 recoverPublicKey failed\n", .{});
        return;
    };
    klogHex("our_pk", &our_pk);

    // 2) client_random — 32 bytes.
    var client_random: [32]u8 = undefined;
    _ = random.fillRandom(&client_random);

    // 3) Build the ClientHello handshake message + wrap in a record.
    const hs_len = messages.buildClientHello(&hs_buf_static, .{
        .client_random = client_random,
        .x25519_pub = our_pk,
        .server_name = TARGET_SNI,
    });
    if (hs_len == 0) {
        debug.klog("[tls] ClientHello build failed\n", .{});
        return;
    }
    debug.klog("[tls] ClientHello body = {d} bytes\n", .{hs_len});

    const rec_len = messages.wrapRecord(&rec_buf_static, .handshake, hs_buf_static[0..hs_len]);
    debug.klog("[tls] record total = {d} bytes\n", .{rec_len});

    // 4) Open TCP. tcpConnect blocks for the SYN-ACK round.
    const slot = net.tcpConnect(TARGET_IP, TARGET_PORT) orelse {
        debug.klog("[tls] TCP connect failed\n", .{});
        return;
    };
    defer net.tcpClose(slot);
    debug.klog("[tls] TCP connected (slot {d})\n", .{slot});

    // 5) Send ClientHello.
    if (!net.tcpSend(slot, rec_buf_static[0..rec_len])) {
        debug.klog("[tls] tcpSend failed\n", .{});
        return;
    }

    // 6) Receive the server's first record. Header is 5 bytes (type +
    //    version + length); read it first, then drain the body.
    var hdr: [5]u8 = undefined;
    const got_hdr = readAtLeast(slot, &hdr, 5, process.tick_count + 3000);
    if (got_hdr != 5) {
        debug.klog("[tls] short read on record header ({d} bytes)\n", .{got_hdr});
        return;
    }
    if (hdr[0] != @intFromEnum(types.ContentType.handshake)) {
        debug.klog("[tls] unexpected content_type=0x{x:0>2} (wanted handshake=0x16)\n", .{hdr[0]});
        return;
    }
    const body_len: usize = (@as(usize, hdr[3]) << 8) | @as(usize, hdr[4]);
    debug.klog("[tls] record body_len = {d}\n", .{body_len});
    if (body_len > 4096) {
        debug.klog("[tls] body too large to probe\n", .{});
        return;
    }
    const got_body = readAtLeast(slot, body_static[0..body_len], body_len, process.tick_count + 500);
    if (got_body != body_len) {
        debug.klog("[tls] short body read ({d} of {d})\n", .{ got_body, body_len });
        return;
    }

    // 7) Body should start with the handshake header: type=ServerHello + 24-bit length.
    if (body_static[0] != @intFromEnum(types.HandshakeType.server_hello)) {
        debug.klog("[tls] first hs msg is not ServerHello (got type={d})\n", .{body_static[0]});
        return;
    }
    const hs_body_len: usize = (@as(usize, body_static[1]) << 16) | (@as(usize, body_static[2]) << 8) | @as(usize, body_static[3]);
    if (hs_body_len + 4 > body_len) {
        debug.klog("[tls] handshake header claims {d} bytes, only {d} available\n", .{ hs_body_len, body_len - 4 });
        return;
    }

    // 8) Parse ServerHello.
    const sh = messages.parseServerHello(body_static[4 .. 4 + hs_body_len]) catch |e| {
        debug.klog("[tls] parseServerHello FAILED: {s}\n", .{@errorName(e)});
        return;
    };
    debug.klog("[tls] ServerHello: cipher=0x{x:0>4}\n", .{@intFromEnum(sh.cipher_suite)});
    klogHex("server_random", &sh.server_random);
    klogHex("server_pk", &sh.server_x25519_pub);

    // Pin the negotiated AEAD (ChaCha20-Poly1305 or AES-128-GCM); governs key
    // length + which primitive the record layer runs.
    const cipher = record_mod.Cipher.fromSuite(@intFromEnum(sh.cipher_suite)) orelse {
        debug.klog("[tls] unsupported cipher 0x{x:0>4}\n", .{@intFromEnum(sh.cipher_suite)});
        return;
    };
    const key_len = cipher.keyLen();

    // 9) Derive shared secret. This is the X25519 ECDH result that
    //    feeds the HKDF key schedule in step 3.
    const shared = X25519.scalarmult(our_sk, sh.server_x25519_pub) catch {
        debug.klog("[tls] X25519.scalarmult FAILED (server pubkey contributed weak point?)\n", .{});
        return;
    };
    klogHex("shared_secret", &shared);

    // === Step 3: HKDF key schedule + decrypt first encrypted record ===
    //
    // Transcript hash spans the ClientHello and ServerHello handshake
    // messages exactly as they were transmitted (no record header, but
    // the 4-byte handshake type/length prefix IS included). Our
    // hs_buf[0..hs_len] holds the ClientHello in that form; body[0..]
    // holds the ServerHello likewise.
    var transcript = Sha256.init(.{});
    transcript.update(hs_buf_static[0..hs_len]);
    transcript.update(body_static[0 .. 4 + hs_body_len]);
    var th: [32]u8 = undefined;
    {
        // Snapshot before final() so we don't spoil the transcript
        // state for subsequent updates in step 4. Sha256.final() pads
        // and compresses, leaving the instance unusable for more data.
        var snap = transcript;
        snap.final(&th);
    }
    klogHex("transcript_hash", &th);

    var keys = keys_mod.deriveHandshakeKeys(shared, th, key_len);
    klogHex("server_hs_key", &keys.server_key);
    klogHex("server_hs_iv", &keys.server_iv);

    // === Step 4: walk all server handshake records up through Finished ===
    //
    // Server sends EE, Cert, CertVerify, Finished — often packed into a
    // single encrypted record but sometimes split. We accumulate the
    // decrypted plaintext of each record into hs_acc and walk it type+
    // length-prefixed. Each parsed handshake message is fed into the
    // transcript hash (still incremental) so we can verify the server
    // Finished MAC the moment it arrives.
    var hs_acc_len: usize = 0;
    var saw_server_finished = false;
    var th_before_finished: [32]u8 = undefined; // transcript hash captured just before Finished is hashed
    var th_before_cv: [32]u8 = undefined; // transcript hash captured just before CertificateVerify
    var saw_cert = false;
    var saw_cv = false;
    cert_msg_len = 0;
    cv_len = 0;

    var record_count: u32 = 0;
    while (!saw_server_finished and record_count < 16) : (record_count += 1) {
        var hdr2: [5]u8 = undefined;
        const got = readAtLeast(slot, &hdr2, 5, process.tick_count + 500);
        if (got != 5) {
            debug.klog("[tls] short read on encrypted record header ({d})\n", .{got});
            return;
        }
        const rec_type = hdr2[0];
        const next_rec_len: usize = (@as(usize, hdr2[3]) << 8) | @as(usize, hdr2[4]);
        debug.klog("[tls] record type=0x{x:0>2} len={d}\n", .{ rec_type, next_rec_len });

        if (rec_type == 0x14) {
            var ccs_body: [4]u8 = undefined;
            _ = readAtLeast(slot, ccs_body[0..next_rec_len], next_rec_len, process.tick_count + 500);
            continue;
        }

        if (rec_type != @intFromEnum(types.ContentType.application_data)) {
            debug.klog("[tls] unexpected record type 0x{x:0>2}, aborting\n", .{rec_type});
            return;
        }

        if (next_rec_len > 4096) {
            debug.klog("[tls] encrypted record too big ({d})\n", .{next_rec_len});
            return;
        }

        const got_ct = readAtLeast(slot, ct_static[0..next_rec_len], next_rec_len, process.tick_count + 500);
        if (got_ct != next_rec_len) {
            debug.klog("[tls] short read on encrypted body ({d}/{d})\n", .{ got_ct, next_rec_len });
            return;
        }

        const pt_len = record_mod.decrypt(
            &pt_static,
            ct_static[0..next_rec_len],
            &hdr2,
            cipher,
            keys.server_key,
            keys.server_iv,
            keys.server_seq,
        ) catch |e| {
            debug.klog("[tls] AEAD decrypt FAILED ({s}) at seq={d}\n", .{ @errorName(e), keys.server_seq });
            return;
        };
        keys.server_seq += 1;

        const stripped = record_mod.stripInnerType(pt_static[0..pt_len]);
        if (stripped.inner_type != 22) {
            debug.klog("[tls] non-handshake inner type 0x{x:0>2}, aborting\n", .{stripped.inner_type});
            return;
        }
        if (hs_acc_len + stripped.content.len > hs_acc.len) {
            debug.klog("[tls] hs_acc overflow\n", .{});
            return;
        }
        @memcpy(hs_acc[hs_acc_len..][0..stripped.content.len], stripped.content);
        hs_acc_len += stripped.content.len;

        // Walk complete handshake messages in the accumulator.
        var walk: usize = 0;
        while (walk + 4 <= hs_acc_len) {
            const hs_type = hs_acc[walk];
            const hs_body_len_w: usize = (@as(usize, hs_acc[walk + 1]) << 16) |
                (@as(usize, hs_acc[walk + 2]) << 8) | @as(usize, hs_acc[walk + 3]);
            const total = 4 + hs_body_len_w;
            if (walk + total > hs_acc_len) break;

            // Snapshot transcript BEFORE adding messages whose verify
            // covers transcript-up-to-but-not-including-themselves.
            // CertificateVerify signs H(CH..Cert); Finished MACs over
            // H(CH..CV) for server / H(CH..serverFin) for client.
            if (hs_type == 15) {
                var snap = transcript;
                snap.final(&th_before_cv);
            }
            if (hs_type == 20) {
                var snap = transcript;
                snap.final(&th_before_finished);
            }
            transcript.update(hs_acc[walk..][0..total]);

            debug.klog("[tls] hs msg type={d} len={d}\n", .{ hs_type, hs_body_len_w });

            // Capture Certificate (type 11) body for x509.parse. Slice
            // points into hs_acc, which gets shifted at end of record —
            // so memcpy out IMMEDIATELY.
            if (hs_type == 11) {
                if (hs_body_len_w > cert_msg_buf.len) {
                    debug.klog("[tls] Certificate too large to capture ({d})\n", .{hs_body_len_w});
                    return;
                }
                @memcpy(cert_msg_buf[0..hs_body_len_w], hs_acc[walk + 4 .. walk + 4 + hs_body_len_w]);
                cert_msg_len = hs_body_len_w;
                saw_cert = true;
            }

            // Capture CertificateVerify (type 15) body.
            if (hs_type == 15) {
                if (hs_body_len_w > cv_buf.len) {
                    debug.klog("[tls] CertificateVerify too large to capture ({d})\n", .{hs_body_len_w});
                    return;
                }
                @memcpy(cv_buf[0..hs_body_len_w], hs_acc[walk + 4 .. walk + 4 + hs_body_len_w]);
                cv_len = hs_body_len_w;
                saw_cv = true;
            }

            if (hs_type == 20) {
                // Verify server Finished.
                if (hs_body_len_w != 32) {
                    debug.klog("[tls] Finished verify_data len {d} != 32\n", .{hs_body_len_w});
                    return;
                }
                var expected: [32]u8 = undefined;
                keys_mod.computeFinishedMac(&expected, keys.server_hs_traffic_secret, th_before_finished);
                const actual = hs_acc[walk + 4 .. walk + 4 + 32];
                if (!std.mem.eql(u8, &expected, actual)) {
                    debug.klog("[tls] SERVER FINISHED MAC MISMATCH\n", .{});
                    klogHex("expected", &expected);
                    klogHex("actual  ", actual);
                    return;
                }
                debug.klog("[tls] server Finished MAC verified\n", .{});
                saw_server_finished = true;
            }

            walk += total;
        }
        // Shift unconsumed remainder to start of accumulator.
        if (walk > 0) {
            const remaining = hs_acc_len - walk;
            if (remaining > 0) @memcpy(hs_acc[0..remaining], hs_acc[walk..][0..remaining]);
            hs_acc_len = remaining;
        }
    }

    if (!saw_server_finished) {
        debug.klog("[tls] never received server Finished\n", .{});
        return;
    }

    // === Step 5: parse leaf certificate + verify CertificateVerify ===
    //
    // The server has now proven it knows the handshake secret (server
    // Finished MAC checked out). Next we prove that the server also
    // holds the private key matching its certificate. Without this
    // check, a man-in-the-middle could complete the handshake using
    // *its own* X25519 + cert and we'd happily talk to it. This is
    // step 5; chain validation against root CAs is step 6.
    if (!saw_cert) {
        debug.klog("[tls] server sent no Certificate — refusing to proceed\n", .{});
        return;
    }
    if (!saw_cv) {
        debug.klog("[tls] server sent no CertificateVerify — refusing to proceed\n", .{});
        return;
    }

    const leaf_der = cert_verify.extractLeafDer(cert_msg_buf[0..cert_msg_len]) catch |e| {
        debug.klog("[tls] extractLeafDer failed: {s}\n", .{@errorName(e)});
        return;
    };
    debug.klog("[tls] leaf cert DER = {d} bytes\n", .{leaf_der.len});

    const leaf = x509.parse(leaf_der) catch |e| {
        debug.klog("[tls] x509.parse failed: {s}\n", .{@errorName(e)});
        return;
    };
    switch (leaf.public_key) {
        .ecdsa_p256 => debug.klog("[tls] leaf pubkey: ECDSA P-256\n", .{}),
        .ecdsa_p384 => debug.klog("[tls] leaf pubkey: ECDSA P-384\n", .{}),
        .rsa => |r| debug.klog("[tls] leaf pubkey: RSA-{d}\n", .{r.modulus.len * 8}),
    }

    // CertificateVerify body wire layout:
    //   uint16 SignatureScheme
    //   uint16 signature_length
    //   opaque signature[signature_length]
    if (cv_len < 4) {
        debug.klog("[tls] CertificateVerify body truncated\n", .{});
        return;
    }
    const cv_scheme: u16 = (@as(u16, cv_buf[0]) << 8) | @as(u16, cv_buf[1]);
    const cv_sig_len: usize = (@as(usize, cv_buf[2]) << 8) | @as(usize, cv_buf[3]);
    if (4 + cv_sig_len > cv_len) {
        debug.klog("[tls] CertificateVerify length mismatch\n", .{});
        return;
    }
    const cv_sig = cv_buf[4 .. 4 + cv_sig_len];
    debug.klog("[tls] CV scheme=0x{x:0>4} sig_len={d}\n", .{ cv_scheme, cv_sig_len });

    if (cert_verify.verifyServer(cv_scheme, cv_sig, &th_before_cv, leaf.public_key)) |_| {
        debug.klog("[tls] CertificateVerify OK — server proven to hold leaf key\n", .{});
    } else |e| {
        if (e == cert_verify.Error.UnsupportedScheme) {
            // Scheme we don't have a verifier for yet. Log + continue
            // so the rest of the handshake exercises end-to-end.
            debug.klog("[tls] CertificateVerify scheme 0x{x:0>4} not yet supported — handshake completing UNAUTHENTICATED\n", .{cv_scheme});
        } else {
            debug.klog("[tls] CertificateVerify FAILED: {s} — aborting\n", .{@errorName(e)});
            return;
        }
    }

    // === Step 5b: walk the certificate chain ===
    //
    // For each cert past the leaf, verify that the previous cert's
    // signature checks out against the current cert's public key. This
    // chains trust from leaf → root. The topmost cert in the chain is
    // either self-signed (verify against own key) or requires a root
    // CA bundle lookup — the latter is step 6.
    //
    // For our test server (single self-signed cert) the loop runs once,
    // there's no link to verify, and the self-sign check at the end
    // exercises the cert-on-cert math path.
    var chain_iter = cert_verify.CertChainIter.init(cert_msg_buf[0..cert_msg_len]) catch |e| {
        debug.klog("[tls] chain iter init failed: {s}\n", .{@errorName(e)});
        return;
    };

    var chain_len: u32 = 0;
    var have_prev = false;
    var prev_cert: x509.Certificate = undefined;
    while (true) {
        const maybe_der = chain_iter.next() catch |e| {
            debug.klog("[tls] chain iter advance failed: {s}\n", .{@errorName(e)});
            return;
        };
        const der = maybe_der orelse break;
        chain_len += 1;

        const c = x509.parse(der) catch |e| {
            debug.klog("[tls] chain[{d}] x509.parse failed: {s}\n", .{ chain_len - 1, @errorName(e) });
            return;
        };
        debug.klog("[tls] chain[{d}] DER={d}B\n", .{ chain_len - 1, der.len });

        if (have_prev) {
            cert_verify.verifyCert(prev_cert, c.public_key) catch |e| {
                debug.klog("[tls] chain[{d}] -> [{d}] sig verify FAILED: {s}\n", .{ chain_len - 2, chain_len - 1, @errorName(e) });
                return;
            };
            debug.klog("[tls] chain[{d}] -> [{d}] sig OK\n", .{ chain_len - 2, chain_len - 1 });
        }
        prev_cert = c;
        have_prev = true;
    }

    if (chain_len == 0) {
        debug.klog("[tls] empty cert chain — refusing\n", .{});
        return;
    }

    // Trust anchor lookup. Try the Mozilla NSS bundle first; that's
    // the normal real-internet path (chain ends at an intermediate, the
    // intermediate's issuer is a trusted root). Fall back to self-signed
    // math if the top cert claims to be its own issuer — useful for
    // private/test CAs but does NOT establish trust on its own.
    const top_self_signed = std.mem.eql(u8, prev_cert.subject_tlv, prev_cert.issuer_tlv);
    if (trust_store.lookup(prev_cert.issuer_tlv)) |root_pk| {
        cert_verify.verifyCert(prev_cert, root_pk) catch |e| {
            debug.klog("[tls] TRUST ANCHOR SIG verify FAILED: {s}\n", .{@errorName(e)});
            return;
        };
        debug.klog("[tls] TRUST ANCHOR HIT — chain anchored to Mozilla NSS root\n", .{});
    } else if (top_self_signed) {
        cert_verify.verifyCert(prev_cert, prev_cert.public_key) catch |e| {
            if (e == cert_verify.Error.UnsupportedScheme) {
                debug.klog("[tls] self-signed top sig algorithm not implemented — UNTRUSTED\n", .{});
            } else {
                debug.klog("[tls] self-signed cert math FAILED: {s} — UNTRUSTED\n", .{@errorName(e)});
            }
        };
        debug.klog("[tls] top cert self-signed but NOT in trust store ({d} roots loaded) — UNTRUSTED\n", .{trust_store.count()});
    } else {
        debug.klog("[tls] no trust anchor found for top cert's issuer — UNTRUSTED\n", .{});
    }

    // Capture transcript hash after server Finished — feeds both the
    // client Finished verify_data and the application-traffic-secret
    // derivation.
    var th_after_sfin: [32]u8 = undefined;
    {
        var snap = transcript;
        snap.final(&th_after_sfin);
    }

    // Build + send client Finished. verify_data = HMAC(client_finished_key, transcript)
    var client_verify_data: [32]u8 = undefined;
    keys_mod.computeFinishedMac(&client_verify_data, keys.client_hs_traffic_secret, th_after_sfin);

    // Handshake message: type=20, 24-bit length=32, body=verify_data
    var fin_msg: [4 + 32]u8 = undefined;
    fin_msg[0] = 20;
    fin_msg[1] = 0;
    fin_msg[2] = 0;
    fin_msg[3] = 32;
    @memcpy(fin_msg[4..], &client_verify_data);

    const tx_len = record_mod.encrypt(
        &tx_record,
        &fin_msg,
        22, // inner_content_type = handshake
        cipher,
        keys.client_key,
        keys.client_iv,
        keys.client_seq,
    ) catch |e| {
        debug.klog("[tls] client Finished encrypt failed: {s}\n", .{@errorName(e)});
        return;
    };
    keys.client_seq += 1;

    if (!net.tcpSend(slot, tx_record[0..tx_len])) {
        debug.klog("[tls] client Finished tcpSend failed\n", .{});
        return;
    }
    debug.klog("[tls] client Finished sent ({d} bytes)\n", .{tx_len});

    // Derive application traffic keys. From now on both sides MUST use
    // these for any record. (We don't actually exchange app data yet —
    // step 5+ wires that in.)
    const app_keys = keys_mod.deriveApplicationKeys(keys.handshake_secret, th_after_sfin, key_len);
    klogHex("client_app_key", &app_keys.client_key);
    klogHex("server_app_key", &app_keys.server_key);

    debug.klog("[tls] === handshake probe step 4 PASS — TLS 1.3 handshake complete ===\n", .{});
}
