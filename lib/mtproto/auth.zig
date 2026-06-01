//! MTProto 2.0 auth_key handshake — the 3 round-trips that establish a
//! permanent authorization key with a Telegram DC over the intermediate TCP
//! transport:
//!
//!     req_pq_multi         -> resPQ
//!     req_DH_params        -> server_DH_params_ok
//!     set_client_DH_params -> dh_gen_ok
//!
//! Every crypto primitive this calls (tl/ige/factorize/rsa_pad/rsa_key/kdf/dh)
//! is KAT-proven off-target against the official core.telegram.org sample;
//! this module is the live glue. On success it returns the 2048-bit auth_key,
//! its id, and the initial server salt.
//!
//! We send the classic `p_q_inner_data#83c95aec` (no dc field) — the variant
//! Telethon still uses and production still accepts.

const std = @import("std");
const libc = @import("libc");
const tl = @import("tl.zig");
const ige = @import("ige.zig");
const factor = @import("factorize.zig");
const rsa = @import("rsa_pad.zig");
const rsa_key = @import("rsa_key.zig");
const kdf = @import("kdf.zig");
const dh = @import("dh.zig");
const transport = @import("transport.zig");
const Sha1 = std.crypto.hash.Sha1;

pub const Logger = *const fn (msg: []const u8) void;

pub const Auth = struct {
    auth_key: [256]u8,
    auth_key_id: [8]u8,
    server_salt: [8]u8,
    g: i32,
    server_time: i32,
};

pub const Error = error{
    Rng,
    Send,
    Recv,
    TransportError,
    BadResPQ,
    NonceMismatch,
    FactorFailed,
    NoKnownKey,
    RsaPad,
    ServerDHFail,
    BadServerDH,
    DHRange,
    DhGenRetry,
    DhGenFail,
    BadDhGen,
    NonceHashMismatch,
};

// --- TL constructor ids (all confirmed against the schema; the two we send
//     blind are anchored by a live req_pq round-trip and the server_DH KAT) ---
const C_REQ_PQ_MULTI: u32 = 0xbe7e8ef1;
const C_RES_PQ: u32 = 0x05162463;
const C_PQ_INNER_DATA: u32 = 0x83c95aec;
const C_REQ_DH_PARAMS: u32 = 0xd712e4be;
const C_SERVER_DH_OK: u32 = 0xd0e8075c;
const C_SERVER_DH_FAIL: u32 = 0x79cb045d;
const C_SERVER_DH_INNER: u32 = 0xb5890dba;
const C_CLIENT_DH_INNER: u32 = 0x6643b654;
const C_SET_CLIENT_DH: u32 = 0xf5045f1f;
const C_DH_GEN_OK: u32 = 0x3bcbf734;
const C_DH_GEN_RETRY: u32 = 0x46dc1fb9;
const C_DH_GEN_FAIL: u32 = 0xa69dae02;

// --- randomness: kernel CSPRNG via libc.getRandom; a failure latches here ---
var rng_ok: bool = true;
fn fill(buf: []u8) void {
    if (!libc.getRandom(buf)) rng_ok = false;
}

// --- unencrypted (auth_key_id=0) envelope plumbing ---
var msg_id_ctr: u64 = 0;
fn nextMsgId() u64 {
    const tod = libc.gettimeofday();
    const sec: u64 = @intCast(tod.sec);
    const usec: u64 = @intCast(tod.usec);
    var id = (sec << 32) | ((usec << 12) & 0xFFFF_FFFC);
    if (id <= msg_id_ctr) id = msg_id_ctr + 4; // strictly increasing, /4
    msg_id_ctr = id;
    return id;
}

fn sendPlain(conn: *transport.Conn, body: []const u8) Error!void {
    var buf: [768]u8 = undefined;
    var w = tl.Writer.init(&buf);
    w.writeLong(0) catch return error.Send; // auth_key_id = 0
    w.writeLong(nextMsgId()) catch return error.Send;
    w.writeU32(@intCast(body.len)) catch return error.Send;
    w.writeRaw(body) catch return error.Send;
    conn.send(w.written()) catch return error.Send;
}

/// Receive one unencrypted message; returns the inner body as a slice of `buf`.
fn recvPlain(conn: *transport.Conn, buf: []u8, log: Logger) Error![]const u8 {
    const frame = conn.recv(buf) catch return error.Recv;
    if (frame.len == 4) { // transport-level error: a 4-byte LE int32 code
        logHex(log, "[auth] transport error frame (LE) = ", frame);
        return error.TransportError;
    }
    if (frame.len < 20) return error.Recv;
    var r = tl.Reader.init(frame);
    _ = r.readLong() catch return error.Recv; // auth_key_id (expect 0)
    _ = r.readLong() catch return error.Recv; // server msg_id
    const len = r.readU32() catch return error.Recv;
    return r.readRaw(len) catch return error.Recv;
}

fn eql16(a: [16]u8, b: [16]u8) bool {
    return std.mem.eql(u8, &a, &b);
}

/// Big-endian minimal-length encoding of a u64 (strip leading zero bytes).
fn u64ToMinBytes(v: u64, out: *[8]u8) usize {
    var tmp: [8]u8 = undefined;
    std.mem.writeInt(u64, &tmp, v, .big);
    var start: usize = 0;
    while (start < 7 and tmp[start] == 0) start += 1;
    const len = 8 - start;
    @memcpy(out[0..len], tmp[start..]);
    return len;
}

// --- tiny serial-friendly formatters (single-threaded app) ---
var line: [320]u8 = undefined;
fn hexNib(n: u8) u8 {
    return if (n < 10) '0' + n else 'a' + (n - 10);
}
fn logHex(log: Logger, prefix: []const u8, bytes: []const u8) void {
    var n: usize = 0;
    for (prefix) |c| {
        if (n < line.len) {
            line[n] = c;
            n += 1;
        }
    }
    for (bytes) |b| {
        if (n + 2 > line.len) break;
        line[n] = hexNib(b >> 4);
        line[n + 1] = hexNib(b & 0xF);
        n += 2;
    }
    if (n < line.len) {
        line[n] = '\n';
        n += 1;
    }
    log(line[0..n]);
}
fn logU64(log: Logger, prefix: []const u8, v: u64) void {
    var n: usize = 0;
    for (prefix) |c| {
        if (n < line.len) {
            line[n] = c;
            n += 1;
        }
    }
    var tmp: [20]u8 = undefined;
    var k: usize = 0;
    if (v == 0) {
        tmp[0] = '0';
        k = 1;
    } else {
        var x = v;
        while (x > 0) : (x /= 10) {
            tmp[k] = '0' + @as(u8, @intCast(x % 10));
            k += 1;
        }
    }
    var i: usize = 0;
    while (i < k) : (i += 1) {
        if (n < line.len) {
            line[n] = tmp[k - 1 - i];
            n += 1;
        }
    }
    if (n < line.len) {
        line[n] = '\n';
        n += 1;
    }
    log(line[0..n]);
}

/// Run the full handshake over an already-connected transport. The caller
/// owns the connection (and its transport magic); we only exchange messages.
pub fn createAuthKey(conn: *transport.Conn, log: Logger) Error!Auth {
    rng_ok = true;
    msg_id_ctr = 0;

    // ============ Round 1: req_pq_multi -> resPQ ============
    var nonce: [16]u8 = undefined;
    fill(&nonce);
    if (!rng_ok) return error.Rng;

    {
        var body: [32]u8 = undefined;
        var w = tl.Writer.init(&body);
        w.writeU32(C_REQ_PQ_MULTI) catch return error.Send;
        w.writeInt128(nonce) catch return error.Send;
        try sendPlain(conn, w.written());
    }
    log("[auth] -> req_pq_multi\n");

    var rbuf: [1024]u8 = undefined;
    const respq = try recvPlain(conn, &rbuf, log);

    var pq_buf: [16]u8 = undefined;
    var pq_len: usize = 0;
    var server_nonce: [16]u8 = undefined;
    var fingerprints: [16]u64 = undefined;
    var fp_count: usize = 0;
    {
        var r = tl.Reader.init(respq);
        if ((r.readU32() catch return error.BadResPQ) != C_RES_PQ) return error.BadResPQ;
        if (!eql16(r.readInt128() catch return error.BadResPQ, nonce)) return error.NonceMismatch;
        server_nonce = r.readInt128() catch return error.BadResPQ;
        const pq = r.readBytes() catch return error.BadResPQ;
        if (pq.len == 0 or pq.len > pq_buf.len) return error.BadResPQ;
        @memcpy(pq_buf[0..pq.len], pq);
        pq_len = pq.len;
        if ((r.readU32() catch return error.BadResPQ) != tl.VECTOR_CTOR) return error.BadResPQ;
        const n = r.readInt() catch return error.BadResPQ;
        if (n < 0) return error.BadResPQ;
        fp_count = @min(@as(usize, @intCast(n)), fingerprints.len);
        var i: usize = 0;
        while (i < fp_count) : (i += 1) fingerprints[i] = r.readLong() catch return error.BadResPQ;
    }
    log("[auth] <- resPQ (nonce OK)\n");

    // pq -> integer, factor into p < q
    var pq_val: u64 = 0;
    for (pq_buf[0..pq_len]) |b| pq_val = (pq_val << 8) | b;
    logU64(log, "[auth] pq = ", pq_val);
    const pf = factor.factorize(pq_val) orelse return error.FactorFailed;
    const p_val = @min(pf[0], pf[1]);
    const q_val = @max(pf[0], pf[1]);
    logU64(log, "[auth] p = ", p_val);
    logU64(log, "[auth] q = ", q_val);

    // pick the first offered key we actually hold
    var chosen_fp: u64 = 0;
    var chosen_key: rsa_key.PublicKey = undefined;
    {
        var found = false;
        var i: usize = 0;
        while (i < fp_count) : (i += 1) {
            if (rsa_key.byFingerprint(fingerprints[i])) |k| {
                chosen_fp = fingerprints[i];
                chosen_key = k;
                found = true;
                break;
            }
        }
        if (!found) return error.NoKnownKey;
    }
    logHex(log, "[auth] server key fp = ", std.mem.asBytes(&chosen_fp));

    // ============ Round 2: req_DH_params -> server_DH_params_ok ============
    var new_nonce: [32]u8 = undefined;
    fill(&new_nonce);
    if (!rng_ok) return error.Rng;

    var pbytes: [8]u8 = undefined;
    const pl = u64ToMinBytes(p_val, &pbytes);
    var qbytes: [8]u8 = undefined;
    const ql = u64ToMinBytes(q_val, &qbytes);

    // p_q_inner_data#83c95aec (<=144 bytes for RSA_PAD)
    const encrypted_data = blk: {
        var pqi: [160]u8 = undefined;
        var w = tl.Writer.init(&pqi);
        w.writeU32(C_PQ_INNER_DATA) catch return error.RsaPad;
        w.writeBytes(pq_buf[0..pq_len]) catch return error.RsaPad;
        w.writeBytes(pbytes[0..pl]) catch return error.RsaPad;
        w.writeBytes(qbytes[0..ql]) catch return error.RsaPad;
        w.writeInt128(nonce) catch return error.RsaPad;
        w.writeInt128(server_nonce) catch return error.RsaPad;
        w.writeInt256(new_nonce) catch return error.RsaPad;
        // Legacy RSA (SHA1(data)++data++pad) — the scheme Telethon uses with the
        // plain p_q_inner_data and that production accepts. (RSA_PAD is kept in
        // rsa_pad.zig for the _dc/temp constructors we may add later.)
        const enc = rsa.rsaEncryptLegacy(w.written(), chosen_key, fill) catch return error.RsaPad;
        if (!rng_ok) return error.Rng;
        break :blk enc;
    };

    {
        var dhreq: [384]u8 = undefined;
        var w = tl.Writer.init(&dhreq);
        w.writeU32(C_REQ_DH_PARAMS) catch return error.Send;
        w.writeInt128(nonce) catch return error.Send;
        w.writeInt128(server_nonce) catch return error.Send;
        w.writeBytes(pbytes[0..pl]) catch return error.Send;
        w.writeBytes(qbytes[0..ql]) catch return error.Send;
        w.writeLong(chosen_fp) catch return error.Send;
        w.writeBytes(&encrypted_data) catch return error.Send;
        try sendPlain(conn, w.written());
    }
    log("[auth] -> req_DH_params\n");

    var rbuf2: [1024]u8 = undefined;
    const sdh = try recvPlain(conn, &rbuf2, log);

    var enc_answer: [1024]u8 = undefined;
    var enc_len: usize = 0;
    {
        var r = tl.Reader.init(sdh);
        const ctor = r.readU32() catch return error.BadServerDH;
        if (ctor == C_SERVER_DH_FAIL) return error.ServerDHFail;
        if (ctor != C_SERVER_DH_OK) return error.BadServerDH;
        if (!eql16(r.readInt128() catch return error.BadServerDH, nonce)) return error.NonceMismatch;
        if (!eql16(r.readInt128() catch return error.BadServerDH, server_nonce)) return error.NonceMismatch;
        const ea = r.readBytes() catch return error.BadServerDH;
        if (ea.len == 0 or ea.len % 16 != 0 or ea.len > enc_answer.len) return error.BadServerDH;
        @memcpy(enc_answer[0..ea.len], ea);
        enc_len = ea.len;
    }
    log("[auth] <- server_DH_params_ok\n");

    // decrypt the answer with the temp AES key derived from the nonces
    const taes = kdf.tmpAesKeyIv(new_nonce, server_nonce);
    ige.decrypt(taes.key, taes.iv, enc_answer[0..enc_len]) catch return error.BadServerDH;

    var g_val: i32 = 0;
    var dh_prime: [256]u8 = undefined;
    var g_a: [256]u8 = undefined;
    var srv_time: i32 = 0;
    {
        const answer_hash = enc_answer[0..20].*;
        var r = tl.Reader.init(enc_answer[20..enc_len]);
        if ((r.readU32() catch return error.BadServerDH) != C_SERVER_DH_INNER) return error.BadServerDH;
        if (!eql16(r.readInt128() catch return error.BadServerDH, nonce)) return error.NonceMismatch;
        if (!eql16(r.readInt128() catch return error.BadServerDH, server_nonce)) return error.NonceMismatch;
        g_val = r.readInt() catch return error.BadServerDH;
        const dp = r.readBytes() catch return error.BadServerDH;
        const ga = r.readBytes() catch return error.BadServerDH;
        srv_time = r.readInt() catch return error.BadServerDH;
        if (dp.len != 256 or ga.len != 256) return error.BadServerDH;
        @memcpy(dh_prime[0..], dp);
        @memcpy(g_a[0..], ga);

        // SHA1(answer) must equal the 20 bytes prepended before encryption
        const answer = enc_answer[20 .. 20 + r.pos];
        var h: [20]u8 = undefined;
        Sha1.hash(answer, &h, .{});
        if (!std.mem.eql(u8, &answer_hash, &h)) return error.BadServerDH;
    }
    log("[auth] server_DH_inner_data parsed (hash OK)\n");

    // DH parameter sanity (mandatory bounds). TODO hardening: verify dh_prime
    // is a safe prime and apply the 2^2048-64 bound recommended by the spec.
    if (g_val < 2 or g_val > 7) return error.DHRange;
    if (dh_prime[0] < 0x80) return error.DHRange; // 2^2047 < dh_prime
    if (!dh.dhValueOk(g_a, dh_prime)) return error.DHRange;

    // ============ Round 3: set_client_DH_params -> dh_gen_ok ============
    var b_rand: [256]u8 = undefined;
    fill(&b_rand);
    if (!rng_ok) return error.Rng;

    const g_b = dh.powModP(dh.gBytes(@intCast(g_val)), &b_rand, dh_prime) catch return error.BadServerDH;
    if (!dh.dhValueOk(g_b, dh_prime)) return error.DHRange;
    const auth_key = dh.powModP(g_a, &b_rand, dh_prime) catch return error.BadServerDH;

    // client_DH_inner_data#6643b654, then AES-IGE(SHA1(data) ++ data ++ rndpad)
    var enc_in: [512]u8 = undefined;
    var enc_total: usize = 0;
    {
        var cdi: [320]u8 = undefined;
        var w = tl.Writer.init(&cdi);
        w.writeU32(C_CLIENT_DH_INNER) catch return error.Send;
        w.writeInt128(nonce) catch return error.Send;
        w.writeInt128(server_nonce) catch return error.Send;
        w.writeLong(0) catch return error.Send; // retry_id = 0 (first attempt)
        w.writeBytes(&g_b) catch return error.Send;
        const data = w.written();

        Sha1.hash(data, enc_in[0..20], .{});
        @memcpy(enc_in[20 .. 20 + data.len], data);
        var total = 20 + data.len;
        const pad = (16 - (total % 16)) % 16;
        fill(enc_in[total .. total + pad]);
        if (!rng_ok) return error.Rng;
        total += pad;
        ige.encrypt(taes.key, taes.iv, enc_in[0..total]) catch return error.BadServerDH;
        enc_total = total;
    }

    {
        var scd: [512]u8 = undefined;
        var w = tl.Writer.init(&scd);
        w.writeU32(C_SET_CLIENT_DH) catch return error.Send;
        w.writeInt128(nonce) catch return error.Send;
        w.writeInt128(server_nonce) catch return error.Send;
        w.writeBytes(enc_in[0..enc_total]) catch return error.Send;
        try sendPlain(conn, w.written());
    }
    log("[auth] -> set_client_DH_params\n");

    var rbuf3: [256]u8 = undefined;
    const gen = try recvPlain(conn, &rbuf3, log);
    {
        var r = tl.Reader.init(gen);
        const ctor = r.readU32() catch return error.BadDhGen;
        if (ctor == C_DH_GEN_RETRY) return error.DhGenRetry;
        if (ctor == C_DH_GEN_FAIL) return error.DhGenFail;
        if (ctor != C_DH_GEN_OK) return error.BadDhGen;
        if (!eql16(r.readInt128() catch return error.BadDhGen, nonce)) return error.NonceMismatch;
        if (!eql16(r.readInt128() catch return error.BadDhGen, server_nonce)) return error.NonceMismatch;
        const nnh = r.readInt128() catch return error.BadDhGen;
        const expect = kdf.newNonceHash(new_nonce, 1, kdf.authKeyAuxHash(auth_key));
        if (!eql16(nnh, expect)) return error.NonceHashMismatch;
    }
    log("[auth] <- dh_gen_ok (new_nonce_hash1 OK)\n");

    var result: Auth = .{
        .auth_key = auth_key,
        .auth_key_id = kdf.authKeyId(auth_key),
        .server_salt = undefined,
        .g = g_val,
        .server_time = srv_time,
    };
    for (0..8) |i| result.server_salt[i] = new_nonce[i] ^ server_nonce[i];
    logHex(log, "[auth] auth_key_id = ", &result.auth_key_id);
    return result;
}
