//! MTProto 2.0 "secure message" layer — the encrypted envelope every message
//! rides in once the Stage-1 handshake has established a permanent auth_key.
//!
//! On the wire each message is:
//!     auth_key_id(8) ++ msg_key(16) ++ AES256_IGE(plaintext)
//! where the encrypted plaintext is
//!     server_salt(8) ++ session_id(8) ++ msg_id(8) ++ seq_no(4)
//!         ++ length(4) ++ message_data ++ padding(12..1024)
//! and the authenticator / key schedule are
//!     msg_key = SHA256( auth_key[88+x : 120+x] ++ plaintext )[8:24]
//!     sha_a   = SHA256( msg_key ++ auth_key[x : x+36] )
//!     sha_b   = SHA256( auth_key[40+x : 76+x] ++ msg_key )
//!     aes_key = sha_a[0:8] ++ sha_b[8:24] ++ sha_a[24:32]
//!     aes_iv  = sha_b[0:8] ++ sha_a[8:24] ++ sha_b[24:32]
//! with x = 0 for client->server and x = 8 for server->client.
//!
//! This file is PURE (std + tl + ige only) so the whole thing is `zig test`-able
//! natively off-target. The byte-ranges below are pinned to an independent
//! Python SHA256 oracle, a full encrypt->decrypt round-trip, and tamper/identity
//! rejection tests. The live socket glue lives in the app driver.

const std = @import("std");
const tl = @import("tl.zig");
const ige = @import("ige.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const RandomFn = *const fn (buf: []u8) void;

pub const Error = error{
    TooBig,
    BadAuthKeyId,
    BadMsgKey,
    Malformed,
};

// --- service / container constructor ids (long-stable MTProto values) ---
pub const C_PING: u32 = 0x7abe77ec;
pub const C_PONG: u32 = 0x347773c5;
pub const C_MSG_CONTAINER: u32 = 0x73f1f8dc;
pub const C_NEW_SESSION: u32 = 0x9ec20908;
pub const C_MSGS_ACK: u32 = 0x62d6b459;
pub const C_BAD_SERVER_SALT: u32 = 0xedab447b;
pub const C_BAD_MSG_NOTIFY: u32 = 0xa7eff811; // CRC32-verified (a7eddc27 is a mis-propagated myth)
pub const C_RPC_RESULT: u32 = 0xf35c6d01;
pub const C_GZIP_PACKED: u32 = 0x3072cfa1;

const AesKeyIv = struct { key: [32]u8, iv: [32]u8 };

/// MTProto 2.0 key/iv schedule. x = 0 (client->server) or 8 (server->client).
fn deriveKeyIv(auth_key: *const [256]u8, msg_key: [16]u8, x: usize) AesKeyIv {
    var a: [32]u8 = undefined; // SHA256(msg_key ++ auth_key[x : x+36])
    var b: [32]u8 = undefined; // SHA256(auth_key[40+x : 76+x] ++ msg_key)
    {
        var h = Sha256.init(.{});
        h.update(&msg_key);
        h.update(auth_key[x .. x + 36]);
        h.final(&a);
    }
    {
        var h = Sha256.init(.{});
        h.update(auth_key[40 + x .. 76 + x]);
        h.update(&msg_key);
        h.final(&b);
    }
    var r: AesKeyIv = undefined;
    @memcpy(r.key[0..8], a[0..8]);
    @memcpy(r.key[8..24], b[8..24]);
    @memcpy(r.key[24..32], a[24..32]);
    @memcpy(r.iv[0..8], b[0..8]);
    @memcpy(r.iv[8..24], a[8..24]);
    @memcpy(r.iv[24..32], b[24..32]);
    return r;
}

/// msg_key = SHA256( auth_key[88+x : 120+x] ++ plaintext )[8:24].
fn computeMsgKey(auth_key: *const [256]u8, plaintext: []const u8, x: usize) [16]u8 {
    var full: [32]u8 = undefined;
    var h = Sha256.init(.{});
    h.update(auth_key[88 + x .. 120 + x]);
    h.update(plaintext);
    h.final(&full);
    return full[8..24].*;
}

/// Build one encrypted client->server datagram (x = 0) into `out`:
///     out = auth_key_id ++ msg_key ++ AES256_IGE(plaintext)
/// `data` is the bare TL-serialized object (e.g. a ping). Padding is the
/// minimal 12..27 bytes that block-aligns the plaintext; `fill` supplies it
/// (kernel CSPRNG live, a deterministic pattern under test). Returns the
/// datagram as a slice of `out`.
pub fn buildEncrypted(
    out: []u8,
    auth_key: *const [256]u8,
    auth_key_id: [8]u8,
    salt: [8]u8,
    session_id: [8]u8,
    msg_id: u64,
    seq_no: u32,
    data: []const u8,
    fill: RandomFn,
) Error![]const u8 {
    const PT_MAX = 1024;
    if (data.len + 64 > PT_MAX) return error.TooBig;

    var pt: [PT_MAX]u8 = undefined;
    var w = tl.Writer.init(&pt);
    w.writeRaw(&salt) catch return error.TooBig;
    w.writeRaw(&session_id) catch return error.TooBig;
    w.writeLong(msg_id) catch return error.TooBig;
    w.writeU32(seq_no) catch return error.TooBig;
    w.writeU32(@intCast(data.len)) catch return error.TooBig;
    w.writeRaw(data) catch return error.TooBig;

    // padding: 12..27 bytes so (data.len + pad) % 16 == 0. The 32-byte header is
    // itself a multiple of 16, so this block-aligns the whole plaintext.
    const pad: usize = 12 + ((16 - ((data.len + 12) % 16)) % 16);
    var padbuf: [27]u8 = undefined;
    fill(padbuf[0..pad]);
    w.writeRaw(padbuf[0..pad]) catch return error.TooBig;

    const plaintext = pt[0..w.pos]; // a multiple of 16
    const msg_key = computeMsgKey(auth_key, plaintext, 0);
    const kiv = deriveKeyIv(auth_key, msg_key, 0);
    ige.encrypt(kiv.key, kiv.iv, plaintext) catch return error.TooBig;

    const total = 24 + plaintext.len;
    if (out.len < total) return error.TooBig;
    @memcpy(out[0..8], &auth_key_id);
    @memcpy(out[8..24], &msg_key);
    @memcpy(out[24..total], plaintext);
    return out[0..total];
}

pub const Decoded = struct {
    msg_id: u64,
    seq_no: u32,
    body: []const u8, // slice into the caller's pt_out buffer
};

/// Decrypt and authenticate one datagram into `pt_out`. x = 8 for real server
/// replies (the tests round-trip with x = 0). Rejects a wrong auth_key_id and a
/// failed msg_key recomputation — the MTProto 2.0 integrity check — before
/// returning the inner header + body.
pub fn decryptInto(
    pt_out: []u8,
    auth_key: *const [256]u8,
    expect_id: [8]u8,
    datagram: []const u8,
    x: usize,
) Error!Decoded {
    if (datagram.len < 24 + 16) return error.Malformed;
    if (!std.mem.eql(u8, datagram[0..8], &expect_id)) return error.BadAuthKeyId;
    const msg_key: [16]u8 = datagram[8..24].*;
    const cipher = datagram[24..];
    if (cipher.len % 16 != 0 or cipher.len > pt_out.len) return error.Malformed;

    const kiv = deriveKeyIv(auth_key, msg_key, x);
    @memcpy(pt_out[0..cipher.len], cipher);
    ige.decrypt(kiv.key, kiv.iv, pt_out[0..cipher.len]) catch return error.Malformed;
    const plaintext = pt_out[0..cipher.len];

    const check = computeMsgKey(auth_key, plaintext, x);
    if (!std.mem.eql(u8, &check, &msg_key)) return error.BadMsgKey;

    var r = tl.Reader.init(plaintext);
    _ = r.readRaw(8) catch return error.Malformed; // server_salt
    _ = r.readRaw(8) catch return error.Malformed; // session_id
    const mid = r.readLong() catch return error.Malformed;
    const seq = r.readU32() catch return error.Malformed;
    const blen = r.readU32() catch return error.Malformed;
    if (blen > plaintext.len) return error.Malformed;
    const body = r.readRaw(blen) catch return error.Malformed;
    return .{ .msg_id = mid, .seq_no = seq, .body = body };
}

/// What a (possibly containerised) server reply told us. The live driver reacts:
/// match the pong, adopt a fresh salt, or resend on a salt rejection. Pure — no
/// I/O, no logging.
pub const Scan = struct {
    pong_id: ?u64 = null,
    new_salt: ?[8]u8 = null, // from new_session_created
    bad_salt: ?[8]u8 = null, // from bad_server_salt -> caller should resend
    bad_msg_code: ?i32 = null,
    rpc_req_id: ?u64 = null, // req_msg_id this rpc_result answers
    rpc_result: ?[]const u8 = null, // the boxed result object (slice into body)
};

/// Walk a decrypted message body (a single object or a msg_container) and pull
/// out the things the handshake-probe cares about.
pub fn scanBody(body: []const u8) Error!Scan {
    var out: Scan = .{};
    try scanInto(body, &out);
    return out;
}

fn scanInto(body: []const u8, out: *Scan) Error!void {
    var r = tl.Reader.init(body);
    const ctor = r.readU32() catch return error.Malformed;
    switch (ctor) {
        C_MSG_CONTAINER => {
            // bare vector: count:int then `count` × (msg_id:long seqno:int bytes:int body)
            const count = r.readU32() catch return error.Malformed;
            var i: u32 = 0;
            while (i < count) : (i += 1) {
                _ = r.readLong() catch return error.Malformed; // inner msg_id
                _ = r.readU32() catch return error.Malformed; // inner seqno
                const blen = r.readU32() catch return error.Malformed; // inner bytes
                const inner = r.readRaw(blen) catch return error.Malformed;
                try scanInto(inner, out);
            }
        },
        C_PONG => {
            _ = r.readLong() catch return error.Malformed; // msg_id of our ping
            out.pong_id = r.readLong() catch return error.Malformed;
        },
        C_NEW_SESSION => {
            _ = r.readLong() catch return error.Malformed; // first_msg_id
            _ = r.readLong() catch return error.Malformed; // unique_id
            const s = r.readRaw(8) catch return error.Malformed; // server_salt
            out.new_salt = s[0..8].*;
        },
        C_BAD_SERVER_SALT => {
            _ = r.readLong() catch return error.Malformed; // bad_msg_id
            _ = r.readU32() catch return error.Malformed; // bad_msg_seqno
            _ = r.readU32() catch return error.Malformed; // error_code
            const s = r.readRaw(8) catch return error.Malformed; // new_server_salt
            out.bad_salt = s[0..8].*;
        },
        C_BAD_MSG_NOTIFY => {
            _ = r.readLong() catch return error.Malformed; // bad_msg_id
            _ = r.readU32() catch return error.Malformed; // bad_msg_seqno
            out.bad_msg_code = r.readInt() catch return error.Malformed;
        },
        C_RPC_RESULT => {
            // rpc_result#f35c6d01 req_msg_id:long result:Object — the remaining
            // bytes ARE the boxed result object (auth.sentCode / rpc_error / ...).
            out.rpc_req_id = r.readLong() catch return error.Malformed;
            out.rpc_result = r.buf[r.pos..];
        },
        else => {}, // msgs_ack, gzip, ... not relevant here
    }
}

// =====================================================================
// Tests — zig test lib/mtproto/session.zig
//
// The KDF/msg_key expectations are produced by an independent Python SHA256
// implementation (stdlib only) over the sample auth_key already pinned in
// kdf.zig; the round-trip/tamper tests exercise the AES-IGE integration and the
// integrity check end to end.

fn hexN(comptime n: usize, comptime s: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

const SAMPLE_AK = hexN(256, "83CBD31C0303361FF1C29437A77CBA749C84F28A118646038C7EDD29EF718A1F" ++
    "6A493047D476A6E678D97A4A5CC7990CEA552D68E109869E5BFC86570049CD8F" ++
    "2EB4BA10B6C4123FB8A977774B4C5185B5C96AF7BD7A71DB78E6E6148CED2048" ++
    "869A21B8ED7FBA7F6F2E7722BFA28447AB84A245CB0E6D01261191B753191E74" ++
    "4DCFDA522D50167832EE4D5EE90AAA6F31821248F0F06BF5692EF604CFC4316C" ++
    "EDE078F71E17BCEBBE388589E6707AF5BA26E8DD063BB116C4B4E7BEF3B462C3" ++
    "350D0376D42F95D353E46BE4C378D2A60141A2339641F8B712EB3ECFB42B7F26" ++
    "F69E9BB15373E0AC4BE266E1681859DDAAB8CD7D877BB847D2A8BD068A784943");

fn expectHex(actual: []const u8, comptime hexstr: []const u8) !void {
    const exp = hexN(hexstr.len / 2, hexstr);
    try std.testing.expectEqualSlices(u8, &exp, actual);
}

// deterministic padding 0xC0, 0xC1, ... — matches the Python oracle.
fn detFill(buf: []u8) void {
    for (buf, 0..) |*b, i| b.* = @intCast((0xC0 + i) & 0xFF);
}

test "MTProto 2.0 KDF byte-ranges match the independent SHA256 oracle" {
    var mk: [16]u8 = undefined;
    for (0..16) |i| mk[i] = @intCast(i); // 00 01 .. 0f
    const k0 = deriveKeyIv(&SAMPLE_AK, mk, 0);
    try expectHex(&k0.key, "943918b0d89b8f7db4180c5b7356fe8d54b71c5892925952e3cdeb891ade296d");
    try expectHex(&k0.iv, "4ea855e28f8a0d988f6afc5569a9aa1c7546a87064f8a38dbf12cd5896832e8f");
    const k8 = deriveKeyIv(&SAMPLE_AK, mk, 8);
    try expectHex(&k8.key, "d8dae6bc729aff51e9785ab788082460390f34e440bd8593dae8eff511b824c9");
    try expectHex(&k8.iv, "9bd2f8e2800fb39da05675004de013db491b3ff29fb89a6cae06a2f43369981f");
}

test "secure-message KAT — msg_key + key/iv over a fixed plaintext (x=0)" {
    const akid = [_]u8{0xAA} ** 8;
    const data = hexN(12, "ec77be7aefcdab8967452301"); // ping ctor (LE) + ping_id (LE)
    var out: [256]u8 = undefined;
    const dg = try buildEncrypted(&out, &SAMPLE_AK, akid, hexN(8, "0102030405060708"), hexN(8, "1122334455667788"), 0x5F3A1B2C12345670, 1, &data, detFill);
    try std.testing.expectEqual(@as(usize, 8 + 16 + 64), dg.len);
    try expectHex(dg[8..24], "7048aa9afb3ef6e1c64d01eb3e936524"); // msg_key from the oracle
    const mk: [16]u8 = dg[8..24].*;
    const kiv = deriveKeyIv(&SAMPLE_AK, mk, 0);
    try expectHex(&kiv.key, "1cfe87926fa291cf812aadd6827e4de9c35ff4e72d9285c26fd5277e0b51c2b6");
    try expectHex(&kiv.iv, "a0cb44ef7aa2004dff9f270d004e4b123cec085fec885832affe1ee882a1ccbe");
}

test "encrypt then decrypt round-trips and authenticates (msg_key verified)" {
    const akid = hexN(8, "1122334455667788");
    const data = hexN(12, "ec77be7aefcdab8967452301");
    var out: [256]u8 = undefined;
    const dg = try buildEncrypted(&out, &SAMPLE_AK, akid, hexN(8, "a1a2a3a4a5a6a7a8"), hexN(8, "b1b2b3b4b5b6b7b8"), 0x5F3A1B2C12345670, 1, &data, detFill);
    var pt: [256]u8 = undefined;
    const dec = try decryptInto(&pt, &SAMPLE_AK, akid, dg, 0); // our own client msg -> x=0
    try std.testing.expectEqual(@as(u64, 0x5F3A1B2C12345670), dec.msg_id);
    try std.testing.expectEqual(@as(u32, 1), dec.seq_no);
    try std.testing.expectEqualSlices(u8, &data, dec.body);
}

test "a tampered ciphertext byte fails the msg_key integrity check" {
    const akid = hexN(8, "1122334455667788");
    const data = hexN(12, "ec77be7aefcdab8967452301");
    var out: [256]u8 = undefined;
    const dg = try buildEncrypted(&out, &SAMPLE_AK, akid, hexN(8, "0001020304050607"), hexN(8, "08090a0b0c0d0e0f"), 0x5F3A1B2C12345670, 1, &data, detFill);
    out[40] ^= 0x01; // flip a byte inside the ciphertext region
    var pt: [256]u8 = undefined;
    try std.testing.expectError(error.BadMsgKey, decryptInto(&pt, &SAMPLE_AK, akid, dg, 0));
}

test "a wrong auth_key_id is rejected before any decryption" {
    const akid = hexN(8, "1122334455667788");
    const wrong = hexN(8, "9999999999999999");
    const data = hexN(12, "ec77be7aefcdab8967452301");
    var out: [256]u8 = undefined;
    const dg = try buildEncrypted(&out, &SAMPLE_AK, akid, hexN(8, "0001020304050607"), hexN(8, "08090a0b0c0d0e0f"), 0x5F3A1B2C12345670, 1, &data, detFill);
    var pt: [256]u8 = undefined;
    try std.testing.expectError(error.BadAuthKeyId, decryptInto(&pt, &SAMPLE_AK, wrong, dg, 0));
}

test "scanBody walks a msg_container and extracts pong_id + the new salt" {
    // inner 1: new_session_created
    const salt8 = hexN(8, "00aa00bb00cc00dd");
    var o1: [64]u8 = undefined;
    var w1 = tl.Writer.init(&o1);
    w1.writeU32(C_NEW_SESSION) catch unreachable;
    w1.writeLong(0x1111111111111110) catch unreachable;
    w1.writeLong(0x2222222222222222) catch unreachable;
    w1.writeRaw(&salt8) catch unreachable;

    // inner 2: msgs_ack (boxed Vector<long>) — must be ignored
    var o2: [64]u8 = undefined;
    var w2 = tl.Writer.init(&o2);
    w2.writeU32(C_MSGS_ACK) catch unreachable;
    w2.writeU32(tl.VECTOR_CTOR) catch unreachable;
    w2.writeU32(1) catch unreachable;
    w2.writeLong(0x1111111111111110) catch unreachable;

    // inner 3: pong
    var o3: [32]u8 = undefined;
    var w3 = tl.Writer.init(&o3);
    w3.writeU32(C_PONG) catch unreachable;
    w3.writeLong(0x1111111111111110) catch unreachable; // msg_id of our ping
    w3.writeLong(0x0123456789ABCDEF) catch unreachable; // ping_id

    const inners = [_][]const u8{ w1.written(), w2.written(), w3.written() };
    var buf: [256]u8 = undefined;
    var w = tl.Writer.init(&buf);
    w.writeU32(C_MSG_CONTAINER) catch unreachable;
    w.writeU32(@intCast(inners.len)) catch unreachable;
    var idc: u64 = 0x7000000000000000;
    for (inners) |obj| {
        w.writeLong(idc) catch unreachable;
        idc += 4;
        w.writeU32(0) catch unreachable; // seqno
        w.writeU32(@intCast(obj.len)) catch unreachable; // bytes
        w.writeRaw(obj) catch unreachable;
    }

    const scan = try scanBody(w.written());
    try std.testing.expectEqual(@as(?u64, 0x0123456789ABCDEF), scan.pong_id);
    try std.testing.expect(scan.new_salt != null);
    try expectHex(&scan.new_salt.?, "00aa00bb00cc00dd");
    try std.testing.expect(scan.bad_salt == null);
}

test "scanBody surfaces an rpc_result payload (req_msg_id + boxed result object)" {
    var buf: [64]u8 = undefined;
    var w = tl.Writer.init(&buf);
    w.writeU32(C_RPC_RESULT) catch unreachable;
    w.writeLong(0x0102030405060708) catch unreachable; // req_msg_id
    w.writeU32(0xdeadbeef) catch unreachable; // (stand-in) result ctor
    w.writeU32(0x11223344) catch unreachable; // result payload
    const scan = try scanBody(w.written());
    try std.testing.expectEqual(@as(?u64, 0x0102030405060708), scan.rpc_req_id);
    try std.testing.expect(scan.rpc_result != null);
    try std.testing.expectEqual(@as(usize, 8), scan.rpc_result.?.len);
    try std.testing.expectEqual(@as(u32, 0xdeadbeef), std.mem.readInt(u32, scan.rpc_result.?[0..4], .little));
}
