// MTProto 2.0 RSA_PAD — the public-key step of the auth handshake.
//
// The client serializes `p_q_inner_data` (<=144 bytes) and must hand the
// server an RSA-encrypted blob built by this exact dance (per
// core.telegram.org, "Creating an Authorization Key"):
//
//   data_with_padding = data ++ random   (padded to 192 bytes)
//   data_pad_reversed = REVERSE(data_with_padding)
//   loop:
//     temp_key          = random 32 bytes
//     data_with_hash    = data_pad_reversed ++ SHA256(temp_key ++ data_with_padding)   (224 B)
//     aes_encrypted     = AES256_IGE(data_with_hash, key=temp_key, iv=0)               (224 B)
//     temp_key_xor      = temp_key XOR SHA256(aes_encrypted)                            (32 B)
//     key_aes_encrypted = temp_key_xor ++ aes_encrypted                                (256 B)
//     if key_aes_encrypted >= modulus: retry with a fresh temp_key
//   encrypted_data = RSA(key_aes_encrypted) = key_aes_encrypted ^ e mod n              (256 B)
//
// The ">= modulus" check falls out for free: ff.Fe.fromBytes rejects a
// non-canonical (>= n) value, which is exactly our retry signal.
//
// Randomness is injected (a fill callback) so the whole module stays pure
// and `zig test`-able; the live client passes the kernel CSPRNG.

const std = @import("std");
const ige = @import("ige.zig");
const ff = std.crypto.ff;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha1 = std.crypto.hash.Sha1;

const M = ff.Modulus(2048);

pub const RandomFn = *const fn (buf: []u8) void;

pub const PublicKey = struct {
    n: [256]u8, // big-endian RSA-2048 modulus
    e: [3]u8 = .{ 0x01, 0x00, 0x01 }, // 65537, big-endian
};

pub const MAX_DATA: usize = 144;

pub const Error = error{ DataTooLong, BadKey, RsaFailed };

pub fn rsaPadEncrypt(data: []const u8, key: PublicKey, fill: RandomFn) Error![256]u8 {
    if (data.len > MAX_DATA) return error.DataTooLong;

    const m = M.fromBytes(&key.n, .big) catch return error.BadKey;

    // data_with_padding (192) = data ++ random tail.
    var data_with_padding: [192]u8 = undefined;
    @memcpy(data_with_padding[0..data.len], data);
    fill(data_with_padding[data.len..]);

    // data_pad_reversed = REVERSE(data_with_padding).
    var data_pad_reversed: [192]u8 = undefined;
    for (0..192) |i| data_pad_reversed[i] = data_with_padding[191 - i];

    const zero_iv = [_]u8{0} ** 32;

    var attempt: usize = 0;
    while (attempt < 256) : (attempt += 1) {
        var temp_key: [32]u8 = undefined;
        fill(&temp_key);

        // data_with_hash (224) = data_pad_reversed ++ SHA256(temp_key ++ data_with_padding).
        var data_with_hash: [224]u8 = undefined;
        @memcpy(data_with_hash[0..192], &data_pad_reversed);
        {
            var h = Sha256.init(.{});
            h.update(&temp_key);
            h.update(&data_with_padding);
            var digest: [32]u8 = undefined;
            h.final(&digest);
            @memcpy(data_with_hash[192..224], &digest);
        }

        // aes_encrypted = AES256_IGE(data_with_hash, temp_key, iv=0).
        var aes_encrypted: [224]u8 = data_with_hash;
        ige.encrypt(temp_key, zero_iv, &aes_encrypted) catch return error.RsaFailed;

        // temp_key_xor = temp_key XOR SHA256(aes_encrypted).
        var sha_aes: [32]u8 = undefined;
        Sha256.hash(&aes_encrypted, &sha_aes, .{});
        var key_aes_encrypted: [256]u8 = undefined;
        for (0..32) |i| key_aes_encrypted[i] = temp_key[i] ^ sha_aes[i];
        @memcpy(key_aes_encrypted[32..256], &aes_encrypted);

        // Reject (>= modulus) and retry; otherwise RSA-encrypt.
        const base = M.Fe.fromBytes(m, &key_aes_encrypted, .big) catch |e| switch (e) {
            error.NonCanonical => continue,
            else => return error.RsaFailed,
        };
        const res = m.powWithEncodedPublicExponent(base, &key.e, .big) catch return error.RsaFailed;
        var out: [256]u8 = undefined;
        res.toBytes(&out, .big) catch return error.RsaFailed;
        return out;
    }
    return error.RsaFailed;
}

/// Legacy RSA step (MTProto 1.0 / "old" scheme) — still accepted by production
/// and exactly what Telethon sends with the plain p_q_inner_data:
///   encrypted_data = RSA( SHA1(data) ++ data ++ random ),
/// the inner block padded to exactly 255 bytes, so as a 2040-bit big-endian
/// integer it is always < the 2048-bit modulus (no >= modulus retry needed).
pub fn rsaEncryptLegacy(data: []const u8, key: PublicKey, fill: RandomFn) Error![256]u8 {
    if (data.len > 235) return error.DataTooLong; // 20(SHA1) + data + pad must fit 255
    const m = M.fromBytes(&key.n, .big) catch return error.BadKey;

    // buf[0] = 0 guarantees value < modulus; the 255-byte payload lives in [1..256].
    var buf = [_]u8{0} ** 256;
    Sha1.hash(data, buf[1..21], .{});
    @memcpy(buf[21 .. 21 + data.len], data);
    fill(buf[21 + data.len .. 256]);

    const base = M.Fe.fromBytes(m, &buf, .big) catch return error.RsaFailed;
    const res = m.powWithEncodedPublicExponent(base, &key.e, .big) catch return error.RsaFailed;
    var out: [256]u8 = undefined;
    res.toBytes(&out, .big) catch return error.RsaFailed;
    return out;
}

// =====================================================================
// Test — zig test lib/mtproto/rsa_pad.zig
//
// Throwaway RSA-2048 keypair generated with openssl. We encrypt, then
// play the SERVER: RSA-decrypt with d, peel the scheme apart, verify the
// embedded SHA256, and confirm the original data comes back. A full
// real-world inverse — far stronger than a self-consistency check.

const TEST_N_HEX =
    "bffcba04cf553af12d23b8bd851a72aa2532bd96d47c26c20ac45001302578d1" ++
    "07c5966ae243bad628c76bf783005eee4a034ff6d5e6a548611fb0822ed24e08" ++
    "d1bd52b20386d37d258f49df28a170605ad0f2be50d7ca9499d62936f2526ef8" ++
    "357c8b19ccda7ef2be9a8dfde99174970c1450f75235061cf2ab40e19547fed3" ++
    "d16ce88e7052178e39a556de308f7f8571226cf60076eb02f7fd3b8daf54e513" ++
    "89ee1e715a40ee1e5c0d07d0dce2148423390025729d4923af0ddb26f3f22a80" ++
    "8468f9c6791658f09aca8fe00943a78fe2147d18a65dd694fd3009519ac37766" ++
    "8761e345a1536abd2ea084f08e4ec17a4d03c9b0aa1abfc3ba6c5d0286e4344b";

const TEST_D_HEX =
    "0d33392eff7a62b5165f706247768c0fbac3045a0c7e04c42ead54bae02e9361" ++
    "fbe0cff8c559d6ccc6bcff65633271547cee415f3d51c0677b960c32c7395a78" ++
    "2cc3919dffb413727554a6c59b2b8e687196103a99a05ca35ef864990c8c3269" ++
    "0a7467b3fc6bc172bb3c312b16161428168287169a265f273a601ff3e2a9b291" ++
    "8b3aecaa36bc40183b62563f0711e0a8e225856ce2796c84dd054440d50eedac" ++
    "92d4aafce929a7c6224c2065380abeac074dd1a59155a2917daca44ab5634c40" ++
    "45deaede7de4e35f595e3b91e66daa2c7d3f314d59391844046b8b2e4b9186ad" ++
    "389df2fff6c11a4e40e62ef091701c4f1174044457fcf4e6fe5125e99283ea91";

var test_rng_state: u64 = 0x1234_5678_9abc_def0;
fn testFill(buf: []u8) void {
    for (buf) |*b| {
        var s = test_rng_state;
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        test_rng_state = s;
        b.* = @truncate(s);
    }
}

test "RSA_PAD round-trips through a real 2048-bit key (we play the server)" {
    var n: [256]u8 = undefined;
    _ = try std.fmt.hexToBytes(&n, TEST_N_HEX);
    var d: [256]u8 = [_]u8{0} ** 256;
    const dn = TEST_D_HEX.len / 2;
    _ = try std.fmt.hexToBytes(d[256 - dn ..], TEST_D_HEX);

    const key = PublicKey{ .n = n };
    const m = try M.fromBytes(&n, .big);
    const zero_iv = [_]u8{0} ** 32;

    for ([_]usize{ 1, 96, 144 }) |L| {
        var data: [144]u8 = undefined;
        for (0..L) |i| data[i] = @intCast((i * 7 + 3) & 0xFF);
        const data_slice = data[0..L];

        const cipher = try rsaPadEncrypt(data_slice, key, testFill);

        // ---- server side ----
        const base = try M.Fe.fromBytes(m, &cipher, .big);
        const res = try m.powWithEncodedExponent(base, &d, .big);
        var x: [256]u8 = undefined;
        try res.toBytes(&x, .big); // x == key_aes_encrypted

        const temp_key_xor = x[0..32].*;
        var aes_encrypted: [224]u8 = x[32..256].*;

        var sha_aes: [32]u8 = undefined;
        Sha256.hash(&aes_encrypted, &sha_aes, .{});
        var temp_key: [32]u8 = undefined;
        for (0..32) |i| temp_key[i] = temp_key_xor[i] ^ sha_aes[i];

        try ige.decrypt(temp_key, zero_iv, &aes_encrypted); // now == data_with_hash
        const data_with_hash = aes_encrypted;

        var data_with_padding: [192]u8 = undefined;
        for (0..192) |i| data_with_padding[i] = data_with_hash[191 - i]; // un-reverse

        var check: [32]u8 = undefined;
        var hh = Sha256.init(.{});
        hh.update(&temp_key);
        hh.update(&data_with_padding);
        hh.final(&check);
        try std.testing.expectEqualSlices(u8, data_with_hash[192..224], &check);
        try std.testing.expectEqualSlices(u8, data_slice, data_with_padding[0..L]);
    }
}

test "legacy RSA round-trips through a real 2048-bit key (we play the server)" {
    var n: [256]u8 = undefined;
    _ = try std.fmt.hexToBytes(&n, TEST_N_HEX);
    var d: [256]u8 = [_]u8{0} ** 256;
    const dn = TEST_D_HEX.len / 2;
    _ = try std.fmt.hexToBytes(d[256 - dn ..], TEST_D_HEX);

    const key = PublicKey{ .n = n };
    const m = try M.fromBytes(&n, .big);

    for ([_]usize{ 1, 96, 144 }) |L| {
        var data: [144]u8 = undefined;
        for (0..L) |i| data[i] = @intCast((i * 13 + 5) & 0xFF);
        const data_slice = data[0..L];

        const cipher = try rsaEncryptLegacy(data_slice, key, testFill);

        // server side: RSA-decrypt with d and peel SHA1 ++ data back out
        const base = try M.Fe.fromBytes(m, &cipher, .big);
        const res = try m.powWithEncodedExponent(base, &d, .big);
        var x: [256]u8 = undefined;
        try res.toBytes(&x, .big);

        try std.testing.expectEqual(@as(u8, 0), x[0]); // leading zero kept it < modulus
        var sha: [20]u8 = undefined;
        Sha1.hash(data_slice, &sha, .{});
        try std.testing.expectEqualSlices(u8, &sha, x[1..21]);
        try std.testing.expectEqualSlices(u8, data_slice, x[21 .. 21 + L]);
    }
}
