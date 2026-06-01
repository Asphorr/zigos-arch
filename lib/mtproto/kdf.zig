//! MTProto auth-handshake key derivations — all SHA1-based.
//!
//! These are the glue between the nonces exchanged in the clear and the
//! temporary AES-IGE key that unwraps server_DH_params_ok, plus the final
//! auth_key identifiers. Pure (std only) so they're `zig test`-able; the
//! tests below pin them to the official core.telegram.org sample values.

const std = @import("std");
const Sha1 = std.crypto.hash.Sha1;

pub const TmpAes = struct { key: [32]u8, iv: [32]u8 };

/// tmp_aes_key / tmp_aes_iv for AES-IGE over server_DH_params_ok.encrypted_answer:
///   key = SHA1(new_nonce + server_nonce) ++ SHA1(server_nonce + new_nonce)[0:12]
///   iv  = SHA1(server_nonce + new_nonce)[12:20] ++ SHA1(new_nonce + new_nonce) ++ new_nonce[0:4]
pub fn tmpAesKeyIv(new_nonce: [32]u8, server_nonce: [16]u8) TmpAes {
    var a: [20]u8 = undefined; // SHA1(new_nonce + server_nonce)
    var b: [20]u8 = undefined; // SHA1(server_nonce + new_nonce)
    var c: [20]u8 = undefined; // SHA1(new_nonce + new_nonce)
    {
        var h = Sha1.init(.{});
        h.update(&new_nonce);
        h.update(&server_nonce);
        h.final(&a);
    }
    {
        var h = Sha1.init(.{});
        h.update(&server_nonce);
        h.update(&new_nonce);
        h.final(&b);
    }
    {
        var h = Sha1.init(.{});
        h.update(&new_nonce);
        h.update(&new_nonce);
        h.final(&c);
    }
    var r: TmpAes = undefined;
    @memcpy(r.key[0..20], &a);
    @memcpy(r.key[20..32], b[0..12]);
    @memcpy(r.iv[0..8], b[12..20]);
    @memcpy(r.iv[8..28], &c);
    @memcpy(r.iv[28..32], new_nonce[0..4]);
    return r;
}

/// auth_key_id = low 64 bits of SHA1(auth_key) = SHA1(auth_key)[12:20].
pub fn authKeyId(auth_key: [256]u8) [8]u8 {
    var d: [20]u8 = undefined;
    Sha1.hash(&auth_key, &d, .{});
    return d[12..20].*;
}

/// auth_key_aux_hash = SHA1(auth_key)[0:8] — feeds new_nonce_hash{1,2,3}.
pub fn authKeyAuxHash(auth_key: [256]u8) [8]u8 {
    var d: [20]u8 = undefined;
    Sha1.hash(&auth_key, &d, .{});
    return d[0..8].*;
}

/// new_nonce_hash{n} = SHA1(new_nonce ++ [n] ++ aux_hash)[4:20]  (16 bytes).
/// n = 1 (dh_gen_ok), 2 (dh_gen_retry), 3 (dh_gen_fail). The server echoes
/// new_nonce_hash1 in dh_gen_ok; we recompute it to authenticate the reply.
pub fn newNonceHash(new_nonce: [32]u8, n: u8, aux_hash: [8]u8) [16]u8 {
    var h = Sha1.init(.{});
    h.update(&new_nonce);
    h.update(&[_]u8{n});
    h.update(&aux_hash);
    var d: [20]u8 = undefined;
    h.final(&d);
    return d[4..20].*;
}

// =====================================================================
// Tests — pinned to core.telegram.org/mtproto/samples-auth_key.

fn hexN(comptime n: usize, comptime s: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "tmp_aes_key / tmp_aes_iv match the official sample" {
    const new_nonce = hexN(32, "264F835B0B7BDFF9C6ED6CF819FD6DF5DCD17E90D67ADD2C2C1E3775C7A6A0AC");
    const server_nonce = hexN(16, "801775A3EFBFD2701AA28AD727BE4646");
    const t = tmpAesKeyIv(new_nonce, server_nonce);
    try std.testing.expectEqualSlices(u8, &hexN(32, "E68CA5ABA101FFCA0ADDA66303A57AFFAA2712FB16A7B8DAFC72C25E8A73A368"), &t.key);
    try std.testing.expectEqualSlices(u8, &hexN(32, "0A355D4431B9DDD91A51EFF3F7D340D64F0390C53F91DC53C331D43C264F835B"), &t.iv);
}

test "auth_key_id of the sample auth_key" {
    const ak = hexN(256, "83CBD31C0303361FF1C29437A77CBA749C84F28A118646038C7EDD29EF718A1F" ++
        "6A493047D476A6E678D97A4A5CC7990CEA552D68E109869E5BFC86570049CD8F" ++
        "2EB4BA10B6C4123FB8A977774B4C5185B5C96AF7BD7A71DB78E6E6148CED2048" ++
        "869A21B8ED7FBA7F6F2E7722BFA28447AB84A245CB0E6D01261191B753191E74" ++
        "4DCFDA522D50167832EE4D5EE90AAA6F31821248F0F06BF5692EF604CFC4316C" ++
        "EDE078F71E17BCEBBE388589E6707AF5BA26E8DD063BB116C4B4E7BEF3B462C3" ++
        "350D0376D42F95D353E46BE4C378D2A60141A2339641F8B712EB3ECFB42B7F26" ++
        "F69E9BB15373E0AC4BE266E1681859DDAAB8CD7D877BB847D2A8BD068A784943");
    try std.testing.expectEqualSlices(u8, &hexN(8, "0438720625F291F6"), &authKeyId(ak));
}
