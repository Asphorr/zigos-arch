//! Telegram production server RSA public keys, with self-verifying fingerprints.
//!
//! A key's MTProto fingerprint is the low 64 bits of
//!     SHA1( TL_bytes(n) ++ TL_bytes(e) )
//! read as a little-endian int64 — exactly the `long` the server lists in
//! resPQ's fingerprint vector. The test at the bottom recomputes the
//! fingerprint of the embedded modulus and asserts it equals the well-known
//! 0xc3b42b026ce86b21, so a transcription slip in the modulus cannot pass.

const std = @import("std");
const tl = @import("tl.zig");
const rsa = @import("rsa_pad.zig");
const Sha1 = std.crypto.hash.Sha1;

pub const PublicKey = rsa.PublicKey;

fn parseHex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

/// Classic Telegram public key — fingerprint 0xc3b42b026ce86b21.
/// Decoded from the canonical PKCS#1 PEM via `openssl rsa -RSAPublicKey_in
/// -modulus` (pyrogram and Telethon ship the byte-identical PEM; an
/// independent SHA1 oracle reproduced the fingerprint before this landed).
pub const classic = PublicKey{
    .n = parseHex(
        "C150023E2F70DB7985DED064759CFECF0AF328E69A41DAF4D6F01B538135A6F9" ++
        "1F8F8B2A0EC9BA9720CE352EFCF6C5680FFC424BD634864902DE0B4BD6D49F4E" ++
        "580230E3AE97D95C8B19442B3C0A10D8F5633FECEDD6926A7F6DAB0DDB7D457F" ++
        "9EA81B8465FCD6FFFEED114011DF91C059CAEDAF97625F6C96ECC74725556934" ++
        "EF781D866B34F011FCE4D835A090196E9A5F0E4449AF7EB697DDB9076494CA5F" ++
        "81104A305B6DD27665722C46B60E5DF680FB16B210607EF217652E60236C255F" ++
        "6A28315F4083A96791D7214BF64C1DF4FD0DB1944FB26A2A57031B32EEE64AD1" ++
        "5A8BA68885CDE74A5BFC920F6ABF59BA5C75506373E7130F9042DA922179251F",
    ),
    .e = .{ 0x01, 0x00, 0x01 },
};

pub const CLASSIC_FP: u64 = 0xc3b42b026ce86b21;

/// Compute a key's MTProto fingerprint: low 64 bits of
/// SHA1(bytes(n) ++ bytes(e)) read little-endian. Mirrors what the server
/// publishes in resPQ.
pub fn fingerprint(key: PublicKey) u64 {
    var buf: [320]u8 = undefined; // bytes(256)=260 + bytes(3)=4 = 264
    var w = tl.Writer.init(&buf);
    w.writeBytes(&key.n) catch unreachable;
    w.writeBytes(&key.e) catch unreachable;
    var digest: [20]u8 = undefined;
    Sha1.hash(w.written(), &digest, .{});
    return std.mem.readInt(u64, digest[12..20], .little);
}

/// Pick a server key by the fingerprint the server offered, or null if we
/// don't carry it. (We currently carry only the classic key, which every
/// production DC still offers.)
pub fn byFingerprint(fp: u64) ?PublicKey {
    if (fp == CLASSIC_FP) return classic;
    return null;
}

test "classic key fingerprint self-verifies" {
    try std.testing.expectEqual(CLASSIC_FP, fingerprint(classic));
}
