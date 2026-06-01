//! End-to-end KAT for the server_DH_params_ok unwrap step.
//!
//! Using our real KDF + AES-IGE + TL Reader, decrypt the official
//! core.telegram.org/mtproto/samples-auth_key encrypted_answer, parse
//! server_DH_inner_data, and verify the embedded SHA1(answer). This pins the
//! whole "unwrap the DH answer" path against real bytes, off-target — so the
//! only thing left untested before a live boot is the socket plumbing.

const std = @import("std");
const ige = @import("ige.zig");
const tl = @import("tl.zig");
const kdf = @import("kdf.zig");
const Sha1 = std.crypto.hash.Sha1;

fn hexN(comptime n: usize, comptime s: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "decrypt + parse server_DH_inner_data (official sample)" {
    const nonce = hexN(16, "79F0AFB50252E5FC96924BFCECDA4F05");
    const server_nonce = hexN(16, "801775A3EFBFD2701AA28AD727BE4646");
    const new_nonce = hexN(32, "264F835B0B7BDFF9C6ED6CF819FD6DF5DCD17E90D67ADD2C2C1E3775C7A6A0AC");

    const t = kdf.tmpAesKeyIv(new_nonce, server_nonce);

    var enc = hexN(592, "9A46DCE9D54DE42C5E4F0D19D776C8C1F318EB1AF8836500B5DA1B1A80D58038" ++
        "A554FEAF627E6DC4E4924943602D8E19488A6E38A0B81346257E4DB5BE6E9E00" ++
        "FE991FD6C56D618D3D0A2493202677AC7CF245846C1494F60D08E61B7FEA8BB7" ++
        "2DD8BA53F6CBF78F2B387757FE2E7F345A368ABBEC694EFDE066DC3D2375CF01" ++
        "0D1E1BF4351724B269E68B541409E07649FEEE1DF6DC5B3C18166879CC678767" ++
        "82D43EC9B79AF8ACF67868F4AB7DE4082603B670EC622B5DFBBB9E908FE02445" ++
        "93A4D22474316020CE0E76A5C6AD021D3989451E0B3E8EE48C355992DB90300B" ++
        "376B296E18BB470300C7DF14BFAE05A452583EAD93167941208BBB5AC8099F04" ++
        "94AA27D6C1A5B678AD12B19FB7D423BB4A29C0EB03169EC538211D82FEB50F20" ++
        "9652D00D3399986B3B0CA09CEB5E2FCCB49017FEE5F54930D9DE371172B3FF10" ++
        "80D733E5DD620B42DBB76A3E9C25B1B89AB8AA35C099322CA390E269D8818EA8" ++
        "722008DE537705B4071DA7DEF502FCD5A30D2026EA8A87A0F4915803A8271B66" ++
        "5690E96AABDFC0B479538AE61BA701EDFF14F7212370958ED41EC8E41E427C40" ++
        "7FBB0360565C1A6BDF285BC5120B11631B75803DFBF8AAEBDC47418A1F061747" ++
        "005ABA9314EE5E261C3E504EAE0ADAAC832B414BF6F7002982CE5B5AE2513761" ++
        "EE29FA1CBA090B9A39AACE2948A80E144DB2C622589D79FB42E3DAE491104E8A" ++
        "653DED7629CDE08B6C41E90E55B0EBCD4F1FC50FADDF4A7A9F6D711F0959DFEF" ++
        "04A744A6ADFD890B2AB405B9AD5F8E3F38928108F4CD0BA501A492FC463BC7BE" ++
        "8C506B5F7D24CC819A95929166B6E814");

    try ige.decrypt(t.key, t.iv, &enc);

    // plaintext = SHA1(answer) ++ answer ++ random padding
    const answer_hash = enc[0..20].*;
    var r = tl.Reader.init(enc[20..]);
    try std.testing.expectEqual(@as(u32, 0xb5890dba), try r.readU32()); // server_DH_inner_data
    try std.testing.expectEqual(nonce, try r.readInt128());
    try std.testing.expectEqual(server_nonce, try r.readInt128());
    const g = try r.readInt();
    const dh_prime = try r.readBytes();
    const g_a = try r.readBytes();
    _ = try r.readInt(); // server_time

    // The answer is exactly the bytes the Reader consumed; its SHA1 must match.
    const answer = enc[20 .. 20 + r.pos];
    var h: [20]u8 = undefined;
    Sha1.hash(answer, &h, .{});
    try std.testing.expectEqualSlices(u8, &answer_hash, &h);

    try std.testing.expectEqual(@as(i32, 3), g);
    try std.testing.expectEqual(@as(usize, 256), dh_prime.len);
    try std.testing.expectEqual(@as(usize, 256), g_a.len);
    try std.testing.expectEqualSlices(u8, &hexN(8, "C71CAEB9C6B1C904"), dh_prime[0..8]);
    try std.testing.expectEqualSlices(u8, &hexN(8, "236F6D779877A357"), g_a[0..8]);
}
