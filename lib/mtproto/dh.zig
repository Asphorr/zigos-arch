//! Diffie-Hellman over the 2048-bit MTProto prime, plus the parameter sanity
//! checks the spec requires. Built on std.crypto.ff.Modulus(2048) — the same
//! constant-time bignum that powers our RSA step. Pure/`zig test`-able; the
//! test pins g_b and auth_key to the official sample.

const std = @import("std");
const ff = std.crypto.ff;
const M = ff.Modulus(2048);

pub const Error = error{ BadPrime, OutOfRange, PowFailed };

/// base^exp mod prime — all big-endian, 256 bytes. `base` must be < prime
/// (caller has usually validated this already; fromBytes enforces it too).
pub fn powModP(base: [256]u8, exp: []const u8, prime: [256]u8) Error![256]u8 {
    const m = M.fromBytes(&prime, .big) catch return error.BadPrime;
    const b = M.Fe.fromBytes(m, &base, .big) catch return error.OutOfRange;
    const r = m.powWithEncodedExponent(b, exp, .big) catch return error.PowFailed;
    var out: [256]u8 = undefined;
    r.toBytes(&out, .big) catch return error.PowFailed;
    return out;
}

/// A small generator g rendered as a 256-byte big-endian value.
pub fn gBytes(g: u32) [256]u8 {
    var out = [_]u8{0} ** 256;
    std.mem.writeInt(u32, out[252..256], g, .big);
    return out;
}

/// Mandatory check (core.telegram.org, "Creating an Authorization Key"):
/// a DH value must satisfy 1 < x < dh_prime - 1. Both `x` and `prime` are
/// big-endian, 256 bytes; we assume x < prime (guaranteed when x arrived via
/// ff.Fe.fromBytes). Returns false if x is 0, 1, or dh_prime-1.
pub fn dhValueOk(x: [256]u8, prime: [256]u8) bool {
    // x >= 2 ?
    var high_nonzero = false;
    for (x[0..255]) |byte| {
        if (byte != 0) {
            high_nonzero = true;
            break;
        }
    }
    if (!high_nonzero and x[255] < 2) return false; // x is 0 or 1

    // x <= prime-2  <=>  x != prime-1  (x < prime already established)
    var pm1 = prime;
    var i: usize = pm1.len;
    while (i > 0) {
        i -= 1;
        if (pm1[i] == 0) {
            pm1[i] = 0xFF;
        } else {
            pm1[i] -= 1;
            break;
        }
    }
    return !std.mem.eql(u8, &x, &pm1);
}

// =====================================================================
// Test — pinned to core.telegram.org/mtproto/samples-auth_key.

fn hex256(comptime s: []const u8) [256]u8 {
    var out: [256]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "DH g_b and auth_key reproduce the official sample" {
    const g = gBytes(3);
    const dh_prime = hex256("C71CAEB9C6B1C9048E6C522F70F13F73980D40238E3E21C14934D037563D930F" ++
        "48198A0AA7C14058229493D22530F4DBFA336F6E0AC925139543AED44CCE7C37" ++
        "20FD51F69458705AC68CD4FE6B6B13ABDC9746512969328454F18FAF8C595F64" ++
        "2477FE96BB2A941D5BCD1D4AC8CC49880708FA9B378E3C4F3A9060BEE67CF9A4" ++
        "A4A695811051907E162753B56B0F6B410DBA74D8A84B2A14B3144E0EF1284754" ++
        "FD17ED950D5965B4B9DD46582DB1178D169C6BC465B0D6FF9CA3928FEF5B9AE4" ++
        "E418FC15E83EBEA0F87FA9FF5EED70050DED2849F47BF959D956850CE929851F" ++
        "0D8115F635B105EE2E4E15D04B2454BF6F4FADF034B10403119CD8E3B92FCC5B");
    const g_a = hex256("236F6D779877A357465CEC030AC5FDA6D6B377372BFA75574289988FD87D966A" ++
        "29B47E0C00BC788900304EA5E03F3856058C309A6CB508553913788D41A61B1D" ++
        "82B0A2F932C68F18FC21851E66D8649AD9E2092F08C96AD67810724369BF0511" ++
        "E74E1F71F1A825EDDFA1D5DC30E359693C0366FF9FB6828699ACFD1F037116F9" ++
        "5ADD42F6C64B580B3287AA32FBA518E4B8C9C7B52413B501247DB05ADDD89179" ++
        "4394DB529E66890603BCD75CF70E6151398EE85F6D8178EA72C6A61937BCE32B" ++
        "FDAEA86B57A27EBC379933F54C7D44F3E407ED26685D88F0F10A344CDF62F4E2" ++
        "0974B374BA1D41DF223A867DD19713CF0FF71F24465D79258B1742916EE35EE3");
    const b = hex256("F2987DDA0ABCE0B7CE23A7B850BE126641CBAABC1F4C250C839E1844E2E2CBE5" ++
        "7BC0A30B45F6C21D8635F5E927DB0D7498A2F03C6A42D3FB2F3787D5B4D63C2F" ++
        "17A6EB197C0412237E528B68D3D70ADCDEEBD7CD6BACEC59D4FB8F17125ED00B" ++
        "95B34A2D5D8A2133937B5DFEF6DB09F0A3A1BC207A87D9FE4761C59880CA5514" ++
        "32E4AFFCF3982B11EABC526977215F4AC2CE20FA7C808A971DA8C8A08FF26DEB" ++
        "B326EE580B551BEAF0C4B677FCE00E5C6AAEDA3A5A42F38C9C6E226EEDED0502" ++
        "A6BEFC991CC1E0B504E187206D172E72E05D958009FB8C27616EBDD28247262A" ++
        "33AF25E911C9DC22D9A88C6E31A623E6C1E1011CDBD184F6DFFC4F77F5370F16");

    const g_b = try powModP(g, &b, dh_prime);
    try std.testing.expectEqualSlices(u8, &hex256("5EEDFBF6A2199CD1B06182C5C4E0DC26B69ECDE1AD6430D192CD8A69E7434B66" ++
        "A42900AF29B3F41C619AD383FB3721705CF52C34C0507433F743592EE5D4FC50" ++
        "F64E0F8686870E36179AF8C8F4587BD572E98AF4A8247DE2F524BCD48642B38F" ++
        "36104046D7502CDC14BF39A88422B4B1111D886A326C473D1145E69E37C676E1" ++
        "E8FDA07E470482F853886700AE1E7FFDE69FF6D40547C515110B74C6680C844B" ++
        "61504FE0A2D3E08BB7BAE70016C97D7E6B7FA4CEBFE6B5BE30C884849ADE39CC" ++
        "50FD9B4FB16F671EFE8533D0BF7FF8BF13957F1E0D55E713199CEACC72419AF6" ++
        "0CDB1D561084565E9F090141B9F8732B2E806C1B01B25BAFFC4EE1BD5525CB8A"), &g_b);

    const auth_key = try powModP(g_a, &b, dh_prime);
    try std.testing.expectEqualSlices(u8, &hex256("83CBD31C0303361FF1C29437A77CBA749C84F28A118646038C7EDD29EF718A1F" ++
        "6A493047D476A6E678D97A4A5CC7990CEA552D68E109869E5BFC86570049CD8F" ++
        "2EB4BA10B6C4123FB8A977774B4C5185B5C96AF7BD7A71DB78E6E6148CED2048" ++
        "869A21B8ED7FBA7F6F2E7722BFA28447AB84A245CB0E6D01261191B753191E74" ++
        "4DCFDA522D50167832EE4D5EE90AAA6F31821248F0F06BF5692EF604CFC4316C" ++
        "EDE078F71E17BCEBBE388589E6707AF5BA26E8DD063BB116C4B4E7BEF3B462C3" ++
        "350D0376D42F95D353E46BE4C378D2A60141A2339641F8B712EB3ECFB42B7F26" ++
        "F69E9BB15373E0AC4BE266E1681859DDAAB8CD7D877BB847D2A8BD068A784943"), &auth_key);

    try std.testing.expect(dhValueOk(g_a, dh_prime));
    try std.testing.expect(dhValueOk(g_b, dh_prime));
}
