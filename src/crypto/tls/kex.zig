// TLS 1.3 ECDHE key-exchange helpers.
//
// We offer two named groups in the ClientHello: x25519 (RFC 7748) and
// secp256r1 / NIST P-256 (RFC 8446 §4.2.8.2). x25519 lives directly in
// std.crypto.dh.X25519; P-256 has no dh wrapper, so we drive the raw
// std.crypto.ecc.P256 point arithmetic here. Both reduce to a 32-byte
// shared secret that feeds the same HKDF key schedule (keys.zig), so the
// caller just picks a group at run time based on the server's choice.
//
// Why P-256 at all: a large slice of real servers prefer (or, behind some
// middleboxes, require) secp256r1 over x25519. Offering only x25519 made
// those endpoints answer with a HelloRetryRequest we don't implement — or
// simply fail — so the baby browser silently couldn't reach them.

const std = @import("std");
const random = @import("../random.zig");

const P256 = std.crypto.ecc.P256;

pub const X25519 = std.crypto.dh.X25519;

/// secp256r1 ephemeral keypair. `public` is the uncompressed SEC1 point
/// (0x04 || X || Y), 65 bytes — exactly the key_share wire format.
pub const P256KeyPair = struct {
    secret: [32]u8,
    public: [65]u8,
};

/// Generate a P-256 ephemeral keypair from ZigOS's own RNG.
///
/// std.crypto's `P256.scalar.random()` pulls from `std.crypto.random`
/// (OS getrandom), which is unavailable in our freestanding build — so we
/// rejection-sample a canonical scalar in [1, n-1] from `random.fillRandom`
/// instead. P-256's order n is just under 2^256, so a uniformly random
/// 32-byte value lands >= n only ~2^-32 of the time; the loop is a
/// formality that also rejects the (astronomically unlikely) zero scalar.
pub fn genP256() ?P256KeyPair {
    var sk: [32]u8 = undefined;
    var tries: u8 = 0;
    while (tries < 16) : (tries += 1) {
        if (!random.fillRandom(&sk)) return null;
        P256.scalar.rejectNonCanonical(sk, .big) catch continue; // reject s >= n
        if (isZero(&sk)) continue;
        const point = P256.basePoint.mul(sk, .big) catch continue;
        return .{ .secret = sk, .public = point.toUncompressedSec1() };
    }
    return null;
}

/// secp256r1 ECDH: multiply the server's public point by our secret and
/// return the 32-byte big-endian X coordinate — the TLS 1.3 P-256 shared
/// secret (RFC 8446 §7.4.2 / RFC 8446 §4.2.8.2). `server_pub` is the
/// server's uncompressed SEC1 key_share value. `fromSec1` validates the
/// point is on the curve and `mul` rejects the identity, so a malformed or
/// small-order server share returns null rather than a degenerate secret.
pub fn p256Ecdh(secret: [32]u8, server_pub: []const u8) ?[32]u8 {
    const point = P256.fromSec1(server_pub) catch return null;
    const shared = point.mul(secret, .big) catch return null;
    return shared.affineCoordinates().x.toBytes(.big);
}

fn isZero(s: *const [32]u8) bool {
    var acc: u8 = 0;
    for (s) |b| acc |= b;
    return acc == 0;
}
