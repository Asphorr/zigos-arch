// Factor the MTProto `pq` challenge.
//
// During the auth handshake the server sends `pq`: the product of two
// primes p and q, each ~31 bits, so pq is a ~63-bit semiprime that fits
// in a u64. The client must split it (p < q) to prove a bit of work.
//
// Pollard's rho with Floyd cycle detection finds a non-trivial factor
// near-instantly at this size. Pure integer math → `zig test`-able.

const std = @import("std");

fn gcd(a0: u64, b0: u64) u64 {
    var a = a0;
    var b = b0;
    while (b != 0) {
        const t = a % b;
        a = b;
        b = t;
    }
    return a;
}

/// (a * b) mod n without overflow — the product can reach ~2^126.
inline fn mulmod(a: u64, b: u64, n: u64) u64 {
    return @intCast((@as(u128, a) * @as(u128, b)) % n);
}

/// g(x) = (x*x + c) mod n — the rho iteration.
inline fn g(x: u64, c: u64, n: u64) u64 {
    const s = mulmod(x, x, n);
    return (s + c) % n;
}

/// Returns {p, q} with p <= q and p*q == n, or null if no factor was
/// found within the retry budget (shouldn't happen for a real semiprime).
pub fn factorize(n: u64) ?[2]u64 {
    if (n < 2) return null;
    if (n % 2 == 0) return order(2, n / 2);

    var c: u64 = 1;
    while (c < 64) : (c += 1) {
        var x: u64 = 2;
        var y: u64 = 2;
        var d: u64 = 1;
        var steps: u64 = 0;
        while (d == 1) {
            x = g(x, c, n);
            y = g(g(y, c, n), c, n);
            const diff = if (x > y) x - y else y - x;
            if (diff == 0) break; // cycle closed with no factor — retry with new c
            d = gcd(diff, n);
            steps += 1;
            if (steps > 10_000_000) break; // safety valve
        }
        if (d != 1 and d != n) return order(d, n / d);
    }
    return null;
}

inline fn order(a: u64, b: u64) [2]u64 {
    return if (a <= b) .{ a, b } else .{ b, a };
}

// =====================================================================
// Tests — zig test lib/mtproto/factorize.zig

test "factor the canonical core.telegram.org pq example" {
    // pq = 1724114033281923457 = 1229739323 * 1402015859
    const got = factorize(1724114033281923457).?;
    try std.testing.expectEqual(@as(u64, 1229739323), got[0]);
    try std.testing.expectEqual(@as(u64, 1402015859), got[1]);
}

test "factor known prime pairs exactly (p<=q)" {
    // Pairs I'm confident are both prime — so the only non-trivial split
    // is exactly {p, q}.
    const cases = [_][2]u64{
        .{ 2, 7 },
        .{ 3, 5 },
        .{ 1229739323, 1402015859 }, // two ~31-bit primes (full pq scale)
    };
    for (cases) |pq| {
        const n = pq[0] * pq[1];
        const got = factorize(n).?;
        try std.testing.expectEqual(@min(pq[0], pq[1]), got[0]);
        try std.testing.expectEqual(@max(pq[0], pq[1]), got[1]);
    }
}

test "always returns a valid non-trivial split (primality-agnostic)" {
    // Whatever the inputs' primality, factorize must hand back two
    // factors > 1, ordered, whose product is n. That's all the handshake
    // needs from a real semiprime.
    const ns = [_]u64{
        2147483647 * 2147483629,
        1000003 * 1000033,
        999983 * 15485863,
        6, 35, 100, 0xFFFF_FFFF, // composites of various shapes
    };
    for (ns) |n| {
        const got = factorize(n).?;
        try std.testing.expect(got[0] > 1);
        try std.testing.expect(got[1] > 1);
        try std.testing.expect(got[0] <= got[1]);
        try std.testing.expectEqual(n, got[0] * got[1]);
    }
}

test "rejects degenerate input" {
    try std.testing.expect(factorize(0) == null);
    try std.testing.expect(factorize(1) == null);
}
