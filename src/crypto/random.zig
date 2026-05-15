// Kernel CSPRNG entropy. Uses x86 RDRAND/RDSEED when available; falls
// back to a TSC-mixed counter as a degraded source if neither is
// present. The fallback is NOT cryptographically secure on its own —
// we accept it because (a) every CPU we target after Ivy Bridge has
// RDRAND and (b) a degraded source is better than `[_]u8{0} ** N`
// when a missing-randomness regression slips in.
//
// API mirrors the shape `std.crypto.random` expects: `fillRandom(out)`
// writes `out.len` bytes into `out`. Callers use it to seed:
//   - TLS 1.3 client_random (32 bytes, must be unique per session)
//   - X25519 ephemeral private key (32 bytes, must be unguessable)
//   - PRNG nonces, session IDs, etc.

const std = @import("std");

/// CPUID-derived feature flag cache. Filled lazily on first use so we
/// don't pay the CPUID cost (~20 cycles) per random byte. Bits 0 and 1
/// follow the canonical CPUID layout: leaf 1 ECX bit 30 for RDRAND,
/// leaf 7 EBX bit 18 for RDSEED.
var caps_init: bool = false;
var has_rdrand: bool = false;
var has_rdseed: bool = false;

fn cpuid(leaf: u32, sub: u32) struct { a: u32, b: u32, c: u32, d: u32 } {
    var a: u32 = leaf;
    var b: u32 = undefined;
    var c: u32 = sub;
    var d: u32 = undefined;
    asm volatile ("cpuid"
        : [a] "+{eax}" (a),
          [b] "={ebx}" (b),
          [c] "+{ecx}" (c),
          [d] "={edx}" (d),
    );
    return .{ .a = a, .b = b, .c = c, .d = d };
}

fn initCaps() void {
    if (caps_init) return;
    const leaf1 = cpuid(1, 0);
    has_rdrand = (leaf1.c & (1 << 30)) != 0;
    const leaf7 = cpuid(7, 0);
    has_rdseed = (leaf7.b & (1 << 18)) != 0;
    caps_init = true;
}

/// Read one 64-bit random word via RDRAND. Returns null if the
/// instruction's CF flag came back zero (entropy pool exhausted — Intel
/// recommends retrying up to 10 times before giving up). We retry once
/// here and let the caller decide what "give up" means.
fn rdrand64() ?u64 {
    var attempts: u8 = 0;
    while (attempts < 10) : (attempts += 1) {
        var v: u64 = undefined;
        var ok: u8 = 0;
        asm volatile (
            \\rdrand %[v]
            \\setc %[ok]
            : [v] "=r" (v),
              [ok] "=r" (ok),
        );
        if (ok != 0) return v;
    }
    return null;
}

fn rdseed64() ?u64 {
    var attempts: u8 = 0;
    while (attempts < 10) : (attempts += 1) {
        var v: u64 = undefined;
        var ok: u8 = 0;
        asm volatile (
            \\rdseed %[v]
            \\setc %[ok]
            : [v] "=r" (v),
              [ok] "=r" (ok),
        );
        if (ok != 0) return v;
    }
    return null;
}

/// Fallback PRNG state — only used if RDRAND/RDSEED both unavailable
/// or both retry-exhausted. xorshift64* over a TSC-seeded state. Not
/// cryptographically secure; logged loud when triggered so we notice
/// the regression instead of silently shipping bad TLS.
var fallback_state: u64 = 0;
var fallback_warned: bool = false;

fn rdtsc() u64 {
    var lo: u32 = undefined;
    var hi: u32 = undefined;
    asm volatile ("rdtsc"
        : [lo] "={eax}" (lo),
          [hi] "={edx}" (hi),
    );
    return (@as(u64, hi) << 32) | @as(u64, lo);
}

fn fallback64() u64 {
    if (fallback_state == 0) fallback_state = rdtsc() | 1;
    var x = fallback_state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    fallback_state = x;
    return x *% 0x2545F4914F6CDD1D;
}

/// Fill `out` with cryptographically random bytes. Returns true on
/// success (RDRAND or RDSEED provided every byte), false if we had to
/// fall back to the xorshift PRNG for any of them. Callers that
/// strictly need real entropy (e.g. TLS keygen) should reject false.
pub fn fillRandom(out: []u8) bool {
    initCaps();
    var degraded = false;
    var pos: usize = 0;
    while (pos < out.len) {
        const word: u64 = blk: {
            if (has_rdseed) {
                if (rdseed64()) |v| break :blk v;
            }
            if (has_rdrand) {
                if (rdrand64()) |v| break :blk v;
            }
            degraded = true;
            if (!fallback_warned) {
                @import("../debug/debug.zig").klog("[random] WARNING: RDRAND/RDSEED unavailable, using xorshift fallback (NOT SECURE for TLS)\n", .{});
                fallback_warned = true;
            }
            break :blk fallback64();
        };
        const remaining = out.len - pos;
        const take = @min(remaining, 8);
        var i: usize = 0;
        while (i < take) : (i += 1) {
            out[pos + i] = @intCast((word >> @intCast(i * 8)) & 0xFF);
        }
        pos += take;
    }
    return !degraded;
}
