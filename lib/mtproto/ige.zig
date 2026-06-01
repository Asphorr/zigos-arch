// AES-256 in IGE mode (Infinite Garble Extension) — the block mode
// MTProto uses for the DH handshake payloads and for encrypted message
// bodies. Built on std.crypto's AES block primitive, so it's pure and
// `zig test`-able off-target.
//
// IGE chaining (16-byte blocks; the 32-byte IV splits into two halves —
// a "previous ciphertext" c_-1 = iv[0..16] and a "previous plaintext"
// p_-1 = iv[16..32]):
//
//   encrypt:  c_i = E(p_i XOR c_{i-1}) XOR p_{i-1}
//   decrypt:  p_i = D(c_i XOR p_{i-1}) XOR c_{i-1}
//
// Both operate in place; data length must be a multiple of 16.

const std = @import("std");
const aes = std.crypto.core.aes;

pub const Error = error{NotBlockAligned};

inline fn xorBlock(out: *[16]u8, a: [16]u8, b: [16]u8) void {
    for (0..16) |i| out[i] = a[i] ^ b[i];
}

pub fn encrypt(key: [32]u8, iv: [32]u8, data: []u8) Error!void {
    if (data.len % 16 != 0) return error.NotBlockAligned;
    const ctx = aes.Aes256.initEnc(key);
    var prev_c: [16]u8 = iv[0..16].*;
    var prev_p: [16]u8 = iv[16..32].*;
    var off: usize = 0;
    while (off < data.len) : (off += 16) {
        const p: [16]u8 = data[off..][0..16].*;
        var x: [16]u8 = undefined;
        xorBlock(&x, p, prev_c); // p_i XOR c_{i-1}
        var e: [16]u8 = undefined;
        ctx.encrypt(&e, &x);
        var c: [16]u8 = undefined;
        xorBlock(&c, e, prev_p); // ... XOR p_{i-1}
        @memcpy(data[off..][0..16], &c);
        prev_c = c;
        prev_p = p;
    }
}

pub fn decrypt(key: [32]u8, iv: [32]u8, data: []u8) Error!void {
    if (data.len % 16 != 0) return error.NotBlockAligned;
    const ctx = aes.Aes256.initDec(key);
    var prev_c: [16]u8 = iv[0..16].*;
    var prev_p: [16]u8 = iv[16..32].*;
    var off: usize = 0;
    while (off < data.len) : (off += 16) {
        const c: [16]u8 = data[off..][0..16].*;
        var x: [16]u8 = undefined;
        xorBlock(&x, c, prev_p); // c_i XOR p_{i-1}
        var d: [16]u8 = undefined;
        ctx.decrypt(&d, &x);
        var p: [16]u8 = undefined;
        xorBlock(&p, d, prev_c); // ... XOR c_{i-1}
        @memcpy(data[off..][0..16], &p);
        prev_c = c;
        prev_p = p;
    }
}

// =====================================================================
// Tests — zig test lib/mtproto/ige.zig

// With an all-zero IV and a single block, IGE degenerates to ECB
// (c_0 = E(p_0 XOR 0) XOR 0 = E(p_0)). So this is really a known-answer
// test of AES-256 itself, using the canonical FIPS-197 Appendix C.3
// vector — which simultaneously proves our IGE wiring adds no garbage.
test "AES-256-IGE zero-IV single block == FIPS-197 AES-256 KAT" {
    var key: [32]u8 = undefined;
    for (0..32) |i| key[i] = @intCast(i); // 000102...1f
    const iv = [_]u8{0} ** 32;
    var block = [_]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    try encrypt(key, iv, &block);
    const expect = [_]u8{ 0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89 };
    try std.testing.expectEqualSlices(u8, &expect, &block);
}

test "AES-256-IGE multi-block encrypt/decrypt is an identity" {
    var key: [32]u8 = undefined;
    for (0..32) |i| key[i] = @intCast((i * 7) & 0xFF);
    var iv: [32]u8 = undefined;
    for (0..32) |i| iv[i] = @intCast((i * 3 + 1) & 0xFF);
    var data: [64]u8 = undefined;
    for (0..64) |i| data[i] = @intCast(i & 0xFF);
    const orig = data;

    try encrypt(key, iv, &data);
    try std.testing.expect(!std.mem.eql(u8, &orig, &data)); // actually encrypted
    try decrypt(key, iv, &data);
    try std.testing.expectEqualSlices(u8, &orig, &data); // and recovered
}

test "non-block-aligned length is rejected" {
    const key = [_]u8{0} ** 32;
    const iv = [_]u8{0} ** 32;
    var data = [_]u8{0} ** 20;
    try std.testing.expectError(error.NotBlockAligned, encrypt(key, iv, &data));
}
