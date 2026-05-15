// std.crypto freestanding spike (TLS arc step 1).
//
// One-shot boot-time check that the three TLS 1.3 primitives we need
// — SHA-256, ChaCha20-Poly1305, X25519 — compile and execute correctly
// from kernel code. If any fail to build, the whole "use std.crypto and
// hand-roll the protocol on top" plan is dead and we'd pivot to vendoring
// BearSSL. If any fail at runtime (wrong digest, decrypt fails, etc.),
// std.crypto needs an env feature we don't provide.
//
// Validates against known RFC test vectors:
//   SHA-256        — NIST FIPS 180-4, "abc"
//   ChaCha20-Poly1305 — RFC 7539 §2.8.2
//   X25519        — RFC 7748 §6.1 (Alice's keypair: sk=09… → expected pk)

const std = @import("std");
const debug = @import("../debug/debug.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const X25519 = std.crypto.dh.X25519;

fn hexEqual(buf: []const u8, expected_hex: []const u8) bool {
    if (buf.len * 2 != expected_hex.len) return false;
    var i: usize = 0;
    while (i < buf.len) : (i += 1) {
        const hi = std.fmt.charToDigit(expected_hex[i * 2], 16) catch return false;
        const lo = std.fmt.charToDigit(expected_hex[i * 2 + 1], 16) catch return false;
        const expected_byte: u8 = @intCast((hi << 4) | lo);
        if (buf[i] != expected_byte) return false;
    }
    return true;
}

fn klogHex(label: []const u8, buf: []const u8) void {
    debug.klog("[crypto] {s} = ", .{label});
    for (buf) |b| debug.klog("{x:0>2}", .{b});
    debug.klog("\n", .{});
}

/// Test SHA-256 against the FIPS 180-4 "abc" vector.
fn testSha256() bool {
    var out: [32]u8 = undefined;
    Sha256.hash("abc", &out, .{});
    klogHex("sha256(\"abc\")", &out);
    const expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    return hexEqual(&out, expected);
}

/// Test ChaCha20-Poly1305 with the RFC 7539 §2.8.2 vector. Encrypt the
/// known plaintext, compare the ciphertext + tag to the spec's reference,
/// then decrypt back to plaintext.
fn testChaCha20Poly1305() bool {
    const key = [_]u8{
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    };
    const nonce = [_]u8{ 0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };
    const aad = [_]u8{ 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };
    const plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    ChaCha20Poly1305.encrypt(&ciphertext, &tag, plaintext, &aad, nonce, key);

    klogHex("chacha20-poly1305 tag", &tag);
    const expected_tag = "1ae10b594f09e26a7e902ecbd0600691";
    if (!hexEqual(&tag, expected_tag)) {
        debug.klog("[crypto] tag mismatch (expected {s})\n", .{expected_tag});
        return false;
    }

    var decrypted: [plaintext.len]u8 = undefined;
    ChaCha20Poly1305.decrypt(&decrypted, &ciphertext, tag, &aad, nonce, key) catch |e| {
        debug.klog("[crypto] decrypt FAILED: {s}\n", .{@errorName(e)});
        return false;
    };
    if (!std.mem.eql(u8, &decrypted, plaintext)) {
        debug.klog("[crypto] decrypt round-trip mismatch\n", .{});
        return false;
    }
    return true;
}

/// Test X25519 with the RFC 7748 §6.1 first-step keypair. Alice's
/// secret key 0x77…2a should derive the public key 0x85…4a from the
/// basepoint.
fn testX25519() bool {
    const alice_sk = [_]u8{
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
        0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
        0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
        0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
    };
    const expected_pk = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";

    const pk = X25519.recoverPublicKey(alice_sk) catch |e| {
        debug.klog("[crypto] X25519.recoverPublicKey FAILED: {s}\n", .{@errorName(e)});
        return false;
    };
    klogHex("X25519 alice pubkey", &pk);
    return hexEqual(&pk, expected_pk);
}

/// Run all three tests. Each prints its result; the final summary
/// reports overall pass/fail so the spike can land as a single
/// boot-line.
pub fn run() void {
    debug.klog("[crypto] === std.crypto freestanding spike ===\n", .{});
    const sha_ok = testSha256();
    const aead_ok = testChaCha20Poly1305();
    const x25519_ok = testX25519();
    if (sha_ok and aead_ok and x25519_ok) {
        debug.klog("[crypto] ALL PASS — std.crypto works freestanding\n", .{});
    } else {
        debug.klog("[crypto] FAILURE — sha={any} aead={any} x25519={any}\n", .{ sha_ok, aead_ok, x25519_ok });
    }
}

// Compile-time check: reference TLS-adjacent types to force their
// declarations to be evaluated. If `std.crypto.tls.Client` (or its
// transitive deps like `std.net.Stream`) pulls in something not
// available freestanding, this fails to build. If it compiles, the
// "use std.crypto.tls directly" option stays open as a fallback even
// if we hand-roll the protocol on top of the primitives.
comptime {
    _ = std.crypto.tls;
    // Also try referencing the high-level Client. If Zig std considers
    // it part of the always-checked tree, build breaks here on missing
    // freestanding deps. If the build still succeeds, we have green
    // light to study/copy the std implementation.
    _ = std.crypto.tls.Client;
}
