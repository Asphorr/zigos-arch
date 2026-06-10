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
//   ChaCha20-Poly1305 — RFC 7539 §2.8.2 (ciphertext + tag + decrypt round-trip)
//   X25519        — RFC 7748 §6.1 (sk=77… × basepoint(9) → Alice's pk, plus
//                   the full Alice/Bob DH exchange agreeing on shared K)

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

    // Full RFC 7539 §2.8.2 expected ciphertext (114 bytes). The tag alone
    // would transitively cover it (Poly1305 runs over the ciphertext), but
    // a conformance spike should check the spec's bytes literally.
    const expected_ct =
        "d31a8d34648e60db7b86afbc53ef7ec2" ++
        "a4aded51296e08fea9e2b5a736ee62d6" ++
        "3dbea45e8ca9671282fafb69da92728b" ++
        "1a71de0a9e060b2905d6a5b67ecd3b36" ++
        "92ddbd7f2d778b8c9803aee328091b58" ++
        "fab324e4fad675945585808b4831d7bc" ++
        "3ff4def08e4b7a9de576d26586cec64b" ++
        "6116";
    if (!hexEqual(&ciphertext, expected_ct)) {
        klogHex("chacha20-poly1305 ct", &ciphertext);
        debug.klog("[crypto] ciphertext mismatch vs RFC 7539 §2.8.2\n", .{});
        return false;
    }

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

/// Test X25519 with the full RFC 7748 §6.1 vector set. Both pubkeys
/// recover from their secret keys (scalarmult by the basepoint), then the
/// two sides of the DH exchange — scalarmult(alice_sk, bob_pk) and
/// scalarmult(bob_sk, alice_pk) — must agree on the spec's shared K.
/// The DH step is what TLS actually performs (arbitrary peer point, a
/// different code path than fixed-base pubkey recovery), so the spike
/// exercises it explicitly instead of inferring it.
fn testX25519() bool {
    const alice_sk = [_]u8{
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
        0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
        0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
        0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
    };
    const expected_alice_pk = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    const bob_sk = [_]u8{
        0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b,
        0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
        0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
        0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb,
    };
    const expected_bob_pk = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
    const expected_shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

    const alice_pk = X25519.recoverPublicKey(alice_sk) catch |e| {
        debug.klog("[crypto] X25519.recoverPublicKey(alice) FAILED: {s}\n", .{@errorName(e)});
        return false;
    };
    klogHex("X25519 alice pubkey", &alice_pk);
    if (!hexEqual(&alice_pk, expected_alice_pk)) return false;

    const bob_pk = X25519.recoverPublicKey(bob_sk) catch |e| {
        debug.klog("[crypto] X25519.recoverPublicKey(bob) FAILED: {s}\n", .{@errorName(e)});
        return false;
    };
    if (!hexEqual(&bob_pk, expected_bob_pk)) {
        klogHex("X25519 bob pubkey", &bob_pk);
        debug.klog("[crypto] bob pubkey mismatch vs RFC 7748 §6.1\n", .{});
        return false;
    }

    // DH exchange: both directions must derive the spec's K.
    const k_ab = X25519.scalarmult(alice_sk, bob_pk) catch |e| {
        debug.klog("[crypto] X25519.scalarmult(alice_sk, bob_pk) FAILED: {s}\n", .{@errorName(e)});
        return false;
    };
    const k_ba = X25519.scalarmult(bob_sk, alice_pk) catch |e| {
        debug.klog("[crypto] X25519.scalarmult(bob_sk, alice_pk) FAILED: {s}\n", .{@errorName(e)});
        return false;
    };
    klogHex("X25519 shared K", &k_ab);
    if (!hexEqual(&k_ab, expected_shared)) {
        debug.klog("[crypto] shared secret mismatch vs RFC 7748 §6.1\n", .{});
        return false;
    }
    if (!std.mem.eql(u8, &k_ab, &k_ba)) {
        debug.klog("[crypto] DH asymmetry: alice·bob_pk != bob·alice_pk\n", .{});
        return false;
    }
    return true;
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
