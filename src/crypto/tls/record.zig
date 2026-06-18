// TLS 1.3 record layer. After ServerHello, every handshake and
// application record on the wire is wrapped as:
//
//   record_header (5 bytes plaintext, type=0x17 application_data)
//   ciphertext (variable, AEAD-encrypted)
//
// AEAD = ChaCha20-Poly1305 or AES-128-GCM (selected per conn; see Cipher).
// Both use a 12-byte nonce + 16-byte tag, so the nonce construction and
// tag-split below are shared. The 12-byte nonce is built per RFC 8446 §5.3:
// take the static IV, then XOR the record sequence number (big-endian, padded
// with zeros to 12 bytes) into it. Sequence resets per direction when a new
// traffic secret is installed.

const std = @import("std");
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;

pub const RecordError = error{
    Truncated,
    BadAuth,
    BufferTooSmall,
};

/// The negotiated TLS 1.3 AEAD. Both use a 12-byte nonce and 16-byte tag and
/// share the SHA-256 key schedule (so the rest of the stack is cipher-agnostic
/// past the key/IV); they differ only in the AEAD primitive and key length.
/// AES-256-GCM is deliberately absent — it needs the SHA-384 transcript.
pub const Cipher = enum {
    chacha20_poly1305, // TLS_CHACHA20_POLY1305_SHA256 (0x1303), 32-byte key
    aes128_gcm, // TLS_AES_128_GCM_SHA256 (0x1301), 16-byte key

    pub fn keyLen(self: Cipher) usize {
        return switch (self) {
            .chacha20_poly1305 => 32,
            .aes128_gcm => 16,
        };
    }

    /// Map a wire cipher-suite code to a Cipher we can actually run, or null
    /// for anything unsupported (incl. AES-256-GCM, which we never advertise).
    pub fn fromSuite(suite: u16) ?Cipher {
        return switch (suite) {
            0x1303 => .chacha20_poly1305,
            0x1301 => .aes128_gcm,
            else => null,
        };
    }
};

/// Construct the per-record nonce (shared by both AEADs — same 12-byte
/// nonce). The IV stays fixed for the conn-direction-lifetime; the sequence number XORs in
/// only the low 8 bytes. We pad seq to a 12-byte vector by leaving
/// nonce[0..4] alone (those bits never change).
pub fn buildNonce(iv: [12]u8, seq: u64) [12]u8 {
    var nonce: [12]u8 = iv;
    // Bytes 4..12 hold the big-endian seq XOR'd into iv. Bytes 0..3
    // pass through unchanged from iv.
    nonce[4] ^= @intCast((seq >> 56) & 0xFF);
    nonce[5] ^= @intCast((seq >> 48) & 0xFF);
    nonce[6] ^= @intCast((seq >> 40) & 0xFF);
    nonce[7] ^= @intCast((seq >> 32) & 0xFF);
    nonce[8] ^= @intCast((seq >> 24) & 0xFF);
    nonce[9] ^= @intCast((seq >> 16) & 0xFF);
    nonce[10] ^= @intCast((seq >> 8) & 0xFF);
    nonce[11] ^= @intCast(seq & 0xFF);
    return nonce;
}

/// Decrypt one TLS 1.3 record's encrypted payload in-place into `out`.
/// `ciphertext` is the wire payload bytes AFTER the 5-byte record
/// header (i.e. everything that contributed to the record's `length`
/// field); the last 16 bytes are the auth tag. `aad` is the 5-byte
/// record header — passed exactly as it appeared on the wire so the
/// tag check matches what the peer computed.
///
/// Returns the plaintext length on success. The TLS 1.3 inner type
/// is the LAST non-zero byte of the plaintext; caller strips it +
/// any trailing zero padding to get the actual content.
pub fn decrypt(out: []u8, ciphertext: []const u8, aad: []const u8, cipher: Cipher, key: [32]u8, iv: [12]u8, seq: u64) RecordError!usize {
    if (ciphertext.len < 16) return RecordError.Truncated;
    const payload_len = ciphertext.len - 16;
    if (out.len < payload_len) return RecordError.BufferTooSmall;

    const nonce = buildNonce(iv, seq);
    var tag: [16]u8 = undefined;
    @memcpy(&tag, ciphertext[payload_len..][0..16]);

    switch (cipher) {
        .chacha20_poly1305 => ChaCha20Poly1305.decrypt(
            out[0..payload_len],
            ciphertext[0..payload_len],
            tag,
            aad,
            nonce,
            key,
        ) catch return RecordError.BadAuth,
        .aes128_gcm => {
            var k16: [16]u8 = undefined;
            @memcpy(&k16, key[0..16]);
            Aes128Gcm.decrypt(
                out[0..payload_len],
                ciphertext[0..payload_len],
                tag,
                aad,
                nonce,
                k16,
            ) catch return RecordError.BadAuth;
        },
    }

    return payload_len;
}

/// Walk back from the end of a decrypted TLS 1.3 record plaintext,
/// skipping any zero padding, to return the inner content type. The
/// content (handshake message, alert, application data) is the bytes
/// BEFORE that final type byte.
pub fn stripInnerType(plain: []const u8) struct { inner_type: u8, content: []const u8 } {
    var end = plain.len;
    while (end > 0 and plain[end - 1] == 0) : (end -= 1) {}
    if (end == 0) return .{ .inner_type = 0, .content = plain[0..0] };
    return .{ .inner_type = plain[end - 1], .content = plain[0 .. end - 1] };
}

/// Encrypt one TLS 1.3 record. Caller supplies the inner payload
/// (handshake message bytes or application data) and the inner content
/// type (22=handshake, 23=appdata). We assemble the
/// (inner_payload || inner_type) plaintext, encrypt + tag, and write
/// the wire format `record_header || ciphertext || tag` into `out`.
///
/// Returns total bytes written. `out` must be at least
///   5 (record header) + inner.len + 1 (inner type) + 16 (tag).
pub fn encrypt(
    out: []u8,
    inner: []const u8,
    inner_type: u8,
    cipher: Cipher,
    key: [32]u8,
    iv: [12]u8,
    seq: u64,
) RecordError!usize {
    const plaintext_len = inner.len + 1; // + 1 for inner content type byte
    const ct_len = plaintext_len + 16;
    const total = 5 + ct_len;
    if (out.len < total) return RecordError.BufferTooSmall;
    if (ct_len > 0xFFFF) return RecordError.BufferTooSmall;

    // Record header (also the AAD per RFC 8446 §5.2).
    out[0] = 0x17; // application_data
    out[1] = 0x03;
    out[2] = 0x03;
    out[3] = @intCast((ct_len >> 8) & 0xFF);
    out[4] = @intCast(ct_len & 0xFF);

    // Build the plaintext into out[5..] so we can encrypt in-place. We
    // could also use a scratch buffer; in-place is fine because
    // ChaCha20-Poly1305 reads source byte-by-byte during XOR (the
    // overlap is well-defined for stream ciphers).
    @memcpy(out[5..][0..inner.len], inner);
    out[5 + inner.len] = inner_type;

    const nonce = buildNonce(iv, seq);
    var tag: [16]u8 = undefined;
    switch (cipher) {
        .chacha20_poly1305 => ChaCha20Poly1305.encrypt(
            out[5 .. 5 + plaintext_len],
            &tag,
            out[5 .. 5 + plaintext_len],
            out[0..5], // AAD = record header
            nonce,
            key,
        ),
        .aes128_gcm => {
            var k16: [16]u8 = undefined;
            @memcpy(&k16, key[0..16]);
            Aes128Gcm.encrypt(
                out[5 .. 5 + plaintext_len],
                &tag,
                out[5 .. 5 + plaintext_len],
                out[0..5], // AAD = record header
                nonce,
                k16,
            );
        },
    }
    @memcpy(out[5 + plaintext_len ..][0..16], &tag);
    return total;
}
