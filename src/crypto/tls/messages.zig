// TLS 1.3 handshake-message construction & parsing.
//
// Only ClientHello and ServerHello are implemented here today. The rest
// of the handshake (EncryptedExtensions, Certificate, CertificateVerify,
// Finished) lives behind the record-layer encryption we haven't built
// yet — see the TLS arc plan.
//
// Wire format reference: RFC 8446 §4.1.2 (ClientHello), §4.1.3
// (ServerHello). We hand-roll the byte layout because using a struct +
// @bitCast doesn't work — fields like `cipher_suites<2..2^16-2>` are
// length-prefixed slices, not fixed structs, and the prefix sizes vary
// per field (u8 for session_id, u16 for cipher_suites, u16 for
// extensions block, u16 for each extension).

const std = @import("std");
const types = @import("types.zig");

// === Cursor helpers — write side ===

/// Writes a value, then advances `pos` by the written width. `pos` is
/// passed by pointer so each call can keep position alive across the
/// whole hello assembly.
fn writeU8(buf: []u8, pos: *usize, v: u8) void {
    buf[pos.*] = v;
    pos.* += 1;
}

fn writeU16(buf: []u8, pos: *usize, v: u16) void {
    buf[pos.*] = @intCast(v >> 8);
    buf[pos.* + 1] = @intCast(v & 0xFF);
    pos.* += 2;
}

fn writeU24(buf: []u8, pos: *usize, v: u32) void {
    buf[pos.*] = @intCast((v >> 16) & 0xFF);
    buf[pos.* + 1] = @intCast((v >> 8) & 0xFF);
    buf[pos.* + 2] = @intCast(v & 0xFF);
    pos.* += 3;
}

fn writeBytes(buf: []u8, pos: *usize, src: []const u8) void {
    @memcpy(buf[pos.*..][0..src.len], src);
    pos.* += src.len;
}

/// Reserve `width` bytes for a length-prefix to be backpatched later.
/// Returns the offset of the prefix so backpatchU16/U24 can fill it
/// after the body has been written.
fn reserveLen(pos: *usize, width: usize) usize {
    const at = pos.*;
    pos.* += width;
    return at;
}

fn backpatchU16(buf: []u8, at: usize, length: usize) void {
    buf[at] = @intCast((length >> 8) & 0xFF);
    buf[at + 1] = @intCast(length & 0xFF);
}

fn backpatchU24(buf: []u8, at: usize, length: usize) void {
    buf[at] = @intCast((length >> 16) & 0xFF);
    buf[at + 1] = @intCast((length >> 8) & 0xFF);
    buf[at + 2] = @intCast(length & 0xFF);
}

// === Cursor helpers — read side ===

const ParseError = error{
    Truncated,
    BadVersion,
    BadCipher,
    BadExtension,
    UnsupportedGroup,
};

const Reader = struct {
    data: []const u8,
    pos: usize = 0,

    fn remaining(self: *const Reader) usize {
        return self.data.len - self.pos;
    }

    fn readU8(self: *Reader) ParseError!u8 {
        if (self.remaining() < 1) return ParseError.Truncated;
        const v = self.data[self.pos];
        self.pos += 1;
        return v;
    }

    fn readU16(self: *Reader) ParseError!u16 {
        if (self.remaining() < 2) return ParseError.Truncated;
        const v = (@as(u16, self.data[self.pos]) << 8) | @as(u16, self.data[self.pos + 1]);
        self.pos += 2;
        return v;
    }

    fn readU24(self: *Reader) ParseError!u32 {
        if (self.remaining() < 3) return ParseError.Truncated;
        const v = (@as(u32, self.data[self.pos]) << 16) |
            (@as(u32, self.data[self.pos + 1]) << 8) |
            @as(u32, self.data[self.pos + 2]);
        self.pos += 3;
        return v;
    }

    fn readBytes(self: *Reader, n: usize) ParseError![]const u8 {
        if (self.remaining() < n) return ParseError.Truncated;
        const s = self.data[self.pos..][0..n];
        self.pos += n;
        return s;
    }

    fn skip(self: *Reader, n: usize) ParseError!void {
        if (self.remaining() < n) return ParseError.Truncated;
        self.pos += n;
    }
};

// === ClientHello ===

pub const ClientHelloParams = struct {
    /// Cryptographically random 32-byte client_random. Server echoes its
    /// own random; both feed into the key schedule. RFC 8446 §4.1.2
    /// requires this to be unguessable per session — feed it from
    /// `crypto/random.fillRandom`.
    client_random: [32]u8,
    /// Our ephemeral X25519 public key for the key_share extension.
    /// Server multiplies its private key by this to derive the shared
    /// secret; we do the same with the server's reply.
    x25519_pub: [32]u8,
    /// SNI hostname. Sent in the server_name extension so virtual hosts
    /// can pick the right cert. Empty disables SNI (some servers will
    /// reject — github.com does).
    server_name: []const u8,
};

/// Build a TLS 1.3 ClientHello in `buf` (excluding the outer record
/// header — caller wraps it). Returns the number of bytes written, or
/// 0 if buf was too small.
pub fn buildClientHello(buf: []u8, p: ClientHelloParams) usize {
    if (buf.len < 256) return 0; // crude safety net; real bound is ~150 bytes for our shape

    var pos: usize = 0;

    // Handshake header: msg_type + 24-bit length (backpatched).
    writeU8(buf, &pos, @intFromEnum(types.HandshakeType.client_hello));
    const hs_len_at = reserveLen(&pos, 3);
    const body_start = pos;

    // legacy_version = TLS 1.2 (real version is in supported_versions ext)
    writeU16(buf, &pos, types.PROTOCOL_TLS_1_2);
    // random[32]
    writeBytes(buf, &pos, &p.client_random);
    // legacy_session_id: empty (length-prefixed u8). TLS 1.3 doesn't use
    // it; sending non-empty triggers "middlebox compat" pseudo-resumption
    // which we skip.
    writeU8(buf, &pos, 0);

    // cipher_suites<2..2^16-2>: just chacha20-poly1305-sha256.
    writeU16(buf, &pos, 2); // suites_len = 1 suite × 2 bytes
    writeU16(buf, &pos, @intFromEnum(types.CipherSuite.chacha20_poly1305_sha256));

    // legacy_compression_methods<1..2^8-1>: [null]
    writeU8(buf, &pos, 1);
    writeU8(buf, &pos, 0);

    // extensions<8..2^16-1>: length-prefixed block, backpatched.
    const ext_len_at = reserveLen(&pos, 2);
    const ext_start = pos;

    // -- server_name (RFC 6066) --
    if (p.server_name.len > 0) {
        writeU16(buf, &pos, @intFromEnum(types.ExtensionType.server_name));
        const sn_len_at = reserveLen(&pos, 2);
        const sn_start = pos;
        writeU16(buf, &pos, @intCast(p.server_name.len + 3)); // server_name_list length
        writeU8(buf, &pos, 0); // NameType = host_name
        writeU16(buf, &pos, @intCast(p.server_name.len));
        writeBytes(buf, &pos, p.server_name);
        backpatchU16(buf, sn_len_at, pos - sn_start);
    }

    // -- supported_versions: [TLS 1.3] --
    writeU16(buf, &pos, @intFromEnum(types.ExtensionType.supported_versions));
    writeU16(buf, &pos, 3); // ext_len: 1 byte list_len + 1×u16 version
    writeU8(buf, &pos, 2); // versions list_len in bytes
    writeU16(buf, &pos, types.PROTOCOL_TLS_1_3);

    // -- supported_groups: [x25519] --
    writeU16(buf, &pos, @intFromEnum(types.ExtensionType.supported_groups));
    writeU16(buf, &pos, 4);
    writeU16(buf, &pos, 2);
    writeU16(buf, &pos, @intFromEnum(types.NamedGroup.x25519));

    // -- signature_algorithms: ECDSA P-256, RSA-PSS, RSA-PKCS1, Ed25519 --
    writeU16(buf, &pos, @intFromEnum(types.ExtensionType.signature_algorithms));
    writeU16(buf, &pos, 10);
    writeU16(buf, &pos, 8);
    writeU16(buf, &pos, @intFromEnum(types.SignatureScheme.ecdsa_secp256r1_sha256));
    writeU16(buf, &pos, @intFromEnum(types.SignatureScheme.rsa_pss_rsae_sha256));
    writeU16(buf, &pos, @intFromEnum(types.SignatureScheme.rsa_pkcs1_sha256));
    writeU16(buf, &pos, @intFromEnum(types.SignatureScheme.ed25519));

    // -- key_share: [x25519: our_pub] --
    writeU16(buf, &pos, @intFromEnum(types.ExtensionType.key_share));
    writeU16(buf, &pos, 38); // ext_len: 2 (list_len) + 2 (group) + 2 (kex_len) + 32 (key)
    writeU16(buf, &pos, 36); // client_shares list_len
    writeU16(buf, &pos, @intFromEnum(types.NamedGroup.x25519));
    writeU16(buf, &pos, 32);
    writeBytes(buf, &pos, &p.x25519_pub);

    // -- psk_key_exchange_modes: [psk_dhe_ke] --
    // RFC 8446 §4.2.9. We don't offer PSK identities, but advertising
    // support for the DHE-PSK mode signals to picky implementations that
    // we're a conformant TLS 1.3 client. Cloudflare's edge appears to
    // gate on this when fingerprint-screening unknown clients.
    writeU16(buf, &pos, @intFromEnum(types.ExtensionType.psk_key_exchange_modes));
    writeU16(buf, &pos, 2); // ext_len: 1 (list_len) + 1 (mode)
    writeU8(buf, &pos, 1); // modes list_len
    writeU8(buf, &pos, 1); // psk_dhe_ke

    // -- application_layer_protocol_negotiation: [http/1.1] --
    // RFC 7301. Without ALPN, modern HTTPS endpoints (Cloudflare,
    // CloudFront, etc.) may treat the conn as a bot probe. We speak
    // HTTP/1.1 only — offer just that so the server doesn't try to
    // upgrade us to h2.
    writeU16(buf, &pos, @intFromEnum(types.ExtensionType.alpn));
    const alpn_proto = "http/1.1";
    const alpn_total_len: u16 = @intCast(2 + 1 + alpn_proto.len); // list_len + name_len + name
    writeU16(buf, &pos, alpn_total_len);
    writeU16(buf, &pos, @intCast(1 + alpn_proto.len)); // protocol_name_list length
    writeU8(buf, &pos, @intCast(alpn_proto.len));
    writeBytes(buf, &pos, alpn_proto);

    // Backpatch extensions block length, then the handshake length.
    backpatchU16(buf, ext_len_at, pos - ext_start);
    backpatchU24(buf, hs_len_at, pos - body_start);
    return pos;
}

// === ServerHello ===

pub const ServerHello = struct {
    server_random: [32]u8,
    cipher_suite: types.CipherSuite,
    /// Server's ephemeral X25519 public key, extracted from key_share.
    /// Combined with our private key via X25519.scalarmult → shared secret.
    server_x25519_pub: [32]u8,
    /// Echoed legacy_session_id_echo. Captured for the transcript hash
    /// even though we don't use it for resumption.
    session_id_len: u8,
    session_id: [32]u8,
};

/// Parse a TLS 1.3 ServerHello. `data` is the handshake-message body
/// (after the outer record header AND after the 4-byte handshake header).
/// Returns a populated ServerHello or a ParseError describing where the
/// wire layout disagreed with the spec.
pub fn parseServerHello(data: []const u8) ParseError!ServerHello {
    var r = Reader{ .data = data };

    const legacy_version = try r.readU16();
    if (legacy_version != types.PROTOCOL_TLS_1_2) return ParseError.BadVersion;

    var out: ServerHello = std.mem.zeroes(ServerHello);
    @memcpy(&out.server_random, try r.readBytes(32));

    const sid_len = try r.readU8();
    if (sid_len > 32) return ParseError.Truncated;
    out.session_id_len = sid_len;
    if (sid_len > 0) @memcpy(out.session_id[0..sid_len], try r.readBytes(sid_len));

    const suite_raw = try r.readU16();
    if (suite_raw != @intFromEnum(types.CipherSuite.chacha20_poly1305_sha256) and
        suite_raw != @intFromEnum(types.CipherSuite.aes_128_gcm_sha256) and
        suite_raw != @intFromEnum(types.CipherSuite.aes_256_gcm_sha384))
    {
        return ParseError.BadCipher;
    }
    out.cipher_suite = @enumFromInt(suite_raw);

    const compression = try r.readU8();
    if (compression != 0) return ParseError.BadExtension;

    const ext_len = try r.readU16();
    if (ext_len != r.remaining()) return ParseError.Truncated;

    var negotiated_version: u16 = 0;
    var got_keyshare = false;
    while (r.remaining() > 0) {
        const ext_type = try r.readU16();
        const this_len = try r.readU16();
        if (this_len > r.remaining()) return ParseError.Truncated;
        const ext_data = try r.readBytes(this_len);

        switch (@as(types.ExtensionType, @enumFromInt(ext_type))) {
            .supported_versions => {
                if (ext_data.len != 2) return ParseError.BadExtension;
                negotiated_version = (@as(u16, ext_data[0]) << 8) | @as(u16, ext_data[1]);
            },
            .key_share => {
                // ServerHello.key_share is just one KeyShareEntry, not a list.
                if (ext_data.len < 4) return ParseError.BadExtension;
                const group: u16 = (@as(u16, ext_data[0]) << 8) | @as(u16, ext_data[1]);
                if (group != @intFromEnum(types.NamedGroup.x25519)) return ParseError.UnsupportedGroup;
                const key_len: u16 = (@as(u16, ext_data[2]) << 8) | @as(u16, ext_data[3]);
                if (key_len != 32 or ext_data.len != 4 + 32) return ParseError.BadExtension;
                @memcpy(&out.server_x25519_pub, ext_data[4..36]);
                got_keyshare = true;
            },
            else => {}, // ignore unknown / unused extensions
        }
    }

    if (negotiated_version != types.PROTOCOL_TLS_1_3) return ParseError.BadVersion;
    if (!got_keyshare) return ParseError.BadExtension;
    return out;
}

// === Outer record layer ===

/// Wrap a handshake payload in a TLSPlaintext record header. Returns
/// the total length (5 + payload.len). `out` must be at least
/// payload.len + 5 bytes.
pub fn wrapRecord(out: []u8, content_type: types.ContentType, payload: []const u8) usize {
    out[0] = @intFromEnum(content_type);
    out[1] = @intCast(types.PROTOCOL_TLS_1_2 >> 8);
    out[2] = @intCast(types.PROTOCOL_TLS_1_2 & 0xFF);
    out[3] = @intCast((payload.len >> 8) & 0xFF);
    out[4] = @intCast(payload.len & 0xFF);
    @memcpy(out[5..][0..payload.len], payload);
    return 5 + payload.len;
}
