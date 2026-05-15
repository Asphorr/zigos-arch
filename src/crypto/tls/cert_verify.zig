// TLS 1.3 CertificateVerify signature verification (RFC 8446 §4.4.3).
//
// The server's CertificateVerify proves that whoever sent it has the
// private key matching the leaf cert's public key — without this
// check, anyone in the network path can substitute their own X25519
// keyshare and we'd derive shared secrets with them instead.
//
// Construction of the signed_data:
//   octet 0x20 × 64
//   "TLS 1.3, server CertificateVerify"
//   0x00
//   transcript_hash (CH .. Certificate, inclusive)
//
// The signature is over (a hash of) that signed_data, using the
// cert's public key. The signature_algorithm two-byte code on the
// wire tells us which scheme to use.

const std = @import("std");
const asn1 = @import("../asn1.zig");
const x509 = @import("../x509.zig");
const time = @import("../../time/time.zig");

const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const EcdsaP384Sha384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;
const Sha512 = std.crypto.hash.sha2.Sha512;
const RsaPss = std.crypto.Certificate.rsa.PSSSignature;
const RsaPkcs1 = std.crypto.Certificate.rsa.PKCS1v1_5Signature;
const RsaPublicKey = std.crypto.Certificate.rsa.PublicKey;

pub const Error = error{
    UnsupportedScheme,
    AlgorithmKeyMismatch,
    Truncated,
    InvalidSignature,
    BadCertMessage,
};

/// SignatureScheme codes from RFC 8446 §4.2.3. We list every value
/// servers commonly negotiate, even if we don't verify them yet, so
/// the diagnostic log can tell the user which scheme blocked us.
pub const Scheme = enum(u16) {
    ecdsa_secp256r1_sha256 = 0x0403,
    ecdsa_secp384r1_sha384 = 0x0503,
    rsa_pss_rsae_sha256 = 0x0804,
    rsa_pss_rsae_sha384 = 0x0805,
    rsa_pss_rsae_sha512 = 0x0806,
    ed25519 = 0x0807,
    rsa_pkcs1_sha256 = 0x0401, // legacy, banned in TLS 1.3 CertVerify but seen
    _,
};

pub const CONTEXT_SERVER: []const u8 = "TLS 1.3, server CertificateVerify";

/// Assemble (64 spaces || context || 0x00 || transcript_hash) into out.
/// Returns the length written. Caller's buffer must be at least
/// 64 + context.len + 1 + transcript_hash.len.
pub fn buildSignedData(out: []u8, context: []const u8, transcript_hash: []const u8) usize {
    var pos: usize = 0;
    var i: usize = 0;
    while (i < 64) : (i += 1) {
        out[pos] = 0x20;
        pos += 1;
    }
    @memcpy(out[pos..][0..context.len], context);
    pos += context.len;
    out[pos] = 0x00;
    pos += 1;
    @memcpy(out[pos..][0..transcript_hash.len], transcript_hash);
    pos += transcript_hash.len;
    return pos;
}

/// Verify a TLS 1.3 server CertificateVerify.
///   scheme: u16 SignatureScheme from the CV wire bytes
///   signature: raw signature bytes (DER ECDSA, or raw RSA)
///   transcript_hash: SHA-256 of (CH .. Certificate)
///   pk: parsed leaf cert's public key
pub fn verifyServer(
    scheme: u16,
    signature: []const u8,
    transcript_hash: []const u8,
    pk: x509.PublicKey,
) Error!void {
    // signed_data fits in 130 bytes for SHA-256 (64 + 33 + 1 + 32) or
    // 146 bytes for SHA-384. 256 leaves headroom.
    var signed_data: [256]u8 = undefined;
    const sd_len = buildSignedData(&signed_data, CONTEXT_SERVER, transcript_hash);

    switch (scheme) {
        @intFromEnum(Scheme.ecdsa_secp256r1_sha256) => {
            if (pk != .ecdsa_p256) return Error.AlgorithmKeyMismatch;
            const pub_key = EcdsaP256Sha256.PublicKey.fromSec1(&pk.ecdsa_p256.sec1) catch
                return Error.InvalidSignature;
            const sig = EcdsaP256Sha256.Signature.fromDer(signature) catch
                return Error.InvalidSignature;
            sig.verify(signed_data[0..sd_len], pub_key) catch
                return Error.InvalidSignature;
        },
        @intFromEnum(Scheme.ecdsa_secp384r1_sha384) => {
            if (pk != .ecdsa_p384) return Error.AlgorithmKeyMismatch;
            const pub_key = EcdsaP384Sha384.PublicKey.fromSec1(&pk.ecdsa_p384.sec1) catch
                return Error.InvalidSignature;
            const sig = EcdsaP384Sha384.Signature.fromDer(signature) catch
                return Error.InvalidSignature;
            sig.verify(signed_data[0..sd_len], pub_key) catch
                return Error.InvalidSignature;
        },
        @intFromEnum(Scheme.rsa_pss_rsae_sha256) => {
            if (pk != .rsa) return Error.AlgorithmKeyMismatch;
            try verifyRsaPss(pk.rsa, signature, signed_data[0..sd_len], Sha256);
        },
        @intFromEnum(Scheme.rsa_pss_rsae_sha384) => {
            if (pk != .rsa) return Error.AlgorithmKeyMismatch;
            try verifyRsaPss(pk.rsa, signature, signed_data[0..sd_len], Sha384);
        },
        @intFromEnum(Scheme.rsa_pss_rsae_sha512) => {
            if (pk != .rsa) return Error.AlgorithmKeyMismatch;
            try verifyRsaPss(pk.rsa, signature, signed_data[0..sd_len], Sha512);
        },
        else => return Error.UnsupportedScheme,
    }
}

/// RSASSA-PSS verify against an X.509 RSA key. Strips the leading
/// 0x00 sign-disambiguation byte that ASN.1 INTEGER encoding adds to
/// the modulus (and exponent), then hands the raw bytes to
/// std.crypto.Certificate.rsa.
///
/// PSSSignature.verify wants a comptime-sized array; we dispatch on
/// modulus byte length to handle the common 2048 / 3072 / 4096-bit
/// RSA keys without an allocator.
fn verifyRsaPss(rk: x509.PublicKey.RsaKey, sig: []const u8, msg: []const u8, comptime Hash: type) Error!void {
    var modulus = rk.modulus;
    if (modulus.len > 0 and modulus[0] == 0) modulus = modulus[1..];
    var exponent = rk.exponent;
    if (exponent.len > 0 and exponent[0] == 0) exponent = exponent[1..];

    const pub_key = RsaPublicKey.fromBytes(exponent, modulus) catch return Error.InvalidSignature;

    if (sig.len != modulus.len) return Error.InvalidSignature;

    switch (modulus.len) {
        256 => { // RSA-2048
            var sig_arr: [256]u8 = undefined;
            @memcpy(&sig_arr, sig);
            RsaPss.verify(256, sig_arr, msg, pub_key, Hash) catch return Error.InvalidSignature;
        },
        384 => { // RSA-3072
            var sig_arr: [384]u8 = undefined;
            @memcpy(&sig_arr, sig);
            RsaPss.verify(384, sig_arr, msg, pub_key, Hash) catch return Error.InvalidSignature;
        },
        512 => { // RSA-4096
            var sig_arr: [512]u8 = undefined;
            @memcpy(&sig_arr, sig);
            RsaPss.verify(512, sig_arr, msg, pub_key, Hash) catch return Error.InvalidSignature;
        },
        else => return Error.UnsupportedScheme,
    }
}

/// Match the SNI hostname we sent against the leaf cert's
/// SubjectAltName DNS entries. Returns true on match.
///
/// RFC 6125: SAN is authoritative if present; CN-based fallback is
/// deprecated and we don't do it. A cert with no SAN can never match
/// for HTTPS.
///
/// Wildcard rules: a "*.foo.bar" entry matches "a.foo.bar" but NOT
/// "a.b.foo.bar" (single-label wildcards only, leftmost only).
pub fn matchHostname(cert: x509.Certificate, hostname: []const u8) bool {
    if (cert.extensions_tlv.len == 0) return false;
    if (hostname.len == 0 or hostname.len > 253) return false;

    // Walk the SEQUENCE OF Extension. Each Extension: SEQUENCE { OID,
    // critical BOOL DEFAULT FALSE, extnValue OCTET STRING }.
    var ext_seq = asn1.Parser.init(cert.extensions_tlv);
    var ext_list = ext_seq.takeSequence() catch return false;
    while (!ext_list.isEmpty()) {
        var ext = ext_list.takeSequence() catch return false;
        const ext_oid = ext.takeOid() catch return false;
        // Optional critical BOOLEAN — peek and skip if present.
        if (!ext.isEmpty() and (ext.peek() catch 0) == 0x01) {
            _ = ext.takeTag(0x01) catch return false;
        }
        const ext_value = ext.takeOctetString() catch return false;
        if (!asn1.oidEqual(ext_oid, &asn1.oid_subject_alt_name)) continue;

        // SubjectAltName ::= GeneralNames ::= SEQUENCE OF GeneralName.
        // We only look at dNSName (context-specific [2] IMPLICIT IA5String,
        // wire tag 0x82). iPAddress + other variants are skipped.
        var san_parser = asn1.Parser.init(ext_value);
        var san_list = san_parser.takeSequence() catch return false;
        while (!san_list.isEmpty()) {
            const entry = san_list.takeAny() catch return false;
            if (entry.tag != 0x82) continue;
            if (dnsNameMatches(entry.value, hostname)) return true;
        }
        // We found the SAN extension and walked all entries; if none
        // matched, no point checking later extensions.
        return false;
    }
    return false;
}

fn dnsNameMatches(cert_name: []const u8, hostname: []const u8) bool {
    if (cert_name.len == 0) return false;

    // Wildcard pattern: must be "*.<suffix>", matches exactly one label
    // before the suffix. "*.foo.com" matches "bar.foo.com", NOT
    // "bar.baz.foo.com" and NOT "foo.com" itself.
    if (cert_name.len >= 2 and cert_name[0] == '*' and cert_name[1] == '.') {
        const suffix = cert_name[1..]; // ".foo.com"
        var first_dot: usize = 0;
        var found = false;
        for (hostname, 0..) |c, i| {
            if (c == '.') {
                first_dot = i;
                found = true;
                break;
            }
        }
        if (!found) return false;
        // The label before the dot must be non-empty.
        if (first_dot == 0) return false;
        return eqlCaseInsensitive(hostname[first_dot..], suffix);
    }

    return eqlCaseInsensitive(cert_name, hostname);
}

/// Reject the cert if the current wall-clock isn't inside its
/// [notBefore, notAfter] window. Returns true on OK, false on expired
/// or not-yet-valid. If the RTC hasn't initialized (time.now() returns
/// {0,0}), we skip the check — better to let TLS proceed than to fail
/// every connection on a system without a battery-backed clock.
pub fn checkValidity(cert: x509.Certificate) bool {
    const now = time.now();
    if (now.sec == 0) return true;
    const not_before_epoch = timeToUnix(cert.not_before);
    const not_after_epoch = timeToUnix(cert.not_after);
    if (now.sec < not_before_epoch) return false;
    if (now.sec > not_after_epoch) return false;
    return true;
}

/// Convert x509.Time (UTC calendar) → Unix epoch seconds. Uses the
/// same days-from-civil algorithm as src/time/time.zig (Howard
/// Hinnant), inlined here to avoid a kernel-internal time-module
/// dependency cycle.
fn timeToUnix(t: x509.Time) u64 {
    const days = daysFromCivil(t.year, t.month, t.day);
    if (days < 0) return 0;
    const secs_in_day: u64 = @as(u64, t.hour) * 3600 + @as(u64, t.minute) * 60 + @as(u64, t.second);
    return @as(u64, @intCast(days)) * 86400 + secs_in_day;
}

fn daysFromCivil(year: u16, month: u8, day: u8) i64 {
    const y_adj: i64 = if (month <= 2) @as(i64, year) - 1 else @as(i64, year);
    const era: i64 = @divFloor(if (y_adj >= 0) y_adj else y_adj - 399, 400);
    const yoe: u64 = @intCast(y_adj - era * 400);
    const m: u64 = @intCast(month);
    const d: u64 = @intCast(day);
    const doy: u64 = (153 * (if (m > 2) m - 3 else m + 9) + 2) / 5 + d - 1;
    const doe: u64 = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + @as(i64, @intCast(doe)) - 719468;
}

fn eqlCaseInsensitive(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        const xl = if (x >= 'A' and x <= 'Z') x + 32 else x;
        const yl = if (y >= 'A' and y <= 'Z') y + 32 else y;
        if (xl != yl) return false;
    }
    return true;
}

/// Extract the leaf certificate's DER bytes from the body of a TLS 1.3
/// Certificate handshake message. Skips the certificate_request_context
/// and the certificate_list length, then returns a slice into `body`
/// covering the first CertificateEntry's cert_data. Extensions and any
/// intermediates are left for the chain walker to consume later.
pub fn extractLeafDer(body: []const u8) Error![]const u8 {
    var it = try CertChainIter.init(body);
    if (try it.next()) |der| return der;
    return Error.BadCertMessage;
}

/// Iterator over CertificateEntry items in a TLS 1.3 Certificate
/// handshake message body. Yields each cert_data DER slice in order
/// (leaf first, root or anchor last). Skips the 2-byte extensions
/// field after each cert.
///
/// Wire layout (RFC 8446 §4.4.2):
///   opaque certificate_request_context<0..2^8-1>
///   CertificateEntry certificate_list<0..2^24-1>
/// CertificateEntry:
///   opaque cert_data<1..2^24-1>
///   Extension extensions<0..2^16-1>
pub const CertChainIter = struct {
    body: []const u8,
    pos: usize,
    end: usize,

    pub fn init(body: []const u8) Error!CertChainIter {
        if (body.len < 4) return Error.BadCertMessage;
        const ctx_len: usize = body[0];
        if (1 + ctx_len + 3 > body.len) return Error.BadCertMessage;
        const list_off = 1 + ctx_len;
        const list_len: usize =
            (@as(usize, body[list_off]) << 16) |
            (@as(usize, body[list_off + 1]) << 8) |
            @as(usize, body[list_off + 2]);
        const list_start = list_off + 3;
        if (list_start + list_len > body.len) return Error.BadCertMessage;
        return .{ .body = body, .pos = list_start, .end = list_start + list_len };
    }

    pub fn next(self: *CertChainIter) Error!?[]const u8 {
        if (self.pos >= self.end) return null;
        if (self.pos + 3 > self.end) return Error.BadCertMessage;
        const cert_len: usize =
            (@as(usize, self.body[self.pos]) << 16) |
            (@as(usize, self.body[self.pos + 1]) << 8) |
            @as(usize, self.body[self.pos + 2]);
        self.pos += 3;
        if (cert_len == 0 or self.pos + cert_len > self.end) return Error.BadCertMessage;
        const der = self.body[self.pos .. self.pos + cert_len];
        self.pos += cert_len;
        // CertificateEntry extensions: 2-byte length + bytes.
        if (self.pos + 2 > self.end) return Error.BadCertMessage;
        const ext_len: usize = (@as(usize, self.body[self.pos]) << 8) | @as(usize, self.body[self.pos + 1]);
        self.pos += 2 + ext_len;
        if (self.pos > self.end) return Error.BadCertMessage;
        return der;
    }
};

/// Verify one X.509 cert's signature against an issuer's public key.
///   For a chain link: issuer_pk = the next cert's public_key.
///   For a self-signed root: issuer_pk = cert.public_key.
/// The message being signed is `cert.tbs_tlv` exactly (no wrapping,
/// unlike TLS 1.3 CertificateVerify).
pub fn verifyCert(cert: x509.Certificate, issuer_pk: x509.PublicKey) Error!void {
    const oid = cert.sig_alg_oid;
    if (asn1.oidEqual(oid, &asn1.oid_sha256_with_rsa)) {
        if (issuer_pk != .rsa) return Error.AlgorithmKeyMismatch;
        try verifyRsaPkcs1(issuer_pk.rsa, cert.signature, cert.tbs_tlv, Sha256);
    } else if (asn1.oidEqual(oid, &asn1.oid_sha384_with_rsa)) {
        if (issuer_pk != .rsa) return Error.AlgorithmKeyMismatch;
        try verifyRsaPkcs1(issuer_pk.rsa, cert.signature, cert.tbs_tlv, Sha384);
    } else if (asn1.oidEqual(oid, &asn1.oid_sha512_with_rsa)) {
        if (issuer_pk != .rsa) return Error.AlgorithmKeyMismatch;
        try verifyRsaPkcs1(issuer_pk.rsa, cert.signature, cert.tbs_tlv, Sha512);
    } else if (asn1.oidEqual(oid, &asn1.oid_ecdsa_with_sha256)) {
        if (issuer_pk != .ecdsa_p256) return Error.AlgorithmKeyMismatch;
        const pub_key = EcdsaP256Sha256.PublicKey.fromSec1(&issuer_pk.ecdsa_p256.sec1) catch
            return Error.InvalidSignature;
        const sig = EcdsaP256Sha256.Signature.fromDer(cert.signature) catch
            return Error.InvalidSignature;
        sig.verify(cert.tbs_tlv, pub_key) catch return Error.InvalidSignature;
    } else if (asn1.oidEqual(oid, &asn1.oid_ecdsa_with_sha384)) {
        if (issuer_pk != .ecdsa_p384) return Error.AlgorithmKeyMismatch;
        const pub_key = EcdsaP384Sha384.PublicKey.fromSec1(&issuer_pk.ecdsa_p384.sec1) catch
            return Error.InvalidSignature;
        const sig = EcdsaP384Sha384.Signature.fromDer(cert.signature) catch
            return Error.InvalidSignature;
        sig.verify(cert.tbs_tlv, pub_key) catch return Error.InvalidSignature;
    } else {
        // rsa-pss with explicit params, Ed25519, GOST, etc. land here.
        // The OID-bytes log on the caller side lets us catch what's
        // showing up in practice and prioritize next.
        return Error.UnsupportedScheme;
    }
}

/// RSASSA-PKCS1-v1_5 verify against an X.509 RSA key. Almost the same
/// shape as verifyRsaPss but the underlying scheme is the older,
/// deterministic one used in most cert SIGNATURES (CertificateVerify
/// in TLS 1.3 mandates PSS, but the certs themselves are typically
/// still signed with PKCS1-v1_5 because cross-vendor support).
fn verifyRsaPkcs1(rk: x509.PublicKey.RsaKey, sig: []const u8, msg: []const u8, comptime Hash: type) Error!void {
    var modulus = rk.modulus;
    if (modulus.len > 0 and modulus[0] == 0) modulus = modulus[1..];
    var exponent = rk.exponent;
    if (exponent.len > 0 and exponent[0] == 0) exponent = exponent[1..];

    const pub_key = RsaPublicKey.fromBytes(exponent, modulus) catch return Error.InvalidSignature;
    if (sig.len != modulus.len) return Error.InvalidSignature;

    switch (modulus.len) {
        256 => {
            var sig_arr: [256]u8 = undefined;
            @memcpy(&sig_arr, sig);
            RsaPkcs1.verify(256, sig_arr, msg, pub_key, Hash) catch return Error.InvalidSignature;
        },
        384 => {
            var sig_arr: [384]u8 = undefined;
            @memcpy(&sig_arr, sig);
            RsaPkcs1.verify(384, sig_arr, msg, pub_key, Hash) catch return Error.InvalidSignature;
        },
        512 => {
            var sig_arr: [512]u8 = undefined;
            @memcpy(&sig_arr, sig);
            RsaPkcs1.verify(512, sig_arr, msg, pub_key, Hash) catch return Error.InvalidSignature;
        },
        else => return Error.UnsupportedScheme,
    }
}
