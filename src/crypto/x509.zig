// X.509 v3 certificate parser. RFC 5280, just enough for what we need:
// extract the SubjectPublicKeyInfo (so we can verify a TLS 1.3
// CertificateVerify signature) and the cert's own signature value +
// algorithm + TBS byte range (for future chain validation).
//
// Certificate ::= SEQUENCE {
//     tbsCertificate       TBSCertificate,
//     signatureAlgorithm   AlgorithmIdentifier,
//     signature            BIT STRING
// }
//
// TBSCertificate ::= SEQUENCE {
//     version         [0] EXPLICIT Version DEFAULT v1,
//     serialNumber    CertificateSerialNumber,
//     signature       AlgorithmIdentifier,
//     issuer          Name,
//     validity        Validity,
//     subject         Name,
//     subjectPublicKeyInfo SubjectPublicKeyInfo,
//     issuerUniqueID  [1] IMPLICIT BIT STRING OPTIONAL,
//     subjectUniqueID [2] IMPLICIT BIT STRING OPTIONAL,
//     extensions      [3] EXPLICIT Extensions OPTIONAL
// }
//
// We deliberately DON'T:
//   - parse Name fields (issuer/subject) — chain matching can compare
//     raw DER if needed
//   - parse Validity (notBefore / notAfter) — wall-clock comparison
//     belongs in a separate validity check
//   - walk Extensions for SubjectAltName / BasicConstraints — those
//     are step 5b in the TLS arc
//
// All slices in the returned Certificate point into the input buffer;
// the input must outlive the Certificate.

const std = @import("std");
const asn1 = @import("asn1.zig");

pub const Error = error{
    BadCert,
    UnsupportedAlgorithm,
    BadEcPoint,
    BadTime,
} || asn1.Error;

/// Calendar date+time as parsed from an X.509 Validity field. Always UTC.
/// We keep it in this generic form rather than converting to a Unix
/// epoch here so x509.zig stays time.zig-agnostic — callers that care
/// about absolute time (chain validity check, audit logging) do the
/// conversion themselves.
pub const Time = struct {
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
};

pub const KeyAlgorithm = enum {
    ecdsa_p256,
    ecdsa_p384,
    rsa,
};

pub const PublicKey = union(KeyAlgorithm) {
    ecdsa_p256: EcdsaP256Key,
    ecdsa_p384: EcdsaP384Key,
    rsa: RsaKey,

    pub const EcdsaP256Key = struct {
        /// SEC1 uncompressed point: 0x04 || X || Y (65 bytes).
        sec1: [65]u8,
    };
    pub const EcdsaP384Key = struct {
        /// SEC1 uncompressed point: 0x04 || X || Y (97 bytes).
        sec1: [97]u8,
    };
    pub const RsaKey = struct {
        /// Modulus N as INTEGER value bytes (may have a leading 0x00 to
        /// disambiguate sign; consumer should strip if treating as
        /// magnitude).
        modulus: []const u8,
        /// Public exponent E as INTEGER value bytes (usually 0x010001).
        exponent: []const u8,
    };
};

pub const Certificate = struct {
    /// The full tbsCertificate TLV (tag+length+value). signatureValue
    /// authenticates exactly this byte range. Keep it for chain
    /// verification (caller hashes it).
    tbs_tlv: []const u8,

    /// Issuer Name field, full TLV (SEQUENCE...). Byte-equal to the
    /// signing cert's subject_tlv in a well-formed chain. Used for
    /// trust-store lookup at the chain top.
    issuer_tlv: []const u8,

    /// Subject Name field, full TLV. Trust store indexes by this
    /// (a chain link's issuer == next cert's subject).
    subject_tlv: []const u8,

    /// Cert's outer signatureAlgorithm OID (the one binding tbs ->
    /// signature). For chain verification this tells the verifier
    /// which scheme + hash to use.
    sig_alg_oid: []const u8,

    /// Cert's outer signature value (BIT STRING contents, unused-bits
    /// byte already stripped). For ECDSA this is a DER-encoded
    /// Ecdsa-Sig-Value SEQUENCE; for RSA it's the raw signature bytes.
    signature: []const u8,

    public_key: PublicKey,

    /// Inner `SEQUENCE OF Extension` TLV from the cert's [3] EXPLICIT
    /// Extensions field, or an empty slice if the cert carries no
    /// extensions. SAN / KeyUsage / BasicConstraints etc. live in here
    /// — callers walk on demand.
    extensions_tlv: []const u8,

    /// notBefore / notAfter from the Validity field, parsed from
    /// UTCTime (pre-2050) or GeneralizedTime (post-2050). Used by the
    /// chain verifier to reject expired or not-yet-valid certs.
    not_before: Time,
    not_after: Time,
};

/// Parse a Validity TIME element — either UTCTime (tag 0x17, 13 bytes
/// "YYMMDDHHMMSSZ") or GeneralizedTime (tag 0x18, 15 bytes
/// "YYYYMMDDHHMMSSZ"). Anything else (local-time variants, fractional
/// seconds, +/-HHMM offsets) is rejected — RFC 5280 says certificates
/// MUST use the Z-terminated form.
fn parseTime(p: *asn1.Parser) Error!Time {
    const v = try p.takeAny();
    var year: u16 = 0;
    var idx: usize = 0;
    if (v.tag == 0x17) {
        // UTCTime: YY MM DD HH MM SS Z
        if (v.value.len != 13 or v.value[12] != 'Z') return Error.BadTime;
        const yy = try twoDigit(v.value[0..2]);
        // RFC 5280 §4.1.2.5.1: YY < 50 → 20YY, else 19YY.
        year = if (yy < 50) 2000 + @as(u16, yy) else 1900 + @as(u16, yy);
        idx = 2;
    } else if (v.tag == 0x18) {
        // GeneralizedTime: YYYY MM DD HH MM SS Z
        if (v.value.len != 15 or v.value[14] != 'Z') return Error.BadTime;
        const y1 = try twoDigit(v.value[0..2]);
        const y2 = try twoDigit(v.value[2..4]);
        year = @as(u16, y1) * 100 + @as(u16, y2);
        idx = 4;
    } else return Error.BadTime;

    const month = try twoDigit(v.value[idx .. idx + 2]);
    const day = try twoDigit(v.value[idx + 2 .. idx + 4]);
    const hour = try twoDigit(v.value[idx + 4 .. idx + 6]);
    const minute = try twoDigit(v.value[idx + 6 .. idx + 8]);
    const second = try twoDigit(v.value[idx + 8 .. idx + 10]);
    if (month < 1 or month > 12 or day < 1 or day > 31 or hour > 23 or minute > 59 or second > 60) return Error.BadTime;
    return .{ .year = year, .month = month, .day = day, .hour = hour, .minute = minute, .second = second };
}

fn twoDigit(s: []const u8) Error!u8 {
    if (s.len < 2 or s[0] < '0' or s[0] > '9' or s[1] < '0' or s[1] > '9') return Error.BadTime;
    return (s[0] - '0') * 10 + (s[1] - '0');
}

pub fn parse(der: []const u8) Error!Certificate {
    var top = asn1.Parser.init(der);
    var outer = try top.takeSequence();

    // tbsCertificate: capture its full TLV for later hashing.
    const tbs_tlv = (try asn1.takeTlv(&outer, 0x30)).encoded;

    // signatureAlgorithm: SEQUENCE { OID, params }
    var sig_alg_seq = try outer.takeSequence();
    const sig_alg_oid = try sig_alg_seq.takeOid();
    // params (NULL for RSA, absent for ECDSA) — ignore.

    // signature BIT STRING
    const sig_bits = try outer.takeBitString();

    // Now parse tbsCertificate from its TLV's value. takeTlv gave us
    // both, so re-walk the value bytes.
    var tbs_outer = asn1.Parser.init(tbs_tlv);
    var tbs = try tbs_outer.takeSequence();

    // [0] EXPLICIT Version (optional). Bytes: A0 03 02 01 02 → v3.
    if (!tbs.isEmpty() and try tbs.peek() == 0xA0) {
        _ = try tbs.takeTag(0xA0);
    }
    _ = try tbs.takeInteger(); // serialNumber
    _ = try tbs.takeSequence(); // signature (algorithm) — repeated of outer
    const issuer_tlv = (try asn1.takeTlv(&tbs, 0x30)).encoded;
    var validity = try tbs.takeSequence();
    const not_before = try parseTime(&validity);
    const not_after = try parseTime(&validity);
    const subject_tlv = (try asn1.takeTlv(&tbs, 0x30)).encoded;

    // SubjectPublicKeyInfo ::= SEQUENCE {
    //   algorithm  AlgorithmIdentifier,
    //   subjectPublicKey BIT STRING
    // }
    var spki = try tbs.takeSequence();
    var spki_alg = try spki.takeSequence();
    const spki_alg_oid = try spki_alg.takeOid();

    // For ECDSA keys, the alg parameter carries the curve OID. For RSA
    // it's NULL. Stash a curve OID if present.
    var curve_oid: []const u8 = &[_]u8{};
    if (!spki_alg.isEmpty()) {
        const param = try spki_alg.takeAny();
        if (param.tag == 0x06) curve_oid = param.value;
        // anything else (including NULL 0x05): ignore
    }

    const pubkey_bits = try spki.takeBitString();

    var pk: PublicKey = undefined;
    if (asn1.oidEqual(spki_alg_oid, &asn1.oid_ec_public_key)) {
        if (asn1.oidEqual(curve_oid, &asn1.oid_prime256v1)) {
            if (pubkey_bits.len != 65 or pubkey_bits[0] != 0x04) return Error.BadEcPoint;
            var key: PublicKey.EcdsaP256Key = .{ .sec1 = undefined };
            @memcpy(&key.sec1, pubkey_bits);
            pk = .{ .ecdsa_p256 = key };
        } else if (asn1.oidEqual(curve_oid, &asn1.oid_secp384r1)) {
            if (pubkey_bits.len != 97 or pubkey_bits[0] != 0x04) return Error.BadEcPoint;
            var key: PublicKey.EcdsaP384Key = .{ .sec1 = undefined };
            @memcpy(&key.sec1, pubkey_bits);
            pk = .{ .ecdsa_p384 = key };
        } else {
            return Error.UnsupportedAlgorithm;
        }
    } else if (asn1.oidEqual(spki_alg_oid, &asn1.oid_rsa_encryption)) {
        // SubjectPublicKey BIT STRING wraps:
        //   RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
        var rsa_p = asn1.Parser.init(pubkey_bits);
        var rsa_seq = try rsa_p.takeSequence();
        const modulus = try rsa_seq.takeInteger();
        const exponent = try rsa_seq.takeInteger();
        pk = .{ .rsa = .{ .modulus = modulus, .exponent = exponent } };
    } else {
        return Error.UnsupportedAlgorithm;
    }

    // Optional [1] IMPLICIT issuerUniqueID, [2] IMPLICIT subjectUniqueID,
    // [3] EXPLICIT Extensions — we only care about [3]. Skip the others.
    // Inside [3] is a SEQUENCE OF Extension; we capture that inner SEQUENCE's
    // full TLV so callers can re-walk it without re-skipping the wrapper.
    var extensions_tlv: []const u8 = &[_]u8{};
    while (!tbs.isEmpty()) {
        const next_tag = try tbs.peek();
        if (next_tag == 0xA3) {
            const wrapper_body = try tbs.takeTag(0xA3);
            var inner = asn1.Parser.init(wrapper_body);
            const seq_tlv = try asn1.takeTlv(&inner, 0x30);
            extensions_tlv = seq_tlv.encoded;
            break;
        } else {
            _ = try tbs.takeAny();
        }
    }

    return .{
        .tbs_tlv = tbs_tlv,
        .issuer_tlv = issuer_tlv,
        .subject_tlv = subject_tlv,
        .sig_alg_oid = sig_alg_oid,
        .signature = sig_bits,
        .public_key = pk,
        .extensions_tlv = extensions_tlv,
        .not_before = not_before,
        .not_after = not_after,
    };
}
