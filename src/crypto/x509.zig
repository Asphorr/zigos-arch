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
} || asn1.Error;

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
};

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
    _ = try tbs.takeSequence(); // validity
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
    };
}
