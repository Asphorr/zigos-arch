// ASN.1 DER (Distinguished Encoding Rules) parser. Just enough for the
// pieces of X.509 v3 we touch today: SEQUENCE / SET / INTEGER / OID /
// BIT STRING / OCTET STRING / context-tagged optionals.
//
// DER encodes each value as Tag-Length-Value:
//   Tag: 1 byte (we don't handle long-form tags >= 31; rare in X.509).
//        Bit 6 set = constructed (children parse as DER); else primitive.
//        Bits 7..6 = class. 00=universal, 10=context-specific, 11=private.
//   Length:
//     0x00..0x7F: length value directly.
//     0x81..0x84: top bit set + low 7 bits = how many length octets follow.
//     0x80     : indefinite (BER only; not allowed in DER, we reject).
//   Value: `length` bytes of content.
//
// All slices returned point INTO the caller's buffer — no allocation,
// no copy. Safe because we never reorder cert bytes.

const std = @import("std");

pub const Error = error{
    Truncated,
    BadTag,
    BadLength,
    NotImplemented,
};

/// Cursor over a DER-encoded byte slice. take* methods advance on
/// success and leave position unchanged on error.
pub const Parser = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn init(buf: []const u8) Parser {
        return .{ .buf = buf };
    }

    pub fn remaining(self: *const Parser) usize {
        return self.buf.len - self.pos;
    }

    pub fn isEmpty(self: *const Parser) bool {
        return self.pos >= self.buf.len;
    }

    /// Peek next byte without advancing.
    pub fn peek(self: *const Parser) Error!u8 {
        if (self.isEmpty()) return Error.Truncated;
        return self.buf[self.pos];
    }

    fn readByte(self: *Parser) Error!u8 {
        if (self.isEmpty()) return Error.Truncated;
        const b = self.buf[self.pos];
        self.pos += 1;
        return b;
    }

    fn readLength(self: *Parser) Error!usize {
        const first = try self.readByte();
        if (first <= 0x7F) return @as(usize, first);
        const n: usize = @intCast(first & 0x7F);
        // n=0 means indefinite (BER); n>4 is absurd for our use (>4 GB).
        if (n == 0 or n > 4) return Error.BadLength;
        var len: usize = 0;
        var i: usize = 0;
        while (i < n) : (i += 1) {
            len = (len << 8) | @as(usize, try self.readByte());
        }
        return len;
    }

    /// Take next element if it carries the expected tag byte. Returns
    /// the VALUE bytes (no tag, no length). Advances past the entire
    /// element on success.
    pub fn takeTag(self: *Parser, tag: u8) Error![]const u8 {
        const start = self.pos;
        const t = try self.readByte();
        if (t != tag) {
            self.pos = start;
            return Error.BadTag;
        }
        const len = try self.readLength();
        if (self.pos + len > self.buf.len) {
            self.pos = start;
            return Error.Truncated;
        }
        const v = self.buf[self.pos .. self.pos + len];
        self.pos += len;
        return v;
    }

    /// Take SEQUENCE (tag 0x30) and return a fresh Parser walking its
    /// children.
    pub fn takeSequence(self: *Parser) Error!Parser {
        const body = try self.takeTag(0x30);
        return Parser.init(body);
    }

    pub fn takeSet(self: *Parser) Error!Parser {
        const body = try self.takeTag(0x31);
        return Parser.init(body);
    }

    pub fn takeOid(self: *Parser) Error![]const u8 {
        return self.takeTag(0x06);
    }

    /// INTEGER value bytes, exactly as encoded (may start with 0x00 to
    /// disambiguate positive from negative — caller strips if needed).
    pub fn takeInteger(self: *Parser) Error![]const u8 {
        return self.takeTag(0x02);
    }

    /// BIT STRING content. DER prefixes the content with a single byte
    /// giving the number of unused bits in the final octet; for the
    /// places we use BIT STRING (cert signature, SPKI public key) that
    /// byte is always 0 and we strip it. If a future caller hits a
    /// non-zero unused-bits BIT STRING we return NotImplemented.
    pub fn takeBitString(self: *Parser) Error![]const u8 {
        const body = try self.takeTag(0x03);
        if (body.len < 1) return Error.BadLength;
        if (body[0] != 0) return Error.NotImplemented;
        return body[1..];
    }

    pub fn takeOctetString(self: *Parser) Error![]const u8 {
        return self.takeTag(0x04);
    }

    /// Take next element without checking its tag. Used for CHOICE
    /// fields (e.g. validity uses either UTCTime or GeneralizedTime)
    /// and for skipping over arbitrary optional bits.
    pub const AnyValue = struct { tag: u8, value: []const u8 };
    pub fn takeAny(self: *Parser) Error!AnyValue {
        const start = self.pos;
        const t = try self.readByte();
        const len = try self.readLength();
        if (self.pos + len > self.buf.len) {
            self.pos = start;
            return Error.Truncated;
        }
        const v = self.buf[self.pos .. self.pos + len];
        self.pos += len;
        return .{ .tag = t, .value = v };
    }

    /// Skip the next element regardless of tag.
    pub fn skip(self: *Parser) Error!void {
        _ = try self.takeAny();
    }

    /// If the next element has the given tag, take it; otherwise
    /// return null without advancing.
    pub fn takeOptional(self: *Parser, tag: u8) Error!?[]const u8 {
        if (self.isEmpty()) return null;
        if (self.buf[self.pos] != tag) return null;
        return try self.takeTag(tag);
    }
};

/// Element captured with both its full encoding (tag+length+value) and
/// its inner value. Used when a higher layer needs to hash the entire
/// TLV — e.g. TBSCertificate is the signed range of a cert.
pub const Tlv = struct {
    /// Full bytes: tag + length + value.
    encoded: []const u8,
    /// Value only.
    value: []const u8,
};

/// Take an element and return both its full TLV bytes (for hashing)
/// and its value (for parsing). Position advances past the element.
pub fn takeTlv(p: *Parser, expected_tag: u8) Error!Tlv {
    const start = p.pos;
    const value = try p.takeTag(expected_tag);
    return .{ .encoded = p.buf[start..p.pos], .value = value };
}

pub fn oidEqual(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

// ---------------------------------------------------------------------
// Well-known OIDs we test against. Each is the DER-encoded BODY of the
// OBJECT IDENTIFIER (without tag or length prefix), so they can be
// compared directly with the bytes Parser.takeOid returns.

/// 1.2.840.10045.2.1 — id-ecPublicKey
pub const oid_ec_public_key = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };

/// 1.2.840.10045.3.1.7 — prime256v1 / secp256r1 / P-256
pub const oid_prime256v1 = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };

/// 1.3.132.0.34 — secp384r1 / P-384
pub const oid_secp384r1 = [_]u8{ 0x2B, 0x81, 0x04, 0x00, 0x22 };

/// 1.2.840.10045.4.3.2 — ecdsa-with-SHA256
pub const oid_ecdsa_with_sha256 = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 };

/// 1.2.840.10045.4.3.3 — ecdsa-with-SHA384
pub const oid_ecdsa_with_sha384 = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03 };

/// 1.2.840.113549.1.1.1 — rsaEncryption
pub const oid_rsa_encryption = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };

/// 1.2.840.113549.1.1.10 — id-RSASSA-PSS
pub const oid_rsa_pss = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A };

/// 1.2.840.113549.1.1.11 — sha256WithRSAEncryption
pub const oid_sha256_with_rsa = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B };

/// 1.2.840.113549.1.1.12 — sha384WithRSAEncryption
pub const oid_sha384_with_rsa = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C };

/// 1.2.840.113549.1.1.13 — sha512WithRSAEncryption
pub const oid_sha512_with_rsa = [_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D };

/// 2.5.29.17 — subjectAltName (the X.509 v3 extension that carries
/// DNS names + IP addresses the cert is valid for).
pub const oid_subject_alt_name = [_]u8{ 0x55, 0x1D, 0x11 };
