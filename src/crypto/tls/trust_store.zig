// Trust store: Mozilla NSS root CA bundle embedded at compile time.
//
// At boot, we walk the embedded PEM bundle once, base64-decode every
// "-----BEGIN CERTIFICATE-----" block into a fixed DER pool, parse
// each cert with x509, and record (subject_tlv, public_key) for trust
// anchor lookup.
//
// Chain validation uses this at the TOP of the cert chain: take the
// topmost cert's `issuer_tlv` and call `lookup(issuer_tlv)`. If found,
// verify the top cert's signature against the returned public key. If
// the top cert is self-signed AND in the store, we end up verifying
// against itself; that's fine because the byte-identical pubkey is
// what's in the trust store.
//
// Sizes are BSS-static because we run freestanding with no allocator:
//   DER pool: 192 KB headroom for the ~150 cert × ~1.5 KB DER bundle
//   Root index: up to MAX_ROOTS entries, each ~120 bytes
// Mozilla's curl-bundle as of 2025 is ~150 certs / ~165 KB decoded;
// the limits above leave room for the next several years of growth.

const std = @import("std");
const debug = @import("../../debug/debug.zig");
const x509 = @import("../x509.zig");

/// Embedded Mozilla CA bundle in PEM format. Refreshed from the host
/// system's /etc/ssl/certs/ca-certificates.crt; update by re-running
/// `scp zigvm:/etc/ssl/certs/ca-certificates.crt src/crypto/tls/ca-bundle.pem`.
/// Lives inside the package (not vendor/) because @embedFile rejects
/// paths that escape the build root.
const PEM_BUNDLE = @embedFile("ca-bundle.pem");

const POOL_SIZE: usize = 192 * 1024;
var der_pool: [POOL_SIZE]u8 = undefined;
var der_pool_used: usize = 0;

const MAX_ROOTS: usize = 200;

const Root = struct {
    subject_tlv: []const u8,
    public_key: x509.PublicKey,
};

var roots: [MAX_ROOTS]Root = undefined;
var root_count: usize = 0;
var initialized: bool = false;
var bad_count: u32 = 0;

const BEGIN_MARKER: []const u8 = "-----BEGIN CERTIFICATE-----";
const END_MARKER: []const u8 = "-----END CERTIFICATE-----";

/// Walk the embedded PEM bundle, decode + parse every cert, and
/// populate the trust anchor index. Safe to call more than once; later
/// calls are no-ops.
pub fn init() void {
    if (initialized) return;
    initialized = true;

    const decoder = std.base64.standard.decoderWithIgnore(" \r\n\t");
    var pem_pos: usize = 0;
    while (pem_pos < PEM_BUNDLE.len and root_count < MAX_ROOTS) {
        const begin_off = std.mem.indexOfPos(u8, PEM_BUNDLE, pem_pos, BEGIN_MARKER) orelse break;
        const body_start = begin_off + BEGIN_MARKER.len;
        const end_off = std.mem.indexOfPos(u8, PEM_BUNDLE, body_start, END_MARKER) orelse break;
        pem_pos = end_off + END_MARKER.len;

        const body = PEM_BUNDLE[body_start..end_off];

        const upper = decoder.calcSizeUpperBound(body.len) catch {
            bad_count += 1;
            continue;
        };
        if (der_pool_used + upper > der_pool.len) {
            debug.klog("[trust] DER pool exhausted at root {d}; skipping rest\n", .{root_count});
            break;
        }
        const dst = der_pool[der_pool_used .. der_pool_used + upper];
        const actual_len = decoder.decode(dst, body) catch {
            bad_count += 1;
            continue;
        };

        const der = der_pool[der_pool_used .. der_pool_used + actual_len];
        const c = x509.parse(der) catch {
            // Cert had something we don't understand (e.g. unusual
            // pubkey algorithm). Skip and roll back the DER pool so the
            // next root reuses the space.
            bad_count += 1;
            continue;
        };

        roots[root_count] = .{
            .subject_tlv = c.subject_tlv,
            .public_key = c.public_key,
        };
        root_count += 1;
        der_pool_used += actual_len;
    }

    debug.klog("[trust] loaded {d} root CAs ({d} skipped), DER pool used {d} KB / {d} KB\n", .{
        root_count, bad_count, der_pool_used / 1024, der_pool.len / 1024,
    });
}

/// Search the trust store for a root whose subject DN bytes equal the
/// given issuer DN bytes. Returns the matching root's public key,
/// or null if no root matches.
///
/// Byte equality works because RFC 5280 §4.1.2.4 requires Name fields
/// to use DER (canonical) encoding, so a CA's subject as published in
/// the root cert matches byte-for-byte with the issuer field of any
/// cert it signs.
pub fn lookup(issuer_tlv: []const u8) ?x509.PublicKey {
    var i: usize = 0;
    while (i < root_count) : (i += 1) {
        if (std.mem.eql(u8, roots[i].subject_tlv, issuer_tlv)) {
            return roots[i].public_key;
        }
    }
    return null;
}

pub fn count() usize {
    return root_count;
}
