// TLS 1.3 key schedule. Implements RFC 8446 §7.1 just deeply enough to
// derive the handshake traffic keys from the X25519 shared secret +
// transcript-hash-up-to-ServerHello.
//
// Why only handshake keys for now: those let us decrypt EE / Cert /
// CertVerify / Finished — the next thing the server sends after the
// plaintext ServerHello. Application-data keys come from a separate
// branch of the schedule that needs the *full* CH..server-Finished
// transcript hash, which we won't have until step 4.

const std = @import("std");

const Sha256 = std.crypto.hash.sha2.Sha256;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

/// HKDF-Expand-Label per RFC 8446 §7.1. The wire-format HkdfLabel is:
///   uint16 length
///   opaque label<7..255>   = "tls13 " ++ label
///   opaque context<0..255> = context
/// We build it on the stack (max ~80 bytes for our biggest label) and
/// hand it to HKDF-Expand as the `info` parameter.
pub fn hkdfExpandLabel(out: []u8, secret: [32]u8, label: []const u8, context: []const u8) void {
    var info: [256]u8 = undefined;
    var pos: usize = 0;

    // length (u16 BE)
    info[pos] = @intCast((out.len >> 8) & 0xFF);
    info[pos + 1] = @intCast(out.len & 0xFF);
    pos += 2;

    // label vector: prefix "tls13 " then caller's label, in a u8-length wrapper.
    const tls13_prefix = "tls13 ";
    const total_label_len = tls13_prefix.len + label.len;
    info[pos] = @intCast(total_label_len);
    pos += 1;
    @memcpy(info[pos..][0..tls13_prefix.len], tls13_prefix);
    pos += tls13_prefix.len;
    @memcpy(info[pos..][0..label.len], label);
    pos += label.len;

    // context vector: u8 length + bytes.
    info[pos] = @intCast(context.len);
    pos += 1;
    if (context.len > 0) {
        @memcpy(info[pos..][0..context.len], context);
        pos += context.len;
    }

    HkdfSha256.expand(out, info[0..pos], secret);
}

/// Derive-Secret(Secret, Label, Messages) per RFC 8446 §7.1.
/// Equivalent to HKDF-Expand-Label with the transcript hash as context
/// and SHA-256 digest length (32) as output length.
fn deriveSecret(out: *[32]u8, secret: [32]u8, label: []const u8, transcript_hash: [32]u8) void {
    hkdfExpandLabel(out, secret, label, &transcript_hash);
}

/// Snapshot of all the handshake-phase derived material we need. We
/// hang on to the traffic secrets (not just key/iv) because computing
/// the server Finished MAC and the application-traffic-secrets later
/// requires HKDF-Expand-Label off those.
pub const HandshakeKeys = struct {
    server_key: [32]u8,
    server_iv: [12]u8,
    server_seq: u64 = 0,
    client_key: [32]u8,
    client_iv: [12]u8,
    client_seq: u64 = 0,
    handshake_secret: [32]u8,
    server_hs_traffic_secret: [32]u8,
    client_hs_traffic_secret: [32]u8,
};

/// Build the full handshake key set from a shared X25519 secret plus
/// the transcript hash through ServerHello. RFC 8446 §7.1 ladder:
///
///   Early Secret = HKDF-Extract(0, 0)
///   Derived      = HKDF-Expand-Label(Early, "derived", H(""))
///   Handshake    = HKDF-Extract(Derived, DHE)
///   CHTS         = HKDF-Expand-Label(Handshake, "c hs traffic", H(CH..SH))
///   SHTS         = HKDF-Expand-Label(Handshake, "s hs traffic", H(CH..SH))
///   key/iv       = HKDF-Expand-Label(CHTS/SHTS, "key"/"iv", "")
pub fn deriveHandshakeKeys(shared_secret: [32]u8, transcript_hash: [32]u8) HandshakeKeys {
    // SHA-256("") = empty-string digest. Used as context for the
    // "derived" label since at that point we have no transcript yet.
    var empty_hash: [32]u8 = undefined;
    Sha256.hash("", &empty_hash, .{});

    // Early Secret: extract with zero salt and zero IKM. We don't do
    // PSK resumption so the IKM is just 32 zero bytes.
    const zero32 = [_]u8{0} ** 32;
    const early_secret: [32]u8 = HkdfSha256.extract(&zero32, &zero32);

    var derived1: [32]u8 = undefined;
    deriveSecret(&derived1, early_secret, "derived", empty_hash);

    // Handshake Secret: extract with derived as salt, DHE as IKM.
    const handshake_secret: [32]u8 = HkdfSha256.extract(&derived1, &shared_secret);

    var chts: [32]u8 = undefined;
    var shts: [32]u8 = undefined;
    deriveSecret(&chts, handshake_secret, "c hs traffic", transcript_hash);
    deriveSecret(&shts, handshake_secret, "s hs traffic", transcript_hash);

    var ck: [32]u8 = undefined;
    var civ: [12]u8 = undefined;
    var sk: [32]u8 = undefined;
    var siv: [12]u8 = undefined;
    hkdfExpandLabel(&ck, chts, "key", "");
    hkdfExpandLabel(&civ, chts, "iv", "");
    hkdfExpandLabel(&sk, shts, "key", "");
    hkdfExpandLabel(&siv, shts, "iv", "");

    return .{
        .server_key = sk,
        .server_iv = siv,
        .client_key = ck,
        .client_iv = civ,
        .handshake_secret = handshake_secret,
        .server_hs_traffic_secret = shts,
        .client_hs_traffic_secret = chts,
    };
}

/// Compute the Finished-message verify_data per RFC 8446 §4.4.4.
///   finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
///   verify_data  = HMAC(finished_key, transcript_hash)
/// BaseKey is the server_hs_traffic_secret for server Finished, client_hs_traffic_secret for ours.
pub fn computeFinishedMac(out: *[32]u8, traffic_secret: [32]u8, transcript_hash: [32]u8) void {
    var finished_key: [32]u8 = undefined;
    hkdfExpandLabel(&finished_key, traffic_secret, "finished", "");
    HmacSha256.create(out, &transcript_hash, &finished_key);
}

/// Application traffic keys. Used after handshake completion (after both
/// Finisheds). Derived from the master secret + transcript-hash through
/// server Finished.
pub const ApplicationKeys = struct {
    server_key: [32]u8,
    server_iv: [12]u8,
    server_seq: u64 = 0,
    client_key: [32]u8,
    client_iv: [12]u8,
    client_seq: u64 = 0,
    client_app_traffic_secret: [32]u8,
    server_app_traffic_secret: [32]u8,
};

/// Continue the RFC 8446 §7.1 key ladder past the Handshake Secret:
///
///   Derived       = HKDF-Expand-Label(Handshake, "derived", H(""))
///   Master Secret = HKDF-Extract(Derived, 0)
///   CATS          = HKDF-Expand-Label(Master, "c ap traffic", H(CH..serverFinished))
///   SATS          = HKDF-Expand-Label(Master, "s ap traffic", H(CH..serverFinished))
///   key / iv      = HKDF-Expand-Label(CATS|SATS, "key"|"iv", "")
pub fn deriveApplicationKeys(handshake_secret: [32]u8, transcript_through_server_finished: [32]u8) ApplicationKeys {
    var empty_hash: [32]u8 = undefined;
    Sha256.hash("", &empty_hash, .{});

    var derived2: [32]u8 = undefined;
    deriveSecret(&derived2, handshake_secret, "derived", empty_hash);

    const zero32 = [_]u8{0} ** 32;
    const master_secret: [32]u8 = HkdfSha256.extract(&derived2, &zero32);

    var cats: [32]u8 = undefined;
    var sats: [32]u8 = undefined;
    deriveSecret(&cats, master_secret, "c ap traffic", transcript_through_server_finished);
    deriveSecret(&sats, master_secret, "s ap traffic", transcript_through_server_finished);

    var ck: [32]u8 = undefined;
    var civ: [12]u8 = undefined;
    var sk: [32]u8 = undefined;
    var siv: [12]u8 = undefined;
    hkdfExpandLabel(&ck, cats, "key", "");
    hkdfExpandLabel(&civ, cats, "iv", "");
    hkdfExpandLabel(&sk, sats, "key", "");
    hkdfExpandLabel(&siv, sats, "iv", "");

    return .{
        .server_key = sk,
        .server_iv = siv,
        .client_key = ck,
        .client_iv = civ,
        .client_app_traffic_secret = cats,
        .server_app_traffic_secret = sats,
    };
}
