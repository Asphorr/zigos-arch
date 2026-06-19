// TLS 1.3 wire-format constants. Numbers from RFC 8446. We deliberately
// list only the values we'll use — adding cipher suites or sig algs is
// a one-line append.

/// Outer record-layer content type (TLSPlaintext.type / TLSCiphertext.type).
pub const ContentType = enum(u8) {
    invalid = 0,
    change_cipher_spec = 20,
    alert = 21,
    handshake = 22,
    application_data = 23,
};

/// Inner handshake-message type (Handshake.msg_type).
pub const HandshakeType = enum(u8) {
    client_hello = 1,
    server_hello = 2,
    new_session_ticket = 4,
    encrypted_extensions = 8,
    certificate = 11,
    certificate_request = 13,
    certificate_verify = 15,
    finished = 20,
};

/// Cipher suite identifiers. We advertise + run ChaCha20-Poly1305 (software-
/// fast, no AES-NI dependency) and AES-128-GCM (mandatory-to-implement, so it
/// lets AES-only servers handshake) — both SHA-256, so one key schedule. AES-
/// 256-GCM (SHA-384) is listed for parsing only; we never offer it.
pub const CipherSuite = enum(u16) {
    aes_128_gcm_sha256 = 0x1301,
    aes_256_gcm_sha384 = 0x1302,
    chacha20_poly1305_sha256 = 0x1303,
    _,
};

/// TLS extension type. ClientHello sends a list; ServerHello echoes
/// the ones it chose to honor. The "_" enum tag means unknown values
/// don't panic on parse.
pub const ExtensionType = enum(u16) {
    server_name = 0,
    alpn = 16,
    supported_groups = 10,
    signature_algorithms = 13,
    record_size_limit = 28,
    supported_versions = 43,
    psk_key_exchange_modes = 45,
    key_share = 51,
    _,
};

/// Named group for ECDH key agreement. We offer x25519 and secp256r1
/// (NIST P-256) — see kex.zig for both keygen + scalarmult paths and
/// messages.zig for the key_share wire encoding. secp384r1 etc. would each
/// need their own entry here plus a curve in kex.zig.
pub const NamedGroup = enum(u16) {
    secp256r1 = 0x0017,
    x25519 = 0x001d,
    _,
};

/// Signature algorithms we'll accept in the server's CertificateVerify.
/// rsa_pkcs1_sha256 is needed for older intermediate CAs; ECDSA P-256
/// is what most modern leaf certs use; Ed25519 is rare in the wild
/// but trivially supported via std.crypto.
pub const SignatureScheme = enum(u16) {
    ecdsa_secp256r1_sha256 = 0x0403,
    ecdsa_secp384r1_sha384 = 0x0503,
    rsa_pss_rsae_sha256 = 0x0804,
    rsa_pss_rsae_sha384 = 0x0805,
    rsa_pss_rsae_sha512 = 0x0806,
    rsa_pkcs1_sha256 = 0x0401,
    ed25519 = 0x0807,
    _,
};

/// On-wire TLS version codes. TLS 1.3 records carry 0x0303 (TLS 1.2)
/// in the outer record for compatibility with middleboxes that block
/// unknown versions; the real 1.3 negotiation lives in the
/// supported_versions extension.
pub const PROTOCOL_TLS_1_2: u16 = 0x0303;
pub const PROTOCOL_TLS_1_3: u16 = 0x0304;

pub const TLS_RECORD_HEADER_SIZE: usize = 5;
pub const TLS_HANDSHAKE_HEADER_SIZE: usize = 4;
/// Maximum TLSPlaintext.fragment length per RFC 8446 §5.1. We use
/// this to size the receive buffer — a single record can't exceed it.
pub const MAX_TLS_FRAGMENT: usize = 16384;
