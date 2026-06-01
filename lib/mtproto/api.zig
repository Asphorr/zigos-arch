//! High-level Telegram API layer (schema layer 225) — the TL bodies that ride
//! inside the encrypted session for login. Pure (std + tl only) so it's
//! `zig test`-able natively; every constructor id is verified against the
//! official tdesktop schema (and the MTProto-core ids by CRC32), and the
//! serialization is byte-pinned to an independent Python TL oracle.
//!
//! What we send:
//!   invokeWithLayer#da9b0d0d layer:int query  — wraps the FIRST query
//!     initConnection#c1cd5ea9 flags:# api_id device_model .. lang_code query
//!       auth.sendCode#a677244f phone api_id api_hash settings:CodeSettings
//!         codeSettings#ad253d78 flags:#            (flags = 0, no options)
//!   auth.signIn#8d52a951 flags:# phone phone_code_hash phone_code  (bare)
//!   auth.exportLoginToken#b7e085fe api_id api_hash except_ids  — QR login
//!   auth.importLoginToken#95ac5ce4 token                       — QR DC migrate
//!
//! What we parse out of an rpc_result:
//!   auth.sentCode#5e002502 flags:# type:auth.SentCodeType phone_code_hash ...
//!   auth.loginToken#629f1980 / loginTokenMigrateTo / loginTokenSuccess
//!   auth.authorization#2ea2c0d4 ...                  -> logged in
//!   auth.authorizationSignUpRequired#44747e9a ...    -> new number
//!   rpc_error#2144ca19 error_code:int error_message:string

const std = @import("std");
const tl = @import("tl.zig");

pub const Error = error{ TooBig, Malformed, UnexpectedCtor, AlreadyAuthorized };

pub const LAYER: i32 = 225;

// Identity advertised in initConnection (cosmetic; the server just records it).
const DEVICE_MODEL = "ZigOS";
const SYSTEM_VERSION = "1.0";
const APP_VERSION = "0.1";
const SYSTEM_LANG = "en";
const LANG_PACK = "";
const LANG_CODE = "en";

// --- constructor ids (tdesktop schema layer 225; core ids CRC32-verified) ---
const C_INVOKE_WITH_LAYER: u32 = 0xda9b0d0d;
const C_INIT_CONNECTION: u32 = 0xc1cd5ea9;
const C_AUTH_SEND_CODE: u32 = 0xa677244f;
const C_CODE_SETTINGS: u32 = 0xad253d78;
const C_AUTH_SIGN_IN: u32 = 0x8d52a951;
const C_AUTH_RESEND_CODE: u32 = 0xcae47523;
const C_AUTH_SENT_CODE: u32 = 0x5e002502;
const C_AUTH_SENT_CODE_SUCCESS: u32 = 0x2390fe44;
const C_RPC_ERROR: u32 = 0x2144ca19;
pub const C_AUTH_AUTHORIZATION: u32 = 0x2ea2c0d4;
pub const C_AUTH_AUTHORIZATION_SIGNUP: u32 = 0x44747e9a;

// QR login (auth.LoginToken flow) — ids verified against the tdesktop schema.
const C_AUTH_EXPORT_LOGIN_TOKEN: u32 = 0xb7e085fe;
const C_AUTH_IMPORT_LOGIN_TOKEN: u32 = 0x95ac5ce4;
const C_AUTH_LOGIN_TOKEN: u32 = 0x629f1980;
const C_AUTH_LOGIN_TOKEN_MIGRATE: u32 = 0x068e9916; // schema prints it as #68e9916
const C_AUTH_LOGIN_TOKEN_SUCCESS: u32 = 0x390d5c5e;
pub const C_UPDATE_LOGIN_TOKEN: u32 = 0x564fe691;

// auth.SentCodeType variants — needed only to skip the boxed `type` field and
// reach phone_code_hash.
const T_APP: u32 = 0x3dbb5986; // length:int
const T_SMS: u32 = 0xc000bba2; // length:int
const T_CALL: u32 = 0x5353e5a7; // length:int
const T_FLASH_CALL: u32 = 0xab03c6d9; // pattern:string
const T_MISSED_CALL: u32 = 0x82006484; // prefix:string length:int
const T_EMAIL_CODE: u32 = 0xf450f59b; // flags:# .. email_pattern:string length:int [int][int]
const T_SETUP_EMAIL: u32 = 0xa5491dea; // flags:# (apple/google = true)
const T_FRAGMENT_SMS: u32 = 0xd9565c39; // url:string length:int
const T_FIREBASE_SMS: u32 = 0x009fd736; // flags:# [bytes][long+bytes][string+int] length:int
const T_SMS_WORD: u32 = 0xa416ac81; // flags:# [beginning:string]
const T_SMS_PHRASE: u32 = 0xb37794af; // flags:# [beginning:string]

/// Write the `invokeWithLayer` + `initConnection` header that must precede the
/// FIRST query on a fresh connection (advertises our layer + device identity).
/// The caller appends the wrapped query immediately after.
fn writeInvokeInit(w: *tl.Writer, api_id: i32) Error!void {
    w.writeU32(C_INVOKE_WITH_LAYER) catch return error.TooBig;
    w.writeInt(LAYER) catch return error.TooBig;
    w.writeU32(C_INIT_CONNECTION) catch return error.TooBig;
    w.writeInt(0) catch return error.TooBig; // initConnection flags (no proxy/params)
    w.writeInt(api_id) catch return error.TooBig;
    w.writeBytes(DEVICE_MODEL) catch return error.TooBig;
    w.writeBytes(SYSTEM_VERSION) catch return error.TooBig;
    w.writeBytes(APP_VERSION) catch return error.TooBig;
    w.writeBytes(SYSTEM_LANG) catch return error.TooBig;
    w.writeBytes(LANG_PACK) catch return error.TooBig;
    w.writeBytes(LANG_CODE) catch return error.TooBig;
}

/// Serialize `auth.sendCode` wrapped in `initConnection` + `invokeWithLayer`
/// (the first query on a fresh connection must carry initConnection). Returns
/// the TL body to hand to session.buildEncrypted as `data`.
pub fn buildSendCode(out: []u8, api_id: i32, api_hash: []const u8, phone: []const u8) Error![]const u8 {
    var w = tl.Writer.init(out);
    try writeInvokeInit(&w, api_id);
    // query = auth.sendCode
    w.writeU32(C_AUTH_SEND_CODE) catch return error.TooBig;
    w.writeBytes(phone) catch return error.TooBig;
    w.writeInt(api_id) catch return error.TooBig;
    w.writeBytes(api_hash) catch return error.TooBig;
    w.writeU32(C_CODE_SETTINGS) catch return error.TooBig;
    w.writeInt(0) catch return error.TooBig; // codeSettings flags (all defaults)
    return w.written();
}

/// Serialize a bare `auth.signIn` (flags bit0 set = phone_code present).
pub fn buildSignIn(out: []u8, phone: []const u8, phone_code_hash: []const u8, code: []const u8) Error![]const u8 {
    var w = tl.Writer.init(out);
    w.writeU32(C_AUTH_SIGN_IN) catch return error.TooBig;
    w.writeInt(1) catch return error.TooBig; // flags: phone_code present (bit 0)
    w.writeBytes(phone) catch return error.TooBig;
    w.writeBytes(phone_code_hash) catch return error.TooBig;
    w.writeBytes(code) catch return error.TooBig;
    return w.written();
}

/// Serialize `auth.resendCode` (flags=0, no reason) — forces Telegram to send
/// the code via the NEXT channel (typically SMS/call) when the first didn't land.
pub fn buildResendCode(out: []u8, phone: []const u8, phone_code_hash: []const u8) Error![]const u8 {
    var w = tl.Writer.init(out);
    w.writeU32(C_AUTH_RESEND_CODE) catch return error.TooBig;
    w.writeInt(0) catch return error.TooBig; // flags
    w.writeBytes(phone) catch return error.TooBig;
    w.writeBytes(phone_code_hash) catch return error.TooBig;
    return w.written();
}

/// Serialize `auth.exportLoginToken` — request (or refresh) a QR-login token.
/// `wrap_init` wraps it in initConnection+invokeWithLayer: set it for the FIRST
/// query on a connection, clear it when re-polling the same connection.
/// `except_ids` is sent empty (we have no already-authorized user ids to skip).
pub fn buildExportLoginToken(out: []u8, api_id: i32, api_hash: []const u8, wrap_init: bool) Error![]const u8 {
    var w = tl.Writer.init(out);
    if (wrap_init) try writeInvokeInit(&w, api_id);
    w.writeU32(C_AUTH_EXPORT_LOGIN_TOKEN) catch return error.TooBig;
    w.writeInt(api_id) catch return error.TooBig;
    w.writeBytes(api_hash) catch return error.TooBig;
    w.writeU32(tl.VECTOR_CTOR) catch return error.TooBig; // except_ids: Vector<long>
    w.writeInt(0) catch return error.TooBig; // (empty)
    return w.written();
}

/// Serialize `auth.importLoginToken` — exchange a migrated token for the
/// authorization on the target DC. `wrap_init` for the FIRST query on that DC's
/// fresh connection. (importLoginToken itself carries only the token.)
pub fn buildImportLoginToken(out: []u8, token: []const u8, api_id: i32, wrap_init: bool) Error![]const u8 {
    var w = tl.Writer.init(out);
    if (wrap_init) try writeInvokeInit(&w, api_id);
    w.writeU32(C_AUTH_IMPORT_LOGIN_TOKEN) catch return error.TooBig;
    w.writeBytes(token) catch return error.TooBig;
    return w.written();
}

/// Wrap an already-serialized BARE query in invokeWithLayer + initConnection.
/// Use this for the FIRST query on a fresh connection that isn't itself a login
/// call — e.g. resuming a persisted session, where the first thing we send is a
/// plain `users.getUsers([inputUserSelf])` probe. The server requires the very
/// first API call on a connection to carry initConnection; subsequent calls are
/// sent bare.
pub fn buildInitWrapped(out: []u8, api_id: i32, query: []const u8) Error![]const u8 {
    var w = tl.Writer.init(out);
    try writeInvokeInit(&w, api_id);
    w.writeRaw(query) catch return error.TooBig;
    return w.written();
}

/// The three shapes of an `auth.LoginToken` result.
pub const LoginToken = union(enum) {
    /// loginToken#629f1980 — show this token as a QR; poll again before `expires`.
    pending: struct { expires: i32, token: []const u8 },
    /// loginTokenMigrateTo#068e9916 — reconnect to `dc_id`, then importLoginToken.
    migrate: struct { dc_id: i32, token: []const u8 },
    /// loginTokenSuccess#390d5c5e — logged in; the slice is the boxed
    /// auth.Authorization object (hand it to `classifyAuth`).
    success: []const u8,
};

/// Parse an `auth.LoginToken` result object (the auth.exportLoginToken reply).
pub fn parseLoginToken(obj: []const u8) Error!LoginToken {
    var r = tl.Reader.init(obj);
    switch (r.readU32() catch return error.Malformed) {
        C_AUTH_LOGIN_TOKEN => {
            const expires = r.readInt() catch return error.Malformed;
            const token = r.readBytes() catch return error.Malformed;
            return .{ .pending = .{ .expires = expires, .token = token } };
        },
        C_AUTH_LOGIN_TOKEN_MIGRATE => {
            const dc_id = r.readInt() catch return error.Malformed;
            const token = r.readBytes() catch return error.Malformed;
            return .{ .migrate = .{ .dc_id = dc_id, .token = token } };
        },
        C_AUTH_LOGIN_TOKEN_SUCCESS => return .{ .success = r.buf[r.pos..] },
        else => return error.UnexpectedCtor,
    }
}

pub const SentCode = struct { phone_code_hash: []const u8, type_ctor: u32 };

/// Parse an `auth.SentCode` result object, returning phone_code_hash + the
/// delivery-type constructor (so the caller can report where the code went).
pub fn parseSentCode(obj: []const u8) Error!SentCode {
    var r = tl.Reader.init(obj);
    switch (r.readU32() catch return error.Malformed) {
        C_AUTH_SENT_CODE => {
            _ = r.readU32() catch return error.Malformed; // flags
            const tctor = try skipSentCodeType(&r); // type (variable length)
            const hash = r.readBytes() catch return error.Malformed;
            return .{ .phone_code_hash = hash, .type_ctor = tctor };
        },
        C_AUTH_SENT_CODE_SUCCESS => return error.AlreadyAuthorized, // code pre-verified
        else => return error.UnexpectedCtor,
    }
}

/// Human name for an auth.SentCodeType constructor — where the code was sent.
pub fn sentCodeTypeName(ctor: u32) []const u8 {
    return switch (ctor) {
        T_APP => "the Telegram app (the '777000' service chat) — NOT SMS",
        T_SMS, T_FRAGMENT_SMS => "SMS",
        T_CALL => "a phone call",
        T_MISSED_CALL => "a missed call (the code is the calling number)",
        T_FLASH_CALL => "a flash call",
        T_FIREBASE_SMS => "SMS (Firebase)",
        T_EMAIL_CODE => "email",
        else => "another channel",
    };
}

/// Advance `r` past one boxed `auth.SentCodeType`; returns its constructor id.
fn skipSentCodeType(r: *tl.Reader) Error!u32 {
    const ctor = r.readU32() catch return error.Malformed;
    switch (ctor) {
        T_APP, T_SMS, T_CALL => _ = r.readInt() catch return error.Malformed,
        T_FLASH_CALL => _ = r.readBytes() catch return error.Malformed,
        T_MISSED_CALL, T_FRAGMENT_SMS => {
            _ = r.readBytes() catch return error.Malformed; // prefix / url
            _ = r.readInt() catch return error.Malformed; // length
        },
        T_EMAIL_CODE => {
            const f = r.readU32() catch return error.Malformed;
            _ = r.readBytes() catch return error.Malformed; // email_pattern
            _ = r.readInt() catch return error.Malformed; // length
            if (f & (1 << 3) != 0) _ = r.readInt() catch return error.Malformed;
            if (f & (1 << 4) != 0) _ = r.readInt() catch return error.Malformed;
        },
        T_SETUP_EMAIL => _ = r.readU32() catch return error.Malformed, // flags only
        T_FIREBASE_SMS => {
            const f = r.readU32() catch return error.Malformed;
            if (f & (1 << 0) != 0) _ = r.readBytes() catch return error.Malformed; // nonce
            if (f & (1 << 2) != 0) {
                _ = r.readLong() catch return error.Malformed; // play_integrity_project_id
                _ = r.readBytes() catch return error.Malformed; // play_integrity_nonce
            }
            if (f & (1 << 1) != 0) {
                _ = r.readBytes() catch return error.Malformed; // receipt
                _ = r.readInt() catch return error.Malformed; // push_timeout
            }
            _ = r.readInt() catch return error.Malformed; // length
        },
        T_SMS_WORD, T_SMS_PHRASE => {
            const f = r.readU32() catch return error.Malformed;
            if (f & (1 << 0) != 0) _ = r.readBytes() catch return error.Malformed; // beginning
        },
        else => return error.UnexpectedCtor,
    }
    return ctor;
}

pub const RpcError = struct { code: i32, message: []const u8 };

pub fn isRpcError(obj: []const u8) bool {
    return obj.len >= 4 and std.mem.readInt(u32, obj[0..4], .little) == C_RPC_ERROR;
}

pub fn parseRpcError(obj: []const u8) Error!RpcError {
    var r = tl.Reader.init(obj);
    if ((r.readU32() catch return error.Malformed) != C_RPC_ERROR) return error.UnexpectedCtor;
    const code = r.readInt() catch return error.Malformed;
    const msg = r.readBytes() catch return error.Malformed;
    return .{ .code = code, .message = msg };
}

pub const AuthOutcome = enum { logged_in, signup_required, unexpected };

/// Classify an `auth.Authorization` result object (the auth.signIn reply).
pub fn classifyAuth(obj: []const u8) AuthOutcome {
    if (obj.len < 4) return .unexpected;
    return switch (std.mem.readInt(u32, obj[0..4], .little)) {
        C_AUTH_AUTHORIZATION => .logged_in,
        C_AUTH_AUTHORIZATION_SIGNUP => .signup_required,
        else => .unexpected,
    };
}

// =====================================================================
// Tests — zig test lib/mtproto/api.zig
//
// Serialization is byte-pinned to an independent Python TL oracle over a fixed
// vector (api_id=12345, api_hash="0123..", phone="+9996621234", layer 225).

fn hexN(comptime n: usize, comptime s: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

fn expectHex(actual: []const u8, comptime hexstr: []const u8) !void {
    const exp = hexN(hexstr.len / 2, hexstr);
    try std.testing.expectEqualSlices(u8, &exp, actual);
}

test "buildSendCode matches the TL oracle (invokeWithLayer+initConnection+sendCode)" {
    var out: [512]u8 = undefined;
    const msg = try buildSendCode(&out, 12345, "0123456789abcdef0123456789abcdef", "+9996621234");
    try expectHex(msg, "0d0d9bdae1000000a95ecdc10000000039300000" ++
        "055a69674f53000003312e3003302e3102656e000000000002656e00" ++
        "4f2477a60b2b393939363632313233343930000020303132333435363738396162636465663031323334353637383961626364656600000078" ++
        "3d25ad00000000");
}

test "buildSignIn matches the TL oracle" {
    var out: [128]u8 = undefined;
    const msg = try buildSignIn(&out, "+9996621234", "abcdef0123", "22222");
    try expectHex(msg, "51a9528d010000000b2b393939363632313233340a61626364656630313233000532323232320000");
}

test "buildResendCode matches the TL oracle" {
    var out: [64]u8 = undefined;
    const msg = try buildResendCode(&out, "+9996621234", "abcdef0123");
    try expectHex(msg, "2375e4ca000000000b2b393939363632313233340a6162636465663031323300");
}

test "parseSentCode extracts phone_code_hash (type = App)" {
    const obj = hexN(32, "0225005e000000008659bb3d050000000c434f4445484153485f415050000000");
    const sc = try parseSentCode(&obj);
    try std.testing.expectEqualStrings("CODEHASH_APP", sc.phone_code_hash);
    try std.testing.expectEqual(@as(u32, 0x3dbb5986), sc.type_ctor); // sentCodeTypeApp
}

test "parseSentCode skips a variable-length type (MissedCall: prefix+length)" {
    const obj = hexN(36, "0225005e0000000084640082062b393939363600060000000b434f4445484153485f4d43");
    const sc = try parseSentCode(&obj);
    try std.testing.expectEqualStrings("CODEHASH_MC", sc.phone_code_hash);
    try std.testing.expectEqual(@as(u32, 0x82006484), sc.type_ctor); // sentCodeTypeMissedCall
}

test "parseRpcError reads code + message" {
    const obj = hexN(24, "19ca4421a40100000d464c4f4f445f574149545f33300000");
    try std.testing.expect(isRpcError(&obj));
    const e = try parseRpcError(&obj);
    try std.testing.expectEqual(@as(i32, 420), e.code);
    try std.testing.expectEqualStrings("FLOOD_WAIT_30", e.message);
}

test "classifyAuth distinguishes logged-in / signup / unexpected" {
    try std.testing.expectEqual(AuthOutcome.logged_in, classifyAuth(&hexN(4, "d4c0a22e")));
    try std.testing.expectEqual(AuthOutcome.signup_required, classifyAuth(&hexN(4, "9a7e7444")));
    try std.testing.expectEqual(AuthOutcome.unexpected, classifyAuth(&hexN(4, "deadbeef")));
}

test "buildExportLoginToken matches the TL oracle (wrapped + bare)" {
    var out: [512]u8 = undefined;
    const wrapped = try buildExportLoginToken(&out, 12345, "0123456789abcdef0123456789abcdef", true);
    try expectHex(wrapped, "0d0d9bdae1000000a95ecdc10000000039300000" ++
        "055a69674f53000003312e3003302e3102656e000000000002656e00" ++
        "fe85e0b73930000020303132333435363738396162636465663031323334353637383961626364656600000015c4b51c00000000");
    var out2: [128]u8 = undefined;
    const bare = try buildExportLoginToken(&out2, 12345, "0123456789abcdef0123456789abcdef", false);
    try expectHex(bare, "fe85e0b73930000020303132333435363738396162636465663031323334353637383961626364656600000015c4b51c00000000");
}

test "buildImportLoginToken matches the TL oracle (bare)" {
    var out: [64]u8 = undefined;
    const msg = try buildImportLoginToken(&out, &hexN(16, "00112233445566778899aabbccddeeff"), 12345, false);
    try expectHex(msg, "e45cac951000112233445566778899aabbccddeeff000000");
}

test "buildInitWrapped prepends invokeWithLayer+initConnection to a bare query" {
    // bare = users.getUsers([inputUserSelf]):
    //   d91a548 (getUsers) ++ 1cb5c415 (vector) ++ 1 ++ f7c1b13f (inputUserSelf)
    const bare = hexN(16, "48a5910d15c4b51c010000003fb1c1f7");
    var out: [256]u8 = undefined;
    const msg = try buildInitWrapped(&out, 12345, &bare);
    try expectHex(msg, "0d0d9bdae1000000a95ecdc10000000039300000" ++
        "055a69674f53000003312e3003302e3102656e000000000002656e00" ++
        "48a5910d15c4b51c010000003fb1c1f7");
}

test "parseLoginToken: pending / migrate / success" {
    const pend = try parseLoginToken(&hexN(16, "80199f622c01000004aabbccdd000000"));
    try std.testing.expectEqual(@as(i32, 300), pend.pending.expires);
    try std.testing.expectEqualSlices(u8, &hexN(4, "aabbccdd"), pend.pending.token);

    const mig = try parseLoginToken(&hexN(16, "16998e060200000004deadbeef000000"));
    try std.testing.expectEqual(@as(i32, 2), mig.migrate.dc_id);
    try std.testing.expectEqualSlices(u8, &hexN(4, "deadbeef"), mig.migrate.token);

    // loginTokenSuccess wraps a boxed auth.authorization — the slice feeds classifyAuth.
    const succ = try parseLoginToken(&hexN(8, "5e5c0d39d4c0a22e"));
    try std.testing.expectEqual(AuthOutcome.logged_in, classifyAuth(succ.success));
}
