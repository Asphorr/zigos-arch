//! Telegram entity parsing (tdesktop schema, layer 225) — the boxed objects that
//! come back inside an rpc_result once we're an authorized user. Pure (std + tl)
//! so it `zig test`s natively, off-target.
//!
//! TL parsing rule that bites: a constructor's fields are serialized in the
//! TEXTUAL order of the schema definition, each present iff its flag bit is set
//! (the bit numbers are NOT in order). To walk a Vector<User> we must consume
//! each User *exactly* — extract the few fields we show, and skip every optional
//! tail field byte-perfectly, recursing into nested boxed types. One wrong skip
//! size desyncs the whole vector, so each skipper is byte-accounted and the
//! tests assert `remaining()==0` after a fully-populated object.
//!
//! Covered so far (enough for "who am I" + a contacts list):
//!   user#31774388 / userEmpty               -> id, first/last name, @username
//!   auth.authorization#2ea2c0d4             -> the self User
//!   contacts.contacts#eae87e42              -> Vector<User>
//! Chat/Channel/Dialog/Message come next (dialog list needs the Message closure).

const std = @import("std");
const tl = @import("tl.zig");
const flate = std.compress.flate;
const schema = @import("tl_schema.zig");

pub const Error = error{ Malformed, UnexpectedCtor };

// --- constructor ids (layer 225) ---
pub const C_USER: u32 = 0x31774388;
pub const C_USER_EMPTY: u32 = 0xd3bc4b7a;
const C_USER_PROFILE_PHOTO: u32 = 0x82d1f706;
const C_USER_PROFILE_PHOTO_EMPTY: u32 = 0x4f11bae1;
const C_USER_STATUS_EMPTY: u32 = 0x09d05049;
const C_USER_STATUS_ONLINE: u32 = 0xedb93949;
const C_USER_STATUS_OFFLINE: u32 = 0x008c703f;
const C_USER_STATUS_RECENTLY: u32 = 0x7b197dc8;
const C_USER_STATUS_LAST_WEEK: u32 = 0x541a1d1a;
const C_USER_STATUS_LAST_MONTH: u32 = 0x65899777;
const C_EMOJI_STATUS_EMPTY: u32 = 0x2de11aae;
const C_EMOJI_STATUS: u32 = 0xe7ff068a;
const C_EMOJI_STATUS_COLLECTIBLE: u32 = 0x7184603b;
const C_USERNAME: u32 = 0xb4073647;
const C_PEER_COLOR: u32 = 0xb54b5acf;
const C_RECENT_STORY: u32 = 0x711d692d;
const C_RESTRICTION_REASON: u32 = 0xd072acb4;

const C_AUTH_AUTHORIZATION: u32 = 0x2ea2c0d4;
pub const C_CONTACTS_CONTACTS: u32 = 0xeae87e42;
pub const C_CONTACTS_NOT_MODIFIED: u32 = 0xb74ba9d2;
const C_CONTACT: u32 = 0x145ade0b;

const C_USERS_GET_USERS: u32 = 0x0d91a548;
const C_CONTACTS_GET_CONTACTS: u32 = 0x5dd69e12;
const C_INPUT_USER_SELF: u32 = 0xf7c1b13f;
const C_GZIP_PACKED: u32 = 0x3072cfa1; // mtproto core: wraps large rpc_result payloads

// thin Reader adapters: collapse tl's ReadError into our Error
fn rU32(r: *tl.Reader) Error!u32 {
    return r.readU32() catch error.Malformed;
}
fn rI32(r: *tl.Reader) Error!i32 {
    return r.readInt() catch error.Malformed;
}
fn rLong(r: *tl.Reader) Error!u64 {
    return r.readLong() catch error.Malformed;
}
fn rBytes(r: *tl.Reader) Error![]const u8 {
    return r.readBytes() catch error.Malformed;
}

inline fn bit(f: u32, comptime n: u5) bool {
    return (f >> n) & 1 == 1;
}

pub const User = struct {
    id: u64 = 0,
    access_hash: u64 = 0, // needed to build an InputPeer for getHistory etc.
    first: []const u8 = "",
    last: []const u8 = "",
    username: []const u8 = "",
    is_self: bool = false,
    deleted: bool = false,
};

/// Parse one `User` from `r`, extracting id/names/@username and advancing `r`
/// to the byte after the whole object (so it's safe inside a Vector<User>).
pub fn parseUser(r: *tl.Reader) Error!User {
    const ctor = try rU32(r);
    if (ctor == C_USER_EMPTY) {
        return .{ .id = try rLong(r), .deleted = true };
    }
    if (ctor != C_USER) return error.UnexpectedCtor;

    const flags = try rU32(r);
    const flags2 = try rU32(r);
    var u = User{
        .id = try rLong(r),
        .is_self = bit(flags, 10),
        .deleted = bit(flags, 13),
    };
    // fields in schema (textual) order:
    if (bit(flags, 0)) u.access_hash = try rLong(r);
    if (bit(flags, 1)) u.first = try rBytes(r);
    if (bit(flags, 2)) u.last = try rBytes(r);
    if (bit(flags, 3)) u.username = try rBytes(r);
    if (bit(flags, 4)) _ = try rBytes(r); // phone
    if (bit(flags, 5)) try skipUserProfilePhoto(r);
    if (bit(flags, 6)) try skipUserStatus(r);
    if (bit(flags, 14)) _ = try rI32(r); // bot_info_version
    if (bit(flags, 18)) try skipVec(r, skipRestrictionReason); // restriction_reason
    if (bit(flags, 19)) _ = try rBytes(r); // bot_inline_placeholder
    if (bit(flags, 22)) _ = try rBytes(r); // lang_code
    if (bit(flags, 30)) try skipEmojiStatus(r);
    if (bit(flags2, 0)) try skipVec(r, skipUsername); // usernames
    if (bit(flags2, 5)) try skipRecentStory(r); // stories_max_id
    if (bit(flags2, 8)) try skipPeerColor(r); // color
    if (bit(flags2, 9)) try skipPeerColor(r); // profile_color
    if (bit(flags2, 12)) _ = try rI32(r); // bot_active_users
    if (bit(flags2, 14)) _ = try rLong(r); // bot_verification_icon
    if (bit(flags2, 15)) _ = try rLong(r); // send_paid_messages_stars
    return u;
}

fn skipUserProfilePhoto(r: *tl.Reader) Error!void {
    const c = try rU32(r);
    if (c == C_USER_PROFILE_PHOTO_EMPTY) return;
    if (c != C_USER_PROFILE_PHOTO) return error.UnexpectedCtor;
    const f = try rU32(r);
    _ = try rLong(r); // photo_id
    if (bit(f, 1)) _ = try rBytes(r); // stripped_thumb
    _ = try rI32(r); // dc_id
}

fn skipUserStatus(r: *tl.Reader) Error!void {
    switch (try rU32(r)) {
        C_USER_STATUS_EMPTY => {},
        C_USER_STATUS_ONLINE, C_USER_STATUS_OFFLINE => _ = try rI32(r), // expires / was_online
        C_USER_STATUS_RECENTLY, C_USER_STATUS_LAST_WEEK, C_USER_STATUS_LAST_MONTH => _ = try rU32(r), // flags
        else => return error.UnexpectedCtor,
    }
}

fn skipEmojiStatus(r: *tl.Reader) Error!void {
    switch (try rU32(r)) {
        C_EMOJI_STATUS_EMPTY => {},
        C_EMOJI_STATUS => {
            const f = try rU32(r);
            _ = try rLong(r); // document_id
            if (bit(f, 0)) _ = try rI32(r); // until
        },
        C_EMOJI_STATUS_COLLECTIBLE => {
            const f = try rU32(r);
            _ = try rLong(r); // collectible_id
            _ = try rLong(r); // document_id
            _ = try rBytes(r); // title
            _ = try rBytes(r); // slug
            _ = try rLong(r); // pattern_document_id
            _ = try rI32(r); // center_color
            _ = try rI32(r); // edge_color
            _ = try rI32(r); // pattern_color
            _ = try rI32(r); // text_color
            if (bit(f, 0)) _ = try rI32(r); // until
        },
        else => return error.UnexpectedCtor,
    }
}

fn skipUsername(r: *tl.Reader) Error!void {
    if ((try rU32(r)) != C_USERNAME) return error.UnexpectedCtor;
    _ = try rU32(r); // flags (editable/active are zero-size)
    _ = try rBytes(r); // username
}

fn skipPeerColor(r: *tl.Reader) Error!void {
    if ((try rU32(r)) != C_PEER_COLOR) return error.UnexpectedCtor;
    const f = try rU32(r);
    if (bit(f, 0)) _ = try rI32(r); // color
    if (bit(f, 1)) _ = try rLong(r); // background_emoji_id
}

fn skipRecentStory(r: *tl.Reader) Error!void {
    if ((try rU32(r)) != C_RECENT_STORY) return error.UnexpectedCtor;
    const f = try rU32(r);
    if (bit(f, 1)) _ = try rI32(r); // max_id (live is zero-size)
}

fn skipRestrictionReason(r: *tl.Reader) Error!void {
    if ((try rU32(r)) != C_RESTRICTION_REASON) return error.UnexpectedCtor;
    _ = try rBytes(r); // platform
    _ = try rBytes(r); // reason
    _ = try rBytes(r); // text
}

/// Skip a `Vector<T>` whose element is consumed by `skipElem`.
fn skipVec(r: *tl.Reader, comptime skipElem: fn (*tl.Reader) Error!void) Error!void {
    if ((try rU32(r)) != tl.VECTOR_CTOR) return error.UnexpectedCtor;
    const n = try rI32(r);
    if (n < 0) return error.Malformed;
    var i: usize = 0;
    while (i < @as(usize, @intCast(n))) : (i += 1) try skipElem(r);
}

/// Extract the self `User` from an `auth.authorization` (the loginTokenSuccess /
/// signIn payload). `user` is its terminal field, so no tail-skip is needed.
pub fn parseSelfFromAuthorization(obj: []const u8) Error!User {
    var r = tl.Reader.init(obj);
    if ((try rU32(&r)) != C_AUTH_AUTHORIZATION) return error.UnexpectedCtor;
    const flags = try rU32(&r);
    // textual order: otherwise_relogin_days(flags.1) tmp_sessions(flags.0) future_auth_token(flags.2)
    if (bit(flags, 1)) _ = try rI32(&r); // otherwise_relogin_days
    if (bit(flags, 0)) _ = try rI32(&r); // tmp_sessions
    if (bit(flags, 2)) _ = try rBytes(&r); // future_auth_token
    return parseUser(&r);
}

/// A parsed `contacts.contacts` positioned at the start of its Vector<User>.
/// Iterate `n_users` times calling `parseUser(&it.users)`.
pub const Contacts = struct {
    n_users: usize,
    users: tl.Reader,
};

pub fn parseContacts(obj: []const u8) Error!Contacts {
    var r = tl.Reader.init(obj);
    switch (try rU32(&r)) {
        C_CONTACTS_CONTACTS => {},
        C_CONTACTS_NOT_MODIFIED => return .{ .n_users = 0, .users = r }, // (only with a nonzero hash)
        else => return error.UnexpectedCtor,
    }
    try skipVec(&r, skipContact); // contacts: Vector<Contact>
    _ = try rI32(&r); // saved_count
    if ((try rU32(&r)) != tl.VECTOR_CTOR) return error.UnexpectedCtor; // users: Vector<User>
    const n = try rI32(&r);
    if (n < 0) return error.Malformed;
    return .{ .n_users = @intCast(n), .users = r };
}

fn skipContact(r: *tl.Reader) Error!void {
    if ((try rU32(r)) != C_CONTACT) return error.UnexpectedCtor;
    _ = try rLong(r); // user_id
    _ = try rU32(r); // mutual:Bool (just a boolTrue/boolFalse ctor, no payload)
}

// ---- request builders (BARE: post-login the connection is already
// initConnection'd, so these queries are not wrapped) ----

/// users.getUsers([inputUserSelf]) — "who am I".
pub fn buildGetUsersSelf(out: []u8) Error![]const u8 {
    var w = tl.Writer.init(out);
    w.writeU32(C_USERS_GET_USERS) catch return error.Malformed;
    w.writeU32(tl.VECTOR_CTOR) catch return error.Malformed;
    w.writeInt(1) catch return error.Malformed;
    w.writeU32(C_INPUT_USER_SELF) catch return error.Malformed;
    return w.written();
}

/// contacts.getContacts(hash=0) — the full saved-contacts list.
pub fn buildGetContacts(out: []u8) Error![]const u8 {
    var w = tl.Writer.init(out);
    w.writeU32(C_CONTACTS_GET_CONTACTS) catch return error.Malformed;
    w.writeLong(0) catch return error.Malformed; // hash
    return w.written();
}

/// users.getUsers returns a bare Vector<User>; parse its header, then iterate.
pub fn parseUserVectorHeader(obj: []const u8) Error!Contacts {
    var r = tl.Reader.init(obj);
    if ((try rU32(&r)) != tl.VECTOR_CTOR) return error.UnexpectedCtor;
    const n = try rI32(&r);
    if (n < 0) return error.Malformed;
    return .{ .n_users = @intCast(n), .users = r };
}

// =====================================================================
// Generic table-driven skip (the engine for walking past nested media/action/
// webpage/... closures byte-exactly). Hand-written parsers below extract the
// few fields we display and call skipBoxed() for everything they don't.

/// Skip one boxed object: read its ctor, look up the field layout in the
/// generated schema table, and consume every field exactly (recursing into
/// nested boxed types and vectors).
pub fn skipBoxed(r: *tl.Reader) Error!void {
    return skipBoxedDepth(r, 0);
}

fn skipBoxedDepth(r: *tl.Reader, depth: u32) Error!void {
    if (depth > 64) return error.Malformed; // runaway-recursion guard
    const id = try rU32(r);
    const fields = schema.fieldsFor(id) orelse return error.UnexpectedCtor;
    var f1: u32 = 0;
    var f2: u32 = 0;
    for (fields) |fld| {
        if (fld.gw == 1 and (f1 >> @as(u5, @truncate(fld.gb))) & 1 == 0) continue;
        if (fld.gw == 2 and (f2 >> @as(u5, @truncate(fld.gb))) & 1 == 0) continue;
        switch (fld.kind) {
            .flags1 => f1 = try rU32(r),
            .flags2 => f2 = try rU32(r),
            .tru => {},
            .int, .boolean => _ = try rU32(r),
            .long => _ = try rLong(r),
            .double => try skipN(r, 8),
            .int128 => try skipN(r, 16),
            .int256 => try skipN(r, 32),
            .bytes => _ = try rBytes(r),
            .boxed => try skipBoxedDepth(r, depth + 1),
            .vector => try skipVectorElems(r, fld.elem, depth),
        }
    }
}

fn skipVectorElems(r: *tl.Reader, elem: schema.Kind, depth: u32) Error!void {
    if ((try rU32(r)) != tl.VECTOR_CTOR) return error.UnexpectedCtor;
    const n = try rI32(r);
    if (n < 0) return error.Malformed;
    var i: usize = 0;
    while (i < @as(usize, @intCast(n))) : (i += 1) {
        switch (elem) {
            .tru => {},
            .int, .boolean => _ = try rU32(r),
            .long => _ = try rLong(r),
            .double => try skipN(r, 8),
            .int128 => try skipN(r, 16),
            .int256 => try skipN(r, 32),
            .bytes => _ = try rBytes(r),
            .boxed => try skipBoxedDepth(r, depth + 1),
            .vector, .flags1, .flags2 => return error.Malformed, // not a valid vector element
        }
    }
}

fn skipN(r: *tl.Reader, n: usize) Error!void {
    _ = r.readRaw(n) catch return error.Malformed;
}

// --- Peer (who a message/dialog is with) ---
pub const PeerKind = enum { none, user, chat, channel };
pub const Peer = struct { kind: PeerKind = .none, id: u64 = 0 };

const C_PEER_USER: u32 = 0x59511722;
const C_PEER_CHAT: u32 = 0x36c6019a;
const C_PEER_CHANNEL: u32 = 0xa2a5371e;

fn parsePeer(r: *tl.Reader) Error!Peer {
    return switch (try rU32(r)) {
        C_PEER_USER => .{ .kind = .user, .id = try rLong(r) },
        C_PEER_CHAT => .{ .kind = .chat, .id = try rLong(r) },
        C_PEER_CHANNEL => .{ .kind = .channel, .id = try rLong(r) },
        else => error.UnexpectedCtor,
    };
}

// --- Message ---
const C_MESSAGE: u32 = 0x95ef6f2b;
const C_MESSAGE_EMPTY: u32 = 0x90a6ca84;
const C_MESSAGE_SERVICE: u32 = 0x7a800e0a;

pub const Message = struct {
    id: i32 = 0,
    from: Peer = .{}, // who sent it (absent in 1-1 → use peer/out flag)
    peer: Peer = .{}, // the dialog it belongs to
    date: i32 = 0,
    text: []const u8 = "",
    out: bool = false, // we sent it
    service: bool = false,
    empty: bool = false,
};

/// Parse one Message (regular / service / empty), extracting id/from/peer/date/
/// text and consuming the entire object so it's safe inside a Vector<Message>.
pub fn parseMessage(r: *tl.Reader) Error!Message {
    switch (try rU32(r)) {
        C_MESSAGE_EMPTY => {
            const f = try rU32(r);
            var m = Message{ .id = try rI32(r), .empty = true };
            if (bit(f, 0)) m.peer = try parsePeer(r);
            return m;
        },
        C_MESSAGE_SERVICE => return parseServiceMessage(r),
        C_MESSAGE => {},
        else => return error.UnexpectedCtor,
    }
    // message#95ef6f2b — fields in schema (textual) order
    const f = try rU32(r);
    const f2 = try rU32(r);
    var m = Message{ .out = bit(f, 1) };
    m.id = try rI32(r);
    if (bit(f, 8)) m.from = try parsePeer(r); // from_id
    if (bit(f, 29)) _ = try rI32(r); // from_boosts_applied
    if (bit(f2, 12)) _ = try rBytes(r); // from_rank
    m.peer = try parsePeer(r); // peer_id
    if (bit(f, 28)) _ = try parsePeer(r); // saved_peer_id
    if (bit(f, 2)) try skipBoxed(r); // fwd_from
    if (bit(f, 11)) _ = try rLong(r); // via_bot_id
    if (bit(f2, 0)) _ = try rLong(r); // via_business_bot_id
    if (bit(f2, 19)) _ = try parsePeer(r); // guestchat_via_from
    if (bit(f, 3)) try skipBoxed(r); // reply_to
    m.date = try rI32(r);
    m.text = try rBytes(r); // message — the text we display
    // tail (not displayed, but must be consumed to stay in sync)
    if (bit(f, 9)) try skipBoxed(r); // media
    if (bit(f, 6)) try skipBoxed(r); // reply_markup
    if (bit(f, 7)) try skipVec(r, skipBoxed); // entities
    if (bit(f, 10)) _ = try rI32(r); // views
    if (bit(f, 10)) _ = try rI32(r); // forwards
    if (bit(f, 23)) try skipBoxed(r); // replies
    if (bit(f, 15)) _ = try rI32(r); // edit_date
    if (bit(f, 16)) _ = try rBytes(r); // post_author
    if (bit(f, 17)) _ = try rLong(r); // grouped_id
    if (bit(f, 20)) try skipBoxed(r); // reactions
    if (bit(f, 22)) try skipVec(r, skipBoxed); // restriction_reason
    if (bit(f, 25)) _ = try rI32(r); // ttl_period
    if (bit(f, 30)) _ = try rI32(r); // quick_reply_shortcut_id
    if (bit(f2, 2)) _ = try rLong(r); // effect
    if (bit(f2, 3)) try skipBoxed(r); // factcheck
    if (bit(f2, 5)) _ = try rI32(r); // report_delivery_until_date
    if (bit(f2, 6)) _ = try rLong(r); // paid_message_stars
    if (bit(f2, 7)) try skipBoxed(r); // suggested_post
    if (bit(f2, 10)) _ = try rI32(r); // schedule_repeat_period
    if (bit(f2, 11)) _ = try rBytes(r); // summary_from_language
    return m;
}

fn parseServiceMessage(r: *tl.Reader) Error!Message {
    // messageService#7a800e0a flags:# .. id:int from_id:flags.8?Peer peer_id:Peer
    //   saved_peer_id:flags.28?Peer reply_to:flags.3?MessageReplyHeader date:int
    //   action:MessageAction reactions:flags.20?MessageReactions ttl_period:flags.25?int
    const f = try rU32(r);
    var m = Message{ .service = true, .out = bit(f, 1), .text = "(service message)" };
    m.id = try rI32(r);
    if (bit(f, 8)) m.from = try parsePeer(r);
    m.peer = try parsePeer(r);
    if (bit(f, 28)) _ = try parsePeer(r);
    if (bit(f, 3)) try skipBoxed(r); // reply_to
    m.date = try rI32(r);
    try skipBoxed(r); // action:MessageAction
    if (bit(f, 20)) try skipBoxed(r); // reactions
    if (bit(f, 25)) _ = try rI32(r); // ttl_period
    return m;
}

// --- messages.Messages response (the getHistory reply) ---
const C_MESSAGES_MESSAGES: u32 = 0x1d73e7ea;
const C_MESSAGES_SLICE: u32 = 0x5f206716;
const C_CHANNEL_MESSAGES: u32 = 0xc776ba4e;
const C_MESSAGES_NOT_MODIFIED: u32 = 0x74535f21;

/// A parsed messages.Messages positioned at the start of its Vector<Message>.
pub const History = struct { n: usize, msgs: tl.Reader };

pub fn parseHistory(obj: []const u8) Error!History {
    var r = tl.Reader.init(obj);
    switch (try rU32(&r)) {
        C_MESSAGES_MESSAGES => {}, // messages vector is first
        C_MESSAGES_NOT_MODIFIED => return .{ .n = 0, .msgs = r },
        C_MESSAGES_SLICE => {
            const f = try rU32(&r);
            _ = try rI32(&r); // count
            if (bit(f, 0)) _ = try rI32(&r); // next_rate
            if (bit(f, 2)) _ = try rI32(&r); // offset_id_offset
            if (bit(f, 3)) try skipBoxed(&r); // search_flood
        },
        C_CHANNEL_MESSAGES => {
            const f = try rU32(&r);
            _ = try rI32(&r); // pts
            _ = try rI32(&r); // count
            if (bit(f, 2)) _ = try rI32(&r); // offset_id_offset
        },
        else => return error.UnexpectedCtor,
    }
    if ((try rU32(&r)) != tl.VECTOR_CTOR) return error.UnexpectedCtor;
    const n = try rI32(&r);
    if (n < 0) return error.Malformed;
    return .{ .n = @intCast(n), .msgs = r };
}

/// After parseHistory's `Vector<Message>` has been fully consumed (the caller must
/// have parsed all `n` messages), walk the trailing `chats` vector and return a
/// (count, Reader) over the `users` vector — the senders, for name resolution.
/// messages.messages / messagesSlice / channelMessages all end `... chats users`.
pub fn parseHistoryUsers(r: *tl.Reader) Error!Contacts {
    if ((try rU32(r)) != tl.VECTOR_CTOR) return error.UnexpectedCtor; // chats: Vector<Chat>
    const nc = try rI32(r);
    if (nc < 0) return error.Malformed;
    var c: usize = 0;
    while (c < @as(usize, @intCast(nc))) : (c += 1) try skipBoxed(r);
    if ((try rU32(r)) != tl.VECTOR_CTOR) return error.UnexpectedCtor; // users: Vector<User>
    const nu = try rI32(r);
    if (nu < 0) return error.Malformed;
    return .{ .n_users = @intCast(nu), .users = r.* };
}

// --- request builder: messages.getHistory ---
const C_MESSAGES_GET_HISTORY: u32 = 0x4423e6c5;
const C_INPUT_PEER_USER: u32 = 0xdde8a54c;
const C_INPUT_PEER_CHAT: u32 = 0x35a95cb9;
const C_INPUT_PEER_CHANNEL: u32 = 0x27bcbbfc;

/// messages.getHistory(peer, limit) — newest `limit` messages of a conversation.
pub fn buildGetHistory(out: []u8, peer: Peer, access_hash: u64, limit: i32) Error![]const u8 {
    var w = tl.Writer.init(out);
    w.writeU32(C_MESSAGES_GET_HISTORY) catch return error.Malformed;
    switch (peer.kind) {
        .user => {
            w.writeU32(C_INPUT_PEER_USER) catch return error.Malformed;
            w.writeLong(peer.id) catch return error.Malformed;
            w.writeLong(access_hash) catch return error.Malformed;
        },
        .chat => {
            w.writeU32(C_INPUT_PEER_CHAT) catch return error.Malformed;
            w.writeLong(peer.id) catch return error.Malformed;
        },
        .channel => {
            w.writeU32(C_INPUT_PEER_CHANNEL) catch return error.Malformed;
            w.writeLong(peer.id) catch return error.Malformed;
            w.writeLong(access_hash) catch return error.Malformed;
        },
        .none => return error.Malformed,
    }
    w.writeInt(0) catch return error.Malformed; // offset_id
    w.writeInt(0) catch return error.Malformed; // offset_date
    w.writeInt(0) catch return error.Malformed; // add_offset
    w.writeInt(limit) catch return error.Malformed; // limit
    w.writeInt(0) catch return error.Malformed; // max_id
    w.writeInt(0) catch return error.Malformed; // min_id
    w.writeLong(0) catch return error.Malformed; // hash
    return w.written();
}

// gzip history window (RFC 1952 max deflate window) — static, off the stack.
var gzip_window: [flate.max_window_len]u8 = undefined;

/// Telegram wraps large rpc_result payloads in `gzip_packed#3072cfa1`. If `obj`
/// is gzip-packed, inflate it into `out` and return the inflated slice; else
/// return `obj` unchanged — so callers can apply this to every result blindly.
pub fn gunzipIfPacked(obj: []const u8, out: []u8) Error![]const u8 {
    if (obj.len < 4 or std.mem.readInt(u32, obj[0..4], .little) != C_GZIP_PACKED) return obj;
    var r = tl.Reader.init(obj);
    _ = try rU32(&r); // gzip_packed ctor
    const packed_data = try rBytes(&r);
    var in: std.Io.Reader = .fixed(packed_data);
    var dec = flate.Decompress.init(&in, .gzip, &gzip_window);
    var w: std.Io.Writer = .fixed(out);
    _ = dec.reader.streamRemaining(&w) catch return error.Malformed; // ReadFailed or out full
    return w.buffered();
}

// =====================================================================
// Live updates — the server-pushed `Updates` objects that carry incoming
// messages (someone messaged us, or we sent from another device). session.zig
// detects + slices the Updates object off the decrypted body; here we parse it.
//
// We REUSE parseMessage (byte-exact, table-driven) for the embedded-Message
// forms, and the generic skipBoxed to step past any non-message Update inside an
// `updates` vector — only possible because Update/Updates were added to the
// generated skip table. The flat short-message forms are synthesized by hand.
// All ctor ids + field orders are from the layer-225 api.tl.

// Updates (the boxed envelope)
const C_UPDATE_SHORT_MESSAGE: u32 = 0x313bc7f8;
const C_UPDATE_SHORT_CHAT_MESSAGE: u32 = 0x4d6deea5;
const C_UPDATE_SHORT: u32 = 0x78d4dec1;
const C_UPDATES: u32 = 0x74ae4240;
const C_UPDATES_COMBINED: u32 = 0x725b04c3;
const C_UPDATES_TOO_LONG: u32 = 0xe317af7e;
// Update (the inner variants we EXTRACT; everything else is skipBoxed'd)
const C_UPDATE_NEW_MESSAGE: u32 = 0x1f2b0afd;
const C_UPDATE_NEW_CHANNEL_MESSAGE: u32 = 0x62ba04d9;

/// The result of parsing one pushed Updates object: the new messages it carried
/// (filled into the caller's buffer) plus a (count, Reader) over its users vector
/// (only for the `updates`/`updatesCombined` container forms) so the caller can
/// harvest sender names. `too_long` signals updatesTooLong (the caller may want
/// to resync via getDifference — not implemented yet).
pub const Incoming = struct {
    msgs: []Message,
    too_long: bool = false,
    n_users: usize = 0,
    users: tl.Reader = undefined,
};

/// updateShortMessage / updateShortChatMessage — a flat (no embedded Message)
/// form for 1-1 and basic-group text messages. Synthesize a Message from it.
fn parseShortMessage(r: *tl.Reader, is_chat: bool) Error!Message {
    const f = try rU32(r);
    var m = Message{ .out = bit(f, 1) };
    m.id = try rI32(r);
    if (is_chat) {
        m.from = .{ .kind = .user, .id = try rLong(r) }; // from_id (the sender)
        m.peer = .{ .kind = .chat, .id = try rLong(r) }; // chat_id (the dialog)
    } else {
        const uid = try rLong(r); // user_id = the other party = the dialog
        m.peer = .{ .kind = .user, .id = uid };
        m.from = .{ .kind = .user, .id = uid };
    }
    m.text = try rBytes(r); // message
    _ = try rI32(r); // pts
    _ = try rI32(r); // pts_count
    m.date = try rI32(r);
    // trailing optionals (fwd_from/via_bot_id/reply_to/entities/ttl_period) are
    // not read: this is the whole standalone object, nothing follows it.
    return m;
}

/// Parse one `Update`: if it's a new-message variant, extract the Message into
/// `out`; otherwise step past it with the generic table-driven skipper.
fn parseOneUpdate(r: *tl.Reader, out: []Message, n: *usize) Error!void {
    const snap = r.*;
    const ctor = try rU32(r);
    if (ctor == C_UPDATE_NEW_MESSAGE or ctor == C_UPDATE_NEW_CHANNEL_MESSAGE) {
        const m = try parseMessage(r); // byte-exact (consumes media/entities/...)
        _ = try rI32(r); // pts
        _ = try rI32(r); // pts_count
        if (!m.empty and n.* < out.len) {
            out[n.*] = m;
            n.* += 1;
        }
    } else {
        r.* = snap; // rewind to the ctor, then skip the whole Update via the table
        try skipBoxed(r);
    }
}

/// Parse a pushed `Updates` object, extracting any new messages into `out`.
pub fn parseUpdates(obj: []const u8, out: []Message) Error!Incoming {
    var r = tl.Reader.init(obj);
    var n: usize = 0;
    switch (try rU32(&r)) {
        C_UPDATES_TOO_LONG => return .{ .msgs = out[0..0], .too_long = true },
        C_UPDATE_SHORT_MESSAGE => {
            const m = try parseShortMessage(&r, false);
            if (!m.empty and out.len > 0) {
                out[0] = m;
                n = 1;
            }
        },
        C_UPDATE_SHORT_CHAT_MESSAGE => {
            const m = try parseShortMessage(&r, true);
            if (!m.empty and out.len > 0) {
                out[0] = m;
                n = 1;
            }
        },
        C_UPDATE_SHORT => {
            // updateShort: update:Update date:int — one embedded Update.
            try parseOneUpdate(&r, out, &n);
        },
        C_UPDATES, C_UPDATES_COMBINED => {
            // updates: Vector<Update> users:Vector<User> chats:Vector<Chat> date seq[...]
            if ((try rU32(&r)) != tl.VECTOR_CTOR) return error.UnexpectedCtor;
            const nupd = try rI32(&r);
            if (nupd < 0) return error.Malformed;
            var i: usize = 0;
            while (i < @as(usize, @intCast(nupd))) : (i += 1) try parseOneUpdate(&r, out, &n);
            // users vector follows — hand it back for sender-name harvesting
            if ((try rU32(&r)) != tl.VECTOR_CTOR) return error.UnexpectedCtor;
            const nusers = try rI32(&r);
            if (nusers < 0) return error.Malformed;
            return .{ .msgs = out[0..n], .n_users = @intCast(nusers), .users = r };
        },
        else => {}, // updateShortSentMessage et al. carry no incoming message for us
    }
    return .{ .msgs = out[0..n] };
}

// =====================================================================
// Dialog list — messages.getDialogs + the messages.dialogs closure (layer 225).
//
// The reply is four parallel vectors: dialogs (ordering + peer + unread),
// messages (the per-dialog "top" message = our preview text), chats (group/
// channel titles), users (people names). They're sequential on the wire with no
// length prefix, so we walk the dialogs vector (byte-exact, by hand) to reach
// the rest, then hand back a Reader snapshot + count for each remaining vector
// so the caller can iterate them with parseUser / parseChatHead / parseMessage.
// All ctor ids + field orders verified against the api.tl that generated the
// skip table (so dialog#'s new unread_poll_votes_count etc. are accounted for).

// request functions
const C_MESSAGES_GET_DIALOGS: u32 = 0xa0f4cb4f;
const C_MESSAGES_SEND_MESSAGE: u32 = 0x545cd15a;
// messages.Dialogs responses
const C_MESSAGES_DIALOGS: u32 = 0x15ba6c40;
const C_MESSAGES_DIALOGS_SLICE: u32 = 0x71e094f3;
const C_MESSAGES_DIALOGS_NOT_MODIFIED: u32 = 0xf0e3e596;
// Dialog
const C_DIALOG: u32 = 0xfc89f7f3;
const C_DIALOG_FOLDER: u32 = 0x71bd134c;
const C_FOLDER: u32 = 0xff544e65;
// Chat
const C_CHAT_EMPTY: u32 = 0x29562865;
const C_CHAT: u32 = 0x41cbf256;
const C_CHAT_FORBIDDEN: u32 = 0x6592a1a7;
const C_CHANNEL: u32 = 0x1c32b11c;
const C_CHANNEL_FORBIDDEN: u32 = 0x17d493d5;
// InputPeer
const C_INPUT_PEER_EMPTY: u32 = 0x7f3b18ea;

/// Serialize an InputPeer (the addressing prefix for getHistory / sendMessage).
fn writeInputPeer(w: *tl.Writer, peer: Peer, access_hash: u64) tl.WriteError!void {
    switch (peer.kind) {
        .user => {
            try w.writeU32(C_INPUT_PEER_USER);
            try w.writeLong(peer.id);
            try w.writeLong(access_hash);
        },
        .chat => {
            try w.writeU32(C_INPUT_PEER_CHAT);
            try w.writeLong(peer.id);
        },
        .channel => {
            try w.writeU32(C_INPUT_PEER_CHANNEL);
            try w.writeLong(peer.id);
            try w.writeLong(access_hash);
        },
        .none => try w.writeU32(C_INPUT_PEER_EMPTY),
    }
}

/// messages.getDialogs — first page (folder 0, no offset), newest dialogs first.
pub fn buildGetDialogs(out: []u8, limit: i32) Error![]const u8 {
    var w = tl.Writer.init(out);
    w.writeU32(C_MESSAGES_GET_DIALOGS) catch return error.Malformed;
    w.writeU32(0) catch return error.Malformed; // flags: exclude_pinned off, folder_id absent
    w.writeInt(0) catch return error.Malformed; // offset_date
    w.writeInt(0) catch return error.Malformed; // offset_id
    w.writeU32(C_INPUT_PEER_EMPTY) catch return error.Malformed; // offset_peer
    w.writeInt(limit) catch return error.Malformed; // limit
    w.writeLong(0) catch return error.Malformed; // hash
    return w.written();
}

/// messages.sendMessage — plain text (no reply/entities/media/schedule). The
/// reply is an Updates object; the caller need only check for an rpc_error.
pub fn buildSendMessage(out: []u8, peer: Peer, access_hash: u64, message: []const u8, random_id: u64) Error![]const u8 {
    var w = tl.Writer.init(out);
    w.writeU32(C_MESSAGES_SEND_MESSAGE) catch return error.Malformed;
    w.writeU32(0) catch return error.Malformed; // flags: every optional absent (reply_to=flags.0 off)
    writeInputPeer(&w, peer, access_hash) catch return error.Malformed;
    w.writeBytes(message) catch return error.Malformed; // message:string
    w.writeLong(random_id) catch return error.Malformed; // random_id
    return w.written();
}

/// A group/channel as it appears in the dialogs reply's chats vector.
pub const ChatInfo = struct {
    kind: PeerKind = .chat,
    id: u64 = 0,
    access_hash: u64 = 0, // nonzero for channels (needed to open them)
    title: []const u8 = "", // slice into the source buffer
};

/// One row of the dialog list: which peer, its newest message id (matches a
/// Message in the messages vector), and the unread badge count.
pub const DialogRow = struct {
    peer: Peer = .{},
    top_message: i32 = 0,
    unread_count: i32 = 0,
    is_folder: bool = false, // the "Archived chats" pseudo-dialog — not a chat
};

/// The parsed dialogs reply: the dialog rows (filled into the caller's array),
/// plus a (count, Reader-at-first-element) for each of the other three vectors.
pub const DialogList = struct {
    dialogs: []DialogRow,
    n_messages: usize,
    messages: tl.Reader,
    n_chats: usize,
    chats: tl.Reader,
    n_users: usize,
    users: tl.Reader,
};

/// folder#ff544e65 — only inside a dialogFolder. We don't display it; just
/// consume it byte-exactly so the surrounding vector stays in sync.
fn skipFolder(r: *tl.Reader) Error!void {
    if ((try rU32(r)) != C_FOLDER) return error.UnexpectedCtor;
    const f = try rU32(r);
    _ = try rI32(r); // id
    _ = try rBytes(r); // title
    if (bit(f, 3)) try skipBoxed(r); // photo:ChatPhoto
}

/// Parse one Dialog (regular or the archive folder), extracting peer/top_message/
/// unread and consuming the whole object. notify_settings + draft are skipped via
/// the generated table (both are in the closure).
fn parseDialog(r: *tl.Reader) Error!DialogRow {
    const ctor = try rU32(r);
    if (ctor == C_DIALOG_FOLDER) {
        _ = try rU32(r); // flags (only pinned, zero-size)
        try skipFolder(r); // folder:Folder
        const peer = try parsePeer(r);
        const top = try rI32(r);
        _ = try rI32(r); // unread_muted_peers_count
        _ = try rI32(r); // unread_unmuted_peers_count
        _ = try rI32(r); // unread_muted_messages_count
        _ = try rI32(r); // unread_unmuted_messages_count
        return .{ .peer = peer, .top_message = top, .is_folder = true };
    }
    if (ctor != C_DIALOG) return error.UnexpectedCtor;
    const f = try rU32(r);
    // pinned/unread_mark/view_forum_as_messages are flags.N?true (zero-size)
    const peer = try parsePeer(r);
    const top = try rI32(r);
    _ = try rI32(r); // read_inbox_max_id
    _ = try rI32(r); // read_outbox_max_id
    const unread = try rI32(r);
    _ = try rI32(r); // unread_mentions_count
    _ = try rI32(r); // unread_reactions_count
    _ = try rI32(r); // unread_poll_votes_count (added in layer 225)
    try skipBoxed(r); // notify_settings:PeerNotifySettings
    if (bit(f, 0)) _ = try rI32(r); // pts
    if (bit(f, 1)) try skipBoxed(r); // draft:DraftMessage
    if (bit(f, 4)) _ = try rI32(r); // folder_id
    if (bit(f, 5)) _ = try rI32(r); // ttl_period
    return .{ .peer = peer, .top_message = top, .unread_count = unread };
}

/// Extract id/title/access_hash from one Chat, advancing `r` past the whole
/// object. The tail is consumed byte-exactly by the generated skip table; we
/// only read the (layer-stable) leading fields by hand off a snapshot.
pub fn parseChatHead(r: *tl.Reader) Error!ChatInfo {
    var snap = r.*;
    try skipBoxed(r); // consume the entire Chat (table-driven, byte-exact)
    return switch (try rU32(&snap)) {
        C_CHAT_EMPTY => .{ .kind = .chat, .id = try rLong(&snap) },
        C_CHAT => blk: {
            _ = try rU32(&snap); // flags
            const id = try rLong(&snap);
            break :blk .{ .kind = .chat, .id = id, .title = try rBytes(&snap) };
        },
        C_CHAT_FORBIDDEN => blk: {
            const id = try rLong(&snap);
            break :blk .{ .kind = .chat, .id = id, .title = try rBytes(&snap) };
        },
        C_CHANNEL => blk: {
            const f = try rU32(&snap);
            _ = try rU32(&snap); // flags2
            const id = try rLong(&snap);
            var ah: u64 = 0;
            if (bit(f, 13)) ah = try rLong(&snap); // access_hash:flags.13?long
            break :blk .{ .kind = .channel, .id = id, .access_hash = ah, .title = try rBytes(&snap) };
        },
        C_CHANNEL_FORBIDDEN => blk: {
            _ = try rU32(&snap); // flags
            const id = try rLong(&snap);
            const ah = try rLong(&snap);
            break :blk .{ .kind = .channel, .id = id, .access_hash = ah, .title = try rBytes(&snap) };
        },
        else => error.UnexpectedCtor,
    };
}

/// Parse a messages.dialogs / dialogsSlice reply. Fills `out` with the dialog
/// rows and returns Readers positioned at the messages/chats/users vectors.
pub fn parseDialogList(obj: []const u8, out: []DialogRow) Error!DialogList {
    var r = tl.Reader.init(obj);
    switch (try rU32(&r)) {
        C_MESSAGES_DIALOGS => {},
        C_MESSAGES_DIALOGS_SLICE => _ = try rI32(&r), // count
        C_MESSAGES_DIALOGS_NOT_MODIFIED => {
            _ = try rI32(&r); // count
            return .{ .dialogs = out[0..0], .n_messages = 0, .messages = r, .n_chats = 0, .chats = r, .n_users = 0, .users = r };
        },
        else => return error.UnexpectedCtor,
    }
    // dialogs: Vector<Dialog>
    if ((try rU32(&r)) != tl.VECTOR_CTOR) return error.UnexpectedCtor;
    const nd = try rI32(&r);
    if (nd < 0) return error.Malformed;
    var count: usize = 0;
    var i: usize = 0;
    while (i < @as(usize, @intCast(nd))) : (i += 1) {
        const d = try parseDialog(&r);
        if (count < out.len) {
            out[count] = d;
            count += 1;
        }
    }
    // messages: Vector<Message> — snapshot, then walk past to reach chats
    if ((try rU32(&r)) != tl.VECTOR_CTOR) return error.UnexpectedCtor;
    const nm = try rI32(&r);
    if (nm < 0) return error.Malformed;
    const messages_snap = r;
    var k: usize = 0;
    while (k < @as(usize, @intCast(nm))) : (k += 1) _ = try parseMessage(&r);
    // chats: Vector<Chat>
    if ((try rU32(&r)) != tl.VECTOR_CTOR) return error.UnexpectedCtor;
    const nc = try rI32(&r);
    if (nc < 0) return error.Malformed;
    const chats_snap = r;
    var c: usize = 0;
    while (c < @as(usize, @intCast(nc))) : (c += 1) try skipBoxed(&r);
    // users: Vector<User>
    if ((try rU32(&r)) != tl.VECTOR_CTOR) return error.UnexpectedCtor;
    const nu = try rI32(&r);
    if (nu < 0) return error.Malformed;
    return .{
        .dialogs = out[0..count],
        .n_messages = @intCast(nm),
        .messages = messages_snap,
        .n_chats = @intCast(nc),
        .chats = chats_snap,
        .n_users = @intCast(nu),
        .users = r,
    };
}

// =====================================================================
// Tests — zig test lib/mtproto/dialogs.zig
//
// Strategy: build objects with tl.Writer exactly as the layer-225 schema lays
// them out, parse them back, and assert both the extracted fields AND that the
// reader is fully consumed (remaining()==0) — the latter proves every optional
// skipper accounts for its bytes, which is what keeps a Vector<User> in sync.

fn expectHex(actual: []const u8, comptime hexstr: []const u8) !void {
    const exp = hexBytes(hexstr);
    try std.testing.expectEqualSlices(u8, &exp, actual);
}

fn hexBytes(comptime hexstr: []const u8) [hexstr.len / 2]u8 {
    var out: [hexstr.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hexstr) catch unreachable;
    return out;
}

/// Emit a fully-populated user#31774388 exercising EVERY optional skip path.
fn writeRichUser(w: *tl.Writer) !void {
    try w.writeU32(C_USER);
    // flags: 0 access_hash, 1 first, 2 last, 3 username, 4 phone, 5 photo,
    //        6 status, 10 self, 14 bot_info_version, 18 restriction_reason,
    //        19 bot_inline_placeholder, 22 lang_code, 30 emoji_status
    const flags: u32 = (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4) |
        (1 << 5) | (1 << 6) | (1 << 10) | (1 << 14) | (1 << 18) | (1 << 19) |
        (1 << 22) | (1 << 30);
    // flags2: 0 usernames, 5 stories_max_id, 8 color, 9 profile_color,
    //         12 bot_active_users, 14 bot_verification_icon, 15 send_paid_messages_stars
    const flags2: u32 = (1 << 0) | (1 << 5) | (1 << 8) | (1 << 9) | (1 << 12) |
        (1 << 14) | (1 << 15);
    try w.writeU32(flags);
    try w.writeU32(flags2);
    try w.writeLong(777000); // id
    try w.writeLong(0x1122334455667788); // access_hash
    try w.writeBytes("Telegram"); // first
    try w.writeBytes("Notifications"); // last
    try w.writeBytes("tg_notify"); // username
    try w.writeBytes("+42000"); // phone
    // photo: userProfilePhoto with stripped_thumb (flags.1)
    try w.writeU32(C_USER_PROFILE_PHOTO);
    try w.writeU32(1 << 1);
    try w.writeLong(0xDEAD); // photo_id
    try w.writeBytes(&[_]u8{ 1, 2, 3 }); // stripped_thumb
    try w.writeInt(2); // dc_id
    // status: userStatusOffline
    try w.writeU32(C_USER_STATUS_OFFLINE);
    try w.writeInt(1700000000); // was_online
    try w.writeInt(7); // bot_info_version
    // restriction_reason: Vector<RestrictionReason>[1]
    try w.writeU32(tl.VECTOR_CTOR);
    try w.writeInt(1);
    try w.writeU32(C_RESTRICTION_REASON);
    try w.writeBytes("ios");
    try w.writeBytes("porn");
    try w.writeBytes("blocked");
    try w.writeBytes("placeholder"); // bot_inline_placeholder
    try w.writeBytes("en"); // lang_code
    // emoji_status: emojiStatus with until (flags.0)
    try w.writeU32(C_EMOJI_STATUS);
    try w.writeU32(1 << 0);
    try w.writeLong(0xEEEE); // document_id
    try w.writeInt(1800000000); // until
    // usernames: Vector<Username>[1]
    try w.writeU32(tl.VECTOR_CTOR);
    try w.writeInt(1);
    try w.writeU32(C_USERNAME);
    try w.writeU32(1 << 1); // active
    try w.writeBytes("alt_name");
    // stories_max_id: recentStory with max_id (flags.1)
    try w.writeU32(C_RECENT_STORY);
    try w.writeU32(1 << 1);
    try w.writeInt(42); // max_id
    // color: peerColor with color + bg
    try w.writeU32(C_PEER_COLOR);
    try w.writeU32((1 << 0) | (1 << 1));
    try w.writeInt(3); // color
    try w.writeLong(0xC0102); // background_emoji_id
    // profile_color: peerColor with neither sub-field
    try w.writeU32(C_PEER_COLOR);
    try w.writeU32(0);
    try w.writeInt(99); // bot_active_users
    try w.writeLong(0xBEEF); // bot_verification_icon
    try w.writeLong(5); // send_paid_messages_stars
}

test "parseUser: fully-populated user — extract fields + consume every byte" {
    var buf: [512]u8 = undefined;
    var w = tl.Writer.init(&buf);
    try writeRichUser(&w);

    var r = tl.Reader.init(w.written());
    const u = try parseUser(&r);
    try std.testing.expectEqual(@as(u64, 777000), u.id);
    try std.testing.expectEqualStrings("Telegram", u.first);
    try std.testing.expectEqualStrings("Notifications", u.last);
    try std.testing.expectEqualStrings("tg_notify", u.username);
    try std.testing.expect(u.is_self);
    try std.testing.expect(!u.deleted);
    try std.testing.expectEqual(@as(usize, 0), r.remaining()); // skippers byte-perfect
}

test "parseUser: minimal user (first name only) + userEmpty, back to back in one buffer" {
    var buf: [128]u8 = undefined;
    var w = tl.Writer.init(&buf);
    // minimal user: only first_name (flags.1)
    try w.writeU32(C_USER);
    try w.writeU32(1 << 1);
    try w.writeU32(0); // flags2
    try w.writeLong(555);
    try w.writeBytes("Bob");
    // followed immediately by a userEmpty — proves the first parse stopped exactly right
    try w.writeU32(C_USER_EMPTY);
    try w.writeLong(123);

    var r = tl.Reader.init(w.written());
    const a = try parseUser(&r);
    try std.testing.expectEqual(@as(u64, 555), a.id);
    try std.testing.expectEqualStrings("Bob", a.first);
    try std.testing.expectEqualStrings("", a.username);
    const b = try parseUser(&r);
    try std.testing.expectEqual(@as(u64, 123), b.id);
    try std.testing.expect(b.deleted);
    try std.testing.expectEqual(@as(usize, 0), r.remaining());
}

test "parseSelfFromAuthorization extracts the user (flags=0)" {
    var buf: [128]u8 = undefined;
    var w = tl.Writer.init(&buf);
    try w.writeU32(C_AUTH_AUTHORIZATION);
    try w.writeU32(0); // flags: no optionals
    try w.writeU32(C_USER);
    try w.writeU32((1 << 1) | (1 << 3)); // first + username
    try w.writeU32(0);
    try w.writeLong(424242);
    try w.writeBytes("Me");
    try w.writeBytes("myhandle");

    const u = try parseSelfFromAuthorization(w.written());
    try std.testing.expectEqual(@as(u64, 424242), u.id);
    try std.testing.expectEqualStrings("Me", u.first);
    try std.testing.expectEqualStrings("myhandle", u.username);
}

test "parseContacts walks past the Contact vector to the User vector" {
    var buf: [256]u8 = undefined;
    var w = tl.Writer.init(&buf);
    try w.writeU32(C_CONTACTS_CONTACTS);
    // contacts: Vector<Contact>[2]
    try w.writeU32(tl.VECTOR_CTOR);
    try w.writeInt(2);
    try w.writeU32(C_CONTACT);
    try w.writeLong(111);
    try w.writeU32(0x997275b5); // boolTrue
    try w.writeU32(C_CONTACT);
    try w.writeLong(222);
    try w.writeU32(0xbc799737); // boolFalse
    try w.writeInt(2); // saved_count
    // users: Vector<User>[2]
    try w.writeU32(tl.VECTOR_CTOR);
    try w.writeInt(2);
    try w.writeU32(C_USER);
    try w.writeU32(1 << 1);
    try w.writeU32(0);
    try w.writeLong(111);
    try w.writeBytes("Alice");
    try w.writeU32(C_USER);
    try w.writeU32(1 << 1);
    try w.writeU32(0);
    try w.writeLong(222);
    try w.writeBytes("Carol");

    var c = try parseContacts(w.written());
    try std.testing.expectEqual(@as(usize, 2), c.n_users);
    const ua = try parseUser(&c.users);
    const ub = try parseUser(&c.users);
    try std.testing.expectEqualStrings("Alice", ua.first);
    try std.testing.expectEqualStrings("Carol", ub.first);
    try std.testing.expectEqual(@as(usize, 0), c.users.remaining());
}

test "builders match the wire exactly" {
    var b1: [32]u8 = undefined;
    try expectHex(try buildGetUsersSelf(&b1), "48a5910d" ++ "15c4b51c" ++ "01000000" ++ "3fb1c1f7");
    var b2: [16]u8 = undefined;
    try expectHex(try buildGetContacts(&b2), "129ed65d" ++ "0000000000000000");
}

test "gunzipIfPacked: inflates gzip_packed, passes plain through" {
    var out: [128]u8 = undefined;

    // a non-gzip object is returned unchanged
    const plain = [_]u8{ 0x88, 0x43, 0x77, 0x31, 1, 2, 3 }; // user# ctor + junk
    try std.testing.expectEqualSlices(u8, &plain, try gunzipIfPacked(&plain, &out));

    // gzip_packed#3072cfa1 wrapping gzip("hello mtproto gzip test 12345")
    const gz = hexBytes("1f8b0800000000000203cb48cdc9c957c82d2928ca2fc95748afca2c5028492d2e51303432363105007163b89a1d000000");
    var buf: [128]u8 = undefined;
    var w = tl.Writer.init(&buf);
    try w.writeU32(C_GZIP_PACKED);
    try w.writeBytes(&gz);
    const inflated = try gunzipIfPacked(w.written(), &out);
    try std.testing.expectEqualStrings("hello mtproto gzip test 12345", inflated);
}

test "skipBoxed: flag-gated object via the generated table (peerColor)" {
    var buf: [32]u8 = undefined;
    var w = tl.Writer.init(&buf);
    try w.writeU32(0xb54b5acf); // peerColor
    try w.writeU32((1 << 0) | (1 << 1)); // flags: color + background_emoji_id present
    try w.writeInt(5); // color
    try w.writeLong(0xABCD); // background_emoji_id
    var r = tl.Reader.init(w.written());
    try skipBoxed(&r);
    try std.testing.expectEqual(@as(usize, 0), r.remaining());
}

fn writeSimpleMessage(w: *tl.Writer, id: i32, text: []const u8) !void {
    try w.writeU32(C_MESSAGE);
    try w.writeU32(0); // flags (no optionals)
    try w.writeU32(0); // flags2
    try w.writeInt(id);
    try w.writeU32(C_PEER_USER);
    try w.writeLong(777);
    try w.writeInt(1700000000); // date
    try w.writeBytes(text);
}

test "parseMessage: extract text; skip media + entities via the table" {
    var buf: [128]u8 = undefined;
    var w = tl.Writer.init(&buf);
    try w.writeU32(C_MESSAGE);
    try w.writeU32((1 << 1) | (1 << 9) | (1 << 7)); // out + media + entities
    try w.writeU32(0); // flags2
    try w.writeInt(101); // id
    try w.writeU32(C_PEER_USER); // peer_id
    try w.writeLong(555);
    try w.writeInt(1700001234); // date
    try w.writeBytes("Hello there!"); // message
    try w.writeU32(0x3ded6320); // media = messageMediaEmpty (0 fields)
    try w.writeU32(tl.VECTOR_CTOR); // entities = [messageEntityBold(0,5)]
    try w.writeInt(1);
    try w.writeU32(0xbd610bc9);
    try w.writeInt(0);
    try w.writeInt(5);

    var r = tl.Reader.init(w.written());
    const m = try parseMessage(&r);
    try std.testing.expectEqual(@as(i32, 101), m.id);
    try std.testing.expect(m.out);
    try std.testing.expectEqual(PeerKind.user, m.peer.kind);
    try std.testing.expectEqual(@as(u64, 555), m.peer.id);
    try std.testing.expectEqual(@as(i32, 1700001234), m.date);
    try std.testing.expectEqualStrings("Hello there!", m.text);
    try std.testing.expectEqual(@as(usize, 0), r.remaining()); // table-skip byte-perfect
}

test "parseHistory + parseMessage iterate a Vector<Message>" {
    var buf: [256]u8 = undefined;
    var w = tl.Writer.init(&buf);
    try w.writeU32(C_MESSAGES_MESSAGES);
    try w.writeU32(tl.VECTOR_CTOR);
    try w.writeInt(2);
    try writeSimpleMessage(&w, 1, "first");
    try writeSimpleMessage(&w, 2, "second");

    var h = try parseHistory(w.written());
    try std.testing.expectEqual(@as(usize, 2), h.n);
    const m1 = try parseMessage(&h.msgs);
    const m2 = try parseMessage(&h.msgs);
    try std.testing.expectEqualStrings("first", m1.text);
    try std.testing.expectEqualStrings("second", m2.text);
}

test "parseHistoryUsers reaches the senders after the messages vector" {
    var buf: [256]u8 = undefined;
    var w = tl.Writer.init(&buf);
    try w.writeU32(C_MESSAGES_MESSAGES);
    try w.writeU32(tl.VECTOR_CTOR);
    try w.writeInt(1);
    try writeSimpleMessage(&w, 5, "hi");
    try w.writeU32(tl.VECTOR_CTOR); // chats: Vector<Chat>[0]
    try w.writeInt(0);
    try w.writeU32(tl.VECTOR_CTOR); // users: Vector<User>[1] = Bob(42)
    try w.writeInt(1);
    try w.writeU32(C_USER);
    try w.writeU32(1 << 1); // first only
    try w.writeU32(0);
    try w.writeLong(42);
    try w.writeBytes("Bob");

    var h = try parseHistory(w.written());
    try std.testing.expectEqual(@as(usize, 1), h.n);
    _ = try parseMessage(&h.msgs); // consume the one message
    var hu = try parseHistoryUsers(&h.msgs);
    try std.testing.expectEqual(@as(usize, 1), hu.n_users);
    const u = try parseUser(&hu.users);
    try std.testing.expectEqual(@as(u64, 42), u.id);
    try std.testing.expectEqualStrings("Bob", u.first);
}

test "buildGetHistory wire bytes (inputPeerUser)" {
    var buf: [64]u8 = undefined;
    const q = try buildGetHistory(&buf, .{ .kind = .user, .id = 0x1122 }, 0x3344, 20);
    try expectHex(q, "c5e62344" ++ // messages.getHistory#4423e6c5
        "4ca5e8dd" ++ // inputPeerUser#dde8a54c
        "2211000000000000" ++ // user_id
        "4433000000000000" ++ // access_hash
        "00000000" ++ "00000000" ++ "00000000" ++ // offset_id, offset_date, add_offset
        "14000000" ++ // limit = 20
        "00000000" ++ "00000000" ++ // max_id, min_id
        "0000000000000000"); // hash
}

// ---- dialog list ----

fn writeNotify(w: *tl.Writer) !void {
    try w.writeU32(0x99622c0c); // peerNotifySettings
    try w.writeU32(0); // flags: every optional absent
}

fn writeUserDialog(w: *tl.Writer, uid: u64, top: i32, unread: i32) !void {
    try w.writeU32(C_DIALOG);
    try w.writeU32(0); // flags
    try w.writeU32(C_PEER_USER);
    try w.writeLong(uid);
    try w.writeInt(top); // top_message
    try w.writeInt(0); // read_inbox_max_id
    try w.writeInt(0); // read_outbox_max_id
    try w.writeInt(unread); // unread_count
    try w.writeInt(0); // unread_mentions_count
    try w.writeInt(0); // unread_reactions_count
    try w.writeInt(0); // unread_poll_votes_count
    try writeNotify(w); // notify_settings
}

test "parseDialogList: dialogs + messages + chats + users stay byte-synced" {
    var buf: [1024]u8 = undefined;
    var w = tl.Writer.init(&buf);
    try w.writeU32(C_MESSAGES_DIALOGS);
    // dialogs: Vector<Dialog>[2] — one user, one channel
    try w.writeU32(tl.VECTOR_CTOR);
    try w.writeInt(2);
    try writeUserDialog(&w, 100, 11, 3);
    try w.writeU32(C_DIALOG); // a channel dialog
    try w.writeU32(0);
    try w.writeU32(C_PEER_CHANNEL);
    try w.writeLong(200);
    try w.writeInt(22); // top_message
    try w.writeInt(0);
    try w.writeInt(0);
    try w.writeInt(0); // unread_count
    try w.writeInt(0);
    try w.writeInt(0);
    try w.writeInt(0);
    try writeNotify(&w);
    // messages: Vector<Message>[2]
    try w.writeU32(tl.VECTOR_CTOR);
    try w.writeInt(2);
    try writeSimpleMessage(&w, 11, "hi from alice");
    try writeSimpleMessage(&w, 22, "channel post");
    // chats: Vector<Chat>[1] — one channel carrying an access_hash
    try w.writeU32(tl.VECTOR_CTOR);
    try w.writeInt(1);
    try w.writeU32(C_CHANNEL);
    try w.writeU32(1 << 13); // flags: access_hash present
    try w.writeU32(0); // flags2
    try w.writeLong(200); // id
    try w.writeLong(0xABCDEF); // access_hash
    try w.writeBytes("My Channel"); // title
    try w.writeU32(0x37c1011c); // photo: chatPhotoEmpty
    try w.writeInt(1700000000); // date
    // users: Vector<User>[1]
    try w.writeU32(tl.VECTOR_CTOR);
    try w.writeInt(1);
    try w.writeU32(C_USER);
    try w.writeU32(1 << 1); // first name only
    try w.writeU32(0);
    try w.writeLong(100);
    try w.writeBytes("Alice");

    var rows: [8]DialogRow = undefined;
    var list = try parseDialogList(w.written(), &rows);
    try std.testing.expectEqual(@as(usize, 2), list.dialogs.len);
    try std.testing.expectEqual(PeerKind.user, list.dialogs[0].peer.kind);
    try std.testing.expectEqual(@as(u64, 100), list.dialogs[0].peer.id);
    try std.testing.expectEqual(@as(i32, 11), list.dialogs[0].top_message);
    try std.testing.expectEqual(@as(i32, 3), list.dialogs[0].unread_count);
    try std.testing.expectEqual(PeerKind.channel, list.dialogs[1].peer.kind);
    try std.testing.expectEqual(@as(u64, 200), list.dialogs[1].peer.id);
    try std.testing.expectEqual(@as(i32, 22), list.dialogs[1].top_message);

    try std.testing.expectEqual(@as(usize, 2), list.n_messages);
    const m0 = try parseMessage(&list.messages);
    const m1 = try parseMessage(&list.messages);
    try std.testing.expectEqualStrings("hi from alice", m0.text);
    try std.testing.expectEqualStrings("channel post", m1.text);

    try std.testing.expectEqual(@as(usize, 1), list.n_chats);
    const ch0 = try parseChatHead(&list.chats);
    try std.testing.expectEqual(PeerKind.channel, ch0.kind);
    try std.testing.expectEqual(@as(u64, 200), ch0.id);
    try std.testing.expectEqual(@as(u64, 0xABCDEF), ch0.access_hash);
    try std.testing.expectEqualStrings("My Channel", ch0.title);

    // users — and prove the WHOLE reply is consumed byte-exactly
    try std.testing.expectEqual(@as(usize, 1), list.n_users);
    const usr = try parseUser(&list.users);
    try std.testing.expectEqual(@as(u64, 100), usr.id);
    try std.testing.expectEqualStrings("Alice", usr.first);
    try std.testing.expectEqual(@as(usize, 0), list.users.remaining());
}

test "parseDialogList tolerates a dialogFolder (archive) entry" {
    var buf: [512]u8 = undefined;
    var w = tl.Writer.init(&buf);
    try w.writeU32(C_MESSAGES_DIALOGS);
    try w.writeU32(tl.VECTOR_CTOR);
    try w.writeInt(2);
    // dialogFolder#71bd134c: flags, folder, peer, top, +4 unread ints
    try w.writeU32(C_DIALOG_FOLDER);
    try w.writeU32(0); // flags (pinned only)
    try w.writeU32(C_FOLDER); // folder:Folder
    try w.writeU32(0); // folder flags (photo absent)
    try w.writeInt(1); // folder id
    try w.writeBytes("Archived"); // folder title
    try w.writeU32(C_PEER_CHAT); // peer
    try w.writeLong(9);
    try w.writeInt(0); // top_message
    try w.writeInt(0);
    try w.writeInt(0);
    try w.writeInt(0);
    try w.writeInt(0); // 4 unread counts
    try writeUserDialog(&w, 100, 11, 0); // a normal dialog after the folder
    // empty messages / chats / users
    try w.writeU32(tl.VECTOR_CTOR);
    try w.writeInt(0);
    try w.writeU32(tl.VECTOR_CTOR);
    try w.writeInt(0);
    try w.writeU32(tl.VECTOR_CTOR);
    try w.writeInt(0);

    var rows: [8]DialogRow = undefined;
    var list = try parseDialogList(w.written(), &rows);
    try std.testing.expectEqual(@as(usize, 2), list.dialogs.len);
    try std.testing.expect(list.dialogs[0].is_folder);
    try std.testing.expect(!list.dialogs[1].is_folder);
    try std.testing.expectEqual(@as(u64, 100), list.dialogs[1].peer.id);
    try std.testing.expectEqual(@as(usize, 0), list.users.remaining());
}

test "buildGetDialogs / buildSendMessage wire bytes" {
    var b1: [64]u8 = undefined;
    try expectHex(try buildGetDialogs(&b1, 50), "4fcbf4a0" ++ // messages.getDialogs#a0f4cb4f
        "00000000" ++ // flags
        "00000000" ++ // offset_date
        "00000000" ++ // offset_id
        "ea183b7f" ++ // offset_peer = inputPeerEmpty#7f3b18ea
        "32000000" ++ // limit = 50
        "0000000000000000"); // hash

    var b2: [64]u8 = undefined;
    const q = try buildSendMessage(&b2, .{ .kind = .user, .id = 0x1122 }, 0x3344, "hey", 0x55);
    try expectHex(q, "5ad15c54" ++ // messages.sendMessage#545cd15a
        "00000000" ++ // flags
        "4ca5e8dd" ++ // peer = inputPeerUser#dde8a54c
        "2211000000000000" ++ // user_id
        "4433000000000000" ++ // access_hash
        "03686579" ++ // message = "hey" (len-prefixed, padded)
        "5500000000000000"); // random_id
}

// ---- live updates ----

test "parseUpdates: updateShortMessage → one synthesized incoming message" {
    var buf: [96]u8 = undefined;
    var w = tl.Writer.init(&buf);
    try w.writeU32(C_UPDATE_SHORT_MESSAGE);
    try w.writeU32(0); // flags
    try w.writeInt(42); // id
    try w.writeLong(555); // user_id
    try w.writeBytes("yo");
    try w.writeInt(1000); // pts
    try w.writeInt(1); // pts_count
    try w.writeInt(1700009999); // date
    var out: [8]Message = undefined;
    const inc = try parseUpdates(w.written(), &out);
    try std.testing.expectEqual(@as(usize, 1), inc.msgs.len);
    try std.testing.expectEqual(PeerKind.user, inc.msgs[0].peer.kind);
    try std.testing.expectEqual(@as(u64, 555), inc.msgs[0].peer.id);
    try std.testing.expectEqualStrings("yo", inc.msgs[0].text);
    try std.testing.expectEqual(@as(i32, 1700009999), inc.msgs[0].date);
    try std.testing.expect(!inc.msgs[0].out);
}

test "parseUpdates: updateShortChatMessage carries the sender + the chat dialog" {
    var buf: [96]u8 = undefined;
    var w = tl.Writer.init(&buf);
    try w.writeU32(C_UPDATE_SHORT_CHAT_MESSAGE);
    try w.writeU32(1 << 1); // flags: out
    try w.writeInt(7); // id
    try w.writeLong(111); // from_id (sender)
    try w.writeLong(222); // chat_id (dialog)
    try w.writeBytes("hi all");
    try w.writeInt(1000); // pts
    try w.writeInt(1); // pts_count
    try w.writeInt(1700000000); // date
    var out: [8]Message = undefined;
    const inc = try parseUpdates(w.written(), &out);
    try std.testing.expectEqual(@as(usize, 1), inc.msgs.len);
    try std.testing.expectEqual(PeerKind.chat, inc.msgs[0].peer.kind);
    try std.testing.expectEqual(@as(u64, 222), inc.msgs[0].peer.id);
    try std.testing.expectEqual(PeerKind.user, inc.msgs[0].from.kind);
    try std.testing.expectEqual(@as(u64, 111), inc.msgs[0].from.id);
    try std.testing.expect(inc.msgs[0].out);
}

test "parseUpdates: updateShort(updateNewMessage) reuses parseMessage" {
    var buf: [128]u8 = undefined;
    var w = tl.Writer.init(&buf);
    try w.writeU32(C_UPDATE_SHORT);
    try w.writeU32(C_UPDATE_NEW_MESSAGE);
    try writeSimpleMessage(&w, 7, "hello"); // message#..., peerUser(777)
    try w.writeInt(1000); // pts
    try w.writeInt(1); // pts_count
    try w.writeInt(1700000000); // updateShort.date
    var out: [8]Message = undefined;
    const inc = try parseUpdates(w.written(), &out);
    try std.testing.expectEqual(@as(usize, 1), inc.msgs.len);
    try std.testing.expectEqual(@as(i32, 7), inc.msgs[0].id);
    try std.testing.expectEqualStrings("hello", inc.msgs[0].text);
}

test "parseUpdates: updates container skips a non-message update + harvests users" {
    var buf: [256]u8 = undefined;
    var w = tl.Writer.init(&buf);
    try w.writeU32(C_UPDATES);
    // updates: Vector<Update>[2] = { updateReadHistoryOutbox (skipped), updateNewMessage }
    try w.writeU32(tl.VECTOR_CTOR);
    try w.writeInt(2);
    // updateReadHistoryOutbox#2f2f21bf peer:Peer max_id:int pts:int pts_count:int — table-skipped
    try w.writeU32(0x2f2f21bf);
    try w.writeU32(C_PEER_USER);
    try w.writeLong(555);
    try w.writeInt(9); // max_id
    try w.writeInt(1000); // pts
    try w.writeInt(1); // pts_count
    // updateNewMessage(message id=8 "hey")
    try w.writeU32(C_UPDATE_NEW_MESSAGE);
    try writeSimpleMessage(&w, 8, "hey");
    try w.writeInt(1001); // pts
    try w.writeInt(1); // pts_count
    // users: Vector<User>[1] = Alice(555)
    try w.writeU32(tl.VECTOR_CTOR);
    try w.writeInt(1);
    try w.writeU32(C_USER);
    try w.writeU32(1 << 1); // first only
    try w.writeU32(0);
    try w.writeLong(555);
    try w.writeBytes("Alice");
    // chats: Vector<Chat>[0] + date + seq (ignored by parseUpdates)
    try w.writeU32(tl.VECTOR_CTOR);
    try w.writeInt(0);
    try w.writeInt(1700000000); // date
    try w.writeInt(1); // seq

    var out: [8]Message = undefined;
    var inc = try parseUpdates(w.written(), &out);
    try std.testing.expectEqual(@as(usize, 1), inc.msgs.len);
    try std.testing.expectEqualStrings("hey", inc.msgs[0].text);
    try std.testing.expectEqual(@as(usize, 1), inc.n_users);
    const u = try parseUser(&inc.users);
    try std.testing.expectEqual(@as(u64, 555), u.id);
    try std.testing.expectEqualStrings("Alice", u.first);
}
