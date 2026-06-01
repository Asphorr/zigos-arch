// tgmt — MTProto user-account client.
//   Stage 1: auth_key handshake.
//   Stage 2: encrypted session.
//   Stage 3: LOGIN — invokeWithLayer(initConnection(auth.sendCode)) for a code,
//            then auth.signIn to become an authorized Telegram user.
//
// Credentials live ONLY on the OS: /tg/config on the writable ext2 disk (the
// disk image is gitignored). They're entered once at first run and persisted —
// nothing sensitive ever touches the source tree. The trace mirrors to the
// terminal and the kernel serial log (klog).

const libc = @import("libc");
const mtproto = @import("mtproto");
const std = @import("std");
const gfx = @import("graphics");
const ttf = @import("ttf_text");
const tg_font = @import("tg_font");
const transport = mtproto.transport;
const auth = mtproto.auth;
const session = mtproto.session;
const api = mtproto.api;
const dialogs = mtproto.dialogs;
const qr = mtproto.qr;

const DC_IP = [4]u8{ 149, 154, 167, 51 }; // Telegram production DC2
const DC_PORT: u16 = 443;

/// Telegram production DC IPs — used when QR login reports the account lives on
/// a different DC (auth.loginTokenMigrateTo).
fn dcIp(dc_id: i32) ?[4]u8 {
    return switch (dc_id) {
        1 => .{ 149, 154, 175, 53 },
        2 => .{ 149, 154, 167, 51 },
        3 => .{ 149, 154, 175, 100 },
        4 => .{ 149, 154, 167, 91 },
        5 => .{ 91, 108, 56, 130 },
        else => null,
    };
}

fn emit(s: []const u8) void {
    libc.print(s);
    libc.klog(s);
}

fn fail(msg: []const u8) noreturn {
    emit(msg);
    libc.exit();
}

// ============================ on-device config ============================
// /tg/config — `key=value` lines, written by this app, read on every run.

const CFG_DIR = "/tg";
const CFG_PATH = "/tg/config";

var cfg_api_id: i32 = 0;
var cfg_api_hash: [96]u8 = undefined;
var cfg_api_hash_len: usize = 0;
var cfg_phone: [40]u8 = undefined;
var cfg_phone_len: usize = 0;

fn apiHash() []const u8 {
    return cfg_api_hash[0..cfg_api_hash_len];
}
fn phone() []const u8 {
    return cfg_phone[0..cfg_phone_len];
}

/// Telegram wants the number as bare digits (country code first, no '+', no
/// spaces). Strip everything else in place so any human format works.
fn normalizePhone() void {
    var w: usize = 0;
    var i: usize = 0;
    while (i < cfg_phone_len) : (i += 1) {
        const c = cfg_phone[i];
        if (c >= '0' and c <= '9') {
            cfg_phone[w] = c;
            w += 1;
        }
    }
    cfg_phone_len = w;
}

fn eql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| if (x != y) return false;
    return true;
}

fn trim(s: []const u8) []const u8 {
    var a: usize = 0;
    var b: usize = s.len;
    while (a < b and (s[a] == ' ' or s[a] == '\r' or s[a] == '\t')) a += 1;
    while (b > a and (s[b - 1] == ' ' or s[b - 1] == '\r' or s[b - 1] == '\t')) b -= 1;
    return s[a..b];
}

fn parseI32(s: []const u8) ?i32 {
    if (s.len == 0) return null;
    var v: i64 = 0;
    for (s) |c| {
        if (c < '0' or c > '9') return null;
        v = v * 10 + @as(i64, c - '0');
        if (v > 0x7fff_ffff) return null;
    }
    return @intCast(v);
}

var idbuf: [12]u8 = undefined;
fn intStr(v: i32) []const u8 {
    if (v <= 0) {
        idbuf[0] = '0';
        return idbuf[0..1];
    }
    var tmp: [12]u8 = undefined;
    var n: usize = 0;
    var x: u32 = @intCast(v);
    while (x > 0) : (x /= 10) {
        tmp[n] = '0' + @as(u8, @intCast(x % 10));
        n += 1;
    }
    for (0..n) |k| idbuf[k] = tmp[n - 1 - k];
    return idbuf[0..n];
}

/// Load /tg/config; returns true iff api_id + api_hash + phone were all read.
fn loadConfig() bool {
    const fd = libc.open(CFG_PATH) orelse return false;
    defer libc.close(fd);
    var buf: [512]u8 = undefined;
    const n = libc.fread(fd, &buf);
    if (n == 0 or n > buf.len) return false;
    const data = buf[0..n];

    var got_id = false;
    var got_hash = false;
    var got_phone = false;
    var start: usize = 0;
    var i: usize = 0;
    while (i <= data.len) : (i += 1) {
        if (i != data.len and data[i] != '\n') continue;
        const raw = trim(data[start..i]);
        start = i + 1;
        if (raw.len == 0 or raw[0] == '#') continue;
        var eq: usize = 0;
        while (eq < raw.len and raw[eq] != '=') eq += 1;
        if (eq == raw.len) continue;
        const key = trim(raw[0..eq]);
        const val = trim(raw[eq + 1 ..]);
        if (eql(key, "api_id")) {
            if (parseI32(val)) |v| {
                cfg_api_id = v;
                got_id = true;
            }
        } else if (eql(key, "api_hash")) {
            if (val.len > 0 and val.len <= cfg_api_hash.len) {
                @memcpy(cfg_api_hash[0..val.len], val);
                cfg_api_hash_len = val.len;
                got_hash = true;
            }
        } else if (eql(key, "phone")) {
            if (val.len > 0 and val.len <= cfg_phone.len) {
                @memcpy(cfg_phone[0..val.len], val);
                cfg_phone_len = val.len;
                got_phone = true;
            }
        }
    }
    return got_id and got_hash and got_phone;
}

fn writeKv(dst: []u8, key: []const u8, val: []const u8) usize {
    var p: usize = 0;
    @memcpy(dst[p..][0..key.len], key);
    p += key.len;
    dst[p] = '=';
    p += 1;
    @memcpy(dst[p..][0..val.len], val);
    p += val.len;
    dst[p] = '\n';
    p += 1;
    return p;
}

fn saveConfig() void {
    _ = libc.mkdir(CFG_DIR); // harmless if it already exists
    const fd = libc.openFlags(CFG_PATH, libc.O_CREATE | libc.O_TRUNC) orelse {
        emit("\x1b[33m[tgmt] warning: couldn't write /tg/config (creds won't persist)\x1b[0m\n");
        return;
    };
    defer libc.close(fd);
    var buf: [512]u8 = undefined;
    var p: usize = 0;
    const hdr = "# ZigOS Telegram credentials — on-device only, never committed\n";
    @memcpy(buf[p..][0..hdr.len], hdr);
    p += hdr.len;
    p += writeKv(buf[p..], "api_id", intStr(cfg_api_id));
    p += writeKv(buf[p..], "api_hash", apiHash());
    p += writeKv(buf[p..], "phone", phone());
    _ = libc.fwrite(fd, buf[0..p]);
}

// ===================== persisted session (Stage 2b) =====================
// /tg/session — the permanent auth_key + which DC it's on, written once after a
// successful login so subsequent boots skip the QR scan entirely. It's a small
// fixed-size binary blob (NOT key=value text):
//
//   magic "ZTG1" (4) | dc_id:i32 LE (4) | auth_key_id (8) | auth_key (256)
//
// This file is as sensitive as the auth_key itself — anyone with it can act as
// the account. It lives only on the gitignored on-device disk, exactly like the
// credentials. The server salt is NOT persisted: a resumed session starts with
// no salt and the first query is corrected+resent via `bad_server_salt`.

const SESS_PATH = "/tg/session";
const SESS_MAGIC = "ZTG1"; // bump the trailing digit if the layout ever changes
const SESS_LEN: usize = 4 + 4 + 8 + 256; // = 272

const Session = struct { dc: i32, key_id: [8]u8, key: [256]u8 };

/// Persist the live auth_key + DC so the next boot can resume without a QR scan.
/// Best-effort: a write failure just means we'll re-scan next time (logged, not fatal).
fn saveSession() void {
    _ = libc.mkdir(CFG_DIR); // harmless if /tg already exists
    const fd = libc.openFlags(SESS_PATH, libc.O_CREATE | libc.O_TRUNC) orelse {
        emit("\x1b[33m[tgmt] warning: couldn't write /tg/session (you'll re-scan the QR next boot)\x1b[0m\n");
        return;
    };
    defer libc.close(fd);
    var buf: [SESS_LEN]u8 = undefined;
    @memcpy(buf[0..4], SESS_MAGIC);
    std.mem.writeInt(i32, buf[4..8], g_dc, .little);
    @memcpy(buf[8..16], &g_auth.auth_key_id);
    @memcpy(buf[16..272], &g_auth.auth_key);
    _ = libc.fwrite(fd, &buf);
    emit("\x1b[32m[tgmt] session saved to /tg/session — no QR needed on the next boot\x1b[0m\n");
}

/// Load a persisted session, or null if absent / wrong size / bad magic.
fn loadSession() ?Session {
    const fd = libc.open(SESS_PATH) orelse return null;
    defer libc.close(fd);
    var buf: [SESS_LEN]u8 = undefined;
    const n = libc.fread(fd, &buf);
    if (n != SESS_LEN) return null;
    if (!eql(buf[0..4], SESS_MAGIC)) return null;
    var s: Session = undefined;
    s.dc = std.mem.readInt(i32, buf[4..8], .little);
    @memcpy(&s.key_id, buf[8..16]);
    @memcpy(&s.key, buf[16..272]);
    return s;
}

/// Truncate /tg/session to empty so loadSession rejects it. Called ONLY when the
/// server explicitly tells us the key is dead (so a network blip never wipes a
/// good session). A truncated file self-heals: the next successful login rewrites it.
fn invalidateSession() void {
    const fd = libc.openFlags(SESS_PATH, libc.O_CREATE | libc.O_TRUNC) orelse return;
    libc.close(fd);
}

/// Interactive first-run setup; saves to /tg/config. Returns false on bad input.
fn promptCreds() bool {
    emit("[tgmt] First-run setup. Creds are saved to /tg/config on the OS disk only\n");
    emit("       (never the source tree). Get them from my.telegram.org.\n");

    emit("api_id  > ");
    var b1: [24]u8 = undefined;
    const id = parseI32(trim(readLine(&b1))) orelse {
        emit("\x1b[31m[tgmt] invalid api_id\x1b[0m\n");
        return false;
    };
    cfg_api_id = id;

    emit("api_hash> ");
    var b2: [96]u8 = undefined;
    const h = trim(readLine(&b2));
    if (h.len == 0 or h.len > cfg_api_hash.len) {
        emit("\x1b[31m[tgmt] invalid api_hash\x1b[0m\n");
        return false;
    }
    @memcpy(cfg_api_hash[0..h.len], h);
    cfg_api_hash_len = h.len;

    emit("phone   > ");
    var b3: [40]u8 = undefined;
    const ph = trim(readLine(&b3));
    if (ph.len == 0 or ph.len > cfg_phone.len) {
        emit("\x1b[31m[tgmt] invalid phone\x1b[0m\n");
        return false;
    }
    @memcpy(cfg_phone[0..ph.len], ph);
    cfg_phone_len = ph.len;
    normalizePhone();

    saveConfig();
    emit("\x1b[32m[tgmt] saved to /tg/config\x1b[0m\n");
    return true;
}

/// Show the number on file and let the user keep it or type a new one.
fn confirmOrChangePhone() void {
    normalizePhone();
    emit("[tgmt] number on file: +");
    emit(phone());
    emit("\n[tgmt] press Enter to use it, or type YOUR number to change: ");
    var pb: [40]u8 = undefined;
    const np = trim(readLine(&pb));
    if (np.len == 0 or np.len > cfg_phone.len) return;
    @memcpy(cfg_phone[0..np.len], np);
    cfg_phone_len = np.len;
    normalizePhone();
    saveConfig();
    emit("[tgmt] number updated.\n");
}

// ============================ session plumbing ============================

var rng_failed = false;
fn fillRng(buf: []u8) void {
    if (!libc.getRandom(buf)) rng_failed = true;
}

var msg_id_ctr: u64 = 0;
fn nextMsgId() u64 {
    const tod = libc.gettimeofday();
    const sec: u64 = @intCast(tod.sec);
    const usec: u64 = @intCast(tod.usec);
    var id = (sec << 32) | ((usec << 12) & 0xFFFF_FFFC);
    if (id <= msg_id_ctr) id = msg_id_ctr + 4;
    msg_id_ctr = id;
    return id;
}

var seq_ctr: u32 = 0;
fn nextContentSeq() u32 {
    const s = seq_ctr * 2 + 1; // content-related -> odd
    seq_ctr += 1;
    return s;
}

var line: [160]u8 = undefined;
fn hexNib(n: u8) u8 {
    return if (n < 10) '0' + n else 'a' + (n - 10);
}
fn logHex(prefix: []const u8, bytes: []const u8) void {
    var n: usize = 0;
    for (prefix) |c| {
        if (n < line.len) {
            line[n] = c;
            n += 1;
        }
    }
    for (bytes) |b| {
        if (n + 2 > line.len) break;
        line[n] = hexNib(b >> 4);
        line[n + 1] = hexNib(b & 0xF);
        n += 2;
    }
    if (n < line.len) {
        line[n] = '\n';
        n += 1;
    }
    emit(line[0..n]);
}

fn errName(e: auth.Error) []const u8 {
    return switch (e) {
        error.Rng => "Rng (getRandom failed)",
        error.Send => "Send",
        error.Recv => "Recv / timed out",
        error.TransportError => "TransportError (server sent error frame)",
        error.BadResPQ => "BadResPQ",
        error.NonceMismatch => "NonceMismatch",
        error.FactorFailed => "FactorFailed",
        error.NoKnownKey => "NoKnownKey",
        error.RsaPad => "RsaPad",
        error.ServerDHFail => "ServerDHFail",
        error.BadServerDH => "BadServerDH",
        error.DHRange => "DHRange",
        error.DhGenRetry => "DhGenRetry",
        error.DhGenFail => "DhGenFail",
        error.BadDhGen => "BadDhGen",
        error.NonceHashMismatch => "NonceHashMismatch",
    };
}

var g_auth: auth.Auth = undefined;
var g_dc: i32 = 2; // DC the live auth_key belongs to (default DC2; updated on a QR migrate)
var session_id: [8]u8 = undefined;
var salt: [8]u8 = undefined;
// Authorized responses (e.g. a contacts list) can be tens of KB, so these are
// sized generously and kept static (off the thread stack). The result slice
// from `invoke` points into resp_pt and must survive until the caller is done.
// Receive buffers sized for the biggest reply we ask for: messages.getDialogs
// returns each dialog's last message (with media/thumbnails) + full channel and
// user objects, which for a busy account is well over 64 KB on the wire.
var inv_rbuf: [262144]u8 = undefined; // raw received frame
var resp_pt: [262144]u8 = undefined; // decrypted plaintext
var inflate_out: [524288]u8 = undefined; // gunzipped result (Telegram packs large lists)

const InvokeError = error{ Rng, Send, Recv, Transport, Decrypt, NoResult };

/// Send one encrypted TL query; return the boxed result object from the
/// rpc_result that answers it (matched by req_msg_id). Adopts a fresh salt,
/// ignores acks and stale re-sends. Returned slice points into static resp_pt.
fn invoke(conn: *transport.Conn, query: []const u8) InvokeError![]const u8 {
    // Two attempts: a freshly-resumed session has no valid salt, so the first
    // query comes back as `bad_server_salt` carrying the correct one — we adopt
    // it and resend. The live (handshake) path has a valid salt and never retries.
    var attempt: u32 = 0;
    while (attempt < 2) : (attempt += 1) {
        const my_msg_id = nextMsgId();
        const seq = nextContentSeq();
        var dg: [1152]u8 = undefined;
        const frame = session.buildEncrypted(&dg, &g_auth.auth_key, g_auth.auth_key_id, salt, session_id, my_msg_id, seq, query, fillRng) catch return error.Send;
        if (rng_failed) return error.Rng;
        conn.send(frame) catch return error.Send;

        var frames: u32 = 0;
        var resend = false;
        while (frames < 32) : (frames += 1) {
            const resp = conn.recv(&inv_rbuf) catch return error.Recv;
            if (resp.len == 4) return error.Transport;
            if (resp.len < 24) return error.Recv;
            const dec = session.decryptInto(&resp_pt, &g_auth.auth_key, g_auth.auth_key_id, resp, 8) catch return error.Decrypt;
            const scan = session.scanBody(dec.body) catch return error.Decrypt;
            if (scan.new_salt) |ns| salt = ns;
            if (scan.bad_salt) |ns| {
                salt = ns; // wrong salt — adopt the correct one and resend
                resend = true;
                break;
            }
            if (scan.rpc_result) |res| {
                if (scan.rpc_req_id == my_msg_id) // our answer (inflate if gzip_packed)
                    return dialogs.gunzipIfPacked(res, &inflate_out) catch return error.Decrypt;
                // else a stale re-send of an earlier query — ignore, keep reading
            }
        }
        if (!resend) break; // exhausted the read loop without our reply (not a salt issue)
    }
    return error.NoResult;
}

fn invokeErrName(e: InvokeError) []const u8 {
    return switch (e) {
        error.Rng => "Rng",
        error.Send => "Send",
        error.Recv => "Recv / timed out",
        error.Transport => "Transport error frame",
        error.Decrypt => "Decrypt / integrity",
        error.NoResult => "no rpc_result",
    };
}

// ============================ Stage 4: who am I + contacts ============================

var u64buf: [20]u8 = undefined;
fn u64Str(v: u64) []const u8 {
    if (v == 0) {
        u64buf[0] = '0';
        return u64buf[0..1];
    }
    var tmp: [20]u8 = undefined;
    var n: usize = 0;
    var x = v;
    while (x > 0) : (x /= 10) {
        tmp[n] = '0' + @as(u8, @intCast(x % 10));
        n += 1;
    }
    for (0..n) |k| u64buf[k] = tmp[n - 1 - k];
    return u64buf[0..n];
}

// "self" identity, copied out of the loginTokenSuccess authorization BEFORE the
// next invoke reuses resp_pt (the User's name slices point into it).
var self_name: [128]u8 = undefined;
var self_name_len: usize = 0;
var self_user: [40]u8 = undefined;
var self_user_len: usize = 0;
var self_id: u64 = 0;

fn copyOut(dst: []u8, src: []const u8) usize {
    const k = @min(src.len, dst.len);
    @memcpy(dst[0..k], src[0..k]);
    return k;
}

fn copySelf(u: dialogs.User) void {
    var n: usize = 0;
    if (u.first.len > 0) n += copyOut(self_name[n..], u.first);
    if (u.last.len > 0) {
        if (n > 0 and n < self_name.len) {
            self_name[n] = ' ';
            n += 1;
        }
        n += copyOut(self_name[n..], u.last);
    }
    self_name_len = n;
    self_user_len = copyOut(&self_user, u.username);
    self_id = u.id;
}

// ============================ Stage 5: GUI ============================
// After login we open a Telegram-style window: a scrollable chat list on the
// left, the selected conversation (message bubbles) on the right. Real contact
// names and messages are Cyrillic, which the ASCII-only SF Pro atlas can't
// draw — so all GUI text goes through a bundled DejaVu Sans TTF (ttf_text),
// which rasterizes + caches arbitrary Unicode glyphs.

// --- palette (light, macOS/Telegram-ish) ---
const COL_SIDEBAR_BG: u32 = 0xFFFFFF;
const COL_HEADER_BG: u32 = 0xFFFFFF;
const COL_DIVIDER: u32 = 0xE3E3E6;
const COL_NAME: u32 = 0x1A1A1A;
const COL_HANDLE: u32 = 0x8A8A8E;
const COL_SEL_BG: u32 = 0x3390EC; // Telegram-blue selection
const COL_SEL_NAME: u32 = 0xFFFFFF;
const COL_SEL_HANDLE: u32 = 0xD7EAFC;
const COL_HOVER_BG: u32 = 0xF1F1F4;
const COL_CHAT_BG: u32 = 0xCED9E6; // soft blue-gray behind the bubbles
const COL_BUBBLE_IN: u32 = 0xFFFFFF;
const COL_BUBBLE_OUT: u32 = 0xE7FDD4; // light green (outgoing)
const COL_BUBBLE_TXT: u32 = 0x16181A;
const COL_SERVICE_BG: u32 = 0x8499AC;
const COL_PLACEHOLDER: u32 = 0x5E6B78;
const COL_INPUT_FIELD: u32 = 0xF0F0F3;

// Telegram's avatar color ring, picked by user id.
const AVATAR_COLORS = [_]u32{ 0xE17076, 0xEDA86C, 0xA695E7, 0x7BC862, 0x6EC9CB, 0x65AADD, 0xEE7AAE };

// --- layout (px) ---
const SIDEBAR_W: u32 = 320;
const HEADER_H: u32 = 56;
const ROW_H: u32 = 58;
const AVATAR_D: u32 = 42;
const INPUT_H: u32 = 52;
const MSG_MARGIN: u32 = 16; // bubble inset from the pane edge
const MSG_GAP: u32 = 8; // vertical gap between bubbles
const PAD_X: u32 = 11; // bubble text horizontal padding
const PAD_Y: u32 = 7; // bubble text vertical padding

// --- window + text renderers (separate glyph caches over the same TTF) ---
var canvas: gfx.Canvas = undefined;
var cw: u32 = 0;
var ch: u32 = 0;
var tr: ttf.Renderer = undefined; // 15px — names + message text
var tr_sm: ttf.Renderer = undefined; // 13px — @handles, hints
var tr_hd: ttf.Renderer = undefined; // 18px — headers + avatar initials

fn initRenderers() bool {
    tr.init(tg_font.bytes, 15.0) catch return false;
    tr_sm.init(tg_font.bytes, 13.0) catch return false;
    tr_hd.init(tg_font.bytes, 18.0) catch return false;
    return true;
}

// --- GUI state ---
var sel: i32 = -1; // selected contact (-1 = none)
var hover: i32 = -1; // hovered contact row
var chat_loaded: i32 = -1; // contact whose history is currently in msgs[]
var list_scroll: i32 = 0; // px the contact list is scrolled down
var msg_scroll: i32 = 0; // px scrolled up from the newest message (0 = pinned to bottom)
var loading: bool = false; // a getHistory call is in flight
var dirty: bool = true; // a redraw is pending

// --- non-blocking network pump (keeps the UI live during getHistory) ---
const NetState = enum { idle, await_history, await_dialogs, await_send };
var net_state: NetState = .idle;
var net_req_id: u64 = 0; // msg_id we're awaiting a reply for
var net_for_contact: i32 = -1; // contact a pending history load belongs to
var net_closed: bool = false; // peer closed the connection
var spin_tick: u32 = 0; // animates the loading spinner
var net_dg: [16384]u8 = undefined; // encrypted-frame scratch for GUI queries

// --- compose box (the reply input; only active while a chat is open) ---
var input: [1024]u8 = undefined;
var input_len: usize = 0;

// --- dialog-list resolution scratch (valid only inside loadDialogsFromObj;
// the User/ChatInfo/Message slices point into the stable inflate_out buffer) ---
var dlg_rows: [256]dialogs.DialogRow = undefined;
var tmp_users: [512]dialogs.User = undefined;
var n_tmp_users: usize = 0;
var tmp_chats: [512]dialogs.ChatInfo = undefined;
var n_tmp_chats: usize = 0;
const PrevEntry = struct { kind: dialogs.PeerKind, id: u64, mid: i32, text: []const u8 };
var tmp_prev: [512]PrevEntry = undefined;
var n_tmp_prev: usize = 0;

fn decodeCp(s: []const u8, i: usize) u32 {
    const b0 = s[i];
    if (b0 < 0x80) return b0;
    if ((b0 & 0xE0) == 0xC0 and i + 1 < s.len) return (@as(u32, b0 & 0x1F) << 6) | (s[i + 1] & 0x3F);
    if ((b0 & 0xF0) == 0xE0 and i + 2 < s.len) return (@as(u32, b0 & 0x0F) << 12) | (@as(u32, s[i + 1] & 0x3F) << 6) | (s[i + 2] & 0x3F);
    if ((b0 & 0xF8) == 0xF0 and i + 3 < s.len) return (@as(u32, b0 & 0x07) << 18) | (@as(u32, s[i + 1] & 0x3F) << 12) | (@as(u32, s[i + 2] & 0x3F) << 6) | (s[i + 3] & 0x3F);
    return 0xFFFD;
}

// First UTF-8 character of `s`, ASCII-uppercased, for an avatar initial.
var initial_buf: [4]u8 = undefined;
fn avatarInitial(s: []const u8) []const u8 {
    if (s.len == 0) return "?";
    const l = ttf.Utf8.cpLen(s, 0);
    @memcpy(initial_buf[0..l], s[0..l]);
    if (l == 1 and initial_buf[0] >= 'a' and initial_buf[0] <= 'z') initial_buf[0] -= 32;
    return initial_buf[0..l];
}

fn avatarColor(id: u64) u32 {
    return AVATAR_COLORS[@intCast(id % AVATAR_COLORS.len)];
}

/// Filled circular avatar with a centered initial.
fn drawAvatar(x: i32, y: i32, d: u32, id: u64, name: []const u8) void {
    const r: u32 = d / 2;
    canvas.fillCircle(x + @as(i32, @intCast(r)), y + @as(i32, @intCast(r)), r, avatarColor(id));
    const initial = avatarInitial(name);
    const iw = tr_hd.measure(initial);
    const ix = x + @as(i32, @intCast((d -| iw) / 2));
    const iy = y + @as(i32, @intCast((d -| tr_hd.lineHeight()) / 2));
    const clip = ttf.Clip{ .x0 = 0, .y0 = 0, .x1 = @intCast(cw), .y1 = @intCast(ch) };
    _ = tr_hd.drawClip(&canvas, ix, iy, initial, 0xFFFFFF, clip);
}

// ---- contacts store: names copied out of the transient receive buffer so the
// interactive UI can re-render them after resp_pt is reused. ----
const Contact = struct {
    name: [80]u8 = undefined,
    name_len: u8 = 0,
    user: [40]u8 = undefined,
    user_len: u8 = 0,
    id: u64 = 0,
    ah: u64 = 0, // access_hash — needed to open the chat (getHistory)
    kind: dialogs.PeerKind = .user, // user / group chat / channel
    preview: [128]u8 = undefined, // last-message snippet (dialog list only)
    preview_len: u8 = 0,
    unread: i32 = 0, // unread badge count
};
var contacts: [1024]Contact = undefined;
var contact_count: usize = 0;

/// Fill a row from a User (name = first + last, @handle, id, access_hash).
fn fillUser(e: *Contact, u: dialogs.User) void {
    var n: usize = 0;
    if (u.deleted) {
        n = copyOut(&e.name, "(deleted account)");
    } else {
        if (u.first.len > 0) n += copyOut(e.name[n..], u.first);
        if (u.last.len > 0) {
            if (n > 0 and n < e.name.len) {
                e.name[n] = ' ';
                n += 1;
            }
            n += copyOut(e.name[n..], u.last);
        }
        if (n == 0) n = copyOut(&e.name, "(no name)");
    }
    e.name_len = @intCast(n);
    e.user_len = @intCast(copyOut(&e.user, u.username));
    e.id = u.id;
    e.ah = u.access_hash;
    e.kind = .user;
}

fn addContact(u: dialogs.User) void {
    if (contact_count >= contacts.len) return;
    const e = &contacts[contact_count];
    e.* = .{};
    fillUser(e, u);
    contact_count += 1;
}

/// Copy `src` into `dst` whole-UTF-8-char at a time (never split a multibyte
/// char), replacing control bytes with spaces so a message stays on one row.
fn sanitizeCopy(dst: []u8, src: []const u8) usize {
    var n: usize = 0;
    var i: usize = 0;
    while (i < src.len) {
        const b = src[i];
        const clen: usize = if (b >= 0xF0) 4 else if (b >= 0xE0) 3 else if (b >= 0xC0) 2 else 1;
        if (i + clen > src.len or n + clen > dst.len) break;
        if (clen == 1) {
            dst[n] = if (b < 0x20) ' ' else b;
        } else {
            @memcpy(dst[n..][0..clen], src[i..][0..clen]);
        }
        n += clen;
        i += clen;
    }
    return n;
}

// ---- message store + chat view (one row per message; reversed so newest is at
// the bottom, like a real chat) ----
const MAX_LINES: usize = 40;
const MsgRow = struct {
    text: [512]u8 = undefined,
    text_len: u16 = 0,
    out: bool = false,
    service: bool = false,
    // Wrapped-line layout for the current window width (computed at chat load).
    line_start: [MAX_LINES]u16 = undefined,
    line_len: [MAX_LINES]u16 = undefined,
    nlines: u8 = 0,
    bub_w: u16 = 0, // inner text width (px)
    bub_h: u16 = 0, // full bubble height (px)
};
var msgs: [128]MsgRow = undefined;
var msg_count: usize = 0;

// ---- word-wrap layout -------------------------------------------------------

fn pushLine(e: *MsgRow, nl: *usize, widest: *u32, a: usize, b: usize, w: u32) void {
    if (nl.* >= MAX_LINES) return;
    e.line_start[nl.*] = @intCast(a);
    e.line_len[nl.*] = @intCast(b - a);
    if (w > widest.*) widest.* = w;
    nl.* += 1;
}

/// Greedy word-wrap `e.text` to `max_inner` px, filling the line table + bubble
/// size. Breaks on spaces; hard-splits a word longer than a whole line.
fn layoutMessage(e: *MsgRow, max_inner: u32) void {
    const s = e.text[0..e.text_len];
    var nl: usize = 0;
    var widest: u32 = 0;
    var i: usize = 0;
    var line_start: usize = 0;
    var cur_w: u32 = 0;
    var last_space: isize = -1;
    var w_at_space: u32 = 0;
    while (i < s.len) {
        const b = s[i];
        if (b == '\n') {
            pushLine(e, &nl, &widest, line_start, i, cur_w);
            i += 1;
            line_start = i;
            cur_w = 0;
            last_space = -1;
            continue;
        }
        const l = ttf.Utf8.cpLen(s, i);
        const adv = tr.advanceOf(decodeCp(s, i));
        if (b == ' ') {
            last_space = @intCast(i);
            w_at_space = cur_w;
        }
        if (cur_w + adv > max_inner and i > line_start) {
            if (last_space >= @as(isize, @intCast(line_start))) {
                const brk: usize = @intCast(last_space);
                pushLine(e, &nl, &widest, line_start, brk, w_at_space);
                i = brk + 1; // skip the breaking space
                line_start = i;
            } else {
                pushLine(e, &nl, &widest, line_start, i, cur_w); // hard break
                line_start = i;
            }
            cur_w = 0;
            last_space = -1;
            continue;
        }
        cur_w += adv;
        i += l;
    }
    if (line_start < s.len or nl == 0) pushLine(e, &nl, &widest, line_start, s.len, cur_w);
    e.nlines = @intCast(nl);
    e.bub_w = @intCast(@min(widest, max_inner));
    const lines: u32 = @max(1, @as(u32, @intCast(nl)));
    e.bub_h = @intCast(PAD_Y * 2 + lines * tr.lineHeight());
}

fn maxInnerWidth() u32 {
    const pane_w = cw -| (SIDEBAR_W + 1);
    var outer = (pane_w * 72) / 100;
    if (outer > 460) outer = 460;
    if (outer < 80) outer = 80;
    return outer -| (PAD_X * 2);
}

fn layoutAll() void {
    const mi = maxInnerWidth();
    var i: usize = 0;
    while (i < msg_count) : (i += 1) layoutMessage(&msgs[i], mi);
}

// ---- drawing ----------------------------------------------------------------

/// fillRect with the y-range clamped to [cy0, cy1) so partially-scrolled rows
/// and bubbles never underflow the u32 fillRect args.
fn fillClampY(x: i32, y: i32, w: u32, h: u32, color: u32, cy0: i32, cy1: i32) void {
    if (x < 0) return;
    var top = y;
    var bot = y + @as(i32, @intCast(h));
    if (top < cy0) top = cy0;
    if (bot > cy1) bot = cy1;
    if (bot <= top) return;
    canvas.fillRect(@intCast(x), @intCast(top), w, @intCast(bot - top), color);
}

fn drawContactRow(idx: usize, row_y: i32) void {
    const e = &contacts[idx];
    const is_sel = (sel == @as(i32, @intCast(idx)));
    const is_hov = (hover == @as(i32, @intCast(idx)) and !is_sel);
    if (is_sel) {
        fillClampY(0, row_y, SIDEBAR_W, ROW_H, COL_SEL_BG, 0, @intCast(ch));
    } else if (is_hov) {
        fillClampY(0, row_y, SIDEBAR_W, ROW_H, COL_HOVER_BG, 0, @intCast(ch));
    }
    const ay = row_y + @as(i32, @intCast((ROW_H - AVATAR_D) / 2));
    drawAvatar(11, ay, AVATAR_D, e.id, e.name[0..e.name_len]);
    const tx: i32 = 11 + @as(i32, @intCast(AVATAR_D)) + 11;

    // unread badge on the right — draw first so name/preview can avoid it
    var right_limit: i32 = @intCast(SIDEBAR_W - 8);
    if (e.unread > 0 and !is_sel) {
        const cnt = intStr(if (e.unread > 9999) 9999 else e.unread);
        const tw: i32 = @intCast(tr_sm.measure(cnt));
        const bw: u32 = @intCast(tw + 14);
        const bh: u32 = 20;
        const bx: i32 = @as(i32, @intCast(SIDEBAR_W - 10)) - @as(i32, @intCast(bw));
        const by: i32 = row_y + @as(i32, @intCast((ROW_H - bh) / 2));
        const row_bg = if (is_hov) COL_HOVER_BG else COL_SIDEBAR_BG;
        fillClampY(bx, by, bw, bh, COL_SEL_BG, @intCast(HEADER_H), @intCast(ch));
        if (by >= @as(i32, @intCast(HEADER_H)) and by + @as(i32, @intCast(bh)) <= @as(i32, @intCast(ch)))
            canvas.roundCornersRadius(@intCast(bx), @intCast(by), bw, bh, bh / 2, row_bg);
        const bclip = ttf.Clip{ .x0 = @intCast(bx), .y0 = @intCast(HEADER_H), .x1 = @intCast(SIDEBAR_W), .y1 = @intCast(ch) };
        tr_sm.drawCentered(&canvas, bx, by + 2, bw, cnt, 0xFFFFFF, bclip);
        right_limit = bx - 6;
    }

    const clip = ttf.Clip{ .x0 = 0, .y0 = @intCast(HEADER_H), .x1 = right_limit, .y1 = @intCast(ch) };
    const name_col = if (is_sel) COL_SEL_NAME else COL_NAME;
    _ = tr.drawClip(&canvas, tx, ay + 2, e.name[0..e.name_len], name_col, clip);

    // second line: last-message preview if we have one, else the @handle
    const sub_col = if (is_sel) COL_SEL_HANDLE else COL_HANDLE;
    if (e.preview_len > 0) {
        _ = tr_sm.drawClip(&canvas, tx, ay + 23, e.preview[0..e.preview_len], sub_col, clip);
    } else if (e.user_len > 0) {
        var hbuf: [48]u8 = undefined;
        hbuf[0] = '@';
        const k = @min(@as(usize, e.user_len), hbuf.len - 1);
        @memcpy(hbuf[1 .. 1 + k], e.user[0..k]);
        _ = tr_sm.drawClip(&canvas, tx, ay + 23, hbuf[0 .. 1 + k], sub_col, clip);
    }
}

fn drawSidebarHeader() void {
    canvas.fillRect(0, 0, SIDEBAR_W, HEADER_H, COL_HEADER_BG);
    const ad: u32 = 40;
    const ay: i32 = @intCast((HEADER_H - ad) / 2);
    drawAvatar(8, ay, ad, self_id, if (self_name_len > 0) self_name[0..self_name_len] else "T");
    const clip = ttf.Clip{ .x0 = 0, .y0 = 0, .x1 = @intCast(SIDEBAR_W - 8), .y1 = @intCast(HEADER_H) };
    const tx: i32 = 8 + @as(i32, @intCast(ad)) + 11;
    const nm = if (self_name_len > 0) self_name[0..self_name_len] else "Telegram";
    _ = tr.drawClip(&canvas, tx, ay + 1, nm, COL_NAME, clip);
    if (self_user_len > 0) {
        var hbuf: [48]u8 = undefined;
        hbuf[0] = '@';
        const k = @min(self_user_len, hbuf.len - 1);
        @memcpy(hbuf[1 .. 1 + k], self_user[0..k]);
        _ = tr_sm.drawClip(&canvas, tx, ay + 22, hbuf[0 .. 1 + k], COL_HANDLE, clip);
    }
    canvas.fillRect(0, HEADER_H - 1, SIDEBAR_W, 1, COL_DIVIDER);
}

fn drawList() void {
    canvas.fillRect(0, HEADER_H, SIDEBAR_W, ch -| HEADER_H, COL_SIDEBAR_BG);
    const view_h: i32 = @as(i32, @intCast(ch)) - @as(i32, @intCast(HEADER_H));
    const total: i32 = @intCast(contact_count * ROW_H);
    var maxscroll: i32 = total - view_h;
    if (maxscroll < 0) maxscroll = 0;
    if (list_scroll < 0) list_scroll = 0;
    if (list_scroll > maxscroll) list_scroll = maxscroll;
    var idx: usize = 0;
    while (idx < contact_count) : (idx += 1) {
        const row_y: i32 = @as(i32, @intCast(HEADER_H)) + @as(i32, @intCast(idx * ROW_H)) - list_scroll;
        if (row_y + @as(i32, @intCast(ROW_H)) <= 0) continue;
        if (row_y >= @as(i32, @intCast(ch))) break;
        drawContactRow(idx, row_y);
    }
    drawSidebarHeader(); // repaints over any row scrolled under it
    canvas.fillRect(SIDEBAR_W, 0, 1, ch, COL_DIVIDER);
}

fn drawCenteredText(r: *ttf.Renderer, x0: u32, w: u32, y: i32, s: []const u8, color: u32) void {
    const tw = r.measure(s);
    const px: i32 = @as(i32, @intCast(x0)) + @as(i32, @intCast((w -| tw) / 2));
    const clip = ttf.Clip{ .x0 = @intCast(x0), .y0 = 0, .x1 = @intCast(x0 + w), .y1 = @intCast(ch) };
    _ = r.drawClip(&canvas, px, y, s, color, clip);
}

fn drawChatHeader(px0: u32, pw: u32) void {
    canvas.fillRect(px0, 0, pw, HEADER_H, COL_HEADER_BG);
    const c = &contacts[@intCast(sel)];
    const ad: u32 = 40;
    const ay: i32 = @intCast((HEADER_H - ad) / 2);
    drawAvatar(@as(i32, @intCast(px0)) + 14, ay, ad, c.id, c.name[0..c.name_len]);
    const clip = ttf.Clip{ .x0 = @intCast(px0), .y0 = 0, .x1 = @intCast(cw), .y1 = @intCast(HEADER_H) };
    const tx: i32 = @as(i32, @intCast(px0)) + 14 + @as(i32, @intCast(ad)) + 12;
    _ = tr_hd.drawClip(&canvas, tx, ay + 1, c.name[0..c.name_len], COL_NAME, clip);
    if (c.user_len > 0) {
        var hbuf: [48]u8 = undefined;
        hbuf[0] = '@';
        const k = @min(@as(usize, c.user_len), hbuf.len - 1);
        @memcpy(hbuf[1 .. 1 + k], c.user[0..k]);
        _ = tr_sm.drawClip(&canvas, tx, ay + 24, hbuf[0 .. 1 + k], COL_HANDLE, clip);
    }
    canvas.fillRect(px0, HEADER_H - 1, pw, 1, COL_DIVIDER);
}

fn drawBubble(e: *const MsgRow, area_x0: u32, pw: u32, y: i32, y0: i32, y1: i32) void {
    const bw: u32 = e.bub_w + PAD_X * 2;
    const bh: u32 = e.bub_h;
    var bx: i32 = undefined;
    var col: u32 = undefined;
    if (e.service) {
        bx = @as(i32, @intCast(area_x0)) + @as(i32, @intCast((pw -| bw) / 2));
        col = COL_SERVICE_BG;
    } else if (e.out) {
        bx = @as(i32, @intCast(area_x0 + pw)) - @as(i32, @intCast(MSG_MARGIN + bw));
        col = COL_BUBBLE_OUT;
    } else {
        bx = @as(i32, @intCast(area_x0 + MSG_MARGIN));
        col = COL_BUBBLE_IN;
    }
    if (bx < @as(i32, @intCast(area_x0))) bx = @intCast(area_x0);
    fillClampY(bx, y, bw, bh, col, y0, y1);
    // Rounded corners only when the bubble is fully in view (the rounding
    // helper takes u32 coords — a partial bubble would underflow).
    if (y >= y0 and y + @as(i32, @intCast(bh)) <= y1) {
        canvas.roundCornersRadius(@intCast(bx), @intCast(y), bw, bh, 12, COL_CHAT_BG);
    }
    const txt_col: u32 = if (e.service) 0xFFFFFF else COL_BUBBLE_TXT;
    const clip = ttf.Clip{ .x0 = @intCast(area_x0), .y0 = y0, .x1 = @intCast(area_x0 + pw), .y1 = y1 };
    const lh = tr.lineHeight();
    var li: usize = 0;
    var ly = y + @as(i32, @intCast(PAD_Y));
    while (li < e.nlines) : (li += 1) {
        const a = e.line_start[li];
        const s = e.text[a .. a + e.line_len[li]];
        _ = tr.drawClip(&canvas, bx + @as(i32, @intCast(PAD_X)), ly, s, txt_col, clip);
        ly += @intCast(lh);
    }
}

fn drawMessages(px0: u32, pw: u32, y0: i32, y1: i32) void {
    canvas.fillRect(px0, @intCast(y0), pw, @intCast(y1 - y0), COL_CHAT_BG);
    if (msg_count == 0) {
        drawCenteredText(&tr, px0, pw, @divTrunc(y0 + y1, 2) - 9, "No messages yet", COL_PLACEHOLDER);
        return;
    }
    const view_h: i32 = y1 - y0;
    var total: i32 = @intCast(MSG_GAP);
    var i: usize = 0;
    while (i < msg_count) : (i += 1) total += @as(i32, @intCast(msgs[i].bub_h + MSG_GAP));
    var maxscroll: i32 = total - view_h;
    if (maxscroll < 0) maxscroll = 0;
    if (msg_scroll < 0) msg_scroll = 0;
    if (msg_scroll > maxscroll) msg_scroll = maxscroll;
    // newest pinned to the bottom; msg_scroll pushes the content down to reveal older
    var y: i32 = y1 - total + msg_scroll + @as(i32, @intCast(MSG_GAP));
    var k: usize = 0;
    while (k < msg_count) : (k += 1) {
        const e = &msgs[msg_count - 1 - k]; // store is newest-first → display oldest→newest
        const bh: i32 = @intCast(e.bub_h);
        if (y + bh > y0 and y < y1) drawBubble(e, px0, pw, y, y0, y1);
        y += bh + @as(i32, @intCast(MSG_GAP));
    }
}

fn drawInputBar(px0: u32, pw: u32) void {
    const by = ch - INPUT_H;
    canvas.fillRect(px0, by, pw, INPUT_H, COL_HEADER_BG);
    canvas.fillRect(px0, by, pw, 1, COL_DIVIDER);
    const fx = px0 + 12;
    const fy = by + 10;
    const fw = pw -| 24;
    const fh = INPUT_H - 20;
    canvas.fillRect(fx, fy, fw, fh, COL_INPUT_FIELD);
    canvas.roundCornersRadius(fx, fy, fw, fh, fh / 2, COL_HEADER_BG);
    const inner_x: i32 = @intCast(fx + 14);
    const inner_w: i32 = @intCast(fw -| 28);
    const clip = ttf.Clip{ .x0 = @intCast(fx + 6), .y0 = @intCast(by), .x1 = @intCast(fx + fw -| 6), .y1 = @intCast(ch) };
    const ty: i32 = @as(i32, @intCast(fy)) + @as(i32, @intCast((fh -| tr.lineHeight()) / 2));
    const caret_h: u32 = tr.lineHeight() -| 4;
    const caret_y: i32 = ty + 2;
    if (input_len == 0) {
        _ = tr.drawClip(&canvas, inner_x, ty, "Message", COL_HANDLE, clip);
        canvas.fillRect(@intCast(inner_x), @intCast(caret_y), 2, caret_h, COL_SEL_BG);
    } else {
        const text = input[0..input_len];
        const tw: i32 = @intCast(tr.measure(text));
        // when the text overflows, scroll it left so the caret (end) stays visible
        const draw_x: i32 = if (tw > inner_w) inner_x - (tw - inner_w) else inner_x;
        const end_x = tr.drawClip(&canvas, draw_x, ty, text, COL_NAME, clip);
        const caret_x: i32 = @min(end_x + 2, @as(i32, @intCast(fx + fw)) - 8);
        canvas.fillRect(@intCast(caret_x), @intCast(caret_y), 2, caret_h, COL_SEL_BG);
    }
}

// Eight dot positions around a ~13px ring (no trig — fixed table).
const SPIN_DX = [8]i32{ 0, 9, 13, 9, 0, -9, -13, -9 };
const SPIN_DY = [8]i32{ -13, -9, 0, 9, 13, 9, 0, -9 };

/// A rotating ring of dots: the leading dot is darkest, the trail fades toward
/// the chat background. `tick` advances the head.
fn drawSpinner(cx: i32, cy: i32, tick: u32) void {
    const head: u32 = (tick / 2) % 8;
    var i: u32 = 0;
    while (i < 8) : (i += 1) {
        const dist = (i + 8 - head) % 8; // 0 = head
        const level: u32 = @min(0x40 + dist * 0x14, 0xC8);
        const col = (level << 16) | (level << 8) | level;
        canvas.fillCircle(cx + SPIN_DX[i], cy + SPIN_DY[i], 3, col);
    }
}

fn drawMain() void {
    const px0 = SIDEBAR_W + 1;
    const pw = cw -| px0;
    if (sel < 0) {
        canvas.fillRect(px0, 0, pw, ch, COL_CHAT_BG);
        drawCenteredText(&tr_hd, px0, pw, @as(i32, @intCast(ch / 2)) - 12, "Select a chat to start messaging", COL_PLACEHOLDER);
        return;
    }
    drawChatHeader(px0, pw);
    const y0: i32 = @intCast(HEADER_H);
    const y1: i32 = @as(i32, @intCast(ch)) - @as(i32, @intCast(INPUT_H));
    if (loading or chat_loaded != sel) {
        canvas.fillRect(px0, @intCast(y0), pw, @intCast(y1 - y0), COL_CHAT_BG);
        const cx: i32 = @intCast(px0 + pw / 2);
        const cy: i32 = @divTrunc(y0 + y1, 2) - 14;
        drawSpinner(cx, cy, spin_tick);
        drawCenteredText(&tr_sm, px0, pw, cy + 22, "Loading messages", COL_PLACEHOLDER);
    } else {
        drawMessages(px0, pw, y0, y1);
    }
    drawInputBar(px0, pw);
}

fn redrawAll() void {
    drawMain();
    drawList();
}

// ---- non-blocking network pump ---------------------------------------------
// The GUI never blocks on the network. A query is sent, then pumpNet() drains
// frames each event-loop tick; the reply slots in when it arrives. Meanwhile
// the window keeps repainting (animated spinner), so nothing ever "freezes".
// (The login flow above still uses the blocking `invoke` — that's fine, it runs
// before the window opens.)

/// Encrypt + send a TL query on the live session; remember its msg_id so the
/// pump can match the reply. Returns false if the frame couldn't be built/sent.
fn sendQuery(conn: *transport.Conn, query: []const u8) bool {
    const my = nextMsgId();
    const seq = nextContentSeq();
    const frame = session.buildEncrypted(&net_dg, &g_auth.auth_key, g_auth.auth_key_id, salt, session_id, my, seq, query, fillRng) catch return false;
    if (rng_failed) return false;
    conn.send(frame) catch return false;
    net_req_id = my;
    return true;
}

/// Ask for a contact's history. Non-blocking — the reply lands via pumpNet().
fn requestHistory(conn: *transport.Conn, idx: usize) void {
    const c = &contacts[idx];
    var qbuf: [64]u8 = undefined;
    const q = dialogs.buildGetHistory(&qbuf, .{ .kind = c.kind, .id = c.id }, c.ah, 40) catch {
        loading = false;
        return;
    };
    if (!sendQuery(conn, q)) {
        loading = false;
        return;
    }
    net_for_contact = @intCast(idx);
    net_state = .await_history;
}

/// Parse a messages.Messages object into the message store + lay it out.
fn loadHistoryFromObj(obj: []const u8) void {
    var h = dialogs.parseHistory(obj) catch {
        msg_count = 0;
        return;
    };
    msg_count = 0;
    var i: usize = 0;
    while (i < h.n and msg_count < msgs.len) : (i += 1) {
        const m = dialogs.parseMessage(&h.msgs) catch break;
        const e = &msgs[msg_count];
        const src = if (m.service) "service message" else if (m.empty) "(empty message)" else m.text;
        e.text_len = @intCast(sanitizeCopy(&e.text, src));
        e.out = m.out;
        e.service = m.service;
        msg_count += 1;
    }
    layoutAll();
}

// ---- dialog list (messages.getDialogs) -------------------------------------

/// Kick off a non-blocking getDialogs — upgrades the sidebar from the plain
/// contacts list to the full dialog list (groups + channels + previews).
fn requestDialogs(conn: *transport.Conn) void {
    var qbuf: [48]u8 = undefined;
    const q = dialogs.buildGetDialogs(&qbuf, 50) catch return;
    if (!sendQuery(conn, q)) return;
    net_state = .await_dialogs;
}

fn findUserById(id: u64) ?*const dialogs.User {
    var i: usize = 0;
    while (i < n_tmp_users) : (i += 1) if (tmp_users[i].id == id) return &tmp_users[i];
    return null;
}

fn findChatById(id: u64) ?*const dialogs.ChatInfo {
    var i: usize = 0;
    while (i < n_tmp_chats) : (i += 1) if (tmp_chats[i].id == id) return &tmp_chats[i];
    return null;
}

fn findPreview(kind: dialogs.PeerKind, id: u64, mid: i32) ?[]const u8 {
    var i: usize = 0;
    while (i < n_tmp_prev) : (i += 1) {
        const p = &tmp_prev[i];
        if (p.mid == mid and p.kind == kind and p.id == id) return p.text;
    }
    return null;
}

/// Replace the sidebar list with the full dialog list. The User/ChatInfo/Message
/// slices point into the stable inflate_out buffer; names + previews are copied
/// out into contacts[] before this returns.
fn loadDialogsFromObj(obj: []const u8) void {
    var list = dialogs.parseDialogList(obj, &dlg_rows) catch {
        emit("\x1b[33m[tgmt] couldn't parse the dialog list; keeping contacts\x1b[0m\n");
        return;
    };
    if (sel >= 0) return; // a chat is already open — don't yank the list away

    // index users / chats / top-messages for name + preview resolution
    n_tmp_users = 0;
    var i: usize = 0;
    while (i < list.n_users and n_tmp_users < tmp_users.len) : (i += 1) {
        tmp_users[n_tmp_users] = dialogs.parseUser(&list.users) catch break;
        n_tmp_users += 1;
    }
    n_tmp_chats = 0;
    i = 0;
    while (i < list.n_chats and n_tmp_chats < tmp_chats.len) : (i += 1) {
        tmp_chats[n_tmp_chats] = dialogs.parseChatHead(&list.chats) catch break;
        n_tmp_chats += 1;
    }
    n_tmp_prev = 0;
    i = 0;
    while (i < list.n_messages and n_tmp_prev < tmp_prev.len) : (i += 1) {
        const m = dialogs.parseMessage(&list.messages) catch break;
        const t: []const u8 = if (m.service) "service message" else if (m.empty) "" else m.text;
        tmp_prev[n_tmp_prev] = .{ .kind = m.peer.kind, .id = m.peer.id, .mid = m.id, .text = t };
        n_tmp_prev += 1;
    }

    // build the rows in the order the server returned them (newest first)
    contact_count = 0;
    for (list.dialogs) |d| {
        if (d.is_folder) continue; // the "Archived chats" pseudo-dialog
        if (contact_count >= contacts.len) break;
        const e = &contacts[contact_count];
        e.* = .{};
        e.id = d.peer.id;
        e.kind = d.peer.kind;
        e.unread = d.unread_count;
        switch (d.peer.kind) {
            .user => {
                if (findUserById(d.peer.id)) |u| {
                    fillUser(e, u.*);
                } else {
                    e.name_len = @intCast(copyOut(&e.name, "(unknown user)"));
                }
            },
            .chat, .channel => {
                if (findChatById(d.peer.id)) |c| {
                    e.ah = c.access_hash;
                    if (c.title.len > 0)
                        e.name_len = @intCast(sanitizeCopy(&e.name, c.title))
                    else
                        e.name_len = @intCast(copyOut(&e.name, "(no title)"));
                } else {
                    e.name_len = @intCast(copyOut(&e.name, "(unknown chat)"));
                }
            },
            .none => e.name_len = @intCast(copyOut(&e.name, "(unknown)")),
        }
        if (findPreview(d.peer.kind, d.peer.id, d.top_message)) |t| {
            e.preview_len = @intCast(sanitizeCopy(&e.preview, t));
        }
        contact_count += 1;
    }

    sel = -1; // the list changed identity → drop any selection / scroll
    chat_loaded = -1;
    msg_count = 0;
    list_scroll = 0;
    emit("[tgmt] loaded ");
    emit(u64Str(@intCast(contact_count)));
    emit(" chats (dialog list)\n");
}

/// Dispatch a matched rpc_result by what we were waiting for.
fn handleResult(res: []const u8) void {
    const obj = dialogs.gunzipIfPacked(res, &inflate_out) catch {
        net_state = .idle;
        loading = false;
        dirty = true;
        return;
    };
    const is_err = api.isRpcError(obj);
    var er: api.RpcError = .{ .code = 0, .message = "rpc_error" };
    if (is_err) er = api.parseRpcError(obj) catch er;
    switch (net_state) {
        .await_history => {
            if (is_err) {
                emit("\x1b[31m[tgmt] chat load rpc_error: ");
                emit(er.message);
                emit("\x1b[0m\n");
                msg_count = 0;
            } else loadHistoryFromObj(obj);
            chat_loaded = net_for_contact;
        },
        .await_dialogs => {
            if (is_err) {
                emit("\x1b[33m[tgmt] getDialogs rpc_error: ");
                emit(er.message);
                emit("\x1b[0m\n");
            } else loadDialogsFromObj(obj);
        },
        .await_send => {
            if (is_err) {
                emit("\x1b[31m[tgmt] send failed: ");
                emit(er.message);
                emit("\x1b[0m\n");
            }
        },
        .idle => {},
    }
    net_state = .idle;
    loading = false;
    dirty = true;
}

// ---- compose + send --------------------------------------------------------

/// Remove the last whole UTF-8 character from the compose buffer.
fn inputBackspace() void {
    if (input_len == 0) return;
    var k: usize = input_len - 1;
    while (k > 0 and (input[k] & 0xC0) == 0x80) k -= 1; // step over continuation bytes
    input_len = k;
}

fn inputAppendByte(b: u8) void {
    if (input_len < input.len) {
        input[input_len] = b;
        input_len += 1;
    }
}

/// Insert a just-sent message at the bottom of the chat. The store is newest-
/// first, so the newest bubble lives at index 0 — shift the rest up by one.
fn prependOutgoing(text: []const u8) void {
    if (msg_count >= msgs.len) msg_count = msgs.len - 1; // drop the oldest to make room
    var i: usize = msg_count;
    while (i > 0) : (i -= 1) msgs[i] = msgs[i - 1];
    const e = &msgs[0];
    e.* = .{};
    e.text_len = @intCast(sanitizeCopy(&e.text, text));
    e.out = true;
    e.service = false;
    layoutMessage(e, maxInnerWidth());
    msg_count += 1;
}

var send_rng: [8]u8 = undefined;

/// Send the composed text to the open chat (non-blocking) and echo it locally.
fn doSend(conn: *transport.Conn) void {
    if (sel < 0 or input_len == 0) return;
    if (net_state != .idle or chat_loaded != sel) return; // only once the chat is loaded
    const c = &contacts[@intCast(sel)];
    fillRng(&send_rng);
    if (rng_failed) {
        emit("\x1b[31m[tgmt] send: getRandom failed\x1b[0m\n");
        return;
    }
    const random_id = std.mem.readInt(u64, &send_rng, .little);
    var qbuf: [1152]u8 = undefined;
    const q = dialogs.buildSendMessage(&qbuf, .{ .kind = c.kind, .id = c.id }, c.ah, input[0..input_len], random_id) catch {
        emit("\x1b[31m[tgmt] send: message too long\x1b[0m\n");
        return;
    };
    if (!sendQuery(conn, q)) {
        emit("\x1b[31m[tgmt] send: transport error\x1b[0m\n");
        return;
    }
    net_state = .await_send;
    prependOutgoing(input[0..input_len]); // optimistic local echo
    input_len = 0;
    msg_scroll = 0; // pin to the bottom so the new bubble shows
    dirty = true;
}

/// Drain whatever frames are buffered (decrypt, adopt salts, match our reply).
/// Never blocks. Server-pushed updates that aren't our reply are consumed and
/// dropped so the socket can't back up (live-update handling comes later).
fn pumpNet(conn: *transport.Conn) void {
    var guard: u32 = 0;
    while (guard < 64) : (guard += 1) {
        const r = conn.pollFrame(&inv_rbuf) catch |e| {
            if (e == error.Closed) {
                net_closed = true;
                return;
            }
            if (e == error.TooLarge) {
                // A reply didn't fit inv_rbuf — it's being drained, so the stream
                // keeps flowing, but we lose that result. Log it and keep pumping.
                emit("\x1b[33m[tgmt] dropped an oversized frame (bigger than the receive buffer)\x1b[0m\n");
                continue;
            }
            return; // transient — stop this tick, retry next
        };
        const frame = r orelse return; // no more complete frames buffered
        if (frame.len > 16384) {
            emit("[tgmt] rx frame ");
            emit(u64Str(@intCast(frame.len)));
            emit(" bytes\n");
        }
        if (frame.len < 24) continue;
        const dec = session.decryptInto(&resp_pt, &g_auth.auth_key, g_auth.auth_key_id, frame, 8) catch continue;
        const scan = session.scanBody(dec.body) catch continue;
        if (scan.new_salt) |ns| salt = ns;
        if (scan.bad_salt) |ns| salt = ns;
        if (scan.rpc_result) |res| {
            if (net_state != .idle and scan.rpc_req_id == net_req_id) handleResult(res);
        }
    }
}

// ---- event handling ---------------------------------------------------------

/// Contact-list row index under a window y (or -1 if none / in the header).
fn listIndexAt(my: i32) i32 {
    if (my < @as(i32, @intCast(HEADER_H))) return -1;
    const rel = my - @as(i32, @intCast(HEADER_H)) + list_scroll;
    if (rel < 0) return -1;
    const i: usize = @intCast(@divTrunc(rel, @as(i32, @intCast(ROW_H))));
    if (i >= contact_count) return -1;
    return @intCast(i);
}

fn onHover(mx: i32, my: i32) void {
    const h: i32 = if (mx >= 0 and mx < @as(i32, @intCast(SIDEBAR_W))) listIndexAt(my) else -1;
    if (h != hover) {
        hover = h;
        dirty = true;
    }
}

fn onClick(mx: i32, my: i32, conn: *transport.Conn) void {
    if (mx < 0 or mx >= @as(i32, @intCast(SIDEBAR_W))) return;
    const i = listIndexAt(my);
    if (i < 0 or i == sel) return;
    sel = i;
    msg_scroll = 0;
    chat_loaded = -1;
    input_len = 0; // fresh compose box for the new chat
    loading = true;
    requestHistory(conn, @intCast(i)); // non-blocking; the reply arrives via pumpNet
    dirty = true;
}

fn onWheel(delta: i32, mx: i32) void {
    const step: i32 = 48;
    if (mx >= 0 and mx < @as(i32, @intCast(SIDEBAR_W))) {
        list_scroll -= delta * step; // wheel up (delta>0) → toward the top
    } else if (sel >= 0 and chat_loaded == sel) {
        msg_scroll += delta * step; // wheel up → reveal older messages
    }
    dirty = true;
}

fn scrollFocused(px: i32) void {
    if (sel >= 0 and chat_loaded == sel) {
        msg_scroll -= px; // +px (j) moves toward newer (bottom)
    } else {
        list_scroll += px;
    }
    dirty = true;
}

fn handleKey(k: u8) bool {
    switch (k) {
        'q', 'Q', 27 => return true, // quit
        'j', 'J' => scrollFocused(56),
        'k', 'K' => scrollFocused(-56),
        ' ' => scrollFocused(220),
        'b' => scrollFocused(-220),
        else => {},
    }
    return false;
}

/// The post-login GUI: open a window and run the Telegram client until it's
/// closed. Reading is live (getHistory on click); the session `conn` stays up.
fn runGui(conn: *transport.Conn) void {
    const scr = libc.getScreenSize();
    var want_w: u32 = if (scr.w > 40) scr.w - 40 else scr.w;
    var want_h: u32 = if (scr.h > 80) scr.h - 80 else scr.h;
    if (want_w > 980) want_w = 980;
    if (want_h > 660) want_h = 660;
    if (want_w < SIDEBAR_W + 260) want_w = SIDEBAR_W + 260;
    if (want_h < 360) want_h = 360;

    const win = libc.createWindow(want_w, want_h) orelse {
        emit("\x1b[31m[tgmt] couldn't open the GUI window\x1b[0m\n");
        return;
    };
    cw = win.alloc_w;
    ch = win.alloc_h;
    canvas = gfx.Canvas.init(win.fb, cw, ch);
    if (!initRenderers()) {
        emit("\x1b[31m[tgmt] font init failed\x1b[0m\n");
        libc.destroyWindow();
        return;
    }
    emit("[tgmt] Telegram window open — click a chat to read it, type to reply, Esc to go back.\n");

    var mx: i32 = 0;
    var my: i32 = 0;
    var prev_left = false;
    redrawAll();
    libc.present();

    while (true) {
        var got = false;
        while (libc.pollEvent()) |ev| {
            got = true;
            switch (ev.kindOf()) {
                .close_request => {
                    libc.destroyWindow();
                    return;
                },
                .key_char => {
                    const cc: u8 = @truncate(ev.a);
                    if (sel >= 0) {
                        // a chat is open → the compose box has focus
                        switch (cc) {
                            27 => { // Esc — back out to the chat list
                                sel = -1;
                                chat_loaded = -1;
                                msg_count = 0;
                                input_len = 0;
                                dirty = true;
                            },
                            '\r', '\n' => doSend(conn),
                            8, 127 => {
                                inputBackspace();
                                dirty = true;
                            },
                            else => if (cc >= 0x20 and cc < 0x7f) {
                                inputAppendByte(cc);
                                dirty = true;
                            },
                        }
                    } else if (handleKey(cc)) {
                        libc.destroyWindow();
                        return;
                    }
                },
                .mouse_move => {
                    mx = @bitCast(ev.a);
                    my = @bitCast(ev.b);
                    onHover(mx, my);
                },
                .mouse_button => {
                    if (ev.buttonIndex() == 0) {
                        const left = ev.buttonPressed();
                        mx = @bitCast(ev.b);
                        my = @bitCast(ev.c);
                        if (left and !prev_left) onClick(mx, my, conn);
                        prev_left = left;
                    }
                },
                .mouse_wheel => onWheel(@bitCast(ev.a), mx),
                else => {},
            }
        }
        // Pump the network without blocking — replies + server updates drain
        // here, so the UI thread is never stuck waiting on a recv.
        pumpNet(conn);
        if (net_closed) {
            emit("\x1b[33m[tgmt] connection closed by the server — closing window.\x1b[0m\n");
            libc.destroyWindow();
            return;
        }
        if (loading) { // animate the spinner while a chat's history is loading
            spin_tick +%= 1;
            dirty = true;
        }
        if (dirty) {
            redrawAll();
            libc.present();
            dirty = false;
        }
        if (!got) libc.sleep(12);
    }
}

/// messages.getDialogs → the full chat list (people + groups + channels, with
/// last-message previews). Blocking, via `invoke`, so the window opens with the
/// list ready and there's no startup race. Returns false (caller falls back to
/// contacts) on any transport/parse/rpc failure. The reply is large, which is
/// why the receive buffers are sized in the hundreds of KB.
fn loadDialogs(conn: *transport.Conn) bool {
    emit("[tgmt] fetching your chats...\n");
    var qbuf: [48]u8 = undefined;
    const q = dialogs.buildGetDialogs(&qbuf, 50) catch return false;
    const r = invoke(conn, q) catch |e| {
        emit("\x1b[33m[tgmt] getDialogs failed: ");
        emit(invokeErrName(e));
        emit(" — falling back to contacts\x1b[0m\n");
        return false;
    };
    if (api.isRpcError(r)) {
        const er = api.parseRpcError(r) catch api.RpcError{ .code = 0, .message = "(unparseable)" };
        emit("\x1b[33m[tgmt] getDialogs rpc_error: ");
        emit(er.message);
        emit(" — falling back to contacts\x1b[0m\n");
        return false;
    }
    loadDialogsFromObj(r); // parse + resolve names/previews into contacts[]
    return contact_count > 0;
}

/// contacts.getContacts → load the saved contacts into the store. Reuses
/// `invoke`, so it runs after self is copied out of the authorization.
fn loadContacts(conn: *transport.Conn) void {
    emit("[tgmt] fetching your contacts...\n");
    var qbuf: [16]u8 = undefined;
    const q = dialogs.buildGetContacts(&qbuf) catch return;
    const r = invoke(conn, q) catch |e| {
        emit("\x1b[31m[tgmt] getContacts failed: ");
        emit(invokeErrName(e));
        if (e == error.Recv) emit(" (list larger than the receive buffer)");
        emit("\x1b[0m\n");
        return;
    };
    if (api.isRpcError(r)) {
        const er = api.parseRpcError(r) catch api.RpcError{ .code = 0, .message = "(unparseable)" };
        emit("\x1b[31m[tgmt] getContacts rpc_error: ");
        emit(er.message);
        emit("\x1b[0m\n");
        return;
    }
    var c = dialogs.parseContacts(r) catch {
        emit("\x1b[31m[tgmt] couldn't parse contacts.contacts\x1b[0m\n");
        return;
    };
    contact_count = 0;
    var i: usize = 0;
    while (i < c.n_users) : (i += 1) {
        const u = dialogs.parseUser(&c.users) catch break;
        addContact(u);
    }
    emit("[tgmt] loaded ");
    emit(u64Str(@intCast(contact_count)));
    emit(" contacts\n");
}

/// Everything that happens once we're authorized: announce, identify self from
/// the authorization payload, and pull a first slice of real account data.
/// `authobj` points into resp_pt — self is copied out before any new invoke.
/// Print "you are: <name> @<handle> id=<n>" from the copied-out self identity.
fn announceSelf() void {
    emit("[tgmt] you are: ");
    emit(if (self_name_len > 0) self_name[0..self_name_len] else "(no name)");
    if (self_user_len > 0) {
        emit("  @");
        emit(self_user[0..self_user_len]);
    }
    emit("  id=");
    emit(u64Str(self_id));
    emit("\n");
}

/// The shared post-login work: pull the full chat list (or fall back to the
/// saved contacts) and open the GUI. Used by both a fresh login and a resumed
/// session. Blocks in the GUI until the window is closed.
fn runLoggedIn(conn: *transport.Conn) void {
    if (!loadDialogs(conn)) loadContacts(conn); // full chat list, or contacts as a fallback
    runGui(conn);
}

fn afterLogin(conn: *transport.Conn, authobj: []const u8) void {
    emit("\x1b[32m[tgmt] ===== LOGGED IN ===== we are an authorized Telegram user.\x1b[0m\n");
    if (dialogs.parseSelfFromAuthorization(authobj)) |me| {
        copySelf(me);
        announceSelf();
    } else |_| {
        emit("[tgmt] (couldn't read self from the authorization)\n");
    }
    saveSession(); // Stage 2b: persist the auth_key so the next boot skips the QR scan
    runLoggedIn(conn);
}

/// Classify a login authorization and, if we're in, run the post-login work.
fn finishLogin(conn: *transport.Conn, authobj: []const u8) QrOutcome {
    const oc = classifyToOutcome(authobj);
    if (oc == .logged_in) afterLogin(conn, authobj);
    return oc;
}

/// Blocking line read from stdin with backspace handling and echo.
fn readLine(buf: []u8) []const u8 {
    var n: usize = 0;
    while (true) {
        const c = libc.readCharBlocking();
        if (c == 0 or c == '\n' or c == '\r') break;
        if (c == 8 or c == 127) {
            if (n > 0) {
                n -= 1;
                emit("\x08 \x08");
            }
            continue;
        }
        if (n < buf.len) {
            buf[n] = c;
            n += 1;
            libc.print(buf[n - 1 .. n]); // echo
        }
    }
    emit("\n");
    return buf[0..n];
}

/// Open a connection to `ip`, run the Stage-1 handshake, and set up a fresh
/// encrypted session (auth_key + session_id + salt, seqno reset). Returns the
/// connection by value, or null on failure (reason already logged).
fn bringUpSession(ip: [4]u8) ?transport.Conn {
    var conn = transport.Conn.connect(ip, DC_PORT) catch {
        emit("\x1b[31m[tgmt] connect failed (is outbound TCP working?)\x1b[0m\n");
        return null;
    };
    emit("\x1b[32m[tgmt] TCP connected\x1b[0m\n");
    g_auth = auth.createAuthKey(&conn, emit) catch |e| {
        emit("\x1b[31m[tgmt] handshake FAILED: ");
        emit(errName(e));
        emit("\x1b[0m\n");
        conn.close();
        return null;
    };
    logHex("[tgmt] auth_key_id = ", &g_auth.auth_key_id);
    fillRng(&session_id);
    if (rng_failed) {
        emit("\x1b[31m[tgmt] getRandom failed\x1b[0m\n");
        conn.close();
        return null;
    }
    salt = g_auth.server_salt;
    seq_ctr = 0;
    return conn;
}

// ===================== resume a persisted session (Stage 2b) =====================

/// Bring up an encrypted session from a SAVED auth_key (no handshake): connect,
/// install the key, pick a fresh session_id, and start with an empty salt — the
/// first query adopts the real salt via `bad_server_salt`. Returns the conn, or
/// null on a connect/RNG failure (already logged).
fn bringUpSessionFromKey(ip: [4]u8, dc: i32, key: [256]u8, key_id: [8]u8) ?transport.Conn {
    var conn = transport.Conn.connect(ip, DC_PORT) catch {
        emit("\x1b[31m[tgmt] reconnect failed (is outbound TCP working?)\x1b[0m\n");
        return null;
    };
    emit("\x1b[32m[tgmt] TCP connected (resuming saved session)\x1b[0m\n");
    g_auth.auth_key = key;
    g_auth.auth_key_id = key_id;
    g_auth.server_salt = [_]u8{0} ** 8;
    g_dc = dc;
    fillRng(&session_id);
    if (rng_failed) {
        emit("\x1b[31m[tgmt] getRandom failed\x1b[0m\n");
        conn.close();
        return null;
    }
    salt = [_]u8{0} ** 8; // unknown until the server corrects it via bad_server_salt
    seq_ctr = 0;
    msg_id_ctr = 0;
    return conn;
}

const SelfResult = enum { ok, dead, transient };

fn startsWithStr(s: []const u8, p: []const u8) bool {
    return s.len >= p.len and eql(s[0..p.len], p);
}

/// True only for rpc_error messages that mean the auth_key is permanently
/// unusable (logged out / revoked / banned). Only these justify wiping the
/// saved session — a transient network error must never discard a good key.
fn isAuthDead(msg: []const u8) bool {
    if (startsWithStr(msg, "AUTH_KEY")) return true; // AUTH_KEY_UNREGISTERED / _INVALID / ...
    if (startsWithStr(msg, "USER_DEACTIVATED")) return true; // deleted / banned
    return eql(msg, "SESSION_REVOKED") or eql(msg, "SESSION_EXPIRED");
}

/// "Who am I" probe on a resumed connection: users.getUsers([inputUserSelf]),
/// wrapped in initConnection (it's the first query on this connection). Doubles
/// as the session-validity check, and copies self out for the GUI header.
fn fetchSelf(conn: *transport.Conn) SelfResult {
    var inner: [32]u8 = undefined;
    const bare = dialogs.buildGetUsersSelf(&inner) catch return .transient;
    var qbuf: [128]u8 = undefined;
    const q = api.buildInitWrapped(&qbuf, cfg_api_id, bare) catch return .transient;
    const r = invoke(conn, q) catch |e| {
        emit("\x1b[33m[tgmt] session check failed: ");
        emit(invokeErrName(e));
        emit("\x1b[0m\n");
        return .transient; // network/transport/decrypt — keep the saved key, retry next boot
    };
    if (api.isRpcError(r)) {
        const er = api.parseRpcError(r) catch api.RpcError{ .code = 0, .message = "(unparseable)" };
        emit("\x1b[33m[tgmt] session check rpc_error: ");
        emit(er.message);
        emit("\x1b[0m\n");
        return if (isAuthDead(er.message)) .dead else .transient;
    }
    var vh = dialogs.parseUserVectorHeader(r) catch return .transient;
    if (vh.n_users == 0) return .transient;
    const me = dialogs.parseUser(&vh.users) catch return .transient;
    copySelf(me);
    announceSelf();
    return .ok;
}

/// Stage 2b fast path: if a saved session exists, reconnect with it and run the
/// client WITHOUT a QR scan. Returns true if we logged in this way (the GUI has
/// already run and returned). Returns false to fall through to a fresh login; a
/// session the server reports as dead is wiped first so we don't retry it.
fn tryResumeSession() bool {
    const sess = loadSession() orelse return false;
    const ip = dcIp(sess.dc) orelse {
        emit("\x1b[33m[tgmt] saved session names an unknown DC — ignoring it\x1b[0m\n");
        return false;
    };
    emit("[tgmt] found a saved session (DC");
    emit(intStr(sess.dc));
    emit(") — reconnecting, no QR scan needed...\n");

    var conn = bringUpSessionFromKey(ip, sess.dc, sess.key, sess.key_id) orelse return false;
    switch (fetchSelf(&conn)) {
        .ok => {
            emit("\x1b[32m[tgmt] ===== RESUMED ===== logged in from the saved session.\x1b[0m\n");
            runLoggedIn(&conn);
            conn.close();
            return true;
        },
        .dead => {
            emit("\x1b[33m[tgmt] saved session was revoked — wiping it, falling back to QR login.\x1b[0m\n");
            invalidateSession();
            conn.close();
            return false;
        },
        .transient => {
            emit("\x1b[33m[tgmt] couldn't verify the saved session right now — keeping it, trying QR login.\x1b[0m\n");
            conn.close();
            return false;
        },
    }
}

// ============================ QR login ============================

var g_qr: qr.Code = undefined;
var url_buf: [512]u8 = undefined;
var qrline: [160]u8 = undefined;
var wait_pt: [4096]u8 = undefined;

/// updateLoginToken#564fe691 (little-endian) — the server pushes this when the
/// user approves the login on their phone.
const UPDATE_LOGIN_TOKEN_LE = [4]u8{ 0x91, 0xe6, 0x4f, 0x56 };

fn buildLoginUrl(token: []const u8) []const u8 {
    const prefix = "tg://login?token=";
    @memcpy(url_buf[0..prefix.len], prefix);
    const e = std.base64.url_safe_no_pad.Encoder;
    const out = e.encode(url_buf[prefix.len..], token);
    return url_buf[0 .. prefix.len + out.len];
}

/// true = light module (drawn as a white block) / false = dark module. Cells
/// outside the symbol are the (light) quiet zone.
fn qrLight(y: usize, x: usize, qz: usize, sz: usize) bool {
    if (y < qz or x < qz or y >= qz + sz or x >= qz + sz) return true;
    return g_qr.at(x - qz, y - qz) == 0;
}

// Half-block glyph byte slots in the kernel terminal's font atlas (added by
// tools/patch_atlas_blocks.py at 0x80..0x8F — NOT CP437). The glyph is drawn in
// the current fg colour over the cell's (dark) background, so with a bright-white
// fg: full = both halves light, upper/lower = one light half, space = both dark.
const BLK_FULL: u8 = 0x80; // █  both module-rows light
const BLK_UPPER: u8 = 0x84; // ▀  top light, bottom dark
const BLK_LOWER: u8 = 0x85; // ▄  bottom light, top dark

/// Render the QR for `text` to the console using half-block glyphs (two module
/// rows per text line). Light modules are drawn bright-white, dark modules are
/// the dark terminal background → dark-on-light, with a 4-module quiet zone.
/// Console only (not mirrored to the serial log, which can't show block glyphs).
fn renderQr(text: []const u8) bool {
    qr.encode(&g_qr, text) catch {
        emit("\x1b[31m[tgmt] QR encode failed (token too long)\x1b[0m\n");
        return false;
    };
    const sz = g_qr.size;
    const qz: usize = 4;
    const total = sz + 2 * qz;
    libc.print("\x1b[2J\x1b[H\x1b[38;2;255;255;255m"); // clear + home + pure-white fg (truecolor, max contrast)
    var ry: usize = 0;
    while (ry < total) : (ry += 2) {
        var p: usize = 0;
        var x: usize = 0;
        while (x < total) : (x += 1) {
            const top = qrLight(ry, x, qz, sz);
            const bot = if (ry + 1 < total) qrLight(ry + 1, x, qz, sz) else true;
            const cell: u8 = if (top and bot) BLK_FULL else if (top and !bot) BLK_UPPER else if (!top and bot) BLK_LOWER else ' ';
            if (p < qrline.len) {
                qrline[p] = cell;
                p += 1;
            }
        }
        if (p < qrline.len) {
            qrline[p] = '\n';
            p += 1;
        }
        libc.print(qrline[0..p]);
    }
    libc.print("\x1b[0m\n"); // reset fg
    return true;
}

/// Listen for the server's updateLoginToken push (sent when the user approves on
/// their phone). Returns true if seen; false after ~`budget_sec` so the caller
/// refreshes the (soon-to-expire) token. Adopts any fresh salt seen meanwhile.
fn waitForScan(conn: *transport.Conn, budget_sec: i64) bool {
    const start: i64 = @intCast(libc.gettimeofday().sec);
    while (@as(i64, @intCast(libc.gettimeofday().sec)) - start < budget_sec) {
        var rbuf: [4096]u8 = undefined;
        const resp = conn.recv(&rbuf) catch |e| {
            if (e == error.Closed) return false;
            continue; // ~16s read timeout — re-check the budget, keep waiting
        };
        if (resp.len < 24) continue;
        const dec = session.decryptInto(&wait_pt, &g_auth.auth_key, g_auth.auth_key_id, resp, 8) catch continue;
        if (session.scanBody(dec.body)) |sc| {
            if (sc.new_salt) |ns| salt = ns;
            if (sc.bad_salt) |ns| salt = ns;
        } else |_| {}
        if (std.mem.indexOf(u8, dec.body, &UPDATE_LOGIN_TOKEN_LE) != null) return true;
    }
    return false;
}

const QrOutcome = enum { logged_in, signup, failed };

fn classifyToOutcome(authobj: []const u8) QrOutcome {
    return switch (api.classifyAuth(authobj)) {
        .logged_in => .logged_in,
        .signup_required => .signup,
        .unexpected => .failed,
    };
}

/// After a migrate: bring up the target DC, importLoginToken, expect success.
fn doImport(dc_id: i32, token: []const u8) QrOutcome {
    emit("[tgmt] account is on DC");
    emit(intStr(dc_id));
    emit(" — migrating the session there...\n");
    const ip = dcIp(dc_id) orelse {
        emit("\x1b[31m[tgmt] unknown DC id for migration\x1b[0m\n");
        return .failed;
    };
    var nconn = bringUpSession(ip) orelse return .failed;
    defer nconn.close();
    g_dc = dc_id; // the session now lives here — saveSession() (in afterLogin) persists it
    var qbuf: [512]u8 = undefined;
    const q = api.buildImportLoginToken(&qbuf, token, cfg_api_id, true) catch return .failed;
    const r = invoke(&nconn, q) catch |e| {
        emit("\x1b[31m[tgmt] importLoginToken failed: ");
        emit(invokeErrName(e));
        emit("\x1b[0m\n");
        return .failed;
    };
    if (api.isRpcError(r)) {
        const er = api.parseRpcError(r) catch api.RpcError{ .code = 0, .message = "(unparseable)" };
        emit("\x1b[31m[tgmt] importLoginToken rpc_error: ");
        emit(er.message);
        emit("\x1b[0m\n");
        return .failed;
    }
    const lt = api.parseLoginToken(r) catch return .failed;
    return switch (lt) {
        .success => |a| finishLogin(&nconn, a),
        else => blk: {
            emit("\x1b[31m[tgmt] unexpected importLoginToken result\x1b[0m\n");
            break :blk .failed;
        },
    };
}

/// The QR-login loop: export a token, show it as a QR, wait for the phone to
/// approve (updateLoginToken push), then re-export to collect the authorization.
/// Refreshes the QR when the token expires; follows a DC migration if requested.
fn qrLogin(conn: *transport.Conn) QrOutcome {
    var first = true;
    var last_token: [300]u8 = undefined;
    var last_len: usize = 0;
    var rounds: u32 = 0;
    while (rounds < 30) : (rounds += 1) {
        var qbuf: [512]u8 = undefined;
        const q = api.buildExportLoginToken(&qbuf, cfg_api_id, apiHash(), first) catch return .failed;
        first = false;
        const r = invoke(conn, q) catch |e| {
            emit("\x1b[31m[tgmt] exportLoginToken failed: ");
            emit(invokeErrName(e));
            emit("\x1b[0m\n");
            return .failed;
        };
        if (api.isRpcError(r)) {
            const er = api.parseRpcError(r) catch api.RpcError{ .code = 0, .message = "(unparseable)" };
            emit("\x1b[31m[tgmt] exportLoginToken rpc_error: ");
            emit(er.message);
            emit("\x1b[0m\n");
            emit("[tgmt] (API_ID_INVALID = check /tg/config.)\n");
            return .failed;
        }
        const lt = api.parseLoginToken(r) catch {
            emit("\x1b[31m[tgmt] could not parse auth.LoginToken\x1b[0m\n");
            return .failed;
        };
        switch (lt) {
            .success => |a| return finishLogin(conn, a),
            .migrate => |m| {
                var tk: [300]u8 = undefined;
                if (m.token.len > tk.len) return .failed;
                @memcpy(tk[0..m.token.len], m.token);
                return doImport(m.dc_id, tk[0..m.token.len]);
            },
            .pending => |p| {
                const same = p.token.len == last_len and std.mem.eql(u8, p.token, last_token[0..last_len]);
                if (!same) {
                    if (renderQr(buildLoginUrl(p.token))) {
                        emit("[tgmt] Scan this with Telegram on your phone:\n");
                        emit("       Settings -> Devices -> Link Desktop Device\n");
                        emit("[tgmt] waiting for you to approve the login...\n");
                    }
                    if (p.token.len <= last_token.len) {
                        @memcpy(last_token[0..p.token.len], p.token);
                        last_len = p.token.len;
                    }
                }
                // refresh the QR ~3s before the token expires (clamped sane)
                const now: i64 = @intCast(libc.gettimeofday().sec);
                var budget: i64 = @as(i64, p.expires) - now - 3;
                if (budget < 10) budget = 10;
                if (budget > 60) budget = 60;
                _ = waitForScan(conn, budget);
            },
        }
    }
    emit("\x1b[33m[tgmt] QR login timed out — re-run to try again.\x1b[0m\n");
    return .failed;
}

// ============================ phone-code login (fallback) ============================

fn codeLogin(conn: *transport.Conn) void {
    emit("[tgmt] -> auth.sendCode\n");
    var qbuf: [512]u8 = undefined;
    const send_code = api.buildSendCode(&qbuf, cfg_api_id, apiHash(), phone()) catch
        return emit("\x1b[31m[tgmt] buildSendCode failed\x1b[0m\n");
    const r1 = invoke(conn, send_code) catch |e| {
        emit("\x1b[31m[tgmt] sendCode invoke failed: ");
        emit(invokeErrName(e));
        emit("\x1b[0m\n");
        return;
    };
    if (api.isRpcError(r1)) {
        const er = api.parseRpcError(r1) catch api.RpcError{ .code = 0, .message = "(unparseable)" };
        emit("\x1b[31m[tgmt] sendCode rpc_error: ");
        emit(er.message);
        emit("\x1b[0m\n");
        emit("[tgmt] (API_ID_INVALID / API_ID_PUBLISHED_FLOOD = check /tg/config; PHONE_NUMBER_INVALID = fix phone.)\n");
        return;
    }
    const sent = api.parseSentCode(r1) catch
        return emit("\x1b[31m[tgmt] could not parse auth.sentCode\x1b[0m\n");
    emit("[tgmt] code delivery: ");
    emit(api.sentCodeTypeName(sent.type_ctor));
    emit("\n");

    var pch_buf: [80]u8 = undefined;
    if (sent.phone_code_hash.len > pch_buf.len) return emit("[tgmt] phone_code_hash too long\n");
    @memcpy(pch_buf[0..sent.phone_code_hash.len], sent.phone_code_hash);
    var phone_code_hash: []const u8 = pch_buf[0..sent.phone_code_hash.len];
    emit("\x1b[32m[tgmt] code sent.\x1b[0m\n");

    while (true) {
        emit("[tgmt] type the code — or 'r' + Enter to resend via the next channel (SMS/call):\n");
        emit("code> ");
        var code_buf: [16]u8 = undefined;
        const code = trim(readLine(&code_buf));

        if (code.len == 1 and (code[0] == 'r' or code[0] == 'R')) {
            emit("[tgmt] -> auth.resendCode\n");
            var rq: [256]u8 = undefined;
            const resend = api.buildResendCode(&rq, phone(), phone_code_hash) catch
                return emit("\x1b[31m[tgmt] buildResendCode failed\x1b[0m\n");
            const rr = invoke(conn, resend) catch |e| {
                emit("\x1b[31m[tgmt] resend invoke failed: ");
                emit(invokeErrName(e));
                emit("\x1b[0m\n");
                continue;
            };
            if (api.isRpcError(rr)) {
                const er = api.parseRpcError(rr) catch api.RpcError{ .code = 0, .message = "(unparseable)" };
                emit("\x1b[31m[tgmt] resend rpc_error: ");
                emit(er.message);
                emit("\x1b[0m\n");
                continue;
            }
            const re = api.parseSentCode(rr) catch {
                emit("\x1b[31m[tgmt] could not parse resend reply\x1b[0m\n");
                continue;
            };
            emit("[tgmt] code delivery: ");
            emit(api.sentCodeTypeName(re.type_ctor));
            emit("\n");
            if (re.phone_code_hash.len <= pch_buf.len) {
                @memcpy(pch_buf[0..re.phone_code_hash.len], re.phone_code_hash);
                phone_code_hash = pch_buf[0..re.phone_code_hash.len];
            }
            continue;
        }
        if (code.len == 0) {
            emit("[tgmt] (empty — type the code, or 'r' to resend)\n");
            continue;
        }

        emit("[tgmt] -> auth.signIn\n");
        var q2: [256]u8 = undefined;
        const sign_in = api.buildSignIn(&q2, phone(), phone_code_hash, code) catch
            return emit("\x1b[31m[tgmt] buildSignIn failed\x1b[0m\n");
        const r2 = invoke(conn, sign_in) catch |e| {
            emit("\x1b[31m[tgmt] signIn invoke failed: ");
            emit(invokeErrName(e));
            emit("\x1b[0m\n");
            return;
        };
        if (api.isRpcError(r2)) {
            const er = api.parseRpcError(r2) catch api.RpcError{ .code = 0, .message = "(unparseable)" };
            emit("\x1b[31m[tgmt] signIn rpc_error: ");
            emit(er.message);
            emit("\x1b[0m\n");
            if (eql(er.message, "PHONE_CODE_INVALID") or eql(er.message, "PHONE_CODE_EMPTY") or eql(er.message, "PHONE_CODE_EXPIRED")) {
                emit("[tgmt] (try the code again, or 'r' to resend)\n");
                continue;
            }
            emit("[tgmt] (SESSION_PASSWORD_NEEDED = 2FA — next sub-stage. Anything else = re-run.)\n");
            return;
        }
        switch (api.classifyAuth(r2)) {
            .logged_in => afterLogin(conn, r2),
            .signup_required => emit("\x1b[33m[tgmt] this number has no account yet (sign-up required).\x1b[0m\n"),
            .unexpected => emit("\x1b[31m[tgmt] unexpected signIn response constructor.\x1b[0m\n"),
        }
        return;
    }
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    emit("[tgmt] MTProto user client — Stage 3: login\n");

    const have_creds = loadConfig();
    if (!have_creds) {
        if (!promptCreds()) fail("\x1b[31m[tgmt] setup incomplete — re-run.\x1b[0m\n");
    } else {
        emit("[tgmt] credentials loaded from /tg/config\n");
    }

    // Stage 2b: try to resume a persisted session first. If it works, the whole
    // client (GUI and all) runs without a handshake or a QR scan, and we're done.
    if (have_creds and tryResumeSession()) {
        libc.exit();
    }

    // No usable saved session → fresh login. (Phone confirmation only matters to
    // the code-login fallback; the QR path doesn't use the number.)
    if (have_creds) confirmOrChangePhone();

    emit("[tgmt] connecting to Telegram DC2 149.154.167.51:443 ...\n");
    var conn = bringUpSession(DC_IP) orelse fail("\x1b[31m[tgmt] could not establish a session\x1b[0m\n");
    defer conn.close();

    // Choose login method. QR is the default (no SMS, no code-delivery issues);
    // the phone-code path stays available as a fallback.
    emit("\n[tgmt] --- Stage 3: login ---\n");
    emit("[tgmt] Login method:\n");
    emit("   [Q] QR code — scan with your phone (recommended)\n");
    emit("   [C] phone code — SMS/app code\n");
    emit("choice (Q/c)> ");
    var cb: [8]u8 = undefined;
    const choice = trim(readLine(&cb));

    if (choice.len >= 1 and (choice[0] == 'c' or choice[0] == 'C')) {
        codeLogin(&conn);
    } else {
        switch (qrLogin(&conn)) {
            .logged_in => {}, // afterLogin already announced + fetched the account
            .signup => emit("\x1b[33m[tgmt] this number has no account yet (sign-up required).\x1b[0m\n"),
            .failed => emit("\x1b[31m[tgmt] QR login did not complete.\x1b[0m\n"),
        }
    }
    libc.exit();
}
