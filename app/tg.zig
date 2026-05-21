// tg.elf — send a Telegram message via the HTTP relay.
//
// First outbound HTTP client app on ZigOS. The OS doesn't have TLS yet, and
// Telegram's Bot API is HTTPS-only, so we POST plain HTTP/1.1 to a relay
// (tools/tg_relay.py) which forwards to api.telegram.org. The relay holds
// the bot token; this app only handles chat IDs and message text.
//
// Defaults assume QEMU user-mode networking: relay runs on the VM at
// 10.0.2.2:8080 (the gateway that maps to the host). Override via the
// "Relay" TextInput at runtime — typed value persists through resends.

const libc = @import("libc");
const gfx = @import("graphics");
const ui = @import("ui");
const fa = @import("font_atlas");

const ALLOC_W: u32 = 800;
const ALLOC_H: u32 = 600;
const INIT_W: u32 = 480;
const INIT_H: u32 = 360;

const RELAY_PORT: u16 = 8085;
const RELAY_DEFAULT = "10.0.2.2";

var vis_w: u32 = INIT_W;
var vis_h: u32 = INIT_H;

var relay_buf: [40]u8 = undefined;
var relay_input: ui.TextInput = undefined;

var chat_buf: [32]u8 = undefined;
var chat_input: ui.TextInput = undefined;

var msg_buf: [400]u8 = undefined;
var msg_input: ui.TextInput = undefined;

var btn_send: ui.Button = undefined;
var btn_close: ui.Button = undefined;

// Status string + color set by the send path; rendered in the body.
var status_text: [128]u8 = undefined;
var status_len: usize = 0;
var status_color: u32 = 0;

fn computeLayout(w: u32, h: u32) void {
    vis_w = w;
    vis_h = h;

    const m: u32 = 16;
    const card_x: u32 = m;
    const card_w: u32 = w -| 2 * m;
    var y: u32 = 60;

    relay_input = .{
        .x = card_x + 12,
        .y = y,
        .w = card_w -| 24,
        .h = 26,
        .buf = &relay_buf,
        .buf_len = relay_input.buf_len,
        .cursor = relay_input.cursor,
    };
    y += 26 + 26;

    chat_input = .{
        .x = card_x + 12,
        .y = y,
        .w = card_w -| 24,
        .h = 26,
        .buf = &chat_buf,
        .buf_len = chat_input.buf_len,
        .cursor = chat_input.cursor,
    };
    y += 26 + 26;

    // Message body — bigger TextInput. We give it most of the remaining
    // vertical space minus room for buttons + status line.
    const msg_h: u32 = if (h > y + 110) h -| (y + 90) else 60;
    msg_input = .{
        .x = card_x + 12,
        .y = y,
        .w = card_w -| 24,
        .h = msg_h,
        .buf = &msg_buf,
        .buf_len = msg_input.buf_len,
        .cursor = msg_input.cursor,
    };
    y += msg_h + 8;

    // Status line sits between the message box and the buttons. (Width is
    // computed at draw time so we don't need to lay it out here.)
    const btn_w: u32 = 100;
    const btn_h: u32 = 28;
    const btn_y: u32 = h -| btn_h -| 8;
    btn_close = .{ .x = (card_x + card_w) -| btn_w, .y = btn_y, .w = btn_w, .h = btn_h, .label = "Close" };
    btn_send = .{ .x = btn_close.x -| btn_w -| 10, .y = btn_y, .w = btn_w, .h = btn_h, .label = "Send" };
}

fn drawLabel(canvas: *gfx.Canvas, x: u32, y: u32, text: []const u8) void {
    fa.drawText(canvas, @intCast(x), @intCast(y), text, ui.palette.text_muted, &fa.default_16);
}

fn parseIp(text: []const u8) ?[4]u8 {
    var ip: [4]u8 = undefined;
    var part: u8 = 0;
    var idx: u32 = 0;
    var have: bool = false;
    for (text) |c| {
        if (c == '.') {
            if (!have or idx >= 3) return null;
            ip[idx] = part;
            idx += 1;
            part = 0;
            have = false;
        } else if (c >= '0' and c <= '9') {
            const v = @as(u32, part) * 10 + (c - '0');
            if (v > 255) return null;
            part = @intCast(v);
            have = true;
        } else {
            return null;
        }
    }
    if (!have or idx != 3) return null;
    ip[3] = part;
    return ip;
}

fn setStatus(text: []const u8, color: u32) void {
    const n = @min(text.len, status_text.len);
    @memcpy(status_text[0..n], text[0..n]);
    status_len = n;
    status_color = color;
}

/// Build a JSON document `{"chat_id":N,"text":"..."}` into `out`. Escapes
/// quotes and backslashes; passes other bytes through. Returns the byte
/// count written, or null on overflow.
fn buildJsonBody(out: []u8, chat_id: []const u8, text: []const u8) ?usize {
    var n: usize = 0;
    const prefix = "{\"chat_id\":";
    if (n + prefix.len > out.len) return null;
    @memcpy(out[n..][0..prefix.len], prefix);
    n += prefix.len;
    // chat_id is numeric — copy verbatim. (Validated upstream.)
    if (n + chat_id.len > out.len) return null;
    @memcpy(out[n..][0..chat_id.len], chat_id);
    n += chat_id.len;
    const mid = ",\"text\":\"";
    if (n + mid.len > out.len) return null;
    @memcpy(out[n..][0..mid.len], mid);
    n += mid.len;
    for (text) |c| {
        if (c == '"' or c == '\\') {
            if (n + 2 > out.len) return null;
            out[n] = '\\';
            out[n + 1] = c;
            n += 2;
        } else if (c == '\n') {
            if (n + 2 > out.len) return null;
            out[n] = '\\';
            out[n + 1] = 'n';
            n += 2;
        } else if (c < 0x20) {
            // Skip other control chars; relay is more forgiving than a
            // strict parser would be.
            continue;
        } else {
            if (n + 1 > out.len) return null;
            out[n] = c;
            n += 1;
        }
    }
    const suffix = "\"}";
    if (n + suffix.len > out.len) return null;
    @memcpy(out[n..][0..suffix.len], suffix);
    n += suffix.len;
    return n;
}

fn writeDecimal(out: []u8, val: usize) ?usize {
    if (val == 0) {
        if (out.len < 1) return null;
        out[0] = '0';
        return 1;
    }
    var tmp: [20]u8 = undefined;
    var v = val;
    var k: usize = 0;
    while (v > 0) : (v /= 10) {
        tmp[k] = '0' + @as(u8, @intCast(v % 10));
        k += 1;
    }
    if (k > out.len) return null;
    var i: usize = 0;
    while (i < k) : (i += 1) out[i] = tmp[k - 1 - i];
    return k;
}

/// Build the full HTTP/1.1 request as plain bytes. Layout:
///   POST /send HTTP/1.1\r\n
///   Host: <ip>\r\n
///   Content-Type: application/json\r\n
///   Content-Length: <N>\r\n
///   Connection: close\r\n
///   \r\n
///   <body>
fn buildHttpRequest(out: []u8, host: []const u8, body: []const u8) ?usize {
    var n: usize = 0;
    const line1 = "POST /send HTTP/1.1\r\nHost: ";
    if (n + line1.len > out.len) return null;
    @memcpy(out[n..][0..line1.len], line1);
    n += line1.len;
    if (n + host.len > out.len) return null;
    @memcpy(out[n..][0..host.len], host);
    n += host.len;
    const ct = "\r\nContent-Type: application/json\r\nContent-Length: ";
    if (n + ct.len > out.len) return null;
    @memcpy(out[n..][0..ct.len], ct);
    n += ct.len;
    const wrote = writeDecimal(out[n..], body.len) orelse return null;
    n += wrote;
    const tail = "\r\nConnection: close\r\n\r\n";
    if (n + tail.len > out.len) return null;
    @memcpy(out[n..][0..tail.len], tail);
    n += tail.len;
    if (n + body.len > out.len) return null;
    @memcpy(out[n..][0..body.len], body);
    n += body.len;
    return n;
}

/// Parse the HTTP status code from the start of a response. Expects
/// "HTTP/1.X NNN ...". Returns the integer code, or null on malformed input.
fn parseStatus(resp: []const u8) ?u32 {
    // Skip "HTTP/1.X " prefix — minimum 9 chars.
    if (resp.len < 13) return null;
    if (resp[0] != 'H' or resp[1] != 'T' or resp[2] != 'T' or resp[3] != 'P') return null;
    var i: usize = 4;
    while (i < resp.len and resp[i] != ' ') : (i += 1) {}
    if (i >= resp.len) return null;
    i += 1; // skip the space
    var code: u32 = 0;
    var got: u32 = 0;
    while (i < resp.len and resp[i] >= '0' and resp[i] <= '9') : (i += 1) {
        code = code * 10 + (resp[i] - '0');
        got += 1;
        if (got > 3) break;
    }
    if (got == 0) return null;
    return code;
}

fn doSend() void {
    if (relay_input.buf_len == 0) {
        setStatus("Enter a relay IP first.", 0xCC4040);
        return;
    }
    if (chat_input.buf_len == 0) {
        setStatus("Enter a chat ID.", 0xCC4040);
        return;
    }
    if (msg_input.buf_len == 0) {
        setStatus("Type a message.", 0xCC4040);
        return;
    }

    const relay_str = relay_buf[0..relay_input.buf_len];
    const ip = parseIp(relay_str) orelse {
        setStatus("Bad relay IP (need a.b.c.d).", 0xCC4040);
        return;
    };

    var json_buf: [512]u8 = undefined;
    const json_len = buildJsonBody(
        &json_buf,
        chat_buf[0..chat_input.buf_len],
        msg_buf[0..msg_input.buf_len],
    ) orelse {
        setStatus("Message too long.", 0xCC4040);
        return;
    };

    var req_buf: [768]u8 = undefined;
    const req_len = buildHttpRequest(&req_buf, relay_str, json_buf[0..json_len]) orelse {
        setStatus("Request build failed.", 0xCC4040);
        return;
    };

    setStatus("Connecting...", ui.palette.text_muted);
    const slot = libc.tcpConnect(ip, RELAY_PORT) orelse {
        setStatus("Connect failed (relay running?).", 0xCC4040);
        return;
    };

    if (!libc.tcpSend(slot, req_buf[0..req_len])) {
        libc.tcpClose(slot);
        setStatus("Send failed.", 0xCC4040);
        return;
    }

    // Read response. Wait up to ~5s, polling every 50ms. Stop on peer close.
    var resp_buf: [1024]u8 = undefined;
    var resp_len: usize = 0;
    var ticks: u32 = 0;
    while (ticks < 100) : (ticks += 1) {
        const got = libc.tcpRecv(slot, resp_buf[resp_len..]);
        resp_len += got;
        if (resp_len >= resp_buf.len) break;
        const status = libc.tcpStatus(slot);
        if (status & libc.TCP_STATUS_PEER_CLOSED != 0 and got == 0) break;
        if (got == 0) libc.sleep(50);
    }
    libc.tcpClose(slot);

    if (resp_len == 0) {
        setStatus("No response from relay.", 0xCC4040);
        return;
    }

    const code = parseStatus(resp_buf[0..resp_len]) orelse {
        setStatus("Malformed response.", 0xCC4040);
        return;
    };

    if (code == 200) {
        setStatus("Sent.", 0x40A040);
        // Clear message body after a successful send so the next one is fresh.
        msg_input.buf_len = 0;
        msg_input.cursor = 0;
    } else {
        var b: [80]u8 = undefined;
        const fmt_msg = "Failed: HTTP ";
        @memcpy(b[0..fmt_msg.len], fmt_msg);
        const wrote = writeDecimal(b[fmt_msg.len..], code) orelse 0;
        setStatus(b[0 .. fmt_msg.len + wrote], 0xCC4040);
    }
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    @memcpy(relay_buf[0..RELAY_DEFAULT.len], RELAY_DEFAULT);
    relay_input = .{ .x = 0, .y = 0, .w = 100, .h = 26, .buf = &relay_buf, .buf_len = RELAY_DEFAULT.len, .cursor = RELAY_DEFAULT.len };
    chat_input = .{ .x = 0, .y = 0, .w = 100, .h = 26, .buf = &chat_buf };
    msg_input = .{ .x = 0, .y = 0, .w = 100, .h = 60, .buf = &msg_buf };

    const win = libc.createWindowEx(ALLOC_W, ALLOC_H, INIT_W, INIT_H) orelse libc.exit();
    var alloc_w: u32 = win.alloc_w; // current FB stride; grows on F10 maximize
    var alloc_h: u32 = win.alloc_h;
    var canvas = gfx.Canvas.init(win.fb, alloc_w, alloc_h);
    _ = libc.getWindowAlloc(); // opt this window into F10 grow-on-maximize (re-fetched in .resize)

    fa.ensureLoaded();
    computeLayout(INIT_W, INIT_H);
    setStatus("Type a chat ID + message, then click Send.", ui.palette.text_muted);

    var prev_left: bool = false;
    var tick: u32 = 0;
    // Latest mouse state, accumulated from window events.
    var cur_mx: i32 = 0;
    var cur_my: i32 = 0;
    var cur_btns: u32 = 0;

    while (true) {
        var should_quit = false;

        while (libc.pollEvent()) |ev| {
            switch (ev.kindOf()) {
                .close_request => {
                    should_quit = true;
                },
                .resize => {
                    // F10 maximize may have GROWN our framebuffer past the
                    // alloc we requested. Re-fetch and rebuild the canvas at
                    // the new stride before clamping/laying out. win.fb stays
                    // valid (kernel re-backs the same VA) so render is crisp
                    // instead of upscaled.
                    const wa = libc.getWindowAlloc();
                    if (wa.w != 0 and (wa.w != alloc_w or wa.h != alloc_h)) {
                        alloc_w = wa.w;
                        alloc_h = wa.h;
                        canvas = gfx.Canvas.init(win.fb, alloc_w, alloc_h);
                    }
                    const new_w = @min(ev.a, alloc_w);
                    const new_h = @min(ev.b, alloc_h);
                    if (new_w != vis_w or new_h != vis_h) computeLayout(new_w, new_h);
                },
                .key_char => {
                    const ch: u8 = @truncate(ev.a);
                    if (ch == 0x1B) {
                        should_quit = true;
                    } else {
                        // Per-event TextInput pump — focus tracking uses the
                        // most recent mouse state, key char goes to whichever
                        // input is currently focused.
                        const left_now_e = (cur_btns & 1) != 0;
                        _ = relay_input.update(cur_mx, cur_my, left_now_e, prev_left, ch);
                        _ = chat_input.update(cur_mx, cur_my, left_now_e, prev_left, ch);
                        _ = msg_input.update(cur_mx, cur_my, left_now_e, prev_left, ch);
                    }
                },
                .mouse_move => {
                    cur_mx = @bitCast(ev.a);
                    cur_my = @bitCast(ev.b);
                    cur_btns = ev.c;
                },
                .mouse_button => {
                    cur_btns = ev.buttonsState();
                    cur_mx = @bitCast(ev.b);
                    cur_my = @bitCast(ev.c);
                },
                else => {},
            }
        }
        if (should_quit) break;

        const left_now = (cur_btns & 1) != 0;

        // Per-frame mouse-only widget updates (focus + hover tracking; no key
        // chars here — those were consumed during the event drain above).
        _ = relay_input.update(cur_mx, cur_my, left_now, prev_left, 0);
        _ = chat_input.update(cur_mx, cur_my, left_now, prev_left, 0);
        _ = msg_input.update(cur_mx, cur_my, left_now, prev_left, 0);

        if (btn_send.update(cur_mx, cur_my, left_now, prev_left)) doSend();
        if (btn_close.update(cur_mx, cur_my, left_now, prev_left)) break;

        // ---- Render ----
        const bg = ui.palette.card_bg;
        canvas.clear(bg);

        // Title bar — same style as About: 50px gradient + AA title and subtitle.
        const title_h: u32 = 50;
        ui.verticalGradient(&canvas, 0, 0, vis_w, title_h, ui.palette.btn_primary_top, ui.palette.btn_primary_bot);
        fa.drawText(&canvas, 16, 4, "Telegram", 0xFFFFFF, &fa.default_24);
        fa.drawText(&canvas, 16, 32, "via HTTP relay", 0xCCDDFF, &fa.default_16);
        ui.drawShadow(&canvas, 0, title_h, vis_w, 1, bg);

        // Field labels above each input.
        drawLabel(&canvas, relay_input.x, relay_input.y -| 22, "Relay IP");
        drawLabel(&canvas, chat_input.x, chat_input.y -| 22, "Chat ID");
        drawLabel(&canvas, msg_input.x, msg_input.y -| 22, "Message");

        const caret_visible = (tick / 30) & 1 == 0;
        relay_input.draw(&canvas, bg, caret_visible);
        chat_input.draw(&canvas, bg, caret_visible);
        msg_input.draw(&canvas, bg, caret_visible);
        btn_send.drawStyled(&canvas, .primary, bg);
        btn_close.drawStyled(&canvas, .default, bg);

        // Status line — one line, just above the buttons.
        if (status_len > 0) {
            const sx: i32 = @intCast(relay_input.x);
            const sy: i32 = @intCast(btn_send.y -| 22);
            fa.drawText(&canvas, sx, sy, status_text[0..status_len], status_color, &fa.default_16);
        }

        libc.present();
        prev_left = left_now;
        tick +%= 1;
        libc.sleep(16);
    }

    libc.destroyWindow();
    libc.exit();
}
