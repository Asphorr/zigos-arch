// web — a small reader-browser. A thin shell over three reusable primitives:
//   * http     — TLS-backed HTTP GET (lib/http.zig)
//   * html      — HTML → styled render.Document (lib/html.zig)
//   * render    — rich-text layout + paint + link hit-testing (lib/render.zig)
//   * webnav    — URL normalize / relative resolve / back-forward history
//
// It renders the *readable* web: headings, bold, monospace <pre>/<code>,
// indented blockquotes/lists, clickable (hover-highlighted) links, and
// images (<img>, decoded via stb_image, streamed in after the text). No
// script engine, no CSS layout — JS apps won't render.
//
// Controls:
//   - type a URL + Enter         → load it (https:// assumed if no scheme)
//   - click a link               → follow it (hover underlines it)
//   - ◄ / ► buttons, or Alt+←/→  → back / forward
//   - ←/→ (no Alt), ↑/↓, PgUp/PgDn, Home/End, wheel → scroll
//   - Backspace edits the address; Esc clears it (or quits if empty)

const libc = @import("libc");
const gfx = @import("graphics");
const fa = @import("font_atlas");
const ui = @import("ui");
const http = @import("http");
const render = @import("render");
const html = @import("html");
const webnav = @import("webnav");
const image = @import("image");

const INIT_W: u32 = 760;
const INIT_H: u32 = 560;

// Layout.
const URLBAR_H: u32 = 32;
const STATUS_H: u32 = 22;
const PAD: u32 = 14;
const SB_W: u32 = 12;
const BTN_W: u32 = 22;
const URL_X: u32 = 6 + BTN_W * 2 + 8; // text starts past the two nav buttons

// Palette (also feeds the render theme).
const BG: u32 = 0x16171A;
const URLBAR_BG: u32 = 0x2A2D33;
const URLBAR_BORDER: u32 = 0x3C404A;
const MUTED: u32 = 0x808898;
const ACCENT: u32 = 0x4DA6E0;
const ERRCOL: u32 = 0xFF8080;
const BTN_HOVER_BG: u32 = 0x3A3E46;

const theme = render.Theme{
    .text = 0xD6DAE0,
    .link = 0x6FB0FF,
    .link_hover = 0xA9D2FF,
    .link_visited = 0xB49AD6,
    .muted = MUTED,
    .bg = BG,
};

// Cap the readable text column so long lines don't stretch edge-to-edge on a
// wide window; the column is centered in the available body width.
const MAX_CONTENT_W: u32 = 720;

// Image limits. Each fetch reuses img_buf; decoded pixels live on the heap
// (freed on the next page load). Bounded so one page can't exhaust memory.
const MAX_FETCH_IMAGES: u32 = 12;
const MAX_IMG_PIXELS: u64 = 3_000_000; // ~12 MB RGBA — skip anything bigger

// --- Big buffers (.bss) ---
var resp_buf: [1024 * 1024]u8 = undefined; // page HTML (truncated past 1 MiB)
var img_buf: [1024 * 1024]u8 = undefined; // per-image fetch scratch (reused)
var doc: render.Document = .{};
var history: webnav.History = .{};
var decoded: [render.MAX_IMAGES]?image.Pixel = [_]?image.Pixel{null} ** render.MAX_IMAGES;
var g_canvas: gfx.Canvas = undefined; // global so the loader can stream repaints

var current_url: [webnav.MAX_URL]u8 = undefined;
var current_url_len: usize = 0;

var input_buf: [webnav.MAX_URL]u8 = undefined;
var input_len: usize = 0;

var status_buf: [160]u8 = undefined;
var status_len: usize = 0;
var status_is_err: bool = false;

var scroll_y: u32 = 0;
var hovered_link: i32 = -1;

// Geometry (updated on resize).
var vis_w: u32 = INIT_W;
var vis_h: u32 = INIT_H;
var alloc_w: u32 = 0;
var alloc_h: u32 = 0;

var scrollbar: ui.Scrollbar = .{ .x = 0, .y = 0, .w = 0, .h = 0 };

// Session history of visited URLs, stored as FNV-1a hashes (a bounded ring;
// collisions only ever over-dim a link, never under-dim). Links pointing at a
// visited URL paint in the muted "visited" color.
const VISITED_CAP: usize = 512;
var visited_hashes: [VISITED_CAP]u64 = [_]u64{0} ** VISITED_CAP;
var visited_count: usize = 0;

fn hashUrl(u: []const u8) u64 {
    var h: u64 = 0xcbf29ce484222325;
    for (u) |c| {
        h ^= c;
        h = h *% 0x100000001b3;
    }
    return h;
}

fn isVisited(u: []const u8) bool {
    const h = hashUrl(u);
    const n = @min(visited_count, VISITED_CAP);
    var i: usize = 0;
    while (i < n) : (i += 1) {
        if (visited_hashes[i] == h) return true;
    }
    return false;
}

fn markVisited(u: []const u8) void {
    if (u.len == 0) return;
    const h = hashUrl(u);
    const n = @min(visited_count, VISITED_CAP);
    var i: usize = 0;
    while (i < n) : (i += 1) {
        if (visited_hashes[i] == h) return; // already known
    }
    visited_hashes[visited_count % VISITED_CAP] = h;
    visited_count += 1;
}

// Dim every link in the current document that resolves to a URL we've visited.
fn applyVisited() void {
    var i: u32 = 0;
    while (i < doc.link_count) : (i += 1) {
        const href = doc.linkHref(@intCast(i));
        if (href.len == 0) continue;
        var abs: [webnav.MAX_URL]u8 = undefined;
        const u = webnav.resolveHref(current_url[0..current_url_len], href, &abs) orelse continue;
        if (isVisited(u)) doc.setLinkVisited(@intCast(i), true);
    }
}

// ---------------------------------------------------------------------
// Small helpers.

fn setStatusStr(s: []const u8, is_err: bool) void {
    const n = @min(s.len, status_buf.len);
    @memcpy(status_buf[0..n], s[0..n]);
    status_len = n;
    status_is_err = is_err;
}

fn appendNum(buf: []u8, pos: usize, n: u32) usize {
    var tmp: [10]u8 = undefined;
    var v = n;
    var k: usize = 0;
    if (v == 0) {
        tmp[0] = '0';
        k = 1;
    } else {
        while (v > 0) : (v /= 10) {
            tmp[9 - k] = @intCast('0' + (v % 10));
            k += 1;
        }
    }
    const src: []const u8 = if (n == 0) tmp[0..1] else tmp[10 - k .. 10];
    var p = pos;
    for (src) |c| {
        if (p >= buf.len) break;
        buf[p] = c;
        p += 1;
    }
    return p;
}

fn bodyOriginY() u32 {
    return URLBAR_H + 4;
}
fn bodyHeight() u32 {
    return vis_h -| URLBAR_H -| STATUS_H -| 4;
}
fn availWidth() u32 {
    return vis_w -| (PAD * 2) -| SB_W;
}
fn contentWidth() u32 {
    return @min(availWidth(), MAX_CONTENT_W);
}
// Left edge of the (possibly capped) text column, centered in the body width.
fn contentX() u32 {
    return PAD + (availWidth() -| contentWidth()) / 2;
}
fn lineStep() u32 {
    return fa.default_16.line_height;
}

fn maxScroll() u32 {
    const bh = bodyHeight();
    return if (doc.doc_height > bh) doc.doc_height - bh else 0;
}

fn clampScroll() void {
    const m = maxScroll();
    if (scroll_y > m) scroll_y = m;
}

fn relayout() void {
    render.layout(&doc, contentWidth());
    clampScroll();
}

// ---------------------------------------------------------------------
// Fetch + navigation.

fn loadUrl(u: []const u8) void {
    const un = @min(u.len, current_url.len);
    @memcpy(current_url[0..un], u[0..un]);
    current_url_len = un;
    // Mirror into the address bar.
    @memcpy(input_buf[0..un], u[0..un]);
    input_len = un;

    markVisited(current_url[0..current_url_len]);
    hovered_link = -1;
    setStatusStr("Loading...", false);
    // Show the new address + "Loading..." over the (still-valid) old page for
    // immediate feedback, THEN release the old page's images and fetch.
    drawAll(&g_canvas);
    libc.present();
    freeImages(); // release the previous page's decoded pixels

    const resp = http.send(.{
        .url = current_url[0..current_url_len],
        .truncate_oversize = true, // render the first chunk of huge pages
    }, resp_buf[0..]) catch |err| {
        doc.reset();
        relayout();
        var b: [160]u8 = undefined;
        const pfx = "fetch failed: ";
        @memcpy(b[0..pfx.len], pfx);
        const en = @errorName(err);
        const n = @min(en.len, b.len - pfx.len);
        @memcpy(b[pfx.len..][0..n], en[0..n]);
        setStatusStr(b[0 .. pfx.len + n], true);
        return;
    };

    html.parse(&doc, resp.body, theme);
    scroll_y = 0;
    relayout();
    applyVisited();

    // Idle status: [title]   HTTP NNN   N links [   (truncated)]
    var b: [160]u8 = undefined;
    var p: usize = 0;
    const ttl = doc.title();
    if (ttl.len > 0) {
        const tn = @min(ttl.len, 84);
        @memcpy(b[0..tn], ttl[0..tn]);
        p = tn;
        @memcpy(b[p..][0..3], "   ");
        p += 3;
    }
    const pfx = "HTTP ";
    @memcpy(b[p..][0..pfx.len], pfx);
    p += pfx.len;
    p = appendNum(b[0..], p, resp.status);
    const mid = "   ";
    @memcpy(b[p..][0..mid.len], mid);
    p += mid.len;
    p = appendNum(b[0..], p, doc.link_count);
    const suf = " links";
    @memcpy(b[p..][0..suf.len], suf);
    p += suf.len;
    if (doc.truncated or resp.truncated) {
        const t = "   (truncated)";
        const tn = @min(t.len, b.len - p);
        @memcpy(b[p..][0..tn], t[0..tn]);
        p += tn;
    }
    setStatusStr(b[0..p], resp.status >= 400);

    // Paint the readable text right away, then stream images in on top.
    drawAll(&g_canvas);
    libc.present();
    fetchImages();
}

/// Free all decoded image pixels (stb-allocated on the heap).
fn freeImages() void {
    for (&decoded) |*slot| {
        if (slot.*) |pic| {
            pic.deinit();
            slot.* = null;
        }
    }
}

/// Fetch + decode each <img> referenced by the current document, reflowing and
/// repainting after each so pictures pop in progressively. Bounded in count
/// and per-image pixel size; anything over budget becomes a placeholder box.
fn fetchImages() void {
    var fetched: u32 = 0;
    var i: u32 = 0;
    while (i < doc.image_count) : (i += 1) {
        const id: i32 = @intCast(i);
        if (fetched >= MAX_FETCH_IMAGES) {
            doc.setImageFailed(id);
            continue;
        }
        const raw = doc.imageUrl(id);
        if (raw.len == 0) {
            doc.setImageFailed(id);
            continue;
        }
        var abs: [webnav.MAX_URL]u8 = undefined;
        const url = webnav.resolveHref(current_url[0..current_url_len], raw, &abs) orelse {
            doc.setImageFailed(id);
            continue;
        };
        const resp = http.get(url, img_buf[0..]) catch {
            doc.setImageFailed(id);
            continue;
        };
        if (resp.status != 200 or resp.body.len == 0) {
            doc.setImageFailed(id);
            continue;
        }
        const pic = image.decode(resp.body, 4) catch {
            doc.setImageFailed(id);
            continue;
        };
        if (pic.width == 0 or pic.height == 0 or
            pic.width > 10000 or pic.height > 10000 or
            @as(u64, pic.width) * pic.height > MAX_IMG_PIXELS)
        {
            pic.deinit();
            doc.setImageFailed(id);
            continue;
        }
        decoded[i] = pic;
        doc.setImageDecoded(id, pic.width, pic.height, pic.pixels.ptr);
        fetched += 1;
        // Progressive: reflow (image now has real dims) and repaint.
        relayout();
        drawAll(&g_canvas);
        libc.present();
    }
}

/// Navigate to a freshly-typed/followed URL: normalize, record history, load.
fn go(raw: []const u8) void {
    var norm: [webnav.MAX_URL]u8 = undefined;
    const url = webnav.normalizeUrl(raw, &norm);
    if (url.len == 0) return;
    history.visit(url);
    loadUrl(url);
}

fn followLink(id: i32) void {
    const href = doc.linkHref(id);
    if (href.len == 0) {
        setStatusStr("bad link", true);
        return;
    }
    var abs: [webnav.MAX_URL]u8 = undefined;
    const url = webnav.resolveHref(current_url[0..current_url_len], href, &abs) orelse {
        setStatusStr("bad link", true);
        return;
    };
    go(url);
}

fn goBack() void {
    if (history.back()) |u| loadUrl(u);
}
fn goForward() void {
    if (history.forward()) |u| loadUrl(u);
}

fn submit() void {
    if (input_len == 0) return;
    // Copy first — loadUrl overwrites input_buf.
    var tmp: [webnav.MAX_URL]u8 = undefined;
    const n = @min(input_len, tmp.len);
    @memcpy(tmp[0..n], input_buf[0..n]);
    go(tmp[0..n]);
}

// ---------------------------------------------------------------------
// Hit-testing.

fn hitTestLink(mx: i32, my: i32) i32 {
    const by0: i32 = @intCast(bodyOriginY());
    const bh: i32 = @intCast(bodyHeight());
    if (my < by0 or my >= by0 + bh) return -1;
    const cx0: i32 = @intCast(contentX());
    const cw: i32 = @intCast(contentWidth());
    if (mx < cx0 or mx >= cx0 + cw) return -1;
    const content_x = mx - cx0;
    const content_y = @as(i32, @intCast(scroll_y)) + (my - by0);
    return render.linkAt(&doc, content_x, content_y);
}

// Returns 1 if back button hit, 2 if forward, 0 otherwise.
fn hitTestNavButton(mx: i32, my: i32) u8 {
    if (my < 0 or my >= @as(i32, @intCast(URLBAR_H))) return 0;
    const bx: i32 = 6;
    if (mx >= bx and mx < bx + @as(i32, @intCast(BTN_W))) return 1;
    if (mx >= bx + @as(i32, @intCast(BTN_W)) and mx < bx + @as(i32, @intCast(BTN_W * 2))) return 2;
    return 0;
}

// ---------------------------------------------------------------------
// Rendering.

fn fillTriangle(canvas: *gfx.Canvas, cx: i32, cy: i32, s: i32, left: bool, color: u32) void {
    // A solid triangle, apex left (◄) or right (►), 2s+1 px tall.
    var dy: i32 = -s;
    while (dy <= s) : (dy += 1) {
        const ad: i32 = if (dy < 0) -dy else dy;
        const x0: i32 = if (left) cx - s + 2 * ad else cx - s;
        const x1: i32 = if (left) cx + s else cx + s - 2 * ad;
        var x = x0;
        while (x <= x1) : (x += 1) canvas.blendPixel(x, cy + dy, color, 0xFF);
    }
}

fn drawNavButton(canvas: *gfx.Canvas, slot: u32, left: bool, enabled: bool) void {
    const x: u32 = 6 + slot * BTN_W;
    const h: u32 = URLBAR_H - 8;
    const cx: i32 = @intCast(x + BTN_W / 2);
    const cy: i32 = @intCast(4 + h / 2);
    const color: u32 = if (enabled) theme.text else 0x4A4E56;
    fillTriangle(canvas, cx, cy, 4, left, color);
}

fn drawUrlBar(canvas: *gfx.Canvas) void {
    const atlas = &fa.default_16;
    const lh = atlas.line_height;
    canvas.fillRect(0, 0, vis_w, URLBAR_H, URLBAR_BG);
    canvas.fillRect(0, URLBAR_H -| 1, vis_w, 1, URLBAR_BORDER);

    drawNavButton(canvas, 0, true, history.canBack());
    drawNavButton(canvas, 1, false, history.canForward());

    const bar_text_y: i32 = @intCast((URLBAR_H -| lh) / 2);
    const bar_clip = fa.Clip.fromRect(URL_X, 0, vis_w -| URL_X -| PAD, URLBAR_H);
    fa.drawTextClipped(canvas, @intCast(URL_X), bar_text_y, input_buf[0..input_len], 0xFFFFFF, atlas, bar_clip);
    const caret_x: i32 = @intCast(URL_X + atlas.measure(input_buf[0..input_len]) + 1);
    if (caret_x < @as(i32, @intCast(vis_w -| PAD))) {
        canvas.fillRect(@intCast(caret_x), @intCast((URLBAR_H -| lh) / 2), 2, lh, ACCENT);
    }
}

fn drawAll(canvas: *gfx.Canvas) void {
    const atlas = &fa.default_16;
    const lh = atlas.line_height;

    canvas.fillRect(0, 0, vis_w, vis_h, BG);
    drawUrlBar(canvas);

    // Body (centered, width-capped readable column).
    const body_y0 = bodyOriginY();
    const body_h = bodyHeight();
    render.paint(&doc, canvas, @intCast(contentX()), @intCast(body_y0), contentWidth(), body_h, scroll_y, theme, hovered_link);

    // Scrollbar (pixel units).
    scrollbar.x = vis_w -| SB_W;
    scrollbar.y = URLBAR_H;
    scrollbar.w = SB_W;
    scrollbar.h = vis_h -| URLBAR_H -| STATUS_H;
    scrollbar.draw(canvas, doc.doc_height, body_h, scroll_y);

    // Status bar. While hovering a link, show its resolved destination URL
    // (like a real browser); otherwise the page status (title / HTTP / errors).
    const sy = vis_h -| STATUS_H;
    canvas.fillRect(0, sy, vis_w, STATUS_H, URLBAR_BG);
    canvas.fillRect(0, sy, vis_w, 1, URLBAR_BORDER);
    const st_y: i32 = @intCast(sy + (STATUS_H -| lh) / 2);

    var hov_buf: [webnav.MAX_URL]u8 = undefined;
    var st_text: []const u8 = status_buf[0..status_len];
    var st_color: u32 = if (status_is_err) ERRCOL else MUTED;
    if (hovered_link >= 0) {
        const href = doc.linkHref(hovered_link);
        if (href.len > 0) {
            if (webnav.resolveHref(current_url[0..current_url_len], href, &hov_buf)) |u| {
                st_text = u;
                st_color = ACCENT;
            }
        }
    }
    fa.drawTextClipped(canvas, @intCast(PAD), st_y, st_text, st_color, atlas, fa.Clip.fromRect(PAD, sy, vis_w -| PAD * 2, STATUS_H));
}

// ---------------------------------------------------------------------

fn scrollByPx(delta: i32) void {
    if (delta < 0) {
        const d: u32 = @intCast(-delta);
        scroll_y = if (scroll_y > d) scroll_y - d else 0;
    } else {
        scroll_y += @intCast(delta);
    }
    clampScroll();
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    fa.ensureLoaded();
    const scr = libc.getScreenSize();
    alloc_w = @min(INIT_W * 2, scr.w);
    alloc_h = @min(INIT_H * 2, scr.h);

    const win = libc.createWindowEx(alloc_w, alloc_h, INIT_W, INIT_H) orelse {
        libc.exit();
    };
    alloc_w = win.alloc_w;
    alloc_h = win.alloc_h;
    g_canvas = gfx.Canvas.init(win.fb, alloc_w, alloc_h);
    _ = libc.getWindowAlloc();

    scrollbar.lines_per_notch = 3 * lineStep(); // pixel-mode wheel step

    go("example.com");
    drawAll(&g_canvas);
    libc.present();

    var needs_redraw = false;
    while (true) {
        while (libc.pollEvent()) |ev| {
            switch (ev.kindOf()) {
                .close_request => {
                    libc.destroyWindow();
                    libc.exit();
                },
                .key_char => {
                    const ch: u8 = @truncate(ev.a);
                    if (ch == '\n' or ch == '\r') {
                        setStatusStr("Loading...", false);
                        drawAll(&g_canvas);
                        libc.present();
                        submit();
                        needs_redraw = true;
                    } else if (ch == 0x08) {
                        if (input_len > 0) input_len -= 1;
                        needs_redraw = true;
                    } else if (ch == 0x1B) {
                        if (input_len > 0) {
                            input_len = 0;
                            needs_redraw = true;
                        } else {
                            libc.destroyWindow();
                            libc.exit();
                        }
                    } else if (ch >= 0x20 and ch <= 0x7E) {
                        if (input_len < input_buf.len) {
                            input_buf[input_len] = ch;
                            input_len += 1;
                            needs_redraw = true;
                        }
                    }
                },
                .key_special => {
                    const code: u8 = @truncate(ev.a);
                    const alt = (ev.b & libc.MOD_ALT) != 0;
                    const page: i32 = @intCast(@max(lineStep(), bodyHeight() -| lineStep()));
                    switch (code) {
                        0x80 => scrollByPx(-@as(i32, @intCast(lineStep()))), // up
                        0x81 => scrollByPx(@intCast(lineStep())), // down
                        0x82 => if (alt) goBack() else scrollByPx(-@as(i32, @intCast(lineStep()))), // left / Alt+left=back
                        0x83 => if (alt) goForward() else scrollByPx(@intCast(lineStep())), // right / Alt+right=fwd
                        0x86 => scrollByPx(-page), // pgup
                        0x87 => scrollByPx(page), // pgdn
                        0x84 => scroll_y = 0, // home
                        0x85 => {
                            scroll_y = maxScroll();
                        }, // end
                        else => {},
                    }
                    needs_redraw = true;
                },
                .mouse_move => {
                    if (scrollbar.handleEvent(ev, doc.doc_height, bodyHeight(), &scroll_y)) needs_redraw = true;
                    const mx: i32 = @bitCast(ev.a);
                    const my: i32 = @bitCast(ev.b);
                    const h = hitTestLink(mx, my);
                    if (h != hovered_link) {
                        hovered_link = h;
                        needs_redraw = true;
                    }
                },
                .mouse_button => {
                    if (scrollbar.handleEvent(ev, doc.doc_height, bodyHeight(), &scroll_y)) needs_redraw = true;
                    if (ev.buttonIndex() == 0 and ev.buttonPressed()) {
                        const mx: i32 = @bitCast(ev.b);
                        const my: i32 = @bitCast(ev.c);
                        const nav = hitTestNavButton(mx, my);
                        if (nav == 1) {
                            goBack();
                            needs_redraw = true;
                        } else if (nav == 2) {
                            goForward();
                            needs_redraw = true;
                        } else if (mx < @as(i32, @intCast(vis_w -| SB_W))) {
                            const id = hitTestLink(mx, my);
                            if (id >= 0) {
                                followLink(id);
                                needs_redraw = true;
                            }
                        }
                    }
                },
                .mouse_wheel => {
                    if (scrollbar.handleEvent(ev, doc.doc_height, bodyHeight(), &scroll_y)) needs_redraw = true;
                },
                .resize => {
                    const wa = libc.getWindowAlloc();
                    if (wa.w != 0 and (wa.w != alloc_w or wa.h != alloc_h)) {
                        alloc_w = wa.w;
                        alloc_h = wa.h;
                        g_canvas = gfx.Canvas.init(win.fb, alloc_w, alloc_h);
                    }
                    const new_w = @min(ev.a, alloc_w);
                    const new_h = @min(ev.b, alloc_h);
                    if (new_w != vis_w or new_h != vis_h) {
                        vis_w = new_w;
                        vis_h = new_h;
                        relayout();
                        needs_redraw = true;
                    }
                },
                else => {},
            }
        }

        if (needs_redraw) {
            needs_redraw = false;
            clampScroll();
            drawAll(&g_canvas);
            libc.present();
        }
        libc.sleep(20);
    }
}
