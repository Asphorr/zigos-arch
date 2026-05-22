// web — a "baby browser" / reader. Fetches an HTTPS URL via the kernel's
// TLS-backed HTTP client (lib/http.zig: get() does DNS + TLS + redirects +
// de-chunking), strips the HTML to readable text + a numbered list of links,
// word-wraps it into a scrollable window, and lets you load a URL or follow a
// link by typing its number.
//
// Controls:
//   - type a URL + Enter        → load it (https:// assumed if no scheme)
//   - type a link number + Enter → follow that link
//   - Up/Down, PgUp/PgDn, Home/End, mouse wheel → scroll
//   - Backspace edits the address; Esc clears it (or quits if empty)
//
// This renders the *readable* web (static, text-heavy pages like example.com,
// docs, blogs). JS-driven apps won't render — there's no script engine.

const libc = @import("libc");
const gfx = @import("graphics");
const ui = @import("ui");
const fa = @import("font_atlas");
const http = @import("http");

const INIT_W: u32 = 760;
const INIT_H: u32 = 560;

// Layout.
const URLBAR_H: u32 = 30;
const STATUS_H: u32 = 22;
const PAD: u32 = 12;
const SB_W: u32 = 12; // scrollbar width

// Palette.
const BG: u32 = 0x16171A;
const URLBAR_BG: u32 = 0x2A2D33;
const URLBAR_BORDER: u32 = 0x3C404A;
const TEXT: u32 = 0xD6DAE0;
const LINK: u32 = 0x6FB0FF;
const MUTED: u32 = 0x808898;
const ACCENT: u32 = 0x4DA6E0;
const ERRCOL: u32 = 0xFF8080;

// --- Buffers (all in .bss) ---
var resp_buf: [256 * 1024]u8 = undefined; // raw HTTP response target for http.get
var text_buf: [128 * 1024]u8 = undefined; // stripped, whitespace-collapsed text
var text_len: usize = 0;
var href_pool: [48 * 1024]u8 = undefined; // packed link hrefs
var href_pool_len: usize = 0;

const Link = struct { href_off: u32, href_len: u32, text_start: u32, text_end: u32 };
var links: [512]Link = undefined;
var link_count: usize = 0;

const Line = struct { start: u32, len: u32 };
var lines_arr: [12000]Line = undefined;
var line_count: usize = 0;

var current_url: [1024]u8 = undefined;
var current_url_len: usize = 0;

var input_buf: [1024]u8 = undefined;
var input_len: usize = 0;

var status_buf: [160]u8 = undefined;
var status_len: usize = 0;
var status_is_err: bool = false;

var scroll_top: u32 = 0; // index of the first visible display line

// Geometry (updated on resize).
var vis_w: u32 = INIT_W;
var vis_h: u32 = INIT_H;
var alloc_w: u32 = 0;
var alloc_h: u32 = 0;

// Whitespace-collapse state for the HTML parser.
var sp_pending: bool = false;
var nl_run: u32 = 0;

var scrollbar: ui.Scrollbar = .{ .x = 0, .y = 0, .w = 0, .h = 0 };

// ---------------------------------------------------------------------
// Small string helpers.

fn isAlpha(c: u8) bool {
    return (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z');
}
fn isAlnum(c: u8) bool {
    return isAlpha(c) or (c >= '0' and c <= '9');
}
fn lower(c: u8) u8 {
    return if (c >= 'A' and c <= 'Z') c + 32 else c;
}
fn eqlLowerAscii(a: []const u8, b_lower: []const u8) bool {
    if (a.len != b_lower.len) return false;
    for (a, b_lower) |ca, cb| {
        if (lower(ca) != cb) return false;
    }
    return true;
}

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

// ---------------------------------------------------------------------
// Text emission with HTML whitespace collapsing.

fn putc(c: u8) void {
    if (text_len >= text_buf.len) return;
    text_buf[text_len] = c;
    text_len += 1;
}

fn emitText(c: u8) void {
    // Printable ASCII non-space char. Flush a pending space if we're mid-line.
    if (nl_run == 0 and sp_pending and text_len > 0) putc(' ');
    sp_pending = false;
    nl_run = 0;
    putc(c);
}

fn emitSpace() void {
    sp_pending = true;
}

fn emitNewline() void {
    if (text_len == 0) return; // drop leading blank lines
    if (nl_run >= 2) return; // cap consecutive blanks (one blank line max)
    putc('\n');
    nl_run += 1;
    sp_pending = false;
}

// ---------------------------------------------------------------------
// HTML entity decode. Emits the decoded char(s) via emitText/emitSpace.
// Returns how many input bytes were consumed (>=1). html[i] == '&'.

fn handleEntity(html: []const u8, i: usize) usize {
    // Find the terminating ';' within a short window.
    var j = i + 1;
    const limit = @min(html.len, i + 12);
    while (j < limit and html[j] != ';') : (j += 1) {}
    if (j >= limit or html[j] != ';') {
        emitText('&');
        return 1;
    }
    const name = html[i + 1 .. j];
    const consumed = (j - i) + 1;

    if (name.len >= 2 and name[0] == '#') {
        // Numeric entity.
        var v: u32 = 0;
        if (name[1] == 'x' or name[1] == 'X') {
            for (name[2..]) |c| {
                const d: u32 = switch (c) {
                    '0'...'9' => c - '0',
                    'a'...'f' => c - 'a' + 10,
                    'A'...'F' => c - 'A' + 10,
                    else => return consumed,
                };
                v = v * 16 + d;
            }
        } else {
            for (name[1..]) |c| {
                if (c < '0' or c > '9') return consumed;
                v = v * 10 + (c - '0');
            }
        }
        if (v == 0xA0) {
            emitSpace();
        } else if (v >= 0x20 and v <= 0x7E) {
            emitText(@intCast(v));
        } // else: unrepresentable — drop
        return consumed;
    }

    // Named entities (the common handful).
    if (eqlLowerAscii(name, "amp")) {
        emitText('&');
    } else if (eqlLowerAscii(name, "lt")) {
        emitText('<');
    } else if (eqlLowerAscii(name, "gt")) {
        emitText('>');
    } else if (eqlLowerAscii(name, "quot")) {
        emitText('"');
    } else if (eqlLowerAscii(name, "apos") or eqlLowerAscii(name, "#39")) {
        emitText('\'');
    } else if (eqlLowerAscii(name, "nbsp")) {
        emitSpace();
    } else if (eqlLowerAscii(name, "mdash") or eqlLowerAscii(name, "ndash")) {
        emitText('-');
    } else if (eqlLowerAscii(name, "hellip")) {
        emitText('.');
        emitText('.');
        emitText('.');
    } else if (eqlLowerAscii(name, "copy")) {
        emitText('(');
        emitText('c');
        emitText(')');
    } else {
        // Unknown — render literally so nothing silently vanishes.
        emitText('&');
        for (name) |c| emitText(c);
        emitText(';');
    }
    return consumed;
}

// ---------------------------------------------------------------------
// Block-level tags force a line break in the rendered text.

fn isBlockTag(name: []const u8) bool {
    const block = [_][]const u8{
        "p", "br", "div", "li", "ul", "ol", "tr", "table", "hr",
        "h1", "h2", "h3", "h4", "h5", "h6", "blockquote", "section",
        "article", "header", "footer", "nav", "pre", "form", "figure",
        "figcaption", "main", "aside", "title", "dt", "dd",
    };
    for (block) |b| {
        if (eqlLowerAscii(name, b)) return true;
    }
    return false;
}

fn findHref(tag_inner: []const u8) ?[]const u8 {
    // Scan for `href` attribute (case-insensitive), then `=`, then value
    // (quoted or bare).
    var i: usize = 0;
    while (i + 4 <= tag_inner.len) : (i += 1) {
        if (lower(tag_inner[i]) == 'h' and eqlLowerAscii(tag_inner[i .. i + 4], "href")) {
            var j = i + 4;
            while (j < tag_inner.len and (tag_inner[j] == ' ' or tag_inner[j] == '\t')) : (j += 1) {}
            if (j >= tag_inner.len or tag_inner[j] != '=') {
                i = j;
                continue;
            }
            j += 1;
            while (j < tag_inner.len and (tag_inner[j] == ' ' or tag_inner[j] == '\t')) : (j += 1) {}
            if (j >= tag_inner.len) return null;
            if (tag_inner[j] == '"' or tag_inner[j] == '\'') {
                const q = tag_inner[j];
                j += 1;
                const start = j;
                while (j < tag_inner.len and tag_inner[j] != q) : (j += 1) {}
                return tag_inner[start..j];
            }
            const start = j;
            while (j < tag_inner.len and tag_inner[j] != ' ' and tag_inner[j] != '\t' and tag_inner[j] != '>') : (j += 1) {}
            return tag_inner[start..j];
        }
    }
    return null;
}

// ---------------------------------------------------------------------
// HTML -> text + numbered links. Single pass.

fn parseHtml(html: []const u8) void {
    text_len = 0;
    link_count = 0;
    href_pool_len = 0;
    sp_pending = false;
    nl_run = 0;
    var cur_link: ?usize = null;

    var i: usize = 0;
    while (i < html.len) {
        const c = html[i];
        if (c == '<') {
            // Comment?
            if (i + 4 <= html.len and html[i + 1] == '!' and html[i + 2] == '-' and html[i + 3] == '-') {
                var k = i + 4;
                while (k + 3 <= html.len and !(html[k] == '-' and html[k + 1] == '-' and html[k + 2] == '>')) : (k += 1) {}
                i = if (k + 3 <= html.len) k + 3 else html.len;
                continue;
            }
            // Parse tag name.
            var j = i + 1;
            var closing = false;
            if (j < html.len and html[j] == '/') {
                closing = true;
                j += 1;
            }
            const name_start = j;
            while (j < html.len and isAlnum(html[j])) : (j += 1) {}
            const name = html[name_start..j];
            // Find tag end '>'.
            var tag_end = j;
            while (tag_end < html.len and html[tag_end] != '>') : (tag_end += 1) {}
            const tag_inner = html[name_start..tag_end];

            if (!closing and (eqlLowerAscii(name, "script") or eqlLowerAscii(name, "style"))) {
                // Skip everything up to the matching close tag.
                const close: []const u8 = if (eqlLowerAscii(name, "script")) "</script" else "</style";
                var k = tag_end;
                while (k < html.len) : (k += 1) {
                    if (html[k] == '<' and k + close.len <= html.len and eqlLowerAscii(html[k .. k + close.len], close)) {
                        // advance past this close tag's '>'
                        var m = k + close.len;
                        while (m < html.len and html[m] != '>') : (m += 1) {}
                        k = m;
                        break;
                    }
                }
                i = if (k < html.len) k + 1 else html.len;
                continue;
            }

            if (eqlLowerAscii(name, "a")) {
                if (!closing) {
                    if (findHref(tag_inner)) |href| {
                        if (link_count < links.len and href.len > 0 and href[0] != '#') {
                            const off = href_pool_len;
                            const hn = @min(href.len, href_pool.len - href_pool_len);
                            if (hn > 0) {
                                @memcpy(href_pool[off..][0..hn], href[0..hn]);
                                href_pool_len += hn;
                                links[link_count] = .{
                                    .href_off = @intCast(off),
                                    .href_len = @intCast(hn),
                                    .text_start = @intCast(text_len),
                                    .text_end = 0,
                                };
                                cur_link = link_count;
                                link_count += 1;
                            }
                        }
                    }
                } else if (cur_link) |idx| {
                    // Append " [N]" marker, then close the link span.
                    emitText(' ');
                    putc('[');
                    const np = appendNum(text_buf[0..], text_len, @intCast(idx + 1));
                    text_len = np;
                    putc(']');
                    links[idx].text_end = @intCast(text_len);
                    cur_link = null;
                }
            }

            if (isBlockTag(name)) emitNewline();

            i = if (tag_end < html.len) tag_end + 1 else html.len;
            continue;
        } else if (c == '&') {
            i += handleEntity(html, i);
            continue;
        } else if (c == ' ' or c == '\t' or c == '\r' or c == '\n') {
            emitSpace();
            i += 1;
            continue;
        } else if (c >= 0x20 and c <= 0x7E) {
            emitText(c);
            i += 1;
            continue;
        } else {
            // Non-ASCII / control byte — skip (keeps text_buf pure ASCII so
            // measure() matches drawText advance exactly when wrapping).
            i += 1;
            continue;
        }
    }

    // Close an unterminated link.
    if (cur_link) |idx| {
        links[idx].text_end = @intCast(text_len);
    }
}

// ---------------------------------------------------------------------
// Word-wrap text_buf into display lines for the given content width.

fn charW(atlas: *const fa.FontAtlas, c: u8) u32 {
    const one = [_]u8{c};
    return atlas.measure(&one);
}

fn pushLine(start: usize, len: usize) void {
    if (line_count >= lines_arr.len) return;
    lines_arr[line_count] = .{ .start = @intCast(start), .len = @intCast(len) };
    line_count += 1;
}

fn wrap(content_w: u32) void {
    line_count = 0;
    const atlas = &fa.default_16;
    var i: usize = 0;
    while (i < text_len) {
        if (text_buf[i] == '\n') {
            pushLine(i, 0); // blank line (paragraph gap)
            i += 1;
            if (line_count >= lines_arr.len) return;
            continue;
        }
        const start = i;
        var width: u32 = 0;
        var last_space: usize = 0;
        var have_space = false;
        while (i < text_len and text_buf[i] != '\n') {
            const cw = charW(atlas, text_buf[i]);
            if (width + cw > content_w and i > start) break;
            if (text_buf[i] == ' ') {
                last_space = i;
                have_space = true;
            }
            width += cw;
            i += 1;
        }
        if (i < text_len and text_buf[i] != '\n') {
            // Width break: prefer the last space; else hard-break the word.
            if (have_space and last_space > start) {
                pushLine(start, last_space - start);
                i = last_space + 1;
            } else {
                pushLine(start, i - start);
            }
        } else {
            pushLine(start, i - start);
            if (i < text_len and text_buf[i] == '\n') i += 1;
        }
        if (line_count >= lines_arr.len) return;
    }
}

// ---------------------------------------------------------------------
// Link membership for colored rendering.

fn linkAt(pos: usize) ?usize {
    var k: usize = 0;
    while (k < link_count) : (k += 1) {
        if (pos >= links[k].text_start and pos < links[k].text_end) return k;
    }
    return null;
}

fn nextLinkStartAfter(pos: usize, limit: usize) usize {
    var best = limit;
    var k: usize = 0;
    while (k < link_count) : (k += 1) {
        const s = links[k].text_start;
        if (s > pos and s < best) best = s;
    }
    return best;
}

// ---------------------------------------------------------------------
// Rendering.

fn bodyVisibleLines() u32 {
    const atlas = &fa.default_16;
    const lh: u32 = atlas.line_height;
    const body_h = vis_h -| URLBAR_H -| STATUS_H;
    if (lh == 0) return 1;
    return body_h / lh;
}

fn clampScroll() void {
    const vis = bodyVisibleLines();
    const total: u32 = @intCast(line_count);
    const max_top = if (total > vis) total - vis else 0;
    if (scroll_top > max_top) scroll_top = max_top;
}

fn drawOneLine(canvas: *gfx.Canvas, line: Line, x: i32, y: i32, clip: fa.Clip) void {
    const atlas = &fa.default_16;
    var pos: usize = line.start;
    const end: usize = line.start + line.len;
    var pen_x: i32 = x;
    while (pos < end) {
        var run_end: usize = end;
        var color: u32 = TEXT;
        if (linkAt(pos)) |idx| {
            color = LINK;
            run_end = @min(end, links[idx].text_end);
        } else {
            run_end = @min(end, nextLinkStartAfter(pos, end));
        }
        if (run_end <= pos) run_end = end; // safety
        const seg = text_buf[pos..run_end];
        fa.drawTextClipped(canvas, pen_x, y, seg, color, atlas, clip);
        pen_x += @intCast(atlas.measure(seg));
        pos = run_end;
    }
}

fn drawAll(canvas: *gfx.Canvas) void {
    const atlas = &fa.default_16;
    const lh: u32 = atlas.line_height;

    // Background.
    canvas.fillRect(0, 0, vis_w, vis_h, BG);

    // --- URL bar ---
    canvas.fillRect(0, 0, vis_w, URLBAR_H, URLBAR_BG);
    canvas.fillRect(0, URLBAR_H -| 1, vis_w, 1, URLBAR_BORDER);
    const bar_text_y: i32 = @intCast((URLBAR_H -| lh) / 2);
    const bar_clip = fa.Clip.fromRect(PAD, 0, vis_w -| PAD * 2, URLBAR_H);
    fa.drawTextClipped(canvas, @intCast(PAD), bar_text_y, input_buf[0..input_len], 0xFFFFFF, atlas, bar_clip);
    // Caret.
    const caret_x: i32 = @intCast(PAD + atlas.measure(input_buf[0..input_len]) + 1);
    if (caret_x < @as(i32, @intCast(vis_w -| PAD))) {
        canvas.fillRect(@intCast(caret_x), @intCast((URLBAR_H -| lh) / 2), 2, lh, ACCENT);
    }

    // --- Body (scrollable text) ---
    const body_y0: u32 = URLBAR_H + 4;
    const body_h = vis_h -| URLBAR_H -| STATUS_H;
    const content_x: u32 = PAD;
    const body_clip = fa.Clip.fromRect(0, URLBAR_H, vis_w, body_h);

    const vis_lines = bodyVisibleLines();
    var row: u32 = 0;
    while (row < vis_lines) : (row += 1) {
        const li = scroll_top + row;
        if (li >= line_count) break;
        const yy: i32 = @intCast(body_y0 + row * lh);
        drawOneLine(canvas, lines_arr[li], @intCast(content_x), yy, body_clip);
    }

    // --- Scrollbar ---
    scrollbar.x = vis_w -| SB_W;
    scrollbar.y = URLBAR_H;
    scrollbar.w = SB_W;
    scrollbar.h = body_h;
    scrollbar.draw(canvas, @intCast(line_count), vis_lines, scroll_top);

    // --- Status bar ---
    const sy: u32 = vis_h -| STATUS_H;
    canvas.fillRect(0, sy, vis_w, STATUS_H, URLBAR_BG);
    canvas.fillRect(0, sy, vis_w, 1, URLBAR_BORDER);
    const st_y: i32 = @intCast(sy + (STATUS_H -| lh) / 2);
    const st_color: u32 = if (status_is_err) ERRCOL else MUTED;
    fa.drawTextClipped(canvas, @intCast(PAD), st_y, status_buf[0..status_len], st_color, atlas, fa.Clip.fromRect(PAD, sy, vis_w -| PAD * 2, STATUS_H));
}

// ---------------------------------------------------------------------
// Fetch + navigation.

fn relayout() void {
    const content_w = vis_w -| (PAD * 2) -| SB_W;
    wrap(content_w);
    scroll_top = 0;
}

fn loadUrl(url: []const u8) void {
    // Remember the URL (for relative-link resolution and the address bar).
    const un = @min(url.len, current_url.len);
    @memcpy(current_url[0..un], url[0..un]);
    current_url_len = un;
    // Mirror into the address bar.
    @memcpy(input_buf[0..un], url[0..un]);
    input_len = un;

    setStatusStr("Loading...", false);
    // Note: http.get blocks for a few seconds (DNS + TLS + fetch); the window
    // can't process events meanwhile. We've drawn "Loading..." before calling.

    const resp = http.get(current_url[0..current_url_len], resp_buf[0..]) catch |err| {
        link_count = 0;
        line_count = 0;
        text_len = 0;
        var b: [160]u8 = undefined;
        const pfx = "fetch failed: ";
        @memcpy(b[0..pfx.len], pfx);
        const en = @errorName(err);
        const n = @min(en.len, b.len - pfx.len);
        @memcpy(b[pfx.len..][0..n], en[0..n]);
        setStatusStr(b[0 .. pfx.len + n], true);
        return;
    };

    parseHtml(resp.body);
    relayout();

    var b: [160]u8 = undefined;
    var p: usize = 0;
    const pfx = "HTTP ";
    @memcpy(b[0..pfx.len], pfx);
    p = pfx.len;
    p = appendNum(b[0..], p, resp.status);
    const mid = "   ";
    @memcpy(b[p..][0..mid.len], mid);
    p += mid.len;
    p = appendNum(b[0..], p, @intCast(link_count));
    const suf = " links";
    @memcpy(b[p..][0..suf.len], suf);
    p += suf.len;
    setStatusStr(b[0..p], resp.status >= 400);
}

fn buildAbsolute(href: []const u8, out: []u8) ?[]const u8 {
    // Already absolute?
    if (href.len >= 7 and (eqlLowerAscii(href[0..7], "http://") or
        (href.len >= 8 and eqlLowerAscii(href[0..8], "https://"))))
    {
        const n = @min(href.len, out.len);
        @memcpy(out[0..n], href[0..n]);
        return out[0..n];
    }

    const base = http.parseUrl(current_url[0..current_url_len]) catch return null;
    const scheme_str: []const u8 = if (base.scheme == .https) "https://" else "http://";

    var p: usize = 0;
    const writeStr = struct {
        fn f(buf: []u8, pos: usize, s: []const u8) usize {
            const n = @min(s.len, buf.len - pos);
            @memcpy(buf[pos..][0..n], s[0..n]);
            return pos + n;
        }
    }.f;

    if (href.len >= 2 and href[0] == '/' and href[1] == '/') {
        // protocol-relative: //host/path
        p = writeStr(out, p, if (base.scheme == .https) "https:" else "http:");
        p = writeStr(out, p, href);
        return out[0..p];
    }

    p = writeStr(out, p, scheme_str);
    p = writeStr(out, p, base.host);
    if (href.len > 0 and href[0] == '/') {
        p = writeStr(out, p, href);
    } else {
        // Relative to the current path's directory.
        var dir_end: usize = 0;
        var k: usize = 0;
        while (k < base.path.len) : (k += 1) {
            if (base.path[k] == '/') dir_end = k + 1;
        }
        p = writeStr(out, p, base.path[0..dir_end]);
        if (dir_end == 0) p = writeStr(out, p, "/");
        p = writeStr(out, p, href);
    }
    return out[0..p];
}

fn followLink(idx: usize) void {
    if (idx >= link_count) return;
    const l = links[idx];
    const href = href_pool[l.href_off..][0..l.href_len];
    var abs: [1024]u8 = undefined;
    const url = buildAbsolute(href, &abs) orelse {
        setStatusStr("bad link", true);
        return;
    };
    loadUrl(url);
}

fn submit() void {
    // Trim.
    var s: usize = 0;
    var e: usize = input_len;
    while (s < e and input_buf[s] == ' ') s += 1;
    while (e > s and input_buf[e - 1] == ' ') e -= 1;
    const inp = input_buf[s..e];
    if (inp.len == 0) return;

    // All digits -> follow link number.
    var all_digits = true;
    var num: u32 = 0;
    for (inp) |c| {
        if (c < '0' or c > '9') {
            all_digits = false;
            break;
        }
        num = num * 10 + (c - '0');
    }
    if (all_digits and num >= 1 and num <= link_count) {
        followLink(num - 1);
        return;
    }

    // Otherwise load as a URL. Copy to a stable buffer first (loadUrl
    // overwrites input_buf).
    var tmp: [1024]u8 = undefined;
    const n = @min(inp.len, tmp.len);
    @memcpy(tmp[0..n], inp[0..n]);
    loadUrl(tmp[0..n]);
}

// ---------------------------------------------------------------------

fn scrollBy(delta: i32) void {
    if (delta < 0) {
        const d: u32 = @intCast(-delta);
        scroll_top = if (scroll_top > d) scroll_top - d else 0;
    } else {
        scroll_top += @intCast(delta);
    }
    clampScroll();
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    fa.ensureLoaded(); // parse the embedded font atlases before any fa.* use
    const scr = libc.getScreenSize();
    alloc_w = @min(INIT_W * 2, scr.w);
    alloc_h = @min(INIT_H * 2, scr.h);

    const win = libc.createWindowEx(alloc_w, alloc_h, INIT_W, INIT_H) orelse {
        libc.exit();
    };
    alloc_w = win.alloc_w;
    alloc_h = win.alloc_h;
    var canvas = gfx.Canvas.init(win.fb, alloc_w, alloc_h);
    _ = libc.getWindowAlloc(); // opt into F10 grow-on-maximize

    // Default page.
    loadUrl("example.com");
    drawAll(&canvas);
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
                        // Loading blocks; show feedback first.
                        setStatusStr("Loading...", false);
                        drawAll(&canvas);
                        libc.present();
                        submit();
                        needs_redraw = true;
                    } else if (ch == 0x08) { // backspace
                        if (input_len > 0) input_len -= 1;
                        needs_redraw = true;
                    } else if (ch == 0x1B) { // esc
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
                    const page: i32 = @intCast(@max(@as(u32, 1), bodyVisibleLines() -| 1));
                    switch (code) {
                        0x80 => scrollBy(-1), // up
                        0x81 => scrollBy(1), // down
                        0x86 => scrollBy(-page), // pgup
                        0x87 => scrollBy(page), // pgdn
                        0x84 => {
                            scroll_top = 0;
                        }, // home
                        0x85 => {
                            scroll_top = 0xFFFFFFFF;
                            clampScroll();
                        }, // end
                        else => {},
                    }
                    needs_redraw = true;
                },
                .mouse_move, .mouse_button, .mouse_wheel => {
                    if (scrollbar.handleEvent(ev, @intCast(line_count), bodyVisibleLines(), &scroll_top)) {
                        needs_redraw = true;
                    }
                },
                .resize => {
                    const wa = libc.getWindowAlloc();
                    if (wa.w != 0 and (wa.w != alloc_w or wa.h != alloc_h)) {
                        alloc_w = wa.w;
                        alloc_h = wa.h;
                        canvas = gfx.Canvas.init(win.fb, alloc_w, alloc_h);
                    }
                    const new_w = @min(ev.a, alloc_w);
                    const new_h = @min(ev.b, alloc_h);
                    if (new_w != vis_w or new_h != vis_h) {
                        vis_w = new_w;
                        vis_h = new_h;
                        relayout(); // re-wrap to the new width
                        needs_redraw = true;
                    }
                },
                else => {},
            }
        }

        if (needs_redraw) {
            needs_redraw = false;
            clampScroll();
            drawAll(&canvas);
            libc.present();
        }
        libc.sleep(20);
    }
}
