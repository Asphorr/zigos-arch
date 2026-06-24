// html — a forgiving HTML→Document adapter for the render engine.
//
// One streaming pass over a byte buffer. Block-level tags (p, h1–6, li, pre,
// blockquote, …) open render blocks with the right indent/margins/bullet/font;
// inline tags (b/strong, code, a) layer style modifiers onto the current run;
// entities are decoded; <script>/<style>/<head>/<title> contents are dropped.
// Whitespace is HTML-collapsed except inside <pre>.
//
// This is deliberately NOT a conformant parser — it's the same "render the
// readable web" scope as the old app/web.zig inline stripper, just retargeted
// to emit structured runs instead of flat text. Malformed pages degrade
// gracefully (unmatched tags can't crash it; worst case a stray style bleeds).

const render = @import("render");

// Indents / gaps (px).
const QINDENT: u16 = 22; // per blockquote nesting level
const LINDENT: u16 = 22; // per list nesting level
const BULLET_GAP: u16 = 12; // room the disc occupies left of li text
const PARA_GAP: u16 = 8;

// Parser state (single-threaded app; module-global like the old web.zig).
var doc: *render.Document = undefined;
var theme: render.Theme = .{};

var base_font: render.Font = .body;
var base_color: u32 = 0xD6DAE0;
var cur_block_open: bool = false;

var bold_depth: u32 = 0;
var code_depth: u32 = 0;
var cur_link: i32 = -1;
var quote_depth: u32 = 0;
var list_depth: u32 = 0;
var pre_depth: u32 = 0;

// Whitespace-collapse state (only consulted when pre_depth == 0).
var sp_pending: bool = false;
var nl_run: u32 = 0;

// ---------------------------------------------------------------------
// ASCII helpers.

fn isAlpha(c: u8) bool {
    return (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z');
}
fn isAlnum(c: u8) bool {
    return isAlpha(c) or (c >= '0' and c <= '9');
}
fn lower(c: u8) u8 {
    return if (c >= 'A' and c <= 'Z') c + 32 else c;
}
fn eqlLower(a: []const u8, b_lower: []const u8) bool {
    if (a.len != b_lower.len) return false;
    for (a, b_lower) |ca, cb| {
        if (lower(ca) != cb) return false;
    }
    return true;
}

fn currentIndent() u16 {
    return @as(u16, @intCast(quote_depth)) * QINDENT + @as(u16, @intCast(list_depth)) * LINDENT;
}
fn baseColorForDepth() u32 {
    return if (quote_depth > 0) theme.muted else theme.text;
}

// ---------------------------------------------------------------------
// Style application + block management.

fn computeStyle() render.Style {
    var s = render.Style{ .font = base_font, .color = currentInlineColor(), .underline = false, .link_id = -1 };
    if (cur_link >= 0) {
        s.color = theme.link;
        s.underline = true;
        s.link_id = cur_link;
    }
    if (code_depth > 0) {
        s.font = if (bold_depth > 0) .mono_bold else .mono;
    } else if (bold_depth > 0 and base_font == .body) {
        s.font = .bold;
    }
    return s;
}

fn applyStyle() void {
    doc.setStyle(computeStyle());
}

fn openBlock(font: render.Font, color: u32, indent: u16, sb: u16, sa: u16, bullet: render.Bullet) void {
    doc.beginBlock(indent, sb, sa, bullet);
    base_font = font;
    base_color = color;
    cur_block_open = true;
    sp_pending = false;
    nl_run = 0;
    resetColorStack(); // inline <span>/<font> colors don't cross block boundaries
    applyStyle();
}

fn closeBlock() void {
    if (cur_block_open) {
        doc.endBlock();
        cur_block_open = false;
    }
    sp_pending = false;
}

fn ensureBlock() void {
    if (!cur_block_open) {
        openBlock(.body, baseColorForDepth(), currentIndent(), 2, 2, .none);
    }
}

// ---------------------------------------------------------------------
// Text emission with whitespace collapsing.

fn emitText(c: u8) void {
    ensureBlock();
    if (pre_depth == 0) {
        if (sp_pending) {
            doc.putByte(' ');
            sp_pending = false;
        }
        nl_run = 0;
    }
    doc.putByte(c);
}

fn emitSpace() void {
    if (pre_depth > 0) {
        ensureBlock();
        doc.putByte(' ');
    } else {
        sp_pending = true;
    }
}

fn emitBreak() void {
    // Forced line break inside the current block (<br>, or a newline in <pre>).
    ensureBlock();
    if (pre_depth == 0) {
        if (nl_run >= 2) return; // cap blank runs
        nl_run += 1;
        sp_pending = false;
    }
    doc.putByte('\n');
}

// ---------------------------------------------------------------------
// Entity decode. html[i] == '&'. Returns bytes consumed (>=1).

fn handleEntity(html: []const u8, i: usize) usize {
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
                if (v > 0x10FFFF) return consumed; // cap: avoid u32 overflow panic
            }
        } else {
            for (name[1..]) |c| {
                if (c < '0' or c > '9') return consumed;
                v = v * 10 + (c - '0');
                if (v > 0x10FFFF) return consumed;
            }
        }
        if (v == 0xA0) {
            emitSpace();
        } else if (v >= 0x20 and v <= 0x7E) {
            emitText(@intCast(v));
        }
        return consumed;
    }

    if (eqlLower(name, "amp")) {
        emitText('&');
    } else if (eqlLower(name, "lt")) {
        emitText('<');
    } else if (eqlLower(name, "gt")) {
        emitText('>');
    } else if (eqlLower(name, "quot")) {
        emitText('"');
    } else if (eqlLower(name, "apos") or eqlLower(name, "#39")) {
        emitText('\'');
    } else if (eqlLower(name, "nbsp")) {
        emitSpace();
    } else if (eqlLower(name, "mdash") or eqlLower(name, "ndash")) {
        emitText('-');
    } else if (eqlLower(name, "hellip")) {
        emitText('.');
        emitText('.');
        emitText('.');
    } else if (eqlLower(name, "copy")) {
        emitText('(');
        emitText('c');
        emitText(')');
    } else {
        emitText('&');
        for (name) |c| emitText(c);
        emitText(';');
    }
    return consumed;
}

// ---------------------------------------------------------------------
// href extraction (case-insensitive, quoted or bare).

// Find attribute `attr` (lowercase) in a tag's inner text, returning its
// value (quoted or bare), or null. Requires a word boundary before the name
// so "src" doesn't match inside "datasrc".
fn findAttr(tag_inner: []const u8, attr: []const u8) ?[]const u8 {
    const alen = attr.len;
    if (alen == 0) return null;
    var i: usize = 0;
    while (i + alen <= tag_inner.len) : (i += 1) {
        if (!eqlLower(tag_inner[i .. i + alen], attr)) continue;
        if (i > 0 and isAlnum(tag_inner[i - 1])) continue; // word boundary
        var j = i + alen;
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
    return null;
}

fn findHref(tag_inner: []const u8) ?[]const u8 {
    return findAttr(tag_inner, "href");
}

fn parseUint(s: []const u8) u32 {
    var v: u32 = 0;
    for (s) |c| {
        if (c < '0' or c > '9') break;
        v = v *% 10 +% (c - '0');
        if (v > 20000) return 20000; // clamp absurd width/height
    }
    return v;
}

// ---------------------------------------------------------------------
// Author colors. style="color:…" and <font color> become a render Style.color;
// the render engine already threads per-run color through layout + paint
// (render.zig:473/720), so this is purely a parser feature. Colors are kept
// legible on the dark reader theme by readableOnDark().

const MIN_LUM: u32 = 90; // floor for author colors on the ~0x16 dark bg
const COLOR_STACK_MAX = 24; // inline <span>/<font> color nesting depth

// Inline color stack: each <span>/<font> open pushes a color, its close pops.
// color_skip keeps push/pop balanced when the stack is full so a deep page
// can't desync the nesting (worst case a stray color bleeds — acceptable, the
// same tolerance the rest of this forgiving parser already has).
var color_stack: [COLOR_STACK_MAX]u32 = undefined;
var color_sp: u32 = 0;
var color_skip: u32 = 0;

fn currentInlineColor() u32 {
    return if (color_sp > 0) color_stack[color_sp - 1] else base_color;
}
fn pushColor(c: u32) void {
    if (color_sp < COLOR_STACK_MAX) {
        color_stack[color_sp] = c;
        color_sp += 1;
    } else color_skip += 1;
}
fn popColor() void {
    if (color_skip > 0) color_skip -= 1 else if (color_sp > 0) color_sp -= 1;
}
fn resetColorStack() void {
    color_sp = 0;
    color_skip = 0;
}

const NamedColor = struct { name: []const u8, rgb: u32 };
const named_colors = [_]NamedColor{
    .{ .name = "black", .rgb = 0x000000 },     .{ .name = "white", .rgb = 0xFFFFFF },
    .{ .name = "red", .rgb = 0xFF0000 },       .{ .name = "lime", .rgb = 0x00FF00 },
    .{ .name = "green", .rgb = 0x008000 },     .{ .name = "blue", .rgb = 0x0000FF },
    .{ .name = "yellow", .rgb = 0xFFFF00 },    .{ .name = "cyan", .rgb = 0x00FFFF },
    .{ .name = "aqua", .rgb = 0x00FFFF },      .{ .name = "magenta", .rgb = 0xFF00FF },
    .{ .name = "fuchsia", .rgb = 0xFF00FF },   .{ .name = "silver", .rgb = 0xC0C0C0 },
    .{ .name = "gray", .rgb = 0x808080 },      .{ .name = "grey", .rgb = 0x808080 },
    .{ .name = "maroon", .rgb = 0x800000 },    .{ .name = "olive", .rgb = 0x808000 },
    .{ .name = "purple", .rgb = 0x800080 },    .{ .name = "teal", .rgb = 0x008080 },
    .{ .name = "navy", .rgb = 0x000080 },      .{ .name = "orange", .rgb = 0xFFA500 },
    .{ .name = "pink", .rgb = 0xFFC0CB },      .{ .name = "brown", .rgb = 0xA52A2A },
    .{ .name = "gold", .rgb = 0xFFD700 },      .{ .name = "indigo", .rgb = 0x4B0082 },
    .{ .name = "violet", .rgb = 0xEE82EE },    .{ .name = "crimson", .rgb = 0xDC143C },
    .{ .name = "salmon", .rgb = 0xFA8072 },    .{ .name = "coral", .rgb = 0xFF7F50 },
    .{ .name = "tomato", .rgb = 0xFF6347 },    .{ .name = "khaki", .rgb = 0xF0E68C },
    .{ .name = "lightgray", .rgb = 0xD3D3D3 }, .{ .name = "lightgrey", .rgb = 0xD3D3D3 },
    .{ .name = "darkgray", .rgb = 0xA9A9A9 },  .{ .name = "darkgrey", .rgb = 0xA9A9A9 },
    .{ .name = "lightblue", .rgb = 0xADD8E6 }, .{ .name = "steelblue", .rgb = 0x4682B4 },
    .{ .name = "royalblue", .rgb = 0x4169E1 }, .{ .name = "skyblue", .rgb = 0x87CEEB },
    .{ .name = "darkred", .rgb = 0x8B0000 },   .{ .name = "darkgreen", .rgb = 0x006400 },
    .{ .name = "darkblue", .rgb = 0x00008B },  .{ .name = "tan", .rgb = 0xD2B48C },
};

fn hexNibble(c: u8) ?u32 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => @as(u32, c - 'a') + 10,
        'A'...'F' => @as(u32, c - 'A') + 10,
        else => null,
    };
}

fn trimWs(s: []const u8) []const u8 {
    var a: usize = 0;
    var b: usize = s.len;
    while (a < b and (s[a] == ' ' or s[a] == '\t' or s[a] == '\r' or s[a] == '\n')) a += 1;
    while (b > a and (s[b - 1] == ' ' or s[b - 1] == '\t' or s[b - 1] == '\r' or s[b - 1] == '\n')) b -= 1;
    return s[a..b];
}

/// Lift a color's luminance so it stays legible on the dark reader theme.
/// Pages author colors for LIGHT backgrounds (black body text, navy headings),
/// which would vanish on our dark bg; too-dark values are scaled up channel-
/// wise (hue-preserving, bright channels saturate) until they clear MIN_LUM.
fn readableOnDark(rgb: u32) u32 {
    const r: u32 = (rgb >> 16) & 0xFF;
    const g: u32 = (rgb >> 8) & 0xFF;
    const b: u32 = rgb & 0xFF;
    const lum = (r * 30 + g * 59 + b * 11) / 100;
    if (lum >= MIN_LUM) return rgb;
    if (lum == 0) return 0xD6DAE0; // pure black → default light text
    const nr: u32 = @min(@as(u32, 255), r * MIN_LUM / lum);
    const ng: u32 = @min(@as(u32, 255), g * MIN_LUM / lum);
    const nb: u32 = @min(@as(u32, 255), b * MIN_LUM / lum);
    return (nr << 16) | (ng << 8) | nb;
}

/// Parse a CSS color value (#rgb, #rrggbb, or a named color) → 0xRRGGBB,
/// luminance-lifted for the dark theme. null for anything else (rgb()/hsl()/
/// inherit/…), so the caller keeps the inherited color.
fn parseColor(raw: []const u8) ?u32 {
    const s = trimWs(raw);
    if (s.len == 0) return null;
    if (s[0] == '#') {
        const hex = s[1..];
        if (hex.len == 3) {
            var v: u32 = 0;
            for (hex) |c| {
                const n = hexNibble(c) orelse return null;
                v = (v << 8) | (n << 4) | n; // #abc → #aabbcc
            }
            return readableOnDark(v);
        } else if (hex.len == 6) {
            var v: u32 = 0;
            for (hex) |c| {
                const n = hexNibble(c) orelse return null;
                v = (v << 4) | n;
            }
            return readableOnDark(v);
        }
        return null;
    }
    for (named_colors) |nc| {
        if (eqlLower(s, nc.name)) return readableOnDark(nc.rgb);
    }
    return null;
}

/// Within a CSS `style` attribute value, return the `color` property's value
/// (NOT background-color). Matches `color` only at a property boundary (start,
/// ';', or whitespace) so `background-color` is skipped.
fn findStyleColor(style: []const u8) ?[]const u8 {
    var i: usize = 0;
    while (i + 5 <= style.len) : (i += 1) {
        if (!eqlLower(style[i .. i + 5], "color")) continue;
        if (i > 0) {
            const p = style[i - 1];
            if (isAlpha(p) or p == '-') continue; // e.g. background-color
        }
        var j = i + 5;
        while (j < style.len and (style[j] == ' ' or style[j] == '\t')) : (j += 1) {}
        if (j >= style.len or style[j] != ':') continue;
        j += 1;
        const start = j;
        while (j < style.len and style[j] != ';') : (j += 1) {}
        return style[start..j];
    }
    return null;
}

/// Author color from a tag's attributes: `style="…color:…"` first, then a
/// legacy `color="…"` attribute (<font color>). null = no author color.
fn colorFromAttrs(tag_inner: []const u8) ?u32 {
    if (findAttr(tag_inner, "style")) |st| {
        if (findStyleColor(st)) |cv| {
            if (parseColor(cv)) |c| return c;
        }
    }
    if (findAttr(tag_inner, "color")) |cv| {
        if (parseColor(cv)) |c| return c;
    }
    return null;
}

// ---------------------------------------------------------------------
// Block-tag → block parameters. Returns null for tags we don't open a block
// for (inline / container / unknown).

const BlockSpec = struct { font: render.Font, sb: u16, sa: u16, bullet: render.Bullet };

fn headingSpec(name: []const u8) ?BlockSpec {
    if (eqlLower(name, "h1")) return .{ .font = .h1, .sb = 16, .sa = 8, .bullet = .none };
    if (eqlLower(name, "h2")) return .{ .font = .h2, .sb = 14, .sa = 6, .bullet = .none };
    if (eqlLower(name, "h3") or eqlLower(name, "h4") or eqlLower(name, "h5") or eqlLower(name, "h6"))
        return .{ .font = .h3, .sb = 10, .sa = 4, .bullet = .none };
    return null;
}

// Plain block-break tags with no extra vertical gap (structural containers).
fn isStructuralBlock(name: []const u8) bool {
    const list = [_][]const u8{
        "div",     "section", "article", "header", "footer",
        "nav",     "main",    "aside",   "figure", "figcaption",
        "table",   "tr",      "dd",      "dt",     "form",
        "address", "details", "summary", "fieldset",
    };
    for (list) |b| {
        if (eqlLower(name, b)) return true;
    }
    return false;
}

// ---------------------------------------------------------------------
// Skip the *content* of a raw-text element up to its close tag. `close` is the
// lowercase opener of the end tag (e.g. "</script"). Returns the index just
// past the close tag's '>'. If no close is found, returns `from` unchanged so
// the caller falls back to treating the element as empty (never eats the doc).

fn skipUntilClose(html: []const u8, from: usize, close: []const u8) ?usize {
    var k = from;
    while (k < html.len) : (k += 1) {
        if (html[k] == '<' and k + close.len <= html.len and eqlLower(html[k .. k + close.len], close)) {
            var m = k + close.len;
            while (m < html.len and html[m] != '>') : (m += 1) {}
            return if (m < html.len) m + 1 else html.len;
        }
    }
    return null;
}

// ---------------------------------------------------------------------
// <title> capture. Display-only; whitespace-collapsed, ASCII, light entity
// decode. Kept separate from the body text pipeline.

fn setTitleClean(s: []const u8) void {
    var buf: [render.MAX_TITLE]u8 = undefined;
    var n: usize = 0;
    var sp = false; // a run of whitespace is pending (leading run suppressed)
    var i: usize = 0;
    while (i < s.len) {
        var ch: u8 = 0;
        var have = false;
        const c = s[i];
        if (c == ' ' or c == '\t' or c == '\r' or c == '\n') {
            if (n > 0) sp = true;
            i += 1;
        } else if (c == '&') {
            var j = i + 1;
            const limit = @min(s.len, i + 12);
            while (j < limit and s[j] != ';') : (j += 1) {}
            if (j < limit and s[j] == ';') {
                const nm = s[i + 1 .. j];
                if (eqlLower(nm, "amp")) {
                    ch = '&';
                    have = true;
                } else if (eqlLower(nm, "lt")) {
                    ch = '<';
                    have = true;
                } else if (eqlLower(nm, "gt")) {
                    ch = '>';
                    have = true;
                } else if (eqlLower(nm, "quot")) {
                    ch = '"';
                    have = true;
                } else if (eqlLower(nm, "apos") or eqlLower(nm, "#39")) {
                    ch = '\'';
                    have = true;
                } else if (eqlLower(nm, "nbsp")) {
                    if (n > 0) sp = true;
                } else if (eqlLower(nm, "mdash") or eqlLower(nm, "ndash")) {
                    ch = '-';
                    have = true;
                }
                // else: unknown entity — dropped.
                i = j + 1;
            } else {
                i += 1; // lone '&' — drop
            }
        } else if (c >= 0x20 and c <= 0x7E) {
            ch = c;
            have = true;
            i += 1;
        } else {
            i += 1; // non-ASCII — drop
        }
        if (have) {
            if (sp and n < buf.len) {
                buf[n] = ' ';
                n += 1;
            }
            sp = false;
            if (n < buf.len) {
                buf[n] = ch;
                n += 1;
            } else break;
        }
    }
    doc.setTitle(buf[0..n]);
}

// `from` is just past the opening <title…>'s '>'. Capture the inner text into
// the document title; return the index just past the matching </title…>'s '>'.
fn captureTitle(html: []const u8, from: usize) usize {
    var k = from;
    while (k < html.len) : (k += 1) {
        if (html[k] == '<' and k + 7 <= html.len and eqlLower(html[k .. k + 7], "</title")) break;
    }
    setTitleClean(html[from..@min(k, html.len)]);
    if (k >= html.len) return html.len;
    var m = k + 7;
    while (m < html.len and html[m] != '>') : (m += 1) {}
    return if (m < html.len) m + 1 else html.len;
}

// Find a <title> anywhere in [from, to) (used to lift a title out of a <head>
// whose contents we otherwise drop) and capture it.
fn scanTitleIn(html: []const u8, from: usize, to: usize) void {
    const lim = @min(to, html.len);
    var k = from;
    while (k + 6 < lim) : (k += 1) { // k+6 < lim <= html.len → after_name read is safe
        if (html[k] != '<') continue;
        if (!eqlLower(html[k .. k + 6], "<title")) continue;
        // Only a real <title> (the next char ends the tag name).
        const after_name = html[k + 6];
        if (after_name == '>' or after_name == ' ' or after_name == '\t' or
            after_name == '\r' or after_name == '\n' or after_name == '/')
        {
            var m = k + 6;
            while (m < html.len and html[m] != '>') : (m += 1) {}
            const inner_from = if (m < html.len) m + 1 else html.len;
            _ = captureTitle(html, inner_from);
            return;
        }
    }
}

// ---------------------------------------------------------------------
// Main pass.

pub fn parse(d: *render.Document, html: []const u8, th: render.Theme) void {
    doc = d;
    theme = th;
    doc.reset();

    base_font = .body;
    base_color = th.text;
    cur_block_open = false;
    bold_depth = 0;
    code_depth = 0;
    cur_link = -1;
    quote_depth = 0;
    list_depth = 0;
    pre_depth = 0;
    sp_pending = false;
    nl_run = 0;
    resetColorStack();

    var i: usize = 0;
    while (i < html.len) {
        const c = html[i];
        if (c == '<') {
            // Comment.
            if (i + 4 <= html.len and html[i + 1] == '!' and html[i + 2] == '-' and html[i + 3] == '-') {
                var k = i + 4;
                while (k + 3 <= html.len and !(html[k] == '-' and html[k + 1] == '-' and html[k + 2] == '>')) : (k += 1) {}
                i = if (k + 3 <= html.len) k + 3 else html.len;
                continue;
            }
            // <!doctype …> and other <! declarations: skip to '>'.
            if (i + 1 < html.len and html[i + 1] == '!') {
                var k = i + 1;
                while (k < html.len and html[k] != '>') : (k += 1) {}
                i = if (k < html.len) k + 1 else html.len;
                continue;
            }

            var j = i + 1;
            var closing = false;
            if (j < html.len and html[j] == '/') {
                closing = true;
                j += 1;
            }
            const name_start = j;
            while (j < html.len and isAlnum(html[j])) : (j += 1) {}
            const name = html[name_start..j];
            var tag_end = j;
            while (tag_end < html.len and html[tag_end] != '>') : (tag_end += 1) {}
            const tag_inner = html[name_start..tag_end];
            const after = if (tag_end < html.len) tag_end + 1 else html.len;

            // Raw-text / head elements: drop their contents — but lift out the
            // <title> (the page title), wherever it lives.
            if (!closing and (eqlLower(name, "script") or eqlLower(name, "style") or
                eqlLower(name, "title") or eqlLower(name, "head")))
            {
                if (eqlLower(name, "script")) {
                    i = skipUntilClose(html, after, "</script") orelse after;
                } else if (eqlLower(name, "style")) {
                    i = skipUntilClose(html, after, "</style") orelse after;
                } else if (eqlLower(name, "title")) {
                    if (doc.title_len == 0) {
                        i = captureTitle(html, after);
                    } else {
                        i = skipUntilClose(html, after, "</title") orelse after;
                    }
                } else { // head — drop contents, but capture the title first
                    const head_end = skipUntilClose(html, after, "</head") orelse html.len;
                    if (doc.title_len == 0) scanTitleIn(html, after, head_end);
                    i = head_end;
                }
                continue;
            }

            handleTag(name, tag_inner, closing);
            i = after;
            continue;
        } else if (c == '&') {
            i += handleEntity(html, i);
            continue;
        } else if (c == ' ' or c == '\t' or c == '\r') {
            emitSpace();
            i += 1;
            continue;
        } else if (c == '\n') {
            if (pre_depth > 0) emitBreak() else emitSpace();
            i += 1;
            continue;
        } else if (c >= 0x20 and c <= 0x7E) {
            emitText(c);
            i += 1;
            continue;
        } else {
            // Non-ASCII / control — drop (keeps text pure ASCII so layout
            // widths match the atlas advance exactly).
            i += 1;
            continue;
        }
    }

    if (cur_link >= 0) cur_link = -1;
    doc.finish();
}

fn handleTag(name: []const u8, tag_inner: []const u8, closing: bool) void {
    // --- inline style modifiers (never break the block) ---
    if (eqlLower(name, "a")) {
        if (!closing) {
            if (findHref(tag_inner)) |href| {
                if (href.len > 0 and href[0] != '#') {
                    const id = doc.addLink(href);
                    if (id >= 0) cur_link = id;
                }
            }
        } else {
            cur_link = -1;
        }
        applyStyle();
        return;
    }
    if (eqlLower(name, "b") or eqlLower(name, "strong")) {
        if (!closing) bold_depth += 1 else if (bold_depth > 0) {
            bold_depth -= 1;
        }
        applyStyle();
        return;
    }
    if (eqlLower(name, "code") or eqlLower(name, "tt") or eqlLower(name, "kbd") or eqlLower(name, "samp")) {
        if (!closing) code_depth += 1 else if (code_depth > 0) {
            code_depth -= 1;
        }
        applyStyle();
        return;
    }
    if (eqlLower(name, "span") or eqlLower(name, "font")) {
        // Inline color carrier. Push this element's author color (or inherit
        // the current one so the matching close pops cleanly). No font/face or
        // size handling — we have no italic/size variants.
        if (!closing) {
            pushColor(colorFromAttrs(tag_inner) orelse currentInlineColor());
        } else popColor();
        applyStyle();
        return;
    }
    if (eqlLower(name, "i") or eqlLower(name, "em") or
        eqlLower(name, "u") or eqlLower(name, "small") or eqlLower(name, "abbr") or
        eqlLower(name, "cite") or eqlLower(name, "sub") or eqlLower(name, "sup"))
    {
        // No italic/etc. variants — render as-is (no-op), keep the block intact.
        return;
    }

    // --- inline line break ---
    if (eqlLower(name, "br")) {
        emitBreak();
        return;
    }

    // --- image (void element) → a block-level picture ---
    if (eqlLower(name, "img")) {
        if (!closing) {
            if (findAttr(tag_inner, "src")) |src| {
                if (src.len > 0 and !(src.len >= 5 and eqlLower(src[0..5], "data:"))) {
                    var w: u32 = 0;
                    var h: u32 = 0;
                    if (findAttr(tag_inner, "width")) |ws| w = parseUint(ws);
                    if (findAttr(tag_inner, "height")) |hs| h = parseUint(hs);
                    const id = doc.addImage(src, w, h);
                    if (id >= 0) doc.addImageBlock(currentIndent(), 6, 6, id, cur_link);
                }
            }
        }
        return;
    }

    // --- list / quote containers (adjust depth, break the block) ---
    if (eqlLower(name, "blockquote")) {
        closeBlock();
        if (!closing) quote_depth += 1 else if (quote_depth > 0) {
            quote_depth -= 1;
        }
        return;
    }
    if (eqlLower(name, "ul") or eqlLower(name, "ol")) {
        closeBlock();
        if (!closing) list_depth += 1 else if (list_depth > 0) {
            list_depth -= 1;
        }
        return;
    }

    // --- block elements that open a styled block ---
    if (eqlLower(name, "li")) {
        if (!closing) {
            const ind = currentIndent() + BULLET_GAP;
            openBlock(.body, colorFromAttrs(tag_inner) orelse baseColorForDepth(), ind, 2, 2, .disc);
        } else closeBlock();
        return;
    }
    if (eqlLower(name, "pre")) {
        if (!closing) {
            pre_depth += 1;
            openBlock(.mono, colorFromAttrs(tag_inner) orelse baseColorForDepth(), currentIndent(), 8, 8, .none);
        } else {
            closeBlock();
            if (pre_depth > 0) pre_depth -= 1;
        }
        return;
    }
    if (eqlLower(name, "p")) {
        if (!closing) {
            openBlock(.body, colorFromAttrs(tag_inner) orelse baseColorForDepth(), currentIndent(), PARA_GAP, PARA_GAP, .none);
        } else closeBlock();
        return;
    }
    if (headingSpec(name)) |spec| {
        if (!closing) {
            openBlock(spec.font, colorFromAttrs(tag_inner) orelse theme.text, currentIndent(), spec.sb, spec.sa, .none);
        } else closeBlock();
        return;
    }
    if (eqlLower(name, "hr")) {
        // A visual gap: close current, leave an empty margin block.
        closeBlock();
        doc.beginBlock(currentIndent(), 6, 6, .none);
        doc.endBlock();
        return;
    }
    if (isStructuralBlock(name)) {
        if (!closing) {
            openBlock(.body, colorFromAttrs(tag_inner) orelse baseColorForDepth(), currentIndent(), 0, 0, .none);
        } else closeBlock();
        return;
    }

    // Unknown tag: ignore (text inside still renders in the current block).
}
