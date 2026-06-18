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
    var s = render.Style{ .font = base_font, .color = base_color, .underline = false, .link_id = -1 };
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

fn findHref(tag_inner: []const u8) ?[]const u8 {
    var i: usize = 0;
    while (i + 4 <= tag_inner.len) : (i += 1) {
        if (lower(tag_inner[i]) == 'h' and eqlLower(tag_inner[i .. i + 4], "href")) {
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

            // Raw-text / head elements: drop their contents.
            if (!closing and (eqlLower(name, "script") or eqlLower(name, "style") or
                eqlLower(name, "title") or eqlLower(name, "head")))
            {
                const close: []const u8 = if (eqlLower(name, "script")) "</script" else if (eqlLower(name, "style")) "</style" else if (eqlLower(name, "title")) "</title" else "</head";
                if (skipUntilClose(html, after, close)) |nx| {
                    i = nx;
                } else {
                    i = after;
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
    if (eqlLower(name, "i") or eqlLower(name, "em") or eqlLower(name, "span") or
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
            openBlock(.body, baseColorForDepth(), ind, 2, 2, .disc);
        } else closeBlock();
        return;
    }
    if (eqlLower(name, "pre")) {
        if (!closing) {
            pre_depth += 1;
            openBlock(.mono, baseColorForDepth(), currentIndent(), 8, 8, .none);
        } else {
            closeBlock();
            if (pre_depth > 0) pre_depth -= 1;
        }
        return;
    }
    if (eqlLower(name, "p")) {
        if (!closing) {
            openBlock(.body, baseColorForDepth(), currentIndent(), PARA_GAP, PARA_GAP, .none);
        } else closeBlock();
        return;
    }
    if (headingSpec(name)) |spec| {
        if (!closing) {
            openBlock(spec.font, theme.text, currentIndent(), spec.sb, spec.sa, .none);
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
            openBlock(.body, baseColorForDepth(), currentIndent(), 0, 0, .none);
        } else closeBlock();
        return;
    }

    // Unknown tag: ignore (text inside still renders in the current block).
}
