// render — a small, allocation-free rich-text layout & paint engine.
//
// This is the "renderer primitive" the baby browser (app/web.zig) stands on,
// but it knows nothing about HTML or HTTP — it's a generic document model that
// any reader (markdown, docs, RSS) can target. The pipeline is:
//
//   1. A producer (e.g. lib/html.zig) fills a `Document` via the builder API:
//        reset → beginBlock → setStyle → putByte… → finish
//      A Document is a flat text buffer plus three parallel descriptions of it:
//        * runs   — contiguous style spans (font/color/underline/link) over text
//        * blocks — block boxes (indent + vertical margins + bullet) over text
//        * links  — href strings, referenced by index from a run's style
//
//   2. `layout(doc, content_w)` word-wraps every block into **line boxes**, each
//      a list of placed **spans** (a run-slice with a resolved x/width). Lines
//      carry pixel `top`/`height`/`baseline`, so scrolling is in PIXELS and a
//      single line can mix a 24px heading run with 16px body runs, baseline-
//      aligned. Total height lands in `doc.doc_height`.
//
//   3. `paint(doc, canvas, …, scroll_y, theme, hovered_link)` blits the visible
//      lines. Faux-bold = draw the glyph run twice (+1px x). Links underline and
//      brighten on hover.
//
//   4. `linkAt(doc, content_x, content_y)` pixel hit-tests → link id (or -1).
//
// Everything lives in fixed `.bss` arrays inside the Document the caller owns,
// so there's no allocator and no failure path beyond "ran out of buffer" (the
// `truncated` flag), which mirrors how app/web.zig already worked.

const gfx = @import("graphics");
const fa = @import("font_atlas");

// ---------------------------------------------------------------------
// Logical fonts. Mapped to a concrete atlas (+ faux-bold flag) at paint time
// so producers think in roles ("this is a heading"), not pixel sizes.

pub const Font = enum(u8) {
    body, // 16px proportional
    bold, // 16px proportional + faux-bold
    h1, // 24px + faux-bold
    h2, // 24px
    h3, // 16px + faux-bold (h4–h6 reuse this)
    mono, // monospace
    mono_bold, // monospace + faux-bold

    pub fn atlas(self: Font) *const fa.FontAtlas {
        return switch (self) {
            .body, .bold, .h3 => &fa.default_16,
            .h1, .h2 => &fa.default_24,
            .mono, .mono_bold => &fa.default_mono,
        };
    }

    pub fn isBold(self: Font) bool {
        return switch (self) {
            .bold, .h1, .h3, .mono_bold => true,
            .body, .h2, .mono => false,
        };
    }
};

pub const Bullet = enum(u8) { none, disc };

pub const Style = struct {
    font: Font = .body,
    color: u32 = 0xD6DAE0,
    underline: bool = false,
    /// Index into `Document.links`, or -1 for "not a link".
    link_id: i32 = -1,

    fn eql(a: Style, b: Style) bool {
        return a.font == b.font and a.color == b.color and
            a.underline == b.underline and a.link_id == b.link_id;
    }
};

pub const Theme = struct {
    text: u32 = 0xD6DAE0,
    link: u32 = 0x6FB0FF,
    link_hover: u32 = 0xA9D2FF,
    muted: u32 = 0x808898,
    bg: u32 = 0x16171A,
};

pub const dark_theme = Theme{};

// ---------------------------------------------------------------------
// Document model.

const Run = struct {
    start: u32 = 0,
    end: u32 = 0,
    style: Style = .{},
};

const Block = struct {
    text_start: u32 = 0,
    text_end: u32 = 0,
    run_start: u32 = 0,
    run_end: u32 = 0,
    indent: u16 = 0,
    space_before: u16 = 0,
    space_after: u16 = 0,
    bullet: Bullet = .none,
    /// >= 0 for an image block (a self-contained block with no text whose one
    /// line is the image). `image_link` carries an enclosing <a>'s link id.
    image_id: i32 = -1,
    image_link: i32 = -1,
};

const Link = struct { off: u32 = 0, len: u32 = 0 };

/// A referenced image. `url` lives in the shared href_pool. Intrinsic decode
/// dims (`src_w`/`src_h`) and `pixels` are filled in by the app after it
/// fetches + decodes; `nat_w`/`nat_h` are the optional <img width/height>
/// request. `pixels` null + `failed` distinguishes pending from broken.
pub const Image = struct {
    url_off: u32 = 0,
    url_len: u32 = 0,
    nat_w: u32 = 0,
    nat_h: u32 = 0,
    src_w: u32 = 0,
    src_h: u32 = 0,
    pixels: ?[*]const u8 = null,
    failed: bool = false,
};

// Layout output.
const Span = struct {
    text_start: u32,
    text_end: u32,
    font: Font,
    color: u32,
    underline: bool,
    link_id: i32,
    x: i32, // relative to the line's content-left (x0 + indent)
    w: u32,
};

const LineBox = struct {
    span_start: u32,
    span_end: u32,
    indent: u16,
    top: u32, // pixels from document top
    height: u16,
    baseline: u16,
    bullet: Bullet,
    // Image lines carry no spans; these describe the picture instead.
    image_id: i32 = -1,
    img_w: u16 = 0,
    img_h: u16 = 0,
    image_link: i32 = -1,
};

// Buffer caps. Generous but bounded; overflow trips `truncated` and stops.
pub const MAX_TEXT: usize = 160 * 1024;
pub const MAX_RUNS: usize = 8000;
pub const MAX_BLOCKS: usize = 4000;
pub const MAX_HREF: usize = 48 * 1024;
pub const MAX_LINKS: usize = 1024;
pub const MAX_SPANS: usize = 14000;
pub const MAX_LINES: usize = 9000;
pub const MAX_IMAGES: usize = 24;

pub const Document = struct {
    // Source content.
    text: [MAX_TEXT]u8 = undefined,
    text_len: u32 = 0,
    runs: [MAX_RUNS]Run = undefined,
    run_count: u32 = 0,
    blocks: [MAX_BLOCKS]Block = undefined,
    block_count: u32 = 0,
    href_pool: [MAX_HREF]u8 = undefined,
    href_len: u32 = 0,
    links: [MAX_LINKS]Link = undefined,
    link_count: u32 = 0,

    // Layout output.
    images: [MAX_IMAGES]Image = undefined,
    image_count: u32 = 0,

    spans: [MAX_SPANS]Span = undefined,
    span_count: u32 = 0,
    lines: [MAX_LINES]LineBox = undefined,
    line_count: u32 = 0,
    doc_height: u32 = 0,

    truncated: bool = false,

    // ---- builder state (transient, valid between reset() and finish()) ----
    b_block_open: bool = false,
    b_block_idx: u32 = 0,
    b_run_open: bool = false,
    b_run_start: u32 = 0,
    b_style: Style = .{},

    // -----------------------------------------------------------------
    // Builder API.

    pub fn reset(self: *Document) void {
        self.text_len = 0;
        self.run_count = 0;
        self.block_count = 0;
        self.href_len = 0;
        self.link_count = 0;
        self.image_count = 0;
        self.span_count = 0;
        self.line_count = 0;
        self.doc_height = 0;
        self.truncated = false;
        self.b_block_open = false;
        self.b_run_open = false;
        self.b_run_start = 0;
        self.b_style = .{};
    }

    fn closeRun(self: *Document) void {
        if (self.b_run_open and self.text_len > self.b_run_start) {
            if (self.run_count < MAX_RUNS) {
                self.runs[self.run_count] = .{
                    .start = self.b_run_start,
                    .end = self.text_len,
                    .style = self.b_style,
                };
                self.run_count += 1;
            } else self.truncated = true;
        }
        self.b_run_open = false;
    }

    /// End the current block (closing any open run). Idempotent.
    pub fn endBlock(self: *Document) void {
        self.closeRun();
        if (self.b_block_open) {
            self.blocks[self.b_block_idx].text_end = self.text_len;
            self.blocks[self.b_block_idx].run_end = self.run_count;
            self.b_block_open = false;
        }
    }

    /// Begin a new block box. Closes the previous one. `indent` is the left
    /// inset in px; `space_before`/`space_after` are vertical margins (px,
    /// collapsed against neighbours at layout time).
    pub fn beginBlock(self: *Document, indent: u16, space_before: u16, space_after: u16, bullet: Bullet) void {
        self.endBlock();
        if (self.block_count >= MAX_BLOCKS) {
            self.truncated = true;
            return;
        }
        self.b_block_idx = self.block_count;
        self.blocks[self.block_count] = .{
            .text_start = self.text_len,
            .text_end = self.text_len,
            .run_start = self.run_count,
            .run_end = self.run_count,
            .indent = indent,
            .space_before = space_before,
            .space_after = space_after,
            .bullet = bullet,
        };
        self.block_count += 1;
        self.b_block_open = true;
        // The next putByte opens a run with the current style.
        self.b_run_open = false;
        self.b_run_start = self.text_len;
    }

    /// Switch the active inline style. Cheap if unchanged.
    pub fn setStyle(self: *Document, style: Style) void {
        if (self.b_run_open and style.eql(self.b_style)) return;
        self.closeRun();
        self.b_style = style;
        self.b_run_start = self.text_len;
        self.b_run_open = true;
    }

    pub fn putByte(self: *Document, c: u8) void {
        if (!self.b_run_open) {
            self.b_run_start = self.text_len;
            self.b_run_open = true;
        }
        if (self.text_len >= MAX_TEXT) {
            self.truncated = true;
            return;
        }
        self.text[self.text_len] = c;
        self.text_len += 1;
    }

    /// Register a link target, returning its id (for `Style.link_id`).
    pub fn addLink(self: *Document, href: []const u8) i32 {
        if (self.link_count >= MAX_LINKS) {
            self.truncated = true;
            return -1;
        }
        const off = self.href_len;
        const n = @min(href.len, MAX_HREF - self.href_len);
        if (n == 0 and href.len != 0) {
            self.truncated = true;
            return -1;
        }
        @memcpy(self.href_pool[off..][0..n], href[0..n]);
        self.href_len += @intCast(n);
        const id: i32 = @intCast(self.link_count);
        self.links[self.link_count] = .{ .off = off, .len = @intCast(n) };
        self.link_count += 1;
        return id;
    }

    pub fn linkHref(self: *const Document, id: i32) []const u8 {
        if (id < 0 or @as(u32, @intCast(id)) >= self.link_count) return "";
        const l = self.links[@intCast(id)];
        return self.href_pool[l.off..][0..l.len];
    }

    /// Register an image by source URL (stored in the href pool). `nat_w/h`
    /// are the optional <img width/height> request (0 = use decoded size).
    pub fn addImage(self: *Document, url: []const u8, nat_w: u32, nat_h: u32) i32 {
        if (self.image_count >= MAX_IMAGES) {
            self.truncated = true;
            return -1;
        }
        const off = self.href_len;
        const n = @min(url.len, MAX_HREF - self.href_len);
        if (n == 0 and url.len != 0) {
            self.truncated = true;
            return -1;
        }
        @memcpy(self.href_pool[off..][0..n], url[0..n]);
        self.href_len += @intCast(n);
        const id: i32 = @intCast(self.image_count);
        self.images[self.image_count] = .{
            .url_off = off,
            .url_len = @intCast(n),
            .nat_w = nat_w,
            .nat_h = nat_h,
        };
        self.image_count += 1;
        return id;
    }

    pub fn imageUrl(self: *const Document, id: i32) []const u8 {
        if (id < 0 or @as(u32, @intCast(id)) >= self.image_count) return "";
        const im = self.images[@intCast(id)];
        return self.href_pool[im.url_off..][0..im.url_len];
    }

    /// App calls this once it has fetched + decoded image `id` (RGBA pixels).
    pub fn setImageDecoded(self: *Document, id: i32, src_w: u32, src_h: u32, pixels: [*]const u8) void {
        if (id < 0 or @as(u32, @intCast(id)) >= self.image_count) return;
        const im = &self.images[@intCast(id)];
        im.src_w = src_w;
        im.src_h = src_h;
        im.pixels = pixels;
        im.failed = false;
    }

    pub fn setImageFailed(self: *Document, id: i32) void {
        if (id < 0 or @as(u32, @intCast(id)) >= self.image_count) return;
        const im = &self.images[@intCast(id)];
        im.pixels = null;
        im.failed = true;
    }

    /// Emit a self-contained image block (its one line is the picture).
    pub fn addImageBlock(self: *Document, indent: u16, sb: u16, sa: u16, image_id: i32, link_id: i32) void {
        self.endBlock();
        if (self.block_count >= MAX_BLOCKS) {
            self.truncated = true;
            return;
        }
        self.blocks[self.block_count] = .{
            .text_start = self.text_len,
            .text_end = self.text_len,
            .run_start = self.run_count,
            .run_end = self.run_count,
            .indent = indent,
            .space_before = sb,
            .space_after = sa,
            .bullet = .none,
            .image_id = image_id,
            .image_link = link_id,
        };
        self.block_count += 1;
        // Self-contained: no open block/run trails it.
        self.b_block_open = false;
        self.b_run_open = false;
        self.b_run_start = self.text_len;
    }

    /// Flush any open run/block. Call once after the last putByte.
    pub fn finish(self: *Document) void {
        self.endBlock();
    }
};

// ---------------------------------------------------------------------
// Layout.

fn charW(font: Font, c: u8) u32 {
    const one = [_]u8{c};
    return font.atlas().measure(&one);
}

fn pushSpan(doc: *Document, sp: Span) bool {
    if (doc.span_count >= MAX_SPANS) {
        doc.truncated = true;
        return false;
    }
    doc.spans[doc.span_count] = sp;
    doc.span_count += 1;
    return true;
}

// Find the run (within a block's run range) that covers text offset `pos`.
// `hint` is a monotonically-advancing cursor to keep this O(runs) per block.
fn runCursor(doc: *const Document, blk: Block, pos: u32, hint: *u32) u32 {
    var rc = hint.*;
    if (rc < blk.run_start) rc = blk.run_start;
    while (rc < blk.run_end and pos >= doc.runs[rc].end) rc += 1;
    // Clamp: if we ran past the end, stay on the last valid run.
    if (rc >= blk.run_end and blk.run_end > blk.run_start) rc = blk.run_end - 1;
    hint.* = rc;
    return rc;
}

// Emit the spans for one display line [start, end) at vertical offset `y`.
// Returns the line's height so the caller can advance `y`.
fn emitLine(doc: *Document, blk: Block, start: u32, end: u32, y: u32, first_line: bool) u16 {
    const span_first = doc.span_count;
    var x: i32 = 0;
    var max_lh: u16 = 0;
    var max_bl: u16 = 0;
    var rc_hint: u32 = blk.run_start;

    var pos = start;
    while (pos < end) {
        const rc = runCursor(doc, blk, pos, &rc_hint);
        const run = if (blk.run_end > blk.run_start) doc.runs[rc] else Run{};
        const seg_end = if (blk.run_end > blk.run_start) @min(end, run.end) else end;
        const stop = if (seg_end <= pos) end else seg_end; // safety: never stall
        const font = run.style.font;
        const a = font.atlas();
        const w = a.measure(doc.text[pos..stop]);
        if (!pushSpan(doc, .{
            .text_start = pos,
            .text_end = stop,
            .font = font,
            .color = run.style.color,
            .underline = run.style.underline,
            .link_id = run.style.link_id,
            .x = x,
            .w = w,
        })) break;
        x += @intCast(w);
        if (a.line_height > max_lh) max_lh = a.line_height;
        if (a.baseline > max_bl) max_bl = a.baseline;
        pos = stop;
    }

    if (doc.span_count == span_first) {
        // Empty line (blank paragraph / leading newline): body-tall gap.
        const a = Font.body.atlas();
        max_lh = a.line_height;
        max_bl = a.baseline;
    }

    if (doc.line_count < MAX_LINES) {
        doc.lines[doc.line_count] = .{
            .span_start = span_first,
            .span_end = doc.span_count,
            .indent = blk.indent,
            .top = y,
            .height = max_lh,
            .baseline = max_bl,
            .bullet = if (first_line) blk.bullet else .none,
        };
        doc.line_count += 1;
    } else doc.truncated = true;

    return max_lh;
}

/// Word-wrap the whole document for `content_w` pixels of content width.
pub fn layout(doc: *Document, content_w: u32) void {
    doc.span_count = 0;
    doc.line_count = 0;
    var y: u32 = 0;
    var prev_after: u32 = 0;

    var bi: u32 = 0;
    while (bi < doc.block_count) : (bi += 1) {
        const blk = doc.blocks[bi];
        // Collapse adjacent margins (max, not sum).
        const gap = @max(prev_after, @as(u32, blk.space_before));
        y += gap;

        const avail: u32 = if (content_w > blk.indent) content_w - blk.indent else 8;

        // Image block: one line, sized to the image (aspect-preserved, clamped
        // to the content column). No spans.
        if (blk.image_id >= 0 and blk.image_id < @as(i32, @intCast(doc.image_count))) {
            const img = doc.images[@intCast(blk.image_id)];
            var nw: u32 = if (img.nat_w > 0) img.nat_w else img.src_w;
            var nh: u32 = if (img.nat_h > 0) img.nat_h else img.src_h;
            if (nw == 0 or nh == 0) {
                // Pending / failed / dimensionless — a modest placeholder box.
                nw = @min(avail, 240);
                nh = 120;
            }
            if (nw > avail and nw > 0) {
                nh = @intCast(@as(u64, nh) * avail / nw);
                nw = avail;
            }
            if (nh == 0) nh = 1;
            if (doc.line_count < MAX_LINES) {
                doc.lines[doc.line_count] = .{
                    .span_start = doc.span_count,
                    .span_end = doc.span_count,
                    .indent = blk.indent,
                    .top = y,
                    .height = @intCast(@min(nh, 65535)),
                    .baseline = 0,
                    .bullet = .none,
                    .image_id = blk.image_id,
                    .img_w = @intCast(@min(nw, 65535)),
                    .img_h = @intCast(@min(nh, 65535)),
                    .image_link = blk.image_link,
                };
                doc.line_count += 1;
            } else doc.truncated = true;
            y += nh;
            prev_after = blk.space_after;
            if (doc.line_count >= MAX_LINES) break;
            continue;
        }

        if (blk.text_start >= blk.text_end) {
            // Empty block (a wrapper div, an <hr>, a structural container) —
            // emits no line; only its margins survive (collapsed). This keeps
            // deeply-nested empty wrappers from spamming blank rows. Explicit
            // blank lines come from <br>, which puts real '\n' bytes in text.
            prev_after = blk.space_after;
            continue;
        }

        var first_line = true;
        var i: u32 = blk.text_start;
        while (i < blk.text_end) {
            const ls = i;
            var width: u32 = 0;
            var last_space: u32 = 0;
            var have_space = false;
            var rc_hint: u32 = blk.run_start;
            var j = ls;
            while (j < blk.text_end and doc.text[j] != '\n') {
                const rc = runCursor(doc, blk, j, &rc_hint);
                const font = if (blk.run_end > blk.run_start) doc.runs[rc].style.font else Font.body;
                const cw = charW(font, doc.text[j]);
                if (width + cw > avail and j > ls) break;
                if (doc.text[j] == ' ') {
                    last_space = j;
                    have_space = true;
                }
                width += cw;
                j += 1;
            }

            var line_end = j;
            var next_i = j;
            if (j < blk.text_end and doc.text[j] == '\n') {
                next_i = j + 1; // consume the hard break
            } else if (j < blk.text_end) {
                // Width break: prefer the last space, else hard-break the word.
                if (have_space and last_space > ls) {
                    line_end = last_space;
                    next_i = last_space + 1; // skip the breaking space
                } else {
                    line_end = j;
                    next_i = j;
                }
            }

            const h = emitLine(doc, blk, ls, line_end, y, first_line);
            y += h;
            first_line = false;
            i = next_i;
            if (doc.line_count >= MAX_LINES or doc.span_count >= MAX_SPANS) break;
        }

        prev_after = blk.space_after;
        if (doc.line_count >= MAX_LINES) break;
    }

    doc.doc_height = y;
}

// ---------------------------------------------------------------------
// Paint + hit-test.

// Binary search for the first line whose bottom edge is below `y_top`
// (i.e. the first line that could be visible at scroll position y_top).
fn firstLineAt(doc: *const Document, y_top: u32) u32 {
    var lo: u32 = 0;
    var hi: u32 = doc.line_count;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        const ln = doc.lines[mid];
        if (ln.top + ln.height <= y_top) lo = mid + 1 else hi = mid;
    }
    return lo;
}

fn clampedFill(canvas: *gfx.Canvas, x: i32, y: i32, w: u32, h: u32, view_x: i32, view_y: i32, view_w: u32, view_h: u32, color: u32) void {
    var x0 = x;
    var y0 = y;
    var x1 = x + @as(i32, @intCast(w));
    var y1 = y + @as(i32, @intCast(h));
    const vx1 = view_x + @as(i32, @intCast(view_w));
    const vy1 = view_y + @as(i32, @intCast(view_h));
    if (x0 < view_x) x0 = view_x;
    if (y0 < view_y) y0 = view_y;
    if (x1 > vx1) x1 = vx1;
    if (y1 > vy1) y1 = vy1;
    if (x1 <= x0 or y1 <= y0) return;
    canvas.fillRect(@intCast(x0), @intCast(y0), @intCast(x1 - x0), @intCast(y1 - y0), color);
}

// A 1px bordered box standing in for a not-yet-loaded or broken image.
fn drawImagePlaceholder(canvas: *gfx.Canvas, x: i32, y: i32, w: u16, h: u16, vx: i32, vy: i32, vw: u32, vh: u32, color: u32) void {
    const wi: u32 = w;
    const hi: u32 = h;
    clampedFill(canvas, x, y, wi, 1, vx, vy, vw, vh, color); // top
    clampedFill(canvas, x, y + @as(i32, @intCast(hi)) - 1, wi, 1, vx, vy, vw, vh, color); // bottom
    clampedFill(canvas, x, y, 1, hi, vx, vy, vw, vh, color); // left
    clampedFill(canvas, x + @as(i32, @intCast(wi)) - 1, y, 1, hi, vx, vy, vw, vh, color); // right
}

fn drawDisc(canvas: *gfx.Canvas, cx: i32, cy: i32, r: i32, color: u32) void {
    var dy: i32 = -r;
    while (dy <= r) : (dy += 1) {
        var dx: i32 = -r;
        while (dx <= r) : (dx += 1) {
            if (dx * dx + dy * dy <= r * r) canvas.blendPixel(cx + dx, cy + dy, color, 0xFF);
        }
    }
}

/// Paint the visible portion of the document into the viewport rect
/// (x0,y0,view_w,view_h). `scroll_y` is the pixel offset of the first visible
/// row. `hovered_link` highlights spans whose link id matches (-1 = none).
pub fn paint(
    doc: *const Document,
    canvas: *gfx.Canvas,
    x0: i32,
    y0: i32,
    view_w: u32,
    view_h: u32,
    scroll_y: u32,
    theme: Theme,
    hovered_link: i32,
) void {
    const clip = fa.Clip.fromRect(@intCast(x0), @intCast(y0), view_w, view_h);
    var li = firstLineAt(doc, scroll_y);
    while (li < doc.line_count) : (li += 1) {
        const line = doc.lines[li];
        if (line.top >= scroll_y + view_h) break;
        const line_y: i32 = y0 + @as(i32, @intCast(line.top)) - @as(i32, @intCast(scroll_y));

        if (line.image_id >= 0 and line.image_id < @as(i32, @intCast(doc.image_count))) {
            const img = doc.images[@intCast(line.image_id)];
            const ix: i32 = x0 + @as(i32, @intCast(line.indent));
            if (img.pixels) |px| {
                canvas.blitRGBAScaled(px, img.src_w, img.src_h, ix, line_y, line.img_w, line.img_h, x0, y0, view_w, view_h);
            } else {
                drawImagePlaceholder(canvas, ix, line_y, line.img_w, line.img_h, x0, y0, view_w, view_h, theme.muted);
            }
            continue;
        }

        if (line.bullet == .disc) {
            const bx: i32 = x0 + @as(i32, @intCast(line.indent)) - 12;
            const by: i32 = line_y + @as(i32, @intCast(line.baseline)) - 5;
            drawDisc(canvas, bx, by, 2, theme.muted);
        }

        var si = line.span_start;
        while (si < line.span_end) : (si += 1) {
            const sp = doc.spans[si];
            const seg = doc.text[sp.text_start..sp.text_end];
            const sx: i32 = x0 + @as(i32, @intCast(line.indent)) + sp.x;
            const cell_y: i32 = line_y + @as(i32, @intCast(line.baseline)) - @as(i32, @intCast(sp.font.atlas().baseline));

            const is_hover = sp.link_id >= 0 and sp.link_id == hovered_link;
            const color = if (is_hover) theme.link_hover else sp.color;

            fa.drawTextClipped(canvas, sx, cell_y, seg, color, sp.font.atlas(), clip);
            if (sp.font.isBold())
                fa.drawTextClipped(canvas, sx + 1, cell_y, seg, color, sp.font.atlas(), clip);

            if (sp.underline or is_hover) {
                const uy: i32 = line_y + @as(i32, @intCast(line.baseline)) + 2;
                clampedFill(canvas, sx, uy, sp.w, 1, x0, y0, view_w, view_h, color);
            }
        }
    }
}

/// Hit-test a point in *content* coordinates (x relative to x0; y already
/// including scroll, i.e. scroll_y + (screen_y - y0)) → link id, or -1.
pub fn linkAt(doc: *const Document, content_x: i32, content_y: i32) i32 {
    if (content_y < 0) return -1;
    const cy: u32 = @intCast(content_y);
    const li = firstLineAt(doc, cy);
    if (li >= doc.line_count) return -1;
    const line = doc.lines[li];
    if (cy < line.top or cy >= line.top + line.height) return -1;
    if (line.image_id >= 0) {
        if (line.image_link >= 0) {
            const ilx = content_x - @as(i32, @intCast(line.indent));
            if (ilx >= 0 and ilx < @as(i32, @intCast(line.img_w))) return line.image_link;
        }
        return -1;
    }
    const lx = content_x - @as(i32, @intCast(line.indent));
    var si = line.span_start;
    while (si < line.span_end) : (si += 1) {
        const sp = doc.spans[si];
        if (sp.link_id >= 0 and lx >= sp.x and lx < sp.x + @as(i32, @intCast(sp.w))) return sp.link_id;
    }
    return -1;
}
