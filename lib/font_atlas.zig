// Anti-aliased font atlas — lookup over a pre-rendered alpha bitmap produced
// by tools/build_atlas.py. The atlas blob is `@embedFile`d at build time so
// kernel and apps share the same `default_16` and `default_24` instances.
//
// Format (matches build_atlas.py output):
//   magic        u32   0x464C5441 = "ATLF"
//   size_px      u16
//   baseline     u8    pixels from glyph cell top to baseline
//   line_height  u8
//   glyph_count  u16
//   codept_start u16   first codepoint (typically 32 = space)
//   atlas_w      u16
//   atlas_h      u16
//   _pad         u16
//   [glyph_count] x Glyph (12 bytes each)
//   atlas_w*atlas_h bytes of alpha (row-major)
//
// drawText() emits one blendPixel per non-zero alpha; ~50–500 pixels per
// glyph at our sizes, dominated by memory bandwidth not arithmetic.

const std = @import("std");
const gfx = @import("graphics");

const ATLF_MAGIC: u32 = 0x464C5441;

const Glyph = extern struct {
    ax: i8,        // horizontal advance
    bx: i8,        // bearing x (offset from pen origin)
    by: i8,        // glyph top in cell (pixels from cell top)
    w: u8,
    h: u8,
    _pad0: u8,
    atlas_x: u16,
    atlas_y: u16,
    _pad1: u16,
};

comptime {
    if (@sizeOf(Glyph) != 12) @compileError("Glyph must be 12 bytes");
}

pub const FontAtlas = struct {
    size_px: u16,
    baseline: u8,
    line_height: u8,
    glyph_count: u16,
    codept_start: u16,
    atlas_w: u16,
    atlas_h: u16,
    /// align(1) — `@embedFile` doesn't guarantee 2-byte alignment of the
    /// blob, so accesses go through unaligned loads.
    glyphs: [*]align(1) const Glyph,
    pixels: [*]const u8,

    /// Parse a `@embedFile`'d atlas blob. Caller's responsibility that the
    /// blob lives as long as the FontAtlas does (in our case forever — the
    /// blob lives in `.rodata`).
    pub fn parse(blob: []const u8) FontAtlas {
        if (blob.len < 16) @panic("font atlas: blob too small for header");
        const magic = std.mem.readInt(u32, blob[0..4], .little);
        if (magic != ATLF_MAGIC) @panic("font atlas: bad magic");
        const size_px = std.mem.readInt(u16, blob[4..6], .little);
        const baseline = blob[6];
        const line_height = blob[7];
        const glyph_count = std.mem.readInt(u16, blob[8..10], .little);
        const codept_start = std.mem.readInt(u16, blob[10..12], .little);
        const atlas_w = std.mem.readInt(u16, blob[12..14], .little);
        const atlas_h = std.mem.readInt(u16, blob[14..16], .little);

        const glyphs_off: usize = 16;
        const glyphs_size: usize = @as(usize, glyph_count) * @sizeOf(Glyph);
        const pixels_off: usize = glyphs_off + glyphs_size;
        const pixels_size: usize = @as(usize, atlas_w) * atlas_h;
        if (blob.len < pixels_off + pixels_size) @panic("font atlas: blob truncated");

        const glyphs_ptr: [*]align(1) const Glyph = @ptrCast(blob.ptr + glyphs_off);
        const pixels_ptr: [*]const u8 = blob.ptr + pixels_off;

        return .{
            .size_px = size_px,
            .baseline = baseline,
            .line_height = line_height,
            .glyph_count = glyph_count,
            .codept_start = codept_start,
            .atlas_w = atlas_w,
            .atlas_h = atlas_h,
            .glyphs = glyphs_ptr,
            .pixels = pixels_ptr,
        };
    }

    /// Pixel-perfect width of `text` rendered with this atlas (sum of advances).
    pub fn measure(self: FontAtlas, text: []const u8) u32 {
        var w: u32 = 0;
        for (text) |c| {
            if (c < self.codept_start) continue;
            const idx: u32 = @as(u32, c) - self.codept_start;
            if (idx >= self.glyph_count) continue;
            const g = self.glyphs[idx];
            const ax: i32 = g.ax;
            if (ax > 0) w += @intCast(ax);
        }
        return w;
    }
};

// Compile-time embedded atlases. Three slots:
//   default_16 — proportional body text (SF Pro Text 16px)
//   default_24 — proportional display titles (SF Pro Display 24px)
//   default_mono — monospace for terminal/console (SF Mono 14px)
const blob_16: []const u8 align(2) = @embedFile("assets/font_16.bin");
const blob_24: []const u8 align(2) = @embedFile("assets/font_24.bin");
const blob_mono: []const u8 align(2) = @embedFile("assets/font_mono.bin");

pub var default_16: FontAtlas = undefined;
pub var default_24: FontAtlas = undefined;
pub var default_mono: FontAtlas = undefined;

var initialized: bool = false;

/// Lazily-parse the embedded blobs. First call sets up the three default
/// atlases; subsequent calls are no-ops. Cheap to call from every
/// drawText() entry — single bool check.
pub fn ensureLoaded() void {
    if (initialized) return;
    default_16 = FontAtlas.parse(blob_16);
    default_24 = FontAtlas.parse(blob_24);
    default_mono = FontAtlas.parse(blob_mono);
    initialized = true;
}

/// Lazy accessors: ensureLoaded then return a pointer to the cached atlas.
/// Use these from widget code that doesn't want a separate init step.
pub fn getDefault16() *const FontAtlas {
    ensureLoaded();
    return &default_16;
}

pub fn getDefault24() *const FontAtlas {
    ensureLoaded();
    return &default_24;
}

pub fn getDefaultMono() *const FontAtlas {
    ensureLoaded();
    return &default_mono;
}

/// Rectangular pixel clip for `drawTextClipped`. All four edges are
/// inclusive on `min`, exclusive on `max` — same convention as
/// `fillRect(x, y, w, h)`.
pub const Clip = struct {
    x_min: i32,
    y_min: i32,
    x_max: i32,
    y_max: i32,

    pub fn fromRect(x: u32, y: u32, w: u32, h: u32) Clip {
        return .{
            .x_min = @intCast(x),
            .y_min = @intCast(y),
            .x_max = @intCast(x + w),
            .y_max = @intCast(y + h),
        };
    }
};

fn drawTextInner(
    canvas: *gfx.Canvas,
    x: i32,
    y: i32,
    text: []const u8,
    color: u32,
    atlas: *const FontAtlas,
    clip: ?Clip,
) void {
    var pen_x: i32 = x;
    for (text) |c| {
        if (c < atlas.codept_start) {
            // Tab/newline/etc. — for now just emit a space-width blank.
            if (c == ' ') {
                const space_idx: u32 = @as(u32, ' ') - atlas.codept_start;
                if (space_idx < atlas.glyph_count) {
                    pen_x += atlas.glyphs[space_idx].ax;
                }
            }
            continue;
        }
        const idx: u32 = @as(u32, c) - atlas.codept_start;
        if (idx >= atlas.glyph_count) {
            // Out-of-range codepoint — advance like a space and skip.
            pen_x += @as(i32, atlas.size_px / 2);
            continue;
        }
        const g = atlas.glyphs[idx];
        // Blit glyph alpha bitmap onto canvas, optionally clipped.
        const glyph_top: i32 = y + g.by;
        const glyph_left: i32 = pen_x + g.bx;
        var gy: u32 = 0;
        while (gy < g.h) : (gy += 1) {
            const py = glyph_top + @as(i32, @intCast(gy));
            if (clip) |c_rect| {
                if (py < c_rect.y_min or py >= c_rect.y_max) continue;
            }
            const row_in_atlas: u32 = @as(u32, g.atlas_y) + gy;
            const row_off: usize = @as(usize, row_in_atlas) * atlas.atlas_w;
            var gx: u32 = 0;
            while (gx < g.w) : (gx += 1) {
                const px = glyph_left + @as(i32, @intCast(gx));
                if (clip) |c_rect| {
                    if (px < c_rect.x_min or px >= c_rect.x_max) continue;
                }
                const a = atlas.pixels[row_off + g.atlas_x + gx];
                if (a == 0) continue;
                canvas.blendPixel(px, py, color, a);
            }
        }
        pen_x += g.ax;
    }
}

/// Render `text` at pen position (x, y) in `color` with `alpha`-blended
/// per-pixel coverage. (x, y) is the *top-left of the cell* — same as
/// `Canvas.drawText16` semantics, so it's a drop-in replacement modulo
/// the visual upgrade. No clipping beyond the framebuffer's natural bounds.
pub fn drawText(canvas: *gfx.Canvas, x: i32, y: i32, text: []const u8, color: u32, atlas: *const FontAtlas) void {
    drawTextInner(canvas, x, y, text, color, atlas, null);
}

/// Same as `drawText` but per-pixel clipped to `clip`. Use this when text
/// must stay inside a panel or card — the alpha glyph blit drops pixels
/// that fall outside, so partially-visible glyphs at the edge render only
/// the visible portion.
pub fn drawTextClipped(canvas: *gfx.Canvas, x: i32, y: i32, text: []const u8, color: u32, atlas: *const FontAtlas, clip: Clip) void {
    drawTextInner(canvas, x, y, text, color, atlas, clip);
}

/// Centered variant — measures `text` and indents from `x` so the rendered
/// width is centered in `box_w` pixels.
pub fn drawTextCentered(canvas: *gfx.Canvas, x: i32, y: i32, box_w: u32, text: []const u8, color: u32, atlas: *const FontAtlas) void {
    const tw = atlas.measure(text);
    const inset: i32 = if (box_w > tw) @intCast((box_w - tw) / 2) else 0;
    drawText(canvas, x + inset, y, text, color, atlas);
}

/// Drop-in replacement for the old bitmap `drawText16/24` methods on Canvas
/// that painted both fg and bg. Fills a rect of (measured-width × line_height)
/// with `bg`, then renders glyphs in `fg` on top via per-pixel alpha. Use
/// when the caller relies on the bg being painted (covers prior pixels). For
/// transparent rendering use the plain `drawText` instead.
pub fn drawTextOpaque(canvas: *gfx.Canvas, x: u32, y: u32, text: []const u8, fg: u32, bg: u32, atlas: *const FontAtlas) void {
    const tw = atlas.measure(text);
    canvas.fillRect(x, y, tw, atlas.line_height, bg);
    drawText(canvas, @intCast(x), @intCast(y), text, fg, atlas);
}

/// Single-char variant of drawTextOpaque. Cell width is one glyph's advance.
pub fn drawCharOpaque(canvas: *gfx.Canvas, x: u32, y: u32, ch: u8, fg: u32, bg: u32, atlas: *const FontAtlas) void {
    const buf = [1]u8{ch};
    drawTextOpaque(canvas, x, y, &buf, fg, bg, atlas);
}

/// Drop-in for `Canvas.drawTextCentered16/24` — fills a (box_w × line_height)
/// rect at (bx, by) with bg, then renders `text` in fg, horizontally centered
/// inside the box.
pub fn drawTextCenteredOpaque(canvas: *gfx.Canvas, bx: u32, by: u32, bw: u32, text: []const u8, fg: u32, bg: u32, atlas: *const FontAtlas) void {
    const tw = atlas.measure(text);
    const tx = bx + (bw -| tw) / 2;
    canvas.fillRect(bx, by, bw, atlas.line_height, bg);
    drawText(canvas, @intCast(tx), @intCast(by), text, fg, atlas);
}

/// Drop-in replacement for the old bitmap `drawNum16`/`drawNumBg` methods —
/// renders `n` in decimal and returns the x past the last digit (for caller
/// chaining like `cx = drawNumOpaque(...); drawTextOpaque(canvas, cx, ...)`).
pub fn drawNumOpaque(canvas: *gfx.Canvas, x: u32, y: u32, n: u32, fg: u32, bg: u32, atlas: *const FontAtlas) u32 {
    var buf: [16]u8 = undefined;
    var v = n;
    var k: usize = 0;
    if (v == 0) {
        buf[0] = '0';
        k = 1;
    } else {
        while (v > 0) : (v /= 10) {
            buf[15 - k] = '0' + @as(u8, @intCast(v % 10));
            k += 1;
        }
    }
    const s: []const u8 = if (n == 0) buf[0..1] else buf[16 - k .. 16];
    drawTextOpaque(canvas, x, y, s, fg, bg, atlas);
    return x + atlas.measure(s);
}
