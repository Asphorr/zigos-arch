//! Glyph-cached UTF-8 text rendering over a TrueType font onto a gfx.Canvas.
//!
//! The pre-baked SF Pro atlas (font_atlas.zig) only carries ASCII 32..126, so
//! it can't render Cyrillic — which the Telegram client needs for real contact
//! names and messages. This module rasterizes a scalable TTF (stb_truetype via
//! lib/truetype.zig) and renders arbitrary Unicode.
//!
//! stb's rasterizer mallocs an alpha bitmap per glyph and isn't cheap, so we
//! rasterize each (renderer, codepoint) ONCE and cache the alpha mask forever
//! (bounded by the number of distinct glyphs the app ever shows — a few
//! hundred). After warm-up, drawing a string is just alpha-blends from cache.
//!
//! Coordinate convention matches Canvas.drawText16: the (x, y) you pass is the
//! TOP-LEFT of the text cell; the baseline sits `ascent` pixels below y.

const tt = @import("truetype");
const gfx = @import("graphics");

/// Inclusive-min / exclusive-max pixel clip rectangle (canvas coordinates).
pub const Clip = struct {
    x0: i32,
    y0: i32,
    x1: i32,
    y1: i32,
};

const Cached = struct {
    /// stb alpha mask, width*height bytes. null = the codepoint has no visible
    /// pixels (space) or failed to rasterize — still has a valid advance.
    bitmap: ?[*]const u8 = null,
    w: u16 = 0,
    h: u16 = 0,
    xoff: i16 = 0,
    yoff: i16 = 0,
    /// Pen advance in pixels.
    adv: u16 = 0,
};

/// Power-of-two cache capacity. Distinct glyphs in Latin + full Cyrillic +
/// punctuation is ~300; 2048 keeps the open-addressing table under 1/8 load.
const CAP: u32 = 2048;
const MASK: u32 = CAP - 1;

pub const Renderer = struct {
    font: tt.Font,
    scale: f32,
    ascent: i32,
    descent: i32,
    line_h: u32,
    // Open-addressing glyph cache. keys[i]==0 marks an empty slot; codepoints
    // are never 0 so no sentinel collision. Parallel arrays avoid padding.
    // No field defaults: instances are always `undefined` + init() (which
    // zeroes `keys`), so we don't emit a 50 KB comptime initializer.
    keys: [CAP]u32 = undefined,
    glyphs: [CAP]Cached = undefined,
    count: u32 = 0,

    fn iround(x: f32) i32 {
        return @intFromFloat(if (x >= 0) x + 0.5 else x - 0.5);
    }

    /// Initialise in place (the struct is ~40 KB — never return it by value).
    pub fn init(self: *Renderer, font_bytes: []const u8, px: f32) !void {
        self.font = try tt.Font.load(font_bytes);
        self.scale = self.font.scaleForPixelHeight(px);
        const vm = self.font.vmetrics();
        self.ascent = iround(@as(f32, @floatFromInt(vm.ascent)) * self.scale);
        self.descent = iround(@as(f32, @floatFromInt(vm.descent)) * self.scale);
        self.line_h = @intCast(@max(1, iround(vm.lineAdvance(self.scale))));
        @memset(&self.keys, 0);
        self.count = 0;
    }

    pub fn lineHeight(self: *const Renderer) u32 {
        return self.line_h;
    }

    pub fn ascentPx(self: *const Renderer) i32 {
        return self.ascent;
    }

    /// Rasterize-on-miss lookup. Returns a stable pointer into the cache.
    fn lookup(self: *Renderer, cp: u32) *Cached {
        var i: u32 = (cp *% 2654435761) & MASK;
        var probes: u32 = 0;
        while (probes < CAP) : (probes += 1) {
            if (self.keys[i] == cp) return &self.glyphs[i];
            if (self.keys[i] == 0) {
                // Miss — rasterize once, keep the bitmap for the app's life.
                self.keys[i] = cp;
                self.count += 1;
                const c = &self.glyphs[i];
                const hm = self.font.hmetrics(cp);
                const a = iround(@as(f32, @floatFromInt(hm.advance)) * self.scale);
                c.adv = @intCast(@max(0, @min(a, 0xFFFF)));
                if (self.font.renderCodepoint(cp, self.scale)) |g| {
                    // Deliberately NOT g.deinit() — the cache owns it now.
                    c.bitmap = g.bitmap.ptr;
                    c.w = @intCast(g.width);
                    c.h = @intCast(g.height);
                    c.xoff = @intCast(g.xoff);
                    c.yoff = @intCast(g.yoff);
                } else {
                    c.bitmap = null;
                }
                return c;
            }
            i = (i + 1) & MASK;
        }
        // Table full (never expected at CAP=2048). Return a throwaway with a
        // sane advance so layout doesn't collapse.
        return &self.glyphs[0];
    }

    /// Pen-advance width of `text` in pixels (also warms the glyph cache).
    pub fn measure(self: *Renderer, text: []const u8) u32 {
        var w: u32 = 0;
        var it = Utf8{ .s = text };
        while (it.next()) |cp| w += self.lookup(cp).adv;
        return w;
    }

    /// Advance of a single codepoint (cache-warming).
    pub fn advanceOf(self: *Renderer, cp: u32) u32 {
        return self.lookup(cp).adv;
    }

    fn blitGlyph(self: *Renderer, canvas: *gfx.Canvas, c: *const Cached, pen: i32, baseline: i32, color: u32, clip: Clip) void {
        _ = self;
        const bm = c.bitmap orelse return;
        const gx0 = pen + c.xoff;
        const gy0 = baseline + c.yoff;
        var gy: u16 = 0;
        while (gy < c.h) : (gy += 1) {
            const py = gy0 + @as(i32, gy);
            if (py < clip.y0 or py >= clip.y1) continue;
            const row: usize = @as(usize, gy) * c.w;
            var gx: u16 = 0;
            while (gx < c.w) : (gx += 1) {
                const px = gx0 + @as(i32, gx);
                if (px < clip.x0 or px >= clip.x1) continue;
                const a = bm[row + gx];
                if (a == 0) continue;
                canvas.blendPixel(px, py, color, a);
            }
        }
    }

    /// Draw `text` clipped to `clip`. (x, y) is the cell top-left. Returns the
    /// pen x past the last glyph.
    pub fn drawClip(self: *Renderer, canvas: *gfx.Canvas, x: i32, y: i32, text: []const u8, color: u32, clip: Clip) i32 {
        var pen = x;
        const baseline = y + self.ascent;
        var it = Utf8{ .s = text };
        while (it.next()) |cp| {
            const c = self.lookup(cp);
            self.blitGlyph(canvas, c, pen, baseline, color, clip);
            pen += c.adv;
        }
        return pen;
    }

    /// Draw `text` clipped only to the framebuffer bounds.
    pub fn draw(self: *Renderer, canvas: *gfx.Canvas, x: i32, y: i32, text: []const u8, color: u32) i32 {
        const clip = Clip{ .x0 = 0, .y0 = 0, .x1 = @intCast(canvas.width), .y1 = @intCast(canvas.height) };
        return self.drawClip(canvas, x, y, text, color, clip);
    }

    /// Draw `text` centered in [x, x+w), clipped to `clip`.
    pub fn drawCentered(self: *Renderer, canvas: *gfx.Canvas, x: i32, y: i32, w: u32, text: []const u8, color: u32, clip: Clip) void {
        const tw = self.measure(text);
        const inset: i32 = if (w > tw) @intCast((w - tw) / 2) else 0;
        _ = self.drawClip(canvas, x + inset, y, text, color, clip);
    }
};

/// Minimal UTF-8 codepoint iterator. Invalid bytes are skipped one at a time
/// (so a corrupt stream degrades to garbage glyphs, never a desync/hang).
pub const Utf8 = struct {
    s: []const u8,
    i: usize = 0,

    pub fn next(self: *Utf8) ?u32 {
        if (self.i >= self.s.len) return null;
        const b0 = self.s[self.i];
        if (b0 < 0x80) {
            self.i += 1;
            return b0;
        }
        if ((b0 & 0xE0) == 0xC0 and self.i + 1 < self.s.len and (self.s[self.i + 1] & 0xC0) == 0x80) {
            const cp = (@as(u32, b0 & 0x1F) << 6) | (self.s[self.i + 1] & 0x3F);
            self.i += 2;
            return cp;
        }
        if ((b0 & 0xF0) == 0xE0 and self.i + 2 < self.s.len and
            (self.s[self.i + 1] & 0xC0) == 0x80 and (self.s[self.i + 2] & 0xC0) == 0x80)
        {
            const cp = (@as(u32, b0 & 0x0F) << 12) | (@as(u32, self.s[self.i + 1] & 0x3F) << 6) | (self.s[self.i + 2] & 0x3F);
            self.i += 3;
            return cp;
        }
        if ((b0 & 0xF8) == 0xF0 and self.i + 3 < self.s.len and
            (self.s[self.i + 1] & 0xC0) == 0x80 and (self.s[self.i + 2] & 0xC0) == 0x80 and (self.s[self.i + 3] & 0xC0) == 0x80)
        {
            const cp = (@as(u32, b0 & 0x07) << 18) | (@as(u32, self.s[self.i + 1] & 0x3F) << 12) |
                (@as(u32, self.s[self.i + 2] & 0x3F) << 6) | (self.s[self.i + 3] & 0x3F);
            self.i += 4;
            return cp;
        }
        // Invalid lead/continuation — skip one byte.
        self.i += 1;
        return 0xFFFD;
    }

    /// Byte length of the codepoint starting at `s[i]` (1 on invalid).
    pub fn cpLen(s: []const u8, i: usize) usize {
        const b0 = s[i];
        if (b0 < 0x80) return 1;
        if ((b0 & 0xE0) == 0xC0) return if (i + 1 < s.len) 2 else 1;
        if ((b0 & 0xF0) == 0xE0) return if (i + 2 < s.len) 3 else 1;
        if ((b0 & 0xF8) == 0xF0) return if (i + 3 < s.len) 4 else 1;
        return 1;
    }
};
