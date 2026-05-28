//! Idiomatic Zig wrapper over stb_truetype.
//!
//! Loads TTF/OTF fonts from memory bytes; rasterizes glyphs to 8-bit alpha
//! masks at a target pixel height; reports kerning between codepoint pairs.
//! All math is freestanding-safe (text_lib.c overrides every libm
//! dependency with SSE2-only implementations — see
//! [[zig-floor-freestanding-baseline]] for why this matters).
//!
//! Typical use:
//!
//!   const tt = @import("truetype");
//!   const font = try tt.Font.load(ttf_bytes);
//!   defer font.deinit();
//!   const scale = font.scaleForPixelHeight(24.0);
//!   const vm = font.vmetrics();
//!   const line_height = @as(i32, @intFromFloat(scale * @as(f32, @floatFromInt(vm.ascent - vm.descent + vm.line_gap))));
//!   const g = font.renderCodepoint('A', scale) orelse return;
//!   defer g.deinit();
//!   // g.bitmap is width*height bytes of alpha; blit into your framebuffer.
//!
//! Built on top of vendor/text_lib.{h,c} which wraps stb_truetype.h v1.26
//! with a small opaque-handle API; the static library is shared across
//! consumers (UI widgets, future VN engine, anything that needs scalable
//! text rendering).

const raw = @import("truetype_raw");

pub const Error = error{
    InitFailed,
    OutOfMemory,
};

pub const VMetrics = struct {
    /// Distance from baseline to the highest point of any glyph, in raw
    /// font units. Multiply by `scale` to get pixels.
    ascent: i32,
    /// Distance from baseline to the lowest point — usually NEGATIVE.
    descent: i32,
    /// Recommended extra space between lines (on top of ascent-descent),
    /// in raw font units.
    line_gap: i32,

    /// Line-to-line baseline advance in pixels at the given scale.
    pub fn lineAdvance(self: VMetrics, scale: f32) f32 {
        return scale * @as(f32, @floatFromInt(self.ascent - self.descent + self.line_gap));
    }
};

pub const HMetrics = struct {
    /// Pen advance after this glyph, in raw font units.
    advance: i32,
    /// X-offset from pen position to the left edge of the glyph, in raw
    /// font units.
    left_side_bearing: i32,
};

/// Rasterized glyph: an 8-bit alpha mask plus pen-offset metadata.
/// Caller owns the bitmap and must call `deinit()`.
pub const Glyph = struct {
    /// width * height bytes of 8-bit alpha (0=fully transparent,
    /// 255=fully opaque). Row-major.
    bitmap: []u8,
    width: u32,
    height: u32,
    /// X-offset from the pen position to the top-left of the bitmap.
    xoff: i32,
    /// Y-offset from the baseline to the top of the bitmap (NEGATIVE for
    /// glyphs that extend above the baseline — which is most of them).
    yoff: i32,

    pub fn deinit(self: Glyph) void {
        raw.tt_free_bitmap(@ptrCast(@constCast(self.bitmap.ptr)));
    }
};

/// Loaded font. Holds an opaque handle to stb_truetype's `stbtt_fontinfo`
/// plus a reference to the user's TTF/OTF bytes (which must outlive the
/// Font — stb stores pointers INTO them).
pub const Font = struct {
    handle: ?*anyopaque,
    /// Reference to the TTF/OTF blob the caller supplied. Held so the
    /// caller can ask "what bytes back this font?" — and as a runtime
    /// reminder that the buffer must outlive the Font.
    bytes: []const u8,

    pub fn load(font_bytes: []const u8) Error!Font {
        const h = raw.tt_font_alloc() orelse return error.OutOfMemory;
        errdefer raw.tt_font_free(h);
        const offset = raw.tt_offset_for_index(font_bytes.ptr, 0);
        if (offset < 0) return error.InitFailed;
        if (raw.tt_init(h, font_bytes.ptr, offset) == 0) {
            return error.InitFailed;
        }
        return .{ .handle = h, .bytes = font_bytes };
    }

    /// Load a specific font from a TTC font collection. Pass 0 for the
    /// first font; 1 for the second; etc.
    pub fn loadFromCollection(font_bytes: []const u8, index: u32) Error!Font {
        const h = raw.tt_font_alloc() orelse return error.OutOfMemory;
        errdefer raw.tt_font_free(h);
        const offset = raw.tt_offset_for_index(font_bytes.ptr, @intCast(index));
        if (offset < 0) return error.InitFailed;
        if (raw.tt_init(h, font_bytes.ptr, offset) == 0) {
            return error.InitFailed;
        }
        return .{ .handle = h, .bytes = font_bytes };
    }

    pub fn deinit(self: Font) void {
        if (self.handle) |h| raw.tt_font_free(h);
    }

    /// Scale factor from raw font units to pixels at the target height.
    /// Multiply any raw-unit value (advance, bearing, ascent, descent) by
    /// this to convert to pixels.
    pub fn scaleForPixelHeight(self: *const Font, pixel_height: f32) f32 {
        return raw.tt_scale_for_pixel_height(self.handle, pixel_height);
    }

    pub fn vmetrics(self: *const Font) VMetrics {
        var a: c_int = 0;
        var d: c_int = 0;
        var g: c_int = 0;
        raw.tt_vmetrics(self.handle, &a, &d, &g);
        return .{ .ascent = a, .descent = d, .line_gap = g };
    }

    /// Codepoint → glyph index. Returns 0 if the codepoint isn't in the
    /// font (the .notdef glyph, usually drawn as a box).
    pub fn glyphIndex(self: *const Font, codepoint: u32) u32 {
        return @intCast(raw.tt_find_glyph_index(self.handle, @intCast(codepoint)));
    }

    pub fn hmetrics(self: *const Font, codepoint: u32) HMetrics {
        var adv: c_int = 0;
        var lsb: c_int = 0;
        raw.tt_codepoint_hmetrics(self.handle, @intCast(codepoint), &adv, &lsb);
        return .{ .advance = adv, .left_side_bearing = lsb };
    }

    /// Kerning adjustment in raw font units between two consecutive
    /// codepoints. Multiply by `scale` for pixels. Returns 0 if the font
    /// has no kerning table for this pair.
    pub fn kernAdvance(self: *const Font, c1: u32, c2: u32) i32 {
        return raw.tt_codepoint_kern_advance(self.handle, @intCast(c1), @intCast(c2));
    }

    /// Render a codepoint to an 8-bit alpha mask at the given scale.
    /// Returns null if the glyph has no visible pixels (whitespace).
    pub fn renderCodepoint(self: *const Font, codepoint: u32, scale: f32) ?Glyph {
        var w: c_int = 0;
        var h: c_int = 0;
        var xoff: c_int = 0;
        var yoff: c_int = 0;
        const bm_opt = raw.tt_codepoint_bitmap(
            self.handle,
            scale,
            scale,
            @intCast(codepoint),
            &w,
            &h,
            &xoff,
            &yoff,
        );
        const bm = bm_opt orelse return null;
        if (w <= 0 or h <= 0) {
            raw.tt_free_bitmap(bm);
            return null;
        }
        const size: usize = @as(usize, @intCast(w)) * @as(usize, @intCast(h));
        return .{
            .bitmap = bm[0..size],
            .width = @intCast(w),
            .height = @intCast(h),
            .xoff = xoff,
            .yoff = yoff,
        };
    }

    /// Measure a UTF-8 string's pen-advance width in pixels at the given
    /// scale, including kerning. Convenience for layout code. Skips bytes
    /// that aren't valid UTF-8.
    pub fn measureUtf8(self: *const Font, text: []const u8, scale: f32) f32 {
        var width: f32 = 0;
        var i: usize = 0;
        var prev: ?u32 = null;
        while (i < text.len) {
            const cp_info = utf8DecodeAt(text, i) orelse {
                i += 1;
                continue;
            };
            const cp = cp_info.cp;
            if (prev) |p| {
                width += @as(f32, @floatFromInt(self.kernAdvance(p, cp))) * scale;
            }
            const hm = self.hmetrics(cp);
            width += @as(f32, @floatFromInt(hm.advance)) * scale;
            prev = cp;
            i += cp_info.len;
        }
        return width;
    }
};

const Utf8Decoded = struct { cp: u32, len: usize };

fn utf8DecodeAt(text: []const u8, i: usize) ?Utf8Decoded {
    if (i >= text.len) return null;
    const b0 = text[i];
    if (b0 < 0x80) return .{ .cp = b0, .len = 1 };
    if ((b0 & 0xE0) == 0xC0 and i + 1 < text.len) {
        const b1 = text[i + 1];
        if ((b1 & 0xC0) != 0x80) return null;
        return .{ .cp = (@as(u32, b0 & 0x1F) << 6) | (b1 & 0x3F), .len = 2 };
    }
    if ((b0 & 0xF0) == 0xE0 and i + 2 < text.len) {
        const b1 = text[i + 1];
        const b2 = text[i + 2];
        if ((b1 & 0xC0) != 0x80 or (b2 & 0xC0) != 0x80) return null;
        return .{
            .cp = (@as(u32, b0 & 0x0F) << 12) | (@as(u32, b1 & 0x3F) << 6) | (b2 & 0x3F),
            .len = 3,
        };
    }
    if ((b0 & 0xF8) == 0xF0 and i + 3 < text.len) {
        const b1 = text[i + 1];
        const b2 = text[i + 2];
        const b3 = text[i + 3];
        if ((b1 & 0xC0) != 0x80 or (b2 & 0xC0) != 0x80 or (b3 & 0xC0) != 0x80) return null;
        return .{
            .cp = (@as(u32, b0 & 0x07) << 18) | (@as(u32, b1 & 0x3F) << 12) | (@as(u32, b2 & 0x3F) << 6) | (b3 & 0x3F),
            .len = 4,
        };
    }
    return null;
}
