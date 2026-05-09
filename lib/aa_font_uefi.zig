// UEFI-side anti-aliased font atlas — same blob format and Glyph layout as
// `lib/font_atlas.zig` (kernel + apps), but the renderer writes directly to a
// GOP framebuffer instead of a `Canvas`. The bootloader target is uefi/msvc;
// pulling in the freestanding `graphics` module isn't possible, so this module
// is a self-contained twin.
//
// IMPORTANT: keep the `Glyph` field order in lockstep with `lib/font_atlas.zig`
// and `tools/build_atlas.py`'s `struct.pack`. Mis-ordering reads pad bytes as
// `w/h` and the inner blit loop never executes (silent black text).

const std = @import("std");

const ATLF_MAGIC: u32 = 0x464C5441;

pub const Glyph = extern struct {
    ax: i8,
    bx: i8,
    by: i8,
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
    glyphs: [*]align(1) const Glyph,
    pixels: [*]const u8,

    pub fn parse(blob: []const u8) FontAtlas {
        if (blob.len < 16) @panic("aa_font: blob too small for header");
        const magic = std.mem.readInt(u32, blob[0..4], .little);
        if (magic != ATLF_MAGIC) @panic("aa_font: bad magic");
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
        if (blob.len < pixels_off + pixels_size) @panic("aa_font: blob truncated");

        return .{
            .size_px = size_px,
            .baseline = baseline,
            .line_height = line_height,
            .glyph_count = glyph_count,
            .codept_start = codept_start,
            .atlas_w = atlas_w,
            .atlas_h = atlas_h,
            .glyphs = @ptrCast(blob.ptr + glyphs_off),
            .pixels = blob.ptr + pixels_off,
        };
    }

    pub fn measure(self: FontAtlas, text: []const u8) u32 {
        var w: u32 = 0;
        for (text) |c| {
            if (c < self.codept_start) {
                if (c == ' ') {
                    const space_idx: u32 = @as(u32, ' ') - self.codept_start;
                    if (space_idx < self.glyph_count) {
                        const ax: i32 = self.glyphs[space_idx].ax;
                        if (ax > 0) w += @intCast(ax);
                    }
                }
                continue;
            }
            const idx: u32 = @as(u32, c) - self.codept_start;
            if (idx >= self.glyph_count) {
                w += self.size_px / 2;
                continue;
            }
            const ax: i32 = self.glyphs[idx].ax;
            if (ax > 0) w += @intCast(ax);
        }
        return w;
    }

    pub fn measureScaled(self: FontAtlas, text: []const u8, scale: u32) u32 {
        return self.measure(text) * scale;
    }
};

const blob_16: []const u8 align(2) = @embedFile("assets/font_16.bin");
const blob_24: []const u8 align(2) = @embedFile("assets/font_24.bin");

pub var default_16: FontAtlas = undefined;
pub var default_24: FontAtlas = undefined;

var initialized: bool = false;

pub fn ensureLoaded() void {
    if (initialized) return;
    default_16 = FontAtlas.parse(blob_16);
    default_24 = FontAtlas.parse(blob_24);
    initialized = true;
}

pub fn getDefault16() *const FontAtlas {
    ensureLoaded();
    return &default_16;
}

pub fn getDefault24() *const FontAtlas {
    ensureLoaded();
    return &default_24;
}

pub const Fb = struct {
    base: [*]volatile u32,
    stride: u32,
    w: u32,
    h: u32,
};

inline fn blendPixel(fb: Fb, px: i32, py: i32, color: u32, alpha: u8) void {
    if (px < 0 or py < 0) return;
    const upx: u32 = @intCast(px);
    const upy: u32 = @intCast(py);
    if (upx >= fb.w or upy >= fb.h) return;
    const off: usize = @as(usize, upy) * fb.stride + upx;
    if (alpha == 255) {
        fb.base[off] = color;
        return;
    }
    const a: u32 = alpha;
    const inv: u32 = 255 - a;
    const old = fb.base[off];
    const fg_r = (color >> 16) & 0xFF;
    const fg_g = (color >> 8) & 0xFF;
    const fg_b = color & 0xFF;
    const bg_r = (old >> 16) & 0xFF;
    const bg_g = (old >> 8) & 0xFF;
    const bg_b = old & 0xFF;
    const r = (fg_r * a + bg_r * inv) / 255;
    const g = (fg_g * a + bg_g * inv) / 255;
    const b = (fg_b * a + bg_b * inv) / 255;
    fb.base[off] = (r << 16) | (g << 8) | b;
}

pub fn drawText(fb: Fb, x: i32, y: i32, text: []const u8, color: u32, atlas: *const FontAtlas) void {
    var pen_x: i32 = x;
    for (text) |c| {
        if (c < atlas.codept_start) {
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
            pen_x += @as(i32, atlas.size_px / 2);
            continue;
        }
        const g = atlas.glyphs[idx];
        const glyph_top: i32 = y + g.by;
        const glyph_left: i32 = pen_x + g.bx;
        var gy: u32 = 0;
        while (gy < g.h) : (gy += 1) {
            const py = glyph_top + @as(i32, @intCast(gy));
            const row_in_atlas: u32 = @as(u32, g.atlas_y) + gy;
            const row_off: usize = @as(usize, row_in_atlas) * atlas.atlas_w;
            var gx: u32 = 0;
            while (gx < g.w) : (gx += 1) {
                const px = glyph_left + @as(i32, @intCast(gx));
                const a = atlas.pixels[row_off + g.atlas_x + gx];
                if (a == 0) continue;
                blendPixel(fb, px, py, color, a);
            }
        }
        pen_x += g.ax;
    }
}

/// Pixel-doubled (or larger) variant — each atlas pixel becomes a `scale*scale`
/// block in the framebuffer. Anti-aliasing is preserved because alpha values
/// are reused across the block. Used for the giant "ZIGOS" logo on the splash.
pub fn drawTextScaled(fb: Fb, x: i32, y: i32, text: []const u8, color: u32, atlas: *const FontAtlas, scale: u32) void {
    if (scale == 0) return;
    if (scale == 1) {
        drawText(fb, x, y, text, color, atlas);
        return;
    }
    var pen_x: i32 = x;
    const sc_i: i32 = @intCast(scale);
    for (text) |c| {
        if (c < atlas.codept_start) {
            if (c == ' ') {
                const space_idx: u32 = @as(u32, ' ') - atlas.codept_start;
                if (space_idx < atlas.glyph_count) {
                    pen_x += @as(i32, atlas.glyphs[space_idx].ax) * sc_i;
                }
            }
            continue;
        }
        const idx: u32 = @as(u32, c) - atlas.codept_start;
        if (idx >= atlas.glyph_count) {
            pen_x += @as(i32, atlas.size_px / 2) * sc_i;
            continue;
        }
        const g = atlas.glyphs[idx];
        const glyph_top: i32 = y + @as(i32, g.by) * sc_i;
        const glyph_left: i32 = pen_x + @as(i32, g.bx) * sc_i;
        var gy: u32 = 0;
        while (gy < g.h) : (gy += 1) {
            const row_in_atlas: u32 = @as(u32, g.atlas_y) + gy;
            const row_off: usize = @as(usize, row_in_atlas) * atlas.atlas_w;
            var gx: u32 = 0;
            while (gx < g.w) : (gx += 1) {
                const a = atlas.pixels[row_off + g.atlas_x + gx];
                if (a == 0) continue;
                // Splat alpha-`a` pixel across a scale*scale block.
                var dy: u32 = 0;
                while (dy < scale) : (dy += 1) {
                    var dx: u32 = 0;
                    while (dx < scale) : (dx += 1) {
                        const px = glyph_left + @as(i32, @intCast(gx)) * sc_i + @as(i32, @intCast(dx));
                        const py = glyph_top + @as(i32, @intCast(gy)) * sc_i + @as(i32, @intCast(dy));
                        blendPixel(fb, px, py, color, a);
                    }
                }
            }
        }
        pen_x += @as(i32, g.ax) * sc_i;
    }
}

/// Centered text in a horizontal box (`x..x+box_w`).
pub fn drawTextCentered(fb: Fb, x: i32, y: i32, box_w: u32, text: []const u8, color: u32, atlas: *const FontAtlas) void {
    const tw = atlas.measure(text);
    const inset: i32 = if (box_w > tw) @intCast((box_w - tw) / 2) else 0;
    drawText(fb, x + inset, y, text, color, atlas);
}
