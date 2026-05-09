// Tiny immediate-mode flow helpers — VStack + HStack — for the UEFI menu
// and About screen. The bootloader switched from a fixed-pitch bitmap font
// (16 px line height, 9 px advance) to anti-aliased SF Pro atlases (~20 px
// line, proportional advance), and every hand-tuned `panel_y + 56` style
// offset broke. These stacks let the caller declare a flow and the cursor
// walks through it, asking each row for its own intrinsic height (text
// rows pull `line_height` from the atlas; fixed-height items declare their
// own). Future font swaps don't trigger a layout audit.
//
// VStack: top-anchored vertical flow. Used inside the menu panel (title,
// accent line, HW info, crash banner, entries) and inside the About info
// panel (label/value rows).
//
// HStack: left-anchored horizontal flow. Used for the footer keycap row
// (Up/Dn ▸ move ▸ 1-4 ▸ jump ▸ Enter ▸ boot ▸ Esc ▸ skip).
//
// Right-aligned items (the auto-boot countdown "12s" tag, per-entry mode
// badges) stay absolute — they're one-offs that don't compose into a flow.
// Bottom-anchored items (countdown bar, footer row) compute their y from
// `panel_y + panel_h - N` directly; mixing them into a VStack would require
// reverse cursors and isn't worth the complexity for two call sites.

const std = @import("std");
const aa = @import("aa_font");

pub const Fb = aa.Fb;

fn fillRect(fb: Fb, x: u32, y: u32, w: u32, h: u32, color: u32) void {
    const x_end = @min(x + w, fb.w);
    const y_end = @min(y + h, fb.h);
    var yy: u32 = y;
    while (yy < y_end) : (yy += 1) {
        var xx: u32 = x;
        while (xx < x_end) : (xx += 1) {
            fb.base[yy * fb.stride + xx] = color;
        }
    }
}

fn drawBorder(fb: Fb, x: u32, y: u32, w: u32, h: u32, color: u32) void {
    fillRect(fb, x, y, w, 1, color);
    if (h >= 2) fillRect(fb, x, y + h - 1, w, 1, color);
    fillRect(fb, x, y, 1, h, color);
    if (w >= 2) fillRect(fb, x + w - 1, y, 1, h, color);
}

pub const VStack = struct {
    fb: Fb,
    x: u32,
    y: u32,
    w: u32,

    pub fn init(fb: Fb, x: u32, y: u32, w: u32) VStack {
        return .{ .fb = fb, .x = x, .y = y, .w = w };
    }

    pub fn cursor(self: *const VStack) u32 {
        return self.y;
    }

    pub fn gap(self: *VStack, px: u32) void {
        self.y += px;
    }

    pub fn skipTo(self: *VStack, target_y: u32) void {
        self.y = target_y;
    }

    /// Reserve `h` rows of vertical space for caller-drawn content. Returns
    /// the y at which the reservation begins; advances the cursor by `h`.
    /// Use for composite items (entry rows, custom widgets).
    pub fn reserve(self: *VStack, h: u32) u32 {
        const yy = self.y;
        self.y += h;
        return yy;
    }

    /// Left-aligned text. Cursor advances by `atlas.line_height`.
    pub fn text(self: *VStack, str: []const u8, color: u32, atlas: *const aa.FontAtlas) void {
        aa.drawText(self.fb, @intCast(self.x), @intCast(self.y), str, color, atlas);
        self.y += atlas.line_height;
    }

    /// Horizontally centered text within the stack's width.
    pub fn textCentered(self: *VStack, str: []const u8, color: u32, atlas: *const aa.FontAtlas) void {
        const tw = atlas.measure(str);
        const cx = self.x + (self.w -| tw) / 2;
        aa.drawText(self.fb, @intCast(cx), @intCast(self.y), str, color, atlas);
        self.y += atlas.line_height;
    }

    /// Centered scaled text (splash logo). Cursor advances by
    /// `atlas.size_px * scale` — the visual cell height of the
    /// pixel-doubled glyph.
    pub fn textScaledCentered(self: *VStack, str: []const u8, color: u32, atlas: *const aa.FontAtlas, scale: u32) void {
        const tw = atlas.measureScaled(str, scale);
        const cx = self.x + (self.w -| tw) / 2;
        aa.drawTextScaled(self.fb, @intCast(cx), @intCast(self.y), str, color, atlas, scale);
        self.y += atlas.size_px * scale;
    }

    /// Filled background row, optionally inset on both horizontal sides
    /// (use 0 for full-width). Cursor advances by `h`.
    pub fn fillRowInset(self: *VStack, inset: u32, h: u32, color: u32) void {
        fillRect(self.fb, self.x + inset, self.y, self.w -| 2 * inset, h, color);
        self.y += h;
    }

    /// 1-px horizontal accent rule. `inset` shrinks both ends.
    pub fn rule(self: *VStack, inset: u32, color: u32) void {
        fillRect(self.fb, self.x + inset, self.y, self.w -| 2 * inset, 1, color);
        self.y += 1;
    }

    /// Two-text row: dim label at `label_x` and bright value at `value_x`
    /// (both relative to the stack's left edge). Cursor advances by
    /// `atlas.line_height`. Used for the About-screen info table.
    pub fn kvRow(
        self: *VStack,
        label_x: u32,
        label: []const u8,
        label_color: u32,
        value_x: u32,
        value: []const u8,
        value_color: u32,
        atlas: *const aa.FontAtlas,
    ) void {
        aa.drawText(self.fb, @intCast(self.x + label_x), @intCast(self.y), label, label_color, atlas);
        aa.drawText(self.fb, @intCast(self.x + value_x), @intCast(self.y), value, value_color, atlas);
        self.y += atlas.line_height;
    }
};

pub const HStack = struct {
    fb: Fb,
    x: u32,
    y: u32,
    h: u32,

    pub fn init(fb: Fb, x: u32, y: u32, h: u32) HStack {
        return .{ .fb = fb, .x = x, .y = y, .h = h };
    }

    pub fn cursor(self: *const HStack) u32 {
        return self.x;
    }

    pub fn gap(self: *HStack, px: u32) void {
        self.x += px;
    }

    pub fn skipTo(self: *HStack, target_x: u32) void {
        self.x = target_x;
    }

    /// Vertically-centered label. Cursor advances by measured width.
    pub fn label(self: *HStack, str: []const u8, color: u32, atlas: *const aa.FontAtlas) void {
        const ty: u32 = self.y + (self.h -| atlas.line_height) / 2;
        aa.drawText(self.fb, @intCast(self.x), @intCast(ty), str, color, atlas);
        self.x += atlas.measure(str);
    }

    /// Bordered keycap pill: text + 6 px padding each side, full row height.
    /// Cursor advances by box width.
    pub fn keycap(
        self: *HStack,
        str: []const u8,
        fg: u32,
        bg: u32,
        border: u32,
        atlas: *const aa.FontAtlas,
    ) void {
        const tw = atlas.measure(str);
        const box_w = tw + 12;
        fillRect(self.fb, self.x, self.y, box_w, self.h, bg);
        drawBorder(self.fb, self.x, self.y, box_w, self.h, border);
        const ty: u32 = self.y + (self.h -| atlas.line_height) / 2;
        aa.drawText(self.fb, @intCast(self.x + 6), @intCast(ty), str, fg, atlas);
        self.x += box_w;
    }

    /// Solid-color badge pill: same shape as `keycap` but no border, used
    /// for entry mode tags (NORMAL / SAFE / VERBOSE / TESTS / INFO). The
    /// caller picks `bg` from the entry's badge_color and we use a fixed
    /// dark `fg` for contrast.
    pub fn badge(
        self: *HStack,
        str: []const u8,
        fg: u32,
        bg: u32,
        atlas: *const aa.FontAtlas,
    ) void {
        const tw = atlas.measure(str);
        const box_w = tw + 12;
        fillRect(self.fb, self.x, self.y, box_w, self.h, bg);
        const ty: u32 = self.y + (self.h -| atlas.line_height) / 2;
        aa.drawText(self.fb, @intCast(self.x + 6), @intCast(ty), str, fg, atlas);
        self.x += box_w;
    }
};
