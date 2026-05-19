// UI widgets for user-space apps (macOS-inspired)
//
// Theme model: `palette` is a RUNTIME-mutable struct instance (not the
// comptime block of consts it used to be). Existing `ui.palette.btn_default_top`
// access keeps working syntactically — it now reads from the live Palette
// instance that `setDarkMode(bool)` swaps. Apps that want to follow desktop
// theme call `ui.setDarkMode(...)` once at startup; everything else inside
// this module then renders in the chosen mode automatically.

const gfx = @import("graphics");
const fa = @import("font_atlas");
const libc = @import("libc");

pub const Canvas = gfx.Canvas;

/// Corner radius used by all card/panel surfaces (Dialog, FolderPicker,
/// ImagePicker, future card-style sections). macOS sits around 10-12 px
/// for sheets and panels; we use 10 because at lower DPI it reads as
/// "rounded" without eating too much usable area on small panels.
pub const PANEL_RADIUS: u32 = 10;

pub const Palette = struct {
    card_bg: u32,
    card_border: u32,
    card_shadow: u32,

    text_strong: u32,
    text_normal: u32,
    text_muted: u32,

    btn_default_top: u32,
    btn_default_bot: u32,
    btn_default_border: u32,

    btn_primary_top: u32,
    btn_primary_bot: u32,
    btn_primary_border: u32,

    btn_destructive_top: u32,
    btn_destructive_bot: u32,
    btn_destructive_border: u32,
};

pub const light_palette = Palette{
    .card_bg = 0xECECEC,
    .card_border = 0xB0B0B0,
    .card_shadow = 0x00000040,
    .text_strong = 0x1A1A1A,
    .text_normal = 0x3C3C3C,
    .text_muted = 0x7A7A7A,
    .btn_default_top = 0xFCFCFC,
    .btn_default_bot = 0xE2E2E2,
    .btn_default_border = 0xA8A8A8,
    .btn_primary_top = 0x4D9CFF,
    .btn_primary_bot = 0x0A6BE0,
    .btn_primary_border = 0x0857B8,
    .btn_destructive_top = 0xE05C50,
    .btn_destructive_bot = 0xB52E22,
    .btn_destructive_border = 0x8B1F16,
};

pub const dark_palette = Palette{
    .card_bg = 0x1F1F1F,
    .card_border = 0x3A3A3A,
    .card_shadow = 0x00000080,
    .text_strong = 0xF0F0F0,
    .text_normal = 0xCCCCCC,
    .text_muted = 0x808080,
    .btn_default_top = 0x4A4A4A,
    .btn_default_bot = 0x363636,
    .btn_default_border = 0x202020,
    // Primary blue stays vivid in dark mode but slightly desaturated.
    .btn_primary_top = 0x3A8AE6,
    .btn_primary_bot = 0x0852B8,
    .btn_primary_border = 0x063F8C,
    .btn_destructive_top = 0xCC4A40,
    .btn_destructive_bot = 0x991F18,
    .btn_destructive_border = 0x701008,
};

pub var palette: Palette = light_palette;

/// Switch the runtime palette. Call once at app startup if the user has
/// dark mode enabled in settings (read via libc.getConfig — eventual TODO,
/// for now apps either default to light or set explicitly).
pub fn setDarkMode(dark: bool) void {
    palette = if (dark) dark_palette else light_palette;
}

// --- Color helpers ---

pub fn lerpColor(top: u32, bot: u32, num: u32, den: u32) u32 {
    if (den == 0) return top;
    const tr: i32 = @intCast((top >> 16) & 0xFF);
    const tg: i32 = @intCast((top >> 8) & 0xFF);
    const tb: i32 = @intCast(top & 0xFF);
    const br: i32 = @intCast((bot >> 16) & 0xFF);
    const bg_: i32 = @intCast((bot >> 8) & 0xFF);
    const bb: i32 = @intCast(bot & 0xFF);
    const n: i32 = @intCast(num);
    const d: i32 = @intCast(den);
    const r: u32 = @intCast(tr + @divTrunc((br - tr) * n, d));
    const g: u32 = @intCast(tg + @divTrunc((bg_ - tg) * n, d));
    const b: u32 = @intCast(tb + @divTrunc((bb - tb) * n, d));
    return (r << 16) | (g << 8) | b;
}

pub fn verticalGradient(canvas: *Canvas, x: u32, y: u32, w: u32, h: u32, top: u32, bot: u32) void {
    var row: u32 = 0;
    while (row < h) : (row += 1) {
        canvas.fillRect(x, y + row, w, 1, lerpColor(top, bot, row, h));
    }
}

pub fn drawRect1px(canvas: *Canvas, x: u32, y: u32, w: u32, h: u32, color: u32) void {
    if (w == 0 or h == 0) return;
    canvas.drawHLine(x, y, w, color);
    canvas.drawHLine(x, y + h - 1, w, color);
    canvas.drawVLine(x, y, h, color);
    canvas.drawVLine(x + w - 1, y, h, color);
}

/// Soft drop shadow — 16-step Gaussian alpha falloff for right + bottom
/// edges plus a 2D Gaussian corner blob at the bottom-right. Uses real
/// src-over alpha blending so it composites correctly over any underlying
/// pixel, not just `surrounding_bg`.
///
/// Matches `src/ui/desktop.zig`'s window-shadow algorithm (alphas + curve)
/// so cards/dialogs visually agree with the window-manager drop shadow.
/// Asymmetric (no top/left shadow) — macOS-style "lit from upper-left"
/// rather than material-design all-around elevation.
///
/// `surrounding_bg` is kept for API compatibility but unused — real alpha
/// blending samples the actual destination pixel, so the caller's bg
/// assumption no longer matters.
pub fn drawShadow(canvas: *Canvas, x: u32, y: u32, w: u32, h: u32, surrounding_bg: u32) void {
    _ = surrounding_bg;
    const SHADOW_W: u32 = 16;
    // Peak ~7.8% — kept in sync with src/ui/desktop.zig's window-manager
    // shadow so in-app cards visually agree with the surrounding window
    // frame. Old peak 0x28 was too inky on small surfaces.
    const SHADOW_MAX: u32 = 0x14;
    const shadow_alphas = [SHADOW_W]u8{
        0x14, 0x12, 0x10, 0x0D, 0x0B, 0x09, 0x07, 0x05,
        0x04, 0x03, 0x02, 0x02, 0x01, 0x01, 0x01, 0x01,
    };

    // Bottom edge — horizontal rows below the rect, full width. The corner
    // blob below will reinforce the bottom-right joint so the corner doesn't
    // look hollow vs the straight edges.
    var si: u32 = 0;
    while (si < SHADOW_W) : (si += 1) {
        const row_y = y + h + si;
        if (row_y >= canvas.height) break;
        const max_w = canvas.width -| x;
        canvas.fillRectAlpha(x, row_y, @min(w, max_w), 1, 0x000000, shadow_alphas[si]);
    }
    // Right edge — vertical cols to the right of the rect, full height.
    si = 0;
    while (si < SHADOW_W) : (si += 1) {
        const col_x = x + w + si;
        if (col_x >= canvas.width) break;
        const max_h = canvas.height -| y;
        canvas.fillRectAlpha(col_x, y, 1, @min(h, max_h), 0x000000, shadow_alphas[si]);
    }
    // Bottom-right corner — 2D Gaussian. Divide by SHADOW_MAX (not 255) so
    // corner darkness matches edge darkness at equal distance from the rect,
    // producing a continuous round shadow instead of a too-light hollow.
    var sy: u32 = 0;
    while (sy < SHADOW_W) : (sy += 1) {
        var sx: u32 = 0;
        while (sx < SHADOW_W) : (sx += 1) {
            const a_combined: u32 = (@as(u32, shadow_alphas[sx]) * @as(u32, shadow_alphas[sy])) / SHADOW_MAX;
            if (a_combined == 0) continue;
            const px = x + w + sx;
            const py = y + h + sy;
            canvas.blendPixel(@intCast(px), @intCast(py), 0x000000, @intCast(a_combined));
        }
    }
}

/// Draw a focus ring 2px outside the rect — a single-pixel outline in the
/// primary color, with a 1px gap so it doesn't merge into the widget's
/// own border. Use for keyboard-focused widgets so users can see where
/// Tab will commit.
pub fn drawFocusRing(canvas: *Canvas, x: u32, y: u32, w: u32, h: u32, color: u32) void {
    if (x < 2 or y < 2) return;
    drawRect1px(canvas, x - 2, y - 2, w + 4, h + 4, color);
}

// --- Button ---

pub const ButtonStyle = enum { default, primary, destructive };

/// Visual state. `update()` flips this each frame from mouse position +
/// button-held flags; apps drawing without calling update() see `.normal`
/// (so old code paths stay visually identical to before this change).
pub const ButtonState = enum { normal, hover, pressed, disabled };

pub const Button = struct {
    x: u32,
    y: u32,
    w: u32,
    h: u32,
    label: []const u8,
    state: ButtonState = .normal,
    enabled: bool = true,

    pub fn contains(self: Button, mx: i32, my: i32) bool {
        const x: i32 = @intCast(self.x);
        const y: i32 = @intCast(self.y);
        return mx >= x and mx < x + @as(i32, @intCast(self.w)) and
            my >= y and my < y + @as(i32, @intCast(self.h));
    }

    /// Pump mouse state into the button. Returns true on the frame where a
    /// click completes (release inside bounds after a press inside bounds).
    /// `left_now` is the current frame's mouse-button-down flag; `left_prev`
    /// is the previous frame's. Callers track prev_left themselves — a
    /// pattern already used everywhere by readChar/getMouse.
    ///
    /// Standard "press, then release while still over the target = click"
    /// semantics. Drag-off cancels (release outside = no click).
    pub fn update(self: *Button, mx: i32, my: i32, left_now: bool, left_prev: bool) bool {
        if (!self.enabled) {
            self.state = .disabled;
            return false;
        }
        const inside = self.contains(mx, my);
        if (left_now and inside) {
            self.state = .pressed;
        } else if (inside) {
            self.state = .hover;
        } else {
            self.state = .normal;
        }
        // Click fires on the falling edge of left_now while still inside.
        return inside and !left_now and left_prev;
    }

    pub fn draw(self: Button, canvas: *Canvas, color: u32, text_color: u32) void {
        canvas.fillRect(self.x, self.y, self.w, self.h, color);
        const atlas = fa.getDefault16();
        const line_h: u32 = atlas.line_height;
        const y_top: i32 = @intCast(self.y + (self.h -| line_h) / 2);
        fa.drawTextCentered(canvas, @intCast(self.x), y_top, self.w, self.label, text_color, atlas);
    }

    pub fn drawRounded(self: Button, canvas: *Canvas, color: u32, text_color: u32, bg: u32) void {
        self.draw(canvas, color, text_color);
        canvas.roundCornersRadius(self.x, self.y, self.w, self.h, buttonRadius(self.h), bg);
    }

    /// macOS-style pill: vertical gradient + 1px border + rounded corners. `bg` is
    /// the surrounding color used to clip the corner pixels (so the pill blends in).
    /// Visual state (hover/pressed/disabled) is read from `self.state`.
    pub fn drawStyled(self: Button, canvas: *Canvas, style: ButtonStyle, bg: u32) void {
        var top: u32 = switch (style) {
            .default => palette.btn_default_top,
            .primary => palette.btn_primary_top,
            .destructive => palette.btn_destructive_top,
        };
        var bot: u32 = switch (style) {
            .default => palette.btn_default_bot,
            .primary => palette.btn_primary_bot,
            .destructive => palette.btn_destructive_bot,
        };
        const border: u32 = switch (style) {
            .default => palette.btn_default_border,
            .primary => palette.btn_primary_border,
            .destructive => palette.btn_destructive_border,
        };
        var text_color: u32 = switch (style) {
            .default => palette.text_normal,
            .primary, .destructive => 0xFFFFFF,
        };

        // State adjustment. `hover` lightens top/bot; `pressed` swaps + darkens
        // (the inversion gives the "depressed inward" feel without needing a
        // separate inset shadow). `disabled` washes everything toward card_bg.
        switch (self.state) {
            .normal => {},
            .hover => {
                top = lerpColor(top, 0xFFFFFF, 1, 8);
                bot = lerpColor(bot, 0xFFFFFF, 1, 10);
            },
            .pressed => {
                const tmp = top;
                top = lerpColor(bot, 0x000000, 1, 12);
                bot = lerpColor(tmp, 0x000000, 1, 16);
            },
            .disabled => {
                top = lerpColor(top, palette.card_bg, 3, 5);
                bot = lerpColor(bot, palette.card_bg, 3, 5);
                text_color = palette.text_muted;
            },
        }

        verticalGradient(canvas, self.x, self.y, self.w, self.h, top, bot);
        drawRect1px(canvas, self.x, self.y, self.w, self.h, border);
        // Subtle highlight on top edge (1px lighter line just below the border).
        // Skipped on `pressed` so the inversion reads cleanly.
        if (self.h > 4 and self.state != .pressed) {
            canvas.drawHLine(self.x + 1, self.y + 1, self.w -| 2, lerpColor(top, 0xFFFFFF, 1, 3));
        }
        const atlas = fa.getDefault16();
        const text_y = self.y + (self.h -| atlas.line_height) / 2;
        // `pressed` nudges the label 1px down for a tactile feel.
        const label_y = if (self.state == .pressed) text_y + 1 else text_y;
        fa.drawTextCentered(canvas, @intCast(self.x), @intCast(label_y), self.w, self.label, text_color, atlas);
        canvas.roundCornersRadius(self.x, self.y, self.w, self.h, buttonRadius(self.h), bg);
    }
};

/// Pick a corner radius that scales with the button height. macOS uses
// --- Card ---
//
// macOS Settings-style rounded panel. Apps group related controls inside
// a Card with a section label above it. The Card paints the background
// + rounded corners; the caller positions controls inside the card area
// using HPAD/VPAD insets.
//
// Hairlines are optional dividers between rows within a card — use when
// the card holds multiple logical rows that should read as separate.
//
// Buttons drawn INSIDE a card should pass `palette.card_bg` as their
// corner-clip bg (not the window bg), or the AA corner pixels will
// blend toward the wrong color and look fringey against the card.

pub const Card = struct {
    x: u32,
    y: u32,
    w: u32,
    h: u32,

    pub const HPAD: u32 = 14;
    pub const VPAD: u32 = 12;

    pub fn drawBg(self: Card, canvas: *Canvas, surrounding_bg: u32) void {
        canvas.fillRect(self.x, self.y, self.w, self.h, palette.card_bg);
        canvas.roundCornersRadius(self.x, self.y, self.w, self.h, PANEL_RADIUS, surrounding_bg);
    }

    /// 1-px hairline divider at absolute y, inset by HPAD on both sides.
    /// Use between rows inside a card that holds multiple logical sections.
    pub fn hairline(self: Card, canvas: *Canvas, y: u32) void {
        canvas.fillRect(self.x + HPAD, y, self.w -| 2 * HPAD, 1, palette.card_border);
    }

    /// X coordinate for content inset on the left edge.
    pub fn innerX(self: Card) u32 {
        return self.x + HPAD;
    }

    /// X coordinate for right-anchored content of width `w`.
    pub fn innerRightX(self: Card, w: u32) u32 {
        return self.x + self.w -| HPAD -| w;
    }
};

/// ~6 px on a 24 px button and ~8-10 px on larger ones. We cap at 10 so
/// big call-to-action buttons don't go pill-shaped.
inline fn buttonRadius(h: u32) u32 {
    return @min(@max(h / 4, 4), 10);
}

// --- Checkbox ---
//
// 14x14 box, optional 'X' on check. Renders next to its own label so apps
// don't have to lay out the text separately. State (hover/pressed) follows
// the same model as Button.

pub const Checkbox = struct {
    x: u32,
    y: u32,
    label: []const u8,
    checked: bool = false,
    state: ButtonState = .normal,
    enabled: bool = true,

    pub const SIZE: u32 = 14;
    pub const LABEL_GAP: u32 = 8;

    pub fn contains(self: Checkbox, mx: i32, my: i32) bool {
        const x: i32 = @intCast(self.x);
        const y: i32 = @intCast(self.y);
        // Clickable region spans box + label so the label is also a target.
        const total_w: i32 = @intCast(SIZE + LABEL_GAP + self.label.len * Canvas.CW16);
        return mx >= x and mx < x + total_w and
            my >= y and my < y + @as(i32, @intCast(SIZE));
    }

    pub fn update(self: *Checkbox, mx: i32, my: i32, left_now: bool, left_prev: bool) bool {
        if (!self.enabled) {
            self.state = .disabled;
            return false;
        }
        const inside = self.contains(mx, my);
        if (left_now and inside) {
            self.state = .pressed;
        } else if (inside) {
            self.state = .hover;
        } else {
            self.state = .normal;
        }
        const clicked = inside and !left_now and left_prev;
        if (clicked) self.checked = !self.checked;
        return clicked;
    }

    pub fn draw(self: Checkbox, canvas: *Canvas, bg: u32) void {
        // Box: filled card_bg + border that brightens on hover, blue when checked.
        const fill: u32 = if (self.checked)
            (if (self.state == .pressed) palette.btn_primary_bot else palette.btn_primary_top)
        else if (self.state == .pressed)
            lerpColor(palette.card_bg, 0x000000, 1, 12)
        else
            palette.card_bg;
        const border: u32 = if (self.checked)
            palette.btn_primary_border
        else if (self.state == .hover or self.state == .pressed)
            palette.text_normal
        else
            palette.card_border;

        canvas.fillRect(self.x, self.y, SIZE, SIZE, fill);
        drawRect1px(canvas, self.x, self.y, SIZE, SIZE, border);

        if (self.checked) {
            // Simple ✓ — two diagonal strokes inside the box.
            const cx = self.x + 3;
            const cy = self.y + 7;
            // Stroke 1: down-right (3px)
            canvas.drawHLine(cx, cy, 1, 0xFFFFFF);
            canvas.drawHLine(cx + 1, cy + 1, 1, 0xFFFFFF);
            canvas.drawHLine(cx + 2, cy + 2, 1, 0xFFFFFF);
            // Stroke 2: up-right (5px)
            canvas.drawHLine(cx + 3, cy + 1, 1, 0xFFFFFF);
            canvas.drawHLine(cx + 4, cy, 1, 0xFFFFFF);
            canvas.drawHLine(cx + 5, cy - 1, 1, 0xFFFFFF);
            canvas.drawHLine(cx + 6, cy - 2, 1, 0xFFFFFF);
            canvas.drawHLine(cx + 7, cy - 3, 1, 0xFFFFFF);
        }

        const text_color = if (self.enabled) palette.text_normal else palette.text_muted;
        // AA label sits on the same row as the box. Atlas line_height is
        // slightly taller than the box; centering pulls it back into line.
        const atlas = fa.getDefault16();
        const label_y_top: i32 = @as(i32, @intCast(self.y)) - @divTrunc(@as(i32, @intCast(atlas.line_height)) - @as(i32, @intCast(SIZE)), 2);
        fa.drawText(canvas, @intCast(self.x + SIZE + LABEL_GAP), label_y_top, self.label, text_color, atlas);
        _ = bg;
    }
};

// --- Toggle (iOS-style switch) ---
//
// Wider than Checkbox; the thumb slides between two positions. Useful for
// binary settings where the on/off state is more prominent than a discrete
// "tick" — themes, dock visibility, mute, etc.

pub const Toggle = struct {
    x: u32,
    y: u32,
    on: bool = false,
    state: ButtonState = .normal,
    enabled: bool = true,

    pub const W: u32 = 36;
    pub const H: u32 = 20;
    pub const THUMB_PAD: u32 = 2;

    pub fn contains(self: Toggle, mx: i32, my: i32) bool {
        const x: i32 = @intCast(self.x);
        const y: i32 = @intCast(self.y);
        return mx >= x and mx < x + @as(i32, @intCast(W)) and
            my >= y and my < y + @as(i32, @intCast(H));
    }

    pub fn update(self: *Toggle, mx: i32, my: i32, left_now: bool, left_prev: bool) bool {
        if (!self.enabled) {
            self.state = .disabled;
            return false;
        }
        const inside = self.contains(mx, my);
        if (left_now and inside) {
            self.state = .pressed;
        } else if (inside) {
            self.state = .hover;
        } else {
            self.state = .normal;
        }
        const clicked = inside and !left_now and left_prev;
        if (clicked) self.on = !self.on;
        return clicked;
    }

    pub fn draw(self: Toggle, canvas: *Canvas, bg: u32) void {
        // Track: blue gradient when on, grey when off. Full pill shape —
        // radius = H/2 rounds it into the macOS toggle look (was a
        // 1px-chamfer rect before).
        const track_top: u32 = if (self.on) palette.btn_primary_top else palette.btn_default_top;
        const track_bot: u32 = if (self.on) palette.btn_primary_bot else palette.btn_default_bot;
        const lit_top = if (self.state == .hover) lerpColor(track_top, 0xFFFFFF, 1, 8) else track_top;
        const lit_bot = if (self.state == .hover) lerpColor(track_bot, 0xFFFFFF, 1, 10) else track_bot;
        verticalGradient(canvas, self.x, self.y, W, H, lit_top, lit_bot);
        drawRect1px(canvas, self.x, self.y, W, H, if (self.on) palette.btn_primary_border else palette.btn_default_border);
        canvas.roundCornersRadius(self.x, self.y, W, H, H / 2, bg);

        // Thumb: white circle that slides between left and right. Radius
        // = thumb_d/2 makes it a true circle with AA edge against the
        // (gradient) track behind it.
        const thumb_d: u32 = H - THUMB_PAD * 2;
        const thumb_y = self.y + THUMB_PAD;
        const thumb_x = if (self.on) self.x + W - THUMB_PAD - thumb_d else self.x + THUMB_PAD;
        canvas.fillRect(thumb_x, thumb_y, thumb_d, thumb_d, 0xFFFFFF);
        canvas.roundCornersRadius(thumb_x, thumb_y, thumb_d, thumb_d, thumb_d / 2, lit_top);
    }
};

// --- Scrollbar ---
//
// Vertical thumb-on-track. Stateless re: the data — apps own
// `scroll_offset` and `content_total`/`content_visible`; Scrollbar reads
// them on draw and writes via the `*scroll_offset` pointer in update().
// Thumb height is `track_h * visible / total` clamped to a min of 20px so
// it stays grabbable on huge lists.

pub const ScrollbarState = enum { normal, hover, dragging };

pub const Scrollbar = struct {
    x: u32,
    y: u32,
    w: u32,
    h: u32,
    state: ScrollbarState = .normal,
    /// Offset from thumb top to mouse_y at drag start. Sticks the thumb to
    /// the cursor so it doesn't jump on click. Unused while not dragging.
    drag_offset: i32 = 0,
    // Internal mouse-state cache for `handleEvent`. Updated from
    // mouse_move / mouse_button events; used to drive drag + page-click
    // logic. `update()` (the legacy externally-fed entry point) bypasses
    // these and uses the caller's mx/my/buttons instead.
    cur_mx: i32 = 0,
    cur_my: i32 = 0,
    cur_left: bool = false,
    prev_left: bool = false,
    /// Lines per wheel notch. 3 matches the desktop's terminal scrollback
    /// step. Apps can override after construction (e.g. text editor with
    /// taller line-height may want 1).
    lines_per_notch: u32 = 3,

    fn thumbBounds(self: Scrollbar, content_total: u32, content_visible: u32, scroll_offset: u32) struct { y: u32, h: u32 } {
        if (content_total <= content_visible or content_total == 0) {
            return .{ .y = self.y, .h = self.h };
        }
        var thumb_h: u32 = self.h * content_visible / content_total;
        if (thumb_h < 20) thumb_h = 20;
        if (thumb_h > self.h) thumb_h = self.h;
        const max_offset = content_total - content_visible;
        const free_track = self.h - thumb_h;
        const thumb_y = self.y + free_track * scroll_offset / max_offset;
        return .{ .y = thumb_y, .h = thumb_h };
    }

    pub fn update(
        self: *Scrollbar,
        mx: i32,
        my: i32,
        left_now: bool,
        left_prev: bool,
        content_total: u32,
        content_visible: u32,
        scroll_offset: *u32,
    ) void {
        // No scrollbar needed — clamp and bail.
        if (content_total <= content_visible) {
            self.state = .normal;
            scroll_offset.* = 0;
            return;
        }

        const tb = self.thumbBounds(content_total, content_visible, scroll_offset.*);
        const tb_y_i: i32 = @intCast(tb.y);
        const tb_h_i: i32 = @intCast(tb.h);
        const x_i: i32 = @intCast(self.x);
        const w_i: i32 = @intCast(self.w);
        const inside_thumb = mx >= x_i and mx < x_i + w_i and
            my >= tb_y_i and my < tb_y_i + tb_h_i;
        const inside_track = mx >= x_i and mx < x_i + w_i and
            my >= @as(i32, @intCast(self.y)) and my < @as(i32, @intCast(self.y + self.h));

        const max_offset = content_total - content_visible;
        const free_track: i32 = @intCast(self.h - tb.h);

        const press_edge = left_now and !left_prev;
        const release_edge = !left_now and left_prev;

        switch (self.state) {
            .normal, .hover => {
                self.state = if (inside_thumb) .hover else .normal;
                if (press_edge and inside_thumb) {
                    self.state = .dragging;
                    self.drag_offset = my - tb_y_i;
                } else if (press_edge and inside_track) {
                    // Page-jump: clicked on track but not thumb — move toward
                    // the cursor by one visible window.
                    if (my < tb_y_i) {
                        scroll_offset.* = if (scroll_offset.* > content_visible) scroll_offset.* - content_visible else 0;
                    } else {
                        scroll_offset.* = @min(scroll_offset.* + content_visible, max_offset);
                    }
                }
            },
            .dragging => {
                if (release_edge or !left_now) {
                    self.state = if (inside_thumb) .hover else .normal;
                    return;
                }
                if (free_track <= 0) return;
                const new_thumb_y_i = my - self.drag_offset;
                const y_i: i32 = @intCast(self.y);
                var pos = new_thumb_y_i - y_i;
                if (pos < 0) pos = 0;
                if (pos > free_track) pos = free_track;
                scroll_offset.* = @intCast(@divTrunc(@as(i64, pos) * @as(i64, max_offset), @as(i64, free_track)));
            },
        }
    }

    /// Single-call event dispatcher: drain a window event and translate it
    /// into scrollbar interaction. Returns `true` iff `scroll_offset`
    /// changed (the caller should set `needs_redraw`). Handles:
    ///   * mouse_wheel  → `lines_per_notch` lines per notch, clamped.
    ///   * mouse_move   → drag-thumb tracking + hover state.
    ///   * mouse_button → press = drag start / page-jump; release = stop.
    /// Other event kinds are ignored. Apps that have only a scrollbar (no
    /// other clickable widgets) can drop their own mouse-state plumbing
    /// entirely and call this for every `pollEvent`.
    pub fn handleEvent(
        self: *Scrollbar,
        ev: libc.Event,
        content_total: u32,
        content_visible: u32,
        scroll_offset: *u32,
    ) bool {
        const old = scroll_offset.*;
        switch (ev.kindOf()) {
            .mouse_move => {
                self.cur_mx = @bitCast(ev.a);
                self.cur_my = @bitCast(ev.b);
                self.cur_left = (ev.c & 1) != 0;
                self.update(self.cur_mx, self.cur_my, self.cur_left, self.prev_left, content_total, content_visible, scroll_offset);
                self.prev_left = self.cur_left;
            },
            .mouse_button => {
                if (ev.buttonIndex() == 0) {
                    self.cur_mx = @bitCast(ev.b);
                    self.cur_my = @bitCast(ev.c);
                    const new_left = ev.buttonPressed();
                    self.update(self.cur_mx, self.cur_my, new_left, self.prev_left, content_total, content_visible, scroll_offset);
                    self.prev_left = new_left;
                    self.cur_left = new_left;
                }
            },
            .mouse_wheel => {
                if (content_total > content_visible) {
                    const max_offset = content_total - content_visible;
                    const delta: i32 = @bitCast(ev.a);
                    const lines = @as(i32, @intCast(self.lines_per_notch));
                    if (delta > 0) {
                        const step: u32 = @intCast(delta * lines);
                        scroll_offset.* = if (old > step) old - step else 0;
                    } else if (delta < 0) {
                        const step: u32 = @intCast(-delta * lines);
                        scroll_offset.* = @min(old + step, max_offset);
                    }
                }
            },
            else => {},
        }
        return scroll_offset.* != old;
    }

    pub fn draw(
        self: Scrollbar,
        canvas: *Canvas,
        content_total: u32,
        content_visible: u32,
        scroll_offset: u32,
    ) void {
        // Track — slightly darker than card_bg.
        const track_color = lerpColor(palette.card_bg, 0x000000, 1, 8);
        canvas.fillRect(self.x, self.y, self.w, self.h, track_color);

        // No thumb if everything fits.
        if (content_total <= content_visible) return;

        const tb = self.thumbBounds(content_total, content_visible, scroll_offset);
        const thumb_color: u32 = switch (self.state) {
            .normal => lerpColor(palette.card_border, 0x000000, 1, 8),
            .hover => palette.text_muted,
            .dragging => palette.btn_primary_top,
        };
        canvas.fillRect(self.x + 1, tb.y, self.w -| 2, tb.h, thumb_color);
    }
};

// --- TextInput ---
//
// Single-line text field. Caller owns the storage `buf` and pumps:
//   - mouse position + left button state (for focus + cursor placement)
//   - one character per frame (from libc.readChar()) — 0 = none
//
// Returns `TextInputEvent { changed, submitted }`. `submitted` is set on
// Enter; the app then reads `buf[0..buf_len]`. The widget never grows the
// buffer — drops chars when at capacity.

pub const TextInputEvent = struct {
    changed: bool = false,
    submitted: bool = false,
};

pub const TextInput = struct {
    x: u32,
    y: u32,
    w: u32,
    h: u32,
    /// Caller-owned mutable storage. Capacity = buf.len.
    buf: []u8,
    buf_len: u32 = 0,
    cursor: u32 = 0,
    focused: bool = false,
    state: ButtonState = .normal,
    enabled: bool = true,

    pub fn contains(self: TextInput, mx: i32, my: i32) bool {
        const x: i32 = @intCast(self.x);
        const y: i32 = @intCast(self.y);
        return mx >= x and mx < x + @as(i32, @intCast(self.w)) and
            my >= y and my < y + @as(i32, @intCast(self.h));
    }

    pub fn update(self: *TextInput, mx: i32, my: i32, left_now: bool, left_prev: bool, ch: u8) TextInputEvent {
        var ev: TextInputEvent = .{};
        if (!self.enabled) {
            self.state = .disabled;
            return ev;
        }
        const inside = self.contains(mx, my);
        const press_edge = left_now and !left_prev;
        if (press_edge) {
            self.focused = inside;
        }
        self.state = if (self.focused) .pressed else if (inside) .hover else .normal;

        if (!self.focused or ch == 0) return ev;

        // Backspace (0x08) — delete one char before cursor.
        if (ch == 0x08) {
            if (self.cursor > 0) {
                std.mem.copyForwards(u8, self.buf[self.cursor - 1 .. self.buf_len - 1], self.buf[self.cursor..self.buf_len]);
                self.cursor -= 1;
                self.buf_len -= 1;
                ev.changed = true;
            }
            return ev;
        }
        // Enter (\n or \r) — submit.
        if (ch == '\n' or ch == '\r') {
            ev.submitted = true;
            return ev;
        }
        // ESC — leave focused. Caller can also handle the global ESC.
        if (ch == 0x1B) {
            self.focused = false;
            return ev;
        }
        // Printable.
        if (ch >= 0x20 and ch < 0x7F and self.buf_len < self.buf.len) {
            std.mem.copyBackwards(u8, self.buf[self.cursor + 1 .. self.buf_len + 1], self.buf[self.cursor..self.buf_len]);
            self.buf[self.cursor] = ch;
            self.cursor += 1;
            self.buf_len += 1;
            ev.changed = true;
        }
        return ev;
    }

    pub fn draw(self: TextInput, canvas: *Canvas, bg: u32, caret_visible: bool) void {
        _ = bg; // reserved for future use (rounded-corner blend); keep for API stability
        // Field background — slightly inset look (darker than card_bg).
        const fill = if (self.enabled) lerpColor(palette.card_bg, 0xFFFFFF, 1, 4) else palette.card_bg;
        canvas.fillRect(self.x, self.y, self.w, self.h, fill);
        const border = switch (self.state) {
            .pressed => palette.btn_primary_border,
            .hover => palette.text_muted,
            else => palette.card_border,
        };
        drawRect1px(canvas, self.x, self.y, self.w, self.h, border);
        // Subtle inset shadow on top.
        if (self.h > 4) {
            canvas.drawHLine(self.x + 1, self.y + 1, self.w -| 2, lerpColor(fill, 0x000000, 1, 16));
        }
        const text_color = if (self.enabled) palette.text_normal else palette.text_muted;
        const atlas = fa.getDefault16();
        const text_y = self.y + (self.h -| atlas.line_height) / 2;
        const text_x = self.x + 6;
        fa.drawText(canvas, @intCast(text_x), @intCast(text_y), self.buf[0..self.buf_len], text_color, atlas);

        // Caret — single vertical line at cursor position. Caller toggles
        // `caret_visible` for blinking (e.g. (tick / 30) & 1 == 0). With AA
        // glyphs the caret X comes from measuring the prefix, not from a
        // fixed CW assumption.
        if (self.focused and caret_visible) {
            const prefix_w = atlas.measure(self.buf[0..self.cursor]);
            const cx = text_x + prefix_w;
            canvas.drawVLine(cx, text_y, atlas.line_height, palette.text_strong);
        }
    }
};

const std = @import("std");

// --- ProgressBar ---

pub const ProgressBar = struct {
    x: u32,
    y: u32,
    w: u32,
    h: u32,
    bg_color: u32,
    fill_color: u32,
    border_color: u32,

    pub fn draw(self: ProgressBar, canvas: *Canvas, value: u32, max: u32) void {
        canvas.fillRect(self.x, self.y, self.w, self.h, self.bg_color);
        if (max > 0) {
            const fill_w = value * self.w / max;
            canvas.fillRect(self.x, self.y, fill_w, self.h, self.fill_color);
        }
        canvas.drawHLine(self.x, self.y, self.w, self.border_color);
        if (self.h > 1) canvas.drawHLine(self.x, self.y + self.h - 1, self.w, self.border_color);
    }
};

// --- Dialog ---

pub const DialogResult = enum { none, primary, secondary };

/// macOS-style modal alert. Caller computes layout once with `init`, then calls
/// `draw` each frame and `hit` on each click.
pub const Dialog = struct {
    x: u32,
    y: u32,
    w: u32,
    h: u32,
    title: []const u8,
    body: []const u8,
    primary_label: []const u8,
    secondary_label: []const u8,
    destructive: bool,
    primary_btn: Button,
    secondary_btn: Button,

    pub const padding: u32 = 18;
    pub const btn_w: u32 = 90;
    pub const btn_h: u32 = 28;
    pub const btn_gap: u32 = 10;

    pub fn init(
        canvas_w: u32,
        canvas_h: u32,
        title: []const u8,
        body: []const u8,
        primary_label: []const u8,
        secondary_label: []const u8,
        destructive: bool,
    ) Dialog {
        const w: u32 = @min(canvas_w -| 40, 360);
        const h: u32 = padding + Canvas.CH16 + 12 + Canvas.CH16 + 18 + btn_h + padding;
        const x = (canvas_w -| w) / 2;
        const y = (canvas_h -| h) / 3;

        const btn_y = y + h - padding - btn_h;
        const primary_x = x + w - padding - btn_w;
        const secondary_x = primary_x -| (btn_w + btn_gap);

        return .{
            .x = x,
            .y = y,
            .w = w,
            .h = h,
            .title = title,
            .body = body,
            .primary_label = primary_label,
            .secondary_label = secondary_label,
            .destructive = destructive,
            .primary_btn = .{ .x = primary_x, .y = btn_y, .w = btn_w, .h = btn_h, .label = primary_label },
            .secondary_btn = .{ .x = secondary_x, .y = btn_y, .w = btn_w, .h = btn_h, .label = secondary_label },
        };
    }

    pub fn draw(self: Dialog, canvas: *Canvas, surrounding_bg: u32) void {
        // Drop shadow via the shared helper (3-layer). Replaces the
        // hardcoded 0xC8/D8/E4 stack; now follows the chosen palette so
        // dark mode dialogs get a darker shadow that reads correctly.
        drawShadow(canvas, self.x, self.y, self.w, self.h, surrounding_bg);

        // Card body
        canvas.fillRect(self.x, self.y, self.w, self.h, palette.card_bg);
        drawRect1px(canvas, self.x, self.y, self.w, self.h, palette.card_border);
        canvas.roundCornersRadius(self.x, self.y, self.w, self.h, PANEL_RADIUS, surrounding_bg);

        // Title
        const atlas = fa.getDefault16();
        const title_y = self.y + Dialog.padding;
        fa.drawTextCentered(canvas, @intCast(self.x), @intCast(title_y), self.w, self.title, palette.text_strong, atlas);

        // Body
        const body_y = title_y + atlas.line_height + 12;
        fa.drawTextCentered(canvas, @intCast(self.x), @intCast(body_y), self.w, self.body, palette.text_muted, atlas);

        // Buttons
        const primary_style: ButtonStyle = if (self.destructive) .destructive else .primary;
        self.secondary_btn.drawStyled(canvas, .default, palette.card_bg);
        self.primary_btn.drawStyled(canvas, primary_style, palette.card_bg);
    }

    pub fn hit(self: Dialog, mx: i32, my: i32) DialogResult {
        if (self.primary_btn.contains(mx, my)) return .primary;
        if (self.secondary_btn.contains(mx, my)) return .secondary;
        return .none;
    }
};

// --- Folder picker --------------------------------------------------------

pub const FolderPickerAction = enum {
    /// Nothing happened this frame. Default each frame.
    none,
    /// User clicked the Cancel button (or pressed Esc — caller forwards
    /// the key). App should `dismiss()` the picker.
    cancel,
    /// User clicked the OK button with a directory selected. App should
    /// read `currentPath()` and `dismiss()`.
    ok,
    /// User clicked a directory in the list (or pressed Enter on the
    /// selected row). Picker has already navigated into it — nothing for
    /// caller to do beyond marking the window dirty for the next frame.
    navigated,
};

/// Modal-overlay folder browser, same caller-owned-state pattern as
/// `Dialog`. App init's once, calls `draw(canvas, bg)` every frame while
/// the picker is up, and feeds clicks to `handleClick(mx, my, left_now,
/// left_prev)`. Returns `FolderPickerAction.ok` once the user has
/// confirmed; caller then reads `currentPath()` and dismisses.
///
/// Filesystem access is via `libc.readdir` — works against ext2, fat32,
/// and tarfs uniformly. The picker only shows directory entries (filters
/// on `FE_FLAG_IS_DIR`); files are hidden because the use case is "pick
/// where to read/write from", not "pick a file".
///
/// Backing arrays live inline so callers can keep the picker on the
/// stack or as a struct field without managing allocations.
pub const FolderPicker = struct {
    x: u32,
    y: u32,
    w: u32,
    h: u32,
    title: []const u8,

    /// Current directory we're browsing, NUL-paddable absolute path.
    path_buf: [256]u8,
    path_len: u32,

    /// Subdirectory entries inside `path_buf`. Capped at MAX_ENTRIES;
    /// directories beyond that are silently dropped. Boot ZigOS root
    /// has ~10 entries so this is plenty for a long time.
    entries: [MAX_ENTRIES]libc.FileEntry,
    entry_count: u32,
    /// Index into `entries[]` of the highlighted row, or -1 if no
    /// selection yet. Drives the "OK uses this directory" decision —
    /// when -1, OK picks `path_buf` itself (i.e., the directory the
    /// list is showing).
    selected: i32,
    /// Scroll offset (in rows). Bumped when the keyboard or list-click
    /// moves the selection off the visible window.
    scroll: u32,

    up_btn: Button,
    cancel_btn: Button,
    ok_btn: Button,

    pub const MAX_ENTRIES: u32 = 128;
    pub const padding: u32 = 14;
    pub const row_h: u32 = 22;
    pub const btn_h: u32 = 28;
    pub const btn_w: u32 = 90;
    pub const btn_gap: u32 = 10;
    pub const min_w: u32 = 360;
    pub const min_h: u32 = 280;

    /// Visible row count in the list area — derived from `h`.
    pub fn visibleRows(self: FolderPicker) u32 {
        const list_h = self.listHeight();
        return list_h / row_h;
    }

    fn listHeight(self: FolderPicker) u32 {
        // h - top padding - title + bar - up-button row - bottom padding - button row - inner gaps
        const overhead: u32 = padding + Canvas.CH16 + 8 + btn_h + 8 + btn_h + padding;
        return self.h -| overhead;
    }

    pub fn init(canvas_w: u32, canvas_h: u32, start_path: []const u8) FolderPicker {
        const w: u32 = @min(canvas_w -| 60, 480);
        const h: u32 = @min(canvas_h -| 80, 380);
        const x = (canvas_w -| w) / 2;
        const y = (canvas_h -| h) / 4;

        var fp: FolderPicker = .{
            .x = x,
            .y = y,
            .w = if (w < min_w) min_w else w,
            .h = if (h < min_h) min_h else h,
            .title = "Choose folder",
            .path_buf = undefined,
            .path_len = 0,
            .entries = undefined,
            .entry_count = 0,
            .selected = -1,
            .scroll = 0,
            .up_btn = .{ .x = x + padding, .y = y + padding + Canvas.CH16 + 6, .w = 80, .h = btn_h, .label = "Up" },
            .cancel_btn = .{ .x = x + w - padding - btn_w * 2 - btn_gap, .y = y + h - padding - btn_h, .w = btn_w, .h = btn_h, .label = "Cancel" },
            .ok_btn = .{ .x = x + w - padding - btn_w, .y = y + h - padding - btn_h, .w = btn_w, .h = btn_h, .label = "Open" },
        };
        fp.setPath(start_path);
        return fp;
    }

    /// Switch the picker to a new directory and re-read its entries.
    /// No-op when the path is empty or longer than 254 bytes. Resets the
    /// selection + scroll so the user sees the top of the new list.
    pub fn setPath(self: *FolderPicker, p: []const u8) void {
        if (p.len == 0 or p.len > 254) return;
        // Canonicalize: ensure trailing slash so concatenation works.
        @memcpy(self.path_buf[0..p.len], p);
        self.path_len = @intCast(p.len);
        if (self.path_buf[self.path_len - 1] != '/') {
            self.path_buf[self.path_len] = '/';
            self.path_len += 1;
        }
        self.refresh();
    }

    /// Re-read `path_buf` from disk. Called automatically by `setPath`
    /// and `navigateUp`; apps can call it manually after creating files
    /// they expect to show up.
    pub fn refresh(self: *FolderPicker) void {
        var tmp: [MAX_ENTRIES]libc.FileEntry = undefined;
        const n = libc.readdir(self.path_buf[0..self.path_len], &tmp);
        var kept: u32 = 0;
        var i: u32 = 0;
        while (i < n and kept < MAX_ENTRIES) : (i += 1) {
            // Show only directories. Files clutter the picker; the use
            // case is "pick a place", not "pick a file".
            if ((tmp[i].flags & libc.FE_FLAG_IS_DIR) == 0) continue;
            // Hide "." and ".." — Up button handles parent navigation
            // explicitly so users can't trip over the convention.
            const name = tmp[i].name[0..tmp[i].name_len];
            if (name.len == 1 and name[0] == '.') continue;
            if (name.len == 2 and name[0] == '.' and name[1] == '.') continue;
            self.entries[kept] = tmp[i];
            kept += 1;
        }
        self.entry_count = kept;
        self.selected = -1;
        self.scroll = 0;
    }

    /// Pop one path component, refresh. No-op when already at "/".
    pub fn navigateUp(self: *FolderPicker) void {
        // Strip the trailing slash, then strip back to the previous one.
        if (self.path_len <= 1) return;
        self.path_len -= 1; // drop trailing '/'
        while (self.path_len > 0 and self.path_buf[self.path_len - 1] != '/') {
            self.path_len -= 1;
        }
        if (self.path_len == 0) {
            self.path_buf[0] = '/';
            self.path_len = 1;
        }
        self.refresh();
    }

    /// Append `name` (one path component) to `path_buf` and refresh.
    /// Truncates silently if the result would exceed 254 bytes — the
    /// user just stays in the current directory.
    pub fn navigateInto(self: *FolderPicker, name: []const u8) void {
        if (self.path_len + name.len + 1 >= self.path_buf.len) return;
        @memcpy(self.path_buf[self.path_len..][0..name.len], name);
        self.path_len += @intCast(name.len);
        self.path_buf[self.path_len] = '/';
        self.path_len += 1;
        self.refresh();
    }

    /// Caller treats this as the chosen folder once `handleClick` /
    /// `handleKey` returns `.ok`.
    pub fn currentPath(self: FolderPicker) []const u8 {
        return self.path_buf[0..self.path_len];
    }

    /// Update button visual state + dispatch the click. Same calling
    /// convention as `Button.update`: caller tracks `left_prev`. Returns
    /// the action to take — most often `.none` (no click) or
    /// `.navigated` (clicked a directory row, picker moved into it).
    pub fn handleClick(self: *FolderPicker, mx: i32, my: i32, left_now: bool, left_prev: bool) FolderPickerAction {
        if (self.up_btn.update(mx, my, left_now, left_prev)) {
            self.navigateUp();
            return .navigated;
        }
        if (self.cancel_btn.update(mx, my, left_now, left_prev)) return .cancel;
        if (self.ok_btn.update(mx, my, left_now, left_prev)) return .ok;

        // Row hit-test. Only fires on the falling edge — matches Button.
        if (!left_now and left_prev) {
            const list_x = self.x + padding;
            const list_y = self.up_btn.y + self.up_btn.h + 6;
            const list_w = self.w -| (padding * 2);
            const list_h = self.listHeight();
            const inside = mx >= @as(i32, @intCast(list_x)) and mx < @as(i32, @intCast(list_x + list_w)) and
                my >= @as(i32, @intCast(list_y)) and my < @as(i32, @intCast(list_y + list_h));
            if (inside) {
                const rel_y: u32 = @intCast(my - @as(i32, @intCast(list_y)));
                const row: u32 = rel_y / row_h + self.scroll;
                if (row < self.entry_count) {
                    // Single-click = select. Double-click would navigate
                    // but we don't have tick tracking at the picker level
                    // — instead, treat clicking the already-selected row
                    // as the navigate gesture.
                    if (self.selected == @as(i32, @intCast(row))) {
                        const name = self.entries[row].name[0..self.entries[row].name_len];
                        self.navigateInto(name);
                        return .navigated;
                    } else {
                        self.selected = @intCast(row);
                        return .none;
                    }
                }
            }
        }
        return .none;
    }

    /// Forward a key press. Up/Down move the selection; Enter navigates
    /// into the selected row; Backspace = Up; Esc = cancel. Returns the
    /// matching action so the caller can dismiss without an explicit
    /// button click.
    pub fn handleKey(self: *FolderPicker, ch: u8) FolderPickerAction {
        switch (ch) {
            0x1B => return .cancel, // Esc
            8, 0x7F => {
                self.navigateUp();
                return .navigated;
            },
            '\n', '\r' => {
                if (self.selected >= 0 and @as(u32, @intCast(self.selected)) < self.entry_count) {
                    const row: u32 = @intCast(self.selected);
                    const name = self.entries[row].name[0..self.entries[row].name_len];
                    self.navigateInto(name);
                    return .navigated;
                }
                return .ok;
            },
            // Arrow keys arrive as the bare scancode in some paths;
            // accept them but don't require them. 0x91 = down, 0x92 = up
            // in the kernel's keymap (see input dispatch).
            0x91 => {
                if (self.entry_count == 0) return .none;
                const next: i32 = if (self.selected < 0) 0 else @min(self.selected + 1, @as(i32, @intCast(self.entry_count - 1)));
                self.selected = next;
                self.scrollIntoView();
                return .none;
            },
            0x92 => {
                if (self.entry_count == 0) return .none;
                const next: i32 = if (self.selected <= 0) 0 else self.selected - 1;
                self.selected = next;
                self.scrollIntoView();
                return .none;
            },
            else => return .none,
        }
    }

    fn scrollIntoView(self: *FolderPicker) void {
        if (self.selected < 0) return;
        const sel: u32 = @intCast(self.selected);
        const visible = self.visibleRows();
        if (sel < self.scroll) {
            self.scroll = sel;
        } else if (sel >= self.scroll + visible) {
            self.scroll = sel - visible + 1;
        }
    }

    pub fn draw(self: FolderPicker, canvas: *Canvas, surrounding_bg: u32) void {
        // Drop shadow + card surface — same vocabulary as Dialog so the
        // two read as part of the same OS look.
        drawShadow(canvas, self.x, self.y, self.w, self.h, surrounding_bg);
        canvas.fillRect(self.x, self.y, self.w, self.h, palette.card_bg);
        drawRect1px(canvas, self.x, self.y, self.w, self.h, palette.card_border);
        canvas.roundCornersRadius(self.x, self.y, self.w, self.h, PANEL_RADIUS, surrounding_bg);

        // Title
        const atlas = fa.getDefault16();
        const title_y = self.y + padding;
        fa.drawTextCentered(canvas, @intCast(self.x), @intCast(title_y), self.w, self.title, palette.text_strong, atlas);

        // Up button
        self.up_btn.drawStyled(canvas, .default, palette.card_bg);

        // Current path crumb to the right of Up button
        const crumb_x = self.up_btn.x + self.up_btn.w + 12;
        const crumb_y = self.up_btn.y + (btn_h -| atlas.line_height) / 2;
        canvas.drawText16Fg(crumb_x, crumb_y, self.path_buf[0..self.path_len], palette.text_normal);

        // Entry list region with a subtle inset frame
        const list_x = self.x + padding;
        const list_y = self.up_btn.y + self.up_btn.h + 6;
        const list_w = self.w -| (padding * 2);
        const list_h = self.listHeight();
        canvas.fillRect(list_x, list_y, list_w, list_h, palette.card_bg);
        drawRect1px(canvas, list_x, list_y, list_w, list_h, palette.card_border);

        // Rows
        const visible = self.visibleRows();
        var ri: u32 = 0;
        while (ri < visible and self.scroll + ri < self.entry_count) : (ri += 1) {
            const entry_idx = self.scroll + ri;
            const row_y = list_y + ri * row_h;
            const sel = (self.selected >= 0 and @as(u32, @intCast(self.selected)) == entry_idx);
            if (sel) {
                canvas.fillRect(list_x + 1, row_y, list_w -| 2, row_h, palette.btn_primary_top);
            }
            const name = self.entries[entry_idx].name[0..self.entries[entry_idx].name_len];
            const text_color: u32 = if (sel) palette.card_bg else palette.text_normal;
            // Folder glyph (lo-fi) + name
            canvas.drawText16Fg(list_x + 8, row_y + (row_h -| atlas.line_height) / 2, "[D]", if (sel) palette.card_bg else palette.text_muted);
            canvas.drawText16Fg(list_x + 36, row_y + (row_h -| atlas.line_height) / 2, name, text_color);
        }

        // Empty-state hint when the directory has no subfolders
        if (self.entry_count == 0) {
            const empty_msg = "(no subfolders)";
            const empty_y = list_y + (list_h -| atlas.line_height) / 2;
            fa.drawTextCentered(canvas, @intCast(list_x), @intCast(empty_y), list_w, empty_msg, palette.text_muted, atlas);
        }

        // Cancel + OK buttons
        self.cancel_btn.drawStyled(canvas, .default, palette.card_bg);
        self.ok_btn.drawStyled(canvas, .primary, palette.card_bg);
    }
};

// --- Image picker (thumbnails) -------------------------------------------

pub const ImagePickerAction = enum {
    none,
    /// User clicked Cancel or pressed Esc. Caller should `dismiss()` the
    /// picker and discard the selection.
    cancel,
    /// User clicked OK with an image selected. Caller reads
    /// `selectedName()` / current path and dismisses.
    ok,
    /// Folder changed (via the embedded folder picker's OK). Caller must
    /// re-decode thumbnails for the new directory and update `thumbs`
    /// before the next draw, then call `acknowledgeFolderChange()`.
    folder_changed,
};

/// Caller-decoded thumbnail. Pixels are RGBA8 (one byte per channel),
/// already scaled to roughly `thumb_w × thumb_h`. The picker doesn't
/// own them — caller keeps them alive for the picker's lifetime (or at
/// least until the next folder change).
pub const Thumbnail = struct {
    /// Filename (display label + identity). The caller derives the full
    /// path by joining `currentDir()` + this name.
    name: []const u8,
    /// RGBA8 pixel data, already scaled to fit the thumbnail cell.
    /// `null` = caller failed to decode; the picker renders a "broken"
    /// placeholder for that slot.
    pixels: ?[*]const u8 = null,
    /// Source dimensions of `pixels` (what they were scaled to). The
    /// picker centers them in the cell so any aspect ratio is fine.
    w: u32 = 0,
    h: u32 = 0,
};

/// Modal-overlay image picker — grid of thumbnails with a folder browse
/// button. Same state-machine pattern as Dialog and FolderPicker, but
/// rendering thumbnails requires the caller to decode them first (this
/// library is libc/image-decoder-agnostic on purpose). Caller supplies
/// the slice via `setThumbnails`; picker draws them in a 3×3 grid.
///
/// Typical wallpaper-picker flow:
///   1. `pick = ImagePicker.init(w, h, "/share/");`
///   2. Decode every image in /share/ into Thumbnail{} entries.
///   3. `pick.setThumbnails(thumbs);`
///   4. Each frame: `pick.draw(canvas, bg);`
///   5. On click: `pick.handleClick(mx, my, left_now, left_prev)`.
///      - `.folder_changed` → re-decode thumbnails for the new dir,
///        call `setThumbnails(...)`, call `acknowledgeFolderChange()`.
///      - `.ok` → read `pick.selectedName()` + join with
///        `pick.currentDir()` to get the chosen path.
///      - `.cancel` → drop the picker.
pub const ImagePicker = struct {
    x: u32,
    y: u32,
    w: u32,
    h: u32,
    title: []const u8,

    /// Directory the thumbnails live in. Caller passes this into
    /// `init`; updated by the embedded folder picker when the user
    /// browses elsewhere.
    dir_buf: [256]u8,
    dir_len: u32,

    /// Caller-owned slice. Empty = picker shows "no images" placeholder.
    thumbs: []const Thumbnail,
    selected: i32,

    /// Embedded folder picker, only rendered when `browsing == true`.
    /// We host it as a nested overlay so the image-picker stays modal
    /// to its parent app and the folder-picker stays modal to the
    /// image-picker — both dismiss back to the layer below.
    browsing: bool,
    folder_picker: FolderPicker,

    /// Set when the embedded folder picker returned OK and the caller
    /// hasn't yet refreshed `thumbs` for the new path. Caller reads
    /// `currentDir()`, re-decodes, calls `setThumbnails` +
    /// `acknowledgeFolderChange`.
    folder_pending: bool,

    browse_btn: Button,
    cancel_btn: Button,
    ok_btn: Button,

    pub const padding: u32 = 16;
    pub const cell_w: u32 = 130;
    pub const cell_h: u32 = 110;
    pub const cell_gap: u32 = 10;
    pub const thumb_w: u32 = cell_w - 16;
    pub const thumb_h: u32 = cell_h - 28; // leave room for filename below
    pub const cols: u32 = 3;
    pub const rows: u32 = 3;
    pub const btn_h: u32 = 28;
    pub const btn_w: u32 = 90;
    pub const btn_gap: u32 = 10;

    pub fn idealWidth() u32 {
        return padding * 2 + cols * cell_w + (cols - 1) * cell_gap;
    }
    pub fn idealHeight() u32 {
        // padding + title + breadcrumb row + rows * cell_h + breathing + btn row + padding
        return padding + Canvas.CH16 + 10 + btn_h + 10 + rows * cell_h + (rows - 1) * cell_gap + 14 + btn_h + padding;
    }

    pub fn init(canvas_w: u32, canvas_h: u32, start_dir: []const u8) ImagePicker {
        const wantw = idealWidth();
        const wanth = idealHeight();
        const w: u32 = @min(canvas_w -| 40, wantw);
        const h: u32 = @min(canvas_h -| 40, wanth);
        const x = (canvas_w -| w) / 2;
        const y = (canvas_h -| h) / 6;

        var ip: ImagePicker = .{
            .x = x,
            .y = y,
            .w = w,
            .h = h,
            .title = "Choose image",
            .dir_buf = undefined,
            .dir_len = 0,
            .thumbs = &[_]Thumbnail{},
            .selected = -1,
            .browsing = false,
            .folder_picker = undefined,
            .folder_pending = false,
            .browse_btn = .{
                .x = x + w - padding - 90,
                .y = y + padding + Canvas.CH16 + 6,
                .w = 90,
                .h = btn_h,
                .label = "Browse...",
            },
            .cancel_btn = .{
                .x = x + w - padding - btn_w * 2 - btn_gap,
                .y = y + h - padding - btn_h,
                .w = btn_w,
                .h = btn_h,
                .label = "Cancel",
            },
            .ok_btn = .{
                .x = x + w - padding - btn_w,
                .y = y + h - padding - btn_h,
                .w = btn_w,
                .h = btn_h,
                .label = "Apply",
            },
        };
        ip.setDir(start_dir);
        return ip;
    }

    pub fn currentDir(self: ImagePicker) []const u8 {
        return self.dir_buf[0..self.dir_len];
    }

    pub fn setDir(self: *ImagePicker, p: []const u8) void {
        if (p.len == 0 or p.len >= self.dir_buf.len) return;
        @memcpy(self.dir_buf[0..p.len], p);
        self.dir_len = @intCast(p.len);
        if (self.dir_buf[self.dir_len - 1] != '/') {
            self.dir_buf[self.dir_len] = '/';
            self.dir_len += 1;
        }
        self.selected = -1;
    }

    /// Hand the picker a fresh slice of thumbnails (e.g. after a folder
    /// change). Slice is owned by the caller; picker holds a reference.
    pub fn setThumbnails(self: *ImagePicker, thumbs: []const Thumbnail) void {
        self.thumbs = thumbs;
        if (self.selected >= @as(i32, @intCast(thumbs.len))) self.selected = -1;
    }

    pub fn selectedName(self: ImagePicker) ?[]const u8 {
        if (self.selected < 0) return null;
        const idx: usize = @intCast(self.selected);
        if (idx >= self.thumbs.len) return null;
        return self.thumbs[idx].name;
    }

    /// Caller calls after refreshing thumbs in response to a
    /// `.folder_changed` action.
    pub fn acknowledgeFolderChange(self: *ImagePicker) void {
        self.folder_pending = false;
    }

    pub fn handleClick(self: *ImagePicker, mx: i32, my: i32, left_now: bool, left_prev: bool) ImagePickerAction {
        // Nested folder picker takes input precedence when open.
        if (self.browsing) {
            switch (self.folder_picker.handleClick(mx, my, left_now, left_prev)) {
                .ok => {
                    self.setDir(self.folder_picker.currentPath());
                    self.browsing = false;
                    self.folder_pending = true;
                    return .folder_changed;
                },
                .cancel => {
                    self.browsing = false;
                    return .none;
                },
                else => return .none,
            }
        }

        if (self.browse_btn.update(mx, my, left_now, left_prev)) {
            self.folder_picker = FolderPicker.init(self.w + self.x * 2, self.h + self.y * 2, self.currentDir());
            // Re-center the folder picker on the parent canvas rather
            // than over the image-picker itself.
            self.folder_picker.x = self.x + (self.w -| self.folder_picker.w) / 2;
            self.folder_picker.y = self.y + (self.h -| self.folder_picker.h) / 2;
            // Re-anchor the buttons too since they're computed from x/y.
            self.folder_picker.up_btn.x = self.folder_picker.x + FolderPicker.padding;
            self.folder_picker.up_btn.y = self.folder_picker.y + FolderPicker.padding + Canvas.CH16 + 6;
            self.folder_picker.cancel_btn.x = self.folder_picker.x + self.folder_picker.w - FolderPicker.padding - FolderPicker.btn_w * 2 - FolderPicker.btn_gap;
            self.folder_picker.cancel_btn.y = self.folder_picker.y + self.folder_picker.h - FolderPicker.padding - FolderPicker.btn_h;
            self.folder_picker.ok_btn.x = self.folder_picker.x + self.folder_picker.w - FolderPicker.padding - FolderPicker.btn_w;
            self.folder_picker.ok_btn.y = self.folder_picker.y + self.folder_picker.h - FolderPicker.padding - FolderPicker.btn_h;
            self.browsing = true;
            return .none;
        }
        if (self.cancel_btn.update(mx, my, left_now, left_prev)) return .cancel;
        if (self.ok_btn.update(mx, my, left_now, left_prev)) return .ok;

        // Cell hit-test — only on falling edge so the click feel matches
        // Button.update.
        if (!left_now and left_prev) {
            const gx = self.gridX();
            const gy = self.gridY();
            const grid_w = cols * cell_w + (cols - 1) * cell_gap;
            const grid_h = rows * cell_h + (rows - 1) * cell_gap;
            const inside = mx >= @as(i32, @intCast(gx)) and mx < @as(i32, @intCast(gx + grid_w)) and
                my >= @as(i32, @intCast(gy)) and my < @as(i32, @intCast(gy + grid_h));
            if (inside) {
                const rel_x: u32 = @intCast(mx - @as(i32, @intCast(gx)));
                const rel_y: u32 = @intCast(my - @as(i32, @intCast(gy)));
                const col_w_total = cell_w + cell_gap;
                const row_h_total = cell_h + cell_gap;
                const col = rel_x / col_w_total;
                const row = rel_y / row_h_total;
                if (col < cols and row < rows and (rel_x % col_w_total) < cell_w and (rel_y % row_h_total) < cell_h) {
                    const idx = row * cols + col;
                    if (idx < self.thumbs.len) {
                        self.selected = @intCast(idx);
                    }
                }
            }
        }
        return .none;
    }

    pub fn handleKey(self: *ImagePicker, ch: u8) ImagePickerAction {
        if (self.browsing) {
            switch (self.folder_picker.handleKey(ch)) {
                .ok => {
                    self.setDir(self.folder_picker.currentPath());
                    self.browsing = false;
                    self.folder_pending = true;
                    return .folder_changed;
                },
                .cancel => {
                    self.browsing = false;
                    return .none;
                },
                else => return .none,
            }
        }
        if (ch == 0x1B) return .cancel;
        if (ch == '\n' or ch == '\r') return if (self.selected >= 0) .ok else .none;
        return .none;
    }

    fn gridX(self: ImagePicker) u32 {
        return self.x + padding;
    }
    fn gridY(self: ImagePicker) u32 {
        return self.y + padding + Canvas.CH16 + 6 + btn_h + 14;
    }

    pub fn draw(self: ImagePicker, canvas: *Canvas, surrounding_bg: u32) void {
        // Card surface — same vocabulary as Dialog/FolderPicker.
        drawShadow(canvas, self.x, self.y, self.w, self.h, surrounding_bg);
        canvas.fillRect(self.x, self.y, self.w, self.h, palette.card_bg);
        drawRect1px(canvas, self.x, self.y, self.w, self.h, palette.card_border);
        canvas.roundCornersRadius(self.x, self.y, self.w, self.h, PANEL_RADIUS, surrounding_bg);

        const atlas = fa.getDefault16();
        const title_y = self.y + padding;
        fa.drawTextCentered(canvas, @intCast(self.x), @intCast(title_y), self.w, self.title, palette.text_strong, atlas);

        // Browse + breadcrumb row
        self.browse_btn.drawStyled(canvas, .default, palette.card_bg);
        const crumb_y = self.browse_btn.y + (btn_h -| atlas.line_height) / 2;
        canvas.drawText16Fg(self.x + padding, crumb_y, self.dir_buf[0..self.dir_len], palette.text_muted);

        // Thumbnail grid
        const gx = self.gridX();
        const gy = self.gridY();
        const grid_count = cols * rows;
        var i: u32 = 0;
        while (i < grid_count) : (i += 1) {
            const col = i % cols;
            const row = i / cols;
            const cx = gx + col * (cell_w + cell_gap);
            const cy = gy + row * (cell_h + cell_gap);

            const is_sel = (self.selected >= 0 and @as(u32, @intCast(self.selected)) == i);
            // Cell frame — slight tint, selected gets the primary color.
            if (is_sel) {
                canvas.fillRect(cx, cy, cell_w, cell_h, palette.btn_primary_top);
            } else {
                drawRect1px(canvas, cx, cy, cell_w, cell_h, palette.card_border);
            }

            if (i < self.thumbs.len) {
                const t = self.thumbs[i];
                // Thumbnail centered in the top region.
                const tcell_x = cx + 8;
                const tcell_y = cy + 6;
                if (t.pixels) |px| {
                    const draw_w = @min(t.w, thumb_w);
                    const draw_h = @min(t.h, thumb_h);
                    const off_x = (thumb_w -| draw_w) / 2;
                    const off_y = (thumb_h -| draw_h) / 2;
                    blitThumb(canvas, px, t.w, t.h, tcell_x + off_x, tcell_y + off_y, draw_w, draw_h);
                } else {
                    // Broken / not yet decoded — placeholder X.
                    canvas.fillRect(tcell_x, tcell_y, thumb_w, thumb_h, palette.card_border);
                    fa.drawTextCentered(canvas, @intCast(tcell_x), @intCast(tcell_y + thumb_h / 2 - atlas.line_height / 2), thumb_w, "?", palette.text_muted, atlas);
                }
                // Filename label below.
                const label_color: u32 = if (is_sel) palette.card_bg else palette.text_normal;
                const label_y = cy + thumb_h + 10;
                fa.drawTextCentered(canvas, @intCast(cx), @intCast(label_y), cell_w, t.name, label_color, atlas);
            }
        }

        if (self.thumbs.len == 0) {
            const empty = "(no images in this folder)";
            const em_y = gy + (rows * cell_h + (rows - 1) * cell_gap) / 2 - atlas.line_height / 2;
            fa.drawTextCentered(canvas, @intCast(gx), @intCast(em_y), cols * cell_w + (cols - 1) * cell_gap, empty, palette.text_muted, atlas);
        }

        // Buttons
        self.cancel_btn.drawStyled(canvas, .default, palette.card_bg);
        const ok_style: ButtonStyle = if (self.selected >= 0) .primary else .default;
        self.ok_btn.drawStyled(canvas, ok_style, palette.card_bg);

        // Nested folder picker overlays everything else when active.
        if (self.browsing) self.folder_picker.draw(canvas, surrounding_bg);
    }
};

fn blitThumb(canvas: *Canvas, src: [*]const u8, sw: u32, sh: u32, dx: u32, dy: u32, dw: u32, dh: u32) void {
    if (dw == 0 or dh == 0 or sw == 0 or sh == 0) return;
    var y: u32 = 0;
    while (y < dh) : (y += 1) {
        const sy: u32 = (y * sh) / dh;
        const src_row = @as(usize, sy) * sw * 4;
        var x: u32 = 0;
        while (x < dw) : (x += 1) {
            const sx: u32 = (x * sw) / dw;
            const sidx = src_row + @as(usize, sx) * 4;
            const r: u32 = src[sidx + 0];
            const g: u32 = src[sidx + 1];
            const b: u32 = src[sidx + 2];
            canvas.putPixel(@intCast(dx + x), @intCast(dy + y), (r << 16) | (g << 8) | b);
        }
    }
}

// =============================================================================
// VStack / HStack — immediate-mode flow layout
// =============================================================================
//
// Apps that hand-position widgets at hardcoded `x=12, y=42 + section_h * N`
// coordinates break every time a font swap or padding tweak changes the
// vertical rhythm — see UEFI menu's AA-font cutover for the canonical
// disaster. These stacks let the caller declare a flow and the cursor
// walks through it: each item asks for its own intrinsic height (text
// rows pull line_height from the atlas; fixed-height items declare their
// own).
//
// Design:
//   * `gap(px)`     — explicit spacing between items
//   * `reserve(h)`  — claim `h` rows, return the y at which the slot
//                     starts; use to place any widget (Button, custom
//                     graphic) without per-widget API
//   * `text(...)`   — drop-in for AA labels; advances by line_height
//   * `button(...)` — convenience that builds a Button at the cursor
//                     and advances — caller still calls .draw / .update
//
// Right-anchored items (top-right close buttons, etc.) compute their x
// from `stack.x + stack.w - N` directly; reverse-cursor support adds
// API complexity for a handful of real call sites and isn't worth it.

pub const VStack = struct {
    canvas: *Canvas,
    x: u32,
    y: u32,
    w: u32,

    pub fn init(canvas: *Canvas, x: u32, y: u32, w: u32) VStack {
        return .{ .canvas = canvas, .x = x, .y = y, .w = w };
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

    /// Reserve `h` rows of vertical space. Returns the y at which the
    /// slot begins; advances the cursor by `h`. Use to place arbitrary
    /// widgets:
    ///   const y = v.reserve(28);
    ///   var btn = ui.Button{ .x = v.x, .y = y, .w = 100, .h = 28, .label = "OK" };
    ///   btn.drawStyled(&canvas, .primary, BG);
    pub fn reserve(self: *VStack, h: u32) u32 {
        const yy = self.y;
        self.y += h;
        return yy;
    }

    /// Left-aligned AA text. Cursor advances by `atlas.line_height`.
    pub fn text(self: *VStack, str: []const u8, color: u32, atlas: *const fa.FontAtlas) void {
        fa.drawText(self.canvas, @intCast(self.x), @intCast(self.y), str, color, atlas);
        self.y += atlas.line_height;
    }

    /// Horizontally-centered text within the stack's width.
    pub fn textCentered(self: *VStack, str: []const u8, color: u32, atlas: *const fa.FontAtlas) void {
        const tw = atlas.measure(str);
        const cx = self.x + (self.w -| tw) / 2;
        fa.drawText(self.canvas, @intCast(cx), @intCast(self.y), str, color, atlas);
        self.y += atlas.line_height;
    }

    /// Text with opaque background paint — use when drawing over an
    /// arbitrary surface (wallpaper, gradient) where AA bleed from the
    /// transparent path would show through.
    pub fn textOpaque(self: *VStack, str: []const u8, fg: u32, bg: u32, atlas: *const fa.FontAtlas) void {
        fa.drawTextOpaque(self.canvas, self.x, self.y, str, fg, bg, atlas);
        self.y += atlas.line_height;
    }

    /// 1-px horizontal rule. `inset` shrinks both ends symmetrically.
    pub fn rule(self: *VStack, inset: u32, color: u32) void {
        self.canvas.fillRect(self.x + inset, self.y, self.w -| 2 * inset, 1, color);
        self.y += 1;
    }

    /// Construct a Button at the current cursor with the stack's left
    /// edge, returning it so the caller can drive .draw / .update. The
    /// cursor advances by `h`. For multi-button rows, use HStack.
    pub fn button(self: *VStack, lbl: []const u8, w: u32, h: u32) Button {
        const yy = self.y;
        self.y += h;
        return Button{ .x = self.x, .y = yy, .w = w, .h = h, .label = lbl };
    }
};

pub const HStack = struct {
    canvas: *Canvas,
    x: u32,
    y: u32,
    h: u32,

    pub fn init(canvas: *Canvas, x: u32, y: u32, h: u32) HStack {
        return .{ .canvas = canvas, .x = x, .y = y, .h = h };
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

    /// Reserve `w` columns; returns the x at which the slot begins.
    /// Use to place widgets — same pattern as VStack.reserve.
    pub fn reserve(self: *HStack, w: u32) u32 {
        const xx = self.x;
        self.x += w;
        return xx;
    }

    /// Vertically-centered label. Cursor advances by measured width.
    pub fn label(self: *HStack, str: []const u8, color: u32, atlas: *const fa.FontAtlas) void {
        const ty: u32 = self.y + (self.h -| atlas.line_height) / 2;
        fa.drawText(self.canvas, @intCast(self.x), @intCast(ty), str, color, atlas);
        self.x += atlas.measure(str);
    }

    /// Construct a Button at the current cursor using the stack's height
    /// and a caller-given width. Cursor advances by `w`.
    pub fn button(self: *HStack, lbl: []const u8, w: u32) Button {
        const xx = self.x;
        self.x += w;
        return Button{ .x = xx, .y = self.y, .w = w, .h = self.h, .label = lbl };
    }
};

