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

/// Soft drop shadow — 6 progressively-lighter 1px stripes below + right
/// of the rect, approximating a fuzzy shadow without alpha blending. The
/// closest stripe is only ~7% darker than `surrounding_bg`, the outermost
/// ~0.5%; the eye smooths the discrete steps into a gentle gradient.
///
/// Each stripe extends one pixel further past the corner than the previous
/// one, which tapers the shadow into a soft quarter-circle at the lower-
/// right corner instead of a hard staircase.
///
/// `surrounding_bg` is the color the shadow fades into — pass the app's
/// background so the gradient blends naturally.
pub fn drawShadow(canvas: *Canvas, x: u32, y: u32, w: u32, h: u32, surrounding_bg: u32) void {
    // Denominators tuned so layer 0 ≈ 7% darker, layer 5 ≈ 0.5%. Quadratic
    // falloff (each step roughly doubles the distance) sells the "soft"
    // look better than a linear ramp because the eye is more sensitive to
    // small contrast differences than large ones.
    const denominators = [6]u32{ 14, 22, 36, 60, 100, 180 };
    inline for (denominators, 0..) |den, i| {
        const ii: u32 = @intCast(i);
        const c = lerpColor(surrounding_bg, 0x000000, 1, den);
        // Bottom stripe: extends `ii+1` pixels past the right edge so the
        // corner ramp from "card pixel" to "background" goes through every
        // layer, not just the innermost.
        if (y + h + ii < canvas.height) {
            const want_w = w + ii + 1;
            const max_w = canvas.width -| x;
            canvas.fillRect(x, y + h + ii, @min(want_w, max_w), 1, c);
        }
        // Right stripe: same idea, extended down.
        if (x + w + ii < canvas.width) {
            const want_h = h + ii + 1;
            const max_h = canvas.height -| y;
            canvas.fillRect(x + w + ii, y, 1, @min(want_h, max_h), c);
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
        canvas.roundCorners(self.x, self.y, self.w, self.h, bg);
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
        canvas.roundCorners(self.x, self.y, self.w, self.h, bg);
    }
};

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
        // Track: blue gradient when on, grey when off.
        const track_top: u32 = if (self.on) palette.btn_primary_top else palette.btn_default_top;
        const track_bot: u32 = if (self.on) palette.btn_primary_bot else palette.btn_default_bot;
        const lit_top = if (self.state == .hover) lerpColor(track_top, 0xFFFFFF, 1, 8) else track_top;
        const lit_bot = if (self.state == .hover) lerpColor(track_bot, 0xFFFFFF, 1, 10) else track_bot;
        verticalGradient(canvas, self.x, self.y, W, H, lit_top, lit_bot);
        drawRect1px(canvas, self.x, self.y, W, H, if (self.on) palette.btn_primary_border else palette.btn_default_border);
        canvas.roundCorners(self.x, self.y, W, H, bg);
        // Round inner edge too — pill look.
        const r: u32 = H / 2 - 1;
        _ = r;

        // Thumb: white circle that slides between left and right.
        const thumb_d: u32 = H - THUMB_PAD * 2;
        const thumb_y = self.y + THUMB_PAD;
        const thumb_x = if (self.on) self.x + W - THUMB_PAD - thumb_d else self.x + THUMB_PAD;
        canvas.fillRect(thumb_x, thumb_y, thumb_d, thumb_d, 0xFFFFFF);
        canvas.roundCorners(thumb_x, thumb_y, thumb_d, thumb_d, lit_top);
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
        canvas.roundCorners(self.x, self.y, self.w, self.h, surrounding_bg);

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
