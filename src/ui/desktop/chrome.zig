// A window as it is painted: the soft shadow around it, the border, the
// titlebar with its traffic lights and title, the content, the fade of an
// animation, the rounded corners.

const gfx = @import("../gfx.zig");
const term_view = @import("term/view.zig");
const surface = @import("surface.zig");
const corners = @import("corners.zig");
const CORNER_R = corners.CORNER_R;
const ALL_CORNERS = corners.ALL_CORNERS;
const saveCornerPixels = corners.saveCornerPixels;
const restoreCornerPixels = corners.restoreCornerPixels;
const wm = @import("window.zig");
const Window = wm.Window;
const windows = &wm.windows;
const conf = @import("config.zig");
const dirty_rects_mod = @import("dirty.zig");
const addDirtyRect = dirty_rects_mod.add;
const background = @import("background.zig");
const theme = @import("../theme.zig");
const TITLEBAR_TEXT_F = theme.TITLEBAR_TEXT_F;
const TITLEBAR_TEXT_U = theme.TITLEBAR_TEXT_U;
const BTN_CLOSE = theme.BTN_CLOSE;
const BTN_MINIMIZE = theme.BTN_MINIMIZE;
const BTN_MAXIMIZE = theme.BTN_MAXIMIZE;
const layout = @import("layout.zig");
const TITLEBAR_H = layout.TITLEBAR_H;
const BORDER = layout.BORDER;
const BTN_RADIUS = layout.BTN_RADIUS;
const aa_font = @import("../aa_font.zig");
const BELL_FLASH_COLOR = theme.BELL_FLASH_COLOR;

// ─── Window drop-shadow geometry ────────────────────────────────────────────
// A soft "elevation" shadow on ALL FOUR sides, biased downward so the bottom
// reads heavier than the top (key light from above) — the macOS/material look,
// not the old right+bottom-only drop shadow. Shared by renderWindow (the blend),
// the dirty-rect, and the z-occlusion test so all three agree on the extent.
//
//   SHADOW_R    — reach in px beyond the window border (corners included)
//   SHADOW_OFFY — downward offset of the shadow caster; the bottom gains +OFFY
//                 of reach, the top loses OFFY of contact strength
//   SHADOW_PEAK — max alpha byte at contact (~19%) under the focused window;
//                 the others cast SHADOW_UNFOCUSED_NUM/16 of it, so the active
//                 window reads as the one nearest the viewer
const SHADOW_R = 26;
const SHADOW_OFFY = 8;
const SHADOW_PEAK = 0x30;
const SHADOW_UNFOCUSED_NUM = 9;
// One symmetric pad that over-covers the (asymmetric) shadow on every side —
// used by the dirty-rect and the occlusion test. Over-covering is harmless
// (a few extra wallpaper px get repainted/flushed); under-covering smears.
pub const SHADOW_SPAD: i32 = SHADOW_R + SHADOW_OFFY + @as(i32, BORDER) + 2;

// Precomputed at COMPILE time: shadow_lut[dy][dx] = alpha byte for a pixel that
// is (dx, dy) px from the (offset) window rect. Euclidean distance → naturally
// round corners; (1 − smoothstep) falloff → soft shoulder near the window and a
// clean vanish at the rim (no hard cut line). Building it at comptime keeps the
// runtime hot path free of sqrt/float, both slow-or-broken on the freestanding-
// baseline target (see the @floatFromInt / @floor freestanding gotchas).
const shadow_lut: [SHADOW_R + 1][SHADOW_R + 1]u8 = blk: {
    @setEvalBranchQuota(20000);
    var lut: [SHADOW_R + 1][SHADOW_R + 1]u8 = [_][SHADOW_R + 1]u8{[_]u8{0} ** (SHADOW_R + 1)} ** (SHADOW_R + 1);
    const r: f64 = SHADOW_R;
    for (0..SHADOW_R + 1) |dy| {
        for (0..SHADOW_R + 1) |dx| {
            const fx: f64 = @floatFromInt(dx);
            const fy: f64 = @floatFromInt(dy);
            const dist = @sqrt(fx * fx + fy * fy);
            if (dist < r) {
                const t = dist / r; // 0 at contact … 1 at the rim
                const fall = 1.0 - (3.0 * t * t - 2.0 * t * t * t); // 1 − smoothstep
                lut[dy][dx] = @intFromFloat(fall * @as(f64, SHADOW_PEAK));
            }
        }
    }
    break :blk lut;
};

/// Shadow-padded outer rect [x0, y0, x1, y1) of a window — the full extent
/// renderWindow can paint (shadow band ⊂ SHADOW_SPAD pad, see SHADOW_*).
pub fn paddedWinRect(i: u8) [4]i32 {
    const w = &windows[i];
    return .{
        w.x - SHADOW_SPAD,
        w.y - SHADOW_SPAD,
        w.x + @as(i32, @intCast(w.width)) + SHADOW_SPAD,
        w.y + @as(i32, @intCast(w.height)) + SHADOW_SPAD,
    };
}

pub fn renderWindow(idx: u8) void {
    const w = &windows[idx];
    if (!w.visible or w.minimized) return;
    const is_focused = (idx == wm.focused);
    const dark = conf.theme == 1;

    // Maximized windows render through the same chrome path as normal
    // windows — they're just laid out in the usable area. The old
    // fullscreen-scaling shortcut here was the source of the "ruins
    // UI for non-Doom apps" complaint: scaling a 480-px window to
    // 1920 px gave blurry pixel slop. Now the app's framebuffer renders
    // at its own resolution (centered if alloc-capped) inside the
    // maximized window frame.

    // Mark this window's region (incl. the all-around soft shadow) dirty for
    // partial GPU flush. SHADOW_SPAD pads every side; clamp the origin to the
    // screen and let addDirtyRect clip the far edges.
    const sx0: i32 = w.x - SHADOW_SPAD;
    const sy0: i32 = w.y - SHADOW_SPAD;
    const ddx: u32 = if (sx0 < 0) 0 else @intCast(sx0);
    const ddy: u32 = if (sy0 < 0) 0 else @intCast(sy0);
    const span: u32 = @intCast(2 * SHADOW_SPAD);
    addDirtyRect(ddx, ddy, w.width + span, w.height + span);

    // Soft "elevation" drop shadow on ALL FOUR sides, biased downward so the
    // bottom reads heavier than the top (key light from above). The shadow is
    // cast by the window+border rect shifted down by SHADOW_OFFY; per-pixel
    // alpha comes from the comptime shadow_lut keyed by the (dx,dy) distance to
    // that rect — Euclidean, so the corners round off naturally. See SHADOW_*.
    //
    // Gated on `w.shadow_dirty` so content-only redraws don't re-blend over the
    // previous frame's shadow (which would accumulate to black after ~30 frames
    // on a 60fps app like sysmon). Redrawn on every shadow_dirty frame (incl.
    // each drag step); the scalar per-pixel blend is bounded by the shadow-band
    // area and runs only here, never on content-only ticks.
    if (w.shadow_dirty) {
        const ol = w.x - @as(i32, BORDER);
        const ot = w.y - @as(i32, BORDER);
        const orr = w.x + @as(i32, @intCast(w.width)) + @as(i32, BORDER);
        const ob = w.y + @as(i32, @intCast(w.height)) + @as(i32, BORDER);
        const ct = ot + SHADOW_OFFY; // caster top/bottom (left/right unshifted)
        const cb = ob + SHADOW_OFFY;
        const tw: i32 = @intCast(gfx.target_w);
        const th: i32 = @intCast(gfx.target_h);

        var py: i32 = ct - SHADOW_R;
        while (py < cb + SHADOW_R) : (py += 1) {
            if (py < 0 or py >= th) continue;
            // vertical distance from the (offset) caster rect, 0 inside its span
            const dy_i: i32 = if (py < ct) ct - py else if (py >= cb) py - cb + 1 else 0;
            if (dy_i > SHADOW_R) continue;
            const row: u32 = @as(u32, @intCast(py)) * gfx.target_w;
            var px: i32 = ol - SHADOW_R;
            while (px < orr + SHADOW_R) : (px += 1) {
                if (px < 0 or px >= tw) continue;
                // Skip the window's own footprint — chrome paints over it
                // below. Its corner squares are not skipped: what shows past
                // the rounded corners lies in the shadow like its surroundings.
                if (px >= ol and px < orr and py >= ot and py < ob) {
                    const cr: i32 = CORNER_R;
                    const in_x = px < ol + cr or px >= orr - cr;
                    const in_y = py < ot + cr or py >= ob - cr;
                    if (!(in_x and in_y)) continue;
                }
                const dx_i: i32 = if (px < ol) ol - px else if (px >= orr) px - orr + 1 else 0;
                if (dx_i > SHADOW_R) continue;
                var a: u32 = shadow_lut[@intCast(dy_i)][@intCast(dx_i)];
                if (!is_focused) a = a * SHADOW_UNFOCUSED_NUM / 16;
                if (a == 0) continue;
                const off: u32 = row + @as(u32, @intCast(px));
                gfx.target[off] = gfx.blendPixel(gfx.target[off], a << 24);
            }
        }
        w.shadow_dirty = false;
    }

    // What lies behind the rounded corners, shadow included, before the
    // chrome is drawn over it.
    saveCornerPixels(w.x - @as(i32, BORDER), w.y - @as(i32, BORDER), w.width + BORDER * 2, w.height + BORDER * 2, ALL_CORNERS);

    const border_color = borderColor(w, is_focused);
    gfx.drawRect(w.x - @as(i32, BORDER), w.y - @as(i32, BORDER), w.width + BORDER * 2, w.height + BORDER * 2, border_color);

    // Title bar: a shallow gradient. The focused window's is a step brighter
    // and carries a 1px highlight on its top edge; the others sit flatter so
    // the eye goes to the active one.
    const tb_top: u32 = if (dark)
        (if (is_focused) @as(u32, 0x3B3B3E) else @as(u32, 0x2B2B2D))
    else
        (if (is_focused) @as(u32, 0xF6F6F6) else @as(u32, 0xECECEC));
    const tb_bot: u32 = if (dark)
        (if (is_focused) @as(u32, 0x303033) else @as(u32, 0x28282A))
    else
        (if (is_focused) @as(u32, 0xE6E6E6) else @as(u32, 0xE4E4E4));
    {
        var row: u32 = 0;
        while (row < TITLEBAR_H) : (row += 1) {
            const c = background.lerpColor(tb_top, tb_bot, row, TITLEBAR_H);
            gfx.fillRect(w.x, w.y + @as(i32, @intCast(row)), w.width, 1, c);
        }
    }
    // Focus highlight — 1px bright bevel along the top edge of the active
    // window's titlebar. Subtle (white at ~20% alpha for dark theme, slightly
    // less for light), reads as "this window is alive".
    if (is_focused) {
        const hi_a: u32 = if (dark) @as(u32, 0x26000000) else @as(u32, 0x40000000);
        gfx.fillRectAlpha(w.x, w.y, w.width, 1, hi_a | 0x00FFFFFF);
    }
    // Separator under the titlebar: darker than the bar in either theme.
    const sep_color: u32 = if (dark)
        (if (is_focused) @as(u32, 0x1A1A1C) else @as(u32, 0x202022))
    else
        (if (is_focused) @as(u32, 0xC2C2C2) else @as(u32, 0xD2D2D2));
    gfx.drawHLine(w.x, w.y + @as(i32, TITLEBAR_H) - 1, w.width, sep_color);

    // Traffic lights (left side): a flat disc inside a 1px darker rim. An
    // unfocused window's turn a uniform gray, so the red/amber/green marks
    // the window that takes input.
    const idle_fill: u32 = if (dark) 0x55555A else 0xCDCDCD;
    const lights = [3][2]u32{
        .{ BTN_CLOSE, 0xDF4840 },
        .{ BTN_MINIMIZE, 0xDCA025 },
        .{ BTN_MAXIMIZE, 0x1FA82F },
    };
    for (lights, 0..) |l, n| {
        const c = wm.trafficLightCenter(w.x, w.y, @intCast(n));
        if (is_focused) {
            gfx.drawFilledCircle(c[0], c[1], BTN_RADIUS, l[1]);
            gfx.drawFilledCircle(c[0], c[1], BTN_RADIUS - 1, l[0]);
        } else {
            gfx.drawFilledCircle(c[0], c[1], BTN_RADIUS, idle_fill);
        }
    }

    // Centered title, SF Pro Text 13 semibold. It yields to the traffic
    // lights: a title too wide to center clear of them is left-aligned
    // after them, and one too wide for that is not drawn.
    const text_color = if (dark)
        (if (is_focused) @as(u32, 0xE4E4E6) else @as(u32, 0x77777C))
    else
        (if (is_focused) TITLEBAR_TEXT_F else TITLEBAR_TEXT_U);
    {
        const title_atlas = aa_font.getDefault13Semibold();
        const title_text = w.title[0..w.title_len];
        const title_px_w: u32 = title_atlas.measure(title_text);
        const lights_end: u32 = @intCast(layout.BTN_FIRST_X + 2 * layout.BTN_PITCH + @as(i32, BTN_RADIUS) + 10);
        const title_y = w.y + @divTrunc(@as(i32, TITLEBAR_H) - @as(i32, @intCast(title_atlas.line_height)), 2);
        if (title_px_w + lights_end * 2 <= w.width) {
            const title_x = w.x + @as(i32, @intCast((w.width - title_px_w) / 2));
            aa_font.drawText(title_x, title_y, title_text, text_color, title_atlas);
        } else if (title_px_w + lights_end + 8 <= w.width) {
            aa_font.drawText(w.x + @as(i32, @intCast(lights_end)), title_y, title_text, text_color, title_atlas);
        }
    }

    // Content area: a program's window shows its framebuffer, a terminal
    // its cells.
    const content_y = w.y + @as(i32, TITLEBAR_H);
    const content_h = w.height -| TITLEBAR_H;
    if (!surface.paintContent(w, content_y, content_h)) {
        if (w.term) |t| term_view.paintContent(idx, w, t, content_y, content_h);
    }

    // Animation fade overlay
    if (w.anim_type != .none) {
        const frame: u32 = w.anim_frame;
        const total: u32 = w.anim_total;
        const fade_alpha: u32 = switch (w.anim_type) {
            .opening, .restoring, .unfullscreening => 255 -| (frame * 255 / (total + 1)),
            .closing, .minimizing, .fullscreening => frame * 255 / (total + 1),
            .none => 0,
        };
        if (fade_alpha > 0) {
            gfx.fillRectAlpha(w.x, w.y, w.width, w.height, (fade_alpha << 24));
            if (w.term) |t| t.painted_valid = false;
        }
    }

    // Round the corners last: the content fills the window's rect down to
    // its bottom corners. The border color traces the arcs.
    restoreCornerPixels(w.x - @as(i32, BORDER), w.y - @as(i32, BORDER), w.width + BORDER * 2, w.height + BORDER * 2, border_color, ALL_CORNERS);
}

/// The 1px window border, a hairline a touch off the body. Flashes while a
/// terminal's bell_phase counts down.
pub fn borderColor(w: *const Window, is_focused: bool) u32 {
    if (w.term) |t| if (t.bell_phase > 0) return BELL_FLASH_COLOR;
    return if (conf.theme == 1)
        (if (is_focused) @as(u32, 0x4A4A4E) else @as(u32, 0x38383B))
    else
        (if (is_focused) @as(u32, 0xB4B4B4) else @as(u32, 0xC8C8C8));
}
