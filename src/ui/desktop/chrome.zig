// A window as it is painted: the soft shadow around it, the border, the
// titlebar with its traffic lights and title, the content, the fade of an
// animation, the rounded corners.

const gfx = @import("../gfx.zig");
const emulator = @import("term/emulator.zig");
const cells = @import("term/cells.zig");
const FONT_W = cells.FONT_W;
const FONT_H = cells.FONT_H;
const drawTermCells = cells.drawTermCells;
const TERM_PAD = cells.TERM_PAD;
const term_view = @import("term/view.zig");
const termCursorCell = term_view.termCursorCell;
const drawTermScrollbar = term_view.drawTermScrollbar;
const corners = @import("corners.zig");
const CORNER_R = corners.CORNER_R;
const ALL_CORNERS = corners.ALL_CORNERS;
const saveCornerPixels = corners.saveCornerPixels;
const restoreCornerPixels = corners.restoreCornerPixels;
const wm = @import("window.zig");
const Window = wm.Window;
const TerminalData = emulator.TerminalData;
const windows = &wm.windows;
const conf = @import("config.zig");
const dirty_rects_mod = @import("dirty.zig");
const addDirtyRect = dirty_rects_mod.add;
const background = @import("background.zig");
const theme = @import("../theme.zig");
const TITLEBAR_TEXT_F = theme.TITLEBAR_TEXT_F;
const TITLEBAR_TEXT_U = theme.TITLEBAR_TEXT_U;
const WINDOW_BG = theme.WINDOW_BG;
const TERM_FG = theme.TERM_FG;
const BTN_CLOSE = theme.BTN_CLOSE;
const BTN_MINIMIZE = theme.BTN_MINIMIZE;
const BTN_MAXIMIZE = theme.BTN_MAXIMIZE;
const layout = @import("layout.zig");
const TITLEBAR_H = layout.TITLEBAR_H;
const BORDER = layout.BORDER;
const BTN_RADIUS = layout.BTN_RADIUS;
const aa_font = @import("../aa_font.zig");
const TERM_COLS = emulator.TERM_COLS;
const TERM_ROWS = emulator.TERM_ROWS;
const BELL_FLASH_COLOR = theme.BELL_FLASH_COLOR;
const SCROLL_LINES: u32 = @import("../../config.zig").SCROLL_LINES;

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

    // Content area
    const content_y = w.y + @as(i32, TITLEBAR_H);
    const content_h = w.height -| TITLEBAR_H;

    // Read the published back buffer if the app has presented at least
    // once. Until then, read gui_fb directly so apps that never call
    // libc.present() still render. Apps that do present (cube) get
    // tear-free reads via the triple-buffer rotation.
    const pub_idx = w.gui_fb_pub.load(.acquire);
    const active_back: ?[*]volatile u32 = if (w.has_presented) w.gui_fb_backs[pub_idx] else w.gui_fb;
    if (w.gpu_slot != null) {
        // Phase 8: slot-backed window. The GPU compositor's per-window
        // draw samples the dmabuf directly and overlays it on top of
        // the backbuf in the same render pass that consumes the
        // backbuf for the background — so the CPU blit below would
        // just write pixels the GPU overdraws. Chrome (titlebar/
        // borders/shadow drawn earlier in this fn) stays in the
        // backbuf and shows via the background pass.
    } else if (active_back orelse w.gui_fb) |fb| {
        // GUI app window — blit the active kernel back buffer to the desktop
        // back buffer. Falls back to gui_fb only on legacy windows that
        // pre-date the triple-buffer change (none should exist post-
        // sysCreateWindow change; defensive fallback).

        // Source = the app's rendered content extent, capped to its FB
        // allocation (reading past it would walk into the next row through
        // the smaller stride).
        const src_w: u32 = if (w.gui_alloc_w > 0) @min(w.gui_w, w.gui_alloc_w) else w.gui_w;
        const src_h: u32 = if (w.gui_alloc_h > 0) @min(w.gui_h, w.gui_alloc_h) else w.gui_h;
        const stride = if (w.gui_alloc_w > 0) w.gui_alloc_w else w.gui_w;
        // Destination = the FULL window content area. When it equals the source
        // (normal/dragged window — drag is capped at the alloc) we blit 1:1:
        // crisp + fast (rep movsl). When it's larger (F10 maximize past the FB
        // alloc) we nearest-neighbor UPSCALE so the content fills the window
        // instead of sitting alloc-sized in the corner with wallpaper around it.
        // (cpu-comp path; the GPU compositor does the equivalent via uv_scale.)
        const dst_w: u32 = w.width;
        const dst_h: u32 = content_h;
        if (src_w != 0 and src_h != 0 and dst_w != 0 and dst_h != 0) {
            if (src_w == dst_w and src_h == dst_h) {
                var row: u32 = 0;
                while (row < dst_h) : (row += 1) {
                    const py = content_y + @as(i32, @intCast(row));
                    if (py < 0) continue;
                    if (py >= @as(i32, @intCast(gfx.target_h))) break;
                    if (w.x >= @as(i32, @intCast(gfx.target_w))) continue;
                    const dst_x: u32 = if (w.x < 0) 0 else @intCast(w.x);
                    const src_skip: u32 = if (w.x < 0) @intCast(-w.x) else 0;
                    const avail = gfx.target_w - dst_x;
                    const count = @min(dst_w -| src_skip, avail);
                    if (count == 0) continue;
                    const dst_off = @as(u32, @intCast(py)) * gfx.target_w + dst_x;
                    const src_off = row * stride + src_skip;
                    const dest = @intFromPtr(gfx.target) + dst_off * 4;
                    const src = @intFromPtr(fb) + src_off * 4;
                    asm volatile ("cld; rep movsl"
                        :
                        : [dst] "{rdi}" (dest),
                          [src] "{rsi}" (src),
                          [cnt] "{rcx}" (count),
                        : .{ .rdi = true, .rsi = true, .rcx = true, .memory = true }
                    );
                }
            } else {
                // Nearest-neighbor scale src→dst. 16.16 fixed-point sampled per
                // pixel (stateless, so the screen-edge `continue`/`break` clips
                // can't desync the source index) — no per-pixel divide and no
                // large stack buffer, keeping pid 2's kstack lean.
                const x_step: u32 = (src_w << 16) / dst_w;
                const y_step: u32 = (src_h << 16) / dst_h;
                var row: u32 = 0;
                while (row < dst_h) : (row += 1) {
                    const py = content_y + @as(i32, @intCast(row));
                    if (py < 0) continue;
                    if (py >= @as(i32, @intCast(gfx.target_h))) break;
                    const sy: u32 = @min((row * y_step) >> 16, src_h - 1);
                    const src_row: [*]volatile u32 = @ptrFromInt(@intFromPtr(fb) + @as(usize, sy) * stride * 4);
                    const dst_row_base = @as(u32, @intCast(py)) * gfx.target_w;
                    var col: u32 = 0;
                    while (col < dst_w) : (col += 1) {
                        const dx = w.x + @as(i32, @intCast(col));
                        if (dx < 0) continue;
                        if (dx >= @as(i32, @intCast(gfx.target_w))) break;
                        const sx: u32 = @min((col * x_step) >> 16, src_w - 1);
                        gfx.target[dst_row_base + @as(u32, @intCast(dx))] = src_row[sx];
                    }
                }
            }
        }
    } else if (w.term) |t| {
        // Terminal window — draw text buffer (with scrollback support)
        gfx.fillRect(w.x, content_y, w.width, content_h, WINDOW_BG);
        gfx.drawHLine(w.x, content_y, w.width, 0x151515);

        const max_rows = content_h / FONT_H;
        const max_cols = (w.width - TERM_PAD * 2) / FONT_W;

        if (t.scroll_view > 0 and t.scroll_count > 0) {
            // Scrolled-back view: show scrollback + text_buf
            t.painted_valid = false;
            var row: u32 = 0;
            while (row < max_rows) : (row += 1) {
                const total_lines = @as(u32, t.scroll_count) + @as(u32, t.text_row) + 1;
                const view_bottom = total_lines -| @as(u32, t.scroll_view);
                const view_top = view_bottom -| max_rows;
                const line_idx = view_top + row;
                if (line_idx >= total_lines) break;

                const y = content_y + @as(i32, @intCast(row * FONT_H));
                if (line_idx < t.scroll_count) {
                    const at = (@as(u32, t.scroll_write) + SCROLL_LINES - t.scroll_count + line_idx) % SCROLL_LINES * TERM_COLS;
                    drawTermCells(w.x, y, t.scroll_buf[at..], t.scroll_attr_buf[at..], t.scroll_fg_rgb_buf[at..], t.scroll_bg_rgb_buf[at..], max_cols);
                } else {
                    const tb_row = line_idx - @as(u32, t.scroll_count);
                    if (tb_row >= TERM_ROWS) continue;
                    const at = tb_row * TERM_COLS;
                    drawTermCells(w.x, y, t.text_buf[at..], t.attr_buf[at..], t.fg_rgb_buf[at..], t.bg_rgb_buf[at..], max_cols);
                }
            }
            gfx.drawString(w.x + @as(i32, @intCast(w.width)) - 80, content_y + 2, "[PgDn]", 0x666688, WINDOW_BG);
        } else {
            // Live view.
            var row: u32 = 0;
            while (row < TERM_ROWS and row < max_rows) : (row += 1) {
                const at = row * TERM_COLS;
                drawTermCells(w.x, content_y + @as(i32, @intCast(row * FONT_H)), t.text_buf[at..], t.attr_buf[at..], t.fg_rgb_buf[at..], t.bg_rgb_buf[at..], max_cols);
            }

            // Text cursor — blink unless the user just typed / output just landed.
            const cursor = termCursorCell(idx, w, t, max_cols, max_rows);
            if (cursor != TerminalData.NO_CURSOR) {
                gfx.fillRect(
                    w.x + @as(i32, @intCast(TERM_PAD + @as(u32, t.text_col) * FONT_W)),
                    content_y + @as(i32, @intCast(@as(u32, t.text_row) * FONT_H)),
                    FONT_W,
                    FONT_H,
                    TERM_FG,
                );
            }
            // The rows now show exactly these cells.
            t.painted_text = t.text_buf;
            t.painted_attr = t.attr_buf;
            t.painted_rgb = t.fg_rgb_buf;
            t.painted_bg = t.bg_rgb_buf;
            t.painted_cursor = cursor;
            t.painted_scroll_count = t.scroll_count;
            t.painted_valid = true;
        }

        drawTermScrollbar(w, t);
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
