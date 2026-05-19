// Dock — bottom-centre pill with pinned shortcuts on the left, then a
// separator, then running-window icons. Hovering an icon for ~10 frames
// pops a tooltip with the title. Clicking dispatches: a shortcut launches
// its app, a running-window icon focuses the window (and restores it from
// the dock if minimized).
//
// State lives here (pill geometry, button positions, hover tracking).
// The compositor calls render()/renderTooltip() once per scene; the input
// handler calls clickAt()/updateHover()/dockY() for hit-testing.

const std = @import("std");
const gfx = @import("../gfx.zig");
const aa_font = @import("../aa_font.zig");
const icons = @import("../icons.zig");
const layout = @import("layout.zig");
const dirty_rects = @import("dirty.zig");
const wm = @import("window.zig");
const pinned = @import("pinned.zig");

const TASKBAR_H = layout.TASKBAR_H;
const DOCK_ICON_SIZE = layout.DOCK_ICON_SIZE;
const DOCK_ICON_PAD = layout.DOCK_ICON_PAD;
const DOCK_PILL_PAD = layout.DOCK_PILL_PAD;
const DOCK_MARGIN_BOTTOM = layout.DOCK_MARGIN_BOTTOM;

const BtnInfo = struct { x: i32, idx: u8, is_shortcut: bool };

var btn_positions: [wm.MAX_WINDOWS + 10]BtnInfo = undefined;
var btn_count: u8 = 0;
var pill_x: i32 = 0;
var pill_y: i32 = 0;
var pill_w: u32 = 0;
var pill_h: u32 = 0;

/// Hover tracking. -1 means cursor not over any dock button. The timer
/// counts frames since hover started; once it reaches TOOLTIP_FRAMES we
/// draw the tooltip. Read by the desktop loop to decide whether the
/// scene needs a full re-render (tooltip pixels live outside the
/// rect-tracker, so a partial flush would leave the tooltip stale).
pub var hover_idx: i8 = -1;
pub var hover_timer: u8 = 0;
pub const TOOLTIP_FRAMES: u8 = 10;

/// Click target — either launch the named pinned shortcut or focus the
/// given running-window slot.
pub const Action = union(enum) {
    shortcut: u8,
    window: u8,
};

pub fn dockY() i32 {
    return @intCast(gfx.screen_h - TASKBAR_H);
}

/// True iff (mx, my) is within the dock's vertical band — used by the
/// click handler to decide whether to consult the dock first.
pub fn inDockZone(my: i32) bool {
    const top = dockY();
    return my >= top and my < top + @as(i32, TASKBAR_H);
}

/// True iff a tooltip is currently visible. Caller uses this to decide
/// whether the next frame needs a .full repaint (tooltip overlays the
/// dock + bg below it, outside the dirty-rect tracker).
pub fn isTooltipVisible() bool {
    return hover_idx >= 0 and hover_timer >= TOOLTIP_FRAMES;
}

pub fn render() void {
    const dy: i32 = dockY();
    dirty_rects.add(0, if (dy < 0) 0 else @intCast(dy), gfx.screen_w, TASKBAR_H);

    const pinned_count: u32 = pinned.dock_indices.len;
    var running_count: u32 = 0;
    for (wm.z_stack[0..wm.z_count]) |i| {
        if (wm.windows[i].visible) running_count += 1;
    }

    const icon_slot = DOCK_ICON_SIZE + DOCK_ICON_PAD;
    const sep_w: u32 = if (running_count > 0) 12 else 0;
    const content_w = pinned_count * icon_slot + sep_w + running_count * icon_slot;
    const pill_w_raw = content_w + DOCK_PILL_PAD * 2;
    pill_w = @min(pill_w_raw, gfx.screen_w -| 20);
    pill_h = DOCK_ICON_SIZE + DOCK_PILL_PAD * 2;
    pill_x = @intCast((gfx.screen_w -| pill_w) / 2);
    pill_y = dy + @as(i32, DOCK_MARGIN_BOTTOM);

    gfx.fillRoundedRectAlpha(pill_x + 2, pill_y + 2, pill_w, pill_h, pill_h / 2, 0x40000000);
    gfx.fillGlass(pill_x, pill_y, pill_w, pill_h, pill_h / 2, 0x30333338, 8);

    btn_count = 0;
    var icon_x: i32 = pill_x + @as(i32, DOCK_PILL_PAD);
    const icon_y: i32 = pill_y + @as(i32, DOCK_PILL_PAD);

    // Pinned shortcuts — only the "system tray" subset (see pinned.dock_indices).
    // The desktop sidebar still shows the full launcher; the dock stays lean
    // so it can dedicate space to running-window thumbnails next to a few
    // always-useful tools.
    for (pinned.dock_indices) |pinned_idx| {
        const sc = pinned.list[pinned_idx];
        gfx.drawIcon32(icon_x, icon_y, sc.icon);

        // Running indicator dot if this shortcut has a window open
        var has_running = false;
        for (wm.z_stack[0..wm.z_count]) |wi| {
            if (!wm.windows[wi].visible) continue;
            const title = wm.windows[wi].title[0..wm.windows[wi].title_len];
            if (title.len >= sc.name.len and std.mem.eql(u8, title[0..sc.name.len], sc.name)) {
                has_running = true;
                break;
            }
        }
        if (has_running) {
            gfx.drawFilledCircle(icon_x + @as(i32, DOCK_ICON_SIZE / 2), pill_y + @as(i32, @intCast(pill_h)) + 3, 2, 0xFFFFFF);
        }

        if (btn_count < wm.MAX_WINDOWS + 10) {
            // `idx` indexes pinned.list (so launchShortcut/tooltip lookup
            // stays uniform across the dock + sidebar surfaces).
            btn_positions[btn_count] = .{ .x = icon_x, .idx = pinned_idx, .is_shortcut = true };
            btn_count += 1;
        }
        icon_x += @as(i32, icon_slot);
    }

    // Separator
    if (running_count > 0) {
        gfx.drawVLine(icon_x + 4, pill_y + 8, pill_h -| 16, 0x555560);
        icon_x += @as(i32, @intCast(sep_w));
    }

    // Running windows
    for (wm.z_stack[0..wm.z_count]) |wi| {
        if (!wm.windows[wi].visible) continue;
        const is_focused = (@as(u8, @intCast(wi)) == wm.focused and !wm.windows[wi].minimized);

        if (is_focused) {
            gfx.fillRoundedRectAlpha(icon_x - 2, icon_y - 2, DOCK_ICON_SIZE + 4, DOCK_ICON_SIZE + 4, 6, 0x604488CC);
        }

        const icon = icons.iconForTitle(wm.windows[wi].title[0..wm.windows[wi].title_len]);
        if (icon) |ic| {
            gfx.drawIcon32(icon_x, icon_y, ic);
        } else {
            gfx.fillRoundedRect(icon_x, icon_y, DOCK_ICON_SIZE, DOCK_ICON_SIZE, 6, 0x4A4A4A);
            if (wm.windows[wi].title_len > 0) {
                gfx.drawString(icon_x + 12, icon_y + 8, wm.windows[wi].title[0..1], 0xFFFFFF, 0x4A4A4A);
            }
        }

        gfx.drawFilledCircle(icon_x + @as(i32, DOCK_ICON_SIZE / 2), pill_y + @as(i32, @intCast(pill_h)) + 3, 2, 0xFFFFFF);

        if (btn_count < wm.MAX_WINDOWS + 10) {
            btn_positions[btn_count] = .{ .x = icon_x, .idx = @intCast(wi), .is_shortcut = false };
            btn_count += 1;
        }
        icon_x += @as(i32, icon_slot);
    }
}

pub fn renderTooltip() void {
    if (!isTooltipVisible()) return;
    const idx: u8 = @intCast(hover_idx);
    if (idx >= btn_count) return;

    const btn = btn_positions[idx];
    var name: []const u8 = "";
    if (btn.is_shortcut) {
        if (btn.idx < pinned.list.len) name = pinned.list[btn.idx].name;
    } else {
        if (btn.idx < wm.MAX_WINDOWS and wm.slot_used[btn.idx]) {
            name = wm.windows[btn.idx].title[0..wm.windows[btn.idx].title_len];
        }
    }
    if (name.len == 0) return;

    const atlas = aa_font.getDefault16();
    const text_w = atlas.measure(name);
    const tip_w: u32 = text_w + 16;
    const tip_h: u32 = atlas.line_height + 10;
    const tip_x: i32 = btn.x + @as(i32, DOCK_ICON_SIZE / 2) - @as(i32, @intCast(tip_w / 2));
    const tip_y: i32 = pill_y - @as(i32, @intCast(tip_h)) - 6;

    // Track painted region so partial-blit paths flush the tooltip.
    const ux: u32 = if (tip_x < 0) 0 else @intCast(tip_x);
    const uy: u32 = if (tip_y < 0) 0 else @intCast(tip_y);
    dirty_rects.add(ux, uy, tip_w + 2, tip_h + 2);

    gfx.fillRoundedRectAlpha(tip_x + 1, tip_y + 1, tip_w, tip_h, 6, 0x30000000);
    gfx.fillGlass(tip_x, tip_y, tip_w, tip_h, 6, 0x38222228, 5);
    const text_y_offset: i32 = @intCast((tip_h -| atlas.line_height) / 2);
    aa_font.drawText(tip_x + 8, tip_y + text_y_offset, name, 0xFFFFFF, atlas);
}

fn itemAt(mx: i32) ?u8 {
    for (0..btn_count) |i| {
        const bx = btn_positions[i].x;
        if (mx >= bx and mx < bx + @as(i32, DOCK_ICON_SIZE)) {
            return @intCast(i);
        }
    }
    return null;
}

/// Resolve a click at (mx, my) to a dock action if one applies. Caller
/// should have already gated on inDockZone(my).
pub fn clickAt(mx: i32) ?Action {
    const btn_i = itemAt(mx) orelse return null;
    const btn = btn_positions[btn_i];
    return if (btn.is_shortcut)
        .{ .shortcut = btn.idx }
    else
        .{ .window = btn.idx };
}

/// Update hover state given the current cursor position. Returns true if
/// the dock visibly changed (hover started/stopped or tooltip just
/// appeared) — caller should mark the next frame .full when this is true.
pub fn updateHover(mx: i32, my: i32) bool {
    if (inDockZone(my)) {
        const new_hover: i8 = if (itemAt(mx)) |idx| @intCast(idx) else -1;
        if (new_hover != hover_idx) {
            hover_idx = new_hover;
            hover_timer = 0;
            return true;
        } else if (hover_idx >= 0) {
            if (hover_timer < 255) hover_timer += 1;
            if (hover_timer == TOOLTIP_FRAMES) return true; // show tooltip
        }
        return false;
    } else if (hover_idx >= 0) {
        hover_idx = -1;
        hover_timer = 0;
        return true;
    }
    return false;
}
