// Right-click context menu — opens on right-click over the desktop bg
// or a window titlebar. Renders a glassy popup, tracks hover, dispatches
// the chosen item back to the caller (which actually executes the
// action — close/minimize a window, spawn a terminal, etc.).
//
// The module is rendering + state only. Action dispatch lives in
// desktop.zig (executeMenuItem) because it reaches into createWindow,
// closeWindow, startAnimation, etc., and dragging that surface in here
// would create a circular import with desktop.

const gfx = @import("../gfx.zig");
const aa_font = @import("../aa_font.zig");
const dirty_rects = @import("dirty.zig");

pub const Context = enum { none, desktop_bg, titlebar };

pub const desktop_items = [_][]const u8{ "New Terminal", "Run App...", "Arrange Icons", "About ZigOS" };
pub const titlebar_items = [_][]const u8{ "Close", "Minimize" };

const ITEM_H: u32 = 28;
const PAD_X: u32 = 14;
const PAD_Y: u32 = 6;

pub var active: bool = false;
pub var x: i32 = 0;
pub var y: i32 = 0;
pub var ctx: Context = .none;
pub var hover: i8 = -1;
pub var target_win: u8 = 0;

pub fn currentItems() []const []const u8 {
    return switch (ctx) {
        .desktop_bg => &desktop_items,
        .titlebar => &titlebar_items,
        .none => &[_][]const u8{},
    };
}

fn menuWidth(items: []const []const u8) u32 {
    const atlas = aa_font.getDefault16();
    var max_w: u32 = 0;
    for (items) |item| {
        const w = atlas.measure(item);
        if (w > max_w) max_w = w;
    }
    return max_w + PAD_X * 2;
}

fn clampPos(mw_u: u32, mh_u: u32) [2]i32 {
    const mw: i32 = @intCast(mw_u);
    const mh: i32 = @intCast(mh_u);
    var cx = x;
    var cy = y;
    if (cx + mw + 6 > @as(i32, @intCast(gfx.screen_w)))
        cx = @as(i32, @intCast(gfx.screen_w)) - mw - 6;
    if (cy + mh + 6 > @as(i32, @intCast(gfx.screen_h)))
        cy = @as(i32, @intCast(gfx.screen_h)) - mh - 6;
    if (cx < 2) cx = 2;
    if (cy < 2) cy = 2;
    return .{ cx, cy };
}

pub fn open(c: Context, mx: i32, my: i32, win: u8) void {
    active = true;
    ctx = c;
    x = mx;
    y = my;
    hover = -1;
    target_win = win;
}

pub fn close() void {
    active = false;
    ctx = .none;
    hover = -1;
    // The menu's painted region won't be re-rendered next frame (active=false
    // makes render() a no-op), so partial blit would leave its pixels stale.
    // Request a full repaint instead.
    dirty_rects.force_full_kind = true;
}

pub fn itemAt(mx: i32, my: i32) i8 {
    const items = currentItems();
    const count: u32 = @intCast(items.len);
    if (count == 0) return -1;
    const mw: i32 = @intCast(menuWidth(items));
    const mh: i32 = @intCast(count * ITEM_H + PAD_Y * 2);
    const pos = clampPos(@intCast(mw), @intCast(mh));
    const cx = pos[0];
    const cy = pos[1];
    if (mx < cx or mx >= cx + mw) return -1;
    if (my < cy or my >= cy + mh) return -1;
    const rel_y = my - cy;
    if (rel_y < @as(i32, PAD_Y)) return -1;
    const idx: u32 = @intCast(rel_y - @as(i32, PAD_Y));
    const item_idx = idx / ITEM_H;
    if (item_idx >= count) return -1;
    return @intCast(item_idx);
}

/// Update hover for the current cursor position. Returns true iff the
/// hovered item changed (caller should mark dirty=full).
pub fn updateHover(mx: i32, my: i32) bool {
    const new_hover = itemAt(mx, my);
    if (new_hover != hover) {
        hover = new_hover;
        return true;
    }
    return false;
}

pub fn render() void {
    if (!active) return;
    const items = currentItems();
    const count: u32 = @intCast(items.len);
    if (count == 0) return;

    const mw = menuWidth(items);
    const mh = count * ITEM_H + PAD_Y * 2;
    const CR: u32 = 8;

    const pos = clampPos(mw, mh);
    const cx = pos[0];
    const cy = pos[1];

    // Track painted region so partial-blit paths flush this overlay.
    // +6 px on right, +8 px on bottom for the two-layer soft shadow,
    // +3 px on left/top for the ambient ring + 1-px highlight border.
    const ux: u32 = if (cx < 3) 0 else @intCast(cx - 3);
    const uy: u32 = if (cy < 2) 0 else @intCast(cy - 2);
    dirty_rects.add(ux, uy, mw + 9, mh + 10);

    // Two-layer soft shadow: a wider ambient ring at low alpha plus a
    // tighter key shadow offset down by 3 px. Matches the window-shadow
    // vocabulary — soft, lifted, never inky.
    gfx.fillRoundedRectAlpha(cx - 2, cy - 1, mw + 4, mh + 6, CR + 2, 0x18000000);
    gfx.fillRoundedRectAlpha(cx + 2, cy + 3, mw + 2, mh + 2, CR, 0x28000000);
    gfx.fillGlass(cx, cy, mw, mh, CR, 0x402C2C30, 6);
    gfx.fillRoundedRectAlpha(cx - 1, cy - 1, mw + 2, mh + 2, CR + 1, 0x20FFFFFF);

    const atlas = aa_font.getDefault16();
    const text_y_offset: i32 = @intCast((ITEM_H -| atlas.line_height) / 2);
    for (0..count) |i| {
        const item_y = cy + @as(i32, @intCast(PAD_Y + @as(u32, @intCast(i)) * ITEM_H));
        const hovered = (hover >= 0 and @as(u32, @intCast(hover)) == i);

        if (hovered) {
            gfx.fillRoundedRect(cx + 4, item_y + 1, mw -| 8, ITEM_H -| 2, 4, 0x4488CC);
        }

        aa_font.drawText(cx + @as(i32, PAD_X), item_y + text_y_offset, items[i], 0xFFFFFF, atlas);

        if (i + 1 < count) {
            gfx.drawHLine(cx + @as(i32, PAD_X), item_y + @as(i32, ITEM_H) - 1, mw -| PAD_X * 2, 0x3A3A3E);
        }
    }
}
