// Right-click context menu — opens on right-click over the desktop bg,
// a window titlebar or a dock app. Renders a glassy popup, tracks hover,
// dispatches the chosen item back to the caller (which actually executes
// the action — close/minimize a window, spawn a terminal, etc.).
//
// The module is rendering + state only. Action dispatch lives in
// desktop.zig (executeMenuItem) because it reaches into createWindow,
// closeWindow, startAnimation, etc., and dragging that surface in here
// would create a circular import with desktop.

const gfx = @import("../gfx.zig");
const aa_font = @import("../aa_font.zig");
const dirty_rects = @import("dirty.zig");
const layout = @import("layout.zig");

pub const Context = enum { none, desktop_bg, titlebar, dock_app };

pub const desktop_items = [_][]const u8{ "New Terminal", "Open App...", "Kernel Console", "Arrange Icons", "About ZigOS" };
pub const titlebar_items = [_][]const u8{ "Close", "Minimize" };
pub const dock_app_items = [_][]const u8{"New Window"};

const ITEM_H: u32 = 24;
const PAD_X: u32 = 12;
const PAD_Y: u32 = 5;
const MIN_W: u32 = 150;
const RADIUS: u32 = 8;
// How far the shadow reaches past the menu: sides and top, and bottom.
const SHADOW_SIDE = 3;
const SHADOW_BOTTOM = 7;

pub var active: bool = false;
pub var x: i32 = 0;
pub var y: i32 = 0;
pub var ctx: Context = .none;
pub var hover: i8 = -1;
/// The window slot for `.titlebar`, the pinned.list index for `.dock_app`.
pub var target_win: u8 = 0;

pub fn currentItems() []const []const u8 {
    return switch (ctx) {
        .desktop_bg => &desktop_items,
        .titlebar => &titlebar_items,
        .dock_app => &dock_app_items,
        .none => &[_][]const u8{},
    };
}

fn menuWidth(items: []const []const u8) u32 {
    const atlas = aa_font.getDefault13();
    var max_w: u32 = 0;
    for (items) |item| {
        const w = atlas.measure(item);
        if (w > max_w) max_w = w;
    }
    return @max(max_w + PAD_X * 2 + 16, MIN_W);
}

fn clampPos(mw_u: u32, mh_u: u32) [2]i32 {
    const mw: i32 = @intCast(mw_u);
    const mh: i32 = @intCast(mh_u);
    var cx = x;
    var cy = y;
    if (cx + mw + 6 > @as(i32, @intCast(gfx.screen_w)))
        cx = @as(i32, @intCast(gfx.screen_w)) - mw - 6;
    // A menu that would run off the bottom opens upward from the cursor.
    if (cy + mh + 8 > @as(i32, @intCast(gfx.screen_h)))
        cy = y - mh;
    if (cx < 4) cx = 4;
    if (cy < 4) cy = 4;
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

/// Open with the menu's bottom edge centred on (ax, ay).
pub fn openAbove(c: Context, ax: i32, ay: i32, win: u8) void {
    open(c, ax, ay, win);
    const items = currentItems();
    const mh: u32 = @as(u32, @intCast(items.len)) * ITEM_H + PAD_Y * 2;
    x = ax - @as(i32, @intCast(menuWidth(items) / 2));
    y = ay - @as(i32, @intCast(mh));
}

pub fn close() void {
    active = false;
    ctx = .none;
    hover = -1;
    // The caller repaints this frame; `painted` tells it where the menu was.
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

/// Screen rect [x0, y0, x1, y1) the last render() painted, null if none.
pub var painted: ?[4]i32 = null;

/// Screen rect [x0, y0, x1, y1) render() would paint now (menu plus its
/// shadow), null when the menu is closed.
pub fn rect() ?[4]i32 {
    if (!active) return null;
    const items = currentItems();
    const count: u32 = @intCast(items.len);
    if (count == 0) return null;
    const mw = menuWidth(items);
    const mh = count * ITEM_H + PAD_Y * 2;
    const pos = clampPos(mw, mh);
    return .{
        pos[0] - SHADOW_SIDE,
        pos[1] - SHADOW_SIDE,
        pos[0] + @as(i32, @intCast(mw)) + SHADOW_SIDE,
        pos[1] + @as(i32, @intCast(mh)) + SHADOW_BOTTOM,
    };
}

pub fn render() void {
    painted = rect();
    const r = painted orelse return;
    const items = currentItems();
    const count: u32 = @intCast(items.len);

    const mw = menuWidth(items);
    const mh = count * ITEM_H + PAD_Y * 2;
    const cx = r[0] + SHADOW_SIDE;
    const cy = r[1] + SHADOW_SIDE;

    // Track painted region so partial-blit paths flush this overlay.
    const ux: u32 = if (r[0] < 0) 0 else @intCast(r[0]);
    const uy: u32 = if (r[1] < 0) 0 else @intCast(r[1]);
    dirty_rects.add(ux, uy, @intCast(r[2] - r[0]), @intCast(r[3] - r[1]));

    // Shadow: a wide faint layer and a tighter one dropped 4 px, both
    // inside rect(). Then the glass and a hairline ring on its edge.
    gfx.fillRoundedRectAlpha(r[0], r[1], mw + 2 * SHADOW_SIDE, mh + SHADOW_SIDE + SHADOW_BOTTOM, RADIUS + 3, 0x14000000);
    gfx.fillRoundedRectAlpha(cx - 1, cy + 4, mw + 2, mh, RADIUS + 1, 0x26000000);
    gfx.fillGlass(cx, cy, mw, mh, RADIUS, 0xB0262629, 6);
    gfx.strokeRoundedRectAlpha(cx, cy, mw, mh, RADIUS, 0x30FFFFFF);

    const atlas = aa_font.getDefault13();
    const text_y_offset: i32 = @intCast((ITEM_H -| atlas.line_height) / 2);
    for (0..count) |i| {
        const item_y = cy + @as(i32, @intCast(PAD_Y + @as(u32, @intCast(i)) * ITEM_H));
        const hovered = (hover >= 0 and @as(u32, @intCast(hover)) == i);
        if (hovered) {
            gfx.fillRoundedRect(cx + 5, item_y, mw -| 10, ITEM_H, 5, layout.ACCENT);
        }
        const fg: u32 = if (hovered) 0xFFFFFF else 0xE6E6E8;
        aa_font.drawText(cx + @as(i32, PAD_X), item_y + text_y_offset, items[i], fg, atlas);
    }
}
