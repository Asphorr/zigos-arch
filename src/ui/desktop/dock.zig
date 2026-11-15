// Dock — bottom-centre glass pill. Pinned apps come first; a dot under one
// marks it running, and clicking it brings its windows forward (launching
// it when there are none). Windows of apps that aren't pinned follow a
// separator, in slot order so icons keep their place as focus moves.
// Hovering an icon highlights it and, after ~10 frames, shows a tooltip.
//
// State lives here (pill geometry, item positions, hover tracking). The
// compositor calls render()/renderTooltip() once per scene; the input
// handler calls clickAt()/menuAt()/updateHover() for hit-testing.

const std = @import("std");
const gfx = @import("../gfx.zig");
const aa_font = @import("../aa_font.zig");
const icons = @import("../icons.zig");
const layout = @import("layout.zig");
const dirty_rects = @import("dirty.zig");
const wm = @import("window.zig");
const pinned = @import("pinned.zig");

const TASKBAR_H = layout.TASKBAR_H;
const ICON = layout.DOCK_ICON_SIZE;
const ICON_PAD = layout.DOCK_ICON_PAD;
const PILL_PAD = layout.DOCK_PILL_PAD;
const PILL_H = layout.DOCK_PILL_H;
const PILL_R = layout.DOCK_PILL_RADIUS;

const SEP_W: u32 = 13;
const ICON_TOP: i32 = 7; // pill top to the icons
const DOT_Y: i32 = 45; // pill top to the running dots' center
const HOVER_PAD = 4;

const ItemKind = enum { app, window };
/// `idx` indexes pinned.list for an app, the window table for a window.
const Item = struct { x: i32, kind: ItemKind, idx: u8 };

const MAX_ITEMS = pinned.dock_indices.len + wm.MAX_WINDOWS;
var items: [MAX_ITEMS]Item = undefined;
var item_count: u8 = 0;
var pill_x: i32 = 0;
var pill_y: i32 = 0;
var pill_w: u32 = 0;

/// Hover tracking. -1 means cursor not over any dock item. The timer
/// counts frames since hover started; once it reaches TOOLTIP_FRAMES we
/// draw the tooltip.
pub var hover_idx: i8 = -1;
pub var hover_timer: u8 = 0;
pub const TOOLTIP_FRAMES: u8 = 10;

/// What a click on a dock item does.
pub const Action = union(enum) {
    /// Launch pinned.list[idx]: the app has no window.
    launch: u8,
    /// Raise and focus this window slot.
    window: u8,
};

/// What a right-click on a dock item addresses.
pub const MenuTarget = union(enum) { app: u8, window: u8 };

/// A dock item's menu: its target and the point the menu's bottom edge is
/// centred on, just above the pill.
pub const Menu = struct { target: MenuTarget, x: i32, y: i32 };

const MENU_GAP: i32 = 10;

pub fn dockY() i32 {
    return @intCast(gfx.screen_h - TASKBAR_H);
}

/// True iff `my` is within the dock's vertical band — used by the click
/// handler to decide whether to consult the dock first.
pub fn inDockZone(my: i32) bool {
    const top = dockY();
    return my >= top and my < top + @as(i32, TASKBAR_H);
}

/// True iff a tooltip is currently visible. While it is, the desktop
/// keeps partial window repaints from painting over it.
pub fn isTooltipVisible() bool {
    return hover_idx >= 0 and hover_timer >= TOOLTIP_FRAMES;
}

fn windowTitle(slot: u8) []const u8 {
    return wm.windows[slot].title[0..wm.windows[slot].title_len];
}

fn shown(slot: usize) bool {
    return wm.slot_used[slot] and wm.windows[slot].visible;
}

/// A window belongs to the app it is titled after (see pinned.nameForProcess).
fn belongsTo(slot: u8, pinned_idx: u8) bool {
    return std.mem.eql(u8, windowTitle(slot), pinned.list[pinned_idx].name);
}

fn isDockApp(slot: u8) bool {
    for (pinned.dock_indices) |pi| {
        if (belongsTo(slot, pi)) return true;
    }
    return false;
}

fn appRunning(pinned_idx: u8) bool {
    for (0..wm.MAX_WINDOWS) |s| {
        if (shown(s) and belongsTo(@intCast(s), pinned_idx)) return true;
    }
    return false;
}

fn appFocused(pinned_idx: u8) bool {
    const f = wm.focused;
    return shown(f) and !wm.windows[f].minimized and belongsTo(f, pinned_idx);
}

/// The window a click on a running app brings forward: its topmost one,
/// or, when that one already has the focus, its bottom-most, so repeated
/// clicks walk through all of them.
fn appWindow(pinned_idx: u8) ?u8 {
    var top: ?u8 = null;
    var bottom: ?u8 = null;
    for (wm.z_stack[0..wm.z_count]) |slot| {
        if (!wm.windows[slot].visible or !belongsTo(slot, pinned_idx)) continue;
        if (bottom == null) bottom = slot;
        top = slot;
    }
    const t = top orelse return null;
    if (t == wm.focused and !wm.windows[t].minimized) return bottom;
    return t;
}

pub fn render() void {
    const dy: i32 = dockY();
    dirty_rects.add(0, if (dy < 0) 0 else @intCast(dy), gfx.screen_w, TASKBAR_H);

    item_count = 0;
    for (pinned.dock_indices) |pi| {
        items[item_count] = .{ .x = 0, .kind = .app, .idx = pi };
        item_count += 1;
    }
    const app_count = item_count;
    for (0..wm.MAX_WINDOWS) |s| {
        if (!shown(s) or isDockApp(@intCast(s))) continue;
        items[item_count] = .{ .x = 0, .kind = .window, .idx = @intCast(s) };
        item_count += 1;
    }
    const has_sep = item_count > app_count;

    const slot_w = ICON + ICON_PAD;
    const content_w = @as(u32, item_count) * slot_w - ICON_PAD + (if (has_sep) SEP_W else 0);
    pill_w = @min(content_w + PILL_PAD * 2, gfx.screen_w -| 20);
    pill_x = @intCast((gfx.screen_w -| pill_w) / 2);
    pill_y = dy + @as(i32, TASKBAR_H - layout.DOCK_MARGIN_BOTTOM - PILL_H);

    // Soft shadow, glass, hairline ring. pillRect() covers all of it.
    gfx.fillRoundedRectAlpha(pill_x - 1, pill_y + 1, pill_w + 2, PILL_H + 4, PILL_R + 1, 0x16000000);
    gfx.fillRoundedRectAlpha(pill_x, pill_y + 3, pill_w, PILL_H, PILL_R, 0x2A000000);
    gfx.fillGlass(pill_x, pill_y, pill_w, PILL_H, PILL_R, 0x5A202024, 8);
    gfx.strokeRoundedRectAlpha(pill_x, pill_y, pill_w, PILL_H, PILL_R, 0x2CFFFFFF);

    var icon_x: i32 = pill_x + @as(i32, PILL_PAD);
    const icon_y: i32 = pill_y + ICON_TOP;
    for (items[0..item_count], 0..) |*it, i| {
        if (has_sep and i == app_count) {
            gfx.fillRectAlpha(icon_x + @as(i32, SEP_W / 2) - @as(i32, ICON_PAD / 2), pill_y + 10, 1, PILL_H - 20, 0x30FFFFFF);
            icon_x += @as(i32, SEP_W);
        }
        it.x = icon_x;

        if (hover_idx >= 0 and @as(usize, @intCast(hover_idx)) == i) {
            gfx.fillRoundedRectAlpha(icon_x - HOVER_PAD, icon_y - HOVER_PAD, ICON + 2 * HOVER_PAD, ICON + 2 * HOVER_PAD, 9, 0x26FFFFFF);
        }

        var running = true;
        var focused = false;
        switch (it.kind) {
            .app => {
                gfx.drawIcon32(icon_x, icon_y, pinned.list[it.idx].icon);
                running = appRunning(it.idx);
                focused = appFocused(it.idx);
            },
            .window => {
                const title = windowTitle(it.idx);
                if (icons.iconForTitle(title)) |ic| {
                    gfx.drawIcon32(icon_x, icon_y, ic);
                } else {
                    gfx.fillRoundedRect(icon_x + 2, icon_y + 2, ICON - 4, ICON - 4, 7, 0x4A4A50);
                    if (title.len > 0) {
                        const atlas = aa_font.getDefault13Semibold();
                        const ty: i32 = icon_y + @as(i32, @intCast((ICON - atlas.line_height) / 2));
                        aa_font.drawTextCentered(icon_x, ty, ICON, title[0..1], 0xFFFFFF, atlas);
                    }
                }
                focused = it.idx == wm.focused and !wm.windows[it.idx].minimized;
            },
        }
        if (running) {
            const dot: u32 = if (focused) 0xFFFFFFFF else 0x8CFFFFFF;
            gfx.drawFilledCircleAlpha(icon_x + @as(i32, ICON / 2), pill_y + DOT_Y, 2, dot);
        }
        icon_x += @as(i32, slot_w);
    }
}

/// Screen rect [x0, y0, x1, y1) the last render() painted: the pill and
/// its shadow. Null before the first one.
pub fn pillRect() ?[4]i32 {
    if (pill_w == 0) return null;
    return .{ pill_x - 1, pill_y, pill_x + @as(i32, @intCast(pill_w)) + 1, pill_y + @as(i32, PILL_H) + 5 };
}

const Tooltip = struct { name: []const u8, x: i32, y: i32, w: u32, h: u32 };

/// The tooltip for the current hover state, placed against the item
/// positions of the last render().
fn tooltip() ?Tooltip {
    if (!isTooltipVisible()) return null;
    const idx: u8 = @intCast(hover_idx);
    if (idx >= item_count) return null;

    const it = items[idx];
    const name: []const u8 = switch (it.kind) {
        .app => pinned.list[it.idx].name,
        .window => if (shown(it.idx)) windowTitle(it.idx) else "",
    };
    if (name.len == 0) return null;

    const atlas = aa_font.getDefault13();
    const tip_w: u32 = atlas.measure(name) + 20;
    const tip_h: u32 = atlas.line_height + 8;
    return .{
        .name = name,
        .x = it.x + @as(i32, ICON / 2) - @as(i32, @intCast(tip_w / 2)),
        .y = pill_y - @as(i32, @intCast(tip_h)) - 8,
        .w = tip_w,
        .h = tip_h,
    };
}

/// Screen rect [x0, y0, x1, y1) the last renderTooltip() painted, null if none.
pub var tooltip_painted: ?[4]i32 = null;

/// Screen rect [x0, y0, x1, y1) renderTooltip() would paint now (glass
/// plus its shadow), null when no tooltip is shown.
pub fn tooltipRect() ?[4]i32 {
    const t = tooltip() orelse return null;
    return .{ t.x, t.y, t.x + @as(i32, @intCast(t.w)), t.y + @as(i32, @intCast(t.h)) + 2 };
}

pub fn renderTooltip() void {
    tooltip_painted = tooltipRect();
    const t = tooltip() orelse return;
    const atlas = aa_font.getDefault13();

    // Track painted region so partial-blit paths flush the tooltip.
    const ux: u32 = if (t.x < 0) 0 else @intCast(t.x);
    const uy: u32 = if (t.y < 0) 0 else @intCast(t.y);
    dirty_rects.add(ux, uy, t.w, t.h + 2);

    gfx.fillRoundedRectAlpha(t.x, t.y + 2, t.w, t.h, 7, 0x30000000);
    gfx.fillGlass(t.x, t.y, t.w, t.h, 7, 0x70222226, 5);
    gfx.strokeRoundedRectAlpha(t.x, t.y, t.w, t.h, 7, 0x2CFFFFFF);
    const text_y: i32 = t.y + @as(i32, @intCast((t.h -| atlas.line_height) / 2));
    aa_font.drawTextCentered(t.x, text_y, t.w, t.name, 0xFFFFFF, atlas);
}

/// Item under (mx, my). The hit box is the icon grown by half the gap on
/// each side and the pill's full height, so there is no dead strip between
/// neighbours.
fn itemAt(mx: i32, my: i32) ?u8 {
    if (my < pill_y or my >= pill_y + @as(i32, PILL_H)) return null;
    const half_gap: i32 = @intCast(ICON_PAD / 2);
    for (items[0..item_count], 0..) |it, i| {
        if (mx >= it.x - half_gap and mx < it.x + @as(i32, ICON) + half_gap) return @intCast(i);
    }
    return null;
}

/// Resolve a left click at (mx, my) to a dock action if one applies.
pub fn clickAt(mx: i32, my: i32) ?Action {
    const it = items[itemAt(mx, my) orelse return null];
    return switch (it.kind) {
        .app => if (appWindow(it.idx)) |slot| .{ .window = slot } else .{ .launch = it.idx },
        .window => .{ .window = it.idx },
    };
}

/// The menu a right click at (mx, my) opens, if it is on an item.
pub fn menuAt(mx: i32, my: i32) ?Menu {
    const it = items[itemAt(mx, my) orelse return null];
    return .{
        .target = switch (it.kind) {
            .app => .{ .app = it.idx },
            .window => .{ .window = it.idx },
        },
        .x = it.x + @as(i32, ICON / 2),
        .y = pill_y - MENU_GAP,
    };
}

/// Hide the tooltip until the cursor has rested on an item again.
pub fn hideTooltip() void {
    hover_timer = 0;
}

pub const HoverChange = enum {
    none,
    /// The tooltip appeared: repaint its rect.
    tooltip,
    /// The hovered item changed: repaint the pill too.
    item,
};

/// Update hover state for the current cursor position. The tooltip timer
/// runs only while `tooltips` is set.
pub fn updateHover(mx: i32, my: i32, tooltips: bool) HoverChange {
    const new_hover: i8 = if (itemAt(mx, my)) |i| @intCast(i) else -1;
    if (new_hover != hover_idx) {
        hover_idx = new_hover;
        hover_timer = 0;
        return .item;
    }
    if (hover_idx >= 0 and tooltips) {
        if (hover_timer < 255) hover_timer += 1;
        if (hover_timer == TOOLTIP_FRAMES) return .tooltip;
    }
    return .none;
}
