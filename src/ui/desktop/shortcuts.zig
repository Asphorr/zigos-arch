// Desktop shortcut icons — the column of icons painted on the desktop
// background (top-left, below the menubar). Click selects, double-click
// launches the pinned app from `pinned.list`. Visual state (which icon
// is selected) lives here; the actual launch is delegated back to the
// caller so this module stays free of coupling to createWindow / shell
// spawn / smp.requestAppLoad logic.

const gfx = @import("../gfx.zig");
const aa_font = @import("../aa_font.zig");
const layout = @import("layout.zig");
const dirty_rects = @import("dirty.zig");
const pinned = @import("pinned.zig");

const MENUBAR_H = layout.MENUBAR_H;
pub const ICON_CELL_W: u32 = 80;
pub const ICON_CELL_H: u32 = 72;
pub const ICON_START_X: u32 = 24;
pub const ICON_START_Y: u32 = MENUBAR_H + 8;

const DOUBLE_CLICK_TICKS: u32 = 80;

var selected: i8 = -1;
var last_click_tick: u32 = 0;

pub fn render() void {
    dirty_rects.add(ICON_START_X -| 4, ICON_START_Y, ICON_CELL_W + 8, @as(u32, @intCast(pinned.list.len)) * ICON_CELL_H);
    const label_atlas = aa_font.getDefault16();
    for (pinned.list, 0..) |sc, si| {
        const y = ICON_START_Y + @as(u32, @intCast(si)) * ICON_CELL_H;
        const x = ICON_START_X;
        const is_sel = (selected >= 0 and @as(usize, @intCast(selected)) == si);

        if (is_sel) {
            gfx.fillRect(@intCast(x -| 4), @intCast(y -| 2), ICON_CELL_W, ICON_CELL_H, 0x3A4A6A);
        }

        const icon_x: i32 = @intCast(x + (ICON_CELL_W - 32) / 2);
        const icon_y: i32 = @intCast(y + 4);
        gfx.drawIcon32(icon_x, icon_y, sc.icon);

        // Label — SF Pro Text 16, alpha-blended over the existing
        // wallpaper/highlight pixels (drawIcon32 doesn't paint the strip
        // below the icon, so the wallpaper underneath shows through).
        aa_font.drawTextCentered(@intCast(x), @intCast(y + 40), ICON_CELL_W, sc.name, 0xEEEEEE, label_atlas);
    }
}

fn iconAt(mx: i32, my: i32) ?i8 {
    const start_y: i32 = @as(i32, ICON_START_Y);
    for (pinned.list, 0..) |_, si| {
        const y = start_y + @as(i32, @intCast(si)) * @as(i32, ICON_CELL_H);
        const x: i32 = @intCast(ICON_START_X -| 4);
        if (mx >= x and mx < x + @as(i32, ICON_CELL_W) and my >= y and my < y + @as(i32, ICON_CELL_H)) {
            return @intCast(si);
        }
    }
    return null;
}

/// Handle a click at (mx, my). Returns the shortcut index to launch on
/// double-click, otherwise null. `now` is an arbitrary tick counter (we
/// just compare against the previous click to gate the double).
pub const ClickResult = enum { miss, selected, launch };

pub fn handleClick(mx: i32, my: i32, now: u32) struct { result: ClickResult, launch_idx: usize } {
    if (iconAt(mx, my)) |icon_idx| {
        if (icon_idx == selected and (now -% last_click_tick) < DOUBLE_CLICK_TICKS) {
            const idx: usize = @intCast(icon_idx);
            selected = -1;
            return .{ .result = .launch, .launch_idx = idx };
        }
        selected = icon_idx;
        last_click_tick = now;
        return .{ .result = .selected, .launch_idx = 0 };
    }
    selected = -1;
    return .{ .result = .miss, .launch_idx = 0 };
}
