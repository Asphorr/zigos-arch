// Top menu bar — glassy backdrop with the "ZigOS" wordmark on the left,
// the focused window's title next to it, and a HH:MM clock pinned to the
// right edge. One frame at the top of every desktop scene.

const gfx = @import("../gfx.zig");
const aa_font = @import("../aa_font.zig");
const rtc = @import("../../time/rtc.zig");
const layout = @import("layout.zig");
const dirty_rects = @import("dirty.zig");

const MENUBAR_H = layout.MENUBAR_H;

/// Render the menubar. `focused_title` is the visible window's title (or
/// null if no window is focused / it isn't visible). The caller decides
/// what counts as focused so this stays free of window-state coupling.
pub fn render(focused_title: ?[]const u8) void {
    dirty_rects.add(0, 0, gfx.screen_w, MENUBAR_H);
    // Glass backdrop (blur + tint)
    gfx.blurRegion(0, 0, gfx.screen_w, MENUBAR_H, 6);
    gfx.saturateRegion(0, 0, gfx.screen_w, MENUBAR_H, 40);
    gfx.fillRectAlpha(0, 0, gfx.screen_w, MENUBAR_H, 0x381A1A1E);
    // Bottom border + top highlight
    gfx.drawHLine(0, @as(i32, MENUBAR_H) - 1, gfx.screen_w, 0x333338);
    gfx.drawHLine(0, 0, gfx.screen_w, 0x18FFFFFF);

    // SF Pro Text 16 for everything in the bar. line_height ~19, MENUBAR_H=28
    // → leave 4-5px above and below.
    const atlas = aa_font.getDefault16();
    const text_y: i32 = @divTrunc(@as(i32, MENUBAR_H) - @as(i32, atlas.line_height), 2);

    aa_font.drawText(12, text_y, "ZigOS", 0xC0C0CC, atlas);

    const zigos_w: i32 = @intCast(atlas.measure("ZigOS"));
    gfx.drawVLine(12 + zigos_w + 8, 6, MENUBAR_H - 12, 0x444448);

    if (focused_title) |title| {
        aa_font.drawText(12 + zigos_w + 18, text_y, title, 0xEEEEEE, atlas);
    }

    const time = rtc.readTime();
    var clock_buf: [5]u8 = undefined;
    clock_buf[0] = '0' + time.hour / 10;
    clock_buf[1] = '0' + time.hour % 10;
    clock_buf[2] = ':';
    clock_buf[3] = '0' + time.minute / 10;
    clock_buf[4] = '0' + time.minute % 10;
    const clock_w: i32 = @intCast(atlas.measure(&clock_buf));
    aa_font.drawText(@as(i32, @intCast(gfx.screen_w)) - clock_w - 12, text_y, &clock_buf, 0xEEEEEE, atlas);
}
