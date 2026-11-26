// A terminal window's rows on screen: which rows differ from what the back
// buffer shows of them, and their repaint alone, without the window around
// them. The cursor block and the scrollback bar.

const std = @import("std");
const gfx = @import("../../gfx.zig");
const process = @import("../../../proc/process.zig");
const wm = @import("../window.zig");
const Window = wm.Window;
const windows = &wm.windows;
const z_stack = &wm.z_stack;
const dirty_rects_mod = @import("../dirty.zig");
const addDirtyRect = dirty_rects_mod.add;
const dock = @import("../dock.zig");
const theme = @import("../../theme.zig");
const WINDOW_BG = theme.WINDOW_BG;
const TERM_FG = theme.TERM_FG;
const layout = @import("../layout.zig");
const TASKBAR_H = layout.TASKBAR_H;
const TITLEBAR_H = layout.TITLEBAR_H;
const BORDER = layout.BORDER;
const CURSOR_BLINK_HALF_TICKS = theme.CURSOR_BLINK_HALF_TICKS;
const chrome = @import("../chrome.zig");
const scene = @import("../scene.zig");

const emulator = @import("emulator.zig");
const cells = @import("cells.zig");
const corners = @import("../corners.zig");
const desktop = @import("../../desktop.zig");
const TerminalData = emulator.TerminalData;
const TERM_COLS = emulator.TERM_COLS;
const TERM_ROWS = emulator.TERM_ROWS;
const cursorShown = emulator.cursorShown;
const FONT_W = cells.FONT_W;
const FONT_H = cells.FONT_H;
const drawTermCells = cells.drawTermCells;
const TERM_PAD = cells.TERM_PAD;
const CORNER_R = corners.CORNER_R;
const BOTTOM_CORNERS = corners.BOTTOM_CORNERS;
const saveCornerPixels = corners.saveCornerPixels;
const keepCornerPixels = corners.keepCornerPixels;
const paddedWinRect = chrome.paddedWinRect;
const MENUBAR_REACH = scene.MENUBAR_REACH;
const DOCK_REACH = scene.DOCK_REACH;
const borderColor = chrome.borderColor;

/// The cell the cursor block of terminal `idx` is drawn in right now, or
/// NO_CURSOR: unfocused, hidden, off the visible grid, or in the dark half
/// of its blink.
pub fn termCursorCell(idx: u8, w: *const Window, t: *const TerminalData, max_cols: u32, max_rows: u32) u16 {
    if (idx != wm.focused or t.text_col >= max_cols or t.text_row >= max_rows or !cursorShown(w, t)) return TerminalData.NO_CURSOR;
    const blink_on = ((process.tick_count -% t.cursor_blink_anchor) / CURSOR_BLINK_HALF_TICKS) & 1 == 0;
    if (!blink_on) return TerminalData.NO_CURSOR;
    return @intCast(@as(u32, t.text_row) * TERM_COLS + t.text_col);
}

/// The scrollback bar along the right edge of a terminal's content area.
pub fn drawTermScrollbar(w: *const Window, t: *const TerminalData) void {
    if (t.scroll_count == 0) return;
    const content_y = w.y + @as(i32, TITLEBAR_H);
    const content_h = w.height -| TITLEBAR_H;
    const max_rows = content_h / FONT_H;
    const total_lines = @as(u32, t.scroll_count) + TERM_ROWS;
    const sb_x = w.x + @as(i32, @intCast(w.width)) - 3;
    gfx.fillRect(sb_x, content_y + 1, 2, content_h -| 1, 0x2A2A2A);
    const thumb_h = @max(content_h * max_rows / total_lines, 8);
    const scroll_pos = total_lines - @as(u32, t.scroll_view) -| max_rows;
    const track_h = content_h -| thumb_h;
    const thumb_y_off = if (total_lines > max_rows) scroll_pos * track_h / (total_lines - max_rows) else 0;
    gfx.fillRect(sb_x, content_y + @as(i32, @intCast(thumb_y_off)), 2, thumb_h, 0x555555);
}

/// Paint one row of terminal `idx` into the back buffer — background,
/// cells, the cursor block if `cursor` lies on it — and record it as what
/// the row shows. The scrollbar's stretch of the row is painted over.
fn paintTermRow(idx: u8, row: u32, cursor: u16) void {
    const w = &windows[idx];
    const t = w.term orelse return;
    const content_y = w.y + @as(i32, TITLEBAR_H);
    const content_h = w.height -| TITLEBAR_H;
    const max_cols = (w.width - TERM_PAD * 2) / FONT_W;
    if (row >= TERM_ROWS or row >= content_h / FONT_H) return;

    const py: i32 = content_y + @as(i32, @intCast(row * FONT_H));

    // A row that reaches the bottom corners is painted across them: they
    // go back as they were.
    const in_corners = py + @as(i32, FONT_H) > w.y + @as(i32, @intCast(w.height)) - @as(i32, CORNER_R);
    const fx = w.x - @as(i32, BORDER);
    const fy = w.y - @as(i32, BORDER);
    if (in_corners) saveCornerPixels(fx, fy, w.width + BORDER * 2, w.height + BORDER * 2, BOTTOM_CORNERS);
    defer if (in_corners) keepCornerPixels(fx, fy, w.width + BORDER * 2, w.height + BORDER * 2, borderColor(w, idx == wm.focused), BOTTOM_CORNERS);

    // Clear the row background
    gfx.fillRect(w.x, py, w.width, FONT_H, WINDOW_BG);
    if (row == 0) gfx.drawHLine(w.x, content_y, w.width, 0x151515);

    const first = row * TERM_COLS;
    drawTermCells(w.x, py, t.text_buf[first..], t.attr_buf[first..], t.fg_rgb_buf[first..], t.bg_rgb_buf[first..], max_cols);

    const cursor_here = cursor != TerminalData.NO_CURSOR and cursor / TERM_COLS == row;
    if (cursor_here) {
        gfx.fillRect(
            w.x + @as(i32, @intCast(TERM_PAD + @as(u32, cursor % TERM_COLS) * FONT_W)),
            py,
            FONT_W,
            FONT_H,
            TERM_FG,
        );
    }

    @memcpy(t.painted_text[first..][0..TERM_COLS], t.text_buf[first..][0..TERM_COLS]);
    @memcpy(t.painted_attr[first..][0..TERM_COLS], t.attr_buf[first..][0..TERM_COLS]);
    @memcpy(t.painted_rgb[first..][0..TERM_COLS], t.fg_rgb_buf[first..][0..TERM_COLS]);
    @memcpy(t.painted_bg[first..][0..TERM_COLS], t.bg_rgb_buf[first..][0..TERM_COLS]);
    if (cursor_here) {
        t.painted_cursor = cursor;
    } else if (t.painted_cursor != TerminalData.NO_CURSOR and t.painted_cursor / TERM_COLS == row) {
        t.painted_cursor = TerminalData.NO_CURSOR;
    }
}

/// Fast path: re-render only the cursor's row of a terminal in the back
/// buffer.
pub fn renderTerminalRow(idx: u8) void {
    const w = &windows[idx];
    const t = w.term orelse return;
    if (!w.visible or w.minimized) return;
    const max_cols = (w.width - TERM_PAD * 2) / FONT_W;
    const max_rows = (w.height -| TITLEBAR_H) / FONT_H;
    paintTermRow(idx, t.text_row, termCursorCell(idx, w, t, max_cols, max_rows));
    redrawTermScrollbar(idx);
}

/// The scrollbar again after rows were painted over it, its foot kept out
/// of the rounded corner.
fn redrawTermScrollbar(idx: u8) void {
    const w = &windows[idx];
    const t = w.term orelse return;
    if (t.scroll_count == 0) return;
    const fx = w.x - @as(i32, BORDER);
    const fy = w.y - @as(i32, BORDER);
    saveCornerPixels(fx, fy, w.width + BORDER * 2, w.height + BORDER * 2, BOTTOM_CORNERS);
    drawTermScrollbar(w, t);
    keepCornerPixels(fx, fy, w.width + BORDER * 2, w.height + BORDER * 2, borderColor(w, idx == wm.focused), BOTTOM_CORNERS);
}

/// Whether the rows of terminal `idx` (at z_stack[z_pos]) can be painted on
/// their own: the back buffer shows the live view as recorded, and nothing
/// is drawn over the content area — no window or its shadow above, no
/// menubar or dock band. Overlays are the caller's (partialHitsOverlay).
pub fn termRowsPaintable(z_pos: usize, idx: u8) bool {
    const w = &windows[idx];
    const t = w.term orelse return false;
    if (!t.painted_valid or t.scroll_view != 0 or w.anim_type != .none) return false;
    if (!w.visible or w.minimized or desktop.backbuf == null) return false;
    const x0 = w.x;
    const y0 = w.y + @as(i32, TITLEBAR_H);
    const x1 = w.x + @as(i32, @intCast(w.width));
    const y1 = w.y + @as(i32, @intCast(w.height));
    const dock_y: i32 = dock.dockY();
    if (y0 < MENUBAR_REACH) return false;
    if (y0 < dock_y + @as(i32, TASKBAR_H) + DOCK_REACH and y1 > dock_y - DOCK_REACH) return false;
    for (z_stack[z_pos + 1 .. wm.z_count]) |above| {
        if (!windows[above].visible or windows[above].minimized) continue;
        const r = paddedWinRect(above);
        if (r[0] < x1 and x0 < r[2] and r[1] < y1 and y0 < r[3]) return false;
    }
    return true;
}

/// Bring the rows of terminal `idx` up to date in the back buffer: those
/// whose cells or cursor block differ from what they show are repainted,
/// and the bands painted go to the dirty tracker. For a window that
/// termRowsPaintable accepted. True if anything was painted.
pub fn repaintStaleRows(idx: u8) bool {
    const w = &windows[idx];
    const t = w.term orelse return false;
    const content_y = w.y + @as(i32, TITLEBAR_H);
    const content_h = w.height -| TITLEBAR_H;
    const max_cols = (w.width - TERM_PAD * 2) / FONT_W;
    const max_rows = @min(TERM_ROWS, content_h / FONT_H);
    const cursor = termCursorCell(idx, w, t, max_cols, max_rows);
    const old_cursor = t.painted_cursor;
    const wx: u32 = if (w.x < 0) 0 else @intCast(w.x);

    var painted = false;
    var band: ?u32 = null; // first row of the run being painted
    var row: u32 = 0;
    while (row <= max_rows) : (row += 1) {
        const stale = row < max_rows and blk: {
            // NO_CURSOR / TERM_COLS is past every row.
            if (cursor != old_cursor and (cursor / TERM_COLS == row or old_cursor / TERM_COLS == row)) break :blk true;
            const a = row * TERM_COLS;
            break :blk !std.mem.eql(u8, t.text_buf[a..][0..TERM_COLS], t.painted_text[a..][0..TERM_COLS]) or
                !std.mem.eql(u8, t.attr_buf[a..][0..TERM_COLS], t.painted_attr[a..][0..TERM_COLS]) or
                !std.mem.eql(u32, t.fg_rgb_buf[a..][0..TERM_COLS], t.painted_rgb[a..][0..TERM_COLS]) or
                !std.mem.eql(u32, t.bg_rgb_buf[a..][0..TERM_COLS], t.painted_bg[a..][0..TERM_COLS]);
        };
        if (stale) {
            paintTermRow(idx, row, cursor);
            if (band == null) band = row;
            painted = true;
        } else if (band) |b| {
            const y = content_y + @as(i32, @intCast(b * FONT_H));
            if (y >= 0) addDirtyRect(wx, @intCast(y), w.width, (row - b) * FONT_H);
            band = null;
        }
    }
    const bar_moved = t.scroll_count != t.painted_scroll_count;
    if (painted or bar_moved) redrawTermScrollbar(idx);
    if (bar_moved) {
        t.painted_scroll_count = t.scroll_count;
        const bar_x = w.x + @as(i32, @intCast(w.width)) - 3;
        if (bar_x >= 0 and content_y >= 0) addDirtyRect(@intCast(bar_x), @intCast(content_y), 3, content_h);
        painted = true;
    }
    return painted;
}
