// App launcher: a panel near the top of the screen with a search field and
// the pinned apps that match it. State, hit-testing and rendering only;
// desktop.zig opens it, feeds it keys and clicks, and launches what it
// answers with.

const std = @import("std");
const gfx = @import("../gfx.zig");
const aa_font = @import("../aa_font.zig");
const keyboard = @import("../../driver/keyboard.zig");
const dirty_rects = @import("dirty.zig");
const layout = @import("layout.zig");
const pinned = @import("pinned.zig");

const W: u32 = 420;
const FIELD_H: u32 = 44;
const ROW_H: u32 = 40;
const MAX_ROWS: u8 = 6;
const LIST_PAD: u32 = 6;
const RADIUS: u32 = 12;
const TEXT_X: i32 = 16;
// How far the shadow reaches past the panel: sides and top, and bottom.
const SHADOW_SIDE = 3;
const SHADOW_BOTTOM = 7;

/// Longest query: with "/bin/" and ".elf" it still fits an app-load name.
const MAX_QUERY = 23;

pub const Choice = union(enum) {
    /// Index into pinned.list.
    app: u8,
    /// No app matched: the query, to be run as a program of that name.
    command: []const u8,
};

pub const Result = union(enum) {
    /// Nothing to repaint.
    none,
    /// Repaint; rect() may have changed.
    changed,
    closed,
    /// Closed, and this is to be started.
    launch: Choice,
};

pub var active: bool = false;
var query: [MAX_QUERY]u8 = undefined;
var query_len: u8 = 0;
var matches: [pinned.list.len]u8 = undefined;
var match_count: u8 = 0;
/// Selected match, and the first one shown.
var sel: u8 = 0;
var top: u8 = 0;

pub fn open() void {
    active = true;
    query_len = 0;
    filter();
}

pub fn close() void {
    // The caller repaints this frame; `painted` tells it where the panel was.
    active = false;
}

fn containsIgnoreCase(hay: []const u8, needle: []const u8) bool {
    return std.ascii.indexOfIgnoreCase(hay, needle) != null;
}

/// Names that start with the query, then names that only contain it.
fn filter() void {
    const q = query[0..query_len];
    match_count = 0;
    for ([_]bool{ true, false }) |want_prefix| {
        for (pinned.list, 0..) |sc, i| {
            const is_prefix = std.ascii.startsWithIgnoreCase(sc.name, q);
            if (is_prefix != want_prefix) continue;
            if (!is_prefix and !containsIgnoreCase(sc.name, q)) continue;
            matches[match_count] = @intCast(i);
            match_count += 1;
        }
    }
    sel = 0;
    top = 0;
}

/// Rows drawn under the field: the matches in view, or the one "Run" row
/// for a query that matches nothing.
fn rowCount() u8 {
    if (match_count == 0) return @intFromBool(query_len != 0);
    return @min(match_count, MAX_ROWS);
}

fn choice() ?Choice {
    if (match_count != 0) return .{ .app = matches[sel] };
    if (query_len != 0) return .{ .command = query[0..query_len] };
    return null;
}

fn moveSel(down: bool) bool {
    if (match_count == 0) return false;
    const old = sel;
    if (down) {
        if (sel + 1 < match_count) sel += 1;
    } else {
        sel -|= 1;
    }
    if (sel < top) top = sel;
    if (sel >= top + MAX_ROWS) top = sel + 1 - MAX_ROWS;
    return sel != old;
}

pub fn key(ch: u8) Result {
    switch (ch) {
        0x1B => {
            close();
            return .closed;
        },
        '\n', '\r' => {
            const c = choice() orelse return .none;
            close();
            return .{ .launch = c };
        },
        0x08, 0x7F => {
            if (query_len == 0) return .none;
            query_len -= 1;
            filter();
            return .changed;
        },
        keyboard.KEY_UP => return if (moveSel(false)) .changed else .none,
        keyboard.KEY_DOWN, '\t' => return if (moveSel(true)) .changed else .none,
        0x20...0x7E => {
            if (query_len == MAX_QUERY) return .none;
            query[query_len] = ch;
            query_len += 1;
            filter();
            return .changed;
        },
        else => return .none,
    }
}

fn panelHeight() u32 {
    const rows: u32 = rowCount();
    return FIELD_H + if (rows == 0) 0 else rows * ROW_H + LIST_PAD * 2;
}

fn panelX() i32 {
    return @divTrunc(@as(i32, @intCast(gfx.screen_w)) - @as(i32, W), 2);
}

fn panelY() i32 {
    return @intCast(gfx.screen_h / 5);
}

/// Row under the cursor, as an index into the rows drawn.
fn rowAt(mx: i32, my: i32) ?u8 {
    const px = panelX();
    if (mx < px or mx >= px + @as(i32, W)) return null;
    const list_y = panelY() + @as(i32, FIELD_H + LIST_PAD);
    if (my < list_y) return null;
    const row: u32 = @intCast(@divTrunc(my - list_y, @as(i32, ROW_H)));
    if (row >= rowCount()) return null;
    return @intCast(row);
}

fn inPanel(mx: i32, my: i32) bool {
    const px = panelX();
    const py = panelY();
    return mx >= px and mx < px + @as(i32, W) and my >= py and my < py + @as(i32, @intCast(panelHeight()));
}

/// The cursor moved. True if the selection followed it.
pub fn hover(mx: i32, my: i32) bool {
    if (match_count == 0) return false;
    const row = rowAt(mx, my) orelse return false;
    if (top + row == sel) return false;
    sel = top + row;
    return true;
}

/// A left press at (mx, my): on a row starts it, elsewhere in the panel
/// does nothing, outside closes.
pub fn click(mx: i32, my: i32) Result {
    if (rowAt(mx, my)) |row| {
        if (match_count != 0) sel = top + row;
        const c = choice() orelse return .none;
        close();
        return .{ .launch = c };
    }
    if (inPanel(mx, my)) return .none;
    close();
    return .closed;
}

/// Screen rect [x0, y0, x1, y1) the last render() painted, null if none.
pub var painted: ?[4]i32 = null;

/// Screen rect [x0, y0, x1, y1) render() would paint now (panel plus its
/// shadow), null when the launcher is closed.
pub fn rect() ?[4]i32 {
    if (!active) return null;
    const px = panelX();
    const py = panelY();
    return .{
        px - SHADOW_SIDE,
        py - SHADOW_SIDE,
        px + @as(i32, W) + SHADOW_SIDE,
        py + @as(i32, @intCast(panelHeight())) + SHADOW_BOTTOM,
    };
}

pub fn render() void {
    painted = rect();
    const r = painted orelse return;
    const px = r[0] + SHADOW_SIDE;
    const py = r[1] + SHADOW_SIDE;
    const ph = panelHeight();

    // Track painted region so partial-blit paths flush this overlay.
    const ux: u32 = if (r[0] < 0) 0 else @intCast(r[0]);
    const uy: u32 = if (r[1] < 0) 0 else @intCast(r[1]);
    dirty_rects.add(ux, uy, @intCast(r[2] - r[0]), @intCast(r[3] - r[1]));

    // The context menu's shadow, glass and ring, at this size.
    gfx.fillRoundedRectAlpha(r[0], r[1], W + 2 * SHADOW_SIDE, ph + SHADOW_SIDE + SHADOW_BOTTOM, RADIUS + 3, 0x14000000);
    gfx.fillRoundedRectAlpha(px - 1, py + 4, W + 2, ph, RADIUS + 1, 0x26000000);
    gfx.fillGlass(px, py, W, ph, RADIUS, 0xB0262629, 6);
    gfx.strokeRoundedRectAlpha(px, py, W, ph, RADIUS, 0x30FFFFFF);

    const atlas = aa_font.getDefault16();
    const lh: u32 = atlas.line_height;
    const field_text_y = py + @as(i32, @intCast((FIELD_H -| lh) / 2));
    const q = query[0..query_len];
    if (q.len == 0) {
        aa_font.drawText(px + TEXT_X, field_text_y, "Open an app", 0x8C8C92, atlas);
    } else {
        aa_font.drawText(px + TEXT_X, field_text_y, q, 0xFFFFFF, atlas);
    }
    const caret_x = px + TEXT_X + @as(i32, @intCast(atlas.measure(q))) + 1;
    gfx.fillRect(caret_x, field_text_y, 1, lh, layout.ACCENT);

    const rows = rowCount();
    if (rows == 0) return;
    gfx.fillRectAlpha(px + 1, py + @as(i32, FIELD_H), W - 2, 1, 0x20FFFFFF);

    const row_text_y: i32 = @intCast((ROW_H -| lh) / 2);
    var i: u8 = 0;
    while (i < rows) : (i += 1) {
        const ry = py + @as(i32, @intCast(FIELD_H + LIST_PAD + @as(u32, i) * ROW_H));
        if (match_count == 0) {
            // The one row: run the query as typed.
            gfx.fillRoundedRect(px + 6, ry + 2, W - 12, ROW_H - 4, 8, layout.ACCENT);
            const run = "Run ";
            aa_font.drawText(px + TEXT_X, ry + row_text_y, run, 0xFFFFFF, atlas);
            aa_font.drawText(px + TEXT_X + @as(i32, @intCast(atlas.measure(run))), ry + row_text_y, q, 0xFFFFFF, atlas);
            return;
        }
        const mi = top + i;
        const sc = &pinned.list[matches[mi]];
        if (mi == sel) gfx.fillRoundedRect(px + 6, ry + 2, W - 12, ROW_H - 4, 8, layout.ACCENT);
        gfx.drawIcon32(px + 14, ry + 4, sc.icon);
        aa_font.drawText(px + 14 + 32 + 12, ry + row_text_y, sc.name, if (mi == sel) 0xFFFFFF else 0xE6E6E8, atlas);
    }
}
