// How a terminal's cells are drawn: the cell size, the colours of a cell from
// its attribute byte, glyphs from the mono atlas, and the box, block and
// shade characters, which are drawn as shapes so that they join cell to cell.

const gfx = @import("../../gfx.zig");
const theme = @import("../../theme.zig");
const WINDOW_BG = theme.WINDOW_BG;
const aa_font = @import("../../aa_font.zig");
const ANSI_PALETTE = theme.ANSI_PALETTE;
const ATTR_BOLD = theme.ATTR_BOLD;
const ATTR_INVERSE = theme.ATTR_INVERSE;
const ATTR_BG = theme.ATTR_BG;

const emulator = @import("emulator.zig");
const TERM_COLS = emulator.TERM_COLS;
const CELL_BULLET = emulator.CELL_BULLET;
const CELL_MIDDOT = emulator.CELL_MIDDOT;
const CELL_ELLIPSIS = emulator.CELL_ELLIPSIS;
const CELL_CHECK = emulator.CELL_CHECK;
const CELL_DEGREE = emulator.CELL_DEGREE;
const CELL_BOX = emulator.CELL_BOX;
const CELL_BOX_HEAVY = emulator.CELL_BOX_HEAVY;
const CELL_QUAD = emulator.CELL_QUAD;
const CELL_LOW8 = emulator.CELL_LOW8;
const CELL_LEFT8 = emulator.CELL_LEFT8;
const BOX_L = emulator.BOX_L;
const BOX_R = emulator.BOX_R;
const BOX_U = emulator.BOX_U;
const BOX_D = emulator.BOX_D;
const ATTR_PAINTS_BG = emulator.ATTR_PAINTS_BG;

// Terminal cell size — sized to fit the SF Mono 14px glyph (advance=9, line_height=18).
// Update both constants together if a different mono atlas size is chosen.
pub const FONT_W: u32 = 9;
pub const FONT_H: u32 = 18;

pub const TERM_PAD: u32 = 4;
/// Wide enough to show every column between the two paddings.
pub const TERM_WIN_W: u32 = TERM_COLS * FONT_W + TERM_PAD * 2;

const CellColors = struct { fg: u32, bg: u32 };

inline fn cellColors(attr: u8, fg_rgb: u32, bg_rgb: u32) CellColors {
    var fg: u32 = undefined;
    if ((attr & theme.ATTR_RGB_FG) != 0) {
        fg = fg_rgb;
    } else {
        const idx: u8 = attr & 0x0F;
        const palette_idx: u8 = if ((attr & ATTR_BOLD) != 0) (idx | 0x08) else idx;
        fg = ANSI_PALETTE[palette_idx];
    }
    var bg: u32 = if ((attr & ATTR_BG) != 0) bg_rgb else WINDOW_BG;
    if ((attr & ATTR_INVERSE) != 0) {
        const swap = fg;
        fg = bg;
        bg = swap;
    }
    return .{ .fg = fg, .bg = bg };
}

/// Render one terminal cell at top-left (x, y): fills the cell rect with `bg`,
/// then blits the SF Mono glyph for `ch` in `fg`. Called once per non-space
/// cell from the three terminal-render paths below.
inline fn drawTermChar(x: i32, y: i32, ch: u8, fg: u32, bg: u32) void {
    gfx.fillRect(x, y, FONT_W, FONT_H, bg);
    if (ch >= CELL_BULLET and (ch <= CELL_DEGREE or ch >= CELL_BOX)) return drawCellShape(x, y, ch, fg);
    const buf: [1]u8 = .{ch};
    aa_font.drawText(x, y, &buf, fg, aa_font.getDefaultMono());
}

/// One row of terminal cells of the window at `win_x`, its top at `y`: every
/// cell that shows a glyph or a background of its own. The row's WINDOW_BG
/// is the caller's.
pub fn drawTermCells(win_x: i32, y: i32, text: []const u8, attrs: []const u8, fgs: []const u32, bgs: []const u32, max_cols: u32) void {
    var col: u32 = 0;
    while (col < TERM_COLS and col < max_cols) : (col += 1) {
        const ch = text[col];
        const attr = attrs[col];
        if (ch == ' ' and (attr & ATTR_PAINTS_BG) == 0) continue;
        const colors = cellColors(attr, fgs[col], bgs[col]);
        drawTermChar(win_x + @as(i32, @intCast(TERM_PAD + col * FONT_W)), y, ch, colors.fg, colors.bg);
    }
}

fn drawCellShape(x: i32, y: i32, ch: u8, fg: u32) void {
    const cx: i32 = x + @as(i32, FONT_W / 2);
    const cy: i32 = y + @as(i32, FONT_H / 2);
    switch (ch) {
        CELL_BOX...CELL_BOX_HEAVY + 0x0F => {
            const th: u32 = if (ch >= CELL_BOX_HEAVY) 3 else 1;
            const o: i32 = @intCast(th / 2);
            // Each arm runs from its edge to just past the middle: corners join.
            if (ch & BOX_L != 0) gfx.fillRect(x, cy - o, FONT_W / 2 + th - th / 2, th, fg);
            if (ch & BOX_R != 0) gfx.fillRect(cx - o, cy - o, FONT_W - FONT_W / 2 + th / 2, th, fg);
            if (ch & BOX_U != 0) gfx.fillRect(cx - o, y, th, FONT_H / 2 + th - th / 2, fg);
            if (ch & BOX_D != 0) gfx.fillRect(cx - o, cy - o, th, FONT_H - FONT_H / 2 + th / 2, fg);
        },
        CELL_QUAD...CELL_QUAD + 0x0F => {
            const hw: u32 = FONT_W / 2;
            const hh: u32 = FONT_H / 2;
            if (ch & 1 != 0) gfx.fillRect(x, y, hw, hh, fg);
            if (ch & 2 != 0) gfx.fillRect(cx, y, FONT_W - hw, hh, fg);
            if (ch & 4 != 0) gfx.fillRect(x, cy, hw, FONT_H - hh, fg);
            if (ch & 8 != 0) gfx.fillRect(cx, cy, FONT_W - hw, FONT_H - hh, fg);
        },
        CELL_LOW8...CELL_LOW8 + 7 => {
            const hgt: u32 = FONT_H * (@as(u32, ch - CELL_LOW8) + 1) / 8;
            gfx.fillRect(x, y + @as(i32, @intCast(FONT_H - hgt)), FONT_W, hgt, fg);
        },
        CELL_LEFT8...CELL_LEFT8 + 7 => gfx.fillRect(x, y, @max(1, FONT_W * (@as(u32, ch - CELL_LEFT8) + 1) / 8), FONT_H, fg),
        CELL_BULLET => {
            // A disc of radius 3.
            const half = [7]u32{ 1, 2, 3, 3, 3, 2, 1 };
            for (half, 0..) |hw, i| gfx.fillRect(cx - @as(i32, @intCast(hw)), cy - 3 + @as(i32, @intCast(i)), 2 * hw + 1, 1, fg);
        },
        CELL_MIDDOT => gfx.fillRect(cx - 1, cy - 1, 2, 2, fg),
        CELL_ELLIPSIS => {
            const base: i32 = y + @as(i32, FONT_H * 3 / 4);
            gfx.fillRect(x + 1, base, 1, 2, fg);
            gfx.fillRect(cx, base, 1, 2, fg);
            gfx.fillRect(x + @as(i32, FONT_W) - 2, base, 1, 2, fg);
        },
        CELL_CHECK => {
            // Down three to the right, then up six.
            var i: i32 = 0;
            while (i < 3) : (i += 1) gfx.fillRect(x + 1 + i, cy + i, 1, 2, fg);
            i = 0;
            while (i < 5) : (i += 1) gfx.fillRect(x + 4 + i, cy + 2 - i, 1, 2, fg);
        },
        CELL_DEGREE => {
            // A ring of 4 at the height of a capital's top.
            gfx.fillRect(x + 3, y + 3, 2, 1, fg);
            gfx.fillRect(x + 3, y + 6, 2, 1, fg);
            gfx.fillRect(x + 2, y + 4, 1, 2, fg);
            gfx.fillRect(x + 5, y + 4, 1, 2, fg);
        },
        else => {},
    }
}
