// The terminal emulator of a Terminal window: the grid of cells with its
// scrollback, and the byte stream that writes it (UTF-8, C0 controls, ESC and
// CSI sequences, SGR colours). What a program prints is its input: every
// byte goes through putCharOnWindow, in ring 0.

const std = @import("std");
const heap = @import("../../../mm/heap.zig");
const process = @import("../../../proc/process.zig");
const cfg = @import("../../../config.zig");
const MAX_WINDOWS: u32 = cfg.MAX_WINDOWS;
const SCROLL_LINES: u32 = cfg.SCROLL_LINES;
const wm = @import("../window.zig");
const Window = wm.Window;
const windows = &wm.windows;
const slot_used = &wm.slot_used;
const wake = @import("../wake.zig");
const theme = @import("../../theme.zig");
const ANSI_PALETTE = theme.ANSI_PALETTE;
const ATTR_DEFAULT = theme.ATTR_DEFAULT;
const ATTR_BOLD = theme.ATTR_BOLD;
const ATTR_INVERSE = theme.ATTR_INVERSE;
const ATTR_BG = theme.ATTR_BG;
const TAB_WIDTH = theme.TAB_WIDTH;
const BELL_FLASH_FRAMES = theme.BELL_FLASH_FRAMES;

pub const TERM_COLS: u32 = 80;
pub const TERM_ROWS: u32 = 25;

/// `string`: inside an OSC/DCS/APC string, dropped up to BEL or ESC \
/// (`string_esc`: its ESC came). `charset`: ESC ( and its kin take one
/// more byte.
pub const EscState = enum(u8) { idle, esc, csi, string, string_esc, charset };

/// Arguments one CSI sequence may carry: a bold truecolor foreground with a
/// truecolor background is eleven.
pub const CSI_ARGS: usize = 16;

pub const TerminalData = struct {
    text_buf: [TERM_COLS * TERM_ROWS]u8,
    attr_buf: [TERM_COLS * TERM_ROWS]u8,
    /// Per-cell 24-bit foreground RGB. Only consulted when the matching
    /// `attr_buf[i] & ATTR_RGB_FG` flag is set; otherwise the cell renders
    /// via `ANSI_PALETTE[attr & 0x0F]`. Costs 8 KB per terminal at the
    /// default 80×25 grid — worth it for actually-orange logos.
    fg_rgb_buf: [TERM_COLS * TERM_ROWS]u32,
    /// Per-cell background, consulted when `attr_buf[i] & ATTR_BG` is set.
    bg_rgb_buf: [TERM_COLS * TERM_ROWS]u32,
    text_row: u16,
    text_col: u16,
    cmd_buf: [128]u8,
    cmd_len: u8,
    history: [8][128]u8,
    history_len: [8]u8,
    history_count: u8,
    history_idx: u8,
    scroll_buf: [SCROLL_LINES * TERM_COLS]u8,
    scroll_attr_buf: [SCROLL_LINES * TERM_COLS]u8,
    scroll_fg_rgb_buf: [SCROLL_LINES * TERM_COLS]u32,
    scroll_bg_rgb_buf: [SCROLL_LINES * TERM_COLS]u32,
    scroll_write: u16,
    scroll_count: u16,
    scroll_view: u16,
    // Escape-sequence parser state. `idle` = consume chars normally;
    // `esc` = saw \x1b, awaiting `[`; `csi` = inside `\x1b[...<final>`,
    // accumulating numeric args separated by `;`.
    esc_state: EscState,
    // Enough slots that no sequence a program sends is cut short: digits
    // past the last slot would pile into it and corrupt it.
    csi_args: [CSI_ARGS]u16,
    csi_arg_count: u8,
    csi_has_arg: bool,
    /// The private marker of the sequence being read ('?', '>', '<', '='),
    /// 0 for none, and whether intermediate bytes came: such a sequence is
    /// not one of the plain ones its final byte would name.
    csi_private: u8 = 0,
    csi_inter: bool = false,
    /// UTF-8 in progress: continuation bytes still due, and the code point
    /// so far.
    utf_left: u8 = 0,
    utf_cp: u32 = 0,
    /// ESC 7 / CSI s.
    saved_row: u16 = 0,
    saved_col: u16 = 0,
    /// CSI ?25l: the program draws its own cursor.
    cursor_hidden: bool = false,
    cur_attr: u8,
    /// Most-recent truecolor fg, in 0x00RRGGBB. Only meaningful when
    /// `cur_attr & ATTR_RGB_FG` is set; SGR `38;2;...` writes both.
    cur_fg_rgb: u32,
    /// The background in force, meaningful when `cur_attr & ATTR_BG` is set.
    cur_bg_rgb: u32 = 0,
    bell_phase: u8,
    cursor_blink_anchor: u64,
    /// Deferred-wrap flag (xterm-style auto-margin). When a printable char
    /// lands in the last column we leave the cursor *at* that column with
    /// `pending_wrap=true` instead of immediately advancing+scrolling. The
    /// wrap commits only on the *next* printable write, and any cursor-
    /// moving control (\r, \n, \x08, CSI cursor moves) clears it. Without
    /// this, the shell's `redrawInputLine` (which writes prompt+content,
    /// possibly to col 79) scrolled the screen every time the user held
    /// backspace on a long line — duplicating the line into scrollback.
    pending_wrap: bool,
    /// The cells and the cursor block as the window's rows show them in the
    /// back buffer, so that output repaints only the rows it changed.
    /// Meaningful while `painted_valid`: a whole-window paint of the live
    /// view sets it, a paint of anything else over the rows drops it.
    painted_text: [TERM_COLS * TERM_ROWS]u8 = undefined,
    painted_attr: [TERM_COLS * TERM_ROWS]u8 = undefined,
    painted_rgb: [TERM_COLS * TERM_ROWS]u32 = undefined,
    painted_bg: [TERM_COLS * TERM_ROWS]u32 = undefined,
    /// Cell index of the cursor block drawn, NO_CURSOR for none.
    painted_cursor: u16 = NO_CURSOR,
    painted_scroll_count: u16 = 0,
    painted_valid: bool = false,
    /// Output has arrived since the rows were last brought up to date.
    rows_stale: bool = false,

    pub const NO_CURSOR: u16 = 0xFFFF;
};

pub fn allocTerminalData() ?*TerminalData {
    // Far above the kvmalloc threshold, so it comes from vmalloc and
    // opening a few terminals doesn't fragment the heap.
    const ptr = heap.kalloc(@sizeOf(TerminalData)) orelse return null;
    const td: *TerminalData = @ptrCast(@alignCast(ptr));
    td.* = .{
        .text_buf = [_]u8{' '} ** (TERM_COLS * TERM_ROWS),
        .attr_buf = [_]u8{ATTR_DEFAULT} ** (TERM_COLS * TERM_ROWS),
        .fg_rgb_buf = [_]u32{0} ** (TERM_COLS * TERM_ROWS),
        .bg_rgb_buf = [_]u32{0} ** (TERM_COLS * TERM_ROWS),
        .text_row = 0,
        .text_col = 0,
        .cmd_buf = [_]u8{0} ** 128,
        .cmd_len = 0,
        .history = [_][128]u8{[_]u8{0} ** 128} ** 8,
        .history_len = [_]u8{0} ** 8,
        .history_count = 0,
        .history_idx = 0,
        .scroll_buf = [_]u8{' '} ** (SCROLL_LINES * TERM_COLS),
        .scroll_attr_buf = [_]u8{ATTR_DEFAULT} ** (SCROLL_LINES * TERM_COLS),
        .scroll_fg_rgb_buf = [_]u32{0} ** (SCROLL_LINES * TERM_COLS),
        .scroll_bg_rgb_buf = [_]u32{0} ** (SCROLL_LINES * TERM_COLS),
        .scroll_write = 0,
        .scroll_count = 0,
        .scroll_view = 0,
        .esc_state = .idle,
        .csi_args = [_]u16{0} ** CSI_ARGS,
        .csi_arg_count = 0,
        .csi_has_arg = false,
        .cur_attr = ATTR_DEFAULT,
        .cur_fg_rgb = 0,
        .bell_phase = 0,
        .cursor_blink_anchor = 0,
        .pending_wrap = false,
    };
    return td;
}

pub fn freeTerminalData(td: *TerminalData) void {
    heap.kfreeAuto(@ptrCast(td));
}

/// A cell with either shows more than its glyph: a space of it is painted too.
pub const ATTR_PAINTS_BG = ATTR_INVERSE | ATTR_BG;

// Cell bytes past ASCII. 0x80..0x85 are the atlas's own block glyphs, which
// programs of ours write as bytes; the rest stand for characters the
// terminal draws itself, so that frames and block art join cell to cell.
pub const CELL_BULLET: u8 = 0x86;
pub const CELL_MIDDOT: u8 = 0x87;
pub const CELL_ELLIPSIS: u8 = 0x88;
pub const CELL_CHECK: u8 = 0x89;
pub const CELL_DEGREE: u8 = 0x8A;
/// Box drawing: + a mask of the arms (BOX_*), light and heavy.
pub const CELL_BOX: u8 = 0xA0;
pub const CELL_BOX_HEAVY: u8 = 0xB0;
/// Quadrants: + a mask (upper left 1, upper right 2, lower left 4, lower right 8).
pub const CELL_QUAD: u8 = 0xC0;
/// The lower (n+1)/8 of the cell, and its left (n+1)/8.
pub const CELL_LOW8: u8 = 0xD0;
pub const CELL_LEFT8: u8 = 0xD8;
pub const BOX_L: u8 = 1;
pub const BOX_R: u8 = 2;
pub const BOX_U: u8 = 4;
pub const BOX_D: u8 = 8;

/// The cell byte that shows code point `cp`: 0 for one that takes no cell.
fn cellFor(cp: u32) u8 {
    return switch (cp) {
        0x20...0x7E => @intCast(cp),
        0x00A0 => ' ',
        0x00B0, 0x02DA => CELL_DEGREE,
        0x00B7, 0x2219, 0x22C5 => CELL_MIDDOT,
        0x2022, 0x25CF, 0x23FA, 0x2B24, 0x25C9 => CELL_BULLET,
        0x25CB, 0x25EF, 0x25E6, 0x25CC => 'o',
        0x2026 => CELL_ELLIPSIS,
        0x2010...0x2015, 0x2212 => '-',
        0x2018, 0x2019 => '\'',
        0x201C, 0x201D => '"',
        0x2190, 0x2039, 0x276E, 0x25C0, 0x25C2 => '<',
        0x2192, 0x203A, 0x276F, 0x25B6, 0x25B8, 0x23F5 => '>',
        0x2191, 0x25B2, 0x25B4 => '^',
        0x2193, 0x25BC, 0x25BE => 'v',
        0x2713, 0x2714 => CELL_CHECK,
        0x2715...0x2718, 0x00D7 => 'x',
        0x2722...0x274B, 0x2217 => '*',
        0x23BF => CELL_BOX | BOX_U | BOX_R,
        0x2500...0x257F => boxCell(cp),
        0x2580...0x259F => blockCell(cp),
        // Zero width: joiners, variation selectors, combining marks.
        0x200B...0x200F, 0x2060, 0xFE00...0xFE0F, 0x0300...0x036F => 0,
        else => '?',
    };
}

fn boxCell(cp: u32) u8 {
    const arms: u8 = switch (cp) {
        0x2500, 0x2501, 0x2504, 0x2505, 0x2508, 0x2509, 0x254C, 0x254D, 0x2550, 0x257C, 0x257E => BOX_L | BOX_R,
        0x2502, 0x2503, 0x2506, 0x2507, 0x250A, 0x250B, 0x254E, 0x254F, 0x2551, 0x257D, 0x257F => BOX_U | BOX_D,
        0x250C...0x250F, 0x2552...0x2554, 0x256D => BOX_R | BOX_D,
        0x2510...0x2513, 0x2555...0x2557, 0x256E => BOX_L | BOX_D,
        0x2514...0x2517, 0x2558...0x255A, 0x2570 => BOX_U | BOX_R,
        0x2518...0x251B, 0x255B...0x255D, 0x256F => BOX_U | BOX_L,
        0x251C...0x2523, 0x255E...0x2560 => BOX_U | BOX_D | BOX_R,
        0x2524...0x252B, 0x2561...0x2563 => BOX_U | BOX_D | BOX_L,
        0x252C...0x2533, 0x2564...0x2566 => BOX_L | BOX_R | BOX_D,
        0x2534...0x253B, 0x2567...0x2569 => BOX_L | BOX_R | BOX_U,
        0x253C...0x254B, 0x256A...0x256C => BOX_L | BOX_R | BOX_U | BOX_D,
        0x2574, 0x2578 => BOX_L,
        0x2575, 0x2579 => BOX_U,
        0x2576, 0x257A => BOX_R,
        0x2577, 0x257B => BOX_D,
        0x2571 => return '/',
        0x2572 => return '\\',
        else => return 'X',
    };
    // The double lines are drawn heavy too.
    const heavy = switch (cp) {
        0x2501, 0x2503, 0x2505, 0x2507, 0x2509, 0x250B, 0x250F, 0x2513, 0x2517, 0x251B, 0x2523, 0x252B, 0x2533, 0x253B, 0x254B, 0x254D, 0x254F, 0x2550...0x256C, 0x2578...0x257B => true,
        else => false,
    };
    return (if (heavy) CELL_BOX_HEAVY else CELL_BOX) | arms;
}

fn blockCell(cp: u32) u8 {
    return switch (cp) {
        0x2580, 0x2594 => CELL_QUAD | 0x3,
        0x2581...0x2587 => CELL_LOW8 + @as(u8, @intCast(cp - 0x2581)),
        0x2588 => CELL_QUAD | 0xF,
        0x2589...0x258F => CELL_LEFT8 + @as(u8, @intCast(0x258F - cp)),
        0x2590, 0x2595 => CELL_QUAD | 0xA,
        0x2591 => 0x81,
        0x2592 => 0x82,
        0x2593 => 0x83,
        0x2596 => CELL_QUAD | 0x4,
        0x2597 => CELL_QUAD | 0x8,
        0x2598 => CELL_QUAD | 0x1,
        0x2599 => CELL_QUAD | 0xD,
        0x259A => CELL_QUAD | 0x9,
        0x259B => CELL_QUAD | 0x7,
        0x259C => CELL_QUAD | 0xB,
        0x259D => CELL_QUAD | 0x2,
        0x259E => CELL_QUAD | 0x6,
        else => CELL_QUAD | 0xE,
    };
}

/// A color of the 256-color palette: the 16 of the theme, the 6x6x6 cube,
/// the gray ramp.
fn color256(n: u16) u32 {
    if (n < 16) return ANSI_PALETTE[n];
    if (n < 232) {
        const lv = [6]u32{ 0, 95, 135, 175, 215, 255 };
        const i = n - 16;
        return (lv[i / 36] << 16) | (lv[(i / 6) % 6] << 8) | lv[i % 6];
    }
    const g: u32 = 8 + 10 * @as(u32, @min(n, 255) - 232);
    return (g << 16) | (g << 8) | g;
}

/// Bounds-checked text buffer index. Returns null if out of range.
pub inline fn textIdx(row: u16, col: u16) ?usize {
    if (row >= TERM_ROWS or col >= TERM_COLS) return null;
    return @as(usize, row) * TERM_COLS + @as(usize, col);
}

/// Append a char to the given terminal window's text buffer, advancing the
/// cursor and applying any in-flight escape sequence. Shared by:
///   - desktopPutChar (kernel CLI output, fallback path)
///   - the per-frame stdout-pipe drain step (user-space shell output)
///
/// Recognized control bytes:
///   - \n         newline (CR+LF; cursor → col 0, row+1, scroll if needed)
///   - \x08       backspace (cursor left, write space at new pos with cur_attr)
///   - \t         tab (cursor advances to next 8-column boundary)
///   - \x07       bell (sets bell_phase; main loop renders a red border flash)
///   - \x1b[...m  SGR — foreground and background color (16, 256, 24-bit), bold, inverse
///   - \x1b[r;cH  cursor position (1-indexed row;col)
///   - \x1b[nA/B/C/D   cursor up/down/right/left by n (default 1)
///   - \x1b[nJ    erase display (0 = below, 1 = above, 2 = all)
///   - \x1b[nK    erase line (0 = right, 1 = left, 2 = all)
/// Anything else (control bytes < 0x20, malformed escapes) is dropped silently.
/// Plain printable bytes are stored alongside `cur_attr` in `attr_buf` so the
/// render path can color each cell independently.
pub fn putCharOnWindow(w: *Window, c: u8) void {
    const t = w.term orelse return;
    // Any output activity restarts the cursor "on" half of the blink cycle —
    // looks dead otherwise when text scrolls past the cursor.
    t.cursor_blink_anchor = process.tick_count;
    switch (t.esc_state) {
        .idle => putCharIdle(w, t, c),
        .esc => putCharAfterEsc(w, t, c),
        .csi => putCharAfterCsi(w, t, c),
        // A string (a title, a query, a clipboard write): nothing of it is
        // ours. BEL or ESC \ ends it.
        .string => {
            if (c == '\x07') t.esc_state = .idle;
            if (c == '\x1b') t.esc_state = .string_esc;
        },
        .string_esc => if (c == '\\') {
            t.esc_state = .idle;
        } else putCharAfterEsc(w, t, c),
        .charset => t.esc_state = .idle,
    }
}

/// A byte of the UTF-8 stream: the cell byte of the character it finishes,
/// null while one is incomplete or takes no cell. A continuation byte with
/// no lead before it is a program's own byte-coded glyph and stands as is.
fn utf8Cell(t: *TerminalData, c: u8) ?u8 {
    if (c < 0x80) {
        t.utf_left = 0;
        return c;
    }
    if (c >= 0xC0) {
        t.utf_left = if (c >= 0xF0) 3 else if (c >= 0xE0) 2 else 1;
        t.utf_cp = c & (@as(u8, 0x3F) >> @as(u3, @intCast(t.utf_left)));
        return null;
    }
    if (t.utf_left == 0) return c;
    t.utf_cp = (t.utf_cp << 6) | (c & 0x3F);
    t.utf_left -= 1;
    if (t.utf_left != 0) return null;
    const cell = cellFor(t.utf_cp);
    return if (cell == 0) null else cell;
}

fn putCharIdle(w: *Window, t: *TerminalData, c: u8) void {
    switch (c) {
        '\x1b' => t.esc_state = .esc,
        '\x07' => {
            t.bell_phase = BELL_FLASH_FRAMES;
            wake.requestWake();
        },
        '\t' => {
            const next = (@as(u32, t.text_col) / TAB_WIDTH + 1) * TAB_WIDTH;
            t.text_col = @intCast(@min(next, TERM_COLS - 1));
            t.pending_wrap = false;
        },
        '\n' => {
            t.text_col = 0;
            t.text_row += 1;
            if (t.text_row >= TERM_ROWS) scrollWindow(w);
            t.pending_wrap = false;
        },
        '\r' => {
            t.text_col = 0;
            t.pending_wrap = false;
        },
        '\x08' => {
            if (t.text_col > 0) {
                t.text_col -= 1;
                writeCell(t, t.text_row, t.text_col, ' ', t.cur_attr);
            }
            t.pending_wrap = false;
        },
        else => {
            // Drop unhandled C0 control bytes rather than render garbage.
            if (c < 0x20) return;
            const cell = utf8Cell(t, c) orelse return;

            // Deferred wrap: if the previous printable write landed at the
            // last column with `pending_wrap=true`, commit the wrap NOW
            // (before this char). \r / \n / \x08 / CSI cursor moves clear
            // the flag, so a clean redraw that starts with `\r` never
            // triggers a scroll regardless of the previous line's length.
            if (t.pending_wrap) {
                t.text_col = 0;
                t.text_row += 1;
                if (t.text_row >= TERM_ROWS) scrollWindow(w);
                t.pending_wrap = false;
            }

            writeCell(t, t.text_row, t.text_col, cell, t.cur_attr);

            if (t.text_col + 1 >= TERM_COLS) {
                // Last column: park here, set the flag, don't scroll yet.
                t.pending_wrap = true;
            } else {
                t.text_col += 1;
            }
        },
    }
}

fn putCharAfterEsc(w: *Window, t: *TerminalData, c: u8) void {
    t.esc_state = .idle;
    switch (c) {
        '[' => {
            t.esc_state = .csi;
            t.csi_args = [_]u16{0} ** CSI_ARGS;
            t.csi_arg_count = 0;
            t.csi_has_arg = false;
            t.csi_private = 0;
            t.csi_inter = false;
        },
        // OSC, DCS, SOS, PM, APC.
        ']', 'P', 'X', '^', '_' => t.esc_state = .string,
        '(', ')', '*', '+', '#', '%' => t.esc_state = .charset,
        '7' => {
            t.saved_row = t.text_row;
            t.saved_col = t.text_col;
        },
        '8' => {
            t.text_row = t.saved_row;
            t.text_col = t.saved_col;
            t.pending_wrap = false;
        },
        // Index, next line, reverse index (the top row stays: no scroll down).
        'D', 'E' => {
            if (c == 'E') t.text_col = 0;
            t.text_row += 1;
            if (t.text_row >= TERM_ROWS) scrollWindow(w);
            t.pending_wrap = false;
        },
        'M' => {
            t.text_row -|= 1;
            t.pending_wrap = false;
        },
        // Reset.
        'c' => {
            t.cur_attr = ATTR_DEFAULT;
            t.cur_fg_rgb = 0;
            t.cur_bg_rgb = 0;
            t.cursor_hidden = false;
            t.text_row = 0;
            t.text_col = 0;
            t.pending_wrap = false;
            eraseDisplay(t, 2);
        },
        // ESC =, ESC > and the rest: nothing of ours.
        else => {},
    }
}

fn putCharAfterCsi(w: *Window, t: *TerminalData, c: u8) void {
    if (c >= '0' and c <= '9') {
        if (t.csi_arg_count < t.csi_args.len) {
            t.csi_args[t.csi_arg_count] = t.csi_args[t.csi_arg_count] *% 10 +% (c - '0');
            t.csi_has_arg = true;
        }
        return;
    }
    if (c == ';' or c == ':') {
        if (t.csi_arg_count + 1 < t.csi_args.len) t.csi_arg_count += 1;
        t.csi_has_arg = true;
        return;
    }
    // Parameter bytes '<' '=' '>' '?' mark a private sequence; 0x20..0x2F
    // are intermediates. Both belong to the sequence: taken, not printed.
    if (c >= 0x3C and c <= 0x3F) {
        t.csi_private = c;
        return;
    }
    if (c >= 0x20 and c <= 0x2F) {
        t.csi_inter = true;
        return;
    }
    // Final byte must be in 0x40..0x7E per ECMA-48; anything else aborts.
    if (c >= 0x40 and c <= 0x7E) {
        const n_args: u8 = if (t.csi_has_arg) (t.csi_arg_count + 1) else 0;
        dispatchCsi(w, t, c, n_args);
    }
    t.esc_state = .idle;
}

/// The terminal's own cursor shows unless the Linux program in it turned it
/// off to draw its own; one that died without turning it back on doesn't
/// leave the shell without.
pub fn cursorShown(w: *const Window, t: *const TerminalData) bool {
    return !(t.cursor_hidden and @import("../../../tty/tty.zig").hasLinuxProgram(w.tty));
}

/// What the terminal answers a program's query with: in through the keys'
/// pipe, as a terminal's reply comes.
fn termReply(w: *Window, bytes: []const u8) void {
    if (w.kb_pipe != 0xFF) _ = @import("../../../proc/pipe.zig").tryWrite(w.kb_pipe, bytes);
}

/// Cells [to, to+n) of the screen take what [from...) held; the four
/// buffers move together.
fn moveCells(t: *TerminalData, to: usize, from: usize, n: usize) void {
    if (to < from) {
        std.mem.copyForwards(u8, t.text_buf[to..][0..n], t.text_buf[from..][0..n]);
        std.mem.copyForwards(u8, t.attr_buf[to..][0..n], t.attr_buf[from..][0..n]);
        std.mem.copyForwards(u32, t.fg_rgb_buf[to..][0..n], t.fg_rgb_buf[from..][0..n]);
        std.mem.copyForwards(u32, t.bg_rgb_buf[to..][0..n], t.bg_rgb_buf[from..][0..n]);
    } else {
        std.mem.copyBackwards(u8, t.text_buf[to..][0..n], t.text_buf[from..][0..n]);
        std.mem.copyBackwards(u8, t.attr_buf[to..][0..n], t.attr_buf[from..][0..n]);
        std.mem.copyBackwards(u32, t.fg_rgb_buf[to..][0..n], t.fg_rgb_buf[from..][0..n]);
        std.mem.copyBackwards(u32, t.bg_rgb_buf[to..][0..n], t.bg_rgb_buf[from..][0..n]);
    }
}

/// Cells [at, at+n) become spaces in the colors in force: an erased
/// stretch takes the current background.
fn blankCells(t: *TerminalData, at: usize, n: usize) void {
    @memset(t.text_buf[at..][0..n], ' ');
    @memset(t.attr_buf[at..][0..n], t.cur_attr);
    @memset(t.fg_rgb_buf[at..][0..n], t.cur_fg_rgb);
    @memset(t.bg_rgb_buf[at..][0..n], t.cur_bg_rgb);
}

fn dispatchCsi(w: *Window, t: *TerminalData, final: u8, n_args: u8) void {
    if (t.csi_inter) return;
    if (t.csi_private != 0) {
        // Of the private modes only the cursor's showing is kept (?25);
        // mouse, paste and key reporting are never turned on.
        if (t.csi_private == '?' and (final == 'h' or final == 'l')) {
            for (t.csi_args[0..n_args]) |a| {
                if (a == 25) t.cursor_hidden = final == 'l';
            }
        }
        return;
    }
    const n: u32 = if (n_args >= 1 and t.csi_args[0] > 0) t.csi_args[0] else 1;
    const row: u32 = t.text_row;
    const col: u32 = t.text_col;
    switch (final) {
        'G', '`' => {
            t.text_col = @intCast(@min(n - 1, TERM_COLS - 1));
            t.pending_wrap = false;
        },
        'd' => {
            t.text_row = @intCast(@min(n - 1, TERM_ROWS - 1));
            t.pending_wrap = false;
        },
        'E' => {
            t.text_row = @intCast(@min(row + n, TERM_ROWS - 1));
            t.text_col = 0;
            t.pending_wrap = false;
        },
        'F' => {
            t.text_row = @intCast(row -| n);
            t.text_col = 0;
            t.pending_wrap = false;
        },
        's' => {
            t.saved_row = t.text_row;
            t.saved_col = t.text_col;
        },
        'u' => {
            t.text_row = t.saved_row;
            t.text_col = t.saved_col;
            t.pending_wrap = false;
        },
        // Scroll up: the top rows go to the scrollback, the cursor stays.
        'S' => {
            var i: u32 = 0;
            while (i < @min(n, TERM_ROWS)) : (i += 1) scrollWindow(w);
            t.text_row = @intCast(row);
        },
        // Erase, delete and insert characters in the row.
        'X' => if (row < TERM_ROWS and col < TERM_COLS) blankCells(t, row * TERM_COLS + col, @min(n, TERM_COLS - col)),
        'P', '@' => if (row < TERM_ROWS and col < TERM_COLS) {
            const at = row * TERM_COLS + col;
            const k = @min(n, TERM_COLS - col);
            const rest = TERM_COLS - col - k;
            if (final == 'P') {
                moveCells(t, at, at + k, rest);
                blankCells(t, at + rest, k);
            } else {
                moveCells(t, at + k, at, rest);
                blankCells(t, at, k);
            }
        },
        // Insert and delete lines at the cursor's row.
        'L', 'M' => if (row < TERM_ROWS) {
            const at = row * TERM_COLS;
            const k = @min(n, TERM_ROWS - row) * TERM_COLS;
            const rest = (TERM_ROWS - row) * TERM_COLS - k;
            if (final == 'M') {
                moveCells(t, at, at + k, rest);
                blankCells(t, at + rest, k);
            } else {
                moveCells(t, at + k, at, rest);
                blankCells(t, at, k);
            }
            t.text_col = 0;
            t.pending_wrap = false;
        },
        // Device status and attributes: a program that asks waits for it.
        'n' => if (n_args >= 1 and t.csi_args[0] == 6) {
            var buf: [16]u8 = undefined;
            termReply(w, std.fmt.bufPrint(&buf, "\x1b[{d};{d}R", .{ row + 1, col + 1 }) catch return);
        } else if (n_args >= 1 and t.csi_args[0] == 5) termReply(w, "\x1b[0n"),
        'c' => termReply(w, "\x1b[?1;2c"),
        'm' => sgr(t, n_args),
        'H', 'f' => {
            // Args are 1-indexed in ANSI; clamp to in-range cells.
            const to_col: u32 = if (n_args >= 2 and t.csi_args[1] > 0) t.csi_args[1] else 1;
            t.text_row = @intCast(@min(n - 1, TERM_ROWS - 1));
            t.text_col = @intCast(@min(to_col - 1, TERM_COLS - 1));
            t.pending_wrap = false;
        },
        'A' => {
            t.text_row = @intCast(row -| n);
            t.pending_wrap = false;
        },
        'B' => {
            t.text_row = @intCast(@min(row + n, TERM_ROWS - 1));
            t.pending_wrap = false;
        },
        'C' => {
            t.text_col = @intCast(@min(col + n, TERM_COLS - 1));
            t.pending_wrap = false;
        },
        'D' => {
            t.text_col = @intCast(col -| n);
            t.pending_wrap = false;
        },
        'J' => eraseDisplay(t, if (n_args >= 1) t.csi_args[0] else 0),
        'K' => eraseLine(t, if (n_args >= 1) t.csi_args[0] else 0),
        else => {},
    }
}

fn sgr(t: *TerminalData, n_args: u8) void {
    if (n_args == 0) {
        t.cur_attr = ATTR_DEFAULT;
        t.cur_fg_rgb = 0;
        t.cur_bg_rgb = 0;
        return;
    }
    var i: u8 = 0;
    while (i < n_args) : (i += 1) {
        const arg = t.csi_args[i];
        switch (arg) {
            0 => {
                t.cur_attr = ATTR_DEFAULT;
                t.cur_fg_rgb = 0;
                t.cur_bg_rgb = 0;
            },
            1 => t.cur_attr |= ATTR_BOLD,
            7 => t.cur_attr |= ATTR_INVERSE,
            22 => t.cur_attr &= ~ATTR_BOLD,
            27 => t.cur_attr &= ~ATTR_INVERSE,
            30...37 => {
                // Palette index — clear the truecolor flag so the cell
                // renders via ANSI_PALETTE again.
                t.cur_attr = (t.cur_attr & 0xF0 & ~theme.ATTR_RGB_FG) | @as(u8, @intCast(arg - 30));
            },
            // Bright fg (90..97) maps to bold + base color, mirroring how most
            // terminals render the "bright" series.
            90...97 => t.cur_attr = ((t.cur_attr & 0xF0 & ~theme.ATTR_RGB_FG) | @as(u8, @intCast(arg - 90))) | ATTR_BOLD,
            // 39 = default fg.
            39 => {
                t.cur_attr = (t.cur_attr & 0xF0 & ~theme.ATTR_RGB_FG) | (ATTR_DEFAULT & 0x0F);
                t.cur_fg_rgb = 0;
            },
            // Background: the 8 colors, their bright ones, the default.
            40...47 => setBg(t, ANSI_PALETTE[arg - 40]),
            100...107 => setBg(t, ANSI_PALETTE[arg - 100 + 8]),
            49 => {
                t.cur_attr &= ~ATTR_BG;
                t.cur_bg_rgb = 0;
            },
            // 38;2;R;G;B = 24-bit truecolor fg, 38;5;N = one of the 256;
            // 48 is the same for the background.
            38, 48 => {
                if (i + 1 >= n_args) break;
                const sub = t.csi_args[i + 1];
                var color: u32 = undefined;
                if (sub == 2) {
                    if (i + 4 >= n_args) break;
                    const r: u32 = @intCast(t.csi_args[i + 2] & 0xFF);
                    const g: u32 = @intCast(t.csi_args[i + 3] & 0xFF);
                    const b: u32 = @intCast(t.csi_args[i + 4] & 0xFF);
                    color = (r << 16) | (g << 8) | b;
                    i += 4;
                } else if (sub == 5) {
                    if (i + 2 >= n_args) break;
                    color = color256(t.csi_args[i + 2]);
                    i += 2;
                } else continue;
                if (arg == 38) {
                    t.cur_fg_rgb = color;
                    t.cur_attr |= theme.ATTR_RGB_FG;
                } else setBg(t, color);
            },
            else => {},
        }
    }
}

fn setBg(t: *TerminalData, color: u32) void {
    t.cur_bg_rgb = color;
    t.cur_attr |= ATTR_BG;
}

fn eraseDisplay(t: *TerminalData, mode: u16) void {
    const cells: usize = TERM_COLS * TERM_ROWS;
    const cur_idx: usize = @min(@as(usize, t.text_row) * TERM_COLS + t.text_col, cells - 1);
    switch (mode) {
        0 => blankCells(t, cur_idx, cells - cur_idx),
        1 => blankCells(t, 0, cur_idx + 1),
        2, 3 => blankCells(t, 0, cells),
        else => {},
    }
}

fn eraseLine(t: *TerminalData, mode: u16) void {
    if (t.text_row >= TERM_ROWS) return;
    const row_start: usize = @as(usize, t.text_row) * TERM_COLS;
    const col: usize = @min(t.text_col, TERM_COLS - 1);
    switch (mode) {
        0 => blankCells(t, row_start + col, TERM_COLS - col),
        1 => blankCells(t, row_start, col + 1),
        2 => blankCells(t, row_start, TERM_COLS),
        else => {},
    }
}

inline fn writeCell(t: *TerminalData, row: u16, col: u16, ch: u8, attr: u8) void {
    if (textIdx(row, col)) |idx| {
        t.text_buf[idx] = ch;
        t.attr_buf[idx] = attr;
        // The colors in force go with the attribute that says whether
        // they count.
        t.fg_rgb_buf[idx] = t.cur_fg_rgb;
        t.bg_rgb_buf[idx] = t.cur_bg_rgb;
    }
}

/// Append a string to the given window's text buffer. Used for boot/error
/// messages that the desktop writes directly into a Terminal window.
pub fn putStringOnWindow(window_idx: u8, data: []const u8) void {
    if (window_idx >= MAX_WINDOWS or !slot_used[window_idx]) return;
    const w = &windows[window_idx];
    if (!w.visible) return;
    for (data) |ch| putCharOnWindow(w, ch);
}

pub fn scrollWindow(w: *Window) void {
    const t = w.term orelse return;
    // Save top row (and its attrs) to the scrollback ring so colored output
    // remains colored when the user scrolls up later: the colors travel
    // alongside attr_buf.
    if (t.scroll_write >= SCROLL_LINES) t.scroll_write = 0;
    const sb_off = @as(u32, t.scroll_write) * TERM_COLS;
    @memcpy(t.scroll_buf[sb_off..][0..TERM_COLS], t.text_buf[0..TERM_COLS]);
    @memcpy(t.scroll_attr_buf[sb_off..][0..TERM_COLS], t.attr_buf[0..TERM_COLS]);
    @memcpy(t.scroll_fg_rgb_buf[sb_off..][0..TERM_COLS], t.fg_rgb_buf[0..TERM_COLS]);
    @memcpy(t.scroll_bg_rgb_buf[sb_off..][0..TERM_COLS], t.bg_rgb_buf[0..TERM_COLS]);
    t.scroll_write = @intCast((@as(u32, t.scroll_write) + 1) % SCROLL_LINES);
    if (t.scroll_count < SCROLL_LINES) t.scroll_count += 1;
    // Auto-scroll to live on new output
    t.scroll_view = 0;

    // The rows move up by one; the last comes in blank, in the colors in
    // force.
    const last: usize = (TERM_ROWS - 1) * TERM_COLS;
    moveCells(t, 0, TERM_COLS, last);
    blankCells(t, last, TERM_COLS);
    t.text_row = @intCast(TERM_ROWS - 1);
}
