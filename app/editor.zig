// Editor — plain text, with Zig highlighting for .zig files.
//
// Ctrl+S saves (asking for a name when there is none), Ctrl+F finds and
// F3 or Ctrl+G finds the next, Ctrl+C/X/V/A work on the selection, and
// Ctrl+Q closes at once. Esc closes too, unless there are unsaved changes.

const libc = @import("libc");
const gfx = @import("graphics");
const fa = @import("font_atlas");
const ui = @import("ui");
const app = @import("app");

const TEXT_FG: u32 = 0xD4D4D8;
const SEL_BG: u32 = 0x264F78;
const CURRENT_LINE_BG: u32 = 0x252528;
const CURSOR_COLOR: u32 = 0xFFFFFF;
const LINE_NUM_FG: u32 = 0x5C5C64;
const LINE_NUM_CURRENT_FG: u32 = 0xB4B4BA;
const EDITED_FG: u32 = 0xE0A458;
const FIELD_BG: u32 = 0x18181A;

// Zig syntax colors (only used when filename ends in .zig).
const HL_KEYWORD: u32 = 0x66B3FF;
const HL_TYPE: u32 = 0xE0AB6B;
const HL_STRING: u32 = 0xC0A050;
const HL_NUMBER: u32 = 0x90C080;
const HL_COMMENT: u32 = 0x707080;
const HL_BUILTIN: u32 = 0xC080C0;

/// Line numbers, right-aligned, and the gap before the text.
const GUTTER_W: u32 = 44;
const GUTTER_PAD: u32 = 10;
const PROMPT_H: u32 = 36;
const TAB_WIDTH: u32 = 4;
const C = gfx.Canvas;

const MAX_SIZE: u32 = 32768;
const NO_SEL: u32 = 0xFFFFFFFF;

var text_buf: [MAX_SIZE]u8 = [_]u8{0} ** MAX_SIZE;
var text_len: u32 = 0;
var cursor_pos: u32 = 0;
var sel_anchor: u32 = NO_SEL;
var scroll_line: u32 = 0;
var modified: bool = false;
var filename: [64]u8 = [_]u8{0} ** 64;
var filename_len: u8 = 0;
var is_zig: bool = false;

// Mode flags. Only one prompt at a time.
var find_mode: bool = false;
var save_as_mode: bool = false;
var prompt_buf: [128]u8 = [_]u8{0} ** 128;
var prompt_len: u8 = 0;
var last_find_pos: u32 = 0;

/// Text rows that fit the window, as of the last frame.
var view_rows: u32 = 1;

/// A line for the status bar that replaces the cursor position until the
/// next key.
var note: []const u8 = "";

fn detectZig() void {
    if (filename_len < 4) { is_zig = false; return; }
    const fn_slice = filename[0..filename_len];
    is_zig = fn_slice[filename_len - 4] == '.' and
        fn_slice[filename_len - 3] == 'z' and
        fn_slice[filename_len - 2] == 'i' and
        fn_slice[filename_len - 1] == 'g';
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    var arg_buf: [64]u8 = undefined;
    const arg_len = libc.getExecArg(&arg_buf);
    if (arg_len > 0 and arg_len <= 64) {
        @memcpy(filename[0..arg_len], arg_buf[0..arg_len]);
        filename_len = @intCast(arg_len);
        detectZig();
        loadFile();
    }

    const scr = libc.getScreenSize();
    app.run(@This(), .{
        .width = @max(480, @min(scr.w * 2 / 5, 760)),
        .height = @max(320, @min(scr.h * 2 / 3, 640)),
    });
}

fn closePrompt() void {
    find_mode = false;
    save_as_mode = false;
    prompt_len = 0;
}

fn save() void {
    if (filename_len == 0) enterSaveAsMode() else saveFile();
}

fn keys(u: *app.Ui) void {
    if (u.key == 0 and u.special == 0) return;
    note = "";
    u.repaint();
    if (u.key == 0x1B) {
        if (find_mode or save_as_mode) {
            closePrompt();
        } else if (modified) {
            note = "Not saved. Ctrl+S saves, Ctrl+Q closes without saving";
        } else {
            u.close();
        }
    } else if (u.key != 0) {
        _ = handleKeyChar(u.key, u.mods);
    } else {
        _ = handleKeySpecial(u.special, u.mods);
    }
}

/// Move the cursor to the character cell under `p`; `text` is the rect the
/// text is drawn in. Halfway across a cell counts as the next one.
fn cursorToPoint(p: app.Point, text: app.Rect) void {
    const text_x: i32 = @intCast(text.x + GUTTER_W);
    const top: i32 = @intCast(text.y);
    const row: u32 = if (p.y > top) @as(u32, @intCast(p.y - top)) / C.CH16 else 0;
    const col: u32 = if (p.x > text_x) (@as(u32, @intCast(p.x - text_x)) + C.CW16 / 2) / C.CW16 else 0;
    moveCursorToLineCol(scroll_line + @min(row, view_rows -| 1), col);
}

pub fn frame(u: *app.Ui) void {
    if (!u.painting) keys(u);
    const prompting = find_mode or save_as_mode;

    u.beginBar();
    // The buttons first: the name takes what room they leave.
    u.alignNext(.right);
    if (u.button("Save")) save();
    u.alignNext(.right);
    if (u.button("Find")) enterFindMode();
    u.heading(if (filename_len > 0) filename[0..filename_len] else "Untitled");
    if (modified) u.caption("Edited", EDITED_FG);
    u.endBar();

    var status_buf: [48]u8 = undefined;
    var size_buf: [32]u8 = undefined;
    if (prompting) {
        const strip = u.bottomBar(PROMPT_H);
        if (u.painting) drawPrompt(u.canvas, strip, if (find_mode) "Find" else "Save as");
    } else {
        u.statusBar(if (note.len != 0) note else positionText(&status_buf), sizeText(&size_buf));
    }

    const area = u.fill();
    view_rows = @max(1, area.h / C.CH16);
    const text = u.vscroll(area, totalLines(), view_rows, &scroll_line);
    if (!prompting) {
        if (u.pressed(text)) |p| {
            clearSelection();
            cursorToPoint(p, text);
            // The anchor of a selection, should the press become a drag.
            sel_anchor = cursor_pos;
        } else if (u.dragging(text)) |p| {
            const before = cursor_pos;
            cursorToPoint(p, text);
            if (cursor_pos != before) u.repaint();
        }
    }
    if (u.painting) drawText(u.canvas, text);
}

inline fn modShift(mods: u32) bool { return (mods & 1) != 0; }
inline fn modCtrl(mods: u32) bool { return (mods & 2) != 0; }

fn clearSelection() void { sel_anchor = NO_SEL; }

const SelRange = struct { start: u32, end: u32 };
fn selectionRange() ?SelRange {
    if (sel_anchor == NO_SEL or sel_anchor == cursor_pos) return null;
    if (sel_anchor < cursor_pos) return .{ .start = sel_anchor, .end = cursor_pos };
    return .{ .start = cursor_pos, .end = sel_anchor };
}

fn deleteSelection() bool {
    const sel = selectionRange() orelse return false;
    const span = sel.end - sel.start;
    const tail = text_buf[sel.end..text_len];
    @memcpy(text_buf[sel.start..][0..tail.len], tail);
    text_len -= span;
    cursor_pos = sel.start;
    clearSelection();
    modified = true;
    return true;
}

fn handleKeyChar(ch: u8, mods: u32) bool {
    // --- Prompt mode (find / save-as) intercepts almost everything ---
    if (find_mode or save_as_mode) {
        if (ch == '\n') {
            if (find_mode) {
                doFind();
            } else if (save_as_mode) {
                save_as_mode = false;
                if (prompt_len > 0) {
                    @memcpy(filename[0..prompt_len], prompt_buf[0..prompt_len]);
                    filename_len = prompt_len;
                    detectZig();
                    prompt_len = 0;
                    saveFile();
                }
            }
            return true;
        }
        if (ch == 0x08) { // Backspace inside prompt
            if (prompt_len > 0) prompt_len -= 1;
            return true;
        }
        if (ch >= 0x20 and ch < 0x7F and prompt_len < prompt_buf.len) {
            prompt_buf[prompt_len] = ch;
            prompt_len += 1;
            return true;
        }
        return false;
    }

    // --- Ctrl-letter shortcuts (low control codes 0x01..0x1A) ---
    if (modCtrl(mods)) {
        switch (ch) {
            'c', 0x03 => { copyToClipboard(); return true; },
            'x', 0x18 => { cutToClipboard(); return true; },
            'v', 0x16 => { pasteFromClipboard(); return true; },
            'a', 0x01 => { selectAll(); return true; },
            'f', 0x06 => { enterFindMode(); return true; },
            'g', 0x07 => { findNext(); return true; },
            's', 0x13 => {
                if (filename_len == 0) {
                    enterSaveAsMode();
                } else {
                    saveFile();
                }
                return true;
            },
            'q', 0x11 => { libc.destroyWindow(); libc.exit(); },
            else => {},
        }
    }

    // Ctrl chars not handled above (e.g. Ctrl+S / Ctrl+Q on raw 0x13/0x11)
    // — already covered. Fall through for normal printable input below.

    if (ch == 0x08) { // Backspace
        if (deleteSelection()) { ensureCursorVisible(); return true; }
        if (cursor_pos > 0 and text_len > 0) {
            const src = text_buf[cursor_pos..text_len];
            @memcpy(text_buf[cursor_pos - 1 ..][0..src.len], src);
            text_len -= 1;
            cursor_pos -= 1;
            modified = true;
            ensureCursorVisible();
        }
        return true;
    }

    if (ch == '\t') { // Tab → 4 spaces
        _ = deleteSelection();
        var i: u32 = 0;
        while (i < TAB_WIDTH and text_len < MAX_SIZE - 1) : (i += 1) insertChar(' ');
        modified = true;
        return true;
    }

    if (ch == '\n') {
        _ = deleteSelection();
        if (text_len < MAX_SIZE - 1) {
            insertChar('\n');
            modified = true;
        }
        return true;
    }

    if (ch >= 0x20 and ch < 0x7F) {
        _ = deleteSelection();
        if (text_len < MAX_SIZE - 1) {
            insertChar(ch);
            modified = true;
        }
        return true;
    }

    return false;
}

fn handleKeySpecial(ch: u8, mods: u32) bool {
    // Prompt mode: only Esc (handled as key_char 0x1B) exits; ignore arrows/etc.
    if (find_mode or save_as_mode) {
        // F3 inside find mode = next match
        if (find_mode and ch == 0x92) { doFind(); return true; }
        return false;
    }

    const shift = modShift(mods);
    const ctrl = modCtrl(mods);

    // Maintain or clear selection based on shift state for movement keys.
    const wasSel = sel_anchor != NO_SEL;
    if (shift and !wasSel) sel_anchor = cursor_pos;
    if (!shift) clearSelection();

    switch (ch) {
        0x80 => moveCursorUp(),     // UP
        0x81 => moveCursorDown(),   // DOWN
        0x82 => {                    // LEFT
            if (ctrl) cursor_pos = wordJumpLeft(cursor_pos)
            else if (cursor_pos > 0) cursor_pos -= 1;
            ensureCursorVisible();
        },
        0x83 => {                    // RIGHT
            if (ctrl) cursor_pos = wordJumpRight(cursor_pos)
            else if (cursor_pos < text_len) cursor_pos += 1;
            ensureCursorVisible();
        },
        0x84 => {                    // HOME
            if (ctrl) cursor_pos = 0 else cursor_pos = lineStart(cursor_pos);
            ensureCursorVisible();
        },
        0x85 => {                    // END
            if (ctrl) cursor_pos = text_len else cursor_pos = lineEnd(cursor_pos);
            ensureCursorVisible();
        },
        0x86 => {                    // PGUP
            const vis = visibleLines();
            const cur = cursorLineCol();
            const new_line = if (cur.line >= vis) cur.line - vis else 0;
            moveCursorToLineCol(new_line, cur.col);
        },
        0x87 => {                    // PGDN
            const vis = visibleLines();
            const cur = cursorLineCol();
            moveCursorToLineCol(cur.line + vis, cur.col);
        },
        0x88 => {                    // DELETE
            if (!deleteSelection()) {
                if (cursor_pos < text_len) {
                    const src = text_buf[cursor_pos + 1 .. text_len];
                    @memcpy(text_buf[cursor_pos..][0..src.len], src);
                    text_len -= 1;
                    modified = true;
                }
            }
            ensureCursorVisible();
        },
        0x92 => findNext(), // F3
        else => {
            // Unknown special key; restore selection state untouched.
            if (!shift) sel_anchor = if (wasSel) sel_anchor else NO_SEL;
            return false;
        },
    }
    return true;
}

fn insertChar(ch: u8) void {
    if (text_len >= MAX_SIZE - 1) return;
    if (cursor_pos > text_len) cursor_pos = text_len;
    var i: u32 = text_len;
    while (i > cursor_pos) : (i -= 1) text_buf[i] = text_buf[i - 1];
    text_buf[cursor_pos] = ch;
    text_len += 1;
    cursor_pos += 1;
    ensureCursorVisible();
}

fn insertSlice(s: []const u8) void {
    for (s) |c| {
        if (text_len >= MAX_SIZE - 1) return;
        insertChar(c);
    }
    modified = true;
}

fn selectAll() void {
    sel_anchor = 0;
    cursor_pos = text_len;
    ensureCursorVisible();
}

fn copyToClipboard() void {
    const sel = selectionRange() orelse return;
    _ = libc.setClipboard(text_buf[sel.start..sel.end]);
}

fn cutToClipboard() void {
    const sel = selectionRange() orelse return;
    _ = libc.setClipboard(text_buf[sel.start..sel.end]);
    _ = deleteSelection();
    ensureCursorVisible();
}

fn pasteFromClipboard() void {
    var tmp: [4096]u8 = undefined;
    const actual = libc.getClipboard(&tmp);
    if (actual == 0) return;
    const copy_n = @min(actual, tmp.len);
    _ = deleteSelection();
    insertSlice(tmp[0..copy_n]);
    ensureCursorVisible();
}

fn enterFindMode() void {
    find_mode = true;
    save_as_mode = false;
    prompt_len = 0;
}

fn enterSaveAsMode() void {
    save_as_mode = true;
    find_mode = false;
    prompt_len = 0;
}

fn doFind() void {
    if (prompt_len == 0) return;
    last_find_pos = cursor_pos;
    findNext();
}

fn findNext() void {
    if (prompt_len == 0) return;
    const needle = prompt_buf[0..prompt_len];
    var start: u32 = cursor_pos;
    if (start > text_len) start = 0;
    // Search forward, wrap around at EOF.
    var hit: ?u32 = searchFrom(start, needle);
    if (hit == null) hit = searchFrom(0, needle);
    if (hit) |pos| {
        sel_anchor = pos;
        cursor_pos = pos + @as(u32, @intCast(needle.len));
        ensureCursorVisible();
    }
}

fn searchFrom(from: u32, needle: []const u8) ?u32 {
    if (needle.len == 0 or text_len < needle.len) return null;
    var i: u32 = from;
    while (i + needle.len <= text_len) : (i += 1) {
        var j: u32 = 0;
        while (j < needle.len and text_buf[i + j] == needle[j]) : (j += 1) {}
        if (j == needle.len) return i;
    }
    return null;
}

fn isWordChar(c: u8) bool {
    return (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or
           (c >= '0' and c <= '9') or c == '_';
}

fn wordJumpRight(pos: u32) u32 {
    var p = pos;
    // Skip current word.
    while (p < text_len and isWordChar(text_buf[p])) : (p += 1) {}
    // Skip following non-word run.
    while (p < text_len and !isWordChar(text_buf[p]) and text_buf[p] != '\n') : (p += 1) {}
    return p;
}

fn wordJumpLeft(pos: u32) u32 {
    var p = pos;
    if (p == 0) return 0;
    p -= 1;
    while (p > 0 and !isWordChar(text_buf[p]) and text_buf[p] != '\n') : (p -= 1) {}
    while (p > 0 and isWordChar(text_buf[p - 1])) : (p -= 1) {}
    return p;
}

fn lineStart(pos: u32) u32 {
    var p = pos;
    while (p > 0 and text_buf[p - 1] != '\n') : (p -= 1) {}
    return p;
}

fn lineEnd(pos: u32) u32 {
    var p = pos;
    while (p < text_len and text_buf[p] != '\n') : (p += 1) {}
    return p;
}

fn moveCursorUp() void {
    const cur = cursorLineCol();
    if (cur.line == 0) return;
    moveCursorToLineCol(cur.line - 1, cur.col);
}

fn moveCursorDown() void {
    const cur = cursorLineCol();
    moveCursorToLineCol(cur.line + 1, cur.col);
}

fn moveCursorToLineCol(target_line: u32, target_col: u32) void {
    var pos: u32 = 0;
    var line: u32 = 0;
    while (pos < text_len and line < target_line) : (pos += 1) {
        if (text_buf[pos] == '\n') line += 1;
    }
    if (line < target_line) {
        cursor_pos = text_len;
        ensureCursorVisible();
        return;
    }
    var col: u32 = 0;
    while (pos < text_len and col < target_col and text_buf[pos] != '\n') : (pos += 1) {
        col += 1;
    }
    cursor_pos = pos;
    ensureCursorVisible();
}

const LineCol = struct { line: u32, col: u32 };

fn cursorLineCol() LineCol {
    var line: u32 = 0;
    var col: u32 = 0;
    var i: u32 = 0;
    while (i < cursor_pos and i < text_len) : (i += 1) {
        if (text_buf[i] == '\n') { line += 1; col = 0; } else col += 1;
    }
    return .{ .line = line, .col = col };
}

fn totalLines() u32 {
    var count: u32 = 1;
    var i: u32 = 0;
    while (i < text_len) : (i += 1) if (text_buf[i] == '\n') { count += 1; };
    return count;
}

fn ensureCursorVisible() void {
    const cur = cursorLineCol();
    const visible = visibleLines();
    if (cur.line < scroll_line) scroll_line = cur.line;
    if (cur.line >= scroll_line + visible) scroll_line = cur.line - visible + 1;
}

fn visibleLines() u32 {
    return view_rows;
}

fn loadFile() void {
    if (filename_len == 0) return;
    const fd = libc.open(filename[0..filename_len]) orelse return;
    text_len = libc.fread(fd, text_buf[0..MAX_SIZE]);
    if (text_len == 0xFFFFFFFF) text_len = 0;
    libc.close(fd);
    cursor_pos = 0;
    scroll_line = 0;
    sel_anchor = NO_SEL;
    modified = false;
}

fn saveFile() void {
    if (filename_len == 0) return;
    const fd = libc.openFlags(filename[0..filename_len], libc.O_CREATE) orelse return;
    _ = libc.fwrite(fd, text_buf[0..text_len]);
    libc.close(fd);
    modified = false;
}

// --- Zig syntax highlighting --------------------------------------------

const zig_keywords = [_][]const u8{
    "fn", "pub", "const", "var", "if", "else", "while", "for", "switch",
    "return", "break", "continue", "defer", "errdefer", "try", "catch",
    "orelse", "and", "or", "struct", "enum", "union", "comptime", "inline",
    "extern", "export", "test", "error", "null", "true", "false", "undefined",
    "unreachable", "async", "await", "suspend", "resume", "nosuspend",
    "anytype", "anyerror", "noreturn", "usingnamespace", "callconv", "align",
    "linksection", "threadlocal", "packed", "volatile", "allowzero", "opaque",
};

const zig_types = [_][]const u8{
    "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64",
    "i128", "isize", "f16", "f32", "f64", "f128", "bool", "void", "type",
    "comptime_int", "comptime_float", "c_int", "c_uint", "c_long",
    "c_short", "c_char", "c_void",
};

fn isKeyword(s: []const u8) bool {
    for (zig_keywords) |k| {
        if (s.len != k.len) continue;
        var ok = true;
        for (s, k) |a, b| if (a != b) { ok = false; break; };
        if (ok) return true;
    }
    return false;
}

fn isType(s: []const u8) bool {
    for (zig_types) |k| {
        if (s.len != k.len) continue;
        var ok = true;
        for (s, k) |a, b| if (a != b) { ok = false; break; };
        if (ok) return true;
    }
    return false;
}

/// One character in its cell of the grid. No background: the selection
/// and the current line's shade are already painted under the text.
fn drawCell(canvas: *gfx.Canvas, x: u32, y: u32, ch: u8, color: u32) void {
    if (ch <= ' ') return;
    fa.drawText(canvas, @intCast(x), @intCast(y), &[1]u8{ch}, color, &fa.default_mono);
}

// Drive the row through a small state machine producing colored runs.
fn drawZigLine(canvas: *gfx.Canvas, x0: u32, y: u32, line: []const u8, max_cols: u32) void {
    var col: u32 = 0;
    var i: u32 = 0;
    const len: u32 = @intCast(line.len);
    while (i < len and col < max_cols) {
        const c = line[i];
        // // line comment
        if (c == '/' and i + 1 < len and line[i + 1] == '/') {
            while (i < len and col < max_cols) : (i += 1) {
                drawCell(canvas, x0 + col * C.CW16, y, line[i], HL_COMMENT);
                col += 1;
            }
            return;
        }
        // "string"
        if (c == '"') {
            drawCell(canvas, x0 + col * C.CW16, y, c, HL_STRING);
            col += 1;
            i += 1;
            while (i < len and col < max_cols) {
                const sc = line[i];
                drawCell(canvas, x0 + col * C.CW16, y, sc, HL_STRING);
                col += 1;
                i += 1;
                if (sc == '\\' and i < len and col < max_cols) {
                    drawCell(canvas, x0 + col * C.CW16, y, line[i], HL_STRING);
                    col += 1;
                    i += 1;
                    continue;
                }
                if (sc == '"') break;
            }
            continue;
        }
        // 'c' char literal
        if (c == '\'') {
            const end_off = blk: {
                var k: u32 = i + 1;
                if (k < len and line[k] == '\\') k += 2 else k += 1;
                if (k < len and line[k] == '\'') break :blk k + 1;
                break :blk i + 1;
            };
            var k = i;
            while (k < end_off and col < max_cols) : (k += 1) {
                drawCell(canvas, x0 + col * C.CW16, y, line[k], HL_STRING);
                col += 1;
            }
            i = end_off;
            continue;
        }
        // @builtin
        if (c == '@' and i + 1 < len and (line[i + 1] >= 'a' and line[i + 1] <= 'z')) {
            var k = i;
            while (k < len and (isWordChar(line[k]) or line[k] == '@') and col < max_cols) : (k += 1) {
                drawCell(canvas, x0 + col * C.CW16, y, line[k], HL_BUILTIN);
                col += 1;
            }
            i = k;
            continue;
        }
        // number literal
        if (c >= '0' and c <= '9') {
            while (i < len and col < max_cols and
                ((line[i] >= '0' and line[i] <= '9') or line[i] == '.' or line[i] == 'x' or
                 line[i] == 'X' or line[i] == '_' or
                 (line[i] >= 'a' and line[i] <= 'f') or (line[i] >= 'A' and line[i] <= 'F'))) : (i += 1)
            {
                drawCell(canvas, x0 + col * C.CW16, y, line[i], HL_NUMBER);
                col += 1;
            }
            continue;
        }
        // identifier / keyword / type
        if (isWordChar(c) and !(c >= '0' and c <= '9')) {
            const start = i;
            while (i < len and isWordChar(line[i])) : (i += 1) {}
            const ident = line[start..i];
            const color: u32 = if (isKeyword(ident)) HL_KEYWORD
                else if (isType(ident)) HL_TYPE
                else TEXT_FG;
            var k: u32 = 0;
            while (k < ident.len and col < max_cols) : (k += 1) {
                drawCell(canvas, x0 + col * C.CW16, y, ident[k], color);
                col += 1;
            }
            continue;
        }
        // default
        drawCell(canvas, x0 + col * C.CW16, y, c, TEXT_FG);
        col += 1;
        i += 1;
    }
}

// --- Drawing ----------------------------------------------------------------

fn writeNum(buf: []u8, n: u32) usize {
    var tmp: [10]u8 = undefined;
    var len: usize = 0;
    var v = n;
    while (true) {
        tmp[len] = '0' + @as(u8, @intCast(v % 10));
        len += 1;
        v /= 10;
        if (v == 0) break;
    }
    for (0..len) |i| buf[i] = tmp[len - 1 - i];
    return len;
}

fn appendText(buf: []u8, len: *usize, s: []const u8) void {
    @memcpy(buf[len.*..][0..s.len], s);
    len.* += s.len;
}

/// "Line 12, Column 5".
fn positionText(buf: *[48]u8) []const u8 {
    const cur = cursorLineCol();
    var len: usize = 0;
    appendText(buf, &len, "Line ");
    len += writeNum(buf[len..], cur.line + 1);
    appendText(buf, &len, ", Column ");
    len += writeNum(buf[len..], cur.col + 1);
    return buf[0..len];
}

/// "Zig   1234 bytes".
fn sizeText(buf: *[32]u8) []const u8 {
    var len: usize = 0;
    if (is_zig) appendText(buf, &len, "Zig   ");
    len += writeNum(buf[len..], text_len);
    appendText(buf, &len, if (text_len == 1) " byte" else " bytes");
    return buf[0..len];
}

/// The text in `r`: line numbers in the gutter, then the grid of cells.
fn drawText(canvas: *gfx.Canvas, r: app.Rect) void {
    const text_x = r.x + GUTTER_W;
    const max_cols = (r.w -| GUTTER_W) / C.CW16;
    const rows = r.h / C.CH16;
    const mono = &fa.default_mono;
    const sel = selectionRange();
    const cur = cursorLineCol();

    // Walk to start of scroll_line.
    var pos: u32 = 0;
    var line: u32 = 0;
    while (pos < text_len and line < scroll_line) : (pos += 1) {
        if (text_buf[pos] == '\n') line += 1;
    }

    var row: u32 = 0;
    while (row < rows) : (row += 1) {
        const y = r.y + row * C.CH16;
        const display_line = scroll_line + row;
        const is_current = display_line == cur.line;

        if (is_current and sel == null) canvas.fillRect(r.x, y, r.w, C.CH16, CURRENT_LINE_BG);

        var num_buf: [10]u8 = undefined;
        const num = num_buf[0..writeNum(&num_buf, display_line +| 1)];
        const num_x = text_x -| GUTTER_PAD -| mono.measure(num);
        fa.drawText(canvas, @intCast(num_x), @intCast(y), num, if (is_current) LINE_NUM_CURRENT_FG else LINE_NUM_FG, mono);

        // Slice this line out of the buffer.
        const line_start = pos;
        var line_end: u32 = pos;
        while (line_end < text_len and text_buf[line_end] != '\n') : (line_end += 1) {}

        // Selection, under the text.
        if (sel) |s| {
            if (s.end > line_start and s.start <= line_end) {
                const a = @max(s.start, line_start) - line_start;
                const b = @min(s.end, line_end) - line_start;
                if (b > a and a < max_cols) {
                    canvas.fillRect(text_x + a * C.CW16, y, @min(b - a, max_cols - a) * C.CW16, C.CH16, SEL_BG);
                }
                // The newline of a line the selection runs past.
                if (s.end > line_end and line_end - line_start < max_cols) {
                    canvas.fillRect(text_x + (line_end - line_start) * C.CW16, y, C.CW16 / 2, C.CH16, SEL_BG);
                }
            }
        }

        const line_slice = text_buf[line_start..line_end];
        if (is_zig) {
            drawZigLine(canvas, text_x, y, line_slice, max_cols);
        } else {
            var col: u32 = 0;
            while (col < line_slice.len and col < max_cols) : (col += 1) {
                drawCell(canvas, text_x + col * C.CW16, y, line_slice[col], TEXT_FG);
            }
        }

        pos = line_end;
        if (pos < text_len and text_buf[pos] == '\n') pos += 1;

        if (is_current and cur.col <= max_cols) {
            canvas.fillRect(text_x + cur.col * C.CW16, y, 2, C.CH16, CURSOR_COLOR);
        }

        if (pos >= text_len and display_line >= cur.line) break;
    }
}

/// The find or save-as prompt in the bottom strip `r`: a caption, the
/// field with what was typed, and what the keys do.
fn drawPrompt(canvas: *gfx.Canvas, r: app.Rect, caption: []const u8) void {
    const p = &ui.palette;
    const small = &fa.default_13;
    const pad: u32 = 10;
    const hint = if (find_mode) "Enter: next    Esc: close" else "Enter: save    Esc: cancel";
    const caption_w = fa.default_13sb.measure(caption);
    const hint_w = small.measure(hint);
    const small_y = r.y + (r.h -| small.line_height) / 2;
    fa.drawText(canvas, @intCast(r.x + pad), @intCast(small_y), caption, p.text_strong, &fa.default_13sb);

    const field_x = r.x + pad + caption_w + pad;
    // The hint gives way first on a narrow window.
    const show_hint = r.w > field_x + 160 + hint_w + 2 * pad;
    const field_w = r.w -| field_x -| (if (show_hint) hint_w + 2 * pad else pad);
    const field_h: u32 = 24;
    const field_y = r.y + (r.h - field_h) / 2;
    canvas.fillRoundedRect(field_x, field_y, field_w, field_h, 6, p.card_border);
    canvas.fillRoundedRect(field_x + 1, field_y + 1, field_w -| 2, field_h -| 2, 5, FIELD_BG);

    // The tail of a query longer than the field stays in view.
    const cols = (field_w -| 16) / C.CW16;
    const shown = prompt_buf[@as(u32, prompt_len) -| cols..prompt_len];
    const text_y = field_y + (field_h -| C.CH16) / 2;
    for (shown, 0..) |ch, i| drawCell(canvas, field_x + 8 + @as(u32, @intCast(i)) * C.CW16, text_y, ch, TEXT_FG);
    canvas.fillRect(field_x + 8 + @as(u32, @intCast(shown.len)) * C.CW16, text_y, 2, C.CH16, CURSOR_COLOR);

    if (show_hint) fa.drawText(canvas, @intCast(r.x + r.w - pad - hint_w), @intCast(small_y), hint, p.text_muted, small);
}
