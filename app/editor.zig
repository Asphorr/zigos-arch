const libc = @import("libc");
const gfx = @import("graphics");
const fa = @import("font_atlas");
const ui = @import("ui");

const BG: u32 = 0x1E1E2E;
const TEXT_FG: u32 = 0xCCCCCC;
const SEL_BG: u32 = 0x3A3A55;
const TOOLBAR_BG: u32 = 0x2A2A3A;
const TOOLBAR_FG: u32 = 0x88AACC;
const STATUS_BG: u32 = 0x2A2A3A;
const STATUS_FG: u32 = 0xAAAAAA;
const CURSOR_COLOR: u32 = 0xFFFFFF;
const LINE_NUM_FG: u32 = 0x555566;
const MODIFIED_FG: u32 = 0xFF8888;
const PROMPT_BG: u32 = 0x36364A;
const PROMPT_FG: u32 = 0xE0E0E0;
const FIND_HIT_BG: u32 = 0x665520;

// Zig syntax colors (only used when filename ends in .zig).
const HL_KEYWORD: u32 = 0x66B3FF;
const HL_TYPE: u32 = 0xE0AB6B;
const HL_STRING: u32 = 0xC0A050;
const HL_NUMBER: u32 = 0x90C080;
const HL_COMMENT: u32 = 0x707080;
const HL_BUILTIN: u32 = 0xC080C0;

const TOOLBAR_H: u32 = 24;
const STATUS_H: u32 = 20;
const LINE_NUM_W: u32 = 36;
const SCROLLBAR_W: u32 = 8;
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

var win_w: u32 = 0;
var win_h: u32 = 0;
var ed_alloc_w: u32 = 0;
var ed_alloc_h: u32 = 0;
var scrollbar: ui.Scrollbar = .{ .x = 0, .y = 0, .w = 0, .h = 0 };

fn layoutScrollbar() void {
    scrollbar.x = win_w -| SCROLLBAR_W;
    scrollbar.y = TOOLBAR_H;
    scrollbar.w = SCROLLBAR_W;
    scrollbar.h = win_h -| (TOOLBAR_H + STATUS_H);
}

fn detectZig() void {
    if (filename_len < 4) { is_zig = false; return; }
    const fn_slice = filename[0..filename_len];
    is_zig = fn_slice[filename_len - 4] == '.' and
        fn_slice[filename_len - 3] == 'z' and
        fn_slice[filename_len - 2] == 'i' and
        fn_slice[filename_len - 1] == 'g';
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    const scr = libc.getScreenSize();
    win_w = scr.w * 2 / 5;
    if (win_w < 400) win_w = 400;
    if (win_w > 700) win_w = 700;
    win_h = scr.h * 2 / 3;
    if (win_h < 300) win_h = 300;
    if (win_h > 600) win_h = 600;

    ed_alloc_w = @min(win_w * 2, scr.w);
    ed_alloc_h = @min(win_h * 2, scr.h);
    while (ed_alloc_w * ed_alloc_h > 524288) {
        if (ed_alloc_w > ed_alloc_h) ed_alloc_w -= 16 else ed_alloc_h -= 16;
    }

    const win = libc.createWindowEx(ed_alloc_w, ed_alloc_h, win_w, win_h) orelse libc.exit();
    ed_alloc_w = win.alloc_w;
    ed_alloc_h = win.alloc_h;
    var canvas = gfx.Canvas.init(win.fb, ed_alloc_w, ed_alloc_h);
    _ = libc.getWindowAlloc(); // opt this window into F10 grow-on-maximize (re-fetched in .resize)
    fa.ensureLoaded();
    layoutScrollbar();

    var arg_buf: [64]u8 = undefined;
    const arg_len = libc.getExecArg(&arg_buf);
    if (arg_len > 0 and arg_len <= 64) {
        @memcpy(filename[0..arg_len], arg_buf[0..arg_len]);
        filename_len = @intCast(arg_len);
        detectZig();
        loadFile();
    }

    var needs_redraw: bool = true;
    var prev_left: bool = false;
    var cur_mx: i32 = 0;
    var cur_my: i32 = 0;
    var cur_btns: u32 = 0;

    while (true) {
        var should_quit = false;

        while (libc.pollEvent()) |ev| {
            if (scrollbar.handleEvent(ev, totalLines(), visibleLines(), &scroll_line)) {
                needs_redraw = true;
            }
            switch (ev.kindOf()) {
                .close_request => should_quit = true,
                .resize => {
                    // F10 maximize may have GROWN our framebuffer past the
                    // alloc we requested. Re-fetch and rebuild the canvas at
                    // the new stride before clamping/laying out (FB ptr is
                    // unchanged) so we render crisply instead of upscaled.
                    const wa = libc.getWindowAlloc();
                    if (wa.w != 0 and (wa.w != ed_alloc_w or wa.h != ed_alloc_h)) {
                        ed_alloc_w = wa.w;
                        ed_alloc_h = wa.h;
                        canvas = gfx.Canvas.init(win.fb, ed_alloc_w, ed_alloc_h);
                    }
                    const new_w = @min(ev.a, ed_alloc_w);
                    const new_h = @min(ev.b, ed_alloc_h);
                    if (new_w != win_w or new_h != win_h) {
                        win_w = new_w;
                        win_h = new_h;
                        layoutScrollbar();
                        ensureCursorVisible();
                        needs_redraw = true;
                    }
                },
                .key_char => {
                    const ch: u8 = @truncate(ev.a);
                    const mods: u32 = ev.b;
                    if (ch == 0x1B) {
                        if (find_mode or save_as_mode) {
                            find_mode = false;
                            save_as_mode = false;
                            prompt_len = 0;
                            needs_redraw = true;
                        } else {
                            should_quit = true;
                        }
                    } else if (ch != 0) {
                        if (handleKeyChar(ch, mods)) needs_redraw = true;
                    }
                },
                .key_special => {
                    const ch: u8 = @truncate(ev.a);
                    const mods: u32 = ev.b;
                    if (handleKeySpecial(ch, mods)) needs_redraw = true;
                },
                .mouse_move => {
                    cur_mx = @bitCast(ev.a);
                    cur_my = @bitCast(ev.b);
                    cur_btns = ev.c;
                    // Drag-select: left held + moving → update cursor + keep anchor
                    if (prev_left and (cur_btns & 1) != 0 and !find_mode and !save_as_mode) {
                        const in_scrollbar = cur_mx >= @as(i32, @intCast(scrollbar.x));
                        if (!in_scrollbar and cur_my >= @as(i32, TOOLBAR_H) and
                            cur_my < @as(i32, @intCast(win_h -| STATUS_H)))
                        {
                            const click_line = @as(u32, @intCast(cur_my - @as(i32, TOOLBAR_H))) / C.CH16 + scroll_line;
                            var click_col: u32 = 0;
                            if (cur_mx > @as(i32, LINE_NUM_W)) {
                                click_col = @as(u32, @intCast(cur_mx - @as(i32, LINE_NUM_W))) / C.CW16;
                            }
                            moveCursorToLineCol(click_line, click_col);
                            needs_redraw = true;
                        }
                    }
                },
                .mouse_button => {
                    cur_btns = ev.buttonsState();
                    cur_mx = @bitCast(ev.b);
                    cur_my = @bitCast(ev.c);
                },
                else => {},
            }
        }
        if (should_quit) break;

        const left = (cur_btns & 1) != 0;
        const in_scrollbar = cur_mx >= @as(i32, @intCast(scrollbar.x));
        if (left and !prev_left and !in_scrollbar and !find_mode and !save_as_mode) {
            if (cur_my >= @as(i32, TOOLBAR_H) and cur_my < @as(i32, @intCast(win_h -| STATUS_H))) {
                const click_line = @as(u32, @intCast(cur_my - @as(i32, TOOLBAR_H))) / C.CH16 + scroll_line;
                var click_col: u32 = 0;
                if (cur_mx > @as(i32, LINE_NUM_W)) {
                    click_col = @as(u32, @intCast(cur_mx - @as(i32, LINE_NUM_W))) / C.CW16;
                }
                clearSelection();
                moveCursorToLineCol(click_line, click_col);
                sel_anchor = cursor_pos; // anchor a fresh selection for drag
                needs_redraw = true;
            }
        }
        prev_left = left;

        if (!needs_redraw) {
            libc.sleep(10);
            continue;
        }
        needs_redraw = false;

        render(&canvas);
        libc.sleep(10);
    }

    libc.destroyWindow();
    libc.exit();
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
    return (win_h -| (TOOLBAR_H + STATUS_H)) / C.CH16;
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
                fa.drawCharOpaque(canvas, x0 + col * C.CW16, y, line[i], HL_COMMENT, BG, &fa.default_mono);
                col += 1;
            }
            return;
        }
        // "string"
        if (c == '"') {
            fa.drawCharOpaque(canvas, x0 + col * C.CW16, y, c, HL_STRING, BG, &fa.default_mono);
            col += 1;
            i += 1;
            while (i < len and col < max_cols) {
                const sc = line[i];
                fa.drawCharOpaque(canvas, x0 + col * C.CW16, y, sc, HL_STRING, BG, &fa.default_mono);
                col += 1;
                i += 1;
                if (sc == '\\' and i < len and col < max_cols) {
                    fa.drawCharOpaque(canvas, x0 + col * C.CW16, y, line[i], HL_STRING, BG, &fa.default_mono);
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
                fa.drawCharOpaque(canvas, x0 + col * C.CW16, y, line[k], HL_STRING, BG, &fa.default_mono);
                col += 1;
            }
            i = end_off;
            continue;
        }
        // @builtin
        if (c == '@' and i + 1 < len and (line[i + 1] >= 'a' and line[i + 1] <= 'z')) {
            var k = i;
            while (k < len and (isWordChar(line[k]) or line[k] == '@') and col < max_cols) : (k += 1) {
                fa.drawCharOpaque(canvas, x0 + col * C.CW16, y, line[k], HL_BUILTIN, BG, &fa.default_mono);
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
                fa.drawCharOpaque(canvas, x0 + col * C.CW16, y, line[i], HL_NUMBER, BG, &fa.default_mono);
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
                fa.drawCharOpaque(canvas, x0 + col * C.CW16, y, ident[k], color, BG, &fa.default_mono);
                col += 1;
            }
            continue;
        }
        // default
        fa.drawCharOpaque(canvas, x0 + col * C.CW16, y, c, TEXT_FG, BG, &fa.default_mono);
        col += 1;
        i += 1;
    }
}

fn render(canvas: *gfx.Canvas) void {
    canvas.clear(BG);

    // --- Toolbar ---
    canvas.fillRect(0, 0, win_w, TOOLBAR_H, TOOLBAR_BG);
    if (filename_len > 0) {
        const fname = filename[0..filename_len];
        fa.drawTextOpaque(canvas, 8, 4, fname, TOOLBAR_FG, TOOLBAR_BG, &fa.default_16);
        if (modified) {
            const fw = fa.default_16.measure(fname);
            fa.drawTextOpaque(canvas, 8 + fw, 4, " *", MODIFIED_FG, TOOLBAR_BG, &fa.default_16);
        }
    } else {
        fa.drawTextOpaque(canvas, 8, 4, "[untitled]", TOOLBAR_FG, TOOLBAR_BG, &fa.default_16);
    }
    fa.drawTextOpaque(canvas, win_w -| 320, 4, "^S Save  ^F Find  ^C/V/X Clip  ^Q Quit",
        0x666688, TOOLBAR_BG, &fa.default_16);

    // --- Text area + selection highlight ---
    const text_y = TOOLBAR_H;
    const text_h = win_h -| (TOOLBAR_H + STATUS_H);
    const vis = text_h / C.CH16;
    const text_area_w = win_w -| SCROLLBAR_W;
    const max_cols = (text_area_w -| LINE_NUM_W) / C.CW16;

    const sel = selectionRange();

    // Walk to start of scroll_line.
    var pos: u32 = 0;
    var line: u32 = 0;
    while (pos < text_len and line < scroll_line) : (pos += 1) {
        if (text_buf[pos] == '\n') line += 1;
    }

    const cur = cursorLineCol();
    var row: u32 = 0;
    while (row < vis) : (row += 1) {
        const y = text_y + row * C.CH16;
        const display_line = scroll_line + row;

        // Line number.
        _ = fa.drawNumOpaque(canvas, 2, y, display_line +| 1, LINE_NUM_FG, BG, &fa.default_mono);
        canvas.drawVLine(LINE_NUM_W - 2, y, C.CH16, 0x333344);

        // Slice this line out of the buffer.
        const line_start = pos;
        var line_end_idx: u32 = pos;
        while (line_end_idx < text_len and text_buf[line_end_idx] != '\n') : (line_end_idx += 1) {}

        // Selection background underlay.
        if (sel) |s| {
            if (s.end > line_start and s.start <= line_end_idx) {
                const a = if (s.start < line_start) line_start else s.start;
                const b = if (s.end > line_end_idx) line_end_idx else s.end;
                const sc_a = a - line_start;
                const sc_b = b - line_start;
                if (sc_b > sc_a and sc_a < max_cols) {
                    const sx = LINE_NUM_W + sc_a * C.CW16;
                    const sw = @min(sc_b - sc_a, max_cols - sc_a) * C.CW16;
                    canvas.fillRect(sx, y, sw, C.CH16, SEL_BG);
                }
                // Highlight trailing newline for multi-line selections.
                if (s.end > line_end_idx) {
                    const sx = LINE_NUM_W + (line_end_idx - line_start) * C.CW16;
                    canvas.fillRect(sx, y, C.CW16 / 2, C.CH16, SEL_BG);
                }
            }
        }

        // Highlight find-match overlay (current selection IS the find hit;
        // we already painted SEL_BG, so additional highlight only kicks in
        // when find mode is active and the selection is exactly the
        // current find result — keeps the cue clearly visible).
        if (find_mode and sel != null) {
            // Re-tint over SEL_BG for emphasis.
            if (sel) |s| if (s.end > line_start and s.start < line_end_idx) {
                const a = if (s.start < line_start) line_start else s.start;
                const b = if (s.end > line_end_idx) line_end_idx else s.end;
                const sc_a = a - line_start;
                const sc_b = b - line_start;
                if (sc_b > sc_a and sc_a < max_cols) {
                    const hx = LINE_NUM_W + sc_a * C.CW16;
                    const hw = @min(sc_b - sc_a, max_cols - sc_a) * C.CW16;
                    canvas.fillRect(hx, y, hw, 1, FIND_HIT_BG);
                    canvas.fillRect(hx, y + C.CH16 - 1, hw, 1, FIND_HIT_BG);
                }
            };
        }

        const line_slice = text_buf[line_start..line_end_idx];
        if (is_zig) {
            drawZigLine(canvas, LINE_NUM_W, y, line_slice, max_cols);
        } else {
            var col: u32 = 0;
            while (col < line_slice.len and col < max_cols) : (col += 1) {
                fa.drawCharOpaque(canvas, LINE_NUM_W + col * C.CW16, y, line_slice[col], TEXT_FG, BG, &fa.default_mono);
            }
        }

        pos = line_end_idx;
        if (pos < text_len and text_buf[pos] == '\n') pos += 1;

        // Cursor.
        if (display_line == cur.line) {
            const cx_px = LINE_NUM_W + cur.col * C.CW16;
            if (cx_px < text_area_w) {
                canvas.fillRect(cx_px, y, 2, C.CH16, CURSOR_COLOR);
            }
        }

        if (pos >= text_len and display_line >= cur.line) break;
    }

    scrollbar.draw(canvas, totalLines(), visibleLines(), scroll_line);

    // --- Status bar / prompt ---
    const sy = win_h -| STATUS_H + 2;
    canvas.fillRect(0, win_h -| STATUS_H, win_w, STATUS_H,
        if (find_mode or save_as_mode) PROMPT_BG else STATUS_BG);

    if (find_mode) {
        renderPrompt(canvas, sy, "Find: ");
    } else if (save_as_mode) {
        renderPrompt(canvas, sy, "Save as: ");
    } else {
        fa.drawTextOpaque(canvas, 8, sy, "Ln ", STATUS_FG, STATUS_BG, &fa.default_16);
        var sx: u32 = 8 + fa.default_16.measure("Ln ");
        sx = fa.drawNumOpaque(canvas, sx, sy, cur.line + 1, STATUS_FG, STATUS_BG, &fa.default_mono);
        fa.drawTextOpaque(canvas, sx + 4, sy, "Col ", STATUS_FG, STATUS_BG, &fa.default_16);
        sx = sx + 4 + fa.default_16.measure("Col ");
        sx = fa.drawNumOpaque(canvas, sx, sy, cur.col + 1, STATUS_FG, STATUS_BG, &fa.default_mono);
        fa.drawTextOpaque(canvas, sx + 8, sy, "Size ", STATUS_FG, STATUS_BG, &fa.default_16);
        sx = sx + 8 + fa.default_16.measure("Size ");
        _ = fa.drawNumOpaque(canvas, sx, sy, text_len, STATUS_FG, STATUS_BG, &fa.default_mono);
        if (is_zig) {
            const tag = "  [zig]";
            const tw = fa.default_16.measure(tag);
            fa.drawTextOpaque(canvas, win_w -| (tw + 8), sy, tag, 0x66B3FF, STATUS_BG, &fa.default_16);
        }
    }
}

fn renderPrompt(canvas: *gfx.Canvas, sy: u32, label: []const u8) void {
    fa.drawTextOpaque(canvas, 8, sy, label, PROMPT_FG, PROMPT_BG, &fa.default_16);
    const lx = 8 + fa.default_16.measure(label);
    if (prompt_len > 0) {
        fa.drawTextOpaque(canvas, lx, sy, prompt_buf[0..prompt_len], PROMPT_FG, PROMPT_BG, &fa.default_mono);
    }
    // Caret at end of prompt.
    const cx = lx + prompt_len * C.CW16;
    canvas.fillRect(cx, sy, 2, C.CH16, CURSOR_COLOR);
}
