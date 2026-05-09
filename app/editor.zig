const libc = @import("libc");
const gfx = @import("graphics");
const fa = @import("font_atlas");
const ui = @import("ui");

const BG: u32 = 0x1E1E2E;
const TEXT_FG: u32 = 0xCCCCCC;
const TOOLBAR_BG: u32 = 0x2A2A3A;
const TOOLBAR_FG: u32 = 0x88AACC;
const STATUS_BG: u32 = 0x2A2A3A;
const STATUS_FG: u32 = 0xAAAAAA;
const CURSOR_COLOR: u32 = 0xFFFFFF;
const LINE_NUM_FG: u32 = 0x555566;
const MODIFIED_FG: u32 = 0xFF8888;
const TOOLBAR_H: u32 = 24;
const STATUS_H: u32 = 20;
const LINE_NUM_W: u32 = 36; // 4 chars + gap
const SCROLLBAR_W: u32 = 8;
const C = gfx.Canvas;

const MAX_SIZE: u32 = 32768; // 32KB max file

var text_buf: [MAX_SIZE]u8 = [_]u8{0} ** MAX_SIZE;
var text_len: u32 = 0;
var cursor_pos: u32 = 0;
var scroll_line: u32 = 0;
var modified: bool = false;
var filename: [64]u8 = [_]u8{0} ** 64;
var filename_len: u8 = 0;

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
    ed_alloc_w = win.alloc_w; // libc may have rounded up to 16-px stride
    ed_alloc_h = win.alloc_h;
    var canvas = gfx.Canvas.init(win.fb, ed_alloc_w, ed_alloc_h);
    fa.ensureLoaded();
    layoutScrollbar();

    // Check for exec arg (filename)
    var arg_buf: [64]u8 = undefined;
    const arg_len = libc.getExecArg(&arg_buf);
    if (arg_len > 0 and arg_len <= 64) {
        @memcpy(filename[0..arg_len], arg_buf[0..arg_len]);
        filename_len = @intCast(arg_len);
        loadFile();
    }

    var needs_redraw: bool = true;
    var prev_left: bool = false;
    // Mouse state accumulated from window events.
    var cur_mx: i32 = 0;
    var cur_my: i32 = 0;
    var cur_btns: u32 = 0;

    while (true) {
        var should_quit = false;

        while (libc.pollEvent()) |ev| {
            // Scrollbar consumes wheel + drag/track interactions and writes
            // scroll_line directly. Editor still owns cursor-positioning
            // clicks in the text area below.
            if (scrollbar.handleEvent(ev, totalLines(), visibleLines(), &scroll_line)) {
                needs_redraw = true;
            }
            switch (ev.kindOf()) {
                .close_request => {
                    should_quit = true;
                },
                .resize => {
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
                    if (ch == 0x1B) {
                        should_quit = true;
                    } else if (ch != 0) {
                        if (handleKey(ch)) needs_redraw = true;
                    }
                },
                .key_special => {
                    const ch: u8 = @truncate(ev.a);
                    if (handleKey(ch)) needs_redraw = true;
                },
                .mouse_move => {
                    cur_mx = @bitCast(ev.a);
                    cur_my = @bitCast(ev.b);
                    cur_btns = ev.c;
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

        // Cursor-positioning click (left-press inside the text area, away
        // from the scrollbar).
        const left = (cur_btns & 1) != 0;
        const in_scrollbar = cur_mx >= @as(i32, @intCast(scrollbar.x));
        if (left and !prev_left and !in_scrollbar) {
            if (cur_my >= @as(i32, TOOLBAR_H) and cur_my < @as(i32, @intCast(win_h -| STATUS_H))) {
                const click_line = @as(u32, @intCast(cur_my - @as(i32, TOOLBAR_H))) / C.CH16 + scroll_line;
                var click_col: u32 = 0;
                if (cur_mx > @as(i32, LINE_NUM_W)) {
                    click_col = @as(u32, @intCast(cur_mx - @as(i32, LINE_NUM_W))) / C.CW16;
                }
                moveCursorToLineCol(click_line, click_col);
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

fn handleKey(ch: u8) bool {
    // Ctrl+S = save
    if (ch == 0x13) {
        saveFile();
        return true;
    }
    // Ctrl+Q = quit
    if (ch == 0x11) {
        libc.destroyWindow();
        libc.exit();
    }

    // Arrow keys
    if (ch == 0x80) { // UP
        moveCursorUp();
        return true;
    }
    if (ch == 0x81) { // DOWN
        moveCursorDown();
        return true;
    }
    if (ch == 0x82) { // LEFT
        if (cursor_pos > 0) cursor_pos -= 1;
        ensureCursorVisible();
        return true;
    }
    if (ch == 0x83) { // RIGHT
        if (cursor_pos < text_len) cursor_pos += 1;
        ensureCursorVisible();
        return true;
    }

    // Backspace
    if (ch == 0x08) {
        if (cursor_pos > 0 and text_len > 0) {
            // Shift text left
            const src = text_buf[cursor_pos..text_len];
            @memcpy(text_buf[cursor_pos - 1 ..][0..src.len], src);
            text_len -= 1;
            cursor_pos -= 1;
            modified = true;
            ensureCursorVisible();
        }
        return true;
    }

    // Enter
    if (ch == '\n') {
        if (text_len < MAX_SIZE - 1) {
            insertChar('\n');
            modified = true;
        }
        return true;
    }

    // Printable
    if (ch >= 0x20 and ch < 0x7F) {
        if (text_len < MAX_SIZE - 1) {
            insertChar(ch);
            modified = true;
        }
        return true;
    }

    return false;
}

fn insertChar(ch: u8) void {
    if (text_len >= MAX_SIZE - 1) return;
    if (cursor_pos > text_len) cursor_pos = text_len;
    // Shift text right from cursor_pos (reverse to avoid overlap)
    var i: u32 = text_len;
    while (i > cursor_pos) : (i -= 1) {
        text_buf[i] = text_buf[i - 1];
    }
    text_buf[cursor_pos] = ch;
    text_len += 1;
    cursor_pos += 1;
    ensureCursorVisible();
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
    // Find start of target_line
    while (pos < text_len and line < target_line) : (pos += 1) {
        if (text_buf[pos] == '\n') line += 1;
    }
    if (line < target_line) {
        // Target line doesn't exist, go to end
        cursor_pos = text_len;
        ensureCursorVisible();
        return;
    }
    // Now pos is at start of target_line, advance by target_col
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
        if (text_buf[i] == '\n') {
            line += 1;
            col = 0;
        } else {
            col += 1;
        }
    }
    return .{ .line = line, .col = col };
}

fn totalLines() u32 {
    var count: u32 = 1;
    var i: u32 = 0;
    while (i < text_len) : (i += 1) {
        if (text_buf[i] == '\n') count += 1;
    }
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
    modified = false;
}

fn saveFile() void {
    if (filename_len == 0) return;
    const fd = libc.openFlags(filename[0..filename_len], libc.O_CREATE) orelse return;
    _ = libc.fwrite(fd, text_buf[0..text_len]);
    libc.close(fd);
    modified = false;
}

fn render(canvas: *gfx.Canvas) void {
    canvas.clear(BG);

    // Toolbar — proportional SF Pro Text. After-filename position uses measure
    // so the " *" lands flush regardless of actual glyph widths.
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
    fa.drawTextOpaque(canvas, win_w -| 200, 4, "^S Save  ^Q Quit", 0x666688, TOOLBAR_BG, &fa.default_16);

    // Text area — width carved out for the scrollbar on the right.
    const text_y = TOOLBAR_H;
    const text_h = win_h -| (TOOLBAR_H + STATUS_H);
    const vis = text_h / C.CH16;
    const text_area_w = win_w -| SCROLLBAR_W;
    const max_cols = (text_area_w -| LINE_NUM_W) / C.CW16;

    // Find start position for scroll_line
    var pos: u32 = 0;
    var line: u32 = 0;
    while (pos < text_len and line < scroll_line) : (pos += 1) {
        if (text_buf[pos] == '\n') line += 1;
    }

    // Render visible lines
    const cur = cursorLineCol();
    var row: u32 = 0;
    while (row < vis) : (row += 1) {
        const y = text_y + row * C.CH16;
        const display_line = scroll_line + row;

        // Line number — mono so digits align across rows.
        _ = fa.drawNumOpaque(canvas, 2, y, display_line +| 1, LINE_NUM_FG, BG, &fa.default_mono);
        canvas.drawVLine(LINE_NUM_W - 2, y, C.CH16, 0x333344);

        // Line content — SF Mono. Advance == 9 == old C.CW16, so column math
        // unchanged.
        var col: u32 = 0;
        while (pos < text_len and text_buf[pos] != '\n') : (pos += 1) {
            if (col < max_cols) {
                fa.drawCharOpaque(canvas, LINE_NUM_W + col * C.CW16, y, text_buf[pos], TEXT_FG, BG, &fa.default_mono);
            }
            col += 1;
        }
        if (pos < text_len and text_buf[pos] == '\n') pos += 1; // skip newline

        // Draw cursor on this line
        if (display_line == cur.line) {
            const cx_px = LINE_NUM_W + cur.col * C.CW16;
            if (cx_px < text_area_w) {
                canvas.fillRect(cx_px, y, 2, C.CH16, CURSOR_COLOR);
            }
        }

        // If we've reached the end of text, stop
        if (pos >= text_len and display_line >= cur.line) {
            // Draw cursor on last line if at end
            if (cursor_pos == text_len and display_line + 1 == cur.line + 1) {
                // cursor already drawn above
            }
            break;
        }
    }

    // Scrollbar on the right edge of the text area.
    scrollbar.draw(canvas, totalLines(), visibleLines(), scroll_line);

    // Status bar — text labels in SF Pro, numeric values in SF Mono so they
    // line up when the cursor moves. Use measure() to position labels and
    // numbers since SF Pro Text has variable widths.
    const sy = win_h -| STATUS_H + 2;
    canvas.fillRect(0, win_h -| STATUS_H, win_w, STATUS_H, STATUS_BG);
    fa.drawTextOpaque(canvas, 8, sy, "Ln ", STATUS_FG, STATUS_BG, &fa.default_16);
    var sx: u32 = 8 + fa.default_16.measure("Ln ");
    sx = fa.drawNumOpaque(canvas, sx, sy, cur.line + 1, STATUS_FG, STATUS_BG, &fa.default_mono);
    fa.drawTextOpaque(canvas, sx + 4, sy, "Col ", STATUS_FG, STATUS_BG, &fa.default_16);
    sx = sx + 4 + fa.default_16.measure("Col ");
    sx = fa.drawNumOpaque(canvas, sx, sy, cur.col + 1, STATUS_FG, STATUS_BG, &fa.default_mono);
    fa.drawTextOpaque(canvas, sx + 8, sy, "Size ", STATUS_FG, STATUS_BG, &fa.default_16);
    sx = sx + 8 + fa.default_16.measure("Size ");
    _ = fa.drawNumOpaque(canvas, sx, sy, text_len, STATUS_FG, STATUS_BG, &fa.default_mono);
}
