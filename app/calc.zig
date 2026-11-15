const libc = @import("libc");
const gfx = @import("graphics");
const ui = @import("ui");
const fa = @import("font_atlas");
const app = @import("app");

const BG: u32 = 0x1E1E20;
const DISPLAY_BG: u32 = 0x2A2A2D;
const KEY_DIGIT: u32 = 0x3C3C40;
const KEY_CLEAR: u32 = 0x5E5E63;
const KEY_OP: u32 = 0xFF9F0A;
const KEY_EQUALS: u32 = 0x0A84FF;

const labels = [20]u8{
    'C', '/', '*', '-',
    '7', '8', '9', '+',
    '4', '5', '6', '=',
    '1', '2', '3', ' ',
    '0', '<', ' ', ' ',
};

const btn_colors = [20]u32{
    KEY_CLEAR, KEY_OP,    KEY_OP,    KEY_OP,
    KEY_DIGIT, KEY_DIGIT, KEY_DIGIT, KEY_OP,
    KEY_DIGIT, KEY_DIGIT, KEY_DIGIT, KEY_EQUALS,
    KEY_DIGIT, KEY_DIGIT, KEY_DIGIT, BG,
    KEY_DIGIT, KEY_DIGIT, BG,        BG,
};

var display_val: i32 = 0;
var pending_op: u8 = 0;
var pending_val: i32 = 0;
var fresh: bool = true;

// Layout for the current content size.
var vis_w: u32 = 0;
var vis_h: u32 = 0;
var btn_w: u32 = 0;
var btn_h: u32 = 0;
var btn_gap: u32 = 0;
var grid_x: u32 = 0;
var grid_y: u32 = 0;

fn computeLayout(w: u32, h: u32) void {
    vis_w = w;
    vis_h = h;
    btn_gap = vis_w / 40;
    if (btn_gap < 2) btn_gap = 2;
    btn_w = (vis_w -| btn_gap * 5) / 4;
    grid_x = btn_gap;
    grid_y = vis_h / 5;
    // Five rows fill the window below the display.
    btn_h = (vis_h -| grid_y -| btn_gap * 5) / 5;
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    const scr = libc.getScreenSize();
    // Typed: a bare @min against 400 would be u9 and overflow below.
    const w: u32 = @min(@max(scr.w / 5, 200), 400);
    app.run(@This(), .{ .width = w, .height = w * 14 / 10, .escape_closes = true });
}

pub fn event(win: *app.Window, ev: app.Event) void {
    switch (ev.kindOf()) {
        .key_char => if (keyLabel(@truncate(ev.a))) |label| {
            handleButton(label);
            win.invalidate();
        },
        .mouse_button => if (app.leftPress(ev)) |p| {
            // Hit-test against the layout of the size being shown.
            computeLayout(win.w, win.h);
            for (0..20) |bi| {
                if (labels[bi] == ' ') continue;
                if (calcButton(@intCast(bi)).contains(p.x, p.y)) {
                    handleButton(labels[bi]);
                    win.invalidate();
                }
            }
        },
        else => {},
    }
}

/// The key a typed character stands for.
fn keyLabel(ch: u8) ?u8 {
    return switch (ch) {
        '0'...'9', '+', '-', '*', '/', '=' => ch,
        '\n' => '=',
        'c', 'C' => 'C',
        0x08, 0x7F => '<',
        else => null,
    };
}

pub fn draw(win: *app.Window) void {
    const canvas = &win.canvas;
    computeLayout(win.w, win.h);
    canvas.clear(BG);

    // Display: a rounded panel, the value right-aligned in the 24 px face.
    const disp_w = vis_w -| btn_gap * 2;
    const disp_h = grid_y -| btn_gap * 2;
    canvas.fillRect(btn_gap, btn_gap, disp_w, disp_h, DISPLAY_BG);
    canvas.roundCornersRadius(btn_gap, btn_gap, disp_w, disp_h, 10, BG);

    var buf: [12]u8 = undefined;
    const text = formatValue(&buf, display_val);
    const atlas = fa.getDefault24();
    const pad: u32 = 12;
    const text_w = atlas.measure(text);
    const tx: u32 = btn_gap + disp_w -| pad -| text_w;
    const ty: u32 = btn_gap + (disp_h -| atlas.line_height) / 2;
    fa.drawText(canvas, @intCast(tx), @intCast(ty), text, 0xFFFFFF, atlas);

    for (0..20) |bi| {
        if (labels[bi] == ' ') continue;
        const btn = calcButton(@intCast(bi));
        btn.drawRounded(canvas, btn_colors[bi], 0xFFFFFF, BG);
    }
}

/// Decimal text of `val` in `buf`.
fn formatValue(buf: *[12]u8, val: i32) []const u8 {
    var v: u32 = @abs(val);
    var i: usize = buf.len;
    while (true) {
        i -= 1;
        buf[i] = @intCast('0' + v % 10);
        v /= 10;
        if (v == 0) break;
    }
    if (val < 0) {
        i -= 1;
        buf[i] = '-';
    }
    return buf[i..];
}

fn calcButton(bi: u32) ui.Button {
    const col = bi % 4;
    const row = bi / 4;
    return .{
        .x = grid_x + col * (btn_w + btn_gap),
        .y = grid_y + row * (btn_h + btn_gap),
        .w = btn_w,
        .h = btn_h,
        .label = labels[bi .. bi + 1],
    };
}

fn handleButton(label: u8) void {
    if (label >= '0' and label <= '9') {
        if (fresh) {
            display_val = 0;
            fresh = false;
        }
        if (display_val < 100000000)
            display_val = display_val * 10 + @as(i32, label - '0');
    } else if (label == 'C') {
        display_val = 0;
        pending_op = 0;
        pending_val = 0;
        fresh = true;
    } else if (label == '<') {
        // Drop the last digit typed; a result is not edited.
        if (!fresh) display_val = @divTrunc(display_val, 10);
    } else if (label == '=') {
        doOp();
        pending_op = 0;
        fresh = true;
    } else if (label == '+' or label == '-' or label == '*' or label == '/') {
        if (pending_op != 0) doOp();
        pending_val = display_val;
        pending_op = label;
        fresh = true;
    }
}

fn doOp() void {
    // Saturating: a result past i32 pins at the limit instead of trapping.
    switch (pending_op) {
        '+' => display_val = pending_val +| display_val,
        '-' => display_val = pending_val -| display_val,
        '*' => display_val = pending_val *| display_val,
        '/' => {
            if (display_val == -1) {
                display_val = 0 -| pending_val;
            } else if (display_val != 0) {
                display_val = @divTrunc(pending_val, display_val);
            }
        },
        else => {},
    }
}
