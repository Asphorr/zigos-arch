const libc = @import("libc");
const gfx = @import("graphics");
const ui = @import("ui");

const BG: u32 = 0x1A1A2E;

const labels = [20]u8{
    'C', '/', '*', '-',
    '7', '8', '9', '+',
    '4', '5', '6', '=',
    '1', '2', '3', ' ',
    '0', '.', ' ', ' ',
};

const btn_colors = [20]u32{
    0x666666, 0xFF8800, 0xFF8800, 0xFF8800,
    0x505050, 0x505050, 0x505050, 0xFF8800,
    0x505050, 0x505050, 0x505050, 0x4488CC,
    0x505050, 0x505050, 0x505050, BG,
    0x505050, 0x505050, BG,       BG,
};

var display_val: i32 = 0;
var pending_op: u8 = 0;
var pending_val: i32 = 0;
var fresh: bool = true;

// Allocated (max) dimensions — never changes, this is the canvas stride
var alloc_w: u32 = 0;
var alloc_h: u32 = 0;
// Current visible dimensions — tracks window content area
var vis_w: u32 = 0;
var vis_h: u32 = 0;
// Layout vars
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
    btn_h = btn_w * 3 / 4;
    grid_x = btn_gap;
    grid_y = vis_h / 5;
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    const scr = libc.getScreenSize();
    var init_w = scr.w / 5;
    if (init_w < 200) init_w = 200;
    if (init_w > 400) init_w = 400;
    const init_h = init_w * 14 / 10;

    // Over-allocate FB for resize headroom (cap at 2MB / 4 = 524288 pixels)
    alloc_w = @min(init_w * 2, scr.w);
    alloc_h = @min(init_h * 2, scr.h);
    while (alloc_w * alloc_h > 524288) {
        if (alloc_w > alloc_h) alloc_w -= 16 else alloc_h -= 16;
    }
    computeLayout(init_w, init_h);

    const win = libc.createWindowEx(alloc_w, alloc_h, init_w, init_h) orelse {
        libc.exit();
    };
    alloc_w = win.alloc_w; // libc may have rounded up to 16-px stride
    alloc_h = win.alloc_h;
    var canvas = gfx.Canvas.init(win.fb, alloc_w, alloc_h);
    _ = libc.getWindowAlloc(); // opt this window into F10 grow-on-maximize (re-fetched in .resize)

    var needs_redraw: bool = true;

    // Initial draw
    canvas.clear(BG);
    canvas.fillRect(btn_gap, btn_gap, vis_w -| btn_gap * 2, grid_y -| btn_gap * 2, 0x2A2A3E);
    canvas.drawNumRightAligned(vis_w -| btn_gap * 2, btn_gap + 6, display_val, 0xFFFFFF, 2);
    for (0..20) |bi| {
        if (labels[bi] == ' ') continue;
        const btn = calcButton(@intCast(bi));
        btn.draw(&canvas, btn_colors[bi], 0xFFFFFF);
    }
    libc.present();

    // Event-driven main loop: drain the window event queue, handle each
    // event, redraw if any handler asked for it, sleep when idle. No
    // more polling readChar + getWindowSize + getMouse + diffing button
    // state; the queue gives us key/mouse/resize/close in one ordered
    // stream.
    while (true) {
        // Drain all currently-pending events.
        while (libc.pollEvent()) |ev| {
            switch (ev.kindOf()) {
                .close_request => {
                    libc.destroyWindow();
                    libc.exit();
                },
                .key_char => {
                    const ch: u8 = @truncate(ev.a);
                    if (ch == 0x1B) {
                        libc.destroyWindow();
                        libc.exit();
                    }
                    if ((ch >= '0' and ch <= '9') or
                        ch == '+' or ch == '-' or ch == '*' or ch == '/')
                    {
                        handleButton(ch);
                        needs_redraw = true;
                    } else if (ch == '\n' or ch == '=') {
                        handleButton('=');
                        needs_redraw = true;
                    } else if (ch == 'c' or ch == 'C') {
                        handleButton('C');
                        needs_redraw = true;
                    }
                },
                .mouse_button => {
                    // Left-button press inside any labelled button → activate it.
                    if (ev.buttonIndex() == 0 and ev.buttonPressed()) {
                        const mx: i32 = @bitCast(ev.b);
                        const my: i32 = @bitCast(ev.c);
                        for (0..20) |bi| {
                            if (labels[bi] == ' ') continue;
                            const btn = calcButton(@intCast(bi));
                            if (btn.contains(mx, my)) {
                                handleButton(labels[bi]);
                                needs_redraw = true;
                            }
                        }
                    }
                },
                .resize => {
                    // F10 maximize may have GROWN our framebuffer past the
                    // alloc we requested. Re-fetch and rebuild the canvas at
                    // the new stride before clamping/laying out (FB ptr is
                    // unchanged) so we render crisply instead of upscaled.
                    const wa = libc.getWindowAlloc();
                    if (wa.w != 0 and (wa.w != alloc_w or wa.h != alloc_h)) {
                        alloc_w = wa.w;
                        alloc_h = wa.h;
                        canvas = gfx.Canvas.init(win.fb, alloc_w, alloc_h);
                    }
                    const new_w = @min(ev.a, alloc_w);
                    const new_h = @min(ev.b, alloc_h);
                    if (new_w != vis_w or new_h != vis_h) {
                        computeLayout(new_w, new_h);
                        needs_redraw = true;
                    }
                },
                else => {},
            }
        }

        if (!needs_redraw) {
            libc.sleep(10);
            continue;
        }
        needs_redraw = false;

        canvas.clear(BG);
        canvas.fillRect(btn_gap, btn_gap, vis_w -| btn_gap * 2, grid_y -| btn_gap * 2, 0x2A2A3E);
        canvas.drawNumRightAligned(vis_w -| btn_gap * 2, btn_gap + 6, display_val, 0xFFFFFF, 2);

        for (0..20) |bi| {
            if (labels[bi] == ' ') continue;
            const btn = calcButton(@intCast(bi));
            btn.draw(&canvas, btn_colors[bi], 0xFFFFFF);
        }

        libc.present();
        libc.sleep(10);
    }
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
    switch (pending_op) {
        '+' => display_val = pending_val + display_val,
        '-' => display_val = pending_val - display_val,
        '*' => display_val = pending_val * display_val,
        '/' => {
            if (display_val != 0) display_val = @divTrunc(pending_val, display_val);
        },
        else => {},
    }
}
