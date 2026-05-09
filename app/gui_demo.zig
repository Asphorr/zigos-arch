const libc = @import("libc");
const gfx = @import("graphics");

const WIDTH: u32 = 320;
const HEIGHT: u32 = 200;

export fn _start() linksection(".text.entry") callconv(.c) void {
    const win = libc.createWindow(WIDTH, HEIGHT) orelse {
        libc.println("Failed to create GUI window!");
        libc.exit();
    };
    var canvas = gfx.Canvas.init(win.fb, win.alloc_w, win.alloc_h);

    canvas.clear(0x000060);
    canvas.drawRect(0, 0, WIDTH, HEIGHT, 0xFFFFFF);
    canvas.drawText(10, 10, "Paint Demo!", 0xFFFF00);
    canvas.drawText(10, 25, "LClick=white RClick=erase", 0xAAFFAA);
    canvas.drawText(10, 40, "ESC=quit", 0xAAFFAA);

    const colors = [_]u32{ 0xFF0000, 0x00FF00, 0x0000FF, 0xFFFF00, 0xFF00FF, 0x00FFFF, 0xFFFFFF, 0xFF8000 };
    for (colors, 0..) |color, ci| {
        canvas.fillRect(@intCast(10 + ci * 38), HEIGHT - 25, 32, 18, color);
    }

    var draw_color: u32 = 0xFFFFFF;
    libc.present();

    // Latest mouse state — accumulated from window events. Hold-to-paint
    // keeps repainting on each mouse_move while a button is held.
    var cur_mx: i32 = 0;
    var cur_my: i32 = 0;
    var cur_btns: u32 = 0;

    while (true) {
        while (libc.pollEvent()) |ev| {
            switch (ev.kindOf()) {
                .close_request => {
                    libc.destroyWindow();
                    libc.exit();
                },
                .key_char => {
                    if (@as(u8, @truncate(ev.a)) == 0x1B) {
                        libc.destroyWindow();
                        libc.exit();
                    }
                },
                .mouse_move => {
                    cur_mx = @bitCast(ev.a);
                    cur_my = @bitCast(ev.b);
                    cur_btns = ev.c;
                    paintAt(&canvas, cur_mx, cur_my, cur_btns, &draw_color, colors);
                },
                .mouse_button => {
                    cur_btns = ev.buttonsState();
                    cur_mx = @bitCast(ev.b);
                    cur_my = @bitCast(ev.c);
                    paintAt(&canvas, cur_mx, cur_my, cur_btns, &draw_color, colors);
                },
                else => {},
            }
        }
        libc.sleep(10);
    }
}

fn paintAt(canvas: *gfx.Canvas, mx: i32, my: i32, buttons: u32, draw_color: *u32, colors: [8]u32) void {
    if (buttons & 1 != 0) {
        if (my >= @as(i32, @intCast(HEIGHT - 25)) and my < @as(i32, @intCast(HEIGHT - 7))) {
            for (colors, 0..) |color, ci| {
                const px: i32 = @intCast(10 + ci * 38);
                if (mx >= px and mx < px + 32) draw_color.* = color;
            }
        } else if (mx >= 1 and my >= 1 and mx < @as(i32, WIDTH - 1) and my < @as(i32, HEIGHT - 1)) {
            drawBrush(canvas, mx, my, draw_color.*);
        }
    }
    if (buttons & 2 != 0) {
        if (mx >= 1 and my >= 1 and mx < @as(i32, WIDTH - 1) and my < @as(i32, HEIGHT - 1)) {
            drawBrush(canvas, mx, my, 0x000060);
        }
    }
}

fn drawBrush(canvas: *gfx.Canvas, cx: i32, cy: i32, color: u32) void {
    var dy: i32 = -1;
    while (dy <= 1) : (dy += 1) {
        var dx: i32 = -1;
        while (dx <= 1) : (dx += 1) {
            canvas.putPixel(cx + dx, cy + dy, color);
        }
    }
}
