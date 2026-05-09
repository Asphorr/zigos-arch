const libc = @import("libc");
const gfx = @import("graphics");
const fa = @import("font_atlas");

const TOOLBAR_H: u32 = 36;
const COLORBAR_H: u32 = 30;

// Allocated (max) FB dimensions — never change, this is the canvas stride
var alloc_w: u32 = 500;
var alloc_h: u32 = 400;
// Current visible dimensions — tracks window content area (clamped to alloc)
var vis_w: u32 = 500;
var vis_h: u32 = 400;

fn canvasY() u32 {
    return TOOLBAR_H;
}
fn canvasH() u32 {
    return vis_h -| (TOOLBAR_H + COLORBAR_H);
}

const BG: u32 = 0x2D2D2D;
const TOOLBAR_BG: u32 = 0x383838;
const BTN_BG: u32 = 0x4A4A4A;
const BTN_SEL: u32 = 0x007AFF;
const TEXT_FG: u32 = 0xE0E0E0;
const CANVAS_BG: u32 = 0xFFFFFF;

const Tool = enum { pencil, brush, eraser, line, rect, ellipse, circle, triangle, fill };

const tool_names = [_][]const u8{ "Pen", "Brh", "Ers", "Lin", "Rct", "Elp", "Cir", "Tri", "Fil" };
const tool_vals = [_]Tool{ .pencil, .brush, .eraser, .line, .rect, .ellipse, .circle, .triangle, .fill };

const palette = [16]u32{
    0x000000, 0xFFFFFF, 0xFF0000, 0x00FF00,
    0x0000FF, 0xFFFF00, 0xFF00FF, 0x00FFFF,
    0x808080, 0xC0C0C0, 0x800000, 0x008000,
    0x000080, 0x808000, 0x800080, 0x008080,
};

var canvas: gfx.Canvas = undefined;
var current_tool: Tool = .pencil;
var current_color: u32 = 0x000000;
var brush_size: u32 = 3;
var fill_shapes: bool = false; // toggled with X — affects rect/ellipse/circle/triangle
var drawing = false;
var drag_x0: i32 = 0;
var drag_y0: i32 = 0;
var prev_mx: i32 = -1;
var prev_my: i32 = -1;

export fn _start() linksection(".text.entry") callconv(.c) void {
    main();
    libc.exit();
}

fn main() void {
    const scr = libc.getScreenSize();
    var init_pw = scr.w * 2 / 5;
    if (init_pw < 400) init_pw = 400;
    if (init_pw > 640) init_pw = 640;
    var init_ph = scr.h * 2 / 5;
    if (init_ph < 300) init_ph = 300;
    if (init_ph > 500) init_ph = 500;
    alloc_w = @min(init_pw * 2, scr.w);
    alloc_h = @min(init_ph * 2, scr.h);
    while (alloc_w * alloc_h > 524288) {
        if (alloc_w > alloc_h) alloc_w -= 16 else alloc_h -= 16;
    }
    vis_w = init_pw;
    vis_h = init_ph;

    const win = libc.createWindowEx(alloc_w, alloc_h, init_pw, init_ph) orelse {
        libc.exit();
        return;
    };
    alloc_w = win.alloc_w; // libc may have rounded up to 16-px stride
    alloc_h = win.alloc_h;
    canvas = gfx.Canvas.init(win.fb, alloc_w, alloc_h);
    fa.ensureLoaded();
    canvas.clear(BG);

    drawToolbar();
    drawColorBar();
    canvas.fillRect(0, canvasY(), vis_w, canvasH(), CANVAS_BG);

    libc.present();

    // Mouse state accumulated from window events. Stroke continuity is
    // already provided by handleMouse's prev_mx/prev_my Bresenham, so
    // squashing multiple mouse_move events into one frame's `cur_*`
    // doesn't drop pixels along a fast drag.
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
                    const ch: u8 = @truncate(ev.a);
                    if (ch == 0x1B) {
                        libc.destroyWindow();
                        libc.exit();
                    }
                    handleKey(ch);
                },
                .resize => {
                    const new_w = @min(ev.a, alloc_w);
                    const new_h = @min(ev.b, alloc_h);
                    if (new_w != vis_w or new_h != vis_h) {
                        // Clear the strip between old and new color bar positions
                        const old_cb_y = vis_h -| COLORBAR_H;
                        vis_w = new_w;
                        vis_h = new_h;
                        const new_cb_y = vis_h -| COLORBAR_H;
                        if (new_cb_y > old_cb_y) {
                            canvas.fillRect(0, old_cb_y, vis_w, new_cb_y - old_cb_y, CANVAS_BG);
                        }
                        drawToolbar();
                        drawColorBar();
                    }
                },
                .mouse_move => {
                    cur_mx = @bitCast(ev.a);
                    cur_my = @bitCast(ev.b);
                    cur_btns = ev.c;
                    handleMouse(cur_mx, cur_my, cur_btns);
                },
                .mouse_button => {
                    cur_btns = ev.buttonsState();
                    cur_mx = @bitCast(ev.b);
                    cur_my = @bitCast(ev.c);
                    handleMouse(cur_mx, cur_my, cur_btns);
                },
                else => {},
            }
        }
        libc.sleep(10);
    }
}

fn handleKey(ch: u8) void {
    switch (ch) {
        'p', 'P' => {
            current_tool = .pencil;
            drawToolbar();
        },
        'b', 'B' => {
            current_tool = .brush;
            drawToolbar();
        },
        'e', 'E' => {
            current_tool = .eraser;
            drawToolbar();
        },
        'l', 'L' => {
            current_tool = .line;
            drawToolbar();
        },
        'r', 'R' => {
            current_tool = .rect;
            drawToolbar();
        },
        'c', 'C' => {
            current_tool = .circle;
            drawToolbar();
        },
        't', 'T' => {
            current_tool = .triangle;
            drawToolbar();
        },
        'f', 'F' => {
            current_tool = .fill;
            drawToolbar();
        },
        'x', 'X' => {
            fill_shapes = !fill_shapes;
            drawToolbar();
        },
        '1' => {
            brush_size = 1;
            drawToolbar();
        },
        '2' => {
            brush_size = 3;
            drawToolbar();
        },
        '3' => {
            brush_size = 5;
            drawToolbar();
        },
        else => {},
    }
}

fn handleMouse(mx: i32, my: i32, buttons: u32) void {
    const left = buttons & 1 != 0;

    // Toolbar click
    if (left and my >= 0 and my < @as(i32, TOOLBAR_H)) {
        const btn_w: i32 = 40;
        const btn_step: i32 = 44;
        for (tool_vals, 0..) |tool, i| {
            const bx: i32 = 4 + @as(i32, @intCast(i)) * btn_step;
            if (mx >= bx and mx < bx + btn_w) {
                current_tool = tool;
                drawToolbar();
                return;
            }
        }
        // Fill-mode toggle button (right of last tool).
        const fill_x: i32 = 4 + @as(i32, @intCast(tool_vals.len)) * btn_step + 4;
        if (mx >= fill_x and mx < fill_x + 44) {
            fill_shapes = !fill_shapes;
            drawToolbar();
            return;
        }
        return;
    }

    // Color bar click
    if (left and my >= @as(i32, @intCast(vis_h -| COLORBAR_H))) {
        const sw: i32 = 30;
        for (palette, 0..) |color, i| {
            const sx: i32 = 8 + @as(i32, @intCast(i)) * (sw + 4);
            if (mx >= sx and mx < sx + sw) {
                current_color = color;
                drawColorBar();
                return;
            }
        }
        return;
    }

    // Canvas area
    if (my >= @as(i32, @intCast(canvasY())) and my < @as(i32, @intCast(canvasY() + canvasH())) and mx >= 0 and mx < @as(i32, @intCast(vis_w))) {
        if (left and !drawing) {
            drawing = true;
            drag_x0 = mx;
            drag_y0 = my;
            prev_mx = mx;
            prev_my = my;

            if (current_tool == .fill) {
                floodFill(mx, my, current_color);
                drawing = false;
            } else if (current_tool == .pencil) {
                stamp(mx, my, current_color, 1);
            } else if (current_tool == .brush) {
                stamp(mx, my, current_color, brush_size);
            } else if (current_tool == .eraser) {
                stamp(mx, my, CANVAS_BG, brush_size);
            }
        } else if (left and drawing) {
            switch (current_tool) {
                .pencil => drawStrokeTo(mx, my, current_color, 1),
                .brush => drawStrokeTo(mx, my, current_color, brush_size),
                .eraser => drawStrokeTo(mx, my, CANVAS_BG, brush_size),
                else => {},
            }
            prev_mx = mx;
            prev_my = my;
        } else if (!left and drawing) {
            drawing = false;
            switch (current_tool) {
                .line => {
                    if (brush_size <= 1)
                        canvas.drawLineAA(drag_x0, drag_y0, mx, my, current_color)
                    else
                        canvas.drawThickLineAA(drag_x0, drag_y0, mx, my, brush_size, current_color);
                },
                .rect => drawRectTool(drag_x0, drag_y0, mx, my, current_color),
                .ellipse => drawEllipseTool(drag_x0, drag_y0, mx, my, current_color),
                .circle => drawCircleTool(drag_x0, drag_y0, mx, my, current_color),
                .triangle => drawTriangleTool(drag_x0, drag_y0, mx, my, current_color),
                else => {},
            }
        }
    } else {
        if (!left) drawing = false;
    }
}

fn stamp(x: i32, y: i32, color: u32, size: u32) void {
    if (size <= 1) {
        canvas.putPixel(x, y, color);
    } else {
        canvas.drawFilledCircle(x, y, size, color);
    }
}

fn drawStrokeTo(mx: i32, my: i32, color: u32, size: u32) void {
    var x0 = prev_mx;
    var y0 = prev_my;
    const dx: i32 = if (mx > x0) mx - x0 else x0 - mx;
    const dy: i32 = -(if (my > y0) my - y0 else y0 - my);
    const sx: i32 = if (x0 < mx) 1 else -1;
    const sy: i32 = if (y0 < my) 1 else -1;
    var err = dx + dy;
    while (true) {
        stamp(x0, y0, color, size);
        if (x0 == mx and y0 == my) break;
        const e2 = 2 * err;
        if (e2 >= dy) {
            err += dy;
            x0 += sx;
        }
        if (e2 <= dx) {
            err += dx;
            y0 += sy;
        }
    }
}

fn drawRectTool(x0: i32, y0: i32, x1: i32, y1: i32, color: u32) void {
    const lx = @min(x0, x1);
    const ly = @min(y0, y1);
    const hx = @max(x0, x1);
    const hy = @max(y0, y1);
    const w: u32 = @intCast(hx - lx + 1);
    const h: u32 = @intCast(hy - ly + 1);
    if (fill_shapes) {
        if (lx >= 0 and ly >= 0) canvas.fillRect(@intCast(lx), @intCast(ly), w, h, color);
    } else {
        canvas.drawLineAA(lx, ly, hx, ly, color);
        canvas.drawLineAA(hx, ly, hx, hy, color);
        canvas.drawLineAA(hx, hy, lx, hy, color);
        canvas.drawLineAA(lx, hy, lx, ly, color);
    }
}

fn drawEllipseTool(x0: i32, y0: i32, x1: i32, y1: i32, color: u32) void {
    // Drag bbox defines the ellipse — center + half-extents.
    const lx = @min(x0, x1);
    const ly = @min(y0, y1);
    const hx = @max(x0, x1);
    const hy = @max(y0, y1);
    const cx = @divTrunc(lx + hx, 2);
    const cy = @divTrunc(ly + hy, 2);
    const rx: u32 = @intCast(@divTrunc(hx - lx, 2));
    const ry: u32 = @intCast(@divTrunc(hy - ly, 2));
    if (rx == 0 or ry == 0) return;
    if (fill_shapes) {
        canvas.fillEllipse(cx, cy, rx, ry, color);
    } else {
        canvas.drawEllipseAA(cx, cy, rx, ry, 1, color);
    }
}

fn drawCircleTool(x0: i32, y0: i32, x1: i32, y1: i32, color: u32) void {
    // Drag distance defines the radius (center is the first click).
    const dx = x1 - x0;
    const dy = y1 - y0;
    const dist_sq: u32 = @intCast(dx * dx + dy * dy);
    var r: u32 = 1;
    while (r * r < dist_sq) r += 1;
    if (r == 0) return;
    if (fill_shapes) {
        canvas.fillCircle(x0, y0, r, color);
    } else {
        canvas.drawCircleAA(x0, y0, r, 1, color);
    }
}

fn drawTriangleTool(x0: i32, y0: i32, x1: i32, y1: i32, color: u32) void {
    // Drag bbox defines an isoceles triangle: base along the bottom of the
    // bbox, apex at the top-center.
    const lx = @min(x0, x1);
    const ly = @min(y0, y1);
    const hx = @max(x0, x1);
    const hy = @max(y0, y1);
    const apex_x = @divTrunc(lx + hx, 2);
    if (fill_shapes) {
        canvas.fillTriangle(lx, hy, hx, hy, apex_x, ly, color);
    } else {
        canvas.drawTriangle(lx, hy, hx, hy, apex_x, ly, color);
    }
}

fn floodFill(sx: i32, sy: i32, color: u32) void {
    if (sx < 0 or sy < 0) return;
    const ux: u32 = @intCast(sx);
    const uy: u32 = @intCast(sy);
    if (ux >= vis_w or uy >= vis_h) return;

    const target = canvas.fb[uy * alloc_w + ux];
    if (target == color) return;

    const STACK_SIZE = 4096;
    var stack_x: [STACK_SIZE]u16 = undefined;
    var stack_y: [STACK_SIZE]u16 = undefined;
    var sp: u32 = 0;

    stack_x[0] = @intCast(ux);
    stack_y[0] = @intCast(uy);
    sp = 1;

    while (sp > 0) {
        sp -= 1;
        const px = stack_x[sp];
        const py = stack_y[sp];
        if (px >= vis_w or py < canvasY() or py >= canvasY() + canvasH()) continue;
        const idx = @as(u32, py) * alloc_w + @as(u32, px);
        if (canvas.fb[idx] != target) continue;

        canvas.fb[idx] = color;

        if (sp + 4 < STACK_SIZE) {
            if (px > 0) {
                stack_x[sp] = px - 1;
                stack_y[sp] = py;
                sp += 1;
            }
            if (px + 1 < vis_w) {
                stack_x[sp] = px + 1;
                stack_y[sp] = py;
                sp += 1;
            }
            if (py > 0) {
                stack_x[sp] = px;
                stack_y[sp] = py - 1;
                sp += 1;
            }
            if (py + 1 < vis_h) {
                stack_x[sp] = px;
                stack_y[sp] = py + 1;
                sp += 1;
            }
        }
    }
}

fn drawToolbar() void {
    canvas.fillRect(0, 0, vis_w, TOOLBAR_H, TOOLBAR_BG);
    const btn_w: u32 = 40;
    const btn_step: u32 = 44;
    for (tool_vals, tool_names, 0..) |tool, name, i| {
        const bx: u32 = 4 + @as(u32, @intCast(i)) * btn_step;
        if (bx + btn_w > vis_w) break;
        const bg: u32 = if (tool == current_tool) BTN_SEL else BTN_BG;
        canvas.fillRect(bx, 4, btn_w, 28, bg);
        fa.drawTextCenteredOpaque(&canvas, bx, 10, btn_w, name, TEXT_FG, bg, &fa.default_16);
    }
    const tools_end: u32 = 4 + @as(u32, @intCast(tool_vals.len)) * btn_step;
    if (vis_w > tools_end + 100) {
        const fill_x = tools_end + 4;
        const fill_bg: u32 = if (fill_shapes) BTN_SEL else BTN_BG;
        canvas.fillRect(fill_x, 4, 44, 28, fill_bg);
        fa.drawTextCenteredOpaque(&canvas, fill_x, 10, 44, "Fill", TEXT_FG, fill_bg, &fa.default_16);
        const size_x: u32 = fill_x + 50;
        if (vis_w > size_x + 50) {
            fa.drawTextOpaque(&canvas, size_x, 10, "Sz:", TEXT_FG, TOOLBAR_BG, &fa.default_16);
            const size_ch: u8 = switch (brush_size) {
                1 => '1',
                3 => '2',
                5 => '3',
                else => '?',
            };
            fa.drawCharOpaque(&canvas, size_x + 30, 10, size_ch, 0x88FF88, TOOLBAR_BG, &fa.default_16);
        }
    }
}

fn drawColorBar() void {
    canvas.fillRect(0, vis_h -| COLORBAR_H, vis_w, COLORBAR_H, TOOLBAR_BG);
    for (palette, 0..) |pal_color, i| {
        const sx = 8 + @as(u32, @intCast(i)) * 34;
        const sy = vis_h -| COLORBAR_H + 4;
        if (sx + 28 > vis_w) break;
        canvas.fillRect(sx, sy, 28, 22, pal_color);
        if (pal_color == current_color) {
            canvas.drawRect(sx -| 1, sy -| 1, 30, 24, 0x007AFF);
        }
    }
    if (vis_w >= 40) {
        canvas.fillRect(vis_w -| 40, vis_h -| COLORBAR_H + 4, 32, 22, current_color);
        canvas.drawRect(vis_w -| 41, vis_h -| COLORBAR_H + 3, 34, 24, 0x888888);
    }
}
