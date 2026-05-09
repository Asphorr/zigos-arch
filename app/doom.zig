// ZigOS Raycaster — Wolfenstein 3D-style 2.5D engine
// Mouse look, WASD movement, gradient ceiling/floor
const libc = @import("libc");
const gfx = @import("graphics");
const fa = @import("font_atlas");

const MAP_W = 20;
const MAP_H = 20;
const TURN_SPEED = 8;
const MOVE_SPEED = 3;
const MOUSE_SENS = 2;
const FRAME_TICKS = 3;

var SCR_W: u32 = 640;
var SCR_H: u32 = 400;

const HUD_H: u32 = 40;
const MINIMAP_S: u32 = 3;

const wall_colors = [6]u32{ 0x000000, 0xBB4444, 0x44AA44, 0x4466CC, 0xBBAA33, 0x888888 };
const wall_dark = [6]u32{ 0x000000, 0x882222, 0x227722, 0x224488, 0x887722, 0x555555 };

const SC_W: u8 = 0x11;
const SC_A: u8 = 0x1E;
const SC_S: u8 = 0x1F;
const SC_D: u8 = 0x20;
const SC_LEFT: u8 = 0x4B;
const SC_RIGHT: u8 = 0x4D;

const SIN_TAB: [1024]i32 = init_sin: {
    @setEvalBranchQuota(20000);
    var t: [1024]i32 = undefined;
    for (0..1024) |i| {
        const p: i32 = @intCast(i % 512);
        const raw = @divTrunc(4 * p * (511 - p), 1023);
        const val = if (raw > 256) @as(i32, 256) else raw;
        t[i] = if (i < 512) val else -val;
    }
    break :init_sin t;
};

fn isin(a: i32) i32 {
    return SIN_TAB[@intCast(@mod(a, 1024))];
}
fn icos(a: i32) i32 {
    return isin(a + 256);
}

const map_data = [MAP_H][MAP_W]u8{
    .{ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 },
    .{ 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
    .{ 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
    .{ 1, 0, 0, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 3, 3, 3, 3, 0, 0, 1 },
    .{ 1, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 3, 0, 0, 1 },
    .{ 1, 0, 0, 2, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 3, 0, 0, 1 },
    .{ 1, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 3, 0, 0, 1 },
    .{ 1, 0, 0, 0, 0, 0, 4, 4, 0, 5, 0, 4, 4, 0, 0, 0, 0, 0, 0, 1 },
    .{ 1, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 1 },
    .{ 1, 0, 0, 5, 5, 0, 4, 0, 0, 0, 0, 0, 4, 0, 5, 5, 0, 0, 0, 1 },
    .{ 1, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 1 },
    .{ 1, 0, 0, 0, 0, 0, 4, 4, 0, 0, 0, 4, 4, 0, 0, 0, 0, 0, 0, 1 },
    .{ 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
    .{ 1, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 0, 0, 1 },
    .{ 1, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 1 },
    .{ 1, 0, 0, 3, 3, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 1 },
    .{ 1, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
    .{ 1, 0, 0, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
    .{ 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
    .{ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 },
};

fn mapAt(x: i32, y: i32) u8 {
    if (x < 0 or y < 0 or x >= MAP_W or y >= MAP_H) return 1;
    return map_data[@intCast(y)][@intCast(x)];
}

var px: i32 = 3 * 256 + 128;
var py: i32 = 2 * 256 + 128;
var pa: i32 = 0;

var canvas: gfx.Canvas = undefined;
var captured: bool = true;
var prev_mx: i32 = 0;
var accum_dx: i32 = 0;

export fn _start() linksection(".text.entry") callconv(.c) void {
    const scr = libc.getScreenSize();
    SCR_W = scr.w * 2 / 5;
    if (SCR_W < 320) SCR_W = 320;
    if (SCR_W > 640) SCR_W = 640;
    SCR_H = scr.h * 2 / 5;
    if (SCR_H < 240) SCR_H = 240;
    if (SCR_H > 440) SCR_H = 440;

    const win = libc.createWindow(SCR_W, SCR_H) orelse libc.exit();
    SCR_W = win.alloc_w; // libc rounded SCR_W up to 16-px stride
    SCR_H = win.alloc_h;
    canvas = gfx.Canvas.init(win.fb, SCR_W, SCR_H);
    fa.ensureLoaded();
    canvas.clear(0);

    const ms = libc.getMouse();
    prev_mx = ms.x;
    libc.setCursorVisible(false); // hide cursor on start

    var last_frame: u32 = 0;
    while (true) {
        // Drain keyboard
        while (true) {
            const ch = libc.readChar();
            if (ch == 0) break;
            if (ch == 0x1B) {
                if (captured) {
                    captured = false;
                    libc.setCursorVisible(true); // show cursor on release
                } else {
                    libc.setCursorVisible(true);
                    libc.destroyWindow();
                    libc.exit();
                }
            }
        }

        // Always read mouse and accumulate deltas (even between frames)
        const ms2 = libc.getMouse();
        if (captured) {
            const dx = ms2.x - prev_mx;
            if (dx != 0) accum_dx += dx;
        }
        prev_mx = ms2.x;

        // Click to re-capture
        if (!captured and (ms2.buttons & 1) != 0) {
            captured = true;
            accum_dx = 0;
            libc.setCursorVisible(false);
        }

        // Frame rate limit
        const now = libc.uptime();
        if (now -% last_frame < FRAME_TICKS) {
            libc.sleep(10);
            continue;
        }
        last_frame = now;

        if (captured) {
            if (accum_dx != 0) {
                pa = @mod(pa + accum_dx * MOUSE_SENS, 1024);
                accum_dx = 0;
            }
            libc.centerMouse();
            prev_mx = libc.getMouse().x;
            pollInput();
        }

        render();
        libc.sleep(10);
    }
}

fn pollInput() void {
    const fwd_x = @divTrunc(icos(pa) * MOVE_SPEED, 64);
    const fwd_y = @divTrunc(isin(pa) * MOVE_SPEED, 64);
    const side_x = @divTrunc(isin(pa) * MOVE_SPEED, 64);
    const side_y = @divTrunc(-icos(pa) * MOVE_SPEED, 64);

    if (libc.keyHeld(SC_W)) tryMove(fwd_x, fwd_y);
    if (libc.keyHeld(SC_S)) tryMove(-fwd_x, -fwd_y);
    if (libc.keyHeld(SC_A)) tryMove(side_x, side_y);
    if (libc.keyHeld(SC_D)) tryMove(-side_x, -side_y);
    if (libc.keyHeld(SC_LEFT)) pa = @mod(pa - TURN_SPEED, 1024);
    if (libc.keyHeld(SC_RIGHT)) pa = @mod(pa + TURN_SPEED, 1024);
}

fn tryMove(dx: i32, dy: i32) void {
    const margin: i32 = 48;
    const mx_off: i32 = if (dx > 0) margin else -margin;
    const my_off: i32 = if (dy > 0) margin else -margin;
    if (mapAt(@divTrunc(px + dx + mx_off, 256), @divTrunc(py, 256)) == 0) px += dx;
    if (mapAt(@divTrunc(px, 256), @divTrunc(py + dy + my_off, 256)) == 0) py += dy;
}

fn render() void {
    const view_h = SCR_H -| HUD_H;
    const half_h: i32 = @intCast(view_h / 2);
    const fov: i32 = 171;

    var col: u32 = 0;
    while (col < SCR_W) : (col += 1) {
        const ray_a = pa - @divTrunc(fov, 2) + @divTrunc(@as(i32, @intCast(col)) * fov, @as(i32, @intCast(SCR_W)));
        const ray = castRay(ray_a);

        var wall_top: u32 = view_h / 2;
        var wall_bot: u32 = view_h / 2;
        var wall_color: u32 = 0;

        if (ray.dist > 0) {
            const cos_d = icos(ray_a - pa);
            const perp = @max(@divTrunc(ray.dist * cos_d, 256), 1);
            const raw_h = @divTrunc(half_h * 256, perp);
            const wh: u32 = @intCast(@min(@as(u32, @intCast(@max(raw_h, 0))), view_h));
            wall_top = (view_h -| wh) / 2;
            wall_bot = wall_top + wh;

            const base = if (ray.side == 0) wall_colors[ray.wtype] else wall_dark[ray.wtype];
            const fog = @min(@as(u32, @intCast(@divTrunc(perp, 4))), 180);
            wall_color = darken(base, fog);
        }

        // Ceiling gradient (dark blue to lighter)
        var y: u32 = 0;
        while (y < wall_top) : (y += 1) {
            const t: u32 = y * 256 / (wall_top + 1);
            const r: u32 = 0x10 + t * 0x20 / 256;
            const g: u32 = 0x10 + t * 0x18 / 256;
            const b: u32 = 0x20 + t * 0x30 / 256;
            pxFast(col, y, (r << 16) | (g << 8) | b);
        }
        // Wall
        canvas.drawVLine(col, wall_top, wall_bot -| wall_top, wall_color);
        // Floor gradient (brown to dark)
        y = wall_bot;
        while (y < view_h) : (y += 1) {
            const dist = y - view_h / 2;
            const shade: u32 = @min(dist / 2, 0x40);
            pxFast(col, y, (shade / 2) << 16 | shade << 8 | (shade / 3));
        }
    }

    // Crosshair
    const cx: u32 = SCR_W / 2;
    const cy: u32 = view_h / 2;
    if (captured) {
        canvas.drawHLine(@intCast(cx -| 4), @intCast(cy), 9, 0xCCCCCC);
        canvas.drawVLine(@intCast(cx), cy -| 4, 9, 0xCCCCCC);
    }

    drawHUD(view_h);
    drawMinimap(SCR_W -| (MAP_W * MINIMAP_S + 6), view_h + 4);
}

fn pxFast(x: u32, y: u32, color: u32) void {
    if (x < canvas.width and y < canvas.height)
        canvas.fb[y * canvas.width + x] = color;
}

fn drawHUD(view_h: u32) void {
    canvas.fillRect(0, view_h, SCR_W, HUD_H, 0x1A1A1A);
    canvas.drawHLine(0, @intCast(view_h), SCR_W, 0x333333);

    // Health
    fa.drawTextOpaque(&canvas, 8, view_h + 4, "HP", 0xFF4444, 0x1A1A1A, &fa.default_16);
    canvas.fillRect(30, view_h + 4, 102, 14, 0x333333);
    canvas.fillRect(31, view_h + 5, 100, 12, 0xCC3333);

    if (captured) {
        fa.drawTextOpaque(&canvas, 8, view_h + 22, "WASD+Mouse | ESC Release", 0x556655, 0x1A1A1A, &fa.default_16);
    } else {
        fa.drawTextOpaque(&canvas, 8, view_h + 22, "Click to play | ESC Quit", 0x888855, 0x1A1A1A, &fa.default_16);
    }
}

const Ray = struct { dist: i32, wtype: u8, side: u8 };

fn castRay(angle: i32) Ray {
    const rdx = icos(angle);
    const rdy = isin(angle);
    var map_x: i32 = @divTrunc(px, 256);
    var map_y: i32 = @divTrunc(py, 256);
    const step_x: i32 = if (rdx >= 0) 1 else -1;
    const step_y: i32 = if (rdy >= 0) 1 else -1;
    const abs_rdx = if (rdx < 0) -rdx else rdx;
    const abs_rdy = if (rdy < 0) -rdy else rdy;
    const delta_x: i32 = if (abs_rdx > 0) @divTrunc(256 * 256, abs_rdx) else 999999;
    const delta_y: i32 = if (abs_rdy > 0) @divTrunc(256 * 256, abs_rdy) else 999999;
    var side_x: i32 = if (rdx >= 0) @divTrunc((map_x * 256 + 256 - px) * delta_x, 256) else @divTrunc((px - map_x * 256) * delta_x, 256);
    var side_y: i32 = if (rdy >= 0) @divTrunc((map_y * 256 + 256 - py) * delta_y, 256) else @divTrunc((py - map_y * 256) * delta_y, 256);
    var side: u8 = 0;
    var steps: u32 = 0;
    while (steps < 80) : (steps += 1) {
        if (side_x < side_y) {
            side_x += delta_x;
            map_x += step_x;
            side = 0;
        } else {
            side_y += delta_y;
            map_y += step_y;
            side = 1;
        }
        const w = mapAt(map_x, map_y);
        if (w != 0) return .{ .dist = if (side == 0) side_x - delta_x else side_y - delta_y, .wtype = w, .side = side };
    }
    return .{ .dist = 0, .wtype = 0, .side = 0 };
}

fn darken(color: u32, amount: u32) u32 {
    return ((((color >> 16) & 0xFF) -| amount) << 16) | ((((color >> 8) & 0xFF) -| amount) << 8) | ((color & 0xFF) -| amount);
}

fn drawMinimap(ox: u32, oy: u32) void {
    var my: u32 = 0;
    while (my < MAP_H) : (my += 1) {
        var mx: u32 = 0;
        while (mx < MAP_W) : (mx += 1) {
            const w = map_data[my][mx];
            const c: u32 = if (w != 0) (wall_dark[w] >> 1) & 0x7F7F7F else 0x111111;
            canvas.fillRect(ox + mx * MINIMAP_S, oy + my * MINIMAP_S, MINIMAP_S, MINIMAP_S, c);
        }
    }
    const ppx = ox + @as(u32, @intCast(@divTrunc(px, 256))) * MINIMAP_S + MINIMAP_S / 2;
    const ppy = oy + @as(u32, @intCast(@divTrunc(py, 256))) * MINIMAP_S + MINIMAP_S / 2;
    canvas.fillRect(ppx -| 1, ppy -| 1, 3, 3, 0x00FF00);
    const dir_x: i32 = @as(i32, @intCast(ppx)) + @divTrunc(icos(pa) * 8, 256);
    const dir_y: i32 = @as(i32, @intCast(ppy)) + @divTrunc(isin(pa) * 8, 256);
    canvas.drawLine(@intCast(ppx), @intCast(ppy), dir_x, dir_y, 0x00FF00);
}
