// Paint — a bitmap sketchpad.
//
// The toolbar picks the tool, the stroke width and whether shapes are
// filled; the strip at the bottom picks the colour. Strokes go straight
// into the drawing; a shape follows the pointer until the button is let go.
// Keys: P B E L R O C T F pick a tool, 1 2 3 the width, X toggles filling.

const libc = @import("libc");
const gfx = @import("graphics");
const ui = @import("ui");
const app = @import("app");

const PAPER: u32 = 0xFFFFFF;
const SWATCH_BAR_H: u32 = 40;
const SWATCH: u32 = 22;
const SWATCH_GAP: u32 = 6;

const Tool = enum { pencil, brush, eraser, line, rect, ellipse, circle, triangle, fill };

const ToolButton = struct { tool: Tool, icon: ui.Icon, key: u8 };
const tools = [_]ToolButton{
    .{ .tool = .pencil, .icon = .pencil, .key = 'p' },
    .{ .tool = .brush, .icon = .brush, .key = 'b' },
    .{ .tool = .eraser, .icon = .eraser, .key = 'e' },
    .{ .tool = .line, .icon = .line, .key = 'l' },
    .{ .tool = .rect, .icon = .rect, .key = 'r' },
    .{ .tool = .ellipse, .icon = .ellipse, .key = 'o' },
    .{ .tool = .circle, .icon = .circle, .key = 'c' },
    .{ .tool = .triangle, .icon = .triangle, .key = 't' },
    .{ .tool = .fill, .icon = .drop, .key = 'f' },
};

const WidthButton = struct { px: u32, icon: ui.Icon, key: u8 };
const widths = [_]WidthButton{
    .{ .px = 1, .icon = .dot_small, .key = '1' },
    .{ .px = 3, .icon = .dot_medium, .key = '2' },
    .{ .px = 5, .icon = .dot_large, .key = '3' },
};

const colors = [16]u32{
    0x000000, 0xFFFFFF, 0xFF0000, 0x00FF00,
    0x0000FF, 0xFFFF00, 0xFF00FF, 0x00FFFF,
    0x808080, 0xC0C0C0, 0x800000, 0x008000,
    0x000080, 0x808000, 0x800080, 0x008080,
};

/// The drawing: one screenful, of which the window shows the top left.
/// Kept apart from the window so that repainting the window, resizing it
/// or previewing a shape never touches what was drawn.
var doc: gfx.Canvas = undefined;

var tool: Tool = .pencil;
var color: u32 = 0x000000;
var width: u32 = 3;
var fill_shapes: bool = false;

/// The button is down on the drawing: `from` is where it went down, `at`
/// where the pointer is, both in the drawing's coordinates.
var drawing: bool = false;
var from: app.Point = .{ .x = 0, .y = 0 };
var at: app.Point = .{ .x = 0, .y = 0 };

/// Runs still to visit, for the flood fill.
const Seed = struct { x: u16, y: u16 };
const MAX_SEEDS: usize = 32768;
var seeds: [*]Seed = undefined;

pub fn init(_: *app.Window) void {
    const scr = libc.getScreenSize();
    const pixels = libc.malloc(@as(usize, scr.w) * scr.h * 4) orelse libc.exit();
    doc = gfx.Canvas.init(@ptrCast(@alignCast(pixels)), scr.w, scr.h);
    doc.clear(PAPER);
    const seed_mem = libc.malloc(MAX_SEEDS * @sizeOf(Seed)) orelse libc.exit();
    seeds = @ptrCast(@alignCast(seed_mem));
}

// --- Drawing ----------------------------------------------------------------

/// A stroke segment `w` wide with round ends.
fn strokeSegment(a: app.Point, b: app.Point, ink: u32, w: u32) void {
    if (w <= 1) {
        doc.drawLineAA(a.x, a.y, b.x, b.y, ink);
        return;
    }
    doc.drawThickLineAA(a.x, a.y, b.x, b.y, 2 * w + 1, ink);
    doc.fillCircle(b.x, b.y, w, ink);
}

fn strokeInk() u32 {
    return if (tool == .eraser) PAPER else color;
}

fn strokeWidth() u32 {
    return if (tool == .pencil) 1 else width;
}

fn isStroke() bool {
    return tool == .pencil or tool == .brush or tool == .eraser;
}

/// The box from (x0, y0) to (x1, y1), both corners in it, filled. fillRect
/// takes no negative origin, so the box is clipped to the canvas here.
fn fillBox(c: *gfx.Canvas, x0: i32, y0: i32, x1: i32, y1: i32) void {
    const cx0 = @max(x0, 0);
    const cy0 = @max(y0, 0);
    if (x1 < cx0 or y1 < cy0) return;
    c.fillRect(@intCast(cx0), @intCast(cy0), @intCast(x1 - cx0 + 1), @intCast(y1 - cy0 + 1), color);
}

fn edge(c: *gfx.Canvas, x0: i32, y0: i32, x1: i32, y1: i32) void {
    if (width <= 1) c.drawLineAA(x0, y0, x1, y1, color) else c.drawThickLineAA(x0, y0, x1, y1, width, color);
}

/// The shape of the current tool between `a` and `b`, drawn on `c` moved
/// by (ox, oy): on the drawing itself, or on the window as a preview.
/// An outline is `width` thick.
fn drawShape(c: *gfx.Canvas, ox: i32, oy: i32, a: app.Point, b: app.Point) void {
    const x0 = a.x + ox;
    const y0 = a.y + oy;
    const x1 = b.x + ox;
    const y1 = b.y + oy;
    const lx = @min(x0, x1);
    const ly = @min(y0, y1);
    const hx = @max(x0, x1);
    const hy = @max(y0, y1);
    const w: i32 = @intCast(width);
    switch (tool) {
        .line => edge(c, x0, y0, x1, y1),
        .rect => if (fill_shapes or hx - lx < 2 * w or hy - ly < 2 * w) {
            fillBox(c, lx, ly, hx, hy);
        } else {
            fillBox(c, lx, ly, hx, ly + w - 1);
            fillBox(c, lx, hy - w + 1, hx, hy);
            fillBox(c, lx, ly + w, lx + w - 1, hy - w);
            fillBox(c, hx - w + 1, ly + w, hx, hy - w);
        },
        .ellipse => {
            const rx: u32 = @intCast(@divTrunc(hx - lx, 2));
            const ry: u32 = @intCast(@divTrunc(hy - ly, 2));
            if (rx == 0 or ry == 0) return;
            const cx = @divTrunc(lx + hx, 2);
            const cy = @divTrunc(ly + hy, 2);
            // A ring as wide as its radius is the whole ellipse.
            c.drawEllipseAA(cx, cy, rx, ry, if (fill_shapes) @max(rx, ry) else width, color);
        },
        .circle => {
            // Centre where the button went down, radius out to the pointer.
            const dx: i64 = x1 - x0;
            const dy: i64 = y1 - y0;
            const dist_sq: u64 = @intCast(dx * dx + dy * dy);
            var r: u32 = 0;
            while (@as(u64, r) * r < dist_sq) r += 1;
            if (r == 0) return;
            c.drawCircleAA(x0, y0, r, if (fill_shapes) r else width, color);
        },
        .triangle => {
            // Base along the bottom of the box, apex at the middle of its top.
            const apex_x = @divTrunc(lx + hx, 2);
            if (fill_shapes) {
                c.fillTriangle(lx, hy, hx, hy, apex_x, ly, color);
                // A hairline outline smooths the slanted edges.
                c.drawTriangle(lx, hy, hx, hy, apex_x, ly, color);
            } else {
                edge(c, lx, hy, hx, hy);
                edge(c, hx, hy, apex_x, ly);
                edge(c, apex_x, ly, lx, hy);
            }
        },
        else => {},
    }
}

/// Recolour the area of one colour around `p`, a row at a time: each run
/// of that colour is filled whole, and the runs touching it above and
/// below are queued.
fn floodFill(p: app.Point, ink: u32) void {
    if (p.x < 0 or p.y < 0 or p.x >= doc.width or p.y >= doc.height) return;
    const w: u32 = doc.width;
    const h: u32 = doc.height;
    const px = doc.fb;
    const target = px[@as(usize, @intCast(p.y)) * w + @as(usize, @intCast(p.x))];
    if (target == ink) return;

    seeds[0] = .{ .x = @intCast(p.x), .y = @intCast(p.y) };
    var n: usize = 1;
    while (n > 0) {
        n -= 1;
        const s = seeds[n];
        const row = px + @as(usize, s.y) * w;
        if (row[s.x] != target) continue;
        var xl: u32 = s.x;
        while (xl > 0 and row[xl - 1] == target) xl -= 1;
        var xr: u32 = s.x;
        while (xr + 1 < w and row[xr + 1] == target) xr += 1;
        for (xl..xr + 1) |x| row[x] = ink;

        const neighbours = [2]?u32{ if (s.y > 0) s.y - 1 else null, if (s.y + 1 < h) s.y + 1 else null };
        for (neighbours) |maybe_y| {
            const ny = maybe_y orelse continue;
            const nrow = px + @as(usize, ny) * w;
            var x = xl;
            while (x <= xr) {
                if (nrow[x] != target) {
                    x += 1;
                    continue;
                }
                // A full queue leaves this run unfilled rather than overrun.
                if (n < MAX_SEEDS) {
                    seeds[n] = .{ .x = @intCast(x), .y = @intCast(ny) };
                    n += 1;
                }
                while (x <= xr and nrow[x] == target) x += 1;
            }
        }
    }
}

// --- The window -------------------------------------------------------------

fn keys(u: *app.Ui) void {
    if (u.key == 0) return;
    const ch = if (u.key >= 'A' and u.key <= 'Z') u.key + 32 else u.key;
    for (tools) |t| {
        if (t.key == ch) tool = t.tool;
    }
    for (widths) |w| {
        if (w.key == ch) width = w.px;
    }
    if (ch == 'x') fill_shapes = !fill_shapes;
    u.repaint();
}

/// The pointer on the drawing, whose top left is the area's.
fn pointer(u: *app.Ui, area: app.Rect) void {
    const ox: i32 = @intCast(area.x);
    const oy: i32 = @intCast(area.y);
    if (u.pressed(area)) |p| {
        from = .{ .x = p.x - ox, .y = p.y - oy };
        at = from;
        if (tool == .fill) {
            floodFill(from, color);
            return;
        }
        drawing = true;
        if (isStroke()) strokeSegment(from, from, strokeInk(), strokeWidth());
        return;
    }
    if (!drawing) return;
    if (u.dragging(area)) |p| {
        const next = app.Point{ .x = p.x - ox, .y = p.y - oy };
        if (next.x == at.x and next.y == at.y) return;
        if (isStroke()) strokeSegment(at, next, strokeInk(), strokeWidth());
        at = next;
        u.repaint();
        return;
    }
    // Let go: the shape as last previewed becomes part of the drawing.
    drawing = false;
    if (!isStroke()) drawShape(&doc, 0, 0, from, at);
    u.repaint();
}

fn swatches(u: *app.Ui, strip: app.Rect) void {
    const p = &ui.palette;
    const y = strip.y + 1 + (strip.h - 1 - SWATCH) / 2;
    for (colors, 0..) |c, i| {
        const r = app.Rect{ .x = strip.x + 12 + @as(u32, @intCast(i)) * (SWATCH + SWATCH_GAP), .y = y, .w = SWATCH, .h = SWATCH };
        if (r.x + r.w + 12 > strip.x + strip.w) break;
        if (u.clicked(r)) color = c;
        if (!u.painting) continue;
        // A ring around the colour in use; a hairline keeps dark colours
        // apart from the bar.
        if (c == color) u.canvas.fillRoundedRect(r.x - 3, r.y - 3, r.w + 6, r.h + 6, 8, p.text_strong);
        u.canvas.fillRoundedRect(r.x - 1, r.y - 1, r.w + 2, r.h + 2, 6, p.card_border);
        u.canvas.fillRoundedRect(r.x, r.y, r.w, r.h, 5, c);
    }
}

pub fn frame(u: *app.Ui) void {
    if (!u.painting) keys(u);

    // The drawing is painted before the bars around it, though it lies
    // between them: a shape previewed past its edge is then covered by the
    // bars instead of drawn over them.
    const area = app.Rect{ .x = 0, .y = app.BAR_H, .w = u.w, .h = u.h -| (app.BAR_H + SWATCH_BAR_H) };
    if (u.painting) {
        const cols = @min(area.w, doc.width);
        var y: u32 = 0;
        while (y < @min(area.h, doc.height)) : (y += 1) {
            const src = doc.fb + @as(usize, y) * doc.width;
            const dst = u.canvas.fb + @as(usize, area.y + y) * u.canvas.width + area.x;
            for (0..cols) |x| dst[x] = src[x];
        }
        if (drawing and !isStroke()) drawShape(u.canvas, @intCast(area.x), @intCast(area.y), from, at);
    }

    u.beginBar();
    for (tools) |t| {
        if (u.iconToggle(t.icon, tool == t.tool)) tool = t.tool;
    }
    _ = u.space(6, 1);
    for (widths) |w| {
        if (u.iconToggle(w.icon, width == w.px)) width = w.px;
    }
    _ = u.space(6, 1);
    if (u.iconToggle(.filled, fill_shapes)) fill_shapes = !fill_shapes;
    u.endBar();

    swatches(u, u.bottomBar(SWATCH_BAR_H));
    if (!u.painting) pointer(u, area);
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    const scr = libc.getScreenSize();
    app.run(@This(), .{
        .width = @max(560, @min(scr.w * 2 / 5, 760)),
        .height = @max(400, @min(scr.h / 2, 560)),
        .escape_closes = true,
    });
}
