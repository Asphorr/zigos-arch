// Shared 2D rasterization primitives — used by both the kernel's gfx.zig
// (operating on the global framebuffer / back buffer) and the userspace
// Canvas in graphics.zig (operating on a per-app window framebuffer).
//
// All primitives are pure functions that take a `Target` describing where
// to write. No globals, no struct state. Kernel and userspace each wrap
// these with thin shims that pass their own (fb, w, h).
//
// Three families:
//   - Sharp scanline fills: fillTriangle, fillPolygonConvex, fillCircle,
//     fillEllipse. Aliased — adjacent fills tile cleanly.
//   - AA outlines: drawLineAA, drawThickLineAA, drawCircleAA, drawEllipseAA.
//     Per-pixel coverage in a 1 px edge band, blended via blendPx.
//   - Stroked paths: strokePolyline, built on drawThickLineAA with
//     bevel-disc joins (round joints, no miter spikes).
//
// Inputs are i32 pixel coords. Internals use 16.16 fixed point for AA
// fractions and 8.8 fixed point for distances. No floating point —
// keeps codegen tight under freestanding.

pub const Target = struct {
    fb: [*]volatile u32,
    w: u32,
    h: u32,
};

pub const Vec2 = struct { x: i32, y: i32 };

// --- Internal helpers -----------------------------------------------------

inline fn iSwap(a: *i32, b: *i32) void {
    const t = a.*;
    a.* = b.*;
    b.* = t;
}

inline fn iAbs(v: i32) i32 {
    return if (v < 0) -v else v;
}

inline fn lerpEdge(y0: i32, x0: i32, y1: i32, x1: i32, y: i32) i32 {
    if (y1 == y0) return x0;
    return x0 + @divTrunc((x1 - x0) * (y - y0), y1 - y0);
}

fn isqrtU(n: u32) u32 {
    if (n == 0) return 0;
    var guess: u32 = n;
    var prev: u32 = 0;
    while (true) {
        prev = guess;
        guess = (guess + n / guess) / 2;
        if (guess >= prev) return prev;
    }
}

/// Source-over blend. Src alpha in bits 24..31 (0xFF = opaque).
pub fn blendPx(dst: u32, src: u32) u32 {
    const alpha = (src >> 24) & 0xFF;
    if (alpha == 0xFF) return src & 0x00FFFFFF;
    if (alpha == 0) return dst;
    const inv = 255 - alpha;
    const r = (((src >> 16) & 0xFF) * alpha + ((dst >> 16) & 0xFF) * inv) / 255;
    const g = (((src >> 8) & 0xFF) * alpha + ((dst >> 8) & 0xFF) * inv) / 255;
    const b = ((src & 0xFF) * alpha + (dst & 0xFF) * inv) / 255;
    return (r << 16) | (g << 8) | b;
}

inline fn aaBandAlpha(v: i32, inner_zero: i32, inner_full: i32, outer_full: i32, outer_zero: i32) u32 {
    if (v <= inner_zero or v >= outer_zero) return 0;
    if (v >= inner_full and v <= outer_full) return 255;
    if (v < inner_full) {
        const range: i32 = inner_full - inner_zero;
        if (range <= 0) return 255;
        const into: i32 = v - inner_zero;
        const a: i32 = @divTrunc(into * 255, range);
        return @intCast(@max(@min(a, 255), 0));
    }
    const range: i32 = outer_zero - outer_full;
    if (range <= 0) return 255;
    const into: i32 = v - outer_full;
    const a: i32 = 255 - @divTrunc(into * 255, range);
    return @intCast(@max(@min(a, 255), 0));
}

/// Bounds-checked, naive (no SSE) fillRect for internal scanline use.
/// Callers with their own fast fillRect (e.g., kernel SSE2) should still
/// route through this for the new primitives — saves a function-pointer
/// indirection and the perf gap is irrelevant for shape interiors.
fn rasterFillRect(t: Target, x: i32, y: i32, w: u32, h: u32, color: u32) void {
    if (w == 0 or h == 0) return;
    const tw: i32 = @intCast(t.w);
    const th: i32 = @intCast(t.h);
    const x_end: i32 = x + @as(i32, @intCast(w));
    const y_end: i32 = y + @as(i32, @intCast(h));
    if (x_end <= 0 or y_end <= 0 or x >= tw or y >= th) return;
    const x0: u32 = if (x < 0) 0 else @intCast(x);
    const y0: u32 = if (y < 0) 0 else @intCast(y);
    const x1: u32 = if (x_end > tw) t.w else @intCast(x_end);
    const y1: u32 = if (y_end > th) t.h else @intCast(y_end);
    var row = y0;
    while (row < y1) : (row += 1) {
        var col = x0;
        const base = row * t.w;
        while (col < x1) : (col += 1) {
            t.fb[base + col] = color;
        }
    }
}

inline fn putPixelBlend(t: Target, x: i32, y: i32, color: u32, alpha: u32) void {
    if (alpha == 0) return;
    if (x < 0 or y < 0) return;
    const ux: u32 = @intCast(x);
    const uy: u32 = @intCast(y);
    if (ux >= t.w or uy >= t.h) return;
    const off = uy * t.w + ux;
    const base = color & 0x00FFFFFF;
    if (alpha >= 250) {
        t.fb[off] = base;
        return;
    }
    t.fb[off] = blendPx(t.fb[off], (alpha << 24) | base);
}

// --- Triangles ------------------------------------------------------------

pub fn fillTriangle(t: Target, x0: i32, y0: i32, x1: i32, y1: i32, x2: i32, y2: i32, color: u32) void {
    var px = [_]i32{ x0, x1, x2 };
    var py = [_]i32{ y0, y1, y2 };
    if (py[1] < py[0]) {
        iSwap(&py[0], &py[1]);
        iSwap(&px[0], &px[1]);
    }
    if (py[2] < py[0]) {
        iSwap(&py[0], &py[2]);
        iSwap(&px[0], &px[2]);
    }
    if (py[2] < py[1]) {
        iSwap(&py[1], &py[2]);
        iSwap(&px[1], &px[2]);
    }
    if (py[0] == py[2]) return;
    const y_top: i32 = @max(py[0], 0);
    const y_bot: i32 = @min(py[2], @as(i32, @intCast(t.h)) - 1);
    const sw_max: i32 = @as(i32, @intCast(t.w)) - 1;
    var y: i32 = y_top;
    while (y <= y_bot) : (y += 1) {
        const x_long = lerpEdge(py[0], px[0], py[2], px[2], y);
        const x_short = if (y < py[1])
            lerpEdge(py[0], px[0], py[1], px[1], y)
        else
            lerpEdge(py[1], px[1], py[2], px[2], y);
        const xl_raw = @min(x_long, x_short);
        const xr_raw = @max(x_long, x_short);
        const xl = @max(xl_raw, 0);
        const xr = @min(xr_raw, sw_max);
        if (xl > xr) continue;
        rasterFillRect(t, xl, y, @intCast(xr - xl + 1), 1, color);
    }
}

// --- Convex polygon fill --------------------------------------------------

pub fn fillPolygonConvex(t: Target, verts: []const Vec2, color: u32) void {
    if (verts.len < 3) return;
    var y_min: i32 = verts[0].y;
    var y_max: i32 = verts[0].y;
    for (verts[1..]) |v| {
        if (v.y < y_min) y_min = v.y;
        if (v.y > y_max) y_max = v.y;
    }
    const y_top: i32 = @max(y_min, 0);
    const y_bot: i32 = @min(y_max, @as(i32, @intCast(t.h)) - 1);
    const sw_max: i32 = @as(i32, @intCast(t.w)) - 1;
    var y: i32 = y_top;
    while (y <= y_bot) : (y += 1) {
        var x_left: i32 = 0;
        var x_right: i32 = 0;
        var have: bool = false;
        for (verts, 0..) |v0, i| {
            const v1 = verts[(i + 1) % verts.len];
            if (v0.y == v1.y) {
                if (v0.y == y) {
                    if (!have) {
                        x_left = @min(v0.x, v1.x);
                        x_right = @max(v0.x, v1.x);
                        have = true;
                    } else {
                        if (v0.x < x_left) x_left = v0.x;
                        if (v1.x < x_left) x_left = v1.x;
                        if (v0.x > x_right) x_right = v0.x;
                        if (v1.x > x_right) x_right = v1.x;
                    }
                }
                continue;
            }
            const ymin = @min(v0.y, v1.y);
            const ymax = @max(v0.y, v1.y);
            if (y < ymin or y >= ymax) continue;
            const x = lerpEdge(v0.y, v0.x, v1.y, v1.x, y);
            if (!have) {
                x_left = x;
                x_right = x;
                have = true;
            } else {
                if (x < x_left) x_left = x;
                if (x > x_right) x_right = x;
            }
        }
        if (!have) continue;
        const xl = @max(x_left, 0);
        const xr = @min(x_right, sw_max);
        if (xl > xr) continue;
        rasterFillRect(t, xl, y, @intCast(xr - xl + 1), 1, color);
    }
}

// --- Circles --------------------------------------------------------------

pub fn fillCircle(t: Target, cx: i32, cy: i32, radius: u32, color: u32) void {
    if (radius == 0) {
        putPixelBlend(t, cx, cy, color, 255);
        return;
    }
    const r: i32 = @intCast(radius);
    const r_sq: u32 = radius * radius;
    var y: i32 = -r;
    while (y <= r) : (y += 1) {
        const yu: u32 = @intCast(iAbs(y));
        const half: u32 = isqrtU(r_sq -| yu * yu);
        const xl: i32 = cx - @as(i32, @intCast(half));
        rasterFillRect(t, xl, cy + y, half * 2 + 1, 1, color);
    }
}

pub fn drawCircleAA(t: Target, cx: i32, cy: i32, radius: u32, width: u32, color: u32) void {
    if (radius == 0 or width == 0) return;
    const r_outer: i32 = @intCast(radius);
    const inner_r: i32 = if (@as(i32, @intCast(radius)) > @as(i32, @intCast(width)))
        @as(i32, @intCast(radius - width))
    else
        0;
    const margin: i32 = 2;
    const bx0: i32 = @max(cx - r_outer - margin, 0);
    const by0: i32 = @max(cy - r_outer - margin, 0);
    const bx1: i32 = @min(cx + r_outer + margin, @as(i32, @intCast(t.w)) - 1);
    const by1: i32 = @min(cy + r_outer + margin, @as(i32, @intCast(t.h)) - 1);

    const outer_full: i32 = r_outer * 256 - 128;
    const outer_zero: i32 = r_outer * 256 + 128;
    const inner_full: i32 = inner_r * 256 + 128;
    const inner_zero: i32 = inner_r * 256 - 128;

    var py: i32 = by0;
    while (py <= by1) : (py += 1) {
        const dy = py - cy;
        const dy_sq: u32 = @intCast(dy * dy);
        var px: i32 = bx0;
        while (px <= bx1) : (px += 1) {
            const dx = px - cx;
            const dx_sq: u32 = @intCast(dx * dx);
            const d_sq: u32 = dx_sq + dy_sq;
            const r_outer_u: u32 = @intCast(r_outer + 1);
            if (d_sq > r_outer_u * r_outer_u) continue;
            const d_fp: i32 = @intCast(isqrtU(d_sq * 65536));
            const alpha: u32 = aaBandAlpha(d_fp, inner_zero, inner_full, outer_full, outer_zero);
            putPixelBlend(t, px, py, color, alpha);
        }
    }
}

// --- Ellipses -------------------------------------------------------------

pub fn fillEllipse(t: Target, cx: i32, cy: i32, rx: u32, ry: u32, color: u32) void {
    if (rx == 0 or ry == 0) return;
    const ryi: i32 = @intCast(ry);
    const ry_sq: u64 = @as(u64, ry) * ry;
    const rx_sq: u64 = @as(u64, rx) * rx;
    var y: i32 = -ryi;
    while (y <= ryi) : (y += 1) {
        const yu: u64 = @intCast(iAbs(y));
        const num: u64 = rx_sq * (ry_sq -| yu * yu);
        const half: u32 = isqrtU(@intCast(num / ry_sq));
        const xl: i32 = cx - @as(i32, @intCast(half));
        rasterFillRect(t, xl, cy + y, half * 2 + 1, 1, color);
    }
}

pub fn drawEllipseAA(t: Target, cx: i32, cy: i32, rx: u32, ry: u32, width: u32, color: u32) void {
    if (rx == 0 or ry == 0 or width == 0) return;
    const rxi: i32 = @intCast(rx);
    const ryi: i32 = @intCast(ry);
    const inner_rx: i32 = if (rxi > @as(i32, @intCast(width))) rxi - @as(i32, @intCast(width)) else 0;
    const inner_ry: i32 = if (ryi > @as(i32, @intCast(width))) ryi - @as(i32, @intCast(width)) else 0;
    const margin: i32 = 2;
    const bx0: i32 = @max(cx - rxi - margin, 0);
    const by0: i32 = @max(cy - ryi - margin, 0);
    const bx1: i32 = @min(cx + rxi + margin, @as(i32, @intCast(t.w)) - 1);
    const by1: i32 = @min(cy + ryi + margin, @as(i32, @intCast(t.h)) - 1);

    var py: i32 = by0;
    while (py <= by1) : (py += 1) {
        const dy = py - cy;
        var px: i32 = bx0;
        while (px <= bx1) : (px += 1) {
            const dx = px - cx;
            const num_o: u64 = @as(u64, @intCast(dx * dx)) * @as(u64, @intCast(ryi * ryi)) +
                @as(u64, @intCast(dy * dy)) * @as(u64, @intCast(rxi * rxi));
            const den_o: u64 = @as(u64, @intCast(rxi * ryi)) * @as(u64, @intCast(rxi * ryi));
            const norm_o_sq_fp: u64 = (num_o * 65536) / den_o;
            const d_outer_fp: i32 = @intCast(isqrtU(@intCast(norm_o_sq_fp)));
            if (inner_rx > 0 and inner_ry > 0) {
                const num_i: u64 = @as(u64, @intCast(dx * dx)) * @as(u64, @intCast(inner_ry * inner_ry)) +
                    @as(u64, @intCast(dy * dy)) * @as(u64, @intCast(inner_rx * inner_rx));
                const den_i: u64 = @as(u64, @intCast(inner_rx * inner_ry)) * @as(u64, @intCast(inner_rx * inner_ry));
                const norm_i_sq_fp: u64 = (num_i * 65536) / den_i;
                const d_inner_fp: i32 = @intCast(isqrtU(@intCast(norm_i_sq_fp)));
                if (d_inner_fp <= 256 - 128 and d_outer_fp <= 256 - 128) continue;
                if (d_outer_fp >= 256 - 128 and d_outer_fp <= 256 + 128) {
                    const into: i32 = d_outer_fp - (256 - 128);
                    const a: i32 = @max(@min(255 - @divTrunc(into * 255, 256), 255), 0);
                    putPixelBlend(t, px, py, color, @intCast(a));
                } else if (d_inner_fp >= 256 - 128 and d_inner_fp <= 256 + 128) {
                    const into: i32 = d_inner_fp - (256 - 128);
                    const a: i32 = @max(@min(@divTrunc(into * 255, 256), 255), 0);
                    putPixelBlend(t, px, py, color, @intCast(a));
                } else if (d_outer_fp < 256 - 128 and d_inner_fp > 256 + 128) {
                    putPixelBlend(t, px, py, color, 255);
                }
            } else {
                if (d_outer_fp >= 256 - 128 and d_outer_fp <= 256 + 128) {
                    const into: i32 = d_outer_fp - (256 - 128);
                    const a: i32 = @max(@min(255 - @divTrunc(into * 255, 256), 255), 0);
                    putPixelBlend(t, px, py, color, @intCast(a));
                } else if (d_outer_fp < 256 - 128) {
                    putPixelBlend(t, px, py, color, 255);
                }
            }
        }
    }
}

// --- Lines ----------------------------------------------------------------

pub fn drawLineAA(t: Target, x0_in: i32, y0_in: i32, x1_in: i32, y1_in: i32, color: u32) void {
    var x0: i32 = x0_in;
    var y0: i32 = y0_in;
    var x1: i32 = x1_in;
    var y1: i32 = y1_in;
    const adx = iAbs(x1 - x0);
    const ady = iAbs(y1 - y0);
    const steep: bool = ady > adx;
    if (steep) {
        iSwap(&x0, &y0);
        iSwap(&x1, &y1);
    }
    if (x0 > x1) {
        iSwap(&x0, &x1);
        iSwap(&y0, &y1);
    }
    const dx = x1 - x0;
    const dy = y1 - y0;
    if (dx == 0) {
        if (steep) putPixelBlend(t, y0, x0, color, 255) else putPixelBlend(t, x0, y0, color, 255);
        return;
    }
    const grad: i32 = @intCast(@divTrunc(@as(i64, dy) * 65536, @as(i64, dx)));
    var intery: i64 = @as(i64, y0) * 65536;
    var x: i32 = x0;
    while (x <= x1) : (x += 1) {
        const ypx: i32 = @intCast(intery >> 16);
        const frac: i64 = intery & 0xFFFF;
        const a_low: u32 = @intCast(((65536 - frac) * 255) >> 16);
        const a_high: u32 = @intCast((frac * 255) >> 16);
        if (steep) {
            putPixelBlend(t, ypx, x, color, a_low);
            putPixelBlend(t, ypx + 1, x, color, a_high);
        } else {
            putPixelBlend(t, x, ypx, color, a_low);
            putPixelBlend(t, x, ypx + 1, color, a_high);
        }
        intery += grad;
    }
}

pub fn drawThickLineAA(t: Target, x0: i32, y0: i32, x1: i32, y1: i32, width: u32, color: u32) void {
    if (width == 0) return;
    const dx = x1 - x0;
    const dy = y1 - y0;
    const len_sq: i64 = @as(i64, dx) * dx + @as(i64, dy) * dy;
    if (len_sq == 0) {
        fillCircle(t, x0, y0, width / 2, color);
        return;
    }
    const len_fp: i64 = @intCast(isqrtU(@intCast(len_sq * 65536)));
    const half_w_fp: i32 = @intCast((width * 256) / 2);
    const margin: i32 = @intCast(width / 2 + 2);
    const bx0: i32 = @max(@min(x0, x1) - margin, 0);
    const by0: i32 = @max(@min(y0, y1) - margin, 0);
    const bx1: i32 = @min(@max(x0, x1) + margin, @as(i32, @intCast(t.w)) - 1);
    const by1: i32 = @min(@max(y0, y1) + margin, @as(i32, @intCast(t.h)) - 1);

    var py: i32 = by0;
    while (py <= by1) : (py += 1) {
        var px: i32 = bx0;
        while (px <= bx1) : (px += 1) {
            const px0 = px - x0;
            const py0 = py - y0;
            const dot: i64 = @as(i64, px0) * dx + @as(i64, py0) * dy;
            var d_fp: i32 = 0;
            if (dot <= 0) {
                const d_sq: u32 = @intCast(@as(i64, px0) * px0 + @as(i64, py0) * py0);
                d_fp = @intCast(isqrtU(d_sq * 65536));
            } else if (dot >= len_sq) {
                const px1 = px - x1;
                const py1 = py - y1;
                const d_sq: u32 = @intCast(@as(i64, px1) * px1 + @as(i64, py1) * py1);
                d_fp = @intCast(isqrtU(d_sq * 65536));
            } else {
                const cross: i64 = @as(i64, dx) * py0 - @as(i64, dy) * px0;
                const cross_abs: i64 = if (cross < 0) -cross else cross;
                d_fp = @intCast(@divTrunc(cross_abs * 65536, len_fp));
            }
            const inner: i32 = half_w_fp - 128;
            const outer: i32 = half_w_fp + 128;
            if (d_fp <= inner) {
                putPixelBlend(t, px, py, color, 255);
            } else if (d_fp >= outer) {
                continue;
            } else {
                const a: i32 = 255 - @divTrunc((d_fp - inner) * 255, 256);
                const alpha_clamped: u32 = @intCast(@max(@min(a, 255), 0));
                putPixelBlend(t, px, py, color, alpha_clamped);
            }
        }
    }
}

// --- Polylines ------------------------------------------------------------

pub fn strokePolyline(t: Target, verts: []const Vec2, width: u32, color: u32, closed: bool) void {
    if (verts.len < 2 or width == 0) return;
    var i: usize = 0;
    const seg_end: usize = if (closed) verts.len else verts.len - 1;
    while (i < seg_end) : (i += 1) {
        const a = verts[i];
        const b = verts[(i + 1) % verts.len];
        drawThickLineAA(t, a.x, a.y, b.x, b.y, width, color);
    }
    const r: u32 = (width + 1) / 2;
    if (r == 0) return;
    var j: usize = if (closed) 0 else 1;
    const j_end: usize = if (closed) verts.len else verts.len - 1;
    while (j < j_end) : (j += 1) {
        fillCircle(t, verts[j].x, verts[j].y, r, color);
    }
}
