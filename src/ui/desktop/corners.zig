// Rounded window corners. The pixels behind each corner square are saved
// before the window is drawn over them and blended back through a coverage
// mask afterwards, a ring of the border colour tracing the arc.

const gfx = @import("../gfx.zig");

// --- Rounded corner masking ---
// Per-pixel alpha-coverage mask for a CORNER_R-radius rounded corner. (0,0)
// is the outer corner (alpha=255 → fully bg). Pivot of the quarter-circle is
// at (R, R) — the deepest inner point. Supersampled 4×4 at comptime so
// edges fade smoothly instead of stair-stepping like the old corner_insets
// table did.
pub const CORNER_R: u32 = 10;
const corner_mask: [CORNER_R][CORNER_R]u8 = blk: {
    @setEvalBranchQuota(50_000);
    var mask: [CORNER_R][CORNER_R]u8 = undefined;
    const R: f32 = @floatFromInt(CORNER_R);
    const SAMPLES: u32 = 4;
    const SAMPLES_F: f32 = @floatFromInt(SAMPLES);
    const TOTAL: u32 = SAMPLES * SAMPLES;
    for (0..CORNER_R) |y_| {
        for (0..CORNER_R) |x_| {
            var outside: u32 = 0;
            const fx: f32 = @floatFromInt(x_);
            const fy: f32 = @floatFromInt(y_);
            for (0..SAMPLES) |sy| {
                for (0..SAMPLES) |sx| {
                    const sub_x = fx + (@as(f32, @floatFromInt(sx)) + 0.5) / SAMPLES_F;
                    const sub_y = fy + (@as(f32, @floatFromInt(sy)) + 0.5) / SAMPLES_F;
                    const dx = R - sub_x;
                    const dy = R - sub_y;
                    if (dx * dx + dy * dy > R * R) outside += 1;
                }
            }
            mask[y_][x_] = @intCast((outside * 255) / TOTAL);
        }
    }
    break :blk mask;
};

// White border-ring coverage hugging the rounded corner's OUTER arc — distance
// (R−CORNER_RING_T, R] from the pivot. Lets the white chrome border continue
// smoothly around the curve instead of the corner dropping straight to bg.
// Same 4×4 supersample as corner_mask; together they partition each corner
// pixel into {outside→bg, ring→border, inside→window}.
const CORNER_RING_T: f32 = 1.6;
const corner_ring: [CORNER_R][CORNER_R]u8 = blk: {
    @setEvalBranchQuota(50_000);
    var mask: [CORNER_R][CORNER_R]u8 = undefined;
    const R: f32 = @floatFromInt(CORNER_R);
    const inner: f32 = R - CORNER_RING_T;
    const SAMPLES: u32 = 4;
    const SAMPLES_F: f32 = @floatFromInt(SAMPLES);
    const TOTAL: u32 = SAMPLES * SAMPLES;
    for (0..CORNER_R) |y_| {
        for (0..CORNER_R) |x_| {
            var inring: u32 = 0;
            const fx: f32 = @floatFromInt(x_);
            const fy: f32 = @floatFromInt(y_);
            for (0..SAMPLES) |sy| {
                for (0..SAMPLES) |sx| {
                    const sub_x = fx + (@as(f32, @floatFromInt(sx)) + 0.5) / SAMPLES_F;
                    const sub_y = fy + (@as(f32, @floatFromInt(sy)) + 0.5) / SAMPLES_F;
                    const dx = R - sub_x;
                    const dy = R - sub_y;
                    const d2 = dx * dx + dy * dy;
                    if (d2 <= R * R and d2 > inner * inner) inring += 1;
                }
            }
            mask[y_][x_] = @intCast((inring * 255) / TOTAL);
        }
    }
    break :blk mask;
};

// Save the full CORNER_R × CORNER_R square at each of the 4 corners
// before drawing the window; restore via the alpha mask afterwards so
// edges blend smoothly with whatever is behind.
const CORNER_BUF_PER: u32 = CORNER_R * CORNER_R;
var corner_save: [4 * CORNER_BUF_PER]u32 = undefined;

/// First corner save/restore works on: all four, or the bottom pair only.
pub const ALL_CORNERS: usize = 0;
pub const BOTTOM_CORNERS: usize = 2;

pub fn saveCornerPixels(x: i32, y: i32, w: u32, h: u32, first: usize) void {
    const right: i32 = x + @as(i32, @intCast(w)) - 1;
    const bot: i32 = y + @as(i32, @intCast(h)) - 1;
    const corners = [_][2]i32{ .{ x, y }, .{ right, y }, .{ x, bot }, .{ right, bot } };
    const x_dirs = [_]i32{ 1, -1, 1, -1 };
    const y_dirs = [_]i32{ 1, 1, -1, -1 };
    for (first..4) |c| {
        const base = c * CORNER_BUF_PER;
        for (0..CORNER_R) |cy| {
            for (0..CORNER_R) |cx| {
                if (corner_mask[cy][cx] == 0) continue;
                const px = corners[c][0] + @as(i32, @intCast(cx)) * x_dirs[c];
                const py = corners[c][1] + @as(i32, @intCast(cy)) * y_dirs[c];
                const idx = base + cy * CORNER_R + cx;
                if (px >= 0 and py >= 0 and @as(u32, @intCast(px)) < gfx.target_w and @as(u32, @intCast(py)) < gfx.target_h) {
                    corner_save[idx] = gfx.target[@as(u32, @intCast(py)) * gfx.target_w + @as(u32, @intCast(px))];
                }
            }
        }
    }
}

pub fn restoreCornerPixels(x: i32, y: i32, w: u32, h: u32, border_color: u32, first: usize) void {
    const right: i32 = x + @as(i32, @intCast(w)) - 1;
    const bot: i32 = y + @as(i32, @intCast(h)) - 1;
    const corners = [_][2]i32{ .{ x, y }, .{ right, y }, .{ x, bot }, .{ right, bot } };
    const x_dirs = [_]i32{ 1, -1, 1, -1 };
    const y_dirs = [_]i32{ 1, 1, -1, -1 };
    const br_r = (border_color >> 16) & 0xFF;
    const br_g = (border_color >> 8) & 0xFF;
    const br_b = border_color & 0xFF;
    for (first..4) |c| {
        const base = c * CORNER_BUF_PER;
        for (0..CORNER_R) |cy| {
            for (0..CORNER_R) |cx| {
                const out_a: u32 = corner_mask[cy][cx]; // outside the arc → background
                const ring_a: u32 = corner_ring[cy][cx]; // on the arc → white border
                if (out_a == 0 and ring_a == 0) continue; // fully interior — keep window pixel
                const px = corners[c][0] + @as(i32, @intCast(cx)) * x_dirs[c];
                const py = corners[c][1] + @as(i32, @intCast(cy)) * y_dirs[c];
                if (px < 0 or py < 0) continue;
                if (@as(u32, @intCast(px)) >= gfx.target_w or @as(u32, @intCast(py)) >= gfx.target_h) continue;
                const off = @as(u32, @intCast(py)) * gfx.target_w + @as(u32, @intCast(px));
                const bg_pixel = corner_save[base + cy * CORNER_R + cx];
                if (out_a >= 254) {
                    gfx.target[off] = bg_pixel; // fully outside the rounded rect
                    continue;
                }
                // 3-way composite: window interior · white border ring · bg outside.
                // The three coverages partition the pixel (sum == 255), so the
                // white chrome border traces the corner arc instead of vanishing.
                const win = gfx.target[off];
                const int_a: u32 = 255 - out_a - ring_a;
                const r = (((win >> 16) & 0xFF) * int_a + br_r * ring_a + ((bg_pixel >> 16) & 0xFF) * out_a) / 255;
                const g = (((win >> 8) & 0xFF) * int_a + br_g * ring_a + ((bg_pixel >> 8) & 0xFF) * out_a) / 255;
                const b = ((win & 0xFF) * int_a + br_b * ring_a + (bg_pixel & 0xFF) * out_a) / 255;
                gfx.target[off] = (r << 16) | (g << 8) | b;
            }
        }
    }
}

/// restoreCornerPixels for rows repainted inside a window already on screen:
/// what was saved is the finished corner, not the background behind it, so
/// wherever the background shows through, the pixel goes back as it was.
pub fn keepCornerPixels(x: i32, y: i32, w: u32, h: u32, border_color: u32, first: usize) void {
    restoreCornerPixels(x, y, w, h, border_color, first);
    const right: i32 = x + @as(i32, @intCast(w)) - 1;
    const bot: i32 = y + @as(i32, @intCast(h)) - 1;
    const corners = [_][2]i32{ .{ x, y }, .{ right, y }, .{ x, bot }, .{ right, bot } };
    const x_dirs = [_]i32{ 1, -1, 1, -1 };
    const y_dirs = [_]i32{ 1, 1, -1, -1 };
    for (first..4) |c| {
        const base = c * CORNER_BUF_PER;
        for (0..CORNER_R) |cy| {
            for (0..CORNER_R) |cx| {
                if (corner_mask[cy][cx] == 0) continue;
                const px = corners[c][0] + @as(i32, @intCast(cx)) * x_dirs[c];
                const py = corners[c][1] + @as(i32, @intCast(cy)) * y_dirs[c];
                if (px < 0 or py < 0) continue;
                if (@as(u32, @intCast(px)) >= gfx.target_w or @as(u32, @intCast(py)) >= gfx.target_h) continue;
                gfx.target[@as(u32, @intCast(py)) * gfx.target_w + @as(u32, @intCast(px))] = corner_save[base + cy * CORNER_R + cx];
            }
        }
    }
}
