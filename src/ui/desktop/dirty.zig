// Dirty-region tracker — tile-grid damage tracking. Each frame the
// compositor records changed regions; the dispatcher at end-of-frame
// flushes only those regions to the host instead of the whole screen.
//
// Algorithm: divide the screen into a fixed 64×64 tile grid (30 × 17
// at 1080p; smaller resolutions ignore the unused tiles). `add(rect)`
// sets the dirty bit for every tile the rect overlaps — O(tiles), no
// rect-list math, no overlap tests, no merge cascades. At iterate
// time, the bitmap is converted to coalesced rectangles: per row,
// horizontal runs of consecutive dirty tiles become row-strips;
// adjacent rows with identical run patterns merge vertically into
// taller rects. Result: bounded rect count regardless of how many
// add() calls happened, with non-overlapping output.
//
// Why tiles vs the prior subtract-on-add region: the subtract approach
// minimized blitted pixels but produced O(K) rects per add in the
// worst case, scaling per-frame virtio_gpu queue traffic with window
// count. Per-frame queue saturation was the regression that triggered
// this rewrite (slower app launches as more windows accumulated). The
// tile grid puts an upper bound on flushRect calls per frame and
// implicitly dedups overlap (OR-ing tile bits — same tile is flushed
// once regardless of how many windows touched it).
//
// `markFull()` escape hatch — once set, addRect is a no-op until
// `reset()` clears it.

const std = @import("std");
const gfx = @import("../gfx.zig");

// Tile geometry. Sized statically for 1920×1080 (rounded up to a
// multiple of 64 → 1920×1088) so the grid covers max resolution with
// one fixed allocation. At lower resolutions some tiles are simply
// never set; iteration stops at gfx.screen_h.
pub const TILE_W: u32 = 64;
pub const TILE_H: u32 = 64;
const SCREEN_MAX_W: u32 = 1920;
const SCREEN_MAX_H: u32 = 1088; // 17 × 64 — covers 1080p with one row of overhang
const TILES_X: u32 = SCREEN_MAX_W / TILE_W; // 30
const TILES_Y: u32 = SCREEN_MAX_H / TILE_H; // 17
const TOTAL_TILES: u32 = TILES_X * TILES_Y; // 510
const TILE_WORDS: u32 = (TOTAL_TILES + 63) / 64; // 8
// Max non-adjacent dirty runs per row: alternating set/clear → ceil(TILES_X/2).
// +1 slack for safety.
const ACTIVE_CAP: u32 = TILES_X / 2 + 2;

var tiles: [TILE_WORDS]u64 = [_]u64{0} ** TILE_WORDS;

pub const MAX_RECTS: u8 = 16;
var rects: [MAX_RECTS][4]u32 = undefined;
var rect_count: u8 = 0;
var rects_built: bool = false;
var full: bool = true; // first frame is always full

/// Request a full-screen repaint on the next frame, regardless of what's
/// in the tile grid. Set by paths that change state outside the tracker
/// (toast tick, animation completion, resolution change). Drained by the
/// desktop main loop's dirty-kind decision.
pub var force_full_kind: bool = false;

inline fn tileIsSet(tx: u32, ty: u32) bool {
    const idx = ty * TILES_X + tx;
    return (tiles[idx >> 6] & (@as(u64, 1) << @as(u6, @intCast(idx & 63)))) != 0;
}

inline fn tileSet(tx: u32, ty: u32) void {
    const idx = ty * TILES_X + tx;
    tiles[idx >> 6] |= (@as(u64, 1) << @as(u6, @intCast(idx & 63)));
}

pub fn add(x: u32, y: u32, w: u32, h: u32) void {
    if (full) return;
    if (w == 0 or h == 0) return;
    if (x >= gfx.screen_w or y >= gfx.screen_h) return;
    rects_built = false;

    // Clamp rect to screen, then compute tile range.
    const eff_w = @min(w, gfx.screen_w - x);
    const eff_h = @min(h, gfx.screen_h - y);
    const tx0 = x / TILE_W;
    const ty0 = y / TILE_H;
    const tx1 = @min((x + eff_w - 1) / TILE_W, TILES_X - 1);
    const ty1 = @min((y + eff_h - 1) / TILE_H, TILES_Y - 1);

    var ty = ty0;
    while (ty <= ty1) : (ty += 1) {
        var tx = tx0;
        while (tx <= tx1) : (tx += 1) {
            tileSet(tx, ty);
        }
    }
}

pub fn markFull() void {
    full = true;
}

pub fn reset() void {
    @memset(&tiles, 0);
    rect_count = 0;
    rects_built = false;
    full = false;
}

pub fn isFull() bool {
    return full;
}

pub fn rectCount() u8 {
    if (!rects_built) buildRects();
    return rect_count;
}

/// Read the i'th coalesced rect. Caller must ensure i < rectCount().
/// Rects are guaranteed non-overlapping and screen-clipped.
pub fn getRect(i: u8) [4]u32 {
    if (!rects_built) buildRects();
    return rects[i];
}

// Convert the tile bitmap into a list of coalesced non-overlapping
// rects. Two-pass per row: first extract this row's horizontal runs,
// then match them against the previous row's open rects — identical
// (start, len) runs extend the existing rect's height; new patterns
// emit fresh rects. If the soft cap (MAX_RECTS) is exceeded, we fall
// back to full-screen repaint — simpler than tracking dozens of
// fragments, and almost-cap means there's a lot of dirty area anyway.
fn buildRects() void {
    rect_count = 0;
    rects_built = true;

    var active: [ACTIVE_CAP][3]u32 = undefined;
    var active_count: u32 = 0;

    var ty: u32 = 0;
    while (ty < TILES_Y) : (ty += 1) {
        const py = ty * TILE_H;
        if (py >= gfx.screen_h) break;
        const row_h = @min(TILE_H, gfx.screen_h - py);

        // Step 1: extract horizontal runs in this row.
        var current: [ACTIVE_CAP][2]u32 = undefined;
        var current_count: u32 = 0;
        var tx: u32 = 0;
        while (tx < TILES_X) {
            while (tx < TILES_X and !tileIsSet(tx, ty)) : (tx += 1) {}
            if (tx >= TILES_X) break;
            const start = tx;
            while (tx < TILES_X and tileIsSet(tx, ty)) : (tx += 1) {}
            current[current_count] = .{ start, tx - start };
            current_count += 1;
        }

        // Step 2: match against the previous row's open rects.
        // Matching (start, len) → vertical extension; otherwise emit new rect.
        var new_active: [ACTIVE_CAP][3]u32 = undefined;
        var new_active_count: u32 = 0;
        for (current[0..current_count]) |run| {
            var matched_idx: ?u32 = null;
            for (active[0..active_count]) |a| {
                if (a[0] == run[0] and a[1] == run[1]) {
                    matched_idx = a[2];
                    break;
                }
            }
            if (matched_idx) |ri| {
                rects[ri][3] += row_h;
                new_active[new_active_count] = .{ run[0], run[1], ri };
                new_active_count += 1;
            } else {
                if (rect_count >= MAX_RECTS) {
                    // Cap exceeded — give up on partial flush, force full repaint.
                    markFull();
                    rect_count = 0;
                    return;
                }
                const px = run[0] * TILE_W;
                const right_edge = @min((run[0] + run[1]) * TILE_W, gfx.screen_w);
                const pw = right_edge - px;
                rects[rect_count] = .{ px, py, pw, row_h };
                new_active[new_active_count] = .{ run[0], run[1], rect_count };
                new_active_count += 1;
                rect_count += 1;
            }
        }

        // Carry forward to next row.
        @memcpy(active[0..new_active_count], new_active[0..new_active_count]);
        active_count = new_active_count;
    }
}
