// What a frame has to repaint: its kind (DirtyKind), the rects seeded for a
// region repaint, the focused terminal's text row riding along with it, and
// what a dragged window has vacated. The rects that reach the display are
// dirty.zig's.

const wm = @import("window.zig");
const windows = &wm.windows;
const slot_used = &wm.slot_used;
const MAX_WINDOWS: u32 = @import("../../config.zig").MAX_WINDOWS;

const chrome = @import("chrome.zig");
const paddedWinRect = chrome.paddedWinRect;
const SHADOW_SPAD = chrome.SHADOW_SPAD;

/// What this frame repaints. .region repaints the queued seeds (see
/// renderRegions); .drag is the same path driven by a window drag.
pub const DirtyKind = enum { none, cursor_only, text_only, drag, full, gui_only, region };

/// Make this frame a region repaint of what has been seeded.
pub fn wantRegion(dirty: *DirtyKind) void {
    switch (dirty.*) {
        .full, .drag, .region => {},
        .text_only => {
            text_row_pending = true;
            dirty.* = .region;
        },
        .none, .cursor_only, .gui_only => dirty.* = .region,
    }
}

/// The focused terminal's text row changed (keystroke echo, cursor blink).
pub fn wantTextRow(dirty: *DirtyKind) void {
    switch (dirty.*) {
        .none, .cursor_only => dirty.* = .text_only,
        .text_only, .full => {},
        .region, .drag => text_row_pending = true,
        .gui_only => {
            text_row_pending = true;
            dirty.* = .region;
        },
    }
}

/// Expandable bbox for a region closure. growOver unions a rect in only
/// when it intersects and isn't already contained, and records growth so
/// the fixpoint loop knows when to stop.
pub const Bbox = struct {
    x0: i32,
    y0: i32,
    x1: i32,
    y1: i32,
    grew: bool = false,

    pub fn intersects(self: Bbox, o: Bbox) bool {
        return self.x0 < o.x1 and o.x0 < self.x1 and self.y0 < o.y1 and o.y0 < self.y1;
    }

    pub fn growOver(self: *Bbox, bx0: i32, by0: i32, bx1: i32, by1: i32) void {
        if (!self.intersects(.{ .x0 = bx0, .y0 = by0, .x1 = bx1, .y1 = by1 })) return;
        const contained = bx0 >= self.x0 and by0 >= self.y0 and bx1 <= self.x1 and by1 <= self.y1;
        if (contained) return;
        self.x0 = @min(self.x0, bx0);
        self.y0 = @min(self.y0, by0);
        self.x1 = @max(self.x1, bx1);
        self.y1 = @max(self.y1, by1);
        self.grew = true;
    }
};

const MAX_REGION_SEEDS = 16;
pub var region_seeds: [MAX_REGION_SEEDS]Bbox = undefined;
pub var region_seed_count: u8 = 0;
/// The focused terminal's text row changed during a .region/.drag frame.
/// Painted on its own, like .text_only, unless its window is repainted
/// in a region anyway.
pub var text_row_pending: bool = false;

/// Queue [x0, y0, x1, y1) for this frame's region repaint. Past the cap,
/// seeds merge into the last one.
pub fn seedRegion(x0: i32, y0: i32, x1: i32, y1: i32) void {
    if (x1 <= x0 or y1 <= y0) return;
    if (region_seed_count == MAX_REGION_SEEDS) {
        const b = &region_seeds[MAX_REGION_SEEDS - 1];
        b.x0 = @min(b.x0, x0);
        b.y0 = @min(b.y0, y0);
        b.x1 = @max(b.x1, x1);
        b.y1 = @max(b.y1, y1);
        return;
    }
    region_seeds[region_seed_count] = .{ .x0 = x0, .y0 = y0, .x1 = x1, .y1 = y1 };
    region_seed_count += 1;
}

pub fn seedRect(r: [4]i32) void {
    seedRegion(r[0], r[1], r[2], r[3]);
}

pub fn seedWindow(i: u8) void {
    if (i >= MAX_WINDOWS or !slot_used[i]) return;
    if (!windows[i].visible or windows[i].minimized) return;
    seedRect(paddedWinRect(i));
}

// Vacated-region accumulator for the tight drag repaint (renderRegions).
// Each move event unions the dragged window's OLD padded rect in here.
// Today handleMouseEvents runs once per frame so this sees one rect per
// frame; the union is defensive so every vacated strip is restored even if
// that ever changes. Screen-unclamped signed coords; consumed and
// invalidated once per rendered frame.
pub var drag_accum_valid: bool = false;
pub var drag_accum_x0: i32 = 0;
pub var drag_accum_y0: i32 = 0;
pub var drag_accum_x1: i32 = 0;
pub var drag_accum_y1: i32 = 0;

/// Union the shadow-padded rect of a (about to be vacated) window position
/// into the drag accumulator.
pub fn accumVacated(x: i32, y: i32, w_px: u32, h_px: u32) void {
    const x0 = x - SHADOW_SPAD;
    const y0 = y - SHADOW_SPAD;
    const x1 = x + @as(i32, @intCast(w_px)) + SHADOW_SPAD;
    const y1 = y + @as(i32, @intCast(h_px)) + SHADOW_SPAD;
    if (!drag_accum_valid) {
        drag_accum_x0 = x0;
        drag_accum_y0 = y0;
        drag_accum_x1 = x1;
        drag_accum_y1 = y1;
        drag_accum_valid = true;
    } else {
        drag_accum_x0 = @min(drag_accum_x0, x0);
        drag_accum_y0 = @min(drag_accum_y0, y0);
        drag_accum_x1 = @max(drag_accum_x1, x1);
        drag_accum_y1 = @max(drag_accum_y1, y1);
    }
}
