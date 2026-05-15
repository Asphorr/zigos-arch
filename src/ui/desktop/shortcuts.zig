// Desktop shortcut icons — the column of icons painted on the desktop
// background (top-left, below the menubar). Click selects, double-click
// launches the pinned app from `pinned.list`. Drag (press + move past
// DRAG_THRESHOLD pixels) picks the icon up; release drops it at the
// cursor position. Per-icon position overrides live in `positions[]`
// and replace the default grid layout when set.
//
// Visual state (selection, drag) lives here; launch is delegated back
// to the caller so this module stays free of coupling to createWindow /
// shell spawn / smp.requestAppLoad logic.

const gfx = @import("../gfx.zig");
const aa_font = @import("../aa_font.zig");
const layout = @import("layout.zig");
const dirty_rects = @import("dirty.zig");
const pinned = @import("pinned.zig");

const MENUBAR_H = layout.MENUBAR_H;
pub const ICON_CELL_W: u32 = 80;
pub const ICON_CELL_H: u32 = 72;
pub const ICON_START_X: u32 = 24;
pub const ICON_START_Y: u32 = MENUBAR_H + 8;
pub const ICON_PIXEL_W: u32 = 32;
pub const ICON_PIXEL_H: u32 = 32;

const DOUBLE_CLICK_TICKS: u32 = 80;

/// Move past this many pixels with the button held and we promote the
/// pending click into a drag. Smaller = more sensitive but accidentally
/// drags icons when the user's hand twitches during a single click. 6
/// matches macOS / GNOME defaults closely.
const DRAG_THRESHOLD: i32 = 6;

/// Drag-ghost opacity (0..255). ~63% lets the desktop underneath show
/// through enough to telegraph "this is just a preview", while keeping
/// the icon recognizable.
const GHOST_ALPHA: u8 = 160;

const Pos = struct { x: i32, y: i32 };
var positions: [pinned.list.len]?Pos = .{null} ** pinned.list.len;

var selected: i8 = -1;
var last_click_tick: u32 = 0;

// --- Press / drag state ---------------------------------------------------
//
// A press goes through three states:
//   1. press_idx == -1                 — nothing pressed
//   2. press_idx >= 0, drag_idx == -1  — button down on an icon, but
//                                         cursor hasn't moved past
//                                         DRAG_THRESHOLD yet (might
//                                         still be a click)
//   3. drag_idx >= 0                   — promoted to a drag; ghost
//                                         follows cursor until release

var press_idx: i8 = -1;
var press_x: i32 = 0;
var press_y: i32 = 0;

var drag_idx: i8 = -1;
var drag_curr_x: i32 = 0;
var drag_curr_y: i32 = 0;
var drag_anchor_x: i32 = 0; // offset from icon top-left to cursor at press
var drag_anchor_y: i32 = 0;

/// Where this icon paints — caller-overridden position if set, else the
/// default column-major grid. The grid wraps into a second/third column
/// once a column runs out of vertical space, so 13+ pinned icons stay
/// fully visible at 1280×800 without overlapping the dock. Both the
/// hit-test and the renderer go through this so they agree on layout.
fn iconCell(si: usize) struct { x: i32, y: i32 } {
    if (positions[si]) |p| return .{ .x = p.x, .y = p.y };
    // Leave ~60 px of breathing room above the dock so the bottom icon's
    // label isn't crushed against the pill.
    const usable_h: u32 = @as(u32, @intCast(gfx.screen_h)) -| (ICON_START_Y + 60);
    const rows_per_col: u32 = @max(1, usable_h / ICON_CELL_H);
    const col: u32 = @as(u32, @intCast(si)) / rows_per_col;
    const row: u32 = @as(u32, @intCast(si)) % rows_per_col;
    return .{
        .x = @as(i32, @intCast(ICON_START_X + col * ICON_CELL_W)),
        .y = @as(i32, @intCast(ICON_START_Y + row * ICON_CELL_H)),
    };
}

pub fn isDragging() bool {
    return drag_idx >= 0;
}

pub fn render() void {
    const label_atlas = aa_font.getDefault16();
    for (pinned.list, 0..) |sc, si| {
        const cell = iconCell(si);
        // Mark the cell dirty so background restore + redraw covers it.
        const cx0: u32 = if (cell.x < 4) 0 else @intCast(cell.x - 4);
        const cy0: u32 = if (cell.y < 2) 0 else @intCast(cell.y - 2);
        dirty_rects.add(cx0, cy0, ICON_CELL_W + 8, ICON_CELL_H);

        // Skip painting the dragged icon at its base position — the
        // ghost rendered by renderDragGhost is the only visible copy
        // until the drop commits a new position.
        if (drag_idx >= 0 and @as(usize, @intCast(drag_idx)) == si) continue;

        const is_sel = (selected >= 0 and @as(usize, @intCast(selected)) == si);
        if (is_sel) {
            gfx.fillRect(cell.x - 4, cell.y - 2, ICON_CELL_W, ICON_CELL_H, 0x3A4A6A);
        }

        const icon_x: i32 = cell.x + @as(i32, @intCast((ICON_CELL_W - ICON_PIXEL_W) / 2));
        const icon_y: i32 = cell.y + 4;
        gfx.drawIcon32(icon_x, icon_y, sc.icon);

        aa_font.drawTextCentered(cell.x, cell.y + 40, ICON_CELL_W, sc.name, 0xEEEEEE, label_atlas);
    }
}

/// Called after windows have been blitted so the ghost sits on top of
/// everything except the cursor. No-op when nothing is being dragged.
pub fn renderDragGhost() void {
    if (drag_idx < 0) return;
    const si: usize = @intCast(drag_idx);
    const sc = pinned.list[si];
    // The cell's top-left, derived from current cursor + the original
    // anchor offset (so the icon "sticks" to the same point on it that
    // the user pressed).
    const cell_x = drag_curr_x - drag_anchor_x;
    const cell_y = drag_curr_y - drag_anchor_y;
    const icon_x: i32 = cell_x + @as(i32, @intCast((ICON_CELL_W - ICON_PIXEL_W) / 2));
    const icon_y: i32 = cell_y + 4;
    gfx.drawIcon32Alpha(icon_x, icon_y, sc.icon, GHOST_ALPHA);
}

fn iconAt(mx: i32, my: i32) ?i8 {
    for (pinned.list, 0..) |_, si| {
        const cell = iconCell(si);
        const x = cell.x - 4;
        const y = cell.y - 2;
        if (mx >= x and mx < x + @as(i32, ICON_CELL_W) and my >= y and my < y + @as(i32, ICON_CELL_H)) {
            return @intCast(si);
        }
    }
    return null;
}

/// Mouse-down on the desktop. If it lands on an icon, capture press
/// state. Selection / launch / drag-start decisions defer until the
/// matching mouse-move or mouse-up.
pub fn handleMouseDown(mx: i32, my: i32) bool {
    if (iconAt(mx, my)) |idx| {
        press_idx = idx;
        press_x = mx;
        press_y = my;
        return true;
    }
    press_idx = -1;
    // Click in empty desktop area clears selection.
    if (selected >= 0) {
        selected = -1;
        return true;
    }
    return false;
}

/// Mouse-move with button held. If we have a pending press AND cursor
/// moved past DRAG_THRESHOLD, promote to a drag. Once dragging, track
/// the cursor so renderDragGhost paints in the right place. Returns
/// true if drag state changed (caller should mark dirty).
pub fn handleMouseMove(mx: i32, my: i32, left_down: bool) bool {
    if (!left_down) return false;

    if (drag_idx >= 0) {
        // Already dragging — just update ghost position.
        if (mx == drag_curr_x and my == drag_curr_y) return false;
        drag_curr_x = mx;
        drag_curr_y = my;
        return true;
    }

    if (press_idx < 0) return false;
    const dx = mx - press_x;
    const dy = my - press_y;
    const absdx = if (dx < 0) -dx else dx;
    const absdy = if (dy < 0) -dy else dy;
    if (absdx < DRAG_THRESHOLD and absdy < DRAG_THRESHOLD) return false;

    // Promote to drag. Anchor = where in the icon cell the user pressed.
    const si: usize = @intCast(press_idx);
    const cell = iconCell(si);
    drag_idx = press_idx;
    drag_curr_x = mx;
    drag_curr_y = my;
    drag_anchor_x = press_x - cell.x;
    drag_anchor_y = press_y - cell.y;
    // Drag supersedes any pending click — selection should follow the
    // drop, not the press, and double-click on a freshly-dropped icon
    // shouldn't fire spuriously.
    selected = press_idx;
    return true;
}

pub const ClickResult = enum { miss, selected, launch, drop };

/// Mouse-up. If a drag is in progress, commit the new position. If
/// instead this was a static press, run the original click / double-
/// click logic.
pub fn handleMouseUp(mx: i32, my: i32, now: u32) struct { result: ClickResult, launch_idx: usize } {
    if (drag_idx >= 0) {
        // Commit drop. New cell top-left = cursor - anchor, clamped to
        // the screen so users can't drop icons into oblivion.
        const new_x = mx - drag_anchor_x;
        const new_y = my - drag_anchor_y;
        const clamped_x: i32 = clampX(new_x);
        const clamped_y: i32 = clampY(new_y);
        const si: usize = @intCast(drag_idx);
        positions[si] = .{ .x = clamped_x, .y = clamped_y };
        drag_idx = -1;
        press_idx = -1;
        // Reset double-click timer so the drop doesn't get paired with
        // the next click into a phantom launch.
        last_click_tick = 0;
        return .{ .result = .drop, .launch_idx = 0 };
    }
    if (press_idx < 0) {
        return .{ .result = .miss, .launch_idx = 0 };
    }
    // Static press on an icon — original click semantics.
    const idx = press_idx;
    press_idx = -1;
    if (iconAt(mx, my) != idx) {
        // Released off-icon — treat as miss.
        return .{ .result = .miss, .launch_idx = 0 };
    }
    if (idx == selected and (now -% last_click_tick) < DOUBLE_CLICK_TICKS) {
        const idx_us: usize = @intCast(idx);
        selected = -1;
        return .{ .result = .launch, .launch_idx = idx_us };
    }
    selected = idx;
    last_click_tick = now;
    return .{ .result = .selected, .launch_idx = 0 };
}

/// Cancel any pending press or active drag without committing. Used on
/// focus loss / resolution change so we don't strand half-completed
/// drags.
pub fn cancelDrag() void {
    drag_idx = -1;
    press_idx = -1;
}

/// Clear every per-icon position override so the icon column snaps back
/// to the default top-down grid. Triggered by the "Arrange Icons" right-
/// click action — escape hatch when the user has scattered icons and
/// wants a clean slate without rebooting.
pub fn resetPositions() void {
    for (&positions) |*p| p.* = null;
    drag_idx = -1;
    press_idx = -1;
    selected = -1;
}

fn clampX(x: i32) i32 {
    if (x < 4) return 4;
    const max_x: i32 = @as(i32, @intCast(gfx.screen_w)) - @as(i32, @intCast(ICON_CELL_W)) - 4;
    if (max_x < 4) return 4;
    if (x > max_x) return max_x;
    return x;
}

fn clampY(y: i32) i32 {
    const min_y: i32 = @as(i32, @intCast(MENUBAR_H)) + 2;
    if (y < min_y) return min_y;
    // Leave room above the dock; assume taskbar ~60 px (matches dock height).
    const max_y: i32 = @as(i32, @intCast(gfx.screen_h)) - @as(i32, @intCast(ICON_CELL_H)) - 60;
    if (max_y < min_y) return min_y;
    if (y > max_y) return max_y;
    return y;
}
