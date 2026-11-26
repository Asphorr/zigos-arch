// The scene in the back buffer: all of it, bottom to top (renderScene), or
// only the regions a frame changed, each grown until every layer it touches
// lies wholly inside it (renderRegions), so that what blends is blended
// once.

const gfx = @import("../gfx.zig");
const display = @import("../display.zig");
const frameperf = @import("frameperf.zig");
const cells = @import("term/cells.zig");
const FONT_H = cells.FONT_H;
const term_view = @import("term/view.zig");
const renderTerminalRow = term_view.renderTerminalRow;
const wm = @import("window.zig");
const windows = &wm.windows;
const slot_used = &wm.slot_used;
const z_stack = &wm.z_stack;
const dirty_rects_mod = @import("dirty.zig");
const addDirtyRect = dirty_rects_mod.add;
const resetDirtyRects = dirty_rects_mod.reset;
const toast = @import("toast.zig");
const menubar = @import("menubar.zig");
const dock = @import("dock.zig");
const shortcuts = @import("shortcuts.zig");
const context_menu = @import("context_menu.zig");
const launcher = @import("launcher.zig");
const background = @import("background.zig");
const layout = @import("layout.zig");
const MENUBAR_H = layout.MENUBAR_H;
const TASKBAR_H = layout.TASKBAR_H;
const TITLEBAR_H = layout.TITLEBAR_H;
const BORDER = layout.BORDER;
const MAX_WINDOWS: u32 = @import("../../config.zig").MAX_WINDOWS;
const manage = @import("manage.zig");
const screen = @import("screen.zig");
const swCursorActive = screen.swCursorActive;
const eraseCursor = screen.eraseCursor;
const drawCursorOnScreen = screen.drawCursorOnScreen;
const bakeCursorToBackBuffer = screen.bakeCursorToBackBuffer;
const unbakeCursorFromBackBuffer = screen.unbakeCursorFromBackBuffer;
const blitWindowBounds = screen.blitWindowBounds;

const chrome = @import("chrome.zig");
const damage = @import("damage.zig");
const paddedWinRect = chrome.paddedWinRect;
const SHADOW_SPAD = chrome.SHADOW_SPAD;
const renderWindow = chrome.renderWindow;
const Bbox = damage.Bbox;
const seedRegion = damage.seedRegion;
const seedRect = damage.seedRect;
const seedWindow = damage.seedWindow;
const DirtyKind = damage.DirtyKind;

/// Incremented at the start of every renderScene call. The mode-9 GPU
/// compositor caches the last value it saw; if unchanged since the last
/// frame, the desktop hasn't redrawn, so the compositor can skip its
/// full-screen blit + flush. Saves ~12 ms/frame when idle.
pub var render_tick: u32 = 0;

/// True iff some window above z_stack[z_pos] in z-order fully contains
/// `idx`'s rect. Used by renderScene to skip painting hidden lower
/// windows. Conservative — only checks single-window containment, not
/// multi-window region unions, so it under-skips rather than over-skips.
fn isCoveredByUpper(z_pos: u8, idx: u8) bool {
    const w = &windows[idx];
    if (w.fullscreen) return false; // fullscreen self never gets skipped
    const w_left: i32 = w.x;
    const w_top: i32 = w.y;
    const w_right: i32 = w.x + @as(i32, @intCast(w.width));
    const w_bot: i32 = w.y + @as(i32, @intCast(w.height));

    var k: u8 = z_pos + 1;
    while (k < wm.z_count) : (k += 1) {
        const u = &windows[z_stack[k]];
        // One mid-animation is see-through and not yet at its rect.
        if (!u.visible or u.minimized or u.anim_type != .none) continue;
        // Strict containment of `w`'s rect inside `u`'s rect. Doesn't
        // account for shadow extents or rounded-corner alpha — tiny
        // visible slivers of the lower window would survive, but the
        // back buffer keeps the previous frame's shadow pixels valid
        // until something forces a repaint.
        const u_left: i32 = u.x;
        const u_top: i32 = u.y;
        const u_right: i32 = u.x + @as(i32, @intCast(u.width));
        const u_bot: i32 = u.y + @as(i32, @intCast(u.height));
        if (u_left <= w_left and u_top <= w_top and
            u_right >= w_right and u_bot >= w_bot)
        {
            return true;
        }
    }
    return false;
}

/// True if a window above `z_pos` in the stack hides window `wi` whole, so
/// that a new frame of it changes nothing on screen. The margin keeps clear
/// of the cover's rounded corners.
pub fn windowCovered(z_pos: usize, wi: u8) bool {
    const COVER_MARGIN: i32 = 12;
    const w = &windows[wi];
    const x1 = w.x + @as(i32, @intCast(w.width));
    const y1 = w.y + @as(i32, @intCast(w.height));
    for (z_stack[z_pos + 1 .. wm.z_count]) |ui| {
        const u = &windows[ui];
        if (!slot_used[ui] or !u.visible or u.minimized or u.anim_type != .none) continue;
        if (w.x >= u.x + COVER_MARGIN and x1 <= u.x + @as(i32, @intCast(u.width)) - COVER_MARGIN and
            w.y >= u.y and y1 <= u.y + @as(i32, @intCast(u.height))) return true;
    }
    return false;
}

pub fn renderScene() void {
    render_tick +%= 1;
    // Maximized windows now keep menubar + dock visible (they only fill
    // the usable area between them), so the background + shortcuts paint
    // unconditionally — they're never fully occluded by a single window.
    background.render();
    shortcuts.render();
    // Full scene re-render — background.render() above wiped the entire
    // back buffer to wallpaper, so each visible window must re-blend its
    // drop shadow. Setting shadow_dirty=true here covers .full and .drag
    // paths (both call renderScene); content-only updates (.gui_only /
    // .text_only) call renderWindow directly *without* clearing first,
    // so they correctly leave the existing back-buffer shadow alone.
    {
        var si: u8 = 0;
        while (si < wm.z_count) : (si += 1) {
            const idx = z_stack[si];
            if (windows[idx].visible) windows[idx].shadow_dirty = true;
        }
    }
    // Render in z-order, bottom→top, so the topmost window paints last
    // and any focus highlight / cursor lands above its neighbors.
    // Skip a window if any opaque window above fully contains it — its
    // pixels would be entirely overpainted, so paint + dirty-rect work
    // is wasted. Catches the common "fullscreen on top" + "alt-tab to
    // a maximized app" cases for free; conservative single-window
    // containment test, doesn't try to compute multi-window union.
    var k: u8 = 0;
    while (k < wm.z_count) : (k += 1) {
        const i = z_stack[k];
        if (!windows[i].visible) continue;
        if (isCoveredByUpper(k, i)) continue;
        renderWindow(i);
    }
    const focused_title: ?[]const u8 = if (slot_used[wm.focused] and windows[wm.focused].visible)
        windows[wm.focused].title[0..windows[wm.focused].title_len]
    else
        null;
    menubar.render(focused_title);
    dock.render();
    dock.renderTooltip();
    toast.render();
    context_menu.render();
    launcher.render();
    // Drag ghost (semi-transparent icon following the cursor) renders
    // last so it floats above windows, menubar, dock, toast, and any
    // context menu. The cursor itself paints after renderScene returns
    // and stays on top of the ghost.
    shortcuts.renderDragGhost();
    // Damage signal for the GPU compositor (mode 9). MUST be at the end
    // of renderScene so the compositor's wake reads a fully-painted
    // backbuf. Calling it at the top would race: compositor wakes,
    // samples bb mid-paint or empty-on-first-frame, then idles forever
    // → pitch-black screen. No-op when the compositor task isn't up.
    @import("../gpu_compositor.zig").requestRender();
}

/// Re-render every visible window above `target` in z-order whose outer
/// rect (including shadow) overlaps `target`. Called from partial-render
/// paths (`.gui_only`) after the target window has been stamped into the
/// back buffer — without this, the target's paint clobbers z-higher
/// neighbors in the overlap region because renderWindow doesn't itself
/// know about stacking order.
///
/// The shadow is now all-around (see SHADOW_* above), so the overlap test is
/// widened by SHADOW_SPAD on EVERY side, not just lower+right.
pub fn repaintZAboveOverlapping(target: u8) void {
    if (target >= MAX_WINDOWS or !slot_used[target]) return;
    const t = &windows[target];
    const t_left: i32 = t.x - SHADOW_SPAD;
    const t_top: i32 = t.y - SHADOW_SPAD;
    const t_right: i32 = t.x + @as(i32, @intCast(t.width)) + SHADOW_SPAD;
    const t_bot: i32 = t.y + @as(i32, @intCast(t.height)) + SHADOW_SPAD;

    var zi: u8 = 0;
    while (zi < wm.z_count and z_stack[zi] != target) : (zi += 1) {}
    if (zi >= wm.z_count) return;
    zi += 1;
    while (zi < wm.z_count) : (zi += 1) {
        const ai = z_stack[zi];
        const aw = &windows[ai];
        if (!aw.visible or aw.minimized) continue;
        const a_left: i32 = aw.x - SHADOW_SPAD;
        const a_top: i32 = aw.y - SHADOW_SPAD;
        const a_right: i32 = aw.x + @as(i32, @intCast(aw.width)) + SHADOW_SPAD;
        const a_bot: i32 = aw.y + @as(i32, @intCast(aw.height)) + SHADOW_SPAD;
        const overlaps = a_right > t_left and a_left < t_right and a_bot > t_top and a_top < t_bot;
        if (!overlaps) continue;
        // Do NOT set shadow_dirty here. Re-blending the 7.8% alpha shadow
        // over its previous frame on every .gui_only tick accumulates to
        // black (see [[project_shadow_dirty_flag]] / window-shadow-
        // accumulation-fix). The chrome+content repaint below covers the
        // overlap clobber; the existing shadow pixels from the last full
        // render stay in the back buffer wherever the target didn't write,
        // which is the common case for "focused terminal above an updating
        // GUI app". A stale-shadow strip only appears in the (rarer) case
        // where the target's rect actually intersects this window's shadow
        // band, and gets fully refreshed on the next renderScene pass.
        renderWindow(ai);
    }
}

/// Mode 9: what the backbuf shows on top of window `i`, as rects
/// [x0, y0, x1, y1) — the windows above it (bordered, without their
/// shadow: the backbuf holds no content under a GPU-slot window's
/// shadow), the menubar, the dock and the overlays — up to out.len of
/// them. The GPU compositor draws a GPU-slot window's content and then
/// the backbuf again over these. Caller holds the windows lock and the
/// compositor's source lock, so this matches the last finished desktop
/// iteration.
pub fn occludersAbove(i: u8, out: [][4]i32) usize {
    var n: usize = 0;
    var above = false;
    for (z_stack[0..wm.z_count]) |j| {
        const w = &windows[j];
        if (above and n < out.len and w.visible and !w.minimized) {
            out[n] = .{
                w.x - @as(i32, BORDER),
                w.y - @as(i32, BORDER),
                w.x + @as(i32, @intCast(w.width + BORDER)),
                w.y + @as(i32, @intCast(w.height + BORDER)),
            };
            n += 1;
        }
        if (j == i) above = true;
    }
    const bands = [_]?[4]i32{
        .{ 0, 0, @intCast(gfx.screen_w), @as(i32, MENUBAR_H) },
        dock.pillRect(),
        dock.tooltip_painted,
        toast.painted,
        context_menu.painted,
        launcher.painted,
    };
    for (bands) |b| {
        const r = b orelse continue;
        if (n == out.len) break;
        out[n] = r;
        n += 1;
    }
    return n;
}

// ─── Region repaint ─────────────────────────────────────────────────────────
// Frames that change a few known spots — terminal output, a window drag, an
// overlay appearing or moving — repaint only those spots instead of the whole
// scene, and hand only those rects to the flush and the GPU compositor. Each
// seed rect grows to the closure of every alpha layer it touches (window
// shadows, icon cells, glass bands and overlays all blend over or read the
// pixels beneath them, so each must lie wholly on freshly restored wallpaper
// or its blend accumulates: the shadow-darkening bug class). Intersecting
// closures merge; each disjoint region is then painted in renderScene's
// order, pixel-identical to renderScene inside it, untouched outside.

// Glass reach: the menubar's blurRegion radius 6 (+saturate), the dock's
// fillGlass radius 8 + pill soft shadow +2, and the overlays' fillGlass
// radius ≤ 6. Each joins a closure padded by its reach so the blur never
// samples stale pixels.
pub const MENUBAR_REACH: i32 = @as(i32, MENUBAR_H) + 8;
pub const DOCK_REACH: i32 = 12;
const OVERLAY_REACH: i32 = 8;

fn sameRect(a: ?[4]i32, b: ?[4]i32) bool {
    const ra = a orelse return b == null;
    const rb = b orelse return false;
    return ra[0] == rb[0] and ra[1] == rb[1] and ra[2] == rb[2] and ra[3] == rb[3];
}

/// An overlay that appeared, vanished or moved since it was last painted
/// needs both its old and its new rect repainted.
fn seedOverlayMove(painted: ?[4]i32, now: ?[4]i32) void {
    if (sameRect(painted, now)) return;
    if (painted) |r| seedRect(r);
    if (now) |r| seedRect(r);
}

/// True if an overlay on screen, or about to be, overlaps `r`.
fn overlayOver(r: [4]i32) bool {
    const area = Bbox{ .x0 = r[0], .y0 = r[1], .x1 = r[2], .y1 = r[3] };
    const overlays = [_]?[4]i32{
        dock.tooltip_painted, toast.painted, context_menu.painted, launcher.painted,
        dock.tooltipRect(),   toast.rect(),  context_menu.rect(),  launcher.rect(),
    };
    for (overlays) |o| {
        const q = o orelse continue;
        if (area.intersects(.{ .x0 = q[0], .y0 = q[1], .x1 = q[2], .y1 = q[3] })) return true;
    }
    return false;
}

/// True if this frame's partial window repaint — .gui_only's tracker rects,
/// .text_only's focused terminal — overlaps an overlay, which it would
/// paint over.
pub fn partialHitsOverlay(dirty: DirtyKind) bool {
    if (dock.tooltip_painted == null and toast.painted == null and context_menu.painted == null and
        launcher.painted == null and
        !dock.isTooltipVisible() and !toast.isActive() and !context_menu.active and !launcher.active) return false;
    if (dirty == .text_only) return slot_used[wm.focused] and overlayOver(paddedWinRect(wm.focused));
    if (dirty_rects_mod.isFull()) return true;
    const n = dirty_rects_mod.rectCount(); // can flip to full on cap overflow
    if (dirty_rects_mod.isFull()) return true;
    var i: u8 = 0;
    while (i < n) : (i += 1) {
        const r = dirty_rects_mod.getRect(i);
        if (overlayOver(.{ @intCast(r[0]), @intCast(r[1]), @intCast(r[0] + r[2]), @intCast(r[1] + r[3]) })) return true;
    }
    return false;
}

/// The focused terminal's text row {x, y, w, h} as .text_only paints and
/// flushes it, null when there is none on screen.
fn textRowRect() ?[4]u32 {
    if (!slot_used[wm.focused]) return null;
    const cw = &windows[wm.focused];
    const ct = cw.term orelse return null;
    if (!cw.visible or cw.minimized) return null;
    const ry = cw.y + @as(i32, TITLEBAR_H) + @as(i32, @intCast(@as(u32, ct.text_row) * FONT_H));
    if (ry < 0) return null;
    return .{ if (cw.x < 0) 0 else @intCast(cw.x), @intCast(ry), cw.width, FONT_H };
}

fn focusedTitle() ?[]const u8 {
    return if (slot_used[wm.focused] and windows[wm.focused].visible)
        windows[wm.focused].title[0..windows[wm.focused].title_len]
    else
        null;
}

const OverlayRects = struct { tip: ?[4]i32, toast: ?[4]i32, menu: ?[4]i32, launcher: ?[4]i32 };

/// Grow `u` until every layer it touches lies wholly inside it. Each pass
/// only grows over a fixed item set, so the fixpoint takes ≤ items passes
/// (1–2 in practice).
fn closeRegion(u: *Bbox, ov: OverlayRects) void {
    const dock_y: i32 = dock.dockY();
    const sw_i: i32 = @intCast(gfx.screen_w);
    u.grew = true;
    while (u.grew) {
        u.grew = false;
        var k: u8 = 0;
        while (k < wm.z_count) : (k += 1) {
            const i = z_stack[k];
            if (!windows[i].visible or windows[i].minimized) continue;
            const r = paddedWinRect(i);
            u.growOver(r[0], r[1], r[2], r[3]);
        }
        var si: usize = 0;
        while (si < shortcuts.cellCount()) : (si += 1) {
            const c = shortcuts.cellRect(si);
            u.growOver(c[0], c[1], c[0] + c[2], c[1] + c[3]);
        }
        u.growOver(0, 0, sw_i, MENUBAR_REACH);
        u.growOver(0, dock_y - DOCK_REACH, sw_i, dock_y + @as(i32, TASKBAR_H) + DOCK_REACH);
        for ([_]?[4]i32{ ov.tip, ov.toast, ov.menu, ov.launcher }) |o| {
            const r = o orelse continue;
            u.growOver(r[0] - OVERLAY_REACH, r[1] - OVERLAY_REACH, r[2] + OVERLAY_REACH, r[3] + OVERLAY_REACH);
        }
    }
}

/// Whether a closed region holds an overlay's paint. With nothing to draw
/// the overlay's render() only records that, so let it run.
fn overlayIn(u: Bbox, r: ?[4]i32) bool {
    const o = r orelse return true;
    return u.intersects(.{ .x0 = o[0], .y0 = o[1], .x1 = o[2], .y1 = o[3] });
}

/// Paint one closed region in renderScene's order.
fn paintRegion(u: Bbox, ov: OverlayRects) void {
    const ux: u32 = if (u.x0 < 0) 0 else @intCast(u.x0);
    const uy: u32 = if (u.y0 < 0) 0 else @intCast(u.y0);
    const ux1: u32 = if (u.x1 < 0) 0 else @min(@as(u32, @intCast(u.x1)), gfx.screen_w);
    const uy1: u32 = if (u.y1 < 0) 0 else @min(@as(u32, @intCast(u.y1)), gfx.screen_h);
    if (ux1 <= ux or uy1 <= uy) return;

    background.renderRect(ux, uy, ux1 - ux, uy1 - uy);
    shortcuts.renderRect(u.x0, u.y0, u.x1, u.y1);
    var k: u8 = 0;
    while (k < wm.z_count) : (k += 1) {
        const i = z_stack[k];
        if (!windows[i].visible or windows[i].minimized) continue;
        const r = paddedWinRect(i);
        const inter = r[0] < u.x1 and u.x0 < r[2] and r[1] < u.y1 and u.y0 < r[3];
        if (!inter) continue;
        // Mirror renderScene's containment skip — a fully-covered window's
        // shadow is never painted there, and painting it here would show a
        // shadow sliver poking past the coverer that pops away on release.
        if (isCoveredByUpper(k, i)) continue;
        // The closure put this window's whole padded rect on freshly restored
        // wallpaper, so the shadow re-blend can't accumulate frame-over-frame.
        // (Two overlapping non-containing shadows double-blend exactly like
        // renderScene does — same pixels, not a divergence.)
        windows[i].shadow_dirty = true;
        renderWindow(i);
    }
    // A band the region reaches lies wholly inside it (closure).
    if (u.y0 < MENUBAR_REACH) menubar.render(focusedTitle());
    if (u.y1 > dock.dockY() - DOCK_REACH) dock.render();
    if (overlayIn(u, ov.tip)) dock.renderTooltip();
    if (overlayIn(u, ov.toast)) toast.render();
    if (overlayIn(u, ov.menu)) context_menu.render();
    if (overlayIn(u, ov.launcher)) launcher.render();
    addDirtyRect(ux, uy, ux1 - ux, uy1 - uy);
}

/// Repaint this frame's seeds — plus the window-drag union, the windows the
/// GUI recomposite already stamped, and any overlay that moved — as closed
/// regions. Returns false, and the caller repaints the full scene, under the
/// software cursor (its previous position isn't modeled), during an icon drag
/// (nor is the ghost), or when the frame is already forced full.
pub fn renderRegions(use_hw_cursor: bool) bool {
    if (!use_hw_cursor or shortcuts.isDragging()) return false;
    if (dirty_rects_mod.isFull()) return false;
    const n = dirty_rects_mod.rectCount(); // can flip to full on cap overflow
    if (dirty_rects_mod.isFull()) return false;

    var ri: u8 = 0;
    while (ri < n) : (ri += 1) {
        const r = dirty_rects_mod.getRect(ri);
        seedRegion(@intCast(r[0]), @intCast(r[1]), @intCast(r[0] + r[2]), @intCast(r[1] + r[3]));
    }
    if (manage.dragging and damage.drag_accum_valid) {
        seedRegion(damage.drag_accum_x0, damage.drag_accum_y0, damage.drag_accum_x1, damage.drag_accum_y1);
        seedWindow(manage.drag_win);
    }
    const ov = OverlayRects{ .tip = dock.tooltipRect(), .toast = toast.rect(), .menu = context_menu.rect(), .launcher = launcher.rect() };
    seedOverlayMove(dock.tooltip_painted, ov.tip);
    seedOverlayMove(toast.painted, ov.toast);
    seedOverlayMove(context_menu.painted, ov.menu);
    seedOverlayMove(launcher.painted, ov.launcher);
    // A pending text row is painted alone unless an overlay lies over its
    // window (the row paint would cover it) or the window lands in a region.
    var row = if (damage.text_row_pending) textRowRect() else null;
    if (row != null and overlayOver(paddedWinRect(wm.focused))) {
        seedWindow(wm.focused);
        row = null;
    }

    var regions = damage.region_seeds;
    var count = damage.region_seed_count;
    damage.region_seed_count = 0;
    for (regions[0..count]) |*u| closeRegion(u, ov);
    // Merge until disjoint: then every layer lies in exactly one region and
    // the regions paint independently.
    var merged = true;
    while (merged) {
        merged = false;
        var i: u8 = 0;
        scan: while (i < count) : (i += 1) {
            var j: u8 = i + 1;
            while (j < count) : (j += 1) {
                const a = regions[i];
                const b = regions[j];
                if (!a.intersects(b)) continue;
                regions[i] = .{ .x0 = @min(a.x0, b.x0), .y0 = @min(a.y0, b.y0), .x1 = @max(a.x1, b.x1), .y1 = @max(a.y1, b.y1) };
                closeRegion(&regions[i], ov);
                count -= 1;
                regions[j] = regions[count];
                merged = true;
                break :scan;
            }
        }
    }
    for (regions[0..count]) |u| paintRegion(u, ov);
    if (row) |r| {
        // A window touching a region lies wholly inside it (closure), so
        // the row is either repainted already or clear of every region.
        const fw = paddedWinRect(wm.focused);
        const win = Bbox{ .x0 = fw[0], .y0 = fw[1], .x1 = fw[2], .y1 = fw[3] };
        var in_region = false;
        for (regions[0..count]) |u| in_region = in_region or u.intersects(win);
        if (!in_region) {
            renderTerminalRow(wm.focused);
            addDirtyRect(r[0], r[1], r[2], r[3]);
        }
    }
    // An overlay that moved while painting (the dock re-laid out its
    // buttons) may have landed outside every region.
    return sameRect(dock.tooltip_painted, ov.tip) and sameRect(toast.painted, ov.toast) and
        sameRect(context_menu.painted, ov.menu) and sameRect(launcher.painted, ov.launcher);
}

/// Stamp the new frames of GUI windows into the back buffer: each window
/// with a frame pending (a present, or an auto-refresh look that found new
/// pixels) and some of itself showing. Returns the frame's kind, raised to
/// .gui_only when a window was stamped and nothing more was due.
pub fn recomposite(kind: DirtyKind) DirtyKind {
    var dirty = kind;
    for (z_stack[0..wm.z_count], 0..) |gi, z_pos| {
        if (windows[gi].gui_present_pending and windows[gi].visible) {
            // Hidden whole behind another window: the frame stays
            // pending until some of the window shows.
            if (windowCovered(z_pos, gi)) continue;
            windows[gi].gui_present_pending = false;
            const w = &windows[gi];
            w.content_seq +%= 1;
            addDirtyRect(
                if (w.x < 0) 0 else @intCast(w.x),
                if (w.y < 0) 0 else @intCast(w.y),
                w.width + BORDER * 2 + 4,
                w.height + TITLEBAR_H + BORDER * 2 + 4,
            );
            if (screen.backbuf != null) {
                renderWindow(gi);
                // Re-paint any visible windows z-above `gi` that overlap
                // its rect. renderWindow stamps pixels into the back
                // buffer at the window's screen position regardless of
                // z-order — without this loop, a background-spawned GUI
                // updating its FB clobbers the focused terminal above
                // it in the overlap area (visible as flicker on each
                // cursor blink). renderScene's bottom→top iteration
                // handles this correctly; `.gui_only` was the partial-
                // render path that skipped it.
                repaintZAboveOverlapping(gi);
            }
            if (dirty == .none or dirty == .cursor_only) dirty = .gui_only;
        }
    }
    return dirty;
}

/// Bring the frame to the display: paint into the back buffer what its kind
/// calls for, copy the changed part to the screen, flush it, and tell the
/// GPU compositor (mode 9). The software pointer is stamped over the copy on
/// its way out and never left in the back buffer.
pub fn present(dirty: DirtyKind, use_hw_cursor: bool) void {
    if (screen.backbuf != null) {
        switch (dirty) {
            .full => {
                renderScene();
                // Reverted partial-blit optimization here while
                // diagnosing a stale-pixel ghost on the cube window —
                // full blit is the safe path. Re-enable once the
                // ghost cause is found.
                if (!use_hw_cursor) bakeCursorToBackBuffer();
                gfx.blitToScreen();
                if (!use_hw_cursor) unbakeCursorFromBackBuffer();
                display.flush();
                resetDirtyRects();
            },
            .drag, .region => {
                // Tight path (hw cursor only): repaint just the closed
                // regions and flush their rects. Falls back to the full-
                // scene path when renderRegions' preconditions don't hold.
                if (renderRegions(use_hw_cursor)) {
                    const dr_count = dirty_rects_mod.rectCount(); // can flip to full on cap overflow
                    if (dirty_rects_mod.isFull()) {
                        gfx.blitToScreen();
                        display.flush();
                    } else {
                        var bi: u8 = 0;
                        while (bi < dr_count) : (bi += 1) {
                            const r = dirty_rects_mod.getRect(bi);
                            gfx.blitRectToScreen(r[0], r[1], r[2], r[3]);
                        }
                        var fi: u8 = 0;
                        while (fi < dr_count) : (fi += 1) {
                            const r = dirty_rects_mod.getRect(fi);
                            display.flushRect(r[0], r[1], r[2], r[3]);
                        }
                    }
                    // Mode 9: rect snapshot → GPU compositor (no-op otherwise).
                    @import("../gpu_compositor.zig").requestRenderFromDirty();
                    resetDirtyRects();
                } else {
                    frameperf.regionFallback();
                    renderScene();
                    if (!use_hw_cursor) bakeCursorToBackBuffer();
                    gfx.blitToScreen();
                    if (!use_hw_cursor) unbakeCursorFromBackBuffer();
                    display.flush();
                    resetDirtyRects();
                }
            },
            .gui_only => {
                // GUI app content update — only blit the window's dirty rect
                if (!use_hw_cursor) bakeCursorToBackBuffer();
                const dr_count = dirty_rects_mod.rectCount();
                if (dr_count > 0) {
                    var di: u8 = 0;
                    while (di < dr_count) : (di += 1) {
                        const r = dirty_rects_mod.getRect(di);
                        gfx.blitRectToScreen(r[0], r[1], r[2], r[3]);
                    }
                } else {
                    gfx.blitToScreen();
                }
                if (!use_hw_cursor) unbakeCursorFromBackBuffer();
                if (dr_count > 0) {
                    var di: u8 = 0;
                    while (di < dr_count) : (di += 1) {
                        const r = dirty_rects_mod.getRect(di);
                        display.flushRect(r[0], r[1], r[2], r[3]);
                    }
                } else {
                    display.flush();
                }
                // Mode 9: hand the rect snapshot to the GPU compositor
                // before the reset clears them. requestRenderFromDirty
                // is a no-op when not in mode 9 (compositor task isn't up).
                @import("../gpu_compositor.zig").requestRenderFromDirty();
                resetDirtyRects();
            },
            .text_only => {
                const cw = &windows[wm.focused];
                if (cw.term != null and cw.visible and !cw.minimized) {
                    renderTerminalRow(wm.focused);
                    const ct = cw.term.?;
                    const content_y = cw.y + @as(i32, TITLEBAR_H);
                    const ry = content_y + @as(i32, @intCast(@as(u32, ct.text_row) * FONT_H));
                    if (ry >= 0) {
                        const uy: u32 = @intCast(ry);
                        if (!use_hw_cursor) eraseCursor();
                        gfx.blitRectToScreen(if (cw.x < 0) 0 else @intCast(cw.x), uy, cw.width, FONT_H);
                        if (swCursorActive(use_hw_cursor)) drawCursorOnScreen();
                        // Partial flush: just the text row band
                        display.flushRect(0, uy, gfx.screen_w, FONT_H);
                        // Mode 9: terminal row → compositor.
                        const cwx: u32 = if (cw.x < 0) 0 else @intCast(cw.x);
                        @import("../gpu_compositor.zig").requestRenderRect(cwx, uy, cw.width, FONT_H);
                    }
                } else {
                    renderWindow(wm.focused);
                    if (!use_hw_cursor) eraseCursor();
                    blitWindowBounds(wm.focused);
                    if (swCursorActive(use_hw_cursor)) drawCursorOnScreen();
                    // Flush window region
                    {
                        const fy: u32 = if (cw.y < 0) 0 else @intCast(cw.y);
                        display.flushRect(0, fy, gfx.screen_w, cw.height + TITLEBAR_H + 8);
                    }
                    // Mode 9: window region → compositor.
                    const wy: u32 = if (cw.y < 0) 0 else @intCast(cw.y);
                    @import("../gpu_compositor.zig").requestRenderRect(0, wy, gfx.screen_w, cw.height + TITLEBAR_H + 8);
                }
            },
            .cursor_only => {
                if (!use_hw_cursor) {
                    eraseCursor();
                    if (swCursorActive(use_hw_cursor)) drawCursorOnScreen();
                    // Software cursor: flush cursor bands
                    display.flush();
                }
                // Hardware cursor: nothing to flush (moveCursor already sent)
            },
            .none => {},
        }
    } else if (dirty != .none) {
        renderScene();
        if (swCursorActive(use_hw_cursor)) drawCursorOnScreen();
        display.flush();
    }
}
