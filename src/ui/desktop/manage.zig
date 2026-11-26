// What the pointer does to windows: raise and focus, the traffic lights,
// dragging by the titlebar (with the snap at a screen edge and the unzoom of
// a zoomed window), resizing by an edge, zoom and restore, and the menus and
// the launcher, which take the pointer while they are open.

const std = @import("std");
const gfx = @import("../gfx.zig");
const mouse = @import("../../driver.zig").mouse;
const process = @import("../../proc/process.zig");
const events_mod = @import("../events.zig");
const EventKind = events_mod.EventKind;
const damage = @import("damage.zig");
const accumVacated = damage.accumVacated;
const seedRect = damage.seedRect;
const seedWindow = damage.seedWindow;
const DirtyKind = damage.DirtyKind;
const client = @import("client.zig");
const createWindow = client.createWindow;
const closeWindow = client.closeWindow;
const surface = @import("surface.zig");
const growGuiFb = surface.growGuiFb;
const emulator = @import("term/emulator.zig");
const cells = @import("term/cells.zig");
const FONT_H = cells.FONT_H;
const TERM_WIN_W = cells.TERM_WIN_W;
const session = @import("term/session.zig");
const termPrompt = session.termPrompt;
const wm = @import("window.zig");
const Window = wm.Window;
const ResizeEdge = wm.ResizeEdge;
const windows = &wm.windows;
const slot_used = &wm.slot_used;
const z_stack = &wm.z_stack;
const pushZTop = wm.pushZTop;
const topSlot = wm.topSlot;
const setFocused = wm.setFocused;
const windowAt = wm.windowAt;
const isInTitlebar = wm.isInTitlebar;
const isOnCloseBtn = wm.isOnCloseBtn;
const isOnMinimizeBtn = wm.isOnMinimizeBtn;
const isOnMaximizeBtn = wm.isOnMaximizeBtn;
const isOnResizeEdge = wm.isOnResizeEdge;
const focusNextVisible = wm.focusNextVisible;
const dirty_rects_mod = @import("dirty.zig");
const markDirtyFull = dirty_rects_mod.markFull;
const animations = @import("animations.zig");
const startAnimation = animations.start;
const pinned = @import("pinned.zig");
const dock = @import("dock.zig");
const shortcuts = @import("shortcuts.zig");
const context_menu = @import("context_menu.zig");
const launcher = @import("launcher.zig");
const layout = @import("layout.zig");
const MENUBAR_H = layout.MENUBAR_H;
const TASKBAR_H = layout.TASKBAR_H;
const TITLEBAR_H = layout.TITLEBAR_H;
const TERM_ROWS = emulator.TERM_ROWS;
const MAX_WINDOWS: u32 = @import("../../config.zig").MAX_WINDOWS;
const MIN_WIN_W = wm.MIN_WIN_W;
const MIN_WIN_H = wm.MIN_WIN_H;

const input = @import("input.zig");
const launch = @import("launch.zig");
const launchShortcut = launch.launchShortcut;
const launchPath = launch.launchPath;

// --- Drag state ---
pub var dragging: bool = false;
pub var drag_win: u8 = 0;
var drag_ox: i32 = 0;
var drag_oy: i32 = 0;
/// Where the dragged window stood before the drag: what a snap at the end
/// of it saves as the place to restore to.
var drag_from_x: i32 = 0;
var drag_from_y: i32 = 0;
/// The drag began on a zoomed window, pressed at (drag_press_x/y), and has
/// not yet moved UNZOOM_DRAG_PX away: the window is still zoomed.
var drag_unzoom: bool = false;
var drag_press_x: i32 = 0;
var drag_press_y: i32 = 0;
const UNZOOM_DRAG_PX: u32 = 8;
var drag_old_x: i32 = 0;
var drag_old_y: i32 = 0;

// Resize state
pub var resizing: bool = false;
pub var resize_win: u8 = 0;
var resize_edge: ResizeEdge = .right;

pub fn toggleFullscreen(idx: u8) void {
    if (idx >= MAX_WINDOWS or !slot_used[idx]) return;
    const w = &windows[idx];
    if (w.anim_type != .none) return; // Already animating

    if (w.fullscreen) {
        // Exit maximize — animate back to saved geometry.
        w.fullscreen = false;
        startAnimation(idx, .unfullscreening);
        w.anim_end_x = w.saved_x;
        w.anim_end_y = w.saved_y;
        w.anim_end_w = w.saved_w;
        w.anim_end_h = w.saved_h;
        // Mirror drag-resize: update gui_w/gui_h so the renderWindow
        // blit doesn't crop content. Without this, vis_w/vis_h stay
        // stuck at the maximized size after un-fullscreen, but w.width
        // is now back to saved, so the blit overruns and reads past
        // the live region (or just shows stale max-size content).
        if (w.gui_fb != null) {
            w.gui_w = w.saved_w;
            w.gui_h = w.saved_h -| TITLEBAR_H;
        }
        // Notify the app of the restored size. It keeps the grown FB (we don't
        // shrink it for now) and renders a sub-region at the same stride.
        pushResize(w, w.saved_w, w.saved_h);
    } else {
        // Enter maximize — fill the entire area between menubar and
        // dock. Keep window chrome (titlebar + traffic-light buttons)
        // visible so the user can un-maximize, close, minimize.
        const usable_h: u32 = @as(u32, @intCast(gfx.screen_h)) -| MENUBAR_H -| TASKBAR_H;
        zoomWindow(idx, 0, @intCast(MENUBAR_H), gfx.screen_w, usable_h);
    }
}

/// Animate `idx` to the given rect and mark it zoomed, remembering the
/// geometry it had: toggleFullscreen (F10, the green button, a titlebar
/// drag) puts that back. Maximize is this over the whole work area.
fn zoomWindow(idx: u8, target_x: i32, target_y: i32, target_w: u32, target_h: u32) void {
    const w = &windows[idx];
    // For GUI apps with a fixed FB allocation (gui_alloc_w/h)
    // smaller than the content area: the GPU compositor scales
    // the FB via uv_scale push constant (gpu_compositor.zig:1819)
    // so the window draws filled. The 2D blit fallback caps
    // vis_w/vis_h to gui_alloc to avoid reading past the FB —
    // unused chrome-region pixels show whatever the background
    // pass painted, which is fine for the rare fallback case.
    w.saved_x = w.x;
    w.saved_y = w.y;
    w.saved_w = w.width;
    w.saved_h = w.height;
    w.fullscreen = true;
    startAnimation(idx, .fullscreening);

    w.anim_end_x = target_x;
    w.anim_end_y = target_y;
    w.anim_end_w = target_w;
    w.anim_end_h = target_h;
    // Mirror drag-resize (desktop.zig:2227,2259): bump gui_w/gui_h
    // to the new target so renderWindow's `vis_w = min(gui_w,
    // w.width)` doesn't crop the blit. Without this, w.width grows
    // to target_w but gui_w stays at the original (e.g. 480), and
    // the compositor only blits the upper-left 480-wide column of
    // an 864-wide window — the right strip + lower rows show
    // wallpaper through. The app discovers the new size by polling
    // getWindowSize() (already returns w.width/height) and repaints
    // to fill the expanded gui_fb region within its alloc cap.
    if (w.gui_fb != null) {
        // Grow the app's framebuffer to the zoomed content size so it
        // can repaint crisply (falls back to upscaling if the bigger
        // contiguous block can't be allocated). Sets gui_w/gui_h.
        _ = growGuiFb(idx, target_w, target_h -| TITLEBAR_H);
    }
    // Notify the app: it re-fetches the (grown) alloc via getWindowAlloc and
    // repaints at the new size.
    pushResize(w, target_w, target_h);
}

/// Tell the app its window is now win_w x win_h. The event carries the
/// content size, as the one sent at creation does: apps lay out to it.
fn pushResize(w: *Window, win_w: u32, win_h: u32) void {
    w.events.push(.{ .kind = @intFromEnum(EventKind.resize), .a = win_w, .b = win_h -| TITLEBAR_H });
}

const SnapRect = struct { x: i32, y: i32, w: u32, h: u32 };

/// Where a window dropped with the cursor at (mx, my) snaps to: a half of
/// the work area at a side edge of the screen, all of it at the top.
fn snapRect(mx: i32, my: i32) ?SnapRect {
    const sw: u32 = gfx.screen_w;
    const top: i32 = @intCast(MENUBAR_H);
    const usable_h: u32 = @as(u32, @intCast(gfx.screen_h)) -| MENUBAR_H -| TASKBAR_H;
    if (my <= 1) return .{ .x = 0, .y = top, .w = sw, .h = usable_h };
    if (mx <= 1) return .{ .x = 0, .y = top, .w = sw / 2, .h = usable_h };
    if (mx >= @as(i32, @intCast(sw)) - 2) return .{ .x = @intCast(sw / 2), .y = top, .w = sw - sw / 2, .h = usable_h };
    return null;
}

/// Raise `slot` to the top of z_stack and focus it. Stable-slot ID model:
/// the windows[] array is unchanged, so drag_win / resize_win / focused /
/// dock_btn indices NEVER need fix-up after this call. (Pre-2026-05-03 we
/// shifted the array on every reorder and patched up every reference;
/// every off-by-one in that fix-up was a UX bug.)
fn bringToFront(slot: u8) void {
    if (slot >= MAX_WINDOWS or !slot_used[slot]) return;
    if (topSlot()) |t| if (t == slot) {
        setFocused(slot);
        return;
    };
    pushZTop(slot);
    setFocused(slot);
}

/// Act on what the launcher answered to a key or a click.
pub fn runLauncherResult(res: launcher.Result) void {
    const pick = switch (res) {
        .launch => |c| c,
        else => return,
    };
    switch (pick) {
        .app => |i| launchShortcut(i),
        .command => |name| {
            var path: [32]u8 = undefined;
            const p = std.fmt.bufPrint(&path, "/bin/{s}.elf", .{name}) catch return;
            launchPath(p);
        },
    }
}

fn executeMenuItem(idx: i8) void {
    if (idx < 0) return;
    switch (context_menu.ctx) {
        .desktop_bg => switch (@as(u8, @intCast(idx))) {
            // New Terminal: the same shell window the Terminal icon opens.
            0 => launchShortcut(0),
            1 => launcher.open(), // Open App...
            2 => { // Kernel Console: a terminal on the in-kernel CLI, no shell.
                // window_count is u8: widen before the multiply.
                const off: i32 = @intCast(@as(u32, wm.window_count) * 30);
                const nw: u32 = TERM_WIN_W;
                const nh: u32 = TERM_ROWS * FONT_H + TITLEBAR_H;
                if (createWindow("Terminal", 80 + off, 40 + off, nw, nh)) |ni| {
                    setFocused(ni);
                    termPrompt(&windows[ni]);
                }
            },
            3 => { // Arrange Icons — snap any displaced shortcut back to grid
                shortcuts.resetPositions();
                markDirtyFull();
            },
            4 => launchPath("/bin/about.elf"),
            else => {},
        },
        // New Window: another instance of the pinned app.
        .dock_app => if (idx == 0 and context_menu.target_win < pinned.list.len) launchShortcut(context_menu.target_win),
        .titlebar => switch (@as(u8, @intCast(idx))) {
            0 => { // Close
                if (slot_used[context_menu.target_win]) closeWindow(context_menu.target_win);
            },
            1 => { // Minimize
                if (slot_used[context_menu.target_win]) {
                    startAnimation(context_menu.target_win, .minimizing);
                    focusNextVisible();
                }
            },
            else => {},
        },
        .none => {},
    }
}

pub fn handleMouseEvents(btn: u8) DirtyKind {
    const mx = mouse.x;
    const my = mouse.y;
    const left_down = (btn & 1) != 0;
    const was_down = (input.prev_buttons & 1) != 0;
    const right_down = (btn & 2) != 0;
    const right_was = (input.prev_buttons & 2) != 0;
    var result: DirtyKind = .none;

    // Mouse-wheel scroll: route to terminal window under cursor (or focused
    // terminal if not directly hovered). 3 lines per notch.
    if (mouse.wheel != 0) {
        // Atomic drain: producers run in IRQ context (xHCI inline drain
        // since Inc2c, PS/2 IRQ12) — a plain read-then-clear loses notches
        // added in between. Producers are BSP-only, so Xchg vs a same-CPU
        // IRQ `+=` is a complete fix, not just a narrower window.
        const w_delta = @atomicRmw(i32, &mouse.wheel, .Xchg, 0, .acq_rel);
        const target_idx: ?u8 = if (windowAt(mx, my)) |hi|
            (if (windows[hi].term != null) hi else null)
        else if (slot_used[wm.focused] and windows[wm.focused].term != null)
            wm.focused
        else
            null;
        if (target_idx) |ti| {
            const w = &windows[ti];
            if (w.term) |tt| {
                const lines_per_notch: i32 = 3;
                const step: i32 = w_delta * lines_per_notch;
                if (step > 0) {
                    const ustep: u16 = @intCast(@min(step, 0xFFFF));
                    tt.scroll_view = @min(tt.scroll_view + ustep, tt.scroll_count);
                } else {
                    const ustep: u16 = @intCast(@min(-step, 0xFFFF));
                    tt.scroll_view -|= ustep;
                }
                seedWindow(ti);
                result = .region;
            }
        }
    }

    // Launcher: modal for the mouse. Opening, closing and resizing are
    // repainted by renderRegions; a selection change keeps the rect, so it
    // is seeded here.
    if (launcher.active) {
        if (launcher.hover(mx, my)) {
            if (launcher.rect()) |r| seedRect(r);
            result = .region;
        }
        if (left_down and !was_down) {
            runLauncherResult(launcher.click(mx, my));
            result = .region;
        } else if (right_down and !right_was) {
            launcher.close();
            result = .region;
        }
        input.prev_buttons = btn;
        return result;
    }

    // Context menu: dismiss on left-click, track hover. A menu that opens,
    // closes or moves is repainted by renderRegions; a hover change keeps
    // the rect, so it is seeded here.
    if (context_menu.active) {
        if (context_menu.updateHover(mx, my)) {
            if (context_menu.rect()) |r| seedRect(r);
            result = .region;
        }
        if (left_down and !was_down) {
            executeMenuItem(context_menu.itemAt(mx, my));
            context_menu.close();
            result = .full;
            input.prev_buttons = btn;
            return result;
        }
        if (right_down and !right_was) {
            context_menu.close();
            result = .region;
            // Fall through to open new menu below
        } else {
            input.prev_buttons = btn;
            return result;
        }
    }

    // Right-click: open context menu
    if (right_down and !right_was) {
        if (windowAt(mx, my) == null and dock.inDockZone(my)) {
            // A pinned app offers a new window; a lone window, what its
            // titlebar does.
            if (dock.menuAt(mx, my)) |m| {
                switch (m.target) {
                    .app => |pi| context_menu.openAbove(.dock_app, m.x, m.y, pi),
                    .window => |slot| context_menu.openAbove(.titlebar, m.x, m.y, slot),
                }
                // The menu sits where the tooltip would.
                dock.hideTooltip();
                result = .region;
            }
        } else if (windowAt(mx, my)) |idx| {
            if (isInTitlebar(idx, mx, my)) {
                context_menu.open(.titlebar, mx, my, idx);
                result = .region;
            }
        } else {
            context_menu.open(.desktop_bg, mx, my, 0);
            result = .region;
        }
    }

    if (left_down and !was_down) {
        // A window covering the click position takes priority over the
        // dock — fullscreen apps (e.g. doom at 640×400 dragged over the
        // dock strip) would otherwise have their clicks eaten by dock
        // shortcut hit-testing, silently launching pinned apps.
        const window_hit = windowAt(mx, my);
        if (window_hit == null and dock.inDockZone(my)) {
            if (dock.clickAt(mx, my)) |action| {
                switch (action) {
                    .launch => |si| launchShortcut(si),
                    .window => |di| {
                        if (windows[di].minimized) {
                            startAnimation(di, .restoring);
                        }
                        // bringToFront is no-op when di is already on top, so we
                        // can call it unconditionally; setFocused is folded in.
                        bringToFront(di);
                    },
                }
                result = .full;
            }
        } else if (window_hit) |clicked_idx| {
            // Stable slot ID — bringToFront only mutates z_stack, so the
            // slot we got from windowAt stays valid for the rest of this
            // click handler regardless of z-order shuffles.
            const idx = clicked_idx;
            const was_top = if (topSlot()) |t| t == idx else false;
            if (!was_top) {
                bringToFront(idx);
                result = .full;
            }
            if (idx != wm.focused) {
                setFocused(idx);
                result = .full;
            }
            if (isOnCloseBtn(idx, mx, my)) {
                closeWindow(idx);
                result = .full;
            } else if (isOnMinimizeBtn(idx, mx, my)) {
                startAnimation(idx, .minimizing);
                focusNextVisible();
                result = .full;
            } else if (isOnMaximizeBtn(idx, mx, my)) {
                toggleFullscreen(idx);
                result = .full;
            } else if (isOnResizeEdge(idx, mx, my)) |edge| {
                resizing = true;
                resize_win = idx;
                resize_edge = edge;
            } else if (isInTitlebar(idx, mx, my)) {
                // Titlebar press = start drag. Maximize is reachable via the
                // window's maximize button and F10 — the prior double-click
                // maximize fired too eagerly on regular drags and was removed.
                // Drag-on-zoomed = restore + drag, like macOS/Win; the
                // restore waits for the cursor to really move, so a click
                // on the titlebar leaves the window zoomed.
                if (windows[idx].fullscreen) {
                    drag_unzoom = true;
                    drag_press_x = mx;
                    drag_press_y = my;
                } else {
                    drag_unzoom = false;
                    drag_ox = mx - windows[idx].x;
                    drag_oy = my - windows[idx].y;
                    drag_from_x = windows[idx].x;
                    drag_from_y = windows[idx].y;
                }
                dragging = true;
                drag_win = idx;
            }
        } else {
            // Mouse-down on desktop background: capture press for the
            // shortcut module. Click/launch/drop fires on mouse-up;
            // drag-start fires on mouse-move past threshold.
            if (shortcuts.handleMouseDown(mx, my)) {
                result = .full;
            }
            // Check resize edge top-down through z_stack so the topmost
            // window's edge wins.
            var k: u8 = wm.z_count;
            while (k > 0) {
                k -= 1;
                const wi = z_stack[k];
                if (!windows[wi].visible or windows[wi].minimized) continue;
                if (isOnResizeEdge(wi, mx, my)) |edge| {
                    resizing = true;
                    resize_win = wi;
                    resize_edge = edge;
                    if (wi != wm.focused) {
                        setFocused(wi);
                        result = .full;
                    }
                    break;
                }
            }
        }
    } else if (!left_down and was_down) {
        // A window dropped with the cursor at a screen edge snaps there.
        // Not one on a GPU slot: its image keeps the size it was created
        // with, so it would be stretched rather than laid out anew.
        if (dragging and drag_win < MAX_WINDOWS and slot_used[drag_win]) {
            const dw = &windows[drag_win];
            if (dw.anim_type == .none and !dw.fullscreen and dw.gpu_slot == null) {
                if (snapRect(mx, my)) |r| {
                    zoomWindow(drag_win, r.x, r.y, r.w, r.h);
                    // Restore to where the drag began, not to the edge.
                    dw.saved_x = drag_from_x;
                    dw.saved_y = drag_from_y;
                    result = .full;
                }
            }
        }
        dragging = false;
        // If a resize was in progress, publish a resize event with the
        // final dimensions before clearing state. Apps that do
        // resolution-dependent layout work see the new size and can
        // reflow without polling getWindowSize every frame.
        if (resizing and resize_win < MAX_WINDOWS and slot_used[resize_win]) {
            const rw = &windows[resize_win];
            pushResize(rw, rw.width, rw.height);
        }
        resizing = false;

        // Mouse-up routing for the shortcut icon module. An active
        // drag wins unconditionally (drop anywhere — including over a
        // window — so the user can park icons next to the focused app
        // even when it's taking up most of the screen). A static
        // press only counts when the release lands back over the
        // desktop, matching the macOS "press-then-drag-off cancels".
        const dragging_icon = shortcuts.isDragging();
        if (dragging_icon or windowAt(mx, my) == null) {
            const now: u32 = @truncate(process.tick_count);
            const r = shortcuts.handleMouseUp(mx, my, now);
            switch (r.result) {
                .launch => {
                    launchShortcut(r.launch_idx);
                    result = .full;
                },
                .selected, .drop => result = .full,
                .miss => {},
            }
        } else {
            // Released over a window with no active drag — drop any
            // pending press so it doesn't latch.
            shortcuts.cancelDrag();
        }
    }

    if (dragging and left_down and drag_unzoom) {
        const dw = &windows[drag_win];
        if (!dw.fullscreen) {
            // Unzoomed some other way meanwhile: an ordinary drag from here.
            drag_unzoom = false;
            drag_ox = mx - dw.x;
            drag_oy = my - dw.y;
            drag_from_x = dw.x;
            drag_from_y = dw.y;
        } else if (@abs(mx - drag_press_x) + @abs(my - drag_press_y) >= UNZOOM_DRAG_PX and dw.anim_type == .none) {
            drag_unzoom = false;
            toggleFullscreen(drag_win);
            // Straight to the restored size: the animation would steer the
            // window back to where it stood while the cursor carries it.
            dw.anim_type = .none;
            dw.width = dw.saved_w;
            dw.height = dw.saved_h;
            // Under the cursor by the middle of its titlebar.
            drag_ox = @intCast(dw.saved_w / 2);
            drag_oy = @intCast(TITLEBAR_H / 2);
            drag_from_x = dw.saved_x;
            drag_from_y = dw.saved_y;
            dw.x = mx - drag_ox;
            dw.y = my - drag_oy;
            result = .full;
        }
    }

    if (dragging and left_down and !drag_unzoom) {
        const new_x = mx - drag_ox;
        var new_y = my - drag_oy;
        // Clamp: keep title bar accessible (don't let window hide under dock or go off-screen)
        const max_y: i32 = @intCast(gfx.screen_h - TASKBAR_H - TITLEBAR_H);
        const min_y: i32 = @as(i32, MENUBAR_H);
        if (new_y > max_y) new_y = max_y;
        if (new_y < min_y) new_y = min_y;
        if (new_x != windows[drag_win].x or new_y != windows[drag_win].y) {
            drag_old_x = windows[drag_win].x;
            drag_old_y = windows[drag_win].y;
            // Record the vacated region for the tight drag repaint instead of
            // the old markDirtyFull() — renderRegions restores exactly this
            // (plus the closure) rather than re-rendering the whole scene.
            accumVacated(drag_old_x, drag_old_y, windows[drag_win].width, windows[drag_win].height);
            windows[drag_win].x = new_x;
            windows[drag_win].y = new_y;
            if (result != .full) result = .drag;
        }
    }

    // Shortcut icon drag: track cursor + promote press → drag once
    // motion exceeds threshold. Mark .drag so the ghost trail is
    // repainted each frame. Skipped while a window-drag is in flight
    // so the two can't fight over the cursor.
    if (!dragging and !resizing) {
        if (shortcuts.handleMouseMove(mx, my, left_down)) {
            if (result != .full) result = .drag;
            markDirtyFull();
        }
    }

    if (resizing and left_down) {
        const w = &windows[resize_win];
        const right_anchor = w.x + @as(i32, @intCast(w.width));
        const bot_anchor = w.y + @as(i32, @intCast(w.height));

        const grows_right = (resize_edge == .right or resize_edge == .bottom_right or resize_edge == .top_right);
        const grows_bottom = (resize_edge == .bottom or resize_edge == .bottom_right or resize_edge == .bottom_left);
        const grows_left = (resize_edge == .left or resize_edge == .top_left or resize_edge == .bottom_left);
        const grows_top = (resize_edge == .top or resize_edge == .top_left or resize_edge == .top_right);

        var changed = false;

        if (grows_right) {
            var new_w: u32 = @max(MIN_WIN_W, @as(u32, @intCast(@max(mx + 2 - w.x, @as(i32, MIN_WIN_W)))));
            if (w.gui_alloc_w > 0) new_w = @min(new_w, w.gui_alloc_w);
            if (new_w != w.width) {
                w.width = new_w;
                if (w.gui_fb != null) w.gui_w = new_w;
                changed = true;
            }
        } else if (grows_left) {
            // Resizing from left: cursor x = new left edge. Width grows
            // by (right_anchor - mx); x moves to mx. Clamp to MIN_WIN_W
            // so we don't let x overrun the right anchor.
            const new_x_raw = mx;
            const new_x_max = right_anchor - @as(i32, MIN_WIN_W);
            const new_x_clamped: i32 = if (new_x_raw > new_x_max) new_x_max else new_x_raw;
            const min_y_for_left: i32 = MENUBAR_H;
            _ = min_y_for_left;
            var new_w: u32 = @intCast(right_anchor - new_x_clamped);
            if (w.gui_alloc_w > 0 and new_w > w.gui_alloc_w) {
                // Allocation-capped: stop at the alloc ceiling, with x
                // adjusted so the right edge stays put.
                new_w = w.gui_alloc_w;
            }
            const new_x_final: i32 = right_anchor - @as(i32, @intCast(new_w));
            if (new_x_final != w.x or new_w != w.width) {
                w.x = new_x_final;
                w.width = new_w;
                if (w.gui_fb != null) w.gui_w = new_w;
                changed = true;
            }
        }

        if (grows_bottom) {
            var new_h: u32 = @max(MIN_WIN_H, @as(u32, @intCast(@max(my + 2 - w.y, @as(i32, MIN_WIN_H)))));
            if (w.gui_alloc_h > 0) new_h = @min(new_h, w.gui_alloc_h + TITLEBAR_H);
            if (new_h != w.height) {
                w.height = new_h;
                if (w.gui_fb != null) w.gui_h = new_h -| TITLEBAR_H;
                changed = true;
            }
        } else if (grows_top) {
            // Resizing from top: never let the titlebar slide under the
            // menubar — clamp new y to MENUBAR_H.
            var new_y_raw = my;
            if (new_y_raw < @as(i32, MENUBAR_H)) new_y_raw = @as(i32, MENUBAR_H);
            const new_y_max = bot_anchor - @as(i32, MIN_WIN_H);
            const new_y_clamped: i32 = if (new_y_raw > new_y_max) new_y_max else new_y_raw;
            var new_h: u32 = @intCast(bot_anchor - new_y_clamped);
            if (w.gui_alloc_h > 0 and new_h > w.gui_alloc_h + TITLEBAR_H) {
                new_h = w.gui_alloc_h + TITLEBAR_H;
            }
            const new_y_final: i32 = bot_anchor - @as(i32, @intCast(new_h));
            if (new_y_final != w.y or new_h != w.height) {
                w.y = new_y_final;
                w.height = new_h;
                if (w.gui_fb != null) w.gui_h = new_h -| TITLEBAR_H;
                changed = true;
            }
        }

        if (changed) {
            // De-maximize on user-driven resize so the maximize toggle
            // reflects reality (clicking maximize again should re-snap
            // to usable area, not restore to some stale saved geometry).
            if (w.fullscreen) w.fullscreen = false;
            result = .full;
            markDirtyFull();
        }
    }

    input.prev_buttons = btn;
    return result;
}
