const std = @import("std");
const gfx = @import("gfx.zig");
const bga = @import("../driver.zig").bga;
const display = @import("display.zig");
const mouse = @import("../driver.zig").mouse;
const keyboard = @import("../driver.zig").keyboard;
const vga = @import("../driver.zig").vga;
const paging = @import("../mm/paging.zig");
const pmm = @import("../mm/pmm.zig");
const debug = @import("../debug/debug.zig");
const elf_loader = @import("../proc/elf_loader.zig");
const xhci = @import("../driver.zig").xhci;
const process = @import("../proc/process.zig");
const sound = @import("../driver.zig").sound;
const events_mod = @import("events.zig");
pub const Event = events_mod.Event;
pub const EventKind = events_mod.EventKind;

const chrome = @import("desktop/chrome.zig");
pub const paddedWinRect = chrome.paddedWinRect;
const renderWindow = chrome.renderWindow;
pub const borderColor = chrome.borderColor;

const scene = @import("desktop/scene.zig");
const renderScene = scene.renderScene;
pub const occludersAbove = scene.occludersAbove;
pub const MENUBAR_REACH = scene.MENUBAR_REACH;
pub const DOCK_REACH = scene.DOCK_REACH;
const partialHitsOverlay = scene.partialHitsOverlay;
const renderRegions = scene.renderRegions;
const repaintZAboveOverlapping = scene.repaintZAboveOverlapping;
const windowCovered = scene.windowCovered;

const damage = @import("desktop/damage.zig");
const accumVacated = damage.accumVacated;
const seedRegion = damage.seedRegion;
const seedRect = damage.seedRect;
const seedWindow = damage.seedWindow;
const wantRegion = damage.wantRegion;
const wantTextRow = damage.wantTextRow;
const DirtyKind = damage.DirtyKind;

const client = @import("desktop/client.zig");
const createWindow = client.createWindow;
const closeWindow = client.closeWindow;
pub const createGuiWindow = client.createGuiWindow;
pub const focusedShellSpawnedPid = client.focusedShellSpawnedPid;
pub const Standing = client.Standing;
pub const actsFor = client.actsFor;
pub const maySetWallpaper = client.maySetWallpaper;
const finishClose = client.finishClose;
pub const DestroyedGui = client.DestroyedGui;
pub const GuiOwner = client.GuiOwner;
pub const groupHasGuiWindow = client.groupHasGuiWindow;
pub const destroyGuiWindow = client.destroyGuiWindow;
pub const focusedPid = client.focusedPid;
pub const focusedSignalTarget = client.focusedSignalTarget;
pub const focusedTty = client.focusedTty;
pub const canReadConsole = client.canReadConsole;
pub const popEvent = client.popEvent;
pub const consoleReadable = client.consoleReadable;
pub const popCharEvent = client.popCharEvent;
pub const getMouseRelative = client.getMouseRelative;
pub const setCursorHidden = client.setCursorHidden;
pub const centerMouse = client.centerMouse;
pub const getWindowContentSize = client.getWindowContentSize;
pub const getWindowAllocSize = client.getWindowAllocSize;

const surface = @import("desktop/surface.zig");
const growGuiFb = surface.growGuiFb;
pub const markGuiPresent = surface.markGuiPresent;
pub const snapshotGuiFb = surface.snapshotGuiFb;
pub const reclaimBackBuffers = surface.reclaimBackBuffers;
const guiContentHash = surface.guiContentHash;
const hasGuiWindows = surface.hasGuiWindows;

const emulator = @import("desktop/term/emulator.zig");
const putCharOnWindow = emulator.putCharOnWindow;

const cells = @import("desktop/term/cells.zig");
const FONT_H = cells.FONT_H;
const TERM_WIN_W = cells.TERM_WIN_W;

const term_view = @import("desktop/term/view.zig");
const renderTerminalRow = term_view.renderTerminalRow;
const termRowsPaintable = term_view.termRowsPaintable;
const repaintStaleRows = term_view.repaintStaleRows;

const session = @import("desktop/term/session.zig");
const termPrompt = session.termPrompt;
const spawnShellOnWindow = session.spawnShellOnWindow;
const handleKeyboard = session.handleKeyboard;

const notify = @import("desktop/notify.zig");
pub const showNotification = notify.showNotification;
pub const showNotificationFrom = notify.showNotificationFrom;

// DBG: input-pipeline diagnostic counters. Bumped from desktop's drain
// loop when chars get dropped. Read by manual klog dumps when input
// behavior is unexpected. Rate-limited so we don't flood the log.
var dbg_focus_drop_count: u64 = 0;
var dbg_event_queue_full: u64 = 0;
var dbg_last_focus_drop_log: u64 = 0;
var dbg_last_qfull_log: u64 = 0;

// --- Window management (storage, z-stack, focus, hit-testing) ---
const wm = @import("desktop/window.zig");
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
const cycleFocus = wm.cycleFocus;

// Persisted UI config (background, theme, dock position, …) — see
// desktop/config.zig. Re-exported so external callers (sysSetConfig,
// settings.elf-side notifications) keep using `desktop.conf.<field>`
// without learning the new path.
pub const conf = @import("desktop/config.zig");
pub var config_changed: bool = false;

// Dirty-region tracker for partial GPU flush — see desktop/dirty.zig.
// Aliased as `dirty_rects_mod` to avoid clashing with the local
// `dirty: DirtyKind` variable inside `run()`.
const dirty_rects_mod = @import("desktop/dirty.zig");
const addDirtyRect = dirty_rects_mod.add;
const markDirtyFull = dirty_rects_mod.markFull;
// Mode 9: requestRenderFromDirty has copied the rects into the compositor's
// own list before a frame resets them, so the reset needs no condition.
const resetDirtyRects = dirty_rects_mod.reset;

// --- Notification system ---
// Top-right toast notification — show()/tick()/render() in desktop/toast.zig.
const toast = @import("desktop/toast.zig");

// Top menu bar — render() in desktop/menubar.zig.
const menubar = @import("desktop/menubar.zig");

// Window animations (open/close/minimize/restore/fullscreen) — desktop/animations.zig.
const animations = @import("desktop/animations.zig");
const startAnimation = animations.start;
const advanceAnimations = animations.advance;
const hasActiveAnimations = animations.hasActive;

// Pinned-app manifest shared by the dock + desktop icons — desktop/pinned.zig.
const pinned = @import("desktop/pinned.zig");

// Bottom-centre dock pill, hover tooltip, click dispatch — desktop/dock.zig.
const dock = @import("desktop/dock.zig");

// Desktop icon column (left side) — render + click/double-click — desktop/shortcuts.zig.
const shortcuts = @import("desktop/shortcuts.zig");

// Right-click context menu (state + render + hit-test) — desktop/context_menu.zig.
// Action dispatch (executeMenuItem) stays here because it reaches into
// createWindow/closeWindow/etc.
const context_menu = @import("desktop/context_menu.zig");

// Open-an-app panel; started apps are launched here (runLauncherResult).
const launcher = @import("desktop/launcher.zig");

// --- Async app launch queue ---
// requestAppLoad rejects if AP is mid-flight on a previous load. Without
// queueing, the click is silently dropped — user clicks shortcut, sees
// "loading" and nothing happens. Buffer up to 8 pending names; drain one
// per frame in the desktop main loop once the AP goes idle.
// Pending-app-launch ring — see desktop/launch_queue.zig.
const launch_queue = @import("desktop/launch_queue.zig");

// Compositor wake primitive — event-driven sleep / wake; replaces the
// legacy "wake every 80 ms" floor in shouldResumeDesktop. See module
// doc-comment for the model.
pub const wake = @import("desktop/wake.zig");

// Owners parked in sysWaitEvent.
const event_wait = @import("desktop/event_wait.zig");

// Frame-time percentiles ([frameperf] serial dump every ~30 s). Phase
// stamps live in the main loop; flush time is accumulated inside
// display.flush/flushRect.
const frameperf = @import("desktop/frameperf.zig");

// --- Colors / palette / terminal tunables (see theme.zig) ---
const theme = @import("theme.zig");

// --- Layout ---
// Spatial constants live in desktop/layout.zig so other extracted
// submodules (toast, dock, menubar, compositor, …) can share them
// without circular imports back into this file.
const layout = @import("desktop/layout.zig");
const MENUBAR_H = layout.MENUBAR_H;
const TASKBAR_H = layout.TASKBAR_H;
const TITLEBAR_H = layout.TITLEBAR_H;
const BORDER = layout.BORDER;

const TERM_ROWS = emulator.TERM_ROWS;

// --- Terminal escape / coloring (see theme.zig for the constant values) ---
const CURSOR_BLINK_HALF_TICKS = theme.CURSOR_BLINK_HALF_TICKS;

// --- Window ---
const MAX_WINDOWS: u32 = @import("../config.zig").MAX_WINDOWS;

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

var prev_buttons: u8 = 0;

// Resize state
pub var resizing: bool = false;
pub var resize_win: u8 = 0;
var resize_edge: ResizeEdge = .right;
const MIN_WIN_W = wm.MIN_WIN_W;
const MIN_WIN_H = wm.MIN_WIN_H;

// --- Back buffer ---
pub var backbuf: ?[*]volatile u32 = null;
var bb_pages: u32 = 0;

/// Read-only access for the GPU compositor (mode 9). Returns null until
/// desktop.run() has finished allocating the back buffer; the compositor
/// polls until non-null before sampling.
pub fn getBackBuffer() ?[*]volatile u32 {
    return backbuf;
}

/// Mode 9: draw into `nb`, the GPU compositor's background source, from
/// now on. Caller holds the compositor's source lock. The old buffer is
/// the boot-reserved region; freeBackBuffer would be a no-op anyway.
fn adoptBackBuffer(nb: [*]volatile u32) void {
    const old = backbuf orelse return;
    const qwords: usize = @as(usize, gfx.target_w) * gfx.target_h / 2;
    asm volatile ("cld; rep movsq"
        :
        : [dst] "{rdi}" (@intFromPtr(nb)),
          [src] "{rsi}" (@intFromPtr(old)),
          [cnt] "{rcx}" (qwords),
        : .{ .rdi = true, .rsi = true, .rcx = true, .memory = true });
    backbuf = nb;
    bb_pages = 0;
    gfx.setTarget(nb, gfx.target_w, gfx.target_h);
    @import("gpu_compositor.zig").backBufferAdopted();
    debug.klog("[desktop] Back buffer: drawing into the GPU compositor's source\n", .{});
}

// --- Cursor ---
const CURSOR_W: u32 = 12;
const CURSOR_H: u32 = 16;
const cursor_sprite = [CURSOR_H][CURSOR_W]u8{
    .{ 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 1, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 1, 2, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 1, 2, 2, 2, 1, 0, 0, 0, 0, 0, 0, 0 },
    .{ 1, 2, 2, 2, 2, 1, 0, 0, 0, 0, 0, 0 },
    .{ 1, 2, 2, 2, 2, 2, 1, 0, 0, 0, 0, 0 },
    .{ 1, 2, 2, 2, 2, 2, 2, 1, 0, 0, 0, 0 },
    .{ 1, 2, 2, 2, 2, 2, 2, 2, 1, 0, 0, 0 },
    .{ 1, 2, 2, 2, 2, 2, 2, 2, 2, 1, 0, 0 },
    .{ 1, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 0 },
    .{ 1, 2, 2, 1, 2, 2, 1, 0, 0, 0, 0, 0 },
    .{ 1, 2, 1, 0, 1, 2, 2, 1, 0, 0, 0, 0 },
    .{ 1, 1, 0, 0, 1, 2, 2, 1, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 0, 1, 2, 2, 1, 0, 0, 0 },
    .{ 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0 },
};
var last_cursor_x: i32 = 0;
var last_cursor_y: i32 = 0;

/// Free-running per-frame counter, incremented once per desktop main-loop
/// iteration. Used for any "every N frames" scheduling that doesn't need
/// to track real time. Wraps around silently — only relative differences
/// matter. (Cursor blink uses `process.tick_count` instead, since the loop
/// wakes irregularly.)
var frame_count: u32 = 0;

/// Last cursor blink phase (`tick_count / CURSOR_BLINK_HALF_TICKS`) we
/// marked dirty for. Used to avoid spamming dirty=.text_only every loop iter
/// when the phase hasn't actually flipped.
var last_blink_phase: u64 = 0;

fn toggleFullscreen(idx: u8) void {
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

// --- Scene rendering (to back buffer) ---

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

fn launchShortcut(idx: usize) void {
    const sc = &pinned.list[idx];
    debug.klog("[launch] shortcut idx={d} name='{s}' cmd='{s}'\n", .{ idx, sc.name, sc.cmd });
    if (sc.cmd.len == 0) {
        // Terminal shortcut: create a window, allocate kb_pipe + out_pipe,
        // spawn app.elf (Ring 3) with stdin/stdout/stderr wired to those
        // pipes. The shell is now a real user process — the desktop just
        // forwards keystrokes and drains stdout each frame.
        // window_count is u8; widen before the multiply or `9 * 30 = 270`
        // overflows u8 arithmetic and Zig's runtime safety panics.
        const off: i32 = @intCast(@as(u32, wm.window_count) * 30);
        const nw: u32 = TERM_WIN_W;
        const nh: u32 = TERM_ROWS * FONT_H + TITLEBAR_H;
        if (createWindow("Terminal", 80 + off, 40 + off, nw, nh)) |ni| {
            setFocused(ni);
            spawnShellOnWindow(ni);
        }
        sound.open();
    } else {
        launchPath(sc.cmd);
    }
}

/// Start the ELF at `path` as an interactive app.
fn launchPath(path: []const u8) void {
    // Try the async load on an AP first.
    const smp = @import("../cpu/smp.zig");
    if (smp.cpu_count > 1) {
        if (smp.requestAppLoad(path)) {
            debug.klog("[launch] requestAppLoad accepted '{s}'\n", .{path});
            showNotification("Loading...");
        } else {
            // AP mid-flight on a previous load — can't fall back to a
            // BSP-side sync read (both paths share NVMe bounce_buf w/o
            // serialization). Queue instead so the click isn't lost;
            // launch_queue.drain in the main loop will submit it once
            // the AP goes idle.
            if (launch_queue.push(path)) {
                debug.klog("[launch] queued '{s}' (depth: {d})\n", .{ path, launch_queue.depth() });
                showNotification("Queued...");
            } else {
                debug.klog("[launch] queue full, dropped '{s}'\n", .{path});
                showNotification("Launch queue full");
            }
        }
    } else {
        // Single-core only — sync fallback is safe (no concurrent
        // reader to race against).
        if (@import("../fs/vfs.zig").loadFileFresh(path)) |fresh| {
            if (elf_loader.loadAndStart(fresh.buf, fresh.size, fresh.pages, fresh.inode, null)) |pid| {
                var nlen = path.len;
                if (nlen >= 4 and path[nlen - 4] == '.') nlen -= 4;
                process.setName(@intCast(pid), path[0..nlen]);
                process.getPCB(pid).priority = .interactive;
            }
        }
    }
    sound.open();
}

// Boot splash extracted to desktop/splash.zig — the long animation
// loop is unrelated to anything else here.
const splash = @import("desktop/splash.zig");

// --- Cursor ---

/// Software-cursor visibility gate. The SW cursor is stamped into the
/// framebuffer only when there's no HW cursor AND the focused app hasn't
/// requested cursor-hide (DOOM/Quake fullscreen call setCursorVisible(false)).
/// Mirrors the gate in renderFrame (search: `app_hides`) so the main-loop fast
/// paths can't drift from it and re-stamp a frozen cursor over a fullscreen
/// game. Erase sites stay gated on `!use_hw_cursor` alone so a cursor drawn
/// before the hide still gets cleaned up.
fn swCursorActive(use_hw_cursor: bool) bool {
    return !use_hw_cursor and !(slot_used[wm.focused] and windows[wm.focused].cursor_hidden_by_app);
}

var cursor_save_buf: [CURSOR_W * CURSOR_H]u32 = [_]u32{0} ** (CURSOR_W * CURSOR_H);

fn eraseCursor() void {
    // Restore from back buffer at old cursor position
    const cx: u32 = if (last_cursor_x < 0) 0 else @intCast(last_cursor_x);
    const cy: u32 = if (last_cursor_y < 0) 0 else @intCast(last_cursor_y);
    gfx.blitRectToScreen(cx, cy, CURSOR_W, CURSOR_H);
    // Flush erased region to the scanout (virtio rect / GOP blit; no-op on
    // a live framebuffer like BGA or GOP-direct).
    display.flushRect(cx, cy, CURSOR_W, CURSOR_H);
}

fn drawCursorOnScreen() void {
    const mx = mouse.x;
    const my = mouse.y;
    for (0..CURSOR_H) |row| {
        for (0..CURSOR_W) |col| {
            const pixel = cursor_sprite[row][col];
            if (pixel != 0) {
                const color: u32 = if (pixel == 1) 0x000000 else 0xFFFFFF;
                gfx.putPixelDirect(mx + @as(i32, @intCast(col)), my + @as(i32, @intCast(row)), color);
            }
        }
    }
    last_cursor_x = mx;
    last_cursor_y = my;
    // Flush cursor region (direct screen writes need an explicit flush on
    // flush-based scanouts — virtio resource or GOP blit).
    {
        const cx: u32 = if (mx < 0) 0 else @intCast(mx);
        const cy: u32 = if (my < 0) 0 else @intCast(my);
        display.flushRect(cx, cy, CURSOR_W, CURSOR_H);
    }
}

/// Draw cursor into back buffer (save pixels underneath first).
/// Call before blitToScreen so cursor is included in the blit — no flicker.
fn bakeCursorToBackBuffer() void {
    const mx = mouse.x;
    const my = mouse.y;
    for (0..CURSOR_H) |row| {
        for (0..CURSOR_W) |col| {
            const sx = mx + @as(i32, @intCast(col));
            const sy = my + @as(i32, @intCast(row));
            if (sx >= 0 and sy >= 0 and @as(u32, @intCast(sx)) < gfx.target_w and @as(u32, @intCast(sy)) < gfx.target_h) {
                const off = @as(u32, @intCast(sy)) * gfx.target_w + @as(u32, @intCast(sx));
                cursor_save_buf[row * CURSOR_W + col] = gfx.target[off];
                if (cursor_sprite[row][col] != 0) {
                    gfx.target[off] = if (cursor_sprite[row][col] == 1) 0x000000 else 0xFFFFFF;
                }
            }
        }
    }
    last_cursor_x = mx;
    last_cursor_y = my;
}

/// Restore back buffer pixels that were overwritten by bakeCursorToBackBuffer.
fn unbakeCursorFromBackBuffer() void {
    for (0..CURSOR_H) |row| {
        for (0..CURSOR_W) |col| {
            const sx = last_cursor_x + @as(i32, @intCast(col));
            const sy = last_cursor_y + @as(i32, @intCast(row));
            if (sx >= 0 and sy >= 0 and @as(u32, @intCast(sx)) < gfx.target_w and @as(u32, @intCast(sy)) < gfx.target_h) {
                const off = @as(u32, @intCast(sy)) * gfx.target_w + @as(u32, @intCast(sx));
                gfx.target[off] = cursor_save_buf[row * CURSOR_W + col];
            }
        }
    }
}

// --- Event handling ---

// --- Launcher ---

/// Act on what the launcher answered to a key or a click.
fn runLauncherResult(res: launcher.Result) void {
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

// --- Context menu ---

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

/// Publish mouse_move / mouse_button / mouse_wheel events to the focused
/// window's queue. Called once per frame before `handleMouseEvents` so
/// the app sees the same input the desktop is about to act on.
///
/// We intentionally publish even when the cursor is over a different
/// window — focus + queue ownership decide who gets events, not hover.
/// This matches the keyboard model and avoids the "mouse silently does
/// nothing while a different app's titlebar is hovered" UX trap.
/// Presses drained from the driver that the desktop hasn't acted on yet.
var press_backlog: [3]u8 = .{ 0, 0, 0 };
const PRESS_BACKLOG_MAX: u8 = 4;
/// Tick of each button's last edge shown to the desktop.
var edge_tick: [3]u64 = .{ 0, 0, 0 };
/// Ticks between two shown edges of one button. A click played back from
/// the counters is thus down long enough for an app that polls the button
/// level every 10 ms to see it.
const EDGE_GAP_TICKS: u64 = 3;

/// The button level the desktop acts on this frame: mouse.buttons, with
/// presses the level never showed played back from the driver's counters.
/// While presses are owed, each call flips the button (a release, then the
/// owed press), at most one edge per EDGE_GAP_TICKS; with nothing owed the
/// level stands.
///
/// The level is read before the counters are drained: a press landing
/// between the two is played back now and agrees with the level next
/// frame; the other order would show it twice.
fn frameButtons() u8 {
    const level = mouse.buttons;
    const now = process.tick_count;
    var btn: u8 = 0;
    inline for (0..3) |b| {
        const mask: u8 = @as(u8, 1) << b;
        const n = @atomicRmw(u8, &mouse.press_count[b], .Xchg, 0, .acq_rel);
        press_backlog[b] = @min(PRESS_BACKLOG_MAX, press_backlog[b] +| n);
        const was_down = (prev_buttons & mask) != 0;
        const level_down = (level & mask) != 0;
        var down = if (press_backlog[b] > 0) !was_down else level_down;
        if (down != was_down) {
            if (now -% edge_tick[b] < EDGE_GAP_TICKS) {
                // Too soon after the last edge: show it once the gap is over.
                down = was_down;
                wake.requestSelfWake(edge_tick[b] + EDGE_GAP_TICKS);
            } else {
                edge_tick[b] = now;
                if (down and press_backlog[b] > 0) press_backlog[b] -= 1;
            }
        }
        if (down) btn |= mask;
        // More edges are owed: come back for the next one.
        if (press_backlog[b] > 0 or down != level_down) wake.requestSelfWake(edge_tick[b] + EDGE_GAP_TICKS);
    }
    return btn;
}

fn pressReplayPending() bool {
    return mouse.pressPending() or (press_backlog[0] | press_backlog[1] | press_backlog[2]) != 0;
}

/// Buttons whose press went to the window `app_btns_win`: the ones pressed
/// over its content area. A press on the desktop, the dock, another window
/// or a titlebar is the desktop's own business; the focused app is told of
/// neither it nor its release.
pub var app_btns: u8 = 0;
pub var app_btns_win: u8 = 0xFF;

/// The window whose content area the cursor is over, as the stack stands
/// before the desktop acts on this frame's input: the one a press now
/// belongs to. A window that hid the cursor has grabbed the pointer and
/// takes every press.
fn pressTarget() ?u8 {
    // An open menu or launcher takes the press, whatever is under it.
    if (context_menu.active or launcher.active) return null;
    if (slot_used[wm.focused] and windows[wm.focused].cursor_hidden_by_app) return wm.focused;
    const idx = windowAt(mouse.x, mouse.y) orelse return null;
    if (isInTitlebar(idx, mouse.x, mouse.y)) return null;
    if (isOnResizeEdge(idx, mouse.x, mouse.y) != null) return null;
    return idx;
}

/// Publish this frame's mouse input to the focused window. `press_target`
/// is pressTarget() from before the desktop handled the frame: a press is
/// delivered only if the window it landed on is the focused one now, so a
/// click that focuses a window also reaches it, and one that closed the
/// window above doesn't fall through to the one beneath.
fn publishMouseToFocused(prev_btns: u8, cur_btns: u8, moved: bool, wheel: i32, press_target: ?u8) void {
    if (app_btns_win != wm.focused) {
        app_btns = 0;
        app_btns_win = wm.focused;
    }
    const owned_before = app_btns;
    app_btns &= cur_btns;
    if (press_target) |t| {
        if (t == wm.focused) app_btns |= cur_btns & ~prev_btns;
    }

    if (!slot_used[wm.focused]) return;
    const w = &windows[wm.focused];
    if (!w.visible or w.minimized) return;

    // Translate to window-local coordinates: x relative to window left,
    // y relative to content-area top (i.e. below the titlebar). Matches
    // `getMouseRelative` so apps that mix `pollEvent` with the legacy
    // `getMouse` syscall see consistent values.
    const rel_x: i32 = mouse.x - w.x;
    const rel_y: i32 = mouse.y - (w.y + @as(i32, TITLEBAR_H));
    const cur_x: u32 = @bitCast(rel_x);
    const cur_y: u32 = @bitCast(rel_y);

    if (moved) {
        w.events.push(.{
            .kind = @intFromEnum(EventKind.mouse_move),
            .a = cur_x,
            .b = cur_y,
            .c = app_btns,
        });
    }

    // Per-button transitions of the buttons the window owns. Three
    // buttons, low 3 bits.
    const changed: u8 = app_btns ^ owned_before;
    inline for ([_]u8{ 0, 1, 2 }) |btn_idx| {
        const mask: u8 = @as(u8, 1) << btn_idx;
        if ((changed & mask) != 0) {
            const pressed: u8 = if ((app_btns & mask) != 0) 1 else 0;
            const a: u32 =
                @as(u32, btn_idx) |
                (@as(u32, pressed) << 8) |
                (@as(u32, app_btns) << 16);
            w.events.push(.{
                .kind = @intFromEnum(EventKind.mouse_button),
                .a = a,
                .b = cur_x,
                .c = cur_y,
            });
        }
    }

    if (wheel != 0) {
        const delta_u32: u32 = @bitCast(wheel);
        w.events.push(.{
            .kind = @intFromEnum(EventKind.mouse_wheel),
            .a = delta_u32,
            .b = cur_x,
            .c = cur_y,
        });
    }
}

fn handleMouseEvents(btn: u8) DirtyKind {
    const mx = mouse.x;
    const my = mouse.y;
    const left_down = (btn & 1) != 0;
    const was_down = (prev_buttons & 1) != 0;
    const right_down = (btn & 2) != 0;
    const right_was = (prev_buttons & 2) != 0;
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
        prev_buttons = btn;
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
            prev_buttons = btn;
            return result;
        }
        if (right_down and !right_was) {
            context_menu.close();
            result = .region;
            // Fall through to open new menu below
        } else {
            prev_buttons = btn;
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

    prev_buttons = btn;
    return result;
}

// --- Dirty region helpers ---

fn blitWindowBounds(idx: u8) void {
    const w = &windows[idx];
    const bx: u32 = if (w.x < @as(i32, BORDER)) 0 else @intCast(w.x - @as(i32, BORDER));
    const by: u32 = if (w.y < @as(i32, BORDER)) 0 else @intCast(w.y - @as(i32, BORDER));
    // Include shadow tail (24 px right + down) plus borders. Without this,
    // partial flushes during drag leave shadow ghosts at the old position.
    gfx.blitRectToScreen(bx, by, w.width + BORDER * 2 + 26, w.height + BORDER * 2 + 26);
}

/// True when run() picked the GOP scanout as the desktop's display (real
/// hardware: no virtio, no BGA). Resolution is then immutable — GOP SetMode
/// is a boot service, gone after ExitBootServices — and the back-buffer
/// policy treats GUEST_FB as the compositing surface in blit mode.
var display_is_gop: bool = false;

fn changeResolution(new_w: u16, new_h: u16) void {
    const virtio_gpu = @import("../driver.zig").virtio_gpu;

    if (display_is_gop) {
        debug.klog("[desktop] resolution change unavailable on GOP scanout (SetMode died with boot services)\n", .{});
        return;
    }

    // Free old back buffer (only allocated in BGA mode — virtio-gpu shares
    // the resource backing). bb_pages == 0 signals the no-alloc path.
    if (bb_pages != 0) paging.freeBackBuffer(bb_pages);
    backbuf = null;

    if (virtio_gpu.active) {
        // Virtio-GPU mode change
        if (!virtio_gpu.changeMode(new_w, new_h)) {
            debug.klog("[desktop] virtio-gpu mode change failed\n", .{});
            return;
        }
        gfx.setScreen(virtio_gpu.framebuffer, virtio_gpu.width, virtio_gpu.height);
    } else {
        // BGA mode change
        _ = bga.init(new_w, new_h);
        gfx.setScreen(bga.framebuffer, bga.width, bga.height);
    }

    if (virtio_gpu.active) {
        backbuf = @as([*]volatile u32, @ptrCast(virtio_gpu.framebuffer));
        bb_pages = 0;
        gfx.useFramebuffer();
        debug.klog("[desktop] Resolution: {d}x{d} (direct-to-resource)\n", .{ gfx.screen_w, gfx.screen_h });
    } else {
        bb_pages = (gfx.screen_w * gfx.screen_h * 4 + 4095) / 4096;
        if (paging.allocBackBuffer(bb_pages)) |buf| {
            backbuf = buf;
            gfx.setTarget(buf, gfx.screen_w, gfx.screen_h);
            debug.klog("[desktop] Resolution: {d}x{d} ({d} pages)\n", .{ gfx.screen_w, gfx.screen_h, bb_pages });
        } else {
            gfx.useFramebuffer();
            debug.klog("[desktop] WARNING: no back buffer at new res\n", .{});
        }
    }

    // Update mouse bounds
    mouse.screen_w = @intCast(gfx.screen_w);
    mouse.screen_h = @intCast(gfx.screen_h);
    if (mouse.x >= mouse.screen_w) mouse.x = mouse.screen_w - 1;
    if (mouse.y >= mouse.screen_h) mouse.y = mouse.screen_h - 1;
}

// --- Main entry point ---

/// Kernel-task entry trampoline. process.createKernelTask plants this
/// function's address on the new task's kstack as the synthetic switchTo
/// ret target. switchTo's `ret` lands here; we call run() and trap if it
/// ever returns (it shouldn't — desktop loops forever).
pub fn taskEntry() callconv(.c) noreturn {
    // Phase 3 cutover: now that enterFirstTask has switched the BSP off
    // the boot stack onto desktop's heap-allocated kstack (high-VA in the
    // physmap window), retire the legacy PML4[0] low identity. Every
    // kernel-side access from this point on must go through the physmap
    // (PHYSMAP_BASE + phys, via `paging.physToVirt`) or the kernel image
    // window at -2 GB. The migration was completed in src/mm/heap.zig
    // (heap moved to the physmap), src/driver/gpu/vga.zig (VGA buffer), and the
    // driver/walker sweep done in Phase 2. Per-process address spaces own
    // their own PML4[0] independently, so user processes are unaffected.
    @import("../mm/paging.zig").dropLowIdentity();
    // The identity window was the last user-accessible memory the kernel
    // itself reached into; with it gone SMAP can go on. It is the last
    // entry of the BSP's per-CPU list; this also checks none was skipped.
    @import("../cpu/cpu_state.zig").completeBoot();
    // enterFirstTask cli'd before swapping us onto desktop's kstack —
    // re-enable IRQs now that RSP is on the high-VA kstack and the
    // legacy low identity is gone.
    asm volatile ("sti");
    // Now that we're a scheduled task with a current_pid, it's safe to
    // flip NVMe controllers into async I/O mode. Pre-enterFirstTask
    // reads (ext2 superblock + symbol/line table loads in main.zig)
    // used the sync polled path; post-this-line reads (every userspace
    // file load via vfs.loadFileFresh) go through submit-and-yield with
    // Q_DEPTH=16-way parallelism.
    // Boot is over — we're in steady-state preemptive multitasking now.
    // Flip the kernel-wide phase flag (paging's boot-only audit consults it).
    @import("../boot/boot_phase.zig").markComplete();
    @import("../driver.zig").nvme.enableAsync();
    run();
    asm volatile ("ud2");
    unreachable;
}

pub fn run() void {
    @import("../cpu/smp.zig").assertBSP("desktop.run");
    if (@import("../cpu/smp.zig").currentPid()) |p| desktop_pid = @intCast(p);
    debug.klog("[desktop] Starting graphical desktop...\n", .{});

    // Register the back-buffer reclaim callback with PMM. When an
    // allocation fails (typically photo / image decode demand-paging
    // into a region bigger than free PMM), handleUserPageFault calls
    // pmm.tryReclaim → us → free the back-buffer slots of every GUI
    // window. Apps lose tear-free presents until their next sysPresent
    // call (lazy realloc), but the system avoids OOM-killing the
    // user's working process.
    pmm.registerReclaim(reclaimBackBuffers);

    // Wipe the VGA text framebuffer to black before the mode switch.
    // Without this, the host display backend mid-transitions the legacy
    // text mode into virtio-gpu scanout — leftover boot-log glyphs from
    // the 80x25 buffer get partially upscaled / re-rendered against the
    // incoming graphical FB and look like colliding text. Better to flash
    // black for a few frames than to show garbled chars.
    // Drop the boot_screen + early framebuffer (BGA) before virtio-gpu
    // mode-set takes over. boot_screen.disable() unhooks vga.redirect_fn
    // so any final klog spew lands wherever it always did; the early_fb
    // handoff turns BGA off cleanly so the virtio mode-set sees the
    // device in a known state. UEFI's GOP framebuffer is replaced by
    // virtio_gpu.framebuffer below — no explicit teardown needed.
    @import("boot_screen.zig").disable();
    @import("early_fb.zig").release();
    @import("../driver.zig").vga.bg = .Black;
    @import("../driver.zig").vga.fg = .Black;
    @import("../driver.zig").vga.clear();
    @import("../driver.zig").vga.available = false;

    const virtio_gpu = @import("../driver.zig").virtio_gpu;
    const gop = @import("../driver.zig").gop_fb;

    // Device selection (virtio-gpu → BGA → GOP) lives in ui/scanout.zig so the
    // installer boots onto the same display the desktop would have picked.
    const so = @import("scanout.zig").bringUp() orelse {
        vga.fg = .LightRed;
        vga.print("No display available!\n", .{});
        vga.fg = .LightGray;
        return;
    };
    const disp_w = so.width;
    const disp_h = so.height;
    display_is_gop = (so.kind == .gop);

    // Back-buffer policy:
    //   * virtio-gpu mode: composite directly into the device resource backing.
    //     The host doesn't see writes until TRANSFER_TO_HOST_2D + RESOURCE_FLUSH,
    //     so the backing IS already a back buffer — no separate alloc, no SSE
    //     memcpy of the full frame on every redraw. Saves ~8MB per .full /
    //     .drag re-render at 1920×1080.
    //   * BGA mode: live framebuffer, host scans out continuously, so we still
    //     need a separate back buffer to avoid tearing.
    // Mode 9 (GPU compositor) forces back-buffer mode even on virtio-gpu
    // so the compositor can sample the desktop's fully rendered scene
    // (windows + chrome + menubar + dock + cursor) without racing the
    // CPU compositor's writes against the GPU compositor's screen-FB
    // writes. Together with `gfx.skip_blit_to_screen = true` below, this
    // makes the compositor the sole writer of virtio-gpu's framebuffer.
    const force_back_buffer = (@import("../boot/boot_info.zig").boot_mode == 9);
    if (virtio_gpu.active and !force_back_buffer) {
        backbuf = @as([*]volatile u32, @ptrCast(virtio_gpu.framebuffer));
        bb_pages = 0;
        gfx.useFramebuffer(); // target := screen (= virtio-gpu resource backing)
        debug.klog("[desktop] Compositor: direct-to-resource (no back buffer)\n", .{});
    } else if (display_is_gop and !gop.direct and !force_back_buffer) {
        // GOP blit mode: GUEST_FB only reaches the panel on flush — it IS a
        // back buffer already, the same shape as virtio's direct-to-resource.
        backbuf = @as([*]volatile u32, @ptrCast(gop.framebuffer));
        bb_pages = 0;
        gfx.useFramebuffer(); // target := screen (= GUEST_FB blit source)
        debug.klog("[desktop] Compositor: direct-to-GUEST_FB (no extra back buffer)\n", .{});
    } else {
        bb_pages = (disp_w * disp_h * 4 + 4095) / 4096;
        if (paging.allocBackBuffer(bb_pages)) |buf| {
            backbuf = buf;
            gfx.setTarget(buf, disp_w, disp_h);
            debug.klog("[desktop] Back buffer: {d} pages (mode={d})\n", .{ bb_pages, @import("../boot/boot_info.zig").boot_mode });
        } else {
            gfx.useFramebuffer();
            debug.klog("[desktop] WARNING: no back buffer\n", .{});
        }
    }
    if (force_back_buffer) {
        gfx.skip_blit_to_screen = true;
        @import("../driver.zig").virtio_gpu.skip_external_flush = true;
        debug.klog("[desktop] Mode 9: blit-to-screen + flush suppressed; GPU compositor owns screen FB\n", .{});
    }

    mouse.screen_w = @intCast(disp_w);
    mouse.screen_h = @intCast(disp_h);
    if (!xhci.hasUsbMouse()) {
        if (!mouse.init()) {
            debug.klog("[desktop] PS/2 mouse not detected — desktop runs without pointer\n", .{});
        }
        keyboard.reEnable();
    } else {
        debug.klog("[desktop] USB mouse active\n", .{});
    }

    // All hardware that auto-binds via pci.bindDevice has now had its init
    // attempt. Surface anything we ignored — typically a NIC variant whose
    // ID we don't match, an unfamiliar AHCI vendor, etc. On QEMU this should
    // be silent; on real HW it's the first place to look when a device
    // doesn't work.
    @import("../driver.zig").pci.logUnbound();

    // Spawn wallpaper.elf as a one-shot — reads /etc/zigos.conf, decodes
    // the configured image via stb_image, pushes pixels to the kernel via
    // sysSetWallpaper, exits. If no wallpaper is configured (or the file
    // is missing), it bails silently and the gradient stays. Fire-and-
    // forget: we don't await it so a slow decode doesn't block boot.
    if (@import("../fs/vfs.zig").loadFileFresh("wallpaper.elf")) |fresh| {
        if (elf_loader.loadAndStart(fresh.buf, fresh.size, fresh.pages, fresh.inode, null)) |wpid| {
            @atomicStore(u8, &client.wallpaper_helper, @intCast(wpid), .monotonic);
            process.setName(@intCast(wpid), "wallpaper");
            debug.klog("[desktop] wallpaper.elf spawned pid={d}\n", .{wpid});
        }
    }

    // Reset window/z-stack/slot bookkeeping (alias `wm.window_count` follows).
    wm.z_count = 0;
    wm.window_count = 0;
    @memset(slot_used, false);
    setFocused(0);
    dragging = false;
    prev_buttons = 0;
    // Clicks made before the desktop existed are not for it.
    for (&mouse.press_count) |*c| _ = @atomicRmw(u8, c, .Xchg, 0, .monotonic);
    press_backlog = .{ 0, 0, 0 };

    // Apply persisted UI config from /etc/zigos.conf (theme, dock, etc.).
    // Done before splash so the splash colors / theme reflect the user's
    // saved preference rather than the compile-time defaults.
    conf.load();

    // Boot splash
    splash.show(backbuf != null);

    const win_w: u32 = TERM_WIN_W;
    const win_h: u32 = TERM_ROWS * FONT_H + TITLEBAR_H;
    const win_x: i32 = @intCast((disp_w - win_w) / 2);
    const win_y: i32 = @intCast(MENUBAR_H + (disp_h - MENUBAR_H - TASKBAR_H - win_h) / 2);

    const initial_term_idx = createWindow("Terminal", win_x, win_y, win_w, win_h);
    if (initial_term_idx) |idx| setFocused(idx);

    // (Idle process is now created earlier — in process.enterFirstTask,
    // before this kernel task itself was switched to. See task #235.)

    // Attach a shell to the initial Terminal.
    if (initial_term_idx) |idx| spawnShellOnWindow(idx);

    // Auto-launch vulkan cube disabled (SHM BAR not available under all boot modes)
    // {
    //     const staging: [*]align(4) u8 = @ptrFromInt(0x300000);
    //     if (@import("../fs/vfs.zig").loadFile("vulkan_cube.elf", staging)) |file_size| {
    //         if (elf_loader.loadAndStart(staging, file_size)) |pid| {
    //             process.setName(@intCast(pid), "vk_cube");
    //             debug.klog("[desktop] Auto-launched vulkan_cube PID={d}\n", .{pid});
    //         }
    //     }
    // }

    // Initial render
    const use_hw_cursor = @import("../driver.zig").virtio_gpu.hw_cursor_active;

    renderScene();
    if (backbuf != null) {
        if (!use_hw_cursor) bakeCursorToBackBuffer();
        gfx.blitToScreen();
        if (!use_hw_cursor) unbakeCursorFromBackBuffer();
    }
    if (@import("../driver.zig").virtio_gpu.active) @import("../driver.zig").virtio_gpu.flush();

    active = true;

    // Mode 9: spawn the GPU compositor as a side-by-side kernel task. It
    // samples a window's published gui_fb back-buffer as a Vulkan texture
    // each frame and renders effect-warped output into a corner rect of
    // the desktop. Lower priority than desktop so it never preempts the
    // CPU compositor's blit-to-screen work.
    if (@import("../boot/boot_info.zig").boot_mode == 9) {
        const compositor = @import("gpu_compositor.zig");
        if (process.createKernelTask(@intFromPtr(&compositor.taskEntry), "gpu_comp", 0, .normal, 32 * 1024)) |pid| {
            debug.klog("[desktop] spawned GPU compositor task PID={d}\n", .{pid});
        } else {
            debug.klog("[desktop] failed to spawn GPU compositor\n", .{});
        }
    }

    while (true) {
        frame_count +%= 1;
        // Inject typematic repeats (held keys past the initial delay) into
        // the keyboard ring before we read from it. Cheap: returns immediately
        // unless a key is actually due for repeat.
        keyboard.pollRepeat(process.tick_count);
        // Reap stale zombies — internally rate-limited to once every 5 s,
        // so this is essentially free on every other call. Picks up
        // zombies whose parent never called waitpid (most often: shell
        // exec'd a child that exited but the shell got distracted).
        process.maybeReapZombies();
        // Yield to Ring 3 scheduler — processes run preemptively until
        // the timer decides the desktop needs attention (input, periodic
        // render). When NOTHING is due, parkOrYield blocks this task
        // instead, letting the BSP reach its idle PCB (hlt + tickless
        // stretch) — see the parking block comment near `parked`.
        last_desktop_tick = process.tick_count;
        parkOrYield();
        // Drain both wake channels now that this iteration is running, not
        // before the park: the park needs the self-wake the last iteration
        // asked for (the next animation or toast frame) as its deadline, and
        // a wake requested during that iteration must keep it from parking.
        // Requests made from here on re-arm for the next iteration.
        wake.consume();
        const ftrace = @import("../debug/ftrace.zig");
        ftrace.mark(.desk_wake, 0);
        // Mode 9: the GPU compositor reads the backbuf (or draws from it in
        // place) between our iterations, never during one.
        const gpu_comp = @import("gpu_compositor.zig");
        const source_wait_t0 = @import("../debug/perf.zig").rdtsc();
        const source_held = gpu_comp.beginDraw();
        defer if (source_held) gpu_comp.endDraw();
        frameperf.sourceWaited(@import("../debug/perf.zig").rdtsc() -% source_wait_t0);
        ftrace.mark(.desk_draw, 0);
        // Frame clock starts AFTER parkOrYield returns and the compositor
        // lets us in — parked/yielded time belongs to the scheduler, not to
        // this frame.
        frameperf.frameBegin();
        if (source_held) {
            if (gpu_comp.takeOfferedBackBuffer()) |nb| adoptBackBuffer(nb);
        }

        // Apply config changes from settings app
        if (config_changed) {
            config_changed = false;
            mouse.speed = conf.mouse_speed;
            if (conf.resolution == 1 and gfx.screen_w != 1920) {
                changeResolution(1920, 1080);
            } else if (conf.resolution == 0 and gfx.screen_w != 1280) {
                changeResolution(1280, 720);
            }
            showNotification("Settings applied!");
        }

        // Toast: advance to this tick. A step moves the pill; renderRegions
        // repaints its old and new rects. It asks to be woken for the next
        // slide step, or at the end of the hold.
        const toast_stepped = toast.tick(process.tick_count);
        if (toast.isActive()) wake.requestSelfWake(toast.nextWake(process.tick_count));

        // Reset mouse transfer ring if watchdog flagged it (must run outside IRQ)
        if (xhci.mouse_needs_reset) {
            xhci.resetMouseRing();
        }

        var dirty: DirtyKind = if (dirty_rects_mod.force_full_kind) .full else .none;
        // `force_full_kind` semantically means "the previous frame painted
        // something that won't be tracked by this frame's renderScene"
        // (animation completion, menu close, resolution change, etc.).
        // Mark the rect tracker full so the .full path falls back to full
        // blit instead of partial — partial would miss pixels where the
        // disappearing element used to live (closing-window halo, etc.).
        if (dirty_rects_mod.force_full_kind) markDirtyFull();
        dirty_rects_mod.force_full_kind = false;
        if (toast_stepped) wantRegion(&dirty);
        // The clock or a CPU/MEM bar moved: repaint the menubar.
        if (menubar.stale()) {
            seedRegion(0, 0, @intCast(gfx.screen_w), @as(i32, MENUBAR_H));
            wantRegion(&dirty);
        }

        // Cursor blink edge: when tick_count crosses a blink half-period
        // boundary and the focused window is a terminal, mark dirty so the
        // cursor cell repaints. Driven by ticks (real time) rather than
        // frame_count so the blink rate is independent of how often the
        // desktop loop wakes (~12.5Hz idle vs higher when busy).
        if (slot_used[wm.focused] and windows[wm.focused].term != null and !windows[wm.focused].minimized) {
            const curr_phase = process.tick_count / CURSOR_BLINK_HALF_TICKS;
            if (curr_phase != last_blink_phase) {
                last_blink_phase = curr_phase;
                wantTextRow(&dirty);
            }
            // Self-wake at the start of the next half-period so the blink
            // toggle fires on time even with no other compositor activity.
            const next_phase_tick = (curr_phase + 1) * CURSOR_BLINK_HALF_TICKS;
            wake.requestSelfWake(next_phase_tick);
        }

        // Bell flash: each terminal with a non-zero bell_phase counts down
        // one frame; while active, repaint the window so the red border
        // re-renders.
        var any_bell_active = false;
        for (z_stack[0..wm.z_count]) |wi| {
            if (windows[wi].term) |tt| {
                if (tt.bell_phase > 0) {
                    tt.bell_phase -= 1;
                    seedWindow(wi);
                    wantRegion(&dirty);
                    if (tt.bell_phase > 0) any_bell_active = true;
                }
            }
        }
        // Bell needs to count down on subsequent ticks even with no other
        // wake source. Pace at ~50 Hz (every 2 ticks) — the flash totals
        // only BELL_FLASH_FRAMES so this drains within ~10 wakeups.
        if (any_bell_active) wake.requestSelfWake(process.tick_count + 2);

        var cursor_moved = false;

        // Keyboard — route to focused window
        // When a GUI app is focused, leave keys in the buffer for the app's readChar
        // Global keyboard intercepts (work regardless of focused window type).
        // F-keys live in a separate desktop-only ring so a fullscreen GUI app
        // (DOOM) can't drain them in its readChar polling loop before this
        // intercept runs.
        if (keyboard.peekGlobal()) |pk| {
            if (pk == 0x99) { // F10 — toggle fullscreen
                _ = keyboard.popGlobal();
                if (slot_used[wm.focused] and windows[wm.focused].visible) {
                    toggleFullscreen(wm.focused);
                    dirty = .full;
                }
            } else if (pk == keyboard.KEY_SIGINT) {
                // Ctrl+C — post SIGINT to the focused window's process. Default
                // action terminates; apps that want to handle (shell forwarding
                // to a child, editor cancelling a search, etc.) install a
                // sigaction(SIGINT, ...) handler.
                _ = keyboard.popGlobal();
                if (slot_used[wm.focused] and windows[wm.focused].visible) {
                    // Terminal windows use shell_pid; GUI windows use owner_pid.
                    // Reading the wrong one earlier silently dropped Ctrl+C in
                    // every terminal because owner_pid stays 0xFF for them.
                    const fw = &windows[wm.focused];
                    const target: u8 = if (fw.term != null) fw.shell_pid else fw.owner_pid;
                    if (target != 0xFF) _ = @import("../proc/signals.zig").send(target, @import("../proc/signals.zig").SIGINT);
                }
            } else {
                // Drain unrecognized F-keys so the ring doesn't fill.
                _ = keyboard.popGlobal();
            }
        }
        if (keyboard.alt_held) {
            if (keyboard.peek()) |pk| {
                if (pk == 0x09) { // Alt+Tab
                    _ = keyboard.pop();
                    cycleFocus();
                    dirty = .full;
                }
            }
        }
        // Ctrl+Space or Alt+Space opens the launcher; open, it takes every
        // key until it closes.
        if (!launcher.active and (keyboard.ctrl_held or keyboard.alt_held)) {
            if (keyboard.peek()) |pk| {
                if (pk == ' ') {
                    _ = keyboard.pop();
                    context_menu.close();
                    launcher.open();
                    wantRegion(&dirty);
                }
            }
        }
        while (launcher.active) {
            const ch = keyboard.pop() orelse break;
            const res = launcher.key(ch);
            switch (res) {
                .none => {},
                // The selection or the query changed inside the same rect.
                .changed => {
                    if (launcher.rect()) |r| seedRect(r);
                    wantRegion(&dirty);
                },
                .closed => wantRegion(&dirty),
                .launch => dirty = .full,
            }
            runLauncherResult(res);
        }

        // Desktop is the sole drainer of `keyboard.buffer`. For every
        // popped key:
        //   - publish an event into the focused window's events queue
        //     (consumed by app via `sysPollEvent` / legacy `sysRead`);
        //   - if focused window is a terminal, also run the existing
        //     handleKeyboard path that writes the char into kb_pipe so
        //     the user-space shell keeps reading from fd 0 unchanged.
        // No focus → drop keystrokes silently. (Used to be: drop for
        // GUI focus, terminal-focus path drains via legacy.)
        const focus_ok = slot_used[wm.focused] and windows[wm.focused].visible and !windows[wm.focused].minimized;
        // DBG: when focus check fails AND there are pending keys, log so
        // we know chars are being dropped at the desktop drain. Rate-limit
        // to once per 100 ticks.
        if (!focus_ok and keyboard.hasData()) {
            dbg_focus_drop_count +%= 1;
            if (process.tick_count -% dbg_last_focus_drop_log >= 100) {
                dbg_last_focus_drop_log = process.tick_count;
                debug.klog("[kbd-drop] focus invalid (focused={d} slot_used={any} visible={any} minimized={any}) — drop_count={d}\n", .{
                    wm.focused,
                    slot_used[wm.focused],
                    if (slot_used[wm.focused]) windows[wm.focused].visible else false,
                    if (slot_used[wm.focused]) windows[wm.focused].minimized else false,
                    dbg_focus_drop_count,
                });
            }
        }
        if (focus_ok) {
            const w = &windows[wm.focused];
            const is_terminal = w.term != null;
            while (keyboard.pop()) |ch| {
                // Publish the event. Special key codes (KEY_UP, KEY_F1, ...)
                // are 0x80..0x9F per keyboard.zig; everything else is a
                // post-translation char.
                const kind: u8 = if (ch >= 0x80 and ch <= 0x9F)
                    @intFromEnum(EventKind.key_special)
                else
                    @intFromEnum(EventKind.key_char);
                const mods: u32 =
                    (@as(u32, @intFromBool(keyboard.shift_held)) << 0) |
                    (@as(u32, @intFromBool(keyboard.ctrl_held)) << 1) |
                    (@as(u32, @intFromBool(keyboard.alt_held)) << 2) |
                    (@as(u32, @intFromBool(keyboard.caps_lock)) << 3);
                const queued = w.events.tryPush(.{ .kind = kind, .a = ch, .b = mods });
                // Wake any io_uring OP_POLL waiters on a console fd. We
                // can't filter by which pid owns the focused window here
                // (fdpoll's wake walk does pollMaskConsole, which re-runs
                // the focus/visibility/owner check), so the broadcast
                // (.console, 0xFFFF) lets the matcher do its job.
                if (queued) {
                    @import("../ipc/fdpoll.zig").wakePollers(.console, 0xFFFF);
                }
                if (!queued) {
                    // Queue full, event dropped.
                    dbg_event_queue_full +%= 1;
                    if (process.tick_count -% dbg_last_qfull_log >= 100) {
                        dbg_last_qfull_log = process.tick_count;
                        const target_pid = if (is_terminal) w.shell_pid else w.owner_pid;
                        var t_state: u8 = 0xFF;
                        var t_assigned: u8 = 0xFF;
                        var t_vruntime: u64 = 0;
                        var t_wait: u8 = 0xFF;
                        if (target_pid < process.MAX_PROCS) {
                            const tp = &process.procs[target_pid];
                            t_state = @intFromEnum(tp.state);
                            t_assigned = tp.assigned_cpu;
                            t_vruntime = tp.vruntime;
                            t_wait = @intFromEnum(tp.wait_kind);
                        }
                        debug.klog("[kbd-drop] events FULL pid={d} term={any} drops={d} kb_drop={d} state={d} cpu={d} wait={d} vruntime={d}\n", .{
                            target_pid,
                            is_terminal,
                            dbg_event_queue_full,
                            @atomicLoad(u64, &keyboard.dbg_push_dropped, .monotonic),
                            t_state,
                            t_assigned,
                            t_wait,
                            t_vruntime,
                        });
                        // Per-CPU rq snapshot — see if shell is even in the rq
                        // and if any band has a stuck-huge floor (would explain
                        // CFS picker passing it over every time).
                        const smp_mod = @import("../cpu/smp.zig");
                        var ci: u8 = 0;
                        while (ci < smp_mod.MAX_CPUS) : (ci += 1) {
                            if (!smp_mod.cpus[ci].alive) continue;
                            const rq = &smp_mod.cpus[ci].runqueue;
                            debug.klog("[kbd-drop]  cpu{d}: nr_run={d} (i={d} n={d} bg={d}) min_vr i={d} n={d} bg={d} sched={d}\n", .{
                                ci,
                                rq.nr_runnable,
                                rq.interactive.count, rq.normal.count, rq.background.count,
                                rq.min_vruntime[2], rq.min_vruntime[1], rq.min_vruntime[0],
                                @atomicLoad(u64, &smp_mod.cpus[ci].schedule_count, .monotonic),
                            });
                        }
                    }
                }

                if (is_terminal) {
                    // ESC: a Linux program's key; our own shell has no use for it.
                    if (ch == 0x1B and !@import("../tty/tty.zig").hasLinuxProgram(w.tty)) continue;
                    if (ch == 0x14) { // Ctrl+T: spawn new terminal
                        // window_count is u8; widen before the multiply or `9 * 30 = 270`
        // overflows u8 arithmetic and Zig's runtime safety panics.
        const off: i32 = @intCast(@as(u32, wm.window_count) * 30);
                        const nw: u32 = TERM_WIN_W;
                        const nh: u32 = TERM_ROWS * FONT_H + TITLEBAR_H;
                        if (createWindow("Terminal", 80 + off, 40 + off, nw, nh)) |ni| {
                            setFocused(ni);
                            termPrompt(&windows[ni]);
                            dirty = .full;
                        }
                    } else {
                        const needs_full = handleKeyboard(w, ch);
                        if (needs_full) dirty = .full else wantTextRow(&dirty);
                    }
                }
            }
        }
        // Mouse
        if (mouse.moved) {
            cursor_moved = true;
            // Don't clear mouse.moved here — publishMouseToFocused below
            // reads it. handleMouseEvents clears it implicitly by acting
            // on cur position. Reset after we've published.
        }
        if (cursor_moved or mouse.buttons != prev_buttons or pressReplayPending() or mouse.wheel != 0) {
            const btn = frameButtons();
            const prev = prev_buttons;
            const moved = mouse.moved;
            mouse.moved = false;
            // handleMouseEvents drains the wheel; the focused app gets the
            // same notches.
            const wheel = mouse.wheel;
            const press_target = pressTarget();
            const mr = handleMouseEvents(btn);
            // After the desktop has acted: focus has settled, so the click
            // that focused a window reaches that window.
            publishMouseToFocused(prev, btn, moved, wheel, press_target);
            switch (mr) {
                .full => dirty = .full,
                .drag => switch (dirty) {
                    .full => {},
                    // A pending row (keypress / cursor blink) rides along with
                    // the drag's regions.
                    .text_only => {
                        damage.text_row_pending = true;
                        dirty = .drag;
                    },
                    else => dirty = .drag,
                },
                .region => wantRegion(&dirty),
                else => {},
            }
            if (cursor_moved and dirty == .none) dirty = .cursor_only;
        }

        // Dock hover tracking for tooltips. A tooltip that appears, moves or
        // vanishes is repainted by renderRegions.
        if (cursor_moved) switch (dock.updateHover(mouse.x, mouse.y, !context_menu.active)) {
            .none => {},
            .tooltip => wantRegion(&dirty),
            .item => {
                // The hover highlight is painted in the pill.
                if (dock.pillRect()) |r| seedRect(r);
                wantRegion(&dirty);
            },
        };

        // Drain stdout pipes for every shell-attached terminal window. The
        // shell process writes via libc.print → fwrite(1) → pipe.write into
        // out_pipe; we pull bytes back here non-blocking and feed them into
        // the window's text buffer. This is the desktop's side of the
        // "TTY-as-two-pipes" architecture: no kernel TTY primitive, just a
        // pair of generic byte streams plus this drain step.
        //
        // Drained bytes can change any rows (`ls`'s lines, a scroll, a
        // program addressing the cursor), so the window is only marked here;
        // the step below repaints whichever rows differ from what they show.
        //
        // A program that prints without pause (`yes`, a long build log)
        // refills the pipe as fast as it is drained here, so each window
        // gets a time slice per iteration: the frame is drawn and the
        // keyboard read in between, and the writer waits on the full pipe.
        {
            const pipe = @import("../proc/pipe.zig");
            const rdtsc = @import("../debug/perf.zig").rdtsc;
            const slice_cyc = @import("../irq/apic.zig").tscPerQuantumSane() * DRAIN_SLICE_MS / 10;
            var drain_buf: [256]u8 = undefined;
            var more = false;
            for (z_stack[0..wm.z_count]) |wi| {
                const w = &windows[wi];
                if (w.out_pipe == 0xFF) continue;
                const t0 = rdtsc();
                var taken: usize = 0;
                while (true) {
                    const got = pipe.tryRead(w.out_pipe, &drain_buf);
                    if (got == 0) break;
                    for (drain_buf[0..got]) |c| putCharOnWindow(w, c);
                    if (w.term) |t| t.rows_stale = true;
                    if (got < drain_buf.len) break;
                    taken += got;
                    // No calibrated clock yet: a byte count stands in.
                    const spent = if (slice_cyc != 0) rdtsc() -% t0 >= slice_cyc else taken >= DRAIN_SLICE_BYTES;
                    if (spent) {
                        more = true;
                        break;
                    }
                }
            }
            if (more) wake.requestWake();
        }

        // Terminals that got output: repaint the rows it changed. Where
        // rows cannot be painted on their own — something lies over the
        // window, it shows its scrollback, or this frame repaints regions
        // anyway — the whole window is repainted as a region.
        //
        // A keystroke or a blink edge in the focused terminal (.text_only)
        // goes the same way: its rows are compared with what they show, so
        // a key whose echo has not come yet draws nothing and presents no
        // frame of its own.
        {
            // The focused terminal is looked at for its text row alone.
            var row_only: u8 = 0xFF;
            if (dirty == .text_only and slot_used[wm.focused]) {
                if (windows[wm.focused].term) |t| {
                    if (!t.rows_stale) row_only = wm.focused;
                    t.rows_stale = true;
                }
            }
            const rows_alone = dirty == .none or dirty == .cursor_only or dirty == .gui_only or dirty == .text_only;
            var rows_painted = false;
            var text_row_done = false;
            for (z_stack[0..wm.z_count], 0..) |wi, z_pos| {
                const t = windows[wi].term orelse continue;
                if (!t.rows_stale) continue;
                t.rows_stale = false;
                if (rows_alone and termRowsPaintable(z_pos, wi)) {
                    if (repaintStaleRows(wi)) rows_painted = true;
                    if (wi == wm.focused) text_row_done = true;
                } else if (row_only == wi) {
                    // Not paintable on its own: the text-row path draws it.
                } else {
                    seedWindow(wi);
                    wantRegion(&dirty);
                }
            }
            if (rows_painted and dirty == .text_only and !text_row_done) {
                // The text row is still owed and a rows-only frame would
                // skip it.
                seedWindow(wm.focused);
                wantRegion(&dirty);
            } else if (rows_painted and (dirty == .none or dirty == .cursor_only or dirty == .text_only)) {
                dirty = .gui_only;
            } else if (dirty == .text_only and text_row_done) {
                // Nothing differed. A software pointer may still have moved.
                dirty = .cursor_only;
            }
        }

        // Check for async app loads completing on AP
        {
            const smp_mod = @import("../cpu/smp.zig");
            if (smp_mod.pollAppLoad()) |_| {
                dirty = .full;
                markDirtyFull();
            }
            // Try to submit a queued launch (no-op if AP still busy).
            launch_queue.drain();
        }

        // Advance window animations
        if (hasActiveAnimations()) {
            advanceAnimations(finishClose);
            dirty = .full;
            markDirtyFull();
            // Animations want a follow-up frame as long as any is still
            // ticking. Pace at 1 tick (~100 Hz upper bound; on 100 Hz
            // timer that's "every frame"). Animation totals are short
            // (~6 frames) so this drains in <100 ms.
            if (hasActiveAnimations()) wake.requestSelfWake(process.tick_count + 1);
        }

        // Auto-refresh: a GUI window whose app never calls sysPresent is read
        // from the app's live framebuffer, so it is re-composited on a
        // timer, at most every 5 ticks (~20 Hz) however often this loop
        // wakes. A window that presents is read from the snapshot
        // sysPresent took and is marked by it (markGuiPresent): nothing to
        // pick up here.
        gui_windows_active = hasGuiWindows();
        gui_autorefresh_active = false;
        if (gui_windows_active) {
            const AUTO_REFRESH_INTERVAL_TICKS: u64 = 5;
            for (z_stack[0..wm.z_count]) |gi| {
                const w = &windows[gi];
                if (w.gui_fb == null or !w.visible or w.has_presented) continue;
                gui_autorefresh_active = true;
                if (process.tick_count -% w.last_auto_refresh_tick >= AUTO_REFRESH_INTERVAL_TICKS) {
                    w.last_auto_refresh_tick = process.tick_count;
                    const h = guiContentHash(w);
                    if (h != w.auto_refresh_hash) {
                        w.auto_refresh_hash = h;
                        w.auto_refresh_settle = true;
                        w.gui_present_pending = true;
                    } else if (w.auto_refresh_settle) {
                        w.auto_refresh_settle = false;
                        w.gui_present_pending = true;
                    }
                }
            }
        }

        // Re-composite GUI windows that need it
        if (gui_windows_active) {
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
                    if (backbuf != null) {
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
        }

        // Wake the focused window's owner out of sysWaitEvent while it has
        // events to read. Once per pass rather than at each push: covers
        // every push site and a window that just became readable.
        if (slot_used[wm.focused]) {
            const fw = &windows[wm.focused];
            if (fw.visible and !fw.minimized and !fw.events.isEmpty()) event_wait.notify(fw.owner_pid);
        }

        // Hardware cursor: just move, no framebuffer interaction
        if (use_hw_cursor) {
            const vgpu_cur = @import("../driver.zig").virtio_gpu;
            // App override (setCursorVisible(false) on the focused window) wins
            // over auto-hide heuristics — keeps DOOM-style FPS apps from
            // re-showing the cursor on every mouse move.
            if (slot_used[wm.focused]) {
                const fw = &windows[wm.focused];
                if (fw.cursor_hidden_by_app) {
                    // Explicit app override — Doom etc. set this and they
                    // want the cursor gone regardless of window state.
                    if (!vgpu_cur.cursor_hidden) vgpu_cur.hideCursor();
                } else if (fw.gui_fb == null and vgpu_cur.cursor_hidden) {
                    vgpu_cur.showCursor();
                    vgpu_cur.moveCursor(mouse.x, mouse.y);
                } else if (cursor_moved) {
                    vgpu_cur.moveCursor(mouse.x, mouse.y);
                }
            } else if (cursor_moved) {
                vgpu_cur.moveCursor(mouse.x, mouse.y);
            }
        }

        if ((dirty == .gui_only or dirty == .text_only) and partialHitsOverlay(dirty)) wantRegion(&dirty);

        // Render based on what changed
        frameperf.prepDone();
        if (backbuf != null) {
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
                        @import("gpu_compositor.zig").requestRenderFromDirty();
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
                    @import("gpu_compositor.zig").requestRenderFromDirty();
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
                            @import("gpu_compositor.zig").requestRenderRect(cwx, uy, cw.width, FONT_H);
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
                        @import("gpu_compositor.zig").requestRenderRect(0, wy, gfx.screen_w, cw.height + TITLEBAR_H + 8);
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
        // Any rendered frame consumed (region path) or superseded (full paths)
        // the vacated-region accumulator and the region seeds; both come with
        // dirty ∈ {.drag, .region, .full}, so no repaint is lost by clearing.
        damage.drag_accum_valid = false;
        damage.region_seed_count = 0;
        damage.text_row_pending = false;
        ftrace.mark(.desk_done, @intFromEnum(dirty));
        frameperf.frameEnd(switch (dirty) {
            .none => .none,
            .cursor_only => .cursor,
            .text_only => .text,
            .gui_only => .gui,
            .drag => .drag,
            .region => .region,
            .full => .full,
        }, process.tick_count);

    }
    active = false;

    vga.redirect_fn = null;
    session.redirect_win = null;
    if (backbuf != null) {
        paging.freeBackBuffer(bb_pages);
        backbuf = null;
    }
    bga.disable();
    debug.klog("[desktop] Returned to text mode\n", .{});
}

// --- GUI app API (called from syscall handlers) ---

// --- Preemptive multitasking ---

pub var active: bool = false;

// --- Desktop parking (the BSP-spin fix, 2026-06-12) -----------------
//
// The desktop is an ordinary .interactive kernel task that historically
// NEVER blocked: its loop ran schedule(), and with no ready user task
// pickNext handed the CPU straight back — an eternal spin that burned
// ~98% of a host core at an idle desktop (measured via host-side
// pidstat; invisible to the in-OS meter because the spin owned the CPU
// it was sampled from). parkOrYield() makes the loop BLOCK on
// .desktop when nothing is due, so pickNext falls through to the idle
// PCB → hlt/mwait → the tickless BSP stretch finally engages.
//
// Wake paths, fastest first:
//   1. BSP idle loop (wakeIfDueFromIdle): checked BEFORE entering
//      mwait/hlt (with MONITOR already armed — no check→sleep window)
//      and again after an IRQ breaks the wait. µs latency on
//      keystrokes/mouse, and on any producer that fired while the BSP
//      was busy running a task.
//   2. wake.requestWake's monitor-word kick: a producer on ANY CPU
//      (AP app-load completion, a task's terminal-pipe write) bumps the
//      BSP's idle_monitor_word — pops an in-progress mwait instantly,
//      then path 1's post-wake check runs.
//   3. IRQ0 tick block due-check (irq0.zig): catches wake sources that
//      arrived while a USER task was running (no idle transition) —
//      ≤10ms; it retargets wake_tick to "now" and wakeExpired's
//      .desktop branch does the setState.
//   4. wakeExpired at wake_tick: the pending self-wake deadline
//      (animations, toast, the GUI auto-refresh floor) or the 1s
//      liveness backstop (menubar clock, zombie reaper).
//
// Paths 3 and 4 were DEAD until 2026-07-16: wakeExpired had no .desktop
// branch (only .gpu_io/.none honor wake_tick), so every wake funneled
// through path 1's post-IRQ check — which itself only ran after an IRQ
// broke the sleep. Net effect: launch-a-window / write-to-a-terminal
// while the desktop was parked drew NOTHING until the next mouse or
// keyboard IRQ. Path 2 didn't exist (idle_monitor_word had no writer).

/// PCB pid of the desktop task; captured at run() entry. null until then.
var desktop_pid: ?u8 = null;
/// True while the desktop task is blocked in parkOrYield. Read by the
/// IRQ0 due-check and the idle-loop waker (both BSP-local).
var parked: bool = false;

pub fn desktopParkedAndDue() bool {
    if (!@atomicLoad(bool, &parked, .acquire)) return false;
    return shouldResumeDesktop();
}

pub fn desktopPid() ?u8 {
    return desktop_pid;
}

/// Called from the BSP idle loop, both BEFORE sleeping (so a wake posted
/// while this CPU was busy isn't slept over) and right after an IRQ broke
/// hlt/mwait. Wakes the parked desktop in a lock-clean context
/// (sched.wake is NOT IRQ-safe, but idle-loop is). Returns true if it
/// woke the desktop — the pre-sleep caller then schedules instead of
/// entering mwait/hlt.
pub fn wakeIfDueFromIdle() bool {
    if (@import("../cpu/smp.zig").myCpu().cpu_id != 0) return false;
    if (!desktopParkedAndDue()) return false;
    if (desktop_pid) |dp| {
        @import("../proc/sched.zig").wake(dp);
        return true;
    }
    return false;
}

/// Liveness backstop when no self-wake is pending: 1 s. Covers slow
/// periodic housekeeping (menubar clock repaint, zombie reaping) if
/// every event-driven wake source goes quiet.
const PARK_BACKSTOP_TICKS: u64 = 100;

/// Self-wake floor while a visible GUI window is on auto-refresh: 10 Hz.
/// An app that never calls sysPresent is repainted by the loop's
/// auto-refresh, which only runs while the desktop is awake — parked for
/// good, it would freeze such a window at the frame last composited.
/// Windows that present wake the loop themselves, and terminals do through
/// pipe writes and keystrokes, so a desktop of those parks indefinitely.
const GUI_PARK_REFRESH_TICKS: u64 = 10;

/// The desktop loop's yield point. Anything due → plain yield (user
/// tasks run; the timer's force_yield/shouldResumeDesktop brings us
/// back, exactly as before). Nothing due → BLOCK until a wake path
/// fires. wake_tick is set BEFORE blockOn so a wakeExpired deadline
/// can't be missed; blockOn's wake_pending handshake covers racing
/// sched.wake() calls.
fn parkOrYield() void {
    if (shouldResumeDesktop()) {
        yieldToScheduler();
        return;
    }
    const cpu = @import("../cpu/smp.zig").myCpu();
    const me: usize = cpu.current_pid orelse {
        yieldToScheduler();
        return;
    };
    const sched = @import("../proc/sched.zig");
    const pcb = process.getPCB(me);
    // GUI refresh floor (see GUI_PARK_REFRESH_TICKS). Coalesces with any
    // earlier pending self-wake — the min wins. gui_autorefresh_active is
    // one iteration stale here (set mid-loop, read post-loop) — intentional:
    // worst case the floor starts/stops one ~100 ms cycle late when such a
    // window is first created/destroyed, then self-corrects.
    if (gui_autorefresh_active) wake.requestSelfWake(process.tick_count + GUI_PARK_REFRESH_TICKS);
    // Held key: the next auto-repeat is a tick deadline this loop must
    // wake for itself. Nothing else fires while a key stays down (USB HID
    // reports a press once), and with the BSP's tick stretched during
    // idle the IRQ0 due-check alone would pace repeats at 10 Hz.
    if (keyboard.nextRepeatTick(process.tick_count)) |t| wake.requestSelfWake(t);
    const self_due = wake.selfWakeAt();
    const deadline: u64 = if (self_due != 0) self_due else process.tick_count + PARK_BACKSTOP_TICKS;
    @atomicStore(u64, &pcb.wake_tick, deadline, .release);
    sched.registerWakeDeadline(deadline);
    @atomicStore(bool, &parked, true, .release);
    sched.blockOn(.desktop, 0);
    @atomicStore(bool, &parked, false, .release);
    // wake_tick is one-shot; clear so a stale deadline can't re-trip the
    // orphan-sleep diagnostics on a future unrelated park.
    @atomicStore(u64, &pcb.wake_tick, 0, .release);
}

// Desktop update interval: timer returns control every N ticks (~50fps at 100Hz)
var last_desktop_tick: u64 = 0;
const DESKTOP_INTERVAL: u64 = 8;
/// How long one loop iteration reads a terminal's output pipe before it
/// goes on to draw (see the drain step); the byte count is the same bound
/// for a boot with no calibrated clock.
const DRAIN_SLICE_MS: u64 = 4;
const DRAIN_SLICE_BYTES: usize = 16 * 1024;
var gui_windows_active: bool = false;
/// A visible GUI window is being re-composited on the auto-refresh timer.
var gui_autorefresh_active: bool = false;

/// Called by timer IRQ handler to decide when to return control to the desktop.
/// In event-driven mode, the floor wakeups (DESKTOP_INTERVAL + GUI 3-tick) are
/// dropped — the loop sleeps until an explicit wake.requestWake / requestSelfWake
/// fires, or input/config arrives. Flip wake.event_driven=false to restore the
/// legacy fixed-rate polling if a wake source is missed.
pub fn shouldResumeDesktop() bool {
    if (wake.isDue(process.tick_count)) return true;
    if (keyboard.hasData()) return true;
    if (keyboard.repeatDue(process.tick_count)) return true;
    if (mouse.moved) return true;
    if (config_changed) return true;
    if (!wake.event_driven) {
        // Legacy fallback: unconditional rate-based wake.
        if (process.tick_count - last_desktop_tick >= DESKTOP_INTERVAL) return true;
        if (toast.isActive()) return true;
        if (gui_windows_active and process.tick_count - last_desktop_tick >= 3) return true;
    }
    return false;
}

/// Yield to the scheduler. Calls process.schedule() which picks a ready
/// user task (via switchTo) and runs it; when this CPU's scheduler context
/// (i.e., this function's caller, desktop.run) is later resumed — by
/// force_yield in handleIRQ0, by sysExit, or by exhaustion of ready user
/// tasks — schedule() returns and we fall through to housekeeping below.
fn yieldToScheduler() void {
    // In the new (Linux-style) dispatch model, this is just process.schedule().
    // schedule() picks a ready user task and switchTo's to it; when this
    // task (the BSP scheduler context) is later resumed (force_yield path
    // in handleIRQ0, sysExit, no-ready-user fallback), schedule returns
    // and we fall through to the desktop main loop's housekeeping.
    process.schedule();

    // After scheduler context is back, restore kernel CR3. schedule() already
    // switched to kernel CR3 when handing back, but this is harmless and keeps
    // the contract explicit.
    //
    // We do NOT call keyboard.reEnable() here. It used to run every yield
    // (~28×/tick) and was the #1 source of "OURS"-class SMI stalls — caught
    // 2026-05-26 with hits up to 773 ms cli-held at reEnable+0x2ED. The
    // PS/2 config it writes is set once by initPS2() at boot and (if USB
    // keyboard wins) immediately masked by disableIRQ1(); reprogramming
    // the same config byte every yield serves no purpose. The one
    // legitimate post-mouse-init reEnable call still happens at desktop
    // startup (see line ~2765).
    asm volatile ("sti");
    @import("../cpu/mmu/pcid.zig").loadCr3(paging.getKernelPageDirPhys(), 0, @import("../cpu/smp.zig").myCpu().cpu_id);
}
