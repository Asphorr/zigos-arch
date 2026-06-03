const std = @import("std");
const gfx = @import("gfx.zig");
const bga = @import("bga.zig");
const mouse = @import("../driver/mouse.zig");
const keyboard = @import("../driver/keyboard.zig");
const vga = @import("vga.zig");
const cli = @import("../cli.zig");
const paging = @import("../mm/paging.zig");
const pmm = @import("../mm/pmm.zig");
const debug = @import("../debug/debug.zig");
const elf_loader = @import("../proc/elf_loader.zig");
const gdt = @import("../cpu/arch/gdt.zig");
const vmm = @import("../mm/vmm.zig");
const xhci = @import("../driver/xhci.zig");
const tarfs = @import("../fs/tarfs.zig");
const icons = @import("icons.zig");
const process = @import("../proc/process.zig");
const sound = @import("../driver/sound.zig");
const events_mod = @import("events.zig");
pub const Event = events_mod.Event;
pub const EventKind = events_mod.EventKind;
const Mutex = @import("../proc/spinlock.zig").Mutex;

// Serializes growGuiFb's FB-mutation sequence against destroyGuiWindow's
// FB teardown. Without it, an F10-grown FB whose owner process exits in
// the narrow window between alloc/PTE-repoint and the publish step can be
// observed mid-update by destroyGuiWindow — which then frees the OLD phys
// block while growGuiFb is also freeing it (the 1789 freeFrame underflows
// the kernel panics on). Mutex (not SpinLock) because growGuiFb calls
// tlb.shootdownAll, which IPIs peer CPUs and waits for ACK — peers that
// are also spinning on windows_lock with IRQs off would never ACK and
// we'd hard-deadlock. The mutex sleeps the waiter through the scheduler
// (IF stays on) so the shootdown still completes.
var gui_fb_realloc_lock: Mutex = .{};

// DBG: input-pipeline diagnostic counters. Bumped from desktop's drain
// loop when chars get dropped. Read by manual klog dumps when input
// behavior is unexpected. Rate-limited so we don't flood the log.
var dbg_focus_drop_count: u64 = 0;
var dbg_event_queue_full: u64 = 0;
var dbg_kbpipe_drop: u64 = 0;
var dbg_last_focus_drop_log: u64 = 0;
var dbg_last_qfull_log: u64 = 0;
var dbg_last_kbpipe_log: u64 = 0;

// --- Window management (storage, z-stack, focus, hit-testing) ---
const wm = @import("desktop/window.zig");
const Window = wm.Window;
const TerminalData = wm.TerminalData;
const AnimationType = wm.AnimationType;
const ResizeEdge = wm.ResizeEdge;
const EscState = wm.EscState;
const windows = &wm.windows;
const slot_used = &wm.slot_used;
const z_stack = &wm.z_stack;
const windowCount = wm.windowCount;
const lockWindows = wm.lockWindows;
const unlockWindows = wm.unlockWindows;
const allocSlot = wm.allocSlot;
const freeSlot = wm.freeSlot;
const pushZTop = wm.pushZTop;
const removeFromZ = wm.removeFromZ;
const topSlot = wm.topSlot;
const setFocused = wm.setFocused;
const allocTerminalData = wm.allocTerminalData;
const freeTerminalData = wm.freeTerminalData;
const defaultWindow = wm.defaultWindow;
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
// dirty_rects_mod.force_full_kind moved to dirty.zig as dirty_rects_mod.force_full_kind
var gui_composite_counter: u8 = 0;

// Dirty-region tracker for partial GPU flush — see desktop/dirty.zig.
// Adapter helpers below preserve the historical names so call sites
// don't all need rewriting; the underlying state is owned by the
// extracted module. Aliased as `dirty_rects_mod` to avoid clashing
// with the local `dirty: DirtyKind` variable inside `run()`.
const dirty_rects_mod = @import("desktop/dirty.zig");

inline fn addDirtyRect(x: u32, y: u32, w: u32, h: u32) void { dirty_rects_mod.add(x, y, w, h); }
inline fn markDirtyFull() void { dirty_rects_mod.markFull(); }
inline fn resetDirtyRects() void {
    // Mode 9: the dispatch's wake fan-out calls requestRenderFromDirty
    // which snapshots the rects into the compositor's own pending list
    // BEFORE this reset. So unconditional reset is fine — the compositor
    // already has its copy. (Earlier we deferred reset entirely in mode
    // 9 hoping the compositor would consume rects directly, but that
    // had a race against the next desktop tick adding new rects mid-
    // consume.)
    dirty_rects_mod.reset();
}

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

pub fn showNotification(text: []const u8) void {
    toast.show(text);
    dirty_rects_mod.force_full_kind = true;
    wake.requestWake();
    sound.notify();
}

// Wallpaper presets + render moved to desktop/background.zig.
const background = @import("desktop/background.zig");

// --- Colors / palette / terminal tunables (see theme.zig) ---
const theme = @import("theme.zig");
const BG_TOP_DEFAULT = theme.BG_TOP_DEFAULT;
const BG_BOTTOM_DEFAULT = theme.BG_BOTTOM_DEFAULT;
const TITLEBAR_FOCUSED = theme.TITLEBAR_FOCUSED;
const TITLEBAR_UNFOCUSED = theme.TITLEBAR_UNFOCUSED;
const TITLEBAR_TEXT_F = theme.TITLEBAR_TEXT_F;
const TITLEBAR_TEXT_U = theme.TITLEBAR_TEXT_U;
const WINDOW_BG = theme.WINDOW_BG;
const WINDOW_BORDER = theme.WINDOW_BORDER;
const WINDOW_SHADOW = theme.WINDOW_SHADOW;
const TERM_FG = theme.TERM_FG;
const BTN_CLOSE = theme.BTN_CLOSE;
const BTN_MINIMIZE = theme.BTN_MINIMIZE;
const BTN_MAXIMIZE = theme.BTN_MAXIMIZE;
const DOCK_BG = theme.DOCK_BG;
const DOCK_BORDER = theme.DOCK_BORDER;
const DOCK_TEXT = theme.DOCK_TEXT;
const DOCK_ACTIVE = theme.DOCK_ACTIVE;

// --- Layout ---
// Spatial constants live in desktop/layout.zig so other extracted
// submodules (toast, dock, menubar, compositor, …) can share them
// without circular imports back into this file.
const layout = @import("desktop/layout.zig");
const MENUBAR_H = layout.MENUBAR_H;
const TASKBAR_H = layout.TASKBAR_H;
const DOCK_ICON_SIZE = layout.DOCK_ICON_SIZE;
const DOCK_ICON_PAD = layout.DOCK_ICON_PAD;
const DOCK_PILL_PAD = layout.DOCK_PILL_PAD;
const DOCK_MARGIN_BOTTOM = layout.DOCK_MARGIN_BOTTOM;
const TITLEBAR_H = layout.TITLEBAR_H;
const BORDER = layout.BORDER;
const BTN_RADIUS = layout.BTN_RADIUS;
// Terminal cell size — sized to fit the SF Mono 14px glyph (advance=9, line_height=18).
// Update both constants together if a different mono atlas size is chosen.
const FONT_W: u32 = 9;
const FONT_H: u32 = 18;
const aa_font = @import("aa_font.zig");

/// Render one terminal cell at top-left (x, y): fills the cell rect with `bg`,
/// then blits the SF Mono glyph for `ch` in `fg`. Called once per non-space
/// cell from the three terminal-render paths below.
inline fn drawTermChar(x: i32, y: i32, ch: u8, fg: u32, bg: u32) void {
    gfx.fillRect(x, y, FONT_W, FONT_H, bg);
    const buf: [1]u8 = .{ch};
    aa_font.drawText(x, y, &buf, fg, aa_font.getDefaultMono());
}
const TERM_COLS: u32 = 80;
const TERM_ROWS: u32 = 25;
const TERM_PAD: u32 = 4;

// --- Terminal escape / coloring (see theme.zig for the constant values) ---
const ANSI_PALETTE = theme.ANSI_PALETTE;
const ATTR_DEFAULT = theme.ATTR_DEFAULT;
const ATTR_BOLD = theme.ATTR_BOLD;
const ATTR_INVERSE = theme.ATTR_INVERSE;
const TAB_WIDTH = theme.TAB_WIDTH;
const BELL_FLASH_FRAMES = theme.BELL_FLASH_FRAMES;
const CURSOR_BLINK_HALF_TICKS = theme.CURSOR_BLINK_HALF_TICKS;
const BELL_FLASH_COLOR = theme.BELL_FLASH_COLOR;

inline fn cellColors(attr: u8, fg_rgb: u32) struct { fg: u32, bg: u32 } {
    var fg: u32 = undefined;
    if ((attr & theme.ATTR_RGB_FG) != 0) {
        fg = fg_rgb;
    } else {
        const idx: u8 = attr & 0x0F;
        const palette_idx: u8 = if ((attr & ATTR_BOLD) != 0) (idx | 0x08) else idx;
        fg = ANSI_PALETTE[palette_idx];
    }
    var bg: u32 = WINDOW_BG;
    if ((attr & ATTR_INVERSE) != 0) {
        const swap = fg;
        fg = bg;
        bg = swap;
    }
    return .{ .fg = fg, .bg = bg };
}

// --- Window ---
const MAX_WINDOWS: u32 = @import("../config.zig").MAX_WINDOWS;
const SCROLL_LINES: u32 = @import("../config.zig").SCROLL_LINES;
const heap = @import("../mm/heap.zig");


/// Bounds-checked text buffer index. Returns null if out of range.
inline fn textIdx(row: u16, col: u16) ?usize {
    if (row >= TERM_ROWS or col >= TERM_COLS) return null;
    return @as(usize, row) * TERM_COLS + @as(usize, col);
}

/// Safe text buffer write.
inline fn textPut(w: *Window, row: u16, col: u16, ch: u8) void {
    const t = w.term orelse return;
    if (textIdx(row, col)) |idx| t.text_buf[idx] = ch;
}

// --- Drag state ---
var dragging: bool = false;
var drag_win: u8 = 0;
var drag_ox: i32 = 0;
var drag_oy: i32 = 0;
var drag_old_x: i32 = 0;
var drag_old_y: i32 = 0;
var prev_buttons: u8 = 0;
/// Double-click detection on the titlebar — when the same window's
/// Titlebar double-click → maximize was removed: too many drags
/// triggered it inadvertently. Maximize is reachable via the window's
/// maximize button and F10.

// Resize state
var resizing: bool = false;
var resize_win: u8 = 0;
var resize_edge: ResizeEdge = .right;
const MIN_WIN_W: u32 = 200;
const MIN_WIN_H: u32 = 100;
const RESIZE_ZONE: i32 = 5;

// Context menu state moved to desktop/context_menu.zig.

// Pinned-app manifest moved to desktop/pinned.zig.
// Desktop icon constants and selection state moved to desktop/shortcuts.zig.

// --- Back buffer ---
var backbuf: ?[*]volatile u32 = null;
var bb_pages: u32 = 0;

/// Read-only access for the GPU compositor (mode 9). Returns null until
/// desktop.run() has finished allocating the back buffer; the compositor
/// polls until non-null before sampling.
pub fn getBackBuffer() ?[*]volatile u32 {
    return backbuf;
}

/// Incremented at the start of every renderScene call. The mode-9 GPU
/// compositor caches the last value it saw; if unchanged since the last
/// frame, the desktop hasn't redrawn, so the compositor can skip its
/// full-screen blit + flush. Saves ~12 ms/frame when idle.
pub var render_tick: u32 = 0;

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

// --- Redirect ---
var redirect_win: ?*Window = null;

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

fn desktopPutChar(c: u8) void {
    const w = redirect_win orelse return;
    putCharOnWindow(w, c);
}

/// Append a char to the given terminal window's text buffer, advancing the
/// cursor and applying any in-flight escape sequence. Shared by:
///   - desktopPutChar (kernel CLI output, fallback path)
///   - the per-frame stdout-pipe drain step (user-space shell output)
///
/// Recognized control bytes:
///   - \n         newline (CR+LF; cursor → col 0, row+1, scroll if needed)
///   - \x08       backspace (cursor left, write space at new pos with cur_attr)
///   - \t         tab (cursor advances to next 8-column boundary)
///   - \x07       bell (sets bell_phase; main loop renders a red border flash)
///   - \x1b[...m  SGR — foreground color, bold, inverse (16-color ANSI palette)
///   - \x1b[r;cH  cursor position (1-indexed row;col)
///   - \x1b[nA/B/C/D   cursor up/down/right/left by n (default 1)
///   - \x1b[nJ    erase display (0 = below, 1 = above, 2 = all)
///   - \x1b[nK    erase line (0 = right, 1 = left, 2 = all)
/// Anything else (control bytes < 0x20, malformed escapes) is dropped silently.
/// Plain printable bytes are stored alongside `cur_attr` in `attr_buf` so the
/// render path can color each cell independently.
fn putCharOnWindow(w: *Window, c: u8) void {
    const t = w.term orelse return;
    // Any output activity restarts the cursor "on" half of the blink cycle —
    // looks dead otherwise when text scrolls past the cursor.
    t.cursor_blink_anchor = process.tick_count;
    switch (t.esc_state) {
        .idle => putCharIdle(w, t, c),
        .esc => putCharAfterEsc(t, c),
        .csi => putCharAfterCsi(w, t, c),
    }
}

fn putCharIdle(w: *Window, t: *TerminalData, c: u8) void {
    switch (c) {
        '\x1b' => t.esc_state = .esc,
        '\x07' => {
            t.bell_phase = BELL_FLASH_FRAMES;
            wake.requestWake();
        },
        '\t' => {
            const next = (@as(u32, t.text_col) / TAB_WIDTH + 1) * TAB_WIDTH;
            t.text_col = @intCast(@min(next, TERM_COLS - 1));
            t.pending_wrap = false;
        },
        '\n' => {
            t.text_col = 0;
            t.text_row += 1;
            if (t.text_row >= TERM_ROWS) scrollWindow(w);
            t.pending_wrap = false;
        },
        '\r' => {
            t.text_col = 0;
            t.pending_wrap = false;
        },
        '\x08' => {
            if (t.text_col > 0) {
                t.text_col -= 1;
                writeCell(t, t.text_row, t.text_col, ' ', t.cur_attr);
            }
            t.pending_wrap = false;
        },
        else => {
            // Drop unhandled C0 control bytes rather than render garbage.
            if (c < 0x20) return;

            // Deferred wrap: if the previous printable write landed at the
            // last column with `pending_wrap=true`, commit the wrap NOW
            // (before this char). \r / \n / \x08 / CSI cursor moves clear
            // the flag, so a clean redraw that starts with `\r` never
            // triggers a scroll regardless of the previous line's length.
            if (t.pending_wrap) {
                t.text_col = 0;
                t.text_row += 1;
                if (t.text_row >= TERM_ROWS) scrollWindow(w);
                t.pending_wrap = false;
            }

            writeCell(t, t.text_row, t.text_col, c, t.cur_attr);

            if (t.text_col + 1 >= TERM_COLS) {
                // Last column: park here, set the flag, don't scroll yet.
                t.pending_wrap = true;
            } else {
                t.text_col += 1;
            }
        },
    }
}

fn putCharAfterEsc(t: *TerminalData, c: u8) void {
    if (c == '[') {
        t.esc_state = .csi;
        t.csi_args = [_]u16{0} ** 8;
        t.csi_arg_count = 0;
        t.csi_has_arg = false;
    } else {
        // Two-char ESC sequences (ESC c, ESC =, etc.) and unknown forms — drop.
        t.esc_state = .idle;
    }
}

fn putCharAfterCsi(w: *Window, t: *TerminalData, c: u8) void {
    if (c >= '0' and c <= '9') {
        if (t.csi_arg_count < t.csi_args.len) {
            t.csi_args[t.csi_arg_count] = t.csi_args[t.csi_arg_count] *% 10 +% (c - '0');
            t.csi_has_arg = true;
        }
        return;
    }
    if (c == ';') {
        if (t.csi_arg_count + 1 < t.csi_args.len) t.csi_arg_count += 1;
        return;
    }
    // Final byte must be in 0x40..0x7E per ECMA-48; anything else aborts.
    if (c >= 0x40 and c <= 0x7E) {
        const n_args: u8 = if (t.csi_has_arg) (t.csi_arg_count + 1) else 0;
        dispatchCsi(w, t, c, n_args);
    }
    t.esc_state = .idle;
}

fn dispatchCsi(w: *Window, t: *TerminalData, final: u8, n_args: u8) void {
    switch (final) {
        'm' => sgr(t, n_args),
        'H', 'f' => {
            // Args are 1-indexed in ANSI; clamp to in-range cells.
            const r: u32 = if (n_args >= 1 and t.csi_args[0] > 0) t.csi_args[0] - 1 else 0;
            const col: u32 = if (n_args >= 2 and t.csi_args[1] > 0) t.csi_args[1] - 1 else 0;
            t.text_row = @intCast(@min(r, TERM_ROWS - 1));
            t.text_col = @intCast(@min(col, TERM_COLS - 1));
            t.pending_wrap = false;
        },
        'A' => {
            const n: u16 = if (n_args >= 1 and t.csi_args[0] > 0) t.csi_args[0] else 1;
            t.text_row = if (t.text_row >= n) t.text_row - n else 0;
            t.pending_wrap = false;
        },
        'B' => {
            const n: u16 = if (n_args >= 1 and t.csi_args[0] > 0) t.csi_args[0] else 1;
            const new_row: u32 = @as(u32, t.text_row) + n;
            t.text_row = @intCast(@min(new_row, TERM_ROWS - 1));
            t.pending_wrap = false;
        },
        'C' => {
            const n: u16 = if (n_args >= 1 and t.csi_args[0] > 0) t.csi_args[0] else 1;
            const new_col: u32 = @as(u32, t.text_col) + n;
            t.text_col = @intCast(@min(new_col, TERM_COLS - 1));
            t.pending_wrap = false;
        },
        'D' => {
            const n: u16 = if (n_args >= 1 and t.csi_args[0] > 0) t.csi_args[0] else 1;
            t.text_col = if (t.text_col >= n) t.text_col - n else 0;
            t.pending_wrap = false;
        },
        'J' => eraseDisplay(t, if (n_args >= 1) t.csi_args[0] else 0),
        'K' => eraseLine(t, if (n_args >= 1) t.csi_args[0] else 0),
        else => {},
    }
    _ = w;
}

fn sgr(t: *TerminalData, n_args: u8) void {
    if (n_args == 0) {
        t.cur_attr = ATTR_DEFAULT;
        t.cur_fg_rgb = 0;
        return;
    }
    var i: u8 = 0;
    while (i < n_args) : (i += 1) {
        const arg = t.csi_args[i];
        switch (arg) {
            0 => {
                t.cur_attr = ATTR_DEFAULT;
                t.cur_fg_rgb = 0;
            },
            1 => t.cur_attr |= ATTR_BOLD,
            7 => t.cur_attr |= ATTR_INVERSE,
            22 => t.cur_attr &= ~ATTR_BOLD,
            27 => t.cur_attr &= ~ATTR_INVERSE,
            30...37 => {
                // Palette index — clear the truecolor flag so the cell
                // renders via ANSI_PALETTE again.
                t.cur_attr = (t.cur_attr & 0xF0 & ~theme.ATTR_RGB_FG) | @as(u8, @intCast(arg - 30));
            },
            // Bright fg (90..97) maps to bold + base color, mirroring how most
            // terminals render the "bright" series.
            90...97 => t.cur_attr = ((t.cur_attr & 0xF0 & ~theme.ATTR_RGB_FG) | @as(u8, @intCast(arg - 90))) | ATTR_BOLD,
            // 39 = default fg.
            39 => {
                t.cur_attr = (t.cur_attr & 0xF0 & ~theme.ATTR_RGB_FG) | (ATTR_DEFAULT & 0x0F);
                t.cur_fg_rgb = 0;
            },
            // 38;2;R;G;B = 24-bit truecolor fg. Consumes the next 4 args
            // (the `2` selector + R/G/B). `38;5;N` (256-color) consumes
            // 2 args; we don't expand the 256-color cube yet, just step
            // over the selector + index so following args parse cleanly.
            38 => {
                if (i + 1 >= n_args) break;
                const sub = t.csi_args[i + 1];
                if (sub == 2) {
                    if (i + 4 >= n_args) break;
                    const r: u32 = @intCast(t.csi_args[i + 2] & 0xFF);
                    const g: u32 = @intCast(t.csi_args[i + 3] & 0xFF);
                    const b: u32 = @intCast(t.csi_args[i + 4] & 0xFF);
                    t.cur_fg_rgb = (r << 16) | (g << 8) | b;
                    t.cur_attr |= theme.ATTR_RGB_FG;
                    i += 4;
                } else if (sub == 5) {
                    // 256-color: skip the index for now; future-proof.
                    if (i + 2 >= n_args) break;
                    i += 2;
                }
            },
            else => {},
        }
    }
}

fn eraseDisplay(t: *TerminalData, mode: u16) void {
    const cur_idx: u32 = @as(u32, t.text_row) * TERM_COLS + t.text_col;
    switch (mode) {
        0 => {
            for (cur_idx..TERM_COLS * TERM_ROWS) |i| {
                t.text_buf[i] = ' ';
                t.attr_buf[i] = t.cur_attr;
                t.fg_rgb_buf[i] = t.cur_fg_rgb;
            }
        },
        1 => {
            const end = @min(cur_idx + 1, TERM_COLS * TERM_ROWS);
            for (0..end) |i| {
                t.text_buf[i] = ' ';
                t.attr_buf[i] = t.cur_attr;
                t.fg_rgb_buf[i] = t.cur_fg_rgb;
            }
        },
        2, 3 => {
            @memset(&t.text_buf, ' ');
            @memset(&t.attr_buf, t.cur_attr);
            @memset(&t.fg_rgb_buf, t.cur_fg_rgb);
        },
        else => {},
    }
}

fn eraseLine(t: *TerminalData, mode: u16) void {
    if (t.text_row >= TERM_ROWS) return;
    const row_start: u32 = @as(u32, t.text_row) * TERM_COLS;
    switch (mode) {
        0 => {
            for (t.text_col..TERM_COLS) |c| {
                t.text_buf[row_start + c] = ' ';
                t.attr_buf[row_start + c] = t.cur_attr;
                t.fg_rgb_buf[row_start + c] = t.cur_fg_rgb;
            }
        },
        1 => {
            const end = @as(u32, t.text_col) + 1;
            for (0..@min(end, TERM_COLS)) |c| {
                t.text_buf[row_start + c] = ' ';
                t.attr_buf[row_start + c] = t.cur_attr;
                t.fg_rgb_buf[row_start + c] = t.cur_fg_rgb;
            }
        },
        2 => {
            for (0..TERM_COLS) |c| {
                t.text_buf[row_start + c] = ' ';
                t.attr_buf[row_start + c] = t.cur_attr;
                t.fg_rgb_buf[row_start + c] = t.cur_fg_rgb;
            }
        },
        else => {},
    }
}

inline fn writeCell(t: *TerminalData, row: u16, col: u16, ch: u8, attr: u8) void {
    if (textIdx(row, col)) |idx| {
        t.text_buf[idx] = ch;
        t.attr_buf[idx] = attr;
        // Mirror cur_fg_rgb so renderers can pull per-cell RGB when the
        // truecolor flag is set. Cheap (one u32 store) and means the
        // erase/scroll memcpy paths don't need parallel "rgb propagation"
        // for the common case where a cell is just rewritten in place.
        t.fg_rgb_buf[idx] = t.cur_fg_rgb;
    }
}

/// Append a string to the given window's text buffer. Used for boot/error
/// messages that the desktop writes directly into a Terminal window.
fn putStringOnWindow(window_idx: u8, data: []const u8) void {
    if (window_idx >= MAX_WINDOWS or !slot_used[window_idx]) return;
    const w = &windows[window_idx];
    if (!w.visible) return;
    for (data) |ch| putCharOnWindow(w, ch);
}


fn scrollWindow(w: *Window) void {
    const t = w.term orelse return;
    // Save top row (and its attrs) to the scrollback ring so colored output
    // remains colored when the user scrolls up later. fg_rgb_buf travels
    // alongside attr_buf so truecolor-set cells preserve their hue in
    // scrollback view.
    if (t.scroll_write >= SCROLL_LINES) t.scroll_write = 0;
    const sb_off = @as(u32, t.scroll_write) * TERM_COLS;
    @memcpy(t.scroll_buf[sb_off..][0..TERM_COLS], t.text_buf[0..TERM_COLS]);
    @memcpy(t.scroll_attr_buf[sb_off..][0..TERM_COLS], t.attr_buf[0..TERM_COLS]);
    @memcpy(t.scroll_fg_rgb_buf[sb_off..][0..TERM_COLS], t.fg_rgb_buf[0..TERM_COLS]);
    t.scroll_write = @intCast((@as(u32, t.scroll_write) + 1) % SCROLL_LINES);
    if (t.scroll_count < SCROLL_LINES) t.scroll_count += 1;
    // Auto-scroll to live on new output
    t.scroll_view = 0;

    // Shift all rows up by one (text + attrs + fg_rgb).
    var row: u32 = 0;
    while (row < TERM_ROWS - 1) : (row += 1) {
        const dst = row * TERM_COLS;
        const src = (row + 1) * TERM_COLS;
        @memcpy(t.text_buf[dst..][0..TERM_COLS], t.text_buf[src..][0..TERM_COLS]);
        @memcpy(t.attr_buf[dst..][0..TERM_COLS], t.attr_buf[src..][0..TERM_COLS]);
        @memcpy(t.fg_rgb_buf[dst..][0..TERM_COLS], t.fg_rgb_buf[src..][0..TERM_COLS]);
    }
    // Clear last row's chars + reset its attrs to current SGR state, so newly
    // written cells inherit any in-flight SGR (e.g. mid-color block).
    @memset(t.text_buf[(TERM_ROWS - 1) * TERM_COLS ..][0..TERM_COLS], ' ');
    @memset(t.attr_buf[(TERM_ROWS - 1) * TERM_COLS ..][0..TERM_COLS], t.cur_attr);
    @memset(t.fg_rgb_buf[(TERM_ROWS - 1) * TERM_COLS ..][0..TERM_COLS], t.cur_fg_rgb);
    t.text_row = @intCast(TERM_ROWS - 1);
}

fn termPrompt(w: *Window) void {
    const t = w.term orelse return;
    const prompt_str = "root@zigos> ";
    for (prompt_str) |ch| {
        if (t.text_col >= TERM_COLS) {
            t.text_col = 0;
            t.text_row += 1;
            if (t.text_row >= TERM_ROWS) scrollWindow(w);
        }
        if (textIdx(t.text_row, t.text_col)) |idx| t.text_buf[idx] = ch;
        t.text_col += 1;
    }
}

fn createWindow(title: []const u8, x: i32, y: i32, w: u32, h: u32) ?u8 {
    const flags = lockWindows();
    defer unlockWindows(flags);
    const td = allocTerminalData() orelse return null;
    const slot = allocSlot() orelse {
        freeTerminalData(td);
        return null;
    };
    windows[slot].x = x;
    windows[slot].y = y;
    windows[slot].width = w;
    windows[slot].height = h;
    windows[slot].visible = true;
    windows[slot].term = td;
    const copy_len = if (title.len > 32) @as(usize, 32) else title.len;
    for (0..copy_len) |i| windows[slot].title[i] = title[i];
    windows[slot].title_len = @intCast(copy_len);
    pushZTop(slot);
    startAnimation(slot, .opening);
    return slot;
}

fn closeWindow(idx: u8) void {
    if (idx >= MAX_WINDOWS or !slot_used[idx]) return;
    // If already animating close, skip
    if (windows[idx].anim_type == .closing) return;
    sound.close();
    // Notify the app that we're closing it. The app has the closing-
    // animation duration (~200 ms) to call exit() and clean up its own
    // state; if it doesn't, the existing destroy path kills it forcibly.
    windows[idx].events.push(.{ .kind = @intFromEnum(EventKind.close_request) });
    // Start closing animation — actual close happens in advanceAnimations completion
    startAnimation(idx, .closing);
}

/// Grow window `idx`'s GUI framebuffer so the app can render crisply at
/// `need_w × need_h` content pixels instead of being upscaled from a smaller
/// allocation. GROW-only (the bigger block is kept until the window closes);
/// returns true once the FB covers need_w/need_h.
///
/// Runs in the DESKTOP TASK, sequential with renderScene — so there is no
/// render-vs-free race on the front buffer (the dangerous case an app-side
/// realloc syscall would have). Mirrors sysCreateWindow's legacy PMM path +
/// unmapGuiFB teardown:
///   1. alloc + zero a new contiguous block;
///   2. map the GROWTH pages first (only these can fail on PT-OOM → clean
///      abort, live mapping untouched), then overwrite the existing
///      [0,old_pages) PTEs in place (no unmapped gap → an app mid-write on
///      another CPU can't fault on GUI_FB_BASE);
///   3. shoot down the app's PCID so no CPU can still reach the old frames
///      (relies on the 2026-05-21 global-flush shootdown fix);
///   4. NULL the front + drain in-flight present snapshots, repoint the window,
///      then drop the old block's two refcounts + free its back buffers.
/// The app learns the new stride via sysGetWindowAlloc on the `.resize` event
/// toggleFullscreen pushes right after.
fn growGuiFb(idx: u8, need_w: u32, need_h: u32) bool {
    // Hold across the full grow so destroyGuiWindow (which also takes
    // this mutex) cannot observe gui_fb_phys_base / gui_alloc_w/h
    // mid-publish, and so it cannot race lines 836-840's OLD-frame
    // release against its own unmapGuiFB. windows_lock is NOT taken
    // around shootdownAll — that would deadlock against a peer CPU
    // spinning on windows_lock with IRQs off (it could not ACK our IPI).
    gui_fb_realloc_lock.acquire();
    defer gui_fb_realloc_lock.release();

    const w = &windows[idx];
    if (w.gpu_slot != null) return false; // GPU path scales via the compositor
    // Opt-in: only grow for apps that have queried getWindowAlloc and thus know
    // to re-fetch their stride on the resize event. Everything else keeps the
    // upscale fallback (no stride change → no shear/blank regression).
    if (!w.fb_growable) return false;
    const fb_kv = w.gui_fb orelse return false;
    const pid = w.owner_pid;
    if (pid >= process.procs.len) return false;

    const new_alloc_w: u32 = (need_w + 15) & ~@as(u32, 15); // 16-px stride
    const new_alloc_h: u32 = need_h;
    // Already big enough — just adopt the new logical content size.
    if (new_alloc_w <= w.gui_alloc_w and new_alloc_h <= w.gui_alloc_h) {
        w.gui_w = need_w;
        w.gui_h = need_h;
        return true;
    }
    const new_bytes: u64 = @as(u64, new_alloc_w) * new_alloc_h * 4;
    if (new_bytes > @import("../mm/memmap.zig").GUI_FB_PER_PID_SIZE) return false;
    const new_pages: u32 = @intCast((new_bytes + 4095) / 4096);
    const old_bytes: u64 = @as(u64, w.gui_alloc_w) * w.gui_alloc_h * 4;
    const old_pages: u32 = @intCast((old_bytes + 4095) / 4096);
    const old_phys = paging.virtToPhys(@intFromPtr(fb_kv)) orelse return false;

    const new_phys = pmm.allocContiguous(new_pages) orelse {
        debug.klog("[maximize] growGuiFb pid={d}: allocContiguous({d} pages) failed; staying {d}x{d}\n", .{ pid, new_pages, w.gui_alloc_w, w.gui_alloc_h });
        return false;
    };
    const new_kv: [*]volatile u32 = @ptrFromInt(paging.physToVirt(new_phys));
    @memset(@as([*]volatile u8, @ptrCast(new_kv))[0 .. new_pages * 4096], 0);

    const pd: [*]align(4096) u64 = @ptrFromInt(paging.physToVirt(process.procs[pid].page_dir_phys));
    const base = paging.GUI_FB_USER_BASE;
    const map_flags = paging.READ_WRITE | paging.USER;

    // Growth pages first — the only ones that can need (and fail to get) a new
    // page-table page. On failure the live [0,old_pages) mapping is untouched.
    var i: u32 = old_pages;
    while (i < new_pages) : (i += 1) {
        vmm.mapUserPage(pd, base + i * 4096, new_phys + i * 4096, map_flags) catch {
            var j: u32 = old_pages;
            while (j < i) : (j += 1) {
                _ = vmm.unmapUserPage(pd, base + j * 4096);
                pmm.releaseFrame(new_phys + j * 4096);
            }
            pmm.freeContiguous(new_phys, new_pages);
            debug.klog("[maximize] growGuiFb pid={d}: PT OOM at growth page {d}; aborted\n", .{ pid, i });
            return false;
        };
        pmm.acquireFrame(new_phys + i * 4096);
    }
    // Repoint the existing [0,old_pages) mapping. mapUserPage refuses to
    // overwrite a PTE that points at a different phys (vmm gap #2 →
    // error.AlreadyMapped), so clear each PTE first. unmapUserPage only zeroes
    // the PTE (no releaseFrame), so the old frame's refcount is left intact for
    // the explicit double-release below. The PT page for this VA already exists
    // (the old FB mapped it), so the subsequent map cannot fail.
    //
    // The one-page-wide gap between unmap and map is safe here: F10 is handled
    // by the desktop task while the app sits parked in its event loop (not
    // writing its FB). An app that renders continuously would want a
    // force-overwrite mapUserPage variant to close the gap entirely.
    i = 0;
    while (i < old_pages) : (i += 1) {
        _ = vmm.unmapUserPage(pd, base + i * 4096);
        vmm.mapUserPage(pd, base + i * 4096, new_phys + i * 4096, map_flags) catch |e| {
            debug.klog("[maximize] growGuiFb pid={d}: in-place remap page {d} failed: {s}\n", .{ pid, i, @errorName(e) });
            @panic("growGuiFb in-place remap (PT page should already exist)");
        };
        pmm.acquireFrame(new_phys + i * 4096);
    }
    // Old frames are now unreachable from the app once its TLB is flushed.
    @import("../cpu/mmu/tlb.zig").shootdownAll(process.procs[pid].pcid);

    // Drain in-flight present snapshots BEFORE taking windows_lock — the
    // drain loop can spin millions of cycles waiting for a peer CPU's
    // sysPresent to finish, and holding windows_lock (IRQ-save spinlock)
    // through that would block IRQ delivery on this CPU for the whole
    // wait. snapshotGuiFb doesn't take windows_lock, so this drain is
    // safe outside it.
    var spin: u32 = 0;
    while (@atomicLoad(u32, &presenting_count, .acquire) > 0) {
        asm volatile ("pause");
        spin += 1;
        if (spin > 10_000_000) break;
    }

    // Publish the new geometry atomically with windows_lock held so the
    // compositor (and createGuiWindow / destroyGuiWindow) cannot observe
    // a half-updated window. NULL the front AND the stale back-buffer
    // pointers first (they point at the OLD, smaller, about-to-be-freed
    // blocks), THEN publish — the ordering reclaimBackBuffers uses. The
    // backs MUST be nulled before gui_fb_pixels grows and gui_fb is
    // re-published: otherwise the next snapshotGuiFb sees them non-null,
    // skips realloc, and memcpys the new (larger) pixel count into a
    // small freed back buffer → overflow + panic in sysPresent.
    var old_back_phys: [3]usize = .{ 0, 0, 0 };
    {
        const wflags = lockWindows();
        defer unlockWindows(wflags);
        w.gui_fb = null;
        w.has_presented = false;
        var s: u8 = 0;
        while (s < 3) : (s += 1) {
            w.gui_fb_backs[s] = null;
            old_back_phys[s] = paging.takeGuiFbBackPhys(pid, s);
        }
        w.gui_fb_pixels = @intCast(@as(u64, new_alloc_w) * new_alloc_h);
        w.gui_alloc_w = new_alloc_w;
        w.gui_alloc_h = new_alloc_h;
        w.gui_w = need_w;
        w.gui_h = need_h;
        w.gui_fb_pub.store(0, .release);
        paging.registerGuiFB(pid, new_phys);
        w.gui_fb = new_kv;
    }

    // Free the OLD block: front frames carry two refs (alloc + acquire) — drop
    // both; each old back buffer (phys taken above) is a single-owner block.
    // Outside windows_lock (refcount math is independent) but still inside
    // gui_fb_realloc_lock so destroyGuiWindow's unmapGuiFB can't also drop a
    // ref on the same OLD frames (it would have done that under
    // gui_fb_realloc_lock + windows_lock and our publish would have shown it
    // OLD-state values via gui_fb_phys_base/gui_alloc still being OLD).
    i = 0;
    while (i < old_pages) : (i += 1) {
        pmm.releaseFrame(old_phys + i * 4096);
        pmm.releaseFrame(old_phys + i * 4096);
    }
    {
        var s: u8 = 0;
        while (s < 3) : (s += 1) {
            if (old_back_phys[s] != 0) pmm.freeContiguous(old_back_phys[s], old_pages);
        }
    }
    debug.klog("[maximize] grew pid={d} FB -> {d}x{d} ({d} pages, was {d} pages)\n", .{ pid, new_alloc_w, new_alloc_h, new_pages, old_pages });
    return true;
}

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
        w.events.push(.{ .kind = @intFromEnum(EventKind.resize), .a = w.saved_w, .b = w.saved_h });
    } else {
        // Enter maximize — fill the entire area between menubar and
        // dock. Keep window chrome (titlebar + traffic-light buttons)
        // visible so the user can un-maximize, close, minimize.
        //
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

        const usable_h: u32 = @as(u32, @intCast(gfx.screen_h)) -| MENUBAR_H -| TASKBAR_H;
        const target_w: u32 = gfx.screen_w;
        const target_h: u32 = usable_h;

        w.anim_end_x = 0;
        w.anim_end_y = @intCast(MENUBAR_H);
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
            // Grow the app's framebuffer to the maximized content size so it
            // can repaint crisply (falls back to upscaling if the bigger
            // contiguous block can't be allocated). Sets gui_w/gui_h.
            _ = growGuiFb(idx, target_w, target_h -| TITLEBAR_H);
        }
        // Notify the app: it re-fetches the (grown) alloc via getWindowAlloc and
        // repaints at the new size. Payload matches the drag-resize convention.
        w.events.push(.{ .kind = @intFromEnum(EventKind.resize), .a = target_w, .b = target_h });
    }
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

const rtc = @import("../time/rtc.zig");

// --- Scene rendering (to back buffer) ---

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
        if (!u.visible or u.minimized) continue;
        // A fullscreen window above covers everything below by definition.
        if (u.fullscreen) return true;
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

fn renderScene() void {
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
    @import("gpu_compositor.zig").requestRender();
}

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
        const nw: u32 = TERM_COLS * FONT_W + BORDER * 2;
        const nh: u32 = TERM_ROWS * FONT_H + TITLEBAR_H;
        if (createWindow("Terminal", 80 + off, 40 + off, nw, nh)) |ni| {
            setFocused(ni);
            spawnShellOnWindow(ni);
        }
    } else {
        // Run app — try async load on AP first.
        const smp = @import("../cpu/smp.zig");
        if (smp.cpu_count > 1) {
            if (smp.requestAppLoad(sc.cmd)) {
                debug.klog("[launch] requestAppLoad accepted '{s}'\n", .{sc.cmd});
                showNotification("Loading...");
            } else {
                // AP mid-flight on a previous load — can't fall back to a
                // BSP-side sync read (both paths share NVMe bounce_buf w/o
                // serialization). Queue instead so the click isn't lost;
                // launch_queue.drain in the main loop will submit it once
                // the AP goes idle.
                if (launch_queue.push(sc.cmd)) {
                    debug.klog("[launch] queued '{s}' (depth: {d})\n", .{ sc.cmd, launch_queue.depth() });
                    showNotification("Queued...");
                } else {
                    debug.klog("[launch] queue full, dropped '{s}'\n", .{sc.cmd});
                    showNotification("Launch queue full");
                }
            }
        } else {
            // Single-core only — sync fallback is safe (no concurrent
            // reader to race against).
            if (@import("../fs/vfs.zig").loadFileFresh(sc.cmd)) |fresh| {
                if (elf_loader.loadAndStart(fresh.buf, fresh.size, fresh.pages, fresh.inode, null)) |pid| {
                    var nlen = sc.cmd.len;
                    if (nlen >= 4 and sc.cmd[nlen - 4] == '.') nlen -= 4;
                    process.setName(@intCast(pid), sc.cmd[0..nlen]);
                    process.getPCB(pid).priority = .interactive;
                }
            }
        }
    }
    sound.open();
}

/// Wire a Terminal window to a freshly-spawned user-space shell:
///   - kb_pipe: desktop → shell stdin   (shell holds read-side, desktop holds write-side)
///   - out_pipe: shell → desktop stdout (shell holds write-side, desktop holds read-side)
/// The desktop's main loop drains `out_pipe` non-blocking each frame and feeds
/// it into the window's text buffer via `putCharOnWindow`. Keyboard handler
/// pushes keystrokes into `kb_pipe`. No new kernel primitive is needed — pipes
/// already do everything a TTY did, and the back-channel into the desktop
/// (out_pipe drain step) is a desktop concern, not a kernel one.
fn spawnShellOnWindow(wi: u8) void {
    const pipe = @import("../proc/pipe.zig");
    const kb_pipe = pipe.alloc() orelse {
        showNotification("Pipe pool full");
        return;
    };
    const out_pipe = pipe.alloc() orelse {
        pipe.closeReader(kb_pipe);
        pipe.closeWriter(kb_pipe);
        showNotification("Pipe pool full");
        return;
    };

    const fresh = @import("../fs/vfs.zig").loadFileFresh("app.elf") orelse {
        putStringOnWindow(wi, "shell: app.elf not found\n");
        pipe.closeReader(kb_pipe);
        pipe.closeWriter(kb_pipe);
        pipe.closeReader(out_pipe);
        pipe.closeWriter(out_pipe);
        return;
    };
    const pid_or_null = elf_loader.loadAndStart(fresh.buf, fresh.size, fresh.pages, fresh.inode, null);
    const pid = pid_or_null orelse {
        putStringOnWindow(wi, "shell: load failed\n");
        pipe.closeReader(kb_pipe);
        pipe.closeWriter(kb_pipe);
        pipe.closeReader(out_pipe);
        pipe.closeWriter(out_pipe);
        return;
    };

    process.setName(@intCast(pid), "shell");
    const pcb = process.getPCB(pid);
    pcb.priority = .interactive;

    // The shell owns: kb_pipe read-side (fd 0), out_pipe write-side (fd 1, fd 2).
    // The desktop owns: kb_pipe write-side, out_pipe read-side. Refcounts are
    // initialized to 1/1 by pipe.alloc(); no addReader/addWriter needed because
    // each end has exactly one owner.
    pcb.fd_table[0] = .{ .in_use = true, .fs_type = .pipe, .pipe_id = kb_pipe, .flags = 0 };
    pcb.fd_table[1] = .{ .in_use = true, .fs_type = .pipe, .pipe_id = out_pipe, .flags = 1 };
    pcb.fd_table[2] = .{ .in_use = true, .fs_type = .pipe, .pipe_id = out_pipe, .flags = 1 };

    windows[wi].kb_pipe = kb_pipe;
    windows[wi].out_pipe = out_pipe;
    windows[wi].shell_pid = @intCast(pid);
    // Event-driven compositor: out_pipe is drained by the desktop loop's
    // tryRead poll, not by a blocking read. Tell pipe.write to wake the
    // compositor when the shell writes to it; otherwise the desktop
    // sleeps through stdout bytes until something else (input, animation)
    // wakes it.
    pipe.setDesktopDrain(out_pipe);
}


// Boot splash extracted to desktop/splash.zig — the long animation
// loop is unrelated to anything else here.
const splash = @import("desktop/splash.zig");

fn fmtNum(buf: []u8, n: u32) void {
    var v = n;
    var i: usize = buf.len;
    while (i > 0) {
        i -= 1;
        buf[i] = '0' + @as(u8, @truncate(v % 10));
        v /= 10;
    }
}

fn roundSmallCorners(x: i32, y: i32, w: u32, h: u32, bg: u32) void {
    const bot: i32 = y + @as(i32, @intCast(h)) - 1;
    const right: i32 = x + @as(i32, @intCast(w)) - 1;
    // 2px radius: just knock off single corner pixels
    gfx.putPixel(x, y, bg);
    gfx.putPixel(x + 1, y, bg);
    gfx.putPixel(x, y + 1, bg);
    gfx.putPixel(right, y, bg);
    gfx.putPixel(right - 1, y, bg);
    gfx.putPixel(right, y + 1, bg);
    gfx.putPixel(x, bot, bg);
    gfx.putPixel(x + 1, bot, bg);
    gfx.putPixel(x, bot - 1, bg);
    gfx.putPixel(right, bot, bg);
    gfx.putPixel(right - 1, bot, bg);
    gfx.putPixel(right, bot - 1, bg);
}

// ─── Window drop-shadow geometry ────────────────────────────────────────────
// A soft "elevation" shadow on ALL FOUR sides, biased downward so the bottom
// reads heavier than the top (key light from above) — the macOS/material look,
// not the old right+bottom-only drop shadow. Shared by renderWindow (the blend),
// the dirty-rect, and the z-occlusion test so all three agree on the extent.
//
//   SHADOW_R    — reach in px beyond the window border (corners included)
//   SHADOW_OFFY — downward offset of the shadow caster; the bottom gains +OFFY
//                 of reach, the top loses OFFY of contact strength
//   SHADOW_PEAK — max alpha byte at contact (~13%); low enough that windows feel
//                 lifted (not glued) and stacked shadows don't muddy into black
const SHADOW_R = 22;
const SHADOW_OFFY = 6;
const SHADOW_PEAK = 0x22;
// One symmetric pad that over-covers the (asymmetric) shadow on every side —
// used by the dirty-rect and the occlusion test. Over-covering is harmless
// (a few extra wallpaper px get repainted/flushed); under-covering smears.
const SHADOW_SPAD: i32 = SHADOW_R + SHADOW_OFFY + @as(i32, BORDER) + 2;

// Precomputed at COMPILE time: shadow_lut[dy][dx] = alpha byte for a pixel that
// is (dx, dy) px from the (offset) window rect. Euclidean distance → naturally
// round corners; (1 − smoothstep) falloff → soft shoulder near the window and a
// clean vanish at the rim (no hard cut line). Building it at comptime keeps the
// runtime hot path free of sqrt/float, both slow-or-broken on the freestanding-
// baseline target (see the @floatFromInt / @floor freestanding gotchas).
const shadow_lut: [SHADOW_R + 1][SHADOW_R + 1]u8 = blk: {
    @setEvalBranchQuota(10000);
    var lut: [SHADOW_R + 1][SHADOW_R + 1]u8 = [_][SHADOW_R + 1]u8{[_]u8{0} ** (SHADOW_R + 1)} ** (SHADOW_R + 1);
    const r: f64 = SHADOW_R;
    for (0..SHADOW_R + 1) |dy| {
        for (0..SHADOW_R + 1) |dx| {
            const fx: f64 = @floatFromInt(dx);
            const fy: f64 = @floatFromInt(dy);
            const dist = @sqrt(fx * fx + fy * fy);
            if (dist < r) {
                const t = dist / r; // 0 at contact … 1 at the rim
                const fall = 1.0 - (3.0 * t * t - 2.0 * t * t * t); // 1 − smoothstep
                lut[dy][dx] = @intFromFloat(fall * @as(f64, SHADOW_PEAK));
            }
        }
    }
    break :blk lut;
};

/// Re-render every visible window above `target` in z-order whose outer
/// rect (including shadow) overlaps `target`. Called from partial-render
/// paths (`.gui_only`) after the target window has been stamped into the
/// back buffer — without this, the target's paint clobbers z-higher
/// neighbors in the overlap region because renderWindow doesn't itself
/// know about stacking order.
///
/// The shadow is now all-around (see SHADOW_* above), so the overlap test is
/// widened by SHADOW_SPAD on EVERY side, not just lower+right.
fn repaintZAboveOverlapping(target: u8) void {
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

fn renderWindow(idx: u8) void {
    const w = &windows[idx];
    if (!w.visible or w.minimized) return;
    const is_focused = (idx == wm.focused);

    // Maximized windows render through the same chrome path as normal
    // windows — they're just laid out in the usable area. The old
    // fullscreen-scaling shortcut here was the source of the "ruins
    // UI for non-Doom apps" complaint: scaling a 480-px window to
    // 1920 px gave blurry pixel slop. Now the app's framebuffer renders
    // at its own resolution (centered if alloc-capped) inside the
    // maximized window frame.

    // Mark this window's region (incl. the all-around soft shadow) dirty for
    // partial GPU flush. SHADOW_SPAD pads every side; clamp the origin to the
    // screen and let addDirtyRect clip the far edges.
    const sx0: i32 = w.x - SHADOW_SPAD;
    const sy0: i32 = w.y - SHADOW_SPAD;
    const ddx: u32 = if (sx0 < 0) 0 else @intCast(sx0);
    const ddy: u32 = if (sy0 < 0) 0 else @intCast(sy0);
    const span: u32 = @intCast(2 * SHADOW_SPAD);
    addDirtyRect(ddx, ddy, w.width + span, w.height + span);

    // Save corner pixels from back buffer BEFORE drawing (for transparent rounded corners)
    saveCornerPixels(w.x - @as(i32, BORDER), w.y - @as(i32, BORDER), w.width + BORDER * 2, w.height + BORDER * 2);

    // Soft "elevation" drop shadow on ALL FOUR sides, biased downward so the
    // bottom reads heavier than the top (key light from above). The shadow is
    // cast by the window+border rect shifted down by SHADOW_OFFY; per-pixel
    // alpha comes from the comptime shadow_lut keyed by the (dx,dy) distance to
    // that rect — Euclidean, so the corners round off naturally. See SHADOW_*.
    //
    // Gated on `w.shadow_dirty` so content-only redraws don't re-blend over the
    // previous frame's shadow (which would accumulate to black after ~30 frames
    // on a 60fps app like sysmon). Redrawn on every shadow_dirty frame (incl.
    // each drag step); the scalar per-pixel blend is bounded by the shadow-band
    // area and runs only here, never on content-only ticks.
    if (w.shadow_dirty) {
        const ol = w.x - @as(i32, BORDER);
        const ot = w.y - @as(i32, BORDER);
        const orr = w.x + @as(i32, @intCast(w.width)) + @as(i32, BORDER);
        const ob = w.y + @as(i32, @intCast(w.height)) + @as(i32, BORDER);
        const ct = ot + SHADOW_OFFY; // caster top/bottom (left/right unshifted)
        const cb = ob + SHADOW_OFFY;
        const tw: i32 = @intCast(gfx.target_w);
        const th: i32 = @intCast(gfx.target_h);

        var py: i32 = ct - SHADOW_R;
        while (py < cb + SHADOW_R) : (py += 1) {
            if (py < 0 or py >= th) continue;
            // vertical distance from the (offset) caster rect, 0 inside its span
            const dy_i: i32 = if (py < ct) ct - py else if (py >= cb) py - cb + 1 else 0;
            if (dy_i > SHADOW_R) continue;
            const row: u32 = @as(u32, @intCast(py)) * gfx.target_w;
            var px: i32 = ol - SHADOW_R;
            while (px < orr + SHADOW_R) : (px += 1) {
                if (px < 0 or px >= tw) continue;
                // Skip the window's own footprint — chrome paints over it below.
                if (px >= ol and px < orr and py >= ot and py < ob) continue;
                const dx_i: i32 = if (px < ol) ol - px else if (px >= orr) px - orr + 1 else 0;
                if (dx_i > SHADOW_R) continue;
                const a = shadow_lut[@intCast(dy_i)][@intCast(dx_i)];
                if (a == 0) continue;
                const off: u32 = row + @as(u32, @intCast(px));
                gfx.target[off] = gfx.blendPixel(gfx.target[off], @as(u32, a) << 24);
            }
        }
        w.shadow_dirty = false;
    }

    // Border (1px) — flashes red while a terminal's bell_phase counts down.
    const border_color: u32 = blk: {
        if (w.term) |t| if (t.bell_phase > 0) break :blk BELL_FLASH_COLOR;
        // Subtle hairline instead of a hard bright outline — a touch lighter
        // than the dark body (dark theme) or a soft grey (light theme). The
        // window reads as elevated via its shadow + AA corners, not a heavy
        // border. restoreCornerPixels reuses this for the rounded corner ring.
        break :blk if (conf.theme == 1) @as(u32, 0x3A3A3A) else @as(u32, 0xC0C0C0);
    };
    gfx.drawRect(w.x - @as(i32, BORDER), w.y - @as(i32, BORDER), w.width + BORDER * 2, w.height + BORDER * 2, border_color);

    // Title bar gradient. Focused windows get a brighter, more saturated
    // gradient + a 1px white-tint highlight on the top edge, evoking the
    // subtle bevel macOS uses to mark the active window. Unfocused windows
    // sit darker/flatter so the eye is drawn to the focused one.
    const tb_top: u32 = if (conf.theme == 1)
        (if (is_focused) @as(u32, 0x3F3F3F) else @as(u32, 0x252525))
    else
        (if (is_focused) @as(u32, 0xFAFAFA) else @as(u32, 0xCBCBCB));
    const tb_bot: u32 = if (conf.theme == 1)
        (if (is_focused) @as(u32, 0x2C2C2C) else @as(u32, 0x1F1F1F))
    else
        (if (is_focused) @as(u32, 0xE8E8E8) else @as(u32, 0xC0C0C0));
    {
        var row: u32 = 0;
        while (row < TITLEBAR_H) : (row += 1) {
            const c = background.lerpColor(tb_top, tb_bot, row, TITLEBAR_H);
            gfx.fillRect(w.x, w.y + @as(i32, @intCast(row)), w.width, 1, c);
        }
    }
    // Focus highlight — 1px bright bevel along the top edge of the active
    // window's titlebar. Subtle (white at ~20% alpha for dark theme, slightly
    // less for light), reads as "this window is alive".
    if (is_focused) {
        const hi_a: u32 = if (conf.theme == 1) @as(u32, 0x33000000) else @as(u32, 0x22000000);
        gfx.fillRectAlpha(w.x, w.y, w.width, 1, hi_a | 0x00FFFFFF);
    }
    // Separator line under titlebar — softer for unfocused windows.
    const sep_color: u32 = if (is_focused) @as(u32, 0xB0B0B0) else @as(u32, 0x707070);
    gfx.drawHLine(w.x, w.y + @as(i32, TITLEBAR_H) - 1, w.width, sep_color);

    // Traffic light buttons (macOS-style, left side). When the window is
    // unfocused they all turn a uniform muted gray — same trick macOS uses
    // to signal "input doesn't go here right now". The eye-catching red/
    // amber/green is reserved for the active window.
    const btn_cy = w.y + @as(i32, TITLEBAR_H / 2);
    const btn_close_col: u32 = if (is_focused) BTN_CLOSE else @as(u32, 0x636368);
    const btn_min_col: u32 = if (is_focused) BTN_MINIMIZE else @as(u32, 0x636368);
    const btn_max_col: u32 = if (is_focused) BTN_MAXIMIZE else @as(u32, 0x636368);
    gfx.drawFilledCircle(w.x + 16, btn_cy, BTN_RADIUS, btn_close_col);
    gfx.drawFilledCircle(w.x + 38, btn_cy, BTN_RADIUS, btn_min_col);
    gfx.drawFilledCircle(w.x + 60, btn_cy, BTN_RADIUS, btn_max_col);
    // Subtle upper specular so the lights read as soft glass beads rather than
    // flat discs — a faint white sheen biased upward (key light from above).
    const gloss_r: u32 = @max(BTN_RADIUS / 2, 2);
    const gloss_up: i32 = @as(i32, @intCast(BTN_RADIUS)) / 2;
    gfx.drawFilledCircleAlpha(w.x + 16, btn_cy - gloss_up, gloss_r, 0x38FFFFFF);
    gfx.drawFilledCircleAlpha(w.x + 38, btn_cy - gloss_up, gloss_r, 0x38FFFFFF);
    gfx.drawFilledCircleAlpha(w.x + 60, btn_cy - gloss_up, gloss_r, 0x38FFFFFF);

    // Centered title — SF Pro Display 24px AA. Title bar gradient is already
    // painted; aa_font draws via per-pixel alpha blend so we just stamp glyphs
    // on top.
    const text_color = if (conf.theme == 1)
        (if (is_focused) @as(u32, 0xEEEEEE) else @as(u32, 0x666666))
    else
        (if (is_focused) TITLEBAR_TEXT_F else TITLEBAR_TEXT_U);
    {
        const title_atlas = aa_font.getDefault24();
        const title_text = w.title[0..w.title_len];
        const title_px_w: u32 = title_atlas.measure(title_text);
        if (title_px_w < w.width) {
            const title_x = w.x + @as(i32, @intCast((w.width - title_px_w) / 2));
            // Center vertically inside the TITLEBAR_H slot. line_height ~29 vs
            // titlebar typically ~30; nudge by 2px so descenders don't clip.
            const title_y = w.y + @divTrunc(@as(i32, TITLEBAR_H) - @as(i32, @intCast(title_atlas.line_height)), 2);
            aa_font.drawText(title_x, title_y, title_text, text_color, title_atlas);
        }
    }

    // Content area
    const content_y = w.y + @as(i32, TITLEBAR_H);
    const content_h = w.height -| TITLEBAR_H;

    // Restore saved corner pixels — rounds the corners, tracing the white
    // chrome border around the arc (border_color drives the ring).
    restoreCornerPixels(w.x - @as(i32, BORDER), w.y - @as(i32, BORDER), w.width + BORDER * 2, w.height + BORDER * 2, border_color);

    // Read the published back buffer if the app has presented at least
    // once. Until then, read gui_fb directly so apps that never call
    // libc.present() still render. Apps that do present (cube) get
    // tear-free reads via the triple-buffer rotation.
    const pub_idx = w.gui_fb_pub.load(.acquire);
    const active_back: ?[*]volatile u32 = if (w.has_presented) w.gui_fb_backs[pub_idx] else w.gui_fb;
    if (w.gpu_slot != null) {
        // Phase 8: slot-backed window. The GPU compositor's per-window
        // draw samples the dmabuf directly and overlays it on top of
        // the backbuf in the same render pass that consumes the
        // backbuf for the background — so the CPU blit below would
        // just write pixels the GPU overdraws. Chrome (titlebar/
        // borders/shadow drawn earlier in this fn) stays in the
        // backbuf and shows via the background pass.
    } else if (active_back orelse w.gui_fb) |fb| {
        // GUI app window — blit the active kernel back buffer to the desktop
        // back buffer. Falls back to gui_fb only on legacy windows that
        // pre-date the triple-buffer change (none should exist post-
        // sysCreateWindow change; defensive fallback).

        // Source = the app's rendered content extent, capped to its FB
        // allocation (reading past it would walk into the next row through
        // the smaller stride).
        const src_w: u32 = if (w.gui_alloc_w > 0) @min(w.gui_w, w.gui_alloc_w) else w.gui_w;
        const src_h: u32 = if (w.gui_alloc_h > 0) @min(w.gui_h, w.gui_alloc_h) else w.gui_h;
        const stride = if (w.gui_alloc_w > 0) w.gui_alloc_w else w.gui_w;
        // Destination = the FULL window content area. When it equals the source
        // (normal/dragged window — drag is capped at the alloc) we blit 1:1:
        // crisp + fast (rep movsl). When it's larger (F10 maximize past the FB
        // alloc) we nearest-neighbor UPSCALE so the content fills the window
        // instead of sitting alloc-sized in the corner with wallpaper around it.
        // (cpu-comp path; the GPU compositor does the equivalent via uv_scale.)
        const dst_w: u32 = w.width;
        const dst_h: u32 = content_h;
        if (src_w != 0 and src_h != 0 and dst_w != 0 and dst_h != 0) {
            if (src_w == dst_w and src_h == dst_h) {
                var row: u32 = 0;
                while (row < dst_h) : (row += 1) {
                    const py = content_y + @as(i32, @intCast(row));
                    if (py < 0) continue;
                    if (py >= @as(i32, @intCast(gfx.target_h))) break;
                    if (w.x >= @as(i32, @intCast(gfx.target_w))) continue;
                    const dst_x: u32 = if (w.x < 0) 0 else @intCast(w.x);
                    const src_skip: u32 = if (w.x < 0) @intCast(-w.x) else 0;
                    const avail = gfx.target_w - dst_x;
                    const count = @min(dst_w -| src_skip, avail);
                    if (count == 0) continue;
                    const dst_off = @as(u32, @intCast(py)) * gfx.target_w + dst_x;
                    const src_off = row * stride + src_skip;
                    const dest = @intFromPtr(gfx.target) + dst_off * 4;
                    const src = @intFromPtr(fb) + src_off * 4;
                    asm volatile ("cld; rep movsl"
                        :
                        : [dst] "{rdi}" (dest),
                          [src] "{rsi}" (src),
                          [cnt] "{rcx}" (count),
                        : .{ .rdi = true, .rsi = true, .rcx = true, .memory = true }
                    );
                }
            } else {
                // Nearest-neighbor scale src→dst. 16.16 fixed-point sampled per
                // pixel (stateless, so the screen-edge `continue`/`break` clips
                // can't desync the source index) — no per-pixel divide and no
                // large stack buffer, keeping pid 2's kstack lean.
                const x_step: u32 = (src_w << 16) / dst_w;
                const y_step: u32 = (src_h << 16) / dst_h;
                var row: u32 = 0;
                while (row < dst_h) : (row += 1) {
                    const py = content_y + @as(i32, @intCast(row));
                    if (py < 0) continue;
                    if (py >= @as(i32, @intCast(gfx.target_h))) break;
                    const sy: u32 = @min((row * y_step) >> 16, src_h - 1);
                    const src_row: [*]volatile u32 = @ptrFromInt(@intFromPtr(fb) + @as(usize, sy) * stride * 4);
                    const dst_row_base = @as(u32, @intCast(py)) * gfx.target_w;
                    var col: u32 = 0;
                    while (col < dst_w) : (col += 1) {
                        const dx = w.x + @as(i32, @intCast(col));
                        if (dx < 0) continue;
                        if (dx >= @as(i32, @intCast(gfx.target_w))) break;
                        const sx: u32 = @min((col * x_step) >> 16, src_w - 1);
                        gfx.target[dst_row_base + @as(u32, @intCast(dx))] = src_row[sx];
                    }
                }
            }
        }
    } else if (w.term) |t| {
        // Terminal window — draw text buffer (with scrollback support)
        gfx.fillRect(w.x, content_y, w.width, content_h, WINDOW_BG);
        gfx.drawHLine(w.x, content_y, w.width, 0x151515);

        const max_rows = content_h / FONT_H;
        const max_cols = (w.width - TERM_PAD * 2) / FONT_W;

        if (t.scroll_view > 0 and t.scroll_count > 0) {
            // Scrolled-back view: show scrollback + text_buf
            var row: u32 = 0;
            while (row < max_rows) : (row += 1) {
                const total_lines = @as(u32, t.scroll_count) + @as(u32, t.text_row) + 1;
                const view_bottom = total_lines -| @as(u32, t.scroll_view);
                const view_top = view_bottom -| max_rows;
                const line_idx = view_top + row;
                if (line_idx >= total_lines) break;

                var line_ptr: []const u8 = undefined;
                var attr_ptr: []const u8 = undefined;
                var rgb_ptr: []const u32 = undefined;
                if (line_idx < t.scroll_count) {
                    const ring_idx = (@as(u32, t.scroll_write) + SCROLL_LINES - t.scroll_count + line_idx) % SCROLL_LINES;
                    line_ptr = t.scroll_buf[ring_idx * TERM_COLS ..][0..TERM_COLS];
                    attr_ptr = t.scroll_attr_buf[ring_idx * TERM_COLS ..][0..TERM_COLS];
                    rgb_ptr = t.scroll_fg_rgb_buf[ring_idx * TERM_COLS ..][0..TERM_COLS];
                } else {
                    const tb_row = line_idx - @as(u32, t.scroll_count);
                    if (tb_row < TERM_ROWS) {
                        line_ptr = t.text_buf[tb_row * TERM_COLS ..][0..TERM_COLS];
                        attr_ptr = t.attr_buf[tb_row * TERM_COLS ..][0..TERM_COLS];
                        rgb_ptr = t.fg_rgb_buf[tb_row * TERM_COLS ..][0..TERM_COLS];
                    } else {
                        continue;
                    }
                }

                var col: u32 = 0;
                while (col < TERM_COLS and col < max_cols) : (col += 1) {
                    const ch = line_ptr[col];
                    const attr = attr_ptr[col];
                    // Render anything that has a glyph OR a non-default bg
                    // (inverse mode paints the bg even on a space — fastfetch's
                    // memory bar and color swatches rely on this).
                    if (ch != ' ' or (attr & ATTR_INVERSE) != 0) {
                        const colors = cellColors(attr, rgb_ptr[col]);
                        drawTermChar(
                            w.x + @as(i32, @intCast(TERM_PAD + col * FONT_W)),
                            content_y + @as(i32, @intCast(row * FONT_H)),
                            ch,
                            colors.fg,
                            colors.bg,
                        );
                    }
                }
            }
            gfx.drawString(w.x + @as(i32, @intCast(w.width)) - 80, content_y + 2, "[PgDn]", 0x666688, WINDOW_BG);
        } else {
            // Live view (normal rendering): per-cell color from attr_buf.
            var row: u32 = 0;
            while (row < TERM_ROWS and row < max_rows) : (row += 1) {
                var col: u32 = 0;
                while (col < TERM_COLS and col < max_cols) : (col += 1) {
                    const cell_idx = row * TERM_COLS + col;
                    const ch = t.text_buf[cell_idx];
                    const attr = t.attr_buf[cell_idx];
                    if (ch != ' ' or (attr & ATTR_INVERSE) != 0) {
                        const colors = cellColors(attr, t.fg_rgb_buf[cell_idx]);
                        drawTermChar(
                            w.x + @as(i32, @intCast(TERM_PAD + col * FONT_W)),
                            content_y + @as(i32, @intCast(row * FONT_H)),
                            ch,
                            colors.fg,
                            colors.bg,
                        );
                    }
                }
            }

            // Text cursor — blink unless the user just typed / output just landed.
            if (is_focused and t.text_col < max_cols and t.text_row < max_rows) {
                const blink_on = ((process.tick_count -% t.cursor_blink_anchor) / CURSOR_BLINK_HALF_TICKS) & 1 == 0;
                if (blink_on) {
                    gfx.fillRect(
                        w.x + @as(i32, @intCast(TERM_PAD + @as(u32, t.text_col) * FONT_W)),
                        content_y + @as(i32, @intCast(@as(u32, t.text_row) * FONT_H)),
                        FONT_W,
                        FONT_H,
                        TERM_FG,
                    );
                }
            }
        }

        // Scrollbar
        const total_lines = @as(u32, t.scroll_count) + TERM_ROWS;
        if (t.scroll_count > 0) {
            const sb_x = w.x + @as(i32, @intCast(w.width)) - 3;
            gfx.fillRect(sb_x, content_y + 1, 2, content_h -| 1, 0x2A2A2A);
            const thumb_h = @max(content_h * max_rows / total_lines, 8);
            const scroll_pos = total_lines - @as(u32, t.scroll_view) -| max_rows;
            const track_h = content_h -| thumb_h;
            const thumb_y_off = if (total_lines > max_rows) scroll_pos * track_h / (total_lines - max_rows) else 0;
            gfx.fillRect(sb_x, content_y + @as(i32, @intCast(thumb_y_off)), 2, thumb_h, 0x555555);
        }
    }

    // Animation fade overlay
    if (w.anim_type != .none) {
        const frame: u32 = w.anim_frame;
        const total: u32 = w.anim_total;
        const fade_alpha: u32 = switch (w.anim_type) {
            .opening, .restoring, .unfullscreening => 255 -| (frame * 255 / (total + 1)),
            .closing, .minimizing, .fullscreening => frame * 255 / (total + 1),
            .none => 0,
        };
        if (fade_alpha > 0) {
            gfx.fillRectAlpha(w.x, w.y, w.width, w.height, (fade_alpha << 24));
        }
    }
}

/// Fast path: re-render only one terminal row + text cursor in the back buffer.
fn renderTerminalRow(idx: u8) void {
    const w = &windows[idx];
    const t = w.term orelse return;
    if (!w.visible or w.minimized) return;

    const content_y = w.y + @as(i32, TITLEBAR_H);
    const content_h = w.height -| TITLEBAR_H;
    const max_cols = (w.width - TERM_PAD * 2) / FONT_W;
    const max_rows = content_h / FONT_H;
    const row: u32 = @as(u32, t.text_row);
    if (row >= max_rows) return;

    const py: i32 = content_y + @as(i32, @intCast(row * FONT_H));

    // Clear the row background
    gfx.fillRect(w.x, py, w.width, FONT_H, WINDOW_BG);

    // Draw characters on this row, per-cell color from attr_buf.
    // Space cells render too when inverse mode is on, so colored bg shows
    // (used by fastfetch's truecolor bar via fg+inverse swap).
    var col: u32 = 0;
    while (col < TERM_COLS and col < max_cols) : (col += 1) {
        const cell_idx = row * TERM_COLS + col;
        const ch = t.text_buf[cell_idx];
        const attr = t.attr_buf[cell_idx];
        if (ch != ' ' or (attr & ATTR_INVERSE) != 0) {
            const colors = cellColors(attr, t.fg_rgb_buf[cell_idx]);
            drawTermChar(
                w.x + @as(i32, @intCast(TERM_PAD + col * FONT_W)),
                py,
                ch,
                colors.fg,
                colors.bg,
            );
        }
    }

    // Text cursor — blink unless the user just typed / output just landed.
    if (idx == wm.focused and t.text_col < max_cols) {
        const blink_on = ((process.tick_count -% t.cursor_blink_anchor) / CURSOR_BLINK_HALF_TICKS) & 1 == 0;
        if (blink_on) {
            gfx.fillRect(
                w.x + @as(i32, @intCast(TERM_PAD + @as(u32, t.text_col) * FONT_W)),
                py,
                FONT_W,
                FONT_H,
                TERM_FG,
            );
        }
    }
}

// --- Rounded corner masking ---
// Per-pixel alpha-coverage mask for an 8px-radius rounded corner. (0,0) is
// the outer corner (alpha=255 → fully bg). Pivot of the quarter-circle is
// at (R, R) — the deepest inner point. Supersampled 4×4 at comptime so
// edges fade smoothly instead of stair-stepping like the old corner_insets
// table did.
const CORNER_R: u32 = 8;
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

fn bgColorAt(y: i32) u32 {
    const start_y: i32 = if (conf.dock_pos == 1) @as(i32, TASKBAR_H) else 0;
    const rel_y = y - start_y;
    if (rel_y < 0) return background.bgTop();
    const h = gfx.screen_h - TASKBAR_H;
    if (@as(u32, @intCast(rel_y)) >= h) return background.bgBot();
    return background.lerpColor(background.bgTop(), background.bgBot(), @intCast(rel_y), h);
}

// Save the full CORNER_R × CORNER_R square at each of the 4 corners
// before drawing the window; restore via the alpha mask afterwards so
// edges blend smoothly with whatever is behind. 4 corners × 8×8 = 256 px.
const CORNER_BUF_PER: u32 = CORNER_R * CORNER_R;
var corner_save: [256]u32 = undefined;

fn saveCornerPixels(x: i32, y: i32, w: u32, h: u32) void {
    const right: i32 = x + @as(i32, @intCast(w)) - 1;
    const bot: i32 = y + @as(i32, @intCast(h)) - 1;
    const corners = [_][2]i32{ .{ x, y }, .{ right, y }, .{ x, bot }, .{ right, bot } };
    const x_dirs = [_]i32{ 1, -1, 1, -1 };
    const y_dirs = [_]i32{ 1, 1, -1, -1 };
    for (0..4) |c| {
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

fn restoreCornerPixels(x: i32, y: i32, w: u32, h: u32, border_color: u32) void {
    const right: i32 = x + @as(i32, @intCast(w)) - 1;
    const bot: i32 = y + @as(i32, @intCast(h)) - 1;
    const corners = [_][2]i32{ .{ x, y }, .{ right, y }, .{ x, bot }, .{ right, bot } };
    const x_dirs = [_]i32{ 1, -1, 1, -1 };
    const y_dirs = [_]i32{ 1, 1, -1, -1 };
    const br_r = (border_color >> 16) & 0xFF;
    const br_g = (border_color >> 8) & 0xFF;
    const br_b = border_color & 0xFF;
    for (0..4) |c| {
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
    // Flush erased region for virtio-gpu
    if (gfx.post_blit_fn != null) {
        const virtio_gpu = @import("../driver/virtio_gpu.zig");
        virtio_gpu.flushRect(cx, cy, CURSOR_W, CURSOR_H);
    }
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
    // Flush cursor region for virtio-gpu (direct writes need explicit flush)
    if (gfx.post_blit_fn != null) {
        const cx: u32 = if (mx < 0) 0 else @intCast(mx);
        const cy: u32 = if (my < 0) 0 else @intCast(my);
        const virtio_gpu = @import("../driver/virtio_gpu.zig");
        virtio_gpu.flushRect(cx, cy, CURSOR_W, CURSOR_H);
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

const KEY_UP = keyboard.KEY_UP;
const KEY_DOWN = keyboard.KEY_DOWN;

/// Returns true if full re-render needed (Enter/scroll/history), false for row-only.
fn handleKeyboard(w: *Window, ch: u8) bool {
    // Reset blink so the cursor stays visible right after a keystroke.
    if (w.term) |tt| tt.cursor_blink_anchor = process.tick_count;
    // Shell-attached terminal: keypresses go straight to the user-space shell
    // via its stdin pipe. The shell does its own echo, line editing, history,
    // prompt. PgUp/PgDn still scroll the kernel-side scrollback buffer (a
    // desktop affordance, not part of the shell's stdin contract).
    if (w.kb_pipe != 0xFF) {
        if (ch == keyboard.KEY_PGUP) {
            const content_h = w.height -| TITLEBAR_H;
            const max_rows: u16 = @intCast(content_h / FONT_H);
            const step = if (max_rows > 2) max_rows - 2 else 1;
            if (w.term) |tt| tt.scroll_view = @min(tt.scroll_view + step, tt.scroll_count);
            return true;
        } else if (ch == keyboard.KEY_PGDN) {
            const content_h = w.height -| TITLEBAR_H;
            const max_rows: u16 = @intCast(content_h / FONT_H);
            const step = if (max_rows > 2) max_rows - 2 else 1;
            if (w.term) |tt| tt.scroll_view -|= step;
            return true;
        }
        // Reset scroll on any other input — feels right for a shell.
        if (w.term) |tt| tt.scroll_view = 0;
        // Forward typeable bytes + line-editing keys to the shell's stdin.
        // The shell does its own readline (cursor moves, history, tab
        // completion), so arrows / Home / End / Delete must reach it.
        // Function keys (0x90+) stay desktop-only — they're global shortcuts.
        // PgUp / PgDn already returned above (kernel-side scrollback).
        const is_printable = ch >= 0x20 and ch <= 0x7E;
        const is_line_edit = ch == '\n' or ch == '\r' or ch == '\t' or ch == '\x08' or ch == 0x03 or ch == 0x1B;
        const is_nav = ch == keyboard.KEY_UP or ch == keyboard.KEY_DOWN or
            ch == keyboard.KEY_LEFT or ch == keyboard.KEY_RIGHT or
            ch == keyboard.KEY_HOME or ch == keyboard.KEY_END or
            ch == keyboard.KEY_DELETE;
        if (!is_printable and !is_line_edit and !is_nav) return false;
        const buf = [_]u8{ch};
        const written = @import("../proc/pipe.zig").tryWrite(w.kb_pipe, &buf);
        if (written == 0) {
            // pipe full / closed — char dropped before reaching shell
            dbg_kbpipe_drop +%= 1;
            if (process.tick_count -% dbg_last_kbpipe_log >= 100) {
                dbg_last_kbpipe_log = process.tick_count;
                debug.klog("[kbd-drop] kb_pipe write dropped pid={d} pipe_id={d} ch=0x{X} drops={d}\n", .{
                    w.shell_pid, w.kb_pipe, ch, dbg_kbpipe_drop,
                });
            }
        }
        return false;
    }

    const t = w.term orelse return false;
    if (ch == '\n') {
        t.scroll_view = 0;
        t.text_col = 0;
        t.text_row += 1;
        if (t.text_row >= TERM_ROWS) scrollWindow(w);
        if (t.cmd_len > 0) {
            const hi = t.history_count % 8;
            const safe_len = @min(t.cmd_len, 127);
            @memcpy(t.history[hi][0..safe_len], t.cmd_buf[0..safe_len]);
            t.history_len[hi] = safe_len;
            t.history_count +%= 1;
            t.history_idx = t.history_count;
            redirect_win = w;
            vga.redirect_fn = &desktopPutChar;
            cli.execute(t.cmd_buf[0..t.cmd_len]);
            vga.redirect_fn = null;
            redirect_win = null;
        }
        t.cmd_len = 0;
        termPrompt(w);
        return true;
    } else if (ch == '\x08') {
        if (t.cmd_len > 0) {
            t.cmd_len -= 1;
            if (t.text_col > 0) {
                t.text_col -= 1;
                if (textIdx(t.text_row, t.text_col)) |idx| t.text_buf[idx] = ' ';
            }
        }
        return false;
    } else if (ch == KEY_UP) {
        if (t.history_count > 0 and t.history_idx > 0) {
            t.history_idx -= 1;
            const hi = t.history_idx % 8;
            recallHistory(w, hi);
        }
        return true;
    } else if (ch == KEY_DOWN) {
        if (t.history_idx < t.history_count) {
            t.history_idx += 1;
            if (t.history_idx < t.history_count) {
                const hi = t.history_idx % 8;
                recallHistory(w, hi);
            } else {
                clearCurrentLine(w);
                t.cmd_len = 0;
            }
        }
        return true;
    } else if (ch == 0x09) {
        if (t.cmd_len >= 4 and std.mem.eql(u8, t.cmd_buf[0..4], "run ")) {
            const prefix = t.cmd_buf[4..t.cmd_len];
            var names: [8][32]u8 = undefined;
            var name_lens: [8]u8 = undefined;
            const count = tarfs.matchPrefix(prefix, &names, &name_lens);
            if (count == 1) {
                const name = names[0][0..name_lens[0]];
                if (name.len > prefix.len) {
                    const remaining = name[prefix.len..];
                    for (remaining) |c| {
                        if (t.cmd_len < 127 and t.text_col < TERM_COLS) {
                            t.cmd_buf[t.cmd_len] = c;
                            t.cmd_len += 1;
                            if (textIdx(t.text_row, t.text_col)) |ti| t.text_buf[ti] = c;
                            t.text_col += 1;
                        }
                    }
                }
            } else if (count > 1) {
                t.text_col = 0;
                t.text_row += 1;
                if (t.text_row >= TERM_ROWS) scrollWindow(w);
                var mi: u8 = 0;
                while (mi < count) : (mi += 1) {
                    for (names[mi][0..name_lens[mi]]) |c| {
                        if (t.text_col < TERM_COLS) {
                            if (textIdx(t.text_row, t.text_col)) |ti| t.text_buf[ti] = c;
                            t.text_col += 1;
                        }
                    }
                    if (t.text_col + 1 < TERM_COLS) {
                        if (textIdx(t.text_row, t.text_col)) |ti| t.text_buf[ti] = ' ';
                        t.text_col += 1;
                    }
                }
                t.text_col = 0;
                t.text_row += 1;
                if (t.text_row >= TERM_ROWS) scrollWindow(w);
                termPrompt(w);
                for (t.cmd_buf[0..t.cmd_len]) |c| {
                    if (t.text_col < TERM_COLS) {
                        if (textIdx(t.text_row, t.text_col)) |ti| t.text_buf[ti] = c;
                        t.text_col += 1;
                    }
                }
            }
        }
        return true;
    } else if (ch == keyboard.KEY_PGUP) {
        const content_h = w.height -| TITLEBAR_H;
        const max_rows: u16 = @intCast(content_h / FONT_H);
        const step = if (max_rows > 2) max_rows - 2 else 1;
        t.scroll_view = @min(t.scroll_view + step, t.scroll_count);
        return true;
    } else if (ch == keyboard.KEY_PGDN) {
        const content_h = w.height -| TITLEBAR_H;
        const max_rows: u16 = @intCast(content_h / FONT_H);
        const step = if (max_rows > 2) max_rows - 2 else 1;
        t.scroll_view -|= step;
        return true;
    } else if (ch >= 0x20 and ch < 0x7F) {
        t.scroll_view = 0;
        if (t.cmd_len < 127 and t.text_col < TERM_COLS) {
            t.cmd_buf[t.cmd_len] = ch;
            t.cmd_len += 1;
            if (textIdx(t.text_row, t.text_col)) |idx| t.text_buf[idx] = ch;
            t.text_col += 1;
        }
        return false;
    }
    return false;
}

fn recallHistory(w: *Window, hi: u8) void {
    const t = w.term orelse return;
    clearCurrentLine(w);
    const len = t.history_len[hi];
    t.cmd_len = len;
    @memcpy(t.cmd_buf[0..len], t.history[hi][0..len]);
    const prompt_len: u16 = 12;
    var col: u16 = 0;
    while (col < len) : (col += 1) {
        if (textIdx(t.text_row, prompt_len + col)) |idx| t.text_buf[idx] = t.cmd_buf[col];
    }
    t.text_col = prompt_len + @as(u16, len);
}

fn clearCurrentLine(w: *Window) void {
    const t = w.term orelse return;
    const prompt_len: u16 = 12;
    var col: u16 = prompt_len;
    while (col < TERM_COLS) : (col += 1) {
        if (textIdx(t.text_row, col)) |idx| t.text_buf[idx] = ' ';
    }
    t.text_col = prompt_len;
    t.cmd_len = 0;
}

const DirtyKind = enum { none, cursor_only, text_only, drag, full, gui_only };

// --- Context menu ---

fn executeMenuItem(idx: i8) void {
    if (idx < 0) return;
    switch (context_menu.ctx) {
        .desktop_bg => switch (@as(u8, @intCast(idx))) {
            0 => { // New Terminal
                // window_count is u8; widen before the multiply or `9 * 30 = 270`
        // overflows u8 arithmetic and Zig's runtime safety panics.
        const off: i32 = @intCast(@as(u32, wm.window_count) * 30);
                const nw: u32 = TERM_COLS * FONT_W + BORDER * 2;
                const nh: u32 = TERM_ROWS * FONT_H + TITLEBAR_H;
                if (createWindow("Terminal", 80 + off, 40 + off, nw, nh)) |ni| {
                    setFocused(ni);
                    termPrompt(&windows[ni]);
                }
            },
            1 => { // Run App...
                // window_count is u8; widen before the multiply or `9 * 30 = 270`
        // overflows u8 arithmetic and Zig's runtime safety panics.
        const off: i32 = @intCast(@as(u32, wm.window_count) * 30);
                const nw: u32 = TERM_COLS * FONT_W + BORDER * 2;
                const nh: u32 = TERM_ROWS * FONT_H + TITLEBAR_H;
                if (createWindow("Terminal", 80 + off, 40 + off, nw, nh)) |ni| {
                    setFocused(ni);
                    termPrompt(&windows[ni]);
                    if (windows[ni].term) |nt| {
                        const pre = "run ";
                        for (pre) |c| {
                            nt.cmd_buf[nt.cmd_len] = c;
                            nt.cmd_len += 1;
                            if (textIdx(nt.text_row, nt.text_col)) |ti|
                                nt.text_buf[ti] = c;
                            nt.text_col += 1;
                        }
                    }
                }
            },
            2 => { // Arrange Icons — snap any displaced shortcut back to grid
                shortcuts.resetPositions();
                markDirtyFull();
            },
            3 => showNotification("ZigOS v0.1 - Zig 0.13.0 x86"),
            else => {},
        },
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
fn publishMouseToFocused(prev_btns: u8) void {
    if (!slot_used[wm.focused]) return;
    const w = &windows[wm.focused];
    if (!w.visible or w.minimized) return;

    // Translate to window-local coordinates: x relative to window left,
    // y relative to content-area top (i.e. below the titlebar). Matches
    // `getMouseRelative` so apps that mix `pollEvent` with the legacy
    // `getMouse` syscall see consistent values.
    const cur_btns = mouse.buttons;
    const rel_x: i32 = mouse.x - w.x;
    const rel_y: i32 = mouse.y - (w.y + @as(i32, TITLEBAR_H));
    const cur_x: u32 = @bitCast(rel_x);
    const cur_y: u32 = @bitCast(rel_y);

    if (mouse.moved) {
        w.events.push(.{
            .kind = @intFromEnum(EventKind.mouse_move),
            .a = cur_x,
            .b = cur_y,
            .c = cur_btns,
        });
    }

    // Per-button transitions. Three buttons, low 3 bits.
    const changed: u8 = cur_btns ^ prev_btns;
    inline for ([_]u8{ 0, 1, 2 }) |btn_idx| {
        const mask: u8 = @as(u8, 1) << btn_idx;
        if ((changed & mask) != 0) {
            const pressed: u8 = if ((cur_btns & mask) != 0) 1 else 0;
            const a: u32 =
                @as(u32, btn_idx) |
                (@as(u32, pressed) << 8) |
                (@as(u32, cur_btns) << 16);
            w.events.push(.{
                .kind = @intFromEnum(EventKind.mouse_button),
                .a = a,
                .b = cur_x,
                .c = cur_y,
            });
        }
    }

    if (mouse.wheel != 0) {
        const delta_u32: u32 = @bitCast(@as(i32, mouse.wheel));
        w.events.push(.{
            .kind = @intFromEnum(EventKind.mouse_wheel),
            .a = delta_u32,
            .b = cur_x,
            .c = cur_y,
        });
    }
}

fn handleMouseEvents() DirtyKind {
    const mx = mouse.x;
    const my = mouse.y;
    const btn = mouse.buttons;
    const left_down = (btn & 1) != 0;
    const was_down = (prev_buttons & 1) != 0;
    const right_down = (btn & 2) != 0;
    const right_was = (prev_buttons & 2) != 0;
    var result: DirtyKind = .none;

    // Mouse-wheel scroll: route to terminal window under cursor (or focused
    // terminal if not directly hovered). 3 lines per notch.
    if (mouse.wheel != 0) {
        const w_delta = mouse.wheel;
        mouse.wheel = 0;
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
                result = .full;
            }
        }
    }

    // Context menu: dismiss on left-click, track hover
    if (context_menu.active) {
        if (context_menu.updateHover(mx, my)) result = .full;
        if (left_down and !was_down) {
            executeMenuItem(context_menu.itemAt(mx, my));
            context_menu.close();
            result = .full;
            prev_buttons = btn;
            return result;
        }
        if (right_down and !right_was) {
            context_menu.close();
            result = .full;
            // Fall through to open new menu below
        } else {
            prev_buttons = btn;
            return result;
        }
    }

    // Right-click: open context menu
    if (right_down and !right_was) {
        if (dock.inDockZone(my)) {
            // Dock — no context menu
        } else if (windowAt(mx, my)) |idx| {
            if (isInTitlebar(idx, mx, my)) {
                context_menu.open(.titlebar, mx, my, idx);
                result = .full;
            }
        } else {
            context_menu.open(.desktop_bg, mx, my, 0);
            result = .full;
        }
    }

    if (left_down and !was_down) {
        // A window covering the click position takes priority over the
        // dock — fullscreen apps (e.g. doom at 640×400 dragged over the
        // dock strip) would otherwise have their clicks eaten by dock
        // shortcut hit-testing, silently launching pinned apps.
        const window_hit = windowAt(mx, my);
        if (window_hit == null and dock.inDockZone(my)) {
            if (dock.clickAt(mx)) |action| {
                switch (action) {
                    .shortcut => |si| launchShortcut(si),
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
                // Drag-on-maximized = restore + drag, like macOS/Win.
                // Computing drag_ox/oy from saved geometry keeps the
                // cursor inside the titlebar after the restore so
                // there's no visual snap.
                if (windows[idx].fullscreen) {
                    toggleFullscreen(idx);
                    const restore_w = windows[idx].saved_w;
                    drag_ox = @as(i32, @intCast(restore_w / 2));
                    drag_oy = @as(i32, TITLEBAR_H / 2);
                    windows[idx].x = mx - drag_ox;
                    windows[idx].y = my - drag_oy;
                } else {
                    drag_ox = mx - windows[idx].x;
                    drag_oy = my - windows[idx].y;
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
        dragging = false;
        // If a resize was in progress, publish a resize event with the
        // final dimensions before clearing state. Apps that do
        // resolution-dependent layout work see the new size and can
        // reflow without polling getWindowSize every frame.
        if (resizing and resize_win < MAX_WINDOWS and slot_used[resize_win]) {
            const rw = &windows[resize_win];
            rw.events.push(.{
                .kind = @intFromEnum(EventKind.resize),
                .a = rw.width,
                .b = rw.height,
            });
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

    if (dragging and left_down) {
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
            windows[drag_win].x = new_x;
            windows[drag_win].y = new_y;
            if (result != .full) result = .drag;
            markDirtyFull();
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

fn changeResolution(new_w: u16, new_h: u16) void {
    const virtio_gpu = @import("../driver/virtio_gpu.zig");

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
    // (heap moved to the physmap), src/ui/vga.zig (VGA buffer), and the
    // driver/walker sweep done in Phase 2. Per-process address spaces own
    // their own PML4[0] independently, so user processes are unaffected.
    @import("../mm/paging.zig").dropLowIdentity();
    // BSP is now off the UEFI low-half boot stack; safe to enable SMAP
    // (kstack is high-VA / U/S=0, so the next push won't #PF).
    @import("../cpu/arch/protect.zig").enableSmapPerCpu();
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
    @import("../driver/nvme.zig").enableAsync();
    run();
    asm volatile ("ud2");
    unreachable;
}

pub fn run() void {
    @import("../cpu/smp.zig").assertBSP("desktop.run");
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
    @import("vga.zig").bg = .Black;
    @import("vga.zig").fg = .Black;
    @import("vga.zig").clear();
    @import("vga.zig").available = false;

    const virtio_gpu = @import("../driver/virtio_gpu.zig");

    // Try virtio-gpu first, fallback to BGA
    var disp_w: u32 = 0;
    var disp_h: u32 = 0;
    if (virtio_gpu.init(1920, 1080)) {
        disp_w = virtio_gpu.width;
        disp_h = virtio_gpu.height;
        gfx.setScreen(virtio_gpu.framebuffer, disp_w, disp_h);
        gfx.post_blit_fn = &virtio_gpu.flush;
        debug.klog("[desktop] Using virtio-gpu {d}x{d}\n", .{ disp_w, disp_h });
    } else if (bga.init(1280, 720)) {
        // Pull dimensions from the BGA device — `gfx.screen_w` is still 0 here
        // because setScreen hasn't run yet. Reading it gave (0,0), which then
        // propagated through showSplash's centering math (`(sw - logo_w) / 2`)
        // and overflowed in ReleaseSafe right at boot.
        disp_w = bga.width;
        disp_h = bga.height;
        gfx.setScreen(bga.framebuffer, disp_w, disp_h);
        debug.klog("[desktop] Using BGA {d}x{d}\n", .{ disp_w, disp_h });
    } else {
        vga.fg = .LightRed;
        vga.print("No display available!\n", .{});
        vga.fg = .LightGray;
        return;
    }

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
        @import("../driver/virtio_gpu.zig").skip_external_flush = true;
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
    @import("../driver/pci.zig").logUnbound();

    // Spawn wallpaper.elf as a one-shot — reads /etc/zigos.conf, decodes
    // the configured image via stb_image, pushes pixels to the kernel via
    // sysSetWallpaper, exits. If no wallpaper is configured (or the file
    // is missing), it bails silently and the gradient stays. Fire-and-
    // forget: we don't await it so a slow decode doesn't block boot.
    if (@import("../fs/vfs.zig").loadFileFresh("wallpaper.elf")) |fresh| {
        if (elf_loader.loadAndStart(fresh.buf, fresh.size, fresh.pages, fresh.inode, null)) |wpid| {
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

    // Apply persisted UI config from /etc/zigos.conf (theme, dock, etc.).
    // Done before splash so the splash colors / theme reflect the user's
    // saved preference rather than the compile-time defaults.
    conf.load();

    // Boot splash
    splash.show(backbuf != null);

    const win_w: u32 = TERM_COLS * FONT_W + BORDER * 2;
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
    const use_hw_cursor = @import("../driver/virtio_gpu.zig").hw_cursor_active;

    renderScene();
    if (backbuf != null) {
        if (!use_hw_cursor) bakeCursorToBackBuffer();
        gfx.blitToScreen();
        if (!use_hw_cursor) unbakeCursorFromBackBuffer();
    }
    if (@import("../driver/virtio_gpu.zig").active) @import("../driver/virtio_gpu.zig").flush();

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
        // Clear event-driven wake flags. We're running because either
        // wake.isDue() told the timer to switch us in (atomic flag /
        // self-wake due), or one of the input checks fired. Either way,
        // we own this iteration — drain both channels before doing any
        // work so producers during the iteration re-arm cleanly for the
        // next wake.
        wake.consume();
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
        // the timer decides the desktop needs attention (input, periodic render)
        last_desktop_tick = process.tick_count;
        yieldToScheduler();

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

        // Toast: advance the slide-in / countdown one tick.
        if (toast.tick()) dirty_rects_mod.force_full_kind = true;
        // Toast keeps animating until its timer drains — request a
        // self-wake so the next tick brings us back to advance the
        // slide-in / fade-out. ~2 ticks (~50 Hz) is plenty for a 200-
        // frame countdown; 1 tick would be 100 Hz, more than needed.
        if (toast.isActive()) wake.requestSelfWake(process.tick_count + 2);

        // Reset mouse transfer ring if watchdog flagged it (must run outside IRQ)
        if (xhci.mouse_needs_reset) {
            xhci.resetMouseRing();
        }

        var dirty: DirtyKind = if (dirty_rects_mod.force_full_kind) .full else .none;
        // `force_full_kind` semantically means "the previous frame painted
        // something that won't be tracked by this frame's renderScene"
        // (animation completion, toast expiry, resolution change, etc.).
        // Mark the rect tracker full so the .full path falls back to full
        // blit instead of partial — partial would miss pixels where the
        // disappearing element used to live (closing-window halo, etc.).
        if (dirty_rects_mod.force_full_kind) markDirtyFull();
        dirty_rects_mod.force_full_kind = false;
        // Context menu and tooltips must use full render (gui_only blits would overwrite parts)
        if (context_menu.active) dirty = .full;
        if (dock.isTooltipVisible()) dirty = .full;

        // Cursor blink edge: when tick_count crosses a blink half-period
        // boundary and the focused window is a terminal, mark dirty so the
        // cursor cell repaints. Driven by ticks (real time) rather than
        // frame_count so the blink rate is independent of how often the
        // desktop loop wakes (~12.5Hz idle vs higher when busy).
        if (slot_used[wm.focused] and windows[wm.focused].term != null and !windows[wm.focused].minimized) {
            const curr_phase = process.tick_count / CURSOR_BLINK_HALF_TICKS;
            if (curr_phase != last_blink_phase) {
                last_blink_phase = curr_phase;
                if (dirty == .none) dirty = .text_only;
            }
            // Self-wake at the start of the next half-period so the blink
            // toggle fires on time even with no other compositor activity.
            const next_phase_tick = (curr_phase + 1) * CURSOR_BLINK_HALF_TICKS;
            wake.requestSelfWake(next_phase_tick);
        }

        // Bell flash: each terminal with a non-zero bell_phase counts down
        // one frame; while active, mark dirty=.full so the red border re-renders.
        var any_bell_active = false;
        for (z_stack[0..wm.z_count]) |wi| {
            if (windows[wi].term) |tt| {
                if (tt.bell_phase > 0) {
                    tt.bell_phase -= 1;
                    dirty = .full;
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
                // DBG: pre-push queue depth (tail to head distance).
                const pre_count: u8 = (w.events.head -% w.events.tail) & 31;
                w.events.push(.{ .kind = kind, .a = ch, .b = mods });
                const post_count: u8 = (w.events.head -% w.events.tail) & 31;
                // Wake any io_uring OP_POLL waiters on a console fd. We
                // can't filter by which pid owns the focused window here
                // (fdpoll's wake walk does pollMaskConsole, which re-runs
                // the focus/visibility/owner check), so the broadcast
                // (.console, 0xFFFF) lets the matcher do its job.
                if (post_count != pre_count) {
                    @import("../cpu/ipc/fdpoll.zig").wakePollers(.console, 0xFFFF);
                }
                if (pre_count == post_count) {
                    // push() did NOT advance head — queue full, event dropped
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
                    if (ch == 0x1B) continue; // ESC: terminals ignore
                    if (ch == 0x14) { // Ctrl+T: spawn new terminal
                        // window_count is u8; widen before the multiply or `9 * 30 = 270`
        // overflows u8 arithmetic and Zig's runtime safety panics.
        const off: i32 = @intCast(@as(u32, wm.window_count) * 30);
                        const nw: u32 = TERM_COLS * FONT_W + BORDER * 2;
                        const nh: u32 = TERM_ROWS * FONT_H + TITLEBAR_H;
                        if (createWindow("Terminal", 80 + off, 40 + off, nw, nh)) |ni| {
                            setFocused(ni);
                            termPrompt(&windows[ni]);
                            dirty = .full;
                        }
                    } else {
                        const needs_full = handleKeyboard(w, ch);
                        if (needs_full) dirty = .full else if (dirty != .full) dirty = .text_only;
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
        if (cursor_moved or mouse.buttons != prev_buttons or mouse.wheel != 0) {
            publishMouseToFocused(prev_buttons);
            mouse.moved = false;
            const mr = handleMouseEvents();
            switch (mr) {
                .full => dirty = .full,
                .drag => {
                    if (dirty != .full) dirty = .drag;
                },
                else => {},
            }
            if (cursor_moved and dirty == .none) dirty = .cursor_only;
        }

        // Dock hover tracking for tooltips
        if (cursor_moved and dock.updateHover(mouse.x, mouse.y)) dirty = .full;

        // Drain stdout pipes for every shell-attached terminal window. The
        // shell process writes via libc.print → fwrite(1) → pipe.write into
        // out_pipe; we pull bytes back here non-blocking and feed them into
        // the window's text buffer. This is the desktop's side of the
        // "TTY-as-two-pipes" architecture: no kernel TTY primitive, just a
        // pair of generic byte streams plus this drain step.
        //
        // dirty=.full (not .text_only) because drained bytes can span
        // multiple rows — `ls`'s newline-separated output, wc's "N bytes
        // M lines\n", etc. — and .text_only only redraws the row at
        // text_row, leaving earlier rows blank until the next full repaint.
        {
            const pipe = @import("../proc/pipe.zig");
            var drain_buf: [256]u8 = undefined;
            for (z_stack[0..wm.z_count]) |wi| {
                const w = &windows[wi];
                if (w.out_pipe == 0xFF) continue;
                while (true) {
                    const got = pipe.tryRead(w.out_pipe, &drain_buf);
                    if (got == 0) break;
                    for (drain_buf[0..got]) |c| putCharOnWindow(w, c);
                    dirty = .full;
                    if (got < drain_buf.len) break;
                }
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
            advanceAnimations();
            dirty = .full;
            markDirtyFull();
            // Animations want a follow-up frame as long as any is still
            // ticking. Pace at 1 tick (~100 Hz upper bound; on 100 Hz
            // timer that's "every frame"). Animation totals are short
            // (~6 frames) so this drains in <100 ms.
            if (hasActiveAnimations()) wake.requestSelfWake(process.tick_count + 1);
        }

        // Auto-refresh: mark all visible GUI windows for re-composite every frame
        gui_windows_active = hasGuiWindows();
        if (gui_windows_active) {
            // Auto-refresh fallback for apps that don't call sysPresent
            // (sysmon, settings, etc.). Throttled per-window to ~20 Hz
            // so a flurry of compositor wakes (cursor blink, mouse
            // hover, keyboard input) doesn't trigger a re-composite +
            // virtio-gpu flush of every GUI window each time. Apps that
            // DO call sysPresent bypass this entirely — markGuiPresent
            // sets gui_present_pending directly without consulting the
            // throttle, so cube / fastfetch / anything performance-
            // sensitive still gets full submission rate.
            //
            // Threshold: 5 ticks ≈ 50 ms ≈ 20 Hz. Sysmon's actual
            // content updates at 2 Hz so 20 Hz is 10× more than needed;
            // mouse hover-tracking-against-GUI-apps still feels instant.
            const AUTO_REFRESH_INTERVAL_TICKS: u64 = 5;
            for (z_stack[0..wm.z_count]) |gi| {
                const w = &windows[gi];
                if (w.gui_fb == null or !w.visible) continue;
                if (process.tick_count -% w.last_auto_refresh_tick >= AUTO_REFRESH_INTERVAL_TICKS) {
                    w.gui_present_pending = true;
                    w.last_auto_refresh_tick = process.tick_count;
                }
            }
        }

        // Re-composite GUI windows that need it
        if (gui_windows_active) {
            for (z_stack[0..wm.z_count]) |gi| {
                if (windows[gi].gui_present_pending and windows[gi].visible) {
                    windows[gi].gui_present_pending = false;
                    const w = &windows[gi];
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

        // Hardware cursor: just move, no framebuffer interaction
        if (use_hw_cursor) {
            const vgpu_cur = @import("../driver/virtio_gpu.zig");
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

        // Render based on what changed
        const vgpu = @import("../driver/virtio_gpu.zig");
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
                    if (vgpu.active) vgpu.flush();
                    resetDirtyRects();
                },
                .drag => {
                    // Window drag — full re-render needed to repaint background behind old position
                    renderScene();
                    if (!use_hw_cursor) bakeCursorToBackBuffer();
                    gfx.blitToScreen();
                    if (!use_hw_cursor) unbakeCursorFromBackBuffer();
                    if (vgpu.active) vgpu.flush();
                    resetDirtyRects();
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
                    if (vgpu.active) {
                        if (dr_count > 0) {
                            var di: u8 = 0;
                            while (di < dr_count) : (di += 1) {
                                const r = dirty_rects_mod.getRect(di);
                                vgpu.flushRect(r[0], r[1], r[2], r[3]);
                            }
                        } else {
                            vgpu.flush();
                        }
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
                            if (vgpu.active) vgpu.flushRect(0, uy, gfx.screen_w, FONT_H);
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
                        if (vgpu.active) {
                            const wy: u32 = if (cw.y < 0) 0 else @intCast(cw.y);
                            vgpu.flushRect(0, wy, gfx.screen_w, cw.height + TITLEBAR_H + 8);
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
                        if (vgpu.active) vgpu.flush();
                    }
                    // Hardware cursor: nothing to flush (moveCursor already sent)
                },
                .none => {},
            }
        } else if (dirty != .none) {
            renderScene();
            if (swCursorActive(use_hw_cursor)) drawCursorOnScreen();
            if (vgpu.active) vgpu.flush();
        }

    }
    active = false;

    vga.redirect_fn = null;
    redirect_win = null;
    if (backbuf != null) {
        paging.freeBackBuffer(bb_pages);
        backbuf = null;
    }
    bga.disable();
    debug.klog("[desktop] Returned to text mode\n", .{});
}

// --- GUI app API (called from syscall handlers) ---

/// Create a GUI window owned by the given process. Returns slot ID or null.
// Title-formatting helper extracted to desktop/title.zig (aliased to
// avoid shadowing the local `title` parameter/var used in createWindow,
// renderMenuBar, etc.).
const win_title = @import("desktop/title.zig");

///
/// `auto_focus` controls whether the new window steals input focus from the
/// currently focused window. Callers (sysCreateWindow) should pass `false`
/// when the new window's owner was spawned by the focused terminal's shell —
/// the user is typing and a background-spawn shouldn't yank the cursor away.
/// Pass `true` for explicit user gestures (shortcut launch, dock click).
pub fn createGuiWindow(pid: u8, fb: [*]volatile u32, fb_backs: [3]?[*]volatile u32, fb_pixels: u32, w: u32, h: u32, alloc_w: u32, alloc_h: u32, auto_focus: bool, gpu_slot: ?u8) ?u8 {
    // Hold gui_fb_realloc_lock so slot recycling can't race a concurrent
    // growGuiFb that's still inside the OLD-release region (the OLD slot
    // it's working with must not be re-allocSlot'd until both growGuiFb
    // and destroyGuiWindow have fully exited). The fragility this guards
    // against is documented next to gui_fb_realloc_lock's declaration.
    // Order is gui_fb_realloc_lock -> windows_lock, matching destroyGuiWindow.
    gui_fb_realloc_lock.acquire();
    defer gui_fb_realloc_lock.release();
    const wflags = lockWindows();
    defer unlockWindows(wflags);
    const slot = allocSlot() orelse return null;
    // Center first window, cascade subsequent ones so they don't all stack
    // at the exact same position (otherwise the top window fully occludes
    // the rest and apps look like they're queueing up).
    const outer_w = w + BORDER * 2;
    const outer_h = h + TITLEBAR_H + BORDER * 2;
    const cascade: i32 = @intCast((wm.z_count % 8) * 28);
    const cx: i32 = @intCast((gfx.screen_w - outer_w) / 2);
    const cy: i32 = @intCast(MENUBAR_H + (gfx.screen_h - MENUBAR_H - TASKBAR_H - outer_h) / 2);
    windows[slot].x = cx + cascade - 56;
    windows[slot].y = cy + cascade - 56;
    windows[slot].width = w;
    windows[slot].height = h + TITLEBAR_H;
    windows[slot].visible = true;
    windows[slot].gui_fb = fb;
    windows[slot].gui_fb_backs = fb_backs;
    windows[slot].gui_fb_pixels = fb_pixels;
    windows[slot].gui_fb_pub = .init(0);
    windows[slot].gui_w = w;
    windows[slot].gui_h = h;
    windows[slot].gui_alloc_w = alloc_w;
    windows[slot].gui_alloc_h = alloc_h;
    windows[slot].owner_pid = pid;
    windows[slot].gpu_slot = gpu_slot;
    const pname = process.getName(pid);
    const written = win_title.pretty(&windows[slot].title, pname);
    if (written > 0) {
        windows[slot].title_len = written;
    } else {
        const title = "GUI App";
        for (0..title.len) |i| windows[slot].title[i] = title[i];
        windows[slot].title_len = @intCast(title.len);
    }
    pushZTop(slot);
    if (auto_focus) {
        setFocused(slot);
    } else if (slot_used[wm.focused] and wm.focused != slot) {
        // Background-spawn (e.g. `files` launched from a focused shell).
        // We DON'T steal input focus (shell keeps the cursor), and the
        // visual stacking should match: shell stays on top so the user
        // can keep typing without the spawn occluding it. Re-pushing the
        // focused window puts it back at z-top — new window settles
        // immediately below.
        pushZTop(wm.focused);
    }
    startAnimation(slot, .opening);
    // Publish an initial resize event so apps can lay out for the actual
    // window size (which may be smaller than the allocation if the
    // window's `w/h` differ from `alloc_w/alloc_h`). Apps that listen for
    // resize events can then skip per-frame `getWindowSize` polling.
    windows[slot].events.push(.{
        .kind = @intFromEnum(EventKind.resize),
        .a = w,
        .b = h,
    });
    debug.klog("[desktop] GUI window created for PID {d}: {d}x{d} (focus={s})\n", .{ pid, w, h, if (auto_focus) "yes" else "no" });
    return slot;
}

/// Returns true iff the focused window is a terminal whose attached shell
/// has the given pid (or any ancestor of pid up the parent chain). Used by
/// sysCreateWindow to decide whether a new GUI window should steal focus.
pub fn focusedShellSpawnedPid(pid: u8) bool {
    if (wm.focused >= MAX_WINDOWS or !slot_used[wm.focused]) return false;
    const fw = &windows[wm.focused];
    if (fw.term == null or fw.shell_pid == 0xFF) return false;
    const shell = fw.shell_pid;
    // Walk parent chain up to a sane bound to avoid an infinite loop on a
    // corrupted PCB ring.
    var cur = pid;
    var hops: u8 = 0;
    while (hops < 16) : (hops += 1) {
        if (cur == shell) return true;
        const pcb = process.getPCB(cur);
        const parent = pcb.parent_pid;
        if (parent == 0 or parent == cur) return false;
        cur = parent;
    }
    return false;
}

/// Composite and display all windows (called from sys_present).
pub fn presentWindow(pid: u8) void {
    _ = pid;
    if (mouse.moved) mouse.moved = false;
    renderScene();
    if (backbuf != null) {
        gfx.waitVSync();
        gfx.blitToScreen();
    }
    // Cursor is only drawn here in software-cursor mode AND when the focused
    // window hasn't asked for it to be hidden. With HW cursor (the default),
    // virtio-gpu handles drawing — we just toggle visibility via hide/showCursor
    // and the firmware composites the sprite. Without this gate, every DOOM
    // frame stamped the SW cursor sprite into the framebuffer regardless of
    // setCursorVisible(false), so the cursor appeared frozen at the last
    // mouse position even with HW cursor "hidden".
    const vgpu = @import("../driver/virtio_gpu.zig");
    const app_hides = slot_used[wm.focused] and windows[wm.focused].cursor_hidden_by_app;
    if (!vgpu.hw_cursor_active and !app_hides) {
        drawCursorOnScreen();
    }
}

/// Remove a window. Tears down per-window resources, frees the slot, and
/// splices it out of z_stack. With stable slot IDs, no other slot's data
/// is touched — outside references to other slots stay valid. Refs that
/// were pointing AT this slot (focused, drag_win, resize_win) get cleaned
/// up here.
fn removeWindow(slot: u8) void {
    if (slot >= MAX_WINDOWS or !slot_used[slot]) return;
    if (windows[slot].term) |td| {
        freeTerminalData(td);
        windows[slot].term = null;
    }
    // Tear down shell pipes if this window had a user-space shell. Closing
    // the desktop's end drops the refcount; once the shell also closes
    // its end the pipe slot is freed by pipe.closeReader/Writer.
    if (windows[slot].kb_pipe != 0xFF) {
        @import("../proc/pipe.zig").closeWriter(windows[slot].kb_pipe);
        windows[slot].kb_pipe = 0xFF;
    }
    if (windows[slot].out_pipe != 0xFF) {
        @import("../proc/pipe.zig").closeReader(windows[slot].out_pipe);
        windows[slot].out_pipe = 0xFF;
    }
    if (windows[slot].shell_pid != 0xFF) {
        process.killProcess(windows[slot].shell_pid);
        windows[slot].shell_pid = 0xFF;
    }

    removeFromZ(slot);
    freeSlot(slot);

    // If we were focused on the dying slot, hand focus to whatever is now
    // on top of the z-stack (most recently raised window).
    if (wm.focused == slot) {
        if (topSlot()) |t| setFocused(t) else setFocused(0);
    }
    // Active drag/resize on the dying slot is cancelled.
    if (dragging and drag_win == slot) dragging = false;
    if (resizing and resize_win == slot) resizing = false;
}

/// Destroy GUI windows owned by the given process.
pub fn destroyGuiWindow(pid: u8) void {
    // Mutex held across the whole teardown so growGuiFb cannot race
    // its publish + OLD-release sequence against our unmapGuiFB. See
    // the lock's declaration for the deadlock analysis. Lock order is
    // ALWAYS gui_fb_realloc_lock -> windows_lock; never the reverse.
    gui_fb_realloc_lock.acquire();
    defer gui_fb_realloc_lock.release();
    const wflags = lockWindows();
    defer unlockWindows(wflags);
    // Restore cursor if this process had it hidden
    if (@import("../driver/virtio_gpu.zig").cursor_hidden) {
        @import("../driver/virtio_gpu.zig").showCursor();
    }
    var any_window_for_pid = false;
    // Iterate slots (not z_stack) since removeWindow mutates z_stack and
    // we'd skip entries with a live z_stack iteration.
    for (0..MAX_WINDOWS) |k| {
        const i: u8 = @intCast(k);
        if (!slot_used[i]) continue;
        if (windows[i].owner_pid != pid) continue;
        any_window_for_pid = true;
        debug.klog("[desktop] GUI window destroyed for PID {d}\n", .{pid});
        if (windows[i].gui_fb != null) {
            const aw = if (windows[i].gui_alloc_w > 0) windows[i].gui_alloc_w else windows[i].gui_w;
            const ah = if (windows[i].gui_alloc_h > 0) windows[i].gui_alloc_h else windows[i].gui_h;
            const fb_size = aw * ah * 4;
            const num_pages = (fb_size + 4095) / 4096;
            // unmapGuiFB iterates internally over front + any lazily-
            // allocated back-buffer slots (tracked per-PID in paging.zig).
            // Each slot was sized num_pages, so we just pass that.
            const free_before = pmm.freeFrameCount();
            paging.unmapGuiFB(pid, num_pages);
            const free_after = pmm.freeFrameCount();
            debug.klog("[fb-diag] pid={d} unmapGuiFB num_pages={d} free {d}->{d} (returned={d})\n", .{
                pid, num_pages, free_before, free_after, free_after -% free_before,
            });
        }
        removeWindow(i);
        dirty_rects_mod.force_full_kind = true;
        markDirtyFull();
    }
    if (any_window_for_pid) wake.requestWake();
    if (!any_window_for_pid) {
        debug.klog("[fb-diag] destroyGuiWindow pid={d}: NO window matched owner_pid\n", .{pid});
    }
}

/// Write mouse position relative to the window's content area into user buffer.
/// Called by sysPresent — marks the GUI window for this PID as needing re-composite.
pub fn markGuiPresent(pid: u8) void {
    for (z_stack[0..wm.z_count]) |i| {
        if (windows[i].owner_pid == pid and windows[i].gui_fb != null) {
            windows[i].gui_present_pending = true;
            // Event-driven compositor wake: a GUI app pushed a new
            // frame, the desktop loop has work to do (re-composite
            // this window, blit the dirty rect). In legacy mode this
            // is a no-op gated by the 3-tick GUI floor; in event-
            // driven mode this is the only thing that brings the
            // compositor back from sleep.
            wake.requestWake();
            return;
        }
    }
}

/// Snapshot the user-writable front buffer into the kernel back buffer for
/// this PID's GUI window. Called by sysPresent before markGuiPresent. The
/// compositor reads from gui_fb_back, so this snapshot is what makes
/// renderWindow see a coherent frame instead of half-old / half-new data
/// (which is what produced the cube's flashing artifact pre-fix). The copy
/// is ~80 µs for a 320×240 window, scaling linearly with pixel count;
/// negligible at the rate sysPresent fires.
/// In-flight snapshotGuiFb counter. Bumped at the top of snapshotGuiFb,
/// released at the bottom. reclaimBackBuffers spin-waits this to zero
/// before freeing back-buffer phys frames — without this, reclaim could
/// race with a mid-memcpy snapshot from another CPU, writing through a
/// pointer we just freed and clobbering whoever PMM hands the frame to
/// next.
var presenting_count: u32 = 0;

pub fn snapshotGuiFb(pid: u8) void {
    _ = @atomicRmw(u32, &presenting_count, .Add, 1, .acquire);
    defer _ = @atomicRmw(u32, &presenting_count, .Sub, 1, .release);
    for (z_stack[0..wm.z_count]) |i| {
        const w = &windows[i];
        if (w.owner_pid == pid) {
            const front = w.gui_fb orelse return;
            const n = w.gui_fb_pixels;
            if (n == 0) return;
            // Race-free triple buffer: write slot (pub+1)%3, then publish
            // it. The compositor is currently reading slot pub; the just-
            // -published slot is a fresh slot it hasn't touched. With 3
            // slots total, we can rotate forward by 2 before we'd reach
            // the slot the compositor is on — so as long as snap rate
            // < 3× compositor rate (always true for 50fps cube/60fps
            // compositor), the in-flight slot is never overwritten.
            const cur_pub = w.gui_fb_pub.load(.acquire);
            const next: u32 = (cur_pub + 1) % 3;
            // Lazy back-buffer alloc. sysCreateWindow leaves all three
            // backs unallocated; we only create them when an app
            // actually calls sysPresent. Apps that never present
            // (sysmon, settings, many tools that rely on auto-refresh)
            // save 3× their framebuffer permanently. First-present pays
            // a one-shot pmm.allocContiguous(num_pages) per slot.
            //
            // If alloc fails (low memory), we silently skip the present:
            // has_presented stays false, the compositor's renderWindow
            // falls back to reading gui_fb directly. Visually
            // indistinguishable; only loses the tear-free property under
            // 60fps+ presenters (cube etc.) — which is a fair trade for
            // not crashing the present syscall under memory pressure.
            if (w.gui_fb_backs[next] == null) {
                const num_pages: u32 = @intCast((@as(usize, n) * 4 + 4095) / 4096);
                if (pmm.allocContiguous(num_pages)) |back_phys| {
                    const back_kv: [*]volatile u32 = @ptrFromInt(paging.physToVirt(back_phys));
                    const back_u8: [*]volatile u8 = @ptrCast(back_kv);
                    @memset(back_u8[0 .. num_pages * 4096], 0);
                    w.gui_fb_backs[next] = back_kv;
                    paging.registerGuiFBBack(pid, @intCast(next), back_phys);
                } else {
                    // PMM exhausted — leave has_presented=false and let
                    // the compositor read gui_fb directly. App keeps
                    // running; only the tear-free property is lost.
                    return;
                }
            }
            const next_buf = w.gui_fb_backs[next] orelse return;
            const dst: [*]u32 = @ptrCast(@volatileCast(next_buf));
            const src: [*]const u32 = @ptrCast(@volatileCast(front));
            @memcpy(dst[0..n], src[0..n]);
            w.gui_fb_pub.store(next, .release);
            // Flip the "first present landed" gate AFTER publish so any
            // concurrent renderWindow that sees has_presented=true also
            // sees the freshly-published slot.
            w.has_presented = true;
            return;
        }
    }
}

/// PMM reclaim callback — drops the lazily-allocated back-buffer slots
/// of every GUI window, returning the freed frames to the PMM. Called
/// from pmm.tryReclaim when an allocation fails (typically from
/// handleUserPageFault on the OOM path). Returns frames actually freed.
///
/// Race safety: NULL the kernel pointer first so any new snapshotGuiFb
/// sees null and lazily reallocates. Then spin-wait `presenting_count`
/// to zero — guarantees no in-flight memcpy is still writing through a
/// pointer we already nulled. Only then do we hand the phys back to
/// PMM. Without the spin, a concurrent snapshotGuiFb on another CPU
/// could write 8 MB into a frame PMM already reassigned, corrupting
/// arbitrary kernel state.
///
/// `has_presented` is cleared so renderWindow falls back to reading
/// gui_fb directly (the existing fallback path). The next sysPresent
/// will lazily reallocate the slot.
pub fn reclaimBackBuffers(needed_frames: u32) u32 {
    var freed_frames: u32 = 0;
    // Phase 1: null all reclaimable back-buffer kernel pointers + take
    // their phys. Doing all the NULL writes first means by the time we
    // start the spin-wait, no new snapshotGuiFb call can latch a
    // pointer that we then free.
    var pending_phys: [MAX_WINDOWS * 3]usize = [_]usize{0} ** (MAX_WINDOWS * 3);
    var pending_pages: u32 = 0;
    var pending_count: usize = 0;
    for (0..MAX_WINDOWS) |k| {
        const i: u8 = @intCast(k);
        if (!slot_used[i]) continue;
        const w = &windows[i];
        if (w.gui_fb == null) continue;
        const aw = if (w.gui_alloc_w > 0) w.gui_alloc_w else w.gui_w;
        const ah = if (w.gui_alloc_h > 0) w.gui_alloc_h else w.gui_h;
        const npages_this: u32 = (aw * ah * 4 + 4095) / 4096;
        var slot: u8 = 0;
        while (slot < 3) : (slot += 1) {
            if (w.gui_fb_backs[slot] == null) continue;
            // NULL the kernel pointer first (atomic with respect to
            // snapshotGuiFb's pointer load). Even if a snapshot
            // already loaded the pointer, the spin-wait below handles
            // it.
            w.gui_fb_backs[slot] = null;
            const phys = paging.takeGuiFbBackPhys(w.owner_pid, slot);
            if (phys != 0) {
                pending_phys[pending_count] = phys;
                pending_count += 1;
                pending_pages = npages_this;
                freed_frames += npages_this;
            }
        }
        // Force compositor onto the gui_fb fallback path. The next
        // sysPresent will lazily reallocate the slot.
        w.has_presented = false;
        if (freed_frames >= needed_frames) break;
    }
    if (pending_count == 0) return 0;

    // Phase 2: spin-wait for any in-flight snapshotGuiFb to finish.
    // Bounded by snapshotGuiFb's memcpy time — fullscreen 1920×1080
    // RGBA is ~8 MB, memcpy at ~5 GB/s is ~1.6 ms worst case. The
    // `pause` lets the other CPU make progress instead of cache-
    // ping-ponging us.
    var spin_iters: u32 = 0;
    while (@atomicLoad(u32, &presenting_count, .acquire) > 0) {
        asm volatile ("pause");
        spin_iters += 1;
        if (spin_iters > 10_000_000) {
            // Sanity bound — if we somehow miss a decrement, don't
            // hang forever. Log + bail; the deferred free might race
            // a snapshot, but at this point the system is in a worse
            // state than a single torn 8 MB write.
            debug.klog("[reclaim] WARN snapshotGuiFb drain timeout, freeing anyway\n", .{});
            break;
        }
    }

    // Phase 3: now safe — actually return the frames to PMM.
    var i: usize = 0;
    while (i < pending_count) : (i += 1) {
        pmm.freeContiguous(pending_phys[i], pending_pages);
    }
    return freed_frames;
}

pub fn focusedPid() u8 {
    if (slot_used[wm.focused] and windows[wm.focused].visible) {
        return windows[wm.focused].owner_pid;
    }
    return 0xFF;
}

/// Pid that should receive a Ctrl+C SIGINT — the shell for terminal
/// windows (since terminal windows don't track an owner_pid; the shell
/// runs as a child and forwards), or the owner_pid for GUI windows.
/// Returns 0xFF if there's no valid target.
///
/// Used by keyboard.push at IRQ time to deliver Ctrl+C without going
/// through the desktop's main event loop. The loop has been observed to
/// stall during long-running net syscalls; direct dispatch makes ^C
/// reliable regardless.
pub fn focusedSignalTarget() u8 {
    if (!slot_used[wm.focused]) return 0xFF;
    const w = &windows[wm.focused];
    if (!w.visible) return 0xFF;
    return if (w.term != null) w.shell_pid else w.owner_pid;
}

/// True iff `pid` is the owner of a non-terminal, focused, visible, non-
/// minimized window — i.e. it's the one process that should currently
/// receive keystrokes via fd=0 (`.console`).
///
/// With the per-window event queue model, this is largely redundant with
/// `popCharEvent` (which already filters by focus + ownership), but it's
/// kept as a fast-path gate so callers don't even need to enter the
/// queue-drain code path when they wouldn't get anything.
pub fn canReadConsole(pid: u8) bool {
    if (!slot_used[wm.focused]) return false;
    const w = &windows[wm.focused];
    if (!w.visible or w.minimized) return false;
    if (w.term != null) return false;
    return w.owner_pid == pid;
}

/// Pop one event from the focused window's queue if `pid` owns it,
/// copying into `out`. Returns true iff an event was delivered. Returns
/// false on: no focused window, focused window invisible/minimized, pid
/// not the owner, queue empty.
///
/// Called by `sysPollEvent`. The semantics ("you only see events when
/// focused") match every other modern OS — apps polling in the
/// background simply get nothing instead of stealing input.
pub fn popEvent(pid: u8, out: *Event) bool {
    if (!slot_used[wm.focused]) return false;
    const w = &windows[wm.focused];
    if (!w.visible or w.minimized) return false;
    if (w.owner_pid != pid) return false;
    if (w.events.pop()) |ev| {
        out.* = ev;
        return true;
    }
    return false;
}

/// Peek-style predicate matching `popCharEvent` — returns true iff the
/// next `popCharEvent(pid)` would succeed without blocking. Used by
/// fdpoll's `pollMaskConsole` so OP_POLL can complete immediately when
/// a console fd already has data ready, and re-check on wake. Pure
/// read — does not pop, does not mutate queue state. Mirrors every
/// gate inside popCharEvent; if those diverge, update both.
pub fn consoleReadable(pid: u8) bool {
    if (!slot_used[wm.focused]) return false;
    const w = &windows[wm.focused];
    if (!w.visible or w.minimized) return false;
    if (w.term != null) return false;
    if (w.owner_pid != pid) return false;
    // Queue uses ring buffer: head==tail = empty. We don't peek event
    // kinds — non-char events are vanishingly rare (no current pusher),
    // and a stale POLLIN that resolves to zero bytes is benign (caller
    // re-polls).
    return w.events.head != w.events.tail;
}

/// Drain one char event from the focused window's queue and return its
/// translated character. Used by legacy `sysRead`/`vfs.read .console`
/// — those code paths used to call `keyboard.pop()` directly, racing
/// every other console-fd reader for the global ring. Now they read
/// from the per-window queue, which is fed only when focused.
///
/// Skips non-char events without consuming them in a way that other
/// callers would notice — but since char/special are the only kinds
/// emitted in Phase 1, the loop is currently single-iteration.
pub fn popCharEvent(pid: u8) ?u8 {
    if (!slot_used[wm.focused]) return null;
    const w = &windows[wm.focused];
    if (!w.visible or w.minimized) return null;
    if (w.term != null) return null; // terminal: shell reads via kb_pipe
    if (w.owner_pid != pid) return null;
    while (w.events.pop()) |ev| {
        const k = @as(EventKind, @enumFromInt(ev.kind));
        if (k == .key_char or k == .key_special) {
            return @truncate(ev.a);
        }
        // Unknown / non-char event — drop and try next. (No future kinds
        // are emitted yet, so this branch isn't currently reached.)
    }
    return null;
}

pub fn getMouseRelative(pid: u8, buf: [*]u32) void {
    // Pull true relative motion from the driver's pre-clamp accumulator
    // (mouse.raw_dx/dy) rather than diffing the screen-clamped cursor
    // position. The old `mouse.x - prev_accum_x` form saturated to 0 the
    // instant the visible cursor pinned to a screen edge, which froze FPS
    // mouse-look mid-turn (the "move right, cursor leaves the window, can't
    // keep turning" bug — hit by both Quake and DOOM). The absolute clamp on
    // mouse.x/y still governs the visible cursor + desktop hit-testing; it just
    // no longer bounds the relative channel apps read from buf[3..4]. NOTE:
    // unbounded turning also needs a relative input device (usb-mouse) + a
    // pointer grab — an absolute usb-tablet can't supply it. See
    // run-uefi-ext2-iommu-game.sh.
    mouse.accum_dx += mouse.raw_dx;
    mouse.accum_dy += mouse.raw_dy;
    mouse.raw_dx = 0;
    mouse.raw_dy = 0;

    for (z_stack[0..wm.z_count]) |i| {
        if (windows[i].owner_pid == pid and windows[i].visible) {
            if (i == wm.focused) {
                // Focused window: return live mouse coordinates
                const rel_x = mouse.x - windows[i].x;
                const rel_y = mouse.y - (windows[i].y + @as(i32, TITLEBAR_H));
                buf[0] = @bitCast(rel_x);
                buf[1] = @bitCast(rel_y);
                buf[2] = @as(u32, mouse.buttons);
                // Store accumulated deltas in buf[3..4] for FPS apps
                buf[3] = @bitCast(mouse.accum_dx);
                buf[4] = @bitCast(mouse.accum_dy);
                mouse.accum_dx = 0;
                mouse.accum_dy = 0;
                windows[i].last_mouse_x = rel_x;
                windows[i].last_mouse_y = rel_y;
            } else {
                buf[0] = @bitCast(windows[i].last_mouse_x);
                buf[1] = @bitCast(windows[i].last_mouse_y);
                buf[2] = 0;
                buf[3] = 0;
                buf[4] = 0;
            }
            return;
        }
    }
    buf[0] = 0;
    buf[1] = 0;
    buf[2] = 0;
    buf[3] = 0;
    buf[4] = 0;
}

pub fn setCursorHidden(pid: u8, hidden: bool) void {
    // Find the calling process's window — don't gate on focus. createWindow()
    // doesn't atomically hand focus, so apps that call setCursorVisible(false)
    // immediately after createWindow() (DOOM does) would race with the
    // focus assignment and silently fail. Per-window flag survives that race;
    // the main loop's cursor-policy code applies it whenever the window is
    // actually focused.
    for (z_stack[0..wm.z_count]) |i| {
        if (windows[i].owner_pid == pid) {
            windows[i].cursor_hidden_by_app = hidden;
        }
    }
    // Apply immediately if that process happens to own the focused window.
    if (slot_used[wm.focused] and windows[wm.focused].owner_pid == pid) {
        const vgpu = @import("../driver/virtio_gpu.zig");
        if (hidden) vgpu.hideCursor() else vgpu.showCursor();
    }
}

/// Warp mouse cursor to the center of a process's window (for FPS-style mouse look)
pub fn centerMouse(pid: u8) void {
    for (z_stack[0..wm.z_count]) |i| {
        if (windows[i].owner_pid == pid and windows[i].visible) {
            const cx = windows[i].x + @as(i32, @intCast(windows[i].width / 2));
            const cy = windows[i].y + @as(i32, TITLEBAR_H) + @as(i32, @intCast((windows[i].height -| TITLEBAR_H) / 2));
            mouse.x = cx;
            mouse.y = cy;
            return;
        }
    }
}

pub fn getWindowContentSize(pid: u8, buf: [*]u32) void {
    for (z_stack[0..wm.z_count]) |i| {
        if (windows[i].owner_pid == pid and windows[i].visible) {
            const w = &windows[i];
            // Maximize no longer means "fill the screen ignoring chrome"
            // — the window has real width/height like any other, so the
            // content size is derived the normal way regardless of the
            // fullscreen flag.
            buf[0] = w.width -| (BORDER * 2);
            buf[1] = w.height -| (TITLEBAR_H + BORDER);
            return;
        }
    }
    buf[0] = 0;
    buf[1] = 0;
}

/// Report the calling window's FB allocation (stride width, rows). growGuiFb
/// can bump this past the app's create-time request on F10 maximize; the app
/// re-fetches it on the `.resize` event and rebuilds its canvas at buf[0] stride.
pub fn getWindowAllocSize(pid: u8, buf: [*]u32) void {
    for (z_stack[0..wm.z_count]) |i| {
        if (windows[i].owner_pid == pid and windows[i].visible) {
            const w = &windows[i];
            // Querying the alloc opts the window into grow-on-maximize: the app
            // is signalling it adapts its stride to the reported alloc.
            w.fb_growable = true;
            buf[0] = if (w.gui_alloc_w > 0) w.gui_alloc_w else w.gui_w;
            buf[1] = if (w.gui_alloc_h > 0) w.gui_alloc_h else w.gui_h;
            return;
        }
    }
    buf[0] = 0;
    buf[1] = 0;
}

// --- Preemptive multitasking ---

pub var active: bool = false;

// Desktop update interval: timer returns control every N ticks (~50fps at 100Hz)
var last_desktop_tick: u64 = 0;
const DESKTOP_INTERVAL: u64 = 8;
var gui_windows_active: bool = false;

fn hasGuiWindows() bool {
    for (z_stack[0..wm.z_count]) |i| {
        if (windows[i].gui_fb != null and windows[i].visible) return true;
    }
    return false;
}

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
