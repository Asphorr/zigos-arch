// Window module — owns the window table, the Window/TerminalData structs,
// the z-stack, focus tracking, slot allocation, and hit-testing helpers.
// Aliased as `wm` from desktop.zig.
//
// Window storage model (post-2026-05-03 z-stack refactor):
//
//   windows[i]        — fixed-position storage, indexed by STABLE SLOT ID.
//                        A slot is allocated when a window is created and
//                        freed when it is fully destroyed. The slot ID never
//                        changes during the window's lifetime, so PIDs,
//                        dock positions, drag/resize handles, focused, and
//                        any other "this window" reference can hold a slot
//                        ID without ever being patched up after a reorder.
//   slot_used[i]      — true iff windows[i] is allocated.
//   z_stack[0..z_count] — slot IDs in z-order, bottom→top. The topmost
//                        window (the one that paints last and is hit-tested
//                        first) is `z_stack[z_count - 1]`.
//
// Compatibility shim: `window_count` is kept as an alias for `z_count` so
// older callers that compare against it still work. They just need to
// remember that "0..window_count" is now positions in z_stack, NOT slot
// IDs — iterate via `for (z_stack[0..z_count]) |slot|` instead.

const std = @import("std");
const events_mod = @import("../events.zig");
const heap = @import("../../mm/heap.zig");
const mouse = @import("../../driver/mouse.zig");
const virtio_gpu = @import("../../driver/virtio_gpu.zig");
const theme = @import("../theme.zig");
const layout = @import("layout.zig");
const cfg = @import("../../config.zig");
const spinlock = @import("../../proc/spinlock.zig");

pub const MAX_WINDOWS: u32 = cfg.MAX_WINDOWS;
pub const SCROLL_LINES: u32 = cfg.SCROLL_LINES;

pub const TERM_COLS: u32 = 80;
pub const TERM_ROWS: u32 = 25;

pub const MIN_WIN_W: u32 = 200;
pub const MIN_WIN_H: u32 = 100;
pub const RESIZE_ZONE: i32 = 5;

const ATTR_DEFAULT = theme.ATTR_DEFAULT;
const TITLEBAR_H = layout.TITLEBAR_H;
const BTN_RADIUS = layout.BTN_RADIUS;

pub const EscState = enum(u8) { idle, esc, csi };

pub const TerminalData = struct {
    text_buf: [TERM_COLS * TERM_ROWS]u8,
    attr_buf: [TERM_COLS * TERM_ROWS]u8,
    text_row: u16,
    text_col: u16,
    cmd_buf: [128]u8,
    cmd_len: u8,
    history: [8][128]u8,
    history_len: [8]u8,
    history_count: u8,
    history_idx: u8,
    scroll_buf: [SCROLL_LINES * TERM_COLS]u8,
    scroll_attr_buf: [SCROLL_LINES * TERM_COLS]u8,
    scroll_write: u16,
    scroll_count: u16,
    scroll_view: u16,
    // Escape-sequence parser state. `idle` = consume chars normally;
    // `esc` = saw \x1b, awaiting `[`; `csi` = inside `\x1b[...<final>`,
    // accumulating numeric args separated by `;`.
    esc_state: EscState,
    csi_args: [4]u16,
    csi_arg_count: u8,
    csi_has_arg: bool,
    cur_attr: u8,
    bell_phase: u8,
    cursor_blink_anchor: u64,
    /// Deferred-wrap flag (xterm-style auto-margin). When a printable char
    /// lands in the last column we leave the cursor *at* that column with
    /// `pending_wrap=true` instead of immediately advancing+scrolling. The
    /// wrap commits only on the *next* printable write, and any cursor-
    /// moving control (\r, \n, \x08, CSI cursor moves) clears it. Without
    /// this, the shell's `redrawInputLine` (which writes prompt+content,
    /// possibly to col 79) scrolled the screen every time the user held
    /// backspace on a long line — duplicating the line into scrollback.
    pending_wrap: bool,
};

pub const AnimationType = enum(u8) { none, opening, closing, minimizing, restoring, fullscreening, unfullscreening };

pub const Window = struct {
    x: i32,
    y: i32,
    width: u32,
    height: u32,
    title: [32]u8,
    title_len: u8,
    visible: bool,
    minimized: bool = false,
    fullscreen: bool = false,
    saved_x: i32 = 0,
    saved_y: i32 = 0,
    saved_w: u32 = 0,
    saved_h: u32 = 0,
    term: ?*TerminalData = null,
    /// If this is a Terminal window hosting a user-space shell, these are the
    /// two pipes that connect the desktop to that shell. The shell's fd 0 is
    /// `kb_pipe` read-side; the desktop pushes keystrokes into the write-side.
    /// The shell's fd 1/2 is `out_pipe` write-side; the desktop drains the
    /// read-side every frame and renders into the window's text buffer.
    /// 0xFF on either field = no shell attached.
    kb_pipe: u8 = 0xFF,
    out_pipe: u8 = 0xFF,
    /// PID of the shell process owning this terminal. Used so closing the
    /// window can SIGKILL the shell. 0xFF = no shell attached yet.
    shell_pid: u8 = 0xFF,
    gui_fb: ?[*]volatile u32 = null,
    /// True race-free triple buffer. The app writes to `gui_fb` (mapped
    /// into user-space). On `sysPresent`, the kernel snapshots `gui_fb`
    /// into `gui_fb_backs[(pub+1)%3]`, then publishes that as the new
    /// `gui_fb_pub`. Compositor reads `gui_fb_backs[gui_fb_pub]`. With
    /// 3 backs the compositor's currently-in-flight slot (= pub at load
    /// time) cannot be reached by the snapshot writer until the writer
    /// has rotated through TWO other slots first. At 50–60 fps cube and
    /// 60 fps compositor, the writer's rotation rate < compositor's
    /// per-frame consumption, so the in-flight slot is never stomped.
    /// (The earlier 2-back impl could stomp after just 2 snaps; visible
    /// as occasional tearing/disappearing pieces.)
    /// Backs share a contiguous 4×fb_size PMM block from sysCreateWindow.
    gui_fb_backs: [3]?[*]volatile u32 = .{ null, null, null },
    /// Most-recently-published back-buffer index, 0..2. Atomic so cross-
    /// CPU reads in renderWindow see the latest publish without locks.
    gui_fb_pub: std.atomic.Value(u32) = .init(0),
    /// Set to true on the app's first sysPresent. Until then renderWindow
    /// reads `gui_fb` (the user-mapped front buffer) directly, so apps
    /// that never call libc.present() (file manager, editor, sysmon)
    /// still render their content. Once true, the published back buffer
    /// is used so cube-style streaming apps remain tear-free.
    has_presented: bool = false,
    /// Size of gui_fb / gui_fb_back_* in u32 elements (i.e. pixel count).
    /// Used by sysPresent to do a single typed @memcpy.
    gui_fb_pixels: u32 = 0,
    /// Step 9.4 Phase 2: index into gpu_compositor.window_slots when the
    /// window's pixels are also mirrored into a Venus dmabuf for direct
    /// GPU sampling. null when the compositor wasn't ready at create
    /// time, or when not running mode 9. Phase 3 wires the rendering;
    /// for now the slot is allocated but unused.
    gpu_slot: ?u8 = null,
    gui_w: u32 = 0,
    gui_h: u32 = 0,
    gui_alloc_w: u32 = 0,
    gui_alloc_h: u32 = 0,
    gui_present_pending: bool = false,
    /// True iff the owning process called setCursorVisible(false). The main
    /// desktop loop honors this when the window is focused — without this,
    /// the loop's auto-show heuristic for windowed apps stomps on the
    /// per-frame state and the app-side hide gets re-enabled every frame.
    /// FPS games (DOOM) need this; the cursor would otherwise flicker with
    /// every mouse movement.
    cursor_hidden_by_app: bool = false,
    owner_pid: u8 = 0xFF,
    last_mouse_x: i32 = 0,
    last_mouse_y: i32 = 0,
    anim_type: AnimationType = .none,
    anim_frame: u8 = 0,
    anim_total: u8 = 10,
    anim_start_x: i32 = 0,
    anim_start_y: i32 = 0,
    anim_start_w: u32 = 0,
    anim_start_h: u32 = 0,
    anim_end_x: i32 = 0,
    anim_end_y: i32 = 0,
    anim_end_w: u32 = 0,
    anim_end_h: u32 = 0,
    /// Per-window event queue. Desktop is the sole producer (drains the
    /// keyboard IRQ ring and publishes events here when this window is
    /// focused); the owning process drains via `sysPollEvent` (or, for
    /// legacy console-fd consumers, via `desktop.popCharEvent` from
    /// `sysRead`/`vfs.read`). See ui/events.zig for the event model.
    events: events_mod.EventQueue = .{},
};

pub const ResizeEdge = enum { right, bottom, bottom_right };

pub fn defaultWindow() Window {
    return .{
        .x = 0,
        .y = 0,
        .width = 0,
        .height = 0,
        .title = [_]u8{0} ** 32,
        .title_len = 0,
        .visible = false,
    };
}

pub var windows: [MAX_WINDOWS]Window = [_]Window{defaultWindow()} ** MAX_WINDOWS;
pub var slot_used: [MAX_WINDOWS]bool = [_]bool{false} ** MAX_WINDOWS;
pub var z_stack: [MAX_WINDOWS]u8 = [_]u8{0} ** MAX_WINDOWS;
pub var z_count: u8 = 0;
/// Old name retained for the few places that still read it; we keep it
/// equal to z_count via the z-stack mutation helpers.
pub var window_count: u8 = 0;
pub var focused: u8 = 0;

/// Backwards-compat alias for z_count. Active windows == z_stack length.
pub inline fn windowCount() u8 {
    return z_count;
}

/// Protects `windows[]` + slot/z bookkeeping + `focused`. Held briefly by
/// syscall mutation paths (sysCreateWindow / destroyGuiWindow / closeWindow
/// / focus changes) and by the BSP compositor whenever it walks the table.
/// SpinLock with IrqSave because the timer IRQ on BSP can preempt a
/// mid-mutation syscall; without IRQ-off we'd deadlock against ourselves.
var windows_lock: spinlock.SpinLock = .{};

pub fn lockWindows() u64 {
    return windows_lock.acquireIrqSave();
}
pub fn unlockWindows(flags: u64) void {
    windows_lock.releaseIrqRestore(flags);
}

/// Lowest-numbered free slot, or null if the table is full.
pub fn allocSlot() ?u8 {
    for (0..MAX_WINDOWS) |i| {
        if (!slot_used[i]) {
            slot_used[i] = true;
            windows[i] = defaultWindow();
            return @intCast(i);
        }
    }
    return null;
}

/// Mark a slot as free. Caller is responsible for tearing down anything the
/// slot owned (FB pages, pipes, terminal data) BEFORE calling this.
pub fn freeSlot(slot: u8) void {
    if (slot >= MAX_WINDOWS) return;
    slot_used[slot] = false;
    windows[slot] = defaultWindow();
}

/// Append a slot to the top of z_stack. Idempotent: if `slot` is already in
/// the stack, it gets removed first (so the result is "raise to top").
pub fn pushZTop(slot: u8) void {
    removeFromZ(slot);
    z_stack[z_count] = slot;
    z_count += 1;
    window_count = z_count;
}

/// Splice `slot` out of z_stack. No-op if it isn't there.
pub fn removeFromZ(slot: u8) void {
    var i: u8 = 0;
    while (i < z_count) : (i += 1) {
        if (z_stack[i] == slot) {
            var j: u8 = i;
            while (j + 1 < z_count) : (j += 1) z_stack[j] = z_stack[j + 1];
            z_count -= 1;
            window_count = z_count;
            return;
        }
    }
}

/// Slot ID of the topmost (latest-painted, first-hit-tested) visible window
/// in the z-stack, or null if the stack is empty.
pub fn topSlot() ?u8 {
    if (z_count == 0) return null;
    return z_stack[z_count - 1];
}

pub fn allocTerminalData() ?*TerminalData {
    // ~36 KB — well above kvmalloc threshold; bypasses the small kernel heap
    // (4 MB) so opening a few terminals doesn't fragment it.
    const ptr = heap.kalloc(@sizeOf(TerminalData)) orelse return null;
    const td: *TerminalData = @ptrCast(@alignCast(ptr));
    td.* = .{
        .text_buf = [_]u8{' '} ** (TERM_COLS * TERM_ROWS),
        .attr_buf = [_]u8{ATTR_DEFAULT} ** (TERM_COLS * TERM_ROWS),
        .text_row = 0,
        .text_col = 0,
        .cmd_buf = [_]u8{0} ** 128,
        .cmd_len = 0,
        .history = [_][128]u8{[_]u8{0} ** 128} ** 8,
        .history_len = [_]u8{0} ** 8,
        .history_count = 0,
        .history_idx = 0,
        .scroll_buf = [_]u8{' '} ** (SCROLL_LINES * TERM_COLS),
        .scroll_attr_buf = [_]u8{ATTR_DEFAULT} ** (SCROLL_LINES * TERM_COLS),
        .scroll_write = 0,
        .scroll_count = 0,
        .scroll_view = 0,
        .esc_state = .idle,
        .csi_args = [_]u16{0} ** 4,
        .csi_arg_count = 0,
        .csi_has_arg = false,
        .cur_attr = ATTR_DEFAULT,
        .bell_phase = 0,
        .cursor_blink_anchor = 0,
        .pending_wrap = false,
    };
    return td;
}

pub fn freeTerminalData(td: *TerminalData) void {
    heap.kfreeAuto(@ptrCast(td));
}

/// Set focused window and restore cursor visibility (apps that need hidden
/// cursor will re-hide on next tick). Publishes focus_out / focus_in events
/// to the previously-focused and newly-focused windows respectively.
pub fn setFocused(idx: u8) void {
    if (idx != focused) {
        if (virtio_gpu.cursor_hidden) {
            virtio_gpu.showCursor();
            virtio_gpu.moveCursor(mouse.x, mouse.y);
        }
        const old_idx = focused;
        const new_pid: u32 = if (slot_used[idx]) windows[idx].owner_pid else 0xFF;
        const old_pid: u32 = if (slot_used[old_idx]) windows[old_idx].owner_pid else 0xFF;
        if (slot_used[old_idx]) {
            windows[old_idx].events.push(.{
                .kind = @intFromEnum(events_mod.EventKind.focus_out),
                .a = new_pid,
            });
        }
        if (slot_used[idx]) {
            windows[idx].events.push(.{
                .kind = @intFromEnum(events_mod.EventKind.focus_in),
                .a = old_pid,
            });
        }
    }
    focused = idx;
}

pub fn focusNextVisible() void {
    // Prefer the topmost visible non-minimized window — that's what's most
    // recently been raised and is what the user expects to see in front.
    var k: u8 = z_count;
    while (k > 0) {
        k -= 1;
        const slot = z_stack[k];
        if (windows[slot].visible and !windows[slot].minimized) {
            setFocused(slot);
            return;
        }
    }
}

pub fn cycleFocus() void {
    if (z_count <= 1) return;
    var z_pos: u8 = 0;
    while (z_pos < z_count) : (z_pos += 1) if (z_stack[z_pos] == focused) break;
    var tries: u8 = 0;
    while (tries < z_count) : (tries += 1) {
        z_pos = (z_pos + 1) % z_count;
        const slot = z_stack[z_pos];
        if (windows[slot].visible and !windows[slot].minimized) {
            setFocused(slot);
            return;
        }
    }
}

pub fn windowAt(mx: i32, my: i32) ?u8 {
    // Walk z-stack top-down so the topmost (latest-painted) window wins
    // hit-testing — same visual order the user sees.
    var k: u8 = z_count;
    while (k > 0) {
        k -= 1;
        const slot = z_stack[k];
        const w = &windows[slot];
        if (!w.visible or w.minimized) continue;
        if (mx >= w.x and mx < w.x + @as(i32, @intCast(w.width)) and
            my >= w.y and my < w.y + @as(i32, @intCast(w.height)))
            return slot;
    }
    return null;
}

pub fn isInTitlebar(idx: u8, mx: i32, my: i32) bool {
    const w = &windows[idx];
    return (my >= w.y and my < w.y + @as(i32, TITLEBAR_H) and
        mx >= w.x and mx < w.x + @as(i32, @intCast(w.width)));
}

pub fn isOnCloseBtn(idx: u8, mx: i32, my: i32) bool {
    const w = &windows[idx];
    const cx = w.x + 16;
    const cy = w.y + @as(i32, TITLEBAR_H / 2);
    const dx = mx - cx;
    const dy = my - cy;
    return (dx * dx + dy * dy <= @as(i32, BTN_RADIUS * BTN_RADIUS));
}

pub fn isOnMinimizeBtn(idx: u8, mx: i32, my: i32) bool {
    const w = &windows[idx];
    const cx = w.x + 38;
    const cy = w.y + @as(i32, TITLEBAR_H / 2);
    const dx = mx - cx;
    const dy = my - cy;
    return (dx * dx + dy * dy <= @as(i32, BTN_RADIUS * BTN_RADIUS));
}

pub fn isOnResizeEdge(idx: u8, mx: i32, my: i32) ?ResizeEdge {
    const w = &windows[idx];
    const right = w.x + @as(i32, @intCast(w.width));
    const bot = w.y + @as(i32, @intCast(w.height));
    const near_right = (mx >= right - RESIZE_ZONE and mx <= right + 2 and my >= w.y + @as(i32, TITLEBAR_H) and my <= bot + 2);
    const near_bottom = (my >= bot - RESIZE_ZONE and my <= bot + 2 and mx >= w.x and mx <= right + 2);
    if (near_right and near_bottom) return .bottom_right;
    if (near_right) return .right;
    if (near_bottom) return .bottom;
    return null;
}
