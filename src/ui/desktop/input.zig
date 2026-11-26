// The pointer's buttons as the desktop and the focused program are shown
// them: presses the level never showed are played back from the driver's
// counters, and a program is told only of the presses that landed on its
// window's content.

const mouse = @import("../../driver.zig").mouse;
const process = @import("../../proc/process.zig");
const events_mod = @import("../events.zig");
const EventKind = events_mod.EventKind;
const wm = @import("window.zig");
const windows = &wm.windows;
const slot_used = &wm.slot_used;
const windowAt = wm.windowAt;
const isInTitlebar = wm.isInTitlebar;
const isOnResizeEdge = wm.isOnResizeEdge;
const context_menu = @import("context_menu.zig");
const launcher = @import("launcher.zig");
const wake = @import("wake.zig");
const layout = @import("layout.zig");
const TITLEBAR_H = layout.TITLEBAR_H;

pub var prev_buttons: u8 = 0;

/// Publish mouse_move / mouse_button / mouse_wheel events to the focused
/// window's queue. Called once per frame before `handleMouseEvents` so
/// the app sees the same input the desktop is about to act on.
///
/// We intentionally publish even when the cursor is over a different
/// window — focus + queue ownership decide who gets events, not hover.
/// This matches the keyboard model and avoids the "mouse silently does
/// nothing while a different app's titlebar is hovered" UX trap.
/// Presses drained from the driver that the desktop hasn't acted on yet.
pub var press_backlog: [3]u8 = .{ 0, 0, 0 };
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
pub fn frameButtons() u8 {
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

pub fn pressReplayPending() bool {
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
pub fn pressTarget() ?u8 {
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
pub fn publishMouseToFocused(prev_btns: u8, cur_btns: u8, moved: bool, wheel: i32, press_target: ?u8) void {
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
