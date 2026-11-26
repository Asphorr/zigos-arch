// The pointer's buttons as the desktop and the focused program are shown
// them: presses the level never showed are played back from the driver's
// counters, and a program is told only of the presses that landed on its
// window's content.

const mouse = @import("../../driver.zig").mouse;
const keyboard = @import("../../driver.zig").keyboard;
const process = @import("../../proc/process.zig");
const debug = @import("../../debug/debug.zig");
const events_mod = @import("../events.zig");
const EventKind = events_mod.EventKind;
const wm = @import("window.zig");
const windows = &wm.windows;
const slot_used = &wm.slot_used;
const windowAt = wm.windowAt;
const isInTitlebar = wm.isInTitlebar;
const isOnResizeEdge = wm.isOnResizeEdge;
const setFocused = wm.setFocused;
const cycleFocus = wm.cycleFocus;
const context_menu = @import("context_menu.zig");
const launcher = @import("launcher.zig");
const dock = @import("dock.zig");
const wake = @import("wake.zig");
const layout = @import("layout.zig");
const TITLEBAR_H = layout.TITLEBAR_H;

const damage = @import("damage.zig");
const DirtyKind = damage.DirtyKind;
const seedRect = damage.seedRect;
const wantRegion = damage.wantRegion;
const wantTextRow = damage.wantTextRow;
const manage = @import("manage.zig");
const toggleFullscreen = manage.toggleFullscreen;
const runLauncherResult = manage.runLauncherResult;
const handleMouseEvents = manage.handleMouseEvents;
const client = @import("client.zig");
const createWindow = client.createWindow;
const emulator = @import("term/emulator.zig");
const TERM_ROWS = emulator.TERM_ROWS;
const cells = @import("term/cells.zig");
const FONT_H = cells.FONT_H;
const TERM_WIN_W = cells.TERM_WIN_W;
const session = @import("term/session.zig");
const termPrompt = session.termPrompt;
const handleKeyboard = session.handleKeyboard;

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

// DBG: input-pipeline diagnostic counters. Bumped from desktop's drain
// loop when chars get dropped. Read by manual klog dumps when input
// behavior is unexpected. Rate-limited so we don't flood the log.
/// Keys dropped because no window had the focus.
pub var dbg_focus_drop_count: u64 = 0;
pub var dbg_event_queue_full: u64 = 0;
pub var dbg_last_focus_drop_log: u64 = 0;
pub var dbg_last_qfull_log: u64 = 0;

/// The keyboard's part of a pass of the loop. The chords the desktop keeps
/// for itself come first (F10, Ctrl+C, Alt+Tab, the launcher's), then the
/// launcher while it is open, then the focused window: every key becomes an
/// event in its queue, and a terminal's goes on to its shell or its console.
/// Whatever the case, the ring is left empty: a key that stayed in it would
/// keep the desktop from parking.
/// Returns the frame's kind raised by what the keys changed.
pub fn keys(frame_kind: DirtyKind) DirtyKind {
    var dirty = frame_kind;
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
                if (target != 0xFF) _ = @import("../../proc/signals.zig").send(target, @import("../../proc/signals.zig").SIGINT);
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
    // No focused window: the keys are dropped. Left in the ring they would
    // keep the desktop from parking (shouldResumeDesktop sees them), hide
    // the chords above behind the oldest of them, and land in the next
    // window to take the focus.
    const focus_ok = slot_used[wm.focused] and windows[wm.focused].visible and !windows[wm.focused].minimized;
    if (!focus_ok) {
        var dropped: u64 = 0;
        while (keyboard.pop()) |_| dropped += 1;
        dbg_focus_drop_count +%= dropped;
        // One line a second at most.
        if (dropped != 0 and process.tick_count -% dbg_last_focus_drop_log >= 100) {
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
                @import("../../ipc/fdpoll.zig").wakePollers(.console, 0xFFFF);
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
                    const smp_mod = @import("../../cpu/smp.zig");
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
                if (ch == 0x1B and !@import("../../tty/tty.zig").hasLinuxProgram(w.tty)) continue;
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
    return dirty;
}

/// The pointer's part of a pass: the buttons as played back, what the desktop
/// makes of them (manage.handleMouseEvents), what the focused program is
/// told, and the dock's hover. `cursor_moved`: mouse.moved as the pass found
/// it; it is cleared here, once it has been published. Returns the frame's
/// kind raised by what the pointer changed.
pub fn pointer(kind: DirtyKind, cursor_moved: bool) DirtyKind {
    var dirty = kind;
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
    return dirty;
}
