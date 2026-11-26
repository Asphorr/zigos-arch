// A window as its owner sees it, and as the rest of the kernel asks about it:
// made and taken down, whose it is, what its program may read (events, keys,
// the pointer) and what it may do in the user's name.

const gfx = @import("../gfx.zig");
const mouse = @import("../../driver.zig").mouse;
const keyboard = @import("../../driver.zig").keyboard;
const paging = @import("../../mm/paging.zig");
const pmm = @import("../../mm/pmm.zig");
const debug = @import("../../debug/debug.zig");
const process = @import("../../proc/process.zig");
const sound = @import("../../driver.zig").sound;
const events_mod = @import("../events.zig");
const Event = events_mod.Event;
const EventKind = events_mod.EventKind;
const emulator = @import("term/emulator.zig");
const wm = @import("window.zig");
const Window = wm.Window;
const TerminalData = emulator.TerminalData;
const windows = &wm.windows;
const slot_used = &wm.slot_used;
const z_stack = &wm.z_stack;
const lockWindows = wm.lockWindows;
const unlockWindows = wm.unlockWindows;
const allocSlot = wm.allocSlot;
const freeSlot = wm.freeSlot;
const pushZTop = wm.pushZTop;
const removeFromZ = wm.removeFromZ;
const topSlot = wm.topSlot;
const setFocused = wm.setFocused;
const allocTerminalData = emulator.allocTerminalData;
const freeTerminalData = emulator.freeTerminalData;
const dirty_rects_mod = @import("dirty.zig");
const markDirtyFull = dirty_rects_mod.markFull;
const animations = @import("animations.zig");
const startAnimation = animations.start;
const pinned = @import("pinned.zig");
const wake = @import("wake.zig");
const layout = @import("layout.zig");
const MENUBAR_H = layout.MENUBAR_H;
const TASKBAR_H = layout.TASKBAR_H;
const TITLEBAR_H = layout.TITLEBAR_H;
const BORDER = layout.BORDER;
const MAX_WINDOWS: u32 = @import("../../config.zig").MAX_WINDOWS;
const win_title = @import("title.zig");

const surface = @import("surface.zig");
const desktop = @import("../desktop.zig");

pub fn createWindow(title: []const u8, x: i32, y: i32, w: u32, h: u32) ?u8 {
    // Terminal data is vmalloc'd: allocate and free it outside windows_lock
    // (IRQs off), since vmalloc.free waits for every CPU's TLB flush.
    const td = allocTerminalData() orelse return null;
    const flags = lockWindows();
    const slot = allocSlot() orelse {
        unlockWindows(flags);
        freeTerminalData(td);
        return null;
    };
    defer unlockWindows(flags);
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

pub fn closeWindow(idx: u8) void {
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
    surface.gui_fb_realloc_lock.acquire();
    defer surface.gui_fb_realloc_lock.release();
    const wflags = lockWindows();
    defer unlockWindows(wflags);
    const slot = allocSlot() orelse return null;
    // Center first window, cascade subsequent ones so they don't all stack
    // at the exact same position (otherwise the top window fully occludes
    // the rest and apps look like they're queueing up).
    //
    // Saturating subtraction (-|) on the centering offsets: window dims are
    // clamped to alloc dims (<= 1920x1080) but NOT to the actual screen, so a
    // window larger than the current framebuffer — e.g. a fuzzer asking for
    // 1920x1080 on a smaller screen, or a legit maximize on a small display —
    // would underflow these u32 subtractions and @panic("integer overflow"),
    // taking down the kernel from an unprivileged sysCreateWindow. Clamp the
    // offset to 0 instead so an oversized window just pins to the top-left.
    const outer_w = w + BORDER * 2;
    const outer_h = h + TITLEBAR_H + BORDER * 2;
    const cascade: i32 = @intCast((wm.z_count % 8) * 28);
    const cx: i32 = @intCast((gfx.screen_w -| outer_w) / 2);
    const cy: i32 = @intCast(MENUBAR_H + (gfx.screen_h -| MENUBAR_H -| TASKBAR_H -| outer_h) / 2);
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
    windows[slot].owner_group = process.procs[pid].tgid;
    windows[slot].gpu_slot = gpu_slot;
    const pname = process.getName(pid);
    const written: u8 = if (pinned.nameForProcess(pname)) |name| blk: {
        const n = @min(name.len, windows[slot].title.len);
        @memcpy(windows[slot].title[0..n], name[0..n]);
        break :blk @intCast(n);
    } else win_title.pretty(&windows[slot].title, pname);
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

/// The closing animation of window `slot` has run out. A program's window
/// goes with its process, whose end takes down every window it owns; a
/// terminal's goes here, with its shell.
pub fn finishClose(slot: u8) void {
    const w = &windows[slot];
    const pid = w.owner_pid;
    if (w.gui_fb != null and pid != 0) {
        process.killProcess(pid);
        while (keyboard.pop()) |_| {}
        return;
    }
    // Before windows_lock: the shell's end takes that lock itself
    // (destroyGuiWindow), and closing a pipe's end wakes whoever waits on
    // the other.
    detachShell(w);
    const term = blk: {
        const flags = lockWindows();
        defer unlockWindows(flags);
        break :blk removeWindow(slot);
    };
    // vmalloc'd: freed with the lock dropped (see createWindow).
    if (term) |t| freeTerminalData(t);
    debug.klog("[desktop] Terminal window closed (slot {d}), {d} left\n", .{ slot, wm.z_count });
}

/// End the shell of a terminal window and close the desktop's ends of its
/// two pipes, so that a read or write blocked on the other end sees EOF or
/// EPIPE. Nothing to do for a window that has no shell.
fn detachShell(w: *Window) void {
    if (w.shell_pid != 0xFF) {
        process.killProcess(w.shell_pid);
        w.shell_pid = 0xFF;
    }
    if (w.kb_pipe != 0xFF) {
        @import("../../proc/pipe.zig").closeWriter(w.kb_pipe);
        w.kb_pipe = 0xFF;
    }
    if (w.out_pipe != 0xFF) {
        @import("../../proc/pipe.zig").closeReader(w.out_pipe);
        w.out_pipe = 0xFF;
    }
    @import("../../tty/tty.zig").close(w.tty);
    w.tty = 0xFF;
}

/// Remove a window. Tears down per-window resources, frees the slot, and
/// splices it out of z_stack. With stable slot IDs, no other slot's data
/// is touched — outside references to other slots stay valid. Refs that
/// were pointing AT this slot (focused, drag_win, resize_win) get cleaned
/// up here. Returns the window's terminal data for the caller to free once
/// windows_lock is dropped.
fn removeWindow(slot: u8) ?*TerminalData {
    if (slot >= MAX_WINDOWS or !slot_used[slot]) return null;
    const term = windows[slot].term;
    windows[slot].term = null;
    detachShell(&windows[slot]);

    removeFromZ(slot);
    freeSlot(slot);

    // If we were focused on the dying slot, hand focus to whatever is now
    // on top of the z-stack (most recently raised window).
    if (wm.focused == slot) {
        if (topSlot()) |t| setFocused(t) else setFocused(0);
    }
    // Active drag/resize on the dying slot is cancelled.
    if (desktop.dragging and desktop.drag_win == slot) desktop.dragging = false;
    if (desktop.resizing and desktop.resize_win == slot) desktop.resizing = false;
    return term;
}

/// What destroyGuiWindow took down, for the owner to finish with: the
/// windows are gone, the framebuffer's place in its address space and the
/// GPU slot behind it are not (see gui_window.zig).
pub const DestroyedGui = struct {
    windows: u8 = 0,
    /// Pages the owner has mapped at GUI_FB_USER_BASE.
    fb_pages: u32 = 0,
    /// GPU compositor slots the windows drew through, a bit each.
    gpu_slots: u32 = 0,
};

/// Whose GUI windows destroyGuiWindow takes down.
pub const GuiOwner = union(enum) {
    /// The task that made them: sysDestroyWindow, the task's end.
    task: u8,
    /// Every task of a thread group, for the group's end: also a window
    /// whose task is ending beside the last one and has yet to take it.
    group: u8,
};

/// Whether thread group `tgid` has a GUI window.
pub fn groupHasGuiWindow(tgid: u8) bool {
    const wflags = lockWindows();
    defer unlockWindows(wflags);
    for (0..MAX_WINDOWS) |i| {
        if (slot_used[i] and windows[i].owner_pid != 0xFF and windows[i].owner_group == tgid) return true;
    }
    return false;
}

/// Destroy the GUI windows of `who`.
pub fn destroyGuiWindow(who: GuiOwner) DestroyedGui {
    var gone: DestroyedGui = .{};
    // Declared first so it runs after both locks are released.
    var dead_terms: [MAX_WINDOWS]?*TerminalData = @splat(null);
    defer for (dead_terms) |dt| if (dt) |t| freeTerminalData(t);
    // Mutex held across the whole teardown so growGuiFb cannot race
    // its publish + OLD-release sequence against our unmapGuiFB. See
    // the lock's declaration for the deadlock analysis. Lock order is
    // ALWAYS gui_fb_realloc_lock -> windows_lock; never the reverse.
    surface.gui_fb_realloc_lock.acquire();
    defer surface.gui_fb_realloc_lock.release();
    const wflags = lockWindows();
    defer unlockWindows(wflags);
    // The group's end is the boot helper's too: its pid passes to another
    // process next.
    switch (who) {
        .group => |g| if (g == @atomicLoad(u8, &wallpaper_helper, .monotonic)) @atomicStore(u8, &wallpaper_helper, 0xFF, .monotonic),
        .task => {},
    }
    // Restore cursor if this process had it hidden
    if (@import("../../driver.zig").virtio_gpu.cursor_hidden) {
        @import("../../driver.zig").virtio_gpu.showCursor();
    }
    // Iterate slots (not z_stack) since removeWindow mutates z_stack and
    // we'd skip entries with a live z_stack iteration.
    for (0..MAX_WINDOWS) |k| {
        const i: u8 = @intCast(k);
        if (!slot_used[i]) continue;
        const pid = windows[i].owner_pid;
        const match = switch (who) {
            .task => |p| pid == p,
            .group => |g| pid != 0xFF and windows[i].owner_group == g,
        };
        if (!match) continue;
        gone.windows += 1;
        debug.klog("[desktop] GUI window destroyed for PID {d}\n", .{pid});
        if (windows[i].gui_fb != null) {
            const aw = if (windows[i].gui_alloc_w > 0) windows[i].gui_alloc_w else windows[i].gui_w;
            const ah = if (windows[i].gui_alloc_h > 0) windows[i].gui_alloc_h else windows[i].gui_h;
            const fb_size = aw * ah * 4;
            const num_pages = (fb_size + 4095) / 4096;
            gone.fb_pages = @max(gone.fb_pages, num_pages);
            if (windows[i].gpu_slot) |s| gone.gpu_slots |= @as(u32, 1) << @intCast(s);
            // unmapGuiFB iterates internally over front + any lazily-
            // allocated back-buffer slots (tracked per-PID in paging.zig:
            // sound only because no window outlives its owner's pid, see
            // gui_window.zig). Each slot was sized num_pages. A GPU
            // slot window registered none: its framebuffer is the slot's.
            const free_before = pmm.freeFrameCount();
            paging.unmapGuiFB(pid, num_pages);
            const free_after = pmm.freeFrameCount();
            debug.klog("[fb-diag] pid={d} unmapGuiFB num_pages={d} free {d}->{d} (returned={d})\n", .{
                pid, num_pages, free_before, free_after, free_after -% free_before,
            });
        }
        dead_terms[i] = removeWindow(i);
        dirty_rects_mod.force_full_kind = true;
        markDirtyFull();
    }
    if (gone.windows != 0) wake.requestWake();
    return gone;
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

/// Which window a caller has to stand behind: the focused one, or any the
/// user can see.
pub const Standing = enum { focused, on_screen };

/// True iff task `pid` belongs to a program the user has in front of them:
/// its group owns such a window, or it descends from that group or from the
/// window's shell — a tool run in the terminal, a helper the app started.
/// Gates what is the user's rather than any program's: the key table, the
/// clipboard, the pointer, the wallpaper. An orphan is init's child and
/// stands behind nothing.
pub fn actsFor(pid: u8, standing: Standing) bool {
    // No desktop: one console, nobody to take from.
    if (!desktop.active) return true;
    var cur = pid;
    var hops: u8 = 0;
    while (hops < 16 and cur < process.MAX_PROCS) : (hops += 1) {
        const pcb = process.getPCB(cur);
        switch (standing) {
            .focused => if (wm.focused < MAX_WINDOWS and slot_used[wm.focused] and
                windowIsOf(&windows[wm.focused], cur, pcb.tgid)) return true,
            .on_screen => for (z_stack[0..wm.z_count]) |i| {
                if (windowIsOf(&windows[i], cur, pcb.tgid)) return true;
            },
        }
        const parent = pcb.parent_pid;
        if (parent == 0 or parent == cur) return false;
        cur = parent;
    }
    return false;
}

fn windowIsOf(w: *const wm.Window, pid: u8, tgid: u8) bool {
    if (!w.visible or w.minimized) return false;
    if (w.owner_group != 0xFF and w.owner_group == tgid) return true;
    return w.shell_pid != 0xFF and (w.shell_pid == pid or w.shell_pid == tgid);
}

/// The wallpaper helper the desktop starts at boot, 0xFF once its process
/// has ended. It has no window to stand behind.
pub var wallpaper_helper: u8 = 0xFF;

/// set_wallpaper: a program on screen (the settings app applying a picture
/// may have lost focus by the time its helper has decoded it), or the boot
/// helper.
pub fn maySetWallpaper(pid: u8) bool {
    const helper = @atomicLoad(u8, &wallpaper_helper, .monotonic);
    return (helper != 0xFF and process.procs[pid].tgid == helper) or actsFor(pid, .on_screen);
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

/// The terminal (tty/tty.zig) of the focused window, 0xFF if it has none.
/// Read at interrupt time, like focusedSignalTarget.
pub fn focusedTty() u8 {
    if (!slot_used[wm.focused]) return 0xFF;
    const w = &windows[wm.focused];
    if (!w.visible) return 0xFF;
    return w.tty;
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
    // We don't peek event kinds — non-char events are vanishingly rare
    // (no current pusher), and a stale POLLIN that resolves to zero bytes
    // is benign (caller re-polls).
    return !w.events.isEmpty();
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
                // Only the presses that landed on this window's content.
                buf[2] = if (desktop.app_btns_win == i) @as(u32, desktop.app_btns) else 0;
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
        const vgpu = @import("../../driver.zig").virtio_gpu;
        if (hidden) vgpu.hideCursor() else vgpu.showCursor();
    }
}

/// Warp the pointer to the centre of `pid`'s window, for mouse look. Only
/// while that window has the focus: the pointer is not a background
/// window's to pull under itself. False when it was left alone.
pub fn centerMouse(pid: u8) bool {
    for (z_stack[0..wm.z_count]) |i| {
        if (i == wm.focused and windows[i].owner_pid == pid and windows[i].visible) {
            const cx = windows[i].x + @as(i32, @intCast(windows[i].width / 2));
            const cy = windows[i].y + @as(i32, TITLEBAR_H) + @as(i32, @intCast((windows[i].height -| TITLEBAR_H) / 2));
            mouse.x = cx;
            mouse.y = cy;
            return true;
        }
    }
    return false;
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
