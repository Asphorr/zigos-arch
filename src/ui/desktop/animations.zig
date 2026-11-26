// Window animations — opening / closing / minimizing / restoring /
// fullscreening / unfullscreening. Each animation runs for a fixed number
// of frames and eases out (1 - (1 - t)^2) from a saved start geometry to
// an end geometry. The compositor reads w.x/w.y/w.width/w.height every
// frame; we mutate those directly so no separate "rendered geometry"
// channel is needed.
//
// A closing animation that has run out hands its window to the caller of
// advance(): what goes with a window (its process, a terminal's shell, the
// slot) is the desktop's to know.

const wm = @import("window.zig");
const gfx = @import("../gfx.zig");
const layout = @import("layout.zig");
const dirty_rects = @import("dirty.zig");
const events = @import("../events.zig");

const Window = wm.Window;
const AnimationType = wm.AnimationType;
const TITLEBAR_H = layout.TITLEBAR_H;
const TASKBAR_H = layout.TASKBAR_H;

inline fn dockY() i32 {
    return @intCast(gfx.screen_h - TASKBAR_H);
}

fn lerpI32(a: i32, b: i32, num: u32, den: u32) i32 {
    if (den == 0) return b;
    return a + @as(i32, @intCast(@divTrunc(@as(i64, b - a) * @as(i64, @intCast(num)), @as(i64, @intCast(den)))));
}

fn lerpU32(a: u32, b: u32, num: u32, den: u32) u32 {
    if (den == 0) return b;
    if (b >= a) return a + (b - a) * num / den else return a - (a - b) * num / den;
}

pub fn start(idx: u8, atype: AnimationType) void {
    if (idx >= wm.MAX_WINDOWS or !wm.slot_used[idx]) return;
    const w = &wm.windows[idx];
    w.anim_type = atype;
    w.anim_frame = 0;
    w.anim_total = 6;
    // Event-driven compositor wake: the next loop iteration will see
    // hasActiveAnimations() and self-wake itself per frame until the
    // animation drains; this initial wake is what brings the desktop
    // back at all if it was parked.
    @import("wake.zig").requestWake();

    switch (atype) {
        .opening => {
            w.anim_end_x = w.x;
            w.anim_end_y = w.y;
            w.anim_end_w = w.width;
            w.anim_end_h = w.height;
            const min_w = w.width / 3;
            const min_h = w.height / 3;
            w.anim_start_x = w.x + @as(i32, @intCast(w.width / 2 -| min_w / 2));
            w.anim_start_y = w.y + @as(i32, @intCast(w.height / 2 -| min_h / 2));
            w.anim_start_w = min_w;
            w.anim_start_h = min_h;
            w.x = w.anim_start_x;
            w.y = w.anim_start_y;
            w.width = w.anim_start_w;
            w.height = w.anim_start_h;
        },
        .closing => {
            w.anim_start_x = w.x;
            w.anim_start_y = w.y;
            w.anim_start_w = w.width;
            w.anim_start_h = w.height;
            const end_w = w.width / 3;
            const end_h = w.height / 3;
            w.anim_end_x = w.x + @as(i32, @intCast(w.width / 2 -| end_w / 2));
            w.anim_end_y = w.y + @as(i32, @intCast(w.height / 2 -| end_h / 2));
            w.anim_end_w = end_w;
            w.anim_end_h = end_h;
        },
        .minimizing => {
            w.anim_start_x = w.x;
            w.anim_start_y = w.y;
            w.anim_start_w = w.width;
            w.anim_start_h = w.height;
            w.anim_end_x = @intCast(gfx.screen_w / 2 - 30);
            w.anim_end_y = dockY();
            w.anim_end_w = 60;
            w.anim_end_h = TITLEBAR_H + 10;
        },
        .restoring => {
            w.anim_start_x = @intCast(gfx.screen_w / 2 - 30);
            w.anim_start_y = dockY();
            w.anim_start_w = 60;
            w.anim_start_h = TITLEBAR_H + 10;
            w.anim_end_x = w.x;
            w.anim_end_y = w.y;
            w.anim_end_w = w.width;
            w.anim_end_h = w.height;
            w.x = w.anim_start_x;
            w.y = w.anim_start_y;
            w.width = w.anim_start_w;
            w.height = w.anim_start_h;
            w.minimized = false;
        },
        .fullscreening => {
            w.anim_start_x = w.x;
            w.anim_start_y = w.y;
            w.anim_start_w = w.width;
            w.anim_start_h = w.height;
            // anim_end set by caller (toggleFullscreen)
        },
        .unfullscreening => {
            w.anim_start_x = w.x;
            w.anim_start_y = w.y;
            w.anim_start_w = w.width;
            w.anim_start_h = w.height;
            // anim_end set by caller (toggleFullscreen)
        },
        .none => {},
    }
}

/// One frame of every running animation. `closed` is called for a window
/// whose closing animation has run out, and takes it down.
pub fn advance(comptime closed: fn (slot: u8) void) void {
    // Iterate slots, NOT z_stack. A closing window's final frame calls
    // `closed`, which ends in removeWindow (for a program's window through
    // process.killProcess → desktop.destroyGuiWindow) and
    // splices the closing window (and any same-PID siblings) out of z_stack
    // mid-iteration. Walking z_stack here would then skip whatever shifted
    // into the freed z-position and read a stale trailing entry on the final
    // iteration — masked only because the common case closes the topmost
    // window (the last iteration, where the splice just drops the tail).
    // Advancing animations is order-independent, and stable slot IDs mean
    // removeWindow never relocates another window's data, so slot order is
    // both correct and immune to the splice. (destroyGuiWindow iterates
    // slots for exactly this reason — see its comment.)
    for (0..wm.MAX_WINDOWS) |k| {
        const i: u8 = @intCast(k);
        if (!wm.slot_used[i]) continue;
        const w = &wm.windows[i];
        if (w.anim_type == .none) continue;

        w.anim_frame += 1;
        const frame: u32 = w.anim_frame;
        const total: u32 = w.anim_total;

        // Ease-out: t = 1 - (1 - frame/total)^2
        const rem = total -| frame;
        const ease_num = total * total - rem * rem;
        const ease_den = total * total;

        w.x = lerpI32(w.anim_start_x, w.anim_end_x, ease_num, ease_den);
        w.y = lerpI32(w.anim_start_y, w.anim_end_y, ease_num, ease_den);
        w.width = @max(lerpU32(w.anim_start_w, w.anim_end_w, ease_num, ease_den), 20);
        w.height = @max(lerpU32(w.anim_start_h, w.anim_end_h, ease_num, ease_den), 20);

        if (w.anim_frame >= w.anim_total) {
            w.x = w.anim_end_x;
            w.y = w.anim_end_y;
            w.width = w.anim_end_w;
            w.height = w.anim_end_h;

            const atype = w.anim_type;
            w.anim_type = .none;

            if (atype == .closing) {
                // The slot may be free from here on: `w` is not to be read.
                closed(i);
                dirty_rects.force_full_kind = true;
                dirty_rects.markFull();
            } else if (atype == .minimizing) {
                w.x = w.anim_start_x;
                w.y = w.anim_start_y;
                w.width = w.anim_start_w;
                w.height = w.anim_start_h;
                w.minimized = true;
            } else if (atype == .fullscreening or atype == .unfullscreening) {
                // Maximize / un-maximize finished — let the owning app
                // react to its new size. Without this, GUI apps stay
                // laid-out for their pre-maximize dimensions and waste
                // the extra screen estate (or render off-canvas). The
                // event carries the content size, like every resize.
                w.events.push(.{
                    .kind = @intFromEnum(events.EventKind.resize),
                    .a = w.width,
                    .b = w.height -| TITLEBAR_H,
                });
            }
        }
    }
}

pub fn hasActive() bool {
    for (wm.z_stack[0..wm.z_count]) |i| {
        if (wm.windows[i].anim_type != .none) return true;
    }
    return false;
}
