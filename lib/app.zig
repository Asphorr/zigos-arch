// Window and main loop of a GUI app. The app supplies handlers; this owns
// the framebuffer, resize and maximize, the close request, and presenting
// only when something was redrawn.
//
//   const app = @import("app");
//
//   export fn _start() linksection(".text.entry") callconv(.c) void {
//       app.run(@This(), .{ .width = 320, .height = 240 });
//   }
//
//   pub fn draw(win: *app.Window) void { win.canvas.clear(0x1E1E20); }
//   pub fn event(win: *app.Window, ev: app.Event) void { ... win.invalidate(); }
//
// An app made of standard controls supplies `frame` instead of `draw` and
// gets widgets and layout: see app_ui.zig.

const libc = @import("libc");
const gfx = @import("graphics");
const app_ui = @import("app_ui.zig");

pub const Event = libc.Event;
pub const Point = app_ui.Point;
pub const Rect = app_ui.Rect;
pub const Ui = app_ui.Ui;

pub const Options = struct {
    /// Initial content size in pixels, clamped to the screen. With `frame`,
    /// height 0 fits the content.
    width: u32,
    height: u32 = 0,
    /// Escape closes the window.
    escape_closes: bool = false,
    /// Call `tick` this often, in ms; 0 = never. For apps that show live data.
    tick_ms: u32 = 0,
};

pub const Window = struct {
    /// The whole framebuffer allocation; the visible part is (0, 0, w, h).
    canvas: gfx.Canvas,
    w: u32,
    h: u32,
    dirty: bool = true,

    /// Redraw before the loop next sleeps.
    pub fn invalidate(self: *Window) void {
        self.dirty = true;
    }

    pub fn close(_: *const Window) noreturn {
        libc.destroyWindow();
        libc.exit();
    }
};

/// Cursor position of a mouse event, in content coordinates.
pub fn mousePos(ev: Event) Point {
    return if (ev.kindOf() == .mouse_move)
        .{ .x = @bitCast(ev.a), .y = @bitCast(ev.b) }
    else
        .{ .x = @bitCast(ev.b), .y = @bitCast(ev.c) };
}

/// Where the left button went down, if `ev` is that.
pub fn leftPress(ev: Event) ?Point {
    if (ev.kindOf() != .mouse_button or ev.buttonIndex() != 0 or !ev.buttonPressed()) return null;
    return mousePos(ev);
}

/// Pixels of framebuffer a window gets beyond its initial size, as headroom
/// for resizing by hand; maximize grows the allocation on its own.
const HEADROOM_PIXELS: u32 = 524288;
/// Longest single sleep in the kernel: a lost wakeup costs this much, not
/// the app.
const MAX_WAIT_MS: u32 = 1000;

/// Up to twice the initial size, cut back to HEADROOM_PIXELS but never
/// below the initial size.
fn allocSize(init_w: u32, init_h: u32, scr_w: u32, scr_h: u32) [2]u32 {
    var aw = @max(init_w, @min(init_w * 2, scr_w));
    var ah = @max(init_h, @min(init_h * 2, scr_h));
    while (aw * ah > HEADROOM_PIXELS) {
        const can_w = aw > init_w;
        const can_h = ah > init_h;
        if (!can_w and !can_h) break;
        if (can_w and (!can_h or aw > ah)) {
            aw = @max(init_w, aw -| 16);
        } else {
            ah = @max(init_h, ah -| 16);
        }
    }
    return .{ aw, ah };
}

/// Open a window and run `App` in it until it closes. `App` is a namespace
/// (usually the app's file, `@This()`) with public functions:
///   draw(win: *Window) void              paint the whole content, or
///   frame(ui: *Ui) void                  widgets, in place of draw
///   event(win: *Window, ev: Event) void  optional; invalidate() to repaint
///   tick(win: *Window) void              optional, every opts.tick_ms
///   init(win: *Window) void              optional, once before the first draw
pub fn run(comptime App: type, opts: Options) noreturn {
    const framed = @hasDecl(App, "frame");
    const scr = libc.getScreenSize();
    const init_w = @min(opts.width, scr.w);

    // Until the window exists, frame lays out against a canvas of one pixel.
    var scratch_px = [1]u32{0};
    var scratch = gfx.Canvas.init(&scratch_px, 1, 1);
    var ui = Ui{ .canvas = &scratch, .w = init_w };
    var want_h = opts.height;
    if (framed and want_h == 0) {
        ui.begin(false);
        App.frame(&ui);
        ui.end();
        want_h = ui.contentHeight();
    }

    const init_h = @min(want_h, scr.h);
    const alloc = allocSize(init_w, init_h, scr.w, scr.h);
    const fbw = libc.createWindowEx(alloc[0], alloc[1], init_w, init_h) orelse libc.exit();
    var alloc_w = fbw.alloc_w;
    var alloc_h = fbw.alloc_h;
    var win = Window{
        .canvas = gfx.Canvas.init(fbw.fb, alloc_w, alloc_h),
        .w = init_w,
        .h = init_h,
    };
    // Asking for the allocation opts the window into grow-on-maximize.
    _ = libc.getWindowAlloc();

    if (@hasDecl(App, "init")) App.init(&win);

    ui.canvas = &win.canvas;
    if (framed) {
        // One pass with nothing drawn, so the first paint has its layout.
        ui.h = win.h;
        ui.begin(false);
        App.frame(&ui);
        ui.end();
    }

    const tick_ticks: u32 = opts.tick_ms / 10;
    var last_tick = libc.uptime();
    // The event that ended the last wait, then the rest of the queue.
    var next = libc.pollEvent();
    while (true) {
        while (next) |ev| : (next = libc.pollEvent()) {
            switch (ev.kindOf()) {
                .close_request => win.close(),
                .key_char => if (opts.escape_closes and @as(u8, @truncate(ev.a)) == 0x1B) win.close(),
                .resize => {
                    // Maximize may have grown the framebuffer: same pointer,
                    // new stride.
                    const wa = libc.getWindowAlloc();
                    if (wa.w != 0 and (wa.w != alloc_w or wa.h != alloc_h)) {
                        alloc_w = wa.w;
                        alloc_h = wa.h;
                        win.canvas = gfx.Canvas.init(fbw.fb, alloc_w, alloc_h);
                        win.dirty = true;
                    }
                    const new_w = @min(ev.a, alloc_w);
                    const new_h = @min(ev.b, alloc_h);
                    if (new_w != win.w or new_h != win.h) {
                        win.w = new_w;
                        win.h = new_h;
                        win.dirty = true;
                    }
                },
                else => {},
            }
            if (@hasDecl(App, "event")) App.event(&win, ev);
            if (framed) {
                if (ui.feed(ev)) {
                    ui.w = win.w;
                    ui.h = win.h;
                    ui.begin(false);
                    App.frame(&ui);
                    ui.end();
                }
                if (ui.changed) win.dirty = true;
            }
        }

        var wait_ms: u32 = MAX_WAIT_MS;
        if (@hasDecl(App, "tick")) {
            if (tick_ticks != 0) {
                var since = libc.uptime() -% last_tick;
                if (since >= tick_ticks) {
                    last_tick +%= since;
                    since = 0;
                    App.tick(&win);
                }
                wait_ms = @min(wait_ms, (tick_ticks - since) * 10);
            }
        }

        if (win.dirty) {
            win.dirty = false;
            if (framed) {
                ui.w = win.w;
                ui.h = win.h;
                ui.begin(true);
                App.frame(&ui);
                ui.end();
                // Laid out differently than it was painted: once more.
                if (ui.changed) win.dirty = true;
            } else {
                App.draw(&win);
            }
            libc.present();
        }
        next = libc.waitEvent(if (win.dirty) 0 else wait_ms);
    }
}
