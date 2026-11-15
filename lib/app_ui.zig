// Immediate-mode widgets for app.run. The app's `frame` lists the window's
// content top to bottom and gets each widget's answer inline:
//
//   pub fn frame(ui: *app.Ui) void {
//       ui.title("Sound");
//       ui.beginGroup("Output");
//       if (ui.choice(&.{ "Speakers", "Headphones" }, output)) |i| output = i;
//       if (ui.stepper(volume_text, "100%")) |step| volume += step * 5;
//       _ = ui.toggle("Mute", &muted);
//       ui.endGroup();
//       if (ui.button("Apply")) apply();
//   }
//
// frame runs once per input event with nothing drawn, and again to paint
// when something changed. Widgets answer only in the input pass, so act on
// their results and nowhere else in frame; draw your own things only when
// `ui.painting`.

const libc = @import("libc");
const gfx = @import("graphics");
const fa = @import("font_atlas");
const widgets = @import("ui");

pub const Point = struct { x: i32, y: i32 };

pub const Rect = struct {
    x: u32 = 0,
    y: u32 = 0,
    w: u32 = 0,
    h: u32 = 0,

    pub fn contains(self: Rect, p: Point) bool {
        if (p.x < 0 or p.y < 0) return false;
        const px: u32 = @intCast(p.x);
        const py: u32 = @intCast(p.y);
        return px >= self.x and px < self.x + self.w and py >= self.y and py < self.y + self.h;
    }
};

pub const Align = enum { left, center, right };
pub const ButtonStyle = widgets.ButtonStyle;

const MARGIN: u32 = 12;
const TOP: u32 = 8;
/// Between one line of widgets and the next.
const LINE_GAP: u32 = 8;
/// Between widgets sharing a line.
const ITEM_GAP: u32 = 6;
const HEADING_GAP: u32 = 6;
const GROUP_GAP: u32 = 16;
const BUTTON_H: u32 = 26;
const BUTTON_PAD: u32 = 14;
const BUTTON_MIN_W: u32 = 64;
const BAR_H: u32 = 6;
const MAX_GROUPS: usize = 16;

pub const Ui = struct {
    canvas: *gfx.Canvas,
    /// Visible content size.
    w: u32 = 0,
    h: u32 = 0,

    /// Input as of the event being handled.
    mouse: Point = .{ .x = -1, .y = -1 },
    down: bool = false,
    was_down: bool = false,
    /// Character typed by this event, else 0.
    key: u8 = 0,

    /// The paint pass; false in the input pass.
    painting: bool = false,
    /// Set at the top of frame while something modal covers the widgets:
    /// they are drawn but ignore the mouse. Cleared every pass.
    blocked: bool = false,
    /// A repaint is wanted.
    changed: bool = true,

    /// Widget under the cursor as of the last input pass, and the one the
    /// button went down on. Ids are positions, so they survive widgets
    /// appearing elsewhere.
    hot: u32 = 0,
    hot_next: u32 = 0,
    active: u32 = 0,

    left: u32 = 0,
    right: u32 = 0,
    /// Top of the next line, and the bottom of the lowest widget so far.
    y: u32 = 0,
    bottom: u32 = 0,
    /// Colour under the next widget, for its rounded corners.
    surface: u32 = 0,
    last: Rect = .{},
    /// Top and height of the widget that began the current line.
    line_y: u32 = 0,
    line_h: u32 = 0,
    same_line: bool = false,
    next_align: Align = .left,

    /// Group heights as last measured; a group's background is painted
    /// before its content, from the pass before.
    group_h: [MAX_GROUPS]u32 = [_]u32{0} ** MAX_GROUPS,
    group_i: usize = 0,
    group_top: u32 = 0,
    in_group: bool = false,

    // --- Driven by app.run ---

    /// Take in an event. False if widgets have no use for it.
    pub fn feed(self: *Ui, ev: libc.Event) bool {
        self.was_down = self.down;
        self.key = 0;
        switch (ev.kindOf()) {
            .mouse_move => {
                self.mouse = .{ .x = @bitCast(ev.a), .y = @bitCast(ev.b) };
                self.down = ev.c & 1 != 0;
            },
            .mouse_button => {
                self.mouse = .{ .x = @bitCast(ev.b), .y = @bitCast(ev.c) };
                self.down = ev.buttonsState() & 1 != 0;
            },
            .key_char => self.key = @truncate(ev.a),
            .focus_out => {
                self.mouse = .{ .x = -1, .y = -1 };
                self.down = false;
            },
            .resize => {},
            else => return false,
        }
        return true;
    }

    pub fn begin(self: *Ui, painting: bool) void {
        fa.ensureLoaded();
        self.painting = painting;
        self.blocked = false;
        self.hot_next = 0;
        self.left = MARGIN;
        self.right = self.w -| MARGIN;
        self.y = TOP;
        self.bottom = TOP;
        self.surface = widgets.palette.window_bg;
        self.last = .{};
        self.same_line = false;
        self.next_align = .left;
        self.group_i = 0;
        self.in_group = false;
        if (painting) {
            self.changed = false;
            self.canvas.fillRect(0, 0, self.w, self.h, self.surface);
        }
    }

    pub fn end(self: *Ui) void {
        if (self.painting) return;
        if (self.hot_next != self.hot) {
            self.hot = self.hot_next;
            self.changed = true;
        }
        if (!self.down) self.active = 0;
        // The event is spent: the paint pass must not see its key or its
        // button edge again.
        self.key = 0;
        self.was_down = self.down;
    }

    /// Height the content laid out by the last pass needs.
    pub fn contentHeight(self: *const Ui) u32 {
        return self.bottom + MARGIN;
    }

    // --- Layout ---

    /// Put the next widget on the line of the last one.
    pub fn sameLine(self: *Ui) void {
        if (self.last.h != 0) self.same_line = true;
    }

    /// Where the next widget sits in the column; then back to the left.
    pub fn alignNext(self: *Ui, a: Align) void {
        self.next_align = a;
    }

    /// Extra space before the next line.
    pub fn gap(self: *Ui, px: u32) void {
        self.y += px;
    }

    /// Room for content of the app's own; `w` 0 takes the column's width.
    pub fn space(self: *Ui, w: u32, h: u32) Rect {
        return self.place(if (w == 0) self.right -| self.left else w, h);
    }

    fn place(self: *Ui, w: u32, h: u32) Rect {
        var r = Rect{ .x = self.left, .y = self.y, .w = w, .h = h };
        const on_line = self.same_line and
            (self.next_align == .right or self.last.x + self.last.w + ITEM_GAP + w <= self.right);
        if (on_line) {
            // Centred on the widget that began the line.
            r.y = (2 * self.line_y + self.line_h -| h) / 2;
            r.x = if (self.next_align == .right) self.right -| w else self.last.x + self.last.w + ITEM_GAP;
        } else {
            switch (self.next_align) {
                .left => {},
                .center => r.x = self.left + (self.right -| self.left -| w) / 2,
                .right => r.x = self.right -| w,
            }
            self.line_y = r.y;
            self.line_h = h;
        }
        self.same_line = false;
        self.next_align = .left;
        self.last = r;
        self.bottom = @max(self.bottom, r.y + h);
        self.y = self.bottom + LINE_GAP;
        return r;
    }

    // --- Interaction ---

    const Hit = struct { clicked: bool, state: widgets.ButtonState };

    fn interact(self: *Ui, r: Rect) Hit {
        const id = (((r.y & 0x7FFF) << 16) | (r.x & 0xFFFF)) + 1;
        const inside = !self.blocked and r.contains(self.mouse);
        if (self.painting) {
            const state: widgets.ButtonState = if (!inside)
                .normal
            else if (self.active == id and self.down)
                .pressed
            else if (self.active == 0)
                .hover
            else
                .normal;
            return .{ .clicked = false, .state = state };
        }
        if (inside and (self.active == 0 or self.active == id)) self.hot_next = id;
        if (inside and self.down and !self.was_down) {
            self.active = id;
            self.changed = true;
        }
        var fired = false;
        if (!self.down and self.was_down and self.active == id) {
            fired = inside;
            self.changed = true;
        }
        return .{ .clicked = fired, .state = .normal };
    }

    /// A press and release inside `r`, for an area from space().
    pub fn clicked(self: *Ui, r: Rect) bool {
        return self.interact(r).clicked;
    }

    /// Ask for a repaint: something the widgets do not show changed.
    pub fn repaint(self: *Ui) void {
        self.changed = true;
    }

    pub fn close(_: *const Ui) noreturn {
        libc.destroyWindow();
        libc.exit();
    }

    // --- Widgets ---

    pub fn title(self: *Ui, str: []const u8) void {
        const atlas = &fa.default_24;
        const r = self.place(atlas.measure(str), atlas.line_height);
        if (self.painting) fa.drawText(self.canvas, @intCast(r.x), @intCast(r.y), str, widgets.palette.text_strong, atlas);
        self.y += 4;
    }

    pub fn label(self: *Ui, str: []const u8) void {
        self.text(str, widgets.palette.text_normal);
    }

    pub fn text(self: *Ui, str: []const u8, color: u32) void {
        const atlas = &fa.default_16;
        const r = self.place(atlas.measure(str), atlas.line_height);
        if (self.painting) fa.drawText(self.canvas, @intCast(r.x), @intCast(r.y), str, color, atlas);
    }

    pub fn button(self: *Ui, str: []const u8) bool {
        return self.styledButton(str, .default);
    }

    pub fn styledButton(self: *Ui, str: []const u8, style: ButtonStyle) bool {
        const w = @max(fa.default_16.measure(str) + 2 * BUTTON_PAD, BUTTON_MIN_W);
        return self.sizedButton(str, w, style);
    }

    fn sizedButton(self: *Ui, str: []const u8, w: u32, style: ButtonStyle) bool {
        const r = self.place(w, BUTTON_H);
        const hit = self.interact(r);
        if (self.painting) {
            const b = widgets.Button{ .x = r.x, .y = r.y, .w = r.w, .h = r.h, .label = str, .state = hit.state };
            b.drawStyled(self.canvas, style, self.surface);
        }
        return hit.clicked;
    }

    /// `value` between a "-" and a "+" button; returns -1 or 1 when one is
    /// clicked. `widest` is the longest text the value can be, so the "+"
    /// stays put as the value changes.
    pub fn stepper(self: *Ui, value: []const u8, widest: []const u8) ?i32 {
        const atlas = &fa.default_16;
        var step: ?i32 = null;
        if (self.sizedButton("-", BUTTON_H, .default)) step = -1;
        self.sameLine();
        const value_w = atlas.measure(value);
        const r = self.place(@max(value_w, atlas.measure(widest)), atlas.line_height);
        if (self.painting) {
            const x = r.x + (r.w - value_w) / 2;
            fa.drawText(self.canvas, @intCast(x), @intCast(r.y), value, widgets.palette.text_normal, atlas);
        }
        self.sameLine();
        if (self.sizedButton("+", BUTTON_H, .default)) step = 1;
        return step;
    }

    /// A line of options with `selected` lit. Returns the one clicked.
    pub fn choice(self: *Ui, options: []const []const u8, selected: usize) ?usize {
        var picked: ?usize = null;
        for (options, 0..) |opt, i| {
            if (i != 0) self.sameLine();
            if (self.styledButton(opt, if (i == selected) .primary else .default)) picked = i;
        }
        return picked;
    }

    /// A labelled switch. Flips `on` when clicked and returns true then.
    pub fn toggle(self: *Ui, str: []const u8, on: *bool) bool {
        const atlas = &fa.default_16;
        const sw_w = widgets.Toggle.W;
        const sw_h = widgets.Toggle.H;
        const h = @max(sw_h, @as(u32, atlas.line_height));
        const r = self.place(self.right -| self.left, h);
        const sw = Rect{ .x = r.x + r.w -| sw_w, .y = r.y + (h - sw_h) / 2, .w = sw_w, .h = sw_h };
        const hit = self.interact(sw);
        if (hit.clicked) on.* = !on.*;
        if (self.painting) {
            fa.drawText(self.canvas, @intCast(r.x), @intCast(r.y + (h - atlas.line_height) / 2), str, widgets.palette.text_normal, atlas);
            const t = widgets.Toggle{ .x = sw.x, .y = sw.y, .on = on.*, .state = hit.state };
            t.draw(self.canvas, self.surface);
        }
        return hit.clicked;
    }

    /// A bar filled to value/max across the column.
    pub fn progress(self: *Ui, value: u32, max: u32) void {
        const r = self.place(self.right -| self.left, BAR_H);
        if (!self.painting) return;
        const p = &widgets.palette;
        self.canvas.fillRect(r.x, r.y, r.w, r.h, p.btn_default_bot);
        if (max != 0) {
            const fill: u32 = @intCast(@as(u64, @min(value, max)) * r.w / max);
            self.canvas.fillRect(r.x, r.y, fill, r.h, p.btn_primary_bot);
        }
        self.canvas.roundCornersRadius(r.x, r.y, r.w, r.h, BAR_H / 2, self.surface);
    }

    /// Start a card, under `heading` if given; widgets up to endGroup go
    /// inside it. Groups do not nest.
    pub fn beginGroup(self: *Ui, heading: ?[]const u8) void {
        if (self.in_group) return;
        if (heading) |str| {
            self.text(str, widgets.palette.text_muted);
            self.y = self.bottom + HEADING_GAP;
        }
        self.in_group = true;
        self.group_top = self.y;
        if (self.painting and self.group_i < MAX_GROUPS and self.group_h[self.group_i] != 0) {
            const card = widgets.Card{ .x = self.left, .y = self.y, .w = self.right -| self.left, .h = self.group_h[self.group_i] };
            card.drawBg(self.canvas, self.surface);
        }
        self.left += widgets.Card.HPAD;
        self.right -|= widgets.Card.HPAD;
        self.y += widgets.Card.VPAD;
        self.bottom = self.y;
        self.surface = widgets.palette.card_bg;
        self.last = .{};
    }

    pub fn endGroup(self: *Ui) void {
        if (!self.in_group) return;
        self.in_group = false;
        const h = self.bottom + widgets.Card.VPAD - self.group_top;
        if (self.group_i < MAX_GROUPS) {
            // Painted at another height just now: paint again.
            if (self.group_h[self.group_i] != h) {
                self.group_h[self.group_i] = h;
                self.changed = true;
            }
            self.group_i += 1;
        }
        self.left = MARGIN;
        self.right = self.w -| MARGIN;
        self.surface = widgets.palette.window_bg;
        self.bottom = self.group_top + h;
        self.y = self.bottom + GROUP_GAP;
        self.last = .{};
        self.same_line = false;
    }
};
