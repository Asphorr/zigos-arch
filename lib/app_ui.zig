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
//
// An app with content of its own frames it with bars and takes the rest:
//
//   pub fn frame(ui: *app.Ui) void {
//       ui.beginBar();
//       if (ui.iconButton(.back, can_go_back)) goBack();
//       ui.heading(title);
//       ui.endBar();
//       ui.statusBar(status, "");
//       const view = ui.list(ui.fill(), &list_state, row_count, 26);
//       if (view.opened) |row| open(row);
//       if (ui.painting) for (view.first..view.first + view.count) |row| drawRow(ui.canvas, view.rowRect(@intCast(row)), row);
//   }
//
// In an area from fill() or space(), the input of the event is in `mouse`,
// `wheel`, `key`, `special`, `mods` and `clicks`, and pressed()/dragging()
// tell where the button went down and where it is now.

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
const PROGRESS_H: u32 = 6;
const MAX_GROUPS: usize = 16;
const MAX_SCROLLS: usize = 4;

/// Height of a toolbar and of the status bar.
pub const BAR_H: u32 = 40;
pub const STATUS_H: u32 = 24;
const BAR_PAD: u32 = 10;
const ICON_BUTTON_W: u32 = 30;
const SCROLL_W: u32 = 10;
/// Two presses this close in time (ticks) and space are a double click.
const DOUBLE_CLICK_TICKS: u32 = 80;
const DOUBLE_CLICK_PX: i32 = 5;
/// `active` while a scrollbar's thumb is dragged; no widget id is this high.
const SCROLL_ID: u32 = 0xF000_0000;

/// What a list keeps between frames; the app owns one per list.
pub const ListState = struct {
    /// First row on screen.
    scroll: u32 = 0,
    selected: ?u32 = null,
    hot: ?u32 = null,
    /// The next pass scrolls the selection into view.
    reveal: bool = false,

    /// Select `row` from the app's side and have it scrolled into view.
    pub fn select(self: *ListState, row: u32) void {
        self.selected = row;
        self.reveal = true;
    }
};

/// One pass over a list: which rows are on screen and what happened.
pub const ListView = struct {
    /// The rows, left of the scrollbar.
    area: Rect,
    row_h: u32,
    /// Rows first .. first + count are on screen.
    first: u32,
    count: u32,
    selected: ?u32,
    /// Row opened in this pass, by a double click or Enter.
    opened: ?u32 = null,

    pub fn rowRect(self: ListView, row: u32) Rect {
        return .{ .x = self.area.x, .y = self.area.y + (row - self.first) * self.row_h, .w = self.area.w, .h = self.row_h };
    }
};

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
    /// Special key (libc.Key) of this event, else 0.
    special: u8 = 0,
    /// Modifiers (libc.MOD_*) of the last key.
    mods: u32 = 0,
    /// Wheel notches of this event, positive away from the user, else 0.
    wheel: i32 = 0,
    /// 1 on the event of a left press, 2 if that press makes a double
    /// click, else 0.
    clicks: u8 = 0,
    click_tick: ?u32 = null,
    click_at: Point = .{ .x = 0, .y = 0 },

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

    in_bar: bool = false,
    bar_top: u32 = 0,
    /// Where edge-to-edge content may start: the bottom of the last bar.
    edge: u32 = 0,
    /// A widget was placed below `edge`.
    flowed: bool = false,
    /// Bottom of what fill() may take: `h` less the strips pinned there.
    floor: u32 = 0,

    scrolls: [MAX_SCROLLS]widgets.Scrollbar = [_]widgets.Scrollbar{.{ .x = 0, .y = 0, .w = 0, .h = 0, .trackless = true }} ** MAX_SCROLLS,
    scroll_i: usize = 0,

    // --- Driven by app.run ---

    /// Take in an event. False if widgets have no use for it.
    pub fn feed(self: *Ui, ev: libc.Event) bool {
        self.was_down = self.down;
        self.key = 0;
        self.special = 0;
        self.wheel = 0;
        self.clicks = 0;
        switch (ev.kindOf()) {
            .mouse_move => {
                self.mouse = .{ .x = @bitCast(ev.a), .y = @bitCast(ev.b) };
                self.down = ev.c & 1 != 0;
            },
            .mouse_button => {
                self.mouse = .{ .x = @bitCast(ev.b), .y = @bitCast(ev.c) };
                self.down = ev.buttonsState() & 1 != 0;
            },
            .mouse_wheel => {
                self.wheel = @bitCast(ev.a);
                self.mouse = .{ .x = @bitCast(ev.b), .y = @bitCast(ev.c) };
            },
            .key_char => {
                self.key = @truncate(ev.a);
                self.mods = ev.b;
            },
            .key_special => {
                self.special = @truncate(ev.a);
                self.mods = ev.b;
            },
            .focus_out => {
                self.mouse = .{ .x = -1, .y = -1 };
                self.down = false;
            },
            .resize => {},
            else => return false,
        }
        // A press can arrive in a move event as well as in a button event.
        if (self.down and !self.was_down) self.countClick();
        return true;
    }

    fn countClick(self: *Ui) void {
        const now = libc.uptime();
        const dx = self.mouse.x - self.click_at.x;
        const dy = self.mouse.y - self.click_at.y;
        const near = @abs(dx) <= DOUBLE_CLICK_PX and @abs(dy) <= DOUBLE_CLICK_PX;
        if (self.click_tick) |t| {
            if (near and now -% t < DOUBLE_CLICK_TICKS) {
                self.clicks = 2;
                // A third press starts over.
                self.click_tick = null;
                return;
            }
        }
        self.clicks = 1;
        self.click_tick = now;
        self.click_at = self.mouse;
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
        self.in_bar = false;
        self.edge = 0;
        self.flowed = false;
        self.floor = self.h;
        self.scroll_i = 0;
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
        // The event is spent: the paint pass must not see its keys, its
        // wheel or its button edge again.
        self.key = 0;
        self.special = 0;
        self.wheel = 0;
        self.clicks = 0;
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

    /// Start a toolbar: a strip across the window under what is laid out
    /// so far. Widgets up to endBar share its one line, from the left; with
    /// alignNext(.right) they stack from the right edge instead.
    pub fn beginBar(self: *Ui) void {
        if (self.in_bar or self.in_group) return;
        const p = &widgets.palette;
        self.in_bar = true;
        self.bar_top = self.flowTop();
        if (self.painting) {
            self.canvas.fillRect(0, self.bar_top, self.w, BAR_H, p.bar_bg);
            self.canvas.fillRect(0, self.bar_top + BAR_H - 1, self.w, 1, p.hairline);
        }
        self.left = BAR_PAD;
        self.right = self.w -| BAR_PAD;
        self.surface = p.bar_bg;
        self.last = .{};
        self.same_line = false;
    }

    pub fn endBar(self: *Ui) void {
        if (!self.in_bar) return;
        self.in_bar = false;
        self.left = MARGIN;
        self.right = self.w -| MARGIN;
        self.surface = widgets.palette.window_bg;
        self.edge = self.bar_top + BAR_H;
        self.flowed = false;
        self.bottom = self.edge;
        self.y = self.edge + TOP;
        self.last = .{};
    }

    /// A strip of `h` pixels pinned to the bottom edge, for content of the
    /// app's own. Call before fill().
    pub fn bottomBar(self: *Ui, h: u32) Rect {
        self.floor -|= h;
        const r = Rect{ .x = 0, .y = self.floor, .w = self.w, .h = h };
        if (self.painting) {
            self.canvas.fillRect(r.x, r.y, r.w, r.h, widgets.palette.bar_bg);
            self.canvas.fillRect(r.x, r.y, r.w, 1, widgets.palette.hairline);
        }
        return r;
    }

    /// A status bar: small text at the left and the right of a bottom
    /// strip. Call before fill().
    pub fn statusBar(self: *Ui, left_text: []const u8, right_text: []const u8) void {
        const r = self.bottomBar(STATUS_H);
        if (!self.painting) return;
        const atlas = &fa.default_13;
        const color = widgets.palette.text_muted;
        const ty = r.y + 1 + (r.h - 1 -| atlas.line_height) / 2;
        const right_w = atlas.measure(right_text);
        if (right_w + 2 * BAR_PAD <= r.w) {
            fa.drawText(self.canvas, @intCast(r.w - BAR_PAD - right_w), @intCast(ty), right_text, color, atlas);
        }
        widgets.drawTextFit(self.canvas, BAR_PAD, ty, r.w -| (3 * BAR_PAD + right_w), left_text, color, atlas);
    }

    /// The rest of the window, edge to edge: from under the bar, or the
    /// widgets placed since, down to the bottom strips. For content the
    /// app draws itself.
    pub fn fill(self: *Ui) Rect {
        const top = self.flowTop();
        const r = Rect{ .x = 0, .y = top, .w = self.w, .h = self.floor -| top };
        self.bottom = @max(self.bottom, self.floor);
        self.y = self.bottom;
        self.flowed = false;
        self.edge = self.bottom;
        self.last = .{};
        return r;
    }

    fn flowTop(self: *const Ui) u32 {
        return if (self.flowed) self.bottom + LINE_GAP else self.edge;
    }

    fn place(self: *Ui, w: u32, h: u32) Rect {
        if (self.in_bar) {
            var bar = Rect{ .x = self.left, .y = self.bar_top + (BAR_H - 1 -| h) / 2, .w = w, .h = h };
            switch (self.next_align) {
                .left => self.left = bar.x + w + ITEM_GAP,
                .center => bar.x = self.left + (self.right -| self.left -| w) / 2,
                .right => {
                    bar.x = self.right -| w;
                    self.right = bar.x -| ITEM_GAP;
                },
            }
            self.same_line = false;
            self.next_align = .left;
            self.last = bar;
            return bar;
        }
        self.flowed = true;
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

    fn idOf(r: Rect) u32 {
        return (((r.y & 0x7FFF) << 16) | (r.x & 0xFFFF)) + 1;
    }

    /// The cursor is over `r` and nothing modal covers it.
    pub fn hovering(self: *const Ui, r: Rect) bool {
        return !self.blocked and r.contains(self.mouse);
    }

    /// Where the left button went down inside `r`, on the event it did.
    pub fn pressed(self: *Ui, r: Rect) ?Point {
        if (self.painting or !self.hovering(r)) return null;
        if (!self.down or self.was_down) return null;
        self.active = idOf(r);
        self.changed = true;
        return self.mouse;
    }

    /// The cursor while the button stays down after a press inside `r`,
    /// wherever it has moved to since.
    pub fn dragging(self: *const Ui, r: Rect) ?Point {
        if (self.painting or !self.down or self.active != idOf(r)) return null;
        return self.mouse;
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

    /// Small text: counters, captions, secondary information.
    pub fn caption(self: *Ui, str: []const u8, color: u32) void {
        self.smallText(str, color, &fa.default_13);
    }

    /// Small semibold text: what a bar is about.
    pub fn heading(self: *Ui, str: []const u8) void {
        self.smallText(str, widgets.palette.text_strong, &fa.default_13sb);
    }

    fn smallText(self: *Ui, str: []const u8, color: u32, atlas: *const fa.FontAtlas) void {
        // In a bar the text gives way to what is already placed.
        const room = self.right -| self.left;
        const r = self.place(@min(atlas.measure(str), room), atlas.line_height);
        if (self.painting) widgets.drawTextFit(self.canvas, r.x, r.y, r.w, str, color, atlas);
    }

    pub fn button(self: *Ui, str: []const u8) bool {
        return self.styledButton(str, .default);
    }

    /// A glyph that stays lit while `on`: one of a set of tools or modes.
    /// Returns true when clicked; the app changes what is on.
    pub fn iconToggle(self: *Ui, icon: widgets.Icon, on: bool) bool {
        const r = self.place(ICON_BUTTON_W, BUTTON_H);
        const p = &widgets.palette;
        const hit = self.interact(r);
        if (self.painting) {
            if (on) {
                self.canvas.fillRoundedRect(r.x, r.y, r.w, r.h, 6, p.selection);
            } else if (hit.state != .normal) {
                self.canvas.fillRoundedRect(r.x, r.y, r.w, r.h, 6, widgets.lerpColor(self.surface, p.text_strong, 1, if (hit.state == .pressed) 5 else 8));
            }
            widgets.drawIcon(self.canvas, icon, r.x + (r.w - widgets.ICON_SIZE) / 2, r.y + (r.h - widgets.ICON_SIZE) / 2, if (on) p.selection_text else p.text_normal);
        }
        return hit.clicked;
    }

    /// A borderless button showing a glyph, for bars. Disabled, it is
    /// drawn dim and does not answer.
    pub fn iconButton(self: *Ui, icon: widgets.Icon, enabled: bool) bool {
        const r = self.place(ICON_BUTTON_W, BUTTON_H);
        const p = &widgets.palette;
        const ix = r.x + (r.w - widgets.ICON_SIZE) / 2;
        const iy = r.y + (r.h - widgets.ICON_SIZE) / 2;
        if (!enabled) {
            if (self.painting) widgets.drawIcon(self.canvas, icon, ix, iy, widgets.lerpColor(self.surface, p.text_muted, 1, 2));
            return false;
        }
        const hit = self.interact(r);
        if (self.painting) {
            switch (hit.state) {
                .hover => self.canvas.fillRoundedRect(r.x, r.y, r.w, r.h, 6, widgets.lerpColor(self.surface, p.text_strong, 1, 8)),
                .pressed => self.canvas.fillRoundedRect(r.x, r.y, r.w, r.h, 6, widgets.lerpColor(self.surface, p.text_strong, 1, 5)),
                else => {},
            }
            widgets.drawIcon(self.canvas, icon, ix, iy, p.text_normal);
        }
        return hit.clicked;
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
        const r = self.place(self.right -| self.left, PROGRESS_H);
        if (!self.painting) return;
        const p = &widgets.palette;
        self.canvas.fillRect(r.x, r.y, r.w, r.h, p.btn_default_bot);
        if (max != 0) {
            const filled: u32 = @intCast(@as(u64, @min(value, max)) * r.w / max);
            self.canvas.fillRect(r.x, r.y, filled, r.h, p.btn_primary_bot);
        }
        self.canvas.roundCornersRadius(r.x, r.y, r.w, r.h, PROGRESS_H / 2, self.surface);
    }

    /// A scrollbar down the right edge of `area` for `total` rows of which
    /// `visible` fit: the wheel over the area and drags of the thumb move
    /// `offset`. Returns the area left of the bar.
    pub fn vscroll(self: *Ui, area: Rect, total: u32, visible: u32, offset: *u32) Rect {
        const rest = Rect{ .x = area.x, .y = area.y, .w = area.w -| SCROLL_W, .h = area.h };
        if (self.scroll_i >= MAX_SCROLLS) return rest;
        const sb = &self.scrolls[self.scroll_i];
        self.scroll_i += 1;
        sb.x = rest.x + rest.w;
        sb.y = area.y;
        sb.w = SCROLL_W;
        sb.h = area.h;
        const max = total -| visible;
        if (self.painting) {
            sb.draw(self.canvas, total, visible, @min(offset.*, max));
            return rest;
        }
        const offset_before = offset.*;
        const state_before = sb.state;
        if (offset.* > max) offset.* = max;
        if (!self.blocked) {
            sb.update(self.mouse.x, self.mouse.y, self.down, self.was_down, total, visible, offset);
            if (self.wheel != 0 and max != 0 and area.contains(self.mouse)) {
                const step: u32 = @abs(self.wheel) * sb.lines_per_notch;
                offset.* = if (self.wheel > 0) offset.* -| step else @min(offset.* + step, max);
            }
        }
        // The drag owns the pointer: widgets it passes over stay cold.
        if (sb.state == .dragging) self.active = SCROLL_ID;
        if (offset.* != offset_before or sb.state != state_before) self.changed = true;
        return rest;
    }

    /// Rows of `row_h` filling `area`: scrolling, a selection that follows
    /// clicks and the arrow keys, and opening by a double click or Enter.
    /// Paints the selection and hover; the app paints each row over them.
    pub fn list(self: *Ui, area: Rect, state: *ListState, total: u32, row_h: u32) ListView {
        const visible: u32 = if (row_h == 0) 0 else area.h / row_h;
        if (state.selected) |s| {
            if (s >= total) state.selected = if (total == 0) null else total - 1;
        }
        if (state.reveal) {
            state.reveal = false;
            if (state.selected) |row| revealRow(state, row, visible);
            self.changed = true;
        }
        const rows = self.vscroll(area, total, visible, &state.scroll);
        var view = ListView{
            .area = rows,
            .row_h = row_h,
            .first = state.scroll,
            .count = @min(visible, total -| state.scroll),
            .selected = state.selected,
        };
        if (self.painting) {
            const p = &widgets.palette;
            if (state.hot) |row| {
                if (state.selected != row and row >= view.first and row < view.first + view.count) self.rowBackground(view.rowRect(row), p.row_hover);
            }
            if (state.selected) |row| {
                if (row >= view.first and row < view.first + view.count) self.rowBackground(view.rowRect(row), p.selection);
            }
            return view;
        }

        var hot: ?u32 = null;
        if (row_h != 0 and self.hovering(rows)) {
            const over = @as(u32, @intCast(self.mouse.y)) - rows.y;
            const row = state.scroll + over / row_h;
            if (row < total and over / row_h < visible) hot = row;
        }
        if (hot != state.hot) {
            state.hot = hot;
            self.changed = true;
        }
        if (self.pressed(rows) != null) {
            if (hot) |row| {
                state.selected = row;
                if (self.clicks == 2) view.opened = row;
            }
        }
        if (!self.blocked and total != 0) {
            const last = total - 1;
            const cur = state.selected;
            const next: ?u32 = switch (self.special) {
                libc.Key.up => if (cur) |c| c -| 1 else last,
                libc.Key.down => if (cur) |c| @min(c + 1, last) else 0,
                libc.Key.home => 0,
                libc.Key.end => last,
                libc.Key.page_up => if (cur) |c| c -| visible else 0,
                libc.Key.page_down => if (cur) |c| @min(c + visible, last) else 0,
                else => null,
            };
            if (next) |row| {
                state.selected = row;
                revealRow(state, row, visible);
                self.changed = true;
            }
            if ((self.key == '\n' or self.key == '\r') and state.selected != null) {
                view.opened = state.selected;
                self.changed = true;
            }
        }
        view.first = state.scroll;
        view.count = @min(visible, total -| state.scroll);
        view.selected = state.selected;
        return view;
    }

    fn revealRow(state: *ListState, row: u32, visible: u32) void {
        if (row < state.scroll) state.scroll = row;
        if (visible != 0 and row >= state.scroll + visible) state.scroll = row + 1 - visible;
    }

    fn rowBackground(self: *Ui, r: Rect, color: u32) void {
        self.canvas.fillRoundedRect(r.x + 6, r.y + 1, r.w -| 8, r.h -| 2, 6, color);
    }

    /// Start a card, under `name` if given; widgets up to endGroup go
    /// inside it. Groups do not nest.
    pub fn beginGroup(self: *Ui, name: ?[]const u8) void {
        if (self.in_group) return;
        if (name) |str| {
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
