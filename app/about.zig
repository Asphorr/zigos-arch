// About app — exercises every widget in lib/ui.zig:
//   - Title bar:    verticalGradient
//   - Info card:    drawShadow + drawRect1px
//   - Memory bar:   ProgressBar (live-driven by libc.meminfo)
//   - Uptime line:  live ticker (libc.uptime)
//   - Toggle:       dark/light mode (rebinds ui.palette)
//   - Checkbox:     reveal advanced info
//   - TextInput:    user greeting (focused → drawFocusRing)
//   - Scrollbar:    scrollable credits panel
//   - Buttons:      default / primary / destructive — incl. ui.Dialog confirm
//
// Window is 480×360; we use createWindowEx so the user can resize larger
// without re-allocing the framebuffer. Layout recomputes on size change.

const libc = @import("libc");
const gfx = @import("graphics");
const ui = @import("ui");
const fa = @import("font_atlas");

const ALLOC_W: u32 = 800;
const ALLOC_H: u32 = 600;
const INIT_W: u32 = 480;
const INIT_H: u32 = 360;

var vis_w: u32 = INIT_W;
var vis_h: u32 = INIT_H;
var dark_mode: bool = false;
var advanced: bool = false;

// Widget instances — laid out by computeLayout() based on current vis_w/h.
var theme_toggle: ui.Toggle = undefined;
var advanced_check: ui.Checkbox = undefined;
var greeting_buf: [48]u8 = undefined;
var greeting_input: ui.TextInput = undefined;
var credits_scrollbar: ui.Scrollbar = undefined;
var btn_reset: ui.Button = undefined;
var btn_notify: ui.Button = undefined;
var btn_ok: ui.Button = undefined;
var mem_bar: ui.ProgressBar = undefined;

var credits_scroll: u32 = 0;
const CREDITS_LINE_H: u32 = 18;

const credits = [_][]const u8{
    "ZigOS - a Zig freestanding kernel.",
    "",
    "Architecture: x86_64 long mode",
    "Toolchain:    Zig 0.15.2 + LLVM",
    "Boot:         Multiboot2 / UEFI",
    "Paging:       4-level, 1GB identity",
    "Scheduling:   per-CPU, kernel tasks",
    "VFS:          tarfs / FAT32 / ext2",
    "Network:      e1000 + virtio-net",
    "Audio:        AC97 + virtio-sound",
    "GPU:          virtio-gpu 2D + Venus",
    "USB:          xHCI 3.0",
    "",
    "Debug:        KASAN, KCSAN, kdbg",
    "              DR0-DR3 watchpoints",
    "              addrinfo annotator",
    "",
    "Allocators:   PMM word-scan",
    "              kvmalloc/kfreeAuto",
    "              slab caches (KASAN)",
    "              libc malloc (Knuth)",
    "",
    "(c) 2026 - built with care.",
};

fn computeLayout(w: u32, h: u32) void {
    vis_w = w;
    vis_h = h;

    const m: u32 = 16;
    const card_x: u32 = m;
    const card_w: u32 = w -| 2 * m;
    // Title bar (gradient) is 50px now (was 44) — gives the 24px AA title
    // and its 16px subtitle full vertical breathing room without bleeding
    // into the body. Body content starts at y=64 (50 title + 14 gap).
    var y: u32 = 64;

    // Toggle sits to the right of "Dark mode" label. Saturating subs because
    // the desktop's opening-window animation feeds tiny widths (w/3) for the
    // first 6 frames — non-saturating math would trap on overflow.
    theme_toggle = .{ .x = (card_x + card_w) -| ui.Toggle.W -| 12, .y = y, .on = dark_mode };
    advanced_check = .{ .x = card_x + 12, .y = y + ui.Toggle.H + 14, .label = "Show advanced info", .checked = advanced };
    y += ui.Toggle.H + 14 + ui.Checkbox.SIZE + 22;

    // Greeting input. Label sits at y-22; AA text occupies a full 18px line
    // height plus a 4px gap to the input border.
    greeting_input = .{
        .x = card_x + 12,
        .y = y,
        .w = card_w -| 24,
        .h = 26,
        .buf = &greeting_buf,
        .buf_len = greeting_input.buf_len, // preserve typed text on relayout
        .cursor = greeting_input.cursor,
    };
    y += 26 + 22;

    // Memory pressure bar — same vertical breathing room as the input above.
    mem_bar = .{
        .x = card_x + 12,
        .y = y,
        .w = card_w -| 24,
        .h = 8,
        .bg_color = ui.lerpColor(ui.palette.card_bg, 0x000000, 1, 12),
        .fill_color = ui.palette.btn_primary_top,
        .border_color = ui.palette.card_border,
    };
    y += 28;

    // Credits panel: scrollable text with right-side scrollbar.
    const credits_h: u32 = if (h > y + 80) h -| (y + 60) else 80;
    const credits_w: u32 = card_w -| 24;
    const sb_w: u32 = 8;
    credits_scrollbar = .{
        .x = (card_x + 12 + credits_w) -| sb_w,
        .y = y,
        .w = sb_w,
        .h = credits_h,
    };
    y += credits_h + 12;

    // Bottom button row — three buttons evenly spaced, right-aligned.
    // All sat-sub: an animating window may have card_w < btn_w*3 + gaps, in
    // which case buttons stack at x=0 (overlapping for the duration of the
    // animation, ~6 frames) instead of trapping.
    const btn_w: u32 = 100;
    const btn_h: u32 = 28;
    const btn_y: u32 = h -| btn_h -| 8;
    btn_ok = .{ .x = (card_x + card_w) -| btn_w, .y = btn_y, .w = btn_w, .h = btn_h, .label = "OK" };
    btn_notify = .{ .x = btn_ok.x -| btn_w -| 10, .y = btn_y, .w = btn_w, .h = btn_h, .label = "Notify" };
    btn_reset = .{ .x = btn_notify.x -| btn_w -| 10, .y = btn_y, .w = btn_w, .h = btn_h, .label = "Reset" };
}

fn formatU32(out: []u8, val: u32) []const u8 {
    var v = val;
    if (v == 0) {
        out[0] = '0';
        return out[0..1];
    }
    var tmp: [10]u8 = undefined;
    var n: usize = 0;
    while (v > 0) : (v /= 10) {
        tmp[n] = '0' + @as(u8, @intCast(v % 10));
        n += 1;
    }
    var i: usize = 0;
    while (i < n) : (i += 1) out[i] = tmp[n - 1 - i];
    return out[0..n];
}

fn drawCredits(canvas: *gfx.Canvas, x: u32, y: u32, w: u32, h: u32) void {
    // Card background for the scrollable area.
    canvas.fillRect(x, y, w, h, ui.lerpColor(ui.palette.card_bg, 0x000000, 1, 32));
    ui.drawRect1px(canvas, x, y, w, h, ui.palette.card_border);

    // Total content height: lines * CREDITS_LINE_H. Visible: h.
    const total: u32 = @as(u32, credits.len) * CREDITS_LINE_H;
    const max_off: u32 = if (total > h) total - h else 0;
    if (credits_scroll > max_off) credits_scroll = max_off;

    // Draw lines, clipping above/below the panel. Per-pixel clip means a
    // line straddling the bottom edge renders only the visible portion.
    const start_line: u32 = credits_scroll / CREDITS_LINE_H;
    const text_x: u32 = x + 8;
    // Inset clip by 1px on each side so the panel border stays clean.
    const clip = fa.Clip{
        .x_min = @intCast(x + 1),
        .y_min = @intCast(y + 1),
        .x_max = @intCast(x + w -| 1),
        .y_max = @intCast(y + h -| 1),
    };
    var line_idx: u32 = start_line;
    while (line_idx < credits.len) : (line_idx += 1) {
        const line_y_abs: i32 = @as(i32, @intCast(y)) + @as(i32, @intCast(line_idx * CREDITS_LINE_H)) - @as(i32, @intCast(credits_scroll));
        if (line_y_abs >= @as(i32, @intCast(y + h))) break;
        if (line_y_abs + @as(i32, @intCast(fa.default_16.line_height)) <= @as(i32, @intCast(y))) continue;
        fa.drawTextClipped(canvas, @intCast(text_x), line_y_abs, credits[line_idx], ui.palette.text_normal, &fa.default_16, clip);
    }
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    // Default greeting.
    const greet = "Hello, ZigOS";
    @memcpy(greeting_buf[0..greet.len], greet);
    greeting_input = .{ .x = 0, .y = 0, .w = 100, .h = 26, .buf = &greeting_buf, .buf_len = greet.len, .cursor = greet.len };

    const win = libc.createWindowEx(ALLOC_W, ALLOC_H, INIT_W, INIT_H) orelse libc.exit();
    var alloc_w: u32 = win.alloc_w; // current FB stride; grows on F10 maximize
    var alloc_h: u32 = win.alloc_h;
    var canvas = gfx.Canvas.init(win.fb, alloc_w, alloc_h);
    _ = libc.getWindowAlloc(); // opt this window into F10 grow-on-maximize (re-fetched in .resize)

    fa.ensureLoaded();
    computeLayout(INIT_W, INIT_H);

    var prev_left: bool = false;
    var dialog: ?ui.Dialog = null;
    var tick: u32 = 0;
    // Latest mouse state, accumulated from window events. Buttons are bit 0 = left.
    var cur_mx: i32 = 0;
    var cur_my: i32 = 0;
    var cur_btns: u32 = 0;

    while (true) {
        var should_quit = false;

        // Drain queued window events. Scrollbar consumes wheel/drag/track
        // interactions for the credits panel; everything else feeds into
        // app-tracked mouse state and per-key TextInput updates.
        while (libc.pollEvent()) |ev| {
            _ = credits_scrollbar.handleEvent(
                ev,
                @as(u32, credits.len) * CREDITS_LINE_H,
                credits_scrollbar.h,
                &credits_scroll,
            );
            switch (ev.kindOf()) {
                .close_request => {
                    should_quit = true;
                },
                .resize => {
                    // F10 maximize may have GROWN our framebuffer past the
                    // alloc we requested. Re-fetch and rebuild the canvas at
                    // the new stride before clamping/laying out. win.fb stays
                    // valid (kernel re-backs the same VA) so render is crisp
                    // instead of upscaled.
                    const wa = libc.getWindowAlloc();
                    if (wa.w != 0 and (wa.w != alloc_w or wa.h != alloc_h)) {
                        alloc_w = wa.w;
                        alloc_h = wa.h;
                        canvas = gfx.Canvas.init(win.fb, alloc_w, alloc_h);
                    }
                    const new_w = @min(ev.a, alloc_w);
                    const new_h = @min(ev.b, alloc_h);
                    if (new_w != vis_w or new_h != vis_h) computeLayout(new_w, new_h);
                },
                .key_char => {
                    const ch: u8 = @truncate(ev.a);
                    if (ch == 0x1B) {
                        // ESC quits ONLY when no dialog is up; otherwise dismisses it.
                        if (dialog != null) dialog = null else should_quit = true;
                    } else if (dialog == null) {
                        // Feed printable / control chars (Enter, Backspace, …) into
                        // TextInput one at a time using the most recently observed
                        // mouse state for focus tracking.
                        const left_now_e = (cur_btns & 1) != 0;
                        _ = greeting_input.update(cur_mx, cur_my, left_now_e, prev_left, ch);
                    }
                },
                .mouse_move => {
                    cur_mx = @bitCast(ev.a);
                    cur_my = @bitCast(ev.b);
                    cur_btns = ev.c;
                },
                .mouse_button => {
                    cur_btns = ev.buttonsState();
                    cur_mx = @bitCast(ev.b);
                    cur_my = @bitCast(ev.c);
                },
                else => {},
            }
        }
        if (should_quit) break;

        // Run all widget updates once per frame against the post-drain
        // mouse snapshot. Click events (release-edge) are detected against
        // `prev_left` from the previous frame.
        const left_now = (cur_btns & 1) != 0;

        // Modal dialog steals all input.
        if (dialog) |*d| {
            _ = d.primary_btn.update(cur_mx, cur_my, left_now, prev_left);
            _ = d.secondary_btn.update(cur_mx, cur_my, left_now, prev_left);
            // Click released over a button = result.
            if (!left_now and prev_left) {
                switch (d.hit(cur_mx, cur_my)) {
                    .primary => {
                        // "Reset" confirmed — for demo, blank greeting.
                        greeting_input.buf_len = 0;
                        greeting_input.cursor = 0;
                        libc.notify("Stats reset");
                        dialog = null;
                    },
                    .secondary => dialog = null,
                    .none => {},
                }
            }
        } else {
            if (theme_toggle.update(cur_mx, cur_my, left_now, prev_left)) {
                dark_mode = theme_toggle.on;
                ui.setDarkMode(dark_mode);
                computeLayout(vis_w, vis_h); // palette change ripples into mem_bar colors
            }
            if (advanced_check.update(cur_mx, cur_my, left_now, prev_left)) {
                advanced = advanced_check.checked;
            }
            // TextInput per-frame update without a key (focus/state only;
            // keys are consumed during the event-drain above).
            _ = greeting_input.update(cur_mx, cur_my, left_now, prev_left, 0);
            if (btn_reset.update(cur_mx, cur_my, left_now, prev_left)) {
                dialog = ui.Dialog.init(vis_w, vis_h, "Reset stats?", "This will clear the greeting.", "Reset", "Cancel", true);
            }
            if (btn_notify.update(cur_mx, cur_my, left_now, prev_left)) {
                if (greeting_input.buf_len > 0) {
                    libc.notify(greeting_buf[0..greeting_input.buf_len]);
                } else {
                    libc.notify("Hello from About");
                }
            }
            if (btn_ok.update(cur_mx, cur_my, left_now, prev_left)) break;
        }

        prev_left = left_now;
        tick +%= 1;

        // --- Draw ---
        const bg = ui.palette.card_bg;
        canvas.clear(bg);

        // Title bar — gradient + drop shadow under it. 50px tall to fit the
        // 24px AA title + 16px subtitle without bleed.
        const title_h: u32 = 50;
        ui.verticalGradient(&canvas, 0, 0, vis_w, title_h, ui.palette.btn_primary_top, ui.palette.btn_primary_bot);
        fa.drawText(&canvas, 16, 4, "About ZigOS", 0xFFFFFF, &fa.default_24);
        fa.drawText(&canvas, 16, 32, "x86_64 freestanding kernel", 0xCCDDFF, &fa.default_16);

        // Card border under title bar.
        ui.drawShadow(&canvas, 0, title_h, vis_w, 1, bg);

        // Theme toggle row label.
        fa.drawText(&canvas, 16, @intCast(theme_toggle.y + 2), "Dark mode", ui.palette.text_normal, &fa.default_16);
        theme_toggle.draw(&canvas, bg);

        advanced_check.draw(&canvas, bg);

        // Greeting input + focus ring when focused.
        fa.drawText(&canvas, 16, @as(i32, @intCast(greeting_input.y -| 22)), "Greeting", ui.palette.text_muted, &fa.default_16);
        if (greeting_input.focused) {
            ui.drawFocusRing(&canvas, greeting_input.x -| 2, greeting_input.y -| 2, greeting_input.w + 4, greeting_input.h + 4, ui.palette.btn_primary_top);
        }
        const caret_visible: bool = (tick / 30) & 1 == 0;
        greeting_input.draw(&canvas, bg, caret_visible);

        // Memory pressure: bar + label with current %.
        const mi = libc.meminfo();
        const used: u32 = if (mi.total_frames > mi.free_frames) mi.total_frames - mi.free_frames else 0;
        const pct: u32 = if (mi.total_frames > 0) used * 100 / mi.total_frames else 0;
        const mem_label_y: i32 = @intCast(mem_bar.y -| 22);
        fa.drawText(&canvas, 16, mem_label_y, "Memory pressure", ui.palette.text_muted, &fa.default_16);
        var pct_buf: [8]u8 = undefined;
        const pct_str = formatU32(&pct_buf, pct);
        // "NN%" right-aligned against the bar's right edge — measure first.
        var pct_with_unit: [12]u8 = undefined;
        @memcpy(pct_with_unit[0..pct_str.len], pct_str);
        pct_with_unit[pct_str.len] = '%';
        const pct_full = pct_with_unit[0 .. pct_str.len + 1];
        const pct_w = fa.default_16.measure(pct_full);
        const pct_x: i32 = @intCast((mem_bar.x + mem_bar.w) -| pct_w);
        fa.drawText(&canvas, pct_x, mem_label_y, pct_full, ui.palette.text_normal, &fa.default_16);
        mem_bar.draw(&canvas, pct, 100);

        // Advanced panel (uptime + pid) — only when checkbox checked.
        if (advanced) {
            const up = libc.uptime();
            const pid = libc.getpid();
            var line_buf: [80]u8 = undefined;
            var n: usize = 0;
            const prefix = "Uptime ";
            @memcpy(line_buf[n..][0..prefix.len], prefix);
            n += prefix.len;
            const up_s = formatU32(line_buf[n..], up);
            n += up_s.len;
            const sep = "s   PID ";
            @memcpy(line_buf[n..][0..sep.len], sep);
            n += sep.len;
            const pid_s = formatU32(line_buf[n..], pid);
            n += pid_s.len;
            const free_s = "   Free ";
            @memcpy(line_buf[n..][0..free_s.len], free_s);
            n += free_s.len;
            const free_kb = mi.free_frames * 4;
            const fk_s = formatU32(line_buf[n..], free_kb);
            n += fk_s.len;
            const kb = " KB";
            @memcpy(line_buf[n..][0..kb.len], kb);
            n += kb.len;
            fa.drawText(&canvas, 16, @intCast(mem_bar.y + mem_bar.h + 8), line_buf[0..n], ui.palette.text_muted, &fa.default_16);
        }

        // Credits panel.
        drawCredits(&canvas, 16, credits_scrollbar.y, vis_w -| 32, credits_scrollbar.h);
        credits_scrollbar.draw(&canvas, @as(u32, credits.len) * CREDITS_LINE_H, credits_scrollbar.h, credits_scroll);

        // Buttons.
        btn_reset.drawStyled(&canvas, .destructive, bg);
        btn_notify.drawStyled(&canvas, .default, bg);
        btn_ok.drawStyled(&canvas, .primary, bg);

        // Dialog on top of everything.
        if (dialog) |d| d.draw(&canvas, bg);

        libc.present();
        libc.sleep(16);
    }

    libc.destroyWindow();
    libc.exit();
}
