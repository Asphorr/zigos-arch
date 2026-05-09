const libc = @import("libc");
const gfx = @import("graphics");
const ui = @import("ui");
const fa = @import("font_atlas");

const BG: u32 = 0x1E1E2E;
const SECTION_COLOR: u32 = 0x8888CC;
const LABEL_COLOR: u32 = 0xCCCCCC;
const STATUS_OK: u32 = 0x66DD88;
const STATUS_WARN: u32 = 0xFFCC55;
const STATUS_BAD: u32 = 0xFF6666;

const CONF_PATH = "/etc/zigos.conf";
const WP_DIR = "/share/";
const MAX_WP_CHOICES: u32 = 4;

var sel_resolution: u8 = 1; // default to 1080p
var sel_background: u8 = 0;
var sel_theme: u8 = 0;
var sel_mouse_speed: u8 = 1;
var sel_dock_pos: u8 = 0;

// Wallpaper state. `sel_wp_idx` is 0 = "None", 1..MAX_WP_CHOICES = wp_files[idx-1].
var sel_wp_idx: u8 = 0;
var sel_wp_w: u32 = 0;
var sel_wp_h: u32 = 0;
var sel_wp_kind: enum { none, exact, letterbox, mismatch, broken } = .none;

// Loaded from /share/ at startup.
var wp_files: [MAX_WP_CHOICES][32]u8 = undefined;
var wp_file_lens: [MAX_WP_CHOICES]u8 = undefined;
var wp_count: u32 = 0;

var alloc_w: u32 = 0;
var alloc_h: u32 = 0;
var vis_w: u32 = 0;
var vis_h: u32 = 0;
var section_h: u32 = 0;

var res_btns: [2]ui.Button = undefined;
var bg_btns: [4]ui.Button = undefined;
const bg_colors = [4]u32{ 0x2D5F8A, 0x5F2D8A, 0x2D8A5F, 0x8A2D2D };
var theme_btns: [2]ui.Button = undefined;
var speed_btns: [3]ui.Button = undefined;
var dock_btns: [2]ui.Button = undefined;
var wp_btns: [MAX_WP_CHOICES + 1]ui.Button = undefined; // [0]=None, [1..]=files
var wp_apply_btn: ui.Button = undefined;
var apply_btn: ui.Button = undefined;

// --- Config persistence -----------------------------------------------------
//
// `/etc/zigos.conf` is a tiny `key=value` text file. We read it on startup so
// the UI shows the user's last-saved choice rather than the compile-time
// defaults, and rewrite it on Apply so the desktop's boot-time loader picks
// up the change on the next reboot.

fn loadConf() void {
    const fd = libc.open(CONF_PATH) orelse return;
    defer libc.close(fd);
    var buf: [1024]u8 = undefined;
    const n = libc.fread(fd, &buf);
    if (n == 0 or n == 0xFFFFFFFF) return;
    parseConf(buf[0..@min(n, buf.len)]);
}

fn parseConf(text: []const u8) void {
    var i: usize = 0;
    while (i < text.len) {
        while (i < text.len and (text[i] == ' ' or text[i] == '\t' or text[i] == '\n' or text[i] == '\r')) i += 1;
        if (i >= text.len) break;
        if (text[i] == '#') {
            while (i < text.len and text[i] != '\n') i += 1;
            continue;
        }
        const key_start = i;
        while (i < text.len and text[i] != '=' and text[i] != '\n') i += 1;
        if (i >= text.len or text[i] != '=') {
            while (i < text.len and text[i] != '\n') i += 1;
            continue;
        }
        const key = text[key_start..i];
        i += 1;
        const val_start = i;
        while (i < text.len and text[i] != '\n' and text[i] != '\r') i += 1;
        applyKv(key, text[val_start..i]);
    }
}

fn parseU8(s: []const u8) ?u8 {
    if (s.len == 0) return null;
    var v: u32 = 0;
    for (s) |c| {
        if (c < '0' or c > '9') return null;
        v = v * 10 + (c - '0');
        if (v > 255) return null;
    }
    return @intCast(v);
}

fn applyKv(key: []const u8, val_str: []const u8) void {
    if (eql(key, "wallpaper")) {
        // Match against scanned files; default to "none" if no match.
        sel_wp_idx = 0;
        if (val_str.len == 0) return;
        // The conf stores absolute path "/share/foo.png"; compare basename.
        var base = val_str;
        const slash_pos = lastIndexOf(val_str, '/');
        if (slash_pos) |p| base = val_str[p + 1 ..];
        var i: u32 = 0;
        while (i < wp_count) : (i += 1) {
            const fname = wp_files[i][0..wp_file_lens[i]];
            if (eql(fname, base)) {
                sel_wp_idx = @intCast(i + 1);
                refreshWallpaperStatus();
                return;
            }
        }
        return;
    }
    const val = parseU8(val_str) orelse return;
    if (eql(key, "resolution") and val <= 1) sel_resolution = val
    else if (eql(key, "background") and val <= 3) sel_background = val
    else if (eql(key, "theme") and val <= 1) sel_theme = val
    else if (eql(key, "mouse_speed") and val <= 2) sel_mouse_speed = val
    else if (eql(key, "dock_pos") and val <= 1) sel_dock_pos = val;
}

fn eql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| if (x != y) return false;
    return true;
}

fn lastIndexOf(s: []const u8, c: u8) ?usize {
    var i: usize = s.len;
    while (i > 0) {
        i -= 1;
        if (s[i] == c) return i;
    }
    return null;
}

fn writeKv(buf: []u8, pos: usize, key: []const u8, val: u8) usize {
    var p = pos;
    @memcpy(buf[p..][0..key.len], key);
    p += key.len;
    buf[p] = '=';
    p += 1;
    buf[p] = '0' + val;
    p += 1;
    buf[p] = '\n';
    p += 1;
    return p;
}

fn writeKvStr(buf: []u8, pos: usize, key: []const u8, val: []const u8) usize {
    var p = pos;
    @memcpy(buf[p..][0..key.len], key);
    p += key.len;
    buf[p] = '=';
    p += 1;
    @memcpy(buf[p..][0..val.len], val);
    p += val.len;
    buf[p] = '\n';
    p += 1;
    return p;
}

fn saveConf() void {
    var buf: [512]u8 = undefined;
    var pos: usize = 0;
    const header = "# ZigOS UI configuration — written by Settings\n";
    @memcpy(buf[pos..][0..header.len], header);
    pos += header.len;
    pos = writeKv(&buf, pos, "resolution", sel_resolution);
    pos = writeKv(&buf, pos, "background", sel_background);
    pos = writeKv(&buf, pos, "theme", sel_theme);
    pos = writeKv(&buf, pos, "mouse_speed", sel_mouse_speed);
    pos = writeKv(&buf, pos, "dock_pos", sel_dock_pos);
    // Wallpaper line: empty if "None" selected, full /share/ path otherwise.
    if (sel_wp_idx == 0) {
        pos = writeKvStr(&buf, pos, "wallpaper", "");
    } else {
        const fname = wp_files[sel_wp_idx - 1][0..wp_file_lens[sel_wp_idx - 1]];
        var path_buf: [128]u8 = undefined;
        @memcpy(path_buf[0..WP_DIR.len], WP_DIR);
        @memcpy(path_buf[WP_DIR.len..][0..fname.len], fname);
        pos = writeKvStr(&buf, pos, "wallpaper", path_buf[0 .. WP_DIR.len + fname.len]);
    }
    const fd = libc.openFlags(CONF_PATH, libc.O_TRUNC) orelse return;
    defer libc.close(fd);
    _ = libc.fwrite(fd, buf[0..pos]);
}

// --- Wallpaper helpers ------------------------------------------------------

fn endsWith(s: []const u8, suf: []const u8) bool {
    if (s.len < suf.len) return false;
    return eql(s[s.len - suf.len ..], suf);
}

/// Scan /share/ at startup, pick up to MAX_WP_CHOICES PNG/JPG/BMP files.
fn scanWallpapers() void {
    var entries: [32]libc.FileEntry = undefined;
    const n = libc.readdir(WP_DIR, &entries);
    if (n == 0) return;
    var out: u32 = 0;
    var i: u32 = 0;
    while (i < n and out < MAX_WP_CHOICES) : (i += 1) {
        const e = &entries[i];
        if (e.flags & libc.FE_FLAG_IS_DIR != 0) continue;
        const name = e.name[0..e.name_len];
        if (name.len > wp_files[0].len) continue;
        if (!(endsWith(name, ".png") or endsWith(name, ".jpg") or
            endsWith(name, ".bmp"))) continue;
        @memcpy(wp_files[out][0..name.len], name);
        wp_file_lens[out] = @intCast(name.len);
        out += 1;
    }
    wp_count = out;
}

/// Read the first 24 bytes of a file and parse PNG IHDR width/height.
/// Returns null on non-PNG / read failure. Cheap (no full decode).
fn peekPngDims(path: []const u8) ?struct { w: u32, h: u32 } {
    const fd = libc.open(path) orelse return null;
    defer libc.close(fd);
    var hdr: [24]u8 = undefined;
    const got = libc.fread(fd, &hdr);
    if (got < 24) return null;
    // PNG signature: 89 50 4E 47 0D 0A 1A 0A
    const sig = [_]u8{ 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };
    for (sig, 0..) |s, idx| if (hdr[idx] != s) return null;
    // IHDR chunk: bytes 12-15 = "IHDR", bytes 16-23 = width(BE) + height(BE).
    if (hdr[12] != 'I' or hdr[13] != 'H' or hdr[14] != 'D' or hdr[15] != 'R') return null;
    const w: u32 = (@as(u32, hdr[16]) << 24) | (@as(u32, hdr[17]) << 16) |
        (@as(u32, hdr[18]) << 8) | @as(u32, hdr[19]);
    const h: u32 = (@as(u32, hdr[20]) << 24) | (@as(u32, hdr[21]) << 16) |
        (@as(u32, hdr[22]) << 8) | @as(u32, hdr[23]);
    return .{ .w = w, .h = h };
}

/// Re-classify the currently-selected wallpaper against the screen.
fn refreshWallpaperStatus() void {
    if (sel_wp_idx == 0) {
        sel_wp_w = 0;
        sel_wp_h = 0;
        sel_wp_kind = .none;
        return;
    }
    const fname = wp_files[sel_wp_idx - 1][0..wp_file_lens[sel_wp_idx - 1]];
    var path_buf: [128]u8 = undefined;
    @memcpy(path_buf[0..WP_DIR.len], WP_DIR);
    @memcpy(path_buf[WP_DIR.len..][0..fname.len], fname);
    const path = path_buf[0 .. WP_DIR.len + fname.len];

    if (peekPngDims(path)) |dims| {
        sel_wp_w = dims.w;
        sel_wp_h = dims.h;
        const scr = libc.getScreenSize();
        if (dims.w == scr.w and dims.h == scr.h) {
            sel_wp_kind = .exact;
        } else if (dims.w <= scr.w and dims.h <= scr.h) {
            sel_wp_kind = .letterbox;
        } else {
            sel_wp_kind = .mismatch;
        }
    } else {
        sel_wp_w = 0;
        sel_wp_h = 0;
        sel_wp_kind = .broken;
    }
}

// --- Layout -----------------------------------------------------------------

fn computeLayout(w: u32, h: u32) void {
    vis_w = w;
    vis_h = h;
    section_h = 60;

    const bh: u32 = 26;
    const m: u32 = 12;
    var y: u32 = 58;

    res_btns[0] = .{ .x = m, .y = y, .w = 110, .h = bh, .label = "1280x720" };
    res_btns[1] = .{ .x = m + 116, .y = y, .w = 120, .h = bh, .label = "1920x1080" };
    y += section_h;

    bg_btns[0] = .{ .x = m, .y = y, .w = 70, .h = bh, .label = "Blue" };
    bg_btns[1] = .{ .x = m + 76, .y = y, .w = 80, .h = bh, .label = "Purple" };
    bg_btns[2] = .{ .x = m + 162, .y = y, .w = 75, .h = bh, .label = "Green" };
    bg_btns[3] = .{ .x = m + 243, .y = y, .w = 60, .h = bh, .label = "Red" };
    y += section_h;

    theme_btns[0] = .{ .x = m, .y = y, .w = 80, .h = bh, .label = "Light" };
    theme_btns[1] = .{ .x = m + 86, .y = y, .w = 80, .h = bh, .label = "Dark" };
    y += section_h;

    speed_btns[0] = .{ .x = m, .y = y, .w = 70, .h = bh, .label = "Slow" };
    speed_btns[1] = .{ .x = m + 76, .y = y, .w = 85, .h = bh, .label = "Normal" };
    speed_btns[2] = .{ .x = m + 167, .y = y, .w = 70, .h = bh, .label = "Fast" };
    y += section_h;

    dock_btns[0] = .{ .x = m, .y = y, .w = 90, .h = bh, .label = "Bottom" };
    dock_btns[1] = .{ .x = m + 96, .y = y, .w = 80, .h = bh, .label = "Top" };
    y += section_h;

    // Wallpaper section: row of buttons (None + scanned files), then a
    // status line + Apply Wallpaper button beneath.
    wp_btns[0] = .{ .x = m, .y = y, .w = 60, .h = bh, .label = "None" };
    var wp_x: u32 = m + 66;
    var i: u32 = 0;
    while (i < MAX_WP_CHOICES) : (i += 1) {
        if (i < wp_count) {
            // Button label points into wp_files (stable for app lifetime).
            wp_btns[i + 1] = .{
                .x = wp_x,
                .y = y,
                .w = 86,
                .h = bh,
                .label = wp_files[i][0..wp_file_lens[i]],
            };
        } else {
            // Empty slot — render off-screen so it doesn't fire on click.
            wp_btns[i + 1] = .{ .x = 9999, .y = y, .w = 0, .h = 0, .label = "" };
        }
        wp_x += 90;
    }
    y += bh + 28; // leave room for the status text under buttons
    wp_apply_btn = .{ .x = vis_w -| 130, .y = y - bh - 5, .w = 120, .h = bh, .label = "Apply Wallpaper" };
    y += section_h - bh - 28;

    apply_btn = .{ .x = vis_w / 2 -| 65, .y = y, .w = 130, .h = 32, .label = "Apply" };
}

// --- Status line drawer -----------------------------------------------------

fn drawWallpaperStatus(canvas: *gfx.Canvas, x: u32, y: u32) void {
    var line_buf: [96]u8 = undefined;
    var line_len: usize = 0;
    var color: u32 = LABEL_COLOR;

    switch (sel_wp_kind) {
        .none => {
            const t = "None — gradient background";
            @memcpy(line_buf[0..t.len], t);
            line_len = t.len;
        },
        .exact => {
            line_len = formatStatus(&line_buf, "✓ exact match");
            color = STATUS_OK;
        },
        .letterbox => {
            line_len = formatStatus(&line_buf, "centered (letterbox)");
            color = STATUS_WARN;
        },
        .mismatch => {
            line_len = formatStatus(&line_buf, "larger than screen — will be cropped");
            color = STATUS_WARN;
        },
        .broken => {
            const t = "couldn't read image (not a PNG?)";
            @memcpy(line_buf[0..t.len], t);
            line_len = t.len;
            color = STATUS_BAD;
        },
    }

    fa.drawTextOpaque(canvas, x, y, line_buf[0..line_len], color, BG, &fa.default_16);
}

fn formatStatus(buf: []u8, suffix: []const u8) usize {
    var p: usize = 0;
    p += writeNum(buf[p..], sel_wp_w);
    buf[p] = 'x';
    p += 1;
    p += writeNum(buf[p..], sel_wp_h);
    const scr = libc.getScreenSize();
    buf[p] = ' ';
    p += 1;
    buf[p] = ' ';
    p += 1;
    buf[p] = '/';
    p += 1;
    buf[p] = ' ';
    p += 1;
    p += writeNum(buf[p..], scr.w);
    buf[p] = 'x';
    p += 1;
    p += writeNum(buf[p..], scr.h);
    buf[p] = ' ';
    p += 1;
    buf[p] = ' ';
    p += 1;
    @memcpy(buf[p..][0..suffix.len], suffix);
    p += suffix.len;
    return p;
}

fn writeNum(buf: []u8, n: u32) usize {
    if (n == 0) {
        buf[0] = '0';
        return 1;
    }
    var tmp: [10]u8 = undefined;
    var i: usize = 0;
    var x = n;
    while (x > 0) {
        tmp[i] = @intCast('0' + (x % 10));
        x /= 10;
        i += 1;
    }
    var p: usize = 0;
    while (i > 0) {
        i -= 1;
        buf[p] = tmp[i];
        p += 1;
    }
    return p;
}

// --- Main -------------------------------------------------------------------

export fn _start() linksection(".text.entry") callconv(.c) void {
    const scr = libc.getScreenSize();
    var init_w = scr.w / 4;
    if (init_w < 460) init_w = 460;
    if (init_w > 540) init_w = 540;
    // 6 sections (was 5) + apply button + breathing room.
    const init_h: u32 = 46 + 60 * 6 + 50;
    alloc_w = @min(init_w * 2, scr.w);
    alloc_h = @min(init_h * 2, scr.h);
    while (alloc_w * alloc_h > 524288) {
        if (alloc_w > alloc_h) alloc_w -= 16 else alloc_h -= 16;
    }

    scanWallpapers();
    loadConf();
    refreshWallpaperStatus(); // applyKv may have set sel_wp_idx
    ui.setDarkMode(sel_theme == 1);

    computeLayout(init_w, init_h);

    const win = libc.createWindowEx(alloc_w, alloc_h, init_w, init_h) orelse {
        libc.exit();
    };
    alloc_w = win.alloc_w;
    alloc_h = win.alloc_h;
    var canvas = gfx.Canvas.init(win.fb, alloc_w, alloc_h);
    fa.ensureLoaded();
    var needs_redraw: bool = true;
    var prev_left: bool = false;
    var cur_mx: i32 = 0;
    var cur_my: i32 = 0;
    var cur_btns: u32 = 0;

    while (true) {
        while (libc.pollEvent()) |ev| {
            switch (ev.kindOf()) {
                .close_request => {
                    libc.destroyWindow();
                    libc.exit();
                },
                .key_char => {
                    if (@as(u8, @truncate(ev.a)) == 0x1B) {
                        libc.destroyWindow();
                        libc.exit();
                    }
                },
                .mouse_move => {
                    cur_mx = @bitCast(ev.a);
                    cur_my = @bitCast(ev.b);
                    cur_btns = ev.c;
                    needs_redraw = true;
                },
                .mouse_button => {
                    cur_btns = ev.buttonsState();
                    cur_mx = @bitCast(ev.b);
                    cur_my = @bitCast(ev.c);
                    needs_redraw = true;
                },
                .resize => {
                    const new_w = @min(ev.a, alloc_w);
                    const new_h = @min(ev.b, alloc_h);
                    if (new_w != vis_w or new_h != vis_h) {
                        computeLayout(new_w, new_h);
                        needs_redraw = true;
                    }
                },
                else => {},
            }
        }

        const left_now = (cur_btns & 1) != 0;
        for (&res_btns, 0..) |*btn, i| {
            if (btn.update(cur_mx, cur_my, left_now, prev_left)) {
                sel_resolution = @intCast(i);
                needs_redraw = true;
            }
        }
        for (&bg_btns, 0..) |*btn, i| {
            if (btn.update(cur_mx, cur_my, left_now, prev_left)) {
                sel_background = @intCast(i);
                needs_redraw = true;
            }
        }
        for (&theme_btns, 0..) |*btn, i| {
            if (btn.update(cur_mx, cur_my, left_now, prev_left)) {
                sel_theme = @intCast(i);
                ui.setDarkMode(i == 1);
                needs_redraw = true;
            }
        }
        for (&speed_btns, 0..) |*btn, i| {
            if (btn.update(cur_mx, cur_my, left_now, prev_left)) {
                sel_mouse_speed = @intCast(i);
                needs_redraw = true;
            }
        }
        for (&dock_btns, 0..) |*btn, i| {
            if (btn.update(cur_mx, cur_my, left_now, prev_left)) {
                sel_dock_pos = @intCast(i);
                needs_redraw = true;
            }
        }
        for (&wp_btns, 0..) |*btn, i| {
            if (btn.update(cur_mx, cur_my, left_now, prev_left)) {
                sel_wp_idx = @intCast(i);
                refreshWallpaperStatus();
                needs_redraw = true;
            }
        }
        if (wp_apply_btn.update(cur_mx, cur_my, left_now, prev_left)) {
            // Persist + spawn wallpaper.elf to do the heavy decode + push.
            saveConf();
            if (sel_wp_idx == 0) {
                _ = libc.exec("wallpaper.elf");
                libc.notify("Wallpaper cleared");
            } else {
                _ = libc.exec("wallpaper.elf");
                libc.notify("Wallpaper applied");
            }
            needs_redraw = true;
        }
        if (apply_btn.update(cur_mx, cur_my, left_now, prev_left)) {
            libc.setConfig(libc.Config.resolution, sel_resolution);
            libc.setConfig(libc.Config.background, sel_background);
            libc.setConfig(libc.Config.theme, sel_theme);
            libc.setConfig(libc.Config.mouse_speed, sel_mouse_speed);
            libc.setConfig(libc.Config.dock_pos, sel_dock_pos);
            libc.applyConfig();
            saveConf();
            libc.notify("Settings saved");
            needs_redraw = true;
        }
        prev_left = left_now;

        if (!needs_redraw) {
            libc.sleep(10);
            continue;
        }
        needs_redraw = false;

        canvas.clear(BG);
        fa.drawTextOpaque(&canvas, 12, 8, "Settings", SECTION_COLOR, BG, &fa.default_24);

        fa.drawTextOpaque(&canvas, 12, 42, "Resolution", LABEL_COLOR, BG, &fa.default_16);
        for (res_btns, 0..) |btn, i|
            btn.drawStyled(&canvas, if (sel_resolution == i) .primary else .default, BG);

        fa.drawTextOpaque(&canvas, 12, 42 + section_h, "Background", LABEL_COLOR, BG, &fa.default_16);
        for (bg_btns, 0..) |btn, i|
            btn.drawStyled(&canvas, if (sel_background == i) .primary else .default, BG);

        fa.drawTextOpaque(&canvas, 12, 42 + section_h * 2, "Theme", LABEL_COLOR, BG, &fa.default_16);
        for (theme_btns, 0..) |btn, i|
            btn.drawStyled(&canvas, if (sel_theme == i) .primary else .default, BG);

        fa.drawTextOpaque(&canvas, 12, 42 + section_h * 3, "Mouse Speed", LABEL_COLOR, BG, &fa.default_16);
        for (speed_btns, 0..) |btn, i|
            btn.drawStyled(&canvas, if (sel_mouse_speed == i) .primary else .default, BG);

        fa.drawTextOpaque(&canvas, 12, 42 + section_h * 4, "Dock Position", LABEL_COLOR, BG, &fa.default_16);
        for (dock_btns, 0..) |btn, i|
            btn.drawStyled(&canvas, if (sel_dock_pos == i) .primary else .default, BG);

        // Wallpaper section (the new one).
        fa.drawTextOpaque(&canvas, 12, 42 + section_h * 5, "Wallpaper", LABEL_COLOR, BG, &fa.default_16);
        for (wp_btns, 0..) |btn, i| {
            // Hide empty slots (label "" with w=0).
            if (btn.w == 0) continue;
            btn.drawStyled(&canvas, if (sel_wp_idx == i) .primary else .default, BG);
        }
        // Status line under the buttons.
        drawWallpaperStatus(&canvas, 12, 42 + section_h * 5 + 26 + 4);
        wp_apply_btn.drawStyled(&canvas, .primary, BG);

        apply_btn.drawStyled(&canvas, .primary, BG);

        libc.present();
        libc.sleep(10);
    }
}
