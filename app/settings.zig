const libc = @import("libc");
const gfx = @import("graphics");
const ui = @import("ui");
const fa = @import("font_atlas");
const stb = @import("stb");
comptime {
    _ = @import("stb_shims");
}

const BG: u32 = 0x1E1E2E;
const SECTION_COLOR: u32 = 0x8888CC;
const LABEL_COLOR: u32 = 0xCCCCCC;
const STATUS_OK: u32 = 0x66DD88;
const STATUS_WARN: u32 = 0xFFCC55;
const STATUS_BAD: u32 = 0xFF6666;

const CONF_PATH = "/etc/zigos.conf";
const WP_DIR = "/share/";

var sel_resolution: u8 = 1; // default to 1080p
var sel_background: u8 = 0;
var sel_theme: u8 = 0;
var sel_mouse_speed: u8 = 1;
var sel_dock_pos: u8 = 0;

// Wallpaper state. `sel_wp_path` is the full path of the picked image
// ("" = no wallpaper / gradient background). Cached image dimensions
// drive the status line.
var sel_wp_path_buf: [256]u8 = undefined;
var sel_wp_path_len: u32 = 0;
var sel_wp_w: u32 = 0;
var sel_wp_h: u32 = 0;
var sel_wp_kind: enum { none, exact, letterbox, mismatch, broken } = .none;

var alloc_w: u32 = 0;
var alloc_h: u32 = 0;
var vis_w: u32 = 0;
var vis_h: u32 = 0;
var section_h: u32 = 0;

// Label y-coordinates produced by computeLayout's VStack walk. Indexed
// in section order: 0=Resolution, 1=Background, 2=Theme, 3=Mouse Speed,
// 4=Dock Position, 5=Wallpaper. Render block reads from this to keep
// the label rows aligned with the button rows below them without
// re-doing the y math at every drawText call site.
var label_ys: [6]u32 = [_]u32{0} ** 6;
var wp_status_y: u32 = 0;
// macOS-style cards — one per section. Each wraps its row of buttons
// with rounded card_bg + AA corners. computeLayout sizes them after
// reserving space for the row(s) inside.
var cards: [6]ui.Card = [_]ui.Card{.{ .x = 0, .y = 0, .w = 0, .h = 0 }} ** 6;

var res_btns: [2]ui.Button = undefined;
var bg_btns: [4]ui.Button = undefined;
const bg_colors = [4]u32{ 0x2D5F8A, 0x5F2D8A, 0x2D8A5F, 0x8A2D2D };
var theme_btns: [2]ui.Button = undefined;
var speed_btns: [3]ui.Button = undefined;
var dock_btns: [2]ui.Button = undefined;
var wp_choose_btn: ui.Button = undefined;
var wp_clear_btn: ui.Button = undefined;
var apply_btn: ui.Button = undefined;

// --- Wallpaper picker state ------------------------------------------------
//
// `wp_picker` opens when the user clicks Choose Wallpaper...; it browses
// folders, shows thumbnails, returns a picked filename. Thumbnails for
// the currently-shown directory live in `wp_thumbs` (decoded from disk
// via stb_image, scaled down to ImagePicker.thumb_w/h). Pixel buffers
// are owned here and freed on folder change / dismiss.

const MAX_THUMBS: u32 = ui.ImagePicker.cols * ui.ImagePicker.rows;
var wp_picker: ui.ImagePicker = undefined;
var wp_picker_active: bool = false;
var wp_thumbs: [MAX_THUMBS]ui.Thumbnail = undefined;
var wp_thumb_count: u32 = 0;
var wp_thumb_pixels: [MAX_THUMBS]?[*]u8 = .{null} ** MAX_THUMBS;
var wp_thumb_names: [MAX_THUMBS][32]u8 = undefined;
var wp_thumb_name_lens: [MAX_THUMBS]u8 = undefined;

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
        sel_wp_path_len = 0;
        if (val_str.len == 0 or val_str.len >= sel_wp_path_buf.len) return;
        @memcpy(sel_wp_path_buf[0..val_str.len], val_str);
        sel_wp_path_len = @intCast(val_str.len);
        refreshWallpaperStatus();
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
    pos = writeKvStr(&buf, pos, "wallpaper", sel_wp_path_buf[0..sel_wp_path_len]);
    const fd = libc.openFlags(CONF_PATH, libc.O_TRUNC) orelse return;
    defer libc.close(fd);
    _ = libc.fwrite(fd, buf[0..pos]);
}

// --- Wallpaper helpers ------------------------------------------------------

fn endsWith(s: []const u8, suf: []const u8) bool {
    if (s.len < suf.len) return false;
    return eql(s[s.len - suf.len ..], suf);
}

fn isImageName(name: []const u8) bool {
    return endsWith(name, ".png") or endsWith(name, ".PNG") or
        endsWith(name, ".jpg") or endsWith(name, ".JPG") or
        endsWith(name, ".jpeg") or endsWith(name, ".JPEG") or
        endsWith(name, ".bmp") or endsWith(name, ".BMP");
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
    if (sel_wp_path_len == 0) {
        sel_wp_w = 0;
        sel_wp_h = 0;
        sel_wp_kind = .none;
        return;
    }
    const path = sel_wp_path_buf[0..sel_wp_path_len];
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
        // For .jpg / .bmp we don't have a dim-peek implementation. Don't
        // mark broken — caller can still apply, wallpaper.elf will report
        // the real dims after decoding.
        sel_wp_kind = .letterbox;
    }
}

// --- Wallpaper picker plumbing ---------------------------------------------

fn freeWallpaperThumbs() void {
    var i: u32 = 0;
    while (i < MAX_THUMBS) : (i += 1) {
        if (wp_thumb_pixels[i]) |px| {
            libc.free(@as([*]u8, @ptrCast(px)));
            wp_thumb_pixels[i] = null;
        }
    }
    wp_thumb_count = 0;
}

/// Decode (or rather, decode + scale-down) every image in `dir` into the
/// `wp_thumbs` slots. Caps at MAX_THUMBS — extras are ignored this turn;
/// a real implementation would page. RGBA byte order, scaled to
/// THUMB_W × THUMB_H (preserving aspect via inner letterbox).
fn scanWallpaperThumbs(dir: []const u8) void {
    freeWallpaperThumbs();
    var entries: [128]libc.FileEntry = undefined;
    const n = libc.readdir(dir, &entries);
    var slot: u32 = 0;
    var i: u32 = 0;
    while (i < n and slot < MAX_THUMBS) : (i += 1) {
        const e = &entries[i];
        if ((e.flags & libc.FE_FLAG_IS_DIR) != 0) continue;
        const name = e.name[0..e.name_len];
        if (!isImageName(name)) continue;

        const decoded = decodeThumb(dir, name);
        @memcpy(wp_thumb_names[slot][0..name.len], name);
        wp_thumb_name_lens[slot] = @intCast(name.len);
        wp_thumb_pixels[slot] = decoded.pixels;
        wp_thumbs[slot] = .{
            .name = wp_thumb_names[slot][0..wp_thumb_name_lens[slot]],
            .pixels = if (decoded.pixels) |p| @ptrCast(p) else null,
            .w = decoded.w,
            .h = decoded.h,
        };
        slot += 1;
    }
    wp_thumb_count = slot;
}

const DecodedThumb = struct { pixels: ?[*]u8, w: u32, h: u32 };

/// File-read scratch buffer reused across decodeThumb calls. Reallocates
/// only when a file is larger than the current capacity. Avoids the
/// per-call malloc(16MB)/free churn that fragmented the heap (see crash
/// autopsy 2026-05-14), but also doesn't pin 16 MB up-front the way an
/// always-on slab would — on 128 MB QEMU, holding 16 MB just for thumbs
/// plus wallpaper.elf's own buffer was enough to wedge cpu1 in mapUserPage
/// under PMM pressure (watchdog crash 2026-05-14, build 6A05B817).
const FILE_BUF_HARD_CAP: usize = 16 * 1024 * 1024;
var thumb_file_buf: ?[*]u8 = null;
var thumb_file_cap: usize = 0;

fn ensureThumbFileBuf(want: usize) ?[*]u8 {
    if (want == 0 or want > FILE_BUF_HARD_CAP) return null;
    if (thumb_file_buf) |b| {
        if (want <= thumb_file_cap) return b;
        libc.free(b);
        thumb_file_buf = null;
        thumb_file_cap = 0;
    }
    const round_up: usize = ((want + 65535) / 65536) * 65536; // 64 KB grain
    const opt = libc.malloc(round_up) orelse return null;
    thumb_file_buf = opt;
    thumb_file_cap = round_up;
    return opt;
}

fn decodeThumb(dir: []const u8, name: []const u8) DecodedThumb {
    // Build full path.
    var path: [320]u8 = undefined;
    if (dir.len + name.len >= path.len) return .{ .pixels = null, .w = 0, .h = 0 };
    @memcpy(path[0..dir.len], dir);
    @memcpy(path[dir.len..][0..name.len], name);
    const full = path[0 .. dir.len + name.len];

    // stat → exact size, malloc just enough (grow-on-demand). Avoids
    // pinning 16 MB for a 1 MB PNG.
    var st: libc.FileStat = undefined;
    if (!libc.stat(full, &st)) return .{ .pixels = null, .w = 0, .h = 0 };
    const want: usize = @as(usize, st.file_size);
    const file_buf = ensureThumbFileBuf(want + 4096) orelse return .{ .pixels = null, .w = 0, .h = 0 };
    const fd = libc.open(full) orelse return .{ .pixels = null, .w = 0, .h = 0 };
    defer libc.close(fd);
    var total: usize = 0;
    while (total < thumb_file_cap) {
        const remaining = thumb_file_cap - total;
        const chunk = if (remaining > 65536) 65536 else remaining;
        const got = libc.fread(fd, file_buf[total .. total + chunk]);
        if (got == 0) break;
        total += got;
    }

    // stb decode → full-res RGBA.
    var iw: c_int = 0;
    var ih: c_int = 0;
    var ich: c_int = 0;
    const px = stb.stbi_load_from_memory(file_buf, @intCast(total), &iw, &ih, &ich, 4);
    if (px == null or iw <= 0 or ih <= 0) return .{ .pixels = null, .w = 0, .h = 0 };
    const src_w: u32 = @intCast(iw);
    const src_h: u32 = @intCast(ih);

    // Scale-down to thumb dimensions while preserving aspect.
    const max_w: u32 = ui.ImagePicker.thumb_w;
    const max_h: u32 = ui.ImagePicker.thumb_h;
    var dst_w: u32 = src_w;
    var dst_h: u32 = src_h;
    if (dst_w > max_w or dst_h > max_h) {
        const fx = (max_w * 256) / dst_w;
        const fy = (max_h * 256) / dst_h;
        const f = @min(fx, fy);
        dst_w = (dst_w * f) / 256;
        dst_h = (dst_h * f) / 256;
        if (dst_w == 0) dst_w = 1;
        if (dst_h == 0) dst_h = 1;
    }

    const dst_size: usize = @as(usize, dst_w) * @as(usize, dst_h) * 4;
    const dst_opt = libc.malloc(dst_size);
    if (dst_opt == null) {
        stb.stbi_image_free(px);
        return .{ .pixels = null, .w = 0, .h = 0 };
    }
    const dst = dst_opt.?;
    var y: u32 = 0;
    while (y < dst_h) : (y += 1) {
        const sy = (y * src_h) / dst_h;
        const drow = y * dst_w * 4;
        const srow = sy * src_w * 4;
        var x: u32 = 0;
        while (x < dst_w) : (x += 1) {
            const sx = (x * src_w) / dst_w;
            dst[drow + x * 4 + 0] = px[srow + sx * 4 + 0];
            dst[drow + x * 4 + 1] = px[srow + sx * 4 + 1];
            dst[drow + x * 4 + 2] = px[srow + sx * 4 + 2];
            dst[drow + x * 4 + 3] = px[srow + sx * 4 + 3];
        }
    }
    stb.stbi_image_free(px);
    return .{ .pixels = dst, .w = dst_w, .h = dst_h };
}

fn commitPickerSelection() void {
    const name_opt = wp_picker.selectedName();
    if (name_opt) |name| {
        const dir = wp_picker.currentDir();
        if (dir.len + name.len < sel_wp_path_buf.len) {
            @memcpy(sel_wp_path_buf[0..dir.len], dir);
            @memcpy(sel_wp_path_buf[dir.len..][0..name.len], name);
            sel_wp_path_len = @intCast(dir.len + name.len);
            refreshWallpaperStatus();
            saveConf();
            applyWallpaperAndNotify("Wallpaper applied", "Wallpaper apply failed");
        }
    }
}

/// Spawn wallpaper.elf, wait for it, and report the real outcome. Previously
/// the notification fired the instant we exec'd, which made silent failures
/// (PMM exhaustion, kvmalloc fragmentation) invisible: the user saw
/// "Wallpaper applied" while the kernel still held the old wallpaper.
fn applyWallpaperAndNotify(ok_msg: []const u8, fail_msg: []const u8) void {
    const pid = libc.exec("wallpaper.elf");
    if (pid == 0 or pid == 0xFFFFFFFF) {
        libc.notify(fail_msg);
        return;
    }
    var status: u32 = 0xFFFFFFFF;
    const reaped = libc.waitpid(pid, &status);
    if (reaped != pid or status != 0) {
        libc.notify(fail_msg);
        return;
    }
    libc.notify(ok_msg);
}

// --- Layout -----------------------------------------------------------------

fn computeLayout(w: u32, h: u32) void {
    vis_w = w;
    vis_h = h;
    section_h = 60; // legacy field, no longer used by the layout itself

    const bh: u32 = 26;
    const m: u32 = 12;
    const LABEL_TO_CARD: u32 = 6; // small gap between section label and the card
    const SECTION_GAP: u32 = 16;
    const lh: u32 = fa.default_16.line_height;
    const card_w: u32 = w -| (m * 2);
    const ix: u32 = m + ui.Card.HPAD; // button x inside a card

    var v = ui.VStack.init(undefined, m, 8, card_w);
    v.gap(fa.default_24.line_height + 12); // title row + gap

    // Each section: label, small gap, then a card with one row of
    // buttons (or two stacked rows for wallpaper). Card top/bottom are
    // determined by `card_y_start` and `v.cursor() - card_y_start`
    // after the row is reserved.

    // Resolution
    label_ys[0] = v.cursor();
    v.gap(lh + LABEL_TO_CARD);
    var card_y = v.cursor();
    v.gap(ui.Card.VPAD);
    var y = v.reserve(bh);
    res_btns[0] = .{ .x = ix, .y = y, .w = 110, .h = bh, .label = "1280x720" };
    res_btns[1] = .{ .x = ix + 116, .y = y, .w = 120, .h = bh, .label = "1920x1080" };
    v.gap(ui.Card.VPAD);
    cards[0] = .{ .x = m, .y = card_y, .w = card_w, .h = v.cursor() - card_y };
    v.gap(SECTION_GAP);

    // Background
    label_ys[1] = v.cursor();
    v.gap(lh + LABEL_TO_CARD);
    card_y = v.cursor();
    v.gap(ui.Card.VPAD);
    y = v.reserve(bh);
    bg_btns[0] = .{ .x = ix, .y = y, .w = 70, .h = bh, .label = "Blue" };
    bg_btns[1] = .{ .x = ix + 76, .y = y, .w = 80, .h = bh, .label = "Purple" };
    bg_btns[2] = .{ .x = ix + 162, .y = y, .w = 75, .h = bh, .label = "Green" };
    bg_btns[3] = .{ .x = ix + 243, .y = y, .w = 60, .h = bh, .label = "Red" };
    v.gap(ui.Card.VPAD);
    cards[1] = .{ .x = m, .y = card_y, .w = card_w, .h = v.cursor() - card_y };
    v.gap(SECTION_GAP);

    // Theme
    label_ys[2] = v.cursor();
    v.gap(lh + LABEL_TO_CARD);
    card_y = v.cursor();
    v.gap(ui.Card.VPAD);
    y = v.reserve(bh);
    theme_btns[0] = .{ .x = ix, .y = y, .w = 80, .h = bh, .label = "Light" };
    theme_btns[1] = .{ .x = ix + 86, .y = y, .w = 80, .h = bh, .label = "Dark" };
    v.gap(ui.Card.VPAD);
    cards[2] = .{ .x = m, .y = card_y, .w = card_w, .h = v.cursor() - card_y };
    v.gap(SECTION_GAP);

    // Mouse Speed
    label_ys[3] = v.cursor();
    v.gap(lh + LABEL_TO_CARD);
    card_y = v.cursor();
    v.gap(ui.Card.VPAD);
    y = v.reserve(bh);
    speed_btns[0] = .{ .x = ix, .y = y, .w = 70, .h = bh, .label = "Slow" };
    speed_btns[1] = .{ .x = ix + 76, .y = y, .w = 85, .h = bh, .label = "Normal" };
    speed_btns[2] = .{ .x = ix + 167, .y = y, .w = 70, .h = bh, .label = "Fast" };
    v.gap(ui.Card.VPAD);
    cards[3] = .{ .x = m, .y = card_y, .w = card_w, .h = v.cursor() - card_y };
    v.gap(SECTION_GAP);

    // Dock Position
    label_ys[4] = v.cursor();
    v.gap(lh + LABEL_TO_CARD);
    card_y = v.cursor();
    v.gap(ui.Card.VPAD);
    y = v.reserve(bh);
    dock_btns[0] = .{ .x = ix, .y = y, .w = 90, .h = bh, .label = "Bottom" };
    dock_btns[1] = .{ .x = ix + 96, .y = y, .w = 80, .h = bh, .label = "Top" };
    v.gap(ui.Card.VPAD);
    cards[4] = .{ .x = m, .y = card_y, .w = card_w, .h = v.cursor() - card_y };
    v.gap(SECTION_GAP);

    // Wallpaper — button row + status line below, both inside the card
    label_ys[5] = v.cursor();
    v.gap(lh + LABEL_TO_CARD);
    card_y = v.cursor();
    v.gap(ui.Card.VPAD);
    y = v.reserve(bh);
    wp_choose_btn = .{ .x = ix, .y = y, .w = 180, .h = bh, .label = "Choose Wallpaper..." };
    wp_clear_btn = .{ .x = ix + 186, .y = y, .w = 70, .h = bh, .label = "Clear" };
    v.gap(8);
    wp_status_y = v.reserve(lh);
    v.gap(ui.Card.VPAD);
    cards[5] = .{ .x = m, .y = card_y, .w = card_w, .h = v.cursor() - card_y };

    // Apply — centered below all cards, 32 px tall as a primary action
    v.gap(SECTION_GAP + 4);
    const apply_y = v.reserve(32);
    apply_btn = .{ .x = vis_w / 2 -| 65, .y = apply_y, .w = 130, .h = 32, .label = "Apply" };
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

    // Status sits INSIDE the wallpaper card now — bg-fill must use the
    // card color, not the window bg, or the opaque rect punches a hole
    // in the card.
    fa.drawTextOpaque(canvas, x, y, line_buf[0..line_len], color, ui.palette.card_bg, &fa.default_16);
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
    // Atlases first — every later height calc (init_h below, computeLayout
    // when called) reads line_height; lazy load would leave it as 0.
    fa.ensureLoaded();

    const scr = libc.getScreenSize();
    var init_w = scr.w / 4;
    if (init_w < 460) init_w = 460;
    if (init_w > 540) init_w = 540;
    // Card layout: title + 5 standard sections + wallpaper (taller, has
    // status row) + apply. Numbers come from computeLayout's actual gaps:
    //   title block:    title_lh + 12
    //   per section:    label_lh + 6 (gap) + 12 (vpad) + 26 (button) + 12 (vpad) + 16 (section gap)
    //   wallpaper extra: 8 (gap) + label_lh (status)
    //   apply block:    (section_gap+4) + 32
    //   bottom margin:  16
    const bh: u32 = 26;
    const lh16: u32 = fa.default_16.line_height;
    const lh24: u32 = fa.default_24.line_height;
    const per_section: u32 = lh16 + 6 + 12 + bh + 12 + 16;
    const init_h: u32 = 8 + lh24 + 12 + per_section * 5 + (per_section + 8 + lh16) + (16 + 4 + 32) + 16;
    alloc_w = @min(init_w * 2, scr.w);
    alloc_h = @min(init_h * 2, scr.h);
    while (alloc_w * alloc_h > 524288) {
        if (alloc_w > alloc_h) alloc_w -= 16 else alloc_h -= 16;
    }

    loadConf();
    refreshWallpaperStatus(); // applyKv may have set sel_wp_path
    ui.setDarkMode(sel_theme == 1);

    // Force font atlases parsed BEFORE computeLayout — the new VStack-based
    // layout reads default_16/default_24's line_height to size the row
    // gaps, and the atlases are otherwise lazy-loaded on first drawText.
    // Without this, line_height reads as 0 (undefined) and all rows
    // collapse onto the buttons below them.
    fa.ensureLoaded();

    computeLayout(init_w, init_h);

    const win = libc.createWindowEx(alloc_w, alloc_h, init_w, init_h) orelse {
        libc.exit();
    };
    alloc_w = win.alloc_w;
    alloc_h = win.alloc_h;
    var canvas = gfx.Canvas.init(win.fb, alloc_w, alloc_h);
    _ = libc.getWindowAlloc(); // opt this window into F10 grow-on-maximize (re-fetched in .resize)
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
                    const ch: u8 = @truncate(ev.a);
                    if (wp_picker_active) {
                        switch (wp_picker.handleKey(ch)) {
                            .cancel => {
                                wp_picker_active = false;
                                freeWallpaperThumbs();
                                needs_redraw = true;
                            },
                            .ok => {
                                commitPickerSelection();
                                wp_picker_active = false;
                                freeWallpaperThumbs();
                                needs_redraw = true;
                            },
                            .folder_changed => {
                                scanWallpaperThumbs(wp_picker.currentDir());
                                wp_picker.setThumbnails(wp_thumbs[0..wp_thumb_count]);
                                wp_picker.acknowledgeFolderChange();
                                needs_redraw = true;
                            },
                            .none => {},
                        }
                    } else if (ch == 0x1B) {
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
                    // F10 maximize may have GROWN our framebuffer past the
                    // alloc we requested. Re-fetch and rebuild the canvas at
                    // the new stride before clamping/laying out (FB ptr is
                    // unchanged) so we render crisply instead of upscaled.
                    const wa = libc.getWindowAlloc();
                    if (wa.w != 0 and (wa.w != alloc_w or wa.h != alloc_h)) {
                        alloc_w = wa.w;
                        alloc_h = wa.h;
                        canvas = gfx.Canvas.init(win.fb, alloc_w, alloc_h);
                    }
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

        // Picker is modal — when active, it consumes the click and the
        // base-settings widgets stop receiving updates.
        if (wp_picker_active) {
            switch (wp_picker.handleClick(cur_mx, cur_my, left_now, prev_left)) {
                .cancel => {
                    wp_picker_active = false;
                    freeWallpaperThumbs();
                    needs_redraw = true;
                },
                .ok => {
                    commitPickerSelection();
                    wp_picker_active = false;
                    freeWallpaperThumbs();
                    needs_redraw = true;
                },
                .folder_changed => {
                    scanWallpaperThumbs(wp_picker.currentDir());
                    wp_picker.setThumbnails(wp_thumbs[0..wp_thumb_count]);
                    wp_picker.acknowledgeFolderChange();
                    needs_redraw = true;
                },
                .none => {
                    if (left_now != prev_left) needs_redraw = true;
                },
            }
            prev_left = left_now;
            if (!needs_redraw) {
                libc.sleep(10);
                continue;
            }
        } else {
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
            if (wp_choose_btn.update(cur_mx, cur_my, left_now, prev_left)) {
                const start_dir: []const u8 = if (sel_wp_path_len > 0) blk: {
                    var i: i32 = @as(i32, @intCast(sel_wp_path_len)) - 1;
                    while (i > 0 and sel_wp_path_buf[@intCast(i)] != '/') : (i -= 1) {}
                    if (i > 0) break :blk sel_wp_path_buf[0 .. @as(usize, @intCast(i)) + 1];
                    break :blk WP_DIR;
                } else WP_DIR;
                wp_picker = ui.ImagePicker.init(vis_w, vis_h, start_dir);
                scanWallpaperThumbs(wp_picker.currentDir());
                wp_picker.setThumbnails(wp_thumbs[0..wp_thumb_count]);
                wp_picker_active = true;
                needs_redraw = true;
            }
            if (wp_clear_btn.update(cur_mx, cur_my, left_now, prev_left)) {
                sel_wp_path_len = 0;
                refreshWallpaperStatus();
                saveConf();
                // Clear talks to the kernel directly. Going via
                // wallpaper.elf would only see an empty `wallpaper=` line
                // in conf and exit cleanly without telling the kernel to
                // drop its current wallpaper.
                if (libc.setWallpaperClear()) {
                    libc.notify("Wallpaper cleared");
                } else {
                    libc.notify("Wallpaper clear failed");
                }
                needs_redraw = true;
            }
        }
        if (!wp_picker_active and apply_btn.update(cur_mx, cur_my, left_now, prev_left)) {
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

        // Each section: label outside the card, then card surface, then
        // buttons inside. Buttons pass `palette.card_bg` as their corner
        // clip color so the AA corners blend against the card and not the
        // window bg behind it.
        const cbg = ui.palette.card_bg;

        fa.drawTextOpaque(&canvas, 12, label_ys[0], "Resolution", LABEL_COLOR, BG, &fa.default_16);
        cards[0].drawBg(&canvas, BG);
        for (res_btns, 0..) |btn, i|
            btn.drawStyled(&canvas, if (sel_resolution == i) .primary else .default, cbg);

        fa.drawTextOpaque(&canvas, 12, label_ys[1], "Background", LABEL_COLOR, BG, &fa.default_16);
        cards[1].drawBg(&canvas, BG);
        for (bg_btns, 0..) |btn, i|
            btn.drawStyled(&canvas, if (sel_background == i) .primary else .default, cbg);

        fa.drawTextOpaque(&canvas, 12, label_ys[2], "Theme", LABEL_COLOR, BG, &fa.default_16);
        cards[2].drawBg(&canvas, BG);
        for (theme_btns, 0..) |btn, i|
            btn.drawStyled(&canvas, if (sel_theme == i) .primary else .default, cbg);

        fa.drawTextOpaque(&canvas, 12, label_ys[3], "Mouse Speed", LABEL_COLOR, BG, &fa.default_16);
        cards[3].drawBg(&canvas, BG);
        for (speed_btns, 0..) |btn, i|
            btn.drawStyled(&canvas, if (sel_mouse_speed == i) .primary else .default, cbg);

        fa.drawTextOpaque(&canvas, 12, label_ys[4], "Dock Position", LABEL_COLOR, BG, &fa.default_16);
        cards[4].drawBg(&canvas, BG);
        for (dock_btns, 0..) |btn, i|
            btn.drawStyled(&canvas, if (sel_dock_pos == i) .primary else .default, cbg);

        fa.drawTextOpaque(&canvas, 12, label_ys[5], "Wallpaper", LABEL_COLOR, BG, &fa.default_16);
        cards[5].drawBg(&canvas, BG);
        wp_choose_btn.drawStyled(&canvas, .default, cbg);
        wp_clear_btn.drawStyled(&canvas, .default, cbg);
        drawWallpaperStatus(&canvas, cards[5].innerX(), wp_status_y);

        apply_btn.drawStyled(&canvas, .primary, BG);

        // Picker overlay paints LAST so it sits above every base widget.
        if (wp_picker_active) wp_picker.draw(&canvas, BG);

        libc.present();
        libc.sleep(10);
    }
}
