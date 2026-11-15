const libc = @import("libc");
const app = @import("app");
const ui = @import("ui");
const image = @import("image");

const STATUS_OK: u32 = 0x66DD88;
const STATUS_WARN: u32 = 0xFFCC55;
const STATUS_BAD: u32 = 0xFF6666;

const CONF_PATH = "/etc/zigos.conf";
const WP_DIR = "/share/";

var sel_resolution: u8 = 1; // default to 1080p
var sel_background: u8 = 0;
var sel_theme: u8 = 1; // the desktop's default when the file has no key
var sel_mouse_speed: u8 = 1;
// The dock has one position; the key is carried through so a saved value
// survives a rewrite of the file.
var sel_dock_pos: u8 = 0;
// Minutes east of UTC; zones sit on the hour or :30 / :45 past it.
var sel_utc_offset: i32 = 0;
const UTC_OFFSET_MIN: i32 = -12 * 60;
const UTC_OFFSET_MAX: i32 = 14 * 60;
const zone_minutes = [_]u32{ 0, 30, 45 };

// Wallpaper state. `sel_wp_path` is the full path of the picked image
// ("" = no wallpaper / gradient background). Cached image dimensions
// drive the status line.
var sel_wp_path_buf: [256]u8 = undefined;
var sel_wp_path_len: u32 = 0;
var sel_wp_w: u32 = 0;
var sel_wp_h: u32 = 0;
var sel_wp_kind: enum { none, exact, letterbox, mismatch, broken } = .none;

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

/// Signed decimal minutes within the range zones use.
fn parseOffset(s: []const u8) ?i32 {
    if (s.len == 0) return null;
    const neg = s[0] == '-';
    const digits = if (neg or s[0] == '+') s[1..] else s;
    if (digits.len == 0 or digits.len > 4) return null;
    var v: i32 = 0;
    for (digits) |c| {
        if (c < '0' or c > '9') return null;
        v = v * 10 + (c - '0');
    }
    if (neg) v = -v;
    return if (v < UTC_OFFSET_MIN or v > UTC_OFFSET_MAX) null else v;
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
    if (eql(key, "utc_offset")) {
        if (parseOffset(val_str)) |minutes| sel_utc_offset = minutes;
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

fn writeKvInt(buf: []u8, pos: usize, key: []const u8, val: i32) usize {
    var num: [12]u8 = undefined;
    var n: usize = 0;
    if (val < 0) {
        num[0] = '-';
        n = 1;
    }
    n += writeNum(num[n..], @abs(val));
    return writeKvStr(buf, pos, key, num[0..n]);
}

fn saveConf() void {
    var buf: [512]u8 = undefined;
    var pos: usize = 0;
    const header = "# ZigOS UI configuration, written by Settings\n";
    @memcpy(buf[pos..][0..header.len], header);
    pos += header.len;
    pos = writeKv(&buf, pos, "resolution", sel_resolution);
    pos = writeKv(&buf, pos, "background", sel_background);
    pos = writeKv(&buf, pos, "theme", sel_theme);
    pos = writeKv(&buf, pos, "mouse_speed", sel_mouse_speed);
    pos = writeKv(&buf, pos, "dock_pos", sel_dock_pos);
    pos = writeKvInt(&buf, pos, "utc_offset", sel_utc_offset);
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
    // stb's per-decode 4-8 MB scratch buffers were freed during the scan;
    // freeing the small downscaled thumbnails above is what unlocks the
    // adjacent-block coalesce that gives us one big free tail. Now is the
    // moment to hand that tail back to the kernel via malloc_trim.
    _ = libc.malloc_trim(0);
}

/// Decode (or rather, decode + scale-down) every image in `dir` into the
/// `wp_thumbs` slots. Caps at MAX_THUMBS — extras are ignored this turn;
/// a real implementation would page. RGBA byte order, scaled to
/// THUMB_W × THUMB_H (preserving aspect via inner letterbox).
fn scanWallpaperThumbs(dir: []const u8) void {
    freeWallpaperThumbs();
    var entries: [128]libc.FileEntry = undefined;
    const n = libc.readdir(dir, &entries);
    // By name, whatever order the disk lists them in.
    var a: u32 = 1;
    while (a < n) : (a += 1) {
        const moving = entries[a];
        var b = a;
        while (b > 0 and ui.nameBefore(moving.name[0..moving.name_len], entries[b - 1].name[0..entries[b - 1].name_len])) : (b -= 1) entries[b] = entries[b - 1];
        entries[b] = moving;
    }
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

    // Decode → full-res RGBA via the idiomatic image wrapper.
    const img = image.decode(file_buf[0..total], 4) catch return .{ .pixels = null, .w = 0, .h = 0 };
    defer img.deinit();
    if (img.width == 0 or img.height == 0) return .{ .pixels = null, .w = 0, .h = 0 };
    const src_w: u32 = img.width;
    const src_h: u32 = img.height;
    const px = img.pixels.ptr;

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
    if (dst_opt == null) return .{ .pixels = null, .w = 0, .h = 0 };
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

fn openPicker(u: *const app.Ui) void {
    // Start in the folder of the current wallpaper.
    const path = sel_wp_path_buf[0..sel_wp_path_len];
    var start_dir: []const u8 = WP_DIR;
    if (lastIndexOf(path, '/')) |slash| {
        if (slash > 0) start_dir = path[0 .. slash + 1];
    }
    wp_picker = ui.ImagePicker.init(u.w, u.h, start_dir);
    rescanPicker();
    wp_picker_active = true;
}

fn rescanPicker() void {
    scanWallpaperThumbs(wp_picker.currentDir());
    wp_picker.setThumbnails(wp_thumbs[0..wp_thumb_count]);
}

fn closePicker() void {
    wp_picker_active = false;
    freeWallpaperThumbs();
}

/// The picker's share of an input pass.
fn pickerInput(u: *app.Ui) void {
    var action = wp_picker.handleClick(u.mouse.x, u.mouse.y, u.down, u.was_down);
    const key = if (u.key != 0) u.key else u.special;
    if (action == .none and key != 0) action = wp_picker.handleKey(key);
    switch (action) {
        .cancel => closePicker(),
        .ok => {
            commitPickerSelection();
            closePicker();
        },
        .folder_changed => {
            rescanPicker();
            wp_picker.acknowledgeFolderChange();
        },
        .none => {},
    }
    // It keeps its own hover and selection.
    u.repaint();
}

// --- Status line -------------------------------------------------------------

const Status = struct { text: []const u8, color: u32 };

fn wallpaperStatus(buf: []u8) Status {
    return switch (sel_wp_kind) {
        .none => .{ .text = "No image: gradient background", .color = ui.palette.text_muted },
        .exact => .{ .text = buf[0..formatStatus(buf, "exact match")], .color = STATUS_OK },
        .letterbox => .{ .text = buf[0..formatStatus(buf, "centered (letterbox)")], .color = STATUS_WARN },
        .mismatch => .{ .text = buf[0..formatStatus(buf, "larger than the screen, will be cropped")], .color = STATUS_WARN },
        .broken => .{ .text = "couldn't read image (not a PNG?)", .color = STATUS_BAD },
    };
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

// --- Time zone ---------------------------------------------------------------

/// "UTC+05:30" for the selected offset.
fn zoneLabel(buf: *[9]u8) []const u8 {
    const mag: u32 = @abs(sel_utc_offset);
    const h: u8 = @intCast(mag / 60);
    const m: u8 = @intCast(mag % 60);
    const sign: u8 = if (sel_utc_offset < 0) '-' else '+';
    buf.* = .{ 'U', 'T', 'C', sign, '0' + h / 10, '0' + h % 10, ':', '0' + m / 10, '0' + m % 10 };
    return buf;
}

fn setZone(minutes: i32) void {
    sel_utc_offset = @max(UTC_OFFSET_MIN, @min(minutes, UTC_OFFSET_MAX));
}

/// Keep the hour, swap the minutes past it.
fn setZoneMinutes(past: u32) void {
    const mag: u32 = @abs(sel_utc_offset);
    const whole: i32 = @intCast(mag / 60 * 60 + past);
    setZone(if (sel_utc_offset < 0) -whole else whole);
}

/// Which of zone_minutes the offset has; past the end when none.
fn zoneMinuteIndex() usize {
    const past = @abs(sel_utc_offset) % 60;
    for (zone_minutes, 0..) |m, i| if (m == past) return i;
    return zone_minutes.len;
}

// --- Actions ----------------------------------------------------------------

fn apply() void {
    libc.setConfig(libc.Config.resolution, sel_resolution);
    libc.setConfig(libc.Config.background, sel_background);
    libc.setConfig(libc.Config.theme, sel_theme);
    libc.setConfig(libc.Config.mouse_speed, sel_mouse_speed);
    libc.setConfig(libc.Config.dock_pos, sel_dock_pos);
    libc.setConfig(libc.Config.utc_offset, @bitCast(sel_utc_offset));
    libc.applyConfig();
    saveConf();
    libc.notify("Settings saved");
}

fn clearWallpaper() void {
    sel_wp_path_len = 0;
    refreshWallpaperStatus();
    saveConf();
    // Straight to the kernel: wallpaper.elf, given an empty `wallpaper=`
    // line, exits without telling it to drop the image it has.
    libc.notify(if (libc.setWallpaperClear()) "Wallpaper cleared" else "Wallpaper clear failed");
}

// --- Window -----------------------------------------------------------------

export fn _start() linksection(".text.entry") callconv(.c) void {
    // Before run(): its first layout already shows the saved choices.
    loadConf();
    const scr = libc.getScreenSize();
    const w: u32 = @min(@max(scr.w / 4, 460), 540);
    app.run(@This(), .{ .width = w });
}

pub fn frame(u: *app.Ui) void {
    // The picker is modal: the settings under it are drawn but inert.
    if (wp_picker_active) {
        u.blocked = true;
        if (!u.painting) pickerInput(u);
    } else if (u.key == 0x1B) {
        u.close();
    }

    // No title of its own (the titlebar has it) and wallpaper under
    // Background: as laid out here the window still fits a 720p work area.
    u.beginGroup("Resolution");
    if (u.choice(&.{ "1280x720", "1920x1080" }, sel_resolution)) |i| sel_resolution = @intCast(i);
    u.endGroup();

    u.beginGroup("Background");
    if (u.choice(&.{ "Blue", "Purple", "Green", "Red" }, sel_background)) |i| sel_background = @intCast(i);
    if (u.button("Choose Wallpaper...")) openPicker(u);
    u.sameLine();
    if (u.button("Clear")) clearWallpaper();
    var status_buf: [96]u8 = undefined;
    const status = wallpaperStatus(&status_buf);
    u.text(status.text, status.color);
    u.endGroup();

    u.beginGroup("Theme");
    if (u.choice(&.{ "Light", "Dark" }, sel_theme)) |i| sel_theme = @intCast(i);
    u.endGroup();

    u.beginGroup("Mouse Speed");
    if (u.choice(&.{ "Slow", "Normal", "Fast" }, sel_mouse_speed)) |i| sel_mouse_speed = @intCast(i);
    u.endGroup();

    u.beginGroup("Time Zone");
    var zone_buf: [9]u8 = undefined;
    if (u.stepper(zoneLabel(&zone_buf), "UTC+00:00")) |step| setZone(sel_utc_offset + step * 60);
    u.sameLine();
    if (u.choice(&.{ ":00", ":30", ":45" }, zoneMinuteIndex())) |i| setZoneMinutes(zone_minutes[i]);
    u.endGroup();

    u.alignNext(.right);
    if (u.styledButton("Apply", .primary)) apply();

    if (wp_picker_active and u.painting) {
        ui.drawScrim(u.canvas, u.w, u.h);
        wp_picker.draw(u.canvas, ui.palette.window_bg);
    }
}
