// photo — image viewer.
//
// Opens the image named on the command line (default
// /share/zigos_test.png) and scans its folder for others (.png, .jpg,
// .jpeg, .bmp): the toolbar arrows and the Left/Right keys step through
// them, Open Folder picks another folder. An image larger than the window
// is scaled down to fit, never up.

const libc = @import("libc");
const gfx = @import("graphics");
const ui = @import("ui");
const fa = @import("font_atlas");
const image = @import("image");
const app = @import("app");

/// Behind the image: a shade under the window body, so the picture's edge
/// shows even where the picture is dark.
const COLOR_STAGE: u32 = 0x161618;

const MIN_W: u32 = 640;
const MIN_H: u32 = 480;
const MAX_IMAGES: u32 = 256;
const FILE_BUF_CAP: usize = 16 * 1024 * 1024;
const CACHE_SIZE: u32 = 4;

// --- State ---

/// Directory we last scanned, trailing-slash terminated.
var dir_buf: [256]u8 = undefined;
var dir_len: u32 = 0;

/// Image filenames in `dir_buf`, in readdir's order.
var images: [MAX_IMAGES]libc.FileEntry = undefined;
var image_count: u32 = 0;
var current_idx: i32 = -1;

/// File-read scratch buffer. Allocated ONCE at startup and reused
/// across every image load — the per-load malloc/free cycle of the
/// 16 MB buffer was the source of the 2026-05-14 photo.elf #PF
/// (heap returned a partially-mapped region after enough cycles).
var file_buf: ?[*]u8 = null;

/// LRU cache of decoded image pixels. Once an image is decoded once,
/// switching back to it via Prev/Next is instant — no disk read, no
/// stb decode. Capped at CACHE_SIZE entries (~16 MB at 2 MP each,
/// well within user heap). Eviction frees the oldest entry's pixels.
const CacheEntry = struct {
    name_buf: [32]u8 = [_]u8{0} ** 32,
    name_len: u8 = 0,
    pixels: ?[*]u8 = null,
    w: u32 = 0,
    h: u32 = 0,
    /// Monotonic stamp; bigger = more recently used. 0 = empty slot.
    stamp: u32 = 0,
};
var cache: [CACHE_SIZE]CacheEntry = [_]CacheEntry{.{}} ** CACHE_SIZE;
var cache_tick: u32 = 0;

/// Index into `cache[]` for the currently-displayed image; -1 = none.
var current_cache: i32 = -1;

/// The current image scaled to the size it was last shown at, as
/// framebuffer pixels: scaling is the slow part of a repaint, and most
/// repaints (hover, the picker) change neither the image nor its size.
/// One screenful, allocated on first use.
var scaled: ?[*]u32 = null;
var scaled_cap: usize = 0;
var scaled_w: u32 = 0;
var scaled_h: u32 = 0;
/// cache[].stamp of the image in `scaled`; 0 = nothing.
var scaled_stamp: u32 = 0;

var picker: ui.FolderPicker = undefined;
var picker_active: bool = false;

// --- Filename helpers ----------------------------------------------------

fn isImage(entry: *const libc.FileEntry) bool {
    if ((entry.flags & libc.FE_FLAG_IS_DIR) != 0) return false;
    const name = entry.name[0..entry.name_len];
    return endsWith(name, ".png") or endsWith(name, ".jpg") or
        endsWith(name, ".jpeg") or endsWith(name, ".bmp");
}

fn endsWith(name: []const u8, suffix: []const u8) bool {
    if (name.len < suffix.len) return false;
    for (0..suffix.len) |i| {
        const a = name[name.len - suffix.len + i];
        const b = suffix[i];
        const al = if (a >= 'A' and a <= 'Z') a + 32 else a;
        const bl = if (b >= 'A' and b <= 'Z') b + 32 else b;
        if (al != bl) return false;
    }
    return true;
}

/// Split `path` at the last '/' into its folder (with the slash) and the
/// file name. A bare name is in the current directory: that is how Files
/// hands an image over.
fn splitPath(path: []const u8, cwd: []const u8) struct { dir: []const u8, name: []const u8 } {
    var last_slash: ?usize = null;
    for (path, 0..) |c, i| {
        if (c == '/') last_slash = i;
    }
    if (last_slash) |ls| return .{ .dir = path[0 .. ls + 1], .name = path[ls + 1 ..] };
    return .{ .dir = cwd, .name = path };
}

// --- Directory scanning + image loading ----------------------------------

fn setDir(p: []const u8) void {
    if (p.len == 0 or p.len + 1 >= dir_buf.len) return;
    @memcpy(dir_buf[0..p.len], p);
    dir_len = @intCast(p.len);
    if (dir_buf[dir_len - 1] != '/') {
        dir_buf[dir_len] = '/';
        dir_len += 1;
    }
}

fn scanDir() void {
    var tmp: [MAX_IMAGES]libc.FileEntry = undefined;
    const n = libc.readdir(dir_buf[0..dir_len], &tmp);
    var kept: u32 = 0;
    var i: u32 = 0;
    while (i < n and kept < MAX_IMAGES) : (i += 1) {
        if (isImage(&tmp[i])) {
            images[kept] = tmp[i];
            kept += 1;
        }
    }
    image_count = kept;
    current_idx = if (kept > 0) 0 else -1;
    // By name, so that Next and Previous go the way a file listing does.
    var a: u32 = 1;
    while (a < kept) : (a += 1) {
        const moving = images[a];
        var b = a;
        while (b > 0 and ui.nameBefore(moving.name[0..moving.name_len], images[b - 1].name[0..images[b - 1].name_len])) : (b -= 1) images[b] = images[b - 1];
        images[b] = moving;
    }
}

fn nameEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| if (x != y) return false;
    return true;
}

/// Point current_idx at `name`, or at the first image if it is not there.
fn selectByName(name: []const u8) void {
    var i: u32 = 0;
    while (i < image_count) : (i += 1) {
        if (nameEql(images[i].name[0..images[i].name_len], name)) {
            current_idx = @intCast(i);
            return;
        }
    }
    current_idx = if (image_count > 0) 0 else -1;
}

/// Find a cache slot whose name matches `name`; null on miss.
fn cacheFind(name: []const u8) ?u32 {
    var i: u32 = 0;
    while (i < CACHE_SIZE) : (i += 1) {
        if (cache[i].stamp == 0) continue;
        if (nameEql(cache[i].name_buf[0..cache[i].name_len], name)) return i;
    }
    return null;
}

/// Pick a slot for a new insertion. Prefers an empty slot; otherwise
/// the oldest (smallest stamp). Frees the evicted entry's pixels.
fn cachePickSlot() u32 {
    var best: u32 = 0;
    var best_stamp: u32 = 0xFFFFFFFF;
    var i: u32 = 0;
    while (i < CACHE_SIZE) : (i += 1) {
        if (cache[i].stamp == 0) return i;
        if (cache[i].stamp < best_stamp) {
            best_stamp = cache[i].stamp;
            best = i;
        }
    }
    if (cache[best].pixels) |p| {
        image.raw.stbi_image_free(p);
        cache[best].pixels = null;
    }
    return best;
}

fn cacheBump(idx: u32) void {
    cache_tick += 1;
    cache[idx].stamp = cache_tick;
}

/// Names from another folder must not match this folder's cached pixels.
fn cacheClear() void {
    for (&cache) |*e| {
        if (e.pixels) |p| image.raw.stbi_image_free(p);
        e.* = .{};
    }
    current_cache = -1;
    scaled_stamp = 0;
}

/// Ensure the FILE_BUF_CAP scratch buffer exists. Allocated once and
/// never freed — perpetual ownership is the point (avoid heap churn).
fn ensureFileBuf() bool {
    if (file_buf != null) return true;
    file_buf = libc.malloc(FILE_BUF_CAP);
    return file_buf != null;
}

fn readEntireFile(path: []const u8) ?[]u8 {
    if (!ensureFileBuf()) return null;
    const buf = file_buf.?[0..FILE_BUF_CAP];
    const fd = libc.open(path) orelse return null;
    defer libc.close(fd);
    var total: usize = 0;
    while (total < FILE_BUF_CAP) {
        const chunk = @min(FILE_BUF_CAP - total, 65536);
        const n = libc.fread(fd, buf[total..][0..chunk]);
        if (n == 0) break;
        total += n;
    }
    return buf[0..total];
}

/// Load the image at `current_idx` into the cache (or look it up if
/// already there) and point `current_cache` at it. False on a read or
/// decode failure: then nothing is shown.
fn loadCurrentImage() bool {
    current_cache = -1;
    if (current_idx < 0 or @as(u32, @intCast(current_idx)) >= image_count) return false;
    const idx: u32 = @intCast(current_idx);
    const name = images[idx].name[0..images[idx].name_len];

    if (cacheFind(name)) |slot| {
        cacheBump(slot);
        current_cache = @intCast(slot);
        return true;
    }

    var path_buf: [320]u8 = undefined;
    if (dir_len + name.len >= path_buf.len) return false;
    @memcpy(path_buf[0..dir_len], dir_buf[0..dir_len]);
    @memcpy(path_buf[dir_len..][0..name.len], name);
    const full = path_buf[0 .. dir_len + name.len];

    const file_data = readEntireFile(full) orelse return false;
    // file_data lives in the reusable file_buf; img.pixels is stb's, kept
    // in the cache and freed with stbi_image_free on eviction.
    const img = image.decode(file_data, 4) catch return false;
    if (img.width == 0 or img.height == 0) {
        img.deinit();
        return false;
    }

    // Slot picked after the decode succeeded: a failure evicts nothing.
    const slot = cachePickSlot();
    @memcpy(cache[slot].name_buf[0..name.len], name);
    cache[slot].name_len = @intCast(name.len);
    cache[slot].pixels = img.pixels.ptr;
    cache[slot].w = @intCast(img.width);
    cache[slot].h = @intCast(img.height);
    cacheBump(slot);
    current_cache = @intCast(slot);
    return true;
}

fn currentEntry() ?*const CacheEntry {
    if (current_cache < 0) return null;
    const e = &cache[@intCast(current_cache)];
    return if (e.pixels != null) e else null;
}

fn step(delta: i32) void {
    if (image_count < 2) return;
    const n: i32 = @intCast(image_count);
    current_idx = @mod(current_idx + delta, n);
    _ = loadCurrentImage();
}

fn openFolder(path: []const u8) void {
    cacheClear();
    setDir(path);
    scanDir();
    _ = loadCurrentImage();
}

// --- Scaling --------------------------------------------------------------

const Size = struct { w: u32, h: u32 };

/// The size an sw x sh image is shown at inside max_w x max_h: whole,
/// in proportion, and never larger than it is.
fn fitSize(sw: u32, sh: u32, max_w: u32, max_h: u32) Size {
    if (sw == 0 or sh == 0 or max_w == 0 or max_h == 0) return .{ .w = 0, .h = 0 };
    if (sw <= max_w and sh <= max_h) return .{ .w = sw, .h = sh };
    // The tighter side decides; the other follows, at least one pixel.
    if (@as(u64, max_w) * sh <= @as(u64, max_h) * sw) {
        return .{ .w = max_w, .h = @max(1, @as(u32, @intCast(@as(u64, sh) * max_w / sw))) };
    }
    return .{ .w = @max(1, @as(u32, @intCast(@as(u64, sw) * max_h / sh))), .h = max_h };
}

/// Scale RGBA `src` (sw x sh) down to dw x dh over `bg`, each output pixel
/// the average of the source pixels it covers. Nearest-neighbour sampling
/// drops most of them and turns fine detail into noise.
fn scaleDown(dst: [*]u32, dw: u32, dh: u32, src: [*]const u8, sw: u32, sh: u32, bg: u32) void {
    const bg_r: u64 = (bg >> 16) & 0xFF;
    const bg_g: u64 = (bg >> 8) & 0xFF;
    const bg_b: u64 = bg & 0xFF;
    var dy: u32 = 0;
    while (dy < dh) : (dy += 1) {
        const y0: u32 = @intCast(@as(u64, dy) * sh / dh);
        const y1: u32 = @max(y0 + 1, @as(u32, @intCast(@as(u64, dy + 1) * sh / dh)));
        var dx: u32 = 0;
        while (dx < dw) : (dx += 1) {
            const x0: u32 = @intCast(@as(u64, dx) * sw / dw);
            const x1: u32 = @max(x0 + 1, @as(u32, @intCast(@as(u64, dx + 1) * sw / dw)));
            // Colour weighted by alpha, so a transparent pixel adds none.
            var r: u64 = 0;
            var g: u64 = 0;
            var b: u64 = 0;
            var a: u64 = 0;
            var sy = y0;
            while (sy < y1) : (sy += 1) {
                var p = src + (@as(usize, sy) * sw + x0) * 4;
                var sx = x0;
                while (sx < x1) : (sx += 1) {
                    const pa: u64 = p[3];
                    r += p[0] * pa;
                    g += p[1] * pa;
                    b += p[2] * pa;
                    a += pa;
                    p += 4;
                }
            }
            const full: u64 = @as(u64, (x1 - x0) * (y1 - y0)) * 255;
            const rest = full - a;
            const out_r: u32 = @intCast((r + bg_r * rest) / full);
            const out_g: u32 = @intCast((g + bg_g * rest) / full);
            const out_b: u32 = @intCast((b + bg_b * rest) / full);
            dst[@as(usize, dy) * dw + dx] = (out_r << 16) | (out_g << 8) | out_b;
        }
    }
}

/// `scaled` holding image `e` at w x h; false if there is no memory for it.
fn ensureScaled(e: *const CacheEntry, w: u32, h: u32) bool {
    const need: usize = @as(usize, w) * h;
    if (scaled == null or scaled_cap < need) {
        // A screenful covers every size the window can take.
        const scr = libc.getScreenSize();
        const cap = @max(need, @as(usize, scr.w) * scr.h);
        const mem = libc.malloc(cap * 4) orelse return false;
        scaled = @ptrCast(@alignCast(mem));
        scaled_cap = cap;
        scaled_stamp = 0;
    }
    if (scaled_stamp == e.stamp and scaled_w == w and scaled_h == h) return true;
    scaleDown(scaled.?, w, h, e.pixels.?, e.w, e.h, COLOR_STAGE);
    scaled_w = w;
    scaled_h = h;
    scaled_stamp = e.stamp;
    return true;
}

fn drawStage(canvas: *gfx.Canvas, area: app.Rect) void {
    canvas.fillRect(area.x, area.y, area.w, area.h, COLOR_STAGE);
    const e = currentEntry() orelse {
        const atlas = &fa.default_16;
        const msg = if (image_count == 0) "No images in this folder" else "This image can't be shown";
        const ty = area.y + (area.h -| atlas.line_height) / 2;
        fa.drawTextCentered(canvas, @intCast(area.x), @intCast(ty), area.w, msg, ui.palette.text_muted, atlas);
        return;
    };
    const size = fitSize(e.w, e.h, area.w, area.h);
    if (size.w == 0 or size.h == 0 or !ensureScaled(e, size.w, size.h)) return;
    const x0 = area.x + (area.w - size.w) / 2;
    const y0 = area.y + (area.h - size.h) / 2;
    const px = scaled.?;
    var y: u32 = 0;
    while (y < size.h and y0 + y < canvas.height) : (y += 1) {
        const row = px + @as(usize, y) * size.w;
        const out = canvas.fb + @as(usize, y0 + y) * canvas.width + x0;
        const n = @min(size.w, canvas.width -| x0);
        for (0..n) |x| out[x] = row[x];
    }
}

// --- Text -----------------------------------------------------------------

fn writeUint(buf: []u8, n: u32) usize {
    var tmp: [10]u8 = undefined;
    var len: usize = 0;
    var v = n;
    while (true) {
        tmp[len] = '0' + @as(u8, @intCast(v % 10));
        len += 1;
        v /= 10;
        if (v == 0) break;
    }
    const out = @min(len, buf.len);
    for (0..out) |i| buf[i] = tmp[len - 1 - i];
    return out;
}

fn append(buf: []u8, len: *usize, text: []const u8) void {
    const n = @min(text.len, buf.len - len.*);
    @memcpy(buf[len.*..][0..n], text[0..n]);
    len.* += n;
}

/// "1920 x 1080", and the scale it is shown at when that is not 100%.
fn infoText(buf: []u8, shown: Size) []const u8 {
    const e = currentEntry() orelse return "";
    var len: usize = 0;
    len += writeUint(buf[len..], e.w);
    append(buf, &len, " x ");
    len += writeUint(buf[len..], e.h);
    if (shown.w != 0 and shown.w < e.w) {
        append(buf, &len, "   ");
        len += writeUint(buf[len..], @max(1, shown.w * 100 / e.w));
        append(buf, &len, "%");
    }
    return buf[0..len];
}

/// "3 of 12".
fn counterText(buf: []u8) []const u8 {
    if (current_idx < 0) return "";
    var len: usize = 0;
    len += writeUint(buf[len..], @intCast(current_idx + 1));
    append(buf, &len, " of ");
    len += writeUint(buf[len..], image_count);
    return buf[0..len];
}

fn currentName() []const u8 {
    if (current_idx < 0) return "";
    const e = &images[@intCast(current_idx)];
    return e.name[0..e.name_len];
}

// --- The window -----------------------------------------------------------

fn openPicker(u: *const app.Ui) void {
    picker = ui.FolderPicker.init(u.w, u.h, dir_buf[0..dir_len]);
    picker_active = true;
}

fn pickerInput(u: *app.Ui) void {
    var action = picker.handleClick(u.mouse.x, u.mouse.y, u.down, u.was_down);
    const key = if (u.key != 0) u.key else u.special;
    if (action == .none and key != 0) action = picker.handleKey(key);
    switch (action) {
        .cancel => picker_active = false,
        .ok => {
            openFolder(picker.currentPath());
            picker_active = false;
        },
        .navigated, .none => {},
    }
    // It keeps its own hover and selection.
    u.repaint();
}

fn keys(u: *app.Ui) void {
    switch (u.special) {
        libc.Key.right, libc.Key.down, libc.Key.page_down => step(1),
        libc.Key.left, libc.Key.up, libc.Key.page_up => step(-1),
        else => switch (u.key) {
            0x1B => u.close(),
            'n', 'N', ' ' => step(1),
            'p', 'P', 0x08 => step(-1),
            'o', 'O' => openPicker(u),
            else => return,
        },
    }
    u.repaint();
}

pub fn frame(u: *app.Ui) void {
    // The picker is modal: the viewer under it is drawn but inert.
    if (picker_active) {
        u.blocked = true;
        if (!u.painting) pickerInput(u);
    } else if (!u.painting) {
        keys(u);
    }

    u.beginBar();
    if (u.iconButton(.back, image_count > 1)) step(-1);
    if (u.iconButton(.forward, image_count > 1)) step(1);
    u.alignNext(.right);
    if (u.button("Open Folder")) openPicker(u);
    u.alignNext(.center);
    u.heading(currentName());
    u.endBar();

    // The status bar comes before the area it describes: fit against what
    // the area will be.
    const stage_h = u.h -| (app.BAR_H + app.STATUS_H);
    const shown: Size = if (currentEntry()) |e| fitSize(e.w, e.h, u.w, stage_h) else .{ .w = 0, .h = 0 };
    var info_buf: [48]u8 = undefined;
    var counter_buf: [32]u8 = undefined;
    u.statusBar(infoText(&info_buf, shown), counterText(&counter_buf));

    const area = u.fill();
    if (u.painting) {
        drawStage(u.canvas, area);
        if (picker_active) {
            ui.drawScrim(u.canvas, u.w, u.h);
            picker.draw(u.canvas, ui.palette.window_bg);
        }
    }
}

// --- Entry --------------------------------------------------------------

export fn _start() linksection(".text.entry") callconv(.c) void {
    var path_buf: [256]u8 = undefined;
    const default_path = "/share/zigos_test.png";
    var path: []const u8 = default_path;
    if (libc.getArgc() >= 2) {
        const len = libc.getArgv(1, &path_buf);
        if (len != 0xFFFFFFFF and len > 0 and len < path_buf.len) path = path_buf[0..len];
    }

    var cwd_buf: [256]u8 = undefined;
    const cwd = libc.getCwd(&cwd_buf) orelse "/";
    const split = splitPath(path, cwd);
    setDir(split.dir);
    scanDir();
    if (split.name.len > 0) selectByName(split.name);
    _ = loadCurrentImage();

    // As large as the first image wants, within three quarters of the
    // screen: the desktop's own bars need the rest.
    const scr = libc.getScreenSize();
    const bars = app.BAR_H + app.STATUS_H;
    var width: u32 = MIN_W;
    var height: u32 = MIN_H;
    if (currentEntry()) |e| {
        const fit = fitSize(e.w, e.h, scr.w * 3 / 4, (scr.h * 3 / 4) -| bars);
        width = @max(MIN_W, fit.w);
        height = @max(MIN_H, fit.h + bars);
    }
    app.run(@This(), .{ .width = width, .height = height });
}
