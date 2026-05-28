// photo — image viewer with directory navigation + folder picker.
//
// Opens the image given on the command line (default
// /share/zigos_test.png), then scans the parent directory for other
// images (.png/.jpg/.jpeg/.bmp) and lets the user cycle through them
// with Prev/Next buttons or Left/Right arrows. The Open Folder button
// pops `ui.FolderPicker`, an overlay folder browser; picking a new
// folder rescans and shows the first image found there.

const libc = @import("libc");
const gfx = @import("graphics");
const ui = @import("ui");
const fa = @import("font_atlas");
const image = @import("image");

// --- Layout ---
const TOOLBAR_H: u32 = 36;
const FOOTER_H: u32 = 24;
const BTN_W: u32 = 88;
const BTN_H: u32 = 26;
const BTN_GAP: u32 = 8;

const COLOR_BG: u32 = 0x1A1A24;
const COLOR_TOOLBAR: u32 = 0x222230;
const COLOR_DIVIDER: u32 = 0x2A2A38;
const COLOR_TEXT: u32 = 0xE0E4F0;
const COLOR_TEXT_DIM: u32 = 0x808898;

const MAX_IMAGES: u32 = 256;
const FILE_BUF_CAP: usize = 16 * 1024 * 1024;
const CACHE_SIZE: u32 = 4;

// --- State ---
var alloc_w: u32 = 0;
var alloc_h: u32 = 0;
var vis_w: u32 = 0;
var vis_h: u32 = 0;

/// Directory we last scanned, trailing-slash terminated.
var dir_buf: [256]u8 = undefined;
var dir_len: u32 = 0;

/// Image filenames in `dir_buf`, sorted by readdir's order.
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
/// The render path reads pixels/w/h directly from cache[current_cache].
var current_cache: i32 = -1;

var prev_btn: ui.Button = .{ .x = 8, .y = 5, .w = BTN_W, .h = BTN_H, .label = "< Prev" };
var next_btn: ui.Button = .{ .x = 8 + BTN_W + BTN_GAP, .y = 5, .w = BTN_W, .h = BTN_H, .label = "Next >" };
var open_btn: ui.Button = .{ .x = 8 + (BTN_W + BTN_GAP) * 2, .y = 5, .w = BTN_W + 28, .h = BTN_H, .label = "Open Folder" };

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

/// Split `path` at the last '/' into (parent_dir_with_slash, filename).
/// Returns null filename if the path has no slash. Parent comes back as
/// "/" for top-level paths.
fn splitPath(path: []const u8) struct { dir: []const u8, name: []const u8 } {
    var last_slash: ?usize = null;
    var i: usize = 0;
    while (i < path.len) : (i += 1) {
        if (path[i] == '/') last_slash = i;
    }
    if (last_slash) |ls| {
        return .{ .dir = path[0 .. ls + 1], .name = path[ls + 1 ..] };
    }
    return .{ .dir = "/", .name = path };
}

// --- Directory scanning + image loading ----------------------------------

fn setDir(p: []const u8) void {
    if (p.len == 0 or p.len >= dir_buf.len) return;
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
}

/// Try to point current_idx at `name`. Falls back to 0 if not found.
fn selectByName(name: []const u8) void {
    var i: u32 = 0;
    while (i < image_count) : (i += 1) {
        const en = images[i].name[0..images[i].name_len];
        if (en.len == name.len) {
            var same = true;
            for (en, name) |a, b| if (a != b) {
                same = false;
                break;
            };
            if (same) {
                current_idx = @intCast(i);
                return;
            }
        }
    }
    current_idx = if (image_count > 0) 0 else -1;
}

fn nameEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| if (x != y) return false;
    return true;
}

/// Find a cache slot whose name matches `name`; null on miss.
fn cacheFind(name: []const u8) ?u32 {
    var i: u32 = 0;
    while (i < CACHE_SIZE) : (i += 1) {
        if (cache[i].stamp == 0) continue;
        const cn = cache[i].name_buf[0..cache[i].name_len];
        if (nameEql(cn, name)) return i;
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
    // Evict — free the pixels we're about to overwrite.
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

/// Ensure the FILE_BUF_CAP scratch buffer exists. Allocated once and
/// never freed — perpetual ownership is the point (avoid heap churn).
fn ensureFileBuf() bool {
    if (file_buf != null) return true;
    file_buf = libc.malloc(FILE_BUF_CAP);
    return file_buf != null;
}

fn readEntireFile(path: []const u8) ?[]u8 {
    if (!ensureFileBuf()) return null;
    const buf_ptr = file_buf.?;
    const buf = buf_ptr[0..FILE_BUF_CAP];
    const fd = libc.open(path) orelse return null;
    defer libc.close(fd);
    var total: usize = 0;
    while (total < FILE_BUF_CAP) {
        const remaining = FILE_BUF_CAP - total;
        const chunk = if (remaining > 65536) 65536 else remaining;
        const n = libc.fread(fd, buf[total..][0..chunk]);
        if (n == 0) break;
        total += n;
    }
    return buf[0..total];
}

/// Load the image at `current_idx` into the cache (or look it up if
/// already there). Updates `current_cache` so the render path knows
/// which slot has the pixels. Returns false on read/decode failure;
/// the displayed image stays whatever was previously there.
fn loadCurrentImage() bool {
    if (current_idx < 0 or @as(u32, @intCast(current_idx)) >= image_count) {
        current_cache = -1;
        return false;
    }
    const idx: u32 = @intCast(current_idx);
    const name = images[idx].name[0..images[idx].name_len];

    // Cache hit: just bump the stamp and update current_cache.
    if (cacheFind(name)) |slot| {
        cacheBump(slot);
        current_cache = @intCast(slot);
        return true;
    }

    // Cache miss: decode and insert. Pre-evict the chosen slot so we
    // don't OOM by holding two N-MB allocations in flight.
    var path_buf: [320]u8 = undefined;
    if (dir_len + name.len >= path_buf.len) return false;
    @memcpy(path_buf[0..dir_len], dir_buf[0..dir_len]);
    @memcpy(path_buf[dir_len..][0..name.len], name);
    const full = path_buf[0 .. dir_len + name.len];

    const file_data = readEntireFile(full) orelse return false;
    const img = image.decode(file_data, 4) catch return false;
    // file_data lives in the reusable file_buf — no free here. img.pixels
    // is the stb-allocated buffer; cache stores the raw pointer + dims and
    // frees via image.raw.stbi_image_free on eviction.
    if (img.width == 0 or img.height == 0) {
        img.deinit();
        return false;
    }

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

/// Free every cache entry. Called on shutdown; not on close/reload
/// (the whole point of the cache is to outlive individual loads).
fn freeAllCaches() void {
    var i: u32 = 0;
    while (i < CACHE_SIZE) : (i += 1) {
        if (cache[i].pixels) |p| {
            image.raw.stbi_image_free(p);
            cache[i].pixels = null;
        }
        cache[i].stamp = 0;
    }
}

// --- Rendering ----------------------------------------------------------

fn render(canvas: *gfx.Canvas) void {
    // Clear background.
    canvas.fillRect(0, 0, vis_w, vis_h, COLOR_BG);

    // Toolbar strip.
    canvas.fillRect(0, 0, vis_w, TOOLBAR_H, COLOR_TOOLBAR);
    canvas.fillRect(0, TOOLBAR_H - 1, vis_w, 1, COLOR_DIVIDER);

    // Buttons enabled/disabled based on whether there are images to nav.
    prev_btn.enabled = image_count > 1;
    next_btn.enabled = image_count > 1;
    prev_btn.drawStyled(canvas, .default, COLOR_TOOLBAR);
    next_btn.drawStyled(canvas, .default, COLOR_TOOLBAR);
    open_btn.drawStyled(canvas, .default, COLOR_TOOLBAR);

    // Image area — between toolbar and footer.
    const img_area_y = TOOLBAR_H;
    const img_area_h = vis_h -| TOOLBAR_H -| FOOTER_H;

    if (current_cache >= 0 and cache[@intCast(current_cache)].pixels != null) {
        const slot: u32 = @intCast(current_cache);
        const e = &cache[slot];
        const px = e.pixels.?;
        // Fit image into available area while preserving aspect ratio.
        // Nearest-neighbor scale — fast and good enough for a viewer.
        const scale_n = computeScale(e.w, e.h, vis_w, img_area_h);
        const draw_w = (e.w * scale_n.num) / scale_n.den;
        const draw_h = (e.h * scale_n.num) / scale_n.den;
        const draw_x = (vis_w -| draw_w) / 2;
        const draw_y = img_area_y + (img_area_h -| draw_h) / 2;
        blitScaled(canvas, px, e.w, e.h, draw_x, draw_y, draw_w, draw_h);
    } else {
        // No image loaded — show a hint.
        const msg = "No image loaded — use Open Folder to browse";
        const atlas = fa.getDefault16();
        const ty = img_area_y + (img_area_h -| atlas.line_height) / 2;
        fa.drawTextCentered(canvas, 0, @intCast(ty), vis_w, msg, COLOR_TEXT_DIM, atlas);
    }

    // Footer with filename + counter.
    const footer_y = vis_h -| FOOTER_H;
    canvas.fillRect(0, footer_y, vis_w, FOOTER_H, COLOR_TOOLBAR);
    canvas.fillRect(0, footer_y, vis_w, 1, COLOR_DIVIDER);
    if (current_idx >= 0) {
        const idx: u32 = @intCast(current_idx);
        const name = images[idx].name[0..images[idx].name_len];
        canvas.drawText16Fg(8, footer_y + (FOOTER_H -| gfx.Canvas.CH16) / 2, name, COLOR_TEXT);
        // "i of N" counter on the right.
        var counter_buf: [32]u8 = undefined;
        const counter = formatCounter(&counter_buf, idx + 1, image_count);
        const cw: u32 = @intCast(counter.len * 9);
        const cx = vis_w -| cw -| 8;
        canvas.drawText16Fg(cx, footer_y + (FOOTER_H -| gfx.Canvas.CH16) / 2, counter, COLOR_TEXT_DIM);
    }

    // Folder picker overlay (on top of everything else).
    if (picker_active) picker.draw(canvas, COLOR_BG);
}

const Ratio = struct { num: u32, den: u32 };

fn computeScale(src_w: u32, src_h: u32, max_w: u32, max_h: u32) Ratio {
    if (src_w == 0 or src_h == 0 or max_w == 0 or max_h == 0) return .{ .num = 1, .den = 1 };
    // Fit-to-bounds factor expressed as a ratio so we don't pull in FP.
    // We pick the smaller of (max_w/src_w) and (max_h/src_h) and represent
    // it as fixed-point num/256.
    const fx = (max_w * 256) / src_w;
    const fy = (max_h * 256) / src_h;
    const f = @min(fx, fy);
    if (f >= 256) return .{ .num = 1, .den = 1 }; // never upscale past 1:1
    return .{ .num = f, .den = 256 };
}

fn blitScaled(canvas: *gfx.Canvas, src: [*]u8, sw: u32, sh: u32, dx: u32, dy: u32, dw: u32, dh: u32) void {
    if (dw == 0 or dh == 0) return;
    const stride = canvas.width;
    var y: u32 = 0;
    while (y < dh) : (y += 1) {
        const cy = dy + y;
        if (cy >= canvas.height) break;
        const sy: u32 = (y * sh) / dh;
        const src_row_base: usize = @as(usize, sy) * sw * 4;
        const dst_row_base: usize = @as(usize, cy) * stride;
        var x: u32 = 0;
        while (x < dw) : (x += 1) {
            const cx = dx + x;
            if (cx >= canvas.width) break;
            const sx: u32 = (x * sw) / dw;
            const sidx = src_row_base + @as(usize, sx) * 4;
            const r: u32 = src[sidx + 0];
            const g: u32 = src[sidx + 1];
            const b: u32 = src[sidx + 2];
            canvas.fb[dst_row_base + cx] = (r << 16) | (g << 8) | b;
        }
    }
}

fn formatCounter(buf: []u8, i: u32, n: u32) []const u8 {
    var len: usize = 0;
    len += writeUint(buf[len..], i);
    const sep = " of ";
    if (len + sep.len < buf.len) {
        @memcpy(buf[len..][0..sep.len], sep);
        len += sep.len;
    }
    len += writeUint(buf[len..], n);
    return buf[0..len];
}

fn writeUint(buf: []u8, n: u32) usize {
    if (n == 0) {
        if (buf.len == 0) return 0;
        buf[0] = '0';
        return 1;
    }
    var tmp: [10]u8 = undefined;
    var ti: usize = 0;
    var v = n;
    while (v > 0) {
        tmp[ti] = '0' + @as(u8, @intCast(v % 10));
        ti += 1;
        v /= 10;
    }
    var i: usize = 0;
    while (ti > 0 and i < buf.len) {
        ti -= 1;
        buf[i] = tmp[ti];
        i += 1;
    }
    return i;
}

// --- Layout ---

fn computeLayout(w: u32, h: u32) void {
    vis_w = w;
    vis_h = h;
}

// --- Entry --------------------------------------------------------------

export fn _start() linksection(".text.entry") callconv(.c) void {
    // Resolve initial path from argv[1] or default.
    var path_buf: [256]u8 = undefined;
    const default_path = "/share/zigos_test.png";
    const path: []const u8 = blk: {
        const argc = libc.getArgc();
        if (argc >= 2) {
            const len = libc.getArgv(1, &path_buf);
            if (len != 0xFFFFFFFF and len > 0 and len < path_buf.len) {
                break :blk path_buf[0..len];
            }
        }
        @memcpy(path_buf[0..default_path.len], default_path);
        break :blk path_buf[0..default_path.len];
    };

    const split = splitPath(path);
    setDir(split.dir);
    scanDir();
    if (split.name.len > 0) selectByName(split.name);

    // Window sizing — start at the larger of the image's natural size
    // and a comfortable minimum.
    _ = loadCurrentImage(); // first try, may fail silently
    const scr = libc.getScreenSize();
    const min_w: u32 = 640;
    const min_h: u32 = 480;
    var init_img_w: u32 = 0;
    var init_img_h: u32 = 0;
    if (current_cache >= 0) {
        const c0 = &cache[@as(u32, @intCast(current_cache))];
        init_img_w = c0.w;
        init_img_h = c0.h;
    }
    var init_w: u32 = if (init_img_w > min_w) init_img_w else min_w;
    var init_h: u32 = if (init_img_h + TOOLBAR_H + FOOTER_H > min_h) init_img_h + TOOLBAR_H + FOOTER_H else min_h;
    if (init_w > scr.w) init_w = scr.w;
    if (init_h > scr.h) init_h = scr.h;
    alloc_w = @min(scr.w, init_w);
    alloc_h = @min(scr.h, init_h);

    const win = libc.createWindowEx(alloc_w, alloc_h, init_w, init_h) orelse libc.exit();
    alloc_w = win.alloc_w;
    alloc_h = win.alloc_h;
    var canvas = gfx.Canvas.init(win.fb, alloc_w, alloc_h);
    _ = libc.getWindowAlloc(); // opt this window into F10 grow-on-maximize (re-fetched in .resize)
    fa.ensureLoaded();
    computeLayout(init_w, init_h);

    var needs_redraw: bool = true;
    var prev_left: bool = false;
    var cur_mx: i32 = 0;
    var cur_my: i32 = 0;
    var cur_btns: u32 = 0;

    while (true) {
        while (libc.pollEvent()) |ev| {
            switch (ev.kindOf()) {
                .close_request => {
                    freeAllCaches();
                    libc.destroyWindow();
                    libc.exit();
                },
                .key_char => {
                    const ch: u8 = @truncate(ev.a);
                    if (picker_active) {
                        switch (picker.handleKey(ch)) {
                            .cancel => {
                                picker_active = false;
                                needs_redraw = true;
                            },
                            .ok => {
                                setDir(picker.currentPath());
                                scanDir();
                                _ = loadCurrentImage();
                                picker_active = false;
                                needs_redraw = true;
                            },
                            .navigated => needs_redraw = true,
                            .none => {},
                        }
                    } else switch (ch) {
                        0x1B => {
                            freeAllCaches();
                            libc.destroyWindow();
                            libc.exit();
                        },
                        0x91, 'n', 'N', ' ' => { // right arrow or Next
                            if (image_count > 1) {
                                current_idx = @mod(current_idx + 1, @as(i32, @intCast(image_count)));
                                _ = loadCurrentImage();
                                needs_redraw = true;
                            }
                        },
                        0x92, 'p', 'P' => { // left arrow or Prev
                            if (image_count > 1) {
                                current_idx = @mod(current_idx - 1 + @as(i32, @intCast(image_count)), @as(i32, @intCast(image_count)));
                                _ = loadCurrentImage();
                                needs_redraw = true;
                            }
                        },
                        'o', 'O' => {
                            picker = ui.FolderPicker.init(vis_w, vis_h, dir_buf[0..dir_len]);
                            picker_active = true;
                            needs_redraw = true;
                        },
                        else => {},
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

        const left = (cur_btns & 1) != 0;

        if (picker_active) {
            const action = picker.handleClick(cur_mx, cur_my, left, prev_left);
            switch (action) {
                .cancel => {
                    picker_active = false;
                    needs_redraw = true;
                },
                .ok => {
                    setDir(picker.currentPath());
                    scanDir();
                    _ = loadCurrentImage();
                    picker_active = false;
                    needs_redraw = true;
                },
                .navigated => needs_redraw = true,
                .none => {
                    if (left != prev_left) needs_redraw = true;
                },
            }
        } else {
            if (prev_btn.update(cur_mx, cur_my, left, prev_left) and image_count > 1) {
                current_idx = @mod(current_idx - 1 + @as(i32, @intCast(image_count)), @as(i32, @intCast(image_count)));
                _ = loadCurrentImage();
                needs_redraw = true;
            }
            if (next_btn.update(cur_mx, cur_my, left, prev_left) and image_count > 1) {
                current_idx = @mod(current_idx + 1, @as(i32, @intCast(image_count)));
                _ = loadCurrentImage();
                needs_redraw = true;
            }
            if (open_btn.update(cur_mx, cur_my, left, prev_left)) {
                picker = ui.FolderPicker.init(vis_w, vis_h, dir_buf[0..dir_len]);
                picker_active = true;
                needs_redraw = true;
            }
            if (left != prev_left) needs_redraw = true; // refresh hover states
        }

        prev_left = left;

        if (needs_redraw) {
            render(&canvas);
            libc.present();
            needs_redraw = false;
        }
        libc.sleep(16);
    }
}
