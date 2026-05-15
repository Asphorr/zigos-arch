// Desktop wallpaper — vertical gradient between two color presets read
// from `desktop.conf.bg`. Painted once per scene under everything else
// (windows, dock, menubar). Trivially fast at 1920×1080 because each
// row is one fillRect call into the fast SSE2 path.
//
// If a userspace process pushes pixel data via sysSetWallpaper (#98),
// the gradient is replaced with that image. Mismatched dimensions are
// centered against the gradient, giving a "letterbox" fallback rather
// than scaling. Settings.elf flags the mismatch in its UI so the user
// knows.

const gfx = @import("../gfx.zig");
const conf = @import("config.zig");
const vmalloc = @import("../../mm/vmalloc.zig");
const debug = @import("../../debug/debug.zig");

const bg_presets = [4][2]u32{
    .{ 0x1B2838, 0x2D5F8A }, // blue
    .{ 0x2B1B38, 0x5F2D8A }, // purple
    .{ 0x1B3828, 0x2D8A5F }, // green
    .{ 0x381B1B, 0x8A2D2D }, // red
};

pub fn bgTop() u32 {
    return bg_presets[conf.bg][0];
}

pub fn bgBot() u32 {
    return bg_presets[conf.bg][1];
}

pub fn lerpColor(top: u32, bot: u32, num: u32, den: u32) u32 {
    const tr: i32 = @intCast((top >> 16) & 0xFF);
    const tg: i32 = @intCast((top >> 8) & 0xFF);
    const tb: i32 = @intCast(top & 0xFF);
    const br: i32 = @intCast((bot >> 16) & 0xFF);
    const bg_: i32 = @intCast((bot >> 8) & 0xFF);
    const bb: i32 = @intCast(bot & 0xFF);
    const n: i32 = @intCast(num);
    const d: i32 = @intCast(den);
    const r: u32 = @intCast(tr + @divTrunc((br - tr) * n, d));
    const g: u32 = @intCast(tg + @divTrunc((bg_ - tg) * n, d));
    const b: u32 = @intCast(tb + @divTrunc((bb - tb) * n, d));
    return (r << 16) | (g << 8) | b;
}

// --- Wallpaper image state -----------------------------------------------

var wp_pixels: ?[*]u32 = null;
var wp_w: u32 = 0;
var wp_h: u32 = 0;

/// Replace the current wallpaper with a freshly-allocated buffer of the
/// given dimensions. Caller is responsible for filling `wp_pixels[0..w*h]`
/// after this returns true (typically via @memcpy from a user-space slice
/// in the syscall handler).
///
/// We free the previous buffer BEFORE the new alloc so peak memory stays
/// at one wallpaper, not two. The naive "alloc-then-free" version doubled
/// the contiguous-page demand on every change and was the most likely
/// failure mode at 8 MB / 2025 pages on a 128 MB QEMU. Downside: if the
/// new alloc fails, the old wallpaper is also gone — gradient takes over.
/// Acceptable since the failure path is rare and the user sees the gap.
pub fn allocateWallpaper(w: u32, h: u32) bool {
    if (w == 0 or h == 0 or w > 4096 or h > 4096) return false;

    const bytes: usize = @as(usize, w) * @as(usize, h) * 4;
    clearWallpaper();
    // vmalloc rather than heap.kvmalloc: a 6+ MB wallpaper needs 1500+
    // contiguous frames from PMM, which can't be served on a fragmented
    // heap. vmalloc returns a virtually-contiguous region backed by
    // individually-allocated frames, so the only requirement is that
    // PMM has enough total free pages — order doesn't matter. Wallpaper
    // bytes are CPU-read-only (no DMA), making vmalloc the right fit.
    const new_buf = vmalloc.alloc(bytes) orelse {
        debug.klog("[wallpaper] vmalloc({d} MB) failed — PMM exhausted?\n", .{
            bytes / (1024 * 1024),
        });
        return false;
    };
    wp_pixels = @ptrCast(@alignCast(new_buf));
    wp_w = w;
    wp_h = h;
    debug.klog("[wallpaper] installed {d}x{d}, {d} MB at 0x{X}\n", .{
        w, h, bytes / (1024 * 1024), @intFromPtr(new_buf),
    });
    return true;
}

/// Drop the wallpaper, falling back to gradient render. Idempotent.
pub fn clearWallpaper() void {
    if (wp_pixels) |p| {
        const old_buf: [*]u8 = @ptrCast(p);
        vmalloc.free(old_buf);
    }
    wp_pixels = null;
    wp_w = 0;
    wp_h = 0;
}

/// Direct write access for the syscall handler — copies user pixels into
/// the wallpaper buffer. Returns the slice if valid, null otherwise.
pub fn wallpaperSlice() ?[]u32 {
    const p = wp_pixels orelse return null;
    return p[0 .. @as(usize, wp_w) * @as(usize, wp_h)];
}

pub fn hasWallpaper() bool {
    return wp_pixels != null;
}

pub fn wallpaperDims() struct { w: u32, h: u32 } {
    return .{ .w = wp_w, .h = wp_h };
}

// --- Render --------------------------------------------------------------

pub fn render() void {
    if (wp_pixels) |pixels| {
        renderWallpaper(pixels);
        return;
    }
    renderGradient();
}

fn renderGradient() void {
    var row: u32 = 0;
    while (row < gfx.screen_h) : (row += 1) {
        const color = lerpColor(bgTop(), bgBot(), row, gfx.screen_h);
        gfx.fillRect(0, @intCast(row), gfx.screen_w, 1, color);
    }
}

fn renderWallpaper(src: [*]u32) void {
    const sw = gfx.target_w;
    const sh = gfx.target_h;
    const w = wp_w;
    const h = wp_h;

    // Letterbox: if image smaller than screen, paint gradient first so the
    // edges don't stay stale from a prior frame. If equal/bigger, the blit
    // covers the whole screen so the gradient pre-pass is redundant.
    if (w < sw or h < sh) renderGradient();

    // Centered top-left of the visible image region in screen coords.
    const off_x: i32 = @as(i32, @intCast(sw)) - @as(i32, @intCast(w));
    const off_y: i32 = @as(i32, @intCast(sh)) - @as(i32, @intCast(h));
    const dst_x0: i32 = @divTrunc(off_x, 2);
    const dst_y0: i32 = @divTrunc(off_y, 2);

    // Source-region clip: when image is bigger we crop centered.
    const src_x0: i32 = if (off_x < 0) @divTrunc(-off_x, 2) else 0;
    const src_y0: i32 = if (off_y < 0) @divTrunc(-off_y, 2) else 0;
    const dx_clipped: i32 = @max(dst_x0, 0);
    const dy_clipped: i32 = @max(dst_y0, 0);
    const blit_w_i: i32 = @min(@as(i32, @intCast(w)) - src_x0, @as(i32, @intCast(sw)) - dx_clipped);
    const blit_h_i: i32 = @min(@as(i32, @intCast(h)) - src_y0, @as(i32, @intCast(sh)) - dy_clipped);
    if (blit_w_i <= 0 or blit_h_i <= 0) return;

    const blit_w: usize = @intCast(blit_w_i);
    const blit_h: usize = @intCast(blit_h_i);
    const dx0: usize = @intCast(dx_clipped);
    const dy0: usize = @intCast(dy_clipped);
    const sx0: usize = @intCast(src_x0);
    const sy0: usize = @intCast(src_y0);

    var row: usize = 0;
    while (row < blit_h) : (row += 1) {
        const dst_off = (dy0 + row) * gfx.target_w + dx0;
        const src_off = (sy0 + row) * @as(usize, w) + sx0;
        const dst_ptr: [*]volatile u32 = gfx.target + dst_off;
        var col: usize = 0;
        while (col < blit_w) : (col += 1) {
            dst_ptr[col] = src[src_off + col];
        }
    }
}
