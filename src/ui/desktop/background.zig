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
const Mutex = @import("../../proc/spinlock.zig").Mutex;

// Serializes wallpaper change (settings → sysSetWallpaper) against the
// render path (desktop task → renderScene → background.render). Without
// it, settings.clearWallpaper can free the vmalloc backing while desktop
// is mid-blit — the now-correct cross-CPU TLB shootdown in vmalloc.free
// turns that latent UAF into an immediate kernel #PF (was masked before
// 2026-05-25 by stale local TLB entries on the renderer's CPU).
// Mutex (sleepable), not SpinLock: render blits 6+ MB at 1920×1080,
// which is too long to hold with interrupts off.
var wp_lock: Mutex = .{};

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
    wp_lock.acquire();
    defer wp_lock.release();
    clearWallpaperLocked();
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
    wp_lock.acquire();
    defer wp_lock.release();
    clearWallpaperLocked();
}

fn clearWallpaperLocked() void {
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
/// Caller must hold `wp_lock` for the duration of the write to keep the
/// returned slice from being unmapped underneath them.
pub fn wallpaperSlice() ?[]u32 {
    const p = wp_pixels orelse return null;
    return p[0 .. @as(usize, wp_w) * @as(usize, wp_h)];
}

pub fn lockForWrite() void {
    wp_lock.acquire();
}

pub fn unlockAfterWrite() void {
    wp_lock.release();
}

pub fn hasWallpaper() bool {
    return wp_pixels != null;
}

pub fn wallpaperDims() struct { w: u32, h: u32 } {
    return .{ .w = wp_w, .h = wp_h };
}

// --- Render --------------------------------------------------------------

pub fn render() void {
    renderRect(0, 0, gfx.screen_w, gfx.screen_h);
}

/// Restore wallpaper/gradient ONLY inside the given screen-space rect —
/// the tight drag path's background pass. Pixel-identical to a full
/// render() restricted to the rect (gradient rows keyed by absolute row;
/// the wallpaper sub-blit uses the same centering math). Holds wp_lock
/// for the whole paint — without it, sysSetWallpaper can vmalloc.free the
/// buffer mid-blit and the cross-CPU TLB shootdown unmaps our source.
pub fn renderRect(rx: u32, ry: u32, rw: u32, rh: u32) void {
    if (rx >= gfx.screen_w or ry >= gfx.screen_h) return;
    const rx1 = @min(rx + rw, gfx.screen_w);
    const ry1 = @min(ry + rh, gfx.screen_h);
    if (rx1 <= rx or ry1 <= ry) return;

    wp_lock.acquire();
    defer wp_lock.release();
    if (wp_pixels) |pixels| {
        renderWallpaperRect(pixels, rx, ry, rx1, ry1);
        return;
    }
    renderGradientRect(rx, ry, rx1, ry1);
}

fn renderGradientRect(rx: u32, ry: u32, rx1: u32, ry1: u32) void {
    var row: u32 = ry;
    while (row < ry1) : (row += 1) {
        const color = lerpColor(bgTop(), bgBot(), row, gfx.screen_h);
        gfx.fillRect(@intCast(rx), @intCast(row), rx1 - rx, 1, color);
    }
}

fn renderWallpaperRect(src: [*]u32, rx: u32, ry: u32, rx1: u32, ry1: u32) void {
    const sw = gfx.target_w;
    const sh = gfx.target_h;
    const w = wp_w;
    const h = wp_h;

    // Letterbox: if image smaller than screen, paint gradient first so the
    // edges don't stay stale from a prior frame. If equal/bigger, the blit
    // covers the requested rect so the gradient pre-pass is redundant.
    if (w < sw or h < sh) renderGradientRect(rx, ry, rx1, ry1);

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

    // Intersect the image's destination region with the requested rect.
    const img_x0: u32 = @intCast(dx_clipped);
    const img_y0: u32 = @intCast(dy_clipped);
    const img_x1: u32 = img_x0 + @as(u32, @intCast(blit_w_i));
    const img_y1: u32 = img_y0 + @as(u32, @intCast(blit_h_i));
    const cx0 = @max(rx, img_x0);
    const cy0 = @max(ry, img_y0);
    const cx1 = @min(rx1, img_x1);
    const cy1 = @min(ry1, img_y1);
    if (cx1 <= cx0 or cy1 <= cy0) return;

    const sx0: usize = @as(usize, @intCast(src_x0)) + (cx0 - img_x0);
    const sy0: usize = @as(usize, @intCast(src_y0)) + (cy0 - img_y0);
    const count: u32 = cx1 - cx0;

    // SSE2 rows — the target pointer is volatile, so a scalar loop here
    // compiles to 2M un-vectorizable stores for a full 1080p restore.
    var row: usize = 0;
    while (row < cy1 - cy0) : (row += 1) {
        const dst_off = (@as(usize, cy0) + row) * gfx.target_w + cx0;
        const src_off = (sy0 + row) * @as(usize, w) + sx0;
        gfx.copyRowIntoTarget(dst_off, src + src_off, count);
    }
}
