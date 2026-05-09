// Boot splash — fade-in "ZigOS / x86 operating system / v0.1" with a
// centre-sweeping accent line, brief hold, fade-out, then a screen
// clear before the desktop main loop takes over. Runs once from
// `desktop.run()` after virtio-gpu (or BGA) is up but before any
// window chrome is drawn.
//
// Visual language matches the UEFI boot manager so booting feels
// continuous from firmware → desktop. Colors live as private consts
// here; if you re-skin one, mirror the change in uefi/menu.zig.

const gfx = @import("../gfx.zig");
const sound = @import("../../driver/sound.zig");

const SPLASH_BG_TOP: u32 = 0x050811;
const SPLASH_BG_BOT: u32 = 0x0E1525;
const SPLASH_LOGO: u32 = 0xE8EEFA;
const SPLASH_LOGO_SHADOW: u32 = 0x1E2E60;
const SPLASH_SUBTITLE: u32 = 0x6A788C;
const SPLASH_VERSION: u32 = 0x50A8FF;
const SPLASH_ACCENT: u32 = 0x50A8FF;
const SPLASH_DOT_DIM: u32 = 0x2A3850;

inline fn lerpColor(top: u32, bot: u32, num: u32, den: u32) u32 {
    const tr: i32 = @intCast((top >> 16) & 0xFF);
    const tg: i32 = @intCast((top >> 8) & 0xFF);
    const tb: i32 = @intCast(top & 0xFF);
    const br: i32 = @intCast((bot >> 16) & 0xFF);
    const bg: i32 = @intCast((bot >> 8) & 0xFF);
    const bb: i32 = @intCast(bot & 0xFF);
    const n: i32 = @intCast(num);
    const d: i32 = @intCast(den);
    const r: u32 = @intCast(tr + @divTrunc((br - tr) * n, d));
    const g: u32 = @intCast(tg + @divTrunc((bg - tg) * n, d));
    const b: u32 = @intCast(tb + @divTrunc((bb - tb) * n, d));
    return (r << 16) | (g << 8) | b;
}

fn busyWaitMs(ms: u32) void {
    // Rough spin delay — ~1 ms per 200 000 iterations on WHPX/pentium4.
    // Fine for the splash, which doesn't depend on precise timing.
    var i: u32 = 0;
    const iters = ms * 200000;
    while (i < iters) : (i += 1) {
        asm volatile ("pause");
    }
}

fn paintBg() void {
    const sw = gfx.screen_w;
    const sh = gfx.screen_h;
    const step: u32 = 4;
    var y: u32 = 0;
    while (y < sh) : (y += step) {
        const c = lerpColor(SPLASH_BG_TOP, SPLASH_BG_BOT, y, sh);
        gfx.fillRect(0, @intCast(y), sw, step, c);
    }
}

/// Run the splash animation start-to-finish. `has_backbuf` mirrors the
/// caller's compositor decision: when true we blit the back buffer to
/// the scanout each frame, otherwise we drew directly to it. Caller is
/// responsible for ensuring virtio-gpu / BGA is initialised first.
pub fn show(has_backbuf: bool) void {
    const sw = gfx.screen_w;
    const sh = gfx.screen_h;
    const vgpu = @import("../../driver/virtio_gpu.zig");

    const logo = "ZigOS";
    const logo_w: u32 = @as(u32, logo.len) * gfx.FONT32_ADV;
    const logo_x: i32 = @intCast((sw - logo_w) / 2);
    const logo_y: i32 = @intCast(sh / 2 - 60);

    const sub = "x86 operating system";
    const sub_w: u32 = @as(u32, sub.len) * 9;
    const sub_x: i32 = @intCast((sw - sub_w) / 2);
    const sub_y: i32 = logo_y + @as(i32, @intCast(gfx.FONT32_H)) + 20;

    const ver = "v0.1";
    const ver_w: u32 = @as(u32, ver.len) * 9;
    const ver_x: i32 = @intCast((sw - ver_w) / 2);
    const ver_y: i32 = sub_y + 28;

    const accent_max_w: u32 = 280;
    const accent_h: u32 = 2;
    const accent_y: i32 = sub_y - 12;
    const accent_cx: i32 = @intCast(sw / 2);

    // Fade-in: 36 frames × 25 ms ≈ 900 ms.
    // Element timeline (frame ranges):
    //   logo + shadow:   0..18  (full at 18)
    //   accent sweep:   10..26  (sweeps left & right from centre)
    //   subtitle:       16..30
    //   version:        22..34
    //   hold full:      34..36 + extra busyWaitMs(250) post-loop
    const FRAMES: u32 = 36;
    var frame: u32 = 0;
    while (frame < FRAMES) : (frame += 1) {
        paintBg();

        // Subtle dot grid background (very dim, centred around logo).
        var dy: u32 = 0;
        while (dy < 6) : (dy += 1) {
            var dx: u32 = 0;
            while (dx < 12) : (dx += 1) {
                const px: i32 = accent_cx - 11 * 24 / 2 + @as(i32, @intCast(dx * 24));
                const py: i32 = logo_y - 80 + @as(i32, @intCast(dy * 24));
                gfx.fillRect(px, py, 2, 2, SPLASH_DOT_DIM);
            }
        }

        // Logo with drop shadow — fades in by brightness lerp.
        const logo_t: u32 = if (frame > 18) 16 else frame * 16 / 18;
        const logo_color = lerpColor(SPLASH_BG_BOT, SPLASH_LOGO, logo_t, 16);
        const shadow_color = lerpColor(SPLASH_BG_BOT, SPLASH_LOGO_SHADOW, logo_t, 16);
        gfx.drawString32(logo_x + 3, logo_y + 3, logo, shadow_color, 0);
        gfx.drawString32(logo_x, logo_y, logo, logo_color, 0);

        // Accent line — sweeps outward from centre over frames 10..26.
        if (frame >= 10) {
            const sweep_t: u32 = if (frame > 26) 16 else (frame - 10) * 16 / 16;
            const half_w: u32 = accent_max_w * sweep_t / 32;
            if (half_w > 0) {
                gfx.fillRect(accent_cx - @as(i32, @intCast(half_w)), accent_y, half_w * 2, accent_h, SPLASH_ACCENT);
            }
        }

        if (frame >= 16) {
            const sub_t: u32 = if (frame > 30) 16 else (frame - 16) * 16 / 14;
            const sub_color = lerpColor(SPLASH_BG_BOT, SPLASH_SUBTITLE, sub_t, 16);
            gfx.drawString(sub_x, sub_y, sub, sub_color, 0);
        }

        if (frame >= 22) {
            const ver_t: u32 = if (frame > 34) 16 else (frame - 22) * 16 / 12;
            const ver_color = lerpColor(SPLASH_BG_BOT, SPLASH_VERSION, ver_t, 16);
            gfx.drawString(ver_x, ver_y, ver, ver_color, 0);
        }

        if (has_backbuf) gfx.blitToScreen();
        if (vgpu.active) vgpu.flush();
        busyWaitMs(25);

        if (frame == 14) sound.startup();
    }

    busyWaitMs(250);

    // Fade-out: 12 frames × 20 ms ≈ 240 ms. Crossfade to bg.
    var fade: u32 = 0;
    while (fade < 12) : (fade += 1) {
        paintBg();
        const out_t: u32 = 16 - fade * 16 / 12;
        const logo_color = lerpColor(SPLASH_BG_BOT, SPLASH_LOGO, out_t, 16);
        const shadow_color = lerpColor(SPLASH_BG_BOT, SPLASH_LOGO_SHADOW, out_t, 16);
        gfx.drawString32(logo_x + 3, logo_y + 3, logo, shadow_color, 0);
        gfx.drawString32(logo_x, logo_y, logo, logo_color, 0);
        const sub_color = lerpColor(SPLASH_BG_BOT, SPLASH_SUBTITLE, out_t, 16);
        gfx.drawString(sub_x, sub_y, sub, sub_color, 0);
        const ver_color = lerpColor(SPLASH_BG_BOT, SPLASH_VERSION, out_t, 16);
        gfx.drawString(ver_x, ver_y, ver, ver_color, 0);
        const accent_color = lerpColor(SPLASH_BG_BOT, SPLASH_ACCENT, out_t, 16);
        gfx.fillRect(accent_cx - @as(i32, @intCast(accent_max_w)), accent_y, accent_max_w * 2, accent_h, accent_color);

        if (has_backbuf) gfx.blitToScreen();
        if (vgpu.active) vgpu.flush();
        busyWaitMs(20);
    }

    // Clear before desktop chrome paints over.
    gfx.fillRect(0, 0, sw, sh, 0x000000);
    if (has_backbuf) gfx.blitToScreen();
    if (vgpu.active) vgpu.flush();
}
