const io = @import("../io.zig");
const font = @import("font8x16.zig");
const font32 = @import("font16x32.zig");
const icons = @import("icons.zig");
const shapes = @import("shapes");

// Render target — back buffer or direct framebuffer
pub var target: [*]volatile u32 = undefined;
pub var target_w: u32 = 0;
pub var target_h: u32 = 0;

// Screen framebuffer (hardware MMIO or guest RAM)
pub var screen: [*]volatile u32 = undefined;
pub var screen_w: u32 = 0;
pub var screen_h: u32 = 0;

// Post-blit callback (virtio-gpu uses this for transfer+flush)
pub var post_blit_fn: ?*const fn () void = null;

pub fn setTarget(buf: [*]volatile u32, w: u32, h: u32) void {
    target = buf;
    target_w = w;
    target_h = h;
}

pub fn setScreen(fb: [*]volatile u32, w: u32, h: u32) void {
    screen = fb;
    screen_w = w;
    screen_h = h;
}

pub fn useFramebuffer() void {
    target = screen;
    target_w = screen_w;
    target_h = screen_h;
}

// --- Clipping helpers ---

inline fn clipRect(x: i32, y: i32, w: u32, h: u32) ?struct { x0: u32, y0: u32, x1: u32, y1: u32 } {
    const iw: i32 = @intCast(w);
    const ih: i32 = @intCast(h);
    const tw: i32 = @intCast(target_w);
    const th: i32 = @intCast(target_h);
    const x_end = x + iw;
    const y_end = y + ih;
    if (x_end <= 0 or y_end <= 0) return null;
    const x0: u32 = if (x < 0) 0 else @intCast(x);
    const y0: u32 = if (y < 0) 0 else @intCast(y);
    const x1: u32 = if (x_end > tw) target_w else @intCast(x_end);
    const y1: u32 = if (y_end > th) target_h else @intCast(y_end);
    if (x0 >= x1 or y0 >= y1) return null;
    return .{ .x0 = x0, .y0 = y0, .x1 = x1, .y1 = y1 };
}

// --- Drawing primitives (optimized) ---

pub fn putPixel(x: i32, y: i32, color: u32) void {
    if (x < 0 or y < 0) return;
    const ux: u32 = @intCast(x);
    const uy: u32 = @intCast(y);
    if (ux >= target_w or uy >= target_h) return;
    target[uy * target_w + ux] = color;
}

pub fn getPixel(x: i32, y: i32) u32 {
    if (x < 0 or y < 0) return 0;
    const ux: u32 = @intCast(x);
    const uy: u32 = @intCast(y);
    if (ux >= target_w or uy >= target_h) return 0;
    return target[uy * target_w + ux];
}

/// Fast filled rectangle — SSE2 for wide fills, rep stosd for narrow.
/// Cross-row fast path: when the visible region spans the full target width,
/// all rows are contiguous in memory and we issue a single SSE2 fill instead
/// of one per row. Big win for full-screen background fills (boot splash,
/// desktop bg, paint canvas wipe).
pub fn fillRect(x: i32, y: i32, w: u32, h: u32, color: u32) void {
    const c = clipRect(x, y, w, h) orelse return;
    const count = c.x1 - c.x0;

    if (count == target_w) {
        const total = count * (c.y1 - c.y0);
        const dest = @intFromPtr(target) + c.y0 * target_w * 4;
        fillSSE2(dest, color, total);
        return;
    }

    var row = c.y0;
    while (row < c.y1) : (row += 1) {
        const offset = row * target_w + c.x0;
        const dest = @intFromPtr(target) + offset * 4;
        if (count >= 4) {
            // fillSSE2's internal >=4 / scalar tail handles small counts too.
            fillSSE2(dest, color, count);
        } else {
            asm volatile ("cld; rep stosl"
                :
                : [dst] "{rdi}" (dest),
                  [val] "{eax}" (color),
                  [cnt] "{rcx}" (count),
                : .{ .rdi = true, .rcx = true, .memory = true }
            );
        }
    }
}

/// Alpha blend: src alpha in bits 24-31 (0xFF=opaque, 0x00=transparent).
pub fn blendPixel(dst: u32, src: u32) u32 {
    const alpha = (src >> 24) & 0xFF;
    if (alpha == 0xFF) return src & 0x00FFFFFF;
    if (alpha == 0) return dst;
    const inv = 255 - alpha;
    const r = (((src >> 16) & 0xFF) * alpha + ((dst >> 16) & 0xFF) * inv) / 255;
    const g = (((src >> 8) & 0xFF) * alpha + ((dst >> 8) & 0xFF) * inv) / 255;
    const b = ((src & 0xFF) * alpha + (dst & 0xFF) * inv) / 255;
    return (r << 16) | (g << 8) | b;
}

/// Alpha-blended filled rectangle. Fast-path to opaque fillRect when alpha=0xFF.
/// Uses SSE2 to blend 4 pixels at a time for large fills.
pub fn fillRectAlpha(x: i32, y: i32, w: u32, h: u32, color: u32) void {
    const alpha = (color >> 24) & 0xFF;
    if (alpha == 0xFF) { fillRect(x, y, w, h, color & 0x00FFFFFF); return; }
    if (alpha == 0) return;
    const c = clipRect(x, y, w, h) orelse return;
    const row_w = c.x1 - c.x0;

    // Prepare SSE2 constants for vectorized blend (4 pixels at a time)
    // src_lo = src color channels unpacked to 16-bit, pre-multiplied by alpha
    // inv_alpha = (255 - alpha) splatted to all 16-bit lanes
    const src_r: u16 = @intCast(((color >> 16) & 0xFF) * alpha);
    const src_g: u16 = @intCast(((color >> 8) & 0xFF) * alpha);
    const src_b: u16 = @intCast((color & 0xFF) * alpha);
    const inv: u16 = @intCast(255 - alpha);

    var row = c.y0;
    while (row < c.y1) : (row += 1) {
        var col = c.x0;
        const row_base = row * target_w;

        // SSE2 path: 4 pixels at a time
        while (col + 4 <= c.x1) : (col += 4) {
            const off = row_base + col;
            const p = target + off;
            // Read 4 dst pixels, blend, write back
            p[0] = blendPixelFast(p[0], src_r, src_g, src_b, inv);
            p[1] = blendPixelFast(p[1], src_r, src_g, src_b, inv);
            p[2] = blendPixelFast(p[2], src_r, src_g, src_b, inv);
            p[3] = blendPixelFast(p[3], src_r, src_g, src_b, inv);
        }

        // Remainder
        while (col < c.x1) : (col += 1) {
            const off = row_base + col;
            target[off] = blendPixelFast(target[off], src_r, src_g, src_b, inv);
        }
        _ = row_w;
    }
}

/// Fast alpha blend with pre-computed src*alpha and inv_alpha
inline fn blendPixelFast(dst: u32, src_r: u16, src_g: u16, src_b: u16, inv: u16) u32 {
    const dr: u16 = @intCast((dst >> 16) & 0xFF);
    const dg: u16 = @intCast((dst >> 8) & 0xFF);
    const db: u16 = @intCast(dst & 0xFF);
    const r: u32 = (src_r + dr * inv) / 255;
    const g: u32 = (src_g + dg * inv) / 255;
    const b: u32 = (src_b + db * inv) / 255;
    return (r << 16) | (g << 8) | b;
}

/// Fill with SSE2: splat color to XMM, 128-bit unaligned stores.
fn fillSSE2(dest: usize, color: u32, count: u32) void {
    // Splat color into XMM0
    asm volatile (
        \\ movd %[color], %%xmm0
        \\ pshufd $0, %%xmm0, %%xmm0
        :
        : [color] "r" (color),
        : .{ .xmm0 = true }
    );
    var ptr = dest;
    var rem = count;
    // 16 pixels (64 bytes) per unrolled iteration
    while (rem >= 16) {
        asm volatile (
            \\ movdqu %%xmm0, 0(%[p])
            \\ movdqu %%xmm0, 16(%[p])
            \\ movdqu %%xmm0, 32(%[p])
            \\ movdqu %%xmm0, 48(%[p])
            :
            : [p] "r" (ptr),
            : .{ .memory = true }
        );
        ptr += 64;
        rem -= 16;
    }
    while (rem >= 4) {
        asm volatile (
            \\ movdqu %%xmm0, (%[p])
            :
            : [p] "r" (ptr),
            : .{ .memory = true }
        );
        ptr += 16;
        rem -= 4;
    }
    while (rem > 0) : (rem -= 1) {
        @as(*volatile u32, @ptrFromInt(ptr)).* = color;
        ptr += 4;
    }
}

pub fn drawRect(x: i32, y: i32, w: u32, h: u32, color: u32) void {
    drawHLine(x, y, w, color);
    drawHLine(x, y + @as(i32, @intCast(h)) - 1, w, color);
    drawVLine(x, y, h, color);
    drawVLine(x + @as(i32, @intCast(w)) - 1, y, h, color);
}

pub fn drawHLine(x: i32, y: i32, w: u32, color: u32) void {
    if (y < 0 or y >= @as(i32, @intCast(target_h))) return;
    const uy: u32 = @intCast(y);
    // Compute the signed end first, then clip both ends to screen. Using
    // `@max(x, 0) + w` would make negative-x lines stretch from 0 to w
    // (instead of stopping at x+w) — that was the long-standing "left
    // window border stretches to the right" bug.
    const x_end_signed: i32 = x +| @as(i32, @intCast(w));
    if (x_end_signed <= 0) return;
    const x0: u32 = if (x < 0) 0 else @intCast(x);
    var x1: u32 = @intCast(x_end_signed);
    if (x1 > target_w) x1 = target_w;
    if (x0 >= x1) return;
    const offset = uy * target_w + x0;
    const count = x1 - x0;
    const dest = @intFromPtr(target) + offset * 4;
    if (count >= 16) {
        fillSSE2(dest, color, count);
    } else {
        asm volatile ("cld; rep stosl"
            :
            : [dst] "{rdi}" (dest),
              [val] "{eax}" (color),
              [cnt] "{rcx}" (count),
            : .{ .rdi = true, .rcx = true, .memory = true }
        );
    }
}

pub fn drawVLine(x: i32, y: i32, h: u32, color: u32) void {
    if (x < 0 or x >= @as(i32, @intCast(target_w))) return;
    const ux: u32 = @intCast(x);
    const c = clipRect(x, y, 1, h) orelse return;
    // Direct pointer arithmetic — skip bounds check per pixel
    var ptr = @intFromPtr(target) + (c.y0 * target_w + ux) * 4;
    const stride = target_w * 4;
    var rows = c.y1 - c.y0;
    while (rows > 0) : (rows -= 1) {
        @as(*volatile u32, @ptrFromInt(ptr)).* = color;
        ptr += stride;
    }
}

// Comptime-precomputed glyph cache for the 8x16 font. For each ASCII char,
// stores packed positions of FG pixels (row<<3 | col). drawChar iterates
// this list — no per-row bit-shift extraction, no nested 16x8 loop. Sits
// in .rodata at compile time, no init step or per-char cost.
const GLYPH_CACHE_MAX: u32 = 128;
const glyph_cache: [128][GLYPH_CACHE_MAX]u8 = blk: {
    @setEvalBranchQuota(200_000);
    var cache: [128][GLYPH_CACHE_MAX]u8 = undefined;
    for (0..128) |ch| {
        const glyph = font.data[ch];
        var count: u8 = 0;
        for (0..16) |row| {
            const bits = glyph[row];
            if (bits == 0) continue;
            for (0..8) |col| {
                if (bits & (@as(u8, 0x80) >> @intCast(col)) != 0) {
                    cache[ch][count] = (@as(u8, @intCast(row)) << 3) | @as(u8, @intCast(col));
                    count += 1;
                }
            }
        }
    }
    break :blk cache;
};
const glyph_count: [128]u8 = blk: {
    @setEvalBranchQuota(200_000);
    var counts: [128]u8 = undefined;
    for (0..128) |ch| {
        const glyph = font.data[ch];
        var count: u8 = 0;
        for (0..16) |row| {
            const bits = glyph[row];
            if (bits == 0) continue;
            for (0..8) |col| {
                if (bits & (@as(u8, 0x80) >> @intCast(col)) != 0) count += 1;
            }
        }
        counts[ch] = count;
    }
    break :blk counts;
};

/// Draw an 8x16 character glyph using the precomputed FG-pixel cache.
/// Has a fully-on-screen fast path that skips per-pixel bounds checks.
pub fn drawChar(x: i32, y: i32, ch: u8, fg: u32, bg: u32) void {
    _ = bg; // bg is not painted — caller fills behind first
    const c: u8 = if (ch < 128) ch else '?';
    const count = glyph_count[c];
    if (count == 0) return;
    const pixels = &glyph_cache[c];

    // Fast path: glyph fully on-screen → no per-pixel clip
    if (x >= 0 and y >= 0 and
        x + 8 <= @as(i32, @intCast(target_w)) and
        y + 16 <= @as(i32, @intCast(target_h)))
    {
        const base = @as(u32, @intCast(y)) * target_w + @as(u32, @intCast(x));
        var i: u8 = 0;
        while (i < count) : (i += 1) {
            const p = pixels[i];
            const row: u32 = p >> 3;
            const col: u32 = p & 7;
            target[base + row * target_w + col] = fg;
        }
        return;
    }

    // Clipping path
    var i: u8 = 0;
    while (i < count) : (i += 1) {
        const p = pixels[i];
        const px = x + @as(i32, p & 7);
        const py = y + @as(i32, p >> 3);
        if (px < 0 or py < 0) continue;
        if (px >= @as(i32, @intCast(target_w)) or py >= @as(i32, @intCast(target_h))) continue;
        target[@as(u32, @intCast(py)) * target_w + @as(u32, @intCast(px))] = fg;
    }
}

pub fn drawString(x: i32, y: i32, str: []const u8, fg: u32, bg: u32) void {
    var cx = x;
    for (str) |ch| {
        drawChar(cx, y, ch, fg, bg);
        cx += 8;
    }
}

/// Draw a filled circle at center (cx, cy) with given radius and color.
pub fn drawFilledCircle(cx: i32, cy: i32, radius: u32, color: u32) void {
    const r: i32 = @intCast(radius);
    const r_outer = r + 1; // 1px anti-alias band
    const r_sq = r * r;
    const base_color = color & 0x00FFFFFF;
    var dy: i32 = -r_outer;
    while (dy <= r_outer) : (dy += 1) {
        var dx: i32 = -r_outer;
        while (dx <= r_outer) : (dx += 1) {
            const dist_sq = dx * dx + dy * dy;
            if (dist_sq <= r_sq - r) {
                // Fully inside — solid color
                putPixel(cx + dx, cy + dy, color);
            } else if (dist_sq <= r_sq + r * 2 + 1) {
                // Edge zone — blend based on distance
                // Coverage approximation: how far into the edge band
                const diff = dist_sq - (r_sq - r);
                const band = @as(u32, @intCast(r * 3 + 1));
                const alpha = if (diff >= band) @as(u32, 0) else 255 - @as(u32, @intCast(diff)) * 255 / band;
                if (alpha > 10) {
                    const px = cx + dx;
                    const py = cy + dy;
                    if (px >= 0 and py >= 0 and px < @as(i32, @intCast(target_w)) and py < @as(i32, @intCast(target_h))) {
                        const off: usize = @intCast(py * @as(i32, @intCast(target_w)) + px);
                        target[off] = blendPixel(target[off], (@as(u32, @intCast(alpha)) << 24) | base_color);
                    }
                }
            }
        }
    }
}

/// Like `drawFilledCircle`, but the entire disc (interior + AA edge) is
/// alpha-blended using the color's top-byte alpha — so it shows the pixels
/// underneath. Used for soft circular speculars (e.g. the traffic-light
/// gloss) where a fully opaque fill would read as a hard dot.
pub fn drawFilledCircleAlpha(cx: i32, cy: i32, radius: u32, color: u32) void {
    const a = (color >> 24) & 0xFF;
    if (a == 0) return;
    const r: i32 = @intCast(radius);
    const r_outer = r + 1;
    const r_sq = r * r;
    const base = color & 0x00FFFFFF;
    var dy: i32 = -r_outer;
    while (dy <= r_outer) : (dy += 1) {
        var dx: i32 = -r_outer;
        while (dx <= r_outer) : (dx += 1) {
            const dist_sq = dx * dx + dy * dy;
            var cov: u32 = 0;
            if (dist_sq <= r_sq - r) {
                cov = 255;
            } else if (dist_sq <= r_sq + r * 2 + 1) {
                const diff = dist_sq - (r_sq - r);
                const band = @as(u32, @intCast(r * 3 + 1));
                cov = if (diff >= band) 0 else 255 - @as(u32, @intCast(diff)) * 255 / band;
            }
            if (cov == 0) continue;
            const pa = (a * cov) / 255;
            if (pa == 0) continue;
            blendPixelAt(cx + dx, cy + dy, (pa << 24) | base);
        }
    }
}

/// SSE2 memcpy for framebuffer rows.
fn copyRowSSE2(dst: usize, src: usize, count: u32) void {
    var d = dst;
    var s = src;
    var rem = count;
    while (rem >= 16) {
        asm volatile (
            \\ movdqu 0(%[s]), %%xmm0
            \\ movdqu 16(%[s]), %%xmm1
            \\ movdqu 32(%[s]), %%xmm2
            \\ movdqu 48(%[s]), %%xmm3
            \\ movdqu %%xmm0, 0(%[d])
            \\ movdqu %%xmm1, 16(%[d])
            \\ movdqu %%xmm2, 32(%[d])
            \\ movdqu %%xmm3, 48(%[d])
            :
            : [d] "r" (d), [s] "r" (s),
            : .{ .xmm0 = true, .xmm1 = true, .xmm2 = true, .xmm3 = true, .memory = true }
        );
        d += 64;
        s += 64;
        rem -= 16;
    }
    if (rem > 0) {
        asm volatile ("cld; rep movsl"
            :
            : [dst] "{rdi}" (d),
              [src] "{rsi}" (s),
              [cnt] "{rcx}" (rem),
            : .{ .rdi = true, .rsi = true, .rcx = true, .memory = true }
        );
    }
}

/// Blit entire back buffer to screen framebuffer using SSE2.
///
/// No-op when target == screen — see desktop.zig setupBackBuffer: in virtio-gpu
/// mode we point target straight at virtio_gpu.framebuffer (the device
/// resource backing) so composition lands directly where TRANSFER_TO_HOST_2D
/// expects it, saving the redundant SSE memcpy of the whole frame (~8MB at
/// 1920×1080×4) per full re-render.
/// When true, blitToScreen / blitRectToScreen / post_blit_fn are
/// suppressed. The mode-9 GPU compositor sets this so the desktop
/// keeps drawing into its back buffer but never reaches the screen FB
/// directly — the compositor is the sole writer of the screen FB.
pub var skip_blit_to_screen: bool = false;

pub fn blitToScreen() void {
    if (skip_blit_to_screen) return;
    if (target == screen) return;
    copyRowSSE2(@intFromPtr(screen), @intFromPtr(target), target_w * target_h);
}

/// Blit a rectangle from back buffer to screen framebuffer. No-op when
/// target == screen (see blitToScreen comment).
pub fn blitRectToScreen(x: u32, y: u32, w: u32, h: u32) void {
    if (skip_blit_to_screen) return;
    if (target == screen) return;
    const x0 = @min(x, target_w);
    const y0 = @min(y, target_h);
    const x1 = @min(x + w, target_w);
    const y1 = @min(y + h, target_h);
    const count = x1 - x0;
    if (count == 0) return;
    var row = y0;
    while (row < y1) : (row += 1) {
        const offset = (row * target_w + x0) * 4;
        copyRowSSE2(@intFromPtr(screen) + offset, @intFromPtr(target) + offset, count);
    }
}

/// Wait for vertical retrace (eliminates tearing). Timeout-safe.
pub fn waitVSync() void {
    var timeout: u32 = 4096;
    // Wait until not in retrace
    while (timeout > 0) : (timeout -= 1) {
        if (io.inb(0x3DA) & 0x08 == 0) break;
    }
    timeout = 4096;
    // Wait until retrace starts
    while (timeout > 0) : (timeout -= 1) {
        if (io.inb(0x3DA) & 0x08 != 0) break;
    }
}

/// Write a pixel directly to the screen framebuffer (bypass back buffer).
pub fn putPixelDirect(x: i32, y: i32, color: u32) void {
    if (x < 0 or y < 0) return;
    const ux: u32 = @intCast(x);
    const uy: u32 = @intCast(y);
    if (ux >= screen_w or uy >= screen_h) return;
    screen[uy * screen_w + ux] = color;
}

// --- 16x32 font rendering ---

pub const FONT32_W: u32 = font32.char_w;
pub const FONT32_H: u32 = font32.char_h;
pub const FONT32_ADV: u32 = font32.advance;

// Comptime FG-pixel cache for the 12x22 (font32) glyph used in window
// titles. Same approach as the 8x16 cache; entries pack (row<<4 | col)
// in a u16 because row range (0..21) needs 5 bits. Sits in .rodata
// (~67 KB) — large for kernel data but cheap given the kernel image is
// already ~7 MB and title text lives on the chrome render hot path.
const GLYPH32_CACHE_MAX: u32 = font32.char_w * font32.char_h;
const glyph32_cache: [128][GLYPH32_CACHE_MAX]u16 = blk: {
    @setEvalBranchQuota(500_000);
    var cache: [128][GLYPH32_CACHE_MAX]u16 = undefined;
    for (0..128) |ch| {
        const glyph = font32.data[ch];
        var count: u16 = 0;
        for (0..font32.char_h) |row| {
            const bits = glyph[row];
            if (bits == 0) continue;
            for (0..font32.char_w) |col| {
                if (bits & (@as(u16, 0x8000) >> @intCast(col)) != 0) {
                    cache[ch][count] = (@as(u16, @intCast(row)) << 4) | @as(u16, @intCast(col));
                    count += 1;
                }
            }
        }
    }
    break :blk cache;
};
const glyph32_count: [128]u16 = blk: {
    @setEvalBranchQuota(500_000);
    var counts: [128]u16 = undefined;
    for (0..128) |ch| {
        const glyph = font32.data[ch];
        var count: u16 = 0;
        for (0..font32.char_h) |row| {
            const bits = glyph[row];
            if (bits == 0) continue;
            for (0..font32.char_w) |col| {
                if (bits & (@as(u16, 0x8000) >> @intCast(col)) != 0) count += 1;
            }
        }
        counts[ch] = count;
    }
    break :blk counts;
};

pub fn drawChar32(x: i32, y: i32, ch: u8, fg: u32, bg: u32) void {
    _ = bg;
    const c: u8 = if (ch < 128) ch else '?';
    const count = glyph32_count[c];
    if (count == 0) return;
    const pixels = &glyph32_cache[c];

    // Fast path: glyph fully on-screen → no per-pixel clip
    if (x >= 0 and y >= 0 and
        x + @as(i32, @intCast(font32.char_w)) <= @as(i32, @intCast(target_w)) and
        y + @as(i32, @intCast(font32.char_h)) <= @as(i32, @intCast(target_h)))
    {
        const base = @as(u32, @intCast(y)) * target_w + @as(u32, @intCast(x));
        var i: u16 = 0;
        while (i < count) : (i += 1) {
            const p = pixels[i];
            const row: u32 = p >> 4;
            const col: u32 = p & 0xF;
            target[base + row * target_w + col] = fg;
        }
        return;
    }
    // Clipping path
    var i: u16 = 0;
    while (i < count) : (i += 1) {
        const p = pixels[i];
        const px = x + @as(i32, p & 0xF);
        const py = y + @as(i32, p >> 4);
        if (px < 0 or py < 0) continue;
        if (px >= @as(i32, @intCast(target_w)) or py >= @as(i32, @intCast(target_h))) continue;
        target[@as(u32, @intCast(py)) * target_w + @as(u32, @intCast(px))] = fg;
    }
}

pub fn drawString32(x: i32, y: i32, str: []const u8, fg: u32, bg: u32) void {
    var cx = x;
    for (str) |ch| {
        drawChar32(cx, y, ch, fg, bg);
        cx += @intCast(FONT32_ADV);
    }
}

// --- App icon rendering ---
//
// Modern set (icons.zig, generated): 32x32 straight-alpha ARGB tiles,
// composited with blendPixel so the anti-aliased edges sit correctly on
// any background (glass dock, wallpaper, drag ghosts).
// Classic set (icons.classic): the original hand-authored 16x16 pixel
// art, drawn 2x pixel-doubled with 0 = transparent. Not wired to any
// surface today — preserved for a future Settings appearance toggle.

/// Draw a 32x32 ARGB icon 1:1, alpha-blending onto the target.
pub fn drawIcon32(x: i32, y: i32, icon: *const icons.Icon) void {
    for (0..icons.SIZE) |row| {
        const py = y + @as(i32, @intCast(row));
        if (py < 0) continue;
        if (py >= @as(i32, @intCast(target_h))) break;
        const row_off = @as(u32, @intCast(py)) * target_w;
        for (0..icons.SIZE) |col| {
            const argb = icon[row][col];
            if (argb >> 24 == 0) continue; // fully transparent
            const px = x + @as(i32, @intCast(col));
            if (px < 0) continue;
            if (px >= @as(i32, @intCast(target_w))) break;
            const off = row_off + @as(u32, @intCast(px));
            target[off] = blendPixel(target[off], argb);
        }
    }
}

/// Like `drawIcon32` but scales the icon's baked alpha by `alpha`
/// (0..255). Used for drag-ghost preview: the icon follows the cursor at
/// ~63% opacity, so the user sees both the desktop underneath AND what
/// they're moving.
pub fn drawIcon32Alpha(x: i32, y: i32, icon: *const icons.Icon, alpha: u8) void {
    if (alpha == 0) return;
    for (0..icons.SIZE) |row| {
        const py = y + @as(i32, @intCast(row));
        if (py < 0) continue;
        if (py >= @as(i32, @intCast(target_h))) break;
        const row_off = @as(u32, @intCast(py)) * target_w;
        for (0..icons.SIZE) |col| {
            const argb = icon[row][col];
            const a = (argb >> 24) * alpha / 255;
            if (a == 0) continue;
            const px = x + @as(i32, @intCast(col));
            if (px < 0) continue;
            if (px >= @as(i32, @intCast(target_w))) break;
            const off = row_off + @as(u32, @intCast(px));
            target[off] = blendPixel(target[off], (a << 24) | (argb & 0x00FFFFFF));
        }
    }
}

/// Draw a classic 16x16 icon scaled 2x to 32x32 (opaque, 0 = transparent).
pub fn drawIconClassic32(x: i32, y: i32, icon: *const icons.classic.Icon) void {
    for (0..16) |row| {
        const py0 = y + @as(i32, @intCast(row * 2));
        const py1 = py0 + 1;
        for (0..16) |col| {
            const color = icon[row][col];
            if (color == 0x00000000) continue;
            const px0 = x + @as(i32, @intCast(col * 2));
            const px1 = px0 + 1;
            putPixel(px0, py0, color);
            putPixel(px1, py0, color);
            putPixel(px0, py1, color);
            putPixel(px1, py1, color);
        }
    }
}

/// Classic-set counterpart of `drawIcon32Alpha`.
pub fn drawIconClassic32Alpha(x: i32, y: i32, icon: *const icons.classic.Icon, alpha: u8) void {
    if (alpha == 0) return;
    for (0..16) |row| {
        const py0 = y + @as(i32, @intCast(row * 2));
        const py1 = py0 + 1;
        for (0..16) |col| {
            const color = icon[row][col];
            if (color == 0x00000000) continue;
            const argb: u32 = (@as(u32, alpha) << 24) | (color & 0x00FFFFFF);
            const px0 = x + @as(i32, @intCast(col * 2));
            const px1 = px0 + 1;
            if (px0 >= 0 and py0 >= 0 and px0 < @as(i32, @intCast(target_w)) and py0 < @as(i32, @intCast(target_h))) {
                const off = @as(u32, @intCast(py0)) * target_w + @as(u32, @intCast(px0));
                target[off] = blendPixel(target[off], argb);
            }
            if (px1 >= 0 and py0 >= 0 and px1 < @as(i32, @intCast(target_w)) and py0 < @as(i32, @intCast(target_h))) {
                const off = @as(u32, @intCast(py0)) * target_w + @as(u32, @intCast(px1));
                target[off] = blendPixel(target[off], argb);
            }
            if (px0 >= 0 and py1 >= 0 and px0 < @as(i32, @intCast(target_w)) and py1 < @as(i32, @intCast(target_h))) {
                const off = @as(u32, @intCast(py1)) * target_w + @as(u32, @intCast(px0));
                target[off] = blendPixel(target[off], argb);
            }
            if (px1 >= 0 and py1 >= 0 and px1 < @as(i32, @intCast(target_w)) and py1 < @as(i32, @intCast(target_h))) {
                const off = @as(u32, @intCast(py1)) * target_w + @as(u32, @intCast(px1));
                target[off] = blendPixel(target[off], argb);
            }
        }
    }
}

// --- Rounded rectangle primitives ---

fn isqrt(n: u32) u32 {
    if (n == 0) return 0;
    var guess: u32 = n;
    var prev: u32 = 0;
    while (true) {
        prev = guess;
        guess = (guess + n / guess) / 2;
        if (guess >= prev) return prev;
    }
}

/// Blend `argb` (alpha in the top byte) onto the target pixel at (px, py).
/// Bounds-checked. Used for the sub-pixel AA edge of rounded corners and for
/// soft circular speculars.
inline fn blendPixelAt(px: i32, py: i32, argb: u32) void {
    if (px < 0 or py < 0) return;
    const ux: u32 = @intCast(px);
    const uy: u32 = @intCast(py);
    if (ux >= target_w or uy >= target_h) return;
    const off = uy * target_w + ux;
    target[off] = blendPixel(target[off], argb);
}

/// Per-row geometry of a rounded corner. `dy` is the vertical distance (0..r)
/// from the corner arc's center row. Returns the integer `inset` (first fully
/// solid column from the edge) and `edge_a` (0..255) — the coverage of the
/// single partially-covered pixel just OUTSIDE that inset on each side.
///
/// Float-free: the boundary sits at `inset - frac(sqrt(inner))`, and
/// `frac(sqrt(n)) ≈ (n - s²)/(2s + 1)` with `s = floor(sqrt(n))`. That fraction
/// IS the coverage of the boundary pixel — blending it turns the old
/// stair-stepped corner into a smooth 1px-AA arc that matches the window
/// chrome's supersampled corners.
fn roundedRowEdge(r: u32, dy: u32) struct { inset: u32, edge_a: u32 } {
    const inner = r * r -| (dy * dy);
    const s = isqrt(inner);
    const denom = 2 * s + 1;
    var frac = (inner - s * s) * 255 / denom;
    if (frac > 255) frac = 255;
    return .{ .inset = r - s, .edge_a = frac };
}

pub fn fillRoundedRect(x: i32, y: i32, w: u32, h: u32, radius: u32, color: u32) void {
    if (w == 0 or h == 0) return;
    const r = @min(radius, w / 2, h / 2);
    if (r == 0) return fillRect(x, y, w, h, color);
    const rgb = color & 0x00FFFFFF;

    for (0..h) |row_i| {
        var inset: u32 = 0;
        var edge_a: u32 = 0;
        if (row_i < r) {
            const e = roundedRowEdge(r, r - 1 - @as(u32, @intCast(row_i)));
            inset = e.inset;
            edge_a = e.edge_a;
        } else if (row_i >= h - r) {
            const e = roundedRowEdge(r, @as(u32, @intCast(row_i)) - (h - r));
            inset = e.inset;
            edge_a = e.edge_a;
        }
        if (inset * 2 >= w) continue;
        const ry = y + @as(i32, @intCast(row_i));
        fillRect(x + @as(i32, @intCast(inset)), ry, w - inset * 2, 1, color);
        // Sub-pixel AA: blend the single partial pixel just outside each side.
        if (inset > 0 and edge_a > 0) {
            blendPixelAt(x + @as(i32, @intCast(inset)) - 1, ry, (edge_a << 24) | rgb);
            blendPixelAt(x + @as(i32, @intCast(w - inset)), ry, (edge_a << 24) | rgb);
        }
    }
}

pub fn fillRoundedRectAlpha(x: i32, y: i32, w: u32, h: u32, radius: u32, color: u32) void {
    if (w == 0 or h == 0) return;
    const r = @min(radius, w / 2, h / 2);
    if (r == 0) return fillRectAlpha(x, y, w, h, color);
    const base_a = (color >> 24) & 0xFF;
    const rgb = color & 0x00FFFFFF;

    for (0..h) |row_i| {
        var inset: u32 = 0;
        var edge_a: u32 = 0;
        if (row_i < r) {
            const e = roundedRowEdge(r, r - 1 - @as(u32, @intCast(row_i)));
            inset = e.inset;
            edge_a = e.edge_a;
        } else if (row_i >= h - r) {
            const e = roundedRowEdge(r, @as(u32, @intCast(row_i)) - (h - r));
            inset = e.inset;
            edge_a = e.edge_a;
        }
        if (inset * 2 >= w) continue;
        const ry = y + @as(i32, @intCast(row_i));
        fillRectAlpha(x + @as(i32, @intCast(inset)), ry, w - inset * 2, 1, color);
        // Sub-pixel AA, scaled by the fill's own alpha.
        if (inset > 0 and edge_a > 0) {
            const pa = (base_a * edge_a) / 255;
            if (pa > 0) {
                blendPixelAt(x + @as(i32, @intCast(inset)) - 1, ry, (pa << 24) | rgb);
                blendPixelAt(x + @as(i32, @intCast(w - inset)), ry, (pa << 24) | rgb);
            }
        }
    }
}

// --- Blur & Glass primitives ---

const BLUR_MAX_W: u32 = 1920;
const BLUR_MAX_H: u32 = 120;
const BLUR_SCRATCH_BYTES: usize = BLUR_MAX_W * BLUR_MAX_H * @sizeOf(u32);

// Heap-allocated lazily on the first blur call. Lives in .bss as a
// pointer (8 bytes) instead of a 900 KB static array, which keeps the
// kernel image well clear of KERNEL_HEAP_BASE — see assertKernelImageFits.
var blur_scratch_ptr: ?[*]u32 = null;

fn blurScratch() ?[*]u32 {
    if (blur_scratch_ptr) |p| return p;
    const heap = @import("../mm/heap.zig");
    const raw = heap.kmallocAligned(BLUR_SCRATCH_BYTES, 16) orelse return null;
    blur_scratch_ptr = @ptrCast(@alignCast(raw));
    return blur_scratch_ptr;
}

/// 3-pass separable box blur on a region of the target buffer.
/// Approximates Gaussian blur. radius is the half-kernel size (kernel = 2*radius+1).
pub fn blurRegion(x: u32, y: u32, w: u32, h: u32, radius: u32) void {
    if (w == 0 or h == 0 or radius == 0) return;
    // Clamp to target bounds
    const x1 = @min(x + w, target_w);
    const y1 = @min(y + h, target_h);
    if (x >= x1 or y >= y1) return;
    const bw = x1 - x;
    const bh = y1 - y;
    if (bw * bh > BLUR_MAX_W * BLUR_MAX_H) return; // region too large for scratch
    const r = @min(radius, @min(bw, bh) / 2);
    if (r == 0) return;

    const scratch = blurScratch() orelse return;

    // 3 passes of box blur approximate Gaussian
    blurPass(scratch, x, y, bw, bh, r);
    blurPass(scratch, x, y, bw, bh, r);
    blurPass(scratch, x, y, bw, bh, r);
}

/// Single separable box blur pass: horizontal then vertical.
fn blurPass(scratch: [*]u32, x: u32, y: u32, w: u32, h: u32, r: u32) void {
    const ksize = r * 2 + 1;

    // --- Horizontal pass: read from target, write to scratch ---
    for (0..h) |row_i| {
        const row: u32 = @intCast(row_i);
        const ty = y + row;
        const row_off = ty * target_w + x;

        // Initialize running sums for first window
        var sum_r: u32 = 0;
        var sum_g: u32 = 0;
        var sum_b: u32 = 0;

        // Seed: sum of first (r+1) pixels, plus r copies of pixel[0] for left edge
        const first = target[row_off];
        sum_r += ((first >> 16) & 0xFF) * (r + 1);
        sum_g += ((first >> 8) & 0xFF) * (r + 1);
        sum_b += (first & 0xFF) * (r + 1);
        for (1..r + 1) |i| {
            const ci: u32 = @intCast(@min(i, w - 1));
            const px = target[row_off + ci];
            sum_r += (px >> 16) & 0xFF;
            sum_g += (px >> 8) & 0xFF;
            sum_b += px & 0xFF;
        }

        for (0..w) |col_i| {
            const col: u32 = @intCast(col_i);
            // Store averaged pixel
            scratch[row * w + col] =
                ((sum_r / ksize) << 16) |
                ((sum_g / ksize) << 8) |
                (sum_b / ksize);

            // Slide window: add entering pixel on right, subtract leaving pixel on left.
            // Plain `add - sub` (no saturating `-|`): the leaving pixel was added to
            // `sum_X` earlier so `sum_X + add - sub >= 0` mathematically. Saturating
            // the byte-channel delta clamped negative deltas to 0, biasing the sum
            // upward at sharp transitions and producing visible streaks/bands.
            const add_idx = @min(col + r + 1, w - 1);
            const sub_idx = if (col >= r) col - r else 0;
            const add_px = target[row_off + add_idx];
            const sub_px = target[row_off + sub_idx];
            sum_r = sum_r + ((add_px >> 16) & 0xFF) - ((sub_px >> 16) & 0xFF);
            sum_g = sum_g + ((add_px >> 8) & 0xFF) - ((sub_px >> 8) & 0xFF);
            sum_b = sum_b + (add_px & 0xFF) - (sub_px & 0xFF);
        }
    }

    // --- Vertical pass: read from scratch, write to target ---
    for (0..w) |col_i| {
        const col: u32 = @intCast(col_i);

        var sum_r: u32 = 0;
        var sum_g: u32 = 0;
        var sum_b: u32 = 0;

        // Seed with first pixel replicated for top edge
        const first = scratch[col];
        sum_r += ((first >> 16) & 0xFF) * (r + 1);
        sum_g += ((first >> 8) & 0xFF) * (r + 1);
        sum_b += (first & 0xFF) * (r + 1);
        for (1..r + 1) |i| {
            const ri: u32 = @intCast(@min(i, h - 1));
            const px = scratch[ri * w + col];
            sum_r += (px >> 16) & 0xFF;
            sum_g += (px >> 8) & 0xFF;
            sum_b += px & 0xFF;
        }

        for (0..h) |row_i| {
            const row: u32 = @intCast(row_i);
            const ty = y + row;
            // Write back to target
            target[ty * target_w + x + col] =
                ((sum_r / ksize) << 16) |
                ((sum_g / ksize) << 8) |
                (sum_b / ksize);

            // Slide window
            const add_idx = @min(row + r + 1, h - 1);
            const sub_idx = if (row >= r) row - r else 0;
            const add_px = scratch[add_idx * w + col];
            const sub_px = scratch[sub_idx * w + col];
            sum_r = sum_r + ((add_px >> 16) & 0xFF) - ((sub_px >> 16) & 0xFF);
            sum_g = sum_g + ((add_px >> 8) & 0xFF) - ((sub_px >> 8) & 0xFF);
            sum_b = sum_b + (add_px & 0xFF) - (sub_px & 0xFF);
        }
    }
}

/// Boost color saturation of a region in the target buffer.
/// boost: 0=no change, 255=full saturation push.
pub fn saturateRegion(x: u32, y: u32, w: u32, h: u32, boost: u8) void {
    if (w == 0 or h == 0 or boost == 0) return;
    const x1 = @min(x + w, target_w);
    const y1 = @min(y + h, target_h);
    if (x >= x1 or y >= y1) return;
    const bw = x1 - x;
    const bh = y1 - y;
    const b: u32 = boost;

    for (0..bh) |row_i| {
        const row: u32 = @intCast(row_i);
        const off = (y + row) * target_w + x;
        for (0..bw) |col_i| {
            const col: u32 = @intCast(col_i);
            const px = target[off + col];
            const r = (px >> 16) & 0xFF;
            const g = (px >> 8) & 0xFF;
            const blue = px & 0xFF;
            const gray = (r + g + blue) / 3;
            // Lerp each channel away from gray: channel + (channel - gray) * boost / 255
            // Clamped to 0-255
            const ib: i32 = @intCast(b);
            const ig: i32 = @intCast(gray);
            const nr = clampChannel(@as(i32, @intCast(r)) + @divTrunc(@as(i32, @intCast(r)) * ib - ig * ib, 255));
            const ng = clampChannel(@as(i32, @intCast(g)) + @divTrunc(@as(i32, @intCast(g)) * ib - ig * ib, 255));
            const nb = clampChannel(@as(i32, @intCast(blue)) + @divTrunc(@as(i32, @intCast(blue)) * ib - ig * ib, 255));
            target[off + col] = (@as(u32, nr) << 16) | (@as(u32, ng) << 8) | @as(u32, nb);
        }
    }
}

inline fn clampChannel(v: i32) u32 {
    if (v < 0) return 0;
    if (v > 255) return 255;
    return @intCast(v);
}

// --- Rounded-glass corner mask scratch ---
//
// `fillGlass` blurs and saturates the full bounding rectangle then paints a
// rounded tint on top. Without masking, the four corner squares (outside the
// rounded shape) keep their blurred-and-saturated wallpaper, producing a
// visible squarish ghost around every glass pill / popover.
//
// Fix: snapshot the four r×r corner squares from `target` before the blur,
// then after blur+saturate restore the pixels that fall outside the rounded
// mask (distance from the matching arc center > r). Lazy heap alloc because
// the buffer is sizeable and `fillGlass` may not be reached on every boot.
const CORNER_MAX_R: u32 = 64;
const CORNER_SCRATCH_BYTES: usize = 4 * CORNER_MAX_R * CORNER_MAX_R * @sizeOf(u32);
var corner_scratch_ptr: ?[*]u32 = null;

fn cornerScratch() ?[*]u32 {
    if (corner_scratch_ptr) |p| return p;
    const heap = @import("../mm/heap.zig");
    const raw = heap.kmallocAligned(CORNER_SCRATCH_BYTES, 16) orelse return null;
    corner_scratch_ptr = @ptrCast(@alignCast(raw));
    return corner_scratch_ptr;
}

fn saveCornerSquare(scratch: [*]u32, idx: usize, x: u32, y: u32, r: u32) void {
    const base = idx * CORNER_MAX_R * CORNER_MAX_R;
    for (0..r) |dy| {
        const ty = y + @as(u32, @intCast(dy));
        const row_off = ty * target_w + x;
        const dst_off = base + dy * CORNER_MAX_R;
        for (0..r) |dx| {
            scratch[dst_off + dx] = target[row_off + @as(u32, @intCast(dx))];
        }
    }
}

/// Restore pixels in the corner square at (x, y, r×r) that fall OUTSIDE the
/// rounded mask. The rounded shape's arc center is at (x + cx_off, y + cy_off).
fn restoreCornerOutsideRounded(
    scratch: [*]u32, idx: usize,
    x: u32, y: u32, r: u32,
    cx_off: u32, cy_off: u32,
) void {
    const base = idx * CORNER_MAX_R * CORNER_MAX_R;
    const arc_cx: i32 = @as(i32, @intCast(x + cx_off));
    const arc_cy: i32 = @as(i32, @intCast(y + cy_off));
    const ir: i32 = @intCast(r);
    const r_sq: i32 = ir * ir;
    for (0..r) |dy| {
        const py: i32 = @as(i32, @intCast(y)) + @as(i32, @intCast(dy));
        const tgt_row = @as(u32, @intCast(py)) * target_w;
        const src_row = base + dy * CORNER_MAX_R;
        for (0..r) |dx| {
            const px: i32 = @as(i32, @intCast(x)) + @as(i32, @intCast(dx));
            const ddx = px - arc_cx;
            const ddy = py - arc_cy;
            if (ddx * ddx + ddy * ddy > r_sq) {
                target[tgt_row + @as(u32, @intCast(px))] = scratch[src_row + dx];
            }
        }
    }
}

/// Composite a frosted glass surface: blur backdrop, boost saturation,
/// apply tinted rounded rect overlay, add specular top edge and shadow.
pub fn fillGlass(x: i32, y: i32, w: u32, h: u32, radius: u32, tint: u32, blur_r: u32) void {
    if (w == 0 or h == 0) return;
    // Clip to get unsigned coords for blur
    const c = clipRect(x, y, w, h) orelse return;
    const cw: u32 = c.x1 - c.x0;
    const ch: u32 = c.y1 - c.y0;

    // Effective rounded radius — clamped both by half-extent and our scratch
    // buffer cap. If a caller asks for radius > CORNER_MAX_R, we degrade to
    // the un-masked behavior outside the cap rather than crashing.
    const r = @min(@min(radius, @min(cw, ch) / 2), CORNER_MAX_R);
    const scratch_opt = if (r > 0) cornerScratch() else null;
    if (scratch_opt) |sc| {
        saveCornerSquare(sc, 0, c.x0, c.y0, r);                 // TL
        saveCornerSquare(sc, 1, c.x1 - r, c.y0, r);             // TR
        saveCornerSquare(sc, 2, c.x0, c.y1 - r, r);             // BL
        saveCornerSquare(sc, 3, c.x1 - r, c.y1 - r, r);         // BR
    }

    blurRegion(c.x0, c.y0, cw, ch, blur_r);
    saturateRegion(c.x0, c.y0, cw, ch, 40);

    if (scratch_opt) |sc| {
        // Arc center offsets: TL(+r,+r) TR(0,+r) BL(+r,0) BR(0,0).
        restoreCornerOutsideRounded(sc, 0, c.x0,     c.y0,     r, r, r);
        restoreCornerOutsideRounded(sc, 1, c.x1 - r, c.y0,     r, 0, r);
        restoreCornerOutsideRounded(sc, 2, c.x0,     c.y1 - r, r, r, 0);
        restoreCornerOutsideRounded(sc, 3, c.x1 - r, c.y1 - r, r, 0, 0);
    }

    // Tint overlay
    fillRoundedRectAlpha(x, y, w, h, radius, tint);
    // Specular top-edge highlight (1px)
    if (h > 2 and w > radius * 2) {
        fillRoundedRectAlpha(x, y, w, 1, radius, 0x18FFFFFF);
    }
}


// ===========================================================================
// Triangles, polygons, lines, circles, ellipses
// ===========================================================================
//
// Thin wrappers around `lib/shapes.zig` — bind the kernel's global
// framebuffer (target / target_w / target_h) to a shapes.Target struct.
// Userspace (Canvas in lib/graphics.zig) wraps the same primitives with
// its own per-window state. See lib/shapes.zig for the actual algorithms.

pub const Vec2 = shapes.Vec2;

inline fn currentTarget() shapes.Target {
    return .{ .fb = target, .w = target_w, .h = target_h };
}

pub fn fillTriangle(x0: i32, y0: i32, x1: i32, y1: i32, x2: i32, y2: i32, color: u32) void {
    shapes.fillTriangle(currentTarget(), x0, y0, x1, y1, x2, y2, color);
}

pub fn fillPolygonConvex(verts: []const Vec2, color: u32) void {
    shapes.fillPolygonConvex(currentTarget(), verts, color);
}

pub fn fillCircle(cx: i32, cy: i32, radius: u32, color: u32) void {
    shapes.fillCircle(currentTarget(), cx, cy, radius, color);
}

pub fn drawCircleAA(cx: i32, cy: i32, radius: u32, width: u32, color: u32) void {
    shapes.drawCircleAA(currentTarget(), cx, cy, radius, width, color);
}

pub fn fillEllipse(cx: i32, cy: i32, rx: u32, ry: u32, color: u32) void {
    shapes.fillEllipse(currentTarget(), cx, cy, rx, ry, color);
}

pub fn drawEllipseAA(cx: i32, cy: i32, rx: u32, ry: u32, width: u32, color: u32) void {
    shapes.drawEllipseAA(currentTarget(), cx, cy, rx, ry, width, color);
}

pub fn drawLineAA(x0: i32, y0: i32, x1: i32, y1: i32, color: u32) void {
    shapes.drawLineAA(currentTarget(), x0, y0, x1, y1, color);
}

pub fn drawThickLineAA(x0: i32, y0: i32, x1: i32, y1: i32, width: u32, color: u32) void {
    shapes.drawThickLineAA(currentTarget(), x0, y0, x1, y1, width, color);
}

pub fn strokePolyline(verts: []const Vec2, width: u32, color: u32, closed: bool) void {
    shapes.strokePolyline(currentTarget(), verts, width, color, closed);
}
