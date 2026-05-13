// Framebuffer canvas and drawing primitives for user-space apps

const font = @import("font");
const shapes = @import("shapes");

pub const Canvas = struct {
    fb: [*]volatile u32,
    width: u32,
    height: u32,

    pub fn init(fb: [*]volatile u32, w: u32, h: u32) Canvas {
        return .{ .fb = fb, .width = w, .height = h };
    }

    pub fn putPixel(self: *Canvas, x: i32, y: i32, color: u32) void {
        if (x < 0 or y < 0) return;
        const ux: u32 = @intCast(x);
        const uy: u32 = @intCast(y);
        if (ux >= self.width or uy >= self.height) return;
        self.fb[uy * self.width + ux] = color;
    }

    /// Per-pixel src-over alpha blend. `alpha` is 0..255 (0 = transparent,
    /// 255 = fully `color`). Used by AA text rendering and other anti-aliased
    /// primitives. Reads the destination pixel, blends each channel, writes
    /// back. ~3-4x slower than putPixel but the only correct path for
    /// non-binary glyph coverage.
    pub fn blendPixel(self: *Canvas, x: i32, y: i32, color: u32, alpha: u8) void {
        if (alpha == 0) return;
        if (x < 0 or y < 0) return;
        const ux: u32 = @intCast(x);
        const uy: u32 = @intCast(y);
        if (ux >= self.width or uy >= self.height) return;
        if (alpha == 255) {
            self.fb[uy * self.width + ux] = color;
            return;
        }
        const idx = uy * self.width + ux;
        const dst = self.fb[idx];
        const a: u32 = alpha;
        const inv: u32 = 255 - a;
        const sr = (color >> 16) & 0xFF;
        const sg = (color >> 8) & 0xFF;
        const sb = color & 0xFF;
        const dr = (dst >> 16) & 0xFF;
        const dg = (dst >> 8) & 0xFF;
        const db = dst & 0xFF;
        const r = (sr * a + dr * inv + 127) / 255;
        const g = (sg * a + dg * inv + 127) / 255;
        const b = (sb * a + db * inv + 127) / 255;
        self.fb[idx] = (r << 16) | (g << 8) | b;
    }

    pub fn clear(self: *Canvas, color: u32) void {
        for (0..self.width * self.height) |i| self.fb[i] = color;
    }

    pub fn fillRect(self: *Canvas, rx: u32, ry: u32, rw: u32, rh: u32, color: u32) void {
        for (0..rh) |row| {
            const y2 = ry + @as(u32, @intCast(row));
            if (y2 >= self.height) break;
            for (0..rw) |col| {
                const x2 = rx + @as(u32, @intCast(col));
                if (x2 >= self.width) break;
                self.fb[y2 * self.width + x2] = color;
            }
        }
    }

    /// Fill a rect with src-over alpha-blended color. `alpha` is 0..255
    /// (0 = transparent, 255 = fully `color`). Same blend math as
    /// `blendPixel` but the bounds check + index base hoist out of the
    /// inner loop, so it's ~3x faster for big fills (drop shadows, etc.).
    pub fn fillRectAlpha(self: *Canvas, rx: u32, ry: u32, rw: u32, rh: u32, color: u32, alpha: u8) void {
        if (alpha == 0) return;
        const a: u32 = alpha;
        const inv: u32 = 255 - a;
        const sr = (color >> 16) & 0xFF;
        const sg = (color >> 8) & 0xFF;
        const sb = color & 0xFF;
        const sra = sr * a;
        const sga = sg * a;
        const sba = sb * a;
        for (0..rh) |row| {
            const y2 = ry + @as(u32, @intCast(row));
            if (y2 >= self.height) break;
            const base = y2 * self.width;
            for (0..rw) |col| {
                const x2 = rx + @as(u32, @intCast(col));
                if (x2 >= self.width) break;
                const idx = base + x2;
                if (alpha == 255) {
                    self.fb[idx] = color;
                    continue;
                }
                const dst = self.fb[idx];
                const dr = (dst >> 16) & 0xFF;
                const dg = (dst >> 8) & 0xFF;
                const db = dst & 0xFF;
                const r = (sra + dr * inv + 127) / 255;
                const g = (sga + dg * inv + 127) / 255;
                const b = (sba + db * inv + 127) / 255;
                self.fb[idx] = (r << 16) | (g << 8) | b;
            }
        }
    }

    pub fn drawRect(self: *Canvas, rx: u32, ry: u32, rw: u32, rh: u32, color: u32) void {
        self.drawHLine(rx, ry, rw, color);
        if (rh > 1) self.drawHLine(rx, ry + rh - 1, rw, color);
        self.drawVLine(rx, ry, rh, color);
        if (rw > 1) self.drawVLine(rx + rw - 1, ry, rh, color);
    }

    pub fn drawHLine(self: *Canvas, x: u32, y: u32, w: u32, color: u32) void {
        if (y >= self.height) return;
        for (0..w) |i| {
            const px = x + @as(u32, @intCast(i));
            if (px >= self.width) break;
            self.fb[y * self.width + px] = color;
        }
    }

    pub fn drawVLine(self: *Canvas, x: u32, y: u32, h: u32, color: u32) void {
        if (x >= self.width) return;
        for (0..h) |i| {
            const py = y + @as(u32, @intCast(i));
            if (py >= self.height) break;
            self.fb[py * self.width + x] = color;
        }
    }

    // --- Text rendering ---

    pub fn drawChar(self: *Canvas, cx: u32, cy: u32, ch: u8, color: u32) void {
        const glyph = font.getGlyph(ch);
        for (0..font.char_h) |row| {
            for (0..font.char_w) |col| {
                if (glyph[row] & (@as(u8, 0x10) >> @intCast(col)) != 0) {
                    const px = cx + @as(u32, @intCast(col));
                    const py = cy + @as(u32, @intCast(row));
                    if (px < self.width and py < self.height)
                        self.fb[py * self.width + px] = color;
                }
            }
        }
    }

    pub fn drawCharBg(self: *Canvas, cx: u32, cy: u32, ch: u8, fg: u32, bg: u32) void {
        const glyph = font.getGlyph(ch);
        for (0..font.char_h) |row| {
            for (0..font.advance) |col| {
                const px = cx + @as(u32, @intCast(col));
                const py = cy + @as(u32, @intCast(row));
                if (px < self.width and py < self.height) {
                    if (col < font.char_w and glyph[row] & (@as(u8, 0x10) >> @intCast(col)) != 0) {
                        self.fb[py * self.width + px] = fg;
                    } else {
                        self.fb[py * self.width + px] = bg;
                    }
                }
            }
        }
    }

    pub fn drawCharScaled(self: *Canvas, cx: u32, cy: u32, ch: u8, color: u32, scale: u32) void {
        const glyph = font.getGlyph(ch);
        for (0..font.char_h) |row| {
            for (0..font.char_w) |col| {
                if (glyph[row] & (@as(u8, 0x10) >> @intCast(col)) != 0) {
                    for (0..scale) |sy| {
                        for (0..scale) |sx| {
                            const px = cx + @as(u32, @intCast(col)) * scale + @as(u32, @intCast(sx));
                            const py = cy + @as(u32, @intCast(row)) * scale + @as(u32, @intCast(sy));
                            if (px < self.width and py < self.height)
                                self.fb[py * self.width + px] = color;
                        }
                    }
                }
            }
        }
    }

    pub fn drawText(self: *Canvas, tx: u32, ty: u32, text: []const u8, color: u32) void {
        var cx = tx;
        for (text) |ch| {
            self.drawChar(cx, ty, ch, color);
            cx += font.advance;
        }
    }

    pub fn drawTextBg(self: *Canvas, tx: u32, ty: u32, text: []const u8, fg: u32, bg: u32) u32 {
        var cx = tx;
        for (text) |ch| {
            self.drawCharBg(cx, ty, ch, fg, bg);
            cx += font.advance;
        }
        return cx;
    }

    pub fn drawNumBg(self: *Canvas, tx: u32, ty: u32, n: u32, fg: u32, bg: u32) u32 {
        if (n == 0) {
            self.drawCharBg(tx, ty, '0', fg, bg);
            return tx + font.advance;
        }
        var digits: [10]u8 = undefined;
        var dlen: u32 = 0;
        var v = n;
        while (v > 0) : (v /= 10) {
            digits[dlen] = @truncate('0' + v % 10);
            dlen += 1;
        }
        var cx = tx;
        var di: u32 = dlen;
        while (di > 0) : (di -= 1) {
            self.drawCharBg(cx, ty, digits[di - 1], fg, bg);
            cx += font.advance;
        }
        return cx;
    }

    pub fn drawTextCentered(self: *Canvas, bx: u32, by: u32, bw: u32, text: []const u8, color: u32) void {
        const text_w: u32 = @as(u32, @intCast(text.len)) * font.advance;
        const tx = bx + (bw -| text_w) / 2;
        self.drawText(tx, by, text, color);
    }

    pub fn drawNumRightAligned(self: *Canvas, right_x: u32, ty: u32, val: i32, color: u32, scale: u32) void {
        var buf: [12]u8 = undefined;
        var len: u32 = 0;
        var v: u32 = if (val < 0) @intCast(-val) else @intCast(val);
        if (v == 0) {
            buf[0] = '0';
            len = 1;
        } else {
            while (v > 0) : (v /= 10) {
                buf[len] = @truncate('0' + v % 10);
                len += 1;
            }
        }
        if (val < 0) {
            buf[len] = '-';
            len += 1;
        }
        const char_scaled_w = font.char_w * scale + scale;
        var cx = right_x;
        for (0..len) |di| {
            cx -|= char_scaled_w;
            self.drawCharScaled(cx, ty, buf[di], color, scale);
        }
    }

    // --- 8x16 font rendering (larger, cleaner text) ---

    const font16 = @import("font8x16");
    pub const CW16: u32 = 9; // 8px glyph + 1px spacing
    pub const CH16: u32 = 16;

    pub fn drawChar16(self: *Canvas, cx: u32, cy: u32, ch: u8, fg: u32, bg: u32) void {
        const glyph = font16.data[ch];
        for (0..16) |row| {
            const py = cy + @as(u32, @intCast(row));
            if (py >= self.height) break;
            const bits = glyph[row];
            for (0..9) |col| {
                const px = cx + @as(u32, @intCast(col));
                if (px >= self.width) break;
                if (col < 8 and bits & (@as(u8, 0x80) >> @intCast(col)) != 0) {
                    self.fb[py * self.width + px] = fg;
                } else {
                    self.fb[py * self.width + px] = bg;
                }
            }
        }
    }

    pub fn drawChar16Fg(self: *Canvas, cx: u32, cy: u32, ch: u8, fg: u32) void {
        const glyph = font16.data[ch];
        for (0..16) |row| {
            const py = cy + @as(u32, @intCast(row));
            if (py >= self.height) break;
            const bits = glyph[row];
            for (0..8) |col| {
                if (bits & (@as(u8, 0x80) >> @intCast(col)) != 0) {
                    const px = cx + @as(u32, @intCast(col));
                    if (px < self.width) self.fb[py * self.width + px] = fg;
                }
            }
        }
    }

    pub fn drawText16(self: *Canvas, tx: u32, ty: u32, text: []const u8, fg: u32, bg: u32) void {
        var cx = tx;
        for (text) |ch| {
            self.drawChar16(cx, ty, ch, fg, bg);
            cx += CW16;
        }
    }

    pub fn drawText16Fg(self: *Canvas, tx: u32, ty: u32, text: []const u8, fg: u32) void {
        var cx = tx;
        for (text) |ch| {
            self.drawChar16Fg(cx, ty, ch, fg);
            cx += CW16;
        }
    }

    pub fn drawNum16(self: *Canvas, tx: u32, ty: u32, n: u32, fg: u32, bg: u32) u32 {
        if (n == 0) {
            self.drawChar16(tx, ty, '0', fg, bg);
            return tx + CW16;
        }
        var digits: [10]u8 = undefined;
        var dlen: u32 = 0;
        var v = n;
        while (v > 0) : (v /= 10) {
            digits[dlen] = @truncate('0' + v % 10);
            dlen += 1;
        }
        var cx = tx;
        var di: u32 = dlen;
        while (di > 0) : (di -= 1) {
            self.drawChar16(cx, ty, digits[di - 1], fg, bg);
            cx += CW16;
        }
        return cx;
    }

    pub fn drawTextCentered16(self: *Canvas, bx: u32, by: u32, bw: u32, text: []const u8, fg: u32, bg: u32) void {
        const text_w: u32 = @as(u32, @intCast(text.len)) * CW16;
        const tx = bx + (bw -| text_w) / 2;
        self.drawText16(tx, by, text, fg, bg);
    }

    // --- 12x24 font rendering (large UI: titles, paint, editor headers) ---

    const font24 = @import("font12x24");
    pub const CW24: u32 = font24.advance; // 13: 12px glyph + 1px spacing
    pub const CH24: u32 = font24.char_h; // 24

    pub fn drawChar24(self: *Canvas, cx: u32, cy: u32, ch: u8, fg: u32, bg: u32) void {
        const glyph = font24.data[ch];
        for (0..font24.char_h) |row| {
            const py = cy + @as(u32, @intCast(row));
            if (py >= self.height) break;
            const bits = glyph[row];
            for (0..CW24) |col| {
                const px = cx + @as(u32, @intCast(col));
                if (px >= self.width) break;
                const set = col < font24.char_w and (bits & (@as(u16, 0x8000) >> @intCast(col))) != 0;
                self.fb[py * self.width + px] = if (set) fg else bg;
            }
        }
    }

    pub fn drawChar24Fg(self: *Canvas, cx: u32, cy: u32, ch: u8, fg: u32) void {
        const glyph = font24.data[ch];
        for (0..font24.char_h) |row| {
            const py = cy + @as(u32, @intCast(row));
            if (py >= self.height) break;
            const bits = glyph[row];
            if (bits == 0) continue;
            for (0..font24.char_w) |col| {
                if (bits & (@as(u16, 0x8000) >> @intCast(col)) != 0) {
                    const px = cx + @as(u32, @intCast(col));
                    if (px < self.width) self.fb[py * self.width + px] = fg;
                }
            }
        }
    }

    pub fn drawText24(self: *Canvas, tx: u32, ty: u32, text: []const u8, fg: u32, bg: u32) void {
        var cx = tx;
        for (text) |ch| {
            self.drawChar24(cx, ty, ch, fg, bg);
            cx += CW24;
        }
    }

    pub fn drawText24Fg(self: *Canvas, tx: u32, ty: u32, text: []const u8, fg: u32) void {
        var cx = tx;
        for (text) |ch| {
            self.drawChar24Fg(cx, ty, ch, fg);
            cx += CW24;
        }
    }

    pub fn drawTextCentered24(self: *Canvas, bx: u32, by: u32, bw: u32, text: []const u8, fg: u32, bg: u32) void {
        const text_w: u32 = @as(u32, @intCast(text.len)) * CW24;
        const tx = bx + (bw -| text_w) / 2;
        self.drawText24(tx, by, text, fg, bg);
    }

    pub fn drawFilledCircle(self: *Canvas, cx_: i32, cy_: i32, radius: u32, color: u32) void {
        const r: i32 = @intCast(radius);
        var dy: i32 = -r;
        while (dy <= r) : (dy += 1) {
            var dx: i32 = -r;
            while (dx <= r) : (dx += 1) {
                if (dx * dx + dy * dy <= r * r) {
                    self.putPixel(cx_ + dx, cy_ + dy, color);
                }
            }
        }
    }

    pub fn drawLine(self: *Canvas, x0_: i32, y0_: i32, x1_: i32, y1_: i32, color: u32) void {
        var x0 = x0_;
        var y0 = y0_;
        const dx: i32 = if (x1_ > x0_) x1_ - x0_ else x0_ - x1_;
        const dy: i32 = -(if (y1_ > y0_) y1_ - y0_ else y0_ - y1_);
        const sx: i32 = if (x0_ < x1_) 1 else -1;
        const sy: i32 = if (y0_ < y1_) 1 else -1;
        var err = dx + dy;
        while (true) {
            self.putPixel(x0, y0, color);
            if (x0 == x1_ and y0 == y1_) break;
            const e2 = 2 * err;
            if (e2 >= dy) { err += dy; x0 += sx; }
            if (e2 <= dx) { err += dx; y0 += sy; }
        }
    }

    pub fn roundCorners(self: *Canvas, bx: u32, by: u32, bw: u32, bh: u32, bg: u32) void {
        if (bw == 0 or bh == 0) return;
        const r = bx + bw - 1;
        const b = by + bh - 1;
        if (r < self.width and by < self.height) {
            self.fb[by * self.width + bx] = bg;
            self.fb[by * self.width + r] = bg;
        }
        if (r < self.width and b < self.height) {
            self.fb[b * self.width + bx] = bg;
            self.fb[b * self.width + r] = bg;
        }
    }

    // ===== Triangles, polygons, AA lines, circles, ellipses =================
    //
    // Thin wrappers around lib/shapes.zig — bind self.fb / .width / .height
    // to a shapes.Target. The kernel's gfx.zig wraps the same primitives
    // around its own global framebuffer. See lib/shapes.zig for algorithms.

    inline fn target(self: *Canvas) shapes.Target {
        return .{ .fb = self.fb, .w = self.width, .h = self.height };
    }

    pub fn fillTriangle(self: *Canvas, x0: i32, y0: i32, x1: i32, y1: i32, x2: i32, y2: i32, color: u32) void {
        shapes.fillTriangle(self.target(), x0, y0, x1, y1, x2, y2, color);
    }

    pub fn drawTriangle(self: *Canvas, x0: i32, y0: i32, x1: i32, y1: i32, x2: i32, y2: i32, color: u32) void {
        self.drawLineAA(x0, y0, x1, y1, color);
        self.drawLineAA(x1, y1, x2, y2, color);
        self.drawLineAA(x2, y2, x0, y0, color);
    }

    pub fn fillCircle(self: *Canvas, cx: i32, cy: i32, radius: u32, color: u32) void {
        shapes.fillCircle(self.target(), cx, cy, radius, color);
    }

    pub fn drawCircleAA(self: *Canvas, cx: i32, cy: i32, radius: u32, width: u32, color: u32) void {
        shapes.drawCircleAA(self.target(), cx, cy, radius, width, color);
    }

    pub fn fillEllipse(self: *Canvas, cx: i32, cy: i32, rx: u32, ry: u32, color: u32) void {
        shapes.fillEllipse(self.target(), cx, cy, rx, ry, color);
    }

    pub fn drawEllipseAA(self: *Canvas, cx: i32, cy: i32, rx: u32, ry: u32, width: u32, color: u32) void {
        shapes.drawEllipseAA(self.target(), cx, cy, rx, ry, width, color);
    }

    pub fn drawLineAA(self: *Canvas, x0: i32, y0: i32, x1: i32, y1: i32, color: u32) void {
        shapes.drawLineAA(self.target(), x0, y0, x1, y1, color);
    }

    pub fn drawThickLineAA(self: *Canvas, x0: i32, y0: i32, x1: i32, y1: i32, width: u32, color: u32) void {
        shapes.drawThickLineAA(self.target(), x0, y0, x1, y1, width, color);
    }

    pub fn fillPolygonConvex(self: *Canvas, verts: []const shapes.Vec2, color: u32) void {
        shapes.fillPolygonConvex(self.target(), verts, color);
    }

    pub fn strokePolyline(self: *Canvas, verts: []const shapes.Vec2, width: u32, color: u32, closed: bool) void {
        shapes.strokePolyline(self.target(), verts, width, color, closed);
    }
};

pub const Vec2 = shapes.Vec2;
