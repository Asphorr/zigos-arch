// UI widgets for user-space apps (macOS-inspired)

const gfx = @import("graphics");

pub const Canvas = gfx.Canvas;

pub const Button = struct {
    x: u32,
    y: u32,
    w: u32,
    h: u32,
    label: []const u8,

    pub fn contains(self: Button, mx: i32, my: i32) bool {
        const x: i32 = @intCast(self.x);
        const y: i32 = @intCast(self.y);
        return mx >= x and mx < x + @as(i32, @intCast(self.w)) and
            my >= y and my < y + @as(i32, @intCast(self.h));
    }

    pub fn draw(self: Button, canvas: *Canvas, color: u32, text_color: u32) void {
        canvas.fillRect(self.x, self.y, self.w, self.h, color);
        canvas.drawTextCentered16(self.x, self.y + (self.h -| Canvas.CH16) / 2, self.w, self.label, text_color, color);
    }

    pub fn drawRounded(self: Button, canvas: *Canvas, color: u32, text_color: u32, bg: u32) void {
        self.draw(canvas, color, text_color);
        canvas.roundCorners(self.x, self.y, self.w, self.h, bg);
    }
};

pub const ProgressBar = struct {
    x: u32,
    y: u32,
    w: u32,
    h: u32,
    bg_color: u32,
    fill_color: u32,
    border_color: u32,

    pub fn draw(self: ProgressBar, canvas: *Canvas, value: u32, max: u32) void {
        canvas.fillRect(self.x, self.y, self.w, self.h, self.bg_color);
        if (max > 0) {
            const fill_w = value * self.w / max;
            canvas.fillRect(self.x, self.y, fill_w, self.h, self.fill_color);
        }
        canvas.drawHLine(self.x, self.y, self.w, self.border_color);
        if (self.h > 1) canvas.drawHLine(self.x, self.y + self.h - 1, self.w, self.border_color);
    }
};
