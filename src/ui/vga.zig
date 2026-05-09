const std = @import("std");
const io = @import("../io.zig");
const memmap = @import("../mm/memmap.zig");

pub const Color = enum(u4) { Black = 0, Blue = 1, Green = 2, Cyan = 3, Red = 4, Magenta = 5, Brown = 6, LightGray = 7, DarkGray = 8, LightBlue = 9, LightGreen = 10, LightCyan = 11, LightRed = 12, Pink = 13, Yellow = 14, White = 15 };
pub const Char = packed struct(u16) { char: u8, fg: Color, bg: Color };
pub const WIDTH = 80;
pub const HEIGHT = 25;
// VGA text buffer phys 0xB8000 — addressed through the kernel physmap so
// it stays reachable after Phase 3 drops PML4[0]. The compile-time +
// PHYSMAP_BASE is the same arithmetic as paging.physToVirt; inlined to
// avoid pulling paging into vga.zig (which is imported very early).
pub const MEM = @as([*]volatile Char, @ptrFromInt(memmap.PHYSMAP_BASE + 0xB8000));
pub var row: usize = 0;
pub var col: usize = 0;
pub var fg: Color = .LightGray;
pub var bg: Color = .Black;
pub var redirect_fn: ?*const fn (u8) void = null;
pub var available: bool = true;

pub fn clear() void {
    if (!available) return;
    for (0..HEIGHT) |y| {
        for (0..WIDTH) |x| MEM[y * WIDTH + x] = .{ .char = ' ', .fg = fg, .bg = bg };
    }
    row = 0;
    col = 0;
    updateCursor();
}

pub fn putChar(c: u8) void {
    if (redirect_fn) |rfn| {
        rfn(c);
        return;
    }
    if (!available) return;
    if (c == '\n') {
        col = 0;
        row += 1;
    } else if (c == '\x08') {
        if (col > 0) col -= 1 else if (row > 0) {
            row -= 1;
            col = WIDTH - 1;
        }
        MEM[row * WIDTH + col] = .{ .char = ' ', .fg = fg, .bg = bg };
    } else {
        MEM[row * WIDTH + col] = .{ .char = c, .fg = fg, .bg = bg };
        col += 1;
        if (col >= WIDTH) {
            col = 0;
            row += 1;
        }
    }
    if (row >= HEIGHT) scroll();
    // NOTE: deliberately do NOT call updateCursor here. Each updateCursor
    // is 4× outb to 0x3D4/0x3D5 → 4 VMEXITs. Calling it per-character
    // makes the boot log crawl under QEMU GTK fullscreen (display thread
    // can't drain vmexits fast enough). Callers (`print`, `clear`) update
    // the cursor once at the end.
}

pub fn scroll() void {
    for (1..HEIGHT) |y| {
        for (0..WIDTH) |x| MEM[(y - 1) * WIDTH + x] = MEM[y * WIDTH + x];
    }
    for (0..WIDTH) |x| MEM[(HEIGHT - 1) * WIDTH + x] = .{ .char = ' ', .fg = fg, .bg = bg };
    row = HEIGHT - 1;
}

fn updateCursor() void {
    const pos = @as(u16, @intCast(row * WIDTH + col));
    io.outb(0x3D4, 0x0F);
    io.outb(0x3D5, @as(u8, @truncate(pos & 0xFF)));
    io.outb(0x3D4, 0x0E);
    io.outb(0x3D5, @as(u8, @truncate((pos >> 8) & 0xFF)));
}

const WriterType = std.io.GenericWriter(void, error{}, writeFn);
fn writeFn(_: void, bytes: []const u8) error{}!usize {
    for (bytes) |b| putChar(b);
    return bytes.len;
}
pub const writer = WriterType{ .context = {} };

pub fn print(comptime format: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const out = std.fmt.bufPrint(&buf, format, args) catch buf[0..buf.len];
    for (out) |b| putChar(b);
    if (available and redirect_fn == null) updateCursor();
}
