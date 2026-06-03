// Test stub for ui/vga.zig. net.zig uses vga.print() and the vga.fg color var
// (only reached from the command-line helpers like nslookup/ping/wget, which the
// harness doesn't drive — but they still have to compile). Silenced by default.
const std = @import("std");
const VERBOSE = false;

pub const Color = enum(u8) {
    Black,
    Blue,
    Green,
    Cyan,
    Red,
    Magenta,
    Brown,
    LightGray,
    DarkGray,
    LightBlue,
    LightGreen,
    LightCyan,
    LightRed,
    Pink,
    Yellow,
    White,
};

pub var fg: Color = .LightGray;

pub fn print(comptime format: []const u8, args: anytype) void {
    if (VERBOSE) std.debug.print(format, args);
}
