// Desktop UI configuration — settable via settings.elf, persisted to
// /etc/zigos.conf, and reloaded by the kernel desktop at boot.
//
// `pub var` here so the values are mutable from setConfig (syscall.zig)
// and applyConfKv. The Settings app writes the same file in the same
// `key=value` format; the parser below is the kernel-side mirror of
// that writer.
//
// Adding a new tunable: add a `pub var`, a parse arm in `applyConfKv`,
// a write arm in settings.zig:saveConf, and a setConfig case if
// runtime-poke from userspace is desired.

const std = @import("std");
const debug = @import("../../debug/debug.zig");

pub var bg: u8 = 0; // 0=blue, 1=purple, 2=green, 3=red
pub var theme: u8 = 1; // 0=light, 1=dark (default dark — matches the dark window body/terminal; a true light theme needs a light body + palette)
pub var mouse_speed: u8 = 1; // 0=slow, 1=normal, 2=fast
pub var dock_pos: u8 = 0; // 0=bottom, 1=top
pub var resolution: u8 = 1; // 0=720p, 1=1080p (default to current)

pub const PATH = "/etc/zigos.conf";

/// Read PATH at boot and apply persisted UI settings. Missing file is
/// fine — defaults stand. Bad values are clamped per-key (same range
/// checks as the setConfig syscall).
pub fn load() void {
    var staging: [4096]u8 align(4) = undefined;
    const size = @import("../../fs/vfs.zig").loadFile(PATH, &staging, null) orelse return;
    if (size == 0 or size >= staging.len) return;
    parse(staging[0..size]);
    debug.klog("[desktop] Loaded {s} ({d} bytes)\n", .{ PATH, size });
}

fn parse(text: []const u8) void {
    var i: usize = 0;
    while (i < text.len) {
        // Skip leading whitespace + comments + blank lines.
        while (i < text.len and (text[i] == ' ' or text[i] == '\t' or text[i] == '\n' or text[i] == '\r')) i += 1;
        if (i >= text.len) break;
        if (text[i] == '#') {
            while (i < text.len and text[i] != '\n') i += 1;
            continue;
        }
        const key_start = i;
        while (i < text.len and text[i] != '=' and text[i] != '\n') i += 1;
        if (i >= text.len or text[i] != '=') {
            while (i < text.len and text[i] != '\n') i += 1;
            continue;
        }
        const key = text[key_start..i];
        i += 1; // skip '='
        const val_start = i;
        while (i < text.len and text[i] != '\n' and text[i] != '\r') i += 1;
        applyKv(key, text[val_start..i]);
    }
}

fn parseU8Decimal(s: []const u8) ?u8 {
    if (s.len == 0) return null;
    var v: u32 = 0;
    for (s) |c| {
        if (c < '0' or c > '9') return null;
        v = v * 10 + (c - '0');
        if (v > 255) return null;
    }
    return @intCast(v);
}

fn applyKv(key: []const u8, val_str: []const u8) void {
    const val = parseU8Decimal(val_str) orelse return;
    if (std.mem.eql(u8, key, "resolution") and val <= 1) {
        resolution = val;
    } else if (std.mem.eql(u8, key, "background") and val <= 3) {
        bg = val;
    } else if (std.mem.eql(u8, key, "theme") and val <= 1) {
        theme = val;
    } else if (std.mem.eql(u8, key, "mouse_speed") and val <= 2) {
        mouse_speed = val;
    } else if (std.mem.eql(u8, key, "dock_pos") and val <= 1) {
        dock_pos = val;
    }
}
