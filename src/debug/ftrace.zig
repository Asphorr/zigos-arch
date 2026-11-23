//! Frame timeline: timestamped points along input -> desktop -> compositor
//! -> present, kept in a ring and printed with the compositor's statistics.
//! Shows where an interaction's frame cycle goes. A mark is one rdtsc and
//! two stores, safe from any context.

const std = @import("std");
const perf = @import("perf.zig");
const apic = @import("../time/apic.zig");
const debug = @import("debug.zig");

/// The letter is what dump() prints.
pub const Point = enum(u8) {
    /// HID interrupt handled; arg = handler time, us.
    input = 'i',
    /// Desktop iteration woke.
    desk_wake = 'w',
    /// Desktop got the source lock.
    desk_draw = 'b',
    /// Desktop iteration ended; arg = dirty kind.
    desk_done = 'd',
    /// Compositor frame started.
    comp_wake = 'c',
    /// Compositor got the source lock.
    comp_lock = 'l',
    /// Frame stream handed to the host.
    comp_sent = 's',
    /// Host finished the frame.
    comp_reply = 'h',
    /// Present submitted; arg = buffer.
    present = 'p',
    /// Host took the present; arg = time it held it, us.
    present_done = 'P',
};

const SIZE = 512; // power of 2
const MAX_DUMP = 192;

var stamps: [SIZE]u64 = [_]u64{0} ** SIZE;
/// point | arg << 8
var infos: [SIZE]u32 = [_]u32{0} ** SIZE;
var next: u32 = 0;

var snap_stamps: [MAX_DUMP]u64 = undefined;
var snap_infos: [MAX_DUMP]u32 = undefined;

pub fn mark(p: Point, arg: u64) void {
    const i = @atomicRmw(u32, &next, .Add, 1, .monotonic) & (SIZE - 1);
    stamps[i] = perf.rdtsc();
    infos[i] = @as(u32, @intFromEnum(p)) | (@as(u32, @intCast(@min(arg, 0xFF_FFFF))) << 8);
}

/// mark() with the microseconds since `t0` as the argument.
pub fn markSince(p: Point, t0: u64) void {
    mark(p, apic.tscToUs(perf.rdtsc() -% t0));
}

/// Print the last `count` marks as "<us since the first><letter><arg>".
/// One caller at a time (the compositor task). A mark racing the snapshot
/// can tear the newest entry; the rest is copied before printing starts.
pub fn dump(count: u32) void {
    const end = @atomicLoad(u32, &next, .monotonic);
    const n = @min(@min(count, end), MAX_DUMP);
    if (n == 0) return;
    for (0..n) |k| {
        const i = (end -% n +% @as(u32, @intCast(k))) & (SIZE - 1);
        snap_stamps[k] = stamps[i];
        snap_infos[k] = infos[i];
    }
    var line: [200]u8 = undefined;
    var len: usize = 0;
    for (0..n) |k| {
        const us = apic.tscToUs(snap_stamps[k] -% snap_stamps[0]);
        const letter: u8 = @truncate(snap_infos[k]);
        const arg = snap_infos[k] >> 8;
        const piece = (if (arg != 0)
            std.fmt.bufPrint(line[len..], " {d}{c}{d}", .{ us, letter, arg })
        else
            std.fmt.bufPrint(line[len..], " {d}{c}", .{ us, letter })) catch break;
        len += piece.len;
        if (len > line.len - 40 or k == n - 1) {
            debug.klog("[ftrace]{s}\n", .{line[0..len]});
            len = 0;
        }
    }
}
