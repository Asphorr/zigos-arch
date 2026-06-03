// Test stub for debug/debug.zig. net.zig calls debug.klog() for TCP tracing.
// Silenced by default; set VERBOSE = true to watch the state machine.
const std = @import("std");
const VERBOSE = false;

pub fn klog(comptime format: []const u8, args: anytype) void {
    if (VERBOSE) std.debug.print(format, args);
}
