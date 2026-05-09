// Kernel cmdline parser. Cmdline comes from `BootInfo.cmdline` (UEFI
// path: read from NVRAM `ZigOSCmdline` variable at boot; Multiboot path:
// always empty). Format is a space-separated list of tokens, each either:
//
//   - A bare flag:    `nosmp`, `verbose`, `nodisplay`
//   - A key=value:    `init=app`, `klog=verbose`, `bench=fs`
//
// No quoting, no escaping — keep it minimal and unsurprising. If you need
// values with spaces, don't.
//
// Apps and subsystems consume this via `find()` (presence) and
// `value()` (key=value lookup). Both are O(N*tokens) per call which is
// fine for boot-time fan-out — there are typically <10 tokens.

const std = @import("std");
const boot_info_mod = @import("boot_info.zig");

var cmdline_buf: [256]u8 = [_]u8{0} ** 256;
var cmdline_len: u32 = 0;

pub fn init(boot_info: *const boot_info_mod.BootInfo) void {
    const n = @min(boot_info.cmdline_len, cmdline_buf.len);
    @memcpy(cmdline_buf[0..n], boot_info.cmdline[0..n]);
    cmdline_len = n;
}

pub fn raw() []const u8 {
    return cmdline_buf[0..cmdline_len];
}

/// Bare flag presence. Matches a token equal to `name` exactly (no `=`).
pub fn find(name: []const u8) bool {
    var it = std.mem.tokenizeScalar(u8, raw(), ' ');
    while (it.next()) |tok| {
        if (std.mem.eql(u8, tok, name)) return true;
    }
    return false;
}

/// Lookup `name=value`. Returns the value slice or null. Values are
/// trimmed only by token boundaries (= the space-delimited remainder
/// after `=`).
pub fn value(name: []const u8) ?[]const u8 {
    var it = std.mem.tokenizeScalar(u8, raw(), ' ');
    while (it.next()) |tok| {
        if (tok.len <= name.len) continue;
        if (tok[name.len] != '=') continue;
        if (!std.mem.eql(u8, tok[0..name.len], name)) continue;
        return tok[name.len + 1 ..];
    }
    return null;
}

/// Parse a positive decimal integer from a key=value flag. Returns null
/// if the flag is absent or the value isn't a valid u32.
pub fn valueU32(name: []const u8) ?u32 {
    const v = value(name) orelse return null;
    return std.fmt.parseInt(u32, v, 10) catch null;
}
