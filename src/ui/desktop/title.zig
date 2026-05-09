// Window-title helpers — small pure utilities used by `createGuiWindow`
// to format an app's `process.getName()` into a user-facing title.

/// Convert a raw process name like "/bin/files" or "Files.elf" into a
/// user-facing window title: strip leading directory, strip a trailing
/// .elf/.efi if any survived setName's strip, and uppercase the first
/// ASCII letter. The PCB's `name` keeps its raw form for klog/ps.
pub fn pretty(out: []u8, name: []const u8) u8 {
    if (name.len == 0) return 0;
    // Strip path: take everything after the last '/'.
    var start: usize = 0;
    var i: usize = 0;
    while (i < name.len) : (i += 1) {
        if (name[i] == '/') start = i + 1;
    }
    var slice = name[start..];
    // Strip trailing .elf/.efi (case-insensitive). Defensive — most call
    // sites already strip it via setName, but a future caller may not.
    if (slice.len >= 4 and slice[slice.len - 4] == '.') {
        const e1 = slice[slice.len - 3] | 0x20;
        const e2 = slice[slice.len - 2] | 0x20;
        const e3 = slice[slice.len - 1] | 0x20;
        if ((e1 == 'e' and e2 == 'l' and e3 == 'f') or
            (e1 == 'e' and e2 == 'f' and e3 == 'i'))
        {
            slice = slice[0 .. slice.len - 4];
        }
    }
    if (slice.len == 0) return 0;
    const tlen = @min(slice.len, out.len);
    for (0..tlen) |k| out[k] = slice[k];
    if (out[0] >= 'a' and out[0] <= 'z') out[0] -= 32;
    return @intCast(tlen);
}
