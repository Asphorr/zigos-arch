// 12x22 bitmap font — comptime scaled from 8x16 font
// Each character is 22 rows of u16 (12 bits used): MSB = leftmost pixel
// Scale factor: 1.5x horizontal, 1.375x vertical (nearest neighbor)

const font8x16 = @import("font8x16.zig");

pub const char_w: u32 = 12;
pub const char_h: u32 = 22;
pub const advance: u32 = 13; // 12px + 1px spacing

pub const data: [128][22]u16 = init: {
    @setEvalBranchQuota(100000);
    var d: [128][22]u16 = [_][22]u16{[_]u16{0} ** 22} ** 128;

    for (0..128) |c| {
        for (0..22) |oy| {
            // Map output row to source row: sy = oy * 16 / 22
            const sy: usize = oy * 16 / 22;
            const src: u8 = font8x16.data[c][sy];
            // Expand 8 bits to 12 bits (1.5x horizontal)
            var expanded: u16 = 0;
            for (0..12) |ox| {
                // Map output col to source col: sx = ox * 8 / 12
                const sx: usize = ox * 8 / 12;
                if (src & (@as(u8, 0x80) >> @intCast(sx)) != 0) {
                    expanded |= @as(u16, 0x8000) >> @intCast(ox);
                }
            }
            d[c][oy] = expanded;
        }
    }

    break :init d;
};
