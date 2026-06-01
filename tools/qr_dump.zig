//! QR validation harness — emits matrices for tools/qr_decode.py (OpenCV) to
//! round-trip. Run: `zig run tools/qr_dump.zig 2>/tmp/cases.txt && python3 tools/qr_decode.py </tmp/cases.txt`
const std = @import("std");
const qr = @import("../lib/mtproto/qr.zig");

fn emit(code: *const qr.Code, text: []const u8) void {
    std.debug.print("CASE {s}\n", .{text});
    var y: usize = 0;
    while (y < code.size) : (y += 1) {
        var x: usize = 0;
        while (x < code.size) : (x += 1) std.debug.print("{c}", .{@as(u8, if (code.at(x, y) == 1) '1' else '0')});
        std.debug.print("\n", .{});
    }
    std.debug.print("ENDCASE\n", .{});
}

const auto_cases = [_][]const u8{
    "HELLO WORLD 123",
    "tg://login?token=AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "tg://login?token=" ++ ("Zm9vYmFy" ** 12),
    "tg://login?token=" ++ ("AbCdEf90-_" ** 20),
};

pub fn main() void {
    var code: qr.Code = undefined;
    // production path: smallest version, auto mask
    for (auto_cases) |text| {
        qr.encode(&code, text) catch continue;
        emit(&code, text);
    }
    // every mask path (forced) on a fixed v4 payload
    const m4 = "tg://login?token=MASKTEST0123456789ABCDEF";
    var m: u3 = 0;
    while (true) : (m += 1) {
        qr.encodeForced(&code, m4, 4, m);
        emit(&code, m4);
        if (m == 7) break;
    }
    // version-info path (v7) and two-EC-group interleave (v10)
    qr.encodeForced(&code, "tg://login?token=" ++ ("x" ** 90), 7, 5);
    emit(&code, "tg://login?token=" ++ ("x" ** 90));
    qr.encodeForced(&code, "tg://login?token=" ++ ("Z" ** 200), 10, 2);
    emit(&code, "tg://login?token=" ++ ("Z" ** 200));
}
