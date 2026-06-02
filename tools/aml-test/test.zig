const std = @import("std");
const aml = @import("src/acpi/aml.zig");
test "aml selfTestExtended → 0 failures" {
    const fails = aml.selfTestExtended();
    try std.testing.expectEqual(@as(u32, 0), fails);
}
