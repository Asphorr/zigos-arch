const io = @import("../io.zig");

fn readReg(reg: u8) u8 {
    io.outb(0x70, reg);
    return io.inb(0x71);
}

fn bcdToBin(bcd: u8) u8 {
    return (bcd & 0x0F) + (bcd >> 4) * 10;
}

pub const Time = struct { hour: u8, minute: u8, second: u8 };

pub const DateTime = struct {
    year: u16, // full year (e.g. 2026)
    month: u8, // 1-12
    day: u8, // 1-31
    hour: u8,
    minute: u8,
    second: u8,
};

pub fn readTime() Time {
    // Wait for update-in-progress flag to clear
    while (readReg(0x0A) & 0x80 != 0) {}
    const raw_sec = readReg(0x00);
    const raw_min = readReg(0x02);
    const raw_hr = readReg(0x04);
    // Check if BCD mode (bit 2 of register B)
    const reg_b = readReg(0x0B);
    if (reg_b & 0x04 != 0) {
        // Binary mode
        return .{ .hour = raw_hr, .minute = raw_min, .second = raw_sec };
    } else {
        // BCD mode
        return .{ .hour = bcdToBin(raw_hr), .minute = bcdToBin(raw_min), .second = bcdToBin(raw_sec) };
    }
}

/// Read the full RTC date+time. Reads twice to dodge the update-in-progress
/// race (UIP flag gives us a window but the registers can still tick over
/// between reads); if the two reads disagree, we go around once more.
pub fn readDateTime() DateTime {
    var prev: DateTime = readDateTimeRaw();
    while (true) {
        const cur = readDateTimeRaw();
        if (cur.second == prev.second and cur.minute == prev.minute and cur.hour == prev.hour and cur.day == prev.day and cur.month == prev.month and cur.year == prev.year) {
            return cur;
        }
        prev = cur;
    }
}

fn readDateTimeRaw() DateTime {
    while (readReg(0x0A) & 0x80 != 0) {}
    const raw_sec = readReg(0x00);
    const raw_min = readReg(0x02);
    const raw_hr = readReg(0x04);
    const raw_day = readReg(0x07);
    const raw_mon = readReg(0x08);
    const raw_yr = readReg(0x09);
    // Century is sometimes at register 0x32 (ACPI FADT specifies it). Many
    // BIOSes leave it at 0; we hardcode 20 (2000s) which is fine for a hobby
    // OS for the next ~70 years.
    const reg_b = readReg(0x0B);
    const bcd = (reg_b & 0x04) == 0;
    const sec = if (bcd) bcdToBin(raw_sec) else raw_sec;
    const min = if (bcd) bcdToBin(raw_min) else raw_min;
    const hr = if (bcd) bcdToBin(raw_hr) else raw_hr;
    const day = if (bcd) bcdToBin(raw_day) else raw_day;
    const mon = if (bcd) bcdToBin(raw_mon) else raw_mon;
    const yr2 = if (bcd) bcdToBin(raw_yr) else raw_yr;
    return .{
        .year = 2000 + @as(u16, yr2),
        .month = mon,
        .day = day,
        .hour = hr,
        .minute = min,
        .second = sec,
    };
}
