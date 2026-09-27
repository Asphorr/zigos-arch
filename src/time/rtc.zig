const io = @import("../io.zig");
const Deadline = @import("../util/deadline.zig").Deadline;

fn readReg(reg: u8) u8 {
    io.outb(0x70, reg);
    return io.inb(0x71);
}

fn bcdToBin(bcd: u8) u8 {
    return (bcd & 0x0F) + (bcd >> 4) * 10;
}

/// UIP stays set at most ~2 ms per second. A board without CMOS reads 0xFF
/// (UIP stuck on), so the wait is bounded and the read goes ahead anyway.
fn waitUpdateDone() void {
    var d = Deadline.ms(10, "rtc uip");
    while (readReg(0x0A) & 0x80 != 0 and d.live()) {}
}

/// Register B: bit 2 = binary (else BCD), bit 1 = 24-hour. In 12-hour mode
/// bit 7 of the hour byte is PM and midnight/noon both encode as 12.
fn decodeHour(raw: u8, reg_b: u8) u8 {
    const h = if ((reg_b & 0x04) == 0) bcdToBin(raw & 0x7F) else raw & 0x7F;
    if (reg_b & 0x02 != 0) return h;
    return h % 12 + (if (raw & 0x80 != 0) @as(u8, 12) else 0);
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
    waitUpdateDone();
    const raw_sec = readReg(0x00);
    const raw_min = readReg(0x02);
    const raw_hr = readReg(0x04);
    const reg_b = readReg(0x0B);
    const bcd = (reg_b & 0x04) == 0;
    return .{
        .hour = decodeHour(raw_hr, reg_b),
        .minute = if (bcd) bcdToBin(raw_min) else raw_min,
        .second = if (bcd) bcdToBin(raw_sec) else raw_sec,
    };
}

/// Read the full RTC date+time. Reads until two consecutive reads agree to
/// dodge the update-in-progress race (UIP gives a window but the registers
/// can still tick over between reads). A live RTC agrees within two tries.
pub fn readDateTime() DateTime {
    var prev: DateTime = readDateTimeRaw();
    var tries: u8 = 0;
    while (tries < 4) : (tries += 1) {
        const cur = readDateTimeRaw();
        if (cur.second == prev.second and cur.minute == prev.minute and cur.hour == prev.hour and cur.day == prev.day and cur.month == prev.month and cur.year == prev.year) {
            return cur;
        }
        prev = cur;
    }
    return prev;
}

fn readDateTimeRaw() DateTime {
    waitUpdateDone();
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
    const day = if (bcd) bcdToBin(raw_day) else raw_day;
    const mon = if (bcd) bcdToBin(raw_mon) else raw_mon;
    const yr2 = if (bcd) bcdToBin(raw_yr) else raw_yr;
    return .{
        .year = 2000 + @as(u16, yr2),
        .month = mon,
        .day = day,
        .hour = decodeHour(raw_hr, reg_b),
        .minute = min,
        .second = sec,
    };
}
