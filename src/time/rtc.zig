//! The CMOS real-time clock: the date and time the machine keeps while it
//! is off or asleep, to the second. time.zig reads it at boot and after S3
//! and keeps the wall clock itself in between.

const io = @import("../io.zig");
const Deadline = @import("../util/deadline.zig").Deadline;

/// CMOS index of the century byte, from the FADT; 0 = the firmware names
/// none and the century is taken to be this one.
var century_reg: u8 = 0; // (c) set once, before the first read

pub fn setCenturyRegister(reg: u8) void {
    century_reg = reg;
}

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

pub const DateTime = struct {
    year: u16, // full year (e.g. 2026)
    month: u8, // 1-12
    day: u8, // 1-31
    hour: u8,
    minute: u8,
    second: u8,
};

/// Read the full RTC date+time. Reads until two consecutive reads agree to
/// dodge the update-in-progress race (UIP gives a window but the registers
/// can still tick over between reads). A live RTC agrees within two tries.
/// null: the registers hold no date — no CMOS behind the ports, or a clock
/// that was never set.
pub fn readDateTime() ?DateTime {
    var prev: DateTime = readDateTimeRaw();
    var tries: u8 = 0;
    while (tries < 4) : (tries += 1) {
        const cur = readDateTimeRaw();
        if (cur.second == prev.second and cur.minute == prev.minute and cur.hour == prev.hour and cur.day == prev.day and cur.month == prev.month and cur.year == prev.year) break;
        prev = cur;
    }
    const d = prev;
    const dated = d.month >= 1 and d.month <= 12 and d.day >= 1 and d.day <= 31 and d.hour < 24 and d.minute < 60 and d.second < 60;
    return if (dated) d else null;
}

fn readDateTimeRaw() DateTime {
    waitUpdateDone();
    const raw_sec = readReg(0x00);
    const raw_min = readReg(0x02);
    const raw_hr = readReg(0x04);
    const raw_day = readReg(0x07);
    const raw_mon = readReg(0x08);
    const raw_yr = readReg(0x09);
    const raw_century: u8 = if (century_reg != 0) readReg(century_reg) else 0;
    const reg_b = readReg(0x0B);
    const bcd = (reg_b & 0x04) == 0;
    const sec = if (bcd) bcdToBin(raw_sec) else raw_sec;
    const min = if (bcd) bcdToBin(raw_min) else raw_min;
    const day = if (bcd) bcdToBin(raw_day) else raw_day;
    const mon = if (bcd) bcdToBin(raw_mon) else raw_mon;
    const yr2 = if (bcd) bcdToBin(raw_yr) else raw_yr;
    // A century byte that reads as none this clock could be in (never set,
    // a dead battery's 19, no such register after all) counts as absent.
    const stored = if (bcd) bcdToBin(raw_century) else raw_century;
    const century: u16 = if (stored >= 20 and stored <= 99) stored else 20;
    return .{
        .year = century * 100 + @as(u16, yr2),
        .month = mon,
        .day = day,
        .hour = decodeHour(raw_hr, reg_b),
        .minute = min,
        .second = sec,
    };
}
