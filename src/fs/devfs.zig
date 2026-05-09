// devfs — synthetic /dev filesystem.
//
// The mount lives at /dev/ (registered in vfs.zig). Each entry is a small
// kernel-side handler keyed by Kind; there is no persistent on-disk state
// and no per-fd allocation. Entries are advertised via listToBuffer so that
// `readdir("/dev/")` enumerates them, and getFileStat answers `stat`.
//
// Currently supported:
//   /dev/null    write-discard, read returns 0 (EOF)
//   /dev/zero    read returns zeros forever
//   /dev/random  read returns xorshift32-derived bytes
//   /dev/usb0    raw block access to the first USB Mass Storage device.
//                 sector-aligned (offset and count multiples of block_size,
//                 typically 512). Returns 0xFFFFFFFF on misalignment.
//
// /dev/usb0 is meant as the kernel-side counterpart to usbcat/usbwrite —
// it lets generic byte tools (`cat /dev/usb0 > backup.bin`, `wc -c …`)
// exercise the xHCI MSC code path without bespoke utilities.

const std = @import("std");
const xhci = @import("../driver/xhci.zig");
const serial = @import("../debug/serial.zig");

pub const Kind = enum(u8) {
    null_dev,
    zero_dev,
    random_dev,
    usb0,
    kmsg,
};

pub const Device = struct {
    name: []const u8,
    kind: Kind,
};

const DEVICES = [_]Device{
    .{ .name = "null", .kind = .null_dev },
    .{ .name = "zero", .kind = .zero_dev },
    .{ .name = "random", .kind = .random_dev },
    .{ .name = "usb0", .kind = .usb0 },
    .{ .name = "kmsg", .kind = .kmsg },
};

// Single global xorshift32 — `random` is for entropy-as-a-toy, not cryptography.
// Seed is non-zero (xorshift cannot recover from 0); reseeding from rdtsc would
// be marginally better, but the current init point is reached very early when
// rdtsc is small and predictable, so it doesn't really help.
var rng_state: u32 = 0x9E3779B9;

fn xorshift32() u32 {
    var x = rng_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    rng_state = x;
    return x;
}

/// Match a relative path (the part after "/dev/") to a device index.
/// Returns null if the name is unknown.
pub fn openFile(rel: []const u8) ?u32 {
    for (DEVICES, 0..) |dev, i| {
        if (std.mem.eql(u8, rel, dev.name)) return @intCast(i);
    }
    return null;
}

pub fn closeFile(_: u32) void {}

/// Total readable bytes for a device, used for `stat` and listdir.
/// Stream-style devices report 0 (no fixed size); usb0 reports the
/// underlying disk capacity (block_count × block_size).
pub fn deviceSize(idx: u32) u64 {
    if (idx >= DEVICES.len) return 0;
    return switch (DEVICES[idx].kind) {
        .null_dev, .zero_dev, .random_dev => 0,
        .usb0 => blk: {
            const bs: u64 = xhci.getMscBlockSize();
            const bc: u64 = xhci.getMscBlockCount();
            break :blk bs * bc;
        },
        .kmsg => serial.ringSize(),
    };
}

/// `offset` is taken by pointer so kmsg can advance it past bytes that
/// fell out of the ring (the conceptual stream may move forward by more
/// than the bytes returned to the user). For non-stream devices the
/// simple `*offset += returned` update happens here too — vfs.read no
/// longer touches the offset for devfs reads.
pub fn read(idx: u32, offset: *u32, buf: [*]u8, count: u32) u32 {
    if (idx >= DEVICES.len or count == 0) return 0;
    const n = switch (DEVICES[idx].kind) {
        .null_dev => @as(u32, 0), // EOF on first read
        .zero_dev => blk: {
            @memset(buf[0..count], 0);
            break :blk count;
        },
        .random_dev => blk: {
            // xorshift produces 32 bits per call; copy them out 4 bytes at a
            // time and handle the tail with a final partial extraction.
            var i: u32 = 0;
            while (i + 4 <= count) : (i += 4) {
                const r = xorshift32();
                buf[i] = @truncate(r);
                buf[i + 1] = @truncate(r >> 8);
                buf[i + 2] = @truncate(r >> 16);
                buf[i + 3] = @truncate(r >> 24);
            }
            if (i < count) {
                var r = xorshift32();
                while (i < count) : (i += 1) {
                    buf[i] = @truncate(r);
                    r >>= 8;
                }
            }
            break :blk count;
        },
        .usb0 => readUsb(offset.*, buf, count),
        .kmsg => return serial.ringRead(offset, buf, count), // already advances offset
    };
    if (n != 0xFFFFFFFF) offset.* += n;
    return n;
}

pub fn write(idx: u32, offset: u32, buf: [*]const u8, count: u32) u32 {
    if (idx >= DEVICES.len or count == 0) return 0;
    return switch (DEVICES[idx].kind) {
        .null_dev, .zero_dev, .random_dev, .kmsg => count, // sinks — pretend we wrote
        .usb0 => writeUsb(offset, buf, count),
    };
}

fn readUsb(offset: u32, buf: [*]u8, count: u32) u32 {
    const bs = xhci.getMscBlockSize();
    const bc = xhci.getMscBlockCount();
    if (bs == 0 or bc == 0) return 0xFFFFFFFF; // no MSC device
    if (bs != 512) return 0xFFFFFFFF; // only 512-byte sectors supported here
    if (offset % bs != 0 or count < bs) return 0xFFFFFFFF;
    const sector_count = count / bs;
    const start_lba = offset / bs;
    if (start_lba >= bc) return 0; // EOF — past end of device
    const max_avail = bc - start_lba;
    const take: u32 = @intCast(@min(@as(u64, sector_count), @as(u64, max_avail)));
    // mscReadSectors itself loops one sector at a time (data buffer limit),
    // so it's safe to call with `take` directly. Stop on the first failure
    // so the caller sees a short read rather than corrupt-mixed data.
    var done: u32 = 0;
    var s: u32 = 0;
    while (s < take) : (s += 1) {
        if (!xhci.mscReadSectors(start_lba + s, 1, buf + done)) break;
        done += bs;
    }
    return done;
}

fn writeUsb(offset: u32, buf: [*]const u8, count: u32) u32 {
    const bs = xhci.getMscBlockSize();
    const bc = xhci.getMscBlockCount();
    if (bs == 0 or bc == 0) return 0xFFFFFFFF;
    if (bs != 512) return 0xFFFFFFFF;
    if (offset % bs != 0 or count < bs) return 0xFFFFFFFF;
    const sector_count = count / bs;
    const start_lba = offset / bs;
    if (start_lba >= bc) return 0xFFFFFFFF;
    const max_avail = bc - start_lba;
    const take: u32 = @intCast(@min(@as(u64, sector_count), @as(u64, max_avail)));
    var done: u32 = 0;
    var s: u32 = 0;
    while (s < take) : (s += 1) {
        if (!xhci.mscWriteSectors(start_lba + s, 1, buf + done)) break;
        done += bs;
    }
    return done;
}

/// FileEntry layout duplicated from syscall.zig — keep in sync if the wire
/// format changes. We can't import syscall.zig (it depends on us), and the
/// struct is intentionally small/stable.
const FileEntry = extern struct {
    name: [32]u8,
    name_len: u8,
    file_size: u32 align(1),
    flags: u8,
    _pad: [10]u8,
};

/// Fill `entries[0..n]` with one record per device. Stops at `max` so
/// readdir's bounded buffer can't be overrun. Returns the number written.
pub fn listToBuffer(entries: [*]FileEntry, max: u32) u32 {
    var count: u32 = 0;
    for (DEVICES, 0..) |dev, i| {
        if (count >= max) break;
        var e: FileEntry = undefined;
        @memset(&e.name, 0);
        @memset(&e._pad, 0);
        const n = @min(dev.name.len, 32);
        @memcpy(e.name[0..n], dev.name[0..n]);
        e.name_len = @intCast(n);
        const sz = deviceSize(@intCast(i));
        e.file_size = if (sz > 0xFFFFFFFF) 0xFFFFFFFF else @intCast(sz);
        e.flags = 0;
        entries[count] = e;
        count += 1;
    }
    return count;
}

pub fn fileSize(rel: []const u8) ?u32 {
    const idx = openFile(rel) orelse return null;
    const sz = deviceSize(idx);
    if (sz > 0xFFFFFFFF) return 0xFFFFFFFF;
    return @intCast(sz);
}
