// usbcat — dump one sector of the USB Mass Storage device in hex+ASCII.
//
// Usage:
//   usbcat            (sector 0)
//   usbcat 5          (sector 5)
//
// This is the user-space side of `mscReadSectors` — it confirms the bulk-IN
// path actually returns data, and is enough to identify a FAT or MBR
// partition table at LBA 0 (`55 AA` magic at bytes 510..512).

const libc = @import("libc");

fn parseU32(s: []const u8) ?u32 {
    if (s.len == 0) return null;
    var v: u32 = 0;
    for (s) |c| {
        if (c < '0' or c > '9') return null;
        v = v * 10 + (c - '0');
    }
    return v;
}

fn printHex2(b: u8) void {
    const hex = "0123456789abcdef";
    libc.printChar(hex[b >> 4]);
    libc.printChar(hex[b & 0x0F]);
}

fn printHexAddr(addr: u32) void {
    const hex = "0123456789abcdef";
    var k: i32 = 7;
    while (k >= 0) : (k -= 1) {
        const nib: u4 = @intCast((addr >> @intCast(k * 4)) & 0xF);
        libc.printChar(hex[nib]);
    }
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    var lba: u32 = 0;
    if (libc.getArgc() >= 2) {
        var b: [12]u8 = undefined;
        const n = libc.getArgv(1, &b);
        if (n != 0 and n != 0xFFFFFFFF) {
            lba = parseU32(b[0..n]) orelse 0;
        }
    }

    const info_opt = libc.usbInfo();
    if (info_opt == null or info_opt.?.present == 0) {
        libc.print("\x1b[31musbcat: no USB device\x1b[0m\n");
        libc.exit();
    }
    const info = info_opt.?;
    if (lba >= info.block_count) {
        libc.print("\x1b[31musbcat: lba out of range\x1b[0m\n");
        libc.exit();
    }

    if (info.block_size != 512) {
        libc.print("\x1b[31musbcat: only 512-byte sectors supported in this dumper\x1b[0m\n");
        libc.exit();
    }

    var buf: [512]u8 = undefined;
    if (!libc.usbReadSector(lba, &buf)) {
        libc.print("\x1b[31musbcat: read failed\x1b[0m\n");
        libc.exit();
    }

    libc.print("\x1b[1msector ");
    libc.printNum(lba);
    libc.print("\x1b[0m\n");

    var off: u32 = 0;
    while (off < 512) : (off += 16) {
        printHexAddr(off);
        libc.print("  ");
        for (0..16) |i| {
            printHex2(buf[off + i]);
            libc.printChar(' ');
            if (i == 7) libc.printChar(' ');
        }
        libc.print(" |");
        for (0..16) |i| {
            const c = buf[off + i];
            if (c >= 0x20 and c <= 0x7E) libc.printChar(c) else libc.printChar('.');
        }
        libc.print("|\n");
    }

    libc.exit();
}
