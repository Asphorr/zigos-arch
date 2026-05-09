// usbwrite — write text to a USB MSC sector. Round-trip test for the
// WRITE(10) path; pair with `usbcat <lba>` to read it back.
//
// Usage:
//   usbwrite <lba> <text...>          (text is argv[2..] joined by spaces)
//
// The buffer is zero-padded to the device's block size, then submitted as a
// single SCSI WRITE(10). Argv is capped at 32 chars per arg × 8 args by the
// kernel, which is plenty for the demonstration.

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

export fn _start() linksection(".text.entry") callconv(.c) void {
    const argc = libc.getArgc();
    if (argc < 3) {
        libc.print("\x1b[31musbwrite: usage: usbwrite <lba> <text...>\x1b[0m\n");
        libc.exit();
    }

    var lba_buf: [12]u8 = undefined;
    const lba_len = libc.getArgv(1, &lba_buf);
    if (lba_len == 0 or lba_len == 0xFFFFFFFF) {
        libc.print("\x1b[31musbwrite: bad LBA\x1b[0m\n");
        libc.exit();
    }
    const lba = parseU32(lba_buf[0..lba_len]) orelse {
        libc.print("\x1b[31musbwrite: LBA must be a non-negative integer\x1b[0m\n");
        libc.exit();
    };

    const info_opt = libc.usbInfo();
    if (info_opt == null or info_opt.?.present == 0) {
        libc.print("\x1b[31musbwrite: no USB device\x1b[0m\n");
        libc.exit();
    }
    const info = info_opt.?;
    if (lba >= info.block_count) {
        libc.print("\x1b[31musbwrite: lba out of range\x1b[0m\n");
        libc.exit();
    }
    if (info.block_size != 512) {
        libc.print("\x1b[31musbwrite: only 512-byte sectors supported\x1b[0m\n");
        libc.exit();
    }

    var sector: [512]u8 = [_]u8{0} ** 512;
    var off: usize = 0;
    var i: u32 = 2;
    while (i < argc) : (i += 1) {
        if (i > 2 and off < sector.len) {
            sector[off] = ' ';
            off += 1;
        }
        var arg: [40]u8 = undefined;
        const n = libc.getArgv(i, &arg);
        if (n == 0 or n == 0xFFFFFFFF) continue;
        const take = if (off + n > sector.len) sector.len - off else n;
        if (take == 0) break;
        @memcpy(sector[off..][0..take], arg[0..take]);
        off += take;
    }

    if (!libc.usbWriteSector(lba, &sector)) {
        libc.print("\x1b[31musbwrite: write failed\x1b[0m\n");
        libc.exit();
    }

    libc.print("wrote ");
    libc.printNum(@intCast(off));
    libc.print(" bytes to LBA ");
    libc.printNum(lba);
    libc.print(" (rest zeroed)\n");
    libc.exit();
}
