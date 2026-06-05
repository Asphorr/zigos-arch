// shutdown — power off (default) or reboot the machine.
//
// Usage:
//   shutdown           power off
//   shutdown -r        reboot
//   shutdown -s        suspend to RAM (S3)
//
// Calls the kernel via syscall 82, which flushes FAT caches and pokes
// the ACPI/PCI reset ports. Under QEMU, poweroff exits the VM cleanly.

const libc = @import("libc");

fn argEquals(buf: []const u8, lit: []const u8) bool {
    if (buf.len != lit.len) return false;
    for (buf, lit) |a, b| if (a != b) return false;
    return true;
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    var mode: u32 = 0; // poweroff
    if (libc.getArgc() >= 2) {
        var arg: [10]u8 = undefined;
        const n = libc.getArgv(1, &arg);
        if (n != 0 and n != 0xFFFFFFFF) {
            const slice = arg[0..@min(@as(usize, @intCast(n)), arg.len)];
            if (argEquals(slice, "-r") or argEquals(slice, "--reboot")) mode = 1;
            if (argEquals(slice, "-s") or argEquals(slice, "--suspend")) mode = 2;
        }
    }

    if (mode == 1) {
        libc.print("Rebooting...\n");
    } else if (mode == 2) {
        libc.print("Suspending to RAM (S3)...\n");
    } else {
        libc.print("Shutting down...\n");
    }
    // Brief delay so the message lands before we yank the power.
    libc.sleep(100);
    libc.shutdown(mode);
    // If we get here: modes 0/1 mean the platform ignored the request; mode 2
    // (S3) means we resumed — or entry was rejected. The kernel logs which.
    if (mode == 2) {
        libc.print("Resumed from S3 (or suspend rejected — see serial).\n");
    } else {
        libc.print("\x1b[31mshutdown: platform did not respond\x1b[0m\n");
    }
    libc.exit();
}
