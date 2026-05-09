// shutdown — power off (default) or reboot the machine.
//
// Usage:
//   shutdown           power off
//   shutdown -r        reboot
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
        var arg: [8]u8 = undefined;
        const n = libc.getArgv(1, &arg);
        if (n != 0 and n != 0xFFFFFFFF) {
            const slice = arg[0..@min(@as(usize, @intCast(n)), arg.len)];
            if (argEquals(slice, "-r") or argEquals(slice, "--reboot")) mode = 1;
        }
    }

    if (mode == 1) {
        libc.print("Rebooting...\n");
    } else {
        libc.print("Shutting down...\n");
    }
    // Brief delay so the message lands before we yank the power.
    libc.sleep(100);
    libc.shutdown(mode);
    // If we get here, the platform didn't take the shutdown port.
    libc.print("\x1b[31mshutdown: platform did not respond\x1b[0m\n");
    libc.exit();
}
