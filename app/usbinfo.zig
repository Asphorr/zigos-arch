// usbinfo — print the connected USB Mass Storage device's parameters.
//
// Use it after attaching a usb-storage device in QEMU to confirm the kernel
// driver enumerated the disk and parsed READ CAPACITY correctly.

const libc = @import("libc");

export fn _start() linksection(".text.entry") callconv(.c) void {
    const info_opt = libc.usbInfo();
    if (info_opt == null) {
        libc.print("\x1b[31mNo USB Mass Storage device found.\x1b[0m\n");
        libc.print("Attach one in QEMU with -device usb-storage,...\n");
        libc.exit();
    }
    const info = info_opt.?;
    if (info.present == 0) {
        libc.print("\x1b[31mNo USB Mass Storage device.\x1b[0m\n");
        libc.exit();
    }

    libc.print("\x1b[1mUSB Mass Storage\x1b[0m\n");
    libc.print("  block size:  ");
    libc.printNum(info.block_size);
    libc.print(" bytes\n");
    libc.print("  block count: ");
    libc.printNum(info.block_count);
    libc.print("\n  total size:  ");
    // Capacity in bytes overflows u32 for >4GB drives — but our QEMU images
    // are small, so an approximate KiB/MiB readout via integer math is fine.
    const bytes_per_kib = 1024 / @as(u32, info.block_size);
    if (bytes_per_kib > 0) {
        const kib = info.block_count / bytes_per_kib;
        libc.printNum(kib);
        libc.print(" KiB (");
        libc.printNum(kib / 1024);
        libc.print(" MiB)\n");
    } else {
        libc.printNum(info.block_count * (info.block_size / 1024));
        libc.print(" KiB\n");
    }

    libc.exit();
}
