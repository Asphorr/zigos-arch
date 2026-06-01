// rndtest — exercise the getrandom syscall (#120) from userland.
//
// Prints 32 CSPRNG bytes as hex and sanity-checks them: not all-zero, and
// two consecutive calls must differ. Quick proof that libc.getRandom →
// kernel crypto/random.fillRandom is wired end to end.

const libc = @import("libc");

fn hexNibble(n: u8) u8 {
    return if (n < 10) '0' + n else 'a' + (n - 10);
}

fn printHex(bytes: []const u8) void {
    for (bytes) |b| {
        const pair = [2]u8{ hexNibble(b >> 4), hexNibble(b & 0xF) };
        libc.print(&pair);
    }
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    var a: [32]u8 = undefined;
    if (!libc.getRandom(&a)) {
        libc.print("\x1b[31mrndtest: getrandom syscall failed\x1b[0m\n");
        libc.exit();
    }

    libc.print("getrandom[0] : ");
    printHex(&a);
    libc.print("\n");

    var b: [32]u8 = undefined;
    _ = libc.getRandom(&b);
    libc.print("getrandom[1] : ");
    printHex(&b);
    libc.print("\n");

    var all_zero = true;
    for (a) |x| {
        if (x != 0) all_zero = false;
    }
    var identical = true;
    for (a, b) |x, y| {
        if (x != y) identical = false;
    }

    if (all_zero) {
        libc.print("\x1b[31mFAIL: buffer is all zero — CSPRNG not filling\x1b[0m\n");
    } else if (identical) {
        libc.print("\x1b[31mFAIL: two calls returned identical bytes\x1b[0m\n");
    } else {
        libc.print("\x1b[32mOK: non-zero, and two calls differ\x1b[0m\n");
    }
    libc.exit();
}
