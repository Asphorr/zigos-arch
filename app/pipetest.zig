// Programmatic pipeline test — exercises pipe + execAs + waitpid + kill in
// one shot. Wires this process's pipe write-end to wc.elf's stdin (fd 0),
// writes a known payload, closes the write end (so wc sees EOF), waitpid's,
// and exits with status 0xCAFE if everything matched.
//
// Auto-launched at boot so the serial log captures the result without needing
// keyboard input. Look for "[pipetest] OK" in serial.log.

const libc = @import("libc");

export fn _start() linksection(".text.entry") callconv(.c) void {
    libc.print("[pipetest] starting\n");

    const fds = libc.pipe() orelse {
        libc.print("[pipetest] FAIL: pipe alloc\n");
        libc.exitWith(0xDEAD0001);
    };
    const r_fd = fds[0];
    const w_fd = fds[1];

    // Spawn wc.elf with its stdin (fd 0) wired to the pipe read end.
    const remap: [1]libc.FdRemap = .{
        .{ .parent_fd = @truncate(r_fd), .child_fd = 0 },
    };
    const child = libc.execAs("wc.elf", &remap);
    if (child == 0xFFFFFFFF) {
        libc.print("[pipetest] FAIL: execAs wc.elf\n");
        libc.close(r_fd);
        libc.close(w_fd);
        libc.exitWith(0xDEAD0002);
    }

    // Write a known payload — 4 lines, 32 bytes.
    const payload = "hello\nfrom\npipetest\nto wc!!\n"; // 28 bytes, 4 newlines
    const wrote = libc.fwrite(w_fd, payload);
    if (wrote != payload.len) {
        libc.print("[pipetest] FAIL: short write\n");
        _ = libc.kill(child, libc.SIGKILL);
        var st_k: u32 = 0;
        _ = libc.waitpid(child, &st_k);
        libc.close(r_fd);
        libc.close(w_fd);
        libc.exitWith(0xDEAD0003);
    }

    // Drop both pipe ends — child sees EOF, parent's writers refcount goes to 0.
    libc.close(r_fd);
    libc.close(w_fd);

    // Wait for wc to print + exit.
    var status: u32 = 0;
    const reaped = libc.waitpid(child, &status);
    if (reaped == 0xFFFFFFFF) {
        libc.print("[pipetest] FAIL: waitpid\n");
        libc.exitWith(0xDEAD0004);
    }

    libc.print("[pipetest] reaped pid=");
    libc.printNum(reaped);
    libc.print(" status=0x");
    libc.printHex(status);
    libc.print("\n[pipetest] OK\n");
    libc.exitWith(0xCAFE0000);
}
