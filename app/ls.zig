// ls — list files in the current working directory.
//
// Uses libc.readdir(cwd) (the path-aware syscall 42) so `cd /dev && ls`
// enumerates device files, `cd /fat && ls` shows the FAT32 root, etc. Falls
// back to libc.listdir (which is FAT32-only) if cwd is unreadable, so a
// process started with no cwd still gets a useful default.

const libc = @import("libc");

export fn _start() linksection(".text.entry") callconv(.c) void {
    var entries: [64]libc.FileEntry = undefined;
    var cwd_buf: [256]u8 = undefined;
    const cwd = libc.getCwd(&cwd_buf);

    const n = if (cwd) |path| blk: {
        const got = libc.readdir(path, &entries);
        if (got == 0) break :blk libc.listdir(&entries);
        break :blk got;
    } else libc.listdir(&entries);

    for (entries[0..n]) |e| {
        // FileEntry.name is null-terminated in a fixed buffer; print until 0.
        var len: usize = 0;
        while (len < e.name.len and e.name[len] != 0) : (len += 1) {}
        libc.print(e.name[0..len]);
        libc.printChar('\n');
    }
    libc.exit();
}
