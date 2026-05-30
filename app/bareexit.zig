// bareexit — prove Slice 3d-2b: a process that writes a MAP_SHARED file and then
// exits WITHOUT msync OR munmap still has its final window of writes persisted
// to disk by pgflushd.
//
// This is the case mapshare/flushtest deliberately did NOT cover. mapshare
// flushes explicitly (msync + munmap); flushtest holds the mapping live across a
// daemon tick. Here the process just *exits* with the dirty mapping still
// mapped and never synced. Before Slice 3d-2b, process teardown CLEARED the
// dirty bit (clearDirtyRangeCacheOnly) to keep the page evictable — silently
// discarding the unflushed writes. 3d-2b makes the *graceful* exit path (the
// voluntary sys_exit / exit_status syscalls) LEAVE the page dirty, so pgflushd
// writes it back within ≤1 interval. (The OOM-kill / fatal-fault / external-kill
// paths still clear, to free memory immediately under pressure.)
//
//   1. create /bareexit.dat (2 pages), fwrite a BASE pattern, close.
//   2. mmap_file_shared → verify it fills BASE from disk.
//   3. write a NEW pattern through the mapping (dirties 2 cache frames).
//   4. sanity: a separate read() fd sees NEW (cache coherence) — confirms the
//      write landed before we exit. (Not a disk proof: read() shares the frame.)
//   5. exit() — NO msync, NO munmap. The mapping is still live at teardown.
//
// PROOF is in serial.log: a `[3d] pgflushd wrote 2 dirty page(s)` line appears
// AFTER `[bareexit] exiting ...`, with no msync/munmap ever issued. That line
// existing at all is the proof: the process is gone and never synced, so the
// ONLY thing that can persist those pages is pgflushd finding them still dirty —
// which only happens because the graceful-exit teardown left them dirty. Without
// 3d-2b the exit would have cleared the bit and pgflushd would find nothing.
//
// The file is intentionally NOT unlinked, so it survives for inspection.

const libc = @import("libc");

const PATH = "/bareexit.dat";
const N: usize = 8192; // 2 pages

var iobuf: [N]u8 = undefined;

fn baseByte(i: usize) u8 {
    return @truncate(i *% 7 +% 1);
}
fn newByte(i: usize) u8 {
    return @truncate(i *% 3 +% 9);
}

const ByteFn = *const fn (usize) u8;

fn mismatches(data: []const u8, f: ByteFn) usize {
    var bad: usize = 0;
    for (data, 0..) |b, i| {
        if (b != f(i)) bad += 1;
    }
    return bad;
}

fn fill(data: []u8, f: ByteFn) void {
    for (data, 0..) |*b, i| b.* = f(i);
}

fn readFull(fd: u32, buf: []u8) usize {
    var total: usize = 0;
    while (total < buf.len) {
        const n = libc.fread(fd, buf[total..]);
        if (n == 0) break; // EOF
        total += n;
    }
    return total;
}

fn fail(msg: []const u8) noreturn {
    libc.print("\x1b[31m[bareexit] FAIL: ");
    libc.print(msg);
    libc.print("\x1b[0m\n");
    libc.klog("[bareexit] FAIL\n");
    libc.exit();
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    libc.print("[bareexit] start: graceful exit with NO msync/munmap must still persist (Slice 3d-2b)\n");

    // 1. Create the file and write BASE to disk.
    const fdw = libc.openFlags(PATH, libc.O_CREATE | libc.O_TRUNC) orelse
        fail("openFlags(O_CREATE) failed");
    fill(iobuf[0..N], &baseByte);
    if (libc.fwrite(fdw, iobuf[0..N]) != N) fail("fwrite BASE short");
    libc.close(fdw);

    // 2. Map it shared; confirm it fills BASE from disk.
    const fda = libc.open(PATH) orelse fail("open for mmap failed");
    const mapA = libc.mmapFileShared(fda, 0, N) orelse fail("mmap_file_shared failed");
    if (mapA.len < N) fail("mapA too short");
    if (mismatches(mapA[0..N], &baseByte) != 0) fail("mapA did not fill BASE from disk");

    // 3. Dirty the mapping with NEW — never msync'd.
    fill(mapA[0..N], &newByte);

    // 4. Sanity (cache coherence, not disk): a separate read() sees NEW, proving
    //    the write took effect before we exit. The DISK proof is the post-exit [3d].
    const fdb = libc.open(PATH) orelse fail("open for sanity read failed");
    if (readFull(fdb, iobuf[0..N]) != N) fail("sanity read short");
    libc.close(fdb);
    if (mismatches(iobuf[0..N], &newByte) != 0) fail("read() did not see the mmap write");
    libc.print("[bareexit]  wrote NEW through mapping; read() coherent (2 pages now dirty)\n");

    // 5. Bare exit: leave fda open, mapA mapped, NO msync, NO munmap. The
    //    graceful teardown path leaves the dirty pages in the cache so pgflushd
    //    persists them within ≤2s — watch serial for the [3d] line AFTER this.
    libc.print("[bareexit]  exiting now with NO msync/munmap — watch serial for [3d] pgflushd wrote 2 dirty page(s)\n");
    libc.klog("[bareexit] exiting (mapping still dirty + live) — pgflushd must persist the final window\n");
    libc.exit();
}
