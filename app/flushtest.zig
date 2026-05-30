// flushtest — prove the background writeback daemon (pgflushd, Slice 3d-2)
// persists a dirty shared mapping on its own, with NO msync and NO munmap.
//
// mapshare.zig proves the *explicit* flush path (msync/munmap → [3c] writeback).
// This proves the *implicit, periodic* one: a long-lived process dirties a
// MAP_SHARED file page and then just sits there. pgflushd wakes every 2s,
// walks the page cache for dirty pages (takeNextDirtyGlobal), and writes them
// back (ext2.writebackPage). Because the mapping is still live (frame refcount
// > 1), the refcount-gated dirty-clear leaves the page dirty — so durability is
// periodic, not one-shot, and a crash loses at most one interval's writes.
//
// The flow:
//   1. create /flushtest.dat (2 pages), fwrite a BASE pattern, close.
//   2. mmap_file_shared it → mapA; verify it fills BASE from disk.
//   3. write a NEW pattern through mapA  → dirties 2 cache frames.
//   4. SLEEP ~3s holding the mapping. A 3s window always contains a pgflushd
//      tick (2s period), so the daemon flushes our 2 pages mid-sleep.
//   5. after waking, assert the live mapping is intact (NEW) — the concurrent
//      writeback read the frame but must not disturb it — and that a separate
//      read() fd is still coherent.
//   6. munmap (cleanup) + unlink.
//
// DISK-TRUTH PROOF is in serial.log: a `[3d] pgflushd wrote 2 dirty page(s)`
// line emitted *between* the "sleeping" and "woke" markers below, i.e. with no
// msync and no munmap having run. The munmap in step 6 emits a separate
// `[3c] writeback` line — distinguishable by tag and by appearing only after
// the "woke" marker. (A userspace re-read can't be disk-truth: read() is served
// from the same cache frame, so it's coherent regardless of whether the bytes
// reached the platter. The kernel trace is the ground truth.)

const libc = @import("libc");

const PATH = "/flushtest.dat";
const N: usize = 8192; // 2 pages — pgflushd reports "wrote 2 dirty page(s)"
const SLEEP_MS: u32 = 3000; // > pgflushd's 2000ms period → always catches a tick

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
    libc.print("\x1b[31m[flushtest] FAIL: ");
    libc.print(msg);
    libc.print("\x1b[0m\n");
    libc.klog("[flushtest] FAIL\n");
    libc.exit();
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    libc.print("[flushtest] start: background writeback daemon (pgflushd) persists a live mapping\n");

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
    libc.print("[flushtest]  step2 ok: shared mapping filled BASE from disk\n");

    // 3. Dirty the mapping with NEW — but do NOT msync. Only pgflushd will flush.
    fill(mapA[0..N], &newByte);
    libc.print("[flushtest]  step3 ok: wrote NEW through mapping (2 pages now dirty, NOT synced)\n");

    // 4. Hold the dirty mapping live across at least one pgflushd tick.
    libc.print("[flushtest]  sleeping ~3s — watch serial for [3d] pgflushd wrote 2 dirty page(s) ...\n");
    libc.klog("[flushtest] sleeping (no msync/munmap held) — pgflushd should flush now\n");
    libc.sleep(SLEEP_MS);
    libc.klog("[flushtest] woke — any [3d] writeback above happened with NO msync/munmap\n");
    libc.print("[flushtest]  woke: pgflushd had its window (see [3d] line above, between the markers)\n");

    // 5. The concurrent writeback read our frame; the live mapping must be intact,
    //    and a separate read() fd must still be coherent with it.
    if (mismatches(mapA[0..N], &newByte) != 0)
        fail("live mapping corrupted by background flush");
    const fdb = libc.open(PATH) orelse fail("open for coherence read failed");
    if (readFull(fdb, iobuf[0..N]) != N) fail("coherence read short");
    libc.close(fdb);
    if (mismatches(iobuf[0..N], &newByte) != 0)
        fail("read() not coherent with mapping after background flush");
    libc.print("[flushtest]  step5 ok: mapping intact + read() coherent after the flush\n");

    // 6. Cleanup. munmap emits its own [3c] writeback (clear=true) AFTER the woke
    //    marker — that's the explicit path, distinct from pgflushd's [3d] above.
    if (!libc.munmap(mapA)) fail("munmap returned false");
    libc.close(fda);
    _ = libc.unlink(PATH);

    libc.print("\x1b[32m[flushtest] OK — pgflushd persisted a dirty mapping with no msync/munmap (proof: [3d] line in serial)\x1b[0m\n");
    libc.klog("[flushtest] OK\n");
    libc.exit();
}
