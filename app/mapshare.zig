// mapshare — end-to-end exercise of MAP_SHARED file mmap + writeback (Slice 3c).
//
// Unlike mmaptest.zig (which uses the *private* mmapFile snapshot), this drives
// the writable shared path: writes through the mapping land in the shared page-
// cache frame, are visible to read() and to a second mapping of the same file,
// and are written back to disk by msync()/munmap(). The flow:
//
//   1. create /mapshare.dat (2 pages) and fwrite a BASE pattern, close.
//   2. mmap_file_shared it → mapA; verify it fills from disk (sees BASE).
//   3. write a NEW pattern through mapA.
//   4. COHERENCE-1: a fresh read() on a *separate* fd must see NEW with NO
//      msync — the defining MAP_SHARED property (read & mapping share one frame).
//   5. COHERENCE-2: a second mmap_file_shared (mapB) must see NEW, and a write
//      through mapB must be visible through mapA — proving a single shared frame.
//   6. msync(mapA) then munmap(mapA): flush the frame to disk.
//   7. PERSISTENCE: re-open fresh and read() — must see the last pattern.
//
// On success: green `[mapshare] OK ...` to stdout + klog. On failure: a red
// message naming the step. Watch serial.log for `[3c] writeback inum=.. pages=..`
// lines (kernel disk-truth: emitted by syncCacheFile each time msync/munmap
// actually persists dirty pages) and `[pf] PID=N lazy fault-in 0x...` on the
// first touch of each mapped page.
//
// NOTE on "verify bytes hit disk": a single-run re-read (step 7) is served by
// the page cache, so on its own it can't distinguish disk from a clean-cache
// hit. The unambiguous disk signal is the `[3c] writeback` serial line; the
// definitive end-to-end persistence test is cross-boot (write+msync in one
// boot, read in the next), left as a follow-up.

const libc = @import("libc");

const PATH = "/mapshare.dat";
const N: usize = 8192; // 2 pages — exercises multi-page writeback + the dirty cursor

// One reusable buffer for the initial fwrite source and every read-back. The
// mmap slices are verified in place, so this is the only large buffer needed.
var iobuf: [N]u8 = undefined;

// Three deterministic, distinct byte patterns (wrapping arithmetic so no
// overflow panic). Distinctness is what makes the coherence checks meaningful:
// a stale BASE buffer can't masquerade as NEW across all 8192 bytes.
fn baseByte(i: usize) u8 {
    return @truncate(i *% 7 +% 1);
}
fn newByte(i: usize) u8 {
    return @truncate(i *% 3 +% 9);
}
fn new2Byte(i: usize) u8 {
    return @truncate(i *% 5 +% 3);
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

// Read exactly buf.len bytes (or until EOF). ext2 read can in principle return
// a short count; loop so the verification isn't a false failure.
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
    libc.print("\x1b[31m[mapshare] FAIL: ");
    libc.print(msg);
    libc.print("\x1b[0m\n");
    libc.klog("[mapshare] FAIL\n");
    libc.exit();
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    libc.print("[mapshare] start: MAP_SHARED file mmap + writeback (2 pages)\n");

    // 1. Create the file and write the BASE pattern to disk.
    const fdw = libc.openFlags(PATH, libc.O_CREATE | libc.O_TRUNC) orelse
        fail("openFlags(O_CREATE) failed");
    fill(iobuf[0..N], &baseByte);
    if (libc.fwrite(fdw, iobuf[0..N]) != N) fail("fwrite BASE short");
    libc.close(fdw);

    // 2. Map it shared and confirm the mapping fills from disk (sees BASE).
    const fda = libc.open(PATH) orelse fail("open for mmap failed");
    const mapA = libc.mmapFileShared(fda, 0, N) orelse fail("mmap_file_shared(A) failed");
    if (mapA.len < N) fail("mapA too short");
    if (mismatches(mapA[0..N], &baseByte) != 0) fail("mapA did not fill BASE from disk");
    libc.print("[mapshare]  step2 ok: shared mapping filled BASE from disk\n");

    // 3. Write the NEW pattern through the shared mapping (dirties the frame).
    fill(mapA[0..N], &newByte);

    // 4. COHERENCE-1: a separate read() fd must observe NEW with no msync — the
    //    read path (readThroughCache) pins the very frame the mapping wrote.
    const fdb = libc.open(PATH) orelse fail("open for coherence read failed");
    if (readFull(fdb, iobuf[0..N]) != N) fail("coherence read short");
    libc.close(fdb);
    if (mismatches(iobuf[0..N], &newByte) != 0)
        fail("read() did NOT see the un-synced mmap write (no shared frame!)");
    libc.print("[mapshare]  step4 ok: read() saw the un-synced mmap write (shared frame)\n");

    // 5. COHERENCE-2: a second shared mapping must see NEW, and writing NEW2
    //    through it must be visible through mapA — one frame behind two VAs.
    const mapB = libc.mmapFileShared(fda, 0, N) orelse fail("mmap_file_shared(B) failed");
    if (mapB.len < N) fail("mapB too short");
    if (mismatches(mapB[0..N], &newByte) != 0) fail("mapB did not see NEW (separate frame?)");
    fill(mapB[0..N], &new2Byte);
    if (mismatches(mapA[0..N], &new2Byte) != 0)
        fail("write via mapB not visible through mapA (separate frame!)");
    _ = libc.munmap(mapB); // mapA still maps the frame → stays dirty (refcount > 1)
    libc.print("[mapshare]  step5 ok: two mappings share one frame (A<->B coherent)\n");

    // 6. Persist: msync (mapping stays live) then munmap (final flush + clear).
    if (!libc.msync(mapA)) fail("msync(mapA) returned false");
    if (!libc.munmap(mapA)) fail("munmap(mapA) returned false");
    libc.close(fda);
    libc.print("[mapshare]  step6 ok: msync + munmap flushed (see [3c] writeback in serial)\n");

    // 7. PERSISTENCE: re-open fresh and read — must see the last pattern (NEW2).
    const fdc = libc.open(PATH) orelse fail("re-open for persistence read failed");
    if (readFull(fdc, iobuf[0..N]) != N) fail("persistence read short");
    libc.close(fdc);
    if (mismatches(iobuf[0..N], &new2Byte) != 0) fail("persisted bytes != NEW2");
    libc.print("[mapshare]  step7 ok: re-read after unmap saw the synced pattern\n");

    _ = libc.unlink(PATH);
    libc.print("\x1b[32m[mapshare] OK (fill-from-disk + read coherence + 2-map coherence + msync/munmap persist)\x1b[0m\n");
    libc.klog("[mapshare] OK\n");
    libc.exit();
}
