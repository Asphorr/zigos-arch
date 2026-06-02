// pmemdax — exercise /dev/pmem0 byte I/O + DAX mmap (NVDIMM N3).
//
// Proves the two userspace access paths reach the SAME physical persistent
// memory:
//   1. DAX mmap (sys mmap_pmem #121): the returned pages point straight at the
//      pmem frames, so stores land in persistent memory with no page-cache copy.
//   2. /dev/pmem0 byte read/write (seek + fread/fwrite through devfs).
//
// Flow:
//   - DAX-map one page at offset DAX_OFF (clear of the N2 boot-counter header at
//     offset 0).
//   - write SIG THROUGH the mapping, read it back via the FILE path → must match
//     (a DAX store is visible to read() ⇒ one physical memory).
//   - write REV via the FILE path, read it back THROUGH the mapping → must match
//     (a file write is visible to the mapping ⇒ bidirectional).
//   - a SECOND DAX mapping of the same window must observe both patterns (two
//     VAs over one physical frame — the defining shared-physical property).
//
// On success: green [pmemdax] PASS + klog. On failure: a red message naming the
// step (and klog). Run it from the shell: `pmemdax`.

const libc = @import("libc");

const PATH = "/dev/pmem0";
const PAGE: usize = 4096;
const DAX_OFF: u32 = 4096; // page-aligned; past the N2 header at offset 0
const SIG = "ZIGOS-DAX-DIRECT-WRITE"; // written THROUGH the DAX mapping
const REV = "FILE-PATH-WROTE-THIS"; // written through the /dev/pmem0 file path
const REV_OFF = 512; // where REV sits within the mapped page

fn fail(msg: []const u8) noreturn {
    libc.print("\x1b[31m[pmemdax] FAIL: ");
    libc.print(msg);
    libc.print("\x1b[0m\n");
    // Mirror the reason to the kernel log so a failure is diagnosable from
    // serial.log alone (the step trail above is console-only).
    libc.klog("[pmemdax] FAIL: ");
    libc.klog(msg);
    libc.klog("\n");
    libc.exit();
}

fn eql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, 0..) |c, i| if (c != b[i]) return false;
    return true;
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    libc.print("[pmemdax] start: /dev/pmem0 byte I/O + DAX mmap\n");

    const fd = libc.open(PATH) orelse fail("open /dev/pmem0 (no NVDIMM?)");

    // 1. DAX-map one page directly onto the pmem frames.
    const map = libc.mmapPmem(fd, DAX_OFF, PAGE) orelse fail("mmap_pmem failed");
    if (map.len < PAGE) fail("DAX mapping too short");
    libc.print("[pmemdax]  step1 ok: DAX mapping established (1 page @ pmem+4096)\n");

    // 2. Write SIG through the mapping; read it back via the file path.
    for (SIG, 0..) |c, i| map[i] = c;
    var rbuf: [64]u8 = undefined;
    _ = libc.seek(fd, DAX_OFF, 0) orelse fail("seek to DAX_OFF failed");
    if (libc.fread(fd, rbuf[0..SIG.len]) != SIG.len) fail("file read short");
    if (!eql(rbuf[0..SIG.len], SIG))
        fail("DAX store NOT visible via /dev/pmem0 read (different memory!)");
    libc.print("[pmemdax]  step2 ok: DAX store read back through /dev/pmem0 — same pmem\n");

    // 3. Write REV via the file path; read it back through the mapping.
    _ = libc.seek(fd, DAX_OFF + REV_OFF, 0) orelse fail("seek for file write failed");
    if (libc.fwrite(fd, REV) != REV.len) fail("file write short");
    if (!eql(map[REV_OFF .. REV_OFF + REV.len], REV))
        fail("file write NOT visible through DAX mapping (different memory!)");
    libc.print("[pmemdax]  step3 ok: /dev/pmem0 write visible through DAX mapping — bidirectional\n");

    // 4. A second DAX mapping of the same window must see both patterns.
    const map2 = libc.mmapPmem(fd, DAX_OFF, PAGE) orelse fail("second mmap_pmem failed");
    if (!eql(map2[0..SIG.len], SIG)) fail("second mapping missing SIG (not a shared frame!)");
    if (!eql(map2[REV_OFF .. REV_OFF + REV.len], REV)) fail("second mapping missing REV");
    libc.print("[pmemdax]  step4 ok: two DAX mappings share one physical frame\n");

    _ = libc.munmap(map2);
    _ = libc.munmap(map);
    libc.close(fd);

    libc.print("\x1b[32m[pmemdax] PASS — /dev/pmem0 + DAX address the same persistent memory\x1b[0m\n");
    libc.klog("[pmemdax] PASS\n");
    libc.exit();
}
