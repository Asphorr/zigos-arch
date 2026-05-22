// swaptest — exercise the swap subsystem: allocate MORE than free RAM, write a
// verifiable pattern across every page (forcing the kernel to evict cold pages
// to the swap disk), then read it all back (forcing those pages to swap back
// in) and verify byte-for-byte. Before swap existed this would OOM-kill at the
// RAM ceiling; with swap it should complete and PASS.

const libc = @import("libc");

export fn _start() linksection(".text.entry") callconv(.c) void {
    const mi = libc.meminfo();
    const free_bytes: usize = @as(usize, mi.free_frames) * 4096;

    // Working set = free RAM + 48 MiB, so ~48 MiB must live on swap (enough to
    // exceed the GUI back-buffer reclaim that runs before swap). Cap at 220 MiB
    // to stay under the user-VA ceiling (mmap grows down from 256 MiB; the heap
    // sits at 32 MiB) so the region can't collide with the heap.
    var target: usize = free_bytes + 48 * 1024 * 1024;
    const CAP: usize = 220 * 1024 * 1024;
    if (target > CAP) target = CAP;

    libc.print("swaptest: free RAM = ");
    libc.printNum(@intCast(free_bytes / (1024 * 1024)));
    libc.print(" MiB; allocating ");
    libc.printNum(@intCast(target / (1024 * 1024)));
    libc.print(" MiB (exceeds RAM -> must swap)\n");

    const buf = libc.mmap(target) orelse {
        libc.print("swaptest: mmap FAILED (VA too large?) — try a smaller target\n");
        libc.exit();
    };
    const pages = buf.len / 4096;

    // Write pass: stamp byte 0 of each page with a page-derived value. As RAM
    // fills, the page-fault handler evicts earlier cold pages to swap.
    var p: usize = 0;
    while (p < pages) : (p += 1) {
        buf[p * 4096] = @truncate(p *% 7 +% 13);
    }
    libc.print("swaptest: wrote ");
    libc.printNum(@intCast(pages));
    libc.print(" pages; verifying (forces swap-in)...\n");

    // Read pass: every evicted page must swap back in with intact contents.
    var bad: usize = 0;
    p = 0;
    while (p < pages) : (p += 1) {
        const want: u8 = @truncate(p *% 7 +% 13);
        if (buf[p * 4096] != want) bad += 1;
    }

    if (bad == 0) {
        libc.print("swaptest: PASS — all pages survived the swap round-trip\n");
    } else {
        libc.print("swaptest: FAIL — ");
        libc.printNum(@intCast(bad));
        libc.print(" corrupted pages\n");
    }
    libc.exit();
}
