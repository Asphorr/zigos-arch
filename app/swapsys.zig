// swapsys — prove the kernel can READ from and WRITE into a user buffer whose
// pages have been evicted to swap (Phase 3 / Gap A1). swaptest already covers
// DIRECT (CPU-fault) swap-in; this covers SYSCALL access: validateUserPtr ->
// prefaultUserRange must page a swapped buffer back in instead of returning
// E_FAULT. We allocate more than RAM (forcing eviction), then round-trip an
// early (now-swapped) slice through a pipe:
//   fwrite(pipe_w, &buf[early])  -> kernel READS a swapped page
//   fread (pipe_r, &buf[early2]) -> kernel WRITES into a swapped page
// Before A1, the first of these returned E_FAULT (or a short count).

const libc = @import("libc");

fn pat(i: usize) u8 {
    return @truncate(i *% 31 +% 7);
}
fn pat2(i: usize) u8 {
    return @truncate(i *% 13 +% 91);
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    const mi = libc.meminfo();
    const free_bytes: usize = @as(usize, mi.free_frames) * 4096;
    var target: usize = free_bytes + 48 * 1024 * 1024;
    const CAP: usize = 220 * 1024 * 1024;
    if (target > CAP) target = CAP;

    libc.print("swapsys: free RAM = ");
    libc.printNum(@intCast(free_bytes / (1024 * 1024)));
    libc.print(" MiB; allocating ");
    libc.printNum(@intCast(target / (1024 * 1024)));
    libc.print(" MiB to force eviction\n");

    const buf = libc.mmap(target) orelse {
        libc.print("swapsys: mmap FAILED\n");
        libc.exit();
    };
    const pages = buf.len / 4096;

    // Fill every byte; as RAM fills, early pages get evicted to swap.
    var i: usize = 0;
    while (i < buf.len) : (i += 1) buf[i] = pat(i);

    // Read-back pass: faults churn the working set through swap so that the
    // early pages we poke via syscalls below end up evicted again.
    var bad_direct: usize = 0;
    i = 0;
    while (i < pages) : (i += 1) {
        if (buf[i * 4096] != pat(i * 4096)) bad_direct += 1;
    }

    const fds = libc.pipe() orelse {
        libc.print("swapsys: pipe FAILED\n");
        libc.exit();
    };
    const rd = fds[0];
    const wr = fds[1];

    const N: usize = 256;
    var tmp: [N]u8 = undefined;

    // --- Test 1: KERNEL READ of a (likely swapped) page ---
    // fwrite makes the kernel read buf[0..N]. Page 0 was written first, so
    // after the churn it is almost certainly on swap. If A1 works the kernel
    // swaps it in and the bytes round-trip; otherwise fwrite hits an unmapped
    // page -> short write / E_FAULT.
    const wrote = libc.fwrite(wr, buf[0..N]);
    const got = libc.fread(rd, tmp[0..N]);
    var read_ok = (wrote == N and got == N);
    if (read_ok) {
        var j: usize = 0;
        while (j < N) : (j += 1) {
            if (tmp[j] != pat(j)) {
                read_ok = false;
                break;
            }
        }
    }

    // --- Test 2: KERNEL WRITE into a (likely swapped) page ---
    // fwrite a distinct stack pattern into the pipe, then fread it back INTO an
    // early buffer page: the kernel must swap that page in, then write to it.
    const off: usize = 4096 * 8; // page 8, also long-cold
    var src: [N]u8 = undefined;
    var k: usize = 0;
    while (k < N) : (k += 1) src[k] = pat2(k);
    const wrote2 = libc.fwrite(wr, src[0..N]);
    const got2 = libc.fread(rd, buf[off .. off + N]);
    var write_ok = (wrote2 == N and got2 == N);
    if (write_ok) {
        k = 0;
        while (k < N) : (k += 1) {
            if (buf[off + k] != pat2(k)) {
                write_ok = false;
                break;
            }
        }
    }

    libc.print("swapsys: direct-verify bad pages = ");
    libc.printNum(@intCast(bad_direct));
    libc.print("\n");

    if (read_ok and write_ok and bad_direct == 0) {
        libc.print("swapsys: PASS — kernel read AND wrote swapped pages via syscalls\n");
    } else {
        const ro: usize = if (read_ok) 1 else 0;
        const wo: usize = if (write_ok) 1 else 0;
        libc.print("swapsys: FAIL — read_ok=");
        libc.printNum(@intCast(ro));
        libc.print(" write_ok=");
        libc.printNum(@intCast(wo));
        libc.print(" wrote=");
        libc.printNum(@intCast(wrote));
        libc.print(" got=");
        libc.printNum(@intCast(got));
        libc.print(" wrote2=");
        libc.printNum(@intCast(wrote2));
        libc.print(" got2=");
        libc.printNum(@intCast(got2));
        libc.print("\n");
    }
    libc.exit();
}
