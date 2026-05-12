// mmaptest — smoke test for sysMmap / sysMunmap. Allocates a 64 KB anonymous
// region, writes a deterministic pattern through every byte (forcing demand-
// paging to materialize 16 distinct pages), reads it back, then unmaps.
// Then mmaps a second time to confirm the lazy-region slot was released.
//
// On success: prints `[mmaptest] OK` to stdout. On failure: a red message
// naming the step. Watch serial.log for `[pf] PID=N lazy fault-in 0x...`
// lines — there should be one per page on the write pass and zero on the
// read pass (pages already faulted in).

const libc = @import("libc");

const N: usize = 64 * 1024;

export fn _start() linksection(".text.entry") callconv(.c) void {
    libc.print("[mmaptest] starting (64 KB anon mmap, pattern verify)\n");

    const buf = libc.mmap(N) orelse {
        libc.print("\x1b[31m[mmaptest] mmap failed\x1b[0m\n");
        libc.exit();
    };

    // Write pattern. Each byte is `(i ^ 0xA5)` truncated — touches every
    // byte so each of the 16 pages gets demand-paged in.
    for (buf, 0..) |*b, i| b.* = @truncate(i ^ 0xA5);

    // Read back + verify.
    var bad: u32 = 0;
    for (buf, 0..) |b, i| {
        const expected: u8 = @truncate(i ^ 0xA5);
        if (b != expected) bad += 1;
    }
    if (bad != 0) {
        libc.print("\x1b[31m[mmaptest] pattern mismatch\x1b[0m\n");
        _ = libc.munmap(buf);
        libc.exit();
    }

    if (!libc.munmap(buf)) {
        libc.print("\x1b[31m[mmaptest] munmap failed\x1b[0m\n");
        libc.exit();
    }

    // Second round-trip — confirms the lazy_regions slot was actually freed
    // (otherwise repeated mmap() in long-running apps would leak the table).
    const buf2 = libc.mmap(N) orelse {
        libc.print("\x1b[31m[mmaptest] second mmap failed\x1b[0m\n");
        libc.exit();
    };
    buf2[0] = 0x42;
    buf2[N - 1] = 0x55;
    if (buf2[0] != 0x42 or buf2[N - 1] != 0x55) {
        libc.print("\x1b[31m[mmaptest] second-round write/read mismatch\x1b[0m\n");
        _ = libc.munmap(buf2);
        libc.exit();
    }
    _ = libc.munmap(buf2);

    // File-backed: open /bin/ls.elf (post-ext2 migration; cwd is "/", apps
    // moved from /tar/ to /bin/), map the first 4 KB, and verify the ELF
    // magic at offset 0. Confirms the file-backed branch reads the correct
    // bytes into the kernel buffer and the page-fault handler copies them
    // into the user page on touch.
    const fd = libc.open("/bin/ls.elf") orelse {
        libc.print("\x1b[31m[mmaptest] open(/bin/ls.elf) failed\x1b[0m\n");
        libc.exit();
    };
    const fmap = libc.mmapFile(fd, 0, 4096) orelse {
        libc.print("\x1b[31m[mmaptest] mmapFile failed\x1b[0m\n");
        libc.close(fd);
        libc.exit();
    };
    if (fmap[0] != 0x7F or fmap[1] != 'E' or fmap[2] != 'L' or fmap[3] != 'F') {
        libc.print("\x1b[31m[mmaptest] ELF magic mismatch in file-backed mmap\x1b[0m\n");
        _ = libc.munmap(fmap);
        libc.close(fd);
        libc.exit();
    }
    _ = libc.munmap(fmap);
    libc.close(fd);

    // mprotect smoke test: mmap RW (default), write, mprotect to PROT_READ,
    // verify the read still works. Don't test the trap path here — a write
    // through a now-RO page would crash the test process and there's no
    // signal-handler way to recover. Manual verification of RO trapping is
    // a separate exercise.
    const mp = libc.mmap(4096) orelse {
        libc.print("\x1b[31m[mmaptest] mprotect-test mmap failed\x1b[0m\n");
        libc.exit();
    };
    mp[0] = 0xAB;
    mp[4095] = 0xCD;
    if (!libc.mprotect(mp, libc.PROT_READ)) {
        libc.print("\x1b[31m[mmaptest] mprotect to PROT_READ failed\x1b[0m\n");
        _ = libc.munmap(mp);
        libc.exit();
    }
    if (mp[0] != 0xAB or mp[4095] != 0xCD) {
        libc.print("\x1b[31m[mmaptest] post-mprotect read mismatch\x1b[0m\n");
        _ = libc.munmap(mp);
        libc.exit();
    }
    // Restore RW so the test can keep using the region (and so munmap below
    // doesn't trip on stale TLB issues — though changePageProt invalidates).
    _ = libc.mprotect(mp, libc.PROT_READ | libc.PROT_WRITE);
    _ = libc.munmap(mp);

    libc.print("\x1b[32m[mmaptest] OK (anon + file-backed + mprotect)\x1b[0m\n");
    libc.exit();
}
