// logd — persistent kernel log daemon.
//
// Drains /dev/kmsg and appends to /var/log/messages on ext2. The kernel
// klog ring is a 16 KiB circular buffer in serial.zig — anything that
// scrolls past gets lost. logd's job is to be running before that happens
// and persist every line to the filesystem.
//
// Usage:
//   logd          — daemonize and run forever (typical)
//   logd -F       — foreground mode (don't daemonize), useful for debug
//
// The log file is pre-touched at boot by build.zig (ext2 driver has no
// createFile yet). logd opens it with O_APPEND and writes in 1 KiB chunks.
// Sleep 200ms between drain cycles so we're not busy-spinning.

const libc = @import("libc");

const LOG_PATH = "/var/log/messages";
const DRAIN_BUF: usize = 1024;
const POLL_MS: u32 = 200;

export fn _start() linksection(".text.entry") callconv(.c) void {
    var foreground = false;
    if (libc.getArgc() >= 2) {
        var arg: [4]u8 = undefined;
        const al = libc.getArgv(1, &arg);
        if (al == 2 and arg[0] == '-' and arg[1] == 'F') foreground = true;
    }

    if (!foreground) {
        // Standard daemon ritual — escapes the parent shell's session, so
        // logd survives logout and isn't killed by Ctrl+C in the spawning
        // terminal.
        const drc = libc.daemon(true, true);
        if (drc != 0) {
            libc.print("\x1b[31mlogd: daemon() failed\x1b[0m\n");
            libc.exit();
        }
    }

    // Open the source: kernel klog ring. The kernel tracks our stream
    // position per-fd; if we fall behind by more than ring_size (16 KiB),
    // ringRead jumps us forward to the oldest visible byte. So no matter
    // how busy the kernel is, we never block the kernel — at worst we
    // lose old bytes (with a noted gap in the file).
    const src_fd = libc.open("/dev/kmsg") orelse {
        libc.print("\x1b[31mlogd: cannot open /dev/kmsg\x1b[0m\n");
        libc.exit();
    };

    // Open the sink: append to the persistent log file. O_CREATE is
    // intentionally not set — ext2 createFile is unimplemented; the file
    // is pre-staged by build.zig. If it's missing we'd silently no-op,
    // so explicitly bail.
    const sink_fd = libc.openFlags(LOG_PATH, libc.O_APPEND) orelse {
        libc.print("\x1b[31mlogd: cannot open ");
        libc.print(LOG_PATH);
        libc.print(" — was it pre-touched in build.zig?\x1b[0m\n");
        libc.exit();
    };

    // Mark our presence in the log itself. Useful when reading the file
    // post-hoc to know logd actually ran (vs the file being stale from a
    // previous boot where logd never started).
    const banner = "[logd] started; draining /dev/kmsg → /var/log/messages\n";
    _ = libc.fwrite(sink_fd, banner);

    var buf: [DRAIN_BUF]u8 = undefined;
    while (true) {
        const n = libc.fread(src_fd, &buf);
        if (n == 0 or n == 0xFFFFFFFF) {
            // No new data — sleep before polling again. The kernel ring's
            // own back-pressure protects us from runaway klog (we always
            // get a snapshot, never a stream of unbounded length).
            libc.sleep(POLL_MS);
            continue;
        }
        // Write the slice that ringRead actually delivered. fwrite returns
        // the byte count it consumed; on a short write we'd want to retry,
        // but our sink is the local ext2 and writeFile completes either
        // fully or returns 0 on hard error.
        const w = libc.fwrite(sink_fd, buf[0..n]);
        if (w == 0) {
            // Likely the ext2 inode ran out of direct/indirect block space
            // (we don't truncate yet). Stop trying — better to be silent
            // than spam the klog ring with our own write failures, which
            // would feed back into our next read.
            break;
        }
    }

    libc.close(src_fd);
    libc.close(sink_fd);
    libc.exit();
}
