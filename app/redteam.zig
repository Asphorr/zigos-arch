// redteam — stateful kernel syscall fuzzer.
//
// V1 (random args) plateaued — it found shallow input-validation bugs and
// then stopped producing new ones. Real bugs hide in *sequences*: open→
// close→use, mmap→munmap→access, create_window→destroy→present. Random
// independent calls never construct those sequences because the chance of
// guessing a valid fd or addr from PRNG noise is ~0.
//
// V2 tracks live resources we allocate (fds, mmap regions, window ids) and
// biases args toward those values, so we exercise multi-step state machines.
// Also adds a small path dictionary for path-arg syscalls — random ptrs to
// unmapped memory just bounce off validateUserPtr; real strings actually
// reach the path parser.
//
// Tracked:
//   - file descriptors: sys#9 (open), sys#51 (pipe — both ends)
//   - mmap regions:     sys#57
//   - window ids:       sys#13
// Biased arg1:
//   - sys#4/10/11/12/29/42 (read/fread/fwrite/close/fsize/readdir): live fd
//   - sys#58/59 (munmap/mprotect): live region addr
//   - sys#14/16/24 (present/destroy_window/get_window_size): live wid
//   - sys#9/21/39/41/43/44/45/46 (open/listdir/chdir/mkdir/unlink/stat/...): path
// Post-syscall: success returns are added to the table; close/munmap/destroy
// remove their target so we don't keep using a stale handle forever.
//
// Usage:
//   redteam               — 1000 iterations
//   redteam <N>           — N iterations
//   redteam <N> <seed>    — deterministic replay (any non-zero seed)

const libc = @import("libc");

var state: u64 = 0;

fn rdtsc() u64 {
    var lo: u32 = undefined;
    var hi: u32 = undefined;
    asm volatile ("rdtsc"
        : [_] "={eax}" (lo),
          [_] "={edx}" (hi),
    );
    return (@as(u64, hi) << 32) | @as(u64, lo);
}

fn next() u32 {
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    return @truncate(state *% 0x2545F4914F6CDD1D);
}

fn spicyArg() u32 {
    const r = next() & 0x1F;
    return switch (r) {
        0 => 0,
        1 => 1,
        2 => 0xFFFFFFFF,
        3 => 0x7FFFFFFF,
        4 => 0x80000000,
        5 => 0x500000,
        6 => 0x4FFFFF,
        7 => 0xC00000,
        8 => 0x10000000,
        9 => 0xFFFFF000,
        10 => 0x4FF000,
        11 => 0x501000,
        else => next(),
    };
}

// === resource tracker ===

const MAX_FDS = 16;
const MAX_REGIONS = 8;
const MAX_WINDOWS = 4;

var live_fds: [MAX_FDS]u32 = undefined;
var n_fds: u32 = 0;

var region_addr: [MAX_REGIONS]u32 = undefined;
var n_regions: u32 = 0;

var live_wids: [MAX_WINDOWS]u32 = undefined;
var n_wids: u32 = 0;

// Reserved buffers we pass to syscalls that write back ids/data.
var pipe_buf: [2]u32 = .{ 0, 0 };
var path_buf: [128]u8 = undefined;
var io_buf: [256]u8 = undefined;

fn addFd(fd: u32) void {
    // Don't track absurd values that aren't real fds (sanity guard against
    // a syscall returning 0 = "ok" being misread as a fd).
    if (fd >= 256) return;
    if (n_fds < MAX_FDS) {
        live_fds[n_fds] = fd;
        n_fds += 1;
    } else {
        // Bounded: evict random slot. Keeps the table churning instead of
        // sticking on the first 16 fds forever.
        live_fds[next() % MAX_FDS] = fd;
    }
}

fn removeFd(fd: u32) void {
    var i: u32 = 0;
    while (i < n_fds) : (i += 1) {
        if (live_fds[i] == fd) {
            n_fds -= 1;
            live_fds[i] = live_fds[n_fds];
            return;
        }
    }
}

fn pickFd() u32 {
    if (n_fds == 0) {
        // Fallback: spicyArg() can return 0 = stdin, and reading stdin
        // blocks waiting for a keypress (silent freeze). Use a high
        // value that's deterministically not stdio.
        return next() | 0x10;
    }
    return live_fds[next() % n_fds];
}

fn addRegion(addr: u32) void {
    if (n_regions < MAX_REGIONS) {
        region_addr[n_regions] = addr;
        n_regions += 1;
    } else {
        region_addr[next() % MAX_REGIONS] = addr;
    }
}

fn removeRegion(addr: u32) void {
    var i: u32 = 0;
    while (i < n_regions) : (i += 1) {
        if (region_addr[i] == addr) {
            n_regions -= 1;
            region_addr[i] = region_addr[n_regions];
            return;
        }
    }
}

fn pickRegion() u32 {
    if (n_regions == 0) return spicyArg();
    return region_addr[next() % n_regions];
}

fn addWid(wid: u32) void {
    if (wid >= 256) return;
    if (n_wids < MAX_WINDOWS) {
        live_wids[n_wids] = wid;
        n_wids += 1;
    } else {
        live_wids[next() % MAX_WINDOWS] = wid;
    }
}

fn removeWid(wid: u32) void {
    var i: u32 = 0;
    while (i < n_wids) : (i += 1) {
        if (live_wids[i] == wid) {
            n_wids -= 1;
            live_wids[i] = live_wids[n_wids];
            return;
        }
    }
}

fn pickWid() u32 {
    if (n_wids == 0) return spicyArg();
    return live_wids[next() % n_wids];
}

// === path dictionary ===
// Mix of (a) real openable files so open() actually returns valid fds and
// fills live_fds — without this, the resource-bias path never fires — and
// (b) boundary cases the path parser is likely to mishandle.
const PATHS = [_][]const u8{
    // Real files (open should succeed → fd added to live_fds)
    "/BUILD.ID",
    "/KERNEL.LINE",
    "/KERNEL.SYM",
    "/etc/motd",
    "/etc/zigos.conf",
    "/bin/echo.elf",
    "/bin/ls.elf",
    "/bin/cat.elf",
    "/bin/redteam.elf",
    // Edge cases (path parser fuzz)
    "/",
    ".",
    "..",
    "/bin",
    "//bin//redteam.elf",
    "/../../..",
    "../../../../../etc",
    "a",
    "",
    "/.",
    "/./",
    "/bin/.",
    "very_long_path_that_might_overflow_the_kernel_buffer_if_anyone_forgot_a_bound_check_xxxxxxxxxxxxxxxx",
};

fn pickPathPtr() u32 {
    const p = PATHS[next() % PATHS.len];
    const n = if (p.len < path_buf.len - 1) p.len else path_buf.len - 1;
    var k: usize = 0;
    while (k < n) : (k += 1) path_buf[k] = p[k];
    path_buf[n] = 0;
    return @intCast(@intFromPtr(&path_buf));
}

// === per-syscall arg shaping ===

fn isFdArg1(sys_no: u32) bool {
    return switch (sys_no) {
        4, 10, 11, 12, 29, 42 => true,
        else => false,
    };
}

fn isRegionArg1(sys_no: u32) bool {
    return switch (sys_no) {
        58, 59 => true,
        else => false,
    };
}

fn isWidArg1(sys_no: u32) bool {
    return switch (sys_no) {
        14, 16, 24 => true,
        else => false,
    };
}

fn isPathArg1(sys_no: u32) bool {
    return switch (sys_no) {
        9, 21, 39, 41, 43, 44, 45, 46 => true,
        else => false,
    };
}

// 70% bias toward a live resource if applicable, 30% spicy fallback. The
// fallback is important — sometimes the bug is "uses the wrong resource",
// which only triggers when arg is e.g. a *closed* fd or a freed addr, and
// pure-bias would never produce that.
fn smartArg1(sys_no: u32) u32 {
    const bias = (next() % 10) < 7;
    if (bias) {
        if (isFdArg1(sys_no)) return pickFd();
        if (isRegionArg1(sys_no)) return pickRegion();
        if (isWidArg1(sys_no)) return pickWid();
        if (isPathArg1(sys_no)) return pickPathPtr();
    }
    // Fallback: spicy random. For fd-arg syscalls, ensure the result is
    // never 0/1/2 (stdio fds — reading from 0 blocks for a keypress, and
    // writing to 1/2 spams the terminal).
    if (isFdArg1(sys_no)) return next() | 0x10;
    return spicyArg();
}

// For some syscalls we can also smarten arg2 (e.g. read/write buf). Use our
// io_buf so the kernel doesn't bounce off validateUserPtr.
fn smartArg2(sys_no: u32) u32 {
    return switch (sys_no) {
        // (fd, buf, len) — pass a real buffer 70% of the time so the read
        // actually copies and we exercise the copy path, not the validator.
        4, 10, 11, 42 => if ((next() % 10) < 7)
            @intCast(@intFromPtr(&io_buf))
        else
            spicyArg(),
        // open(path, flags) — flags = O_RDONLY/WRONLY/RDWR plus modifiers.
        // Garbage flags don't matter to ZigOS's openFlags right now (it
        // ignores them mostly), but biasing toward 0..3 keeps the call
        // looking like a normal open and makes any future flag validation
        // exercise normal paths.
        9 => if ((next() % 10) < 8) (next() % 4) else spicyArg(),
        else => spicyArg(),
    };
}

fn smartArg3(sys_no: u32) u32 {
    return switch (sys_no) {
        // For read/write/readdir, cap len to io_buf size most of the time
        // so we don't OOB into adjacent .data on success.
        4, 10, 11, 42 => if ((next() % 10) < 8)
            (next() % @as(u32, @intCast(io_buf.len + 1)))
        else
            spicyArg(),
        else => spicyArg(),
    };
}

// === post-syscall bookkeeping ===

fn isError(ret: u32) bool {
    return ret == 0xFFFFFFFF or ret >= 0xFFFFFF00;
}

fn postProcess(sys_no: u32, a1: u32, ret: u32) void {
    switch (sys_no) {
        9 => if (!isError(ret)) addFd(ret), // open returns fd
        12 => if (!isError(ret)) removeFd(a1), // close
        13 => if (!isError(ret)) addWid(ret), // create_window returns wid
        16 => if (!isError(ret)) removeWid(a1), // destroy_window
        // sys#51 (pipe) deliberately NOT tracked: a read on an empty pipe
        // with no writer blocks forever. Single-process fuzz can't make
        // useful progress on pipes — that's option-2 (multi-process race)
        // territory. The call still happens with a real pipe_buf so the
        // pipe-creation path is exercised; we just discard the resulting fds.
        57 => {
            // mmap returns user VA on success. Heuristic: it's in user
            // range and not an obvious errno bit pattern.
            if (ret >= 0x500000 and ret < 0x10000000) addRegion(ret);
        },
        58 => removeRegion(a1), // munmap
        else => {},
    }
}

// === blocked syscalls ===

fn isBlocked(sys_no: u32) bool {
    return switch (sys_no) {
        3 => true, // exit
        8 => true, // sleep — random u32 ms = up to ~50 days of sleep
        22 => true, // exec — replaces our image
        48 => true, // exit_status — calls destroyCurrentWithStatus(arg1), kills us
        50 => true, // kill — could whack ourselves or others
        52 => true, // exec_as
        54 => true, // usleep — same indefinite-sleep risk as sys#8
        62 => true, // sigreturn — outside a signal handler, kills us via DEAD000B
        64 => true, // sigsuspend — parks until signal; random fuzz won't deliver one
        65 => true, // pause — same indefinite-block as sigsuspend
        82 => true, // shutdown — kills the whole OS
        83 => true, // clone — thread spawn, complicates teardown
        86 => true, // exit_thread
        92 => true, // fork — risk of fuzz-bomb
        else => false,
    };
}

fn parseU32(s: []const u8) u32 {
    if (s.len == 0) return 0;
    var v: u32 = 0;
    for (s) |c| {
        if (c < '0' or c > '9') return 0;
        v = v *% 10 +% @as(u32, c - '0');
    }
    return v;
}

// Fix arg1 for syscalls whose "live" arg lives in arg2 (the only one we
// have right now is pipe — its only arg is a buffer for the two fds).
fn forceArg1(sys_no: u32) ?u32 {
    return switch (sys_no) {
        51 => @intCast(@intFromPtr(&pipe_buf)), // pipe: must be a real buffer
        else => null,
    };
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    var iters: u32 = 1000;
    var seed: u64 = 0;

    if (libc.getArgc() >= 2) {
        var buf: [16]u8 = undefined;
        const n = libc.getArgv(1, &buf);
        if (n != 0xFFFFFFFF and n != 0) {
            const v = parseU32(buf[0..n]);
            if (v != 0) iters = v;
        }
    }
    if (libc.getArgc() >= 3) {
        var buf: [16]u8 = undefined;
        const n = libc.getArgv(2, &buf);
        if (n != 0xFFFFFFFF and n != 0) {
            seed = @as(u64, parseU32(buf[0..n]));
        }
    }

    state = if (seed != 0) seed else (rdtsc() | 1);

    libc.print("[redteam] starting stateful syscall fuzzer pid=");
    libc.printNum(libc.getpid());
    libc.print(" iters=");
    libc.printNum(iters);
    libc.print(" seed=0x");
    libc.printHex(@truncate(state >> 32));
    libc.printHex(@truncate(state));
    libc.print("\n");

    var i: u32 = 0;
    var skipped: u32 = 0;
    var ok_count: u32 = 0;
    var err_count: u32 = 0;
    var biased: u32 = 0;

    while (i < iters) : (i += 1) {
        const sys_no: u32 = next() % 130;
        if (isBlocked(sys_no)) {
            skipped += 1;
            continue;
        }

        const a1 = forceArg1(sys_no) orelse smartArg1(sys_no);
        const a2 = smartArg2(sys_no);
        const a3 = smartArg3(sys_no);

        // Note for the report: did we use a tracked resource here?
        if (isFdArg1(sys_no) and n_fds > 0 and a1 == live_fds[0]) biased += 1;

        // Trace EVERY call to serial.log. If redteam parks, the last line
        // shows exactly which syscall caused it. Tiny payload (~60 bytes/iter
        // = ~60 KB for 1000 iters) — fine for diagnostic; remove later if
        // redteam itself becomes the regression test for normal ops.
        libc.klogFmt("[redteam] iter={d} sys#{d} a1=0x{x} a2=0x{x} a3=0x{x} live[fd={d} rg={d} wid={d}]\n", .{
            i, sys_no, a1, a2, a3, n_fds, n_regions, n_wids,
        });

        const ret = libc.syscall3(sys_no, a1, a2, a3);
        postProcess(sys_no, a1, ret);

        if (isError(ret)) {
            err_count += 1;
        } else {
            ok_count += 1;
        }

        if (i % 50 == 0) {
            libc.print("[redteam] iter=");
            libc.printNum(i);
            libc.print(" sys#");
            libc.printNum(sys_no);
            libc.print(" args=0x");
            libc.printHex(a1);
            libc.print(",0x");
            libc.printHex(a2);
            libc.print(",0x");
            libc.printHex(a3);
            libc.print(" ret=0x");
            libc.printHex(ret);
            libc.print(" live[fd=");
            libc.printNum(n_fds);
            libc.print(" rg=");
            libc.printNum(n_regions);
            libc.print(" wid=");
            libc.printNum(n_wids);
            libc.print("]\n");
        }
    }

    libc.print("[redteam] done: ");
    libc.printNum(iters);
    libc.print(" iters, ok=");
    libc.printNum(ok_count);
    libc.print(" err=");
    libc.printNum(err_count);
    libc.print(" skipped=");
    libc.printNum(skipped);
    libc.print(" final live[fd=");
    libc.printNum(n_fds);
    libc.print(" rg=");
    libc.printNum(n_regions);
    libc.print(" wid=");
    libc.printNum(n_wids);
    libc.print("] — kernel survived\n");

    libc.exit();
}
