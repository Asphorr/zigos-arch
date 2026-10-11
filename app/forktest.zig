// Smoke + isolation test for fork() + COW (syscall #92).
//
// Five scenarios in sequence:
//   1. Trivial fork — parent prints child PID, child prints "hello", both exit.
//   2. COW isolation on stack — both sides write a unique pattern to the same
//      stack slot AFTER fork; each side reads back its own pattern. Proves the
//      shared frame got copied on first write.
//   3. COW isolation on heap (sbrk) — same pattern via a heap byte.
//   4. A tarfs file mmap inherited by the child — its kernel buffer outlives
//      whichever of the two unmaps first.
//   5. Fork from a threaded process — a worker on the other CPU sees the
//      writes made after fork, and its own writes stay out of the child.
//
// Run from the shell or by boot mode 18 (src/test/user_selftest.zig), which
// checks the exit status 0xCAFE0042. "[forktest] OK" appears once all four
// pass; any FAIL line localizes the bug class (fork return code,
// parent/child id collision, COW bleed, etc.).

const std = @import("std");
const libc = @import("libc");

export fn _start() linksection(".text.entry") callconv(.c) void {
    libc.print("[forktest] starting\n");

    // --- Scenario 1: trivial fork ---
    const r1 = libc.fork();
    if (r1 == 0xFFFFFFFA) {
        libc.print("[forktest] FAIL s1: fork returned EAGAIN\n");
        libc.exitWith(0xDEAD0001);
    }
    if (r1 == 0) {
        libc.print("[forktest] s1 child: hello\n");
        libc.exitWith(0x42);
    }
    {
        var st: u32 = 0;
        const reaped = libc.waitpid(r1, &st);
        if (reaped != r1) {
            libc.print("[forktest] FAIL s1: waitpid wrong pid\n");
            libc.exitWith(0xDEAD0002);
        }
        if ((st & 0xFF) != 0x42) {
            libc.print("[forktest] FAIL s1: bad child exit status\n");
            libc.exitWith(0xDEAD0003);
        }
        libc.print("[forktest] s1 OK\n");
    }

    // --- Scenario 2: stack-COW isolation ---
    var stack_word: u32 = 0xAAAAAAAA;
    const r2 = libc.fork();
    if (r2 == 0xFFFFFFFA) {
        libc.print("[forktest] FAIL s2: fork EAGAIN\n");
        libc.exitWith(0xDEAD0011);
    }
    if (r2 == 0) {
        // Child writes a different pattern. With COW, this triggers a fault
        // and a private copy of the stack page; parent's value should not see
        // this change.
        stack_word = 0xCCCCCCCC;
        if (stack_word != 0xCCCCCCCC) libc.exitWith(0xDEAD0012);
        libc.exitWith(0x55);
    }
    // Parent: also write but with a parent-specific pattern.
    stack_word = 0xBBBBBBBB;
    {
        var st: u32 = 0;
        _ = libc.waitpid(r2, &st);
        if ((st & 0xFF) != 0x55) {
            libc.print("[forktest] FAIL s2: child status\n");
            libc.exitWith(0xDEAD0013);
        }
        // Parent's stack_word must still be its own write, not the child's.
        if (stack_word != 0xBBBBBBBB) {
            libc.print("[forktest] FAIL s2: stack_word bled across fork (COW broken)\n");
            libc.exitWith(0xDEAD0014);
        }
        libc.print("[forktest] s2 OK (stack COW intact)\n");
    }

    // --- Scenario 3: heap-COW isolation via sbrk ---
    const heap_buf = libc.sbrk(4096) orelse {
        libc.print("[forktest] FAIL s3: sbrk\n");
        libc.exitWith(0xDEAD0021);
    };
    const heap_byte: *volatile u8 = @ptrCast(heap_buf);
    heap_byte.* = 0x11;

    const r3 = libc.fork();
    if (r3 == 0xFFFFFFFA) {
        libc.print("[forktest] FAIL s3: fork EAGAIN\n");
        libc.exitWith(0xDEAD0022);
    }
    if (r3 == 0) {
        if (heap_byte.* != 0x11) libc.exitWith(0xDEAD0023);
        heap_byte.* = 0x22;
        if (heap_byte.* != 0x22) libc.exitWith(0xDEAD0024);
        libc.exitWith(0x77);
    }
    heap_byte.* = 0x33;
    {
        var st: u32 = 0;
        _ = libc.waitpid(r3, &st);
        if ((st & 0xFF) != 0x77) {
            libc.print("[forktest] FAIL s3: child status\n");
            libc.exitWith(0xDEAD0025);
        }
        if (heap_byte.* != 0x33) {
            libc.print("[forktest] FAIL s3: heap_byte bled across fork (COW broken)\n");
            libc.exitWith(0xDEAD0026);
        }
        libc.print("[forktest] s3 OK (heap COW intact)\n");
    }

    scenario4();
    scenario5();

    libc.print("[forktest] OK\n");
    libc.exitWith(0xCAFE0042);
}

fn fail(msg: []const u8, code: u32) noreturn {
    libc.print(msg);
    libc.exitWith(code);
}

const MAP_PAGES = 8;
const MAP_LEN = MAP_PAGES * 4096;

/// Pages [first, last] of the mapping (faulting them in) equal the file bytes.
fn pagesMatch(map: []const u8, ref: [*]const u8, first: usize, last: usize) bool {
    var i = first * 4096;
    while (i < (last + 1) * 4096) : (i += 1) {
        if (map[i] != ref[i]) return false;
    }
    return true;
}

// --- Scenario 4: private file mmap outside ext2 across fork ---
// A tarfs mapping is served from one kernel buffer that the child inherits,
// so the buffer must outlive whichever process lets go of it last.
//   4a: the child faults pages in and exits, then the parent faults the rest.
//   4b: the parent unmaps first, then the child faults every page in.
fn scenario4() void {
    const fd = libc.open("/tar/app.elf") orelse fail("[forktest] FAIL s4: open /tar/app.elf\n", 0xDEAD0031);
    const ref = libc.sbrk(MAP_LEN) orelse fail("[forktest] FAIL s4: sbrk\n", 0xDEAD0032);
    @memset(ref[0..MAP_LEN], 0);
    var got: usize = 0;
    while (got < MAP_LEN) {
        const n = libc.fread(fd, ref[got..MAP_LEN]);
        if (n == 0 or libc.isErr(n)) break;
        got += n;
    }
    if (got < MAP_LEN) fail("[forktest] FAIL s4: short read of /tar/app.elf\n", 0xDEAD0033);

    const map_a = libc.mmapFile(fd, 0, MAP_LEN) orelse fail("[forktest] FAIL s4a: mmapFile\n", 0xDEAD0034);
    if (!pagesMatch(map_a, ref, 0, 0)) fail("[forktest] FAIL s4a: parent page 0\n", 0xDEAD0035);
    const ra = libc.fork();
    if (ra == 0xFFFFFFFA) fail("[forktest] FAIL s4a: fork EAGAIN\n", 0xDEAD0036);
    if (ra == 0) {
        if (!pagesMatch(map_a, ref, 0, 3)) libc.exitWith(0xDEAD0037);
        libc.exitWith(0x64);
    }
    {
        var st: u32 = 0;
        _ = libc.waitpid(ra, &st);
        if ((st & 0xFF) != 0x64) fail("[forktest] FAIL s4a: child saw wrong file bytes\n", 0xDEAD0038);
    }
    if (!pagesMatch(map_a, ref, 4, MAP_PAGES - 1)) fail("[forktest] FAIL s4a: parent pages after child exit\n", 0xDEAD0039);
    if (!libc.munmap(map_a)) fail("[forktest] FAIL s4a: munmap\n", 0xDEAD003A);
    libc.print("[forktest] s4a OK (child exits first)\n");

    const map_b = libc.mmapFile(fd, 0, MAP_LEN) orelse fail("[forktest] FAIL s4b: mmapFile\n", 0xDEAD0041);
    const p = libc.pipe() orelse fail("[forktest] FAIL s4b: pipe\n", 0xDEAD0042);
    const rb = libc.fork();
    if (rb == 0xFFFFFFFA) fail("[forktest] FAIL s4b: fork EAGAIN\n", 0xDEAD0043);
    if (rb == 0) {
        libc.close(p[1]);
        var go: [1]u8 = undefined;
        _ = libc.fread(p[0], &go); // returns once the parent has unmapped
        if (!pagesMatch(map_b, ref, 0, MAP_PAGES - 1)) libc.exitWith(0xDEAD0044);
        libc.exitWith(0x65);
    }
    libc.close(p[0]);
    if (!libc.munmap(map_b)) fail("[forktest] FAIL s4b: munmap\n", 0xDEAD0045);
    _ = libc.fwrite(p[1], "g");
    libc.close(p[1]);
    {
        var st: u32 = 0;
        _ = libc.waitpid(rb, &st);
        if ((st & 0xFF) != 0x65) fail("[forktest] FAIL s4b: child saw wrong file bytes\n", 0xDEAD0046);
    }
    libc.close(fd);
    libc.print("[forktest] s4b OK (parent unmaps first)\n");
}

// --- Scenario 5: fork from a threaded process ---
// A worker pinned to the other CPU keeps TLB entries for `word` and `go` while
// the main thread forks. The main thread's write to `go` breaks COW onto a new
// frame the worker must see, and the worker's write to `word` must land in the
// parent's copy, not in the frame the child still reads. Missing shootdowns
// show as a worker that never sees `go` or a child that sees 0xBAD. Anything
// else that flushes the worker's TLB (VM exits under nested virt, kernel-wide
// flushes) closes the stale window early, so the latency until the worker saw
// `go` is printed as well: microseconds with the shootdown, up to a tick
// without.
const S5 = struct {
    word: *volatile u32,
    seen_tsc: *volatile u64,
    go: *volatile u32,
    ready: *volatile u32,
    stale: *volatile u32,
};

/// Ticks the worker waits for `go` before declaring its view stale.
const S5_WAIT_TICKS: u32 = 300;

fn rdtsc() u64 {
    var lo: u32 = undefined;
    var hi: u32 = undefined;
    asm volatile ("rdtsc"
        : [lo] "={eax}" (lo),
          [hi] "={edx}" (hi),
    );
    return @as(u64, lo) | (@as(u64, hi) << 32);
}

fn s5Worker(arg: ?*anyopaque) callconv(.c) ?*anyopaque {
    const s: *const S5 = @ptrCast(@alignCast(arg.?));
    if (libc.sched_setaffinity(0, 1) != 0) {
        s.ready.* = 2;
        return null;
    }
    libc.yield();
    s.ready.* = 1;
    const t0 = libc.uptime();
    var n: u32 = 0;
    while (s.go.* == 0) {
        s.word.* = 1;
        n +%= 1;
        if (n % 65536 == 0 and libc.uptime() -% t0 > S5_WAIT_TICKS) {
            s.stale.* = 1;
            break;
        }
    }
    s.seen_tsc.* = rdtsc();
    s.word.* = 0xBAD;
    return null;
}

fn scenario5() void {
    const raw = libc.sbrk(3 * 4096) orelse fail("[forktest] FAIL s5: sbrk\n", 0xDEAD0051);
    const base = (@intFromPtr(raw) + 4095) & ~@as(usize, 4095);
    const word_page: [*]volatile u32 = @ptrFromInt(base);
    const go_page: [*]volatile u32 = @ptrFromInt(base + 4096);
    const s = S5{
        .word = &word_page[0],
        .seen_tsc = @ptrFromInt(base + 8),
        .go = &go_page[0],
        .ready = &go_page[1],
        .stale = &go_page[2],
    };
    s.word.* = 1;
    s.seen_tsc.* = 0;
    s.go.* = 0;
    s.ready.* = 0;
    s.stale.* = 0;

    if (libc.sched_setaffinity(0, 0) != 0) fail("[forktest] FAIL s5: pin main thread\n", 0xDEAD0052);
    libc.yield();
    const tcb = libc.pthreadCreate(s5Worker, @ptrCast(@constCast(&s))) orelse fail("[forktest] FAIL s5: pthreadCreate\n", 0xDEAD0053);
    const t0 = libc.uptime();
    while (s.ready.* == 0) {
        if (libc.uptime() -% t0 > S5_WAIT_TICKS) fail("[forktest] FAIL s5: worker never started\n", 0xDEAD0054);
        libc.yield();
    }
    if (s.ready.* == 2) {
        _ = libc.pthreadJoin(tcb);
        _ = libc.sched_setaffinity(0, -1);
        libc.print("[forktest] s5 skipped (one CPU)\n");
        return;
    }

    const child = libc.fork();
    if (child == 0xFFFFFFFA) fail("[forktest] FAIL s5: fork EAGAIN\n", 0xDEAD0055);
    if (child == 0) {
        libc.sleep(50); // past the worker's post-fork write
        libc.exitWith(if (s.word.* == 1) 0x66 else 0xDEAD0056);
    }
    const t_go = rdtsc();
    s.go.* = 1;
    _ = libc.pthreadJoin(tcb);
    _ = libc.sched_setaffinity(0, -1);
    if (s.stale.* != 0) fail("[forktest] FAIL s5: worker never saw a write made after fork\n", 0xDEAD0057);
    if (s.word.* != 0xBAD) fail("[forktest] FAIL s5: worker's write missing in the parent\n", 0xDEAD0058);
    var st: u32 = 0;
    _ = libc.waitpid(child, &st);
    if ((st & 0xFF) != 0x66) fail("[forktest] FAIL s5: worker's write reached the child\n", 0xDEAD0059);
    var buf: [96]u8 = undefined;
    const kcyc = (s.seen_tsc.* -% t_go) / 1000;
    libc.print(std.fmt.bufPrint(&buf, "[forktest] s5 OK (threads across fork; worker saw go after {d} kcyc)\n", .{kcyc}) catch "[forktest] s5 OK\n");
}
