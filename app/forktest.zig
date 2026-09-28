// Smoke + isolation test for fork() + COW (syscall #92).
//
// Four scenarios in sequence:
//   1. Trivial fork — parent prints child PID, child prints "hello", both exit.
//   2. COW isolation on stack — both sides write a unique pattern to the same
//      stack slot AFTER fork; each side reads back its own pattern. Proves the
//      shared frame got copied on first write.
//   3. COW isolation on heap (sbrk) — same pattern via a heap byte.
//   4. A tarfs file mmap inherited by the child — its kernel buffer outlives
//      whichever of the two unmaps first.
//
// Run from the shell or by boot mode 18 (src/test/user_selftest.zig), which
// checks the exit status 0xCAFE0042. "[forktest] OK" appears once all four
// pass; any FAIL line localizes the bug class (fork return code,
// parent/child id collision, COW bleed, etc.).

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
