// Smoke + isolation test for fork() + COW (syscall #92).
//
// Three scenarios in sequence:
//   1. Trivial fork — parent prints child PID, child prints "hello", both exit.
//   2. COW isolation on stack — both sides write a unique pattern to the same
//      stack slot AFTER fork; each side reads back its own pattern. Proves the
//      shared frame got copied on first write.
//   3. COW isolation on heap (sbrk) — same pattern via a heap byte.
//
// Auto-launched from boot menu / shell so serial.log captures the result.
// "[forktest] OK" appears once all three pass; any FAIL line localizes the
// bug class (fork return code, parent/child id collision, COW bleed, etc.).

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

    libc.print("[forktest] OK\n");
    libc.exitWith(0xCAFE0042);
}
