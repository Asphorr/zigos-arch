// Smoke + bidirectional-sharing test for MAP_SHARED|MAP_ANONYMOUS
// (syscall #114, mmap_shared_anon). Three scenarios:
//
//   1. Parent allocs shared region, writes A, forks. Child reads — must see A.
//      Confirms fork-inheritance + initial visibility.
//   2. Child writes B, exits. Parent reads after waitpid — must see B.
//      Confirms child's writes propagate to parent (true SHARED, not COW).
//   3. Parent writes C after waitpid. Confirms region still alive after one
//      attacher released. (Single-AS-now case.)
//
// All three pass → "[shmtest] OK". Each fail localizes the bug: post-fork
// read (lazy fault didn't map shm frame), post-write read (COW broke
// sharing — handleCowFault shm escape missing), or post-release crash
// (refcount went to 0 prematurely).

const libc = @import("libc");

export fn _start() linksection(".text.entry") callconv(.c) void {
    libc.print("[shmtest] starting\n");

    const buf = libc.mmapSharedAnon(4096) orelse {
        libc.print("[shmtest] FAIL: mmap_shared_anon returned null\n");
        libc.exitWith(0xDEAD0101);
    };
    if (buf.len < 4096) {
        libc.print("[shmtest] FAIL: short slice\n");
        libc.exitWith(0xDEAD0102);
    }

    const word: *volatile u32 = @ptrCast(@alignCast(buf.ptr));

    // Parent pre-fork write.
    word.* = 0xAAAA1111;

    const pid = libc.fork();
    if (pid == 0xFFFFFFFA) {
        libc.print("[shmtest] FAIL: fork EAGAIN\n");
        libc.exitWith(0xDEAD0103);
    }
    if (pid == 0) {
        // Scenario 1: child sees parent's pre-fork write.
        if (word.* != 0xAAAA1111) {
            libc.print("[shmtest] FAIL s1 (child): didn't see parent's write\n");
            libc.exitWith(0xDEAD0104);
        }
        // Scenario 2: child writes a new value for parent to read.
        word.* = 0xBBBB2222;
        if (word.* != 0xBBBB2222) {
            libc.print("[shmtest] FAIL s2 (child): own write didn't stick\n");
            libc.exitWith(0xDEAD0105);
        }
        libc.exitWith(0x42);
    }

    // Parent waits for child, then reads.
    var st: u32 = 0;
    const reaped = libc.waitpid(pid, &st);
    if (reaped != pid) {
        libc.print("[shmtest] FAIL: waitpid wrong pid\n");
        libc.exitWith(0xDEAD0106);
    }
    if ((st & 0xFF) != 0x42) {
        libc.print("[shmtest] FAIL: child exit status wrong\n");
        libc.exitWith(0xDEAD0107);
    }

    // Scenario 2 (parent side): parent must see child's write.
    if (word.* != 0xBBBB2222) {
        libc.print("[shmtest] FAIL s2 (parent): didn't see child's write — sharing broken\n");
        libc.exitWith(0xDEAD0108);
    }
    libc.print("[shmtest] s1+s2 OK (bidirectional sharing)\n");

    // Scenario 3: region still alive after child released.
    word.* = 0xCCCC3333;
    if (word.* != 0xCCCC3333) {
        libc.print("[shmtest] FAIL s3: region died after child release\n");
        libc.exitWith(0xDEAD0109);
    }
    libc.print("[shmtest] s3 OK (region survives single-attacher release)\n");

    if (!libc.munmap(buf)) {
        libc.print("[shmtest] FAIL: munmap returned false\n");
        libc.exitWith(0xDEAD010A);
    }

    libc.print("[shmtest] OK\n");
    libc.exitWith(0xCAFE0114);
}
