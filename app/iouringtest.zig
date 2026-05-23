// Smoke test for io_uring Phase 1 (syscalls #115 io_uring_setup +
// #116 io_uring_enter). Three scenarios:
//
//   s1 — setup + 3x OP_NOP: ring mechanism works (SQ tail bump, kernel
//        drains, CQ tail advances, user_data echoes back).
//   s2 — OP_WRITE to stdout: kernel routes opcode → vfs.write, the
//        bytes actually appear on screen.
//   s3 — SQ-full + back-pressure: fill the ring, enter to drain, refill.
//        Confirms head/tail wrap math.
//
// "[iouringtest] OK" + exit 0xCAFE0115 on success.

const libc = @import("libc");

export fn _start() linksection(".text.entry") callconv(.c) void {
    libc.print("[iouringtest] starting\n");

    var ring = libc.ioUringSetup(8) orelse {
        libc.print("[iouringtest] FAIL: setup returned null\n");
        libc.exitWith(0xDEAD0201);
    };

    // --- s1: 3x NOP ---
    {
        var i: u32 = 0;
        while (i < 3) : (i += 1) {
            const sqe = ring.getSqe() orelse {
                libc.print("[iouringtest] FAIL s1: getSqe returned null on empty ring\n");
                libc.exitWith(0xDEAD0202);
            };
            sqe.* = .{
                .opcode = libc.IOURING_OP_NOP,
                .flags = 0,
                ._pad1 = 0,
                .fd = 0,
                .off = 0,
                .addr = 0,
                .len = 0,
                .user_data = 0x1000 + @as(u64, i),
                ._pad2 = [_]u8{0} ** 28,
            };
        }
        ring.submit(3);
        const n = ring.enter(3, 3) orelse {
            libc.print("[iouringtest] FAIL s1: enter returned null\n");
            libc.exitWith(0xDEAD0203);
        };
        if (n != 3) {
            libc.print("[iouringtest] FAIL s1: enter returned wrong count\n");
            libc.exitWith(0xDEAD0204);
        }
        // Reap 3 CQEs and verify user_data matches.
        var j: u32 = 0;
        while (j < 3) : (j += 1) {
            const cqe = ring.reapCqe() orelse {
                libc.print("[iouringtest] FAIL s1: reapCqe null mid-drain\n");
                libc.exitWith(0xDEAD0205);
            };
            if (cqe.user_data != 0x1000 + @as(u64, j)) {
                libc.print("[iouringtest] FAIL s1: user_data mismatch\n");
                libc.exitWith(0xDEAD0206);
            }
            if (cqe.res != 0) {
                libc.print("[iouringtest] FAIL s1: NOP res != 0\n");
                libc.exitWith(0xDEAD0207);
            }
        }
        if (ring.reapCqe() != null) {
            libc.print("[iouringtest] FAIL s1: extra CQE on drained ring\n");
            libc.exitWith(0xDEAD0208);
        }
        libc.print("[iouringtest] s1 OK (3x NOP, user_data echoed)\n");
    }

    // --- s2: OP_WRITE to stdout ---
    {
        const msg = "[iouringtest] s2 hello via OP_WRITE\n";
        const sqe = ring.getSqe() orelse {
            libc.print("[iouringtest] FAIL s2: getSqe null\n");
            libc.exitWith(0xDEAD0209);
        };
        sqe.* = .{
            .opcode = libc.IOURING_OP_WRITE,
            .flags = 0,
            ._pad1 = 0,
            .fd = 1, // stdout
            .off = 0,
            .addr = @intFromPtr(msg.ptr),
            .len = @intCast(msg.len),
            .user_data = 0x2000,
            ._pad2 = [_]u8{0} ** 28,
        };
        ring.submit(1);
        _ = ring.enter(1, 1) orelse {
            libc.print("[iouringtest] FAIL s2: enter null\n");
            libc.exitWith(0xDEAD020A);
        };
        const cqe = ring.reapCqe() orelse {
            libc.print("[iouringtest] FAIL s2: CQE missing\n");
            libc.exitWith(0xDEAD020B);
        };
        if (cqe.user_data != 0x2000) {
            libc.print("[iouringtest] FAIL s2: user_data mismatch\n");
            libc.exitWith(0xDEAD020C);
        }
        if (cqe.res != @as(i32, @intCast(msg.len))) {
            libc.print("[iouringtest] FAIL s2: write res != len\n");
            libc.exitWith(0xDEAD020D);
        }
        libc.print("[iouringtest] s2 OK\n");
    }

    // --- s3: SQ-full + back-pressure ---
    {
        var filled: u32 = 0;
        while (ring.getSqe()) |sqe| {
            sqe.* = .{
                .opcode = libc.IOURING_OP_NOP,
                .flags = 0,
                ._pad1 = 0,
                .fd = 0,
                .off = 0,
                .addr = 0,
                .len = 0,
                .user_data = 0x3000 + @as(u64, filled),
                ._pad2 = [_]u8{0} ** 28,
            };
            filled += 1;
            if (filled > 16) {
                libc.print("[iouringtest] FAIL s3: getSqe didn't return null on full ring\n");
                libc.exitWith(0xDEAD020E);
            }
        }
        if (filled != 8) {
            libc.print("[iouringtest] FAIL s3: ring capacity mismatch\n");
            libc.exitWith(0xDEAD020F);
        }
        ring.submit(filled);
        _ = ring.enter(filled, filled) orelse {
            libc.print("[iouringtest] FAIL s3: enter null\n");
            libc.exitWith(0xDEAD0210);
        };
        var drained: u32 = 0;
        while (ring.reapCqe()) |cqe| {
            _ = cqe;
            drained += 1;
        }
        if (drained != 8) {
            libc.print("[iouringtest] FAIL s3: didn't drain full ring\n");
            libc.exitWith(0xDEAD0211);
        }
        // Re-fill after drain: head/tail wrap math must work.
        if (ring.getSqe() == null) {
            libc.print("[iouringtest] FAIL s3: ring stuck full after drain\n");
            libc.exitWith(0xDEAD0212);
        }
        libc.print("[iouringtest] s3 OK (8 entries, wrap intact)\n");
    }

    libc.print("[iouringtest] OK\n");
    libc.exitWith(0xCAFE0115);
}
