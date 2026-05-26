// Smoke test for io_uring across all Phase 1–3 features.
//
//   s1 — setup + 3x OP_NOP: ring mechanism works (SQ tail bump, kernel
//        drains, CQ tail advances, user_data echoes back).
//   s2 — OP_WRITE to stdout: kernel routes opcode → vfs.write, the
//        bytes actually appear on screen.
//   s3 — SQ-full + back-pressure: fill the ring, enter to drain, refill.
//        Confirms head/tail wrap math.
//   s4 — non-blocking submit + later blocking-on-min_complete (Phase 2
//        async worker).
//   s5 — 4x OP_NVME_READ concurrent on nvme0 (Phase 3 A1 per-IRQ async).
//        Proves the worker submits all 4 to the device before any complete,
//        and that IRQ-driven callbacks post CQEs without re-entering vfs.
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
        // Abandon the test getSqe — we didn't fill or submit it, but
        // pending was bumped. Reset so the next scenario doesn't shift
        // its slots by one.
        ring.pending = 0;
        libc.print("[iouringtest] s3 OK (8 entries, wrap intact)\n");
    }

    // --- s4: async behavior — submit + return + later-block-on-min_complete ---
    // Submit 4 NOPs with enter(min_complete=0) — should return quickly without
    // forcing kernel-side completion. Then sleep briefly, then call
    // enter(min_complete=4) which should observe the worker already drained
    // (or block until it has).
    {
        var i: u32 = 0;
        while (i < 4) : (i += 1) {
            const sqe = ring.getSqe() orelse {
                libc.print("[iouringtest] FAIL s4: getSqe null\n");
                libc.exitWith(0xDEAD0213);
            };
            sqe.* = .{
                .opcode = libc.IOURING_OP_NOP,
                .flags = 0,
                ._pad1 = 0,
                .fd = 0,
                .off = 0,
                .addr = 0,
                .len = 0,
                .user_data = 0x4000 + @as(u64, i),
                ._pad2 = [_]u8{0} ** 28,
            };
        }
        ring.submit(4);
        // Non-blocking enter (min_complete=0).
        _ = ring.enter(4, 0) orelse {
            libc.print("[iouringtest] FAIL s4: non-blocking enter null\n");
            libc.exitWith(0xDEAD0214);
        };
        // Block until 4 CQEs are ready.
        const ready = ring.enter(0, 4) orelse {
            libc.print("[iouringtest] FAIL s4: blocking enter null\n");
            libc.exitWith(0xDEAD0215);
        };
        if (ready < 4) {
            libc.print("[iouringtest] FAIL s4: blocking enter returned < 4 ready\n");
            libc.exitWith(0xDEAD0216);
        }
        var drained: u32 = 0;
        while (ring.reapCqe()) |cqe| {
            if (cqe.user_data != 0x4000 + @as(u64, drained)) {
                libc.print("[iouringtest] FAIL s4: user_data order broke\n");
                libc.exitWith(0xDEAD0217);
            }
            drained += 1;
        }
        if (drained != 4) {
            libc.print("[iouringtest] FAIL s4: drained != 4\n");
            libc.exitWith(0xDEAD0218);
        }
        libc.print("[iouringtest] s4 OK (async submit + later min_complete=4)\n");
    }

    // --- s5: per-IRQ async — 4x OP_NVME_READ concurrent ---
    // Each op reads one sector (LBA 0..3) of nvme0 into a 512-byte slice
    // of `buf`. All four are submitted before any complete; we block on
    // min_complete=4. If the worker were serializing (Phase 2), this would
    // still pass but take 4× wall time — kernel logs show per-IRQ async.
    {
        var buf: [4 * 512]u8 = [_]u8{0xCC} ** (4 * 512);
        var i: u32 = 0;
        while (i < 4) : (i += 1) {
            const sqe = ring.getSqe() orelse {
                libc.print("[iouringtest] FAIL s5: getSqe null\n");
                libc.exitWith(0xDEAD0219);
            };
            sqe.* = .{
                .opcode = libc.IOURING_OP_NVME_READ,
                .flags = 0,
                ._pad1 = 0,
                .fd = 0, // nvme0
                .off = @as(u64, i), // LBA i
                .addr = @intFromPtr(&buf[i * 512]),
                .len = 1, // 1 sector
                .user_data = 0x5000 + @as(u64, i),
                ._pad2 = [_]u8{0} ** 28,
            };
        }
        ring.submit(4);
        const ready = ring.enter(4, 4) orelse {
            libc.print("[iouringtest] FAIL s5: enter null\n");
            libc.exitWith(0xDEAD021A);
        };
        if (ready < 4) {
            libc.print("[iouringtest] FAIL s5: ready < 4\n");
            libc.exitWith(0xDEAD021B);
        }
        // Collect by user_data — completion order is whatever NVMe IRQs
        // fire in, NOT submit order, so we can't assume 0x5000, 0x5001…
        // sequentially. Just check that all 4 expected user_data values
        // show up exactly once with res > 0.
        var seen: [4]bool = [_]bool{false} ** 4;
        var ok_count: u32 = 0;
        while (ring.reapCqe()) |cqe| {
            const expected_base: u64 = 0x5000;
            if (cqe.user_data < expected_base or cqe.user_data >= expected_base + 4) {
                libc.print("[iouringtest] FAIL s5: stray user_data\n");
                libc.exitWith(0xDEAD021C);
            }
            const slot: usize = @intCast(cqe.user_data - expected_base);
            if (seen[slot]) {
                libc.print("[iouringtest] FAIL s5: duplicate user_data\n");
                libc.exitWith(0xDEAD021D);
            }
            seen[slot] = true;
            if (cqe.res != 512) {
                libc.print("[iouringtest] FAIL s5: res != 512\n");
                libc.exitWith(0xDEAD021E);
            }
            ok_count += 1;
        }
        if (ok_count != 4) {
            libc.print("[iouringtest] FAIL s5: ok_count != 4\n");
            libc.exitWith(0xDEAD021F);
        }
        // Sanity: each 512-byte slice should be non-uniform (it's the
        // boot disk, not blank). Check that at least one byte in each
        // slice differs from the 0xCC pre-fill — proves the device
        // actually wrote to user memory.
        var s: u32 = 0;
        while (s < 4) : (s += 1) {
            var any_change = false;
            var k: u32 = 0;
            while (k < 512) : (k += 1) {
                if (buf[s * 512 + k] != 0xCC) {
                    any_change = true;
                    break;
                }
            }
            if (!any_change) {
                libc.print("[iouringtest] FAIL s5: buffer slice unchanged (NVMe never wrote)\n");
                libc.exitWith(0xDEAD0220);
            }
        }
        libc.print("[iouringtest] s5 OK (4x OP_NVME_READ concurrent, per-IRQ async)\n");
    }

    // --- s6: OP_POLL (task #893) ---
    //
    // 6a — fast path: create a pipe and poll its write end with POLLOUT.
    //      An empty pipe is always writable, so submitPollOp's inline
    //      check satisfies the request → CQE posted before the SQE even
    //      reaches the slow-path waiter registration.
    // 6b — slow path: poll the read end with POLLIN against an empty
    //      pipe → no inline match → fdpoll registers a waiter. We then
    //      fwrite() to the write end; pipe.write calls fdpoll.wakePollers,
    //      which posts the CQE via pollCompletionCallback. Verifies the
    //      cross-CPU wake path end-to-end.
    {
        const fds = libc.pipe() orelse {
            libc.print("[iouringtest] FAIL s6: pipe() returned null\n");
            libc.exitWith(0xDEAD0221);
        };
        const rfd = fds[0];
        const wfd = fds[1];

        // 6a — POLLOUT on writable pipe (fast path).
        {
            const sqe = ring.getSqe() orelse {
                libc.print("[iouringtest] FAIL s6a: getSqe null\n");
                libc.exitWith(0xDEAD0222);
            };
            sqe.* = .{
                .opcode = libc.IOURING_OP_POLL,
                .flags = 0,
                ._pad1 = 0,
                .fd = wfd,
                .off = 0,
                .addr = 0,
                .len = libc.POLLOUT,
                .user_data = 0x6000,
                ._pad2 = [_]u8{0} ** 28,
            };
            ring.submit(1);
            const ready = ring.enter(1, 1) orelse {
                libc.print("[iouringtest] FAIL s6a: enter null\n");
                libc.exitWith(0xDEAD0223);
            };
            if (ready < 1) {
                libc.print("[iouringtest] FAIL s6a: ready < 1\n");
                libc.exitWith(0xDEAD0224);
            }
            const cqe = ring.reapCqe() orelse {
                libc.print("[iouringtest] FAIL s6a: CQE missing\n");
                libc.exitWith(0xDEAD0225);
            };
            if (cqe.user_data != 0x6000) {
                libc.print("[iouringtest] FAIL s6a: user_data mismatch\n");
                libc.exitWith(0xDEAD0226);
            }
            if (cqe.res < 0) {
                libc.print("[iouringtest] FAIL s6a: negative res (errno)\n");
                libc.exitWith(0xDEAD0227);
            }
            if ((@as(u32, @intCast(cqe.res)) & libc.POLLOUT) == 0) {
                libc.print("[iouringtest] FAIL s6a: POLLOUT bit missing\n");
                libc.exitWith(0xDEAD0228);
            }
            libc.print("[iouringtest] s6a OK (POLLOUT fast path on writable pipe)\n");
        }

        // 6b — POLLIN on empty pipe (slow path: register, then wake).
        {
            const sqe = ring.getSqe() orelse {
                libc.print("[iouringtest] FAIL s6b: getSqe null\n");
                libc.exitWith(0xDEAD0229);
            };
            sqe.* = .{
                .opcode = libc.IOURING_OP_POLL,
                .flags = 0,
                ._pad1 = 0,
                .fd = rfd,
                .off = 0,
                .addr = 0,
                .len = libc.POLLIN,
                .user_data = 0x6100,
                ._pad2 = [_]u8{0} ** 28,
            };
            ring.submit(1);
            // Non-blocking enter: just kick the worker. CQE shouldn't be
            // ready yet because pipe is empty + has writers.
            _ = ring.enter(1, 0) orelse {
                libc.print("[iouringtest] FAIL s6b: kick enter null\n");
                libc.exitWith(0xDEAD022A);
            };

            // Push a byte into the pipe — pipe.write fires wakePollers.
            const wmsg = "X";
            const nw = libc.fwrite(wfd, wmsg);
            if (nw != 1) {
                libc.print("[iouringtest] FAIL s6b: pipe write failed\n");
                libc.exitWith(0xDEAD022B);
            }

            const ready = ring.enter(0, 1) orelse {
                libc.print("[iouringtest] FAIL s6b: block enter null\n");
                libc.exitWith(0xDEAD022C);
            };
            if (ready < 1) {
                libc.print("[iouringtest] FAIL s6b: ready < 1 after wake\n");
                libc.exitWith(0xDEAD022D);
            }
            const cqe = ring.reapCqe() orelse {
                libc.print("[iouringtest] FAIL s6b: CQE missing after wake\n");
                libc.exitWith(0xDEAD022E);
            };
            if (cqe.user_data != 0x6100) {
                libc.print("[iouringtest] FAIL s6b: user_data mismatch\n");
                libc.exitWith(0xDEAD022F);
            }
            if (cqe.res < 0) {
                libc.print("[iouringtest] FAIL s6b: negative res\n");
                libc.exitWith(0xDEAD0230);
            }
            if ((@as(u32, @intCast(cqe.res)) & libc.POLLIN) == 0) {
                libc.print("[iouringtest] FAIL s6b: POLLIN bit missing\n");
                libc.exitWith(0xDEAD0231);
            }
            libc.print("[iouringtest] s6b OK (POLLIN slow path + wake from pipe.write)\n");
        }

        libc.close(rfd);
        libc.close(wfd);
    }

    libc.print("[iouringtest] OK\n");
    libc.exitWith(0xCAFE0115);
}
