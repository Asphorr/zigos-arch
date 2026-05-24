// io_uring Phase 3 A1 micro-benchmark — concurrent vs sequential raw-LBA
// NVMe reads.
//
// Submits N=16 OP_NVME_READ two ways:
//   - sequential: one SQE → submit → enter(min=1) → reap, repeat. Worker
//     dispatches one NVMe op at a time; total ~= N × per-op latency.
//   - concurrent: all N SQEs → submit → enter(min=N). Worker batches all
//     N into NVMe's queue (Q_DEPTH=16, matches MAX_PENDING_PER_INSTANCE);
//     completions stream back as IRQs fire. Total ~= 1 × per-op latency
//     plus a bit of in-IRQ-callback dispatch overhead.
//
// Targets nvme2 (swap.img, 128 MB / 262144 sectors) — least contended
// (no FS readers on swap during a normal test), and there's room for
// scattered LBAs without overlapping the kernel's own swap traffic.
// Distinct LBA ranges per test (concurrent at 100000+, sequential at 0+)
// so the device's tiny on-board cache can't bias the second pass.
// "Wall time" is gettimeofday → gettimeofday around each batch.

const libc = @import("libc");
const std = @import("std");

const N_OPS: u32 = 16;
const SECTOR_SIZE: u32 = 512;
const RING_ENTRIES: u32 = 32;
const NVME_CTRL: u32 = 2; // nvme2 = swap.img (128 MB / 262144 sectors)
const LBA_STRIDE: u64 = 4096; // 4K-sector skip = 2 MB between reads, defeats
// sequential prefetch and avoids per-op cache hit.
// Both bases + (N_OPS-1)*LBA_STRIDE stay under 262144.
const SEQ_LBA_BASE: u64 = 0;
const CONC_LBA_BASE: u64 = 100_000;

inline fn elapsedUs(t0: libc.TimeOfDay, t1: libc.TimeOfDay) u64 {
    return (t1.sec - t0.sec) *% 1_000_000 +% (@as(u64, t1.usec) -% @as(u64, t0.usec));
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    libc.print("[diskbench] starting (N=16 OP_NVME_READ on nvme2/swap)\n");

    var ring = libc.ioUringSetup(RING_ENTRIES) orelse {
        libc.print("[diskbench] FAIL: io_uring_setup\n");
        libc.exitWith(0xDEAD0301);
    };

    // One contiguous buffer holds all read targets across both runs.
    var buf: [N_OPS * SECTOR_SIZE]u8 = [_]u8{0} ** (N_OPS * SECTOR_SIZE);

    // ===== Concurrent run FIRST (cold cache on its LBA range) =====
    const t0_conc = libc.gettimeofday();
    {
        var i: u32 = 0;
        while (i < N_OPS) : (i += 1) {
            const sqe = ring.getSqe() orelse {
                libc.print("[diskbench] FAIL: getSqe (concurrent)\n");
                libc.exitWith(0xDEAD0302);
            };
            sqe.* = .{
                .opcode = libc.IOURING_OP_NVME_READ,
                .flags = 0,
                ._pad1 = 0,
                .fd = NVME_CTRL,
                .off = CONC_LBA_BASE + @as(u64, i) * LBA_STRIDE,
                .addr = @intFromPtr(&buf[i * SECTOR_SIZE]),
                .len = 1,
                .user_data = 0xC000_0000 + @as(u64, i),
                ._pad2 = [_]u8{0} ** 28,
            };
        }
        ring.submit(N_OPS);
        _ = ring.enter(N_OPS, N_OPS) orelse {
            libc.print("[diskbench] FAIL: concurrent enter\n");
            libc.exitWith(0xDEAD0303);
        };
        var got: u32 = 0;
        while (ring.reapCqe()) |cqe| {
            if (cqe.res != SECTOR_SIZE) {
                libc.print("[diskbench] FAIL: concurrent res != 512\n");
                libc.exitWith(0xDEAD0304);
            }
            got += 1;
        }
        if (got != N_OPS) {
            libc.print("[diskbench] FAIL: concurrent count mismatch\n");
            libc.exitWith(0xDEAD0305);
        }
    }
    const t1_conc = libc.gettimeofday();
    const conc_us = elapsedUs(t0_conc, t1_conc);

    // ===== Sequential run (different LBAs — also cold) =====
    const t0_seq = libc.gettimeofday();
    {
        var i: u32 = 0;
        while (i < N_OPS) : (i += 1) {
            const sqe = ring.getSqe() orelse {
                libc.print("[diskbench] FAIL: getSqe (sequential)\n");
                libc.exitWith(0xDEAD0306);
            };
            sqe.* = .{
                .opcode = libc.IOURING_OP_NVME_READ,
                .flags = 0,
                ._pad1 = 0,
                .fd = NVME_CTRL,
                .off = SEQ_LBA_BASE + @as(u64, i) * LBA_STRIDE,
                .addr = @intFromPtr(&buf[i * SECTOR_SIZE]),
                .len = 1,
                .user_data = 0xCA00_0000 + @as(u64, i),
                ._pad2 = [_]u8{0} ** 28,
            };
            ring.submit(1);
            _ = ring.enter(1, 1) orelse {
                libc.print("[diskbench] FAIL: sequential enter\n");
                libc.exitWith(0xDEAD0307);
            };
            const cqe = ring.reapCqe() orelse {
                libc.print("[diskbench] FAIL: sequential reap\n");
                libc.exitWith(0xDEAD0308);
            };
            if (cqe.res != SECTOR_SIZE) {
                libc.print("[diskbench] FAIL: sequential res != 512\n");
                libc.exitWith(0xDEAD0309);
            }
        }
    }
    const t1_seq = libc.gettimeofday();
    const seq_us = elapsedUs(t0_seq, t1_seq);

    // ===== Report =====
    var rbuf: [320]u8 = undefined;
    const conc_safe = if (conc_us == 0) 1 else conc_us;
    const speedup_x100 = (seq_us * 100) / conc_safe;
    const s = std.fmt.bufPrint(&rbuf,
        "[diskbench] N={d} × {d}B sectors on nvme2 (stride {d} LBAs)\n" ++
        "  sequential: {d} us  ({d} us/op)\n" ++
        "  concurrent: {d} us  ({d} us/op)\n" ++
        "  speedup:    {d}.{d:0>2}x\n",
        .{
            N_OPS,
            SECTOR_SIZE,
            LBA_STRIDE,
            seq_us, seq_us / N_OPS,
            conc_us, conc_us / N_OPS,
            speedup_x100 / 100, speedup_x100 % 100,
        },
    ) catch "[diskbench] (bufPrint failed)\n";
    libc.print(s);

    libc.exitWith(0xCAFE0301);
}
