const std = @import("std");
const io = @import("../io.zig");

const PORT: u16 = 0x3F8; // COM1

// Line Status Register (PORT+5) bits used ONLY by the bounded-poll
// emergency writer below (the normal putChar path is fire-and-forget on
// purpose — see putChar's comment for why).
const LSR: u16 = PORT + 5;
const LSR_THR_EMPTY: u8 = 0x20; // bit 5 — holding reg empty, OK to queue a byte
const LSR_TEMT: u8 = 0x40; // bit 6 — transmitter fully drained (FIFO + shift reg)
// Per-byte cap for emergency LSR THR-empty polls. Each poll is an `inb`
// VM-exit under nested Hyper-V, so the old 1M cap could cost ~0.5s PER BYTE
// on a non-draining UART — a multi-KB dumpAll() at IF=0 then ran for tens of
// seconds and tripped the peer watchdog (the schedstress setTssRsp0 autopsy
// wedge, 2026-06-24). 8192 is ample headroom for a healthy-but-busy FIFO yet
// bails in <10ms when the UART is wedged. emergencyPutChar layers two TOTAL
// bounds on top of this per-byte cap (stall-streak giveup + throttle-byte
// budget) so an oversized or stalled crash dump can never outlive the watchdog.
const EMERG_SPIN_CAP: u32 = 8192;
// After this many consecutive bytes each hit the full poll cap, the UART is
// deemed not draining at all (host detached / serial load-shed) and the
// emergency writer stops waiting entirely — fire-and-forget for the rest.
const EMERG_STALL_GIVEUP: u32 = 32;
// Total bytes the emergency writer will THR-throttle (wait for FIFO space)
// before degrading to fire-and-forget. Serial is ~11.5 KB/s at 115200 baud
// and this path runs with interrupts off, so a dump larger than this can't
// shift out within the watchdog's ~3s tick-stall budget; past it we stop
// waiting (bytes may drop if the FIFO is full, but the CPU keeps moving and
// the in-memory ring still holds the full text for /dev/kmsg).
const EMERG_THROTTLE_BUDGET: u32 = 12 * 1024;

// Cross-CPU write lock. Without this, fire-and-forget putChar calls from
// BSP and AP interleave at byte granularity (a `[smp.timing]` line gets
// shredded by a concurrent `[perf]` dump). Plain test-and-set + cli to
// guarantee an in-flight write isn't preempted into the same lock by an
// IRQ on the SAME core. We avoid the ticket SpinLock here because its
// long-spin warning re-enters serial.print and would deadlock.
var write_lock: u32 = 0;

inline fn lockWrite() u64 {
    var flags: u64 = undefined;
    asm volatile ("pushfq; pop %[f]; cli"
        : [f] "=r" (flags),
    );
    while (@cmpxchgWeak(u32, &write_lock, 0, 1, .acquire, .monotonic) != null) {
        asm volatile ("pause");
    }
    return flags;
}

inline fn unlockWrite(flags: u64) void {
    @atomicStore(u32, &write_lock, 0, .release);
    if (flags & 0x200 != 0) asm volatile ("sti");
}

/// Set once by kdbg.enterCritical when the system enters a panic/fault
/// critical section. While true, EVERY serial write bypasses write_lock and
/// uses the lock-free, bounded-LSR-poll emergency path below. Two problems
/// this solves at once:
///   1. Deadlock. A peer CPU frozen by NMI mid-`write` still holds
///      write_lock; any locked print after that — this CPU's panic banner,
///      or the peer's own nmiSnapshot — would spin on the lock forever. The
///      NMI snapshot hung exactly here (2026-06-04 wedge: log ended at a
///      lone `[`, a partial line from a peer frozen mid-write).
///   2. Lost tail. putChar is fire-and-forget, so the last ~16 bytes of a
///      crash dump sit in QEMU's FIFO when we halt; the emergency writer
///      waits (bounded) on THR-empty so nothing is dropped.
/// Never cleared — the only caller is the about-to-halt panic path.
pub var emergency_mode: bool = false;

// In-memory mirror of everything sent over the serial port. /dev/kmsg
// reads from this so user-space tools (cat, grep, dmesg) can inspect
// recent kernel log output without needing the host's serial.log file.
//
// 64 KiB holds ~600 lines of typical kernel output — sized so a boot-scale
// print burst can't lap the deferred-port drainer (see `deferred`). Reads are
// addressed by a *monotonic stream position* (total bytes ever written),
// not by ring index — that way an fd's saved offset survives ring wraps
// and the dmesg follow loop can pick up cleanly across iterations.
// `total_written` wraps after 4 GiB which is many hours; kernel-mode
// modular subtraction (-%) makes the comparison correct across that
// boundary too.
//
// We don't try to be lockless: serial.write is already racy across cores
// (see putChar's wait-loop), and the worst case is a torn line.
const RING_LEN: u32 = 64 * 1024;
var ring: [RING_LEN]u8 = [_]u8{0} ** RING_LEN;
var ring_pos: u32 = 0; // next write index (physical, into `ring`)
var total_written: u32 = 0; // monotonic byte counter (stream position)

/// Deferred-port mode. When true, normal `write` only appends to the ring;
/// the UART I/O happens in ksoftirqd via `drainToPort` (the .klog softirq).
/// Rationale: each `outb` is a VM exit (µs-scale under nested virt), so an
/// 80-char line costs a fraction of a millisecond — and several printers
/// (smi.tick, cli-hold flush, perf dump) run from cli'd tick context, where
/// that cost is pure jitter. Flipped on by softirq.startAll once ksoftirqd
/// exists; flipped back off permanently by the emergency path, which also
/// flushes the backlog (crash output must be synchronous and complete).
pub var deferred: bool = false;

/// Stream position (same coordinate as total_written) of the next byte to
/// send to the UART. Single consumer: only the BSP ksoftirqd drainer (or
/// the one-shot emergency flush) advances it.
var drain_pos: u32 = 0;

/// Bytes that fell out of the ring before the drainer reached them (port
/// output lost them; the in-ring /dev/kmsg view saw them until lapped).
var port_lost_bytes: u32 = 0;

/// Load-shed high-water mark (bytes of unsent backlog). When deferred-mode
/// output outruns ksoftirqd's drainToPort by more than this, `write` DROPS the
/// message instead of appending. Rationale: a self-amplifying klog flood (e.g.
/// a [slow-sc] storm during a scheduler stress test — each line's serial cost
/// makes the next syscall slower, so more lines) makes the backlog grow without
/// bound; appending anyway only lengthens the cli'd `write_lock` critical
/// section that EVERY CPU contends on, until a CPU spins there long enough for
/// the hang watchdog to NMI the box (observed 2026-06-20). Past this mark the
/// drainer is already >3/4 of a ring behind and about to lap (lose bytes)
/// anyway, so dropping loses no more than lapping would — but keeps the write
/// path O(1) so logging can never starve the scheduler. The in-ring /dev/kmsg
/// view still holds the most-recent RING_LEN bytes. Checked locklessly BEFORE
/// lockWrite so a flooding CPU never even contends for the lock.
const DROP_HIGH_WATER: u32 = (RING_LEN / 4) * 3; // 48 KiB of 64 KiB
/// Bytes dropped by the load-shed path since the last recovery report.
var dropped_bytes: u32 = 0;

pub fn init() void {
    io.outb(PORT + 1, 0x00); // Disable interrupts
    io.outb(PORT + 3, 0x80); // Enable DLAB
    io.outb(PORT + 0, 0x03); // 38400 baud (lo)
    io.outb(PORT + 1, 0x00); // 38400 baud (hi)
    io.outb(PORT + 3, 0x03); // 8N1
    io.outb(PORT + 2, 0xC7); // Enable FIFO
    io.outb(PORT + 4, 0x0B); // IRQs enabled, RTS/DSR set
}

fn putChar(c: u8) void {
    // No busy-wait on LSR.THR_EMPTY. QEMU's emulated UART rate-limits the
    // FIFO drain, and the spin loop here was costing ~us per byte under
    // contention — a single 80-char klog took 30-400 ms to drain because
    // each putChar busy-waited on a kvm-exit-emulated `inb`. Stacked
    // across the dozen klogs in a `desktop.createGuiWindow` call path,
    // it added 200-400 ms per window — the actual cause of "files take
    // 6-8 s to load". Fire-and-forget: if QEMU's 16-byte FIFO is full
    // we drop a byte, which is fine for a debug log. The in-kernel ring
    // (`ringPush`, /dev/kmsg) keeps the full text either way.
    io.outb(PORT, c);
}

fn ringPush(c: u8) void {
    ring[ring_pos] = c;
    ring_pos += 1;
    if (ring_pos >= RING_LEN) ring_pos = 0;
    total_written +%= 1;
}

pub fn write(msg: []const u8) void {
    if (@atomicLoad(bool, &emergency_mode, .acquire)) {
        emergencyWrite(msg);
        return;
    }
    // Load-shed under a log flood (see DROP_HIGH_WATER). Only in deferred mode,
    // where a backlog can build; the check is lockless so a flooding CPU bails
    // before contending for write_lock. Synchronous mode has no backlog — every
    // byte goes straight out — so it skips this and always appends.
    if (@atomicLoad(bool, &deferred, .monotonic)) {
        // Sample drain_pos (the chasing cursor) BEFORE total_written (the head).
        // We're preemptible here (pre-lockWrite, IF may be 1), so the drainer can
        // advance drain_pos between the two reads. Reading the cursor first means
        // head >= cursor always holds for the pair, so `head -% cursor` can only
        // OVER-estimate the backlog (shed a touch early) — never wrap to ~4 GiB
        // and shed everything, which reading the head first would allow. drain_pos
        // read plain (single BSP-drainer writer; aligned-u32 access is atomic on
        // x86) — same convention as pendingToPort.
        const dp = drain_pos;
        const backlog = @atomicLoad(u32, &total_written, .monotonic) -% dp;
        if (backlog > DROP_HIGH_WATER) {
            _ = @atomicRmw(u32, &dropped_bytes, .Add, @as(u32, @truncate(msg.len)), .monotonic);
            return;
        }
    }
    const flags = lockWrite();
    defer unlockWrite(flags);
    const to_port = !@atomicLoad(bool, &deferred, .monotonic);
    for (msg) |c| {
        if (to_port) putChar(c);
        ringPush(c);
    }
}

/// Sync the drain cursor to the current write head. Called once when flipping
/// INTO deferred mode: everything written so far went out synchronously, so the
/// drainer must start "caught up" rather than re-walking the whole boot log —
/// and, with load-shedding live, so the backlog isn't ~48 KiB at the cutover
/// (which would false-trip DROP_HIGH_WATER and drop the first post-boot lines).
/// Single caller, runs on the BSP drainer BEFORE `deferred` is published true,
/// so no drainToPort races it.
pub fn syncDrainCursor() void {
    drain_pos = @atomicLoad(u32, &total_written, .monotonic);
}

/// Bytes appended but not yet sent to the UART. 0 whenever deferred mode is
/// off (everything went out synchronously). Used by the IRQ0 tick as the
/// "raise .klog or not" hint.
pub fn pendingToPort() u32 {
    if (!@atomicLoad(bool, &deferred, .monotonic)) return 0;
    return @atomicLoad(u32, &total_written, .monotonic) -% drain_pos;
}

/// .klog softirq handler — runs in ksoftirqd (IF=1, schedulable). Copies
/// pending ring bytes to the UART in small chunks. Lock-free against
/// writers: ringRead only touches stream positions < total_written, which
/// are stable unless the ring laps the cursor mid-drain — under that kind
/// of burst a torn byte in the port output is acceptable (the ring is the
/// canonical record) and the lap itself is counted + reported.
pub fn drainToPort() void {
    if (!@atomicLoad(bool, &deferred, .monotonic)) return;
    var chunk: [256]u8 = undefined;
    // Per-invocation cap: ksoftirqd also drains .hid (input) — a full-ring
    // drain at ~µs-per-char of port VM exits would block input for tens of
    // ms under storm logging. 4 KB ≈ a few ms worst case; the leftover
    // keeps pendingToPort() nonzero so the next tick re-raises us.
    var budget: u32 = 4096;
    while (budget > 0) {
        const behind = @atomicLoad(u32, &total_written, .monotonic) -% drain_pos;
        if (behind == 0) break;
        if (behind > RING_LEN) {
            // Writers lapped us; ringRead will jump the cursor forward.
            port_lost_bytes +%= behind - RING_LEN;
        }
        const n = ringRead(&drain_pos, &chunk, chunk.len);
        if (n == 0) break;
        for (chunk[0..n]) |c| putChar(c);
        budget -|= n;
    }
    if (port_lost_bytes != 0) {
        const lost = port_lost_bytes;
        port_lost_bytes = 0;
        print("[klog] {d} bytes lost to port (ring lapped the drainer)\n", .{lost});
    }
    // Report load-shed drops once the backlog has recovered, so the gap is
    // visible without the report itself re-flooding (only fires when we're
    // back under a quarter ring — i.e. the flood is over). The read+reset
    // isn't a strict CAS; an overlapping write's increment can be missed and
    // folded into the next report, which is fine for a diagnostic counter.
    const dropped = @atomicLoad(u32, &dropped_bytes, .monotonic);
    if (dropped != 0 and (@atomicLoad(u32, &total_written, .monotonic) -% drain_pos) < (RING_LEN / 4)) {
        @atomicStore(u32, &dropped_bytes, 0, .monotonic);
        print("[klog] {d} bytes load-shed (dropped under flood to keep the scheduler live)\n", .{dropped});
    }
}

/// Panic-mode lock release. Use only from a panic / corruption-report
/// path that's about to print and halt. Forcibly clears `write_lock` so
/// subsequent serial.print calls don't deadlock against an in-flight
/// write on another CPU (whose serial state is now never going to
/// finish because we've cli'd / halted that path). Output may interleave
/// with whatever the other CPU was printing — acceptable for a panic.
pub fn panicResetLock() void {
    @atomicStore(u32, &write_lock, 0, .release);
}

/// Bounds-safe ring push for the emergency path, where two CPUs (the
/// panicking one and a peer running its NMI snapshot) can push concurrently
/// with no lock held. Reads ring_pos into a local and clamps before
/// indexing, so a torn `ring_pos += 1` between the two CPUs can never
/// produce an out-of-bounds store. It may still lose/tear bytes in the ring
/// under that race — fine for a panic; the host serial.log is the record.
fn ringPushSafe(c: u8) void {
    var p = ring_pos;
    if (p >= RING_LEN) p = 0;
    ring[p] = c;
    p += 1;
    if (p >= RING_LEN) p = 0;
    ring_pos = p;
    total_written +%= 1;
}

/// Lock-free, bounded byte write for the fault/NMI/panic path. Waits
/// (capped) for THR-empty so the FIFO doesn't drop bytes, then writes.
/// Takes NO lock and does NO cli — safe to call from an NMI handler that
/// may have interrupted a normal `write` that still holds write_lock.
// Emergency-path degrade state. Module-level so the panicking CPU and a
// peer's NMI snapshot share it. Monotonic atomics — torn races are fine (same
// tolerance as ringPushSafe); never reset except the streak on a good drain.
// emergency_mode is a one-way latch, so this is a one-shot panic-path counter.
var emerg_stall_streak: u32 = 0;
var emerg_slow_bytes: u32 = 0;

fn emergencyPutChar(c: u8) void {
    // Two TOTAL degrade paths keep an oversized or stalled crash dump from
    // becoming a multi-second IF=0 hang that trips the peer watchdog (the
    // schedstress setTssRsp0 autopsy wedge, 2026-06-24):
    //   (a) UART not draining at all — once EMERG_STALL_GIVEUP bytes in a row
    //       hit the full poll cap, stop waiting.
    //   (b) UART draining but baud-limited — after EMERG_THROTTLE_BUDGET bytes
    //       of throttled output, stop waiting so the tail can't run past the
    //       watchdog.
    // In either degraded state we still outb the byte (it may drop if the FIFO
    // is full); the in-memory ring keeps the full text for /dev/kmsg.
    const stalled = @atomicLoad(u32, &emerg_stall_streak, .monotonic) >= EMERG_STALL_GIVEUP;
    const over_budget = @atomicLoad(u32, &emerg_slow_bytes, .monotonic) >= EMERG_THROTTLE_BUDGET;
    if (stalled or over_budget) {
        io.outb(PORT, c);
        return;
    }
    _ = @atomicRmw(u32, &emerg_slow_bytes, .Add, 1, .monotonic);
    var spins: u32 = 0;
    while (spins < EMERG_SPIN_CAP) : (spins += 1) {
        if (io.inb(LSR) & LSR_THR_EMPTY != 0) {
            @atomicStore(u32, &emerg_stall_streak, 0, .monotonic); // drained → reset streak
            io.outb(PORT, c);
            return;
        }
        asm volatile ("pause");
    }
    // Hit the cap — this byte didn't drain. Bump the stall streak; once it
    // crosses EMERG_STALL_GIVEUP we stop waiting on subsequent bytes.
    _ = @atomicRmw(u32, &emerg_stall_streak, .Add, 1, .monotonic);
    io.outb(PORT, c);
}

/// Lock-free emergency byte-string write. See `emergency_mode`.
pub fn emergencyWrite(msg: []const u8) void {
    // One-shot deferred-mode unwind: flush the ring backlog FIRST so the
    // crash dump lands AFTER the lines that led up to it, then force all
    // subsequent output synchronous (we may be about to halt — ksoftirqd
    // will never drain again). Racy vs a concurrent normal write's loaded
    // `deferred` — worst case its bytes reach only the ring, not the port.
    if (@atomicLoad(bool, &deferred, .monotonic)) {
        @atomicStore(bool, &deferred, false, .release);
        var chunk: [256]u8 = undefined;
        var guard: u32 = RING_LEN;
        while (guard > 0) {
            const n = ringRead(&drain_pos, &chunk, chunk.len);
            if (n == 0) break;
            for (chunk[0..n]) |c| emergencyPutChar(c);
            guard -|= n;
        }
    }
    for (msg) |c| {
        emergencyPutChar(c);
        ringPushSafe(c);
    }
}

/// Bounded wait for the UART transmitter to fully drain (LSR.TEMT) before
/// the panic path halts, so the tail of a crash dump isn't stranded in
/// QEMU's 16-byte FIFO. Bounded so a dead UART can't hang the halt itself.
pub fn drainFifo() void {
    var spins: u32 = 0;
    while (spins < EMERG_SPIN_CAP) : (spins += 1) {
        if (io.inb(LSR) & LSR_TEMT != 0) return;
        asm volatile ("pause");
    }
}

/// Number of bytes currently visible in the ring (≤ RING_LEN).
pub fn ringSize() u32 {
    return @min(total_written, RING_LEN);
}

/// Total bytes ever written to the log (mod 2^32). `total_written -%
/// stream_pos` gives the distance behind the head in u32-wrap-safe form.
pub fn ringEndPos() u32 {
    return total_written;
}

/// Read at conceptual stream position `*stream_pos`. Returns bytes
/// copied; advances `*stream_pos` past the bytes copied AND past any
/// bytes that fell out of the ring while the caller was away (so the
/// next call resumes at the oldest still-visible byte). Returns 0 when
/// the cursor is caught up (EOF — caller may poll later in follow mode).
pub fn ringRead(stream_pos: *u32, buf: [*]u8, count: u32) u32 {
    const tw = total_written;
    const behind = tw -% stream_pos.*;
    if (behind == 0) return 0; // caught up — EOF for one-shot, "no new data" for follow

    // If the cursor fell off the back of the ring, jump it forward to
    // the oldest still-visible byte before reading.
    if (behind > RING_LEN) stream_pos.* = tw -% RING_LEN;
    const remain = tw -% stream_pos.*;
    const take: u32 = @min(count, remain);
    var i: u32 = 0;
    while (i < take) : (i += 1) {
        const phys = (stream_pos.* +% i) % RING_LEN;
        buf[i] = ring[phys];
    }
    stream_pos.* +%= take;
    return take;
}

pub fn hex32(val: u32) void {
    const hexchars = "0123456789ABCDEF";
    write("0x");
    var buf: [8]u8 = undefined;
    var v = val;
    var i: usize = 8;
    while (i > 0) {
        i -= 1;
        buf[i] = hexchars[v & 0xF];
        v >>= 4;
    }
    write(&buf);
}

const WriterType = std.io.GenericWriter(void, error{}, writeFn);
fn writeFn(_: void, bytes: []const u8) error{}!usize {
    if (@atomicLoad(bool, &emergency_mode, .acquire)) {
        emergencyWrite(bytes);
        return bytes.len;
    }
    // Mirror write()'s load-shed backstop (see DROP_HIGH_WATER). drain_pos
    // sampled before total_written for the same anti-wrap reason as write().
    if (@atomicLoad(bool, &deferred, .monotonic)) {
        const dp = drain_pos;
        const backlog = @atomicLoad(u32, &total_written, .monotonic) -% dp;
        if (backlog > DROP_HIGH_WATER) {
            _ = @atomicRmw(u32, &dropped_bytes, .Add, @as(u32, @truncate(bytes.len)), .monotonic);
            return bytes.len;
        }
    }
    const flags = lockWrite();
    defer unlockWrite(flags);
    const to_port = !@atomicLoad(bool, &deferred, .monotonic);
    for (bytes) |b| {
        if (to_port) putChar(b);
        ringPush(b);
    }
    return bytes.len;
}
pub const writer = WriterType{ .context = {} };

/// Format and write a message. Per-CPU static buffers eliminate two issues
/// the older single-stack-local version had:
///   1. 512-byte stack-local in every klog caller bloated kstack frames,
///      leaving locals adjacent to the buf vulnerable to a `bufPrint`
///      overrun (a real concern under the new std.io.Writer machinery).
///   2. The previous `catch buf[0..buf.len]` returned ALL 512 bytes on
///      format failure — 512 bytes of `0xAA` (Zig's undefined-fill)
///      flushed straight to serial.
/// Per-CPU (vs single static) avoids two-CPU bufPrint races that would
/// otherwise scramble print_buf mid-format and emit garbled output.
// Sized to fit any plausible LAPIC id we'd run on; APs above this share
// slot 0 (output may garble in the unlikely overflow, no crash).
const PRINT_NUM_BUFS: usize = 8;
const PRINT_BUF_LEN: usize = 1024;
var print_bufs: [PRINT_NUM_BUFS][PRINT_BUF_LEN]u8 align(16) = undefined;

pub fn print(comptime format: []const u8, args: anytype) void {
    // Avoid importing smp.zig (it imports us — circular). Read LAPIC ID
    // directly. The LAPIC base (0xFEE00000) is identity-mapped at boot,
    // so this is safe even before the APIC software-init runs — BSP just
    // reads its hardware LAPIC ID from MMIO.
    const lapic_id = @import("../time/apic.zig").getLapicId();
    const cpu_idx: usize = if (lapic_id < PRINT_NUM_BUFS) @intCast(lapic_id) else 0;
    const buf = &print_bufs[cpu_idx];
    const out = std.fmt.bufPrint(buf, format, args) catch "[print: buf overflow]\n";
    write(out);
}

// Dedicated emergency format buffers — separate from print_bufs so that a
// peer interrupted by NMI mid-`print` (its print_bufs slot half-formatted)
// can format its snapshot cleanly, and so a resumed normal write (a
// non-panic diagnostic snapshot that IRETs back) still sees its original
// bytes rather than ones we overwrote.
var emerg_bufs: [PRINT_NUM_BUFS][PRINT_BUF_LEN]u8 align(16) = undefined;

/// Lock-free formatted print for the fault/NMI/panic path. Mirrors `print`
/// but formats into emerg_bufs and emits via the lock-free emergencyWrite,
/// so it can never deadlock on write_lock. nmiSnapshot/broadcastNMI call
/// this directly because they run in NMI context, possibly before
/// emergency_mode is even set; once it IS set, plain `print`/`write` also
/// route through the lock-free path automatically (no call-site changes).
pub fn emergencyPrint(comptime format: []const u8, args: anytype) void {
    const lapic_id = @import("../time/apic.zig").getLapicId();
    const idx: usize = if (lapic_id < PRINT_NUM_BUFS) @intCast(lapic_id) else 0;
    const out = std.fmt.bufPrint(&emerg_bufs[idx], format, args) catch "[emerg: buf overflow]\n";
    emergencyWrite(out);
}
