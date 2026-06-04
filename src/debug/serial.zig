const std = @import("std");
const io = @import("../io.zig");

const PORT: u16 = 0x3F8; // COM1

// Line Status Register (PORT+5) bits used ONLY by the bounded-poll
// emergency writer below (the normal putChar path is fire-and-forget on
// purpose — see putChar's comment for why).
const LSR: u16 = PORT + 5;
const LSR_THR_EMPTY: u8 = 0x20; // bit 5 — holding reg empty, OK to queue a byte
const LSR_TEMT: u8 = 0x40; // bit 6 — transmitter fully drained (FIFO + shift reg)
// Hard spin cap for every emergency LSR poll, so a wedged or absent UART
// can never turn a crash dump into a *second* hang. ~1M pause-spins is
// well under a millisecond of real time but far longer than QEMU needs to
// drain one byte.
const EMERG_SPIN_CAP: u32 = 1_000_000;

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
// 16 KiB is enough for ~150 lines of typical kernel output. Reads are
// addressed by a *monotonic stream position* (total bytes ever written),
// not by ring index — that way an fd's saved offset survives ring wraps
// and the dmesg follow loop can pick up cleanly across iterations.
// `total_written` wraps after 4 GiB which is many hours; kernel-mode
// modular subtraction (-%) makes the comparison correct across that
// boundary too.
//
// We don't try to be lockless: serial.write is already racy across cores
// (see putChar's wait-loop), and the worst case is a torn line.
const RING_LEN: u32 = 16 * 1024;
var ring: [RING_LEN]u8 = [_]u8{0} ** RING_LEN;
var ring_pos: u32 = 0; // next write index (physical, into `ring`)
var total_written: u32 = 0; // monotonic byte counter (stream position)

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
    const flags = lockWrite();
    defer unlockWrite(flags);
    for (msg) |c| {
        putChar(c);
        ringPush(c);
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
fn emergencyPutChar(c: u8) void {
    var spins: u32 = 0;
    while (spins < EMERG_SPIN_CAP) : (spins += 1) {
        if (io.inb(LSR) & LSR_THR_EMPTY != 0) break;
        asm volatile ("pause");
    }
    io.outb(PORT, c);
}

/// Lock-free emergency byte-string write. See `emergency_mode`.
pub fn emergencyWrite(msg: []const u8) void {
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
    const flags = lockWrite();
    defer unlockWrite(flags);
    for (bytes) |b| {
        putChar(b);
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
