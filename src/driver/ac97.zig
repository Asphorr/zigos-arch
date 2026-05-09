// AC97 Audio Driver — Intel ICH-compatible codec via PCI
// Uses DMA buffer descriptors for PCM playback (16-bit stereo, 22050 Hz)

const io = @import("../io.zig");
const pci = @import("pci.zig");
const pmm = @import("../mm/pmm.zig");
const paging = @import("../mm/paging.zig");
const debug = @import("../debug/debug.zig");
const SpinLock = @import("../proc/spinlock.zig").SpinLock;

/// Serializes everything that touches `bdl_phys` / `buf_phys` / the PCM-out
/// register sequence. Audio entry points are called from syscall context
/// (sys#38 audio_write) and from desktop sound effects; tick() is called
/// from IRQ0. IrqSave protects the syscall path against the same-CPU IRQ.
var lock: SpinLock = .{};

// NAM (Native Audio Mixer) register offsets — BAR0
const NAM_RESET: u16 = 0x00;
const NAM_MASTER_VOL: u16 = 0x02;
const NAM_PCM_VOL: u16 = 0x18;
const NAM_EXT_AUDIO_CTRL: u16 = 0x2A;
const NAM_SAMPLE_RATE: u16 = 0x2C;

// NABM (Native Audio Bus Master) register offsets — BAR1
const PO_BDBAR: u16 = 0x10; // Buffer Descriptor Base Address (u32)
const PO_CIV: u16 = 0x14; // Current Index Value (u8)
const PO_LVI: u16 = 0x15; // Last Valid Index (u8)
const PO_SR: u16 = 0x16; // Status (u16)
const PO_CR: u16 = 0x1B; // Control (u8)
const GLOB_CNT: u16 = 0x2C; // Global Control (u32)
const GLOB_STA: u16 = 0x30; // Global Status (u32)

const BDL_ENTRIES: u32 = 32;
const SAMPLE_RATE: u32 = 22050;
const BUF_PAGES: u32 = 4; // 16KB audio buffer

// Buffer Descriptor entry (8 bytes each)
const BufferDesc = extern struct {
    addr: u32, // physical address of PCM data
    length: u16, // number of samples (not bytes)
    flags: u16, // bit 14 = last, bit 15 = IOC
};

var nam_base: u16 = 0;
var nabm_base: u16 = 0;
var bdl_phys: usize = 0;
var buf_phys: usize = 0;
pub var initialized: bool = false;
var playing: bool = false;
var play_stop_tick: u64 = 0;

pub fn init() bool {
    // Find AC97 device: multimedia audio controller
    const dev = pci.findByClass(0x04, 0x01, 0x00) orelse {
        debug.klog("[ac97] No device found\n", .{});
        return false;
    };

    debug.klog("[ac97] Found at bus={d} dev={d} irq={d}\n", .{ dev.bus, dev.dev, dev.irq_line });

    // I/O + MEM + bus master, INTx kept (AC97 has no MSI cap).
    pci.bindDeviceLegacyIrq(dev);

    // Read I/O BARs (mask off type bit)
    const bar0_raw = pci.configRead(dev.bus, dev.dev, dev.func, 0x10);
    const bar1_raw = pci.configRead(dev.bus, dev.dev, dev.func, 0x14);
    nam_base = @truncate(bar0_raw & 0xFFFC);
    nabm_base = @truncate(bar1_raw & 0xFFFC);

    debug.klog("[ac97] NAM=0x{X:0>4} NABM=0x{X:0>4}\n", .{ nam_base, nabm_base });

    // Cold reset via Global Control
    io.outl(nabm_base + GLOB_CNT, 0x02); // cold reset
    busyWait(10);
    io.outl(nabm_base + GLOB_CNT, 0x00); // clear reset
    busyWait(10);

    // Wait for codec ready
    for (0..100) |_| {
        const sta = io.inl(nabm_base + GLOB_STA);
        if (sta & 0x100 != 0) break; // primary codec ready
        busyWait(1);
    }

    // Reset codec via NAM
    io.outb16(nam_base + NAM_RESET, 0);
    busyWait(5);

    // Set volumes (0 = max for master, lower values for PCM)
    io.outb16(nam_base + NAM_MASTER_VOL, 0x0000);
    io.outb16(nam_base + NAM_PCM_VOL, 0x0808);

    // Enable Variable Rate Audio
    var ext = io.inw(nam_base + NAM_EXT_AUDIO_CTRL);
    ext |= 1;
    io.outb16(nam_base + NAM_EXT_AUDIO_CTRL, ext);
    busyWait(2);

    // Set sample rate
    io.outb16(nam_base + NAM_SAMPLE_RATE, @intCast(SAMPLE_RATE));

    // Allocate BDL page (physically contiguous)
    bdl_phys = pmm.allocFrame() orelse return false;
    @memset(@as([*]u8, @ptrFromInt(paging.physToVirt(bdl_phys)))[0..4096], 0);

    // Allocate audio buffer (4 contiguous pages = 16KB)
    buf_phys = pmm.allocContiguous(BUF_PAGES) orelse return false;
    @memset(@as([*]u8, @ptrFromInt(paging.physToVirt(buf_phys)))[0 .. BUF_PAGES * 4096], 0);

    // Reset PCM out channel
    io.outb(nabm_base + PO_CR, 0x02); // reset
    busyWait(1);
    io.outb(nabm_base + PO_CR, 0x00); // clear reset

    // Set BDL base address
    io.outl(nabm_base + PO_BDBAR, @truncate(bdl_phys));

    initialized = true;
    debug.klog("[ac97] Initialized (sample rate: {d} Hz)\n", .{SAMPLE_RATE});
    return true;
}

fn busyWait(ticks: u32) void {
    // Simple delay using PIT counter reads
    for (0..@as(usize, ticks) * 10000) |_| {
        asm volatile ("pause");
    }
}

/// Play PCM buffer via DMA. num_samples = per-channel sample count.
pub fn playBuffer(num_samples: u32) void {
    if (!initialized or num_samples == 0) return;

    // Reset PCM out channel (required to restart after completion)
    io.outb(nabm_base + PO_CR, 0x02); // bit 1 = reset
    for (0..1000) |_| {
        if (io.inb(nabm_base + PO_CR) & 0x02 == 0) break;
        asm volatile ("pause");
    }
    // Clear status
    io.outb16(nabm_base + PO_SR, 0x1C);

    // Set BDL entry 0 = audio data, entry 1 = zero-length stop marker
    const bdl: [*]volatile BufferDesc = @ptrFromInt(paging.physToVirt(bdl_phys));
    bdl[0].addr = @truncate(buf_phys);
    bdl[0].length = @intCast(@min(num_samples, 0xFFFE));
    bdl[0].flags = 0x4000; // IOC (not last — continue to entry 1)
    // Entry 1: empty buffer to halt DMA after playback
    bdl[1].addr = @truncate(buf_phys); // point anywhere valid
    bdl[1].length = 1; // minimum
    bdl[1].flags = 0xC000; // IOC + Last

    // Set BDL base
    io.outl(nabm_base + PO_BDBAR, @truncate(bdl_phys));
    // Last valid index = 1 (stop after entry 1)
    io.outb(nabm_base + PO_LVI, 1);
    // Start playback
    io.outb(nabm_base + PO_CR, 0x01);
    playing = true;
    // Calculate stop time: samples / sample_rate * 100 ticks/sec + small margin
    const duration_ticks = (num_samples * 100 / SAMPLE_RATE) + 5;
    play_stop_tick = @import("../proc/process.zig").tick_count + duration_ticks;
}

/// Write 16-bit signed stereo PCM samples to the audio buffer and play.
/// Called from user-space audio syscall. Samples are interleaved L,R,L,R...
pub fn writeSamples(src: [*]const i16, stereo_samples: u32) void {
    if (!initialized or stereo_samples == 0) return;
    const flags = lock.acquireIrqSave();
    defer lock.releaseIrqRestore(flags);
    const max_samples = BUF_PAGES * 4096 / 2; // max i16 values in buffer
    const count = @min(stereo_samples * 2, max_samples); // stereo = 2 i16 per sample
    const dst: [*]volatile i16 = @ptrFromInt(paging.physToVirt(buf_phys));
    for (0..count) |i| dst[i] = src[i];
    playBuffer(stereo_samples);
}

/// Called from IRQ0 — stop DMA when playback duration has elapsed.
pub fn tick() void {
    if (!playing) return;
    // Already in IRQ context (cli'd) — plain acquire is fine; we just need
    // to fence against a syscall on another CPU mid-playBuffer setup.
    lock.acquire();
    defer lock.release();
    if (@import("../proc/process.zig").tick_count >= play_stop_tick) {
        io.outb(nabm_base + PO_CR, 0x00); // stop DMA
        io.outb16(nabm_base + PO_SR, 0x1C); // clear status
        playing = false;
    }
}

/// Generate triangle wave (smoother than square). Returns sample count.
fn generateTriangle(offset: u32, freq: u32, duration_ms: u32, volume: i16) u32 {
    if (freq == 0) return 0;
    const num = SAMPLE_RATE * duration_ms / 1000;
    const period = SAMPLE_RATE / freq;
    if (period == 0) return 0;
    const half = period / 2;
    if (half == 0) return 0;
    const samples: [*]i16 = @ptrFromInt(paging.physToVirt(buf_phys));
    const max_samples = BUF_PAGES * 4096 / 4; // 16KB / 4 bytes per stereo sample
    var i: u32 = 0;
    while (i < num and (offset / 4 + i) < max_samples) : (i += 1) {
        const phase = i % period;
        const vol32: i32 = volume;
        const val: i16 = if (phase < half)
            @intCast(@divTrunc(vol32 * (2 * @as(i32, @intCast(phase)) - @as(i32, @intCast(half))), @as(i32, @intCast(half))))
        else
            @intCast(@divTrunc(vol32 * (3 * @as(i32, @intCast(half)) - 2 * @as(i32, @intCast(phase))), @as(i32, @intCast(half))));
        const idx = offset / 2 + i * 2;
        samples[idx] = val; // Left
        samples[idx + 1] = val; // Right
    }
    return i;
}

/// Generate square wave. Returns sample count.
fn generateSquare(offset: u32, freq: u32, duration_ms: u32, volume: i16) u32 {
    if (freq == 0) {
        // Silence
        const num = SAMPLE_RATE * duration_ms / 1000;
        const samples: [*]i16 = @ptrFromInt(paging.physToVirt(buf_phys));
        const max_samples = BUF_PAGES * 4096 / 4;
        var i: u32 = 0;
        while (i < num and (offset / 4 + i) < max_samples) : (i += 1) {
            const idx = offset / 2 + i * 2;
            samples[idx] = 0;
            samples[idx + 1] = 0;
        }
        return i;
    }
    const num = SAMPLE_RATE * duration_ms / 1000;
    const half_period = SAMPLE_RATE / (freq * 2);
    if (half_period == 0) return 0;
    const samples: [*]i16 = @ptrFromInt(paging.physToVirt(buf_phys));
    const max_samples = BUF_PAGES * 4096 / 4;
    var i: u32 = 0;
    while (i < num and (offset / 4 + i) < max_samples) : (i += 1) {
        const phase = i % (half_period * 2);
        const val: i16 = if (phase < half_period) volume else -volume;
        const idx = offset / 2 + i * 2;
        samples[idx] = val;
        samples[idx + 1] = val;
    }
    return i;
}

// --- Sound Effects (same API as speaker.zig) ---

pub fn startup() void {
    const flags = lock.acquireIrqSave();
    defer lock.releaseIrqRestore(flags);
    var off: u32 = 0;
    off += generateTriangle(off, 523, 100, 8000) * 4;
    off += generateTriangle(off, 659, 100, 8000) * 4;
    off += generateTriangle(off, 784, 150, 8000) * 4;
    playBuffer(off / 4);
}

pub fn click() void {
    const flags = lock.acquireIrqSave();
    defer lock.releaseIrqRestore(flags);
    const n = generateSquare(0, 1400, 15, 4000);
    playBuffer(n);
}

pub fn open() void {
    const flags = lock.acquireIrqSave();
    defer lock.releaseIrqRestore(flags);
    var off: u32 = 0;
    off += generateTriangle(off, 600, 40, 6000) * 4;
    off += generateTriangle(off, 900, 40, 6000) * 4;
    playBuffer(off / 4);
}

pub fn close() void {
    const flags = lock.acquireIrqSave();
    defer lock.releaseIrqRestore(flags);
    var off: u32 = 0;
    off += generateTriangle(off, 800, 40, 6000) * 4;
    off += generateTriangle(off, 500, 40, 6000) * 4;
    playBuffer(off / 4);
}

pub fn err() void {
    const flags = lock.acquireIrqSave();
    defer lock.releaseIrqRestore(flags);
    var off: u32 = 0;
    off += generateSquare(off, 250, 60, 6000) * 4;
    off += generateSquare(off, 0, 30, 0) * 4;
    off += generateSquare(off, 200, 80, 6000) * 4;
    playBuffer(off / 4);
}

pub fn notify() void {
    const flags = lock.acquireIrqSave();
    defer lock.releaseIrqRestore(flags);
    var off: u32 = 0;
    off += generateTriangle(off, 880, 50, 6000) * 4;
    off += generateTriangle(off, 1100, 70, 6000) * 4;
    playBuffer(off / 4);
}
