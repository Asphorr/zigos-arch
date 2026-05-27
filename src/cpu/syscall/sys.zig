//! Syscall handlers (sys) — split out of syscall.zig (#797).
//! Dispatched from cpu/syscall.zig doSyscallInner; named in SYSCALLS.

const std = @import("std");
const vga = @import("../../ui/vga.zig");
const elf_loader = @import("../../proc/elf_loader.zig");
const keyboard = @import("../../driver/keyboard.zig");
const process = @import("../../proc/process.zig");
const vmm = @import("../../mm/vmm.zig");
const pmm = @import("../../mm/pmm.zig");
const paging = @import("../../mm/paging.zig");
const bga = @import("../../ui/bga.zig");
const vfs = @import("../../fs/vfs.zig");
const desktop = @import("../../ui/desktop.zig");
const xhci = @import("../../driver/xhci.zig");
const debug = @import("../../debug/debug.zig");
const perf = @import("../../debug/perf.zig");
const pipe = @import("../../proc/pipe.zig");
const memmap = @import("../../mm/memmap.zig");
const config = @import("../../config.zig");
const smp = @import("../smp.zig");
const signals = @import("../../proc/signals.zig");
const errno = @import("../../proc/errno.zig");
const sched_asm = @import("../../proc/sched_asm.zig");
const apic = @import("../../time/apic.zig");

const common = @import("common.zig");
const validateUserPtr = common.validateUserPtr;
const validateUserPtrAligned = common.validateUserPtrAligned;
const USER_SPACE_START = common.USER_SPACE_START;
const USER_SPACE_END = common.USER_SPACE_END;
const E_INVAL = common.E_INVAL;
const E_NOENT = common.E_NOENT;
const E_FAULT = common.E_FAULT;
const E_BADF = common.E_BADF;
const E_NOMEM = common.E_NOMEM;
const E_AGAIN = common.E_AGAIN;
const E_BUSY = common.E_BUSY;
const E_NAMETOOLONG = common.E_NAMETOOLONG;
const E_PIPE = common.E_PIPE;
const E_SRCH = common.E_SRCH;
const E_NOSYS = common.E_NOSYS;
const E_PERM = common.E_PERM;
const E_CHILD = common.E_CHILD;
const E_INTR = common.E_INTR;

pub fn sysAudioWrite(buf_ptr: u32, num_samples: u32) u32 {
    if (num_samples == 0 or num_samples > 8192) return E_INVAL;
    if (!validateUserPtrAligned(buf_ptr, num_samples * 4, 2)) return E_FAULT; // stereo i16 = 4 bytes/sample, 2-byte aligned
    const sound = @import("../../driver/sound.zig");
    if (!sound.isReady()) return E_INVAL;
    const src: [*]const i16 = @ptrFromInt(@as(usize, buf_ptr));
    sound.writeSamples(src, num_samples);
    return 0;
}

pub fn sysSetConfig(key: u32, value: u32) u32 {
    const val: u8 = @truncate(value);
    switch (key) {
        0 => { // resolution: 0=720p, 1=1080p
            if (val <= 1) desktop.conf.resolution = val;
        },
        1 => { // background: 0=blue, 1=purple, 2=green, 3=red
            if (val <= 3) desktop.conf.bg = val;
        },
        2 => { // theme: 0=light, 1=dark
            if (val <= 1) desktop.conf.theme = val;
        },
        3 => { // mouse speed: 0=slow, 1=normal, 2=fast
            if (val <= 2) desktop.conf.mouse_speed = val;
        },
        4 => { // dock position: 0=bottom, 1=top
            if (val <= 1) desktop.conf.dock_pos = val;
        },
        255 => { // apply
            desktop.config_changed = true;
            // Wake the event-driven compositor so the apply path runs
            // promptly instead of waiting for the next input event.
            desktop.wake.requestWake();
        },
        else => return 0xFFFFFFFF,
    }
    return 0;
}

pub fn sysMeminfo(buf_ptr: u32) u32 {
    if (!validateUserPtrAligned(buf_ptr, 8, 4)) return E_FAULT;
    const buf: [*]u32 = @ptrFromInt(@as(usize, buf_ptr));
    buf[0] = pmm.freeFrameCount();
    buf[1] = pmm.managedFrameCount();
    return 0;
}

/// Per-CPU tick stats — `(irq_ticks, idle_ticks)` u64 pair per alive CPU,
/// packed sequentially. Caller passes a buffer sized for `max_cpus` entries
/// (16 bytes each); we fill up to the alive count and return the actual
/// count written. Returns E_FAULT on bad user pointer or buf too small.
///
/// Used by sysmon / top-style tools: compute `(d_irq - d_idle) / d_irq * 100`
/// across two snapshots to get instantaneous utilization per CPU.
const CpuStat = extern struct {
    irq_ticks: u64,
    idle_ticks: u64,
};

pub fn sysCpuStats(buf_ptr: u32, max_cpus: u32) u32 {
    if (max_cpus == 0) return E_INVAL;
    // Clamp BEFORE computing byte_len — the redteam fuzzer hands us
    // max_cpus=0x7fffffff which would overflow u32 in the multiply
    // below (`* 16`). MAX_CPUS is tiny (single digits typically), so
    // capping here costs nothing for honest callers.
    const clamped: u32 = if (max_cpus > smp.MAX_CPUS) smp.MAX_CPUS else max_cpus;
    const byte_len: u32 = clamped * @sizeOf(CpuStat);
    if (!validateUserPtrAligned(buf_ptr, byte_len, @alignOf(CpuStat))) return E_FAULT;
    const buf: [*]CpuStat = @ptrFromInt(@as(usize, buf_ptr));
    var written: u32 = 0;
    for (&smp.cpus) |*c| {
        if (!c.alive) continue;
        if (written >= clamped) break;
        buf[written] = .{
            .irq_ticks = @atomicLoad(u64, &c.irq_tick_count, .acquire),
            .idle_ticks = @atomicLoad(u64, &c.idle_tick_count, .acquire),
        };
        written += 1;
    }
    return written;
}

/// klog(buf, len) — write `buf[0..len]` directly to kernel serial, prefixed
/// with the calling PID. Bypasses the fd table, so apps whose stdout is wired
/// to a pipe (children of the shell, GUI launches that go through a terminal
/// host) can still emit traceable diagnostics that show up in serial.log.
/// Truncates len to 256 to keep the kernel from spending serial bandwidth on
/// runaway output.
pub fn sysKlog(buf_ptr: u32, len: u32) u32 {
    if (len == 0) return 0;
    const safe_len: u32 = @min(len, 256);
    if (!validateUserPtr(buf_ptr, safe_len)) return E_FAULT;
    const ptr: [*]const u8 = @ptrFromInt(@as(usize, buf_ptr));
    const pid = process.getCurrentPid();
    @import("../../debug/serial.zig").print("[klog pid={d}] {s}", .{ pid, ptr[0..safe_len] });
    return 0;
}

/// shutdown(mode) — flush filesystem caches and ask the platform to power
/// off (mode 0) or reboot (mode 1). For poweroff: prefers FADT.PM1a_CNT
/// (and PM1b_CNT if present) so real hardware is supported, then falls
/// back to the legacy QEMU/Bochs/VBox port magic for environments where
/// ACPI parsing failed. Reboot uses the standard PCI reset register
/// (0xCF9) with an 8042 fallback. Never returns on success.
///
/// SLP_TYPa = 5 (S5 — soft off) is hardcoded. The "right" way is to read
/// the value from DSDT's `\_S5_` package, but that requires an AML
/// interpreter; every BIOS we've ever seen uses 5 here, and QEMU
/// accepts any SLP_TYP when SLP_EN=1.
pub fn sysShutdown(mode: u32) u32 {
    const io = @import("../../io.zig");
    const fat32 = @import("../../fs/fat32.zig");
    const acpi = @import("../../time/acpi.zig");

    // Best-effort: flush dirty FS caches before yanking the power.
    if (fat32.isInitialized()) fat32.flushAll();
    // Then commit any in-flight NVMe writes to non-volatile storage —
    // without this, the device write cache can lose recent writes on
    // power-off even after fat32.flushAll has drained the OS-side caches.
    @import("../../driver/nvme.zig").flushAll();

    if (mode == 1) {
        // Reboot path, preferred order:
        //   1. Hyper-V reset MSR — clean hypervisor-mediated reset on QEMU
        //      with `-cpu host,hv-reset` or real Hyper-V. Synchronous; we
        //      don't return if the host honors it. Skipped when the MSR
        //      isn't exposed.
        //   2. ACPI reset register (FADT.reset_reg + reset_value). Modern
        //      Intel ME / AMD PSP hold reset state in a way only ACPI's
        //      preferred reset path clears cleanly. No-op when the BIOS
        //      didn't fill in FADT.reset_reg (older systems).
        //   3. PCI reset register (port 0xCF9, bit 1 = system reset,
        //      bit 2 pulsed = full reset) — modern QEMU honors this.
        //   4. 8042 keyboard controller pulse — bare-metal fallback that
        //      works on every PC since the AT, but is occasionally
        //      ignored by VMs.
        // Each attempt does nothing if the previous already triggered;
        // the kernel just keeps writing reset registers until something
        // takes.
        const hyperv = @import("../../virt/hyperv.zig");
        _ = hyperv.tryReset();
        acpi.tryReset();
        io.outb(0xCF9, 0x06);
        var spin: u32 = 0;
        while ((io.inb(0x64) & 0x02) != 0 and spin < 100000) : (spin += 1) {}
        io.outb(0x64, 0xFE);
    } else {
        // SLP_TYPa=5, SLP_EN=1 → bit pattern 0x3400. Writing this to
        // PM1a_CNT (and PM1b_CNT if non-zero) is the spec-mandated
        // way to enter S5.
        const sleep_word: u16 = (@as(u16, 5) << 10) | (1 << 13);
        if (acpi.getFadt()) |f| {
            if (f.pm1a_cnt_blk != 0) io.outw(@truncate(f.pm1a_cnt_blk), sleep_word);
            if (f.pm1b_cnt_blk != 0) io.outw(@truncate(f.pm1b_cnt_blk), sleep_word);
        }
        // Belt-and-suspenders for hosts where FADT was unparseable or
        // the FADT-named port isn't actually wired (some emulator
        // configs leave PM1a_CNT_BLK as zero and rely on the port magic).
        io.outw(0x604, 0x2000); // QEMU
        io.outw(0xB004, 0x2000); // Bochs
        io.outw(0x4004, 0x3400); // VirtualBox
    }

    // If we're still alive, halt forever.
    while (true) asm volatile ("cli; hlt");
}

/// User-visible USB MSC info struct. Layout matches libc's UsbInfo.
const UsbInfoUser = extern struct {
    present: u8,
    _pad: [3]u8 = .{ 0, 0, 0 },
    block_size: u32,
    block_count: u32,
};

/// usb_info(info_ptr) — fill `info_ptr` with the present/size of the first
/// USB Mass Storage device. Returns 0 if a device exists, 0xFFFFFFFF if no
/// MSC device is connected. Either way the struct is zero-initialised first
/// so callers can read `present` to be sure.
pub fn sysUsbInfo(info_ptr: u32) u32 {
    if (!validateUserPtrAligned(info_ptr, @sizeOf(UsbInfoUser), @alignOf(UsbInfoUser))) return E_INVAL;
    const dst: *UsbInfoUser = @ptrFromInt(@as(usize, info_ptr));
    dst.* = .{ .present = 0, .block_size = 0, .block_count = 0 };
    if (!xhci.hasMscDevice()) return E_INVAL;
    dst.* = .{
        .present = 1,
        .block_size = xhci.getMscBlockSize(),
        .block_count = xhci.getMscBlockCount(),
    };
    return 0;
}

/// usb_read_sector(lba, buf) — read one MSC block (typically 512 B) from
/// `lba` into the user buffer. Caller is responsible for sizing the buffer
/// to match the device's reported block_size — we only validate the page
/// containing the buffer pointer; mistaken caller sizing risks overflowing
/// later memory. Returns 0 on success.
pub fn sysUsbReadSector(lba: u32, buf_ptr: u32) u32 {
    if (!xhci.hasMscDevice()) return E_INVAL;
    const block_size = xhci.getMscBlockSize();
    if (block_size == 0 or block_size > 4096) return E_INVAL;
    if (!validateUserPtr(buf_ptr, block_size)) return E_FAULT;
    const buf: [*]u8 = @ptrFromInt(@as(usize, buf_ptr));
    if (!xhci.mscReadSectors(lba, 1, buf)) return E_INVAL;
    return 0;
}

/// usb_write_sector(lba, buf) — write one MSC block. Same sizing contract
/// as `sysUsbReadSector`. Returns 0 on success, 0xFFFFFFFF if no device or
/// the underlying SCSI WRITE(10) failed.
pub fn sysUsbWriteSector(lba: u32, buf_ptr: u32) u32 {
    if (!xhci.hasMscDevice()) return E_INVAL;
    const block_size = xhci.getMscBlockSize();
    if (block_size == 0 or block_size > 4096) return E_INVAL;
    if (!validateUserPtr(buf_ptr, block_size)) return E_FAULT;
    const buf: [*]const u8 = @ptrFromInt(@as(usize, buf_ptr));
    if (!xhci.mscWriteSectors(lba, 1, buf)) return E_INVAL;
    return 0;
}

/// debug_crash(variant) — deliberately trigger one kernel crash class
/// to exercise the panic / autopsy / halt-all-CPUs machinery. Used by
/// app/crashtest.elf as a CI / regression smoke for the panic path.
///
/// Modeled on style9's `cmd_crash` (BSD-style sibling project) which
/// validates the same five fault classes from its in-kernel shell.
/// ZigOS has no in-kernel shell, so we route through a syscall instead.
///
///   1 = dfree     — heap double-free (heap detects mismatched header)
///   2 = wild      — kfree at offset +64 of a real allocation (header magic mismatch)
///   3 = assert    — @panic from kernel code path
///   4 = unmapped  — write to canonical-unmapped kernel VA (#PF in ring 0)
///   5 = nonc      — write to non-canonical VA (#GP, vec 13)
///   6 = panic     — direct @panic("crashtest: user-requested")
///
/// Returns 0xFFFFFFFF for unknown variant (the others never return —
/// they trigger panic which halts the system).
pub fn sysDebugCrash(variant: u32) u32 {
    const heap = @import("../../mm/heap.zig");
    debug.klog("[crashtest] sysDebugCrash variant={d}\n", .{variant});

    switch (variant) {
        1 => {
            // dfree: kalloc → kfree → kfree. The second kfree should trip
            // heap's free-list / canary check and panic.
            const p = heap.kalloc(64) orelse @panic("crashtest dfree: kalloc returned null");
            heap.kfree(p);
            debug.klog("[crashtest] dfree: freeing {*} a second time...\n", .{p});
            heap.kfree(p);
            @panic("crashtest dfree: kfree double-free should have panicked");
        },
        2 => {
            // wild: kfree at the wrong offset. The 64-byte header in front
            // of `p + 64` is allocation payload, not a heap header — the
            // canary / size check fires.
            const p = heap.kalloc(128) orelse @panic("crashtest wild: kalloc returned null");
            debug.klog("[crashtest] wild: kfree({*} + 64)...\n", .{p});
            heap.kfree(@as([*]u8, @ptrCast(p)) + 64);
            @panic("crashtest wild: misaligned kfree should have panicked");
        },
        3 => {
            // assert: deliberate kernel @panic — tests the dump pipeline
            // independently of any specific corruption shape.
            @panic("crashtest assert: deliberate KASSERT-equivalent");
        },
        4 => {
            // unmapped: high-half VA in an empty PML4 slot. Kernel
            // physmap = PML4[256] (0xFFFF800000000000), vmalloc = PML4[258].
            // PML4[273] = 0xFFFF888000000000 is left empty by setup —
            // write triggers a kernel-mode #PF that the exception handler
            // panics on (ring-3-only fault servicing).
            const up: *volatile u64 = @ptrFromInt(0xFFFF888000000000);
            debug.klog("[crashtest] unmapped: writing 0xDEAD to {*}...\n", .{up});
            up.* = 0xDEAD;
            @panic("crashtest unmapped: write to empty PML4 slot should have faulted");
        },
        5 => {
            // nonc: bit 47 set, bits 48-63 zero → non-canonical. Touching
            // it raises #GP (vector 13), distinct fault class from #PF.
            const up: *volatile u64 = @ptrFromInt(0x0000800000000000);
            debug.klog("[crashtest] nonc: writing 0xDEAD to non-canonical {*}...\n", .{up});
            up.* = 0xDEAD;
            @panic("crashtest nonc: write to non-canonical should have GP'd");
        },
        6 => {
            @panic("crashtest panic: user-requested deliberate panic");
        },
        else => return 0xFFFFFFFF,
    }
}

