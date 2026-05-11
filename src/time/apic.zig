// Local APIC + IOAPIC driver — replaces legacy 8259 PIC + PIT timer
// Provides 100Hz periodic timer via APIC LVT Timer, external IRQ routing via IOAPIC

const io = @import("../io.zig");
const paging = @import("../mm/paging.zig");
const acpi = @import("acpi.zig");
const debug = @import("../debug/debug.zig");

// Local APIC + IOAPIC bases — stored as kernel-pointer VAs through the
// physmap (PHYSMAP_BASE + phys). Phase 3 dropped PML4[0], so the raw
// phys form (0xFEE00000) is no longer dereferenceable in supervisor
// mode. `lapicRead`/`Write` and `ioapicRead`/`Write` cast these to
// `*volatile u32` directly, so the stored value must already be in the
// kernel virtual range. `applyAcpi` translates MADT phys overrides into
// the physmap form before assigning.
var lapic_base: u64 = paging.PHYSMAP_BASE + 0xFEE00000;
var ioapic_base: u64 = paging.PHYSMAP_BASE + 0xFEC00000;
/// GSI base of the IOAPIC we wired into `ioapic_base`. Captured from MADT
/// so initIOAPIC's range log reads "GSI N..M" instead of just "N entries"
/// — on multi-IOAPIC systems IOAPIC 0 doesn't always start at GSI 0.
var ioapic_gsi_base: u32 = 0;

// MADT-derived ISA IRQ → GSI remap. Entry [n] is the GSI that ISA IRQ n
// is delivered to; 0xFF means "no override, identity map". The most
// common override is IRQ0 → GSI 2 (since GSI 0 is owned by the timer
// LVT on a unified IOAPIC).
var iso_remap: [16]u8 = [_]u8{0xFF} ** 16;
var iso_flags: [16]u16 = [_]u16{0} ** 16;

const LAPIC_ID: u32 = 0x020;
const LAPIC_VER: u32 = 0x030;
const LAPIC_TPR: u32 = 0x080;
const LAPIC_EOI: u32 = 0x0B0;
const LAPIC_SVR: u32 = 0x0F0;
const LAPIC_LVT_TIMER: u32 = 0x320;
const LAPIC_LVT_LINT0: u32 = 0x350;
const LAPIC_LVT_LINT1: u32 = 0x360;
const LAPIC_TIMER_ICR: u32 = 0x380;
const LAPIC_TIMER_CCR: u32 = 0x390;
const LAPIC_TIMER_DCR: u32 = 0x3E0;

// IOAPIC MMIO registers (offsets from `ioapic_base`)
const IOAPIC_REGSEL: u32 = 0x00;
const IOAPIC_WIN: u32 = 0x10;
const IOAPIC_VER_REG: u32 = 0x01;
const IOAPIC_REDTBL: u32 = 0x10;

// IOAPIC redirection-entry low-dword bits (Intel 82093AA datasheet —
// "I/O Redirection Table Register" section).
//   [7:0]   Vector             [10:8]  Delivery mode (000 = Fixed)
//   [11]    Dest mode (0=phys) [12]    Delivery status (RO)
//   [13]    Polarity (0=high, 1=low)
//   [14]    Remote IRR (RO)
//   [15]    Trigger (0=edge, 1=level)
//   [16]    Mask
const IOAPIC_LO_POLARITY_LOW: u32 = 1 << 13;
const IOAPIC_LO_TRIGGER_LEVEL: u32 = 1 << 15;
const IOAPIC_LO_MASKED: u32 = 1 << 16;

// APIC Base MSR
const IA32_APIC_BASE_MSR: u32 = 0x1B;
const IA32_TSC_DEADLINE_MSR: u32 = 0x6E0;

// LVT Timer mode bits (17:18). One-shot=00, Periodic=01, TSC-Deadline=10.
const LVT_TIMER_MODE_TSC_DEADLINE: u32 = 2 << 17;

pub var apic_active: bool = false;
var apic_timer_count: u32 = 0;

// TSC-deadline mode replaces the LAPIC count-down timer with a per-CPU
// MSR write of an absolute TSC deadline. More accurate (no 10MHz LAPIC
// divider quantization) and present on essentially every CPU made
// after 2009. Detected via CPUID.01H ECX bit 24; falls back cleanly to
// count-down mode if missing.
pub var tsc_deadline_active: bool = false;
var tsc_per_quantum: u64 = 0;

// x2APIC mode swaps LAPIC MMIO for MSR access (range 0x800-0x83F) and
// gives 32-bit destination IDs in the ICR. We don't auto-enable it —
// xAPIC works fine for our MAX_CPUS — but we honour it if firmware
// already turned it on (some UEFI implementations do, and once enabled
// you cannot disable without a CPU reset). Detected by re-reading
// IA32_APIC_BASE bit 10 after our enable-bit-11 write.
pub var x2apic_active: bool = false;

inline fn lapicMsr(reg: u32) u32 {
    return 0x800 + reg / 16;
}

inline fn x2apicRead(reg: u32) u32 {
    var lo: u32 = undefined;
    asm volatile ("rdmsr"
        : [lo] "={eax}" (lo)
        : [msr] "{ecx}" (lapicMsr(reg))
        : .{ .edx = true });
    return lo;
}

inline fn x2apicWrite(reg: u32, val: u32) void {
    asm volatile ("wrmsr"
        :
        : [msr] "{ecx}" (lapicMsr(reg)),
          [lo] "{eax}" (val),
          [hi] "{edx}" (@as(u32, 0)));
}

pub inline fn readTsc() u64 {
    var lo: u32 = undefined;
    var hi: u32 = undefined;
    asm volatile ("rdtsc"
        : [lo] "={eax}" (lo),
          [hi] "={edx}" (hi),
    );
    return (@as(u64, hi) << 32) | lo;
}

/// Convert a TSC delta to milliseconds using the calibrated TSC rate.
/// Returns 0 before APIC calibration completes.
pub fn tscToMs(delta: u64) u64 {
    if (tsc_per_quantum == 0) return 0;
    return delta * 10 / tsc_per_quantum;
}

/// TSC ticks per 10ms LAPIC quantum, or 0 if calibration hasn't run yet.
/// Callers building wall-clock TSC deadlines should multiply by the
/// number of quanta they want and fall back to a conservative baseline
/// when the return value is 0.
pub fn tscPerQuantum() u64 {
    return tsc_per_quantum;
}

inline fn rdtsc() u64 {
    var lo: u32 = undefined;
    var hi: u32 = undefined;
    asm volatile ("rdtsc"
        : [lo] "={eax}" (lo),
          [hi] "={edx}" (hi),
    );
    return (@as(u64, hi) << 32) | lo;
}

inline fn wrmsr(msr: u32, val: u64) void {
    asm volatile ("wrmsr"
        :
        : [msr] "{ecx}" (msr),
          [lo] "{eax}" (@as(u32, @truncate(val))),
          [hi] "{edx}" (@as(u32, @truncate(val >> 32))),
    );
}

fn detectTscDeadline() bool {
    var ecx: u32 = undefined;
    asm volatile ("cpuid"
        : [ecx] "={ecx}" (ecx)
        : [eax] "{eax}" (@as(u32, 1))
        : .{ .ebx = true, .edx = true });
    return (ecx & (1 << 24)) != 0;
}

// --- LAPIC MMIO access ---

const LAPIC_ICR_LO: u32 = 0x300;
const LAPIC_ICR_HI: u32 = 0x310;

pub fn lapicRead(reg: u32) u32 {
    if (x2apic_active) return x2apicRead(reg);
    return @as(*volatile u32, @ptrFromInt(lapic_base + reg)).*;
}

pub fn lapicWrite(reg: u32, val: u32) void {
    if (x2apic_active) {
        x2apicWrite(reg, val);
        return;
    }
    @as(*volatile u32, @ptrFromInt(lapic_base + reg)).* = val;
}

// --- IOAPIC MMIO access ---

fn ioapicRead(reg: u32) u32 {
    @as(*volatile u32, @ptrFromInt(ioapic_base + IOAPIC_REGSEL)).* = reg;
    return @as(*volatile u32, @ptrFromInt(ioapic_base + IOAPIC_WIN)).*;
}

fn ioapicWrite(reg: u32, val: u32) void {
    @as(*volatile u32, @ptrFromInt(ioapic_base + IOAPIC_REGSEL)).* = reg;
    @as(*volatile u32, @ptrFromInt(ioapic_base + IOAPIC_WIN)).* = val;
}

/// Read MADT (if present) and override `lapic_base`, `ioapic_base`, and
/// `iso_remap` from the firmware-provided values. Map the overridden
/// addresses if they differ from the architectural defaults — `mapAPIC`
/// in paging.zig only maps the spec-default 0xFEC/FEE pages.
///
/// `m.lapic_addr` / `e.ioapic_addr` are *physical* addresses from the MADT.
/// `lapic_base` / `ioapic_base` store the kernel-pointer view (physmap VA),
/// so each override is `physToVirt(phys)`. The phys form is also passed to
/// `paging.mapMMIO` (which is a no-op for phys < 64 GB after Phase 3, but
/// stays correct for higher BARs in case future hardware needs them).
fn applyAcpi() void {
    const m = acpi.getMadt() orelse return;
    if (m.lapic_addr != 0) {
        const new_va = paging.physToVirt(m.lapic_addr);
        if (new_va != lapic_base) {
            debug.klog("[apic] MADT overrides LAPIC base: phys 0x{x} (was VA 0x{x})\n", .{ m.lapic_addr, lapic_base });
            lapic_base = new_va;
            paging.mapMMIO(@intCast(m.lapic_addr), 0x1000);
        }
    }

    const Ctx = struct {
        ioapic_seen: bool = false,
    };
    var ctx = Ctx{};
    const Walker = struct {
        fn cb(c: *Ctx, h: *align(1) const acpi.MadtEntryHeader) void {
            switch (@as(acpi.MadtType, @enumFromInt(h.entry_type))) {
                .ioapic => {
                    const e: *align(1) const acpi.MadtIoapic = @ptrCast(h);
                    if (!c.ioapic_seen) {
                        const new_va = paging.physToVirt(e.ioapic_addr);
                        if (new_va != ioapic_base) {
                            debug.klog("[apic] MADT overrides IOAPIC base: phys 0x{x} (was VA 0x{x})\n", .{ e.ioapic_addr, ioapic_base });
                            ioapic_base = new_va;
                            paging.mapMMIO(@intCast(e.ioapic_addr), 0x1000);
                        }
                        ioapic_gsi_base = e.gsi_base;
                        debug.klog("[apic] IOAPIC[0] phys=0x{x} gsi_base={d} (active)\n", .{ e.ioapic_addr, e.gsi_base });
                        c.ioapic_seen = true;
                    } else {
                        // Multiple IOAPICs on real hardware — we only
                        // wire the first one. Workstations / servers
                        // sometimes route specific GSIs (e.g. PCH legacy
                        // IRQs vs CPU-local sources) across separate
                        // IOAPICs; if a device's GSI is outside the
                        // first IOAPIC's range, MSI-X works (bypasses
                        // IOAPIC) but legacy IRQ doesn't.
                        debug.klog("[apic] IOAPIC[+] phys=0x{x} gsi_base={d} (NOT WIRED — IRQs in this range need MSI-X)\n", .{ e.ioapic_addr, e.gsi_base });
                    }
                },
                .interrupt_source_override => {
                    const e: *align(1) const acpi.MadtIso = @ptrCast(h);
                    if (e.source < 16) {
                        iso_remap[e.source] = @intCast(e.gsi);
                        iso_flags[e.source] = e.flags;
                        debug.klog("[apic] MADT ISO: ISA IRQ{d} -> GSI{d} flags=0x{x}\n", .{ e.source, e.gsi, e.flags });
                    }
                },
                else => {},
            }
        }
    };
    acpi.forEachMadtEntry(Ctx, &ctx, Walker.cb);
}

/// Translate a legacy ISA IRQ number to its GSI per MADT ISO entries.
/// Returns the IRQ unchanged if no override applies.
fn isaToGsi(isa_irq: u8) u8 {
    if (isa_irq >= 16) return isa_irq;
    const m = iso_remap[isa_irq];
    return if (m == 0xFF) isa_irq else m;
}

// --- CPUID detection ---

pub fn detect() bool {
    var edx: u32 = undefined;
    asm volatile ("cpuid"
        : [edx] "={edx}" (edx)
        : [eax] "{eax}" (@as(u32, 1))
        : .{ .ebx = true, .ecx = true }
    );
    return (edx & (1 << 9)) != 0;
}

// --- PIC disable ---

fn disablePIC() void {
    // Remap PIC to vectors 0xF0-0xFF (out of the way of APIC vectors)
    io.outb(0x20, 0x11);
    io.outb(0xA0, 0x11);
    io.outb(0x21, 0xF0);
    io.outb(0xA1, 0xF8);
    io.outb(0x21, 0x04);
    io.outb(0xA1, 0x02);
    io.outb(0x21, 0x01);
    io.outb(0xA1, 0x01);
    // Mask all IRQs
    io.outb(0x21, 0xFF);
    io.outb(0xA1, 0xFF);
    debug.klog("[apic] Legacy PIC disabled\n", .{});
}

// --- IOAPIC configuration ---

/// Program a redirection entry by GSI with explicit electrical properties.
/// Always uses Fixed delivery mode + Physical destination (APIC ID 0 = BSP).
/// `polarity_low` and `trigger_level` are don't-cares when `masked` is true,
/// since the entry won't fire — but real hardware still latches them, and
/// some chipsets get sticky if the polarity is wrong on first unmask, so
/// it's safest to plant correct values up front.
fn ioapicSetEntry(gsi: u8, vector: u8, masked: bool, polarity_low: bool, trigger_level: bool) void {
    const reg_lo = IOAPIC_REDTBL + @as(u32, gsi) * 2;
    const reg_hi = reg_lo + 1;
    var lo_val: u32 = @as(u32, vector);
    if (polarity_low) lo_val |= IOAPIC_LO_POLARITY_LOW;
    if (trigger_level) lo_val |= IOAPIC_LO_TRIGGER_LEVEL;
    if (masked) lo_val |= IOAPIC_LO_MASKED;
    ioapicWrite(reg_hi, 0); // Destination APIC ID 0 (BSP)
    ioapicWrite(reg_lo, lo_val);
}

/// Decode MADT ISO `flags` for `isa_irq` into IOAPIC polarity/trigger bools.
/// Per ACPI 6.4 §5.2.12.5:
///   polarity (bits 0-1): 00 = bus default, 01 = active high, 11 = active low
///   trigger  (bits 2-3): 00 = bus default, 01 = edge,        11 = level
/// 10 is reserved; we treat it as bus default (firmware sometimes uses it
/// and the spec doesn't say what to do — bus-default never fires the IRQ
/// the wrong way for ISA, which is the only bus we wire here).
///
/// ISA bus default is active-high + edge, so absent overrides we return
/// {false, false}, matching the previous hard-coded behaviour. Bit-level
/// translation happens here so `enableIsaPin` and `enableIRQ` are oblivious
/// to the MADT encoding.
const IsaPin = struct { polarity_low: bool, trigger_level: bool };

fn isaPinElectrical(isa_irq: u8) IsaPin {
    const flags: u16 = if (isa_irq < 16) iso_flags[isa_irq] else 0;
    return .{
        .polarity_low = (flags & 0b11) == 0b11,
        .trigger_level = ((flags >> 2) & 0b11) == 0b11,
    };
}

/// Internal helper: enable an ISA IRQ, programming the IOAPIC pin with
/// MADT-declared polarity/trigger. Used by `initIOAPIC` and `enableIRQ`.
fn enableIsaPin(isa_irq: u8, vector: u8) void {
    const e = isaPinElectrical(isa_irq);
    const gsi = isaToGsi(isa_irq);
    ioapicSetEntry(gsi, vector, false, e.polarity_low, e.trigger_level);
    debug.klog("[apic] ISA IRQ{d} -> GSI{d} vec={d} pol={s} trig={s}\n", .{
        isa_irq, gsi, vector,
        if (e.polarity_low) "low" else "high",
        if (e.trigger_level) "level" else "edge",
    });
}

fn initIOAPIC() void {
    const ver = ioapicRead(IOAPIC_VER_REG);
    const max_entries: u8 = @truncate((ver >> 16) & 0xFF);
    const gsi_first = ioapic_gsi_base;
    const gsi_last = ioapic_gsi_base + @as(u32, max_entries);
    debug.klog("[apic] IOAPIC[0] version=0x{X:0>2} covers GSI {d}..{d} ({d} entries)\n", .{ ver & 0xFF, gsi_first, gsi_last, max_entries + 1 });

    // Mask all entries first. Polarity/trigger are don't-care on masked
    // entries; pass ISA-default bits to keep the latched values sane in
    // case anything observes the redirection table before unmask.
    var i: u8 = 0;
    while (i <= max_entries) : (i += 1) {
        ioapicSetEntry(i, 0x20 + i, true, false, false);
    }

    // Unmask needed external IRQs. `enableIsaPin` honours MADT-declared
    // polarity/trigger flags — without this, chipsets where firmware
    // reports active-low/level for a legacy line (some PIIX/ICH SKUs on
    // real hardware do this) get stuck IRQs because the IOAPIC waits for
    // a polarity transition that never comes.
    enableIsaPin(1, 33); // keyboard
    enableIsaPin(12, 44); // mouse
}

// --- LAPIC initialization ---

fn initLAPIC() void {
    // Enable APIC via MSR. We OR in the global-enable bit but preserve
    // bit 10 (x2APIC enable) — some firmware turns x2APIC on, and once
    // it's on we can't go back without a CPU reset. After the write we
    // re-read to see whether bit 10 stuck and switch to MSR access if so.
    var lo: u32 = undefined;
    var hi: u32 = undefined;
    asm volatile ("rdmsr"
        : [lo] "={eax}" (lo), [hi] "={edx}" (hi)
        : [msr] "{ecx}" (IA32_APIC_BASE_MSR));
    lo |= (1 << 11); // Global enable
    asm volatile ("wrmsr"
        :
        : [msr] "{ecx}" (IA32_APIC_BASE_MSR),
          [lo] "{eax}" (lo),
          [hi] "{edx}" (hi));

    // Re-read; if bit 10 is set we're in x2APIC mode. lapicRead/lapicWrite
    // start using MSR access from this point on.
    asm volatile ("rdmsr"
        : [lo] "={eax}" (lo), [hi] "={edx}" (hi)
        : [msr] "{ecx}" (IA32_APIC_BASE_MSR));
    x2apic_active = (lo & (1 << 10)) != 0;
    if (x2apic_active) debug.klog("[apic] x2APIC mode active (firmware-enabled)\n", .{});

    // Set Spurious Interrupt Vector Register: vector 0xFF + software enable (bit 8)
    lapicWrite(LAPIC_SVR, 0x1FF);

    // Task Priority = 0 (accept all interrupts)
    lapicWrite(LAPIC_TPR, 0);

    const id_raw = lapicRead(LAPIC_ID);
    const id = if (x2apic_active) id_raw else (id_raw >> 24);
    const ver_reg = lapicRead(LAPIC_VER);
    debug.klog("[apic] LAPIC ID={d} version=0x{X:0>2}\n", .{ id, ver_reg & 0xFF });
}

// --- APIC timer calibration ---
//
// Two paths, in preference order:
//   1. HPET-gated (preferred) — modern UEFI laptops sometimes ship with
//      PIT disabled in firmware; HPET is the only working time reference.
//      We need this on real HW or tsc_per_quantum stays 0 forever and
//      every elapsed-time check returns 0ms.
//   2. PIT Channel 2 — legacy fallback for systems without HPET (rare on
//      x86_64 — ACPI 1.0+ machines all have HPET).
//
// Single 10 ms gated window measures BOTH the LAPIC count-down rate
// (apic_timer_count) and the TSC rate (tsc_per_quantum) in one shot.
// The two are independent — the LAPIC count is what one-shot mode arms
// against; the TSC count is what TSC-deadline mode wants. Boot picks
// whichever the CPU supports.

/// True if calibration used HPET, false if it fell back to PIT. Logged
/// once at the end of apic.init() so the timer-source decision is in one
/// obvious place when debugging "why is sleep weird on this machine."
var calibrated_via_hpet: bool = false;
/// True if Hyper-V frequency MSRs supplied calibration directly. Skips
/// the 10 ms HPET gate when running under QEMU/KVM with `hv-frequencies`.
var calibrated_via_hyperv: bool = false;

/// Hyper-V-direct calibration. Reads HV_X64_MSR_TSC_FREQUENCY +
/// HV_X64_MSR_APIC_FREQUENCY (one rdmsr each, no busy-wait gate).
/// Returns true on success.
fn calibrateTimerHyperv() bool {
    const hyperv = @import("../cpu/hyperv.zig");
    if (!hyperv.hasFrequencyMsrs()) return false;

    const tsc_hz = hyperv.tscFrequencyHz();
    const apic_hz = hyperv.apicFrequencyHz();
    if (tsc_hz == 0 or apic_hz == 0) return false;

    // 100 Hz quantum = 10 ms. LAPIC count-down uses divider 16 (DCR=0x03);
    // effective tick rate = apic_hz / 16, so per-quantum count = apic_hz / 1600.
    tsc_per_quantum = tsc_hz / 100;
    apic_timer_count = @intCast(apic_hz / 1600);
    calibrated_via_hyperv = true;

    debug.klog("[apic] Hyper-V calibration: TSC={d} Hz APIC={d} Hz → {d} TSC / {d} LAPIC ticks per 10ms\n", .{ tsc_hz, apic_hz, tsc_per_quantum, apic_timer_count });
    return true;
}

/// HPET-based calibration. Returns true on success.
fn calibrateTimerHpet() bool {
    const hpet = @import("hpet.zig");
    if (!hpet.isInitialized()) return false;

    // Set APIC timer divider to 16 + start counting down from max
    lapicWrite(LAPIC_TIMER_DCR, 0x03);
    lapicWrite(LAPIC_TIMER_ICR, 0xFFFFFFFF);

    const hpet_start_ns = hpet.readNanos();
    const tsc_start = rdtsc();

    // Wait 10 ms via HPET. readNanos returns nanos since hpet.init() —
    // never wraps (u64 holds ~584 years at ns precision).
    const target_ns = hpet_start_ns + 10_000_000;
    while (hpet.readNanos() < target_ns) {
        asm volatile ("pause");
    }

    const tsc_end = rdtsc();
    const elapsed = 0xFFFFFFFF - lapicRead(LAPIC_TIMER_CCR);

    lapicWrite(LAPIC_LVT_TIMER, 1 << 16); // mask

    apic_timer_count = elapsed;
    tsc_per_quantum = tsc_end - tsc_start;
    calibrated_via_hpet = true;
    debug.klog("[apic] HPET calibration: {d} LAPIC / {d} TSC ticks per 10ms\n", .{ elapsed, tsc_per_quantum });
    return true;
}

fn calibrateTimer() void {
    if (calibrateTimerHyperv()) return;
    if (calibrateTimerHpet()) return;
    debug.klog("[apic] HPET unavailable — falling back to PIT Channel 2\n", .{});
    calibrateTimerPit();
}

fn calibrateTimerPit() void {
    // Set PIT Channel 2 for one-shot, 10ms (11932 ticks at 1193182 Hz)
    const PIT_10MS: u16 = 11932;

    // Gate PIT Channel 2 via speaker port
    var gate = io.inb(0x61);
    gate = (gate & 0xFC) | 0x01; // enable gate (bit 0), disable speaker (bit 1 clear)
    io.outb(0x61, gate);

    // Set PIT Channel 2: mode 0 (one-shot), lobyte/hibyte
    io.outb(0x43, 0xB0);
    io.outb(0x42, @truncate(PIT_10MS & 0xFF));
    io.outb(0x42, @truncate(PIT_10MS >> 8));

    // Set APIC timer divider to 16
    lapicWrite(LAPIC_TIMER_DCR, 0x03);

    // Start APIC timer with max count
    lapicWrite(LAPIC_TIMER_ICR, 0xFFFFFFFF);

    // Sample TSC at the start of the same window. PIT gate has already
    // started; LAPIC counter is decrementing.
    const tsc_start = rdtsc();

    // Wait for PIT Channel 2 output (bit 5 of port 0x61 goes high)
    while (io.inb(0x61) & 0x20 == 0) {
        asm volatile ("pause");
    }

    const tsc_end = rdtsc();
    // Read how many APIC ticks elapsed in 10ms
    const elapsed = 0xFFFFFFFF - lapicRead(LAPIC_TIMER_CCR);

    // Stop APIC timer
    lapicWrite(LAPIC_LVT_TIMER, 1 << 16); // mask

    apic_timer_count = elapsed;
    tsc_per_quantum = tsc_end - tsc_start;
    debug.klog("[apic] Timer calibration: {d} LAPIC / {d} TSC ticks per 10ms\n", .{ elapsed, tsc_per_quantum });
}

fn startTimer() void {
    if (tsc_deadline_active) {
        // TSC-deadline: vector 32 with mode bits 17:18 = 10. The MSR
        // value is an absolute TSC value at which the IRQ fires; arm
        // the first one a quantum out.
        lapicWrite(LAPIC_LVT_TIMER, 32 | LVT_TIMER_MODE_TSC_DEADLINE);
        wrmsr(IA32_TSC_DEADLINE_MSR, rdtsc() + tsc_per_quantum);
    } else {
        // LVT Timer: vector 32, ONE-SHOT mode. handleIRQ0 re-arms after each
        // tick — see armOneShot. Periodic mode is fine but burns the CPU 100x/sec
        // even when an AP has nothing to do; one-shot lets idle APs sleep
        // longer until either a sleeping process needs to wake or a real
        // event arrives.
        lapicWrite(LAPIC_LVT_TIMER, 32);
        // Divider = 16
        lapicWrite(LAPIC_TIMER_DCR, 0x03);
        // First arm — calibrated for 10ms quantum
        lapicWrite(LAPIC_TIMER_ICR, apic_timer_count);
    }
}

// --- Public API ---

pub fn eoi() void {
    lapicWrite(LAPIC_EOI, 0);
}

pub fn enableIRQ(irq: u8) void {
    if (irq >= 24) return;
    const vector: u8 = switch (irq) {
        1 => 33,
        12 => 44,
        else => 0x20 + irq,
    };
    enableIsaPin(irq, vector);
}

pub fn init() bool {
    if (!detect()) {
        debug.klog("[apic] Not detected via CPUID\n", .{});
        return false;
    }
    debug.klog("[apic] Detected, initializing...\n", .{});

    // Map APIC MMIO pages at the architectural defaults first; if
    // applyAcpi() decides MADT moves them, it'll map the new ranges too.
    paging.mapAPIC();

    // Pull MADT-derived overrides into lapic_base / ioapic_base / iso_remap.
    applyAcpi();

    // Disable legacy PIC
    disablePIC();

    // Initialize Local APIC
    initLAPIC();

    // Initialize IOAPIC
    initIOAPIC();

    tsc_deadline_active = detectTscDeadline();
    debug.klog("[apic] TSC-deadline timer: {s}\n", .{if (tsc_deadline_active) "supported" else "unsupported (using LAPIC count-down)"});

    // Calibrate and start timer at 100Hz
    calibrateTimer();

    // Sanity check
    if (apic_timer_count < 100 or apic_timer_count > 100000000) {
        debug.klog("[apic] WARNING: calibration seems wrong, falling back to PIC\n", .{});
        return false;
    }
    if (tsc_deadline_active and (tsc_per_quantum < 1_000_000 or tsc_per_quantum > 100_000_000_000)) {
        // TSC ran far too slowly / quickly for 10ms — KVM TSC scaling
        // is probably off. Disable TSC-deadline rather than risk a
        // 100µs scheduler tick that pegs the CPU.
        debug.klog("[apic] TSC calibration sus ({d}); disabling TSC-deadline\n", .{tsc_per_quantum});
        tsc_deadline_active = false;
    }

    startTimer();

    apic_active = true;
    debug.klog("[apic] timer config: source={s} mode={s} freq=100Hz\n", .{
        if (calibrated_via_hyperv) "Hyper-V" else if (calibrated_via_hpet) "HPET" else "PIT",
        if (tsc_deadline_active) "TSC-deadline" else "LAPIC-count",
    });
    return true;
}

// --- SMP IPI functions ---

pub fn getLapicId() u32 {
    const raw = lapicRead(LAPIC_ID);
    return if (x2apic_active) raw else raw >> 24;
}

/// Issue an ICR command. xAPIC: split 32-bit hi/lo writes + poll the
/// delivery-status bit. x2APIC: single 64-bit MSR write — there's no
/// status bit because the write completes synchronously.
fn icrSend(target_id: u32, command: u32) void {
    if (x2apic_active) {
        wrmsr(0x830, (@as(u64, target_id) << 32) | @as(u64, command));
        return;
    }
    lapicWrite(LAPIC_ICR_HI, target_id << 24);
    lapicWrite(LAPIC_ICR_LO, command);
    while (lapicRead(LAPIC_ICR_LO) & (1 << 12) != 0) asm volatile ("pause");
}

pub fn sendInitIPI(target_id: u32) void {
    icrSend(target_id, 0x00004500); // INIT, level assert
}

pub fn sendSIPI(target_id: u32, vector: u8) void {
    icrSend(target_id, 0x00004600 | @as(u32, vector));
}

pub fn sendIPI(target_id: u32, vector: u8) void {
    icrSend(target_id, @as(u32, vector));
}

/// Send an NMI (Non-Maskable Interrupt) to `target_id`. Hardware delivers
/// to vector 2 unconditionally — the vector field of the ICR is ignored
/// for NMI delivery mode. Used by debug.kdbg.broadcastNMI to force a
/// state snapshot from a stuck CPU even when its IF is cleared.
pub fn sendNMI(target_id: u32) void {
    // Delivery mode = NMI (100b in bits 8-10) + Level = assert (bit 14).
    icrSend(target_id, 0x00004400);
}

/// Initialize LAPIC for an AP (does NOT touch IOAPIC or PIC)
pub fn initLAPICForAP() void {
    // Enable APIC via MSR
    var lo: u32 = undefined;
    var hi: u32 = undefined;
    asm volatile ("rdmsr"
        : [lo] "={eax}" (lo), [hi] "={edx}" (hi)
        : [msr] "{ecx}" (IA32_APIC_BASE_MSR)
    );
    lo |= (1 << 11);
    asm volatile ("wrmsr"
        :
        : [msr] "{ecx}" (IA32_APIC_BASE_MSR),
          [lo] "{eax}" (lo),
          [hi] "{edx}" (hi)
    );
    lapicWrite(LAPIC_SVR, 0x1FF);
    lapicWrite(LAPIC_TPR, 0);
}

/// Start LAPIC timer for an AP (uses BSP's calibrated count)
pub fn startTimerForAP() void {
    if (tsc_deadline_active) {
        lapicWrite(LAPIC_LVT_TIMER, 32 | LVT_TIMER_MODE_TSC_DEADLINE);
        wrmsr(IA32_TSC_DEADLINE_MSR, rdtsc() + tsc_per_quantum);
    } else {
        lapicWrite(LAPIC_LVT_TIMER, 32); // vector 32, one-shot
        lapicWrite(LAPIC_TIMER_DCR, 0x03); // divide by 16
        lapicWrite(LAPIC_TIMER_ICR, apic_timer_count);
    }
}

/// Re-arm the timer to fire one `timerQuantum()`-equivalent unit (or a
/// multiple) from now. Caller passes a value in whatever unit the active
/// mode wants — `timerQuantum()` returns one such unit so most callers
/// can just multiply.
pub fn armOneShot(ticks: u32) void {
    if (tsc_deadline_active) {
        wrmsr(IA32_TSC_DEADLINE_MSR, rdtsc() + ticks);
    } else {
        lapicWrite(LAPIC_TIMER_ICR, ticks);
    }
}

/// Ticks per ~10 ms quantum, in whatever unit the active timer wants
/// (LAPIC counter ticks for count-down mode, TSC ticks for TSC-deadline).
pub fn timerQuantum() u32 {
    return if (tsc_deadline_active) @intCast(tsc_per_quantum) else apic_timer_count;
}
