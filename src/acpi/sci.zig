// Dynamic ACPI — the runtime/event half of ACPI that acpi.zig (the static
// table parser) deliberately stops short of. acpi.zig reads the FADT/MADT/HPET/
// MCFG and even pattern-matches the DSDT's `\_S5_` package, but it never puts
// the machine into ACPI mode and never wires the SCI (System Control Interrupt).
// This module does both, then handles the one fixed-feature event that needs no
// AML to interpret: the power button.
//
// Slice A scope (this file today):
//   * enableAcpiMode() — the FADT SMI_CMD / ACPI_ENABLE handshake that transfers
//     event control from the firmware (legacy SMI) to the OS (SCI), confirmed by
//     PM1_CNT.SCI_EN going high. Idempotent and bounded: a no-op when firmware
//     already enabled it (UEFI usually does) or on hardware-reduced ACPI.
//   * route the SCI through the IOAPIC to a dynirq vector (level-triggered).
//   * arm ONLY the fixed power-button enable (PM1x_EN.PWRBTN_EN) and mask every
//     GPE, so no un-handled General Purpose Event can assert the shared,
//     level-triggered SCI line and wedge the box in an interrupt storm.
//   * sciHandler() — on each SCI, check PM1x_STS.PWRBTN_STS; if set, clear it
//     (write-1-to-clear, which de-asserts the line) and flag a graceful
//     power-off. The flag is consumed by the `acpid` kernel thread (main.zig)
//     in normal thread context — we must NOT flush filesystems / poke NVMe from
//     the IRQ handler (IF=0, on the isr_stack; a lock the interrupted task holds
//     would deadlock).
//
// Not here yet (later slices): the AML interpreter, GPE method dispatch
// (_Lxx/_Exx), the control-method power button (PNP0C0C _PRW), thermal, battery.
// Those all build on the SCI substrate established here.
//
// Reference: ACPI 6.4 §4.8.3 (PM1 event/control), §4.8.2.1 (power button),
// §5.8 (ACPI mode / SCI), §16 (sleep states).

const std = @import("std");
const acpi = @import("acpi.zig");
const apic = @import("../time/apic.zig");
const dynirq = @import("../cpu/idt/dynirq.zig");
const io = @import("../io.zig");
const debug = @import("../debug/debug.zig");
const serial = @import("../debug/serial.zig");

// --- PM1 register bit fields (ACPI 6.4 Tables 4.17 / 4.19) ------------------

/// PM1 control register, bit 0 — SCI_EN. Set once the OS owns ACPI events
/// (SCI mode). We poll this after kicking SMI_CMD to confirm the handover.
const PM1_CNT_SCI_EN: u16 = 1 << 0;

/// PM1 status/enable register, bit 8 — the fixed power-button event. In the
/// STATUS register it's write-1-to-clear; in the ENABLE register it gates
/// whether a status assertion raises the SCI.
const PM1_PWRBTN: u16 = 1 << 8;

/// FADT.flags bit 20 = HW_REDUCED_ACPI. When set there is no SMI_CMD / PM1 /
/// SCI_EN machinery at all — events arrive via GPIO/interrupt controllers
/// described in AML instead. None of the PM1 path below applies, so we bail.
/// (QEMU's i440fx/q35 are NOT hardware-reduced, so this is the real path there.)
const FADT_HW_REDUCED: u32 = 1 << 20;

/// Single IOAPIC entry-count ceiling we route within. QEMU's IOAPIC exposes 24
/// GSIs and the SCI lands at GSI 9; a firmware reporting an SCI GSI at/above
/// this would need a second IOAPIC we don't drive, so we decline to route it
/// (the power button is simply unavailable rather than mis-routed).
const SCI_GSI_MAX: u16 = 24;

// --- module state ----------------------------------------------------------

/// Set by sciHandler on a power-button press, consumed by takePowerOffRequest()
/// from the `acpid` thread (0 = idle, 1 = press pending). A u8 (not bool) so the
/// atomic exchange below is unambiguously supported. Written from IRQ context
/// (IF=0, isr_stack) and read from thread context on possibly another CPU, so
/// access must not tear or be reordered around.
var power_off_requested: u8 = 0;

/// The dynirq vector the SCI is routed to (diagnostics). 0 = unrouted.
var sci_vector: u8 = 0;

/// Thread-side consumer of the power-button flag. Atomically test-and-clears,
/// so it returns true exactly once per press; the caller then runs the graceful
/// shutdown. A press landing between a peer's load and store is simply picked up
/// on the next poll — perfectly fine latency for a power button.
pub fn takePowerOffRequest() bool {
    return @atomicRmw(u8, &power_off_requested, .Xchg, 0, .acq_rel) != 0;
}

// --- PM1 register addressing ------------------------------------------------
//
// The PM1 EVENT block splits in half: the lower `pm1_evt_len/2` bytes are the
// STATUS register, the upper half is the ENABLE register. There can be two
// banks (PM1a, PM1b); PM1b is absent on QEMU and most systems (its block
// address is then 0). The CONTROL block (SLP_TYP/SLP_EN/SCI_EN) is separate.
// We use the legacy 32-bit FADT fields as I/O ports — same as sysShutdown — so
// this matches the existing, proven shutdown path.

const Pm1Ports = struct {
    sts_a: u16,
    en_a: u16,
    sts_b: u16, // 0 if PM1b absent
    en_b: u16, // 0 if PM1b absent
    cnt_a: u16,
    cnt_b: u16, // 0 if absent
};

fn pm1Ports(f: *align(1) const acpi.Fadt) Pm1Ports {
    // pm1_evt_len is the WHOLE event block length (typically 4 → 2-byte STS +
    // 2-byte EN). Guard a degenerate length so the EN port can't alias STS.
    // u32 so it adds cleanly to the u32 block address (Zig won't mix widths).
    const half: u32 = if (f.pm1_evt_len >= 4) f.pm1_evt_len / 2 else 2;
    var p = Pm1Ports{
        .sts_a = @truncate(f.pm1a_evt_blk),
        .en_a = @truncate(f.pm1a_evt_blk +% half),
        .sts_b = 0,
        .en_b = 0,
        .cnt_a = @truncate(f.pm1a_cnt_blk),
        .cnt_b = 0,
    };
    if (f.pm1b_evt_blk != 0) {
        p.sts_b = @truncate(f.pm1b_evt_blk);
        p.en_b = @truncate(f.pm1b_evt_blk +% half);
    }
    if (f.pm1b_cnt_blk != 0) p.cnt_b = @truncate(f.pm1b_cnt_blk);
    return p;
}

// --- GPE storm safety -------------------------------------------------------

/// Disable every General Purpose Event by zeroing the GPE enable registers
/// (and clearing any latched status). Storm safety: the SCI is shared and
/// level-triggered, so an enabled GPE we have no handler for would assert the
/// line, sciHandler would find no PWRBTN_STS, EOI, and the still-asserted line
/// would immediately re-fire — a livelock that hard-hangs the machine. Until
/// the GPE/AML slice lands, no GPE may be enabled. GPE blocks split like PM1:
/// lower half = status, upper half = enable.
fn maskAllGpes(f: *align(1) const acpi.Fadt) void {
    maskGpeBlock(f.gpe0_blk, f.gpe0_blk_len);
    maskGpeBlock(f.gpe1_blk, f.gpe1_blk_len);
}

fn maskGpeBlock(blk: u32, len: u8) void {
    if (blk == 0 or len < 2) return;
    const half: u32 = len / 2; // status bytes == enable bytes
    const en_base: u32 = blk +% half;
    // u32 index + wrapping adds: a garbage firmware block address can't trip a
    // ReleaseSafe overflow panic; a bad port just writes harmlessly into space.
    var i: u32 = 0;
    while (i < half) : (i += 1) {
        io.outb(@truncate(en_base +% i), 0x00); // disable every GPE
        io.outb(@truncate(blk +% i), 0xFF); // clear any latched status (W1C)
    }
}

// --- ACPI mode handshake ----------------------------------------------------

/// Transfer ACPI event control from firmware (SMI) to the OS (SCI) via the FADT
/// SMI_CMD/ACPI_ENABLE handshake, confirmed by PM1_CNT.SCI_EN going high.
/// Returns true if ACPI mode is on when we return (already-on counts).
///
/// Bounded: firmware that never sets SCI_EN can't hang us — we give up after a
/// fixed spin budget and log. The caller still routes the SCI regardless; if
/// SCI_EN never came up the line just won't fire (a no-op, not a crash).
fn enableAcpiMode(f: *align(1) const acpi.Fadt, cnt_a: u16) bool {
    const sciEnabled = struct {
        fn check(port: u16) bool {
            return port != 0 and (io.inw(port) & PM1_CNT_SCI_EN) != 0;
        }
    }.check;

    // Already in ACPI mode? (UEFI commonly enables it before handing off.)
    if (sciEnabled(cnt_a)) {
        debug.klog("[sci] ACPI mode already enabled (SCI_EN set)\n", .{});
        return true;
    }
    // No SMI command port / no enable value → can't perform the handshake.
    if (f.smi_cmd == 0 or f.acpi_enable == 0) {
        debug.klog("[sci] no SMI_CMD/ACPI_ENABLE handshake available (smi_cmd=0x{x})\n", .{f.smi_cmd});
        return false;
    }
    // Kick the firmware: write ACPI_ENABLE to the SMI command port.
    io.outb(@truncate(f.smi_cmd), f.acpi_enable);
    // Poll SCI_EN. ACPI doesn't bound the latency; in practice it's near-
    // immediate on QEMU. Cap the spin so non-conforming firmware can't wedge boot.
    var spin: u32 = 0;
    const SPIN_MAX: u32 = 5_000_000;
    while (spin < SPIN_MAX) : (spin += 1) {
        if (sciEnabled(cnt_a)) {
            debug.klog("[sci] ACPI mode enabled via SMI_CMD (spin={d})\n", .{spin});
            return true;
        }
    }
    debug.klog("[sci] WARNING: SCI_EN never set after ACPI_ENABLE — continuing anyway\n", .{});
    return false;
}

// --- SCI handler ------------------------------------------------------------

/// SCI interrupt handler. Runs via the dynirq stub: IF=0, on the per-CPU
/// isr_stack, with the LAPIC EOI issued for us after we return. Fixed-feature
/// dispatch only for now (power button). We do the bare minimum here — read +
/// clear PM1 status and flag a deferred power-off — because the filesystem
/// flush / NVMe sync of an actual shutdown must run in thread context (acpid),
/// not from an IRQ that may have preempted a lock holder.
fn sciHandler() callconv(.c) void {
    const f = acpi.getFadt() orelse return;
    const p = pm1Ports(f);
    var pressed = false;

    // PM1a status.
    if (p.sts_a != 0) {
        const sts = io.inw(p.sts_a);
        if (sts & PM1_PWRBTN != 0) {
            io.outw(p.sts_a, PM1_PWRBTN); // write-1-to-clear → de-asserts the line
            pressed = true;
        }
    }
    // PM1b status (rare; absent on QEMU and most systems).
    if (p.sts_b != 0) {
        const sts = io.inw(p.sts_b);
        if (sts & PM1_PWRBTN != 0) {
            io.outw(p.sts_b, PM1_PWRBTN);
            pressed = true;
        }
    }

    if (pressed) {
        @atomicStore(u8, &power_off_requested, 1, .release);
        serial.print("[sci] power button -> graceful power-off requested\n", .{});
    }
}

// --- init -------------------------------------------------------------------

/// One-time boot init. MUST run after acpi.init() (FADT cached) and after
/// apic.init() (IOAPIC up, so the SCI GSI can be routed). Wires the fixed power
/// button. Everything is best-effort and logged — a firmware quirk here disables
/// the power button, it never crashes boot.
pub fn init() void {
    const f = acpi.getFadt() orelse {
        debug.klog("[sci] no FADT — dynamic ACPI / power button unavailable\n", .{});
        return;
    };

    // Hardware-reduced ACPI has no PM1/SMI_CMD/SCI machinery; the fixed power
    // button doesn't exist there (it's an AML-described GPIO event instead).
    if (f.flags & FADT_HW_REDUCED != 0) {
        debug.klog("[sci] hardware-reduced ACPI — fixed power button N/A (needs AML/GPIO)\n", .{});
        return;
    }

    const p = pm1Ports(f);

    // 1. Take ownership of ACPI events (legacy SMI → OS SCI).
    _ = enableAcpiMode(f, p.cnt_a);

    // 2. Storm safety FIRST: mask every GPE and clear stale PM1 status BEFORE we
    //    unmask the SCI at the IOAPIC, so nothing un-handled can fire it.
    maskAllGpes(f);
    if (p.sts_a != 0) io.outw(p.sts_a, 0xFFFF); // clear all PM1a status (W1C)
    if (p.sts_b != 0) io.outw(p.sts_b, 0xFFFF);

    // 3. Enable ONLY the power button as an SCI source. Writing the exact value
    //    (not OR-ing) guarantees no other PM1 event is enabled, so any SCI we
    //    get must be the power button — clearing PWRBTN_STS always de-asserts it.
    if (p.en_a != 0) io.outw(p.en_a, PM1_PWRBTN);
    if (p.en_b != 0) io.outw(p.en_b, PM1_PWRBTN);

    // 4. Route the SCI GSI to a dynirq vector (level-triggered). The dynirq stub
    //    auto-EOIs after sciHandler returns; the LAPIC EOI clears the IOAPIC
    //    remote-IRR for the level line once the source has de-asserted.
    if (f.sci_int >= SCI_GSI_MAX) {
        debug.klog("[sci] SCI GSI{d} beyond single-IOAPIC range — power button not routed\n", .{f.sci_int});
        return;
    }
    const vec = dynirq.allocDynVector() orelse {
        debug.klog("[sci] no free dynirq vector — SCI not routed, power button off\n", .{});
        return;
    };
    dynirq.registerIrq(vec, &sciHandler);
    apic.routeSci(@truncate(f.sci_int), vec);
    sci_vector = vec;

    debug.klog("[sci] ready: ACPI mode on, power button armed, SCI GSI{d} -> vec 0x{X}\n", .{ f.sci_int, vec });
}
