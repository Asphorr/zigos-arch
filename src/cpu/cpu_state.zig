//! The processor state a CPU has only until it is next reset — at power-on,
//! by INIT, across S3 — as one list, in the order it is put back.
//!
//! A CPU that comes out of reset into a kernel that is already up (an AP at
//! boot, every CPU after S3) runs the whole list: `restore`. The boot CPU
//! cannot. At boot each entry waits for something — the LAPIC for ACPI and
//! paging, SMAP for the BSP to leave its boot stack — so the boot path
//! reaches the same entries one at a time with `apply`, and `completeBoot`
//! stops the boot if one was never reached.
//!
//! State that has to be put back is an entry here and is written nowhere
//! else: the four paths cannot then disagree about it.
//!
//! Not here: what gets a CPU into 64-bit Zig code at all — paging and long
//! mode (CR0, CR4.PAE, EFER.LME, CR3) and SSE (CR0.MP, CR4.OSFXSR). That is
//! the trampoline's, or the loader's and the boot entry's.

const std = @import("std");
const serial = @import("../debug/serial.zig");
const apic = @import("../irq/apic.zig");
const s3 = @import("../acpi/s3.zig");
const smp = @import("smp.zig");
const protect = @import("arch/protect.zig");
const fp = @import("arch/fp.zig");
const mce = @import("arch/mce.zig");
const pmu = @import("arch/pmu.zig");
const syscall_entry = @import("../syscall/entry.zig");
const lbr = @import("../debug/lbr.zig");
const watch = @import("../debug/watch.zig");
const kvm = @import("../virt/kvm.zig");
const paging = @import("../mm/paging.zig");

/// Which reset this CPU is coming out of. The entries are the same for all
/// four; the few places they differ say so by this.
pub const Path = enum {
    bsp_boot,
    ap_boot,
    bsp_resume,
    ap_resume,

    pub fn isBsp(self: Path) bool {
        return self == .bsp_boot or self == .bsp_resume;
    }
};

/// In the order `restore` runs them.
pub const Step = enum {
    /// The time-stamp counter, moved forward by what a sleep took from it:
    /// the same amount on every CPU, for deadlines pass between them as raw
    /// counter values. Nothing at boot. First: whatever reads the clock
    /// below must not see it gone back.
    time_stamp,
    /// IA32_APIC_BASE: the LAPIC on, in the mode the BSP chose (xAPIC or
    /// x2APIC). Ahead of `identity`, which reads the LAPIC ID: in the wrong
    /// mode that read is a #GP with no IDT to take it.
    lapic_mode,
    /// Which CPU this is: its cpus[] slot, and IA32_TSC_AUX, where myCpuId()
    /// reads it. Nothing before this may ask — klog does.
    identity,
    /// GDTR and TR to this CPU's own GDT and TSS, IDTR to the shared IDT.
    descriptor_tables,
    /// EFER.SCE and NXE, STAR, LSTAR, SFMASK. Until NXE is on, a page mapped
    /// no-execute is a reserved-bit fault: what the entries above touch —
    /// the kernel image, cpus[], the LAPIC's page — is mapped without it.
    syscall,
    /// IA32_DEBUGCTL.LBR: without it a crash on this CPU dumps an empty
    /// branch ring.
    branch_record,
    /// CR4: SMEP, UMIP, PCIDE, PGE.
    cr4_protection,
    /// CR4.SMAP, and AC in SFMASK. Only on a stack that is not a user page:
    /// on Multiboot the BSP boots on one and waits until it has left it.
    smap,
    /// CR4.OSXSAVE and XCR0, for AVX state.
    extended_state,
    /// MCG_CTL, the bank controls, CR4.MCE.
    machine_check,
    /// Spurious vector and task priority: the LAPIC delivers.
    lapic,
    /// Counter 0 stopped, the LVT's PMI entry masked.
    pmu,
    /// KVM's per-CPU areas: steal time, PV EOI, kvmclock.
    paravirt,
    /// CR0.WP: ring 0 obeys read-only pages on this CPU too. The write-watch
    /// and .kdata_protected catch nothing on a CPU without it.
    write_protect,
    /// IA32_PAT: entry 4 is write-combining. A CPU without it takes the
    /// framebuffer's PTEs for write-back.
    pat,
    /// DR0-DR3 and DR7 are at their reset values, whatever watch.zig last
    /// wrote: it forgets, and writes them again on this CPU's next tick.
    debug_registers,
    /// The LAPIC timer. Last: it is the scheduler tick.
    timer,
};

fn run(comptime step: Step, path: Path) void {
    switch (step) {
        .time_stamp => s3.restoreTsc(path),
        .lapic_mode => apic.setMode(path.isBsp()),
        .identity => smp.claimSlot(path),
        .descriptor_tables => smp.loadDescriptorTables(path),
        .syscall => {
            syscall_entry.init();
            // A CPU that reaches user code without them takes #UD on its
            // first `syscall`, and says nothing.
            var buf: [8]u8 = undefined;
            syscall_entry.verifyMsrs(switch (path) {
                .bsp_boot => "BSP",
                .bsp_resume => "S3-BSP",
                .ap_boot, .ap_resume => std.fmt.bufPrint(&buf, "AP{d}", .{smp.myCpu().cpu_id}) catch "AP?",
            });
        },
        .branch_record => lbr.enable(),
        .cr4_protection => protect.applyEarlyCr4(),
        .smap => protect.enableSmapPerCpu(),
        .extended_state => fp.enableExtended(),
        .machine_check => mce.perCpuInit(),
        .lapic => apic.enableLocal(path.isBsp()),
        .pmu => pmu.perCpuInit(),
        .paravirt => kvm.enablePerCpuPv(smp.myCpu().cpu_id),
        .write_protect => paging.enableCR0WriteProtect(),
        .pat => paging.setupPat(),
        .debug_registers => watch.invalidateLocalCache(),
        .timer => apic.startTimer(),
    }
}

/// The whole list, on a CPU just out of reset. Interrupts are off and stay
/// off; the caller decides what the CPU runs next.
pub fn restore(comptime path: Path) void {
    comptime std.debug.assert(path != .bsp_boot);
    inline for (comptime std.enums.values(Step)) |step| run(step, path);
}

const StepSet = std.EnumSet(Step);

/// What the boot CPU has applied so far. Its own: no other CPU reads or
/// writes it.
var boot_applied: StepSet = StepSet.initEmpty();

/// One entry, on the boot CPU, once what it needs is up — its own probe
/// included: an entry applied ahead of its `detect` does nothing, and still
/// counts as applied.
pub fn apply(comptime step: Step) void {
    comptime std.debug.assert(!resume_only.contains(step));
    run(step, .bsp_boot);
    boot_applied.insert(step);
}

/// Entries that only undo a sleep: a booting CPU has nothing to put back.
const resume_only = StepSet.initOne(.time_stamp);

/// The boot CPU is on a task's stack and about to take interrupts: the last
/// entry, then the check that none was left out.
pub fn completeBoot() void {
    apply(.smap);
    assertBootApplied(StepSet.initEmpty());
}

/// The same check for the boots that leave the BSP without SMAP: the
/// selftest and stress entries, which also keep the low identity.
pub fn completeBootWithoutSmap() void {
    assertBootApplied(StepSet.initOne(.smap));
}

/// Without a LAPIC smp.init leaves the BSP as boot made it: CPU 0 by
/// definition, on the boot GDT, ticking from the PIT.
const needs_lapic = StepSet.initMany(&.{ .lapic_mode, .identity, .descriptor_tables, .lapic, .pmu, .timer });

fn assertBootApplied(left_off: StepSet) void {
    var excused = left_off.unionWith(resume_only);
    if (!apic.apic_active) excused.setUnion(needs_lapic);
    const missing = boot_applied.unionWith(excused).complement();
    if (missing.count() == 0) return;
    var it = missing.iterator();
    while (it.next()) |step| {
        serial.print("[cpu-state] the boot CPU never applied '{s}'\n", .{@tagName(step)});
    }
    @panic("cpu_state: the boot path left out per-CPU state that APs and S3 resume restore");
}
