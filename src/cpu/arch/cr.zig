//! Control registers: the one place that moves to and from them, with the
//! bits by name. RFLAGS bits are here too, for the masks built from them.
//!
//! `set`/`clear` write only when a bit changes: a write to CR0 or CR4 is a
//! serializing instruction and, under a hypervisor, usually an exit.

pub const cr0 = struct {
    pub const PE: u64 = 1 << 0;
    /// WAIT/FWAIT honour TS.
    pub const MP: u64 = 1 << 1;
    /// No FPU: x87 instructions are #NM, SSE ones #UD.
    pub const EM: u64 = 1 << 2;
    pub const TS: u64 = 1 << 3;
    /// x87 errors arrive as #MF, not through the legacy IRQ 13.
    pub const NE: u64 = 1 << 5;
    /// Ring 0 obeys read-only pages too.
    pub const WP: u64 = 1 << 16;
    pub const NW: u64 = 1 << 29;
    pub const CD: u64 = 1 << 30;
    pub const PG: u64 = 1 << 31;

    pub inline fn read() u64 {
        return asm volatile ("movq %%cr0, %[value]"
            : [value] "=r" (-> u64),
        );
    }

    pub inline fn write(value: u64) void {
        asm volatile ("movq %[value], %%cr0"
            :
            : [value] "r" (value),
        );
    }

    pub inline fn set(bits: u64) void {
        const old = read();
        if (old | bits != old) write(old | bits);
    }

    pub inline fn clear(bits: u64) void {
        const old = read();
        if (old & ~bits != old) write(old & ~bits);
    }
};

/// The address of the last page fault.
pub const cr2 = struct {
    pub inline fn read() u64 {
        return asm volatile ("movq %%cr2, %[value]"
            : [value] "=r" (-> u64),
        );
    }

    pub inline fn write(value: u64) void {
        asm volatile ("movq %[value], %%cr2"
            :
            : [value] "r" (value),
        );
    }
};

/// The root of the page tables. Under CR4.PCIDE the low 12 bits are the
/// PCID and NOFLUSH is not stored: it only tells this write to keep the
/// PCID's TLB entries.
pub const cr3 = struct {
    pub const PCID_MASK: u64 = 0xFFF;
    pub const NOFLUSH: u64 = 1 << 63;

    pub inline fn read() u64 {
        return asm volatile ("movq %%cr3, %[value]"
            : [value] "=r" (-> u64),
        );
    }

    /// Changes what every address means: the compiler must not carry a
    /// load across it.
    pub inline fn write(value: u64) void {
        asm volatile ("movq %[value], %%cr3"
            :
            : [value] "r" (value),
            : .{ .memory = true });
    }
};

pub const cr4 = struct {
    pub const PAE: u64 = 1 << 5;
    /// #MC is delivered; without it a machine check shuts the CPU down.
    pub const MCE: u64 = 1 << 6;
    /// Global pages: PTE.G entries outlive a CR3 write.
    pub const PGE: u64 = 1 << 7;
    /// FXSAVE/FXRSTOR and SSE.
    pub const OSFXSR: u64 = 1 << 9;
    /// SIMD floating-point errors arrive as #XM.
    pub const OSXMMEXCPT: u64 = 1 << 10;
    /// SGDT/SIDT/SLDT/SMSW/STR are #GP in ring 3.
    pub const UMIP: u64 = 1 << 11;
    pub const VMXE: u64 = 1 << 13;
    pub const FSGSBASE: u64 = 1 << 16;
    pub const PCIDE: u64 = 1 << 17;
    /// XSAVE and XCR0.
    pub const OSXSAVE: u64 = 1 << 18;
    /// Ring 0 does not execute user pages.
    pub const SMEP: u64 = 1 << 20;
    /// Ring 0 does not touch user pages unless RFLAGS.AC.
    pub const SMAP: u64 = 1 << 21;

    pub inline fn read() u64 {
        return asm volatile ("movq %%cr4, %[value]"
            : [value] "=r" (-> u64),
        );
    }

    pub inline fn write(value: u64) void {
        asm volatile ("movq %[value], %%cr4"
            :
            : [value] "r" (value),
        );
    }

    pub inline fn set(bits: u64) void {
        const old = read();
        if (old | bits != old) write(old | bits);
    }

    pub inline fn clear(bits: u64) void {
        const old = read();
        if (old & ~bits != old) write(old & ~bits);
    }
};

pub const rflags = struct {
    pub const TF: u64 = 1 << 8;
    pub const IF: u64 = 1 << 9;
    pub const DF: u64 = 1 << 10;
    pub const IOPL: u64 = 3 << 12;
    pub const NT: u64 = 1 << 14;
    /// Suspends SMAP while set.
    pub const AC: u64 = 1 << 18;
};

/// Drops this CPU's TLB entries for the address space in CR3 (under PCID,
/// for the current PCID). Global pages stay: `flushTlbGlobal` for a change
/// to a kernel mapping.
pub inline fn flushTlb() void {
    cr3.write(cr3.read());
}

/// Drops every TLB entry of this CPU, global pages included. This CPU
/// only: other CPUs need a shootdown.
pub inline fn flushTlbGlobal() void {
    const value = cr4.read();
    if (value & cr4.PGE == 0) {
        // No entry is global yet, and an unchanged CR4 write flushes nothing.
        return flushTlb();
    }
    cr4.write(value & ~cr4.PGE);
    cr4.write(value);
}
