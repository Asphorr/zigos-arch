/// Ticket-based spinlock for SMP synchronization.
/// Uses @atomicRmw for lock-free ticket acquisition.
pub const SpinLock = struct {
    next_ticket: u32 = 0,
    now_serving: u32 = 0,
    /// Holder diagnostics — populated after acquire wins, cleared on
    /// release. Read by the spin-warn diagnostic so a deadlock dump
    /// names not just the spinner but the CPU + RIP that's still
    /// sitting on the lock. 0xFF cpu = unheld.
    holder_cpu: u8 = 0xFF,
    holder_ra: u64 = 0,

    /// Acquire the lock. Spins until this ticket is served.
    ///
    /// Backoff strategy: proportional-to-ticket-distance. A waiter that's
    /// `D` tickets behind issues `min(D, 32)` `pause` instructions before
    /// re-checking — far-behind waiters re-poll less aggressively, which
    /// cuts the cache-line ping the releaser would otherwise eat (every
    /// `now_serving` write invalidates every waiter's cached copy). The
    /// next-in-line waiter (D==1) still polls at ~max rate so handoff
    /// latency is unchanged from the unbacked-off case.
    ///
    /// After ~200M poll iterations (≈seconds on KVM, longer on real HW
    /// once distance>1 stretches each iteration) we log a one-shot
    /// warning naming both the caller (return address) and the current
    /// holder (cpu + ra). Long spin = almost always a missing release
    /// or a cross-CPU deadlock; the log line is enough for symbols.zig
    /// to resolve both ends.
    pub fn acquire(self: *SpinLock) void {
        const ra = @returnAddress();
        const ticket = @atomicRmw(u32, &self.next_ticket, .Add, 1, .seq_cst);
        var spins: u64 = 0;
        var warned = false;
        while (true) {
            const serving = @atomicLoad(u32, &self.now_serving, .acquire);
            if (serving == ticket) {
                self.holder_cpu = currentCpuId();
                self.holder_ra = ra;
                return;
            }
            // u32 wrapping subtract: handles next_ticket overflow correctly
            // since both values are mod 2^32 of the same monotonic counter.
            const distance: u32 = ticket -% serving;
            const cap: u32 = if (distance > 32) 32 else distance;
            var i: u32 = 0;
            while (i < cap) : (i += 1) asm volatile ("pause");
            spins +%= 1;
            if (!warned and spins > 200_000_000) {
                warned = true;
                printSpinDiag(self, ticket, serving, ra);
            }
        }
    }

    /// Release the lock. Advances to the next ticket.
    pub fn release(self: *SpinLock) void {
        self.holder_cpu = 0xFF;
        // Leave holder_ra in place as a "last holder" hint — useful when a
        // deadlock fires immediately after a release/re-acquire cycle.
        _ = @atomicRmw(u32, &self.now_serving, .Add, 1, .release);
    }

    /// Acquire with interrupts disabled. Returns previous RFLAGS for restore.
    pub fn acquireIrqSave(self: *SpinLock) u64 {
        const flags = saveAndDisableIrq();
        self.acquire();
        return flags;
    }

    /// Release and restore interrupt state.
    pub fn releaseIrqRestore(self: *SpinLock, flags: u64) void {
        self.release();
        restoreIrq(flags);
    }
};

fn currentCpuId() u8 {
    const apic = @import("../time/apic.zig");
    if (!apic.apic_active) return 0;
    return @as(u8, @truncate(apic.getLapicId()));
}

/// Print the [lock-spin] diagnostic with symbol-resolved caller and
/// holder addresses, then broadcast an NMI to capture every other
/// CPU's current RIP. Falls back to raw hex when the kernel symbol
/// table hasn't been loaded yet (early boot) or when the address
/// falls in a gap between known symbols.
///
/// The NMI broadcast is the key signal: holder_ra is just where the
/// holder ACQUIRED the lock — it doesn't tell us where the holder
/// currently IS (could be in the wait loop, past it but stuck on a
/// nested call, etc.). NMI snapshots dump live RIP from every CPU.
fn printSpinDiag(self: *SpinLock, ticket: u32, serving: u32, ra: usize) void {
    const symbols = @import("../debug/symbols.zig");
    const serial = @import("../debug/serial.zig");
    const kdbg = @import("../debug/kdbg.zig");
    const caller = symbols.resolveKernel(ra);
    const holder = symbols.resolveKernel(self.holder_ra);
    serial.print("[lock-spin] cpu{d} waiting on lock@0x{X} ticket={d} now_serving={d} caller=", .{
        currentCpuId(), @intFromPtr(self), ticket, serving,
    });
    if (caller) |c| {
        serial.print("{s}+0x{X}", .{ c.name, c.offset });
    } else {
        serial.print("0x{X}", .{ra});
    }
    serial.print(" | holder cpu{d} ra=", .{self.holder_cpu});
    if (holder) |h| {
        serial.print("{s}+0x{X}\n", .{ h.name, h.offset });
    } else {
        serial.print("0x{X}\n", .{self.holder_ra});
    }
    // NMI broadcast → every other CPU prints `[nmi-snap cpuN] rip=...
    // fn=symbol+0xN` from inside its NMI handler. Tells us where the
    // holder is RIGHT NOW, not just where it acquired.
    kdbg.broadcastNMI();
}

fn saveAndDisableIrq() u64 {
    var flags: u64 = undefined;
    asm volatile ("pushfq; pop %[f]; cli"
        : [f] "=r" (flags),
    );
    return flags;
}

fn restoreIrq(flags: u64) void {
    if (flags & 0x200 != 0) asm volatile ("sti");
}
