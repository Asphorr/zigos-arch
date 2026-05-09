/// Ticket-based spinlock for SMP synchronization.
/// Uses @atomicRmw for lock-free ticket acquisition.
pub const SpinLock = struct {
    next_ticket: u32 = 0,
    now_serving: u32 = 0,

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
    /// warning naming the caller (return address) and the holder. Long
    /// spin = almost always a missing release or a cross-CPU deadlock;
    /// the log line is enough for symbols.zig to resolve.
    pub fn acquire(self: *SpinLock) void {
        const ra = @returnAddress();
        const ticket = @atomicRmw(u32, &self.next_ticket, .Add, 1, .seq_cst);
        var spins: u64 = 0;
        var warned = false;
        while (true) {
            const serving = @atomicLoad(u32, &self.now_serving, .acquire);
            if (serving == ticket) return;
            // u32 wrapping subtract: handles next_ticket overflow correctly
            // since both values are mod 2^32 of the same monotonic counter.
            const distance: u32 = ticket -% serving;
            const cap: u32 = if (distance > 32) 32 else distance;
            var i: u32 = 0;
            while (i < cap) : (i += 1) asm volatile ("pause");
            spins +%= 1;
            if (!warned and spins > 200_000_000) {
                warned = true;
                const cpu_id = blk: {
                    const apic = @import("../time/apic.zig");
                    if (!apic.apic_active) break :blk @as(u8, 0);
                    break :blk @as(u8, @truncate(apic.getLapicId()));
                };
                @import("../debug/serial.zig").print(
                    "[lock-spin] cpu{d} waiting on lock@0x{X} ticket={d} now_serving={d} caller=0x{X}\n",
                    .{ cpu_id, @intFromPtr(self), ticket, serving, ra },
                );
            }
        }
    }

    /// Release the lock. Advances to the next ticket.
    pub fn release(self: *SpinLock) void {
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
