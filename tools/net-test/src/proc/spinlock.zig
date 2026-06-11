// Test stub for proc/spinlock.zig — the harness is single-threaded, so the
// net_lock is a no-op here. Signatures mirror the real SpinLock's subset
// that net.zig uses (acquireIrqSave/releaseIrqRestore).
pub const SpinLock = struct {
    pub fn acquire(self: *SpinLock) void {
        _ = self;
    }
    pub fn release(self: *SpinLock) void {
        _ = self;
    }
    pub fn acquireIrqSave(self: *SpinLock) u64 {
        _ = self;
        return 0;
    }
    pub fn releaseIrqRestore(self: *SpinLock, flags: u64) void {
        _ = self;
        _ = flags;
    }
};
