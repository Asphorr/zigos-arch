// Test stub for proc/process.zig — net.zig only touches `tick_count` and
// `kernelSleepMs`. tick_count is the virtual clock the harness drives directly
// (e.g. `process.tick_count += 301` to fire a retransmit timer). One kernel
// tick is ~10 ms, so kernelSleepMs advances the clock by ms/10 — enough for the
// blocking deadline loops in net.zig (connect/close/arp) to terminate instantly
// instead of spinning forever against a frozen clock.
pub var tick_count: u64 = 0;

pub fn kernelSleepMs(ms: u64) void {
    const ticks = ms / 10;
    tick_count +%= if (ticks == 0) 1 else ticks;
}
