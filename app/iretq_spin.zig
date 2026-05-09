// Ring-3 spinner used by stress_iretq (boot_mode=4). Drives lots of timer
// IRQs at ring-3 and exercises the wake-from-sleep code path that originally
// triggered the iretq frame race (paint clicks → shell wake → handleIRQ0 →
// corrupt iretq frame → kernel #GP).
//
// Each iteration: ~50 K nops in user mode (CPU-busy enough to take 5–10
// timer IRQs at 100 Hz on a contended vCPU), then libc.sleep(1) to leave
// kernel mode via the wake path. No prints, no windows — we just need to
// exist and be schedulable.

const libc = @import("libc");

export fn _start() linksection(".text.entry") callconv(.c) void {
    while (true) {
        var i: u32 = 0;
        while (i < 50_000) : (i += 1) asm volatile ("");
        libc.sleep(1);
    }
}
