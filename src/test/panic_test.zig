// Panic UI test harness — boot_mode=7 entry.
//
// Runs as a kernel task; after a brief settle (so the boot log finishes
// flushing to serial and the framebuffer is in steady state), triggers
// a controlled @panic. The point is to render the panic_screen.draw()
// output reliably so the visuals can be iterated on without hunting a
// real crash.
//
// To exercise the #PF/#GP/#UD branches of the panic screen, swap the
// trigger via TRIGGER_KIND. Default is plain @panic (vec=255).

const debug = @import("../debug/debug.zig");
const serial = @import("../debug/serial.zig");

const TriggerKind = enum {
    panic_msg, // @panic — exercises panic_screen with int_no=255
    page_fault, // null deref — exercises int_no=14 path
    invalid_opcode, // ud2 — exercises int_no=6 path
};

const TRIGGER_KIND: TriggerKind = .panic_msg;

pub fn taskEntry() callconv(.c) noreturn {
    serial.print("[panic-test] settling for 200ms before trigger...\n", .{});
    // Brief delay so the framebuffer + serial reach steady state. ~200M
    // pause iters ≈ 200ms on a typical CPU.
    var spins: u64 = 0;
    while (spins < 200_000_000) : (spins += 1) asm volatile ("pause");

    serial.print("[panic-test] triggering controlled crash (kind={s})\n", .{@tagName(TRIGGER_KIND)});

    switch (TRIGGER_KIND) {
        .panic_msg => @panic("panic-test: controlled @panic to verify the panic screen UI"),
        .page_fault => {
            const p: *volatile u64 = @ptrFromInt(0x0);
            p.* = 0xDEADBEEF; // null write → #PF
            unreachable;
        },
        .invalid_opcode => {
            asm volatile ("ud2");
            unreachable;
        },
    }
}
