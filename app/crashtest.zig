// crashtest — deliberately panic the kernel via syscall #117 to exercise
// the panic / autopsy / halt-all-CPUs machinery.
//
// USAGE: crashtest <variant>
//   dfree     heap double-free          (heap header / free-list check)
//   wild      kfree at +64 offset       (header magic mismatch)
//   assert    kernel @panic             (clean dump pipeline)
//   unmapped  write to unmapped kVA     (kernel-mode #PF)
//   nonc      write to non-canonical    (#GP vec 13, not #PF)
//   panic     direct @panic              (no specific corruption — baseline)
//   slablock  @panic under a slab cache lock (the panic path takes no lock)
//   uaf       read of a freed heap block  (a -Dkasan kernel reports it)
//   race      unlocked writes from two processes (a -Dkcsan kernel reports it)
//
// Every variant but `race` halts the system. Reboot to recover. There is no
// recovery from a kernel panic and that's the entire point — this is the
// test that validates the panic path is itself reliable.
//
// `uaf` and `race` are how a sanitizer build is shown to be alive: a run
// under one that reports nothing proves nothing until these have been
// reported.
//
// The kernel answers only if built with -Ddebug-crash.
//
// Modeled on style9's `cmd_crash` (BSD-style sibling kernel). They run it
// from an in-kernel shell; we route through a debug syscall because our
// shell is userspace. Same intent: five canonical fault classes, all in
// one place, easy to invoke.

const libc = @import("libc");

const Variant = struct {
    name: []const u8,
    code: u32,
};

const variants = [_]Variant{
    .{ .name = "dfree", .code = libc.CRASH_DFREE },
    .{ .name = "wild", .code = libc.CRASH_WILD },
    .{ .name = "assert", .code = libc.CRASH_ASSERT },
    .{ .name = "unmapped", .code = libc.CRASH_UNMAPPED },
    .{ .name = "nonc", .code = libc.CRASH_NONC },
    .{ .name = "panic", .code = libc.CRASH_PANIC },
    .{ .name = "slablock", .code = libc.CRASH_SLABLOCK },
    .{ .name = "uaf", .code = libc.CRASH_UAF },
    .{ .name = "race", .code = libc.CRASH_RACE },
};

/// Two processes in the same call at once; nothing halts.
fn race() noreturn {
    libc.print("[crashtest] two processes write one kernel word with no lock...\n");
    const child = libc.fork();
    if (child == 0xFFFFFFFF) {
        libc.print("[crashtest] fork failed: one writer is no race\n");
        libc.exitWith(1);
    }
    const rv = libc.debugCrash(libc.CRASH_RACE);
    if (child == 0) libc.exitWith(rv);
    _ = libc.waitpid(child, null);
    if (rv != 0) {
        libc.print("[crashtest] the kernel did not answer (built without -Ddebug-crash?)\n");
        libc.exitWith(1);
    }
    libc.print("[crashtest] race: done; a -Dkcsan kernel has reported it in its log\n");
    libc.klog("[crashtest] race: done\n");
    libc.exitWith(0);
}

fn usage() noreturn {
    libc.print("usage: crashtest <");
    for (variants, 0..) |v, i| {
        if (i > 0) libc.print("|");
        libc.print(v.name);
    }
    libc.print(">\n");
    libc.exitWith(1);
}

fn argsEq(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, 0..) |c, i| if (c != b[i]) return false;
    return true;
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    if (libc.getArgc() < 2) usage();

    var arg: [32]u8 = undefined;
    const n = libc.getArgv(1, &arg);
    if (n == 0 or n == 0xFFFFFFFF) usage();
    const requested = arg[0..n];

    for (variants) |v| {
        if (argsEq(requested, v.name)) {
            if (v.code == libc.CRASH_RACE) race();
            libc.print("[crashtest] triggering kernel '");
            libc.print(v.name);
            libc.print("' — system will panic + halt; reboot to recover.\n");
            const rv = libc.debugCrash(v.code);
            // If we get here, the syscall didn't panic — that's itself a
            // bug in the kernel handler. Surface clearly.
            libc.print("[crashtest] UNEXPECTED RETURN from debugCrash — kernel didn't panic\n");
            libc.exitWith(rv);
        }
    }

    libc.print("crashtest: unknown variant '");
    libc.print(requested);
    libc.print("'\n");
    usage();
}
