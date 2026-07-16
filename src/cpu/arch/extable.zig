// Kernel exception table — the registry the #PF/#GP handler consults before
// declaring a kernel-mode fault fatal.
//
// This is Linux's __ex_table idea with the registration inverted: instead of
// a linker section collecting (fault, fixup) pairs at link time, each module
// that owns a faultable instruction site publishes its pair into its own
// module globals from the accessor itself (`leaq Nf(%rip)` on every entry —
// idempotent, live before the faulting instruction can execute, no locks,
// no init order). This file is only the DISPATCH point: exception.zig asks
// once, modules answer for their own sites.
//
// Contract for a module adding a site (see msr.zig and usercopy.zig for the
// two live examples):
//   * The accessor holding the asm must be `noinline` (or provably
//     single-instantiation): inlining duplicates the site, and concurrent
//     callers of different instances cross-stomp the published globals —
//     a fault in one instance then misses the table and panics.
//   * Publish (fault_rip, fixup_rip) BEFORE the faulting instruction, every
//     call, to the same link-time-constant values.
//   * The fixup path must be legal to land on with the fault-time register
//     state (rep-string ops conveniently keep their progress in rcx/rsi/rdi).
//   * Expose `fixupRip(rip: u64) ?u64` and add it to the chain below.
//
// The handler side (exception.zig) redirects saved RIP and returns — no
// blocking, no allocation, safe from any fault context including under
// spinlocks with IRQs off. Anything that needs to BLOCK to resolve the
// fault (swap-in, COW break) happens in the caller's context after the
// fixup reports failure — see usercopy.zig's retry layer.

/// Return the fixup RIP for a registered kernel fault site, else null
/// (the fault takes its normal fatal course). Called on every kernel-mode
/// #GP and #PF — keep it a short chain of address compares.
pub fn fixupRip(rip: u64) ?u64 {
    if (@import("usercopy.zig").fixupRip(rip)) |f| return f;
    if (@import("msr.zig").fixupRip(rip)) |f| return f;
    return null;
}
