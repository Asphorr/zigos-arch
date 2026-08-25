//! errtrace — print where an error was born and how it propagated.
//!
//! ReleaseSafe already pays for error-return tracing (forced on in
//! build.zig): every `try` appends its return address to a hidden
//! per-call-chain StackTrace. This module is the ~40 lines that make
//! that purchase visible: symbol-resolve the trace via the kernel
//! symtab and append the fail-ring tail (the formatted detail the
//! trace can't carry).
//!
//! Use at the point where an error SURFACES — an ABI boundary mapping
//! it to errno, a top-level task loop, a mount that gives up:
//!
//! ```zig
//! vfs.read(...) catch |e| {
//!     errtrace.dump(e, @errorReturnTrace());
//!     return errno.fromError(e);
//! };
//! ```
//!
//! Not for expected-and-handled errors (a probe loop trying the next
//! disk) — those stay quiet; their detail is already in the fail ring
//! if anyone needs it post-hoc.

const std = @import("std");

const serial = @import("../debug/serial.zig");
const symbols = @import("../debug/symbols.zig");
const fail = @import("fail.zig");

/// Cap on printed frames — traces deeper than this are cut with a note.
const MAX_FRAMES: usize = 16;

pub fn dump(err: anyerror, trace: ?*std.builtin.StackTrace) void {
    serial.print("[errtrace] error.{s}\n", .{@errorName(err)});
    if (trace) |t| {
        // The trace buffer is a RING: on a chain deeper than the buffer,
        // index keeps counting while the oldest frames are overwritten,
        // and the oldest RETAINED frame sits at (index - stored) % len —
        // linear [0..shown] indexing would print the wrong frames in the
        // wrong order (std.debug.writeStackTrace does this same modulo
        // walk).
        const cap = t.instruction_addresses.len;
        const stored = @min(t.index, cap);
        const shown = @min(stored, MAX_FRAMES);
        const first = (t.index - stored) % @max(cap, 1);
        var i: usize = 0;
        while (i < shown) : (i += 1) {
            const addr = t.instruction_addresses[(first + i) % cap];
            if (symbols.resolveKernel(addr)) |r| {
                serial.print("  via {s}+0x{X}\n", .{ r.name, r.offset });
            } else {
                serial.print("  via 0x{X:0>16}\n", .{addr});
            }
        }
        if (t.index > shown) {
            serial.print("  ({d} more frames not shown)\n", .{t.index - shown});
        }
        if (t.index == 0) {
            serial.print("  (empty trace — error was constructed, not propagated via try)\n", .{});
        }
    } else {
        serial.print("  (no error-return trace — error tracing off in this build?)\n", .{});
    }
    fail.dumpRecent(8);
}
