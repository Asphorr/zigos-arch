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
        const stored = @min(t.index, t.instruction_addresses.len);
        const shown = @min(stored, MAX_FRAMES);
        for (t.instruction_addresses[0..shown]) |addr| {
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
