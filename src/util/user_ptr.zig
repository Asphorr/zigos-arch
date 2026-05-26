//! Type-safe wrapper for user-space pointers.
//!
//! Direct `usize` / `u32` user VAs flowing through kernel code carry an
//! implicit "you need to validate before dereferencing" contract that's
//! invisible at the deref site. The Linux SPARSE `__user` annotation
//! enforces this externally; in Zig we can lift it into the type system:
//! a `UserPtr(T)` cannot be dereferenced directly. The only way to read
//! or write the underlying user memory is via `.copyIn()` / `.copyOut()`,
//! and reaching those methods requires going through `.validate()` first
//! — which range-checks, prefaults, walks the page table, and toggles
//! SMAP (STAC).
//!
//! See docs/STYLE.md "User pointers" for the convention.

const std = @import("std");

/// Type-safe user-space pointer to a single `T`. Construct with
/// `UserPtr(T).fromRaw(addr)`; gate access via `.validate()`.
pub fn UserPtr(comptime T: type) type {
    return struct {
        addr: u64,

        const Self = @This();

        /// Wrap a raw user VA. Does NOT validate — the only way to use
        /// the pointer is via `validate()` which returns a verified
        /// handle. Cheap constructor at the syscall ABI boundary.
        pub inline fn fromRaw(addr: u64) Self {
            return .{ .addr = addr };
        }

        /// Range-check + prefault + STAC. On success, returns the same
        /// Self for chaining: `UserPtr(u32).fromRaw(arg).validate() orelse return E_FAULT`.
        /// On any range fault, missing page, alignment violation, or
        /// unmapped lazy region, returns null. The caller-side SMAP
        /// unlock is held for the rest of the syscall (doSyscall's
        /// trailing CLAC closes it on exit).
        pub fn validate(self: Self) ?Self {
            const common = @import("../cpu/syscall/common.zig");
            if (!common.validateUserPtrAligned(@intCast(self.addr), @sizeOf(T), @alignOf(T))) return null;
            return self;
        }

        /// Read one `T` out of user memory. Only call after `validate()`
        /// — pre-validate deref is a type error since `validate` is the
        /// only path that returns Self from a fresh `fromRaw`.
        pub inline fn copyIn(self: Self) T {
            const p: *const T = @ptrFromInt(@as(usize, @intCast(self.addr)));
            return p.*;
        }

        /// Write one `T` to user memory. Same validate-first contract.
        pub inline fn copyOut(self: Self, value: T) void {
            const p: *T = @ptrFromInt(@as(usize, @intCast(self.addr)));
            p.* = value;
        }

        /// Raw pointer escape hatch for callers that need to pass the VA
        /// to a lower-level routine (e.g. `vfs.read(buf_ptr, len)`).
        /// Caller assumes responsibility for the safety contract that
        /// `validate()` would otherwise hold.
        pub inline fn raw(self: Self) u64 {
            return self.addr;
        }
    };
}
