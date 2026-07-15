//! Type-safe wrapper for user-space pointers.
//!
//! Direct `usize` / `u32` user VAs flowing through kernel code carry an
//! implicit "you need to validate before dereferencing" contract that's
//! invisible at the deref site. The Linux SPARSE `__user` annotation
//! enforces this externally; in Zig we can lift it into the type system:
//! a `UserPtr(T)` cannot be dereferenced at all — it has no `copyIn` /
//! `copyOut`. Those live only on the proof types `validate()` /
//! `validateWrite()` return, so "deref an unvalidated user pointer" is
//! a compile error, not a code-review catch. (Zig has no private fields,
//! so hand-rolling a proof literal is *possible* — but that's a
//! deliberate act a reviewer can grep for, not an accident.)
//!
//! See docs/STYLE.md "User pointers" for the convention.

const std = @import("std");

/// Type-safe user-space pointer to a single `T`. Construct with
/// `UserPtr(T).fromRaw(addr)`; gate access via `.validate()` (read) or
/// `.validateWrite()` (write) — each returns a proof handle carrying
/// the matching copy methods.
pub fn UserPtr(comptime T: type) type {
    return struct {
        addr: u64,

        const Self = @This();

        /// Wrap a raw user VA. Does NOT validate — this type has no
        /// deref methods; the only way to touch the memory is through
        /// the handle `validate()` / `validateWrite()` returns. Cheap
        /// constructor at the syscall ABI boundary.
        pub inline fn fromRaw(addr: u64) Self {
            return .{ .addr = addr };
        }

        /// Range-check + prefault + STAC. On success returns a read-only
        /// proof handle: `UserPtr(u32).fromRaw(arg).validate() orelse return E_FAULT`.
        /// On any range fault, missing page, alignment violation, or
        /// unmapped lazy region, returns null. The caller-side SMAP
        /// unlock is held for the rest of the syscall (doSyscall's
        /// trailing CLAC closes it on exit).
        ///
        /// READ-ONLY contract: this only proves the page is *present*, not
        /// *writable* — a present-but-read-only user page (the app's own
        /// .text/.rodata, or an un-broken COW page) passes here. Hence the
        /// handle has `copyIn` only; a write target must go through
        /// `validateWrite()`, or the store would #PF (err=0x3) in ring 0
        /// after STAC opens.
        pub fn validate(self: Self) ?Validated {
            const common = @import("../cpu/syscall/common.zig");
            if (!common.validateUserPtrAligned(@intCast(self.addr), @sizeOf(T), @alignOf(T))) return null;
            return .{ .addr = self.addr };
        }

        /// Like `validate()` but ALSO proves the page is writable (breaks COW
        /// and rejects genuinely read-only pages). Returns null (→ caller maps
        /// to E_FAULT) for a read-only target, converting what would be a
        /// kernel write-fault panic into a clean errno. The handle carries
        /// both directions — a user page that's writable is also readable.
        pub fn validateWrite(self: Self) ?ValidatedWrite {
            const common = @import("../cpu/syscall/common.zig");
            if (!common.validateUserPtrWriteAligned(@intCast(self.addr), @sizeOf(T), @alignOf(T))) return null;
            return .{ .addr = self.addr };
        }

        /// Raw pointer escape hatch for callers that need to pass the VA
        /// to a lower-level routine (e.g. `vfs.read(buf_ptr, len)`).
        /// Caller assumes responsibility for the safety contract that
        /// `validate()` would otherwise hold.
        pub inline fn raw(self: Self) u64 {
            return self.addr;
        }

        /// Proof of `validate()`: page present + aligned, NOT proven
        /// writable. Read access only.
        pub const Validated = struct {
            addr: u64,

            /// Read one `T` out of user memory.
            pub inline fn copyIn(self: Validated) T {
                const p: *const T = @ptrFromInt(@as(usize, @intCast(self.addr)));
                return p.*;
            }

            pub inline fn raw(self: Validated) u64 {
                return self.addr;
            }
        };

        /// Proof of `validateWrite()`: page present + aligned + writable
        /// (COW broken). Both directions.
        pub const ValidatedWrite = struct {
            addr: u64,

            /// Read one `T` out of user memory.
            pub inline fn copyIn(self: ValidatedWrite) T {
                const p: *const T = @ptrFromInt(@as(usize, @intCast(self.addr)));
                return p.*;
            }

            /// Write one `T` to user memory. Only reachable here — the
            /// writable-page proof is in the type.
            pub inline fn copyOut(self: ValidatedWrite, value: T) void {
                const p: *T = @ptrFromInt(@as(usize, @intCast(self.addr)));
                p.* = value;
            }

            pub inline fn raw(self: ValidatedWrite) u64 {
                return self.addr;
            }
        };
    };
}
