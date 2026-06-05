//! The ZigOS virtual-address-space model — single comptime-verified source of
//! truth for every fixed VA boundary, plus typed address newtypes that make the
//! bug classes this kernel keeps refighting (phys-as-virt, conflated user
//! floors) into *compile errors* instead of runtime triple faults.
//!
//! This module is PURE (imports only `std`) so the whole invariant set is
//! validated natively with `zig test src/mm/layout.zig` — no QEMU, no kernel.
//! `memmap.zig` re-exports the constants below so every existing consumer keeps
//! working unchanged; this file is where they're *defined* and *proven*.
//!
//! ── The two user floors (the Ctrl+C landmine) ──────────────────────────────
//! User space carries TWO distinct floors, and conflating them is the class of
//! bug that broke Ctrl+C (signals.zig) and EFAULT'd stack-buffer syscalls
//! (common.zig). They are now structural, not conventional:
//!   • CODE/RIP/segment validity  →  [USER_VA_FLOOR, USER_VA_MAX)
//!       code never lives below the ELF load base. Used by kdbg.ripIsValidUser
//!       and elf_loader.isUserVA. → `isValidUserCode` / `userCodeRangeOk`.
//!   • DATA/STACK/mappable validity → [USER_SPACE_START, USER_SPACE_END)
//!       the user stack lives in [USER_SPACE_START, USER_VA_FLOOR) — the 1 MB
//!       reserve just under the load base — so data/stack pointers floor LOWER
//!       than code. Used by validateUserPtr, vmm.mapUserPage, signals frames.
//!       → `isUserDataAddr` / `userDataRangeOk`.
//! `classify()` returns an exhaustive tagged class; every validator routes
//! through a `switch` over it, so ADDING a region is a compile error until each
//! validator decides where the new region belongs — the ad-hoc `if (va < FLOOR)`
//! ladders that produced the conflated-floor footgun are gone.

const std = @import("std");

// ── Architectural VA constants (x86_64 4-level paging) ─────────────────────
const PAGE_SIZE: u64 = 0x1000;

/// Canonical-low ceiling (exclusive). On x86_64 a VA is canonical iff bits
/// 47..63 are all 0 (low half) or all 1 (high half); every USER boundary must
/// sit strictly below this, and every KERNEL VA at or above its high mirror.
pub const USER_CANONICAL_MAX: u64 = 0x0000_8000_0000_0000;

// ── Kernel-side VA windows (higher-half; Phase 3 dropped PML4[0]) ───────────
// Source of truth; memmap.zig re-exports these. Values are pinned by the
// comptime block below so an edit here that diverges from linker.ld / boot.asm
// trips the build instead of triple-faulting at boot.

/// Higher-half kernel image base (PML4[511]+PDPT[510], maps phys 0..1 GB).
/// Must match `KERNEL_VIRT_BASE` in src/linker.ld.
pub const KERNEL_VIRT_BASE: u64 = 0xFFFFFFFF80000000;

/// Physmap base (PML4[256], 512 GB window mapping phys 0..PHYSMAP_SIZE). The
/// canonical "kernel reaches any phys frame" view. Must match `pdpt_physmap`
/// in src/boot/boot.asm and uefi/uefi_boot.zig.
pub const PHYSMAP_BASE: u64 = 0xFFFF800000000000;
pub const PHYSMAP_SIZE: u64 = 0x8000000000; // 512 GB (one full PML4 slot)

// ── User-space VA layout (per-process, low half) ───────────────────────────
// Boundaries low→high. The derived ones (USER_SPACE_START) are expressed in
// terms of their primaries so a single bump stays consistent; verify() below
// proves ordering / alignment / canonical-form at comptime.

/// Lowest legitimate user-mode VA at all (the data/stack floor). Sits one
/// USER_STACK_RESERVE below the code load base so the downward-growing user
/// stack in [USER_SPACE_START, USER_VA_FLOOR) is mappable.
pub const USER_SPACE_START: u64 = USER_VA_FLOOR - USER_STACK_RESERVE; // 0x400000

/// Stack reserve below the ELF load base. MUST be >= elf_loader's
/// `stack_pages * PAGE_SIZE` (the assert in elf_loader keeps it in sync).
pub const USER_STACK_RESERVE: u64 = 0x100000; // 256 pages = 1 MB

/// ELF load base — app/linker.ld pins user .text here. The CODE/RIP floor: a
/// saved RIP below this on return-to-user is wild.
pub const USER_VA_FLOOR: u64 = 0x500000; // 5 MB

/// Initial sbrk position; heap grows up from here toward USER_SPACE_END.
pub const USER_BRK_INITIAL: u64 = 0x2000000; // 32 MB

/// Data/stack/mappable ceiling (exclusive). mmap_top starts here and grows
/// down; mapUserPage rejects >= this. The true addressable user ceiling.
pub const USER_SPACE_END: u64 = 0x10000000; // 256 MB

/// ELF-segment / RIP validity ceiling (exclusive). Looser than USER_SPACE_END:
/// a sanity bound on code addresses, NOT a guarantee of mappability. The span
/// [USER_SPACE_END, USER_VA_MAX) is `user_high_unmappable` — code validators
/// accept it but it cannot be mapped. (Tightening this to USER_SPACE_END is a
/// candidate cleanup; kept wide here to stay behavior-identical to the
/// pre-refactor kernel.)
pub const USER_VA_MAX: u64 = 0x40000000; // 1 GB

// ── Comptime verification ──────────────────────────────────────────────────
// The single proof that the layout is well-formed. Any future edit that
// inverts an ordering, de-aligns a boundary, leaves the canonical half, or
// breaks the derived-reserve identity becomes a build error here.

const Boundary = struct { name: []const u8, va: u64 };

/// Ordered user-VA boundaries (low→high), each the *start* of a named span.
const user_boundaries = [_]Boundary{
    .{ .name = "USER_SPACE_START", .va = USER_SPACE_START },
    .{ .name = "USER_VA_FLOOR", .va = USER_VA_FLOOR },
    .{ .name = "USER_BRK_INITIAL", .va = USER_BRK_INITIAL },
    .{ .name = "USER_SPACE_END", .va = USER_SPACE_END },
    .{ .name = "USER_VA_MAX", .va = USER_VA_MAX },
};

fn verify() void {
    // Kernel VA constants pinned to their known-good literals (drift guard:
    // these MUST match linker.ld / boot.asm, which can't be cross-checked from
    // here — so at least pin the value).
    if (KERNEL_VIRT_BASE != 0xFFFFFFFF80000000) @compileError("layout: KERNEL_VIRT_BASE drifted from linker.ld value");
    if (PHYSMAP_BASE != 0xFFFF800000000000) @compileError("layout: PHYSMAP_BASE drifted from boot.asm value");
    if (PHYSMAP_BASE & (PHYSMAP_SIZE - 1) != 0) @compileError("layout: PHYSMAP_BASE not aligned to PHYSMAP_SIZE");
    if (PHYSMAP_BASE < USER_CANONICAL_MAX) @compileError("layout: PHYSMAP_BASE must be in the high half");
    if (KERNEL_VIRT_BASE < USER_CANONICAL_MAX) @compileError("layout: KERNEL_VIRT_BASE must be in the high half");

    // User boundaries: strictly increasing, page-aligned, canonical-low.
    var i: usize = 0;
    while (i < user_boundaries.len) : (i += 1) {
        const b = user_boundaries[i];
        if (b.va & (PAGE_SIZE - 1) != 0) @compileError("layout: " ++ b.name ++ " is not page-aligned");
        if (b.va >= USER_CANONICAL_MAX) @compileError("layout: " ++ b.name ++ " escapes the canonical low half");
        if (i > 0 and b.va <= user_boundaries[i - 1].va) {
            @compileError("layout: " ++ b.name ++ " is not strictly above " ++ user_boundaries[i - 1].name ++ " — boundaries must increase");
        }
    }

    // The stack reserve must be non-empty (a zero reserve means no mappable
    // stack region below the load base — the original silent-EFAULT bug).
    if (USER_SPACE_START >= USER_VA_FLOOR) @compileError("layout: USER_SPACE_START must be below USER_VA_FLOOR (no stack reserve)");
    if (USER_VA_FLOOR - USER_SPACE_START != USER_STACK_RESERVE) @compileError("layout: USER_STACK_RESERVE inconsistent with USER_VA_FLOOR-USER_SPACE_START");
    // Data ceiling must not exceed the code/segment ceiling (else mapUserPage
    // could accept a page the segment validator rejects — the inverse footgun).
    if (USER_SPACE_END > USER_VA_MAX) @compileError("layout: USER_SPACE_END above USER_VA_MAX — data ceiling exceeds code ceiling");
    // A non-null guard: page 0 stays unmapped so a null deref faults.
    if (USER_SPACE_START < PAGE_SIZE) @compileError("layout: USER_SPACE_START must leave page 0 unmapped (null-deref guard)");
}

comptime {
    verify();
}

// ── Exhaustive VA classification ───────────────────────────────────────────

/// Disjoint, exhaustive partition of the full 64-bit VA space from the user
/// point of view. Validators switch over this; adding a variant forces every
/// switch to handle it (or fail to compile).
pub const AddrClass = enum {
    /// [0, USER_SPACE_START) — page 0, kernel low-PA numbers; invalid for user.
    below_user,
    /// [USER_SPACE_START, USER_VA_FLOOR) — the 1 MB stack reserve. DATA ok, CODE no.
    user_stack,
    /// [USER_VA_FLOOR, USER_BRK_INITIAL) — ELF text/rodata/data load area.
    user_code,
    /// [USER_BRK_INITIAL, USER_SPACE_END) — heap (grows up) ∪ mmap (grows down).
    user_heap_mmap,
    /// [USER_SPACE_END, USER_VA_MAX) — CODE validators accept, but UNMAPPABLE
    /// (mapUserPage/validateUserPtr reject). The named home of the old latent
    /// "segment passes load but faults at map time" inconsistency.
    user_high_unmappable,
    /// [USER_VA_MAX, ...) — above the user window; kernel half lives up here.
    above_user,
};

pub fn classify(va: u64) AddrClass {
    if (va < USER_SPACE_START) return .below_user;
    if (va < USER_VA_FLOOR) return .user_stack;
    if (va < USER_BRK_INITIAL) return .user_code;
    if (va < USER_SPACE_END) return .user_heap_mmap;
    if (va < USER_VA_MAX) return .user_high_unmappable;
    return .above_user;
}

/// CODE/RIP/segment membership: [USER_VA_FLOOR, USER_VA_MAX). Exhaustive switch
/// — a new AddrClass variant won't compile until it's classified here.
fn classIsUserCode(c: AddrClass) bool {
    return switch (c) {
        .user_code, .user_heap_mmap, .user_high_unmappable => true,
        .below_user, .user_stack, .above_user => false,
    };
}

/// DATA/STACK/mappable membership: [USER_SPACE_START, USER_SPACE_END).
fn classIsUserData(c: AddrClass) bool {
    return switch (c) {
        .user_stack, .user_code, .user_heap_mmap => true,
        .below_user, .user_high_unmappable, .above_user => false,
    };
}

// ── Validator predicates (the only thing the 5 validators should call) ─────

/// A single code/RIP address is valid. Replaces `rip >= USER_VA_FLOOR and
/// rip < USER_VA_MAX` (kdbg.ripIsValidUser).
pub fn isValidUserCode(va: u64) bool {
    return classIsUserCode(classify(va));
}

/// A single data/stack address is valid (one page, no length). Replaces
/// `virt >= USER_SPACE_START and virt < USER_SPACE_END` (vmm.mapUserPage).
pub fn isUserDataAddr(va: u64) bool {
    return classIsUserData(classify(va));
}

/// A [addr, addr+size) range is valid for CODE/segments. Mirrors
/// elf_loader.isUserVA exactly (saturating add, end<=ceiling).
pub fn userCodeRangeOk(addr: u64, size: u64) bool {
    if (!isValidUserCode(addr)) return false;
    const end = addr +| size; // saturating — matches the original `+|`
    return end <= USER_VA_MAX;
}

/// A [addr, len) range is valid for DATA/stack access. Unifies the two prior
/// implementations (common.validateUserPtr's `+` and signals.validateUserRange's
/// `+%`): saturating add turns an overflowing length into a clean reject on
/// BOTH paths (signals already rejected; validateUserPtr previously risked a
/// ReleaseSafe overflow panic on a hostile length — now hardened identically).
/// Identical accept/reject to both on every non-overflowing input.
pub fn userDataRangeOk(addr: u64, len: u64) bool {
    if (addr < USER_SPACE_START or addr >= USER_SPACE_END) return false;
    if (len == 0) return true;
    const end = addr +| len; // saturating
    return end <= USER_SPACE_END;
}

// ── Typed addresses ────────────────────────────────────────────────────────
// Non-exhaustive enum newtypes: distinct in the type system (can't pass a UVa
// where a KVa is wanted), explicit conversions, and — critically — only KVa
// has `.ptr()`. A Phys must go Phys→KVa (through the physmap) before it can be
// dereferenced, and a UVa is never dereferenced by the kernel directly. That
// structurally encodes the Phase-3 rule and kills the `@ptrFromInt(phys)` class.

/// A physical address. No `.ptr()` — convert via `.toKVa()` first.
pub const Phys = enum(u64) {
    _,
    pub inline fn from(v: u64) Phys {
        return @enumFromInt(v);
    }
    pub inline fn raw(self: Phys) u64 {
        return @intFromEnum(self);
    }
    pub inline fn add(self: Phys, n: u64) Phys {
        return from(self.raw() + n);
    }
    /// Kernel view of this frame through the high-half physmap (PML4[256]).
    pub inline fn toKVa(self: Phys) KVa {
        return KVa.from(PHYSMAP_BASE + self.raw());
    }
};

/// A kernel virtual address (high half: kernel image window or physmap). The
/// only address type the kernel may dereference, via `.ptr(T)`.
pub const KVa = enum(u64) {
    _,
    pub inline fn from(v: u64) KVa {
        return @enumFromInt(v);
    }
    pub inline fn raw(self: KVa) u64 {
        return @intFromEnum(self);
    }
    pub inline fn ptr(self: KVa, comptime T: type) T {
        return @ptrFromInt(self.raw());
    }
    /// Reverse-map to phys across the three kernel windows; null if this VA is
    /// in none of them (a wild kernel pointer). Mirrors paging.virtToPhys.
    pub inline fn toPhys(self: KVa) ?Phys {
        const v = self.raw();
        if (v >= KERNEL_VIRT_BASE) return Phys.from(v - KERNEL_VIRT_BASE);
        if (v >= PHYSMAP_BASE and v < PHYSMAP_BASE + PHYSMAP_SIZE) return Phys.from(v - PHYSMAP_BASE);
        if (v < 0x100000000) return Phys.from(v); // boot low-identity (<4 GB)
        return null;
    }
};

/// A user virtual address (low half, per-process). No `.ptr()` — the kernel
/// touches user memory only after validation + STAC, through copy helpers.
pub const UVa = enum(u64) {
    _,
    pub inline fn from(v: u64) UVa {
        return @enumFromInt(v);
    }
    pub inline fn raw(self: UVa) u64 {
        return @intFromEnum(self);
    }
    pub inline fn class(self: UVa) AddrClass {
        return classify(self.raw());
    }
    pub inline fn isCode(self: UVa) bool {
        return isValidUserCode(self.raw());
    }
    pub inline fn isData(self: UVa) bool {
        return isUserDataAddr(self.raw());
    }
};

// ── 4-level paging structure ───────────────────────────────────────────────
// VA → table-index decomposition. Named, single-purpose helpers replace the
// repeated, easy-to-misorder `(va >> N) & 0x1FF` open-coding in paging.zig.
// Each returns a usize ready to index a [*]u64 table.

pub inline fn pml4Index(va: anytype) usize {
    return @intCast((va >> 39) & 0x1FF);
}
pub inline fn pdptIndex(va: anytype) usize {
    return @intCast((va >> 30) & 0x1FF);
}
pub inline fn pdIndex(va: anytype) usize {
    return @intCast((va >> 21) & 0x1FF);
}
pub inline fn ptIndex(va: anytype) usize {
    return @intCast((va >> 12) & 0x1FF);
}

// ── Native tests (zig test src/mm/layout.zig) ──────────────────────────────

test "constants match the pre-refactor literals (no-op guard)" {
    try std.testing.expectEqual(@as(u64, 0x400000), USER_SPACE_START);
    try std.testing.expectEqual(@as(u64, 0x100000), USER_STACK_RESERVE);
    try std.testing.expectEqual(@as(u64, 0x500000), USER_VA_FLOOR);
    try std.testing.expectEqual(@as(u64, 0x2000000), USER_BRK_INITIAL);
    try std.testing.expectEqual(@as(u64, 0x10000000), USER_SPACE_END);
    try std.testing.expectEqual(@as(u64, 0x40000000), USER_VA_MAX);
    try std.testing.expectEqual(@as(u64, 0xFFFFFFFF80000000), KERNEL_VIRT_BASE);
    try std.testing.expectEqual(@as(u64, 0xFFFF800000000000), PHYSMAP_BASE);
}

test "classify partitions the boundaries correctly" {
    try std.testing.expectEqual(AddrClass.below_user, classify(0));
    try std.testing.expectEqual(AddrClass.below_user, classify(USER_SPACE_START - 1));
    try std.testing.expectEqual(AddrClass.user_stack, classify(USER_SPACE_START));
    try std.testing.expectEqual(AddrClass.user_stack, classify(USER_VA_FLOOR - 1));
    try std.testing.expectEqual(AddrClass.user_code, classify(USER_VA_FLOOR));
    try std.testing.expectEqual(AddrClass.user_code, classify(USER_BRK_INITIAL - 1));
    try std.testing.expectEqual(AddrClass.user_heap_mmap, classify(USER_BRK_INITIAL));
    try std.testing.expectEqual(AddrClass.user_heap_mmap, classify(USER_SPACE_END - 1));
    try std.testing.expectEqual(AddrClass.user_high_unmappable, classify(USER_SPACE_END));
    try std.testing.expectEqual(AddrClass.user_high_unmappable, classify(USER_VA_MAX - 1));
    try std.testing.expectEqual(AddrClass.above_user, classify(USER_VA_MAX));
    try std.testing.expectEqual(AddrClass.above_user, classify(KERNEL_VIRT_BASE));
}

test "isValidUserCode reproduces rip>=FLOOR and rip<MAX" {
    const samples = [_]u64{ 0, 0x3FFFFF, USER_SPACE_START, USER_VA_FLOOR - 1, USER_VA_FLOOR, 0x800000, USER_SPACE_END, USER_VA_MAX - 1, USER_VA_MAX, KERNEL_VIRT_BASE };
    for (samples) |x| {
        const want = (x >= USER_VA_FLOOR and x < USER_VA_MAX);
        try std.testing.expectEqual(want, isValidUserCode(x));
    }
}

test "isUserDataAddr reproduces va>=START and va<END" {
    const samples = [_]u64{ 0, USER_SPACE_START - 1, USER_SPACE_START, USER_VA_FLOOR, USER_BRK_INITIAL, USER_SPACE_END - 1, USER_SPACE_END, USER_VA_MAX, KERNEL_VIRT_BASE };
    for (samples) |x| {
        const want = (x >= USER_SPACE_START and x < USER_SPACE_END);
        try std.testing.expectEqual(want, isUserDataAddr(x));
    }
}

test "userCodeRangeOk mirrors elf isUserVA" {
    // in range
    try std.testing.expect(userCodeRangeOk(USER_VA_FLOOR, 0x1000));
    // below floor
    try std.testing.expect(!userCodeRangeOk(USER_SPACE_START, 0x1000));
    // straddles the ceiling
    try std.testing.expect(!userCodeRangeOk(USER_VA_MAX - 0x800, 0x1000));
    // saturating add can't wrap to accept
    try std.testing.expect(!userCodeRangeOk(USER_VA_FLOOR, std.math.maxInt(u64)));
}

test "userDataRangeOk mirrors validateUserPtr / validateUserRange" {
    try std.testing.expect(userDataRangeOk(USER_SPACE_START, 0)); // single addr
    try std.testing.expect(userDataRangeOk(USER_BRK_INITIAL, 0x1000));
    try std.testing.expect(!userDataRangeOk(USER_SPACE_START - 1, 0));
    try std.testing.expect(!userDataRangeOk(USER_SPACE_END, 0)); // ceiling exclusive
    try std.testing.expect(!userDataRangeOk(USER_SPACE_END - 0x800, 0x1000)); // straddle
    try std.testing.expect(!userDataRangeOk(USER_SPACE_START, std.math.maxInt(u64))); // overflow → reject, no panic
}

test "typed addresses: Phys<->KVa round-trip through physmap" {
    const p = Phys.from(0x1000);
    try std.testing.expectEqual(@as(u64, PHYSMAP_BASE + 0x1000), p.toKVa().raw());
    try std.testing.expectEqual(@as(u64, 0x1000), p.toKVa().toPhys().?.raw());
    try std.testing.expectEqual(@as(u64, 0x3000), p.add(0x2000).raw());
    // kernel image window reverses too
    const kimg = KVa.from(KERNEL_VIRT_BASE + 0x200000);
    try std.testing.expectEqual(@as(u64, 0x200000), kimg.toPhys().?.raw());
    // a wild high VA in the canonical gap has no phys
    try std.testing.expect(KVa.from(0x100000000).toPhys() == null);
}

test "typed UVa classifies" {
    try std.testing.expectEqual(AddrClass.user_code, UVa.from(USER_VA_FLOOR).class());
    try std.testing.expect(UVa.from(USER_VA_FLOOR).isCode());
    try std.testing.expect(UVa.from(USER_SPACE_START).isData());
    try std.testing.expect(!UVa.from(USER_SPACE_START).isCode()); // stack reserve: data yes, code no
}

test "paging index decomposition" {
    // PHYSMAP_BASE = 0xFFFF800000000000 → PML4 slot 256.
    try std.testing.expectEqual(@as(usize, 256), pml4Index(PHYSMAP_BASE));
    // KERNEL_VIRT_BASE = 0xFFFFFFFF80000000 → PML4 511, PDPT 510.
    try std.testing.expectEqual(@as(usize, 511), pml4Index(KERNEL_VIRT_BASE));
    try std.testing.expectEqual(@as(usize, 510), pdptIndex(KERNEL_VIRT_BASE));
    // Arbitrary VA matches the open-coded expressions it replaces.
    const va: u64 = 0x0000_0000_0123_4567;
    try std.testing.expectEqual(@as(usize, (va >> 39) & 0x1FF), pml4Index(va));
    try std.testing.expectEqual(@as(usize, (va >> 30) & 0x1FF), pdptIndex(va));
    try std.testing.expectEqual(@as(usize, (va >> 21) & 0x1FF), pdIndex(va));
    try std.testing.expectEqual(@as(usize, (va >> 12) & 0x1FF), ptIndex(va));
}
