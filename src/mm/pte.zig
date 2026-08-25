//! pte — the 4 KiB user PTE as a typed value.
//!
//! A PTE is a sum type the hardware forces into one u64: which variant a
//! word is in is decided by discriminant BITS (PRESENT, and — only while
//! PRESENT=0 — the two software markers), and the payload's meaning changes
//! completely with the variant. The kernel has been reading that sum type
//! through hand-applied masks in three files (vmm walk, swap state machine,
//! fault dispatch); every mask read is one chance to test the wrong bit on
//! the right word — the exact class the 2026-05-23/24 CAS-loss sweeps kept
//! finding one more instance of.
//!
//! This module makes the discrimination a `switch`:
//!
//!     switch (pte.decode(word)) {
//!         .absent   => ...,     // never faulted / discarded
//!         .present  => |p| ..., // p.writable, p.cow, p.frame()
//!         .swapped  => |s| ..., // page on disk; slot/gen codec stays swap's
//!         .inflight => |f| ..., // mid-eviction; f.frame pinned by evictor
//!         .corrupt  => |w| ..., // non-present, nonzero, unmarked — NOT ours
//!     }
//!
//! and makes word SURGERY a struct edit: `var p = Present.fromWord(w);
//! p.cow = false; p.writable = true;` replaces `(w & ~COW) | READ_WRITE`.
//! Both compile to the same instructions — a packed struct IS the word.
//!
//! What stays outside:
//!   - The slot+gen packing inside a SWAPPED word is swap.zig's PRIVATE
//!     codec (geometry derives from NUM_SLOTS; the gen tag is consumed only
//!     by CAS bit-equality). decode() names the state; swap decodes the
//!     payload. Nobody else has any business in those bits.
//!   - CAS loops keep comparing raw u64 snapshots. The type covers reads
//!     and word CONSTRUCTION; the concurrency protocol is untouched.
//!
//! The comptime block at the bottom is the partition proof: every field of
//! `Present` is proven to sit on the bit the historic paging.* constant
//! names, and decode() is proven total and mutually exclusive on a sample
//! matrix — a mis-declared field width fails the BUILD, not a boot.

const std = @import("std");
const paging = @import("paging.zig");
const Phys = @import("../util/addr.zig").Phys;

/// Software markers for non-present words. Bits 10/11 are AVL on x86_64 —
/// the CPU ignores everything but PRESENT=0, so they are ours. Owned here
/// (swap.zig imports them) so the decode switch and the encoders can never
/// disagree about which bit means what.
pub const SWAPPED_MARK: u64 = 1 << 10;
pub const INFLIGHT_MARK: u64 = 1 << 11;

/// The PRESENT variant, as the word itself. Field order IS the layout —
/// see the comptime proof. `page_size` is PAT on a 4 KiB leaf; this view is
/// for leaves (vmm's walk checks PS at PD/PDPT level on the raw word before
/// ever reaching a leaf).
pub const Present = packed struct(u64) {
    present: bool = false, // bit 0
    writable: bool = false, // bit 1
    user: bool = false, // bit 2
    write_through: bool = false, // bit 3  (PWT)
    cache_disable: bool = false, // bit 4  (PCD)
    accessed: bool = false, // bit 5  (A — CPU-set; swap clock clears)
    dirty: bool = false, // bit 6  (D — CPU-set on write)
    page_size: bool = false, // bit 7  (PAT on a 4K leaf)
    global: bool = false, // bit 8
    cow: bool = false, // bit 9  (software: copy-on-write)
    avl10: bool = false, // bit 10 (SWAPPED marker — meaningless while present)
    avl11: bool = false, // bit 11 (INFLIGHT marker — meaningless while present)
    frame_bits: u40 = 0, // bits 12..51 (phys >> 12)
    avl_high: u11 = 0, // bits 52..62
    no_exec: bool = false, // bit 63 (NX; EFER.NXE is required at boot)

    pub inline fn fromWord(w: u64) Present {
        return @bitCast(w);
    }
    pub inline fn word(self: Present) u64 {
        return @bitCast(self);
    }
    pub inline fn frame(self: Present) Phys {
        return Phys.of(@as(u64, self.frame_bits) << 12);
    }
    pub inline fn setFrame(self: *Present, f: Phys) void {
        self.frame_bits = @intCast(f.raw() >> 12);
    }
};

/// A SWAPPED word, payload undecoded — the slot/gen codec belongs to
/// swap.zig (its geometry derives from NUM_SLOTS, and the gen tag is only
/// ever consumed by CAS bit-equality, never read back).
pub const Swapped = struct { word: u64 };

/// A SWAP_INFLIGHT word: the evicting thread parked this frame's phys in
/// the PTE while the write-out is in flight.
pub const Inflight = struct { frame: Phys };

pub const View = union(enum) {
    absent,
    present: Present,
    swapped: Swapped,
    inflight: Inflight,
    /// Non-present, nonzero, and neither marker set (or impossibly both) —
    /// no kernel path writes such a word into a user PT. Naming it forces
    /// every switch to decide what defensive means there instead of
    /// silently lumping it with a real state.
    corrupt: u64,
};

/// COW write-fault resolutions, as vocabulary. Both are pure word math —
/// callers CAS the result against their original snapshot as before.
/// Promote in place: sole owner (or shared mapping) keeps the frame,
/// gains write, drops the COW mark.
pub inline fn cowPromote(w: u64) u64 {
    var p = Present.fromWord(w);
    p.cow = false;
    p.writable = true;
    return p.word();
}

/// Break to a private copy: same flags, write restored, COW dropped, frame
/// replaced by the caller's freshly-copied private page.
pub inline fn cowBreakTo(w: u64, private_frame: Phys) u64 {
    var p = Present.fromWord(w);
    p.cow = false;
    p.writable = true;
    p.setFrame(private_frame);
    return p.word();
}

pub fn decode(w: u64) View {
    if (w & paging.PRESENT != 0) return .{ .present = Present.fromWord(w) };
    if (w == 0) return .absent;
    const sw = w & SWAPPED_MARK != 0;
    const inf = w & INFLIGHT_MARK != 0;
    if (sw and inf) return .{ .corrupt = w };
    if (inf) return .{ .inflight = .{ .frame = Phys.of(w & paging.PAGE_MASK) } };
    if (sw) return .{ .swapped = .{ .word = w } };
    return .{ .corrupt = w };
}

// ---------------------------- partition proof -------------------------------
// Every claim the module makes about bit positions, proven at compile time
// against the constants the rest of the kernel has been masking with since
// boot day. A field declared one bit wide of the truth fails right here.
comptime {
    const a = std.debug.assert;
    // Each Present field sits exactly on its historic constant.
    a(@as(u64, @bitCast(Present{ .present = true })) == paging.PRESENT);
    a(@as(u64, @bitCast(Present{ .writable = true })) == paging.READ_WRITE);
    a(@as(u64, @bitCast(Present{ .user = true })) == paging.USER);
    a(@as(u64, @bitCast(Present{ .write_through = true })) == paging.WRITE_THROUGH);
    a(@as(u64, @bitCast(Present{ .cache_disable = true })) == paging.CACHE_DISABLE);
    a(@as(u64, @bitCast(Present{ .accessed = true })) == paging.ACCESSED);
    a(@as(u64, @bitCast(Present{ .dirty = true })) == paging.DIRTY);
    a(@as(u64, @bitCast(Present{ .page_size = true })) == paging.PAGE_SIZE_FLAG);
    a(@as(u64, @bitCast(Present{ .cow = true })) == paging.COW);
    a(@as(u64, @bitCast(Present{ .avl10 = true })) == SWAPPED_MARK);
    a(@as(u64, @bitCast(Present{ .avl11 = true })) == INFLIGHT_MARK);
    a(@as(u64, @bitCast(Present{ .no_exec = true })) == paging.NX);
    a(@as(u64, @bitCast(Present{ .frame_bits = ~@as(u40, 0) })) == paging.PAGE_MASK);
    // The markers never collide with anything the present view names.
    a(SWAPPED_MARK & INFLIGHT_MARK == 0);
    a((SWAPPED_MARK | INFLIGHT_MARK) & (paging.PRESENT | paging.COW | paging.PAGE_MASK) == 0);

    // Word surgery through the view produces the exact words the historic
    // mask formulas produced (the COW handler's three constructions).
    {
        const old: u64 = paging.PRESENT | paging.USER | paging.COW | paging.ACCESSED |
            (0x1234000 & paging.PAGE_MASK) | paging.NX;
        var p = Present.fromWord(old);
        p.cow = false;
        p.writable = true;
        a(p.word() == (old & ~paging.COW) | paging.READ_WRITE);
        p.setFrame(Phys.of(0x7777000));
        a(p.word() == ((old & ~paging.COW & ~paging.PAGE_MASK) | 0x7777000 | paging.READ_WRITE));
        a(p.frame().raw() == 0x7777000);
        // The named resolutions equal the historic mask formulas verbatim.
        a(cowPromote(old) == (old & ~paging.COW) | paging.READ_WRITE);
        a(cowBreakTo(old, Phys.of(0x7777000)) ==
            ((old & ~paging.PAGE_MASK & ~paging.COW) | 0x7777000 | paging.READ_WRITE));
    }

    // decode() is total and mutually exclusive on the state matrix.
    a(decode(0) == .absent);
    a(decode(paging.PRESENT | 0xABC000) == .present);
    a(decode(paging.PRESENT | SWAPPED_MARK) == .present); // PRESENT wins; markers are AVL noise
    a(decode(SWAPPED_MARK | (7 << 12)) == .swapped);
    a(decode(INFLIGHT_MARK | 0x5000) == .inflight);
    a(decode(SWAPPED_MARK | INFLIGHT_MARK) == .corrupt); // both markers: no writer produces this
    a(decode(paging.COW) == .corrupt); // non-present, unmarked, nonzero: not ours
    a(decode(INFLIGHT_MARK | 0x5000).inflight.frame.raw() == 0x5000);
}
