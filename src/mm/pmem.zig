// Persistent memory (NVDIMM) — discovery + mapping.
//
// N1: find the byte-addressable persistent-memory region and map it. The
// region is discovered two complementary ways:
//   - the static ACPI NFIT (acpi.firstPmemRange) — the authoritative geometry
//     oracle: guest-physical base + length of the PM System-Physical-Address
//     range;
//   - the ACPI namespace's NVDIMM root device (\_SB.NVDR, _HID "ACPI0012", via
//     aml.nvdimmInfo) — confirms the firmware's *dynamic* control interface
//     (_FIT / _DSM, driven over the QEMU DSM mailbox in later slices).
//
// The region is real DRAM (a file-backed QEMU memory-backend), so it lives in
// the kernel physmap as write-back memory and is reachable directly via
// physToVirt while it lands inside the boot-mapped window.
//
// N2: persistence primitives — CLWB / CLFLUSHOPT / CLFLUSH followed by SFENCE
// push stores out to the persistence domain (best instruction the CPU
// advertises, picked at boot). A boot-survival self-test keeps a monotonic
// boot counter in the region itself to prove the contents survive a VM restart
// (the backing file does the persisting; under QEMU-without-libpmem the flushes
// are advisory and durability lands when QEMU msyncs the mapping on exit).
//
// N2.5: typed persistent objects — Persistent(T) proves at compile time that
// a struct may live in the region (every bit pattern a valid value, explicit
// layout, no pointers, no implicit padding), pins the layout with a comptime
// fingerprint, and hands out only durable stores. The boot-counter header is
// its reference consumer.

const std = @import("std"); // comptime-only: @typeInfo walks + comptimePrint

const acpi = @import("../acpi/acpi.zig");
const aml = @import("../acpi/aml.zig");
const paging = @import("paging.zig");
const pmm = @import("pmm.zig");
const debug = @import("../debug/debug.zig");

var present: bool = false;
var base_phys: u64 = 0;
var len_bytes: u64 = 0;
var region: [*]volatile u8 = undefined;

/// True once init() has mapped a persistent-memory region.
pub fn isPresent() bool {
    return present;
}

/// Guest-physical base of the pmem region (0 if none).
pub fn basePhys() u64 {
    return base_phys;
}

/// Length of the pmem region in bytes (0 if none).
pub fn size() u64 {
    return len_bytes;
}

/// Kernel pointer to the mapped pmem region, or null if no NVDIMM is present.
pub fn ptr() ?[*]volatile u8 {
    return if (present) region else null;
}

// --- N2: persistence primitives --------------------------------------------
//
// Making a store durable on real NVDIMM hardware is a two-step dance (Intel
// SDM Vol 1 §10.4 + the persistent-memory programming model):
//   1. write back the dirty cache lines covering the data, then
//   2. SFENCE so those writebacks are ordered before any later store and
//      before we treat the data as persisted.
// We use the strongest line-flush the CPU advertises:
//   CLWB        CPUID.07H:EBX[24]  — write back, keep the line cached (best
//                                    for pmem: hot data stays hot)
//   CLFLUSHOPT  CPUID.07H:EBX[23]  — write back + evict, weakly ordered
//   CLFLUSH     CPUID.01H:EDX[19]  — baseline, always present on x86_64
// SFENCE orders all three (CLFLUSH is already ordered; the fence is harmless).

const CACHE_LINE = 64;

const FlushKind = enum { clwb, clflushopt, clflush };
var flush_kind: FlushKind = .clflush;

inline fn cpuid(leaf: u32, subleaf: u32) struct { eax: u32, ebx: u32, ecx: u32, edx: u32 } {
    var eax: u32 = undefined;
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    var edx: u32 = undefined;
    asm volatile ("cpuid"
        : [_] "={eax}" (eax),
          [_] "={ebx}" (ebx),
          [_] "={ecx}" (ecx),
          [_] "={edx}" (edx),
        : [_] "{eax}" (leaf),
          [_] "{ecx}" (subleaf),
    );
    return .{ .eax = eax, .ebx = ebx, .ecx = ecx, .edx = edx };
}

/// Pick the best available write-back instruction once at boot.
fn detectFlush() void {
    if (cpuid(0, 0).eax >= 7) {
        const ebx = cpuid(7, 0).ebx;
        if (ebx & (1 << 24) != 0) {
            flush_kind = .clwb;
            return;
        }
        if (ebx & (1 << 23) != 0) {
            flush_kind = .clflushopt;
            return;
        }
    }
    flush_kind = .clflush; // CPUID.01H:EDX[19], guaranteed on x86_64
}

inline fn flushLine(addr: usize) void {
    switch (flush_kind) {
        .clwb => asm volatile ("clwb (%[p])"
            :
            : [p] "r" (addr),
            : .{ .memory = true }),
        .clflushopt => asm volatile ("clflushopt (%[p])"
            :
            : [p] "r" (addr),
            : .{ .memory = true }),
        .clflush => asm volatile ("clflush (%[p])"
            :
            : [p] "r" (addr),
            : .{ .memory = true }),
    }
}

inline fn sfence() void {
    asm volatile ("sfence" ::: .{ .memory = true });
}

/// Flush + fence a byte range of the mapped pmem region out to the persistence
/// domain. `off`/`len` are offsets into the region. Cache-line aligned, so a
/// sub-line range still writes back the whole covering line(s). No-op when no
/// NVDIMM is present. This is the durability primitive the N4 crash-consistent
/// log builds on.
pub fn persistRange(off: u64, len: u64) void {
    if (!present or len == 0 or off >= len_bytes) return;
    const base = @intFromPtr(region);
    var a = (base + off) & ~@as(usize, CACHE_LINE - 1); // align down to the line
    const clamped_len = @min(len, len_bytes - off);
    const end = base + off + clamped_len;
    while (a < end) : (a += CACHE_LINE) flushLine(a);
    sfence();
}

// --- N3: byte-addressable access (backs /dev/pmem0) ------------------------

/// Read up to `dst.len` bytes from the pmem region starting at byte offset
/// `off` into `dst`. Returns the number of bytes copied — clamped at the end
/// of the region, 0 if no NVDIMM or `off` is past the end. Byte-granular: the
/// whole point of pmem is that it is not block-structured.
pub fn readAt(off: u64, dst: []u8) usize {
    if (!present or off >= len_bytes) return 0;
    const n: usize = @intCast(@min(@as(u64, dst.len), len_bytes - off));
    var i: usize = 0;
    while (i < n) : (i += 1) dst[i] = region[@intCast(off + i)];
    return n;
}

/// Write `src` into the pmem region at byte offset `off`, then push the touched
/// bytes out to the persistence domain (persistRange). Returns the number of
/// bytes written — clamped at the end of the region, 0 if no NVDIMM or `off` is
/// past the end. Every /dev/pmem0 write is durable on return.
pub fn writeAt(off: u64, src: []const u8) usize {
    if (!present or off >= len_bytes) return 0;
    const n: usize = @intCast(@min(@as(u64, src.len), len_bytes - off));
    var i: usize = 0;
    while (i < n) : (i += 1) region[@intCast(off + i)] = src[i];
    persistRange(off, n);
    return n;
}

// --- N2.5: typed persistent objects — the compiler as format police ---------
//
// Bytes in this region have two failure modes ordinary RAM never shows:
//   1. they OUTLIVE THE BINARY — next boot's kernel, possibly rebuilt from
//      changed source, reinterprets them, so a struct stored here is an
//      on-disk format, not an in-memory convenience;
//   2. they can be TORN — a crash mid-store leaves any byte pattern, so a
//      field type with invalid representations (bool, enum, pointer) makes
//      the post-crash *load* undefined behavior, not merely wrong data.
// Persistent(T) turns both into compile errors:
//   - assertPersistable walks T recursively and rejects, naming the field
//     path, everything whose bit patterns are not all valid values (bool,
//     enum, union, optional), everything the compiler may re-lay-out
//     (auto-layout structs), pointer-sized integers, implicit padding (torn
//     padding makes checksums lie), and the pmem classic — pointers: a
//     virtual address is garbage after reboot;
//   - layoutId folds the recursive layout (field names, offsets, widths)
//     into a comptime fingerprint; locking it (HEADER_LAYOUT_ID below) makes
//     editing a persistent struct fail the build until the on-pmem format
//     bump is made consciously — rule 5's comptime-assert idea aimed at
//     persistence instead of bounds;
//   - the handle exposes only load (snapshot out) and store (write-through +
//     persistRange): through the handle, a store that skips the persistence
//     domain does not compile — the same split user_ptr.zig makes with its
//     validate()/copyIn proof handles.
// The validator is what makes load() sound: copying raw — possibly torn —
// bytes into a T is defensible only because every bit pattern of a
// persistable T is a valid T.
//
// Concurrency: like readAt/writeAt, handles do not lock; the caller owns
// exclusion over its window (the boot self-test runs single-threaded).

/// Reject, at compile time and naming the offending field path, any type
/// whose bytes cannot safely live in persistent memory. Admission rule:
/// every bit pattern is a valid value, the layout is explicit, and nothing
/// address-shaped hides inside.
fn assertPersistable(comptime T: type, comptime path: []const u8) void {
    switch (@typeInfo(T)) {
        .int => if (T == usize or T == isize) @compileError(path ++
            ": pointer-sized integer in a persistent format — spell the width (u64)"),
        .float => {},
        .array => |a| assertPersistable(a.child, path ++ "[i]"),
        .@"struct" => |s| switch (s.layout) {
            .auto => @compileError(path ++
                ": auto struct layout is not ABI-stable and these bytes outlive the binary — use extern struct"),
            .@"extern" => {
                comptime var expect: usize = 0;
                inline for (s.fields) |f| {
                    if (@offsetOf(T, f.name) != expect) @compileError(path ++ "." ++ f.name ++
                        ": implicit padding before this field — torn padding bytes make checksums lie; pad explicitly with [N]u8");
                    assertPersistable(f.type, path ++ "." ++ f.name);
                    expect = @offsetOf(T, f.name) + @sizeOf(f.type);
                }
                if (expect != @sizeOf(T)) @compileError(path ++
                    ": implicit trailing padding — pad explicitly with [N]u8");
            },
            .@"packed" => {
                if (@bitSizeOf(T) != 8 * @sizeOf(T)) @compileError(path ++
                    ": packed struct has padding bits (@bitSizeOf < 8*@sizeOf) — undefined padding makes persisted bytes non-deterministic and byte checksums lie; pad to whole bytes");
                inline for (s.fields) |f| {
                    assertPersistable(f.type, path ++ "." ++ f.name);
                }
            },
        },
        .pointer => @compileError(path ++
            ": pointer in a persistent format — a virtual address does not survive reboot"),
        .bool, .@"enum" => @compileError(path ++
            ": has invalid bit patterns, so loading a torn write is undefined behavior — store an explicit-width integer and convert with checked casts"),
        .optional => @compileError(path ++
            ": optional layout is not ABI-stable — encode absence as an explicit field"),
        .@"union" => @compileError(path ++
            ": a union hides which arm was live from crash recovery — store an integer tag + extern payload"),
        else => @compileError(path ++ ": " ++ @typeName(T) ++ " cannot live in persistent memory"),
    }
}

/// FNV-1a over the recursive layout of T — container kinds, field names,
/// offsets, widths. Two types agree iff the same bytes mean the same thing,
/// so a locked layoutId is a compile-time regression test for an on-pmem
/// format.
const FNV1A_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
const FNV1A_PRIME: u64 = 0x100000001b3;

fn layoutId(comptime T: type) u64 {
    return comptime layoutFold(T, FNV1A_OFFSET_BASIS);
}

fn layoutFold(comptime T: type, comptime h: u64) u64 {
    switch (@typeInfo(T)) {
        .int, .float => return fnv1a(h, @typeName(T)),
        .array => |a| return layoutFold(a.child, fnv1a(h, std.fmt.comptimePrint("[{d}]", .{a.len}))),
        .@"struct" => |s| {
            comptime var x = fnv1a(h, if (s.layout == .@"packed") "packed{" else "extern{");
            inline for (s.fields) |f| {
                const off = if (s.layout == .@"packed") @bitOffsetOf(T, f.name) else @offsetOf(T, f.name);
                x = layoutFold(f.type, fnv1a(x, std.fmt.comptimePrint("{s}@{d};", .{ f.name, off })));
            }
            return fnv1a(x, "}");
        },
        else => unreachable, // assertPersistable admits nothing else
    }
}

fn fnv1a(comptime h: u64, comptime s: []const u8) u64 {
    comptime var x = h;
    inline for (s) |b| {
        x ^= b;
        x *%= FNV1A_PRIME;
    }
    return x;
}

/// Typed handle to a T at a fixed byte offset of the pmem region.
/// Instantiating Persistent(T) is itself the proof that T is persistable;
/// map() adds the runtime proof that the window exists. store() is durable
/// on return. The raw region pointer never escapes the handle, so the
/// store-without-flush bug class does not compile here — byte-granular
/// callers (/dev/pmem0, DAX mmap) keep using readAt/writeAt/ptr().
pub fn Persistent(comptime T: type) type {
    assertPersistable(T, @typeName(T));
    if (@sizeOf(T) == 0) @compileError(@typeName(T) ++ ": zero-size type — nothing to persist");
    return struct {
        window: [*]volatile u8, // region + off, established by map()
        off: u64, // byte offset in the region — persistRange speaks offsets

        const Self = @This();

        /// Bind byte offset `off` of the region to a T. Null when no NVDIMM
        /// is present, [off, off+@sizeOf(T)) overruns the region, or the
        /// mapped address misaligns T. The caller owns exclusion of the
        /// window, same contract as readAt/writeAt.
        pub fn map(off: u64) ?Self {
            if (!present) return null;
            if (off > len_bytes or len_bytes - off < @sizeOf(T)) return null;
            const delta: usize = @intCast(off);
            // Stricter than the bytewise load/store need — kept so the handle
            // stays sound if a raw *T view is ever exposed later.
            if ((@intFromPtr(region) + delta) % @alignOf(T) != 0) return null;
            return .{ .window = region + delta, .off = off };
        }

        /// Snapshot the persistent value into a kernel local. Sound even
        /// against a torn prior store: every bit pattern of a persistable T
        /// is a valid T (assertPersistable's admission rule).
        pub fn load(self: Self) T {
            var v: T = undefined;
            const dst: [*]u8 = @ptrCast(&v);
            var i: usize = 0;
            while (i < @sizeOf(T)) : (i += 1) dst[i] = self.window[i];
            return v;
        }

        /// Write `v` through to the region and push it to the persistence
        /// domain — durable on return. The only mutator on the handle.
        pub fn store(self: Self, v: T) void {
            const src: [*]const u8 = @ptrCast(&v);
            var i: usize = 0;
            while (i < @sizeOf(T)) : (i += 1) self.window[i] = src[i];
            persistRange(self.off, @sizeOf(T));
        }
    };
}

// --- N2: boot-survival self-test -------------------------------------------
//
// Keep a small header at offset 0: a magic, a monotonic boot counter, and an
// integrity word. The very first boot finds no magic (blank region) and stamps
// boot #1; every later boot finds the magic, bumps the counter, and reports how
// many reboots the data has survived. Re-running the VM bumps the counter every
// time — the proof that the file-backed region truly persists. (Torn-write
// safety across an unclean crash is N4's job; a clean QEMU exit flushes the
// whole mapping, so the counter is consistent here.)

const PMEM_MAGIC: u64 = 0x314D454D5047495A; // bytes "ZIGPMEM1" in memory order
const PMEM_CHECK_SALT: u64 = 0x9E3779B97F4A7C15;

const Header = extern struct {
    magic: u64,
    boot_count: u64,
    check: u64, // = magic ^ boot_count ^ salt — rejects a blank/torn header
};

/// Locked layout fingerprint of the on-pmem Header. If editing Header fires
/// the assert below, the new binary would misread regions the old one wrote:
/// bump PMEM_MAGIC (old headers then read as blank instead of as garbage),
/// paste the new id from the error message, and re-lock.
const HEADER_LAYOUT_ID: u64 = 0x5f1186780d92b64d;

comptime {
    // Validate first so an unsupported field type reports its field path here
    // instead of tripping layoutFold's unreachable.
    assertPersistable(Header, @typeName(Header));
    const got = layoutId(Header);
    if (got != HEADER_LAYOUT_ID) @compileError(std.fmt.comptimePrint(
        "on-pmem Header layout changed: layoutId 0x{x} != locked 0x{x} — bump PMEM_MAGIC and re-lock",
        .{ got, HEADER_LAYOUT_ID },
    ));
}

var boot_seq: u64 = 0;

/// Boot counter recovered/written by the last persistence self-test (0 if no
/// NVDIMM, or before init()).
pub fn bootCount() u64 {
    return boot_seq;
}

/// Which write-back instruction the persistence primitives use ("clwb" /
/// "clflushopt" / "clflush").
pub fn flushName() []const u8 {
    return @tagName(flush_kind);
}

fn headerValid(h: Header) bool {
    return h.magic == PMEM_MAGIC and h.check == (h.magic ^ h.boot_count ^ PMEM_CHECK_SALT);
}

/// Read the persistent boot counter, bump it, write it back durably, and log
/// the survival count. Run once at boot after the region is mapped. This is
/// Persistent(T)'s reference consumer: the store is durable by construction,
/// not because anyone remembered persistRange.
fn persistenceSelfTest() void {
    const hdr = Persistent(Header).map(0) orelse return;
    const cur = hdr.load();

    var next: Header = undefined;
    if (headerValid(cur)) {
        next.boot_count = cur.boot_count + 1;
        debug.klog("[pmem] persistence: signature valid — boot #{d} (survived {d} reboot(s))\n", .{
            next.boot_count, next.boot_count - 1,
        });
    } else {
        next.boot_count = 1;
        debug.klog("[pmem] persistence: no signature — fresh region, boot #1\n", .{});
    }
    next.magic = PMEM_MAGIC;
    next.check = next.magic ^ next.boot_count ^ PMEM_CHECK_SALT;

    hdr.store(next);
    boot_seq = next.boot_count;

    debug.klog("[pmem] persistence: header committed via {s}+sfence (counter now {d})\n", .{
        flushName(), next.boot_count,
    });
}

/// Discover + map the persistent-memory region. Called once at boot, right
/// after acpi.init (which parses the NFIT and builds the AML namespace).
pub fn init() void {
    const range = acpi.firstPmemRange() orelse {
        if (acpi.hasNfit())
            debug.klog("[pmem] NFIT present but no persistent-memory SPA range\n", .{})
        else
            debug.klog("[pmem] no NFIT — no NVDIMM present\n", .{});
        return;
    };
    base_phys = range.base;
    len_bytes = range.length;

    // Real, file-backed DRAM: keep it write-back cacheable and reach it through
    // the physmap. mapWBRange is a no-op while [base, base+len) is inside the
    // boot-mapped window, and extends the physmap if firmware ever places it
    // above PHYSMAP_SIZE.
    paging.mapWBRange(@intCast(base_phys), @intCast(len_bytes));
    region = @ptrFromInt(paging.physToVirt(base_phys));
    present = true;
    detectFlush();

    // These frames sit above PMM-managed RAM. Once DAX mmap maps them into a
    // user AS, teardown will freeFrame each present leaf — register the window
    // so the PMM treats those frees as expected no-ops instead of warnings.
    pmm.registerDeviceRange(@intCast(base_phys), @intCast(len_bytes));

    debug.klog("[pmem] NFIT: persistent-memory SPA range base=0x{x} len=0x{x} ({d} MiB)\n", .{
        base_phys, len_bytes, len_bytes / (1024 * 1024),
    });

    // Touch the first bytes to prove the mapping is live + show current content
    // (zeros on a fresh pmem.img, a saved signature once N2 writes one).
    debug.klog("[pmem] mapped @ VA 0x{x}; first 16 bytes:", .{@intFromPtr(region)});
    var i: usize = 0;
    while (i < 16 and i < len_bytes) : (i += 1) debug.klog(" {x:0>2}", .{region[i]});
    debug.klog("\n", .{});

    // AML-side discovery: confirm the firmware's dynamic NVDIMM interface, which
    // later slices drive to call _FIT (re-read the NFIT) and _DSM (health /
    // labels) over the QEMU DSM mailbox.
    if (aml.nvdimmInfo()) |nv| {
        debug.klog("[pmem] AML: NVDIMM root '{s}' (_HID ACPI0012); methods present: _FIT={s} _DSM={s} NCAL={s}\n", .{
            nv.path,
            if (nv.has_fit) "yes" else "no",
            if (nv.has_dsm) "yes" else "no",
            if (nv.has_ncal) "yes" else "no",
        });
        // N5/A5: actually EXECUTE the firmware control interface. _FIT drives the
        // QEMU DSM mailbox end-to-end — it calls _DSM/NCAL internally, which
        // marshals a request into the NRAM mailbox buffer (a SystemMemory region
        // the firmware based at the patched MEMA address), pokes the NTFI I/O port
        // to hand off to QEMU, and reads the wide response back — then returns the
        // live NFIT as a buffer. Cross-checking its PM range against the static
        // NFIT oracle proves the whole dynamic AML path works against real
        // firmware, not just discovery.
        if (nv.has_fit) fitCrossCheck(nv.path);

        // Labels (the AML "finish"): drive the per-NVDIMM `_DSM` label functions
        // over the same DSM mailbox `_FIT` rides — proving the interpreter works
        // the mailbox for functions beyond FIT, not just FIT discovery.
        dsmLabelProbe(nv.path);
    } else {
        debug.klog("[pmem] AML: no ACPI0012 NVDIMM root device found in namespace\n", .{});
    }

    // N2: prove the region survives reboots — read/bump/persist a boot counter
    // kept in the region itself. Runs after the first-bytes dump above, so that
    // dump shows the PRIOR boot's persisted header before we increment it.
    persistenceSelfTest();
}

/// A5: execute the firmware's `_FIT` control method and cross-check the
/// persistent-memory range it reports against the static NFIT oracle
/// (acpi.firstPmemRange). `_FIT` runs the full DSM-mailbox round-trip in AML —
/// request marshaling, NTFI hand-off, wide response read — so agreement proves
/// the dynamic path works end-to-end against real firmware. Every step logs, so a
/// partial result (mailbox inactive, executor stopped early, empty range) is
/// legible in the boot log rather than a silent nothing.
fn fitCrossCheck(dev_path: []const u8) void {
    var path_buf: [160]u8 = undefined;
    if (dev_path.len + 5 > path_buf.len) return;
    @memcpy(path_buf[0..dev_path.len], dev_path);
    @memcpy(path_buf[dev_path.len..][0..5], "._FIT");
    const path = path_buf[0 .. dev_path.len + 5];

    const ret = aml.evalMethod(path) orelse {
        debug.klog("[pmem] AML _FIT: did not evaluate (mailbox path inactive)\n", .{});
        return;
    };
    const fit = aml.asBuffer(ret) orelse {
        debug.klog("[pmem] AML _FIT: returned a non-buffer (executor stopped early)\n", .{});
        return;
    };
    debug.klog("[pmem] AML _FIT: returned {d} bytes\n", .{fit.len});

    const dyn = acpi.pmemRangeFromFitBuffer(fit) orelse {
        debug.klog("[pmem] AML _FIT: no PM SPA range parsed from the returned buffer\n", .{});
        return;
    };
    const stat = acpi.firstPmemRange() orelse {
        debug.klog("[pmem] AML _FIT: dynamic base=0x{x} len=0x{x} (no static NFIT to compare)\n", .{ dyn.base, dyn.length });
        return;
    };
    const match = dyn.base == stat.base and dyn.length == stat.length;
    debug.klog("[pmem] AML _FIT vs static NFIT: dyn[base=0x{x} len=0x{x}] static[base=0x{x} len=0x{x}] => {s}\n", .{
        dyn.base, dyn.length, stat.base, stat.length, if (match) "MATCH" else "MISMATCH",
    });
}

// === labels: per-NVDIMM _DSM (driving the DSM mailbox beyond _FIT) ===========

// NVDIMM _DSM interface UUIDs in ACPI ToUUID() mixed-endian byte order (first
// three fields little-endian, last two as written). The per-device label
// functions dispatch on the device UUID; the root _FIT/query uses the root UUID.
const NVDIMM_ROOT_UUID = [16]u8{ // 2F10E7A4-9E91-11E4-89D3-123B93F75CBA
    0xA4, 0xE7, 0x10, 0x2F, 0x91, 0x9E, 0xE4, 0x11,
    0x89, 0xD3, 0x12, 0x3B, 0x93, 0xF7, 0x5C, 0xBA,
};
const NVDIMM_DEV_UUID = [16]u8{ // 4309AC30-0D11-11E4-9191-0800200C9A66
    0x30, 0xAC, 0x09, 0x43, 0x11, 0x0D, 0xE4, 0x11,
    0x91, 0x91, 0x08, 0x00, 0x20, 0x0C, 0x9A, 0x66,
};

fn le32(b: []const u8, off: usize) u32 {
    if (off + 4 > b.len) return 0;
    return @as(u32, b[off]) | (@as(u32, b[off + 1]) << 8) |
        (@as(u32, b[off + 2]) << 16) | (@as(u32, b[off + 3]) << 24);
}

fn dumpHex(label: []const u8, b: []const u8, max: usize) void {
    debug.klog("{s}", .{label});
    var i: usize = 0;
    while (i < b.len and i < max) : (i += 1) debug.klog(" {x:0>2}", .{b[i]});
    if (b.len > max) debug.klog(" … ({d} bytes)", .{b.len});
    debug.klog("\n", .{});
}

/// Labels (the AML "finish"): exercise the per-NVDIMM `_DSM` label functions over
/// the same DSM mailbox `_FIT` rides, proving the interpreter drives the mailbox
/// for functions beyond FIT discovery. Enumerates the child NVDIMM device,
/// queries its supported functions, then reads the Namespace Label Storage Area
/// size and cross-checks it against the launcher's configured `label-size`. Every
/// step logs; a not-supported result (no label-size configured) stays legible.
fn dsmLabelProbe(root_path: []const u8) void {
    const dev = aml.nvdimmFirstDevice(root_path) orelse {
        debug.klog("[pmem] AML _DSM labels: no child NVDIMM device exposes _DSM under '{s}'\n", .{root_path});
        return;
    };
    debug.klog("[pmem] AML _DSM labels: child NVDIMM device '{s}'\n", .{dev});

    // Function 0 (query) — supported-function bitmap. No input; proves the 4-arg
    // _DSM path + device-UUID dispatch even before labels are configured.
    if (aml.callDsm(dev, &NVDIMM_DEV_UUID, 1, 0, null)) |q| {
        if (aml.asBuffer(q)) |qb| {
            dumpHex("[pmem] AML _DSM query (func0):", qb, 16);
        } else debug.klog("[pmem] AML _DSM query (func0): non-buffer result\n", .{});
    } else debug.klog("[pmem] AML _DSM query (func0): did not evaluate\n", .{});

    // Function 4 (Get Namespace Label Size) — output [status u32][size u32][max_xfer u32].
    const expect: u32 = 2 * 1024 * 1024; // launcher label-size=2M
    var labels_ok = false;
    if (aml.callDsm(dev, &NVDIMM_DEV_UUID, 1, 4, null)) |r| {
        if (aml.asBuffer(r)) |rb| {
            dumpHex("[pmem] AML _DSM GetLabelSize (func4):", rb, 16);
            if (rb.len >= 8) {
                const status = le32(rb, 0);
                const lsize = le32(rb, 4);
                labels_ok = status == 0 and lsize == expect;
                debug.klog("[pmem] AML _DSM label area: status={d} size={d} ({d} KiB) vs expected {d} => {s}\n", .{
                    status, lsize, lsize / 1024, expect,
                    if (labels_ok) "MATCH" else "MISMATCH",
                });
            }
        } else debug.klog("[pmem] AML _DSM GetLabelSize: non-buffer result\n", .{});
    } else debug.klog("[pmem] AML _DSM GetLabelSize: did not evaluate\n", .{});

    // Functions 5/6: the label-data round trip + cross-reboot persistence proof.
    if (labels_ok) dsmLabelRoundTrip(dev);
}

const LBL_MAGIC = [8]u8{ 'Z', 'I', 'G', 'L', 'B', 'L', '0', '1' }; // signature at LSA offset 0

fn writeLe32(b: []u8, off: usize, v: u32) void {
    b[off] = @truncate(v);
    b[off + 1] = @truncate(v >> 8);
    b[off + 2] = @truncate(v >> 16);
    b[off + 3] = @truncate(v >> 24);
}

fn bytesEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var i: usize = 0;
    while (i < a.len) : (i += 1) if (a[i] != b[i]) return false;
    return true;
}

/// The label-data round trip + persistence proof (M-C/M-D): read the Label
/// Storage Area via `_DSM` func 5, write a signature record via func 6, read it
/// back to confirm the in-boot round trip, and — across reboots — detect a prior
/// boot's signature to prove it persisted. Label data moves ONLY through the DSM
/// mailbox (not the mmap'd SPA), so this drives the bidirectional mailbox end to
/// end with real INPUT marshaling (offset/length, then offset/length/data). The
/// signature is raw scratch at LSA offset 0 — we deliberately don't write a real
/// namespace label (the index-block format is a separate concern); the point is
/// the data path, not namespace management.
fn dsmLabelRoundTrip(dev: []const u8) void {
    const REC = 12; // 8-byte magic + u32 write counter

    // --- M-C: Get Label Data (func 5), offset 0, REC bytes → [status u32][data REC] ---
    var in5: [8]u8 = undefined; // {offset u32, length u32}
    writeLe32(&in5, 0, 0);
    writeLe32(&in5, 4, REC);
    var prior: u32 = 0;
    var persisted = false;
    if (aml.callDsm(dev, &NVDIMM_DEV_UUID, 1, 5, &in5)) |r| {
        if (aml.asBuffer(r)) |rb| {
            dumpHex("[pmem] AML _DSM GetLabelData (func5) @0:", rb, 4 + REC);
            if (rb.len >= 4 + REC and le32(rb, 0) == 0 and bytesEql(rb[4 .. 4 + 8], &LBL_MAGIC)) {
                prior = le32(rb, 4 + 8);
                persisted = true;
            }
        } else debug.klog("[pmem] AML _DSM GetLabelData: non-buffer result\n", .{});
    } else debug.klog("[pmem] AML _DSM GetLabelData: did not evaluate\n", .{});
    if (persisted) {
        debug.klog("[pmem] AML _DSM labels: signature PERSISTED across reboot — prior write #{d}\n", .{prior});
    } else {
        debug.klog("[pmem] AML _DSM labels: no prior signature (fresh LSA)\n", .{});
    }

    // --- M-D: Set Label Data (func 6) — write magic + incremented counter ---
    const next = prior + 1;
    var in6: [8 + REC]u8 = undefined; // {offset u32, length u32, data[REC]}
    writeLe32(&in6, 0, 0);
    writeLe32(&in6, 4, REC);
    @memcpy(in6[8 .. 8 + 8], &LBL_MAGIC);
    writeLe32(&in6, 8 + 8, next);
    if (aml.callDsm(dev, &NVDIMM_DEV_UUID, 1, 6, &in6)) |w| {
        var st6: u32 = 0xffffffff;
        if (aml.asBuffer(w)) |wb| {
            if (wb.len >= 4) st6 = le32(wb, 0);
        }
        debug.klog("[pmem] AML _DSM SetLabelData (func6): status={d} (wrote signature #{d})\n", .{ st6, next });
    } else debug.klog("[pmem] AML _DSM SetLabelData: did not evaluate\n", .{});

    // --- verify the write in-boot: read back, expect magic + next ---
    if (aml.callDsm(dev, &NVDIMM_DEV_UUID, 1, 5, &in5)) |r2| {
        if (aml.asBuffer(r2)) |rb2| {
            const ok = rb2.len >= 4 + REC and le32(rb2, 0) == 0 and
                bytesEql(rb2[4 .. 4 + 8], &LBL_MAGIC) and le32(rb2, 4 + 8) == next;
            if (ok) {
                debug.klog("[pmem] AML _DSM labels: in-boot read-back OK (signature #{d}) => ROUND-TRIP\n", .{next});
            } else dumpHex("[pmem] AML _DSM labels: read-back MISMATCH:", rb2, 4 + REC);
        }
    }
}
