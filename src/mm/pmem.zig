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
/// the survival count. Run once at boot after the region is mapped.
fn persistenceSelfTest() void {
    if (!present or len_bytes < @sizeOf(Header)) return;
    const h: *volatile Header = @ptrCast(@alignCast(region));

    // Volatile field reads — pull the prior boot's header out of pmem.
    const cur = Header{ .magic = h.magic, .boot_count = h.boot_count, .check = h.check };

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

    // Write the header back and push it to the persistence domain.
    h.magic = next.magic;
    h.boot_count = next.boot_count;
    h.check = next.check;
    persistRange(0, @sizeOf(Header));
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
    } else {
        debug.klog("[pmem] AML: no ACPI0012 NVDIMM root device found in namespace\n", .{});
    }

    // N2: prove the region survives reboots — read/bump/persist a boot counter
    // kept in the region itself. Runs after the first-bytes dump above, so that
    // dump shows the PRIOR boot's persisted header before we increment it.
    persistenceSelfTest();
}
