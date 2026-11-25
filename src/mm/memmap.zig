// The kernel's memory map: the fixed virtual addresses (re-exported from
// layout.zig, which proves them disjoint at comptime) and the physical
// memory the kernel holds for its whole life.
//
// Physical memory is not laid out at build time: the firmware's memory map
// decides. The loader says where it put the image and what it keeps
// (BootInfo); `init` places the two graphics buffers in what is left, and
// `claim` places whatever else must exist before there is an allocator (the
// PMM's own tables). The PMM keeps off all of these:
//
//   below LOW_MEMORY_END  firmware data, the real-mode trampolines
//   held()                every range below, by name:
//     kernelImagePhys()   the image (.text, .rodata, .data, .bss)
//     bootData()          the loader's page tables, BootInfo, memory map
//     guestFb()           guest GPU framebuffer (GUEST_FB_SIZE)
//     backBuffer()        CPU back buffer for compositing (BACK_BUFFER_SIZE)
//     claim()ed blocks
//
// User space (per-process page tables): each process gets its own PML4[0]
// from createAddressSpace; user-app .text loads at USER_VA_FLOOR (matches
// app/linker.ld). A native user_brk starts at USER_BRK_INITIAL and grows to
// NATIVE_SPACE_END. Two distinct floors apply: native CODE validators
// (elf_loader's native segments, sysClone entry) floor at USER_VA_FLOOR
// because native code never lives below the load base; STACK/DATA validators
// (validateUserPtr, vmm.mapUserPage, signals frame validation, and kdbg
// ripIsValidUser, as Linux code may sit lower) MUST floor at USER_SPACE_START,
// since a native stack lives in [NATIVE_STACK_BOTTOM, USER_VA_FLOOR) and a
// Linux image may sit lower still. Conflating the two is the class of bug
// that broke Ctrl+C.

const std = @import("std");

/// VA-space model: typed addresses (Phys/KVa/UVa) + comptime-verified layout.
/// The VA constants below are *re-exported* from here (single source of truth);
/// see layout.zig for the two-floor rationale and the invariant proofs.
const layout = @import("layout.zig");
const protocol = @import("boot_protocol");

/// The first megabyte: firmware data and the real-mode trampolines. Never
/// the PMM's.
pub const LOW_MEMORY_END: usize = 0x100000;

/// A stretch of physical memory. The empty range overlaps and contains nothing.
pub const Range = struct {
    base: usize = 0,
    size: usize = 0,

    pub fn end(self: Range) usize {
        return self.base + self.size;
    }

    pub fn contains(self: Range, addr: usize) bool {
        return addr >= self.base and addr < self.end();
    }

    pub fn overlaps(self: Range, other: Range) bool {
        return self.size != 0 and other.size != 0 and self.base < other.end() and other.base < self.end();
    }
};

/// Higher-half kernel base — must match `KERNEL_VIRT_BASE` in src/linker.ld.
/// Kernel symbols (kmain, _kernel_end, &__kdata_protected_start, etc.) link
/// there; `paging.virtToPhys` turns one into a physical address.
pub const KERNEL_VIRT_BASE: usize = layout.KERNEL_VIRT_BASE;

/// Physmap base. Maps phys
/// 0..PHYSMAP_SIZE at VA `PHYSMAP_BASE..PHYSMAP_BASE+PHYSMAP_SIZE`. The
/// canonical "kernel can read/write any phys frame" view in Phase 2+. Use
/// `paging.physToVirt(p)` rather than the bare constant whenever possible.
///
/// Sized to cover the full 512 GB span addressable by one PML4 slot (one
/// 4 KB PDPT page = 512 × 1 GB entries). Smaller windows leave high-phys
/// MMIO BARs unmapped (e.g. xHCI BAR at ~481 GB under `-cpu host` with
/// 39-bit maxphyaddr) and the bare physToVirt() result page-faults.
/// Both loaders (src/boot/boot.asm, uefi/handoff.zig) build the window
/// from lib/boot_protocol.zig; the comptime block below holds these to it.
pub const PHYSMAP_BASE: usize = layout.PHYSMAP_BASE;
pub const PHYSMAP_SIZE: usize = layout.PHYSMAP_SIZE; // 512 GB (full PML4 slot)

// linker.ld: the image's first byte seen through the image window, and its end.
extern var __kernel_image_start: u8;
extern var _kernel_end: u8;

/// Virtual end of the kernel image (high half, what Zig sees).
pub fn kernelEnd() usize {
    return @intFromPtr(&_kernel_end);
}

/// physical = image address - KERNEL_VIRT_BASE + this.
pub inline fn imagePhysOffset() u64 {
    return layout.image_phys_offset;
}

/// The image in physical memory, low boot sections included.
pub fn kernelImagePhys() Range {
    const start = @intFromPtr(&__kernel_image_start);
    return .{
        .base = start - KERNEL_VIRT_BASE +% @as(usize, @intCast(imagePhysOffset())),
        .size = kernelEnd() - start,
    };
}

/// Where the loader put the image. Call first at entry: until then an image
/// address turns into the physical address it was linked for.
pub fn adoptImagePlacement(info: *const protocol.BootInfo) void {
    layout.image_phys_offset = info.kernel_phys_offset;
}

// --- Validator constant (matches user-app linker convention) ---
// The lowest legitimate user-mode VA. app/linker.ld pins user-app .text
// at 0x500000, so any saved RIP below this on iretq-to-user is wild
// (kdbg.validateUserReturnIretq), as is any sysExec entry below this
// (syscall.zig). USER_SPACE_START sits 64 KB lower to make room for the
// downward-growing user stack.
//
// Independent of the kernel image: user addresses are per-process VAs, the
// image is wherever the loader put it. Bumping this constant requires
// re-linking all user apps and is rarely the right move.
pub const USER_VA_FLOOR: usize = layout.USER_VA_FLOOR;

// --- Physical memory the kernel holds for its whole life ---

/// The scanout a virtio-gpu resource is backed by, and the buffer a GOP
/// console without a directly usable panel draws into. Contiguous: the
/// device takes it as one run of frames.
pub const GUEST_FB_SIZE: usize = protocol.MAX_FRAMEBUFFER_BYTES;
/// The compositor's CPU back buffer.
pub const BACK_BUFFER_SIZE: usize = protocol.MAX_FRAMEBUFFER_BYTES;

var boot_data: Range = .{};
var guest_fb: Range = .{};
var back_buffer: Range = .{};
/// The firmware's memory map as the loader handed it over. Empty before `init`.
var boot_map: []const protocol.MemoryRegion = &.{};

/// A range the kernel holds for its whole life, and what it is.
pub const Held = struct { name: []const u8, range: Range };

var held_table: [8]Held = undefined;
var held_count: usize = 0;

/// Every held range. Grows during single-threaded boot only.
pub fn held() []const Held {
    return held_table[0..held_count];
}

fn hold(name: []const u8, range: Range) void {
    if (range.size == 0) return;
    held_table[held_count] = .{ .name = name, .range = range };
    held_count += 1;
}

/// The loader's page tables, BootInfo and memory map. The kernel runs on
/// these tables for good; empty on Multiboot, where they are in the image.
pub fn bootData() Range {
    return boot_data;
}

/// The memory map the loader handed over. Empty before `init`.
pub fn bootMap() []const protocol.MemoryRegion {
    return boot_map;
}

/// Empty before `init`.
pub fn guestFb() Range {
    return guest_fb;
}

/// Empty before `init`.
pub fn backBuffer() Range {
    return back_buffer;
}

/// Records what the loader keeps and places the graphics buffers. Before
/// early_fb: a blitting GOP console draws into the guest framebuffer, long
/// before there is a PMM to ask.
pub fn init(info: *const protocol.BootInfo) void {
    // A loader may give the map as a low-identity pointer, and that window
    // goes (paging.dropLowIdentity); the physmap stays.
    const map_address = @intFromPtr(info.memory_map);
    const map: [*]const protocol.MemoryRegion = @ptrFromInt(if (map_address < PHYSMAP_BASE) PHYSMAP_BASE + map_address else map_address);
    boot_map = map[0..info.memory_map_count];

    boot_data = .{ .base = @intCast(info.boot_data_base), .size = @intCast(info.boot_data_size) };
    const image = kernelImagePhys();
    hold("kernel-image-phys", image);
    hold("boot_data", boot_data);
    guest_fb = claim("guest_fb", GUEST_FB_SIZE, .low) orelse
        @panic("memmap: no usable RAM for the guest framebuffer");
    back_buffer = claim("back_buffer", BACK_BUFFER_SIZE, .low) orelse
        @panic("memmap: no usable RAM for the back buffer");
    @import("../debug/serial.zig").print(
        "[memmap] image 0x{X}..0x{X} (link +0x{X}), boot data 0x{X}..0x{X}, guest fb 0x{X}, back buffer 0x{X}\n",
        .{ image.base, image.end(), imagePhysOffset(), boot_data.base, boot_data.end(), guest_fb.base, back_buffer.base },
    );
}

const PLACEMENT_ALIGN: usize = 0x200000;
/// What a 32-bit DMA address reaches.
pub const LOW_LIMIT: u64 = 0x1_0000_0000;

/// Where `claim` looks.
pub const Where = enum {
    /// Below LOW_LIMIT, lowest address first.
    low,
    /// Anywhere the physmap reaches, highest address first: out of the way
    /// of what must be low.
    high,
};

/// `size` bytes of usable RAM, clear of everything held so far, held from
/// now on. For what has to exist before the PMM does; boot only.
pub fn claim(name: []const u8, size: usize, where: Where) ?Range {
    const range = switch (where) {
        .low => placeLow(size),
        .high => placeHigh(size),
    } orelse return null;
    hold(name, range);
    return range;
}

/// Whether the firmware's map calls all of [base, base + size) usable RAM.
/// For what must sit at an address fixed in advance, such as a real-mode
/// trampoline: a page the firmware keeps for itself is not ours to write.
pub fn isUsableRam(base: usize, size: usize) bool {
    for (boot_map) |region| {
        if (region.kind == .usable and region.base <= base and base + size <= region.base +| region.length) return true;
    }
    return false;
}

/// First fit, lowest region first: `size` bytes of usable RAM between
/// LOW_MEMORY_END and LOW_LIMIT that touch nothing held.
fn placeLow(size: usize) ?Range {
    for (boot_map) |region| {
        if (region.kind != .usable or region.base >= LOW_LIMIT) continue;
        const region_end: u64 = @min(region.base +| region.length, LOW_LIMIT);
        var base: u64 = std.mem.alignForward(u64, @max(region.base, LOW_MEMORY_END), PLACEMENT_ALIGN);
        search: while (base +| size <= region_end) {
            const candidate: Range = .{ .base = @intCast(base), .size = size };
            for (held()) |h| {
                if (candidate.overlaps(h.range)) {
                    base = std.mem.alignForward(u64, h.range.end(), PLACEMENT_ALIGN);
                    continue :search;
                }
            }
            return candidate;
        }
    }
    return null;
}

/// The highest `size` bytes of usable RAM above LOW_MEMORY_END, below the
/// physmap's end, that touch nothing held.
fn placeHigh(size: usize) ?Range {
    var best: ?Range = null;
    for (boot_map) |region| {
        if (region.kind != .usable) continue;
        const floor: u64 = std.mem.alignForward(u64, @max(region.base, LOW_MEMORY_END), PLACEMENT_ALIGN);
        const region_end: u64 = @min(region.base +| region.length, PHYSMAP_SIZE);
        if (region_end < floor +| size) continue;
        var base: u64 = std.mem.alignBackward(u64, region_end - size, PLACEMENT_ALIGN);
        search: while (base >= floor) {
            const candidate: Range = .{ .base = @intCast(base), .size = size };
            for (held()) |h| {
                if (candidate.overlaps(h.range)) {
                    if (h.range.base < floor +| size) break :search;
                    base = std.mem.alignBackward(u64, h.range.base - size, PLACEMENT_ALIGN);
                    continue :search;
                }
            }
            if (best == null or candidate.base > best.?.base) best = candidate;
            break;
        }
    }
    return best;
}

// GUI framebuffers are PMM-allocated per window now (sysCreateWindow).
// Only the per-window size cap remains.
// 10 MB max per window. Initial allocations stay small (apps request their
// window size, still bounded by GUI_MAX_SIZE = 8 MB in sysCreateWindow); the
// extra headroom is for F10 grow-on-maximize (desktop.growGuiFb), which only
// the maximized window pays — a full 1920×1080 RGBA buffer is ~8.3 MB.
pub const GUI_FB_PER_PID_SIZE: usize = 0xA00000;

// --- User-space layout (per-process) ---
// A native stack takes [NATIVE_STACK_BOTTOM, USER_VA_FLOOR), just under the
// load base, inside the user window (USER_SPACE_START lies lower still, at
// Linux's mmap_min_addr). Without a mappable reserve there,
// mapUserPage silently rejects stack faults (virt < USER_SPACE_START), the
// PF handler thinks the lazy fault-in succeeded (mapUserPage is void), and
// the app spins re-faulting until OOM kills it (caught 2026-05-20 on
// Q1 with its 64-page stack — leaked 200 MB before OOM).
// MUST be >= elf_loader's `stack_pages * PAGE_SIZE`. The comptime
// assert in src/proc/elf_loader.zig keeps this in sync.
//
// 1 MB / 256 pages (2026-05-20): Quake1's R_EdgeDrawing overflowed the
// prior 64-page reservation by ~7 KB. Lazy-fault means unused pages
// cost zero PMM, so the reserve sets only the VA ceiling. Going higher
// (e.g. 4 MB) would push USER_SPACE_START into the kernel image's low
// PA range — stay at 1 MB until an app needs more and we restructure
// the low-VA layout.
pub const USER_STACK_RESERVE: u64 = layout.USER_STACK_RESERVE; // 256 pages = 1 MB
pub const USER_SPACE_START: u64 = layout.USER_SPACE_START;
pub const NATIVE_STACK_BOTTOM: u64 = layout.NATIVE_STACK_BOTTOM;
pub const USER_SPACE_END: u64 = layout.USER_SPACE_END; // 512 GB
pub const NATIVE_SPACE_END: u64 = layout.NATIVE_SPACE_END; // 256 MB
pub const LINUX_MMAP_TOP: u64 = layout.LINUX_MMAP_TOP;
pub const LINUX_MMAP_FLOOR: u64 = layout.LINUX_MMAP_FLOOR;
pub const LINUX_STACK_RESERVE: u64 = layout.LINUX_STACK_RESERVE;
// Initial native sbrk position (per-process VA). Lives in user low-half VA
// space, fully independent of kernel low-PA layout — kernel reaches its
// own heap through the high-half physmap (Phase 3 dropped PML4[0]), so
// a numeric collision between user-VA and kernel-PHYS is harmless.
// 0x2000000 (32 MB) gives apps a fresh upward range from a round
// boundary; well below NATIVE_SPACE_END (0x10000000 = 256 MB).
pub const USER_BRK_INITIAL: usize = layout.USER_BRK_INITIAL;

// VA classification + validator predicates + typed addresses, all defined and
// comptime-proven in layout.zig. Re-exported here so the 5 user-VA validators
// (kdbg.ripIsValidUser, common.validateUserPtr, vmm.mapUserPage,
// signals.validateUserRange, elf_loader.isUserVA) route through ONE exhaustive
// classifier instead of ad-hoc `if (va < FLOOR)` ladders — adding a region is a
// compile error until every validator re-decides where it belongs.
pub const AddrClass = layout.AddrClass;
pub const classify = layout.classify;
pub const isValidUserCode = layout.isValidUserCode;
pub const isUserDataAddr = layout.isUserDataAddr;
pub const userCodeRangeOk = layout.userCodeRangeOk;
pub const userDataRangeOk = layout.userDataRangeOk;
pub const Phys = layout.Phys;
pub const KVa = layout.KVa;
pub const UVa = layout.UVa;

comptime {
    // The loader builds the windows from boot_protocol.zig.
    if (layout.KERNEL_VIRT_BASE != protocol.KERNEL_VIRT_BASE or layout.PHYSMAP_BASE != protocol.PHYSMAP_BASE or
        layout.PHYSMAP_SIZE != protocol.PHYSMAP_SIZE)
    {
        @compileError("memmap: layout.zig and lib/boot_protocol.zig disagree on the kernel windows");
    }

    // User-space sanity.
    if (USER_BRK_INITIAL >= NATIVE_SPACE_END) {
        @compileError("USER_BRK_INITIAL beyond NATIVE_SPACE_END");
    }
    if (USER_BRK_INITIAL < USER_VA_FLOOR) {
        @compileError("USER_BRK_INITIAL must be at or above USER_VA_FLOOR");
    }
}
