const std = @import("std");
const vga = @import("../ui/vga.zig");
const process = @import("process.zig");
const gdt = @import("../cpu/arch/gdt.zig");
const debug = @import("../debug/debug.zig");
const vmm = @import("../mm/vmm.zig");
const pmm = @import("../mm/pmm.zig");
const paging = @import("../mm/paging.zig");
const Phys = @import("../util/addr.zig").Phys;
const symbols = @import("../debug/symbols.zig");
const memmap = @import("../mm/memmap.zig");
const heap = @import("../mm/heap.zig");
const vfs = @import("../fs/vfs.zig");
const ext2 = @import("../fs/ext2/ext2.zig");
const ext2_inode = @import("../fs/ext2/inode.zig");
const config = @import("../config.zig");

/// Optional launch descriptor handed to loadAndStart so it can set the new
/// process's name + real argv BEFORE building a Linux binary's SysV initial
/// stack (which reads pcb.name/argv for argv[0..argc]). Callers that launch
/// by name only (desktop, smp, boot) pass null; a Linux binary launched that
/// way gets the "prog" argv[0] fallback.
pub const LaunchInfo = struct {
    /// Clean program name with the `.elf` extension stripped → pcb.name + argv[0].
    name: []const u8,
    /// Full exec string ("prog.elf arg1 arg2") for splitting argv[1..].
    raw: []const u8,
    /// Index in `raw` where the filename ends (the first space, or raw.len).
    fname_len: usize,
    /// When true, loadAndStart leaves the PCB in .loading instead of flipping
    /// it .ready — the caller (sysExec/sysExecAs) still has parent→child
    /// inheritance (fd 0/1/2, cwd, pgid/sid, nice/pin) and fd remaps to apply,
    /// and an AP's pickNext must not dispatch the child until those are done.
    /// The caller releases via process.assignInitialCpu + setState(.ready),
    /// in that order (rqEnter must land on the right per-CPU runqueue).
    start_held: bool = false,
    /// Absolute path of the executable → pcb.exe_path (/proc/self/exe).
    /// spawnPath fills it in.
    exe_path: []const u8 = "",
    /// A Linux execve: the image is Linux whatever its EI_OSABI says, and
    /// its stack gets these argv and envp.
    exec_args: ?*const ExecArgs = null,
};

/// argv and envp strings of a Linux execve: each NUL-terminated, argv's
/// first, back to back.
pub const ExecArgs = struct {
    strings: []const u8,
    argc: u32,
    envc: u32,
};

const Header = extern struct {
    ident: [16]u8,
    type: u16,
    machine: u16,
    version: u32,
    entry: u64,
    phoff: u64,
    shoff: u64,
    flags: u32,
    ehsize: u16,
    phentsize: u16,
    phnum: u16,
    shentsize: u16,
    shnum: u16,
    shstrndx: u16,
};

// ELF64 program header: note p_flags is second field (after p_type)
const ProgramHeader = extern struct {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
};

const PAGE_SIZE: usize = 4096;

// Apps link at USER_VA_FLOOR (app/linker.ld); any ELF segment below that is
// suspicious — almost always means someone tried to launch kernel.elf or a
// UEFI binary from the file browser. A Linux image has its stack at the top
// of the window, not under the load base, and may start at the window's
// bottom: 0x400000 is where ld puts an x86-64 executable that isn't PIE.
fn isUserVA(addr: usize, size: usize, linux: bool) bool {
    return if (linux) memmap.userDataRangeOk(addr, size) else memmap.userCodeRangeOk(addr, size);
}

const ELFOSABI_LINUX: u8 = 3;
const ET_DYN: u16 = 3;

/// Where a Linux program built to run at any address (ET_DYN) goes: above
/// what a fixed image and its break reach, below where mmap starts placing.
const PIE_BASE: usize = 0x55_5555_4000;
/// Most alignment a loadable segment may ask for.
const MAX_SEG_ALIGN: u64 = 1 << 30;

/// The pages an image's PT_LOADs cover before any move, and the largest
/// alignment they ask for.
const Extent = struct { lo: usize, hi: usize, al: usize };

/// Null if there is no PT_LOAD, one ends past the user window, or one asks
/// for an alignment that isn't a power of two up to MAX_SEG_ALIGN.
fn extentOf(phdrs: [*]align(1) const ProgramHeader, phnum: u16) ?Extent {
    var lo: usize = std.math.maxInt(usize);
    var hi: usize = 0;
    var al: usize = PAGE_SIZE;
    for (0..phnum) |i| {
        const ph = phdrs[i];
        if (ph.p_type != PT_LOAD_T) continue;
        if (ph.p_align > MAX_SEG_ALIGN or (ph.p_align > 1 and !std.math.isPowerOfTwo(ph.p_align))) return null;
        const end = std.math.add(u64, ph.p_vaddr, ph.p_memsz) catch return null;
        if (end > memmap.USER_SPACE_END) return null;
        lo = @min(lo, pageDown(@intCast(ph.p_vaddr)));
        hi = @max(hi, @as(usize, @intCast(end)));
        al = @max(al, @as(usize, @intCast(ph.p_align)));
    }
    if (hi == 0) return null;
    return .{ .lo = lo, .hi = pageUp(hi), .al = al };
}

/// How far the program's segments move: nothing for a fixed-address image,
/// to PIE_BASE for a position-independent Linux one. A multiple of the
/// largest alignment, so every segment keeps its own.
fn programBias(header: Header, ext: Extent, linux: bool) usize {
    if (header.type != ET_DYN or !linux) return 0;
    return std.mem.alignForward(usize, PIE_BASE, ext.al);
}

/// Where a new process's break and stack go.
const Layout = struct {
    linux: bool,
    brk: usize,
    stack_base: usize,
    stack_top: usize,
};

/// Check every PT_LOAD against the user window and lay the process out
/// around the image. The break starts at the page after the highest segment
/// (native: not below USER_BRK_INITIAL). A native stack is the reserve under
/// the load base; a Linux stack is the top LINUX_STACK_RESERVE of the window.
/// The image is Linux if its EI_OSABI says so or `linux` is set; its
/// segments move by `bias`. Null if a segment is out of range.
fn layoutFor(header: Header, phdrs: [*]align(1) const ProgramHeader, linux: bool, bias: usize) ?Layout {
    const is_linux = linux or header.ident[7] == ELFOSABI_LINUX;
    var end: usize = 0;
    for (0..header.phnum) |i| {
        if (phdrs[i].p_type != PT_LOAD_T) continue;
        const p_vaddr: usize = std.math.add(usize, @intCast(phdrs[i].p_vaddr), bias) catch {
            debug.klog("[elf] Rejected: segment 0x{X} moved by 0x{X} wraps\n", .{ phdrs[i].p_vaddr, bias });
            return null;
        };
        const p_memsz: usize = @intCast(phdrs[i].p_memsz);
        if (!isUserVA(p_vaddr, p_memsz, is_linux)) {
            debug.klog("[elf] Rejected: segment 0x{X}+{d} outside user VA\n", .{ p_vaddr, p_memsz });
            return null;
        }
        end = @max(end, p_vaddr + p_memsz);
    }
    const image_end = (end + PAGE_SIZE - 1) & ~@as(usize, PAGE_SIZE - 1);
    if (is_linux) {
        const stack_base: usize = memmap.USER_SPACE_END - memmap.LINUX_STACK_RESERVE;
        if (image_end > stack_base) {
            debug.klog("[elf] Rejected: image ends at 0x{X}, in the stack region\n", .{image_end});
            return null;
        }
        return .{ .linux = true, .brk = image_end, .stack_base = stack_base, .stack_top = memmap.USER_SPACE_END };
    }
    // Native syscalls carry addresses as u32.
    if (image_end > memmap.NATIVE_SPACE_END) {
        debug.klog("[elf] Rejected: native image ends at 0x{X}, above 0x{X}\n", .{ image_end, memmap.NATIVE_SPACE_END });
        return null;
    }
    return .{
        .linux = false,
        .brk = @max(memmap.USER_BRK_INITIAL, image_end),
        .stack_base = memmap.USER_SPACE_START,
        .stack_top = memmap.USER_VA_FLOOR,
    };
}

// (PerCpuRspSlot + per_cpu_rsp_save removed. The Linux-style switchTo
// primitive saves each task's RSP into its own pcb.kernel_esp; dying-task
// callers go to a per-CPU dead_letter_kesp. No shared longjmp anchor.)

/// Allocate a per-process kernel-side ELF buffer (PMM-allocated contiguous
/// frames in the lower-4GB identity-mapped range) and copy `file_size` bytes
/// from `staging` into it. Returns null if PMM has no contiguous chunk that
/// big. Caller stores the pointer in pcb.elf_buf for later free.
const ElfBuf = struct { buf: [*]u8, pages: u32 };

fn allocAndCopyElfBuf(staging: [*]const u8, file_size: usize) ?ElfBuf {
    const pages: u32 = @intCast((file_size + PAGE_SIZE - 1) / PAGE_SIZE);
    const phys = pmm.allocContiguous(pages) orelse {
        debug.klog("[elf] allocContiguous({d} pages) failed\n", .{pages});
        return null;
    };
    // Reach the PMM frame through the kernel physmap.
    const buf = phys.toVirt().ptr([*]u8);
    @memcpy(buf[0..file_size], staging[0..file_size]);
    return .{ .buf = buf, .pages = pages };
}

fn freePmmRange(base_va: usize, pages: u32) void {
    // Callers pass @intFromPtr(elf_buf) — a kernel physmap VA (elf_buf is the
    // physToVirt of a PMM frame; see allocAndCopyElfBuf / vfs.loadFileFresh).
    // freeContiguous speaks phys, so translate — exactly as lifecycle.freeElfBuf
    // does. (Pre-3e this passed the VA straight through; only rare error paths
    // ever hit it, so freeContiguous's bad-range reject silently leaked. Slice
    // 3e's success-path elf_buf drop fires it on every DROPPED load and surfaced
    // it: a [pmm] WARNING + ~1 MB leaked per exec.)
    const phys = paging.virtToPhys(base_va) orelse {
        debug.klog("[elf] freePmmRange: virtToPhys(0x{X:0>16}) failed — leaking {d} pages\n", .{ base_va, pages });
        return;
    };
    pmm.freeContiguous(Phys.of(phys), pages);
}

/// Register a lazy region for a single PT_LOAD segment, sourced from elf_buf.
/// Pages in [seg_start_aligned, seg_end_aligned) get allocated on first touch;
/// the page-fault handler copies file-backed bytes from elf_buf and zero-fills
/// the rest (BSS portion + alignment padding).
fn registerSegmentLazy(
    pid: usize,
    elf_buf: [*]const u8,
    p_vaddr: usize,
    p_memsz: usize,
    p_filesz: usize,
    p_offset: usize,
) bool {
    const seg_start = p_vaddr & ~@as(usize, PAGE_SIZE - 1);
    const seg_end = (p_vaddr + p_memsz + PAGE_SIZE - 1) & ~@as(usize, PAGE_SIZE - 1);
    return process.addLazyRegionWithSource(
        pid,
        seg_start,
        seg_end,
        0,
        elf_buf,
        p_vaddr,
        p_filesz,
        p_offset,
    );
}

// ELF program-header flag bits.
const PF_X: u32 = 0x1;
const PF_W: u32 = 0x2;
// PF_R = 0x4 — always set for loadable segments; PROT_READ has no PTE bit.

/// Translate a PT_LOAD's p_flags into our PROT_* bitmask (always readable;
/// writable iff PF_W; executable iff PF_X). Used for cache-shared segments so
/// `cacheMapFlags` produces the right RO / RX / NX mapping.
fn segProt(p_flags: u32) u8 {
    var prot: u8 = process.PROT_READ;
    if (p_flags & PF_W != 0) prot |= process.PROT_WRITE;
    if (p_flags & PF_X != 0) prot |= process.PROT_EXEC;
    return prot;
}

/// Register every PT_LOAD segment's lazy region (Slice 3e), choosing per segment:
///   * pure BSS (p_filesz==0)           → anonymous zero-fill (no source), the
///                                         same path the stack uses.
///   * read-only, file==mem, page-      → the unified page cache: the segment's
///     congruent, on ext2 (inode!=0)      frames are SHARED across every process
///                                         running this binary; a stray write
///                                         COW-diverges into a private copy.
///   * everything else (RW init data,   → a private copy demand-paged from
///     or a non-qualifying RO segment)    elf_buf (the legacy path).
/// Returns whether ANY segment still needs elf_buf (so the caller knows whether
/// to retain it or free it after symbol parsing), or null if a region couldn't
/// be registered or a segment's VA is out of user range (caller kills the proc).
/// The segments move by `bias` (layoutFor checked the moved ranges).
fn registerSegments(pid: usize, elf_buf: [*]const u8, phoff: usize, phnum: u16, inode: u32, bias: usize) ?bool {
    const phdrs: [*]align(1) const ProgramHeader = @ptrCast(elf_buf + phoff);
    var needs_elf_buf = false;
    var n_cache: u32 = 0;
    var n_anon: u32 = 0;
    var n_priv: u32 = 0;
    for (0..phnum) |i| {
        if (phdrs[i].p_type != 1) continue; // PT_LOAD
        const p_vaddr: usize = @as(usize, @intCast(phdrs[i].p_vaddr)) + bias;
        const p_memsz: usize = @intCast(phdrs[i].p_memsz);
        const p_filesz: usize = @intCast(phdrs[i].p_filesz);
        const p_offset: usize = @intCast(phdrs[i].p_offset);
        const p_flags = phdrs[i].p_flags;
        // layoutFor held each segment to its personality's window already.
        if (!memmap.userDataRangeOk(p_vaddr, p_memsz)) {
            debug.klog("[elf] segment 0x{X}+{d} outside user VA\n", .{ p_vaddr, p_memsz });
            return null;
        }
        const seg_start = p_vaddr & ~@as(usize, PAGE_SIZE - 1);
        const seg_end = (p_vaddr + p_memsz + PAGE_SIZE - 1) & ~@as(usize, PAGE_SIZE - 1);

        if (p_filesz == 0) {
            // Pure BSS: anonymous zero-fill — no file content, never needs elf_buf.
            if (!process.addLazyRegion(pid, seg_start, seg_end, 0)) return null;
            n_anon += 1;
        } else if (inode != 0 and (p_flags & PF_W) == 0 and p_filesz == p_memsz and
            (p_offset & (PAGE_SIZE - 1)) == (p_vaddr & (PAGE_SIZE - 1)))
        {
            // Read-only, fully file-backed, page-congruent, on ext2: share via
            // the unified page cache. cache_off is the file offset of the page-
            // aligned segment start (congruence guarantees off & ~0xFFF lines up
            // with vaddr & ~0xFFF). Maps RO, executable iff PF_X; a write
            // COW-diverges (the cache's own ref keeps refcount>=2, so the shared
            // frame is copied, never stolen).
            if (!process.addRegion(pid, .{
                .start = seg_start,
                .end = seg_end,
                .cache_inode = inode,
                .cache_off = p_offset & ~@as(usize, PAGE_SIZE - 1),
                .prot = segProt(p_flags),
            })) return null;
            n_cache += 1;
        } else {
            // RW initialized data (+maybe a BSS tail), or a non-qualifying RO
            // segment (filesz!=memsz, not page-congruent, or non-ext2 boot):
            // keep the private elf_buf-sourced copy.
            if (!registerSegmentLazy(pid, elf_buf, p_vaddr, p_memsz, p_filesz, p_offset)) return null;
            needs_elf_buf = true;
            n_priv += 1;
        }
    }
    debug.klog("[elf] pid={d} inode={d}: segs cache={d} anon={d} priv={d} elf_buf={s}\n", .{
        pid, inode, n_cache, n_anon, n_priv, if (needs_elf_buf) "kept" else "DROPPED",
    });
    return needs_elf_buf;
}

inline fn pageDown(v: usize) usize {
    return v & ~@as(usize, PAGE_SIZE - 1);
}

inline fn pageUp(v: usize) usize {
    return (v + PAGE_SIZE - 1) & ~@as(usize, PAGE_SIZE - 1);
}

/// File bytes in frames of their own, for a region that owns them.
const Owned = struct { buf: [*]u8, pages: u16 };

/// `len` bytes of the file at `off`, zero-padded to whole pages. Null if
/// out of frames, too big for a region's buffer, or the read came up short.
fn readOwned(inum: u32, off: u64, len: usize) ?Owned {
    const n = (len + PAGE_SIZE - 1) / PAGE_SIZE;
    if (n == 0 or n > std.math.maxInt(u16)) return null;
    const phys = pmm.allocContiguousUser(@intCast(n)) orelse return null;
    const buf = phys.toVirt().ptr([*]u8);
    @memset(buf[0 .. n * PAGE_SIZE], 0);
    if (vfs.readThroughCache(inum, off, buf, @intCast(len)) != len) {
        pmm.releaseContiguous(phys, @intCast(n));
        return null;
    }
    return .{ .buf = buf, .pages = @intCast(n) };
}

/// Add `r`, sourced from `b`, which it then owns; `b` goes back if it
/// can't be added.
fn addOwned(pid: usize, r: process.LazyRegion, b: Owned) bool {
    var reg = r;
    reg.source = b.buf;
    reg.src_offset = 0;
    reg.buf_owned = true;
    reg.buf_pages = b.pages;
    if (process.addRegion(pid, reg)) return true;
    pmm.releaseContiguous(Phys.of(paging.virtToPhys(@intFromPtr(b.buf)).?), b.pages);
    return false;
}

/// Register one PT_LOAD of an ext2 image read through the page cache, as up
/// to three regions: the pages holding only file bytes map the cache
/// (shared until written), the page where the file bytes end and the bss
/// begins gets a private copy with a zero tail, and the bss pages after it
/// are anonymous. A segment whose file offset and address differ within a
/// page lines up with no cache page; its file bytes go to a buffer of its
/// own. Its ranges were checked by layoutFor and segmentsInFile.
fn registerCachedSegment(pid: usize, inum: u32, ph: ProgramHeader) bool {
    const vaddr: usize = @intCast(ph.p_vaddr);
    const memsz: usize = @intCast(ph.p_memsz);
    const filesz: usize = @intCast(ph.p_filesz);
    const off: u64 = ph.p_offset;
    const prot = segProt(ph.p_flags);
    const seg_start = pageDown(vaddr);
    const mem_end = pageUp(vaddr + memsz);

    if (filesz == 0) return process.addRegion(pid, .{ .start = seg_start, .end = mem_end, .prot = prot });
    if (off % PAGE_SIZE != vaddr % PAGE_SIZE) {
        const b = readOwned(inum, off, filesz) orelse return false;
        return addOwned(pid, .{ .start = seg_start, .end = mem_end, .src_va_base = vaddr, .src_size = filesz, .prot = prot }, b);
    }

    const file_end = vaddr + filesz;
    const start_off = off - (vaddr - seg_start); // file offset of seg_start
    // Without bss the last page maps whole, file bytes past the segment
    // included, as on Linux; with bss that page's tail must read zero.
    const cache_end = if (memsz > filesz) pageDown(file_end) else pageUp(file_end);
    if (cache_end > seg_start and !process.addRegion(pid, .{
        .start = seg_start,
        .end = cache_end,
        .cache_inode = inum,
        .cache_off = start_off,
        .prot = prot,
    })) return false;

    var next = cache_end;
    if (memsz > filesz and file_end % PAGE_SIZE != 0) {
        const page = pageDown(file_end);
        const b = readOwned(inum, start_off + (page - seg_start), file_end - page) orelse return false;
        if (!addOwned(pid, .{ .start = page, .end = page + PAGE_SIZE, .src_va_base = page, .src_size = file_end - page, .prot = prot }, b)) return false;
        next = page + PAGE_SIZE;
    }
    if (mem_end > next and !process.addRegion(pid, .{ .start = next, .end = mem_end, .prot = prot })) return false;
    return true;
}

/// The segments move by `bias`; their moved ranges were checked.
fn registerCachedSegments(pid: usize, inum: u32, phdrs: [*]align(1) const ProgramHeader, phnum: u16, bias: usize) bool {
    var n: u32 = 0;
    for (0..phnum) |i| {
        var ph = phdrs[i];
        if (ph.p_type != PT_LOAD_T) continue;
        ph.p_vaddr += bias;
        if (!registerCachedSegment(pid, inum, ph)) return false;
        n += 1;
    }
    debug.klog("[elf] pid={d} inode={d}: {d} segments through the page cache, at +0x{X}\n", .{ pid, inum, n, bias });
    return true;
}

// --- Linux personality: SysV initial process stack ---------------------------
// A Linux x86-64 `_start` reads argc/argv/envp/auxv off the stack (RSP → argc)
// and sets up TLS from the auxiliary vector — none of which the native zigos
// path provides (native argv arrives via syscalls). For a .linux process we
// eagerly map the top stack page, lay down the SysV block there, and point the
// task's first-dispatch RSP at argc. The whole block is ~300 bytes, so one
// eager page suffices; the rest of the stack stays lazy. That page is a normal
// private anon frame — destroyAddressSpace reclaims it on exit like any other.

// Linux auxv tags (the subset we populate).
const AT_NULL: u64 = 0;
const AT_PHDR: u64 = 3;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;
const AT_PAGESZ: u64 = 6;
const AT_BASE: u64 = 7;
const AT_FLAGS: u64 = 8;
const AT_ENTRY: u64 = 9;
const AT_PLATFORM: u64 = 15;
const AT_HWCAP2: u64 = 26;
const AT_EXECFN: u64 = 31;
const AT_UID: u64 = 11;
const AT_EUID: u64 = 12;
const AT_GID: u64 = 13;
const AT_EGID: u64 = 14;
const AT_HWCAP: u64 = 16;
const AT_CLKTCK: u64 = 17;
const AT_SECURE: u64 = 23;
const AT_RANDOM: u64 = 25;

const PT_LOAD_T: u32 = 1;
const PT_INTERP_T: u32 = 3;
const PT_PHDR_T: u32 = 6;

/// What the auxiliary vector tells a Linux program of its image.
const Aux = struct {
    /// Where its program headers lie in its memory.
    phdr: u64,
    phnum: u16,
    /// Its own entry, wherever execution starts.
    entry: u64,
    /// How far its interpreter was moved; 0 without one.
    base: u64 = 0,
};

/// Where the program headers lie in the image's memory: PT_PHDR says, else
/// the PT_LOAD whose file bytes hold them; 0 if none does.
fn phdrAddr(phdrs: [*]align(1) const ProgramHeader, phnum: u16, phoff: u64, bias: usize) u64 {
    for (0..phnum) |i| {
        if (phdrs[i].p_type == PT_PHDR_T) return phdrs[i].p_vaddr +% bias;
    }
    for (0..phnum) |i| {
        const ph = phdrs[i];
        if (ph.p_type == PT_LOAD_T and phoff >= ph.p_offset and phoff - ph.p_offset < ph.p_filesz)
            return ph.p_vaddr +% (phoff - ph.p_offset) +% bias;
    }
    return 0;
}

const PLATFORM = "x86_64";

/// The environment every Linux process starts with (nothing passes one in
/// yet). HOME is where programs keep caches and dotfiles.
const LINUX_ENV = [_][]const u8{ "HOME=/", "PATH=/bin" };

inline fn rdtsc() u64 {
    var lo: u32 = undefined;
    var hi: u32 = undefined;
    asm volatile ("rdtsc"
        : [lo] "={eax}" (lo),
          [hi] "={edx}" (hi),
    );
    return (@as(u64, hi) << 32) | lo;
}

/// Most bytes the SysV block (strings, pointers, auxv) may take.
const MAX_INITIAL_STACK: usize = 128 * 1024;

/// A launch's argv (pcb.argv, else "prog") and the default environment, as
/// ExecArgs packed into `buf`.
fn launchArgs(pid: usize, buf: []u8) ExecArgs {
    const pcb = process.getPCB(pid);
    var n: usize = 0;
    const argc: usize = @min(@as(usize, pcb.argc), @as(usize, config.MAX_ARGS));
    for (0..argc) |ai| {
        const alen: usize = @min(@as(usize, pcb.arg_lens[ai]), @as(usize, config.MAX_ARG_LEN));
        @memcpy(buf[n..][0..alen], pcb.argv[ai][0..alen]);
        buf[n + alen] = 0;
        n += alen + 1;
    }
    if (argc == 0) {
        @memcpy(buf[0..5], "prog\x00");
        n = 5;
    }
    for (LINUX_ENV) |s| {
        @memcpy(buf[n..][0..s.len], s);
        buf[n + s.len] = 0;
        n += s.len + 1;
    }
    return .{ .strings = buf[0..n], .argc = @intCast(@max(argc, 1)), .envc = LINUX_ENV.len };
}

const LAUNCH_ARGS_BYTES = blk: {
    var n: usize = @as(usize, config.MAX_ARGS) * (@as(usize, config.MAX_ARG_LEN) + 1) + 5;
    for (LINUX_ENV) |s| n += s.len + 1;
    break :blk n;
};

/// Build the SysV initial stack for a .linux process and point its first-
/// dispatch RSP at argc. `pd` is the new address space, `stack_top` the
/// page-aligned top of the user stack region, `aux` what the auxiliary
/// vector says of the image, `exec_args` an execve's argv and envp (null:
/// the launch's). The block takes as many pages below the top as it needs.
/// Returns false if they couldn't be mapped (caller kills it).
fn setupLinuxInitialStack(
    pid: usize,
    pd: [*]align(4096) u64,
    stack_top: usize,
    aux: Aux,
    exec_args: ?*const ExecArgs,
) bool {
    var own: [LAUNCH_ARGS_BYTES]u8 = undefined;
    const args: ExecArgs = if (exec_args) |a| a.* else launchArgs(pid, &own);
    // AT_EXECFN: the path the program was started by; argv[0] if none.
    const pcb = process.getPCB(pid);
    const execfn = if (pcb.exe_path_len != 0) pcb.exe_path[0..pcb.exe_path_len] else std.mem.sliceTo(args.strings, 0);

    // The block, top down: the program's path and the platform name, 16
    // random bytes, the strings, then
    // argc | argv[0..argc] | NULL | envp | NULL | auxv with &argc 16-aligned.
    // Built in a kernel buffer standing for the pages below stack_top, then
    // copied into fresh frames mapped there RW/NX, as the lazy stack-fault
    // path would map them (protToMapFlags(R|W)).
    const AUXV_PAIRS = 19;
    const words: usize = 1 + (args.argc + 1) + (args.envc + 1) + AUXV_PAIRS * 2;
    const total = (execfn.len + 1) + (PLATFORM.len + 1) + 16 + args.strings.len + words * 8 + 16;
    if (total > MAX_INITIAL_STACK) {
        debug.klog("[linux] pid={d}: argv and envp take {d} bytes, past {d}\n", .{ pid, total, MAX_INITIAL_STACK });
        return false;
    }
    const span = std.mem.alignForward(usize, total, PAGE_SIZE);
    const page_base: usize = stack_top - span;
    const kbuf = heap.kmallocAligned(span, 16) orelse return false;
    defer heap.kfree(kbuf);
    @memset(kbuf[0..span], 0);

    var off: usize = span;

    off -= execfn.len + 1;
    @memcpy(kbuf[off..][0..execfn.len], execfn);
    const execfn_va: u64 = page_base + off;
    off -= PLATFORM.len + 1;
    @memcpy(kbuf[off..][0..PLATFORM.len], PLATFORM);
    const platform_va: u64 = page_base + off;

    // 16 random bytes for AT_RANDOM (musl seeds its stack canary from these).
    // rdtsc-derived — not cryptographic, but canary strength isn't an M1 goal;
    // what matters is the pointer is valid and the bytes vary per launch.
    off -= 16;
    const rand_off = off;
    {
        const r0 = rdtsc() ^ (@as(u64, pid) << 40);
        const r1 = (rdtsc() << 1) ^ 0x9E3779B97F4A7C15;
        var k: usize = 0;
        while (k < 8) : (k += 1) {
            kbuf[rand_off + k] = @truncate(r0 >> @intCast(k * 8));
            kbuf[rand_off + 8 + k] = @truncate(r1 >> @intCast(k * 8));
        }
    }
    const rand_va: u64 = page_base + rand_off;

    off -= args.strings.len;
    @memcpy(kbuf[off..][0..args.strings.len], args.strings);
    const strings_off = off;

    // Auxiliary vector — (type,value) pairs, AT_NULL-terminated.
    const auxv = [AUXV_PAIRS][2]u64{
        .{ AT_PHDR, aux.phdr },
        .{ AT_PHENT, @sizeOf(ProgramHeader) },
        .{ AT_PHNUM, aux.phnum },
        .{ AT_PAGESZ, PAGE_SIZE },
        .{ AT_BASE, aux.base },
        .{ AT_FLAGS, 0 },
        .{ AT_ENTRY, aux.entry },
        .{ AT_RANDOM, rand_va },
        .{ AT_EXECFN, execfn_va },
        .{ AT_PLATFORM, platform_va },
        .{ AT_HWCAP2, 0 },
        .{ AT_UID, 0 },
        .{ AT_EUID, 0 },
        .{ AT_GID, 0 },
        .{ AT_EGID, 0 },
        .{ AT_SECURE, 0 },
        .{ AT_CLKTCK, 100 },
        .{ AT_HWCAP, 0 },
        .{ AT_NULL, 0 },
    };

    var block_off: usize = off - words * 8;
    block_off &= ~@as(usize, 0xF); // &argc must be 16-byte aligned at _start
    const argc_va: u64 = page_base + block_off;

    const wp: [*]align(1) u64 = @ptrFromInt(@intFromPtr(kbuf) + block_off);
    var w: usize = 0;
    wp[w] = args.argc; w += 1;
    // The pointers walk the strings: argc of them, a NULL, envc, a NULL.
    var s: usize = 0;
    for (0..args.argc + args.envc) |k| {
        if (k == args.argc) {
            wp[w] = 0; w += 1; // argv terminator
        }
        wp[w] = page_base + strings_off + s; w += 1;
        s += (std.mem.indexOfScalarPos(u8, args.strings, s, 0) orelse args.strings.len) - s + 1;
    }
    if (args.envc == 0) {
        wp[w] = 0; w += 1; // argv terminator
    }
    wp[w] = 0; w += 1; // envp terminator
    for (auxv) |pair| {
        wp[w] = pair[0]; w += 1;
        wp[w] = pair[1]; w += 1;
    }

    const flags = vmm.protToMapFlags(process.PROT_READ | process.PROT_WRITE);
    var p: usize = 0;
    while (p < span / PAGE_SIZE) : (p += 1) {
        const frame = vmm.allocAndMapUserPage(pd, page_base + p * PAGE_SIZE, flags) catch {
            debug.klog("[linux] setupLinuxInitialStack: map of stack page {d} failed\n", .{p});
            return false;
        };
        @memcpy(frame.toVirt().ptr([*]u8)[0..PAGE_SIZE], kbuf[p * PAGE_SIZE ..][0..PAGE_SIZE]);
    }

    // Point the task's first-dispatch RSP at argc (overriding create()'s native
    // (16-aligned − 8) value). The slot index comes from the dispatch
    // contract (frames.dispatch) — this used to be a hand-counted
    // "frame[18] is RSP, 20 qwords below the top".
    const fspec = @import("frames.zig").dispatch;
    const iretf: [*]u64 = @ptrFromInt(process.procs[pid].kernel_stack_top - fspec.pt_regs_bytes);
    iretf[fspec.iretq.rsp.at()] = argc_va;

    const argv0_log = std.mem.sliceTo(args.strings, 0);
    debug.klog("[linux] pid={d} SysV stack: rsp=0x{X} argc={d} envc={d} argv0='{s}' phdr=0x{X} phnum={d} entry=0x{X} base=0x{X}\n", .{
        pid, argc_va, args.argc, args.envc, argv0_log, aux.phdr, aux.phnum, aux.entry, aux.base,
    });
    return true;
}

/// Start the program at `path`. An ext2 file is mapped through the page
/// cache, only its headers read up front; anything else (tarfs, fat32) is
/// read whole first. Same contract as loadAndStart.
pub fn spawnPath(path: []const u8, launch: ?LaunchInfo) ?usize {
    var exe_buf: [255]u8 = undefined;
    var li = launch;
    if (li) |*l| l.exe_path = exePath(path, &exe_buf);
    if (vfs.lookupCached(path)) |f| return loadCached(f.inum, f.size, li);
    const fresh = vfs.loadFileFresh(path) orelse return null;
    return loadAndStart(fresh.buf, fresh.size, fresh.pages, fresh.inode, li);
}

/// A Linux execve's new image from ext2 inode `inum`: a process built and
/// held in .loading, never dispatched, whose address space the caller takes
/// over (lifecycle.takeExecImage). `launch.exec_args` must be set. Null if
/// the file isn't an image we can run, or memory ran out.
pub fn loadForExec(inum: u32, size: u64, launch: LaunchInfo) ?usize {
    var li = launch;
    li.start_held = true;
    return loadCached(inum, size, li);
}

/// The absolute path `name` names, as vfs.lookupCached resolves it: as
/// given when absolute, else under the root, else under /bin. Empty when it
/// doesn't fit `buf`.
fn exePath(name: []const u8, buf: *[255]u8) []const u8 {
    if (name.len > 0 and name[0] == '/') return name;
    const dir: []const u8 = if (ext2.lookupFile(name) != null) "/" else "/bin/";
    if (dir.len + name.len > buf.len) return "";
    @memcpy(buf[0..dir.len], dir);
    @memcpy(buf[dir.len..][0..name.len], name);
    return buf[0 .. dir.len + name.len];
}

/// Load an ELF and create the process, but don't enter user mode.
/// Returns PID or null. Used by the desktop for multitasking.
///
/// `elf_buf` ownership is transferred to this function. On success, the
/// buffer is stashed in `pcb.elf_buf` and freed when the process exits.
/// On any failure path, this function frees `elf_buf` itself — the caller
/// must NOT touch it after the call.
pub fn loadAndStart(elf_buf: [*]align(4) u8, file_size: usize, elf_buf_pages: u32, inode: u32, launch: ?LaunchInfo) ?usize {
    debug.klog("[elf] Loading ELF64 binary...\n", .{});
    const img: Image = .{ .buffer = .{ .buf = elf_buf, .size = file_size, .pages = elf_buf_pages, .inode = inode } };
    const header = @as([*]align(1) const Header, @ptrCast(elf_buf))[0];
    if (file_size < @sizeOf(Header) or !headerOk(header, file_size)) {
        // Diagnostic: dump first 32 bytes + parsed fields. The "Invalid"
        // condition is hit when DMA returned garbage (race on PRDT) — the
        // bytes show whether the buffer is zeros (DMA never wrote), stale
        // (cache coherence miss), or scrambled (interleaved with another
        // transfer).
        debug.klog("[elf] Invalid ELF64 header — file_size={d} elf_buf=0x{X:0>16}\n", .{ file_size, @intFromPtr(elf_buf) });
        debug.klog("[elf]   ident[0..4]: {X:0>2} {X:0>2} {X:0>2} {X:0>2}  (want: 7F 45 4C 46)\n", .{ header.ident[0], header.ident[1], header.ident[2], header.ident[3] });
        debug.klog("[elf]   ident[4]={d} (want 2 = ELF64), machine=0x{X} (want 0x3E = AMD64), phentsize={d} phoff=0x{X} phnum={d}\n", .{ header.ident[4], header.machine, header.phentsize, header.phoff, header.phnum });
        debug.klog("[elf]   First 32 bytes:", .{});
        for (0..@min(32, file_size)) |i| debug.klog(" {X:0>2}", .{elf_buf[i]});
        debug.klog("\n", .{});
        img.drop();
        return null;
    }
    return startImage(img, header, launch);
}

/// Most header bytes loadCached reads; the program headers must end within.
const MAX_HEADER_BYTES: usize = 64 * 1024;

/// loadAndStart for an ext2 file, mapped through the page cache: only the
/// ELF header and program headers are read here, segment pages on first
/// touch.
fn loadCached(inum: u32, size: u64, launch: ?LaunchInfo) ?usize {
    debug.klog("[elf] Loading ELF64 binary from inode {d} ({d} bytes) through the page cache\n", .{ inum, size });
    const h = readHeaders(inum, size) orelse return null;
    defer heap.kfree(h.hdr);
    return startImage(.{ .cached = .{ .inum = inum, .size = size, .hdr = h.hdr } }, h.header, launch);
}

/// An ext2 image's ELF header, and its first bytes through the program
/// headers in `hdr`, from the heap: the caller frees it.
const Headers = struct { header: Header, hdr: [*]align(8) u8 };

fn readHeaders(inum: u32, size: u64) ?Headers {
    var header: Header = undefined;
    const hb = std.mem.asBytes(&header);
    if (size < hb.len or vfs.readThroughCache(inum, 0, hb, hb.len) != hb.len or !headerOk(header, size)) {
        debug.klog("[elf] inode {d}: not an x86-64 ELF64 executable\n", .{inum});
        return null;
    }
    const hdr_len: usize = @intCast(@max(hb.len, header.phoff + @as(u64, header.phnum) * @sizeOf(ProgramHeader)));
    if (hdr_len > MAX_HEADER_BYTES) {
        debug.klog("[elf] inode {d}: program headers end at {d}, past {d}\n", .{ inum, hdr_len, MAX_HEADER_BYTES });
        return null;
    }
    const raw = heap.kmallocAligned(hdr_len, 8) orelse return null;
    const hdr: [*]align(8) u8 = @alignCast(raw);
    if (vfs.readThroughCache(inum, 0, hdr, @intCast(hdr_len)) != hdr_len) {
        heap.kfree(raw);
        return null;
    }
    // The header validated above, whatever the file holds now.
    @memcpy(hdr[0..hb.len], hb);
    return .{ .header = header, .hdr = hdr };
}

/// `out.len` bytes of the image from file offset `off`.
fn readAt(img: Image, off: u64, out: []u8) bool {
    const size = img.fileSize();
    if (off > size or out.len > size - off) return false;
    switch (img) {
        .buffer => |b| {
            @memcpy(out, b.buf[@intCast(off)..][0..out.len]);
            return true;
        },
        .cached => |c| return vfs.readThroughCache(c.inum, off, out.ptr, @intCast(out.len)) == out.len,
    }
}

// --- The interpreter of a dynamic program ------------------------------------
//
// A dynamically linked program names its interpreter, the dynamic linker
// (/lib/ld-musl-x86_64.so.1 for musl), in PT_INTERP. Both are mapped here and
// the interpreter starts; it finds the program through the auxiliary vector
// (AT_PHDR, AT_ENTRY, AT_BASE), maps its libraries with mmap and jumps to it.
// The interpreter goes where the first mmap would: at the top of the mmap
// area, below the program if the program is there.

/// Longest path PT_INTERP may give.
const INTERP_MAX: usize = 255;

const Interp = struct {
    inum: u32,
    header: Header,
    /// Its first bytes through the program headers, from the heap.
    hdr: [*]align(8) u8,
    /// How far its segments move: what AT_BASE tells (musl takes its own
    /// load bias from it).
    bias: usize,

    fn phdrs(self: *const Interp) [*]align(1) const ProgramHeader {
        return @ptrCast(self.hdr + @as(usize, @intCast(self.header.phoff)));
    }

    fn entry(self: *const Interp) usize {
        return @as(usize, @intCast(self.header.entry)) +% self.bias;
    }

    fn deinit(self: *const Interp) void {
        heap.kfree(self.hdr);
    }
};

const InterpRead = union(enum) { none, interp: Interp, fail };

fn hasInterp(phdrs: [*]align(1) const ProgramHeader, phnum: u16) bool {
    for (0..phnum) |i| {
        if (phdrs[i].p_type == PT_INTERP_T) return true;
    }
    return false;
}

/// The interpreter `img` names, read and placed clear of [prog_lo, prog_hi),
/// the program's pages. .none if it names none.
fn openInterp(img: Image, header: Header, linux: bool, prog_lo: usize, prog_hi: usize) InterpRead {
    const phdrs: [*]align(1) const ProgramHeader = @ptrCast(img.bytes() + @as(usize, @intCast(header.phoff)));
    const ph = for (0..header.phnum) |i| {
        if (phdrs[i].p_type == PT_INTERP_T) break phdrs[i];
    } else return .none;
    if (!linux) {
        debug.klog("[elf] Rejected: a native program with an interpreter\n", .{});
        return .fail;
    }
    var path_buf: [INTERP_MAX + 1]u8 = undefined;
    if (ph.p_filesz < 2 or ph.p_filesz > path_buf.len) {
        debug.klog("[elf] Rejected: an interpreter path of {d} bytes\n", .{ph.p_filesz});
        return .fail;
    }
    const len: usize = @intCast(ph.p_filesz);
    if (!readAt(img, ph.p_offset, path_buf[0..len]) or path_buf[len - 1] != 0) {
        debug.klog("[elf] Rejected: the interpreter path can't be read\n", .{});
        return .fail;
    }
    const path = std.mem.sliceTo(path_buf[0..len], 0);
    // Relative to nothing: a path of the loading task's would do, but no
    // toolchain writes one.
    if (path.len == 0 or path[0] != '/') {
        debug.klog("[elf] Rejected: interpreter '{s}' is not an absolute path\n", .{path});
        return .fail;
    }
    const pcb = process.currentPCB() orelse process.getPCB(0);
    var rbuf: [256]u8 = undefined;
    const r = vfs.resolvePath(pcb, path, &rbuf) orelse return interpMissing(path);
    if (r.fs != .ext2) return interpMissing(path);
    const inum = ext2.lookupPath(r.path) orelse return interpMissing(path);
    const ino = ext2_inode.readInode(inum) orelse return interpMissing(path);
    if (!ext2_inode.isReg(&ino)) return interpMissing(path);
    const size = ext2_inode.fileSize(&ino);

    const h = readHeaders(inum, size) orelse return .fail;
    var it = Interp{ .inum = inum, .header = h.header, .hdr = h.hdr, .bias = 0 };
    const iph = it.phdrs();
    const n = h.header.phnum;
    const usable = h.header.type == ET_DYN and segmentsInFile(iph, n, size) and !hasInterp(iph, n);
    const ext = (if (usable) extentOf(iph, n) else null) orelse {
        debug.klog("[elf] Rejected: interpreter '{s}' is not a position-independent image\n", .{path});
        it.deinit();
        return .fail;
    };
    // Its pages are [bias + lo, bias + hi), the bias a multiple of its
    // alignment: as high as fits under the mmap top, else under the program.
    var bias = std.mem.alignBackward(usize, memmap.LINUX_MMAP_TOP -| ext.hi, ext.al);
    if (bias + ext.lo < prog_hi and prog_lo < bias + ext.hi) bias = std.mem.alignBackward(usize, prog_lo -| ext.hi, ext.al);
    if (bias + ext.lo < memmap.USER_SPACE_START or (bias + ext.lo < prog_hi and prog_lo < bias + ext.hi)) {
        debug.klog("[elf] Rejected: no room for interpreter '{s}' ({d} bytes)\n", .{ path, ext.hi - ext.lo });
        it.deinit();
        return .fail;
    }
    it.bias = bias;
    if (!isUserVA(it.entry(), 1, true)) {
        debug.klog("[elf] Rejected: interpreter entry 0x{X} outside user VA\n", .{it.entry()});
        it.deinit();
        return .fail;
    }
    debug.klog("[elf] interpreter '{s}' (inode {d}) at 0x{X}\n", .{ path, inum, bias + ext.lo });
    return .{ .interp = it };
}

fn interpMissing(path: []const u8) InterpRead {
    debug.klog("[elf] Rejected: interpreter '{s}' is not a file on ext2\n", .{path});
    return .fail;
}

/// Where a new process's segments come from.
const Image = union(enum) {
    /// The whole file in a PMM buffer (tarfs, fat32, the desktop's async
    /// load). The process keeps it while a segment sources from it.
    buffer: struct { buf: [*]align(4) u8, size: usize, pages: u32, inode: u32 },
    /// An ext2 file read through the page cache. `hdr` holds its first
    /// bytes through the program headers; the caller frees it.
    cached: struct { inum: u32, size: u64, hdr: [*]align(8) const u8 },

    /// The file's first bytes: the ELF header and the program headers.
    fn bytes(self: Image) [*]align(4) const u8 {
        return switch (self) {
            .buffer => |b| b.buf,
            .cached => |c| c.hdr,
        };
    }

    fn fileSize(self: Image) u64 {
        return switch (self) {
            .buffer => |b| b.size,
            .cached => |c| c.size,
        };
    }

    fn inode(self: Image) u32 {
        return switch (self) {
            .buffer => |b| b.inode,
            .cached => |c| c.inum,
        };
    }

    /// Give back a buffer no process took.
    fn drop(self: Image) void {
        switch (self) {
            .buffer => |b| freePmmRange(@intFromPtr(b.buf), b.pages),
            .cached => {},
        }
    }
};

/// An x86-64 ELF64 whose program headers, of the size we index them at,
/// lie in the first `avail` bytes.
fn headerOk(header: Header, avail: u64) bool {
    if (!std.mem.eql(u8, header.ident[0..4], "\x7fELF") or header.ident[4] != 2 or header.machine != 0x3E) return false;
    if (header.phentsize != @sizeOf(ProgramHeader)) return false;
    const ph_len = @as(u64, header.phnum) * @sizeOf(ProgramHeader);
    return header.phoff <= avail and ph_len <= avail - header.phoff;
}

/// Every PT_LOAD's file bytes lie in the file and fit its memory size.
fn segmentsInFile(phdrs: [*]align(1) const ProgramHeader, phnum: u16, size: u64) bool {
    for (0..phnum) |i| {
        const ph = phdrs[i];
        if (ph.p_type != PT_LOAD_T) continue;
        if (ph.p_filesz > ph.p_memsz) return false;
        if (ph.p_offset > size or ph.p_filesz > size - ph.p_offset) return false;
    }
    return true;
}

/// The process for a validated header: address space, PCB, regions, the
/// Linux initial stack, symbols. Takes over `img`'s buffer either way.
fn startImage(img: Image, header: Header, launch: ?LaunchInfo) ?usize {
    const phoff: usize = @intCast(header.phoff);
    const phdrs: [*]align(1) const ProgramHeader = @ptrCast(img.bytes() + phoff);
    const exec_args = if (launch) |li| li.exec_args else null;
    const linux = exec_args != null or header.ident[7] == ELFOSABI_LINUX;

    if (!segmentsInFile(phdrs, header.phnum, img.fileSize())) {
        debug.klog("[elf] Rejected: a segment's file bytes lie outside the file\n", .{});
        img.drop();
        return null;
    }
    const ext = extentOf(phdrs, header.phnum) orelse {
        debug.klog("[elf] Rejected: no loadable segment, or one out of range or oddly aligned\n", .{});
        img.drop();
        return null;
    };
    const bias = programBias(header, ext, linux);
    const entry_addr: usize = @as(usize, @intCast(header.entry)) +% bias;
    if (!isUserVA(entry_addr, 1, linux)) {
        debug.klog("[elf] Rejected: entry 0x{X} outside user VA range\n", .{entry_addr});
        img.drop();
        return null;
    }

    // Validate every PT_LOAD's VA range fits in user space before doing
    // any per-segment work — bail early without partial state.
    const lay = layoutFor(header, phdrs, exec_args != null, bias) orelse {
        img.drop();
        return null;
    };

    const interp: ?Interp = switch (openInterp(img, header, linux, ext.lo + bias, ext.hi + bias)) {
        .none => null,
        .interp => |it| it,
        .fail => {
            img.drop();
            return null;
        },
    };
    defer if (interp) |*it| it.deinit();

    var pd_phys: Phys = Phys.of(0);
    const pd = vmm.createAddressSpace(&pd_phys) orelse {
        img.drop();
        return null;
    };

    // The user stack is a lazy region: pages back on first touch. A native
    // task starts just below its top; a Linux task's RSP is moved to the
    // SysV block by setupLinuxInitialStack. A dynamic program starts in its
    // interpreter.
    const start: usize = if (interp) |*it| it.entry() else entry_addr;
    const pid = process.create(start, lay.stack_top - 8) orelse {
        vmm.destroyAddressSpace(pd, pd_phys);
        img.drop();
        return null;
    };
    debug.klog("[elf] Process created PID={d} entry=0x{X:0>16}\n", .{ pid, start });

    // From here the PCB owns the address space and the buffer; a failure
    // tears the process down (abortLoading), which frees both.
    const pcb = process.getPCB(pid);
    pcb.page_directory = pd;
    pcb.page_dir_phys = pd_phys.raw();
    pcb.pcid = @import("../cpu/mmu/pcid.zig").alloc();
    switch (img) {
        .buffer => |b| {
            pcb.elf_buf = b.buf;
            pcb.elf_buf_pages = b.pages;
        },
        .cached => {},
    }
    pcb.stack_base = lay.stack_base;
    pcb.brk_base = lay.brk;
    pcb.user_brk = lay.brk;
    // Record the source inode for ETXTBSY: while this process is live, writes
    // and truncates of this same file are refused (process.isTextBusy). 0 for
    // tarfs/non-regular loads (inum is an ext2 identity); harmless there.
    pcb.text_inum = img.inode();
    // ABI personality: EI_OSABI (e_ident[7]) == ELFOSABI_LINUX (3) marks an
    // unmodified Linux x86-64 binary, so its `syscall`s route to the Linux
    // translation layer (syscall/linux.zig). Native zigos ELFs have OSABI 0.
    // One detection point here covers every launch path (shell/desktop/smp).
    // What a Linux process execs is Linux too (layoutFor): a binary built
    // here carries no OSABI stamp.
    pcb.personality = if (lay.linux) .linux else .native;

    // Set the process name + real argv from the launch descriptor (if any)
    // BEFORE setupLinuxInitialStack below reads them. The caller used to do
    // this AFTER loadAndStart returned, which left a Linux binary's argv as
    // the "prog" placeholder because the stack was already built. Native
    // processes read argv via syscalls, so the ordering only matters here.
    if (launch) |li| {
        process.setName(@intCast(pid), li.name);
        process.populateArgv(pcb, li.name, li.raw, li.fname_len);
        const n = @min(li.exe_path.len, pcb.exe_path.len);
        @memcpy(pcb.exe_path[0..n], li.exe_path[0..n]);
        pcb.exe_path_len = @intCast(n);
    }

    // Register lazy regions: the stack, then each PT_LOAD segment. The heap
    // is registered later by sbrk/brk.
    if (!process.addLazyRegion(pid, lay.stack_base, lay.stack_top, 0)) {
        debug.klog("[elf] Failed to register lazy stack region for PID {d}\n", .{pid});
        process.abortLoading(@intCast(pid));
        return null;
    }
    const needs_elf_buf: ?bool = switch (img) {
        .buffer => |b| registerSegments(pid, b.buf, phoff, header.phnum, b.inode, bias),
        .cached => |c| if (registerCachedSegments(pid, c.inum, phdrs, header.phnum, bias)) false else null,
    };
    const interp_ok = if (interp) |*it| registerCachedSegments(pid, it.inum, it.phdrs(), it.header.phnum, it.bias) else true;
    if (needs_elf_buf == null or !interp_ok) {
        debug.klog("[elf] segment registration failed for PID {d}\n", .{pid});
        process.abortLoading(@intCast(pid));
        return null;
    }

    // Linux personality: build the SysV initial stack (argc/argv/envp/auxv +
    // RSP). Native processes get argv via syscalls and skip this entirely.
    if (pcb.personality == .linux) {
        const aux = Aux{
            .phdr = phdrAddr(phdrs, header.phnum, header.phoff, bias),
            .phnum = header.phnum,
            .entry = entry_addr,
            .base = if (interp) |*it| it.bias else 0,
        };
        if (!setupLinuxInitialStack(pid, pd, lay.stack_top, aux, exec_args)) {
            debug.klog("[linux] initial-stack setup failed for PID {d}\n", .{pid});
            process.abortLoading(@intCast(pid));
            return null;
        }
    }

    // Debug symbols from the ELF section headers, where the image lies.
    pcb.sym_table = switch (img) {
        .buffer => |b| symbols.parseElfSymbols(b.buf, b.size),
        .cached => |c| symbols.parseElfSymbolsFile(c.inum, c.size, c.hdr[0..@sizeOf(Header)]),
    };
    if (bias != 0) if (pcb.sym_table) |st| {
        for (st.entries[0..st.count]) |*e| e.addr +%= bias;
    };

    // Slice 3e: if no segment is demand-paged from elf_buf (all are cache-shared
    // or pure-BSS anon), the per-process whole-file copy is dead weight — free it
    // now instead of holding it until exit. freeElfBuf is null-safe, so teardown
    // simply no-ops. Symbol parsing above already copied what it needs.
    if (!needs_elf_buf.?) {
        if (pcb.elf_buf) |buf| freePmmRange(@intFromPtr(buf), pcb.elf_buf_pages);
        pcb.elf_buf = null;
        pcb.elf_buf_pages = 0;
    }

    // Init complete — transition .loading → .ready. Until this store, an AP
    // sees the PCB as not-runnable. After this, pickNext can dispatch it
    // and the iretq will land on a fully-initialized address space + lazy
    // region table. assignInitialCpu BEFORE the state flip so the rqEnter
    // setState triggers lands on the right per-CPU runqueue.
    //
    // start_held callers keep the slot in .loading: sysExec used to flip the
    // child runnable HERE and then apply fd/cwd/pgid/nice inheritance after —
    // an idle AP could dispatch the child in that window and it would run
    // with console fds / wrong cwd / its own pgid (Ctrl+C miss).
    const hold = if (launch) |li| li.start_held else false;
    if (!hold) {
        process.assignInitialCpu(pid);
        process.setState(pid, .ready);
    }

    return pid;
}

pub fn loadAndExecute(elf_buf: [*]align(4) u8, file_size: usize, elf_buf_pages: u32, inode: u32) void {
    debug.klog("[elf] Loading ELF64 binary...\n", .{});
    const header = @as([*]align(1) const Header, @ptrCast(elf_buf))[0];
    const phoff: usize = @intCast(header.phoff);
    if (file_size < @sizeOf(Header) or !headerOk(header, file_size) or
        !segmentsInFile(@ptrCast(elf_buf + phoff), header.phnum, file_size))
    {
        vga.fg = .LightRed;
        vga.print("ELF Error!\n", .{});
        debug.klog("[elf] Invalid ELF64 header\n", .{});
        freePmmRange(@intFromPtr(elf_buf), elf_buf_pages);
        return;
    }

    const lay = layoutFor(header, @ptrCast(elf_buf + phoff), false, 0) orelse {
        vga.fg = .LightRed;
        vga.print("Error: segment outside user space!\n", .{});
        freePmmRange(@intFromPtr(elf_buf), elf_buf_pages);
        return;
    };

    // Create per-process address space
    var pd_phys: Phys = Phys.of(0);
    const pd = vmm.createAddressSpace(&pd_phys) orelse {
        vga.fg = .LightRed;
        vga.print("Error: cannot create address space!\n", .{});
        debug.klog("[elf] Failed to create address space\n", .{});
        freePmmRange(@intFromPtr(elf_buf), elf_buf_pages);
        return;
    };

    // Create process with fake interrupt frame
    const entry: usize = @intCast(header.entry);
    const pid = process.create(entry, lay.stack_top - 8) orelse {
        vga.fg = .LightRed;
        vga.print("Error: process table full!\n", .{});
        debug.klog("[elf] Process table full\n", .{});
        vmm.destroyAddressSpace(pd, pd_phys);
        freePmmRange(@intFromPtr(elf_buf), elf_buf_pages);
        return;
    };
    debug.klog("[elf] Process created PID={d} entry=0x{X:0>16}\n", .{ pid, header.entry });

    // Store address space + ELF buffer in PCB
    const pcb = process.getPCB(pid);
    pcb.page_directory = pd;
    pcb.page_dir_phys = pd_phys.raw();
    pcb.pcid = @import("../cpu/mmu/pcid.zig").alloc();
    pcb.elf_buf = elf_buf;
    pcb.elf_buf_pages = elf_buf_pages;
    pcb.stack_base = lay.stack_base;
    pcb.brk_base = lay.brk;
    pcb.user_brk = lay.brk;
    pcb.text_inum = inode; // ETXTBSY — see loadAndStart
    // ABI personality (see loadAndStart): Linux OSABI(3) → Linux syscall layer.
    pcb.personality = if (lay.linux) .linux else .native;

    if (!process.addLazyRegion(pid, lay.stack_base, lay.stack_top, 0)) {
        vga.fg = .LightRed;
        vga.print("Error: lazy stack region full!\n", .{});
        process.abortLoading(@intCast(pid));
        return;
    }

    const needs_elf_buf = registerSegments(pid, elf_buf, phoff, header.phnum, inode, 0) orelse {
        vga.fg = .LightRed;
        vga.print("Error: segment registration failed!\n", .{});
        process.abortLoading(@intCast(pid));
        return;
    };

    // Linux personality: build the SysV initial stack before any elf_buf drop
    // (see loadAndStart for the full rationale).
    if (pcb.personality == .linux) {
        const aux = Aux{
            .phdr = phdrAddr(@ptrCast(elf_buf + phoff), header.phnum, header.phoff, 0),
            .phnum = header.phnum,
            .entry = header.entry,
        };
        if (!setupLinuxInitialStack(pid, pd, lay.stack_top, aux, null)) {
            debug.klog("[linux] initial-stack setup failed for PID {d}\n", .{pid});
            process.abortLoading(@intCast(pid));
            return;
        }
    }

    // Parse debug symbols from ELF section headers (use kernel-side ELF buffer).
    pcb.sym_table = symbols.parseElfSymbols(elf_buf, file_size);

    // Slice 3e: drop the per-process whole-file copy if nothing sources from it
    // (all segments cache-shared or pure-BSS anon). See loadAndStart.
    if (!needs_elf_buf) {
        freePmmRange(@intFromPtr(elf_buf), elf_buf_pages);
        pcb.elf_buf = null;
        pcb.elf_buf_pages = 0;
    }

    // Init complete — flip .loading → .ready so an AP's pickNext can see it
    // (and so this CPU's later preemption-resume cycles work). loadAndExecute
    // dispatches synchronously below, but state must be at least .ready for
    // the post-preemption schedule path. assignInitialCpu first so the
    // setState rqEnter lands on the right rq.
    process.assignInitialCpu(pid);
    process.setState(pid, .ready);

    // Mark process as running and set TSS for initial launch
    process.setCurrent(pid);
    const proc_info = process.getProcessInfo(pid);
    gdt.setTssRsp0(pid, proc_info.kernel_stack_top);

    // Switch to the new address space (PCID-tagged so subsequent reloads
    // can preserve this process's TLB across context switches).
    @import("../cpu/mmu/pcid.zig").loadCr3(pd_phys.raw(), pcb.pcid, @import("../cpu/smp.zig").myCpu().cpu_id);

    debug.klog("[elf] Entering Ring 3\n", .{});
    // Synchronously wait for the loaded process to exit. schedule() may pick
    // OTHER tasks first; we loop until the one we just loaded actually dies.
    // (The legacy enterUserMode/returnToKernel pair returned at any sysExit
    // on this CPU's dispatch path, which had the same loose semantics; this
    // makes the wait explicit.)
    while (process.procs[pid].state != .zombie and process.procs[pid].state != .unused) {
        process.schedule();
        asm volatile ("sti");
    }
}

/// Copy data to pages mapped in a page directory.
/// Since physical frames are in identity-mapped PMM range, we write to physical addresses directly.
fn copyToMappedPages(pd: [*]align(4096) u64, virt_start: usize, src: [*]const u8, len: usize) void {
    var offset: usize = 0;
    while (offset < len) {
        const virt = virt_start + offset;
        const phys = resolvePhys(pd, virt) orelse return;
        const page_offset = virt & (PAGE_SIZE - 1);
        const chunk = @min(PAGE_SIZE - page_offset, len - offset);
        const dest: [*]u8 = @ptrFromInt(paging.physToVirt(phys + page_offset));
        @memcpy(dest[0..chunk], src[offset..][0..chunk]);
        offset += chunk;
    }
}

/// Zero pages mapped in a page directory.
fn zeroMappedPages(pd: [*]align(4096) u64, virt_start: usize, len: usize) void {
    var offset: usize = 0;
    while (offset < len) {
        const virt = virt_start + offset;
        const phys = resolvePhys(pd, virt) orelse return;
        const page_offset = virt & (PAGE_SIZE - 1);
        const chunk = @min(PAGE_SIZE - page_offset, len - offset);
        const dest: [*]u8 = @ptrFromInt(paging.physToVirt(phys + page_offset));
        @memset(dest[0..chunk], 0);
        offset += chunk;
    }
}

/// Resolve virtual address to physical address using 4-level page tables (PML4→PDPT→PD→PT).
pub fn resolvePhys(pml4: [*]align(4096) u64, virt: usize) ?usize {
    const MASK: u64 = 0x000FFFFFFFFFF000;
    const v: u64 = @intCast(virt);

    // PML4 → PDPT
    const pml4_idx = (v >> 39) & 0x1FF;
    const pml4e = pml4[pml4_idx];
    if (pml4e & 1 == 0) return null;
    const pdpt: [*]const u64 = @ptrFromInt(paging.physToVirt(pml4e & MASK));

    // PDPT → PD
    const pdpt_idx = (v >> 30) & 0x1FF;
    const pdpte = pdpt[pdpt_idx];
    if (pdpte & 1 == 0) return null;
    const pd: [*]const u64 = @ptrFromInt(paging.physToVirt(pdpte & MASK));

    // PD → PT (check for 2MB page)
    const pd_idx = (v >> 21) & 0x1FF;
    const pde = pd[pd_idx];
    if (pde & 1 == 0) return null;
    if (pde & 0x80 != 0) {
        // 2MB page
        return @intCast((pde & MASK) + (v & 0x1FFFFF));
    }
    const pt: [*]const u64 = @ptrFromInt(paging.physToVirt(pde & MASK));

    // PT → physical page
    const pt_idx = (v >> 12) & 0x1FF;
    const pte = pt[pt_idx];
    if (pte & 1 == 0) return null;
    return @intCast(pte & MASK);
}

// (enterUserMode / returnToKernel / returnToKernelHere removed.
// Replaced by sched_asm.zig's switchTo (kernel↔kernel context switch)
// and retToUserStub (single iretq site for new tasks). Dispatch sites
// now call process.schedule() directly.)
