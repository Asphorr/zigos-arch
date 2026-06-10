//! Syscall handlers (gpu) — split out of syscall.zig (#797).
//! Dispatched from cpu/syscall.zig doSyscallInner; named in SYSCALLS.

const std = @import("std");
const vga = @import("../../ui/vga.zig");
const elf_loader = @import("../../proc/elf_loader.zig");
const keyboard = @import("../../driver/keyboard.zig");
const process = @import("../../proc/process.zig");
const vmm = @import("../../mm/vmm.zig");
const pmm = @import("../../mm/pmm.zig");
const paging = @import("../../mm/paging.zig");
const bga = @import("../../ui/bga.zig");
const vfs = @import("../../fs/vfs.zig");
const desktop = @import("../../ui/desktop.zig");
const xhci = @import("../../driver/xhci.zig");
const debug = @import("../../debug/debug.zig");
const perf = @import("../../debug/perf.zig");
const pipe = @import("../../proc/pipe.zig");
const memmap = @import("../../mm/memmap.zig");
const config = @import("../../config.zig");
const smp = @import("../smp.zig");
const signals = @import("../../proc/signals.zig");
const errno = @import("../../proc/errno.zig");
const sched_asm = @import("../../proc/sched_asm.zig");
const apic = @import("../../time/apic.zig");

const common = @import("common.zig");
const validateUserPtr = common.validateUserPtr;
const validateUserPtrAligned = common.validateUserPtrAligned;
const validateUserPtrWrite = common.validateUserPtrWrite;
const validateUserPtrWriteAligned = common.validateUserPtrWriteAligned;
const USER_SPACE_START = common.USER_SPACE_START;
const USER_SPACE_END = common.USER_SPACE_END;
const E_INVAL = common.E_INVAL;
const E_NOENT = common.E_NOENT;
const E_FAULT = common.E_FAULT;
const E_BADF = common.E_BADF;
const E_NOMEM = common.E_NOMEM;
const E_AGAIN = common.E_AGAIN;
const E_BUSY = common.E_BUSY;
const E_NAMETOOLONG = common.E_NAMETOOLONG;
const E_PIPE = common.E_PIPE;
const E_SRCH = common.E_SRCH;
const E_NOSYS = common.E_NOSYS;
const E_PERM = common.E_PERM;
const E_CHILD = common.E_CHILD;
const E_INTR = common.E_INTR;

var next_gpu_ctx_id: u32 = 1;

/// Hard ceiling on a single user-requested HOST GPU blob (sysGpuCreateBlob /
/// sysGpuMapBlob). The host venus pool is `hostmem=256M`; a single blob at or
/// near that size is abuse, not a real app — the fuzzer asked for 1 GiB
/// (size=0x40000000), which the host UNSPEC-rejected and which, repeated,
/// helped poison the shared renderer and kill the display. Real venus apps
/// allocate much smaller individual blobs. sysGpuCreateGuestBlob already caps
/// itself at 32 MB; this is the matching bound the host-blob path was missing.
/// NOT a substitute for real per-process GPU resource isolation (deferred) —
/// just stops the gross memory-DoS. (2026-06-04)
const GPU_BLOB_MAX_SIZE: u32 = 256 * 1024 * 1024;

/// Cap on a single GUEST blob (sysGpuCreateGuestBlob). Guest blobs are
/// backed by pmm.allocContiguous — the scarcest PMM resource (the whole
/// machine has 64-256 MB) — so the bound is much tighter than the
/// host-pool cap above. 32 MB = 8192 contiguous frames, enough for a
/// 1920x1080 RGBA image with headroom.
const GPU_GUEST_BLOB_MAX_SIZE: u32 = 32 * 1024 * 1024;

pub fn sysGpuCtxCreate(capset_id: u32) u32 {
    const virtio_gpu = @import("../../driver/virtio_gpu.zig");
    if (!virtio_gpu.has_virgl) {
        debug.klog("[gpu] ctx_create: no virgl support\n", .{});
        return E_INVAL;
    }

    const pcb = process.currentPCB() orelse return E_FAULT;
    if (pcb.gpu_has_ctx) {
        debug.klog("[gpu] ctx_create: reusing ctx_id={d}\n", .{pcb.gpu_ctx_id});
        return pcb.gpu_ctx_id;
    }

    // Atomic fetch-and-add: two CPUs concurrently entering this syscall must
    // not both grab the same ID. Without this the GPU sees duplicate context
    // IDs and the second ctxCreate silently corrupts the first's state.
    const ctx_id = @atomicRmw(u32, &next_gpu_ctx_id, .Add, 1, .acq_rel);

    if (!virtio_gpu.ctxCreate(ctx_id, capset_id, "app")) {
        debug.klog("[gpu] ctx_create FAILED ctx_id={d} capset={d}\n", .{ ctx_id, capset_id });
        return E_INVAL;
    }

    pcb.gpu_ctx_id = ctx_id;
    pcb.gpu_has_ctx = true;
    debug.klog("[gpu] ctx_create OK ctx_id={d} capset={d}\n", .{ ctx_id, capset_id });
    return ctx_id;
}

pub fn sysGpuSubmit3D(buf_ptr: u32, buf_len: u32) u32 {
    const virtio_gpu = @import("../../driver/virtio_gpu.zig");
    if (buf_len == 0 or buf_len > 15 * 4096) return E_INVAL;
    if (!validateUserPtr(buf_ptr, buf_len)) return E_FAULT;

    const pcb = process.currentPCB() orelse return E_FAULT;
    if (!pcb.gpu_has_ctx) return E_INVAL;

    const src: [*]const u8 = @ptrFromInt(@as(usize, buf_ptr));
    if (virtio_gpu.submit3D(pcb.gpu_ctx_id, src[0..buf_len])) {
        debug.klog("[gpu] submit_3d OK ctx={d} len={d} bytes\n", .{ pcb.gpu_ctx_id, buf_len });
        return 0;
    } else {
        debug.klog("[gpu] submit_3d FAILED ctx={d} len={d}\n", .{ pcb.gpu_ctx_id, buf_len });
        return E_INVAL;
    }
}

pub fn sysGpuCtxDestroy() u32 {
    const virtio_gpu = @import("../../driver/virtio_gpu.zig");
    const pcb = process.currentPCB() orelse return E_FAULT;
    if (!pcb.gpu_has_ctx) return 0;

    _ = virtio_gpu.ctxDestroy(pcb.gpu_ctx_id);
    pcb.gpu_has_ctx = false;
    pcb.gpu_ctx_id = 0;
    return 0;
}

pub fn sysGpuGetCapsetInfo(index: u32, buf_ptr: u32) u32 {
    // Returns [capset_id: u32, max_version: u32, max_size: u32] to user buffer
    if (!validateUserPtrWriteAligned(buf_ptr, 12, 4)) {
        debug.klog("[gpu] capset_info[{d}] FAIL: bad user ptr 0x{X}\n", .{ index, buf_ptr });
        return E_INVAL;
    }
    const virtio_gpu = @import("../../driver/virtio_gpu.zig");
    if (!virtio_gpu.has_virgl) {
        debug.klog("[gpu] capset_info[{d}] FAIL: no virgl\n", .{index});
        return E_INVAL;
    }

    var cmd = virtio_gpu.GetCapsetInfo{ .hdr = .{ .cmd_type = 0x0108 }, .capset_index = index };
    var resp: virtio_gpu.RespCapsetInfo = undefined;
    @memset(@as([*]u8, @ptrCast(&resp))[0..@sizeOf(virtio_gpu.RespCapsetInfo)], 0);

    if (!virtio_gpu.sendCmd(
        @as([*]const u8, @ptrCast(&cmd)),
        @sizeOf(virtio_gpu.GetCapsetInfo),
        @as([*]u8, @ptrCast(&resp)),
        @sizeOf(virtio_gpu.RespCapsetInfo),
    )) {
        debug.klog("[gpu] capset_info[{d}] FAIL: sendCmd\n", .{index});
        return E_INVAL;
    }

    if (resp.hdr.cmd_type != 0x1102) {
        debug.klog("[gpu] capset_info[{d}] FAIL: resp.cmd_type=0x{X} (id={d} size={d})\n", .{
            index, resp.hdr.cmd_type, resp.capset_id, resp.capset_max_size,
        });
        return E_INVAL;
    }

    const buf: [*]u32 = @ptrFromInt(@as(usize, buf_ptr));
    buf[0] = resp.capset_id;
    buf[1] = resp.capset_max_version;
    buf[2] = resp.capset_max_size;
    debug.klog("[gpu] capset_info[{d}]: id={d} ver={d} size={d}\n", .{
        index, resp.capset_id, resp.capset_max_version, resp.capset_max_size,
    });
    return 0;
}

pub fn sysGpuCreateBlob(blob_mem: u32, size: u32, blob_id_arg: u32) u32 {
    const virtio_gpu = @import("../../driver/virtio_gpu.zig");
    if (!virtio_gpu.has_blob) return E_INVAL;
    // Bound the host allocation — see GPU_BLOB_MAX_SIZE. Without this a 1 GiB
    // request reaches the host renderer and pressures the shared venus pool.
    if (size == 0 or size > GPU_BLOB_MAX_SIZE) return E_INVAL;

    const pcb = process.currentPCB() orelse return E_FAULT;
    if (!pcb.gpu_has_ctx) return E_INVAL;

    const resource_id = virtio_gpu.alloc3DResourceId();
    const blob_id: u64 = blob_id_arg;
    if (!virtio_gpu.resourceCreateBlob(
        pcb.gpu_ctx_id,
        resource_id,
        blob_mem,
        if (blob_id_arg != 0) 5 else 1, // MAPPABLE + CROSS_DEVICE for VkDeviceMemory blobs
        blob_id,
        size,
    )) return E_INVAL;

    return resource_id;
}

pub fn sysGpuMapBlob(resource_id: u32, size: u32) u32 {
    const virtio_gpu = @import("../../driver/virtio_gpu.zig");
    debug.klog("[gpu] mapBlob: res={d} size={d}\n", .{ resource_id, size });
    if (!virtio_gpu.has_blob) {
        debug.klog("[gpu] mapBlob: no blob support\n", .{});
        return E_INVAL;
    }
    // Bound the map — sysGpuMapBlob maps `size` bytes (kernel WB + user_brk
    // pages), so an unclamped size balloons the page tables and user_brk. Match
    // the create cap; a legit map never exceeds the blob it created.
    if (size == 0 or size > GPU_BLOB_MAX_SIZE) return E_INVAL;

    const pcb = process.currentPCB() orelse return E_FAULT;
    if (!pcb.gpu_has_ctx) return E_INVAL;
    const pd = pcb.page_directory orelse return E_FAULT;

    // Attach resource to context first
    if (!virtio_gpu.ctxAttachResource(pcb.gpu_ctx_id, resource_id)) {
        debug.klog("[gpu] mapBlob: ctxAttach failed\n", .{});
        return E_INVAL;
    }

    // Map blob in SHM BAR — get physical address
    const phys = virtio_gpu.resourceMapBlob(resource_id, size) orelse {
        debug.klog("[gpu] mapBlob: resourceMapBlob failed\n", .{});
        return E_INVAL;
    };

    // Ensure kernel can access the SHM BAR pages. Use the WB variant
    // (NOT mapMMIO!): virtio-gpu BLOB memory is host DRAM exposed through
    // the SHM BAR — not MMIO registers — and the host's mmap of the
    // backing dma-buf is WB. Mapping UC on the guest side breaks MESI
    // coherency across the KVM boundary (guest reads stale DRAM until
    // the host CPU flushes its caches), and pegs reads to ~1.5 GB/s.
    paging.mapWBRange(phys, size);

    // Map into user space at the process brk region. Same WB-everywhere
    // rationale — both kernel and user mappings of the same physical
    // pages must agree on cacheability or x86 calls it undefined.
    const pages = (size + 4095) / 4096;
    const base_virt = pcb.user_brk;
    var mapped_pages: usize = 0;
    for (0..pages) |i| {
        const virt = base_virt + i * 0x1000;
        const p = phys + i * 0x1000;
        vmm.mapUserPage(pd, virt, p, paging.PRESENT | paging.READ_WRITE | paging.USER) catch |e| {
            debug.klog("[gpu] map_blob mapUserPage failed at page={d} virt=0x{X}: {s}\n", .{ i, virt, @errorName(e) });
            // phys is host-owned SHM BAR memory — no PMM frame to free,
            // just undo the page-table installs and leave user_brk where
            // it was (we never bumped it).
            var j: usize = 0;
            while (j < mapped_pages) : (j += 1) {
                _ = vmm.unmapUserPage(pd, base_virt + j * 0x1000);
            }
            return E_INVAL;
        };
        mapped_pages += 1;
    }
    pcb.user_brk = base_virt + pages * 0x1000;

    debug.klog("[gpu] map_blob: res={d} phys=0x{X} virt=0x{X} size={d}\n", .{ resource_id, phys, base_virt, size });
    return @intCast(base_virt);
}

/// Allocate guest physical pages, create a virtio-gpu BLOB_MEM_GUEST
/// resource backed by them, attach to context, and map into user space.
/// Returns the user VA where the pages are mapped; writes the
/// resource_id to *out_resource_id (so the caller can pass it into a
/// Venus `vkAllocateMemory` chained with `VkImportMemoryResourceInfoMESA`).
///
/// The resulting memory IS shared bidirectionally with the host's Venus
/// renderer: Lavapipe writes go to the same physical pages the user
/// reads. This is the path that actually delivers Vulkan-rendered
/// pixels to the guest, unlike BLOB_MEM_HOST3D which gives Lavapipe a
/// disconnected allocation.
pub fn sysGpuCreateGuestBlob(size: u32, out_resource_id_ptr: u32) u32 {
    const virtio_gpu = @import("../../driver/virtio_gpu.zig");
    if (!virtio_gpu.has_blob) return E_INVAL;
    if (size == 0 or size > GPU_GUEST_BLOB_MAX_SIZE) return E_INVAL;
    if (!validateUserPtrWriteAligned(out_resource_id_ptr, 4, 4)) return E_FAULT;

    const pcb = process.currentPCB() orelse return E_FAULT;
    if (!pcb.gpu_has_ctx) return E_INVAL;
    const pd = pcb.page_directory orelse return E_FAULT;

    const num_pages = (size + 4095) / 4096;
    const phys_base = pmm.allocContiguous(num_pages) orelse {
        debug.klog("[gpu] createGuestBlob: pmm.allocContiguous({d} pages) FAILED\n", .{num_pages});
        return E_INVAL;
    };

    // Zero the pages so callers don't observe stale heap garbage. The
    // pages are guest physical, mapped into kernel via physToVirt
    // (PHYSMAP_BASE + phys, kernel can reach any phys frame).
    const kvirt: [*]u8 = @ptrFromInt(paging.physToVirt(phys_base));
    @memset(kvirt[0 .. num_pages * 4096], 0);

    const resource_id = virtio_gpu.alloc3DResourceId();
    // MAPPABLE | SHAREABLE: guest mmaps it, virgl shares it with Lavapipe.
    if (!virtio_gpu.resourceCreateGuestBlob(
        pcb.gpu_ctx_id,
        resource_id,
        0x03,
        phys_base,
        @as(u64, size),
    )) {
        debug.klog("[gpu] createGuestBlob: resourceCreateGuestBlob FAILED\n", .{});
        // No host resource exists — the contiguous block has no other
        // owner, return it to the PMM. (Was a leak: up to 8192 frames
        // per failed call, user-triggerable.)
        pmm.freeContiguous(phys_base, num_pages);
        return E_INVAL;
    }

    if (!virtio_gpu.ctxAttachResource(pcb.gpu_ctx_id, resource_id)) {
        debug.klog("[gpu] createGuestBlob: ctxAttachResource FAILED\n", .{});
        // The host resource WAS created and references phys_base — unref
        // it first so the host drops its mapping, THEN free the backing.
        // Freeing while the resource lives would hand the host a window
        // into recycled frames.
        _ = virtio_gpu.resourceUnref(resource_id);
        pmm.freeContiguous(phys_base, num_pages);
        return E_INVAL;
    }

    const base_virt = pcb.user_brk;
    var mapped_pages: usize = 0;
    for (0..num_pages) |i| {
        const virt = base_virt + i * 0x1000;
        const phys = phys_base + i * 0x1000;
        // PRESENT for clarity only — mapUserPage ORs it in regardless
        // (vmm.zig new_pte). Keeps this call site consistent with
        // sysGpuMapBlob's.
        vmm.mapUserPage(pd, virt, phys, paging.PRESENT | paging.READ_WRITE | paging.USER) catch |e| {
            // Rollback: undo the page-table installs we did, unref the
            // created+attached host resource so the host drops its
            // reference to phys_base, and only THEN free the contiguous
            // block (no dual-owner refs — these pages are only mapped
            // into one PML4). user_brk stays where it was (never bumped).
            // Previously the resource was left alive ("defensive leak")
            // while its backing went back to the PMM — the host kept a
            // window into recycled frames.
            debug.klog("[gpu] createGuestBlob mapUserPage failed at page={d} virt=0x{X}: {s}\n", .{ i, virt, @errorName(e) });
            var j: usize = 0;
            while (j < mapped_pages) : (j += 1) {
                _ = vmm.unmapUserPage(pd, base_virt + j * 0x1000);
            }
            _ = virtio_gpu.resourceUnref(resource_id);
            pmm.freeContiguous(phys_base, num_pages);
            return E_INVAL;
        };
        mapped_pages += 1;
    }
    pcb.user_brk = base_virt + num_pages * 0x1000;

    const out_ptr: *u32 = @ptrFromInt(@as(usize, out_resource_id_ptr));
    out_ptr.* = resource_id;

    debug.klog("[gpu] createGuestBlob: res={d} phys=0x{X} virt=0x{X} pages={d}\n",
        .{ resource_id, phys_base, base_virt, num_pages });
    return @intCast(base_virt);
}

pub fn sysGpuResourceCreate3D(params_ptr: u32) u32 {
    const virtio_gpu = @import("../../driver/virtio_gpu.zig");
    if (!virtio_gpu.has_virgl) return E_INVAL;

    const pcb = process.currentPCB() orelse return E_FAULT;
    if (!pcb.gpu_has_ctx) return E_INVAL;
    if (!validateUserPtrAligned(params_ptr, 20, 4)) return E_FAULT;

    const params: [*]const u32 = @ptrFromInt(@as(usize, params_ptr));
    const resource_id = virtio_gpu.alloc3DResourceId();
    debug.klog("[gpu] resource_create_3d: id={d} {d}x{d} fmt={d} bind=0x{x}\n", .{
        resource_id, params[3], params[4], params[1], params[2],
    });

    if (!virtio_gpu.resourceCreate3D(
        pcb.gpu_ctx_id,
        resource_id,
        params[0],
        params[1],
        params[2],
        params[3],
        params[4],
    )) {
        debug.klog("[gpu] resource_create_3d FAILED\n", .{});
        return E_INVAL;
    }

    if (!virtio_gpu.ctxAttachResource(pcb.gpu_ctx_id, resource_id)) {
        debug.klog("[gpu] ctx_attach_resource FAILED\n", .{});
        return E_INVAL;
    }

    debug.klog("[gpu] resource_create_3d OK id={d}\n", .{resource_id});
    return resource_id;
}

pub fn sysGpuTransferToHost3D(resource_id: u32, params_ptr: u32) u32 {
    const virtio_gpu = @import("../../driver/virtio_gpu.zig");
    if (!virtio_gpu.has_virgl) return E_INVAL;

    const pcb = process.currentPCB() orelse return E_FAULT;
    if (!pcb.gpu_has_ctx) return E_INVAL;
    if (!validateUserPtrAligned(params_ptr, 12, 4)) return E_FAULT;

    // params: [width, height, stride]
    const params: [*]const u32 = @ptrFromInt(@as(usize, params_ptr));
    if (!virtio_gpu.transferToHost3D(
        pcb.gpu_ctx_id,
        resource_id,
        params[0], // width
        params[1], // height
        params[2], // stride
    )) return E_INVAL;

    return 0;
}

/// Symmetric counterpart of sysGpuTransferToHost3D. Pulls a host-side 3D
/// resource (e.g. a Lavapipe-rendered VkImage exposed as a virtio-gpu
/// resource) into the guest-mmapped blob backing it. Required when auto-
/// dmabuf-sharing isn't engaged and Lavapipe writes don't reach the guest
/// blob on their own — call after vkDeviceWaitIdle, before reading pixels.
pub fn sysGpuTransferFromHost3D(resource_id: u32, params_ptr: u32) u32 {
    const virtio_gpu = @import("../../driver/virtio_gpu.zig");
    if (!virtio_gpu.has_virgl) return E_INVAL;

    const pcb = process.currentPCB() orelse return E_FAULT;
    if (!pcb.gpu_has_ctx) return E_INVAL;
    if (!validateUserPtrAligned(params_ptr, 12, 4)) return E_FAULT;

    // params: [width, height, stride]
    const params: [*]const u32 = @ptrFromInt(@as(usize, params_ptr));
    if (!virtio_gpu.transferFromHost3D(
        pcb.gpu_ctx_id,
        resource_id,
        params[0], // width
        params[1], // height
        params[2], // stride
    )) return E_INVAL;

    return 0;
}

/// Point a scanout slot at a blob resource — used by Vulkan apps that
/// want their rendered output displayed directly, sidestepping the
/// (broken-on-this-stack) blob readback path. params: [scanout_id,
/// width, height, format, stride].
pub fn sysGpuSetScanoutBlob(resource_id: u32, params_ptr: u32) u32 {
    const virtio_gpu = @import("../../driver/virtio_gpu.zig");
    if (!virtio_gpu.has_virgl) return E_INVAL;
    if (!validateUserPtrAligned(params_ptr, 20, 4)) return E_FAULT;

    const params: [*]const u32 = @ptrFromInt(@as(usize, params_ptr));
    if (!virtio_gpu.setScanoutBlob(
        params[0], // scanout_id
        resource_id,
        params[1], // width
        params[2], // height
        params[3], // format
        params[4], // stride
    )) return E_INVAL;

    return 0;
}

/// Force a re-display of a scanned-out resource. Pair with
/// setScanoutBlob — call this after every render to push new contents.
pub fn sysGpuResourceFlush(resource_id: u32, params_ptr: u32) u32 {
    const virtio_gpu = @import("../../driver/virtio_gpu.zig");
    if (!virtio_gpu.has_virgl) return E_INVAL;
    if (!validateUserPtrAligned(params_ptr, 8, 4)) return E_FAULT;

    const params: [*]const u32 = @ptrFromInt(@as(usize, params_ptr));
    if (!virtio_gpu.resourceFlush(resource_id, params[0], params[1])) return E_INVAL;

    return 0;
}

