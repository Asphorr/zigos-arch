//! 3D: capsets, contexts, SUBMIT_3D, blob resources and the hostmem BAR.

const pci = @import("../../bus/pci.zig");
const Phys = @import("../../../util/addr.zig").Phys;
const paging = @import("../../../mm/paging.zig");
const debug = @import("../../../debug/debug.zig");
const iommu = @import("../../iommu.zig");
const vg = @import("../virtio_gpu.zig");
const virtio = @import("../../bus/virtio.zig");
const proto = @import("protocol.zig");
const ctrlq = @import("ctrlq.zig");
const present = @import("present.zig");

// SHM BAR for blob resources (host-visible memory)
pub var shm_bar_phys: usize = 0;
pub var shm_bar_size: usize = 0;

// --- GPU commands ---

pub fn detectShmBar(dev_pci: pci.PciDevice) void {
    // SHM caps share the modern-virtio cap layout; pci.findVirtioCap gives
    // us bar/offset/length (low 32 bits) and the cfg_off so we can read the
    // SHM-specific extension fields (offset_hi, length_hi at +16/+20, plus
    // shm_id in byte 1 of the second dword).
    const cap = pci.findVirtioCap(dev_pci, virtio.CAP_SHARED_MEMORY_CFG) orelse return;

    const cap_data = pci.configRead(dev_pci.bus, dev_pci.dev, dev_pci.func, cap.cfg_off + 4);
    const shm_id: u8 = @truncate(cap_data >> 8);
    const offset_hi = pci.configRead(dev_pci.bus, dev_pci.dev, dev_pci.func, cap.cfg_off + 16);
    const length_hi = pci.configRead(dev_pci.bus, dev_pci.dev, dev_pci.func, cap.cfg_off + 20);

    const offset: u64 = @as(u64, offset_hi) << 32 | cap.offset;
    const length: u64 = @as(u64, length_hi) << 32 | cap.length;

    debug.klog("[virtio-gpu] SHM cap: bar={d} id={d} off=0x{X} len=0x{X}\n", .{
        cap.bar, shm_id, offset, length,
    });

    // ID 1 = VIRTIO_GPU_SHM_ID_HOST_VISIBLE
    if (shm_id == 1) {
        const bar_reg: u8 = 0x10 + cap.bar * 4;
        var bar_base: usize = pci.readBar64(dev_pci.bus, dev_pci.dev, dev_pci.func, bar_reg);

        // UEFI/OVMF fallback: if firmware didn't assign the BAR, allocate
        // from our MMIO pool and assign it ourselves.
        if (bar_base == 0) {
            const bar_size: u64 = if (length > 0) length else 256 * 1024 * 1024;
            const new_base = pci.allocMmio64(bar_size, bar_size);
            pci.assignBar64(dev_pci.bus, dev_pci.dev, dev_pci.func, cap.bar, new_base);
            bar_base = @intCast(new_base);
            debug.klog("[virtio-gpu] SHM BAR auto-assigned to 0x{X} ({d}MB)\n", .{
                bar_base, bar_size / (1024 * 1024),
            });
            // SHM BAR is host DRAM exposed via virtio-gpu BLOB (e.g. Vulkan
            // render targets). It's data, not registers — must be Write-Back
            // so x86 MESI snooping keeps the guest's view coherent with the
            // host's WB mapping of the same dma-buf. UC here breaks the cube
            // (~9% torn frames + 1.5 GB/s read bandwidth instead of 30+).
            paging.mapWBRange(bar_base, @intCast(bar_size));
        }

        shm_bar_phys = bar_base + @as(usize, @truncate(offset));
        shm_bar_size = @truncate(length);
        debug.klog("[virtio-gpu] SHM BAR: phys=0x{X} size={d}MB\n", .{
            shm_bar_phys, shm_bar_size / (1024 * 1024),
        });
    }
}

pub fn queryCapsets() void {
    var index: u32 = 0;
    while (index < 16) : (index += 1) {
        var cmd = proto.GetCapsetInfo{ .hdr = .{ .cmd_type = proto.CMD_GET_CAPSET_INFO }, .capset_index = index };
        var resp: proto.RespCapsetInfo = undefined;
        @memset(@as([*]u8, @ptrCast(&resp))[0..@sizeOf(proto.RespCapsetInfo)], 0);

        if (!ctrlq.sendCmd(
            @as([*]const u8, @ptrCast(&cmd)),
            @sizeOf(proto.GetCapsetInfo),
            @as([*]u8, @ptrCast(&resp)),
            @sizeOf(proto.RespCapsetInfo),
        )) break;

        if (resp.hdr.cmd_type != proto.RESP_OK_CAPSET_INFO) break;
        if (resp.capset_id == 0 and resp.capset_max_size == 0) break; // empty slot

        debug.klog("[virtio-gpu] Capset {d}: id={d} ver={d} size={d}\n", .{
            index, resp.capset_id, resp.capset_max_version, resp.capset_max_size,
        });

        if (resp.capset_id == proto.CAPSET_VENUS) {
            vg.has_venus = true;
            debug.klog("[virtio-gpu] Venus capset found!\n", .{});
        }
        if (resp.capset_id == proto.CAPSET_VIRGL or resp.capset_id == proto.CAPSET_VIRGL2) {
            vg.has_virgl_capset = true;
        }
    }
}

// ============================================================
// 3D Context API
// ============================================================

pub var next_3d_resource_id: u32 = 1000;

pub fn alloc3DResourceId() u32 {
    const id = next_3d_resource_id;
    next_3d_resource_id += 1;
    return id;
}

/// Create a 3D rendering context (VirGL or Venus).
/// ctx_id: unique context ID (typically per-process)
/// capset_id: which capset to use (CAPSET_VIRGL=1, CAPSET_VENUS=4)
/// name: debug name for the context
pub fn ctxCreate(ctx_id: u32, capset_id: u32, name: []const u8) bool {
    var cmd = proto.CtxCreate{
        .hdr = .{ .cmd_type = proto.CMD_CTX_CREATE, .ctx_id = ctx_id },
        .context_init = if (vg.has_context_init) capset_id else 0,
    };

    // Copy debug name
    const copy_len = if (name.len > 64) 64 else name.len;
    for (0..copy_len) |i| cmd.debug_name[i] = name[i];
    cmd.nlen = @intCast(copy_len);

    var resp = proto.CtrlHdr{};
    if (!ctrlq.sendCmd(
        @as([*]const u8, @ptrCast(&cmd)),
        @sizeOf(proto.CtxCreate),
        @as([*]u8, @ptrCast(&resp)),
        @sizeOf(proto.CtrlHdr),
    )) {
        debug.klog("[virtio-gpu] ctxCreate timeout\n", .{});
        return false;
    }

    if (resp.cmd_type != proto.RESP_OK_NODATA) {
        debug.klog("[virtio-gpu] ctxCreate failed: 0x{X}\n", .{resp.cmd_type});
        return false;
    }

    debug.klog("[virtio-gpu] 3D context {d} created (capset={d})\n", .{ ctx_id, capset_id });
    return true;
}

/// Destroy a 3D context.
pub fn ctxDestroy(ctx_id: u32) bool {
    var cmd = proto.CtrlHdr{ .cmd_type = proto.CMD_CTX_DESTROY, .ctx_id = ctx_id };
    var resp = proto.CtrlHdr{};
    if (!ctrlq.sendCmd(
        @as([*]const u8, @ptrCast(&cmd)),
        @sizeOf(proto.CtrlHdr),
        @as([*]u8, @ptrCast(&resp)),
        @sizeOf(proto.CtrlHdr),
    )) return false;
    return resp.cmd_type == proto.RESP_OK_NODATA;
}

/// Attach a resource to a 3D context (makes it accessible to the context).
pub fn ctxAttachResource(ctx_id: u32, resource_id: u32) bool {
    var cmd = proto.CtxResource{
        .hdr = .{ .cmd_type = proto.CMD_CTX_ATTACH_RESOURCE, .ctx_id = ctx_id },
        .resource_id = resource_id,
    };
    var resp = proto.CtrlHdr{};
    if (!ctrlq.sendCmd(
        @as([*]const u8, @ptrCast(&cmd)),
        @sizeOf(proto.CtxResource),
        @as([*]u8, @ptrCast(&resp)),
        @sizeOf(proto.CtrlHdr),
    )) return false;
    return resp.cmd_type == proto.RESP_OK_NODATA;
}

/// Submit a 3D command buffer to a context.
/// cmd_data contains VirGL or Venus protocol commands.
pub fn submit3D(ctx_id: u32, cmd_data: []const u8) bool {
    const hdr_size = @sizeOf(proto.CmdSubmit3D);
    const total = hdr_size + cmd_data.len;
    if (total > ctrlq.CMD_PAGES * 4096) {
        debug.klog("[virtio-gpu] submit3D too large: {d}\n", .{cmd_data.len});
        return false;
    }

    // Serialize against sendCmd — both touch ctrl_vq + cmd_phys/resp_phys.
    // Without this, BSP rendering racing with AP syscalls corrupts the ring.
    defer present.kickPendingFromTask(); // see sendCmd — runs after the release
    ctrlq.ctrl_lock.acquire();
    defer ctrlq.ctrl_lock.release();
    // As in sendCmd: an outstanding async flush pair owns cmd/resp slots,
    // and its completion would pass for ours in sendCmdViaPhys.
    present.waitAsyncFlushIdleLocked();

    // Write header + command data directly to cmd_phys.
    const dst: [*]volatile u8 = @ptrFromInt(paging.physToVirt(ctrlq.cmd_phys));
    var hdr = proto.CmdSubmit3D{
        .hdr = .{ .cmd_type = proto.CMD_SUBMIT_3D, .ctx_id = ctx_id },
        .size = @intCast(cmd_data.len),
    };
    const hdr_bytes: [*]const u8 = @ptrCast(&hdr);
    @memcpy(@as([*]volatile u8, dst)[0..hdr_size], hdr_bytes[0..hdr_size]);
    @memcpy(@as([*]volatile u8, dst + hdr_size)[0..cmd_data.len], cmd_data);

    const resp_dst: [*]volatile u8 = @ptrFromInt(paging.physToVirt(ctrlq.resp_phys));
    @memset(resp_dst[0..@sizeOf(proto.CtrlHdr)], 0);

    if (!ctrlq.sendCmdViaPhys(@intCast(total), @sizeOf(proto.CtrlHdr))) return false;

    ctrlq.clflushRange(paging.physToVirt(ctrlq.resp_phys), @sizeOf(proto.CtrlHdr)); // gap #2
    const resp: *volatile proto.CtrlHdr = @ptrFromInt(paging.physToVirt(ctrlq.resp_phys));
    return resp.cmd_type == proto.RESP_OK_NODATA;
}

/// Create a blob resource (for shared memory with host GPU).
pub fn resourceCreateBlob(ctx_id: u32, resource_id: u32, blob_mem: u32, blob_flags: u32, blob_id: u64, size: u64) bool {
    debug.klog("[virtio-gpu] createBlob: ctx={d} res={d} mem={d} flags={d} blob_id={d} size={d} struct_size={d}\n", .{ ctx_id, resource_id, blob_mem, blob_flags, blob_id, size, @sizeOf(proto.ResourceCreateBlob) });
    var cmd = proto.ResourceCreateBlob{
        .hdr = .{ .cmd_type = proto.CMD_RESOURCE_CREATE_BLOB, .ctx_id = ctx_id },
        .resource_id = resource_id,
        .blob_mem = blob_mem,
        .blob_flags = blob_flags,
        .nr_entries = 0, // HOST3D doesn't need guest backing
        .blob_id = blob_id,
        .size = size,
    };
    // Response variant is either RESP_OK_NODATA (CtrlHdr only) or
    // RESP_OK_RESOURCE_UUID — size for the larger one so the device write
    // never truncates, even though we only inspect cmd_type below.
    var resp_buf: [@sizeOf(proto.RespResourceUuid)]u8 align(4) = @splat(0);
    if (!ctrlq.sendCmd(
        @as([*]const u8, @ptrCast(&cmd)),
        @sizeOf(proto.ResourceCreateBlob),
        &resp_buf,
        @sizeOf(proto.RespResourceUuid),
    )) {
        debug.klog("[virtio-gpu] createBlob timeout\n", .{});
        return false;
    }
    const resp_hdr: *const proto.CtrlHdr = @ptrCast(@alignCast(&resp_buf));
    if (resp_hdr.cmd_type != proto.RESP_OK_NODATA) {
        debug.klog("[virtio-gpu] createBlob failed: 0x{X}\n", .{resp_hdr.cmd_type});
        return false;
    }
    return true;
}

/// How the host backs a VkDeviceMemory blob: as a dma-buf it can scan out
/// directly, or only as a mapping it reads through a pointer.
pub const MemoryBlob = enum { dma_buf, mapped };

/// Wrap Venus VkDeviceMemory `blob_id` as a mappable blob. With
/// `try_dma_buf`, asks for a dma-buf first (CROSS_DEVICE); a host driver
/// that cannot export host-visible memory refuses that but can still map
/// it, so retry mappable-only.
pub fn resourceCreateMemoryBlob(ctx_id: u32, resource_id: u32, blob_mem: u32, blob_id: u64, size: u64, try_dma_buf: bool) ?MemoryBlob {
    if (try_dma_buf and resourceCreateBlob(ctx_id, resource_id, blob_mem, proto.BLOB_FLAG_USE_MAPPABLE | proto.BLOB_FLAG_USE_CROSS_DEVICE, blob_id, size))
        return .dma_buf;
    if (resourceCreateBlob(ctx_id, resource_id, blob_mem, proto.BLOB_FLAG_USE_MAPPABLE, blob_id, size))
        return .mapped;
    return null;
}

// SHM BAR bump allocator — each blob gets a unique page-aligned offset
pub var shm_next_offset: u64 = 0;

/// Map a blob resource into the SHM BAR. Returns the blob's SHM-BAR physical
/// address (device memory, never a PMM frame) or null.
/// The offset is a guest-specified INPUT telling QEMU where in the SHM BAR to place this blob.
/// The response only contains caching flags (map_info), NOT an offset.
pub fn resourceMapBlob(resource_id: u32, size: u32) ?Phys {
    if (shm_bar_phys == 0) {
        debug.klog("[virtio-gpu] mapBlob: no SHM BAR\n", .{});
        return null;
    }

    // Allocate a unique page-aligned offset in the SHM BAR
    const offset = shm_next_offset;
    const aligned_size = ((@as(u64, size) + 4095) / 4096) * 4096;
    if (offset + aligned_size > shm_bar_size) {
        debug.klog("[virtio-gpu] mapBlob: SHM BAR full (offset=0x{X} size={d})\n", .{ offset, size });
        return null;
    }
    shm_next_offset = offset + aligned_size;

    var cmd = proto.ResourceMapBlob{
        .hdr = .{ .cmd_type = proto.CMD_RESOURCE_MAP_BLOB },
        .resource_id = resource_id,
        .offset = offset, // Guest-specified offset into SHM BAR
    };
    var resp: proto.RespMapInfo = undefined;
    @memset(@as([*]u8, @ptrCast(&resp))[0..@sizeOf(proto.RespMapInfo)], 0);

    debug.klog("[virtio-gpu] mapBlob: sending res={d} offset=0x{X} size={d}\n", .{ resource_id, offset, size });
    if (!ctrlq.sendCmd(
        @as([*]const u8, @ptrCast(&cmd)),
        @sizeOf(proto.ResourceMapBlob),
        @as([*]u8, @ptrCast(&resp)),
        @sizeOf(proto.RespMapInfo),
    )) {
        debug.klog("[virtio-gpu] mapBlob: sendCmd timeout\n", .{});
        return null;
    }

    debug.klog("[virtio-gpu] mapBlob: resp_type=0x{X} map_info={d}\n", .{ resp.hdr.cmd_type, resp.map_info });
    if (resp.hdr.cmd_type != proto.RESP_OK_MAP_INFO) return null;

    const phys = shm_bar_phys + @as(usize, @truncate(offset));
    debug.klog("[virtio-gpu] mapBlob: res={d} offset=0x{X} phys=0x{X}\n", .{ resource_id, offset, phys });
    return Phys.of(phys);
}

/// Create a 3D resource (texture/buffer) for VirGL rendering.
pub fn resourceCreate3D(ctx_id: u32, resource_id: u32, target: u32, format: u32, bind: u32, w: u32, h: u32) bool {
    var cmd = proto.ResourceCreate3D{
        .hdr = .{ .cmd_type = proto.CMD_RESOURCE_CREATE_3D, .ctx_id = ctx_id },
        .resource_id = resource_id,
        .target = target,
        .format = format,
        .bind = bind,
        .width = w,
        .height = h,
    };
    var resp = proto.CtrlHdr{};
    if (!ctrlq.sendCmd(
        @as([*]const u8, @ptrCast(&cmd)),
        @sizeOf(proto.ResourceCreate3D),
        @as([*]u8, @ptrCast(&resp)),
        @sizeOf(proto.CtrlHdr),
    )) return false;
    if (resp.cmd_type != proto.RESP_OK_NODATA) {
        debug.klog("[virtio-gpu] resourceCreate3D failed: 0x{X}\n", .{resp.cmd_type});
        return false;
    }
    return true;
}

/// Transfer 3D resource contents from guest to host.
pub fn transferToHost3D(ctx_id: u32, resource_id: u32, w: u32, h: u32, stride: u32) bool {
    var cmd = proto.TransferHost3D{
        .hdr = .{ .cmd_type = proto.CMD_TRANSFER_TO_HOST_3D, .ctx_id = ctx_id },
        .box_w = w,
        .box_h = h,
        .box_d = 1,
        .resource_id = resource_id,
        .stride = stride,
    };
    var resp = proto.CtrlHdr{};
    if (!ctrlq.sendCmd(
        @as([*]const u8, @ptrCast(&cmd)),
        @sizeOf(proto.TransferHost3D),
        @as([*]u8, @ptrCast(&resp)),
        @sizeOf(proto.CtrlHdr),
    )) return false;
    if (resp.cmd_type != proto.RESP_OK_NODATA) {
        debug.klog("[virtio-gpu] transferToHost3D failed: 0x{X}\n", .{resp.cmd_type});
        return false;
    }
    return true;
}

/// Create a GUEST-backed blob resource — guest physical pages are the
/// storage, virgl sees them as a dmabuf (via udmabuf). This is the path
/// for Vulkan rendering where Lavapipe needs to write into memory the
/// guest can also read. Pair with Venus `vkAllocateMemory` chained with
/// `VkImportMemoryResourceInfoMESA` referencing this `resource_id` —
/// Lavapipe then imports the dmabuf as `VkDeviceMemory`'s backing.
///
/// `(phys_base, size)` defines a single contiguous physical range
/// (typical PMM allocContiguous output). Sent as one SG entry — no
/// per-page bookkeeping. Cmd is built directly in `cmd_phys` because
/// variable-length (header + N × MemEntry) doesn't fit a fixed extern.
pub fn resourceCreateGuestBlob(ctx_id: u32, resource_id: u32, blob_flags: u32, phys_base: u64, size: u64) bool {
    debug.klog("[virtio-gpu] createGuestBlob: ctx={d} res={d} flags={d} phys=0x{X} size={d}\n",
        .{ ctx_id, resource_id, blob_flags, phys_base, size });

    // Map the guest-blob backing into the device's IOVA before the host
    // starts reading/writing through it. Caller passes a contiguous phys
    // range so one dmaMap call covers it.
    _ = iommu.dmaMap(vg.pci_bus, vg.pci_dev, vg.pci_func, phys_base, size, .{});

    // cmd_phys/resp_phys belong to whoever holds ctrl_lock: build under it.
    defer present.kickPendingFromTask(); // see sendCmd — runs after the release
    ctrlq.ctrl_lock.acquire();
    defer ctrlq.ctrl_lock.release();
    present.waitAsyncFlushIdleLocked();

    const cmd_dst: [*]volatile u8 = @ptrFromInt(paging.physToVirt(ctrlq.cmd_phys));
    @memset(cmd_dst[0..4096], 0);

    const cmd: *volatile proto.ResourceCreateBlob = @ptrFromInt(paging.physToVirt(ctrlq.cmd_phys));
    cmd.hdr = .{ .cmd_type = proto.CMD_RESOURCE_CREATE_BLOB, .ctx_id = ctx_id };
    cmd.resource_id = resource_id;
    cmd.blob_mem = proto.BLOB_MEM_GUEST;
    cmd.blob_flags = blob_flags;
    cmd.nr_entries = 1;
    cmd.blob_id = 0;
    cmd.size = size;

    const entry: *volatile proto.MemEntry = @ptrFromInt(paging.physToVirt(ctrlq.cmd_phys + @sizeOf(proto.ResourceCreateBlob)));
    entry.* = .{ .addr = phys_base, .length = @truncate(size), .padding = 0 };

    const total_len: u32 = @intCast(@sizeOf(proto.ResourceCreateBlob) + @sizeOf(proto.MemEntry));

    const resp_dst: [*]volatile u8 = @ptrFromInt(paging.physToVirt(ctrlq.resp_phys));
    @memset(resp_dst[0..48], 0);

    if (!ctrlq.sendCmdViaPhys(total_len, 48)) {
        debug.klog("[virtio-gpu] createGuestBlob timeout\n", .{});
        return false;
    }

    ctrlq.clflushRange(paging.physToVirt(ctrlq.resp_phys), 48); // gap #2
    const resp: *const proto.CtrlHdr = @ptrFromInt(paging.physToVirt(ctrlq.resp_phys));
    if (resp.cmd_type != proto.RESP_OK_NODATA) {
        debug.klog("[virtio-gpu] createGuestBlob failed: 0x{X}\n", .{resp.cmd_type});
        return false;
    }
    return true;
}

/// Transfer 3D resource contents from host back to guest. Used to read pixels
/// rendered by Lavapipe (or any host-side 3D backend) into a guest-mmapped
/// blob — the explicit readback path when auto-dmabuf-sharing isn't engaged.
pub fn transferFromHost3D(ctx_id: u32, resource_id: u32, w: u32, h: u32, stride: u32) bool {
    var cmd = proto.TransferHost3D{
        .hdr = .{ .cmd_type = proto.CMD_TRANSFER_FROM_HOST_3D, .ctx_id = ctx_id },
        .box_w = w,
        .box_h = h,
        .box_d = 1,
        .resource_id = resource_id,
        .stride = stride,
    };
    var resp = proto.CtrlHdr{};
    if (!ctrlq.sendCmd(
        @as([*]const u8, @ptrCast(&cmd)),
        @sizeOf(proto.TransferHost3D),
        @as([*]u8, @ptrCast(&resp)),
        @sizeOf(proto.CtrlHdr),
    )) return false;
    if (resp.cmd_type != proto.RESP_OK_NODATA) {
        debug.klog("[virtio-gpu] transferFromHost3D failed: 0x{X}\n", .{resp.cmd_type});
        return false;
    }
    return true;
}
