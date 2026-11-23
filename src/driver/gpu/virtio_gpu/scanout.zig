//! The guest framebuffer and scanout 0: 2D resources, blob scanout and
//! mode changes.

const std = @import("std");
const paging = @import("../../../mm/paging.zig");
const debug = @import("../../../debug/debug.zig");
const iommu = @import("../../iommu.zig");
const perf = @import("../../../debug/perf.zig");
const vg = @import("../virtio_gpu.zig");
const proto = @import("protocol.zig");
const ctrlq = @import("ctrlq.zig");
const present = @import("present.zig");

// Framebuffer state
pub const MAX_FB_PAGES: u32 = 2048; // 8MB for 1920x1080x4
pub var fb_page_phys: [MAX_FB_PAGES]usize = [_]usize{0} ** MAX_FB_PAGES;
pub var fb_num_pages: u32 = 0;
pub var blob_virt: [vg.MAX_BLOBS][*]volatile u32 = .{ undefined, undefined, undefined };
pub var blob_resource_ids: [vg.MAX_BLOBS]u32 = .{ 0, 0, 0 };

/// The present of blob_back has gone to the host.
pub fn blobsFlipped() void {
    const old_front = vg.blob_front;
    vg.blob_front = vg.blob_back;
    vg.blob_back = if (vg.blob_count >= 3) 3 - vg.blob_front - old_front else old_front;
    vg.framebuffer = blob_virt[vg.blob_back];
    vg.current_resource_id = blob_resource_ids[vg.blob_back];
}

// Saved id of the original 2D scanout resource (the one current_resource_id
// pointed at before armBlobScanout overwrote it). dropOriginal2DScanout
// uses this to detach + unref the right host-side resource without
// touching the blob we just promoted.
pub var original_2d_resource_id: u32 = 0;

pub fn getDisplayInfo() ?proto.Rect {
    var cmd = proto.CtrlHdr{ .cmd_type = proto.CMD_GET_DISPLAY_INFO };
    var resp: proto.DisplayInfo = undefined;
    @memset(@as([*]u8, @ptrCast(&resp))[0..@sizeOf(proto.DisplayInfo)], 0);

    if (!ctrlq.sendCmd(
        @as([*]const u8, @ptrCast(&cmd)),
        @sizeOf(proto.CtrlHdr),
        @as([*]u8, @ptrCast(&resp)),
        @sizeOf(proto.DisplayInfo),
    )) return null;

    if (resp.hdr.cmd_type != proto.RESP_OK_DISPLAY_INFO) {
        debug.klog("[virtio-gpu] GET_DISPLAY_INFO failed: 0x{X}\n", .{resp.hdr.cmd_type});
        return null;
    }

    for (0..16) |i| {
        if (resp.pmodes[i].enabled != 0) {
            debug.klog("[virtio-gpu] Display {d}: {d}x{d}\n", .{
                i, resp.pmodes[i].r.width, resp.pmodes[i].r.height,
            });
            return resp.pmodes[i].r;
        }
    }
    return null;
}

pub fn resourceCreate2D(resource_id: u32, w: u32, h: u32) bool {
    var cmd = proto.ResourceCreate2D{
        .hdr = .{ .cmd_type = proto.CMD_RESOURCE_CREATE_2D },
        .resource_id = resource_id,
        .format = proto.FORMAT_B8G8R8X8_UNORM,
        .width = w,
        .height = h,
    };
    return ctrlq.sendSimpleCmd(@as([*]const u8, @ptrCast(&cmd)), @sizeOf(proto.ResourceCreate2D));
}

/// Most scatter-gather entries one ATTACH_BACKING carries: what fits the
/// large buffer.
const ATTACH_MAX_ENTRIES: usize = (ctrlq.LARGE_CMD_MAX - @sizeOf(proto.AttachBacking)) / @sizeOf(proto.MemEntry);

pub fn attachBacking(resource_id: u32, pages: []const usize, page_count: u32) bool {
    const big = ctrlq.largeAcquire() orelse return false;
    defer big.release();
    // The entries go straight into the large buffer, contiguous pages
    // merged into one.
    const entries: [*]volatile proto.MemEntry = @ptrFromInt(@intFromPtr(big.cmd()) + @sizeOf(proto.AttachBacking));
    var nr: u32 = 0;
    var i: u32 = 0;
    while (i < page_count and nr < ATTACH_MAX_ENTRIES) {
        const start = pages[i];
        var length: usize = 4096;
        i += 1;
        while (i < page_count and pages[i] == start + length) : (i += 1) {
            length += 4096;
        }
        entries[nr] = .{ .addr = start, .length = @truncate(length), .padding = 0 };
        nr += 1;
    }
    if (i < page_count) {
        debug.klog("[virtio-gpu] ATTACH_BACKING: {d} pages need more than {d} entries\n", .{ page_count, ATTACH_MAX_ENTRIES });
        return false;
    }
    debug.klog("[virtio-gpu] Merged {d} pages into {d} entries\n", .{ page_count, nr });
    const attach: *volatile proto.AttachBacking = @ptrCast(@alignCast(big.cmd()));
    attach.* = .{ .hdr = .{ .cmd_type = proto.CMD_RESOURCE_ATTACH_BACKING }, .resource_id = resource_id, .nr_entries = nr };
    const total_len = @sizeOf(proto.AttachBacking) + @as(usize, nr) * @sizeOf(proto.MemEntry);
    if (!big.run(total_len, @sizeOf(proto.CtrlHdr))) return false;
    const resp = big.respHdr().cmd_type;
    if (resp != proto.RESP_OK_NODATA) {
        debug.klog("[virtio-gpu] ATTACH_BACKING failed: 0x{X}\n", .{resp});
        return false;
    }
    return true;
}

/// ATTACH_BACKING of one contiguous range (the staging buffer, the cursor).
pub fn attachBackingContiguous(resource_id: u32, base_phys: usize, npages: u32) bool {
    const cmd = proto.AttachBackingOne{
        .attach = .{ .hdr = .{ .cmd_type = proto.CMD_RESOURCE_ATTACH_BACKING }, .resource_id = resource_id, .nr_entries = 1 },
        .entry = .{ .addr = base_phys, .length = @intCast(@as(usize, npages) * 4096), .padding = 0 },
    };
    var resp: proto.CtrlHdr = .{};
    if (!ctrlq.send(std.mem.asBytes(&cmd), std.mem.asBytes(&resp))) return false;
    if (resp.cmd_type != proto.RESP_OK_NODATA) {
        debug.klog("[virtio-gpu] ATTACH_BACKING of res {d} failed: 0x{X}\n", .{ resource_id, resp.cmd_type });
        return false;
    }
    return true;
}

pub fn setScanout(resource_id: u32, w: u32, h: u32) bool {
    var cmd = proto.SetScanout{
        .hdr = .{ .cmd_type = proto.CMD_SET_SCANOUT },
        .r = .{ .x = 0, .y = 0, .width = w, .height = h },
        .scanout_id = 0,
        .resource_id = resource_id,
    };
    return ctrlq.sendSimpleCmd(@as([*]const u8, @ptrCast(&cmd)), @sizeOf(proto.SetScanout));
}

/// Point a scanout slot at a blob resource. Used by Vulkan apps that
/// render to a Venus-backed blob and want it displayed directly without
/// going through a CPU readback. format is a virtio_gpu_formats enum
/// (e.g. R8G8B8A8_UNORM=67). stride is bytes-per-row.
pub fn setScanoutBlob(scanout_id: u32, resource_id: u32, w: u32, h: u32, format: u32, stride: u32) bool {
    var cmd = proto.SetScanoutBlob{
        .hdr = .{ .cmd_type = proto.CMD_SET_SCANOUT_BLOB },
        .r = .{ .x = 0, .y = 0, .width = w, .height = h },
        .scanout_id = scanout_id,
        .resource_id = resource_id,
        .width = w,
        .height = h,
        .format = format,
        .strides = .{ stride, 0, 0, 0 },
    };
    return ctrlq.sendSimpleCmd(@as([*]const u8, @ptrCast(&cmd)), @sizeOf(proto.SetScanoutBlob));
}

/// Tell the host display to re-read scanout contents from a resource.
/// After updating a scanned-out resource, call this to make the change
/// visible. Public wrapper of the existing internal resourceFlushCmd.
pub fn resourceFlush(resource_id: u32, w: u32, h: u32) bool {
    return resourceFlushCmd(resource_id, 0, 0, w, h);
}

pub fn transferToHost(resource_id: u32, x: u32, y: u32, w: u32, h: u32) bool {
    // offset = byte position in backing store where the rect's data starts
    // For full-width transfers (x=0, w=width), offset = y * stride
    const offset: u64 = @as(u64, y) * @as(u64, vg.width) * 4 + @as(u64, x) * 4;
    var cmd = proto.TransferToHost2D{
        .hdr = .{ .cmd_type = proto.CMD_TRANSFER_TO_HOST_2D },
        .r = .{ .x = x, .y = y, .width = w, .height = h },
        .offset = offset,
        .resource_id = resource_id,
        .padding = 0,
    };
    return ctrlq.sendSimpleCmd(@as([*]const u8, @ptrCast(&cmd)), @sizeOf(proto.TransferToHost2D));
}

pub fn resourceFlushCmd(resource_id: u32, x: u32, y: u32, w: u32, h: u32) bool {
    // Previously FENCE-flagged for implicit vblank sync. Measured cost
    // (perf.flush_rect): mean 86 M cycles ≈ 28 ms per call on QEMU's
    // GTK display backend — the fence response blocks until host
    // frame-done, and the desktop task is charged as busy for the
    // entire wait. At ~21 flushes/sec that was 60 %+ of one CPU spent
    // blocking on host vsync. Dropped the flag: tearing on the CPU
    // compositor path is invisible at UI refresh rates, and the GPU
    // compositor (mode 9, blob scanout) uses its own fence ping-pong
    // (`project_venus_fence_lies.md`) so it doesn't rely on this one.
    var cmd = proto.ResourceFlush{
        .hdr = .{
            .cmd_type = proto.CMD_RESOURCE_FLUSH,
        },
        .r = .{ .x = x, .y = y, .width = w, .height = h },
        .resource_id = resource_id,
        .padding = 0,
    };
    return ctrlq.sendSimpleCmd(@as([*]const u8, @ptrCast(&cmd)), @sizeOf(proto.ResourceFlush));
}

/// Set up display: create resource, attach backing, set scanout.
pub fn setupDisplay(w: u32, h: u32) bool {
    debug.klog("[virtio-gpu] Creating resource {d} ({d}x{d})...\n", .{ vg.current_resource_id, w, h });
    if (!resourceCreate2D(vg.current_resource_id, w, h)) {
        debug.klog("[virtio-gpu] RESOURCE_CREATE_2D failed\n", .{});
        return false;
    }
    present.ensureStaging();
    debug.klog("[virtio-gpu] Attaching {d} pages ({s} backing)...\n", .{
        fb_num_pages,
        if (present.staging_active) @as([]const u8, "staging") else "live-FB",
    });
    const attached = if (present.staging_active)
        attachBackingContiguous(vg.current_resource_id, present.staging_phys, present.staging_pages)
    else
        attachBacking(vg.current_resource_id, fb_page_phys[0..fb_num_pages], fb_num_pages);
    if (!attached) {
        debug.klog("[virtio-gpu] ATTACH_BACKING failed\n", .{});
        return false;
    }
    debug.klog("[virtio-gpu] Setting scanout...\n", .{});
    if (!setScanout(vg.current_resource_id, w, h)) {
        debug.klog("[virtio-gpu] SET_SCANOUT failed\n", .{});
        return false;
    }
    present.copyRectToStaging(0, 0, w, h);
    _ = transferToHost(vg.current_resource_id, 0, 0, w, h);
    _ = resourceFlushCmd(vg.current_resource_id, 0, 0, w, h);
    return true;
}

/// pub: the GPU syscall layer (syscall/gpu.zig) calls this on its
/// guest-blob error-rollback paths — a created-but-unusable resource must
/// be unref'd BEFORE its guest backing pages go back to the PMM, or the
/// host renderer keeps a reference into recycled frames.
pub fn resourceUnref(resource_id: u32) bool {
    var cmd = proto.ResourceId{
        .hdr = .{ .cmd_type = proto.CMD_RESOURCE_UNREF },
        .resource_id = resource_id,
    };
    return ctrlq.sendSimpleCmd(@as([*]const u8, @ptrCast(&cmd)), @sizeOf(proto.ResourceId));
}

pub fn detachBacking(resource_id: u32) bool {
    var cmd = proto.ResourceId{
        .hdr = .{ .cmd_type = proto.CMD_RESOURCE_DETACH_BACKING },
        .resource_id = resource_id,
    };
    return ctrlq.sendSimpleCmd(@as([*]const u8, @ptrCast(&cmd)), @sizeOf(proto.ResourceId));
}

/// Tear down the original 2D scanout resource. Called by the compositor
/// once it has its own blob-backed scanout armed and no longer needs
/// the 2D resource. Uses original_2d_resource_id captured by armBlobScanout
/// before it overwrote current_resource_id with the blob res id —
/// otherwise we'd detach the blob we just promoted. Cursor stays
/// untouched (separate resource id). Skips setScanout(0,0,0) because
/// scanout 0 is now armed at the blob and we don't want to disable it.
pub fn dropOriginal2DScanout() void {
    if (original_2d_resource_id == 0) return;
    _ = detachBacking(original_2d_resource_id);
    _ = resourceUnref(original_2d_resource_id);
    original_2d_resource_id = 0;
}

/// Switch scanout 0 to a caller-provided blob resource (typically a
/// HOST3D blob allocated via Venus, since QEMU 9.2's virgl path has a
/// success-check inversion in `virgl_cmd_resource_create_blob` that
/// breaks BLOB_MEM_GUEST creates). Caller has already done:
///   - resourceCreateBlob (HOST3D, blob_id=mem_id, MAPPABLE|CROSS_DEVICE)
///   - ctxAttachResource
///   - resourceMapBlob → kvirt[i]
/// for each of `n_blobs` resources. This function just disables the
/// existing scanout, points it at blob 0, sets the public state.
///
/// On entry: framebuffer is still the old 2D backing.
/// On success: framebuffer points at the back blob (the one the next
/// frame should render into) and flushUnconditional handles flips.
pub fn armBlobScanout(res_ids: []const u32, virts: []const [*]volatile u32, n: u32) bool {
    if (!vg.active) return false;
    if (n < 1 or n > vg.MAX_BLOBS) return false;
    if (res_ids.len < n or virts.len < n) return false;
    if (vg.scanout_is_blob) return false; // already armed; tear down first via dropBlobScanout

    // Capture the original 2D scanout resource before we overwrite
    // current_resource_id with the blob below. dropOriginal2DScanout
    // reads this to release the right host-side resource later.
    if (original_2d_resource_id == 0) original_2d_resource_id = vg.current_resource_id;

    var i: u32 = 0;
    while (i < n) : (i += 1) {
        blob_resource_ids[i] = res_ids[i];
        blob_virt[i] = virts[i];
    }

    // Disable the existing scanout, then point slot 0 at blob 0. Format
    // matches the original 2D scanout (B8G8R8X8 = XRGB8888): the kernel
    // writes pixels as u32 0x00RRGGBB, alpha byte is unused. Picking
    // B8G8R8A8 instead would make the display interpret the 0x00 alpha
    // as fully transparent and the screen would render blank.
    _ = setScanout(0, 0, 0);
    if (!setScanoutBlob(0, blob_resource_ids[0], vg.width, vg.height, proto.FORMAT_B8G8R8X8_UNORM, vg.width * 4)) {
        debug.klog("[virtio-gpu] armBlobScanout: setScanoutBlob FAILED\n", .{});
        // Re-arm 2D fallback so we don't black-screen.
        _ = setScanout(vg.current_resource_id, vg.width, vg.height);
        return false;
    }

    // After arm, `framebuffer` points at the back blob (compositor's
    // write target). Single-buffer: back == front == blob[0]. Double-
    // buffer: blob[0] is initial front (host displays it), blob[1] is
    // back; the first flushUnconditional() page-flips them.
    vg.blob_count = n;
    vg.blob_front = 0;
    vg.blob_back = if (n >= 2) 1 else 0;
    vg.scanout_is_blob = true;
    vg.framebuffer = blob_virt[vg.blob_back];
    vg.current_resource_id = blob_resource_ids[vg.blob_back];

    // First flush so the host's GL surface picks up the front blob's
    // contents (whatever the compositor pre-painted into it).
    _ = resourceFlushCmd(blob_resource_ids[0], 0, 0, vg.width, vg.height);
    debug.klog("[virtio-gpu] armBlobScanout: ok n={d} {d}x{d} res0={d}\n", .{ n, vg.width, vg.height, blob_resource_ids[0] });
    return true;
}

/// Change display resolution. Returns true if successful.
pub fn changeMode(new_w: u32, new_h: u32) bool {
    if (!vg.active) return false;
    debug.klog("[virtio-gpu] Changing to {d}x{d}\n", .{ new_w, new_h });

    // Tear down old display
    debug.klog("[virtio-gpu] Disabling scanout...\n", .{});
    _ = setScanout(0, 0, 0); // Disable scanout (resource_id=0)
    debug.klog("[virtio-gpu] Detaching backing...\n", .{});
    _ = detachBacking(vg.current_resource_id);
    debug.klog("[virtio-gpu] Unref resource {d}...\n", .{vg.current_resource_id});
    _ = resourceUnref(vg.current_resource_id);

    // Unmap old FB pages from device IOVA before they go back to PMM.
    {
        var pi: u32 = 0;
        while (pi < fb_num_pages) : (pi += 1) {
            iommu.dmaUnmap(vg.pci_bus, vg.pci_dev, vg.pci_func, fb_page_phys[pi], 4096);
        }
    }

    // Free old guest FB pages
    debug.klog("[virtio-gpu] Freeing old FB...\n", .{});
    paging.freeGuestFB(fb_num_pages);

    // Allocate new guest FB
    const fb_size = new_w * new_h * 4;
    fb_num_pages = (fb_size + 4095) / 4096;
    if (fb_num_pages > MAX_FB_PAGES) return false;

    const fb_virt = paging.allocGuestFB(fb_num_pages, &fb_page_phys) orelse return false;
    vg.framebuffer = fb_virt;
    vg.width = new_w;
    vg.height = new_h;

    // Map new FB pages into device IOVA.
    {
        var pi: u32 = 0;
        while (pi < fb_num_pages) : (pi += 1) {
            _ = iommu.dmaMap(vg.pci_bus, vg.pci_dev, vg.pci_func, fb_page_phys[pi], 4096, .{});
        }
    }

    // Zero new FB
    const fb_u8: [*]volatile u8 = @ptrCast(fb_virt);
    for (0..fb_size) |i| fb_u8[i] = 0;

    // Create new display resources
    vg.current_resource_id += 1;
    if (!setupDisplay(new_w, new_h)) return false;

    debug.klog("[virtio-gpu] Mode changed to {d}x{d}\n", .{ new_w, new_h });
    return true;
}
