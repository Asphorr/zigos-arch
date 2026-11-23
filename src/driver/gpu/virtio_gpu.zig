//! virtio-gpu: device bring-up, S3 resume and the state other code reads.
//! The driver's parts live in virtio_gpu/; this file re-exports their API.

const pci = @import("../bus/pci.zig");
const pmm = @import("../../mm/pmm.zig");
const paging = @import("../../mm/paging.zig");
const debug = @import("../../debug/debug.zig");
const msix = @import("../../irq/msix.zig");
const iommu = @import("../iommu.zig");
const apic = @import("../../irq/apic.zig");
const Deadline = @import("../../util/deadline.zig").Deadline;
const proto = @import("virtio_gpu/protocol.zig");
const ctrlq = @import("virtio_gpu/ctrlq.zig");
const present = @import("virtio_gpu/present.zig");
const scanout = @import("virtio_gpu/scanout.zig");
const cursor = @import("virtio_gpu/cursor.zig");
const context = @import("virtio_gpu/context.zig");

/// Completions may be waited for by interrupt (blockOn) rather than by
/// polling. False until kernelMain's global sti: init runs from early_fb in
/// boot phase 2, before apic.init enables the LAPIC, and an MSI sent then is
/// lost. main.zig sets it.
pub var msix_safe_to_use: bool = false;

// MSI-X statistics, read by procfs and the `gpu` CLI command. Delivery
// follows the table entry, which a sync submitter retargets at its own CPU.
pub var virtio_gpu_irq_count: u64 = 0;
pub var virtio_gpu_irq_per_cpu: [@import("../../cpu/smp.zig").MAX_CPUS]u64 =
    .{0} ** @import("../../cpu/smp.zig").MAX_CPUS;
/// Waiter wakes issued by the MSI-X handler.
pub var virtio_gpu_waiter_wakes: u64 = 0;

pub const virtio = @import("../bus/virtio.zig");
pub const Virtqueue = virtio.Queue;

pub const MAX_QUEUE_SIZE: u16 = 64;

// --- Driver state ---

pub var common_cfg: usize = 0; // MMIO address of common config
pub var notify_base: usize = 0; // MMIO address of notify region
pub var notify_off_multiplier: u32 = 0;

// PCI BDF cached at init so the lazy paths (initCursor, resourceCreate*Blob,
// late framebuffer attaches) can call iommu.dmaMap without re-walking the
// PCI cache. Same pattern as virtio_net / xhci / hda.
pub var pci_bus: u8 = 0;
pub var pci_dev: u8 = 0;
pub var pci_func: u8 = 0;

/// The six BAR registers (config 0x10..0x27), snapshotted at init. S3
/// (suspend-to-RAM) powers the PCI function down and the firmware does NOT
/// re-program device BARs on resume — a real OS saves/restores config space in
/// its PM callbacks. resumeFromS3 writes these back before re-enabling decode,
/// otherwise common_cfg/notify_base (kernel VAs mapping to the boot BAR phys)
/// point at a BAR that no longer decodes and every MMIO read returns 0 (→ device
/// reports no features → FEATURES_OK never sets). 64-bit BARs (BAR0/1, BAR2/3
/// here) are covered by restoring all six slots low-then-high in index order.
pub var saved_bars: [6]u32 = .{ 0, 0, 0, 0, 0, 0 };
pub var saved_pci_valid: bool = false;
pub var active: bool = false;
pub var hw_cursor_active: bool = false;

// 3D/Venus capability state
pub var has_virgl: bool = false;
pub var has_blob: bool = false;
pub var has_context_init: bool = false;
pub var has_venus: bool = false;
pub var has_virgl_capset: bool = false;
pub var framebuffer: [*]volatile u32 = undefined;
pub var width: u32 = 0;
pub var height: u32 = 0;
pub var current_resource_id: u32 = 0;

// Blob-backed scanout state (step 8d/8e).
//
// When `scanout_is_blob` is true the per-frame flush path skips
// TRANSFER_TO_HOST_2D — the host udmabuf-imports the blob memory so
// RESOURCE_FLUSH presents it directly. Two or three blobs page-flip (see
// blob_back); single-blob mode (step 8d) uses only index 0.
//
// The blobs themselves are allocated and exported by external code
// (gpu_compositor.zig allocates them via Venus as HOST3D blobs to bypass
// the QEMU 9.2 virgl_cmd_resource_create_blob success-check inversion
// that breaks BLOB_MEM_GUEST). This module just records the resource
// IDs so flushUnconditional / flushRectUnconditional know what to flip.
pub var scanout_is_blob: bool = false;
pub const MAX_BLOBS: u32 = 3;
pub var blob_count: u32 = 0; // 1 = single blob, 2 or 3 = page flip
pub var blob_front: u32 = 0; // which blob is currently scanned out

/// Which blob the next present shows; the frame is rendered into it. With
/// three blobs the host reads it neither now nor while the present before
/// is still in flight; with two it is the previous front, free only once
/// that present has been taken.
pub var blob_back: u32 = 0;

// --- Common config and queues ---

fn ccRead8(off: u32) u8 {
    return virtio.ccRead8(common_cfg, off);
}
fn ccWrite8(off: u32, v: u8) void {
    virtio.ccWrite8(common_cfg, off, v);
}
fn ccRead16(off: u32) u16 {
    return virtio.ccRead16(common_cfg, off);
}
fn ccWrite16(off: u32, v: u16) void {
    virtio.ccWrite16(common_cfg, off, v);
}
fn ccRead32(off: u32) u32 {
    return virtio.ccRead32(common_cfg, off);
}
fn ccWrite32(off: u32, v: u32) void {
    virtio.ccWrite32(common_cfg, off, v);
}

pub fn setupQueueInto(qi: u16, vq: *Virtqueue) bool {
    return vq.init(common_cfg, qi, MAX_QUEUE_SIZE);
}

/// Doorbell; Queue.init cached the queue's notify offset.
pub fn notifyQueue(qi: u16, vq: *const Virtqueue) void {
    virtio.notifyQueue(notify_base, vq.notify_off, notify_off_multiplier, qi);
}

// --- Public API ---

pub fn init(xres: u32, yres: u32) bool {
    // Idempotent: early-boot path (early_fb.tryVirtioGpu after Phase 2) can
    // call init at 1920×1080 to bring the boot screen graphical, then
    // desktop.taskEntry calls init again expecting the device to be ready.
    // Skip the whole device dance if we already armed the scanout.
    if (active) {
        debug.klog("[virtio-gpu] init: already active ({d}x{d}), requested {d}x{d} ignored\n", .{ width, height, xres, yres });
        return true;
    }
    // Name the locks so a panic / watchdog dump can identify who holds
    // them when the system wedges (the queue's own: ctrlq.init).
    @import("../../proc/spinlock.zig").registerMutex("virtio_gpu.present", &present.present_lock);
    @import("../../proc/spinlock.zig").registerLock("virtio_gpu.cursor_lock", &cursor.cursor_lock);
    debug.klog("[virtio-gpu] Scanning for device...\n", .{});

    // Find virtio-gpu PCI device via the bus cache.
    const dev_found = pci.findByVendorDevice(proto.VENDOR, proto.DEVICE) orelse {
        debug.klog("[virtio-gpu] No device found\n", .{});
        return false;
    };
    debug.klog("[virtio-gpu] Found at bus={d} dev={d}\n", .{ dev_found.bus, dev_found.dev });

    // Bus master + MEM/IO + INTx-disable (virtio uses MSI-X for the
    // controlq/cursorq via the common cap below).
    var bind = pci.bindDevice(dev_found);
    defer bind.deinit();
    pci_bus = dev_found.bus;
    pci_dev = dev_found.dev;
    pci_func = dev_found.func;

    // Switch to isolated DMA. Every subsequent DMA buffer must be
    // dmaMap'd before the device touches it, or the IOMMU faults.
    _ = iommu.enableIsolation(pci_bus, pci_dev, pci_func);

    // Parse PCI capabilities to find common config + notify region.
    const common_cap = pci.findVirtioCap(dev_found, virtio.CAP_COMMON_CFG) orelse {
        debug.klog("[virtio-gpu] No common config capability\n", .{});
        return false;
    };
    const notify_cap = pci.findVirtioCap(dev_found, virtio.CAP_NOTIFY_CFG) orelse {
        debug.klog("[virtio-gpu] No notify capability\n", .{});
        return false;
    };

    debug.klog("[virtio-gpu] Common: BAR{d} off=0x{X} len={d}\n", .{
        common_cap.bar, common_cap.offset, common_cap.length,
    });
    debug.klog("[virtio-gpu] Notify: BAR{d} off=0x{X} mult={d}\n", .{
        notify_cap.bar, notify_cap.offset, notify_cap.notify_off_mult,
    });

    // Map BARs
    const common_bar_phys = pci.mapBar(dev_found, common_cap.bar, 0x4000) orelse {
        debug.klog("[virtio-gpu] Failed to map common BAR\n", .{});
        return false;
    };
    common_cfg = common_bar_phys + common_cap.offset;

    // Notify may be in same or different BAR
    if (notify_cap.bar == common_cap.bar) {
        notify_base = common_bar_phys + notify_cap.offset;
    } else {
        const notify_bar_phys = pci.mapBar(dev_found, notify_cap.bar, 0x4000) orelse {
            debug.klog("[virtio-gpu] Failed to map notify BAR\n", .{});
            return false;
        };
        notify_base = notify_bar_phys + notify_cap.offset;
    }
    notify_off_multiplier = notify_cap.notify_off_mult;

    // Device init sequence
    ccWrite8(virtio.CC_DEVICE_STATUS, 0); // Reset
    ccWrite8(virtio.CC_DEVICE_STATUS, virtio.STATUS_ACKNOWLEDGE);
    ccWrite8(virtio.CC_DEVICE_STATUS, virtio.STATUS_ACKNOWLEDGE | virtio.STATUS_DRIVER);

    // Feature negotiation — read device features, accept 3D + transport features
    ccWrite32(virtio.CC_DEVICE_FEATURE_SELECT, 0);
    const dev_features_0 = ccRead32(virtio.CC_DEVICE_FEATURE);
    ccWrite32(virtio.CC_DEVICE_FEATURE_SELECT, 1);
    const dev_features_1 = ccRead32(virtio.CC_DEVICE_FEATURE);
    debug.klog("[virtio-gpu] Device features: 0x{X} 0x{X}\n", .{ dev_features_0, dev_features_1 });

    // GPU features (word 0, bits 0-4)
    var driver_features_0: u32 = 0;
    if (dev_features_0 & (@as(u32, 1) << proto.F_VIRGL) != 0) {
        has_virgl = true;
        driver_features_0 |= @as(u32, 1) << proto.F_VIRGL;
    }
    if (dev_features_0 & (@as(u32, 1) << proto.F_RESOURCE_BLOB) != 0) {
        has_blob = true;
        driver_features_0 |= @as(u32, 1) << proto.F_RESOURCE_BLOB;
    }
    if (dev_features_0 & (@as(u32, 1) << proto.F_CONTEXT_INIT) != 0) {
        has_context_init = true;
        driver_features_0 |= @as(u32, 1) << proto.F_CONTEXT_INIT;
    }
    // Accept EDID if offered (bit 1)
    if (dev_features_0 & (@as(u32, 1) << proto.F_EDID) != 0) {
        driver_features_0 |= @as(u32, 1) << proto.F_EDID;
    }
    // VIRTIO_F_RING_EVENT_IDX (bit 29) — negotiate so the driver can suppress
    // unnecessary interrupts AND control exactly which usedIdx triggers the
    // next IRQ via the avail-ring `used_event` slot. Workaround for
    // CVE-2024-3446's mem_reentrancy_guard side-effect: by going through the
    // event_idx notification path in QEMU, we may bypass the silent-drop
    // class that hits unconditional MSI-X delivery for SUBMIT_3D.
    var have_event_idx: bool = false;
    if (dev_features_0 & (@as(u32, 1) << proto.F_RING_EVENT_IDX) != 0) {
        driver_features_0 |= @as(u32, 1) << proto.F_RING_EVENT_IDX;
        have_event_idx = true;
    }

    // Transport features (word 1): VIRTIO_F_VERSION_1 = bit 0 of word 1 (global bit 32)
    var driver_features_1: u32 = 0;
    if (dev_features_1 & 1 != 0) {
        driver_features_1 |= 1; // VERSION_1
    }

    ccWrite32(virtio.CC_DRIVER_FEATURE_SELECT, 0);
    ccWrite32(virtio.CC_DRIVER_FEATURE, driver_features_0);
    ccWrite32(virtio.CC_DRIVER_FEATURE_SELECT, 1);
    ccWrite32(virtio.CC_DRIVER_FEATURE, driver_features_1);
    ccWrite8(virtio.CC_DEVICE_STATUS, virtio.STATUS_ACKNOWLEDGE | virtio.STATUS_DRIVER | virtio.STATUS_FEATURES_OK);

    if (has_virgl) debug.klog("[virtio-gpu] 3D features: VIRGL{s}{s}{s}\n", .{
        if (has_blob) " BLOB" else "",
        if (has_context_init) " CTX_INIT" else "",
        if (have_event_idx) " EVENT_IDX" else "",
    });
    ctrlq.use_event_idx = have_event_idx;

    // Check FEATURES_OK
    if (ccRead8(virtio.CC_DEVICE_STATUS) & virtio.STATUS_FEATURES_OK == 0) {
        debug.klog("[virtio-gpu] FEATURES_OK not set!\n", .{});
        return false;
    }

    // Disable global MSIX
    ccWrite16(virtio.CC_MSIX_CONFIG, 0xFFFF);

    // Setup control virtqueue (queue 0)
    if (!setupQueueInto(0, &ctrlq.ctrl_vq)) {
        debug.klog("[virtio-gpu] Failed to setup control queue\n", .{});
        ccWrite8(virtio.CC_DEVICE_STATUS, 0x80);
        return false;
    }
    // Map the queue rings into our IOVA space. Desc/avail share one page,
    // used has its own.
    _ = iommu.dmaMap(pci_bus, pci_dev, pci_func, ctrlq.ctrl_vq.desc_phys, 4096, .{});
    _ = iommu.dmaMap(pci_bus, pci_dev, pci_func, ctrlq.ctrl_vq.used_phys, 4096, .{});

    // The queue's slots and its large buffer.
    if (!ctrlq.init()) {
        debug.klog("[virtio-gpu] Failed to set up the control queue's buffers\n", .{});
        ccWrite8(virtio.CC_DEVICE_STATUS, 0x80);
        return false;
    }

    // Driver OK
    ccWrite8(virtio.CC_DEVICE_STATUS, virtio.STATUS_ACKNOWLEDGE | virtio.STATUS_DRIVER | virtio.STATUS_FEATURES_OK | virtio.STATUS_DRIVER_OK);
    debug.klog("[virtio-gpu] Device ready\n", .{});

    // Detect SHM BAR for blob resources
    if (has_blob) {
        context.detectShmBar(dev_found);
    }

    // Query capsets if 3D is available
    if (has_virgl) {
        context.queryCapsets();
    }

    // Get display info
    const display = scanout.getDisplayInfo() orelse {
        debug.klog("[virtio-gpu] No display available\n", .{});
        return false;
    };

    width = if (xres > 0) xres else display.width;
    height = if (yres > 0) yres else display.height;

    // Allocate guest framebuffer
    const fb_size = width * height * 4;
    scanout.fb_num_pages = (fb_size + 4095) / 4096;
    if (scanout.fb_num_pages > scanout.MAX_FB_PAGES) {
        debug.klog("[virtio-gpu] FB too large: {d} pages\n", .{scanout.fb_num_pages});
        return false;
    }

    const fb_virt = paging.allocGuestFB(scanout.fb_num_pages, &scanout.fb_page_phys) orelse {
        debug.klog("[virtio-gpu] Failed to allocate guest FB\n", .{});
        return false;
    };
    framebuffer = fb_virt;

    // Zero the framebuffer
    const fb_u8: [*]volatile u8 = @ptrCast(fb_virt);
    for (0..fb_size) |i| fb_u8[i] = 0;

    debug.klog("[virtio-gpu] FB: {d}x{d} ({d} pages)\n", .{ width, height, scanout.fb_num_pages });

    // Map every FB page into the device's IOVA space. allocGuestFB picks
    // scattered phys frames (one per page), so we iterate rather than
    // assuming contiguity.
    {
        var pi: u32 = 0;
        while (pi < scanout.fb_num_pages) : (pi += 1) {
            _ = iommu.dmaMap(pci_bus, pci_dev, pci_func, scanout.fb_page_phys[pi], 4096, .{});
        }
    }

    // Create display resources
    current_resource_id = 1;
    if (!scanout.setupDisplay(width, height)) return false;

    active = true;
    debug.klog("[virtio-gpu] Initialized {d}x{d}\n", .{ width, height });

    // Initialize hardware cursor
    _ = cursor.initCursor();

    // Wire MSI-X for the ctrl queue. Done here, AFTER all init-time
    // sendCmd calls (queryCapsets/getDisplayInfo/setupDisplay/initCursor)
    // have finished — those want the polled path because IF state during
    // boot is undefined and `sti; hlt` would force interrupts on too
    // early. From this point forward, sendCmd uses the IRQ-driven path.
    {
        if (msix.armOne(dev_found, 0, ctrlq.virtioGpuIrqHandler)) |armed| {
            // Point ctrl queue (0) at MSI-X table entry 0.
            ccWrite16(virtio.CC_QUEUE_SELECT, 0);
            ccWrite16(virtio.CC_QUEUE_MSIX_VECTOR, 0);
            if (ccRead16(virtio.CC_QUEUE_MSIX_VECTOR) == 0) {
                ctrlq.use_msix = true;
                ctrlq.msix_entry_addr = armed.entry_addr;
                debug.klog("[virtio-gpu] MSI-X armed: IDT vec=0x{X} dest=0x{X} entry=0x{X}\n", .{
                    armed.vector.irq_vector, armed.vector.addr, armed.entry_addr,
                });
            } else {
                debug.klog("[virtio-gpu] MSI-X vector write rejected, polled mode\n", .{});
            }
        } else {
            debug.klog("[virtio-gpu] MSI-X unavailable, polled mode\n", .{});
        }
    }

    // Snapshot the BARs for the S3 resume restore (see saved_bars). They were
    // programmed by firmware before init ran and don't change after enumeration,
    // so capturing once here is sufficient.
    {
        var bi: u8 = 0;
        while (bi < 6) : (bi += 1) {
            const off: u8 = 0x10 + bi * 4;
            saved_bars[bi] = pci.configRead(pci_bus, pci_dev, pci_func, off);
        }
        saved_pci_valid = true;
    }

    bind.commit();
    return true;
}

/// Re-initialize the virtio-gpu after an S3 (suspend-to-RAM) resume.
///
/// Across S3 the machine was powered down, so the device came back in its
/// power-on-reset state: virtqueues forgotten, every host resource (the 2D
/// scanout + any compositor blobs) destroyed, DRIVER_OK cleared, and the PCI
/// function dropped to D3. Guest RAM survived, though — the framebuffer pages,
/// the command/response buffers, and the virtqueue ring memory are all still
/// allocated and still mapped (page tables + IOMMU tables live in RAM). So we
/// only re-drive the device handshake, re-point the device at the (surviving)
/// rings, and re-create the 2D scanout bound to the (surviving) guest
/// framebuffer.
///
/// Called once from the S3 resume path (acpi/s3.zig) on the BSP with IF=0.
/// Forces the polled submit path for the duration: that path neither yields
/// (blockOn) nor depends on the GPU MSI-X IRQ / LAPIC tick, so the whole
/// re-init is atomic — no other task can run and observe a half-initialized
/// device — and it works before interrupts are re-enabled, exactly the context
/// the early-boot init() ran in before MSI-X was armed.
///
/// Resets to the plain 2D scanout regardless of the pre-suspend mode: if the
/// compositor had armed a blob double-buffer those host blobs are gone too, and
/// rebuilding them needs the Venus/virgl context path (a later step); dropping
/// to 2D restores a working desktop either way. Best-effort — returns false
/// (system stays headless, as before CP2c) on any failed step rather than
/// panicking.
pub fn resumeFromS3() bool {
    if (!active) return false; // GPU was never initialised — nothing to resume
    if (common_cfg == 0) return false;

    debug.klog("[virtio-gpu] S3 resume: re-initializing device ({d}x{d})\n", .{ width, height });

    // Bring the PCI function back to D0 + re-enable Bus Master/Memory (S3
    // dropped it to D3 and may have cleared the command register). Re-find the
    // device from the bus cache — same BDF we bound at init.
    const dev_found = pci.findByVendorDevice(proto.VENDOR, proto.DEVICE) orelse {
        debug.klog("[virtio-gpu] S3 resume: device not found\n", .{});
        return false;
    };

    // S3 cleared the device's PCI BARs. Restore them from the init snapshot
    // BEFORE re-enabling decode (Linux-style: disable I/O+Mem decode, write the
    // BARs, then bindDevice re-enables Memory + Bus Master). Without this,
    // common_cfg/notify_base map to a BAR that no longer decodes and every MMIO
    // read returns 0.
    if (saved_pci_valid) {
        const cmd_before = pci.configRead16(pci_bus, pci_dev, pci_func, 0x04);
        pci.configWrite16(pci_bus, pci_dev, pci_func, 0x04, cmd_before & ~@as(u16, 0x0003));
        var bi: u8 = 0;
        while (bi < 6) : (bi += 1) {
            const off: u8 = 0x10 + bi * 4;
            pci.configWrite(pci_bus, pci_dev, pci_func, off, saved_bars[bi]);
        }
        debug.klog("[virtio-gpu] S3 resume: PCI BARs restored (cmd was 0x{X})\n", .{cmd_before});
    }

    var bind = pci.bindDevice(dev_found);
    defer bind.deinit();

    // Force the polled submit path for every command below: no blockOn(.gpu_io)
    // yields, no dependence on the GPU IRQ or the LAPIC tick (neither may
    // deliver yet at this point in resume). Restored on exit so steady-state
    // frames go back to the fast IRQ-driven path.
    const saved_force_polled = ctrlq.force_polled;
    ctrlq.force_polled = true;
    defer ctrlq.force_polled = saved_force_polled;

    // --- Re-drive the device handshake (per virtio §3.1.1) ---
    // Unlike init (which runs against an already-reset device at boot), here the
    // device is live in DRIVER_OK, so the reset is NOT instant: we MUST wait for a
    // read-back of 0 before re-initialising, or the device rejects FEATURES_OK
    // while it's still tearing down its old state. Mirrors virtio_net/virtio_sound.
    ccWrite8(virtio.CC_DEVICE_STATUS, 0); // reset
    var d_reset = Deadline.ms(100, "virtio-gpu reset drain");
    while (ccRead8(virtio.CC_DEVICE_STATUS) != 0 and d_reset.live()) {}
    ccWrite8(virtio.CC_DEVICE_STATUS, virtio.STATUS_ACKNOWLEDGE);
    ccWrite8(virtio.CC_DEVICE_STATUS, virtio.STATUS_ACKNOWLEDGE | virtio.STATUS_DRIVER);

    // Re-negotiate features. The device advertises the same set as at boot, so
    // re-derive driver features from what it offers (keeps the accepted bits
    // consistent with has_*/use_event_idx already recorded by init).
    ccWrite32(virtio.CC_DEVICE_FEATURE_SELECT, 0);
    const dev_features_0 = ccRead32(virtio.CC_DEVICE_FEATURE);
    ccWrite32(virtio.CC_DEVICE_FEATURE_SELECT, 1);
    const dev_features_1 = ccRead32(virtio.CC_DEVICE_FEATURE);
    var driver_features_0: u32 = 0;
    if (dev_features_0 & (@as(u32, 1) << proto.F_VIRGL) != 0) driver_features_0 |= @as(u32, 1) << proto.F_VIRGL;
    if (dev_features_0 & (@as(u32, 1) << proto.F_RESOURCE_BLOB) != 0) driver_features_0 |= @as(u32, 1) << proto.F_RESOURCE_BLOB;
    if (dev_features_0 & (@as(u32, 1) << proto.F_CONTEXT_INIT) != 0) driver_features_0 |= @as(u32, 1) << proto.F_CONTEXT_INIT;
    if (dev_features_0 & (@as(u32, 1) << proto.F_EDID) != 0) driver_features_0 |= @as(u32, 1) << proto.F_EDID;
    if (dev_features_0 & (@as(u32, 1) << proto.F_RING_EVENT_IDX) != 0) driver_features_0 |= @as(u32, 1) << proto.F_RING_EVENT_IDX;
    var driver_features_1: u32 = 0;
    if (dev_features_1 & 1 != 0) driver_features_1 |= 1; // VERSION_1
    ccWrite32(virtio.CC_DRIVER_FEATURE_SELECT, 0);
    ccWrite32(virtio.CC_DRIVER_FEATURE, driver_features_0);
    ccWrite32(virtio.CC_DRIVER_FEATURE_SELECT, 1);
    ccWrite32(virtio.CC_DRIVER_FEATURE, driver_features_1);
    ccWrite8(virtio.CC_DEVICE_STATUS, virtio.STATUS_ACKNOWLEDGE | virtio.STATUS_DRIVER | virtio.STATUS_FEATURES_OK);
    if (ccRead8(virtio.CC_DEVICE_STATUS) & virtio.STATUS_FEATURES_OK == 0) {
        debug.klog("[virtio-gpu] S3 resume: FEATURES_OK rejected\n", .{});
        return false;
    }
    ccWrite16(virtio.CC_MSIX_CONFIG, 0xFFFF);

    // --- Re-program the control virtqueue onto its EXISTING rings (leak-free) ---
    // Everything in flight died with the controller: the queue forgets it
    // (under its lock), then the present engine its batch.
    if (!ctrlq.reprogramAfterDeviceReset(common_cfg)) {
        debug.klog("[virtio-gpu] S3 resume: ctrl queue reprogram failed\n", .{});
        return false;
    }
    present.resetAfterDeviceReset();

    // DRIVER_OK — device is live again.
    ccWrite8(virtio.CC_DEVICE_STATUS, virtio.STATUS_ACKNOWLEDGE | virtio.STATUS_DRIVER | virtio.STATUS_FEATURES_OK | virtio.STATUS_DRIVER_OK);

    // Re-point the ctrl-queue MSI-X vector (the reset cleared it to 0xFFFF). The
    // IDT vector + MSI-X table entry themselves survive in RAM; only the device's
    // per-queue vector register needs re-arming. The setup cmds below still run
    // polled (forced above); this just restores fast completions for steady state.
    if (ctrlq.use_msix and ctrlq.msix_entry_addr != 0) {
        ccWrite16(virtio.CC_QUEUE_SELECT, 0);
        ccWrite16(virtio.CC_QUEUE_MSIX_VECTOR, 0);
        if (ccRead16(virtio.CC_QUEUE_MSIX_VECTOR) != 0) {
            ctrlq.use_msix = false;
            debug.klog("[virtio-gpu] S3 resume: MSI-X re-arm rejected, polled steady state\n", .{});
        }
    }

    // --- Drop any blob-scanout state and re-create the plain 2D scanout on the
    // surviving guest framebuffer. The device's resource-id space was reset, so
    // reusing current_resource_id is fine. ---
    scanout_is_blob = false;
    blob_count = 0;
    blob_front = 0;
    blob_back = 0;
    scanout.original_2d_resource_id = 0;
    skip_external_flush = false; // the 2D desktop owns flushing again
    if (!scanout.setupDisplay(width, height)) {
        debug.klog("[virtio-gpu] S3 resume: setupDisplay failed\n", .{});
        return false;
    }

    // The hardware-cursor resource is gone too; leave it disabled so moveCursor
    // no-ops (SDL's show-cursor=on covers the pointer). A leak-free cursor
    // re-arm reusing the surviving image buffer is a later refinement.
    hw_cursor_active = false;

    // --- Clear the wedge state so flushes resume immediately, then repaint the
    // whole screen from the surviving framebuffer. ---
    present.consecutive_flush_failures = 0;
    present.wedged = false;
    present.flushUnconditional();

    bind.commit();
    debug.klog("[virtio-gpu] S3 resume: device re-initialized, display restored\n", .{});
    return true;
}

/// When true, public flush()/flushRect() calls become no-ops. The
/// mode-9 GPU compositor sets this flag so its own writes are the only
/// thing reaching the screen each frame; it uses flushUnconditional()
/// to bypass the gate when it actually wants to flush.
pub var skip_external_flush: bool = false;

/// Move hardware cursor to (x, y). Lightweight — just sends position via cursor queue.
pub var cursor_hidden: bool = false;

// --- API of the parts ---

pub const queueBusy = ctrlq.busy;
pub const releaseTask = ctrlq.releaseTask;
pub const CMD_RESOURCE_CREATE_3D = proto.CMD_RESOURCE_CREATE_3D;
pub const GetCapsetInfo = proto.GetCapsetInfo;
pub const RespCapsetInfo = proto.RespCapsetInfo;
pub const ResourceCreate3D = proto.ResourceCreate3D;
pub const sendCmd = ctrlq.sendCmd;
pub const PresentStats = present.PresentStats;
pub const takePresentStats = present.takePresentStats;
pub const waitPresentIdle = present.waitPresentIdle;
pub const setScanoutBlob = scanout.setScanoutBlob;
pub const resourceFlush = scanout.resourceFlush;
pub const sweepWanted = ctrlq.sweepWanted;
pub const tickSweep = ctrlq.tickSweep;
pub const dumpWaiterForTarget = ctrlq.dumpWaiterForTarget;
pub const resourceUnref = scanout.resourceUnref;
pub const dropOriginal2DScanout = scanout.dropOriginal2DScanout;
pub const armBlobScanout = scanout.armBlobScanout;
pub const changeMode = scanout.changeMode;
pub const flush = present.flush;
pub const flushUnconditional = present.flushUnconditional;
pub const flushRect = present.flushRect;
pub const flushRectUnconditional = present.flushRectUnconditional;
pub const initCursor = cursor.initCursor;
pub const moveCursor = cursor.moveCursor;
pub const hideCursor = cursor.hideCursor;
pub const showCursor = cursor.showCursor;
pub const alloc3DResourceId = context.alloc3DResourceId;
pub const ctxCreate = context.ctxCreate;
pub const ctxDestroy = context.ctxDestroy;
pub const ctxAttachResource = context.ctxAttachResource;
pub const submit3D = context.submit3D;
pub const resourceCreateBlob = context.resourceCreateBlob;
pub const MemoryBlob = context.MemoryBlob;
pub const resourceCreateMemoryBlob = context.resourceCreateMemoryBlob;
pub const BlobOwner = context.BlobOwner;
pub const resourceMapBlob = context.resourceMapBlob;
pub const resourceUnmapBlob = context.resourceUnmapBlob;
pub const releaseOwnedBlobs = context.releaseOwnedBlobs;
pub const hostmemStats = context.hostmemStats;
pub const resourceCreate3D = context.resourceCreate3D;
pub const transferToHost3D = context.transferToHost3D;
pub const resourceCreateGuestBlob = context.resourceCreateGuestBlob;
pub const transferFromHost3D = context.transferFromHost3D;
