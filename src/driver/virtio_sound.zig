// virtio-sound (virtio v1.2 §5.14) — output-only driver.
//
// Probes a virtio-sound PCI device, enumerates its PCM streams, picks the
// first OUTPUT stream, configures it for 22050 Hz S16 stereo (matches DOOM's
// mixer + the existing AC97 audioWrite contract), and then accepts raw S16
// stereo frames through `writeSamples`. Each call submits a fixed-size chunk
// to the TX virtqueue; the device consumes asynchronously and returns the
// descriptor when it's done. We poll the used ring on each writeSamples so
// reclamation is bounded.
//
// What's intentionally not implemented:
//   - Capture (RX queue is created but never used).
//   - Jack remap, channel maps beyond defaults.
//   - Format negotiation: we hardcode S16 stereo @ 22050 Hz.
//   - Multi-stream output (we lock onto the first output stream).
//   - MSI-X (we poll-only — no IRQ handler is registered).

const io = @import("../io.zig");
const pci = @import("pci.zig");
const pmm = @import("../mm/pmm.zig");
const paging = @import("../mm/paging.zig");
const debug = @import("../debug/debug.zig");
const process = @import("../proc/process.zig");
const spinlock = @import("../proc/spinlock.zig");
const iommu = @import("../cpu/mmu/iommu.zig");

// --- Constants ---

const VIRTIO_VENDOR: u16 = 0x1AF4;
// Modern virtio devices use PCI device ID = 0x1040 + virtio_device_id.
// virtio-sound is virtio device id 25 (per spec §5).
const VIRTIO_SOUND_DEVICE_ID: u16 = 0x1040 + 25;

const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;
const VIRTIO_PCI_CAP_ISR_CFG: u8 = 3;
const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4;

const STATUS_ACKNOWLEDGE: u8 = 1;
const STATUS_DRIVER: u8 = 2;
const STATUS_DRIVER_OK: u8 = 4;
const STATUS_FEATURES_OK: u8 = 8;
const STATUS_FAILED: u8 = 128;

const VRING_DESC_F_NEXT: u16 = 1;
const VRING_DESC_F_WRITE: u16 = 2;

// Common config layout (modern virtio).
const CC_DEVICE_FEATURE_SELECT: u32 = 0x00;
const CC_DEVICE_FEATURE: u32 = 0x04;
const CC_DRIVER_FEATURE_SELECT: u32 = 0x08;
const CC_DRIVER_FEATURE: u32 = 0x0C;
const CC_MSIX_CONFIG: u32 = 0x10;
const CC_NUM_QUEUES: u32 = 0x12;
const CC_DEVICE_STATUS: u32 = 0x14;
const CC_CONFIG_GENERATION: u32 = 0x15;
const CC_QUEUE_SELECT: u32 = 0x16;
const CC_QUEUE_SIZE: u32 = 0x18;
const CC_QUEUE_MSIX_VECTOR: u32 = 0x1A;
const CC_QUEUE_ENABLE: u32 = 0x1C;
const CC_QUEUE_NOTIFY_OFF: u32 = 0x1E;
const CC_QUEUE_DESC_LO: u32 = 0x20;
const CC_QUEUE_DESC_HI: u32 = 0x24;
const CC_QUEUE_AVAIL_LO: u32 = 0x28;
const CC_QUEUE_AVAIL_HI: u32 = 0x2C;
const CC_QUEUE_USED_LO: u32 = 0x30;
const CC_QUEUE_USED_HI: u32 = 0x34;

// Virtqueue ordering (per virtio-sound spec §5.14.2).
const VQ_CONTROL: u16 = 0;
const VQ_EVENT: u16 = 1;
const VQ_TX: u16 = 2;
const VQ_RX: u16 = 3;

// Control plane request codes.
const VIRTIO_SND_R_JACK_INFO: u32 = 0x0001;
const VIRTIO_SND_R_PCM_INFO: u32 = 0x0100;
const VIRTIO_SND_R_PCM_SET_PARAMS: u32 = 0x0101;
const VIRTIO_SND_R_PCM_PREPARE: u32 = 0x0102;
const VIRTIO_SND_R_PCM_RELEASE: u32 = 0x0103;
const VIRTIO_SND_R_PCM_START: u32 = 0x0104;
const VIRTIO_SND_R_PCM_STOP: u32 = 0x0105;
const VIRTIO_SND_R_CHMAP_INFO: u32 = 0x0200;

const VIRTIO_SND_S_OK: u32 = 0x8000;
const VIRTIO_SND_S_BAD_MSG: u32 = 0x8001;
const VIRTIO_SND_S_NOT_SUPP: u32 = 0x8002;
const VIRTIO_SND_S_IO_ERR: u32 = 0x8003;

const VIRTIO_SND_PCM_FMT_S16: u8 = 5;
const VIRTIO_SND_PCM_RATE_22050: u8 = 4;
const VIRTIO_SND_PCM_RATE_44100: u8 = 6;

// PCM stream direction (in the virtio_snd_pcm_info struct).
const VIRTIO_SND_D_OUTPUT: u8 = 0;
const VIRTIO_SND_D_INPUT: u8 = 1;

// --- Wire-protocol structures ---

const SndHdr = extern struct {
    code: u32 align(1),
};

const SndPcmHdr = extern struct {
    hdr: SndHdr,
    stream_id: u32 align(1),
};

const SndQueryInfo = extern struct {
    hdr: SndHdr,
    start_id: u32 align(1),
    count: u32 align(1),
    size: u32 align(1),
};

const SndPcmInfo = extern struct {
    hdr: extern struct {
        hda_fn_nid: u32 align(1),
    },
    features: u32 align(1),
    formats: u64 align(1),
    rates: u64 align(1),
    direction: u8,
    channels_min: u8,
    channels_max: u8,
    padding: [5]u8,
};

const SndPcmSetParams = extern struct {
    hdr: SndPcmHdr,
    buffer_bytes: u32 align(1),
    period_bytes: u32 align(1),
    features: u32 align(1),
    channels: u8,
    format: u8,
    rate: u8,
    padding: u8 = 0,
};

const SndPcmStatus = extern struct {
    status: u32 align(1),
    latency_bytes: u32 align(1),
};

/// First descriptor of every TX submission. The device reads stream_id to
/// route the bytes to the right PCM stream — same struct shape applies to
/// RX (capture) but we don't use that direction.
const SndPcmXfer = extern struct {
    stream_id: u32 align(1),
};

const SndConfig = extern struct {
    jacks: u32 align(1),
    streams: u32 align(1),
    chmaps: u32 align(1),
};

// --- Virtqueue (shared with virtio_gpu via driver/virtio.zig) ---

const virtio = @import("virtio.zig");
const VirtqDesc = virtio.VirtqDesc;
const Virtqueue = virtio.Queue;

const MAX_QUEUE_SIZE: u16 = 64;
const NUM_TX_BUFS: u16 = 16;
const TX_BUF_SIZE: u32 = 4096; // ~46ms at 22050 Hz S16 stereo (≈22ms at 44100)

// --- Driver state ---

pub var initialized: bool = false;

var common_base: usize = 0;
var notify_base: usize = 0;
var notify_off_multiplier: u32 = 0;
var device_base: usize = 0;

var ctrl_vq: Virtqueue = .{};
var tx_vq: Virtqueue = .{};

// Single-buffer scratch for control-queue cmd/resp (we serialize via ctrl_lock).
var ctrl_cmd_phys: usize = 0;
var ctrl_resp_phys: usize = 0;

// TX buffer pool. Each tx slot owns a {xfer_hdr, audio_data, status} triple
// of contiguous physical buffers to simplify lifecycle: when the device
// returns descriptor d_xfer, the whole triple is reclaimed atomically.
var tx_pool_phys: [NUM_TX_BUFS]usize = .{0} ** NUM_TX_BUFS;
var tx_xfer_hdr_phys: [NUM_TX_BUFS]usize = .{0} ** NUM_TX_BUFS;
var tx_status_phys: [NUM_TX_BUFS]usize = .{0} ** NUM_TX_BUFS;
var tx_buffer_idx_for_desc: [MAX_QUEUE_SIZE]u8 = .{0xFF} ** MAX_QUEUE_SIZE;
var tx_buffer_inflight: [NUM_TX_BUFS]bool = .{false} ** NUM_TX_BUFS;

var output_stream_id: u32 = 0xFFFFFFFF;

var ctrl_lock: spinlock.SpinLock = .{};
var tx_lock: spinlock.SpinLock = .{};

// --- MMIO helpers ---

fn ccWrite8(off: u32, v: u8) void {
    const p: *volatile u8 = @ptrFromInt(common_base + off);
    p.* = v;
}
fn ccRead8(off: u32) u8 {
    const p: *volatile u8 = @ptrFromInt(common_base + off);
    return p.*;
}
fn ccWrite16(off: u32, v: u16) void {
    const p: *volatile u16 = @ptrFromInt(common_base + off);
    p.* = v;
}
fn ccRead16(off: u32) u16 {
    const p: *volatile u16 = @ptrFromInt(common_base + off);
    return p.*;
}
fn ccWrite32(off: u32, v: u32) void {
    const p: *volatile u32 = @ptrFromInt(common_base + off);
    p.* = v;
}
fn ccRead32(off: u32) u32 {
    const p: *volatile u32 = @ptrFromInt(common_base + off);
    return p.*;
}

fn devRead32(off: u32) u32 {
    const p: *volatile u32 = @ptrFromInt(device_base + off);
    return p.*;
}

// --- PCI capability parsing ---
// `pci.findVirtioCap` and `pci.mapBar` are used directly; no per-driver
// shim needed once we keep the `pci.PciDevice` from the bus cache.

const CapInfo = pci.VirtioCap;

// --- Virtqueue setup ---
// Backing logic now lives in virtio.Queue.init; this is a thin wrapper
// that supplies the driver's MAX_QUEUE_SIZE clamp.

fn setupQueue(qi: u16, vq: *Virtqueue) bool {
    return vq.init(common_base, qi, MAX_QUEUE_SIZE);
}

fn notifyQueue(qi: u16, vq: *const Virtqueue) void {
    const addr = notify_base + @as(usize, vq.notify_off) * notify_off_multiplier;
    @as(*volatile u16, @ptrFromInt(addr)).* = qi;
}

// --- Control-queue round-trip ---
//
// Builds a 2-descriptor chain (cmd buffer in to device, resp buffer back to
// driver) for one control message, kicks the queue, busy-waits for the host
// to bump used_idx, then copies the response back. Synchronous and serialized
// via ctrl_lock. Mirrors virtio_gpu's sendCmd almost line-for-line.

fn ctrlSend(cmd_buf: []const u8, resp_buf: []u8) bool {
    ctrl_lock.acquire();
    defer ctrl_lock.release();
    if (ctrl_vq.num_free < 2) return false;
    if (cmd_buf.len > 256 or resp_buf.len > 256) return false;

    const cmd_dst: [*]volatile u8 = @ptrFromInt(paging.physToVirt(ctrl_cmd_phys));
    for (0..cmd_buf.len) |i| cmd_dst[i] = cmd_buf[i];
    const resp_dst: [*]volatile u8 = @ptrFromInt(paging.physToVirt(ctrl_resp_phys));
    for (0..resp_buf.len) |i| resp_dst[i] = 0;

    const d0_idx = ctrl_vq.free_head;
    const d0 = ctrl_vq.descPtr(d0_idx);
    const d1_idx: u16 = @intCast(d0.next);
    const d1 = ctrl_vq.descPtr(d1_idx);
    ctrl_vq.free_head = @intCast(d1.next);
    ctrl_vq.num_free -= 2;

    d0.addr = ctrl_cmd_phys;
    d0.len = @intCast(cmd_buf.len);
    d0.flags = VRING_DESC_F_NEXT;
    d0.next = d1_idx;

    d1.addr = ctrl_resp_phys;
    d1.len = @intCast(resp_buf.len);
    d1.flags = VRING_DESC_F_WRITE;
    d1.next = 0;

    const ai = ctrl_vq.availIdx().*;
    ctrl_vq.availRing(ai % ctrl_vq.queue_size).* = d0_idx;
    asm volatile ("" ::: .{ .memory = true });
    ctrl_vq.availIdx().* = ai +% 1;
    notifyQueue(VQ_CONTROL, &ctrl_vq);

    var timeout: u32 = 5_000_000;
    while (ctrl_vq.last_used_idx == ctrl_vq.usedIdx().* and timeout > 0) : (timeout -= 1) {
        asm volatile ("pause");
    }
    const got = timeout > 0;
    if (got) ctrl_vq.last_used_idx +%= 1;
    d1.next = ctrl_vq.free_head;
    d0.next = d1_idx;
    ctrl_vq.free_head = d0_idx;
    ctrl_vq.num_free += 2;

    if (!got) return false;
    for (0..resp_buf.len) |i| resp_buf[i] = resp_dst[i];
    return true;
}

fn pcmCmd(code: u32, stream_id: u32) bool {
    const cmd: SndPcmHdr = .{ .hdr = .{ .code = code }, .stream_id = stream_id };
    const cmd_bytes: [*]const u8 = @ptrCast(&cmd);
    var resp: SndHdr = .{ .code = 0 };
    const resp_bytes: [*]u8 = @ptrCast(&resp);
    if (!ctrlSend(cmd_bytes[0..@sizeOf(SndPcmHdr)], resp_bytes[0..@sizeOf(SndHdr)])) return false;
    if (resp.code != VIRTIO_SND_S_OK) {
        debug.klog("[virtio-snd] PCM cmd 0x{X} failed: status=0x{X}\n", .{ code, resp.code });
        return false;
    }
    return true;
}

// --- TX pool reclamation ---

fn reclaimTx() void {
    while (tx_vq.last_used_idx != tx_vq.usedIdx().*) {
        const idx = tx_vq.last_used_idx % tx_vq.queue_size;
        const desc_id: u16 = @intCast(tx_vq.usedRingId(idx).*);
        tx_vq.last_used_idx +%= 1;

        // Walk the descriptor chain back to free state, bumping num_free.
        // The buffer pool slot is recorded against the head descriptor.
        var head = desc_id;
        const pool_idx = tx_buffer_idx_for_desc[head];
        if (pool_idx < NUM_TX_BUFS) {
            tx_buffer_inflight[pool_idx] = false;
            tx_buffer_idx_for_desc[head] = 0xFF;
        }
        // Three descriptors per submission (xfer hdr, payload, status).
        // Walk via .next pointers, then re-link the tail to free_head.
        var d = tx_vq.descPtr(head);
        var count: u8 = 1;
        while ((d.flags & VRING_DESC_F_NEXT) != 0 and count < 4) : (count += 1) {
            head = d.next;
            d = tx_vq.descPtr(head);
        }
        d.next = tx_vq.free_head;
        tx_vq.free_head = desc_id;
        tx_vq.num_free += count;
    }
}

fn allocTxBuffer() ?u8 {
    for (0..NUM_TX_BUFS) |i| {
        if (!tx_buffer_inflight[i]) {
            tx_buffer_inflight[i] = true;
            return @intCast(i);
        }
    }
    return null;
}

// --- Public API ---

pub fn isReady() bool {
    return initialized;
}

/// Submit `samples` (interleaved S16 stereo) to the playback stream. Blocks
/// briefly on TX buffer exhaustion (poll-and-retry) so the caller's "fire
/// and forget" mental model from AC97 still works. Drops audio if the host
/// stops draining for so long that we exhaust the pool — preferable to
/// stalling DOOM forever.
pub fn writeSamples(src: [*]const i16, stereo_samples: u32) void {
    if (!initialized or stereo_samples == 0) return;

    const bytes_total: u32 = stereo_samples * 4; // 2 channels * 2 bytes
    var off: u32 = 0;

    while (off < bytes_total) {
        tx_lock.acquire();
        reclaimTx();
        const pool_idx_opt = allocTxBuffer();
        if (pool_idx_opt == null) {
            tx_lock.release();
            // Pool exhausted — give the host one short window to drain, then drop.
            for (0..1024) |_| asm volatile ("pause");
            tx_lock.acquire();
            reclaimTx();
            const second = allocTxBuffer();
            if (second == null) {
                tx_lock.release();
                return; // drop the rest of this chunk
            }
        }
        const pool_idx = pool_idx_opt orelse blk: {
            // Tried again above; re-find the freshly-allocated slot.
            for (0..NUM_TX_BUFS) |i| {
                if (tx_buffer_inflight[i]) break :blk @as(u8, @intCast(i));
            }
            tx_lock.release();
            return;
        };

        const chunk = if (bytes_total - off > TX_BUF_SIZE) TX_BUF_SIZE else bytes_total - off;

        const dst: [*]volatile u8 = @ptrFromInt(paging.physToVirt(tx_pool_phys[pool_idx]));
        const src_bytes: [*]const u8 = @ptrCast(src);
        for (0..chunk) |i| dst[i] = src_bytes[off + i];

        const xfer: *volatile SndPcmXfer = @ptrFromInt(paging.physToVirt(tx_xfer_hdr_phys[pool_idx]));
        xfer.stream_id = output_stream_id;

        const status_dst: [*]volatile u8 = @ptrFromInt(paging.physToVirt(tx_status_phys[pool_idx]));
        for (0..@sizeOf(SndPcmStatus)) |i| status_dst[i] = 0;

        if (tx_vq.num_free < 3) {
            tx_buffer_inflight[pool_idx] = false;
            tx_lock.release();
            return;
        }

        const d0_idx = tx_vq.free_head;
        const d0 = tx_vq.descPtr(d0_idx);
        const d1_idx: u16 = @intCast(d0.next);
        const d1 = tx_vq.descPtr(d1_idx);
        const d2_idx: u16 = @intCast(d1.next);
        const d2 = tx_vq.descPtr(d2_idx);
        tx_vq.free_head = @intCast(d2.next);
        tx_vq.num_free -= 3;

        d0.addr = tx_xfer_hdr_phys[pool_idx];
        d0.len = @sizeOf(SndPcmXfer);
        d0.flags = VRING_DESC_F_NEXT;
        d0.next = d1_idx;

        d1.addr = tx_pool_phys[pool_idx];
        d1.len = chunk;
        d1.flags = VRING_DESC_F_NEXT;
        d1.next = d2_idx;

        d2.addr = tx_status_phys[pool_idx];
        d2.len = @sizeOf(SndPcmStatus);
        d2.flags = VRING_DESC_F_WRITE;
        d2.next = 0;

        tx_buffer_idx_for_desc[d0_idx] = pool_idx;

        const ai = tx_vq.availIdx().*;
        tx_vq.availRing(ai % tx_vq.queue_size).* = d0_idx;
        asm volatile ("" ::: .{ .memory = true });
        tx_vq.availIdx().* = ai +% 1;

        notifyQueue(VQ_TX, &tx_vq);
        tx_lock.release();
        off += chunk;
    }
}

// --- Initialization ---

const SoundConfigPick = struct { stream_id: u32, ok: bool };

fn pickOutputStream(num_streams: u32) SoundConfigPick {
    if (num_streams == 0) return .{ .stream_id = 0, .ok = false };

    var query: SndQueryInfo = .{
        .hdr = .{ .code = VIRTIO_SND_R_PCM_INFO },
        .start_id = 0,
        .count = num_streams,
        .size = @sizeOf(SndPcmInfo),
    };
    const cmd_bytes: [*]const u8 = @ptrCast(&query);

    // Header + per-stream info packed by the device. Keep the response buffer
    // small and bail if the device claims more streams than we can hold.
    const max_streams: u32 = 8;
    if (num_streams > max_streams) return .{ .stream_id = 0, .ok = false };
    var resp: [@sizeOf(SndHdr) + @sizeOf(SndPcmInfo) * 8]u8 = undefined;
    const resp_len = @sizeOf(SndHdr) + @sizeOf(SndPcmInfo) * num_streams;
    if (!ctrlSend(cmd_bytes[0..@sizeOf(SndQueryInfo)], resp[0..resp_len])) return .{ .stream_id = 0, .ok = false };
    const hdr: *const SndHdr = @ptrCast(@alignCast(&resp[0]));
    if (hdr.code != VIRTIO_SND_S_OK) return .{ .stream_id = 0, .ok = false };

    for (0..num_streams) |i| {
        const off = @sizeOf(SndHdr) + i * @sizeOf(SndPcmInfo);
        const info: *const SndPcmInfo = @ptrCast(@alignCast(&resp[off]));
        if (info.direction == VIRTIO_SND_D_OUTPUT) {
            return .{ .stream_id = @intCast(i), .ok = true };
        }
    }
    return .{ .stream_id = 0, .ok = false };
}

pub fn init() bool {
    debug.klog("[virtio-snd] Scanning for device...\n", .{});

    const dev_found = pci.findByVendorDevice(VIRTIO_VENDOR, VIRTIO_SOUND_DEVICE_ID) orelse {
        debug.klog("[virtio-snd] No device found\n", .{});
        return false;
    };
    debug.klog("[virtio-snd] Found device at {d}:{d}\n", .{ dev_found.bus, dev_found.dev });

    // Bus-master + MEM/IO + INTx-disable (uses MSI-X via virtio common cap).
    var bind = pci.bindDevice(dev_found);
    defer bind.deinit();

    // IOMMU Phase 3: own SL page table; map virtqueues + scratch
    // buffers + TX pool entries as they're allocated below.
    _ = iommu.enableIsolation(dev_found.bus, dev_found.dev, dev_found.func);

    const common_cap = pci.findVirtioCap(dev_found, VIRTIO_PCI_CAP_COMMON_CFG) orelse {
        debug.klog("[virtio-snd] No common config cap\n", .{});
        return false;
    };
    const notify_cap = pci.findVirtioCap(dev_found, VIRTIO_PCI_CAP_NOTIFY_CFG) orelse {
        debug.klog("[virtio-snd] No notify cap\n", .{});
        return false;
    };
    const device_cap = pci.findVirtioCap(dev_found, VIRTIO_PCI_CAP_DEVICE_CFG) orelse {
        debug.klog("[virtio-snd] No device-config cap\n", .{});
        return false;
    };

    const common_bar = pci.mapBar(dev_found, common_cap.bar, 0x4000) orelse return false;
    const notify_bar = pci.mapBar(dev_found, notify_cap.bar, 0x4000) orelse return false;
    const device_bar = pci.mapBar(dev_found, device_cap.bar, 0x4000) orelse return false;

    common_base = common_bar + common_cap.offset;
    notify_base = notify_bar + notify_cap.offset;
    notify_off_multiplier = notify_cap.notify_off_mult;
    device_base = device_bar + device_cap.offset;

    // Reset → ACK → DRIVER (per virtio §3.1.1)
    ccWrite8(CC_DEVICE_STATUS, 0);
    var spin: u32 = 0;
    while (ccRead8(CC_DEVICE_STATUS) != 0 and spin < 1000) : (spin += 1) {
        asm volatile ("pause");
    }
    ccWrite8(CC_DEVICE_STATUS, STATUS_ACKNOWLEDGE);
    ccWrite8(CC_DEVICE_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER);

    // Read device features (low 32 bits) — virtio-sound has no feature bits in v1.2,
    // so we negotiate zero. Still need to set FEATURES_OK to advance the handshake.
    ccWrite32(CC_DEVICE_FEATURE_SELECT, 0);
    _ = ccRead32(CC_DEVICE_FEATURE);
    ccWrite32(CC_DRIVER_FEATURE_SELECT, 0);
    ccWrite32(CC_DRIVER_FEATURE, 0);
    ccWrite32(CC_DRIVER_FEATURE_SELECT, 1);
    ccWrite32(CC_DRIVER_FEATURE, 0);

    ccWrite8(CC_DEVICE_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK);
    if ((ccRead8(CC_DEVICE_STATUS) & STATUS_FEATURES_OK) == 0) {
        debug.klog("[virtio-snd] FEATURES_OK rejected\n", .{});
        return false;
    }

    // Read device config (jacks, streams, chmaps).
    const num_jacks = devRead32(0);
    const num_streams = devRead32(4);
    const num_chmaps = devRead32(8);
    debug.klog("[virtio-snd] jacks={d} streams={d} chmaps={d}\n", .{ num_jacks, num_streams, num_chmaps });
    if (num_streams == 0) {
        debug.klog("[virtio-snd] No PCM streams advertised\n", .{});
        return false;
    }

    if (!setupQueue(VQ_CONTROL, &ctrl_vq)) return false;
    if (!setupQueue(VQ_EVENT, &tx_vq)) return false; // dummy — we don't use eventq
    // Reuse: the eventq doesn't get touched but must be enabled for the device.
    // Re-call setupQueue for tx_vq on its real index.
    if (!setupQueue(VQ_TX, &tx_vq)) return false;

    // Map both virtqueue rings (desc/avail share one frame; used has its own).
    _ = iommu.dmaMap(dev_found.bus, dev_found.dev, dev_found.func, ctrl_vq.desc_phys, 4096, .{});
    _ = iommu.dmaMap(dev_found.bus, dev_found.dev, dev_found.func, ctrl_vq.used_phys, 4096, .{});
    _ = iommu.dmaMap(dev_found.bus, dev_found.dev, dev_found.func, tx_vq.desc_phys, 4096, .{});
    _ = iommu.dmaMap(dev_found.bus, dev_found.dev, dev_found.func, tx_vq.used_phys, 4096, .{});

    // Allocate scratch buffers used by the control round-trip.
    ctrl_cmd_phys = pmm.allocFrame() orelse return false;
    ctrl_resp_phys = pmm.allocFrame() orelse return false;
    _ = iommu.dmaMap(dev_found.bus, dev_found.dev, dev_found.func, ctrl_cmd_phys, 4096, .{});
    _ = iommu.dmaMap(dev_found.bus, dev_found.dev, dev_found.func, ctrl_resp_phys, 4096, .{});
    @memset(@as([*]u8, @ptrFromInt(paging.physToVirt(ctrl_cmd_phys)))[0..4096], 0);
    @memset(@as([*]u8, @ptrFromInt(paging.physToVirt(ctrl_resp_phys)))[0..4096], 0);

    // Allocate TX pool — one PMM frame per slot, sliced into hdr/payload/status.
    for (0..NUM_TX_BUFS) |i| {
        const frame = pmm.allocFrame() orelse return false;
        _ = iommu.dmaMap(dev_found.bus, dev_found.dev, dev_found.func, frame, 4096, .{});
        @memset(@as([*]u8, @ptrFromInt(paging.physToVirt(frame)))[0..4096], 0);
        // Layout in the frame:
        //   [0   .. 16)    : SndPcmXfer header (4 bytes really, padded)
        //   [64  .. 64+TX_BUF_SIZE) : audio data
        //   [TX_BUF_SIZE+64 .. ) : SndPcmStatus
        tx_xfer_hdr_phys[i] = frame;
        tx_pool_phys[i] = frame + 64;
        tx_status_phys[i] = frame + 64 + TX_BUF_SIZE;
    }

    ccWrite8(CC_DEVICE_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK);

    // Find an output stream and set it up: SET_PARAMS → PREPARE → START.
    const pick = pickOutputStream(num_streams);
    if (!pick.ok) {
        debug.klog("[virtio-snd] No output stream\n", .{});
        return false;
    }
    output_stream_id = pick.stream_id;
    debug.klog("[virtio-snd] Using output stream {d}\n", .{output_stream_id});

    var sp: SndPcmSetParams = .{
        .hdr = .{ .hdr = .{ .code = VIRTIO_SND_R_PCM_SET_PARAMS }, .stream_id = output_stream_id },
        .buffer_bytes = TX_BUF_SIZE * NUM_TX_BUFS,
        .period_bytes = TX_BUF_SIZE,
        .features = 0,
        .channels = 2,
        .format = VIRTIO_SND_PCM_FMT_S16,
        .rate = VIRTIO_SND_PCM_RATE_22050,
    };
    {
        const cmd_bytes: [*]const u8 = @ptrCast(&sp);
        var resp: SndHdr = .{ .code = 0 };
        const resp_bytes: [*]u8 = @ptrCast(&resp);
        if (!ctrlSend(cmd_bytes[0..@sizeOf(SndPcmSetParams)], resp_bytes[0..@sizeOf(SndHdr)])) return false;
        if (resp.code != VIRTIO_SND_S_OK) {
            debug.klog("[virtio-snd] SET_PARAMS failed: 0x{X}\n", .{resp.code});
            return false;
        }
    }
    if (!pcmCmd(VIRTIO_SND_R_PCM_PREPARE, output_stream_id)) return false;
    if (!pcmCmd(VIRTIO_SND_R_PCM_START, output_stream_id)) return false;

    initialized = true;
    debug.klog("[virtio-snd] Ready (22050 Hz S16 stereo)\n", .{});
    bind.commit();
    return true;
}
