const io = @import("../io.zig");
const pci = @import("pci.zig");
const pmm = @import("../mm/pmm.zig");
const paging = @import("../mm/paging.zig");
const debug = @import("../debug/debug.zig");
const idt = @import("../cpu/idt.zig");
const msix = @import("../time/msix.zig");
const iommu = @import("../cpu/iommu.zig");
const SpinLock = @import("../proc/spinlock.zig").SpinLock;
const Mutex = @import("../proc/spinlock.zig").Mutex;
const apic = @import("../time/apic.zig");
const perf = @import("../debug/perf.zig");

/// Slow-submit threshold for sendCmdViaPhys. When wait exceeds this, log
/// the cmd_type (first u32 of cmd_phys, per virtio-gpu spec) + lengths
/// so we can see *which* particular command is the bottleneck. 50ms is
/// well above normal (real cmds <1ms, blob page-flips ~16ms vsync) so
/// it only fires for genuinely pathological waits.
const SLOW_GPU_SUBMIT_THRESHOLD_MS: u64 = 50;

// Serialises all access to the control virtqueue. Without this, BSP rendering
// (flushRect/transferToHost called from the desktop) races with AP syscalls
// (gpuGetCapsetInfo, gpuCtxCreate, etc.) and corrupts the descriptor ring —
// previously seen as syscalls returning garbage cmd_types for index >= 1.
//
// Mutex (not SpinLock): sendCmd holds this across blockOn(.gpu_io) while
// waiting for the host's MSI-X response (~50-80ms). A SpinLock here would
// deadlock — the holder yields via blockOn, scheduler picks another task
// on the same CPU, that task tries to acquire and spins forever because
// SpinLock keys ownership by CPU. Mutex keys by PCB, so the waiter
// correctly sleeps on .mutex and is woken on release. (See the
// 2026-05-16 fastfetch wedge for the original incident.)
var ctrl_lock: Mutex = .{};

/// True iff a GPU control-channel op is in flight on some pid. Used by the
/// panic-screen render path to skip post_blit_fn (= flushUnconditional)
/// when calling it would recursively acquire ctrl_lock from a pid that
/// already owns it (interrupted mid-sendCmd by a panic). Snapshot only —
/// fine for the panic case (single-shot, racy-but-not-fatal).
pub fn ctrlLockBusy() bool {
    return ctrl_lock.isHeld();
}
/// Serializes cursor_vq + cursor_cmd page mutations. Cursor updates fire
/// from desktop main loop (mouse motion) and from focus changes (which
/// can run from syscall context), so cross-CPU access is real. IrqSave
/// because timer IRQ on BSP can drive a cursor move via virtio_gpu.flush
/// callbacks if we ever wire them to the cursor path.
var cursor_lock: SpinLock = .{};

// MSI-X / IRQ-driven completion state. When `use_msix` is true, sendCmd
// blocks on `sti; hlt` instead of a `pause` spin — woken by either the
// virtio-gpu IRQ or the LAPIC tick. Saves milliseconds of CPU per Vulkan
// frame which would otherwise be burned in `pause`.
var use_msix: bool = false;
/// Gate the sti+hlt completion-wait. False until kernelMain's `asm sti`
/// in Phase 5 — before that, the LAPIC's spurious-vector enable bit isn't
/// set yet (apic.init does it in Phase 3, but we're called from early_fb
/// in Phase 2), so MSI writes to 0xFEE00000 are ignored and `hlt` becomes
/// permanent. Polling spin works regardless of LAPIC state. Set to true
/// from main.zig right after the global sti.
pub var msix_safe_to_use: bool = false;
/// Diagnostic switch for bisecting async-wait wedges. When true,
/// sendCmdViaPhys skips the blockOn(.gpu_io) path and pause-spins
/// instead — same as the early-boot pre-MSI-X behaviour. CLI / kdbg
/// can flip this live; sendCmd reads it on entry so the next submit
/// uses the new mode. Cost when false: one memory load per submit.
pub var force_polled: bool = false;
pub var virtio_gpu_irq_count: u64 = 0;
/// True iff VIRTIO_F_RING_EVENT_IDX was negotiated. When set, sendCmdViaPhys
/// writes the target usedIdx into ctrl_vq.usedEvent() before HLT so the
/// device knows exactly when to fire MSI-X — workaround for QEMU's
/// re-entrancy guard silently dropping unconditional notifications.
var use_event_idx: bool = false;

/// MSI-X table entry kernel-virtual address, captured at arm time so
/// sendCmdViaPhys can re-target the entry to the calling CPU's APIC ID
/// before each wait. Steering MSI-X to the same CPU as the `sti; hlt`
/// waiter cuts cmd latency from ~10ms (next LAPIC tick) to ~µs (real
/// completion IRQ on the waiting CPU). 0 means "not armed".
var msix_entry_addr: usize = 0;

/// Catch-all MSI-X handler. Just bumps a counter — the real check
/// (used_idx advance) happens in the next iteration of sendCmd's
/// `sti; hlt` loop. Same shape as `nvmeIrqHandler`.
/// MSI-X target landing breakdown (read at any time via virtioGpuIrqStats).
/// Even with `retargetEntry` writing the correct destination APIC ID,
/// QEMU/KVM/Hyper-V routes all virtio-gpu MSI-X to cpu0 in practice.
/// Kept as a counter (not periodic log) so the CLI can sample on demand.
/// Sized to smp.MAX_CPUS so we don't silently truncate IRQ counts on
/// CPUs ≥ 4 (was hardcoded [4]u64 — gap #15).
pub var virtio_gpu_irq_per_cpu: [@import("../cpu/smp.zig").MAX_CPUS]u64 =
    .{0} ** @import("../cpu/smp.zig").MAX_CPUS;
/// IPIs we sent from the MSI-X handler to wake other CPUs from sti+hlt.
/// Compared against process.kill_kick handler invocations to determine
/// whether IPI delivery is the broken link. (See process.kickHandlerCount.)
pub var virtio_gpu_wake_ipis_sent: u64 = 0;

/// The single pid currently parked in blockOn(.gpu_io) via sendCmdViaPhys
/// / sendSimpleCmdPair. ctrl_lock serializes submitters so there's at
/// most one. 0xFF = nobody waiting; otherwise = pid. Updated atomically
/// because the IRQ handler reads it concurrently from cpu0.
///
/// Pre-existing code scanned ALL MAX_PROCS PCBs on every IRQ — fine
/// when MAX_PROCS was small but wasteful at 256. Direct lookup also
/// lets us IPI ONLY the CPU the waiter parked on, instead of fanning
/// out the wake-IPI to every alive CPU. (Gaps #8 + #9, 2026-05-20.)
var current_gpu_waiter: u8 = 0xFF;
fn virtioGpuIrqHandler() callconv(.c) void {
    virtio_gpu_irq_count +%= 1;
    const smp_mod = @import("../cpu/smp.zig");
    const cpu_id = smp_mod.myCpu().cpu_id;
    if (cpu_id < virtio_gpu_irq_per_cpu.len) virtio_gpu_irq_per_cpu[cpu_id] +%= 1;
    const process = @import("../proc/process.zig");

    // Direct waiter lookup (gap #8). ctrl_lock serializes submitters so
    // current_gpu_waiter is at most one pid; previous code walked all
    // MAX_PROCS PCBs every IRQ. We MUST NOT call process.wake() — it
    // takes cross-CPU sched_lock and a wedge during paint.elf load
    // traced to exactly that path. Bump wake_tick to "now" and let
    // BSP's wakeExpired (runs from IRQ0 in a lock-clean context) do
    // the setState + rqEnter. The targeted IPI below kicks the waiter's
    // CPU out of hlt so its next IRQ0 fires immediately.
    const pid = @atomicLoad(u8, &current_gpu_waiter, .acquire);
    if (pid == 0xFF) return;
    const pcb = &process.procs[pid];
    @atomicStore(u64, &pcb.wake_tick, process.tick_count, .release);
    @import("../proc/sched.zig").registerWakeDeadline(process.tick_count);
    // Participate in blockOn's lost-wake handshake (sched.zig:1817).
    // Without this, an IRQ landing between the submitter's last
    // usedIdxCoherent re-read and blockOn's setState(.sleeping) is
    // silently dropped — recovery falls onto wakeExpired's 10 ms
    // safety net, which compounds with schedule overhead into the
    // 150 ms-per-cycle yield-loop the autopsy 2026-05-25 surfaced.
    // Same shape as the 2026-05-22 futex lost-wake fix
    // ([[futex-lostwake-fix-2026-05-22]]); every waker outside the
    // process.wake() path has to set wake_pending or it's blind to
    // the handshake. wake_tick stays as the missed-notify safety net.
    @atomicStore(bool, &pcb.wake_pending, true, .release);

    // Targeted IPI (gap #9). Re-read wait_kind to defend against the
    // waiter having raced through wake → re-park on something else;
    // if it's no longer .gpu_io, no IPI is needed (the new waker
    // owns delivery). last_cpu is the CPU the waiter most recently
    // ran on — same one it parked from, since blockOn doesn't migrate.
    if (@atomicLoad(process.WaitKind, &pcb.wait_kind, .acquire) != .gpu_io) return;
    const wcpu = pcb.last_cpu;
    if (wcpu == cpu_id) return; // own LAPIC tick will re-check usedIdx
    if (wcpu >= smp_mod.MAX_CPUS) return;
    const cl = &smp_mod.cpus[wcpu];
    if (!cl.alive) return;
    if (process.wakeVector()) |v| {
        apic.sendIPI(cl.lapic_id, v);
        virtio_gpu_wake_ipis_sent +%= 1;
    }
}

// --- Virtio PCI modern (MMIO-based) ---

const VIRTIO_VENDOR: u16 = 0x1AF4;
const VIRTIO_GPU_DEVICE: u16 = 0x1050; // 0x1040 + device_type 16

// Virtio PCI capability types
const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;
const VIRTIO_PCI_CAP_ISR_CFG: u8 = 3;
const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4;
const VIRTIO_PCI_CAP_SHM_CFG: u8 = 8;

const STATUS_ACKNOWLEDGE: u8 = 1;
const STATUS_DRIVER: u8 = 2;
const STATUS_FEATURES_OK: u8 = 8;
const STATUS_DRIVER_OK: u8 = 4;

const VRING_DESC_F_NEXT: u16 = 1;
const VRING_DESC_F_WRITE: u16 = 2;

// --- Virtio-GPU command types ---

const CMD_GET_DISPLAY_INFO: u32 = 0x0100;
const CMD_RESOURCE_CREATE_2D: u32 = 0x0101;
const CMD_RESOURCE_UNREF: u32 = 0x0102;
const CMD_SET_SCANOUT: u32 = 0x0103;
const CMD_RESOURCE_FLUSH: u32 = 0x0104;
const CMD_TRANSFER_TO_HOST_2D: u32 = 0x0105;
const CMD_RESOURCE_ATTACH_BACKING: u32 = 0x0106;
const CMD_RESOURCE_DETACH_BACKING: u32 = 0x0107;
const CMD_GET_CAPSET_INFO: u32 = 0x0108;
const CMD_GET_CAPSET: u32 = 0x0109;
const CMD_GET_EDID: u32 = 0x010a;
const CMD_RESOURCE_ASSIGN_UUID: u32 = 0x010b;
const CMD_RESOURCE_CREATE_BLOB: u32 = 0x010c;
const CMD_SET_SCANOUT_BLOB: u32 = 0x010d;

// 3D context commands
const CMD_CTX_CREATE: u32 = 0x0200;
const CMD_CTX_DESTROY: u32 = 0x0201;
const CMD_CTX_ATTACH_RESOURCE: u32 = 0x0202;
const CMD_CTX_DETACH_RESOURCE: u32 = 0x0203;
pub const CMD_RESOURCE_CREATE_3D: u32 = 0x0204;
const CMD_TRANSFER_TO_HOST_3D: u32 = 0x0205;
const CMD_TRANSFER_FROM_HOST_3D: u32 = 0x0206;
const CMD_SUBMIT_3D: u32 = 0x0207;
const CMD_RESOURCE_MAP_BLOB: u32 = 0x0208;
const CMD_RESOURCE_UNMAP_BLOB: u32 = 0x0209;

// Cursor commands (sent via cursor queue, fire-and-forget)
const CMD_UPDATE_CURSOR: u32 = 0x0300;
const CMD_MOVE_CURSOR: u32 = 0x0301;

// Bit 0 of CtrlHdr.flags. When set on a command, QEMU does not write a
// response until virglrenderer's fence callback for that fence_id fires.
// For RESOURCE_FLUSH this means the response is gated on the host display
// backend's frame-done event — the implicit vblank-sync our zero-copy
// scanout has otherwise been missing. Caller must also fill in a unique
// CtrlHdr.fence_id.
const VIRTIO_GPU_FLAG_FENCE: u32 = 1;

const RESP_OK_NODATA: u32 = 0x1100;
const RESP_OK_DISPLAY_INFO: u32 = 0x1101;
const RESP_OK_CAPSET_INFO: u32 = 0x1102;
const RESP_OK_CAPSET: u32 = 0x1103;
const RESP_OK_EDID: u32 = 0x1104;
const RESP_OK_RESOURCE_UUID: u32 = 0x1105;
const RESP_OK_MAP_INFO: u32 = 0x1106;

// Feature bits
const VIRTIO_GPU_F_VIRGL: u5 = 0;
const VIRTIO_GPU_F_EDID: u5 = 1;
const VIRTIO_GPU_F_RESOURCE_UUID: u5 = 2;
const VIRTIO_GPU_F_RESOURCE_BLOB: u5 = 3;
const VIRTIO_GPU_F_CONTEXT_INIT: u5 = 4;

// Capset IDs
const CAPSET_VIRGL: u32 = 1;
const CAPSET_VIRGL2: u32 = 2;
const CAPSET_VENUS: u32 = 4;
const CAPSET_DRM: u32 = 5;

const FORMAT_B8G8R8X8_UNORM: u32 = 2; // XRGB8888 in memory (0xXXRRGGBB)
const FORMAT_B8G8R8A8_UNORM: u32 = 1; // ARGB8888 for cursor

// --- Modern virtio common config (MMIO layout) ---
// Offsets within the common config structure
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

// --- Protocol structures ---

const CtrlHdr = extern struct {
    cmd_type: u32 = 0,
    flags: u32 = 0,
    fence_id: u64 = 0,
    ctx_id: u32 = 0,
    ring_idx: u8 = 0,
    padding: [3]u8 = .{ 0, 0, 0 },
};

const Rect = extern struct {
    x: u32 = 0,
    y: u32 = 0,
    width: u32 = 0,
    height: u32 = 0,
};

const DisplayInfo = extern struct {
    hdr: CtrlHdr,
    pmodes: [16]PmodeInfo,
};

const PmodeInfo = extern struct {
    r: Rect,
    enabled: u32,
    flags: u32,
};

const ResourceCreate2D = extern struct {
    hdr: CtrlHdr,
    resource_id: u32,
    format: u32,
    width: u32,
    height: u32,
};

const AttachBacking = extern struct {
    hdr: CtrlHdr,
    resource_id: u32,
    nr_entries: u32,
};

const MemEntry = extern struct {
    addr: u64,
    length: u32,
    padding: u32,
};

const SetScanout = extern struct {
    hdr: CtrlHdr,
    r: Rect,
    scanout_id: u32,
    resource_id: u32,
};

/// VIRTIO_GPU_CMD_SET_SCANOUT_BLOB layout per virtio_gpu.h spec — points
/// a scanout slot at a blob resource (whose host-side storage may be a
/// Vulkan VkDeviceMemory tracked by Venus). Used to display Vulkan-
/// rendered output without a guest readback path.
const SetScanoutBlob = extern struct {
    hdr: CtrlHdr,
    r: Rect,
    scanout_id: u32,
    resource_id: u32,
    width: u32,
    height: u32,
    format: u32,
    padding: u32 = 0,
    strides: [4]u32 = .{ 0, 0, 0, 0 },
    offsets: [4]u32 = .{ 0, 0, 0, 0 },
};

const TransferToHost2D = extern struct {
    hdr: CtrlHdr,
    r: Rect,
    offset: u64,
    resource_id: u32,
    padding: u32,
};

const ResourceFlush = extern struct {
    hdr: CtrlHdr,
    r: Rect,
    resource_id: u32,
    padding: u32,
};

const CursorPos = extern struct {
    scanout_id: u32 = 0,
    x: u32 = 0,
    y: u32 = 0,
    padding: u32 = 0,
};

const UpdateCursor = extern struct {
    hdr: CtrlHdr = .{},
    pos: CursorPos = .{},
    resource_id: u32 = 0,
    hot_x: u32 = 0,
    hot_y: u32 = 0,
    padding: u32 = 0,
};

// --- 3D/Capset protocol structures ---

pub const GetCapsetInfo = extern struct {
    hdr: CtrlHdr = .{},
    capset_index: u32 = 0,
    padding: u32 = 0,
};

pub const RespCapsetInfo = extern struct {
    hdr: CtrlHdr = .{},
    capset_id: u32 = 0,
    capset_max_version: u32 = 0,
    capset_max_size: u32 = 0,
    padding: u32 = 0,
};

// Response for CMD_RESOURCE_CREATE_BLOB. Device may emit either RESP_OK_NODATA
// (no body beyond CtrlHdr) or RESP_OK_RESOURCE_UUID (CtrlHdr + 16-byte UUID).
// resourceCreateBlob only inspects hdr.cmd_type, but we size the receive buf
// to the larger variant so the device-side write never truncates.
const RespResourceUuid = extern struct {
    hdr: CtrlHdr = .{},
    uuid: [16]u8 = @splat(0),
};

const GetCapset = extern struct {
    hdr: CtrlHdr = .{},
    capset_id: u32 = 0,
    capset_size: u32 = 0,
};

// --- 3D context structs ---

const CtxCreate = extern struct {
    hdr: CtrlHdr = .{},
    nlen: u32 = 0,
    context_init: u32 = 0,
    debug_name: [64]u8 = [_]u8{0} ** 64,
};

const CtxDestroy = extern struct {
    hdr: CtrlHdr = .{},
};

const CtxResource = extern struct {
    hdr: CtrlHdr = .{},
    resource_id: u32 = 0,
    padding: u32 = 0,
};

const CmdSubmit3D = extern struct {
    hdr: CtrlHdr = .{},
    size: u32 = 0, // size of command data following this struct
    padding: u32 = 0,
};

const ResourceCreateBlob = extern struct {
    hdr: CtrlHdr = .{},
    resource_id: u32 = 0,
    blob_mem: u32 = 0, // 1=GUEST, 2=HOST3D, 3=HOST3D_GUEST
    blob_flags: u32 = 0, // 1=MAPPABLE, 2=SHAREABLE, 4=CROSS_DEVICE
    nr_entries: u32 = 0,
    blob_id: u64 = 0,
    size: u64 = 0,
};

const ResourceMapBlob = extern struct {
    hdr: CtrlHdr = .{},
    resource_id: u32 = 0,
    padding: u32 = 0,
    offset: u64 = 0,
};

const RespMapInfo = extern struct {
    hdr: CtrlHdr = .{},
    map_info: u32 = 0,
    padding: u32 = 0,
    map_offset: u64 = 0,
};

pub const ResourceCreate3D = extern struct {
    hdr: CtrlHdr = .{},
    resource_id: u32 = 0,
    target: u32 = 0, // PIPE_TEXTURE_*
    format: u32 = 0, // PIPE_FORMAT_*
    bind: u32 = 0, // PIPE_BIND_*
    width: u32 = 0,
    height: u32 = 0,
    depth: u32 = 1,
    array_size: u32 = 1,
    last_level: u32 = 0,
    nr_samples: u32 = 0,
    flags: u32 = 0,
    padding: u32 = 0,
};

const TransferHost3D = extern struct {
    hdr: CtrlHdr = .{},
    box_x: u32 = 0,
    box_y: u32 = 0,
    box_z: u32 = 0,
    box_w: u32 = 0,
    box_h: u32 = 0,
    box_d: u32 = 1,
    offset: u64 = 0,
    resource_id: u32 = 0,
    level: u32 = 0,
    stride: u32 = 0,
    layer_stride: u32 = 0,
};

// Blob memory types
const BLOB_MEM_GUEST: u32 = 1;
const BLOB_MEM_HOST3D: u32 = 2;
const BLOB_MEM_HOST3D_GUEST: u32 = 3;

// Blob flags
const BLOB_FLAG_USE_MAPPABLE: u32 = 1;
const BLOB_FLAG_USE_SHAREABLE: u32 = 2;
const BLOB_FLAG_USE_CROSS_DEVICE: u32 = 4;

// --- Virtqueue (shared with virtio_sound via driver/virtio.zig) ---

const virtio = @import("virtio.zig");
const VirtqDesc = virtio.VirtqDesc;
const Virtqueue = virtio.Queue;

const MAX_QUEUE_SIZE: u16 = 64;

// --- Driver state ---

var common_cfg: usize = 0; // MMIO address of common config
var notify_base: usize = 0; // MMIO address of notify region
var notify_off_multiplier: u32 = 0;
var ctrl_vq: Virtqueue = .{};
var cursor_vq: Virtqueue = .{};

// PCI BDF cached at init so the lazy paths (initCursor, resourceCreate*Blob,
// late framebuffer attaches) can call iommu.dmaMap without re-walking the
// PCI cache. Same pattern as virtio_net / xhci / hda.
var pci_bus: u8 = 0;
var pci_dev: u8 = 0;
var pci_func: u8 = 0;
// Cursor command ring. Single-page (4 KB) carved into CURSOR_RING_SIZE
// UpdateCursor slots. Each sendCursorCmd writes into a fresh slot and
// hands its physical address to the device; the previous in-flight slot
// is left untouched while the host DMA-reads it. Sized to MAX_QUEUE_SIZE
// so the cursor virtqueue's own free-descriptor accounting (num_free)
// guarantees we never wrap a slot whose previous use is still pending.
var cursor_cmd_phys: usize = 0;
const CURSOR_RING_SIZE: u32 = MAX_QUEUE_SIZE;
comptime {
    if (CURSOR_RING_SIZE * @sizeOf(UpdateCursor) > 4096) {
        @compileError("cursor ring exceeds one PMM frame");
    }
}
var cursor_ring_idx: u32 = 0;
const CURSOR_RESOURCE_ID: u32 = 100;
pub var active: bool = false;
pub var hw_cursor_active: bool = false;

// SHM BAR for blob resources (host-visible memory)
pub var shm_bar_phys: usize = 0;
pub var shm_bar_size: usize = 0;

// 3D/Venus capability state
pub var has_virgl: bool = false;
pub var has_blob: bool = false;
pub var has_context_init: bool = false;
pub var has_venus: bool = false;
pub var has_virgl_capset: bool = false;
var venus_capset_version: u32 = 0;
var venus_capset_size: u32 = 0;

// Pre-allocated command buffer (4 pages = 16KB for large attach_backing) and response page
const CMD_PAGES: u32 = 4;
var cmd_phys: usize = 0;
var resp_phys: usize = 0;

// Framebuffer state
const MAX_FB_PAGES: u32 = 2048; // 8MB for 1920x1080x4
var fb_page_phys: [MAX_FB_PAGES]usize = [_]usize{0} ** MAX_FB_PAGES;
var fb_num_pages: u32 = 0;
pub var framebuffer: [*]volatile u32 = undefined;
pub var width: u32 = 0;
pub var height: u32 = 0;
pub var current_resource_id: u32 = 0;

// Blob-backed scanout state (step 8d/8e).
//
// When `scanout_is_blob` is true the per-frame flush path skips
// TRANSFER_TO_HOST_2D — the host udmabuf-imports the blob memory so
// RESOURCE_FLUSH presents it directly. Up to 2 blobs for double-buffered
// page-flip swap (step 8e); single-blob mode (step 8d) uses only index 0.
//
// The blobs themselves are allocated and exported by external code
// (gpu_compositor.zig allocates them via Venus as HOST3D blobs to bypass
// the QEMU 9.2 virgl_cmd_resource_create_blob success-check inversion
// that breaks BLOB_MEM_GUEST). This module just records the resource
// IDs so flushUnconditional / flushRectUnconditional know what to flip.
pub var scanout_is_blob: bool = false;
var blob_virt: [2][*]volatile u32 = .{ undefined, undefined };
var blob_resource_ids: [2]u32 = .{ 0, 0 };
pub var blob_count: u32 = 0; // 1 = single blob, 2 = double-buffer swap
pub var blob_front: u32 = 0; // which blob is currently scanned out
// Saved id of the original 2D scanout resource (the one current_resource_id
// pointed at before armBlobScanout overwrote it). dropOriginal2DScanout
// uses this to detach + unref the right host-side resource without
// touching the blob we just promoted.
var original_2d_resource_id: u32 = 0;

// Monotonic counter for VIRTIO_GPU_FLAG_FENCE cmds. Only the FENCE-flagged
// RESOURCE_FLUSH path consumes this currently — used to gate the response
// on host display backend's frame-done callback (vblank sync).
var fence_id_next: u64 = 0;

// --- Cache-coherence helpers (gap #1+#2, 2026-05-20) ---
//
// Same race class as `nvme.zig:562-565`'s clflush dance: QEMU's GTK /
// Venus / display backend runs on a different host CPU than the guest's
// vCPU0. The host writes `usedIdx` and `resp_phys` directly into guest
// memory through QEMU's mmap, BYPASSING the guest's vCPU. Without an
// explicit clflush + mfence on the guest side, our L1 keeps a stale
// (pre-DMA) cache line — we read zero / unchanged for the field the
// host already updated. Symptom: the Phase A poll spin times out, the
// hlt waiter only "sees" the change when the cache line gets evicted
// for other reasons (10+ ms later); on the resp read the cmd_type
// reads as 0 instead of RESP_OK_NODATA, the caller treats the (already-
// successful) command as failed, retries, retries, retries — the
// multi-minute compositor freeze user observed 2026-05-20.

/// Invalidate a single cache line (assumed aligned to 64 B) and order
/// the subsequent reads. mfence is the cross-CPU barrier; clflush alone
/// only invalidates the line on the local CPU.
inline fn clflushLine(addr: usize) void {
    asm volatile ("clflush (%[a])"
        :
        : [a] "r" (addr),
        : .{ .memory = true });
    asm volatile ("mfence" ::: .{ .memory = true });
}

/// Invalidate every cache line covering `[addr, addr+len)`. Used for
/// the response buffer, which can be larger than one cache line
/// (e.g. RESP_OK_DISPLAY_INFO is 280 B = 5 lines).
inline fn clflushRange(addr: usize, len: usize) void {
    var p = addr & ~@as(usize, 63);
    const end = addr + len;
    while (p < end) : (p += 64) {
        asm volatile ("clflush (%[a])"
            :
            : [a] "r" (p),
            : .{ .memory = true });
    }
    asm volatile ("mfence" ::: .{ .memory = true });
}

/// Coherent read of a virtqueue's used_idx. Replaces every bare
/// `vq.usedIdx().*` read in the wait paths. Without this the polling
/// loops were observing stale values for arbitrarily long until the
/// cache line got naturally evicted.
inline fn usedIdxCoherent(vq: *Virtqueue) u16 {
    clflushLine(@intFromPtr(vq.usedIdx()));
    return vq.usedIdx().*;
}

// --- MMIO register helpers ---

fn ccRead8(off: u32) u8 {
    const ptr: *volatile u8 = @ptrFromInt(common_cfg + off);
    return ptr.*;
}
fn ccWrite8(off: u32, v: u8) void {
    const ptr: *volatile u8 = @ptrFromInt(common_cfg + off);
    ptr.* = v;
}
fn ccRead16(off: u32) u16 {
    const ptr: *volatile u16 = @ptrFromInt(common_cfg + off);
    return ptr.*;
}
fn ccWrite16(off: u32, v: u16) void {
    const ptr: *volatile u16 = @ptrFromInt(common_cfg + off);
    ptr.* = v;
}
fn ccRead32(off: u32) u32 {
    const ptr: *volatile u32 = @ptrFromInt(common_cfg + off);
    return ptr.*;
}
fn ccWrite32(off: u32, v: u32) void {
    const ptr: *volatile u32 = @ptrFromInt(common_cfg + off);
    ptr.* = v;
}

// --- PCI capability parsing ---
// `pci.findVirtioCap` and `pci.mapBar` are used directly; no per-driver
// shim needed once we keep the `pci.PciDevice` from the bus cache.

const CapInfo = pci.VirtioCap;

// --- Virtqueue setup ---
// Backing logic now in virtio.Queue.init; thin wrappers here.

fn setupQueueInto(qi: u16, vq: *Virtqueue) bool {
    return vq.init(common_cfg, qi, MAX_QUEUE_SIZE);
}

fn setupQueue(qi: u16) bool {
    return setupQueueInto(qi, &ctrl_vq);
}

/// Ring the doorbell using the queue's cached notify_off (set in
/// Queue.init). Replaces a 4-MMIO-op dance per call (write QSELECT, read
/// NOTIFY_OFF, compute, write doorbell) with a single u16 write — the
/// notify offset is spec-constant per queue.
fn notifyQueue(qi: u16, vq: *const Virtqueue) void {
    const addr = notify_base + @as(usize, vq.notify_off) * notify_off_multiplier;
    @as(*volatile u16, @ptrFromInt(addr)).* = qi;
}

// --- Command sending ---

/// Internal: run the descriptor-chain dance against ctrl_vq with a command
/// already sitting in `cmd_phys` (length `cmd_len`) and a zeroed response
/// buffer of `resp_len` at `resp_phys`. Caller holds `ctrl_lock`.
///
/// This is the shared implementation that `sendCmd` (caller buffer) and
/// the in-place builders (attachBacking, submit3D, resourceCreateGuestBlob)
/// both need. Before this existed, each in-place builder duplicated ~25
/// lines of identical descriptor-chain + wait-loop code.
fn sendCmdViaPhys(cmd_len: u32, resp_len: u32) bool {
    // Bracket the entire submit-and-wait so per-syscall latency attribution
    // can show "sysGpuSubmit3D dt=900ms = 870ms gpu_wait + 30ms misc".
    const sp = @import("../debug/syscall_perf.zig").scope(.gpu_wait);
    defer sp.end();
    if (ctrl_vq.num_free < 2) return false;

    const d0_idx = ctrl_vq.free_head;
    const d0 = ctrl_vq.descPtr(d0_idx);
    const d1_idx: u16 = @intCast(d0.next);
    const d1 = ctrl_vq.descPtr(d1_idx);
    ctrl_vq.free_head = @intCast(d1.next);
    ctrl_vq.num_free -= 2;

    d0.addr = cmd_phys;
    d0.len = cmd_len;
    d0.flags = VRING_DESC_F_NEXT;
    d0.next = d1_idx;

    d1.addr = resp_phys;
    d1.len = resp_len;
    d1.flags = VRING_DESC_F_WRITE;
    d1.next = 0;

    const ai = ctrl_vq.availIdx().*;
    ctrl_vq.availRing(ai % ctrl_vq.queue_size).* = d0_idx;
    asm volatile ("" ::: .{ .memory = true }); // compiler barrier; x86 TSO handles CPU ordering
    ctrl_vq.availIdx().* = ai +% 1;

    // Re-target MSI-X to the calling CPU's APIC ID BEFORE notifying the
    // host. Hyper-V halts a vCPU while it's in HLT — virtual LAPIC stops
    // ticking, so the only thing that wakes our `sti; hlt` is the actual
    // completion IRQ. If MSI-X is hardwired to cpu0 and we're waiting on
    // cpu1, the wake never arrives directly; cube only resumes when some
    // other CPU IPIs/NMIs cpu1 (e.g. spinlock NMI broadcast at ~50ms),
    // so wait_ms ends up dominated by that side-channel rather than real
    // host time. ctrl_lock serializes submitters, so retarget is race-free
    // — whoever holds the lock owns the MSI-X destination for this submit.
    if (msix_entry_addr != 0) {
        const my_cpu = @import("../cpu/smp.zig").myCpu();
        const my_apic_id: u32 = my_cpu.lapic_id;
        @import("../time/msix.zig").retargetEntry(msix_entry_addr, my_apic_id);
        // One-shot diagnostic: confirm we're actually retargeting with a
        // sane lapic_id (not 0 from uninit). Also dump the post-retarget
        // entry contents so we can see whether QEMU honored the rewrite.
        const dbg_state = struct {
            var seen: [4]bool = .{ false, false, false, false };
        };
        if (my_cpu.cpu_id < 4 and !dbg_state.seen[my_cpu.cpu_id]) {
            dbg_state.seen[my_cpu.cpu_id] = true;
            const e_ptr: [*]const volatile u32 = @ptrFromInt(msix_entry_addr);
            debug.klog(
                "[gpu-msix-retarget] cpu={d} lapic_id={d} entry: addr_lo=0x{X} addr_hi=0x{X} data=0x{X} vc=0x{X}\n",
                .{ my_cpu.cpu_id, my_apic_id, e_ptr[0], e_ptr[1], e_ptr[2], e_ptr[3] },
            );
        }
    }

    // EVENT_IDX: tell the device "fire MSI-X when usedIdx reaches THIS value".
    // last_used_idx is the value we last consumed; we want a notification
    // when usedIdx advances past it. Spec: device fires when
    // `usedIdx == used_event + 1`. So write last_used_idx into used_event
    // and the very next response triggers an IRQ. Must be written BEFORE
    // notifyQueue so the device sees it before processing the cmd.
    if (use_event_idx) {
        ctrl_vq.usedEvent().* = ctrl_vq.last_used_idx;
        asm volatile ("" ::: .{ .memory = true }); // compiler barrier; x86 TSO handles CPU ordering
    }

    notifyQueue(0, &ctrl_vq);

    // Bookend the wait in TSC so we can attribute slow submits to the
    // specific cmd_type (first u32 of cmd_phys per virtio-gpu spec).
    // Without this, all we see is "ctrl_lock held for 10s" — no clue
    // whether it was SUBMIT_3D, RESOURCE_CREATE_3D, TRANSFER_TO_HOST,
    // or a fence wait that triggered it.
    const wait_start_tsc = perf.rdtsc();

    // Wait for the host to advance used_idx. Two paths:
    //   * MSI-X armed (post-init): `sti; hlt` until either our handler
    //     fires or the LAPIC tick wakes us. Cheap — CPU is HLT-idle so
    //     it can serve other IRQs (network, disk, kbd) instead of
    //     burning ~3 ms of `pause` per command. 100 ticks ≈ 1 s
    //     timeout on the default 10 ms LAPIC period — was 1000 (=10s),
    //     way too long; real cmds complete in <1 ms.
    //   * Polled (init phase, before MSI-X is wired): legacy `pause`
    //     spin with a 10M-iteration cap.
    // Hoisted out of the blk so the slow-submit log can include it.
    var hlt_iters: u32 = 0;
    // Short adaptive spin-poll BEFORE falling to MSI-X-driven hlt.
    // Workaround for CVE-2024-3446's mem_reentrancy_guard side-effect:
    // QEMU's virtio devices silently drop virtio_notify() calls when
    // the host re-enters the device's MMIO region during command
    // processing — common for SUBMIT_3D where Venus touches blob/
    // dma-buf regions. Without phase A, simple flushes whose IRQ got
    // dropped would hlt for the full LAPIC tick (10 ms) waiting.
    //
    // Trade-off: phase A burns 100 % CPU. The old 100 ms window cost
    // ~21 ms per flush × 21 flushes/s = 40 %+ of one CPU. A 200 µs
    // window catches the truly fast path (most ctrl-vq cmds complete
    // in < 20 µs) and falls through to hlt for genuinely slow ones —
    // which now spend their wait in C-state at ~0 % CPU, woken by the
    // LAPIC tick to re-check usedIdx.
    var phase_a_pause_iters: u64 = 0;
    var phase_a_done_via_poll: bool = false;
    // Gap #5 (2026-05-20): read cmd_type up front so we can pass it as
    // the blockOn target. Was previously read only on the slow-gpu log
    // path (line ~807, post-wait); now also used to identify which cmd
    // is hanging when the yield-loop / stuck-waiter detector dumps us.
    const cmd_type_for_target: u32 = blk_ct: {
        const cv: [*]const volatile u32 = @ptrFromInt(paging.physToVirt(cmd_phys));
        break :blk_ct cv[0];
    };
    if (use_msix and msix_safe_to_use and !force_polled) {
        const tsc_per_q = apic.tscPerQuantum();
        if (tsc_per_q > 0) {
            // 200 µs at 100 Hz tick (tsc_per_q = ticks per 10 ms) = q/50.
            const deadline = perf.rdtsc() +% (tsc_per_q / 50);
            while (perf.rdtsc() < deadline) : (phase_a_pause_iters +%= 1) {
                if (ctrl_vq.last_used_idx != usedIdxCoherent(&ctrl_vq)) {
                    phase_a_done_via_poll = true;
                    break;
                }
                asm volatile ("pause");
            }
        }
    }
    const wake_runs_before_cpu0 = @import("../proc/process.zig").wake_handler_runs[0];
    const wake_runs_before_cpu1 = @import("../proc/process.zig").wake_handler_runs[1];
    const got_response: bool = blk: {
        if (phase_a_done_via_poll) break :blk true;
        if (use_msix and msix_safe_to_use and !force_polled) {
            // Sleep-yield wait. blockOn parks the calling PCB in .sleeping
            // with wait_kind=.gpu_io; schedule() then picks idle (or
            // another runnable task), which means the timer IRQs that
            // fire during the wait charge against the idle PCB's
            // is_idle=true → idle_tick_count++ instead of the GPU
            // submitter. Without this yield, the submitter holds
            // current_pid through the entire wait and the menubar /
            // sysmon CPU bars peg at 100 % even though the CPU is in
            // C-state. virtioGpuIrqHandler walks PCBs and wakes any
            // .gpu_io waiter when usedIdx advances; ctrl_lock keeps the
            // waiter count at ≤ 1.
            //
            // Timeout: re-check after each yield; bail after 100
            // schedule round-trips (~1 s if waking only via the 10 ms
            // LAPIC tick; far sooner under any real GPU IRQ delivery).
            const process = @import("../proc/process.zig");
            const cur_pid_outer = @import("../cpu/smp.zig").myCpu().current_pid orelse break :blk false;
            // Stamp ourselves as THE gpu_io waiter so virtioGpuIrqHandler
            // can wake us directly instead of scanning MAX_PROCS PCBs and
            // can IPI only our last_cpu instead of fanning out to all
            // alive CPUs. Cleared by defer on every exit path (true, false,
            // or panic-unwind). Gaps #8 + #9.
            @atomicStore(u8, &current_gpu_waiter, @intCast(cur_pid_outer), .release);
            defer @atomicStore(u8, &current_gpu_waiter, 0xFF, .release);
            while (true) {
                if (ctrl_vq.last_used_idx != usedIdxCoherent(&ctrl_vq)) {
                    break :blk true;
                }
                if (hlt_iters >= 100) {
                    break :blk false;
                }
                // Safety-net: set wake_tick = now + 1 tick (~10 ms) so
                // wakeExpired() wakes us if the GPU IRQ goes missing
                // (CVE-2024-3446 drops virtio_notify under reentrancy).
                // The primary waker is still virtioGpuIrqHandler — now
                // routes through current_gpu_waiter direct lookup. Set
                // wake_tick BEFORE blockOn so the soft-yield doesn't race
                // wakeExpired clearing it. @atomicStore to avoid racing
                // the IRQ handler's @atomicStore of wake_tick = now
                // (without atomicity, the IRQ's "wake now" could be
                // clobbered by our "wake at now+1" → one extra tick of
                // latency per loss).
                @atomicStore(
                    u64,
                    &process.procs[cur_pid_outer].wake_tick,
                    process.tick_count +% 1,
                    .release,
                );
                @import("../proc/sched.zig").registerWakeDeadline(process.tick_count +% 1);
                process.blockOn(.gpu_io, cmd_type_for_target);
                hlt_iters += 1;
            }
        } else {
            var timeout: u32 = 10000000;
            while (ctrl_vq.last_used_idx == usedIdxCoherent(&ctrl_vq) and timeout > 0) : (timeout -= 1) {
                asm volatile ("pause");
            }
            break :blk timeout > 0;
        }
    };

    // Free descriptors regardless of timeout. On timeout we re-sync our
    // cursor to the host's actual usedIdx — the original "leave it stale
    // to avoid poisoning" comment had the failure mode backwards: when
    // the host completes our cmd AFTER we time out, usedIdx advances and
    // the NEXT caller sees `last != used`, returns true immediately
    // without waiting, and reads a stale resp_phys for our (already-
    // dead) cmd. Re-syncing on timeout costs nothing if usedIdx hasn't
    // moved, and prevents the cascade if it has.
    if (got_response) {
        ctrl_vq.last_used_idx +%= 1;
    } else {
        ctrl_vq.last_used_idx = usedIdxCoherent(&ctrl_vq);
    }
    d1.next = ctrl_vq.free_head;
    d0.next = d1_idx;
    ctrl_vq.free_head = d0_idx;
    ctrl_vq.num_free += 2;

    // Slow-submit breadcrumb. Read cmd_type AFTER the wait so a partially-
    // initialised cmd buffer can't fault us in the hot path; the cmd has
    // been DMA-visible to the host since notifyQueue, so the read here
    // reflects what we actually submitted.
    const wait_dt = perf.rdtsc() -% wait_start_tsc;
    const wait_ms = apic.tscToMs(wait_dt);
    if (wait_ms >= SLOW_GPU_SUBMIT_THRESHOLD_MS) {
        const cmd_virt: [*]const volatile u32 = @ptrFromInt(paging.physToVirt(cmd_phys));
        const cmd_type = cmd_virt[0];
        const wake_d_cpu0 = @import("../proc/process.zig").wake_handler_runs[0] -% wake_runs_before_cpu0;
        const wake_d_cpu1 = @import("../proc/process.zig").wake_handler_runs[1] -% wake_runs_before_cpu1;
        debug.klog(
            "[slow-gpu] cmd_type=0x{X} cmd_len={d} resp_len={d} wait={d}ms hlt_iters={d} poll_iters={d} via_poll={any} wake_during(cpu0={d},cpu1={d}) ok={any}\n",
            .{ cmd_type, cmd_len, resp_len, wait_ms, hlt_iters, phase_a_pause_iters, phase_a_done_via_poll, wake_d_cpu0, wake_d_cpu1, got_response },
        );
    }

    if (!got_response) {
        debug.klog("[virtio-gpu] Command timeout (usedIdx now {d})\n", .{ctrl_vq.last_used_idx});
        return false;
    }
    return true;
}

pub fn sendCmd(cmd_buf: [*]const u8, cmd_len: u32, resp_buf: [*]u8, resp_len: u32) bool {
    ctrl_lock.acquire();
    defer ctrl_lock.release();

    const cmd_dst: [*]volatile u8 = @ptrFromInt(paging.physToVirt(cmd_phys));
    @memcpy(@as([*]volatile u8, cmd_dst)[0..cmd_len], cmd_buf[0..cmd_len]);

    const resp_dst: [*]volatile u8 = @ptrFromInt(paging.physToVirt(resp_phys));
    @memset(@as([*]volatile u8, resp_dst)[0..resp_len], 0);

    if (!sendCmdViaPhys(cmd_len, resp_len)) return false;

    // Gap #2: clflush before reading the device-written resp. Without
    // this we sometimes saw cmd_type=0 (stale zero from the @memset
    // above) instead of the actual RESP_OK_*; caller then treated the
    // (already-successful) command as failed.
    clflushRange(@intFromPtr(resp_dst), resp_len);
    @memcpy(resp_buf[0..resp_len], @as([*]const volatile u8, resp_dst)[0..resp_len]);
    return true;
}

fn sendSimpleCmd(cmd_buf: [*]const u8, cmd_len: u32) bool {
    var resp: CtrlHdr = .{};
    if (!sendCmd(cmd_buf, cmd_len, @as([*]u8, @ptrCast(&resp)), @sizeOf(CtrlHdr))) return false;
    if (resp.cmd_type != RESP_OK_NODATA) {
        debug.klog("[virtio-gpu] Error response: 0x{X}\n", .{resp.cmd_type});
        return false;
    }
    return true;
}

/// Per-chain cmd slot within `cmd_phys` for the batched-pair path. The
/// flush hot path only uses two slots (256 B each is way more than
/// `SetScanoutBlob` or `ResourceFlush` need) and we already have 16 KB
/// of `cmd_phys` reserved. Same offsets used for `resp_phys`.
const PAIR_CMD_SLOT_BYTES: u32 = 256;

/// Batched-submit equivalent of two back-to-back `sendSimpleCmd` calls.
/// Submits both cmds to the controlq before notifying the device once,
/// then blocks on a single MSI-X round-trip until *both* responses
/// arrive. Used by the compositor flush path where the
/// `SetScanoutBlob` + `ResourceFlush` pair previously took two host
/// round-trips (~41 ms mean) per frame; batching halves it.
///
/// Returns true only when both commands returned `RESP_OK_NODATA`.
fn sendSimpleCmdPair(
    cmd0_buf: [*]const u8,
    cmd0_len: u32,
    cmd1_buf: [*]const u8,
    cmd1_len: u32,
) bool {
    ctrl_lock.acquire();
    defer ctrl_lock.release();

    if (ctrl_vq.num_free < 4) return false;
    if (cmd0_len > PAIR_CMD_SLOT_BYTES or cmd1_len > PAIR_CMD_SLOT_BYTES) return false;

    // Stage cmd buffers into the shared cmd_phys page (slot 0 + slot 1)
    // and zero the response slots.
    const cmd_base: usize = paging.physToVirt(cmd_phys);
    const resp_base: usize = paging.physToVirt(resp_phys);
    const cmd0_dst: [*]volatile u8 = @ptrFromInt(cmd_base);
    const cmd1_dst: [*]volatile u8 = @ptrFromInt(cmd_base + PAIR_CMD_SLOT_BYTES);
    const resp0_dst: [*]volatile u8 = @ptrFromInt(resp_base);
    const resp1_dst: [*]volatile u8 = @ptrFromInt(resp_base + PAIR_CMD_SLOT_BYTES);
    @memcpy(cmd0_dst[0..cmd0_len], cmd0_buf[0..cmd0_len]);
    @memcpy(cmd1_dst[0..cmd1_len], cmd1_buf[0..cmd1_len]);
    @memset(resp0_dst[0..@sizeOf(CtrlHdr)], 0);
    @memset(resp1_dst[0..@sizeOf(CtrlHdr)], 0);

    const sp = @import("../debug/syscall_perf.zig").scope(.gpu_wait);
    defer sp.end();

    // Allocate two chains of two descriptors each: (cmd0→resp0), (cmd1→resp1).
    const c0d0_idx = ctrl_vq.free_head;
    const c0d0 = ctrl_vq.descPtr(c0d0_idx);
    const c0d1_idx: u16 = @intCast(c0d0.next);
    const c0d1 = ctrl_vq.descPtr(c0d1_idx);
    const c1d0_idx: u16 = @intCast(c0d1.next);
    const c1d0 = ctrl_vq.descPtr(c1d0_idx);
    const c1d1_idx: u16 = @intCast(c1d0.next);
    const c1d1 = ctrl_vq.descPtr(c1d1_idx);
    ctrl_vq.free_head = @intCast(c1d1.next);
    ctrl_vq.num_free -= 4;

    c0d0.addr = cmd_phys;
    c0d0.len = cmd0_len;
    c0d0.flags = VRING_DESC_F_NEXT;
    c0d0.next = c0d1_idx;
    c0d1.addr = resp_phys;
    c0d1.len = @sizeOf(CtrlHdr);
    c0d1.flags = VRING_DESC_F_WRITE;
    c0d1.next = 0;

    c1d0.addr = cmd_phys + PAIR_CMD_SLOT_BYTES;
    c1d0.len = cmd1_len;
    c1d0.flags = VRING_DESC_F_NEXT;
    c1d0.next = c1d1_idx;
    c1d1.addr = resp_phys + PAIR_CMD_SLOT_BYTES;
    c1d1.len = @sizeOf(CtrlHdr);
    c1d1.flags = VRING_DESC_F_WRITE;
    c1d1.next = 0;

    // Publish BOTH chain heads in avail before notifying. Two avail
    // entries, one notify — device sees a 2-deep batch and processes
    // them in pipeline; we only pay one MSI-X round-trip.
    var ai = ctrl_vq.availIdx().*;
    ctrl_vq.availRing(ai % ctrl_vq.queue_size).* = c0d0_idx;
    ai +%= 1;
    ctrl_vq.availRing(ai % ctrl_vq.queue_size).* = c1d0_idx;
    asm volatile ("" ::: .{ .memory = true });
    ctrl_vq.availIdx().* = ai +% 1;

    if (msix_entry_addr != 0) {
        const my_cpu = @import("../cpu/smp.zig").myCpu();
        const my_apic_id: u32 = my_cpu.lapic_id;
        @import("../time/msix.zig").retargetEntry(msix_entry_addr, my_apic_id);
    }

    // EVENT_IDX: ask device to fire IRQ when usedIdx == used_event + 1.
    // Setting used_event = last_used_idx + 1 means we only get one IRQ
    // when BOTH responses have landed — no spurious wake on the first.
    if (use_event_idx) {
        ctrl_vq.usedEvent().* = ctrl_vq.last_used_idx +% 1;
        asm volatile ("" ::: .{ .memory = true });
    }

    notifyQueue(0, &ctrl_vq);

    const wait_start_tsc = perf.rdtsc();
    var hlt_iters: u32 = 0;
    var phase_a_pause_iters: u64 = 0;
    var phase_a_done_via_poll: bool = false;
    const target_idx: u16 = ctrl_vq.last_used_idx +% 2;
    // Gap #5: pass cmd0_type as the blockOn target so the autopsy can
    // name the operation. For the pair path this is typically
    // CMD_SET_SCANOUT_BLOB or CMD_TRANSFER_TO_HOST_2D (the flush hot path).
    const cmd_type_for_target: u32 = blk_ct: {
        const cv: [*]const volatile u32 = @ptrFromInt(cmd_base);
        break :blk_ct cv[0];
    };
    if (use_msix and msix_safe_to_use and !force_polled) {
        const tsc_per_q = apic.tscPerQuantum();
        if (tsc_per_q > 0) {
            const deadline = perf.rdtsc() +% (tsc_per_q / 50);
            while (perf.rdtsc() < deadline) : (phase_a_pause_iters +%= 1) {
                // Gap #6: use `>=` (with wrap) instead of `==`. If the
                // device advances past target_idx for any reason (a
                // concurrent op crammed in by a future caller, or a
                // wraparound race), strict `==` would never trigger.
                // u16 wrap-aware "is at least target_idx" check: the
                // difference is small (≤ MAX_QUEUE_SIZE), so signed
                // (i16) subtraction handles wraps correctly.
                const used = usedIdxCoherent(&ctrl_vq);
                if (@as(i16, @bitCast(used -% target_idx)) >= 0) {
                    phase_a_done_via_poll = true;
                    break;
                }
                asm volatile ("pause");
            }
        }
    }
    const got_response: bool = blk: {
        if (phase_a_done_via_poll) break :blk true;
        if (use_msix and msix_safe_to_use and !force_polled) {
            const process = @import("../proc/process.zig");
            const cur_pid_outer = @import("../cpu/smp.zig").myCpu().current_pid orelse break :blk false;
            // Single-waiter / targeted-IPI stamp; see sendCmdViaPhys above.
            @atomicStore(u8, &current_gpu_waiter, @intCast(cur_pid_outer), .release);
            defer @atomicStore(u8, &current_gpu_waiter, 0xFF, .release);
            while (true) {
                const used = usedIdxCoherent(&ctrl_vq);
                if (@as(i16, @bitCast(used -% target_idx)) >= 0) break :blk true;
                if (hlt_iters >= 100) break :blk false;
                // @atomicStore to avoid racing virtioGpuIrqHandler's
                // @atomicStore of wake_tick = now (see sendCmdViaPhys
                // for the full rationale).
                @atomicStore(
                    u64,
                    &process.procs[cur_pid_outer].wake_tick,
                    process.tick_count +% 1,
                    .release,
                );
                @import("../proc/sched.zig").registerWakeDeadline(process.tick_count +% 1);
                process.blockOn(.gpu_io, cmd_type_for_target);
                hlt_iters += 1;
            }
        } else {
            var timeout: u32 = 10000000;
            while (@as(i16, @bitCast(usedIdxCoherent(&ctrl_vq) -% target_idx)) < 0 and timeout > 0) : (timeout -= 1) {
                asm volatile ("pause");
            }
            break :blk timeout > 0;
        }
    };

    if (got_response) {
        ctrl_vq.last_used_idx +%= 2;
    } else {
        ctrl_vq.last_used_idx = usedIdxCoherent(&ctrl_vq);
    }

    // Return all 4 descriptors to the free list (preserve original
    // chain order so the next allocator sees a contiguous run).
    c1d1.next = ctrl_vq.free_head;
    c1d0.next = c1d1_idx;
    c0d1.next = c1d0_idx;
    c0d0.next = c0d1_idx;
    ctrl_vq.free_head = c0d0_idx;
    ctrl_vq.num_free += 4;

    const wait_dt = perf.rdtsc() -% wait_start_tsc;
    const wait_ms = apic.tscToMs(wait_dt);
    if (wait_ms >= SLOW_GPU_SUBMIT_THRESHOLD_MS) {
        const cmd0_virt: [*]const volatile u32 = @ptrFromInt(cmd_base);
        const cmd1_virt: [*]const volatile u32 = @ptrFromInt(cmd_base + PAIR_CMD_SLOT_BYTES);
        debug.klog(
            "[slow-gpu pair] cmd0=0x{X} cmd1=0x{X} wait={d}ms hlt={d} poll={d} via_poll={any} ok={any}\n",
            .{ cmd0_virt[0], cmd1_virt[0], wait_ms, hlt_iters, phase_a_pause_iters, phase_a_done_via_poll, got_response },
        );
    }

    if (!got_response) return false;

    // Gap #2: clflush both resp slots before decoding. Each CtrlHdr is
    // 24 B; clflushRange aligns to 64-byte lines so a single line covers
    // each slot, but call twice for clarity.
    clflushRange(resp_base, @sizeOf(CtrlHdr));
    clflushRange(resp_base + PAIR_CMD_SLOT_BYTES, @sizeOf(CtrlHdr));
    const resp0: *const CtrlHdr = @ptrFromInt(resp_base);
    const resp1: *const CtrlHdr = @ptrFromInt(resp_base + PAIR_CMD_SLOT_BYTES);
    if (resp0.cmd_type != RESP_OK_NODATA or resp1.cmd_type != RESP_OK_NODATA) {
        debug.klog("[virtio-gpu] Pair error: resp0=0x{X} resp1=0x{X}\n", .{ resp0.cmd_type, resp1.cmd_type });
        return false;
    }
    return true;
}

// --- GPU commands ---

fn detectShmBar(dev_pci: pci.PciDevice) void {
    // SHM caps share the modern-virtio cap layout; pci.findVirtioCap gives
    // us bar/offset/length (low 32 bits) and the cfg_off so we can read the
    // SHM-specific extension fields (offset_hi, length_hi at +16/+20, plus
    // shm_id in byte 1 of the second dword).
    const cap = pci.findVirtioCap(dev_pci, VIRTIO_PCI_CAP_SHM_CFG) orelse return;

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

fn queryCapsets() void {
    var index: u32 = 0;
    while (index < 16) : (index += 1) {
        var cmd = GetCapsetInfo{ .hdr = .{ .cmd_type = CMD_GET_CAPSET_INFO }, .capset_index = index };
        var resp: RespCapsetInfo = undefined;
        @memset(@as([*]u8, @ptrCast(&resp))[0..@sizeOf(RespCapsetInfo)], 0);

        if (!sendCmd(
            @as([*]const u8, @ptrCast(&cmd)),
            @sizeOf(GetCapsetInfo),
            @as([*]u8, @ptrCast(&resp)),
            @sizeOf(RespCapsetInfo),
        )) break;

        if (resp.hdr.cmd_type != RESP_OK_CAPSET_INFO) break;
        if (resp.capset_id == 0 and resp.capset_max_size == 0) break; // empty slot

        debug.klog("[virtio-gpu] Capset {d}: id={d} ver={d} size={d}\n", .{
            index, resp.capset_id, resp.capset_max_version, resp.capset_max_size,
        });

        if (resp.capset_id == CAPSET_VENUS) {
            has_venus = true;
            venus_capset_version = resp.capset_max_version;
            venus_capset_size = resp.capset_max_size;
            debug.klog("[virtio-gpu] Venus capset found!\n", .{});
        }
        if (resp.capset_id == CAPSET_VIRGL or resp.capset_id == CAPSET_VIRGL2) {
            has_virgl_capset = true;
        }
    }
}

fn getDisplayInfo() ?Rect {
    var cmd = CtrlHdr{ .cmd_type = CMD_GET_DISPLAY_INFO };
    var resp: DisplayInfo = undefined;
    @memset(@as([*]u8, @ptrCast(&resp))[0..@sizeOf(DisplayInfo)], 0);

    if (!sendCmd(
        @as([*]const u8, @ptrCast(&cmd)),
        @sizeOf(CtrlHdr),
        @as([*]u8, @ptrCast(&resp)),
        @sizeOf(DisplayInfo),
    )) return null;

    if (resp.hdr.cmd_type != RESP_OK_DISPLAY_INFO) {
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

fn resourceCreate2D(resource_id: u32, w: u32, h: u32) bool {
    var cmd = ResourceCreate2D{
        .hdr = .{ .cmd_type = CMD_RESOURCE_CREATE_2D },
        .resource_id = resource_id,
        .format = FORMAT_B8G8R8X8_UNORM,
        .width = w,
        .height = h,
    };
    return sendSimpleCmd(@as([*]const u8, @ptrCast(&cmd)), @sizeOf(ResourceCreate2D));
}

// Module-scope to keep attachBacking's frame small. 1000 entries × 16 bytes
// = 16000 bytes. Previously a stack local — Zig ReleaseSafe `undefined`-fills
// it with 0xAA on entry, and the resulting 16KB memset on desktop's kstack
// (a) consumed huge frame depth and (b) tripped the kstack_deep watchpoint
// at 2026-05-17. attachBacking is only called from setupDisplay during
// virtio_gpu.init (boot-time, single-threaded) so no locking is needed.
var attach_backing_merged: [1000]MemEntry = undefined;

fn attachBacking(resource_id: u32, pages: []const usize, page_count: u32) bool {
    // Merge contiguous physical pages into fewer scatter-gather entries
    // This keeps the command small enough to fit in one page
    const merged = &attach_backing_merged;
    var nr_merged: u32 = 0;
    var i: u32 = 0;
    while (i < page_count and nr_merged < 1000) {
        const start = pages[i];
        var length: usize = 4096;
        i += 1;
        while (i < page_count and pages[i] == start + length) : (i += 1) {
            length += 4096;
        }
        merged[nr_merged] = .{ .addr = start, .length = @truncate(length), .padding = 0 };
        nr_merged += 1;
    }
    debug.klog("[virtio-gpu] Merged {d} pages into {d} entries\n", .{ page_count, nr_merged });

    // Build command in cmd_phys buffer
    const cmd_dst: [*]volatile u8 = @ptrFromInt(paging.physToVirt(cmd_phys));
    @memset(cmd_dst[0..4096], 0);

    const attach: *volatile AttachBacking = @ptrFromInt(paging.physToVirt(cmd_phys));
    attach.hdr.cmd_type = CMD_RESOURCE_ATTACH_BACKING;
    attach.resource_id = resource_id;
    attach.nr_entries = nr_merged;

    const entries: [*]volatile MemEntry = @ptrFromInt(paging.physToVirt(cmd_phys + @sizeOf(AttachBacking)));
    for (0..nr_merged) |j| {
        entries[j] = .{ .addr = merged[j].addr, .length = merged[j].length, .padding = 0 };
    }

    const total_len: u32 = @intCast(@sizeOf(AttachBacking) + nr_merged * @sizeOf(MemEntry));

    // Cmd is already built in cmd_phys; zero the response slot then run the
    // shared descriptor-chain helper.
    const resp_dst: [*]volatile u8 = @ptrFromInt(paging.physToVirt(resp_phys));
    @memset(resp_dst[0..@sizeOf(CtrlHdr)], 0);
    ctrl_lock.acquire();
    defer ctrl_lock.release();
    if (!sendCmdViaPhys(total_len, @sizeOf(CtrlHdr))) return false;

    clflushRange(paging.physToVirt(resp_phys), @sizeOf(CtrlHdr)); // gap #2
    const resp: *const CtrlHdr = @ptrFromInt(paging.physToVirt(resp_phys));
    if (resp.cmd_type != RESP_OK_NODATA) {
        debug.klog("[virtio-gpu] ATTACH_BACKING failed: 0x{X}\n", .{resp.cmd_type});
        return false;
    }
    return true;
}

fn setScanout(resource_id: u32, w: u32, h: u32) bool {
    var cmd = SetScanout{
        .hdr = .{ .cmd_type = CMD_SET_SCANOUT },
        .r = .{ .x = 0, .y = 0, .width = w, .height = h },
        .scanout_id = 0,
        .resource_id = resource_id,
    };
    return sendSimpleCmd(@as([*]const u8, @ptrCast(&cmd)), @sizeOf(SetScanout));
}

/// Point a scanout slot at a blob resource. Used by Vulkan apps that
/// render to a Venus-backed blob and want it displayed directly without
/// going through a CPU readback. format is a virtio_gpu_formats enum
/// (e.g. R8G8B8A8_UNORM=67). stride is bytes-per-row.
pub fn setScanoutBlob(scanout_id: u32, resource_id: u32, w: u32, h: u32, format: u32, stride: u32) bool {
    var cmd = SetScanoutBlob{
        .hdr = .{ .cmd_type = CMD_SET_SCANOUT_BLOB },
        .r = .{ .x = 0, .y = 0, .width = w, .height = h },
        .scanout_id = scanout_id,
        .resource_id = resource_id,
        .width = w,
        .height = h,
        .format = format,
        .strides = .{ stride, 0, 0, 0 },
    };
    return sendSimpleCmd(@as([*]const u8, @ptrCast(&cmd)), @sizeOf(SetScanoutBlob));
}

/// Tell the host display to re-read scanout contents from a resource.
/// After updating a scanned-out resource, call this to make the change
/// visible. Public wrapper of the existing internal resourceFlushCmd.
pub fn resourceFlush(resource_id: u32, w: u32, h: u32) bool {
    return resourceFlushCmd(resource_id, 0, 0, w, h);
}

fn transferToHost(resource_id: u32, x: u32, y: u32, w: u32, h: u32) bool {
    // offset = byte position in backing store where the rect's data starts
    // For full-width transfers (x=0, w=width), offset = y * stride
    const offset: u64 = @as(u64, y) * @as(u64, width) * 4 + @as(u64, x) * 4;
    var cmd = TransferToHost2D{
        .hdr = .{ .cmd_type = CMD_TRANSFER_TO_HOST_2D },
        .r = .{ .x = x, .y = y, .width = w, .height = h },
        .offset = offset,
        .resource_id = resource_id,
        .padding = 0,
    };
    return sendSimpleCmd(@as([*]const u8, @ptrCast(&cmd)), @sizeOf(TransferToHost2D));
}

fn resourceFlushCmd(resource_id: u32, x: u32, y: u32, w: u32, h: u32) bool {
    // Previously FENCE-flagged for implicit vblank sync. Measured cost
    // (perf.flush_rect): mean 86 M cycles ≈ 28 ms per call on QEMU's
    // GTK display backend — the fence response blocks until host
    // frame-done, and the desktop task is charged as busy for the
    // entire wait. At ~21 flushes/sec that was 60 %+ of one CPU spent
    // blocking on host vsync. Dropped the flag: tearing on the CPU
    // compositor path is invisible at UI refresh rates, and the GPU
    // compositor (mode 9, blob scanout) uses its own fence ping-pong
    // (`project_venus_fence_lies.md`) so it doesn't rely on this one.
    var cmd = ResourceFlush{
        .hdr = .{
            .cmd_type = CMD_RESOURCE_FLUSH,
        },
        .r = .{ .x = x, .y = y, .width = w, .height = h },
        .resource_id = resource_id,
        .padding = 0,
    };
    return sendSimpleCmd(@as([*]const u8, @ptrCast(&cmd)), @sizeOf(ResourceFlush));
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
    // Name the critical locks so a panic / watchdog dump can identify
    // who holds them when the system wedges. ctrl_lock specifically is
    // the one held across blockOn(.gpu_io) during virtio-gpu submits.
    @import("../proc/spinlock.zig").registerMutex("virtio_gpu.ctrl_lock", &ctrl_lock);
    @import("../proc/spinlock.zig").registerLock("virtio_gpu.cursor_lock", &cursor_lock);
    debug.klog("[virtio-gpu] Scanning for device...\n", .{});

    // Find virtio-gpu PCI device via the bus cache.
    const dev_found = pci.findByVendorDevice(VIRTIO_VENDOR, VIRTIO_GPU_DEVICE) orelse {
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
    const common_cap = pci.findVirtioCap(dev_found, VIRTIO_PCI_CAP_COMMON_CFG) orelse {
        debug.klog("[virtio-gpu] No common config capability\n", .{});
        return false;
    };
    const notify_cap = pci.findVirtioCap(dev_found, VIRTIO_PCI_CAP_NOTIFY_CFG) orelse {
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
    ccWrite8(CC_DEVICE_STATUS, 0); // Reset
    ccWrite8(CC_DEVICE_STATUS, STATUS_ACKNOWLEDGE);
    ccWrite8(CC_DEVICE_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER);

    // Feature negotiation — read device features, accept 3D + transport features
    ccWrite32(CC_DEVICE_FEATURE_SELECT, 0);
    const dev_features_0 = ccRead32(CC_DEVICE_FEATURE);
    ccWrite32(CC_DEVICE_FEATURE_SELECT, 1);
    const dev_features_1 = ccRead32(CC_DEVICE_FEATURE);
    debug.klog("[virtio-gpu] Device features: 0x{X} 0x{X}\n", .{ dev_features_0, dev_features_1 });

    // GPU features (word 0, bits 0-4)
    var driver_features_0: u32 = 0;
    if (dev_features_0 & (@as(u32, 1) << VIRTIO_GPU_F_VIRGL) != 0) {
        has_virgl = true;
        driver_features_0 |= @as(u32, 1) << VIRTIO_GPU_F_VIRGL;
    }
    if (dev_features_0 & (@as(u32, 1) << VIRTIO_GPU_F_RESOURCE_BLOB) != 0) {
        has_blob = true;
        driver_features_0 |= @as(u32, 1) << VIRTIO_GPU_F_RESOURCE_BLOB;
    }
    if (dev_features_0 & (@as(u32, 1) << VIRTIO_GPU_F_CONTEXT_INIT) != 0) {
        has_context_init = true;
        driver_features_0 |= @as(u32, 1) << VIRTIO_GPU_F_CONTEXT_INIT;
    }
    // Accept EDID if offered (bit 1)
    if (dev_features_0 & (@as(u32, 1) << VIRTIO_GPU_F_EDID) != 0) {
        driver_features_0 |= @as(u32, 1) << VIRTIO_GPU_F_EDID;
    }
    // VIRTIO_F_RING_EVENT_IDX (bit 29) — negotiate so the driver can suppress
    // unnecessary interrupts AND control exactly which usedIdx triggers the
    // next IRQ via the avail-ring `used_event` slot. Workaround for
    // CVE-2024-3446's mem_reentrancy_guard side-effect: by going through the
    // event_idx notification path in QEMU, we may bypass the silent-drop
    // class that hits unconditional MSI-X delivery for SUBMIT_3D.
    var have_event_idx: bool = false;
    if (dev_features_0 & (@as(u32, 1) << 29) != 0) {
        driver_features_0 |= @as(u32, 1) << 29;
        have_event_idx = true;
    }

    // Transport features (word 1): VIRTIO_F_VERSION_1 = bit 0 of word 1 (global bit 32)
    var driver_features_1: u32 = 0;
    if (dev_features_1 & 1 != 0) {
        driver_features_1 |= 1; // VERSION_1
    }

    ccWrite32(CC_DRIVER_FEATURE_SELECT, 0);
    ccWrite32(CC_DRIVER_FEATURE, driver_features_0);
    ccWrite32(CC_DRIVER_FEATURE_SELECT, 1);
    ccWrite32(CC_DRIVER_FEATURE, driver_features_1);
    ccWrite8(CC_DEVICE_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK);

    if (has_virgl) debug.klog("[virtio-gpu] 3D features: VIRGL{s}{s}{s}\n", .{
        if (has_blob) " BLOB" else "",
        if (has_context_init) " CTX_INIT" else "",
        if (have_event_idx) " EVENT_IDX" else "",
    });
    use_event_idx = have_event_idx;

    // Check FEATURES_OK
    if (ccRead8(CC_DEVICE_STATUS) & STATUS_FEATURES_OK == 0) {
        debug.klog("[virtio-gpu] FEATURES_OK not set!\n", .{});
        return false;
    }

    // Disable global MSIX
    ccWrite16(CC_MSIX_CONFIG, 0xFFFF);

    // Setup control virtqueue (queue 0)
    if (!setupQueue(0)) {
        debug.klog("[virtio-gpu] Failed to setup control queue\n", .{});
        ccWrite8(CC_DEVICE_STATUS, 0x80);
        return false;
    }
    // Map the queue rings into our IOVA space. Desc/avail share one page,
    // used has its own.
    _ = iommu.dmaMap(pci_bus, pci_dev, pci_func, ctrl_vq.desc_phys, 4096, .{});
    _ = iommu.dmaMap(pci_bus, pci_dev, pci_func, ctrl_vq.used_phys, 4096, .{});

    // Allocate command buffer (4 contiguous pages for large scatter-gather lists)
    cmd_phys = pmm.allocContiguous(CMD_PAGES) orelse return false;
    resp_phys = pmm.allocFrame() orelse return false;
    _ = iommu.dmaMap(pci_bus, pci_dev, pci_func, cmd_phys, CMD_PAGES * 4096, .{});
    _ = iommu.dmaMap(pci_bus, pci_dev, pci_func, resp_phys, 4096, .{});

    // Driver OK
    ccWrite8(CC_DEVICE_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK);
    debug.klog("[virtio-gpu] Device ready\n", .{});

    // Detect SHM BAR for blob resources
    if (has_blob) {
        detectShmBar(dev_found);
    }

    // Query capsets if 3D is available
    if (has_virgl) {
        queryCapsets();
    }

    // Get display info
    const display = getDisplayInfo() orelse {
        debug.klog("[virtio-gpu] No display available\n", .{});
        return false;
    };

    width = if (xres > 0) xres else display.width;
    height = if (yres > 0) yres else display.height;

    // Allocate guest framebuffer
    const fb_size = width * height * 4;
    fb_num_pages = (fb_size + 4095) / 4096;
    if (fb_num_pages > MAX_FB_PAGES) {
        debug.klog("[virtio-gpu] FB too large: {d} pages\n", .{fb_num_pages});
        return false;
    }

    const fb_virt = paging.allocGuestFB(fb_num_pages, &fb_page_phys) orelse {
        debug.klog("[virtio-gpu] Failed to allocate guest FB\n", .{});
        return false;
    };
    framebuffer = fb_virt;

    // Zero the framebuffer
    const fb_u8: [*]volatile u8 = @ptrCast(fb_virt);
    for (0..fb_size) |i| fb_u8[i] = 0;

    debug.klog("[virtio-gpu] FB: {d}x{d} ({d} pages)\n", .{ width, height, fb_num_pages });

    // Map every FB page into the device's IOVA space. allocGuestFB picks
    // scattered phys frames (one per page), so we iterate rather than
    // assuming contiguity.
    {
        var pi: u32 = 0;
        while (pi < fb_num_pages) : (pi += 1) {
            _ = iommu.dmaMap(pci_bus, pci_dev, pci_func, fb_page_phys[pi], 4096, .{});
        }
    }

    // Create display resources
    current_resource_id = 1;
    if (!setupDisplay(width, height)) return false;

    active = true;
    debug.klog("[virtio-gpu] Initialized {d}x{d}\n", .{ width, height });

    // Initialize hardware cursor
    _ = initCursor();

    // Wire MSI-X for the ctrl queue. Done here, AFTER all init-time
    // sendCmd calls (queryCapsets/getDisplayInfo/setupDisplay/initCursor)
    // have finished — those want the polled path because IF state during
    // boot is undefined and `sti; hlt` would force interrupts on too
    // early. From this point forward, sendCmd uses the IRQ-driven path.
    {
        if (msix.armOne(dev_found, 0, virtioGpuIrqHandler)) |armed| {
            // Point ctrl queue (0) at MSI-X table entry 0.
            ccWrite16(CC_QUEUE_SELECT, 0);
            ccWrite16(CC_QUEUE_MSIX_VECTOR, 0);
            if (ccRead16(CC_QUEUE_MSIX_VECTOR) == 0) {
                use_msix = true;
                msix_entry_addr = armed.entry_addr;
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

    bind.commit();
    return true;
}

/// Gap #3 (2026-05-20): per-tick sweeper, called from `handleIRQ0` on
/// BSP. Catches the case where the GPU device DID complete the command
/// but the IRQ never reached us (CVE-2024-3446 reentrancy guard silently
/// dropping virtio_notify, or PCIe posted-write ordering hiding the CQE
/// from the IRQ-time read). Walks the ctrl queue's coherent used_idx
/// and pokes all .gpu_io waiters' wake_tick to "now" so wakeExpired()
/// kicks them on the same tick. Mirrors `nvme.tickSweep`.
///
/// Cost when idle: one clflush + one memory read per tick. Sub-microsecond.
pub fn tickSweep() void {
    if (!active) return;
    if (!use_msix) return;
    const hw_used = usedIdxCoherent(&ctrl_vq);
    if (ctrl_vq.last_used_idx == hw_used) return;
    // HW advanced past SW — wake any .gpu_io waiter so its loop re-checks
    // (and via gap #1's clflush, observes the new used_idx this time).
    const process = @import("../proc/process.zig");
    var pid: u8 = 0;
    var any_woken = false;
    while (pid < process.MAX_PROCS) : (pid += 1) {
        const wk = @atomicLoad(u8, @as(*const u8, @ptrCast(&process.procs[pid].wait_kind)), .acquire);
        if (wk == @intFromEnum(process.WaitKind.gpu_io)) {
            @atomicStore(u64, &process.procs[pid].wake_tick, process.tick_count, .release);
            any_woken = true;
        }
    }
    // Register the deadline once (now) if we set any wake_tick — avoids N
    // cmpxchg loops for N waiters all stamping the same tick.
    if (any_woken) @import("../proc/sched.zig").registerWakeDeadline(process.tick_count);
}

/// Gap #4 (2026-05-20): diagnostic dump for the yield-loop / stuck-waiter
/// detectors. Mirrors `nvme.dumpWaiterForTarget`. `target` is the cmd_type
/// the waiter passed to blockOn — names which GPU command is hanging.
/// Reports SW vs HW state so the autopsy can distinguish:
///   - HW done, SW missed       → tickSweep regression / cache miss
///   - HW pending, ctrl_lock idle → device-side stuck (Venus deadlock, etc.)
///   - ctrl_lock held by dead pid → mutex-leak class
pub fn dumpWaiterForTarget(target: u32) void {
    debug.klog("  virtio-gpu state (cmd_type=0x{X}):\n", .{target});
    debug.klog("    active        = {any}\n", .{active});
    debug.klog("    use_msix      = {any}\n", .{use_msix});
    debug.klog("    msix_safe     = {any}\n", .{msix_safe_to_use});
    debug.klog("    use_event_idx = {any}\n", .{use_event_idx});
    if (!active) return;
    const hw_used = usedIdxCoherent(&ctrl_vq);
    debug.klog("    sw_last_used  = {d}\n", .{ctrl_vq.last_used_idx});
    debug.klog("    hw_used_idx   = {d}\n", .{hw_used});
    debug.klog("    avail_idx     = {d}\n", .{ctrl_vq.availIdx().*});
    debug.klog("    num_free      = {d}\n", .{ctrl_vq.num_free});
    debug.klog("    irq_count     = {d}\n", .{virtio_gpu_irq_count});
    debug.klog("    ipis_sent     = {d}\n", .{virtio_gpu_wake_ipis_sent});
    if (hw_used != ctrl_vq.last_used_idx) {
        debug.klog("    ===> HW advanced beyond SW; tickSweep should pick this up next tick\n", .{});
    } else if (ctrl_vq.availIdx().* != ctrl_vq.last_used_idx) {
        debug.klog("    ===> SW submitted a cmd; HW has NOT completed — device-side wedge\n", .{});
    } else {
        debug.klog("    (queue idle — waiter is racing a future submit?)\n", .{});
    }
}

/// Set up display: create resource, attach backing, set scanout.
fn setupDisplay(w: u32, h: u32) bool {
    debug.klog("[virtio-gpu] Creating resource {d} ({d}x{d})...\n", .{ current_resource_id, w, h });
    if (!resourceCreate2D(current_resource_id, w, h)) {
        debug.klog("[virtio-gpu] RESOURCE_CREATE_2D failed\n", .{});
        return false;
    }
    debug.klog("[virtio-gpu] Attaching {d} pages...\n", .{fb_num_pages});
    if (!attachBacking(current_resource_id, fb_page_phys[0..fb_num_pages], fb_num_pages)) {
        debug.klog("[virtio-gpu] ATTACH_BACKING failed\n", .{});
        return false;
    }
    debug.klog("[virtio-gpu] Setting scanout...\n", .{});
    if (!setScanout(current_resource_id, w, h)) {
        debug.klog("[virtio-gpu] SET_SCANOUT failed\n", .{});
        return false;
    }
    _ = transferToHost(current_resource_id, 0, 0, w, h);
    _ = resourceFlushCmd(current_resource_id, 0, 0, w, h);
    return true;
}

fn resourceUnref(resource_id: u32) bool {
    const ResourceUnref = extern struct { hdr: CtrlHdr, resource_id: u32, padding: u32 };
    var cmd = ResourceUnref{
        .hdr = .{ .cmd_type = CMD_RESOURCE_UNREF },
        .resource_id = resource_id,
        .padding = 0,
    };
    return sendSimpleCmd(@as([*]const u8, @ptrCast(&cmd)), @sizeOf(ResourceUnref));
}

fn detachBacking(resource_id: u32) bool {
    const DetachBacking = extern struct { hdr: CtrlHdr, resource_id: u32, padding: u32 };
    var cmd = DetachBacking{
        .hdr = .{ .cmd_type = CMD_RESOURCE_DETACH_BACKING },
        .resource_id = resource_id,
        .padding = 0,
    };
    return sendSimpleCmd(@as([*]const u8, @ptrCast(&cmd)), @sizeOf(DetachBacking));
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
    if (!active) return false;
    if (n < 1 or n > 2) return false;
    if (res_ids.len < n or virts.len < n) return false;
    if (scanout_is_blob) return false; // already armed; tear down first via dropBlobScanout

    // Capture the original 2D scanout resource before we overwrite
    // current_resource_id with the blob below. dropOriginal2DScanout
    // reads this to release the right host-side resource later.
    if (original_2d_resource_id == 0) original_2d_resource_id = current_resource_id;

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
    if (!setScanoutBlob(0, blob_resource_ids[0], width, height, FORMAT_B8G8R8X8_UNORM, width * 4)) {
        debug.klog("[virtio-gpu] armBlobScanout: setScanoutBlob FAILED\n", .{});
        // Re-arm 2D fallback so we don't black-screen.
        _ = setScanout(current_resource_id, width, height);
        return false;
    }

    // After arm, `framebuffer` points at the back blob (compositor's
    // write target). Single-buffer: back == front == blob[0]. Double-
    // buffer: blob[0] is initial front (host displays it), blob[1] is
    // back; the first flushUnconditional() page-flips them.
    blob_count = n;
    blob_front = 0;
    scanout_is_blob = true;
    if (n >= 2) {
        framebuffer = blob_virt[1];
        current_resource_id = blob_resource_ids[1];
    } else {
        framebuffer = blob_virt[0];
        current_resource_id = blob_resource_ids[0];
    }

    // First flush so the host's GL surface picks up the front blob's
    // contents (whatever the compositor pre-painted into it).
    _ = resourceFlushCmd(blob_resource_ids[0], 0, 0, width, height);
    debug.klog("[virtio-gpu] armBlobScanout: ok n={d} {d}x{d} res0={d}\n", .{ n, width, height, blob_resource_ids[0] });
    return true;
}

/// Change display resolution. Returns true if successful.
pub fn changeMode(new_w: u32, new_h: u32) bool {
    if (!active) return false;
    debug.klog("[virtio-gpu] Changing to {d}x{d}\n", .{ new_w, new_h });

    // Tear down old display
    debug.klog("[virtio-gpu] Disabling scanout...\n", .{});
    _ = setScanout(0, 0, 0); // Disable scanout (resource_id=0)
    debug.klog("[virtio-gpu] Detaching backing...\n", .{});
    _ = detachBacking(current_resource_id);
    debug.klog("[virtio-gpu] Unref resource {d}...\n", .{current_resource_id});
    _ = resourceUnref(current_resource_id);

    // Unmap old FB pages from device IOVA before they go back to PMM.
    {
        var pi: u32 = 0;
        while (pi < fb_num_pages) : (pi += 1) {
            iommu.dmaUnmap(pci_bus, pci_dev, pci_func, fb_page_phys[pi], 4096);
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
    framebuffer = fb_virt;
    width = new_w;
    height = new_h;

    // Map new FB pages into device IOVA.
    {
        var pi: u32 = 0;
        while (pi < fb_num_pages) : (pi += 1) {
            _ = iommu.dmaMap(pci_bus, pci_dev, pci_func, fb_page_phys[pi], 4096, .{});
        }
    }

    // Zero new FB
    const fb_u8: [*]volatile u8 = @ptrCast(fb_virt);
    for (0..fb_size) |i| fb_u8[i] = 0;

    // Create new display resources
    current_resource_id += 1;
    if (!setupDisplay(new_w, new_h)) return false;

    debug.klog("[virtio-gpu] Mode changed to {d}x{d}\n", .{ new_w, new_h });
    return true;
}

/// When true, public flush()/flushRect() calls become no-ops. The
/// mode-9 GPU compositor sets this flag so its own writes are the only
/// thing reaching the screen each frame; it uses flushUnconditional()
/// to bypass the gate when it actually wants to flush.
pub var skip_external_flush: bool = false;

// =============================================================================
// Compositor wedge tracking (gaps #7 + #16).
//
// Without this, a host-side stall (CVE-2024-3446 reentrancy drop, virgl
// thread stuck, host hypervisor descheduling for SMI) made the compositor
// call sendCmdViaPhys → 1-sec timeout, then immediately retry next frame.
// 60 retries/sec × 1 sec wait/retry = the desktop completely frozen for
// minutes while it grinds through identical failing submits.
//
// Now: after WEDGE_THRESHOLD consecutive flush failures we mark the GPU
// wedged and short-circuit subsequent flush*() calls (early-return at
// function entry). The desktop keeps running — input, syscalls, scheduling
// all unchanged — but the screen stops updating. Every
// WEDGE_PROBE_INTERVAL_TICKS we allow one probe through; if it succeeds,
// clear wedged and resume normal flushing.
//
// Threshold is small (4) because each failure already costs ~1 sec, so
// the user-visible latency budget is "blow 4 sec then surrender" — not
// the multi-minute hang the old code produced.
// =============================================================================
const WEDGE_THRESHOLD: u32 = 4;
const WEDGE_PROBE_INTERVAL_TICKS: u64 = 500; // ~5 sec at 100 Hz

var consecutive_flush_failures: u32 = 0;
pub var wedged: bool = false;
var wedge_first_tick: u64 = 0;
var last_probe_tick: u64 = 0;

/// Update wedge state from a sendSimpleCmdPair result. Returns the input
/// `ok` unchanged so the caller can keep its existing flow.
fn noteFlushResult(ok: bool) bool {
    if (ok) {
        if (wedged) {
            const span = @import("../proc/process.zig").tick_count -% wedge_first_tick;
            debug.klog("[gpu] CONTROLLER RECOVERED after {d} ticks wedged\n", .{span});
        }
        consecutive_flush_failures = 0;
        wedged = false;
    } else {
        consecutive_flush_failures +%= 1;
        if (!wedged and consecutive_flush_failures >= WEDGE_THRESHOLD) {
            wedged = true;
            wedge_first_tick = @import("../proc/process.zig").tick_count;
            last_probe_tick = wedge_first_tick;
            debug.klog(
                "[gpu] CONTROLLER WEDGE after {d} consecutive flush timeouts — suppressing flushes (probe every {d} ticks)\n",
                .{ consecutive_flush_failures, WEDGE_PROBE_INTERVAL_TICKS },
            );
        }
    }
    return ok;
}

/// Wedge gate for flush callers. Returns true → caller should early-return
/// (skip this frame's flush). Returns false → caller proceeds normally.
/// When wedged AND the probe interval has elapsed, returns false so ONE
/// flush attempt goes through; result feeds noteFlushResult and either
/// clears the wedge or re-arms the probe timer.
fn shouldSkipFlush() bool {
    if (!wedged) return false;
    const now = @import("../proc/process.zig").tick_count;
    if ((now -% last_probe_tick) >= WEDGE_PROBE_INTERVAL_TICKS) {
        last_probe_tick = now;
        return false; // let one probe through
    }
    return true;
}

pub fn flush() void {
    if (skip_external_flush) return;
    flushUnconditional();
}

pub fn flushUnconditional() void {
    if (!active) return;
    if (shouldSkipFlush()) return;
    const t = @import("../debug/perf.zig").enter();
    defer @import("../debug/perf.zig").leave(.flush_rect, t);
    if (scanout_is_blob and blob_count >= 2) {
        // Page flip: the compositor just wrote into blob[1-blob_front]
        // (which framebuffer points at). Display it, then point
        // framebuffer at the now-back blob (= old front). The two cmds
        // (SetScanoutBlob + ResourceFlush) are batched into one virtqueue
        // submit so the host pipelines them and we pay one round-trip
        // instead of two — the dominant per-frame cost on QEMU's GTK
        // backend (~21 ms saved/frame).
        const new_front = 1 - blob_front;
        var sb = SetScanoutBlob{
            .hdr = .{ .cmd_type = CMD_SET_SCANOUT_BLOB },
            .r = .{ .x = 0, .y = 0, .width = width, .height = height },
            .scanout_id = 0,
            .resource_id = blob_resource_ids[new_front],
            .width = width,
            .height = height,
            .format = FORMAT_B8G8R8X8_UNORM,
            .strides = .{ width * 4, 0, 0, 0 },
        };
        var rf = ResourceFlush{
            .hdr = .{ .cmd_type = CMD_RESOURCE_FLUSH },
            .r = .{ .x = 0, .y = 0, .width = width, .height = height },
            .resource_id = blob_resource_ids[new_front],
            .padding = 0,
        };
        _ = noteFlushResult(sendSimpleCmdPair(
            @as([*]const u8, @ptrCast(&sb)),
            @sizeOf(SetScanoutBlob),
            @as([*]const u8, @ptrCast(&rf)),
            @sizeOf(ResourceFlush),
        ));
        blob_front = new_front;
        framebuffer = blob_virt[1 - new_front];
        current_resource_id = blob_resource_ids[1 - new_front];
    } else if (scanout_is_blob) {
        // Single-buffer blob: host udmabuf-imports our pages, no transfer.
        _ = noteFlushResult(resourceFlushCmd(current_resource_id, 0, 0, width, height));
    } else {
        // 2D fallback: full transfer + flush — also batched into one
        // virtqueue submit + single MSI-X round-trip.
        var th = TransferToHost2D{
            .hdr = .{ .cmd_type = CMD_TRANSFER_TO_HOST_2D },
            .r = .{ .x = 0, .y = 0, .width = width, .height = height },
            .offset = 0,
            .resource_id = current_resource_id,
            .padding = 0,
        };
        var rf = ResourceFlush{
            .hdr = .{ .cmd_type = CMD_RESOURCE_FLUSH },
            .r = .{ .x = 0, .y = 0, .width = width, .height = height },
            .resource_id = current_resource_id,
            .padding = 0,
        };
        _ = noteFlushResult(sendSimpleCmdPair(
            @as([*]const u8, @ptrCast(&th)),
            @sizeOf(TransferToHost2D),
            @as([*]const u8, @ptrCast(&rf)),
            @sizeOf(ResourceFlush),
        ));
    }
}

/// Flush a dirty rectangle. Only transfers the specified region.
pub fn flushRect(x: u32, y: u32, w: u32, h: u32) void {
    if (skip_external_flush) return;
    flushRectUnconditional(x, y, w, h);
}

/// Compositor-only flushRect that bypasses skip_external_flush. The
/// mode-9 GPU compositor uses this to flush its own dirty regions.
pub fn flushRectUnconditional(x: u32, y: u32, w: u32, h: u32) void {
    if (!active) return;
    if (shouldSkipFlush()) return;
    const x0 = @min(x, width);
    const y0 = @min(y, height);
    const x1 = @min(x + w, width);
    const y1 = @min(y + h, height);
    if (x0 >= x1 or y0 >= y1) return;
    const t = @import("../debug/perf.zig").enter();
    defer @import("../debug/perf.zig").leave(.flush_rect, t);
    if (scanout_is_blob and blob_count >= 2) {
        // Page flip: SetScanoutBlob + ResourceFlush batched (see
        // flushUnconditional for rationale). Partial rects can't be
        // flipped — always present the whole back.
        const new_front = 1 - blob_front;
        var sb = SetScanoutBlob{
            .hdr = .{ .cmd_type = CMD_SET_SCANOUT_BLOB },
            .r = .{ .x = 0, .y = 0, .width = width, .height = height },
            .scanout_id = 0,
            .resource_id = blob_resource_ids[new_front],
            .width = width,
            .height = height,
            .format = FORMAT_B8G8R8X8_UNORM,
            .strides = .{ width * 4, 0, 0, 0 },
        };
        var rf = ResourceFlush{
            .hdr = .{ .cmd_type = CMD_RESOURCE_FLUSH },
            .r = .{ .x = 0, .y = 0, .width = width, .height = height },
            .resource_id = blob_resource_ids[new_front],
            .padding = 0,
        };
        _ = noteFlushResult(sendSimpleCmdPair(
            @as([*]const u8, @ptrCast(&sb)),
            @sizeOf(SetScanoutBlob),
            @as([*]const u8, @ptrCast(&rf)),
            @sizeOf(ResourceFlush),
        ));
        blob_front = new_front;
        framebuffer = blob_virt[1 - new_front];
        current_resource_id = blob_resource_ids[1 - new_front];
    } else if (scanout_is_blob) {
        _ = noteFlushResult(resourceFlushCmd(current_resource_id, x0, y0, x1 - x0, y1 - y0));
    } else {
        // 2D fallback dirty-rect path — transfer + flush batched.
        const xferw = x1 - x0;
        const xferh = y1 - y0;
        const offset: u64 = @as(u64, y0) * @as(u64, width) * 4 + @as(u64, x0) * 4;
        var th = TransferToHost2D{
            .hdr = .{ .cmd_type = CMD_TRANSFER_TO_HOST_2D },
            .r = .{ .x = x0, .y = y0, .width = xferw, .height = xferh },
            .offset = offset,
            .resource_id = current_resource_id,
            .padding = 0,
        };
        var rf = ResourceFlush{
            .hdr = .{ .cmd_type = CMD_RESOURCE_FLUSH },
            .r = .{ .x = x0, .y = y0, .width = xferw, .height = xferh },
            .resource_id = current_resource_id,
            .padding = 0,
        };
        _ = noteFlushResult(sendSimpleCmdPair(
            @as([*]const u8, @ptrCast(&th)),
            @sizeOf(TransferToHost2D),
            @as([*]const u8, @ptrCast(&rf)),
            @sizeOf(ResourceFlush),
        ));
    }
}

// Dirty rect accumulator for batched flushing
var dirty_x_min: u32 = 0xFFFFFFFF;
var dirty_y_min: u32 = 0xFFFFFFFF;
var dirty_x_max: u32 = 0;
var dirty_y_max: u32 = 0;

/// Mark a rectangular region as dirty (accumulated, flushed later with flushDirty).
pub fn markDirtyRect(x: u32, y: u32, w: u32, h: u32) void {
    const x1 = @min(x + w, width);
    const y1 = @min(y + h, height);
    if (x < dirty_x_min) dirty_x_min = x;
    if (y < dirty_y_min) dirty_y_min = y;
    if (x1 > dirty_x_max) dirty_x_max = x1;
    if (y1 > dirty_y_max) dirty_y_max = y1;
}

/// Mark a Y-band as dirty (backwards compat).
pub fn markDirty(y: u32, h: u32) void {
    markDirtyRect(0, y, width, h);
}

/// Mark entire screen dirty.
pub fn markFullDirty() void {
    dirty_x_min = 0;
    dirty_y_min = 0;
    dirty_x_max = width;
    dirty_y_max = height;
}

/// Flush all accumulated dirty regions in one transfer+flush.
pub fn flushDirty() void {
    if (!active) return;
    if (dirty_x_min >= dirty_x_max or dirty_y_min >= dirty_y_max) return;
    _ = transferToHost(current_resource_id, dirty_x_min, dirty_y_min, dirty_x_max - dirty_x_min, dirty_y_max - dirty_y_min);
    _ = resourceFlushCmd(current_resource_id, dirty_x_min, dirty_y_min, dirty_x_max - dirty_x_min, dirty_y_max - dirty_y_min);
    dirty_x_min = 0xFFFFFFFF;
    dirty_y_min = 0xFFFFFFFF;
    dirty_x_max = 0;
    dirty_y_max = 0;
}

// --- Hardware cursor ---

// The 12x16 arrow sprite (same as desktop.zig, converted to RGBA at init)
const SPRITE_W = 12;
const SPRITE_H = 16;
const cursor_sprite = [SPRITE_H][SPRITE_W]u8{
    .{ 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 1, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 1, 2, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 1, 2, 2, 2, 1, 0, 0, 0, 0, 0, 0, 0 },
    .{ 1, 2, 2, 2, 2, 1, 0, 0, 0, 0, 0, 0 },
    .{ 1, 2, 2, 2, 2, 2, 1, 0, 0, 0, 0, 0 },
    .{ 1, 2, 2, 2, 2, 2, 2, 1, 0, 0, 0, 0 },
    .{ 1, 2, 2, 2, 2, 2, 2, 2, 1, 0, 0, 0 },
    .{ 1, 2, 2, 2, 2, 2, 2, 2, 2, 1, 0, 0 },
    .{ 1, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 0 },
    .{ 1, 2, 2, 1, 2, 2, 1, 0, 0, 0, 0, 0 },
    .{ 1, 2, 1, 0, 1, 2, 2, 1, 0, 0, 0, 0 },
    .{ 1, 1, 0, 0, 1, 2, 2, 1, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 0, 1, 2, 2, 1, 0, 0, 0 },
    .{ 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0 },
};

/// Initialize hardware cursor: create 64x64 resource, upload image, enable.
pub fn initCursor() bool {
    if (!active) return false;

    // Setup cursor queue (queue 1)
    if (!setupQueueInto(1, &cursor_vq)) {
        debug.klog("[virtio-gpu] Failed to setup cursor queue\n", .{});
        return false;
    }
    _ = iommu.dmaMap(pci_bus, pci_dev, pci_func, cursor_vq.desc_phys, 4096, .{});
    _ = iommu.dmaMap(pci_bus, pci_dev, pci_func, cursor_vq.used_phys, 4096, .{});

    // Allocate cursor command page
    cursor_cmd_phys = pmm.allocFrame() orelse return false;
    @memset(@as([*]u8, @ptrFromInt(paging.physToVirt(cursor_cmd_phys)))[0..4096], 0);
    _ = iommu.dmaMap(pci_bus, pci_dev, pci_func, cursor_cmd_phys, 4096, .{});

    // Allocate cursor image: 64x64 RGBA = 16384 bytes = 4 contiguous pages
    const cursor_img_phys = pmm.allocContiguous(4) orelse return false;
    _ = iommu.dmaMap(pci_bus, pci_dev, pci_func, cursor_img_phys, 4 * 4096, .{});

    // Zero and draw cursor into the 64x64 RGBA buffer
    const pixels: [*]volatile u32 = @ptrFromInt(paging.physToVirt(cursor_img_phys));
    for (0..64 * 64) |i| pixels[i] = 0; // Fully transparent

    // Draw the sprite (0=transparent, 1=black, 2=white)
    for (0..SPRITE_H) |row| {
        for (0..SPRITE_W) |col| {
            const p = cursor_sprite[row][col];
            if (p != 0) {
                const color: u32 = if (p == 1) 0xFF000000 else 0xFFFFFFFF; // ARGB
                pixels[row * 64 + col] = color;
            }
        }
    }

    // Create 2D resource for cursor
    if (!resourceCreate2D(CURSOR_RESOURCE_ID, 64, 64)) {
        debug.klog("[virtio-gpu] Cursor resource create failed\n", .{});
        return false;
    }

    // Attach backing (single contiguous 4-page region). Build directly in
    // cmd_phys + sendCmdViaPhys — using sendCmd would self-alias the
    // @memcpy (cmd_buf and cmd_dst both point at cmd_phys via physmap).
    _ = [1]usize{cursor_img_phys}; // (kept for clarity — single-entry SG)
    const cmd_dst: [*]volatile u8 = @ptrFromInt(paging.physToVirt(cmd_phys));
    @memset(cmd_dst[0..4096], 0);

    const attach: *volatile AttachBacking = @ptrFromInt(paging.physToVirt(cmd_phys));
    attach.hdr.cmd_type = CMD_RESOURCE_ATTACH_BACKING;
    attach.resource_id = CURSOR_RESOURCE_ID;
    attach.nr_entries = 1;
    const entries: [*]volatile MemEntry = @ptrFromInt(paging.physToVirt(cmd_phys + @sizeOf(AttachBacking)));
    entries[0] = .{ .addr = cursor_img_phys, .length = 64 * 64 * 4, .padding = 0 };

    const total_len: u32 = @sizeOf(AttachBacking) + @sizeOf(MemEntry);
    {
        const resp_dst: [*]volatile u8 = @ptrFromInt(paging.physToVirt(resp_phys));
        @memset(resp_dst[0..@sizeOf(CtrlHdr)], 0);
        ctrl_lock.acquire();
        defer ctrl_lock.release();
        if (!sendCmdViaPhys(total_len, @sizeOf(CtrlHdr))) {
            debug.klog("[virtio-gpu] Cursor backing attach failed\n", .{});
            return false;
        }
        clflushRange(paging.physToVirt(resp_phys), @sizeOf(CtrlHdr)); // gap #2
        const resp: *const CtrlHdr = @ptrFromInt(paging.physToVirt(resp_phys));
        if (resp.cmd_type != RESP_OK_NODATA) {
            debug.klog("[virtio-gpu] Cursor ATTACH_BACKING resp 0x{X}\n", .{resp.cmd_type});
            return false;
        }
    }

    // Transfer cursor image to host
    _ = transferToHost(CURSOR_RESOURCE_ID, 0, 0, 64, 64);

    // Send UPDATE_CURSOR via cursor queue
    sendCursorCmd(CMD_UPDATE_CURSOR, 0, 0, CURSOR_RESOURCE_ID);

    hw_cursor_active = true;
    debug.klog("[virtio-gpu] Hardware cursor enabled\n", .{});
    return true;
}

/// Move hardware cursor to (x, y). Lightweight — just sends position via cursor queue.
pub var cursor_hidden: bool = false;

pub fn moveCursor(x: i32, y: i32) void {
    if (!hw_cursor_active) return;
    if (cursor_hidden) return; // don't move when hidden
    const ux: u32 = if (x < 0) 0 else @intCast(x);
    const uy: u32 = if (y < 0) 0 else @intCast(y);
    sendCursorCmd(CMD_MOVE_CURSOR, ux, uy, CURSOR_RESOURCE_ID);
}

pub fn hideCursor() void {
    if (!hw_cursor_active) return;
    cursor_hidden = true;
    // Detach cursor resource from scanout (resource_id=0 removes cursor)
    sendCursorCmd(CMD_UPDATE_CURSOR, 0, 0, 0);
}

pub fn showCursor() void {
    if (!hw_cursor_active) return;
    cursor_hidden = false;
    // Re-attach cursor resource to scanout
    sendCursorCmd(CMD_UPDATE_CURSOR, 0, 0, CURSOR_RESOURCE_ID);
}

/// Send a cursor command (fire-and-forget, no response).
fn sendCursorCmd(cmd_type: u32, x: u32, y: u32, resource_id: u32) void {
    const flags = cursor_lock.acquireIrqSave();
    defer cursor_lock.releaseIrqRestore(flags);
    if (cursor_vq.num_free == 0) return;

    // Pick the next ring slot and compute its phys addr. Each in-flight
    // descriptor owns its slot until the host completes; the next call
    // writes into a different slot, so the host never sees a torn struct
    // even when sendCursorCmd is invoked back-to-back faster than the
    // host can drain.
    const slot = cursor_ring_idx % CURSOR_RING_SIZE;
    cursor_ring_idx +%= 1;
    const slot_offset = slot * @sizeOf(UpdateCursor);
    const slot_phys = cursor_cmd_phys + slot_offset;
    const cmd: *volatile UpdateCursor = @ptrFromInt(paging.physToVirt(slot_phys));
    cmd.hdr.cmd_type = cmd_type;
    cmd.hdr.flags = 0;
    cmd.hdr.fence_id = 0;
    cmd.hdr.ctx_id = 0;
    cmd.hdr.ring_idx = 0;
    cmd.hdr.padding = .{ 0, 0, 0 };
    cmd.pos.scanout_id = 0;
    cmd.pos.x = x;
    cmd.pos.y = y;
    cmd.pos.padding = 0;
    cmd.resource_id = resource_id;
    cmd.hot_x = 0;
    cmd.hot_y = 0;
    cmd.padding = 0;

    // Add to cursor queue (single descriptor, no response needed)
    const d_idx = cursor_vq.free_head;
    const d = cursor_vq.descPtr(d_idx);
    cursor_vq.free_head = @intCast(d.next);
    cursor_vq.num_free -= 1;

    d.addr = slot_phys;
    d.len = @sizeOf(UpdateCursor);
    d.flags = 0; // No WRITE flag, no NEXT — fire and forget
    d.next = 0;

    const ai = cursor_vq.availIdx().*;
    cursor_vq.availRing(ai % cursor_vq.queue_size).* = d_idx;
    asm volatile ("" ::: .{ .memory = true }); // compiler barrier; x86 TSO handles CPU ordering
    cursor_vq.availIdx().* = ai +% 1;

    // Notify cursor queue (uses cached notify_off — see notifyQueue helper).
    notifyQueue(1, &cursor_vq);

    // Reclaim used descriptors. The host's used-ring entry tells us
    // WHICH descriptor completed via usedRingId(ui).* — we must NOT
    // re-push the local `d_idx` we just submitted (that is the same
    // slot N times across N completions, corrupting the free list
    // into a self-loop and over-incrementing num_free). Prior bug:
    // after enough cursor moves num_free underflows / free_head
    // points at itself, and sendCursorCmd silently drops at the
    // num_free==0 guard above. Mouse cursor "stops updating" after
    // ~queue_size moves. Read each completed id from the used ring
    // and return THAT desc to the free list.
    while (cursor_vq.last_used_idx != usedIdxCoherent(&cursor_vq)) {
        const ui = cursor_vq.last_used_idx % cursor_vq.queue_size;
        const used_id: u16 = @intCast(cursor_vq.usedRingId(ui).*);
        cursor_vq.last_used_idx +%= 1;
        if (used_id >= cursor_vq.queue_size) continue;
        const used_d = cursor_vq.descPtr(used_id);
        used_d.next = cursor_vq.free_head;
        cursor_vq.free_head = used_id;
        cursor_vq.num_free += 1;
    }
}

// ============================================================
// 3D Context API
// ============================================================

var next_3d_resource_id: u32 = 1000;

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
    var cmd = CtxCreate{
        .hdr = .{ .cmd_type = CMD_CTX_CREATE, .ctx_id = ctx_id },
        .context_init = if (has_context_init) capset_id else 0,
    };

    // Copy debug name
    const copy_len = if (name.len > 64) 64 else name.len;
    for (0..copy_len) |i| cmd.debug_name[i] = name[i];
    cmd.nlen = @intCast(copy_len);

    var resp = CtrlHdr{};
    if (!sendCmd(
        @as([*]const u8, @ptrCast(&cmd)),
        @sizeOf(CtxCreate),
        @as([*]u8, @ptrCast(&resp)),
        @sizeOf(CtrlHdr),
    )) {
        debug.klog("[virtio-gpu] ctxCreate timeout\n", .{});
        return false;
    }

    if (resp.cmd_type != RESP_OK_NODATA) {
        debug.klog("[virtio-gpu] ctxCreate failed: 0x{X}\n", .{resp.cmd_type});
        return false;
    }

    debug.klog("[virtio-gpu] 3D context {d} created (capset={d})\n", .{ ctx_id, capset_id });
    return true;
}

/// Destroy a 3D context.
pub fn ctxDestroy(ctx_id: u32) bool {
    var cmd = CtrlHdr{ .cmd_type = CMD_CTX_DESTROY, .ctx_id = ctx_id };
    var resp = CtrlHdr{};
    if (!sendCmd(
        @as([*]const u8, @ptrCast(&cmd)),
        @sizeOf(CtrlHdr),
        @as([*]u8, @ptrCast(&resp)),
        @sizeOf(CtrlHdr),
    )) return false;
    return resp.cmd_type == RESP_OK_NODATA;
}

/// Attach a resource to a 3D context (makes it accessible to the context).
pub fn ctxAttachResource(ctx_id: u32, resource_id: u32) bool {
    var cmd = CtxResource{
        .hdr = .{ .cmd_type = CMD_CTX_ATTACH_RESOURCE, .ctx_id = ctx_id },
        .resource_id = resource_id,
    };
    var resp = CtrlHdr{};
    if (!sendCmd(
        @as([*]const u8, @ptrCast(&cmd)),
        @sizeOf(CtxResource),
        @as([*]u8, @ptrCast(&resp)),
        @sizeOf(CtrlHdr),
    )) return false;
    return resp.cmd_type == RESP_OK_NODATA;
}

/// Submit a 3D command buffer to a context.
/// cmd_data contains VirGL or Venus protocol commands.
pub fn submit3D(ctx_id: u32, cmd_data: []const u8) bool {
    const hdr_size = @sizeOf(CmdSubmit3D);
    const total = hdr_size + cmd_data.len;
    if (total > CMD_PAGES * 4096) {
        debug.klog("[virtio-gpu] submit3D too large: {d}\n", .{cmd_data.len});
        return false;
    }

    // Serialize against sendCmd — both touch ctrl_vq + cmd_phys/resp_phys.
    // Without this, BSP rendering racing with AP syscalls corrupts the ring.
    ctrl_lock.acquire();
    defer ctrl_lock.release();

    // Write header + command data directly to cmd_phys.
    const dst: [*]volatile u8 = @ptrFromInt(paging.physToVirt(cmd_phys));
    var hdr = CmdSubmit3D{
        .hdr = .{ .cmd_type = CMD_SUBMIT_3D, .ctx_id = ctx_id },
        .size = @intCast(cmd_data.len),
    };
    const hdr_bytes: [*]const u8 = @ptrCast(&hdr);
    @memcpy(@as([*]volatile u8, dst)[0..hdr_size], hdr_bytes[0..hdr_size]);
    @memcpy(@as([*]volatile u8, dst + hdr_size)[0..cmd_data.len], cmd_data);

    const resp_dst: [*]volatile u8 = @ptrFromInt(paging.physToVirt(resp_phys));
    @memset(resp_dst[0..@sizeOf(CtrlHdr)], 0);

    if (!sendCmdViaPhys(@intCast(total), @sizeOf(CtrlHdr))) return false;

    clflushRange(paging.physToVirt(resp_phys), @sizeOf(CtrlHdr)); // gap #2
    const resp: *volatile CtrlHdr = @ptrFromInt(paging.physToVirt(resp_phys));
    return resp.cmd_type == RESP_OK_NODATA;
}

/// Create a blob resource (for shared memory with host GPU).
pub fn resourceCreateBlob(ctx_id: u32, resource_id: u32, blob_mem: u32, blob_flags: u32, blob_id: u64, size: u64) bool {
    debug.klog("[virtio-gpu] createBlob: ctx={d} res={d} mem={d} flags={d} blob_id={d} size={d} struct_size={d}\n", .{ ctx_id, resource_id, blob_mem, blob_flags, blob_id, size, @sizeOf(ResourceCreateBlob) });
    var cmd = ResourceCreateBlob{
        .hdr = .{ .cmd_type = CMD_RESOURCE_CREATE_BLOB, .ctx_id = ctx_id },
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
    var resp_buf: [@sizeOf(RespResourceUuid)]u8 align(4) = @splat(0);
    if (!sendCmd(
        @as([*]const u8, @ptrCast(&cmd)),
        @sizeOf(ResourceCreateBlob),
        &resp_buf,
        @sizeOf(RespResourceUuid),
    )) {
        debug.klog("[virtio-gpu] createBlob timeout\n", .{});
        return false;
    }
    const resp_hdr: *const CtrlHdr = @ptrCast(@alignCast(&resp_buf));
    if (resp_hdr.cmd_type != RESP_OK_NODATA) {
        debug.klog("[virtio-gpu] createBlob failed: 0x{X}\n", .{resp_hdr.cmd_type});
        return false;
    }
    return true;
}

// SHM BAR bump allocator — each blob gets a unique page-aligned offset
var shm_next_offset: u64 = 0;

/// Map a blob resource into the SHM BAR. Returns the physical address or null.
/// The offset is a guest-specified INPUT telling QEMU where in the SHM BAR to place this blob.
/// The response only contains caching flags (map_info), NOT an offset.
pub fn resourceMapBlob(resource_id: u32, size: u32) ?usize {
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

    var cmd = ResourceMapBlob{
        .hdr = .{ .cmd_type = CMD_RESOURCE_MAP_BLOB },
        .resource_id = resource_id,
        .offset = offset, // Guest-specified offset into SHM BAR
    };
    var resp: RespMapInfo = undefined;
    @memset(@as([*]u8, @ptrCast(&resp))[0..@sizeOf(RespMapInfo)], 0);

    debug.klog("[virtio-gpu] mapBlob: sending res={d} offset=0x{X} size={d}\n", .{ resource_id, offset, size });
    if (!sendCmd(
        @as([*]const u8, @ptrCast(&cmd)),
        @sizeOf(ResourceMapBlob),
        @as([*]u8, @ptrCast(&resp)),
        @sizeOf(RespMapInfo),
    )) {
        debug.klog("[virtio-gpu] mapBlob: sendCmd timeout\n", .{});
        return null;
    }

    debug.klog("[virtio-gpu] mapBlob: resp_type=0x{X} map_info={d}\n", .{ resp.hdr.cmd_type, resp.map_info });
    if (resp.hdr.cmd_type != RESP_OK_MAP_INFO) return null;

    const phys = shm_bar_phys + @as(usize, @truncate(offset));
    debug.klog("[virtio-gpu] mapBlob: res={d} offset=0x{X} phys=0x{X}\n", .{ resource_id, offset, phys });
    return phys;
}

/// Create a 3D resource (texture/buffer) for VirGL rendering.
pub fn resourceCreate3D(ctx_id: u32, resource_id: u32, target: u32, format: u32, bind: u32, w: u32, h: u32) bool {
    var cmd = ResourceCreate3D{
        .hdr = .{ .cmd_type = CMD_RESOURCE_CREATE_3D, .ctx_id = ctx_id },
        .resource_id = resource_id,
        .target = target,
        .format = format,
        .bind = bind,
        .width = w,
        .height = h,
    };
    var resp = CtrlHdr{};
    if (!sendCmd(
        @as([*]const u8, @ptrCast(&cmd)),
        @sizeOf(ResourceCreate3D),
        @as([*]u8, @ptrCast(&resp)),
        @sizeOf(CtrlHdr),
    )) return false;
    if (resp.cmd_type != RESP_OK_NODATA) {
        debug.klog("[virtio-gpu] resourceCreate3D failed: 0x{X}\n", .{resp.cmd_type});
        return false;
    }
    return true;
}

/// Transfer 3D resource contents from guest to host.
pub fn transferToHost3D(ctx_id: u32, resource_id: u32, w: u32, h: u32, stride: u32) bool {
    var cmd = TransferHost3D{
        .hdr = .{ .cmd_type = CMD_TRANSFER_TO_HOST_3D, .ctx_id = ctx_id },
        .box_w = w,
        .box_h = h,
        .box_d = 1,
        .resource_id = resource_id,
        .stride = stride,
    };
    var resp = CtrlHdr{};
    if (!sendCmd(
        @as([*]const u8, @ptrCast(&cmd)),
        @sizeOf(TransferHost3D),
        @as([*]u8, @ptrCast(&resp)),
        @sizeOf(CtrlHdr),
    )) return false;
    if (resp.cmd_type != RESP_OK_NODATA) {
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
    _ = iommu.dmaMap(pci_bus, pci_dev, pci_func, phys_base, size, .{});

    const cmd_dst: [*]volatile u8 = @ptrFromInt(paging.physToVirt(cmd_phys));
    @memset(cmd_dst[0..4096], 0);

    const cmd: *volatile ResourceCreateBlob = @ptrFromInt(paging.physToVirt(cmd_phys));
    cmd.hdr = .{ .cmd_type = CMD_RESOURCE_CREATE_BLOB, .ctx_id = ctx_id };
    cmd.resource_id = resource_id;
    cmd.blob_mem = BLOB_MEM_GUEST;
    cmd.blob_flags = blob_flags;
    cmd.nr_entries = 1;
    cmd.blob_id = 0;
    cmd.size = size;

    const entry: *volatile MemEntry = @ptrFromInt(paging.physToVirt(cmd_phys + @sizeOf(ResourceCreateBlob)));
    entry.* = .{ .addr = phys_base, .length = @truncate(size), .padding = 0 };

    const total_len: u32 = @intCast(@sizeOf(ResourceCreateBlob) + @sizeOf(MemEntry));

    const resp_dst: [*]volatile u8 = @ptrFromInt(paging.physToVirt(resp_phys));
    @memset(resp_dst[0..48], 0);

    ctrl_lock.acquire();
    defer ctrl_lock.release();
    if (!sendCmdViaPhys(total_len, 48)) {
        debug.klog("[virtio-gpu] createGuestBlob timeout\n", .{});
        return false;
    }

    clflushRange(paging.physToVirt(resp_phys), 48); // gap #2
    const resp: *const CtrlHdr = @ptrFromInt(paging.physToVirt(resp_phys));
    if (resp.cmd_type != RESP_OK_NODATA) {
        debug.klog("[virtio-gpu] createGuestBlob failed: 0x{X}\n", .{resp.cmd_type});
        return false;
    }
    return true;
}

/// Transfer 3D resource contents from host back to guest. Used to read pixels
/// rendered by Lavapipe (or any host-side 3D backend) into a guest-mmapped
/// blob — the explicit readback path when auto-dmabuf-sharing isn't engaged.
pub fn transferFromHost3D(ctx_id: u32, resource_id: u32, w: u32, h: u32, stride: u32) bool {
    var cmd = TransferHost3D{
        .hdr = .{ .cmd_type = CMD_TRANSFER_FROM_HOST_3D, .ctx_id = ctx_id },
        .box_w = w,
        .box_h = h,
        .box_d = 1,
        .resource_id = resource_id,
        .stride = stride,
    };
    var resp = CtrlHdr{};
    if (!sendCmd(
        @as([*]const u8, @ptrCast(&cmd)),
        @sizeOf(TransferHost3D),
        @as([*]u8, @ptrCast(&resp)),
        @sizeOf(CtrlHdr),
    )) return false;
    if (resp.cmd_type != RESP_OK_NODATA) {
        debug.klog("[virtio-gpu] transferFromHost3D failed: 0x{X}\n", .{resp.cmd_type});
        return false;
    }
    return true;
}
