//! virtio-gpu wire format (virtio 1.2 §5.7, Linux uapi virtio_gpu.h).
//! Sizes are checked against the spec at the bottom.

pub const VENDOR: u16 = 0x1AF4;
pub const DEVICE: u16 = 0x1050; // 0x1040 + device type 16

// Feature bits, word 0.
pub const F_VIRGL: u5 = 0;
pub const F_EDID: u5 = 1;
pub const F_RESOURCE_UUID: u5 = 2;
pub const F_RESOURCE_BLOB: u5 = 3;
pub const F_CONTEXT_INIT: u5 = 4;
pub const F_RING_EVENT_IDX: u5 = 29; // transport bit, also in word 0
// Word 1.
pub const F_VERSION_1_HI: u5 = 0; // global bit 32

// 2D commands.
pub const CMD_GET_DISPLAY_INFO: u32 = 0x0100;
pub const CMD_RESOURCE_CREATE_2D: u32 = 0x0101;
pub const CMD_RESOURCE_UNREF: u32 = 0x0102;
pub const CMD_SET_SCANOUT: u32 = 0x0103;
pub const CMD_RESOURCE_FLUSH: u32 = 0x0104;
pub const CMD_TRANSFER_TO_HOST_2D: u32 = 0x0105;
pub const CMD_RESOURCE_ATTACH_BACKING: u32 = 0x0106;
pub const CMD_RESOURCE_DETACH_BACKING: u32 = 0x0107;
pub const CMD_GET_CAPSET_INFO: u32 = 0x0108;
pub const CMD_GET_CAPSET: u32 = 0x0109;
pub const CMD_GET_EDID: u32 = 0x010a;
pub const CMD_RESOURCE_ASSIGN_UUID: u32 = 0x010b;
pub const CMD_RESOURCE_CREATE_BLOB: u32 = 0x010c;
pub const CMD_SET_SCANOUT_BLOB: u32 = 0x010d;

// 3D commands.
pub const CMD_CTX_CREATE: u32 = 0x0200;
pub const CMD_CTX_DESTROY: u32 = 0x0201;
pub const CMD_CTX_ATTACH_RESOURCE: u32 = 0x0202;
pub const CMD_CTX_DETACH_RESOURCE: u32 = 0x0203;
pub const CMD_RESOURCE_CREATE_3D: u32 = 0x0204;
pub const CMD_TRANSFER_TO_HOST_3D: u32 = 0x0205;
pub const CMD_TRANSFER_FROM_HOST_3D: u32 = 0x0206;
pub const CMD_SUBMIT_3D: u32 = 0x0207;
pub const CMD_RESOURCE_MAP_BLOB: u32 = 0x0208;
pub const CMD_RESOURCE_UNMAP_BLOB: u32 = 0x0209;

// Cursor queue.
pub const CMD_UPDATE_CURSOR: u32 = 0x0300;
pub const CMD_MOVE_CURSOR: u32 = 0x0301;

// CtrlHdr.flags bit 0: the device answers only once fence_id signals.
pub const FLAG_FENCE: u32 = 1;

pub const RESP_OK_NODATA: u32 = 0x1100;
pub const RESP_OK_DISPLAY_INFO: u32 = 0x1101;
pub const RESP_OK_CAPSET_INFO: u32 = 0x1102;
pub const RESP_OK_CAPSET: u32 = 0x1103;
pub const RESP_OK_EDID: u32 = 0x1104;
pub const RESP_OK_RESOURCE_UUID: u32 = 0x1105;
pub const RESP_OK_MAP_INFO: u32 = 0x1106;

pub const CAPSET_VIRGL: u32 = 1;
pub const CAPSET_VIRGL2: u32 = 2;
pub const CAPSET_VENUS: u32 = 4;
pub const CAPSET_DRM: u32 = 5;

pub const FORMAT_B8G8R8A8_UNORM: u32 = 1; // ARGB8888
pub const FORMAT_B8G8R8X8_UNORM: u32 = 2; // XRGB8888, pixel = 0x00RRGGBB

pub const BLOB_MEM_GUEST: u32 = 1;
pub const BLOB_MEM_HOST3D: u32 = 2;
pub const BLOB_MEM_HOST3D_GUEST: u32 = 3;

pub const BLOB_FLAG_USE_MAPPABLE: u32 = 1;
pub const BLOB_FLAG_USE_SHAREABLE: u32 = 2;
pub const BLOB_FLAG_USE_CROSS_DEVICE: u32 = 4;

// VIRTIO_GPU_SHM_ID_HOST_VISIBLE: the shared-memory cap of the hostmem BAR.
pub const SHM_ID_HOST_VISIBLE: u8 = 1;

pub const CtrlHdr = extern struct {
    cmd_type: u32 = 0,
    flags: u32 = 0,
    fence_id: u64 = 0,
    ctx_id: u32 = 0,
    ring_idx: u8 = 0,
    padding: [3]u8 = .{ 0, 0, 0 },
};

pub const Rect = extern struct {
    x: u32 = 0,
    y: u32 = 0,
    width: u32 = 0,
    height: u32 = 0,
};

pub const PmodeInfo = extern struct {
    r: Rect,
    enabled: u32,
    flags: u32,
};

pub const DisplayInfo = extern struct {
    hdr: CtrlHdr,
    pmodes: [16]PmodeInfo,
};

pub const ResourceCreate2D = extern struct {
    hdr: CtrlHdr,
    resource_id: u32,
    format: u32,
    width: u32,
    height: u32,
};

/// RESOURCE_UNREF and RESOURCE_DETACH_BACKING.
pub const ResourceId = extern struct {
    hdr: CtrlHdr,
    resource_id: u32,
    padding: u32 = 0,
};

/// Followed by nr_entries MemEntry.
pub const AttachBacking = extern struct {
    hdr: CtrlHdr,
    resource_id: u32,
    nr_entries: u32,
};

pub const MemEntry = extern struct {
    addr: u64,
    length: u32,
    padding: u32,
};

pub const SetScanout = extern struct {
    hdr: CtrlHdr,
    r: Rect,
    scanout_id: u32,
    resource_id: u32,
};

pub const SetScanoutBlob = extern struct {
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

pub const TransferToHost2D = extern struct {
    hdr: CtrlHdr,
    r: Rect,
    offset: u64,
    resource_id: u32,
    padding: u32,
};

pub const ResourceFlush = extern struct {
    hdr: CtrlHdr,
    r: Rect,
    resource_id: u32,
    padding: u32,
};

pub const CursorPos = extern struct {
    scanout_id: u32 = 0,
    x: u32 = 0,
    y: u32 = 0,
    padding: u32 = 0,
};

pub const UpdateCursor = extern struct {
    hdr: CtrlHdr = .{},
    pos: CursorPos = .{},
    resource_id: u32 = 0,
    hot_x: u32 = 0,
    hot_y: u32 = 0,
    padding: u32 = 0,
};

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

pub const GetCapset = extern struct {
    hdr: CtrlHdr = .{},
    capset_id: u32 = 0,
    capset_size: u32 = 0,
};

/// RESOURCE_CREATE_BLOB may answer OK_NODATA or OK_RESOURCE_UUID; receive
/// buffers are sized for the larger one.
pub const RespResourceUuid = extern struct {
    hdr: CtrlHdr = .{},
    uuid: [16]u8 = @splat(0),
};

pub const CtxCreate = extern struct {
    hdr: CtrlHdr = .{},
    nlen: u32 = 0,
    context_init: u32 = 0,
    debug_name: [64]u8 = [_]u8{0} ** 64,
};

pub const CtxResource = extern struct {
    hdr: CtrlHdr = .{},
    resource_id: u32 = 0,
    padding: u32 = 0,
};

/// Followed by `size` bytes of the context's protocol stream.
pub const CmdSubmit3D = extern struct {
    hdr: CtrlHdr = .{},
    size: u32 = 0,
    padding: u32 = 0,
};

/// Followed by nr_entries MemEntry for BLOB_MEM_GUEST.
pub const ResourceCreateBlob = extern struct {
    hdr: CtrlHdr = .{},
    resource_id: u32 = 0,
    blob_mem: u32 = 0,
    blob_flags: u32 = 0,
    nr_entries: u32 = 0,
    blob_id: u64 = 0,
    size: u64 = 0,
};

/// offset: where in the hostmem BAR the guest wants the blob.
pub const ResourceMapBlob = extern struct {
    hdr: CtrlHdr = .{},
    resource_id: u32 = 0,
    padding: u32 = 0,
    offset: u64 = 0,
};

/// The spec's response is 32 bytes; map_offset is never written.
pub const RespMapInfo = extern struct {
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

/// ATTACH_BACKING of one contiguous range.
pub const AttachBackingOne = extern struct {
    attach: AttachBacking,
    entry: MemEntry,
};

/// RESOURCE_CREATE_BLOB of one contiguous range of guest memory.
pub const ResourceCreateBlobOne = extern struct {
    blob: ResourceCreateBlob,
    entry: MemEntry,
};

pub const TransferHost3D = extern struct {
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

comptime {
    const sizes = .{
        .{ CtrlHdr, 24 },           .{ Rect, 16 },              .{ DisplayInfo, 408 },
        .{ ResourceCreate2D, 40 },  .{ ResourceId, 32 },        .{ AttachBacking, 32 },
        .{ MemEntry, 16 },          .{ SetScanout, 48 },        .{ SetScanoutBlob, 96 },
        .{ TransferToHost2D, 56 },  .{ ResourceFlush, 48 },     .{ UpdateCursor, 56 },
        .{ GetCapsetInfo, 32 },     .{ RespCapsetInfo, 40 },    .{ GetCapset, 32 },
        .{ RespResourceUuid, 40 },  .{ CtxCreate, 96 },         .{ CtxResource, 32 },
        .{ CmdSubmit3D, 32 },       .{ ResourceCreateBlob, 56 }, .{ ResourceMapBlob, 40 },
        .{ ResourceCreate3D, 72 },  .{ TransferHost3D, 72 },    .{ AttachBackingOne, 48 },
        .{ ResourceCreateBlobOne, 72 },
    };
    for (sizes) |s| {
        @setEvalBranchQuota(10_000);
        if (@sizeOf(s[0]) != s[1]) @compileError("virtio-gpu: " ++ @typeName(s[0]) ++ " does not match the spec size");
    }
}
