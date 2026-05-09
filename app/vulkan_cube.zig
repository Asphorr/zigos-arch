// Vulkan Spinning Cube — Venus wire protocol over virtio-gpu
// Renders an animated multi-colored cube with depth testing and push constants

const libc = @import("libc");
const venus = @import("venus");
const SpirV = @import("spirv");

// SPIR-V shaders — glslc-compiled (fallback while debugging comptime)
const lit_vert_spirv = [_]u32{
    0x07230203, 0x00010000, 0x000d000b, 0x0000002a, 0x00000000, 0x00020011, 0x00000001, 0x0006000b,
    0x00000001, 0x4c534c47, 0x6474732e, 0x3035342e, 0x00000000, 0x0003000e, 0x00000000, 0x00000001,
    0x000b000f, 0x00000000, 0x00000004, 0x6e69616d, 0x00000000, 0x0000000d, 0x00000019, 0x00000024,
    0x00000025, 0x00000027, 0x00000028, 0x00030003, 0x00000002, 0x000001c2, 0x000a0004, 0x475f4c47,
    0x4c474f4f, 0x70635f45, 0x74735f70, 0x5f656c79, 0x656e696c, 0x7269645f, 0x69746365, 0x00006576,
    0x00080004, 0x475f4c47, 0x4c474f4f, 0x6e695f45, 0x64756c63, 0x69645f65, 0x74636572, 0x00657669,
    0x00040005, 0x00000004, 0x6e69616d, 0x00000000, 0x00060005, 0x0000000b, 0x505f6c67, 0x65567265,
    0x78657472, 0x00000000, 0x00060006, 0x0000000b, 0x00000000, 0x505f6c67, 0x7469736f, 0x006e6f69,
    0x00070006, 0x0000000b, 0x00000001, 0x505f6c67, 0x746e696f, 0x657a6953, 0x00000000, 0x00070006,
    0x0000000b, 0x00000002, 0x435f6c67, 0x4470696c, 0x61747369, 0x0065636e, 0x00070006, 0x0000000b,
    0x00000003, 0x435f6c67, 0x446c6c75, 0x61747369, 0x0065636e, 0x00030005, 0x0000000d, 0x00000000,
    0x00040005, 0x00000011, 0x68737550, 0x00000000, 0x00040006, 0x00000011, 0x00000000, 0x0070766d,
    0x00060006, 0x00000011, 0x00000001, 0x6867696c, 0x72694474, 0x00000000, 0x00040005, 0x00000013,
    0x68737570, 0x00000000, 0x00050005, 0x00000019, 0x6f506e69, 0x69746973, 0x00006e6f, 0x00050005,
    0x00000024, 0x67617266, 0x6f6c6f43, 0x00000072, 0x00040005, 0x00000025, 0x6f436e69, 0x00726f6c,
    0x00050005, 0x00000027, 0x67617266, 0x6d726f4e, 0x00006c61, 0x00050005, 0x00000028, 0x6f4e6e69,
    0x6c616d72, 0x00000000, 0x00050048, 0x0000000b, 0x00000000, 0x0000000b, 0x00000000, 0x00050048,
    0x0000000b, 0x00000001, 0x0000000b, 0x00000001, 0x00050048, 0x0000000b, 0x00000002, 0x0000000b,
    0x00000003, 0x00050048, 0x0000000b, 0x00000003, 0x0000000b, 0x00000004, 0x00030047, 0x0000000b,
    0x00000002, 0x00040048, 0x00000011, 0x00000000, 0x00000005, 0x00050048, 0x00000011, 0x00000000,
    0x00000023, 0x00000000, 0x00050048, 0x00000011, 0x00000000, 0x00000007, 0x00000010, 0x00050048,
    0x00000011, 0x00000001, 0x00000023, 0x00000040, 0x00030047, 0x00000011, 0x00000002, 0x00040047,
    0x00000019, 0x0000001e, 0x00000000, 0x00040047, 0x00000024, 0x0000001e, 0x00000000, 0x00040047,
    0x00000025, 0x0000001e, 0x00000002, 0x00040047, 0x00000027, 0x0000001e, 0x00000001, 0x00040047,
    0x00000028, 0x0000001e, 0x00000001, 0x00020013, 0x00000002, 0x00030021, 0x00000003, 0x00000002,
    0x00030016, 0x00000006, 0x00000020, 0x00040017, 0x00000007, 0x00000006, 0x00000004, 0x00040015,
    0x00000008, 0x00000020, 0x00000000, 0x0004002b, 0x00000008, 0x00000009, 0x00000001, 0x0004001c,
    0x0000000a, 0x00000006, 0x00000009, 0x0006001e, 0x0000000b, 0x00000007, 0x00000006, 0x0000000a,
    0x0000000a, 0x00040020, 0x0000000c, 0x00000003, 0x0000000b, 0x0004003b, 0x0000000c, 0x0000000d,
    0x00000003, 0x00040015, 0x0000000e, 0x00000020, 0x00000001, 0x0004002b, 0x0000000e, 0x0000000f,
    0x00000000, 0x00040018, 0x00000010, 0x00000007, 0x00000004, 0x0004001e, 0x00000011, 0x00000010,
    0x00000007, 0x00040020, 0x00000012, 0x00000009, 0x00000011, 0x0004003b, 0x00000012, 0x00000013,
    0x00000009, 0x00040020, 0x00000014, 0x00000009, 0x00000010, 0x00040017, 0x00000017, 0x00000006,
    0x00000003, 0x00040020, 0x00000018, 0x00000001, 0x00000017, 0x0004003b, 0x00000018, 0x00000019,
    0x00000001, 0x0004002b, 0x00000006, 0x0000001b, 0x3f800000, 0x00040020, 0x00000021, 0x00000003,
    0x00000007, 0x00040020, 0x00000023, 0x00000003, 0x00000017, 0x0004003b, 0x00000023, 0x00000024,
    0x00000003, 0x0004003b, 0x00000018, 0x00000025, 0x00000001, 0x0004003b, 0x00000023, 0x00000027,
    0x00000003, 0x0004003b, 0x00000018, 0x00000028, 0x00000001, 0x00050036, 0x00000002, 0x00000004,
    0x00000000, 0x00000003, 0x000200f8, 0x00000005, 0x00050041, 0x00000014, 0x00000015, 0x00000013,
    0x0000000f, 0x0004003d, 0x00000010, 0x00000016, 0x00000015, 0x0004003d, 0x00000017, 0x0000001a,
    0x00000019, 0x00050051, 0x00000006, 0x0000001c, 0x0000001a, 0x00000000, 0x00050051, 0x00000006,
    0x0000001d, 0x0000001a, 0x00000001, 0x00050051, 0x00000006, 0x0000001e, 0x0000001a, 0x00000002,
    0x00070050, 0x00000007, 0x0000001f, 0x0000001c, 0x0000001d, 0x0000001e, 0x0000001b, 0x00050091,
    0x00000007, 0x00000020, 0x00000016, 0x0000001f, 0x00050041, 0x00000021, 0x00000022, 0x0000000d,
    0x0000000f, 0x0003003e, 0x00000022, 0x00000020, 0x0004003d, 0x00000017, 0x00000026, 0x00000025,
    0x0003003e, 0x00000024, 0x00000026, 0x0004003d, 0x00000017, 0x00000029, 0x00000028, 0x0003003e,
    0x00000027, 0x00000029, 0x000100fd, 0x00010038,
};
const lit_frag_spirv = [_]u32{
    0x07230203, 0x00010000, 0x000d000b, 0x00000030, 0x00000000, 0x00020011, 0x00000001, 0x0006000b,
    0x00000001, 0x4c534c47, 0x6474732e, 0x3035342e, 0x00000000, 0x0003000e, 0x00000000, 0x00000001,
    0x0008000f, 0x00000004, 0x00000004, 0x6e69616d, 0x00000000, 0x0000000b, 0x00000020, 0x00000029,
    0x00030010, 0x00000004, 0x00000007, 0x00030003, 0x00000002, 0x000001c2, 0x000a0004, 0x475f4c47,
    0x4c474f4f, 0x70635f45, 0x74735f70, 0x5f656c79, 0x656e696c, 0x7269645f, 0x69746365, 0x00006576,
    0x00080004, 0x475f4c47, 0x4c474f4f, 0x6e695f45, 0x64756c63, 0x69645f65, 0x74636572, 0x00657669,
    0x00040005, 0x00000004, 0x6e69616d, 0x00000000, 0x00030005, 0x00000009, 0x0000006e, 0x00050005,
    0x0000000b, 0x67617266, 0x6d726f4e, 0x00006c61, 0x00040005, 0x0000000f, 0x66666964, 0x00000000,
    0x00040005, 0x00000013, 0x68737550, 0x00000000, 0x00040006, 0x00000013, 0x00000000, 0x0070766d,
    0x00060006, 0x00000013, 0x00000001, 0x6867696c, 0x72694474, 0x00000000, 0x00040005, 0x00000015,
    0x68737570, 0x00000000, 0x00030005, 0x0000001f, 0x0074696c, 0x00050005, 0x00000020, 0x67617266,
    0x6f6c6f43, 0x00000072, 0x00050005, 0x00000029, 0x4374756f, 0x726f6c6f, 0x00000000, 0x00040047,
    0x0000000b, 0x0000001e, 0x00000001, 0x00040048, 0x00000013, 0x00000000, 0x00000005, 0x00050048,
    0x00000013, 0x00000000, 0x00000023, 0x00000000, 0x00050048, 0x00000013, 0x00000000, 0x00000007,
    0x00000010, 0x00050048, 0x00000013, 0x00000001, 0x00000023, 0x00000040, 0x00030047, 0x00000013,
    0x00000002, 0x00040047, 0x00000020, 0x0000001e, 0x00000000, 0x00040047, 0x00000029, 0x0000001e,
    0x00000000, 0x00020013, 0x00000002, 0x00030021, 0x00000003, 0x00000002, 0x00030016, 0x00000006,
    0x00000020, 0x00040017, 0x00000007, 0x00000006, 0x00000003, 0x00040020, 0x00000008, 0x00000007,
    0x00000007, 0x00040020, 0x0000000a, 0x00000001, 0x00000007, 0x0004003b, 0x0000000a, 0x0000000b,
    0x00000001, 0x00040020, 0x0000000e, 0x00000007, 0x00000006, 0x00040017, 0x00000011, 0x00000006,
    0x00000004, 0x00040018, 0x00000012, 0x00000011, 0x00000004, 0x0004001e, 0x00000013, 0x00000012,
    0x00000011, 0x00040020, 0x00000014, 0x00000009, 0x00000013, 0x0004003b, 0x00000014, 0x00000015,
    0x00000009, 0x00040015, 0x00000016, 0x00000020, 0x00000001, 0x0004002b, 0x00000016, 0x00000017,
    0x00000001, 0x00040020, 0x00000018, 0x00000009, 0x00000011, 0x0004002b, 0x00000006, 0x0000001d,
    0x00000000, 0x0004003b, 0x0000000a, 0x00000020, 0x00000001, 0x0004002b, 0x00000006, 0x00000022,
    0x3e99999a, 0x0004002b, 0x00000006, 0x00000023, 0x3f333333, 0x00040020, 0x00000028, 0x00000003,
    0x00000011, 0x0004003b, 0x00000028, 0x00000029, 0x00000003, 0x0004002b, 0x00000006, 0x0000002b,
    0x3f800000, 0x00050036, 0x00000002, 0x00000004, 0x00000000, 0x00000003, 0x000200f8, 0x00000005,
    0x0004003b, 0x00000008, 0x00000009, 0x00000007, 0x0004003b, 0x0000000e, 0x0000000f, 0x00000007,
    0x0004003b, 0x00000008, 0x0000001f, 0x00000007, 0x0004003d, 0x00000007, 0x0000000c, 0x0000000b,
    0x0006000c, 0x00000007, 0x0000000d, 0x00000001, 0x00000045, 0x0000000c, 0x0003003e, 0x00000009,
    0x0000000d, 0x0004003d, 0x00000007, 0x00000010, 0x00000009, 0x00050041, 0x00000018, 0x00000019,
    0x00000015, 0x00000017, 0x0004003d, 0x00000011, 0x0000001a, 0x00000019, 0x0008004f, 0x00000007,
    0x0000001b, 0x0000001a, 0x0000001a, 0x00000000, 0x00000001, 0x00000002, 0x00050094, 0x00000006,
    0x0000001c, 0x00000010, 0x0000001b, 0x0007000c, 0x00000006, 0x0000001e, 0x00000001, 0x00000028,
    0x0000001c, 0x0000001d, 0x0003003e, 0x0000000f, 0x0000001e, 0x0004003d, 0x00000007, 0x00000021,
    0x00000020, 0x0004003d, 0x00000006, 0x00000024, 0x0000000f, 0x00050085, 0x00000006, 0x00000025,
    0x00000023, 0x00000024, 0x00050081, 0x00000006, 0x00000026, 0x00000022, 0x00000025, 0x0005008e,
    0x00000007, 0x00000027, 0x00000021, 0x00000026, 0x0003003e, 0x0000001f, 0x00000027, 0x0004003d,
    0x00000007, 0x0000002a, 0x0000001f, 0x00050051, 0x00000006, 0x0000002c, 0x0000002a, 0x00000000,
    0x00050051, 0x00000006, 0x0000002d, 0x0000002a, 0x00000001, 0x00050051, 0x00000006, 0x0000002e,
    0x0000002a, 0x00000002, 0x00070050, 0x00000011, 0x0000002f, 0x0000002c, 0x0000002d, 0x0000002e,
    0x0000002b, 0x0003003e, 0x00000029, 0x0000002f, 0x000100fd, 0x00010038,
};

// --- Constants ---
const RT_W: u32 = 320;
const RT_H: u32 = 240;
// B8G8R8A8 puts the bytes in the same order our window framebuffer expects
// (low byte = B, then G, then R, then A). Reading a pixel as u32 gives
// 0xAARRGGBB directly — no R↔B swizzle needed when copying to win_fb.
// Lavapipe advertises this format; vulkaninfo SurfaceFormat[1] confirms.
const VK_FORMAT_B8G8R8A8_UNORM: u32 = 44;
const VK_FORMAT_D32_SFLOAT: u32 = 126;

// Resource IDs.
// Ping-pong: render target, memory, view, framebuffer, cmd buf, and fence
// each have two slots so frame N renders into slot N%2 while we read frame
// N-1's output from the opposite slot. By the time we read an opposite
// slot, the host has had a full frame to actually finish writing it —
// works around the Lavapipe/Venus fence-signals-before-completion race
// without needing a retry loop or cache-coherency tricks.
const INSTANCE: u64 = 100;
const PHYS_DEV: u64 = 101;
const DEVICE: u64 = 102;
const QUEUE: u64 = 103;
const RENDER_IMAGE = [2]u64{ 200, 240 };
const RENDER_MEM = [2]u64{ 202, 242 };
const RENDER_VIEW = [2]u64{ 203, 243 };
const DEPTH_IMAGE: u64 = 210;
const DEPTH_MEM: u64 = 212;
const DEPTH_VIEW: u64 = 213;
const VTX_BUFFER: u64 = 220;
const VTX_MEM: u64 = 222;
const RENDER_PASS: u64 = 300;
const FRAMEBUFFER = [2]u64{ 301, 311 };
const PIPELINE_LAYOUT: u64 = 302;
const VERT_MODULE: u64 = 303;
const FRAG_MODULE: u64 = 304;
const PIPELINE: u64 = 305;
const STAGING_BUFFER: u64 = 230;
const STAGING_MEM: u64 = 232;
const CMD_POOL: u64 = 400;
const CMD_BUF = [2]u64{ 401, 411 };
const RENDER_FENCE = [2]u64{ 500, 510 };

var cs: venus.CmdStream = .{};
var reply_buf: [*]volatile u8 = undefined;

/// Inline rdtsc — read the CPU's timestamp counter. Unprivileged on x86_64,
/// usable from userspace. Used for sub-millisecond phase timing in the
/// render loop. NOT serializing — adjacent phases may bleed into each other
/// by ~10s of cycles, but for ms-scale phases this is in the noise.
inline fn rdtsc() u64 {
    var lo: u32 = undefined;
    var hi: u32 = undefined;
    asm volatile ("rdtsc"
        : [lo] "={eax}" (lo),
          [hi] "={edx}" (hi),
    );
    return @as(u64, lo) | (@as(u64, hi) << 32);
}


// --- Cube geometry: 36 vertices (6 faces x 2 triangles x 3 verts) ---
// Each vertex: pos(vec3) + normal(vec3) + color(vec3) = 9 floats = 36 bytes
const Vertex = extern struct { x: f32, y: f32, z: f32, nx: f32, ny: f32, nz: f32, r: f32, g: f32, b: f32 };
fn V(x: f32, y: f32, z: f32, nx: f32, ny: f32, nz: f32, r: f32, g: f32, b: f32) Vertex {
    return .{ .x = x, .y = y, .z = z, .nx = nx, .ny = ny, .nz = nz, .r = r, .g = g, .b = b };
}

const cube_vertices = [36]Vertex{
    // Front face (red) - z = +0.5, normal = (0,0,1)
    V(-0.5, -0.5, 0.5, 0, 0, 1, 1, 0, 0), V(0.5, -0.5, 0.5, 0, 0, 1, 1, 0, 0), V(0.5, 0.5, 0.5, 0, 0, 1, 1, 0, 0),
    V(-0.5, -0.5, 0.5, 0, 0, 1, 1, 0, 0), V(0.5, 0.5, 0.5, 0, 0, 1, 1, 0, 0),  V(-0.5, 0.5, 0.5, 0, 0, 1, 1, 0, 0),
    // Back face (green) - z = -0.5, normal = (0,0,-1)
    V(0.5, -0.5, -0.5, 0, 0, -1, 0, 1, 0), V(-0.5, -0.5, -0.5, 0, 0, -1, 0, 1, 0), V(-0.5, 0.5, -0.5, 0, 0, -1, 0, 1, 0),
    V(0.5, -0.5, -0.5, 0, 0, -1, 0, 1, 0), V(-0.5, 0.5, -0.5, 0, 0, -1, 0, 1, 0),  V(0.5, 0.5, -0.5, 0, 0, -1, 0, 1, 0),
    // Right face (blue) - x = +0.5, normal = (1,0,0)
    V(0.5, -0.5, 0.5, 1, 0, 0, 0, 0, 1), V(0.5, -0.5, -0.5, 1, 0, 0, 0, 0, 1), V(0.5, 0.5, -0.5, 1, 0, 0, 0, 0, 1),
    V(0.5, -0.5, 0.5, 1, 0, 0, 0, 0, 1), V(0.5, 0.5, -0.5, 1, 0, 0, 0, 0, 1),  V(0.5, 0.5, 0.5, 1, 0, 0, 0, 0, 1),
    // Left face (yellow) - x = -0.5, normal = (-1,0,0)
    V(-0.5, -0.5, -0.5, -1, 0, 0, 1, 1, 0), V(-0.5, -0.5, 0.5, -1, 0, 0, 1, 1, 0), V(-0.5, 0.5, 0.5, -1, 0, 0, 1, 1, 0),
    V(-0.5, -0.5, -0.5, -1, 0, 0, 1, 1, 0), V(-0.5, 0.5, 0.5, -1, 0, 0, 1, 1, 0),  V(-0.5, 0.5, -0.5, -1, 0, 0, 1, 1, 0),
    // Top face (cyan) - y = +0.5, normal = (0,1,0)
    V(-0.5, 0.5, 0.5, 0, 1, 0, 0, 1, 1), V(0.5, 0.5, 0.5, 0, 1, 0, 0, 1, 1), V(0.5, 0.5, -0.5, 0, 1, 0, 0, 1, 1),
    V(-0.5, 0.5, 0.5, 0, 1, 0, 0, 1, 1), V(0.5, 0.5, -0.5, 0, 1, 0, 0, 1, 1), V(-0.5, 0.5, -0.5, 0, 1, 0, 0, 1, 1),
    // Bottom face (magenta) - y = -0.5, normal = (0,-1,0)
    V(-0.5, -0.5, -0.5, 0, -1, 0, 1, 0, 1), V(0.5, -0.5, -0.5, 0, -1, 0, 1, 0, 1), V(0.5, -0.5, 0.5, 0, -1, 0, 1, 0, 1),
    V(-0.5, -0.5, -0.5, 0, -1, 0, 1, 0, 1), V(0.5, -0.5, 0.5, 0, -1, 0, 1, 0, 1),  V(-0.5, -0.5, 0.5, 0, -1, 0, 1, 0, 1),
};
const VTX_SIZE: u32 = 36 * 36; // 1296 bytes

// --- Matrix math ---
const Mat4 = struct {
    d: [16]f32,

    fn identity() Mat4 {
        return .{ .d = .{
            1, 0, 0, 0,
            0, 1, 0, 0,
            0, 0, 1, 0,
            0, 0, 0, 1,
        } };
    }

    fn multiply(a: Mat4, b: Mat4) Mat4 {
        var r: [16]f32 = undefined;
        for (0..4) |col| {
            for (0..4) |row| {
                var sum: f32 = 0;
                for (0..4) |k| {
                    sum += a.d[k * 4 + row] * b.d[col * 4 + k];
                }
                r[col * 4 + row] = sum;
            }
        }
        return .{ .d = r };
    }

    fn perspective(fov_deg: f32, aspect: f32, near: f32, far: f32) Mat4 {
        const fov_rad = fov_deg * (3.14159265 / 180.0);
        const f = 1.0 / @tan(fov_rad / 2.0);
        const nf = 1.0 / (near - far);
        return .{ .d = .{
            f / aspect, 0, 0,                  0,
            0,          f, 0,                  0,
            0,          0, (far + near) * nf,  -1,
            0,          0, 2 * far * near * nf, 0,
        } };
    }

    fn translate(x: f32, y: f32, z: f32) Mat4 {
        return .{ .d = .{
            1, 0, 0, 0,
            0, 1, 0, 0,
            0, 0, 1, 0,
            x, y, z, 1,
        } };
    }

    fn rotateX(angle: f32) Mat4 {
        const c = @cos(angle);
        const s = @sin(angle);
        return .{ .d = .{
            1, 0,  0, 0,
            0, c,  s, 0,
            0, -s, c, 0,
            0, 0,  0, 1,
        } };
    }

    fn rotateY(angle: f32) Mat4 {
        const c = @cos(angle);
        const s = @sin(angle);
        return .{ .d = .{
            c, 0, -s, 0,
            0, 1, 0,  0,
            s, 0, c,  0,
            0, 0, 0,  1,
        } };
    }
};

var scan_info: [3]u32 = undefined;

// --- Main ---
export fn _start() callconv(.c) noreturn {
    libc.print("=== Vulkan Cube ===\n");

    // Find Venus capset
    var found_venus = false;
    for (0..16) |i| {
        if (!libc.gpuGetCapsetInfo(@intCast(i), &scan_info)) break;
        if (scan_info[0] == 0 and scan_info[2] == 0) break;
        if (scan_info[0] == 4) found_venus = true;
    }
    if (!found_venus) { libc.print("No Venus!\n"); halt(); }

    _ = libc.gpuCtxCreate(4) orelse { libc.print("Ctx fail!\n"); halt(); };

    const reply = venus.setupReplyStream(4096) orelse {
        libc.print("Reply fail!\n"); cleanup(); halt();
    };
    reply_buf = reply.buf;

    // Create instance
    if (!vkCmd(struct {
        fn f(s: *venus.CmdStream) void {
            s.cmdHeader(venus.CMD_vkCreateInstance, venus.CMD_FLAG_GENERATE_REPLY);
            s.writePresent();
            s.writeU32(venus.VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO);
            s.writeNull(); s.writeU32(0);
            s.writePresent();
            s.writeU32(venus.VK_STRUCTURE_TYPE_APPLICATION_INFO);
            s.writeNull();
            s.writeString("VkCube"); s.writeU32(1);
            s.writeString("ZigOS"); s.writeU32(1);
            s.writeU32((1 << 22) | (2 << 12));
            s.writeU32(0); s.writeU64(0); s.writeU32(0); s.writeU64(0);
            s.writeNull(); s.writePresent(); s.writeU64(INSTANCE);
        }
    }.f, "vkCreateInstance")) { cleanup(); halt(); }

    if (!vkCmd(struct {
        fn f(s: *venus.CmdStream) void {
            s.cmdHeader(venus.CMD_vkEnumeratePhysicalDevices, venus.CMD_FLAG_GENERATE_REPLY);
            s.writeU64(INSTANCE); s.writePresent(); s.writeU32(1);
            s.writeU64(1); s.writeU64(PHYS_DEV);
        }
    }.f, "vkEnumPhysDev")) { cleanup(); halt(); }

    if (!vkEnc(venus.encodeCreateDeviceExportable, .{ PHYS_DEV, 0, DEVICE }, "vkCreateDevice")) { cleanup(); halt(); }
    fire(venus.encodeGetDeviceQueue, .{ DEVICE, 0, 0, QUEUE });

    // --- Vertex buffer ---
    // Memory + buffer are both Exportable (DMA_BUF) because Lavapipe-via-
    // Venus tags ALL memory with DMA_BUF handle type once the device was
    // created via encodeCreateDeviceExportable — using plain
    // encodeAllocateMemory still triggers VUID-02726 on bind. Match what
    // Lavapipe thinks: Exportable on both sides, validation stays clean.
    //
    // Vertex data is uploaded via vkCmdUpdateBuffer in the one-shot setup
    // cmd buf below — the bytes travel inline in the command stream itself,
    // so no working guest↔host blob memory sharing is required (which is
    // unreliable: validate.log shows udmabuf_fd=0).
    if (!vkEnc(venus.encodeAllocateMemoryExportable, .{ DEVICE, @as(u64, VTX_SIZE), 0, VTX_MEM }, "vkAllocVtxMem")) { cleanup(); halt(); }
    // VERTEX_BUFFER (0x80) | TRANSFER_DST (0x02) — TRANSFER_DST is required
    // for vkCmdUpdateBuffer.
    if (!vkEnc(venus.encodeCreateBufferExportable, .{ DEVICE, @as(u64, VTX_SIZE), @as(u32, 0x82), VTX_BUFFER }, "vkCreateBuffer")) { cleanup(); halt(); }
    if (!vkEnc(venus.encodeBindBufferMemory, .{ DEVICE, VTX_BUFFER, VTX_MEM, @as(u64, 0) }, "vkBindBufMem")) { cleanup(); halt(); }

    // --- Render image (alloc-then-blob — the ordering virgl requires) ---
    // Tried "blob first, vkAllocateMemory with import-resource pNext"
    // (Mesa's GUEST_VRAM pattern). Failed: virgl's HOST3D blob create
    // calls `vkr_context_get_object(blob_id)` and rejects when the
    // VkDeviceMemory doesn't exist server-side yet. The Mesa pattern
    // works because Linux kernel virtgpu translates GUEST_VRAM mode
    // into something that pre-creates the memory placeholder — we
    // can't replicate that from custom-OS land.
    //
    // So back to the original order: allocate VkDeviceMemory first
    // (with VkExportMemoryAllocateInfo declaring DMA_BUF handle type),
    // then create the HOST3D blob with blob_id=RENDER_MEM. virgl finds
    // the existing VkDeviceMemory, exports its DMA_BUF, creates a
    // resource around the fd. gpuMapBlob mmaps that resource into user
    // space via the SHM BAR — pixel_ptr aliases Lavapipe's allocation.
    //
    // After each render we call gpuResourceFlush to push the latest
    // contents through the host's transfer machinery (per virtio-gpu
    // protocol, RESOURCE_FLUSH for the resource). Memory note records
    // that clear-color briefly DID arrive at pixel_ptr earlier — the
    // infrastructure works, we just need to ensure we keep using it.
    const px_size: u32 = RT_W * RT_H * 4;

    // memory_type_index=0 is correct: Lavapipe advertises a single type with
    // flags 0xf (DEVICE_LOCAL | HOST_VISIBLE | HOST_COHERENT | HOST_CACHED)
    // — confirmed via host vulkaninfo. Earlier we tried querying memory
    // properties through Venus to "pick the right type" but the reply for
    // vkGetPhysicalDeviceMemoryProperties is silently dropped (drinks the
    // ring without writing anything readable from offset 0), and there's
    // only one type anyway. Hardcoding 0 saves a round-trip and is correct.
    // Two color render targets, one per ping-pong slot. Each gets its own
    // VkImage + VkDeviceMemory + HOST3D blob + guest mmap. Depth is shared
    // (Vulkan serializes render-pass loads/stores on a single queue, so
    // the two images can safely write the depth buffer in alternation).
    var pixel_ptrs: [2][*]volatile u8 = undefined;
    for (0..2) |i| {
        if (!vkEnc(venus.encodeCreateImageExportable, .{ DEVICE, RT_W, RT_H, VK_FORMAT_B8G8R8A8_UNORM, @as(u32, 0x10), RENDER_IMAGE[i] }, "vkCreateImg")) { cleanup(); halt(); }
        if (!vkEnc(venus.encodeAllocateMemoryExportable, .{ DEVICE, @as(u64, px_size), 0, RENDER_MEM[i] }, "vkAllocRndMem")) { cleanup(); halt(); }
        if (!vkEnc(venus.encodeBindImageMemory, .{ DEVICE, RENDER_IMAGE[i], RENDER_MEM[i], @as(u64, 0) }, "vkBindImgMem")) { cleanup(); halt(); }

        const blob = libc.gpuCreateBlobWithId(venus.BLOB_MEM_HOST3D, px_size, @intCast(RENDER_MEM[i])) orelse {
            libc.print("Blob create fail!\n");
            cleanup(); halt();
        };
        pixel_ptrs[i] = libc.gpuMapBlob(blob, px_size) orelse {
            libc.print("Blob map fail!\n");
            cleanup(); halt();
        };
    }

    // --- Depth image ---
    // Even though we don't blob-back the depth buffer, Lavapipe (under
    // encodeCreateDeviceExportable) reports its memory with DMA_BUF handle
    // type at bind time, so we must declare it on the image too — otherwise
    // VUID-02728 fires and cascades into CS error.
    if (!vkEnc(venus.encodeCreateImageExportable, .{ DEVICE, RT_W, RT_H, VK_FORMAT_D32_SFLOAT, @as(u32, 0x20), DEPTH_IMAGE }, "vkCreateDepth")) { cleanup(); halt(); }
    if (!vkEnc(venus.encodeAllocateMemoryExportable, .{ DEVICE, @as(u64, RT_W * RT_H * 4), 0, DEPTH_MEM }, "vkAllocDepth")) { cleanup(); halt(); }
    if (!vkEnc(venus.encodeBindImageMemory, .{ DEVICE, DEPTH_IMAGE, DEPTH_MEM, @as(u64, 0) }, "vkBindDepth")) { cleanup(); halt(); }

    // --- Views ---
    for (0..2) |i| {
        if (!vkEnc(venus.encodeCreateImageViewEx, .{ DEVICE, RENDER_IMAGE[i], VK_FORMAT_B8G8R8A8_UNORM, @as(u32, 1), RENDER_VIEW[i] }, "vkColorView")) { cleanup(); halt(); }
    }
    if (!vkEnc(venus.encodeCreateImageViewEx, .{ DEVICE, DEPTH_IMAGE, VK_FORMAT_D32_SFLOAT, @as(u32, 2), DEPTH_VIEW }, "vkDepthView")) { cleanup(); halt(); }

    // --- Render pass + framebuffers (one per slot, sharing depth) ---
    if (!vkEnc(venus.encodeCreateRenderPassDepth, .{ DEVICE, VK_FORMAT_B8G8R8A8_UNORM, VK_FORMAT_D32_SFLOAT, RENDER_PASS }, "vkRenderPass")) { cleanup(); halt(); }
    for (0..2) |i| {
        if (!vkEnc(venus.encodeCreateFramebuffer2, .{ DEVICE, RENDER_PASS, RENDER_VIEW[i], DEPTH_VIEW, RT_W, RT_H, FRAMEBUFFER[i] }, "vkFramebuffer")) { cleanup(); halt(); }
    }

    // --- Shaders + pipeline ---
    if (!vkEnc(venus.encodeCreateShaderModule, .{ DEVICE, &lit_vert_spirv, VERT_MODULE }, "vkShader(v)")) { cleanup(); halt(); }
    if (!vkEnc(venus.encodeCreateShaderModule, .{ DEVICE, &lit_frag_spirv, FRAG_MODULE }, "vkShader(f)")) { cleanup(); halt(); }
    if (!vkEnc(venus.encodeCreatePipelineLayoutPush, .{ DEVICE, @as(u32, 0x01 | 0x10), @as(u32, 80), PIPELINE_LAYOUT }, "vkPipeLayout")) { cleanup(); halt(); }
    if (!vkEnc(venus.encodeCreateGraphicsPipelinesCube, .{ DEVICE, PIPELINE_LAYOUT, RENDER_PASS, VERT_MODULE, FRAG_MODULE, RT_W, RT_H, PIPELINE }, "vkPipeline")) { cleanup(); halt(); }

    // --- Command pool + per-slot command buffers ---
    if (!vkEnc(venus.encodeCreateCommandPool, .{ DEVICE, 0, CMD_POOL }, "vkCmdPool")) { cleanup(); halt(); }
    for (0..2) |i| {
        if (!vkEnc(venus.encodeAllocateCommandBuffers, .{ DEVICE, CMD_POOL, CMD_BUF[i] }, "vkCmdBuf")) { cleanup(); halt(); }
    }

    // --- One-shot vertex data upload via vkCmdUpdateBuffer ---
    // 1296 bytes of cube_vertices travel inline in the command stream,
    // bypassing the broken blob-memory sharing path. Lavapipe receives
    // the data inside the cmd buf and writes it into VTX_BUFFER's
    // memory through its own transfer machinery.
    // Create the render fence once. Used both for the vertex-upload submit
    // below and per-frame in the render loop. Without fence-based sync we
    // can't wait on submissions — vk{Device,Queue}WaitIdle are stubbed
    // host-side (vkr_dispatch_*WaitIdle just calls vkr_context_set_fatal).
    for (0..2) |i| {
        if (!vkEnc(venus.encodeCreateFence, .{ DEVICE, @as(u32, 0), RENDER_FENCE[i] }, "vkCreateFence")) { cleanup(); halt(); }
    }

    {
        cs.reset();
        venus.encodeBeginCommandBuffer(&cs, CMD_BUF[0]);
        const vtx_bytes: *const [VTX_SIZE]u8 = @ptrCast(&cube_vertices);
        venus.encodeCmdUpdateBuffer(&cs, CMD_BUF[0], VTX_BUFFER, 0, vtx_bytes);
        venus.encodeEndCommandBuffer(&cs, CMD_BUF[0]);
        _ = cs.submit();

        cs.reset();
        venus.encodeQueueSubmitFence(&cs, QUEUE, CMD_BUF[0], RENDER_FENCE[0]);
        _ = cs.submit();

        // Wait for the upload to complete before continuing. 1 second is
        // plenty for Lavapipe (CPU rendering, microseconds for a 36-vertex
        // copy). UINT64_MAX would also work but a finite timeout exposes
        // hangs immediately.
        if (!vkEnc(venus.encodeWaitForFences, .{ DEVICE, RENDER_FENCE[0], @as(u64, 1_000_000_000) }, "vkWaitFence (vtx)")) { cleanup(); halt(); }
        if (!vkEnc(venus.encodeResetFences, .{ DEVICE, RENDER_FENCE[0] }, "vkResetFence (vtx)")) {
            // Reset returns VK_SUCCESS=0 normally; treat any non-success as fatal.
            cleanup(); halt();
        }
    }
    libc.print("Vertex data uploaded (vkCmdUpdateBuffer)\n");

    libc.print("Setup complete!\n");

    // --- Create a regular GUI window for the cube. Render path:
    //   Vulkan → RENDER_IMAGE
    //   gpuTransferFromHost3D → blob (pixel_ptr above)
    //   swizzle/memcpy           → window FB
    //   libc.present             → desktop composites
    // This sidesteps the scanout-blob path that didn't work on this
    // Lavapipe-via-Venus stack (virgl never honored the swap; you got
    // a frozen desktop). Cube is now just another window — draggable,
    // closable, doesn't take over the screen.
    const _win = libc.createWindow(RT_W, RT_H) orelse {
        libc.print("createWindow FAILED\n");
        cleanup(); halt();
    };
    const win_fb = _win.fb;
    libc.print("Window created\n");

    // --- Render loop ---
    //
    // Sequential (NOT pipelined). An earlier attempt at pipelining
    // (record N+1 while host renders N) tripped Lavapipe validation:
    // VUID-vkQueueSubmit-fence-00064 ("VkFence is already in use by another
    // submission") and VUID-vkQueueSubmit-pCommandBuffers-00071 ("VkCommandBuffer
    // is already in use"). Even with vkWaitForFences gating the next submit,
    // Lavapipe seemed to consider the cmd buf "in use" past fence signal —
    // possibly because Lavapipe's vkQueueSubmit returns before its worker
    // thread has fully released the cmd buf, or because vkr's per-queue mutex
    // serializes submits in a way that races with our protocol-level wait.
    // Either way, host crashed with `std::future_error: Promise already
    // satisfied` after ~7 frames and the cube froze. Revert: keep the loop
    // strictly serial. Lavapipe at 320×240 + Venus round-trips runs ~17 fps
    // on this stack — bottleneck isn't us.
    //
    // No swizzle: render target is B8G8R8A8 which already matches the window
    // FB's 0xAARRGGBB layout when read as u32 on x86 LE. Plain memcpy.
    const start_time = libc.uptime();
    const pixel_count: usize = RT_W * RT_H;

    // --- TSC calibration for frame-breakdown timing ---
    // We don't know the exact host CPU frequency, but the kernel tick is a
    // reliable 10 ms reference. Sleep one heartbeat-window's worth (100 ms)
    // and divide cycles by elapsed wall time to get cycles_per_us. Off by a
    // few percent is fine — we just want orders-of-magnitude visibility into
    // where the frame is going.
    const calib_t0 = libc.uptime();
    const calib_tsc0 = rdtsc();
    libc.sleep(100);
    const calib_tsc1 = rdtsc();
    const calib_t1 = libc.uptime();
    const calib_ticks = calib_t1 - calib_t0;
    const calib_us = if (calib_ticks > 0) @as(u64, calib_ticks) * 10 * 1000 else 100_000;
    const cycles_per_us = (calib_tsc1 - calib_tsc0) / calib_us;
    libc.klogFmt("[cube perf] calibrated: {d} cycles/us ({d} cycles in {d} us)\n", .{
        cycles_per_us, calib_tsc1 - calib_tsc0, calib_us,
    });

    // Per-phase cycle accumulators. Reset every heartbeat (300 frames).
    // After batching all 4 venus round-trips into one cs.submit, the
    // breakdown is: enc (encoding all venus commands into cs.buf) + batch
    // (the single cs.submit that runs the whole frame on the host) + the
    // user-space tail (mcpy/present/poll/sleep).
    var t_enc: u64 = 0;
    var t_batch: u64 = 0;
    var t_mcpy: u64 = 0;
    var t_present: u64 = 0;
    var t_poll: u64 = 0;
    var t_sleep: u64 = 0;
    var t_total: u64 = 0;
    var t_count: u32 = 0;

    // Diagnostic counters for the rare-glitch hunt. Resets every heartbeat
    // so the count tells us "out of the last 300 frames, how many were
    // weird" rather than a runaway total.
    var n_wait_nonzero: u32 = 0; // vkWaitForFences VkResult != VK_SUCCESS
    var last_wait_result: i32 = 0; // most recent non-zero result, for klog
    var n_black_px: u32 = 0; // displayed pixel_ptr[0] unexpectedly 0 (render likely failed)

    var frame_no: u32 = 0;
    while (true) : (frame_no += 1) {
        const elapsed = libc.uptime() -% start_time;
        const angle: f32 = @as(f32, @floatFromInt(elapsed)) * 0.005;

        const model = Mat4.rotateY(angle).multiply(Mat4.rotateX(angle * 0.7));
        const view = Mat4.translate(0, 0, -3);
        const proj = Mat4.perspective(60.0, @as(f32, RT_W) / @as(f32, RT_H), 0.1, 100.0);
        const mvp = proj.multiply(view.multiply(model));

        var push_data: [80]u8 = undefined;
        const mvp_src: *const [64]u8 = @ptrCast(&mvp.d);
        @memcpy(push_data[0..64], mvp_src);
        const light_dir = [4]f32{ 0.57, 0.57, 0.57, 0.0 };
        const light_src: *const [16]u8 = @ptrCast(&light_dir);
        @memcpy(push_data[64..80], light_src);

        // Ping-pong: this frame writes slot target_idx and (if past the
        // first frame) reads slot read_idx — written 1+ frames ago, so
        // the host has had a full frame of additional time to actually
        // finish that buffer regardless of fence-signal accuracy.
        const target_idx: usize = frame_no % 2;

        const ts_iter = rdtsc();

        // ── Batched protocol stream (one virtio-gpu SUBMIT_3D round-trip) ──
        //   1. Begin/Cmds/End — record the cmd buf for slot target_idx
        //   2. ResetFences    — fence[target] to unsignaled
        //   3. QueueSubmit    — cmd buf[target] goes pending, fence[target]
        //                       associates
        //   4. Seek(0)        — reset reply ring head
        //   5. WaitForFences  — block on fence[target]. Empirically lies
        //                       about completion (signals before all writes
        //                       commit), but we don't read this slot —
        //                       we read the OPPOSITE slot below.
        clearReply();
        cs.reset();
        venus.encodeBeginCommandBuffer(&cs, CMD_BUF[target_idx]);
        venus.encodeCmdBeginRenderPassDepth(&cs, CMD_BUF[target_idx], RENDER_PASS, FRAMEBUFFER[target_idx], RT_W, RT_H);
        venus.encodeCmdBindPipeline(&cs, CMD_BUF[target_idx], PIPELINE);
        venus.encodeCmdBindVertexBuffers(&cs, CMD_BUF[target_idx], VTX_BUFFER);
        venus.encodeCmdPushConstants(&cs, CMD_BUF[target_idx], PIPELINE_LAYOUT, 0x01 | 0x10, &push_data);
        venus.encodeCmdDraw(&cs, CMD_BUF[target_idx], 36, 1);
        venus.encodeCmdEndRenderPass(&cs, CMD_BUF[target_idx]);
        // Barrier COLOR_ATTACHMENT_OPTIMAL(2) → GENERAL(1) for host read.
        venus.encodeCmdPipelineBarrier(&cs, CMD_BUF[target_idx], RENDER_IMAGE[target_idx],
            2, 1,
            0x400, 0x4000, // srcStage=COLOR_ATTACH_OUTPUT, dstStage=HOST
            0x100, 0x2000, // srcAccess=COLOR_ATTACH_WRITE, dstAccess=HOST_READ
        );
        venus.encodeEndCommandBuffer(&cs, CMD_BUF[target_idx]);
        venus.encodeResetFences(&cs, DEVICE, RENDER_FENCE[target_idx]);
        venus.encodeQueueSubmitFence(&cs, QUEUE, CMD_BUF[target_idx], RENDER_FENCE[target_idx]);
        venus.encodeSeekReplyCommandStream(&cs, 0);
        venus.encodeWaitForFences(&cs, DEVICE, RENDER_FENCE[target_idx], 1_000_000_000);
        const ts_enc = rdtsc();
        _ = cs.submit();
        const ts_batch = rdtsc();

        const wait_result = venus.readReplyResult(reply_buf);
        if (wait_result != 0) {
            n_wait_nonzero += 1;
            last_wait_result = wait_result;
        }

        // Read from the opposite slot — last written one full frame ago.
        // Frame 0 has nothing to display since the opposite slot has never
        // been rendered to, so we just skip the present.
        var ts_mcpy: u64 = ts_batch;
        var ts_present: u64 = ts_batch;
        if (frame_no >= 1) {
            const read_idx: usize = (target_idx + 1) % 2;
            const pixel_u32_read: [*]const u32 = @ptrCast(@alignCast(@volatileCast(pixel_ptrs[read_idx])));
            if (pixel_u32_read[0] == 0) n_black_px += 1;
            @memcpy(win_fb[0..pixel_count], pixel_u32_read[0..pixel_count]);
            ts_mcpy = rdtsc();
            libc.present();
            ts_present = rdtsc();
        }

        while (libc.pollEvent()) |ev| {
            if (ev.kindOf() == .close_request) {
                cleanup();
                libc.exit();
            }
        }
        const ts_poll = rdtsc();

        // sleep(8) → kernel rounds up to 1 tick (10 ms) + scheduler latency
        // = ~20 ms wall (down from ~30 with sleep(16) which rounded to 2
        // ticks). Cube paces at ~40 fps without burning CPU. After batching
        // dropped CTRL queue traffic by 70%, this is comfortably below the
        // saturation threshold that previously stalled the desktop.
        libc.sleep(8);
        const ts_sleep = rdtsc();

        // Accumulate per-phase deltas.
        t_enc += ts_enc -% ts_iter;
        t_batch += ts_batch -% ts_enc;
        t_mcpy += ts_mcpy -% ts_batch;
        t_present += ts_present -% ts_mcpy;
        t_poll += ts_poll -% ts_present;
        t_sleep += ts_sleep -% ts_poll;
        t_total += ts_sleep -% ts_iter;
        t_count += 1;

        if (frame_no % 300 == 0 and frame_no > 0) {
            // Average microseconds per phase across the last 300 frames.
            // Subtract iter/sleep first to focus on the work; sleep(16)
            // dominates total otherwise. fps from total_us per frame.
            const us = struct {
                fn n(cycles: u64, count: u32, cyc_per_us: u64) u64 {
                    if (count == 0 or cyc_per_us == 0) return 0;
                    return (cycles / @as(u64, count)) / cyc_per_us;
                }
            }.n;
            const u_total = us(t_total, t_count, cycles_per_us);
            const fps = if (u_total > 0) 1_000_000 / u_total else 0;
            libc.klogFmt(
                "[cube perf {d}f] avg us/frame: enc={d} batch={d} mcpy={d} pres={d} poll={d} slp={d} tot={d} (~{d} fps) | px0=0x{X:0>8} wait_err={d}/{d} (last={d}) black_px={d}\n",
                .{
                    t_count,
                    us(t_enc, t_count, cycles_per_us),
                    us(t_batch, t_count, cycles_per_us),
                    us(t_mcpy, t_count, cycles_per_us),
                    us(t_present, t_count, cycles_per_us),
                    us(t_poll, t_count, cycles_per_us),
                    us(t_sleep, t_count, cycles_per_us),
                    u_total,
                    fps,
                    win_fb[0],
                    n_wait_nonzero,
                    t_count,
                    last_wait_result,
                    n_black_px,
                },
            );
            t_enc = 0;
            t_batch = 0;
            t_mcpy = 0;
            t_present = 0;
            t_poll = 0;
            t_sleep = 0;
            t_total = 0;
            t_count = 0;
            n_wait_nonzero = 0;
            last_wait_result = 0;
            n_black_px = 0;
        }
    }
}

// --- Helpers (same as vulkan_triangle) ---
fn clearReply() void {
    for (0..64) |i| reply_buf[i] = 0;
}
fn patchReplyFlag() void {
    const p: *align(1) u32 = @ptrCast(cs.buf[4..8]);
    p.* = venus.CMD_FLAG_GENERATE_REPLY;
}
fn vkCmd(encodeFn: *const fn (*venus.CmdStream) void, name: []const u8) bool {
    clearReply();
    cs.reset();
    encodeFn(&cs);
    return checkResult(name);
}
fn vkEnc(comptime encodeFn: anytype, args: anytype, name: []const u8) bool {
    clearReply();
    cs.reset();
    @call(.auto, encodeFn, .{&cs} ++ args);
    patchReplyFlag();
    return checkResult(name);
}
fn fire(comptime encodeFn: anytype, args: anytype) void {
    cs.reset();
    @call(.auto, encodeFn, .{&cs} ++ args);
    _ = cs.submit();
}
fn checkResult(name: []const u8) bool {
    if (!cs.submit()) {
        libc.print("  ");
        libc.print(name);
        libc.print(" SUBMIT FAIL\n");
        return false;
    }
    const result = venus.readReplyResult(reply_buf);
    libc.print("  ");
    libc.print(name);
    if (result == 0) {
        libc.print(" OK\n");
        return true;
    }
    libc.print(" ERR=");
    libc.printNum(@bitCast(result));
    libc.print("\n");
    return false;
}
fn cleanup() void {
    libc.gpuCtxDestroy();
}
fn halt() noreturn {
    while (true) libc.sleep(1000);
}
