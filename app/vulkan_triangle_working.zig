// Vulkan Triangle — Venus wire protocol over virtio-gpu
// Renders a red triangle via Vulkan/Venus, displays CPU visualization

const libc = @import("libc");
const venus = @import("venus");

// SPIR-V shaders
const vert_spirv = [_]u32{
    0x07230203, 0x00010000, 0x00000000, 0x00000027, 0x00000000, 0x00020011, 0x00000001, 0x0003000E,
    0x00000000, 0x00000001, 0x0007000F, 0x00000000, 0x00000001, 0x6E69616D, 0x00000000, 0x00000002,
    0x00000003, 0x00040047, 0x00000002, 0x0000000B, 0x0000002A, 0x00040047, 0x00000003, 0x0000000B,
    0x00000000, 0x00020013, 0x0000000A, 0x00030021, 0x0000000B, 0x0000000A, 0x00030016, 0x0000000C,
    0x00000020, 0x00040017, 0x0000000D, 0x0000000C, 0x00000002, 0x00040017, 0x0000000E, 0x0000000C,
    0x00000004, 0x00040015, 0x0000000F, 0x00000020, 0x00000001, 0x00040015, 0x00000012, 0x00000020,
    0x00000000, 0x00040020, 0x00000010, 0x00000001, 0x0000000F, 0x00040020, 0x00000011, 0x00000003,
    0x0000000E, 0x0004002B, 0x00000012, 0x00000013, 0x00000003, 0x0004001C, 0x0000001B, 0x0000000D,
    0x00000013, 0x00040020, 0x0000001C, 0x00000007, 0x0000001B, 0x00040020, 0x0000001D, 0x00000007,
    0x0000000D, 0x0004002B, 0x0000000C, 0x00000014, 0x00000000, 0x0004002B, 0x0000000C, 0x00000015,
    0x3F000000, 0x0004002B, 0x0000000C, 0x00000016, 0xBF000000, 0x0004002B, 0x0000000C, 0x00000017,
    0x3F800000, 0x0005002C, 0x0000000D, 0x00000018, 0x00000014, 0x00000016, 0x0005002C, 0x0000000D,
    0x00000019, 0x00000015, 0x00000015, 0x0005002C, 0x0000000D, 0x0000001A, 0x00000016, 0x00000015,
    0x0006002C, 0x0000001B, 0x00000020, 0x00000018, 0x00000019, 0x0000001A, 0x0004003B, 0x00000010,
    0x00000002, 0x00000001, 0x0004003B, 0x00000011, 0x00000003, 0x00000003, 0x00050036, 0x0000000A,
    0x00000001, 0x00000000, 0x0000000B, 0x000200F8, 0x0000001E, 0x0004003B, 0x0000001C, 0x0000001F,
    0x00000007, 0x0003003E, 0x0000001F, 0x00000020, 0x0004003D, 0x0000000F, 0x00000021, 0x00000002,
    0x00050041, 0x0000001D, 0x00000022, 0x0000001F, 0x00000021, 0x0004003D, 0x0000000D, 0x00000023,
    0x00000022, 0x00050051, 0x0000000C, 0x00000024, 0x00000023, 0x00000000, 0x00050051, 0x0000000C,
    0x00000025, 0x00000023, 0x00000001, 0x00070050, 0x0000000E, 0x00000026, 0x00000024, 0x00000025,
    0x00000014, 0x00000017, 0x0003003E, 0x00000003, 0x00000026, 0x000100FD, 0x00010038,
};
const frag_spirv = [_]u32{
    0x07230203, 0x00010000, 0x00000000, 0x00000013, 0x00000000, 0x00020011, 0x00000001, 0x0003000E,
    0x00000000, 0x00000001, 0x0006000F, 0x00000004, 0x00000001, 0x6E69616D, 0x00000000, 0x00000002,
    0x00030010, 0x00000001, 0x00000007, 0x00040047, 0x00000002, 0x0000001E, 0x00000000, 0x00020013,
    0x0000000A, 0x00030021, 0x0000000B, 0x0000000A, 0x00030016, 0x0000000C, 0x00000020, 0x00040017,
    0x0000000D, 0x0000000C, 0x00000004, 0x00040020, 0x0000000E, 0x00000003, 0x0000000D, 0x0004002B,
    0x0000000C, 0x0000000F, 0x3F800000, 0x0004002B, 0x0000000C, 0x00000010, 0x00000000, 0x0007002C,
    0x0000000D, 0x00000011, 0x0000000F, 0x00000010, 0x00000010, 0x0000000F, 0x0004003B, 0x0000000E,
    0x00000002, 0x00000003, 0x00050036, 0x0000000A, 0x00000001, 0x00000000, 0x0000000B, 0x000200F8,
    0x00000012, 0x0003003E, 0x00000002, 0x00000011, 0x000100FD, 0x00010038,
};

const RT_W: u32 = 320;
const RT_H: u32 = 240;
const VK_FORMAT_R8G8B8A8_UNORM: u32 = 37;

const INSTANCE: u64 = 100;
const PHYS_DEV: u64 = 101;
const DEVICE: u64 = 102;
const QUEUE: u64 = 103;
const IMAGE: u64 = 200;
const IMAGE_VIEW: u64 = 201;
const RENDER_MEM: u64 = 202;
const RENDER_PASS: u64 = 300;
const PIPELINE_LAYOUT: u64 = 301;
const VERT_MODULE: u64 = 302;
const FRAG_MODULE: u64 = 303;
const PIPELINE: u64 = 304;
const FRAMEBUFFER: u64 = 305;
const CMD_POOL: u64 = 400;
const CMD_BUF: u64 = 401;

var cs: venus.CmdStream = .{};
var reply_buf: [*]volatile u8 = undefined;

export fn _start() callconv(.c) noreturn {
    libc.print("=== Vulkan Triangle ===\n\n");

    // Find Venus capset
    var found_venus = false;
    for (0..16) |i| {
        var info: [3]u32 = undefined;
        if (!libc.gpuGetCapsetInfo(@intCast(i), &info)) break;
        if (info[0] == 0 and info[2] == 0) break;
        if (info[0] == 4) found_venus = true;
    }
    if (!found_venus) { libc.print("No Venus!\n"); halt(); }

    _ = libc.gpuCtxCreate(4) orelse { libc.print("Ctx fail!\n"); halt(); };

    const reply = venus.setupReplyStream(4096) orelse {
        libc.print("Reply stream fail!\n");
        cleanup(); halt();
    };
    reply_buf = reply.buf;
    libc.print("Reply stream OK\n");

    // vkCreateInstance
    if (!vkCmd(struct {
        fn f(s: *venus.CmdStream) void {
            s.cmdHeader(venus.CMD_vkCreateInstance, venus.CMD_FLAG_GENERATE_REPLY);
            s.writePresent();
            s.writeU32(venus.VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO);
            s.writeNull(); s.writeU32(0);
            s.writePresent();
            s.writeU32(venus.VK_STRUCTURE_TYPE_APPLICATION_INFO);
            s.writeNull();
            s.writeString("VkTri"); s.writeU32(1);
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

    if (!vkEnc(venus.encodeCreateDevice, .{ PHYS_DEV, 0, DEVICE }, "vkCreateDevice")) { cleanup(); halt(); }
    fire(venus.encodeGetDeviceQueue, .{ DEVICE, 0, 0, QUEUE });

    if (!vkEnc(venus.encodeCreateImage, .{ DEVICE, RT_W, RT_H, VK_FORMAT_R8G8B8A8_UNORM, 0x10, IMAGE }, "vkCreateImage")) { cleanup(); halt(); }
    if (!vkEnc(venus.encodeAllocateMemory, .{ DEVICE, 4 * 1024 * 1024, 0, RENDER_MEM }, "vkAllocMemory")) { cleanup(); halt(); }
    if (!vkEnc(venus.encodeBindImageMemory, .{ DEVICE, IMAGE, RENDER_MEM, 0 }, "vkBindImgMem")) { cleanup(); halt(); }
    if (!vkEnc(venus.encodeCreateImageView, .{ DEVICE, IMAGE, VK_FORMAT_R8G8B8A8_UNORM, IMAGE_VIEW }, "vkCreateImgView")) { cleanup(); halt(); }

    if (!vkEnc(venus.encodeCreateRenderPass, .{ DEVICE, VK_FORMAT_R8G8B8A8_UNORM, RENDER_PASS }, "vkRenderPass")) { cleanup(); halt(); }
    if (!vkEnc(venus.encodeCreateFramebuffer, .{ DEVICE, RENDER_PASS, IMAGE_VIEW, RT_W, RT_H, FRAMEBUFFER }, "vkFB")) { cleanup(); halt(); }
    if (!vkEnc(venus.encodeCreateShaderModule, .{ DEVICE, &vert_spirv, VERT_MODULE }, "vkShader(v)")) { cleanup(); halt(); }
    if (!vkEnc(venus.encodeCreateShaderModule, .{ DEVICE, &frag_spirv, FRAG_MODULE }, "vkShader(f)")) { cleanup(); halt(); }
    if (!vkEnc(venus.encodeCreatePipelineLayout, .{ DEVICE, PIPELINE_LAYOUT }, "vkPipeLayout")) { cleanup(); halt(); }
    if (!vkEnc(venus.encodeCreateGraphicsPipelines, .{ DEVICE, PIPELINE_LAYOUT, RENDER_PASS, VERT_MODULE, FRAG_MODULE, PIPELINE }, "vkPipeline")) { cleanup(); halt(); }
    if (!vkEnc(venus.encodeCreateCommandPool, .{ DEVICE, 0, CMD_POOL }, "vkCmdPool")) { cleanup(); halt(); }
    if (!vkEnc(venus.encodeAllocateCommandBuffers, .{ DEVICE, CMD_POOL, CMD_BUF }, "vkCmdBuf")) { cleanup(); halt(); }

    fire(venus.encodeBeginCommandBuffer, .{CMD_BUF});
    fire(venus.encodeCmdBeginRenderPass, .{ CMD_BUF, RENDER_PASS, FRAMEBUFFER, RT_W, RT_H });
    fire(venus.encodeCmdBindPipeline, .{ CMD_BUF, PIPELINE });
    fire(venus.encodeCmdDraw, .{ CMD_BUF, 3, 1 });
    fire(venus.encodeCmdEndRenderPass, .{CMD_BUF});
    fire(venus.encodeEndCommandBuffer, .{CMD_BUF});

    if (!vkEnc(venus.encodeQueueSubmit, .{ QUEUE, CMD_BUF }, "vkSubmit")) { cleanup(); halt(); }
    if (!vkEnc(venus.encodeDeviceWaitIdle, .{DEVICE}, "vkWaitIdle")) { cleanup(); halt(); }

    libc.print("\nAll Vulkan calls OK!\n");

    // Display CPU triangle
    const _win = libc.createWindow(RT_W, RT_H) orelse { cleanup(); halt(); };
    const fb = _win.fb;
    for (0..RT_W * RT_H) |i| fb[i] = 0xFF000000;

    // Rasterize triangle matching vertex shader output
    const x0: i32 = 160; const y0: i32 = 60;
    const x1i: i32 = 240; const y1i: i32 = 180;
    const x2i: i32 = 80;
    var y: i32 = y0;
    while (y <= y1i) : (y += 1) {
        const t: f32 = @as(f32, @floatFromInt(y - y0)) / @as(f32, @floatFromInt(y1i - y0));
        const lx: i32 = x0 + @as(i32, @intFromFloat(t * @as(f32, @floatFromInt(x2i - x0))));
        const rx: i32 = x0 + @as(i32, @intFromFloat(t * @as(f32, @floatFromInt(x1i - x0))));
        var x: i32 = lx;
        while (x <= rx) : (x += 1) {
            if (x >= 0 and x < @as(i32, RT_W))
                fb[@intCast(@as(i32, RT_W) * y + x)] = 0xFFFF0000;
        }
    }
    libc.present();
    libc.print("Displayed!\n");

    cs.reset();
    venus.encodeDestroyInstance(&cs, INSTANCE);
    _ = cs.submit();
    cleanup();
    while (true) libc.sleep(100);
}

fn clearReply() void { for (0..64) |i| reply_buf[i] = 0; }
fn patchReplyFlag() void {
    const p: *align(1) u32 = @ptrCast(cs.buf[4..8]);
    p.* = venus.CMD_FLAG_GENERATE_REPLY;
}

fn vkCmd(encodeFn: *const fn (*venus.CmdStream) void, name: []const u8) bool {
    clearReply(); cs.reset(); encodeFn(&cs);
    return checkResult(name);
}
fn vkEnc(comptime encodeFn: anytype, args: anytype, name: []const u8) bool {
    clearReply(); cs.reset();
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
    if (!cs.submit()) { libc.print("  "); libc.print(name); libc.print(" FAIL\n"); return false; }
    const result = venus.readReplyResult(reply_buf);
    libc.print("  "); libc.print(name);
    if (result == 0) { libc.print(" OK\n"); return true; }
    libc.print(" ERR="); libc.printNum(@bitCast(result)); libc.print("\n");
    return false;
}
fn cleanup() void { libc.gpuCtxDestroy(); }
fn halt() noreturn { while (true) libc.sleep(1000); }
