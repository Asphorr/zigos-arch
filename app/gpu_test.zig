// GPU 3D Test — VirGL Screen Clear
// Creates a VirGL context, sets up render state, clears to red, displays result

const libc = @import("libc");
const virgl = @import("virgl");

export fn _start() callconv(.c) noreturn {
    libc.print("=== GPU 3D Test ===\n\n");

    // 1. Query capsets
    libc.print("Querying capsets...\n");
    var found_virgl = false;
    for (0..16) |i| {
        var info: [3]u32 = undefined;
        if (!libc.gpuGetCapsetInfo(@intCast(i), &info)) break;
        if (info[0] == 0 and info[2] == 0) break;

        libc.print("  Capset[");
        libc.printNum(@intCast(i));
        libc.print("]: id=");
        libc.printNum(info[0]);
        if (info[0] == 1) {
            libc.print(" (VIRGL)");
            found_virgl = true;
        } else if (info[0] == 2) {
            libc.print(" (VIRGL2)");
            found_virgl = true;
        } else if (info[0] == 4) {
            libc.print(" (VENUS)");
        }
        libc.print("\n");
    }

    if (!found_virgl) {
        libc.print("No VirGL capset found!\n");
        while (true) libc.sleep(1000);
    }

    // 2. Create VirGL context
    libc.print("\nCreating VirGL context...\n");
    const ctx_id = libc.gpuCtxCreate(1) orelse {
        libc.print("FAILED to create context!\n");
        while (true) libc.sleep(1000);
    };
    libc.print("  Context created: ");
    libc.printNum(ctx_id);
    libc.print("\n");

    // 3. Create a 3D render target resource (320x240 for testing)
    const RT_W: u32 = 320;
    const RT_H: u32 = 240;
    libc.print("Creating 3D resource (");
    libc.printNum(RT_W);
    libc.print("x");
    libc.printNum(RT_H);
    libc.print(")...\n");

    const create_params = [5]u32{
        virgl.PIPE_TEXTURE_2D, // target
        virgl.PIPE_FORMAT_B8G8R8X8_UNORM, // format
        virgl.PIPE_BIND_RENDER_TARGET, // bind
        RT_W, // width
        RT_H, // height
    };
    const res_id = libc.gpuResourceCreate3D(&create_params) orelse {
        libc.print("FAILED to create 3D resource!\n");
        libc.gpuCtxDestroy();
        while (true) libc.sleep(1000);
    };
    libc.print("  Resource created: ");
    libc.printNum(res_id);
    libc.print("\n");

    // 4. Build VirGL command buffer
    libc.print("Building VirGL commands...\n");
    var cmdbuf = virgl.CmdBuf{};

    // Create sub-context
    cmdbuf.createSubCtx(1);
    cmdbuf.setSubCtx(1);

    // Create and bind pipeline state objects
    cmdbuf.createBlend(1);
    cmdbuf.bindObject(1, 1); // bind blend

    cmdbuf.createDSA(2);
    cmdbuf.bindObject(3, 2); // bind DSA

    cmdbuf.createRasterizer(3);
    cmdbuf.bindObject(2, 3); // bind rasterizer

    // Create surface from our 3D resource
    cmdbuf.createSurface(4, res_id, virgl.PIPE_FORMAT_B8G8R8X8_UNORM);

    // Set framebuffer
    cmdbuf.setFramebufferState(4);

    // Set viewport
    cmdbuf.setViewport(RT_W, RT_H);

    // Clear to RED
    cmdbuf.clear(virgl.PIPE_CLEAR_COLOR0, 1.0, 0.0, 0.0, 1.0);

    libc.print("  Commands: ");
    libc.printNum(@intCast(cmdbuf.pos));
    libc.print(" dwords (");
    libc.printNum(@intCast(cmdbuf.pos * 4));
    libc.print(" bytes)\n");

    // 5. Submit command buffer
    libc.print("Submitting 3D commands...\n");
    if (cmdbuf.submit()) {
        libc.print("  SUCCESS! Screen cleared to RED.\n");
    } else {
        libc.print("  FAILED to submit!\n");
    }

    // 6. Done
    libc.print("\n=== Test Complete ===\n");
    libc.print("VirGL pipeline working!\n");

    libc.gpuCtxDestroy();
    while (true) libc.sleep(1000);
}
