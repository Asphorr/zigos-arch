// VirGL Command Encoder
// Builds VirGL command buffers for submission via gpu_submit_3d syscall

const libc = @import("libc");

// VirGL command IDs
const CCMD_NOP: u32 = 0;
const CCMD_CREATE_OBJECT: u32 = 1;
const CCMD_BIND_OBJECT: u32 = 2;
const CCMD_DESTROY_OBJECT: u32 = 3;
const CCMD_SET_VIEWPORT_STATE: u32 = 4;
const CCMD_SET_FRAMEBUFFER_STATE: u32 = 5;
const CCMD_CLEAR: u32 = 7;
const CCMD_SET_SUB_CTX: u32 = 28;
const CCMD_CREATE_SUB_CTX: u32 = 29;

// Object types
const OBJ_BLEND: u32 = 1;
const OBJ_RASTERIZER: u32 = 2;
const OBJ_DSA: u32 = 3;
const OBJ_SURFACE: u32 = 8;

// PIPE constants
pub const PIPE_TEXTURE_2D: u32 = 2;
pub const PIPE_BIND_RENDER_TARGET: u32 = 0x02;
pub const PIPE_FORMAT_B8G8R8X8_UNORM: u32 = 2;
pub const PIPE_FORMAT_B8G8R8A8_UNORM: u32 = 1;
pub const PIPE_CLEAR_COLOR0: u32 = 0x04;

fn cmd0(cmd: u32, obj: u32, len: u32) u32 {
    return cmd | (obj << 8) | (len << 16);
}

fn fui(f: f32) u32 {
    return @bitCast(f);
}

/// Command buffer builder
pub const CmdBuf = struct {
    buf: [2048]u32 = undefined,
    pos: usize = 0,

    fn emit(self: *CmdBuf, val: u32) void {
        if (self.pos < self.buf.len) {
            self.buf[self.pos] = val;
            self.pos += 1;
        }
    }

    /// Create a sub-context
    pub fn createSubCtx(self: *CmdBuf, id: u32) void {
        self.emit(cmd0(CCMD_CREATE_SUB_CTX, 0, 1));
        self.emit(id);
    }

    /// Set active sub-context
    pub fn setSubCtx(self: *CmdBuf, id: u32) void {
        self.emit(cmd0(CCMD_SET_SUB_CTX, 0, 1));
        self.emit(id);
    }

    /// Create a blend object (simple: all color write, no blending)
    pub fn createBlend(self: *CmdBuf, handle: u32) void {
        self.emit(cmd0(CCMD_CREATE_OBJECT, OBJ_BLEND, 11));
        self.emit(handle);
        self.emit(0); // S0: no independent blend, no logicop
        self.emit(0); // logicop_func
        // Per-RT blend state: enable RGBA colormask = 0xF << 27
        self.emit(0x78000000); // RT0
        self.emit(0); // RT1
        self.emit(0); // RT2
        self.emit(0); // RT3
        self.emit(0); // RT4
        self.emit(0); // RT5
        self.emit(0); // RT6
        self.emit(0); // RT7
    }

    /// Create a DSA object (no depth/stencil test)
    pub fn createDSA(self: *CmdBuf, handle: u32) void {
        self.emit(cmd0(CCMD_CREATE_OBJECT, OBJ_DSA, 5));
        self.emit(handle);
        self.emit(0); // S0: no depth test
        self.emit(0); // front stencil
        self.emit(0); // back stencil
        self.emit(0); // alpha_ref
    }

    /// Create a rasterizer object (defaults)
    pub fn createRasterizer(self: *CmdBuf, handle: u32) void {
        self.emit(cmd0(CCMD_CREATE_OBJECT, OBJ_RASTERIZER, 9));
        self.emit(handle);
        self.emit(0x20000002); // S0: depth_clip=1, half_pixel_center=1
        self.emit(fui(1.0)); // point_size
        self.emit(0); // sprite_coord_enable
        self.emit(0); // S3
        self.emit(fui(1.0)); // line_width
        self.emit(0); // offset_units
        self.emit(0); // offset_scale
        self.emit(0); // offset_clamp
    }

    /// Create a surface object referencing a 3D resource
    pub fn createSurface(self: *CmdBuf, handle: u32, resource_id: u32, format: u32) void {
        self.emit(cmd0(CCMD_CREATE_OBJECT, OBJ_SURFACE, 5));
        self.emit(handle);
        self.emit(resource_id);
        self.emit(format);
        self.emit(0); // level 0
        self.emit(0); // first_layer=0, last_layer=0
    }

    /// Bind an object
    pub fn bindObject(self: *CmdBuf, obj_type: u32, handle: u32) void {
        self.emit(cmd0(CCMD_BIND_OBJECT, obj_type, 1));
        self.emit(handle);
    }

    /// Set framebuffer state (single color buffer, no depth)
    pub fn setFramebufferState(self: *CmdBuf, surface_handle: u32) void {
        self.emit(cmd0(CCMD_SET_FRAMEBUFFER_STATE, 0, 3));
        self.emit(1); // nr_cbufs
        self.emit(0); // zsurf_handle (no depth)
        self.emit(surface_handle);
    }

    /// Set viewport state
    pub fn setViewport(self: *CmdBuf, width: u32, height: u32) void {
        const w: f32 = @floatFromInt(width);
        const h: f32 = @floatFromInt(height);
        self.emit(cmd0(CCMD_SET_VIEWPORT_STATE, 0, 7));
        self.emit(0); // start_slot
        self.emit(fui(w / 2.0)); // scale_x
        self.emit(fui(h / 2.0)); // scale_y
        self.emit(fui(0.5)); // scale_z
        self.emit(fui(w / 2.0)); // translate_x
        self.emit(fui(h / 2.0)); // translate_y
        self.emit(fui(0.5)); // translate_z
    }

    /// Clear with a solid color (r, g, b, a as 0.0-1.0)
    pub fn clear(self: *CmdBuf, buffers: u32, r: f32, g: f32, b: f32, a: f32) void {
        self.emit(cmd0(CCMD_CLEAR, 0, 8));
        self.emit(buffers);
        self.emit(fui(r));
        self.emit(fui(g));
        self.emit(fui(b));
        self.emit(fui(a));
        // depth as f64 = 1.0 (two u32s)
        const depth: f64 = 1.0;
        const depth_bits: u64 = @bitCast(depth);
        self.emit(@truncate(depth_bits));
        self.emit(@truncate(depth_bits >> 32));
        self.emit(0); // stencil
    }

    /// Get the command buffer as a byte slice for submission
    pub fn bytes(self: *CmdBuf) []const u8 {
        const ptr: [*]const u8 = @ptrCast(&self.buf);
        return ptr[0 .. self.pos * 4];
    }

    /// Submit this command buffer via syscall
    pub fn submit(self: *CmdBuf) bool {
        return libc.gpuSubmit3D(self.bytes());
    }
};
