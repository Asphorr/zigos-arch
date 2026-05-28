//! Idiomatic Zig wrapper over stb_image.
//!
//! Decodes PNG / JPG / BMP / GIF / TGA / HDR / PSD / PIC from memory bytes.
//! The C implementation lives in `vendor/photo_lib.c` (a stb_image impl-include
//! shim), compiled once into the `stb_image` static library; this module is
//! the consumer-facing surface that hides the translate-c'd C ABI behind a
//! Zig-shaped API.
//!
//! Usage:
//!   const image = @import("image");
//!   const img = try image.decode(file_bytes, 4);  // 4 = force RGBA
//!   defer img.deinit();
//!   // img.pixels is a flat row-major buffer of w*h*channels bytes.
//!
//! Promoted from per-app translate-c modules to a shared lib/ dependency
//! 2026-05-28 as the foundation for the upcoming visual-novel engine port,
//! shared with photo.elf / settings.elf / wallpaper.elf.

const stb = @import("stb");

/// Raw translate-c bindings — escape hatch for callers that need a C-shape
/// API (e.g., passing pointers to ad-hoc decoders). New code should prefer
/// `decode()`.
pub const raw = stb;

pub const Error = error{
    /// stb_image returned a null pointer — file format unsupported, header
    /// malformed, or out of memory. Call `lastError()` for stb's reason
    /// string before doing anything else (it's a single global, clobbered
    /// by the next decode attempt).
    DecodeFailed,
};

/// A decoded image. Caller owns the underlying buffer and must call
/// `deinit()`; the buffer was allocated by stb_image's STBI_MALLOC, which
/// routes to the per-process heap via `lib/stb_shims.zig`.
pub const Pixel = struct {
    width: u32,
    height: u32,
    /// Channel count actually populated in `pixels` — matches the
    /// `desired_channels` argument to `decode()` (1=Y, 2=YA, 3=RGB, 4=RGBA).
    channels: u8,
    /// Source channel count from the file before any forced conversion.
    /// Useful for diagnostics or for decode flows that want to know if a
    /// file was natively RGBA vs forced from RGB.
    source_channels: u8,
    /// Row-major pixel data: rows[0..height] each of width*channels bytes.
    pixels: []u8,

    pub fn deinit(self: Pixel) void {
        stb.stbi_image_free(@ptrCast(@constCast(self.pixels.ptr)));
    }
};

/// Decode `bytes` into RGBA (or whatever `desired_channels` requests). Pass
/// 0 to keep the file's native channel count; passing 4 is the common
/// "force RGBA so my blitter has a uniform stride" choice.
pub fn decode(bytes: []const u8, desired_channels: u8) Error!Pixel {
    var w: c_int = 0;
    var h: c_int = 0;
    var ch: c_int = 0;
    const px_opt = stb.stbi_load_from_memory(
        bytes.ptr,
        @intCast(bytes.len),
        &w,
        &h,
        &ch,
        @intCast(desired_channels),
    );
    const px = px_opt orelse return error.DecodeFailed;
    const out_channels: u8 = if (desired_channels == 0) @intCast(ch) else desired_channels;
    const pixel_bytes: usize = @as(usize, @intCast(w)) * @as(usize, @intCast(h)) * out_channels;
    return .{
        .width = @intCast(w),
        .height = @intCast(h),
        .channels = out_channels,
        .source_channels = @intCast(ch),
        .pixels = px[0..pixel_bytes],
    };
}

/// stb_image's last failure reason (UTF-8 C string). Returns null if no
/// decode has been attempted yet or the buffer was cleared. Stb keeps this
/// in a global, so the value is only meaningful immediately after a
/// `decode()` that returned `error.DecodeFailed`.
pub fn lastError() ?[]const u8 {
    const ptr_opt = stb.stbi_failure_reason();
    const ptr = ptr_opt orelse return null;
    var len: usize = 0;
    while (ptr[len] != 0) : (len += 1) {}
    return ptr[0..len];
}
