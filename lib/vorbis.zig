//! Idiomatic Zig wrapper over stb_vorbis (OGG Vorbis decoder).
//!
//! Two APIs:
//!   - One-shot decode: load a whole short BGM track into a sample
//!     buffer. Convenient but holds the full decoded PCM in RAM.
//!   - Streaming Decoder: pull short PCM chunks on demand. Required
//!     for long tracks (DDLC's 5 MB OGG files would expand to ~50 MB
//!     of decoded 16-bit stereo).
//!
//! All math is freestanding-safe via vendor/c_math.c (no libm).
//!
//! Typical streaming use:
//!
//!   const decoder = try vorbis.Decoder.open(ogg_bytes);
//!   defer decoder.close();
//!   const info = decoder.info();
//!   // info.channels (1=mono, 2=stereo)
//!   // info.sample_rate (Hz, e.g. 44100)
//!   var buf: [4096]i16 = undefined;
//!   while (true) {
//!       const got = decoder.read(buf[0..]);  // interleaved samples
//!       if (got == 0) break;
//!       audio_sink.write(buf[0..got]);
//!   }

const raw = @import("vorbis_raw");

pub const Error = error{
    DecodeFailed,
    OutOfMemory,
};

pub const Info = struct {
    channels: u8,
    sample_rate: u32,
    /// Total frame count if known (PCM frames, not bytes). 0 if the
    /// stream length couldn't be determined.
    total_frames: u32,
};

/// One-shot full decode. Returns interleaved s16 samples (channels * frames
/// elements) allocated by stb_vorbis; caller must `deinit()`.
pub const Pcm = struct {
    samples: []i16,
    channels: u8,
    sample_rate: u32,
    frames: u32,

    pub fn deinit(self: Pcm) void {
        // stb_vorbis_decode_memory output came from malloc; free via libc free.
        // The exported `free` symbol in stb_shims.zig handles this.
        const Free = extern struct {};
        _ = Free;
        cFree(@ptrCast(@constCast(self.samples.ptr)));
    }
};

extern fn free(ptr: ?*anyopaque) void;

fn cFree(p: ?*anyopaque) void {
    free(p);
}

pub fn decode(bytes: []const u8) Error!Pcm {
    var channels: c_int = 0;
    var sample_rate: c_int = 0;
    var output: ?[*]c_short = null;
    var frames: c_int = 0;
    const got_channels = raw.vb_decode_memory(
        bytes.ptr,
        @intCast(bytes.len),
        &channels,
        &sample_rate,
        &output,
        &frames,
    );
    if (got_channels == 0 or output == null or frames <= 0) return error.DecodeFailed;
    const total_samples: usize = @as(usize, @intCast(channels)) * @as(usize, @intCast(frames));
    return .{
        .samples = output.?[0..total_samples],
        .channels = @intCast(channels),
        .sample_rate = @intCast(sample_rate),
        .frames = @intCast(frames),
    };
}

/// Streaming pull-decoder. Keeps the stream open between read() calls
/// so the decoder state survives chunked reads without re-parsing.
pub const Decoder = struct {
    handle: ?*raw.vb_stream,

    pub fn open(bytes: []const u8) Error!Decoder {
        var err: c_int = 0;
        const h = raw.vb_open_memory(bytes.ptr, @intCast(bytes.len), &err);
        if (h == null) return error.DecodeFailed;
        return .{ .handle = h };
    }

    pub fn close(self: Decoder) void {
        if (self.handle) |h| raw.vb_close(h);
    }

    pub fn info(self: *const Decoder) Info {
        return .{
            .channels = @intCast(raw.vb_channels(self.handle)),
            .sample_rate = @intCast(raw.vb_sample_rate(self.handle)),
            .total_frames = raw.vb_total_frames(self.handle),
        };
    }

    /// Pull up to `out.len / channels` frames of interleaved s16 PCM
    /// into `out`. Returns the number of FRAMES decoded (not samples);
    /// 0 = end of stream.
    pub fn read(self: *Decoder, out: []i16) u32 {
        const ch: u32 = @intCast(raw.vb_channels(self.handle));
        if (ch == 0) return 0;
        const max_frames: c_int = @intCast(out.len / ch);
        const got = raw.vb_read_short_interleaved(self.handle, out.ptr, max_frames);
        return @intCast(got);
    }

    /// Rewind to the start of the stream (e.g. for BGM looping).
    pub fn seekStart(self: *Decoder) bool {
        return raw.vb_seek_start(self.handle) != 0;
    }
};
