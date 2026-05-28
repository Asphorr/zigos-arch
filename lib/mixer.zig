//! Multi-voice software mixer (userspace).
//!
//! Pull-callback design: each `Voice` has a `pull` fn that fills s16
//! interleaved stereo frames on demand. The mixer pulls a fixed-size
//! block from each active voice every `mix()` call, scales by the
//! voice's volume (Q8 fixed-point), sums into a temp accumulator with
//! saturation, and writes the result back as s16. The caller then
//! ships the mixed buffer to `audio_write`.
//!
//! Designed for the upcoming Ren'Py-style VN engine: BGM looped on
//! voice 0, voice line on voice 1, SFX on voices 2-7. Linear volume
//! ramps support BGM crossfades on screen transitions (Ren'Py's
//! `music.play("x.ogg", fadein=2.0, fadeout=2.0)`).
//!
//! Format is fixed at 44100 Hz stereo s16 — matches what the kernel
//! sound stack (virtio-snd / HDA / AC97) expects. Resampling is not
//! provided; OGG decode via stb_vorbis is the source of truth and DDLC
//! ships all assets at 44100/stereo.
//!
//! Typical use:
//!
//!   var m = mixer.Mixer.init();
//!   const bgm = try m.play(vorbisVoice.pull, &bgm_ctx, .{ .looped = true, .volume = 200 });
//!   const sfx = try m.play(vorbisVoice.pull, &sfx_ctx, .{ .volume = 256 });
//!   var buf: [2048]i16 = undefined;
//!   while (running) {
//!       const frames = m.mix(buf[0..]);
//!       try audio.write(buf[0 .. frames * 2]);
//!   }
//!
//! Threadless: callers drive the pump from their own loop. No allocations.

pub const MAX_VOICES: u8 = 8;
pub const SAMPLE_RATE: u32 = 44100;
pub const CHANNELS: u8 = 2;

/// Voice pull-callback. Fills `dst` with up to dst.len/2 frames of
/// interleaved s16 stereo. Returns frames written (0..=dst.len/2).
/// 0 means end-of-stream — the voice will be retired by the mixer
/// unless `Options.looped` was true and a `seek` callback restarts it.
pub const PullFn = *const fn (ctx: *anyopaque, dst: []i16) u32;

/// Optional rewind callback for looped voices. Called when `pull`
/// returns 0; if it succeeds, the mixer keeps the voice active and
/// pulls again. If not provided on a looped voice, the voice is
/// retired exactly like a non-looped one (silent failure mode is
/// caller's problem — set up the loop properly).
pub const SeekStartFn = *const fn (ctx: *anyopaque) bool;

pub const Options = struct {
    /// Q8 fixed-point initial volume: 0=silent, 256=unity.
    volume: u16 = 256,
    /// If true, the mixer attempts to rewind via `seek_start` on EOF.
    looped: bool = false,
    /// Rewind callback. Required iff `looped == true`.
    seek_start: ?SeekStartFn = null,
};

pub const Error = error{
    NoFreeVoice,
    InvalidVoice,
    LoopWithoutSeek,
};

const State = enum(u8) {
    idle,
    playing,
};

const Voice = struct {
    state: State,
    pull: PullFn,
    ctx: *anyopaque,
    seek_start: ?SeekStartFn,
    looped: bool,

    /// Current Q8 volume. Mutated by ramp logic when a fade is active.
    volume_q8: u16,

    /// Linear-ramp state. `fade_remain_frames > 0` means a ramp is
    /// active; per `mix()`-block we step `fade_step_q24` per frame
    /// into `fade_accum_q24` and update `volume_q8` from its high
    /// 16 bits. Q24 gives ~67M sub-steps over a multi-second fade
    /// without quantisation buzz.
    fade_remain_frames: u32,
    fade_step_q24: i32,
    fade_accum_q24: i64,
    fade_target_q8: u16,
};

pub const Mixer = struct {
    voices: [MAX_VOICES]Voice,

    /// Master volume Q8. Multiplied with per-voice on the way out.
    master_q8: u16,

    /// Scratch buffer for the per-voice pull. Sized to match the
    /// largest reasonable `mix()` block — most callers use 512 or
    /// 1024 frames per call. Stack-allocated inside `mix()` to keep
    /// the Mixer struct small for use in struct fields.
    /// (No field here — see `mix()` for the local declaration.)
    pub fn init() Mixer {
        var m: Mixer = undefined;
        for (&m.voices) |*v| v.state = .idle;
        m.master_q8 = 256;
        return m;
    }

    /// Start playing on the first idle voice slot. Returns the slot
    /// index (0..MAX_VOICES) for later `stop` / `setVolume` / `fade`
    /// calls.
    pub fn play(
        self: *Mixer,
        pull: PullFn,
        ctx: *anyopaque,
        opts: Options,
    ) Error!u8 {
        if (opts.looped and opts.seek_start == null) return error.LoopWithoutSeek;
        for (&self.voices, 0..) |*v, i| {
            if (v.state == .idle) {
                v.* = .{
                    .state = .playing,
                    .pull = pull,
                    .ctx = ctx,
                    .seek_start = opts.seek_start,
                    .looped = opts.looped,
                    .volume_q8 = opts.volume,
                    .fade_remain_frames = 0,
                    .fade_step_q24 = 0,
                    .fade_accum_q24 = 0,
                    .fade_target_q8 = opts.volume,
                };
                return @intCast(i);
            }
        }
        return error.NoFreeVoice;
    }

    pub fn stop(self: *Mixer, slot: u8) void {
        if (slot >= MAX_VOICES) return;
        self.voices[slot].state = .idle;
    }

    pub fn isActive(self: *const Mixer, slot: u8) bool {
        if (slot >= MAX_VOICES) return false;
        return self.voices[slot].state == .playing;
    }

    pub fn setVolume(self: *Mixer, slot: u8, volume_q8: u16) void {
        if (slot >= MAX_VOICES) return;
        var v = &self.voices[slot];
        v.volume_q8 = volume_q8;
        v.fade_remain_frames = 0;
        v.fade_target_q8 = volume_q8;
    }

    /// Master volume Q8 (0..=256). Applied to the final mix after
    /// per-voice scaling. Default 256 (unity).
    pub fn setMasterVolume(self: *Mixer, volume_q8: u16) void {
        self.master_q8 = volume_q8;
    }

    /// Linearly ramp `slot`'s volume to `target_q8` over `frames`
    /// frames (frames / 44100 seconds). Use for crossfades.
    /// When the ramp reaches `target`, if `target == 0`, the voice
    /// is automatically retired (Ren'Py's fadeout-then-stop pattern).
    pub fn fade(self: *Mixer, slot: u8, target_q8: u16, frames: u32) void {
        if (slot >= MAX_VOICES) return;
        var v = &self.voices[slot];
        if (frames == 0) {
            v.volume_q8 = target_q8;
            v.fade_remain_frames = 0;
            return;
        }
        const start_q24: i64 = @as(i64, v.volume_q8) << 16; // Q8 → Q24
        const target_q24: i64 = @as(i64, target_q8) << 16;
        const step: i64 = @divTrunc(target_q24 - start_q24, @as(i64, frames));
        v.fade_step_q24 = @intCast(step);
        v.fade_accum_q24 = start_q24;
        v.fade_remain_frames = frames;
        v.fade_target_q8 = target_q8;
    }

    /// Pull samples from every active voice, sum-with-saturation into
    /// `dst`. `dst.len` must be even (2 channels). Returns the number
    /// of frames written (== dst.len / 2 unless something pathological
    /// like a tiny dst is passed).
    pub fn mix(self: *Mixer, dst: []i16) u32 {
        const total_frames: u32 = @intCast(dst.len / 2);
        if (total_frames == 0) return 0;

        // Stack scratch for one voice's pull. 1024 frames = 4 KB,
        // dst is split into chunks of this size when larger.
        var scratch: [2048]i16 = undefined; // 1024 frames * 2 channels
        const max_chunk_frames: u32 = scratch.len / 2;

        // Zero dst (sum accumulator starts at silence).
        for (dst) |*s| s.* = 0;

        var frame_off: u32 = 0;
        while (frame_off < total_frames) {
            const chunk = @min(total_frames - frame_off, max_chunk_frames);
            const samples = chunk * 2;

            // Reuse `dst` slice as the running mix accumulator (already
            // initialised to 0 above). Per voice: pull into scratch,
            // scale & add into dst, with sub-mix saturation.
            for (&self.voices) |*v| {
                if (v.state != .playing) continue;

                const got = v.pull(v.ctx, scratch[0..samples]);
                if (got == 0) {
                    // EOF — try the loop hook, otherwise retire.
                    if (v.looped) if (v.seek_start) |s| {
                        if (s(v.ctx)) {
                            // Retry once; if still 0, give up.
                            const got2 = v.pull(v.ctx, scratch[0..samples]);
                            if (got2 == 0) {
                                v.state = .idle;
                                continue;
                            }
                            addVoice(v, scratch[0 .. got2 * 2], dst[frame_off * 2 .. (frame_off + got2) * 2]);
                            continue;
                        }
                    };
                    v.state = .idle;
                    continue;
                }

                addVoice(v, scratch[0 .. got * 2], dst[frame_off * 2 .. (frame_off + got) * 2]);
            }

            frame_off += chunk;
        }

        // Apply master volume in-place. Fast path when master == 256.
        if (self.master_q8 != 256) {
            const m: i32 = @intCast(self.master_q8);
            for (dst) |*s| {
                const scaled: i32 = (@as(i32, s.*) * m) >> 8;
                s.* = @intCast(@max(-32768, @min(32767, scaled)));
            }
        }

        return total_frames;
    }
};

/// Mix one voice's `src` samples into `dst` with the voice's current
/// volume + fade ramp. Both buffers are interleaved stereo s16.
/// `src.len == dst.len`. Saturating add.
fn addVoice(v: *Voice, src: []const i16, dst: []i16) void {
    if (v.fade_remain_frames == 0) {
        // Steady-state — single volume across the whole chunk.
        const vol: i32 = @intCast(v.volume_q8);
        if (vol == 0) return; // silent voice, skip
        if (vol == 256) {
            // Unity — skip the multiply.
            var i: usize = 0;
            while (i < src.len) : (i += 1) {
                const sum: i32 = @as(i32, dst[i]) + @as(i32, src[i]);
                dst[i] = @intCast(@max(-32768, @min(32767, sum)));
            }
            return;
        }
        var i: usize = 0;
        while (i < src.len) : (i += 1) {
            const scaled: i32 = (@as(i32, src[i]) * vol) >> 8;
            const sum: i32 = @as(i32, dst[i]) + scaled;
            dst[i] = @intCast(@max(-32768, @min(32767, sum)));
        }
    } else {
        // Ramp active — step volume per frame.
        const frames: usize = src.len / 2;
        var i: usize = 0;
        while (i < frames) : (i += 1) {
            const vol: i32 = @intCast(v.volume_q8);
            const l_scaled: i32 = (@as(i32, src[i * 2]) * vol) >> 8;
            const r_scaled: i32 = (@as(i32, src[i * 2 + 1]) * vol) >> 8;
            const l_sum: i32 = @as(i32, dst[i * 2]) + l_scaled;
            const r_sum: i32 = @as(i32, dst[i * 2 + 1]) + r_scaled;
            dst[i * 2] = @intCast(@max(-32768, @min(32767, l_sum)));
            dst[i * 2 + 1] = @intCast(@max(-32768, @min(32767, r_sum)));

            // Step the ramp.
            v.fade_accum_q24 += v.fade_step_q24;
            v.volume_q8 = @intCast(@max(0, @min(@as(i64, 65535), v.fade_accum_q24 >> 16)));
            v.fade_remain_frames -= 1;
            if (v.fade_remain_frames == 0) {
                v.volume_q8 = v.fade_target_q8;
                if (v.fade_target_q8 == 0) {
                    // Fade-to-silence reached — retire the voice. We
                    // can't `return` here without losing the rest of
                    // `frames`, but since target is 0 the remaining
                    // adds would be silent anyway. Mark idle for the
                    // next mix() call.
                    v.state = .idle;
                    break;
                }
            }
        }
    }
}
