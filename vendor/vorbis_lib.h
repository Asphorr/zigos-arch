// Slim public-API surface for the stb_vorbis dependency. Mirrors the
// photo_lib.h / text_lib.h pattern: translate-c reads this small header
// instead of the 5500-line stb_vorbis.c, producing tight Zig bindings.
// The actual implementation lives in vorbis_lib.c which builds
// stb_vorbis.c with STB_VORBIS_NO_STDIO defined (we have no stdio in
// freestanding) and links against vendor/c_math.c for the libm symbols
// stb_vorbis calls.

#ifndef VORBIS_LIB_H
#define VORBIS_LIB_H

#ifdef __cplusplus
extern "C" {
#endif

/// Decode an entire OGG Vorbis blob into 16-bit signed PCM in one go.
/// Convenience for "load this short BGM track into memory at startup."
/// For long streaming use the open_memory / get_samples_short API
/// instead so the decoded PCM doesn't pin a full song's worth of RAM.
///
/// Returns the channel count, or 0 on decode failure. Out-params:
///   `sample_rate` — Hz (e.g. 44100)
///   `output`      — malloc'd interleaved s16 samples
///                   (total = channels * frames; caller frees with free())
///   `frames`      — number of stereo (or mono / surround) frames decoded
int vb_decode_memory(
    const unsigned char* data,
    int len,
    int* channels,
    int* sample_rate,
    short** output,
    int* frames);

// ---- Streaming pull-data API ----------------------------------------------
//
// For long BGM files we don't want to hold the whole decoded PCM. Open
// the bitstream once, then pull short PCM chunks on demand.

typedef struct vb_stream vb_stream;

/// Open a vorbis stream from an in-memory OGG blob. The blob must
/// remain valid for the lifetime of the stream (stb stores pointers
/// INTO it). Returns NULL on parse failure.
vb_stream* vb_open_memory(const unsigned char* data, int len, int* error);

void vb_close(vb_stream* s);

/// Read up to `frames` worth of interleaved s16 PCM into `out`. Returns
/// the number of frames actually written; 0 means end of stream.
/// `out` capacity must be at least frames * channels * sizeof(short).
int vb_read_short_interleaved(
    vb_stream* s,
    short* out,
    int frames);

/// Stream metadata.
int vb_channels(vb_stream* s);
int vb_sample_rate(vb_stream* s);
unsigned int vb_total_frames(vb_stream* s);

/// Seek to the start of the stream (e.g. for BGM loop).
int vb_seek_start(vb_stream* s);

#ifdef __cplusplus
}
#endif

#endif // VORBIS_LIB_H
