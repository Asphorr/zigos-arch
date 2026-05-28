// Implementation TU for the stb_vorbis dependency. Disables stdio
// (we have none in freestanding) and pulls in stb_vorbis.c's
// pull-data API. Math symbols (sqrt/sin/cos/...) come from
// vendor/c_math.c which links into the same static library.

#include <stddef.h>
#include <stdint.h>

// Disable file-based I/O — we only do in-memory decode.
#define STB_VORBIS_NO_STDIO

// Keep the pull-data API (open_memory + get_samples_short_interleaved).
// Push-data API is for stream-decoder use cases (network/seek) — leave
// it on for potential future use; it adds ~5 KB to the lib.

// Force libc shim symbol resolution — declare the few we use here so
// the C compiler doesn't insist on libc headers.
extern void* malloc(unsigned long);
extern void* realloc(void*, unsigned long);
extern void  free(void*);
extern void* memcpy(void*, const void*, unsigned long);
extern void* memset(void*, int, unsigned long);
extern void* memmove(void*, const void*, unsigned long);
extern int   memcmp(const void*, const void*, unsigned long);
extern int   abs(int);

// ldexp not in doom_src/include/math.h's Quake-set; stb_vorbis uses it
// for power-of-2 scaling in spectral envelope decode. Backed by c_math.c.
extern double ldexp(double, int);

// alloca: stb_vorbis's `temp_alloc` macro falls back to alloca() when the
// caller didn't supply a scratch buffer (we don't). clang/gcc treat
// __builtin_alloca as always-available without a header; aliasing the
// name here keeps stb_vorbis's stack-allocation path working.
#define alloca __builtin_alloca

// stb_vorbis includes <stdlib.h>/<string.h>/<assert.h>/<math.h>; the
// freestanding shim headers (doom_src/include/) provide prototype-only
// versions which the linker satisfies from our shim libs.

// Make assert a no-op — saves us implementing assert + assert_fail.
#define NDEBUG 1

#include "stb_vorbis.c"

// ---- Slim public-API wrappers --------------------------------------------

#include "vorbis_lib.h"

int vb_decode_memory(
    const unsigned char* data,
    int len,
    int* channels,
    int* sample_rate,
    short** output,
    int* frames)
{
    int n = stb_vorbis_decode_memory(data, len, channels, sample_rate, output);
    if (n < 0) {
        if (frames) *frames = 0;
        return 0;
    }
    if (frames) *frames = n;
    return *channels;
}

struct vb_stream {
    stb_vorbis* v;
};

vb_stream* vb_open_memory(const unsigned char* data, int len, int* error) {
    int err = 0;
    stb_vorbis* v = stb_vorbis_open_memory(data, len, &err, NULL);
    if (error) *error = err;
    if (v == NULL) return NULL;
    vb_stream* s = (vb_stream*)malloc(sizeof(vb_stream));
    if (s == NULL) {
        stb_vorbis_close(v);
        return NULL;
    }
    s->v = v;
    return s;
}

void vb_close(vb_stream* s) {
    if (s == NULL) return;
    if (s->v) stb_vorbis_close(s->v);
    free(s);
}

int vb_read_short_interleaved(vb_stream* s, short* out, int frames) {
    if (s == NULL || s->v == NULL) return 0;
    stb_vorbis_info info = stb_vorbis_get_info(s->v);
    int got = stb_vorbis_get_samples_short_interleaved(s->v, info.channels, out, frames * info.channels);
    return got;
}

int vb_channels(vb_stream* s) {
    if (s == NULL || s->v == NULL) return 0;
    return stb_vorbis_get_info(s->v).channels;
}

int vb_sample_rate(vb_stream* s) {
    if (s == NULL || s->v == NULL) return 0;
    return stb_vorbis_get_info(s->v).sample_rate;
}

unsigned int vb_total_frames(vb_stream* s) {
    if (s == NULL || s->v == NULL) return 0;
    return stb_vorbis_stream_length_in_samples(s->v);
}

int vb_seek_start(vb_stream* s) {
    if (s == NULL || s->v == NULL) return 0;
    return stb_vorbis_seek_start(s->v);
}
