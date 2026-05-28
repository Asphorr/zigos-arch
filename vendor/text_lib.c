// Implementation TU for the stb_truetype dependency. Math overrides
// come from vendor/freestanding_math.h (SSE2-only ops, no libm).
//
// malloc/free/memcpy/memset/strlen come from the static library's
// lib/stb_shims.zig (Zig exports).

#include <stddef.h>
#include <stdint.h>

#include "freestanding_math.h"

// All STBTT_* macros must be #defined BEFORE the stb_truetype.h include —
// the header's default branches each `#include <foo.h>`, which fails in
// freestanding. We override every override-point.

// Math
#define STBTT_ifloor(x)    fsm_ifloor(x)
#define STBTT_iceil(x)     fsm_iceil(x)
#define STBTT_sqrt(x)      fsm_sqrt(x)
#define STBTT_pow(x, y)    fsm_pow(x, y)
#define STBTT_fmod(x, y)   fsm_fmod(x, y)
#define STBTT_cos(x)       fsm_cos(x)
#define STBTT_acos(x)      fsm_acos(x)
#define STBTT_fabs(x)      fsm_fabs(x)

// Memory — malloc/free come from lib/stb_shims.zig (Zig exports).
extern void* malloc(unsigned long);
extern void  free(void*);
#define STBTT_malloc(x, u)  ((void)(u), malloc((unsigned long)(x)))
#define STBTT_free(x, u)    ((void)(u), free(x))

// Mem/string ops — from lib/stb_shims.zig.
extern void* memcpy(void*, const void*, unsigned long);
extern void* memset(void*, int, unsigned long);
extern unsigned long strlen(const char*);
#define STBTT_memcpy(d, s, n)  memcpy((d), (s), (unsigned long)(n))
#define STBTT_memset(d, c, n)  memset((d), (c), (unsigned long)(n))
#define STBTT_strlen(s)        strlen(s)

// Assert: no-op (we trust the rasterizer's invariants).
#define STBTT_assert(x)        ((void)0)

#define STB_TRUETYPE_IMPLEMENTATION
#include "stb_truetype.h"

// ---- Slim public-API wrappers ---------------------------------------------

#include "text_lib.h"

void* tt_font_alloc(void) {
    return malloc(sizeof(stbtt_fontinfo));
}

void tt_font_free(void* font) {
    free(font);
}

int tt_init(void* font, const unsigned char* data, int offset) {
    return stbtt_InitFont((stbtt_fontinfo*)font, data, offset);
}

int tt_offset_for_index(const unsigned char* data, int index) {
    return stbtt_GetFontOffsetForIndex(data, index);
}

void tt_vmetrics(void* font, int* ascent, int* descent, int* line_gap) {
    stbtt_GetFontVMetrics((stbtt_fontinfo*)font, ascent, descent, line_gap);
}

float tt_scale_for_pixel_height(void* font, float pixel_height) {
    return stbtt_ScaleForPixelHeight((stbtt_fontinfo*)font, pixel_height);
}

int tt_find_glyph_index(void* font, int codepoint) {
    return stbtt_FindGlyphIndex((stbtt_fontinfo*)font, codepoint);
}

void tt_codepoint_hmetrics(void* font, int codepoint, int* advance, int* lsb) {
    stbtt_GetCodepointHMetrics((stbtt_fontinfo*)font, codepoint, advance, lsb);
}

int tt_codepoint_kern_advance(void* font, int c1, int c2) {
    return stbtt_GetCodepointKernAdvance((stbtt_fontinfo*)font, c1, c2);
}

unsigned char* tt_codepoint_bitmap(
    void* font,
    float scale_x,
    float scale_y,
    int codepoint,
    int* width,
    int* height,
    int* xoff,
    int* yoff)
{
    return stbtt_GetCodepointBitmap(
        (stbtt_fontinfo*)font, scale_x, scale_y, codepoint,
        width, height, xoff, yoff);
}

void tt_free_bitmap(unsigned char* bitmap) {
    stbtt_FreeBitmap(bitmap, NULL);
}
