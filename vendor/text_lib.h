// Slim public-API surface for the stb_truetype dependency. Translate-c
// reads this small header instead of the 5000-line stb_truetype.h and
// produces tight Zig bindings; the actual implementation lives in
// text_lib.c which #defines STB_TRUETYPE_IMPLEMENTATION before
// #including stb_truetype.h, along with override macros for the libm
// functions (so we don't depend on libm in freestanding).
//
// Mirrors the photo_lib.h pattern used for stb_image.

#ifndef TEXT_LIB_H
#define TEXT_LIB_H

#ifdef __cplusplus
extern "C" {
#endif

/// Allocate an opaque stbtt_fontinfo. The struct's actual size (~200 B
/// in stb_truetype v1.26) is hidden behind this allocator so Zig-side
/// callers don't need to track it. Returns NULL on OOM.
void* tt_font_alloc(void);

void tt_font_free(void* font);

/// Initialize the font from a TTF/OTF buffer. `data` must remain valid
/// for the lifetime of the font (stb stores pointers INTO it).
/// `offset` is the table offset within `data` — pass 0 for single-font
/// TTFs; for TTC collections call tt_offset_for_index first.
/// Returns 1 on success, 0 on failure.
int tt_init(void* font, const unsigned char* data, int offset);

/// For TTC font collections: find the byte offset of the `index`-th
/// font inside `data`. Returns -1 if the index is out of range or
/// the file isn't a valid collection. Single-font TTF returns 0 for
/// index=0.
int tt_offset_for_index(const unsigned char* data, int index);

/// Read the font's vertical metrics in raw units. Multiply by the scale
/// returned by tt_scale_for_pixel_height to get pixel values.
void tt_vmetrics(void* font, int* ascent, int* descent, int* line_gap);

/// Get the scale factor that converts raw font units to the target
/// pixel height. Used for both x and y in our blitter — non-square
/// pixels are rare on modern displays.
float tt_scale_for_pixel_height(void* font, float pixel_height);

/// Lookup table for codepoint → glyph index. Returns 0 if the
/// codepoint isn't represented (the .notdef glyph).
int tt_find_glyph_index(void* font, int codepoint);

/// Horizontal metrics for a codepoint. `advance` is the pen advance
/// (right-shift after this glyph); `left_side_bearing` is the x-offset
/// from the pen position to the left edge of the glyph.
void tt_codepoint_hmetrics(void* font, int codepoint, int* advance, int* lsb);

/// Kerning adjustment between two consecutive codepoints. Returns 0 if
/// the font has no kerning table for this pair.
int tt_codepoint_kern_advance(void* font, int c1, int c2);

/// Rasterize a codepoint into an 8-bit alpha mask. The returned buffer
/// is malloc'd; caller frees with tt_free_bitmap. `width`/`height` get
/// the bitmap dimensions; `xoff`/`yoff` are the pixel offsets from the
/// pen origin to the top-left of the bitmap.
unsigned char* tt_codepoint_bitmap(
    void* font,
    float scale_x,
    float scale_y,
    int codepoint,
    int* width,
    int* height,
    int* xoff,
    int* yoff);

void tt_free_bitmap(unsigned char* bitmap);

#ifdef __cplusplus
}
#endif

#endif // TEXT_LIB_H
