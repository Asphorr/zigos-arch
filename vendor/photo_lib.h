// Clean public-API surface for the photo viewer's stb_image dependency.
// Translate-c reads this small header (instead of the 7000-line stb_image.h)
// and produces tight Zig bindings; the actual implementation lives in
// photo_lib.c which #defines STB_IMAGE_IMPLEMENTATION before #including
// stb_image.h.

#ifndef PHOTO_LIB_H
#define PHOTO_LIB_H

#ifdef __cplusplus
extern "C" {
#endif

unsigned char *stbi_load_from_memory(const unsigned char *buffer, int len,
                                     int *x, int *y, int *channels_in_file,
                                     int desired_channels);

void stbi_image_free(void *retval_from_stbi_load);

const char *stbi_failure_reason(void);

#ifdef __cplusplus
}
#endif

#endif
