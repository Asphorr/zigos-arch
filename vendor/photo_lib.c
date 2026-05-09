// stb_image implementation TU. Built once per app that wants image decode.
// Defines minimize the dependency surface (no HDR math, no libc stdio,
// only PNG/JPEG/BMP).

#define STB_IMAGE_IMPLEMENTATION
#define STBI_NO_HDR
#define STBI_NO_LINEAR
#define STBI_NO_STDIO
#define STBI_NO_GIF
#define STBI_NO_PSD
#define STBI_NO_PIC
#define STBI_NO_PNM
#define STBI_NO_TGA
#define STBI_ASSERT(x) ((void)0)

// Force-replace libc allocator with our app-side libc (declared as
// `export fn malloc/realloc/free` in app/photo.zig).
extern void *malloc(unsigned long);
extern void *realloc(void *, unsigned long);
extern void  free(void *);
#define STBI_MALLOC(sz)         malloc(sz)
#define STBI_REALLOC(p, sz)     realloc((p), (sz))
#define STBI_FREE(p)            free(p)

#include "stb_image.h"
