// External-linkage libm wrappers backed by the static-inline helpers in
// freestanding_math.h. Linked into vendor libs that call sqrt/cos/sin
// etc. via the standard libm names (e.g. stb_vorbis) — these are the
// symbols the linker actually resolves.
//
// Not linked into the stb_truetype static library because that one uses
// STBTT_* macro overrides directly against fsm_* names; pulling these
// symbols in too would risk multiple-definition collisions if a future
// app links both libraries.

#include "freestanding_math.h"

double sqrt(double x)            { return fsm_sqrt(x); }
double sin(double x)             { return fsm_sin(x); }
double cos(double x)             { return fsm_cos(x); }
double tan(double x)             { return fsm_tan(x); }
double acos(double x)            { return fsm_acos(x); }
double fabs(double x)            { return fsm_fabs(x); }
double floor(double x)           { return fsm_floor(x); }
double ceil(double x)            { return fsm_ceil(x); }
double pow(double x, double y)   { return fsm_pow(x, y); }
double exp(double x)             { return fsm_exp(x); }
double log(double x)             { return fsm_log(x); }
double fmod(double x, double y)  { return fsm_fmod(x, y); }
double ldexp(double x, int n)    { return fsm_ldexp(x, n); }

float sqrtf(float x)             { return (float)fsm_sqrt((double)x); }
float sinf(float x)              { return (float)fsm_sin((double)x); }
float cosf(float x)              { return (float)fsm_cos((double)x); }
float fabsf(float x)             { return (float)fsm_fabs((double)x); }
float floorf(float x)            { return (float)fsm_floor((double)x); }
float ceilf(float x)             { return (float)fsm_ceil((double)x); }
