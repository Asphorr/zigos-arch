#ifndef _MATH_H
#define _MATH_H

// Q1 uses double-precision math (sqrt/sin/cos/atan2/fabs/floor/ceil/pow/exp/log).
// Doom didn't need any of these; Q1 does. Implementations land in
// app/quake1.zig as C-ABI exports backed by std.math.
double sqrt(double x);
double sin(double x);
double cos(double x);
double tan(double x);
double atan(double x);
double atan2(double y, double x);
double asin(double x);
double acos(double x);
double floor(double x);
double ceil(double x);
double fabs(double x);
double pow(double x, double y);
double exp(double x);
double log(double x);
double fmod(double x, double y);

float sqrtf(float x);
float sinf(float x);
float cosf(float x);
float fabsf(float x);
float floorf(float x);
float ceilf(float x);

#define M_PI    3.14159265358979323846
#define M_PI_2  1.57079632679489661923
#define M_SQRT2 1.41421356237309504880

#define HUGE_VAL (1e300 * 1e300)

#endif
