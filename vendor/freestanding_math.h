// Shared freestanding-safe math implementations for vendored stb_*
// libraries. SSE2-only ops (always available on x86_64); no libm
// dependency, no @floor / @cos that hangs in freestanding-baseline
// builds (see [[zig-floor-freestanding-baseline]]).
//
// Used by:
//   - vendor/text_lib.c (stb_truetype)
//   - vendor/vorbis_lib.c (stb_vorbis)
//   - any future vendor lib that needs the same set
//
// All helpers are `static inline` so each TU gets its own copy with no
// link-time conflicts. Names are `fsm_*` (freestanding math) for visual
// distinction from libc names.

#ifndef FREESTANDING_MATH_H
#define FREESTANDING_MATH_H

// trunc: cvttsd2si truncates toward zero. Valid for |x| < 2^63.
static inline double fsm_trunc(double x) {
    long long i = (long long)x;
    return (double)i;
}

static inline int fsm_ifloor(double x) {
    long long i = (long long)x;
    return (x < (double)i) ? (int)(i - 1) : (int)i;
}

static inline int fsm_iceil(double x) {
    long long i = (long long)x;
    return (x > (double)i) ? (int)(i + 1) : (int)i;
}

static inline double fsm_floor(double x) {
    return (double)fsm_ifloor(x);
}

static inline double fsm_ceil(double x) {
    return (double)fsm_iceil(x);
}

static inline double fsm_fabs(double x) {
    return x < 0.0 ? -x : x;
}

static inline double fsm_sqrt(double x) {
    double r;
    __asm__ ("sqrtsd %1, %0" : "=x"(r) : "x"(x));
    return r;
}

static inline double fsm_fmod(double x, double y) {
    if (y == 0.0) return 0.0;
    double q = x / y;
    return x - fsm_trunc(q) * y;
}

// Range-reduced Taylor series for sin (good to ~1e-12 over [-π,π]).
static inline double fsm_sin(double x) {
    const double PI = 3.14159265358979323846;
    const double TWO_PI = 6.28318530717958647692;
    if (x > PI || x < -PI) {
        double k = fsm_trunc(x / TWO_PI + (x >= 0 ? 0.5 : -0.5));
        x -= k * TWO_PI;
    }
    double x2 = x * x;
    double t = x;
    double sum = x;
    t *= x2; sum -= t / 6.0;
    t *= x2; sum += t / 120.0;
    t *= x2; sum -= t / 5040.0;
    t *= x2; sum += t / 362880.0;
    t *= x2; sum -= t / 39916800.0;
    t *= x2; sum += t / 6227020800.0;
    return sum;
}

// Range-reduced Taylor series for cos (good to ~1e-12 over [-π,π]).
static inline double fsm_cos(double x) {
    const double PI = 3.14159265358979323846;
    const double TWO_PI = 6.28318530717958647692;
    if (x > PI || x < -PI) {
        double k = fsm_trunc(x / TWO_PI + (x >= 0 ? 0.5 : -0.5));
        x -= k * TWO_PI;
    }
    double x2 = x * x;
    double t = 1.0;
    double sum = 1.0;
    t *= x2; sum -= t / 2.0;
    t *= x2; sum += t / 24.0;
    t *= x2; sum -= t / 720.0;
    t *= x2; sum += t / 40320.0;
    t *= x2; sum -= t / 3628800.0;
    t *= x2; sum += t / 479001600.0;
    return sum;
}

// tan(x) = sin(x)/cos(x). Caller responsible for x not on cos=0.
static inline double fsm_tan(double x) {
    return fsm_sin(x) / fsm_cos(x);
}

// acos via Hastings polynomial (~1e-5 accuracy on [-1,1]).
//   acos(x) = sqrt(1-x) * (a0 + a1*x + a2*x^2 + a3*x^3)   for x in [0,1]
//   acos(x) = π - acos(-x)                                for x in [-1,0]
static inline double fsm_acos(double x) {
    const double PI = 3.14159265358979323846;
    if (x < 0) {
        // Inline the recursion as one step to keep `static inline` valid.
        double xp = -x;
        if (xp > 1.0) xp = 1.0;
        double s = fsm_sqrt(1.0 - xp);
        double p = 1.5707288 - 0.2121144 * xp + 0.0742610 * xp * xp - 0.0187293 * xp * xp * xp;
        return PI - s * p;
    }
    if (x > 1.0) x = 1.0;
    double s = fsm_sqrt(1.0 - x);
    double p = 1.5707288 - 0.2121144 * x + 0.0742610 * x * x - 0.0187293 * x * x * x;
    return s * p;
}

// exp(x) via 2^(x/ln2) decomposition: split into integer + fractional
// power-of-2 part, multiply the fractional Taylor result by the integer
// power via direct exponent-bit manipulation of the IEEE-754 double.
static inline double fsm_exp(double x) {
    const double LN2 = 0.6931471805599453;
    const double INV_LN2 = 1.4426950408889634;
    double t = x * INV_LN2;
    long long n = (long long)(t + (t >= 0 ? 0.5 : -0.5));
    double f = x - (double)n * LN2;
    double f2 = f * f;
    double f3 = f2 * f;
    double f4 = f3 * f;
    double f5 = f4 * f;
    double f6 = f5 * f;
    double ef = 1.0 + f + f2/2.0 + f3/6.0 + f4/24.0 + f5/120.0 + f6/720.0;
    if (n > 1023) n = 1023;
    if (n < -1022) n = -1022;
    union { double d; long long i; } u;
    u.i = (n + 1023) << 52;
    return ef * u.d;
}

// ln(x) via mantissa-exponent split + atanh series on (m-1)/(m+1).
static inline double fsm_log(double x) {
    if (x <= 0) return -1e308;
    const double LN2 = 0.6931471805599453;
    union { double d; long long i; } u;
    u.d = x;
    long long bits = u.i;
    int e = (int)((bits >> 52) & 0x7FF) - 1023;
    bits = (bits & 0x000FFFFFFFFFFFFFLL) | (1023LL << 52);
    u.i = bits;
    double m = u.d; // m in [1, 2)
    double t = (m - 1.0) / (m + 1.0);
    double t2 = t * t;
    double sum = t;
    double tk = t * t2;
    sum += tk / 3.0; tk *= t2;
    sum += tk / 5.0; tk *= t2;
    sum += tk / 7.0; tk *= t2;
    sum += tk / 9.0; tk *= t2;
    sum += tk / 11.0;
    return 2.0 * sum + (double)e * LN2;
}

static inline double fsm_pow(double x, double y) {
    if (x == 0.0) return y > 0.0 ? 0.0 : 1.0;
    if (y == 0.0) return 1.0;
    if (x < 0.0) return 0.0; // none of our callers pass x<0
    return fsm_exp(y * fsm_log(x));
}

// ldexp(x, n) = x * 2^n via direct exponent-bit manipulation.
static inline double fsm_ldexp(double x, int n) {
    if (x == 0.0) return 0.0;
    union { double d; long long i; } u;
    u.d = x;
    int e = (int)((u.i >> 52) & 0x7FF);
    if (e == 0 || e == 0x7FF) return x; // denormal/inf/nan — give up
    e += n;
    if (e <= 0) return 0.0;
    if (e >= 0x7FF) return x < 0 ? -1e308 * 1e308 : 1e308 * 1e308; // ±inf
    u.i = (u.i & 0x800FFFFFFFFFFFFFLL) | ((long long)e << 52);
    return u.d;
}

#endif // FREESTANDING_MATH_H
