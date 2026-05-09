#!/usr/bin/env python3
# Procedural sunset-mountains wallpaper generator. Pure-PIL (no numpy) so
# it runs anywhere Pillow is installed. Output: share/sunset.png at 1920x1080.
#
# Layered composition:
#   - Multi-stop sky gradient (zenith → sunset → horizon)
#   - Bright sun with bloom halo via GaussianBlur
#   - Sparse stars in the upper sky
#   - 5 mountain ridges, parallax-shifted, atmospheric perspective
#     (distant ridges tinted toward sky color, closest near-black)
#   - Subtle horizon haze band

import math
import os
import random
from PIL import Image, ImageDraw, ImageFilter

W, H = 1920, 1080
OUT = "share/sunset.png"
os.makedirs("share", exist_ok=True)


def lerp(a, b, t):
    return a + (b - a) * t


def lerp_color(c1, c2, t):
    return tuple(int(round(lerp(a, b, t))) for a, b in zip(c1, c2))


# Multi-stop vertical gradient. Stops are (y_fraction, RGB).
SKY_STOPS = [
    (0.00, (8, 12, 50)),       # zenith — deep indigo
    (0.30, (50, 30, 90)),      # high sky — purple
    (0.55, (140, 60, 100)),    # mid — magenta dusk
    (0.72, (230, 100, 70)),    # sunset orange
    (0.85, (255, 180, 110)),   # horizon gold
    (0.92, (255, 215, 160)),   # haze
    (1.00, (140, 95, 80)),     # base of frame, falls into ground tones
]


def sky_color_at(y_frac: float):
    for i in range(len(SKY_STOPS) - 1):
        p1, c1 = SKY_STOPS[i]
        p2, c2 = SKY_STOPS[i + 1]
        if p1 <= y_frac <= p2:
            t = (y_frac - p1) / max(p2 - p1, 1e-9)
            return lerp_color(c1, c2, t)
    return SKY_STOPS[-1][1]


def render_sky() -> Image.Image:
    img = Image.new("RGB", (W, H))
    draw = ImageDraw.Draw(img)
    for y in range(H):
        draw.line([(0, y), (W, y)], fill=sky_color_at(y / (H - 1)))
    return img


def render_sun(base: Image.Image, sun_x: int, sun_y: int):
    """Bright disc on horizon + bloom halo via GaussianBlur on a separate
    layer, alpha-composited over the sky."""
    halo = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    hd = ImageDraw.Draw(halo)
    # Outer halo: large soft glow
    R = 380
    hd.ellipse((sun_x - R, sun_y - R, sun_x + R, sun_y + R), fill=(255, 200, 130, 90))
    halo = halo.filter(ImageFilter.GaussianBlur(radius=120))

    # Sun core: bright white-yellow disc with smaller blur.
    core = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    cd = ImageDraw.Draw(core)
    r = 75
    cd.ellipse((sun_x - r, sun_y - r, sun_x + r, sun_y + r), fill=(255, 245, 220, 255))
    core = core.filter(ImageFilter.GaussianBlur(radius=8))

    base = base.convert("RGBA")
    base = Image.alpha_composite(base, halo)
    base = Image.alpha_composite(base, core)
    return base


def render_stars(base: Image.Image, count: int = 220):
    """Tiny faint points in the upper sky (above the sunset band) only."""
    rng = random.Random(42)
    layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    upper_h = int(H * 0.45)
    for _ in range(count):
        x = rng.randint(0, W - 1)
        y = rng.randint(0, upper_h)
        b = rng.uniform(0.3, 1.0)
        a = int(160 * b)
        # Two-pixel star with subtle "twinkle" plus
        d.point([(x, y)], fill=(255, 255, 240, a))
        if rng.random() < 0.15:
            d.point([(x - 1, y), (x + 1, y), (x, y - 1), (x, y + 1)],
                    fill=(255, 255, 240, a // 3))
    return Image.alpha_composite(base.convert("RGBA"), layer)


def smooth_noise(width: int, *, seed: int, base_y: float, amp: float, octaves: int = 6, base_freq: float = 1.5) -> list[int]:
    """Multi-octave sine-sum (poor-man's Perlin) for a natural ridge line.
    Returns a list of `width` ints clamped to [0, H-1]."""
    rng = random.Random(seed)
    phases = [rng.uniform(0, 2 * math.pi) for _ in range(octaves)]
    amps = [amp / (1.6 ** i) for i in range(octaves)]
    freqs = [base_freq * (2 ** i) for i in range(octaves)]
    out = []
    for x in range(width):
        h = base_y
        for ph, a, f in zip(phases, amps, freqs):
            h += a * math.sin(2 * math.pi * f * x / width + ph)
        out.append(max(0, min(H - 1, int(h))))
    return out


def render_mountain(base: Image.Image, ridge: list[int], color, blur: float = 0.0):
    """Fill below the ridge line with `color`. Optional blur softens the
    silhouette for distant haze-shrouded peaks."""
    layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    # Polygon: ridge points + bottom-right + bottom-left corners.
    poly = [(0, H)]
    for x in range(W):
        poly.append((x, ridge[x]))
    poly.append((W - 1, H))
    d.polygon(poly, fill=color)
    if blur > 0:
        layer = layer.filter(ImageFilter.GaussianBlur(radius=blur))
    return Image.alpha_composite(base.convert("RGBA"), layer)


def render_horizon_haze(base: Image.Image, y_center: int, height: int, color):
    """Soft horizontal band of low-alpha color at the horizon, fading top
    and bottom."""
    layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    half = height // 2
    for off in range(-half, half):
        # triangular falloff from center
        t = 1.0 - abs(off) / half
        a = int(120 * t)
        y = y_center + off
        if 0 <= y < H:
            d.line([(0, y), (W, y)], fill=(*color, a))
    return Image.alpha_composite(base.convert("RGBA"), layer)


def main():
    img = render_sky()
    print("sky done")

    # Sun on horizon, slightly right of center.
    img = render_sun(img, sun_x=int(W * 0.62), sun_y=int(H * 0.78))
    print("sun done")

    img = render_stars(img)
    print("stars done")

    # Five mountain layers, back to front. Atmospheric perspective: distant
    # ridges are colored toward the sunset-tinted sky (warm purple-pink),
    # closer ones cool toward indigo-black. Each layer's base_y is lower
    # (further down screen) and amplitude bigger (more dramatic ridge).
    mountains = [
        # (seed, base_y_frac, amp_frac, base_freq, octaves, color, blur)
        (1, 0.62, 0.040, 1.0, 5, (140, 100, 130, 255), 4.0),
        (2, 0.70, 0.060, 0.8, 5, (95, 65, 110, 255), 2.0),
        (3, 0.78, 0.080, 0.7, 6, (60, 40, 85, 255), 1.0),
        (4, 0.86, 0.095, 0.6, 6, (28, 20, 50, 255), 0.5),
        (5, 0.94, 0.110, 0.5, 6, (8, 6, 18, 255), 0.0),
    ]
    for seed, by, amp, freq, oct_, color, blur in mountains:
        ridge = smooth_noise(W, seed=seed, base_y=by * H, amp=amp * H,
                             octaves=oct_, base_freq=freq)
        img = render_mountain(img, ridge, color, blur=blur)
    print("mountains done")

    # Horizon haze brings the warm sunset color into the silhouettes —
    # softens the hard transition between sky and back-most ridge.
    img = render_horizon_haze(img, y_center=int(H * 0.78), height=160,
                              color=(255, 180, 130))
    print("haze done")

    img = img.convert("RGB")
    img.save(OUT, "PNG", optimize=True)
    print(f"wrote {OUT} ({W}x{H})")


if __name__ == "__main__":
    main()
