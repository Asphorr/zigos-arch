#!/usr/bin/env python3
# Generates a couple of test wallpapers in share/ — one matching the
# default 1080p resolution exactly, one at 720p so the user can see the
# letterbox path. Programmatic so we don't ship static binary assets.

import math
import os
from PIL import Image, ImageDraw, ImageFont

OUT_DIR = "share"


def make_wallpaper(width: int, height: int, name: str, palette: list[tuple[int, int, int]]):
    img = Image.new("RGBA", (width, height), (0, 0, 0, 255))
    px = img.load()

    cx_norm = 0.5
    cy_norm = 0.5
    for y in range(height):
        for x in range(width):
            u = x / (width - 1)
            v = y / (height - 1)
            dx, dy = u - cx_norm, v - cy_norm
            r = math.sqrt(dx * dx + dy * dy)
            t = max(0.0, min(1.0, r * 1.4))
            inner = palette[0]
            outer = palette[1]
            rr = int(inner[0] * (1 - t) + outer[0] * t)
            gg = int(inner[1] * (1 - t) + outer[1] * t)
            bb = int(inner[2] * (1 - t) + outer[2] * t)
            # subtle noise so it doesn't look bandy
            n = ((x * 1103515245 + y * 12345) >> 8) & 7
            rr = max(0, min(255, rr + n))
            gg = max(0, min(255, gg + n))
            bb = max(0, min(255, bb + n))
            px[x, y] = (rr, gg, bb, 255)

    draw = ImageDraw.Draw(img)
    try:
        font_size = max(48, height // 14)
        font = ImageFont.truetype(
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", font_size
        )
    except OSError:
        font = ImageFont.load_default()

    label = "ZigOS"
    bbox = draw.textbbox((0, 0), label, font=font)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    tx = (width - tw) // 2
    ty = (height - th) // 2
    draw.text((tx + 3, ty + 3), label, fill=(0, 0, 0, 200), font=font)
    draw.text((tx, ty), label, fill=(255, 255, 255, 255), font=font)

    sub = f"{width}x{height}"
    try:
        sub_font = ImageFont.truetype(
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", max(24, font_size // 3)
        )
    except OSError:
        sub_font = font
    sb = draw.textbbox((0, 0), sub, font=sub_font)
    stw = sb[2] - sb[0]
    draw.text(((width - stw) // 2, ty + th + 6), sub, fill=(255, 255, 255, 220), font=sub_font)

    out = os.path.join(OUT_DIR, name)
    img.save(out, "PNG")
    print(f"wrote {out} ({width}x{height})")


os.makedirs(OUT_DIR, exist_ok=True)
make_wallpaper(1920, 1080, "wp_1080p.png", [(40, 80, 160), (10, 20, 60)])
make_wallpaper(1280, 720, "wp_720p.png", [(80, 40, 140), (20, 10, 60)])
