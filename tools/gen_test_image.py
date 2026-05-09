#!/usr/bin/env python3
# Generates a test PNG for photo.elf to display.
# Programmatic so we don't ship a binary asset that drifts.

import sys
import math
from PIL import Image, ImageDraw, ImageFont

W, H = 480, 320
out = sys.argv[1] if len(sys.argv) > 1 else "share/zigos_test.png"

img = Image.new("RGBA", (W, H), (0, 0, 0, 255))
px = img.load()

# Diagonal gradient with a soft sin radial overlay -> something
# visually distinctive that exercises a wide color range.
for y in range(H):
    for x in range(W):
        u = x / (W - 1)
        v = y / (H - 1)
        cx, cy = u - 0.5, v - 0.5
        r = math.sqrt(cx * cx + cy * cy)
        ring = (math.cos(r * 18) + 1) * 0.5

        red = int(255 * (0.15 + 0.85 * u * ring))
        green = int(255 * (0.10 + 0.85 * v * (1 - ring * 0.5)))
        blue = int(255 * (0.30 + 0.55 * (1 - u) * (1 - v)))

        px[x, y] = (
            max(0, min(255, red)),
            max(0, min(255, green)),
            max(0, min(255, blue)),
            255,
        )

draw = ImageDraw.Draw(img)

try:
    font = ImageFont.truetype(
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 28
    )
except OSError:
    font = ImageFont.load_default()

label = "ZigOS Photo"
bbox = draw.textbbox((0, 0), label, font=font)
tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
tx, ty = (W - tw) // 2, (H - th) // 2 - 18

# Drop shadow + main text for readability over the gradient.
draw.text((tx + 2, ty + 2), label, fill=(0, 0, 0, 200), font=font)
draw.text((tx, ty), label, fill=(255, 255, 255, 255), font=font)

# Color-bar sanity strip at the bottom: 8 hues, 16-tone shade ramp.
strip_h = 24
for i in range(W):
    hue = i / (W - 1)
    rr = int(255 * max(0, 1 - abs(hue * 6 - 0)))
    gg = int(255 * max(0, 1 - abs(hue * 6 - 2)))
    bb = int(255 * max(0, 1 - abs(hue * 6 - 4)))
    for y in range(H - strip_h, H):
        px[i, y] = (rr, gg, bb, 255)

img.save(out, "PNG")
print(f"wrote {out} ({W}x{H})")
