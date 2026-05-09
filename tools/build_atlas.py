#!/usr/bin/env python3
"""Render a TTF font to a binary alpha atlas for the kernel/apps.

Usage:
    python3 tools/build_atlas.py --font /path/to/Font.ttf --size 16 --out assets/font_16.bin

Output format (little-endian):
    magic        u32   "ATLF" = 0x464C5441
    size_px      u16   nominal size in pixels (== `size` arg)
    baseline     u8    pixels from glyph cell top to baseline
    line_height  u8    advance from one baseline to the next
    glyph_count  u16   number of glyphs (typically 95: ASCII 32..126)
    codept_start u16   first codepoint (typically 32)
    atlas_w      u16   atlas image width
    atlas_h      u16   atlas image height
    pad          u16   reserved, 0
    [glyph_count] x {                         (each glyph entry = 12 bytes)
        ax       i8     horizontal advance
        bx       i8     bearing x (offset from pen)
        by       i8     bearing y (positive = above baseline)
        w        u8     glyph width (pixels in atlas)
        h        u8     glyph height (pixels in atlas)
        _pad     u8
        atlas_x  u16    glyph's top-left x in atlas
        atlas_y  u16    glyph's top-left y in atlas
        _pad2    u16
    }
    atlas[atlas_w*atlas_h]  u8  one alpha byte per pixel, row-major

We pack glyphs into a simple shelf-packed atlas. ASCII fits in <512x32 at 16px
or <512x48 at 24px, so atlas size stays tiny (< 32 KB).
"""

import argparse
import struct
import sys
from PIL import Image, ImageDraw, ImageFont

ATLAS_MAGIC = 0x464C5441  # "ATLF"
HEADER_SIZE = 16
GLYPH_SIZE = 12

CODEPOINT_START = 32   # space
CODEPOINT_END = 127    # exclusive (skip DEL)


def render_glyph(font: ImageFont.FreeTypeFont, ch: str):
    """Rasterize a single glyph to a tight grayscale image.

    Returns (image, bearing_x, bearing_y, advance) where bearing_y is
    measured from the baseline (positive = above baseline).
    """
    mask, offset = font.getmask2(ch, mode="L")
    w, h = mask.size
    if w == 0 or h == 0:
        # Whitespace — empty image, but we still want advance.
        bbox = font.getbbox(ch)
        ax = font.getlength(ch)
        return Image.new("L", (0, 0)), 0, 0, int(round(ax))

    img = Image.frombytes("L", (w, h), bytes(mask))
    bx, by_top = offset                    # offset from pen origin (top-left)
    ax = font.getlength(ch)                # horizontal advance
    # Convert "top of bbox relative to pen origin" -> "bearing_y from baseline".
    # Pillow's offset.y is the y-coord of the bbox top above the pen origin
    # using PIL's screen-coordinates (y grows down). For Pillow ≥ 9 the
    # convention is `offset = (left, top)` where `top` is negative for glyphs
    # rising above the baseline. We don't get the baseline directly from
    # getmask2; for a clean atlas we re-derive it from font.getmetrics().
    return img, bx, by_top, int(round(ax))


def build_atlas(font_path: str, size_px: int) -> bytes:
    font = ImageFont.truetype(font_path, size_px)
    ascent, descent = font.getmetrics()
    line_height = ascent + descent
    if line_height > 255:
        line_height = 255
    if ascent > 255:
        ascent = 255

    # First pass: rasterize each glyph, collect dimensions.
    glyphs = []
    for cp in range(CODEPOINT_START, CODEPOINT_END):
        ch = chr(cp)
        img, bx, by_top, ax = render_glyph(font, ch)
        glyphs.append({
            "cp": cp,
            "img": img,
            "bx": bx,
            "by_top": by_top,    # offset from pen origin (negative = above pen)
            "ax": ax,
            "w": img.size[0],
            "h": img.size[1],
        })

    # Shelf pack: rows of `line_height` height, advance left-to-right.
    pad = 1
    atlas_w = 512
    cur_x = 0
    cur_y = 0
    row_h = 0
    for g in glyphs:
        if g["w"] == 0:
            g["atlas_x"] = 0
            g["atlas_y"] = 0
            continue
        if cur_x + g["w"] + pad > atlas_w:
            cur_x = 0
            cur_y += row_h + pad
            row_h = 0
        g["atlas_x"] = cur_x
        g["atlas_y"] = cur_y
        cur_x += g["w"] + pad
        if g["h"] > row_h:
            row_h = g["h"]
    atlas_h = cur_y + row_h
    if atlas_h == 0:
        atlas_h = 1

    # Compose the atlas image.
    atlas = Image.new("L", (atlas_w, atlas_h), 0)
    for g in glyphs:
        if g["w"] > 0:
            atlas.paste(g["img"], (g["atlas_x"], g["atlas_y"]))

    # Build the binary blob.
    out = bytearray()
    out += struct.pack("<IHBBHHHH",
        ATLAS_MAGIC,
        size_px,
        ascent,             # baseline = ascent (distance from cell top to baseline)
        line_height,
        len(glyphs),
        CODEPOINT_START,
        atlas_w,
        atlas_h,
    )
    assert len(out) == HEADER_SIZE

    for g in glyphs:
        # Pillow's getmask2 offset is cell-top-relative — pen origin is the
        # upper-left corner of the rendered image, NOT the baseline. So
        # by_top IS the row in the cell where the glyph bitmap starts; we
        # store it as-is.
        glyph_top_in_cell = g["by_top"]
        if glyph_top_in_cell < -127:
            glyph_top_in_cell = -127
        if glyph_top_in_cell > 127:
            glyph_top_in_cell = 127

        ax = g["ax"]
        if ax < -127: ax = -127
        if ax > 127: ax = 127
        bx = g["bx"]
        if bx < -127: bx = -127
        if bx > 127: bx = 127

        out += struct.pack("<bbbBBBHH",
            ax,
            bx,
            glyph_top_in_cell,
            g["w"] if g["w"] <= 255 else 255,
            g["h"] if g["h"] <= 255 else 255,
            0,                  # pad
            g["atlas_x"],
            g["atlas_y"],
        )
        # struct.pack with 'H' is 2 bytes — total above is bbbBBB(6) + HH(4) = 10 bytes.
        # We need 12 — pad two more.
        out += b"\x00\x00"
    out += atlas.tobytes()
    return bytes(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--font", required=True)
    ap.add_argument("--size", type=int, required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    blob = build_atlas(args.font, args.size)
    with open(args.out, "wb") as f:
        f.write(blob)
    print(f"[atlas] {args.out}: {len(blob)} bytes ({args.font} @ {args.size}px)", file=sys.stderr)


if __name__ == "__main__":
    main()
