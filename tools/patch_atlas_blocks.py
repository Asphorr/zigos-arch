#!/usr/bin/env python3
"""Patch an existing font atlas .bin to add block-element glyphs at 0x80..0x8F.

The kernel terminal's font (aa_font, derived from a TTF via build_atlas.py)
only carries ASCII 32..126. The Spleen 8x16 *bitmap* font already remaps the
unicode block elements into single-byte slots 0x80..0x85 for window apps —
this script extends the same convention to the TTF-derived atlases so the
terminal can render them too. Halftone shading + half-blocks let fastfetch
draw a 3D-feeling Z that solid colored spaces alone can't reach.

We don't regenerate the atlas from a TTF (we don't have the original) — we
read the existing .bin, append programmatically-rasterized block elements
to the atlas image below the existing rows, then write a new .bin with the
extra glyph entries. Existing ASCII glyphs are preserved byte-for-byte.

Codepoint map (slot → glyph):
    0x80 █  full block         0x88 ▘  upper-left quarter
    0x81 ░  light shade 25%    0x89 ▝  upper-right quarter
    0x82 ▒  medium shade 50%   0x8A ▖  lower-left quarter
    0x83 ▓  dark shade 75%     0x8B ▗  lower-right quarter
    0x84 ▀  upper half         0x8C ▚  UL + LR quarters
    0x85 ▄  lower half         0x8D ▞  UR + LL quarters
    0x86 ▌  left half          0x8E ▙  UL + LL + LR quarters
    0x87 ▐  right half         0x8F ▟  UR + LL + LR quarters

Usage:
    python3 tools/patch_atlas_blocks.py --in lib/assets/font_mono.bin \\
                                        --out lib/assets/font_mono.bin
"""

import argparse
import struct
import sys
from PIL import Image, ImageDraw

ATLAS_MAGIC = 0x464C5441
HEADER_SIZE = 16
GLYPH_SIZE = 12

BLOCK_CPS = list(range(0x80, 0x90))  # 0x80..0x8F = 16 glyphs


def render_block(cp, cell_w, cell_h):
    """Rasterize one block element into a cell_w × cell_h grayscale bitmap."""
    img = Image.new("L", (cell_w, cell_h), 0)
    draw = ImageDraw.Draw(img)
    hw = cell_w // 2
    hh = cell_h // 2

    if cp == 0x80:
        draw.rectangle([0, 0, cell_w, cell_h], fill=255)
    elif cp == 0x84:
        draw.rectangle([0, 0, cell_w, hh], fill=255)
    elif cp == 0x85:
        draw.rectangle([0, hh, cell_w, cell_h], fill=255)
    elif cp == 0x86:
        draw.rectangle([0, 0, hw, cell_h], fill=255)
    elif cp == 0x87:
        draw.rectangle([hw, 0, cell_w, cell_h], fill=255)
    elif cp == 0x88:
        draw.rectangle([0, 0, hw, hh], fill=255)
    elif cp == 0x89:
        draw.rectangle([hw, 0, cell_w, hh], fill=255)
    elif cp == 0x8A:
        draw.rectangle([0, hh, hw, cell_h], fill=255)
    elif cp == 0x8B:
        draw.rectangle([hw, hh, cell_w, cell_h], fill=255)
    elif cp == 0x8C:
        draw.rectangle([0, 0, hw, hh], fill=255)
        draw.rectangle([hw, hh, cell_w, cell_h], fill=255)
    elif cp == 0x8D:
        draw.rectangle([hw, 0, cell_w, hh], fill=255)
        draw.rectangle([0, hh, hw, cell_h], fill=255)
    elif cp == 0x8E:
        draw.rectangle([0, 0, hw, hh], fill=255)
        draw.rectangle([0, hh, cell_w, cell_h], fill=255)
    elif cp == 0x8F:
        draw.rectangle([hw, 0, cell_w, hh], fill=255)
        draw.rectangle([0, hh, cell_w, cell_h], fill=255)
    elif cp in (0x81, 0x82, 0x83):
        # ░▒▓ — 4x4 ordered Bayer dither at 25/50/75% coverage. Halftone shading.
        bayer = [
            [0, 8, 2, 10],
            [12, 4, 14, 6],
            [3, 11, 1, 9],
            [15, 7, 13, 5],
        ]
        threshold = {0x81: 4, 0x82: 8, 0x83: 12}[cp]
        for y in range(cell_h):
            for x in range(cell_w):
                if bayer[y % 4][x % 4] < threshold:
                    img.putpixel((x, y), 255)

    return img


def patch(in_path, out_path):
    with open(in_path, "rb") as f:
        blob = f.read()

    (magic, size_px, baseline, line_height, glyph_count,
     codept_start, atlas_w, atlas_h) = struct.unpack(
        "<IHBBHHHH", blob[:HEADER_SIZE]
    )
    if magic != ATLAS_MAGIC:
        sys.exit(f"bad magic 0x{magic:08X}")

    # Parse existing glyph entries (preserved verbatim).
    glyphs = []
    off = HEADER_SIZE
    for i in range(glyph_count):
        (ax, bx, by, w, h, _p1, atlas_x, atlas_y, _p2) = struct.unpack(
            "<bbbBBBHHH", blob[off:off + GLYPH_SIZE]
        )
        glyphs.append({
            "cp": codept_start + i,
            "ax": ax, "bx": bx, "by": by,
            "w": w, "h": h,
            "atlas_x": atlas_x, "atlas_y": atlas_y,
        })
        off += GLYPH_SIZE

    pixels_off = HEADER_SIZE + glyph_count * GLYPH_SIZE
    existing_pixels = blob[pixels_off:pixels_off + atlas_w * atlas_h]
    if len(existing_pixels) != atlas_w * atlas_h:
        sys.exit("atlas pixel block truncated")

    # Determine cell dimensions. For monospace fonts every glyph has the same ax;
    # for proportional fonts 'M' is a reasonable proxy for the block-element width.
    cell_w = None
    for g in glyphs:
        if g["cp"] == ord("M"):
            cell_w = g["ax"]
            break
    if cell_w is None or cell_w < 1:
        cell_w = max(1, size_px // 2)
    cell_h = line_height

    last_cp = codept_start + glyph_count - 1
    first_new_cp = last_cp + 1

    # The aa_font lookup is `idx = c - codept_start` — single contiguous range.
    # If there's a gap (e.g. existing atlas ends at 126 and block elements start
    # at 128), insert zero-advance placeholders so the indexing stays valid.
    new_glyphs = []
    cp = first_new_cp
    while cp < BLOCK_CPS[0]:
        new_glyphs.append({
            "cp": cp, "img": None,
            "ax": cell_w, "bx": 0, "by": 0,
            "w": 0, "h": 0,
        })
        cp += 1
    for bcp in BLOCK_CPS:
        img = render_block(bcp, cell_w, cell_h)
        new_glyphs.append({
            "cp": bcp, "img": img,
            "ax": cell_w, "bx": 0, "by": 0,
            "w": cell_w, "h": cell_h,
        })

    # Shelf-pack new glyphs in a fresh row below the existing atlas.
    pad = 1
    new_row_y = atlas_h + pad
    cur_x = 0
    row_h = 0
    for ng in new_glyphs:
        if ng["w"] == 0:
            ng["atlas_x"] = 0
            ng["atlas_y"] = 0
            continue
        if cur_x + ng["w"] + pad > atlas_w:
            new_row_y += row_h + pad
            cur_x = 0
            row_h = 0
        ng["atlas_x"] = cur_x
        ng["atlas_y"] = new_row_y
        cur_x += ng["w"] + pad
        if ng["h"] > row_h:
            row_h = ng["h"]
    new_atlas_h = new_row_y + row_h
    if new_atlas_h > 65535:
        sys.exit("atlas too tall after patch")

    new_atlas = Image.new("L", (atlas_w, new_atlas_h), 0)
    existing_img = Image.frombytes("L", (atlas_w, atlas_h), existing_pixels)
    new_atlas.paste(existing_img, (0, 0))
    for ng in new_glyphs:
        if ng["w"] > 0 and ng["img"] is not None:
            new_atlas.paste(ng["img"], (ng["atlas_x"], ng["atlas_y"]))

    new_glyph_count = glyph_count + len(new_glyphs)
    out = bytearray()
    out += struct.pack(
        "<IHBBHHHH",
        ATLAS_MAGIC, size_px, baseline, line_height,
        new_glyph_count, codept_start, atlas_w, new_atlas_h,
    )
    # Pad slot the original wasn't writing — header is 16 bytes (the format
    # uses HHHH which is 8 bytes; the `_pad` u16 at the tail is captured by
    # the H written here via the assertion that HEADER_SIZE==16. Reproduce
    # the original layout: write the trailing pad u16 as 0.
    # struct.pack returned 16 bytes for "<IHBBHHHH" already (4+2+1+1+2+2+2+2=16).
    assert len(out) == HEADER_SIZE

    def write_glyph(g):
        out.extend(struct.pack(
            "<bbbBBBHH",
            g["ax"], g["bx"], g["by"],
            min(g["w"], 255), min(g["h"], 255),
            0, g["atlas_x"], g["atlas_y"],
        ))
        out.extend(b"\x00\x00")  # trailing _pad u16

    for g in glyphs:
        write_glyph(g)
    for ng in new_glyphs:
        write_glyph(ng)
    out.extend(new_atlas.tobytes())

    with open(out_path, "wb") as f:
        f.write(out)

    print(
        f"[patch] {out_path}: glyphs {glyph_count} → {new_glyph_count}, "
        f"atlas {atlas_w}x{atlas_h} → {atlas_w}x{new_atlas_h}, "
        f"cell {cell_w}x{cell_h}",
        file=sys.stderr,
    )


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="in_path", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    patch(args.in_path, args.out)
