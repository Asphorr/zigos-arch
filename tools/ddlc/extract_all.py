#!/usr/bin/env python3
"""Extract every entry from every .rpa archive into a flat directory tree.

WebP-disguised-as-PNG (Ren'Py optimization) gets re-encoded to real PNG
so stb_image can consume it on the ZigOS side. JPGs and audio formats
pass through unchanged.

Usage:
    python extract_all.py <game/ dir> <output/ dir>

Output:
    Same relative-path layout the archives use internally — e.g.,
    `images/bg/club.png` lands at `<output>/images/bg/club.png`.

Idempotent: re-runs overwrite. ~1-2 min for DDLC 1.1.1 on an SSD.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from recon import rpa_open  # type: ignore

# Pillow is host-only; we use it solely to normalise the WebP-disguised-as-PNG
# files Ren'Py ships. ZigOS's stb_image doesn't decode WebP.
from PIL import Image  # type: ignore
import io


def normalise_image(content: bytes, name: str) -> bytes:
    """If `content` looks like WebP (and the filename ends in .png), recode it
    as real PNG so the engine's stb_image decoder will accept it. Otherwise
    return the bytes unchanged."""
    if not name.lower().endswith(".png"):
        return content
    # WebP files start with "RIFF" + 4 bytes size + "WEBP".
    if len(content) >= 12 and content[:4] == b"RIFF" and content[8:12] == b"WEBP":
        img = Image.open(io.BytesIO(content))
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()
    return content


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    game_dir = Path(sys.argv[1])
    out_dir = Path(sys.argv[2])
    out_dir.mkdir(parents=True, exist_ok=True)

    total_entries = 0
    total_bytes = 0
    converted = 0
    for rpa in sorted(game_dir.glob("*.rpa")):
        print(f"# {rpa.name}")
        for name, content in rpa_open(rpa):
            normalised = normalise_image(content, name)
            if normalised is not content:
                converted += 1
            out = out_dir / name
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(normalised)
            total_entries += 1
            total_bytes += len(normalised)
        print(f"  -> entries so far: {total_entries}")

    print(f"# total entries: {total_entries}")
    print(f"# total bytes:   {total_bytes:,}")
    print(f"# webp→png recoded: {converted}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
