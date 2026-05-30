"""Stage a minimal DDLC asset set for the VN engine MVP.

Pulls one BG per ch0 scene + one sprite per main character out of
images.rpa and writes them under D:/zigos-arch/share/ddlc/.
WebP frames get recoded to PNG so the existing image.decode path
(stb_image) can read them without WebP support.

Output layout (mirrors DDLC's archive layout so the engine can
resolve `["sayori","3a"]` -> `/share/ddlc/sayori/3a.png`):

    share/ddlc/bg/<scene>.png
    share/ddlc/<char>/<pose>.png
    share/ddlc/<char>/default.png   <- engine fallback

`default.png` is uniformly the fallback the engine reaches for when the
literal pose tag doesn't match a staged file. For chars that have a
pre-composited full-body PNG in the archive (sayori 3a, monika 3a, yuri
0a), we copy that. For natsuki — whose poses are all body+face layered
at runtime with no pre-composite shipped — we alpha-blend a body PNG
with a face overlay PNG on the shared 960x960 canvas. Both layers use
canvas coordinates so the head lands in the right place.

Usage (from anywhere):

    python tools/ddlc/stage_vn_assets.py
"""

from __future__ import annotations

import io
import sys
from pathlib import Path

from PIL import Image

# Reuse the RPA reader that python_sample.py / extract_all.py already set up.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from recon import rpa_open  # noqa: E402

RPA = Path("D:/IGRABOGDAN/DDLC! 1.1.1/DDLC! 1.1.1/game/images.rpa")
# Poem-minigame word list lives in a SEPARATE archive (scripts.rpa), not
# images.rpa. It's a plain CSV: `word,sPoint,nPoint,yPoint` (appeal rank 1-3
# to Sayori/Natsuki/Yuri per word). 228 words. The engine parses it at
# runtime for the poem screen.
SCRIPTS_RPA = Path("D:/IGRABOGDAN/DDLC! 1.1.1/DDLC! 1.1.1/game/scripts.rpa")
OUT = Path("D:/zigos-arch/share/ddlc")

# Match SPRITE_RES in compose_poses.py — every sprite shipped under
# share/ddlc/<char>/ gets LANCZOS-resized to this resolution so the engine
# draws at 1:1 instead of nearest-neighbor downscaling 960->720 at runtime.
# BGs ship verbatim because the archive already has them at 1280x720.
SPRITE_RES = 720
# Engine draws every sprite at 540 when >1 character is on stage
# (multi-char draw path in app/vn.zig:drawSprite). Pre-bake at that exact
# size with LANCZOS so the runtime nearest-neighbor doesn't shred outlines.
SPRITE_RES_MULTI = 540

# ch0 Scenes use _day-suffixed names, but the archive has the base PNG only —
# Ren'Py composes the time-of-day variant. For MVP we map both to the base.
WANT_BG = {
    "images/bg/club.png",
    "images/bg/class.png",
    "images/bg/corridor.png",
    "images/bg/residential.png",
}

# Sprites we want to pull verbatim. Each character ALSO needs body+face
# layer files to bake `default.png` (see DEFAULT_RECIPE) — list all the
# raw archive entries we'll need to read.
WANT_SPRITES = {
    "images/sayori/3a.png",
    "images/sayori/3b.png",
    "images/sayori/3c.png",
    "images/monika/3a.png",
}

# Recipe for the per-character `default.png` the engine falls back to. Each
# entry is either:
#   ("copy", <archive-name>) — dest is a verbatim copy of that PNG, or
#   ("compose", *layers)     — bottom-up alpha-composite of N layer files
#                              that all share the 960x960 canvas.
# DDLC's archive splits each body into a LEFT half (`<n>l.png`, cols ~242-480)
# and a RIGHT half (`<n>r.png`, cols ~480-770), so a full body needs BOTH.
# Yuri's `0a.png` has the body+head shape baked in but no eye/mouth features —
# those live in single-letter face overlays we layer on top.
DEFAULT_RECIPE = {
    "sayori":  ("copy", "images/sayori/3a.png"),
    "monika":  ("copy", "images/monika/3a.png"),
    "yuri":    ("compose", "images/yuri/0a.png", "images/yuri/a.png"),
    "natsuki": ("compose",
                "images/natsuki/1l.png",  # left half of body
                "images/natsuki/1r.png",  # right half of body
                "images/natsuki/1t.png"), # head + face
}

WANT = WANT_BG | WANT_SPRITES | {p for r in DEFAULT_RECIPE.values() for p in r[1:]}

# Main-route chapter scripts the engine chains through (ch0 -> ch3). The
# branching/ending chapters are reachable only via in-script Jump/Call.
SCRIPT_SRC = Path("D:/tmp/ddlc_ast")
SCRIPT_OUT = Path("D:/zigos-arch/share/vn")
SCRIPT_CHAPTERS = (0, 1, 2, 3)


def normalise(content: bytes) -> bytes:
    """WebP -> PNG; otherwise pass-through. stb_image can't decode WebP."""
    if len(content) >= 12 and content[:4] == b"RIFF" and content[8:12] == b"WEBP":
        img = Image.open(io.BytesIO(content))
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()
    return content


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    written = 0
    seen = set()
    # First pass: pull every PNG we'll need (including layer files for
    # composition). Keep a name -> normalised-bytes map so the compose pass
    # doesn't have to re-scan the archive.
    blobs: dict[str, bytes] = {}
    for name, data in rpa_open(RPA):
        if name not in WANT:
            continue
        seen.add(name)
        blobs[name] = normalise(data)

    # BGs ship verbatim — archive has them at the right res already.
    for name in sorted(WANT_BG):
        if name not in blobs:
            continue
        rel = name.removeprefix("images/")
        dest = OUT / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(blobs[name])
        print(f"  + {rel} ({len(blobs[name]):,} B)")
        written += 1

    # Sprites get LANCZOS-resized to SPRITE_RES before writing. Also
    # emit a @540 variant for the multi-char draw path.
    for name in sorted(WANT_SPRITES):
        if name not in blobs:
            continue
        rel = name.removeprefix("images/")
        dest_solo = OUT / rel
        dest_solo.parent.mkdir(parents=True, exist_ok=True)
        im = Image.open(io.BytesIO(blobs[name])).convert("RGBA")
        solo = im if im.size == (SPRITE_RES, SPRITE_RES) else im.resize((SPRITE_RES, SPRITE_RES), Image.LANCZOS)
        solo.save(dest_solo, format="PNG")
        print(f"  + {rel} (resized to {SPRITE_RES}x{SPRITE_RES})")
        written += 1
        multi_rel = rel.replace(".png", f"@{SPRITE_RES_MULTI}.png")
        dest_multi = OUT / multi_rel
        multi = im.resize((SPRITE_RES_MULTI, SPRITE_RES_MULTI), Image.LANCZOS)
        multi.save(dest_multi, format="PNG")
        print(f"  + {multi_rel} (resized to {SPRITE_RES_MULTI}x{SPRITE_RES_MULTI})")
        written += 1

    # Bake `<char>/default.png` per the recipe — either a verbatim copy of
    # a pre-composited PNG or an alpha-blend of layer files. Always
    # LANCZOS-resized to SPRITE_RES.
    for char, recipe in DEFAULT_RECIPE.items():
        dest = OUT / char / "default.png"
        dest.parent.mkdir(parents=True, exist_ok=True)
        kind = recipe[0]
        composed: Image.Image | None = None
        if kind == "copy":
            src = recipe[1]
            if src not in blobs:
                print(f"  ! default.png missing source {src}", file=sys.stderr)
                continue
            composed = Image.open(io.BytesIO(blobs[src])).convert("RGBA")
            shorts = src.split("/")[-1]
            tag = f"copy {shorts}"
        elif kind == "compose":
            layer_names = recipe[1:]
            missing_layer = [n for n in layer_names if n not in blobs]
            if missing_layer:
                print(f"  ! default.png missing layers for {char}: {missing_layer}", file=sys.stderr)
                continue
            layers = [Image.open(io.BytesIO(blobs[n])).convert("RGBA") for n in layer_names]
            if not all(im.size == layers[0].size for im in layers):
                sizes = [im.size for im in layers]
                print(f"  ! {char} layer size mismatch {sizes}", file=sys.stderr)
                continue
            composed = layers[0]
            for top in layers[1:]:
                composed = Image.alpha_composite(composed, top)
            shorts = " + ".join(n.split("/")[-1] for n in layer_names)
            tag = f"compose {shorts}"
        if composed is None:
            continue
        solo = composed if composed.size == (SPRITE_RES, SPRITE_RES) else composed.resize((SPRITE_RES, SPRITE_RES), Image.LANCZOS)
        solo.save(dest, format="PNG")
        glyph = "=" if kind == "copy" else "~"
        print(f"  {glyph} {char}/default.png ({tag})")
        written += 1
        dest_multi = OUT / char / f"default@{SPRITE_RES_MULTI}.png"
        multi = composed.resize((SPRITE_RES_MULTI, SPRITE_RES_MULTI), Image.LANCZOS)
        multi.save(dest_multi, format="PNG")
        print(f"  {glyph} {char}/default@{SPRITE_RES_MULTI}.png ({tag})")
        written += 1

    # Stage main-route chapter scripts so the engine can chain through
    # ch0 -> ch3 after Return-at-top.
    SCRIPT_OUT.mkdir(parents=True, exist_ok=True)
    for n in SCRIPT_CHAPTERS:
        src = SCRIPT_SRC / f"script-ch{n}.json"
        if not src.exists():
            print(f"  ! script-ch{n}.json missing from {SCRIPT_SRC}", file=sys.stderr)
            continue
        dest = SCRIPT_OUT / f"script-ch{n}.json"
        dest.write_bytes(src.read_bytes())
        print(f"  * {dest.relative_to(OUT.parent.parent)} ({src.stat().st_size:,} B)")
        written += 1

    # Stage the poem-minigame word list out of scripts.rpa so the engine's
    # poem screen can load /share/vn/poemwords.txt at runtime.
    poemwords = next((d for n, d in rpa_open(SCRIPTS_RPA) if n == "poemwords.txt"), None)
    if poemwords is not None:
        dest = SCRIPT_OUT / "poemwords.txt"
        dest.write_bytes(poemwords)
        nwords = sum(
            1 for ln in poemwords.decode("utf-8", "replace").splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        )
        print(f"  * {dest.relative_to(OUT.parent.parent)} ({nwords} words)")
        written += 1
    else:
        print(f"  ! poemwords.txt not found in {SCRIPTS_RPA}", file=sys.stderr)

    missing = WANT - seen
    if missing:
        print(f"# missing from archive: {sorted(missing)}", file=sys.stderr)
    print(f"# wrote {written} files -> {OUT}")
    return 0 if not missing else 1


if __name__ == "__main__":
    sys.exit(main())
