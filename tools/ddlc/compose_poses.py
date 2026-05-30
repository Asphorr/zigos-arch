"""Pre-bake every (char, pose) sprite the converted DDLC scripts reference.

DDLC's Ren'Py LayeredImage composes a sprite at runtime by stacking:

    body-left half + body-right half + head/face overlay

The archive ships the layers as separate PNGs that share a 960x960 canvas
positioned identically. Our VN engine has no compositor (would burn heap
re-decoding multiple PNGs per Show), so we bake the composites offline
and the engine just loads `/share/ddlc/<char>/<pose>.png` directly. When
this script doesn't manage to compose a given pose (missing layer, weird
tag), the engine's per-character `default.png` fallback still keeps the
character on screen.

What it does:

    1. Walk every script-ch*.json under D:/tmp/ddlc_ast/ and collect the
       (char, pose) tuples referenced by Show statements.
    2. For each tuple, run a per-character recipe to pick layer files.
    3. Bottom-up alpha_composite the layers, write the PNG to
       D:/zigos-arch/share/ddlc/<char>/<pose>.png. Skip tuples we already
       baked on a prior run (mtime check).

Conventions discovered while wiring 2026-05-28 (see
[[ddlc-sprite-layered-composition]] memory):

  - Body half files: `<digit>l.png` (cols ~240-480), `<digit>r.png`
    (cols ~480-770), with `<digit>bl`/`<digit>br` blush variants.
  - sayori/monika face overlays: single letters (`a.png`, `b.png`, ...).
  - natsuki head files: `<digit>t.png` (body N head, default expression),
    `<digit>t<face>.png` (body N head with face expression), positioned
    at canvas top.
  - yuri: `0a.png`/`0b.png` is a full body+head SILHOUETTE without
    eye/mouth features; face overlays go on top of it.
  - sayori `3a-d.png` and monika `3a-b.png` are the only flat-composite
    files — use them verbatim when the pose matches.

Usage:

    python tools/ddlc/compose_poses.py
"""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parent))
from recon import rpa_open  # noqa: E402

RPA = Path("D:/IGRABOGDAN/DDLC! 1.1.1/DDLC! 1.1.1/game/images.rpa")
AST_DIR = Path("D:/tmp/ddlc_ast")
OUT = Path("D:/zigos-arch/share/ddlc")

CHARS = ("sayori", "natsuki", "monika", "yuri")

# Sprites display at SPRITE_DST in app/vn.zig; resample to those resolutions
# offline with high-quality LANCZOS so the engine draws 1:1 at runtime. The
# engine's drawPixmapAlphaScaled is Q16 nearest-neighbor — downscaling
# 720->540 on the fly aliased hair strands and outlines into chunky steps.
# Pre-resizing eats the cost once with a much better filter; disk drops too.
#
# The MULTI suffix variant is used by the multi-character draw path (count>1)
# where every sprite renders at 540 regardless of count. Bare `<pose>.png`
# is the solo 720x720 used when only one character is on stage.
SPRITE_RES = 720
SPRITE_RES_MULTI = 540


def enumerate_poses() -> dict[str, set[str]]:
    """Walk every script-ch*.json and collect Show-statement (char, pose)
    tuples. Returns {char: {pose, ...}}."""
    poses: dict[str, set[str]] = {c: set() for c in CHARS}
    for script in sorted(AST_DIR.glob("script-ch*.json")):
        try:
            with script.open("r", encoding="utf-8") as f:
                root = json.load(f)
        except Exception:
            continue
        if not isinstance(root, list) or len(root) < 2:
            continue
        body = root[1]
        if not isinstance(body, list):
            continue
        # body is [Init/Label/...]; descend into Label.block too.
        stack: list = list(body)
        while stack:
            node = stack.pop()
            if not isinstance(node, dict):
                continue
            t = node.get("type")
            if t == "Label":
                blk = node.get("block")
                if isinstance(blk, list):
                    stack.extend(blk)
                continue
            if t != "Show":
                continue
            imspec = node.get("imspec") or []
            if not imspec:
                continue
            head = imspec[0]
            if not isinstance(head, list) or not head:
                continue
            char = head[0] if isinstance(head[0], str) else None
            if char not in poses:
                continue
            # Build the pose tag by concatenating the remaining words —
            # DDLC uses a single trailing word like "4p" or sometimes
            # nothing (bare `show sayori`).
            tag = "".join(w for w in head[1:] if isinstance(w, str))
            poses[char].add(tag)
    return poses


def split_pose(pose: str) -> tuple[str, str]:
    """`4p` -> ('4', 'p'); `2bta` -> ('2', 'bta'); `1` -> ('1', '')."""
    i = 0
    while i < len(pose) and pose[i].isdigit():
        i += 1
    return pose[:i], pose[i:]


def load_archive() -> dict[str, bytes]:
    """Map archive-relative name -> raw PNG/WebP bytes. WebP gets recoded
    to PNG so PIL can blend without WebP support."""
    blobs: dict[str, bytes] = {}
    for name, data in rpa_open(RPA):
        if not name.startswith("images/"):
            continue
        # Recode WebP to PNG so downstream PIL ops stay consistent.
        if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
            im = Image.open(io.BytesIO(data))
            buf = io.BytesIO()
            im.save(buf, format="PNG")
            data = buf.getvalue()
        blobs[name] = data
    return blobs


def open_layer(blobs: dict[str, bytes], char: str, basename: str) -> Image.Image | None:
    path = f"images/{char}/{basename}.png"
    blob = blobs.get(path)
    if blob is None:
        return None
    return Image.open(io.BytesIO(blob)).convert("RGBA")


def recipe(char: str, pose: str, blobs: dict[str, bytes]) -> list[Image.Image] | None:
    """Pick a list of layer Images to alpha_composite bottom-up. Returns
    None when no usable layers were found — caller falls back to
    default.png."""
    # 1) Direct verbatim file (covers sayori 3a-d, monika 3a-b).
    direct = open_layer(blobs, char, pose) if pose else None
    if direct is not None:
        return [direct]

    body, face = split_pose(pose)
    if not body:
        return None

    layers: list[Image.Image] = []

    # 2) Yuri: silhouette layer underneath the body halves. Without it
    # the body halves leave a vertical gap in the middle (yuri's half
    # files don't meet at column 480).
    if char == "yuri":
        # Prefer `0<face>` if it exists (silhouette tinted to expression),
        # else fall back to plain 0a / 0b.
        for sil in [f"0{face}", "0a", "0b"]:
            im = open_layer(blobs, char, sil)
            if im is not None:
                layers.append(im)
                break

    # 3) Body halves — universal across all characters.
    body_added = 0
    for half in (f"{body}l", f"{body}r"):
        im = open_layer(blobs, char, half)
        if im is not None:
            layers.append(im)
            body_added += 1

    # If no body half files exist for the requested digit (e.g.
    # `sayori 4*` — sayori only ships body 1/2/3), bail. Without any
    # body the face overlay would render as a floating head against an
    # empty background. Falling back to default.png at engine load keeps
    # the character whole, even if the expression nuance is lost.
    if body_added == 0 and not (char == "yuri" and layers):
        return None

    # 4) Head / face. Per-character layering convention.
    if char == "natsuki":
        # Natsuki's head includes eyes+mouth; expression letter rides on
        # the head file as a suffix. Try most-specific first.
        head_candidates = [f"{body}t{face}", f"{body}t", "t"]
        for cand in head_candidates:
            im = open_layer(blobs, char, cand)
            if im is not None:
                layers.append(im)
                break
    else:
        # sayori / monika / yuri: face overlay is a single-letter file.
        # Only meaningful when the pose actually has a face suffix.
        if face:
            im = open_layer(blobs, char, face)
            if im is not None:
                layers.append(im)

    if not layers:
        return None
    return layers


def compose(layers: list[Image.Image]) -> Image.Image:
    """Bottom-up alpha_composite at the natural layer size. Returns the
    raw composite — caller applies the per-size LANCZOS resamples."""
    out = layers[0]
    for top in layers[1:]:
        if top.size != out.size:
            top = top.resize(out.size, Image.LANCZOS)
        out = Image.alpha_composite(out, top)
    return out


def bake_one(char: str, pose: str, blobs: dict[str, bytes]) -> str:
    """Return one of: 'baked', 'skipped' (already up-to-date), 'missing'
    (no layers resolvable — engine will fall back to default.png).
    Always writes both the solo (SPRITE_RES) and multi-char
    (SPRITE_RES_MULTI) outputs in one shot. Idempotency uses the multi
    output as the marker because it's the one most likely to be missing
    when re-running after a tooling change."""
    if not pose:
        return "skipped"  # bare `show <char>` — engine uses default.png
    dest_solo = OUT / char / f"{pose}.png"
    dest_multi = OUT / char / f"{pose}@{SPRITE_RES_MULTI}.png"
    if dest_solo.exists() and dest_multi.exists():
        return "skipped"
    layers = recipe(char, pose, blobs)
    if not layers:
        return "missing"
    raw = compose(layers)
    dest_solo.parent.mkdir(parents=True, exist_ok=True)
    if not dest_solo.exists():
        solo = raw if raw.size == (SPRITE_RES, SPRITE_RES) else raw.resize((SPRITE_RES, SPRITE_RES), Image.LANCZOS)
        solo.save(dest_solo, format="PNG")
    if not dest_multi.exists():
        multi = raw.resize((SPRITE_RES_MULTI, SPRITE_RES_MULTI), Image.LANCZOS)
        multi.save(dest_multi, format="PNG")
    return "baked"


def main() -> int:
    print("[compose] loading images.rpa ...")
    blobs = load_archive()
    print(f"[compose] {len(blobs)} archive entries")

    poses = enumerate_poses()
    total = sum(len(s) for s in poses.values())
    print(f"[compose] {total} (char, pose) tuples referenced across script-ch*.json")
    print()

    stats = {"baked": 0, "skipped": 0, "missing": 0}
    missing: list[str] = []
    for char in CHARS:
        for pose in sorted(poses[char]):
            kind = bake_one(char, pose, blobs)
            stats[kind] += 1
            tag = f"{char}/{pose or '<bare>'}"
            if kind == "baked":
                print(f"  + {tag}")
            elif kind == "missing":
                missing.append(tag)

    print()
    print(f"[compose] baked={stats['baked']}  skipped={stats['skipped']}  missing={stats['missing']}")
    if missing:
        print(f"[compose] missing tuples (will fall back to default.png at runtime):")
        for t in missing:
            print(f"    {t}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
