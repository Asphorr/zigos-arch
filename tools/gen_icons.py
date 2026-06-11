#!/usr/bin/env python3
"""Generate src/ui/icons.zig — macOS-style app icons for the ZigOS desktop.

Each icon is a 28px rounded-square gradient tile (Big Sur/Sonoma language:
uniform silhouette, ~22% corner radius, vertical gradient, baked soft drop
shadow) with an anti-aliased glyph, rasterized from a handful of SDF shapes
at 3x3 supersampling and baked into 32x32 straight-alpha ARGB arrays that
gfx.blendPixel composites at runtime.

Run:  python tools/gen_icons.py
Writes src/ui/icons.zig and a human-checkable preview PNG (path printed).
"""

import math
import os
import struct
import sys
import zlib

SIZE = 32
SS = 3  # supersamples per axis

# ---------------------------------------------------------------- SDF shapes

def rbox(cx, cy, hw, hh, r):
    def d(px, py):
        qx = abs(px - cx) - (hw - r)
        qy = abs(py - cy) - (hh - r)
        ax = qx if qx > 0 else 0.0
        ay = qy if qy > 0 else 0.0
        return math.hypot(ax, ay) + min(max(qx, qy), 0.0) - r
    return d

def circle(cx, cy, r):
    return lambda px, py: math.hypot(px - cx, py - cy) - r

def ring(cx, cy, r, w):
    return lambda px, py: abs(math.hypot(px - cx, py - cy) - r) - w / 2

def seg(ax, ay, bx, by, w):
    vx, vy = bx - ax, by - ay
    vv = vx * vx + vy * vy
    def d(px, py):
        ux, uy = px - ax, py - ay
        t = (ux * vx + uy * vy) / vv
        t = 0.0 if t < 0 else (1.0 if t > 1 else t)
        return math.hypot(ux - t * vx, uy - t * vy) - w / 2
    return d

def polyline(pts, w):
    segs = [seg(pts[i][0], pts[i][1], pts[i + 1][0], pts[i + 1][1], w)
            for i in range(len(pts) - 1)]
    return union(*segs)

def poly(pts):
    n = len(pts)
    def d(px, py):
        dmin = 1e18
        s = 1.0
        j = n - 1
        for i in range(n):
            bx, by = pts[i]
            ax, ay = pts[j]
            ex, ey = ax - bx, ay - by
            wx, wy = px - bx, py - by
            t = (wx * ex + wy * ey) / (ex * ex + ey * ey)
            t = 0.0 if t < 0 else (1.0 if t > 1 else t)
            dx, dy = wx - ex * t, wy - ey * t
            dd = dx * dx + dy * dy
            if dd < dmin:
                dmin = dd
            c1 = py >= by
            c2 = py < ay
            c3 = ex * wy > ey * wx
            if (c1 and c2 and c3) or (not c1 and not c2 and not c3):
                s = -s
            j = i
        return s * math.sqrt(dmin)
    return d

def ellipse(cx, cy, rx, ry, rot=0.0):
    cr, sr = math.cos(-rot), math.sin(-rot)
    k = min(rx, ry)
    def d(px, py):
        ux, uy = px - cx, py - cy
        qx = ux * cr - uy * sr
        qy = ux * sr + uy * cr
        return (math.hypot(qx / rx, qy / ry) - 1.0) * k
    return d

def union(*ds):
    return lambda px, py: min(dd(px, py) for dd in ds)

def sub(a, b):
    return lambda px, py: max(a(px, py), -b(px, py))

def inter(a, b):
    return lambda px, py: max(a(px, py), b(px, py))

def rotated(d0, cx, cy, ang):
    """Rotate a shape by `ang` around (cx, cy)."""
    cr, sr = math.cos(-ang), math.sin(-ang)
    def d(px, py):
        ux, uy = px - cx, py - cy
        return d0(cx + ux * cr - uy * sr, cy + ux * sr + uy * cr)
    return d

# ---------------------------------------------------------------- compositing

def C(hexstr, a=1.0):
    h = hexstr.lstrip('#')
    return (int(h[0:2], 16) / 255.0, int(h[2:4], 16) / 255.0,
            int(h[4:6], 16) / 255.0, a)

class Layer:
    def __init__(self, sdf, color, soft=None):
        self.sdf = sdf
        self.color = color          # (r,g,b,a) or callable(x, y) -> tuple
        self.soft = soft            # None = 1px AA edge; s = soft falloff px

    def coverage(self, px, py):
        d = self.sdf(px, py)
        if self.soft is None:
            c = 0.5 - d
            return 0.0 if c < 0 else (1.0 if c > 1 else c)
        if d <= 0:
            return 1.0
        c = 1.0 - d / self.soft
        return c * c if c > 0 else 0.0

    def color_at(self, x, y):
        return self.color(x, y) if callable(self.color) else self.color

def vgrad(top, bot, y0, y1):
    def f(_x, y):
        t = (y - y0) / (y1 - y0)
        t = 0.0 if t < 0 else (1.0 if t > 1 else t)
        return tuple(top[i] + (bot[i] - top[i]) * t for i in range(4))
    return f

def over(dst, src):
    dr, dg, db, da = dst
    sr, sg, sb, sa = src
    oa = sa + da * (1 - sa)
    if oa <= 1e-6:
        return (0.0, 0.0, 0.0, 0.0)
    return ((sr * sa + dr * da * (1 - sa)) / oa,
            (sg * sa + dg * da * (1 - sa)) / oa,
            (sb * sa + db * da * (1 - sa)) / oa, oa)

def render(layers):
    img = [[(0.0, 0.0, 0.0, 0.0)] * SIZE for _ in range(SIZE)]
    inv = 1.0 / (SS * SS)
    offs = [(sx + 0.5) / SS for sx in range(SS)]
    for y in range(SIZE):
        for x in range(SIZE):
            dst = (0.0, 0.0, 0.0, 0.0)
            for L in layers:
                cov = 0.0
                for oy in offs:
                    for ox in offs:
                        cov += L.coverage(x + ox, y + oy)
                cov *= inv
                if cov <= 0.0:
                    continue
                r, g, b, a = L.color_at(x + 0.5, y + 0.5)
                dst = over(dst, (r, g, b, a * cov))
            img[y][x] = dst
    return img

# ---------------------------------------------------------------- tile frame

TCX, TCY = 16.0, 15.2     # tile centre (slightly high: room for the shadow)
THW, THH = 13.6, 13.6     # half extents -> 27.2px tile in the 32px cell
TR = 6.2                  # corner radius ~= 22.8% (macOS squircle ratio)
TILE = rbox(TCX, TCY, THW, THH, TR)

def tile_icon(top_hex, bot_hex, glyphs):
    """Shadow + gradient tile + top highlight + tile-clipped glyph layers."""
    layers = [
        Layer(rbox(TCX, TCY + 1.5, THW - 0.6, THH - 0.4, TR), (0, 0, 0, 0.40), soft=2.4),
        Layer(TILE, vgrad(C(top_hex), C(bot_hex), TCY - THH, TCY + THH)),
        Layer(seg(TCX - THW + TR, TCY - THH + 1.0,
                  TCX + THW - TR, TCY - THH + 1.0, 1.0), (1, 1, 1, 0.16)),
    ]
    for L in glyphs:
        L.sdf = inter(L.sdf, TILE)
        layers.append(L)
    return layers

W = (1.0, 1.0, 1.0, 1.0)  # white glyph default

# ---------------------------------------------------------------- the icons

def icon_terminal():
    g = [
        Layer(polyline([(10.0, 10.6), (14.8, 15.2), (10.0, 19.8)], 1.8), W),
        Layer(seg(17.0, 19.9, 23.0, 19.9, 1.8), W),
    ]
    return tile_icon('#34343C', '#17171C', g)

def icon_folder():
    g = [
        Layer(union(rbox(11.8, 11.6, 3.2, 1.8, 1.2),
                    rbox(16.0, 17.0, 7.4, 5.2, 1.6)), C('#3F9BFF')),
        Layer(rbox(16.0, 18.4, 7.4, 3.8, 1.6), C('#6CB5FF')),
    ]
    return tile_icon('#FBFCFE', '#E3E7EE', g)

def icon_web():
    # Safari: white dial ring + two-tone needle (red north, white south),
    # deliberately shorter than the ring so it can't read as a "no entry"
    # slash. Needle axis SW->NE through the centre; waist is perpendicular.
    a = (12.4, 19.0)   # south tip
    b = (19.6, 11.8)   # north tip
    w1 = (17.0, 16.4)  # waist
    w2 = (15.0, 14.4)
    g = [
        Layer(ring(16.0, 15.4, 7.4, 1.4), W),
        Layer(poly([b, w2, w1]), C('#FF5147')),
        Layer(poly([a, w1, w2]), W),
    ]
    return tile_icon('#47ABFF', '#0A60D6', g)

def icon_paint():
    g = [
        Layer(seg(22.6, 7.4, 18.8, 11.6, 2.1), C('#E2A55E')),
        Layer(seg(18.6, 11.8, 16.6, 14.0, 2.4), C('#C9CDD6')),
        # bristle tip: converges to a point at the SW end
        Layer(poly([(17.4, 13.0), (18.6, 14.4), (11.4, 19.4)]), C('#2D8CFF')),
        # curved paint swoosh under the brush
        Layer(polyline([(8.8, 22.6), (11.8, 23.9), (15.6, 23.5)], 1.8),
              C('#2D8CFF', 0.92)),
    ]
    return tile_icon('#FBFCFE', '#E3E7EE', g)

def icon_calc():
    g = [Layer(rbox(16.0, 10.4, 6.4, 1.7, 1.0), C('#ECECF2', 0.95))]
    for yi, gy in enumerate((15.2, 18.8, 22.4)):
        for xi, gx in enumerate((11.2, 16.0, 20.8)):
            col = C('#FF9F0A') if xi == 2 else C('#ECECF2')
            g.append(Layer(circle(gx, gy, 1.55), col))
    return tile_icon('#3C3C44', '#1E1E24', g)

def icon_settings():
    cx, cy = 16.0, 15.4
    body = ring(cx, cy, 4.9, 3.0)
    teeth = [rotated(rbox(cx, cy - 7.0, 1.3, 1.7, 0.6), cx, cy,
                     k * math.pi / 4) for k in range(8)]
    gear = sub(union(body, *teeth), circle(cx, cy, 2.1))
    return tile_icon('#AEB4BE', '#6E747F', [Layer(gear, W)])

def icon_monitor():
    pts = [(7.8, 16.4), (11.2, 16.4), (13.2, 11.0), (16.2, 21.8),
           (18.8, 13.0), (20.6, 16.4), (24.2, 16.4)]
    return tile_icon('#FBFCFE', '#E3E7EE',
                     [Layer(polyline(pts, 1.8), C('#0A84FF'))])

def icon_editor():
    grey = C('#B7BCC6')
    g = [
        Layer(seg(9.2, 10.8, 16.2, 10.8, 1.3), grey),
        Layer(seg(9.2, 14.2, 22.8, 14.2, 1.3), grey),
        Layer(seg(9.2, 17.6, 22.8, 17.6, 1.3), grey),
        Layer(seg(9.2, 21.0, 18.4, 21.0, 1.3), grey),
        # pencil: orange body NE->SW, wood + graphite tip
        Layer(seg(24.4, 6.6, 20.0, 11.0, 2.5), C('#FF9F0A')),
        Layer(poly([(19.2, 10.0), (21.0, 11.8), (16.6, 14.4)]), C('#E8C49A')),
        Layer(poly([(17.7, 13.0), (18.2, 13.9), (16.6, 14.4)]), C('#54565E')),
    ]
    return tile_icon('#FBFCFE', '#E3E7EE', g)

def icon_photo():
    cx, cy = 16.0, 15.4
    hues = ['#F5483D', '#FF9500', '#FFCC00', '#34C759',
            '#00C7BE', '#0A84FF', '#5E5CE6', '#BF5AF2']
    g = []
    for k, h in enumerate(hues):
        a = k * math.pi / 4
        px = cx + 4.4 * math.sin(a)
        py = cy - 4.4 * math.cos(a)
        g.append(Layer(ellipse(px, py, 2.0, 4.3, a), C(h, 0.85)))
    return tile_icon('#FBFCFE', '#E3E7EE', g)

def icon_wallpaper():
    g = [
        Layer(circle(21.6, 9.8, 2.3), C('#FFFFFF', 0.95)),
        Layer(poly([(4.0, 29.0), (13.0, 13.8), (21.0, 29.0)]), C('#FFFFFF', 0.78)),
        Layer(poly([(13.0, 29.0), (20.0, 17.2), (28.5, 29.0)]), W),
    ]
    return tile_icon('#54B9F2', '#176BC4', g)

def icon_sigil():
    z = C('#F7A41D')
    g = [
        Layer(rbox(16.0, 10.6, 5.6, 1.4, 0.5), z),
        Layer(rbox(16.0, 20.2, 5.6, 1.4, 0.5), z),
        Layer(seg(20.2, 10.8, 11.8, 20.0, 2.5), z),
    ]
    return tile_icon('#22222C', '#101016', g)

def icon_tg():
    plane = poly([(8.4, 16.2), (24.2, 9.0), (20.2, 23.6), (15.4, 19.2)])
    return tile_icon('#45BCEC', '#1786C0', [Layer(plane, W)])

def icon_doom():
    cx, cy = 16.0, 15.4
    g = [
        Layer(ring(cx, cy, 5.0, 1.5), W),
        Layer(seg(cx, cy - 7.4, cx, cy - 3.2, 1.5), W),
        Layer(seg(cx, cy + 3.2, cx, cy + 7.4, 1.5), W),
        Layer(seg(cx - 7.4, cy, cx - 3.2, cy, 1.5), W),
        Layer(seg(cx + 3.2, cy, cx + 7.4, cy, 1.5), W),
        Layer(circle(cx, cy, 1.15), W),
    ]
    return tile_icon('#97312B', '#420E0B', g)

def icon_quake():
    # The Quake nail: thin ring with a long spike driven down through it,
    # tapering to a point well below the ring.
    g = [
        Layer(ring(16.0, 12.0, 5.4, 1.5), W),
        Layer(poly([(14.6, 8.4), (17.4, 8.4), (16.0, 27.4)]), W),
    ]
    return tile_icon('#AC7339', '#52280E', g)

def icon_fastfetch():
    g = [
        Layer(polyline([(9.6, 10.2), (12.6, 13.0), (9.6, 15.8)], 1.5), W),
        Layer(seg(15.2, 11.2, 22.6, 11.2, 1.4), C('#E6E8EE', 0.9)),
        Layer(seg(15.2, 14.6, 20.4, 14.6, 1.4), C('#E6E8EE', 0.9)),
    ]
    swatches = ['#F5483D', '#FF9F0A', '#FFD60A', '#34C759', '#0A84FF', '#BF5AF2']
    for k, h in enumerate(swatches):
        g.append(Layer(rbox(9.6 + k * 2.55, 21.6, 0.95, 0.95, 0.35), C(h)))
    return tile_icon('#2E3440', '#171C26', g)

ICONS = [
    ('terminal',  icon_terminal),
    ('folder',    icon_folder),
    ('globe',     icon_web),
    ('paint',     icon_paint),
    ('calc',      icon_calc),
    ('settings',  icon_settings),
    ('monitor',   icon_monitor),
    ('editor',    icon_editor),
    ('photo',     icon_photo),
    ('wallpaper', icon_wallpaper),
    ('sigil',     icon_sigil),
    ('tg',        icon_tg),
    ('doom',      icon_doom),
    ('quake',     icon_quake),
    ('fastfetch', icon_fastfetch),
]

# ---------------------------------------------------------------- PNG preview

def write_png(path, w, h, pix):
    """pix: list of rows, each row list of (r,g,b) 0-255 tuples."""
    raw = b''.join(
        b'\x00' + b''.join(bytes((p[0], p[1], p[2])) for p in row)
        for row in pix)
    def chunk(t, d):
        return struct.pack('>I', len(d)) + t + d + struct.pack('>I', zlib.crc32(t + d))
    ihdr = struct.pack('>IIBBBBB', w, h, 8, 2, 0, 0, 0)
    with open(path, 'wb') as f:
        f.write(b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', ihdr)
                + chunk(b'IDAT', zlib.compress(raw, 9)) + chunk(b'IEND', b''))

def compose_on(img, bg):
    out = []
    for row in img:
        orow = []
        for (r, g, b, a) in row:
            orow.append((int(round((r * a + bg[0] * (1 - a)) * 255)),
                         int(round((g * a + bg[1] * (1 - a)) * 255)),
                         int(round((b * a + bg[2] * (1 - a)) * 255))))
        out.append(orow)
    return out

def preview(rendered, path):
    cols = 8
    rows_n = (len(rendered) + cols - 1) // cols
    scale = 6
    pad = 8
    bands = [C('#0E1525')[:3], C('#ECEDF0')[:3]]
    cell = SIZE * scale + pad
    bw = cols * cell + pad
    band_h = rows_n * cell + pad
    strip_h = SIZE + 2 * pad
    H = band_h * 2 + strip_h
    pix = [[(0, 0, 0)] * bw for _ in range(H)]
    for bi, bg in enumerate(bands):
        base_y = bi * band_h
        bgi = tuple(int(c * 255) for c in bg)
        for y in range(band_h):
            for x in range(bw):
                pix[base_y + y][x] = bgi
        for idx, (_n, img) in enumerate(rendered):
            flat = compose_on(img, bg)
            gx = pad + (idx % cols) * cell
            gy = base_y + pad + (idx // cols) * cell
            for y in range(SIZE * scale):
                row = pix[gy + y]
                src = flat[y // scale]
                for x in range(SIZE * scale):
                    row[gx + x] = src[x // scale]
    # actual-size strip on the dark bg
    bg = bands[0]
    bgi = tuple(int(c * 255) for c in bg)
    for y in range(strip_h):
        for x in range(bw):
            pix[band_h * 2 + y][x] = bgi
    for idx, (_n, img) in enumerate(rendered):
        flat = compose_on(img, bg)
        gx = pad + idx * (SIZE + 6)
        gy = band_h * 2 + pad
        for y in range(SIZE):
            for x in range(SIZE):
                pix[gy + y][gx + x] = flat[y][x]
    write_png(path, bw, H, pix)

# ---------------------------------------------------------------- Zig emitter

HEADER = '''\
// GENERATED FILE - do not edit by hand. Regenerate with:
//   python tools/gen_icons.py
//
// macOS-style app icons for the dock / desktop shortcuts: a uniform 27px
// rounded-square gradient tile (Big Sur/Sonoma language) with a baked soft
// drop shadow and an anti-aliased glyph, stored as 32x32 straight-alpha
// ARGB (0xAARRGGBB). gfx.drawIcon32 composites them with gfx.blendPixel,
// so they sit correctly on any background (glass dock, wallpaper, drag
// ghosts). Authored as SDF shape programs in the generator; tweak there.

const std = @import("std");

pub const SIZE: u32 = 32;
pub const Icon = [SIZE][SIZE]u32;

'''

FOOTER = '''\
/// The original hand-authored 16x16 pixel-art set, preserved for a future
/// Settings appearance toggle (drawn via gfx.drawIconClassic32).
pub const classic = @import("icons_classic.zig");

/// Old name kept for callers that predate the redesign: the cog and the
/// sliders tile collapsed into one Settings icon.
pub const gear = settings;

const Entry = struct { prefix: []const u8, icon: *const Icon };

// Longest-prefix-first where prefixes overlap ("telegram" before "tg" is
// not needed since both map to tg, but keep the habit).
const title_map = [_]Entry{
    .{ .prefix = "term", .icon = &terminal },
    .{ .prefix = "pain", .icon = &paint },
    .{ .prefix = "calc", .icon = &calc },
    .{ .prefix = "sett", .icon = &settings },
    .{ .prefix = "file", .icon = &folder },
    .{ .prefix = "sys", .icon = &monitor },
    .{ .prefix = "edit", .icon = &editor },
    .{ .prefix = "doom", .icon = &doom },
    .{ .prefix = "quake", .icon = &quake },
    .{ .prefix = "photo", .icon = &photo },
    .{ .prefix = "sigil", .icon = &sigil },
    .{ .prefix = "telegram", .icon = &tg },
    .{ .prefix = "tg", .icon = &tg },
    .{ .prefix = "fastfetch", .icon = &fastfetch },
    .{ .prefix = "wallpaper", .icon = &wallpaper },
    .{ .prefix = "web", .icon = &globe },
    .{ .prefix = "gui", .icon = &paint },
};

pub fn iconForTitle(title: []const u8) ?*const Icon {
    for (&title_map) |e| {
        if (std.ascii.startsWithIgnoreCase(title, e.prefix)) return e.icon;
    }
    return null;
}
'''

def to_argb(img):
    out = []
    for row in img:
        orow = []
        for (r, g, b, a) in row:
            ai = int(round(a * 255))
            if ai == 0:
                orow.append(0)
                continue
            orow.append((ai << 24) | (int(round(r * 255)) << 16)
                        | (int(round(g * 255)) << 8) | int(round(b * 255)))
        out.append(orow)
    return out

def emit_zig(rendered, path):
    parts = [HEADER]
    for name, img in rendered:
        argb = to_argb(img)
        parts.append(f'pub const {name}: Icon = .{{\n')
        for row in argb:
            vals = ', '.join(f'0x{v:08X}' for v in row)
            parts.append(f'    .{{ {vals} }},\n')
        parts.append('};\n\n')
    parts.append(FOOTER)
    with open(path, 'w', newline='\n') as f:
        f.write(''.join(parts))

# ---------------------------------------------------------------- main

def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    rendered = [(name, render(fn())) for name, fn in ICONS]

    preview_path = os.environ.get('ICONS_PREVIEW',
                                  os.path.join(os.environ.get('TEMP', '/tmp'),
                                               'zigos_icons_preview.png'))
    preview(rendered, preview_path)
    print(f'preview: {preview_path}')

    if '--preview-only' not in sys.argv:
        out = os.path.join(root, 'src', 'ui', 'icons.zig')
        emit_zig(rendered, out)
        print(f'wrote:   {out}')

if __name__ == '__main__':
    main()
