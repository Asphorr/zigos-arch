#!/usr/bin/env python3
"""Simulate the ZigOS console half-block QR rendering and decode it.
Each module is drawn ~9px wide x 8px tall (a VGA text cell split top/bottom by the
half-block glyphs), so this checks the real on-screen aspect ratio is scannable."""
import sys
import numpy as np
import cv2

txt = sys.stdin.read()
cases, cur = [], None
for line in txt.splitlines():
    if line.startswith("CASE "):
        cur = {"text": line[5:], "rows": []}
    elif line == "ENDCASE":
        cases.append(cur); cur = None
    elif cur is not None and line and set(line) <= {"0", "1"}:
        cur["rows"].append(line)

WPX, HPX, QZ = 9, 8, 4
ok = 0
for c in cases[:4]:  # production auto-encode cases
    rows = c["rows"]; n = len(rows); tot = n + 2 * QZ
    img = np.full((tot * HPX, tot * WPX), 255, np.uint8)
    for y in range(n):
        for x in range(n):
            if rows[y][x] == "1":
                img[(y + QZ) * HPX:(y + QZ + 1) * HPX, (x + QZ) * WPX:(x + QZ + 1) * WPX] = 0
    d, _, _ = cv2.QRCodeDetector().detectAndDecode(img)
    m = (d == c["text"]); ok += m
    tag = "OK  " if m else "FAIL"
    shown = d[:38] if d else "<empty>"
    print(f"[{tag}] v{(n-17)//4} module=9x8px decoded={shown}")
print(f"{ok}/4 scannable at console half-block geometry")
