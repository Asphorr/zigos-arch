#!/usr/bin/env python3
"""Decode the matrices emitted by qr_dump.zig with OpenCV's QR reader.
True end-to-end validation: a phone scanning the rendered code does exactly this."""
import sys
import numpy as np
import cv2

txt = sys.stdin.read()
cases = []
cur = None
for line in txt.splitlines():
    if line.startswith("CASE "):
        cur = {"text": line[5:], "rows": []}
    elif line == "ENDCASE":
        cases.append(cur); cur = None
    elif cur is not None and line and set(line) <= {"0", "1"}:
        cur["rows"].append(line)

SCALE, QZ = 12, 4
ok = 0
for c in cases:
    rows = c["rows"]
    n = len(rows)
    img = np.full((n + 2 * QZ, n + 2 * QZ), 255, np.uint8)
    for y, row in enumerate(rows):
        for x, ch in enumerate(row):
            if ch == "1":
                img[y + QZ, x + QZ] = 0
    big = np.kron(img, np.ones((SCALE, SCALE), np.uint8))
    data, pts, _ = cv2.QRCodeDetector().detectAndDecode(big)
    match = (data == c["text"])
    ok += match
    status = "OK " if match else "FAIL"
    print(f"[{status}] v{(n-17)//4:>2} {n}x{n}  decoded={'<empty>' if not data else (data[:40]+('...' if len(data)>40 else ''))}")
    if not match and data:
        print(f"        expected={c['text'][:50]}")
print(f"\n{ok}/{len(cases)} round-tripped")
sys.exit(0 if ok == len(cases) else 1)
