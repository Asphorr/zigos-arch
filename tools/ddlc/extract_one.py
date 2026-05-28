#!/usr/bin/env python3
"""Extract one named entry from an RPA-3.0 archive.

Usage:
    python extract_one.py <archive.rpa> <internal/path/file.png> <out.png>
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from recon import rpa_open  # type: ignore


def main() -> int:
    if len(sys.argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    rpa = Path(sys.argv[1])
    want = sys.argv[2]
    out = Path(sys.argv[3])
    for name, content in rpa_open(rpa):
        if name == want:
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(content)
            print(f"wrote {out} ({len(content)} bytes)")
            return 0
    print(f"not found in archive: {want}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
