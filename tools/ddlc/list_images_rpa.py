#!/usr/bin/env python3
"""List entries in images.rpa, filtered to a substring if provided."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from recon import rpa_open  # type: ignore


def main() -> int:
    rpa = Path(sys.argv[1])
    needle = sys.argv[2] if len(sys.argv) >= 3 else ""
    for name, content in rpa_open(rpa):
        if needle in name:
            print(f"{len(content):>8}  {name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
