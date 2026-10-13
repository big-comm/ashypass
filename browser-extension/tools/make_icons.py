#!/usr/bin/env python3
"""Renders the extension icons (PNG, 16/32/48/96/128) from the application
icon, usr/share/icons/hicolor/scalable/apps/ashypass.svg, so the extension and
the app always look the same.

Needs `rsvg-convert` (librsvg). Run from anywhere with:
    python3 -I browser-extension/tools/make_icons.py
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

SIZES = (16, 32, 48, 96, 128)
EXTENSION = Path(__file__).resolve().parent.parent
APP_ICON = EXTENSION.parent / "usr/share/icons/hicolor/scalable/apps/ashypass.svg"
OUT = EXTENSION / "src/icons"


def main() -> int:
    renderer = shutil.which("rsvg-convert")
    if renderer is None:
        print("rsvg-convert not found (install librsvg)", file=sys.stderr)
        return 1
    if not APP_ICON.is_file():
        print(f"application icon not found: {APP_ICON}", file=sys.stderr)
        return 1
    OUT.mkdir(parents=True, exist_ok=True)
    for size in SIZES:
        target = OUT / f"icon-{size}.png"
        subprocess.run(
            [renderer, "-w", str(size), "-h", str(size), "-o", str(target), str(APP_ICON)],
            check=True,
        )
        print(f"wrote {target.relative_to(EXTENSION)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
