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
# Chrome Web Store guidance for the 128 px icon: the artwork at 96 x 96 with
# 16 px of transparent space around it. Smaller sizes use the whole square.
PADDING = {128: 16}
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
        pad = PADDING.get(size, 0)
        art = size - 2 * pad
        subprocess.run(
            [
                renderer,
                "-w", str(art),
                "-h", str(art),
                "--page-width", str(size),
                "--page-height", str(size),
                "--left", str(pad),
                "--top", str(pad),
                "-o", str(target),
                str(APP_ICON),
            ],
            check=True,
        )
        print(f"wrote {target.relative_to(EXTENSION)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
