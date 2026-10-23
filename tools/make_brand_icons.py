#!/usr/bin/env python3
"""Builds crates/ashypass-core/assets/brand-icons.json.gz from Simple Icons
(https://simpleicons.org, CC0-1.0): every brand's names, colour and path,
for the icons shown beside verification codes (ashypass_core::brand_icons).

Standard library only. Get the package and pass its folder:

    mkdir -p /tmp/si && cd /tmp/si && npm pack simple-icons@<version>
    tar -xzf simple-icons-*.tgz
    python3 -I tools/make_brand_icons.py /tmp/si/package

Record the version in crates/ashypass-core/assets/BRAND-ICONS.md.
"""

from __future__ import annotations

import gzip
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "crates/ashypass-core/assets/brand-icons.json.gz"
PATH_RE = re.compile(r' d="([^"]+)"')


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    package = Path(sys.argv[1])
    data = json.loads((package / "data/simple-icons.json").read_text(encoding="utf-8"))
    version = json.loads((package / "package.json").read_text(encoding="utf-8"))["version"]
    icons = []
    for entry in data:
        svg = (package / "icons" / f"{entry['slug']}.svg").read_text(encoding="utf-8")
        match = PATH_RE.search(svg)
        if match is None:
            raise SystemExit(f"no path in {entry['slug']}.svg")
        aliases = entry.get("aliases") or {}
        names = [entry["title"], *aliases.get("aka", [])]
        names += [dup["title"] for dup in aliases.get("dup", [])]
        names += list((aliases.get("loc") or {}).values())
        icons.append({"s": entry["slug"], "n": names, "h": entry["hex"], "d": match.group(1)})
    raw = json.dumps({"version": version, "icons": icons}, separators=(",", ":"), ensure_ascii=False)
    # mtime 0: the same input gives the same file.
    OUT.write_bytes(gzip.compress(raw.encode("utf-8"), compresslevel=9, mtime=0))
    print(f"{len(icons)} icons from Simple Icons {version}: {OUT.relative_to(ROOT)} ({OUT.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
