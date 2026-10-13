#!/usr/bin/env python3
"""Builds the Ashy Pass browser extension from src/ and the two manifests.

Standard library only. Run from anywhere with:
    python3 -I browser-extension/build.py [--out DIR]

Produces (in dist/ by default):
    chrome-dev/                      unpacked, with the development "key"
    firefox-dev/                     unpacked
    ashypass-chrome-<version>.zip    Chrome Web Store upload (no "key", no "is" locale)
    ashypass-firefox-<version>.zip   for AMO signing
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
DEV_KEY_FILE = ROOT / "chrome-dev-key.pub"

# Locales Chrome does not know; the Web Store rejects packages that ship them.
CHROME_UNSUPPORTED_LOCALES = {"is"}

# Fixed timestamp so the zips are reproducible.
ZIP_DATE = (2024, 1, 1, 0, 0, 0)
VERSION_RE = re.compile(r"^\d+(\.\d+){0,3}$")


def read_version() -> str:
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    if not VERSION_RE.match(version) or any(len(p) > 1 and p.startswith("0") for p in version.split(".")):
        raise SystemExit(f"VERSION must look like 1.2.3, got {version!r}")
    return version


def load_manifest(browser: str, version: str) -> dict:
    manifest = json.loads((ROOT / f"manifest.{browser}.json").read_text(encoding="utf-8"))
    if "key" in manifest:
        raise SystemExit(f"manifest.{browser}.json must not contain 'key'; it is added for chrome-dev only")
    manifest["version"] = version
    return manifest


def source_files(skip_locales: set[str]) -> list[Path]:
    files = []
    for path in sorted(SRC.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(SRC)
        if any(part.startswith(".") for part in rel.parts):
            continue
        if rel.parts[0] == "_locales" and len(rel.parts) > 1 and rel.parts[1] in skip_locales:
            continue
        files.append(rel)
    return files


def write_tree(dest: Path, manifest: dict, files: list[Path]) -> None:
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    for rel in files:
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(SRC / rel, target)
    (dest / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def write_zip(dest: Path, manifest: dict, files: list[Path]) -> None:
    dest.unlink(missing_ok=True)

    def add(zf: zipfile.ZipFile, name: str, data: bytes) -> None:
        info = zipfile.ZipInfo(name, date_time=ZIP_DATE)
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o644 << 16
        zf.writestr(info, data)

    with zipfile.ZipFile(dest, "w") as zf:
        add(zf, "manifest.json", (json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))
        for rel in files:
            add(zf, rel.as_posix(), (SRC / rel).read_bytes())


def dev_key() -> str:
    key = DEV_KEY_FILE.read_text(encoding="ascii").strip()
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", key):
        raise SystemExit(f"{DEV_KEY_FILE.name} must hold one base64 line")
    return key


def build(out: Path) -> list[Path]:
    version = read_version()
    out.mkdir(parents=True, exist_ok=True)

    chrome = load_manifest("chrome", version)
    firefox = load_manifest("firefox", version)
    chrome_files = source_files(CHROME_UNSUPPORTED_LOCALES)
    firefox_files = source_files(set())

    chrome_dev = dict(chrome)
    chrome_dev["key"] = dev_key()

    outputs = [
        out / "chrome-dev",
        out / "firefox-dev",
        out / f"ashypass-chrome-{version}.zip",
        out / f"ashypass-firefox-{version}.zip",
    ]
    write_tree(outputs[0], chrome_dev, chrome_files)
    write_tree(outputs[1], firefox, firefox_files)
    write_zip(outputs[2], chrome, chrome_files)
    write_zip(outputs[3], firefox, firefox_files)

    # Last line of defence: the store package must never carry the dev key.
    with zipfile.ZipFile(outputs[2]) as zf:
        packaged = json.loads(zf.read("manifest.json"))
        names = zf.namelist()
    if "key" in packaged or any(n.startswith("_locales/is/") for n in names):
        raise SystemExit("Chrome store package is not clean")
    return outputs


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, default=ROOT / "dist", help="output directory (default: dist/)")
    args = parser.parse_args(argv)
    for path in build(args.out.resolve()):
        print(path)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
