#!/usr/bin/env bash
# Build the loopback integration tests as the current user, then exec the
# resulting binary under sudo. Avoids running `cargo` as root, which would
# chown target/ and break subsequent non-root builds.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "[1/3] Checking required tools…"
for tool in losetup cryptsetup mkfs.ext4 blkid; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "  missing: $tool" >&2
        echo "  install: sudo pacman -S util-linux cryptsetup e2fsprogs" >&2
        exit 1
    fi
done

echo "[2/3] Building test binary…"
cargo test -p ashypass-drives --tests --no-run 2>&1 | tail -5

# Cargo emits the test binary under target/debug/deps/loopback-<hash>.
# Pick the newest one matching the pattern.
BIN="$(find target/debug/deps -maxdepth 1 -type f -executable -name 'loopback-*' \
       ! -name '*.d' ! -name '*.rlib' -printf '%T@ %p\n' \
       | sort -rn | head -1 | cut -d' ' -f2-)"

if [[ -z "${BIN:-}" || ! -x "$BIN" ]]; then
    echo "could not locate compiled test binary in target/debug/deps/" >&2
    exit 1
fi

echo "[3/3] Running under sudo: $BIN"
echo "       (--test-threads=1 to keep loop devices serialised)"
echo
exec sudo "$BIN" --ignored --test-threads=1 --nocapture
