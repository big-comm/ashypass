#!/usr/bin/env bash
# Install the freshly-built artifacts to system paths so the polkit policy
# resolves and the helper is callable via pkexec. Doesn't touch pacman —
# leaves the system package intact. Run from the repo root.
#
# Safe to re-run. To uninstall, see scripts/uninstall-dev.sh.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ "${EUID}" -eq 0 ]]; then
    echo "Don't run this as root — it will sudo where needed." >&2
    exit 1
fi

echo "[1/4] Building release artifacts…"
cargo build --release \
    --bin ashypass \
    --bin ashypass-cli \
    --bin ashypass-drives-helper

echo "[2/4] Installing helper binary to /usr/libexec/ashypass/…"
sudo install -d /usr/libexec/ashypass
sudo install -m755 target/release/ashypass-drives-helper \
                   /usr/libexec/ashypass/ashypass-drives-helper

echo "[3/4] Installing polkit policy…"
sudo install -d /usr/share/polkit-1/actions
sudo install -m644 \
    usr/share/polkit-1/actions/com.bigcommunity.ashypass.drives.policy \
    /usr/share/polkit-1/actions/com.bigcommunity.ashypass.drives.policy

echo "[4/4] Reloading polkit…"
# Polkitd watches the actions directory, but a SIGHUP makes it pick up
# changes immediately without waiting for inotify quiescence.
if pgrep -x polkitd >/dev/null 2>&1; then
    sudo pkill -HUP polkitd || true
fi

echo
echo "Done."
echo "  helper:  /usr/libexec/ashypass/ashypass-drives-helper"
echo "  policy:  /usr/share/polkit-1/actions/com.bigcommunity.ashypass.drives.policy"
echo
echo "Now you can run the GUI normally:"
echo "  cargo run -p ashypass-app"
echo
echo "The wizard will trigger ONE polkit prompt per encryption session,"
echo "branded with the 'com.bigcommunity.ashypass.drives.helper' action."
