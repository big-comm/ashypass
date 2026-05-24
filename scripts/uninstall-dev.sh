#!/usr/bin/env bash
# Reverse of install-dev.sh. Removes only what install-dev.sh wrote; leaves
# the pacman-installed ashypass package untouched.
set -euo pipefail

if [[ "${EUID}" -eq 0 ]]; then
    echo "Don't run this as root — it will sudo where needed." >&2
    exit 1
fi

echo "Removing dev artifacts…"
sudo rm -f /usr/libexec/ashypass/ashypass-drives-helper
sudo rmdir --ignore-fail-on-non-empty /usr/libexec/ashypass 2>/dev/null || true
sudo rm -f /usr/share/polkit-1/actions/com.bigcommunity.ashypass.drives.policy

if pgrep -x polkitd >/dev/null 2>&1; then
    sudo pkill -HUP polkitd || true
fi
echo "Done."
