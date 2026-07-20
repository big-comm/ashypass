#!/usr/bin/env bash
# Reverse of install-dev.sh. Removes only what install-dev.sh wrote; leaves
# the pacman-installed ashypass package untouched.
set -euo pipefail

if [[ "${EUID}" -eq 0 ]]; then
    echo "Don't run this as root — it will sudo where needed." >&2
    exit 1
fi

echo "Removing dev artifacts…"
remove_unowned() {
    local path=$1
    if pacman -Qo "$path" >/dev/null 2>&1; then
        echo "Keeping package-owned file: $path"
    else
        sudo rm -f "$path"
    fi
}

remove_unowned /usr/libexec/ashypass/ashypass-drives-helper
sudo rmdir --ignore-fail-on-non-empty /usr/libexec/ashypass 2>/dev/null || true
remove_unowned /usr/share/polkit-1/actions/com.bigcommunity.ashypass.drives.policy

if pgrep -x polkitd >/dev/null 2>&1; then
    sudo pkill -HUP polkitd || true
fi
echo "Done."
