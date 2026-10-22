#!/usr/bin/env bash
# End-to-end test of the browser extension in real browsers, with the real
# native host and a throwaway vault. Everything lives in a temporary folder:
# the vault, the browser profiles and the native host registrations (Firefox
# runs with a temporary HOME); the real vault, keyring and browser profiles
# are never touched.
#
#   browser-extension/tests/e2e/run.sh [chromium|firefox|all]
#
# Needs Node.js and network access the first time (Playwright and its
# Chromium go to $ASHYPASS_E2E_CACHE, /tmp/ashypass-e2e by default), and a
# Firefox for the Firefox part.
set -euo pipefail
which=${1:-all}
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
cache=${ASHYPASS_E2E_CACHE:-/tmp/ashypass-e2e}
root=$(mktemp -d /tmp/ashypass-e2e-run.XXXXXX)
trap 'rm -rf "$root"' EXIT

echo "[1/4] Building the native host, the test vault tool and the extension…"
cargo build -q --manifest-path "$repo/Cargo.toml" -p ashypass-native-host --bin ashypass-native-host --example e2e_vault
python3 -I "$repo/browser-extension/build.py" --out "$root/ext" >/dev/null

# The host and the vault tool see only the temporary folders.
isolated=(env -u GNOME_KEYRING_CONTROL DBUS_SESSION_BUS_ADDRESS=unix:path=/nonexistent
  XDG_RUNTIME_DIR="$root/run" XDG_CONFIG_HOME="$root/config" XDG_DATA_HOME="$root/data")
mkdir -p "$root/run" && chmod 700 "$root/run"
cat >"$root/host.sh" <<EOF
#!/bin/sh
exec ${isolated[@]@Q} "$repo/target/debug/ashypass-native-host" "\$@"
EOF
chmod +x "$root/host.sh"
host_manifest() { # <allowed key> <allowed value>
  printf '{"name":"com.bigcommunity.ashypass","description":"Ashy Pass (test)","path":"%s","type":"stdio","%s":["%s"]}\n' \
    "$root/host.sh" "$1" "$2"
}

echo "[2/4] Test page and vault…"
node -e '
const http = require("node:http");
const s = http.createServer(); s.listen(0, "127.0.0.1", () => { console.log(s.address().port); s.close(); });
' >"$root/port"
port=$(cat "$root/port")
"${isolated[@]}" "$repo/target/debug/examples/e2e_vault" "http://127.0.0.1:$port"

echo "[3/4] Test tools…"
if [ ! -d "$cache/node/node_modules/playwright-core" ]; then
  mkdir -p "$cache/node"
  (cd "$cache/node" && npm init -y >/dev/null && npm i -s playwright-core@latest >/dev/null)
fi
export NODE_PATH="$cache/node/node_modules" PLAYWRIGHT_BROWSERS_PATH="$cache/browsers"
cp "$here"/*.mjs "$cache/node/"

status=0
echo "[4/4] Browsers…"
if [ "$which" = chromium ] || [ "$which" = all ]; then
  (cd "$cache/node" && npx -y playwright-core install chromium >/dev/null)
  mkdir -p "$root/chromium/NativeMessagingHosts"
  host_manifest allowed_origins "chrome-extension://opelfkfheadglgamfephkfejfpcnlbck/" \
    >"$root/chromium/NativeMessagingHosts/com.bigcommunity.ashypass.json"
  (cd "$cache/node" && node chromium.mjs "$root/ext/chrome-dev" "$root/chromium" "$port") || status=1
fi
if [ "$which" = firefox ] || [ "$which" = all ]; then
  mkdir -p "$root/home/.mozilla/native-messaging-hosts"
  host_manifest allowed_extensions "ashypass@big-comm.github.io" \
    >"$root/home/.mozilla/native-messaging-hosts/com.bigcommunity.ashypass.json"
  (cd "$cache/node" && HOME="$root/home" node firefox.mjs "$root/ext/firefox-dev" "$root/firefox" "$port") || status=1
fi
exit $status
