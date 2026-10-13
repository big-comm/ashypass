# Ashy Pass browser extension

The browser side of [Ashy Pass](https://github.com/big-comm/ashypass), the
GNOME password manager for Linux. It runs in Chrome, Brave, Chromium, Edge,
Vivaldi and Firefox (Manifest V3).

The extension is deliberately thin: it **stores no secrets** and keeps no
vault data. Each time you click *Fill*, *Copy* or *Generate*, it asks the
Ashy Pass desktop app and forgets the answer once it has been used.

## How it talks to the app

The background script opens one
[native messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging)
port to `com.bigcommunity.ashypass`. The browser starts the
`ashypass-native-host` program installed by the Ashy Pass package. That program
opens the vault, using the system keyring or the master password you type in
the popup, and answers JSON requests. [PROTOCOL.md](PROTOCOL.md) describes the
requests and errors.

```
popup ──runtime.sendMessage──▶ background ──connectNative port──▶ ashypass-native-host ──▶ vault
```

To link a browser, open Ashy Pass → Settings → Browser, turn the extension on
and connect your browser. This installs the host manifest that lists the
extension ids below.

## Layout

| Path | What it is |
|------|------------|
| `src/background.js` | Native port, `rid` bookkeeping, popup message API, filling |
| `src/lib/helpers.js` | Pure helpers (URL handling, request tracker, …), unit-tested |
| `src/lib/fill.js` | `fillCredentials`, the function injected into the page |
| `src/popup/` | Popup UI (HTML/CSS/JS, no frameworks) |
| `src/_locales/` | Translations (29 languages) |
| `src/icons/` | PNG icons, rendered by `tools/make_icons.py` from the app icon (`usr/share/icons/hicolor/scalable/apps/ashypass.svg`) |
| `manifest.chrome.json`, `manifest.firefox.json` | One manifest per browser family |
| `chrome-dev-key.pub` | Public key that pins the Chrome development id (it is not a secret) |
| `VERSION` | Extension version written into both manifests |

## Build

You only need Python 3 (standard library). There is no npm, bundler or
compile step.

```sh
python3 -I browser-extension/build.py          # writes browser-extension/dist/
```

| Output | Use |
|--------|-----|
| `dist/chrome-dev/` | Unpacked Chrome build. Its manifest has `key`, so the id is always `opelfkfheadglgamfephkfejfpcnlbck` |
| `dist/firefox-dev/` | Unpacked Firefox build |
| `dist/ashypass-chrome-<version>.zip` | Chrome Web Store upload. It has no `key`, and it leaves out the `is` locale because Chrome rejects it |
| `dist/ashypass-firefox-<version>.zip` | Upload to addons.mozilla.org for signing |

To release, bump `VERSION` and run the build again. To redraw the icons, run
`python3 -I browser-extension/tools/make_icons.py`.

## Test

These tests need Node 22 or newer, with no packages installed:

```sh
cd browser-extension
node --test
```

The suite covers the following:

- the helpers and the request tracker (rids, out-of-order replies, timeouts, disconnects);
- `fillCredentials` against a fake DOM (field choice, hidden or disabled fields, cross-origin frames, React-style value setters);
- the background script against a fake `chrome` API and a scripted host;
- `node --check` on every JS file, plus checks that there is no eval, no `innerHTML` and no inline scripts;
- both manifests, every `messages.json` (same keys as `en`, matching placeholders, real translations) and the output of `build.py`.

## Load the unpacked extension

**Chrome, Brave, Chromium, Edge, Vivaldi**

1. Run the build.
2. Open `chrome://extensions` (`brave://extensions`, …) and turn on *Developer mode*.
3. Click *Load unpacked* and choose `browser-extension/dist/chrome-dev`.
4. Check that the id is `opelfkfheadglgamfephkfejfpcnlbck`. That id is what the native host allows.

**Firefox**

1. Run the build.
2. Open `about:debugging#/runtime/this-firefox`.
3. Click *Load Temporary Add-on…* and choose `browser-extension/dist/firefox-dev/manifest.json`.

The id is fixed (`ashypass@big-comm.github.io`), so the host accepts the
temporary add-on too. A temporary add-on is removed when Firefox restarts.

Use **Ctrl+Shift+L** or the toolbar button to open the popup.

## Extension ids

| Browser | Id | Where it comes from |
|---------|----|---------------------|
| Firefox | `ashypass@big-comm.github.io` | `browser_specific_settings.gecko.id` (fixed) |
| Chrome (dev) | `opelfkfheadglgamfephkfejfpcnlbck` | `key` added to the `chrome-dev` manifest by `build.py` |
| Chrome Web Store | assigned on first publication | add it to the host's allowed origins |

## Security model

- **No secrets stored.** The extension never writes vault data to storage,
  never caches it in memory, and never logs it. The popup asks the background
  for each value, and the background asks the host.
- **User action required.** Filling and copying only happen when you click a
  button in the popup. Nothing is filled automatically, and the extension has
  no content scripts that run on page load.
- **Fill only on the matching site.** The background reads the tab's URL itself
  and sends it with `fill {id, url}`. The host refuses (`no_match`) unless the
  entry belongs to that site. The extension never uses `get` to fill. Filling
  works only on `http:`/`https:` pages.
- **Same-origin frames only.** The filler is injected with `allFrames: true`,
  but it does nothing in any frame whose `location.origin` differs from the
  tab's origin. Cross-origin iframes never receive credentials, and if the tab
  navigated in the meantime, nothing is filled.
- **Never submits.** The filler sets the values with the native setter, fires
  `input` and `change`, and focuses the password field. Submitting is up to you.
- **Minimal permissions.** The extension asks only for `nativeMessaging`,
  `activeTab`, `scripting` and `clipboardWrite`. There are no host
  permissions, so the extension can reach a page only after you open the
  popup on it.
- **Only the popup is trusted.** The background ignores messages that do not
  come from the extension's own pages.
- **The master password** goes straight from the password field to the host.
  The field is cleared after each attempt, and the key stays inside the host
  process.
- **No remote code.** All code ships in the package. It uses no `eval`, no
  inline scripts and no `innerHTML`, so it works under the default MV3 CSP of
  both stores.
