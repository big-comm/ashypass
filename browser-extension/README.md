# Ashy Pass browser extension

The browser side of [Ashy Pass](https://github.com/big-comm/ashypass), the
GNOME password manager for Linux. It runs in Chrome, Brave, Chromium, Edge,
Vivaldi and Firefox (Manifest V3).

The extension is deliberately thin: it **stores no secrets** and keeps no
vault data. Each time you click *Fill*, *Copy* or *Show*, it asks the
Ashy Pass desktop app and forgets the answer once it has been used.

## Features

- **Popup** (Alt+Shift+L or the toolbar button), with three tabs at the bottom:
  - **Vault**: search (as you type), Folder and Type filters (all items,
    logins with codes, favorites), and the sections *Autofill suggestions*
    (logins for the current site, with a *Fill* button), *Favorites* and
    *All items*. Each row shows the site icon cached by the desktop app (or a
    coloured letter), the title and the username, plus buttons to open the
    website, copy the username, the password or the verification code, and a
    ⋮ menu (favorite, copy website address, details, edit, delete). The
    details view shows the username, the password (hidden until you ask), the
    website, the folder and the live verification code with its countdown,
    with *Edit* and *Delete* below. *Add* saves a new login for the current
    site. *Edit* changes the name, username, password, website, folder and
    notes (verification codes stay as they are); it refuses to overwrite a login that
    was changed in the desktop app meanwhile. *Delete* asks first and follows
    the desktop app: to the trash when it is on, synced deletions included.
  - **Generator**: password, passphrase or PIN, with the usual options
    (length, character types, words, separator…). The options (never the
    values) are remembered. *Fill on this page* puts the generated password
    into the password fields of the page.
  - **Settings**: lock, open the desktop app, inline suggestions, keyboard
    shortcut, version and links.
- **Unlocking** with the PIN set up in Ashy Pass, or the master password.
- **Inline suggestions** (on by default, can be turned off in Settings): a small Ashy Pass button inside login
  fields and a menu under the field that lists the logins of the site. Click
  one to fill it. See [Inline suggestions](#inline-suggestions) for how it is
  isolated from the page.

## How it talks to the app

The background script opens one
[native messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging)
port to `com.bigcommunity.ashypass`. The browser starts the
`ashypass-native-host` program installed by the Ashy Pass package. That program
opens the vault, using the system keyring or the master password you type in
the popup, and answers JSON requests. [PROTOCOL.md](PROTOCOL.md) describes the
requests and errors.

```
popup / inline menu ──runtime.sendMessage──▶ background ──connectNative port──▶ ashypass-native-host ──▶ vault
```

To link a browser, open Ashy Pass → Settings → Browser, turn the extension on
and connect your browser. This installs the host manifest that lists the
extension ids below.

## Layout

| Path | What it is |
|------|------------|
| `src/background.js` | Native port, `rid` bookkeeping, message API for the popup and the inline menu, filling, inline script registration |
| `src/lib/helpers.js` | Pure helpers (URLs, request tracker, filters, favicon batching, generator options, inline tokens, sender checks), unit-tested |
| `src/lib/fill.js` | `fillCredentials` and `fillPasswordFields`, the functions injected into the page |
| `src/lib/icons.js`, `src/lib/theme.css` | Shared icons (built with DOM APIs) and colours (light/dark) |
| `src/popup/` | Popup UI (HTML/CSS/JS, no frameworks) |
| `src/inline/content.js` | Content script: the button in login fields and the menu frame placement |
| `src/inline/menu.*` | The suggestions menu, an extension page shown in an `<iframe>` |
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
- `fillCredentials` and `fillPasswordFields` against a fake DOM (field choice, hidden or disabled fields, cross-origin frames, React-style value setters);
- the helpers: filters, favicon batching, generator option mapping, sender checks, inline tokens (bound to tab and frame, single use, expiry);
- the background script against a fake `chrome` API and a scripted host, including the inline token flow, and against a fake `browser` API (the listener must return the promise there);
- `node --check` on every JS file, plus checks that there is no eval, no `innerHTML` and no inline scripts;
- both manifests, every `messages.json` (same keys as `en`, matching placeholders, real translations) and the output of `build.py`.

## Load the unpacked extension

**Chrome, Brave, Chromium, Edge, Vivaldi**

1. Run the build.
2. Open `chrome://extensions` (`brave://extensions`, …) and turn on *Developer mode*.
3. Click *Load unpacked* and choose `browser-extension/dist/chrome-dev`.
4. Check that the id is `opelfkfheadglgamfephkfejfpcnlbck`.
5. Allow that id in the native host. Debug builds of the host allow it by
   themselves; a packaged (release) Ashy Pass does not, because anyone can
   make an extension with the public development key. Run once:
   `/usr/lib/ashypass/ashypass-native-host --install --chrome-id opelfkfheadglgamfephkfejfpcnlbck`.

**Firefox**

1. Run the build.
2. Open `about:debugging#/runtime/this-firefox`.
3. Click *Load Temporary Add-on…* and choose `browser-extension/dist/firefox-dev/manifest.json`.

The id is fixed (`ashypass@big-comm.github.io`), so the host accepts the
temporary add-on too. A temporary add-on is removed when Firefox restarts.

Use **Alt+Shift+L** or the toolbar button to open the popup.

## Extension ids

| Browser | Id | Where it comes from |
|---------|----|---------------------|
| Firefox | `ashypass@big-comm.github.io` | `browser_specific_settings.gecko.id` (fixed) |
| Chrome (dev) | `opelfkfheadglgamfephkfejfpcnlbck` | `key` added to the `chrome-dev` manifest by `build.py` |
| Chrome Web Store | assigned on first publication | add it to the host's allowed origins |

## Permissions

| Permission | Why |
|------------|-----|
| `nativeMessaging` | Talk to the Ashy Pass desktop app (`ashypass-native-host`). |
| `activeTab` | Read the address of the tab where you opened the popup, and fill it, only after you click the toolbar button or press the shortcut. |
| `scripting` | Inject the filler into that tab and register the inline script. |
| `clipboardWrite` | Copy usernames, passwords and codes when you click *Copy*. |
| `storage` | Remember the generator options and whether you dismissed the inline-suggestions hint. Never vault data. |
| `http://*/*`, `https://*/*` | Asked at install in Chrome, like other password managers; Firefox leaves MV3 site access to the user, so the popup asks for it the first time (*Enable*): runs the small content script that shows the Ashy Pass button and menu in login fields, and fills from that menu without opening the popup. The script never receives vault data. *Show suggestions in login fields* in Settings turns the feature off (the script is unregistered). |

## Inline suggestions

Turning the option on (Settings, or the hint card in the Vault tab) asks the
browser for access to websites and then registers `inline/content.js` with
`scripting.registerContentScripts` (all frames, `document_idle`). Turning it
off unregisters the script and removes the permission. If the permission is
granted but the script is not registered (for example after an update), the
background registers it again at startup. Pages that were already open need a
reload.

How it is kept away from the page:

- **The page never sees the list.** The content script only draws a button
  inside the field (in a closed shadow root) and places an `<iframe>` of
  `inline/menu.html`, an extension page. The page cannot read a cross-origin
  frame. The content script gets no vault data at all: the only message it
  may send is a request for an opening token.
- **Opening tokens.** When a login field is focused, the content script asks
  the background for a token. The background takes the tab and frame from
  `sender` (never from the message), refuses frames whose origin differs from
  the tab's, and records `{tab, frame, origin}` under a random 128-bit token
  that expires after 5 minutes. The content script passes the token to the
  menu frame with `postMessage` targeted at the extension origin. The menu
  uses it to read the suggestions (the first use binds the token to that menu
  frame and tab), and to fill once: after a fill the token is gone.
- **Filling** goes through the host `fill` command with the tab's current
  URL, so the host still checks that the entry belongs to the site, and only
  into the frame that opened the menu, after checking that the tab still shows
  the same origin. The filler refuses other origins and never submits.
- **Frame messages** between the content script and the menu are checked by
  source window and origin. They only carry sizes and UI events.
- The menu page is web-accessible only to `http(s)` pages; without a valid
  token it shows nothing. (Chrome's `use_dynamic_url` is not used: with it the
  content script and the menu frame see different origins, so the token
  hand-off is refused.)
- If the vault is locked, the menu offers *Unlock*, which opens the toolbar
  popup (`action.openPopup`). Browsers that refuse to open it get a hint to
  click the toolbar icon. *Add login* opens the popup on the Add view the same way.

## Security model

- **No secrets stored.** The extension never writes vault data to storage,
  never caches it, and never logs it. The popup asks the background for each
  value, and the background asks the host. Only the generator options and the
  hint dismissal are kept in `storage.local`. Favicons are cached in memory
  while the popup is open.
- **User action required.** Filling and copying only happen when you click a
  button in the popup or a login in the inline menu. Nothing is filled
  automatically, and nothing is ever submitted.
- **Fill only on the matching site.** The background reads the tab's URL itself
  and sends it with `fill {id, url}`. The host refuses (`no_match`) unless the
  entry belongs to that site. The extension never uses `get` to fill. Filling
  works only on `http:`/`https:` pages.
- **Same-origin frames only.** The popup's filler is injected with
  `allFrames: true`, but it does nothing in any frame whose `location.origin`
  differs from the tab's origin. The inline menu fills only the frame that
  opened it. Cross-origin iframes never receive credentials or the inline
  button.
- **Minimal permissions by default.** Without the inline option there are no
  host permissions: the extension reaches a page only after you open the popup
  on it.
- **Trusted senders.** The background answers the popup (extension pages)
  fully, the menu frame only with the inline commands and favicons, content
  scripts only with opening tokens, and ignores everything else.
- **The master password and PIN** go straight from the field to the host.
  The field is cleared after each attempt, and the key stays inside the host
  process.
- **No remote code.** All code ships in the package. It uses no `eval`, no
  inline scripts and no `innerHTML`, so it works under the default MV3 CSP of
  both stores.
