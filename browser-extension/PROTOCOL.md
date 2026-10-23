# Ashy Pass browser protocol (version 4)

The extension talks to `ashypass-native-host` through native messaging
(`runtime.connectNative("com.bigcommunity.ashypass")`). Each message is a JSON
object; the browser adds the length prefix.

## Requests

Every request has a `cmd` and may carry a numeric `rid`. The host copies `rid`
into the response, so one long-lived port can have several requests in flight.

| cmd         | fields                         | success response                                   |
|-------------|--------------------------------|----------------------------------------------------|
| `ping`      | —                              | `{ok, version, protocol: 4}`                       |
| `status`    | —                              | `{ok, enabled, has_vault, unlocked, pin_available}`|
| `unlock`    | `password`                     | `{ok}`                                             |
| `unlock_pin`| `pin`                          | `{ok}`; wrong PIN: `bad_pin` with `attempts_left`  |
| `lock`      | —                              | `{ok}`                                             |
| `match_url` | `url`                          | `{ok, entries: [Summary]}`                         |
| `search`    | `query`                        | `{ok, entries: [Summary]}`                         |
| `list`      | `query?`                       | `{ok, entries: [Summary]}`                         |
| `fill`      | `id`, `url`                    | `{ok, username, password}`                         |
| `get`       | `id`, `notes?` (bool)          | `{ok, entry: Entry}`                               |
| `totp`      | `id`                           | `{ok, code, remaining, period}`                    |
| `generate`  | see below                      | `{ok, password}`                                   |
| `folders`   | —                              | `{ok, folders: [string]}`                          |
| `favicons`  | `hosts: [string]` (≤ 40)       | `{ok, icons: {host: "data:image/…;base64,…"}}`     |
| `add`       | `title`, `password`, `username?`, `url?`, `category?`, `notes?` | `{ok, id}`        |
| `update`    | `id`, `updated_at`, `title`, `password`, `username?`, `url?`, `category?`, `notes?` | `{ok, id}` |
| `delete`    | `id`                           | `{ok, trashed}`                                    |
| `toggle_favorite` | `id`                     | `{ok, favorite}`                                   |
| `open_app`  | —                              | `{ok}` (brings up the desktop app)                 |

`generate` fields (all optional): `kind` (`password` default, `passphrase`,
`pin`), `length` (password ≤ 128, PIN 4–64), `uppercase`, `lowercase`,
`digits`, `symbols`, `avoid_ambiguous` (password), `words` (3–12),
`separator` (≤ 3 chars), `capitalize`, `number` (passphrase).

`favicons` only reads the icons the desktop app already cached; hosts without
one are absent from `icons`. It never fetches anything.

`Summary`: `{id, title, username, url, category, has_totp, favorite}`

Replies with `entries` also carry `truncated`: true when the list was cut to
fit one message (browsers take at most 1 MiB from the host), which only
happens with several thousand entries; search narrows it down.

`Entry`: `{id, title, username, url, password, category, has_totp, favorite, updated_at}`,
plus `notes` (empty string when none) only when the request has `notes: true`.
Notes often hold recovery codes: the extension asks for them only to fill the
edit form, never for copying or filling pages.

`update` replaces the editable fields: an absent `username`, `url` or
`category` clears it. An absent `notes` keeps the notes, a blank one clears
them. The verification code is kept. Only the
fields that differ are written, so an unchanged password adds nothing to the
password history. `updated_at` is the value `get` returned; when the entry was
changed since (desktop app, sync), the host refuses with `changed` and writes
nothing.

`delete` follows the desktop app: the entry goes to the trash when the trash
is on (`trashed: true`), and is deleted for good otherwise. A login synced to
Nextcloud is deleted there on the next sync.

`fill` only answers when the entry belongs to the site at `url` (same rules
as `match_url`); otherwise it fails with `no_match`. The extension must use
`fill` for filling pages, never `get`.

## Errors

`{ok: false, error: "<English text>", code: "<code>"}`

| code           | meaning                                                         |
|----------------|-----------------------------------------------------------------|
| `disabled`     | Browser integration is off in Ashy Pass (Settings → Browser).   |
| `no_vault`     | No vault has been created yet.                                  |
| `locked`       | The vault is locked: ask for the master password (`unlock`).    |
| `bad_password` | Wrong master password.                                          |
| `bad_pin`      | Wrong PIN; `attempts_left` tells how many remain.               |
| `pin_disabled` | Too many wrong PINs (or the PIN no longer matches the vault): it was turned off; use the master password. |
| `pin_unavailable` | No PIN is set up on this computer.                           |
| `rate_limited` | Too many wrong passwords; wait and try again.                   |
| `not_found`    | No entry with that id.                                          |
| `no_match`     | `fill` for an entry that does not belong to the page.           |
| `no_totp`      | `totp` for an entry without a verification code.                |
| `changed`      | `update` with an outdated `updated_at`: the entry changed meanwhile. |
| `invalid`      | Malformed request.                                              |
| `internal`     | Anything else.                                                  |

## Unlocking

The host unlocks the vault by itself when the master password is stored in
the system keyring (Settings → Protection → Open automatically at login).
Otherwise the extension asks for the PIN set up in Ashy Pass (`unlock_pin`,
when `status.pin_available`) or the master password (`unlock`). The PIN
follows the desktop rules: wrong attempts are counted in the stored record
and the PIN is turned off after 5.
The key stays in the host process only: it is dropped after the auto-lock
delay without requests, when the screen locks (if that option is on), when
`lock` is sent, or when the port closes.

## Extension ids

| Browser           | Id                                   | Where it comes from                  |
|-------------------|--------------------------------------|--------------------------------------|
| Firefox           | `ashypass@big-comm.github.io`        | `browser_specific_settings` (fixed)  |
| Chrome (dev)      | `opelfkfheadglgamfephkfejfpcnlbck`   | `key` in the development manifest; allowed by debug hosts, or `--install --chrome-id` |
| Chrome Web Store  | `aaffaajejkomddnihpblnkolkhcgaoom`   | allowed by the host (`CHROME_EXTENSION_IDS`) |
