# Ashy Pass browser protocol (version 2)

The extension talks to `ashypass-native-host` through native messaging
(`runtime.connectNative("com.bigcommunity.ashypass")`). Each message is a JSON
object; the browser adds the length prefix.

## Requests

Every request has a `cmd` and may carry a numeric `rid`. The host copies `rid`
into the response, so one long-lived port can have several requests in flight.

| cmd         | fields                         | success response                                   |
|-------------|--------------------------------|----------------------------------------------------|
| `ping`      | —                              | `{ok, version, protocol: 2}`                       |
| `status`    | —                              | `{ok, enabled, has_vault, unlocked}`               |
| `unlock`    | `password`                     | `{ok}`                                             |
| `lock`      | —                              | `{ok}`                                             |
| `match_url` | `url`                          | `{ok, entries: [Summary]}`                         |
| `search`    | `query`                        | `{ok, entries: [Summary]}`                         |
| `list`      | `query?`                       | `{ok, entries: [Summary]}`                         |
| `fill`      | `id`, `url`                    | `{ok, username, password}`                         |
| `get`       | `id`                           | `{ok, entry: Entry}`                               |
| `totp`      | `id`                           | `{ok, code, remaining, period}`                    |
| `generate`  | `kind?` (`password`, `passphrase`, `pin`), `length?` | `{ok, password}`         |

`Summary`: `{id, title, username, url, category, has_totp}`

`Entry`: `{id, title, username, url, password, category, has_totp}` (no notes)

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
| `rate_limited` | Too many wrong passwords; wait and try again.                   |
| `not_found`    | No entry with that id.                                          |
| `no_match`     | `fill` for an entry that does not belong to the page.           |
| `no_totp`      | `totp` for an entry without a verification code.                |
| `invalid`      | Malformed request.                                              |
| `internal`     | Anything else.                                                  |

## Unlocking

The host unlocks the vault by itself when the master password is stored in
the system keyring (Settings → Protection → Open automatically at login).
Otherwise the extension asks for the master password and sends `unlock`.
The key stays in the host process only: it is dropped after the auto-lock
delay without requests, when the screen locks (if that option is on), when
`lock` is sent, or when the port closes.

## Extension ids

| Browser           | Id                                   | Where it comes from                  |
|-------------------|--------------------------------------|--------------------------------------|
| Firefox           | `ashypass@big-comm.github.io`        | `browser_specific_settings` (fixed)  |
| Chrome (dev)      | `opelfkfheadglgamfephkfejfpcnlbck`   | `key` in the development manifest    |
| Chrome Web Store  | assigned on first publication        | add it to the host's allowed list    |
