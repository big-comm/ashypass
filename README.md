# Ashy Pass

<p align="center">
  <img src="https://github.com/big-comm/ashypass/blob/main/usr/share/icons/hicolor/scalable/apps/ashypass.svg" alt="Ashy Pass" width="128" height="128">
</p>

<p align="center">
  <strong>Modern, encrypted password manager for Linux desktops.</strong><br>
  Rust · GTK4 · libadwaita · AES-256-GCM · Argon2id
</p>

<p align="center">
  <a href="https://github.com/big-comm/ashypass/releases"><img src="https://img.shields.io/badge/version-3.0.0-blue.svg" alt="Version"/></a>
  <a href="https://github.com/big-comm/ashypass/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License"/></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-1.85+-orange.svg" alt="Rust"/></a>
  <a href="https://www.gtk.org/"><img src="https://img.shields.io/badge/GTK-4.12+-purple.svg" alt="GTK"/></a>
  <a href="https://bigcommunity.com"><img src="https://img.shields.io/badge/BigCommunity-Platform-blue" alt="BigCommunity"/></a>
</p>

---

## Overview

Ashy Pass is a desktop password manager designed around GNOME-style ergonomics and modern cryptography. The 3.x series is a ground-up rewrite in Rust on top of GTK4 / libadwaita, replacing the previous Python implementation.

The on-disk vault uses **AES-256-GCM** authenticated encryption with **Argon2id** key derivation. Legacy 2.x Fernet vaults are auto-migrated on first unlock — no manual export required.

The project ships as a **multi-crate workspace**:

| Crate | Role |
|-------|------|
| `ashypass-core` | Pure library: crypto, vault, importers, generators, sync, backup. No GTK. |
| `ashypass-app` | GTK4 / libadwaita desktop application. |
| `ashypass-cli` | Terminal companion sharing the same vault and keyring item. |
| `ashypass-native-host` | Chrome / Firefox native-messaging host for browser extensions. |

## Features

### Security
- **AES-256-GCM** authenticated encryption per field (password, notes, TOTP secret).
- **Argon2id** master verification *and* per-entry key derivation (`t=3, m=64 MiB, p=4` by default, auto-tuned at first run).
- **Quick Unlock** via the Secret Service (GNOME Keyring / KWallet) so daily use doesn't require retyping the master password.
- **Automatic session lock** with configurable idle timeout and pre-lock warning toast.
- **Clipboard auto-clear** after a configurable interval; only clears if the contents are still the secret you copied.
- **HIBP audit** with k-anonymity (only the first 5 hex digits of the SHA-1 hash are sent).
- **Soft-delete trash** with configurable retention; entries are recoverable until purge.
- **FIDO2 second-factor scaffolding** with BIP39 backup-phrase fallback. *CTAP2 hardware calls are stubbed; the storage layout and recovery flow are wired.*
- **Zero-knowledge** — the master password and derived keys never leave the machine.

### Vault
- Encrypted SQLite storage (rusqlite, `FK ON DELETE CASCADE`).
- Categories, favorites, full-text search, and per-entry tags.
- Per-entry **TOTP** with selectable algorithm (SHA1 / SHA256 / SHA512), digits (6 / 8), and period.
- Favicon fetcher with on-disk cache (`<host>/favicon.ico` → Google `s2` fallback).
- One-click copy with timed auto-clear and clipboard scoping.

### Password generation
- Strong passwords with configurable length and character classes.
- Diceware-style passphrases (EFF wordlist).
- Numeric PINs.
- Real-time strength meter (entropy-based: Weak → Very Strong).

### Import / Export
- **CSV** (Chrome, Firefox, Bitwarden-compatible).
- **KeePass** (`.kdbx`) read-only import.
- **1Password** export bundles.
- **Aegis** and **andOTP** JSON for TOTP, auto-tagged under category `2FA`.
- Native `.ashy` encrypted export / import.
- CSV export (Chrome-compatible).

### Cloud & sync
- **Nextcloud Passwords** bidirectional sync (REST API v1.0) — folders, tags, password versions.
- **WebDAV / Nextcloud Files** encrypted backup with generation-aware conflict detection.
- **Google Drive** backup via direct REST + OAuth 2.0 PKCE (no Python SDK), uploading to a dedicated `AshyPass Backups` folder.
- Each backend has list / restore / delete from inside Settings.

### Browser integration
- `ashypass-native-host` implements the Chrome native-messaging wire protocol (`u32` length prefix + UTF-8 JSON).
- Supported commands: `ping`, `list`, `search`, `match_url`, `get`, `generate`.
- Reuses the Secret Service item so the GUI's Quick Unlock policy applies — no separate browser unlock.

### Terminal companion
- `ashypass-cli`: list, search, copy, generate, and add entries from the shell.
- Shares the GUI's vault file and keyring item; falls back to a silent stdin prompt when no stored master is available.

### Interface
- libadwaita styling; dark mode follows the desktop.
- Sidebar-based settings dialog organised into **Security · Data · Cloud · Appearance** sections.
- Default window 800×650, minimum 700×570.
- Toast notifications, view stacks, and animated transitions.
- gettext-based localization with **30 language catalogues** shipped (`bg, cs, da, de, el, en, es, et, fi, fr, he, hr, hu, is, it, ja, ko, nl, no, pl, pt, pt_BR, ro, ru, sk, sv, tr, uk, zh`).

## Status

| Area | State |
|------|-------|
| Core crypto (Argon2id + AES-256-GCM v2) | Stable |
| v1 → v2 vault migration (Fernet → AES-GCM) | Stable |
| Vault CRUD, search, categories, favorites, trash | Stable |
| Password / passphrase / PIN generation + strength meter | Stable |
| TOTP view + RFC 6238 generation | Stable |
| HIBP audit (k-anonymity) | Stable |
| Importers (CSV, Aegis, andOTP, KeePass, 1Password, `.ashy`) | Stable |
| Settings dialog (sidebar layout) | Stable |
| Google Drive backup (REST + OAuth PKCE) | Stable — requires build-time client ID |
| WebDAV / Nextcloud Files backup | Stable |
| Nextcloud Passwords bidirectional sync | Stable |
| Browser native-messaging host | Stable |
| CLI companion | Stable |
| Quick Unlock via Secret Service | Stable |
| Favicon fetch + cache | Stable |
| FIDO2 hardware (CTAP2 register / assert) | Storage and backup-phrase wired; CTAP2 calls stubbed |
| i18n (gettext-rs, 30 catalogues) | Fully translated and CI-compiled |

## System requirements

| | |
|---|---|
| OS | Linux with GTK 4.12+ |
| Toolchain | Rust 1.85+, `pkg-config`, GTK4 / libadwaita dev headers |
| Runtime libs | `gtk4`, `libadwaita`, `gettext`, `sqlite`, `openssl`, `glibc`, `gcc-libs`, optional Secret Service daemon (gnome-keyring / kwallet) |
| Memory | ~50 MiB resident |
| Disk | ~30 MiB binary + vault |

## Building

```bash
git clone https://github.com/big-comm/ashypass.git
cd ashypass
cargo build --release --workspace
./target/release/ashypass
```

Enable the FIDO2 stack (CTAP2 wiring is still stubbed; see **Status**):

```bash
cargo build --release -p ashypass-app --features fido2
```

Provide Google Drive credentials at build time (without these the Cloud Backup page shows a "not configured" notice):

```bash
ASHYPASS_GOOGLE_CLIENT_ID=xxx.apps.googleusercontent.com \
ASHYPASS_GOOGLE_CLIENT_SECRET=xxx \
  cargo build --release -p ashypass-app
```

Build the auxiliary binaries:

```bash
cargo build --release -p ashypass-cli           # produces ./target/release/ashypass-cli
cargo build --release -p ashypass-native-host   # produces ./target/release/ashypass-native-host
```

### Arch / Manjaro

```bash
cd pkgbuild
makepkg -si
```

The PKGBUILD compiles every `locale/*.po` into `usr/share/locale/<lang>/LC_MESSAGES/ashypass.mo`, installs the desktop file, icons, and native-messaging manifests for Chromium- and Firefox-based browsers.

## Usage

### First run
1. Launch Ashy Pass.
2. Set a master password on the **Vault** tab — used to derive the AES-256-GCM key.
3. (Optional) Enable Quick Unlock in **Settings → Security** to cache the master in the Secret Service.
4. Add entries, or import a CSV / KeePass database from **Settings → Data**.

### Generating passwords
- Use the **Generator** tab to pick a type, tweak options, and copy.
- Inside the add/edit dialog, the password row carries a generate button (⚡) with presets: Strong, Passphrase, PIN, Custom.

### TOTP
- Edit any entry, paste a Base32 secret in the **TOTP Settings** group, choose algorithm/digits/period, save.
- The **2FA** tab lists live codes; click to copy.

### Cloud sync & backup
- **Nextcloud Passwords** — *Settings → Cloud → Nextcloud Passwords*: enter URL, username, app password, choose a folder, hit *Sync*. Conflicts are resolved by version timestamps.
- **WebDAV backup** — *Settings → Cloud → WebDAV*: encrypted database is uploaded with a generation marker so concurrent writes don't silently overwrite.
- **Google Drive backup** — *Settings → Cloud → Google Drive → Sign in*: the system browser opens an OAuth PKCE flow with a `127.0.0.1` callback. *Back up now* uploads the encrypted database; *Restore latest* downloads it as `passwords.restored.db`.

### Browser extension
1. Build / install `ashypass-native-host`.
2. The package installs `com.bigcommunity.ashypass.json` manifests under `~/.config/<browser>/NativeMessagingHosts/`.
3. The companion extension communicates via the manifest — see the project's extension repo.

### CLI
```bash
ashypass-cli list                       # all entries (decrypted if keyring unlocked)
ashypass-cli search github              # filter by query
ashypass-cli copy <id>                  # copy password with auto-clear
ashypass-cli generate --length 24       # generate without storing
ashypass-cli add github.com --user me   # interactive add
```

### FIDO2 / YubiKey (preview)
- *Settings → Security → Two-Factor → Register* — currently returns a "not yet wired" error; storage layout and backup-phrase recovery are implemented.
- *Generate Backup Phrase* yields a 12-word BIP39 phrase shown once; only its Argon2id hash is persisted.

### Configuration

| File | Purpose |
|------|---------|
| `~/.config/ashypass/settings.json` | UI prefs, lock / clipboard timeouts, generator defaults, trash retention |
| `~/.config/ashypass/fido2.json` | Registered FIDO2 slots + backup-phrase hash |
| `~/.local/share/ashypass/passwords.db` | Encrypted SQLite vault |
| `~/.local/share/ashypass/token.json` | Google Drive OAuth tokens |
| `~/.local/share/ashypass/favicons/` | Cached site icons |

## Architecture

```
ashypass/
├── crates/
│   ├── ashypass-core/                # Pure library — no GTK
│   │   └── src/
│   │       ├── crypto/               # argon2_kdf, aes_gcm_v2, fernet_legacy, key, autotune
│   │       ├── db/                   # rusqlite vault, schema, migration v1→v2
│   │       ├── generator.rs          # passwords / passphrases / PINs
│   │       ├── strength.rs           # entropy-based strength meter
│   │       ├── totp.rs               # RFC 6238 (SHA1 / SHA256 / SHA512)
│   │       ├── importers/            # aegis, andotp, ashy, bitwarden, csv, keepass, onepassword
│   │       ├── backup/               # drive, webdav, oauth, sync
│   │       ├── sync/                 # nextcloud_passwords, nextcloud_engine
│   │       ├── audit.rs · hibp.rs    # password-health + breach checks (k-anonymity)
│   │       ├── favicons.rs           # fetch + on-disk cache
│   │       ├── fido2.rs              # slots + BIP39 backup + CTAP2 stubs
│   │       ├── keyring.rs            # Secret Service (Quick Unlock)
│   │       └── settings.rs           # serde-backed user prefs
│   ├── ashypass-app/                 # GTK4 / libadwaita desktop UI
│   │   └── src/
│   │       ├── main.rs · state.rs · session.rs · clipboard.rs · events.rs
│   │       └── ui/                   # window, vault_view, generator_view, totp_view,
│   │                                 #   settings_dialog (sidebar), i18n (tr! macro)
│   ├── ashypass-cli/                 # Terminal companion (shares vault + keyring)
│   └── ashypass-native-host/         # Chrome/Firefox native-messaging host
├── locale/                           # 30 .po files + ashypass.pot template
├── scripts/                          # update-translations.sh, packaging helpers
└── pkgbuild/                         # Arch / Manjaro PKGBUILD
```

See [CRYPTO_SPEC.md](CRYPTO_SPEC.md) for the exact algorithm parameters and blob layout — useful for porting or interoperability.

## Translations

UI strings are wrapped in the `tr!()` macro, which delegates to `gettext_rs` and caches per-thread results behind a `&'static str`.

To refresh the template and recompile catalogues after editing source strings:

```bash
./scripts/update-translations.sh
```

The script runs `xgettext` (recognising both `tr!` and `tr_static!`), `msgmerge --no-fuzzy-matching` against every `locale/*.po`, and `msgfmt` into `usr/share/locale/<lang>/LC_MESSAGES/ashypass.mo`. The PKGBUILD performs the same compile step at packaging time, so the CI/CD pipeline only needs the source `.po` files committed.

## Contributing

1. Fork and create a feature branch from `main`.
2. Run `cargo fmt --all` and `cargo clippy --workspace --all-targets -- -D warnings`.
3. Add tests next to the code you touch (see existing `#[cfg(test)]` modules in `ashypass-core`).
4. Keep commit messages in English; UI strings stay in English and are translated via the `.po` workflow above.
5. Open a PR against `main`.

## License

MIT — see [LICENSE](LICENSE).

## Acknowledgments

- **EFF** — Diceware wordlist for passphrase generation.
- **GNOME** — GTK4 / libadwaita.
- **RustCrypto** — `argon2`, `aes-gcm`, `pbkdf2`, `hmac`, `sha2`.
- **rusqlite** — embedded SQLite bindings.
- **Have I Been Pwned** — breach corpus consumed via the k-anonymity range API.
- **Nextcloud** — Passwords and Files REST APIs.

---

<p align="center">
  <a href="https://github.com/big-comm/ashypass/issues">Report a bug</a> ·
  <a href="https://github.com/big-comm/ashypass/issues">Request a feature</a> ·
  <a href="https://github.com/big-comm/ashypass/discussions">Discussions</a>
</p>
