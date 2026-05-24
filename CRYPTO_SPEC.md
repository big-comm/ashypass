# CRYPTO_SPEC.md — Ashy Pass Cryptographic Specification

Version: 2.0
Date: 2026-05-10

## Overview

Ashy Pass uses a layered encryption scheme to protect stored passwords and TOTP secrets. This document specifies the exact parameters and algorithms so that any compatible implementation (e.g., Android companion app, alternative client) can produce identical ciphertext and interoperate with the same SQLite database.

The current on-disk format is **v2** (AES-256-GCM + Argon2id). The legacy **v1** format (Fernet + PBKDF2) is documented for backward read; v1 databases are migrated to v2 atomically on the first successful unlock.

## Versioning

The `master.crypto_version` column tags the format used by the current vault:

| Value | KDF                        | Cipher                | Status     |
|-------|----------------------------|-----------------------|------------|
| 1     | PBKDF2-HMAC-SHA256 (100k)  | Fernet (AES-128-CBC + HMAC-SHA256) | Read-only — migrate on unlock |
| 2     | Argon2id (t=3, m=64 MiB, p=4) | AES-256-GCM        | **Current** |

A v1 vault is upgraded to v2 by re-encrypting every BLOB column inside a single transaction; if any row fails, the transaction rolls back and the vault stays v1.

## Key Derivation

### Master password verification

The master password is verified using **Argon2id** (`argon2` crate, RustCrypto):

| Parameter    | Value |
|--------------|-------|
| Variant      | Argon2id |
| Version      | 0x13 (1.3) |
| Time cost    | 3 |
| Memory cost  | 65536 KiB (64 MiB) |
| Parallelism  | 4 |
| Hash length  | 32 bytes |
| Salt         | 16 random bytes, encoded into the PHC string |

The Argon2 hash (PHC format, e.g. `$argon2id$v=19$m=65536,t=3,p=4$…`) is stored in `master.password_hash`.

### Encryption key derivation (v2)

```
salt = master.salt                    (UTF-8 text; the literal bytes are used as input)
key  = Argon2id(
    password   = master_password.as_bytes(),
    salt       = salt.as_bytes(),
    t_cost     = 3,
    m_cost     = 65536 KiB,
    parallelism = 4,
    output_len = 32
)
```

The resulting 32-byte `key` is used directly as the AES-256-GCM symmetric key. No additional encoding step (no base64-of-key) is performed in v2.

### Encryption key derivation (v1, legacy / read-only)

```
key  = PBKDF2-HMAC-SHA256(
    password   = master_password.as_bytes(),
    salt       = salt.as_bytes(),    # the base64url string is itself the salt bytes
    iterations = 100000,
    dklen      = 32
)
fernet_key = base64url_encode(key)
```

`fernet_key` is then fed into a Fernet decryption routine to read v1 BLOBs during migration.

## Encryption

### v2 — AES-256-GCM

Each encrypted column is an opaque BLOB with the layout:

```
| 1 byte version=0x02 | 12 bytes nonce | ciphertext (variable) | 16 bytes GCM tag |
```

- Cipher: **AES-256-GCM** (`aes-gcm` crate).
- Nonce: 12 random bytes, generated per encryption from the OS CSPRNG.
- Tag: 16 bytes, appended to the ciphertext by GCM.
- AAD: none.
- Version byte: `0x02` — readers must reject any other value.

The minimum valid blob size is `1 + 12 + 16 = 29` bytes (empty plaintext still has a tag).

### v1 — Fernet (read-only)

Legacy ciphertext (Fernet token, base64url-encoded inside the BLOB):

```
Version (1 byte = 0x80) || Timestamp (8 bytes, big-endian) || IV (16 bytes) || Ciphertext (AES-128-CBC, PKCS7 padded) || HMAC-SHA256 (32 bytes)
```

- Encryption: AES-128-CBC.
- Authentication: HMAC-SHA256 over the preceding bytes.
- Key split: first 16 bytes of the decoded `fernet_key` = HMAC key; last 16 bytes = AES key.

Only used for reading entries during the v1 → v2 migration.

### Encrypted columns

| Column                   | Plaintext encoding |
|--------------------------|--------------------|
| `password_encrypted`     | UTF-8 string |
| `notes_encrypted`        | UTF-8 string (nullable) |
| `totp_secret_encrypted`  | UTF-8 string — Base32 TOTP secret (nullable) |

## Salt Generation

```
salt = SaltString::generate(OsRng)    // Argon2 16-byte random salt, base64 encoded
```

The salt is stored verbatim as text in `master.salt`. On master password change a fresh salt is generated and **every** encrypted column is re-encrypted inside a single SQLite transaction.

## Database Schema (v2)

### `master`

| Column          | Type    | Description |
|-----------------|---------|-------------|
| id              | INTEGER | Always `1` (single-row table, `CHECK (id = 1)`) |
| password_hash   | TEXT    | Argon2id PHC string |
| salt            | TEXT    | Argon2 SaltString |
| crypto_version  | INTEGER | `1` or `2` |
| created_at      | INTEGER | Unix timestamp (seconds) |

### `passwords`

| Column                  | Type    | Description |
|-------------------------|---------|-------------|
| id                      | INTEGER | Auto-increment primary key |
| title                   | TEXT    | Plaintext title |
| username                | TEXT    | Plaintext username (nullable) |
| password_encrypted      | BLOB    | v2 ciphertext (or v1 Fernet token in pre-migration vaults) |
| notes_encrypted         | BLOB    | Encrypted notes (nullable) |
| url                     | TEXT    | Plaintext URL (nullable) |
| totp_secret_encrypted   | BLOB    | Encrypted Base32 TOTP secret (nullable) |
| totp_algorithm          | TEXT    | `SHA1` / `SHA256` / `SHA512` (default `SHA1`) |
| totp_digits             | INTEGER | `6` or `8` (default `6`) |
| totp_period             | INTEGER | Seconds (default `30`) |
| category                | TEXT    | Optional category label |
| favorite                | INTEGER | `0` / `1` |
| created_at              | INTEGER | Unix timestamp |
| updated_at              | INTEGER | Unix timestamp |
| last_accessed           | INTEGER | Unix timestamp (nullable) |

Indexes:

```sql
CREATE INDEX idx_passwords_title    ON passwords(title);
CREATE INDEX idx_passwords_username ON passwords(username);
```

## TOTP Generation (RFC 6238)

```
counter        = floor(unix_timestamp / period)
counter_bytes  = u64_big_endian(counter)
mac            = HMAC(algorithm, key = base32_decode(secret), message = counter_bytes)
offset         = mac[last_byte] & 0x0F
code           = (u32_big_endian(mac[offset..offset+4]) & 0x7FFFFFFF) % 10^digits
```

Supported algorithms: `SHA1` (default), `SHA256`, `SHA512`.

`otpauth://` URI format:

```
otpauth://totp/{issuer}:{account}?secret={BASE32}&issuer={issuer}&algorithm={algo}&digits={digits}&period={period}
```

## Optional Second Factor — FIDO2

When enabled, unlock requires (master password) AND (authenticator OR backup phrase). The vault key is derived as:

```
vault_key   = Argon2id(master_password, salt)              // as above
fido_wrap   = SHA256("ashypass-fido2-wrap" || hmac_secret) // 32 bytes
final_key   = vault_key XOR fido_wrap
```

`hmac_secret` comes from a CTAP2 `getAssertion` with the `hmac-secret` extension on the slot's stored 32-byte salt.

### Backup phrase

If no token is present, the user can fall back to a 12-word **BIP39** phrase (128 bits of entropy). The phrase itself is never stored — only its Argon2id PHC hash in `fido2.json`. Verification reconstructs `hmac_secret` from the phrase via the same SHA-256 derivation (same domain separator).

### Slot storage (`~/.config/ashypass/fido2.json`)

```json
{
  "enabled": true,
  "slots": [
    {
      "credential_id": "<base64 raw bytes>",
      "salt":          "<base64 32 bytes>",
      "registered_at": 1715300000,
      "nickname":      "YubiKey 5C"
    }
  ],
  "backup_code_hash": "$argon2id$v=19$m=65536,t=3,p=4$…"
}
```

Maximum slots: **2**. Relying party id: `ashypass.local`.

## Test Vectors

### Argon2id key derivation

```
password = "correct horse battery staple"
salt     = "ashypass-test-salt"
params   = t=3, m=65536, p=4, len=32
→ key (hex) = (implementation-defined for the exact build; verified equal between
              Rust client and reference Python in tests, see argon2_kdf tests)
```

Deterministic by construction — two runs with the same (password, salt, params) MUST produce the same 32-byte output.

### AES-256-GCM blob

```
key (hex)       = 4242…42 (32 bytes)
plaintext       = "hello world"
→ ciphertext blob starts with 0x02, followed by a 12-byte random nonce,
  followed by 11 bytes of AES-GCM ciphertext, followed by a 16-byte tag.
  Two encrypts of the same plaintext produce different blobs (nonce randomness).
```

### TOTP (RFC 6238 Appendix B-like)

```
secret (Base32) = "JBSWY3DPEHPK3PXP"
algorithm       = SHA1
digits          = 6
period          = 30
timestamp       = 1234567890
counter         = 1234567890 / 30 = 41152263
→ expected OTP  = "005924"
```

## Security Properties

1. **At-rest encryption** — every sensitive column is AEAD-protected (AES-256-GCM).
2. **Memory-hard KDF** — Argon2id `t=3, m=64 MiB, p=4` for both verification and derivation.
3. **Authenticated** — GCM tag verifies ciphertext and version byte; tamper → decrypt failure.
4. **Forward secrecy on password change** — new salt + new key + atomic re-encrypt.
5. **Atomic migration** — v1 → v2 happens inside one transaction; partial failure rolls back.
6. **TOTP secrets encrypted** — same v2 envelope as passwords.
7. **Clipboard auto-clear** — both passwords and TOTP codes scheduled for clear; only cleared if contents still match what was written.
8. **Optional 2FA** — vault key is XOR-mixed with an authenticator-derived secret; loss of token still allows recovery via the BIP39 backup phrase, whose hash is the only persisted proof.
9. **Zero-knowledge cloud backup** — Google Drive only ever sees the encrypted SQLite file.

---

## External Drive Encryption (LUKS2)

The `ashypass-drives` crate adds optional full-volume encryption for
removable storage (USB sticks, external HDDs/SSDs). Unlike the password
vault, which operates on individual database columns, drive encryption
must protect every sector of the block device — a different threat model
and therefore a different cipher mode.

### Why LUKS2, not a homegrown stack

`dm-crypt` + LUKS2 is the Linux kernel's audited full-disk encryption
layer, used by every mainstream distribution's installer. AES-NI hardware
acceleration in the kernel is something userspace cannot match. We wrap
`cryptsetup` rather than re-implement.

### Parameters (single source of truth: `crates/ashypass-drives/src/luks.rs`)

| Parameter            | Value                  | Rationale |
|----------------------|------------------------|-----------|
| LUKS version         | 2                      | Argon2id support; per-keyslot KDF tuning; JSON metadata |
| Cipher               | `aes-xts-plain64`      | NIST-approved storage-at-rest mode; `plain64` IV works above 2 TiB |
| Key size             | 512 bits               | XTS splits into two 256-bit keys → AES-256 effective |
| Hash (AF splitter)   | SHA-256                | |
| KDF                  | Argon2id               | Memory-hard; GPU/ASIC-resistant |
| KDF memory           | 1 048 576 KiB (1 GiB)  | Floor; cryptsetup may raise based on host RAM |
| KDF parallelism      | 4                      | |
| KDF iter-time        | 2 000 ms               | Target unlock latency |
| Sector size          | 4096 bytes             | Matches modern flash; avoids 512↔4K translation cost |
| Master key entropy   | `--use-random`         | Pulls from `/dev/random` at format time |
| Passphrase transport | stdin via `--key-file=-` | Never appears in argv or `/proc/<pid>/cmdline` |

### Pre-format wipe

`cryptsetup luksFormat` does not erase the data region. To make recovered
plaintext from prior writes indistinguishable from ciphertext, we open the
device with a plain dm-crypt mapping keyed from `/dev/urandom`, then write
zeros through that mapping. The kernel encrypts the zeros at AES-NI speed
(GB/s), so the device sees random-looking ciphertext across every sector.

For SSDs, `blkdiscard --secure` is offered as a faster opt-in, with a
clear warning that its guarantees depend on the device firmware.

### Safety preconditions

Before any destructive operation, `safety::inspect` refuses to proceed if:

- the device is not flagged removable or hotplug, **and** `allow_fixed` is off;
- the device is read-only;
- any partition is currently mounted;
- the device or any partition backs the running root filesystem (`/proc/mounts`);
- the device holds an active swap area (`/proc/swaps`);
- the device is referenced in `/etc/crypttab`.

The device is then re-resolved through `/dev/disk/by-id/...` and pinned for
the remainder of the pipeline, so udev re-numbering during a hotplug storm
cannot redirect the operation to a sibling.

### Privilege

Privileged calls (`cryptsetup`, `dd`, `mkfs.*`, `blkdiscard`) are dispatched
via `pkexec`, mediated by the polkit policy in
`usr/share/polkit-1/actions/com.bigcommunity.ashypass.drives.policy`.

### Passphrase handling

Passphrases live in `ashypass_drives::Passphrase`, which `Zeroize`s its
buffer on drop and is never `Clone`. They are written straight to the
child's stdin and never logged or echoed.

### Future work (not in this iteration)

- FIDO2 keyslot enrollment via `systemd-cryptenroll --fido2-device=auto`.
- Keyfile keyslot whose key material is stored as a vault item.
- Privileged helper binary (`/usr/libexec/ashypass/drives-helper`) with a
  scoped polkit action ID, replacing direct `pkexec cryptsetup` so users
  get a branded prompt and we limit what the elevated process can do.
- Loopback integration tests gated behind `cargo test -- --ignored`.

---

## Updates (2026-05-23)

- **`drives info --json`**: emits the full LUKS2 metadata via `cryptsetup
  luksDump --dump-json-metadata`, including the Argon2id keyslot tuning
  parameters (memory, iterations, parallelism) that the human-readable
  dump omits.
- **`drives format --quick`**: opt-in shortcut for `--wipe none`. Documented
  as Mint/Cryptomator-equivalent: instant, but prior plaintext outside the
  LUKS data region may survive.
- **`drives enroll-fido2`**: wraps `systemd-cryptenroll --fido2-device=auto`
  to add a FIDO2 hardware-token keyslot on an existing volume. Toggles for
  PIN and user-presence (touch) are exposed as flags.
- **Wipe progress source switched** from `dd status=progress` stderr parsing
  to `/proc/diskstats` polled on a 200 ms cadence in a `std::thread::scope`
  worker. Reason: the `dd → sudo → pty → pipe` chain buffers progress
  updates unreliably; the kernel's diskstats counter is impossible to
  buffer-out-of.
- **Plain-mode wipe key material** is now read by Ashy Pass (64 random
  bytes from `/dev/urandom`) and piped to `cryptsetup` via stdin
  (`--key-file -`), instead of pointing `cryptsetup` at `/dev/urandom`
  directly. Avoids version-dependent behaviour where `--keyfile-size` is
  ignored for special files and `cryptsetup` reads urandom forever.

### Privileged helper

A separate binary `ashypass-drives-helper` is now shipped under
`/usr/libexec/ashypass/`. Launched once via `pkexec` (single polkit
authentication), it accepts JSON-Lines requests on stdin and writes
responses on stdout. Operations: `luks-format`, `luks-open`, `luks-close`,
`wipe`, `mkfs`, `shutdown`. Passphrases are transmitted base64-encoded so
binary data is safe across the line protocol.

The polkit action `com.bigcommunity.ashypass.drives.helper` is annotated
with `org.freedesktop.policykit.exec.path` pointing at the helper, and
`allow_active=auth_admin_keep` so a session-wide authentication covers
the entire encrypt/unlock workflow.

Client side, `ashypass_drives::helper_client::HelperClient` spawns the
helper and exposes typed methods. The GUI wizard does not yet route
through it (still uses `PkexecRunner`, one prompt per call); the switch
is mechanical and tracked as future work.
