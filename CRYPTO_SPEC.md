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
