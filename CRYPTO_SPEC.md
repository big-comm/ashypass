# CRYPTO_SPEC.md — Ashy Pass Cryptographic Specification

Version: 1.0
Date: 2025-01-01

## Overview

Ashy Pass uses a layered encryption scheme to protect stored passwords and TOTP secrets. This document specifies the exact parameters and algorithms so that any compatible implementation (e.g., Android companion app) can produce identical ciphertext and interoperate with the same database.

## Key Derivation

### Master Password Verification

The master password is verified using **Argon2id** (via the `argon2-cffi` library):

| Parameter    | Value   |
|-------------|---------|
| Variant     | Argon2id |
| Time cost   | 3       |
| Memory cost | 65536 KiB (64 MB) |
| Parallelism | 4       |
| Hash length | 32 bytes |

The Argon2 hash string (PHC format) is stored in the `master.password_hash` column.

### Encryption Key Derivation

The encryption key is derived from the master password using **PBKDF2-HMAC-SHA256**:

```
salt = master.salt  (base64url-encoded 32 random bytes, stored as text)
key  = PBKDF2-HMAC-SHA256(
    password  = master_password.encode('utf-8'),
    salt      = salt.encode('utf-8'),  # the base64url string itself is the salt
    iterations = 100000,
    dklen     = 32
)
fernet_key = base64url_encode(key)
```

The resulting `fernet_key` is used to construct a `cryptography.fernet.Fernet` instance.

## Encryption

All sensitive fields are encrypted using **Fernet** (from the `cryptography` library), which provides:

- **AES-128-CBC** encryption
- **HMAC-SHA256** authentication
- Automatic IV generation (128-bit random)
- Timestamp verification

### Fernet Token Format

```
Version (1 byte) || Timestamp (8 bytes, big-endian) || IV (16 bytes) || Ciphertext (PKCS7 padded) || HMAC (32 bytes)
```

All tokens are base64url-encoded.

### Encrypted Fields

| Column                   | Plaintext encoding |
|--------------------------|-------------------|
| `password_encrypted`     | UTF-8 string      |
| `notes_encrypted`        | UTF-8 string (nullable) |
| `totp_secret_encrypted`  | UTF-8 string (Base32 TOTP secret, nullable) |

## Salt Generation

New vaults generate a 32-byte random salt:

```python
salt = base64.urlsafe_b64encode(os.urandom(32))  # stored as text in DB
```

On master password change, a new salt is generated and all entries are re-encrypted atomically within a transaction.

## Database Schema

### `master` table

| Column         | Type    | Description |
|----------------|---------|-------------|
| id             | INTEGER | Always 1 (single master password) |
| password_hash  | TEXT    | Argon2id PHC hash string |
| salt           | TEXT    | Base64url-encoded 32-byte random salt |
| created_at     | INTEGER | Unix timestamp |

### `passwords` table

| Column                  | Type    | Description |
|-------------------------|---------|-------------|
| id                      | INTEGER | Auto-increment primary key |
| title                   | TEXT    | Entry title (plaintext) |
| username                | TEXT    | Username (plaintext, nullable) |
| password_encrypted      | BLOB    | Fernet-encrypted password |
| notes_encrypted         | BLOB    | Fernet-encrypted notes (nullable) |
| url                     | TEXT    | URL (plaintext, nullable) |
| totp_secret_encrypted   | BLOB    | Fernet-encrypted TOTP Base32 secret (nullable) |
| totp_algorithm          | TEXT    | SHA1, SHA256, or SHA512 (default: SHA1) |
| totp_digits             | INTEGER | 6 or 8 (default: 6) |
| totp_period             | INTEGER | Period in seconds (default: 30) |
| created_at              | INTEGER | Unix timestamp |
| updated_at              | INTEGER | Unix timestamp |
| last_accessed           | INTEGER | Unix timestamp (nullable) |

## TOTP Generation

TOTP codes follow **RFC 6238** (Time-Based One-Time Passwords):

```
counter = floor(unix_timestamp / period)
counter_bytes = big_endian_uint64(counter)
mac = HMAC(algorithm, key=base32_decode(secret), message=counter_bytes)
offset = mac[last_byte] & 0x0F
code = (big_endian_uint32(mac[offset:offset+4]) & 0x7FFFFFFF) % 10^digits
```

### Supported Algorithms

| Algorithm | Hash function |
|-----------|--------------|
| SHA1      | HMAC-SHA1 (default, most common) |
| SHA256    | HMAC-SHA256 |
| SHA512    | HMAC-SHA512 |

### `otpauth://` URI Format

```
otpauth://totp/{issuer}:{account}?secret={BASE32}&issuer={issuer}&algorithm={algo}&digits={digits}&period={period}
```

## Test Vectors

### PBKDF2-HMAC-SHA256

```
Password: "test_password"
Salt:     b"dGVzdF9zYWx0X3ZhbHVlX2Jhc2U2NA=="  (the literal base64 string as bytes)
Iterations: 100000
dklen: 32
→ Derive key, then base64url-encode for Fernet
```

### TOTP (RFC 6238 Appendix B)

```
Secret (Base32): "JBSWY3DPEHPK3PXP"  (decodes to "Hello!ÞÃ\xa7\xa5")
Algorithm: SHA1
Digits: 6
Period: 30
Timestamp: 1234567890
Counter: 1234567890 // 30 = 41152263
→ Expected OTP: "005924"
```

## Security Properties

1. **At-rest encryption**: All sensitive data encrypted with AES via Fernet
2. **Key derivation**: Argon2id provides memory-hard protection against brute-force
3. **Authenticated encryption**: Fernet HMAC-SHA256 prevents tampering
4. **Forward secrecy on password change**: New salt + new key on master password change
5. **Atomic re-encryption**: Transaction rollback on failure during password change
6. **TOTP secrets encrypted**: Same Fernet encryption as passwords
7. **Clipboard auto-clear**: Both passwords and TOTP codes cleared from clipboard after timeout
