#!/usr/bin/env python3
"""Ashy Pass - Aegis Import Module - Import from Aegis Authenticator JSON export (plain and encrypted)"""

import base64
import hashlib
import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)


class AegisEncryptedError(Exception):
    """Raised when an Aegis export is encrypted and requires a password."""
    pass


def _extract_entries(db_obj: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract TOTP entries from a decrypted Aegis db object."""
    entries = db_obj.get("entries", [])
    results: List[Dict[str, Any]] = []

    for entry in entries:
        if entry.get("type") != "totp":
            logger.info("Skipping non-TOTP entry: %s (type=%s)", entry.get("name"), entry.get("type"))
            continue

        info = entry.get("info", {})
        issuer = entry.get("issuer", "")
        name = entry.get("name", "")

        title = f"{issuer}: {name}" if issuer and name else (issuer or name or "Unknown")

        results.append({
            "title": title,
            "username": name if name != title else None,
            "password": "",
            "totp_secret": info.get("secret", ""),
            "totp_algorithm": info.get("algo", "SHA1").upper(),
            "totp_digits": info.get("digits", 6),
            "totp_period": info.get("period", 30),
            "url": None,
            "notes": f"Imported from Aegis ({issuer})" if issuer else "Imported from Aegis",
        })

    return results


def is_aegis_encrypted(file_path: str) -> bool:
    """Check if an Aegis JSON export is encrypted (db is a string, not a dict)."""
    path = Path(file_path)
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    db = data.get("db")
    return isinstance(db, str)


def parse_aegis_json(file_path: str) -> List[Dict[str, Any]]:
    """Parse an Aegis Authenticator plaintext JSON export.

    Raises AegisEncryptedError if the export is encrypted (use parse_aegis_encrypted instead).

    Returns:
        List of dicts with keys: title, username, totp_secret, totp_algorithm,
        totp_digits, totp_period, url, notes.
    """
    path = Path(file_path)
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    db = data.get("db", {})
    if isinstance(db, str):
        raise AegisEncryptedError(
            "This Aegis export is encrypted. Please provide the password to decrypt it."
        )

    results = _extract_entries(db)
    logger.info("Parsed %d TOTP entries from Aegis plaintext export", len(results))
    return results


def parse_aegis_encrypted(file_path: str, password: str) -> List[Dict[str, Any]]:
    """Parse an Aegis Authenticator encrypted JSON export.

    Decryption process:
    1. Find a password-type slot (type=1) in header.slots
    2. Derive key from password using scrypt with slot's salt/N/r/p
    3. Decrypt the master key from slot using AES-256-GCM
    4. Decrypt the db payload using the master key with AES-256-GCM
    5. Parse the decrypted JSON and extract entries

    Args:
        file_path: Path to the encrypted Aegis JSON export
        password: The password used to encrypt the Aegis vault

    Returns:
        List of TOTP entry dicts.

    Raises:
        ValueError: If decryption fails (wrong password or corrupted data)
    """
    path = Path(file_path)
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    header = data.get("header", {})
    db_b64 = data.get("db", "")

    if not isinstance(db_b64, str) or not db_b64:
        raise ValueError("Expected encrypted Aegis export but db is not an encrypted string.")

    # Find a password slot (type 1)
    slots = header.get("slots", [])
    password_slot = None
    for slot in slots:
        if slot.get("type") == 1:
            password_slot = slot
            break

    if password_slot is None:
        raise ValueError("No password slot found in Aegis export. Biometric-only vaults are not supported.")

    # Derive key from password using scrypt
    salt = bytes.fromhex(password_slot["salt"])
    n = password_slot["n"]
    r = password_slot["r"]
    p = password_slot["p"]

    # Calculate required memory: 128 * N * r bytes, plus margin
    maxmem = 128 * n * r * 2

    derived_key = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=n,
        r=r,
        p=p,
        dklen=32,
        maxmem=maxmem,
    )

    # Decrypt the master key from the slot
    slot_key_enc = bytes.fromhex(password_slot["key"])
    key_params = password_slot["key_params"]
    slot_nonce = bytes.fromhex(key_params["nonce"])
    slot_tag = bytes.fromhex(key_params["tag"])

    try:
        aesgcm = AESGCM(derived_key)
        master_key = aesgcm.decrypt(slot_nonce, slot_key_enc + slot_tag, None)
    except Exception:
        raise ValueError("Wrong password or corrupted Aegis export.")

    # Decrypt the database content
    header_params = header.get("params", {})
    db_nonce = bytes.fromhex(header_params["nonce"])
    db_tag = bytes.fromhex(header_params["tag"])
    db_encrypted = base64.b64decode(db_b64)

    try:
        aesgcm_master = AESGCM(master_key)
        db_json_bytes = aesgcm_master.decrypt(db_nonce, db_encrypted + db_tag, None)
    except Exception:
        raise ValueError("Failed to decrypt Aegis database. Data may be corrupted.")

    db_obj = json.loads(db_json_bytes.decode("utf-8"))
    results = _extract_entries(db_obj)
    logger.info("Parsed %d TOTP entries from Aegis encrypted export", len(results))
    return results
