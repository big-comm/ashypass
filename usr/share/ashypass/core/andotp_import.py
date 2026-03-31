#!/usr/bin/env python3
"""Ashy Pass - andOTP Import Module - Import from andOTP plaintext JSON backup"""

import json
import logging
from pathlib import Path
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


def parse_andotp_json(file_path: str) -> List[Dict[str, Any]]:
    """Parse an andOTP plaintext JSON backup.

    Expected structure (array of entries):
        [{"secret": "BASE32", "issuer": "Example", "label": "user@example.com",
          "type": "TOTP", "algorithm": "SHA1", "digits": 6, "period": 30}]

    Returns:
        List of dicts with keys: title, username, totp_secret, totp_algorithm,
        totp_digits, totp_period, url, notes.
    """
    path = Path(file_path)
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError("Invalid andOTP format: expected a JSON array of entries.")

    results: List[Dict[str, Any]] = []

    for entry in data:
        entry_type = entry.get("type", "").upper()
        if entry_type != "TOTP":
            logger.info("Skipping non-TOTP entry: %s (type=%s)", entry.get("issuer"), entry_type)
            continue

        issuer = entry.get("issuer", "")
        label = entry.get("label", "")
        secret = entry.get("secret", "")

        if not secret:
            logger.warning("Skipping entry without secret: %s", issuer or label)
            continue

        title = f"{issuer}: {label}" if issuer and label else (issuer or label or "Unknown")

        results.append({
            "title": title,
            "username": label if label != title else None,
            "password": "",
            "totp_secret": secret,
            "totp_algorithm": entry.get("algorithm", "SHA1").upper(),
            "totp_digits": entry.get("digits", 6),
            "totp_period": entry.get("period", 30),
            "url": None,
            "notes": f"Imported from andOTP ({issuer})" if issuer else "Imported from andOTP",
        })

    logger.info("Parsed %d TOTP entries from andOTP backup", len(results))
    return results
