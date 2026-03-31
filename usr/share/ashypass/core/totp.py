#!/usr/bin/env python3
"""Ashy Pass - TOTP Module - RFC 6238 Time-Based One-Time Password generation"""

import base64
import hashlib
import hmac
import struct
import time
import logging
from typing import Optional
from urllib.parse import parse_qs, unquote, urlparse

logger = logging.getLogger(__name__)

# Supported algorithms
ALGORITHMS = {
    "SHA1": hashlib.sha1,
    "SHA256": hashlib.sha256,
    "SHA512": hashlib.sha512,
}


def generate_totp(
    secret: str,
    algorithm: str = "SHA1",
    digits: int = 6,
    period: int = 30,
    timestamp: Optional[float] = None,
) -> str:
    """Generate a TOTP code per RFC 6238.

    Args:
        secret: Base32-encoded shared secret.
        algorithm: Hash algorithm (SHA1, SHA256, SHA512).
        digits: Number of digits in the OTP (6 or 8).
        period: Time step in seconds.
        timestamp: Unix timestamp (defaults to current time).

    Returns:
        Zero-padded OTP string.
    """
    if timestamp is None:
        timestamp = time.time()

    # Decode base32 secret (tolerate spaces and lowercase)
    clean_secret = secret.replace(" ", "").upper()
    # Pad to multiple of 8 for base32
    padding = (8 - len(clean_secret) % 8) % 8
    clean_secret += "=" * padding
    key = base64.b32decode(clean_secret)

    # Calculate time counter
    counter = int(timestamp) // period
    counter_bytes = struct.pack(">Q", counter)

    # HMAC
    hash_func = ALGORITHMS.get(algorithm.upper())
    if hash_func is None:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    mac = hmac.new(key, counter_bytes, hash_func).digest()

    # Dynamic truncation (RFC 4226 §5.4)
    offset = mac[-1] & 0x0F
    code_int = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF
    code = code_int % (10**digits)

    return str(code).zfill(digits)


def remaining_seconds(period: int = 30) -> int:
    """Return seconds remaining in the current TOTP period."""
    return period - (int(time.time()) % period)


def parse_otpauth_uri(uri: str) -> dict:
    """Parse an otpauth:// URI into TOTP parameters.

    Supports:
        otpauth://totp/Issuer:account?secret=BASE32&issuer=Issuer&algorithm=SHA1&digits=6&period=30

    Returns:
        Dict with keys: type, label, issuer, secret, algorithm, digits, period.
    """
    parsed = urlparse(uri)
    if parsed.scheme != "otpauth":
        raise ValueError("Not an otpauth URI")

    otp_type = parsed.hostname  # "totp" or "hotp"
    if otp_type != "totp":
        raise ValueError(f"Unsupported OTP type: {otp_type}")

    # Label: /Issuer:account or /account
    label = unquote(parsed.path.lstrip("/"))
    params = parse_qs(parsed.query)

    secret = params.get("secret", [None])[0]
    if not secret:
        raise ValueError("Missing secret parameter")

    issuer = params.get("issuer", [None])[0]
    if not issuer and ":" in label:
        issuer = label.split(":", 1)[0]

    account = label.split(":", 1)[-1] if ":" in label else label

    return {
        "type": otp_type,
        "label": account,
        "issuer": issuer or "",
        "secret": secret,
        "algorithm": params.get("algorithm", ["SHA1"])[0].upper(),
        "digits": int(params.get("digits", [6])[0]),
        "period": int(params.get("period", [30])[0]),
    }
