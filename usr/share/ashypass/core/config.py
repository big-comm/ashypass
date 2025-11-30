#!/usr/bin/env python3
"""
Ashy Pass - Configuration Module
Application constants and configuration management
"""

import os
from pathlib import Path

# Application Information
APP_ID = "com.bigcommunity.ashypass"  # Restored original ID
APP_NAME = "Ashy Pass"
APP_VERSION = "1.2.1"

# Paths
CONFIG_DIR = Path.home() / ".config" / "ashypass"
DATA_DIR = Path.home() / ".local" / "share" / "ashypass"
DATABASE_PATH = DATA_DIR / "passwords.db"

# Security Settings
SESSION_TIMEOUT_SECONDS = 30
CLIPBOARD_CLEAR_SECONDS = 60
MIN_MASTER_PASSWORD_LENGTH = 8

# Password Generation Defaults
DEFAULT_PASSWORD_LENGTH = 16
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128
DEFAULT_PASSPHRASE_WORDS = 4
MIN_PASSPHRASE_WORDS = 3
MAX_PASSPHRASE_WORDS = 8
DEFAULT_PIN_LENGTH = 6
MIN_PIN_LENGTH = 4
MAX_PIN_LENGTH = 12

# Characters
AMBIGUOUS_CHARS = "il1Lo0O"
DEFAULT_SYMBOLS = "!@#$%&*()-_=+[]{}|;:,.<>?/"

# UI Settings
WINDOW_DEFAULT_WIDTH = 500
WINDOW_DEFAULT_HEIGHT = 800
WINDOW_MIN_WIDTH = 450
WINDOW_MIN_HEIGHT = 800


def ensure_directories() -> None:
    """Create configuration and data directories if they don't exist"""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
