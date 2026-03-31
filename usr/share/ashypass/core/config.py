#!/usr/bin/env python3
"""
Ashy Pass - Configuration Module
Application constants and configuration management
"""

import os
import json
import logging
from pathlib import Path
from typing import Any, Dict

logger = logging.getLogger(__name__)

# Application Information
APP_ID = "com.bigcommunity.ashypass"  # Restored original ID
APP_NAME = "Ashy Pass"
APP_VERSION = "2.1.0"

# Paths
CONFIG_DIR = Path.home() / ".config" / "ashypass"
DATA_DIR = Path.home() / ".local" / "share" / "ashypass"
DATABASE_PATH = DATA_DIR / "passwords.db"
CONFIG_FILE = CONFIG_DIR / "settings.json"

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
WINDOW_DEFAULT_WIDTH = 900
WINDOW_DEFAULT_HEIGHT = 650
WINDOW_MIN_WIDTH = 700
WINDOW_MIN_HEIGHT = 500


def ensure_directories() -> None:
    """Create configuration and data directories if they don't exist"""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def load_settings() -> Dict[str, Any]:
    """Load user settings from JSON file"""
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError, ValueError):
            pass
    return {}


def save_settings(settings: Dict[str, Any]) -> None:
    """Save user settings to JSON file"""
    ensure_directories()
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(settings, f, indent=2)
    except Exception as e:
        logger.error("Error saving settings: %s", e)
