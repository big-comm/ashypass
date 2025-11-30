# Ashy Pass

<p align="center">
  <img src="https://github.com/big-comm/ashypass/blob/main/usr/share/icons/hicolor/scalable/apps/ashypass.svg" alt="Ashy Pass Logo" width="128" height="128">
</p>

<p align="center">
  <strong>Secure Password Manager with Advanced Generation</strong>
</p>

<p align="center">
  <a href="https://github.com/big-comm/ashypass/releases"><img src="https://img.shields.io/badge/Version-1.0.0-blue.svg" alt="Version"/></a>
  <a href="https://bigcommunity.com"><img src="https://img.shields.io/badge/BigCommunity-Platform-blue" alt="BigCommunity Platform"/></a>
  <a href="https://github.com/big-comm/ashypass/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License"/></a>
  <a href="https://www.gtk.org/"><img src="https://img.shields.io/badge/GTK-4.0+-orange.svg" alt="GTK Version"/></a>
  <a href="https://gnome.pages.gitlab.gnome.org/libadwaita/"><img src="https://img.shields.io/badge/libadwaita-1.0+-purple.svg" alt="libadwaita Version"/></a>
</p>

---

## Overview

Ashy Pass is a modern, secure password manager built with GTK4 and libadwaita, designed for GNOME desktop environments. It provides military-grade encryption, intelligent password generation, seamless vault management with automatic session locking, and cloud backup via Google Drive.

## Features

### 🔐 Security
- **Military-grade encryption** with Argon2 key derivation and Fernet (AES-256)
- **Automatic session locking** after 30 seconds of inactivity
- **Secure password generation** using Python's cryptographically secure `secrets` module
- **Master password protection** with PBKDF2 hashing
- **Zero-knowledge architecture** - your master password never leaves your device

### 🎲 Password Generation
- **Strong passwords** with configurable length (8-64 characters) and character sets
- **Passphrases** using EFF wordlist (3-10 words with customizable separators)
- **PIN codes** for numeric-only requirements (4-12 digits)
- **Quick generation** directly in vault dialogs with preset options:
  - Strong Password (16 chars, all types)
  - Passphrase (4 words)
  - PIN Code (6 digits)
  - Custom... (full generator dialog)
- **Real-time strength indicator** with visual feedback (Weak, Medium, Strong, Very Strong)

### 💾 Vault Management
- **Encrypted storage** for passwords, usernames, URLs, and notes
- **Automatic favicon fetching** and caching for visual identification
- **Search functionality** to quickly find stored credentials
- **One-click password copying** to clipboard with security timeout
- **In-vault password generator** with dropdown menu integration

### ☁️ Cloud Backup & Sync
- **Google Drive integration** with OAuth 2.0 authentication
- **Automatic encrypted backups** to your Google Drive
- **Manual backup on demand** via Settings
- **Secure token storage** with automatic refresh
- **User-specific backups** in dedicated folder

### 📤 Import/Export
- **CSV import** from Google Chrome, Firefox, and other password managers
- **CSV export** compatible with Google Chrome password manager
- **Bulk password migration** with automatic field mapping
- **Backup to local files** for offline storage

### 🎨 User Interface
- **Modern GNOME design** following libadwaita guidelines
- **Responsive layout** adapting to window size
- **Dark mode support** with automatic theme switching
- **Intuitive navigation** with view switcher
- **Toast notifications** for user feedback
- **Multi-language support** with gettext internationalization

## System Requirements

### Minimum
- **OS:** Linux with GTK 4.0 support
- **Python:** 3.10 or higher
- **Memory:** 256 MB RAM
- **Storage:** 50 MB available space

### Recommended
- **Desktop:** GNOME 43+ or compatible environment
- **Display:** 1280x720 resolution or higher
- **Internet:** For Google Drive backup and favicon fetching

## Installation

### From Package Manager

```bash
# Arch Linux / Manjaro
sudo pacman -U ashypass-*.pkg.tar.zst
```

### Manual Installation

```bash
# Clone the repository
git clone https://github.com/big-comm/ashypass.git
cd ashypass

# Install dependencies
pip install -r requirements.txt

# Run the application
python3 main.py
```

## Usage

### First-Time Setup

1. Launch Ashy Pass from your application menu
2. Navigate to the **Vault** tab
3. Create a strong master password (minimum 8 characters)
4. Confirm your master password

### Generating Passwords

**Quick Generation:**
1. Go to the **Generator** tab
2. Select type: Password, Passphrase, or PIN
3. Adjust options as needed
4. Click **Copy to Clipboard** or **Generate New**

**In-Vault Generation:**
1. Click the **+** button in the Vault toolbar
2. Click the generation button (⚡) next to the password field
3. Choose from preset options:
   - **Strong Password** - 16 characters with all character types
   - **Passphrase** - 4 words separated by hyphens
   - **PIN Code** - 6-digit numeric code
   - **Custom...** - Opens full generator with all options

### Managing Vault Entries

- **Add:** Click the **+** button, fill in details, and save
- **Edit:** Click the edit icon on any entry
- **Copy:** Click the copy icon to copy password to clipboard
- **Delete:** Click the trash icon and confirm deletion
- **Search:** Use the search bar to filter entries by title, username, or URL
- **Favicons:** Automatically fetched from URLs for visual identification

### Google Drive Backup

**Setup:**
1. Click the **Settings** icon (⚙️) in the toolbar
2. Go to **Cloud Backup** tab
3. Click **Sign in with Google**
4. Authorize Ashy Pass in your browser
5. Your encrypted vault will automatically backup

**Manual Backup:**
1. Open **Settings** → **Cloud Backup**
2. Click **Backup Now**
3. Encrypted database uploaded to Google Drive

**Note:** All backups are encrypted with your master password. Google cannot access your passwords.

### Import/Export Passwords

**Import from CSV:**
1. Open **Settings** → **Import/Export**
2. Click the import icon
3. Select your CSV file (from Chrome, Firefox, etc.)
4. Passwords are automatically added to your vault

**Export to CSV:**
1. Open **Settings** → **Import/Export**
2. Click the export icon
3. Choose save location
4. File can be imported to Google Chrome: `chrome://password-manager/settings`

**CSV Format (Google Chrome compatible):**
```csv
name,url,username,password,note
GitHub,https://github.com,user@email.com,MySecurePass123,Development account
```

### Security Best Practices

- Use a **strong master password** (16+ characters with mixed case, numbers, symbols)
- Enable **Google Drive backup** for disaster recovery
- Regularly **export backups** to external storage
- Never share your **master password** with anyone
- Keep your system and Ashy Pass **updated**

## Configuration

Configuration file: `~/.config/ashypass/config.json`

```json
{
  "session_timeout": 30,
  "auto_lock": true,
  "clipboard_timeout": 45,
  "default_password_length": 16,
  "theme": "auto"
}
```

Data directory: `~/.local/share/ashypass/`
- `passwords.db` - Encrypted password database
- `token.pickle` - Google Drive authentication token
- `favicons/` - Cached website icons

## Architecture

Ashy Pass follows a three-layer architecture:

```
ashypass/
├── core/                  # Business logic and security
│   ├── auth.py            # Session management
│   ├── database.py        # Encrypted storage (Argon2 + Fernet)
│   ├── generator.py       # Password generation
│   ├── backup_service.py  # Google Drive integration
│   ├── csv_handler.py     # Import/Export functionality
│   ├── client_secrets.py  # OAuth credentials
│   └── config.py          # Application settings
├── ui/                    # GTK4/libadwaita interface
│   ├── window.py          # Main application window
│   ├── generator_view.py  # Generator interface
│   ├── vault_view.py      # Vault interface
│   └── settings_dialog.py # Settings and preferences
└── utils/                 # Utilities
    ├── clipboard.py       # Clipboard operations
    └── i18n.py            # Internationalization (gettext)
```

**Security Flow:**
1. Master password → Argon2 KDF → Encryption key
2. Passwords → Fernet encryption → SQLite database
3. Decryption → Session verification → Display
4. Google Drive → Encrypted database upload → Secure cloud storage

**Google Drive Integration:**
- OAuth 2.0 authentication with `openid`, `drive.file`, `userinfo.email` scopes
- Encrypted database backups in "AshyPass Backups" folder
- Automatic token refresh for seamless access
- No access to passwords by Google (zero-knowledge)

## Development

### Setup Development Environment

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run in development mode
python3 main.py
```

### Building Translations

```bash
# Extract translatable strings
xgettext --language=Python --keyword=_ --output=locale/ashypass.pot *.py ui/*.py core/*.py utils/*.py

# Compile translations
msgfmt locale/pt_BR/LC_MESSAGES/ashypass.po -o locale/pt_BR/LC_MESSAGES/ashypass.mo
```

### Code Style

- Follow **PEP 8** guidelines
- Use **type hints** for function signatures
- Document classes and methods with **docstrings**
- Keep functions **focused and testable**
- Use `_()` function for all user-facing strings (i18n)

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- **EFF Wordlist** for passphrase generation
- **GNOME Team** for GTK4 and libadwaita
- **Python Cryptography** library for encryption primitives
- **Google Drive API** for cloud backup functionality

---

<p align="center">
  <strong>Built with ❤️ for the GNOME community</strong>
</p>

<p align="center">
  <a href="https://github.com/big-comm/ashypass/issues">Report Bug</a> •
  <a href="https://github.com/big-comm/ashypass/issues">Request Feature</a>
</p>
