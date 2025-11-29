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

Ashy Pass is a modern, secure password manager built with GTK4 and libadwaita, designed for GNOME desktop environments. It provides military-grade encryption, intelligent password generation, and seamless vault management with automatic session locking.

## Features

### 🔐 Security
- **Military-grade encryption** with Argon2 key derivation and Fernet (AES-256)
- **Automatic session locking** after 30 seconds of inactivity
- **Secure password generation** using Python's cryptographically secure `secrets` module
- **Master password protection** with PBKDF2 hashing

### 🎲 Password Generation
- **Strong passwords** with configurable length (8-64 characters) and character sets
- **Passphrases** using EFF wordlist (3-10 words with customizable separators)
- **PIN codes** for numeric-only requirements (4-12 digits)
- **Quick generation** directly in vault dialogs with preset options
- **Custom generator** with full control over all parameters
- **Real-time strength indicator** with visual feedback

### 💾 Vault Management
- **Encrypted storage** for passwords, usernames, URLs, and notes
- **Automatic favicon fetching** and caching for visual identification
- **Search functionality** to quickly find stored credentials
- **One-click password copying** to clipboard with security timeout
- **Import/Export** capabilities for backup and migration

### 🎨 User Interface
- **Modern GNOME design** following libadwaita guidelines
- **Responsive layout** adapting to window size
- **Dark mode support** with automatic theme switching
- **Intuitive navigation** with view switcher
- **Toast notifications** for user feedback

## System Requirements

### Minimum
- **OS:** Linux with GTK 4.0 support
- **Python:** 3.10 or higher
- **Memory:** 256 MB RAM
- **Storage:** 50 MB available space

### Recommended
- **Desktop:** GNOME 43+ or compatible environment
- **Display:** 1280x720 resolution or higher

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
2. Click the generation button next to the password field
3. Choose from preset options or select **Custom** for full control

### Managing Vault Entries

- **Add:** Click the **+** button, fill in details, and save
- **Edit:** Click the edit icon on any entry
- **Copy:** Click the copy icon to copy password to clipboard
- **Delete:** Click the trash icon and confirm deletion
- **Search:** Use the search bar to filter entries by title, username, or URL

### Security Best Practices

- Use a **strong master password** (16+ characters with mixed case, numbers, symbols)
- Enable **automatic locking** by setting session timeout
- Regularly **backup your vault** using export functionality
- Never share your **master password** with anyone

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

## Architecture

Ashy Pass follows a three-layer architecture:

```
ashypass/
├── core/           # Business logic and security
│   ├── auth.py     # Session management
│   ├── database.py # Encrypted storage
│   ├── generator.py # Password generation
│   └── config.py   # Application settings
├── ui/             # GTK4/libadwaita interface
│   ├── window.py   # Main application window
│   ├── generator_view.py # Generator interface
│   └── vault_view.py     # Vault interface
└── utils/          # Utilities
    ├── clipboard.py # Clipboard operations
    └── i18n.py     # Internationalization
```

**Security Flow:**
1. Master password → Argon2 KDF → Encryption key
2. Passwords → Fernet encryption → SQLite database
3. Decryption → Session verification → Display


### Code Style

- Follow **PEP 8** guidelines
- Use **type hints** for function signatures
- Document classes and methods with **docstrings**
- Keep functions **focused and testable**

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

---

<p align="center">
  <strong>Built with ❤️ for the GNOME community</strong>
</p>

<p align="center">
  <a href="https://github.com/big-comm/ashypass/issues">Report Bug</a> •
  <a href="https://github.com/big-comm/ashypass/issues">Request Feature</a>
</p>
