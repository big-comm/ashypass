#!/usr/bin/env python3
"""Ashy Pass - Favicon Utility - Async favicon loading with caching"""

import hashlib
import os
import re
import threading
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("GdkPixbuf", "2.0")
from gi.repository import Gtk, GLib, GdkPixbuf

from core.config import DATA_DIR, load_settings

# Favicon cache directory
FAVICON_CACHE_DIR = DATA_DIR / "favicons"
FAVICON_CACHE_DIR.mkdir(parents=True, exist_ok=True)

# Fallback favicon paths to try (prefer PNG over ICO for better GTK compat)
_FAVICON_PATHS = [
    "/apple-touch-icon.png",
    "/apple-touch-icon-precomposed.png",
    "/favicon.png",
    "/favicon.ico",
]

# Well-known Android package → domain overrides
_PACKAGE_OVERRIDES = {
    "com.alibaba.aliexpresshd": "aliexpress.com",
    "com.aliexpress.aer": "aliexpress.com",
    "com.disney.disneyplus": "disneyplus.com",
    "com.xiaomi.smarthome": "home.mi.com",
    "com.itau": "itau.com.br",
    "com.bradesco": "bradesco.com.br",
    "com.nu.production": "nubank.com.br",
    "com.mercadopago.wallet": "mercadopago.com.br",
    "com.mercadolibre": "mercadolivre.com.br",
    "tv.twitch.android.app": "twitch.tv",
    "com.spotify.music": "spotify.com",
    "com.netflix.mediaclient": "netflix.com",
    "com.amazon.mShop.android.shopping": "amazon.com",
    "com.whatsapp": "whatsapp.com",
    "org.telegram.messenger": "telegram.org",
    "com.twitter.android": "x.com",
    "com.zhiliaoapp.musically": "tiktok.com",
    "com.github.android": "github.com",
    "com.microsoft.teams": "teams.microsoft.com",
    "com.discord": "discord.com",
    "com.valve.android.steamcommunity": "store.steampowered.com",
    "com.cloudflare.onedotonedotonedotone": "cloudflare.com",
}


def _domain_from_android_package(package: str) -> str | None:
    """Derive a web domain from an Android package name.

    Uses known overrides first, then heuristic extraction.
    """
    # Check overrides first
    pkg_lower = package.lower()
    if pkg_lower in _PACKAGE_OVERRIDES:
        return _PACKAGE_OVERRIDES[pkg_lower]

    parts = package.split(".")
    if len(parts) < 2:
        return None

    # Remove generic TLD and suffix components
    skip = {
        "com", "org", "net", "br", "io", "de", "fr", "uk", "co", "tv",
        "android", "app", "mobile", "wallet", "client", "production",
        "messenger", "music", "mediaclient", "shopping",
    }
    meaningful = [p for p in parts if p.lower() not in skip and len(p) > 1]
    if not meaningful:
        if len(parts) >= 2:
            return f"{parts[1]}.com"
        return None

    # Use the longest meaningful part (typically the brand name)
    brand = max(meaningful, key=len)
    return f"{brand}.com"


def _extract_domain(url: str) -> str | None:
    """Extract domain from URL, including android:// package URIs."""
    if not url:
        return None
    try:
        # Handle android:// URIs: android://hash@com.package.name/
        if url.startswith("android://"):
            match = re.search(r"@([a-zA-Z0-9_.]+)/?", url)
            if match:
                package = match.group(1)
                return _domain_from_android_package(package)
            return None

        parsed = urllib.parse.urlparse(url)
        if not parsed.scheme:
            url = f"https://{url}"
            parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc
        return domain if domain else None
    except (ValueError, AttributeError):
        return None


def _cache_path_for(domain: str) -> Path:
    """Get cache file path for a domain."""
    url_hash = hashlib.sha256(domain.encode()).hexdigest()[:16]
    return FAVICON_CACHE_DIR / f"{url_hash}.png"


def _download_favicon(domain: str, cache_path: Path) -> bool:
    """Try to download a favicon from multiple paths. Returns True on success."""
    headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}

    # 1. Try DuckDuckGo icons API first (best coverage, returns PNG)
    try:
        ddg_url = f"https://icons.duckduckgo.com/ip3/{domain}.ico"
        req = urllib.request.Request(ddg_url, headers=headers)
        with urllib.request.urlopen(req, timeout=5) as response:
            data = response.read()
            if len(data) > 100:
                with open(cache_path, "wb") as f:
                    f.write(data)
                return True
    except (urllib.error.URLError, OSError, ValueError):
        pass

    # 2. Try direct paths on the domain
    for path in _FAVICON_PATHS:
        favicon_url = f"https://{domain}{path}"
        try:
            req = urllib.request.Request(favicon_url, headers=headers)
            with urllib.request.urlopen(req, timeout=5) as response:
                data = response.read()
                if len(data) > 100:
                    with open(cache_path, "wb") as f:
                        f.write(data)
                    return True
        except (urllib.error.URLError, OSError, ValueError):
            continue

    return False


def load_favicon_async(url: str, image_widget: Gtk.Image) -> None:
    """Load favicon for a URL into a Gtk.Image widget, asynchronously."""
    # Check if favicons are enabled in settings
    settings = load_settings()
    if not settings.get("show_favicons", True):
        return

    domain = _extract_domain(url)
    if not domain:
        return

    cache_path = _cache_path_for(domain)

    # Already cached — load directly
    if cache_path.exists():
        GLib.idle_add(_update_image, image_widget, str(cache_path))
        return

    def _download():
        if _download_favicon(domain, cache_path):
            GLib.idle_add(_update_image, image_widget, str(cache_path))

    thread = threading.Thread(target=_download, daemon=True)
    thread.start()


def _update_image(image_widget: Gtk.Image, path: str) -> bool:
    """Update image widget in the main thread using GdkPixbuf for reliable format support."""
    try:
        if os.path.exists(path):
            pixbuf = GdkPixbuf.Pixbuf.new_from_file_at_scale(path, 32, 32, True)
            image_widget.set_from_pixbuf(pixbuf)
    except (GLib.Error, Exception):
        pass
    return False
