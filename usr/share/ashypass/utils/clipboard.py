#!/usr/bin/env python3
"""Ashy Pass - Clipboard Utilities"""

from typing import Optional
from gi.repository import Gdk, GLib

from core.config import CLIPBOARD_CLEAR_SECONDS


class ClipboardManager:
    """Manages clipboard operations with security features"""
    
    def __init__(self):
        self.display = Gdk.Display.get_default()
        self.clipboard = self.display.get_clipboard()
        self._clear_timeout_id: Optional[int] = None
    
    def copy_text(self, text: str, auto_clear: bool = True, timeout: int = CLIPBOARD_CLEAR_SECONDS) -> None:
        """Copy text to clipboard"""
        if self._clear_timeout_id is not None:
            GLib.source_remove(self._clear_timeout_id)
            self._clear_timeout_id = None
        
        self.clipboard.set(text)
        
        if auto_clear:
            self._clear_timeout_id = GLib.timeout_add_seconds(timeout, self._clear_clipboard)
    
    def _clear_clipboard(self) -> bool:
        """Clear clipboard contents"""
        self.clipboard.set("")
        self._clear_timeout_id = None
        return False
    
    def cancel_auto_clear(self) -> None:
        """Cancel scheduled clipboard clear"""
        if self._clear_timeout_id is not None:
            GLib.source_remove(self._clear_timeout_id)
            self._clear_timeout_id = None
