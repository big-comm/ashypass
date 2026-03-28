#!/usr/bin/env python3
"""Ashy Pass - Authentication Module - Session management with automatic timeout"""

import time
from typing import Optional, Callable
from gi.repository import GLib

from core.config import SESSION_TIMEOUT_SECONDS


class SessionManager:
    """Manages authentication session with automatic timeout"""

    WARNING_SECONDS = 10

    def __init__(self, timeout_seconds: int = SESSION_TIMEOUT_SECONDS):
        self.timeout_seconds = timeout_seconds
        self._authenticated = False
        self._last_activity = 0
        self._timeout_id: Optional[int] = None
        self._warning_id: Optional[int] = None
        self._lock_callback: Optional[Callable] = None
        self._warning_callback: Optional[Callable[[int], None]] = None
    
    def login(self) -> None:
        """Mark session as authenticated"""
        self._authenticated = True
        self.reset_timeout()
    
    def logout(self) -> None:
        """End session and clear authentication"""
        self._authenticated = False
        self._cancel_timeout()
        if self._lock_callback:
            self._lock_callback()
    
    def is_authenticated(self) -> bool:
        """Check if session is currently authenticated"""
        return self._authenticated
    
    def on_activity(self) -> None:
        """Reset timeout on user activity"""
        if self._authenticated:
            self.reset_timeout()
    
    def reset_timeout(self) -> None:
        """Reset the inactivity timeout"""
        self._last_activity = time.time()
        self._cancel_timeout()
        # Schedule warning before lock
        warning_delay = max(1, self.timeout_seconds - self.WARNING_SECONDS)
        self._warning_id = GLib.timeout_add_seconds(warning_delay, self._on_warning)
        self._timeout_id = GLib.timeout_add_seconds(self.timeout_seconds, self._on_timeout)
    
    def _cancel_timeout(self) -> None:
        """Cancel active timeout and warning"""
        if self._timeout_id is not None:
            GLib.source_remove(self._timeout_id)
            self._timeout_id = None
        if self._warning_id is not None:
            GLib.source_remove(self._warning_id)
            self._warning_id = None

    def _on_warning(self) -> bool:
        """Notify that session is about to lock"""
        self._warning_id = None
        if self._authenticated and self._warning_callback:
            remaining = self.get_remaining_time()
            if remaining > 0:
                self._warning_callback(remaining)
        return False
    
    def _on_timeout(self) -> bool:
        """Handle timeout expiration"""
        self._timeout_id = None
        elapsed = time.time() - self._last_activity
        
        if elapsed >= self.timeout_seconds:
            self.logout()
            return False
        else:
            remaining = self.timeout_seconds - elapsed
            self._timeout_id = GLib.timeout_add_seconds(int(remaining) + 1, self._on_timeout)
            return False
    
    def set_lock_callback(self, callback: Callable) -> None:
        """Set callback to be called when session locks"""
        self._lock_callback = callback

    def set_warning_callback(self, callback: Callable[[int], None]) -> None:
        """Set callback for timeout warning. Receives remaining seconds."""
        self._warning_callback = callback
    
    def get_remaining_time(self) -> int:
        """Get remaining seconds before timeout"""
        if not self._authenticated:
            return 0
        
        elapsed = time.time() - self._last_activity
        return max(0, int(self.timeout_seconds - elapsed))
