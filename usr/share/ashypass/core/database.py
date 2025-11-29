#!/usr/bin/env python3
"""Ashy Pass - Database Module - Encrypted SQLite password storage"""

import sqlite3
import time
from pathlib import Path
from typing import Optional, List, Dict, Any
import hashlib
import base64

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet

from core.config import DATABASE_PATH


class Database:
    """Manages encrypted password storage"""
    
    def __init__(self, db_path: Path = DATABASE_PATH):
        self.db_path = db_path
        self.connection: Optional[sqlite3.Connection] = None
        self.ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
        self._fernet: Optional[Fernet] = None
    
    def connect(self) -> None:
        """Establish database connection"""
        self.connection = sqlite3.connect(str(self.db_path))
        self.connection.row_factory = sqlite3.Row
    
    def close(self) -> None:
        """Close database connection"""
        if self.connection:
            self.connection.close()
            self.connection = None
        self._fernet = None
    
    def initialize(self) -> None:
        """Create database tables if they don't exist"""
        if not self.connection:
            self.connect()
        
        cursor = self.connection.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS master (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                username TEXT,
                password_encrypted BLOB NOT NULL,
                notes_encrypted BLOB,
                url TEXT,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                last_accessed INTEGER
            )
        """)
        
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_passwords_title ON passwords(title)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_passwords_username ON passwords(username)")
        
        self.connection.commit()
    
    def has_master_password(self) -> bool:
        """Check if master password is set"""
        if not self.connection:
            self.connect()
        
        cursor = self.connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM master")
        return cursor.fetchone()[0] > 0
    
    def set_master_password(self, password: str) -> bool:
        """Set the master password (first-time setup)"""
        if not self.connection:
            self.connect()
        
        if self.has_master_password():
            return False
        
        salt = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())
        password_hash = self.ph.hash(password)
        
        cursor = self.connection.cursor()
        cursor.execute(
            "INSERT INTO master (id, password_hash, salt, created_at) VALUES (1, ?, ?, ?)",
            (password_hash, salt.decode(), int(time.time())),
        )
        self.connection.commit()
        
        self._derive_encryption_key(password, salt)
        return True
    
    def verify_master_password(self, password: str) -> bool:
        """Verify master password and unlock database"""
        if not self.connection:
            self.connect()
        
        cursor = self.connection.cursor()
        cursor.execute("SELECT password_hash, salt FROM master WHERE id = 1")
        row = cursor.fetchone()
        
        if not row:
            return False
        
        try:
            self.ph.verify(row["password_hash"], password)
            self._derive_encryption_key(password, row["salt"].encode())
            return True
        except VerifyMismatchError:
            return False
    
    def _derive_encryption_key(self, password: str, salt: bytes) -> None:
        """Derive Fernet encryption key from master password"""
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)
        self._fernet = Fernet(base64.urlsafe_b64encode(key))
    
    def _encrypt(self, data: str) -> bytes:
        """Encrypt data using Fernet"""
        if not self._fernet:
            raise RuntimeError("Database not unlocked")
        return self._fernet.encrypt(data.encode())
    
    def _decrypt(self, data: bytes) -> str:
        """Decrypt data using Fernet"""
        if not self._fernet:
            raise RuntimeError("Database not unlocked")
        return self._fernet.decrypt(data).decode()
    
    def add_password(self, title: str, password: str, username: Optional[str] = None,
                    notes: Optional[str] = None, url: Optional[str] = None) -> int:
        """Add a new password entry"""
        if not self.connection:
            self.connect()
        
        timestamp = int(time.time())
        password_encrypted = self._encrypt(password)
        notes_encrypted = self._encrypt(notes) if notes else None
        
        cursor = self.connection.cursor()
        cursor.execute(
            """INSERT INTO passwords (title, username, password_encrypted, notes_encrypted, url, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (title, username, password_encrypted, notes_encrypted, url, timestamp, timestamp),
        )
        self.connection.commit()
        return cursor.lastrowid
    
    def get_passwords(self, search: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get all password entries (passwords remain encrypted)"""
        if not self.connection:
            self.connect()
        
        cursor = self.connection.cursor()
        
        if search:
            cursor.execute(
                """SELECT id, title, username, url, created_at, updated_at, last_accessed
                   FROM passwords WHERE title LIKE ? OR username LIKE ? OR url LIKE ? ORDER BY title""",
                (f"%{search}%", f"%{search}%", f"%{search}%"),
            )
        else:
            cursor.execute(
                "SELECT id, title, username, url, created_at, updated_at, last_accessed FROM passwords ORDER BY title"
            )
        
        return [dict(row) for row in cursor.fetchall()]
    
    def get_password(self, password_id: int) -> Optional[Dict[str, Any]]:
        """Get a specific password entry with decrypted password"""
        if not self.connection:
            self.connect()
        
        cursor = self.connection.cursor()
        cursor.execute("SELECT * FROM passwords WHERE id = ?", (password_id,))
        row = cursor.fetchone()
        
        if not row:
            return None
        
        entry = dict(row)
        entry["password"] = self._decrypt(entry["password_encrypted"])
        entry["notes"] = self._decrypt(entry["notes_encrypted"]) if entry["notes_encrypted"] else None
        
        cursor.execute("UPDATE passwords SET last_accessed = ? WHERE id = ?", (int(time.time()), password_id))
        self.connection.commit()
        
        return entry
    
    def update_password(self, password_id: int, title: Optional[str] = None,
                       password: Optional[str] = None, username: Optional[str] = None,
                       notes: Optional[str] = None, url: Optional[str] = None) -> bool:
        """Update a password entry"""
        if not self.connection:
            self.connect()
        
        updates, params = [], []
        
        if title is not None:
            updates.append("title = ?")
            params.append(title)
        if password is not None:
            updates.append("password_encrypted = ?")
            params.append(self._encrypt(password))
        if username is not None:
            updates.append("username = ?")
            params.append(username)
        if notes is not None:
            updates.append("notes_encrypted = ?")
            params.append(self._encrypt(notes) if notes else None)
        if url is not None:
            updates.append("url = ?")
            params.append(url)
        
        if not updates:
            return False
        
        updates.append("updated_at = ?")
        params.extend([int(time.time()), password_id])
        
        cursor = self.connection.cursor()
        cursor.execute(f"UPDATE passwords SET {', '.join(updates)} WHERE id = ?", params)
        self.connection.commit()
        return cursor.rowcount > 0
    
    def delete_password(self, password_id: int) -> bool:
        """Delete a password entry"""
        if not self.connection:
            self.connect()
        
        cursor = self.connection.cursor()
        cursor.execute("DELETE FROM passwords WHERE id = ?", (password_id,))
        self.connection.commit()
        return cursor.rowcount > 0
