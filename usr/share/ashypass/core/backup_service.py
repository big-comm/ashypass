import os
import os.path
import json
import logging
import threading
from typing import Optional, Dict, Any
from pathlib import Path

# Google API Client imports
try:
    from google_auth_oauthlib.flow import InstalledAppFlow
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
    from googleapiclient.discovery import build
    from googleapiclient.http import MediaFileUpload

    GOOGLE_LIBS_AVAILABLE = True
except ImportError:
    GOOGLE_LIBS_AVAILABLE = False

from core.config import DATA_DIR, DATABASE_PATH
from core.client_secrets import GOOGLE_CLIENT_CONFIG

SCOPES = [
    "https://www.googleapis.com/auth/drive.file",
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
]
TOKEN_FILE = DATA_DIR / "token.json"
LEGACY_TOKEN_FILE = DATA_DIR / "token.pickle"


class BackupService:
    """
    Manages Google Drive backups and authentication.
    Uses embedded client configuration.
    """

    def __init__(self):
        self.creds = None
        self.service = None
        self.user_info_service = None
        self.folder_id: Optional[str] = None
        self.folder_name = "AshyPass Backups"
        self._is_backing_up = False

        # Attempt to load existing token on startup
        if GOOGLE_LIBS_AVAILABLE:
            # Migrate legacy pickle token to JSON if needed
            self._migrate_legacy_token()
            if TOKEN_FILE.exists():
                self._load_token()

    def _migrate_legacy_token(self) -> None:
        """Migrate legacy pickle token to JSON format"""
        if not LEGACY_TOKEN_FILE.exists() or TOKEN_FILE.exists():
            return
        try:
            import pickle

            with open(LEGACY_TOKEN_FILE, "rb") as f:
                creds = pickle.load(f)
            self._save_token(creds)
            LEGACY_TOKEN_FILE.unlink()
            logging.info("Migrated legacy token.pickle to token.json")
        except Exception as e:
            logging.error(f"Error migrating legacy token: {e}")

    def _save_token(self, creds) -> None:
        """Save credentials to JSON file with restrictive permissions"""
        token_data = {
            "token": creds.token,
            "refresh_token": creds.refresh_token,
            "token_uri": creds.token_uri,
            "client_id": creds.client_id,
            "client_secret": creds.client_secret,
            "scopes": list(creds.scopes) if creds.scopes else SCOPES,
        }
        # Write with restrictive permissions (owner-only read/write)
        fd = os.open(str(TOKEN_FILE), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(token_data, f)
        except Exception:
            os.close(fd)
            raise

    def _load_token(self) -> bool:
        """Load token from JSON file and refresh if necessary"""
        try:
            with open(TOKEN_FILE, "r") as f:
                token_data = json.load(f)

            self.creds = Credentials.from_authorized_user_info(token_data, SCOPES)

            if self.creds and self.creds.expired and self.creds.refresh_token:
                self.creds.refresh(Request())
                self._save_token(self.creds)

            if self.creds and self.creds.valid:
                self.service = build("drive", "v3", credentials=self.creds)
                self.user_info_service = build("oauth2", "v2", credentials=self.creds)
                return True
        except Exception as e:
            logging.error(f"Error loading token: {e}")
            self.creds = None
        return False

    def is_logged_in(self) -> bool:
        """Check if user is currently logged in"""
        return self.creds is not None and self.creds.valid

    def get_user_info(self) -> Optional[Dict[str, Any]]:
        """Get logged in user profile info"""
        if not self.is_logged_in() or not self.user_info_service:
            return None
        try:
            return self.user_info_service.userinfo().get().execute()
        except Exception as e:
            logging.error(f"Error fetching user info: {e}")
            return None

    def login(self) -> bool:
        """
        Initiates the login flow.
        Returns True if successful.
        """
        if not GOOGLE_LIBS_AVAILABLE:
            logging.error("Google API libraries not installed.")
            return False

        try:
            # Use embedded config instead of file
            flow = InstalledAppFlow.from_client_config(GOOGLE_CLIENT_CONFIG, SCOPES)

            self.creds = flow.run_local_server(port=0)

            # Save the credentials as JSON
            self._save_token(self.creds)
            
            self.service = build('drive', 'v3', credentials=self.creds)
            self.user_info_service = build('oauth2', 'v2', credentials=self.creds)
            return True
            
        except Exception as e:
            logging.error(f"Login failed: {e}")
            return False

    def logout(self) -> None:
        """Clear credentials and token file"""
        self.creds = None
        self.service = None
        self.user_info_service = None
        if TOKEN_FILE.exists():
            try:
                os.remove(TOKEN_FILE)
            except OSError:
                pass

    def _get_or_create_folder(self) -> Optional[str]:
        """Finds or creates the backup folder."""
        if not self.service:
            return None
            
        if self.folder_id:
            return self.folder_id
            
        try:
            query = f"name = '{self.folder_name}' and mimeType = 'application/vnd.google-apps.folder' and trashed = false"
            results = self.service.files().list(q=query, spaces='drive', fields='files(id, name)').execute()
            items = results.get('files', [])
            
            if not items:
                file_metadata = {
                    'name': self.folder_name,
                    'mimeType': 'application/vnd.google-apps.folder'
                }
                file = self.service.files().create(body=file_metadata, fields='id').execute()
                self.folder_id = file.get('id')
            else:
                self.folder_id = items[0]['id']
                
            return self.folder_id
            
        except Exception as e:
            logging.error(f"Error getting folder: {e}")
            return None

    def backup_database(self) -> bool:
        """
        Uploads the current database file to Google Drive.
        Returns True if successful.
        """
        if not self.is_logged_in():
            return False
        
        # Prevent concurrent backups
        if self._is_backing_up:
            return False
        self._is_backing_up = True

        try:
            folder_id = self._get_or_create_folder()
            if not folder_id:
                return False
                
            if not DATABASE_PATH.exists():
                return False
                
            file_metadata = {
                'name': 'ashypass.db',
                'parents': [folder_id]
            }
            media = MediaFileUpload(str(DATABASE_PATH), 
                                   mimetype='application/x-sqlite3',
                                   resumable=True)
            
            query = f"name = 'ashypass.db' and '{folder_id}' in parents and trashed = false"
            results = self.service.files().list(q=query, spaces='drive', fields='files(id)').execute()
            items = results.get('files', [])
            
            if items:
                file_id = items[0]['id']
                self.service.files().update(
                    fileId=file_id,
                    media_body=media
                ).execute()
            else:
                self.service.files().create(
                    body=file_metadata,
                    media_body=media,
                    fields='id'
                ).execute()
                
            logging.info("Backup successful.")
            return True
            
        except Exception as e:
            logging.error(f"Backup failed: {e}")
            return False
        finally:
            self._is_backing_up = False

    def auto_backup(self) -> None:
        """Run backup in a separate thread (fire and forget)"""
        if self.is_logged_in():
            thread = threading.Thread(target=self.backup_database)
            thread.daemon = True
            thread.start()