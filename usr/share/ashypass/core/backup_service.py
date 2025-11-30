import os.path
import pickle
import logging
import threading
from typing import Optional, Dict, Any
from pathlib import Path

# Google API Client imports
try:
    from google_auth_oauthlib.flow import InstalledAppFlow
    from google.auth.transport.requests import Request
    from googleapiclient.discovery import build
    from googleapiclient.http import MediaFileUpload
    GOOGLE_LIBS_AVAILABLE = True
except ImportError:
    GOOGLE_LIBS_AVAILABLE = False

from core.config import DATA_DIR, DATABASE_PATH
from core.client_secrets import GOOGLE_CLIENT_CONFIG

SCOPES = [
    'https://www.googleapis.com/auth/drive.file',
    'openid',
    'https://www.googleapis.com/auth/userinfo.email'
]
TOKEN_FILE = DATA_DIR / 'token.pickle'

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
        if GOOGLE_LIBS_AVAILABLE and TOKEN_FILE.exists():
             self._load_token()

    def _load_token(self) -> bool:
        """Load token from file and refresh if necessary"""
        try:
            with open(TOKEN_FILE, 'rb') as token:
                self.creds = pickle.load(token)
            
            if self.creds and self.creds.expired and self.creds.refresh_token:
                self.creds.refresh(Request())
                # Save refreshed token
                with open(TOKEN_FILE, 'wb') as token:
                    pickle.dump(self.creds, token)
            
            if self.creds and self.creds.valid:
                self.service = build('drive', 'v3', credentials=self.creds)
                self.user_info_service = build('oauth2', 'v2', credentials=self.creds)
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
            flow = InstalledAppFlow.from_client_config(
                GOOGLE_CLIENT_CONFIG, SCOPES)
            
            self.creds = flow.run_local_server(port=0)
            
            # Save the credentials
            with open(TOKEN_FILE, 'wb') as token:
                pickle.dump(self.creds, token)
            
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