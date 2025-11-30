import csv
import os
from typing import List, Dict, Optional, Any

class CsvHandler:
    """Handles import and export of passwords in CSV format (Google Chrome compatible)"""
    
    FIELD_NAMES = ['name', 'url', 'username', 'password', 'note']
    
    @staticmethod
    def import_csv(file_path: str) -> List[Dict[str, str]]:
        """
        Reads a CSV file and returns a list of password entries.
        Expected format: name, url, username, password, note
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
            
        entries = []
        try:
            with open(file_path, mode='r', encoding='utf-8', newline='') as csvfile:
                # Google CSVs usually have a header. Sniffer could be used, 
                # but let's assume standard header or try to detect.
                # We'll use DictReader which uses the first row as keys.
                reader = csv.DictReader(csvfile)
                
                # Normalize headers to lowercase to match our expected keys
                if reader.fieldnames:
                    headers = [h.lower() for h in reader.fieldnames]
                    reader.fieldnames = headers
                
                for row in reader:
                    # Map Google's 'name' to our 'title' logic, but keep dict generic
                    entry = {
                        'title': row.get('name') or row.get('title') or 'Untitled',
                        'url': row.get('url') or '',
                        'username': row.get('username') or '',
                        'password': row.get('password') or '',
                        'notes': row.get('note') or row.get('notes') or ''
                    }
                    
                    # Only add if there is at least a password or title
                    if entry['password'] or entry['title'] != 'Untitled':
                        entries.append(entry)
                        
        except Exception as e:
            print(f"Error importing CSV: {e}")
            raise
            
        return entries

    @staticmethod
    def export_csv(file_path: str, passwords: List[Dict[str, Any]]) -> bool:
        """
        Exports a list of password dictionaries to a CSV file.
        """
        try:
            with open(file_path, mode='w', encoding='utf-8', newline='') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=CsvHandler.FIELD_NAMES)
                
                writer.writeheader()
                
                for p in passwords:
                    # Decrypt/Prepare data before calling this method or ensure 'passwords' list 
                    # passed here contains plain text if the user authorized it.
                    # NOTE: The database usually returns encrypted data. 
                    # The caller must ensure passwords are decrypted.
                    
                    row = {
                        'name': p.get('title', ''),
                        'url': p.get('url', ''),
                        'username': p.get('username', ''),
                        'password': p.get('password', ''), # Must be plain text
                        'note': p.get('notes', '')
                    }
                    writer.writerow(row)
            return True
        except Exception as e:
            print(f"Error exporting CSV: {e}")
            return False
