import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Gtk, Adw, GLib, Gio

from core.backup_service import BackupService
from core.csv_handler import CsvHandler
from core.database import Database
from utils.i18n import _
import threading

class SettingsDialog(Adw.PreferencesWindow):
    """Application Settings Window"""
    
    def __init__(self, parent, backup_service: BackupService, database: Database):
        super().__init__()
        self.set_transient_for(parent)
        self.set_modal(True)
        self.set_default_size(500, 600)
        self.set_title(_("Settings"))

        self.backup_service = backup_service
        self.database = database
        self.csv_handler = CsvHandler()

        self._build_ui()
        self._update_account_status()
        
    def _build_ui(self):
        # --- Cloud Sync Page ---
        page_cloud = Adw.PreferencesPage()
        page_cloud.set_title(_("Cloud Backup"))
        page_cloud.set_icon_name("folder-remote-symbolic")
        
        # Account Group
        group_account = Adw.PreferencesGroup()
        group_account.set_title(_("Google Account"))
        group_account.set_description(_("Sign in to automatically backup your encrypted database to Google Drive."))
        
        # Status Row
        self.row_status = Adw.ActionRow()
        self.row_status.set_title(_("Status"))
        group_account.add(self.row_status)
        
        # Account Info Row
        self.row_account = Adw.ActionRow()
        self.row_account.set_title(_("Account"))
        self.row_account.set_visible(False)
        group_account.add(self.row_account)

        # Login Button Row
        self.row_login = Adw.ActionRow()
        self.btn_login = Gtk.Button(label=_("Sign in with Google"))
        self.btn_login.add_css_class("pill")
        self.btn_login.add_css_class("suggested-action")
        self.btn_login.set_valign(Gtk.Align.CENTER)
        self.btn_login.connect("clicked", self._on_login_clicked)
        self.row_login.add_suffix(self.btn_login)
        group_account.add(self.row_login)
        
        # Logout Button Row
        self.row_logout = Adw.ActionRow()
        self.btn_logout = Gtk.Button(label=_("Sign Out"))
        self.btn_logout.add_css_class("pill")
        self.btn_logout.add_css_class("destructive-action")
        self.btn_logout.set_valign(Gtk.Align.CENTER)
        self.btn_logout.connect("clicked", self._on_logout_clicked)
        self.row_logout.add_suffix(self.btn_logout)
        self.row_logout.set_visible(False)
        group_account.add(self.row_logout)
        
        page_cloud.add(group_account)
        
        # Actions Group
        group_actions = Adw.PreferencesGroup()
        group_actions.set_title(_("Actions"))
        
        self.row_backup_now = Adw.ActionRow()
        self.row_backup_now.set_title(_("Backup Now"))
        self.row_backup_now.set_subtitle(_("Force a manual backup to Google Drive"))
        
        btn_backup = Gtk.Button(icon_name="document-save-symbolic")
        btn_backup.set_valign(Gtk.Align.CENTER)
        btn_backup.add_css_class("flat")
        btn_backup.connect("clicked", self._on_backup_now_clicked)
        
        self.row_backup_now.add_suffix(btn_backup)
        group_actions.add(self.row_backup_now)
        
        page_cloud.add(group_actions)

        self.add(page_cloud)

        # --- Import/Export Page ---
        page_import_export = Adw.PreferencesPage()
        page_import_export.set_title(_("Import/Export"))
        page_import_export.set_icon_name("document-save-symbolic")

        # Import/Export Group
        group_import_export = Adw.PreferencesGroup()
        group_import_export.set_title(_("CSV Import/Export"))
        group_import_export.set_description(_("Import passwords from or export to CSV format (compatible with Google Chrome)."))

        # Import Row
        row_import = Adw.ActionRow()
        row_import.set_title(_("Import from CSV"))
        row_import.set_subtitle(_("Import passwords from a CSV file"))

        btn_import = Gtk.Button(icon_name="document-open-symbolic")
        btn_import.set_valign(Gtk.Align.CENTER)
        btn_import.add_css_class("flat")
        btn_import.connect("clicked", self._on_import_clicked)
        row_import.add_suffix(btn_import)

        group_import_export.add(row_import)

        # Export Row
        row_export = Adw.ActionRow()
        row_export.set_title(_("Export to CSV"))
        row_export.set_subtitle(_("Export all passwords to a CSV file"))

        btn_export = Gtk.Button(icon_name="document-save-symbolic")
        btn_export.set_valign(Gtk.Align.CENTER)
        btn_export.add_css_class("flat")
        btn_export.connect("clicked", self._on_export_clicked)
        row_export.add_suffix(btn_export)

        group_import_export.add(row_export)

        page_import_export.add(group_import_export)

        self.add(page_import_export)

    def _update_account_status(self):
        """Update UI based on login state"""
        is_logged = self.backup_service.is_logged_in()
        
        self.row_login.set_visible(not is_logged)
        self.row_logout.set_visible(is_logged)
        self.row_account.set_visible(is_logged)
        self.row_backup_now.set_sensitive(is_logged)
        
        if is_logged:
            self.row_status.set_subtitle(_("Connected"))
            # Try to fetch user info
            try:
                info = self.backup_service.get_user_info()
                if info and 'email' in info:
                    self.row_account.set_subtitle(info['email'])
                    # Could also set avatar if we wanted to fetch the image
            except:
                self.row_account.set_subtitle(_("Unknown User"))
        else:
            self.row_status.set_subtitle(_("Disconnected"))

    def _on_login_clicked(self, btn):
        """Handle login"""
        self.btn_login.set_sensitive(False)
        self.btn_login.set_label(_("Waiting for browser..."))
        
        def run_login():
            success = self.backup_service.login()
            GLib.idle_add(self._on_login_finished, success)
            
        thread = threading.Thread(target=run_login)
        thread.daemon = True
        thread.start()
        
    def _on_login_finished(self, success):
        self.btn_login.set_sensitive(True)
        self.btn_login.set_label(_("Sign in with Google"))
        
        if success:
            self._update_account_status()
            # Trigger initial backup
            self.backup_service.auto_backup()
            
            # Show success toast in parent window
            parent = self.get_transient_for()
            if parent and hasattr(parent, 'show_toast'):
                parent.show_toast(_("Successfully connected to Google Drive"))
        else:
            # Show error dialog
            dlg = Adw.AlertDialog()
            dlg.set_heading(_("Login Failed"))
            dlg.set_body(_("Could not connect to Google. Please check your internet connection and try again.\n\nNote: If you are the developer, ensure CLIENT_ID is configured."))
            dlg.add_response("ok", _("OK"))
            dlg.present(self)

    def _on_logout_clicked(self, btn):
        self.backup_service.logout()
        self._update_account_status()

    def _on_backup_now_clicked(self, btn):
        parent = self.get_transient_for()
        if parent and hasattr(parent, 'show_toast'):
             parent.show_toast(_("Starting backup..."))

        self.backup_service.auto_backup()

    def _on_import_clicked(self, btn):
        """Handle CSV import"""
        dialog = Gtk.FileDialog()
        dialog.set_title(_("Select CSV File to Import"))

        # Set filter for CSV files
        filter_csv = Gtk.FileFilter()
        filter_csv.set_name(_("CSV Files"))
        filter_csv.add_pattern("*.csv")

        filter_all = Gtk.FileFilter()
        filter_all.set_name(_("All Files"))
        filter_all.add_pattern("*")

        filters = Gio.ListStore.new(Gtk.FileFilter)
        filters.append(filter_csv)
        filters.append(filter_all)
        dialog.set_filters(filters)
        dialog.set_default_filter(filter_csv)

        dialog.open(self, None, self._on_import_file_selected)

    def _on_import_file_selected(self, dialog, result):
        """Handle file selection for import"""
        try:
            file = dialog.open_finish(result)
            if file:
                file_path = file.get_path()
                self._import_passwords(file_path)
        except Exception as e:
            if "dismissed" not in str(e).lower():
                self._show_error_dialog(_("Import Failed"), str(e))

    def _import_passwords(self, file_path: str):
        """Import passwords from CSV file"""
        try:
            # Import CSV
            entries = self.csv_handler.import_csv(file_path)

            if not entries:
                self._show_info_dialog(_("Import Complete"), _("No valid entries found in CSV file."))
                return

            # Add to database
            count = 0
            for entry in entries:
                try:
                    self.database.add_password(
                        title=entry['title'],
                        password=entry['password'],
                        username=entry.get('username'),
                        notes=entry.get('notes'),
                        url=entry.get('url')
                    )
                    count += 1
                except Exception as e:
                    print(f"Error importing entry {entry.get('title')}: {e}")

            # Show success message
            parent = self.get_transient_for()
            if parent and hasattr(parent, 'show_toast'):
                parent.show_toast(_("Imported {count} passwords").format(count=count))

            # Refresh vault view
            if parent and hasattr(parent, 'vault_view'):
                parent.vault_view._load_passwords()

        except Exception as e:
            self._show_error_dialog(_("Import Failed"), str(e))

    def _on_export_clicked(self, btn):
        """Handle CSV export"""
        dialog = Gtk.FileDialog()
        dialog.set_title(_("Export Passwords to CSV"))
        dialog.set_initial_name("ashypass_passwords.csv")

        # Set filter for CSV files
        filter_csv = Gtk.FileFilter()
        filter_csv.set_name(_("CSV Files"))
        filter_csv.add_pattern("*.csv")
        dialog.set_default_filter(filter_csv)

        dialog.save(self, None, self._on_export_file_selected)

    def _on_export_file_selected(self, dialog, result):
        """Handle file selection for export"""
        try:
            file = dialog.save_finish(result)
            if file:
                file_path = file.get_path()
                self._export_passwords(file_path)
        except Exception as e:
            if "dismissed" not in str(e).lower():
                self._show_error_dialog(_("Export Failed"), str(e))

    def _export_passwords(self, file_path: str):
        """Export passwords to CSV file"""
        try:
            # Get all passwords from database
            passwords = self.database.get_passwords()

            if not passwords:
                self._show_info_dialog(_("Export Complete"), _("No passwords to export."))
                return

            # Export to CSV
            success = self.csv_handler.export_csv(file_path, passwords)

            if success:
                parent = self.get_transient_for()
                if parent and hasattr(parent, 'show_toast'):
                    parent.show_toast(_("Exported {count} passwords").format(count=len(passwords)))
            else:
                self._show_error_dialog(_("Export Failed"), _("Could not write to file."))

        except Exception as e:
            self._show_error_dialog(_("Export Failed"), str(e))

    def _show_error_dialog(self, title: str, message: str):
        """Show error dialog"""
        dlg = Adw.AlertDialog()
        dlg.set_heading(title)
        dlg.set_body(message)
        dlg.add_response("ok", _("OK"))
        dlg.present(self)

    def _show_info_dialog(self, title: str, message: str):
        """Show info dialog"""
        dlg = Adw.AlertDialog()
        dlg.set_heading(title)
        dlg.set_body(message)
        dlg.add_response("ok", _("OK"))
        dlg.present(self)
