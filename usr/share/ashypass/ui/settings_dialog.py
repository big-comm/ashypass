import logging
import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Gtk, Adw, GLib, Gio

from core.backup_service import BackupService
from core.csv_handler import CsvHandler
from core.aegis_import import (
    parse_aegis_json,
    parse_aegis_encrypted,
    AegisEncryptedError,
    is_aegis_encrypted,
)
from core.andotp_import import parse_andotp_json
from core.database import Database
from core.config import MIN_MASTER_PASSWORD_LENGTH, load_settings, save_settings
from utils.i18n import _
import threading

class SettingsDialog(Adw.PreferencesWindow):
    """Application Settings Window"""
    
    def __init__(self, parent, backup_service: BackupService, database: Database):
        super().__init__()
        self.set_transient_for(parent)
        self.set_modal(True)
        self.set_default_size(640, 600)
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
        btn_backup.set_tooltip_text(_("Backup Now"))
        btn_backup.update_property([Gtk.AccessibleProperty.LABEL], [_("Backup Now")])
        btn_backup.connect("clicked", self._on_backup_now_clicked)
        self.btn_backup = btn_backup
        
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
        btn_import.set_tooltip_text(_("Import from CSV"))
        btn_import.update_property(
            [Gtk.AccessibleProperty.LABEL], [_("Import from CSV")]
        )
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
        btn_export.set_tooltip_text(_("Export to CSV"))
        btn_export.update_property([Gtk.AccessibleProperty.LABEL], [_("Export to CSV")])
        btn_export.connect("clicked", self._on_export_clicked)
        row_export.add_suffix(btn_export)

        group_import_export.add(row_export)

        page_import_export.add(group_import_export)

        # 2FA Import Group
        group_2fa = Adw.PreferencesGroup()
        group_2fa.set_title(_("2FA / TOTP Import"))
        group_2fa.set_description(
            _("Import TOTP entries from authenticator apps (plain or encrypted).")
        )

        row_aegis = Adw.ActionRow()
        row_aegis.set_title(_("Import from Aegis"))
        row_aegis.set_subtitle(_("Aegis JSON export (plain or encrypted)"))

        btn_aegis = Gtk.Button(icon_name="document-open-symbolic")
        btn_aegis.set_valign(Gtk.Align.CENTER)
        btn_aegis.add_css_class("flat")
        btn_aegis.set_tooltip_text(_("Import from Aegis"))
        btn_aegis.update_property(
            [Gtk.AccessibleProperty.LABEL], [_("Import from Aegis")]
        )
        btn_aegis.connect("clicked", self._on_aegis_import_clicked)
        row_aegis.add_suffix(btn_aegis)
        group_2fa.add(row_aegis)

        row_andotp = Adw.ActionRow()
        row_andotp.set_title(_("Import from andOTP"))
        row_andotp.set_subtitle(_("andOTP plaintext JSON backup"))

        btn_andotp = Gtk.Button(icon_name="document-open-symbolic")
        btn_andotp.set_valign(Gtk.Align.CENTER)
        btn_andotp.add_css_class("flat")
        btn_andotp.set_tooltip_text(_("Import from andOTP"))
        btn_andotp.update_property(
            [Gtk.AccessibleProperty.LABEL], [_("Import from andOTP")]
        )
        btn_andotp.connect("clicked", self._on_andotp_import_clicked)
        row_andotp.add_suffix(btn_andotp)
        group_2fa.add(row_andotp)

        page_import_export.add(group_2fa)

        self.add(page_import_export)

        # --- Appearance Page ---
        page_appearance = Adw.PreferencesPage()
        page_appearance.set_title(_("Appearance"))
        page_appearance.set_icon_name("preferences-desktop-appearance-symbolic")

        group_icons = Adw.PreferencesGroup()
        group_icons.set_title(_("Icons"))
        group_icons.set_description(
            _(
                "Show website favicons next to passwords and 2FA codes for easier identification."
            )
        )

        self._settings = load_settings()

        self.favicon_switch_row = Adw.SwitchRow()
        self.favicon_switch_row.set_title(_("Show Favicons"))
        self.favicon_switch_row.set_subtitle(
            _("Download website icons (requires internet)")
        )
        self.favicon_switch_row.set_active(self._settings.get("show_favicons", True))
        self.favicon_switch_row.connect("notify::active", self._on_favicon_toggled)
        group_icons.add(self.favicon_switch_row)

        page_appearance.add(group_icons)
        self.add(page_appearance)

        # --- Security Page ---
        page_security = Adw.PreferencesPage()
        page_security.set_title(_("Security"))
        page_security.set_icon_name("channel-secure-symbolic")

        group_master = Adw.PreferencesGroup()
        group_master.set_title(_("Master Password"))
        group_master.set_description(
            _("Change your master password. All stored passwords will be re-encrypted.")
        )

        self.current_password_row = Adw.PasswordEntryRow()
        self.current_password_row.set_title(_("Current Password"))
        group_master.add(self.current_password_row)

        self.new_password_row = Adw.PasswordEntryRow()
        self.new_password_row.set_title(_("New Password"))
        group_master.add(self.new_password_row)

        self.confirm_password_row = Adw.PasswordEntryRow()
        self.confirm_password_row.set_title(_("Confirm New Password"))
        group_master.add(self.confirm_password_row)

        btn_change = Gtk.Button(label=_("Change Master Password"))
        btn_change.add_css_class("pill")
        btn_change.add_css_class("destructive-action")
        btn_change.set_halign(Gtk.Align.CENTER)
        btn_change.set_margin_top(12)
        btn_change.connect("clicked", self._on_change_master_clicked)
        group_master.add(btn_change)

        page_security.add(group_master)

        # Lock timeout group
        group_timeout = Adw.PreferencesGroup()
        group_timeout.set_title(_("Auto-Lock"))
        group_timeout.set_description(
            _("Automatically lock the vault after a period of inactivity.")
        )

        self.timeout_spin = Adw.SpinRow()
        self.timeout_spin.set_title(_("Lock after (seconds)"))
        self.timeout_spin.set_subtitle(_("Minimum 15 seconds"))
        self.timeout_spin.set_adjustment(
            Gtk.Adjustment(
                value=self._settings.get("lock_timeout", 30),
                lower=15,
                upper=600,
                step_increment=15,
                page_increment=60,
            )
        )
        self.timeout_spin.connect("notify::value", self._on_timeout_changed)
        group_timeout.add(self.timeout_spin)

        page_security.add(group_timeout)
        self.add(page_security)

    def _on_favicon_toggled(self, switch_row, _pspec) -> None:
        """Handle favicon toggle"""
        self._settings["show_favicons"] = switch_row.get_active()
        save_settings(self._settings)

    def _on_timeout_changed(self, spin_row, _pspec) -> None:
        """Handle lock timeout change"""
        value = int(spin_row.get_value())
        self._settings["lock_timeout"] = value
        save_settings(self._settings)
        # Apply to running session
        parent = self.get_transient_for()
        if parent and hasattr(parent, "session"):
            parent.session.timeout_seconds = value
            if parent.session.is_authenticated():
                parent.session.reset_timeout()

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
            except Exception:
                self.row_account.set_subtitle(_("Unknown User"))
        else:
            self.row_status.set_subtitle(_("Disconnected"))

    def _on_login_clicked(self, btn):
        """Handle login"""
        self.btn_login.set_sensitive(False)
        self.btn_login.set_label(_("Waiting for browser..."))
        self._login_spinner = Gtk.Spinner(spinning=True)
        self._login_spinner.set_valign(Gtk.Align.CENTER)
        self.row_login.add_prefix(self._login_spinner)
        
        def run_login():
            success = self.backup_service.login()
            GLib.idle_add(self._on_login_finished, success)
            
        thread = threading.Thread(target=run_login)
        thread.daemon = True
        thread.start()
        
    def _on_login_finished(self, success):
        self.btn_login.set_sensitive(True)
        self.btn_login.set_label(_("Sign in with Google"))
        if self._login_spinner:
            self.row_login.remove(self._login_spinner)
            self._login_spinner = None
        
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
        self.btn_backup.set_sensitive(False)
        self._backup_spinner = Gtk.Spinner(spinning=True)
        self._backup_spinner.set_valign(Gtk.Align.CENTER)
        self.row_backup_now.add_prefix(self._backup_spinner)

        def run_backup():
            success = self.backup_service.backup_database()
            GLib.idle_add(self._on_backup_finished, success)

        thread = threading.Thread(target=run_backup, daemon=True)
        thread.start()

    def _on_backup_finished(self, success: bool) -> None:
        self.btn_backup.set_sensitive(True)
        if self._backup_spinner:
            self.row_backup_now.remove(self._backup_spinner)
            self._backup_spinner = None
        parent = self.get_transient_for()
        if parent and hasattr(parent, "show_toast"):
            if success:
                parent.show_toast(_("Backup complete"))
            else:
                parent.show_toast(_("Backup failed — check your connection"))

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
            if not self.database._fernet:
                self._show_error_dialog(
                    _("Vault Locked"),
                    _(
                        "You must unlock the vault before importing. Go to the Vault tab and enter your master password first."
                    ),
                )
                return

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
                    logging.getLogger(__name__).error(
                        "Error importing entry %s: %s", entry.get("title"), e
                    )

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
        """Handle CSV export with security warning"""
        dlg = Adw.AlertDialog()
        dlg.set_heading(_("Security Warning"))
        dlg.set_body(
            _(
                "The exported CSV file will contain all your passwords in plain text. "
                "Make sure to store it in a secure location and delete it when no longer needed."
            )
        )
        dlg.add_response("cancel", _("Cancel"))
        dlg.add_response("continue", _("Continue Export"))
        dlg.set_response_appearance("continue", Adw.ResponseAppearance.DESTRUCTIVE)
        dlg.set_default_response("cancel")
        dlg.set_close_response("cancel")

        def on_warning_response(d, response):
            if response == "continue":
                self._open_export_dialog()

        dlg.connect("response", on_warning_response)
        dlg.present(self)

    def _open_export_dialog(self):
        """Open file chooser for export"""
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

    def _on_aegis_import_clicked(self, btn):
        """Handle Aegis JSON import"""
        dialog = Gtk.FileDialog()
        dialog.set_title(_("Select Aegis JSON Export"))

        filter_json = Gtk.FileFilter()
        filter_json.set_name(_("JSON Files"))
        filter_json.add_pattern("*.json")

        filter_all = Gtk.FileFilter()
        filter_all.set_name(_("All Files"))
        filter_all.add_pattern("*")

        filters = Gio.ListStore.new(Gtk.FileFilter)
        filters.append(filter_json)
        filters.append(filter_all)
        dialog.set_filters(filters)
        dialog.set_default_filter(filter_json)

        dialog.open(self, None, self._on_aegis_file_selected)

    def _on_aegis_file_selected(self, dialog, result):
        """Handle Aegis file selection"""
        try:
            file = dialog.open_finish(result)
            if file:
                file_path = file.get_path()
                self._import_aegis(file_path)
        except Exception as e:
            if "dismissed" not in str(e).lower():
                self._show_error_dialog(_("Import Failed"), str(e))

    def _import_aegis(self, file_path: str):
        """Import TOTP entries from Aegis JSON file (plain or encrypted)"""
        try:
            entries = parse_aegis_json(file_path)
            self._save_totp_entries(entries, "Aegis")
        except AegisEncryptedError:
            self._ask_aegis_password(file_path)
        except Exception as e:
            self._show_error_dialog(_("Import Failed"), str(e))

    def _ask_aegis_password(self, file_path: str):
        """Show dialog to ask for Aegis vault password"""
        dlg = Adw.AlertDialog()
        dlg.set_heading(_("Encrypted Aegis Export"))
        dlg.set_body(
            _("This Aegis export is encrypted. Enter the password to decrypt it.")
        )
        dlg.add_response("cancel", _("Cancel"))
        dlg.add_response("decrypt", _("Decrypt"))
        dlg.set_response_appearance("decrypt", Adw.ResponseAppearance.SUGGESTED)
        dlg.set_default_response("decrypt")
        dlg.set_close_response("cancel")

        password_entry = Gtk.PasswordEntry()
        password_entry.set_show_peek_icon(True)
        password_entry.set_hexpand(True)
        password_entry.set_margin_top(12)
        password_entry.set_margin_start(12)
        password_entry.set_margin_end(12)
        dlg.set_extra_child(password_entry)

        def on_response(d, response):
            if response == "decrypt":
                pwd = password_entry.get_text()
                if not pwd:
                    self._show_error_dialog(_("Error"), _("Password cannot be empty."))
                    return
                try:
                    entries = parse_aegis_encrypted(file_path, pwd)
                    self._save_totp_entries(entries, "Aegis")
                except ValueError as ve:
                    self._show_error_dialog(_("Decryption Failed"), str(ve))
                except Exception as ex:
                    self._show_error_dialog(_("Import Failed"), str(ex))

        dlg.connect("response", on_response)
        dlg.present(self)

    def _on_andotp_import_clicked(self, btn):
        """Handle andOTP JSON import"""
        dialog = Gtk.FileDialog()
        dialog.set_title(_("Select andOTP JSON Backup"))

        filter_json = Gtk.FileFilter()
        filter_json.set_name(_("JSON Files"))
        filter_json.add_pattern("*.json")

        filter_all = Gtk.FileFilter()
        filter_all.set_name(_("All Files"))
        filter_all.add_pattern("*")

        filters = Gio.ListStore.new(Gtk.FileFilter)
        filters.append(filter_json)
        filters.append(filter_all)
        dialog.set_filters(filters)
        dialog.set_default_filter(filter_json)

        dialog.open(self, None, self._on_andotp_file_selected)

    def _on_andotp_file_selected(self, dialog, result):
        """Handle andOTP file selection"""
        try:
            file = dialog.open_finish(result)
            if file:
                file_path = file.get_path()
                self._import_andotp(file_path)
        except Exception as e:
            if "dismissed" not in str(e).lower():
                self._show_error_dialog(_("Import Failed"), str(e))

    def _import_andotp(self, file_path: str):
        """Import TOTP entries from andOTP JSON backup"""
        try:
            entries = parse_andotp_json(file_path)
            self._save_totp_entries(entries, "andOTP")
        except Exception as e:
            self._show_error_dialog(_("Import Failed"), str(e))

    def _save_totp_entries(self, entries: list, source: str):
        """Save imported TOTP entries to database"""
        if not entries:
            self._show_info_dialog(
                _("Import Complete"),
                _("No TOTP entries found in {source} export.").format(source=source),
            )
            return

        if not self.database._fernet:
            self._show_error_dialog(
                _("Vault Locked"),
                _(
                    "You must unlock the vault before importing. Go to the Vault tab and enter your master password first."
                ),
            )
            return

        count = 0
        for entry in entries:
            try:
                self.database.add_password(
                    title=entry["title"],
                    password=entry.get("password", ""),
                    username=entry.get("username"),
                    notes=entry.get("notes"),
                    url=entry.get("url"),
                    totp_secret=entry.get("totp_secret"),
                    totp_algorithm=entry.get("totp_algorithm", "SHA1"),
                    totp_digits=entry.get("totp_digits", 6),
                    totp_period=entry.get("totp_period", 30),
                )
                count += 1
            except Exception as e:
                logging.getLogger(__name__).error(
                    "Error importing %s entry %s: %s", source, entry.get("title"), e
                )

        parent = self.get_transient_for()
        if parent and hasattr(parent, "show_toast"):
            parent.show_toast(
                _("Imported {count} TOTP entries from {source}").format(
                    count=count, source=source
                )
            )

        if parent and hasattr(parent, "vault_view"):
            parent.vault_view._load_passwords()

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

    def _on_change_master_clicked(self, btn):
        """Handle change master password"""
        current = self.current_password_row.get_text()
        new_pwd = self.new_password_row.get_text()
        confirm = self.confirm_password_row.get_text()

        if not current or not new_pwd or not confirm:
            self._show_error_dialog(_("Error"), _("All fields are required"))
            return

        if len(new_pwd) < MIN_MASTER_PASSWORD_LENGTH:
            self._show_error_dialog(
                _("Error"),
                _("New password must be at least {min} characters").format(
                    min=MIN_MASTER_PASSWORD_LENGTH
                ),
            )
            return

        if new_pwd != confirm:
            self._show_error_dialog(_("Error"), _("New passwords do not match"))
            return

        try:
            if self.database.change_master_password(current, new_pwd):
                self.current_password_row.set_text("")
                self.new_password_row.set_text("")
                self.confirm_password_row.set_text("")

                parent = self.get_transient_for()
                if parent and hasattr(parent, "show_toast"):
                    parent.show_toast(_("Master password changed successfully"))
            else:
                self._show_error_dialog(_("Error"), _("Current password is incorrect"))
        except Exception as e:
            self._show_error_dialog(
                _("Error"),
                _("Failed to change master password: {error}").format(error=str(e)),
            )
