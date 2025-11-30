#!/usr/bin/env python3
"""
Ashy Pass - Main Window
GTK4/libadwaita main application window with view switcher
"""

import threading
import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')

from gi.repository import Gtk, Adw, GLib, Gio, GObject

from core.config import WINDOW_DEFAULT_WIDTH, WINDOW_DEFAULT_HEIGHT, WINDOW_MIN_WIDTH, WINDOW_MIN_HEIGHT
from core.database import Database
from core.auth import SessionManager
from core.csv_handler import CsvHandler
from core.backup_service import BackupService
from utils.i18n import _
from ui.generator_view import GeneratorView
from ui.vault_view import VaultView
from ui.settings_dialog import SettingsDialog


class MainWindow(Adw.ApplicationWindow):
    """Main application window"""
    
    def __init__(self, app, database: Database):
        super().__init__(application=app)
        
        self.database = database
        self.session = SessionManager()
        self.backup_service = BackupService()
        
        # Connect auto-backup to database changes
        self.database.add_change_listener(self.backup_service.auto_backup)
        
        # Window properties
        self.set_title("Ashy Pass")
        self.set_default_size(WINDOW_DEFAULT_WIDTH, WINDOW_DEFAULT_HEIGHT)
        self.set_size_request(WINDOW_MIN_WIDTH, WINDOW_MIN_HEIGHT)
        
        self._setup_actions()
        
        # Build UI
        self._build_ui()
    
    def _setup_actions(self):
        """Setup window actions"""
        # Import Action
        action_import = Gio.SimpleAction.new("import_csv", None)
        action_import.connect("activate", self.on_import_csv)
        self.add_action(action_import)

        # Export Action
        action_export = Gio.SimpleAction.new("export_csv", None)
        action_export.connect("activate", self.on_export_csv)
        self.add_action(action_export)

        # Settings Action
        action_settings = Gio.SimpleAction.new("settings", None)
        action_settings.connect("activate", self.on_settings)
        self.add_action(action_settings)

    def _build_ui(self) -> None:
        """Build the user interface"""
        # Toast overlay
        self.toast_overlay = Adw.ToastOverlay()
        
        # Navigation view
        self.nav_view = Adw.NavigationView()
        
        # Main page with view switcher
        main_page = self._create_main_page()
        self.nav_view.add(main_page)
        
        self.toast_overlay.set_child(self.nav_view)
        self.set_content(self.toast_overlay)
    
    def _create_main_page(self) -> Adw.NavigationPage:
        """Create main page with view switcher"""
        page = Adw.NavigationPage()
        page.set_title("Ashy Pass")
        
        # Toolbar view
        toolbar_view = Adw.ToolbarView()
        
        # Header bar with view switcher
        header = Adw.HeaderBar()

        # View switcher title
        self.view_switcher_title = Adw.ViewSwitcherTitle()
        header.set_title_widget(self.view_switcher_title)
        
        # Menu Button
        menu_button = Gtk.MenuButton()
        menu_button.set_icon_name("open-menu-symbolic")
        
        menu = Gio.Menu()
        
        section_main = Gio.Menu()
        section_main.append(_("Settings"), "win.settings")
        menu.append_section(None, section_main)
        
        section_csv = Gio.Menu()
        section_csv.append(_("Import from Google CSV"), "win.import_csv")
        section_csv.append(_("Export to CSV"), "win.export_csv")
        menu.append_section(None, section_csv)
        
        section_app = Gio.Menu()
        section_app.append(_("About"), "app.about")
        section_app.append(_("Quit"), "app.quit")
        menu.append_section(None, section_app)
        
        menu_button.set_menu_model(menu)
        header.pack_end(menu_button)

        # Vault buttons (only visible in vault view)
        self.add_button = Gtk.Button()
        self.add_button.set_icon_name("list-add-symbolic")
        self.add_button.set_tooltip_text(_("Add Password"))
        self.add_button.set_visible(False)
        header.pack_end(self.add_button)

        self.lock_button = Gtk.Button()
        self.lock_button.set_icon_name("system-lock-screen-symbolic")
        self.lock_button.set_tooltip_text(_("Lock Vault"))
        self.lock_button.set_visible(False)
        header.pack_end(self.lock_button)

        toolbar_view.add_top_bar(header)
        
        # View stack
        self.view_stack = Adw.ViewStack()
        self.view_switcher_title.set_stack(self.view_stack)
        
        # Generator view
        self.generator_view = GeneratorView()
        self.view_stack.add_titled_with_icon(
            self.generator_view,
            "generator",
            "Generator",
            "view-reveal-symbolic"
        )
        
        # Vault view
        self.vault_view = VaultView(self.database, self.session)
        self.view_stack.add_titled_with_icon(
            self.vault_view,
            "vault",
            "Vault",
            "dialog-password-symbolic"
        )

        # Connect vault buttons
        self.add_button.connect("clicked", lambda _: self.vault_view._show_add_dialog())
        self.lock_button.connect("clicked", lambda _: self.vault_view._lock_vault())

        # Connect stack notify to show/hide vault buttons
        self.view_stack.connect("notify::visible-child", self._on_view_changed)

        toolbar_view.set_content(self.view_stack)

        page.set_child(toolbar_view)
        
        return page
    
    def _on_view_changed(self, stack, *args) -> None:
        """Handle view change to show/hide vault buttons"""
        is_vault = stack.get_visible_child_name() == "vault"
        is_authenticated = self.session.is_authenticated()

        self.add_button.set_visible(is_vault and is_authenticated)
        self.lock_button.set_visible(is_vault and is_authenticated)

    def show_toast(self, message: str) -> None:
        """Show a toast notification"""
        toast = Adw.Toast.new(message)
        toast.set_timeout(3)
        self.toast_overlay.add_toast(toast)

    # --- Action Handlers ---

    def on_import_csv(self, action, param):
        """Handle Import CSV action"""
        if not self.session.is_authenticated():
            self.show_toast(_("Please unlock the vault first"))
            return

        chooser = Gtk.FileChooserNative(
            title=_("Import Passwords"),
            transient_for=self,
            action=Gtk.FileChooserAction.OPEN
        )
        
        filter_csv = Gtk.FileFilter()
        filter_csv.set_name("CSV Files")
        filter_csv.add_pattern("*.csv")
        chooser.add_filter(filter_csv)
        
        def on_response(dialog, response):
            if response == Gtk.ResponseType.ACCEPT:
                file_path = dialog.get_file().get_path()
                try:
                    entries = CsvHandler.import_csv(file_path)
                    count = 0
                    for entry in entries:
                        self.database.add_password(
                            title=entry['title'],
                            password=entry['password'],
                            username=entry['username'],
                            url=entry['url'],
                            notes=entry['notes']
                        )
                        count += 1
                    
                    self.show_toast(_("Imported {count} passwords").format(count=count))
                    self.vault_view._load_passwords()
                except Exception as e:
                    self.show_toast(_("Error importing CSV: {error}").format(error=str(e)))
            dialog.destroy()
            
        chooser.connect("response", on_response)
        chooser.show()

    def on_export_csv(self, action, param):
        """Handle Export CSV action"""
        if not self.session.is_authenticated():
            self.show_toast(_("Please unlock the vault first"))
            return

        chooser = Gtk.FileChooserNative(
            title=_("Export Passwords"),
            transient_for=self,
            action=Gtk.FileChooserAction.SAVE
        )
        chooser.set_current_name("ashypass_export.csv")
        
        filter_csv = Gtk.FileFilter()
        filter_csv.set_name("CSV Files")
        filter_csv.add_pattern("*.csv")
        chooser.add_filter(filter_csv)
        
        def on_response(dialog, response):
            if response == Gtk.ResponseType.ACCEPT:
                file_path = dialog.get_file().get_path()
                
                # Fetch all passwords (decrypted)
                passwords_list = self.database.get_passwords()
                decrypted_passwords = []
                
                for p in passwords_list:
                    full_entry = self.database.get_password(p['id'])
                    if full_entry:
                        decrypted_passwords.append(full_entry)
                
                if CsvHandler.export_csv(file_path, decrypted_passwords):
                    self.show_toast(_("Passwords exported successfully"))
                else:
                    self.show_toast(_("Error exporting passwords"))
            dialog.destroy()
            
        chooser.connect("response", on_response)
        chooser.show()

    def on_settings(self, action, param):
        """Open settings dialog"""
        dialog = SettingsDialog(self, self.backup_service, self.database)
        dialog.present()
