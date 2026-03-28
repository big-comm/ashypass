#!/usr/bin/env python3
"""
Ashy Pass - Main Window
GTK4/libadwaita main application window with view switcher
"""

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Gtk, Adw, GLib, Gio

from core.config import (
    WINDOW_DEFAULT_WIDTH,
    WINDOW_DEFAULT_HEIGHT,
    WINDOW_MIN_WIDTH,
    WINDOW_MIN_HEIGHT,
)
from core.database import Database
from core.auth import SessionManager
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

        # Register keyboard shortcuts
        app.set_accels_for_action("win.search", ["<primary>f"])

    def _setup_actions(self):
        """Setup window actions"""
        # Settings Action
        action_settings = Gio.SimpleAction.new("settings", None)
        action_settings.connect("activate", self.on_settings)
        self.add_action(action_settings)

        # Search Action (Ctrl+F)
        action_search = Gio.SimpleAction.new("search", None)
        action_search.connect("activate", self._on_search_activated)
        self.add_action(action_search)

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
        menu_button.update_property([Gtk.AccessibleProperty.LABEL], [_("Main Menu")])

        menu = Gio.Menu()

        section_main = Gio.Menu()
        section_main.append(_("Settings"), "win.settings")
        menu.append_section(None, section_main)

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
        self.add_button.update_property(
            [Gtk.AccessibleProperty.LABEL], [_("Add Password")]
        )
        self.add_button.set_visible(False)
        header.pack_end(self.add_button)

        self.lock_button = Gtk.Button()
        self.lock_button.set_icon_name("system-lock-screen-symbolic")
        self.lock_button.set_tooltip_text(_("Lock Vault"))
        self.lock_button.update_property(
            [Gtk.AccessibleProperty.LABEL], [_("Lock Vault")]
        )
        self.lock_button.set_visible(False)
        header.pack_end(self.lock_button)

        toolbar_view.add_top_bar(header)

        # View stack
        self.view_stack = Adw.ViewStack()
        self.view_switcher_title.set_stack(self.view_stack)

        # Generator view
        self.generator_view = GeneratorView()
        self.view_stack.add_titled_with_icon(
            self.generator_view, "generator", _("Generator"), "view-reveal-symbolic"
        )

        # Vault view
        self.vault_view = VaultView(self.database, self.session)
        self.view_stack.add_titled_with_icon(
            self.vault_view, "vault", _("Vault"), "dialog-password-symbolic"
        )

        # Connect vault buttons
        self.add_button.connect("clicked", lambda _: self.vault_view._show_add_dialog())
        self.lock_button.connect("clicked", lambda _: self.vault_view._lock_vault())

        # Connect stack notify to show/hide vault buttons
        self.view_stack.connect("notify::visible-child", self._on_view_changed)

        toolbar_view.set_content(self.view_stack)

        # Bottom view switcher bar (shown on narrow windows)
        self.view_switcher_bar = Adw.ViewSwitcherBar()
        self.view_switcher_bar.set_stack(self.view_stack)
        toolbar_view.add_bottom_bar(self.view_switcher_bar)

        # Bind title squeezing to bottom bar reveal
        self.view_switcher_title.connect(
            "notify::title-visible", self._on_title_visible_changed
        )

        page.set_child(toolbar_view)

        return page

    def _on_view_changed(self, stack, *args) -> None:
        """Handle view change to show/hide vault buttons"""
        is_vault = stack.get_visible_child_name() == "vault"
        is_authenticated = self.session.is_authenticated()

        self.add_button.set_visible(is_vault and is_authenticated)
        self.lock_button.set_visible(is_vault and is_authenticated)

    def _on_title_visible_changed(self, title, *args) -> None:
        """Show bottom bar when title is squeezed on narrow windows"""
        self.view_switcher_bar.set_reveal(title.get_title_visible())

    def show_toast(self, message: str) -> None:
        """Show a toast notification"""
        toast = Adw.Toast.new(message)
        toast.set_timeout(3)
        self.toast_overlay.add_toast(toast)

    def on_settings(self, action, param):
        """Open settings dialog"""
        dialog = SettingsDialog(self, self.backup_service, self.database)
        dialog.present()

    def _on_search_activated(self, action, param):
        """Focus vault search entry on Ctrl+F"""
        if (
            self.view_stack.get_visible_child_name() == "vault"
            and self.session.is_authenticated()
        ):
            self.vault_view.search_entry.grab_focus()
