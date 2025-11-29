#!/usr/bin/env python3
"""
Ashy Pass - Main Window
GTK4/libadwaita main application window with view switcher
"""

import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')

from gi.repository import Gtk, Adw, GLib, GObject

from core.config import WINDOW_DEFAULT_WIDTH, WINDOW_DEFAULT_HEIGHT, WINDOW_MIN_WIDTH, WINDOW_MIN_HEIGHT
from core.database import Database
from core.auth import SessionManager
from utils.i18n import _
from ui.generator_view import GeneratorView
from ui.vault_view import VaultView


class MainWindow(Adw.ApplicationWindow):
    """Main application window"""
    
    def __init__(self, app, database: Database):
        super().__init__(application=app)
        
        self.database = database
        self.session = SessionManager()
        
        # Window properties
        self.set_title("Ashy Pass")
        self.set_default_size(WINDOW_DEFAULT_WIDTH, WINDOW_DEFAULT_HEIGHT)
        self.set_size_request(WINDOW_MIN_WIDTH, WINDOW_MIN_HEIGHT)
        
        # Build UI
        self._build_ui()
    
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
