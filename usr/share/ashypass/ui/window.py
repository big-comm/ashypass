#!/usr/bin/env python3
"""
Ashy Pass - Main Window
GTK4/libadwaita main application window with OverlaySplitView
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
from ui.totp_view import TotpView
from ui.settings_dialog import SettingsDialog


class MainWindow(Adw.ApplicationWindow):
    """Main application window with sidebar navigation"""

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
        self._build_ui()

        # Register keyboard shortcuts
        app.set_accels_for_action("win.search", ["<primary>f"])

    def _setup_actions(self):
        """Setup window actions"""
        action_settings = Gio.SimpleAction.new("settings", None)
        action_settings.connect("activate", self.on_settings)
        self.add_action(action_settings)

        action_search = Gio.SimpleAction.new("search", None)
        action_search.connect("activate", self._on_search_activated)
        self.add_action(action_search)

    def _build_ui(self) -> None:
        """Build the user interface with OverlaySplitView"""
        self.toast_overlay = Adw.ToastOverlay()

        self.split_view = Adw.OverlaySplitView()
        self.split_view.set_min_sidebar_width(220)
        self.split_view.set_max_sidebar_width(280)
        self.split_view.set_sidebar_width_fraction(0.30)

        # Build sidebar and content
        self.split_view.set_sidebar(self._build_sidebar())
        self.split_view.set_content(self._build_content())

        self.toast_overlay.set_child(self.split_view)
        self.set_content(self.toast_overlay)

    def _build_sidebar(self) -> Adw.ToolbarView:
        """Build sidebar with navigation items"""
        toolbar = Adw.ToolbarView()

        # Sidebar header
        header = Adw.HeaderBar()
        header.set_show_end_title_buttons(False)

        title_label = Gtk.Label(label="Ashy Pass")
        title_label.add_css_class("heading")
        header.set_title_widget(title_label)

        toolbar.add_top_bar(header)

        # Navigation list
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.set_vexpand(True)

        nav_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        nav_box.set_margin_start(8)
        nav_box.set_margin_end(8)
        nav_box.set_margin_top(6)
        nav_box.set_margin_bottom(12)

        # Navigation items
        self._nav_buttons = {}
        self._nav_box = nav_box

        self._add_nav_item(nav_box, "vault", "dialog-password-symbolic", _("Vault"))
        self._add_nav_item(nav_box, "totp", "auth-sim-symbolic", _("2FA"))
        self._add_nav_item(nav_box, "generator", "view-reveal-symbolic", _("Generator"))

        # Dynamic items (shown when authenticated)
        self._auth_separator = Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL)
        self._auth_separator.set_margin_top(6)
        self._auth_separator.set_margin_bottom(6)
        self._auth_separator.set_visible(False)
        nav_box.append(self._auth_separator)

        self._add_nav_item(nav_box, "groups", "folder-symbolic", _("Groups"))
        self._nav_buttons["groups"].set_visible(False)

        self._add_nav_item(
            nav_box, "favorites", "emblem-favorite-symbolic", _("Favorites")
        )
        self._nav_buttons["favorites"].set_visible(False)

        self._lock_nav_btn = self._add_nav_item(
            nav_box, "lock", "system-lock-screen-symbolic", _("Lock")
        )
        self._nav_buttons["lock"].set_visible(False)

        # Separator before settings
        sep = Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL)
        sep.set_margin_top(6)
        sep.set_margin_bottom(6)
        nav_box.append(sep)

        self._add_nav_item(nav_box, "settings", "emblem-system-symbolic", _("Settings"))

        scroll.set_child(nav_box)
        toolbar.set_content(scroll)

        return toolbar

    def _add_nav_item(self, parent: Gtk.Box, name: str, icon_name: str, label: str):
        """Add a navigation item to the sidebar"""
        btn = Gtk.Button()
        btn.add_css_class("flat")

        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        box.set_margin_start(8)
        box.set_margin_end(8)
        box.set_margin_top(6)
        box.set_margin_bottom(6)

        icon = Gtk.Image.new_from_icon_name(icon_name)
        icon.set_pixel_size(18)
        box.append(icon)

        lbl = Gtk.Label(label=label)
        lbl.set_xalign(0)
        lbl.set_hexpand(True)
        box.append(lbl)

        btn.set_child(box)
        btn.connect("clicked", self._on_nav_clicked, name)

        self._nav_buttons[name] = btn
        parent.append(btn)

    def _build_content(self) -> Adw.ToolbarView:
        """Build the content area with header and stacked views"""
        toolbar = Adw.ToolbarView()

        # Content header
        self.content_header = Adw.HeaderBar()
        self.content_header.set_show_start_title_buttons(False)

        # Menu Button (right side)
        menu_button = Gtk.MenuButton()
        menu_button.set_icon_name("open-menu-symbolic")
        menu_button.update_property([Gtk.AccessibleProperty.LABEL], [_("Main Menu")])

        menu = Gio.Menu()
        section_app = Gio.Menu()
        section_app.append(_("About"), "app.about")
        section_app.append(_("Quit"), "app.quit")
        menu.append_section(None, section_app)

        menu_button.set_menu_model(menu)
        self.content_header.pack_end(menu_button)

        # Vault action buttons (visible when vault is active and authenticated)
        self.add_button = Gtk.Button()
        self.add_button.set_icon_name("list-add-symbolic")
        self.add_button.set_tooltip_text(_("Add Password"))
        self.add_button.update_property(
            [Gtk.AccessibleProperty.LABEL], [_("Add Password")]
        )
        self.add_button.set_visible(False)
        self.content_header.pack_end(self.add_button)

        self.lock_button = Gtk.Button()
        self.lock_button.set_icon_name("system-lock-screen-symbolic")
        self.lock_button.set_tooltip_text(_("Lock Vault"))
        self.lock_button.update_property(
            [Gtk.AccessibleProperty.LABEL], [_("Lock Vault")]
        )
        self.lock_button.set_visible(False)
        self.content_header.pack_end(self.lock_button)

        # Search toggle button (left side)
        self.search_button = Gtk.ToggleButton()
        self.search_button.set_icon_name("edit-find-symbolic")
        self.search_button.set_tooltip_text(_("Search"))
        self.search_button.set_visible(False)
        self.search_button.connect("toggled", self._on_search_toggled)
        self.content_header.pack_start(self.search_button)

        # Title (center)
        self.content_title = Gtk.Label(label=_("Vault"))
        self.content_title.add_css_class("heading")
        self.content_header.set_title_widget(self.content_title)

        toolbar.add_top_bar(self.content_header)

        # Content stack
        self.content_stack = Gtk.Stack()
        self.content_stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        self.content_stack.set_transition_duration(200)

        # Vault view
        self.vault_view = VaultView(self.database, self.session)
        self.content_stack.add_named(self.vault_view, "vault")

        # TOTP view
        self.totp_view = TotpView(self.database, self.session)
        self.content_stack.add_named(self.totp_view, "totp")

        # Generator view
        self.generator_view = GeneratorView()
        self.content_stack.add_named(self.generator_view, "generator")

        # Connect vault buttons
        self.add_button.connect("clicked", lambda _: self.vault_view._show_add_dialog())
        self.lock_button.connect("clicked", lambda _: self.vault_view._lock_vault())

        toolbar.set_content(self.content_stack)

        # Select vault by default
        self._select_nav("vault")

        return toolbar

    def _on_nav_clicked(self, button: Gtk.Button, name: str):
        """Handle sidebar navigation click"""
        if name == "settings":
            self.on_settings(None, None)
            return
        if name == "lock":
            self.vault_view._lock_vault()
            self._update_auth_nav()
            return
        if name == "groups":
            self._highlight_nav("groups")
            self.content_stack.set_visible_child_name("vault")
            self.content_title.set_label(_("Groups"))
            self.vault_view.show_groups_view()
            self.add_button.set_visible(False)
            self.lock_button.set_visible(False)
            return
        if name == "favorites":
            self._highlight_nav("favorites")
            self.content_stack.set_visible_child_name("vault")
            self.content_title.set_label(_("Favorites"))
            self.vault_view.show_favorites_view()
            self.add_button.set_visible(False)
            self.lock_button.set_visible(False)
            return
        self._select_nav(name)

    def _highlight_nav(self, name: str):
        """Highlight a nav button without switching content stack"""
        for btn_name, btn in self._nav_buttons.items():
            if btn_name == name:
                btn.remove_css_class("flat")
                btn.add_css_class("suggested-action")
            else:
                btn.remove_css_class("suggested-action")
                btn.add_css_class("flat")

    def _select_nav(self, name: str):
        """Select a navigation item and show corresponding content"""
        # Update button styles
        for btn_name, btn in self._nav_buttons.items():
            if btn_name == name:
                btn.remove_css_class("flat")
                btn.add_css_class("suggested-action")
            else:
                btn.remove_css_class("suggested-action")
                btn.add_css_class("flat")

        # Update content
        self.content_stack.set_visible_child_name(name)

        # Close search when switching views
        self.search_button.set_active(False)

        # Reset vault view mode when navigating to vault directly
        if name == "vault":
            self.vault_view._view_mode = "all"

        # Update title
        titles = {
            "vault": _("Vault"),
            "totp": _("2FA"),
            "generator": _("Generator"),
        }
        self.content_title.set_label(titles.get(name, name))

        # Update vault buttons visibility
        is_vault = name == "vault"
        is_authenticated = self.session.is_authenticated()
        self.add_button.set_visible(is_vault and is_authenticated)
        self.lock_button.set_visible(is_vault and is_authenticated)

        # Update auth-dependent nav items
        self._update_auth_nav()

        # Refresh TOTP view when navigated to
        if name == "totp":
            self.totp_view.refresh()

    def _on_view_changed(self, *args) -> None:
        """Handle view change to show/hide vault buttons (called by vault_view)"""
        self._update_auth_nav()

    def _update_auth_nav(self) -> None:
        """Update sidebar items based on authentication state"""
        is_authenticated = self.session.is_authenticated()
        current = self.content_stack.get_visible_child_name()
        is_vault = current == "vault"

        # Header buttons
        self.add_button.set_visible(is_vault and is_authenticated)
        self.lock_button.set_visible(is_vault and is_authenticated)

        # Search button (visible in vault, totp, groups, favorites)
        is_searchable = current in ("vault", "totp")
        self.search_button.set_visible(is_searchable and is_authenticated)

        # Dynamic sidebar items
        self._auth_separator.set_visible(is_authenticated)
        self._nav_buttons["groups"].set_visible(is_authenticated)
        self._nav_buttons["favorites"].set_visible(is_authenticated)
        self._nav_buttons["lock"].set_visible(is_authenticated)

    def _on_search_toggled(self, btn: Gtk.ToggleButton) -> None:
        """Toggle search bar visibility in the current view"""
        current = self.content_stack.get_visible_child_name()
        active = btn.get_active()
        if current == "vault":
            self.vault_view.search_bar.set_search_mode(active)
            if active:
                self.vault_view.search_entry.grab_focus()
        elif current == "totp":
            self.totp_view.search_bar.set_search_mode(active)
            if active:
                self.totp_view.search_entry.grab_focus()

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
            self.content_stack.get_visible_child_name() == "vault"
            and self.session.is_authenticated()
        ):
            self.vault_view.search_entry.grab_focus()
