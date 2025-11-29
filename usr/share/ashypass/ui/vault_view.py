#!/usr/bin/env python3
"""
Ashy Pass - Vault View
GTK4/libadwaita UI for encrypted password storage
"""

import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')

from gi.repository import Gtk, Adw, GLib, Gio
from typing import Optional, Dict, Any
import urllib.request
import urllib.parse
import hashlib
import os

from core.database import Database
from core.auth import SessionManager
from core.generator import PasswordGenerator, PasswordConfig
from utils.clipboard import ClipboardManager
from utils.i18n import _
from core.config import MIN_MASTER_PASSWORD_LENGTH, DATA_DIR


class VaultView(Adw.NavigationPage):
    """Password vault view with authentication"""
    
    def __init__(self, database: Database, session: SessionManager):
        super().__init__(title=_("Vault"))

        self.database = database
        self.session = session
        self.clipboard = ClipboardManager()
        self.generator = PasswordGenerator()

        # Favicon cache directory
        self.favicon_cache_dir = DATA_DIR / "favicons"
        self.favicon_cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Set lock callback
        self.session.set_lock_callback(self._on_session_locked)
        
        # Build UI
        self._build_ui()
        
        # Check authentication state
        self._update_view()
    
    def _build_ui(self) -> None:
        """Build the user interface"""
        # Main stack for auth/content switching
        self.main_stack = Gtk.Stack()
        self.main_stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        self.main_stack.set_transition_duration(300)
        
        # Login/setup page
        self.main_stack.add_named(self._create_auth_page(), "auth")
        
        # Vault content page
        self.main_stack.add_named(self._create_vault_page(), "vault")
        
        self.set_child(self.main_stack)
    
    def _create_auth_page(self) -> Gtk.Widget:
        """Create authentication page"""
        # Content
        clamp = Adw.Clamp()
        clamp.set_maximum_size(400)
        clamp.set_margin_top(48)
        clamp.set_margin_bottom(48)
        clamp.set_margin_start(12)
        clamp.set_margin_end(12)
        
        content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        content_box.set_spacing(24)
        
        # Icon
        icon = Gtk.Image.new_from_icon_name("dialog-password-symbolic")
        icon.set_pixel_size(64)
        icon.add_css_class("dim-label")
        content_box.append(icon)
        
        # Title
        title = Gtk.Label()
        title.set_markup(f"<span size='xx-large' weight='bold'>{_('Password Vault')}</span>")
        content_box.append(title)

        # Subtitle
        subtitle = Gtk.Label()
        subtitle.set_text(_("Enter your master password to unlock"))
        subtitle.add_css_class("dim-label")
        content_box.append(subtitle)
        
        # Password entry group
        self.auth_group = Adw.PreferencesGroup()
        
        self.master_password_entry = Adw.PasswordEntryRow()
        self.master_password_entry.set_title(_("Master Password"))
        self.master_password_entry.connect("entry-activated", self._on_unlock_clicked)
        self.auth_group.add(self.master_password_entry)

        # For first-time setup
        self.confirm_password_entry = Adw.PasswordEntryRow()
        self.confirm_password_entry.set_title(_("Confirm Password"))
        self.confirm_password_entry.connect("entry-activated", self._on_unlock_clicked)
        self.confirm_password_entry.set_visible(False)
        self.auth_group.add(self.confirm_password_entry)
        
        content_box.append(self.auth_group)
        
        # Error label
        self.auth_error_label = Gtk.Label()
        self.auth_error_label.add_css_class("error")
        self.auth_error_label.set_visible(False)
        content_box.append(self.auth_error_label)
        
        # Unlock button
        self.unlock_button = Gtk.Button()
        self.unlock_button.set_label(_("Unlock Vault"))
        self.unlock_button.add_css_class("pill")
        self.unlock_button.add_css_class("suggested-action")
        self.unlock_button.set_halign(Gtk.Align.CENTER)
        self.unlock_button.connect("clicked", self._on_unlock_clicked)
        content_box.append(self.unlock_button)

        clamp.set_child(content_box)

        return clamp
    
    def _create_vault_page(self) -> Gtk.Widget:
        """Create vault content page"""
        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)

        # Search bar
        search_bar_widget = Gtk.SearchBar()
        self.search_entry = Gtk.SearchEntry()
        self.search_entry.set_placeholder_text(_("Search passwords..."))
        self.search_entry.connect("search-changed", self._on_search_changed)
        search_bar_widget.set_child(self.search_entry)
        search_bar_widget.set_key_capture_widget(main_box)
        main_box.append(search_bar_widget)
        
        # Password list
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_vexpand(True)
        
        self.list_box = Gtk.ListBox()
        self.list_box.set_selection_mode(Gtk.SelectionMode.NONE)
        self.list_box.add_css_class("boxed-list")
        self.list_box.set_margin_top(12)
        self.list_box.set_margin_bottom(12)
        self.list_box.set_margin_start(12)
        self.list_box.set_margin_end(12)
        
        scrolled.set_child(self.list_box)
        
        # Empty state
        self.empty_status = Adw.StatusPage()
        self.empty_status.set_icon_name("dialog-password-symbolic")
        self.empty_status.set_title(_("No Passwords Stored"))
        self.empty_status.set_description(_("Add your first password using the + button"))
        
        # Stack for empty/content state
        self.content_stack = Gtk.Stack()
        self.content_stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        self.content_stack.set_transition_duration(200)
        self.content_stack.add_named(scrolled, "list")
        self.content_stack.add_named(self.empty_status, "empty")

        main_box.append(self.content_stack)

        return main_box
    
    def _update_view(self) -> None:
        """Update view based on authentication state"""
        if self.session.is_authenticated():
            self.main_stack.set_visible_child_name("vault")
            self._load_passwords()
            # Update toolbar buttons visibility
            self._update_toolbar_buttons()
        else:
            # Check if we need setup or login
            has_master = self.database.has_master_password()

            if has_master:
                self.unlock_button.set_label(_("Unlock Vault"))
                self.confirm_password_entry.set_visible(False)
            else:
                self.unlock_button.set_label(_("Create Master Password"))
                self.confirm_password_entry.set_visible(True)
            
            self.main_stack.set_visible_child_name("auth")
            self.master_password_entry.set_text("")
            self.confirm_password_entry.set_text("")
            self.auth_error_label.set_visible(False)
            # Update toolbar buttons visibility
            self._update_toolbar_buttons()

    def _update_toolbar_buttons(self) -> None:
        """Update toolbar buttons visibility"""
        root = self.get_root()
        if root and hasattr(root, '_on_view_changed'):
            root._on_view_changed(root.view_stack)
    
    def _on_unlock_clicked(self, *args) -> None:
        """Handle unlock button click"""
        password = self.master_password_entry.get_text()

        if not password:
            self._show_auth_error(_("Please enter a password"))
            return

        has_master = self.database.has_master_password()

        if has_master:
            # Login attempt
            if self.database.verify_master_password(password):
                self.session.login()
                self._update_view()
            else:
                self._show_auth_error(_("Incorrect master password"))
        else:
            # First-time setup
            confirm = self.confirm_password_entry.get_text()

            if len(password) < MIN_MASTER_PASSWORD_LENGTH:
                self._show_auth_error(_("Password must be at least {min} characters").format(min=MIN_MASTER_PASSWORD_LENGTH))
                return

            if password != confirm:
                self._show_auth_error(_("Passwords do not match"))
                return

            if self.database.set_master_password(password):
                self.session.login()
                self._update_view()
            else:
                self._show_auth_error(_("Failed to setup master password"))
    
    def _show_auth_error(self, message: str) -> None:
        """Show authentication error message"""
        self.auth_error_label.set_text(message)
        self.auth_error_label.set_visible(True)
    
    def _lock_vault(self) -> None:
        """Lock the vault"""
        self.session.logout()
        self._update_view()
    
    def _on_session_locked(self) -> None:
        """Handle automatic session lock"""
        self._update_view()
        # Show toast notification
        self.activate_action("app.show-toast", GLib.Variant.new_string(_("Vault locked due to inactivity")))
    
    def _load_passwords(self, search: Optional[str] = None) -> None:
        """Load passwords from database"""
        # Clear list
        while True:
            row = self.list_box.get_first_child()
            if row is None:
                break
            self.list_box.remove(row)
        
        # Load from database
        passwords = self.database.get_passwords(search)
        
        if not passwords:
            self.content_stack.set_visible_child_name("empty")
            return
        
        self.content_stack.set_visible_child_name("list")
        
        # Add rows
        for pwd_data in passwords:
            row = self._create_password_row(pwd_data)
            self.list_box.append(row)
    
    def _create_password_row(self, pwd_data: Dict[str, Any]) -> Adw.ActionRow:
        """Create a password list row"""
        row = Adw.ActionRow()
        row.set_title(pwd_data["title"])

        subtitle_parts = []
        if pwd_data.get("username"):
            subtitle_parts.append(pwd_data["username"])
        if pwd_data.get("url"):
            subtitle_parts.append(pwd_data["url"])

        if subtitle_parts:
            row.set_subtitle(" • ".join(subtitle_parts))

        # Add favicon if URL is available
        if pwd_data.get("url"):
            favicon_path = self._fetch_favicon(pwd_data["url"])
            if favicon_path and os.path.exists(favicon_path):
                try:
                    favicon = Gtk.Image.new_from_file(favicon_path)
                    favicon.set_pixel_size(32)
                    row.add_prefix(favicon)
                except:
                    # Use default icon if favicon fails to load
                    icon = Gtk.Image.new_from_icon_name("dialog-password-symbolic")
                    icon.set_pixel_size(32)
                    row.add_prefix(icon)
            else:
                # Use default icon
                icon = Gtk.Image.new_from_icon_name("dialog-password-symbolic")
                icon.set_pixel_size(32)
                row.add_prefix(icon)
        else:
            # Use default icon if no URL
            icon = Gtk.Image.new_from_icon_name("dialog-password-symbolic")
            icon.set_pixel_size(32)
            row.add_prefix(icon)
        
        # Copy button
        copy_btn = Gtk.Button()
        copy_btn.set_icon_name("edit-copy-symbolic")
        copy_btn.set_valign(Gtk.Align.CENTER)
        copy_btn.add_css_class("flat")
        copy_btn.set_tooltip_text(_("Copy Password"))
        copy_btn.connect("clicked", lambda _, pwd_id=pwd_data["id"]: self._copy_password(pwd_id))
        row.add_suffix(copy_btn)

        # Edit button
        edit_btn = Gtk.Button()
        edit_btn.set_icon_name("document-edit-symbolic")
        edit_btn.set_valign(Gtk.Align.CENTER)
        edit_btn.add_css_class("flat")
        edit_btn.set_tooltip_text(_("Edit"))
        edit_btn.connect("clicked", lambda _, pwd_id=pwd_data["id"]: self._show_edit_dialog(pwd_id))
        row.add_suffix(edit_btn)

        # Delete button
        delete_btn = Gtk.Button()
        delete_btn.set_icon_name("user-trash-symbolic")
        delete_btn.set_valign(Gtk.Align.CENTER)
        delete_btn.add_css_class("flat")
        delete_btn.set_tooltip_text(_("Delete"))
        delete_btn.connect("clicked", lambda _, pwd_id=pwd_data["id"]: self._confirm_delete(pwd_id))
        row.add_suffix(delete_btn)
        
        return row
    
    def _on_search_changed(self, entry: Gtk.SearchEntry) -> None:
        """Handle search text change"""
        search_text = entry.get_text().strip()
        self._load_passwords(search_text if search_text else None)
        self.session.on_activity()
    
    def _copy_password(self, password_id: int) -> None:
        """Copy password to clipboard"""
        entry = self.database.get_password(password_id)
        if entry:
            self.clipboard.copy_text(entry["password"])
            self.activate_action("app.show-toast", GLib.Variant.new_string(_("Password copied to clipboard")))
            self.session.on_activity()
    
    def _show_add_dialog(self) -> None:
        """Show add password dialog"""
        self._show_password_dialog()
    
    def _show_edit_dialog(self, password_id: int) -> None:
        """Show edit password dialog"""
        entry = self.database.get_password(password_id)
        if entry:
            self._show_password_dialog(entry)
        self.session.on_activity()
    
    def _show_password_dialog(self, entry: Optional[Dict[str, Any]] = None) -> None:
        """Show password add/edit dialog"""
        is_edit = entry is not None

        dialog = Adw.AlertDialog()
        dialog.set_heading(_("Edit Password") if is_edit else _("Add Password"))
        dialog.add_response("cancel", _("Cancel"))
        dialog.add_response("save", _("Save"))
        dialog.set_response_appearance("save", Adw.ResponseAppearance.SUGGESTED)
        dialog.set_default_response("save")
        dialog.set_close_response("cancel")
        
        # Form
        form = Adw.PreferencesGroup()

        title_entry = Adw.EntryRow()
        title_entry.set_title(_("Title"))
        if entry:
            title_entry.set_text(entry.get("title", ""))
        form.add(title_entry)

        username_entry = Adw.EntryRow()
        username_entry.set_title(_("Username"))
        if entry:
            username_entry.set_text(entry.get("username", "") or "")
        form.add(username_entry)

        # Password row with generate button
        password_row = Adw.ActionRow()
        password_row.set_title(_("Password"))

        password_entry = Gtk.PasswordEntry()
        password_entry.set_show_peek_icon(True)
        password_entry.set_hexpand(True)
        if entry:
            password_entry.set_text(entry.get("password", ""))
        password_row.add_suffix(password_entry)

        # Generate button with menu
        generate_btn = Gtk.MenuButton()
        generate_btn.set_icon_name("document-new-symbolic")
        generate_btn.set_tooltip_text(_("Generate Password"))
        generate_btn.set_valign(Gtk.Align.CENTER)

        # Create menu
        menu = Gio.Menu()
        menu.append(_("Strong Password"), "password.generate-strong")
        menu.append(_("Passphrase"), "password.generate-passphrase")
        menu.append(_("PIN Code"), "password.generate-pin")
        menu.append(_("Custom..."), "password.generate-custom")
        generate_btn.set_menu_model(menu)

        password_row.add_suffix(generate_btn)
        form.add(password_row)

        # Store references for callbacks
        dialog._password_entry = password_entry
        dialog._vault_view = self

        # Setup action group for password generation
        action_group = Gio.SimpleActionGroup()

        # Generate strong password action
        action_strong = Gio.SimpleAction.new("generate-strong", None)
        action_strong.connect("activate", lambda a, p: self._generate_password_in_dialog(password_entry, "strong"))
        action_group.add_action(action_strong)

        # Generate passphrase action
        action_passphrase = Gio.SimpleAction.new("generate-passphrase", None)
        action_passphrase.connect("activate", lambda a, p: self._generate_password_in_dialog(password_entry, "passphrase"))
        action_group.add_action(action_passphrase)

        # Generate PIN action
        action_pin = Gio.SimpleAction.new("generate-pin", None)
        action_pin.connect("activate", lambda a, p: self._generate_password_in_dialog(password_entry, "pin"))
        action_group.add_action(action_pin)

        # Generate custom action
        action_custom = Gio.SimpleAction.new("generate-custom", None)
        action_custom.connect("activate", lambda a, p: self._show_custom_generator_dialog(password_entry))
        action_group.add_action(action_custom)

        generate_btn.insert_action_group("password", action_group)

        url_entry = Adw.EntryRow()
        url_entry.set_title(_("URL"))
        if entry:
            url_entry.set_text(entry.get("url", "") or "")
        form.add(url_entry)

        notes_entry = Adw.EntryRow()
        notes_entry.set_title(_("Notes"))
        if entry:
            notes_entry.set_text(entry.get("notes", "") or "")
        form.add(notes_entry)
        
        dialog.set_extra_child(form)
        
        def on_response(dlg, response):
            if response == "save":
                title = title_entry.get_text().strip()
                username = username_entry.get_text().strip() or None
                password = password_entry.get_text()
                url = url_entry.get_text().strip() or None
                notes = notes_entry.get_text().strip() or None

                if not title:
                    self.activate_action("app.show-toast", GLib.Variant.new_string(_("Title is required")))
                    return

                if not password:
                    self.activate_action("app.show-toast", GLib.Variant.new_string(_("Password is required")))
                    return

                try:
                    if is_edit:
                        self.database.update_password(
                            entry["id"],
                            title=title,
                            username=username,
                            password=password,
                            url=url,
                            notes=notes
                        )
                        self.activate_action("app.show-toast", GLib.Variant.new_string(_("Password updated")))
                    else:
                        self.database.add_password(title, password, username, notes, url)
                        self.activate_action("app.show-toast", GLib.Variant.new_string(_("Password added")))

                    self._load_passwords()
                    self.session.on_activity()
                except Exception as e:
                    self.activate_action("app.show-toast", GLib.Variant.new_string(_("Error: {error}").format(error=str(e))))
        
        dialog.connect("response", on_response)
        dialog.present(self.get_root())
    
    def _confirm_delete(self, password_id: int) -> None:
        """Show delete confirmation dialog"""
        entry = self.database.get_password(password_id)
        if not entry:
            return

        dialog = Adw.AlertDialog()
        dialog.set_heading(_("Delete Password?"))
        dialog.set_body(_("Are you sure you want to delete '{title}'? This action cannot be undone.").format(title=entry['title']))
        dialog.add_response("cancel", _("Cancel"))
        dialog.add_response("delete", _("Delete"))
        dialog.set_response_appearance("delete", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_default_response("cancel")
        dialog.set_close_response("cancel")

        def on_response(dlg, response):
            if response == "delete":
                if self.database.delete_password(password_id):
                    self.activate_action("app.show-toast", GLib.Variant.new_string(_("Password deleted")))
                    self._load_passwords()
                    self.session.on_activity()

        dialog.connect("response", on_response)
        dialog.present(self.get_root())

    def _generate_password_in_dialog(self, password_entry: Gtk.PasswordEntry, gen_type: str) -> None:
        """Generate password directly in the dialog"""
        try:
            if gen_type == "strong":
                # Strong password: 16 chars, all types
                config = PasswordConfig(
                    length=16,
                    use_uppercase=True,
                    use_lowercase=True,
                    use_digits=True,
                    use_symbols=True,
                    exclude_ambiguous=True
                )
                password = self.generator.generate_password(config)
            elif gen_type == "passphrase":
                # Passphrase: 4 words
                password = self.generator.generate_passphrase(
                    num_words=4,
                    separator="-",
                    capitalize=True,
                    add_number=True
                )
            elif gen_type == "pin":
                # PIN: 6 digits
                password = self.generator.generate_pin(6)
            else:
                return

            password_entry.set_text(password)
            self.activate_action("app.show-toast", GLib.Variant.new_string(_("Password generated")))
        except Exception as e:
            self.activate_action("app.show-toast", GLib.Variant.new_string(_("Error generating password")))

    def _show_custom_generator_dialog(self, password_entry: Gtk.PasswordEntry) -> None:
        """Show custom generator dialog with all options"""
        dialog = Adw.AlertDialog()
        dialog.set_heading(_("Custom Password Generator"))
        dialog.add_response("cancel", _("Cancel"))
        dialog.add_response("generate", _("Generate"))
        dialog.set_response_appearance("generate", Adw.ResponseAppearance.SUGGESTED)
        dialog.set_default_response("generate")
        dialog.set_close_response("cancel")

        # Type selector
        type_group = Adw.PreferencesGroup()
        type_group.set_title(_("Type"))

        type_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        type_box.set_halign(Gtk.Align.CENTER)
        type_box.add_css_class("linked")

        password_btn = Gtk.ToggleButton(label=_("Password"))
        password_btn.set_active(True)
        type_box.append(password_btn)

        passphrase_btn = Gtk.ToggleButton(label=_("Passphrase"))
        passphrase_btn.set_group(password_btn)
        type_box.append(passphrase_btn)

        pin_btn = Gtk.ToggleButton(label=_("PIN"))
        pin_btn.set_group(password_btn)
        type_box.append(pin_btn)

        type_group.add(type_box)

        # Options stack
        options_stack = Gtk.Stack()
        options_stack.set_transition_type(Gtk.StackTransitionType.SLIDE_LEFT_RIGHT)

        # Password options
        pwd_group = Adw.PreferencesGroup()
        pwd_group.set_title(_("Password Options"))

        length_spin = Adw.SpinRow()
        length_spin.set_title(_("Length"))
        length_spin.set_adjustment(Gtk.Adjustment(value=16, lower=8, upper=64, step_increment=1))
        pwd_group.add(length_spin)

        uppercase_switch = Adw.SwitchRow(title=_("Uppercase Letters"), active=True)
        pwd_group.add(uppercase_switch)

        lowercase_switch = Adw.SwitchRow(title=_("Lowercase Letters"), active=True)
        pwd_group.add(lowercase_switch)

        digits_switch = Adw.SwitchRow(title=_("Digits"), active=True)
        pwd_group.add(digits_switch)

        symbols_switch = Adw.SwitchRow(title=_("Symbols"), active=True)
        pwd_group.add(symbols_switch)

        ambiguous_switch = Adw.SwitchRow(title=_("Exclude Ambiguous"), active=True)
        pwd_group.add(ambiguous_switch)

        options_stack.add_named(pwd_group, "password")

        # Passphrase options
        phrase_group = Adw.PreferencesGroup()
        phrase_group.set_title(_("Passphrase Options"))

        words_spin = Adw.SpinRow(title=_("Number of Words"))
        words_spin.set_adjustment(Gtk.Adjustment(value=4, lower=3, upper=10, step_increment=1))
        phrase_group.add(words_spin)

        separator_entry = Adw.EntryRow(title=_("Separator"), text="-")
        phrase_group.add(separator_entry)

        capitalize_switch = Adw.SwitchRow(title=_("Capitalize Words"), active=True)
        phrase_group.add(capitalize_switch)

        add_number_switch = Adw.SwitchRow(title=_("Add Number"), active=True)
        phrase_group.add(add_number_switch)

        options_stack.add_named(phrase_group, "passphrase")

        # PIN options
        pin_group = Adw.PreferencesGroup()
        pin_group.set_title(_("PIN Options"))

        pin_length_spin = Adw.SpinRow(title=_("Length"))
        pin_length_spin.set_adjustment(Gtk.Adjustment(value=6, lower=4, upper=12, step_increment=1))
        pin_group.add(pin_length_spin)

        options_stack.add_named(pin_group, "pin")

        # Connect type buttons to stack
        def on_type_changed(button, type_name):
            if button.get_active():
                options_stack.set_visible_child_name(type_name)

        password_btn.connect("toggled", on_type_changed, "password")
        passphrase_btn.connect("toggled", on_type_changed, "passphrase")
        pin_btn.connect("toggled", on_type_changed, "pin")

        # Main container
        container = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        container.set_spacing(12)
        container.append(type_group)
        container.append(options_stack)

        dialog.set_extra_child(container)

        def on_response(dlg, response):
            if response == "generate":
                try:
                    current_type = options_stack.get_visible_child_name()

                    if current_type == "password":
                        config = PasswordConfig(
                            length=int(length_spin.get_value()),
                            use_uppercase=uppercase_switch.get_active(),
                            use_lowercase=lowercase_switch.get_active(),
                            use_digits=digits_switch.get_active(),
                            use_symbols=symbols_switch.get_active(),
                            exclude_ambiguous=ambiguous_switch.get_active()
                        )
                        password = self.generator.generate_password(config)
                    elif current_type == "passphrase":
                        password = self.generator.generate_passphrase(
                            num_words=int(words_spin.get_value()),
                            separator=separator_entry.get_text(),
                            capitalize=capitalize_switch.get_active(),
                            add_number=add_number_switch.get_active()
                        )
                    elif current_type == "pin":
                        password = self.generator.generate_pin(int(pin_length_spin.get_value()))

                    password_entry.set_text(password)
                    self.activate_action("app.show-toast", GLib.Variant.new_string(_("Password generated")))
                except Exception as e:
                    self.activate_action("app.show-toast", GLib.Variant.new_string(_("Error generating password")))

        dialog.connect("response", on_response)
        dialog.present(self.get_root())

    def _get_favicon_url(self, url: str) -> Optional[str]:
        """Get favicon URL from website URL"""
        if not url:
            return None

        try:
            parsed = urllib.parse.urlparse(url)
            if not parsed.scheme:
                url = f"https://{url}"
                parsed = urllib.parse.urlparse(url)

            domain = f"{parsed.scheme}://{parsed.netloc}"
            return f"{domain}/favicon.ico"
        except:
            return None

    def _fetch_favicon(self, url: str) -> Optional[str]:
        """Fetch and cache favicon, return local path"""
        favicon_url = self._get_favicon_url(url)
        if not favicon_url:
            return None

        # Generate cache filename from URL hash
        url_hash = hashlib.md5(favicon_url.encode()).hexdigest()
        cache_path = self.favicon_cache_dir / f"{url_hash}.ico"

        # Return if already cached
        if cache_path.exists():
            return str(cache_path)

        # Download favicon
        try:
            req = urllib.request.Request(favicon_url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=5) as response:
                with open(cache_path, 'wb') as f:
                    f.write(response.read())
            return str(cache_path)
        except:
            return None
