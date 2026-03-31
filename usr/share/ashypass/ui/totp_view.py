#!/usr/bin/env python3
"""
Ashy Pass - TOTP View
GTK4/libadwaita dedicated 2FA authenticator view with live countdown
"""

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Gtk, Adw, GLib, Gio, Pango
from typing import Dict, Any

from core.database import Database
from core.auth import SessionManager
from core.config import MIN_MASTER_PASSWORD_LENGTH
from core.totp import generate_totp, remaining_seconds
from utils.clipboard import ClipboardManager
from utils.i18n import _
from utils.favicon import load_favicon_async


class TotpView(Adw.NavigationPage):
    """Dedicated 2FA/TOTP authenticator view with live codes"""

    def __init__(self, database: Database, session: SessionManager):
        super().__init__(title=_("2FA"))

        self.database = database
        self.session = session
        self.clipboard = ClipboardManager()
        self._totp_timer_id: int | None = None
        self._totp_rows: list = []  # (label, progress, pwd_data, row)
        self._updating_categories: bool = False

        self._build_ui()

    def _build_ui(self) -> None:
        """Build the TOTP view UI"""
        self.main_stack = Gtk.Stack()
        self.main_stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        self.main_stack.set_transition_duration(300)

        # Locked state — auth page
        self.main_stack.add_named(self._create_auth_page(), "locked")

        # TOTP list (includes internal empty state)
        self.main_stack.add_named(self._create_totp_page(), "totp")

        self.set_child(self.main_stack)

    def _create_auth_page(self) -> Gtk.Widget:
        """Create authentication page (same style as vault)"""
        clamp = Adw.Clamp()
        clamp.set_maximum_size(400)
        clamp.set_margin_top(48)
        clamp.set_margin_bottom(48)
        clamp.set_margin_start(12)
        clamp.set_margin_end(12)

        content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        content_box.set_spacing(24)

        icon = Gtk.Image.new_from_icon_name("dialog-password-symbolic")
        icon.set_pixel_size(64)
        icon.add_css_class("dim-label")
        content_box.append(icon)

        title = Gtk.Label()
        title.set_markup(f"<span size='xx-large' weight='bold'>{_('Ashy Pass')}</span>")
        content_box.append(title)

        subtitle = Gtk.Label()
        subtitle.set_text(_("Enter your master password to unlock"))
        subtitle.add_css_class("dim-label")
        content_box.append(subtitle)

        self.auth_group = Adw.PreferencesGroup()

        self.master_password_entry = Adw.PasswordEntryRow()
        self.master_password_entry.set_title(_("Master Password"))
        self.master_password_entry.connect("entry-activated", self._on_unlock_clicked)
        self.auth_group.add(self.master_password_entry)

        content_box.append(self.auth_group)

        self.auth_error_label = Gtk.Label()
        self.auth_error_label.add_css_class("error")
        self.auth_error_label.set_visible(False)
        content_box.append(self.auth_error_label)

        unlock_btn = Gtk.Button()
        unlock_btn.set_label(_("Unlock"))
        unlock_btn.add_css_class("pill")
        unlock_btn.add_css_class("suggested-action")
        unlock_btn.set_halign(Gtk.Align.CENTER)
        unlock_btn.connect("clicked", self._on_unlock_clicked)
        content_box.append(unlock_btn)

        clamp.set_child(content_box)
        return clamp

    def _on_unlock_clicked(self, *args) -> None:
        """Handle unlock from 2FA view"""
        password = self.master_password_entry.get_text()
        if not password:
            self._show_auth_error(_("Please enter a password"))
            return

        if not self.database.has_master_password():
            self._show_auth_error(_("Please create your master password in the Vault tab first."))
            return

        if self.database.verify_master_password(password):
            self.session.login()
            self.master_password_entry.set_text("")
            self.auth_error_label.set_visible(False)
            # Notify vault view to update too
            root = self.get_root()
            if root and hasattr(root, "vault_view"):
                root.vault_view._update_view()
            if root and hasattr(root, "_on_view_changed"):
                root._on_view_changed()
            self._load_totp_entries()
        else:
            self._show_auth_error(_("Incorrect master password"))

    def _show_auth_error(self, message: str) -> None:
        self.auth_error_label.set_text(message)
        self.auth_error_label.set_visible(True)

    def _create_totp_page(self) -> Gtk.Widget:
        """Create the main TOTP codes page"""
        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)

        # Search
        self.search_bar = Gtk.SearchBar()
        self.search_entry = Gtk.SearchEntry()
        self.search_entry.set_placeholder_text(_("Search 2FA codes..."))
        self.search_entry.update_property(
            [Gtk.AccessibleProperty.LABEL], [_("Search 2FA codes")]
        )
        self.search_entry.connect("search-changed", self._on_search_changed)
        self.search_bar.set_child(self.search_entry)
        main_box.append(self.search_bar)

        # Category filter bar
        self.category_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        self.category_bar.set_margin_start(12)
        self.category_bar.set_margin_end(12)
        self.category_bar.set_margin_top(4)
        self.category_bar.set_margin_bottom(4)
        self.category_bar.set_visible(False)

        cat_icon = Gtk.Image.new_from_icon_name("folder-symbolic")
        self.category_bar.append(cat_icon)

        self.category_dropdown = Gtk.DropDown()
        self.category_dropdown.set_hexpand(True)
        self._category_model = Gtk.StringList.new([_("All")])
        self.category_dropdown.set_model(self._category_model)
        self.category_dropdown.connect("notify::selected", self._on_category_changed)
        self.category_bar.append(self.category_dropdown)

        main_box.append(self.category_bar)

        # Inner stack: list vs empty (keeps search visible)
        self.totp_content_stack = Gtk.Stack()
        self.totp_content_stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        self.totp_content_stack.set_vexpand(True)

        # Scrollable list
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
        self.totp_content_stack.add_named(scrolled, "list")

        # Empty status for search results
        self.totp_empty_status = Adw.StatusPage()
        self.totp_empty_status.set_icon_name("edit-find-symbolic")
        self.totp_empty_status.set_title(_("No Results"))
        self.totp_empty_status.set_description(_("No 2FA codes match your search"))
        self.totp_content_stack.add_named(self.totp_empty_status, "empty")

        main_box.append(self.totp_content_stack)

        return main_box

    def refresh(self) -> None:
        """Refresh the TOTP view based on auth state"""
        if not self.session.is_authenticated():
            self._stop_timer()
            self.main_stack.set_visible_child_name("locked")
            return

        self._load_totp_entries()

    def _load_totp_entries(self, search: str | None = None) -> None:
        """Load TOTP entries from database"""
        self._stop_timer()
        self._totp_rows.clear()

        # Clear list
        while True:
            child = self.list_box.get_first_child()
            if child is None:
                break
            self.list_box.remove(child)

        # Update category filter
        self._update_category_filter()

        passwords = self.database.get_passwords(search=search)
        totp_entries = [p for p in passwords if p.get("has_totp")]

        # Apply category filter
        selected_cat = self._get_selected_category()
        if selected_cat:
            totp_entries = [
                p for p in totp_entries
                if (p.get("category") or "") == selected_cat
            ]

        if not totp_entries:
            if search:
                self.totp_empty_status.set_icon_name("edit-find-symbolic")
                self.totp_empty_status.set_title(_("No Results"))
                self.totp_empty_status.set_description(_("No 2FA codes match your search"))
            else:
                self.totp_empty_status.set_icon_name("auth-sim-symbolic")
                self.totp_empty_status.set_title(_("No 2FA Codes"))
                self.totp_empty_status.set_description(
                    _("Import your TOTP tokens from Aegis or andOTP in Settings → Import/Export")
                )
            # Stay on "totp" page so search bar remains visible
            self.main_stack.set_visible_child_name("totp")
            self.totp_content_stack.set_visible_child_name("empty")
            return

        self.main_stack.set_visible_child_name("totp")
        self.totp_content_stack.set_visible_child_name("list")

        for entry in totp_entries:
            row = self._create_totp_row(entry)
            self.list_box.append(row)

        # Start live update
        self._update_totp_displays()
        self._totp_timer_id = GLib.timeout_add(1000, self._update_totp_displays)

    def _create_totp_row(self, pwd_data: Dict[str, Any]) -> Gtk.ListBoxRow:
        """Create a row for a TOTP entry with large code on top and name below"""
        row = Gtk.ListBoxRow()
        row.set_activatable(False)

        outer_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        outer_box.set_margin_top(8)
        outer_box.set_margin_bottom(8)
        outer_box.set_margin_start(12)
        outer_box.set_margin_end(12)

        # Favicon / icon
        icon = Gtk.Image.new_from_icon_name("auth-sim-symbolic")
        icon.set_pixel_size(32)
        icon.set_valign(Gtk.Align.CENTER)
        outer_box.append(icon)

        url = pwd_data.get("url", "")
        if url:
            load_favicon_async(url, icon)

        # Center: code on top (big), name below (small)
        center_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        center_box.set_hexpand(True)
        center_box.set_valign(Gtk.Align.CENTER)

        code_label = Gtk.Label()
        code_label.add_css_class("monospace")
        code_label.add_css_class("title-1")
        code_label.set_xalign(0)
        code_label.set_text("------")
        center_box.append(code_label)

        # Name + username subtitle
        subtitle_parts = [pwd_data["title"]]
        if pwd_data.get("username"):
            subtitle_parts.append(pwd_data["username"])
        if pwd_data.get("category"):
            subtitle_parts.append(f"📁 {pwd_data['category']}")

        name_label = Gtk.Label()
        name_label.set_xalign(0)
        name_label.set_text(" · ".join(subtitle_parts))
        name_label.add_css_class("dim-label")
        name_label.add_css_class("caption")
        name_label.set_ellipsize(Pango.EllipsizeMode.END)
        center_box.append(name_label)

        outer_box.append(center_box)

        # Progress bar (circular-style level bar)
        progress = Gtk.LevelBar()
        progress.set_mode(Gtk.LevelBarMode.CONTINUOUS)
        progress.set_min_value(0)
        progress.set_max_value(1.0)
        progress.set_size_request(36, -1)
        progress.set_valign(Gtk.Align.CENTER)
        outer_box.append(progress)

        # Action buttons box
        btn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=2)
        btn_box.set_valign(Gtk.Align.CENTER)

        # Copy
        copy_btn = Gtk.Button()
        copy_btn.set_icon_name("edit-copy-symbolic")
        copy_btn.add_css_class("flat")
        copy_btn.set_tooltip_text(_("Copy Code"))
        copy_btn.connect(
            "clicked", lambda _, pid=pwd_data["id"]: self._copy_totp(pid)
        )
        btn_box.append(copy_btn)

        # Edit
        edit_btn = Gtk.Button()
        edit_btn.set_icon_name("document-edit-symbolic")
        edit_btn.add_css_class("flat")
        edit_btn.set_tooltip_text(_("Edit"))
        edit_btn.connect(
            "clicked", lambda _, pid=pwd_data["id"]: self._show_edit_dialog(pid)
        )
        btn_box.append(edit_btn)

        # Delete
        delete_btn = Gtk.Button()
        delete_btn.set_icon_name("user-trash-symbolic")
        delete_btn.add_css_class("flat")
        delete_btn.set_tooltip_text(_("Delete"))
        delete_btn.connect(
            "clicked", lambda _, pid=pwd_data["id"]: self._confirm_delete(pid)
        )
        btn_box.append(delete_btn)

        outer_box.append(btn_box)

        row.set_child(outer_box)
        self._totp_rows.append((code_label, progress, pwd_data, row))

        return row

    def _update_totp_displays(self) -> bool:
        """Update all TOTP codes and progress bars"""
        for label, progress, pwd_data, row in self._totp_rows:
            if not label.get_parent():
                continue
            secret_enc = pwd_data.get("totp_secret_encrypted")
            if not secret_enc:
                continue
            try:
                secret = self.database._decrypt(secret_enc)
                algo = pwd_data.get("totp_algorithm", "SHA1")
                digits = pwd_data.get("totp_digits", 6)
                period = pwd_data.get("totp_period", 30)
                code = generate_totp(secret, algorithm=algo, digits=digits, period=period)
                remaining = remaining_seconds(period)
                label.set_text(code)
                progress.set_value(remaining / period)
            except Exception:
                label.set_text("------")
                progress.set_value(0)

        self.session.on_activity()
        return True  # keep timer running

    def _copy_totp(self, password_id: int) -> None:
        """Copy TOTP code to clipboard"""
        entry = self.database.get_password(password_id)
        if entry and entry.get("totp_secret"):
            algo = entry.get("totp_algorithm", "SHA1")
            digits = entry.get("totp_digits", 6)
            period = entry.get("totp_period", 30)
            code = generate_totp(entry["totp_secret"], algorithm=algo, digits=digits, period=period)
            self.clipboard.copy_text(code)
            root = self.get_root()
            if root and hasattr(root, "show_toast"):
                root.show_toast(_("TOTP code copied"))
        self.session.on_activity()

    def _show_edit_dialog(self, password_id: int) -> None:
        """Show edit dialog for a TOTP entry"""
        entry = self.database.get_password(password_id)
        if not entry:
            return

        dialog = Adw.AlertDialog()
        dialog.set_heading(_("Edit 2FA Entry"))
        dialog.add_response("cancel", _("Cancel"))
        dialog.add_response("save", _("Save"))
        dialog.set_response_appearance("save", Adw.ResponseAppearance.SUGGESTED)
        dialog.set_default_response("save")
        dialog.set_close_response("cancel")

        form = Adw.PreferencesGroup()

        title_entry = Adw.EntryRow()
        title_entry.set_title(_("Title"))
        title_entry.set_text(entry.get("title", ""))
        form.add(title_entry)

        username_entry = Adw.EntryRow()
        username_entry.set_title(_("Username"))
        username_entry.set_text(entry.get("username", "") or "")
        form.add(username_entry)

        url_entry = Adw.EntryRow()
        url_entry.set_title(_("URL"))
        url_entry.set_text(entry.get("url", "") or "")
        form.add(url_entry)

        category_entry = Adw.EntryRow()
        category_entry.set_title(_("Category"))
        category_entry.set_text(entry.get("category", "") or "")
        form.add(category_entry)

        # TOTP settings
        totp_group = Adw.PreferencesGroup()
        totp_group.set_title(_("TOTP Settings"))

        totp_entry = Adw.PasswordEntryRow()
        totp_entry.set_title(_("TOTP Secret (Base32)"))
        if entry.get("totp_secret"):
            totp_entry.set_text(entry["totp_secret"])
        totp_group.add(totp_entry)

        totp_algo_row = Adw.ComboRow()
        totp_algo_row.set_title(_("Algorithm"))
        totp_algo_row.set_model(Gtk.StringList.new(["SHA1", "SHA256", "SHA512"]))
        algos = ["SHA1", "SHA256", "SHA512"]
        try:
            totp_algo_row.set_selected(algos.index(entry.get("totp_algorithm", "SHA1")))
        except ValueError:
            pass
        totp_group.add(totp_algo_row)

        totp_digits_row = Adw.SpinRow()
        totp_digits_row.set_title(_("Digits"))
        totp_digits_row.set_adjustment(
            Gtk.Adjustment(
                value=entry.get("totp_digits", 6),
                lower=6, upper=8, step_increment=2,
            )
        )
        totp_group.add(totp_digits_row)

        totp_period_row = Adw.SpinRow()
        totp_period_row.set_title(_("Period (seconds)"))
        totp_period_row.set_adjustment(
            Gtk.Adjustment(
                value=entry.get("totp_period", 30),
                lower=15, upper=60, step_increment=15,
            )
        )
        totp_group.add(totp_period_row)

        content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        content_box.set_size_request(500, -1)
        content_box.append(form)
        content_box.append(totp_group)
        dialog.set_extra_child(content_box)

        def on_response(dlg, response):
            if response == "save":
                title = title_entry.get_text().strip()
                if not title:
                    title_entry.add_css_class("error")
                    return
                totp_algos = ["SHA1", "SHA256", "SHA512"]
                try:
                    self.database.update_password(
                        password_id,
                        title=title,
                        username=username_entry.get_text().strip() or None,
                        password=entry.get("password", ""),
                        url=url_entry.get_text().strip() or None,
                        totp_secret=totp_entry.get_text().strip() or None,
                        totp_algorithm=totp_algos[totp_algo_row.get_selected()],
                        totp_digits=int(totp_digits_row.get_value()),
                        totp_period=int(totp_period_row.get_value()),
                        category=category_entry.get_text().strip() or None,
                    )
                    root = self.get_root()
                    if root and hasattr(root, "show_toast"):
                        root.show_toast(_("Entry updated"))
                    self._load_totp_entries()
                    self.session.on_activity()
                except Exception as e:
                    error_dlg = Adw.AlertDialog()
                    error_dlg.set_heading(_("Error"))
                    error_dlg.set_body(str(e))
                    error_dlg.add_response("ok", _("OK"))
                    error_dlg.present(self.get_root())

        dialog.connect("response", on_response)
        dialog.present(self.get_root())

    def _confirm_delete(self, password_id: int) -> None:
        """Show delete confirmation for a TOTP entry"""
        entry = self.database.get_password(password_id)
        if not entry:
            return

        dialog = Adw.AlertDialog()
        dialog.set_heading(_("Delete 2FA Entry?"))
        dialog.set_body(
            _("Are you sure you want to delete '{title}'? This action cannot be undone.").format(
                title=entry["title"]
            )
        )
        dialog.add_response("cancel", _("Cancel"))
        dialog.add_response("delete", _("Delete"))
        dialog.set_response_appearance("delete", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_default_response("cancel")
        dialog.set_close_response("cancel")

        def on_response(dlg, response):
            if response == "delete":
                if self.database.delete_password(password_id):
                    root = self.get_root()
                    if root and hasattr(root, "show_toast"):
                        root.show_toast(_("Entry deleted"))
                    self._load_totp_entries()
                    self.session.on_activity()

        dialog.connect("response", on_response)
        dialog.present(self.get_root())

    def _on_search_changed(self, entry: Gtk.SearchEntry) -> None:
        """Handle search text change"""
        text = entry.get_text().strip()
        self._load_totp_entries(search=text if text else None)

    def _on_category_changed(self, dropdown, _pspec) -> None:
        """Handle category filter change"""
        if self._updating_categories:
            return
        self._load_totp_entries(
            search=self.search_entry.get_text().strip() or None
        )
        self.session.on_activity()

    def _get_selected_category(self) -> str | None:
        """Get selected category from dropdown (None means 'All')"""
        idx = self.category_dropdown.get_selected()
        if idx == 0:
            return None
        item = self._category_model.get_string(idx)
        return item if item else None

    def _update_category_filter(self) -> None:
        """Refresh the category dropdown with current categories from DB"""
        self._updating_categories = True
        categories = self.database.get_categories()
        items = [_("All")] + categories
        self._category_model = Gtk.StringList.new(items)
        self.category_dropdown.set_model(self._category_model)
        self.category_bar.set_visible(len(categories) > 0)
        self._updating_categories = False

    def _stop_timer(self) -> None:
        """Stop TOTP refresh timer"""
        if self._totp_timer_id is not None:
            GLib.source_remove(self._totp_timer_id)
            self._totp_timer_id = None

    def on_lock(self) -> None:
        """Called when vault is locked"""
        self._stop_timer()
        self._totp_rows.clear()
        self.main_stack.set_visible_child_name("locked")
