#!/usr/bin/env python3
"""Ashy Pass - Generator View"""

import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')

from gi.repository import Gtk, Adw, GLib
from core.generator import PasswordGenerator, PasswordConfig
from utils.clipboard import ClipboardManager
from utils.i18n import _
from core.config import *


class GeneratorView(Adw.NavigationPage):
    """Password generator view"""
    
    def __init__(self):
        super().__init__(title=_("Generator"))
        self.generator = PasswordGenerator()
        self.clipboard = ClipboardManager()
        self.current_password = ""
        self._build_ui()
        self._generate_password()
    
    def _build_ui(self) -> None:
        """Build the user interface"""
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)

        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        content.set_margin_top(12)
        content.set_margin_bottom(12)
        content.set_margin_start(12)
        content.set_margin_end(12)
        content.set_spacing(24)
        
        # Password display
        group = Adw.PreferencesGroup()
        group.set_title(_("Generated Password"))

        password_row = Adw.ActionRow()
        password_row.set_title(_("Password"))

        # Use selectable label for read-only password display
        self.password_label = Gtk.Label()
        self.password_label.set_selectable(True)
        self.password_label.add_css_class("monospace")
        self.password_label.add_css_class("title-3")
        self.password_label.set_xalign(1.0)  # Align right
        password_row.add_suffix(self.password_label)

        group.add(password_row)
        
        # Strength indicator
        strength_row = Adw.ActionRow()
        strength_row.set_title(_("Strength"))
        self.strength_label = Gtk.Label()
        self.strength_label.add_css_class("title-4")
        strength_row.add_suffix(self.strength_label)
        group.add(strength_row)
        
        self.strength_bar = Gtk.LevelBar()
        self.strength_bar.set_mode(Gtk.LevelBarMode.CONTINUOUS)
        self.strength_bar.set_min_value(0)
        self.strength_bar.set_max_value(100)
        self.strength_bar.set_margin_top(6)
        self.strength_bar.set_margin_bottom(6)
        self.strength_bar.set_margin_start(12)
        self.strength_bar.set_margin_end(12)
        group.add(self.strength_bar)
        
        # Buttons
        btn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        btn_box.set_spacing(12)
        btn_box.set_halign(Gtk.Align.CENTER)
        btn_box.set_margin_top(12)
        
        copy_btn = Gtk.Button(label=_("Copy to Clipboard"))
        copy_btn.add_css_class("pill")
        copy_btn.add_css_class("suggested-action")
        copy_btn.connect("clicked", self._on_copy_clicked)
        btn_box.append(copy_btn)

        regen_btn = Gtk.Button(label=_("Generate New"))
        regen_btn.add_css_class("pill")
        regen_btn.connect("clicked", lambda _: self._generate_password())
        btn_box.append(regen_btn)
        
        group.add(btn_box)
        content.append(group)
        
        # Type selector
        type_group = Adw.PreferencesGroup()
        type_group.set_title(_("Generation Type"))

        type_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        type_box.set_halign(Gtk.Align.CENTER)
        type_box.add_css_class("linked")

        password_btn = Gtk.ToggleButton(label=_("Password"))
        password_btn.set_active(True)
        password_btn.connect("toggled", self._on_type_changed, "password")
        type_box.append(password_btn)

        passphrase_btn = Gtk.ToggleButton(label=_("Passphrase"))
        passphrase_btn.set_group(password_btn)
        passphrase_btn.connect("toggled", self._on_type_changed, "passphrase")
        type_box.append(passphrase_btn)

        pin_btn = Gtk.ToggleButton(label=_("PIN"))
        pin_btn.set_group(password_btn)
        pin_btn.connect("toggled", self._on_type_changed, "pin")
        type_box.append(pin_btn)
        
        type_group.add(type_box)
        content.append(type_group)
        
        # Options stack
        self.options_stack = Gtk.Stack()
        self.options_stack.set_transition_type(Gtk.StackTransitionType.SLIDE_LEFT_RIGHT)
        self.options_stack.add_titled(self._create_password_options(), "password", "Password")
        self.options_stack.add_titled(self._create_passphrase_options(), "passphrase", "Passphrase")
        self.options_stack.add_titled(self._create_pin_options(), "pin", "PIN")
        content.append(self.options_stack)

        scrolled.set_child(content)
        self.set_child(scrolled)
    
    def _create_password_options(self) -> Adw.PreferencesGroup:
        """Create password generation options"""
        group = Adw.PreferencesGroup()
        group.set_title(_("Password Options"))

        self.length_spin = Adw.SpinRow()
        self.length_spin.set_title(_("Length"))
        self.length_spin.set_adjustment(Gtk.Adjustment(value=DEFAULT_PASSWORD_LENGTH,
            lower=MIN_PASSWORD_LENGTH, upper=MAX_PASSWORD_LENGTH, step_increment=1))
        self.length_spin.connect("changed", lambda _: self._generate_password())
        group.add(self.length_spin)

        self.uppercase_switch = Adw.SwitchRow(title=_("Uppercase Letters (A-Z)"), active=True)
        self.uppercase_switch.connect("notify::active", lambda *_: self._generate_password())
        group.add(self.uppercase_switch)

        self.lowercase_switch = Adw.SwitchRow(title=_("Lowercase Letters (a-z)"), active=True)
        self.lowercase_switch.connect("notify::active", lambda *_: self._generate_password())
        group.add(self.lowercase_switch)

        self.digits_switch = Adw.SwitchRow(title=_("Digits (0-9)"), active=True)
        self.digits_switch.connect("notify::active", lambda *_: self._generate_password())
        group.add(self.digits_switch)

        self.symbols_switch = Adw.SwitchRow(title=_("Symbols (!@#$...)"), active=True)
        self.symbols_switch.connect("notify::active", lambda *_: self._generate_password())
        group.add(self.symbols_switch)

        self.ambiguous_switch = Adw.SwitchRow(title=_("Exclude Ambiguous Characters"), active=True)
        self.ambiguous_switch.set_subtitle(_("Avoid characters like 0, O, 1, l, I"))
        self.ambiguous_switch.connect("notify::active", lambda *_: self._generate_password())
        group.add(self.ambiguous_switch)
        
        return group
    
    def _create_passphrase_options(self) -> Adw.PreferencesGroup:
        """Create passphrase generation options"""
        group = Adw.PreferencesGroup()
        group.set_title(_("Passphrase Options"))

        self.words_spin = Adw.SpinRow(title=_("Number of Words"))
        self.words_spin.set_adjustment(Gtk.Adjustment(value=DEFAULT_PASSPHRASE_WORDS,
            lower=MIN_PASSPHRASE_WORDS, upper=MAX_PASSPHRASE_WORDS, step_increment=1))
        self.words_spin.connect("changed", lambda _: self._generate_password())
        group.add(self.words_spin)

        self.separator_entry = Adw.EntryRow(title=_("Separator"), text="-")
        self.separator_entry.connect("changed", lambda _: self._generate_password())
        group.add(self.separator_entry)

        self.capitalize_switch = Adw.SwitchRow(title=_("Capitalize Words"), active=True)
        self.capitalize_switch.connect("notify::active", lambda *_: self._generate_password())
        group.add(self.capitalize_switch)

        self.add_number_switch = Adw.SwitchRow(title=_("Add Number at End"), active=True)
        self.add_number_switch.connect("notify::active", lambda *_: self._generate_password())
        group.add(self.add_number_switch)
        
        return group
    
    def _create_pin_options(self) -> Adw.PreferencesGroup:
        """Create PIN generation options"""
        group = Adw.PreferencesGroup()
        group.set_title(_("PIN Options"))

        self.pin_length_spin = Adw.SpinRow(title=_("Length"))
        self.pin_length_spin.set_adjustment(Gtk.Adjustment(value=DEFAULT_PIN_LENGTH,
            lower=MIN_PIN_LENGTH, upper=MAX_PIN_LENGTH, step_increment=1))
        self.pin_length_spin.connect("changed", lambda _: self._generate_password())
        group.add(self.pin_length_spin)
        
        return group
    
    def _on_type_changed(self, button: Gtk.ToggleButton, type_name: str) -> None:
        """Handle generation type change"""
        if button.get_active():
            self.options_stack.set_visible_child_name(type_name)
            self._generate_password()
    
    def _generate_password(self) -> None:
        """Generate password based on current settings"""
        current_type = self.options_stack.get_visible_child_name()
        
        try:
            if current_type == "password":
                config = PasswordConfig(
                    length=int(self.length_spin.get_value()),
                    use_uppercase=self.uppercase_switch.get_active(),
                    use_lowercase=self.lowercase_switch.get_active(),
                    use_digits=self.digits_switch.get_active(),
                    use_symbols=self.symbols_switch.get_active(),
                    exclude_ambiguous=self.ambiguous_switch.get_active(),
                )
                self.current_password = self.generator.generate_password(config)
            elif current_type == "passphrase":
                self.current_password = self.generator.generate_passphrase(
                    num_words=int(self.words_spin.get_value()),
                    separator=self.separator_entry.get_text(),
                    capitalize=self.capitalize_switch.get_active(),
                    add_number=self.add_number_switch.get_active(),
                )
            elif current_type == "pin":
                self.current_password = self.generator.generate_pin(int(self.pin_length_spin.get_value()))
            
            self.password_label.set_text(self.current_password)
            self._update_strength_indicator()
        except ValueError as e:
            print(f"Error: {e}")
    
    def _update_strength_indicator(self) -> None:
        """Update password strength indicator"""
        score, level = self.generator.check_password_strength(self.current_password)
        self.strength_label.set_text(_(level))
        self.strength_bar.set_value(score)
        
        # Update color
        self.strength_label.remove_css_class("success")
        self.strength_label.remove_css_class("warning")
        self.strength_label.remove_css_class("error")
        
        if score >= 80:
            self.strength_label.add_css_class("success")
        elif score >= 40:
            self.strength_label.add_css_class("warning")
        else:
            self.strength_label.add_css_class("error")
    
    def _on_copy_clicked(self, button: Gtk.Button) -> None:
        """Handle copy button click"""
        if self.current_password:
            self.clipboard.copy_text(self.current_password)
            self.activate_action("app.show-toast", GLib.Variant.new_string(_("Password copied to clipboard")))
