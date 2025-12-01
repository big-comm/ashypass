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
from core.config import load_settings, save_settings


class GeneratorView(Adw.NavigationPage):
    """Password generator view"""
    
    def __init__(self):
        super().__init__(title=_("Generator"))
        self.generator = PasswordGenerator()
        self.clipboard = ClipboardManager()
        self.current_password = ""
        self.settings = load_settings()
        self._build_ui()
        self._load_preferences()
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

        # Password row - same style as Strength row
        password_row = Adw.ActionRow()
        password_row.set_title(_("Password"))

        # Password label - selectable, monospace, left-aligned in a scrolled window
        password_scroll = Gtk.ScrolledWindow()
        password_scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.NEVER)
        password_scroll.set_max_content_width(400)
        password_scroll.set_propagate_natural_width(True)

        self.password_label = Gtk.Label()
        self.password_label.set_selectable(True)
        self.password_label.add_css_class("monospace")
        self.password_label.add_css_class("title-3")
        self.password_label.set_xalign(0.0)  # Left align

        password_scroll.set_child(self.password_label)
        password_row.add_suffix(password_scroll)

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
        self.length_spin.connect("changed", lambda _: self._on_option_changed())
        group.add(self.length_spin)

        self.uppercase_switch = Adw.SwitchRow(title=_("Uppercase Letters (A-Z)"), active=True)
        self.uppercase_switch.connect("notify::active", lambda *_: self._on_option_changed())
        group.add(self.uppercase_switch)

        self.lowercase_switch = Adw.SwitchRow(title=_("Lowercase Letters (a-z)"), active=True)
        self.lowercase_switch.connect("notify::active", lambda *_: self._on_option_changed())
        group.add(self.lowercase_switch)

        self.digits_switch = Adw.SwitchRow(title=_("Digits (0-9)"), active=True)
        self.digits_switch.connect("notify::active", lambda *_: self._on_option_changed())
        group.add(self.digits_switch)

        self.symbols_switch = Adw.SwitchRow(title=_("Symbols (!@#$...)"), active=True)
        self.symbols_switch.connect("notify::active", lambda *_: self._on_option_changed())
        group.add(self.symbols_switch)

        self.ambiguous_switch = Adw.SwitchRow(title=_("Exclude Ambiguous Characters"), active=True)
        self.ambiguous_switch.set_subtitle(_("Avoid characters like 0, O, 1, l, I"))
        self.ambiguous_switch.connect("notify::active", lambda *_: self._on_option_changed())
        group.add(self.ambiguous_switch)
        
        return group
    
    def _create_passphrase_options(self) -> Adw.PreferencesGroup:
        """Create passphrase generation options"""
        group = Adw.PreferencesGroup()
        group.set_title(_("Passphrase Options"))

        self.words_spin = Adw.SpinRow(title=_("Number of Words"))
        self.words_spin.set_adjustment(Gtk.Adjustment(value=DEFAULT_PASSPHRASE_WORDS,
            lower=MIN_PASSPHRASE_WORDS, upper=MAX_PASSPHRASE_WORDS, step_increment=1))
        self.words_spin.connect("changed", lambda _: self._on_option_changed())
        group.add(self.words_spin)

        self.separator_entry = Adw.EntryRow(title=_("Separator"), text="-")
        self.separator_entry.connect("changed", lambda _: self._on_option_changed())
        group.add(self.separator_entry)

        self.capitalize_switch = Adw.SwitchRow(title=_("Capitalize Words"), active=True)
        self.capitalize_switch.connect("notify::active", lambda *_: self._on_option_changed())
        group.add(self.capitalize_switch)

        self.add_number_switch = Adw.SwitchRow(title=_("Add Number at End"), active=True)
        self.add_number_switch.connect("notify::active", lambda *_: self._on_option_changed())
        group.add(self.add_number_switch)
        
        return group
    
    def _create_pin_options(self) -> Adw.PreferencesGroup:
        """Create PIN generation options"""
        group = Adw.PreferencesGroup()
        group.set_title(_("PIN Options"))

        self.pin_length_spin = Adw.SpinRow(title=_("Length"))
        self.pin_length_spin.set_adjustment(Gtk.Adjustment(value=DEFAULT_PIN_LENGTH,
            lower=MIN_PIN_LENGTH, upper=MAX_PIN_LENGTH, step_increment=1))
        self.pin_length_spin.connect("changed", lambda _: self._on_option_changed())
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

    def _load_preferences(self) -> None:
        """Load saved generator preferences"""
        gen_prefs = self.settings.get("generator", {})

        # Load password options
        if "length" in gen_prefs:
            self.length_spin.set_value(gen_prefs["length"])
        if "uppercase" in gen_prefs:
            self.uppercase_switch.set_active(gen_prefs["uppercase"])
        if "lowercase" in gen_prefs:
            self.lowercase_switch.set_active(gen_prefs["lowercase"])
        if "digits" in gen_prefs:
            self.digits_switch.set_active(gen_prefs["digits"])
        if "symbols" in gen_prefs:
            self.symbols_switch.set_active(gen_prefs["symbols"])
        if "exclude_ambiguous" in gen_prefs:
            self.ambiguous_switch.set_active(gen_prefs["exclude_ambiguous"])

        # Load passphrase options
        if "passphrase_words" in gen_prefs:
            self.words_spin.set_value(gen_prefs["passphrase_words"])
        if "passphrase_separator" in gen_prefs:
            self.separator_entry.set_text(gen_prefs["passphrase_separator"])
        if "passphrase_capitalize" in gen_prefs:
            self.capitalize_switch.set_active(gen_prefs["passphrase_capitalize"])
        if "passphrase_add_number" in gen_prefs:
            self.add_number_switch.set_active(gen_prefs["passphrase_add_number"])

        # Load PIN options
        if "pin_length" in gen_prefs:
            self.pin_length_spin.set_value(gen_prefs["pin_length"])

    def _save_preferences(self) -> None:
        """Save current generator preferences"""
        gen_prefs = {
            "length": int(self.length_spin.get_value()),
            "uppercase": self.uppercase_switch.get_active(),
            "lowercase": self.lowercase_switch.get_active(),
            "digits": self.digits_switch.get_active(),
            "symbols": self.symbols_switch.get_active(),
            "exclude_ambiguous": self.ambiguous_switch.get_active(),
            "passphrase_words": int(self.words_spin.get_value()),
            "passphrase_separator": self.separator_entry.get_text(),
            "passphrase_capitalize": self.capitalize_switch.get_active(),
            "passphrase_add_number": self.add_number_switch.get_active(),
            "pin_length": int(self.pin_length_spin.get_value()),
        }

        self.settings["generator"] = gen_prefs
        save_settings(self.settings)

    def _on_option_changed(self) -> None:
        """Handle option change - save preferences and regenerate"""
        self._save_preferences()
        self._generate_password()

    def _on_copy_clicked(self, button: Gtk.Button) -> None:
        """Handle copy button click"""
        if self.current_password:
            self.clipboard.copy_text(self.current_password)
            self.activate_action("app.show-toast", GLib.Variant.new_string(_("Password copied to clipboard")))
