//! Password generator view — task #8.
//!
//! Top: generated password display + strength bar + Copy/Regenerate buttons.
//! Middle: type selector (Password / Passphrase / PIN) toggling an options Stack.
//! Bottom: per-type options (length, character classes, words, separator, etc.).

use crate::tr;
use adw::prelude::*;
use ashypass_core::config::{
    DEFAULT_PASSPHRASE_WORDS, DEFAULT_PASSWORD_LENGTH, DEFAULT_PIN_LENGTH, MAX_PASSPHRASE_WORDS,
    MAX_PASSWORD_LENGTH, MAX_PIN_LENGTH, MIN_PASSPHRASE_WORDS, MIN_PASSWORD_LENGTH, MIN_PIN_LENGTH,
};
use ashypass_core::generator::{
    generate_passphrase, generate_password, generate_pin, PasswordConfig,
};
use ashypass_core::strength::legacy_score as check_password_strength;
use gtk::glib;
use std::cell::RefCell;
use std::rc::Rc;

pub struct GeneratorView {
    pub root: gtk::Box,
    #[expect(dead_code, reason = "keeps view model alive for signal handlers")]
    inner: Rc<Inner>,
}

struct Inner {
    toast: adw::ToastOverlay,
    current_password: RefCell<String>,

    password_label: gtk::Label,
    strength_label: gtk::Label,
    strength_bar: gtk::LevelBar,

    options_stack: gtk::Stack,

    // password options
    length_spin: adw::SpinRow,
    uppercase_switch: adw::SwitchRow,
    lowercase_switch: adw::SwitchRow,
    digits_switch: adw::SwitchRow,
    symbols_switch: adw::SwitchRow,
    ambiguous_switch: adw::SwitchRow,

    // passphrase options
    words_spin: adw::SpinRow,
    separator_entry: adw::EntryRow,
    capitalize_switch: adw::SwitchRow,
    add_number_switch: adw::SwitchRow,

    // pin options
    pin_length_spin: adw::SpinRow,
}

impl GeneratorView {
    pub fn new(toast: adw::ToastOverlay) -> Self {
        let root = gtk::Box::new(gtk::Orientation::Vertical, 0);
        root.set_vexpand(true);
        root.set_hexpand(true);

        let scrolled = gtk::ScrolledWindow::builder()
            .hscrollbar_policy(gtk::PolicyType::Never)
            .vscrollbar_policy(gtk::PolicyType::Automatic)
            .vexpand(true)
            .hexpand(true)
            .build();
        let content = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(24)
            .margin_top(12)
            .margin_bottom(12)
            .margin_start(12)
            .margin_end(12)
            .build();

        // ---- Generated password group ----
        let pwd_group = adw::PreferencesGroup::builder()
            .title(tr!("Generated Password"))
            .build();

        let password_row = adw::ActionRow::builder().title(tr!("Password")).build();
        let password_scroll = gtk::ScrolledWindow::builder()
            .hscrollbar_policy(gtk::PolicyType::Automatic)
            .vscrollbar_policy(gtk::PolicyType::Never)
            .max_content_width(400)
            .propagate_natural_width(true)
            .build();
        let password_label = gtk::Label::new(None);
        password_label.set_selectable(true);
        password_label.add_css_class("monospace");
        password_label.add_css_class("title-3");
        password_label.set_xalign(0.0);
        password_scroll.set_child(Some(&password_label));
        password_row.add_suffix(&password_scroll);
        pwd_group.add(&password_row);

        let strength_row = adw::ActionRow::builder().title(tr!("Strength")).build();
        let strength_label = gtk::Label::new(None);
        strength_label.add_css_class("title-4");
        strength_row.add_suffix(&strength_label);
        pwd_group.add(&strength_row);

        content.append(&pwd_group);

        let strength_bar = gtk::LevelBar::builder()
            .mode(gtk::LevelBarMode::Continuous)
            .min_value(0.0)
            .max_value(100.0)
            .margin_top(6)
            .margin_bottom(6)
            .margin_start(12)
            .margin_end(12)
            .build();
        content.append(&strength_bar);

        let btn_box = gtk::Box::builder()
            .orientation(gtk::Orientation::Horizontal)
            .spacing(12)
            .halign(gtk::Align::Center)
            .margin_top(6)
            .build();
        let copy_btn = gtk::Button::with_label(tr!("Copy to Clipboard"));
        copy_btn.add_css_class("pill");
        copy_btn.add_css_class("suggested-action");
        btn_box.append(&copy_btn);
        let regen_btn = gtk::Button::with_label(tr!("Generate New"));
        regen_btn.add_css_class("pill");
        btn_box.append(&regen_btn);
        content.append(&btn_box);

        // ---- Type selector ----
        let type_group = adw::PreferencesGroup::builder()
            .title(tr!("Generation Type"))
            .build();
        let type_box = gtk::Box::builder()
            .orientation(gtk::Orientation::Horizontal)
            .halign(gtk::Align::Center)
            .build();
        type_box.add_css_class("linked");

        let pwd_tg = gtk::ToggleButton::with_label(tr!("Password"));
        pwd_tg.set_active(true);
        type_box.append(&pwd_tg);
        let pass_tg = gtk::ToggleButton::with_label(tr!("Passphrase"));
        pass_tg.set_group(Some(&pwd_tg));
        type_box.append(&pass_tg);
        let pin_tg = gtk::ToggleButton::with_label(tr!("PIN"));
        pin_tg.set_group(Some(&pwd_tg));
        type_box.append(&pin_tg);
        type_group.add(&type_box);
        content.append(&type_group);

        // ---- Options stack ----
        let options_stack = gtk::Stack::builder()
            .transition_type(gtk::StackTransitionType::SlideLeftRight)
            .build();

        let (
            pwd_options,
            length_spin,
            uppercase_switch,
            lowercase_switch,
            digits_switch,
            symbols_switch,
            ambiguous_switch,
        ) = build_password_options();
        options_stack.add_named(&pwd_options, Some("password"));

        let (pass_options, words_spin, separator_entry, capitalize_switch, add_number_switch) =
            build_passphrase_options();
        options_stack.add_named(&pass_options, Some("passphrase"));

        let (pin_options, pin_length_spin) = build_pin_options();
        options_stack.add_named(&pin_options, Some("pin"));

        content.append(&options_stack);

        scrolled.set_child(Some(&content));
        root.append(&scrolled);

        let inner = Rc::new(Inner {
            toast,
            current_password: RefCell::new(String::new()),
            password_label,
            strength_label,
            strength_bar,
            options_stack: options_stack.clone(),
            length_spin,
            uppercase_switch,
            lowercase_switch,
            digits_switch,
            symbols_switch,
            ambiguous_switch,
            words_spin,
            separator_entry,
            capitalize_switch,
            add_number_switch,
            pin_length_spin,
        });

        // Wire up callbacks
        {
            let inner_cl = inner.clone();
            copy_btn.connect_clicked(move |_| inner_cl.copy_clicked());
        }
        {
            let inner_cl = inner.clone();
            regen_btn.connect_clicked(move |_| inner_cl.generate());
        }
        {
            let inner_cl = inner.clone();
            pwd_tg.connect_toggled(move |b| {
                if b.is_active() {
                    inner_cl.options_stack.set_visible_child_name("password");
                    inner_cl.generate();
                }
            });
        }
        {
            let inner_cl = inner.clone();
            pass_tg.connect_toggled(move |b| {
                if b.is_active() {
                    inner_cl.options_stack.set_visible_child_name("passphrase");
                    inner_cl.generate();
                }
            });
        }
        {
            let inner_cl = inner.clone();
            pin_tg.connect_toggled(move |b| {
                if b.is_active() {
                    inner_cl.options_stack.set_visible_child_name("pin");
                    inner_cl.generate();
                }
            });
        }

        wire_option_changes(&inner);

        inner.generate();

        Self { root, inner }
    }
}

fn wire_option_changes(inner: &Rc<Inner>) {
    let connect_spin = |s: &adw::SpinRow, inner: &Rc<Inner>| {
        let inner_cl = inner.clone();
        s.connect_changed(move |_| inner_cl.generate());
    };
    let connect_switch = |s: &adw::SwitchRow, inner: &Rc<Inner>| {
        let inner_cl = inner.clone();
        s.connect_active_notify(move |_| inner_cl.generate());
    };
    let connect_entry = |s: &adw::EntryRow, inner: &Rc<Inner>| {
        let inner_cl = inner.clone();
        s.connect_changed(move |_| inner_cl.generate());
    };

    connect_spin(&inner.length_spin, inner);
    connect_switch(&inner.uppercase_switch, inner);
    connect_switch(&inner.lowercase_switch, inner);
    connect_switch(&inner.digits_switch, inner);
    connect_switch(&inner.symbols_switch, inner);
    connect_switch(&inner.ambiguous_switch, inner);

    connect_spin(&inner.words_spin, inner);
    connect_entry(&inner.separator_entry, inner);
    connect_switch(&inner.capitalize_switch, inner);
    connect_switch(&inner.add_number_switch, inner);

    connect_spin(&inner.pin_length_spin, inner);
}

impl Inner {
    fn current_type(&self) -> String {
        self.options_stack
            .visible_child_name()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "password".to_string())
    }

    fn generate(&self) {
        let pwd = match self.current_type().as_str() {
            "password" => {
                let cfg = PasswordConfig {
                    length: self.length_spin.value() as usize,
                    use_uppercase: self.uppercase_switch.is_active(),
                    use_lowercase: self.lowercase_switch.is_active(),
                    use_digits: self.digits_switch.is_active(),
                    use_symbols: self.symbols_switch.is_active(),
                    exclude_ambiguous: self.ambiguous_switch.is_active(),
                    custom_symbols: String::new(),
                };
                match generate_password(&cfg) {
                    Ok(p) => p,
                    Err(e) => {
                        self.password_label
                            .set_text(&format!("{}: {e}", tr!("Error")));
                        return;
                    }
                }
            }
            "passphrase" => generate_passphrase(
                self.words_spin.value() as usize,
                self.separator_entry.text().as_str(),
                self.capitalize_switch.is_active(),
                self.add_number_switch.is_active(),
            ),
            "pin" => generate_pin(self.pin_length_spin.value() as usize),
            _ => return,
        };

        self.password_label.set_text(&pwd);
        self.update_strength(&pwd);
        *self.current_password.borrow_mut() = pwd;
    }

    fn update_strength(&self, pwd: &str) {
        let (score, level) = check_password_strength(pwd);
        self.strength_label
            .set_text(crate::ui::i18n::localized_strength_label(level));
        self.strength_bar.set_value(score as f64);

        self.strength_label.remove_css_class("success");
        self.strength_label.remove_css_class("warning");
        self.strength_label.remove_css_class("error");
        if score >= 80 {
            self.strength_label.add_css_class("success");
        } else if score >= 40 {
            self.strength_label.add_css_class("warning");
        } else {
            self.strength_label.add_css_class("error");
        }
    }

    fn copy_clicked(&self) {
        let pwd = self.current_password.borrow().clone();
        if pwd.is_empty() {
            return;
        }
        let seconds = ashypass_core::settings::Settings::load().clipboard_clear;
        crate::clipboard::copy(&pwd, seconds);
        let toast = adw::Toast::builder()
            .title(tr!("Password copied to clipboard"))
            .timeout(3)
            .build();
        self.toast.add_toast(toast);
    }
}

#[allow(clippy::type_complexity)]
fn build_password_options() -> (
    adw::PreferencesGroup,
    adw::SpinRow,
    adw::SwitchRow,
    adw::SwitchRow,
    adw::SwitchRow,
    adw::SwitchRow,
    adw::SwitchRow,
) {
    let group = adw::PreferencesGroup::builder()
        .title(tr!("Password Options"))
        .build();

    let length_adj = gtk::Adjustment::new(
        DEFAULT_PASSWORD_LENGTH as f64,
        MIN_PASSWORD_LENGTH as f64,
        MAX_PASSWORD_LENGTH as f64,
        1.0,
        1.0,
        0.0,
    );
    let length_spin = adw::SpinRow::builder()
        .title(tr!("Length"))
        .adjustment(&length_adj)
        .build();
    group.add(&length_spin);

    let uppercase_switch = adw::SwitchRow::builder()
        .title(tr!("Uppercase Letters (A-Z)"))
        .active(true)
        .build();
    group.add(&uppercase_switch);

    let lowercase_switch = adw::SwitchRow::builder()
        .title(tr!("Lowercase Letters (a-z)"))
        .active(true)
        .build();
    group.add(&lowercase_switch);

    let digits_switch = adw::SwitchRow::builder()
        .title(tr!("Digits (0-9)"))
        .active(true)
        .build();
    group.add(&digits_switch);

    let symbols_switch = adw::SwitchRow::builder()
        .title(tr!("Symbols (!@#$…)"))
        .active(true)
        .build();
    group.add(&symbols_switch);

    let ambiguous_switch = adw::SwitchRow::builder()
        .title(tr!("Exclude Ambiguous Characters"))
        .subtitle(tr!("Avoid characters like 0, O, 1, l, I"))
        .active(true)
        .build();
    group.add(&ambiguous_switch);

    (
        group,
        length_spin,
        uppercase_switch,
        lowercase_switch,
        digits_switch,
        symbols_switch,
        ambiguous_switch,
    )
}

fn build_passphrase_options() -> (
    adw::PreferencesGroup,
    adw::SpinRow,
    adw::EntryRow,
    adw::SwitchRow,
    adw::SwitchRow,
) {
    let group = adw::PreferencesGroup::builder()
        .title(tr!("Passphrase Options"))
        .build();

    let words_adj = gtk::Adjustment::new(
        DEFAULT_PASSPHRASE_WORDS as f64,
        MIN_PASSPHRASE_WORDS as f64,
        MAX_PASSPHRASE_WORDS as f64,
        1.0,
        1.0,
        0.0,
    );
    let words_spin = adw::SpinRow::builder()
        .title(tr!("Number of Words"))
        .adjustment(&words_adj)
        .build();
    group.add(&words_spin);

    let separator_entry = adw::EntryRow::builder()
        .title(tr!("Separator"))
        .text("-")
        .build();
    group.add(&separator_entry);

    let capitalize_switch = adw::SwitchRow::builder()
        .title(tr!("Capitalize Words"))
        .active(true)
        .build();
    group.add(&capitalize_switch);

    let add_number_switch = adw::SwitchRow::builder()
        .title(tr!("Add Number at End"))
        .active(true)
        .build();
    group.add(&add_number_switch);

    (
        group,
        words_spin,
        separator_entry,
        capitalize_switch,
        add_number_switch,
    )
}

fn build_pin_options() -> (adw::PreferencesGroup, adw::SpinRow) {
    let group = adw::PreferencesGroup::builder()
        .title(tr!("PIN Options"))
        .build();

    let pin_adj = gtk::Adjustment::new(
        DEFAULT_PIN_LENGTH as f64,
        MIN_PIN_LENGTH as f64,
        MAX_PIN_LENGTH as f64,
        1.0,
        1.0,
        0.0,
    );
    let pin_length_spin = adw::SpinRow::builder()
        .title(tr!("Length"))
        .adjustment(&pin_adj)
        .build();
    group.add(&pin_length_spin);

    (group, pin_length_spin)
}

#[allow(dead_code)]
fn _unused(_: glib::ControlFlow) {}
