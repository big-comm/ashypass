//! "Create password": a good password ready at once, adjustments tucked away.
//!
//! The same `GeneratorPanel` serves two places:
//! - the standalone page, where the main actions are *Copy password* and
//!   *Save to vault…* (which opens the entry form with the value filled in);
//! - the entry form, where the main action is *Use this password* and the
//!   value goes straight into the field, never through the clipboard.
//!
//! The panel never claims that a password is "secure": it shows the real
//! character count and a labelled *estimate*, and reminds the user that
//! creating a password here does not change it on any site.

use crate::state::SharedState;
use crate::tr;
use crate::ui::widgets::{copy_secret, page_heading, Chrome};
use adw::prelude::*;
use ashypass_core::config::{
    DEFAULT_PASSPHRASE_WORDS, DEFAULT_PIN_LENGTH, MAX_PASSPHRASE_WORDS, MAX_PASSWORD_LENGTH,
    MAX_PIN_LENGTH, MIN_PASSPHRASE_WORDS, MIN_PASSWORD_LENGTH, MIN_PIN_LENGTH,
};
use ashypass_core::generator::{
    generate_passphrase, generate_password, generate_pin, PasswordConfig,
};
use gtk::{gio, glib};
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use zeroize::Zeroizing;

/// Starting length for random passwords in the UI. The core default stays
/// at 16 for its other callers (CLI, browser host); 20 random characters
/// remain accepted almost everywhere and need no adjusting.
pub const UI_DEFAULT_PASSWORD_LENGTH: f64 = 20.0;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GeneratorKind {
    Random,
    Words,
    Pin,
}

impl GeneratorKind {
    fn id(self) -> &'static str {
        match self {
            Self::Random => "random",
            Self::Words => "words",
            Self::Pin => "pin",
        }
    }

    fn from_id(id: &str) -> Self {
        match id {
            "words" => Self::Words,
            "pin" => Self::Pin,
            _ => Self::Random,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Random => tr!("Random password"),
            Self::Words => tr!("Random words"),
            Self::Pin => tr!("Numeric PIN"),
        }
    }

    fn hint(self) -> &'static str {
        match self {
            Self::Random => tr!("Recommended for accounts you keep in the vault."),
            Self::Words => tr!("Easier to type and remember."),
            Self::Pin => tr!("Use when the service asks for a numeric code."),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PanelMode {
    Standalone,
    Embedded,
}

type ValueCallback = Box<dyn Fn(String)>;

pub struct GeneratorPanel {
    pub root: gtk::Box,
    inner: Rc<PanelInner>,
}

struct PanelInner {
    state: SharedState,
    toast: adw::ToastOverlay,
    mode: PanelMode,
    kind: Cell<GeneratorKind>,
    current: RefCell<Zeroizing<String>>,

    kind_button: gtk::MenuButton,
    kind_hint: gtk::Label,
    password_label: gtk::Label,
    summary_label: gtk::Label,
    expander: adw::ExpanderRow,

    length_row: adw::SpinRow,
    uppercase_row: adw::SwitchRow,
    lowercase_row: adw::SwitchRow,
    digits_row: adw::SwitchRow,
    symbols_row: adw::SwitchRow,
    ambiguous_row: adw::SwitchRow,

    words_row: adw::SpinRow,
    separator_row: adw::EntryRow,
    capitalize_row: adw::SwitchRow,
    add_number_row: adw::SwitchRow,

    pin_length_row: adw::SpinRow,

    on_primary: RefCell<Option<ValueCallback>>,
}

impl GeneratorPanel {
    pub fn new(state: SharedState, toast: adw::ToastOverlay, mode: PanelMode) -> Self {
        let root = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(16)
            .build();

        // ---- Type selector: the two everyday choices first, PIN under
        // "Other formats" with its own explanation.
        let kind_menu = gio::Menu::new();
        let main_section = gio::Menu::new();
        for kind in [GeneratorKind::Random, GeneratorKind::Words] {
            let item = gio::MenuItem::new(Some(kind.label()), None);
            item.set_action_and_target_value(Some("gen.kind"), Some(&kind.id().to_variant()));
            main_section.append_item(&item);
        }
        kind_menu.append_section(None, &main_section);
        let other_section = gio::Menu::new();
        let pin_item = gio::MenuItem::new(Some(GeneratorKind::Pin.label()), None);
        pin_item.set_action_and_target_value(
            Some("gen.kind"),
            Some(&GeneratorKind::Pin.id().to_variant()),
        );
        other_section.append_item(&pin_item);
        kind_menu.append_section(Some(tr!("Other formats")), &other_section);

        let kind_button = gtk::MenuButton::builder()
            .label(GeneratorKind::Random.label())
            .menu_model(&kind_menu)
            .halign(gtk::Align::Start)
            .tooltip_text(tr!("Type of password"))
            .build();
        let kind_hint = gtk::Label::builder()
            .label(GeneratorKind::Random.hint())
            .xalign(0.0)
            .wrap(true)
            .build();
        kind_hint.add_css_class("dim-label");
        kind_hint.add_css_class("caption");
        let kind_box = gtk::Box::builder()
            .orientation(gtk::Orientation::Horizontal)
            .spacing(12)
            .build();
        kind_box.append(&kind_button);
        kind_box.append(&kind_hint);
        root.append(&kind_box);

        // ---- Result card: the value, its real length and an estimate.
        let card = gtk::Box::builder()
            .orientation(gtk::Orientation::Horizontal)
            .spacing(8)
            .build();
        card.add_css_class("card");
        card.add_css_class("ashy-result-card");
        let value_box = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(6)
            .hexpand(true)
            .build();
        let password_label = gtk::Label::builder()
            .xalign(0.0)
            .selectable(true)
            .wrap(true)
            .wrap_mode(gtk::pango::WrapMode::Char)
            .build();
        password_label.add_css_class("ashy-secret-large");
        password_label.add_css_class("monospace");
        password_label
            .update_property(&[gtk::accessible::Property::Label(tr!("Generated password"))]);
        value_box.append(&password_label);
        let summary_label = gtk::Label::builder().xalign(0.0).wrap(true).build();
        summary_label.add_css_class("dim-label");
        summary_label.add_css_class("caption");
        value_box.append(&summary_label);
        card.append(&value_box);

        let copy_icon = gtk::Button::builder()
            .icon_name("edit-copy-symbolic")
            .tooltip_text(tr!("Copy password"))
            .valign(gtk::Align::Center)
            .build();
        copy_icon.add_css_class("flat");
        copy_icon.update_property(&[gtk::accessible::Property::Label(tr!("Copy password"))]);
        let regenerate = gtk::Button::builder()
            .icon_name("view-refresh-symbolic")
            .tooltip_text(tr!("Generate another"))
            .valign(gtk::Align::Center)
            .build();
        regenerate.add_css_class("flat");
        regenerate.update_property(&[gtk::accessible::Property::Label(tr!("Generate another"))]);
        card.append(&copy_icon);
        card.append(&regenerate);
        root.append(&card);

        // ---- Actions: one primary per context.
        let actions = gtk::Box::builder()
            .orientation(gtk::Orientation::Horizontal)
            .spacing(12)
            .homogeneous(true)
            .build();
        let (primary, secondary) = match mode {
            PanelMode::Standalone => (
                gtk::Button::with_label(tr!("Copy password")),
                Some(gtk::Button::with_label(tr!("Save to vault…"))),
            ),
            PanelMode::Embedded => (gtk::Button::with_label(tr!("Use this password")), None),
        };
        primary.add_css_class("pill");
        primary.add_css_class("suggested-action");
        actions.append(&primary);
        if let Some(secondary) = secondary.as_ref() {
            secondary.add_css_class("pill");
            actions.append(secondary);
        }
        root.append(&actions);

        // ---- Adjustments, collapsed by default.
        let options_group = adw::PreferencesGroup::new();
        let expander = adw::ExpanderRow::builder()
            .title(tr!("Adjust length and characters"))
            .subtitle(tr!("Only needed when a site has specific rules"))
            .build();
        options_group.add(&expander);

        let length_row = adw::SpinRow::builder()
            .title(tr!("Length"))
            .adjustment(&gtk::Adjustment::new(
                UI_DEFAULT_PASSWORD_LENGTH,
                MIN_PASSWORD_LENGTH as f64,
                MAX_PASSWORD_LENGTH as f64,
                1.0,
                4.0,
                0.0,
            ))
            .build();
        let uppercase_row = switch_row(tr!("Uppercase letters (A–Z)"), true);
        let lowercase_row = switch_row(tr!("Lowercase letters (a–z)"), true);
        let digits_row = switch_row(tr!("Numbers (0–9)"), true);
        let symbols_row = switch_row(tr!("Symbols (!@#$…)"), true);
        let ambiguous_row = switch_row(tr!("Avoid look-alike characters (l, 1, O, 0)"), true);

        let words_row = adw::SpinRow::builder()
            .title(tr!("Number of words"))
            .adjustment(&gtk::Adjustment::new(
                DEFAULT_PASSPHRASE_WORDS as f64,
                MIN_PASSPHRASE_WORDS as f64,
                MAX_PASSPHRASE_WORDS as f64,
                1.0,
                1.0,
                0.0,
            ))
            .build();
        let separator_row = adw::EntryRow::builder()
            .title(tr!("Separator"))
            .text("-")
            .build();
        let capitalize_row = switch_row(tr!("Capitalize words"), true);
        let add_number_row = switch_row(tr!("Add a number"), true);

        let pin_length_row = adw::SpinRow::builder()
            .title(tr!("Number of digits"))
            .adjustment(&gtk::Adjustment::new(
                DEFAULT_PIN_LENGTH as f64,
                MIN_PIN_LENGTH as f64,
                MAX_PIN_LENGTH as f64,
                1.0,
                1.0,
                0.0,
            ))
            .build();

        // Rows for every kind live in the expander; only the current kind's
        // rows are visible.
        for row in [
            length_row.upcast_ref::<gtk::Widget>(),
            uppercase_row.upcast_ref(),
            lowercase_row.upcast_ref(),
            digits_row.upcast_ref(),
            symbols_row.upcast_ref(),
            ambiguous_row.upcast_ref(),
            words_row.upcast_ref(),
            separator_row.upcast_ref(),
            capitalize_row.upcast_ref(),
            add_number_row.upcast_ref(),
            pin_length_row.upcast_ref(),
        ] {
            expander.add_row(row);
        }
        root.append(&options_group);

        let note = gtk::Box::builder()
            .orientation(gtk::Orientation::Horizontal)
            .spacing(8)
            .build();
        note.add_css_class("ashy-note");
        let note_icon = gtk::Image::from_icon_name("dialog-information-symbolic");
        note_icon.set_accessible_role(gtk::AccessibleRole::Presentation);
        note.append(&note_icon);
        let note_label = gtk::Label::builder()
            .label(match mode {
                PanelMode::Standalone => {
                    tr!("Creating a password here does not change your password on any site.")
                }
                PanelMode::Embedded => tr!(
                    "The password goes into the form. Saving the form does not change it on the site."
                ),
            })
            .wrap(true)
            .xalign(0.0)
            .build();
        note_label.add_css_class("caption");
        note.append(&note_label);
        root.append(&note);

        let inner = Rc::new(PanelInner {
            state,
            toast,
            mode,
            kind: Cell::new(GeneratorKind::Random),
            current: RefCell::new(Zeroizing::new(String::new())),
            kind_button,
            kind_hint,
            password_label,
            summary_label,
            expander,
            length_row,
            uppercase_row,
            lowercase_row,
            digits_row,
            symbols_row,
            ambiguous_row,
            words_row,
            separator_row,
            capitalize_row,
            add_number_row,
            pin_length_row,
            on_primary: RefCell::new(None),
        });

        // Kind action, scoped to this panel.
        let group = gio::SimpleActionGroup::new();
        let kind_action = gio::SimpleAction::new_stateful(
            "kind",
            Some(glib::VariantTy::STRING),
            &GeneratorKind::Random.id().to_variant(),
        );
        {
            let weak = Rc::downgrade(&inner);
            kind_action.connect_activate(move |action, target| {
                let Some(id) = target.and_then(|t| t.str()) else {
                    return;
                };
                action.set_state(&id.to_variant());
                if let Some(inner) = weak.upgrade() {
                    inner.set_kind(GeneratorKind::from_id(id));
                }
            });
        }
        group.add_action(&kind_action);
        root.insert_action_group("gen", Some(&group));

        {
            let weak = Rc::downgrade(&inner);
            copy_icon.connect_clicked(move |_| {
                if let Some(inner) = weak.upgrade() {
                    inner.copy();
                }
            });
        }
        {
            let weak = Rc::downgrade(&inner);
            regenerate.connect_clicked(move |_| {
                if let Some(inner) = weak.upgrade() {
                    inner.generate();
                }
            });
        }
        {
            let weak = Rc::downgrade(&inner);
            primary.connect_clicked(move |_| {
                let Some(inner) = weak.upgrade() else { return };
                match inner.mode {
                    PanelMode::Standalone => inner.copy(),
                    PanelMode::Embedded => inner.emit_primary(),
                }
            });
        }
        if let Some(secondary) = secondary {
            let weak = Rc::downgrade(&inner);
            secondary.connect_clicked(move |_| {
                if let Some(inner) = weak.upgrade() {
                    inner.emit_primary();
                }
            });
        }
        wire_option_changes(&inner);
        inner.set_kind(GeneratorKind::Random);

        Self { root, inner }
    }

    /// Standalone: called with the value by *Save to vault…*.
    /// Embedded: called with the value by *Use this password*.
    pub fn set_on_primary(&self, cb: ValueCallback) {
        *self.inner.on_primary.borrow_mut() = Some(cb);
    }

    #[cfg(debug_assertions)]
    pub fn dev_set_kind(&self, id: &str) {
        self.inner.set_kind(GeneratorKind::from_id(id));
    }

    #[cfg(debug_assertions)]
    pub fn dev_expand(&self, expanded: bool) {
        self.inner.expander.set_expanded(expanded);
    }
}

fn switch_row(title: &str, active: bool) -> adw::SwitchRow {
    adw::SwitchRow::builder()
        .title(title)
        .active(active)
        .build()
}

fn wire_option_changes(inner: &Rc<PanelInner>) {
    let regen = {
        let weak = Rc::downgrade(inner);
        move || {
            if let Some(inner) = weak.upgrade() {
                inner.generate();
            }
        }
    };
    {
        let regen = regen.clone();
        inner.length_row.connect_value_notify(move |_| regen());
    }
    {
        let regen = regen.clone();
        inner.words_row.connect_value_notify(move |_| regen());
    }
    {
        let regen = regen.clone();
        inner.pin_length_row.connect_value_notify(move |_| regen());
    }
    {
        let regen = regen.clone();
        inner.separator_row.connect_changed(move |_| regen());
    }
    // A site's rules can forbid a class, but at least one must stay on or
    // there is nothing to generate from.
    let classes = [
        inner.uppercase_row.clone(),
        inner.lowercase_row.clone(),
        inner.digits_row.clone(),
        inner.symbols_row.clone(),
    ];
    for row in classes.iter() {
        let regen = regen.clone();
        let all = classes.clone();
        row.connect_active_notify(move |changed| {
            if !all.iter().any(|r| r.is_active()) {
                changed.set_active(true);
                return;
            }
            regen();
        });
    }
    for row in [
        inner.ambiguous_row.clone(),
        inner.capitalize_row.clone(),
        inner.add_number_row.clone(),
    ] {
        let regen = regen.clone();
        row.connect_active_notify(move |_| regen());
    }
}

impl PanelInner {
    fn set_kind(&self, kind: GeneratorKind) {
        self.kind.set(kind);
        self.kind_button.set_label(kind.label());
        self.kind_hint.set_label(kind.hint());
        let random = kind == GeneratorKind::Random;
        let words = kind == GeneratorKind::Words;
        for row in [
            self.length_row.upcast_ref::<gtk::Widget>(),
            self.uppercase_row.upcast_ref(),
            self.lowercase_row.upcast_ref(),
            self.digits_row.upcast_ref(),
            self.symbols_row.upcast_ref(),
            self.ambiguous_row.upcast_ref(),
        ] {
            row.set_visible(random);
        }
        for row in [
            self.words_row.upcast_ref::<gtk::Widget>(),
            self.separator_row.upcast_ref(),
            self.capitalize_row.upcast_ref(),
            self.add_number_row.upcast_ref(),
        ] {
            row.set_visible(words);
        }
        self.pin_length_row.set_visible(kind == GeneratorKind::Pin);
        self.expander.set_title(match kind {
            GeneratorKind::Random => tr!("Adjust length and characters"),
            GeneratorKind::Words => tr!("Adjust words and separator"),
            GeneratorKind::Pin => tr!("Adjust number of digits"),
        });
        self.generate();
    }

    fn generate(&self) {
        let value = match self.kind.get() {
            GeneratorKind::Random => {
                let cfg = PasswordConfig {
                    length: self.length_row.value() as usize,
                    use_uppercase: self.uppercase_row.is_active(),
                    use_lowercase: self.lowercase_row.is_active(),
                    use_digits: self.digits_row.is_active(),
                    use_symbols: self.symbols_row.is_active(),
                    exclude_ambiguous: self.ambiguous_row.is_active(),
                    custom_symbols: String::new(),
                };
                match generate_password(&cfg) {
                    Ok(p) => p,
                    Err(e) => {
                        log::warn!("password generation failed: {e}");
                        self.summary_label
                            .set_label(tr!("These options cannot produce a password."));
                        return;
                    }
                }
            }
            GeneratorKind::Words => generate_passphrase(
                self.words_row.value() as usize,
                self.separator_row.text().as_str(),
                self.capitalize_row.is_active(),
                self.add_number_row.is_active(),
            ),
            GeneratorKind::Pin => generate_pin(self.pin_length_row.value() as usize),
        };
        self.password_label.set_label(&value);
        self.summary_label.set_label(&summary_for(
            self.kind.get(),
            &value,
            self.words_row.value() as usize,
        ));
        *self.current.borrow_mut() = Zeroizing::new(value);
    }

    fn copy(&self) {
        let value = self.current.borrow().clone();
        if value.is_empty() {
            return;
        }
        copy_secret(&self.state, &value);
        // Only what happened: it was copied, not saved and not used anywhere.
        self.toast.add_toast(
            adw::Toast::builder()
                .title(tr!("Password copied"))
                .timeout(3)
                .build(),
        );
        crate::session::SessionManager::on_activity(&self.state.session);
    }

    fn emit_primary(&self) {
        let value = self.current.borrow().to_string();
        if value.is_empty() {
            return;
        }
        if let Some(cb) = self.on_primary.borrow().as_ref() {
            cb(value);
        }
    }
}

/// "20 characters · Estimated strength: high", always computed from the
/// actual value so the label can never disagree with what is shown.
fn summary_for(kind: GeneratorKind, value: &str, words: usize) -> String {
    let chars = value.chars().count();
    let count = match kind {
        GeneratorKind::Words => format!(
            "{} · {}",
            crate::trn!("{} word", "{} words", words).replace("{}", &words.to_string()),
            crate::trn!("{} character", "{} characters", chars).replace("{}", &chars.to_string())
        ),
        GeneratorKind::Pin => {
            crate::trn!("{} digit", "{} digits", chars).replace("{}", &chars.to_string())
        }
        GeneratorKind::Random => {
            crate::trn!("{} character", "{} characters", chars).replace("{}", &chars.to_string())
        }
    };
    let strength = ashypass_core::strength::estimate(value, &[]);
    format!(
        "{count} · {}: {}",
        tr!("Estimated strength"),
        strength_word(strength.score)
    )
}

pub fn strength_word(score: u8) -> &'static str {
    match score {
        0 => tr!("very low"),
        1 => tr!("low"),
        2 => tr!("medium"),
        3 => tr!("high"),
        _ => tr!("very high"),
    }
}

// ============================================================================
// Standalone page
// ============================================================================

pub struct GeneratorView {
    pub root: adw::ToolbarView,
    pub panel: GeneratorPanel,
}

impl GeneratorView {
    pub fn new(state: SharedState, toast: adw::ToastOverlay, chrome: &Chrome) -> Self {
        let toolbar = adw::ToolbarView::new();
        toolbar.add_top_bar(&chrome.header(None));

        let panel = GeneratorPanel::new(state, toast, PanelMode::Standalone);
        let content = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(20)
            .build();
        content.append(&page_heading(
            tr!("Create password"),
            Some(tr!("A new password to use on a website or app.")),
        ));
        content.append(&panel.root);

        let clamp = adw::Clamp::builder()
            .maximum_size(640)
            .margin_top(12)
            .margin_bottom(24)
            .margin_start(18)
            .margin_end(18)
            .child(&content)
            .build();
        let scrolled = gtk::ScrolledWindow::builder()
            .hscrollbar_policy(gtk::PolicyType::Never)
            .vexpand(true)
            .child(&clamp)
            .build();
        toolbar.set_content(Some(&scrolled));
        Self {
            root: toolbar,
            panel,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_ids_round_trip() {
        for kind in [
            GeneratorKind::Random,
            GeneratorKind::Words,
            GeneratorKind::Pin,
        ] {
            assert_eq!(GeneratorKind::from_id(kind.id()), kind);
        }
        assert_eq!(GeneratorKind::from_id("unknown"), GeneratorKind::Random);
    }

    #[test]
    fn summary_counts_the_real_value() {
        // The mockup labelled an 18-character sample as "20 characters";
        // the summary must always come from the string itself.
        let sample = "C9m#7kL2v@Qp4nZ8t!";
        let summary = summary_for(GeneratorKind::Random, sample, 0);
        assert!(summary.starts_with("18 "), "{summary}");
        let pin = summary_for(GeneratorKind::Pin, "123456", 0);
        assert!(pin.starts_with("6 "), "{pin}");
    }

    #[test]
    fn default_ui_length_is_within_core_bounds() {
        let len = UI_DEFAULT_PASSWORD_LENGTH as usize;
        assert!((MIN_PASSWORD_LENGTH..=MAX_PASSWORD_LENGTH).contains(&len));
        let cfg = PasswordConfig {
            length: len,
            ..PasswordConfig::default()
        };
        assert_eq!(generate_password(&cfg).unwrap().chars().count(), len);
    }
}
