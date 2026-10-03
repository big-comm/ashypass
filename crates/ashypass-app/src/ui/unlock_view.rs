//! The single unlock screen shared by every page that needs the vault.
//!
//! It has three modes and each one keeps title, explanation, field label and
//! button about the same method — the old screen asked for the master
//! password above a PIN field:
//!
//! - **Setup**: no vault yet. Creates the master password and says plainly
//!   that it cannot be recovered.
//! - **Password**: unlock with the master password.
//! - **Pin**: unlock with the quick-unlock PIN configured on this computer,
//!   with a way back to the master password.

use crate::session::SessionManager;
use crate::state::SharedState;
use crate::tr;
use crate::ui::widgets::describe;
use adw::prelude::*;
use ashypass_core::config::MIN_MASTER_PASSWORD_LENGTH;
use gtk::{gdk, glib};
use std::cell::{Cell, RefCell};
use std::rc::Rc;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UnlockMode {
    Setup,
    Password,
    Pin,
}

type Callback = Box<dyn Fn()>;

pub struct UnlockView {
    pub root: gtk::Widget,
    inner: Rc<Inner>,
}

struct Inner {
    state: SharedState,
    mode: Cell<UnlockMode>,
    busy: Cell<bool>,

    icon: gtk::Image,
    title: gtk::Label,
    subtitle: gtk::Label,
    secret_entry: adw::PasswordEntryRow,
    confirm_entry: adw::PasswordEntryRow,
    caps_warning: gtk::Label,
    strength_label: gtk::Label,
    error_label: gtk::Label,
    primary_button: gtk::Button,
    spinner: gtk::Spinner,
    switch_method_button: gtk::Button,
    setup_help: gtk::Box,

    /// Keyring-backed unlock is a startup convenience only. Once it has been
    /// tried, or the user has locked the vault, it must not run again: every
    /// lock re-evaluates the mode, which would otherwise reopen the vault
    /// on the spot with the stored master password.
    keyring_unlock_allowed: Cell<bool>,
    /// The user chose the master password while a PIN is configured.
    prefer_password: Cell<bool>,
    on_unlocked: RefCell<Option<Callback>>,
    on_import_help: RefCell<Option<Callback>>,
}

impl UnlockView {
    pub fn new(state: SharedState) -> Rc<Self> {
        let clamp = adw::Clamp::builder()
            .maximum_size(420)
            .margin_top(36)
            .margin_bottom(36)
            .margin_start(18)
            .margin_end(18)
            .valign(gtk::Align::Center)
            .build();
        let content = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(14)
            .build();

        let icon = gtk::Image::builder()
            .icon_name("ashypass")
            .pixel_size(80)
            .build();
        icon.set_accessible_role(gtk::AccessibleRole::Presentation);
        content.append(&icon);

        let title = gtk::Label::builder()
            .wrap(true)
            .justify(gtk::Justification::Center)
            .build();
        title.add_css_class("title-1");
        title.set_accessible_role(gtk::AccessibleRole::Heading);
        content.append(&title);

        let subtitle = gtk::Label::builder()
            .wrap(true)
            .justify(gtk::Justification::Center)
            .build();
        subtitle.add_css_class("dim-label");
        content.append(&subtitle);

        let fields = gtk::ListBox::builder()
            .selection_mode(gtk::SelectionMode::None)
            .margin_top(8)
            .build();
        fields.add_css_class("boxed-list");
        let secret_entry = adw::PasswordEntryRow::new();
        fields.append(&secret_entry);
        let confirm_entry = adw::PasswordEntryRow::builder()
            .title(tr!("Confirm master password"))
            .visible(false)
            .build();
        fields.append(&confirm_entry);
        content.append(&fields);

        let caps_warning = gtk::Label::builder()
            .label(tr!("Caps Lock is on"))
            .xalign(0.0)
            .visible(false)
            .build();
        caps_warning.add_css_class("warning");
        caps_warning.add_css_class("caption");
        content.append(&caps_warning);

        let strength_label = gtk::Label::builder()
            .xalign(0.0)
            .wrap(true)
            .visible(false)
            .build();
        strength_label.add_css_class("caption");
        strength_label.add_css_class("dim-label");
        content.append(&strength_label);

        let error_label = gtk::Label::builder()
            .xalign(0.0)
            .wrap(true)
            .visible(false)
            .build();
        error_label.add_css_class("error");
        error_label.set_accessible_role(gtk::AccessibleRole::Alert);
        content.append(&error_label);
        describe(&secret_entry, &error_label);
        describe(&secret_entry, &caps_warning);

        let primary_row = gtk::Box::builder()
            .orientation(gtk::Orientation::Horizontal)
            .spacing(8)
            .halign(gtk::Align::Fill)
            .build();
        let primary_button = gtk::Button::builder().hexpand(true).build();
        primary_button.add_css_class("pill");
        primary_button.add_css_class("suggested-action");
        let spinner = gtk::Spinner::builder().visible(false).build();
        primary_row.append(&primary_button);
        primary_row.append(&spinner);
        content.append(&primary_row);

        let switch_method_button = gtk::Button::builder()
            .halign(gtk::Align::Center)
            .visible(false)
            .build();
        switch_method_button.add_css_class("flat");
        content.append(&switch_method_button);

        // First run only: the honest answer to "what if I forget it?" and a
        // pointer for people who already keep passwords somewhere else.
        let setup_help = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(8)
            .margin_top(8)
            .visible(false)
            .build();
        let recovery = gtk::Label::builder()
            .label(tr!(
                "Ashy Pass cannot recover this password. Without it, nobody — including you — can open the vault. Write it down somewhere safe."
            ))
            .wrap(true)
            .xalign(0.0)
            .build();
        recovery.add_css_class("caption");
        let recovery_box = gtk::Box::builder()
            .orientation(gtk::Orientation::Horizontal)
            .spacing(10)
            .build();
        recovery_box.add_css_class("ashy-note");
        let info_icon = gtk::Image::from_icon_name("dialog-information-symbolic");
        info_icon.set_valign(gtk::Align::Start);
        recovery_box.append(&info_icon);
        recovery_box.append(&recovery);
        setup_help.append(&recovery_box);
        let import_help = gtk::Button::builder()
            .label(tr!("I already keep passwords somewhere else"))
            .halign(gtk::Align::Center)
            .build();
        import_help.add_css_class("flat");
        setup_help.append(&import_help);
        content.append(&setup_help);

        clamp.set_child(Some(&content));
        let scrolled = gtk::ScrolledWindow::builder()
            .hscrollbar_policy(gtk::PolicyType::Never)
            .vexpand(true)
            .child(&clamp)
            .build();

        let inner = Rc::new(Inner {
            state,
            mode: Cell::new(UnlockMode::Password),
            busy: Cell::new(false),
            icon,
            title,
            subtitle,
            secret_entry,
            confirm_entry,
            caps_warning,
            strength_label,
            error_label,
            primary_button,
            spinner,
            switch_method_button,
            setup_help,
            keyring_unlock_allowed: Cell::new(true),
            prefer_password: Cell::new(false),
            on_unlocked: RefCell::new(None),
            on_import_help: RefCell::new(None),
        });

        wire(&inner, &import_help);
        inner.refresh();

        Rc::new(Self {
            root: scrolled.upcast(),
            inner,
        })
    }

    pub fn set_on_unlocked(&self, cb: Callback) {
        *self.inner.on_unlocked.borrow_mut() = Some(cb);
    }

    pub fn set_on_import_help(&self, cb: Callback) {
        *self.inner.on_import_help.borrow_mut() = Some(cb);
    }

    /// Re-evaluate the mode (setup / password / PIN) and clear the fields.
    pub fn refresh(&self) {
        self.inner.refresh();
    }

    pub fn focus(&self) {
        self.inner.focus();
    }

    /// Called on every lock: the keyring shortcut is spent, the user goes
    /// back to the configured method.
    pub fn on_locked(&self) {
        self.inner.keyring_unlock_allowed.set(false);
        self.inner.prefer_password.set(false);
        self.inner.refresh();
    }

    /// One attempt at the opt-in keyring unlock, at startup only.
    pub fn try_keyring_unlock(&self) -> bool {
        self.inner.try_keyring_unlock()
    }

    #[cfg(debug_assertions)]
    pub fn dev_submit(&self, secret: &str) {
        self.inner.secret_entry.set_text(secret);
        if self.inner.mode.get() == UnlockMode::Setup {
            self.inner.confirm_entry.set_text(secret);
        }
        self.inner.on_primary();
    }
}

fn wire(inner: &Rc<Inner>, import_help: &gtk::Button) {
    let weak = Rc::downgrade(inner);
    inner.primary_button.connect_clicked(move |_| {
        if let Some(inner) = weak.upgrade() {
            inner.on_primary();
        }
    });
    let weak = Rc::downgrade(inner);
    inner.secret_entry.connect_entry_activated(move |_| {
        if let Some(inner) = weak.upgrade() {
            if inner.mode.get() == UnlockMode::Setup {
                inner.confirm_entry.grab_focus();
            } else {
                inner.on_primary();
            }
        }
    });
    let weak = Rc::downgrade(inner);
    inner.confirm_entry.connect_entry_activated(move |_| {
        if let Some(inner) = weak.upgrade() {
            inner.on_primary();
        }
    });
    let weak = Rc::downgrade(inner);
    inner.secret_entry.connect_changed(move |entry| {
        if let Some(inner) = weak.upgrade() {
            inner.error_label.set_visible(false);
            inner.secret_entry.remove_css_class("error");
            if inner.mode.get() == UnlockMode::Setup {
                inner.update_setup_strength(&entry.text());
            }
        }
    });
    let weak = Rc::downgrade(inner);
    inner.switch_method_button.connect_clicked(move |_| {
        if let Some(inner) = weak.upgrade() {
            let to_password = inner.mode.get() == UnlockMode::Pin;
            inner.prefer_password.set(to_password);
            inner.refresh();
        }
    });
    let weak = Rc::downgrade(inner);
    import_help.connect_clicked(move |_| {
        if let Some(inner) = weak.upgrade() {
            if let Some(cb) = inner.on_import_help.borrow().as_ref() {
                cb();
            }
        }
    });

    // Caps Lock warning, live: a wrong-case password is the most common
    // reason a correct password "does not work".
    if let Some(keyboard) = gdk::Display::default()
        .and_then(|display| display.default_seat())
        .and_then(|seat| seat.keyboard())
    {
        let weak = Rc::downgrade(inner);
        let update = move |device: &gdk::Device| {
            if let Some(inner) = weak.upgrade() {
                inner.caps_warning.set_visible(device.is_caps_locked());
            }
        };
        update(&keyboard);
        keyboard.connect_caps_lock_state_notify(update);
    }
}

impl Inner {
    fn has_master(&self) -> bool {
        self.state
            .vault
            .borrow()
            .has_master_password()
            .unwrap_or(false)
    }

    fn pin_configured(&self) -> bool {
        self.state.vault.borrow().is_quick_unlock_available()
            || ashypass_core::keyring::is_quick_unlock_stored()
            || self
                .state
                .settings()
                .quick_unlock
                .as_ref()
                .is_some_and(|p| p.is_configured())
    }

    fn refresh(&self) {
        let mode = if !self.has_master() {
            UnlockMode::Setup
        } else if !self.prefer_password.get() && self.pin_configured() {
            UnlockMode::Pin
        } else {
            UnlockMode::Password
        };
        self.mode.set(mode);
        self.secret_entry.set_text("");
        self.confirm_entry.set_text("");
        self.error_label.set_visible(false);
        self.secret_entry.remove_css_class("error");
        self.confirm_entry.remove_css_class("error");
        self.set_busy(false);

        match mode {
            UnlockMode::Setup => {
                self.title.set_label(tr!("Create your vault"));
                self.subtitle.set_label(tr!(
                    "Choose a master password. It protects everything you keep in Ashy Pass on this computer."
                ));
                self.secret_entry.set_title(tr!("Master password"));
                self.confirm_entry.set_visible(true);
                self.primary_button.set_label(tr!("Create my vault"));
                self.switch_method_button.set_visible(false);
                self.setup_help.set_visible(true);
                self.strength_label.set_visible(true);
                self.strength_label.set_label(&format!(
                    "{} {MIN_MASTER_PASSWORD_LENGTH}",
                    tr!("Minimum length:")
                ));
            }
            UnlockMode::Password => {
                self.title.set_label(tr!("Unlock your vault"));
                self.subtitle.set_label(tr!(
                    "Enter your master password to access your saved items."
                ));
                self.secret_entry.set_title(tr!("Master password"));
                self.confirm_entry.set_visible(false);
                self.primary_button.set_label(tr!("Unlock"));
                let pin = self.pin_configured();
                self.switch_method_button.set_visible(pin);
                self.switch_method_button.set_label(tr!("Use PIN"));
                self.setup_help.set_visible(false);
                self.strength_label.set_visible(false);
            }
            UnlockMode::Pin => {
                self.title.set_label(tr!("Unlock with PIN"));
                self.subtitle
                    .set_label(tr!("Enter the PIN set up on this computer."));
                self.secret_entry.set_title(tr!("PIN"));
                self.confirm_entry.set_visible(false);
                self.primary_button.set_label(tr!("Unlock"));
                self.switch_method_button.set_visible(true);
                self.switch_method_button
                    .set_label(tr!("Use master password"));
                self.setup_help.set_visible(false);
                self.strength_label.set_visible(false);
            }
        }
        self.icon.set_icon_name(Some("ashypass"));
    }

    fn focus(&self) {
        let target = self.secret_entry.clone();
        glib::idle_add_local_once(move || {
            target.grab_focus();
        });
    }

    fn set_busy(&self, busy: bool) {
        self.busy.set(busy);
        self.spinner.set_visible(busy);
        if busy {
            self.spinner.start();
        } else {
            self.spinner.stop();
        }
        self.primary_button.set_sensitive(!busy);
        self.secret_entry.set_sensitive(!busy);
        self.confirm_entry.set_sensitive(!busy);
        self.switch_method_button.set_sensitive(!busy);
    }

    fn show_error(&self, message: &str) {
        self.error_label.set_label(message);
        self.error_label.set_visible(true);
        self.secret_entry.add_css_class("error");
    }

    fn update_setup_strength(&self, password: &str) {
        if password.is_empty() {
            self.strength_label.set_label(&format!(
                "{} {MIN_MASTER_PASSWORD_LENGTH}",
                tr!("Minimum length:")
            ));
            return;
        }
        let (_, level) = ashypass_core::strength::legacy_score(password);
        self.strength_label.set_label(&format!(
            "{} · {}: {}",
            crate::trn!("{} character", "{} characters", password.chars().count())
                .replace("{}", &password.chars().count().to_string()),
            tr!("Estimated strength"),
            crate::ui::i18n::localized_strength_label(level)
        ));
    }

    fn finish_unlock(&self) {
        SessionManager::login(&self.state.session);
        self.secret_entry.set_text("");
        self.confirm_entry.set_text("");
        if let Some(cb) = self.on_unlocked.borrow().as_ref() {
            cb();
        }
    }

    fn on_primary(self: &Rc<Self>) {
        if self.busy.get() {
            return;
        }
        match self.mode.get() {
            UnlockMode::Setup => self.create_vault(),
            UnlockMode::Password => self.unlock_with_password(),
            UnlockMode::Pin => self.unlock_with_pin(),
        }
    }

    fn create_vault(self: &Rc<Self>) {
        let password = self.secret_entry.text().to_string();
        let confirm = self.confirm_entry.text().to_string();
        if password.chars().count() < MIN_MASTER_PASSWORD_LENGTH {
            self.show_error(&format!(
                "{} {MIN_MASTER_PASSWORD_LENGTH}",
                tr!("The master password is too short. Minimum length:")
            ));
            return;
        }
        if password != confirm {
            self.confirm_entry.add_css_class("error");
            self.show_error(tr!("The passwords do not match"));
            return;
        }
        // Bind the result first: a `borrow_mut()` in a match scrutinee would
        // stay alive through the callback, which borrows the vault again.
        let result = self.state.vault.borrow_mut().set_master_password(&password);
        match result {
            Ok(()) => {
                if let Err(error) = self.state.update_settings(|s| s.quick_unlock = None) {
                    log::warn!("could not save settings: {error}");
                }
                self.finish_unlock();
            }
            Err(e) => self.show_error(&format!("{}: {e}", tr!("Could not create the vault"))),
        }
    }

    fn unlock_with_password(self: &Rc<Self>) {
        let password = self.secret_entry.text().to_string();
        if password.is_empty() {
            self.show_error(tr!("Enter your master password"));
            return;
        }
        self.set_busy(true);
        let weak = Rc::downgrade(self);
        // Let the spinner paint before the key derivation blocks the loop.
        glib::idle_add_local_once(move || {
            let Some(inner) = weak.upgrade() else { return };
            let result = inner.state.vault.borrow_mut().unlock(&password);
            inner.set_busy(false);
            match result {
                Ok(()) => inner.finish_unlock(),
                Err(ashypass_core::Error::InvalidMasterPassword) => {
                    inner.secret_entry.set_text("");
                    inner.show_error(tr!("Incorrect master password"));
                    inner.focus();
                }
                Err(e) => inner.show_error(&format!("{}: {e}", tr!("Could not unlock the vault"))),
            }
        });
    }

    fn unlock_with_pin(self: &Rc<Self>) {
        let pin = self.secret_entry.text().to_string();
        if pin.is_empty() {
            self.show_error(tr!("Enter your PIN"));
            return;
        }
        self.set_busy(true);
        let weak = Rc::downgrade(self);
        glib::idle_add_local_once(move || {
            if let Some(inner) = weak.upgrade() {
                inner.set_busy(false);
                inner.pin_attempt(&pin);
            }
        });
    }

    fn pin_attempt(self: &Rc<Self>, pin: &str) {
        let mut loaded_settings = (*self.state.settings()).clone();
        let legacy_quick_unlock = loaded_settings.quick_unlock.clone();
        let keyring_quick_unlock = ashypass_core::keyring::load_quick_unlock()
            .map_err(|error| log::warn!("quick-unlock keyring read failed: {error}"))
            .ok()
            .flatten();
        let persistent_quick_unlock = keyring_quick_unlock
            .as_ref()
            .or(legacy_quick_unlock.as_ref());
        let result = {
            let mut vault = self.state.vault.borrow_mut();
            if vault.is_quick_unlock_available() {
                match vault.quick_unlock(pin) {
                    Ok(()) => Ok(()),
                    Err(ashypass_core::Error::InvalidMasterPassword) => {
                        Err(ashypass_core::Error::InvalidMasterPassword)
                    }
                    Err(e) => match persistent_quick_unlock {
                        Some(prefs) => vault.quick_unlock_persistent(pin, prefs),
                        None => Err(e),
                    },
                }
            } else if let Some(prefs) = persistent_quick_unlock {
                vault.quick_unlock_persistent(pin, prefs)
            } else {
                vault.quick_unlock(pin)
            }
        };
        match result {
            Ok(()) => {
                // A correct PIN clears the failure budget.
                if let Some(prefs) = persistent_quick_unlock.filter(|p| p.failed_attempts > 0) {
                    let mut reset = prefs.clone();
                    reset.failed_attempts = 0;
                    if let Err(error) = ashypass_core::keyring::store_quick_unlock(&reset) {
                        log::warn!("could not reset PIN attempt counter: {error}");
                    }
                }
                if keyring_quick_unlock.is_none() {
                    if let Some(prefs) = legacy_quick_unlock.as_ref() {
                        match ashypass_core::keyring::store_quick_unlock(prefs) {
                            Ok(()) => {
                                loaded_settings.quick_unlock = None;
                                if let Err(error) = loaded_settings.save() {
                                    log::warn!(
                                        "could not clear migrated quick-unlock settings: {error}"
                                    );
                                }
                            }
                            Err(error) => log::warn!(
                                "could not migrate quick-unlock state to keyring: {error}"
                            ),
                        }
                    }
                }
                self.finish_unlock();
            }
            Err(ashypass_core::Error::InvalidMasterPassword) => {
                self.secret_entry.set_text("");
                // Persisted PIN state has no rate limit of its own, so count
                // wrong attempts and destroy it once the budget is spent.
                match persistent_quick_unlock.cloned() {
                    Some(prefs) => {
                        let remaining = self.record_failed_pin_attempt(prefs);
                        if remaining == 0 {
                            self.prefer_password.set(true);
                            self.refresh();
                            self.show_error(tr!(
                                "Too many incorrect PINs. Quick unlock was turned off — use your master password."
                            ));
                        } else {
                            self.show_error(
                                &crate::trn!(
                                    "Incorrect PIN. {} attempt left.",
                                    "Incorrect PIN. {} attempts left.",
                                    remaining as usize
                                )
                                .replace("{}", &remaining.to_string()),
                            );
                        }
                    }
                    None => self.show_error(tr!("Incorrect PIN")),
                }
                self.focus();
            }
            Err(e) => {
                log::warn!("quick unlock failed: {e}");
                self.state.vault.borrow_mut().disable_quick_unlock();
                self.prefer_password.set(true);
                self.refresh();
                self.show_error(tr!(
                    "The PIN could not be used on this computer. Use your master password."
                ));
            }
        }
    }

    /// Persist one more failed PIN attempt and return how many remain. At zero
    /// the persisted quick-unlock state is wiped from both the keyring and the
    /// legacy settings file, so the master password is the only way back in.
    fn record_failed_pin_attempt(
        &self,
        mut prefs: ashypass_core::settings::QuickUnlockPrefs,
    ) -> u32 {
        use ashypass_core::settings::QUICK_UNLOCK_MAX_ATTEMPTS;

        prefs.failed_attempts = prefs.failed_attempts.saturating_add(1);
        let remaining = QUICK_UNLOCK_MAX_ATTEMPTS.saturating_sub(prefs.failed_attempts);

        if remaining == 0 {
            self.state.vault.borrow_mut().disable_quick_unlock();
            if let Err(error) = ashypass_core::keyring::delete_quick_unlock() {
                log::warn!("could not clear quick-unlock keyring item: {error}");
            }
            if let Err(error) = self.state.update_settings(|s| s.quick_unlock = None) {
                log::warn!("could not clear quick-unlock settings: {error}");
            }
            return 0;
        }

        // Best effort: if the counter cannot be persisted we still refuse this
        // attempt, we just cannot enforce the budget across restarts.
        if let Err(error) = ashypass_core::keyring::store_quick_unlock(&prefs) {
            log::warn!("could not record failed PIN attempt: {error}");
            let stored = prefs.clone();
            if let Err(error) = self
                .state
                .update_settings(|s| s.quick_unlock = Some(stored))
            {
                log::warn!("could not record failed PIN attempt in settings: {error}");
            }
        }
        remaining
    }

    fn try_keyring_unlock(&self) -> bool {
        if self.state.vault.borrow().is_unlocked() {
            return true;
        }
        if !self.keyring_unlock_allowed.replace(false) || !self.has_master() {
            return false;
        }
        let Ok(Some(pw)) = ashypass_core::keyring::load_master() else {
            return false;
        };
        let result = self.state.vault.borrow_mut().unlock(&pw);
        match result {
            Ok(()) => {
                self.finish_unlock();
                true
            }
            Err(ashypass_core::Error::InvalidMasterPassword) => {
                // Stored secret no longer matches the vault — purge it so we
                // don't keep trying on every restart.
                let _ = ashypass_core::keyring::delete_master();
                false
            }
            Err(e) => {
                // A transient failure (busy database, I/O) says nothing about
                // the stored secret, so keep it for the next start.
                log::warn!("keyring unlock failed: {e}");
                false
            }
        }
    }
}
