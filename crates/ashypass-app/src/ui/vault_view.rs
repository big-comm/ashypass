//! Vault view — CRUD, search, favorites, categories, auth.
//!
//! Ported from the original `ui/vault_view.py`. Two pages in a `Gtk.Stack`:
//! an auth/setup screen when locked, and the password list when unlocked.

use crate::session::SessionManager;
use crate::state::SharedState;
use crate::tr;
use adw::prelude::*;
use ashypass_core::config::MIN_MASTER_PASSWORD_LENGTH;
use ashypass_core::db::vault::{NewEntry, PasswordEntry, UpdateEntry};
use ashypass_core::generator::{
    generate_passphrase, generate_password, generate_pin, PasswordConfig,
};
use ashypass_core::settings::Settings;
use ashypass_core::totp::{generate_totp, remaining_seconds, Algorithm};
use gtk::glib;
use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::rc::Rc;

type AuthChangedCb = Box<dyn Fn()>;
type TotpWidget = (gtk::Label, gtk::ProgressBar, i64, String, u8, u32);
type RenderSlot = Rc<RefCell<Option<Rc<dyn Fn()>>>>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum ViewMode {
    All,
    Favorites,
    Groups,
}

pub struct VaultView {
    pub root: gtk::Box,
    pub search_bar: gtk::SearchBar,
    pub search_entry: gtk::SearchEntry,
    inner: Rc<Inner>,
}

struct Inner {
    state: SharedState,
    toast: adw::ToastOverlay,

    main_stack: gtk::Stack,

    // Auth page
    master_entry: adw::PasswordEntryRow,
    confirm_entry: adw::PasswordEntryRow,
    pin_entry: adw::PasswordEntryRow,
    pin_button: gtk::Button,
    use_master_button: gtk::Button,
    unlock_button: gtk::Button,
    auth_error: gtk::Label,
    strength_box: gtk::Box,
    strength_bar: gtk::LevelBar,
    strength_label: gtk::Label,

    // Vault page
    timeout_banner: adw::Banner,
    search_entry: gtk::SearchEntry,
    search_reload_id: RefCell<Option<glib::SourceId>>,
    category_bar: gtk::Box,
    category_dropdown: gtk::DropDown,
    category_model: RefCell<gtk::StringList>,
    category_names: RefCell<Vec<String>>,
    updating_categories: Cell<bool>,
    list_box: gtk::ListBox,
    list_scrolled: gtk::ScrolledWindow,
    empty_status: adw::StatusPage,
    content_stack: gtk::Stack,

    view_mode: Cell<ViewMode>,
    expanded_folders: RefCell<HashSet<String>>,
    totp_widgets: RefCell<Vec<TotpWidget>>,
    totp_timer_id: RefCell<Option<glib::SourceId>>,

    on_auth_changed: RefCell<Option<AuthChangedCb>>,
}

impl VaultView {
    pub fn new(state: SharedState, toast: adw::ToastOverlay) -> Rc<Self> {
        let root = gtk::Box::new(gtk::Orientation::Vertical, 0);
        root.set_vexpand(true);
        root.set_hexpand(true);

        let main_stack = gtk::Stack::builder()
            .transition_type(gtk::StackTransitionType::Crossfade)
            .transition_duration(300)
            .build();

        // ---- Auth page ----
        let (
            auth_page,
            master_entry,
            confirm_entry,
            pin_entry,
            unlock_button,
            pin_button,
            use_master_button,
            auth_error,
            strength_box,
            strength_bar,
            strength_label,
        ) = build_auth_page();
        main_stack.add_named(&auth_page, Some("auth"));

        // ---- Vault page ----
        let (
            vault_page,
            timeout_banner,
            search_bar,
            search_entry,
            category_bar,
            category_dropdown,
            category_model,
            list_box,
            list_scrolled,
            empty_status,
            content_stack,
        ) = build_vault_page();
        main_stack.add_named(&vault_page, Some("vault"));

        root.append(&main_stack);

        let inner = Rc::new(Inner {
            state,
            toast,
            main_stack,
            master_entry,
            confirm_entry,
            pin_entry,
            pin_button,
            use_master_button,
            unlock_button,
            auth_error,
            strength_box,
            strength_bar,
            strength_label,
            timeout_banner,
            search_entry: search_entry.clone(),
            search_reload_id: RefCell::new(None),
            category_bar,
            category_dropdown,
            category_model: RefCell::new(category_model),
            category_names: RefCell::new(Vec::new()),
            updating_categories: Cell::new(false),
            list_box,
            list_scrolled,
            empty_status,
            content_stack,
            view_mode: Cell::new(ViewMode::All),
            expanded_folders: RefCell::new(HashSet::new()),
            totp_widgets: RefCell::new(Vec::new()),
            totp_timer_id: RefCell::new(None),
            on_auth_changed: RefCell::new(None),
        });

        wire_auth(&inner);
        wire_vault(&inner);
        wire_events(&inner);
        wire_session_warning(&inner);

        inner.update_view();

        Self {
            root,
            search_bar,
            search_entry,
            inner,
        }
        .into_rc()
    }

    fn into_rc(self) -> Rc<Self> {
        Rc::new(self)
    }

    pub fn set_on_auth_changed(&self, cb: AuthChangedCb) {
        *self.inner.on_auth_changed.borrow_mut() = Some(cb);
    }

    pub fn focus_auth_field(&self) {
        self.inner.focus_auth_field();
    }

    pub fn show_add_dialog(&self) {
        if !self.inner.state.vault.borrow().is_unlocked() {
            return;
        }
        show_password_dialog(&self.inner, None);
    }

    /// Lock the vault triggered by user click or external (session timeout).
    pub fn lock_vault(&self) {
        self.inner.stop_totp_timer();
        self.inner.cancel_pending_search_reload();
        self.inner.state.vault.borrow_mut().lock();
        self.inner.timeout_banner.set_revealed(false);
        self.inner.update_view();
        self.inner.notify_auth_changed();
    }

    pub fn show_groups_view(&self) {
        self.inner.view_mode.set(ViewMode::Groups);
        self.inner.load_passwords(None);
    }

    pub fn show_favorites_view(&self) {
        self.inner.view_mode.set(ViewMode::Favorites);
        self.inner.load_passwords(None);
    }

    pub fn show_all_view(&self) {
        self.inner.view_mode.set(ViewMode::All);
        self.inner.load_passwords(None);
    }
}

// ============================================================================
// UI construction
// ============================================================================

#[allow(clippy::type_complexity)]
fn build_auth_page() -> (
    adw::Clamp,
    adw::PasswordEntryRow,
    adw::PasswordEntryRow,
    adw::PasswordEntryRow,
    gtk::Button,
    gtk::Button,
    gtk::Button,
    gtk::Label,
    gtk::Box,
    gtk::LevelBar,
    gtk::Label,
) {
    let clamp = adw::Clamp::builder()
        .maximum_size(400)
        .margin_top(48)
        .margin_bottom(48)
        .margin_start(12)
        .margin_end(12)
        .build();

    let content = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(24)
        .build();

    let icon = gtk::Image::from_icon_name("dialog-password-symbolic");
    icon.set_pixel_size(64);
    icon.add_css_class("dim-label");
    content.append(&icon);

    let title = gtk::Label::new(None);
    title.set_markup(&format!(
        "<span size='xx-large' weight='bold'>{}</span>",
        tr!("Ashy Pass")
    ));
    content.append(&title);

    let subtitle = gtk::Label::new(Some(tr!("Enter your master password to unlock")));
    subtitle.add_css_class("dim-label");
    content.append(&subtitle);

    let group = adw::PreferencesGroup::new();

    let master_entry = adw::PasswordEntryRow::builder()
        .title(tr!("Master Password"))
        .build();
    group.add(&master_entry);

    // Strength indicator (visible only during first-time setup)
    let strength_box = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(4)
        .margin_start(12)
        .margin_end(12)
        .visible(false)
        .build();
    let strength_bar = gtk::LevelBar::builder()
        .mode(gtk::LevelBarMode::Continuous)
        .min_value(0.0)
        .max_value(100.0)
        .build();
    strength_box.append(&strength_bar);
    let strength_label = gtk::Label::new(None);
    strength_label.add_css_class("dim-label");
    strength_label.add_css_class("caption");
    strength_label.set_xalign(0.0);
    strength_box.append(&strength_label);
    group.add(&strength_box);

    let confirm_entry = adw::PasswordEntryRow::builder()
        .title(tr!("Confirm Password"))
        .visible(false)
        .build();
    group.add(&confirm_entry);

    let pin_entry = adw::PasswordEntryRow::builder()
        .title(tr!("Quick-unlock PIN"))
        .visible(false)
        .build();
    group.add(&pin_entry);

    content.append(&group);

    let auth_error = gtk::Label::new(None);
    auth_error.add_css_class("error");
    auth_error.set_visible(false);
    content.append(&auth_error);

    let unlock_button = gtk::Button::with_label(tr!("Unlock Vault"));
    unlock_button.add_css_class("pill");
    unlock_button.add_css_class("suggested-action");
    unlock_button.set_halign(gtk::Align::Center);
    content.append(&unlock_button);

    let pin_button = gtk::Button::with_label(tr!("Unlock with PIN"));
    pin_button.add_css_class("pill");
    pin_button.add_css_class("suggested-action");
    pin_button.set_halign(gtk::Align::Center);
    pin_button.set_visible(false);
    content.append(&pin_button);

    let use_master_button = gtk::Button::with_label(tr!("Use master password instead"));
    use_master_button.add_css_class("flat");
    use_master_button.set_halign(gtk::Align::Center);
    use_master_button.set_visible(false);
    content.append(&use_master_button);

    clamp.set_child(Some(&content));

    (
        clamp,
        master_entry,
        confirm_entry,
        pin_entry,
        unlock_button,
        pin_button,
        use_master_button,
        auth_error,
        strength_box,
        strength_bar,
        strength_label,
    )
}

#[allow(clippy::type_complexity)]
fn build_vault_page() -> (
    gtk::Box,
    adw::Banner,
    gtk::SearchBar,
    gtk::SearchEntry,
    gtk::Box,
    gtk::DropDown,
    gtk::StringList,
    gtk::ListBox,
    gtk::ScrolledWindow,
    adw::StatusPage,
    gtk::Stack,
) {
    let main_box = gtk::Box::new(gtk::Orientation::Vertical, 0);

    let timeout_banner = adw::Banner::builder()
        .title(tr!("Vault will lock soon due to inactivity"))
        .button_label(tr!("Stay Unlocked"))
        .revealed(false)
        .build();
    main_box.append(&timeout_banner);

    let search_entry = gtk::SearchEntry::new();
    search_entry.set_placeholder_text(Some(tr!("Search passwords…")));
    let search_bar = gtk::SearchBar::builder()
        .search_mode_enabled(false)
        .child(&search_entry)
        .build();
    search_bar.connect_entry(&search_entry);
    main_box.append(&search_bar);

    let category_bar = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(6)
        .margin_start(12)
        .margin_end(12)
        .margin_top(4)
        .margin_bottom(4)
        .visible(false)
        .build();
    let cat_icon = gtk::Image::from_icon_name("folder-symbolic");
    cat_icon.add_css_class("folder-heading-icon");
    category_bar.append(&cat_icon);
    let category_model = gtk::StringList::new(&[tr!("All")]);
    let category_dropdown = gtk::DropDown::builder()
        .hexpand(true)
        .model(&category_model)
        .build();
    category_bar.append(&category_dropdown);
    main_box.append(&category_bar);

    let scrolled = gtk::ScrolledWindow::builder().vexpand(true).build();
    let list_box = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .margin_top(12)
        .margin_bottom(12)
        .margin_start(12)
        .margin_end(12)
        .build();
    list_box.add_css_class("boxed-list");
    scrolled.set_child(Some(&list_box));

    let empty_status = adw::StatusPage::builder()
        .icon_name("dialog-password-symbolic")
        .title(tr!("No Passwords Stored"))
        .description(tr!("Add your first password using the + button"))
        .build();

    let content_stack = gtk::Stack::builder()
        .transition_type(gtk::StackTransitionType::Crossfade)
        .transition_duration(200)
        .build();
    content_stack.add_named(&scrolled, Some("list"));
    content_stack.add_named(&empty_status, Some("empty"));
    main_box.append(&content_stack);

    (
        main_box,
        timeout_banner,
        search_bar,
        search_entry,
        category_bar,
        category_dropdown,
        category_model,
        list_box,
        scrolled,
        empty_status,
        content_stack,
    )
}

// ============================================================================
// Wiring
// ============================================================================

fn wire_auth(inner: &Rc<Inner>) {
    let inner_cl = inner.clone();
    inner
        .unlock_button
        .connect_clicked(move |_| inner_cl.on_unlock_clicked());

    let inner_cl = inner.clone();
    inner
        .master_entry
        .connect_entry_activated(move |_| inner_cl.on_unlock_clicked());

    let inner_cl = inner.clone();
    inner
        .confirm_entry
        .connect_entry_activated(move |_| inner_cl.on_unlock_clicked());

    let inner_cl = inner.clone();
    inner
        .pin_button
        .connect_clicked(move |_| inner_cl.on_pin_unlock_clicked());

    let inner_cl = inner.clone();
    inner
        .pin_entry
        .connect_entry_activated(move |_| inner_cl.on_pin_unlock_clicked());

    let inner_cl = inner.clone();
    inner.use_master_button.connect_clicked(move |_| {
        inner_cl.show_master_unlock();
    });

    let inner_cl = inner.clone();
    inner.master_entry.connect_changed(move |entry| {
        if !inner_cl.strength_box.is_visible() {
            return;
        }
        let pwd = entry.text();
        let s = pwd.as_str();
        if s.is_empty() {
            inner_cl.strength_bar.set_value(0.0);
            inner_cl.strength_label.set_text("");
        } else {
            let (score, level) = ashypass_core::strength::legacy_score(s);
            inner_cl.strength_bar.set_value(score as f64);
            inner_cl.strength_label.set_text(level);
        }
    });
}

fn wire_vault(inner: &Rc<Inner>) {
    let inner_cl = inner.clone();
    inner.search_entry.connect_search_changed(move |_| {
        if let Some(id) = inner_cl.search_reload_id.borrow_mut().take() {
            id.remove();
        }
        let inner_weak = Rc::downgrade(&inner_cl);
        let id = glib::timeout_add_local(std::time::Duration::from_millis(150), move || {
            let Some(inner) = inner_weak.upgrade() else {
                return glib::ControlFlow::Break;
            };
            *inner.search_reload_id.borrow_mut() = None;
            let text = inner.search_entry.text().trim().to_string();
            let search = if text.is_empty() { None } else { Some(text) };
            inner.load_passwords(search.as_deref());
            SessionManager::on_activity(&inner.state.session);
            glib::ControlFlow::Break
        });
        *inner_cl.search_reload_id.borrow_mut() = Some(id);
    });

    let inner_cl = inner.clone();
    inner.category_dropdown.connect_selected_notify(move |_| {
        if inner_cl.updating_categories.get() {
            return;
        }
        if let Some(id) = inner_cl.search_reload_id.borrow_mut().take() {
            id.remove();
        }
        let text = inner_cl.search_entry.text().trim().to_string();
        let search = if text.is_empty() { None } else { Some(text) };
        inner_cl.load_passwords(search.as_deref());
        SessionManager::on_activity(&inner_cl.state.session);
    });

    let inner_cl = inner.clone();
    inner.timeout_banner.connect_button_clicked(move |b| {
        b.set_revealed(false);
        SessionManager::on_activity(&inner_cl.state.session);
    });
}

fn wire_session_warning(inner: &Rc<Inner>) {
    let inner_weak = Rc::downgrade(inner);
    let cb: Rc<dyn Fn(u64)> = Rc::new(move |remaining| {
        let Some(inner) = inner_weak.upgrade() else {
            return;
        };
        inner.timeout_banner.set_title(&format!(
            "{} ({}s)",
            tr!("Vault will lock soon due to inactivity"),
            remaining
        ));
        inner.timeout_banner.set_revealed(true);
    });
    inner.state.session.borrow_mut().set_warning_callback(cb);
}

fn wire_events(inner: &Rc<Inner>) {
    let inner_weak = Rc::downgrade(inner);
    inner.state.events.subscribe(move |event| {
        let Some(inner) = inner_weak.upgrade() else {
            return;
        };
        match event {
            crate::events::AppEvent::VaultChanged
            | crate::events::AppEvent::SyncCompleted { .. }
                if inner.can_show_vault_data() =>
            {
                inner.update_view();
            }
            crate::events::AppEvent::SessionLocked => inner.update_view(),
            _ => {}
        }
    });
}

// ============================================================================
// Inner — view model logic
// ============================================================================

impl Inner {
    fn can_show_vault_data(&self) -> bool {
        self.state.session.borrow().is_authenticated() && self.state.vault.borrow().is_unlocked()
    }

    fn notify_auth_changed(&self) {
        if let Some(cb) = self.on_auth_changed.borrow().as_ref() {
            cb();
        }
    }

    fn show_toast(&self, message: &str) {
        let toast = adw::Toast::builder().title(message).timeout(3).build();
        self.toast.add_toast(toast);
    }

    /// If the user has opted in to keyring-backed unlock, fetch the stored
    /// master password and try to unlock with it. Silent on failure — we just
    /// fall through to the normal prompt. Returns true when the vault was
    /// successfully unlocked through this path.
    fn try_keyring_unlock(self: &Rc<Self>) -> bool {
        if self.state.vault.borrow().is_unlocked() {
            return true;
        }
        if !self
            .state
            .vault
            .borrow()
            .has_master_password()
            .unwrap_or(false)
        {
            return false;
        }
        let Ok(Some(pw)) = ashypass_core::keyring::load_master() else {
            return false;
        };
        if self.state.vault.borrow_mut().unlock(&pw).is_ok() {
            SessionManager::login(&self.state.session);
            self.notify_auth_changed();
            true
        } else {
            // Stored secret no longer matches the vault — purge it so we don't
            // keep trying on every restart.
            let _ = ashypass_core::keyring::delete_master();
            false
        }
    }

    fn update_view(self: &Rc<Self>) {
        let mut authed = self.state.session.borrow().is_authenticated()
            && self.state.vault.borrow().is_unlocked();
        if !authed {
            authed = self.try_keyring_unlock();
        }
        if authed {
            self.main_stack.set_visible_child_name("vault");
            self.load_passwords(None);
        } else {
            let has_master = self
                .state
                .vault
                .borrow()
                .has_master_password()
                .unwrap_or(false);
            let quick = has_master
                && (self.state.vault.borrow().is_quick_unlock_available()
                    || Settings::load()
                        .quick_unlock
                        .as_ref()
                        .is_some_and(|p| p.is_configured()));
            if has_master {
                self.unlock_button.set_label(tr!("Unlock Vault"));
                self.confirm_entry.set_visible(false);
                self.strength_box.set_visible(false);
            } else {
                self.unlock_button.set_label(tr!("Create Master Password"));
                self.confirm_entry.set_visible(true);
                self.strength_box.set_visible(true);
            }
            // Decide whether to show PIN UI or master UI.
            self.pin_entry.set_visible(quick);
            self.pin_button.set_visible(quick);
            self.use_master_button.set_visible(quick);
            self.master_entry.set_visible(!quick);
            self.unlock_button.set_visible(!quick);

            self.main_stack.set_visible_child_name("auth");
            self.master_entry.set_text("");
            self.confirm_entry.set_text("");
            self.pin_entry.set_text("");
            self.auth_error.set_visible(false);
            self.strength_bar.set_value(0.0);
            self.strength_label.set_text("");
            self.focus_auth_field();
        }
    }

    fn focus_auth_field(&self) {
        let target = if self.pin_entry.is_visible() {
            self.pin_entry.clone().upcast::<gtk::Widget>()
        } else {
            self.master_entry.clone().upcast::<gtk::Widget>()
        };
        glib::idle_add_local_once(move || {
            target.grab_focus();
        });
    }

    /// Switch the auth page from PIN-only to master-password mode. Triggered
    /// when the user clicks "Use master password instead" or after too many
    /// failed PIN attempts.
    fn show_master_unlock(self: &Rc<Self>) {
        self.pin_entry.set_visible(false);
        self.pin_button.set_visible(false);
        self.use_master_button.set_visible(false);
        self.master_entry.set_visible(true);
        self.unlock_button.set_visible(true);
        self.focus_auth_field();
    }

    fn on_pin_unlock_clicked(self: &Rc<Self>) {
        let pin = self.pin_entry.text().to_string();
        if pin.is_empty() {
            self.show_auth_error(tr!("Please enter your PIN"));
            return;
        }
        let persistent_quick_unlock = Settings::load().quick_unlock;
        let r = {
            let mut vault = self.state.vault.borrow_mut();
            if vault.is_quick_unlock_available() {
                match vault.quick_unlock(&pin) {
                    Ok(()) => Ok(()),
                    Err(ashypass_core::Error::InvalidMasterPassword) => {
                        Err(ashypass_core::Error::InvalidMasterPassword)
                    }
                    Err(e) => {
                        if let Some(prefs) = persistent_quick_unlock.as_ref() {
                            vault.quick_unlock_persistent(&pin, prefs)
                        } else {
                            Err(e)
                        }
                    }
                }
            } else if let Some(prefs) = persistent_quick_unlock.as_ref() {
                vault.quick_unlock_persistent(&pin, prefs)
            } else {
                vault.quick_unlock(&pin)
            }
        };
        match r {
            Ok(()) => {
                SessionManager::login(&self.state.session);
                self.update_view();
                self.notify_auth_changed();
            }
            Err(ashypass_core::Error::InvalidMasterPassword) => {
                self.show_auth_error(tr!("Incorrect PIN"));
                self.pin_entry.set_text("");
            }
            Err(e) => {
                // Cache may have been lost (e.g. dev path) — fall back.
                self.show_auth_error(&format!("{}: {e}", tr!("Quick-unlock failed")));
                self.state.vault.borrow_mut().disable_quick_unlock();
                let mut settings = Settings::load();
                settings.quick_unlock = None;
                let _ = settings.save();
                self.show_master_unlock();
            }
        }
    }

    fn show_auth_error(&self, msg: &str) {
        self.auth_error.set_text(msg);
        self.auth_error.set_visible(true);
    }

    fn on_unlock_clicked(self: &Rc<Self>) {
        let password = self.master_entry.text().to_string();
        if password.is_empty() {
            self.show_auth_error(tr!("Please enter a password"));
            return;
        }

        let has_master = self
            .state
            .vault
            .borrow()
            .has_master_password()
            .unwrap_or(false);

        if has_master {
            let r = self.state.vault.borrow_mut().unlock(&password);
            match r {
                Ok(()) => {
                    SessionManager::login(&self.state.session);
                    self.update_view();
                    self.notify_auth_changed();
                }
                Err(ashypass_core::Error::InvalidMasterPassword) => {
                    self.show_auth_error(tr!("Incorrect master password"));
                }
                Err(e) => {
                    self.show_auth_error(&format!("{}: {e}", tr!("Failed to unlock vault")));
                }
            }
        } else {
            let confirm = self.confirm_entry.text().to_string();
            if password.chars().count() < MIN_MASTER_PASSWORD_LENGTH {
                self.show_auth_error(&format!(
                    "{} {} {}",
                    tr!("Password must be at least"),
                    MIN_MASTER_PASSWORD_LENGTH,
                    tr!("characters")
                ));
                return;
            }
            if password != confirm {
                self.show_auth_error(tr!("Passwords do not match"));
                return;
            }
            match self.state.vault.borrow_mut().set_master_password(&password) {
                Ok(()) => {
                    let mut settings = Settings::load();
                    settings.quick_unlock = None;
                    let _ = settings.save();
                    SessionManager::login(&self.state.session);
                    self.update_view();
                    self.notify_auth_changed();
                }
                Err(e) => {
                    self.show_auth_error(&format!(
                        "{}: {e}",
                        tr!("Failed to setup master password")
                    ));
                }
            }
        }
    }

    fn load_passwords(self: &Rc<Self>, search: Option<&str>) {
        if !self.can_show_vault_data() {
            return;
        }
        self.main_stack.set_visible_child_name("vault");
        self.stop_totp_timer();
        self.totp_widgets.borrow_mut().clear();
        clear_list_box(&self.list_box);
        let ui_settings = Settings::load();
        self.apply_vault_list_density(ui_settings.compact_vault_list);

        let mode = self.view_mode.get();
        let selected_category = if mode == ViewMode::All {
            self.get_selected_category()
        } else {
            None
        };
        if mode == ViewMode::All {
            self.update_category_filter(selected_category.as_deref());
        } else {
            self.category_bar.set_visible(false);
        }

        let mut entries = match self
            .state
            .vault
            .borrow()
            .list_filtered(search, selected_category.as_deref())
        {
            Ok(v) => v,
            Err(e) => {
                log::error!("vault.list failed: {e}");
                return;
            }
        };

        if mode == ViewMode::Favorites {
            entries.retain(|p| p.favorite);
        } else if mode == ViewMode::Groups {
            self.load_grouped(entries, search.is_some(), &ui_settings);
            return;
        }

        if entries.is_empty() {
            let (icon, title, desc) = match mode {
                ViewMode::Favorites => (
                    "emblem-favorite-symbolic",
                    tr!("No Favorites"),
                    tr!("Mark passwords as favorite with the star icon"),
                ),
                _ if search.is_some() => (
                    "edit-find-symbolic",
                    tr!("No Results"),
                    tr!("No passwords match your search"),
                ),
                _ => (
                    "dialog-password-symbolic",
                    tr!("No Passwords Stored"),
                    tr!("Add your first password using the + button"),
                ),
            };
            self.empty_status.set_icon_name(Some(icon));
            self.empty_status.set_title(title);
            self.empty_status.set_description(Some(desc));
            self.content_stack.set_visible_child_name("empty");
            return;
        }

        self.content_stack.set_visible_child_name("list");
        let nextcloud_synced_ids = self.nextcloud_synced_ids();
        for entry in entries {
            let row = self.create_password_row(
                &entry,
                ui_settings.show_sync_badges && nextcloud_synced_ids.contains(&entry.id),
                ui_settings.show_favicons,
            );
            self.list_box.append(&row);
        }
        self.start_totp_timer();
    }

    fn load_grouped(
        self: &Rc<Self>,
        entries: Vec<PasswordEntry>,
        filtering: bool,
        ui_settings: &Settings,
    ) {
        use std::collections::BTreeMap;
        let mut groups: BTreeMap<String, Vec<PasswordEntry>> = BTreeMap::new();
        let mut uncategorized: Vec<PasswordEntry> = Vec::new();
        if !filtering {
            for folder in self.state.vault.borrow().categories().unwrap_or_default() {
                groups.entry(folder).or_default();
            }
        }
        for p in entries {
            match p.category.clone().filter(|s| !s.is_empty()) {
                Some(cat) => groups.entry(cat).or_default().push(p),
                None => uncategorized.push(p),
            }
        }

        if groups.is_empty() && uncategorized.is_empty() {
            if filtering {
                self.empty_status.set_icon_name(Some("edit-find-symbolic"));
                self.empty_status.set_title(tr!("No Results"));
                self.empty_status
                    .set_description(Some(tr!("No passwords match your search")));
                self.content_stack.set_visible_child_name("empty");
            } else {
                self.content_stack.set_visible_child_name("list");
                self.add_create_folder_row();
            }
            return;
        }

        self.content_stack.set_visible_child_name("list");
        let nextcloud_synced_ids = self.nextcloud_synced_ids();
        self.add_create_folder_row();

        for (cat, items) in groups {
            let expanded = self.expanded_folders.borrow().contains(&cat);
            let items_empty = items.is_empty();
            let row = adw::ActionRow::builder()
                .title(&cat)
                .subtitle(format!("{}", items.len()))
                .activatable(true)
                .build();
            let folder_icon = gtk::Image::from_icon_name("folder-symbolic");
            folder_icon.add_css_class("folder-heading-icon");
            row.add_prefix(&folder_icon);
            row.add_suffix(&gtk::Image::from_icon_name(if expanded {
                "pan-down-symbolic"
            } else {
                "pan-end-symbolic"
            }));
            {
                let inner_cl = self.clone();
                let cat = cat.clone();
                row.connect_activated(move |_| {
                    inner_cl.toggle_group_folder(&cat);
                });
            }
            self.list_box.append(&row);

            if expanded {
                for e in items {
                    let row = self.create_password_row(
                        &e,
                        ui_settings.show_sync_badges && nextcloud_synced_ids.contains(&e.id),
                        ui_settings.show_favicons,
                    );
                    self.list_box.append(&row);
                }
                if items_empty {
                    let empty = adw::ActionRow::builder()
                        .title(tr!("No Passwords Stored"))
                        .sensitive(false)
                        .build();
                    self.list_box.append(&empty);
                }
            }
        }

        if !uncategorized.is_empty() {
            let key = String::new();
            let expanded = self.expanded_folders.borrow().contains(&key);
            let row = adw::ActionRow::builder()
                .title(tr!("Uncategorized"))
                .subtitle(format!("{}", uncategorized.len()))
                .activatable(true)
                .build();
            let folder_icon = gtk::Image::from_icon_name("folder-symbolic");
            folder_icon.add_css_class("folder-heading-icon");
            row.add_prefix(&folder_icon);
            row.add_suffix(&gtk::Image::from_icon_name(if expanded {
                "pan-down-symbolic"
            } else {
                "pan-end-symbolic"
            }));
            {
                let inner_cl = self.clone();
                row.connect_activated(move |_| {
                    inner_cl.toggle_group_folder("");
                });
            }
            self.list_box.append(&row);

            if expanded {
                for e in uncategorized {
                    let row = self.create_password_row(
                        &e,
                        ui_settings.show_sync_badges && nextcloud_synced_ids.contains(&e.id),
                        ui_settings.show_favicons,
                    );
                    self.list_box.append(&row);
                }
            }
        }

        self.start_totp_timer();
    }

    fn add_create_folder_row(self: &Rc<Self>) {
        let row = adw::ActionRow::builder()
            .title(tr!("Folder"))
            .subtitle(tr!(
                "Set a category on entries to organize them into groups"
            ))
            .activatable(true)
            .build();
        let icon = gtk::Image::from_icon_name("folder-new-symbolic");
        icon.add_css_class("folder-heading-icon");
        row.add_prefix(&icon);
        row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
        {
            let inner_cl = self.clone();
            row.connect_activated(move |_| {
                inner_cl.show_add_folder_dialog();
            });
        }
        self.list_box.append(&row);
    }

    fn current_search(&self) -> Option<String> {
        let text = self.search_entry.text().trim().to_string();
        if text.is_empty() {
            None
        } else {
            Some(text)
        }
    }

    fn reload_current_filter(self: &Rc<Self>) {
        let scroll_y = self.list_scrolled.vadjustment().value();
        let search = self.current_search();
        self.load_passwords(search.as_deref());
        self.restore_scroll(scroll_y);
    }

    fn restore_scroll(&self, value: f64) {
        let adjustment = self.list_scrolled.vadjustment();
        glib::idle_add_local_once(move || {
            let lower = adjustment.lower();
            let max = (adjustment.upper() - adjustment.page_size()).max(lower);
            adjustment.set_value(value.clamp(lower, max));
        });
    }

    fn toggle_group_folder(self: &Rc<Self>, folder: &str) {
        {
            let mut expanded = self.expanded_folders.borrow_mut();
            if !expanded.insert(folder.to_string()) {
                expanded.remove(folder);
            }
        }
        self.reload_current_filter();
        SessionManager::on_activity(&self.state.session);
    }

    fn show_add_folder_dialog(self: &Rc<Self>) {
        let dialog = adw::AlertDialog::builder()
            .heading(tr!("Folder"))
            .default_response("save")
            .close_response("cancel")
            .build();
        dialog.add_response("cancel", tr!("Cancel"));
        dialog.add_response("save", tr!("Save"));
        dialog.set_response_appearance("save", adw::ResponseAppearance::Suggested);

        let folder_entry = adw::EntryRow::builder().title(tr!("Folder")).build();
        let list = gtk::ListBox::builder()
            .selection_mode(gtk::SelectionMode::None)
            .build();
        list.add_css_class("boxed-list");
        list.append(&folder_entry);
        dialog.set_extra_child(Some(&list));

        let inner_cl = self.clone();
        dialog.connect_response(None, move |dlg, response| {
            if response != "save" {
                dlg.close();
                return;
            }
            let name = folder_entry.text().trim().to_string();
            if name.is_empty() {
                folder_entry.add_css_class("error");
                return;
            }
            match inner_cl.state.vault.borrow().create_folder(&name) {
                Ok(_) => {
                    inner_cl.show_toast(&format!("{}: {name}", tr!("Folder")));
                    inner_cl.reload_current_filter();
                    SessionManager::on_activity(&inner_cl.state.session);
                    dlg.close();
                }
                Err(e) => {
                    inner_cl.show_toast(&format!("{}: {e}", tr!("Error saving password")));
                }
            }
        });
        dialog.present(Some(self.toast.upcast_ref::<gtk::Widget>()));
    }

    fn nextcloud_synced_ids(&self) -> HashSet<i64> {
        self.state
            .vault
            .borrow()
            .nc_all_mappings()
            .map(|items| items.into_iter().map(|m| m.entry_id).collect())
            .unwrap_or_default()
    }

    fn apply_vault_list_density(&self, compact: bool) {
        let margin = if compact { 6 } else { 12 };
        self.list_box.set_margin_top(margin);
        self.list_box.set_margin_bottom(margin);
        self.list_box.set_margin_start(margin);
        self.list_box.set_margin_end(margin);
    }

    fn create_password_row(
        self: &Rc<Self>,
        entry: &PasswordEntry,
        nextcloud_synced: bool,
        show_favicons: bool,
    ) -> adw::ActionRow {
        let row = adw::ActionRow::builder().title(&entry.title).build();

        let mut parts: Vec<String> = Vec::new();
        if let Some(u) = entry.username.as_deref().filter(|s| !s.is_empty()) {
            parts.push(u.to_string());
        }
        if let Some(u) = entry.url.as_deref().filter(|s| !s.is_empty()) {
            parts.push(u.to_string());
        }
        if let Some(c) = entry.category.as_deref().filter(|s| !s.is_empty()) {
            parts.push(format!("{}: {c}", tr!("Folder")));
        }
        if !parts.is_empty() {
            let escaped = glib::markup_escape_text(&parts.join(" • "));
            row.set_subtitle(&escaped);
        }

        let icon = gtk::Image::new();
        if show_favicons {
            crate::favicons::apply(&icon, entry.url.as_deref(), 32);
        } else {
            icon.set_pixel_size(32);
            icon.set_icon_name(Some("dialog-password-symbolic"));
        }
        row.add_prefix(&icon);

        if nextcloud_synced {
            let badge = gtk::Label::builder()
                .label("Nextcloud")
                .tooltip_text(tr!("Nextcloud Passwords"))
                .valign(gtk::Align::Center)
                .build();
            badge.add_css_class("caption");
            badge.add_css_class("sync-provider-badge");
            row.add_suffix(&badge);
        }

        // Favorite toggle
        let fav_btn = gtk::Button::builder()
            .valign(gtk::Align::Center)
            .tooltip_text(tr!("Favorite"))
            .build();
        fav_btn.add_css_class("flat");
        set_favorite_button_state(&fav_btn, entry.favorite);
        {
            let inner_cl = self.clone();
            let id = entry.id;
            fav_btn.connect_clicked(move |btn| inner_cl.toggle_favorite(id, btn));
        }
        row.add_suffix(&fav_btn);

        // Copy button
        let copy_btn = gtk::Button::builder()
            .icon_name("edit-copy-symbolic")
            .valign(gtk::Align::Center)
            .tooltip_text(tr!("Copy Password"))
            .build();
        copy_btn.add_css_class("flat");
        {
            let inner_cl = self.clone();
            let id = entry.id;
            copy_btn.connect_clicked(move |_| inner_cl.copy_password(id));
        }
        row.add_suffix(&copy_btn);

        // Edit button
        let edit_btn = gtk::Button::builder()
            .icon_name("document-edit-symbolic")
            .valign(gtk::Align::Center)
            .tooltip_text(tr!("Edit"))
            .build();
        edit_btn.add_css_class("flat");
        {
            let inner_cl = self.clone();
            let id = entry.id;
            edit_btn.connect_clicked(move |_| inner_cl.show_edit_dialog(id));
        }
        row.add_suffix(&edit_btn);

        // History button
        let history_btn = gtk::Button::builder()
            .icon_name("document-open-recent-symbolic")
            .valign(gtk::Align::Center)
            .tooltip_text(tr!("Password history"))
            .build();
        history_btn.add_css_class("flat");
        {
            let inner_cl = self.clone();
            let id = entry.id;
            history_btn.connect_clicked(move |_| inner_cl.show_history_dialog(id));
        }
        row.add_suffix(&history_btn);

        // Delete button
        let del_btn = gtk::Button::builder()
            .icon_name("user-trash-symbolic")
            .valign(gtk::Align::Center)
            .tooltip_text(tr!("Delete"))
            .build();
        del_btn.add_css_class("flat");
        {
            let inner_cl = self.clone();
            let id = entry.id;
            del_btn.connect_clicked(move |_| inner_cl.confirm_delete(id));
        }
        row.add_suffix(&del_btn);

        row
    }

    fn get_selected_category(&self) -> Option<String> {
        let idx = self.category_dropdown.selected();
        if idx == 0 {
            return None;
        }
        let model = self.category_model.borrow();
        let s = model.string(idx)?;
        let s = s.to_string();
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    }

    fn update_category_filter(&self, selected: Option<&str>) {
        self.updating_categories.set(true);
        let cats = self.state.vault.borrow().categories().unwrap_or_default();

        if *self.category_names.borrow() != cats {
            let mut items: Vec<&str> = Vec::with_capacity(1 + cats.len());
            items.push(tr!("All"));
            for c in &cats {
                items.push(c.as_str());
            }
            let model = gtk::StringList::new(&items);
            self.category_dropdown.set_model(Some(&model));
            *self.category_model.borrow_mut() = model;
            *self.category_names.borrow_mut() = cats.clone();
        }

        let selected_idx = selected
            .and_then(|name| cats.iter().position(|cat| cat == name))
            .map(|idx| (idx + 1) as u32)
            .unwrap_or(0);
        if self.category_dropdown.selected() != selected_idx {
            self.category_dropdown.set_selected(selected_idx);
        }
        self.category_bar.set_visible(!cats.is_empty());
        self.updating_categories.set(false);
    }

    fn copy_password(self: &Rc<Self>, id: i64) {
        let pw = {
            let v = self.state.vault.borrow();
            match v.get(id) {
                Ok(Some(e)) => e.password,
                _ => None,
            }
        };
        if let Some(pw) = pw {
            copy_to_clipboard(&pw);
            self.show_toast(tr!("Password copied to clipboard"));
            SessionManager::on_activity(&self.state.session);
        }
    }

    fn toggle_favorite(self: &Rc<Self>, id: i64, btn: &gtk::Button) {
        if let Ok(new_state) = self.state.vault.borrow().toggle_favorite(id) {
            set_favorite_button_state(btn, new_state);
        }
        SessionManager::on_activity(&self.state.session);
    }

    fn show_edit_dialog(self: &Rc<Self>, id: i64) {
        let entry = match self.state.vault.borrow().get(id) {
            Ok(Some(e)) => e,
            _ => return,
        };
        show_password_dialog(self, Some(entry));
        SessionManager::on_activity(&self.state.session);
    }

    fn show_history_dialog(self: &Rc<Self>, id: i64) {
        let entry_title = self
            .state
            .vault
            .borrow()
            .get(id)
            .ok()
            .flatten()
            .map(|e| e.title)
            .unwrap_or_default();
        let history = match self.state.vault.borrow().password_history(id) {
            Ok(h) => h,
            Err(e) => {
                self.show_toast(&format!("{}: {e}", tr!("Failed to read history")));
                return;
            }
        };

        let dialog = adw::Dialog::builder()
            .title(tr!("Password History"))
            .content_width(520)
            .content_height(420)
            .build();

        let toolbar = adw::ToolbarView::new();
        toolbar.add_top_bar(&adw::HeaderBar::new());

        let page = adw::PreferencesPage::new();
        let group = adw::PreferencesGroup::builder().title(&entry_title).build();

        if history.is_empty() {
            let row = adw::ActionRow::builder()
                .title(tr!("No previous passwords recorded."))
                .subtitle(tr!(
                    "Older versions appear here after the password is changed."
                ))
                .build();
            group.add(&row);
        } else {
            for h in &history {
                let when = chrono::DateTime::<chrono::Utc>::from_timestamp(h.changed_at, 0)
                    .map(|dt| dt.format("%Y-%m-%d %H:%M UTC").to_string())
                    .unwrap_or_else(|| format!("ts={}", h.changed_at));
                let row = adw::ActionRow::builder()
                    .title(mask_password(&h.password))
                    .subtitle(&when)
                    .build();
                let copy_btn = gtk::Button::builder()
                    .icon_name("edit-copy-symbolic")
                    .tooltip_text(tr!("Copy"))
                    .valign(gtk::Align::Center)
                    .build();
                copy_btn.add_css_class("flat");
                {
                    let pw = h.password.clone();
                    let self_cl = self.clone();
                    copy_btn.connect_clicked(move |_| {
                        copy_to_clipboard(&pw);
                        self_cl.show_toast(tr!("Password copied to clipboard"));
                    });
                }
                row.add_suffix(&copy_btn);
                group.add(&row);
            }
        }

        page.add(&group);

        if !history.is_empty() {
            let actions_group = adw::PreferencesGroup::new();
            let clear_btn = gtk::Button::with_label(tr!("Clear history"));
            clear_btn.add_css_class("destructive-action");
            clear_btn.set_halign(gtk::Align::End);
            clear_btn.set_margin_top(8);
            {
                let inner_cl = self.clone();
                let dialog_cl = dialog.clone();
                clear_btn.connect_clicked(move |_| {
                    if let Err(e) = inner_cl.state.vault.borrow().clear_password_history(id) {
                        inner_cl.show_toast(&format!("{e}"));
                    } else {
                        inner_cl.show_toast(tr!("History cleared"));
                        dialog_cl.close();
                    }
                });
            }
            actions_group.add(&clear_btn);
            page.add(&actions_group);
        }

        toolbar.set_content(Some(&page));
        dialog.set_child(Some(&toolbar));
        dialog.present(Some(&self.toast));
        SessionManager::on_activity(&self.state.session);
    }

    fn confirm_delete(self: &Rc<Self>, id: i64) {
        let entry = match self.state.vault.borrow().get(id) {
            Ok(Some(e)) => e,
            _ => return,
        };
        let trash_enabled = ashypass_core::settings::Settings::load().trash_retention_days > 0;
        let body = if trash_enabled {
            format!(
                "{} '{}'?",
                tr!("Are you sure you want to delete"),
                entry.title
            )
        } else {
            format!(
                "{} '{}'? {}",
                tr!("Are you sure you want to delete"),
                entry.title,
                tr!("This action cannot be undone.")
            )
        };

        let dialog = adw::AlertDialog::builder()
            .heading(tr!("Delete Password?"))
            .body(&body)
            .default_response("cancel")
            .close_response("cancel")
            .build();
        dialog.add_response("cancel", tr!("Cancel"));
        dialog.add_response("delete", tr!("Delete"));
        dialog.set_response_appearance("delete", adw::ResponseAppearance::Destructive);

        let inner_cl = self.clone();
        dialog.connect_response(None, move |dlg, response| {
            if response == "delete" {
                let deleted = if trash_enabled {
                    inner_cl.state.vault.borrow().delete(id)
                } else {
                    inner_cl.state.vault.borrow().delete_permanent(id)
                };
                if let Ok(true) = deleted {
                    inner_cl.show_toast(if trash_enabled {
                        tr!("Password deleted")
                    } else {
                        tr!("Permanently deleted")
                    });
                    inner_cl.reload_current_filter();
                    SessionManager::on_activity(&inner_cl.state.session);
                }
            }
            dlg.close();
        });
        dialog.present(Some(self.toast.upcast_ref::<gtk::Widget>()));
    }

    // ---- TOTP timer ----

    fn start_totp_timer(self: &Rc<Self>) {
        self.stop_totp_timer();
        if self.totp_widgets.borrow().is_empty() {
            return;
        }
        self.update_totp_displays();
        let inner_weak = Rc::downgrade(self);
        let id = glib::timeout_add_seconds_local(1, move || {
            let Some(inner) = inner_weak.upgrade() else {
                return glib::ControlFlow::Break;
            };
            inner.update_totp_displays();
            glib::ControlFlow::Continue
        });
        *self.totp_timer_id.borrow_mut() = Some(id);
    }

    fn stop_totp_timer(&self) {
        if let Some(id) = self.totp_timer_id.borrow_mut().take() {
            id.remove();
        }
    }

    fn cancel_pending_search_reload(&self) {
        if let Some(id) = self.search_reload_id.borrow_mut().take() {
            id.remove();
        }
    }

    fn update_totp_displays(&self) {
        let now = chrono::Utc::now().timestamp() as u64;
        let widgets = self.totp_widgets.borrow();
        for (label, progress, id, algo_str, digits, period) in widgets.iter() {
            // Fetch secret each tick (decrypts via vault.get). Cheap since AES-GCM is fast.
            let secret = {
                let v = self.state.vault.borrow();
                match v.get(*id) {
                    Ok(Some(e)) => e.totp_secret,
                    _ => None,
                }
            };
            let Some(secret) = secret else {
                label.set_text("------");
                progress.set_fraction(0.0);
                continue;
            };
            let algo = Algorithm::parse(algo_str).unwrap_or(Algorithm::Sha1);
            match generate_totp(&secret, algo, *digits, *period, now) {
                Ok(code) => {
                    label.set_text(&code);
                    let rem = remaining_seconds(*period, now);
                    progress.set_fraction(rem as f64 / *period as f64);
                }
                Err(_) => {
                    label.set_text("------");
                    progress.set_fraction(0.0);
                }
            }
        }
    }
}

// ============================================================================
// Add/Edit dialog
// ============================================================================

fn show_password_dialog(inner: &Rc<Inner>, entry: Option<PasswordEntry>) {
    let is_edit = entry.is_some();
    let dialog = adw::AlertDialog::builder()
        .heading(if is_edit {
            tr!("Edit Password")
        } else {
            tr!("Add Password")
        })
        .default_response("save")
        .close_response("cancel")
        .build();
    dialog.add_response("cancel", tr!("Cancel"));
    dialog.add_response("save", tr!("Save"));
    dialog.set_response_appearance("save", adw::ResponseAppearance::Suggested);

    let form = adw::PreferencesGroup::new();

    let title_entry = adw::EntryRow::builder().title(tr!("Title")).build();
    if let Some(e) = entry.as_ref() {
        title_entry.set_text(&e.title);
    }
    form.add(&title_entry);

    let username_entry = adw::EntryRow::builder().title(tr!("Username")).build();
    if let Some(u) = entry.as_ref().and_then(|e| e.username.clone()) {
        username_entry.set_text(&u);
    }
    form.add(&username_entry);

    let password_entry = adw::PasswordEntryRow::builder()
        .title(tr!("Password"))
        .build();
    if let Some(p) = entry.as_ref().and_then(|e| e.password.clone()) {
        password_entry.set_text(&p);
    }

    // Generator MenuButton suffix
    let gen_btn = gtk::MenuButton::builder()
        .icon_name("document-new-symbolic")
        .tooltip_text(tr!("Generate Password"))
        .valign(gtk::Align::Center)
        .build();
    gen_btn.add_css_class("flat");
    let menu = gio::Menu::new();
    menu.append(Some(tr!("Strong Password")), Some("pwd.gen-strong"));
    menu.append(Some(tr!("Passphrase")), Some("pwd.gen-passphrase"));
    menu.append(Some(tr!("PIN Code")), Some("pwd.gen-pin"));
    gen_btn.set_menu_model(Some(&menu));

    let action_group = gio::SimpleActionGroup::new();
    let act_strong = gio::SimpleAction::new("gen-strong", None);
    {
        let pe = password_entry.clone();
        let inner_cl = inner.clone();
        act_strong.connect_activate(move |_, _| {
            if let Ok(pw) = generate_password(&PasswordConfig::default()) {
                pe.set_text(&pw);
                inner_cl.show_toast(tr!("Password generated"));
            }
        });
    }
    action_group.add_action(&act_strong);

    let act_pass = gio::SimpleAction::new("gen-passphrase", None);
    {
        let pe = password_entry.clone();
        let inner_cl = inner.clone();
        act_pass.connect_activate(move |_, _| {
            let pw = generate_passphrase(4, "-", true, true);
            pe.set_text(&pw);
            inner_cl.show_toast(tr!("Password generated"));
        });
    }
    action_group.add_action(&act_pass);

    let act_pin = gio::SimpleAction::new("gen-pin", None);
    {
        let pe = password_entry.clone();
        let inner_cl = inner.clone();
        act_pin.connect_activate(move |_, _| {
            let pw = generate_pin(6);
            pe.set_text(&pw);
            inner_cl.show_toast(tr!("Password generated"));
        });
    }
    action_group.add_action(&act_pin);

    gen_btn.insert_action_group("pwd", Some(&action_group));
    password_entry.add_suffix(&gen_btn);
    form.add(&password_entry);

    let url_entry = adw::EntryRow::builder().title(tr!("URL")).build();
    if let Some(u) = entry.as_ref().and_then(|e| e.url.clone()) {
        url_entry.set_text(&u);
    }
    form.add(&url_entry);

    let notes_entry = adw::EntryRow::builder().title(tr!("Notes")).build();
    if let Some(n) = entry.as_ref().and_then(|e| e.notes.clone()) {
        notes_entry.set_text(&n);
    }
    form.add(&notes_entry);

    let category_entry = adw::EntryRow::builder().title(tr!("Category")).build();
    if let Some(c) = entry.as_ref().and_then(|e| e.category.clone()) {
        category_entry.set_text(&c);
    }
    form.add(&category_entry);

    let tags_entry = adw::EntryRow::builder()
        .title(tr!("Tags (comma-separated)"))
        .build();
    if let Some(eid) = entry.as_ref().map(|e| e.id) {
        let current = inner.state.vault.borrow().tags_of(eid).unwrap_or_default();
        tags_entry.set_text(&current.join(", "));
    }
    form.add(&tags_entry);

    // TOTP group
    let totp_group = adw::PreferencesGroup::builder()
        .title(tr!("Two-Factor Authentication"))
        .build();

    let totp_entry = adw::PasswordEntryRow::builder()
        .title(tr!("TOTP Secret (Base32)"))
        .build();
    if let Some(s) = entry.as_ref().and_then(|e| e.totp_secret.clone()) {
        totp_entry.set_text(&s);
    }
    totp_group.add(&totp_entry);

    let algo_model = gtk::StringList::new(&["SHA1", "SHA256", "SHA512"]);
    let totp_algo_row = adw::ComboRow::builder()
        .title(tr!("Algorithm"))
        .model(&algo_model)
        .build();
    if let Some(e) = entry.as_ref() {
        let idx = match e.totp_algorithm.as_str() {
            "SHA256" => 1,
            "SHA512" => 2,
            _ => 0,
        };
        totp_algo_row.set_selected(idx);
    }
    totp_group.add(&totp_algo_row);

    let digits_adj = gtk::Adjustment::new(
        entry.as_ref().map(|e| e.totp_digits as f64).unwrap_or(6.0),
        6.0,
        8.0,
        2.0,
        2.0,
        0.0,
    );
    let totp_digits_row = adw::SpinRow::builder()
        .title(tr!("Digits"))
        .adjustment(&digits_adj)
        .build();
    totp_group.add(&totp_digits_row);

    let period_adj = gtk::Adjustment::new(
        entry.as_ref().map(|e| e.totp_period as f64).unwrap_or(30.0),
        15.0,
        60.0,
        15.0,
        15.0,
        0.0,
    );
    let totp_period_row = adw::SpinRow::builder()
        .title(tr!("Period (seconds)"))
        .adjustment(&period_adj)
        .build();
    totp_group.add(&totp_period_row);

    let content = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(12)
        .build();
    content.set_size_request(500, -1);
    content.append(&form);
    content.append(&totp_group);

    // Attachments: only available for entries that already exist on disk.
    // For new entries the user is asked to save first.
    if let Some(eid) = entry.as_ref().map(|e| e.id) {
        let attach_group = adw::PreferencesGroup::builder()
            .title(tr!("Attachments"))
            .description(tr!(
                "Encrypted with your master key. Stored inside the vault."
            ))
            .build();

        let add_btn = gtk::Button::builder()
            .icon_name("list-add-symbolic")
            .tooltip_text(tr!("Add file"))
            .valign(gtk::Align::Center)
            .build();
        add_btn.add_css_class("flat");
        attach_group.set_header_suffix(Some(&add_btn));

        let render: RenderSlot = Rc::new(RefCell::new(None));
        let attachment_rows: Rc<RefCell<Vec<gtk::Widget>>> = Rc::new(RefCell::new(Vec::new()));
        let attach_group_cl = attach_group.clone();
        let inner_for_render = inner.clone();
        let render_fn: Rc<dyn Fn()> = Rc::new({
            let render_slot = render.clone();
            let attachment_rows = attachment_rows.clone();
            move || {
                // Clear existing rows; we re-add them from a fresh listing.
                for child in attachment_rows.borrow_mut().drain(..) {
                    attach_group_cl.remove(&child);
                }
                let entries = inner_for_render
                    .state
                    .vault
                    .borrow()
                    .list_attachments(eid)
                    .unwrap_or_default();
                if entries.is_empty() {
                    let row = adw::ActionRow::builder()
                        .title(tr!("No attachments"))
                        .subtitle(tr!("Click the + button to add a file."))
                        .sensitive(false)
                        .build();
                    attach_group_cl.add(&row);
                    attachment_rows
                        .borrow_mut()
                        .push(row.upcast::<gtk::Widget>());
                    return;
                }
                for att in entries {
                    let row = adw::ActionRow::builder()
                        .title(&att.filename)
                        .subtitle(format!(
                            "{} · {}",
                            human_size(att.size_bytes),
                            att.mime_type
                                .as_deref()
                                .unwrap_or("application/octet-stream")
                        ))
                        .build();

                    let save_btn = gtk::Button::builder()
                        .icon_name("document-save-symbolic")
                        .tooltip_text(tr!("Save as…"))
                        .valign(gtk::Align::Center)
                        .build();
                    save_btn.add_css_class("flat");
                    {
                        let inner_cl = inner_for_render.clone();
                        let att_id = att.id;
                        let filename = att.filename.clone();
                        save_btn.connect_clicked(move |btn| {
                            let parent = btn.root().and_then(|r| r.downcast::<gtk::Window>().ok());
                            let dialog = gtk::FileDialog::builder()
                                .title(tr!("Save attachment"))
                                .initial_name(&filename)
                                .modal(true)
                                .build();
                            let inner_cl = inner_cl.clone();
                            dialog.save(
                                parent.as_ref(),
                                None::<&gio::Cancellable>,
                                move |result| {
                                    let Ok(file) = result else { return };
                                    let Some(path) = file.path() else { return };
                                    match inner_cl.state.vault.borrow().get_attachment(att_id) {
                                        Ok(Some((_info, data))) => {
                                            match std::fs::write(&path, &data) {
                                                Ok(_) => {
                                                    inner_cl.show_toast(tr!("Attachment saved"))
                                                }
                                                Err(e) => inner_cl.show_toast(&format!(
                                                    "{}: {e}",
                                                    tr!("Save failed")
                                                )),
                                            }
                                        }
                                        Ok(None) => {
                                            inner_cl.show_toast(tr!("Attachment not found"))
                                        }
                                        Err(e) => inner_cl
                                            .show_toast(&format!("{}: {e}", tr!("Decrypt failed"))),
                                    }
                                },
                            );
                        });
                    }
                    row.add_suffix(&save_btn);

                    let del_btn = gtk::Button::builder()
                        .icon_name("user-trash-symbolic")
                        .tooltip_text(tr!("Delete attachment"))
                        .valign(gtk::Align::Center)
                        .build();
                    del_btn.add_css_class("flat");
                    del_btn.add_css_class("destructive-action");
                    {
                        let inner_cl = inner_for_render.clone();
                        let att_id = att.id;
                        let render_slot = render_slot.clone();
                        del_btn.connect_clicked(move |_| {
                            let _ = inner_cl.state.vault.borrow().delete_attachment(att_id);
                            inner_cl.show_toast(tr!("Attachment deleted"));
                            if let Some(r) = render_slot.borrow().as_ref() {
                                r();
                            }
                        });
                    }
                    row.add_suffix(&del_btn);

                    attach_group_cl.add(&row);
                    attachment_rows
                        .borrow_mut()
                        .push(row.upcast::<gtk::Widget>());
                }
            }
        });
        *render.borrow_mut() = Some(render_fn.clone());
        render_fn();

        {
            let inner_cl = inner.clone();
            let render_slot = render.clone();
            add_btn.connect_clicked(move |btn| {
                let parent = btn.root().and_then(|r| r.downcast::<gtk::Window>().ok());
                let dialog = gtk::FileDialog::builder()
                    .title(tr!("Add attachment"))
                    .modal(true)
                    .build();
                let inner_cl = inner_cl.clone();
                let render_slot = render_slot.clone();
                dialog.open(parent.as_ref(), None::<&gio::Cancellable>, move |result| {
                    let Ok(file) = result else { return };
                    let Some(path) = file.path() else { return };
                    let data = match std::fs::read(&path) {
                        Ok(d) => d,
                        Err(e) => {
                            inner_cl.show_toast(&format!("{}: {e}", tr!("Read failed")));
                            return;
                        }
                    };
                    let filename = path
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("attachment")
                        .to_string();
                    let mime = mime_guess_from_ext(&filename);
                    match inner_cl.state.vault.borrow().add_attachment(
                        eid,
                        &filename,
                        mime.as_deref(),
                        &data,
                    ) {
                        Ok(_) => {
                            inner_cl.show_toast(tr!("Attachment added"));
                            if let Some(r) = render_slot.borrow().as_ref() {
                                r();
                            }
                        }
                        Err(e) => {
                            inner_cl.show_toast(&format!("{}: {e}", tr!("Save failed")));
                        }
                    }
                });
            });
        }

        content.append(&attach_group);
    }

    dialog.set_extra_child(Some(&content));

    let entry_id = entry.as_ref().map(|e| e.id);
    let inner_cl = inner.clone();
    let title_entry_cl = title_entry.clone();
    let password_entry_cl = password_entry.clone();
    dialog.connect_response(None, move |dlg, response| {
        if response != "save" {
            dlg.close();
            return;
        }

        let title = title_entry_cl.text().trim().to_string();
        let password = password_entry_cl.text().to_string();
        let mut has_error = false;
        if title.is_empty() {
            title_entry_cl.add_css_class("error");
            has_error = true;
        } else {
            title_entry_cl.remove_css_class("error");
        }
        if password.is_empty() {
            password_entry_cl.add_css_class("error");
            has_error = true;
        } else {
            password_entry_cl.remove_css_class("error");
        }
        if has_error {
            return;
        }

        let username = trim_to_opt(&username_entry.text());
        let url = trim_to_opt(&url_entry.text());
        let notes = trim_to_opt(&notes_entry.text());
        let category = trim_to_opt(&category_entry.text());
        let totp_secret = trim_to_opt(&totp_entry.text());

        let algo = match totp_algo_row.selected() {
            1 => "SHA256",
            2 => "SHA512",
            _ => "SHA1",
        }
        .to_string();
        let digits = totp_digits_row.value() as u8;
        let period = totp_period_row.value() as u32;

        let tag_list: Vec<String> = tags_entry
            .text()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let result = if let Some(id) = entry_id {
            inner_cl
                .state
                .vault
                .borrow()
                .update(
                    id,
                    UpdateEntry {
                        title: Some(title),
                        username: Some(username.unwrap_or_default()),
                        password: Some(password),
                        notes: Some(notes),
                        url: Some(url),
                        totp_secret: Some(totp_secret),
                        totp_algorithm: Some(algo),
                        totp_digits: Some(digits),
                        totp_period: Some(period),
                        category: Some(category),
                    },
                )
                .map(|_| Some(id))
        } else {
            inner_cl
                .state
                .vault
                .borrow()
                .add(NewEntry {
                    title,
                    username,
                    password,
                    url,
                    notes,
                    totp_secret,
                    totp_algorithm: Some(algo),
                    totp_digits: Some(digits),
                    totp_period: Some(period),
                    category,
                })
                .map(Some)
        };

        match result {
            Ok(maybe_id) => {
                if let Some(id) = maybe_id {
                    let _ = inner_cl.state.vault.borrow().set_tags(id, &tag_list);
                }
                inner_cl.show_toast(if entry_id.is_some() {
                    tr!("Password updated")
                } else {
                    tr!("Password added")
                });
                inner_cl.reload_current_filter();
                SessionManager::on_activity(&inner_cl.state.session);
                dlg.close();
            }
            Err(e) => {
                inner_cl.show_toast(&format!("{}: {e}", tr!("Error saving password")));
            }
        }
    });

    dialog.present(Some(inner.toast.upcast_ref::<gtk::Widget>()));
}

// ============================================================================
// Helpers
// ============================================================================

fn set_favorite_button_state(btn: &gtk::Button, favorite: bool) {
    btn.set_icon_name(if favorite {
        "starred-symbolic"
    } else {
        "non-starred-symbolic"
    });
    btn.remove_css_class(if favorite {
        "favorite-inactive"
    } else {
        "favorite-active"
    });
    btn.add_css_class(if favorite {
        "favorite-active"
    } else {
        "favorite-inactive"
    });
}

fn clear_list_box(lb: &gtk::ListBox) {
    while let Some(row) = lb.first_child() {
        lb.remove(&row);
    }
}

fn trim_to_opt(s: &glib::GString) -> Option<String> {
    let t = s.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

fn mask_password(s: &str) -> String {
    let len = s.chars().count();
    if len == 0 {
        return String::new();
    }
    let visible = len.min(3);
    let masked = "•".repeat(len.saturating_sub(visible));
    let tail: String = s.chars().skip(len.saturating_sub(visible)).collect();
    format!("{masked}{tail}")
}

fn copy_to_clipboard(text: &str) {
    let seconds = ashypass_core::settings::Settings::load().clipboard_clear;
    crate::clipboard::copy(text, seconds);
}

fn human_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

fn mime_guess_from_ext(filename: &str) -> Option<String> {
    let ext = filename
        .rsplit_once('.')
        .map(|x| x.1.to_ascii_lowercase())?;
    Some(
        match ext.as_str() {
            "png" => "image/png",
            "jpg" | "jpeg" => "image/jpeg",
            "gif" => "image/gif",
            "webp" => "image/webp",
            "svg" => "image/svg+xml",
            "pdf" => "application/pdf",
            "txt" => "text/plain",
            "json" => "application/json",
            "xml" => "application/xml",
            "zip" => "application/zip",
            "7z" => "application/x-7z-compressed",
            "tar" => "application/x-tar",
            "gz" => "application/gzip",
            _ => return None,
        }
        .to_string(),
    )
}

use gtk::gio;
