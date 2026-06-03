//! 2FA / TOTP view — task #8.
//!
//! Two pages in a `Gtk.Stack`: a locked-screen unlock page and the live TOTP
//! list. Each row shows a large code label, name + username, a level bar
//! reflecting the remaining seconds, and copy/edit/delete actions.

use crate::session::SessionManager;
use crate::state::SharedState;
use crate::tr;
use adw::prelude::*;
use ashypass_core::db::vault::{NewEntry, PasswordEntry, UpdateEntry};
use ashypass_core::totp::{generate_totp, parse_otpauth, remaining_seconds, Algorithm};
use gtk::glib;
use std::cell::RefCell;
use std::rc::Rc;

pub struct TotpView {
    pub root: gtk::Box,
    pub search_bar: gtk::SearchBar,
    pub search_entry: gtk::SearchEntry,
    inner: Rc<Inner>,
}

struct Inner {
    state: SharedState,
    toast: adw::ToastOverlay,

    main_stack: gtk::Stack,

    // Auth page widgets
    master_entry: adw::PasswordEntryRow,
    auth_error: gtk::Label,

    // TOTP page widgets
    search_entry: gtk::SearchEntry,
    search_reload_id: RefCell<Option<glib::SourceId>>,
    list_box: gtk::ListBox,
    empty_status: adw::StatusPage,
    content_stack: gtk::Stack,

    rows: RefCell<Vec<RowData>>,
    timer_id: RefCell<Option<glib::SourceId>>,

    on_auth_changed: RefCell<Option<Box<dyn Fn()>>>,
}

struct RowData {
    code_label: gtk::Label,
    progress: gtk::LevelBar,
    id: i64,
    secret: String,
    algorithm: String,
    digits: u8,
    period: u32,
}

impl TotpView {
    pub fn new(state: SharedState, toast: adw::ToastOverlay) -> Rc<Self> {
        let root = gtk::Box::new(gtk::Orientation::Vertical, 0);
        root.set_vexpand(true);
        root.set_hexpand(true);

        let main_stack = gtk::Stack::builder()
            .transition_type(gtk::StackTransitionType::Crossfade)
            .transition_duration(300)
            .build();

        let (auth_page, master_entry, auth_error, unlock_btn) = build_auth_page();
        main_stack.add_named(&auth_page, Some("locked"));

        let (totp_page, search_bar, search_entry, list_box, empty_status, content_stack) =
            build_totp_page();
        main_stack.add_named(&totp_page, Some("totp"));

        root.append(&main_stack);

        let inner = Rc::new(Inner {
            state,
            toast,
            main_stack,
            master_entry: master_entry.clone(),
            auth_error: auth_error.clone(),
            search_entry: search_entry.clone(),
            search_reload_id: RefCell::new(None),
            list_box,
            empty_status,
            content_stack,
            rows: RefCell::new(Vec::new()),
            timer_id: RefCell::new(None),
            on_auth_changed: RefCell::new(None),
        });

        // Auth wiring
        {
            let inner_cl = inner.clone();
            unlock_btn.connect_clicked(move |_| inner_cl.on_unlock_clicked());
        }
        {
            let inner_cl = inner.clone();
            master_entry.connect_entry_activated(move |_| inner_cl.on_unlock_clicked());
        }

        // TOTP wiring
        {
            let inner_cl = inner.clone();
            search_entry.connect_search_changed(move |_| {
                if let Some(id) = inner_cl.search_reload_id.borrow_mut().take() {
                    id.remove();
                }
                let inner_weak = Rc::downgrade(&inner_cl);
                let id =
                    glib::timeout_add_local(std::time::Duration::from_millis(150), move || {
                        let Some(inner) = inner_weak.upgrade() else {
                            return glib::ControlFlow::Break;
                        };
                        *inner.search_reload_id.borrow_mut() = None;
                        let text = inner.search_entry.text().trim().to_string();
                        let search = if text.is_empty() { None } else { Some(text) };
                        inner.load_entries(search.as_deref());
                        SessionManager::on_activity(&inner.state.session);
                        glib::ControlFlow::Break
                    });
                *inner_cl.search_reload_id.borrow_mut() = Some(id);
            });
        }
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

    pub fn refresh(&self) {
        let authed = self.inner.state.session.borrow().is_authenticated()
            && self.inner.state.vault.borrow().is_unlocked();
        if !authed {
            self.inner.cancel_pending_search_reload();
            self.inner.stop_timer();
            self.inner.rows.borrow_mut().clear();
            self.inner.main_stack.set_visible_child_name("locked");
            self.inner.master_entry.set_text("");
            self.inner.auth_error.set_visible(false);
            self.focus_auth_field();
            return;
        }
        self.inner.load_entries(None);
    }

    pub fn on_locked(&self) {
        self.inner.cancel_pending_search_reload();
        self.inner.stop_timer();
        self.inner.rows.borrow_mut().clear();
        self.inner.main_stack.set_visible_child_name("locked");
        self.focus_auth_field();
    }

    pub fn set_on_auth_changed(&self, cb: Box<dyn Fn()>) {
        *self.inner.on_auth_changed.borrow_mut() = Some(cb);
    }

    pub fn focus_auth_field(&self) {
        self.inner.focus_auth_field();
    }

    pub fn show_add_dialog(&self) {
        if self.inner.state.session.borrow().is_authenticated()
            && self.inner.state.vault.borrow().is_unlocked()
        {
            self.inner.show_add_dialog();
        }
    }
}

fn build_auth_page() -> (adw::Clamp, adw::PasswordEntryRow, gtk::Label, gtk::Button) {
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

    let icon = gtk::Image::from_icon_name("auth-sim-symbolic");
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
    content.append(&group);

    let auth_error = gtk::Label::new(None);
    auth_error.add_css_class("error");
    auth_error.set_visible(false);
    content.append(&auth_error);

    let unlock_btn = gtk::Button::with_label(tr!("Unlock"));
    unlock_btn.add_css_class("pill");
    unlock_btn.add_css_class("suggested-action");
    unlock_btn.set_halign(gtk::Align::Center);
    content.append(&unlock_btn);

    clamp.set_child(Some(&content));
    (clamp, master_entry, auth_error, unlock_btn)
}

#[allow(clippy::type_complexity)]
fn build_totp_page() -> (
    gtk::Box,
    gtk::SearchBar,
    gtk::SearchEntry,
    gtk::ListBox,
    adw::StatusPage,
    gtk::Stack,
) {
    let main_box = gtk::Box::new(gtk::Orientation::Vertical, 0);

    let search_entry = gtk::SearchEntry::new();
    search_entry.set_placeholder_text(Some(tr!("Search 2FA codes…")));
    let search_bar = gtk::SearchBar::builder()
        .search_mode_enabled(false)
        .child(&search_entry)
        .build();
    search_bar.connect_entry(&search_entry);
    main_box.append(&search_bar);

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
        .icon_name("auth-sim-symbolic")
        .title(tr!("No 2FA Codes"))
        .description(tr!("Add a TOTP secret to an entry to see live codes here."))
        .build();

    let content_stack = gtk::Stack::builder()
        .transition_type(gtk::StackTransitionType::Crossfade)
        .vexpand(true)
        .build();
    content_stack.add_named(&scrolled, Some("list"));
    content_stack.add_named(&empty_status, Some("empty"));
    main_box.append(&content_stack);

    (
        main_box,
        search_bar,
        search_entry,
        list_box,
        empty_status,
        content_stack,
    )
}

impl Inner {
    fn focus_auth_field(&self) {
        let target = self.master_entry.clone().upcast::<gtk::Widget>();
        glib::idle_add_local_once(move || {
            target.grab_focus();
        });
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

    fn show_auth_error(&self, msg: &str) {
        self.auth_error.set_text(msg);
        self.auth_error.set_visible(true);
    }

    fn on_unlock_clicked(self: &Rc<Self>) {
        let pwd = self.master_entry.text().to_string();
        if pwd.is_empty() {
            self.show_auth_error(tr!("Please enter a password"));
            return;
        }
        if !self
            .state
            .vault
            .borrow()
            .has_master_password()
            .unwrap_or(false)
        {
            self.show_auth_error(tr!(
                "Please create your master password in the Vault tab first."
            ));
            return;
        }
        let r = self.state.vault.borrow_mut().unlock(&pwd);
        match r {
            Ok(()) => {
                SessionManager::login(&self.state.session);
                self.master_entry.set_text("");
                self.auth_error.set_visible(false);
                self.load_entries(None);
                self.notify_auth_changed();
            }
            Err(ashypass_core::Error::InvalidMasterPassword) => {
                self.show_auth_error(tr!("Incorrect master password"));
            }
            Err(e) => {
                self.show_auth_error(&format!("{}: {e}", tr!("Failed to unlock vault")));
            }
        }
    }

    fn load_entries(self: &Rc<Self>, search: Option<&str>) {
        if !(self.state.session.borrow().is_authenticated()
            && self.state.vault.borrow().is_unlocked())
        {
            return;
        }
        self.stop_timer();
        self.rows.borrow_mut().clear();
        clear_list_box(&self.list_box);

        let mut entries = match self.state.vault.borrow().list(search) {
            Ok(v) => v,
            Err(e) => {
                log::error!("vault.list (totp) failed: {e}");
                return;
            }
        };
        entries.retain(|p| p.has_totp);

        let entries: Vec<(PasswordEntry, String)> = {
            let vault = self.state.vault.borrow();
            entries
                .into_iter()
                .filter_map(|entry| match vault.totp_secret(entry.id) {
                    Ok(Some(secret)) => Some((entry, secret)),
                    Ok(None) => None,
                    Err(e) => {
                        log::error!("totp secret read failed: {e}");
                        None
                    }
                })
                .collect()
        };

        self.main_stack.set_visible_child_name("totp");

        if entries.is_empty() {
            let (icon, title, desc) = if search.is_some() {
                (
                    "edit-find-symbolic",
                    tr!("No Results"),
                    tr!("No 2FA codes match your search"),
                )
            } else {
                (
                    "auth-sim-symbolic",
                    tr!("No 2FA Codes"),
                    tr!("Add a TOTP secret to an entry to see live codes here."),
                )
            };
            self.empty_status.set_icon_name(Some(icon));
            self.empty_status.set_title(title);
            self.empty_status.set_description(Some(desc));
            self.content_stack.set_visible_child_name("empty");
            return;
        }

        self.content_stack.set_visible_child_name("list");
        let large_codes = ashypass_core::settings::Settings::load().large_totp_codes;
        for (entry, secret) in entries {
            let row = self.build_row(&entry, secret, large_codes);
            self.list_box.append(&row);
        }
        self.start_timer();
    }

    fn build_row(
        self: &Rc<Self>,
        entry: &PasswordEntry,
        secret: String,
        large_codes: bool,
    ) -> gtk::ListBoxRow {
        let row = gtk::ListBoxRow::new();
        row.set_activatable(false);

        let outer = gtk::Box::builder()
            .orientation(gtk::Orientation::Horizontal)
            .spacing(12)
            .margin_top(8)
            .margin_bottom(8)
            .margin_start(12)
            .margin_end(12)
            .build();

        let icon = gtk::Image::from_icon_name("auth-sim-symbolic");
        icon.set_pixel_size(32);
        icon.set_valign(gtk::Align::Center);
        outer.append(&icon);

        let center = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(2)
            .hexpand(true)
            .valign(gtk::Align::Center)
            .build();

        let code_label = gtk::Label::new(Some("------"));
        code_label.add_css_class("monospace");
        if large_codes {
            code_label.add_css_class("title-1");
            code_label.add_css_class("totp-code");
        } else {
            code_label.add_css_class("title-2");
        }
        code_label.set_xalign(0.0);
        center.append(&code_label);

        let mut parts: Vec<String> = vec![entry.title.clone()];
        if let Some(u) = entry.username.as_deref().filter(|s| !s.is_empty()) {
            parts.push(u.to_string());
        }
        let name_label = gtk::Label::builder()
            .label(parts.join(" · "))
            .xalign(0.0)
            .ellipsize(gtk::pango::EllipsizeMode::End)
            .build();
        name_label.add_css_class("dim-label");
        name_label.add_css_class("caption");
        center.append(&name_label);
        outer.append(&center);

        let progress = gtk::LevelBar::builder()
            .mode(gtk::LevelBarMode::Continuous)
            .min_value(0.0)
            .max_value(1.0)
            .valign(gtk::Align::Center)
            .build();
        progress.set_size_request(36, -1);
        outer.append(&progress);

        let btn_box = gtk::Box::builder()
            .orientation(gtk::Orientation::Horizontal)
            .spacing(2)
            .valign(gtk::Align::Center)
            .build();

        let copy_btn = gtk::Button::builder()
            .icon_name("edit-copy-symbolic")
            .tooltip_text(tr!("Copy Code"))
            .build();
        copy_btn.add_css_class("flat");
        {
            let inner_cl = self.clone();
            let id = entry.id;
            copy_btn.connect_clicked(move |_| inner_cl.copy_totp(id));
        }
        btn_box.append(&copy_btn);

        let edit_btn = gtk::Button::builder()
            .icon_name("document-edit-symbolic")
            .tooltip_text(tr!("Edit"))
            .build();
        edit_btn.add_css_class("flat");
        {
            let inner_cl = self.clone();
            let id = entry.id;
            edit_btn.connect_clicked(move |_| inner_cl.show_edit_dialog(id));
        }
        btn_box.append(&edit_btn);

        let del_btn = gtk::Button::builder()
            .icon_name("user-trash-symbolic")
            .tooltip_text(tr!("Delete"))
            .build();
        del_btn.add_css_class("flat");
        {
            let inner_cl = self.clone();
            let id = entry.id;
            del_btn.connect_clicked(move |_| inner_cl.confirm_delete(id));
        }
        btn_box.append(&del_btn);

        outer.append(&btn_box);
        row.set_child(Some(&outer));

        self.rows.borrow_mut().push(RowData {
            code_label,
            progress,
            id: entry.id,
            secret,
            algorithm: entry.totp_algorithm.clone(),
            digits: entry.totp_digits,
            period: entry.totp_period,
        });

        row
    }

    fn start_timer(self: &Rc<Self>) {
        self.stop_timer();
        if self.rows.borrow().is_empty() {
            return;
        }
        self.update_displays();
        let weak = Rc::downgrade(self);
        let id = glib::timeout_add_seconds_local(1, move || {
            let Some(inner) = weak.upgrade() else {
                return glib::ControlFlow::Break;
            };
            inner.update_displays();
            glib::ControlFlow::Continue
        });
        *self.timer_id.borrow_mut() = Some(id);
    }

    fn stop_timer(&self) {
        if let Some(id) = self.timer_id.borrow_mut().take() {
            id.remove();
        }
    }

    fn cancel_pending_search_reload(&self) {
        if let Some(id) = self.search_reload_id.borrow_mut().take() {
            id.remove();
        }
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
        let search = self.current_search();
        self.load_entries(search.as_deref());
    }

    fn update_displays(&self) {
        let now = chrono::Utc::now().timestamp() as u64;
        let rows = self.rows.borrow();
        for rd in rows.iter() {
            let algo = Algorithm::parse(&rd.algorithm).unwrap_or(Algorithm::Sha1);
            match generate_totp(&rd.secret, algo, rd.digits, rd.period, now) {
                Ok(code) => {
                    rd.code_label.set_text(&code);
                    let rem = remaining_seconds(rd.period, now);
                    rd.progress.set_value(rem as f64 / rd.period as f64);
                }
                Err(_) => {
                    rd.code_label.set_text("------");
                    rd.progress.set_value(0.0);
                }
            }
        }
    }

    fn copy_totp(self: &Rc<Self>, id: i64) {
        let row_data = self.rows.borrow().iter().find(|rd| rd.id == id).map(|rd| {
            (
                rd.secret.clone(),
                rd.algorithm.clone(),
                rd.digits,
                rd.period,
            )
        });
        let Some((secret, algorithm, digits, period)) = row_data else {
            return;
        };
        let algo = Algorithm::parse(&algorithm).unwrap_or(Algorithm::Sha1);
        let now = chrono::Utc::now().timestamp() as u64;
        if let Ok(code) = generate_totp(&secret, algo, digits, period, now) {
            let seconds = ashypass_core::settings::Settings::load().clipboard_clear;
            crate::clipboard::copy(&code, seconds);
            self.show_toast(tr!("TOTP code copied"));
        }
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
            .heading(tr!("Delete 2FA Entry?"))
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
                        tr!("Entry deleted")
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

    fn show_add_dialog(self: &Rc<Self>) {
        let dialog = adw::AlertDialog::builder()
            .heading(tr!("Add 2FA Code"))
            .default_response("save")
            .close_response("cancel")
            .build();
        dialog.add_response("cancel", tr!("Cancel"));
        dialog.add_response("save", tr!("Save"));
        dialog.set_response_appearance("save", adw::ResponseAppearance::Suggested);

        let form = adw::PreferencesGroup::new();
        let title_entry = adw::EntryRow::builder().title(tr!("Title")).build();
        form.add(&title_entry);
        let username_entry = adw::EntryRow::builder().title(tr!("Username")).build();
        form.add(&username_entry);
        let url_entry = adw::EntryRow::builder().title(tr!("URL")).build();
        form.add(&url_entry);

        let totp_group = adw::PreferencesGroup::builder()
            .title(tr!("TOTP Settings"))
            .description(tr!("Paste a Base32 secret or an otpauth:// URI"))
            .build();
        let totp_entry = adw::PasswordEntryRow::builder()
            .title(tr!("TOTP Secret"))
            .build();
        totp_group.add(&totp_entry);

        let algo_model = gtk::StringList::new(&["SHA1", "SHA256", "SHA512"]);
        let algo_row = adw::ComboRow::builder()
            .title(tr!("Algorithm"))
            .model(&algo_model)
            .build();
        algo_row.set_selected(0);
        totp_group.add(&algo_row);

        let digits_adj = gtk::Adjustment::new(6.0, 6.0, 8.0, 2.0, 2.0, 0.0);
        let digits_row = adw::SpinRow::builder()
            .title(tr!("Digits"))
            .adjustment(&digits_adj)
            .build();
        totp_group.add(&digits_row);

        let period_adj = gtk::Adjustment::new(30.0, 15.0, 60.0, 15.0, 15.0, 0.0);
        let period_row = adw::SpinRow::builder()
            .title(tr!("Period (seconds)"))
            .adjustment(&period_adj)
            .build();
        totp_group.add(&period_row);

        let content = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(12)
            .build();
        content.set_size_request(500, -1);
        content.append(&form);
        content.append(&totp_group);
        dialog.set_extra_child(Some(&content));

        let inner_cl = self.clone();
        let title_entry_focus = title_entry.clone();
        dialog.connect_response(None, move |dlg, response| {
            if response != "save" {
                dlg.close();
                return;
            }

            let mut title = title_entry.text().trim().to_string();
            let mut username = trim_to_opt(&username_entry.text());
            let url = trim_to_opt(&url_entry.text());
            let secret_input = totp_entry.text().trim().to_string();
            if secret_input.is_empty() {
                totp_entry.add_css_class("error");
                inner_cl.show_toast(tr!("TOTP secret is required"));
                return;
            }

            let mut algo = selected_algorithm(&algo_row).to_string();
            let mut digits = digits_row.value() as u8;
            let mut period = period_row.value() as u32;
            let secret = if secret_input.to_ascii_lowercase().starts_with("otpauth://") {
                match parse_otpauth(&secret_input) {
                    Ok(parsed) => {
                        if title.is_empty() {
                            title = if parsed.issuer.is_empty() {
                                parsed.label.clone()
                            } else {
                                parsed.issuer.clone()
                            };
                        }
                        if username.is_none() && !parsed.issuer.is_empty() {
                            username = Some(parsed.label.clone());
                        }
                        algo = parsed.algorithm.as_str().to_string();
                        digits = parsed.digits;
                        period = parsed.period;
                        parsed.secret
                    }
                    Err(e) => {
                        totp_entry.add_css_class("error");
                        inner_cl.show_toast(&format!("{}: {e}", tr!("Invalid TOTP secret")));
                        return;
                    }
                }
            } else {
                secret_input
            };

            if title.is_empty() {
                title_entry.add_css_class("error");
                return;
            }
            title_entry.remove_css_class("error");
            totp_entry.remove_css_class("error");
            if !(6..=8).contains(&digits) || period == 0 {
                totp_entry.add_css_class("error");
                inner_cl.show_toast(tr!("Invalid TOTP settings"));
                return;
            }

            let algorithm = Algorithm::parse(&algo).unwrap_or(Algorithm::Sha1);
            if let Err(e) = generate_totp(&secret, algorithm, digits, period, 0) {
                totp_entry.add_css_class("error");
                inner_cl.show_toast(&format!("{}: {e}", tr!("Invalid TOTP secret")));
                return;
            }

            let new_entry = NewEntry {
                title,
                username,
                password: String::new(),
                notes: None,
                url,
                totp_secret: Some(secret),
                totp_algorithm: Some(algo),
                totp_digits: Some(digits),
                totp_period: Some(period),
                category: Some("2FA".into()),
            };

            match inner_cl.state.vault.borrow().add(new_entry) {
                Ok(_) => {
                    inner_cl.show_toast(tr!("2FA code added"));
                    inner_cl.reload_current_filter();
                    SessionManager::on_activity(&inner_cl.state.session);
                    dlg.close();
                }
                Err(e) => {
                    inner_cl.show_toast(&format!("{}: {e}", tr!("Error")));
                }
            }
        });

        dialog.present(Some(self.toast.upcast_ref::<gtk::Widget>()));
        glib::idle_add_local_once(move || {
            title_entry_focus.grab_focus();
        });
    }

    fn show_edit_dialog(self: &Rc<Self>, id: i64) {
        let entry = match self.state.vault.borrow().get(id) {
            Ok(Some(e)) => e,
            _ => return,
        };

        let dialog = adw::AlertDialog::builder()
            .heading(tr!("Edit 2FA Entry"))
            .default_response("save")
            .close_response("cancel")
            .build();
        dialog.add_response("cancel", tr!("Cancel"));
        dialog.add_response("save", tr!("Save"));
        dialog.set_response_appearance("save", adw::ResponseAppearance::Suggested);

        let form = adw::PreferencesGroup::new();

        let title_entry = adw::EntryRow::builder()
            .title(tr!("Title"))
            .text(&entry.title)
            .build();
        form.add(&title_entry);
        let username_entry = adw::EntryRow::builder()
            .title(tr!("Username"))
            .text(entry.username.as_deref().unwrap_or(""))
            .build();
        form.add(&username_entry);
        let url_entry = adw::EntryRow::builder()
            .title(tr!("URL"))
            .text(entry.url.as_deref().unwrap_or(""))
            .build();
        form.add(&url_entry);
        let totp_group = adw::PreferencesGroup::builder()
            .title(tr!("TOTP Settings"))
            .build();

        let totp_entry = adw::PasswordEntryRow::builder()
            .title(tr!("TOTP Secret (Base32)"))
            .build();
        if let Some(s) = entry.totp_secret.as_deref() {
            totp_entry.set_text(s);
        }
        totp_group.add(&totp_entry);

        let algo_model = gtk::StringList::new(&["SHA1", "SHA256", "SHA512"]);
        let algo_row = adw::ComboRow::builder()
            .title(tr!("Algorithm"))
            .model(&algo_model)
            .build();
        algo_row.set_selected(match entry.totp_algorithm.as_str() {
            "SHA256" => 1,
            "SHA512" => 2,
            _ => 0,
        });
        totp_group.add(&algo_row);

        let digits_adj = gtk::Adjustment::new(entry.totp_digits as f64, 6.0, 8.0, 2.0, 2.0, 0.0);
        let digits_row = adw::SpinRow::builder()
            .title(tr!("Digits"))
            .adjustment(&digits_adj)
            .build();
        totp_group.add(&digits_row);

        let period_adj =
            gtk::Adjustment::new(entry.totp_period as f64, 15.0, 60.0, 15.0, 15.0, 0.0);
        let period_row = adw::SpinRow::builder()
            .title(tr!("Period (seconds)"))
            .adjustment(&period_adj)
            .build();
        totp_group.add(&period_row);

        let content = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(12)
            .build();
        content.set_size_request(500, -1);
        content.append(&form);
        content.append(&totp_group);
        dialog.set_extra_child(Some(&content));

        let inner_cl = self.clone();
        let title_entry_cl = title_entry.clone();
        dialog.connect_response(None, move |dlg, response| {
            if response != "save" {
                dlg.close();
                return;
            }
            let title = title_entry_cl.text().trim().to_string();
            if title.is_empty() {
                title_entry_cl.add_css_class("error");
                return;
            }
            title_entry_cl.remove_css_class("error");

            let algo = match algo_row.selected() {
                1 => "SHA256",
                2 => "SHA512",
                _ => "SHA1",
            }
            .to_string();

            let change = UpdateEntry {
                title: Some(title),
                username: Some(username_entry.text().trim().to_string()),
                password: None,
                notes: None,
                url: Some(trim_to_opt(&url_entry.text())),
                totp_secret: Some(trim_to_opt(&totp_entry.text())),
                totp_algorithm: Some(algo),
                totp_digits: Some(digits_row.value() as u8),
                totp_period: Some(period_row.value() as u32),
                category: None,
            };
            match inner_cl.state.vault.borrow().update(id, change) {
                Ok(_) => {
                    inner_cl.show_toast(tr!("Entry updated"));
                    inner_cl.reload_current_filter();
                    SessionManager::on_activity(&inner_cl.state.session);
                    dlg.close();
                }
                Err(e) => {
                    inner_cl.show_toast(&format!("{}: {e}", tr!("Error")));
                }
            }
        });

        dialog.present(Some(self.toast.upcast_ref::<gtk::Widget>()));
    }
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

fn selected_algorithm(row: &adw::ComboRow) -> &'static str {
    match row.selected() {
        1 => "SHA256",
        2 => "SHA512",
        _ => "SHA1",
    }
}
