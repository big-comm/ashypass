//! "Verification codes": identify the account first, then copy its code.
//!
//! Each row shows the service and the account, the current code and when it
//! changes ("18 s"), a *Copy code* button and a menu for the less frequent
//! actions. The code copied is computed at the moment of the click and the
//! clipboard is never refreshed behind the user's back.
//!
//! The one-second refresh runs only while the page is on screen and the vault
//! is unlocked, and only updates text — the countdown is not announced to
//! screen readers every second.

use crate::session::SessionManager;
use crate::state::SharedState;
use crate::tr;
use crate::ui::entry_form::{self, parse_totp_input, totp_error_message, EntryFormOptions};
use crate::ui::widgets::{account_line, copy_secret, group_code, page_heading, Chrome, EmptyState};
use adw::prelude::*;
use ashypass_core::db::vault::{NewEntry, PasswordEntry, UpdateEntry};
use ashypass_core::totp::{generate_totp, Algorithm};
use gtk::{gio, glib};
use std::cell::RefCell;
use std::rc::Rc;
use zeroize::Zeroizing;

pub struct TotpView {
    pub root: adw::ToolbarView,
    inner: Rc<Inner>,
}

struct Inner {
    state: SharedState,
    toast: adw::ToastOverlay,
    root: adw::ToolbarView,
    search_entry: gtk::SearchEntry,
    search_reload_id: RefCell<Option<glib::SourceId>>,
    list_box: gtk::ListBox,
    content_stack: gtk::Stack,
    empty: EmptyState,
    rows: RefCell<Vec<RowData>>,
    timer_id: RefCell<Option<glib::SourceId>>,
}

struct RowData {
    code_label: gtk::Label,
    countdown_label: gtk::Label,
    progress: gtk::LevelBar,
    secret: Zeroizing<String>,
    algorithm: Algorithm,
    digits: u8,
    period: u32,
}

impl TotpView {
    pub fn new(state: SharedState, toast: adw::ToastOverlay, chrome: &Chrome) -> Rc<Self> {
        let search_entry = gtk::SearchEntry::builder()
            .placeholder_text(tr!("Search codes"))
            .hexpand(true)
            .build();
        search_entry.update_property(&[gtk::accessible::Property::Label(tr!(
            "Search verification codes"
        ))]);
        let search_clamp = adw::Clamp::builder()
            .maximum_size(420)
            .child(&search_entry)
            .build();
        let header = chrome.header(Some(search_clamp.upcast_ref()));

        let content = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(16)
            .margin_top(12)
            .margin_bottom(24)
            .margin_start(18)
            .margin_end(18)
            .build();
        content.append(&page_heading(
            tr!("Verification codes"),
            Some(tr!(
                "Use these codes when a site asks for two-step verification."
            )),
        ));

        let list_box = gtk::ListBox::builder()
            .selection_mode(gtk::SelectionMode::None)
            .build();
        list_box.add_css_class("boxed-list");
        list_box.update_property(&[gtk::accessible::Property::Label(tr!("Verification codes"))]);
        let empty = EmptyState::new();
        let content_stack = gtk::Stack::builder()
            .transition_type(gtk::StackTransitionType::Crossfade)
            .vhomogeneous(false)
            .build();
        content_stack.add_named(&list_box, Some("list"));
        content_stack.add_named(&empty.root, Some("empty"));
        content.append(&content_stack);

        let add_button = gtk::Button::builder().halign(gtk::Align::Center).build();
        let add_box = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        add_box.append(&gtk::Image::from_icon_name("list-add-symbolic"));
        add_box.append(&gtk::Label::new(Some(tr!("Add verification code"))));
        add_button.set_child(Some(&add_box));
        add_button.add_css_class("pill");
        content.append(&add_button);

        let clamp = adw::Clamp::builder()
            .maximum_size(820)
            .child(&content)
            .build();
        let scrolled = gtk::ScrolledWindow::builder()
            .hscrollbar_policy(gtk::PolicyType::Never)
            .vexpand(true)
            .child(&clamp)
            .build();

        let root = adw::ToolbarView::new();
        root.add_top_bar(&header);
        root.set_content(Some(&scrolled));
        search_entry.set_key_capture_widget(Some(&scrolled));

        let inner = Rc::new(Inner {
            state,
            toast,
            root: root.clone(),
            search_entry,
            search_reload_id: RefCell::new(None),
            list_box,
            content_stack,
            empty,
            rows: RefCell::new(Vec::new()),
            timer_id: RefCell::new(None),
        });

        {
            let weak = Rc::downgrade(&inner);
            add_button.connect_clicked(move |button| {
                if let Some(inner) = weak.upgrade() {
                    inner.show_add_dialog(button);
                }
            });
        }
        {
            let weak = Rc::downgrade(&inner);
            inner.search_entry.connect_search_changed(move |_| {
                let Some(inner) = weak.upgrade() else { return };
                if let Some(id) = inner.search_reload_id.borrow_mut().take() {
                    id.remove();
                }
                let weak = Rc::downgrade(&inner);
                let id =
                    glib::timeout_add_local(std::time::Duration::from_millis(150), move || {
                        if let Some(inner) = weak.upgrade() {
                            *inner.search_reload_id.borrow_mut() = None;
                            inner.reload();
                            SessionManager::on_activity(&inner.state.session);
                        }
                        glib::ControlFlow::Break
                    });
                *inner.search_reload_id.borrow_mut() = Some(id);
            });
        }
        // Refresh codes only while the page is on screen.
        {
            let weak = Rc::downgrade(&inner);
            root.connect_map(move |_| {
                if let Some(inner) = weak.upgrade() {
                    inner.reload();
                }
            });
        }
        {
            let weak = Rc::downgrade(&inner);
            root.connect_unmap(move |_| {
                if let Some(inner) = weak.upgrade() {
                    inner.stop_timer();
                }
            });
        }
        {
            let weak = Rc::downgrade(&inner);
            let _permanent = inner.state.events.subscribe(move |event| {
                let Some(inner) = weak.upgrade() else { return };
                if matches!(
                    event,
                    crate::events::AppEvent::VaultChanged
                        | crate::events::AppEvent::SyncCompleted { .. }
                ) && inner.root.is_mapped()
                {
                    inner.reload();
                }
            });
        }

        Rc::new(Self { root, inner })
    }

    /// The vault locked: drop the rows (codes and account names), the
    /// secrets kept for them and the search text.
    pub fn on_locked(&self) {
        let inner = &self.inner;
        inner.search_entry.set_text("");
        if let Some(id) = inner.search_reload_id.borrow_mut().take() {
            id.remove();
        }
        inner.stop_timer();
        inner.rows.borrow_mut().clear();
        inner.list_box.remove_all();
    }

    pub fn on_unlocked(&self) {
        if self.inner.root.is_mapped() {
            self.inner.reload();
        }
    }

    pub fn focus_search(&self) {
        self.inner.search_entry.grab_focus();
    }

    pub fn show_add_dialog(&self) {
        self.inner.show_add_dialog(&self.inner.root);
    }
}

impl Inner {
    fn can_show_vault_data(&self) -> bool {
        self.state.session.borrow().is_authenticated() && self.state.vault.borrow().is_unlocked()
    }

    fn toast(&self, message: &str) {
        self.toast
            .add_toast(adw::Toast::builder().title(message).timeout(3).build());
    }

    fn stop_timer(&self) {
        if let Some(id) = self.timer_id.borrow_mut().take() {
            id.remove();
        }
    }

    fn reload(self: &Rc<Self>) {
        self.stop_timer();
        if !self.can_show_vault_data() {
            return;
        }
        let search = Some(self.search_entry.text().trim().to_string()).filter(|s| !s.is_empty());
        let entries: Vec<(PasswordEntry, Zeroizing<String>)> = {
            let vault = self.state.vault.borrow();
            let listed = match vault.list(search.as_deref()) {
                Ok(v) => v,
                Err(e) => {
                    log::error!("vault.list (totp) failed: {e}");
                    return;
                }
            };
            listed
                .into_iter()
                .filter(|e| e.has_totp)
                .filter_map(|entry| match vault.totp_secret(entry.id) {
                    Ok(Some(secret)) => Some((entry, Zeroizing::new(secret))),
                    Ok(None) => None,
                    Err(e) => {
                        log::error!("totp secret read failed: {e}");
                        None
                    }
                })
                .collect()
        };

        self.rows.borrow_mut().clear();
        self.list_box.remove_all();

        if entries.is_empty() {
            if let Some(search) = search.as_deref() {
                self.empty.set(
                    "edit-find-symbolic",
                    &format!("{} “{search}”", tr!("No codes found for")),
                    tr!("Names, accounts and sites with verification codes were searched."),
                );
            } else {
                self.empty.set(
                    "security-high-symbolic",
                    tr!("No verification codes yet"),
                    tr!("When a site offers two-step verification, add its setup key here to get the codes."),
                );
            }
            self.content_stack.set_visible_child_name("empty");
            return;
        }
        self.content_stack.set_visible_child_name("list");
        let large = self.state.settings().large_totp_codes;
        let favicons = self.state.settings().show_favicons;
        for (entry, secret) in entries {
            let row = self.build_row(&entry, secret, large, favicons);
            self.list_box.append(&row);
        }
        self.update_codes();
        let weak = Rc::downgrade(self);
        let id = glib::timeout_add_seconds_local(1, move || {
            let Some(inner) = weak.upgrade() else {
                return glib::ControlFlow::Break;
            };
            if !inner.can_show_vault_data() {
                *inner.timer_id.borrow_mut() = None;
                return glib::ControlFlow::Break;
            }
            inner.update_codes();
            glib::ControlFlow::Continue
        });
        *self.timer_id.borrow_mut() = Some(id);
    }

    fn build_row(
        self: &Rc<Self>,
        entry: &PasswordEntry,
        secret: Zeroizing<String>,
        large: bool,
        favicons: bool,
    ) -> gtk::ListBoxRow {
        let id = entry.id;
        let row = gtk::ListBoxRow::builder().activatable(false).build();
        let content = gtk::Box::builder()
            .orientation(gtk::Orientation::Horizontal)
            .spacing(12)
            .margin_top(10)
            .margin_bottom(10)
            .margin_start(12)
            .margin_end(8)
            .build();

        let icon = gtk::Image::new();
        if favicons {
            crate::favicons::apply(&icon, entry.url.as_deref(), 32);
        } else {
            icon.set_pixel_size(32);
            icon.set_icon_name(Some("security-high-symbolic"));
        }
        icon.add_css_class("ashy-entry-icon");
        icon.set_accessible_role(gtk::AccessibleRole::Presentation);
        content.append(&icon);

        let text = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(2)
            .hexpand(true)
            .valign(gtk::Align::Center)
            .build();
        let title = gtk::Label::builder()
            .label(&entry.title)
            .xalign(0.0)
            .ellipsize(gtk::pango::EllipsizeMode::End)
            .build();
        title.add_css_class("heading");
        text.append(&title);
        let line = account_line(
            &entry.title,
            entry.username.as_deref(),
            entry.url.as_deref(),
        );
        if !line.is_empty() {
            let account = gtk::Label::builder()
                .label(&line)
                .xalign(0.0)
                .ellipsize(gtk::pango::EllipsizeMode::Middle)
                .build();
            account.add_css_class("dim-label");
            account.add_css_class("caption");
            text.append(&account);
        }
        content.append(&text);

        let code_label = gtk::Label::builder()
            .valign(gtk::Align::Center)
            .selectable(true)
            .build();
        code_label.add_css_class("ashy-code");
        code_label.add_css_class("monospace");
        if large {
            code_label.add_css_class("ashy-code-large");
        }
        content.append(&code_label);

        let timer_box = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(2)
            .valign(gtk::Align::Center)
            .width_request(44)
            .build();
        let progress = gtk::LevelBar::builder()
            .min_value(0.0)
            .max_value(1.0)
            .build();
        progress.add_css_class("ashy-code-timer");
        progress.set_accessible_role(gtk::AccessibleRole::Presentation);
        let countdown_label = gtk::Label::new(None);
        countdown_label.add_css_class("caption");
        countdown_label.add_css_class("dim-label");
        countdown_label.add_css_class("numeric");
        timer_box.append(&progress);
        timer_box.append(&countdown_label);
        content.append(&timer_box);

        let copy = gtk::Button::builder()
            .label(tr!("Copy code"))
            .valign(gtk::Align::Center)
            .build();
        copy.add_css_class("ashy-row-action");
        copy.update_property(&[gtk::accessible::Property::Label(&format!(
            "{} — {}",
            tr!("Copy code"),
            entry.title
        ))]);
        {
            let weak = Rc::downgrade(self);
            let secret = secret.clone();
            let algorithm = Algorithm::parse(&entry.totp_algorithm).unwrap_or(Algorithm::Sha1);
            let digits = entry.totp_digits;
            let period = entry.totp_period.max(1);
            copy.connect_clicked(move |_| {
                let Some(inner) = weak.upgrade() else { return };
                if !inner.can_show_vault_data() {
                    return;
                }
                let now = chrono::Utc::now().timestamp().max(0) as u64;
                if let Ok(code) = generate_totp(&secret, algorithm, digits, period, now) {
                    copy_secret(&inner.state, &code);
                    inner.toast(tr!("Code copied"));
                }
                SessionManager::on_activity(&inner.state.session);
            });
        }
        content.append(&copy);

        let menu = gio::Menu::new();
        menu.append(Some(tr!("Edit access…")), Some("code.edit"));
        let danger = gio::Menu::new();
        danger.append(Some(tr!("Remove verification code…")), Some("code.remove"));
        danger.append(Some(tr!("Delete access…")), Some("code.delete"));
        menu.append_section(None, &danger);
        let more = gtk::MenuButton::builder()
            .icon_name("view-more-symbolic")
            .menu_model(&menu)
            .valign(gtk::Align::Center)
            .tooltip_text(tr!("More actions"))
            .build();
        more.add_css_class("flat");
        more.update_property(&[gtk::accessible::Property::Label(&format!(
            "{} — {}",
            tr!("More actions"),
            entry.title
        ))]);
        content.append(&more);

        let group = gio::SimpleActionGroup::new();
        for (name, run) in [
            ("edit", Inner::edit_entry as fn(&Rc<Inner>, i64)),
            ("remove", Inner::confirm_remove_code as fn(&Rc<Inner>, i64)),
            ("delete", Inner::confirm_delete as fn(&Rc<Inner>, i64)),
        ] {
            let action = gio::SimpleAction::new(name, None);
            let weak = Rc::downgrade(self);
            action.connect_activate(move |_, _| {
                if let Some(inner) = weak.upgrade() {
                    run(&inner, id);
                }
            });
            group.add_action(&action);
        }
        row.insert_action_group("code", Some(&group));
        row.set_child(Some(&content));

        self.rows.borrow_mut().push(RowData {
            code_label,
            countdown_label,
            progress,
            secret,
            algorithm: Algorithm::parse(&entry.totp_algorithm).unwrap_or(Algorithm::Sha1),
            digits: entry.totp_digits,
            period: entry.totp_period.max(1),
        });
        row
    }

    fn update_codes(&self) {
        let now = chrono::Utc::now().timestamp().max(0) as u64;
        for rd in self.rows.borrow().iter() {
            let period = rd.period as u64;
            let remaining = period - (now % period);
            match generate_totp(&rd.secret, rd.algorithm, rd.digits, rd.period, now) {
                Ok(code) => {
                    let grouped = group_code(&code);
                    if rd.code_label.label() != grouped {
                        rd.code_label.set_label(&grouped);
                    }
                }
                Err(_) => rd.code_label.set_label("—"),
            }
            rd.progress.set_value(remaining as f64 / period as f64);
            rd.countdown_label.set_label(&format!("{remaining} s"));
            rd.countdown_label.set_tooltip_text(Some(
                &crate::trn!(
                    "New code in {} second",
                    "New code in {} seconds",
                    remaining as usize
                )
                .replace("{}", &remaining.to_string()),
            ));
            // Close to the switch is information, not an alarm.
            if remaining <= 5 {
                rd.countdown_label.add_css_class("ashy-code-expiring");
            } else {
                rd.countdown_label.remove_css_class("ashy-code-expiring");
            }
        }
    }

    fn edit_entry(self: &Rc<Self>, id: i64) {
        let entry = match self.state.vault.borrow().get(id) {
            Ok(Some(e)) => e,
            _ => return,
        };
        let weak = Rc::downgrade(self);
        entry_form::present(
            &self.state,
            &self.toast,
            &self.root,
            EntryFormOptions {
                entry: Some(entry),
                prefill_password: None,
                prefill_folder: None,
                on_saved: Some(Box::new(move |_| {
                    if let Some(inner) = weak.upgrade() {
                        inner.reload();
                    }
                })),
            },
        );
    }

    fn confirm_remove_code(self: &Rc<Self>, id: i64) {
        let Some(entry) = self
            .state
            .vault
            .borrow()
            .get_without_touch(id)
            .ok()
            .flatten()
        else {
            return;
        };
        let has_password = entry.password.as_deref().is_some_and(|p| !p.is_empty());
        if !has_password {
            // Removing the only secret would leave an empty access behind.
            self.confirm_delete(id);
            return;
        }
        let dialog = adw::AlertDialog::builder()
            .heading(format!("{} “{}”?", tr!("Remove the verification code from"), entry.title))
            .body(tr!(
                "The password and other details stay. Before removing, make sure another app or a backup code can still sign you in, or turn off two-step verification on the site."
            ))
            .close_response("cancel")
            .default_response("cancel")
            .build();
        dialog.add_response("cancel", tr!("Cancel"));
        dialog.add_response("remove", tr!("Remove code"));
        dialog.set_response_appearance("remove", adw::ResponseAppearance::Destructive);
        let weak = Rc::downgrade(self);
        dialog.connect_response(None, move |_, response| {
            let Some(inner) = weak.upgrade() else { return };
            if response != "remove" || !inner.can_show_vault_data() {
                return;
            }
            let change = UpdateEntry {
                title: None,
                username: None,
                password: None,
                notes: None,
                url: None,
                totp_secret: Some(None),
                totp_algorithm: None,
                totp_digits: None,
                totp_period: None,
                category: None,
            };
            match inner.state.vault.borrow().update(id, change) {
                Ok(_) => inner.toast(tr!("Verification code removed")),
                Err(e) => inner.toast(&format!("{}: {e}", tr!("Could not remove the code"))),
            }
            inner.reload();
        });
        self.state.track_sensitive_dialog(&dialog);
        dialog.present(Some(&self.root));
    }

    fn confirm_delete(self: &Rc<Self>, id: i64) {
        let Some(entry) = self
            .state
            .vault
            .borrow()
            .get_without_touch(id)
            .ok()
            .flatten()
        else {
            return;
        };
        let retention = self.state.settings().trash_retention_days;
        let who = entry
            .username
            .as_deref()
            .filter(|u| !u.trim().is_empty())
            .map(|u| format!(" ({u})"))
            .unwrap_or_default();
        let mut body = tr!("This deletes the whole access: verification code, password and notes.")
            .to_string();
        body.push(' ');
        body.push_str(if retention > 0 {
            tr!("It can be restored from Deleted items.")
        } else {
            tr!("This cannot be undone.")
        });
        let dialog = adw::AlertDialog::builder()
            .heading(format!("{} “{}”{who}?", tr!("Delete"), entry.title))
            .body(&body)
            .close_response("cancel")
            .default_response("cancel")
            .build();
        dialog.add_response("cancel", tr!("Cancel"));
        dialog.add_response("delete", tr!("Delete access"));
        dialog.set_response_appearance("delete", adw::ResponseAppearance::Destructive);
        let weak = Rc::downgrade(self);
        dialog.connect_response(None, move |_, response| {
            let Some(inner) = weak.upgrade() else { return };
            if response != "delete" || !inner.can_show_vault_data() {
                return;
            }
            let deleted = if retention > 0 {
                inner.state.vault.borrow().delete(id)
            } else {
                inner.state.vault.borrow().delete_permanent(id)
            };
            match deleted {
                Ok(true) => inner.toast(if retention > 0 {
                    tr!("Moved to Deleted items")
                } else {
                    tr!("Permanently deleted")
                }),
                Ok(false) => inner.toast(tr!("This access no longer exists")),
                Err(e) => inner.toast(&format!("{}: {e}", tr!("Could not delete"))),
            }
            inner.reload();
        });
        self.state.track_sensitive_dialog(&dialog);
        dialog.present(Some(&self.root));
    }

    /// Add a code to an existing access or create a new one. The text
    /// explains where the setup key comes from, so nobody pastes the six
    /// digits shown by another app instead.
    fn show_add_dialog(self: &Rc<Self>, anchor: &impl IsA<gtk::Widget>) {
        if !self.can_show_vault_data() {
            return;
        }
        let dialog = adw::Dialog::builder()
            .title(tr!("Add verification code"))
            .content_width(540)
            .content_height(620)
            .build();
        let header = adw::HeaderBar::builder()
            .show_start_title_buttons(false)
            .show_end_title_buttons(false)
            .build();
        let cancel = gtk::Button::with_label(tr!("Cancel"));
        let save = gtk::Button::with_label(tr!("Add code"));
        save.add_css_class("suggested-action");
        header.pack_start(&cancel);
        header.pack_end(&save);
        let toolbar = adw::ToolbarView::new();
        toolbar.add_top_bar(&header);

        let content = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(18)
            .margin_top(12)
            .margin_bottom(24)
            .margin_start(12)
            .margin_end(12)
            .build();
        let explain = gtk::Label::builder()
            .label(tr!(
                "On the site you want to protect, open the two-step verification settings and choose an authenticator app. Copy the setup key (or the otpauth:// link) it shows and paste it below."
            ))
            .wrap(true)
            .xalign(0.0)
            .build();
        explain.add_css_class("ashy-note");
        content.append(&explain);

        // Where the code goes: an existing access or a new one.
        let entries: Vec<PasswordEntry> = self
            .state
            .vault
            .borrow()
            .list(None)
            .unwrap_or_default()
            .into_iter()
            .filter(|e| !e.has_totp)
            .collect();
        let target_group = adw::PreferencesGroup::builder()
            .title(tr!("Where should the code be saved?"))
            .build();
        let mut target_items: Vec<String> = vec![tr!("A new access").to_string()];
        target_items.extend(entries.iter().map(|e| {
            let line = account_line(&e.title, e.username.as_deref(), e.url.as_deref());
            if line.is_empty() {
                e.title.clone()
            } else {
                format!("{} — {line}", e.title)
            }
        }));
        let target_model =
            gtk::StringList::new(&target_items.iter().map(String::as_str).collect::<Vec<_>>());
        let target_row = adw::ComboRow::builder()
            .title(tr!("Save in"))
            .model(&target_model)
            .enable_search(true)
            .build();
        target_group.add(&target_row);
        let title_row = adw::EntryRow::builder().title(tr!("Name")).build();
        let user_row = adw::EntryRow::builder()
            .title(tr!("User or e-mail (optional)"))
            .build();
        let url_row = adw::EntryRow::builder()
            .title(tr!("Website (optional)"))
            .build();
        target_group.add(&title_row);
        target_group.add(&user_row);
        target_group.add(&url_row);
        {
            let rows = [title_row.clone(), user_row.clone(), url_row.clone()];
            target_row.connect_selected_notify(move |row| {
                let new_access = row.selected() == 0;
                for r in &rows {
                    r.set_visible(new_access);
                }
            });
        }
        content.append(&target_group);

        let key_group = adw::PreferencesGroup::builder()
            .title(tr!("Setup key"))
            .build();
        let key_row = adw::PasswordEntryRow::builder()
            .title(tr!("Setup key or otpauth:// link"))
            .build();
        key_group.add(&key_row);
        let params = adw::ExpanderRow::builder()
            .title(tr!("Code settings"))
            .subtitle(tr!("Change only if the site shows different values"))
            .build();
        let algo_model = gtk::StringList::new(&["SHA1", "SHA256", "SHA512"]);
        let algo_row = adw::ComboRow::builder()
            .title(tr!("Algorithm"))
            .model(&algo_model)
            .build();
        let digits_row = adw::SpinRow::builder()
            .title(tr!("Digits"))
            .adjustment(&gtk::Adjustment::new(6.0, 6.0, 8.0, 1.0, 1.0, 0.0))
            .build();
        let period_row = adw::SpinRow::builder()
            .title(tr!("New code every (seconds)"))
            .adjustment(&gtk::Adjustment::new(30.0, 15.0, 120.0, 15.0, 15.0, 0.0))
            .build();
        params.add_row(&algo_row);
        params.add_row(&digits_row);
        params.add_row(&period_row);
        key_group.add(&params);
        content.append(&key_group);

        let error = gtk::Label::builder()
            .xalign(0.0)
            .wrap(true)
            .visible(false)
            .build();
        error.add_css_class("error");
        error.set_accessible_role(gtk::AccessibleRole::Alert);
        crate::ui::widgets::describe(&key_row, &error);
        content.append(&error);

        let clamp = adw::Clamp::builder()
            .maximum_size(600)
            .child(&content)
            .build();
        let scrolled = gtk::ScrolledWindow::builder()
            .hscrollbar_policy(gtk::PolicyType::Never)
            .vexpand(true)
            .child(&clamp)
            .build();
        toolbar.set_content(Some(&scrolled));
        dialog.set_child(Some(&toolbar));
        dialog.set_default_widget(Some(&save));

        {
            let dialog = dialog.clone();
            cancel.connect_clicked(move |_| {
                dialog.close();
            });
        }
        {
            let error = error.clone();
            key_row.connect_changed(move |row| {
                error.set_visible(false);
                row.remove_css_class("error");
            });
        }
        let weak = Rc::downgrade(self);
        let dialog_cl = dialog.clone();
        save.connect_clicked(move |_| {
            let Some(inner) = weak.upgrade() else { return };
            if !inner.can_show_vault_data() {
                dialog_cl.close();
                return;
            }
            let algo = match algo_row.selected() {
                1 => "SHA256",
                2 => "SHA512",
                _ => "SHA1",
            };
            let parsed = match parse_totp_input(
                &key_row.text(),
                algo,
                digits_row.value() as u8,
                period_row.value() as u32,
            ) {
                Ok(p) => p,
                Err(e) => {
                    error.set_label(&totp_error_message(&e));
                    error.set_visible(true);
                    key_row.add_css_class("error");
                    return;
                }
            };
            let selected = target_row.selected() as usize;
            let result = if selected == 0 {
                let mut title = title_row.text().trim().to_string();
                if title.is_empty() {
                    title = parsed
                        .issuer
                        .clone()
                        .or(parsed.label.clone())
                        .unwrap_or_default();
                }
                if title.is_empty() {
                    error.set_label(tr!("Give this access a name, for example the site or app."));
                    error.set_visible(true);
                    title_row.add_css_class("error");
                    return;
                }
                let user = Some(user_row.text().trim().to_string())
                    .filter(|s| !s.is_empty())
                    .or_else(|| parsed.issuer.as_ref().and(parsed.label.clone()));
                inner
                    .state
                    .vault
                    .borrow()
                    .add(NewEntry {
                        title,
                        username: user,
                        password: String::new(),
                        url: Some(url_row.text().trim().to_string()).filter(|s| !s.is_empty()),
                        notes: None,
                        totp_secret: Some(parsed.secret),
                        totp_algorithm: Some(parsed.algorithm),
                        totp_digits: Some(parsed.digits),
                        totp_period: Some(parsed.period),
                        category: None,
                    })
                    .map(|_| ())
            } else {
                let Some(target) = entries.get(selected - 1) else {
                    return;
                };
                inner
                    .state
                    .vault
                    .borrow()
                    .update(
                        target.id,
                        UpdateEntry {
                            title: None,
                            username: None,
                            password: None,
                            notes: None,
                            url: None,
                            totp_secret: Some(Some(parsed.secret)),
                            totp_algorithm: Some(parsed.algorithm),
                            totp_digits: Some(parsed.digits),
                            totp_period: Some(parsed.period),
                            category: None,
                        },
                    )
                    .map(|_| ())
            };
            match result {
                Ok(()) => {
                    inner.toast(tr!("Verification code saved to the vault"));
                    inner.reload();
                    dialog_cl.close();
                }
                Err(e) => {
                    error.set_label(&format!(
                        "{} ({e})",
                        tr!("Could not save. Nothing was changed in the vault")
                    ));
                    error.set_visible(true);
                }
            }
        });

        SessionManager::inhibit(&self.state.session);
        {
            let state = self.state.clone();
            dialog.connect_closed(move |_| SessionManager::release(&state.session));
        }
        self.state.track_sensitive_dialog(&dialog);
        dialog.present(Some(anchor));
    }
}
