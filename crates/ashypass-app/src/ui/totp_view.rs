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
use crate::trn;
use crate::ui::entry_form::{self, parse_totp_input, totp_error_message, EntryFormOptions};
use crate::ui::widgets::{account_line, copy_secret, group_code, page_heading, Chrome, EmptyState};
use adw::prelude::*;
use ashypass_core::db::vault::{NewEntry, PasswordEntry, UpdateEntry};
use ashypass_core::totp::{generate_totp, Algorithm};
use gtk::{gio, glib};
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use zeroize::Zeroizing;

pub struct TotpView {
    pub root: adw::ToolbarView,
    inner: Rc<Inner>,
}

struct Inner {
    state: SharedState,
    toast: adw::ToastOverlay,
    /// A phone-width window: each code row on two lines.
    narrow: Cell<bool>,
    root: adw::ToolbarView,
    search_entry: gtk::SearchEntry,
    search_reload_id: RefCell<Option<glib::SourceId>>,
    list_box: gtk::ListBox,
    content_stack: gtk::Stack,
    empty: EmptyState,
    rows: RefCell<Vec<RowData>>,
    timer_id: RefCell<Option<glib::SourceId>>,
    scrolled: gtk::ScrolledWindow,
    /// Second of the last code update.
    last_tick: Cell<Option<u64>>,
    /// Filter buttons, one per group (the items' tags, as in the Android
    /// app and Aegis).
    groups_bar: gtk::FlowBox,
    /// The group shown (`None`: all).
    group: RefCell<Option<String>>,
}

struct RowData {
    code_label: gtk::Label,
    countdown_label: gtk::Label,
    progress: gtk::LevelBar,
    secret: Zeroizing<String>,
    algorithm: Algorithm,
    digits: u8,
    period: u32,
    /// Time step of the code on screen: the HMAC runs once per period, not
    /// on every tick.
    shown_step: Cell<Option<u64>>,
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
            .margin_start(12)
            .margin_end(12)
            .build();
        content.append(&page_heading(
            tr!("Verification codes"),
            Some(tr!(
                "Use these codes when a site asks for two-step verification."
            )),
        ));

        let groups_bar = gtk::FlowBox::builder()
            .selection_mode(gtk::SelectionMode::None)
            .column_spacing(6)
            .row_spacing(6)
            .max_children_per_line(30)
            .visible(false)
            .build();
        content.append(&groups_bar);

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

        let inner = Rc::new(Inner {
            state,
            toast,
            narrow: Cell::new(false),
            root: root.clone(),
            search_entry,
            search_reload_id: RefCell::new(None),
            list_box,
            content_stack,
            empty,
            rows: RefCell::new(Vec::new()),
            timer_id: RefCell::new(None),
            scrolled: scrolled.clone(),
            last_tick: Cell::new(None),
            groups_bar,
            group: RefCell::new(None),
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
                    big_gtk_kit::source::remove(id);
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
                        | crate::events::AppEvent::DisplayChanged
                        | crate::events::AppEvent::VaultChangedBySync
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
            big_gtk_kit::source::remove(id);
        }
        inner.stop_timer();
        inner.rows.borrow_mut().clear();
        inner.list_box.remove_all();
    }

    /// Lay the rows out for a phone-width window (or not), from the
    /// window's narrow breakpoint.
    pub fn set_narrow(&self, narrow: bool) {
        if self.inner.narrow.replace(narrow) != narrow && self.inner.root.is_mapped() {
            self.inner.reload();
        }
    }

    pub fn on_unlocked(&self) {
        if self.inner.root.is_mapped() {
            self.inner.reload();
        }
    }

    pub fn focus_search(&self) {
        self.inner.search_entry.grab_focus();
    }

    pub fn search_entry(&self) -> gtk::SearchEntry {
        self.inner.search_entry.clone()
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
        self.toast.add_toast(
            adw::Toast::builder()
                .use_markup(false)
                .title(message)
                .timeout(3)
                .build(),
        );
    }

    fn stop_timer(&self) {
        if let Some(id) = self.timer_id.borrow_mut().take() {
            big_gtk_kit::source::remove(id);
        }
    }

    fn reload(self: &Rc<Self>) {
        self.stop_timer();
        if !self.can_show_vault_data() {
            return;
        }
        let search = Some(self.search_entry.text().trim().to_string()).filter(|s| !s.is_empty());
        let mut groups: Vec<String> = Vec::new();
        let entries: Vec<(PasswordEntry, Zeroizing<String>)> = {
            let vault = self.state.vault.borrow();
            // Groups of every code (not only the searched ones), for the bar.
            if let Ok(all) = vault.list(None) {
                for e in all.iter().filter(|e| e.has_totp) {
                    for tag in vault.tags_of(e.id).unwrap_or_default() {
                        if !groups.iter().any(|g| g.eq_ignore_ascii_case(&tag)) {
                            groups.push(tag);
                        }
                    }
                }
            }
            groups.sort_by_key(|g| g.to_lowercase());
            let shown_group = self.group.borrow().clone().filter(|g| groups.contains(g));
            *self.group.borrow_mut() = shown_group.clone();
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
                .filter(|e| {
                    shown_group
                        .as_ref()
                        .is_none_or(|g| vault.tags_of(e.id).unwrap_or_default().contains(g))
                })
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

        self.fill_groups_bar(&groups);

        // Rebuilding the rows must not throw the reader back to the top.
        let scroll = self.scrolled.vadjustment();
        let position = scroll.value();
        let scroll = Some(scroll);
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
        let settings = self.state.settings();
        let large = settings.large_totp_codes;
        // Off: no icon column at all. On: the brand's icon, else the site's
        // when site icons are on (Password list), else a plain one.
        let icons = settings.totp_icons.then_some(settings.show_favicons);
        for (entry, secret) in entries {
            let row = self.build_row(&entry, secret, large, icons);
            self.list_box.append(&row);
        }
        self.last_tick.set(None);
        self.update_codes();
        if let Some(adjustment) = scroll {
            glib::idle_add_local_once(move || {
                let max = (adjustment.upper() - adjustment.page_size()).max(0.0);
                adjustment.set_value(position.min(max));
            });
        }
        let weak = Rc::downgrade(self);
        // Half a second, so a new code shows at most half a second late
        // (a one-second timer has an arbitrary phase).
        let id = glib::timeout_add_local(std::time::Duration::from_millis(500), move || {
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

    /// One toggle per group, plus "All"; hidden when no code has a group.
    fn fill_groups_bar(self: &Rc<Self>, groups: &[String]) {
        while let Some(child) = self.groups_bar.first_child() {
            self.groups_bar.remove(&child);
        }
        self.groups_bar.set_visible(!groups.is_empty());
        if groups.is_empty() {
            return;
        }
        let current = self.group.borrow().clone();
        let mut first: Option<gtk::ToggleButton> = None;
        for group in std::iter::once(None).chain(groups.iter().cloned().map(Some)) {
            let button = gtk::ToggleButton::builder()
                .label(group.as_deref().unwrap_or(tr!("All")))
                .active(group == current)
                .build();
            button.add_css_class("pill");
            button.add_css_class("ashy-group-chip");
            match &first {
                Some(f) => button.set_group(Some(f)),
                None => first = Some(button.clone()),
            }
            let weak = Rc::downgrade(self);
            button.connect_toggled(move |b| {
                if !b.is_active() {
                    return;
                }
                if let Some(inner) = weak.upgrade() {
                    if *inner.group.borrow() != group {
                        *inner.group.borrow_mut() = group.clone();
                        // After the toggle signal: reload rebuilds this bar.
                        let inner = inner.clone();
                        glib::idle_add_local_once(move || inner.reload());
                    }
                }
            });
            self.groups_bar.append(&button);
        }
    }

    /// Choose the groups of a code (the item's tags), or create one.
    fn edit_groups(self: &Rc<Self>, id: i64) {
        let (current, mut known) = {
            let vault = self.state.vault.borrow();
            let current = vault.tags_of(id).unwrap_or_default();
            let mut known: Vec<String> = Vec::new();
            for e in vault
                .list(None)
                .unwrap_or_default()
                .iter()
                .filter(|e| e.has_totp)
            {
                for tag in vault.tags_of(e.id).unwrap_or_default() {
                    if !known.iter().any(|g| g.eq_ignore_ascii_case(&tag)) {
                        known.push(tag);
                    }
                }
            }
            (current, known)
        };
        known.sort_by_key(|g| g.to_lowercase());
        let dialog = big_gtk_kit::alert::Alert::builder(Some(&self.root))
            .heading(tr!("Groups"))
            .body(tr!("Group the codes as in Aegis. Groups are the item's tags: they sync to your other devices."))
            .close_response("cancel")
            .default_response("save")
            .build();
        dialog.add_response("cancel", tr!("Cancel"));
        dialog.add_response("save", tr!("Save"));
        dialog.set_response_appearance("save", adw::ResponseAppearance::Suggested);
        let list = gtk::ListBox::builder()
            .selection_mode(gtk::SelectionMode::None)
            .build();
        list.add_css_class("boxed-list");
        let mut checks: Vec<(String, gtk::CheckButton)> = Vec::new();
        for group in known {
            let check = gtk::CheckButton::builder()
                .active(current.iter().any(|c| c.eq_ignore_ascii_case(&group)))
                .valign(gtk::Align::Center)
                .build();
            let row = adw::ActionRow::builder()
                .title(&group)
                .activatable_widget(&check)
                .build();
            row.add_prefix(&check);
            list.append(&row);
            checks.push((group, check));
        }
        let new_row = adw::EntryRow::builder().title(tr!("New group")).build();
        list.append(&new_row);
        dialog.set_extra_child(Some(&list));
        let weak = Rc::downgrade(self);
        dialog.connect_response(Some("save"), move |_, _| {
            let Some(inner) = weak.upgrade() else { return };
            if !inner.can_show_vault_data() {
                return;
            }
            let mut chosen: Vec<String> = checks
                .iter()
                .filter(|(_, c)| c.is_active())
                .map(|(g, _)| g.clone())
                .collect();
            let new_group = new_row.text().trim().to_string();
            if !new_group.is_empty() {
                chosen.push(new_group);
            }
            let saved = inner.state.vault.borrow().set_tags(id, &chosen);
            if let Err(e) = saved {
                inner.toast(&format!("{}: {e}", tr!("Could not save")));
            }
        });
        self.state.track_sensitive_dialog(&dialog);
        dialog.present();
    }

    fn build_row(
        self: &Rc<Self>,
        entry: &PasswordEntry,
        secret: Zeroizing<String>,
        large: bool,
        icons: Option<bool>,
    ) -> gtk::ListBoxRow {
        let id = entry.id;
        let row = gtk::ListBoxRow::builder().activatable(false).build();
        let content = gtk::Box::builder()
            .orientation(gtk::Orientation::Horizontal)
            .spacing(8)
            .margin_top(10)
            .margin_bottom(10)
            .margin_start(12)
            .margin_end(8)
            .build();
        // Narrow window: the name on its own line, the code and its buttons
        // under it, so neither gets squeezed into "…".
        let (head, tail) = if self.narrow.get() {
            content.set_orientation(gtk::Orientation::Vertical);
            content.set_spacing(4);
            let head = gtk::Box::new(gtk::Orientation::Horizontal, 8);
            let tail = gtk::Box::new(gtk::Orientation::Horizontal, 8);
            content.append(&head);
            content.append(&tail);
            (head, tail)
        } else {
            (content.clone(), content.clone())
        };

        if let Some(favicons) = icons {
            let icon = gtk::Image::new();
            // The brand's icon (built in), else the saved site's, else a
            // plain one.
            if !crate::favicons::apply_brand(&icon, &entry.title, 32) {
                if favicons {
                    crate::favicons::apply(&icon, entry.url.as_deref(), 32);
                } else {
                    icon.set_pixel_size(32);
                    icon.set_icon_name(Some("security-high-symbolic"));
                }
            }
            icon.add_css_class("ashy-entry-icon");
            icon.set_accessible_role(gtk::AccessibleRole::Presentation);
            head.append(&icon);
        }

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
        head.append(&text);

        // Not selectable: Ctrl+C on the label would skip the clipboard
        // auto-clear that the Copy button applies.
        let code_label = gtk::Label::builder().valign(gtk::Align::Center).build();
        code_label.add_css_class("ashy-code");
        code_label.add_css_class("monospace");
        if large {
            code_label.add_css_class("ashy-code-large");
        }
        if self.narrow.get() {
            // Pushes the buttons to the end of their line.
            code_label.set_hexpand(true);
            code_label.set_xalign(0.0);
        }
        tail.append(&code_label);

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
        tail.append(&timer_box);

        // Icon and words; the icon alone on a phone-width window, where the
        // words would be cut to "Co…" (the tooltip still names it).
        let copy_content = adw::ButtonContent::builder()
            .icon_name("edit-copy-symbolic")
            .can_shrink(true)
            .build();
        if !self.narrow.get() {
            copy_content.set_label(tr!("Copy code"));
        }
        let copy = gtk::Button::builder()
            .child(&copy_content)
            .tooltip_text(tr!("Copy code"))
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
        tail.append(&copy);

        let menu = gio::Menu::new();
        menu.append(Some(tr!("Edit access…")), Some("code.edit"));
        menu.append(Some(tr!("Groups…")), Some("code.groups"));
        big_gtk_kit::menu::append_shared_section(&menu, None, "code-row-danger", || {
            let danger = gio::Menu::new();
            danger.append(Some(tr!("Remove verification code…")), Some("code.remove"));
            danger.append(Some(tr!("Delete access…")), Some("code.delete"));
            danger
        });
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
        tail.append(&more);

        let group = gio::SimpleActionGroup::new();
        for (name, run) in [
            ("edit", Inner::edit_entry as fn(&Rc<Inner>, i64)),
            ("groups", Inner::edit_groups as fn(&Rc<Inner>, i64)),
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
            shown_step: Cell::new(None),
        });
        row
    }

    fn update_codes(&self) {
        let now = chrono::Utc::now().timestamp().max(0) as u64;
        // The timer ticks twice a second; work only when the second changed.
        if self.last_tick.replace(Some(now)) == Some(now) {
            return;
        }
        for rd in self.rows.borrow().iter() {
            let period = rd.period as u64;
            let remaining = period - (now % period);
            let step = now / period;
            if rd.shown_step.replace(Some(step)) != Some(step) {
                match generate_totp(&rd.secret, rd.algorithm, rd.digits, rd.period, now) {
                    Ok(code) => rd.code_label.set_label(&group_code(&code)),
                    Err(_) => rd.code_label.set_label("—"),
                }
            }
            rd.progress.set_value(remaining as f64 / period as f64);
            rd.countdown_label.set_label(&format!("{remaining} s"));
            rd.countdown_label.set_tooltip_text(Some(
                &trn!(
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
        let dialog = big_gtk_kit::alert::Alert::builder(Some(&self.root))
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
                // Keep the type and fields the desktop does not edit yet.
                item_type: None,
                extra: None,
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
        dialog.present();
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
        let dialog = big_gtk_kit::alert::Alert::builder(Some(&self.root))
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
        dialog.present();
    }

    /// Add a code to an existing access or create a new one. The text
    /// explains where the setup key comes from, so nobody pastes the six
    /// digits shown by another app instead.
    fn show_add_dialog(self: &Rc<Self>, anchor: &impl IsA<gtk::Widget>) {
        if !self.can_show_vault_data() {
            return;
        }
        let dialog = big_gtk_kit::dialog::Dialog::builder(Some(anchor))
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
                "On the site you want to protect, open the two-step verification settings and choose an authenticator app. Read the QR code it shows, or copy the setup key (the letters and numbers shown under the QR code, often behind “Can't scan it?”) and paste it below."
            ))
            .wrap(true)
            .xalign(0.0)
            .build();
        explain.add_css_class("ashy-note");
        content.append(&explain);
        let migrate = gtk::Label::builder()
            .label(tr!(
                "Coming from Google Authenticator? There, open the menu, choose Transfer accounts → Export accounts, and read the QR code it shows here: all its codes come at once."
            ))
            .wrap(true)
            .xalign(0.0)
            .build();
        migrate.add_css_class("dim-label");
        content.append(&migrate);

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
        let key_row = big_gtk_kit::password::password_row(
            adw::PasswordEntryRow::builder().title(tr!("Setup key or otpauth:// link")),
        );
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

        // Reading the QR code shown by the site fills the key (and, for a
        // new access, the name and account it carries).
        let qr_group = adw::PreferencesGroup::builder()
            .title(tr!("Read the QR code"))
            .description(tr!(
                "The image is read on this computer only. A screen capture is deleted right after reading."
            ))
            .build();
        let qr_status = gtk::Label::builder()
            .xalign(0.0)
            .wrap(true)
            .visible(false)
            .margin_top(8)
            .build();
        qr_status.set_accessible_role(gtk::AccessibleRole::Status);
        let qr_buttons = {
            let key_row = key_row.clone();
            let title_row = title_row.clone();
            let user_row = user_row.clone();
            let target_row = target_row.clone();
            let qr_status = qr_status.clone();
            let weak = Rc::downgrade(self);
            let dialog_weak = dialog.downgrade();
            crate::ui::qr_scan::scan_buttons(move |result| {
                if let crate::ui::qr_scan::ScanResult::Migration(uri) = &result {
                    if let (Some(inner), Some(dialog)) = (weak.upgrade(), dialog_weak.upgrade()) {
                        inner.offer_migration(uri, &dialog, &qr_status);
                        return;
                    }
                }
                qr_status.set_label(crate::ui::qr_scan::message_for(&result));
                qr_status.set_visible(true);
                if let crate::ui::qr_scan::ScanResult::Otpauth(uri) = result {
                    qr_status.remove_css_class("error");
                    key_row.set_text(&uri);
                    if target_row.selected() == 0 {
                        if let Ok(parsed) = ashypass_core::totp::parse_otpauth(&uri) {
                            if title_row.text().is_empty() {
                                let name = if parsed.issuer.is_empty() {
                                    parsed.label.clone()
                                } else {
                                    parsed.issuer.clone()
                                };
                                title_row.set_text(&name);
                            }
                            if user_row.text().is_empty() && !parsed.issuer.is_empty() {
                                user_row.set_text(&parsed.label);
                            }
                        }
                    }
                } else {
                    qr_status.add_css_class("error");
                }
            })
        };
        let qr_box = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .build();
        qr_box.append(&qr_buttons);
        qr_box.append(&qr_status);
        qr_group.add(&qr_box);
        content.insert_child_after(&qr_group, Some(&target_group));

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
            let dialog = dialog.downgrade();
            cancel.connect_clicked(move |_| {
                if let Some(dialog) = dialog.upgrade() {
                    dialog.close();
                }
            });
        }
        {
            let error = error.clone();
            key_row.connect_changed(move |row| {
                error.set_visible(false);
                row.remove_css_class("error");
            });
        }
        {
            let error = error.clone();
            title_row.connect_changed(move |row| {
                error.set_visible(false);
                row.remove_css_class("error");
            });
        }
        let weak = Rc::downgrade(self);
        // Weak: the button sits in the dialog.
        let dialog_weak = dialog.downgrade();
        save.connect_clicked(move |_| {
            let (Some(inner), Some(dialog_cl)) = (weak.upgrade(), dialog_weak.upgrade()) else {
                return;
            };
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
                        item_type: None,
                        extra: None,
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
                            // Keep the type and fields the desktop does not edit yet.
                            item_type: None,
                            extra: None,
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
        dialog.present();
    }

    /// A Google Authenticator export read in *Add verification code*: ask,
    /// then add each of its codes as a new access. A code already here (same
    /// name and account) is skipped, so reading the same export twice adds
    /// nothing.
    fn offer_migration(self: &Rc<Self>, uri: &str, add_dialog: &adw::Dialog, status: &gtk::Label) {
        let migration = match ashypass_core::totp::parse_migration(uri) {
            Ok(migration) if !migration.codes.is_empty() => migration,
            _ => {
                status.set_label(tr!(
                    "This Google Authenticator export has no codes that can be used here."
                ));
                status.add_css_class("error");
                status.set_visible(true);
                return;
            }
        };
        let existing: Vec<(String, String)> = self
            .state
            .vault
            .borrow()
            .list(None)
            .unwrap_or_default()
            .into_iter()
            .filter(|e| e.has_totp)
            .map(|e| (e.title, e.username.unwrap_or_default()))
            .collect();
        let entries = migration_entries(migration.codes, &existing);
        if entries.is_empty() {
            status.set_label(tr!("Every code in this export is already in the vault."));
            status.remove_css_class("error");
            status.set_visible(true);
            return;
        }
        let names: Vec<&str> = entries.iter().map(|e| e.title.as_str()).collect();
        let mut body = names.join(", ");
        if migration.unsupported > 0 {
            body.push_str("\n\n");
            body.push_str(&trn!(
                "One code uses a counter or an algorithm Ashy Pass does not support and is left out.",
                "Some codes use a counter or an algorithm Ashy Pass does not support and are left out.",
                migration.unsupported
            ));
        }
        let heading = trn!(
            "Add {} code from Google Authenticator?",
            "Add {} codes from Google Authenticator?",
            entries.len()
        )
        .replace("{}", &entries.len().to_string());
        let alert = big_gtk_kit::alert::Alert::builder(Some(add_dialog))
            .heading(&heading)
            .body(&body)
            .default_response("add")
            .close_response("cancel")
            .build();
        alert.add_response("cancel", tr!("Cancel"));
        alert.add_response("add", tr!("Add codes"));
        alert.set_response_appearance("add", adw::ResponseAppearance::Suggested);
        let inner = self.clone();
        let add_dialog = add_dialog.downgrade();
        let entries = RefCell::new(entries);
        alert.connect_response(None, move |_, response| {
            if response != "add" || !inner.can_show_vault_data() {
                return;
            }
            let total = entries.borrow().len();
            let mut added = 0;
            for entry in entries.borrow_mut().drain(..) {
                match inner.state.vault.borrow().add(entry) {
                    Ok(_) => added += 1,
                    Err(e) => log::warn!("could not add an imported code: {e}"),
                }
            }
            inner.reload();
            if added == total {
                inner.toast(
                    &trn!("{} code added", "{} codes added", added)
                        .replace("{}", &added.to_string()),
                );
            } else {
                inner.toast(
                    &tr!("{added} of {total} codes added; the others could not be saved")
                        .replace("{added}", &added.to_string())
                        .replace("{total}", &total.to_string()),
                );
            }
            if let Some(dialog) = add_dialog.upgrade() {
                dialog.close();
            }
        });
        alert.present();
    }
}

/// New accesses for the codes of a Google Authenticator export: named after
/// the issuer (the account under it), or the account when there is none.
/// Codes already in the vault, by name and account, are left out.
fn migration_entries(
    codes: Vec<ashypass_core::totp::OtpAuth>,
    existing: &[(String, String)],
) -> Vec<NewEntry> {
    codes
        .into_iter()
        .map(|code| {
            let (title, username) = if code.issuer.is_empty() {
                (code.label, None)
            } else {
                (code.issuer, Some(code.label).filter(|l| !l.is_empty()))
            };
            NewEntry {
                item_type: None,
                extra: None,
                title,
                username,
                password: String::new(),
                url: None,
                notes: None,
                totp_secret: Some(code.secret),
                totp_algorithm: Some(code.algorithm.as_str().to_string()),
                totp_digits: Some(code.digits),
                totp_period: Some(code.period),
                category: None,
            }
        })
        .filter(|new| {
            let key = (new.title.clone(), new.username.clone().unwrap_or_default());
            !existing.contains(&key)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_export_becomes_new_accesses_without_duplicates() {
        let code = |issuer: &str, label: &str| ashypass_core::totp::OtpAuth {
            label: label.to_string(),
            issuer: issuer.to_string(),
            secret: "JBSWY3DPEHPK3PXP".to_string(),
            algorithm: Algorithm::Sha1,
            digits: 6,
            period: 30,
        };
        let existing = vec![("GitHub".to_string(), "ana".to_string())];
        let entries = migration_entries(
            vec![
                code("GitHub", "ana"),
                code("Google", "ana@example.com"),
                code("", "router"),
            ],
            &existing,
        );
        let names: Vec<(&str, Option<&str>)> = entries
            .iter()
            .map(|e| (e.title.as_str(), e.username.as_deref()))
            .collect();
        assert_eq!(
            names,
            [("Google", Some("ana@example.com")), ("router", None)]
        );
        assert_eq!(entries[0].totp_algorithm.as_deref(), Some("SHA1"));
        assert_eq!(entries[0].totp_secret.as_deref(), Some("JBSWY3DPEHPK3PXP"));
    }
}
