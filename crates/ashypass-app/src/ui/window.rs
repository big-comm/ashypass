//! Main application window with OverlaySplitView (sidebar + content stack).
//!
//! Ported from the original `ui/window.py`. Aims for identical visual layout.

use crate::session::SessionManager;
use crate::state::SharedState;
use crate::tr;
use crate::ui::{
    drives_view::DrivesView, generator_view::GeneratorView, settings_dialog,
    totp_view::TotpView, vault_view::VaultView,
};
use adw::prelude::*;
use ashypass_core::config::{
    WINDOW_DEFAULT_HEIGHT, WINDOW_DEFAULT_WIDTH, WINDOW_MIN_HEIGHT, WINDOW_MIN_WIDTH,
};
use gtk::{gdk, gio};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

pub struct MainWindow {
    pub window: adw::ApplicationWindow,
    #[expect(dead_code, reason = "keeps view model alive for signal handlers")]
    inner: Rc<MainWindowInner>,
}

struct MainWindowInner {
    state: SharedState,
    toast_overlay: adw::ToastOverlay,
    content_stack: gtk::Stack,
    content_title: gtk::Label,
    search_button: gtk::ToggleButton,
    add_button: gtk::Button,
    lock_button: gtk::Button,
    nav_buttons: RefCell<HashMap<&'static str, gtk::Button>>,
    auth_separator: gtk::Separator,
    vault_view: Rc<VaultView>,
    totp_view: Rc<TotpView>,
}

impl MainWindow {
    pub fn new(app: &adw::Application, state: SharedState) -> Self {
        let window = adw::ApplicationWindow::builder()
            .application(app)
            .title("Ashy Pass")
            .default_width(WINDOW_DEFAULT_WIDTH)
            .default_height(WINDOW_DEFAULT_HEIGHT)
            .width_request(WINDOW_MIN_WIDTH)
            .height_request(WINDOW_MIN_HEIGHT)
            .build();

        let toast_overlay = adw::ToastOverlay::new();
        let split = adw::OverlaySplitView::builder()
            .min_sidebar_width(220.0)
            .max_sidebar_width(280.0)
            .sidebar_width_fraction(0.30)
            .build();

        // --- Build content area first so the sidebar callbacks can reference it ---
        let content_stack = gtk::Stack::builder()
            .transition_type(gtk::StackTransitionType::Crossfade)
            .transition_duration(200)
            .build();
        let content_title = gtk::Label::builder().label(tr!("Generator")).build();
        content_title.add_css_class("heading");

        let search_button = gtk::ToggleButton::builder()
            .icon_name("edit-find-symbolic")
            .tooltip_text(tr!("Search"))
            .visible(false)
            .build();

        let add_button = gtk::Button::builder()
            .icon_name("list-add-symbolic")
            .tooltip_text(tr!("Add Password"))
            .visible(false)
            .build();

        let lock_button = gtk::Button::builder()
            .icon_name("system-lock-screen-symbolic")
            .tooltip_text(tr!("Lock Vault"))
            .visible(false)
            .build();

        let vault_view = VaultView::new(state.clone(), toast_overlay.clone());
        let totp_view = TotpView::new(state.clone(), toast_overlay.clone());
        let generator_view = GeneratorView::new(toast_overlay.clone());
        let drives_view = DrivesView::new(toast_overlay.clone());

        content_stack.add_named(&vault_view.root, Some("vault"));
        content_stack.add_named(&totp_view.root, Some("totp"));
        content_stack.add_named(&generator_view.root, Some("generator"));
        content_stack.add_named(&drives_view.root, Some("drives"));

        // Build the content's ToolbarView (header + stack)
        let content_toolbar = adw::ToolbarView::new();
        let content_header = adw::HeaderBar::builder()
            .show_start_title_buttons(false)
            .title_widget(&content_title)
            .build();

        let menu = gio::Menu::new();
        let help_section = gio::Menu::new();
        help_section.append(Some(tr!("Keyboard Shortcuts")), Some("win.shortcuts"));
        menu.append_section(None, &help_section);
        let app_section = gio::Menu::new();
        app_section.append(Some(tr!("About")), Some("app.about"));
        app_section.append(Some(tr!("Quit")), Some("app.quit"));
        menu.append_section(None, &app_section);
        let menu_button = gtk::MenuButton::builder()
            .icon_name("open-menu-symbolic")
            .menu_model(&menu)
            .build();

        content_header.pack_end(&menu_button);
        content_header.pack_end(&add_button);
        content_header.pack_end(&lock_button);
        content_header.pack_start(&search_button);
        content_toolbar.add_top_bar(&content_header);
        content_toolbar.set_content(Some(&content_stack));

        split.set_content(Some(&content_toolbar));

        // --- Sidebar ---
        let sidebar_toolbar = adw::ToolbarView::new();
        let sidebar_header = adw::HeaderBar::builder()
            .show_end_title_buttons(false)
            .build();
        let sidebar_title = gtk::Label::builder().label("Ashy Pass").build();
        sidebar_title.add_css_class("heading");
        sidebar_header.set_title_widget(Some(&sidebar_title));
        sidebar_toolbar.add_top_bar(&sidebar_header);

        let scroll = gtk::ScrolledWindow::builder()
            .hscrollbar_policy(gtk::PolicyType::Never)
            .vscrollbar_policy(gtk::PolicyType::Automatic)
            .vexpand(true)
            .build();
        let nav_box = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(2)
            .margin_start(8)
            .margin_end(8)
            .margin_top(6)
            .margin_bottom(12)
            .build();

        let nav_buttons: RefCell<HashMap<&'static str, gtk::Button>> = RefCell::new(HashMap::new());
        add_nav_item(
            &nav_box,
            &nav_buttons,
            "generator",
            "view-reveal-symbolic",
            tr!("Generator"),
        );
        add_nav_item(
            &nav_box,
            &nav_buttons,
            "vault",
            "dialog-password-symbolic",
            tr!("Vault"),
        );
        add_nav_item(
            &nav_box,
            &nav_buttons,
            "totp",
            "auth-sim-symbolic",
            tr!("2FA"),
        );
        add_nav_item(
            &nav_box,
            &nav_buttons,
            "drives",
            "drive-removable-media-symbolic",
            tr!("Drives"),
        );

        let auth_separator = gtk::Separator::builder()
            .orientation(gtk::Orientation::Horizontal)
            .margin_top(6)
            .margin_bottom(6)
            .visible(false)
            .build();
        nav_box.append(&auth_separator);

        add_nav_item(
            &nav_box,
            &nav_buttons,
            "groups",
            "folder-symbolic",
            tr!("Groups"),
        );
        nav_buttons
            .borrow()
            .get("groups")
            .unwrap()
            .set_visible(false);

        add_nav_item(
            &nav_box,
            &nav_buttons,
            "favorites",
            "emblem-favorite-symbolic",
            tr!("Favorites"),
        );
        nav_buttons
            .borrow()
            .get("favorites")
            .unwrap()
            .set_visible(false);

        add_nav_item(
            &nav_box,
            &nav_buttons,
            "lock",
            "system-lock-screen-symbolic",
            tr!("Lock"),
        );
        nav_buttons.borrow().get("lock").unwrap().set_visible(false);

        let bottom_sep = gtk::Separator::builder()
            .orientation(gtk::Orientation::Horizontal)
            .margin_top(6)
            .margin_bottom(6)
            .build();
        nav_box.append(&bottom_sep);
        add_nav_item(
            &nav_box,
            &nav_buttons,
            "settings",
            "emblem-system-symbolic",
            tr!("Settings"),
        );

        scroll.set_child(Some(&nav_box));
        sidebar_toolbar.set_content(Some(&scroll));
        split.set_sidebar(Some(&sidebar_toolbar));

        toast_overlay.set_child(Some(&split));
        window.set_content(Some(&toast_overlay));

        let inner = Rc::new(MainWindowInner {
            state: state.clone(),
            toast_overlay: toast_overlay.clone(),
            content_stack,
            content_title,
            search_button: search_button.clone(),
            add_button: add_button.clone(),
            lock_button: lock_button.clone(),
            nav_buttons,
            auth_separator,
            vault_view: vault_view.clone(),
            totp_view: totp_view.clone(),
        });

        // --- Wire up sidebar nav clicks ---
        for (name, btn) in inner.nav_buttons.borrow().iter() {
            let name = *name;
            let inner_cl = inner.clone();
            let window_cl = window.clone();
            btn.connect_clicked(move |_| {
                on_nav_clicked(&inner_cl, &window_cl, name);
            });
        }

        // Header buttons
        {
            let inner_cl = inner.clone();
            add_button.connect_clicked(move |_| inner_cl.on_add_clicked());
        }
        {
            let inner_cl = inner.clone();
            lock_button.connect_clicked(move |_| {
                inner_cl.vault_view.lock_vault();
                inner_cl.update_auth_nav();
            });
        }
        {
            let inner_cl = inner.clone();
            search_button.connect_toggled(move |b| inner_cl.on_search_toggled(b.is_active()));
        }

        // Apply persisted auto-lock timeout from settings
        {
            let s = ashypass_core::settings::Settings::load();
            state.session.borrow_mut().timeout_seconds = s.lock_timeout.max(15);
        }

        // Wire session lock callback to refresh the UI when timer expires.
        // Also publishes a `SessionLocked` event on the app bus so other views
        // can react without needing direct callback wiring.
        {
            let inner_cl = inner.clone();
            let toast_cl = toast_overlay.clone();
            let events = state.events.clone();
            let cb: Rc<dyn Fn()> = Rc::new(move || {
                inner_cl.vault_view.lock_vault();
                inner_cl.totp_view.on_locked();
                inner_cl.update_auth_nav();
                let toast = adw::Toast::builder()
                    .title(tr!("Vault locked due to inactivity"))
                    .timeout(4)
                    .build();
                toast_cl.add_toast(toast);
                events.emit(crate::events::AppEvent::SessionLocked);
            });
            state.session.borrow_mut().set_lock_callback(cb);
        }

        // Warning toast a few seconds before auto-lock, mirrored on the bus.
        {
            let toast_cl = toast_overlay.clone();
            let events = state.events.clone();
            let cb: Rc<dyn Fn(u64)> = Rc::new(move |remaining| {
                let toast = adw::Toast::builder()
                    .title(format!("{} ({}s)", tr!("Vault will lock soon"), remaining))
                    .timeout(3)
                    .build();
                toast_cl.add_toast(toast);
                events.emit(crate::events::AppEvent::SessionWarning {
                    seconds_left: remaining,
                });
            });
            state.session.borrow_mut().set_warning_callback(cb);
        }

        // Wire vault-view auth-changed callback to refresh sidebar
        {
            let inner_cl = inner.clone();
            vault_view.set_on_auth_changed(Box::new(move || {
                inner_cl.update_auth_nav();
            }));
        }
        {
            let inner_cl = inner.clone();
            totp_view.set_on_auth_changed(Box::new(move || {
                inner_cl.update_auth_nav();
            }));
        }
        {
            let inner_weak = Rc::downgrade(&inner);
            state.events.subscribe(move |event| {
                if matches!(
                    event,
                    crate::events::AppEvent::VaultChanged
                        | crate::events::AppEvent::SyncCompleted { .. }
                        | crate::events::AppEvent::SessionLocked
                ) {
                    if let Some(inner) = inner_weak.upgrade() {
                        inner.update_auth_nav();
                    }
                }
            });
        }

        // Window-wide activity tracker (key + click) — resets the auto-lock
        // timer whenever the user is doing something.
        {
            let key_ctl = gtk::EventControllerKey::new();
            let sess = state.session.clone();
            let inner_cl = inner.clone();
            let window_cl = window.clone();
            key_ctl.connect_key_pressed(move |_, keyval, _, modifiers| {
                SessionManager::on_activity(&sess);
                if inner_cl.handle_type_to_search(&window_cl, keyval, modifiers) {
                    glib::Propagation::Stop
                } else {
                    glib::Propagation::Proceed
                }
            });
            window.add_controller(key_ctl);
        }
        {
            let click_ctl = gtk::GestureClick::new();
            click_ctl.set_propagation_phase(gtk::PropagationPhase::Capture);
            let sess = state.session.clone();
            click_ctl.connect_pressed(move |_, _, _, _| {
                SessionManager::on_activity(&sess);
            });
            window.add_controller(click_ctl);
        }

        // Show generator by default (no auth required)
        inner.select_nav("generator");

        // Ctrl+F shortcut wires to focusing vault search entry
        let search_action = gio::SimpleAction::new("search", None);
        {
            let inner_cl = inner.clone();
            search_action.connect_activate(move |_, _| inner_cl.focus_search());
        }
        window.add_action(&search_action);
        app.set_accels_for_action("win.search", &["<Primary>f"]);

        let settings_action = gio::SimpleAction::new("settings", None);
        {
            let window_cl = window.clone();
            let state_cl = state.clone();
            let toast_cl = toast_overlay.clone();
            settings_action.connect_activate(move |_, _| {
                settings_dialog::present(&window_cl, state_cl.clone(), toast_cl.clone());
            });
        }
        window.add_action(&settings_action);
        app.set_accels_for_action("win.settings", &["<Primary>comma"]);

        let new_action = gio::SimpleAction::new("new-entry", None);
        {
            let inner_cl = inner.clone();
            new_action.connect_activate(move |_, _| {
                if inner_cl.state.session.borrow().is_authenticated() {
                    let current = inner_cl
                        .content_stack
                        .visible_child_name()
                        .map(|s| s.to_string())
                        .unwrap_or_default();
                    if current == "totp" {
                        inner_cl.totp_view.show_add_dialog();
                    } else {
                        inner_cl.select_nav("vault");
                        inner_cl.vault_view.show_add_dialog();
                    }
                }
            });
        }
        window.add_action(&new_action);
        app.set_accels_for_action("win.new-entry", &["<Primary>n"]);

        let lock_action = gio::SimpleAction::new("lock", None);
        {
            let inner_cl = inner.clone();
            lock_action.connect_activate(move |_, _| {
                if inner_cl.state.session.borrow().is_authenticated() {
                    inner_cl.vault_view.lock_vault();
                    SessionManager::logout(&inner_cl.state.session);
                    inner_cl.update_auth_nav();
                }
            });
        }
        window.add_action(&lock_action);
        app.set_accels_for_action("win.lock", &["<Primary>l"]);

        let nav_vault_action = gio::SimpleAction::new("nav-vault", None);
        {
            let inner_cl = inner.clone();
            nav_vault_action.connect_activate(move |_, _| inner_cl.select_nav("vault"));
        }
        window.add_action(&nav_vault_action);
        app.set_accels_for_action("win.nav-vault", &["<Primary>1"]);

        let nav_totp_action = gio::SimpleAction::new("nav-totp", None);
        {
            let inner_cl = inner.clone();
            nav_totp_action.connect_activate(move |_, _| inner_cl.select_nav("totp"));
        }
        window.add_action(&nav_totp_action);
        app.set_accels_for_action("win.nav-totp", &["<Primary>2"]);

        let nav_gen_action = gio::SimpleAction::new("nav-generator", None);
        {
            let inner_cl = inner.clone();
            nav_gen_action.connect_activate(move |_, _| inner_cl.select_nav("generator"));
        }
        window.add_action(&nav_gen_action);
        app.set_accels_for_action("win.nav-generator", &["<Primary>3"]);

        let shortcuts_action = gio::SimpleAction::new("shortcuts", None);
        {
            let window_cl = window.clone();
            shortcuts_action.connect_activate(move |_, _| {
                show_shortcuts_window(&window_cl);
            });
        }
        window.add_action(&shortcuts_action);
        app.set_accels_for_action("win.shortcuts", &["<Primary>question", "F1"]);

        Self { window, inner }
    }

    pub fn present(&self) {
        self.window.present();
    }
}

fn add_nav_item(
    parent: &gtk::Box,
    map: &RefCell<HashMap<&'static str, gtk::Button>>,
    name: &'static str,
    icon: &str,
    label: &str,
) {
    let btn = gtk::Button::new();
    btn.add_css_class("flat");

    let bx = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(10)
        .margin_start(8)
        .margin_end(8)
        .margin_top(6)
        .margin_bottom(6)
        .build();

    let img = gtk::Image::from_icon_name(icon);
    img.set_pixel_size(18);
    bx.append(&img);

    let lbl = gtk::Label::builder()
        .label(label)
        .xalign(0.0)
        .hexpand(true)
        .build();
    bx.append(&lbl);

    btn.set_child(Some(&bx));
    parent.append(&btn);
    map.borrow_mut().insert(name, btn);
}

fn on_nav_clicked(
    inner: &Rc<MainWindowInner>,
    window: &adw::ApplicationWindow,
    name: &'static str,
) {
    match name {
        "settings" => {
            settings_dialog::present(window, inner.state.clone(), inner.toast_overlay.clone());
        }
        "lock" => {
            inner.vault_view.lock_vault();
            SessionManager::logout(&inner.state.session);
            inner.update_auth_nav();
        }
        "groups" => {
            inner.highlight_nav("groups");
            inner.content_stack.set_visible_child_name("vault");
            inner.content_title.set_label(tr!("Groups"));
            inner.vault_view.show_groups_view();
            inner.add_button.set_visible(false);
            inner.lock_button.set_visible(false);
        }
        "favorites" => {
            inner.highlight_nav("favorites");
            inner.content_stack.set_visible_child_name("vault");
            inner.content_title.set_label(tr!("Favorites"));
            inner.vault_view.show_favorites_view();
            inner.add_button.set_visible(false);
            inner.lock_button.set_visible(false);
        }
        n => inner.select_nav(n),
    }
}

impl MainWindowInner {
    fn highlight_nav(&self, name: &str) {
        for (btn_name, btn) in self.nav_buttons.borrow().iter() {
            if *btn_name == name {
                btn.remove_css_class("flat");
                btn.add_css_class("suggested-action");
            } else {
                btn.remove_css_class("suggested-action");
                btn.add_css_class("flat");
            }
        }
    }

    fn select_nav(&self, name: &'static str) {
        self.highlight_nav(name);
        self.content_stack.set_visible_child_name(name);
        self.search_button.set_active(false);

        let title = match name {
            "vault" => tr!("Vault"),
            "totp" => tr!("2FA"),
            "generator" => tr!("Generator"),
            "drives" => tr!("Drives"),
            other => other,
        };
        self.content_title.set_label(title);

        let is_vault = name == "vault";
        let is_totp = name == "totp";
        let authed = self.state.session.borrow().is_authenticated();
        self.add_button.set_visible((is_vault || is_totp) && authed);
        self.lock_button.set_visible(is_vault && authed);

        self.update_auth_nav();

        if name == "totp" {
            self.totp_view.refresh();
            if !authed {
                self.totp_view.focus_auth_field();
            }
        } else if name == "vault" {
            self.vault_view.show_all_view();
            if !authed {
                self.vault_view.focus_auth_field();
            }
        }
    }

    fn update_auth_nav(&self) {
        let authed = self.state.session.borrow().is_authenticated();
        let current = self
            .content_stack
            .visible_child_name()
            .map(|s| s.to_string())
            .unwrap_or_default();
        let is_vault = current == "vault";
        let is_totp = current == "totp";
        let is_searchable = current == "vault" || current == "totp";

        self.add_button.set_visible((is_vault || is_totp) && authed);
        self.add_button.set_tooltip_text(Some(if is_totp {
            tr!("Add 2FA Code")
        } else {
            tr!("Add Password")
        }));
        self.lock_button.set_visible(is_vault && authed);
        self.search_button.set_visible(is_searchable && authed);

        self.auth_separator.set_visible(authed);
        let map = self.nav_buttons.borrow();
        if let Some(b) = map.get("groups") {
            b.set_visible(authed);
        }
        if let Some(b) = map.get("favorites") {
            b.set_visible(authed);
        }
        if let Some(b) = map.get("lock") {
            b.set_visible(authed);
        }
    }

    fn on_search_toggled(&self, active: bool) {
        let current = self
            .content_stack
            .visible_child_name()
            .map(|s| s.to_string())
            .unwrap_or_default();
        match current.as_str() {
            "vault" => {
                self.vault_view.search_bar.set_search_mode(active);
                if active {
                    self.vault_view.search_entry.grab_focus();
                }
            }
            "totp" => {
                self.totp_view.search_bar.set_search_mode(active);
                if active {
                    self.totp_view.search_entry.grab_focus();
                }
            }
            _ => {}
        }
    }

    fn on_add_clicked(&self) {
        if !self.state.session.borrow().is_authenticated() {
            return;
        }
        let current = self
            .content_stack
            .visible_child_name()
            .map(|s| s.to_string())
            .unwrap_or_default();
        match current.as_str() {
            "vault" => self.vault_view.show_add_dialog(),
            "totp" => self.totp_view.show_add_dialog(),
            _ => {}
        }
    }

    fn focus_search(&self) {
        let current = self
            .content_stack
            .visible_child_name()
            .map(|s| s.to_string())
            .unwrap_or_default();
        if !self.state.session.borrow().is_authenticated() {
            return;
        }
        match current.as_str() {
            "vault" => {
                self.search_button.set_active(true);
                self.vault_view.search_entry.grab_focus();
            }
            "totp" => {
                self.search_button.set_active(true);
                self.totp_view.search_entry.grab_focus();
            }
            _ => {}
        }
    }

    fn handle_type_to_search(
        &self,
        window: &adw::ApplicationWindow,
        keyval: gdk::Key,
        modifiers: gdk::ModifierType,
    ) -> bool {
        if self.search_button.is_active()
            || !self.search_button.is_visible()
            || !self.state.session.borrow().is_authenticated()
            || focus_is_text_input(gtk::prelude::GtkWindowExt::focus(window).as_ref())
            || modifiers.intersects(
                gdk::ModifierType::CONTROL_MASK
                    | gdk::ModifierType::ALT_MASK
                    | gdk::ModifierType::SUPER_MASK
                    | gdk::ModifierType::META_MASK,
            )
        {
            return false;
        }

        let Some(ch) = keyval.to_unicode() else {
            return false;
        };
        if ch.is_control() || ch.is_whitespace() {
            return false;
        }

        let current = self
            .content_stack
            .visible_child_name()
            .map(|s| s.to_string())
            .unwrap_or_default();
        match current.as_str() {
            "vault" => {
                self.search_button.set_active(true);
                self.vault_view.search_entry.set_text(&ch.to_string());
                self.vault_view.search_entry.set_position(-1);
                self.vault_view.search_entry.grab_focus();
                true
            }
            "totp" => {
                self.search_button.set_active(true);
                self.totp_view.search_entry.set_text(&ch.to_string());
                self.totp_view.search_entry.set_position(-1);
                self.totp_view.search_entry.grab_focus();
                true
            }
            _ => false,
        }
    }
}

fn focus_is_text_input(focus: Option<&gtk::Widget>) -> bool {
    let mut current = focus.cloned();
    while let Some(widget) = current {
        if widget.is::<gtk::Editable>()
            || widget.is::<gtk::TextView>()
            || widget.is::<gtk::SpinButton>()
            || widget.is::<adw::EntryRow>()
            || widget.is::<adw::PasswordEntryRow>()
        {
            return true;
        }
        current = widget.parent();
    }
    false
}

fn show_shortcuts_window(parent: &adw::ApplicationWindow) {
    let dialog = adw::Dialog::builder()
        .title(tr!("Keyboard Shortcuts"))
        .content_width(520)
        .content_height(560)
        .build();

    let toolbar = adw::ToolbarView::new();
    let header = adw::HeaderBar::new();
    toolbar.add_top_bar(&header);

    let page = adw::PreferencesPage::new();

    let groups: &[(&str, &[(&str, &str)])] = &[
        (
            tr!("Navigation"),
            &[
                ("Ctrl+1", tr!("Show Vault")),
                ("Ctrl+2", tr!("Show 2FA")),
                ("Ctrl+3", tr!("Show Generator")),
                ("Ctrl+F", tr!("Focus Search")),
            ],
        ),
        (
            tr!("Vault"),
            &[("Ctrl+N", tr!("New Entry")), ("Ctrl+L", tr!("Lock Vault"))],
        ),
        (
            tr!("Application"),
            &[
                ("Ctrl+,", tr!("Open Settings")),
                ("F1 / Ctrl+?", tr!("Keyboard Shortcuts")),
                ("Ctrl+Q", tr!("Quit")),
            ],
        ),
    ];

    for (group_title, shortcuts) in groups {
        let group = adw::PreferencesGroup::builder().title(*group_title).build();
        for (accel, label) in *shortcuts {
            let row = adw::ActionRow::builder().title(*label).build();
            let key_label = gtk::Label::builder()
                .label(*accel)
                .css_classes(vec!["dim-label".to_string(), "monospace".to_string()])
                .build();
            row.add_suffix(&key_label);
            group.add(&row);
        }
        page.add(&group);
    }

    toolbar.set_content(Some(&page));
    dialog.set_child(Some(&toolbar));
    dialog.present(Some(parent));
}
