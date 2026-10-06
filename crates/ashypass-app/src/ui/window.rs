//! Main window: navigation sidebar, the page stack and the shared unlock
//! screen.
//!
//! The sidebar lists destinations only — *My passwords*, *Verification
//! codes*, *Create password*, then *Backups* and *Settings*. Locking is a
//! button, not a page; external drives live under *Tools* in the main menu.
//!
//! Pages that need the vault show the shared unlock screen while it is
//! locked; *Create password* keeps working. A password created on that page
//! survives the unlock: *Save to vault…* asks to unlock and then opens the
//! entry form with the same value.
//!
//! Width breakpoints collapse the list/details split first and then the
//! sidebar, so the window stays usable from phone-like widths up.

use crate::session::SessionManager;
use crate::state::SharedState;
use crate::tr;
use crate::trn;
use crate::ui::backups_view::BackupsView;
use crate::ui::unlock_view::UnlockView;
use crate::ui::widgets::Chrome;
use crate::ui::{
    drives_view::DrivesView, generator_view::GeneratorView, settings_dialog, totp_view::TotpView,
    vault_view::VaultView,
};
use adw::prelude::*;
use gtk::{gio, glib};
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use zeroize::Zeroizing;

type WindowAction = Box<dyn Fn(&Rc<MainWindowInner>)>;

const DEFAULT_WIDTH: i32 = 960;
const DEFAULT_HEIGHT: i32 = 720;
const MIN_WIDTH: i32 = 360;
const MIN_HEIGHT: i32 = 480;

/// Destinations shown in the sidebar, in order.
const NAV: &[(&str, &str)] = &[
    ("vault", "dialog-password-symbolic"),
    ("totp", "security-high-symbolic"),
    ("generator", "list-add-symbolic"),
    ("backups", "document-save-symbolic"),
    ("settings", "emblem-system-symbolic"),
];

fn nav_label(name: &str) -> &'static str {
    match name {
        "vault" => tr!("My passwords"),
        "totp" => tr!("Verification codes"),
        "generator" => tr!("Create password"),
        "backups" => tr!("Backups"),
        "settings" => tr!("Settings"),
        "drives" => tr!("External drives"),
        _ => "",
    }
}

fn requires_vault(page: &str) -> bool {
    matches!(page, "vault" | "totp" | "backups")
}

pub struct MainWindow {
    pub window: adw::ApplicationWindow,
    inner: Rc<MainWindowInner>,
}

struct MainWindowInner {
    state: SharedState,
    window: adw::ApplicationWindow,
    toast_overlay: adw::ToastOverlay,
    split: adw::OverlaySplitView,
    nav_list: gtk::ListBox,
    lock_button: gtk::Button,
    lock_banner: adw::Banner,
    gate: gtk::Stack,
    pages: gtk::Stack,
    current: Cell<&'static str>,
    pending_page: Cell<Option<&'static str>>,
    /// A password created on the generator page while the vault was locked,
    /// waiting for the unlock to open the entry form.
    pending_password: RefCell<Option<Zeroizing<String>>>,
    banner_timer: RefCell<Option<glib::SourceId>>,
    unlock_view: Rc<UnlockView>,
    vault_view: Rc<VaultView>,
    totp_view: Rc<TotpView>,
    generator_view: GeneratorView,
    backups_view: Rc<BackupsView>,
    auto_sync: crate::auto_sync::Handle,
}

impl MainWindow {
    pub fn new(app: &adw::Application, state: SharedState) -> Self {
        let window = adw::ApplicationWindow::builder()
            .application(app)
            .title("Ashy Pass")
            .default_width(DEFAULT_WIDTH)
            .default_height(DEFAULT_HEIGHT)
            .width_request(MIN_WIDTH)
            .height_request(MIN_HEIGHT)
            .build();

        let toast_overlay = adw::ToastOverlay::new();
        let split = adw::OverlaySplitView::builder()
            .min_sidebar_width(190.0)
            .max_sidebar_width(250.0)
            .sidebar_width_fraction(0.22)
            .build();

        let menu = gio::Menu::new();
        let tools = gio::Menu::new();
        tools.append(Some(tr!("External drives")), Some("win.drives"));
        menu.append_section(Some(tr!("Tools")), &tools);
        let help = gio::Menu::new();
        help.append(Some(tr!("Keyboard shortcuts")), Some("win.shortcuts"));
        help.append(Some(tr!("About Ashy Pass")), Some("app.about"));
        menu.append_section(None, &help);
        let quit = gio::Menu::new();
        quit.append(Some(tr!("Quit")), Some("app.quit"));
        menu.append_section(None, &quit);
        let chrome = Chrome {
            split: split.clone(),
            menu,
        };

        // ---- Pages -----------------------------------------------------
        let unlock_view = UnlockView::new(state.clone());
        let vault_view = VaultView::new(state.clone(), toast_overlay.clone(), &chrome);
        let totp_view = TotpView::new(state.clone(), toast_overlay.clone(), &chrome);
        let generator_view = GeneratorView::new(state.clone(), toast_overlay.clone(), &chrome);
        let backups_view = BackupsView::new(state.clone(), toast_overlay.clone(), &chrome);
        let drives_view = DrivesView::new(toast_overlay.clone());
        let drives_page = adw::ToolbarView::new();
        let drives_title = gtk::Label::new(Some(tr!("External drives")));
        drives_title.add_css_class("heading");
        drives_page.add_top_bar(&chrome.header(Some(drives_title.upcast_ref())));
        drives_page.set_content(Some(&drives_view.root));

        let pages = gtk::Stack::builder()
            .transition_type(gtk::StackTransitionType::Crossfade)
            .transition_duration(150)
            .build();
        pages.add_named(&vault_view.root, Some("vault"));
        pages.add_named(&totp_view.root, Some("totp"));
        pages.add_named(&generator_view.root, Some("generator"));
        pages.add_named(&backups_view.root, Some("backups"));
        pages.add_named(&drives_page, Some("drives"));

        let unlock_page = adw::ToolbarView::new();
        unlock_page.add_top_bar(&chrome.header(None));
        unlock_page.set_content(Some(&unlock_view.root));

        let gate = gtk::Stack::builder()
            .transition_type(gtk::StackTransitionType::Crossfade)
            .transition_duration(150)
            .vexpand(true)
            .build();
        gate.add_named(&unlock_page, Some("unlock"));
        gate.add_named(&pages, Some("pages"));

        // Pre-lock warning: a banner, not a small toast, with time to react.
        let lock_banner = adw::Banner::builder()
            .button_label(tr!("Keep using"))
            .revealed(false)
            .build();
        let content = gtk::Box::new(gtk::Orientation::Vertical, 0);
        content.append(&lock_banner);
        content.append(&gate);
        split.set_content(Some(&content));

        // ---- Sidebar ---------------------------------------------------
        let sidebar_toolbar = adw::ToolbarView::new();
        let sidebar_header = adw::HeaderBar::builder()
            .show_end_title_buttons(false)
            .build();
        let brand = gtk::Box::builder()
            .orientation(gtk::Orientation::Horizontal)
            .spacing(8)
            .build();
        let brand_icon = gtk::Image::builder()
            .icon_name("ashypass")
            .pixel_size(24)
            .build();
        brand_icon.set_accessible_role(gtk::AccessibleRole::Presentation);
        let brand_label = gtk::Label::new(Some("Ashy Pass"));
        brand_label.add_css_class("heading");
        brand.append(&brand_icon);
        brand.append(&brand_label);
        sidebar_header.set_title_widget(Some(&brand));
        sidebar_toolbar.add_top_bar(&sidebar_header);

        let nav_list = gtk::ListBox::builder()
            .selection_mode(gtk::SelectionMode::Single)
            .build();
        nav_list.add_css_class("navigation-sidebar");
        nav_list.update_property(&[gtk::accessible::Property::Label(tr!("Sections"))]);
        for (name, icon) in NAV {
            let row = gtk::ListBoxRow::new();
            row.set_widget_name(name);
            let row_box = gtk::Box::builder()
                .orientation(gtk::Orientation::Horizontal)
                .spacing(12)
                .margin_top(4)
                .margin_bottom(4)
                .margin_start(4)
                .margin_end(4)
                .build();
            let image = gtk::Image::from_icon_name(icon);
            image.set_accessible_role(gtk::AccessibleRole::Presentation);
            row_box.append(&image);
            row_box.append(
                &gtk::Label::builder()
                    .label(nav_label(name))
                    .xalign(0.0)
                    .hexpand(true)
                    .ellipsize(gtk::pango::EllipsizeMode::End)
                    .build(),
            );
            row.set_child(Some(&row_box));
            if *name == "backups" {
                // Separate the everyday destinations from the rest.
                let separator = gtk::ListBoxRow::builder()
                    .selectable(false)
                    .activatable(false)
                    .can_focus(false)
                    .child(&gtk::Separator::new(gtk::Orientation::Horizontal))
                    .build();
                separator.add_css_class("ashy-nav-separator");
                separator.set_accessible_role(gtk::AccessibleRole::Separator);
                nav_list.append(&separator);
            }
            nav_list.append(&row);
        }
        let nav_scroll = gtk::ScrolledWindow::builder()
            .hscrollbar_policy(gtk::PolicyType::Never)
            .vexpand(true)
            .child(&nav_list)
            .build();

        let lock_button = gtk::Button::builder()
            .margin_start(12)
            .margin_end(12)
            .margin_bottom(12)
            .margin_top(6)
            .visible(false)
            .tooltip_text(tr!("Lock the vault now (Ctrl+L)"))
            .build();
        let lock_box = gtk::Box::builder()
            .orientation(gtk::Orientation::Horizontal)
            .spacing(10)
            .build();
        lock_box.append(&gtk::Image::from_icon_name("system-lock-screen-symbolic"));
        lock_box.append(&gtk::Label::new(Some(tr!("Lock"))));
        lock_button.set_child(Some(&lock_box));
        lock_button.add_css_class("ashy-lock-button");

        let sidebar_box = gtk::Box::new(gtk::Orientation::Vertical, 0);
        sidebar_box.append(&nav_scroll);
        sidebar_box.append(&lock_button);
        sidebar_toolbar.set_content(Some(&sidebar_box));
        split.set_sidebar(Some(&sidebar_toolbar));

        toast_overlay.set_child(Some(&split));
        window.set_content(Some(&toast_overlay));

        // ---- Adaptive breakpoints -------------------------------------
        let medium = adw::Breakpoint::new(adw::BreakpointCondition::new_length(
            adw::BreakpointConditionLengthType::MaxWidth,
            1400.0,
            adw::LengthUnit::Sp,
        ));
        medium.add_setter(&vault_view.root, "collapsed", Some(&true.to_value()));
        let narrow = adw::Breakpoint::new(adw::BreakpointCondition::new_length(
            adw::BreakpointConditionLengthType::MaxWidth,
            620.0,
            adw::LengthUnit::Sp,
        ));
        narrow.add_setter(&vault_view.root, "collapsed", Some(&true.to_value()));
        narrow.add_setter(&split, "collapsed", Some(&true.to_value()));
        window.add_breakpoint(medium);
        window.add_breakpoint(narrow);

        // Typing anywhere on the list goes to its search box.
        vault_view.set_key_capture(&vault_view.root);

        let auto_sync = crate::auto_sync::install(state.clone(), toast_overlay.clone());

        let inner = Rc::new(MainWindowInner {
            state: state.clone(),
            window: window.clone(),
            toast_overlay: toast_overlay.clone(),
            split,
            nav_list,
            lock_button: lock_button.clone(),
            lock_banner,
            gate,
            pages,
            current: Cell::new("vault"),
            pending_page: Cell::new(None),
            pending_password: RefCell::new(None),
            banner_timer: RefCell::new(None),
            unlock_view: unlock_view.clone(),
            vault_view: vault_view.clone(),
            totp_view: totp_view.clone(),
            generator_view,
            backups_view,
            auto_sync,
        });

        wire(&inner, app);

        // Apply the persisted auto-lock delay.
        {
            let s = state.settings();
            state.session.borrow_mut().timeout_seconds = s.lock_timeout.max(15);
        }

        // Startup: one try at the opt-in keyring unlock, then the vault.
        if !inner.unlock_view.try_keyring_unlock() {
            inner.show_page("vault");
            inner.unlock_view.focus();
        }

        Self { window, inner }
    }

    pub fn present(&self) {
        self.window.present();
    }

    /// Lock from outside the window (screen lock, suspend).
    pub fn lock_handle(&self) -> Rc<dyn Fn()> {
        let weak = Rc::downgrade(&self.inner);
        Rc::new(move || {
            if let Some(inner) = weak.upgrade() {
                inner.lock_now(false);
            }
        })
    }

    #[cfg(debug_assertions)]
    pub fn dev(&self) -> DevHandle {
        DevHandle {
            inner: self.inner.clone(),
        }
    }
}

fn wire(inner: &Rc<MainWindowInner>, app: &adw::Application) {
    // Sidebar selection.
    {
        let weak = Rc::downgrade(inner);
        inner.nav_list.connect_row_activated(move |_, row| {
            let Some(inner) = weak.upgrade() else { return };
            let name = row.widget_name();
            if let Some(page) = NAV.iter().map(|(n, _)| *n).find(|n| *n == name.as_str()) {
                inner.on_nav(page);
            }
        });
    }
    // Only activation navigates: a click both selects and activates a row,
    // and reacting to both opened Settings twice.
    {
        let weak = Rc::downgrade(inner);
        inner.lock_button.connect_clicked(move |_| {
            if let Some(inner) = weak.upgrade() {
                inner.lock_now(false);
            }
        });
    }

    // Unlock screen → back to where the user was going.
    {
        let weak = Rc::downgrade(inner);
        inner.unlock_view.set_on_unlocked(Box::new(move || {
            if let Some(inner) = weak.upgrade() {
                inner.on_unlocked();
            }
        }));
    }
    {
        let weak = Rc::downgrade(inner);
        let _permanent = inner.state.events.subscribe(move |event| {
            if matches!(event, crate::events::AppEvent::VaultUnlocked) {
                if let Some(inner) = weak.upgrade() {
                    if inner.unlocked() {
                        inner.on_unlocked();
                    }
                }
            }
        });
    }
    {
        let weak = Rc::downgrade(inner);
        inner.unlock_view.set_on_import_help(Box::new(move || {
            if let Some(inner) = weak.upgrade() {
                inner.show_import_help();
            }
        }));
    }
    {
        let weak = Rc::downgrade(inner);
        inner
            .generator_view
            .panel
            .set_on_primary(Box::new(move |value| {
                if let Some(inner) = weak.upgrade() {
                    inner.save_generated(Zeroizing::new(value));
                }
            }));
    }
    {
        let weak = Rc::downgrade(inner);
        inner.vault_view.set_on_import(Box::new(move || {
            if let Some(inner) = weak.upgrade() {
                inner.show_page("backups");
                inner.backups_view.show_import();
            }
        }));
    }
    {
        let weak = Rc::downgrade(inner);
        inner
            .backups_view
            .set_on_replace(Box::new(move |path, master, file_password| {
                if let Some(inner) = weak.upgrade() {
                    inner.replace_vault(path, master, file_password);
                }
            }));
    }
    {
        let weak = Rc::downgrade(inner);
        inner.vault_view.set_on_trash(Box::new(move || {
            if let Some(inner) = weak.upgrade() {
                settings_dialog::present_trash(&inner.window, inner.state.clone());
            }
        }));
    }

    // Idle lock and its warning.
    {
        let weak = Rc::downgrade(inner);
        let cb: Rc<dyn Fn()> = Rc::new(move || {
            if let Some(inner) = weak.upgrade() {
                inner.lock_now(true);
            }
        });
        inner.state.session.borrow_mut().set_lock_callback(cb);
    }
    {
        let weak = Rc::downgrade(inner);
        let cb: Rc<dyn Fn(u64)> = Rc::new(move |remaining| {
            if let Some(inner) = weak.upgrade() {
                inner.show_lock_warning(remaining);
                inner
                    .state
                    .events
                    .emit(crate::events::AppEvent::SessionWarning {
                        seconds_left: remaining,
                    });
            }
        });
        inner.state.session.borrow_mut().set_warning_callback(cb);
    }
    {
        let weak = Rc::downgrade(inner);
        inner.lock_banner.connect_button_clicked(move |_| {
            if let Some(inner) = weak.upgrade() {
                SessionManager::on_activity(&inner.state.session);
                inner.hide_lock_warning();
            }
        });
    }

    // Window-wide activity tracker (key + click). Capture phase: entries
    // consume key presses before they bubble back to the window.
    {
        let key = gtk::EventControllerKey::new();
        key.set_propagation_phase(gtk::PropagationPhase::Capture);
        let weak = Rc::downgrade(inner);
        key.connect_key_pressed(move |_, _, _, _| {
            if let Some(inner) = weak.upgrade() {
                inner.on_user_activity();
            }
            glib::Propagation::Proceed
        });
        inner.window.add_controller(key);
    }
    {
        let click = gtk::GestureClick::new();
        click.set_propagation_phase(gtk::PropagationPhase::Capture);
        let weak = Rc::downgrade(inner);
        click.connect_pressed(move |_, _, _, _| {
            if let Some(inner) = weak.upgrade() {
                inner.on_user_activity();
            }
        });
        inner.window.add_controller(click);
    }

    // ---- Actions and shortcuts ------------------------------------------
    let window = &inner.window;
    let add_action = |name: &str, accels: &[&str], run: WindowAction| {
        let action = gio::SimpleAction::new(name, None);
        let weak = Rc::downgrade(inner);
        action.connect_activate(move |_, _| {
            if let Some(inner) = weak.upgrade() {
                run(&inner);
            }
        });
        window.add_action(&action);
        if !accels.is_empty() {
            app.set_accels_for_action(&format!("win.{name}"), accels);
        }
    };
    add_action("search", &["<Primary>f"], Box::new(|i| i.focus_search()));
    add_action(
        "settings",
        &["<Primary>comma"],
        Box::new(|i| i.open_settings()),
    );
    add_action("new-entry", &["<Primary>n"], Box::new(|i| i.new_entry()));
    add_action(
        "lock",
        &["<Primary>l"],
        Box::new(|i| {
            if i.state.vault.borrow().is_unlocked() {
                i.lock_now(false);
            }
        }),
    );
    add_action(
        "nav-vault",
        &["<Primary>1"],
        Box::new(|i| i.show_page("vault")),
    );
    add_action(
        "nav-totp",
        &["<Primary>2"],
        Box::new(|i| i.show_page("totp")),
    );
    add_action(
        "nav-generator",
        &["<Primary>3"],
        Box::new(|i| i.show_page("generator")),
    );
    add_action(
        "nav-backups",
        &["<Primary>4"],
        Box::new(|i| i.show_page("backups")),
    );
    add_action("drives", &[], Box::new(|i| i.show_page("drives")));
    add_action(
        "shortcuts",
        &["<Primary>question", "F1"],
        Box::new(|i| show_shortcuts_window(&i.window)),
    );
}

impl MainWindowInner {
    fn unlocked(&self) -> bool {
        self.state.session.borrow().is_authenticated() && self.state.vault.borrow().is_unlocked()
    }

    fn toast(&self, message: &str, timeout: u32) {
        self.toast_overlay.add_toast(
            adw::Toast::builder()
                .title(message)
                .timeout(timeout)
                .build(),
        );
    }

    fn on_nav(self: &Rc<Self>, page: &'static str) {
        if page == "settings" {
            self.open_settings();
            // Settings is a dialog, not a place: keep the current page
            // highlighted.
            self.highlight_nav(self.current.get());
            return;
        }
        self.show_page(page);
    }

    fn highlight_nav(&self, page: &str) {
        let mut index = 0;
        let mut found = None;
        while let Some(row) = self.nav_list.row_at_index(index) {
            if row.widget_name() == page {
                found = Some(row);
                break;
            }
            index += 1;
        }
        self.nav_list.select_row(found.as_ref());
    }

    fn show_page(self: &Rc<Self>, page: &'static str) {
        self.current.set(page);
        self.highlight_nav(page);
        self.pages.set_visible_child_name(page);
        if requires_vault(page) && !self.unlocked() {
            self.pending_page.set(Some(page));
            self.unlock_view.refresh();
            self.gate.set_visible_child_name("unlock");
            self.unlock_view.focus();
        } else {
            self.gate.set_visible_child_name("pages");
        }
        self.window
            .set_title(Some(&format!("{} — Ashy Pass", nav_label(page))));
        if self.split.is_collapsed() {
            self.split.set_show_sidebar(false);
        }
        self.lock_button.set_visible(self.unlocked());
    }

    fn on_unlocked(self: &Rc<Self>) {
        self.lock_button.set_visible(true);
        self.vault_view.on_unlocked();
        self.totp_view.on_unlocked();
        self.backups_view.on_unlocked();
        self.auto_sync.on_vault_unlocked();
        let target = self.pending_page.take().unwrap_or(self.current.get());
        self.show_page(target);
        if let Some(password) = self.pending_password.borrow_mut().take() {
            self.show_page("vault");
            self.vault_view.show_add_dialog(Some(password));
        }
    }

    /// The single lock path for every trigger: sidebar button, Ctrl+L and
    /// the idle timer. Every view drops its secrets and open dialogs close.
    fn lock_now(self: &Rc<Self>, idle: bool) {
        self.hide_lock_warning();
        crate::clipboard::clear_now();
        let closed = self.state.close_sensitive_dialogs();
        self.state.vault.borrow_mut().lock();
        SessionManager::mark_locked(&self.state.session);
        self.vault_view.on_locked();
        self.totp_view.on_locked();
        self.backups_view.on_locked();
        self.unlock_view.on_locked();
        self.lock_button.set_visible(false);
        if requires_vault(self.current.get()) {
            self.pending_page.set(Some(self.current.get()));
            self.gate.set_visible_child_name("unlock");
            self.unlock_view.focus();
        }
        self.state
            .events
            .emit(crate::events::AppEvent::SessionLocked);
        if closed > 0 {
            self.toast(
                tr!("Vault locked. Open windows were closed; unsaved changes were discarded."),
                6,
            );
        } else if idle {
            self.toast(tr!("Vault locked after a period of inactivity"), 4);
        }
    }

    fn on_user_activity(&self) {
        SessionManager::on_activity(&self.state.session);
        if self.lock_banner.is_revealed() {
            self.hide_lock_warning();
        }
    }

    fn show_lock_warning(self: &Rc<Self>, remaining: u64) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(remaining);
        let update = {
            let banner = self.lock_banner.clone();
            move || {
                let left = deadline
                    .saturating_duration_since(std::time::Instant::now())
                    .as_secs();
                banner.set_title(
                    &trn!(
                        "The vault will lock in {} second because of inactivity.",
                        "The vault will lock in {} seconds because of inactivity.",
                        left as usize
                    )
                    .replace("{}", &left.to_string()),
                );
                left
            }
        };
        update();
        self.lock_banner.set_revealed(true);
        if let Some(id) = self.banner_timer.borrow_mut().take() {
            id.remove();
        }
        let weak = Rc::downgrade(self);
        let id = glib::timeout_add_seconds_local(1, move || {
            let left = update();
            if left == 0 {
                // Either the lock happened (and hid the banner) or an open
                // form is holding it off; a frozen "0 seconds" helps no one.
                if let Some(inner) = weak.upgrade() {
                    *inner.banner_timer.borrow_mut() = None;
                    inner.lock_banner.set_revealed(false);
                }
                return glib::ControlFlow::Break;
            }
            glib::ControlFlow::Continue
        });
        *self.banner_timer.borrow_mut() = Some(id);
    }

    fn hide_lock_warning(&self) {
        if let Some(id) = self.banner_timer.borrow_mut().take() {
            id.remove();
        }
        self.lock_banner.set_revealed(false);
    }

    fn save_generated(self: &Rc<Self>, value: Zeroizing<String>) {
        if self.unlocked() {
            self.show_page("vault");
            self.vault_view.show_add_dialog(Some(value));
            return;
        }
        *self.pending_password.borrow_mut() = Some(value);
        self.show_page("vault");
        self.toast(
            tr!("Unlock the vault to save the new password. It will not be lost."),
            6,
        );
    }

    fn new_entry(self: &Rc<Self>) {
        if !self.unlocked() {
            return;
        }
        if self.current.get() == "totp" {
            self.totp_view.show_add_dialog();
        } else {
            self.show_page("vault");
            self.vault_view.show_add_dialog(None);
        }
    }

    fn focus_search(self: &Rc<Self>) {
        if !self.unlocked() {
            return;
        }
        match self.current.get() {
            "totp" => self.totp_view.focus_search(),
            _ => {
                self.show_page("vault");
                self.vault_view.focus_search();
            }
        }
    }

    fn open_settings(self: &Rc<Self>) {
        settings_dialog::present(&self.window, self.state.clone(), self.toast_overlay.clone());
    }

    fn show_import_help(self: &Rc<Self>) {
        let dialog = adw::AlertDialog::builder()
            .heading(tr!("Bring your passwords"))
            .body(tr!(
                "From another app: create your vault first, then open Backups → Import passwords.\n\nFrom a copy made by Ashy Pass: restore it now. The vault will open with the master password of the copy."
            ))
            .close_response("ok")
            .build();
        dialog.add_response("ok", tr!("Understood"));
        dialog.add_response("restore", tr!("Restore a backup…"));
        dialog.set_default_response(Some("ok"));
        let weak = Rc::downgrade(self);
        dialog.connect_response(None, move |_, response| {
            if response == "restore" {
                if let Some(inner) = weak.upgrade() {
                    inner.backups_view.show_restore(&inner.window);
                }
            }
        });
        dialog.present(Some(&self.window));
    }

    /// Swap the live vault for a validated backup. The open vault is closed
    /// first (the restore refuses while another connection could still
    /// write), the core keeps a copy of the current file, and the restored
    /// vault reopens locked.
    fn replace_vault(
        self: &Rc<Self>,
        candidate: std::path::PathBuf,
        master: Zeroizing<String>,
        file_password: Option<Zeroizing<String>>,
    ) {
        if self.unlocked() {
            self.lock_now(false);
        }
        let live = ashypass_core::config::database_path();
        let placeholder_path = ashypass_core::config::data_dir()
            .join(format!(".restore-placeholder-{}.db", std::process::id()));
        let placeholder = match ashypass_core::db::Vault::open(&placeholder_path) {
            Ok(v) => v,
            Err(e) => {
                self.toast(&format!("{}: {e}", tr!("Nothing was restored")), 6);
                return;
            }
        };
        // Dropping the old vault closes its connection and checkpoints it.
        drop(self.state.install_vault(placeholder));
        self.toast(tr!("Restoring the copy…"), 3);
        let weak = Rc::downgrade(self);
        let worker_live = live.clone();
        crate::ui::settings_dialog::run_background_task(
            move || {
                ashypass_core::backup::restore_db_snapshot_with(
                    &worker_live,
                    &candidate,
                    &master,
                    file_password.as_deref().map(|s| s.as_str()),
                )
            },
            move |outcome| {
                let Some(inner) = weak.upgrade() else { return };
                // Reopen the live file whatever happened: on failure it is
                // still the previous vault, untouched.
                match ashypass_core::db::Vault::open(&live) {
                    Ok(vault) => {
                        drop(inner.state.install_vault(vault));
                        for suffix in ["", "-wal", "-shm"] {
                            let mut path = placeholder_path.clone().into_os_string();
                            path.push(suffix);
                            let _ = std::fs::remove_file(path);
                        }
                    }
                    Err(e) => {
                        // Never let the empty placeholder pose as the user's
                        // vault: stop here and ask for a restart.
                        log::error!("could not reopen the vault after restore: {e}");
                        let dialog = adw::AlertDialog::builder()
                            .heading(tr!("The vault could not be reopened"))
                            .body(format!(
                                "{}\n\n{e}",
                                tr!("Ashy Pass will close. Open it again to continue; your vault file was not deleted.")
                            ))
                            .build();
                        dialog.add_response("quit", tr!("Close Ashy Pass"));
                        let window = inner.window.clone();
                        dialog.connect_response(None, move |_, _| {
                            if let Some(app) = window.application() {
                                app.quit();
                            }
                        });
                        dialog.present(Some(&inner.window));
                        return;
                    }
                }
                inner
                    .state
                    .events
                    .emit(crate::events::AppEvent::VaultChanged);
                inner.unlock_view.refresh();
                inner.show_page("vault");
                let (heading, body) = match outcome {
                    Ok(done) => (
                        tr!("Backup restored").to_string(),
                        match done.previous_copy {
                            Some(previous) => format!(
                                "{}\n\n{}\n{}",
                                tr!("Unlock with the master password of the copy."),
                                tr!("The previous vault was kept at:"),
                                previous.display()
                            ),
                            None => tr!("Unlock with the master password of the copy.").to_string(),
                        },
                    ),
                    Err(e) => (
                        tr!("Nothing was restored").to_string(),
                        format!("{}\n\n{e}", tr!("Your vault was not changed.")),
                    ),
                };
                let dialog = adw::AlertDialog::builder()
                    .heading(heading)
                    .body(body)
                    .build();
                dialog.add_response("ok", tr!("OK"));
                dialog.present(Some(&inner.window));
            },
        );
    }
}

fn show_shortcuts_window(parent: &adw::ApplicationWindow) {
    let dialog = adw::Dialog::builder()
        .title(tr!("Keyboard shortcuts"))
        .content_width(520)
        .content_height(560)
        .build();
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&adw::HeaderBar::new());
    let page = adw::PreferencesPage::new();
    let groups: &[(&str, &[(&str, &str)])] = &[
        (
            tr!("Navigation"),
            &[
                ("Ctrl+1", tr!("My passwords")),
                ("Ctrl+2", tr!("Verification codes")),
                ("Ctrl+3", tr!("Create password")),
                ("Ctrl+4", tr!("Backups")),
                ("Ctrl+F", tr!("Go to search")),
            ],
        ),
        (
            tr!("Vault"),
            &[("Ctrl+N", tr!("Add password")), ("Ctrl+L", tr!("Lock"))],
        ),
        (
            tr!("Application"),
            &[
                ("Ctrl+,", tr!("Settings")),
                ("F1 / Ctrl+?", tr!("Keyboard shortcuts")),
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

// ============================================================================
// Development harness (debug builds only)
// ============================================================================

/// Drives the window from a script for visual checks. Never compiled into
/// release builds, and refuses to run against anything but a throwaway
/// data directory.
#[cfg(debug_assertions)]
pub struct DevHandle {
    inner: Rc<MainWindowInner>,
}

#[cfg(debug_assertions)]
impl DevHandle {
    pub fn run_step(&self, step: &str) {
        let inner = &self.inner;
        let (cmd, arg) = step.split_once(':').unwrap_or((step, ""));
        match cmd {
            "unlock" => inner.unlock_view.dev_submit(arg),
            "page" => {
                if let Some((name, _)) = NAV.iter().find(|(n, _)| *n == arg) {
                    inner.show_page(name);
                } else if arg == "drives" {
                    inner.show_page("drives");
                }
            }
            "open-first" => inner.vault_view.dev_open_first(),
            "search" => inner.vault_view.dev_search(arg),
            "add" => inner.vault_view.show_add_dialog(None),
            "add-code" => inner.totp_view.show_add_dialog(),
            "settings" => inner.open_settings(),
            "lock" => inner.lock_now(false),
            "warn" => inner.show_lock_warning(arg.parse().unwrap_or(20)),
            "gen-kind" => inner.generator_view.panel.dev_set_kind(arg),
            "gen-expand" => inner.generator_view.panel.dev_expand(arg != "0"),
            "save-generated" => {
                inner.save_generated(Zeroizing::new("Dev-Generated-Pass-123".into()))
            }
            "close-dialogs" => {
                inner.state.close_sensitive_dialogs();
            }
            "export" => {
                // export:<path>|<file password>
                if let Some((path, password)) = arg.split_once('|') {
                    let vault = inner.state.vault.borrow();
                    match ashypass_core::importers::ashy::export_vault(&vault, path, password) {
                        Ok(n) => eprintln!("dev: exported {n} entries to {path}"),
                        Err(e) => eprintln!("dev: export failed: {e}"),
                    }
                }
            }
            "replace" => {
                // replace:<path>|<master>|<file password>
                let parts: Vec<&str> = arg.splitn(3, '|').collect();
                if let [path, master, file] = parts[..] {
                    inner.replace_vault(
                        path.into(),
                        Zeroizing::new(master.to_string()),
                        Some(Zeroizing::new(file.to_string())),
                    );
                }
            }
            "import-csv" => crate::ui::import_flow::analyse(
                inner.state.clone(),
                inner.toast_overlay.clone(),
                inner.window.clone().upcast(),
                ashypass_core::importers::ImportSource::Csv,
                arg.into(),
            ),
            "clip-test" => {
                crate::clipboard::copy("clip-secret-123", 0);
                if let Some(display) = gtk::gdk::Display::default() {
                    let clipboard = display.clipboard();
                    eprintln!("dev: clipboard formats: {}", clipboard.formats().to_str());
                    clipboard.read_text_async(None::<&gio::Cancellable>, |res| {
                        eprintln!(
                            "dev: clipboard text = {:?}",
                            res.ok().flatten().map(|s| s.to_string())
                        );
                    });
                }
            }
            "click" => {
                // click:<button label> — anywhere in the window, dialogs included.
                match find_widget(&inner.window.clone().upcast(), &|w| {
                    button_label(w).as_deref() == Some(arg)
                }) {
                    Some(w) => {
                        if let Ok(button) = w.downcast::<gtk::Button>() {
                            button.emit_clicked();
                            eprintln!("dev: clicked {arg}");
                        }
                    }
                    None => eprintln!("dev: no button {arg}"),
                }
            }
            "field" => {
                // field:<row title> — print the text of an entry row.
                let found = find_widget(&inner.window.clone().upcast(), &|w| {
                    w.downcast_ref::<adw::EntryRow>()
                        .is_some_and(|row| row.title() == arg)
                });
                match found.and_then(|w| w.downcast::<adw::EntryRow>().ok()) {
                    Some(row) => eprintln!("dev: field {arg} = {:?}", row.text().len()),
                    None => eprintln!("dev: no field {arg}"),
                }
            }
            "count" => {
                let n = inner
                    .state
                    .vault
                    .borrow()
                    .list(None)
                    .map(|l| l.len())
                    .unwrap_or(0);
                eprintln!("dev: entries={n} unlocked={}", inner.unlocked());
            }
            "size" => {
                if let Some((w, h)) = arg.split_once('x') {
                    let w = w.parse().unwrap_or(DEFAULT_WIDTH);
                    let h = h.parse().unwrap_or(DEFAULT_HEIGHT);
                    inner.window.set_default_size(w, h);
                }
            }
            "dark" => adw::StyleManager::default().set_color_scheme(adw::ColorScheme::ForceDark),
            "light" => adw::StyleManager::default().set_color_scheme(adw::ColorScheme::ForceLight),
            "sidebar" => inner.split.set_show_sidebar(arg != "0"),
            other => log::warn!("unknown dev step: {other}"),
        }
    }

    pub fn window(&self) -> adw::ApplicationWindow {
        self.inner.window.clone()
    }

    pub fn state(&self) -> SharedState {
        self.inner.state.clone()
    }
}

#[cfg(debug_assertions)]
fn button_label(widget: &gtk::Widget) -> Option<String> {
    let button = widget.downcast_ref::<gtk::Button>()?;
    if let Some(label) = button.label() {
        return Some(label.to_string());
    }
    let child = button.child()?;
    if let Some(label) = child.downcast_ref::<gtk::Label>() {
        return Some(label.label().to_string());
    }
    if let Some(content) = child.downcast_ref::<adw::ButtonContent>() {
        return Some(content.label().to_string());
    }
    None
}

#[cfg(debug_assertions)]
fn find_widget(root: &gtk::Widget, test: &dyn Fn(&gtk::Widget) -> bool) -> Option<gtk::Widget> {
    if test(root) && root.is_mapped() {
        return Some(root.clone());
    }
    let mut child = root.first_child();
    while let Some(c) = child {
        if let Some(found) = find_widget(&c, test) {
            return Some(found);
        }
        child = c.next_sibling();
    }
    None
}
