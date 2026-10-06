//! "My passwords": find an access, copy its password, open its details.
//!
//! Layout: an `adw::NavigationSplitView` with the list on the left and the
//! details of the open access on the right. Narrow windows collapse it, so
//! opening an access replaces the list and *Back* returns to it (the window
//! drives `collapsed` with a breakpoint).
//!
//! Each row shows the name, the account and the domain, a visible *Copy
//! password* button and a *More* menu. Clicking the row opens the details; it
//! never copies silently. Folders and favourites are filters over the same
//! collection, and the search only searches this page.
//!
//! The list is a `gtk::ListView`: only visible rows get widgets, so typing in
//! the search box no longer rebuilds thousands of buttons.

use crate::session::SessionManager;
use crate::state::{SharedState, SyncStatus};
use crate::tr;
use crate::trn;
use crate::ui::entry_form::{self, EntryFormOptions};
use crate::ui::widgets::{
    account_line, copy_secret, display_domain, openable_url, Chrome, EmptyState,
};
use adw::prelude::*;
use ashypass_core::db::vault::PasswordEntry;
use ashypass_core::totp::{generate_totp, Algorithm};
use gtk::{gio, glib};
use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::rc::Rc;
use zeroize::Zeroizing;

const SEARCH_DEBOUNCE_MS: u64 = 80;

/// Which part of the collection the list shows.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub enum FolderFilter {
    #[default]
    All,
    NoFolder,
    Named(String),
}

impl FolderFilter {
    fn target(&self) -> String {
        match self {
            Self::All => "all".into(),
            Self::NoFolder => "none".into(),
            Self::Named(name) => format!("f:{name}"),
        }
    }

    fn from_target(target: &str) -> Self {
        match target {
            "none" => Self::NoFolder,
            t => match t.strip_prefix("f:") {
                Some(name) => Self::Named(name.to_string()),
                None => Self::All,
            },
        }
    }

    fn matches(&self, category: Option<&str>) -> bool {
        let category = category.map(str::trim).filter(|c| !c.is_empty());
        match self {
            Self::All => true,
            Self::NoFolder => category.is_none(),
            Self::Named(name) => category == Some(name.as_str()),
        }
    }

    fn label(&self) -> String {
        match self {
            Self::All => tr!("All folders").to_string(),
            Self::NoFolder => tr!("No folder").to_string(),
            Self::Named(name) => name.clone(),
        }
    }
}

/// Metadata of every entry, with a lowercase search index. Rebuilt only when
/// the vault changes, never per keystroke.
pub struct PasswordListCache {
    entries: Vec<Rc<PasswordEntry>>,
    search_index: Vec<String>,
    categories: Vec<String>,
}

impl PasswordListCache {
    pub fn new(entries: Vec<PasswordEntry>, categories: Vec<String>) -> Self {
        let search_index = entries.iter().map(password_search_text).collect();
        Self {
            entries: entries.into_iter().map(Rc::new).collect(),
            search_index,
            categories,
        }
    }

    pub fn filtered(
        &self,
        search: Option<&str>,
        folder: &FolderFilter,
        favorites_only: bool,
    ) -> Vec<Rc<PasswordEntry>> {
        let needle = search
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_lowercase);
        self.entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| folder.matches(entry.category.as_deref()))
            .filter(|(_, entry)| !favorites_only || entry.favorite)
            .filter(|(idx, _)| {
                needle
                    .as_ref()
                    .is_none_or(|needle| self.search_index[*idx].contains(needle))
            })
            .map(|(_, entry)| entry.clone())
            .collect()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

type Callback = Box<dyn Fn()>;
type RowAction = Box<dyn Fn(&Rc<Inner>, Rc<PasswordEntry>)>;

pub struct VaultView {
    pub root: adw::NavigationSplitView,
    inner: Rc<Inner>,
}

struct Inner {
    state: SharedState,
    toast: adw::ToastOverlay,
    split: adw::NavigationSplitView,

    search_entry: gtk::SearchEntry,
    folder_button: gtk::MenuButton,
    folder_menu: gio::Menu,
    folder_filter: RefCell<FolderFilter>,
    /// The stateful `vault.folder` actions, so the menu's radio mark follows
    /// changes made outside the menu (reset on lock, "Search all folders").
    folder_actions: RefCell<Vec<gio::SimpleAction>>,
    favorites_toggle: gtk::ToggleButton,
    count_label: gtk::Label,
    sync_label: gtk::Label,

    store: gio::ListStore,
    list_view: gtk::ListView,
    content_stack: gtk::Stack,
    empty: EmptyState,

    cache: RefCell<Option<Rc<PasswordListCache>>>,
    synced_ids: RefCell<Option<Rc<HashSet<i64>>>>,
    show_badges: Cell<bool>,
    show_favicons: Cell<bool>,
    search_reload_id: RefCell<Option<glib::SourceId>>,
    event_reload_id: RefCell<Option<glib::SourceId>>,

    details_page: adw::NavigationPage,
    details_toolbar: adw::ToolbarView,
    details_placeholder: gtk::Widget,
    open_id: Cell<Option<i64>>,
    details_timer: RefCell<Option<glib::SourceId>>,

    on_import: RefCell<Option<Callback>>,
    on_trash: RefCell<Option<Callback>>,
}

impl VaultView {
    pub fn new(state: SharedState, toast: adw::ToastOverlay, chrome: &Chrome) -> Rc<Self> {
        // ---- List page ------------------------------------------------
        let search_entry = gtk::SearchEntry::builder()
            .placeholder_text(tr!("Search by name, account or site"))
            .hexpand(true)
            .build();
        search_entry.update_property(&[gtk::accessible::Property::Label(tr!("Search passwords"))]);
        let search_clamp = adw::Clamp::builder()
            .maximum_size(420)
            .child(&search_entry)
            .build();
        let list_header = chrome.header(Some(search_clamp.upcast_ref()));
        let add_button = gtk::Button::builder()
            .icon_name("list-add-symbolic")
            .tooltip_text(tr!("Add password"))
            .build();
        add_button.add_css_class("suggested-action");
        add_button.update_property(&[gtk::accessible::Property::Label(tr!("Add password"))]);
        list_header.pack_end(&add_button);

        let page_menu = gio::Menu::new();
        page_menu.append(Some(tr!("Import passwords…")), Some("vault.import"));
        page_menu.append(
            Some(tr!("Organize folders…")),
            Some("vault.organize-folders"),
        );
        page_menu.append(Some(tr!("Deleted items…")), Some("vault.trash"));
        let page_menu_button = gtk::MenuButton::builder()
            .icon_name("view-more-symbolic")
            .menu_model(&page_menu)
            .tooltip_text(tr!("More options"))
            .build();
        page_menu_button.update_property(&[gtk::accessible::Property::Label(tr!("More options"))]);
        list_header.pack_end(&page_menu_button);

        let filter_bar = gtk::Box::builder()
            .orientation(gtk::Orientation::Horizontal)
            .spacing(8)
            .margin_top(6)
            .margin_bottom(6)
            .margin_start(12)
            .margin_end(12)
            .build();
        let folder_menu = gio::Menu::new();
        let folder_button = gtk::MenuButton::builder()
            .label(tr!("All folders"))
            .menu_model(&folder_menu)
            .tooltip_text(tr!("Show a folder"))
            .build();
        folder_button.add_css_class("flat");
        folder_button.set_always_show_arrow(true);
        let favorites_toggle = gtk::ToggleButton::builder()
            .tooltip_text(tr!("Show only favorites"))
            .build();
        let fav_box = gtk::Box::new(gtk::Orientation::Horizontal, 6);
        fav_box.append(&gtk::Image::from_icon_name("starred-symbolic"));
        fav_box.append(&gtk::Label::new(Some(tr!("Favorites"))));
        favorites_toggle.set_child(Some(&fav_box));
        favorites_toggle.add_css_class("flat");
        let count_label = gtk::Label::builder().hexpand(true).xalign(1.0).build();
        count_label.add_css_class("dim-label");
        count_label.add_css_class("caption");
        filter_bar.append(&folder_button);
        filter_bar.append(&favorites_toggle);
        filter_bar.append(&count_label);

        let store = gio::ListStore::new::<glib::BoxedAnyObject>();
        let selection = gtk::NoSelection::new(Some(store.clone()));
        let factory = gtk::SignalListItemFactory::new();
        let list_view = gtk::ListView::builder()
            .model(&selection)
            .factory(&factory)
            .single_click_activate(true)
            .build();
        list_view.add_css_class("ashy-entry-list");
        list_view.update_property(&[gtk::accessible::Property::Label(tr!("Passwords"))]);
        let list_scrolled = gtk::ScrolledWindow::builder()
            .hscrollbar_policy(gtk::PolicyType::Never)
            .vexpand(true)
            .child(&list_view)
            .build();

        let empty = EmptyState::new();
        let content_stack = gtk::Stack::builder()
            .transition_type(gtk::StackTransitionType::Crossfade)
            .vexpand(true)
            .build();
        content_stack.add_named(&list_scrolled, Some("list"));
        content_stack.add_named(&empty.root, Some("empty"));

        let sync_label = gtk::Label::builder()
            .wrap(true)
            .visible(false)
            .margin_top(6)
            .margin_bottom(8)
            .margin_start(12)
            .margin_end(12)
            .build();
        sync_label.add_css_class("caption");
        sync_label.add_css_class("dim-label");

        let list_body = gtk::Box::new(gtk::Orientation::Vertical, 0);
        list_body.append(&filter_bar);
        list_body.append(&content_stack);
        list_body.append(&sync_label);

        let list_toolbar = adw::ToolbarView::new();
        list_toolbar.add_top_bar(&list_header);
        list_toolbar.set_content(Some(&list_body));
        let list_page = adw::NavigationPage::builder()
            .title(tr!("My passwords"))
            .tag("list")
            .child(&list_toolbar)
            .build();

        // ---- Details page --------------------------------------------
        let details_toolbar = adw::ToolbarView::new();
        let placeholder = EmptyState::new();
        placeholder.set(
            "dialog-password-symbolic",
            tr!("Select an access"),
            tr!("Its user, password and other details appear here."),
        );
        let placeholder_widget: gtk::Widget = placeholder.root.clone().upcast();
        // The access name is already the page heading below.
        details_toolbar.add_top_bar(&adw::HeaderBar::builder().show_title(false).build());
        details_toolbar.set_content(Some(&placeholder_widget));
        let details_page = adw::NavigationPage::builder()
            .title(tr!("Details"))
            .tag("details")
            .child(&details_toolbar)
            .build();

        let split = adw::NavigationSplitView::builder()
            .sidebar(&list_page)
            .content(&details_page)
            // A fixed list width: a long value in the details (a URL, a
            // note) must not push the split around while browsing.
            .min_sidebar_width(560.0)
            .max_sidebar_width(560.0)
            .sidebar_width_fraction(0.5)
            .build();

        let inner = Rc::new(Inner {
            state,
            toast,
            split: split.clone(),
            search_entry,
            folder_button,
            folder_menu,
            folder_filter: RefCell::new(FolderFilter::All),
            folder_actions: RefCell::new(Vec::new()),
            favorites_toggle,
            count_label,
            sync_label,
            store,
            list_view: list_view.clone(),
            content_stack,
            empty,
            cache: RefCell::new(None),
            synced_ids: RefCell::new(None),
            show_badges: Cell::new(false),
            show_favicons: Cell::new(true),
            search_reload_id: RefCell::new(None),
            event_reload_id: RefCell::new(None),
            details_page,
            details_toolbar,
            details_placeholder: placeholder_widget,
            open_id: Cell::new(None),
            details_timer: RefCell::new(None),
            on_import: RefCell::new(None),
            on_trash: RefCell::new(None),
        });

        setup_factory(&inner, &factory);
        wire(&inner, &list_view, &add_button);
        install_actions(&inner, list_body.upcast_ref());
        install_actions(&inner, inner.details_toolbar.upcast_ref());

        Rc::new(Self { root: split, inner })
    }

    pub fn set_on_import(&self, cb: Callback) {
        *self.inner.on_import.borrow_mut() = Some(cb);
    }

    pub fn set_on_trash(&self, cb: Callback) {
        *self.inner.on_trash.borrow_mut() = Some(cb);
    }

    /// The vault was unlocked: load the collection.
    pub fn on_unlocked(&self) {
        self.inner.invalidate_caches();
        self.inner.reload();
    }

    /// The vault was locked: drop every row, the open details and the
    /// search text. Hidden is not gone.
    pub fn on_locked(&self) {
        let inner = &self.inner;
        inner.search_entry.set_text("");
        inner.cancel_pending();
        inner.store.remove_all();
        inner.invalidate_caches();
        *inner.folder_filter.borrow_mut() = FolderFilter::All;
        inner.folder_button.set_label(tr!("All folders"));
        inner.sync_folder_actions(&FolderFilter::All);
        inner.favorites_toggle.set_active(false);
        inner.folder_menu.remove_all();
        inner.close_details();
    }

    pub fn focus_search(&self) {
        self.inner.split.set_show_content(false);
        self.inner.search_entry.grab_focus();
    }

    /// Open the entry form. `prefill` carries a password created on the
    /// generator page so it is never lost on the way in.
    pub fn show_add_dialog(&self, prefill: Option<Zeroizing<String>>) {
        self.inner.show_add_dialog(prefill);
    }

    /// Type-to-search: characters typed anywhere on the list go to the
    /// search box.
    pub fn set_key_capture(&self, widget: &impl IsA<gtk::Widget>) {
        self.inner.search_entry.set_key_capture_widget(Some(widget));
    }

    #[cfg(debug_assertions)]
    pub fn dev_open_first(&self) {
        if let Some(obj) = self.inner.store.item(0) {
            if let Ok(boxed) = obj.downcast::<glib::BoxedAnyObject>() {
                let id = boxed.borrow::<Rc<PasswordEntry>>().id;
                self.inner.open_details(id);
            }
        }
    }

    #[cfg(debug_assertions)]
    pub fn dev_search(&self, text: &str) {
        self.inner.search_entry.set_text(text);
    }
}

// ============================================================================
// Rows
// ============================================================================

fn item_entry(item: &gtk::ListItem) -> Option<Rc<PasswordEntry>> {
    let boxed = item.item()?.downcast::<glib::BoxedAnyObject>().ok()?;
    let entry = boxed.borrow::<Rc<PasswordEntry>>().clone();
    Some(entry)
}

fn setup_factory(inner: &Rc<Inner>, factory: &gtk::SignalListItemFactory) {
    let weak = Rc::downgrade(inner);
    factory.connect_setup(move |_, obj| {
        let Some(item) = obj.downcast_ref::<gtk::ListItem>() else {
            return;
        };
        let root = gtk::Box::builder()
            .orientation(gtk::Orientation::Horizontal)
            .spacing(12)
            .build();
        root.add_css_class("ashy-entry-row");

        let icon = gtk::Image::builder().pixel_size(32).build();
        icon.add_css_class("ashy-entry-icon");
        icon.set_accessible_role(gtk::AccessibleRole::Presentation);
        root.append(&icon);

        let text = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(2)
            .hexpand(true)
            .valign(gtk::Align::Center)
            .build();
        let title = gtk::Label::builder()
            .xalign(0.0)
            .ellipsize(gtk::pango::EllipsizeMode::End)
            .build();
        title.add_css_class("heading");
        // Two lines before cutting: the account is what tells two entries
        // for the same service apart, it must not vanish into an ellipsis.
        let subtitle = gtk::Label::builder()
            .xalign(0.0)
            .wrap(true)
            .wrap_mode(gtk::pango::WrapMode::WordChar)
            .lines(2)
            .ellipsize(gtk::pango::EllipsizeMode::End)
            .build();
        subtitle.add_css_class("dim-label");
        subtitle.add_css_class("caption");
        text.append(&title);
        text.append(&subtitle);
        root.append(&text);

        let badge = gtk::Label::builder()
            .label("Nextcloud")
            .tooltip_text(tr!("Synchronized with Nextcloud Passwords"))
            .valign(gtk::Align::Center)
            .visible(false)
            .build();
        badge.add_css_class("caption");
        badge.add_css_class("ashy-badge");
        root.append(&badge);

        let star = gtk::Image::builder()
            .icon_name("starred-symbolic")
            .valign(gtk::Align::Center)
            .tooltip_text(tr!("Favorite"))
            .visible(false)
            .build();
        star.add_css_class("ashy-favorite");
        root.append(&star);

        let copy = gtk::Button::builder()
            .label(tr!("Copy password"))
            .valign(gtk::Align::Center)
            .build();
        copy.add_css_class("ashy-row-action");
        root.append(&copy);

        let menu = gio::Menu::new();
        let open_section = gio::Menu::new();
        open_section.append(Some(tr!("Open details")), Some("row.open"));
        open_section.append(Some(tr!("Copy user")), Some("row.copy-user"));
        open_section.append(Some(tr!("Edit…")), Some("row.edit"));
        menu.append_section(None, &open_section);
        let fav_section = gio::Menu::new();
        fav_section.append(Some(tr!("Add to favorites")), Some("row.favorite"));
        menu.append_section(None, &fav_section);
        let danger_section = gio::Menu::new();
        danger_section.append(Some(tr!("Password history…")), Some("row.history"));
        danger_section.append(Some(tr!("Delete…")), Some("row.delete"));
        menu.append_section(None, &danger_section);
        let more = gtk::MenuButton::builder()
            .icon_name("view-more-symbolic")
            .menu_model(&menu)
            .valign(gtk::Align::Center)
            .tooltip_text(tr!("More actions"))
            .build();
        more.add_css_class("flat");
        more.update_property(&[gtk::accessible::Property::Label(tr!("More actions"))]);
        root.append(&more);
        item.set_child(Some(&root));

        // Actions read the row's *current* item at click time: rows are
        // recycled, so nothing about the entry may be captured here.
        let group = gio::SimpleActionGroup::new();
        let item_weak = item.downgrade();
        let add = |name: &str, run: RowAction| {
            let action = gio::SimpleAction::new(name, None);
            let weak = weak.clone();
            let item_weak = item_weak.clone();
            action.connect_activate(move |_, _| {
                let (Some(inner), Some(item)) = (weak.upgrade(), item_weak.upgrade()) else {
                    return;
                };
                if let Some(entry) = item_entry(&item) {
                    run(&inner, entry);
                }
            });
            group.add_action(&action);
        };
        add("open", Box::new(|inner, e| inner.open_details(e.id)));
        add(
            "copy-user",
            Box::new(|inner, e| inner.copy_username(e.username.as_deref())),
        );
        add("edit", Box::new(|inner, e| inner.show_edit_dialog(e.id)));
        add("favorite", Box::new(|inner, e| inner.toggle_favorite(e.id)));
        add(
            "history",
            Box::new(|inner, e| inner.show_history_dialog(e.id)),
        );
        add("delete", Box::new(|inner, e| inner.confirm_delete(e.id)));
        root.insert_action_group("row", Some(&group));

        {
            let weak = weak.clone();
            let item_weak = item_weak.clone();
            copy.connect_clicked(move |_| {
                let (Some(inner), Some(item)) = (weak.upgrade(), item_weak.upgrade()) else {
                    return;
                };
                if let Some(entry) = item_entry(&item) {
                    inner.copy_password(entry.id);
                }
            });
        }

        let weak = weak.clone();
        item.connect_item_notify(move |item| {
            let Some(inner) = weak.upgrade() else { return };
            let Some(entry) = item_entry(item) else {
                return;
            };
            title.set_label(&entry.title);
            let line = account_line(
                &entry.title,
                entry.username.as_deref(),
                entry.url.as_deref(),
            );
            subtitle.set_label(&line);
            subtitle.set_visible(!line.is_empty());
            star.set_visible(entry.favorite);
            if inner.open_id.get() == Some(entry.id) {
                root.add_css_class("ashy-open");
            } else {
                root.remove_css_class("ashy-open");
            }
            if inner.show_favicons.get() {
                crate::favicons::apply(&icon, entry.url.as_deref(), 32);
            } else {
                icon.set_widget_name("");
                icon.set_icon_name(Some("dialog-password-symbolic"));
            }
            let synced = inner.show_badges.get()
                && inner
                    .synced_ids
                    .borrow()
                    .as_ref()
                    .is_some_and(|ids| ids.contains(&entry.id));
            badge.set_visible(synced);
            fav_section.remove_all();
            fav_section.append(
                Some(if entry.favorite {
                    tr!("Remove from favorites")
                } else {
                    tr!("Add to favorites")
                }),
                Some("row.favorite"),
            );
            copy.update_property(&[gtk::accessible::Property::Label(&format!(
                "{} — {}",
                tr!("Copy password"),
                entry.title
            ))]);
            more.update_property(&[gtk::accessible::Property::Label(&format!(
                "{} — {}",
                tr!("More actions"),
                entry.title
            ))]);
        });
    });
}

fn wire(inner: &Rc<Inner>, list_view: &gtk::ListView, add_button: &gtk::Button) {
    let weak = Rc::downgrade(inner);
    list_view.connect_activate(move |_, position| {
        let Some(inner) = weak.upgrade() else { return };
        if let Some(obj) = inner.store.item(position) {
            if let Ok(boxed) = obj.downcast::<glib::BoxedAnyObject>() {
                let id = boxed.borrow::<Rc<PasswordEntry>>().id;
                inner.open_details(id);
            }
        }
    });

    let weak = Rc::downgrade(inner);
    add_button.connect_clicked(move |_| {
        if let Some(inner) = weak.upgrade() {
            inner.show_add_dialog(None);
        }
    });

    let weak = Rc::downgrade(inner);
    inner.search_entry.connect_search_changed(move |_| {
        let Some(inner) = weak.upgrade() else { return };
        inner.cancel_search_reload();
        let weak = Rc::downgrade(&inner);
        let id = glib::timeout_add_local(
            std::time::Duration::from_millis(SEARCH_DEBOUNCE_MS),
            move || {
                if let Some(inner) = weak.upgrade() {
                    *inner.search_reload_id.borrow_mut() = None;
                    inner.apply_filter();
                    SessionManager::on_activity(&inner.state.session);
                }
                glib::ControlFlow::Break
            },
        );
        *inner.search_reload_id.borrow_mut() = Some(id);
    });
    // Escape in the search box clears it rather than leaving a hidden filter.
    let weak = Rc::downgrade(inner);
    inner.search_entry.connect_stop_search(move |entry| {
        entry.set_text("");
        if let Some(inner) = weak.upgrade() {
            inner.apply_filter();
        }
    });

    let weak = Rc::downgrade(inner);
    inner.favorites_toggle.connect_toggled(move |_| {
        if let Some(inner) = weak.upgrade() {
            inner.apply_filter();
        }
    });

    let weak = Rc::downgrade(inner);
    let _permanent = inner.state.events.subscribe(move |event| {
        let Some(inner) = weak.upgrade() else { return };
        match event {
            crate::events::AppEvent::VaultChanged
            | crate::events::AppEvent::SyncCompleted { .. }
                if inner.can_show_vault_data() =>
            {
                inner.invalidate_caches();
                inner.schedule_reload();
            }
            crate::events::AppEvent::SyncStatusChanged if inner.can_show_vault_data() => {
                if let Some(cache) = inner.cache.borrow().clone() {
                    let badges = inner.state.settings().show_sync_badges;
                    inner.update_sync_state(&cache, badges);
                }
            }
            _ => {}
        }
    });
}

fn install_actions(inner: &Rc<Inner>, widget: &gtk::Widget) {
    let group = gio::SimpleActionGroup::new();

    let folder = gio::SimpleAction::new_stateful(
        "folder",
        Some(glib::VariantTy::STRING),
        &"all".to_variant(),
    );
    {
        let weak = Rc::downgrade(inner);
        folder.connect_activate(move |action, target| {
            let Some(target) = target.and_then(|t| t.str()) else {
                return;
            };
            action.set_state(&target.to_variant());
            if let Some(inner) = weak.upgrade() {
                inner.set_folder_filter(FolderFilter::from_target(target));
            }
        });
    }
    group.add_action(&folder);
    inner.folder_actions.borrow_mut().push(folder.clone());

    let simple = |name: &str, run: fn(&Rc<Inner>)| {
        let action = gio::SimpleAction::new(name, None);
        let weak = Rc::downgrade(inner);
        action.connect_activate(move |_, _| {
            if let Some(inner) = weak.upgrade() {
                run(&inner);
            }
        });
        group.add_action(&action);
    };
    simple("new-folder", |inner| inner.show_new_folder_dialog());
    simple("organize-folders", |inner| {
        inner.show_organize_folders_dialog()
    });
    simple("import", |inner| {
        if let Some(cb) = inner.on_import.borrow().as_ref() {
            cb();
        }
    });
    simple("trash", |inner| {
        if let Some(cb) = inner.on_trash.borrow().as_ref() {
            cb();
        }
    });
    simple("search-all", |inner| {
        inner.favorites_toggle.set_active(false);
        inner.set_folder_filter(FolderFilter::All);
    });
    widget.insert_action_group("vault", Some(&group));
}

// ============================================================================
// Inner
// ============================================================================

impl Inner {
    fn can_show_vault_data(&self) -> bool {
        self.state.session.borrow().is_authenticated() && self.state.vault.borrow().is_unlocked()
    }

    fn toast(&self, message: &str) {
        self.toast
            .add_toast(adw::Toast::builder().title(message).timeout(3).build());
    }

    fn cancel_search_reload(&self) {
        if let Some(id) = self.search_reload_id.borrow_mut().take() {
            id.remove();
        }
    }

    fn cancel_pending(&self) {
        self.cancel_search_reload();
        if let Some(id) = self.event_reload_id.borrow_mut().take() {
            id.remove();
        }
        self.stop_details_timer();
    }

    fn invalidate_caches(&self) {
        self.cache.borrow_mut().take();
        self.synced_ids.borrow_mut().take();
    }

    fn cache(&self) -> ashypass_core::Result<Rc<PasswordListCache>> {
        if let Some(cache) = self.cache.borrow().as_ref() {
            return Ok(cache.clone());
        }
        let vault = self.state.vault.borrow();
        let entries = vault.list(None)?;
        let categories = vault.categories().unwrap_or_default();
        let cache = Rc::new(PasswordListCache::new(entries, categories));
        *self.cache.borrow_mut() = Some(cache.clone());
        Ok(cache)
    }

    fn schedule_reload(self: &Rc<Self>) {
        if let Some(id) = self.event_reload_id.borrow_mut().take() {
            id.remove();
        }
        let weak = Rc::downgrade(self);
        let id = glib::timeout_add_local(std::time::Duration::from_millis(60), move || {
            if let Some(inner) = weak.upgrade() {
                *inner.event_reload_id.borrow_mut() = None;
                inner.reload();
            }
            glib::ControlFlow::Break
        });
        *self.event_reload_id.borrow_mut() = Some(id);
    }

    /// Re-read settings and sync state, rebuild the folder menu and refilter.
    fn reload(self: &Rc<Self>) {
        if !self.can_show_vault_data() {
            return;
        }
        let settings = self.state.settings();
        self.show_favicons.set(settings.show_favicons);
        if settings.compact_vault_list {
            self.list_view.add_css_class("ashy-compact");
        } else {
            self.list_view.remove_css_class("ashy-compact");
        }
        let cache = match self.cache() {
            Ok(cache) => cache,
            Err(e) => {
                log::error!("vault.list failed: {e}");
                self.empty.set(
                    "dialog-error-symbolic",
                    tr!("Could not read the vault"),
                    &e.to_string(),
                );
                self.content_stack.set_visible_child_name("empty");
                return;
            }
        };
        self.update_sync_state(&cache, settings.show_sync_badges);
        self.rebuild_folder_menu(&cache.categories);
        // A folder that no longer exists cannot stay selected.
        let stale = matches!(&*self.folder_filter.borrow(), FolderFilter::Named(name) if !cache.categories.contains(name));
        if stale {
            *self.folder_filter.borrow_mut() = FolderFilter::All;
            self.folder_button.set_label(tr!("All folders"));
            self.sync_folder_actions(&FolderFilter::All);
        }
        self.apply_filter();
        // Keep the open details in step with the data (edited, deleted…).
        if let Some(id) = self.open_id.get() {
            let still_there = cache.entries.iter().any(|e| e.id == id);
            if still_there {
                self.render_details(id);
            } else {
                self.close_details();
            }
        }
    }

    /// When every entry comes from Nextcloud Passwords a badge on each row
    /// says nothing; one line under the list says it once. Badges remain
    /// for mixed collections, where they tell entries apart.
    fn update_sync_state(&self, cache: &PasswordListCache, badges_enabled: bool) {
        let ids: HashSet<i64> = self
            .state
            .vault
            .borrow()
            .nc_all_mappings()
            .map(|items| items.into_iter().map(|m| m.entry_id).collect())
            .unwrap_or_default();
        let total = cache.len();
        let synced = cache.entries.iter().filter(|e| ids.contains(&e.id)).count();
        let all_synced = total > 0 && synced == total;
        self.show_badges
            .set(badges_enabled && synced > 0 && !all_synced);
        // The observed sync state first: it tells the user whether the
        // latest changes reached the server, not just that a link exists.
        let time = |at: i64| {
            glib::DateTime::from_unix_local(at)
                .ok()
                .and_then(|dt| dt.format("%H:%M").ok())
                .map(|s| s.to_string())
                .unwrap_or_default()
        };
        let logged_in = self.state.nextcloud.borrow().is_logged_in();
        let status_text = match self.state.sync_status.get() {
            _ if !logged_in => None,
            SyncStatus::Pending => {
                Some(tr!("Saved on this computer. Waiting to synchronize.").to_string())
            }
            SyncStatus::Running => Some(tr!("Synchronizing with Nextcloud Passwords…").to_string()),
            SyncStatus::Synced { at } => Some(format!(
                "{} {}.",
                tr!("Synchronized with Nextcloud Passwords at"),
                time(at)
            )),
            SyncStatus::Failed { at } => Some(format!(
                "{} {}. {}",
                tr!("Could not synchronize at"),
                time(at),
                tr!("Your entries are still available on this computer.")
            )),
            SyncStatus::Unknown => None,
        };
        if let Some(text) = status_text {
            self.sync_label.set_label(&text);
            self.sync_label.set_visible(true);
        } else if all_synced {
            self.sync_label.set_label(tr!(
                "All entries are synchronized with Nextcloud Passwords."
            ));
            self.sync_label.set_visible(true);
        } else if synced > 0 && !badges_enabled {
            self.sync_label.set_label(
                &trn!(
                    "{} of these entries is synchronized with Nextcloud Passwords.",
                    "{} of these entries are synchronized with Nextcloud Passwords.",
                    synced
                )
                .replace("{}", &synced.to_string()),
            );
            self.sync_label.set_visible(true);
        } else {
            self.sync_label.set_visible(false);
        }
        *self.synced_ids.borrow_mut() = Some(Rc::new(ids));
    }

    fn rebuild_folder_menu(&self, categories: &[String]) {
        self.folder_menu.remove_all();
        let filters = gio::Menu::new();
        let item = |label: &str, filter: FolderFilter| {
            let item = gio::MenuItem::new(Some(label), None);
            item.set_action_and_target_value(
                Some("vault.folder"),
                Some(&filter.target().to_variant()),
            );
            item
        };
        filters.append_item(&item(tr!("All folders"), FolderFilter::All));
        filters.append_item(&item(tr!("No folder"), FolderFilter::NoFolder));
        self.folder_menu.append_section(None, &filters);
        if !categories.is_empty() {
            let named = gio::Menu::new();
            for category in categories {
                named.append_item(&item(category, FolderFilter::Named(category.clone())));
            }
            self.folder_menu
                .append_section(Some(tr!("Folders")), &named);
        }
        let manage = gio::Menu::new();
        manage.append(Some(tr!("Create folder…")), Some("vault.new-folder"));
        manage.append(
            Some(tr!("Organize folders…")),
            Some("vault.organize-folders"),
        );
        self.folder_menu.append_section(None, &manage);
    }

    fn sync_folder_actions(&self, filter: &FolderFilter) {
        let target = filter.target().to_variant();
        for action in self.folder_actions.borrow().iter() {
            action.set_state(&target);
        }
    }

    fn set_folder_filter(&self, filter: FolderFilter) {
        self.folder_button.set_label(&filter.label());
        self.sync_folder_actions(&filter);
        *self.folder_filter.borrow_mut() = filter;
        self.apply_filter();
        SessionManager::on_activity(&self.state.session);
    }

    fn current_search(&self) -> Option<String> {
        let text = self.search_entry.text().trim().to_string();
        (!text.is_empty()).then_some(text)
    }

    fn apply_filter(&self) {
        if !self.can_show_vault_data() {
            return;
        }
        let Some(cache) = self.cache.borrow().clone() else {
            return;
        };
        let search = self.current_search();
        let folder = self.folder_filter.borrow().clone();
        let favorites_only = self.favorites_toggle.is_active();
        let entries = cache.filtered(search.as_deref(), &folder, favorites_only);

        // Replacing the model scrolls the list back to the top. Skip it when
        // the same entries are already shown in the same order.
        let unchanged = self.store.n_items() as usize == entries.len()
            && entries.iter().enumerate().all(|(i, e)| {
                self.store
                    .item(i as u32)
                    .and_then(|o| o.downcast::<glib::BoxedAnyObject>().ok())
                    .is_some_and(|b| Rc::ptr_eq(&b.borrow::<Rc<PasswordEntry>>(), e))
            });
        if !unchanged {
            // Same number of rows: a refresh of the same entries (a favorite,
            // an edit, a sync), so keep the user's place in the list.
            let refresh = self.store.n_items() as usize == entries.len();
            let adjustment = self.list_view.vadjustment();
            let position = adjustment.as_ref().map(|a| a.value()).unwrap_or(0.0);
            let items: Vec<glib::Object> = entries
                .iter()
                .map(|e| glib::BoxedAnyObject::new(e.clone()).upcast())
                .collect();
            self.store.splice(0, self.store.n_items(), &items);
            if let (true, Some(adjustment)) = (refresh, adjustment) {
                glib::idle_add_local_once(move || {
                    let max = (adjustment.upper() - adjustment.page_size()).max(0.0);
                    adjustment.set_value(position.min(max));
                });
            }
        }

        let shown = entries.len();
        self.count_label.set_label(
            &trn!("{} password", "{} passwords", shown).replace("{}", &shown.to_string()),
        );

        if shown > 0 {
            self.content_stack.set_visible_child_name("list");
            return;
        }
        self.show_empty_state(&cache, search.as_deref(), &folder, favorites_only);
    }

    fn show_empty_state(
        &self,
        cache: &PasswordListCache,
        search: Option<&str>,
        folder: &FolderFilter,
        favorites_only: bool,
    ) {
        let filtered = folder != &FolderFilter::All || favorites_only;
        if cache.len() == 0 {
            self.empty.set(
                "dialog-password-symbolic",
                tr!("Your vault is ready"),
                tr!("Save an access or bring your passwords from another app."),
            );
            let add = self.empty.add_action(tr!("Add password"), true);
            add.set_action_name(Some("win.new-entry"));
            let import = self.empty.add_action(tr!("Import passwords"), false);
            import.set_action_name(Some("vault.import"));
        } else if let Some(search) = search {
            let title = format!("{} “{search}”", tr!("No passwords found for"));
            let scope = if favorites_only {
                tr!("The search is limited to favorites.").to_string()
            } else {
                match folder {
                    FolderFilter::All => {
                        tr!("Names, accounts and sites were searched.").to_string()
                    }
                    FolderFilter::NoFolder => {
                        tr!("The search is limited to passwords without a folder.").to_string()
                    }
                    FolderFilter::Named(name) => {
                        format!("{} {name}.", tr!("The search is limited to the folder"))
                    }
                }
            };
            self.empty.set("edit-find-symbolic", &title, &scope);
            if filtered {
                let all = self.empty.add_action(tr!("Search all folders"), true);
                all.set_action_name(Some("vault.search-all"));
            }
        } else if favorites_only {
            self.empty.set(
                "starred-symbolic",
                tr!("Your most used accesses can be here"),
                tr!("Open a password and mark the star to find it faster."),
            );
            let all = self.empty.add_action(tr!("See my passwords"), true);
            all.set_action_name(Some("vault.search-all"));
        } else {
            self.empty.set(
                "folder-symbolic",
                tr!("This folder is empty"),
                tr!("Choose this folder when adding or editing a password."),
            );
            let all = self.empty.add_action(tr!("See all folders"), true);
            all.set_action_name(Some("vault.search-all"));
        }
        self.content_stack.set_visible_child_name("empty");
    }

    // ---- Actions ------------------------------------------------------

    fn copy_password(&self, id: i64) {
        if !self.can_show_vault_data() {
            return;
        }
        let password = self
            .state
            .vault
            .borrow()
            .get(id)
            .ok()
            .flatten()
            .and_then(|e| e.password)
            .map(Zeroizing::new);
        match password {
            Some(pw) if !pw.is_empty() => {
                copy_secret(&self.state, &pw);
                self.toast(tr!("Password copied"));
            }
            _ => self.toast(tr!("This access has no saved password")),
        }
        SessionManager::on_activity(&self.state.session);
    }

    fn copy_username(&self, username: Option<&str>) {
        match username.filter(|u| !u.trim().is_empty()) {
            Some(user) => {
                copy_secret(&self.state, user);
                self.toast(tr!("User copied"));
            }
            None => self.toast(tr!("This access has no user")),
        }
    }

    fn toggle_favorite(&self, id: i64) {
        let result = self.state.vault.borrow().toggle_favorite(id);
        match result {
            Ok(true) => self.toast(tr!("Added to favorites")),
            Ok(false) => self.toast(tr!("Removed from favorites")),
            Err(e) => self.toast(&format!("{}: {e}", tr!("Could not change the favorite"))),
        }
        // Favorites do not change `updated_at`, so the change listener may
        // not fire; refresh explicitly.
        self.invalidate_caches();
        SessionManager::on_activity(&self.state.session);
    }

    fn show_add_dialog(self: &Rc<Self>, prefill: Option<Zeroizing<String>>) {
        if !self.can_show_vault_data() {
            return;
        }
        let folder = match &*self.folder_filter.borrow() {
            FolderFilter::Named(name) => Some(name.clone()),
            _ => None,
        };
        let weak = Rc::downgrade(self);
        entry_form::present(
            &self.state,
            &self.toast,
            &self.split,
            EntryFormOptions {
                entry: None,
                prefill_password: prefill,
                prefill_folder: folder,
                on_saved: Some(Box::new(move |id| {
                    if let Some(inner) = weak.upgrade() {
                        inner.invalidate_caches();
                        inner.reload();
                        inner.open_details(id);
                    }
                })),
            },
        );
    }

    fn show_edit_dialog(self: &Rc<Self>, id: i64) {
        let entry = match self.state.vault.borrow().get(id) {
            Ok(Some(e)) => e,
            _ => return,
        };
        let weak = Rc::downgrade(self);
        entry_form::present(
            &self.state,
            &self.toast,
            &self.split,
            EntryFormOptions {
                entry: Some(entry),
                prefill_password: None,
                prefill_folder: None,
                on_saved: Some(Box::new(move |id| {
                    if let Some(inner) = weak.upgrade() {
                        inner.invalidate_caches();
                        inner.reload();
                        inner.render_details(id);
                    }
                })),
            },
        );
        SessionManager::on_activity(&self.state.session);
    }

    fn show_history_dialog(self: &Rc<Self>, id: i64) {
        let title = self
            .state
            .vault
            .borrow()
            .get_without_touch(id)
            .ok()
            .flatten()
            .map(|e| e.title)
            .unwrap_or_default();
        let history = match self.state.vault.borrow().password_history(id) {
            Ok(h) => h,
            Err(e) => {
                self.toast(&format!("{}: {e}", tr!("Could not read the history")));
                return;
            }
        };
        let dialog = adw::Dialog::builder()
            .title(tr!("Password history"))
            .content_width(520)
            .content_height(440)
            .build();
        let toolbar = adw::ToolbarView::new();
        toolbar.add_top_bar(&adw::HeaderBar::new());
        let page = adw::PreferencesPage::new();
        let group = adw::PreferencesGroup::builder()
            .title(glib::markup_escape_text(&title).as_str())
            .description(tr!(
                "Previous passwords kept by Ashy Pass when this one was changed."
            ))
            .build();
        if history.is_empty() {
            let row = adw::ActionRow::builder()
                .title(tr!("No previous passwords"))
                .subtitle(tr!(
                    "Older versions appear here after the password is changed."
                ))
                .build();
            group.add(&row);
        } else {
            for h in &history {
                let row = adw::ActionRow::builder()
                    .title(mask_password(&h.password))
                    .subtitle(format_timestamp(h.changed_at))
                    .use_markup(false)
                    .build();
                let copy = gtk::Button::builder()
                    .icon_name("edit-copy-symbolic")
                    .tooltip_text(tr!("Copy"))
                    .valign(gtk::Align::Center)
                    .build();
                copy.add_css_class("flat");
                copy.update_property(&[gtk::accessible::Property::Label(tr!(
                    "Copy this old password"
                ))]);
                {
                    // Read the value at click time instead of keeping a copy
                    // of every old password alive in the closure.
                    let inner = self.clone();
                    let changed_at = h.changed_at;
                    copy.connect_clicked(move |_| {
                        if !inner.can_show_vault_data() {
                            return;
                        }
                        let value = inner
                            .state
                            .vault
                            .borrow()
                            .password_history(id)
                            .ok()
                            .and_then(|items| {
                                items
                                    .into_iter()
                                    .find(|item| item.changed_at == changed_at)
                                    .map(|item| Zeroizing::new(item.password))
                            });
                        if let Some(value) = value {
                            copy_secret(&inner.state, &value);
                            inner.toast(tr!("Password copied"));
                        }
                    });
                }
                row.add_suffix(&copy);
                group.add(&row);
            }
        }
        page.add(&group);
        if !history.is_empty() {
            let actions = adw::PreferencesGroup::new();
            let clear = gtk::Button::with_label(tr!("Clear history"));
            clear.add_css_class("destructive-action");
            clear.set_halign(gtk::Align::End);
            {
                let inner = self.clone();
                let dialog = dialog.clone();
                clear.connect_clicked(move |_| {
                    match inner.state.vault.borrow().clear_password_history(id) {
                        Ok(_) => {
                            inner.toast(tr!("History cleared"));
                            dialog.close();
                        }
                        Err(e) => {
                            inner.toast(&format!("{}: {e}", tr!("Could not clear the history")))
                        }
                    }
                });
            }
            actions.add(&clear);
            page.add(&actions);
        }
        toolbar.set_content(Some(&page));
        dialog.set_child(Some(&toolbar));
        self.state.track_sensitive_dialog(&dialog);
        dialog.present(Some(&self.split));
    }

    fn confirm_delete(self: &Rc<Self>, id: i64) {
        let entry = match self.state.vault.borrow().get_without_touch(id) {
            Ok(Some(e)) => e,
            _ => return,
        };
        let retention = self.state.settings().trash_retention_days;
        let who = entry
            .username
            .as_deref()
            .filter(|u| !u.trim().is_empty())
            .map(|u| format!(" ({u})"))
            .unwrap_or_default();
        let heading = format!("{} “{}”{who}?", tr!("Delete"), entry.title);
        let body = if retention > 0 {
            format!(
                "{} {}",
                tr!("The access moves to Deleted items, where it can be restored for"),
                trn!("{} day.", "{} days.", retention as usize)
                    .replace("{}", &retention.to_string())
            )
        } else {
            tr!("Deleted items are not kept (see Settings). This cannot be undone.").to_string()
        };
        let dialog = adw::AlertDialog::builder()
            .heading(&heading)
            .body(&body)
            .default_response("cancel")
            .close_response("cancel")
            .build();
        dialog.add_response("cancel", tr!("Cancel"));
        dialog.add_response("delete", tr!("Delete"));
        dialog.set_response_appearance("delete", adw::ResponseAppearance::Destructive);
        let inner = self.clone();
        dialog.connect_response(None, move |_, response| {
            if response != "delete" || !inner.can_show_vault_data() {
                return;
            }
            let deleted = if retention > 0 {
                inner.state.vault.borrow().delete(id)
            } else {
                inner.state.vault.borrow().delete_permanent(id)
            };
            match deleted {
                Ok(true) => {
                    if inner.open_id.get() == Some(id) {
                        inner.close_details();
                    }
                    if retention > 0 {
                        inner.offer_undo(id);
                    } else {
                        inner.toast(tr!("Permanently deleted"));
                    }
                }
                Ok(false) => inner.toast(tr!("This access no longer exists")),
                Err(e) => inner.toast(&format!("{}: {e}", tr!("Could not delete"))),
            }
            SessionManager::on_activity(&inner.state.session);
        });
        self.state.track_sensitive_dialog(&dialog);
        dialog.present(Some(&self.split));
    }

    /// "Undo" is offered only because the trash really holds the entry.
    fn offer_undo(self: &Rc<Self>, original_id: i64) {
        let toast = adw::Toast::builder()
            .title(tr!("Moved to Deleted items"))
            .button_label(tr!("Undo"))
            .timeout(6)
            .build();
        let inner = self.clone();
        toast.connect_button_clicked(move |_| {
            if !inner.can_show_vault_data() {
                return;
            }
            let trash_id = inner
                .state
                .vault
                .borrow()
                .list_trash()
                .ok()
                .and_then(|items| {
                    items
                        .into_iter()
                        .filter(|t| t.original_id == original_id)
                        .max_by_key(|t| t.deleted_at)
                        .map(|t| t.trash_id)
                });
            let restored = trash_id.map(|tid| inner.state.vault.borrow().restore_from_trash(tid));
            match restored {
                Some(Ok(Some(_))) => inner.toast(tr!("Restored")),
                _ => inner.toast(tr!("Could not restore. Look in Deleted items.")),
            }
        });
        self.toast.add_toast(toast);
    }

    fn show_new_folder_dialog(self: &Rc<Self>) {
        let dialog = adw::AlertDialog::builder()
            .heading(tr!("Create folder"))
            .body(tr!(
                "Folders organize your passwords. You can choose them when adding or editing."
            ))
            .default_response("create")
            .close_response("cancel")
            .build();
        dialog.add_response("cancel", tr!("Cancel"));
        dialog.add_response("create", tr!("Create"));
        dialog.set_response_appearance("create", adw::ResponseAppearance::Suggested);
        let name_row = adw::EntryRow::builder()
            .title(tr!("Folder name"))
            .activates_default(true)
            .build();
        let list = gtk::ListBox::builder()
            .selection_mode(gtk::SelectionMode::None)
            .build();
        list.add_css_class("boxed-list");
        list.append(&name_row);
        dialog.set_extra_child(Some(&list));
        let inner = self.clone();
        dialog.connect_response(None, move |_, response| {
            if response != "create" {
                return;
            }
            let name = name_row.text().trim().to_string();
            if name.is_empty() {
                return;
            }
            match inner.state.vault.borrow().create_folder(&name) {
                Ok(true) => inner.toast(tr!("Folder created")),
                Ok(false) => inner.toast(tr!("This folder already exists")),
                Err(e) => inner.toast(&format!("{}: {e}", tr!("Could not create the folder"))),
            }
            inner.invalidate_caches();
            inner.reload();
            inner.set_folder_filter(FolderFilter::Named(name));
        });
        self.state.track_sensitive_dialog(&dialog);
        dialog.present(Some(&self.split));
    }

    fn show_organize_folders_dialog(self: &Rc<Self>) {
        crate::ui::folders::present(&self.state, &self.toast, &self.split);
    }

    // ---- Details ------------------------------------------------------

    fn stop_details_timer(&self) {
        if let Some(id) = self.details_timer.borrow_mut().take() {
            id.remove();
        }
    }

    fn close_details(&self) {
        self.stop_details_timer();
        if let Some(previous) = self.open_id.take() {
            self.refresh_rows(&[previous]);
        }
        // Dropping the old content drops every decrypted value it showed.
        self.details_toolbar
            .set_content(Some(&self.details_placeholder));
        self.details_page.set_title(tr!("Details"));
        self.split.set_show_content(false);
    }

    fn open_details(self: &Rc<Self>, id: i64) {
        self.render_details(id);
        self.split.set_show_content(true);
        SessionManager::on_activity(&self.state.session);
    }

    /// Re-bind the rows of `ids` so their "open" highlight follows.
    fn refresh_rows(&self, ids: &[i64]) {
        for position in 0..self.store.n_items() {
            let Some(obj) = self.store.item(position) else {
                continue;
            };
            let Ok(boxed) = obj.downcast::<glib::BoxedAnyObject>() else {
                continue;
            };
            let id = boxed.borrow::<Rc<PasswordEntry>>().id;
            if ids.contains(&id) {
                // A fresh object makes the row re-bind; signalling a change
                // with the same object would not update it.
                let entry = boxed.borrow::<Rc<PasswordEntry>>().clone();
                let fresh: glib::Object = glib::BoxedAnyObject::new(entry).upcast();
                self.store.splice(position, 1, &[fresh]);
            }
        }
    }

    fn render_details(self: &Rc<Self>, id: i64) {
        self.stop_details_timer();
        if !self.can_show_vault_data() {
            return;
        }
        let entry = match self.state.vault.borrow().get(id) {
            Ok(Some(e)) => e,
            Ok(None) => {
                self.close_details();
                return;
            }
            Err(e) => {
                self.toast(&format!("{}: {e}", tr!("Could not open this access")));
                return;
            }
        };
        let previous = self.open_id.replace(Some(id));
        if previous != Some(id) {
            let mut ids = vec![id];
            ids.extend(previous);
            self.refresh_rows(&ids);
        }
        self.details_page.set_title(&entry.title);
        let content = build_details(self, &entry);
        self.details_toolbar.set_content(Some(&content));
    }
}

// ============================================================================
// Details content
// ============================================================================

fn copy_button(tooltip: &str) -> gtk::Button {
    let button = gtk::Button::builder()
        .icon_name("edit-copy-symbolic")
        .tooltip_text(tooltip)
        .valign(gtk::Align::Center)
        .build();
    button.add_css_class("flat");
    button.update_property(&[gtk::accessible::Property::Label(tooltip)]);
    button
}

const HIDDEN_PASSWORD: &str = "••••••••••••";

fn build_details(inner: &Rc<Inner>, entry: &PasswordEntry) -> gtk::Widget {
    let id = entry.id;
    let outer = gtk::Box::new(gtk::Orientation::Vertical, 0);

    // Header actions for this entry live in the content so they follow the
    // open access: favorite, edit and a menu with history and delete.
    let actions = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(6)
        .halign(gtk::Align::End)
        .build();
    let star = gtk::ToggleButton::builder()
        .icon_name(if entry.favorite {
            "starred-symbolic"
        } else {
            "non-starred-symbolic"
        })
        .active(entry.favorite)
        .tooltip_text(if entry.favorite {
            tr!("Remove from favorites")
        } else {
            tr!("Add to favorites")
        })
        .valign(gtk::Align::Center)
        .build();
    star.add_css_class("flat");
    if entry.favorite {
        star.add_css_class("ashy-favorite");
    }
    star.update_property(&[gtk::accessible::Property::Label(tr!("Favorite"))]);
    {
        let weak = Rc::downgrade(inner);
        star.connect_clicked(move |_| {
            if let Some(inner) = weak.upgrade() {
                inner.toggle_favorite(id);
                inner.reload();
            }
        });
    }
    let edit = gtk::Button::with_label(tr!("Edit"));
    edit.set_valign(gtk::Align::Center);
    {
        let weak = Rc::downgrade(inner);
        edit.connect_clicked(move |_| {
            if let Some(inner) = weak.upgrade() {
                inner.show_edit_dialog(id);
            }
        });
    }
    let menu = gio::Menu::new();
    menu.append(Some(tr!("Password history…")), Some("details.history"));
    menu.append(Some(tr!("Delete…")), Some("details.delete"));
    let more = gtk::MenuButton::builder()
        .icon_name("view-more-symbolic")
        .menu_model(&menu)
        .tooltip_text(tr!("More actions"))
        .valign(gtk::Align::Center)
        .build();
    more.add_css_class("flat");
    more.update_property(&[gtk::accessible::Property::Label(tr!("More actions"))]);
    let group = gio::SimpleActionGroup::new();
    for (name, run) in [
        ("history", Inner::show_history_dialog as fn(&Rc<Inner>, i64)),
        ("delete", Inner::confirm_delete as fn(&Rc<Inner>, i64)),
    ] {
        let action = gio::SimpleAction::new(name, None);
        let weak = Rc::downgrade(inner);
        action.connect_activate(move |_, _| {
            if let Some(inner) = weak.upgrade() {
                run(&inner, id);
            }
        });
        group.add_action(&action);
    }
    outer.insert_action_group("details", Some(&group));
    actions.append(&star);
    actions.append(&edit);
    actions.append(&more);

    let content = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(18)
        .margin_top(12)
        .margin_bottom(24)
        .margin_start(18)
        .margin_end(18)
        .build();

    let title_row = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(14)
        .build();
    let icon = gtk::Image::new();
    if inner.show_favicons.get() {
        crate::favicons::apply(&icon, entry.url.as_deref(), 48);
    } else {
        icon.set_pixel_size(48);
        icon.set_icon_name(Some("dialog-password-symbolic"));
    }
    icon.add_css_class("ashy-entry-icon");
    icon.set_accessible_role(gtk::AccessibleRole::Presentation);
    title_row.append(&icon);
    let title_box = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(2)
        .hexpand(true)
        .valign(gtk::Align::Center)
        .build();
    let title = gtk::Label::builder()
        .label(&entry.title)
        .xalign(0.0)
        .wrap(true)
        .wrap_mode(gtk::pango::WrapMode::WordChar)
        .build();
    title.add_css_class("title-2");
    title.set_accessible_role(gtk::AccessibleRole::Heading);
    title_box.append(&title);
    if let Some(domain) = entry
        .url
        .as_deref()
        .map(display_domain)
        .filter(|d| !d.is_empty())
    {
        let sub = gtk::Label::builder().label(&domain).xalign(0.0).build();
        sub.add_css_class("dim-label");
        title_box.append(&sub);
    }
    title_row.append(&title_box);
    title_row.append(&actions);
    content.append(&title_row);

    let fields = adw::PreferencesGroup::new();

    if let Some(user) = entry.username.as_deref().filter(|u| !u.trim().is_empty()) {
        let row = adw::ActionRow::builder()
            .title(tr!("User"))
            .subtitle(user)
            .use_markup(false)
            .subtitle_selectable(true)
            .build();
        row.add_css_class("property");
        let copy = copy_button(tr!("Copy user"));
        {
            let weak = Rc::downgrade(inner);
            let user = user.to_string();
            copy.connect_clicked(move |_| {
                if let Some(inner) = weak.upgrade() {
                    inner.copy_username(Some(&user));
                }
            });
        }
        row.add_suffix(&copy);
        fields.add(&row);
    }

    let has_password = entry.password.as_deref().is_some_and(|p| !p.is_empty());
    if has_password {
        let estimate = entry
            .password
            .as_deref()
            .map(|p| ashypass_core::strength::estimate(p, &[]))
            .map(|s| crate::ui::generator_view::strength_word(s.score))
            .unwrap_or_default();
        let hidden_subtitle = format!(
            "{HIDDEN_PASSWORD}\n{}: {estimate}",
            tr!("Estimated strength")
        );
        let row = adw::ActionRow::builder()
            .title(tr!("Password"))
            .subtitle(&hidden_subtitle)
            .use_markup(false)
            .build();
        row.add_css_class("property");
        let reveal = gtk::ToggleButton::builder()
            .icon_name("view-reveal-symbolic")
            .tooltip_text(tr!("Show password"))
            .valign(gtk::Align::Center)
            .build();
        reveal.add_css_class("flat");
        reveal.update_property(&[gtk::accessible::Property::Label(tr!("Show password"))]);
        {
            let row = row.clone();
            let weak = Rc::downgrade(inner);
            let hidden_subtitle = hidden_subtitle.clone();
            reveal.connect_toggled(move |button| {
                let Some(inner) = weak.upgrade() else { return };
                if button.is_active() && inner.can_show_vault_data() {
                    // Fetch on demand: the details keep only the mask.
                    let value = inner
                        .state
                        .vault
                        .borrow()
                        .get_without_touch(id)
                        .ok()
                        .flatten()
                        .and_then(|e| e.password)
                        .map(Zeroizing::new);
                    if let Some(value) = value {
                        row.set_subtitle(&value);
                        row.add_css_class("ashy-revealed");
                    }
                    button.set_icon_name("view-conceal-symbolic");
                    button.set_tooltip_text(Some(tr!("Hide password")));
                } else {
                    row.set_subtitle(&hidden_subtitle);
                    row.remove_css_class("ashy-revealed");
                    button.set_icon_name("view-reveal-symbolic");
                    button.set_tooltip_text(Some(tr!("Show password")));
                }
            });
        }
        let copy = copy_button(tr!("Copy password"));
        {
            let weak = Rc::downgrade(inner);
            copy.connect_clicked(move |_| {
                if let Some(inner) = weak.upgrade() {
                    inner.copy_password(id);
                }
            });
        }
        row.add_suffix(&reveal);
        row.add_suffix(&copy);
        fields.add(&row);
    }

    if let (Some(secret), true) = (entry.totp_secret.clone(), entry.has_totp) {
        let row = adw::ActionRow::builder()
            .title(tr!("Verification code"))
            .use_markup(false)
            .build();
        row.add_css_class("property");
        let algo = Algorithm::parse(&entry.totp_algorithm).unwrap_or(Algorithm::Sha1);
        let digits = entry.totp_digits;
        let period = entry.totp_period.max(1);
        let secret = Zeroizing::new(secret);
        let update = {
            let row = row.clone();
            let secret = secret.clone();
            move || {
                let now = chrono::Utc::now().timestamp().max(0) as u64;
                let remaining = period as u64 - (now % period as u64);
                match generate_totp(&secret, algo, digits, period, now) {
                    Ok(code) => row.set_subtitle(&format!(
                        "{}   ·   {}",
                        crate::ui::widgets::group_code(&code),
                        trn!(
                            "new code in {} second",
                            "new code in {} seconds",
                            remaining as usize
                        )
                        .replace("{}", &remaining.to_string())
                    )),
                    Err(_) => row.set_subtitle(tr!("The saved key is not valid")),
                }
            }
        };
        update();
        let copy = copy_button(tr!("Copy code"));
        {
            let weak = Rc::downgrade(inner);
            let secret = secret.clone();
            copy.connect_clicked(move |_| {
                let Some(inner) = weak.upgrade() else { return };
                // Computed at the moment of the click, never refreshed in the
                // clipboard afterwards.
                let now = chrono::Utc::now().timestamp().max(0) as u64;
                if let Ok(code) = generate_totp(&secret, algo, digits, period, now) {
                    copy_secret(&inner.state, &code);
                    inner.toast(tr!("Code copied"));
                }
            });
        }
        row.add_suffix(&copy);
        fields.add(&row);
        let timer = glib::timeout_add_seconds_local(1, move || {
            update();
            glib::ControlFlow::Continue
        });
        *inner.details_timer.borrow_mut() = Some(timer);
    }

    if let Some(url) = entry.url.as_deref().filter(|u| !u.trim().is_empty()) {
        let row = adw::ActionRow::builder()
            .title(tr!("Website"))
            .subtitle(url)
            .use_markup(false)
            .subtitle_selectable(true)
            .build();
        row.add_css_class("property");
        if let Some(target) = openable_url(url) {
            let open = gtk::Button::builder()
                .icon_name("adw-external-link-symbolic")
                .tooltip_text(tr!("Open website"))
                .valign(gtk::Align::Center)
                .build();
            open.add_css_class("flat");
            open.update_property(&[gtk::accessible::Property::Label(tr!("Open website"))]);
            open.connect_clicked(move |button| {
                let launcher = gtk::UriLauncher::new(&target);
                let parent = button.root().and_then(|r| r.downcast::<gtk::Window>().ok());
                launcher.launch(parent.as_ref(), None::<&gio::Cancellable>, |_| {});
            });
            row.add_suffix(&open);
        }
        let copy = copy_button(tr!("Copy address"));
        {
            let weak = Rc::downgrade(inner);
            let url = url.to_string();
            copy.connect_clicked(move |_| {
                if let Some(inner) = weak.upgrade() {
                    crate::clipboard::copy(&url, 0);
                    inner.toast(tr!("Address copied"));
                }
            });
        }
        row.add_suffix(&copy);
        fields.add(&row);
    }

    let folder = entry
        .category
        .as_deref()
        .filter(|c| !c.trim().is_empty())
        .unwrap_or(tr!("No folder"));
    let folder_row = adw::ActionRow::builder()
        .title(tr!("Folder"))
        .subtitle(folder)
        .use_markup(false)
        .build();
    folder_row.add_css_class("property");
    fields.add(&folder_row);

    let tags = inner.state.vault.borrow().tags_of(id).unwrap_or_default();
    if !tags.is_empty() {
        let row = adw::ActionRow::builder()
            .title(tr!("Tags"))
            .subtitle(tags.join(", "))
            .use_markup(false)
            .build();
        row.add_css_class("property");
        fields.add(&row);
    }
    content.append(&fields);

    if let Some(notes) = entry.notes.as_deref().filter(|n| !n.trim().is_empty()) {
        let group = adw::PreferencesGroup::builder().title(tr!("Notes")).build();
        let label = gtk::Label::builder()
            .label(notes)
            .wrap(true)
            .wrap_mode(gtk::pango::WrapMode::WordChar)
            .xalign(0.0)
            .selectable(true)
            .margin_top(12)
            .margin_bottom(12)
            .margin_start(12)
            .margin_end(12)
            .build();
        let frame = gtk::Frame::builder().child(&label).build();
        frame.add_css_class("view");
        frame.add_css_class("ashy-notes");
        group.add(&frame);
        content.append(&group);
    }

    let attachments = inner
        .state
        .vault
        .borrow()
        .list_attachments(id)
        .unwrap_or_default();
    if !attachments.is_empty() {
        let group = adw::PreferencesGroup::builder()
            .title(tr!("Attachments"))
            .build();
        for att in attachments {
            let row = adw::ActionRow::builder()
                .title(&att.filename)
                .subtitle(human_size(att.size_bytes))
                .use_markup(false)
                .build();
            let save = gtk::Button::builder()
                .icon_name("document-save-symbolic")
                .tooltip_text(tr!("Save a copy…"))
                .valign(gtk::Align::Center)
                .build();
            save.add_css_class("flat");
            save.update_property(&[gtk::accessible::Property::Label(tr!("Save a copy…"))]);
            {
                let state = inner.state.clone();
                let toast = inner.toast.clone();
                let filename = att.filename.clone();
                let att_id = att.id;
                save.connect_clicked(move |button| {
                    save_attachment_copy(&state, &toast, button, att_id, &filename);
                });
            }
            row.add_suffix(&save);
            group.add(&row);
        }
        content.append(&group);
    }

    let changed = gtk::Label::builder()
        .label(format!(
            "{} {}",
            tr!("Last changed:"),
            format_timestamp(entry.updated_at)
        ))
        .xalign(0.0)
        .build();
    changed.add_css_class("caption");
    changed.add_css_class("dim-label");
    content.append(&changed);

    let clamp = adw::Clamp::builder()
        .maximum_size(720)
        .child(&content)
        .build();
    // Automatic, not Never: with Never the longest unbreakable value would
    // become the pane's minimum width and resize the split per entry.
    let scrolled = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Automatic)
        .propagate_natural_width(false)
        .vexpand(true)
        .child(&clamp)
        .build();
    outer.append(&scrolled);
    outer.upcast()
}

// ============================================================================
// Helpers
// ============================================================================

/// Local date and time in the user's locale.
pub fn format_timestamp(ts: i64) -> String {
    glib::DateTime::from_unix_local(ts)
        .ok()
        .and_then(|dt| dt.format("%x %X").ok())
        .map(|s| s.to_string())
        .unwrap_or_default()
}

pub(crate) fn save_attachment_copy(
    state: &SharedState,
    toast: &adw::ToastOverlay,
    anchor: &impl IsA<gtk::Widget>,
    att_id: i64,
    filename: &str,
) {
    let parent = anchor.root().and_then(|r| r.downcast::<gtk::Window>().ok());
    let dialog = gtk::FileDialog::builder()
        .title(tr!("Save attachment"))
        .initial_name(filename)
        .modal(true)
        .build();
    let state = state.clone();
    let toast = toast.clone();
    dialog.save(parent.as_ref(), None::<&gio::Cancellable>, move |result| {
        let Ok(file) = result else { return };
        let Some(path) = file.path() else { return };
        let message = match state.vault.borrow().get_attachment(att_id) {
            Ok(Some((_info, data))) => match write_private(&path, &data) {
                Ok(()) => tr!("Attachment saved").to_string(),
                Err(e) => format!("{}: {e}", tr!("Could not save the file")),
            },
            Ok(None) => tr!("Attachment not found").to_string(),
            Err(e) => format!("{}: {e}", tr!("Could not decrypt the attachment")),
        };
        toast.add_toast(adw::Toast::builder().title(message).timeout(4).build());
    });
}

/// Attachments are secrets too: write them owner-only.
fn write_private(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(data)?;
    file.sync_all()
}

fn password_search_text(entry: &PasswordEntry) -> String {
    let mut text = entry.title.to_lowercase();
    for part in [entry.username.as_deref(), entry.url.as_deref()]
        .into_iter()
        .flatten()
        .filter(|s| !s.is_empty())
    {
        text.push('\n');
        text.push_str(&part.to_lowercase());
    }
    text
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

pub(crate) fn human_size(bytes: u64) -> String {
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

pub(crate) fn mime_guess_from_ext(filename: &str) -> Option<String> {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(
        id: i64,
        title: &str,
        username: Option<&str>,
        url: Option<&str>,
        category: Option<&str>,
        favorite: bool,
    ) -> PasswordEntry {
        PasswordEntry {
            id,
            title: title.to_string(),
            username: username.map(str::to_string),
            url: url.map(str::to_string),
            password: None,
            notes: None,
            totp_secret: None,
            totp_algorithm: "SHA1".to_string(),
            totp_digits: 6,
            totp_period: 30,
            has_totp: false,
            category: category.map(str::to_string),
            favorite,
            created_at: 0,
            updated_at: 0,
            last_accessed: None,
        }
    }

    fn sample() -> PasswordListCache {
        PasswordListCache::new(
            vec![
                entry(
                    1,
                    "GitHub",
                    Some("octo"),
                    Some("https://github.com"),
                    Some("Work"),
                    true,
                ),
                entry(
                    2,
                    "Bank",
                    Some("ana"),
                    Some("https://bank.example"),
                    Some("Personal"),
                    false,
                ),
                entry(3, "Router", None, Some("192.168.0.1"), None, false),
                entry(4, "GitLab", Some("octo"), None, Some("Work"), false),
            ],
            vec!["Personal".into(), "Work".into()],
        )
    }

    fn ids(list: Vec<Rc<PasswordEntry>>) -> Vec<i64> {
        list.iter().map(|e| e.id).collect()
    }

    #[test]
    fn search_covers_name_account_and_site() {
        let cache = sample();
        assert_eq!(
            ids(cache.filtered(Some("git"), &FolderFilter::All, false)),
            vec![1, 4]
        );
        assert_eq!(
            ids(cache.filtered(Some("ANA"), &FolderFilter::All, false)),
            vec![2]
        );
        assert_eq!(
            ids(cache.filtered(Some("192.168"), &FolderFilter::All, false)),
            vec![3]
        );
        assert_eq!(
            ids(cache.filtered(Some("   "), &FolderFilter::All, false)).len(),
            4
        );
    }

    #[test]
    fn folders_and_favorites_filter_the_same_collection() {
        let cache = sample();
        let work = FolderFilter::Named("Work".into());
        assert_eq!(ids(cache.filtered(None, &work, false)), vec![1, 4]);
        assert_eq!(ids(cache.filtered(None, &work, true)), vec![1]);
        assert_eq!(
            ids(cache.filtered(None, &FolderFilter::NoFolder, false)),
            vec![3]
        );
        assert_eq!(
            ids(cache.filtered(Some("bank"), &work, false)),
            Vec::<i64>::new()
        );
    }

    #[test]
    fn folder_filter_targets_round_trip_names_with_symbols() {
        for filter in [
            FolderFilter::All,
            FolderFilter::NoFolder,
            FolderFilter::Named("Work: \"x\" (1)".into()),
            FolderFilter::Named("f:odd".into()),
        ] {
            assert_eq!(FolderFilter::from_target(&filter.target()), filter);
        }
    }

    #[test]
    fn blank_category_counts_as_no_folder() {
        assert!(FolderFilter::NoFolder.matches(Some("  ")));
        assert!(!FolderFilter::NoFolder.matches(Some("Work")));
    }

    #[test]
    fn history_mask_keeps_only_the_tail() {
        assert_eq!(mask_password("abcdef"), "•••def");
        assert_eq!(mask_password("ab"), "ab");
        assert_eq!(mask_password(""), "");
    }
}
