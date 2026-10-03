//! Shared application state held by `Rc<RefCell<...>>` so it can be passed
//! into the many `'static`-bounded GTK callbacks.

use ashypass_core::backup::{BackupService, WebdavService};
use ashypass_core::config::settings_file;
use ashypass_core::db::Vault;
use ashypass_core::settings::Settings;
use ashypass_core::sync::NextcloudPasswordsClient;
use std::cell::RefCell;
use std::fs;
use std::rc::Rc;
use std::time::SystemTime;

use adw::prelude::*;

use crate::events::EventBus;
use crate::session::SessionManager;

pub struct AppState {
    pub vault: RefCell<Vault>,
    /// Session is `Rc<RefCell<>>` directly because its glib timers clone the
    /// outer handle to mutate themselves on fire.
    pub session: Rc<RefCell<SessionManager>>,
    pub backup: RefCell<BackupService>,
    pub webdav: RefCell<WebdavService>,
    pub nextcloud: RefCell<NextcloudPasswordsClient>,
    /// Single typed event bus that lets emitters (vault listener, session
    /// timer, sync orchestrator) fan out signals to all interested views
    /// without per-callsite callback wiring.
    pub events: Rc<EventBus>,
    /// Parsed `settings.json`, cached with the file stamp it was parsed from.
    ///
    /// `Settings::load()` reads and re-parses the file on every call, and the
    /// UI reads settings from hot paths — `load_passwords` runs on each search
    /// keystroke. The cache is validated against the file's mtime and length
    /// instead of being explicitly invalidated, so writes made outside
    /// `update_settings` (the settings dialog keeps its own copy, and the CLI
    /// may run concurrently) are still picked up.
    settings: RefCell<CachedSettings>,
    /// Dialogs that show or edit vault data. Locking closes every one of them:
    /// a dialog left open over a locked vault would keep showing secrets, and
    /// acting on it would fail with a raw crypto error.
    sensitive_dialogs: RefCell<Vec<adw::Dialog>>,
}

struct CachedSettings {
    value: Rc<Settings>,
    stamp: Option<FileStamp>,
}

/// Cheap change detector for `settings.json`: modification time plus length.
#[derive(PartialEq, Eq, Clone, Copy)]
struct FileStamp {
    modified: SystemTime,
    len: u64,
}

impl FileStamp {
    fn current() -> Option<Self> {
        let meta = fs::metadata(settings_file()).ok()?;
        Some(Self {
            modified: meta.modified().ok()?,
            len: meta.len(),
        })
    }
}

pub type SharedState = Rc<AppState>;

/// Bridge the core's vault-listener callback (Send + Sync, so it must be
/// reachable from a background thread) into a glib-main-loop dispatch onto
/// the bus, so subscribers never run off the main thread.
fn bridge_vault_events(vault: &Vault, events: &Rc<EventBus>) {
    let events = events.clone();
    vault.add_change_listener(move || {
        let events = events.clone();
        glib::idle_add_local_once(move || {
            events.emit(crate::events::AppEvent::VaultChanged);
        });
    });
}

impl AppState {
    pub fn new(vault: Vault) -> SharedState {
        let events = Rc::new(EventBus::new());
        // Bridge the core's vault-listener callback (Send + Sync, so it must
        // be reachable from a background thread) into a glib-main-loop
        // dispatch onto the bus. Without `idle_add`, a future cross-thread
        // mutation could call subscribers off the main thread, which is
        // unsafe for GTK widgets.
        bridge_vault_events(&vault, &events);
        Rc::new(Self {
            vault: RefCell::new(vault),
            session: Rc::new(RefCell::new(SessionManager::default())),
            backup: RefCell::new(BackupService::new()),
            webdav: RefCell::new(WebdavService::new()),
            nextcloud: RefCell::new(NextcloudPasswordsClient::new()),
            events,
            settings: RefCell::new(CachedSettings {
                value: Rc::new(Settings::load()),
                stamp: FileStamp::current(),
            }),
            sensitive_dialogs: RefCell::new(Vec::new()),
        })
    }

    /// Swap the open vault for `vault` (after a restore) and return the old
    /// one. The new vault gets the same change notifications.
    pub fn install_vault(&self, vault: Vault) -> Vault {
        bridge_vault_events(&vault, &self.events);
        std::mem::replace(&mut *self.vault.borrow_mut(), vault)
    }

    /// Register a dialog to be closed when the vault locks. It unregisters
    /// itself when closed by any other route.
    pub fn track_sensitive_dialog(self: &Rc<Self>, dialog: &impl IsA<adw::Dialog>) {
        let dialog = dialog.upcast_ref::<adw::Dialog>().clone();
        let weak = Rc::downgrade(self);
        dialog.connect_closed(move |closed| {
            if let Some(state) = weak.upgrade() {
                state.sensitive_dialogs.borrow_mut().retain(|d| d != closed);
            }
        });
        self.sensitive_dialogs.borrow_mut().push(dialog);
    }

    /// Close every tracked dialog. Returns how many were open.
    pub fn close_sensitive_dialogs(&self) -> usize {
        // Take the list first: `close()` re-enters the `closed` handler above.
        let open: Vec<adw::Dialog> = std::mem::take(&mut *self.sensitive_dialogs.borrow_mut());
        for dialog in &open {
            dialog.force_close();
        }
        open.len()
    }

    /// Current settings, re-parsed only when `settings.json` changed on disk.
    pub fn settings(&self) -> Rc<Settings> {
        let stamp = FileStamp::current();
        {
            let cached = self.settings.borrow();
            if cached.stamp == stamp {
                return cached.value.clone();
            }
        }
        let value = Rc::new(Settings::load());
        *self.settings.borrow_mut() = CachedSettings {
            value: value.clone(),
            stamp,
        };
        value
    }

    /// Mutate settings, persist them, and refresh the cache. Returns the error
    /// from persisting, if any — the in-memory value is updated regardless so
    /// the UI stays consistent with what the user just chose.
    pub fn update_settings<F>(&self, edit: F) -> ashypass_core::Result<()>
    where
        F: FnOnce(&mut Settings),
    {
        let mut next = (*self.settings()).clone();
        edit(&mut next);
        let result = next.save();
        *self.settings.borrow_mut() = CachedSettings {
            value: Rc::new(next),
            stamp: FileStamp::current(),
        };
        result
    }
}
