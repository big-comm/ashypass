//! Shared application state held by `Rc<RefCell<...>>` so it can be passed
//! into the many `'static`-bounded GTK callbacks.

use ashypass_core::backup::{BackupService, WebdavService};
use ashypass_core::db::Vault;
use ashypass_core::sync::NextcloudPasswordsClient;
use std::cell::RefCell;
use std::rc::Rc;

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
}

pub type SharedState = Rc<AppState>;

impl AppState {
    pub fn new(vault: Vault) -> SharedState {
        let events = Rc::new(EventBus::new());
        // Bridge the core's vault-listener callback (Send + Sync, so it must
        // be reachable from a background thread) into a glib-main-loop
        // dispatch onto the bus. Without `idle_add`, a future cross-thread
        // mutation could call subscribers off the main thread, which is
        // unsafe for GTK widgets.
        {
            let events = events.clone();
            vault.add_change_listener(move || {
                let events = events.clone();
                glib::idle_add_local_once(move || {
                    events.emit(crate::events::AppEvent::VaultChanged);
                });
            });
        }
        Rc::new(Self {
            vault: RefCell::new(vault),
            session: Rc::new(RefCell::new(SessionManager::default())),
            backup: RefCell::new(BackupService::new()),
            webdav: RefCell::new(WebdavService::new()),
            nextcloud: RefCell::new(NextcloudPasswordsClient::new()),
            events,
        })
    }
}
