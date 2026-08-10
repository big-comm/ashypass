//! Background scheduler for Nextcloud Passwords sync.
//!
//! Three trigger sources, all coalesced through a single single-flight runner:
//!
//! 1. **Post-edit (debounced)** — [`AppEvent::VaultChanged`] schedules a sync
//!    5 seconds in the future. A new edit within that window resets the
//!    timer so we coalesce rapid bursts (typing a long note, bulk import)
//!    into one sync.
//! 2. **Periodic** — every `nextcloud_auto_sync_interval_minutes` minutes,
//!    we run a sync to pull remote changes that came from other clients
//!    (Nextcloud Passwords web/mobile/etc.). Nextcloud has no push API for
//!    Passwords, so polling is the only option.
//! 3. **On unlock** — when the vault transitions from locked to unlocked,
//!    we kick off one sync so the first view is fresh.
//!
//! Single-flight: at most one sync runs at any moment. If a new request
//! arrives while one is in flight, we flip a "rerun-after" flag and start
//! again immediately after the running sync completes.
//!
//! Failures surface as a toast on the toplevel window's toast overlay.
//! Success is silent (sidebar badges and entry rows update via the existing
//! `VaultChanged` event the sync itself emits).

use crate::events::AppEvent;
use crate::state::SharedState;
use crate::tr;
use ashypass_core::settings::Settings;
use ashypass_core::sync::{nextcloud_engine, ConflictResolution, SyncReport};
use gtk::glib;
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::mpsc;

const DEBOUNCE_SECONDS: u32 = 5;

/// Install the auto-sync scheduler onto the given application state.
///
/// Holds references through `Rc`/`RefCell`. The returned handle lets the
/// settings dialog re-apply config when the user toggles the auto-sync
/// preference or changes the interval.
pub fn install(state: SharedState, toast: adw::ToastOverlay) -> Handle {
    let inner = Rc::new(Inner {
        state,
        toast,
        debounce_source: RefCell::new(None),
        periodic_source: RefCell::new(None),
        in_flight: Cell::new(false),
        rerun_after: Cell::new(false),
        settings: RefCell::new(Settings::load()),
    });

    // Subscribe to vault mutations — schedule a debounced sync.
    {
        let inner_for_sub = inner.clone();
        let _permanent = inner.state.events.subscribe(move |event| {
            if matches!(event, AppEvent::VaultChanged) {
                inner_for_sub.schedule_debounced();
            }
        });
    }

    inner.apply_settings();
    Handle { inner }
}

/// Public handle returned by [`install`]. Used by the settings dialog to
/// re-apply preferences after the user changes them.
#[derive(Clone)]
pub struct Handle {
    inner: Rc<Inner>,
}

impl Handle {
    /// Re-read settings from disk and reconfigure the periodic timer.
    #[allow(dead_code)] // Public API: the settings dialog will call this
    pub fn reload_settings(&self) {
        *self.inner.settings.borrow_mut() = Settings::load();
        self.inner.apply_settings();
    }

    /// Trigger one sync right now, cancelling any pending debounce.
    #[allow(dead_code)] // Public API: the settings dialog will call this
    pub fn sync_now(&self) {
        self.inner.cancel_debounce();
        self.inner.run_sync();
    }

    /// Called by the vault unlock flow. Honours
    /// `settings.nextcloud_sync_on_unlock`.
    pub fn on_vault_unlocked(&self) {
        if self.inner.settings.borrow().nextcloud_sync_on_unlock {
            self.inner.run_sync();
        }
    }
}

struct Inner {
    state: SharedState,
    toast: adw::ToastOverlay,
    debounce_source: RefCell<Option<glib::SourceId>>,
    periodic_source: RefCell<Option<glib::SourceId>>,
    in_flight: Cell<bool>,
    rerun_after: Cell<bool>,
    settings: RefCell<Settings>,
}

impl Inner {
    /// Apply the periodic-timer side of the current settings. Idempotent —
    /// cancels any prior timer before installing a new one.
    fn apply_settings(self: &Rc<Self>) {
        if let Some(id) = self.periodic_source.borrow_mut().take() {
            id.remove();
        }
        let s = self.settings.borrow();
        if !s.nextcloud_auto_sync || s.nextcloud_auto_sync_interval_minutes == 0 {
            return;
        }
        let interval_secs = (s.nextcloud_auto_sync_interval_minutes as u64) * 60;
        let inner = self.clone();
        let id = glib::timeout_add_seconds_local(interval_secs as u32, move || {
            inner.run_sync();
            glib::ControlFlow::Continue
        });
        *self.periodic_source.borrow_mut() = Some(id);
    }

    fn schedule_debounced(self: &Rc<Self>) {
        if !self.settings.borrow().nextcloud_auto_sync {
            return;
        }
        self.cancel_debounce();
        let inner = self.clone();
        let id = glib::timeout_add_seconds_local(DEBOUNCE_SECONDS, move || {
            inner.debounce_source.borrow_mut().take();
            inner.run_sync();
            glib::ControlFlow::Break
        });
        *self.debounce_source.borrow_mut() = Some(id);
    }

    fn cancel_debounce(&self) {
        if let Some(id) = self.debounce_source.borrow_mut().take() {
            id.remove();
        }
    }

    fn run_sync(self: &Rc<Self>) {
        // No-op if Nextcloud isn't configured or vault is locked.
        if !self.state.nextcloud.borrow().is_logged_in() {
            return;
        }
        if !self.state.vault.borrow().is_unlocked() {
            return;
        }
        if self.in_flight.get() {
            // A sync is already running — request another one when it
            // finishes so we don't drop the user's edits.
            self.rerun_after.set(true);
            return;
        }
        self.in_flight.set(true);

        // Clone what the worker thread needs. The Nextcloud client owns its
        // HTTP transport and is Send + Sync. The vault is borrowed through
        // `session_reopen_parts` (path + derived key) so the worker can open
        // an independent handle without holding a `RefCell` borrow across
        // the thread boundary or asking the user for a password again.
        let (db_path, session_key) = match self.state.vault.borrow().session_reopen_parts() {
            Ok(parts) => parts,
            Err(e) => {
                log::warn!("auto-sync: vault not reopenable: {e}");
                self.in_flight.set(false);
                return;
            }
        };
        let client = self.state.nextcloud.borrow().clone();
        let (tx, rx) = mpsc::channel::<Result<SyncReport, String>>();
        std::thread::spawn(move || {
            let result = (|| -> Result<SyncReport, String> {
                let vault = ashypass_core::db::Vault::open_with_session_key(db_path, session_key)
                    .map_err(|e| e.to_string())?;
                nextcloud_engine::sync(&vault, &client, ConflictResolution::LastWriteWins)
                    .map_err(|e| e.to_string())
            })();
            let _ = tx.send(result);
        });

        let inner = self.clone();
        glib::timeout_add_local(std::time::Duration::from_millis(150), move || {
            match rx.try_recv() {
                Ok(Ok(report)) => {
                    inner.in_flight.set(false);
                    if !report.stats.errors.is_empty() {
                        show_toast(
                            &inner.toast,
                            &format!(
                                "{} ({})",
                                tr!("Sync completed with issues"),
                                report.stats.errors.len()
                            ),
                        );
                    }
                    // The sync may have inserted/updated entries locally —
                    // notify the rest of the UI so views refresh.
                    if report.stats.created_locally
                        + report.stats.updated_locally
                        + report.stats.deleted_locally
                        > 0
                    {
                        inner.state.events.emit(AppEvent::VaultChanged);
                    }
                    inner.maybe_rerun();
                    glib::ControlFlow::Break
                }
                Ok(Err(msg)) => {
                    inner.in_flight.set(false);
                    show_toast(&inner.toast, &format!("{}: {msg}", tr!("Sync failed")));
                    inner.maybe_rerun();
                    glib::ControlFlow::Break
                }
                Err(mpsc::TryRecvError::Empty) => glib::ControlFlow::Continue,
                Err(mpsc::TryRecvError::Disconnected) => {
                    inner.in_flight.set(false);
                    inner.maybe_rerun();
                    glib::ControlFlow::Break
                }
            }
        });
    }

    fn maybe_rerun(self: &Rc<Self>) {
        if self.rerun_after.replace(false) {
            // Run after the current main-loop turn so we don't recurse.
            let inner = self.clone();
            glib::idle_add_local_once(move || {
                inner.run_sync();
            });
        }
    }
}

fn show_toast(overlay: &adw::ToastOverlay, msg: &str) {
    let t = adw::Toast::builder().title(msg).timeout(4).build();
    overlay.add_toast(t);
}
