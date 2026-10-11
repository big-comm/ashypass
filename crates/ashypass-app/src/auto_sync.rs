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
//!    Passwords, so polling is the only option. After consecutive failures
//!    the delay doubles, up to one hour, and resets on the next success.
//! 3. **On unlock** — when the vault transitions from locked to unlocked,
//!    we kick off one sync so the first view is fresh.
//!
//! Single-flight: at most one sync runs at any moment. If a new request
//! arrives while one is in flight, we flip a "rerun-after" flag and start
//! again immediately after the running sync completes.
//!
//! Failures surface as a toast on the toplevel window's toast overlay.
//! Success is silent: when the sync changed local data it emits
//! [`AppEvent::VaultChangedBySync`], which refreshes the views without
//! scheduling another sync.

use crate::events::AppEvent;
use crate::state::{SharedState, SyncStatus};
use crate::tr;
use ashypass_core::settings::Settings;
use ashypass_core::sync::{nextcloud_engine, ConflictResolution, SyncReport};
use gtk::glib;
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::mpsc;

const DEBOUNCE_SECONDS: u32 = 5;
/// Longest periodic delay reached by backing off after failures.
const MAX_BACKOFF_SECONDS: u64 = 60 * 60;

/// Install the auto-sync scheduler onto the given application state.
///
/// Holds references through `Rc`/`RefCell`. The settings dialog announces
/// preference changes with [`AppEvent::SyncSettingsChanged`], which makes the
/// scheduler re-read them.
pub fn install(state: SharedState, toast: adw::ToastOverlay) -> Handle {
    let inner = Rc::new(Inner {
        settings: RefCell::new((*state.settings()).clone()),
        state,
        toast,
        debounce_source: RefCell::new(None),
        periodic_source: RefCell::new(None),
        in_flight: Cell::new(false),
        rerun_after: Cell::new(false),
        failures: Cell::new(0),
    });

    // Subscribe to vault mutations — schedule a debounced sync. Changes made
    // by a sync arrive as `VaultChangedBySync` and are deliberately ignored.
    {
        let inner_for_sub = inner.clone();
        let _permanent = inner.state.events.subscribe(move |event| match event {
            AppEvent::VaultChanged => inner_for_sub.schedule_debounced(),
            AppEvent::SyncSettingsChanged => inner_for_sub.reload_settings(),
            _ => {}
        });
    }

    inner.apply_settings();
    Handle { inner }
}

/// Public handle returned by [`install`].
#[derive(Clone)]
pub struct Handle {
    inner: Rc<Inner>,
}

impl Handle {
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
    /// Syncs that failed in a row; stretches the periodic delay.
    failures: Cell<u32>,
    settings: RefCell<Settings>,
}

impl Inner {
    /// Re-read the preferences and reconfigure the timers.
    fn reload_settings(self: &Rc<Self>) {
        *self.settings.borrow_mut() = (*self.state.settings()).clone();
        if !self.settings.borrow().nextcloud_auto_sync {
            self.cancel_debounce();
        }
        self.apply_settings();
    }

    /// Apply the periodic-timer side of the current settings. Idempotent —
    /// cancels any prior timer before installing a new one.
    fn apply_settings(self: &Rc<Self>) {
        self.schedule_periodic();
    }

    /// (Re)start the periodic timer from now. One-shot: each run schedules
    /// the next one when it finishes, so the delay can follow the failures.
    fn schedule_periodic(self: &Rc<Self>) {
        if let Some(id) = self.periodic_source.borrow_mut().take() {
            id.remove();
        }
        let interval_minutes = {
            let s = self.settings.borrow();
            if !s.nextcloud_auto_sync || s.nextcloud_auto_sync_interval_minutes == 0 {
                return;
            }
            s.nextcloud_auto_sync_interval_minutes
        };
        let delay = periodic_delay_seconds(interval_minutes, self.failures.get());
        let inner = self.clone();
        let id =
            glib::timeout_add_seconds_local(u32::try_from(delay).unwrap_or(u32::MAX), move || {
                inner.periodic_source.borrow_mut().take();
                if !inner.run_sync() {
                    // Nothing ran (signed out, locked): try again later.
                    inner.schedule_periodic();
                }
                glib::ControlFlow::Break
            });
        *self.periodic_source.borrow_mut() = Some(id);
    }

    fn schedule_debounced(self: &Rc<Self>) {
        if !self.settings.borrow().nextcloud_auto_sync {
            return;
        }
        if self.state.nextcloud.borrow().is_logged_in() && !self.in_flight.get() {
            self.state.set_sync_status(SyncStatus::Pending);
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

    /// Start a sync. Returns false when none was started or queued (not
    /// signed in, vault locked); a queued or started sync reschedules the
    /// periodic timer when it finishes.
    fn run_sync(self: &Rc<Self>) -> bool {
        // No-op if Nextcloud isn't configured or vault is locked.
        if !self.state.nextcloud.borrow().is_logged_in() {
            return false;
        }
        if !self.state.vault.borrow().is_unlocked() {
            return false;
        }
        if self.in_flight.get() {
            // A sync is already running — request another one when it
            // finishes so we don't drop the user's edits.
            self.rerun_after.set(true);
            return true;
        }
        self.in_flight.set(true);
        self.state.set_sync_status(SyncStatus::Running);

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
                return false;
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
                    inner.failures.set(0);
                    let now = chrono::Utc::now().timestamp();
                    inner
                        .state
                        .set_sync_status(if report.stats.errors.is_empty() {
                            SyncStatus::Synced { at: now }
                        } else {
                            SyncStatus::Failed { at: now }
                        });
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
                    // notify the rest of the UI so views refresh. Not
                    // `VaultChanged`: that would schedule another sync.
                    if report.stats.created_locally
                        + report.stats.updated_locally
                        + report.stats.deleted_locally
                        > 0
                    {
                        inner.state.events.emit(AppEvent::VaultChangedBySync);
                    }
                    inner.finish();
                    glib::ControlFlow::Break
                }
                Ok(Err(msg)) => {
                    inner.in_flight.set(false);
                    inner.failures.set(inner.failures.get().saturating_add(1));
                    inner.state.set_sync_status(SyncStatus::Failed {
                        at: chrono::Utc::now().timestamp(),
                    });
                    show_toast(&inner.toast, &format!("{}: {msg}", tr!("Sync failed")));
                    inner.finish();
                    glib::ControlFlow::Break
                }
                Err(mpsc::TryRecvError::Empty) => glib::ControlFlow::Continue,
                Err(mpsc::TryRecvError::Disconnected) => {
                    inner.in_flight.set(false);
                    inner.failures.set(inner.failures.get().saturating_add(1));
                    inner.state.set_sync_status(SyncStatus::Failed {
                        at: chrono::Utc::now().timestamp(),
                    });
                    inner.finish();
                    glib::ControlFlow::Break
                }
            }
        });
        true
    }

    /// After a sync: restart the periodic timer (with the current backoff)
    /// and run a sync that was requested meanwhile.
    fn finish(self: &Rc<Self>) {
        self.schedule_periodic();
        self.maybe_rerun();
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

/// Seconds until the next periodic sync: the configured interval, doubled
/// for each consecutive failure, but never more than an hour (or the
/// interval itself, if that is longer).
fn periodic_delay_seconds(interval_minutes: u32, failures: u32) -> u64 {
    let base = u64::from(interval_minutes) * 60;
    let backoff = base.saturating_mul(1u64 << failures.min(16));
    backoff.min(MAX_BACKOFF_SECONDS.max(base))
}

fn show_toast(overlay: &adw::ToastOverlay, msg: &str) {
    let t = adw::Toast::builder().title(msg).timeout(4).build();
    overlay.add_toast(t);
}

#[cfg(test)]
mod tests {
    use super::periodic_delay_seconds;

    #[test]
    fn failures_double_the_delay_up_to_an_hour() {
        assert_eq!(periodic_delay_seconds(5, 0), 300);
        assert_eq!(periodic_delay_seconds(5, 1), 600);
        assert_eq!(periodic_delay_seconds(5, 2), 1200);
        assert_eq!(periodic_delay_seconds(5, 3), 2400);
        assert_eq!(periodic_delay_seconds(5, 4), 3600);
        assert_eq!(periodic_delay_seconds(5, 40), 3600);
        // An interval of an hour or more is never shortened.
        assert_eq!(periodic_delay_seconds(60, 0), 3600);
        assert_eq!(periodic_delay_seconds(90, 3), 5400);
    }
}
