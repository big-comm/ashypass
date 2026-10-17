//! Background scheduler for the end-to-end encrypted folder sync
//! (`ashypass_core::sync::folder`), the one shared with Ashy Pass for
//! Android: every item type, through a WebDAV folder.
//!
//! Runs after edits (debounced), when the vault is unlocked, every
//! [`PERIOD_MINUTES`] (doubling after failures, up to an hour), and when
//! Settings asks. One sync at a time; a request during a sync runs another
//! one right after. The master password is only needed to join a folder
//! (Settings asks for it) and after changing it ([`rewrap`]).

use crate::events::AppEvent;
use crate::state::{SharedState, SyncStatus};
use crate::tr;
use crate::trn;
use adw::prelude::*;
use ashypass_core::sync::folder::{self, FolderSyncOptions, FolderSyncReport};
use gtk::glib;
use std::cell::{Cell, RefCell};
use std::rc::Rc;

const DEBOUNCE_SECONDS: u32 = 5;
const PERIOD_MINUTES: u64 = 15;
const MAX_BACKOFF_SECONDS: u64 = 60 * 60;

pub fn install(state: SharedState, toast: adw::ToastOverlay) -> Handle {
    let inner = Rc::new(Inner {
        state,
        toast,
        debounce: RefCell::new(None),
        periodic: RefCell::new(None),
        in_flight: Cell::new(false),
        rerun_after: Cell::new(false),
        failures: Cell::new(0),
        approve_deletes: Cell::new(0),
    });
    let sub = inner.clone();
    let _permanent = inner.state.events.subscribe(move |event| match event {
        AppEvent::VaultChanged => sub.schedule_debounced(),
        AppEvent::FolderSyncRequested => {
            sub.cancel_debounce();
            sub.run();
        }
        AppEvent::FolderSyncChanged => {
            sub.failures.set(0);
            sub.schedule_periodic();
        }
        _ => {}
    });
    inner.schedule_periodic();
    Handle { inner }
}

#[derive(Clone)]
pub struct Handle {
    inner: Rc<Inner>,
}

impl Handle {
    pub fn on_vault_unlocked(&self) {
        self.inner.run();
    }
}

struct Inner {
    state: SharedState,
    toast: adw::ToastOverlay,
    debounce: RefCell<Option<glib::SourceId>>,
    periodic: RefCell<Option<glib::SourceId>>,
    in_flight: Cell<bool>,
    rerun_after: Cell<bool>,
    failures: Cell<u32>,
    /// A large deletion the user approved, for the next sync.
    approve_deletes: Cell<usize>,
}

impl Inner {
    fn schedule_periodic(self: &Rc<Self>) {
        if let Some(id) = self.periodic.borrow_mut().take() {
            id.remove();
        }
        if self.state.folder_account.borrow().is_none() {
            return;
        }
        let base = PERIOD_MINUTES * 60;
        let delay = base
            .saturating_mul(1 << self.failures.get().min(16))
            .min(MAX_BACKOFF_SECONDS.max(base));
        let inner = self.clone();
        let id =
            glib::timeout_add_seconds_local(u32::try_from(delay).unwrap_or(u32::MAX), move || {
                inner.periodic.borrow_mut().take();
                if !inner.run() {
                    inner.schedule_periodic();
                }
                glib::ControlFlow::Break
            });
        *self.periodic.borrow_mut() = Some(id);
    }

    fn schedule_debounced(self: &Rc<Self>) {
        if self.state.folder_account.borrow().is_none() {
            return;
        }
        if !self.in_flight.get() {
            self.state.set_folder_status(SyncStatus::Pending);
        }
        self.cancel_debounce();
        let inner = self.clone();
        let id = glib::timeout_add_seconds_local(DEBOUNCE_SECONDS, move || {
            inner.debounce.borrow_mut().take();
            inner.run();
            glib::ControlFlow::Break
        });
        *self.debounce.borrow_mut() = Some(id);
    }

    fn cancel_debounce(&self) {
        if let Some(id) = self.debounce.borrow_mut().take() {
            id.remove();
        }
    }

    /// Start a sync; false when none was started or queued (not connected,
    /// vault locked).
    fn run(self: &Rc<Self>) -> bool {
        let Some(account) = self.state.folder_account.borrow().clone() else {
            return false;
        };
        if !self.state.vault.borrow().is_unlocked() {
            return false;
        }
        if self.in_flight.replace(true) {
            self.rerun_after.set(true);
            return true;
        }
        let parts = match self.state.vault.borrow().session_reopen_parts() {
            Ok(parts) => parts,
            Err(e) => {
                log::warn!("folder sync: vault not reopenable: {e}");
                self.in_flight.set(false);
                return false;
            }
        };
        self.state.set_folder_status(SyncStatus::Running);
        let options = FolderSyncOptions {
            approve_deletes: self.approve_deletes.replace(0),
        };
        let inner = self.clone();
        crate::ui::settings_dialog::run_background(
            move || -> ashypass_core::Result<FolderSyncReport> {
                let vault = ashypass_core::db::Vault::open_with_session_key(parts.0, parts.1)?;
                folder::sync(&vault, &account.remote()?, None, options)
            },
            move |result| inner.finished(result),
        );
        true
    }

    fn finished(self: &Rc<Self>, result: ashypass_core::Result<FolderSyncReport>) {
        self.in_flight.set(false);
        let now = chrono::Utc::now().timestamp();
        match result {
            Ok(report) => {
                self.failures.set(0);
                self.state.set_folder_status(SyncStatus::Synced { at: now });
                if report.received + report.deleted_here > 0 {
                    // Not `VaultChanged`: that would schedule another sync.
                    self.state.events.emit(AppEvent::VaultChangedBySync);
                }
            }
            Err(ashypass_core::Error::MassDelete { count, .. }) => {
                self.state.set_folder_status(SyncStatus::Failed { at: now });
                self.ask_mass_delete(count);
            }
            Err(e) => {
                self.failures.set(self.failures.get().saturating_add(1));
                self.state.set_folder_status(SyncStatus::Failed { at: now });
                // Only the first failure in a row: offline, every retry
                // would toast again.
                if self.failures.get() == 1 {
                    show_toast(
                        &self.toast,
                        &format!("{}: {e}", tr!("Encrypted folder sync failed")),
                    );
                }
            }
        }
        self.schedule_periodic();
        if self.rerun_after.replace(false) {
            let inner = self.clone();
            glib::idle_add_local_once(move || {
                inner.run();
            });
        }
    }

    fn ask_mass_delete(self: &Rc<Self>, count: usize) {
        let dialog = adw::AlertDialog::builder()
            .heading(
                trn!(
                    "Delete {} entry here too?",
                    "Delete {} entries here too?",
                    count
                )
                .replace("{}", &count.to_string()),
            )
            .body(tr!(
                "Another device deleted them from the encrypted sync folder. If that was you, they move to Deleted items here. If not, keep them: they are sent to the folder again."
            ))
            .close_response("keep")
            .default_response("keep")
            .build();
        dialog.add_response("keep", tr!("Keep them"));
        dialog.add_response("delete", tr!("Move to Deleted items"));
        dialog.set_response_appearance("delete", adw::ResponseAppearance::Destructive);
        let inner = self.clone();
        dialog.connect_response(Some("delete"), move |_, _| {
            inner.approve_deletes.set(count);
            inner.run();
        });
        self.state.track_sensitive_dialog(&dialog);
        dialog.present(Some(&self.toast));
    }
}

/// After the master password changed here: wrap the folder's key with the
/// new one, so other devices join with it. Runs in the background. If it
/// fails (offline), new devices join with the previous password until the
/// next time this runs; existing devices are not affected.
pub fn rewrap(state: &SharedState, new_master: &str) {
    let Some(account) = state.folder_account.borrow().clone() else {
        return;
    };
    let Ok(parts) = state.vault.borrow().session_reopen_parts() else {
        return;
    };
    let master = zeroize::Zeroizing::new(new_master.to_string());
    crate::ui::settings_dialog::run_background(
        move || -> ashypass_core::Result<FolderSyncReport> {
            let vault = ashypass_core::db::Vault::open_with_session_key(parts.0, parts.1)?;
            folder::sync(
                &vault,
                &account.remote()?,
                Some(&master),
                FolderSyncOptions::default(),
            )
        },
        |result| {
            if let Err(e) = result {
                log::warn!("folder sync: re-wrapping the key failed: {e}");
            }
        },
    );
}

fn show_toast(overlay: &adw::ToastOverlay, msg: &str) {
    overlay.add_toast(
        adw::Toast::builder()
            .use_markup(false)
            .title(msg)
            .timeout(4)
            .build(),
    );
}
