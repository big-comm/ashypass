//! Settings → Synchronization — the end-to-end encrypted folder sync (every item
//! type, shared with Ashy Pass for Android). The scheduler is
//! `crate::folder_sync`.

use super::*;
use crate::events::AppEvent;
use crate::state::SyncStatus;
use ashypass_core::sync::folder::{self, FolderSyncOptions};
use ashypass_core::sync::folder_account::FolderSyncAccount;

pub(super) fn build_folder_sync_group(state: SharedState, toast: Toaster) -> adw::PreferencesGroup {
    let group = adw::PreferencesGroup::builder()
        .title(tr!("Encrypted folder sync"))
        .description(tr!(
            "Logins, cards, identities, notes and passkeys, encrypted on this computer before they leave, through a folder on Nextcloud or any WebDAV server. Ashy Pass for Android uses the same folder."
        ))
        .build();

    let status_row = adw::ActionRow::builder().title(tr!("Status")).build();
    group.add(&status_row);

    let connect_row = adw::ActionRow::builder().activatable(true).build();
    connect_row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
    group.add(&connect_row);

    let sync_row = adw::ActionRow::builder()
        .title(tr!("Sync now"))
        .activatable(true)
        .build();
    sync_row.add_suffix(&gtk::Image::from_icon_name("view-refresh-symbolic"));
    group.add(&sync_row);

    let refresh: Rc<dyn Fn()> = {
        let state = state.clone();
        let status_row = status_row.downgrade();
        let connect_row = connect_row.downgrade();
        let sync_row = sync_row.downgrade();
        Rc::new(move || {
            let (Some(status_row), Some(connect_row), Some(sync_row)) = (
                status_row.upgrade(),
                connect_row.upgrade(),
                sync_row.upgrade(),
            ) else {
                return;
            };
            let account = state.folder_account.borrow().clone();
            match account {
                None => {
                    status_row.set_subtitle(tr!("Not connected"));
                    connect_row.set_title(tr!("Connect…"));
                    connect_row.set_subtitle(tr!("Nextcloud or WebDAV address, user, password"));
                    sync_row.set_sensitive(false);
                }
                Some(account) => {
                    let when = match state.folder_status.get() {
                        SyncStatus::Running => tr!("Syncing…").to_string(),
                        SyncStatus::Pending => tr!("Changes waiting to be sent").to_string(),
                        SyncStatus::Synced { at } => format!(
                            "{} {}",
                            tr!("Last sync:"),
                            chrono::DateTime::from_timestamp(at, 0)
                                .map(|t| t
                                    .with_timezone(&chrono::Local)
                                    .format("%x %X")
                                    .to_string())
                                .unwrap_or_default()
                        ),
                        SyncStatus::Failed { .. } => tr!("The last sync failed").to_string(),
                        SyncStatus::Unknown => String::new(),
                    };
                    let place = format!("{} · {}", account.folder, account.user);
                    status_row.set_subtitle(&if when.is_empty() {
                        place
                    } else {
                        format!("{place}\n{when}")
                    });
                    connect_row.set_title(tr!("Disconnect"));
                    connect_row.set_subtitle(tr!(
                        "Items stay here and in the folder; connecting again merges them"
                    ));
                    sync_row.set_sensitive(state.folder_status.get() != SyncStatus::Running);
                }
            }
        })
    };
    refresh();

    let subscription = {
        let refresh = refresh.clone();
        state.events.subscribe(move |event| {
            if matches!(
                event,
                AppEvent::FolderSyncStatusChanged | AppEvent::FolderSyncChanged
            ) {
                refresh();
            }
        })
    };
    {
        let events = state.events.clone();
        group.connect_destroy(move |_| events.unsubscribe(subscription));
    }

    {
        let state = state.clone();
        sync_row.connect_activated(move |_| state.events.emit(AppEvent::FolderSyncRequested));
    }
    {
        let state = state.clone();
        let toast = toast.clone();
        connect_row.connect_activated(move |row| {
            if state.folder_account.borrow().is_some() {
                confirm_disconnect(row, state.clone(), toast.clone());
            } else {
                let parent = row.root().and_then(|r| r.downcast::<gtk::Window>().ok());
                show_connect_dialog(parent.as_ref(), state.clone(), toast.clone());
            }
        });
    }
    group
}

fn confirm_disconnect(row: &adw::ActionRow, state: SharedState, toast: Toaster) {
    let dialog = adw::AlertDialog::builder()
        .heading(tr!("Disconnect the sync folder?"))
        .body(tr!(
            "Your items stay on this computer and in the folder. Connecting again later merges them instead of duplicating."
        ))
        .close_response("cancel")
        .default_response("cancel")
        .build();
    dialog.add_response("cancel", tr!("Cancel"));
    dialog.add_response("disconnect", tr!("Disconnect"));
    dialog.set_response_appearance("disconnect", adw::ResponseAppearance::Destructive);
    dialog.connect_response(Some("disconnect"), move |_, _| {
        if let Err(e) = folder::forget(&state.vault.borrow()) {
            show_toast(&toast, &format!("{}: {e}", tr!("Disconnect failed")));
            return;
        }
        if let Err(e) = FolderSyncAccount::delete() {
            log::warn!("could not delete the sync folder account: {e}");
        }
        *state.folder_account.borrow_mut() = None;
        state.set_folder_status(SyncStatus::Unknown);
        state.events.emit(AppEvent::FolderSyncChanged);
        show_toast(&toast, tr!("Sync folder disconnected"));
    });
    let parent = row.root();
    dialog.present(parent.as_ref());
}

fn show_connect_dialog(parent: Option<&gtk::Window>, state: SharedState, toast: Toaster) {
    if !state.vault.borrow().is_unlocked() {
        show_toast(&toast, tr!("Unlock the vault first"));
        return;
    }
    let needs_master = folder::needs_master_password(&state.vault.borrow()).unwrap_or(true);
    let dialog = adw::AlertDialog::builder()
        .heading(tr!("Connect the sync folder"))
        .body(if needs_master {
            tr!(
                "Use the same master password on all your devices: it opens the folder's key. You type it once here, to join."
            )
        } else {
            ""
        })
        .build();
    dialog.add_response("cancel", tr!("Cancel"));
    dialog.add_response("connect", tr!("Connect"));
    dialog.set_default_response(Some("connect"));
    dialog.set_response_appearance("connect", adw::ResponseAppearance::Suggested);

    let nextcloud_row = adw::SwitchRow::builder()
        .title(tr!("Nextcloud server"))
        .subtitle(tr!("Off: another WebDAV server, with its full address"))
        .active(true)
        .build();
    let url_row = adw::EntryRow::builder()
        .title(tr!("Server address"))
        .build();
    let user_row = adw::EntryRow::builder().title(tr!("Login name")).build();
    let pass_row = adw::PasswordEntryRow::builder()
        .title(tr!("App password"))
        .build();
    let folder_row = adw::EntryRow::builder()
        .title(tr!("Folder"))
        .text("AshyPass Sync")
        .build();
    let master_row = adw::PasswordEntryRow::builder()
        .title(tr!("Master password"))
        .visible(needs_master)
        .build();
    // The Nextcloud Passwords account works for the folder too.
    if let Some(nc) = state.nextcloud.borrow().config.clone() {
        url_row.set_text(&nc.base_url);
        user_row.set_text(&nc.username);
        pass_row.set_text(&nc.app_password);
    }

    let list = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .build();
    list.add_css_class("boxed-list");
    for row in [
        nextcloud_row.upcast_ref::<gtk::Widget>(),
        url_row.upcast_ref(),
        user_row.upcast_ref(),
        pass_row.upcast_ref(),
        folder_row.upcast_ref(),
        master_row.upcast_ref(),
    ] {
        list.append(row);
    }
    dialog.set_extra_child(Some(&list));

    dialog.connect_response(Some("connect"), move |_, _| {
        let account = FolderSyncAccount {
            server_url: url_row.text().trim().to_string(),
            nextcloud: nextcloud_row.is_active(),
            user: user_row.text().trim().to_string(),
            password: pass_row.text().to_string(),
            folder: folder_row.text().trim().to_string(),
        };
        if account.server_url.is_empty() || account.user.is_empty() || account.password.is_empty()
        {
            show_toast(&toast, tr!("Address, user and password are required"));
            return;
        }
        let master = needs_master.then(|| zeroize::Zeroizing::new(master_row.text().to_string()));
        if master.as_ref().is_some_and(|m| m.is_empty()) {
            show_toast(&toast, tr!("Enter the master password"));
            return;
        }
        let parts = match state.vault.borrow().session_reopen_parts() {
            Ok(parts) => parts,
            Err(e) => {
                show_toast(&toast, &format!("{}: {e}", tr!("Connect failed")));
                return;
            }
        };
        state.set_folder_status(SyncStatus::Running);
        let state = state.clone();
        let toast = toast.clone();
        let worker_account = account.clone();
        run_background(
            move || -> ashypass_core::Result<_> {
                let remote = worker_account.remote()?;
                remote.probe()?;
                let vault = ashypass_core::db::Vault::open_with_session_key(parts.0, parts.1)?;
                folder::sync(
                    &vault,
                    &remote,
                    master.as_deref().map(|m| m.as_str()),
                    FolderSyncOptions::default(),
                )
            },
            move |result| match result {
                Ok(report) => {
                    if let Err(e) = account.save() {
                        log::warn!("could not save the sync folder account: {e}");
                    }
                    *state.folder_account.borrow_mut() = Some(account);
                    state.set_folder_status(SyncStatus::Synced {
                        at: chrono::Utc::now().timestamp(),
                    });
                    state.events.emit(AppEvent::FolderSyncChanged);
                    if report.received + report.deleted_here > 0 {
                        state.events.emit(AppEvent::VaultChangedBySync);
                    }
                    show_toast(
                        &toast,
                        &format!(
                            "{} {} · {} {}",
                            tr!("Connected. Received:"),
                            report.received,
                            tr!("sent:"),
                            report.sent
                        ),
                    );
                }
                Err(e) => {
                    state.set_folder_status(SyncStatus::Unknown);
                    let message = match e {
                        ashypass_core::Error::InvalidMasterPassword => {
                            tr!("Wrong master password. The folder belongs to a vault with another one.")
                                .to_string()
                        }
                        e => format!("{}: {e}", tr!("Connect failed")),
                    };
                    show_toast(&toast, &message);
                }
            },
        );
    });
    dialog.present(parent);
}
