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
            "Logins, cards, identities, notes and passkeys, encrypted on this computer before they leave, through a folder on Nextcloud, pCloud, WebDAV, Dropbox, Google Drive or this computer. Ashy Pass for Android uses the same folder."
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
                    connect_row.set_subtitle(tr!(
                        "Nextcloud, pCloud, WebDAV, Dropbox, Google Drive or a local folder"
                    ));
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
                    let service = match account.provider() {
                        ashypass_core::sync::folder_account::PROVIDER_DROPBOX => "Dropbox",
                        ashypass_core::sync::folder_account::PROVIDER_GOOGLE_DRIVE => {
                            "Google Drive"
                        }
                        ashypass_core::sync::folder_account::PROVIDER_LOCAL => {
                            tr!("Folder on this computer")
                        }
                        _ if account.nextcloud => "Nextcloud",
                        _ if account.is_pcloud() => "pCloud",
                        _ => "WebDAV",
                    };
                    let place = [service, &account.folder, &account.user]
                        .into_iter()
                        .filter(|s| !s.is_empty())
                        .collect::<Vec<_>>()
                        .join(" · ");
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
    use ashypass_core::sync::folder_account::{
        PCLOUD_WEBDAV_EU, PCLOUD_WEBDAV_US, PROVIDER_DROPBOX, PROVIDER_GOOGLE_DRIVE,
        PROVIDER_LOCAL, PROVIDER_WEBDAV,
    };
    use ashypass_core::sync::folder_cloud::{dropbox_app_key, DropboxAuth};
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

    // Service: (id, name, kind). WebDAV ones differ in the fields asked.
    #[derive(Clone, Copy, PartialEq)]
    enum Kind {
        Nextcloud,
        Webdav,
        // pCloud: WebDAV on its server for the region, e-mail and password.
        Pcloud(&'static str),
        Other,
    }
    let services: [(&str, &str, Kind); 7] = [
        (PROVIDER_WEBDAV, "Nextcloud", Kind::Nextcloud),
        (
            PROVIDER_WEBDAV,
            tr!("pCloud (data in the US)"),
            Kind::Pcloud(PCLOUD_WEBDAV_US),
        ),
        (
            PROVIDER_WEBDAV,
            tr!("pCloud (data in Europe)"),
            Kind::Pcloud(PCLOUD_WEBDAV_EU),
        ),
        (
            PROVIDER_WEBDAV,
            tr!("WebDAV (ownCloud, Synology, Seafile, Koofr…)"),
            Kind::Webdav,
        ),
        (PROVIDER_DROPBOX, "Dropbox", Kind::Other),
        (PROVIDER_GOOGLE_DRIVE, "Google Drive", Kind::Other),
        (PROVIDER_LOCAL, tr!("Folder on this computer"), Kind::Other),
    ];
    let service_row = adw::ComboRow::builder()
        .title(tr!("Service"))
        .model(&gtk::StringList::new(
            &services.iter().map(|s| s.1).collect::<Vec<_>>(),
        ))
        .build();
    let url_row = adw::EntryRow::builder()
        .title(tr!("Server address"))
        .build();
    let user_row = adw::EntryRow::builder().title(tr!("Login name")).build();
    let pass_row = adw::PasswordEntryRow::builder()
        .title(tr!("App password"))
        .build();
    let pcloud_row = adw::ActionRow::builder()
        .title(tr!("Your pCloud e-mail and password"))
        .subtitle(tr!(
            "With two-step verification on, pCloud e-mails you about the new sign-in: approve it there and connect again."
        ))
        .subtitle_lines(0)
        .build();
    // Dropbox: allow in the browser, paste the code Dropbox shows.
    let dropbox_auth: Rc<RefCell<Option<DropboxAuth>>> = Rc::new(RefCell::new(None));
    let dropbox_row = adw::ActionRow::builder()
        .title(tr!("Allow Ashy Pass in Dropbox"))
        .subtitle(tr!("Opens Dropbox in the browser; copy the code it shows"))
        .build();
    let dropbox_button = gtk::Button::builder()
        .label(tr!("Open Dropbox"))
        .valign(gtk::Align::Center)
        .build();
    dropbox_row.add_suffix(&dropbox_button);
    let code_row = adw::EntryRow::builder()
        .title(tr!("Code from Dropbox"))
        .build();
    {
        let dropbox_auth = dropbox_auth.clone();
        let toast = toast.clone();
        dropbox_button.connect_clicked(move |button| {
            let Some(key) = dropbox_app_key() else {
                show_toast(&toast, tr!("This build has no Dropbox app key"));
                return;
            };
            let auth = DropboxAuth::start(&key);
            let launcher = gtk::UriLauncher::new(&auth.authorize_url());
            let window = button.root().and_then(|r| r.downcast::<gtk::Window>().ok());
            launcher.launch(window.as_ref(), None::<&gio::Cancellable>, |_| {});
            *dropbox_auth.borrow_mut() = Some(auth);
        });
    }
    // Google Drive: the sign-in from Backups → Google Drive.
    let google_row = adw::ActionRow::builder()
        .title(tr!("Google account"))
        .subtitle(if ashypass_core::backup::oauth::Token::load().is_some() {
            tr!("Uses your Google Drive sign-in from Backups")
        } else {
            tr!("Sign in to Google to use your Drive")
        })
        .build();
    let google_button = gtk::Button::builder()
        .label(tr!("Sign in to Google"))
        .valign(gtk::Align::Center)
        .visible(ashypass_core::backup::oauth::Token::load().is_none())
        .build();
    google_row.add_suffix(&google_button);
    {
        let toast = toast.clone();
        let google_row = google_row.clone();
        google_button.connect_clicked(move |button| {
            let Some(creds) = ashypass_core::backup::ClientCredentials::load() else {
                show_toast(&toast, tr!("This build has no Google sign-in configured"));
                return;
            };
            button.set_sensitive(false);
            let button = button.clone();
            let toast = toast.clone();
            let google_row = google_row.clone();
            // Opens the browser; returns when Google sends the user back.
            run_background(
                move || ashypass_core::backup::oauth::login(&creds).map(|_| ()),
                move |result| {
                    button.set_sensitive(true);
                    match result {
                        Ok(()) => {
                            button.set_visible(false);
                            google_row
                                .set_subtitle(tr!("Uses your Google Drive sign-in from Backups"));
                        }
                        Err(e) => {
                            show_toast(&toast, &format!("{}: {e}", tr!("Google sign-in failed")))
                        }
                    }
                },
            );
        });
    }
    // A local folder (synced by Syncthing, a cloud client…).
    let local_path: Rc<RefCell<String>> = Rc::new(RefCell::new(String::new()));
    let local_row = adw::ActionRow::builder()
        .title(tr!("Folder"))
        .subtitle(tr!("Not chosen"))
        .build();
    let local_button = gtk::Button::builder()
        .label(tr!("Choose…"))
        .valign(gtk::Align::Center)
        .build();
    local_row.add_suffix(&local_button);
    {
        let local_path = local_path.clone();
        let local_row = local_row.clone();
        local_button.connect_clicked(move |button| {
            let chooser = gtk::FileDialog::builder()
                .title(tr!("Choose the folder"))
                .modal(true)
                .build();
            let window = button.root().and_then(|r| r.downcast::<gtk::Window>().ok());
            let local_path = local_path.clone();
            let local_row = local_row.clone();
            chooser.select_folder(window.as_ref(), None::<&gio::Cancellable>, move |result| {
                if let Some(path) = result.ok().and_then(|f| f.path()) {
                    let text = path.display().to_string();
                    local_row.set_subtitle(&text);
                    *local_path.borrow_mut() = text;
                }
            });
        });
    }
    let folder_row = adw::EntryRow::builder()
        .title(tr!("Folder name"))
        .text("AshyPass Sync")
        .build();
    let master_row = adw::PasswordEntryRow::builder()
        .title(tr!("Master password"))
        .visible(needs_master)
        .build();
    // The Nextcloud Passwords account works for the folder too.
    let nextcloud = state.nextcloud.borrow().config.clone();
    if let Some(nc) = &nextcloud {
        url_row.set_text(&nc.base_url);
        user_row.set_text(&nc.username);
        pass_row.set_text(&nc.app_password);
    }

    let show_fields = {
        let (url_row, user_row, pass_row) = (url_row.clone(), user_row.clone(), pass_row.clone());
        let pcloud_row = pcloud_row.clone();
        let last_kind = std::cell::Cell::new(Kind::Nextcloud);
        let (dropbox_row, code_row, google_row, local_row) = (
            dropbox_row.clone(),
            code_row.clone(),
            google_row.clone(),
            local_row.clone(),
        );
        move |index: u32| {
            let (provider, _, kind) = services[index as usize];
            let webdav = provider == PROVIDER_WEBDAV;
            let pcloud = matches!(kind, Kind::Pcloud(_));
            // The Nextcloud account's login is no use on pCloud, and the
            // other way round.
            if pcloud != matches!(last_kind.get(), Kind::Pcloud(_)) {
                url_row.set_text("");
                user_row.set_text("");
                pass_row.set_text("");
                if let (Kind::Nextcloud, Some(nc)) = (kind, &nextcloud) {
                    url_row.set_text(&nc.base_url);
                    user_row.set_text(&nc.username);
                    pass_row.set_text(&nc.app_password);
                }
            }
            last_kind.set(kind);
            url_row.set_visible(webdav && !pcloud);
            user_row.set_visible(webdav);
            pass_row.set_visible(webdav);
            pcloud_row.set_visible(pcloud);
            let nextcloud = kind == Kind::Nextcloud;
            url_row.set_title(if nextcloud {
                tr!("Server address")
            } else {
                tr!("WebDAV address")
            });
            user_row.set_title(if nextcloud {
                tr!("Login name")
            } else if pcloud {
                tr!("pCloud e-mail")
            } else {
                tr!("User name")
            });
            pass_row.set_title(if nextcloud {
                tr!("App password")
            } else {
                tr!("Password")
            });
            dropbox_row.set_visible(provider == PROVIDER_DROPBOX);
            code_row.set_visible(provider == PROVIDER_DROPBOX);
            google_row.set_visible(provider == PROVIDER_GOOGLE_DRIVE);
            local_row.set_visible(provider == PROVIDER_LOCAL);
        }
    };
    show_fields(0);
    service_row.connect_selected_notify(move |row| show_fields(row.selected()));

    let list = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .build();
    list.add_css_class("boxed-list");
    for row in [
        service_row.upcast_ref::<gtk::Widget>(),
        pcloud_row.upcast_ref(),
        url_row.upcast_ref(),
        user_row.upcast_ref(),
        pass_row.upcast_ref(),
        dropbox_row.upcast_ref(),
        code_row.upcast_ref(),
        google_row.upcast_ref(),
        local_row.upcast_ref(),
        folder_row.upcast_ref(),
        master_row.upcast_ref(),
    ] {
        list.append(row);
    }
    dialog.set_extra_child(Some(&list));

    dialog.connect_response(Some("connect"), move |_, _| {
        let (provider, _, kind) = services[service_row.selected() as usize];
        let mut account = FolderSyncAccount {
            provider: provider.to_string(),
            nextcloud: kind == Kind::Nextcloud,
            folder: folder_row.text().trim().to_string(),
            ..Default::default()
        };
        // Dropbox signs in during the connection, with the pasted code.
        let mut dropbox_code: Option<(DropboxAuth, String)> = None;
        match provider {
            PROVIDER_WEBDAV => {
                account.server_url = match kind {
                    Kind::Pcloud(server) => server.to_string(),
                    _ => url_row.text().trim().to_string(),
                };
                account.user = user_row.text().trim().to_string();
                account.password = pass_row.text().to_string();
                if account.server_url.is_empty()
                    || account.user.is_empty()
                    || account.password.is_empty()
                {
                    show_toast(&toast, tr!("Address, user and password are required"));
                    return;
                }
            }
            PROVIDER_DROPBOX => {
                let code = code_row.text().trim().to_string();
                match dropbox_auth.borrow_mut().take() {
                    Some(auth) if !code.is_empty() => dropbox_code = Some((auth, code)),
                    _ => {
                        show_toast(
                            &toast,
                            tr!("Open Dropbox, allow Ashy Pass and paste the code it shows"),
                        );
                        return;
                    }
                }
            }
            PROVIDER_LOCAL => {
                account.server_url = local_path.borrow().clone();
                if account.server_url.is_empty() {
                    show_toast(&toast, tr!("Choose the folder"));
                    return;
                }
            }
            _ => {}
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
        run_background(
            move || -> ashypass_core::Result<_> {
                if let Some((auth, code)) = dropbox_code {
                    let tokens = auth.finish(&code)?;
                    account.password = tokens.refresh_token.ok_or_else(|| {
                        ashypass_core::Error::Other("Dropbox gave no refresh token".into())
                    })?;
                }
                let shown = account.probe()?;
                if !shown.is_empty() {
                    account.user = shown;
                }
                let vault = ashypass_core::db::Vault::open_with_session_key(parts.0, parts.1)?;
                let report = folder::sync(
                    &vault,
                    account.remote()?.as_ref(),
                    master.as_deref().map(|m| m.as_str()),
                    FolderSyncOptions::default(),
                )?;
                Ok((account, report))
            },
            move |result| match result {
                Ok((account, report)) => {
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
