//! Settings → Synchronization — the end-to-end encrypted folder sync (every item
//! type, shared with Ashy Pass for Android). The scheduler is
//! `crate::folder_sync`.

use super::*;
use crate::events::AppEvent;
use crate::state::SyncStatus;
use ashypass_core::sync::folder::{self, FolderSyncOptions};
use ashypass_core::sync::folder_account::FolderSyncAccount;
use ashypass_core::sync::pairing;

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

    let pair_row = adw::ActionRow::builder()
        .title(tr!("Connect a phone…"))
        .subtitle(tr!("Shows a QR code to scan with Ashy Pass for Android"))
        .activatable(true)
        .build();
    pair_row.add_suffix(&gtk::Image::from_icon_name("phone-symbolic"));
    group.add(&pair_row);

    let refresh: Rc<dyn Fn()> = {
        let state = state.clone();
        let status_row = status_row.downgrade();
        let connect_row = connect_row.downgrade();
        let sync_row = sync_row.downgrade();
        let pair_row = pair_row.downgrade();
        Rc::new(move || {
            let (Some(status_row), Some(connect_row), Some(sync_row), Some(pair_row)) = (
                status_row.upgrade(),
                connect_row.upgrade(),
                sync_row.upgrade(),
                pair_row.upgrade(),
            ) else {
                return;
            };
            let account = state.folder_account.borrow().clone();
            pair_row.set_visible(account.as_ref().is_some_and(pairing::can_pair));
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
        pair_row.connect_activated(move |row| {
            if let Some(account) = state.folder_account.borrow().clone() {
                show_pairing_dialog(row, account, toast.clone());
            }
        });
    }
    {
        let state = state.clone();
        let toast = toast.clone();
        connect_row.connect_activated(move |row| {
            if state.folder_account.borrow().is_some() {
                confirm_disconnect(row, state.clone(), toast.clone());
            } else if let Some(dialog) = row
                .ancestor(adw::PreferencesDialog::static_type())
                .and_downcast::<adw::PreferencesDialog>()
            {
                show_connect_page(&dialog, state.clone(), toast.clone());
            }
        });
    }
    group
}

fn confirm_disconnect(row: &adw::ActionRow, state: SharedState, toast: Toaster) {
    let dialog = big_gtk_kit::alert::Alert::builder(row.root().as_ref())
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
    dialog.present();
}

/// The connection form, as a page of the settings: it stays open while
/// connecting (with a spinner) and shows what went wrong, to fix and retry.
fn show_connect_page(dialog: &adw::PreferencesDialog, state: SharedState, toast: Toaster) {
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
    let pass_row = big_gtk_kit::password::password_row(
        adw::PasswordEntryRow::builder().title(tr!("App password")),
    );
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
        // Weak: the button sits in the row.
        let google_row = google_row.downgrade();
        google_button.connect_clicked(move |button| {
            let Some(creds) = ashypass_core::backup::ClientCredentials::load() else {
                show_toast(&toast, tr!("This build has no Google sign-in configured"));
                return;
            };
            let Some(google_row) = google_row.upgrade() else {
                return;
            };
            button.set_sensitive(false);
            google_row.set_subtitle(tr!("Waiting for Google in the browser…"));
            let button = button.clone();
            let toast = toast.clone();
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
                            google_row.set_subtitle(tr!("Sign in to Google to use your Drive"));
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
        // Weak: the button sits in the row.
        let local_row = local_row.downgrade();
        local_button.connect_clicked(move |button| {
            let chooser = gtk::FileDialog::builder()
                .title(tr!("Choose the folder"))
                .modal(true)
                .build();
            let window = button.root().and_then(|r| r.downcast::<gtk::Window>().ok());
            let local_path = local_path.clone();
            let local_row = local_row.clone();
            chooser.select_folder(window.as_ref(), None::<&gio::Cancellable>, move |result| {
                if let (Some(path), Some(local_row)) =
                    (result.ok().and_then(|f| f.path()), local_row.upgrade())
                {
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
    let master_row = big_gtk_kit::password::password_row(
        adw::PasswordEntryRow::builder()
            .title(tr!("Master password"))
            .visible(needs_master),
    );
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

    let page = adw::PreferencesPage::new();
    let group = adw::PreferencesGroup::builder()
        .description(if needs_master {
            tr!(
                "Use the same master password on all your devices: it opens the folder's key. You type it once here, to join."
            )
        } else {
            ""
        })
        .build();
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
        group.add(row);
    }
    page.add(&group);

    // While connecting: a spinner and what is going on; after a failure,
    // what went wrong, with the form left as it was.
    let spinner = gtk::Spinner::builder().visible(false).build();
    let status = gtk::Label::builder()
        .xalign(0.0)
        .wrap(true)
        .hexpand(true)
        .build();
    status.set_accessible_role(gtk::AccessibleRole::Alert);
    let status_box = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(12)
        .visible(false)
        .build();
    status_box.append(&spinner);
    status_box.append(&status);
    let button = gtk::Button::builder()
        .label(tr!("Connect"))
        .halign(gtk::Align::End)
        .build();
    button.add_css_class("suggested-action");
    button.add_css_class("pill");
    let action_box = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(12)
        .build();
    action_box.append(&status_box);
    action_box.append(&button);
    let actions = adw::PreferencesGroup::new();
    actions.add(&action_box);
    page.add(&actions);

    // Weak: the Connect button's own handler calls it.
    let show = {
        let (spinner, status, status_box) = (
            spinner.downgrade(),
            status.downgrade(),
            status_box.downgrade(),
        );
        let (group, button) = (group.downgrade(), button.downgrade());
        move |message: &str, busy: bool| {
            let (Some(spinner), Some(status), Some(status_box), Some(group), Some(button)) = (
                spinner.upgrade(),
                status.upgrade(),
                status_box.upgrade(),
                group.upgrade(),
                button.upgrade(),
            ) else {
                return;
            };
            status_box.set_visible(!message.is_empty());
            status.set_label(message);
            if busy {
                status.remove_css_class("error");
            } else {
                status.add_css_class("error");
            }
            spinner.set_visible(busy);
            spinner.set_spinning(busy);
            group.set_sensitive(!busy);
            button.set_sensitive(!busy);
        }
    };

    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&adw::HeaderBar::new());
    toolbar.set_content(Some(&page));
    let nav = adw::NavigationPage::builder()
        .title(tr!("Connect the sync folder"))
        .child(&toolbar)
        .build();

    // Dropbox's code works once: the sign-in it gave is kept for a retry
    // (after a wrong master password, say).
    let dropbox_token: Rc<RefCell<Option<String>>> = Rc::new(RefCell::new(None));
    let dialog_weak = dialog.downgrade();
    button.connect_clicked(move |_| {
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
                    show(tr!("Address, user and password are required"), false);
                    return;
                }
            }
            PROVIDER_DROPBOX => {
                if let Some(token) = dropbox_token.borrow().clone() {
                    account.password = token;
                } else {
                    let code = code_row.text().trim().to_string();
                    match dropbox_auth.borrow_mut().take() {
                        Some(auth) if !code.is_empty() => dropbox_code = Some((auth, code)),
                        auth => {
                            *dropbox_auth.borrow_mut() = auth;
                            show(
                                tr!("Open Dropbox, allow Ashy Pass and paste the code it shows"),
                                false,
                            );
                            return;
                        }
                    }
                }
            }
            PROVIDER_LOCAL => {
                account.server_url = local_path.borrow().clone();
                if account.server_url.is_empty() {
                    show(tr!("Choose the folder"), false);
                    return;
                }
            }
            _ => {}
        }
        let master = needs_master.then(|| zeroize::Zeroizing::new(master_row.text().to_string()));
        if master.as_ref().is_some_and(|m| m.is_empty()) {
            show(tr!("Enter the master password"), false);
            return;
        }
        let parts = match state.vault.borrow().session_reopen_parts() {
            Ok(parts) => parts,
            Err(e) => {
                show(&format!("{}: {e}", tr!("Connect failed")), false);
                return;
            }
        };
        show(tr!("Connecting and syncing…"), true);
        state.set_folder_status(SyncStatus::Running);
        let state = state.clone();
        let toast = toast.clone();
        let show = show.clone();
        let dialog_weak = dialog_weak.clone();
        let dropbox_token = dropbox_token.clone();
        run_background(
            move || {
                // The Dropbox sign-in, kept even when what follows fails.
                let mut token = None;
                let result = (|| -> ashypass_core::Result<_> {
                    if let Some((auth, code)) = dropbox_code {
                        let tokens = auth.finish(&code)?;
                        account.password = tokens.refresh_token.ok_or_else(|| {
                            ashypass_core::Error::Other("Dropbox gave no refresh token".into())
                        })?;
                        token = Some(account.password.clone());
                    }
                    let shown = account.probe()?;
                    if !shown.is_empty() {
                        account.user = shown;
                    }
                    let vault =
                        ashypass_core::db::Vault::open_with_session_key(parts.0, parts.1)?;
                    let report = folder::sync(
                        &vault,
                        account.remote()?.as_ref(),
                        master.as_deref().map(|m| m.as_str()),
                        FolderSyncOptions::default(),
                    )?;
                    Ok((account, report))
                })();
                (token, result)
            },
            move |(token, result)| {
                if token.is_some() {
                    *dropbox_token.borrow_mut() = token;
                }
                match result {
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
                        if let Some(dialog) = dialog_weak.upgrade() {
                            dialog.pop_subpage();
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
                        show(&message, false);
                    }
                }
            },
        );
    });
    dialog.push_subpage(&nav);
}

/// The connection as a QR code for Ashy Pass for Android, sealed with a
/// 6-digit code shown below it (`ashypass_core::sync::pairing`).
fn show_pairing_dialog(row: &adw::ActionRow, account: FolderSyncAccount, toast: Toaster) {
    let dialog = big_gtk_kit::alert::Alert::builder(row.root().as_ref())
        .heading(tr!("Connect a phone"))
        .body(tr!(
            "In Ashy Pass for Android, open Settings → Encrypted folder sync and tap “Scan the computer's QR code”. Then type the code below and your master password."
        ))
        .build();
    dialog.add_response("close", tr!("Close"));
    dialog.set_default_response(Some("close"));

    let content = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(12)
        .halign(gtk::Align::Center)
        .build();
    let spinner = gtk::Spinner::builder()
        .spinning(true)
        .width_request(48)
        .height_request(48)
        .margin_top(24)
        .margin_bottom(24)
        .build();
    content.append(&spinner);
    dialog.set_extra_child(Some(&content));

    // Sealing costs a memory-hard key derivation: off the main thread.
    let now = chrono::Utc::now().timestamp();
    let dialog_weak = dialog.downgrade();
    run_background(
        move || -> ashypass_core::Result<(pairing::Pairing, Vec<u8>, u32)> {
            let pairing = pairing::seal(&account, now)?;
            let (pixels, size) = qr_pixels(&pairing.qr)?;
            Ok((pairing, pixels, size))
        },
        move |result| {
            let Some(dialog) = dialog_weak.upgrade() else {
                return;
            };
            content.remove(&spinner);
            match result {
                Ok((pairing, pixels, size)) => {
                    let texture = gtk::gdk::MemoryTexture::new(
                        size as i32,
                        size as i32,
                        gtk::gdk::MemoryFormat::R8g8b8,
                        &glib::Bytes::from_owned(pixels),
                        size as usize * 3,
                    );
                    let picture = gtk::Picture::for_paintable(&texture);
                    picture.set_can_shrink(false);
                    picture.set_alternative_text(Some(tr!("Connection QR code")));
                    content.append(&picture);
                    let code = gtk::Label::builder()
                        .label(format!("{} {}", &pairing.code[..3], &pairing.code[3..]))
                        .selectable(true)
                        .build();
                    code.add_css_class("title-1");
                    code.add_css_class("monospace");
                    content.append(&code);
                    let note = gtk::Label::builder()
                        .label(tr!(
                            "Good for 10 minutes. The QR code alone is no use without this code, and neither opens your passwords without the master password."
                        ))
                        .wrap(true)
                        .max_width_chars(42)
                        .justify(gtk::Justification::Center)
                        .build();
                    note.add_css_class("dim-label");
                    content.append(&note);
                    // Gone when it stops working.
                    let dialog_weak = dialog.downgrade();
                    glib::timeout_add_seconds_local_once(
                        pairing::PAIRING_TTL_SECS as u32,
                        move || {
                            if let Some(dialog) = dialog_weak.upgrade() {
                                dialog.close();
                            }
                        },
                    );
                }
                Err(e) => {
                    dialog.close();
                    show_toast(
                        &toast,
                        &format!("{}: {e}", tr!("Could not make the QR code")),
                    );
                }
            }
        },
    );
    dialog.present();
}

/// `text` as a QR code: RGB pixels, and the side in pixels.
fn qr_pixels(text: &str) -> ashypass_core::Result<(Vec<u8>, u32)> {
    let code = qrcode::QrCode::new(text.as_bytes())
        .map_err(|e| ashypass_core::Error::Other(format!("QR code: {e}")))?;
    let image = code
        .render::<image::Rgb<u8>>()
        .quiet_zone(true)
        .min_dimensions(280, 280)
        .build();
    let size = image.width();
    Ok((image.into_raw(), size))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pairing_qr_code_reads_back() {
        let account = FolderSyncAccount {
            provider: "dropbox".into(),
            user: "ana@example.com".into(),
            // About the size of a Dropbox refresh token.
            password: "x".repeat(64),
            folder: "AshyPass Sync".into(),
            ..Default::default()
        };
        let pairing = pairing::seal(&account, 0).unwrap();
        let (pixels, size) = qr_pixels(&pairing.qr).unwrap();
        let image = image::RgbImage::from_raw(size, size, pixels).unwrap();
        let luma = image::DynamicImage::ImageRgb8(image).to_luma8();
        let mut prepared =
            rqrr::PreparedImage::prepare_from_greyscale(size as usize, size as usize, |x, y| {
                luma.get_pixel(x as u32, y as u32).0[0]
            });
        let grids = prepared.detect_grids();
        assert_eq!(grids.len(), 1);
        let (_, text) = grids[0].decode().unwrap();
        assert_eq!(text, pairing.qr);
    }
}
