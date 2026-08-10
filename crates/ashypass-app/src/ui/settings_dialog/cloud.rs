//! `settings_dialog` — cloud section.

use super::*;

// ---------------------------------------------------------------------------
// Cloud Backup — Google Drive (task #11)
// ---------------------------------------------------------------------------

pub(super) fn populate_cloud(
    page: &adw::PreferencesPage,
    state: SharedState,
    toast: adw::ToastOverlay,
    parent: gtk::Widget,
    dialog_slot: Rc<RefCell<Option<adw::Dialog>>>,
) {
    let creds = Rc::new(RefCell::new(
        ashypass_core::backup::ClientCredentials::load(),
    ));
    let logged_in = state.backup.borrow().is_logged_in();

    let group = adw::PreferencesGroup::builder()
        .title(tr!("Google Drive"))
        .description(tr!(
            "Encrypted vault uploaded as-is. Folder: \"AshyPass Backups\"."
        ))
        .build();

    let status_row = adw::ActionRow::builder()
        .title(tr!("Status"))
        .subtitle(if logged_in {
            tr!("Signed in")
        } else if creds.borrow().is_none() {
            tr!("Not configured")
        } else {
            tr!("Not signed in")
        })
        .build();
    group.add(&status_row);

    let drive_action_rows: Rc<RefCell<Vec<adw::ActionRow>>> = Rc::new(RefCell::new(Vec::new()));
    let google_signin_row: Rc<RefCell<Option<adw::ActionRow>>> = Rc::new(RefCell::new(None));

    let configure_row = adw::ActionRow::builder()
        .title(tr!("Configure Google OAuth"))
        .subtitle(if creds.borrow().is_some() {
            tr!("Configured")
        } else {
            tr!("OAuth client not configured at build time")
        })
        .activatable(true)
        .build();
    configure_row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
    {
        let creds = creds.clone();
        let status = status_row.clone();
        let toast = toast.clone();
        let signin_row = google_signin_row.clone();
        let configure = configure_row.clone();
        configure_row.connect_activated(move |row| {
            let parent = row.root().and_then(|r| r.downcast::<gtk::Window>().ok());
            show_google_oauth_dialog(
                parent.as_ref(),
                creds.clone(),
                status.clone(),
                configure.clone(),
                signin_row.borrow().clone(),
                toast.clone(),
            );
        });
    }
    group.add(&configure_row);

    let signin_row = adw::ActionRow::builder()
        .title(if logged_in {
            tr!("Sign out")
        } else {
            tr!("Sign in to Google")
        })
        .subtitle(tr!("Opens the browser for OAuth consent"))
        .activatable(true)
        .build();
    signin_row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
    signin_row.set_sensitive(logged_in || creds.borrow().is_some());
    *google_signin_row.borrow_mut() = Some(signin_row.clone());
    {
        let state = state.clone();
        let toast = toast.clone();
        let creds = creds.clone();
        let status = status_row.clone();
        let signin = signin_row.clone();
        let action_rows = drive_action_rows.clone();
        signin_row.connect_activated(move |_| {
            if state.backup.borrow().is_logged_in() {
                if let Err(e) = state.backup.borrow_mut().logout() {
                    show_toast(&toast, &format!("{}: {e}", tr!("Sign out failed")));
                    return;
                }
                status.set_subtitle(tr!("Not signed in"));
                signin.set_title(tr!("Sign in to Google"));
                for row in action_rows.borrow().iter() {
                    row.set_sensitive(false);
                }
                show_toast(&toast, tr!("Signed out"));
                return;
            }
            let Some(c) = creds.borrow().clone() else {
                show_toast(&toast, tr!("Not configured"));
                return;
            };
            signin.set_sensitive(false);
            status.set_subtitle(tr!("Signing in…"));
            let mut service = state.backup.borrow().clone();
            let state_done = state.clone();
            let toast_done = toast.clone();
            let status_done = status.clone();
            let signin_done = signin.clone();
            let action_rows_done = action_rows.clone();
            run_background(
                move || {
                    let result = service.login(&c);
                    (service, result)
                },
                move |(service, result)| {
                    *state_done.backup.borrow_mut() = service;
                    signin_done.set_sensitive(true);
                    match result {
                        Ok(()) => {
                            status_done.set_subtitle(tr!("Signed in"));
                            signin_done.set_title(tr!("Sign out"));
                            for row in action_rows_done.borrow().iter() {
                                row.set_sensitive(true);
                            }
                            show_toast(&toast_done, tr!("Signed in to Google Drive"));
                        }
                        Err(e) => {
                            status_done.set_subtitle(tr!("Not signed in"));
                            show_toast(&toast_done, &format!("{}: {e}", tr!("Sign in failed")));
                        }
                    }
                },
            );
        });
    }
    group.add(&signin_row);

    let backup_row = adw::ActionRow::builder()
        .title(tr!("Back up now"))
        .subtitle(tr!("Upload the current vault file to Drive"))
        .activatable(true)
        .build();
    backup_row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
    backup_row.set_sensitive(logged_in);
    drive_action_rows.borrow_mut().push(backup_row.clone());
    {
        let state = state.clone();
        let toast = toast.clone();
        backup_row.connect_activated(move |row| {
            let stamp = chrono::Utc::now().format("%Y%m%d-%H%M%S").to_string();
            let name = format!("passwords-{stamp}.db");
            let parts = match state.vault.borrow().session_reopen_parts() {
                Ok(parts) => parts,
                Err(error) => {
                    show_toast(&toast, &format!("{}: {error}", tr!("Backup failed")));
                    return;
                }
            };
            row.set_sensitive(false);
            let row_done = row.clone();
            let mut service = state.backup.borrow().clone();
            let state_done = state.clone();
            let toast_done = toast.clone();
            run_background(
                move || {
                    let snapshot = temporary_snapshot_path("drive");
                    let outcome: ashypass_core::Result<()> = (|| {
                        let vault =
                            ashypass_core::db::Vault::open_with_session_key(parts.0, parts.1)?;
                        vault.backup_to(&snapshot)?;
                        service.upload(&snapshot, &name)?;
                        Ok(())
                    })();
                    let _ = std::fs::remove_file(&snapshot);
                    (service, outcome)
                },
                move |(service, outcome)| {
                    *state_done.backup.borrow_mut() = service;
                    row_done.set_sensitive(true);
                    match outcome {
                        Ok(()) => show_toast(&toast_done, tr!("Backup uploaded")),
                        Err(e) => {
                            show_toast(&toast_done, &format!("{}: {e}", tr!("Backup failed")))
                        }
                    }
                },
            );
        });
    }
    group.add(&backup_row);

    let restore_row = adw::ActionRow::builder()
        .title(tr!("Restore latest"))
        .activatable(true)
        .build();
    restore_row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
    restore_row.set_sensitive(logged_in);
    drive_action_rows.borrow_mut().push(restore_row.clone());
    {
        let state = state.clone();
        let toast = toast.clone();
        restore_row.connect_activated(move |row| {
            row.set_sensitive(false);
            let row_done = row.clone();
            let mut service = state.backup.borrow().clone();
            let state_done = state.clone();
            let toast_done = toast.clone();
            run_background(
                move || {
                    let outcome: ashypass_core::Result<std::path::PathBuf> = (|| {
                        let svc = &mut service;
                        let files = svc.list_backups()?;
                        let latest = files
                            .iter()
                            .find(|file| is_database_backup_name(&file.name))
                            .ok_or(ashypass_core::Error::Other("no backups found".into()))?
                            .clone();
                        let dest = restore_destination();
                        svc.download(&latest.id, &dest)?;
                        if let Err(error) = ashypass_core::db::Vault::validate_database(&dest) {
                            let _ = std::fs::remove_file(&dest);
                            return Err(error);
                        }
                        Ok(dest)
                    })(
                    );
                    (service, outcome)
                },
                move |(service, outcome)| {
                    *state_done.backup.borrow_mut() = service;
                    row_done.set_sensitive(true);
                    match outcome {
                        Ok(p) => show_toast(
                            &toast_done,
                            &format!("{}: {}", tr!("Restored to"), p.display()),
                        ),
                        Err(e) => {
                            show_toast(&toast_done, &format!("{}: {e}", tr!("Restore failed")))
                        }
                    }
                },
            );
        });
    }
    group.add(&restore_row);

    page.add(&group);

    page.add(&build_webdav_group(state.clone(), toast.clone()));
    page.add(&build_nextcloud_passwords_group(
        state,
        toast,
        parent,
        dialog_slot,
    ));
}

pub(super) fn show_google_oauth_dialog(
    parent: Option<&gtk::Window>,
    creds: Rc<RefCell<Option<ashypass_core::backup::ClientCredentials>>>,
    status: adw::ActionRow,
    configure: adw::ActionRow,
    signin_row: Option<adw::ActionRow>,
    toast: adw::ToastOverlay,
) {
    let dialog = adw::AlertDialog::builder()
        .heading(tr!("Configure Google OAuth"))
        .body(tr!("OAuth client not configured at build time"))
        .build();
    dialog.add_response("cancel", tr!("Cancel"));
    dialog.add_response("save", tr!("Save"));
    dialog.set_default_response(Some("save"));
    dialog.set_response_appearance("save", adw::ResponseAppearance::Suggested);

    let client_id = adw::EntryRow::builder().title(tr!("Client ID")).build();
    let client_secret = adw::PasswordEntryRow::builder()
        .title(tr!("Client Secret (optional)"))
        .build();
    if let Some(existing) = creds.borrow().as_ref() {
        client_id.set_text(&existing.client_id);
        if let Some(secret) = existing.client_secret.as_ref() {
            client_secret.set_text(secret);
        }
    }
    let list = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .build();
    list.add_css_class("boxed-list");
    list.append(&client_id);
    list.append(&client_secret);
    dialog.set_extra_child(Some(&list));

    dialog.connect_response(None, move |_dlg, response| {
        if response != "save" {
            return;
        }
        let id = client_id.text().trim().to_string();
        if id.is_empty() {
            client_id.add_css_class("error");
            show_toast(&toast, tr!("All fields are required."));
            return;
        }
        let secret = client_secret.text().trim().to_string();
        let cfg = ashypass_core::backup::ClientCredentials {
            client_id: id,
            client_secret: if secret.is_empty() {
                None
            } else {
                Some(secret)
            },
        };
        match cfg.save() {
            Ok(()) => {
                *creds.borrow_mut() = Some(cfg);
                status.set_subtitle(tr!("Not signed in"));
                configure.set_subtitle(tr!("Configured"));
                if let Some(row) = signin_row.as_ref() {
                    row.set_sensitive(true);
                }
                show_toast(&toast, tr!("Configured"));
            }
            Err(e) => show_toast(&toast, &format!("{}: {e}", tr!("Configure failed"))),
        }
    });
    dialog.present(parent);
}

pub(super) fn build_webdav_group(
    state: SharedState,
    toast: adw::ToastOverlay,
) -> adw::PreferencesGroup {
    let logged_in = state.webdav.borrow().is_logged_in();
    let group = adw::PreferencesGroup::builder()
        .title(tr!("WebDAV / Nextcloud"))
        .description(tr!(
            "Encrypted vault uploaded as-is over HTTPS. Works with any RFC 4918 server."
        ))
        .build();

    let status_row = adw::ActionRow::builder()
        .title(tr!("Status"))
        .subtitle(if logged_in {
            tr!("Configured")
        } else {
            tr!("Not configured")
        })
        .build();
    group.add(&status_row);

    let webdav_action_rows: Rc<RefCell<Vec<adw::ActionRow>>> = Rc::new(RefCell::new(Vec::new()));

    let configure_row = adw::ActionRow::builder()
        .title(if logged_in {
            tr!("Sign out")
        } else {
            tr!("Configure WebDAV")
        })
        .subtitle(tr!("Server URL, username, app-password"))
        .activatable(true)
        .build();
    configure_row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
    {
        let state = state.clone();
        let toast = toast.clone();
        let status = status_row.clone();
        let configure = configure_row.clone();
        let action_rows = webdav_action_rows.clone();
        configure_row.connect_activated(move |row| {
            if state.webdav.borrow().is_logged_in() {
                if let Err(e) = state.webdav.borrow_mut().logout() {
                    show_toast(&toast, &format!("{}: {e}", tr!("Sign out failed")));
                    return;
                }
                status.set_subtitle(tr!("Not configured"));
                configure.set_title(tr!("Configure WebDAV"));
                for row in action_rows.borrow().iter() {
                    row.set_sensitive(false);
                }
                show_toast(&toast, tr!("Signed out"));
                return;
            }
            let parent = row.root().and_then(|r| r.downcast::<gtk::Window>().ok());
            show_webdav_dialog(parent.as_ref(), state.clone(), toast.clone(), {
                let status = status.clone();
                let configure = configure.clone();
                let action_rows = action_rows.clone();
                move || {
                    status.set_subtitle(tr!("Configured"));
                    configure.set_title(tr!("Sign out"));
                    for row in action_rows.borrow().iter() {
                        row.set_sensitive(true);
                    }
                }
            });
        });
    }
    group.add(&configure_row);

    let backup_row = adw::ActionRow::builder()
        .title(tr!("Back up now"))
        .subtitle(tr!("Upload the current vault file to WebDAV"))
        .activatable(true)
        .build();
    backup_row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
    backup_row.set_sensitive(logged_in);
    webdav_action_rows.borrow_mut().push(backup_row.clone());
    {
        let state = state.clone();
        let toast = toast.clone();
        backup_row.connect_activated(move |row| {
            let stamp = chrono::Utc::now().format("%Y%m%d-%H%M%S").to_string();
            let name = format!("passwords-{stamp}.db");
            let parts = match state.vault.borrow().session_reopen_parts() {
                Ok(parts) => parts,
                Err(error) => {
                    show_toast(&toast, &format!("{}: {error}", tr!("Backup failed")));
                    return;
                }
            };
            let service = state.webdav.borrow().clone();
            row.set_sensitive(false);
            let row_done = row.clone();
            let toast_done = toast.clone();
            run_background(
                move || {
                    let snapshot = temporary_snapshot_path("webdav");
                    let outcome = (|| {
                        let vault =
                            ashypass_core::db::Vault::open_with_session_key(parts.0, parts.1)?;
                        vault.backup_to(&snapshot)?;
                        service.ensure_folder()?;
                        service.upload(&snapshot, &name)
                    })();
                    let _ = std::fs::remove_file(&snapshot);
                    outcome
                },
                move |outcome| {
                    row_done.set_sensitive(true);
                    match outcome {
                        Ok(()) => show_toast(&toast_done, tr!("Backup uploaded")),
                        Err(e) => {
                            show_toast(&toast_done, &format!("{}: {e}", tr!("Backup failed")))
                        }
                    }
                },
            );
        });
    }
    group.add(&backup_row);

    // Incremental sync row — uploads an encrypted `.ashy` snapshot named with
    // the local generation counter so concurrent writes from a second machine
    // can be detected before they get clobbered.
    let sync_row = adw::ActionRow::builder()
        .title(tr!("Sync now"))
        .subtitle(tr!("Encrypted snapshot upload with conflict detection"))
        .activatable(true)
        .build();
    sync_row.add_suffix(&gtk::Image::from_icon_name("emblem-synchronizing-symbolic"));
    sync_row.set_sensitive(logged_in);
    webdav_action_rows.borrow_mut().push(sync_row.clone());
    {
        let state = state.clone();
        let toast = toast.clone();
        sync_row.connect_activated(move |row| {
            let parent = row.root().and_then(|r| r.downcast::<gtk::Window>().ok());
            run_webdav_sync(parent.as_ref(), state.clone(), toast.clone(), false);
        });
    }
    group.add(&sync_row);

    let restore_row = adw::ActionRow::builder()
        .title(tr!("Restore latest"))
        .activatable(true)
        .build();
    restore_row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
    restore_row.set_sensitive(logged_in);
    webdav_action_rows.borrow_mut().push(restore_row.clone());
    {
        let state = state.clone();
        let toast = toast.clone();
        restore_row.connect_activated(move |row| {
            row.set_sensitive(false);
            let row_done = row.clone();
            let service = state.webdav.borrow().clone();
            let toast_done = toast.clone();
            run_background(
                move || {
                    let outcome: ashypass_core::Result<std::path::PathBuf> = (|| {
                        let mut files = service.list_backups()?;
                        files.retain(|file| is_database_backup_name(&file.name));
                        files.sort_by(|a, b| b.name.cmp(&a.name));
                        let latest = files
                            .into_iter()
                            .next()
                            .ok_or(ashypass_core::Error::Other("no backups found".into()))?;
                        let dest = restore_destination();
                        service.download(&latest.href, &dest)?;
                        if let Err(error) = ashypass_core::db::Vault::validate_database(&dest) {
                            let _ = std::fs::remove_file(&dest);
                            return Err(error);
                        }
                        Ok(dest)
                    })(
                    );
                    outcome
                },
                move |outcome| {
                    row_done.set_sensitive(true);
                    match outcome {
                        Ok(p) => show_toast(
                            &toast_done,
                            &format!("{}: {}", tr!("Restored to"), p.display()),
                        ),
                        Err(e) => {
                            show_toast(&toast_done, &format!("{}: {e}", tr!("Restore failed")))
                        }
                    }
                },
            );
        });
    }
    group.add(&restore_row);

    group
}

pub(super) fn show_webdav_dialog<F>(
    parent: Option<&gtk::Window>,
    state: SharedState,
    toast: adw::ToastOverlay,
    on_saved: F,
) where
    F: Fn() + 'static,
{
    let dialog = adw::AlertDialog::builder()
        .heading(tr!("WebDAV / Nextcloud"))
        .body(tr!(
            "For Nextcloud, the base URL looks like https://cloud.example.com/remote.php/dav/files/USERNAME"
        ))
        .build();
    dialog.add_response("cancel", tr!("Cancel"));
    dialog.add_response("save", tr!("Save"));
    dialog.set_default_response(Some("save"));
    dialog.set_response_appearance("save", adw::ResponseAppearance::Suggested);

    let url_row = adw::EntryRow::builder().title(tr!("Server URL")).build();
    let user_row = adw::EntryRow::builder().title(tr!("Username")).build();
    let pass_row = adw::PasswordEntryRow::builder()
        .title(tr!("Password / app-password"))
        .build();
    let folder_row = adw::EntryRow::builder()
        .title(tr!("Folder"))
        .text("AshyPass Backups")
        .build();

    let list = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .build();
    list.add_css_class("boxed-list");
    list.append(&url_row);
    list.append(&user_row);
    list.append(&pass_row);
    list.append(&folder_row);
    dialog.set_extra_child(Some(&list));

    let on_saved = Rc::new(on_saved);
    {
        let url_row = url_row.clone();
        let user_row = user_row.clone();
        let pass_row = pass_row.clone();
        let folder_row = folder_row.clone();
        let state = state.clone();
        let toast = toast.clone();
        let on_saved = on_saved.clone();
        dialog.connect_response(None, move |_dlg, resp| {
            if resp != "save" {
                return;
            }
            let cfg = ashypass_core::backup::WebdavConfig {
                base_url: url_row.text().trim().to_string(),
                username: user_row.text().trim().to_string(),
                password: pass_row.text().to_string(),
                folder: folder_row.text().trim().to_string(),
            };
            if cfg.base_url.is_empty() || cfg.username.is_empty() || cfg.password.is_empty() {
                show_toast(&toast, tr!("URL, username and password are required"));
                return;
            }
            let mut service = state.webdav.borrow().clone();
            let state_done = state.clone();
            let toast_done = toast.clone();
            let on_saved_done = on_saved.clone();
            run_background(
                move || {
                    let result = service.login(cfg);
                    (service, result)
                },
                move |(service, result)| {
                    *state_done.webdav.borrow_mut() = service;
                    match result {
                        Ok(()) => {
                            show_toast(&toast_done, tr!("WebDAV configured"));
                            on_saved_done();
                        }
                        Err(e) => {
                            show_toast(&toast_done, &format!("{}: {e}", tr!("Configure failed")))
                        }
                    }
                },
            );
        });
    }
    dialog.present(parent);
}

/// Drive the incremental-sync flow: plan → resolve conflict → upload.
///
/// `force` is `true` when the user has already chosen to overwrite a detected
/// conflict; we re-enter this function from the conflict dialog with `force`
/// set so we can skip the planning step and go straight to upload.
pub(super) fn run_webdav_sync(
    parent: Option<&gtk::Window>,
    state: SharedState,
    toast: adw::ToastOverlay,
    force: bool,
) {
    use ashypass_core::backup::sync as sync_mod;

    if !force {
        let parts = match state.vault.borrow().session_reopen_parts() {
            Ok(parts) => parts,
            Err(error) => {
                show_toast(&toast, &format!("{}: {error}", tr!("Sync failed")));
                return;
            }
        };
        let service = state.webdav.borrow().clone();
        let parent = parent.cloned();
        let state_done = state.clone();
        let toast_done = toast.clone();
        run_background(
            move || {
                let vault = ashypass_core::db::Vault::open_with_session_key(parts.0, parts.1)?;
                sync_mod::plan_push(&vault, &service)
            },
            move |result| match result {
                Ok(plan) => match plan.action {
                    sync_mod::SyncAction::NoChanges => {
                        show_toast(&toast_done, tr!("Vault already in sync"));
                    }
                    sync_mod::SyncAction::Conflict {
                        unseen_remote_generation,
                    } => show_sync_conflict_dialog(
                        parent.as_ref(),
                        state_done.clone(),
                        toast_done.clone(),
                        plan.local_generation,
                        unseen_remote_generation,
                    ),
                    sync_mod::SyncAction::Ready => prompt_webdav_push(
                        parent.as_ref(),
                        state_done.clone(),
                        toast_done.clone(),
                        false,
                    ),
                },
                Err(error) => {
                    show_toast(&toast_done, &format!("{}: {error}", tr!("Sync failed")));
                }
            },
        );
        return;
    }

    prompt_webdav_push(parent, state, toast, true);
}

pub(super) fn prompt_webdav_push(
    parent: Option<&gtk::Window>,
    state: SharedState,
    toast: adw::ToastOverlay,
    force: bool,
) {
    // Try keyring first so users who opted in get a one-click push.
    let master = match ashypass_core::keyring::load_master() {
        Ok(Some(pw)) => Some(pw),
        _ => None,
    };
    if let Some(pw) = master {
        do_webdav_push(state, toast, pw, /*force=*/ force);
        return;
    }

    // Otherwise prompt for the master password.
    prompt_password(
        parent,
        tr!("Master password"),
        tr!("Required to encrypt the snapshot before upload"),
        false,
        {
            let state = state.clone();
            let toast = toast.clone();
            move |pw| {
                let ok = state
                    .vault
                    .borrow()
                    .verify_master_password(&pw)
                    .unwrap_or(false);
                if !ok {
                    show_toast(&toast, tr!("Wrong master password"));
                    return;
                }
                do_webdav_push(state.clone(), toast.clone(), pw, force);
            }
        },
    );
}

pub(super) fn do_webdav_push(
    state: SharedState,
    toast: adw::ToastOverlay,
    master: String,
    force: bool,
) {
    use ashypass_core::backup::sync as sync_mod;
    let parts = match state.vault.borrow().session_reopen_parts() {
        Ok(parts) => parts,
        Err(error) => {
            show_toast(&toast, &format!("{}: {error}", tr!("Sync failed")));
            return;
        }
    };
    let service = state.webdav.borrow().clone();
    let state_done = state.clone();
    let toast_done = toast.clone();
    run_background(
        move || {
            let vault = ashypass_core::db::Vault::open_with_session_key(parts.0, parts.1);
            vault.and_then(|vault| sync_mod::push(&vault, &service, &master, force))
        },
        move |outcome| {
            match outcome {
                Ok(sync_mod::PushOutcome::Uploaded { filename, .. }) => {
                    show_toast(
                        &toast_done,
                        &format!("{}: {filename}", tr!("Snapshot uploaded")),
                    );
                    state_done
                        .events
                        .emit(crate::events::AppEvent::SyncCompleted { filename });
                }
                Ok(sync_mod::PushOutcome::Skipped(_)) => {
                    show_toast(&toast_done, tr!("Vault already in sync"));
                }
                Ok(sync_mod::PushOutcome::Conflict(plan)) => {
                    // Should be unreachable with force=true, but stay defensive.
                    show_toast(
                        &toast_done,
                        &format!(
                            "{}: remote generation {}",
                            tr!("Sync conflict"),
                            plan.remote_max_generation
                        ),
                    );
                    state_done
                        .events
                        .emit(crate::events::AppEvent::SyncConflict {
                            local_generation: plan.local_generation,
                            remote_generation: plan.remote_max_generation,
                        });
                }
                Err(e) => {
                    let msg = format!("{e}");
                    show_toast(&toast_done, &format!("{}: {msg}", tr!("Sync failed")));
                    state_done
                        .events
                        .emit(crate::events::AppEvent::SyncFailed(msg));
                }
            }
        },
    );
}

pub(super) fn show_sync_conflict_dialog(
    parent: Option<&gtk::Window>,
    state: SharedState,
    toast: adw::ToastOverlay,
    local_gen: u64,
    remote_gen: u64,
) {
    let dialog = adw::AlertDialog::builder()
        .heading(tr!("Sync conflict detected"))
        .body(format!(
            "{}\n\n{} {local_gen}\n{} {remote_gen}",
            tr!("Another device uploaded a newer snapshot since this device last synced. Uploading now would orphan the remote changes."),
            tr!("This device generation:"),
            tr!("Remote generation:"),
        ))
        .build();
    dialog.add_response("cancel", tr!("Cancel"));
    dialog.add_response("force", tr!("Upload anyway"));
    dialog.set_response_appearance("force", adw::ResponseAppearance::Destructive);
    dialog.set_default_response(Some("cancel"));

    let state = state.clone();
    let toast = toast.clone();
    dialog.connect_response(None, move |dlg, resp| {
        if resp != "force" {
            return;
        }
        let parent = dlg.parent().and_then(|w| w.downcast::<gtk::Window>().ok());
        run_webdav_sync(parent.as_ref(), state.clone(), toast.clone(), true);
    });
    dialog.present(parent);
}
