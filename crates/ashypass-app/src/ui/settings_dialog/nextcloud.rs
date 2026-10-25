//! `settings_dialog` — nextcloud section.

use super::*;

// ---------------------------------------------------------------------------
// Nextcloud Passwords — bidirectional sync with the official Nextcloud
// Passwords app via its REST API. Distinct from the WebDAV backup above:
// this reconciles individual entries instead of uploading encrypted blobs.
// ---------------------------------------------------------------------------

pub(super) fn build_nextcloud_passwords_group(
    state: SharedState,
    toast: Toaster,
    parent: gtk::Widget,
    dialog_slot: DialogSlot,
) -> adw::PreferencesGroup {
    let logged_in = state.nextcloud.borrow().is_logged_in();
    let group = adw::PreferencesGroup::builder()
        .title(tr!("Nextcloud Passwords"))
        .description(tr!(
            "Two-way sync with the official 'Passwords' app on your Nextcloud server. The server keeps these entries in a form it can read: use it only with a server you trust. Sign in with an app password from Settings → Security."
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

    let nextcloud_action_rows: Rc<RefCell<Vec<adw::ActionRow>>> = Rc::new(RefCell::new(Vec::new()));

    let configure_row = adw::ActionRow::builder()
        .title(if logged_in {
            tr!("Sign out")
        } else {
            tr!("Configure Nextcloud Passwords")
        })
        .subtitle(tr!("Server URL, username, app password"))
        .activatable(true)
        .build();
    configure_row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
    {
        let state = state.clone();
        let toast = toast.clone();
        let status = status_row.clone();
        let action_rows = nextcloud_action_rows.clone();
        let parent_widget = parent.clone();
        let dialog_slot = dialog_slot.clone();
        configure_row.connect_activated(move |row| {
            // From the argument: a captured copy would make the row hold itself.
            let configure = row.clone();
            if state.nextcloud.borrow().is_logged_in() {
                // A running sync would write its mappings back after the
                // reset below.
                if ashypass_core::sync::nextcloud_engine::is_sync_running() {
                    show_toast(&toast, tr!("Wait for the sync to finish, then sign out."));
                    return;
                }
                // Drop the sync records before the credentials: if this fails
                // the account stays signed in, and stale mappings never meet
                // a different account on the next sign-in.
                let reset = state.vault.borrow_mut().nc_reset_sync_state();
                if let Err(e) = reset {
                    show_toast(
                        &toast,
                        &format!(
                            "{}: {}",
                            tr!("Sign out failed"),
                            crate::ui::errors::describe(&e)
                        ),
                    );
                    return;
                }
                if let Err(e) = state.nextcloud.borrow_mut().logout() {
                    show_toast(
                        &toast,
                        &format!(
                            "{}: {}",
                            tr!("Sign out failed"),
                            crate::ui::errors::describe(&e)
                        ),
                    );
                    return;
                }
                status.set_subtitle(tr!("Not configured"));
                configure.set_title(tr!("Configure Nextcloud Passwords"));
                for row in action_rows.borrow().iter() {
                    row.set_sensitive(false);
                }
                // No status and no badges any more under the list.
                state.set_sync_status(crate::state::SyncStatus::Unknown);
                state
                    .events
                    .emit(crate::events::AppEvent::SyncStatusChanged);
                show_toast(&toast, tr!("Signed out"));
                return;
            }
            let parent = row.root().and_then(|r| r.downcast::<gtk::Window>().ok());
            show_nextcloud_dialog(
                parent.as_ref(),
                state.clone(),
                toast.clone(),
                parent_widget.clone(),
                dialog_slot.clone(),
                {
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
                },
            );
        });
    }
    group.add(&configure_row);

    let sync_row = adw::ActionRow::builder()
        .title(tr!("Sync now"))
        .subtitle(tr!(
            "Brings the server's changes and sends yours; the newest version wins"
        ))
        .activatable(true)
        .build();
    sync_row.add_suffix(&gtk::Image::from_icon_name("emblem-synchronizing-symbolic"));
    sync_row.set_sensitive(logged_in);
    nextcloud_action_rows.borrow_mut().push(sync_row.clone());
    {
        let state = state.clone();
        let toast = toast.clone();
        let parent_widget = parent.clone();
        let dialog_slot = dialog_slot.clone();
        sync_row.connect_activated(move |row| {
            let parent = row.root().and_then(|r| r.downcast::<gtk::Window>().ok());
            run_nextcloud_sync(
                parent.as_ref(),
                state.clone(),
                toast.clone(),
                Some(parent_widget.clone()),
                Some(dialog_slot.clone()),
                Some(row.clone()),
            );
        });
    }
    group.add(&sync_row);

    add_auto_sync_rows(&group, &state, &nextcloud_action_rows, logged_in);

    group
}

/// Choices offered for the periodic sync, in minutes.
const AUTO_SYNC_INTERVALS: [u32; 4] = [5, 15, 30, 60];

/// "Sync automatically", its interval and "Sync when the vault is unlocked".
/// Each change is saved at once and announced so the running scheduler
/// picks it up. Like "Sync now", they stay insensitive until an account is
/// signed in: a switch shown on beside "Not configured" reads as syncing.
fn add_auto_sync_rows(
    group: &adw::PreferencesGroup,
    state: &SharedState,
    action_rows: &Rc<RefCell<Vec<adw::ActionRow>>>,
    logged_in: bool,
) {
    let current = state.settings();

    let auto_row = adw::SwitchRow::builder()
        .title(tr!("Sync automatically"))
        .subtitle(tr!(
            "Send changes shortly after each edit and check the server regularly"
        ))
        .active(current.nextcloud_auto_sync)
        .sensitive(logged_in)
        .build();

    let labels: Vec<String> = AUTO_SYNC_INTERVALS
        .iter()
        .map(|minutes| format!("{minutes} {}", trn!("minute", "minutes", *minutes as usize)))
        .collect();
    let model = gtk::StringList::new(&labels.iter().map(String::as_str).collect::<Vec<_>>());
    let interval_row = adw::ComboRow::builder()
        .title(tr!("Check the server every"))
        .model(&model)
        .sensitive(logged_in && current.nextcloud_auto_sync)
        .build();
    interval_row.set_selected(interval_index(current.nextcloud_auto_sync_interval_minutes));

    let unlock_row = adw::SwitchRow::builder()
        .title(tr!("Sync when the vault is unlocked"))
        .active(current.nextcloud_sync_on_unlock)
        .sensitive(logged_in)
        .build();

    {
        let state = state.clone();
        let interval_row = interval_row.clone();
        auto_row.connect_active_notify(move |row| {
            let value = row.is_active();
            interval_row.set_sensitive(value && row.is_sensitive());
            save_sync_setting(&state, |s| s.nextcloud_auto_sync = value);
        });
    }
    {
        // Signing in or out turns the switch on or off as a whole; the
        // interval follows it.
        let interval_row = interval_row.clone();
        auto_row.connect_sensitive_notify(move |row| {
            interval_row.set_sensitive(row.is_sensitive() && row.is_active());
        });
    }
    action_rows
        .borrow_mut()
        .extend([auto_row.clone().upcast(), unlock_row.clone().upcast()]);
    {
        let state = state.clone();
        interval_row.connect_selected_notify(move |row| {
            let Some(minutes) = AUTO_SYNC_INTERVALS.get(row.selected() as usize).copied() else {
                return;
            };
            save_sync_setting(&state, |s| s.nextcloud_auto_sync_interval_minutes = minutes);
        });
    }
    {
        let state = state.clone();
        unlock_row.connect_active_notify(move |row| {
            let value = row.is_active();
            save_sync_setting(&state, |s| s.nextcloud_sync_on_unlock = value);
        });
    }

    group.add(&auto_row);
    group.add(&interval_row);
    group.add(&unlock_row);
}

/// Row to show for a stored interval: the exact choice, else the closest
/// longer one (the longest for anything above it).
fn interval_index(minutes: u32) -> u32 {
    AUTO_SYNC_INTERVALS
        .iter()
        .position(|choice| *choice >= minutes)
        .unwrap_or(AUTO_SYNC_INTERVALS.len() - 1) as u32
}

fn save_sync_setting<F>(state: &SharedState, edit: F)
where
    F: FnOnce(&mut Settings),
{
    // Persist through the shared state: saving this page's snapshot would
    // write back stale values changed on other pages.
    if let Err(e) = state.update_settings(edit) {
        log::warn!("could not save settings: {e}");
    }
    state
        .events
        .emit(crate::events::AppEvent::SyncSettingsChanged);
}

pub(super) fn show_nextcloud_dialog<F>(
    parent: Option<&gtk::Window>,
    state: SharedState,
    toast: Toaster,
    unlock_parent: gtk::Widget,
    dialog_slot: DialogSlot,
    on_saved: F,
) where
    F: Fn() + 'static,
{
    let dialog = big_gtk_kit::alert::Alert::builder(parent)
        .heading(tr!("Nextcloud Passwords"))
        .body(tr!(
            "Server address (for example cloud.example.com), username and an app password."
        ))
        .build();
    dialog.add_response("cancel", tr!("Cancel"));
    dialog.add_response("save", tr!("Save"));
    dialog.set_default_response(Some("save"));
    dialog.set_response_appearance("save", adw::ResponseAppearance::Suggested);

    let url_row = adw::EntryRow::builder().title(tr!("Server URL")).build();
    let user_row = adw::EntryRow::builder().title(tr!("Username")).build();
    let pass_row = big_gtk_kit::password::password_row(
        adw::PasswordEntryRow::builder().title(tr!("App password")),
    );
    let parent_window = parent.cloned();

    let list = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .build();
    list.add_css_class("boxed-list");
    list.append(&url_row);
    list.append(&user_row);
    list.append(&pass_row);
    dialog.set_extra_child(Some(&list));

    let on_saved = Rc::new(on_saved);
    {
        let state = state.clone();
        let toast = toast.clone();
        let url_row = url_row.clone();
        let user_row = user_row.clone();
        let pass_row = pass_row.clone();
        let on_saved = on_saved.clone();
        let parent_window = parent_window.clone();
        let unlock_parent = unlock_parent.clone();
        let dialog_slot = dialog_slot.clone();
        dialog.connect_response(None, move |_dlg, resp| {
            if resp != "save" {
                return;
            }
            let cfg = ashypass_core::sync::NcConfig {
                base_url: url_row.text().to_string(),
                username: user_row.text().to_string(),
                app_password: pass_row.text().to_string(),
            };
            let mut client = state.nextcloud.borrow().clone();
            let state_done = state.clone();
            let toast_done = toast.clone();
            let on_saved_done = on_saved.clone();
            let parent_window_done = parent_window.clone();
            let unlock_parent_done = unlock_parent.clone();
            let dialog_slot_done = dialog_slot.clone();
            run_background(
                move || {
                    let result = client.login(cfg);
                    (client, result)
                },
                move |(client, result)| {
                    *state_done.nextcloud.borrow_mut() = client;
                    match result {
                        Ok(()) => {
                            show_toast(&toast_done, tr!("Nextcloud Passwords connected"));
                            on_saved_done();
                            show_nextcloud_initial_sync_dialog(
                                parent_window_done.as_ref(),
                                state_done.clone(),
                                toast_done.clone(),
                                unlock_parent_done.clone(),
                                dialog_slot_done.clone(),
                            );
                        }
                        Err(e) => show_toast(
                            &toast_done,
                            &format!(
                                "{}: {}",
                                tr!("Configure failed"),
                                crate::ui::errors::describe(&e)
                            ),
                        ),
                    }
                },
            );
        });
    }
    dialog.present();
}

pub(super) fn show_nextcloud_initial_sync_dialog(
    parent: Option<&gtk::Window>,
    state: SharedState,
    toast: Toaster,
    unlock_parent: gtk::Widget,
    dialog_slot: DialogSlot,
) {
    if !state.vault.borrow().is_unlocked() {
        show_toast(&toast, tr!("Unlock the vault first"));
        show_settings_unlock_dialog(&unlock_parent, state, toast, dialog_slot);
        return;
    }

    let dialog = big_gtk_kit::alert::Alert::builder(parent)
        .heading(tr!("Nextcloud Passwords connected"))
        .body(tr!(
            "Two-way reconcile: pull remote, push local, resolve by latest-wins"
        ))
        .default_response("sync")
        .close_response("cancel")
        .build();
    dialog.add_response("cancel", tr!("Cancel"));
    dialog.add_response("sync", tr!("Sync now"));
    dialog.set_response_appearance("sync", adw::ResponseAppearance::Suggested);
    let parent_window = parent.cloned();
    dialog.connect_response(None, move |dlg, response| {
        if response == "sync" {
            run_nextcloud_sync(
                parent_window.as_ref(),
                state.clone(),
                toast.clone(),
                None,
                None,
                None,
            );
        }
        dlg.close();
    });
    dialog.present();
}

pub(super) fn run_nextcloud_sync(
    parent: Option<&gtk::Window>,
    state: SharedState,
    toast: Toaster,
    unlock_parent: Option<gtk::Widget>,
    dialog_slot: Option<DialogSlot>,
    active_row: Option<adw::ActionRow>,
) {
    use ashypass_core::sync::{nextcloud_engine, ConflictResolution};
    if !state.vault.borrow().is_unlocked() {
        show_toast(&toast, tr!("Unlock the vault first"));
        if let (Some(unlock_parent), Some(dialog_slot)) = (unlock_parent, dialog_slot) {
            show_settings_unlock_dialog(&unlock_parent, state, toast, dialog_slot);
        } else {
            show_message_dialog(
                parent,
                tr!("Vault must be unlocked to configure"),
                tr!("Unlock the vault first"),
            );
        }
        return;
    }
    let (db_path, session_key) = match state.vault.borrow().session_reopen_parts() {
        Ok(parts) => parts,
        Err(e) => {
            let msg = format!(
                "{}: {}",
                tr!("Sync failed"),
                crate::ui::errors::describe(&e)
            );
            show_toast(&toast, &msg);
            show_message_dialog(parent, tr!("Sync failed"), &msg);
            return;
        }
    };
    let client = state.nextcloud.borrow().clone();
    let parent_window = parent.cloned();
    let progress_ui = show_nextcloud_progress_dialog(parent);
    let (sender, receiver) = std::sync::mpsc::channel::<NextcloudSyncMessage>();
    if let Some(row) = active_row.as_ref() {
        row.set_title(tr!("Synchronizing..."));
        row.set_subtitle(tr!("Please wait while AshyPass talks to Nextcloud"));
        row.set_sensitive(false);
    }
    show_toast(&toast, tr!("Synchronizing Nextcloud"));

    let worker_sender = sender.clone();
    std::thread::spawn(move || {
        let progress_sender = worker_sender.clone();
        let outcome = (|| {
            let vault = ashypass_core::db::Vault::open_with_session_key(db_path, session_key)?;
            nextcloud_engine::sync_with_progress(
                &vault,
                &client,
                ConflictResolution::LastWriteWins,
                move |progress| {
                    let _ = progress_sender.send(NextcloudSyncMessage::Progress(progress));
                },
            )
        })();
        let _ = worker_sender.send(NextcloudSyncMessage::Finished(outcome));
    });
    drop(sender);

    glib::timeout_add_local(std::time::Duration::from_millis(150), move || {
        let mut latest_progress = None;
        let mut finished = None;

        loop {
            match receiver.try_recv() {
                Ok(NextcloudSyncMessage::Progress(progress)) => latest_progress = Some(progress),
                Ok(NextcloudSyncMessage::Finished(outcome)) => {
                    finished = Some(outcome);
                    break;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    if let Some(row) = active_row.as_ref() {
                        restore_nextcloud_sync_row(row);
                    }
                    progress_ui.spinner.stop();
                    progress_ui.dialog.close();
                    let msg = tr!("Sync failed").to_string();
                    show_toast(&toast, &msg);
                    show_message_dialog(parent_window.as_ref(), tr!("Sync failed"), &msg);
                    state.events.emit(crate::events::AppEvent::SyncFailed(msg));
                    return glib::ControlFlow::Break;
                }
            }
        }

        if let Some(progress) = latest_progress {
            update_nextcloud_progress(&progress_ui, progress);
        } else {
            progress_ui.progress.pulse();
        }

        if let Some(outcome) = finished {
            if let Some(row) = active_row.as_ref() {
                restore_nextcloud_sync_row(row);
            }
            progress_ui.spinner.stop();
            progress_ui.dialog.close();
            finish_nextcloud_sync(
                parent_window.as_ref(),
                state.clone(),
                toast.clone(),
                outcome,
            );
            glib::ControlFlow::Break
        } else {
            glib::ControlFlow::Continue
        }
    });
}

pub(super) fn restore_nextcloud_sync_row(row: &adw::ActionRow) {
    row.set_title(tr!("Sync now"));
    row.set_subtitle(tr!(
        "Two-way reconcile: pull remote, push local, resolve by latest-wins"
    ));
    row.set_sensitive(true);
}

pub(super) fn finish_nextcloud_sync(
    parent: Option<&gtk::Window>,
    state: SharedState,
    toast: Toaster,
    result: NextcloudSyncResult,
) {
    match result {
        Ok(r) => {
            present_sync_success_dialog(parent, &toast, &r);
            // The line under the list follows manual syncs too.
            let at = chrono::Utc::now().timestamp();
            state.set_sync_status(if r.stats.errors.is_empty() {
                crate::state::SyncStatus::Synced { at }
            } else {
                crate::state::SyncStatus::Failed { at }
            });
            state.events.emit(crate::events::AppEvent::SyncCompleted {
                filename: "nextcloud".into(),
            });
        }
        Err(ashypass_core::Error::MassDelete { count, .. }) => {
            // Not a failure to report: a question for the user, asked by the
            // auto-sync scheduler (which reruns the sync if confirmed).
            state
                .events
                .emit(crate::events::AppEvent::MassDeletePending { count });
        }
        Err(e) => {
            let e = e.to_string();
            // Concise toast + structured dialog with the raw error tucked
            // behind an expander so the surface stays calm.
            show_toast(&toast, tr!("Sync failed"));
            state.set_sync_status(crate::state::SyncStatus::Failed {
                at: chrono::Utc::now().timestamp(),
            });
            present_sync_failure_dialog(parent, &e);
            state
                .events
                .emit(crate::events::AppEvent::SyncFailed(e.to_string()));
        }
    }
}

/// Render a structured success dialog using `adw::AlertDialog` with a
/// custom extra_child built from `adw::PreferencesGroup` rows. Zero-count
/// rows are omitted, the passphrase-less note is surfaced separately, and
/// errors collapse behind an expander.
pub(crate) fn present_sync_success_dialog(
    parent: Option<&gtk::Window>,
    toast: &Toaster,
    report: &ashypass_core::sync::SyncReport,
) {
    let s = &report.stats;
    let has_errors = !s.errors.is_empty();
    let total_changes = s.created_locally
        + s.created_remotely
        + s.updated_locally
        + s.updated_remotely
        + s.deleted_locally
        + s.deleted_remotely;

    // ---- concise toast: ONE summary line, no per-bucket spam ----
    let toast_msg = if has_errors {
        format!("{}: {}", tr!("Sync completed with issues"), s.errors.len())
    } else if total_changes == 0 && s.conflicts == 0 {
        tr!("Everything was already in sync").to_string()
    } else {
        format!(
            "{} {}",
            total_changes,
            trn!("entry synchronized", "entries synchronized", total_changes)
        )
    };
    show_toast(toast, &toast_msg);

    let heading = if has_errors {
        tr!("Sync completed with warnings")
    } else if total_changes == 0 && s.conflicts == 0 {
        tr!("Everything is in sync")
    } else {
        tr!("Sync completed")
    };

    let body_text = if has_errors {
        tr!("The sync finished, but some items reported errors.")
    } else if total_changes == 0 && s.conflicts == 0 {
        tr!("Nothing changed — Ashy Pass and Nextcloud were already aligned.")
    } else {
        tr!("Two-way reconciliation completed successfully.")
    };

    let dialog = big_gtk_kit::alert::Alert::builder(parent)
        .heading(heading)
        .body(body_text)
        .build();
    dialog.add_response("ok", tr!("Done"));
    dialog.set_default_response(Some("ok"));
    dialog.set_close_response("ok");

    let content = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(16)
        .margin_top(8)
        .build();

    // -- Push (Ashy Pass → Nextcloud) ----------------------------------
    let push_rows: Vec<(&str, usize, &str)> = [
        (
            tr!("Created remotely"),
            s.created_remotely,
            "list-add-symbolic",
        ),
        (
            tr!("Updated remotely"),
            s.updated_remotely,
            "document-edit-symbolic",
        ),
        (
            tr!("Deleted remotely"),
            s.deleted_remotely,
            "edit-delete-symbolic",
        ),
    ]
    .into_iter()
    .filter(|(_, n, _)| *n > 0)
    .collect();
    if !push_rows.is_empty() {
        let group = adw::PreferencesGroup::builder()
            .title(tr!("Sent to Nextcloud"))
            .build();
        for (label, n, icon) in push_rows {
            group.add(&sync_count_row(label, n, icon, "accent"));
        }
        content.append(&group);
    }

    // -- Pull (Nextcloud → Ashy Pass) ----------------------------------
    let pull_rows: Vec<(&str, usize, &str)> = [
        (
            tr!("Created locally"),
            s.created_locally,
            "list-add-symbolic",
        ),
        (
            tr!("Updated locally"),
            s.updated_locally,
            "document-edit-symbolic",
        ),
    ]
    .into_iter()
    .filter(|(_, n, _)| *n > 0)
    .collect();
    if !pull_rows.is_empty() {
        let group = adw::PreferencesGroup::builder()
            .title(tr!("Received from Nextcloud"))
            .build();
        for (label, n, icon) in pull_rows {
            group.add(&sync_count_row(label, n, icon, "success"));
        }
        content.append(&group);
    }

    // -- Conflicts -----------------------------------------------------
    if s.conflicts > 0 {
        let group = adw::PreferencesGroup::builder()
            .title(tr!("Conflicts"))
            .description(tr!(
                "Resolved automatically using the 'last edit wins' policy."
            ))
            .build();
        group.add(&sync_count_row(
            tr!("Reconciled items"),
            s.conflicts,
            "view-refresh-symbolic",
            "warning",
        ));
        for (title, decision) in report.conflict_details.iter().take(5) {
            let r = adw::ActionRow::builder()
                .title(title)
                .subtitle(match *decision {
                    "local" => tr!("Kept local version"),
                    "remote" => tr!("Kept remote version"),
                    other => other,
                })
                .use_markup(false)
                .build();
            group.add(&r);
        }
        content.append(&group);
    }

    // -- Passwordless skip (informational, not an error) ---------------
    if s.skipped_passwordless > 0 {
        let group = adw::PreferencesGroup::new();
        let row = adw::ActionRow::builder()
            .title(format!(
                "{} {}",
                s.skipped_passwordless,
                trn!(
                    "passwordless entry was skipped",
                    "passwordless entries were skipped",
                    s.skipped_passwordless
                )
            ))
            .subtitle(tr!(
                "Nextcloud Passwords requires a non-empty password field. Add a password to these entries in Ashy Pass before sending them."
            ))
            .build();
        let icon = gtk::Image::from_icon_name("dialog-information-symbolic");
        icon.add_css_class("accent");
        row.add_prefix(&icon);
        group.add(&row);
        content.append(&group);
    }

    // -- Errors (collapsed by default) ---------------------------------
    if has_errors {
        let group = adw::PreferencesGroup::builder()
            .title(tr!("Error details"))
            .build();
        let expander = adw::ExpanderRow::builder()
            .title(format!(
                "{} {}",
                s.errors.len(),
                trn!("reported error", "reported errors", s.errors.len())
            ))
            .build();
        let icon = gtk::Image::from_icon_name("dialog-warning-symbolic");
        icon.add_css_class("warning");
        expander.add_prefix(&icon);
        for err in s.errors.iter().take(10) {
            let r = adw::ActionRow::builder()
                .title(err.as_str())
                .use_markup(false)
                .build();
            r.add_css_class("monospace");
            expander.add_row(&r);
        }
        if s.errors.len() > 10 {
            let r = adw::ActionRow::builder()
                .title(format!("… +{} {}", s.errors.len() - 10, tr!("more")))
                .build();
            r.add_css_class("dim-label");
            expander.add_row(&r);
        }
        group.add(&expander);
        content.append(&group);
    }

    // If nothing happened (no rows above), the dialog body already says
    // "Tudo em sincronia" — leave the extra_child empty.
    if content.first_child().is_some() {
        dialog.set_extra_child(Some(&content));
    }

    dialog.present();
}

pub(super) fn sync_count_row(
    label: &str,
    count: usize,
    icon_name: &str,
    icon_class: &str,
) -> adw::ActionRow {
    let row = adw::ActionRow::builder().title(label).build();
    let icon = gtk::Image::from_icon_name(icon_name);
    icon.add_css_class(icon_class);
    row.add_prefix(&icon);
    let count_label = gtk::Label::builder()
        .label(count.to_string())
        .valign(gtk::Align::Center)
        .build();
    count_label.add_css_class("monospace");
    count_label.add_css_class("title-4");
    count_label.add_css_class(icon_class);
    row.add_suffix(&count_label);
    row
}

pub(crate) fn present_sync_failure_dialog(parent: Option<&gtk::Window>, error: &str) {
    let dialog = big_gtk_kit::alert::Alert::builder(parent)
        .heading(tr!("Could not sync"))
        .body(tr!(
            "Ashy Pass could not reach Nextcloud. Check your connection, server address, and app password."
        ))
        .build();
    dialog.add_response("ok", tr!("Understood"));
    dialog.set_default_response(Some("ok"));
    dialog.set_close_response("ok");

    // Tuck the raw error behind an expander so the surface stays calm.
    let group = adw::PreferencesGroup::new();
    let expander = adw::ExpanderRow::builder()
        .title(tr!("Show technical details"))
        .build();
    let icon = gtk::Image::from_icon_name("dialog-error-symbolic");
    icon.add_css_class("error");
    expander.add_prefix(&icon);
    let err_row = adw::ActionRow::builder()
        .title(error)
        .use_markup(false)
        .build();
    err_row.add_css_class("monospace");
    expander.add_row(&err_row);
    group.add(&expander);

    dialog.set_extra_child(Some(&group));
    dialog.present();
}
