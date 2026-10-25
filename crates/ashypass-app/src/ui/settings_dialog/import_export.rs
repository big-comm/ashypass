//! `settings_dialog` — exports to other apps. Imports go through
//! `ui::import_flow` (preview, then a report), backups through the Backups
//! page.

use super::*;

pub(super) fn run_export_kdbx(state: SharedState, toast: Toaster, anchor: gtk::Widget) {
    let parent_window = anchor.root().and_then(|r| r.downcast::<gtk::Window>().ok());
    prompt_password(
        parent_window.as_ref(),
        tr!("Encrypt KeePass export"),
        tr!("Pick a password for the .kdbx file. You will need it to open the database."),
        true,
        {
            let state = state.clone();
            let toast = toast.clone();
            let anchor = anchor.clone();
            move |password| {
                let dialog = gtk::FileDialog::builder()
                    .title(tr!("Save KeePass export"))
                    .initial_name("ashypass-export.kdbx")
                    .modal(true)
                    .build();
                let parent = anchor.root().and_then(|r| r.downcast::<gtk::Window>().ok());
                let state = state.clone();
                let toast = toast.clone();
                let password = password.clone();
                // The file chooser is the desktop's window: no activity here.
                let hold = SessionManager::hold(&state.session);
                dialog.save(parent.as_ref(), None::<&gio::Cancellable>, move |result| {
                    let Ok(file) = result else { return };
                    let Some(path) = file.path() else { return };
                    let parts = match state.vault.borrow().session_reopen_parts() {
                        Ok(parts) => parts,
                        Err(error) => {
                            show_toast(&toast, &export_failed(&error));
                            return;
                        }
                    };
                    let toast_done = toast.clone();
                    run_background(
                        move || {
                            let vault =
                                ashypass_core::db::Vault::open_with_session_key(parts.0, parts.1)?;
                            ashypass_core::importers::keepass::export_vault(
                                &vault, &path, &password,
                            )
                        },
                        move |outcome| {
                            drop(hold);
                            match outcome {
                                Ok(n) => show_toast(
                                    &toast_done,
                                    &format!("{} ({n})", tr!("KeePass export complete")),
                                ),
                                Err(e) => show_toast(&toast_done, &export_failed(&e)),
                            }
                        },
                    );
                });
            }
        },
    );
}

/// Why an export failed, in words for the likely case: the vault locked
/// before the file was written.
fn export_failed(error: &ashypass_core::Error) -> String {
    match error {
        ashypass_core::Error::Locked => {
            tr!("The vault was locked before the export was saved. Unlock it and export again.")
                .to_string()
        }
        other => format!("{}: {other}", tr!("Export failed")),
    }
}

pub(super) fn prompt_password<F>(
    parent: Option<&gtk::Window>,
    heading: &str,
    body: &str,
    confirm: bool,
    on_ok: F,
) where
    F: Fn(String) + 'static,
{
    let dialog = big_gtk_kit::alert::Alert::builder(parent)
        .heading(heading)
        .body(body)
        .build();
    dialog.add_response("cancel", tr!("Cancel"));
    dialog.add_response("ok", tr!("OK"));
    dialog.set_default_response(Some("ok"));
    dialog.set_response_appearance("ok", adw::ResponseAppearance::Suggested);

    let pw = big_gtk_kit::password::password_row(
        adw::PasswordEntryRow::builder().title(tr!("Password")),
    );
    let confirm_row = big_gtk_kit::password::password_row(
        adw::PasswordEntryRow::builder().title(tr!("Confirm password")),
    );

    let list = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .build();
    list.add_css_class("boxed-list");
    list.append(&pw);
    if confirm {
        list.append(&confirm_row);
    }
    dialog.set_extra_child(Some(&list));

    let on_ok = Rc::new(on_ok);
    {
        let pw = pw.clone();
        let confirm_row = confirm_row.clone();
        let on_ok = on_ok.clone();
        dialog.connect_response(None, move |dlg, resp| {
            if resp != "ok" {
                return;
            }
            let p = pw.text().to_string();
            if p.is_empty() {
                return;
            }
            if confirm && p != confirm_row.text().as_str() {
                let warn = big_gtk_kit::alert::Alert::builder(Some(dlg))
                    .heading(tr!("Passwords do not match"))
                    .build();
                warn.add_response("ok", tr!("OK"));
                warn.present();
                return;
            }
            on_ok(p);
        });
    }
    dialog.present();
}

pub(super) fn run_export_csv(state: SharedState, toast: Toaster, anchor: gtk::Widget) {
    let dialog = gtk::FileDialog::builder()
        .title(tr!("Export vault to CSV"))
        .initial_name("ashypass-export.csv")
        .modal(true)
        .build();

    let parent = anchor.root().and_then(|r| r.downcast::<gtk::Window>().ok());
    let hold = SessionManager::hold(&state.session);
    dialog.save(parent.as_ref(), None::<&gio::Cancellable>, move |result| {
        let Ok(file) = result else { return };
        let Some(path) = file.path() else { return };
        let parts = match state.vault.borrow().session_reopen_parts() {
            Ok(parts) => parts,
            Err(error) => {
                show_toast(&toast, &export_failed(&error));
                return;
            }
        };
        let toast_done = toast.clone();
        run_background(
            move || {
                let vault = ashypass_core::db::Vault::open_with_session_key(parts.0, parts.1)?;
                ashypass_core::importers::vault_import::export_vault_to_csv(&vault, &path)
            },
            move |outcome| {
                drop(hold);
                match outcome {
                    Ok(n) => show_toast(&toast_done, &format!("{} ({n})", tr!("Export complete"))),
                    Err(e) => show_toast(&toast_done, &export_failed(&e)),
                }
            },
        );
    });
}
