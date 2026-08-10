//! `settings_dialog` — import export section.

use super::*;

// ---------------------------------------------------------------------------
// Import / Export — scaffold for task #10
// ---------------------------------------------------------------------------

pub(super) fn populate_import_export(
    page: &adw::PreferencesPage,
    state: SharedState,
    toast: adw::ToastOverlay,
    parent: gtk::Widget,
    dialog_slot: Rc<RefCell<Option<adw::Dialog>>>,
) {
    let authed = state.vault.borrow().is_unlocked();
    if !authed {
        page.add(&locked_notice_group(
            state.clone(),
            toast.clone(),
            parent,
            dialog_slot,
        ));
    }

    let import_group = adw::PreferencesGroup::builder()
        .title(tr!("Import"))
        .description(tr!(
            "CSV, Bitwarden JSON, 1Password 1PUX, Aegis JSON, andOTP JSON"
        ))
        .build();
    import_group.set_sensitive(authed);

    import_group.add(&import_row(
        state.clone(),
        toast.clone(),
        tr!("Import CSV"),
        tr!("Bitwarden, Chrome, 1Password compatible columns"),
        ImportKind::Csv,
    ));
    import_group.add(&import_row(
        state.clone(),
        toast.clone(),
        tr!("Import Bitwarden (JSON)"),
        tr!("Unencrypted Bitwarden vault export"),
        ImportKind::Bitwarden,
    ));
    import_group.add(&import_row(
        state.clone(),
        toast.clone(),
        tr!("Import 1Password (.1pux)"),
        tr!("Unencrypted 1Password 8 export archive"),
        ImportKind::Onepassword,
    ));
    import_group.add(&import_row(
        state.clone(),
        toast.clone(),
        tr!("Import Aegis (TOTP)"),
        tr!("Plain JSON export from Aegis Authenticator"),
        ImportKind::Aegis,
    ));
    import_group.add(&import_row(
        state.clone(),
        toast.clone(),
        tr!("Import andOTP"),
        tr!("Plain JSON export from andOTP"),
        ImportKind::Andotp,
    ));

    page.add(&import_group);

    let export_group = adw::PreferencesGroup::builder()
        .title(tr!("Export"))
        .description(tr!(
            "Prefer the encrypted .ashy export. The CSV path stores credentials in plaintext."
        ))
        .build();
    export_group.set_sensitive(authed);

    let ashy_row = adw::ActionRow::builder()
        .title(tr!("Export encrypted (.ashy)"))
        .subtitle(tr!(
            "Argon2id + AES-256-GCM, password-protected. Re-importable by Ashy Pass."
        ))
        .activatable(true)
        .build();
    ashy_row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
    {
        let state = state.clone();
        let toast = toast.clone();
        ashy_row.connect_activated(move |row| {
            run_export_ashy(
                state.clone(),
                toast.clone(),
                row.upcast_ref::<gtk::Widget>().clone(),
            );
        });
    }
    export_group.add(&ashy_row);

    let import_ashy_row = adw::ActionRow::builder()
        .title(tr!("Import from .ashy"))
        .subtitle(tr!("Restore from an Ashy Pass encrypted export"))
        .activatable(true)
        .build();
    import_ashy_row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
    {
        let state = state.clone();
        let toast = toast.clone();
        import_ashy_row.connect_activated(move |row| {
            run_import_ashy(
                state.clone(),
                toast.clone(),
                row.upcast_ref::<gtk::Widget>().clone(),
            );
        });
    }
    export_group.add(&import_ashy_row);

    let kdbx_export_row = adw::ActionRow::builder()
        .title(tr!("Export to KeePass (.kdbx)"))
        .subtitle(tr!(
            "KDBX4 with Argon2id + AES-256. Opens in KeePassXC, KeeWeb, etc."
        ))
        .activatable(true)
        .build();
    kdbx_export_row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
    {
        let state = state.clone();
        let toast = toast.clone();
        kdbx_export_row.connect_activated(move |row| {
            run_export_kdbx(
                state.clone(),
                toast.clone(),
                row.upcast_ref::<gtk::Widget>().clone(),
            );
        });
    }
    export_group.add(&kdbx_export_row);

    let kdbx_import_row = adw::ActionRow::builder()
        .title(tr!("Import KeePass (.kdbx)"))
        .subtitle(tr!("KDBX3/KDBX4 password-protected database"))
        .activatable(true)
        .build();
    kdbx_import_row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
    {
        let state = state.clone();
        let toast = toast.clone();
        kdbx_import_row.connect_activated(move |row| {
            run_import_kdbx(
                state.clone(),
                toast.clone(),
                row.upcast_ref::<gtk::Widget>().clone(),
            );
        });
    }
    export_group.add(&kdbx_import_row);

    let export_row = adw::ActionRow::builder()
        .title(tr!("Export to CSV (plaintext)"))
        .subtitle(tr!("Saves all entries as plaintext"))
        .activatable(true)
        .build();
    export_row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
    {
        let state = state.clone();
        let toast = toast.clone();
        export_row.connect_activated(move |row| {
            run_export_csv(
                state.clone(),
                toast.clone(),
                row.upcast_ref::<gtk::Widget>().clone(),
            );
        });
    }
    export_group.add(&export_row);
    page.add(&export_group);
}

#[derive(Clone, Copy)]
pub(super) enum ImportKind {
    Csv,
    Aegis,
    Andotp,
    Bitwarden,
    Onepassword,
}

pub(super) fn import_row(
    state: SharedState,
    toast: adw::ToastOverlay,
    title: &str,
    subtitle: &str,
    kind: ImportKind,
) -> adw::ActionRow {
    let row = adw::ActionRow::builder()
        .title(title)
        .subtitle(subtitle)
        .activatable(true)
        .build();
    row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
    {
        let state = state.clone();
        let toast = toast.clone();
        row.connect_activated(move |r| {
            run_import(
                state.clone(),
                toast.clone(),
                kind,
                r.upcast_ref::<gtk::Widget>().clone(),
            );
        });
    }
    row
}

pub(super) fn run_import(
    state: SharedState,
    toast: adw::ToastOverlay,
    kind: ImportKind,
    anchor: gtk::Widget,
) {
    let dialog = gtk::FileDialog::builder()
        .title(match kind {
            ImportKind::Csv => tr!("Choose a CSV file"),
            ImportKind::Aegis => tr!("Choose an Aegis JSON export"),
            ImportKind::Andotp => tr!("Choose an andOTP JSON export"),
            ImportKind::Bitwarden => tr!("Choose a Bitwarden JSON export"),
            ImportKind::Onepassword => tr!("Choose a 1Password .1pux archive"),
        })
        .modal(true)
        .build();

    let filter = gtk::FileFilter::new();
    match kind {
        ImportKind::Csv => {
            filter.set_name(Some("CSV"));
            filter.add_suffix("csv");
            filter.add_mime_type("text/csv");
        }
        ImportKind::Aegis | ImportKind::Andotp | ImportKind::Bitwarden => {
            filter.set_name(Some("JSON"));
            filter.add_suffix("json");
            filter.add_mime_type("application/json");
        }
        ImportKind::Onepassword => {
            filter.set_name(Some("1Password 1PUX"));
            filter.add_suffix("1pux");
            filter.add_mime_type("application/zip");
        }
    }
    let filters = gio::ListStore::new::<gtk::FileFilter>();
    filters.append(&filter);
    dialog.set_filters(Some(&filters));

    let parent = anchor.root().and_then(|r| r.downcast::<gtk::Window>().ok());
    dialog.open(parent.as_ref(), None::<&gio::Cancellable>, move |result| {
        let Ok(file) = result else { return };
        let Some(path) = file.path() else { return };
        let parts = match state.vault.borrow().session_reopen_parts() {
            Ok(parts) => parts,
            Err(error) => {
                show_toast(&toast, &format!("{}: {error}", tr!("Import failed")));
                return;
            }
        };
        let state_done = state.clone();
        let toast_done = toast.clone();
        run_background(
            move || {
                let outcome: ashypass_core::Result<usize> = (|| {
                    let vault = ashypass_core::db::Vault::open_with_session_key(parts.0, parts.1)?;
                    match kind {
                        ImportKind::Csv => {
                            let entries = ashypass_core::importers::import_csv(&path)?;
                            ashypass_core::importers::import_csv_entries(&vault, entries)
                        }
                        ImportKind::Aegis => {
                            let entries = ashypass_core::importers::aegis::import_plain(&path)?;
                            ashypass_core::importers::import_aegis_entries(&vault, entries)
                        }
                        ImportKind::Andotp => {
                            let entries = ashypass_core::importers::andotp::import_plain(&path)?;
                            ashypass_core::importers::import_andotp_entries(&vault, entries)
                        }
                        ImportKind::Bitwarden => {
                            ashypass_core::importers::bitwarden::import_into_vault(&vault, &path)
                        }
                        ImportKind::Onepassword => {
                            ashypass_core::importers::onepassword::import_into_vault(&vault, &path)
                        }
                    }
                })();
                outcome
            },
            move |outcome| match outcome {
                Ok(n) => {
                    show_toast(&toast_done, &format!("{} ({n})", tr!("Import complete")));
                    state_done
                        .events
                        .emit(crate::events::AppEvent::VaultChanged);
                }
                Err(e) => show_toast(&toast_done, &format!("{}: {e}", tr!("Import failed"))),
            },
        );
    });
}

pub(super) fn run_export_ashy(state: SharedState, toast: adw::ToastOverlay, anchor: gtk::Widget) {
    let parent_window = anchor.root().and_then(|r| r.downcast::<gtk::Window>().ok());
    prompt_password(
        parent_window.as_ref(),
        tr!("Encrypt export"),
        tr!("Pick a password to protect this .ashy file. You will need it to import."),
        true,
        {
            let state = state.clone();
            let toast = toast.clone();
            let anchor = anchor.clone();
            move |password| {
                let dialog = gtk::FileDialog::builder()
                    .title(tr!("Save encrypted export"))
                    .initial_name("ashypass-export.ashy")
                    .modal(true)
                    .build();
                let parent = anchor.root().and_then(|r| r.downcast::<gtk::Window>().ok());
                let state = state.clone();
                let toast = toast.clone();
                let password = password.clone();
                dialog.save(parent.as_ref(), None::<&gio::Cancellable>, move |result| {
                    let Ok(file) = result else { return };
                    let Some(path) = file.path() else { return };
                    let parts = match state.vault.borrow().session_reopen_parts() {
                        Ok(parts) => parts,
                        Err(error) => {
                            show_toast(&toast, &format!("{}: {error}", tr!("Export failed")));
                            return;
                        }
                    };
                    let toast_done = toast.clone();
                    run_background(
                        move || {
                            let vault =
                                ashypass_core::db::Vault::open_with_session_key(parts.0, parts.1)?;
                            ashypass_core::importers::ashy::export_vault(&vault, &path, &password)
                        },
                        move |outcome| match outcome {
                            Ok(n) => show_toast(
                                &toast_done,
                                &format!("{} ({n})", tr!("Encrypted export complete")),
                            ),
                            Err(e) => {
                                show_toast(&toast_done, &format!("{}: {e}", tr!("Export failed")))
                            }
                        },
                    );
                });
            }
        },
    );
}

pub(super) fn run_import_ashy(state: SharedState, toast: adw::ToastOverlay, anchor: gtk::Widget) {
    let dialog = gtk::FileDialog::builder()
        .title(tr!("Open .ashy export"))
        .modal(true)
        .build();
    let parent = anchor.root().and_then(|r| r.downcast::<gtk::Window>().ok());
    let state_cl = state.clone();
    let toast_cl = toast.clone();
    let anchor_cl = anchor.clone();
    dialog.open(parent.as_ref(), None::<&gio::Cancellable>, move |result| {
        let Ok(file) = result else { return };
        let Some(path) = file.path() else { return };
        let state = state_cl.clone();
        let toast = toast_cl.clone();
        let parent_window = anchor_cl
            .root()
            .and_then(|r| r.downcast::<gtk::Window>().ok());
        prompt_password(
            parent_window.as_ref(),
            tr!("Import .ashy"),
            tr!("Enter the password used when this file was exported."),
            false,
            move |password| {
                let parts = match state.vault.borrow().session_reopen_parts() {
                    Ok(parts) => parts,
                    Err(error) => {
                        show_toast(&toast, &format!("{}: {error}", tr!("Import failed")));
                        return;
                    }
                };
                let state_done = state.clone();
                let toast_done = toast.clone();
                let path = path.clone();
                run_background(
                    move || {
                        let vault =
                            ashypass_core::db::Vault::open_with_session_key(parts.0, parts.1)?;
                        ashypass_core::importers::ashy::import_into_vault(&vault, &path, &password)
                    },
                    move |outcome| match outcome {
                        Ok(n) => {
                            show_toast(&toast_done, &format!("{} ({n})", tr!("Import complete")));
                            state_done
                                .events
                                .emit(crate::events::AppEvent::VaultChanged);
                        }
                        Err(e) => {
                            show_toast(&toast_done, &format!("{}: {e}", tr!("Import failed")));
                        }
                    },
                );
            },
        );
    });
}

pub(super) fn run_export_kdbx(state: SharedState, toast: adw::ToastOverlay, anchor: gtk::Widget) {
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
                dialog.save(parent.as_ref(), None::<&gio::Cancellable>, move |result| {
                    let Ok(file) = result else { return };
                    let Some(path) = file.path() else { return };
                    let parts = match state.vault.borrow().session_reopen_parts() {
                        Ok(parts) => parts,
                        Err(error) => {
                            show_toast(&toast, &format!("{}: {error}", tr!("Export failed")));
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
                        move |outcome| match outcome {
                            Ok(n) => show_toast(
                                &toast_done,
                                &format!("{} ({n})", tr!("KeePass export complete")),
                            ),
                            Err(e) => {
                                show_toast(&toast_done, &format!("{}: {e}", tr!("Export failed")))
                            }
                        },
                    );
                });
            }
        },
    );
}

pub(super) fn run_import_kdbx(state: SharedState, toast: adw::ToastOverlay, anchor: gtk::Widget) {
    let dialog = gtk::FileDialog::builder()
        .title(tr!("Open KeePass database"))
        .modal(true)
        .build();
    let filter = gtk::FileFilter::new();
    filter.set_name(Some("KeePass (.kdbx)"));
    filter.add_suffix("kdbx");
    let filters = gio::ListStore::new::<gtk::FileFilter>();
    filters.append(&filter);
    dialog.set_filters(Some(&filters));

    let parent = anchor.root().and_then(|r| r.downcast::<gtk::Window>().ok());
    let state_cl = state.clone();
    let toast_cl = toast.clone();
    let anchor_cl = anchor.clone();
    dialog.open(parent.as_ref(), None::<&gio::Cancellable>, move |result| {
        let Ok(file) = result else { return };
        let Some(path) = file.path() else { return };
        let state = state_cl.clone();
        let toast = toast_cl.clone();
        let parent_window = anchor_cl
            .root()
            .and_then(|r| r.downcast::<gtk::Window>().ok());
        prompt_password(
            parent_window.as_ref(),
            tr!("Open KeePass database"),
            tr!("Enter the master password for this .kdbx file."),
            false,
            move |password| {
                let parts = match state.vault.borrow().session_reopen_parts() {
                    Ok(parts) => parts,
                    Err(error) => {
                        show_toast(&toast, &format!("{}: {error}", tr!("Import failed")));
                        return;
                    }
                };
                let state_done = state.clone();
                let toast_done = toast.clone();
                let path = path.clone();
                run_background(
                    move || {
                        let vault =
                            ashypass_core::db::Vault::open_with_session_key(parts.0, parts.1)?;
                        ashypass_core::importers::keepass::import_into_vault(
                            &vault, &path, &password,
                        )
                    },
                    move |outcome| match outcome {
                        Ok(n) => {
                            show_toast(&toast_done, &format!("{} ({n})", tr!("Import complete")));
                            state_done
                                .events
                                .emit(crate::events::AppEvent::VaultChanged);
                        }
                        Err(e) => {
                            show_toast(&toast_done, &format!("{}: {e}", tr!("Import failed")))
                        }
                    },
                );
            },
        );
    });
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
    let dialog = adw::AlertDialog::builder()
        .heading(heading)
        .body(body)
        .build();
    dialog.add_response("cancel", tr!("Cancel"));
    dialog.add_response("ok", tr!("OK"));
    dialog.set_default_response(Some("ok"));
    dialog.set_response_appearance("ok", adw::ResponseAppearance::Suggested);

    let pw = adw::PasswordEntryRow::builder()
        .title(tr!("Password"))
        .build();
    let confirm_row = adw::PasswordEntryRow::builder()
        .title(tr!("Confirm password"))
        .build();

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
                let warn = adw::AlertDialog::builder()
                    .heading(tr!("Passwords do not match"))
                    .build();
                warn.add_response("ok", tr!("OK"));
                warn.present(Some(dlg));
                return;
            }
            on_ok(p);
        });
    }
    dialog.present(parent);
}

pub(super) fn run_export_csv(state: SharedState, toast: adw::ToastOverlay, anchor: gtk::Widget) {
    let dialog = gtk::FileDialog::builder()
        .title(tr!("Export vault to CSV"))
        .initial_name("ashypass-export.csv")
        .modal(true)
        .build();

    let parent = anchor.root().and_then(|r| r.downcast::<gtk::Window>().ok());
    dialog.save(parent.as_ref(), None::<&gio::Cancellable>, move |result| {
        let Ok(file) = result else { return };
        let Some(path) = file.path() else { return };
        let parts = match state.vault.borrow().session_reopen_parts() {
            Ok(parts) => parts,
            Err(error) => {
                show_toast(&toast, &format!("{}: {error}", tr!("Export failed")));
                return;
            }
        };
        let toast_done = toast.clone();
        run_background(
            move || {
                let vault = ashypass_core::db::Vault::open_with_session_key(parts.0, parts.1)?;
                ashypass_core::importers::vault_import::export_vault_to_csv(&vault, &path)
            },
            move |outcome| match outcome {
                Ok(n) => show_toast(&toast_done, &format!("{} ({n})", tr!("Export complete"))),
                Err(e) => show_toast(&toast_done, &format!("{}: {e}", tr!("Export failed"))),
            },
        );
    });
}
