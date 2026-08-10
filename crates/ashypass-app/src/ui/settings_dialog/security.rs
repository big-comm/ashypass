//! `settings_dialog` — security section.

use super::*;

// ---------------------------------------------------------------------------
// Security
// ---------------------------------------------------------------------------

pub(super) fn populate_security(
    page: &adw::PreferencesPage,
    state: SharedState,
    settings: Rc<RefCell<Settings>>,
    toast: adw::ToastOverlay,
    parent: gtk::Widget,
    dialog_slot: Rc<RefCell<Option<adw::Dialog>>>,
) {
    let unlocked = state.vault.borrow().is_unlocked();
    if !unlocked {
        page.add(&locked_notice_group(
            state.clone(),
            toast.clone(),
            parent,
            dialog_slot,
        ));
    }

    // --- Master password
    let mp_group = adw::PreferencesGroup::builder()
        .title(tr!("Master Password"))
        .description(tr!(
            "Used to unlock the vault. Changing it re-encrypts all stored data."
        ))
        .build();

    let current_row = adw::PasswordEntryRow::builder()
        .title(tr!("Current password"))
        .build();
    let new_row = adw::PasswordEntryRow::builder()
        .title(tr!("New password"))
        .build();
    let confirm_row = adw::PasswordEntryRow::builder()
        .title(tr!("Confirm new password"))
        .build();
    let change_btn = gtk::Button::builder()
        .label(tr!("Change Master Password"))
        .halign(gtk::Align::End)
        .margin_top(8)
        .build();
    change_btn.add_css_class("suggested-action");
    change_btn.add_css_class("pill");
    change_btn.set_sensitive(unlocked);

    let status_lbl = gtk::Label::builder()
        .xalign(0.0)
        .wrap(true)
        .visible(false)
        .build();
    status_lbl.add_css_class("dim-label");

    let row_actions = adw::PreferencesGroup::new();
    row_actions.add(&current_row);
    row_actions.add(&new_row);
    row_actions.add(&confirm_row);

    mp_group.add(&row_actions);

    let btn_box = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(6)
        .margin_top(6)
        .build();
    btn_box.append(&status_lbl);
    btn_box.append(&change_btn);
    mp_group.add(&btn_box);

    {
        let state = state.clone();
        let settings = settings.clone();
        let cur = current_row.clone();
        let new_e = new_row.clone();
        let conf = confirm_row.clone();
        let status = status_lbl.clone();
        change_btn.connect_clicked(move |_| {
            let cur_pw = cur.text().to_string();
            let new_pw = new_e.text().to_string();
            let conf_pw = conf.text().to_string();
            status.set_visible(true);
            if cur_pw.is_empty() || new_pw.is_empty() {
                status.set_text(tr!("All fields are required."));
                status.remove_css_class("success");
                status.add_css_class("error");
                return;
            }
            if new_pw.chars().count() < MIN_MASTER_PASSWORD_LENGTH {
                status.set_text(&format!(
                    "{} ({}+ chars)",
                    tr!("Password too short"),
                    MIN_MASTER_PASSWORD_LENGTH
                ));
                status.remove_css_class("success");
                status.add_css_class("error");
                return;
            }
            if new_pw != conf_pw {
                status.set_text(tr!("Passwords do not match."));
                status.remove_css_class("success");
                status.add_css_class("error");
                return;
            }
            match state
                .vault
                .borrow_mut()
                .change_master_password(&cur_pw, &new_pw)
            {
                Ok(()) => {
                    if let Err(error) = ashypass_core::keyring::delete_quick_unlock() {
                        log::warn!("could not revoke quick-unlock keyring state: {error}");
                    }
                    settings.borrow_mut().quick_unlock = None;
                    if let Err(error) = settings.borrow().save() {
                        log::warn!("could not save quick-unlock migration: {error}");
                    }
                    status.set_text(tr!("Master password changed."));
                    status.remove_css_class("error");
                    status.add_css_class("success");
                    cur.set_text("");
                    new_e.set_text("");
                    conf.set_text("");
                }
                Err(e) => {
                    status.set_text(&format!("{}: {e}", tr!("Error")));
                    status.remove_css_class("success");
                    status.add_css_class("error");
                }
            }
        });
    }

    page.add(&mp_group);

    // --- Auto-lock + clipboard
    let timing_group = adw::PreferencesGroup::builder()
        .title(tr!("Session"))
        .build();

    let lock_row = adw::SpinRow::with_range(15.0, 3600.0, 15.0);
    lock_row.set_title(tr!("Auto-lock after (seconds)"));
    lock_row.set_subtitle(tr!("Lock vault when idle for this long"));
    lock_row.set_value(settings.borrow().lock_timeout as f64);
    {
        let settings = settings.clone();
        let state = state.clone();
        lock_row.connect_value_notify(move |row| {
            let v = row.value() as u64;
            settings.borrow_mut().lock_timeout = v;
            save_settings(&settings.borrow());
            state.session.borrow_mut().timeout_seconds = v.max(15);
            // Re-arm with the new duration; the timer already running was
            // scheduled against the previous value.
            SessionManager::on_activity(&state.session);
        });
    }
    timing_group.add(&lock_row);

    let clip_row = adw::SpinRow::with_range(0.0, 600.0, 15.0);
    clip_row.set_title(tr!("Clear clipboard after (seconds)"));
    clip_row.set_subtitle(tr!("0 disables auto-clear"));
    clip_row.set_value(settings.borrow().clipboard_clear as f64);
    {
        let settings = settings.clone();
        clip_row.connect_value_notify(move |row| {
            settings.borrow_mut().clipboard_clear = row.value() as u64;
            save_settings(&settings.borrow());
        });
    }
    timing_group.add(&clip_row);

    page.add(&timing_group);

    // --- Browser integration
    let browser_group = adw::PreferencesGroup::builder()
        .title(tr!("Browser Integration"))
        .description(tr!(
            "When enabled, the browser extension can read vault entries by \
             unlocking from the system keyring, even while this window is \
             locked. The key is dropped again after the auto-lock delay."
        ))
        .build();

    let browser_row = adw::SwitchRow::builder()
        .title(tr!("Allow browser extension access"))
        .subtitle(tr!("Answer native-messaging requests from the extension"))
        .active(settings.borrow().browser_integration)
        .build();
    {
        let settings = settings.clone();
        browser_row.connect_active_notify(move |row| {
            settings.borrow_mut().browser_integration = row.is_active();
            save_settings(&settings.borrow());
        });
    }
    browser_group.add(&browser_row);
    page.add(&browser_group);

    // --- Quick-unlock (PIN)
    let qu_group = adw::PreferencesGroup::builder()
        .title(tr!("Quick Unlock"))
        .description(tr!(
            "After auto-lock or restart, unlock with a short PIN instead of \
             the master password on this device. The vault key is stored \
             encrypted by the PIN."
        ))
        .build();

    let pin_row = adw::PasswordEntryRow::builder()
        .title(tr!("New PIN (6+ chars)"))
        .build();
    qu_group.add(&pin_row);

    let qu_status_row = adw::ActionRow::builder().title(tr!("Status")).build();
    let qu_status_lbl = gtk::Label::new(None);
    qu_status_lbl.add_css_class("dim-label");
    let render_qu_status = {
        let state = state.clone();
        let settings = settings.clone();
        move || {
            let v = state.vault.borrow();
            let persisted = ashypass_core::keyring::is_quick_unlock_stored()
                || settings
                    .borrow()
                    .quick_unlock
                    .as_ref()
                    .is_some_and(|p| p.is_configured());
            if persisted {
                tr!("Enabled on this device")
            } else if v.is_quick_unlock_available() {
                tr!("Enabled for this session")
            } else if v.is_unlocked() {
                tr!("Disabled")
            } else {
                tr!("Vault must be unlocked to configure")
            }
        }
    };
    qu_status_lbl.set_label(render_qu_status());
    qu_status_row.add_suffix(&qu_status_lbl);
    qu_group.add(&qu_status_row);

    let qu_btn_box = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(8)
        .margin_top(8)
        .halign(gtk::Align::End)
        .build();
    let qu_disable_btn = gtk::Button::with_label(tr!("Disable"));
    let qu_enable_btn = gtk::Button::with_label(tr!("Enable / Update"));
    qu_enable_btn.add_css_class("suggested-action");
    qu_btn_box.append(&qu_disable_btn);
    qu_btn_box.append(&qu_enable_btn);
    qu_group.add(&qu_btn_box);

    {
        let state = state.clone();
        let settings = settings.clone();
        let pin_row = pin_row.clone();
        let status_lbl = qu_status_lbl.clone();
        let toast = toast.clone();
        let render = render_qu_status.clone();
        qu_enable_btn.connect_clicked(move |_| {
            let pin = pin_row.text().to_string();
            let r = state
                .vault
                .borrow_mut()
                .enable_persistent_quick_unlock(&pin);
            match r {
                Ok(prefs) => {
                    if let Err(error) = ashypass_core::keyring::store_quick_unlock(&prefs) {
                        state.vault.borrow_mut().disable_quick_unlock();
                        toast.add_toast(
                            adw::Toast::builder()
                                .title(format!("{}: {error}", tr!("System keyring unavailable")))
                                .timeout(5)
                                .build(),
                        );
                        return;
                    }
                    settings.borrow_mut().quick_unlock = None;
                    if let Err(error) = settings.borrow().save() {
                        log::warn!("could not clear legacy quick-unlock state: {error}");
                    }
                    pin_row.set_text("");
                    status_lbl.set_label(render());
                    toast.add_toast(
                        adw::Toast::builder()
                            .title(tr!("Quick-unlock enabled"))
                            .timeout(3)
                            .build(),
                    );
                }
                Err(ashypass_core::Error::Locked) => {
                    toast.add_toast(
                        adw::Toast::builder()
                            .title(tr!("Unlock the vault first"))
                            .timeout(3)
                            .build(),
                    );
                }
                Err(e) => {
                    toast.add_toast(
                        adw::Toast::builder()
                            .title(format!("{e}"))
                            .timeout(3)
                            .build(),
                    );
                }
            }
        });
    }
    {
        let state = state.clone();
        let settings = settings.clone();
        let status_lbl = qu_status_lbl.clone();
        let toast = toast.clone();
        let render = render_qu_status.clone();
        qu_disable_btn.connect_clicked(move |_| {
            if let Err(error) = ashypass_core::keyring::delete_quick_unlock() {
                toast.add_toast(
                    adw::Toast::builder()
                        .title(format!(
                            "{}: {error}",
                            tr!("Could not disable quick-unlock")
                        ))
                        .timeout(5)
                        .build(),
                );
                return;
            }
            state.vault.borrow_mut().disable_quick_unlock();
            settings.borrow_mut().quick_unlock = None;
            if let Err(error) = settings.borrow().save() {
                log::warn!("could not clear legacy quick-unlock state: {error}");
            }
            status_lbl.set_label(render());
            toast.add_toast(
                adw::Toast::builder()
                    .title(tr!("Quick-unlock disabled"))
                    .timeout(3)
                    .build(),
            );
        });
    }

    page.add(&qu_group);

    // --- System keyring (Secret Service)
    let kr_group = adw::PreferencesGroup::builder()
        .title(tr!("System Keyring"))
        .description(tr!(
            "Store the master password in the desktop's Secret Service (GNOME \
             Keyring, KWallet, etc.) so Ashy Pass can unlock automatically on \
             start. The keyring is locked with your login password — disable \
             this if multiple users share the desktop session."
        ))
        .build();

    let kr_master_row = adw::PasswordEntryRow::builder()
        .title(tr!("Current master password"))
        .build();
    kr_group.add(&kr_master_row);

    let kr_status_row = adw::ActionRow::builder().title(tr!("Status")).build();
    let kr_status_lbl = gtk::Label::new(None);
    kr_status_lbl.add_css_class("dim-label");
    let render_kr_status = || {
        if ashypass_core::keyring::is_stored() {
            tr!("Master password is in the keyring")
        } else {
            tr!("Not stored")
        }
    };
    kr_status_lbl.set_label(render_kr_status());
    kr_status_row.add_suffix(&kr_status_lbl);
    kr_group.add(&kr_status_row);

    let kr_btn_box = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(8)
        .margin_top(8)
        .halign(gtk::Align::End)
        .build();
    let kr_remove_btn = gtk::Button::with_label(tr!("Remove"));
    let kr_store_btn = gtk::Button::with_label(tr!("Store"));
    kr_store_btn.add_css_class("suggested-action");
    kr_btn_box.append(&kr_remove_btn);
    kr_btn_box.append(&kr_store_btn);
    kr_group.add(&kr_btn_box);

    {
        let state = state.clone();
        let toast = toast.clone();
        let kr_master_row = kr_master_row.clone();
        let kr_status_lbl = kr_status_lbl.clone();
        kr_store_btn.connect_clicked(move |_| {
            let pw = kr_master_row.text().to_string();
            if pw.is_empty() {
                toast.add_toast(
                    adw::Toast::builder()
                        .title(tr!("Type the current master password first"))
                        .timeout(3)
                        .build(),
                );
                return;
            }
            // Confirm it actually matches the active vault before storing.
            if !state
                .vault
                .borrow()
                .verify_master_password(&pw)
                .unwrap_or(false)
            {
                toast.add_toast(
                    adw::Toast::builder()
                        .title(tr!("Wrong master password"))
                        .timeout(3)
                        .build(),
                );
                return;
            }
            match ashypass_core::keyring::store_master(&pw) {
                Ok(()) => {
                    kr_master_row.set_text("");
                    kr_status_lbl.set_label(render_kr_status());
                    toast.add_toast(
                        adw::Toast::builder()
                            .title(tr!("Stored in system keyring"))
                            .timeout(3)
                            .build(),
                    );
                }
                Err(e) => {
                    toast.add_toast(
                        adw::Toast::builder()
                            .title(format!("{}: {e}", tr!("Keyring error")))
                            .timeout(4)
                            .build(),
                    );
                }
            }
        });
    }
    {
        let toast = toast.clone();
        let kr_status_lbl = kr_status_lbl.clone();
        kr_remove_btn.connect_clicked(move |_| match ashypass_core::keyring::delete_master() {
            Ok(()) => {
                kr_status_lbl.set_label(render_kr_status());
                toast.add_toast(
                    adw::Toast::builder()
                        .title(tr!("Removed from keyring"))
                        .timeout(3)
                        .build(),
                );
            }
            Err(e) => {
                toast.add_toast(
                    adw::Toast::builder()
                        .title(format!("{}: {e}", tr!("Keyring error")))
                        .timeout(4)
                        .build(),
                );
            }
        });
    }

    page.add(&kr_group);

    // --- Argon2 KDF tuning
    let kdf_group = adw::PreferencesGroup::builder()
        .title(tr!("Key Derivation (Argon2id)"))
        .description(tr!(
            "Argon2id turns your master password into the vault encryption key; \
             it is not a physical security key. Higher costs slow brute force but also slow unlock. \
             Auto-tune picks values calibrated to ~500 ms on this machine. \
             Existing master hashes keep their original costs; tuned values \
             apply on the next master password change."
        ))
        .build();

    let params_row = adw::ActionRow::builder()
        .title(tr!("Current parameters"))
        .build();
    let params_lbl = gtk::Label::builder().build();
    params_lbl.add_css_class("dim-label");
    params_lbl.add_css_class("monospace");
    let render_params = |p: ashypass_core::crypto::autotune::TunedParams| {
        format!(
            "t={} m={} MiB p={}",
            p.t_cost,
            p.m_cost_kib / 1024,
            p.p_cost
        )
    };
    params_lbl.set_label(&render_params(settings.borrow().argon2));
    params_row.add_suffix(&params_lbl);
    kdf_group.add(&params_row);

    let tune_row = adw::ActionRow::builder()
        .title(tr!("Auto-tune"))
        .subtitle(tr!("Benchmark this machine (~5 s)"))
        .activatable(true)
        .build();
    let tune_btn = gtk::Button::builder()
        .label(tr!("Run"))
        .valign(gtk::Align::Center)
        .build();
    tune_btn.add_css_class("suggested-action");
    let tune_spinner = gtk::Spinner::new();
    tune_spinner.set_visible(false);
    tune_row.add_suffix(&tune_spinner);
    tune_row.add_suffix(&tune_btn);
    kdf_group.add(&tune_row);

    {
        use std::sync::{Arc, Mutex};
        let settings_cl = settings.clone();
        let params_lbl_cl = params_lbl.clone();
        let tune_btn_cl = tune_btn.clone();
        let tune_spinner_cl = tune_spinner.clone();
        let busy = Rc::new(RefCell::new(false));
        let cb = Rc::new(move || {
            if *busy.borrow() {
                return;
            }
            *busy.borrow_mut() = true;
            tune_btn_cl.set_sensitive(false);
            tune_spinner_cl.set_visible(true);
            tune_spinner_cl.start();

            let result: Arc<Mutex<Option<ashypass_core::crypto::autotune::TunedParams>>> =
                Arc::new(Mutex::new(None));
            {
                let result = result.clone();
                std::thread::spawn(move || {
                    let tuned = ashypass_core::crypto::autotune::autotune(500, 1_048_576);
                    if let Ok(mut slot) = result.lock() {
                        *slot = Some(tuned);
                    }
                });
            }
            let settings = settings_cl.clone();
            let params_lbl = params_lbl_cl.clone();
            let tune_btn_inner = tune_btn_cl.clone();
            let tune_spinner_inner = tune_spinner_cl.clone();
            let busy = busy.clone();
            glib::timeout_add_local(std::time::Duration::from_millis(150), move || {
                let tuned_opt = result.lock().ok().and_then(|g| *g);
                if let Some(tuned) = tuned_opt {
                    settings.borrow_mut().argon2 = tuned;
                    save_settings(&settings.borrow());
                    params_lbl.set_label(&render_params(tuned));
                    tune_btn_inner.set_sensitive(true);
                    tune_spinner_inner.stop();
                    tune_spinner_inner.set_visible(false);
                    *busy.borrow_mut() = false;
                    glib::ControlFlow::Break
                } else {
                    glib::ControlFlow::Continue
                }
            });
        });
        let cb_btn = cb.clone();
        tune_btn.connect_clicked(move |_| (cb_btn)());
        tune_row.connect_activated(move |_| (cb)());
    }

    page.add(&kdf_group);
}
