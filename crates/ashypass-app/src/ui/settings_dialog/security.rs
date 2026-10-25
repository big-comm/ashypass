//! `settings_dialog` — "Protection and unlocking" and "Browser".
//!
//! Everyday choices first, in units people use (minutes, not seconds), and
//! descriptions that match what the code really does: the PIN is a local
//! convenience with real limits, clearing the clipboard only clears what
//! Ashy Pass copied, and changing the master password opens its own page
//! instead of three fields that are always on screen.

use super::*;
use zeroize::Zeroizing;

/// Auto-lock choices, in seconds. A value saved by an older version that is
/// not in this list is shown as its own entry and kept as is.
const LOCK_CHOICES: &[u64] = &[30, 60, 120, 300, 600, 900, 1800, 3600];
/// Clipboard choices, in seconds; 0 = never.
const CLIPBOARD_CHOICES: &[u64] = &[0, 15, 30, 60, 120, 300];

pub(super) fn duration_label(seconds: u64) -> String {
    if seconds == 0 {
        return tr!("Never").to_string();
    }
    if seconds.is_multiple_of(3600) {
        let hours = (seconds / 3600) as usize;
        return trn!("{} hour", "{} hours", hours).replace("{}", &hours.to_string());
    }
    if seconds.is_multiple_of(60) {
        let minutes = (seconds / 60) as usize;
        return trn!("{} minute", "{} minutes", minutes).replace("{}", &minutes.to_string());
    }
    trn!("{} second", "{} seconds", seconds as usize).replace("{}", &seconds.to_string())
}

/// The choices to offer: the standard list plus the current value when it
/// is not one of them, in ascending order.
pub(super) fn choices_with(current: u64, standard: &[u64]) -> Vec<u64> {
    let mut values = standard.to_vec();
    if !values.contains(&current) {
        values.push(current);
        values.sort_unstable();
    }
    values
}

fn duration_row<F>(
    title: &str,
    subtitle: Option<&str>,
    standard: &[u64],
    current: u64,
    on_change: F,
) -> adw::ComboRow
where
    F: Fn(u64) + 'static,
{
    let values = choices_with(current, standard);
    let labels: Vec<String> = values.iter().map(|v| duration_label(*v)).collect();
    let model = gtk::StringList::new(&labels.iter().map(String::as_str).collect::<Vec<_>>());
    let row = adw::ComboRow::builder().title(title).model(&model).build();
    if let Some(subtitle) = subtitle {
        row.set_subtitle(subtitle);
    }
    if let Some(index) = values.iter().position(|v| *v == current) {
        row.set_selected(index as u32);
    }
    row.connect_selected_notify(move |row| {
        if let Some(value) = values.get(row.selected() as usize) {
            on_change(*value);
        }
    });
    row
}

pub(super) fn populate_protection(
    page: &adw::PreferencesPage,
    state: SharedState,
    toast: Toaster,
    parent: gtk::Widget,
    dialog_slot: DialogSlot,
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
    let settings = state.settings();

    // --- Master password -------------------------------------------------
    let master_group = adw::PreferencesGroup::builder()
        .title(tr!("Master password"))
        .description(tr!(
            "It opens the vault on this computer. Nobody can recover it for you — not even Ashy Pass."
        ))
        .build();
    let change_row = adw::ActionRow::builder()
        .title(tr!("Change master password…"))
        .activatable(true)
        .sensitive(unlocked)
        .build();
    change_row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
    {
        let state = state.clone();
        let toast = toast.clone();
        // The dialog from the row: a captured one would hold itself.
        change_row.connect_activated(move |row| {
            let Some(dialog) = settings_dialog_of(row) else {
                return;
            };
            dialog.push_subpage(&change_master_page(&state, &toast, &dialog));
        });
    }
    master_group.add(&change_row);
    // Recovery that really exists: the PIN of this computer already opens
    // the vault, so it can authorise a new master password.
    if unlocked && pin_record(&state).is_some() {
        let reset_row = adw::ActionRow::builder()
            .title(tr!("Forgot the master password…"))
            .subtitle(tr!("Set a new one using the PIN of this computer"))
            .activatable(true)
            .build();
        reset_row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
        let state = state.clone();
        let toast = toast.clone();
        reset_row.connect_activated(move |row| {
            let Some(dialog) = settings_dialog_of(row) else {
                return;
            };
            dialog.push_subpage(&reset_master_page(&state, &toast, &dialog));
        });
        master_group.add(&reset_row);
    }
    page.add(&master_group);

    // --- Auto-lock -------------------------------------------------------
    let lock_group = adw::PreferencesGroup::builder()
        .title(tr!("Automatic lock"))
        .description(tr!(
            "A warning appears before it locks, with time to keep using it"
        ))
        .build();
    {
        let state_cl = state.clone();
        let row = duration_row(
            tr!("Lock after inactivity"),
            None,
            LOCK_CHOICES,
            settings.lock_timeout,
            move |seconds| {
                if let Err(e) = state_cl.update_settings(|s| s.lock_timeout = seconds) {
                    log::warn!("could not save settings: {e}");
                }
                state_cl.session.borrow_mut().timeout_seconds = seconds.max(15);
                // Re-arm with the new duration.
                SessionManager::on_activity(&state_cl.session);
            },
        );
        lock_group.add(&row);
    }
    let screen_lock_row = adw::SwitchRow::builder()
        .title(tr!("Lock when the screen locks or the computer sleeps"))
        .active(settings.lock_on_screen_lock)
        .build();
    {
        let state = state.clone();
        screen_lock_row.connect_active_notify(move |row| {
            let active = row.is_active();
            if let Err(e) = state.update_settings(|s| s.lock_on_screen_lock = active) {
                log::warn!("could not save settings: {e}");
            }
        });
    }
    lock_group.add(&screen_lock_row);
    page.add(&lock_group);

    // --- Clipboard ---------------------------------------------------------
    let clip_group = adw::PreferencesGroup::builder()
        .title(tr!("Clipboard"))
        .description(tr!(
            "Only clears the clipboard if it still holds what Ashy Pass copied, so text you copied afterwards in another app is kept. Clipboard history managers may keep copies that Ashy Pass cannot remove."
        ))
        .build();
    {
        let state = state.clone();
        let row = duration_row(
            tr!("Clear copied passwords after"),
            None,
            CLIPBOARD_CHOICES,
            settings.clipboard_clear,
            move |seconds| {
                if let Err(e) = state.update_settings(|s| s.clipboard_clear = seconds) {
                    log::warn!("could not save settings: {e}");
                }
            },
        );
        clip_group.add(&row);
    }
    let history_row = adw::SwitchRow::builder()
        .title(tr!("Hide copied passwords from clipboard history"))
        .subtitle(tr!(
            "Asks history managers such as Big Clipboard and Klipper not to record them"
        ))
        .active(settings.clipboard_hide_from_history)
        .build();
    {
        let state = state.clone();
        history_row.connect_active_notify(move |row| {
            let active = row.is_active();
            if let Err(e) = state.update_settings(|s| s.clipboard_hide_from_history = active) {
                log::warn!("could not save settings: {e}");
            }
        });
    }
    clip_group.add(&history_row);
    page.add(&clip_group);

    page.add(&pin_group(&state, &toast, unlocked));
    page.add(&keyring_group(&state, &toast));

    // --- Technical details ----------------------------------------------
    page.add(&kdf_group(&state));
    if let Some(group) = legacy_backup_group(&state, &toast) {
        page.add(&group);
    }
}

/// Dedicated page for changing the master password.
/// The persisted PIN record of this computer, if any.
fn pin_record(state: &SharedState) -> Option<ashypass_core::settings::QuickUnlockPrefs> {
    ashypass_core::keyring::load_quick_unlock()
        .ok()
        .flatten()
        .filter(|p| p.is_configured())
        .or_else(|| {
            state
                .settings()
                .quick_unlock
                .clone()
                .filter(|p| p.is_configured())
        })
}

/// Replace a forgotten master password, authorised by the PIN.
fn reset_master_page(
    state: &SharedState,
    toast: &Toaster,
    dialog: &adw::PreferencesDialog,
) -> adw::NavigationPage {
    let page = adw::PreferencesPage::new();
    let group = adw::PreferencesGroup::builder()
        .description(tr!(
            "Confirm the PIN you use on this computer and choose a new master password. Everything in the vault is encrypted again, and the PIN keeps working. Backups made earlier still need the master password they were made with."
        ))
        .build();
    let pin_row = big_gtk_kit::password::password_row(
        adw::PasswordEntryRow::builder().title(tr!("PIN of this computer")),
    );
    let new_row = big_gtk_kit::password::password_row(
        adw::PasswordEntryRow::builder().title(tr!("New master password")),
    );
    let confirm_row = big_gtk_kit::password::password_row(
        adw::PasswordEntryRow::builder().title(tr!("Confirm new master password")),
    );
    group.add(&pin_row);
    group.add(&new_row);
    group.add(&confirm_row);
    page.add(&group);

    let status = gtk::Label::builder()
        .xalign(0.0)
        .wrap(true)
        .visible(false)
        .build();
    status.set_accessible_role(gtk::AccessibleRole::Alert);
    status.add_css_class("error");
    let button = gtk::Button::builder()
        .label(tr!("Set new master password"))
        .halign(gtk::Align::End)
        .build();
    button.add_css_class("suggested-action");
    button.add_css_class("pill");
    let actions = adw::PreferencesGroup::new();
    let action_box = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(12)
        .build();
    action_box.append(&status);
    action_box.append(&button);
    actions.add(&action_box);
    page.add(&actions);

    {
        let state = state.clone();
        let toast = toast.clone();
        // Weak: the button sits in a page of the dialog.
        let dialog = dialog.downgrade();
        button.connect_clicked(move |button| {
            let Some(dialog) = dialog.upgrade() else {
                return;
            };
            let show = |message: &str| {
                status.set_label(message);
                status.set_visible(true);
            };
            let pin = Zeroizing::new(pin_row.text().to_string());
            let new = Zeroizing::new(new_row.text().to_string());
            if pin.is_empty() || new.is_empty() {
                show(tr!("Fill in all three fields."));
                return;
            }
            if new.chars().count() < MIN_MASTER_PASSWORD_LENGTH {
                show(&format!(
                    "{} {MIN_MASTER_PASSWORD_LENGTH}",
                    tr!("The new password is too short. Minimum length:")
                ));
                return;
            }
            if new.as_str() != confirm_row.text().as_str() {
                show(tr!("The new passwords do not match."));
                return;
            }
            let Some(prefs) = pin_record(&state) else {
                show(tr!(
                    "There is no PIN on this computer. Nothing was changed."
                ));
                return;
            };
            let (key, format) = {
                let vault = state.vault.borrow();
                match (vault.session_reopen_parts(), vault.key_format()) {
                    (Ok((_, key)), Ok(format)) => (key, format),
                    _ => {
                        show(tr!("Unlock the vault first"));
                        return;
                    }
                }
            };
            // Three memory-hard derivations: off the main loop, so the
            // window keeps drawing; the vault itself changes back here.
            button.set_sensitive(false);
            show(tr!("Encrypting the vault again…"));
            let state = state.clone();
            let toast = toast.clone();
            let dialog = dialog.clone();
            let status = status.clone();
            let button = button.clone();
            let worker_new = new.clone();
            run_background(
                move || ashypass_core::db::vault::prepare_pin_reset(
                        &pin,
                        &prefs,
                        &key,
                        &worker_new,
                        format,
                    ),
                move |prepared| {
            let show = |message: &str| {
                status.set_label(message);
                status.set_visible(true);
            };
            button.set_sensitive(true);
            let result = prepared.and_then(|reset| state.vault.borrow_mut().apply_pin_reset(reset));
            match result {
                Ok(rewrapped) => {
                    // The vault key changed; the core re-wrapped it with the
                    // same PIN, so unlocking by PIN keeps working.
                    let pin_kept = match ashypass_core::keyring::store_quick_unlock(&rewrapped) {
                        Ok(()) => {
                            if let Err(e) = state.update_settings(|s| s.quick_unlock = None) {
                                log::warn!("could not clear legacy quick-unlock state: {e}");
                            }
                            true
                        }
                        Err(e) => {
                            log::warn!("could not store the PIN: {e}");
                            let _ = ashypass_core::keyring::delete_quick_unlock();
                            state.vault.borrow_mut().disable_quick_unlock();
                            false
                        }
                    };
                    if ashypass_core::keyring::is_stored() {
                        if let Err(e) = ashypass_core::keyring::store_master(&new) {
                            log::warn!("could not update the keyring copy: {e}");
                            let _ = ashypass_core::keyring::delete_master();
                        }
                    }
                    crate::folder_sync::rewrap(&state, &new);
                    toast.add_toast(
                        adw::Toast::builder().use_markup(false)
                            .title(if pin_kept {
                                tr!("New master password set. Write it down somewhere safe.")
                            } else {
                                tr!("New master password set, but the PIN could not be kept. Set it up again below.")
                            })
                            .timeout(8)
                            .build(),
                    );
                    dialog.pop_subpage();
                }
                Err(ashypass_core::Error::InvalidMasterPassword) => {
                    show(tr!("Incorrect PIN. Nothing was changed."));
                }
                Err(ashypass_core::Error::KeyMismatch) => {
                    show(tr!(
                        "This PIN no longer matches the vault. Nothing was changed."
                    ));
                }
                Err(e) => show(&format!("{} ({})", tr!("The password was not changed"), crate::ui::errors::describe(&e))),
            }
                },
            );
        });
    }

    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&adw::HeaderBar::new());
    toolbar.set_content(Some(&page));
    adw::NavigationPage::builder()
        .title(tr!("Forgot the master password"))
        .child(&toolbar)
        .build()
}

fn change_master_page(
    state: &SharedState,
    toast: &Toaster,
    dialog: &adw::PreferencesDialog,
) -> adw::NavigationPage {
    let page = adw::PreferencesPage::new();
    let group = adw::PreferencesGroup::builder()
        .description(tr!(
            "Everything in the vault is encrypted again with the new password. Backups made earlier still open with the password they were made with."
        ))
        .build();
    let current_row = big_gtk_kit::password::password_row(
        adw::PasswordEntryRow::builder().title(tr!("Current master password")),
    );
    let new_row = big_gtk_kit::password::password_row(
        adw::PasswordEntryRow::builder().title(tr!("New master password")),
    );
    let confirm_row = big_gtk_kit::password::password_row(
        adw::PasswordEntryRow::builder().title(tr!("Confirm new master password")),
    );
    group.add(&current_row);
    group.add(&new_row);
    group.add(&confirm_row);
    page.add(&group);

    let status = gtk::Label::builder()
        .xalign(0.0)
        .wrap(true)
        .visible(false)
        .build();
    status.set_accessible_role(gtk::AccessibleRole::Alert);
    let button = gtk::Button::builder()
        .label(tr!("Change master password"))
        .halign(gtk::Align::End)
        .build();
    button.add_css_class("suggested-action");
    button.add_css_class("pill");
    let actions = adw::PreferencesGroup::new();
    let action_box = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(12)
        .build();
    action_box.append(&status);
    action_box.append(&button);
    actions.add(&action_box);
    page.add(&actions);

    let show = {
        let status = status.clone();
        move |message: &str, ok: bool| {
            status.set_label(message);
            status.set_visible(true);
            status.remove_css_class(if ok { "error" } else { "success" });
            status.add_css_class(if ok { "success" } else { "error" });
        }
    };
    {
        let state = state.clone();
        let toast = toast.clone();
        // Weak: the button sits in a page of the dialog.
        let dialog = dialog.downgrade();
        button.connect_clicked(move |button| {
            let Some(dialog) = dialog.upgrade() else {
                return;
            };
            let current = Zeroizing::new(current_row.text().to_string());
            let new = Zeroizing::new(new_row.text().to_string());
            let confirm = Zeroizing::new(confirm_row.text().to_string());
            if current.is_empty() || new.is_empty() {
                show(tr!("Fill in all three fields."), false);
                return;
            }
            if new.chars().count() < MIN_MASTER_PASSWORD_LENGTH {
                show(
                    &format!(
                        "{} {MIN_MASTER_PASSWORD_LENGTH}",
                        tr!("The new password is too short. Minimum length:")
                    ),
                    false,
                );
                return;
            }
            if *new != *confirm {
                show(tr!("The new passwords do not match."), false);
                return;
            }
            let master = {
                let vault = state.vault.borrow();
                vault
                    .master_hash()
                    .and_then(|hash| Ok((hash, vault.key_format()?)))
            };
            let (hash, format) = match master {
                Ok(master) => master,
                Err(e) => {
                    show(
                        &format!(
                            "{} ({})",
                            tr!("The password was not changed"),
                            crate::ui::errors::describe(&e)
                        ),
                        false,
                    );
                    return;
                }
            };
            // Verifying and deriving are memory-hard: run them on a worker
            // and re-encrypt on the main thread, which owns the vault.
            button.set_sensitive(false);
            show(tr!("Encrypting the vault again…"), true);
            let state = state.clone();
            let toast = toast.clone();
            let dialog = dialog.clone();
            let show = show.clone();
            let button = button.clone();
            let worker_new = new.clone();
            run_background(
                move || -> ashypass_core::Result<_> {
                    if !ashypass_core::crypto::argon2_kdf::verify_master(&current, &hash)? {
                        return Err(ashypass_core::Error::InvalidMasterPassword);
                    }
                    ashypass_core::db::vault::prepare_rekey(&worker_new, format)
                },
                move |prepared| {
                    button.set_sensitive(true);
                    if !state.vault.borrow().is_unlocked() {
                        show(tr!("Unlock the vault first"), false);
                        return;
                    }
                    let result = prepared.and_then(|p| state.vault.borrow_mut().apply_rekey(p));
                    match result {
                        Ok(()) => {
                            // The PIN wraps the old key: it must be set up again.
                            if let Err(error) = ashypass_core::keyring::delete_quick_unlock() {
                                log::warn!("could not revoke quick-unlock keyring state: {error}");
                            }
                            state.vault.borrow_mut().disable_quick_unlock();
                            if let Err(error) = state.update_settings(|s| s.quick_unlock = None) {
                                log::warn!("could not clear quick-unlock settings: {error}");
                            }
                            // A copy in the keyring would no longer open the vault.
                            if ashypass_core::keyring::is_stored() {
                                if let Err(error) = ashypass_core::keyring::store_master(&new) {
                                    log::warn!("could not update the keyring copy: {error}");
                                    let _ = ashypass_core::keyring::delete_master();
                                }
                            }
                            crate::folder_sync::rewrap(&state, &new);
                            toast.add_toast(
                                adw::Toast::builder()
                                    .use_markup(false)
                                    .title(tr!(
                                "Master password changed. If you used a PIN, set it up again."
                            ))
                                    .timeout(6)
                                    .build(),
                            );
                            dialog.pop_subpage();
                        }
                        Err(ashypass_core::Error::InvalidMasterPassword) => {
                            show(
                        tr!("The current master password is incorrect. Nothing was changed."),
                        false,
                    );
                        }
                        Err(e) => show(
                            &format!(
                                "{} ({})",
                                tr!("The password was not changed"),
                                crate::ui::errors::describe(&e)
                            ),
                            false,
                        ),
                    }
                },
            );
        });
    }

    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&adw::HeaderBar::new());
    toolbar.set_content(Some(&page));
    adw::NavigationPage::builder()
        .title(tr!("Change master password"))
        .child(&toolbar)
        .build()
}

fn pin_group(state: &SharedState, toast: &Toaster, unlocked: bool) -> adw::PreferencesGroup {
    let group = adw::PreferencesGroup::builder()
        .title(tr!("PIN on this computer"))
        .description(tr!(
            "Optional. Unlock this computer with a short PIN after an automatic lock or a restart. The vault key is kept in the system keyring, encrypted with the PIN. A PIN is easier to guess than the master password, so anyone with access to your session and keyring could try it; after 5 wrong attempts it is turned off and the master password is required again."
        ))
        .build();
    let status_row = adw::ActionRow::builder()
        .title(tr!("Current state"))
        .build();
    let status_label = gtk::Label::new(None);
    status_label.add_css_class("dim-label");
    status_row.add_suffix(&status_label);
    let render = {
        let state = state.clone();
        move || -> &'static str {
            let persisted = ashypass_core::keyring::is_quick_unlock_stored()
                || state
                    .settings()
                    .quick_unlock
                    .as_ref()
                    .is_some_and(|p| p.is_configured());
            if persisted {
                tr!("On")
            } else if state.vault.borrow().is_quick_unlock_available() {
                tr!("On until Ashy Pass closes")
            } else {
                tr!("Off")
            }
        }
    };
    status_label.set_label(render());
    group.add(&status_row);

    let pin_row = big_gtk_kit::password::password_row(
        adw::PasswordEntryRow::builder()
            .title(tr!("New PIN (at least 4 characters)"))
            .sensitive(unlocked),
    );
    group.add(&pin_row);

    let buttons = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(8)
        .margin_top(8)
        .halign(gtk::Align::End)
        .build();
    let disable = gtk::Button::with_label(tr!("Turn off"));
    let enable = gtk::Button::with_label(tr!("Set PIN"));
    enable.set_sensitive(unlocked);
    buttons.append(&disable);
    buttons.append(&enable);
    group.add(&buttons);

    // The PIN itself is never stored (only the vault key wrapped with it),
    // so there is nothing to show. With a PIN on, the field for a new one
    // stays hidden until the user asks to change it.
    let editing = Rc::new(std::cell::Cell::new(false));
    // Weak: the buttons it updates call it from their own handlers.
    let layout: Rc<dyn Fn()> = {
        let status_row = status_row.downgrade();
        let status_label = status_label.downgrade();
        let pin_row = pin_row.downgrade();
        let enable = enable.downgrade();
        let disable = disable.downgrade();
        let editing = editing.clone();
        let render = render.clone();
        Rc::new(move || {
            let (Some(status_row), Some(status_label), Some(pin_row), Some(enable), Some(disable)) = (
                status_row.upgrade(),
                status_label.upgrade(),
                pin_row.upgrade(),
                enable.upgrade(),
                disable.upgrade(),
            ) else {
                return;
            };
            let label = render();
            status_label.set_label(label);
            let on = label != tr!("Off");
            status_row.set_subtitle(if on {
                tr!("The PIN is not stored anywhere, so it cannot be shown. To change it, set a new one.")
            } else {
                ""
            });
            pin_row.set_visible(!on || editing.get());
            enable.set_label(match (on, editing.get()) {
                (false, _) => tr!("Set PIN"),
                (true, false) => tr!("Change PIN"),
                (true, true) => tr!("Save new PIN"),
            });
            disable.set_sensitive(on);
        })
    };
    layout();

    let notify = {
        let toast = toast.clone();
        move |message: &str| {
            toast.add_toast(
                adw::Toast::builder()
                    .use_markup(false)
                    .title(message)
                    .timeout(4)
                    .build(),
            );
        }
    };
    {
        let state = state.clone();
        let pin_row = pin_row.clone();
        let notify = notify.clone();
        let layout = layout.clone();
        let editing = editing.clone();
        enable.connect_clicked(move |button| {
            if !pin_row.is_visible() {
                // "Change PIN": open the field first.
                editing.set(true);
                layout();
                pin_row.grab_focus();
                return;
            }
            let pin = Zeroizing::new(pin_row.text().to_string());
            let key = match state.vault.borrow().session_reopen_parts() {
                Ok((_, key)) => key,
                Err(_) => {
                    notify(tr!("Unlock the vault first"));
                    return;
                }
            };
            enum Outcome {
                Saved(ashypass_core::crypto::key::DerivedKey),
                Keyring(ashypass_core::Error),
                Failed(ashypass_core::Error),
            }
            // Wrapping the key is deliberately slow and the keyring is a
            // D-Bus round trip: both run on a worker.
            button.set_sensitive(false);
            let state = state.clone();
            let pin_row = pin_row.clone();
            let notify = notify.clone();
            let button = button.clone();
            let layout = layout.clone();
            let editing = editing.clone();
            run_background(
                move || match ashypass_core::db::vault::prepare_quick_unlock(&pin, &key) {
                    Ok(prefs) => match ashypass_core::keyring::store_quick_unlock(&prefs) {
                        Ok(()) => Outcome::Saved(key),
                        Err(e) => Outcome::Keyring(e),
                    },
                    Err(e) => Outcome::Failed(e),
                },
                move |outcome| {
                    button.set_sensitive(true);
                    let result = match outcome {
                        Outcome::Saved(wrapped) => {
                            let cached = state
                                .vault
                                .borrow_mut()
                                .cache_key_for_quick_unlock(&wrapped);
                            // Locked or re-keyed meanwhile: the stored
                            // record must not stay behind.
                            if cached.is_err() {
                                let _ = ashypass_core::keyring::delete_quick_unlock();
                            }
                            cached
                        }
                        Outcome::Keyring(error) => {
                            notify(&format!(
                                "{}: {}",
                                tr!(
                                    "The system keyring is not available, so the PIN was not saved"
                                ),
                                crate::ui::errors::describe(&error)
                            ));
                            return;
                        }
                        Outcome::Failed(e) => Err(e),
                    };
                    match result {
                        Ok(()) => {
                            if let Err(error) = state.update_settings(|s| s.quick_unlock = None) {
                                log::warn!("could not clear legacy quick-unlock state: {error}");
                            }
                            pin_row.set_text("");
                            editing.set(false);
                            layout();
                            notify(tr!("PIN set for this computer"));
                        }
                        Err(ashypass_core::Error::Locked) => notify(tr!("Unlock the vault first")),
                        Err(ashypass_core::Error::InvalidInput(_)) => {
                            notify(tr!("The PIN must have at least 4 characters"))
                        }
                        Err(e) => notify(&format!(
                            "{}: {}",
                            tr!("The PIN was not set"),
                            crate::ui::errors::describe(&e)
                        )),
                    }
                },
            );
        });
    }
    {
        let state = state.clone();
        let editing = editing.clone();
        disable.connect_clicked(move |_| {
            if let Err(error) = ashypass_core::keyring::delete_quick_unlock() {
                notify(&format!(
                    "{}: {}",
                    tr!("Could not turn off the PIN"),
                    crate::ui::errors::describe(&error)
                ));
                return;
            }
            state.vault.borrow_mut().disable_quick_unlock();
            if let Err(error) = state.update_settings(|s| s.quick_unlock = None) {
                log::warn!("could not clear legacy quick-unlock state: {error}");
            }
            editing.set(false);
            layout();
            notify(tr!(
                "PIN turned off. The master password is required to unlock."
            ));
        });
    }
    group
}

fn keyring_group(state: &SharedState, toast: &Toaster) -> adw::PreferencesGroup {
    let group = adw::PreferencesGroup::builder()
        .title(tr!("Open automatically at login"))
        .description(tr!(
            "Keeps the master password in the system keyring (GNOME Keyring, KWallet) so the vault opens by itself when Ashy Pass starts. Anyone who can use your logged-in session can then open the vault. Locking still requires the master password or PIN to unlock again."
        ))
        .build();
    let status_row = adw::ActionRow::builder()
        .title(tr!("Current state"))
        .build();
    let status_label = gtk::Label::new(None);
    status_label.add_css_class("dim-label");
    let render = || {
        if ashypass_core::keyring::is_stored() {
            tr!("On")
        } else {
            tr!("Off")
        }
    };
    status_label.set_label(render());
    status_row.add_suffix(&status_label);
    group.add(&status_row);
    let master_row = big_gtk_kit::password::password_row(
        adw::PasswordEntryRow::builder().title(tr!("Master password")),
    );
    group.add(&master_row);
    let buttons = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(8)
        .margin_top(8)
        .halign(gtk::Align::End)
        .build();
    let remove = gtk::Button::with_label(tr!("Turn off"));
    let store = gtk::Button::with_label(tr!("Turn on"));
    buttons.append(&remove);
    buttons.append(&store);
    group.add(&buttons);
    // The field only confirms the master password when turning this on;
    // once it is on there is nothing to edit there.
    // Weak: the buttons it updates call it from their own handlers.
    let layout: Rc<dyn Fn()> = {
        let status_label = status_label.downgrade();
        let master_row = master_row.downgrade();
        let remove = remove.downgrade();
        let store = store.downgrade();
        Rc::new(move || {
            let (Some(status_label), Some(master_row), Some(remove), Some(store)) = (
                status_label.upgrade(),
                master_row.upgrade(),
                remove.upgrade(),
                store.upgrade(),
            ) else {
                return;
            };
            let on = ashypass_core::keyring::is_stored();
            status_label.set_label(if on { tr!("On") } else { tr!("Off") });
            master_row.set_visible(!on);
            store.set_visible(!on);
            remove.set_sensitive(on);
        })
    };
    layout();
    {
        let state = state.clone();
        let toast = toast.clone();
        let master_row = master_row.clone();
        let layout = layout.clone();
        store.connect_clicked(move |button| {
            let pw = Zeroizing::new(master_row.text().to_string());
            if pw.is_empty() {
                toast.add_toast(
                    adw::Toast::builder()
                        .use_markup(false)
                        .title(tr!("Type the master password first"))
                        .timeout(4)
                        .build(),
                );
                return;
            }
            let Ok(hash) = state.vault.borrow().master_hash() else {
                return;
            };
            // Argon2 verification and the keyring write run on a worker.
            button.set_sensitive(false);
            let toast = toast.clone();
            let master_row = master_row.clone();
            let layout = layout.clone();
            let button = button.clone();
            run_background(
                move || -> Result<bool, String> {
                    if !ashypass_core::crypto::argon2_kdf::verify_master(&pw, &hash)
                        .unwrap_or(false)
                    {
                        return Ok(false);
                    }
                    ashypass_core::keyring::store_master(&pw)
                        .map(|()| true)
                        .map_err(|e| e.to_string())
                },
                move |result| {
                    button.set_sensitive(true);
                    let message = match result {
                        Ok(true) => {
                            master_row.set_text("");
                            layout();
                            tr!("The vault will open automatically at login").to_string()
                        }
                        Ok(false) => tr!("Incorrect master password").to_string(),
                        Err(e) => format!(
                            "{}: {}",
                            tr!("Keyring error"),
                            crate::ui::errors::describe(&e)
                        ),
                    };
                    toast.add_toast(
                        adw::Toast::builder()
                            .use_markup(false)
                            .title(message)
                            .timeout(4)
                            .build(),
                    );
                },
            );
        });
    }
    {
        let toast = toast.clone();
        remove.connect_clicked(move |_| {
            let message = match ashypass_core::keyring::delete_master() {
                Ok(()) => {
                    layout();
                    tr!("Removed from the keyring").to_string()
                }
                Err(e) => format!(
                    "{}: {}",
                    tr!("Keyring error"),
                    crate::ui::errors::describe(&e)
                ),
            };
            toast.add_toast(
                adw::Toast::builder()
                    .use_markup(false)
                    .title(message)
                    .timeout(4)
                    .build(),
            );
        });
    }
    group
}

fn kdf_group(state: &SharedState) -> adw::PreferencesGroup {
    let group = adw::PreferencesGroup::builder()
        .title(tr!("Technical details"))
        .build();
    let expander = adw::ExpanderRow::builder()
        .title(tr!("Key derivation (Argon2id)"))
        .subtitle(tr!("How the master password becomes the encryption key"))
        .build();
    let cipher_row = adw::ActionRow::builder()
        .title(tr!("Encryption"))
        .subtitle(tr!("Every entry is encrypted with AES-256-GCM under a key derived from the master password"))
        .build();
    group.add(&cipher_row);
    let about = adw::ActionRow::builder()
        .title(tr!(
            "Higher costs slow down guessing attacks and also slow down unlocking. Auto-tune picks values for about half a second on this computer."
        ))
        .build();
    about.add_css_class("dim-label");
    expander.add_row(&about);
    let params_row = adw::ActionRow::builder()
        .title(tr!("Current parameters"))
        .build();
    let params_label = gtk::Label::new(None);
    params_label.add_css_class("dim-label");
    params_label.add_css_class("monospace");
    let render = |p: ashypass_core::crypto::autotune::TunedParams| {
        format!(
            "t={} m={} MiB p={}",
            p.t_cost,
            p.m_cost_kib / 1024,
            p.p_cost
        )
    };
    params_label.set_label(&render(state.settings().argon2));
    params_row.add_suffix(&params_label);
    expander.add_row(&params_row);
    let tune_row = adw::ActionRow::builder()
        .title(tr!("Auto-tune"))
        .subtitle(tr!("Measures this computer (about 5 seconds)"))
        .build();
    let tune = gtk::Button::builder()
        .label(tr!("Run"))
        .valign(gtk::Align::Center)
        .build();
    let spinner = gtk::Spinner::builder().visible(false).build();
    tune_row.add_suffix(&spinner);
    tune_row.add_suffix(&tune);
    expander.add_row(&tune_row);
    {
        let state = state.clone();
        tune.connect_clicked(move |button| {
            button.set_sensitive(false);
            spinner.set_visible(true);
            spinner.start();
            let state = state.clone();
            let button = button.clone();
            let spinner = spinner.clone();
            let params_label = params_label.clone();
            run_background(
                || ashypass_core::crypto::autotune::autotune(500, 1_048_576),
                move |tuned| {
                    if let Err(e) = state.update_settings(|s| s.argon2 = tuned) {
                        log::warn!("could not save settings: {e}");
                    }
                    params_label.set_label(&render(tuned));
                    button.set_sensitive(true);
                    spinner.stop();
                    spinner.set_visible(false);
                },
            );
        });
    }
    expander.add_row(&strong_key_row(state));
    group.add(&expander);
    group
}

/// Opt-in switch for the vault key format. Off (the default) keeps the fixed
/// costs every Ashy Pass 3 release opens; on derives the vault key with the
/// auto-tuned costs, which older releases refuse.
fn strong_key_row(state: &SharedState) -> adw::ActionRow {
    use ashypass_core::db::vault::KeyFormat;
    let current = state
        .vault
        .borrow()
        .key_format()
        .unwrap_or(KeyFormat::Compatible);
    let switch = gtk::Switch::builder()
        .active(current == KeyFormat::Strong)
        .valign(gtk::Align::Center)
        .build();
    let row = adw::ActionRow::builder()
        .title(tr!("Use these costs for the vault key"))
        .subtitle(tr!(
            "Stronger against guessing the master password. While this is on, older versions of Ashy Pass cannot open the vault with the master password."
        ))
        .activatable_widget(&switch)
        .build();
    row.add_suffix(&switch);
    row.set_sensitive(state.vault.borrow().is_unlocked());
    let state = state.clone();
    // Set while the code moves the switch, so that is not taken as a request.
    let by_code = Rc::new(std::cell::Cell::new(false));
    // Refuse the change here; it happens only after the master password is
    // confirmed and the vault was encrypted again.
    switch.connect_state_set(move |switch, wanted| {
        if by_code.get() {
            return glib::Propagation::Proceed;
        }
        let wanted = if wanted {
            KeyFormat::Strong
        } else {
            KeyFormat::Compatible
        };
        ask_key_format_change(&state, switch, wanted, by_code.clone());
        glib::Propagation::Stop
    });
    row
}

/// Move `switch` to `on` without asking again.
fn set_switch(switch: &gtk::Switch, on: bool, by_code: &std::cell::Cell<bool>) {
    by_code.set(true);
    big_gtk_kit::switch::set_active(switch, on);
    switch.set_state(on);
    by_code.set(false);
}

fn ask_key_format_change(
    state: &SharedState,
    row: &gtk::Switch,
    wanted: ashypass_core::db::vault::KeyFormat,
    by_code: Rc<std::cell::Cell<bool>>,
) {
    use ashypass_core::db::vault::KeyFormat;
    let dialog = big_gtk_kit::alert::Alert::builder(Some(row))
        .heading(tr!("Change how the vault key is protected?"))
        .body(if wanted == KeyFormat::Strong {
            tr!("Everything in the vault is encrypted again with a key derived using the costs above. Older versions of Ashy Pass will not open the vault with the master password. The PIN must be set up again.")
        } else {
            tr!("Everything in the vault is encrypted again with the standard costs, which every version of Ashy Pass 3 opens. The PIN must be set up again.")
        })
        .close_response("cancel")
        .default_response("change")
        .build();
    dialog.add_response("cancel", tr!("Cancel"));
    dialog.add_response("change", tr!("Encrypt again"));
    dialog.set_response_appearance("change", adw::ResponseAppearance::Suggested);
    let password = big_gtk_kit::password::password_row(
        adw::PasswordEntryRow::builder()
            .title(tr!("Master password"))
            .activates_default(true),
    );
    let list = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .build();
    list.add_css_class("boxed-list");
    list.append(&password);
    dialog.set_extra_child(Some(&list));
    {
        // Cancelled: the switch goes back to what is in effect.
        let row = row.clone();
        let by_code = by_code.clone();
        dialog.connect_response(Some("cancel"), move |_, _| {
            set_switch(&row, row.state(), &by_code);
        });
    }
    {
        // Closed without an answer (the vault locked): same as cancel,
        // unless the change is already running.
        let row = row.clone();
        let by_code = by_code.clone();
        dialog.connect_closed(move |_| {
            if row.is_sensitive() && row.is_active() != row.state() {
                set_switch(&row, row.state(), &by_code);
            }
        });
    }
    let state_cl = state.clone();
    let row_cl = row.clone();
    dialog.connect_response(Some("change"), move |_, _| {
        let state = state_cl.clone();
        let row = row_cl.clone();
        let by_code = by_code.clone();
        let typed = Zeroizing::new(password.text().to_string());
        let Ok(hash) = state.vault.borrow().master_hash() else {
            set_switch(&row, row.state(), &by_code);
            return;
        };
        row.set_sensitive(false);
        toast_near(&row, tr!("Encrypting the vault again…"));
        run_background(
            move || -> ashypass_core::Result<_> {
                if !ashypass_core::crypto::argon2_kdf::verify_master(&typed, &hash)? {
                    return Err(ashypass_core::Error::InvalidMasterPassword);
                }
                ashypass_core::db::vault::prepare_rekey(&typed, wanted)
            },
            move |prepared| {
                row.set_sensitive(true);
                let show = |message: &str| toast_near(&row, message);
                if !state.vault.borrow().is_unlocked() {
                    set_switch(&row, row.state(), &by_code);
                    show(tr!("Unlock the vault first"));
                    return;
                }
                let result = prepared.and_then(|p| state.vault.borrow_mut().apply_rekey(p));
                if result.is_err() {
                    set_switch(&row, row.state(), &by_code);
                }
                match result {
                    Ok(()) => {
                        // The PIN wraps the old key.
                        if let Err(error) = ashypass_core::keyring::delete_quick_unlock() {
                            log::warn!("could not revoke quick-unlock keyring state: {error}");
                        }
                        state.vault.borrow_mut().disable_quick_unlock();
                        if let Err(error) = state.update_settings(|s| s.quick_unlock = None) {
                            log::warn!("could not clear quick-unlock settings: {error}");
                        }
                        set_switch(&row, wanted == KeyFormat::Strong, &by_code);
                        show(tr!(
                            "Vault encrypted again. Set up the PIN again if you used one."
                        ));
                    }
                    Err(ashypass_core::Error::InvalidMasterPassword) => {
                        show(tr!("Incorrect master password. Nothing was changed."));
                    }
                    Err(e) => show(&format!(
                        "{} ({})",
                        tr!("Nothing was changed"),
                        crate::ui::errors::describe(&e)
                    )),
                }
            },
        );
    });
    state.track_sensitive_dialog(&dialog);
    dialog.present();
}

/// A toast on the settings dialog that contains `widget`.
fn toast_near(widget: &impl IsA<gtk::Widget>, message: &str) {
    if let Some(dialog) = widget
        .ancestor(adw::PreferencesDialog::static_type())
        .and_then(|w| w.downcast::<adw::PreferencesDialog>().ok())
    {
        dialog.add_toast(
            adw::Toast::builder()
                .title(message)
                .use_markup(false)
                .timeout(6)
                .build(),
        );
    }
}

/// After a migration from Ashy Pass 2.x a copy of the old vault, protected
/// by the weaker scheme of that version, stays next to the new one. Offer to
/// remove it — never automatically.
fn legacy_backup_group(state: &SharedState, toast: &Toaster) -> Option<adw::PreferencesGroup> {
    let path = state.vault.borrow().legacy_backup_path()?;
    let group = adw::PreferencesGroup::builder()
        .title(tr!("Copy of the vault from Ashy Pass 2"))
        .description(tr!(
            "Kept when your vault was upgraded. It uses the older, weaker protection of version 2. Remove it once you are sure the upgraded vault works."
        ))
        .build();
    let row = adw::ActionRow::builder()
        .title(path.display().to_string())
        .use_markup(false)
        .build();
    let remove = gtk::Button::builder()
        .label(tr!("Remove"))
        .valign(gtk::Align::Center)
        .build();
    remove.add_css_class("destructive-action");
    row.add_suffix(&remove);
    group.add(&row);
    let state = state.clone();
    let toast = toast.clone();
    remove.connect_clicked(move |button| {
        let confirm = big_gtk_kit::alert::Alert::builder(Some(button))
            .heading(tr!("Remove the old copy?"))
            .body(tr!(
                "The file is overwritten and deleted. Your current vault is not affected."
            ))
            .close_response("cancel")
            .default_response("cancel")
            .build();
        confirm.add_response("cancel", tr!("Cancel"));
        confirm.add_response("remove", tr!("Remove"));
        confirm.set_response_appearance("remove", adw::ResponseAppearance::Destructive);
        let state = state.clone();
        let toast = toast.clone();
        let button_cl = button.clone();
        confirm.connect_response(None, move |_, response| {
            if response != "remove" {
                return;
            }
            let message = match state.vault.borrow().remove_legacy_backup() {
                Ok(_) => {
                    button_cl.set_sensitive(false);
                    tr!("Old copy removed").to_string()
                }
                Err(e) => format!(
                    "{}: {}",
                    tr!("Could not remove the old copy"),
                    crate::ui::errors::describe(&e)
                ),
            };
            toast.add_toast(
                adw::Toast::builder()
                    .use_markup(false)
                    .title(message)
                    .timeout(4)
                    .build(),
            );
        });
        confirm.present();
    });
    Some(group)
}

/// The settings dialog `widget` sits in.
fn settings_dialog_of(widget: &impl IsA<gtk::Widget>) -> Option<adw::PreferencesDialog> {
    widget
        .ancestor(adw::PreferencesDialog::static_type())
        .and_downcast::<adw::PreferencesDialog>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saved_custom_durations_are_kept_in_the_choices() {
        assert_eq!(choices_with(300, LOCK_CHOICES), LOCK_CHOICES.to_vec());
        let custom = choices_with(45, LOCK_CHOICES);
        assert!(custom.contains(&45));
        assert!(custom.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn durations_read_in_natural_units() {
        assert_eq!(duration_label(0), "Never");
        assert_eq!(duration_label(30), "30 seconds");
        assert_eq!(duration_label(60), "1 minute");
        assert_eq!(duration_label(900), "15 minutes");
        assert_eq!(duration_label(3600), "1 hour");
        assert_eq!(duration_label(45), "45 seconds");
    }
}
