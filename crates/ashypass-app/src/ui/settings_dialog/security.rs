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
    if seconds % 3600 == 0 {
        let hours = (seconds / 3600) as usize;
        return trn!("{} hour", "{} hours", hours).replace("{}", &hours.to_string());
    }
    if seconds % 60 == 0 {
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
    dialog: adw::PreferencesDialog,
    dialog_slot: Rc<RefCell<Option<adw::Dialog>>>,
) {
    let unlocked = state.vault.borrow().is_unlocked();
    if !unlocked {
        page.add(&locked_notice_group(
            state.clone(),
            toast.clone(),
            dialog.clone().upcast(),
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
        let dialog = dialog.clone();
        change_row.connect_activated(move |_| {
            dialog.push_subpage(&change_master_page(&state, &toast, &dialog));
        });
    }
    master_group.add(&change_row);
    page.add(&master_group);

    // --- Auto-lock -------------------------------------------------------
    let lock_group = adw::PreferencesGroup::builder()
        .title(tr!("Automatic lock"))
        .build();
    {
        let state_cl = state.clone();
        let row = duration_row(
            tr!("Lock after inactivity"),
            Some(tr!(
                "A warning appears before it locks, with time to keep using it"
            )),
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
    let current_row = adw::PasswordEntryRow::builder()
        .title(tr!("Current master password"))
        .build();
    let new_row = adw::PasswordEntryRow::builder()
        .title(tr!("New master password"))
        .build();
    let confirm_row = adw::PasswordEntryRow::builder()
        .title(tr!("Confirm new master password"))
        .build();
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
        let dialog = dialog.clone();
        button.connect_clicked(move |button| {
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
            button.set_sensitive(false);
            let result = state
                .vault
                .borrow_mut()
                .change_master_password(&current, &new);
            button.set_sensitive(true);
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
                    toast.add_toast(
                        adw::Toast::builder()
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
                    &format!("{} ({e})", tr!("The password was not changed")),
                    false,
                ),
            }
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

    let pin_row = adw::PasswordEntryRow::builder()
        .title(tr!("New PIN (at least 6 characters)"))
        .sensitive(unlocked)
        .build();
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

    let notify = {
        let toast = toast.clone();
        move |message: &str| {
            toast.add_toast(adw::Toast::builder().title(message).timeout(4).build());
        }
    };
    {
        let state = state.clone();
        let pin_row = pin_row.clone();
        let status_label = status_label.clone();
        let render = render.clone();
        let notify = notify.clone();
        enable.connect_clicked(move |_| {
            let pin = Zeroizing::new(pin_row.text().to_string());
            let result = state
                .vault
                .borrow_mut()
                .enable_persistent_quick_unlock(&pin);
            match result {
                Ok(prefs) => {
                    if let Err(error) = ashypass_core::keyring::store_quick_unlock(&prefs) {
                        state.vault.borrow_mut().disable_quick_unlock();
                        notify(&format!(
                            "{}: {error}",
                            tr!("The system keyring is not available, so the PIN was not saved")
                        ));
                        return;
                    }
                    if let Err(error) = state.update_settings(|s| s.quick_unlock = None) {
                        log::warn!("could not clear legacy quick-unlock state: {error}");
                    }
                    pin_row.set_text("");
                    status_label.set_label(render());
                    notify(tr!("PIN set for this computer"));
                }
                Err(ashypass_core::Error::Locked) => notify(tr!("Unlock the vault first")),
                Err(ashypass_core::Error::InvalidInput(_)) => {
                    notify(tr!("The PIN must have at least 6 characters"))
                }
                Err(e) => notify(&format!("{}: {e}", tr!("The PIN was not set"))),
            }
        });
    }
    {
        let state = state.clone();
        let status_label = status_label.clone();
        disable.connect_clicked(move |_| {
            if let Err(error) = ashypass_core::keyring::delete_quick_unlock() {
                notify(&format!("{}: {error}", tr!("Could not turn off the PIN")));
                return;
            }
            state.vault.borrow_mut().disable_quick_unlock();
            if let Err(error) = state.update_settings(|s| s.quick_unlock = None) {
                log::warn!("could not clear legacy quick-unlock state: {error}");
            }
            status_label.set_label(render());
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
    let master_row = adw::PasswordEntryRow::builder()
        .title(tr!("Master password"))
        .build();
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
    {
        let state = state.clone();
        let toast = toast.clone();
        let master_row = master_row.clone();
        let status_label = status_label.clone();
        store.connect_clicked(move |_| {
            let pw = Zeroizing::new(master_row.text().to_string());
            let message = if pw.is_empty() {
                tr!("Type the master password first").to_string()
            } else if !state
                .vault
                .borrow()
                .verify_master_password(&pw)
                .unwrap_or(false)
            {
                tr!("Incorrect master password").to_string()
            } else {
                match ashypass_core::keyring::store_master(&pw) {
                    Ok(()) => {
                        master_row.set_text("");
                        status_label.set_label(render());
                        tr!("The vault will open automatically at login").to_string()
                    }
                    Err(e) => format!("{}: {e}", tr!("Keyring error")),
                }
            };
            toast.add_toast(adw::Toast::builder().title(message).timeout(4).build());
        });
    }
    {
        let toast = toast.clone();
        let status_label = status_label.clone();
        remove.connect_clicked(move |_| {
            let message = match ashypass_core::keyring::delete_master() {
                Ok(()) => {
                    status_label.set_label(render());
                    tr!("Removed from the keyring").to_string()
                }
                Err(e) => format!("{}: {e}", tr!("Keyring error")),
            };
            toast.add_toast(adw::Toast::builder().title(message).timeout(4).build());
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
    let about = adw::ActionRow::builder()
        .title(tr!(
            "Higher costs slow down guessing attacks and also slow down unlocking. Auto-tune picks values for about half a second on this computer; they apply the next time the master password is set or changed."
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
    group.add(&expander);
    let keys = adw::ActionRow::builder()
        .title(tr!("Security keys (FIDO2)"))
        .subtitle(tr!(
            "Not available for the vault yet. External drives can use them."
        ))
        .build();
    group.add(&keys);
    group
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
        let confirm = adw::AlertDialog::builder()
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
                Err(e) => format!("{}: {e}", tr!("Could not remove the old copy")),
            };
            toast.add_toast(adw::Toast::builder().title(message).timeout(4).build());
        });
        confirm.present(Some(button));
    });
    Some(group)
}

pub(super) fn populate_browser(page: &adw::PreferencesPage, state: SharedState) {
    let group = adw::PreferencesGroup::builder()
        .title(tr!("Browser extension"))
        .description(tr!(
            "When on, the Ashy Pass browser extension can read vault entries by unlocking from the system keyring, even while this window is locked. The key is dropped again after the auto-lock delay."
        ))
        .build();
    let row = adw::SwitchRow::builder()
        .title(tr!("Allow the browser extension"))
        .subtitle(tr!("Answer requests from the installed extension"))
        .active(state.settings().browser_integration)
        .build();
    row.connect_active_notify(move |row| {
        let active = row.is_active();
        if let Err(e) = state.update_settings(|s| s.browser_integration = active) {
            log::warn!("could not save settings: {e}");
        }
    });
    group.add(&row);
    page.add(&group);
    let how = adw::PreferencesGroup::builder()
        .title(tr!("Connecting the extension"))
        .description(tr!(
            "Install the extension in Chrome or Firefox, then register this computer with:  ashypass-native-host --install <extension-id>"
        ))
        .build();
    page.add(&how);
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
