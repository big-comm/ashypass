//! `settings_dialog` — appearance section.

use super::*;

// ---------------------------------------------------------------------------
// Appearance
// ---------------------------------------------------------------------------

pub(super) fn populate_appearance(
    page: &adw::PreferencesPage,
    settings: Rc<RefCell<Settings>>,
    state: SharedState,
) {
    let group = adw::PreferencesGroup::builder()
        .title(tr!("Vault List"))
        .build();

    let favicons_row = adw::SwitchRow::builder()
        .title(tr!("Show favicons"))
        .subtitle(tr!("Fetch and display site icons next to vault entries"))
        .active(settings.borrow().show_favicons)
        .build();
    {
        let settings = settings.clone();
        let state = state.clone();
        favicons_row.connect_active_notify(move |row| {
            settings.borrow_mut().show_favicons = row.is_active();
            save_settings(&settings.borrow());
            state.events.emit(crate::events::AppEvent::VaultChanged);
        });
    }
    group.add(&favicons_row);

    let favicon_fallback_row = adw::SwitchRow::builder()
        .title(tr!("Use Google as favicon fallback"))
        .subtitle(tr!(
            "Sends the site's address to Google when it serves no icon of its own"
        ))
        .active(settings.borrow().favicon_third_party_fallback)
        .build();
    {
        let settings = settings.clone();
        let state = state.clone();
        favicon_fallback_row.connect_active_notify(move |row| {
            settings.borrow_mut().favicon_third_party_fallback = row.is_active();
            save_settings(&settings.borrow());
            state.events.emit(crate::events::AppEvent::VaultChanged);
        });
    }
    favicons_row
        .bind_property("active", &favicon_fallback_row, "sensitive")
        .sync_create()
        .build();
    group.add(&favicon_fallback_row);

    let sync_badges_row = adw::SwitchRow::builder()
        .title(tr!("Show Nextcloud badges"))
        .subtitle(tr!("Mark entries that are linked to Nextcloud Passwords"))
        .active(settings.borrow().show_sync_badges)
        .build();
    {
        let settings = settings.clone();
        let state = state.clone();
        sync_badges_row.connect_active_notify(move |row| {
            settings.borrow_mut().show_sync_badges = row.is_active();
            save_settings(&settings.borrow());
            state.events.emit(crate::events::AppEvent::VaultChanged);
        });
    }
    group.add(&sync_badges_row);

    let compact_row = adw::SwitchRow::builder()
        .title(tr!("Compact vault list"))
        .subtitle(tr!("Use tighter spacing for long password lists"))
        .active(settings.borrow().compact_vault_list)
        .build();
    {
        let settings = settings.clone();
        let state = state.clone();
        compact_row.connect_active_notify(move |row| {
            settings.borrow_mut().compact_vault_list = row.is_active();
            save_settings(&settings.borrow());
            state.events.emit(crate::events::AppEvent::VaultChanged);
        });
    }
    group.add(&compact_row);
    page.add(&group);

    let two_factor_group = adw::PreferencesGroup::builder()
        .title(tr!("2FA Codes"))
        .build();
    let large_totp_row = adw::SwitchRow::builder()
        .title(tr!("Large 2FA codes"))
        .subtitle(tr!("Use larger digits for easier reading"))
        .active(settings.borrow().large_totp_codes)
        .build();
    {
        let settings = settings.clone();
        large_totp_row.connect_active_notify(move |row| {
            settings.borrow_mut().large_totp_codes = row.is_active();
            save_settings(&settings.borrow());
        });
    }
    two_factor_group.add(&large_totp_row);
    page.add(&two_factor_group);
}
