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
    let theme_group = adw::PreferencesGroup::builder().title(tr!("Style")).build();
    let theme_values = ["system", "light", "dark"];
    let theme_model = gtk::StringList::new(&[tr!("Follow the system"), tr!("Light"), tr!("Dark")]);
    let theme_row = adw::ComboRow::builder()
        .title(tr!("Appearance"))
        .model(&theme_model)
        .build();
    let current = settings.borrow().color_scheme.clone();
    theme_row.set_selected(theme_values.iter().position(|v| *v == current).unwrap_or(0) as u32);
    {
        let settings = settings.clone();
        let state_s = state.clone();
        theme_row.connect_selected_notify(move |row| {
            let value = theme_values
                .get(row.selected() as usize)
                .copied()
                .unwrap_or("system");
            let value = value.to_string();
            settings.borrow_mut().color_scheme = value.clone();
            apply_color_scheme(&value);
            // Persist through the shared state: saving this page's snapshot
            // would write back stale values changed on other pages.
            if let Err(e) = state_s.update_settings(|s| s.color_scheme = value) {
                log::warn!("could not save settings: {e}");
            }
        });
    }
    theme_group.add(&theme_row);
    page.add(&theme_group);

    let group = adw::PreferencesGroup::builder()
        .title(tr!("Password list"))
        .build();

    let favicons_row = adw::SwitchRow::builder()
        .title(tr!("Show favicons"))
        .subtitle(tr!("Fetch and display site icons next to vault entries"))
        .active(settings.borrow().show_favicons)
        .build();
    {
        let settings = settings.clone();
        let state_s = state.clone();
        let state = state.clone();
        favicons_row.connect_active_notify(move |row| {
            let value = row.is_active();
            settings.borrow_mut().show_favicons = value;
            // Persist through the shared state: saving this page's snapshot
            // would write back stale values changed on other pages.
            if let Err(e) = state_s.update_settings(|s| s.show_favicons = value) {
                log::warn!("could not save settings: {e}");
            }
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
        let state_s = state.clone();
        let state = state.clone();
        favicon_fallback_row.connect_active_notify(move |row| {
            let value = row.is_active();
            settings.borrow_mut().favicon_third_party_fallback = value;
            // Persist through the shared state: saving this page's snapshot
            // would write back stale values changed on other pages.
            if let Err(e) = state_s.update_settings(|s| s.favicon_third_party_fallback = value) {
                log::warn!("could not save settings: {e}");
            }
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
        .subtitle(tr!(
            "Only when some entries come from Nextcloud Passwords and others do not"
        ))
        .active(settings.borrow().show_sync_badges)
        .build();
    {
        let settings = settings.clone();
        let state_s = state.clone();
        let state = state.clone();
        sync_badges_row.connect_active_notify(move |row| {
            let value = row.is_active();
            settings.borrow_mut().show_sync_badges = value;
            // Persist through the shared state: saving this page's snapshot
            // would write back stale values changed on other pages.
            if let Err(e) = state_s.update_settings(|s| s.show_sync_badges = value) {
                log::warn!("could not save settings: {e}");
            }
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
        let state_s = state.clone();
        let state = state.clone();
        compact_row.connect_active_notify(move |row| {
            let value = row.is_active();
            settings.borrow_mut().compact_vault_list = value;
            // Persist through the shared state: saving this page's snapshot
            // would write back stale values changed on other pages.
            if let Err(e) = state_s.update_settings(|s| s.compact_vault_list = value) {
                log::warn!("could not save settings: {e}");
            }
            state.events.emit(crate::events::AppEvent::VaultChanged);
        });
    }
    group.add(&compact_row);
    page.add(&group);

    let two_factor_group = adw::PreferencesGroup::builder()
        .title(tr!("Verification codes"))
        .build();
    let large_totp_row = adw::SwitchRow::builder()
        .title(tr!("Large verification codes"))
        .subtitle(tr!("Use larger digits for easier reading"))
        .active(settings.borrow().large_totp_codes)
        .build();
    {
        let settings = settings.clone();
        let state_s = state.clone();
        let state = state.clone();
        large_totp_row.connect_active_notify(move |row| {
            let value = row.is_active();
            settings.borrow_mut().large_totp_codes = value;
            // Persist through the shared state: saving this page's snapshot
            // would write back stale values changed on other pages.
            if let Err(e) = state_s.update_settings(|s| s.large_totp_codes = value) {
                log::warn!("could not save settings: {e}");
            }
            state.events.emit(crate::events::AppEvent::VaultChanged);
        });
    }
    two_factor_group.add(&large_totp_row);
    page.add(&two_factor_group);
}

/// Apply "system", "light" or "dark" to the whole app.
pub(crate) fn apply_color_scheme(value: &str) {
    adw::StyleManager::default().set_color_scheme(match value {
        "light" => adw::ColorScheme::ForceLight,
        "dark" => adw::ColorScheme::ForceDark,
        _ => adw::ColorScheme::Default,
    });
}
