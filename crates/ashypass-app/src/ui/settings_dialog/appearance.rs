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

    // Shown passwords: digits and symbols in colour (as in the extension).
    // The row shows a password in the chosen colours; its page, every
    // style on the same random password.
    let colors_row = adw::ActionRow::builder()
        .title(tr!("Password colors"))
        .activatable(true)
        .build();
    let colors_sample = sample_label();
    colors_row.add_suffix(&colors_sample);
    colors_row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
    let sample = Rc::new(RefCell::new(color_sample()));
    let refresh_row: Rc<dyn Fn()> = {
        let (row, label, settings, sample) = (
            colors_row.downgrade(),
            colors_sample.downgrade(),
            settings.clone(),
            sample.clone(),
        );
        Rc::new(move || {
            let (Some(row), Some(label)) = (row.upgrade(), label.upgrade()) else {
                return;
            };
            let id = settings.borrow().password_colors.clone();
            row.set_subtitle(color_name(&id));
            label.set_markup(&sample_markup(&sample.borrow(), &id));
        })
    };
    refresh_row();
    // The colours differ between the light and dark styles.
    {
        let refresh_row = refresh_row.clone();
        let handler = adw::StyleManager::default().connect_dark_notify(move |_| refresh_row());
        let handler = std::cell::Cell::new(Some(handler));
        colors_row.connect_destroy(move |_| {
            if let Some(handler) = handler.take() {
                adw::StyleManager::default().disconnect(handler);
            }
        });
    }
    {
        let settings = settings.clone();
        let state = state.clone();
        colors_row.connect_activated(move |row| {
            let Some(dialog) = row
                .ancestor(adw::PreferencesDialog::static_type())
                .and_downcast::<adw::PreferencesDialog>()
            else {
                return;
            };
            dialog.push_subpage(&password_colors_page(
                settings.clone(),
                state.clone(),
                sample.clone(),
                refresh_row.clone(),
            ));
        });
    }
    theme_group.add(&colors_row);
    page.add(&theme_group);

    let group = adw::PreferencesGroup::builder()
        .title(tr!("Password list"))
        .build();

    let favicons_row = adw::SwitchRow::builder()
        .title(tr!("Show favicons"))
        .subtitle(tr!(
            "Each icon is downloaded from the site itself, which sees your internet address. Sites on your local network are never contacted."
        ))
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
            state.events.emit(crate::events::AppEvent::DisplayChanged);
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
            state.events.emit(crate::events::AppEvent::DisplayChanged);
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
            state.events.emit(crate::events::AppEvent::DisplayChanged);
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
            state.events.emit(crate::events::AppEvent::DisplayChanged);
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
            state.events.emit(crate::events::AppEvent::DisplayChanged);
        });
    }
    two_factor_group.add(&large_totp_row);
    let totp_icons_row = adw::SwitchRow::builder()
        .title(tr!("Show icons beside the codes"))
        .subtitle(tr!("The site's icon, when the code has a site saved"))
        .active(settings.borrow().totp_icons)
        .build();
    {
        let settings = settings.clone();
        let state = state.clone();
        totp_icons_row.connect_active_notify(move |row| {
            let value = row.is_active();
            settings.borrow_mut().totp_icons = value;
            if let Err(e) = state.update_settings(|s| s.totp_icons = value) {
                log::warn!("could not save settings: {e}");
            }
            state.events.emit(crate::events::AppEvent::DisplayChanged);
        });
    }
    two_factor_group.add(&totp_icons_row);
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

/// The ids of the password colour choices, "off" first, in display order.
fn color_ids() -> Vec<&'static str> {
    std::iter::once("off")
        .chain(crate::ui::password_colors::THEMES.iter().map(|t| t.0))
        .collect()
}

fn color_name(id: &str) -> &'static str {
    color_ids()
        .iter()
        .position(|v| *v == id)
        .and_then(|i| i.checked_sub(1))
        .map(|i| crate::ui::password_colors::theme_names()[i])
        .unwrap_or(tr!("No colors"))
}

/// A random password to show the colours on, with a few digits and
/// symbols at least.
fn color_sample() -> String {
    let config = ashypass_core::generator::PasswordConfig::default();
    let enough = |p: &str| {
        p.chars().filter(|c| c.is_ascii_digit()).count() >= 3
            && p.chars().filter(|c| !c.is_alphanumeric()).count() >= 3
    };
    (0..50)
        .filter_map(|_| ashypass_core::generator::generate_password(&config).ok())
        .find(|p| enough(p))
        .unwrap_or_else(|| "x7#Kq2!mZ9$wT4".into())
}

/// `sample` as the password list shows it in colours `id`, monospaced.
fn sample_markup(sample: &str, id: &str) -> String {
    let text = crate::ui::password_colors::markup(sample, id)
        .unwrap_or_else(|| glib::markup_escape_text(sample).to_string());
    format!("<span font_family=\"monospace\" size=\"large\">{text}</span>")
}

/// Where a sample password goes: a row suffix (the row's subtitle would
/// dim the colours).
fn sample_label() -> gtk::Label {
    let label = gtk::Label::builder().valign(gtk::Align::Center).build();
    label.set_accessible_role(gtk::AccessibleRole::Presentation);
    label
}

/// Every password colour style, each on the same random password.
fn password_colors_page(
    settings: Rc<RefCell<Settings>>,
    state: SharedState,
    sample: Rc<RefCell<String>>,
    refresh_row: Rc<dyn Fn()>,
) -> adw::NavigationPage {
    let page = adw::PreferencesPage::new();
    let group = adw::PreferencesGroup::builder()
        .description(tr!("Digits and symbols in color, easier to read and type"))
        .build();
    let another = gtk::Button::builder()
        .icon_name("view-refresh-symbolic")
        .tooltip_text(tr!("Another example"))
        .valign(gtk::Align::Center)
        .build();
    another.add_css_class("flat");
    group.set_header_suffix(Some(&another));

    let mut rows = Vec::new();
    for id in color_ids() {
        let row = adw::ActionRow::builder()
            .title(color_name(id))
            .activatable(true)
            .build();
        let label = sample_label();
        row.add_suffix(&label);
        let check = gtk::Image::from_icon_name("object-select-symbolic");
        // Keep the samples aligned whether or not the check shows.
        let check_slot = gtk::Box::builder().width_request(16).build();
        check_slot.append(&check);
        row.add_suffix(&check_slot);
        group.add(&row);
        rows.push((id, label, check));
    }
    let rows = Rc::new(rows);
    let refresh: Rc<dyn Fn()> = {
        let (rows, settings, sample) = (rows.clone(), settings.clone(), sample.clone());
        Rc::new(move || {
            let current = settings.borrow().password_colors.clone();
            for (id, label, check) in rows.iter() {
                label.set_markup(&sample_markup(&sample.borrow(), id));
                check.set_visible(*id == current);
            }
        })
    };
    refresh();
    for (id, label, _) in rows.iter() {
        let Some(row) = label
            .ancestor(adw::ActionRow::static_type())
            .and_downcast::<adw::ActionRow>()
        else {
            continue;
        };
        let id = id.to_string();
        let (settings, state, refresh, refresh_row) = (
            settings.clone(),
            state.clone(),
            refresh.clone(),
            refresh_row.clone(),
        );
        row.connect_activated(move |_| {
            settings.borrow_mut().password_colors = id.clone();
            let value = id.clone();
            if let Err(e) = state.update_settings(|s| s.password_colors = value) {
                log::warn!("could not save settings: {e}");
            }
            state.events.emit(crate::events::AppEvent::DisplayChanged);
            refresh();
            refresh_row();
        });
    }
    {
        let (sample, refresh, refresh_row) = (sample.clone(), refresh.clone(), refresh_row.clone());
        another.connect_clicked(move |_| {
            *sample.borrow_mut() = color_sample();
            refresh();
            refresh_row();
        });
    }
    {
        let refresh = refresh.clone();
        let handler = adw::StyleManager::default().connect_dark_notify(move |_| refresh());
        let handler = std::cell::Cell::new(Some(handler));
        page.connect_destroy(move |_| {
            if let Some(handler) = handler.take() {
                adw::StyleManager::default().disconnect(handler);
            }
        });
    }
    page.add(&group);

    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&adw::HeaderBar::new());
    toolbar.set_content(Some(&page));
    adw::NavigationPage::builder()
        .title(tr!("Password colors"))
        .child(&toolbar)
        .build()
}
