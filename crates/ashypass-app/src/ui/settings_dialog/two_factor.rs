//! `settings_dialog` — two factor section.

use super::*;

// ---------------------------------------------------------------------------
// Two-Factor (FIDO2 / YubiKey + backup phrase) — task #12
// ---------------------------------------------------------------------------

#[allow(dead_code)]
pub(super) fn populate_two_factor(page: &adw::PreferencesPage, toast: adw::ToastOverlay) {
    use ashypass_core::fido2::{
        generate_backup_phrase, hash_backup_phrase, register, slot_short, Fido2Config, MAX_SLOTS,
    };

    let config = Rc::new(RefCell::new(Fido2Config::load()));

    // --- Security keys
    let keys_group = adw::PreferencesGroup::builder()
        .title(tr!("Security Keys"))
        .description(tr!(
            "Register up to 2 physical FIDO2 authenticators (YubiKey, SoloKey, etc.)"
        ))
        .build();

    let keys_box_holder = Rc::new(RefCell::new(keys_group.clone()));
    let refresh_keys: Rc<dyn Fn()> = {
        let config = config.clone();
        let holder = keys_box_holder.clone();
        let toast = toast.clone();
        Rc::new(move || {
            let group = holder.borrow().clone();
            // Rebuild rows: detach old children, then add fresh ones.
            // adw::PreferencesGroup doesn't expose enumerate; we rebuild by
            // replacing the description text and adding new rows. Since GTK
            // allows duplicate rows, we instead recreate via "remove all" —
            // adw 1.4 doesn't have remove_all, so we attach a Box ourselves
            // below the description as a container we control.
            let _ = group; // placeholder; the dynamic listing happens in `list_box` below.
            let _ = toast;
            let _ = config;
        })
    };
    let _ = refresh_keys;

    // Dynamic listing: a single ListBox we manage ourselves.
    let list_box = gtk::ListBox::new();
    list_box.add_css_class("boxed-list");
    list_box.set_selection_mode(gtk::SelectionMode::None);

    let render_slot: RenderSlot = Rc::new(RefCell::new(None));
    let render = {
        let list_box = list_box.clone();
        let config = config.clone();
        let toast = toast.clone();
        let render_slot = render_slot.clone();
        Rc::new(move || {
            while let Some(child) = list_box.first_child() {
                list_box.remove(&child);
            }
            let cfg = config.borrow().clone();
            if cfg.slots.is_empty() {
                let empty = adw::ActionRow::builder()
                    .title(tr!("No keys registered"))
                    .subtitle(tr!("Plug in your authenticator and click Register"))
                    .build();
                list_box.append(&empty);
            } else {
                for (idx, slot) in cfg.slots.iter().enumerate() {
                    let row = adw::ActionRow::builder()
                        .title(
                            slot.nickname
                                .clone()
                                .unwrap_or_else(|| format!("{} {}", tr!("Key"), idx + 1)),
                        )
                        .subtitle(format!("id: {}", slot_short(slot)))
                        .build();
                    let rm = gtk::Button::builder()
                        .icon_name("user-trash-symbolic")
                        .valign(gtk::Align::Center)
                        .tooltip_text(tr!("Remove"))
                        .build();
                    rm.add_css_class("flat");
                    {
                        let config = config.clone();
                        let toast = toast.clone();
                        let render_slot = render_slot.clone();
                        rm.connect_clicked(move |_| {
                            let mut cfg = config.borrow_mut();
                            if idx < cfg.slots.len() {
                                cfg.slots.remove(idx);
                                if cfg.slots.is_empty() {
                                    cfg.enabled = false;
                                }
                                if let Err(e) = cfg.save() {
                                    show_toast(&toast, &format!("{}: {e}", tr!("Error")));
                                    return;
                                }
                                drop(cfg);
                                show_toast(&toast, tr!("Key removed"));
                                if let Some(cb) = render_slot.borrow().clone() {
                                    (cb)();
                                }
                            }
                        });
                    }
                    row.add_suffix(&rm);
                    list_box.append(&row);
                }
            }
        })
    };
    *render_slot.borrow_mut() = Some(render.clone());
    render();

    let row_holder = adw::PreferencesGroup::new();
    row_holder.add(&list_box);
    keys_group.add(&row_holder);

    let register_btn = gtk::Button::builder()
        .label(tr!("Register Security Key"))
        .halign(gtk::Align::End)
        .margin_top(8)
        .build();
    register_btn.add_css_class("suggested-action");
    register_btn.add_css_class("pill");
    {
        let config = config.clone();
        let toast = toast.clone();
        let render = render.clone();
        register_btn.connect_clicked(move |btn| {
            btn.set_sensitive(false);
            btn.set_label(tr!("Touch your key…"));
            let outcome = register(None, None);
            btn.set_sensitive(true);
            btn.set_label(tr!("Register Security Key"));
            match outcome {
                Ok(slot) => {
                    *config.borrow_mut() = Fido2Config::load();
                    let _ = slot;
                    render();
                    show_toast(&toast, tr!("Key registered"));
                }
                Err(e) => show_toast(&toast, &format!("{}: {e}", tr!("Register failed"))),
            }
        });
    }
    let btn_box = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .margin_top(8)
        .build();
    btn_box.append(&register_btn);
    keys_group.add(&btn_box);

    register_btn.set_sensitive(config.borrow().slots.len() < MAX_SLOTS);
    page.add(&keys_group);

    // --- Backup phrase
    let bp_group = adw::PreferencesGroup::builder()
        .title(tr!("Backup Phrase"))
        .description(tr!(
            "A 12-word BIP-39 phrase to unlock without a security key. Shown once."
        ))
        .build();

    let phrase_row = adw::ActionRow::builder()
        .title(tr!("Backup phrase"))
        .subtitle(match config.borrow().backup_code_hash {
            Some(_) => tr!("Set — generate a new one to replace it"),
            None => tr!("Not set"),
        })
        .build();
    bp_group.add(&phrase_row);

    let gen_btn = gtk::Button::builder()
        .label(tr!("Generate Backup Phrase"))
        .halign(gtk::Align::End)
        .margin_top(8)
        .build();
    gen_btn.add_css_class("pill");
    {
        let config = config.clone();
        let toast = toast.clone();
        let phrase_row = phrase_row.clone();
        gen_btn.connect_clicked(move |btn| {
            let phrase = match generate_backup_phrase() {
                Ok(p) => p,
                Err(e) => {
                    show_toast(&toast, &format!("{}: {e}", tr!("Error")));
                    return;
                }
            };
            let hash = match hash_backup_phrase(&phrase) {
                Ok(h) => h,
                Err(e) => {
                    show_toast(&toast, &format!("{}: {e}", tr!("Error")));
                    return;
                }
            };
            {
                let mut cfg = config.borrow_mut();
                cfg.backup_code_hash = Some(hash);
                if let Err(e) = cfg.save() {
                    show_toast(&toast, &format!("{}: {e}", tr!("Error")));
                    return;
                }
            }
            phrase_row.set_subtitle(tr!("Set — generate a new one to replace it"));
            present_backup_phrase_dialog(btn, &phrase);
        });
    }
    let bp_btn_box = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .margin_top(8)
        .build();
    bp_btn_box.append(&gen_btn);
    bp_group.add(&bp_btn_box);

    page.add(&bp_group);
}

#[allow(dead_code)]
pub(super) fn present_backup_phrase_dialog(anchor: &impl IsA<gtk::Widget>, phrase: &str) {
    let dialog = adw::AlertDialog::builder()
        .heading(tr!("Backup Phrase"))
        .body(tr!(
            "Write these 12 words down and keep them safe. This is the only time they will be shown."
        ))
        .build();
    let body = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .margin_top(12)
        .margin_bottom(12)
        .margin_start(12)
        .margin_end(12)
        .build();
    let label = gtk::Label::builder()
        .label(phrase)
        .wrap(true)
        .selectable(true)
        .build();
    label.add_css_class("monospace");
    label.add_css_class("heading");
    body.append(&label);
    dialog.set_extra_child(Some(&body));
    dialog.add_response("close", tr!("Done"));
    dialog.set_default_response(Some("close"));
    dialog.set_close_response("close");
    dialog.present(Some(anchor));
}

pub(super) fn populate_two_factor_unavailable(page: &adw::PreferencesPage) {
    let group = adw::PreferencesGroup::builder()
        .title(tr!("Security Keys"))
        .description(tr!(
            "Vault FIDO2 protection is unavailable until hardware registration and assertion are fully implemented. Existing configuration is preserved."
        ))
        .build();
    let row = adw::ActionRow::builder()
        .title(tr!("FIDO2 vault protection unavailable"))
        .subtitle(tr!(
            "No security key or recovery phrase changes can be made in this version."
        ))
        .build();
    group.add(&row);
    page.add(&group);
}
