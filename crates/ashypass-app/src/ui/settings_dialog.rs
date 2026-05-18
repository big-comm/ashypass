//! Preferences dialog — ported from the original `ui/settings_dialog.py`.
//!
//! Pages:
//! - Security: change master password, auto-lock timeout, clipboard auto-clear
//! - Appearance: show favicons toggle
//! - Import/Export: scaffolding for task #10 (CSV / Aegis / andOTP)
//! - Cloud Backup: scaffolding for task #11 (Google Drive)

use crate::session::SessionManager;
use crate::state::SharedState;
use crate::tr;
use adw::prelude::*;
use ashypass_core::config::MIN_MASTER_PASSWORD_LENGTH;
use ashypass_core::settings::Settings;
use gtk::gio;
use std::cell::RefCell;
use std::rc::Rc;

type RenderSlot = Rc<RefCell<Option<Rc<dyn Fn()>>>>;
type NextcloudSyncResult = Result<ashypass_core::sync::SyncReport, String>;
type AuditResult = Result<ashypass_core::audit::Report, String>;

enum NextcloudSyncMessage {
    Progress(ashypass_core::sync::NextcloudSyncProgress),
    Finished(NextcloudSyncResult),
}

#[derive(Clone)]
struct NextcloudProgressUi {
    dialog: adw::Dialog,
    spinner: gtk::Spinner,
    title: gtk::Label,
    detail: gtk::Label,
    progress: gtk::ProgressBar,
}

pub fn present(
    parent: &impl IsA<gtk::Widget>,
    state: SharedState,
    _toast: adw::ToastOverlay,
) {
    let parent_widget = parent.upcast_ref::<gtk::Widget>().clone();
    let dialog_slot: Rc<RefCell<Option<adw::Dialog>>> = Rc::new(RefCell::new(None));
    let toast = adw::ToastOverlay::new();
    let settings = Rc::new(RefCell::new(Settings::load()));

    // Build the 4 preference pages — each is an AdwPreferencesPage so the
    // existing group/row helpers keep their look (with scroll).
    let security_page = adw::PreferencesPage::builder().build();
    populate_security(
        &security_page,
        state.clone(),
        settings.clone(),
        toast.clone(),
        parent_widget.clone(),
        dialog_slot.clone(),
    );
    populate_two_factor(&security_page, toast.clone());
    populate_audit(
        &security_page,
        state.clone(),
        settings.clone(),
        toast.clone(),
    );

    let data_page = adw::PreferencesPage::builder().build();
    populate_import_export(
        &data_page,
        state.clone(),
        toast.clone(),
        parent_widget.clone(),
        dialog_slot.clone(),
    );
    populate_trash(&data_page, state.clone(), settings.clone(), toast.clone());

    let cloud_page = adw::PreferencesPage::builder().build();
    populate_cloud(
        &cloud_page,
        state.clone(),
        toast.clone(),
        parent_widget.clone(),
        dialog_slot.clone(),
    );

    let appearance_page = adw::PreferencesPage::builder().build();
    populate_appearance(&appearance_page, settings);

    // Sidebar + content stack: trades the bottom ViewSwitcherBar for a real
    // left rail (GNOME-Settings style). NavigationSplitView is responsive —
    // collapses to a stack on narrow widths.
    let sections: [(&str, &str, &adw::PreferencesPage); 4] = [
        ("security", "security-high-symbolic", &security_page),
        ("data", "folder-symbolic", &data_page),
        ("cloud", "folder-remote-symbolic", &cloud_page),
        ("appearance", "preferences-desktop-appearance-symbolic", &appearance_page),
    ];
    let labels: [&str; 4] = [
        tr!("Security"),
        tr!("Data"),
        tr!("Cloud"),
        tr!("Appearance"),
    ];

    let stack = adw::ViewStack::new();
    let listbox = gtk::ListBox::new();
    listbox.set_selection_mode(gtk::SelectionMode::Single);
    listbox.add_css_class("navigation-sidebar");

    for (i, (name, icon, page)) in sections.iter().enumerate() {
        stack.add_named(*page, Some(name));

        let row = gtk::ListBoxRow::new();
        let row_box = gtk::Box::new(gtk::Orientation::Horizontal, 12);
        row_box.set_margin_top(8);
        row_box.set_margin_bottom(8);
        row_box.set_margin_start(12);
        row_box.set_margin_end(12);
        let img = gtk::Image::from_icon_name(icon);
        let lbl = gtk::Label::builder()
            .label(labels[i])
            .xalign(0.0)
            .hexpand(true)
            .build();
        row_box.append(&img);
        row_box.append(&lbl);
        row.set_child(Some(&row_box));
        // The stack's child name lives in a widget property so the row-selected
        // handler can map a row back to a page without a parallel array.
        row.set_widget_name(name);
        listbox.append(&row);
    }

    let stack_for_rows = stack.clone();
    listbox.connect_row_selected(move |_, row| {
        if let Some(row) = row {
            stack_for_rows.set_visible_child_name(&row.widget_name());
        }
    });
    if let Some(first) = listbox.row_at_index(0) {
        listbox.select_row(Some(&first));
    }

    let sidebar_scroll = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .vexpand(true)
        .child(&listbox)
        .build();
    let sidebar_toolbar = adw::ToolbarView::new();
    sidebar_toolbar.add_top_bar(&adw::HeaderBar::new());
    sidebar_toolbar.set_content(Some(&sidebar_scroll));

    let content_scroll = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .vexpand(true)
        .hexpand(true)
        .child(&stack)
        .build();
    let content_toolbar = adw::ToolbarView::new();
    content_toolbar.add_top_bar(&adw::HeaderBar::new());
    content_toolbar.set_content(Some(&content_scroll));

    let sidebar_page = adw::NavigationPage::builder()
        .title(tr!("Settings"))
        .child(&sidebar_toolbar)
        .build();
    let content_page = adw::NavigationPage::builder()
        .title(tr!("Settings"))
        .child(&content_toolbar)
        .build();

    let split = adw::NavigationSplitView::new();
    split.set_sidebar(Some(&sidebar_page));
    split.set_content(Some(&content_page));
    split.set_min_sidebar_width(200.0);
    split.set_max_sidebar_width(240.0);
    toast.set_child(Some(&split));

    let dialog = adw::Dialog::builder()
        .title(tr!("Settings"))
        .content_width(960)
        .content_height(680)
        .child(&toast)
        .build();
    *dialog_slot.borrow_mut() = Some(dialog.clone());
    dialog.present(Some(parent));
}

// ---------------------------------------------------------------------------
// Security
// ---------------------------------------------------------------------------

fn populate_security(
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
            if new_pw.len() < MIN_MASTER_PASSWORD_LENGTH {
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
            match state.vault.borrow_mut().change_master_password(&cur_pw, &new_pw) {
                Ok(()) => {
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
            let _ = settings.borrow().save();
            state.session.borrow_mut().timeout_seconds = v.max(15);
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
            let _ = settings.borrow().save();
        });
    }
    timing_group.add(&clip_row);

    page.add(&timing_group);

    // --- Quick-unlock (PIN)
    let qu_group = adw::PreferencesGroup::builder()
        .title(tr!("Quick Unlock"))
        .description(tr!(
            "After auto-lock, unlock with a short PIN instead of the master \
             password. The PIN guards a key cached in memory only — it is \
             discarded when the app closes."
        ))
        .build();

    let pin_row = adw::PasswordEntryRow::builder()
        .title(tr!("New PIN (4+ chars)"))
        .build();
    qu_group.add(&pin_row);

    let qu_status_row = adw::ActionRow::builder()
        .title(tr!("Status"))
        .build();
    let qu_status_lbl = gtk::Label::new(None);
    qu_status_lbl.add_css_class("dim-label");
    let render_qu_status = {
        let state = state.clone();
        move || {
            let v = state.vault.borrow();
            if v.is_quick_unlock_available() {
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
        let pin_row = pin_row.clone();
        let status_lbl = qu_status_lbl.clone();
        let toast = toast.clone();
        let render = render_qu_status.clone();
        qu_enable_btn.connect_clicked(move |_| {
            let pin = pin_row.text().to_string();
            let r = state.vault.borrow_mut().enable_quick_unlock(&pin);
            match r {
                Ok(()) => {
                    pin_row.set_text("");
                    status_lbl.set_label(render());
                    toast.add_toast(adw::Toast::builder()
                        .title(tr!("Quick-unlock enabled"))
                        .timeout(3)
                        .build());
                }
                Err(ashypass_core::Error::Locked) => {
                    toast.add_toast(adw::Toast::builder()
                        .title(tr!("Unlock the vault first"))
                        .timeout(3)
                        .build());
                }
                Err(e) => {
                    toast.add_toast(adw::Toast::builder()
                        .title(format!("{e}"))
                        .timeout(3)
                        .build());
                }
            }
        });
    }
    {
        let state = state.clone();
        let status_lbl = qu_status_lbl.clone();
        let toast = toast.clone();
        let render = render_qu_status.clone();
        qu_disable_btn.connect_clicked(move |_| {
            state.vault.borrow_mut().disable_quick_unlock();
            status_lbl.set_label(render());
            toast.add_toast(adw::Toast::builder()
                .title(tr!("Quick-unlock disabled"))
                .timeout(3)
                .build());
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
        kr_remove_btn.connect_clicked(move |_| {
            match ashypass_core::keyring::delete_master() {
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
            }
        });
    }

    page.add(&kr_group);

    // --- Argon2 KDF tuning
    let kdf_group = adw::PreferencesGroup::builder()
        .title(tr!("Key Derivation (Argon2id)"))
        .description(tr!(
            "Higher costs slow brute force but also slow unlock. \
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
                    let _ = settings.borrow().save();
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

// ---------------------------------------------------------------------------
// Two-Factor (FIDO2 / YubiKey + backup phrase) — task #12
// ---------------------------------------------------------------------------

fn populate_two_factor(page: &adw::PreferencesPage, toast: adw::ToastOverlay) {
    use ashypass_core::fido2::{
        generate_backup_phrase, hash_backup_phrase, register, slot_short, Fido2Config, MAX_SLOTS,
    };

    let config = Rc::new(RefCell::new(Fido2Config::load()));

    // --- Security keys
    let keys_group = adw::PreferencesGroup::builder()
        .title(tr!("Security Keys"))
        .description(tr!(
            "Register up to 2 FIDO2 authenticators (YubiKey, Solo, etc.)"
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

fn present_backup_phrase_dialog(anchor: &impl IsA<gtk::Widget>, phrase: &str) {
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

// ---------------------------------------------------------------------------
// Appearance
// ---------------------------------------------------------------------------

fn populate_appearance(page: &adw::PreferencesPage, settings: Rc<RefCell<Settings>>) {
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
        favicons_row.connect_active_notify(move |row| {
            settings.borrow_mut().show_favicons = row.is_active();
            let _ = settings.borrow().save();
        });
    }
    group.add(&favicons_row);
    page.add(&group);
}

// ---------------------------------------------------------------------------
// Import / Export — scaffold for task #10
// ---------------------------------------------------------------------------

fn populate_import_export(
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
enum ImportKind {
    Csv,
    Aegis,
    Andotp,
    Bitwarden,
    Onepassword,
}

fn import_row(
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

fn show_toast(overlay: &adw::ToastOverlay, message: &str) {
    overlay.add_toast(adw::Toast::builder().title(message).timeout(4).build());
}

fn show_message_dialog(parent: Option<&gtk::Window>, heading: &str, body: &str) {
    let dialog = adw::AlertDialog::builder()
        .heading(heading)
        .body(body)
        .build();
    dialog.add_response("ok", tr!("OK"));
    dialog.set_default_response(Some("ok"));
    dialog.present(parent);
}

fn show_nextcloud_progress_dialog(parent: Option<&gtk::Window>) -> NextcloudProgressUi {
    let dialog = adw::Dialog::builder()
        .title(tr!("Synchronizing Nextcloud"))
        .content_width(420)
        .build();

    let content = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(12)
        .margin_top(24)
        .margin_bottom(24)
        .margin_start(24)
        .margin_end(24)
        .build();

    let spinner = gtk::Spinner::new();
    spinner.set_halign(gtk::Align::Center);
    spinner.start();
    content.append(&spinner);

    let title = gtk::Label::builder()
        .label(tr!("Preparing synchronization"))
        .xalign(0.5)
        .build();
    title.add_css_class("title-3");
    content.append(&title);

    let detail = gtk::Label::builder()
        .label(tr!("Waiting for Nextcloud..."))
        .xalign(0.5)
        .wrap(true)
        .build();
    detail.add_css_class("dim-label");
    content.append(&detail);

    let progress = gtk::ProgressBar::new();
    progress.set_show_text(true);
    progress.set_text(Some(tr!("Starting...")));
    progress.pulse();
    content.append(&progress);

    dialog.set_child(Some(&content));
    dialog.present(parent);

    NextcloudProgressUi {
        dialog,
        spinner,
        title,
        detail,
        progress,
    }
}

fn update_nextcloud_progress(
    ui: &NextcloudProgressUi,
    progress: ashypass_core::sync::NextcloudSyncProgress,
) {
    ui.title.set_text(nextcloud_phase_label(progress.phase));
    if progress.total == 0 {
        ui.detail.set_text(tr!("Waiting for Nextcloud..."));
        ui.progress.set_text(Some(tr!("Working...")));
        ui.progress.pulse();
        return;
    }

    let current = progress.current.min(progress.total);
    let fraction = current as f64 / progress.total as f64;
    let percent = (fraction * 100.0).round() as u8;
    ui.progress.set_fraction(fraction);
    ui.progress.set_text(Some(&format!("{percent}%")));
    ui.detail
        .set_text(&format!("{current}/{} ({percent}%)", progress.total));
}

fn nextcloud_phase_label(phase: ashypass_core::sync::NextcloudSyncPhase) -> &'static str {
    use ashypass_core::sync::NextcloudSyncPhase;
    match phase {
        NextcloudSyncPhase::Preparing => tr!("Preparing synchronization"),
        NextcloudSyncPhase::ApplyingDeletes => tr!("Applying local deletions"),
        NextcloudSyncPhase::FetchingRemote => tr!("Fetching remote passwords"),
        NextcloudSyncPhase::SyncingFolders => tr!("Syncing folders"),
        NextcloudSyncPhase::SyncingLocal => tr!("Sending local changes"),
        NextcloudSyncPhase::PullingRemote => tr!("Downloading remote changes"),
        NextcloudSyncPhase::Finishing => tr!("Finishing synchronization"),
    }
}

fn locked_notice_group(
    state: SharedState,
    toast: adw::ToastOverlay,
    parent: gtk::Widget,
    dialog_slot: Rc<RefCell<Option<adw::Dialog>>>,
) -> adw::PreferencesGroup {
    let group = adw::PreferencesGroup::new();
    let row = adw::ActionRow::builder()
        .title(tr!("Vault must be unlocked to configure"))
        .subtitle(tr!("Unlock Vault"))
        .activatable(true)
        .build();
    row.add_prefix(&gtk::Image::from_icon_name("system-lock-screen-symbolic"));
    row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
    row.connect_activated(move |_| {
        show_settings_unlock_dialog(
            &parent,
            state.clone(),
            toast.clone(),
            dialog_slot.clone(),
        );
    });
    group.add(&row);
    group
}

fn show_settings_unlock_dialog(
    parent: &gtk::Widget,
    state: SharedState,
    toast: adw::ToastOverlay,
    dialog_slot: Rc<RefCell<Option<adw::Dialog>>>,
) {
    let has_master = state.vault.borrow().has_master_password().unwrap_or(false);
    let dialog = adw::AlertDialog::builder()
        .heading(if has_master {
            tr!("Unlock Vault")
        } else {
            tr!("Create Master Password")
        })
        .default_response("unlock")
        .close_response("cancel")
        .build();
    dialog.add_response("cancel", tr!("Cancel"));
    dialog.add_response("unlock", if has_master { tr!("Unlock Vault") } else { tr!("Save") });
    dialog.set_response_appearance("unlock", adw::ResponseAppearance::Suggested);

    let password_row = adw::PasswordEntryRow::builder()
        .title(tr!("Master Password"))
        .build();
    let confirm_row = adw::PasswordEntryRow::builder()
        .title(tr!("Confirm Password"))
        .visible(!has_master)
        .build();
    let list = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .build();
    list.add_css_class("boxed-list");
    list.append(&password_row);
    if !has_master {
        list.append(&confirm_row);
    }
    dialog.set_extra_child(Some(&list));

    {
        let parent = parent.clone();
        let state = state.clone();
        let toast = toast.clone();
        let dialog_slot = dialog_slot.clone();
        dialog.connect_response(None, move |dlg, response| {
            if response != "unlock" {
                return;
            }
            let password = password_row.text().to_string();
            if password.is_empty() {
                password_row.add_css_class("error");
                return;
            }

            let result = if has_master {
                state.vault.borrow_mut().unlock(&password)
            } else {
                if password.chars().count() < MIN_MASTER_PASSWORD_LENGTH {
                    show_toast(&toast, tr!("Password too short"));
                    return;
                }
                if password != confirm_row.text().as_str() {
                    show_toast(&toast, tr!("Passwords do not match"));
                    return;
                }
                state.vault.borrow_mut().set_master_password(&password)
            };

            match result {
                Ok(()) => {
                    SessionManager::login(&state.session);
                    state.events.emit(crate::events::AppEvent::VaultChanged);
                    dlg.close();
                    if let Some(settings_dialog) = dialog_slot.borrow_mut().take() {
                        settings_dialog.close();
                    }
                    present(&parent, state.clone(), toast.clone());
                }
                Err(ashypass_core::Error::InvalidMasterPassword) => {
                    show_toast(&toast, tr!("Incorrect master password"));
                }
                Err(e) => {
                    show_toast(&toast, &format!("{}: {e}", tr!("Failed to unlock vault")));
                }
            }
        });
    }
    dialog.present(Some(parent));
}

fn run_import(
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
    dialog.open(
        parent.as_ref(),
        None::<&gio::Cancellable>,
        move |result| {
            let Ok(file) = result else { return };
            let Some(path) = file.path() else { return };
            let outcome: ashypass_core::Result<usize> = (|| match kind {
                ImportKind::Csv => {
                    let entries = ashypass_core::importers::import_csv(&path)?;
                    ashypass_core::importers::import_csv_entries(&state.vault.borrow(), entries)
                }
                ImportKind::Aegis => {
                    let entries = ashypass_core::importers::aegis::import_plain(&path)?;
                    ashypass_core::importers::import_aegis_entries(
                        &state.vault.borrow(),
                        entries,
                    )
                }
                ImportKind::Andotp => {
                    let entries = ashypass_core::importers::andotp::import_plain(&path)?;
                    ashypass_core::importers::import_andotp_entries(
                        &state.vault.borrow(),
                        entries,
                    )
                }
                ImportKind::Bitwarden => {
                    ashypass_core::importers::bitwarden::import_into_vault(
                        &state.vault.borrow(),
                        &path,
                    )
                }
                ImportKind::Onepassword => {
                    ashypass_core::importers::onepassword::import_into_vault(
                        &state.vault.borrow(),
                        &path,
                    )
                }
            })();
            match outcome {
                Ok(n) => show_toast(&toast, &format!("{} ({n})", tr!("Import complete"))),
                Err(e) => show_toast(&toast, &format!("{}: {e}", tr!("Import failed"))),
            }
        },
    );
}

fn run_export_ashy(state: SharedState, toast: adw::ToastOverlay, anchor: gtk::Widget) {
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
                dialog.save(
                    parent.as_ref(),
                    None::<&gio::Cancellable>,
                    move |result| {
                        let Ok(file) = result else { return };
                        let Some(path) = file.path() else { return };
                        match ashypass_core::importers::ashy::export_vault(
                            &state.vault.borrow(),
                            &path,
                            &password,
                        ) {
                            Ok(n) => show_toast(
                                &toast,
                                &format!("{} ({n})", tr!("Encrypted export complete")),
                            ),
                            Err(e) => {
                                show_toast(&toast, &format!("{}: {e}", tr!("Export failed")))
                            }
                        }
                    },
                );
            }
        },
    );
}

fn run_import_ashy(state: SharedState, toast: adw::ToastOverlay, anchor: gtk::Widget) {
    let dialog = gtk::FileDialog::builder()
        .title(tr!("Open .ashy export"))
        .modal(true)
        .build();
    let parent = anchor.root().and_then(|r| r.downcast::<gtk::Window>().ok());
    let state_cl = state.clone();
    let toast_cl = toast.clone();
    let anchor_cl = anchor.clone();
    dialog.open(
        parent.as_ref(),
        None::<&gio::Cancellable>,
        move |result| {
            let Ok(file) = result else { return };
            let Some(path) = file.path() else { return };
            let state = state_cl.clone();
            let toast = toast_cl.clone();
            let parent_window =
                anchor_cl.root().and_then(|r| r.downcast::<gtk::Window>().ok());
            prompt_password(
                parent_window.as_ref(),
                tr!("Import .ashy"),
                tr!("Enter the password used when this file was exported."),
                false,
                move |password| {
                    match ashypass_core::importers::ashy::import_into_vault(
                        &state.vault.borrow(),
                        &path,
                        &password,
                    ) {
                        Ok(n) => {
                            show_toast(&toast, &format!("{} ({n})", tr!("Import complete")));
                        }
                        Err(e) => {
                            show_toast(&toast, &format!("{}: {e}", tr!("Import failed")));
                        }
                    }
                },
            );
        },
    );
}

fn run_export_kdbx(state: SharedState, toast: adw::ToastOverlay, anchor: gtk::Widget) {
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
                    match ashypass_core::importers::keepass::export_vault(
                        &state.vault.borrow(),
                        &path,
                        &password,
                    ) {
                        Ok(n) => show_toast(
                            &toast,
                            &format!("{} ({n})", tr!("KeePass export complete")),
                        ),
                        Err(e) => show_toast(&toast, &format!("{}: {e}", tr!("Export failed"))),
                    }
                });
            }
        },
    );
}

fn run_import_kdbx(state: SharedState, toast: adw::ToastOverlay, anchor: gtk::Widget) {
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
        let parent_window = anchor_cl.root().and_then(|r| r.downcast::<gtk::Window>().ok());
        prompt_password(
            parent_window.as_ref(),
            tr!("Open KeePass database"),
            tr!("Enter the master password for this .kdbx file."),
            false,
            move |password| {
                match ashypass_core::importers::keepass::import_into_vault(
                    &state.vault.borrow(),
                    &path,
                    &password,
                ) {
                    Ok(n) => show_toast(&toast, &format!("{} ({n})", tr!("Import complete"))),
                    Err(e) => show_toast(&toast, &format!("{}: {e}", tr!("Import failed"))),
                }
            },
        );
    });
}

fn prompt_password<F>(
    parent: Option<&gtk::Window>,
    heading: &str,
    body: &str,
    confirm: bool,
    on_ok: F,
) where
    F: Fn(String) + 'static,
{
    let dialog = adw::AlertDialog::builder().heading(heading).body(body).build();
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

fn run_export_csv(state: SharedState, toast: adw::ToastOverlay, anchor: gtk::Widget) {
    let dialog = gtk::FileDialog::builder()
        .title(tr!("Export vault to CSV"))
        .initial_name("ashypass-export.csv")
        .modal(true)
        .build();

    let parent = anchor.root().and_then(|r| r.downcast::<gtk::Window>().ok());
    dialog.save(
        parent.as_ref(),
        None::<&gio::Cancellable>,
        move |result| {
            let Ok(file) = result else { return };
            let Some(path) = file.path() else { return };
            match ashypass_core::importers::vault_import::export_vault_to_csv(
                &state.vault.borrow(),
                &path,
            ) {
                Ok(n) => show_toast(&toast, &format!("{} ({n})", tr!("Export complete"))),
                Err(e) => show_toast(&toast, &format!("{}: {e}", tr!("Export failed"))),
            }
        },
    );
}

// ---------------------------------------------------------------------------
// Cloud Backup — Google Drive (task #11)
// ---------------------------------------------------------------------------

fn populate_cloud(
    page: &adw::PreferencesPage,
    state: SharedState,
    toast: adw::ToastOverlay,
    parent: gtk::Widget,
    dialog_slot: Rc<RefCell<Option<adw::Dialog>>>,
) {
    let creds = Rc::new(RefCell::new(
        ashypass_core::backup::ClientCredentials::load(),
    ));
    let logged_in = state.backup.borrow().is_logged_in();

    let group = adw::PreferencesGroup::builder()
        .title(tr!("Google Drive"))
        .description(tr!(
            "Encrypted vault uploaded as-is. Folder: \"AshyPass Backups\"."
        ))
        .build();

    let status_row = adw::ActionRow::builder()
        .title(tr!("Status"))
        .subtitle(if logged_in {
            tr!("Signed in")
        } else if creds.borrow().is_none() {
            tr!("Not configured")
        } else {
            tr!("Not signed in")
        })
        .build();
    group.add(&status_row);

    let drive_action_rows: Rc<RefCell<Vec<adw::ActionRow>>> =
        Rc::new(RefCell::new(Vec::new()));
    let google_signin_row: Rc<RefCell<Option<adw::ActionRow>>> = Rc::new(RefCell::new(None));

    let configure_row = adw::ActionRow::builder()
        .title(tr!("Configure Google OAuth"))
        .subtitle(if creds.borrow().is_some() {
            tr!("Configured")
        } else {
            tr!("OAuth client not configured at build time")
        })
        .activatable(true)
        .build();
    configure_row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
    {
        let creds = creds.clone();
        let status = status_row.clone();
        let toast = toast.clone();
        let signin_row = google_signin_row.clone();
        let configure = configure_row.clone();
        configure_row.connect_activated(move |row| {
            let parent = row.root().and_then(|r| r.downcast::<gtk::Window>().ok());
            show_google_oauth_dialog(
                parent.as_ref(),
                creds.clone(),
                status.clone(),
                configure.clone(),
                signin_row.borrow().clone(),
                toast.clone(),
            );
        });
    }
    group.add(&configure_row);

    let signin_row = adw::ActionRow::builder()
        .title(if logged_in {
            tr!("Sign out")
        } else {
            tr!("Sign in to Google")
        })
        .subtitle(tr!("Opens the browser for OAuth consent"))
        .activatable(true)
        .build();
    signin_row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
    signin_row.set_sensitive(logged_in || creds.borrow().is_some());
    *google_signin_row.borrow_mut() = Some(signin_row.clone());
    {
        let state = state.clone();
        let toast = toast.clone();
        let creds = creds.clone();
        let status = status_row.clone();
        let signin = signin_row.clone();
        let action_rows = drive_action_rows.clone();
        signin_row.connect_activated(move |_| {
            if state.backup.borrow().is_logged_in() {
                if let Err(e) = state.backup.borrow_mut().logout() {
                    show_toast(&toast, &format!("{}: {e}", tr!("Sign out failed")));
                    return;
                }
                status.set_subtitle(tr!("Not signed in"));
                signin.set_title(tr!("Sign in to Google"));
                for row in action_rows.borrow().iter() {
                    row.set_sensitive(false);
                }
                show_toast(&toast, tr!("Signed out"));
                return;
            }
            let Some(c) = creds.borrow().clone() else {
                show_toast(&toast, tr!("Not configured"));
                return;
            };
            match state.backup.borrow_mut().login(&c) {
                Ok(()) => {
                    status.set_subtitle(tr!("Signed in"));
                    signin.set_title(tr!("Sign out"));
                    for row in action_rows.borrow().iter() {
                        row.set_sensitive(true);
                    }
                    show_toast(&toast, tr!("Signed in to Google Drive"));
                }
                Err(e) => show_toast(&toast, &format!("{}: {e}", tr!("Sign in failed"))),
            }
        });
    }
    group.add(&signin_row);

    let backup_row = adw::ActionRow::builder()
        .title(tr!("Back up now"))
        .subtitle(tr!("Upload the current vault file to Drive"))
        .activatable(true)
        .build();
    backup_row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
    backup_row.set_sensitive(logged_in);
    drive_action_rows.borrow_mut().push(backup_row.clone());
    {
        let state = state.clone();
        let toast = toast.clone();
        backup_row.connect_activated(move |_| {
            let db_path = ashypass_core::config::database_path();
            let stamp = chrono::Utc::now().format("%Y%m%d-%H%M%S").to_string();
            let name = format!("passwords-{stamp}.db");
            match state.backup.borrow_mut().upload(&db_path, &name) {
                Ok(_id) => show_toast(&toast, tr!("Backup uploaded")),
                Err(e) => show_toast(&toast, &format!("{}: {e}", tr!("Backup failed"))),
            }
        });
    }
    group.add(&backup_row);

    let restore_row = adw::ActionRow::builder()
        .title(tr!("Restore latest"))
        .subtitle(tr!("Downloads the most recent backup as ~/.local/share/ashypass/passwords.restored.db"))
        .activatable(true)
        .build();
    restore_row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
    restore_row.set_sensitive(logged_in);
    drive_action_rows.borrow_mut().push(restore_row.clone());
    {
        let state = state.clone();
        let toast = toast.clone();
        restore_row.connect_activated(move |_| {
            let outcome: ashypass_core::Result<std::path::PathBuf> = (|| {
                let mut svc = state.backup.borrow_mut();
                let files = svc.list_backups()?;
                let latest = files
                    .first()
                    .ok_or(ashypass_core::Error::Other("no backups found".into()))?
                    .clone();
                let dest = ashypass_core::config::data_dir().join("passwords.restored.db");
                svc.download(&latest.id, &dest)?;
                Ok(dest)
            })();
            match outcome {
                Ok(p) => show_toast(
                    &toast,
                    &format!("{}: {}", tr!("Restored to"), p.display()),
                ),
                Err(e) => show_toast(&toast, &format!("{}: {e}", tr!("Restore failed"))),
            }
        });
    }
    group.add(&restore_row);

    page.add(&group);

    page.add(&build_webdav_group(state.clone(), toast.clone()));
    page.add(&build_nextcloud_passwords_group(
        state,
        toast,
        parent,
        dialog_slot,
    ));
}

fn show_google_oauth_dialog(
    parent: Option<&gtk::Window>,
    creds: Rc<RefCell<Option<ashypass_core::backup::ClientCredentials>>>,
    status: adw::ActionRow,
    configure: adw::ActionRow,
    signin_row: Option<adw::ActionRow>,
    toast: adw::ToastOverlay,
) {
    let dialog = adw::AlertDialog::builder()
        .heading(tr!("Configure Google OAuth"))
        .body(tr!("OAuth client not configured at build time"))
        .build();
    dialog.add_response("cancel", tr!("Cancel"));
    dialog.add_response("save", tr!("Save"));
    dialog.set_default_response(Some("save"));
    dialog.set_response_appearance("save", adw::ResponseAppearance::Suggested);

    let client_id = adw::EntryRow::builder().title(tr!("Client ID")).build();
    let client_secret = adw::PasswordEntryRow::builder()
        .title(tr!("Client Secret (optional)"))
        .build();
    if let Some(existing) = creds.borrow().as_ref() {
        client_id.set_text(&existing.client_id);
        if let Some(secret) = existing.client_secret.as_ref() {
            client_secret.set_text(secret);
        }
    }
    let list = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .build();
    list.add_css_class("boxed-list");
    list.append(&client_id);
    list.append(&client_secret);
    dialog.set_extra_child(Some(&list));

    dialog.connect_response(None, move |_dlg, response| {
        if response != "save" {
            return;
        }
        let id = client_id.text().trim().to_string();
        if id.is_empty() {
            client_id.add_css_class("error");
            show_toast(&toast, tr!("All fields are required."));
            return;
        }
        let secret = client_secret.text().trim().to_string();
        let cfg = ashypass_core::backup::ClientCredentials {
            client_id: id,
            client_secret: if secret.is_empty() { None } else { Some(secret) },
        };
        match cfg.save() {
            Ok(()) => {
                *creds.borrow_mut() = Some(cfg);
                status.set_subtitle(tr!("Not signed in"));
                configure.set_subtitle(tr!("Configured"));
                if let Some(row) = signin_row.as_ref() {
                    row.set_sensitive(true);
                }
                show_toast(&toast, tr!("Configured"));
            }
            Err(e) => show_toast(&toast, &format!("{}: {e}", tr!("Configure failed"))),
        }
    });
    dialog.present(parent);
}

fn build_webdav_group(state: SharedState, toast: adw::ToastOverlay) -> adw::PreferencesGroup {
    let logged_in = state.webdav.borrow().is_logged_in();
    let group = adw::PreferencesGroup::builder()
        .title(tr!("WebDAV / Nextcloud"))
        .description(tr!(
            "Encrypted vault uploaded as-is over HTTPS. Works with any RFC 4918 server."
        ))
        .build();

    let status_row = adw::ActionRow::builder()
        .title(tr!("Status"))
        .subtitle(if logged_in { tr!("Configured") } else { tr!("Not configured") })
        .build();
    group.add(&status_row);

    let webdav_action_rows: Rc<RefCell<Vec<adw::ActionRow>>> =
        Rc::new(RefCell::new(Vec::new()));

    let configure_row = adw::ActionRow::builder()
        .title(if logged_in { tr!("Sign out") } else { tr!("Configure WebDAV") })
        .subtitle(tr!("Server URL, username, app-password"))
        .activatable(true)
        .build();
    configure_row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
    {
        let state = state.clone();
        let toast = toast.clone();
        let status = status_row.clone();
        let configure = configure_row.clone();
        let action_rows = webdav_action_rows.clone();
        configure_row.connect_activated(move |row| {
            if state.webdav.borrow().is_logged_in() {
                if let Err(e) = state.webdav.borrow_mut().logout() {
                    show_toast(&toast, &format!("{}: {e}", tr!("Sign out failed")));
                    return;
                }
                status.set_subtitle(tr!("Not configured"));
                configure.set_title(tr!("Configure WebDAV"));
                for row in action_rows.borrow().iter() {
                    row.set_sensitive(false);
                }
                show_toast(&toast, tr!("Signed out"));
                return;
            }
            let parent = row.root().and_then(|r| r.downcast::<gtk::Window>().ok());
            show_webdav_dialog(parent.as_ref(), state.clone(), toast.clone(), {
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
            });
        });
    }
    group.add(&configure_row);

    let backup_row = adw::ActionRow::builder()
        .title(tr!("Back up now"))
        .subtitle(tr!("Upload the current vault file to WebDAV"))
        .activatable(true)
        .build();
    backup_row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
    backup_row.set_sensitive(logged_in);
    webdav_action_rows.borrow_mut().push(backup_row.clone());
    {
        let state = state.clone();
        let toast = toast.clone();
        backup_row.connect_activated(move |_| {
            let db_path = ashypass_core::config::database_path();
            let stamp = chrono::Utc::now().format("%Y%m%d-%H%M%S").to_string();
            let name = format!("passwords-{stamp}.db");
            let svc = state.webdav.borrow();
            if let Err(e) = svc.ensure_folder() {
                show_toast(&toast, &format!("{}: {e}", tr!("Backup failed")));
                return;
            }
            match svc.upload(&db_path, &name) {
                Ok(()) => show_toast(&toast, tr!("Backup uploaded")),
                Err(e) => show_toast(&toast, &format!("{}: {e}", tr!("Backup failed"))),
            }
        });
    }
    group.add(&backup_row);

    // Incremental sync row — uploads an encrypted `.ashy` snapshot named with
    // the local generation counter so concurrent writes from a second machine
    // can be detected before they get clobbered.
    let sync_row = adw::ActionRow::builder()
        .title(tr!("Sync now"))
        .subtitle(tr!(
            "Encrypted snapshot upload with conflict detection"
        ))
        .activatable(true)
        .build();
    sync_row.add_suffix(&gtk::Image::from_icon_name("emblem-synchronizing-symbolic"));
    sync_row.set_sensitive(logged_in);
    webdav_action_rows.borrow_mut().push(sync_row.clone());
    {
        let state = state.clone();
        let toast = toast.clone();
        sync_row.connect_activated(move |row| {
            let parent = row.root().and_then(|r| r.downcast::<gtk::Window>().ok());
            run_webdav_sync(parent.as_ref(), state.clone(), toast.clone(), false);
        });
    }
    group.add(&sync_row);

    let restore_row = adw::ActionRow::builder()
        .title(tr!("Restore latest"))
        .subtitle(tr!(
            "Downloads the most recent backup as ~/.local/share/ashypass/passwords.restored.db"
        ))
        .activatable(true)
        .build();
    restore_row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
    restore_row.set_sensitive(logged_in);
    webdav_action_rows.borrow_mut().push(restore_row.clone());
    {
        let state = state.clone();
        let toast = toast.clone();
        restore_row.connect_activated(move |_| {
            let outcome: ashypass_core::Result<std::path::PathBuf> = (|| {
                let svc = state.webdav.borrow();
                let mut files = svc.list_backups()?;
                files.sort_by(|a, b| b.modified.cmp(&a.modified));
                let latest = files
                    .into_iter()
                    .next()
                    .ok_or(ashypass_core::Error::Other("no backups found".into()))?;
                let dest = ashypass_core::config::data_dir().join("passwords.restored.db");
                svc.download(&latest.href, &dest)?;
                Ok(dest)
            })();
            match outcome {
                Ok(p) => show_toast(
                    &toast,
                    &format!("{}: {}", tr!("Restored to"), p.display()),
                ),
                Err(e) => show_toast(&toast, &format!("{}: {e}", tr!("Restore failed"))),
            }
        });
    }
    group.add(&restore_row);

    group
}

fn show_webdav_dialog<F>(
    parent: Option<&gtk::Window>,
    state: SharedState,
    toast: adw::ToastOverlay,
    on_saved: F,
) where
    F: Fn() + 'static,
{
    let dialog = adw::AlertDialog::builder()
        .heading(tr!("WebDAV / Nextcloud"))
        .body(tr!(
            "For Nextcloud, the base URL looks like https://cloud.example.com/remote.php/dav/files/USERNAME"
        ))
        .build();
    dialog.add_response("cancel", tr!("Cancel"));
    dialog.add_response("save", tr!("Save"));
    dialog.set_default_response(Some("save"));
    dialog.set_response_appearance("save", adw::ResponseAppearance::Suggested);

    let url_row = adw::EntryRow::builder()
        .title(tr!("Server URL"))
        .build();
    let user_row = adw::EntryRow::builder().title(tr!("Username")).build();
    let pass_row = adw::PasswordEntryRow::builder()
        .title(tr!("Password / app-password"))
        .build();
    let folder_row = adw::EntryRow::builder()
        .title(tr!("Folder"))
        .text("AshyPass Backups")
        .build();

    let list = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .build();
    list.add_css_class("boxed-list");
    list.append(&url_row);
    list.append(&user_row);
    list.append(&pass_row);
    list.append(&folder_row);
    dialog.set_extra_child(Some(&list));

    let on_saved = Rc::new(on_saved);
    {
        let url_row = url_row.clone();
        let user_row = user_row.clone();
        let pass_row = pass_row.clone();
        let folder_row = folder_row.clone();
        let state = state.clone();
        let toast = toast.clone();
        let on_saved = on_saved.clone();
        dialog.connect_response(None, move |_dlg, resp| {
            if resp != "save" {
                return;
            }
            let cfg = ashypass_core::backup::WebdavConfig {
                base_url: url_row.text().trim().to_string(),
                username: user_row.text().trim().to_string(),
                password: pass_row.text().to_string(),
                folder: folder_row.text().trim().to_string(),
            };
            if cfg.base_url.is_empty() || cfg.username.is_empty() || cfg.password.is_empty() {
                show_toast(&toast, tr!("URL, username and password are required"));
                return;
            }
            match state.webdav.borrow_mut().login(cfg) {
                Ok(()) => {
                    show_toast(&toast, tr!("WebDAV configured"));
                    on_saved();
                }
                Err(e) => show_toast(&toast, &format!("{}: {e}", tr!("Configure failed"))),
            }
        });
    }
    dialog.present(parent);
}

/// Drive the incremental-sync flow: plan → resolve conflict → upload.
///
/// `force` is `true` when the user has already chosen to overwrite a detected
/// conflict; we re-enter this function from the conflict dialog with `force`
/// set so we can skip the planning step and go straight to upload.
fn run_webdav_sync(
    parent: Option<&gtk::Window>,
    state: SharedState,
    toast: adw::ToastOverlay,
    force: bool,
) {
    use ashypass_core::backup::sync as sync_mod;

    if !force {
        let plan = match sync_mod::plan_push(
            &state.vault.borrow(),
            &state.webdav.borrow(),
        ) {
            Ok(p) => p,
            Err(e) => {
                show_toast(&toast, &format!("{}: {e}", tr!("Sync failed")));
                return;
            }
        };
        match plan.action {
            sync_mod::SyncAction::NoChanges => {
                show_toast(&toast, tr!("Vault already in sync"));
                return;
            }
            sync_mod::SyncAction::Conflict {
                unseen_remote_generation,
            } => {
                show_sync_conflict_dialog(
                    parent,
                    state.clone(),
                    toast.clone(),
                    plan.local_generation,
                    unseen_remote_generation,
                );
                return;
            }
            sync_mod::SyncAction::Ready => {}
        }
    }

    // Try keyring first so users who opted in get a one-click push.
    let master = match ashypass_core::keyring::load_master() {
        Ok(Some(pw)) => Some(pw),
        _ => None,
    };
    if let Some(pw) = master {
        do_webdav_push(state, toast, pw, /*force=*/ force);
        return;
    }

    // Otherwise prompt for the master password.
    prompt_password(
        parent,
        tr!("Master password"),
        tr!("Required to encrypt the snapshot before upload"),
        false,
        {
            let state = state.clone();
            let toast = toast.clone();
            move |pw| {
                let ok = state
                    .vault
                    .borrow()
                    .verify_master_password(&pw)
                    .unwrap_or(false);
                if !ok {
                    show_toast(&toast, tr!("Wrong master password"));
                    return;
                }
                do_webdav_push(state.clone(), toast.clone(), pw, force);
            }
        },
    );
}

fn do_webdav_push(state: SharedState, toast: adw::ToastOverlay, master: String, force: bool) {
    use ashypass_core::backup::sync as sync_mod;
    let outcome = sync_mod::push(
        &state.vault.borrow(),
        &state.webdav.borrow(),
        &master,
        force,
    );
    match outcome {
        Ok(sync_mod::PushOutcome::Uploaded { filename, .. }) => {
            show_toast(&toast, &format!("{}: {filename}", tr!("Snapshot uploaded")));
            state
                .events
                .emit(crate::events::AppEvent::SyncCompleted { filename });
        }
        Ok(sync_mod::PushOutcome::Skipped(_)) => {
            show_toast(&toast, tr!("Vault already in sync"));
        }
        Ok(sync_mod::PushOutcome::Conflict(plan)) => {
            // Should be unreachable with force=true, but stay defensive.
            show_toast(
                &toast,
                &format!(
                    "{}: remote generation {}",
                    tr!("Sync conflict"),
                    plan.remote_max_generation
                ),
            );
            state.events.emit(crate::events::AppEvent::SyncConflict {
                local_generation: plan.local_generation,
                remote_generation: plan.remote_max_generation,
            });
        }
        Err(e) => {
            let msg = format!("{e}");
            show_toast(&toast, &format!("{}: {msg}", tr!("Sync failed")));
            state
                .events
                .emit(crate::events::AppEvent::SyncFailed(msg));
        }
    }
}

fn show_sync_conflict_dialog(
    parent: Option<&gtk::Window>,
    state: SharedState,
    toast: adw::ToastOverlay,
    local_gen: u64,
    remote_gen: u64,
) {
    let dialog = adw::AlertDialog::builder()
        .heading(tr!("Sync conflict detected"))
        .body(format!(
            "{}\n\n{} {local_gen}\n{} {remote_gen}",
            tr!("Another device uploaded a newer snapshot since this device last synced. Uploading now would orphan the remote changes."),
            tr!("This device generation:"),
            tr!("Remote generation:"),
        ))
        .build();
    dialog.add_response("cancel", tr!("Cancel"));
    dialog.add_response("force", tr!("Upload anyway"));
    dialog.set_response_appearance("force", adw::ResponseAppearance::Destructive);
    dialog.set_default_response(Some("cancel"));

    let state = state.clone();
    let toast = toast.clone();
    dialog.connect_response(None, move |dlg, resp| {
        if resp != "force" {
            return;
        }
        let parent = dlg
            .parent()
            .and_then(|w| w.downcast::<gtk::Window>().ok());
        run_webdav_sync(parent.as_ref(), state.clone(), toast.clone(), true);
    });
    dialog.present(parent);
}

// ---------------------------------------------------------------------------
// Nextcloud Passwords — bidirectional sync with the official Nextcloud
// Passwords app via its REST API. Distinct from the WebDAV backup above:
// this reconciles individual entries instead of uploading encrypted blobs.
// ---------------------------------------------------------------------------

fn build_nextcloud_passwords_group(
    state: SharedState,
    toast: adw::ToastOverlay,
    parent: gtk::Widget,
    dialog_slot: Rc<RefCell<Option<adw::Dialog>>>,
) -> adw::PreferencesGroup {
    let logged_in = state.nextcloud.borrow().is_logged_in();
    let group = adw::PreferencesGroup::builder()
        .title(tr!("Nextcloud Passwords"))
        .description(tr!(
            "Two-way sync with the official 'Passwords' app on your Nextcloud server. Use an app password from Settings → Security."
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

    let nextcloud_action_rows: Rc<RefCell<Vec<adw::ActionRow>>> =
        Rc::new(RefCell::new(Vec::new()));

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
        let configure = configure_row.clone();
        let action_rows = nextcloud_action_rows.clone();
        let parent_widget = parent.clone();
        let dialog_slot = dialog_slot.clone();
        configure_row.connect_activated(move |row| {
            if state.nextcloud.borrow().is_logged_in() {
                if let Err(e) = state.nextcloud.borrow_mut().logout() {
                    show_toast(&toast, &format!("{}: {e}", tr!("Sign out failed")));
                    return;
                }
                status.set_subtitle(tr!("Not configured"));
                configure.set_title(tr!("Configure Nextcloud Passwords"));
                for row in action_rows.borrow().iter() {
                    row.set_sensitive(false);
                }
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
            "Two-way reconcile: pull remote, push local, resolve by latest-wins"
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

    group
}

fn show_nextcloud_dialog<F>(
    parent: Option<&gtk::Window>,
    state: SharedState,
    toast: adw::ToastOverlay,
    unlock_parent: gtk::Widget,
    dialog_slot: Rc<RefCell<Option<adw::Dialog>>>,
    on_saved: F,
) where
    F: Fn() + 'static,
{
    let dialog = adw::AlertDialog::builder()
        .heading(tr!("Nextcloud Passwords"))
        .body(tr!(
            "Server URL (e.g. https://cloud.example.com), username and an app password."
        ))
        .build();
    dialog.add_response("cancel", tr!("Cancel"));
    dialog.add_response("save", tr!("Save"));
    dialog.set_default_response(Some("save"));
    dialog.set_response_appearance("save", adw::ResponseAppearance::Suggested);

    let url_row = adw::EntryRow::builder().title(tr!("Server URL")).build();
    let user_row = adw::EntryRow::builder().title(tr!("Username")).build();
    let pass_row = adw::PasswordEntryRow::builder()
        .title(tr!("App password"))
        .build();
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
            match state.nextcloud.borrow_mut().login(cfg) {
                Ok(()) => {
                    show_toast(&toast, tr!("Nextcloud Passwords connected"));
                    on_saved();
                    show_nextcloud_initial_sync_dialog(
                        parent_window.as_ref(),
                        state.clone(),
                        toast.clone(),
                        unlock_parent.clone(),
                        dialog_slot.clone(),
                    );
                }
                Err(e) => show_toast(&toast, &format!("{}: {e}", tr!("Configure failed"))),
            }
        });
    }
    dialog.present(parent);
}

fn show_nextcloud_initial_sync_dialog(
    parent: Option<&gtk::Window>,
    state: SharedState,
    toast: adw::ToastOverlay,
    unlock_parent: gtk::Widget,
    dialog_slot: Rc<RefCell<Option<adw::Dialog>>>,
) {
    if !state.vault.borrow().is_unlocked() {
        show_toast(&toast, tr!("Unlock the vault first"));
        show_settings_unlock_dialog(&unlock_parent, state, toast, dialog_slot);
        return;
    }

    let dialog = adw::AlertDialog::builder()
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
    dialog.present(parent);
}

fn run_nextcloud_sync(
    parent: Option<&gtk::Window>,
    state: SharedState,
    toast: adw::ToastOverlay,
    unlock_parent: Option<gtk::Widget>,
    dialog_slot: Option<Rc<RefCell<Option<adw::Dialog>>>>,
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
            let msg = format!("{}: {e}", tr!("Sync failed"));
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
        })()
        .map_err(|e| e.to_string());
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

fn restore_nextcloud_sync_row(row: &adw::ActionRow) {
    row.set_title(tr!("Sync now"));
    row.set_subtitle(tr!(
        "Two-way reconcile: pull remote, push local, resolve by latest-wins"
    ));
    row.set_sensitive(true);
}

fn finish_nextcloud_sync(
    parent: Option<&gtk::Window>,
    state: SharedState,
    toast: adw::ToastOverlay,
    result: NextcloudSyncResult,
) {
    match result {
        Ok(r) => {
            let s = &r.stats;
            let heading = if s.errors.is_empty() {
                tr!("Sync completed")
            } else {
                tr!("Sync completed with errors")
            };
            show_toast(&toast, heading);
            let mut body = format!(
                "{}\n{}: {}\n{}: {}\n{}: {}\n{}: {}\n{}: {}\n{}: {}",
                tr!("Nextcloud sync finished."),
                tr!("Created locally"),
                s.created_locally,
                tr!("Created on Nextcloud"),
                s.created_remotely,
                tr!("Updated locally"),
                s.updated_locally,
                tr!("Updated on Nextcloud"),
                s.updated_remotely,
                tr!("Deleted on Nextcloud"),
                s.deleted_remotely,
                tr!("Conflicts resolved"),
                s.conflicts,
            );
            if s.skipped_passwordless > 0 {
                let skipped = format!(
                    "{}: {}",
                    tr!("Passwordless entries ignored"),
                    s.skipped_passwordless
                );
                show_toast(&toast, &skipped);
                body.push_str("\n\n");
                body.push_str(&skipped);
                body.push('\n');
                body.push_str(tr!(
                    "Nextcloud requires a filled password, so these local entries were not sent."
                ));
            }
            if !s.errors.is_empty() {
                let head = s.errors.first().cloned().unwrap_or_default();
                let extra = if s.errors.len() > 1 {
                    format!(" (+{} more)", s.errors.len() - 1)
                } else {
                    String::new()
                };
                show_toast(&toast, &format!("{}: {head}{extra}", tr!("Sync errors")));
                body.push_str("\n\n");
                body.push_str(tr!("Sync errors"));
                body.push_str(":\n");
                for err in s.errors.iter().take(5) {
                    body.push_str("- ");
                    body.push_str(err);
                    body.push('\n');
                }
                if s.errors.len() > 5 {
                    body.push_str(&format!("... +{} more", s.errors.len() - 5));
                }
            }
            show_message_dialog(parent, heading, &body);
            state
                .events
                .emit(crate::events::AppEvent::SyncCompleted {
                    filename: "nextcloud".into(),
                });
        }
        Err(e) => {
            let msg = format!("{}: {e}", tr!("Sync failed"));
            show_toast(&toast, &msg);
            show_message_dialog(parent, tr!("Sync failed"), &msg);
            state
                .events
                .emit(crate::events::AppEvent::SyncFailed(e.to_string()));
        }
    }
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

fn populate_audit(
    page: &adw::PreferencesPage,
    state: SharedState,
    settings: Rc<RefCell<Settings>>,
    toast: adw::ToastOverlay,
) {
    let opts_group = adw::PreferencesGroup::builder()
        .title(tr!("Audit Options"))
        .description(tr!(
            "Scan the vault for weak, duplicate, old, breached, and 2FA-less entries."
        ))
        .build();
    let hibp_row = adw::SwitchRow::builder()
        .title(tr!("Check Have I Been Pwned (online)"))
        .subtitle(tr!(
            "Sends only the first 5 hex chars of SHA-1(password) per entry. Cached locally for 7 days."
        ))
        .active(settings.borrow().audit_check_hibp)
        .build();
    {
        let settings = settings.clone();
        hibp_row.connect_active_notify(move |row| {
            settings.borrow_mut().audit_check_hibp = row.is_active();
            let _ = settings.borrow().save();
        });
    }
    opts_group.add(&hibp_row);
    let run_row = adw::ActionRow::builder()
        .title(tr!("Run Audit"))
        .activatable(true)
        .build();
    let run_arrow = gtk::Image::from_icon_name("go-next-symbolic");
    run_row.add_suffix(&run_arrow);
    opts_group.add(&run_row);
    page.add(&opts_group);

    let summary_group = adw::PreferencesGroup::builder().title(tr!("Summary")).build();
    let summary_row = adw::ActionRow::builder()
        .title(tr!("Not run yet"))
        .subtitle("")
        .build();
    summary_group.add(&summary_row);
    page.add(&summary_group);

    let findings_group = adw::PreferencesGroup::builder().title(tr!("Findings")).build();
    page.add(&findings_group);

    let finding_rows: Rc<RefCell<Vec<adw::ActionRow>>> = Rc::new(RefCell::new(Vec::new()));
    let findings_group_cl = findings_group.clone();
    let summary_row_cl = summary_row.clone();
    let hibp_row_cl = hibp_row.clone();
    let finding_rows_cl = finding_rows.clone();
    run_row.connect_activated(move |trigger| {
        if !state.vault.borrow().is_unlocked() {
            show_toast(&toast, tr!("Unlock the vault first"));
            return;
        }
        let state = state.clone();
        let toast = toast.clone();
        let findings_group = findings_group_cl.clone();
        let summary_row = summary_row_cl.clone();
        let hibp_row = hibp_row_cl.clone();
        let finding_rows = finding_rows_cl.clone();
        let trigger = trigger.clone();
        trigger.set_sensitive(false);
        for existing in finding_rows.borrow_mut().drain(..) {
            findings_group.remove(&existing);
        }
        let (db_path, session_key) = match state.vault.borrow().session_reopen_parts() {
            Ok(parts) => parts,
            Err(e) => {
                show_toast(&toast, &format!("{}: {e}", tr!("Audit failed")));
                trigger.set_sensitive(true);
                return;
            }
        };
        let mut opts = ashypass_core::audit::AuditOptions::defaults();
        opts.check_hibp = hibp_row.is_active();
        summary_row.set_title(tr!("Run Audit"));
        summary_row.set_subtitle("");
        show_toast(&toast, tr!("Run Audit"));

        let (sender, receiver) = std::sync::mpsc::channel::<AuditResult>();
        std::thread::spawn(move || {
            let outcome = (|| {
                let vault = ashypass_core::db::Vault::open_with_session_key(db_path, session_key)?;
                ashypass_core::audit::run(&vault, opts)
            })()
            .map_err(|e| e.to_string());
            let _ = sender.send(outcome);
        });

        glib::timeout_add_local(std::time::Duration::from_millis(150), move || {
            match receiver.try_recv() {
                Ok(Ok(report)) => {
                    render_audit_report(
                        &report,
                        &summary_row,
                        &findings_group,
                        &finding_rows,
                        &toast,
                    );
                    trigger.set_sensitive(true);
                    glib::ControlFlow::Break
                }
                Ok(Err(e)) => {
                    show_toast(&toast, &format!("{}: {e}", tr!("Audit failed")));
                    trigger.set_sensitive(true);
                    glib::ControlFlow::Break
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => glib::ControlFlow::Continue,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    show_toast(&toast, tr!("Audit failed"));
                    trigger.set_sensitive(true);
                    glib::ControlFlow::Break
                }
            }
        });
    });
}

fn render_audit_report(
    report: &ashypass_core::audit::Report,
    summary_row: &adw::ActionRow,
    findings_group: &adw::PreferencesGroup,
    finding_rows: &Rc<RefCell<Vec<adw::ActionRow>>>,
    toast: &adw::ToastOverlay,
) {
    summary_row.set_title(&format!(
        "{} {}",
        report.total_entries,
        tr!("entries scanned")
    ));
    summary_row.set_subtitle(&format!(
        "{} {} • {} {} • {} {} • {} {} • {} {}",
        report.count(ashypass_core::audit::IssueKind::Weak),
        tr!("weak"),
        report.count(ashypass_core::audit::IssueKind::Duplicate),
        tr!("duplicate"),
        report.count(ashypass_core::audit::IssueKind::Old),
        tr!("old"),
        report.count(ashypass_core::audit::IssueKind::Breached),
        tr!("breached"),
        report.count(ashypass_core::audit::IssueKind::MissingTotp),
        tr!("no 2FA"),
    ));
    for err in &report.network_errors {
        show_toast(toast, err);
    }
    if report.findings.is_empty() {
        let row = adw::ActionRow::builder()
            .title(tr!("All clear"))
            .subtitle(tr!("No issues found."))
            .build();
        findings_group.add(&row);
        finding_rows.borrow_mut().push(row);
        show_toast(
            toast,
            &format!("{} {}", report.total_entries, tr!("entries scanned")),
        );
        return;
    }
    for f in report.findings.iter().take(200) {
        let issues = f
            .kinds
            .iter()
            .map(|k| match k {
                ashypass_core::audit::IssueKind::Weak => tr!("weak"),
                ashypass_core::audit::IssueKind::Duplicate => tr!("duplicate"),
                ashypass_core::audit::IssueKind::Old => tr!("old"),
                ashypass_core::audit::IssueKind::Breached => tr!("breached"),
                ashypass_core::audit::IssueKind::MissingTotp => tr!("no 2FA"),
            })
            .collect::<Vec<_>>()
            .join(" • ");
        let subtitle = match f.breached_count {
            Some(c) => format!("{issues} ({} ×{c})", tr!("seen")),
            None => issues,
        };
        let row = adw::ActionRow::builder()
            .title(&f.title)
            .subtitle(&subtitle)
            .build();
        let chip = gtk::Label::new(Some(f.strength_label));
        chip.add_css_class("dim-label");
        row.add_suffix(&chip);
        findings_group.add(&row);
        finding_rows.borrow_mut().push(row);
    }
    show_toast(
        toast,
        &format!("{} {}", report.total_entries, tr!("entries scanned")),
    );
}

fn clear_group(group: &adw::PreferencesGroup) {
    while let Some(child) = group.first_child() {
        // The PreferencesGroup wraps its rows in an internal ListBox; finding
        // the actual ListBoxRow and removing via the group's `remove` keeps
        // the layout sane. For non-row children (the internal header), skip.
        if let Some(row) = child.downcast_ref::<adw::PreferencesRow>() {
            group.remove(row);
        } else if let Some(boxw) = child.downcast_ref::<gtk::Box>() {
            // walk into the internal box for ListBoxRow children
            let mut c = boxw.first_child();
            while let Some(node) = c {
                let next = node.next_sibling();
                if let Some(row) = node.downcast_ref::<adw::PreferencesRow>() {
                    group.remove(row);
                }
                c = next;
            }
            break;
        } else {
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Trash
// ---------------------------------------------------------------------------

fn populate_trash(
    page: &adw::PreferencesPage,
    state: SharedState,
    settings: Rc<RefCell<Settings>>,
    toast: adw::ToastOverlay,
) {
    // Retention setting
    let retention_group = adw::PreferencesGroup::builder()
        .title(tr!("Retention"))
        .description(tr!(
            "Deleted entries stay in the trash for this many days, then are \
             permanently removed on next app start. Set 0 to bypass the trash."
        ))
        .build();
    let retention_row = adw::SpinRow::with_range(0.0, 365.0, 1.0);
    retention_row.set_title(tr!("Keep deleted entries for (days)"));
    retention_row.set_value(settings.borrow().trash_retention_days as f64);
    {
        let settings = settings.clone();
        retention_row.connect_value_notify(move |row| {
            settings.borrow_mut().trash_retention_days = row.value() as u32;
            let _ = settings.borrow().save();
        });
    }
    retention_group.add(&retention_row);
    page.add(&retention_group);

    // Listing
    let list_group = adw::PreferencesGroup::builder()
        .title(tr!("Trashed entries"))
        .build();
    page.add(&list_group);

    let list_holder = Rc::new(RefCell::new(list_group.clone()));
    // Self-referential render closure: stored in a RefCell so button handlers
    // built during rendering can re-invoke it once it's installed.
    let render_slot: RenderSlot = Rc::new(RefCell::new(None));
    let render: Rc<dyn Fn()> = {
        let state = state.clone();
        let holder = list_holder.clone();
        let toast = toast.clone();
        let render_slot = render_slot.clone();
        Rc::new(move || {
            let group = holder.borrow().clone();
            clear_group(&group);
            let entries = match state.vault.borrow().list_trash() {
                Ok(v) => v,
                Err(e) => {
                    let row = adw::ActionRow::builder()
                        .title(format!("{e}"))
                        .build();
                    group.add(&row);
                    return;
                }
            };
            if entries.is_empty() {
                let row = adw::ActionRow::builder()
                    .title(tr!("Trash is empty."))
                    .build();
                group.add(&row);
                return;
            }
            for t in entries {
                let when = chrono::DateTime::<chrono::Utc>::from_timestamp(t.deleted_at, 0)
                    .map(|dt| dt.format("%Y-%m-%d %H:%M UTC").to_string())
                    .unwrap_or_default();
                let row = adw::ActionRow::builder()
                    .title(&t.title)
                    .subtitle(format!(
                        "{} — {}",
                        t.username.as_deref().unwrap_or(""),
                        when
                    ))
                    .build();

                let restore_btn = gtk::Button::builder()
                    .icon_name("edit-undo-symbolic")
                    .tooltip_text(tr!("Restore"))
                    .valign(gtk::Align::Center)
                    .build();
                restore_btn.add_css_class("flat");
                let purge_btn = gtk::Button::builder()
                    .icon_name("edit-delete-symbolic")
                    .tooltip_text(tr!("Delete permanently"))
                    .valign(gtk::Align::Center)
                    .build();
                purge_btn.add_css_class("flat");

                {
                    let state = state.clone();
                    let toast = toast.clone();
                    let trash_id = t.trash_id;
                    let render_slot = render_slot.clone();
                    restore_btn.connect_clicked(move |_| {
                        let r = state.vault.borrow().restore_from_trash(trash_id);
                        match r {
                            Ok(Some(_)) => {
                                toast.add_toast(adw::Toast::builder()
                                    .title(tr!("Entry restored"))
                                    .timeout(3)
                                    .build());
                                if let Some(cb) = render_slot.borrow().clone() {
                                    (cb)();
                                }
                            }
                            Ok(None) => {}
                            Err(e) => {
                                toast.add_toast(adw::Toast::builder()
                                    .title(format!("{e}"))
                                    .timeout(3)
                                    .build());
                            }
                        }
                    });
                }
                {
                    let state = state.clone();
                    let toast = toast.clone();
                    let trash_id = t.trash_id;
                    let render_slot = render_slot.clone();
                    purge_btn.connect_clicked(move |_| {
                        let r = state.vault.borrow().delete_from_trash(trash_id);
                        match r {
                            Ok(_) => {
                                toast.add_toast(adw::Toast::builder()
                                    .title(tr!("Permanently deleted"))
                                    .timeout(3)
                                    .build());
                                if let Some(cb) = render_slot.borrow().clone() {
                                    (cb)();
                                }
                            }
                            Err(e) => {
                                toast.add_toast(adw::Toast::builder()
                                    .title(format!("{e}"))
                                    .timeout(3)
                                    .build());
                            }
                        }
                    });
                }

                row.add_suffix(&restore_btn);
                row.add_suffix(&purge_btn);
                group.add(&row);
            }
        })
    };
    *render_slot.borrow_mut() = Some(render.clone());
    (render)();

    let action_group = adw::PreferencesGroup::new();
    let refresh_row = adw::ActionRow::builder()
        .title(tr!("Refresh listing"))
        .activatable(true)
        .build();
    {
        let render = render.clone();
        refresh_row.connect_activated(move |_| (render)());
    }
    action_group.add(&refresh_row);

    let empty_row = adw::ActionRow::builder()
        .title(tr!("Empty trash"))
        .subtitle(tr!("Permanently deletes every trashed entry."))
        .activatable(true)
        .build();
    {
        let state = state.clone();
        let toast = toast.clone();
        let render = render.clone();
        empty_row.connect_activated(move |_| {
            match state.vault.borrow().empty_trash() {
                Ok(n) => {
                    toast.add_toast(adw::Toast::builder()
                        .title(format!("{} {}", n, tr!("entries removed")))
                        .timeout(3)
                        .build());
                    (render)();
                }
                Err(e) => {
                    toast.add_toast(adw::Toast::builder()
                        .title(format!("{e}"))
                        .timeout(3)
                        .build());
                }
            }
        });
    }
    action_group.add(&empty_row);
    page.add(&action_group);
}
