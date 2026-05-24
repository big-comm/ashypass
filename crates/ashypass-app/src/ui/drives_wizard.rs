//! Drive encryption wizard.
//!
//! 4-step `adw::NavigationView` flow that wraps the `ashypass_drives`
//! pipeline. All destructive operations route through a background thread;
//! progress flows back to the main loop via a `glib::MainContext` channel.
//!
//! Pages:
//!   1. `confirm` — device summary + safety reasons + destructive consent
//!   2. `key`     — passphrase × 2 with live strength meter
//!   3. `options` — filesystem / wipe mode / allow-discards
//!   4. `run`     — live progress (`adw::ProgressBar`) + step ticker

use crate::tr;
use adw::prelude::*;
use ashypass_core::strength::legacy_score;
use ashypass_drives::detect::{human_size, Drive};
use ashypass_drives::fs::Filesystem;
use ashypass_drives::passphrase::Passphrase;
use ashypass_drives::pipeline::{
    encrypt_via_helper, unlock_existing, EncryptRequest, Progress, Step,
};
use ashypass_drives::runner::PkexecRunner;
use ashypass_drives::safety;
use ashypass_drives::wipe::WipeMode;
use gtk::glib;
use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;

/// Open the wizard against `drive`. Calls `on_done(success)` when the user
/// finishes or cancels.
pub fn present(parent: &impl IsA<gtk::Window>, drive: Drive, toast: adw::ToastOverlay) {
    let win = adw::Window::builder()
        .transient_for(parent)
        .modal(true)
        .default_width(560)
        .default_height(540)
        .title(tr!("Encrypt Drive"))
        .build();

    let nav = adw::NavigationView::new();
    let drive_rc = Rc::new(drive);
    let state = Rc::new(RefCell::new(WizardState::default()));

    let confirm = build_confirm_page(&nav, drive_rc.clone(), state.clone());
    nav.add(&confirm);
    nav.push_by_tag("confirm");

    win.set_content(Some(&nav));
    win.present();

    // Capture toast for the runner page; closure created later when "Encrypt"
    // is clicked, by which point we'll have a window handle ready.
    let _ = toast;
}

#[derive(Default, Debug)]
struct WizardState {
    passphrase: Option<Passphrase>,
    filesystem: Filesystem,
    wipe_mode: Option<WipeMode>,
    allow_discards: bool,
    label: String,
}

// ─────────────────────────────────────────────────────────────────────────
// Step 1 — confirm
// ─────────────────────────────────────────────────────────────────────────

fn build_confirm_page(
    nav: &adw::NavigationView,
    drive: Rc<Drive>,
    state: Rc<RefCell<WizardState>>,
) -> adw::NavigationPage {
    let page = adw::NavigationPage::builder()
        .tag("confirm")
        .title(tr!("Confirm Device"))
        .build();

    let toolbar = adw::ToolbarView::new();
    let header = adw::HeaderBar::new();
    toolbar.add_top_bar(&header);

    let content = scrollable_column();

    // Big destructive warning at the top.
    let warning = adw::PreferencesGroup::new();
    let warn_row = adw::ActionRow::builder()
        .title(tr!("This will erase everything on the drive"))
        .subtitle(tr!(
            "All partitions, files, and filesystem signatures will be permanently destroyed."
        ))
        .build();
    let warn_icon = gtk::Image::from_icon_name("dialog-warning-symbolic");
    warn_icon.set_icon_size(gtk::IconSize::Large);
    warn_icon.add_css_class("error");
    warn_row.add_prefix(&warn_icon);
    warning.add(&warn_row);
    content.append(&warning);

    // Device details grid.
    let info = adw::PreferencesGroup::builder().title(tr!("Device")).build();
    info.add(&detail_row(tr!("Vendor"), drive.vendor.as_deref().unwrap_or("—")));
    info.add(&detail_row(tr!("Model"), drive.model.as_deref().unwrap_or("—")));
    info.add(&detail_row(tr!("Serial"), drive.serial.as_deref().unwrap_or("—")));
    info.add(&detail_row(tr!("Size"), &human_size(drive.size_bytes)));
    info.add(&detail_row(tr!("Path"), &drive.path));
    if !drive.partitions.is_empty() {
        let parts: Vec<String> = drive
            .partitions
            .iter()
            .map(|p| {
                format!(
                    "{} ({}, {})",
                    p.name,
                    p.fstype.as_deref().unwrap_or("?"),
                    human_size(p.size_bytes)
                )
            })
            .collect();
        info.add(&detail_row(tr!("Will destroy"), &parts.join(", ")));
    }
    content.append(&info);

    // Safety pre-flight check — same `safety::inspect` the CLI uses.
    let safety_group = adw::PreferencesGroup::new();
    let report = safety::inspect(&PathBuf::from(&drive.path), safety::SafetyPolicy::default());
    match &report {
        Ok(r) if r.allow_destructive => {
            let r = adw::ActionRow::builder()
                .title(tr!("Safety checks passed"))
                .build();
            let ok = gtk::Image::from_icon_name("emblem-ok-symbolic");
            ok.add_css_class("success");
            r.add_prefix(&ok);
            safety_group.add(&r);
        }
        Ok(r) => {
            let row = adw::ActionRow::builder()
                .title(tr!("Safety checks failed"))
                .subtitle(r.reasons.join("\n"))
                .build();
            let ic = gtk::Image::from_icon_name("dialog-error-symbolic");
            ic.add_css_class("error");
            row.add_prefix(&ic);
            safety_group.add(&row);
        }
        Err(e) => {
            let row = adw::ActionRow::builder()
                .title(tr!("Safety check error"))
                .subtitle(format!("{e}"))
                .build();
            safety_group.add(&row);
        }
    }
    content.append(&safety_group);

    let actions = button_row();
    let cancel = gtk::Button::with_label(tr!("Cancel"));
    let next = gtk::Button::builder()
        .label(tr!("I understand — Continue"))
        .build();
    next.add_css_class("destructive-action");
    next.add_css_class("pill");
    next.set_sensitive(matches!(&report, Ok(r) if r.allow_destructive));
    actions.append(&cancel);
    actions.append(&next);
    content.append(&actions);

    toolbar.set_content(Some(&content));
    page.set_child(Some(&toolbar));

    {
        let nav_cl = nav.clone();
        cancel.connect_clicked(move |_| {
            if let Some(root) = nav_cl.root().and_downcast::<gtk::Window>() {
                root.close();
            }
        });
    }
    {
        let nav_cl = nav.clone();
        let drive_cl = drive.clone();
        let state_cl = state.clone();
        next.connect_clicked(move |_| {
            let key_page = build_key_page(&nav_cl, drive_cl.clone(), state_cl.clone());
            nav_cl.push(&key_page);
        });
    }

    page
}

// ─────────────────────────────────────────────────────────────────────────
// Step 2 — passphrase
// ─────────────────────────────────────────────────────────────────────────

fn build_key_page(
    nav: &adw::NavigationView,
    drive: Rc<Drive>,
    state: Rc<RefCell<WizardState>>,
) -> adw::NavigationPage {
    let page = adw::NavigationPage::builder()
        .tag("key")
        .title(tr!("Set Passphrase"))
        .build();

    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&adw::HeaderBar::new());
    let content = scrollable_column();

    let group = adw::PreferencesGroup::builder()
        .title(tr!("Passphrase"))
        .description(tr!(
            "At least 8 characters. A four-word passphrase from the EFF wordlist is a strong default."
        ))
        .build();
    let pw = adw::PasswordEntryRow::builder().title(tr!("Passphrase")).build();
    let pw2 = adw::PasswordEntryRow::builder().title(tr!("Repeat")).build();
    group.add(&pw);
    group.add(&pw2);
    content.append(&group);

    let strength_group = adw::PreferencesGroup::new();
    let strength_row = adw::ActionRow::builder().title(tr!("Strength")).build();
    let strength_label = gtk::Label::new(None);
    strength_label.add_css_class("monospace");
    strength_row.add_suffix(&strength_label);
    let bar = gtk::LevelBar::builder()
        .mode(gtk::LevelBarMode::Continuous)
        .min_value(0.0)
        .max_value(100.0)
        .margin_top(6)
        .margin_bottom(6)
        .margin_start(12)
        .margin_end(12)
        .build();
    strength_group.add(&strength_row);
    let strength_box = gtk::Box::new(gtk::Orientation::Vertical, 0);
    strength_box.append(&strength_group);
    strength_box.append(&bar);
    content.append(&strength_box);

    let actions = button_row();
    let back = gtk::Button::with_label(tr!("Back"));
    let next = gtk::Button::builder().label(tr!("Continue")).build();
    next.add_css_class("suggested-action");
    next.add_css_class("pill");
    next.set_sensitive(false);
    actions.append(&back);
    actions.append(&next);
    content.append(&actions);

    toolbar.set_content(Some(&content));
    page.set_child(Some(&toolbar));

    // Live validation: enable Next only when both passphrases match and
    // are ≥ 8 chars; update the strength meter from the first entry.
    {
        let pw_cl = pw.clone();
        let pw2_cl = pw2.clone();
        let next_cl = next.clone();
        let bar_cl = bar.clone();
        let lbl_cl = strength_label.clone();
        let update = Rc::new(move || {
            let s = pw_cl.text();
            let s2 = pw2_cl.text();
            let (score_u8, word) = legacy_score(s.as_str());
            bar_cl.set_value(score_u8 as f64);
            lbl_cl.set_label(word);
            let valid = s.len() >= 8 && s == s2;
            next_cl.set_sensitive(valid);
        });
        let u1 = update.clone();
        pw.connect_changed(move |_| u1());
        let u2 = update.clone();
        pw2.connect_changed(move |_| u2());
    }

    {
        let nav_cl = nav.clone();
        back.connect_clicked(move |_| {
            nav_cl.pop();
        });
    }
    {
        let nav_cl = nav.clone();
        let drive_cl = drive.clone();
        let state_cl = state.clone();
        let pw_cl = pw.clone();
        next.connect_clicked(move |_| {
            state_cl.borrow_mut().passphrase = Some(Passphrase::from_str(pw_cl.text().as_str()));
            let opts_page = build_options_page(&nav_cl, drive_cl.clone(), state_cl.clone());
            nav_cl.push(&opts_page);
        });
    }

    page
}


// ─────────────────────────────────────────────────────────────────────────
// Step 3 — options
// ─────────────────────────────────────────────────────────────────────────

fn build_options_page(
    nav: &adw::NavigationView,
    drive: Rc<Drive>,
    state: Rc<RefCell<WizardState>>,
) -> adw::NavigationPage {
    let page = adw::NavigationPage::builder()
        .tag("options")
        .title(tr!("Options"))
        .build();

    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&adw::HeaderBar::new());
    let content = scrollable_column();

    let label_row = adw::EntryRow::builder().title(tr!("Label")).build();
    label_row.set_text("ashypass");

    let fs_model = gtk::StringList::new(&["ext4", "btrfs", "xfs"]);
    let fs_row = adw::ComboRow::builder()
        .title(tr!("Filesystem"))
        .model(&fs_model)
        .selected(0)
        .build();

    let wipe_model = gtk::StringList::new(&[
        tr!("Encrypted zero (recommended — slow but secure)"),
        tr!("Secure discard (SSD/NVMe only, near-instant)"),
        tr!("Random pass (slowest)"),
        tr!("None — quick, leaves prior data recoverable"),
    ]);
    let wipe_row = adw::ComboRow::builder()
        .title(tr!("Pre-format wipe"))
        .model(&wipe_model)
        .selected(0)
        .build();

    let discards_row = adw::SwitchRow::builder()
        .title(tr!("Allow TRIM through encrypted mapping"))
        .subtitle(tr!(
            "Helps SSD wear-leveling but leaks free-space patterns to the device."
        ))
        .active(false)
        .build();

    let group = adw::PreferencesGroup::new();
    group.add(&label_row);
    group.add(&fs_row);
    group.add(&wipe_row);
    group.add(&discards_row);
    content.append(&group);

    let actions = button_row();
    let back = gtk::Button::with_label(tr!("Back"));
    let go = gtk::Button::with_label(tr!("Encrypt"));
    go.add_css_class("destructive-action");
    go.add_css_class("pill");
    actions.append(&back);
    actions.append(&go);
    content.append(&actions);

    toolbar.set_content(Some(&content));
    page.set_child(Some(&toolbar));

    {
        let nav_cl = nav.clone();
        back.connect_clicked(move |_| {
            nav_cl.pop();
        });
    }
    {
        let nav_cl = nav.clone();
        let state_cl = state.clone();
        let drive_cl = drive.clone();
        go.connect_clicked(move |_| {
            let mut st = state_cl.borrow_mut();
            st.filesystem = match fs_row.selected() {
                1 => Filesystem::Btrfs,
                2 => Filesystem::Xfs,
                _ => Filesystem::Ext4,
            };
            st.wipe_mode = Some(match wipe_row.selected() {
                1 => WipeMode::SecureDiscard,
                2 => WipeMode::Random,
                3 => WipeMode::None,
                _ => WipeMode::EncryptedZero,
            });
            st.allow_discards = discards_row.is_active();
            st.label = label_row.text().to_string();
            drop(st);

            let run = build_run_page(&nav_cl, drive_cl.clone(), state_cl.clone());
            nav_cl.push(&run);
        });
    }

    page
}

// ─────────────────────────────────────────────────────────────────────────
// Step 4 — run / progress
// ─────────────────────────────────────────────────────────────────────────

fn build_run_page(
    nav: &adw::NavigationView,
    drive: Rc<Drive>,
    state: Rc<RefCell<WizardState>>,
) -> adw::NavigationPage {
    let page = adw::NavigationPage::builder()
        .tag("run")
        .title(tr!("Encrypting…"))
        .can_pop(false)
        .build();

    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&adw::HeaderBar::new());
    let content = scrollable_column();

    let status_label = gtk::Label::new(Some(tr!("Preparing…")));
    status_label.add_css_class("title-2");
    status_label.set_xalign(0.0);
    content.append(&status_label);

    let progress = gtk::ProgressBar::builder()
        .show_text(true)
        .text(tr!("…"))
        .margin_top(8)
        .margin_bottom(8)
        .build();
    content.append(&progress);

    // Step ticker.
    let ticker_group = adw::PreferencesGroup::new();
    let step_rows = [
        ("safety", tr!("Safety check")),
        ("wipe", tr!("Wipe device")),
        ("format", tr!("Write LUKS2 header")),
        ("open", tr!("Open encrypted mapping")),
        ("mkfs", tr!("Create filesystem")),
        ("close", tr!("Close mapping")),
    ];
    let mut row_map: std::collections::HashMap<&'static str, adw::ActionRow> =
        std::collections::HashMap::new();
    for (tag, title) in &step_rows {
        let r = adw::ActionRow::builder().title(*title).build();
        let icon = gtk::Image::from_icon_name("content-loading-symbolic");
        icon.add_css_class("dim-label");
        r.add_prefix(&icon);
        ticker_group.add(&r);
        row_map.insert(tag, r);
    }
    content.append(&ticker_group);

    let actions = button_row();
    let close_btn = gtk::Button::with_label(tr!("Close"));
    close_btn.set_sensitive(false);
    actions.append(&close_btn);
    content.append(&actions);

    toolbar.set_content(Some(&content));
    page.set_child(Some(&toolbar));

    // Move state out for the worker thread; runs in background, posts events
    // to the main loop via a glib channel.
    let drive_path = drive.path.clone();
    let total_bytes = drive.size_bytes;
    let st = state.borrow();
    let passphrase = st.passphrase.as_ref().map(|p| p.as_bytes().to_vec());
    let wipe_mode = st.wipe_mode.unwrap_or(WipeMode::EncryptedZero);
    let filesystem = st.filesystem;
    let allow_discards = st.allow_discards;
    let label = if st.label.is_empty() { "ashypass".to_string() } else { st.label.clone() };
    drop(st);

    let Some(passphrase_bytes) = passphrase else {
        status_label.set_label(tr!("Internal error: no passphrase set"));
        return page;
    };

    // Cross-thread channel: worker → main loop. The deprecated
    // `glib::MainContext::channel` was removed in glib 0.20, so we use
    // a standard mpsc channel polled from the main loop via a timeout.
    let (sender, receiver) = std::sync::mpsc::channel::<UiEvent>();

    // Worker thread — runs the whole pipeline through `encrypt_via_helper`,
    // so polkit prompts exactly once when the helper spawns.
    std::thread::spawn(move || {
        let pp = Passphrase::new(passphrase_bytes);
        let req = EncryptRequest {
            device: PathBuf::from(&drive_path),
            label: label.clone(),
            filesystem,
            wipe_mode,
            allow_discards,
        };
        let result = encrypt_via_helper(&req, &pp, |p| {
            let _ = sender.send(UiEvent::Progress(p));
        });
        let _ = sender.send(match result {
            Ok(_) => UiEvent::Done(Ok(label)),
            Err(e) => UiEvent::Done(Err(e.to_string())),
        });
    });

    // Main-loop drain — poll every 80 ms. The timeout source lives until
    // the worker drops its sender, then `try_recv` returns Disconnected
    // and we tear down.
    let row_map = Rc::new(row_map);
    let status_label_cl = status_label.clone();
    let progress_cl = progress.clone();
    let close_btn_cl = close_btn.clone();
    glib::timeout_add_local(std::time::Duration::from_millis(80), move || {
        let mut alive = true;
        loop {
            match receiver.try_recv() {
                Ok(ev) => handle_event(
                    ev,
                    &row_map,
                    &status_label_cl,
                    &progress_cl,
                    &close_btn_cl,
                ),
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    alive = false;
                    break;
                }
            }
        }
        if alive {
            glib::ControlFlow::Continue
        } else {
            glib::ControlFlow::Break
        }
    });

    {
        let nav_cl = nav.clone();
        close_btn.connect_clicked(move |_| {
            if let Some(root) = nav_cl.root().and_downcast::<gtk::Window>() {
                root.close();
            }
        });
    }

    // Silence `total_bytes` unused-warning — it lives only to feed the
    // Wiping event, which already carries its own total.
    let _ = total_bytes;

    page
}

fn handle_event(
    ev: UiEvent,
    row_map: &std::collections::HashMap<&'static str, adw::ActionRow>,
    status_label: &gtk::Label,
    progress: &gtk::ProgressBar,
    close_btn: &gtk::Button,
) {
    match ev {
        UiEvent::Progress(Progress::Started(s)) => {
            if let Some(row) = row_map.get(step_tag(s)) {
                let img = gtk::Image::from_icon_name("content-loading-symbolic");
                img.add_css_class("accent");
                row.remove_css_class("dim-label");
                set_row_prefix(row, &img);
            }
            status_label.set_label(&format!("{}…", step_human(s)));
            if !matches!(s, Step::Wipe) {
                progress.pulse();
            }
        }
        UiEvent::Progress(Progress::Finished(s)) => {
            if let Some(row) = row_map.get(step_tag(s)) {
                let img = gtk::Image::from_icon_name("emblem-ok-symbolic");
                img.add_css_class("success");
                set_row_prefix(row, &img);
            }
        }
        UiEvent::Progress(Progress::Wiping { copied, total }) => {
            let frac = if total == 0 {
                0.0
            } else {
                (copied as f64 / total as f64).clamp(0.0, 1.0)
            };
            progress.set_fraction(frac);
            progress.set_text(Some(&format!(
                "{} / {} · {:.1}%",
                human_size(copied),
                human_size(total),
                frac * 100.0
            )));
        }
        UiEvent::Done(Ok(label)) => {
            status_label.set_label(tr!("Done."));
            progress.set_fraction(1.0);
            progress.set_text(Some(&format!(
                "{}: {}",
                tr!("Encrypted as"),
                label
            )));
            close_btn.set_sensitive(true);
        }
        UiEvent::Done(Err(msg)) => {
            status_label.set_label(&format!("{}: {msg}", tr!("Failed")));
            progress.set_text(Some(tr!("Error")));
            close_btn.set_sensitive(true);
        }
    }
}

enum UiEvent {
    Progress(Progress),
    Done(std::result::Result<String, String>),
}

fn step_tag(s: Step) -> &'static str {
    match s {
        Step::Safety => "safety",
        Step::Wipe => "wipe",
        Step::LuksFormat => "format",
        Step::LuksOpen => "open",
        Step::MkFs => "mkfs",
        Step::LuksClose => "close",
    }
}
fn step_human(s: Step) -> &'static str {
    match s {
        Step::Safety => tr!("Safety check"),
        Step::Wipe => tr!("Wiping device"),
        Step::LuksFormat => tr!("Writing LUKS2 header"),
        Step::LuksOpen => tr!("Opening encrypted mapping"),
        Step::MkFs => tr!("Creating filesystem"),
        Step::LuksClose => tr!("Closing mapping"),
    }
}

/// Present a small modal asking for the passphrase and unlocking the given
/// device on success. `device_path` is something like `/dev/sda` or
/// `/dev/sda1`. `label_hint` seeds the mapper name; falls back to "ashypass".
pub fn present_unlock(
    parent: &impl IsA<gtk::Window>,
    device_path: PathBuf,
    label_hint: Option<String>,
    toast: adw::ToastOverlay,
) {
    let win = adw::Window::builder()
        .transient_for(parent)
        .modal(true)
        .default_width(420)
        .default_height(260)
        .title(tr!("Unlock Drive"))
        .build();

    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&adw::HeaderBar::new());
    let content = scrollable_column();

    let group = adw::PreferencesGroup::builder()
        .title(tr!("Encrypted device"))
        .description(device_path.display().to_string())
        .build();
    let pw = adw::PasswordEntryRow::builder()
        .title(tr!("Passphrase"))
        .build();
    group.add(&pw);
    content.append(&group);

    let status = gtk::Label::new(None);
    status.set_xalign(0.0);
    status.add_css_class("caption");
    content.append(&status);

    let actions = button_row();
    let cancel = gtk::Button::with_label(tr!("Cancel"));
    let unlock = gtk::Button::builder().label(tr!("Unlock")).build();
    unlock.add_css_class("suggested-action");
    unlock.add_css_class("pill");
    actions.append(&cancel);
    actions.append(&unlock);
    content.append(&actions);

    toolbar.set_content(Some(&content));
    win.set_content(Some(&toolbar));
    win.present();

    {
        let win_cl = win.clone();
        cancel.connect_clicked(move |_| win_cl.close());
    }

    {
        let win_cl = win.clone();
        let status_cl = status.clone();
        let pw_cl = pw.clone();
        let toast_cl = toast.clone();
        unlock.connect_clicked(move |btn| {
            let pp_text = pw_cl.text();
            if pp_text.is_empty() {
                status_cl.set_label(tr!("Empty passphrase"));
                return;
            }
            btn.set_sensitive(false);
            status_cl.set_label(tr!("Unlocking…"));

            let (sender, receiver) = std::sync::mpsc::channel::<UnlockResult>();
            let device = device_path.clone();
            let label = label_hint.clone().unwrap_or_else(|| "ashypass".into());
            let pp_bytes = pp_text.as_bytes().to_vec();
            std::thread::spawn(move || {
                let pp = Passphrase::new(pp_bytes);
                let runner = PkexecRunner;
                let r = unlock_existing(&runner, &device, &label, &pp, false);
                let _ = sender.send(match r {
                    Ok(path) => UnlockResult::Ok(path.display().to_string()),
                    Err(e) => UnlockResult::Err(e.to_string()),
                });
            });

            let win_done = win_cl.clone();
            let status_done = status_cl.clone();
            let toast_done = toast_cl.clone();
            let btn_done = btn.clone();
            glib::timeout_add_local(std::time::Duration::from_millis(120), move || {
                match receiver.try_recv() {
                    Ok(UnlockResult::Ok(path)) => {
                        let t = adw::Toast::builder()
                            .title(format!("{}: {path}", tr!("Unlocked at")))
                            .timeout(5)
                            .build();
                        toast_done.add_toast(t);
                        win_done.close();
                        glib::ControlFlow::Break
                    }
                    Ok(UnlockResult::Err(msg)) => {
                        status_done.set_label(&msg);
                        btn_done.set_sensitive(true);
                        glib::ControlFlow::Break
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => glib::ControlFlow::Continue,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => glib::ControlFlow::Break,
                }
            });
        });
    }
}

enum UnlockResult {
    Ok(String),
    Err(String),
}

/// Modal that enrolls a FIDO2 token on an existing LUKS device. Prompts for
/// the current passphrase (needed to authorise the new keyslot), then
/// invokes `systemd-cryptenroll --fido2-device=auto` via `pkexec`. The
/// token-specific dance (touch, optional PIN) is driven by systemd, not us.
pub fn present_enroll_fido2(
    parent: &impl IsA<gtk::Window>,
    device_path: PathBuf,
    toast: adw::ToastOverlay,
) {
    let win = adw::Window::builder()
        .transient_for(parent)
        .modal(true)
        .default_width(440)
        .default_height(360)
        .title(tr!("Enrol FIDO2 Token"))
        .build();

    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&adw::HeaderBar::new());
    let content = scrollable_column();

    let intro = adw::PreferencesGroup::builder()
        .title(tr!("Add a hardware token keyslot"))
        .description(tr!(
            "Insert your FIDO2 token (Yubikey, Nitrokey, etc.) and authorise on \
             the device when prompted. Your current passphrase is required to \
             authorise the new keyslot."
        ))
        .build();
    let device_row = adw::ActionRow::builder()
        .title(tr!("Device"))
        .subtitle(device_path.display().to_string())
        .build();
    intro.add(&device_row);
    content.append(&intro);

    let key_group = adw::PreferencesGroup::new();
    let pw = adw::PasswordEntryRow::builder()
        .title(tr!("Current passphrase"))
        .build();
    key_group.add(&pw);
    content.append(&key_group);

    let opts = adw::PreferencesGroup::new();
    let pin_row = adw::SwitchRow::builder()
        .title(tr!("Require PIN at unlock"))
        .active(true)
        .build();
    let presence_row = adw::SwitchRow::builder()
        .title(tr!("Require user-presence (touch the token)"))
        .active(true)
        .build();
    opts.add(&pin_row);
    opts.add(&presence_row);
    content.append(&opts);

    let status = gtk::Label::new(None);
    status.set_xalign(0.0);
    status.add_css_class("caption");
    content.append(&status);

    let actions = button_row();
    let cancel = gtk::Button::with_label(tr!("Cancel"));
    let go = gtk::Button::with_label(tr!("Enrol"));
    go.add_css_class("suggested-action");
    go.add_css_class("pill");
    actions.append(&cancel);
    actions.append(&go);
    content.append(&actions);

    toolbar.set_content(Some(&content));
    win.set_content(Some(&toolbar));
    win.present();

    {
        let win_cl = win.clone();
        cancel.connect_clicked(move |_| win_cl.close());
    }

    {
        let win_cl = win.clone();
        let status_cl = status.clone();
        let pw_cl = pw.clone();
        let toast_cl = toast.clone();
        go.connect_clicked(move |btn| {
            let text = pw_cl.text();
            if text.is_empty() {
                status_cl.set_label(tr!("Empty passphrase"));
                return;
            }
            btn.set_sensitive(false);
            status_cl.set_label(tr!("Talking to your token… check the device for a touch prompt."));

            let (sender, receiver) = std::sync::mpsc::channel::<UnlockResult>();
            let device = device_path.clone();
            let pp_bytes = text.as_bytes().to_vec();
            let pin = pin_row.is_active();
            let presence = presence_row.is_active();
            std::thread::spawn(move || {
                let pp = Passphrase::new(pp_bytes);
                let runner = PkexecRunner;
                let r = ashypass_drives::luks::enroll_fido2(&runner, &device, &pp, pin, presence);
                let _ = sender.send(match r {
                    Ok(()) => UnlockResult::Ok("ok".into()),
                    Err(e) => UnlockResult::Err(e.to_string()),
                });
            });

            let win_done = win_cl.clone();
            let status_done = status_cl.clone();
            let toast_done = toast_cl.clone();
            let btn_done = btn.clone();
            glib::timeout_add_local(std::time::Duration::from_millis(120), move || {
                match receiver.try_recv() {
                    Ok(UnlockResult::Ok(_)) => {
                        let t = adw::Toast::builder()
                            .title(tr!("FIDO2 keyslot added"))
                            .timeout(5)
                            .build();
                        toast_done.add_toast(t);
                        win_done.close();
                        glib::ControlFlow::Break
                    }
                    Ok(UnlockResult::Err(msg)) => {
                        status_done.set_label(&msg);
                        btn_done.set_sensitive(true);
                        glib::ControlFlow::Break
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => glib::ControlFlow::Continue,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => glib::ControlFlow::Break,
                }
            });
        });
    }
}

fn set_row_prefix(row: &adw::ActionRow, new: &gtk::Image) {
    // ActionRow lacks a "replace prefix" API, so we add the new icon. The
    // old one is left in place but we mute its color via remove_css_class
    // upstream. Visually the new icon sits next to the old one — acceptable
    // for a wizard.
    row.add_prefix(new);
}

// ─────────────────────────────────────────────────────────────────────────
// Layout helpers
// ─────────────────────────────────────────────────────────────────────────

fn scrollable_column() -> gtk::Box {
    let outer = gtk::Box::new(gtk::Orientation::Vertical, 0);
    let scroll = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .vscrollbar_policy(gtk::PolicyType::Automatic)
        .vexpand(true)
        .hexpand(true)
        .build();
    let column = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(18)
        .margin_top(18)
        .margin_bottom(18)
        .margin_start(18)
        .margin_end(18)
        .build();
    scroll.set_child(Some(&column));
    outer.append(&scroll);
    column
}

fn button_row() -> gtk::Box {
    gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(12)
        .halign(gtk::Align::End)
        .margin_top(12)
        .build()
}

fn detail_row(label: &str, value: &str) -> adw::ActionRow {
    let row = adw::ActionRow::builder().title(label).build();
    let v = gtk::Label::builder()
        .label(value)
        .selectable(true)
        .xalign(1.0)
        .build();
    v.add_css_class("monospace");
    v.add_css_class("numeric");
    row.add_suffix(&v);
    row
}
