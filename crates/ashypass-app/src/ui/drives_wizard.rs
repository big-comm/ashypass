//! Drive encryption wizard.
//!
//! 4-step `adw::NavigationView` flow that wraps the `ashypass_drives`
//! pipeline. All destructive operations route through a background thread;
//! progress flows back to the main loop via a `glib::MainContext` channel.
//!
//! Pages:
//!   1. `confirm` — device summary + safety reasons + typed destructive
//!      consent (last 4 characters of the serial, or the device path)
//!   2. `key`     — passphrase × 2 with live strength meter
//!   3. `options` — filesystem / wipe mode / allow-discards
//!   4. `run`     — live progress (`adw::ProgressBar`) + step ticker

use crate::tr;
use adw::prelude::*;
use ashypass_core::strength::legacy_score;
use ashypass_drives::detect::{human_size, Drive};
use ashypass_drives::fs::Filesystem;
use ashypass_drives::helper_client::HelperClient;
use ashypass_drives::passphrase::Passphrase;
use ashypass_drives::pipeline::{
    encrypt_via_helper, unlock_via_helper, EncryptRequest, Progress, Step,
};
use ashypass_drives::safety::{self, DeviceIdentity, SafetyReport};
use ashypass_drives::validate::{check_label_for_fs, LabelError};
use ashypass_drives::wipe::WipeMode;
use gtk::glib;
use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::rc::Rc;

/// User-facing text for a drive operation error. A dismissed polkit prompt
/// is not a failure worth a technical message.
pub(super) fn describe_error(error: &ashypass_drives::Error) -> String {
    match error {
        ashypass_drives::Error::AuthCancelled => tr!("Authentication was cancelled").to_string(),
        other => other.to_string(),
    }
}

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

    // Closing the window does not stop the worker thread or the helper, so
    // it would hide a half-written drive. Refuse while the pipeline runs.
    {
        let running = state.borrow().running.clone();
        win.connect_close_request(move |_| {
            if running.get() {
                glib::Propagation::Stop
            } else {
                glib::Propagation::Proceed
            }
        });
    }

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
    /// Stable path (`/dev/disk/by-id/...`) pinned by the confirm-page safety
    /// check; used for the destructive run instead of `/dev/sdX`.
    pinned_device: Option<PathBuf>,
    /// Identity from the confirm-page inspection (includes the by-id link);
    /// every destructive helper request is checked against it.
    expected: Option<DeviceIdentity>,
    /// True while the encryption pipeline runs; blocks closing the window.
    running: Rc<Cell<bool>>,
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
    let info = adw::PreferencesGroup::builder()
        .title(tr!("Device"))
        .build();
    info.add(&detail_row(
        tr!("Vendor"),
        drive.vendor.as_deref().unwrap_or("—"),
    ));
    info.add(&detail_row(
        tr!("Model"),
        drive.model.as_deref().unwrap_or("—"),
    ));
    info.add(&detail_row(
        tr!("Serial"),
        drive.serial.as_deref().unwrap_or("—"),
    ));
    info.add(&detail_row(tr!("Size"), &human_size(drive.size_bytes)));
    info.add(&detail_row(tr!("Path"), &drive.path));
    if drive.volumes().next().is_some() {
        let parts: Vec<String> = drive
            .volumes()
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

    // Safety pre-flight check — same `safety::inspect` the CLI uses — plus a
    // check that the device behind the path is still the one listed above.
    // It runs `lsblk` and walks sysfs, so it runs off the main loop; the
    // confirmation entry stays disabled until it passes.
    let safety_group = adw::PreferencesGroup::new();
    let checking_row = adw::ActionRow::builder()
        .title(tr!("Checking the drive…"))
        .build();
    checking_row.add_prefix(&gtk::Spinner::builder().spinning(true).build());
    safety_group.add(&checking_row);
    content.append(&safety_group);

    // Typed confirmation: the destructive button stays disabled until the
    // user types something only visible on this page for *this* drive.
    let token = ConfirmToken::for_drive(&drive);
    let confirm_group = adw::PreferencesGroup::builder()
        .title(tr!("Confirm"))
        .description(match token {
            ConfirmToken::SerialSuffix(_) => {
                tr!("Type the last 4 characters of the serial number shown above.")
            }
            ConfirmToken::Path(_) => tr!("Type the device path shown above."),
        })
        .build();
    let confirm_entry = adw::EntryRow::builder()
        .title(match token {
            ConfirmToken::SerialSuffix(_) => tr!("Last 4 characters of the serial"),
            ConfirmToken::Path(_) => tr!("Device path"),
        })
        .build();
    confirm_group.add(&confirm_entry);
    content.append(&confirm_group);

    let actions = button_row();
    let cancel = gtk::Button::with_label(tr!("Cancel"));
    let next = gtk::Button::builder()
        .label(tr!("I understand — Continue"))
        .build();
    next.add_css_class("destructive-action");
    next.add_css_class("pill");
    next.set_sensitive(false);
    let safe = Rc::new(Cell::new(false));
    confirm_entry.set_sensitive(false);
    {
        let next_cl = next.clone();
        let safe_cl = safe.clone();
        confirm_entry.connect_changed(move |entry| {
            next_cl.set_sensitive(safe_cl.get() && token.matches(entry.text().as_str()));
        });
    }
    {
        let snapshot = (*drive).clone();
        let safety_group = safety_group.clone();
        let confirm_entry = confirm_entry.clone();
        let state = state.clone();
        super::settings_dialog::run_background(
            move || inspect_confirmed(&snapshot),
            move |report| {
                safety_group.remove(&checking_row);
                let passed = show_safety_result(&safety_group, &report);
                if let Ok(r) = &report {
                    let mut st = state.borrow_mut();
                    st.pinned_device = Some(r.canonical_path.clone());
                    st.expected = Some(r.identity());
                }
                safe.set(passed);
                confirm_entry.set_sensitive(passed);
            },
        );
    }
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

/// Inspect the drive the user picked and check that the device behind its
/// path is still the one listed. Blocking; runs on a worker thread.
fn inspect_confirmed(snapshot: &Drive) -> ashypass_drives::Result<SafetyReport> {
    let report = safety::inspect(
        &PathBuf::from(&snapshot.path),
        safety::SafetyPolicy::default(),
    )?;
    DeviceIdentity::of(snapshot).check_unchanged(&report.identity())?;
    Ok(report)
}

/// Outcome of the confirm-page safety check.
#[derive(Debug, PartialEq, Eq)]
enum SafetyVerdict {
    Passed,
    /// One or more guards refused; the reasons, one per line.
    Refused(String),
    /// Safe, but there is no `/dev/disk/by-id` link to pin the drive with.
    /// The helper would refuse it after the passphrase step, so stop here.
    NoStableLink,
    Error(String),
}

fn safety_verdict(report: &ashypass_drives::Result<SafetyReport>) -> SafetyVerdict {
    match report {
        Ok(r) if !r.allow_destructive => SafetyVerdict::Refused(r.reasons.join("\n")),
        Ok(r) if !r.pinned_by_id() => SafetyVerdict::NoStableLink,
        Ok(_) => SafetyVerdict::Passed,
        Err(e) => SafetyVerdict::Error(e.to_string()),
    }
}

/// Render the safety verdict into `group`. Returns true when the drive may
/// be encrypted.
fn show_safety_result(
    group: &adw::PreferencesGroup,
    report: &ashypass_drives::Result<SafetyReport>,
) -> bool {
    let verdict = safety_verdict(report);
    let passed = verdict == SafetyVerdict::Passed;
    let (title, subtitle, icon, class) = match verdict {
        SafetyVerdict::Passed => (
            tr!("Safety checks passed"),
            None,
            "emblem-ok-symbolic",
            "success",
        ),
        SafetyVerdict::Refused(reasons) => (
            tr!("Safety checks failed"),
            Some(reasons),
            "dialog-error-symbolic",
            "error",
        ),
        SafetyVerdict::NoStableLink => (
            tr!("No stable device link"),
            Some(
                tr!(
                    "This drive has no /dev/disk/by-id link, so Ashy Pass cannot make sure \
                     it is still the same drive when erasing it. It cannot be encrypted here."
                )
                .to_string(),
            ),
            "dialog-error-symbolic",
            "error",
        ),
        SafetyVerdict::Error(message) => (
            tr!("Safety check error"),
            Some(message),
            "dialog-error-symbolic",
            "error",
        ),
    };
    let row = adw::ActionRow::builder().title(title).build();
    if let Some(subtitle) = subtitle {
        // Subtitles are Pango markup; reasons may contain paths with `<`.
        row.set_subtitle(&glib::markup_escape_text(&subtitle));
    }
    let image = gtk::Image::from_icon_name(icon);
    image.add_css_class(class);
    row.add_prefix(&image);
    group.add(&row);
    passed
}

/// What the user must type on the confirm page.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ConfirmToken {
    /// Last 4 characters of the serial number (case-insensitive).
    SerialSuffix(String),
    /// Full device path, for drives without a usable serial.
    Path(String),
}

impl ConfirmToken {
    fn for_drive(drive: &Drive) -> Self {
        match drive.serial.as_deref().map(str::trim) {
            Some(serial) if serial.chars().count() >= 4 => {
                let suffix: String = serial
                    .chars()
                    .rev()
                    .take(4)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect();
                Self::SerialSuffix(suffix)
            }
            _ => Self::Path(drive.path.clone()),
        }
    }

    fn matches(&self, typed: &str) -> bool {
        let typed = typed.trim();
        match self {
            Self::SerialSuffix(expected) => typed.eq_ignore_ascii_case(expected),
            Self::Path(expected) => typed == expected,
        }
    }
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
    let pw = adw::PasswordEntryRow::builder()
        .title(tr!("Passphrase"))
        .build();
    let pw2 = adw::PasswordEntryRow::builder()
        .title(tr!("Repeat"))
        .build();
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
            lbl_cl.set_label(crate::ui::i18n::localized_strength_label(word));
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
            state_cl.borrow_mut().passphrase = Some(Passphrase::from_text(pw_cl.text().as_str()));
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

    let label_error = gtk::Label::builder().xalign(0.0).wrap(true).build();
    label_error.add_css_class("caption");
    label_error.add_css_class("error");
    content.append(&label_error);

    let actions = button_row();
    let back = gtk::Button::with_label(tr!("Back"));
    let go = gtk::Button::with_label(tr!("Encrypt"));
    go.add_css_class("destructive-action");
    go.add_css_class("pill");
    actions.append(&back);
    actions.append(&go);
    content.append(&actions);

    // Live label validation against the selected filesystem's limit, so a
    // label mkfs would reject is caught before anything is wiped.
    {
        let label_cl = label_row.clone();
        let fs_cl = fs_row.clone();
        let error_cl = label_error.clone();
        let go_cl = go.clone();
        let validate = Rc::new(move || {
            let result = check_label_for_fs(&label_cl.text(), selected_filesystem(&fs_cl));
            match result {
                Ok(()) => {
                    label_cl.remove_css_class("error");
                    error_cl.set_visible(false);
                }
                Err(e) => {
                    label_cl.add_css_class("error");
                    error_cl.set_label(&label_error_text(e));
                    error_cl.set_visible(true);
                }
            }
            go_cl.set_sensitive(result.is_ok());
        });
        validate();
        let v1 = validate.clone();
        label_row.connect_changed(move |_| v1());
        let v2 = validate.clone();
        fs_row.connect_selected_notify(move |_| v2());
    }

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
        go.connect_clicked(move |button| {
            // A double click must not start two destructive pipelines on
            // the same drive.
            if !button.is_sensitive() {
                return;
            }
            button.set_sensitive(false);
            let mut st = state_cl.borrow_mut();
            st.filesystem = selected_filesystem(&fs_row);
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
    {
        let go = go.clone();
        page.connect_shown(move |_| go.set_sensitive(true));
    }

    page
}

fn selected_filesystem(row: &adw::ComboRow) -> Filesystem {
    match row.selected() {
        1 => Filesystem::Btrfs,
        2 => Filesystem::Xfs,
        _ => Filesystem::Ext4,
    }
}

fn label_error_text(error: LabelError) -> String {
    match error {
        LabelError::Empty => tr!("Enter a label.").to_string(),
        LabelError::TooLong { max_bytes } => format!(
            "{}: {max_bytes}",
            tr!("Label too long for this filesystem. Maximum length in bytes")
        ),
        LabelError::InvalidCharacters => {
            tr!("The label cannot start with \"-\" or contain \"/\" or control characters.")
                .to_string()
        }
    }
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
    let st = state.borrow();
    let running = st.running.clone();
    let expected = st.expected.clone();
    let drive_path = st
        .pinned_device
        .clone()
        .unwrap_or_else(|| PathBuf::from(&drive.path));
    let passphrase = st.passphrase.as_ref().map(|p| p.as_bytes().to_vec());
    let wipe_mode = st.wipe_mode.unwrap_or(WipeMode::EncryptedZero);
    let filesystem = st.filesystem;
    let allow_discards = st.allow_discards;
    let label = if st.label.is_empty() {
        "ashypass".to_string()
    } else {
        st.label.clone()
    };
    drop(st);

    let Some(passphrase_bytes) = passphrase else {
        status_label.set_label(tr!("Internal error: no passphrase set"));
        close_btn.set_sensitive(true);
        return page;
    };
    let Some(expected) = expected else {
        status_label.set_label(tr!("Internal error: the drive was not checked"));
        close_btn.set_sensitive(true);
        return page;
    };

    // From here until the worker reports back the window must stay open.
    let window = nav.root().and_downcast::<gtk::Window>();
    running.set(true);
    if let Some(window) = &window {
        window.set_deletable(false);
    }

    // Cross-thread channel: worker → main loop. The deprecated
    // `glib::MainContext::channel` was removed in glib 0.20, so we use
    // a standard mpsc channel polled from the main loop via a timeout.
    let (sender, receiver) = std::sync::mpsc::channel::<UiEvent>();

    // Worker thread — runs the whole pipeline through `encrypt_via_helper`,
    // so polkit prompts exactly once when the helper spawns.
    std::thread::spawn(move || {
        let pp = Passphrase::new(passphrase_bytes);
        let req = EncryptRequest {
            device: drive_path,
            expected,
            label: label.clone(),
            filesystem,
            wipe_mode,
            allow_discards,
        };
        let result = encrypt_via_helper(&req, &pp, |p| {
            let _ = sender.send(UiEvent::Progress(p));
        });
        let _ = sender.send(UiEvent::Done(result.map(|_| label)));
    });

    // Main-loop drain — poll every 80 ms. The timeout source lives until
    // the worker drops its sender, then `try_recv` returns Disconnected
    // and we tear down (and allow closing the window again, even if the
    // worker died without reporting).
    let row_map = Rc::new(row_map);
    let status_label_cl = status_label.clone();
    let progress_cl = progress.clone();
    let close_btn_cl = close_btn.clone();
    glib::timeout_add_local(std::time::Duration::from_millis(80), move || {
        let mut alive = true;
        loop {
            match receiver.try_recv() {
                Ok(ev) => handle_event(ev, &row_map, &status_label_cl, &progress_cl, &close_btn_cl),
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    alive = false;
                    running.set(false);
                    if let Some(window) = &window {
                        window.set_deletable(true);
                    }
                    close_btn_cl.set_sensitive(true);
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
            progress.set_text(Some(&format!("{}: {}", tr!("Encrypted as"), label)));
            close_btn.set_sensitive(true);
        }
        UiEvent::Done(Err(error)) => {
            let msg = describe_error(&error);
            status_label.set_label(&format!("{}: {msg}", tr!("Failed")));
            progress.set_text(Some(tr!("Error")));
            close_btn.set_sensitive(true);
        }
    }
}

enum UiEvent {
    Progress(Progress),
    Done(std::result::Result<String, ashypass_drives::Error>),
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

            let (sender, receiver) = std::sync::mpsc::channel::<ashypass_drives::Result<String>>();
            let device = device_path.clone();
            let label = label_hint.clone().unwrap_or_else(|| "ashypass".into());
            let pp_bytes = pp_text.as_bytes().to_vec();
            std::thread::spawn(move || {
                let pp = Passphrase::new(pp_bytes);
                // Through the privileged helper: it re-checks that the target
                // is a LUKS volume on a removable drive before opening it.
                let r = unlock_via_helper(&device, &label, &pp, false);
                let _ = sender.send(r.map(|path| path.display().to_string()));
            });

            let win_done = win_cl.clone();
            let status_done = status_cl.clone();
            let toast_done = toast_cl.clone();
            let btn_done = btn.clone();
            glib::timeout_add_local(
                std::time::Duration::from_millis(120),
                move || match receiver.try_recv() {
                    Ok(Ok(path)) => {
                        let t = adw::Toast::builder()
                            .title(glib::markup_escape_text(&format!(
                                "{}: {path}",
                                tr!("Unlocked at")
                            )))
                            .timeout(5)
                            .build();
                        toast_done.add_toast(t);
                        win_done.close();
                        glib::ControlFlow::Break
                    }
                    Ok(Err(error)) => {
                        status_done.set_label(&describe_error(&error));
                        btn_done.set_sensitive(true);
                        glib::ControlFlow::Break
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => glib::ControlFlow::Continue,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => glib::ControlFlow::Break,
                },
            );
        });
    }
}

/// Modal that enrolls a FIDO2 token on an existing LUKS device. Prompts for
/// the current passphrase (needed to authorise the new keyslot), then has
/// the privileged helper (which validates the device first) run
/// `systemd-cryptenroll --fido2-device=auto`. The
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
            status_cl.set_label(tr!(
                "Talking to your token… check the device for a touch prompt."
            ));

            let (sender, receiver) = std::sync::mpsc::channel::<ashypass_drives::Result<()>>();
            let device = device_path.clone();
            let pp_bytes = text.as_bytes().to_vec();
            let pin = pin_row.is_active();
            let presence = presence_row.is_active();
            std::thread::spawn(move || {
                let pp = Passphrase::new(pp_bytes);
                let r = HelperClient::spawn()
                    .and_then(|mut helper| helper.enroll_fido2(&device, &pp, pin, presence));
                let _ = sender.send(r);
            });

            let win_done = win_cl.clone();
            let status_done = status_cl.clone();
            let toast_done = toast_cl.clone();
            let btn_done = btn.clone();
            glib::timeout_add_local(
                std::time::Duration::from_millis(120),
                move || match receiver.try_recv() {
                    Ok(Ok(())) => {
                        let t = adw::Toast::builder()
                            .title(tr!("FIDO2 keyslot added"))
                            .timeout(5)
                            .build();
                        toast_done.add_toast(t);
                        win_done.close();
                        glib::ControlFlow::Break
                    }
                    Ok(Err(error)) => {
                        status_done.set_label(&describe_error(&error));
                        btn_done.set_sensitive(true);
                        glib::ControlFlow::Break
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => glib::ControlFlow::Continue,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => glib::ControlFlow::Break,
                },
            );
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

#[cfg(test)]
mod tests {
    use super::*;

    fn drive(serial: Option<&str>) -> Drive {
        Drive {
            path: "/dev/sdb".into(),
            name: "sdb".into(),
            size_bytes: 1,
            vendor: None,
            model: None,
            serial: serial.map(str::to_string),
            wwn: None,
            ptuuid: None,
            diskseq: None,
            transport: Some("usb".into()),
            removable: true,
            hotplug: true,
            read_only: false,
            mountpoint: None,
            rotational: false,
            partition_table: None,
            fstype: None,
            whole_disk: None,
            partitions: Vec::new(),
            stacked: Vec::new(),
        }
    }

    #[test]
    fn confirmation_uses_serial_suffix_when_available() {
        let token = ConfirmToken::for_drive(&drive(Some("E0D55EA5")));
        assert_eq!(token, ConfirmToken::SerialSuffix("5EA5".into()));
        assert!(token.matches("5EA5"));
        assert!(token.matches(" 5ea5 "));
        assert!(!token.matches("E0D5"));
        assert!(!token.matches(""));
        assert!(!token.matches("/dev/sdb"));
    }

    fn report(allow: bool, canonical: &str) -> SafetyReport {
        SafetyReport {
            canonical_path: PathBuf::from(canonical),
            device_node: PathBuf::from("/dev/sdb"),
            serial: Some("E0D55EA5".into()),
            size_bytes: 1,
            model: None,
            vendor: None,
            wwn: None,
            ptuuid: None,
            diskseq: None,
            allow_destructive: allow,
            reasons: if allow {
                Vec::new()
            } else {
                vec!["device is read-only".into()]
            },
        }
    }

    #[test]
    fn confirm_page_requires_a_by_id_link() {
        let pinned = Ok(report(true, "/dev/disk/by-id/usb-Kingston-0:0"));
        assert_eq!(safety_verdict(&pinned), SafetyVerdict::Passed);
        // Safe, but only reachable as /dev/sdb: stop before the passphrase.
        let unpinned = Ok(report(true, "/dev/sdb"));
        assert_eq!(safety_verdict(&unpinned), SafetyVerdict::NoStableLink);
        // by-path links are stable but the helper only accepts by-id.
        let by_path = Ok(report(true, "/dev/disk/by-path/pci-0000:00:14.0-usb-0:1"));
        assert_eq!(safety_verdict(&by_path), SafetyVerdict::NoStableLink);
        // Guard refusals still win.
        let refused = Ok(report(false, "/dev/sdb"));
        assert_eq!(
            safety_verdict(&refused),
            SafetyVerdict::Refused("device is read-only".into())
        );
    }

    #[test]
    fn dismissed_polkit_prompt_is_reported_plainly() {
        assert_eq!(
            describe_error(&ashypass_drives::Error::AuthCancelled),
            "Authentication was cancelled"
        );
    }

    #[test]
    fn confirmation_falls_back_to_the_path() {
        for serial in [None, Some("ab"), Some("   ")] {
            let token = ConfirmToken::for_drive(&drive(serial));
            assert_eq!(token, ConfirmToken::Path("/dev/sdb".into()));
            assert!(token.matches("/dev/sdb"));
            assert!(!token.matches("/dev/sdc"));
            assert!(!token.matches("/DEV/SDB"));
        }
    }
}
