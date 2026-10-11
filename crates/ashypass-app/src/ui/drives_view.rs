//! External drive encryption view — dysk-inspired dense listing.
//!
//! Each drive is one `adw::ExpanderRow`:
//!   ┌───────────────────────────────────────────────────────────────┐
//!   │ [icon] Kingston DataTraveler 3.0                              │
//!   │        USB · 57.7 GiB · /dev/sda          [ Encrypt… ]  [▾]   │
//!   ├───────────────────────────────────────────────────────────────┤
//!   │   sda1   Ventoy        ████████░░ 12%   exfat   /run/media…   │
//!   │   sda2                                  vfat    not mounted   │
//!   └───────────────────────────────────────────────────────────────┘
//!
//! Visual primitives:
//!   - drive icon chosen by transport × rotational (USB stick vs HDD vs SSD)
//!   - usage bar (`gtk::LevelBar`) per mounted partition with offsets
//!     low/high/full so the theme colors it green→yellow→red automatically
//!   - filesystem badge: `success` (linux-native), `warning` (foreign),
//!     `accent` (crypto_LUKS), dimmed (unknown)

use crate::tr;
use adw::prelude::*;
use ashypass_drives::detect::{human_size, list_removable, Drive, Partition};
use ashypass_drives::validate::validate_mapper_name;
use gtk::glib;
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::Once;

/// `gtk::LevelBar` defaults to "battery" semantics (full = good). For disk
/// usage we want the opposite, so we ship our own colored offsets via a CSS
/// provider installed once per display.
static CSS_INSTALLED: Once = Once::new();
const USAGE_CSS: &str = "
levelbar.disk-usage trough block.usage-low {
    background-color: @success_color;
    border-color: @success_color;
}
levelbar.disk-usage trough block.usage-mid {
    background-color: @warning_color;
    border-color: @warning_color;
}
levelbar.disk-usage trough block.usage-high {
    background-color: @error_color;
    border-color: @error_color;
}
levelbar.disk-usage trough block.empty-fill-block {
    background-color: alpha(@window_fg_color, 0.12);
}
.numeric {
    font-feature-settings: 'tnum' 1, 'zero' 1, 'ss01' 1;
    font-variant-numeric: tabular-nums slashed-zero;
}
";

fn install_usage_css() {
    CSS_INSTALLED.call_once(|| {
        let provider = gtk::CssProvider::new();
        provider.load_from_string(USAGE_CSS);
        if let Some(display) = gtk::gdk::Display::default() {
            gtk::style_context_add_provider_for_display(
                &display,
                &provider,
                gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
            );
        }
    });
}

/// Icon for removable drives. `drive-removable-media-*` renders as an eject
/// glyph in several themes; `media-removable` is the USB-stick shape.
const REMOVABLE_DRIVE_ICON: &str = "media-removable-symbolic";

pub struct DrivesView {
    pub root: gtk::Box,
    #[expect(dead_code, reason = "keeps view model alive for signal handlers")]
    inner: Rc<Inner>,
}

struct Inner {
    toast: adw::ToastOverlay,
    list_container: gtk::Box,
    #[expect(dead_code, reason = "held to keep the widget alive in the stack")]
    empty_status: adw::StatusPage,
    content_stack: gtk::Stack,
    last_signature: RefCell<String>,
    /// A scan is running on a worker thread; polls are skipped meanwhile.
    scanning: Cell<bool>,
    /// The user asked for a refresh while a poll was running: rebuild with
    /// that poll's result and report its errors.
    forced_pending: Cell<bool>,
    /// Last scan error logged, so a persistent failure is logged once
    /// instead of every poll.
    last_error: RefCell<Option<String>>,
}

impl DrivesView {
    pub fn new(toast: adw::ToastOverlay) -> Rc<Self> {
        install_usage_css();
        let root = gtk::Box::new(gtk::Orientation::Vertical, 0);
        root.set_vexpand(true);
        root.set_hexpand(true);

        let banner = adw::Banner::builder()
            .title(tr!(
                "Encrypting erases the whole drive. Unlock and lock work for LUKS drives."
            ))
            .revealed(true)
            .build();
        root.append(&banner);

        let action_strip = gtk::Box::builder()
            .orientation(gtk::Orientation::Horizontal)
            .spacing(8)
            .margin_top(12)
            .margin_start(12)
            .margin_end(12)
            .halign(gtk::Align::End)
            .build();
        let refresh_btn = gtk::Button::builder()
            .icon_name("view-refresh-symbolic")
            .tooltip_text(tr!("Search for drives"))
            .build();
        refresh_btn.add_css_class("flat");
        action_strip.append(&refresh_btn);
        root.append(&action_strip);

        let content_stack = gtk::Stack::builder()
            .transition_type(gtk::StackTransitionType::Crossfade)
            .vexpand(true)
            .build();

        let empty_status = adw::StatusPage::builder()
            .icon_name(REMOVABLE_DRIVE_ICON)
            .title(tr!("No external drives detected"))
            .description(tr!(
                "Plug in a USB drive or external disk, then search for drives."
            ))
            .vexpand(true)
            .build();
        content_stack.add_named(&empty_status, Some("empty"));

        let scrolled = gtk::ScrolledWindow::builder()
            .hscrollbar_policy(gtk::PolicyType::Never)
            .vscrollbar_policy(gtk::PolicyType::Automatic)
            .vexpand(true)
            .hexpand(true)
            .build();
        let list_container = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(12)
            .margin_top(12)
            .margin_bottom(12)
            .margin_start(12)
            .margin_end(12)
            .build();
        scrolled.set_child(Some(&list_container));
        content_stack.add_named(&scrolled, Some("list"));

        root.append(&content_stack);

        let inner = Rc::new(Inner {
            toast,
            list_container,
            empty_status,
            content_stack,
            last_signature: RefCell::new(String::new()),
            scanning: Cell::new(false),
            forced_pending: Cell::new(false),
            last_error: RefCell::new(None),
        });

        inner.scan(true);

        {
            let inner_cl = inner.clone();
            refresh_btn.connect_clicked(move |_| inner_cl.scan(true));
        }

        // Hot-plug poll. Cheap (one lsblk call, on a worker thread) and
        // signature-based: we only rebuild widgets when the device topology
        // actually changes.
        {
            let inner_cl = inner.clone();
            let root_cl = root.clone();
            glib::timeout_add_seconds_local(3, move || {
                // Only while the page is on screen: nobody needs the list
                // while it is hidden.
                if root_cl.is_mapped() {
                    inner_cl.scan(false);
                }
                glib::ControlFlow::Continue
            });
        }

        Rc::new(Self { root, inner })
    }
}

impl Inner {
    /// Run `lsblk` on a worker thread and update the list from the main
    /// loop. `force` rebuilds even if nothing changed and reports failures
    /// with a toast; polls only rebuild on change and log failures.
    fn scan(self: &Rc<Self>, force: bool) {
        if self.scanning.replace(true) {
            if force {
                self.forced_pending.set(true);
            }
            return;
        }
        let inner = self.clone();
        super::settings_dialog::run_background(list_removable, move |result| {
            inner.scanning.set(false);
            let force = force || inner.forced_pending.replace(false);
            match result {
                Ok(drives) => {
                    inner.last_error.replace(None);
                    let sig = signature(&drives);
                    if force || sig != *inner.last_signature.borrow() {
                        *inner.last_signature.borrow_mut() = sig;
                        inner.populate(&drives);
                    }
                }
                Err(e) => {
                    let message = e.to_string();
                    if inner.last_error.borrow().as_deref() != Some(message.as_str()) {
                        log::warn!("drive scan failed: {message}");
                        inner.last_error.replace(Some(message.clone()));
                    }
                    if force {
                        let toast = adw::Toast::builder()
                            .title(glib::markup_escape_text(&format!(
                                "{}: {message}",
                                tr!("Failed to scan drives")
                            )))
                            .timeout(4)
                            .build();
                        inner.toast.add_toast(toast);
                    }
                }
            }
        });
    }

    fn populate(&self, drives: &[Drive]) {
        while let Some(child) = self.list_container.first_child() {
            self.list_container.remove(&child);
        }
        if drives.is_empty() {
            self.content_stack.set_visible_child_name("empty");
            return;
        }
        self.content_stack.set_visible_child_name("list");

        let group = adw::PreferencesGroup::new();
        for drive in drives {
            group.add(&drive_row(drive, &self.toast));
        }
        self.list_container.append(&group);
    }
}

/// Cheap fingerprint of device topology. Only changes here should rebuild rows.
///
/// Usage figures (`fs_used`) are deliberately left out: copying files to a
/// mounted drive would otherwise rebuild the list (and collapse every
/// expanded row) on each poll. The usage bars catch up on the next
/// topology change or manual refresh.
fn signature(drives: &[Drive]) -> String {
    let mut s = String::new();
    for d in drives {
        s.push_str(&d.path);
        s.push(':');
        s.push_str(&d.size_bytes.to_string());
        s.push(':');
        s.push_str(d.fstype.as_deref().unwrap_or("-"));
        for p in d.volumes() {
            s.push('|');
            s.push_str(&p.name);
            s.push(',');
            s.push_str(p.fstype.as_deref().unwrap_or("-"));
            s.push(',');
            s.push_str(p.mountpoint.as_deref().unwrap_or("-"));
            // LUKS open/close state — without this the row never flips
            // between Unlock and Lock on auto-refresh.
            s.push(',');
            s.push_str(p.active_mapping.as_deref().unwrap_or("-"));
            s.push(',');
            s.push_str(p.inner_mountpoint.as_deref().unwrap_or("-"));
        }
        s.push('\n');
    }
    s
}

fn drive_row(drive: &Drive, toast: &adw::ToastOverlay) -> adw::ExpanderRow {
    let row = adw::ExpanderRow::new();

    let title = drive
        .model
        .clone()
        .or_else(|| drive.vendor.clone())
        .unwrap_or_else(|| drive.name.clone());
    // Subtitle mixes sans-serif (bus tag, "read-only") with monospace
    // (size, /dev path) via Pango markup. ExpanderRow's subtitle parses
    // markup by default — no `set_use_markup` needed.
    let mut subtitle = String::new();
    if let Some(t) = drive.transport.as_deref() {
        subtitle.push_str(&glib::markup_escape_text(&t.to_uppercase()));
        subtitle.push_str("  ·  ");
    }
    subtitle.push_str(&mono_span(&human_size(drive.size_bytes)));
    subtitle.push_str("  ·  ");
    subtitle.push_str(&mono_span(&drive.path));
    if drive.read_only {
        subtitle.push_str("  ·  ");
        subtitle.push_str(tr!("read-only"));
    }

    row.set_title(glib::markup_escape_text(&title).as_str());
    row.set_subtitle(&subtitle);

    // Leading icon — chosen by transport × rotational.
    let icon = gtk::Image::from_icon_name(drive_icon_name(drive));
    icon.set_icon_size(gtk::IconSize::Large);
    icon.set_margin_end(6);
    row.add_prefix(&icon);

    // Encrypt button as suffix.
    let encrypt_btn = gtk::Button::builder()
        .label(tr!("Encrypt…"))
        .tooltip_text(tr!("Launch the encryption wizard"))
        .sensitive(true)
        .valign(gtk::Align::Center)
        .build();
    encrypt_btn.add_css_class("destructive-action");
    encrypt_btn.add_css_class("pill");
    let drive_for_btn = drive.clone();
    let toast_for_btn = toast.clone();
    encrypt_btn.connect_clicked(move |btn| {
        if let Some(window) = btn.root().and_downcast::<gtk::Window>() {
            super::drives_wizard::present(&window, drive_for_btn.clone(), toast_for_btn.clone());
        }
    });
    row.add_suffix(&encrypt_btn);

    // Details summary as the first child row.
    row.add_row(&drive_details_row(drive));

    // Volume children. A drive encrypted by Ashy Pass has no partition
    // table: the whole disk is the LUKS volume and gets the same row (and
    // Unlock / Lock / FIDO2 actions) as a partition would.
    if !drive.partitions.is_empty() {
        for part in &drive.partitions {
            row.add_row(&partition_row(part, toast));
        }
    } else if let Some(volume) = drive.whole_disk.as_ref() {
        row.add_row(&partition_row(volume, toast));
    } else {
        let blank = adw::ActionRow::builder()
            .title(tr!("Whole device — no partition table"))
            .subtitle(human_size(drive.size_bytes))
            .build();
        row.add_row(&blank);
    }
    row
}

fn drive_details_row(drive: &Drive) -> adw::ActionRow {
    let grid = gtk::Grid::builder()
        .row_spacing(4)
        .column_spacing(14)
        .margin_top(10)
        .margin_bottom(10)
        .margin_start(6)
        .margin_end(6)
        .build();

    let mut row_idx: i32 = 0;
    let push = |grid: &gtk::Grid, idx: &mut i32, label: &str, value: gtk::Widget| {
        let lbl = gtk::Label::builder().label(label).xalign(1.0).build();
        lbl.add_css_class("caption");
        lbl.add_css_class("dim-label");
        grid.attach(&lbl, 0, *idx, 1, 1);
        grid.attach(&value, 1, *idx, 1, 1);
        *idx += 1;
    };

    if let Some(v) = drive.vendor.as_deref() {
        push(&grid, &mut row_idx, tr!("Vendor"), sans_value(v));
    }
    if let Some(m) = drive.model.as_deref() {
        push(&grid, &mut row_idx, tr!("Model"), sans_value(m));
    }
    if let Some(s) = drive.serial.as_deref() {
        push(&grid, &mut row_idx, tr!("Serial"), mono_value(s));
    }
    let transport = drive
        .transport
        .as_deref()
        .map(str::to_uppercase)
        .unwrap_or_else(|| "—".into());
    push(
        &grid,
        &mut row_idx,
        tr!("Bus / media"),
        sans_value(&format!("{transport} · {}", media_kind(drive))),
    );

    let table = drive
        .partition_table
        .as_deref()
        .map(|t| match t {
            "gpt" => "GPT".to_string(),
            "dos" => "MBR (DOS)".to_string(),
            other => other.to_uppercase(),
        })
        .unwrap_or_else(|| tr!("none").to_string());
    push(
        &grid,
        &mut row_idx,
        tr!("Partition table"),
        sans_value(&table),
    );

    let allocated: u64 = drive.partitions.iter().map(|p| p.size_bytes).sum();
    let unallocated = drive.size_bytes.saturating_sub(allocated);
    let capacity_markup = format!(
        "{}  ({} {}, {} {})",
        mono_span(&human_size(drive.size_bytes)),
        mono_span(&human_size(allocated)),
        glib::markup_escape_text(tr!("allocated")),
        mono_span(&human_size(unallocated)),
        glib::markup_escape_text(tr!("free")),
    );
    push(
        &grid,
        &mut row_idx,
        tr!("Capacity"),
        markup_value(&capacity_markup),
    );
    if drive.read_only {
        push(
            &grid,
            &mut row_idx,
            tr!("Write protection"),
            sans_value(tr!("read-only")),
        );
    }

    let row = adw::ActionRow::builder().activatable(false).build();
    row.set_child(Some(&grid));
    row
}

fn sans_value(text: &str) -> gtk::Widget {
    let l = gtk::Label::builder()
        .label(text)
        .xalign(0.0)
        .selectable(true)
        .wrap(true)
        .build();
    l.add_css_class("caption");
    l.upcast()
}

fn mono_value(text: &str) -> gtk::Widget {
    let l = gtk::Label::builder()
        .label(text)
        .xalign(0.0)
        .selectable(true)
        .build();
    l.add_css_class("caption");
    l.add_css_class("monospace");
    l.add_css_class("numeric");
    l.upcast()
}

fn markup_value(markup: &str) -> gtk::Widget {
    let l = gtk::Label::builder().xalign(0.0).selectable(true).build();
    l.set_markup(markup);
    l.add_css_class("caption");
    l.add_css_class("numeric");
    l.upcast()
}

/// Wrap text in a Pango `<span face="monospace">` after escaping it. Used
/// inline in titles and subtitles where alignment matters (sizes, paths)
/// but the surrounding text should stay in the UI sans-serif.
fn mono_span(text: &str) -> String {
    format!(
        "<span face=\"monospace\">{}</span>",
        glib::markup_escape_text(text)
    )
}

/// `lsblk`'s `rota` field is unreliable on USB mass storage (the SCSI
/// emulation layer often reports `1` for flash sticks). We treat the
/// rotational flag as informative only for sata/nvme transports.
fn media_kind(drive: &Drive) -> &'static str {
    match drive.transport.as_deref() {
        Some("usb" | "mmc" | "sd") => tr!("flash storage"),
        _ if drive.rotational => tr!("rotational (HDD)"),
        _ => tr!("solid-state"),
    }
}

fn drive_icon_name(drive: &Drive) -> &'static str {
    match (drive.transport.as_deref(), drive.rotational) {
        (Some("usb"), false) => REMOVABLE_DRIVE_ICON,
        (Some("usb"), true) => "drive-harddisk-usb-symbolic",
        (Some("nvme"), _) => "drive-harddisk-solidstate-symbolic",
        (Some("sata"), false) => "drive-harddisk-solidstate-symbolic",
        (Some("sata"), true) => "drive-harddisk-symbolic",
        (Some("mmc") | Some("sd"), _) => "media-flash-symbolic",
        _ if drive.removable => REMOVABLE_DRIVE_ICON,
        _ => "drive-harddisk-symbolic",
    }
}

fn partition_row(part: &Partition, toast: &adw::ToastOverlay) -> adw::ActionRow {
    // Title: <mono>sda1</mono>  ·  <sans>Ventoy</sans>
    let mut title = mono_span(&part.name);
    if let Some(l) = part.label.as_deref().filter(|l| !l.is_empty()) {
        title.push_str("  ·  ");
        title.push_str(&glib::markup_escape_text(l));
    }

    // Subtitle: <mono>57.6 GiB</mono>  ·  <mono>/run/media/...</mono>
    //   or:    <mono>32.0 MiB</mono>  ·  not mounted
    let mut subtitle = mono_span(&human_size(part.size_bytes));
    subtitle.push_str("  ·  ");
    match part.mountpoint.as_deref() {
        Some(mp) => subtitle.push_str(&mono_span(mp)),
        None => subtitle.push_str(tr!("not mounted")),
    }

    let row = adw::ActionRow::builder()
        .title(&title)
        .subtitle(&subtitle)
        .use_markup(false)
        .build();

    // Suffix box: usage bar (when mounted) above the filesystem badge.
    let suffix = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(4)
        .valign(gtk::Align::Center)
        .halign(gtk::Align::End)
        .build();

    if let (Some(used), Some(size)) = (part.fs_used, part.fs_size) {
        if size > 0 {
            suffix.append(&usage_widget(used, size));
        }
    }

    let fstype = part.fstype.as_deref().unwrap_or("");
    if !fstype.is_empty() {
        suffix.append(&fstype_badge(fstype));
    }
    if !fstype.is_empty() || part.fs_used.is_some() {
        row.add_suffix(&suffix);
    }

    // LUKS partitions get either Unlock (locked) or Lock (already open),
    // plus a FIDO2-enrol icon button when locked.
    if fstype == "crypto_LUKS" {
        let part_path = std::path::PathBuf::from(&part.path);

        if let Some(mapping) = part.active_mapping.clone() {
            // Already unlocked — show the inner mountpoint/FS as suffix
            // and offer a Lock button to tear the mapping down.
            if let Some(mp) = part.inner_mountpoint.as_deref() {
                let mp_label = gtk::Label::builder().label(mp).xalign(1.0).build();
                mp_label.add_css_class("caption");
                mp_label.add_css_class("monospace");
                mp_label.add_css_class("dim-label");
                row.add_suffix(&mp_label);
            }
            let lock_btn = gtk::Button::builder()
                .label(tr!("Lock"))
                .valign(gtk::Align::Center)
                .build();
            lock_btn.add_css_class("destructive-action");
            lock_btn.add_css_class("pill");
            if validate_mapper_name(&mapping).is_ok() {
                lock_btn.set_tooltip_text(Some(&format!(
                    "{}: /dev/mapper/{mapping}",
                    tr!("Close active mapping")
                )));
                connect_lock(&lock_btn, mapping, part.inner_mountpoint.is_some(), toast);
            } else {
                // Opened by udisks / the file manager (or another tool):
                // Ashy Pass only ever closes its own `ashypass_*` mappings.
                lock_btn.set_sensitive(false);
                lock_btn.set_tooltip_text(Some(tr!(
                    "Unlocked by another application. Lock it from your file manager."
                )));
            }
            row.add_suffix(&lock_btn);
        } else {
            let label_hint = part.label.clone();

            let part_path_fido = part_path.clone();
            let fido_btn = gtk::Button::builder()
                .icon_name("auth-fingerprint-symbolic")
                .tooltip_text(tr!("Add FIDO2 token keyslot"))
                .valign(gtk::Align::Center)
                .build();
            fido_btn.add_css_class("flat");
            let toast_fido = toast.clone();
            fido_btn.connect_clicked(move |btn| {
                if let Some(window) = btn.root().and_downcast::<gtk::Window>() {
                    super::drives_wizard::present_enroll_fido2(
                        &window,
                        part_path_fido.clone(),
                        toast_fido.clone(),
                    );
                }
            });
            row.add_suffix(&fido_btn);

            let unlock_btn = gtk::Button::builder()
                .label(tr!("Unlock"))
                .tooltip_text(tr!("Open the encrypted volume"))
                .valign(gtk::Align::Center)
                .build();
            unlock_btn.add_css_class("suggested-action");
            unlock_btn.add_css_class("pill");
            let toast_unlock = toast.clone();
            unlock_btn.connect_clicked(move |btn| {
                if let Some(window) = btn.root().and_downcast::<gtk::Window>() {
                    super::drives_wizard::present_unlock(
                        &window,
                        part_path.clone(),
                        label_hint.clone(),
                        toast_unlock.clone(),
                    );
                }
            });
            row.add_suffix(&unlock_btn);
        }
    }

    row
}

/// Wire the Lock button: unmount through udisks (best effort; the helper
/// refuses a still-mounted mapping with a clear message), close the mapping
/// through the privileged helper, and report the outcome on the window's
/// toast overlay.
fn connect_lock(btn: &gtk::Button, mapping: String, mounted: bool, toast: &adw::ToastOverlay) {
    let toast = toast.clone();
    btn.connect_clicked(move |btn| {
        let mapping_for_thread = mapping.clone();
        let mapped_path = std::path::PathBuf::from(format!("/dev/mapper/{mapping}"));
        btn.set_sensitive(false);

        let (sender, receiver) = std::sync::mpsc::channel::<ashypass_drives::Result<()>>();
        std::thread::spawn(move || {
            // Unmount first — Nautilus or any other client holding the
            // mapping would block cryptsetup close with EBUSY.
            if mounted {
                unmount_with_udisks(&mapped_path);
            }
            let r = ashypass_drives::helper_client::HelperClient::spawn()
                .and_then(|mut helper| helper.luks_lock(&mapping_for_thread));
            let _ = sender.send(r);
        });

        let btn_done = btn.clone();
        let toast_done = toast.clone();
        glib::timeout_add_local(std::time::Duration::from_millis(120), move || {
            let message = match receiver.try_recv() {
                Ok(Ok(())) => tr!("Drive locked").to_string(),
                Ok(Err(error)) => format!(
                    "{}: {}",
                    tr!("Could not lock the drive"),
                    super::drives_wizard::describe_error(&error)
                ),
                Err(std::sync::mpsc::TryRecvError::Empty) => return glib::ControlFlow::Continue,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    tr!("Could not lock the drive").to_string()
                }
            };
            btn_done.set_sensitive(true);
            // Toast titles are Pango markup; cryptsetup output may contain `<`.
            toast_done.add_toast(
                adw::Toast::builder()
                    .title(glib::markup_escape_text(&message).as_str())
                    .timeout(5)
                    .build(),
            );
            glib::ControlFlow::Break
        });
    });
}

/// `udisksctl unmount -b <mapping>`. Failures are logged, not fatal: the
/// helper re-checks the mount state and refuses with a clear reason.
fn unmount_with_udisks(mapped_path: &std::path::Path) {
    match std::process::Command::new("udisksctl")
        .arg("unmount")
        .arg("-b")
        .arg(mapped_path)
        .stdin(std::process::Stdio::null())
        .output()
    {
        Ok(output) if output.status.success() => {}
        Ok(output) => log::warn!(
            "udisksctl unmount {} failed: {}",
            mapped_path.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ),
        Err(error) => log::warn!("could not run udisksctl: {error}"),
    }
}

fn usage_widget(used: u64, size: u64) -> gtk::Box {
    let container = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(8)
        .valign(gtk::Align::Center)
        .build();

    let ratio = (used as f64 / size as f64).clamp(0.0, 1.0);
    let bar = gtk::LevelBar::builder()
        .mode(gtk::LevelBarMode::Continuous)
        .min_value(0.0)
        .max_value(1.0)
        .value(ratio)
        .width_request(90)
        .height_request(8)
        .valign(gtk::Align::Center)
        .build();
    bar.add_css_class("disk-usage");
    // Custom offsets so our CSS provider can colour each band correctly
    // for "full = bad" semantics.
    bar.add_offset_value("usage-low", 0.5);
    bar.add_offset_value("usage-mid", 0.8);
    bar.add_offset_value("usage-high", 1.0);

    let free = size.saturating_sub(used);
    let pct = (ratio * 100.0).round() as u32;
    // Mix mono (numbers) + sans (the connective "free of" and the %).
    let markup = format!(
        "<span face=\"monospace\">{free}</span> {of} <span face=\"monospace\">{size}</span>  \
         <span alpha=\"60%\">·</span>  <span face=\"monospace\">{pct}%</span>",
        free = glib::markup_escape_text(&human_size(free)),
        size = glib::markup_escape_text(&human_size(size)),
        of = glib::markup_escape_text(tr!("free of")),
        pct = pct,
    );
    let label = gtk::Label::builder().xalign(1.0).build();
    label.set_markup(&markup);
    label.add_css_class("dim-label");
    label.add_css_class("caption");
    label.add_css_class("numeric");

    container.append(&bar);
    container.append(&label);
    container
}

fn fstype_badge(fstype: &str) -> gtk::Label {
    let label = gtk::Label::builder()
        .label(fstype)
        .valign(gtk::Align::Center)
        .build();
    label.add_css_class("caption");
    label.add_css_class("monospace");
    label.add_css_class(fstype_css_class(fstype));
    label
}

fn fstype_css_class(fstype: &str) -> &'static str {
    match fstype {
        "crypto_LUKS" => "accent",
        "ext2" | "ext3" | "ext4" | "btrfs" | "xfs" | "f2fs" => "success",
        "vfat" | "exfat" | "ntfs" | "hfsplus" => "warning",
        "swap" => "error",
        _ => "dim-label",
    }
}
