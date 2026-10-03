//! Preferences dialog — ported from the original `ui/settings_dialog.py`.
//!
//! Pages:
//! - Security: change master password, auto-lock timeout, clipboard auto-clear
//! - Appearance: show favicons toggle
//! - Import/Export: scaffolding for task #10 (CSV / Aegis / andOTP)
//! - Cloud Backup: scaffolding for task #11 (Google Drive)

use crate::session::SessionManager;
use crate::state::SharedState;
use crate::{tr, trn};
use adw::prelude::*;
use ashypass_core::config::MIN_MASTER_PASSWORD_LENGTH;
use ashypass_core::settings::Settings;
use gtk::gio;
use std::cell::RefCell;
use std::rc::Rc;

mod appearance;
mod audit;
mod cloud;
mod import_export;
mod nextcloud;
mod public_api;
mod security;
mod trash;
#[allow(dead_code)]
mod two_factor;

pub(crate) use appearance::apply_color_scheme;
use appearance::*;
use audit::*;
use cloud::*;
use import_export::*;
use nextcloud::*;
// Re-exported for the dev-only preview harness in `ui::preview`.
pub(crate) use nextcloud::{present_sync_failure_dialog, present_sync_success_dialog};
pub use public_api::*;
use security::*;
use trash::*;

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

pub fn present(parent: &impl IsA<gtk::Widget>, state: SharedState, _toast: adw::ToastOverlay) {
    let dialog = adw::PreferencesDialog::builder()
        .title(tr!("Settings"))
        .search_enabled(true)
        .content_width(760)
        .content_height(680)
        .build();
    // Sub-dialogs and the legacy unlock prompt reach the settings window
    // through this slot to close or re-open it.
    let dialog_slot: Rc<RefCell<Option<adw::Dialog>>> =
        Rc::new(RefCell::new(Some(dialog.clone().upcast())));
    // Toasts raised from inside the dialog must show over it.
    let toast = Toaster::Dialog(dialog.downgrade());
    let parent_widget: gtk::Widget = dialog.clone().upcast();

    let protection = adw::PreferencesPage::builder()
        .title(tr!("Protection"))
        .icon_name("security-high-symbolic")
        .build();
    populate_protection(
        &protection,
        state.clone(),
        toast.clone(),
        dialog.clone(),
        dialog_slot.clone(),
    );
    let settings = Rc::new(RefCell::new(Settings::load()));
    populate_audit(
        &protection,
        state.clone(),
        settings.clone(),
        toast.clone(),
        parent_widget.clone(),
        dialog_slot.clone(),
    );

    let sync = adw::PreferencesPage::builder()
        .title(tr!("Synchronization"))
        .icon_name("emblem-synchronizing-symbolic")
        .build();
    populate_sync(
        &sync,
        state.clone(),
        toast.clone(),
        parent_widget.clone(),
        dialog_slot.clone(),
    );

    let browser = adw::PreferencesPage::builder()
        .title(tr!("Browser"))
        .icon_name("web-browser-symbolic")
        .build();
    populate_browser(&browser, state.clone());

    let appearance = adw::PreferencesPage::builder()
        .title(tr!("Appearance"))
        .icon_name("preferences-desktop-appearance-symbolic")
        .build();
    populate_appearance(&appearance, settings, state.clone());

    dialog.add(&protection);
    dialog.add(&sync);
    dialog.add(&browser);
    dialog.add(&appearance);

    state.track_sensitive_dialog(&dialog);
    dialog.present(Some(parent));
}

/// Where a settings page sends its toasts: the preferences dialog itself, or
/// an overlay when a section is shown in another dialog or page.
#[derive(Clone)]
pub enum Toaster {
    Overlay(adw::ToastOverlay),
    Dialog(glib::WeakRef<adw::PreferencesDialog>),
}

impl Toaster {
    pub fn add_toast(&self, toast: adw::Toast) {
        match self {
            Self::Overlay(overlay) => overlay.add_toast(toast),
            Self::Dialog(dialog) => {
                if let Some(dialog) = dialog.upgrade() {
                    dialog.add_toast(toast);
                }
            }
        }
    }
}

impl From<adw::ToastOverlay> for Toaster {
    fn from(overlay: adw::ToastOverlay) -> Self {
        Self::Overlay(overlay)
    }
}

fn show_toast(overlay: &Toaster, message: &str) {
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
    toast: Toaster,
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
        show_settings_unlock_dialog(&parent, state.clone(), toast.clone(), dialog_slot.clone());
    });
    group.add(&row);
    group
}

fn show_settings_unlock_dialog(
    parent: &gtk::Widget,
    state: SharedState,
    toast: Toaster,
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
    dialog.add_response(
        "unlock",
        if has_master {
            tr!("Unlock Vault")
        } else {
            tr!("Save")
        },
    );
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

    let password_row_focus = password_row.clone();
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
                    if !has_master {
                        let mut settings = Settings::load();
                        settings.quick_unlock = None;
                        save_settings(&settings);
                    }
                    SessionManager::login(&state.session);
                    state.events.emit(crate::events::AppEvent::VaultChanged);
                    dlg.close();
                    // Take before closing: `close()` can run handlers that
                    // reach for the same slot, and holding the RefMut across
                    // that would panic.
                    let open_settings = dialog_slot.borrow_mut().take();
                    if let Some(settings_dialog) = open_settings {
                        settings_dialog.close();
                    }
                    present(&parent, state.clone(), adw::ToastOverlay::new());
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
    glib::idle_add_local_once(move || {
        password_row_focus.grab_focus();
    });
}

fn is_database_backup_name(name: &str) -> bool {
    let Some(stem) = name
        .strip_prefix("passwords-")
        .and_then(|name| name.strip_suffix(".db"))
    else {
        return false;
    };
    let Some((date, time)) = stem.split_once('-') else {
        return false;
    };
    date.len() == 8
        && time.len() == 6
        && date.bytes().all(|byte| byte.is_ascii_digit())
        && time.bytes().all(|byte| byte.is_ascii_digit())
}

fn temporary_snapshot_path(provider: &str) -> std::path::PathBuf {
    let nonce = chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default();
    ashypass_core::config::data_dir().join(format!(
        ".{provider}-snapshot-{}-{}.db",
        std::process::id(),
        nonce
    ))
}

fn restore_destination() -> std::path::PathBuf {
    let stamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
    let nonce = chrono::Utc::now().timestamp_subsec_nanos();
    ashypass_core::config::data_dir().join(format!("passwords-restored-{stamp}-{:08x}.db", nonce))
}

pub(crate) fn run_background<T, F, C>(task: F, complete: C)
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
    C: FnOnce(T) + 'static,
{
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let _ = sender.send(task());
    });
    let complete = Rc::new(RefCell::new(Some(complete)));
    glib::timeout_add_local(
        std::time::Duration::from_millis(50),
        move || match receiver.try_recv() {
            Ok(result) => {
                // Release the borrow before running the continuation: it is
                // arbitrary user code and may re-enter this cell.
                let continuation = complete.borrow_mut().take();
                if let Some(complete) = continuation {
                    complete(result);
                }
                glib::ControlFlow::Break
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => glib::ControlFlow::Continue,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                log::error!("background operation terminated without a result");
                glib::ControlFlow::Break
            }
        },
    );
}

fn save_settings(settings: &Settings) {
    if let Err(error) = settings.save() {
        log::warn!("could not save settings: {error}");
    }
}
