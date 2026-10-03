//! Entry points used outside the settings dialog: the Backups page, the
//! trash from "My passwords", and the confirmation prompts shared by
//! sensitive operations.

use super::*;
use zeroize::Zeroizing;

/// Where the user says their passwords come from. Each maps to a file type
/// and importer; the person never has to know the format's name first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImportSource {
    Bitwarden,
    Onepassword,
    Keepass,
    BrowserCsv,
    OtherCsv,
    Aegis,
    Andotp,
    AshyMerge,
}

pub fn import_from(
    state: SharedState,
    toast: adw::ToastOverlay,
    source: ImportSource,
    anchor: gtk::Widget,
) {
    crate::ui::import_flow::start(state, toast, source, anchor);
}

pub fn export_kdbx(state: SharedState, toast: adw::ToastOverlay, anchor: gtk::Widget) {
    let toast: Toaster = toast.into();
    run_export_kdbx(state, toast, anchor);
}

/// A CSV export can be read by anyone who gets the file. Say so, list what
/// it contains, and require the master password before choosing where to
/// write it.
pub fn export_csv_with_warning(state: SharedState, toast: adw::ToastOverlay, anchor: gtk::Widget) {
    let toast: Toaster = toast.into();
    let dialog = adw::AlertDialog::builder()
        .heading(tr!("This file can be read without a password"))
        .body(tr!(
            "Anyone who gets the file can see what it contains: names, users, websites, passwords and notes. Verification codes, folders and attachments are not included. Confirm your master password to continue."
        ))
        .close_response("cancel")
        .default_response("cancel")
        .build();
    dialog.add_response("cancel", tr!("Cancel"));
    dialog.add_response("export", tr!("Export unprotected file"));
    dialog.set_response_appearance("export", adw::ResponseAppearance::Destructive);
    let password = adw::PasswordEntryRow::builder()
        .title(tr!("Master password"))
        .build();
    let list = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .build();
    list.add_css_class("boxed-list");
    list.append(&password);
    dialog.set_extra_child(Some(&list));
    dialog.set_response_enabled("export", false);
    {
        let dialog = dialog.clone();
        password.connect_changed(move |row| {
            dialog.set_response_enabled("export", !row.text().is_empty());
        });
    }
    let anchor_cl = anchor.clone();
    let tracked_state = Rc::downgrade(&state);
    dialog.connect_response(None, move |_, response| {
        if response != "export" {
            return;
        }
        let ok = state
            .vault
            .borrow()
            .verify_master_password(&password.text())
            .unwrap_or(false);
        if !ok {
            show_toast(
                &toast,
                tr!("Incorrect master password. Nothing was exported."),
            );
            return;
        }
        run_export_csv(state.clone(), toast.clone(), anchor_cl.clone());
    });
    let tracked = dialog.clone();
    dialog.present(Some(&anchor));
    if let Some(state) = tracked_state.upgrade() {
        state.track_sensitive_dialog(&tracked);
    }
}

/// Ask for the master password before a sensitive operation. `on_ok` runs
/// only when it is correct.
pub fn confirm_master_password<F>(
    state: &SharedState,
    anchor: &gtk::Widget,
    heading: &str,
    body: &str,
    on_ok: F,
) where
    F: Fn() + 'static,
{
    let dialog = adw::AlertDialog::builder()
        .heading(heading)
        .body(body)
        .close_response("cancel")
        .default_response("ok")
        .build();
    dialog.add_response("cancel", tr!("Cancel"));
    dialog.add_response("ok", tr!("Continue"));
    dialog.set_response_appearance("ok", adw::ResponseAppearance::Suggested);
    let password = adw::PasswordEntryRow::builder()
        .title(tr!("Master password"))
        .activates_default(true)
        .build();
    let list = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .build();
    list.add_css_class("boxed-list");
    list.append(&password);
    dialog.set_extra_child(Some(&list));
    let state_cl = state.clone();
    let anchor_cl = anchor.clone();
    dialog.connect_response(None, move |_, response| {
        if response != "ok" {
            return;
        }
        let ok = state_cl
            .vault
            .borrow()
            .verify_master_password(&password.text())
            .unwrap_or(false);
        if ok {
            on_ok();
        } else {
            let warn = adw::AlertDialog::builder()
                .heading(tr!("Incorrect master password"))
                .body(tr!("Nothing was changed."))
                .build();
            warn.add_response("ok", tr!("OK"));
            warn.present(Some(&anchor_cl));
        }
    });
    state.track_sensitive_dialog(&dialog);
    dialog.present(Some(anchor));
}

/// Ask for a new password twice (for a backup or export file).
pub fn ask_new_password<F>(anchor: &gtk::Widget, heading: &str, body: &str, on_ok: F)
where
    F: Fn(Zeroizing<String>) + 'static,
{
    let parent = anchor.root().and_then(|r| r.downcast::<gtk::Window>().ok());
    prompt_password(parent.as_ref(), heading, body, true, move |password| {
        on_ok(Zeroizing::new(password));
    });
}

pub fn run_background_task<T, F, C>(task: F, complete: C)
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
    C: FnOnce(T) + 'static,
{
    run_background(task, complete);
}

/// Deleted items, opened from "My passwords".
pub fn present_trash(parent: &impl IsA<gtk::Widget>, state: SharedState) {
    let toast = adw::ToastOverlay::new();
    let page = adw::PreferencesPage::new();
    let settings = Rc::new(RefCell::new(Settings::load()));
    populate_trash(&page, state.clone(), settings, toast.clone().into());
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&adw::HeaderBar::new());
    toolbar.set_content(Some(&page));
    toast.set_child(Some(&toolbar));
    let dialog = adw::Dialog::builder()
        .title(tr!("Deleted items"))
        .content_width(640)
        .content_height(600)
        .child(&toast)
        .build();
    state.track_sensitive_dialog(&dialog);
    dialog.present(Some(parent));
}

/// Google Drive and WebDAV copies, opened from the Backups page.
pub fn present_cloud_backups(parent: &impl IsA<gtk::Widget>, state: SharedState) {
    let toast = adw::ToastOverlay::new();
    let page = adw::PreferencesPage::new();
    let slot: Rc<RefCell<Option<adw::Dialog>>> = Rc::new(RefCell::new(None));
    populate_cloud(
        &page,
        state.clone(),
        toast.clone().into(),
        parent.clone().upcast(),
        slot.clone(),
    );
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&adw::HeaderBar::new());
    toolbar.set_content(Some(&page));
    toast.set_child(Some(&toolbar));
    let dialog = adw::Dialog::builder()
        .title(tr!("Copies in the cloud"))
        .content_width(680)
        .content_height(640)
        .child(&toast)
        .build();
    *slot.borrow_mut() = Some(dialog.clone());
    state.track_sensitive_dialog(&dialog);
    dialog.present(Some(parent));
}
