//! "Backups": make a protected copy, restore one, bring passwords from
//! another app, or take them to one.
//!
//! The page answers the questions a person actually has: when was the last
//! copy made, where is it, what does it contain, and which password opens it.
//! A protected copy is the normal path; a file anyone can read is a separate,
//! explicit choice with its own warning and a master password check.
//!
//! Backups are not synchronization: Nextcloud Passwords and WebDAV sync live
//! in Settings → Synchronization.

use crate::state::SharedState;
use crate::tr;
use crate::ui::settings_dialog::{self, ImportSource};
use crate::ui::widgets::{page_heading, Chrome};
use adw::prelude::*;
use gtk::{gio, glib};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::rc::Rc;

/// What the app remembers about the last backup it made on this computer.
/// Kept apart from settings.json: it is a record, not a preference.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupStatus {
    pub when: i64,
    pub location: String,
    pub entries: usize,
}

fn status_path() -> PathBuf {
    ashypass_core::config::config_dir().join("backup-status.json")
}

pub fn load_status() -> Option<BackupStatus> {
    let text = std::fs::read_to_string(status_path()).ok()?;
    serde_json::from_str(&text).ok()
}

pub fn save_status(status: &BackupStatus) {
    let result = (|| -> std::io::Result<()> {
        let path = status_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_vec_pretty(status)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, json)?;
        std::fs::rename(tmp, path)
    })();
    if let Err(e) = result {
        log::warn!("could not record backup status: {e}");
    }
}

pub struct BackupsView {
    pub root: adw::NavigationView,
    inner: Rc<Inner>,
}

struct Inner {
    state: SharedState,
    toast: adw::ToastOverlay,
    nav: adw::NavigationView,
    status_row: adw::ActionRow,
    status_icon: gtk::Image,
    import_page: adw::NavigationPage,
}

impl BackupsView {
    pub fn new(state: SharedState, toast: adw::ToastOverlay, chrome: &Chrome) -> Rc<Self> {
        let nav = adw::NavigationView::new();

        // ---- Main page -------------------------------------------------
        let content = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(20)
            .margin_top(12)
            .margin_bottom(24)
            .margin_start(18)
            .margin_end(18)
            .build();
        content.append(&page_heading(
            tr!("Backups"),
            Some(tr!(
                "Keep a protected copy of your vault somewhere safe, and bring your passwords in or out."
            )),
        ));

        let status_group = adw::PreferencesGroup::new();
        let status_row = adw::ActionRow::builder().use_markup(false).build();
        let status_icon = gtk::Image::builder().pixel_size(32).build();
        status_icon.set_accessible_role(gtk::AccessibleRole::Presentation);
        status_row.add_prefix(&status_icon);
        status_group.add(&status_row);
        content.append(&status_group);

        let actions = gtk::Box::builder()
            .orientation(gtk::Orientation::Horizontal)
            .spacing(12)
            .homogeneous(true)
            .build();
        let create = gtk::Button::with_label(tr!("Create backup"));
        create.add_css_class("pill");
        create.add_css_class("suggested-action");
        let restore = gtk::Button::with_label(tr!("Restore a backup"));
        restore.add_css_class("pill");
        actions.append(&create);
        actions.append(&restore);
        content.append(&actions);

        let about = adw::PreferencesGroup::builder()
            .title(tr!("About the backup"))
            .build();
        for (icon, title, subtitle) in [
            (
                "channel-secure-symbolic",
                tr!("Protected by a password you choose"),
                tr!("You choose it when creating the copy. Without it the copy cannot be opened — Ashy Pass cannot recover it."),
            ),
            (
                "view-list-symbolic",
                tr!("What it contains"),
                tr!("Passwords, notes, verification codes, folders, favorites and tags. A full restore also brings back attachments and password history."),
            ),
            (
                "document-save-symbolic",
                tr!("Where it goes"),
                tr!("Wherever you save the file. Keep it off this computer too — on a USB drive or in your own cloud storage."),
            ),
        ] {
            let row = adw::ActionRow::builder()
                .title(title)
                .subtitle(subtitle)
                .use_markup(false)
                .build();
            row.add_prefix(&gtk::Image::from_icon_name(icon));
            about.add(&row);
        }
        content.append(&about);

        let data_group = adw::PreferencesGroup::builder()
            .title(tr!("Other apps"))
            .build();
        let import_row = adw::ActionRow::builder()
            .title(tr!("Import passwords"))
            .subtitle(tr!("Bring passwords from another app or browser"))
            .activatable(true)
            .build();
        import_row.add_prefix(&gtk::Image::from_icon_name("document-open-symbolic"));
        import_row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
        data_group.add(&import_row);
        let export_row = adw::ActionRow::builder()
            .title(tr!("Take my data to another app"))
            .subtitle(tr!("Export to KeePass or to a file anyone can read"))
            .activatable(true)
            .build();
        export_row.add_prefix(&gtk::Image::from_icon_name("document-send-symbolic"));
        export_row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
        data_group.add(&export_row);
        content.append(&data_group);

        let cloud_group = adw::PreferencesGroup::builder()
            .title(tr!("Copies in the cloud"))
            .description(tr!(
                "Upload an encrypted copy of the vault to Google Drive or a WebDAV server. This is a backup, not synchronization."
            ))
            .build();
        let cloud_row = adw::ActionRow::builder()
            .title(tr!("Google Drive and WebDAV"))
            .subtitle(tr!("Set up, upload or download cloud copies"))
            .activatable(true)
            .build();
        cloud_row.add_prefix(&gtk::Image::from_icon_name("folder-remote-symbolic"));
        cloud_row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
        cloud_group.add(&cloud_row);
        content.append(&cloud_group);

        let clamp = adw::Clamp::builder()
            .maximum_size(720)
            .child(&content)
            .build();
        let scrolled = gtk::ScrolledWindow::builder()
            .hscrollbar_policy(gtk::PolicyType::Never)
            .vexpand(true)
            .child(&clamp)
            .build();
        let main_toolbar = adw::ToolbarView::new();
        main_toolbar.add_top_bar(&chrome.header(None));
        main_toolbar.set_content(Some(&scrolled));
        let main_page = adw::NavigationPage::builder()
            .title(tr!("Backups"))
            .tag("main")
            .child(&main_toolbar)
            .build();
        nav.add(&main_page);

        let import_page = build_import_page(&state, &toast);
        let inner = Rc::new(Inner {
            state,
            toast,
            nav: nav.clone(),
            status_row,
            status_icon,
            import_page,
        });
        inner.refresh_status();

        {
            let weak = Rc::downgrade(&inner);
            create.connect_clicked(move |button| {
                if let Some(inner) = weak.upgrade() {
                    inner.create_backup(button);
                }
            });
        }
        {
            let weak = Rc::downgrade(&inner);
            restore.connect_clicked(move |button| {
                if let Some(inner) = weak.upgrade() {
                    settings_dialog::restore_backup(
                        inner.state.clone(),
                        inner.toast.clone(),
                        button.clone().upcast(),
                    );
                }
            });
        }
        {
            let weak = Rc::downgrade(&inner);
            import_row.connect_activated(move |_| {
                if let Some(inner) = weak.upgrade() {
                    inner.show_import();
                }
            });
        }
        {
            let weak = Rc::downgrade(&inner);
            export_row.connect_activated(move |row| {
                if let Some(inner) = weak.upgrade() {
                    inner.choose_export(row);
                }
            });
        }
        {
            let weak = Rc::downgrade(&inner);
            cloud_row.connect_activated(move |row| {
                if let Some(inner) = weak.upgrade() {
                    settings_dialog::present_cloud_backups(row, inner.state.clone());
                }
            });
        }

        Rc::new(Self { root: nav, inner })
    }

    pub fn show_import(&self) {
        self.inner.show_import();
    }

    pub fn on_unlocked(&self) {
        self.inner.refresh_status();
    }

    pub fn on_locked(&self) {
        self.inner.nav.pop_to_tag("main");
    }
}

impl Inner {
    fn toast(&self, message: &str) {
        self.toast
            .add_toast(adw::Toast::builder().title(message).timeout(4).build());
    }

    fn show_import(&self) {
        if self.nav.visible_page().and_then(|p| p.tag()).as_deref() != Some("import") {
            self.nav.push(&self.import_page);
        }
    }

    fn refresh_status(&self) {
        match load_status() {
            Some(status) => {
                self.status_icon.set_icon_name(Some("emblem-ok-symbolic"));
                self.status_icon.add_css_class("success");
                self.status_icon.remove_css_class("warning");
                self.status_row
                    .set_title(tr!("Last backup made on this computer"));
                self.status_row.set_subtitle(&format!(
                    "{} · {} · {}",
                    crate::ui::vault_view::format_timestamp(status.when),
                    crate::trn!("{} entry", "{} entries", status.entries)
                        .replace("{}", &status.entries.to_string()),
                    status.location
                ));
            }
            None => {
                self.status_icon
                    .set_icon_name(Some("dialog-warning-symbolic"));
                self.status_icon.add_css_class("warning");
                self.status_icon.remove_css_class("success");
                self.status_row
                    .set_title(tr!("No backup made on this computer yet"));
                self.status_row.set_subtitle(tr!(
                    "If this computer is lost or damaged, a backup is the only way to get your passwords back."
                ));
            }
        }
    }

    /// Protected copy: master password check, a password for the file, a
    /// destination, then the result that was really written.
    fn create_backup(self: &Rc<Self>, anchor: &gtk::Button) {
        let weak = Rc::downgrade(self);
        let anchor_widget: gtk::Widget = anchor.clone().upcast();
        let prompt_anchor = anchor_widget.clone();
        settings_dialog::confirm_master_password(
            &self.state,
            &prompt_anchor,
            tr!("Create backup"),
            tr!("Confirm your master password to create a backup."),
            move || {
                let Some(inner) = weak.upgrade() else { return };
                let weak = Rc::downgrade(&inner);
                settings_dialog::ask_new_password(
                    &anchor_widget,
                    tr!("Password for this backup"),
                    tr!("You will need this password to restore the copy. You may reuse your master password; Ashy Pass cannot recover it."),
                    move |password| {
                        let Some(inner) = weak.upgrade() else { return };
                        inner.save_backup_file(password);
                    },
                );
            },
        );
    }

    fn save_backup_file(self: &Rc<Self>, password: zeroize::Zeroizing<String>) {
        let name = format!(
            "ashypass-backup-{}.ashy",
            glib::DateTime::now_local()
                .ok()
                .and_then(|d| d.format("%Y-%m-%d").ok())
                .map(|s| s.to_string())
                .unwrap_or_default()
        );
        let dialog = gtk::FileDialog::builder()
            .title(tr!("Save backup"))
            .initial_name(&name)
            .modal(true)
            .build();
        let parent = self
            .nav
            .root()
            .and_then(|r| r.downcast::<gtk::Window>().ok());
        let weak = Rc::downgrade(self);
        dialog.save(parent.as_ref(), None::<&gio::Cancellable>, move |result| {
            let Some(inner) = weak.upgrade() else { return };
            let Ok(file) = result else { return };
            let Some(path) = file.path() else { return };
            let parts = match inner.state.vault.borrow().session_reopen_parts() {
                Ok(parts) => parts,
                Err(e) => {
                    inner.toast(&format!("{}: {e}", tr!("The backup was not created")));
                    return;
                }
            };
            let weak = Rc::downgrade(&inner);
            let target = path.clone();
            settings_dialog::run_background_task(
                move || {
                    let vault = ashypass_core::db::Vault::open_with_session_key(parts.0, parts.1)?;
                    ashypass_core::importers::ashy::export_vault(&vault, &target, &password)
                },
                move |outcome: ashypass_core::Result<usize>| {
                    let Some(inner) = weak.upgrade() else { return };
                    match outcome {
                        Ok(entries) => {
                            save_status(&BackupStatus {
                                when: chrono::Utc::now().timestamp(),
                                location: path.display().to_string(),
                                entries,
                            });
                            inner.refresh_status();
                            inner.toast(&format!("{} {}", tr!("Backup created:"), path.display()));
                        }
                        Err(e) => {
                            inner.toast(&format!("{}: {e}", tr!("The backup was not created")))
                        }
                    }
                },
            );
        });
    }

    fn choose_export(self: &Rc<Self>, anchor: &adw::ActionRow) {
        let dialog = adw::AlertDialog::builder()
            .heading(tr!("Take my data to another app"))
            .body(tr!(
                "KeePass keeps the file protected by a password. A CSV file can be read by anyone who gets hold of it."
            ))
            .close_response("cancel")
            .build();
        dialog.add_response("cancel", tr!("Cancel"));
        dialog.add_response("csv", tr!("Unprotected CSV…"));
        dialog.add_response("kdbx", tr!("KeePass (.kdbx)…"));
        dialog.set_response_appearance("kdbx", adw::ResponseAppearance::Suggested);
        dialog.set_default_response(Some("kdbx"));
        let state = self.state.clone();
        let toast = self.toast.clone();
        let anchor_widget: gtk::Widget = anchor.clone().upcast();
        dialog.connect_response(None, move |_, response| match response {
            "kdbx" => {
                let state_cl = state.clone();
                let toast = toast.clone();
                let anchor_cl = anchor_widget.clone();
                settings_dialog::confirm_master_password(
                    &state,
                    &anchor_cl.clone(),
                    tr!("Export to KeePass"),
                    tr!("Confirm your master password to export your data."),
                    move || {
                        settings_dialog::export_kdbx(
                            state_cl.clone(),
                            toast.clone(),
                            anchor_cl.clone(),
                        )
                    },
                );
            }
            "csv" => {
                settings_dialog::export_csv_with_warning(
                    state.clone(),
                    toast.clone(),
                    anchor_widget.clone(),
                );
            }
            _ => {}
        });
        dialog.present(Some(anchor));
    }
}

/// "Where do you want to bring your passwords from?" — sources, not formats.
fn build_import_page(state: &SharedState, toast: &adw::ToastOverlay) -> adw::NavigationPage {
    let content = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(18)
        .margin_top(12)
        .margin_bottom(24)
        .margin_start(18)
        .margin_end(18)
        .build();
    content.append(&page_heading(
        tr!("Import passwords"),
        Some(tr!("Where do you want to bring your passwords from?")),
    ));

    let flow = gtk::FlowBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .min_children_per_line(1)
        .max_children_per_line(2)
        .column_spacing(12)
        .row_spacing(12)
        .homogeneous(true)
        .build();
    let sources: [(ImportSource, &str, &str, &str); 8] = [
        (
            ImportSource::Bitwarden,
            "Bitwarden",
            tr!("Unencrypted JSON export"),
            "dialog-password-symbolic",
        ),
        (
            ImportSource::Onepassword,
            "1Password",
            tr!("1PUX export file"),
            "dialog-password-symbolic",
        ),
        (
            ImportSource::Keepass,
            "KeePass / KeePassXC",
            tr!("Password-protected .kdbx database"),
            "channel-secure-symbolic",
        ),
        (
            ImportSource::BrowserCsv,
            tr!("Browser"),
            tr!("Chrome, Edge, Brave or Firefox password export (CSV)"),
            "web-browser-symbolic",
        ),
        (
            ImportSource::Aegis,
            "Aegis",
            tr!("Verification codes (unencrypted JSON)"),
            "security-high-symbolic",
        ),
        (
            ImportSource::Andotp,
            "andOTP",
            tr!("Verification codes (unencrypted JSON)"),
            "security-high-symbolic",
        ),
        (
            ImportSource::AshyMerge,
            "Ashy Pass",
            tr!("Add the entries of a .ashy backup to this vault"),
            "ashypass",
        ),
        (
            ImportSource::OtherCsv,
            tr!("Other CSV file"),
            tr!("Columns such as name, url, username, password"),
            "text-x-generic-symbolic",
        ),
    ];
    for (source, title, subtitle, icon) in sources {
        let button = gtk::Button::builder().build();
        button.add_css_class("card");
        button.add_css_class("ashy-source-card");
        let row = gtk::Box::builder()
            .orientation(gtk::Orientation::Horizontal)
            .spacing(12)
            .margin_top(10)
            .margin_bottom(10)
            .margin_start(10)
            .margin_end(10)
            .build();
        let image = gtk::Image::builder().icon_name(icon).pixel_size(32).build();
        image.set_accessible_role(gtk::AccessibleRole::Presentation);
        row.append(&image);
        let text = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(2)
            .valign(gtk::Align::Center)
            .build();
        let title_label = gtk::Label::builder().label(title).xalign(0.0).build();
        title_label.add_css_class("heading");
        let subtitle_label = gtk::Label::builder()
            .label(subtitle)
            .xalign(0.0)
            .wrap(true)
            .build();
        subtitle_label.add_css_class("caption");
        subtitle_label.add_css_class("dim-label");
        text.append(&title_label);
        text.append(&subtitle_label);
        row.append(&text);
        button.set_child(Some(&row));
        button.update_property(&[gtk::accessible::Property::Label(&format!(
            "{title}: {subtitle}"
        ))]);
        {
            let state = state.clone();
            let toast = toast.clone();
            button.connect_clicked(move |b| {
                settings_dialog::import_from(
                    state.clone(),
                    toast.clone(),
                    source,
                    b.clone().upcast(),
                );
            });
        }
        flow.append(&button);
    }
    content.append(&flow);

    let note = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(10)
        .build();
    note.add_css_class("ashy-note");
    note.append(&gtk::Image::from_icon_name("dialog-information-symbolic"));
    let note_label = gtk::Label::builder()
        .label(tr!(
            "First export your passwords from the other app, then choose that file here. Before importing you will see what was recognized. Delete unprotected export files afterwards."
        ))
        .wrap(true)
        .xalign(0.0)
        .build();
    note_label.add_css_class("caption");
    note.append(&note_label);
    content.append(&note);

    let clamp = adw::Clamp::builder()
        .maximum_size(760)
        .child(&content)
        .build();
    let scrolled = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .vexpand(true)
        .child(&clamp)
        .build();
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&adw::HeaderBar::new());
    toolbar.set_content(Some(&scrolled));
    adw::NavigationPage::builder()
        .title(tr!("Import passwords"))
        .tag("import")
        .child(&toolbar)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_round_trips() {
        let status = BackupStatus {
            when: 1_700_000_000,
            location: "/tmp/x.ashy".into(),
            entries: 3,
        };
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(serde_json::from_str::<BackupStatus>(&json).unwrap(), status);
    }
}
