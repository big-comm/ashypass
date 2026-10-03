//! Import with a preview and an honest result.
//!
//! 1. The user picked a source (Bitwarden, a browser, KeePass…) and a file.
//! 2. The file is read off the main thread and compared with the vault —
//!    nothing is written yet.
//! 3. A preview says how many items were recognised, how many are already
//!    in the vault, and what cannot be imported and why.
//! 4. Only then the import runs, in one transaction, and the result separates
//!    a complete import from a partial one: "imported" never hides skipped
//!    items.

use crate::state::SharedState;
use crate::tr;
use crate::trn;
use crate::ui::settings_dialog::{run_background_task, ImportSource};
use adw::prelude::*;
use ashypass_core::importers::{
    self, ImportPreview, ImportReport, ImportSource as CoreSource, ParsedImport,
};
use gtk::gio;
use std::path::PathBuf;
use zeroize::Zeroizing;

const MAX_LISTED_ISSUES: usize = 30;

pub fn start(
    state: SharedState,
    toast: adw::ToastOverlay,
    source: ImportSource,
    anchor: gtk::Widget,
) {
    if !state.vault.borrow().is_unlocked() {
        return;
    }
    let (title, filter_name, suffixes): (&str, &str, &[&str]) = match source {
        ImportSource::Bitwarden => (tr!("Choose the Bitwarden export"), "JSON", &["json"]),
        ImportSource::Onepassword => (tr!("Choose the 1Password export"), "1PUX", &["1pux"]),
        ImportSource::Keepass => (tr!("Choose the KeePass database"), "KeePass", &["kdbx"]),
        ImportSource::BrowserCsv | ImportSource::OtherCsv => {
            (tr!("Choose the CSV file"), "CSV", &["csv"])
        }
        ImportSource::Aegis => (tr!("Choose the Aegis export"), "JSON", &["json"]),
        ImportSource::Andotp => (tr!("Choose the andOTP export"), "JSON", &["json"]),
        ImportSource::AshyMerge => (tr!("Choose the Ashy Pass backup"), "Ashy Pass", &["ashy"]),
    };
    let filter = gtk::FileFilter::new();
    filter.set_name(Some(filter_name));
    for suffix in suffixes {
        filter.add_suffix(suffix);
    }
    let filters = gio::ListStore::new::<gtk::FileFilter>();
    filters.append(&filter);
    let dialog = gtk::FileDialog::builder()
        .title(title)
        .modal(true)
        .filters(&filters)
        .build();
    let parent = anchor.root().and_then(|r| r.downcast::<gtk::Window>().ok());
    dialog.open(parent.as_ref(), None::<&gio::Cancellable>, move |result| {
        let Ok(file) = result else { return };
        let Some(path) = file.path() else { return };
        match source {
            ImportSource::Keepass | ImportSource::AshyMerge => {
                let heading = if source == ImportSource::Keepass {
                    tr!("Password of the KeePass database")
                } else {
                    tr!("Password of the backup")
                };
                ask_password(&anchor, heading, {
                    let state = state.clone();
                    let toast = toast.clone();
                    let anchor = anchor.clone();
                    let path = path.clone();
                    move |password| {
                        let core = if source == ImportSource::Keepass {
                            CoreSource::KeePass {
                                password: password.to_string(),
                            }
                        } else {
                            CoreSource::Ashy {
                                password: password.to_string(),
                            }
                        };
                        analyse(
                            state.clone(),
                            toast.clone(),
                            anchor.clone(),
                            core,
                            path.clone(),
                        );
                    }
                });
            }
            other => {
                let core = match other {
                    ImportSource::Bitwarden => CoreSource::Bitwarden,
                    ImportSource::Onepassword => CoreSource::OnePassword,
                    ImportSource::Aegis => CoreSource::Aegis,
                    ImportSource::Andotp => CoreSource::Andotp,
                    _ => CoreSource::Csv,
                };
                analyse(state.clone(), toast.clone(), anchor.clone(), core, path);
            }
        }
    });
}

fn ask_password<F>(anchor: &gtk::Widget, heading: &str, done: F)
where
    F: Fn(Zeroizing<String>) + 'static,
{
    let dialog = adw::AlertDialog::builder()
        .heading(heading)
        .close_response("cancel")
        .default_response("ok")
        .build();
    dialog.add_response("cancel", tr!("Cancel"));
    dialog.add_response("ok", tr!("Continue"));
    dialog.set_response_appearance("ok", adw::ResponseAppearance::Suggested);
    let row = adw::PasswordEntryRow::builder()
        .title(tr!("Password"))
        .activates_default(true)
        .build();
    let list = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .build();
    list.add_css_class("boxed-list");
    list.append(&row);
    dialog.set_extra_child(Some(&list));
    dialog.connect_response(None, move |_, response| {
        if response == "ok" && !row.text().is_empty() {
            done(Zeroizing::new(row.text().to_string()));
        }
    });
    dialog.present(Some(anchor));
}

fn toast_message(toast: &adw::ToastOverlay, message: &str) {
    toast.add_toast(adw::Toast::builder().title(message).timeout(5).build());
}

/// Read and compare with the vault in the background, then show the preview.
pub(crate) fn analyse(
    state: SharedState,
    toast: adw::ToastOverlay,
    anchor: gtk::Widget,
    source: CoreSource,
    path: PathBuf,
) {
    let parts = match state.vault.borrow().session_reopen_parts() {
        Ok(parts) => parts,
        Err(e) => {
            toast_message(&toast, &format!("{}: {e}", tr!("Nothing was imported")));
            return;
        }
    };
    toast_message(&toast, tr!("Reading the file…"));
    run_background_task(
        move || -> ashypass_core::Result<(ParsedImport, ImportPreview)> {
            let vault = ashypass_core::db::Vault::open_with_session_key(parts.0, parts.1)?;
            let parsed = importers::parse_source(&source, &path)?;
            let preview = importers::preview(&vault, &parsed)?;
            Ok((parsed, preview))
        },
        move |outcome| match outcome {
            // Locked while reading: the preview would list entries over a
            // locked vault. Drop it; nothing was written.
            Ok(_) if !state.vault.borrow().is_unlocked() => {}
            Ok((parsed, preview)) => show_preview(state, toast, anchor, parsed, preview),
            Err(e) => {
                let dialog = adw::AlertDialog::builder()
                    .heading(tr!("This file could not be read"))
                    .body(format!(
                        "{}\n\n{e}",
                        tr!("Nothing was imported. Check that you chose the right app and an unencrypted export.")
                    ))
                    .build();
                dialog.add_response("ok", tr!("OK"));
                dialog.present(Some(&anchor));
            }
        },
    );
}

pub fn preview_text(preview: &ImportPreview) -> String {
    let mut lines = vec![trn!(
        "{} item will be imported.",
        "{} items will be imported.",
        preview.recognized
    )
    .replace("{}", &preview.recognized.to_string())];
    if preview.duplicates > 0 {
        lines.push(
            trn!(
                "{} is already in the vault and will be skipped.",
                "{} are already in the vault and will be skipped.",
                preview.duplicates
            )
            .replace("{}", &preview.duplicates.to_string()),
        );
    }
    if preview.similar > 0 {
        lines.push(
            trn!(
                "{} looks like an existing entry but has different content; it will be added, nothing is overwritten.",
                "{} look like existing entries but have different content; they will be added, nothing is overwritten.",
                preview.similar
            )
            .replace("{}", &preview.similar.to_string()),
        );
    }
    if !preview.unsupported.is_empty() {
        lines.push(
            trn!(
                "{} cannot be imported.",
                "{} cannot be imported.",
                preview.unsupported.len()
            )
            .replace("{}", &preview.unsupported.len().to_string()),
        );
    }
    if !preview.warnings.is_empty() {
        lines.push(
            trn!(
                "{} will be imported with an adjustment.",
                "{} will be imported with adjustments.",
                preview.warnings.len()
            )
            .replace("{}", &preview.warnings.len().to_string()),
        );
    }
    lines.join("\n")
}

fn issues_list(lines: Vec<String>) -> Option<gtk::Widget> {
    if lines.is_empty() {
        return None;
    }
    let total = lines.len();
    let mut text: Vec<String> = lines.into_iter().take(MAX_LISTED_ISSUES).collect();
    if total > MAX_LISTED_ISSUES {
        text.push(
            trn!("… and {} more", "… and {} more", total - MAX_LISTED_ISSUES)
                .replace("{}", &(total - MAX_LISTED_ISSUES).to_string()),
        );
    }
    let label = gtk::Label::builder()
        .label(text.join("\n"))
        .xalign(0.0)
        .wrap(true)
        .selectable(true)
        .margin_top(8)
        .margin_bottom(8)
        .margin_start(10)
        .margin_end(10)
        .build();
    label.add_css_class("caption");
    let scrolled = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .max_content_height(220)
        .propagate_natural_height(true)
        .child(&label)
        .build();
    let frame = gtk::Frame::builder().child(&scrolled).build();
    let expander = gtk::Expander::builder()
        .label(tr!("Details"))
        .child(&frame)
        .build();
    Some(expander.upcast())
}

fn show_preview(
    state: SharedState,
    toast: adw::ToastOverlay,
    anchor: gtk::Widget,
    parsed: ParsedImport,
    preview: ImportPreview,
) {
    let dialog = adw::AlertDialog::builder()
        .heading(tr!("Before importing"))
        .body(preview_text(&preview))
        .close_response("cancel")
        .default_response("import")
        .build();
    dialog.add_response("cancel", tr!("Cancel"));
    let lines: Vec<String> = preview
        .unsupported
        .iter()
        .chain(&preview.warnings)
        .map(|i| format!("{}: {}", i.title, i.reason))
        .collect();
    if let Some(details) = issues_list(lines) {
        dialog.set_extra_child(Some(&details));
    }
    if preview.recognized == 0 {
        dialog.set_body(&format!(
            "{}\n\n{}",
            preview_text(&preview),
            tr!("There is nothing new to import.")
        ));
    } else {
        dialog.add_response("import", tr!("Import"));
        dialog.set_response_appearance("import", adw::ResponseAppearance::Suggested);
    }
    let parsed = std::cell::RefCell::new(Some(parsed));
    let anchor_cl = anchor.clone();
    dialog.connect_response(None, move |_, response| {
        if response != "import" {
            return;
        }
        let Some(parsed) = parsed.borrow_mut().take() else {
            return;
        };
        apply(state.clone(), toast.clone(), anchor_cl.clone(), parsed);
    });
    dialog.present(Some(&anchor));
}

fn apply(state: SharedState, toast: adw::ToastOverlay, anchor: gtk::Widget, parsed: ParsedImport) {
    let parts = match state.vault.borrow().session_reopen_parts() {
        Ok(parts) => parts,
        Err(e) => {
            toast_message(&toast, &format!("{}: {e}", tr!("Nothing was imported")));
            return;
        }
    };
    run_background_task(
        move || -> ashypass_core::Result<ImportReport> {
            let vault = ashypass_core::db::Vault::open_with_session_key(parts.0, parts.1)?;
            importers::apply(&vault, parsed)
        },
        move |outcome| {
            state.events.emit(crate::events::AppEvent::VaultChanged);
            match outcome {
                Ok(report) => show_report(&anchor, &report),
                Err(e) => {
                    let dialog = adw::AlertDialog::builder()
                        .heading(tr!("Nothing was imported"))
                        .body(format!(
                            "{}\n\n{e}",
                            tr!("The import stopped and every change was undone. Your vault is as it was.")
                        ))
                        .build();
                    dialog.add_response("ok", tr!("OK"));
                    dialog.present(Some(&anchor));
                }
            }
        },
    );
}

pub fn report_heading(report: &ImportReport) -> String {
    if report.imported == 0 {
        tr!("Nothing was imported").to_string()
    } else if report.is_complete() {
        tr!("Import complete").to_string()
    } else {
        tr!("Import partly complete").to_string()
    }
}

pub fn report_text(report: &ImportReport) -> String {
    let mut lines = vec![
        trn!("{} item imported.", "{} items imported.", report.imported)
            .replace("{}", &report.imported.to_string()),
    ];
    if report.duplicates > 0 {
        lines.push(
            trn!(
                "{} was already in the vault.",
                "{} were already in the vault.",
                report.duplicates
            )
            .replace("{}", &report.duplicates.to_string()),
        );
    }
    let not_imported = report.skipped.len() + report.failed.len();
    if not_imported > 0 {
        lines.push(
            trn!(
                "{} was not imported — see the details.",
                "{} were not imported — see the details.",
                not_imported
            )
            .replace("{}", &not_imported.to_string()),
        );
    }
    if !report.warnings.is_empty() {
        lines.push(
            trn!(
                "{} was imported with an adjustment — see the details.",
                "{} were imported with adjustments — see the details.",
                report.warnings.len()
            )
            .replace("{}", &report.warnings.len().to_string()),
        );
    }
    if report.imported > 0 {
        lines
            .push(tr!("Delete the export file if it was not protected by a password.").to_string());
    }
    lines.join("\n")
}

fn show_report(anchor: &gtk::Widget, report: &ImportReport) {
    let dialog = adw::AlertDialog::builder()
        .heading(report_heading(report))
        .body(report_text(report))
        .build();
    if let Some(details) = issues_list(report.issue_lines()) {
        dialog.set_extra_child(Some(&details));
    }
    dialog.add_response("ok", tr!("OK"));
    dialog.present(Some(anchor));
}

#[cfg(test)]
mod tests {
    use super::*;
    use ashypass_core::importers::ImportIssue;

    #[test]
    fn partial_imports_never_read_as_complete() {
        let mut report = ImportReport {
            imported: 10,
            ..Default::default()
        };
        assert_eq!(report_heading(&report), "Import complete");
        report
            .skipped
            .push(ImportIssue::new("Card", "unsupported type"));
        assert_eq!(report_heading(&report), "Import partly complete");
        assert!(report_text(&report).contains("1 was not imported"));
        let none = ImportReport::default();
        assert_eq!(report_heading(&none), "Nothing was imported");
    }

    #[test]
    fn preview_mentions_duplicates_and_unsupported() {
        let preview = ImportPreview {
            recognized: 3,
            duplicates: 2,
            similar: 0,
            unsupported: vec![ImportIssue::new("x", "y")],
            warnings: vec![],
        };
        let text = preview_text(&preview);
        assert!(text.contains("3 items will be imported."));
        assert!(text.contains("2 are already in the vault"));
        assert!(text.contains("1 cannot be imported."));
    }
}
