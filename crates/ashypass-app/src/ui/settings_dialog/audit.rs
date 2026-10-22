//! `settings_dialog` — audit section.

use super::*;

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

pub(super) fn populate_audit(
    page: &adw::PreferencesPage,
    state: SharedState,
    settings: Rc<RefCell<Settings>>,
    toast: Toaster,
    parent: gtk::Widget,
    dialog_slot: Rc<RefCell<Option<adw::Dialog>>>,
) {
    let duplicates = build_duplicates_group(state.clone(), toast.clone());
    let opts_group = adw::PreferencesGroup::builder()
        .title(tr!("Check my passwords"))
        .description(tr!(
            "Looks for weak, repeated and old passwords, accounts without a verification code and, if you allow it, passwords that appeared in known data breaches."
        ))
        .build();
    let hibp_row = adw::SwitchRow::builder()
        .title(tr!("Check known data breaches (online)"))
        .subtitle(tr!(
            "Uses Have I Been Pwned. Only the first 5 characters of a hash of each password are sent, never the password. Results are kept on this computer for 7 days."
        ))
        .active(settings.borrow().audit_check_hibp)
        .build();
    {
        let settings = settings.clone();
        let state_s = state.clone();
        hibp_row.connect_active_notify(move |row| {
            let value = row.is_active();
            settings.borrow_mut().audit_check_hibp = value;
            // Persist through the shared state: saving this page's snapshot
            // would write back stale values changed on other pages.
            if let Err(e) = state_s.update_settings(|s| s.audit_check_hibp = value) {
                log::warn!("could not save settings: {e}");
            }
        });
    }
    opts_group.add(&hibp_row);
    let run_row = adw::ActionRow::builder()
        .title(tr!("Check now"))
        .activatable(true)
        .build();
    let run_spinner = gtk::Spinner::new();
    run_spinner.set_visible(false);
    let run_arrow = gtk::Image::from_icon_name("go-next-symbolic");
    run_row.add_suffix(&run_spinner);
    run_row.add_suffix(&run_arrow);
    opts_group.add(&run_row);
    page.add(&opts_group);

    let summary_group = adw::PreferencesGroup::builder()
        .title(tr!("Summary"))
        .build();
    let summary_row = adw::ActionRow::builder()
        .title(tr!("Not run yet"))
        .subtitle("")
        .use_markup(false)
        .build();
    summary_group.add(&summary_row);
    page.add(&summary_group);

    let findings_group = adw::PreferencesGroup::builder()
        .title(tr!("Findings"))
        .build();
    page.add(&findings_group);

    let finding_rows: Rc<RefCell<Vec<adw::ActionRow>>> = Rc::new(RefCell::new(Vec::new()));
    let findings_group_cl = findings_group.clone();
    let summary_row_cl = summary_row.clone();
    let hibp_row_cl = hibp_row.clone();
    let finding_rows_cl = finding_rows.clone();
    let run_spinner_cl = run_spinner.clone();
    let run_arrow_cl = run_arrow.clone();
    run_row.connect_activated(move |trigger| {
        if !state.vault.borrow().is_unlocked() {
            show_toast(&toast, tr!("Unlock the vault first"));
            show_settings_unlock_dialog(&parent, state.clone(), toast.clone(), dialog_slot.clone());
            return;
        }
        let state = state.clone();
        let toast = toast.clone();
        let findings_group = findings_group_cl.clone();
        let summary_row = summary_row_cl.clone();
        let hibp_row = hibp_row_cl.clone();
        let finding_rows = finding_rows_cl.clone();
        let run_spinner = run_spinner_cl.clone();
        let run_arrow = run_arrow_cl.clone();
        let trigger = trigger.clone();
        trigger.set_sensitive(false);
        trigger.set_title(tr!("Running audit..."));
        trigger.set_subtitle(tr!("Scanning vault..."));
        run_arrow.set_visible(false);
        run_spinner.set_visible(true);
        run_spinner.start();
        for existing in finding_rows.borrow_mut().drain(..) {
            findings_group.remove(&existing);
        }
        let (db_path, session_key) = match state.vault.borrow().session_reopen_parts() {
            Ok(parts) => parts,
            Err(e) => {
                show_toast(&toast, &format!("{}: {e}", tr!("Audit failed")));
                trigger.set_title(tr!("Check now"));
                trigger.set_subtitle("");
                trigger.set_sensitive(true);
                run_spinner.stop();
                run_spinner.set_visible(false);
                run_arrow.set_visible(true);
                return;
            }
        };
        let mut opts = ashypass_core::audit::AuditOptions::defaults();
        opts.check_hibp = hibp_row.is_active();
        summary_row.set_title(tr!("Running audit..."));
        summary_row.set_subtitle(tr!("Scanning vault..."));
        show_toast(&toast, tr!("Running audit..."));

        let (sender, receiver) = std::sync::mpsc::channel::<AuditResult>();
        std::thread::spawn(move || {
            let outcome = (|| {
                let vault = ashypass_core::db::Vault::open_with_session_key(db_path, session_key)?;
                ashypass_core::audit::run(&vault, opts)
            })()
            .map_err(|e| e.to_string());
            let _ = sender.send(outcome);
        });

        let state_done = state.clone();
        glib::timeout_add_local(
            std::time::Duration::from_millis(150),
            move || match receiver.try_recv() {
                // Locked meanwhile: never show entry names over a locked vault.
                Ok(_) if !state_done.vault.borrow().is_unlocked() => glib::ControlFlow::Break,
                Ok(Ok(report)) => {
                    render_audit_report(
                        &report,
                        &summary_row,
                        &findings_group,
                        &finding_rows,
                        &toast,
                    );
                    trigger.set_title(tr!("Check now"));
                    trigger.set_subtitle("");
                    trigger.set_sensitive(true);
                    run_spinner.stop();
                    run_spinner.set_visible(false);
                    run_arrow.set_visible(true);
                    glib::ControlFlow::Break
                }
                Ok(Err(e)) => {
                    show_toast(&toast, &format!("{}: {e}", tr!("Audit failed")));
                    summary_row.set_title(tr!("Audit failed"));
                    summary_row.set_subtitle(&e);
                    trigger.set_title(tr!("Check now"));
                    trigger.set_subtitle("");
                    trigger.set_sensitive(true);
                    run_spinner.stop();
                    run_spinner.set_visible(false);
                    run_arrow.set_visible(true);
                    glib::ControlFlow::Break
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => glib::ControlFlow::Continue,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    show_toast(&toast, tr!("Audit failed"));
                    summary_row.set_title(tr!("Audit failed"));
                    summary_row.set_subtitle("");
                    trigger.set_title(tr!("Check now"));
                    trigger.set_subtitle("");
                    trigger.set_sensitive(true);
                    run_spinner.stop();
                    run_spinner.set_visible(false);
                    run_arrow.set_visible(true);
                    glib::ControlFlow::Break
                }
            },
        );
    });
    page.add(&duplicates);
}

/// Settings → Protection → Duplicate items: the same site and account, or
/// the same two-step code, more than once. Merging keeps one item and moves
/// the rest to the trash.
fn build_duplicates_group(state: SharedState, toast: Toaster) -> adw::PreferencesGroup {
    let group = adw::PreferencesGroup::builder()
        .title(tr!("Duplicate items"))
        .description(tr!(
            "Logins of the same site and account, or items with the same verification code, left by imports or by two syncs. Merging keeps one, brings into it what only the others had (code, notes, other websites, groups; other passwords go to its history) and moves the others to Deleted items."
        ))
        .build();
    let row = adw::ActionRow::builder()
        .title(tr!("Find duplicate items"))
        .activatable(true)
        .build();
    row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
    row.connect_activated(move |row| {
        if !state.vault.borrow().is_unlocked() {
            show_toast(&toast, tr!("Unlock the vault first"));
            return;
        }
        let found = ashypass_core::duplicates::find_duplicates(&state.vault.borrow());
        match found {
            Ok(groups) if groups.is_empty() => show_toast(&toast, tr!("No duplicate items")),
            Ok(groups) => present_duplicates(row, state.clone(), toast.clone(), groups),
            Err(e) => show_toast(&toast, &format!("{}: {e}", tr!("Could not check"))),
        }
    });
    group.add(&row);
    group
}

fn present_duplicates(
    anchor: &adw::ActionRow,
    state: SharedState,
    toast: Toaster,
    groups: Vec<ashypass_core::duplicates::DuplicateGroup>,
) {
    use ashypass_core::duplicates::{merge_duplicates, DuplicateReason};
    let page = adw::PreferencesPage::new();
    let count = groups.len();
    for found in groups {
        let section = adw::PreferencesGroup::builder()
            .title(glib::markup_escape_text(&found.label).as_str())
            .description(match found.reason {
                DuplicateReason::SameLogin => tr!("Same site and account"),
                DuplicateReason::SameCode => tr!("Same verification code"),
            })
            .build();
        let mut first: Option<gtk::CheckButton> = None;
        let choices: Rc<RefCell<Vec<(i64, gtk::CheckButton)>>> = Rc::default();
        for (i, member) in found.members.iter().enumerate() {
            let check = gtk::CheckButton::builder()
                .active(i == 0)
                .valign(gtk::Align::Center)
                .build();
            match &first {
                Some(f) => check.set_group(Some(f)),
                None => first = Some(check.clone()),
            }
            let when = chrono::DateTime::from_timestamp(member.updated_at, 0)
                .map(|t| t.with_timezone(&chrono::Local).format("%x").to_string())
                .unwrap_or_default();
            let mut details = vec![member.username.clone(), member.url.clone()];
            details.retain(|d| !d.is_empty());
            details.push(format!("{} {when}", tr!("Changed")));
            if member.password_differs {
                details.push(tr!("different password").to_string());
            }
            let item = adw::ActionRow::builder()
                .title(glib::markup_escape_text(&member.title).as_str())
                .subtitle(glib::markup_escape_text(&details.join(" · ")).as_str())
                .activatable_widget(&check)
                .build();
            item.add_prefix(&check);
            section.add(&item);
            choices.borrow_mut().push((member.id, check));
        }
        let merge = gtk::Button::builder()
            .label(tr!("Merge, keeping the selected one"))
            .halign(gtk::Align::End)
            .margin_top(6)
            .build();
        merge.add_css_class("suggested-action");
        {
            let state = state.clone();
            let toast = toast.clone();
            // Weak: the button sits in the section's header.
            let section = section.downgrade();
            let choices = choices.clone();
            merge.connect_clicked(move |button| {
                let ids: Vec<i64> = choices.borrow().iter().map(|(id, _)| *id).collect();
                let Some(keep) = choices
                    .borrow()
                    .iter()
                    .find(|(_, c)| c.is_active())
                    .map(|(id, _)| *id)
                else {
                    return;
                };
                let others: Vec<i64> = ids.into_iter().filter(|id| *id != keep).collect();
                let merged = merge_duplicates(&state.vault.borrow(), keep, &others);
                match merged {
                    Ok(()) => {
                        button.set_sensitive(false);
                        if let Some(section) = section.upgrade() {
                            section.set_sensitive(false);
                            section.set_description(Some(tr!("Merged")));
                        }
                        show_toast(&toast, tr!("Merged; the others are in Deleted items"));
                    }
                    Err(e) => show_toast(&toast, &format!("{}: {e}", tr!("Could not merge"))),
                }
            });
        }
        section.set_header_suffix(Some(&merge));
        page.add(&section);
    }
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&adw::HeaderBar::new());
    toolbar.set_content(Some(&page));
    let dialog = big_gtk_kit::dialog::Dialog::builder(Some(anchor))
        .title(format!("{} ({count})", tr!("Duplicate items")))
        .content_width(640)
        .content_height(620)
        .child(&toolbar)
        .build();
    state.track_sensitive_dialog(&dialog);
    dialog.present();
}

pub(super) fn render_audit_report(
    report: &ashypass_core::audit::Report,
    summary_row: &adw::ActionRow,
    findings_group: &adw::PreferencesGroup,
    finding_rows: &Rc<RefCell<Vec<adw::ActionRow>>>,
    toast: &Toaster,
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
            .use_markup(false)
            .build();
        let chip = gtk::Label::new(Some(crate::ui::i18n::localized_strength_label(
            f.strength_label,
        )));
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
