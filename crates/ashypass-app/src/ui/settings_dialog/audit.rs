//! `settings_dialog` — audit section.

use super::*;

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

pub(super) fn populate_audit(
    page: &adw::PreferencesPage,
    state: SharedState,
    settings: Rc<RefCell<Settings>>,
    toast: adw::ToastOverlay,
    parent: gtk::Widget,
    dialog_slot: Rc<RefCell<Option<adw::Dialog>>>,
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
            save_settings(&settings.borrow());
        });
    }
    opts_group.add(&hibp_row);
    let run_row = adw::ActionRow::builder()
        .title(tr!("Run Audit"))
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
                trigger.set_title(tr!("Run Audit"));
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

        glib::timeout_add_local(
            std::time::Duration::from_millis(150),
            move || match receiver.try_recv() {
                Ok(Ok(report)) => {
                    render_audit_report(
                        &report,
                        &summary_row,
                        &findings_group,
                        &finding_rows,
                        &toast,
                    );
                    trigger.set_title(tr!("Run Audit"));
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
                    trigger.set_title(tr!("Run Audit"));
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
                    trigger.set_title(tr!("Run Audit"));
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
}

pub(super) fn render_audit_report(
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
