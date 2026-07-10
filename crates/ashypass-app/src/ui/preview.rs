//! Dev-only preview harnesses for dialogs that normally require an external
//! configured service (Nextcloud Passwords sync, FIDO2 enrolment, etc.).
//!
//! Enable from the shell:
//! ```sh
//! ASHYPASS_PREVIEW=sync-success cargo run -p ashypass-app
//! ASHYPASS_PREVIEW=sync-success-clean,sync-failure cargo run -p ashypass-app
//! ```
//!
//! Each preview fabricates a plausible payload and feeds it to the real
//! rendering code so we exercise the same widgets the production flow does.
//! Not gated behind a cargo feature on purpose — the cost is one `getenv`
//! at startup, well worth the ability to design-iterate without a server.

use ashypass_core::sync::{SyncReport, SyncStats};
use gtk::prelude::*;

pub fn present(kind: &str, parent: &impl IsA<gtk::Window>) {
    match kind {
        "sync-success" => present_sync_success(parent),
        "sync-success-clean" => present_sync_success_clean(parent),
        "sync-success-conflicts" => present_sync_success_conflicts(parent),
        "sync-success-skipped" => present_sync_success_skipped(parent),
        "sync-success-errors" => present_sync_success_errors(parent),
        "sync-failure" => present_sync_failure(parent),
        other => eprintln!(
            "ashypass-preview: unknown kind {other:?}. Known: \
             sync-success, sync-success-clean, sync-success-conflicts, \
             sync-success-skipped, sync-success-errors, sync-failure."
        ),
    }
}

fn fabricate_overlay() -> adw::ToastOverlay {
    adw::ToastOverlay::new()
}

fn present_sync_success(parent: &impl IsA<gtk::Window>) {
    let report = SyncReport {
        stats: SyncStats {
            created_remotely: 3,
            updated_remotely: 2,
            deleted_remotely: 1,
            deleted_locally: 0,
            created_locally: 1,
            updated_locally: 4,
            conflicts: 0,
            skipped_passwordless: 0,
            errors: Vec::new(),
        },
        conflict_details: Vec::new(),
    };
    super::settings_dialog::present_sync_success_dialog(
        Some(&parent.clone().upcast::<gtk::Window>()),
        &fabricate_overlay(),
        &report,
    );
}

fn present_sync_success_clean(parent: &impl IsA<gtk::Window>) {
    let report = SyncReport {
        stats: SyncStats::default(),
        conflict_details: Vec::new(),
    };
    super::settings_dialog::present_sync_success_dialog(
        Some(&parent.clone().upcast::<gtk::Window>()),
        &fabricate_overlay(),
        &report,
    );
}

fn present_sync_success_conflicts(parent: &impl IsA<gtk::Window>) {
    let report = SyncReport {
        stats: SyncStats {
            created_remotely: 1,
            updated_remotely: 2,
            updated_locally: 1,
            conflicts: 3,
            ..Default::default()
        },
        conflict_details: vec![
            ("GitHub - leoathayde".into(), "local"),
            ("Nextcloud admin".into(), "remote"),
            ("Banco do Brasil".into(), "local"),
        ],
    };
    super::settings_dialog::present_sync_success_dialog(
        Some(&parent.clone().upcast::<gtk::Window>()),
        &fabricate_overlay(),
        &report,
    );
}

fn present_sync_success_skipped(parent: &impl IsA<gtk::Window>) {
    let report = SyncReport {
        stats: SyncStats {
            updated_remotely: 1,
            deleted_remotely: 1,
            skipped_passwordless: 13,
            ..Default::default()
        },
        conflict_details: Vec::new(),
    };
    super::settings_dialog::present_sync_success_dialog(
        Some(&parent.clone().upcast::<gtk::Window>()),
        &fabricate_overlay(),
        &report,
    );
}

fn present_sync_success_errors(parent: &impl IsA<gtk::Window>) {
    let report = SyncReport {
        stats: SyncStats {
            created_remotely: 2,
            updated_locally: 1,
            errors: vec![
                "create Gmail: HTTP 500 Internal Server Error".into(),
                "update Twitter: 429 Too Many Requests, retry after 60s".into(),
                "delete abc-uuid-123: connection reset by peer".into(),
            ],
            ..Default::default()
        },
        conflict_details: Vec::new(),
    };
    super::settings_dialog::present_sync_success_dialog(
        Some(&parent.clone().upcast::<gtk::Window>()),
        &fabricate_overlay(),
        &report,
    );
}

fn present_sync_failure(parent: &impl IsA<gtk::Window>) {
    super::settings_dialog::present_sync_failure_dialog(
        Some(&parent.clone().upcast::<gtk::Window>()),
        "HTTP 401 Unauthorized — app password rejected by server",
    );
}
