//! A throwaway vault for the browser extension's end-to-end test
//! (`browser-extension/tests/e2e/run.sh`): created in the XDG folders of
//! the environment, which the test points at a temporary directory, with
//! browser integration on.
//!
//!   e2e_vault <site url>
//!
//! One login for `<site url>` (with a verification code) and one for
//! another site.

use ashypass_core::db::vault::{NewEntry, Vault};
use ashypass_core::settings::Settings;

const MASTER: &str = "correct horse battery";

fn main() {
    let site = std::env::args()
        .nth(1)
        .expect("usage: e2e_vault <site url>");
    ashypass_core::config::ensure_directories().unwrap();
    let mut vault = Vault::open(ashypass_core::config::database_path()).unwrap();
    vault.set_master_password(MASTER).unwrap();
    vault
        .add(NewEntry {
            title: "Test login".into(),
            username: Some("ana".into()),
            password: "s3cret-P4ss!".into(),
            url: Some(format!("{site}/login")),
            totp_secret: Some("JBSWY3DPEHPK3PXP".into()),
            ..Default::default()
        })
        .unwrap();
    vault
        .add(NewEntry {
            title: "Other site".into(),
            username: Some("bob".into()),
            password: "other-site-password".into(),
            url: Some("https://example.org/login".into()),
            ..Default::default()
        })
        .unwrap();
    let mut settings = Settings::load();
    settings.browser_extension = true;
    settings.save().unwrap();
    println!("e2e vault ready");
}
