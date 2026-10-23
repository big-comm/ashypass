//! Hand the sync folder's connection to another device: the computer shows
//! it as a QR code, encrypted with a 6-digit code shown next to it, and the
//! phone scans the QR and types the code. A photo of the QR alone is no use.
//!
//! The master password is never in it: the new device still needs it to
//! open the folder's key. Google Drive accounts carry no sign-in (each
//! device signs in to Google itself), local folders can't be handed over.
//!
//! ```text
//! ashypass-pair:1:<base64url( 16-byte salt | aes_gcm_v2 blob )>
//! ```
//!
//! The key is Argon2id of the code with the PIN costs (`derive_key_pin`),
//! so a search through the million codes takes weeks, and the code is good
//! for `PAIRING_TTL_SECS` only.

use super::folder_account::{FolderSyncAccount, PROVIDER_GOOGLE_DRIVE, PROVIDER_LOCAL};
use crate::crypto::{aes_gcm_v2, argon2_kdf};
use crate::{Error, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const PREFIX: &str = "ashypass-pair:1:";
const SALT_LEN: usize = 16;

/// How long a pairing code stays good.
pub const PAIRING_TTL_SECS: i64 = 10 * 60;

/// What `open` reports for a code that does not open the QR.
pub const WRONG_CODE: &str = "wrong pairing code";
/// What `open` reports for a QR older than `PAIRING_TTL_SECS`.
pub const EXPIRED: &str = "pairing code expired";
/// What `open` reports for a QR that is not an Ashy Pass pairing one.
pub const NOT_PAIRING: &str = "not an Ashy Pass connection code";

#[derive(Serialize, Deserialize)]
struct Payload {
    account: FolderSyncAccount,
    expires_at: i64,
}

/// A connection to show: the QR's text and the code to type.
pub struct Pairing {
    pub qr: String,
    /// Six digits.
    pub code: String,
}

/// Whether `account` can be handed over (not a folder on this computer).
pub fn can_pair(account: &FolderSyncAccount) -> bool {
    account.provider() != PROVIDER_LOCAL
}

/// Text that looks like a pairing QR (to tell it from other QR codes).
pub fn is_pairing_text(text: &str) -> bool {
    text.trim().starts_with(PREFIX)
}

/// Seal `account` for another device, good until `now + PAIRING_TTL_SECS`.
pub fn seal(account: &FolderSyncAccount, now: i64) -> Result<Pairing> {
    if !can_pair(account) {
        return Err(Error::InvalidInput(
            "a folder on this computer can't be used on another device".into(),
        ));
    }
    let mut account = account.clone();
    if account.provider() == PROVIDER_GOOGLE_DRIVE {
        // This device's Google sign-in is no use on another one.
        account.password.clear();
    }
    let payload = Zeroizing::new(serde_json::to_vec(&Payload {
        account,
        expires_at: now + PAIRING_TTL_SECS,
    })?);
    let code = format!("{:06}", rand::thread_rng().gen_range(0..1_000_000u32));
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    let key = argon2_kdf::derive_key_pin(&code, &salt)?;
    let mut blob = salt.to_vec();
    blob.extend(aes_gcm_v2::encrypt(&key, &payload)?);
    Ok(Pairing {
        qr: format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(blob)),
        code,
    })
}

/// The account in a pairing QR, with the code shown next to it (spaces
/// and dashes in it are ignored).
pub fn open(qr: &str, code: &str, now: i64) -> Result<FolderSyncAccount> {
    let blob = qr
        .trim()
        .strip_prefix(PREFIX)
        .and_then(|b| URL_SAFE_NO_PAD.decode(b).ok())
        .filter(|b| b.len() > SALT_LEN)
        .ok_or_else(|| Error::InvalidInput(NOT_PAIRING.into()))?;
    let code: String = code
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect();
    if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
        return Err(Error::InvalidInput(WRONG_CODE.into()));
    }
    let (salt, sealed) = blob.split_at(SALT_LEN);
    let key = argon2_kdf::derive_key_pin(&code, salt)?;
    let payload = Zeroizing::new(
        aes_gcm_v2::decrypt(&key, sealed).map_err(|_| Error::InvalidInput(WRONG_CODE.into()))?,
    );
    let payload: Payload = serde_json::from_slice(&payload)?;
    if now > payload.expires_at {
        return Err(Error::InvalidInput(EXPIRED.into()));
    }
    Ok(payload.account)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::folder_account::{PROVIDER_DROPBOX, PROVIDER_WEBDAV};

    fn account(provider: &str) -> FolderSyncAccount {
        FolderSyncAccount {
            provider: provider.into(),
            server_url: "cloud.example.com".into(),
            nextcloud: true,
            user: "ana".into(),
            password: "app-password".into(),
            folder: "AshyPass Sync".into(),
        }
    }

    #[test]
    fn the_code_opens_the_qr_until_it_expires() {
        let pairing = seal(&account(PROVIDER_WEBDAV), 1_000).unwrap();
        assert!(is_pairing_text(&pairing.qr));
        assert_eq!(pairing.code.len(), 6);
        // Neither the password nor the address shows in the QR.
        assert!(!pairing.qr.contains("app-password") && !pairing.qr.contains("example"));

        let spaced = format!("{} {}", &pairing.code[..3], &pairing.code[3..]);
        let got = open(&pairing.qr, &spaced, 1_000 + 60).unwrap();
        assert_eq!(
            (
                got.provider(),
                got.server_url.as_str(),
                got.nextcloud,
                got.user.as_str()
            ),
            (PROVIDER_WEBDAV, "cloud.example.com", true, "ana")
        );
        assert_eq!(
            (got.password.as_str(), got.folder.as_str()),
            ("app-password", "AshyPass Sync")
        );

        let late = open(&pairing.qr, &pairing.code, 1_000 + PAIRING_TTL_SECS + 1);
        assert!(matches!(late, Err(Error::InvalidInput(m)) if m == EXPIRED));
    }

    #[test]
    fn a_wrong_code_or_another_qr_is_refused() {
        let pairing = seal(&account(PROVIDER_DROPBOX), 0).unwrap();
        let wrong = if pairing.code == "000000" {
            "000001"
        } else {
            "000000"
        };
        assert!(
            matches!(open(&pairing.qr, wrong, 0), Err(Error::InvalidInput(m)) if m == WRONG_CODE)
        );
        assert!(
            matches!(open(&pairing.qr, "12345", 0), Err(Error::InvalidInput(m)) if m == WRONG_CODE)
        );
        assert!(!is_pairing_text("otpauth://totp/x?secret=JBSWY3DP"));
        assert!(matches!(
            open("otpauth://totp/x?secret=JBSWY3DP", &pairing.code, 0),
            Err(Error::InvalidInput(m)) if m == NOT_PAIRING
        ));
    }

    #[test]
    fn google_drive_goes_without_the_sign_in_and_local_folders_stay() {
        let pairing = seal(&account(PROVIDER_GOOGLE_DRIVE), 0).unwrap();
        let got = open(&pairing.qr, &pairing.code, 0).unwrap();
        assert_eq!(got.provider(), PROVIDER_GOOGLE_DRIVE);
        assert!(got.password.is_empty());
        assert!(!can_pair(&account(PROVIDER_LOCAL)));
        assert!(seal(&account(PROVIDER_LOCAL), 0).is_err());
    }
}
