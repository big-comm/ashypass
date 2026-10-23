//! Stand-in for [`keyring`](crate::keyring) where there is no freedesktop
//! Secret Service (Android, iOS). The functions keep the Linux signatures and
//! behave like a session without a keyring: nothing is stored, lookups find
//! nothing. Mobile apps keep their secrets in the platform store (Android
//! Keystore, iOS Keychain) on their own side.

use crate::{Error, Result};

fn unavailable() -> Error {
    Error::Other("no system keyring on this platform".into())
}

pub fn store_master(_password: &str) -> Result<()> {
    Err(unavailable())
}

pub fn store_named_secret(_kind: &'static str, _label: &str, _secret: &str) -> Result<()> {
    Err(unavailable())
}

pub fn load_master() -> Result<Option<String>> {
    Ok(None)
}

pub fn load_named_secret(_kind: &'static str) -> Result<Option<String>> {
    Ok(None)
}

pub fn delete_master() -> Result<()> {
    Ok(())
}

pub fn store_quick_unlock(_prefs: &crate::settings::QuickUnlockPrefs) -> Result<()> {
    Err(unavailable())
}

pub fn load_quick_unlock() -> Result<Option<crate::settings::QuickUnlockPrefs>> {
    Ok(None)
}

pub fn delete_quick_unlock() -> Result<()> {
    Ok(())
}

pub fn is_quick_unlock_stored() -> bool {
    false
}

pub fn delete_named_secret(_kind: &'static str) -> Result<()> {
    Ok(())
}

pub fn is_stored() -> bool {
    false
}

pub fn is_named_secret_stored(_kind: &'static str) -> bool {
    false
}
