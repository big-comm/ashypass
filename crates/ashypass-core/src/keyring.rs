//! System keyring integration via the freedesktop Secret Service (D-Bus).
//!
//! Lets the user opt in to storing the vault master password in the desktop
//! environment's secret store (GNOME Keyring, KWallet, KeePassXC's Secret
//! Service backend, …). On supported sessions, this enables silent unlock at
//! startup; otherwise all calls return `Ok(None)` / `Err(Other(...))` and the
//! app falls back to the normal password prompt.
//!
//! Threat model: the master password is exposed to any other process that the
//! user has granted access to their default collection. The user opts in
//! explicitly; we never silently store anything.

use crate::{Error, Result};
use secret_service::blocking::SecretService;
use secret_service::EncryptionType;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Duration;

/// All Ashy Pass keyring items carry these attribute pairs so we can find
/// them again and so they don't collide with other apps' secrets.
fn attributes(kind: &'static str) -> HashMap<&'static str, &'static str> {
    HashMap::from([("application", "ashypass"), ("kind", kind)])
}

const MASTER_PASSWORD_KIND: &str = "master-password";
const LABEL: &str = "Ashy Pass — vault master password";
const QUICK_UNLOCK_KIND: &str = "quick-unlock";
const QUICK_UNLOCK_LABEL: &str = "Ashy Pass — quick-unlock state";

/// How long to wait for the Secret Service to answer the initial connect.
/// Activation of a keyring daemon takes a second or two; a service that is
/// registered but never answers would otherwise block the caller forever
/// (zbus calls have no timeout), freezing the GTK main loop.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);

/// Set once a connect timed out: later calls fail fast instead of waiting
/// again for a service that is not coming.
static UNRESPONSIVE: AtomicBool = AtomicBool::new(false);

fn service() -> Result<SecretService<'static>> {
    connect_with_timeout(CONNECT_TIMEOUT, || {
        SecretService::connect(EncryptionType::Dh)
    })
}

fn connect_with_timeout<T, E, F>(timeout: Duration, connect: F) -> Result<T>
where
    T: Send + 'static,
    E: std::fmt::Display + Send + 'static,
    F: FnOnce() -> std::result::Result<T, E> + Send + 'static,
{
    if UNRESPONSIVE.load(Ordering::Relaxed) {
        return Err(Error::Other("secret service is not responding".into()));
    }
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(connect());
    });
    match receiver.recv_timeout(timeout) {
        Ok(result) => result.map_err(|e| Error::Other(format!("secret service connect: {e}"))),
        Err(_) => {
            UNRESPONSIVE.store(true, Ordering::Relaxed);
            Err(Error::Other("secret service is not responding".into()))
        }
    }
}

/// Write the master password to the user's default collection, replacing any
/// existing entry with the same attributes. `replace=true` so we don't grow
/// duplicate items if the user toggles the setting off and on.
pub fn store_master(password: &str) -> Result<()> {
    store_named_secret(MASTER_PASSWORD_KIND, LABEL, password)
}

/// Write an application secret under a stable kind. Intended for service
/// app-passwords that should not be persisted in plaintext JSON configs.
pub fn store_named_secret(kind: &'static str, label: &str, secret: &str) -> Result<()> {
    let ss = service()?;
    let collection = ss
        .get_default_collection()
        .map_err(|e| Error::Other(format!("default collection: {e}")))?;
    // Unlock the collection first; users on freshly-logged-in sessions often
    // have the default collection locked.
    collection
        .unlock()
        .map_err(|e| Error::Other(format!("unlock collection: {e}")))?;
    collection
        .create_item(
            label,
            attributes(kind),
            secret.as_bytes(),
            true,
            "text/plain",
        )
        .map_err(|e| Error::Other(format!("create item: {e}")))?;
    Ok(())
}

/// Look up the master password if one is stored. Returns `Ok(None)` if no
/// item matching our attributes exists (i.e. user hasn't opted in yet, or
/// previously opted out). Bubbles up real errors otherwise.
pub fn load_master() -> Result<Option<String>> {
    load_named_secret(MASTER_PASSWORD_KIND)
}

/// Look up an application secret by kind.
pub fn load_named_secret(kind: &'static str) -> Result<Option<String>> {
    let ss = service()?;
    let found = ss
        .search_items(attributes(kind))
        .map_err(|e| Error::Other(format!("search: {e}")))?;
    let item = match found.unlocked.into_iter().next() {
        Some(i) => i,
        None => match found.locked.into_iter().next() {
            Some(i) => {
                i.unlock()
                    .map_err(|e| Error::Other(format!("unlock item: {e}")))?;
                i
            }
            None => return Ok(None),
        },
    };
    let bytes = item
        .get_secret()
        .map_err(|e| Error::Other(format!("get secret: {e}")))?;
    let text = String::from_utf8(bytes)
        .map_err(|_| Error::Other("keyring item is not valid UTF-8".into()))?;
    Ok(Some(text))
}

/// Remove the stored master password. No-op if nothing is stored.
pub fn delete_master() -> Result<()> {
    delete_named_secret(MASTER_PASSWORD_KIND)
}

pub fn store_quick_unlock(prefs: &crate::settings::QuickUnlockPrefs) -> Result<()> {
    let serialized = serde_json::to_string(prefs)?;
    store_named_secret(QUICK_UNLOCK_KIND, QUICK_UNLOCK_LABEL, &serialized)
}

pub fn load_quick_unlock() -> Result<Option<crate::settings::QuickUnlockPrefs>> {
    load_named_secret(QUICK_UNLOCK_KIND)?
        .map(|serialized| serde_json::from_str(&serialized).map_err(Error::from))
        .transpose()
}

pub fn delete_quick_unlock() -> Result<()> {
    delete_named_secret(QUICK_UNLOCK_KIND)
}

pub fn is_quick_unlock_stored() -> bool {
    is_named_secret_stored(QUICK_UNLOCK_KIND)
}

/// Remove application secrets with the given kind. No-op if none are stored.
pub fn delete_named_secret(kind: &'static str) -> Result<()> {
    let ss = service()?;
    let found = ss
        .search_items(attributes(kind))
        .map_err(|e| Error::Other(format!("search: {e}")))?;
    for item in found.unlocked.into_iter().chain(found.locked) {
        item.delete()
            .map_err(|e| Error::Other(format!("delete item: {e}")))?;
    }
    Ok(())
}

/// True when an item matching our attributes is present (locked or not).
/// Useful for showing the right toggle state without reading the secret.
pub fn is_stored() -> bool {
    is_named_secret_stored(MASTER_PASSWORD_KIND)
}

/// True when a secret matching the given kind is present (locked or not).
pub fn is_named_secret_stored(kind: &'static str) -> bool {
    let Ok(ss) = service() else { return false };
    let Ok(found) = ss.search_items(attributes(kind)) else {
        return false;
    };
    !found.unlocked.is_empty() || !found.locked.is_empty()
}

#[cfg(test)]
mod timeout_tests {
    use super::*;

    #[test]
    fn a_service_that_never_answers_does_not_block_forever() {
        let started = std::time::Instant::now();
        let result: Result<()> = connect_with_timeout(Duration::from_millis(100), || {
            std::thread::sleep(Duration::from_secs(5));
            Ok::<(), String>(())
        });
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
        // Later calls fail fast.
        let again: Result<()> =
            connect_with_timeout(Duration::from_secs(5), || Ok::<(), String>(()));
        assert!(again.is_err());
        UNRESPONSIVE.store(false, Ordering::Relaxed);
    }
}
