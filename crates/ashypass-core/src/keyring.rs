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

/// All Ashy Pass keyring items carry these attribute pairs so we can find
/// them again and so they don't collide with other apps' secrets.
fn attributes() -> HashMap<&'static str, &'static str> {
    HashMap::from([
        ("application", "ashypass"),
        ("kind", "master-password"),
    ])
}

const LABEL: &str = "Ashy Pass — vault master password";

fn service() -> Result<SecretService<'static>> {
    SecretService::connect(EncryptionType::Dh)
        .map_err(|e| Error::Other(format!("secret service connect: {e}")))
}

/// Write the master password to the user's default collection, replacing any
/// existing entry with the same attributes. `replace=true` so we don't grow
/// duplicate items if the user toggles the setting off and on.
pub fn store_master(password: &str) -> Result<()> {
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
            LABEL,
            attributes(),
            password.as_bytes(),
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
    let ss = service()?;
    let found = ss
        .search_items(attributes())
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
    let ss = service()?;
    let found = ss
        .search_items(attributes())
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
    let Ok(ss) = service() else { return false };
    let Ok(found) = ss.search_items(attributes()) else {
        return false;
    };
    !found.unlocked.is_empty() || !found.locked.is_empty()
}
