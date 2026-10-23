//! The PIN saved on this computer ("quick unlock"), shared by the desktop app
//! and the browser host so both follow the same rules: the record lives in the
//! keyring (older versions kept it in the settings file), wrong PINs are
//! counted in the record itself, and at `QUICK_UNLOCK_MAX_ATTEMPTS` the record
//! is destroyed so only the master password opens the vault.
//!
//! Deriving the key (`db::derive_quick_unlock_key`) is deliberately slow, so
//! callers run it where they like (the app on a worker thread) and hand the
//! result to [`finish_pin_attempt`].

use crate::crypto::key::DerivedKey;
use crate::db::vault::Vault;
use crate::settings::{QuickUnlockPrefs, Settings, QUICK_UNLOCK_MAX_ATTEMPTS};
use crate::{Error, Result};

/// The persisted PIN record and where it was found.
#[derive(Clone)]
pub struct StoredPin {
    pub prefs: QuickUnlockPrefs,
    /// From the keyring (as opposed to the legacy settings file).
    pub from_keyring: bool,
}

/// How a PIN attempt ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinOutcome {
    /// The vault is open.
    Unlocked,
    /// Wrong PIN; `remaining` attempts are left before the PIN is turned off.
    Wrong { remaining: u32 },
    /// Wrong PIN, and that was the last attempt: the PIN was turned off.
    TurnedOff,
    /// The PIN opens a key that no longer matches this vault (master password
    /// changed elsewhere, vault restored): it was turned off.
    Stale,
    /// The PIN could not be used (keyring or record problem).
    Unusable,
}

/// Saves a change to the settings file, the way the caller does it (the app
/// keeps a cached copy, the browser host reads and writes the file).
pub type UpdateSettings<'a> = &'a mut dyn FnMut(&dyn Fn(&mut Settings));

/// The PIN record of this computer, if one is set up: the keyring first, then
/// the settings file of older versions.
pub fn stored_pin(settings: &Settings) -> Option<StoredPin> {
    let keyring = crate::keyring::load_quick_unlock()
        .map_err(|error| log::warn!("quick-unlock keyring read failed: {error}"))
        .ok()
        .flatten()
        .filter(|p| p.is_configured());
    if let Some(prefs) = keyring {
        return Some(StoredPin {
            prefs,
            from_keyring: true,
        });
    }
    settings
        .quick_unlock
        .clone()
        .filter(|p| p.is_configured())
        .map(|prefs| StoredPin {
            prefs,
            from_keyring: false,
        })
}

/// Apply the result of `derive_quick_unlock_key(pin, &stored.prefs)`: open the
/// vault, or count the wrong attempt, and keep the stored record up to date.
pub fn finish_pin_attempt(
    vault: &mut Vault,
    stored: StoredPin,
    derived: Result<(DerivedKey, Option<QuickUnlockPrefs>)>,
    update: UpdateSettings,
) -> PinOutcome {
    match derived {
        Ok((key, upgraded)) => match vault.install_quick_unlock_key(key) {
            Ok(()) => {
                after_success(&stored, upgraded, update);
                PinOutcome::Unlocked
            }
            Err(Error::KeyMismatch) => {
                forget_pin(vault, update);
                PinOutcome::Stale
            }
            Err(error) => {
                log::warn!("quick unlock failed: {error}");
                vault.disable_quick_unlock();
                PinOutcome::Unusable
            }
        },
        Err(Error::InvalidMasterPassword) => {
            match record_failed_attempt(vault, stored.prefs, update) {
                0 => PinOutcome::TurnedOff,
                remaining => PinOutcome::Wrong { remaining },
            }
        }
        Err(error) => {
            log::warn!("quick unlock failed: {error}");
            vault.disable_quick_unlock();
            PinOutcome::Unusable
        }
    }
}

/// Turn the PIN off on this computer: session cache, keyring and settings.
pub fn forget_pin(vault: &mut Vault, update: UpdateSettings) {
    vault.disable_quick_unlock();
    if let Err(error) = crate::keyring::delete_quick_unlock() {
        log::warn!("could not clear quick-unlock keyring item: {error}");
    }
    update(&|s: &mut Settings| s.quick_unlock = None);
}

/// Save the record in its current format (without the old PIN hash) and in
/// the keyring, and reset the failure counter.
fn after_success(stored: &StoredPin, upgraded: Option<QuickUnlockPrefs>, update: UpdateSettings) {
    let to_store = match upgraded {
        Some(new) => Some(new),
        None if stored.prefs.failed_attempts > 0 || !stored.from_keyring => {
            let mut reset = stored.prefs.clone();
            reset.failed_attempts = 0;
            Some(reset)
        }
        None => None,
    };
    let Some(record) = to_store else { return };
    match crate::keyring::store_quick_unlock(&record) {
        Ok(()) => {
            if !stored.from_keyring {
                update(&|s: &mut Settings| s.quick_unlock = None);
            }
        }
        Err(error) => {
            log::warn!("could not store quick-unlock state in the keyring: {error}");
            if !stored.from_keyring {
                update(&|s: &mut Settings| s.quick_unlock = Some(record.clone()));
            }
        }
    }
}

/// Persist one more failed attempt and return how many remain. At zero the
/// record is wiped from the keyring and the settings file, so the master
/// password is the only way back in.
fn record_failed_attempt(
    vault: &mut Vault,
    mut prefs: QuickUnlockPrefs,
    update: UpdateSettings,
) -> u32 {
    prefs.failed_attempts = prefs.failed_attempts.saturating_add(1);
    let remaining = QUICK_UNLOCK_MAX_ATTEMPTS.saturating_sub(prefs.failed_attempts);
    if remaining == 0 {
        forget_pin(vault, update);
        return 0;
    }
    // Best effort: if the counter cannot be persisted this attempt is still
    // refused; only the budget across restarts is lost.
    if let Err(error) = crate::keyring::store_quick_unlock(&prefs) {
        log::warn!("could not record failed PIN attempt: {error}");
        update(&|s: &mut Settings| s.quick_unlock = Some(prefs.clone()));
    }
    remaining
}
