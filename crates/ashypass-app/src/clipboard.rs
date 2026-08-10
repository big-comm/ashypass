//! Clipboard with auto-clear.
//!
//! `copy()` writes `text` to the system clipboard then schedules a clear after
//! `seconds`. If the clipboard contents changed in the meantime (user copied
//! something else), we leave it alone.
//!
//! The pending timer never holds the copied secret: it keeps a SHA-256 digest
//! and compares digests at clear time. Otherwise every copy would leave a
//! second, un-zeroized plaintext copy of the password alive in the heap for the
//! whole auto-clear window.

use gtk::prelude::*;
use gtk::{gdk, gio};
use sha2::{Digest, Sha256};
use std::cell::RefCell;

thread_local! {
    /// Digest of whatever we last put on the clipboard, while it is still ours
    /// to clear. Lets `clear_now` (lock / shutdown) wipe a secret whose timer
    /// has not fired yet, without ever holding the secret itself.
    static PENDING: RefCell<Option<[u8; 32]>> = const { RefCell::new(None) };
}

fn digest(text: &str) -> [u8; 32] {
    Sha256::digest(text.as_bytes()).into()
}

/// Copy `text` to the clipboard and schedule a clear after `seconds`.
/// `0` disables the auto-clear.
pub fn copy(text: &str, seconds: u64) {
    let Some(display) = gdk::Display::default() else {
        return;
    };
    let clipboard = display.clipboard();
    clipboard.set_text(text);

    if seconds == 0 {
        PENDING.with(|p| *p.borrow_mut() = None);
        return;
    }

    let expected = digest(text);
    PENDING.with(|p| *p.borrow_mut() = Some(expected));

    glib::timeout_add_seconds_local(seconds as u32, move || {
        // Only clear if this is still the copy we made; a later `copy()` or an
        // explicit `clear_now()` supersedes us.
        let still_ours = PENDING.with(|p| *p.borrow() == Some(expected));
        if still_ours {
            clear_if_matches(expected);
        }
        glib::ControlFlow::Break
    });
}

/// Clear the clipboard immediately if it still holds the secret we put there.
/// Called when the vault locks and on shutdown, so a copied password does not
/// outlive the session just because its timer had not fired.
pub fn clear_now() {
    let pending = PENDING.with(|p| p.borrow_mut().take());
    if let Some(expected) = pending {
        clear_if_matches(expected);
    }
}

/// Best-effort clear during application shutdown.
///
/// Unlike `clear_now` this cannot verify the current contents first: the
/// read-back is async and the main loop is going away. So it clears only when a
/// secret of ours is still pending, accepting that a clipboard entry the user
/// copied from elsewhere in the last few seconds may be dropped too. Leaving a
/// password behind for a clipboard manager to persist is the worse outcome.
pub fn clear_on_exit() {
    let pending = PENDING.with(|p| p.borrow_mut().take());
    if pending.is_none() {
        return;
    }
    if let Some(display) = gdk::Display::default() {
        display.clipboard().set_text("");
    }
}

fn clear_if_matches(expected: [u8; 32]) {
    let Some(display) = gdk::Display::default() else {
        return;
    };
    display
        .clipboard()
        .read_text_async(None::<&gio::Cancellable>, move |res| {
            if let Ok(Some(current)) = res {
                if digest(current.as_str()) == expected {
                    if let Some(display) = gdk::Display::default() {
                        display.clipboard().set_text("");
                    }
                    PENDING.with(|p| {
                        let mut slot = p.borrow_mut();
                        if *slot == Some(expected) {
                            *slot = None;
                        }
                    });
                }
            }
        });
}
