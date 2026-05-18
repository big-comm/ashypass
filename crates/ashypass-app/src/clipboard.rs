//! Clipboard with auto-clear.
//!
//! `copy()` writes `text` to the system clipboard then schedules a clear after
//! `seconds`. If the clipboard contents changed in the meantime (user copied
//! something else), we leave it alone.

use gtk::prelude::*;
use gtk::{gdk, gio};

/// Copy `text` to the clipboard and schedule a clear after `seconds`.
/// `0` disables the auto-clear.
pub fn copy(text: &str, seconds: u64) {
    let Some(display) = gdk::Display::default() else {
        return;
    };
    let clipboard = display.clipboard();
    clipboard.set_text(text);

    if seconds == 0 {
        return;
    }

    let expected = text.to_string();
    glib::timeout_add_seconds_local(seconds as u32, move || {
        let Some(display) = gdk::Display::default() else {
            return glib::ControlFlow::Break;
        };
        let cb = display.clipboard();
        let expected = expected.clone();
        cb.read_text_async(None::<&gio::Cancellable>, move |res| {
            if let Ok(Some(current)) = res {
                if current.as_str() == expected {
                    if let Some(display) = gdk::Display::default() {
                        display.clipboard().set_text("");
                    }
                }
            }
        });
        glib::ControlFlow::Break
    });
}
