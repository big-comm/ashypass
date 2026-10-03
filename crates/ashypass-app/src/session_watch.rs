//! Lock the vault when the screen locks or the computer goes to sleep.
//!
//! Listens on D-Bus for the screensaver's `ActiveChanged(true)` (GNOME and
//! the freedesktop interface used by KDE and others) and logind's
//! `PrepareForSleep(true)`. Honours the "Lock when the screen locks or the
//! computer sleeps" setting; when neither bus is reachable nothing happens
//! and the idle timer still applies.

use crate::state::SharedState;
use gtk::gio;
use std::rc::Rc;

const SCREENSAVERS: &[(&str, &str)] = &[
    ("org.gnome.ScreenSaver", "/org/gnome/ScreenSaver"),
    (
        "org.freedesktop.ScreenSaver",
        "/org/freedesktop/ScreenSaver",
    ),
];

pub fn install(state: SharedState, lock: Rc<dyn Fn()>) {
    let trigger: Rc<dyn Fn()> = {
        let state = state.clone();
        Rc::new(move || {
            if state.settings().lock_on_screen_lock && state.vault.borrow().is_unlocked() {
                lock();
            }
        })
    };

    if let Ok(session) = gio::bus_get_sync(gio::BusType::Session, gio::Cancellable::NONE) {
        for (interface, path) in SCREENSAVERS {
            let trigger = trigger.clone();
            // The subscription lives as long as the connection, which lives
            // as long as the process.
            #[allow(deprecated)]
            let _id = session.signal_subscribe(
                None,
                Some(interface),
                Some("ActiveChanged"),
                Some(path),
                None,
                gio::DBusSignalFlags::NONE,
                move |_, _, _, _, _, params| {
                    if params.get::<(bool,)>().is_some_and(|(active,)| active) {
                        trigger();
                    }
                },
            );
        }
        std::mem::forget(session);
    }

    if let Ok(system) = gio::bus_get_sync(gio::BusType::System, gio::Cancellable::NONE) {
        let trigger = trigger.clone();
        #[allow(deprecated)]
        let _id = system.signal_subscribe(
            Some("org.freedesktop.login1"),
            Some("org.freedesktop.login1.Manager"),
            Some("PrepareForSleep"),
            Some("/org/freedesktop/login1"),
            None,
            gio::DBusSignalFlags::NONE,
            move |_, _, _, _, _, params| {
                if params.get::<(bool,)>().is_some_and(|(starting,)| starting) {
                    trigger();
                }
            },
        );
        std::mem::forget(system);
    }
}
