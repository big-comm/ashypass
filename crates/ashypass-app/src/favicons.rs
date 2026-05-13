//! UI-side favicon loader.
//!
//! Sets the favicon on a `gtk::Image` for a given URL. If the file isn't
//! cached yet, schedules a background fetch and updates the image when it
//! lands. Falls back to a generic icon on failure.

use ashypass_core::favicons;
use gtk::glib;
use gtk::prelude::*;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

const FALLBACK_ICON: &str = "dialog-password-symbolic";

pub fn apply(image: &gtk::Image, url: Option<&str>, pixel: i32) {
    image.set_pixel_size(pixel);

    let Some(host) = url.and_then(favicons::host_of) else {
        image.set_icon_name(Some(FALLBACK_ICON));
        return;
    };

    if let Some(path) = favicons::lookup(&host) {
        image.set_from_file(Some(&path));
        return;
    }

    image.set_icon_name(Some(FALLBACK_ICON));

    let image_weak = image.downgrade();
    let result: Arc<Mutex<Option<PathBuf>>> = Arc::new(Mutex::new(None));
    let result_thread = result.clone();
    let host_for_thread = host.clone();

    std::thread::spawn(move || {
        if let Ok(path) = favicons::fetch_blocking(&host_for_thread) {
            *result_thread.lock().unwrap() = Some(path);
        }
    });

    // Poll the result on the main loop until the worker thread finishes
    // (typically <2s). One-shot delayed read keeps the UI quiet on success.
    glib::timeout_add_seconds_local(2, move || {
        let path_opt = result.lock().unwrap().clone();
        if let Some(path) = path_opt {
            if let Some(img) = image_weak.upgrade() {
                img.set_from_file(Some(&path));
            }
            return glib::ControlFlow::Break;
        }
        glib::ControlFlow::Continue
    });
}
