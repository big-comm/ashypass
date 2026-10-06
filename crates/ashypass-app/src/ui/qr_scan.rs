//! Read a verification-code QR code: from an image file, from a screen
//! capture (through the desktop's screenshot portal) or from an image on the
//! clipboard. Decoding is done locally with `rqrr`; nothing leaves the
//! computer.
//!
//! A screen capture holds the secret, so the file the portal wrote is deleted
//! as soon as it has been read.

use crate::tr;
use adw::prelude::*;
use gtk::{gdk, gio, glib};
use std::path::PathBuf;
use std::rc::Rc;

/// What a scan found.
#[derive(Debug, PartialEq, Eq)]
pub enum ScanResult {
    /// An `otpauth://` link, ready for the setup-key field.
    Otpauth(String),
    /// A Google Authenticator export (`otpauth-migration://`): several
    /// accounts packed together, not supported here.
    Migration,
    /// A QR code with something else in it.
    Other,
    /// No QR code in the image.
    NotFound,
}

/// Decode every QR code in an encoded image (PNG, JPEG, …).
pub fn decode_image_bytes(bytes: &[u8]) -> Result<Vec<String>, String> {
    let image = image::load_from_memory(bytes).map_err(|e| e.to_string())?;
    let luma = image.to_luma8();
    let (width, height) = luma.dimensions();
    let mut prepared =
        rqrr::PreparedImage::prepare_from_greyscale(width as usize, height as usize, |x, y| {
            luma.get_pixel(x as u32, y as u32)[0]
        });
    let grids = prepared.detect_grids();
    Ok(grids
        .into_iter()
        .filter_map(|grid| grid.decode().ok().map(|(_, content)| content))
        .collect())
}

/// Pick the useful content among decoded QR codes.
pub fn classify(contents: &[String]) -> ScanResult {
    if let Some(uri) = contents
        .iter()
        .map(|c| c.trim())
        .find(|c| c.to_ascii_lowercase().starts_with("otpauth://"))
    {
        return ScanResult::Otpauth(uri.to_string());
    }
    if contents.iter().any(|c| {
        c.trim()
            .to_ascii_lowercase()
            .starts_with("otpauth-migration://")
    }) {
        return ScanResult::Migration;
    }
    if contents.is_empty() {
        ScanResult::NotFound
    } else {
        ScanResult::Other
    }
}

pub fn scan_bytes(bytes: &[u8]) -> ScanResult {
    match decode_image_bytes(bytes) {
        Ok(contents) => classify(&contents),
        Err(_) => ScanResult::NotFound,
    }
}

pub fn message_for(result: &ScanResult) -> &'static str {
    match result {
        ScanResult::Otpauth(_) => tr!("QR code read. Check the details and save."),
        ScanResult::Migration => tr!(
            "This is a Google Authenticator export with several accounts. Show the QR code of each account on its site instead."
        ),
        ScanResult::Other => {
            tr!("This QR code is not a verification-code setup. Use the one shown by the site's two-step verification settings.")
        }
        ScanResult::NotFound => tr!(
            "No QR code was found. Make sure the whole code is visible and not too small."
        ),
    }
}

type Done = Rc<dyn Fn(ScanResult)>;

/// Buttons to read a QR code; `done` receives the result of each attempt.
pub fn scan_buttons<F>(done: F) -> gtk::Box
where
    F: Fn(ScanResult) + 'static,
{
    let done: Done = Rc::new(done);
    let row = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(8)
        .homogeneous(true)
        .build();

    let open = button("image-x-generic-symbolic", tr!("Open image…"));
    let capture = button("camera-photo-symbolic", tr!("Capture from screen…"));
    let paste = button("edit-paste-symbolic", tr!("Paste image"));
    row.append(&open);
    row.append(&capture);
    row.append(&paste);

    {
        let done = done.clone();
        open.connect_clicked(move |b| open_image(b, done.clone()));
    }
    {
        let done = done.clone();
        capture.connect_clicked(move |b| capture_screen(b, done.clone()));
    }
    paste.connect_clicked(move |_| paste_image(done.clone()));
    row
}

fn button(icon: &str, label: &str) -> gtk::Button {
    let content = adw::ButtonContent::builder()
        .icon_name(icon)
        .label(label)
        .build();
    let button = gtk::Button::builder().child(&content).build();
    button.update_property(&[gtk::accessible::Property::Label(label)]);
    button
}

fn open_image(anchor: &gtk::Button, done: Done) {
    let filter = gtk::FileFilter::new();
    filter.set_name(Some(tr!("Images")));
    filter.add_pixbuf_formats();
    let filters = gio::ListStore::new::<gtk::FileFilter>();
    filters.append(&filter);
    let dialog = gtk::FileDialog::builder()
        .title(tr!("Choose an image with the QR code"))
        .filters(&filters)
        .modal(true)
        .build();
    let parent = anchor.root().and_then(|r| r.downcast::<gtk::Window>().ok());
    dialog.open(parent.as_ref(), None::<&gio::Cancellable>, move |result| {
        let Ok(file) = result else { return };
        let Some(path) = file.path() else { return };
        match std::fs::read(&path) {
            Ok(bytes) => done(scan_bytes(&bytes)),
            Err(_) => done(ScanResult::NotFound),
        }
    });
}

fn paste_image(done: Done) {
    let Some(display) = gdk::Display::default() else {
        return;
    };
    display
        .clipboard()
        .read_texture_async(None::<&gio::Cancellable>, move |result| {
            let scan = match result {
                Ok(Some(texture)) => scan_bytes(&texture.save_to_png_bytes()),
                _ => ScanResult::NotFound,
            };
            done(scan);
        });
}

/// Ask the screenshot portal for an interactive capture, read it, delete it.
fn capture_screen(anchor: &gtk::Button, done: Done) {
    let anchor = anchor.clone();
    let fail = {
        let done = done.clone();
        move |reason: String| {
            log::warn!("screen capture for QR failed: {reason}");
            done(ScanResult::NotFound);
        }
    };
    let connection = match gio::bus_get_sync(gio::BusType::Session, gio::Cancellable::NONE) {
        Ok(c) => c,
        Err(e) => return fail(e.to_string()),
    };
    let Some(unique) = connection.unique_name() else {
        return fail("no bus name".into());
    };
    let token = format!("ashypass_qr_{}", glib::random_int());
    let sender = unique.trim_start_matches(':').replace('.', "_");
    let request_path = format!("/org/freedesktop/portal/desktop/request/{sender}/{token}");

    let window_hidden = anchor.root().and_then(|r| r.downcast::<gtk::Window>().ok());
    // Subscribe before calling, so a fast response is not missed.
    let subscription: Rc<std::cell::RefCell<Option<gio::SignalSubscriptionId>>> = Rc::default();
    let handled = Rc::new(std::cell::Cell::new(false));
    {
        let connection_cl = connection.clone();
        let subscription_cl = subscription.clone();
        let done = done.clone();
        let handled = handled.clone();
        let window_back = window_hidden.clone();
        #[allow(deprecated)]
        let id = connection.signal_subscribe(
            Some("org.freedesktop.portal.Desktop"),
            Some("org.freedesktop.portal.Request"),
            Some("Response"),
            Some(&request_path),
            None,
            gio::DBusSignalFlags::NONE,
            move |_, _, _, _, _, params| {
                if handled.replace(true) {
                    return;
                }
                // The capture is done (or cancelled): bring the window back.
                if let Some(window) = window_back.as_ref() {
                    window.present();
                }
                if let Some(id) = subscription_cl.borrow_mut().take() {
                    #[allow(deprecated)]
                    connection_cl.signal_unsubscribe(id);
                }
                let Some((response, results)) = params.get::<(u32, glib::VariantDict)>() else {
                    done(ScanResult::NotFound);
                    return;
                };
                if response != 0 {
                    // Cancelled by the user: nothing to report.
                    return;
                }
                let path: Option<PathBuf> = results
                    .lookup::<String>("uri")
                    .ok()
                    .flatten()
                    .and_then(|uri| glib::filename_from_uri(&uri).ok())
                    .map(|(path, _)| path);
                let Some(path) = path else {
                    done(ScanResult::NotFound);
                    return;
                };
                let scan = std::fs::read(&path)
                    .map(|bytes| scan_bytes(&bytes))
                    .unwrap_or(ScanResult::NotFound);
                // The capture contains the secret: do not leave it behind.
                if let Err(e) = std::fs::remove_file(&path) {
                    log::warn!(
                        "could not delete the screen capture {}: {e}",
                        path.display()
                    );
                }
                done(scan);
            },
        );
        *subscription.borrow_mut() = Some(id);
    }

    let options = glib::VariantDict::new(None);
    options.insert("handle_token", token.as_str());
    options.insert("interactive", true);
    options.insert("modal", true);
    let parameters = ("", options.end()).to_variant();
    // Let the user see the screen: hide our window while they pick the area.
    if let Some(window) = window_hidden.as_ref() {
        window.minimize();
    }
    let subscription_err = subscription.clone();
    let connection_err = connection.clone();
    connection.call(
        Some("org.freedesktop.portal.Desktop"),
        "/org/freedesktop/portal/desktop",
        "org.freedesktop.portal.Screenshot",
        "Screenshot",
        Some(&parameters),
        Some(glib::VariantTy::new("(o)").expect("valid type")),
        gio::DBusCallFlags::NONE,
        -1,
        gio::Cancellable::NONE,
        move |result| {
            // This reply only acknowledges the request; the capture itself
            // arrives later as `Response`. Restore the window here only if
            // the request failed.
            if let Err(e) = result {
                if let Some(window) = window_hidden.as_ref() {
                    window.present();
                }
                if let Some(id) = subscription_err.borrow_mut().take() {
                    #[allow(deprecated)]
                    connection_err.signal_unsubscribe(id);
                }
                fail(e.to_string());
            }
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn otpauth_links_win_over_other_codes() {
        let found = vec![
            "https://example.com".to_string(),
            " otpauth://totp/Example:ana?secret=JBSWY3DPEHPK3PXP&issuer=Example ".to_string(),
        ];
        assert_eq!(
            classify(&found),
            ScanResult::Otpauth(
                "otpauth://totp/Example:ana?secret=JBSWY3DPEHPK3PXP&issuer=Example".into()
            )
        );
        assert_eq!(
            classify(&["otpauth-migration://offline?data=abc".to_string()]),
            ScanResult::Migration
        );
        assert_eq!(classify(&["hello".to_string()]), ScanResult::Other);
        assert_eq!(classify(&[]), ScanResult::NotFound);
    }

    #[test]
    fn a_generated_qr_code_is_decoded() {
        let uri = "otpauth://totp/Example:ana@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";
        let code = qrcode::QrCode::new(uri.as_bytes()).unwrap();
        let image = code
            .render::<image::Luma<u8>>()
            .quiet_zone(true)
            .min_dimensions(240, 240)
            .build();
        let mut png = Vec::new();
        image::DynamicImage::ImageLuma8(image)
            .write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
            .unwrap();
        assert_eq!(scan_bytes(&png), ScanResult::Otpauth(uri.to_string()));
    }

    #[test]
    fn images_without_codes_are_reported() {
        let blank = image::DynamicImage::new_luma8(120, 120);
        let mut png = Vec::new();
        blank
            .write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
            .unwrap();
        assert_eq!(scan_bytes(&png), ScanResult::NotFound);
    }
}
