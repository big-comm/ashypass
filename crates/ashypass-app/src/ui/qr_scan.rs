//! Read a verification-code QR code: from an image file, from a screen
//! capture (through the desktop's screenshot portal) or from an image on the
//! clipboard. Decoding is done locally with `rqrr`; nothing leaves the
//! computer.
//!
//! A screen capture holds the secret, so the file the portal wrote is deleted
//! as soon as it has been read.
//!
//! Reading and decoding run on a worker thread and are bounded (file size,
//! pixel dimensions, decoder allocations) so a huge or hostile image cannot
//! freeze or exhaust the app.

use crate::tr;
use crate::ui::settings_dialog::run_background_task;
use adw::prelude::*;
use gtk::{gdk, gio, glib};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::rc::Rc;

/// Largest image file read for a QR code.
const MAX_IMAGE_FILE_BYTES: u64 = 20 * 1024 * 1024;
/// Largest accepted width and height, in pixels.
const MAX_IMAGE_DIMENSION: u32 = 8192;
/// Upper bound for the decoder's own allocations (an 8192×8192 RGBA image
/// needs 256 MiB).
const MAX_DECODE_ALLOC_BYTES: u64 = 320 * 1024 * 1024;

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
    /// The file or image could not be read (missing, too large, or not a
    /// supported picture).
    Unreadable,
}

fn decode_limits() -> image::Limits {
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(MAX_IMAGE_DIMENSION);
    limits.max_image_height = Some(MAX_IMAGE_DIMENSION);
    limits.max_alloc = Some(MAX_DECODE_ALLOC_BYTES);
    limits
}

/// Decode every QR code in an encoded image (PNG, JPEG, …). Images larger
/// than [`MAX_IMAGE_DIMENSION`] on either side are refused.
pub fn decode_image_bytes(bytes: &[u8]) -> Result<Vec<String>, String> {
    let mut reader = image::ImageReader::new(std::io::Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|e| e.to_string())?;
    reader.limits(decode_limits());
    let image = reader.decode().map_err(|e| e.to_string())?;
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
        Err(error) => {
            log::debug!("QR image could not be decoded: {error}");
            ScanResult::Unreadable
        }
    }
}

/// Read at most `limit` bytes from `reader` and scan them; anything larger
/// is refused without being decoded.
fn scan_reader(reader: impl Read, limit: u64) -> ScanResult {
    let mut bytes = Vec::new();
    if reader
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() as u64 > limit
    {
        return ScanResult::Unreadable;
    }
    scan_bytes(&bytes)
}

/// Read and scan an image file. Blocking: call from a worker thread.
pub fn scan_file(path: &Path) -> ScanResult {
    let Ok(file) = std::fs::File::open(path) else {
        return ScanResult::Unreadable;
    };
    match file.metadata() {
        Ok(metadata) if metadata.len() <= MAX_IMAGE_FILE_BYTES => {
            scan_reader(file, MAX_IMAGE_FILE_BYTES)
        }
        _ => ScanResult::Unreadable,
    }
}

/// Run `scan` on a worker thread and hand the result to `done` on the GTK
/// thread.
fn scan_in_background<F>(scan: F, done: Done)
where
    F: FnOnce() -> ScanResult + Send + 'static,
{
    run_background_task(scan, move |result| done(result));
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
        ScanResult::Unreadable => tr!(
            "This image could not be opened. Use a PNG, JPEG or WebP picture of up to 20 MB."
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
        let Some(path) = file.path() else {
            done(ScanResult::Unreadable);
            return;
        };
        scan_in_background(move || scan_file(&path), done);
    });
}

fn paste_image(done: Done) {
    let Some(display) = gdk::Display::default() else {
        return;
    };
    display
        .clipboard()
        .read_texture_async(None::<&gio::Cancellable>, move |result| {
            let texture = match result {
                Ok(Some(texture)) => texture,
                Ok(None) => return done(ScanResult::NotFound),
                Err(_) => return done(ScanResult::NotFound),
            };
            let too_big = |side: i32| u32::try_from(side).map_or(true, |s| s > MAX_IMAGE_DIMENSION);
            if too_big(texture.width()) || too_big(texture.height()) {
                return done(ScanResult::Unreadable);
            }
            // The texture lives on the GTK side; only its encoded bytes go to
            // the worker thread.
            let bytes = texture.save_to_png_bytes().to_vec();
            scan_in_background(move || scan_bytes(&bytes), done);
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
                scan_in_background(
                    move || {
                        let scan = scan_file(&path);
                        // The capture contains the secret: do not leave it behind.
                        if let Err(e) = std::fs::remove_file(&path) {
                            log::warn!(
                                "could not delete the screen capture {}: {e}",
                                path.display()
                            );
                        }
                        scan
                    },
                    done.clone(),
                );
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

    fn png_of(width: u32, height: u32) -> Vec<u8> {
        let mut png = Vec::new();
        image::DynamicImage::new_luma8(width, height)
            .write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
            .unwrap();
        png
    }

    #[test]
    fn oversized_dimensions_are_refused_before_decoding() {
        // Tiny file, but the header claims more pixels than allowed.
        assert!(decode_image_bytes(&png_of(MAX_IMAGE_DIMENSION + 1, 1)).is_err());
        assert!(decode_image_bytes(&png_of(1, MAX_IMAGE_DIMENSION + 1)).is_err());
        assert_eq!(
            scan_bytes(&png_of(MAX_IMAGE_DIMENSION + 1, 1)),
            ScanResult::Unreadable
        );
        assert_eq!(scan_bytes(&png_of(64, 64)), ScanResult::NotFound);
    }

    #[test]
    fn unreadable_input_is_not_reported_as_missing_code() {
        assert_eq!(scan_bytes(b"not an image"), ScanResult::Unreadable);
        let png = png_of(64, 64);
        assert_eq!(
            scan_reader(std::io::Cursor::new(&png), png.len() as u64),
            ScanResult::NotFound
        );
        assert_eq!(
            scan_reader(std::io::Cursor::new(&png), png.len() as u64 - 1),
            ScanResult::Unreadable
        );
        assert_eq!(
            scan_file(Path::new("/nonexistent/ashypass-qr-test.png")),
            ScanResult::Unreadable
        );
        assert_ne!(
            message_for(&ScanResult::Unreadable),
            message_for(&ScanResult::NotFound)
        );
    }
}
