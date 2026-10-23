//! UI-side favicon loader.
//!
//! Sets the favicon on a `gtk::Image` for a given URL. If the file isn't
//! cached yet, schedules a background fetch and updates the image when it
//! lands. Falls back to a generic icon on failure.

use ashypass_core::favicons;
use gtk::prelude::*;
use gtk::{gdk, glib};
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{mpsc, Arc, LazyLock, Mutex};

const FALLBACK_ICON: &str = "dialog-password-symbolic";
const FETCH_WORKERS: usize = 4;
/// A host whose icon could not be fetched is tried again after this long
/// (the network may have been down), not only after a restart.
const RETRY_MISSING: std::time::Duration = std::time::Duration::from_secs(10 * 60);

/// Decoded once per host: rows re-bind on every scroll, and decoding the
/// file each time is wasted work on the main thread.
#[derive(Clone)]
enum Cached {
    Icon(gdk::Texture),
    Missing(std::time::Instant),
}

struct FetchRequest {
    host: String,
    reply: mpsc::Sender<Option<PathBuf>>,
}

static FETCHER: LazyLock<mpsc::Sender<FetchRequest>> = LazyLock::new(|| {
    let (tx, rx) = mpsc::channel::<FetchRequest>();
    let rx = Arc::new(Mutex::new(rx));
    for _ in 0..FETCH_WORKERS {
        let rx = rx.clone();
        std::thread::spawn(move || loop {
            let request = {
                let Ok(rx) = rx.lock() else {
                    return;
                };
                rx.recv()
            };
            let Ok(request) = request else {
                return;
            };
            let path = favicons::fetch_blocking(&request.host).ok();
            let _ = request.reply.send(path);
        });
    }
    tx
});

thread_local! {
    static CACHE: RefCell<HashMap<String, Cached>> = RefCell::new(HashMap::new());
    /// Images waiting for a host's icon. Every image that asks while a fetch
    /// is in flight is served when it lands, not just the first one.
    static WAITERS: RefCell<HashMap<String, Vec<glib::WeakRef<gtk::Image>>>> =
        RefCell::new(HashMap::new());
}

/// Tag stored on the image so a late fetch result is only applied if the
/// image still shows the same host. List rows are recycled: by the time an
/// icon arrives the image may belong to a different entry.
fn tag_for(host: &str) -> String {
    format!("favicon:{host}")
}

pub fn apply(image: &gtk::Image, url: Option<&str>, pixel: i32) {
    image.set_pixel_size(pixel);

    let Some(host) = url.and_then(favicons::host_of) else {
        image.set_widget_name("");
        image.set_icon_name(Some(FALLBACK_ICON));
        return;
    };
    image.set_widget_name(&tag_for(&host));

    match CACHE.with(|cache| cache.borrow().get(&host).cloned()) {
        Some(Cached::Icon(texture)) => {
            image.set_paintable(Some(&texture));
            return;
        }
        Some(Cached::Missing(at)) if at.elapsed() < RETRY_MISSING => {
            image.set_icon_name(Some(FALLBACK_ICON));
            return;
        }
        _ => {}
    }

    if let Some(texture) = favicons::lookup(&host).and_then(|path| load(&path)) {
        CACHE.with(|cache| {
            cache
                .borrow_mut()
                .insert(host, Cached::Icon(texture.clone()));
        });
        image.set_paintable(Some(&texture));
        return;
    }

    image.set_icon_name(Some(FALLBACK_ICON));
    let first_waiter = WAITERS.with(|waiters| {
        let mut waiters = waiters.borrow_mut();
        let list = waiters.entry(host.clone()).or_default();
        list.push(image.downgrade());
        list.len() == 1
    });
    if !first_waiter {
        return;
    }

    let (reply, rx) = mpsc::channel();
    if FETCHER
        .send(FetchRequest {
            host: host.clone(),
            reply,
        })
        .is_err()
    {
        WAITERS.with(|waiters| {
            waiters.borrow_mut().remove(&host);
        });
        return;
    }

    glib::timeout_add_local(std::time::Duration::from_millis(250), move || {
        let path_opt = match rx.try_recv() {
            Ok(path_opt) => path_opt,
            Err(mpsc::TryRecvError::Empty) => return glib::ControlFlow::Continue,
            Err(mpsc::TryRecvError::Disconnected) => None,
        };
        let texture = path_opt.as_deref().and_then(load);
        CACHE.with(|cache| {
            cache.borrow_mut().insert(
                host.clone(),
                match &texture {
                    Some(texture) => Cached::Icon(texture.clone()),
                    None => Cached::Missing(std::time::Instant::now()),
                },
            );
        });
        let waiting = WAITERS.with(|waiters| waiters.borrow_mut().remove(&host));
        if let Some(texture) = texture {
            let tag = tag_for(&host);
            for image in waiting.into_iter().flatten() {
                if let Some(image) = image.upgrade() {
                    if image.widget_name() == tag {
                        image.set_paintable(Some(&texture));
                    }
                }
            }
        }
        glib::ControlFlow::Break
    });
}

fn load(path: &std::path::Path) -> Option<gdk::Texture> {
    gdk::Texture::from_filename(path)
        .map_err(|e| log::debug!("favicon {} not loadable: {e}", path.display()))
        .ok()
}

/// Forget which sites were looked up (host names say what is in the vault).
/// Called when the vault locks.
pub fn clear_cache() {
    CACHE.with(|cache| cache.borrow_mut().clear());
}

thread_local! {
    /// Brand icons drawn so far, by Simple Icons id.
    static BRANDS: RefCell<HashMap<String, Option<gdk::Texture>>> = RefCell::new(HashMap::new());
}

/// Show the built-in brand icon for a code named `name` (offline, see
/// `ashypass_core::brand_icons`). Returns false, leaving `image` as it
/// was, when no brand matches.
pub fn apply_brand(image: &gtk::Image, name: &str, pixel: i32) -> bool {
    let Some(brand) = ashypass_core::brand_icons::find(name) else {
        return false;
    };
    let texture = BRANDS.with(|cache| {
        cache
            .borrow_mut()
            .entry(brand.slug.clone())
            .or_insert_with(|| {
                // Drawn at twice the size shown, for HiDPI screens.
                let svg = brand.svg((pixel * 2) as u32);
                gdk::Texture::from_bytes(&glib::Bytes::from_owned(svg.into_bytes()))
                    .map_err(|e| log::warn!("brand icon {}: {e}", brand.slug))
                    .ok()
            })
            .clone()
    });
    let Some(texture) = texture else {
        return false;
    };
    image.set_widget_name("");
    image.set_pixel_size(pixel);
    image.set_paintable(Some(&texture));
    true
}
