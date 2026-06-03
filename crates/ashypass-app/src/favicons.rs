//! UI-side favicon loader.
//!
//! Sets the favicon on a `gtk::Image` for a given URL. If the file isn't
//! cached yet, schedules a background fetch and updates the image when it
//! lands. Falls back to a generic icon on failure.

use ashypass_core::favicons;
use gtk::glib;
use gtk::prelude::*;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{mpsc, Arc, LazyLock, Mutex};

const FALLBACK_ICON: &str = "dialog-password-symbolic";
const FETCH_WORKERS: usize = 4;

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
    static CACHE: RefCell<HashMap<String, Option<PathBuf>>> = RefCell::new(HashMap::new());
    static PENDING: RefCell<HashSet<String>> = RefCell::new(HashSet::new());
}

pub fn apply(image: &gtk::Image, url: Option<&str>, pixel: i32) {
    image.set_pixel_size(pixel);

    let Some(host) = url.and_then(favicons::host_of) else {
        image.set_icon_name(Some(FALLBACK_ICON));
        return;
    };

    if let Some(cached) = CACHE.with(|cache| cache.borrow().get(&host).cloned()) {
        match cached {
            Some(path) => image.set_from_file(Some(&path)),
            None => image.set_icon_name(Some(FALLBACK_ICON)),
        }
        return;
    }

    if let Some(path) = favicons::lookup(&host) {
        CACHE.with(|cache| {
            cache.borrow_mut().insert(host, Some(path.clone()));
        });
        image.set_from_file(Some(&path));
        return;
    }

    image.set_icon_name(Some(FALLBACK_ICON));
    let already_pending = PENDING.with(|pending| !pending.borrow_mut().insert(host.clone()));
    if already_pending {
        return;
    }

    let image_weak = image.downgrade();
    let (reply, rx) = mpsc::channel();
    if FETCHER
        .send(FetchRequest {
            host: host.clone(),
            reply,
        })
        .is_err()
    {
        PENDING.with(|pending| {
            pending.borrow_mut().remove(&host);
        });
        return;
    }

    glib::timeout_add_local(std::time::Duration::from_millis(250), move || {
        let path_opt = match rx.try_recv() {
            Ok(path_opt) => path_opt,
            Err(mpsc::TryRecvError::Empty) => return glib::ControlFlow::Continue,
            Err(mpsc::TryRecvError::Disconnected) => None,
        };
        CACHE.with(|cache| {
            cache.borrow_mut().insert(host.clone(), path_opt.clone());
        });
        PENDING.with(|pending| {
            pending.borrow_mut().remove(&host);
        });
        if let Some(path) = path_opt {
            if let Some(img) = image_weak.upgrade() {
                img.set_from_file(Some(&path));
            }
        }
        glib::ControlFlow::Break
    });
}
