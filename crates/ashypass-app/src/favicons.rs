//! UI-side favicon loader.
//!
//! Sets the favicon on a `gtk::Image` for a given URL. If the file isn't
//! cached yet, schedules a background fetch and updates the image when it
//! lands. Falls back to a generic icon on failure.

use ashypass_core::favicons;
use gtk::glib;
use gtk::prelude::*;
use std::cell::RefCell;
use std::collections::HashMap;
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
        CACHE.with(|cache| {
            cache.borrow_mut().insert(host.clone(), path_opt.clone());
        });
        let waiting = WAITERS.with(|waiters| waiters.borrow_mut().remove(&host));
        if let Some(path) = path_opt {
            let tag = tag_for(&host);
            for image in waiting.into_iter().flatten() {
                if let Some(image) = image.upgrade() {
                    if image.widget_name() == tag {
                        image.set_from_file(Some(&path));
                    }
                }
            }
        }
        glib::ControlFlow::Break
    });
}
