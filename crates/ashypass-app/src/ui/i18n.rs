//! Translation helpers backed by `gettext_rs`.
//!
//! `tr!("literal")` returns a `&'static str`. Translations are looked up via
//! `gettext()` the first time a key is seen and cached per-thread; if the
//! translation equals the source we return the original `'static` slice to
//! avoid leaking anything. Otherwise the translated `String` is leaked once
//! into the cache — locales don't churn at runtime and the working set is
//! bounded by the number of distinct UI strings.

use gettextrs::gettext;
use std::cell::RefCell;
use std::collections::HashMap;

thread_local! {
    static CACHE: RefCell<HashMap<&'static str, &'static str>> = RefCell::new(HashMap::new());
}

pub fn tr_static(source: &'static str) -> &'static str {
    CACHE.with(|c| {
        if let Some(v) = c.borrow().get(source) {
            return *v;
        }
        let translated = gettext(source);
        let v: &'static str = if translated == source {
            source
        } else {
            Box::leak(translated.into_boxed_str())
        };
        c.borrow_mut().insert(source, v);
        v
    })
}

#[macro_export]
macro_rules! tr {
    ($s:literal) => {
        $crate::ui::i18n::tr_static($s)
    };
}
