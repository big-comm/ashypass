//! Translation helpers backed by `gettext_rs`.
//!
//! `tr!("literal")` returns a `&'static str`. Translations are looked up via
//! `gettext()` the first time a key is seen and cached per-thread; if the
//! translation equals the source we return the original `'static` slice to
//! avoid leaking anything. Otherwise the translated `String` is leaked once
//! into the cache — locales don't churn at runtime and the working set is
//! bounded by the number of distinct UI strings.

use gettextrs::{gettext, ngettext};
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

pub fn tr_plural(singular: &'static str, plural: &'static str, count: usize) -> String {
    ngettext(singular, plural, count.min(u32::MAX as usize) as u32)
}

pub fn localized_strength_label(label: &str) -> &str {
    match label {
        "Very Weak" => tr_static("Very Weak"),
        "Weak" => tr_static("Weak"),
        "Medium" => tr_static("Medium"),
        "Strong" => tr_static("Strong"),
        "Very Strong" => tr_static("Very Strong"),
        other => other,
    }
}

#[macro_export]
macro_rules! tr {
    ($s:literal) => {
        $crate::ui::i18n::tr_static($s)
    };
}

#[macro_export]
macro_rules! trn {
    ($singular:literal, $plural:literal, $count:expr) => {
        $crate::ui::i18n::tr_plural($singular, $plural, $count)
    };
}
