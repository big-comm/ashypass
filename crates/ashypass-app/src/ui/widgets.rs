//! Small building blocks shared by the main pages: the per-page header with
//! the sidebar toggle and main menu, clipboard copy that honours the user's
//! clear-after setting, compact empty states and URL helpers.

use crate::state::SharedState;
use crate::tr;
use adw::prelude::*;
use gtk::gio;

/// Window chrome every page header repeats: a sidebar toggle that only shows
/// while the sidebar is collapsed, and the main menu.
#[derive(Clone)]
pub struct Chrome {
    pub split: adw::OverlaySplitView,
    pub menu: gio::Menu,
}

impl Chrome {
    /// Header bar for a page: sidebar toggle at the start, main menu at the
    /// end. Callers pack their own page actions between them.
    pub fn header(&self, title: Option<&gtk::Widget>) -> adw::HeaderBar {
        let header = adw::HeaderBar::new();
        if let Some(title) = title {
            header.set_title_widget(Some(title));
        } else {
            header.set_title_widget(Some(&gtk::Box::new(gtk::Orientation::Horizontal, 0)));
        }

        let toggle = gtk::ToggleButton::builder()
            .icon_name("sidebar-show-symbolic")
            .tooltip_text(tr!("Show sidebar"))
            .build();
        self.split
            .bind_property("collapsed", &toggle, "visible")
            .sync_create()
            .build();
        self.split
            .bind_property("show-sidebar", &toggle, "active")
            .sync_create()
            .bidirectional()
            .build();
        header.pack_start(&toggle);

        let menu_button = gtk::MenuButton::builder()
            .icon_name("open-menu-symbolic")
            .menu_model(&self.menu)
            .tooltip_text(tr!("Main menu"))
            .primary(true)
            .build();
        header.pack_end(&menu_button);
        header
    }
}

/// Large page title with an optional one-line explanation underneath, the
/// way the mockups open each task page.
pub fn page_heading(title: &str, subtitle: Option<&str>) -> gtk::Box {
    let heading = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(4)
        .build();
    let title_label = gtk::Label::builder()
        .label(title)
        .xalign(0.0)
        .wrap(true)
        .build();
    title_label.add_css_class("title-1");
    title_label.set_accessible_role(gtk::AccessibleRole::Heading);
    heading.append(&title_label);
    if let Some(subtitle) = subtitle {
        let subtitle_label = gtk::Label::builder()
            .label(subtitle)
            .xalign(0.0)
            .wrap(true)
            .build();
        subtitle_label.add_css_class("dim-label");
        heading.append(&subtitle_label);
    }
    heading
}

/// A compact empty state: small icon, title, explanation and an optional
/// row of actions. `adw::StatusPage` defaults to a 128 px icon that fills a
/// small window without telling the user what to do next.
pub struct EmptyState {
    pub root: gtk::Box,
    pub icon: gtk::Image,
    pub title: gtk::Label,
    pub description: gtk::Label,
    pub actions: gtk::Box,
}

impl EmptyState {
    pub fn new() -> Self {
        let root = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(8)
            .valign(gtk::Align::Center)
            .halign(gtk::Align::Center)
            .margin_top(24)
            .margin_bottom(24)
            .margin_start(24)
            .margin_end(24)
            .build();
        root.add_css_class("ashy-empty-state");
        let icon = gtk::Image::builder().pixel_size(48).build();
        icon.add_css_class("dim-label");
        icon.set_accessible_role(gtk::AccessibleRole::Presentation);
        let title = gtk::Label::builder()
            .wrap(true)
            .justify(gtk::Justification::Center)
            .build();
        title.add_css_class("title-3");
        let description = gtk::Label::builder()
            .wrap(true)
            .justify(gtk::Justification::Center)
            .max_width_chars(48)
            .build();
        description.add_css_class("dim-label");
        let actions = gtk::Box::builder()
            .orientation(gtk::Orientation::Horizontal)
            .spacing(12)
            .halign(gtk::Align::Center)
            .margin_top(8)
            .build();
        root.append(&icon);
        root.append(&title);
        root.append(&description);
        root.append(&actions);
        Self {
            root,
            icon,
            title,
            description,
            actions,
        }
    }

    pub fn set(&self, icon: &str, title: &str, description: &str) {
        self.icon.set_icon_name(Some(icon));
        self.title.set_label(title);
        self.description.set_label(description);
        self.description.set_visible(!description.is_empty());
        while let Some(child) = self.actions.first_child() {
            self.actions.remove(&child);
        }
        self.actions.set_visible(false);
    }

    pub fn add_action(&self, label: &str, suggested: bool) -> gtk::Button {
        let button = gtk::Button::with_label(label);
        button.add_css_class("pill");
        if suggested {
            button.add_css_class("suggested-action");
        }
        self.actions.append(&button);
        self.actions.set_visible(true);
        button
    }
}

/// Copy `text` and arm the auto-clear timer from the user's setting.
pub fn copy_secret(state: &SharedState, text: &str) {
    let seconds = state.settings().clipboard_clear;
    crate::clipboard::copy(text, seconds);
}

/// The host of a URL without scheme, credentials, port, path or `www.`, for
/// display. Falls back to the trimmed input when it does not parse.
pub fn display_domain(url: &str) -> String {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let with_scheme = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    };
    match url::Url::parse(&with_scheme)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
    {
        Some(host) => host.strip_prefix("www.").unwrap_or(&host).to_string(),
        None => trimmed.to_string(),
    }
}

/// A URL the system can open: adds `https://` to bare hosts and refuses
/// anything that is not http(s), so a stored `file:` or `javascript:` value
/// is never handed to the launcher.
pub fn openable_url(url: &str) -> Option<String> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return None;
    }
    let candidate = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    };
    let parsed = url::Url::parse(&candidate).ok()?;
    matches!(parsed.scheme(), "http" | "https")
        .then(|| parsed.host_str().is_some())
        .filter(|ok| *ok)
        .map(|_| parsed.to_string())
}

/// Subtitle for an access: account and domain, skipping the domain when it is
/// already the title so the same word is not shown twice.
pub fn account_line(title: &str, username: Option<&str>, url: Option<&str>) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(user) = username.map(str::trim).filter(|s| !s.is_empty()) {
        parts.push(user.to_string());
    }
    if let Some(domain) = url.map(display_domain).filter(|s| !s.is_empty()) {
        if !domain.eq_ignore_ascii_case(title.trim()) {
            parts.push(domain);
        }
    }
    parts.join(" · ")
}

/// Group a TOTP code for reading aloud and comparing: `482193` → `482 193`,
/// `12345678` → `1234 5678`, `1234567` → `123 4567`.
pub fn group_code(code: &str) -> String {
    let len = code.chars().count();
    if len < 6 {
        return code.to_string();
    }
    let split = len / 2;
    let (head, tail): (String, String) = (
        code.chars().take(split).collect(),
        code.chars().skip(split).collect(),
    );
    format!("{head} {tail}")
}

/// Mark a label as describing `widget` for assistive technologies.
pub fn describe(widget: &impl IsA<gtk::Accessible>, label: &impl IsA<gtk::Accessible>) {
    widget.update_relation(&[gtk::accessible::Relation::DescribedBy(
        &[label.upcast_ref()],
    )]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_strips_scheme_path_and_www() {
        assert_eq!(
            display_domain("https://www.example.com/login"),
            "example.com"
        );
        assert_eq!(
            display_domain("accounts.example.org"),
            "accounts.example.org"
        );
        assert_eq!(display_domain("http://user@host.tld:8080/x"), "host.tld");
        assert_eq!(display_domain("  "), "");
        assert_eq!(display_domain("192.168.0.10"), "192.168.0.10");
    }

    #[test]
    fn openable_url_only_allows_web_schemes() {
        assert_eq!(
            openable_url("example.com").as_deref(),
            Some("https://example.com/")
        );
        assert!(openable_url("javascript:alert(1)").is_none());
        assert!(openable_url("file:///etc/passwd").is_none());
        assert!(openable_url("").is_none());
    }

    #[test]
    fn account_line_skips_domain_equal_to_title() {
        assert_eq!(
            account_line("example.com", Some("ana"), Some("https://example.com")),
            "ana"
        );
        assert_eq!(
            account_line("Loja", Some("ana@x.com"), Some("https://loja.example")),
            "ana@x.com · loja.example"
        );
        assert_eq!(account_line("Server", None, None), "");
    }

    #[test]
    fn codes_are_grouped_for_reading() {
        assert_eq!(group_code("482193"), "482 193");
        assert_eq!(group_code("12345678"), "1234 5678");
        assert_eq!(group_code("1234567"), "123 4567");
        assert_eq!(group_code("12"), "12");
    }
}
