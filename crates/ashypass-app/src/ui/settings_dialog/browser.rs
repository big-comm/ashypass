//! `settings_dialog` — browser extension section.
//!
//! The extension talks to `ashypass-native-host`; the browser finds that
//! program through a small manifest file in its own configuration folder.
//! "Connect browsers" writes those manifests for this user, so nothing has to
//! be typed in a terminal.

use super::*;

/// Store pages of the published extension; empty until it is published
/// there, and the first step then points at the instructions instead.
const FIREFOX_STORE_URL: &str = "https://addons.mozilla.org/firefox/addon/ashy-pass/";
const CHROME_STORE_URL: &str =
    "https://chromewebstore.google.com/detail/ashy-pass/aaffaajejkomddnihpblnkolkhcgaoom";
const MANUAL_INSTALL_URL: &str =
    "https://github.com/big-comm/ashypass/blob/main/browser-extension/README.md#load-the-unpacked-extension";

/// Three numbered steps, in the order they are done: install the extension,
/// connect the browsers (which also allows the extension), and the switch
/// that allows it. Each browser found says whether it is connected, and
/// whether the switch blocks it.
pub(super) fn populate_browser(page: &adw::PreferencesPage, state: SharedState, toast: Toaster) {
    let intro = adw::PreferencesGroup::builder()
        .title(tr!("Browser extension"))
        .description(tr!(
            "Fill and copy your passwords in Chrome, Brave, Edge, Vivaldi, Firefox and LibreWolf. The extension never stores anything: it asks Ashy Pass each time, and only fills a page after you click."
        ))
        .build();
    page.add(&intro);

    // ---- 1. Install ----------------------------------------------------
    let install_group = adw::PreferencesGroup::builder()
        .title(tr!("1. Install the extension"))
        .build();
    // A store card per browser family; a family whose store page is not
    // out yet gets a row to the instructions to load the extension by hand.
    let mut manual_rows = Vec::new();
    for store in [&CHROME_STORE, &FIREFOX_STORE] {
        if store.url.is_empty() {
            manual_rows.push(link_row(
                store.fallback_title(),
                Some(tr!("Not in the store yet: see how to install it by hand")),
                MANUAL_INSTALL_URL,
            ));
        } else {
            let installed = browsers_with_extension(&BrowserPaths::current(), store.family);
            install_group.add(&store_card(store, &installed));
        }
    }
    page.add(&install_group);
    if !manual_rows.is_empty() {
        // Rows in a group of their own: in one group with the cards they
        // would come before them (a group lists its rows first).
        let rows = adw::PreferencesGroup::new();
        for row in &manual_rows {
            rows.add(row);
        }
        page.add(&rows);
    }

    // ---- 2. Connect ----------------------------------------------------
    let connect_group = adw::PreferencesGroup::builder()
        .title(tr!("2. Connect it to Ashy Pass"))
        .description(tr!(
            "Run this once after installing a browser, so it can find Ashy Pass. It only adds a small file to each browser's settings folder."
        ))
        .build();
    let connect_row = adw::ActionRow::builder()
        .title(tr!("Connect browsers"))
        .subtitle(tr!("For the browsers installed for this user"))
        .build();
    let connect = gtk::Button::builder()
        .label(tr!("Connect"))
        .valign(gtk::Align::Center)
        .build();
    connect.add_css_class("suggested-action");
    connect_row.add_suffix(&connect);
    connect_group.add(&connect_row);

    // ---- 3. Allow ------------------------------------------------------
    let allow_group = adw::PreferencesGroup::builder()
        .title(tr!("3. Allow it"))
        .build();
    let switch = adw::SwitchRow::builder()
        .title(tr!("Allow the browser extension"))
        .subtitle(tr!(
            "Turned on when you connect. When off, the extension cannot see anything in the vault"
        ))
        .active(state.settings().browser_extension)
        .build();
    allow_group.add(&switch);

    // One row per browser set up for this user: connected or not, and
    // blocked while the switch is off.
    let status_rows: Rc<RefCell<Vec<adw::ActionRow>>> = Rc::default();
    let refresh_status: Rc<dyn Fn()> = {
        // Weak: the Connect button and the switch, inside the page, call it.
        let group = connect_group.downgrade();
        let switch = switch.downgrade();
        let rows = status_rows.clone();
        Rc::new(move || {
            let (Some(group), Some(switch)) = (group.upgrade(), switch.upgrade()) else {
                return;
            };
            let allowed = switch.is_active();
            for row in rows.borrow_mut().drain(..) {
                group.remove(&row);
            }
            let found = browser_connections(&BrowserPaths::current());
            if found.is_empty() {
                let row = adw::ActionRow::builder()
                    .title(tr!("No browser found yet"))
                    .subtitle(tr!("Open your browser once, then connect"))
                    .build();
                group.add(&row);
                rows.borrow_mut().push(row);
            }
            for (name, connected) in found {
                let row = adw::ActionRow::builder().title(name).build();
                let (text, class) = match (connected, allowed) {
                    (true, true) => (tr!("Connected"), "success"),
                    (true, false) => (tr!("Connected, but blocked (step 3)"), "warning"),
                    (false, _) => (tr!("Not connected"), "dim-label"),
                };
                let label = gtk::Label::new(Some(text));
                label.add_css_class(class);
                if connected && allowed {
                    row.add_suffix(&gtk::Image::from_icon_name("object-select-symbolic"));
                }
                row.add_suffix(&label);
                group.add(&row);
                rows.borrow_mut().push(row);
            }
        })
    };
    refresh_status();
    {
        let state = state.clone();
        let refresh_status = refresh_status.clone();
        switch.connect_active_notify(move |row| {
            let active = row.is_active();
            if let Err(e) = state.update_settings(|s| s.browser_extension = active) {
                log::warn!("could not save settings: {e}");
            }
            refresh_status();
        });
    }
    {
        let toast = toast.clone();
        let refresh_status = refresh_status.clone();
        let switch = switch.downgrade();
        connect.connect_clicked(move |button| {
            let Some(host) = native_host_path() else {
                toast.add_toast(
                    adw::Toast::builder()
                        .title(tr!("The browser connector of Ashy Pass is not installed"))
                        .timeout(5)
                        .build(),
                );
                return;
            };
            button.set_sensitive(false);
            let button = button.clone();
            let toast = toast.clone();
            let refresh_status = refresh_status.clone();
            let switch = switch.clone();
            run_background(
                move || {
                    let mut command = std::process::Command::new(host);
                    command.arg("--install").stdin(std::process::Stdio::null());
                    // The scripted UI harness runs with throwaway XDG folders
                    // but the real HOME: keep the manifests inside the
                    // throwaway profile instead of the user's browsers.
                    #[cfg(debug_assertions)]
                    if std::env::var_os("ASHYPASS_DEV_SCRIPT").is_some() {
                        if let Some(root) = std::env::var_os("XDG_DATA_HOME")
                            .map(std::path::PathBuf::from)
                            .and_then(|data| data.parent().map(|p| p.join("home")))
                        {
                            let _ = std::fs::create_dir_all(root.join(".config/chromium"));
                            command.env("HOME", root);
                        }
                    }
                    command
                        .output()
                        .map_err(|e| e.to_string())
                        .and_then(|out| {
                            if out.status.success() {
                                Ok(String::from_utf8_lossy(&out.stdout)
                                    .lines()
                                    .filter(|line| line.starts_with("wrote "))
                                    .count())
                            } else {
                                Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
                            }
                        })
                },
                move |result| {
                    button.set_sensitive(true);
                    // Connecting is asking for the extension: allow it too
                    // (this refreshes the list through the switch).
                    if let (Ok(count), Some(switch)) = (&result, switch.upgrade()) {
                        if *count > 0 {
                            switch.set_active(true);
                        }
                    }
                    refresh_status();
                    let message = match result {
                        Ok(0) => tr!("No supported browser was found. Open your browser once, then try again.").to_string(),
                        Ok(count) => trn!(
                            "Connected to {} browser. Restart it if it is open.",
                            "Connected to {} browsers. Restart them if they are open.",
                            count
                        )
                        .replace("{}", &count.to_string()),
                        Err(e) => format!("{}: {}", tr!("Could not connect the browsers"), crate::ui::errors::describe(&e)),
                    };
                    toast.add_toast(adw::Toast::builder().title(message).timeout(6).build());
                },
            );
        });
    }
    page.add(&connect_group);
    page.add(&allow_group);

    let unlock_group = adw::PreferencesGroup::builder()
        .title(tr!("Unlocking"))
        .description(tr!(
            "The extension asks for your master password and keeps the vault open only until the automatic lock. If “Open automatically at login” is on, it opens without asking. Locking the screen locks it too, when that option is on."
        ))
        .build();
    page.add(&unlock_group);
}

/// One store's card: its page, a picture of the extension at work (from the
/// store's own screenshots, built in: showing it fetches nothing) and its
/// words. Texts are source strings, translated when shown.
struct StoreCard {
    url: &'static str,
    picture_en: &'static [u8],
    picture_pt_br: &'static [u8],
    family: Family,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Family {
    Chromium,
    Firefox,
}

const CHROME_STORE: StoreCard = StoreCard {
    url: CHROME_STORE_URL,
    picture_en: include_bytes!("../../../assets/extension-preview-en.png"),
    picture_pt_br: include_bytes!("../../../assets/extension-preview-pt_BR.png"),
    family: Family::Chromium,
};

const FIREFOX_STORE: StoreCard = StoreCard {
    url: FIREFOX_STORE_URL,
    picture_en: include_bytes!("../../../assets/extension-popup-en.png"),
    picture_pt_br: include_bytes!("../../../assets/extension-popup-pt_BR.png"),
    family: Family::Firefox,
};

impl StoreCard {
    fn title(&self) -> &'static str {
        match self.family {
            Family::Chromium => tr!("Ashy Pass for Chrome"),
            Family::Firefox => tr!("Ashy Pass for Firefox"),
        }
    }

    fn body(&self) -> &'static str {
        match self.family {
            Family::Chromium => tr!(
                "Click a login field and pick your login: it fills only on the site it belongs to."
            ),
            Family::Firefox => tr!(
                "Your logins for the site you are on, one click to fill. Search the vault and make new passwords too."
            ),
        }
    }

    fn button(&self) -> &'static str {
        match self.family {
            Family::Chromium => tr!("Add to the browser"),
            Family::Firefox => tr!("Add to Firefox"),
        }
    }

    fn caption(&self) -> &'static str {
        match self.family {
            Family::Chromium => tr!("Chrome Web Store · Chrome, Brave, Edge and Vivaldi"),
            Family::Firefox => tr!("Firefox Add-ons · Firefox and LibreWolf"),
        }
    }

    fn alternative_text(&self) -> &'static str {
        match self.family {
            Family::Chromium => {
                tr!("A login form with the Ashy Pass suggestions under the email field")
            }
            Family::Firefox => {
                tr!("The Ashy Pass window in the browser, with the logins for the site")
            }
        }
    }

    /// The row title while the store page is not out.
    fn fallback_title(&self) -> &'static str {
        match self.family {
            Family::Chromium => tr!("Get the extension for Chrome, Brave, Edge and Vivaldi"),
            Family::Firefox => tr!("Get the extension for Firefox"),
        }
    }
}

/// The extension's store page as a card: a picture of it at work, what it
/// does, and one button to add it. Side by side, or stacked on a narrow
/// window.
/// `installed_in`: the browsers that already have the extension, said on
/// the card (the button then only shows the store page).
fn store_card(store: &StoreCard, installed_in: &[&str]) -> gtk::Widget {
    let portuguese = glib::language_names()
        .first()
        .is_some_and(|lang| lang.starts_with("pt"));
    let bytes = glib::Bytes::from_static(if portuguese {
        store.picture_pt_br
    } else {
        store.picture_en
    });
    let picture = gtk::Picture::builder()
        .can_shrink(true)
        .content_fit(gtk::ContentFit::Contain)
        .width_request(220)
        .height_request(197)
        .build();
    if let Ok(texture) = gdk::Texture::from_bytes(&bytes) {
        picture.set_paintable(Some(&texture));
    }
    picture.set_alternative_text(Some(store.alternative_text()));

    let text = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(8)
        .valign(gtk::Align::Center)
        .width_request(220)
        .build();
    let title = gtk::Label::builder()
        .label(store.title())
        .xalign(0.0)
        .wrap(true)
        .max_width_chars(26)
        .build();
    title.add_css_class("title-4");
    text.append(&title);
    let body = gtk::Label::builder()
        .label(store.body())
        .xalign(0.0)
        .wrap(true)
        // A natural width that leaves room for the picture beside it.
        .max_width_chars(32)
        .build();
    body.add_css_class("dim-label");
    text.append(&body);
    let add = gtk::Button::builder()
        .label(store.button())
        .halign(gtk::Align::Start)
        .margin_top(4)
        .build();
    add.add_css_class("pill");
    if installed_in.is_empty() {
        add.add_css_class("suggested-action");
    } else {
        let status = gtk::Box::builder()
            .orientation(gtk::Orientation::Horizontal)
            .spacing(6)
            .build();
        status.append(&gtk::Image::from_icon_name("object-select-symbolic"));
        let names = installed_in.join(", ");
        status.append(
            &gtk::Label::builder()
                .label(tr!("Installed in {}").replace("{}", &names))
                .xalign(0.0)
                .wrap(true)
                .max_width_chars(30)
                .build(),
        );
        status.add_css_class("success");
        text.append(&status);
        add.set_label(tr!("Open in the store"));
    }
    text.append(&add);
    let browsers = gtk::Label::builder()
        .label(store.caption())
        .xalign(0.0)
        .wrap(true)
        .max_width_chars(32)
        .build();
    browsers.add_css_class("caption");
    browsers.add_css_class("dim-label");
    text.append(&browsers);
    {
        let url = store.url;
        let family = store.family;
        add.connect_clicked(move |button| open_store(button, url, family));
    }

    let card = adw::WrapBox::builder()
        .child_spacing(18)
        .line_spacing(12)
        .margin_top(12)
        .margin_bottom(12)
        .margin_start(12)
        .margin_end(12)
        .build();
    // The picture's own size (480 px) would be its natural width and push
    // the text under it even on a wide window.
    card.append(
        &adw::Clamp::builder()
            .maximum_size(220)
            .child(&picture)
            .build(),
    );
    card.append(&text);
    let frame = gtk::Box::new(gtk::Orientation::Vertical, 0);
    frame.add_css_class("card");
    // Room between one store's card and the next.
    frame.set_margin_bottom(12);
    frame.append(&card);
    frame.upcast()
}

/// Desktop files of the Firefox-family browsers, the usual first.
const FIREFOX_APPS: &[&str] = &[
    "firefox.desktop",
    "org.mozilla.firefox.desktop",
    "firefox-esr.desktop",
    "librewolf.desktop",
    "io.gitlab.librewolf-community.desktop",
    "waterfox.desktop",
];

/// Open a store page. Firefox Add-ons opens in a Firefox-family browser:
/// in the default browser (Brave, Chrome) it only offers to download
/// Firefox. The Chrome Web Store serves several browsers, so it opens in
/// the default one.
fn open_store(button: &gtk::Button, url: &str, family: Family) {
    if family == Family::Firefox {
        let firefox = gio::AppInfo::all().into_iter().find(|app| {
            app.id()
                .is_some_and(|id| FIREFOX_APPS.contains(&id.as_str()))
        });
        if let Some(app) = firefox {
            let context = button.display().app_launch_context();
            match app.launch_uris(&[url], Some(&context)) {
                Ok(()) => return,
                Err(e) => log::warn!("could not open {url} in {}: {e}", app.name()),
            }
        }
    }
    let parent = button.root().and_then(|r| r.downcast::<gtk::Window>().ok());
    gtk::UriLauncher::new(url).launch(parent.as_ref(), None::<&gio::Cancellable>, |_| {});
}

/// A row that opens `url` in the browser.
fn link_row(title: &str, subtitle: Option<&str>, url: &str) -> adw::ActionRow {
    let row = adw::ActionRow::builder()
        .title(title)
        .activatable(true)
        .build();
    if let Some(subtitle) = subtitle {
        row.set_subtitle(subtitle);
    }
    row.add_suffix(&gtk::Image::from_icon_name("adw-external-link-symbolic"));
    let url = url.to_string();
    row.connect_activated(move |row| {
        let parent = row.root().and_then(|r| r.downcast::<gtk::Window>().ok());
        gtk::UriLauncher::new(&url).launch(parent.as_ref(), None::<&gio::Cancellable>, |_| {});
    });
    row
}

/// The native host program: next to this executable (development builds,
/// the test bundle), then where the package installs it.
fn native_host_path() -> Option<std::path::PathBuf> {
    let beside = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join("ashypass-native-host")));
    beside
        .into_iter()
        .chain([std::path::PathBuf::from(
            "/usr/lib/ashypass/ashypass-native-host",
        )])
        .find(|path| path.is_file())
}

/// Where browsers look for the native host's manifest: this user's folders
/// and the ones the package installs system-wide.
struct BrowserPaths {
    home: std::path::PathBuf,
    config: std::path::PathBuf,
    /// Prefix of the system-wide folders (`/`; a temporary folder in tests).
    system: std::path::PathBuf,
}

impl BrowserPaths {
    fn current() -> Self {
        let home = dirs::home_dir().unwrap_or_default();
        let config = std::env::var_os("XDG_CONFIG_HOME")
            .map(std::path::PathBuf::from)
            .filter(|p| p.is_absolute())
            .unwrap_or_else(|| home.join(".config"));
        Self {
            home,
            config,
            system: "/".into(),
        }
    }
}

const HOST_MANIFEST: &str = "com.bigcommunity.ashypass.json";

/// The browsers set up for this user, and whether each finds Ashy Pass: a
/// manifest (its own, or the package's) that points at an existing host and
/// allows an extension. The folders are the ones `ashypass-native-host
/// --install` writes to.
/// The extension's ids in the two stores (as allowed by the native host).
const CHROME_EXTENSION_ID: &str = "aaffaajejkomddnihpblnkolkhcgaoom";
const FIREFOX_EXTENSION_ID: &str = "ashypass@big-comm.github.io";

/// A browser this user may have: where it keeps its data, and where it
/// looks for the host manifest (this user's first, then the system's).
struct Browser {
    name: &'static str,
    family: Family,
    folders: Vec<std::path::PathBuf>,
    manifests: Vec<std::path::PathBuf>,
}

impl Browser {
    /// Set up for this user: it ran at least once (see
    /// `ashypass_core::browser_profiles`).
    fn in_use(&self) -> bool {
        use ashypass_core::browser_profiles::{chromium_in_use, firefox_in_use};
        match self.family {
            Family::Chromium => self.folders.iter().any(|f| chromium_in_use(f)),
            Family::Firefox => firefox_in_use(&self.folder_refs()),
        }
    }

    /// The Ashy Pass extension is installed in it.
    fn has_extension(&self) -> bool {
        use ashypass_core::browser_profiles::{chromium_has_extension, firefox_has_extension};
        match self.family {
            Family::Chromium => self
                .folders
                .iter()
                .any(|f| chromium_has_extension(f, CHROME_EXTENSION_ID)),
            Family::Firefox => firefox_has_extension(&self.folder_refs(), FIREFOX_EXTENSION_ID),
        }
    }

    /// The browser reads this user's manifest first: when there is one it
    /// decides, even if the package's system-wide one would work (a
    /// manifest that allows no extension blocks them all).
    fn connected(&self) -> bool {
        let allowed = match self.family {
            Family::Chromium => "allowed_origins",
            Family::Firefox => "allowed_extensions",
        };
        self.manifests
            .iter()
            .find(|path| path.exists())
            .is_some_and(|path| manifest_works(path, allowed))
    }

    fn folder_refs(&self) -> Vec<&std::path::Path> {
        self.folders.iter().map(|f| f.as_path()).collect()
    }
}

/// Every browser Ashy Pass knows, set up or not. Each channel and edition
/// has its own profile folder (as in `ashypass-native-host --install`).
fn known_browsers(paths: &BrowserPaths) -> Vec<Browser> {
    let BrowserPaths {
        home,
        config,
        system,
    } = paths;
    let chrome = |name, dir: &str, system_dir: Option<&str>| {
        let profile = config.join(dir);
        let mut manifests = vec![profile.join("NativeMessagingHosts").join(HOST_MANIFEST)];
        manifests.extend(system_dir.map(|d| system.join(d).join(HOST_MANIFEST)));
        Browser {
            name,
            family: Family::Chromium,
            folders: vec![profile],
            manifests,
        }
    };
    let firefox = |name, legacy: &str, xdg: &str, system_dir: Option<&str>| {
        let mut manifests = vec![home
            .join(legacy)
            .join("native-messaging-hosts")
            .join(HOST_MANIFEST)];
        manifests.extend(system_dir.map(|d| system.join(d).join(HOST_MANIFEST)));
        Browser {
            name,
            family: Family::Firefox,
            folders: vec![home.join(legacy), config.join(xdg)],
            manifests,
        }
    };
    const CHROME: Option<&str> = Some("etc/opt/chrome/native-messaging-hosts");
    const EDGE: Option<&str> = Some("etc/opt/edge/native-messaging-hosts");
    vec![
        chrome("Google Chrome", "google-chrome", CHROME),
        chrome("Google Chrome Beta", "google-chrome-beta", CHROME),
        chrome("Google Chrome Dev", "google-chrome-unstable", CHROME),
        chrome(
            "Chromium",
            "chromium",
            Some("etc/chromium/native-messaging-hosts"),
        ),
        chrome("Brave", "BraveSoftware/Brave-Browser", None),
        chrome("Brave Origin", "BraveSoftware/Brave-Origin", None),
        chrome("Brave Beta", "BraveSoftware/Brave-Browser-Beta", None),
        chrome("Brave Nightly", "BraveSoftware/Brave-Browser-Nightly", None),
        chrome("Microsoft Edge", "microsoft-edge", EDGE),
        chrome("Microsoft Edge Beta", "microsoft-edge-beta", EDGE),
        chrome("Microsoft Edge Dev", "microsoft-edge-dev", EDGE),
        chrome("Vivaldi", "vivaldi", None),
        chrome("Vivaldi Snapshot", "vivaldi-snapshot", None),
        firefox(
            "Firefox",
            ".mozilla",
            "mozilla",
            Some("usr/lib/mozilla/native-messaging-hosts"),
        ),
        firefox("LibreWolf", ".librewolf", "librewolf", None),
        firefox("Waterfox", ".waterfox", "waterfox", None),
    ]
}

/// The browsers set up for this user, and whether each finds Ashy Pass.
fn browser_connections(paths: &BrowserPaths) -> Vec<(&'static str, bool)> {
    known_browsers(paths)
        .into_iter()
        .filter(Browser::in_use)
        .map(|browser| (browser.name, browser.connected()))
        .collect()
}

/// The browsers of `family` that already have the extension.
fn browsers_with_extension(paths: &BrowserPaths, family: Family) -> Vec<&'static str> {
    known_browsers(paths)
        .into_iter()
        .filter(|browser| browser.family == family && browser.in_use() && browser.has_extension())
        .map(|browser| browser.name)
        .collect()
}

/// A host manifest that points at an existing program and lets at least one
/// extension use it.
fn manifest_works(path: &std::path::Path, allowed_key: &str) -> bool {
    let Ok(text) = std::fs::read_to_string(path) else {
        return false;
    };
    let Ok(manifest) = serde_json::from_str::<serde_json::Value>(&text) else {
        return false;
    };
    manifest["name"] == "com.bigcommunity.ashypass"
        && manifest["path"]
            .as_str()
            .is_some_and(|host| std::path::Path::new(host).is_file())
        && manifest[allowed_key]
            .as_array()
            .is_some_and(|ids| !ids.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &std::path::Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    #[test]
    fn browsers_show_connected_only_with_a_working_manifest() {
        let dir = std::env::temp_dir().join(format!("ashypass-browsers-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let host = dir.join("bin/ashypass-native-host");
        write(&host, "");
        let paths = BrowserPaths {
            home: dir.join("home"),
            config: dir.join("home/.config"),
            system: dir.join("root"),
        };
        let manifest = |key: &str, ids: &str| {
            format!(
                r#"{{"name":"com.bigcommunity.ashypass","path":"{}","type":"stdio","{key}":{ids}}}"#,
                host.display()
            )
        };
        // Set up: Brave (connected), Chromium (no extension allowed), Firefox
        // (through the package's system manifest); Vivaldi is not installed.
        write(
            &paths
                .config
                .join("BraveSoftware/Brave-Browser/NativeMessagingHosts")
                .join(HOST_MANIFEST),
            &manifest("allowed_origins", r#"["chrome-extension://abc/"]"#),
        );
        write(
            &paths
                .config
                .join("chromium/NativeMessagingHosts")
                .join(HOST_MANIFEST),
            &manifest("allowed_origins", "[]"),
        );
        write(
            &paths
                .system
                .join("usr/lib/mozilla/native-messaging-hosts")
                .join(HOST_MANIFEST),
            &manifest("allowed_extensions", r#"["ashypass@big-comm.github.io"]"#),
        );
        write(
            &paths
                .config
                .join("BraveSoftware/Brave-Origin/NativeMessagingHosts")
                .join(HOST_MANIFEST),
            &manifest("allowed_origins", r#"["chrome-extension://abc/"]"#),
        );
        // Chrome: the package's system manifest works, but an older Connect
        // left this user's manifest allowing nothing, and that one wins.
        write(
            &paths
                .config
                .join("google-chrome/NativeMessagingHosts")
                .join(HOST_MANIFEST),
            &manifest("allowed_origins", "[]"),
        );
        write(
            &paths
                .system
                .join("etc/opt/chrome/native-messaging-hosts")
                .join(HOST_MANIFEST),
            &manifest("allowed_origins", r#"["chrome-extension://abc/"]"#),
        );
        // Each of them ran (Local State, a Firefox profile). Vivaldi's
        // folder only holds another program's host manifest: not listed.
        for folder in [
            "google-chrome",
            "chromium",
            "BraveSoftware/Brave-Browser",
            "BraveSoftware/Brave-Origin",
        ] {
            write(&paths.config.join(folder).join("Local State"), "{}");
        }
        write(
            &paths.home.join(".mozilla/firefox/profiles.ini"),
            "[General]",
        );
        write(
            &paths
                .config
                .join("vivaldi/NativeMessagingHosts/com.example.other.json"),
            "{}",
        );
        let found = browser_connections(&paths);
        assert_eq!(
            found,
            vec![
                ("Google Chrome", false),
                ("Chromium", false),
                ("Brave", true),
                ("Brave Origin", true),
                ("Firefox", true)
            ]
        );
        // A manifest whose program is gone does not count.
        std::fs::remove_file(&host).unwrap();
        assert_eq!(
            browser_connections(&paths),
            vec![
                ("Google Chrome", false),
                ("Chromium", false),
                ("Brave", false),
                ("Brave Origin", false),
                ("Firefox", false)
            ]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
