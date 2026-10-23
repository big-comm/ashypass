//! `settings_dialog` — browser extension section.
//!
//! The extension talks to `ashypass-native-host`; the browser finds that
//! program through a small manifest file in its own configuration folder.
//! "Connect browsers" writes those manifests for this user, so nothing has to
//! be typed in a terminal.

use super::*;

/// Store pages of the published extension. Empty until it is published;
/// the rows are hidden while empty.
const FIREFOX_STORE_URL: &str = "";
const CHROME_STORE_URL: &str = "";

pub(super) fn populate_browser(page: &adw::PreferencesPage, state: SharedState, toast: Toaster) {
    let group = adw::PreferencesGroup::builder()
        .title(tr!("Browser extension"))
        .description(tr!(
            "Fill and copy your passwords in Chrome, Brave, Edge, Vivaldi, Firefox and LibreWolf. The extension never stores anything: it asks Ashy Pass each time, and only fills a page after you click."
        ))
        .build();
    let switch = adw::SwitchRow::builder()
        .title(tr!("Allow the browser extension"))
        .subtitle(tr!(
            "When off, the extension cannot see anything in the vault"
        ))
        .active(state.settings().browser_extension)
        .build();
    {
        let state = state.clone();
        switch.connect_active_notify(move |row| {
            let active = row.is_active();
            if let Err(e) = state.update_settings(|s| s.browser_extension = active) {
                log::warn!("could not save settings: {e}");
            }
        });
    }
    group.add(&switch);
    page.add(&group);

    let connect_group = adw::PreferencesGroup::builder()
        .title(tr!("Connect your browsers"))
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
    connect_row.add_suffix(&connect);
    connect_group.add(&connect_row);

    // One row per browser set up for this user: connected or not.
    let status_rows: Rc<RefCell<Vec<adw::ActionRow>>> = Rc::default();
    let refresh_status: Rc<dyn Fn()> = {
        // Weak: the Connect button, inside the group, calls it.
        let group = connect_group.downgrade();
        let rows = status_rows.clone();
        Rc::new(move || {
            let Some(group) = group.upgrade() else {
                return;
            };
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
                let label = gtk::Label::new(Some(if connected {
                    tr!("Connected")
                } else {
                    tr!("Not connected")
                }));
                label.add_css_class(if connected { "success" } else { "dim-label" });
                if connected {
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
        let toast = toast.clone();
        let refresh_status = refresh_status.clone();
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
                    refresh_status();
                    let message = match result {
                        Ok(0) => tr!("No supported browser was found. Open your browser once, then try again.").to_string(),
                        Ok(count) => trn!(
                            "Connected to {} browser. Restart it if it is open.",
                            "Connected to {} browsers. Restart them if they are open.",
                            count
                        )
                        .replace("{}", &count.to_string()),
                        Err(e) => format!("{}: {e}", tr!("Could not connect the browsers")),
                    };
                    toast.add_toast(adw::Toast::builder().title(message).timeout(6).build());
                },
            );
        });
    }
    page.add(&connect_group);

    let unlock_group = adw::PreferencesGroup::builder()
        .title(tr!("Unlocking"))
        .description(tr!(
            "The extension asks for your master password and keeps the vault open only until the automatic lock. If “Open automatically at login” is on, it opens without asking. Locking the screen locks it too, when that option is on."
        ))
        .build();
    page.add(&unlock_group);

    let stores: Vec<(&str, &str)> = [
        (tr!("Get the extension for Firefox"), FIREFOX_STORE_URL),
        (
            tr!("Get the extension for Chrome, Brave, Edge and Vivaldi"),
            CHROME_STORE_URL,
        ),
    ]
    .into_iter()
    .filter(|(_, url)| !url.is_empty())
    .collect();
    if !stores.is_empty() {
        let store_group = adw::PreferencesGroup::new();
        for (title, url) in stores {
            let row = adw::ActionRow::builder()
                .title(title)
                .activatable(true)
                .build();
            row.add_suffix(&gtk::Image::from_icon_name("adw-external-link-symbolic"));
            let url = url.to_string();
            row.connect_activated(move |row| {
                let parent = row.root().and_then(|r| r.downcast::<gtk::Window>().ok());
                gtk::UriLauncher::new(&url).launch(
                    parent.as_ref(),
                    None::<&gio::Cancellable>,
                    |_| {},
                );
            });
            store_group.add(&row);
        }
        page.add(&store_group);
    }
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
fn browser_connections(paths: &BrowserPaths) -> Vec<(&'static str, bool)> {
    let BrowserPaths {
        home,
        config,
        system,
    } = paths;
    let chrome = |name, dir: &str, system_dir: Option<&str>| {
        let profile = config.join(dir);
        let mut manifests = vec![profile.join("NativeMessagingHosts").join(HOST_MANIFEST)];
        manifests.extend(system_dir.map(|d| system.join(d).join(HOST_MANIFEST)));
        (name, profile.exists(), manifests, "allowed_origins")
    };
    let firefox = |name, legacy: &str, xdg: &str, system_dir: Option<&str>| {
        let installed = home.join(legacy).exists() || config.join(xdg).exists();
        let mut manifests = vec![home
            .join(legacy)
            .join("native-messaging-hosts")
            .join(HOST_MANIFEST)];
        manifests.extend(system_dir.map(|d| system.join(d).join(HOST_MANIFEST)));
        (name, installed, manifests, "allowed_extensions")
    };
    const CHROME: Option<&str> = Some("etc/opt/chrome/native-messaging-hosts");
    const EDGE: Option<&str> = Some("etc/opt/edge/native-messaging-hosts");
    // Each channel and edition has its own profile folder (as in
    // `ashypass-native-host --install`).
    let browsers = [
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
    ];
    browsers
        .into_iter()
        .filter(|(_, installed, _, _)| *installed)
        .map(|(name, _, manifests, allowed)| {
            let connected = manifests.iter().any(|path| manifest_works(path, allowed));
            (name, connected)
        })
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
        std::fs::create_dir_all(paths.home.join(".mozilla/firefox")).unwrap();
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
        let found = browser_connections(&paths);
        assert_eq!(
            found,
            vec![
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
                ("Chromium", false),
                ("Brave", false),
                ("Brave Origin", false),
                ("Firefox", false)
            ]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
