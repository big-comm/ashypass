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
    {
        let toast = toast.clone();
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
