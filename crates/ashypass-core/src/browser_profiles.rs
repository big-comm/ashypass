//! Whether a browser is really set up for this user.
//!
//! A browser's settings folder alone proves nothing: it stays after the
//! browser is removed, and other programs' installers create
//! `NativeMessagingHosts` inside the folder of every browser they know,
//! installed or not. What a browser writes on its first run does: Chromium
//! browsers keep a `Local State` file at the top of their folder, Firefox
//! browsers a `profiles.ini`.

use std::path::Path;

/// A Chromium-family browser (Chrome, Brave, Edge, Vivaldi, …) has run with
/// `folder` (e.g. `~/.config/google-chrome`) as its user data.
pub fn chromium_in_use(folder: &Path) -> bool {
    folder.join("Local State").is_file()
}

/// A Firefox-family browser has a profile in one of `folders` (its legacy
/// `~/.mozilla/firefox` style folder or its XDG one, such as
/// `~/.config/mozilla/firefox`). The `profiles.ini` is looked for in each
/// folder and one level below it, where forks keep it.
pub fn firefox_in_use(folders: &[&Path]) -> bool {
    folders.iter().any(|folder| {
        folder.join("profiles.ini").is_file()
            || std::fs::read_dir(folder).is_ok_and(|entries| {
                entries
                    .flatten()
                    .any(|entry| entry.path().join("profiles.ini").is_file())
            })
    })
}

/// The extension `id` is in a Chromium-family browser using `folder`: listed
/// in the preferences of one of its profiles (`Default`, `Profile 1`, …).
pub fn chromium_has_extension(folder: &Path, id: &str) -> bool {
    let Ok(entries) = std::fs::read_dir(folder) else {
        return false;
    };
    entries.flatten().any(|entry| {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        (name == "Default" || name.starts_with("Profile "))
            && ["Secure Preferences", "Preferences"].iter().any(|file| {
                read_json(&entry.path().join(file))
                    .is_some_and(|prefs| prefs["extensions"]["settings"][id].is_object())
            })
    })
}

/// The extension `id` is installed and on in a Firefox-family browser: in
/// the `extensions.json` of a profile under one of `folders` (profiles sit
/// one or two levels below them).
pub fn firefox_has_extension(folders: &[&Path], id: &str) -> bool {
    fn subfolders(folder: &Path) -> Vec<std::path::PathBuf> {
        std::fs::read_dir(folder)
            .map(|entries| {
                entries
                    .flatten()
                    .map(|e| e.path())
                    .filter(|p| p.is_dir())
                    .collect()
            })
            .unwrap_or_default()
    }
    folders.iter().any(|folder| {
        subfolders(folder)
            .into_iter()
            .flat_map(|level1| {
                let mut found = subfolders(&level1);
                found.push(level1);
                found
            })
            .any(|profile| {
                read_json(&profile.join("extensions.json")).is_some_and(|list| {
                    list["addons"].as_array().is_some_and(|addons| {
                        addons.iter().any(|addon| {
                            addon["id"] == id && addon["active"].as_bool().unwrap_or(false)
                        })
                    })
                })
            })
    })
}

fn read_json(path: &Path) -> Option<serde_json::Value> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_browser_that_ran_counts() {
        let dir = tempfile::tempdir().unwrap();
        // A folder with nothing but another program's host manifests.
        let leftover = dir.path().join("vivaldi");
        std::fs::create_dir_all(leftover.join("NativeMessagingHosts")).unwrap();
        assert!(!chromium_in_use(&leftover));
        assert!(!chromium_in_use(&dir.path().join("missing")));
        let chrome = dir.path().join("google-chrome");
        std::fs::create_dir_all(&chrome).unwrap();
        std::fs::write(chrome.join("Local State"), "{}").unwrap();
        assert!(chromium_in_use(&chrome));

        let mozilla = dir.path().join(".mozilla");
        std::fs::create_dir_all(mozilla.join("native-messaging-hosts")).unwrap();
        assert!(!firefox_in_use(&[&mozilla]));
        let xdg = dir.path().join("config/mozilla");
        std::fs::create_dir_all(xdg.join("firefox")).unwrap();
        std::fs::write(xdg.join("firefox/profiles.ini"), "[General]").unwrap();
        assert!(firefox_in_use(&[&mozilla, &xdg]));
    }

    #[test]
    fn an_installed_extension_is_found_in_its_profile() {
        let dir = tempfile::tempdir().unwrap();
        let brave = dir.path().join("BraveSoftware/Brave-Browser");
        std::fs::create_dir_all(brave.join("Default")).unwrap();
        std::fs::write(
            brave.join("Default/Secure Preferences"),
            r#"{"extensions":{"settings":{"aaffaajejkomddnihpblnkolkhcgaoom":{"location":1}}}}"#,
        )
        .unwrap();
        assert!(chromium_has_extension(
            &brave,
            "aaffaajejkomddnihpblnkolkhcgaoom"
        ));
        assert!(!chromium_has_extension(
            &brave,
            "someotherextensionidaaaaaaaaaaaa"
        ));

        let xdg = dir.path().join("config/mozilla");
        let profile = xdg.join("firefox/abcd.default-release");
        std::fs::create_dir_all(&profile).unwrap();
        std::fs::write(
            profile.join("extensions.json"),
            r#"{"addons":[{"id":"ashypass@big-comm.github.io","active":true},{"id":"off@x","active":false}]}"#,
        )
        .unwrap();
        assert!(firefox_has_extension(
            &[&xdg],
            "ashypass@big-comm.github.io"
        ));
        assert!(!firefox_has_extension(&[&xdg], "off@x"));
        assert!(!firefox_has_extension(
            &[&dir.path().join("none")],
            "ashypass@big-comm.github.io"
        ));
    }
}
