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
}
