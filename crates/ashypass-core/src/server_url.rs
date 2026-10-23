//! Normalise a server address typed by a person.
//!
//! People type `cloud.example.com`, `cloud.example.com/` or paste the URL of
//! the page they are looking at. A bare host gets `https://`, surrounding
//! space and trailing slashes go. An explicit `http://` is kept as typed so
//! the HTTPS rule can still reject it with a clear message.

/// `cloud.example.com` → `https://cloud.example.com`.
pub fn normalize(input: &str) -> String {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let with_scheme = if has_scheme(trimmed) {
        trimmed.to_string()
    } else {
        format!("https://{}", trimmed.trim_start_matches('/'))
    };
    with_scheme.trim_end_matches('/').to_string()
}

/// `scheme://` at the very start (RFC 3986 scheme characters), so a `://`
/// later in a path or query does not count.
fn has_scheme(url: &str) -> bool {
    let Some(end) = url.find("://") else {
        return false;
    };
    let scheme = &url[..end];
    scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// Like [`normalize`], for a Nextcloud base address: also drops the
/// `/index.php…` and `/apps/…` paths copied from the browser's address bar.
pub fn normalize_nextcloud(input: &str) -> String {
    let mut url = normalize(input);
    for marker in ["/index.php", "/apps/"] {
        if let Some(position) = url.find(marker) {
            // Only cut inside the path, never in the scheme or host.
            let host_end = url.find("://").map(|i| i + 3).unwrap_or(0);
            if position > host_end {
                url.truncate(position);
            }
        }
    }
    url.trim_end_matches('/').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_scheme_later_in_the_url_is_not_the_scheme() {
        assert_eq!(
            normalize("cloud.example.com/r?u=http://x"),
            "https://cloud.example.com/r?u=http://x"
        );
        assert_eq!(normalize("http://cloud.lan"), "http://cloud.lan");
    }

    #[test]
    fn a_bare_domain_gets_https() {
        assert_eq!(normalize("cloud.example.com"), "https://cloud.example.com");
        assert_eq!(
            normalize("  cloud.example.com/  "),
            "https://cloud.example.com"
        );
        assert_eq!(
            normalize("cloud.example.com:8443/nc"),
            "https://cloud.example.com:8443/nc"
        );
        assert_eq!(
            normalize("https://cloud.example.com//"),
            "https://cloud.example.com"
        );
        assert_eq!(normalize(""), "");
    }

    #[test]
    fn an_explicit_http_is_kept_for_the_https_check() {
        assert_eq!(
            normalize("http://cloud.example.com"),
            "http://cloud.example.com"
        );
    }

    #[test]
    fn nextcloud_paths_from_the_address_bar_are_dropped() {
        assert_eq!(
            normalize_nextcloud("cloud.example.com/index.php/apps/passwords/#/folders"),
            "https://cloud.example.com"
        );
        assert_eq!(
            normalize_nextcloud("https://example.com/nextcloud/apps/files/"),
            "https://example.com/nextcloud"
        );
        assert_eq!(
            normalize_nextcloud("cloud.example.com"),
            "https://cloud.example.com"
        );
    }
}
