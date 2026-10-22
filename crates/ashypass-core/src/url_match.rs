//! Which saved logins belong to a page or app: the rules the browser
//! extension and the Android autofill share. Same site means the same
//! registrable domain on the Public Suffix List (so `github.io` users are
//! kept apart), a compatible scheme (never an `https` login on an `http`
//! page) and a compatible port.

/// Pull the hostname out of a URL, stripping the scheme and any path. Returns
/// `None` only if the input is empty.
pub fn url_host(input: &str) -> Option<String> {
    let s = input.trim();
    if s.is_empty() {
        return None;
    }
    let authority = url_authority(s);
    // A bracketed IPv6 literal is full of colons, so strip the port only after
    // the closing bracket; splitting on ':' first would reduce it to "[".
    let host = match authority.strip_prefix('[') {
        Some(rest) => rest.split_once(']').map(|(h, _)| h).unwrap_or(rest),
        None => authority.split(':').next().unwrap_or(""),
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

/// Split `input` into the text before `://` and the rest, but only when that
/// `://` comes before the first `/`, `?`, `#` or `\`: in
/// `example.com/login?next=https://other.com` the `://` belongs to the query,
/// and the string has no scheme.
fn split_scheme(input: &str) -> (Option<&str>, &str) {
    let Some(separator) = input.find("://") else {
        return (None, input);
    };
    let path_start = input.find(['/', '?', '#', '\\']).unwrap_or(input.len());
    if separator <= path_start {
        (Some(&input[..separator]), &input[separator + 3..])
    } else {
        (None, input)
    }
}

/// The `host[:port]` part of a URL, without scheme, userinfo or path.
fn url_authority(input: &str) -> &str {
    let (_, no_scheme) = split_scheme(input);
    // The authority ends at the first `/`, `?` or `#`. Missing `#` here let
    // `https://evil.com#@example.com` resolve to `example.com`.
    let authority_end = no_scheme
        .find(['/', '?', '#', '\\'])
        .unwrap_or(no_scheme.len());
    no_scheme[..authority_end].rsplit('@').next().unwrap_or("")
}

/// Port component of a URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UrlPort {
    /// No port, or an empty one (`host:`): the scheme's default port.
    Default,
    Explicit(u16),
    /// Not a number in `0..=65535`. Never matches anything.
    Invalid,
}

fn url_port(input: &str) -> UrlPort {
    let authority = url_authority(input.trim());
    let after_host = match authority.strip_prefix('[') {
        Some(rest) => rest.split_once(']').map_or("", |(_, r)| r),
        None => authority.split_once(':').map_or("", |(_, p)| p),
    };
    let port = after_host.strip_prefix(':').unwrap_or(after_host);
    if port.is_empty() {
        UrlPort::Default
    } else if port.bytes().all(|b| b.is_ascii_digit()) {
        port.parse().map_or(UrlPort::Invalid, UrlPort::Explicit)
    } else {
        UrlPort::Invalid
    }
}

/// Well-known default port of `scheme`, if any.
fn default_port(scheme: Option<&str>) -> Option<u16> {
    match scheme? {
        "http" | "ws" => Some(80),
        "https" | "wss" => Some(443),
        "ftp" => Some(21),
        _ => None,
    }
}

/// Whether an entry saved with `entry_url` may be offered on `page_url` as
/// far as the port goes. An entry with an explicit port (`https://nas:5001`)
/// only matches a page on that same port; an entry without one only matches
/// pages on the default port of their scheme, so a credential for
/// `https://example.com` is not offered to a service on `example.com:8443`.
fn port_compatible(entry_url: &str, page_url: &str) -> bool {
    let page_default = default_port(url_scheme(page_url).as_deref());
    let page_port = match url_port(page_url) {
        UrlPort::Invalid => return false,
        UrlPort::Default => None,
        UrlPort::Explicit(port) => Some(port),
    };
    match url_port(entry_url) {
        UrlPort::Invalid => false,
        UrlPort::Default => page_port.is_none() || page_port == page_default,
        UrlPort::Explicit(port) => page_port.or(page_default) == Some(port),
    }
}

/// Lower-case scheme of `input` (`https`, `http`, …), or `None` when the
/// string has no `scheme://` prefix (a bare host saved by the user).
fn url_scheme(input: &str) -> Option<String> {
    let scheme = split_scheme(input.trim()).0?;
    let mut chars = scheme.chars();
    let valid = chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
    valid.then(|| scheme.to_ascii_lowercase())
}

/// Whether an entry saved with `entry` scheme may be offered on a page loaded
/// with `page` scheme.
///
/// Downgrades are refused: a credential saved for `https://` is never offered
/// on an `http://` page, where a network attacker controls the content. An
/// `http://` entry may be offered on the `https://` version of the site. A
/// bare host saved without a scheme (`192.168.1.1`, `nas.local`) says
/// nothing about it, so it matches both `http://` and `https://` pages (the
/// port rule still limits it to their default ports unless it names one);
/// `entry_matches_page` reads a bare public site (`example.com`) as `https`.
/// Any other scheme must match exactly, and a page without a recognisable
/// scheme only matches bare-host entries.
fn scheme_compatible(entry: Option<&str>, page: Option<&str>) -> bool {
    match (entry, page) {
        (None, None) => true,
        (Some("https"), Some(page)) => page == "https",
        (None | Some("http"), Some(page)) => page == "http" || page == "https",
        (Some(entry), Some(page)) => entry == page,
        (Some(_), None) => false,
    }
}

/// Full matching rule for `match_url`: compatible scheme, compatible port and
/// same site.
pub fn entry_matches_page(entry_url: &str, page_url: &str) -> bool {
    let (Some(entry_host), Some(page_host)) = (url_host(entry_url), url_host(page_url)) else {
        return false;
    };
    // A bare public site (`example.com`) means its https site: offering it on
    // `http://example.com` would hand it to whoever controls the network.
    // Only local names and addresses (`nas.local`, `192.168.1.1`) keep both.
    let entry_scheme = url_scheme(entry_url).or_else(|| {
        registrable_domain(entry_host.trim_start_matches("www.")).map(|_| "https".to_string())
    });
    scheme_compatible(entry_scheme.as_deref(), url_scheme(page_url).as_deref())
        && port_compatible(entry_url, page_url)
        && host_match(&entry_host, &page_host)
}

/// The registrable domain of `host` (`mail.corp.example.co.uk` →
/// `example.co.uk`), per the Public Suffix List including its private section
/// (`github.io`, `myshopify.com`, `s3.amazonaws.com`, …). Returns `None` when
/// `host` is itself a public suffix, an IP literal, or sits under a suffix the
/// list does not know: such hosts only ever match exactly.
pub(crate) fn registrable_domain(host: &str) -> Option<String> {
    // IP literals have no registrable domain; treating the last two octets as
    // one would make 192.168.1.10 and 10.0.1.10 "the same site".
    if host.parse::<std::net::IpAddr>().is_ok() || host.contains(':') {
        return None;
    }
    let host = host.trim_end_matches('.');
    if host.is_empty() || host.split('.').any(str::is_empty) {
        return None;
    }
    let domain = psl::domain(host.as_bytes())?;
    // The PSL's implicit `*` rule makes any unknown TLD a suffix. Fail closed
    // there instead of guessing that registrations happen at the second level.
    if !domain.suffix().is_known() {
        return None;
    }
    std::str::from_utf8(domain.as_bytes())
        .ok()
        .map(str::to_string)
}

/// Match `candidate` against `target`, allowing `www.` shedding and
/// subdomain-style matches within one registrable domain (so a stored
/// `example.com` entry is offered on `mail.example.com`).
///
/// Crossing a public-suffix boundary is refused: `github.io` must not match
/// `attacker.github.io`, and two hosts that merely share a public suffix
/// (`a.com.br` / `b.com.br`) are unrelated.
fn host_match(candidate: &str, target: &str) -> bool {
    let c = candidate.trim_start_matches("www.");
    let t = target.trim_start_matches("www.");
    if c == t {
        return true;
    }
    // Both sides must resolve to the same registrable domain. IP literals and
    // bare public suffixes yield `None` and so only ever match exactly.
    match (registrable_domain(c), registrable_domain(t)) {
        (Some(cd), Some(td)) => cd == td,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_public_sites_are_https_only_local_names_keep_both() {
        assert!(entry_matches_page(
            "example.com",
            "https://example.com/login"
        ));
        assert!(entry_matches_page(
            "www.example.com/login",
            "https://mail.example.com/"
        ));
        assert!(!entry_matches_page(
            "example.com",
            "http://example.com/login"
        ));
        assert!(!entry_matches_page(
            "example.co.uk",
            "http://shop.example.co.uk/"
        ));
        // Local names and addresses say nothing about the scheme.
        assert!(entry_matches_page("192.168.1.1", "http://192.168.1.1/"));
        assert!(entry_matches_page("nas.local", "http://nas.local/"));
        assert!(entry_matches_page("router", "http://router/"));
        // Saved with http on purpose: still offered there.
        assert!(entry_matches_page(
            "http://example.com",
            "http://example.com/login"
        ));
    }

    #[test]
    fn url_host_strips_scheme_and_path() {
        assert_eq!(
            url_host("https://example.com/login?next=/x"),
            Some("example.com".into())
        );
        assert_eq!(url_host("example.com"), Some("example.com".into()));
        assert_eq!(
            url_host("https://USER:PW@host.tld:8443/x"),
            Some("host.tld".into())
        );
        assert_eq!(url_host(""), None);
    }

    #[test]
    fn url_host_ignores_userinfo_lookalikes_after_the_authority() {
        assert_eq!(
            url_host("https://evil.com#@example.com/"),
            Some("evil.com".into())
        );
        assert_eq!(
            url_host("https://evil.com?@example.com"),
            Some("evil.com".into())
        );
        assert_eq!(
            url_host("https://evil.com\\@example.com"),
            Some("evil.com".into())
        );
    }

    #[test]
    fn url_host_keeps_ipv6_literals_intact() {
        assert_eq!(url_host("http://[::1]:8080/x"), Some("::1".into()));
        assert_eq!(
            url_host("http://[2001:db8::5]/"),
            Some("2001:db8::5".into())
        );
    }

    #[test]
    fn host_match_handles_www_and_subdomains() {
        assert!(host_match("example.com", "example.com"));
        assert!(host_match("www.example.com", "example.com"));
        assert!(host_match("example.com", "www.example.com"));
        assert!(host_match("mail.example.com", "example.com"));
        assert!(host_match("example.com", "mail.example.com"));
        assert!(host_match("a.corp.example.com", "b.example.com"));
        assert!(!host_match("attacker.com", "example.com"));
        assert!(!host_match("example.org", "example.com"));
    }

    #[test]
    fn host_match_respects_public_suffix_boundaries() {
        // A bare public suffix must not vouch for its tenants.
        assert!(!host_match("github.io", "attacker.github.io"));
        assert!(!host_match("attacker.github.io", "victim.github.io"));
        assert!(!host_match("com.br", "banco.com.br"));
        assert!(!host_match("a.com.br", "b.com.br"));
        // …but real registrable domains under a multi-label suffix still work.
        assert!(host_match("banco.com.br", "www.banco.com.br"));
        assert!(host_match("login.banco.com.br", "banco.com.br"));
        assert!(host_match("shop.co.uk", "www.shop.co.uk"));
        assert!(!host_match("shop.co.uk", "other.co.uk"));
    }

    #[test]
    fn host_match_rejects_ip_literal_confusion() {
        assert!(host_match("192.168.1.10", "192.168.1.10"));
        assert!(!host_match("192.168.1.10", "10.0.1.10"));
        assert!(!host_match("192.168.1.10", "168.1.10"));
        assert!(!host_match("2001:db8::5", "2001:db8::6"));
    }

    #[test]
    fn unknown_public_suffixes_fail_closed() {
        // `school.nz` is not in the built-in list and `nz` is not flat: the
        // old two-label fallback made these "the same site".
        assert!(!host_match("a.school.nz", "evil.school.nz"));
        assert!(!host_match("login.example.zz", "example.zz"));
        assert!(!host_match("a.example.zz", "b.example.zz"));
        assert!(!host_match("a.gov.pl", "evil.gov.pl"));
        // …but exact matches (and `www.`) still work there.
        assert!(host_match("example.zz", "example.zz"));
        assert!(host_match("www.example.zz", "example.zz"));
        assert!(host_match("bank.school.nz", "bank.school.nz"));
        // Listed second-level registries behave like a public suffix.
        assert!(!host_match("a.co.nz", "evil.co.nz"));
        assert!(host_match("shop.co.nz", "login.shop.co.nz"));
        assert!(!host_match("a.com.io", "b.com.io"));
        assert!(!host_match("a.edu.br", "b.edu.br"));
        // Flat TLDs keep subdomain matching.
        assert!(host_match("accounts.example.de", "example.de"));
        assert_eq!(
            registrable_domain("x.y.example.com").as_deref(),
            Some("example.com")
        );
        assert_eq!(registrable_domain("x.example.zz"), None);
        assert_eq!(registrable_domain("com"), None);
    }

    #[test]
    fn longest_listed_suffix_wins() {
        assert_eq!(
            registrable_domain("bucket.s3.amazonaws.com").as_deref(),
            Some("bucket.s3.amazonaws.com")
        );
        assert!(!host_match("a.s3.amazonaws.com", "b.s3.amazonaws.com"));
    }

    #[test]
    fn public_suffix_list_private_section_is_honoured() {
        // Shared hosts under a flat TLD: each tenant is its own site.
        assert!(!host_match("shop.myshopify.com", "evil.myshopify.com"));
        assert!(host_match("shop.myshopify.com", "www.shop.myshopify.com"));
        assert!(host_match("admin.shop.myshopify.com", "shop.myshopify.com"));
        assert_eq!(
            registrable_domain("admin.shop.myshopify.com").as_deref(),
            Some("shop.myshopify.com")
        );
        assert_eq!(registrable_domain("myshopify.com"), None);
        assert!(!host_match("victim.github.io", "attacker.github.io"));
        assert!(host_match("victim.github.io", "docs.victim.github.io"));
        assert_eq!(registrable_domain("github.io"), None);
    }

    #[test]
    fn public_suffix_list_icann_section_is_honoured() {
        assert_eq!(
            registrable_domain("mail.corp.example.co.uk").as_deref(),
            Some("example.co.uk")
        );
        assert_eq!(registrable_domain("co.uk"), None);
        assert!(host_match("login.example.co.uk", "example.co.uk"));
        assert!(!host_match("example.co.uk", "attacker.co.uk"));
        // A plain second-level registration.
        assert_eq!(
            registrable_domain("a.b.example.com").as_deref(),
            Some("example.com")
        );
        assert!(host_match("accounts.example.com", "example.com"));
        assert!(!host_match("example.com", "example.com.evil.net"));
        // Trailing dots and empty labels.
        assert_eq!(
            registrable_domain("www.example.com.").as_deref(),
            Some("example.com")
        );
        assert_eq!(registrable_domain("a..example.com"), None);
    }

    #[test]
    fn url_port_parsing() {
        assert_eq!(url_port("https://example.com/x"), UrlPort::Default);
        assert_eq!(url_port("https://example.com:/x"), UrlPort::Default);
        assert_eq!(url_port("example.com:8443"), UrlPort::Explicit(8443));
        assert_eq!(
            url_port("https://u:p@example.com:8443/x"),
            UrlPort::Explicit(8443)
        );
        assert_eq!(url_port("http://[::1]:8080/"), UrlPort::Explicit(8080));
        assert_eq!(url_port("http://[::1]/"), UrlPort::Default);
        assert_eq!(url_port("https://example.com:99999"), UrlPort::Invalid);
        assert_eq!(url_port("https://example.com:80x"), UrlPort::Invalid);
    }

    #[test]
    fn entry_matching_respects_ports() {
        // An entry without a port only matches the default port.
        assert!(entry_matches_page(
            "https://example.com",
            "https://example.com/"
        ));
        assert!(entry_matches_page(
            "https://example.com",
            "https://example.com:443/"
        ));
        assert!(!entry_matches_page(
            "https://example.com",
            "https://example.com:8443/"
        ));
        assert!(!entry_matches_page(
            "example.com",
            "https://example.com:8443/"
        ));
        assert!(entry_matches_page(
            "http://example.com",
            "https://example.com/"
        ));
        // An explicit port only matches that port.
        assert!(entry_matches_page(
            "https://nas.example.com:5001",
            "https://nas.example.com:5001/login"
        ));
        assert!(!entry_matches_page(
            "https://nas.example.com:5001",
            "https://nas.example.com/"
        ));
        assert!(!entry_matches_page(
            "https://nas.example.com:5001",
            "https://nas.example.com:5002/"
        ));
        assert!(entry_matches_page(
            "example.com:8443",
            "https://example.com:8443/"
        ));
        // An explicit default port behaves like no port.
        assert!(entry_matches_page(
            "https://example.com:443",
            "https://example.com/"
        ));
        assert!(entry_matches_page(
            "http://192.168.1.10:8080",
            "http://192.168.1.10:8080/"
        ));
        assert!(!entry_matches_page(
            "http://192.168.1.10:8080",
            "http://192.168.1.10/"
        ));
        // Malformed ports never match.
        assert!(!entry_matches_page(
            "https://example.com:abc",
            "https://example.com/"
        ));
        assert!(!entry_matches_page(
            "https://example.com",
            "https://example.com:abc/"
        ));
    }

    #[test]
    fn scheme_rules() {
        assert_eq!(url_scheme("HTTPS://example.com").as_deref(), Some("https"));
        assert_eq!(url_scheme("example.com"), None);
        assert_eq!(url_scheme("1x://example.com"), None);
        // No downgrade.
        assert!(!scheme_compatible(Some("https"), Some("http")));
        // A bare host carries no scheme to downgrade from.
        assert!(scheme_compatible(None, Some("http")));
        // Same scheme or upgrade.
        assert!(scheme_compatible(Some("https"), Some("https")));
        assert!(scheme_compatible(None, Some("https")));
        assert!(scheme_compatible(Some("http"), Some("http")));
        assert!(scheme_compatible(Some("http"), Some("https")));
        // Other schemes match exactly only.
        assert!(scheme_compatible(Some("ftp"), Some("ftp")));
        assert!(!scheme_compatible(Some("ftp"), Some("https")));
        assert!(!scheme_compatible(None, Some("chrome-extension")));
        assert!(!scheme_compatible(Some("https"), None));
    }

    #[test]
    fn entry_matching_combines_scheme_and_host() {
        assert!(entry_matches_page(
            "https://example.com",
            "https://login.example.com/x"
        ));
        assert!(entry_matches_page("example.com", "https://example.com/"));
        assert!(!entry_matches_page(
            "https://example.com",
            "http://example.com/"
        ));
        // A bare public site is its https site (no downgrade).
        assert!(!entry_matches_page("example.com", "http://example.com/"));
        assert!(entry_matches_page(
            "http://intranet.example.com",
            "http://intranet.example.com/"
        ));
        assert!(entry_matches_page(
            "http://example.com",
            "https://example.com/"
        ));
        assert!(!entry_matches_page(
            "https://example.com",
            "https://evil.com#@example.com"
        ));
        assert!(!entry_matches_page("", "https://example.com"));
    }

    #[test]
    fn bare_host_entries_match_http_and_https_on_default_ports() {
        for entry in ["192.168.1.1", "nas.local"] {
            for scheme in ["http", "https"] {
                assert!(
                    entry_matches_page(entry, &format!("{scheme}://{entry}/login")),
                    "{entry} on {scheme}"
                );
            }
            assert!(entry_matches_page(entry, &format!("http://{entry}:80/")));
            assert!(entry_matches_page(entry, &format!("https://{entry}:443/")));
            // Not on another port, and not on other schemes.
            assert!(!entry_matches_page(entry, &format!("http://{entry}:8080/")));
            assert!(!entry_matches_page(
                entry,
                &format!("https://{entry}:8443/")
            ));
            assert!(!entry_matches_page(entry, &format!("ftp://{entry}/")));
        }
        // A bare host with a port matches that port on either scheme.
        assert!(entry_matches_page(
            "nas.local:5000",
            "http://nas.local:5000/"
        ));
        assert!(entry_matches_page(
            "nas.local:5000",
            "https://nas.local:5000/"
        ));
        assert!(!entry_matches_page("nas.local:5000", "http://nas.local/"));
        // A different IP is still a different site.
        assert!(!entry_matches_page("192.168.1.1", "http://192.168.1.2/"));
        // An explicit https entry is still never offered over http.
        assert!(!entry_matches_page(
            "https://nas.local",
            "http://nas.local/"
        ));
    }

    #[test]
    fn scheme_separator_inside_the_path_or_query_is_not_a_scheme() {
        let entry = "example.com/login?next=https://other.com";
        assert_eq!(split_scheme(entry), (None, entry));
        assert_eq!(url_scheme(entry), None);
        assert_eq!(url_authority(entry), "example.com");
        assert_eq!(url_host(entry), Some("example.com".into()));
        assert_eq!(url_port(entry), UrlPort::Default);
        assert!(entry_matches_page(entry, "https://example.com/"));
        assert!(!entry_matches_page(entry, "https://other.com/"));
        for input in [
            "example.com#https://other.com",
            "example.com?x=ftp://other.com",
        ] {
            assert_eq!(url_host(input), Some("example.com".into()), "{input}");
            assert_eq!(url_scheme(input), None, "{input}");
        }
        // A real scheme is still recognised.
        assert_eq!(
            split_scheme("https://example.com/a?b=http://c"),
            (Some("https"), "example.com/a?b=http://c")
        );
        assert_eq!(
            url_host("https://example.com/?next=https://other.com"),
            Some("example.com".into())
        );
    }
}
