//! Brand icons for verification codes, from Simple Icons (CC0-1.0, built in:
//! nothing is fetched, no name leaves the device). A code's name ("GitHub",
//! "Google: ana@example.com") is matched exactly against each brand's names
//! and aliases, ignoring case, accents and punctuation; a name that matches
//! no brand gets none, never a guess.
//!
//! The pack is `assets/brand-icons.json.gz`, made by
//! `tools/make_brand_icons.py`; see `assets/BRAND-ICONS.md`.

use serde::Deserialize;
use std::collections::HashMap;
use std::io::Read;
use std::sync::OnceLock;
use unicode_normalization::UnicodeNormalization;

const PACK: &[u8] = include_bytes!("../assets/brand-icons.json.gz");

#[derive(Debug, Deserialize)]
pub struct BrandIcon {
    /// Simple Icons' id (`github`).
    #[serde(rename = "s")]
    pub slug: String,
    /// The brand's names, the first being its title.
    #[serde(rename = "n")]
    names: Vec<String>,
    /// Brand colour, `RRGGBB`.
    #[serde(rename = "h")]
    pub hex: String,
    /// SVG path data in a 24×24 box.
    #[serde(rename = "d")]
    path: String,
}

#[derive(Deserialize)]
struct Pack {
    version: String,
    icons: Vec<BrandIcon>,
}

struct Index {
    version: String,
    icons: Vec<BrandIcon>,
    by_name: HashMap<String, usize>,
}

fn index() -> &'static Index {
    static INDEX: OnceLock<Index> = OnceLock::new();
    INDEX.get_or_init(|| {
        let mut json = String::new();
        let pack: Pack = flate2::read::GzDecoder::new(PACK)
            .read_to_string(&mut json)
            .ok()
            .and_then(|_| serde_json::from_str(&json).ok())
            .unwrap_or(Pack {
                version: String::new(),
                icons: Vec::new(),
            });
        let mut by_name = HashMap::new();
        // Titles first, then aliases: an alias never takes another brand's title.
        for primary in [true, false] {
            for (i, icon) in pack.icons.iter().enumerate() {
                let names = if primary {
                    &icon.names[..1.min(icon.names.len())]
                } else {
                    icon.names.get(1..).unwrap_or_default()
                };
                for name in names {
                    let key = normalize(name);
                    if !key.is_empty() {
                        by_name.entry(key).or_insert(i);
                    }
                }
            }
        }
        Index {
            version: pack.version,
            icons: pack.icons,
            by_name,
        }
    })
}

/// Lower case, without accents, letters and digits only: "Fórum BigLinux"
/// and "forum-biglinux" are the same name.
fn normalize(name: &str) -> String {
    name.nfd()
        .filter(char::is_ascii_alphanumeric)
        .flat_map(|c| c.to_lowercase())
        .collect()
}

/// "accounts.google.com" → "google": the registrable domain of a name that
/// is a host (no spaces, a dot, a known public suffix), without the suffix.
fn domain_label(name: &str) -> Option<String> {
    let host = name.to_ascii_lowercase();
    if host.contains(char::is_whitespace) || !host.contains('.') {
        return None;
    }
    let domain = crate::url_match::registrable_domain(&host)?;
    domain.split('.').next().map(str::to_string)
}

/// The Simple Icons version built in.
pub fn version() -> &'static str {
    &index().version
}

/// The brand of a code named `name`: the whole name, the part before a
/// `:` or `(` (as in "Google: ana@example.com", "Amazon (AWS)"), or, for a
/// name that is a site's address ("accounts.google.com"), its registrable
/// domain without the suffix ("google").
pub fn find(name: &str) -> Option<&'static BrandIcon> {
    let index = index();
    let name = name.trim();
    let site = domain_label(name);
    let candidates = [
        Some(name),
        name.split_once(':').map(|(head, _)| head),
        name.split_once('(').map(|(head, _)| head),
        site.as_deref(),
    ];
    let found = candidates
        .into_iter()
        .flatten()
        .map(normalize)
        .filter(|key| !key.is_empty())
        .find_map(|key| index.by_name.get(&key).copied());
    found.map(|i| &index.icons[i])
}

impl BrandIcon {
    /// The brand's title.
    pub fn title(&self) -> &str {
        self.names.first().map(String::as_str).unwrap_or(&self.slug)
    }

    /// The icon as an SVG of `size` pixels: the brand's mark in white or
    /// black (whichever reads on its colour) on a rounded square of the
    /// brand's colour, so it shows on light and dark themes alike.
    pub fn svg(&self, size: u32) -> String {
        let hex = if self.hex.len() == 6 && self.hex.chars().all(|c| c.is_ascii_hexdigit()) {
            self.hex.as_str()
        } else {
            "777777"
        };
        let channel = |i: usize| u8::from_str_radix(&hex[i..i + 2], 16).unwrap_or(0x77) as f64;
        // Relative luminance (sRGB, roughly): light brand colours get a black mark.
        let luminance = (0.2126 * channel(0) + 0.7152 * channel(2) + 0.0722 * channel(4)) / 255.0;
        let mark = if luminance > 0.6 {
            "#000000"
        } else {
            "#ffffff"
        };
        format!(
            "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{size}\" height=\"{size}\" viewBox=\"0 0 24 24\">\
             <rect width=\"24\" height=\"24\" rx=\"6\" fill=\"#{hex}\"/>\
             <path transform=\"translate(5 5) scale(0.5833)\" fill=\"{mark}\" d=\"{}\"/></svg>",
            self.path.replace('"', "")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pack_loads() {
        assert!(index().icons.len() > 3000);
        assert!(!version().is_empty());
    }

    #[test]
    fn code_names_find_their_brand() {
        assert_eq!(find("GitHub").unwrap().slug, "github");
        assert_eq!(find("github").unwrap().slug, "github");
        assert_eq!(find("Google: ana@example.com").unwrap().slug, "google");
        assert_eq!(find("Cloudflare").unwrap().slug, "cloudflare");
        assert_eq!(find("  Nextcloud  ").unwrap().slug, "nextcloud");
        assert_eq!(find("Proton Mail").unwrap().slug, "protonmail");
        // Names that are a site's address.
        assert_eq!(find("github.com").unwrap().slug, "github");
        assert_eq!(find("accounts.google.com").unwrap().slug, "google");
        assert_eq!(find("gitlab.com").unwrap().slug, "gitlab");
    }

    #[test]
    fn unknown_or_partial_names_get_none() {
        // Exact names only: no guessing from a part of the name.
        assert!(find("Fórum BigLinux & BigCommunity").is_none());
        assert!(find("My GitHub account").is_none());
        // An unknown site, or a dotted name that is not a host.
        assert!(find("biglinux.com.br").is_none());
        assert!(find("v1.2 beta").is_none());
        assert!(find("").is_none());
        assert!(find("::").is_none());
    }

    #[test]
    fn the_svg_is_well_formed_and_contrasts() {
        let github = find("GitHub").unwrap();
        let svg = github.svg(64);
        assert!(svg.starts_with("<svg") && svg.ends_with("</svg>"));
        assert!(svg.contains("width=\"64\""));
        // GitHub's colour is near black: a white mark.
        assert!(svg.contains("fill=\"#ffffff\""));
    }
}
