//! Cryptographically secure password / passphrase / PIN generation.

use crate::config::{AMBIGUOUS_CHARS, DEFAULT_SYMBOLS, MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH};
use crate::{Error, Result};
use rand::seq::SliceRandom;
use rand::{rngs::OsRng, Rng};

/// Legacy word list retained for API compatibility. Generation uses the full
/// 2,048-word BIP39 English list below.
pub const PASSPHRASE_WORDS: &[&str] = &[
    "able",
    "about",
    "above",
    "accept",
    "action",
    "active",
    "actual",
    "advance",
    "advice",
    "afraid",
    "after",
    "again",
    "against",
    "agency",
    "agent",
    "agree",
    "ahead",
    "allow",
    "almost",
    "alone",
    "along",
    "already",
    "always",
    "amount",
    "ancient",
    "angle",
    "angry",
    "animal",
    "annual",
    "another",
    "answer",
    "anyone",
    "apart",
    "appear",
    "apple",
    "apply",
    "approve",
    "april",
    "area",
    "argue",
    "arise",
    "around",
    "arrive",
    "artist",
    "aside",
    "assault",
    "asset",
    "assist",
    "assume",
    "attack",
    "attempt",
    "attend",
    "attract",
    "author",
    "autumn",
    "avenue",
    "avoid",
    "awake",
    "award",
    "aware",
    "balance",
    "barrel",
    "barrier",
    "battle",
    "beach",
    "beauty",
    "become",
    "before",
    "begin",
    "behalf",
    "behave",
    "behind",
    "belief",
    "belong",
    "below",
    "benefit",
    "beside",
    "better",
    "between",
    "beyond",
    "blame",
    "branch",
    "brave",
    "bread",
    "break",
    "bridge",
    "brief",
    "bright",
    "bring",
    "broken",
    "brother",
    "brown",
    "budget",
    "build",
    "burden",
    "button",
    "camera",
    "cancel",
    "cancer",
    "cannot",
    "canvas",
    "capable",
    "capital",
    "carbon",
    "career",
    "careful",
    "carpet",
    "carry",
    "castle",
    "casual",
    "catch",
    "cause",
    "ceiling",
    "center",
    "central",
    "century",
    "certain",
    "chair",
    "challenge",
    "chance",
    "change",
    "channel",
    "chapter",
    "charge",
    "chart",
    "chase",
    "cheap",
    "check",
    "chemical",
    "chest",
    "chicken",
    "chief",
    "child",
    "choice",
    "choose",
    "church",
    "circle",
    "citizen",
    "civil",
    "claim",
    "class",
    "classic",
    "clean",
    "clear",
    "client",
    "climate",
    "climb",
    "clock",
    "close",
    "cloud",
    "coach",
    "coast",
];

#[derive(Debug, Clone)]
pub struct PasswordConfig {
    pub length: usize,
    pub use_uppercase: bool,
    pub use_lowercase: bool,
    pub use_digits: bool,
    pub use_symbols: bool,
    pub exclude_ambiguous: bool,
    pub custom_symbols: String,
}

impl Default for PasswordConfig {
    fn default() -> Self {
        Self {
            length: 16,
            use_uppercase: true,
            use_lowercase: true,
            use_digits: true,
            use_symbols: true,
            exclude_ambiguous: true,
            custom_symbols: String::new(),
        }
    }
}

pub fn generate_password(cfg: &PasswordConfig) -> Result<String> {
    if cfg.length < MIN_PASSWORD_LENGTH || cfg.length > MAX_PASSWORD_LENGTH {
        return Err(Error::InvalidInput(format!(
            "length must be between {MIN_PASSWORD_LENGTH} and {MAX_PASSWORD_LENGTH}"
        )));
    }

    let mut classes: Vec<Vec<char>> = Vec::new();
    if cfg.use_lowercase {
        classes.push(filtered_class(
            "abcdefghijklmnopqrstuvwxyz",
            cfg.exclude_ambiguous,
        ));
    }
    if cfg.use_uppercase {
        classes.push(filtered_class(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            cfg.exclude_ambiguous,
        ));
    }
    if cfg.use_digits {
        classes.push(filtered_class("0123456789", cfg.exclude_ambiguous));
    }
    if cfg.use_symbols {
        let symbols = if cfg.custom_symbols.is_empty() {
            DEFAULT_SYMBOLS
        } else {
            &cfg.custom_symbols
        };
        classes.push(filtered_class(symbols, cfg.exclude_ambiguous));
    }
    if classes.is_empty() {
        return Err(Error::InvalidInput("no character set selected".into()));
    }
    if classes.iter().any(Vec::is_empty) {
        return Err(Error::InvalidInput(
            "a selected character set is empty after filtering".into(),
        ));
    }
    if cfg.length < classes.len() {
        return Err(Error::InvalidInput(
            "length is too short for the selected character sets".into(),
        ));
    }

    let chars: Vec<char> = classes.iter().flatten().copied().collect();
    let mut rng = OsRng;
    let mut password: Vec<char> = classes
        .iter()
        .map(|class| *class.choose(&mut rng).expect("validated non-empty class"))
        .collect();
    password.extend((password.len()..cfg.length).map(|_| chars[rng.gen_range(0..chars.len())]));
    password.shuffle(&mut rng);

    Ok(password.into_iter().collect())
}

fn filtered_class(class: &str, exclude_ambiguous: bool) -> Vec<char> {
    class
        .chars()
        .filter(|character| !exclude_ambiguous || !AMBIGUOUS_CHARS.contains(*character))
        .collect()
}

pub fn generate_passphrase(
    num_words: usize,
    separator: &str,
    capitalize: bool,
    add_number: bool,
) -> String {
    let mut rng = OsRng;
    let mut parts: Vec<String> = (0..num_words)
        .map(|_| {
            let w = bip39::Language::English
                .word_list()
                .choose(&mut rng)
                .expect("BIP39 English word list is non-empty");
            if capitalize {
                let mut s = w.to_string();
                if let Some(c) = s.get_mut(0..1) {
                    c.make_ascii_uppercase();
                }
                s
            } else {
                w.to_string()
            }
        })
        .collect();
    if add_number {
        parts.push(format!("{:04}", rng.gen_range(0..10000)));
    }
    parts.join(separator)
}

pub fn generate_pin(length: usize) -> String {
    let mut rng = OsRng;
    (0..length)
        .map(|_| char::from(b'0' + rng.gen_range(0..10)))
        .collect()
}

/// Backwards-compat alias for the old heuristic estimator. New code should use
/// `crate::strength::estimate` directly for richer info.
#[deprecated(note = "use `crate::strength::legacy_score` or `crate::strength::estimate`")]
pub fn check_password_strength(password: &str) -> (u8, &'static str) {
    crate::strength::legacy_score(password)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_respects_length() {
        let cfg = PasswordConfig {
            length: 24,
            ..Default::default()
        };
        let pw = generate_password(&cfg).unwrap();
        assert_eq!(pw.chars().count(), 24);
    }

    #[test]
    fn password_uses_only_selected_classes() {
        let cfg = PasswordConfig {
            length: 32,
            use_uppercase: false,
            use_symbols: false,
            use_lowercase: true,
            use_digits: true,
            exclude_ambiguous: false,
            custom_symbols: String::new(),
        };
        let pw = generate_password(&cfg).unwrap();
        assert!(pw
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
    }

    #[test]
    fn passphrase_word_count() {
        let p = generate_passphrase(4, "-", true, false);
        assert_eq!(p.split('-').count(), 4);
        let p = generate_passphrase(4, "-", true, true);
        assert_eq!(p.split('-').count(), 5);
    }

    #[test]
    fn pin_is_numeric() {
        let p = generate_pin(6);
        assert_eq!(p.len(), 6);
        assert!(p.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn every_selected_class_is_always_present() {
        let cfg = PasswordConfig {
            length: 8,
            ..PasswordConfig::default()
        };
        for _ in 0..1_000 {
            let password = generate_password(&cfg).unwrap();
            assert!(password.chars().any(|c| c.is_ascii_lowercase()));
            assert!(password.chars().any(|c| c.is_ascii_uppercase()));
            assert!(password.chars().any(|c| c.is_ascii_digit()));
            assert!(password.chars().any(|c| DEFAULT_SYMBOLS.contains(c)));
            assert!(!password.chars().any(|c| AMBIGUOUS_CHARS.contains(c)));
        }
    }

    #[test]
    fn passphrases_use_the_full_bip39_word_list() {
        assert_eq!(bip39::Language::English.word_list().len(), 2048);
        assert!(PASSPHRASE_WORDS.len() < bip39::Language::English.word_list().len());
    }
}
