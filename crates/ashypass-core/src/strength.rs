//! Password strength estimation backed by `zxcvbn`.
//!
//! Exposes:
//! - `Strength { score, entropy_bits, label, crack_seconds_offline_fast }`
//! - `estimate(password, user_inputs)` — the proper analysis (used by the
//!   auditoria report and the live strength meter).
//! - `legacy_score(password)` — `(u8, &'static str)` for the existing UI call
//!   sites that haven't migrated yet. Returns a 0..=100 score derived from the
//!   zxcvbn 0..=4 scale.

use zxcvbn::{zxcvbn, Score};

#[derive(Debug, Clone)]
pub struct Strength {
    /// 0..=4 from zxcvbn.
    pub score: u8,
    /// log2(guesses).
    pub entropy_bits: f64,
    pub label: &'static str,
    /// Offline fast-hash attacker (10B guesses/s).
    pub crack_seconds_offline_fast: f64,
}

pub fn estimate(password: &str, user_inputs: &[&str]) -> Strength {
    let est = zxcvbn(password, user_inputs);
    let score_u8 = match est.score() {
        Score::Zero => 0,
        Score::One => 1,
        Score::Two => 2,
        Score::Three => 3,
        Score::Four => 4,
        _ => 0,
    };
    let guesses = est.guesses() as f64;
    let entropy_bits = if guesses > 1.0 { guesses.log2() } else { 0.0 };
    Strength {
        score: score_u8,
        entropy_bits,
        label: label_for(score_u8),
        crack_seconds_offline_fast: guesses / 10_000_000_000.0,
    }
}

pub fn label_for(score: u8) -> &'static str {
    match score {
        0 => "Very Weak",
        1 => "Weak",
        2 => "Medium",
        3 => "Strong",
        _ => "Very Strong",
    }
}

/// Backwards-compatible scoring: (0..=100, &'static str).
///
/// Maps the zxcvbn 0..=4 scale to a 0..=100 range so the existing UI
/// `LevelBar` doesn't need to change.
pub fn legacy_score(password: &str) -> (u8, &'static str) {
    if password.is_empty() {
        return (0, label_for(0));
    }
    let s = estimate(password, &[]);
    let pct = match s.score {
        0 => 10,
        1 => 30,
        2 => 55,
        3 => 80,
        _ => 100,
    };
    (pct, s.label)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn very_weak_passwords_score_zero_or_one() {
        for pw in &["password", "123456", "qwerty"] {
            let (pct, _) = legacy_score(pw);
            assert!(pct <= 30, "expected weak score for {pw:?}, got {pct}");
        }
    }

    #[test]
    fn very_strong_password_scores_high() {
        let (pct, _) = legacy_score("Tr0ub4dor&3xC9!aB_pZmQ-9k");
        assert!(pct >= 80, "expected strong score, got {pct}");
    }

    #[test]
    fn entropy_increases_with_length() {
        let short = estimate("abc123!", &[]);
        let long = estimate("abcdef123456!@#$%^abcXYZqq", &[]);
        assert!(long.entropy_bits > short.entropy_bits);
    }
}
