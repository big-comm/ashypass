//! One-time-password parsing shared by the importers.
//!
//! Exporters store TOTP either as an `otpauth://` URI or as a bare base32
//! secret. Everything the vault cannot represent (HOTP counters, Steam
//! tokens, unsupported digit counts) is reported as unsupported instead of
//! being silently coerced to SHA1/6/30, which would generate wrong codes.

use crate::db::vault::NewEntry;
use crate::importers::report::ImportIssue;
use crate::totp::{self, Algorithm};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TotpParams {
    pub secret: String,
    pub algorithm: String,
    pub digits: u8,
    pub period: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TotpField {
    Absent,
    Supported(TotpParams),
    Unsupported { raw: String, reason: String },
}

/// Strip whitespace, separators and `=` padding; base32 is case-insensitive.
pub(crate) fn normalize_secret(secret: &str) -> String {
    secret
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
        .collect::<String>()
        .to_ascii_uppercase()
}

/// Accept the spellings used by the various exporters: `SHA1`, `sha-256`,
/// `HMAC-SHA-512`.
pub(crate) fn normalize_algorithm(value: &str) -> Option<String> {
    let upper = value.trim().to_ascii_uppercase().replace(['-', '_'], "");
    let upper = upper.strip_prefix("HMAC").unwrap_or(&upper);
    Algorithm::parse(upper).ok().map(|a| a.as_str().to_string())
}

/// Validate explicit parameters (Aegis, andOTP, KeePass native fields).
pub(crate) fn from_parts(
    raw: &str,
    secret: &str,
    algorithm: &str,
    digits: u8,
    period: u32,
) -> TotpField {
    let secret = normalize_secret(secret);
    if secret.is_empty() {
        return TotpField::Absent;
    }
    let unsupported = |reason: &str| TotpField::Unsupported {
        raw: raw.to_string(),
        reason: reason.to_string(),
    };
    let Some(algorithm) = normalize_algorithm(algorithm) else {
        return unsupported("unsupported TOTP algorithm");
    };
    if !matches!(digits, 6 | 8) {
        return unsupported("only 6- or 8-digit codes are supported");
    }
    if totp::validate_parameters(digits, period).is_err() {
        return unsupported("unsupported TOTP period");
    }
    let parsed_algorithm = Algorithm::parse(&algorithm).expect("normalized above");
    if totp::generate_totp(&secret, parsed_algorithm, digits, period, 0).is_err() {
        return unsupported("invalid TOTP secret");
    }
    TotpField::Supported(TotpParams {
        secret,
        algorithm,
        digits,
        period,
    })
}

/// Parse a TOTP field that is either an otpauth/steam URI or a bare secret.
pub(crate) fn parse_field(raw: &str) -> TotpField {
    let raw = raw.trim();
    if raw.is_empty() {
        return TotpField::Absent;
    }
    let unsupported = |reason: &str| TotpField::Unsupported {
        raw: raw.to_string(),
        reason: reason.to_string(),
    };
    let lower = raw.to_ascii_lowercase();
    if lower.starts_with("steam://") {
        return unsupported("Steam tokens are not supported");
    }
    if !lower.starts_with("otpauth://") {
        return from_parts(raw, raw, "SHA1", 6, 30);
    }
    let Ok(parsed) = url::Url::parse(raw) else {
        return unsupported("malformed otpauth URI");
    };
    match parsed.host_str().map(str::to_ascii_lowercase).as_deref() {
        Some("totp") => {}
        Some("hotp") => return unsupported("HOTP counters are not supported"),
        _ => return unsupported("unsupported otpauth type"),
    }
    let mut secret = None::<String>;
    let mut algorithm = "SHA1".to_string();
    let mut digits = 6u8;
    let mut period = 30u32;
    for (key, value) in parsed.query_pairs() {
        match key.to_ascii_lowercase().as_str() {
            // query_pairs percent-decodes the value.
            "secret" => secret = Some(value.into_owned()),
            "algorithm" => algorithm = value.into_owned(),
            "digits" => match value.trim().parse() {
                Ok(value) => digits = value,
                Err(_) => return unsupported("invalid TOTP digits"),
            },
            "period" => match value.trim().parse() {
                Ok(value) => period = value,
                Err(_) => return unsupported("invalid TOTP period"),
            },
            "encoder" if value.eq_ignore_ascii_case("steam") => {
                return unsupported("Steam tokens are not supported");
            }
            _ => {}
        }
    }
    let Some(secret) = secret.filter(|s| !s.trim().is_empty()) else {
        return unsupported("otpauth URI has no secret");
    };
    from_parts(raw, &secret, &algorithm, digits, period)
}

/// Store a parsed TOTP on `entry`. An unsupported value is kept verbatim in
/// the (encrypted) notes so nothing is lost, and a warning is recorded.
pub(crate) fn attach(entry: &mut NewEntry, field: TotpField, warnings: &mut Vec<ImportIssue>) {
    match field {
        TotpField::Absent => {}
        TotpField::Supported(params) => {
            entry.totp_secret = Some(params.secret);
            entry.totp_algorithm = Some(params.algorithm);
            entry.totp_digits = Some(params.digits);
            entry.totp_period = Some(params.period);
        }
        TotpField::Unsupported { raw, reason } => {
            append_note(entry, &format!("One-time password (not imported): {raw}"));
            warnings.push(ImportIssue::new(
                &entry.title,
                &format!("{reason}; original value kept in notes"),
            ));
        }
    }
}

pub(crate) fn append_note(entry: &mut NewEntry, text: &str) {
    match entry.notes.as_mut().filter(|n| !n.is_empty()) {
        Some(notes) => {
            notes.push_str("\n\n");
            notes.push_str(text);
        }
        None => entry.notes = Some(text.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn supported(field: TotpField) -> TotpParams {
        match field {
            TotpField::Supported(params) => params,
            other => panic!("expected supported TOTP, got {other:?}"),
        }
    }

    #[test]
    fn keeps_uri_parameters() {
        let params = supported(parse_field(
            "otpauth://totp/Ex:alice?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=8&period=60",
        ));
        assert_eq!(params.algorithm, "SHA256");
        assert_eq!(params.digits, 8);
        assert_eq!(params.period, 60);
        assert_eq!(params.secret, "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn percent_decodes_and_normalizes_secret() {
        let params = supported(parse_field(
            "otpauth://totp/x?secret=jbsw%20y3dp%20ehpk%203pxp%3D%3D&algorithm=sha512",
        ));
        assert_eq!(params.secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(params.algorithm, "SHA512");
    }

    #[test]
    fn bare_secret_uses_defaults() {
        let params = supported(parse_field(" jbswy3dpehpk3pxp "));
        assert_eq!(
            (params.algorithm.as_str(), params.digits, params.period),
            ("SHA1", 6, 30)
        );
    }

    #[test]
    fn unsupported_values_are_reported() {
        for raw in [
            "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=3",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=7",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&encoder=steam",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5",
            "otpauth://totp/x?issuer=nosecret",
            "steam://JBSWY3DPEHPK3PXP",
            "not base32 !!!",
        ] {
            assert!(
                matches!(parse_field(raw), TotpField::Unsupported { .. }),
                "{raw}"
            );
        }
        assert_eq!(parse_field("  "), TotpField::Absent);
    }

    #[test]
    fn algorithm_spellings() {
        assert_eq!(
            normalize_algorithm("HMAC-SHA-256").as_deref(),
            Some("SHA256")
        );
        assert_eq!(normalize_algorithm("sha1").as_deref(), Some("SHA1"));
        assert_eq!(normalize_algorithm("MD5"), None);
    }

    #[test]
    fn unsupported_totp_is_kept_in_notes() {
        let mut entry = NewEntry {
            title: "Example".into(),
            notes: Some("existing".into()),
            ..NewEntry::default()
        };
        let mut warnings = Vec::new();
        attach(
            &mut entry,
            parse_field("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=7"),
            &mut warnings,
        );
        assert!(entry.totp_secret.is_none());
        assert!(entry.notes.as_deref().unwrap().starts_with("existing\n\n"));
        assert!(entry.notes.as_deref().unwrap().contains("digits=7"));
        assert_eq!(warnings.len(), 1);
    }
}
