//! andOTP plain JSON importer.

use crate::{Error, Result};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct AndotpEntry {
    pub issuer: String,
    pub label: String,
    pub secret: String,
    pub algorithm: String,
    pub digits: u8,
    pub period: u32,
}

#[derive(Deserialize)]
struct Raw {
    #[serde(default)]
    issuer: String,
    #[serde(default)]
    label: String,
    secret: String,
    #[serde(default = "default_algo")]
    algorithm: String,
    #[serde(default = "default_digits")]
    digits: u8,
    #[serde(default = "default_period")]
    period: u32,
    #[serde(rename = "type", default)]
    kind: String,
}

fn default_algo() -> String {
    "SHA1".into()
}
fn default_digits() -> u8 {
    6
}
fn default_period() -> u32 {
    30
}

pub fn import_plain(path: impl AsRef<Path>) -> Result<Vec<AndotpEntry>> {
    let data = std::fs::read_to_string(path)?;
    let raws: Vec<Raw> =
        serde_json::from_str(&data).map_err(|e| Error::Other(format!("andotp json: {e}")))?;
    Ok(raws
        .into_iter()
        .filter(|r| r.kind.is_empty() || r.kind.eq_ignore_ascii_case("totp"))
        .map(|r| AndotpEntry {
            issuer: r.issuer,
            label: r.label,
            secret: r.secret,
            algorithm: r.algorithm,
            digits: r.digits,
            period: r.period,
        })
        .collect())
}
