//! Aegis Authenticator importer.
//!
//! Aegis exports come in two flavors:
//!   - "plain" JSON (no encryption)
//!   - encrypted JSON (scrypt + AES-256-GCM with a vault password)
//!
//! Only plain import is supported in this initial port; encrypted import is a
//! follow-up (the scrypt vault key + GCM unwrap of slots needs careful porting).

use crate::{Error, Result};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct AegisEntry {
    pub issuer: String,
    pub label: String,
    pub secret: String,
    pub algorithm: String,
    pub digits: u8,
    pub period: u32,
}

#[derive(Deserialize)]
struct AegisFile {
    db: AegisDb,
}
#[derive(Deserialize)]
struct AegisDb {
    entries: Vec<AegisRaw>,
}
#[derive(Deserialize)]
struct AegisRaw {
    #[serde(rename = "type")]
    kind: String,
    name: String,
    issuer: Option<String>,
    info: AegisInfo,
}
#[derive(Deserialize)]
struct AegisInfo {
    secret: String,
    algo: Option<String>,
    digits: Option<u8>,
    period: Option<u32>,
}

pub fn import_plain(path: impl AsRef<Path>) -> Result<Vec<AegisEntry>> {
    let data = std::fs::read_to_string(path)?;
    let parsed: AegisFile = serde_json::from_str(&data)
        .map_err(|e| Error::Other(format!("aegis json: {e}")))?;
    let mut out = Vec::new();
    for raw in parsed.db.entries {
        if !raw.kind.eq_ignore_ascii_case("totp") {
            continue;
        }
        out.push(AegisEntry {
            issuer: raw.issuer.unwrap_or_default(),
            label: raw.name,
            secret: raw.info.secret,
            algorithm: raw.info.algo.unwrap_or_else(|| "SHA1".into()),
            digits: raw.info.digits.unwrap_or(6),
            period: raw.info.period.unwrap_or(30),
        });
    }
    Ok(out)
}
