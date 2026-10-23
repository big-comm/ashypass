//! RFC 6238 TOTP + otpauth:// URI parser.

use crate::{Error, Result};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl Algorithm {
    pub fn parse(s: &str) -> Result<Self> {
        match s.to_ascii_uppercase().as_str() {
            "SHA1" => Ok(Self::Sha1),
            "SHA256" => Ok(Self::Sha256),
            "SHA512" => Ok(Self::Sha512),
            other => Err(Error::InvalidInput(format!(
                "unsupported algorithm: {other}"
            ))),
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }
}

pub fn generate_totp(
    base32_secret: &str,
    algo: Algorithm,
    digits: u8,
    period: u32,
    timestamp: u64,
) -> Result<String> {
    validate_parameters(digits, period)?;
    // Sites show the key in groups ("ABCD-EFGH ...") and some keep the
    // base32 `=` padding: neither is part of the key.
    let cleaned: String = base32_secret
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect();
    let upper = cleaned.trim_end_matches('=').to_ascii_uppercase();
    let key = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &upper)
        .ok_or_else(|| Error::InvalidInput("invalid base32 secret".into()))?;
    if key.is_empty() {
        return Err(Error::InvalidInput("TOTP secret is empty".into()));
    }
    let counter = timestamp / period as u64;
    let counter_bytes = counter.to_be_bytes();

    let mac_bytes = match algo {
        Algorithm::Sha1 => {
            let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(&key)
                .map_err(|e| Error::Crypto(format!("hmac: {e}")))?;
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        Algorithm::Sha256 => {
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key)
                .map_err(|e| Error::Crypto(format!("hmac: {e}")))?;
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        Algorithm::Sha512 => {
            let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(&key)
                .map_err(|e| Error::Crypto(format!("hmac: {e}")))?;
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
    };

    let offset = (mac_bytes[mac_bytes.len() - 1] & 0x0F) as usize;
    let code = (((mac_bytes[offset] as u32 & 0x7F) << 24)
        | ((mac_bytes[offset + 1] as u32) << 16)
        | ((mac_bytes[offset + 2] as u32) << 8)
        | (mac_bytes[offset + 3] as u32))
        % 10u32.pow(digits as u32);

    Ok(format!("{:0width$}", code, width = digits as usize))
}

pub fn remaining_seconds(period: u32, now: u64) -> u32 {
    if period == 0 {
        return 0;
    }
    period - (now % period as u64) as u32
}

pub fn validate_parameters(digits: u8, period: u32) -> Result<()> {
    if !matches!(digits, 6 | 8) {
        return Err(Error::InvalidInput("TOTP digits must be 6 or 8".into()));
    }
    if !(1..=300).contains(&period) {
        return Err(Error::InvalidInput(
            "TOTP period must be between 1 and 300 seconds".into(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct OtpAuth {
    pub label: String,
    pub issuer: String,
    pub secret: String,
    pub algorithm: Algorithm,
    pub digits: u8,
    pub period: u32,
}

pub fn parse_otpauth(uri: &str) -> Result<OtpAuth> {
    let parsed = url::Url::parse(uri).map_err(|e| Error::InvalidInput(format!("url: {e}")))?;
    if parsed.scheme() != "otpauth" {
        return Err(Error::InvalidInput("not an otpauth URI".into()));
    }
    if parsed.host_str() != Some("totp") {
        return Err(Error::InvalidInput("only TOTP supported".into()));
    }

    let path = parsed.path().trim_start_matches('/');
    let decoded_path = percent_encoding::percent_decode_str(path)
        .decode_utf8()
        .map_err(|_| Error::InvalidInput("invalid label encoding".into()))?
        .into_owned();

    let mut secret = None::<String>;
    let mut issuer = None::<String>;
    let mut algorithm = Algorithm::Sha1;
    let mut digits = 6u8;
    let mut period = 30u32;
    for (k, v) in parsed.query_pairs() {
        match k.as_ref() {
            "secret" => secret = Some(v.to_string()),
            "issuer" => issuer = Some(v.to_string()),
            "algorithm" => algorithm = Algorithm::parse(&v)?,
            "digits" => {
                digits = v
                    .parse()
                    .map_err(|_| Error::InvalidInput("invalid TOTP digits".into()))?
            }
            "period" => {
                period = v
                    .parse()
                    .map_err(|_| Error::InvalidInput("invalid TOTP period".into()))?
            }
            _ => {}
        }
    }
    let secret = secret.ok_or_else(|| Error::InvalidInput("missing secret".into()))?;
    generate_totp(&secret, algorithm, digits, period, 0)?;
    let (issuer, account) = match decoded_path.split_once(':') {
        Some((i, a)) => (issuer.unwrap_or_else(|| i.to_string()), a.to_string()),
        None => (issuer.unwrap_or_default(), decoded_path.clone()),
    };
    Ok(OtpAuth {
        label: account,
        issuer,
        secret,
        algorithm,
        digits,
        period,
    })
}

// Minimal percent-decoding (avoid pulling another crate); fall back to a tiny impl.
mod percent_encoding {
    pub fn percent_decode_str(s: &str) -> Decoded<'_> {
        Decoded(s)
    }
    pub struct Decoded<'a>(pub &'a str);
    impl<'a> Decoded<'a> {
        pub fn decode_utf8(self) -> Result<std::borrow::Cow<'a, str>, std::str::Utf8Error> {
            let bytes = self.0.as_bytes();
            let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
            let mut i = 0;
            while i < bytes.len() {
                let b = bytes[i];
                if b == b'%' && i + 2 < bytes.len() {
                    let h = |c: u8| -> Option<u8> {
                        match c {
                            b'0'..=b'9' => Some(c - b'0'),
                            b'a'..=b'f' => Some(c - b'a' + 10),
                            b'A'..=b'F' => Some(c - b'A' + 10),
                            _ => None,
                        }
                    };
                    if let (Some(h1), Some(h2)) = (h(bytes[i + 1]), h(bytes[i + 2])) {
                        out.push((h1 << 4) | h2);
                        i += 3;
                        continue;
                    }
                }
                out.push(b);
                i += 1;
            }
            // Use into_owned-style return
            std::str::from_utf8(&out)?;
            Ok(std::borrow::Cow::Owned(unsafe {
                String::from_utf8_unchecked(out)
            }))
        }
    }
}

/// What a Google Authenticator export QR code (`otpauth-migration://offline
/// ?data=…`) holds: its TOTP codes, and how many of its items cannot be
/// used here (HOTP counters, MD5).
#[derive(Debug, Default)]
pub struct Migration {
    pub codes: Vec<OtpAuth>,
    pub unsupported: usize,
}

/// Read a Google Authenticator export QR code. Its payload is a small
/// protobuf message (MigrationPayload), decoded by hand here.
pub fn parse_migration(uri: &str) -> Result<Migration> {
    let parsed =
        url::Url::parse(uri.trim()).map_err(|e| Error::InvalidInput(format!("url: {e}")))?;
    if parsed.scheme() != "otpauth-migration" {
        return Err(Error::InvalidInput("not an otpauth-migration URI".into()));
    }
    let data = parsed
        .query_pairs()
        .find(|(k, _)| k == "data")
        .map(|(_, v)| v.replace(' ', "+"))
        .ok_or_else(|| Error::InvalidInput("missing data".into()))?;
    use base64::Engine as _;
    let trimmed = data.trim_end_matches('=');
    let bytes = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(trimmed)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(trimmed))
        .map_err(|_| Error::InvalidInput("invalid migration data".into()))?;
    let bad = || Error::InvalidInput("invalid migration data".into());
    let mut out = Migration::default();
    for (field, value) in proto_fields(&bytes).ok_or_else(bad)? {
        let (1, ProtoValue::Bytes(item)) = (field, value) else {
            continue;
        };
        let mut secret = Vec::new();
        let (mut name, mut issuer) = (String::new(), String::new());
        let (mut algorithm, mut digits, mut kind) = (1u64, 1u64, 2u64);
        for (field, value) in proto_fields(item).ok_or_else(bad)? {
            match (field, value) {
                (1, ProtoValue::Bytes(b)) => secret = b.to_vec(),
                (2, ProtoValue::Bytes(b)) => name = String::from_utf8_lossy(b).into_owned(),
                (3, ProtoValue::Bytes(b)) => issuer = String::from_utf8_lossy(b).into_owned(),
                (4, ProtoValue::Varint(v)) => algorithm = v,
                (5, ProtoValue::Varint(v)) => digits = v,
                (6, ProtoValue::Varint(v)) => kind = v,
                _ => {}
            }
        }
        let algorithm = match algorithm {
            0 | 1 => Some(Algorithm::Sha1),
            2 => Some(Algorithm::Sha256),
            3 => Some(Algorithm::Sha512),
            _ => None, // MD5
        };
        let digits = match digits {
            0 | 1 => Some(6u8),
            2 => Some(8u8),
            _ => None,
        };
        // Type 1 is HOTP (a counter); 0 (unspecified) and 2 are TOTP.
        let (Some(algorithm), Some(digits), false, false) =
            (algorithm, digits, kind == 1, secret.is_empty())
        else {
            out.unsupported += 1;
            continue;
        };
        let secret = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &secret);
        // "Issuer:account" labels carry the issuer twice.
        let account = match name.split_once(':') {
            Some((prefix, rest)) if issuer.is_empty() || prefix.trim() == issuer.trim() => {
                if issuer.is_empty() {
                    issuer = prefix.trim().to_string();
                }
                rest.trim().to_string()
            }
            _ => name.trim().to_string(),
        };
        out.codes.push(OtpAuth {
            label: account,
            issuer,
            secret,
            algorithm,
            digits,
            period: 30,
        });
    }
    Ok(out)
}

enum ProtoValue<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
}

fn proto_varint(buf: &[u8], at: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let byte = *buf.get(*at)?;
        *at += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

/// The (field number, value) pairs of a protobuf message; `None` when it
/// is malformed. Fixed-width fields are skipped.
fn proto_fields(buf: &[u8]) -> Option<Vec<(u64, ProtoValue<'_>)>> {
    let mut at = 0;
    let mut out = Vec::new();
    while at < buf.len() {
        let key = proto_varint(buf, &mut at)?;
        let field = key >> 3;
        match key & 7 {
            0 => out.push((field, ProtoValue::Varint(proto_varint(buf, &mut at)?))),
            2 => {
                let len = usize::try_from(proto_varint(buf, &mut at)?).ok()?;
                let end = at.checked_add(len)?;
                out.push((field, ProtoValue::Bytes(buf.get(at..end)?)));
                at = end;
            }
            1 => at = at.checked_add(8)?,
            5 => at = at.checked_add(4)?,
            _ => return None,
        }
    }
    (at == buf.len()).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 Appendix B test vectors (SHA1, secret = ASCII "12345678901234567890",
    // which is base32 GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ).
    #[test]
    fn rfc6238_vectors_sha1() {
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let cases: &[(u64, &str)] = &[
            (59, "94287082"),
            (1111111109, "07081804"),
            (1111111111, "14050471"),
            (1234567890, "89005924"),
            (2000000000, "69279037"),
        ];
        for (t, expected) in cases {
            let code = generate_totp(secret, Algorithm::Sha1, 8, 30, *t).unwrap();
            assert_eq!(code, *expected, "ts={}", t);
        }
    }

    fn base32_of(ascii: &str) -> String {
        base32::encode(
            base32::Alphabet::Rfc4648 { padding: false },
            ascii.as_bytes(),
        )
    }

    // RFC 6238 Appendix B: the SHA256 and SHA512 vectors use 32- and 64-byte
    // seeds (the ASCII digits repeated), not the 20-byte SHA1 seed.
    #[test]
    fn rfc6238_vectors_sha256_and_sha512() {
        let sha256 = base32_of("12345678901234567890123456789012");
        let sha512 = base32_of("1234567890123456789012345678901234567890123456789012345678901234");
        let cases: &[(u64, &str, &str)] = &[
            (59, "46119246", "90693936"),
            (1111111109, "68084774", "25091201"),
            (1111111111, "67062674", "99943326"),
            (1234567890, "91819424", "93441116"),
            (2000000000, "90698825", "38618901"),
            (20000000000, "77737706", "47863826"),
        ];
        for (t, expected_256, expected_512) in cases {
            assert_eq!(
                generate_totp(&sha256, Algorithm::Sha256, 8, 30, *t).unwrap(),
                *expected_256,
                "SHA256 ts={t}"
            );
            assert_eq!(
                generate_totp(&sha512, Algorithm::Sha512, 8, 30, *t).unwrap(),
                *expected_512,
                "SHA512 ts={t}"
            );
        }
        let uri = format!("otpauth://totp/x?secret={sha512}&algorithm=sha512&digits=8");
        let parsed = parse_otpauth(&uri).unwrap();
        assert_eq!(parsed.algorithm, Algorithm::Sha512);
        assert_eq!(
            generate_totp(&parsed.secret, parsed.algorithm, 8, 30, 59).unwrap(),
            "90693936"
        );
    }

    #[test]
    fn secret_spellings_produce_the_same_code() {
        let reference =
            generate_totp("JBSWY3DPEHPK3PXP", Algorithm::Sha1, 6, 30, 1234567890).unwrap();
        for spelling in [
            "jbswy3dpehpk3pxp",
            "JBSW Y3DP EHPK 3PXP",
            " jbsw y3dp\tehpk 3pxp ",
        ] {
            assert_eq!(
                generate_totp(spelling, Algorithm::Sha1, 6, 30, 1234567890).unwrap(),
                reference,
                "{spelling:?}"
            );
        }
        // Lowercase and percent-encoded spaces inside an otpauth URI.
        let parsed =
            parse_otpauth("otpauth://totp/x?secret=jbsw%20y3dp%20ehpk%203pxp&issuer=x").unwrap();
        assert_eq!(
            generate_totp(&parsed.secret, parsed.algorithm, 6, 30, 1234567890).unwrap(),
            reference
        );
        // Padded and hyphen-grouped secrets are normalized by the import
        // parser before they reach `generate_totp`.
        for spelling in [
            "JBSWY3DPEHPK3PXP====",
            "jbsw-y3dp-ehpk-3pxp",
            "otpauth://totp/x?secret=jbsw-y3dp-ehpk-3pxp%3D%3D",
        ] {
            let crate::importers::otp::TotpField::Supported(params) =
                crate::importers::otp::parse_field(spelling)
            else {
                panic!("{spelling:?} should be supported");
            };
            assert_eq!(params.secret, "JBSWY3DPEHPK3PXP");
            assert_eq!(
                generate_totp(&params.secret, Algorithm::Sha1, 6, 30, 1234567890).unwrap(),
                reference
            );
        }
    }

    #[test]
    fn period_bounds_are_inclusive() {
        for period in [1, 300] {
            assert!(validate_parameters(6, period).is_ok());
            assert!(generate_totp("JBSWY3DPEHPK3PXP", Algorithm::Sha1, 6, period, 1_000).is_ok());
            let uri = format!("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period={period}");
            assert_eq!(parse_otpauth(&uri).unwrap().period, period);
        }
        assert_eq!(remaining_seconds(1, 1_000), 1);
        assert_eq!(remaining_seconds(300, 1_000), 200);
        for period in [0, 301] {
            assert!(validate_parameters(6, period).is_err());
            let uri = format!("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period={period}");
            assert!(parse_otpauth(&uri).is_err());
        }
    }

    #[test]
    fn google_authenticator_default_secret() {
        // Secret JBSWY3DPEHPK3PXP decodes to "Hello!\xDE\xAD\xBE\xEF" — the standard
        // demo secret. At t=1234567890 we get 742275 (cross-checked with pyotp/oathtool).
        // (The CRYPTO_SPEC.md "005924" entry is incorrect — it accidentally copied the
        // last 6 digits of the 20-byte RFC vector. Tracked for spec update.)
        let code = generate_totp("JBSWY3DPEHPK3PXP", Algorithm::Sha1, 6, 30, 1234567890).unwrap();
        assert_eq!(code, "742275");
    }

    #[test]
    fn parse_otpauth_basic() {
        let uri = "otpauth://totp/ACME%20Co:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30";
        let p = parse_otpauth(uri).unwrap();
        assert_eq!(p.issuer, "ACME Co");
        assert_eq!(p.label, "alice@example.com");
        assert_eq!(p.secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(p.digits, 6);
        assert_eq!(p.period, 30);
    }

    #[test]
    fn rejects_invalid_parameters_without_panicking() {
        assert!(generate_totp("JBSWY3DPEHPK3PXP", Algorithm::Sha1, 7, 30, 0).is_err());
        assert!(generate_totp("JBSWY3DPEHPK3PXP", Algorithm::Sha1, 6, 0, 0).is_err());
        assert_eq!(remaining_seconds(0, 123), 0);
        assert!(parse_otpauth("otpauth://totp/test?secret=JBSWY3DPEHPK3PXP&digits=nope").is_err());
    }

    #[test]
    fn google_authenticator_exports_are_read() {
        fn varint(mut v: u64, out: &mut Vec<u8>) {
            while v >= 0x80 {
                out.push((v as u8) | 0x80);
                v >>= 7;
            }
            out.push(v as u8);
        }
        fn bytes(field: u64, b: &[u8], out: &mut Vec<u8>) {
            varint(field << 3 | 2, out);
            varint(b.len() as u64, out);
            out.extend_from_slice(b);
        }
        fn number(field: u64, v: u64, out: &mut Vec<u8>) {
            varint(field << 3, out);
            varint(v, out);
        }
        let item = |secret: &[u8], name: &str, issuer: &str, algo: u64, digits: u64, kind: u64| {
            let mut m = Vec::new();
            bytes(1, secret, &mut m);
            bytes(2, name.as_bytes(), &mut m);
            bytes(3, issuer.as_bytes(), &mut m);
            number(4, algo, &mut m);
            number(5, digits, &mut m);
            number(6, kind, &mut m);
            m
        };
        let mut payload = Vec::new();
        bytes(
            1,
            &item(b"Hello!\xde\xad\xbe\xef", "GitHub:ana", "GitHub", 1, 1, 2),
            &mut payload,
        );
        bytes(
            1,
            &item(b"another key", "bob@x.com", "", 2, 2, 2),
            &mut payload,
        );
        bytes(1, &item(b"counter", "c", "Bank", 1, 1, 1), &mut payload); // HOTP
        number(2, 1, &mut payload); // version
        use base64::Engine as _;
        let data = base64::engine::general_purpose::STANDARD.encode(&payload);
        let uri = format!(
            "otpauth-migration://offline?data={}",
            url::form_urlencoded::byte_serialize(data.as_bytes()).collect::<String>()
        );
        let m = parse_migration(&uri).unwrap();
        assert_eq!((m.codes.len(), m.unsupported), (2, 1));
        assert_eq!(
            (m.codes[0].issuer.as_str(), m.codes[0].label.as_str()),
            ("GitHub", "ana")
        );
        assert_eq!(m.codes[0].secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(
            (m.codes[1].digits, m.codes[1].algorithm),
            (8, Algorithm::Sha256)
        );
        assert_eq!(m.codes[1].label, "bob@x.com");
        for code in &m.codes {
            generate_totp(&code.secret, code.algorithm, code.digits, code.period, 0).unwrap();
        }
        assert!(parse_migration("otpauth-migration://offline?data=%%%").is_err());
        let empty = parse_migration("otpauth-migration://offline?data=").unwrap();
        assert!(empty.codes.is_empty());
    }
}
