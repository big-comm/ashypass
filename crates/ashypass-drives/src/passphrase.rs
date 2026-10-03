//! Zeroizing passphrase newtype.
//!
//! We never log, format, or clone passphrases except into the child process's
//! stdin. The buffer is wiped on drop via the `zeroize` crate.

use zeroize::Zeroize;

pub struct Passphrase(Vec<u8>);

impl Passphrase {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Read a passphrase from a UTF-8 string. The original `String` is **not**
    /// zeroized — callers that hold the original should pass `bytes.into_bytes()`
    /// directly, or use [`Passphrase::from_string_zeroizing`].
    pub fn from_text(s: &str) -> Self {
        Self(s.as_bytes().to_vec())
    }

    /// Consume a `String`, copy its bytes, and overwrite the original buffer.
    pub fn from_string_zeroizing(mut s: String) -> Self {
        let p = Self(s.as_bytes().to_vec());
        // Best-effort: overwrite then drop. We can't truly zeroize a `String`
        // capacity-side because `String::clear()` only sets len, but writing
        // the same length of zero bytes covers the visible region.
        unsafe {
            let v = s.as_mut_vec();
            v.iter_mut().for_each(|b| *b = 0);
            v.clear();
        }
        p
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for Passphrase {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Passphrase({} bytes redacted)", self.0.len())
    }
}

/// A secret carried as text inside a protocol message (the base64-encoded
/// passphrase of a helper request). Serialises transparently, but `Debug`
/// is redacted and the buffer is wiped on drop.
#[derive(Default, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretString(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_never_contains_the_secret() {
        let p = Passphrase::from_text("hunter2");
        assert!(!format!("{p:?}").contains("hunter2"));
        let s = SecretString::new("aHVudGVyMg==".into());
        assert!(!format!("{s:?}").contains("aHVudGVyMg"));
        assert_eq!(serde_json::to_string(&s).unwrap(), "\"aHVudGVyMg==\"");
    }
}
