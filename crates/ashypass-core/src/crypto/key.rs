use zeroize::{Zeroize, ZeroizeOnDrop};

/// 32-byte symmetric key for AES-256-GCM. Zeroed on drop.
#[derive(Clone, ZeroizeOnDrop)]
pub struct DerivedKey(pub(crate) [u8; 32]);

impl DerivedKey {
    pub(crate) fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for DerivedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DerivedKey(***)")
    }
}

impl Zeroize for DerivedKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
