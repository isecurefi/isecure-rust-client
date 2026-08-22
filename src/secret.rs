//! Zeroizing secret value wrappers.

use std::fmt;

use zeroize::{Zeroize, Zeroizing};

/// UTF-8 secret that is redacted from `Debug` and zeroized on drop.
#[derive(Default)]
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    /// Takes ownership of secret text.
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    /// Borrows the secret for the shortest possible caller-controlled scope.
    pub fn expose_secret(&self) -> &str {
        self.0.as_str()
    }

    /// Returns whether the secret contains no bytes.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the secret length without exposing its contents.
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for SecretString {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretString([REDACTED])")
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Secret bytes that are redacted from `Debug` and zeroized on drop.
#[derive(Default)]
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    /// Takes ownership of secret bytes.
    pub fn new(value: Vec<u8>) -> Self {
        Self(Zeroizing::new(value))
    }

    /// Borrows the bytes for the shortest possible caller-controlled scope.
    pub fn expose_secret(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Returns whether the secret contains no bytes.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the secret length without exposing its contents.
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl From<Vec<u8>> for SecretBytes {
    fn from(value: Vec<u8>) -> Self {
        Self::new(value)
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretBytes([REDACTED])")
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_exposes_secret_values() {
        let text = SecretString::new("text-secret-canary");
        let bytes = SecretBytes::new(b"bytes-secret-canary".to_vec());

        assert_eq!(format!("{text:?}"), "SecretString([REDACTED])");
        assert_eq!(format!("{bytes:?}"), "SecretBytes([REDACTED])");
    }
}
