//! Explicit resource limits for memory-constrained native and WebAssembly hosts.

use crate::ProtocolError;

const DEFAULT_MAX_URL_BYTES: usize = 8 * 1024;
const DEFAULT_MAX_REQUEST_BODY_BYTES: usize = 48 * 1024 * 1024;
const DEFAULT_MAX_RESPONSE_BODY_BYTES: usize = 48 * 1024 * 1024;
const DEFAULT_MAX_FILE_BYTES: usize = 32 * 1024 * 1024;
const DEFAULT_MAX_SIGNATURE_BYTES: usize = 1024 * 1024;
const DEFAULT_MAX_COLLECTION_ITEMS: usize = 10_000;

/// Memory and collection bounds enforced by the SDK in addition to host limits.
///
/// These defaults are defensive SDK limits, not statements about provider or bank
/// limits. A signed Connector profile may choose lower or higher non-zero values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceLimits {
    max_url_bytes: usize,
    max_request_body_bytes: usize,
    max_response_body_bytes: usize,
    max_file_bytes: usize,
    max_signature_bytes: usize,
    max_collection_items: usize,
}

impl ResourceLimits {
    /// Creates explicit non-zero limits.
    pub const fn new(
        max_url_bytes: usize,
        max_request_body_bytes: usize,
        max_response_body_bytes: usize,
        max_file_bytes: usize,
        max_signature_bytes: usize,
        max_collection_items: usize,
    ) -> Result<Self, ProtocolError> {
        if max_url_bytes == 0
            || max_request_body_bytes == 0
            || max_response_body_bytes == 0
            || max_file_bytes == 0
            || max_signature_bytes == 0
            || max_collection_items == 0
        {
            return Err(ProtocolError::InvalidConfiguration);
        }
        Ok(Self {
            max_url_bytes,
            max_request_body_bytes,
            max_response_body_bytes,
            max_file_bytes,
            max_signature_bytes,
            max_collection_items,
        })
    }

    /// Maximum resolved request URL length in bytes.
    pub const fn max_url_bytes(self) -> usize {
        self.max_url_bytes
    }

    /// Maximum serialized JSON request body length in bytes.
    pub const fn max_request_body_bytes(self) -> usize {
        self.max_request_body_bytes
    }

    /// Maximum JSON response body length admitted by the SDK.
    pub const fn max_response_body_bytes(self) -> usize {
        self.max_response_body_bytes
    }

    /// Maximum decoded bank-file length in bytes.
    pub const fn max_file_bytes(self) -> usize {
        self.max_file_bytes
    }

    /// Maximum detached-signature text length in bytes.
    pub const fn max_signature_bytes(self) -> usize {
        self.max_signature_bytes
    }

    /// Maximum item count for each provider-returned collection.
    pub const fn max_collection_items(self) -> usize {
        self.max_collection_items
    }
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_url_bytes: DEFAULT_MAX_URL_BYTES,
            max_request_body_bytes: DEFAULT_MAX_REQUEST_BODY_BYTES,
            max_response_body_bytes: DEFAULT_MAX_RESPONSE_BODY_BYTES,
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_signature_bytes: DEFAULT_MAX_SIGNATURE_BYTES,
            max_collection_items: DEFAULT_MAX_COLLECTION_ITEMS,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_must_be_non_zero() {
        assert_eq!(
            ResourceLimits::new(1, 1, 1, 1, 1, 0),
            Err(ProtocolError::InvalidConfiguration)
        );
        assert!(ResourceLimits::new(1, 1, 1, 1, 1, 1).is_ok());
    }
}
