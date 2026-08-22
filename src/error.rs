//! Structured SDK errors without provider payload leakage.

use std::{error, fmt};

/// Transport failure category supplied by the injected host.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportErrorKind {
    /// Caller or host cancelled the exchange.
    Aborted,
    /// The configured deadline elapsed.
    Timeout,
    /// No HTTP response was obtained.
    Network,
    /// A host capability or placement is unavailable.
    Unavailable,
    /// The request may have reached the provider, but no response is known.
    OutcomeIndeterminate,
}

/// Value-minimized transport error.
pub struct TransportError {
    /// Stable category.
    kind: TransportErrorKind,
    /// Optional stable host error code; never a raw provider response.
    code: Option<String>,
}

impl TransportError {
    /// Constructs a transport error without unsafe free-form detail.
    pub fn new(kind: TransportErrorKind, code: Option<String>) -> Self {
        let code = code.filter(|value| {
            !value.is_empty()
                && value.len() <= 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        });
        Self { kind, code }
    }

    /// Stable transport failure category.
    pub const fn kind(&self) -> TransportErrorKind {
        self.kind
    }

    /// Validated value-free host code, when supplied.
    pub fn code(&self) -> Option<&str> {
        self.code.as_deref()
    }
}

impl fmt::Debug for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransportError")
            .field("kind", &self.kind)
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ISECure transport failed ({:?})", self.kind)
    }
}

impl error::Error for TransportError {}

/// Non-success HTTP response with safe structured fields.
#[derive(Debug)]
pub struct HttpError {
    /// HTTP status.
    pub status: u16,
    /// Optional two-character ISECure response code.
    pub response_code: Option<String>,
    /// Optional provider request ID for support correlation.
    pub request_id: Option<String>,
}

/// HTTP-success response whose ISECure `ResponseCode` is not `00`.
#[derive(Debug)]
pub struct LogicalError {
    /// ISECure response code.
    pub response_code: String,
    /// Optional provider request ID for support correlation.
    pub request_id: Option<String>,
}

/// Malformed, incompatible, or unsafe protocol data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    /// JSON did not match the exact expected response shape.
    MalformedResponse,
    /// A required response value was absent or empty.
    MissingValue,
    /// Challenge did not carry its timestamp segment.
    InvalidChallenge,
    /// Public key PEM or RSA parameters were invalid.
    InvalidPublicKey,
    /// Authentication step was invoked out of sequence.
    InvalidAuthState,
    /// Session exists but has expired.
    SessionExpired,
    /// Provider returned an API key outside the configured security domain.
    ApiKeyMismatch,
    /// URL or configuration is not admissible.
    InvalidConfiguration,
}

/// All SDK failures.
#[derive(Debug)]
pub enum Error {
    /// Injected transport failed before returning an HTTP response.
    Transport(TransportError),
    /// Provider returned a non-success HTTP status.
    Http(HttpError),
    /// Provider returned HTTP success with logical failure.
    Logical(LogicalError),
    /// Wire data or local call ordering violated the contract.
    Protocol(ProtocolError),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(error) => error.fmt(formatter),
            Self::Http(error) => {
                write!(formatter, "ISECure HTTP request failed ({})", error.status)
            }
            Self::Logical(error) => write!(
                formatter,
                "ISECure operation failed (ResponseCode {})",
                error.response_code
            ),
            Self::Protocol(error) => write!(formatter, "ISECure protocol failed ({error:?})"),
        }
    }
}

impl error::Error for Error {}

impl From<TransportError> for Error {
    fn from(value: TransportError) -> Self {
        Self::Transport(value)
    }
}

impl From<ProtocolError> for Error {
    fn from(value: ProtocolError) -> Self {
        Self::Protocol(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_codes_accept_only_bounded_value_free_identifiers() {
        let safe = TransportError::new(
            TransportErrorKind::Network,
            Some("HOST_TIMEOUT_1".to_owned()),
        );
        assert_eq!(safe.code(), Some("HOST_TIMEOUT_1"));

        for unsafe_code in [
            "contains a response body",
            "contains/slash",
            "contains:colon",
            "12345678901234567890123456789012345678901234567890123456789012345",
        ] {
            let error =
                TransportError::new(TransportErrorKind::Network, Some(unsafe_code.to_owned()));
            assert_eq!(error.code(), None);
            assert!(!format!("{error:?}").contains(unsafe_code));
        }
    }
}
