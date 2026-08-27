//! HTTP-shaped transport contract injected by native or WebAssembly hosts.

use alloc::{string::String, vec::Vec};
use core::{fmt, future::Future};

use crate::{SecretBytes, SecretString, TransportError};

/// HTTP methods used by ISECure REST API v2.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpMethod {
    /// Read a resource.
    Get,
    /// Create or transition a resource.
    Post,
    /// Replace or create a resource.
    Put,
    /// Delete or revoke a resource.
    Delete,
}

impl HttpMethod {
    /// Returns the canonical uppercase wire method.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
        }
    }
}

/// Header value that preserves whether transport diagnostics must redact it.
#[derive(Debug)]
pub enum HeaderValue {
    /// Non-secret protocol metadata.
    Public(String),
    /// Credential or bearer material.
    Secret(SecretString),
}

impl HeaderValue {
    /// Exposes the exact wire value to the injected transport.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Public(value) => value,
            Self::Secret(value) => value.expose_secret(),
        }
    }

    /// Reports whether logs must fully redact this value.
    pub const fn is_secret(&self) -> bool {
        matches!(self, Self::Secret(_))
    }
}

/// One exact HTTP header.
#[derive(Debug)]
pub struct Header {
    /// Header name.
    pub name: String,
    /// Header value with redaction classification.
    pub value: HeaderValue,
}

/// Complete bounded request passed to the caller-owned transport.
pub struct Request {
    /// HTTP method.
    pub method: HttpMethod,
    /// Fully resolved URL. Path and query values are percent encoded.
    pub url: String,
    /// Exact request headers.
    pub headers: Vec<Header>,
    /// JSON body bytes. All bodies are treated as sensitive and zeroized.
    pub body: Option<SecretBytes>,
}

impl fmt::Debug for Request {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Request")
            .field("method", &self.method)
            // Account email, phone, bank identifiers, file references, and
            // query values are carried in URLs. Transports may inspect the
            // field directly, but ordinary diagnostics must not print it.
            .field("url", &"[REDACTED]")
            .field("headers", &self.headers)
            .field("body", &self.body)
            .finish()
    }
}

/// Raw HTTP response returned by the injected transport.
#[derive(Debug)]
pub struct Response {
    /// HTTP status code.
    pub status: u16,
    /// Response bytes. They may contain credentials and are always zeroized.
    pub body: SecretBytes,
}

/// Caller-provided transport for native HTTP, Wasm host HTTP, or deterministic tests.
///
/// Retrying belongs here because only the transport knows whether a request was
/// sent. The SDK marks request method and bytes exactly but never opens a socket.
pub trait Transport {
    /// Future returned by [`Transport::send`].
    type Future<'a>: Future<Output = Result<Response, TransportError>> + 'a
    where
        Self: 'a;

    /// Sends one exact request.
    fn send(&self, request: Request) -> Self::Future<'_>;
}
