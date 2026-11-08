#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod auth;
mod brokered;
mod brokered_security;
#[cfg(feature = "std")]
mod client;
mod crypto;
mod error;
mod limits;
mod models;
mod protocol;
mod secret;
mod transport;
#[cfg(feature = "std")]
mod url;

pub use auth::{AuthErrorReason, AuthState, AuthStep, MfaMethod, Session, TotpEnrollment};
pub use brokered::{
    BrokeredAuthContext, BrokeredAuthState, BrokeredOperation, BrokeredRegistrationState,
    BusinessFacade, BusinessPlan, CaptureSummary, EXACT_ARTIFACT_BODY_MARKER_V1, ProtectedBinding,
    ProtectedValueKind, RegistrationKind, SanitizedAuthResponse, SanitizedResponse, SecurityStage,
};
pub use brokered_security::{
    CaptureBroker, ProtectedResponseField, RequestFieldPlacement, RequestMutation, SecurityFacade,
    SecurityPrepareInput, TransientSecret,
};
#[cfg(feature = "std")]
pub use client::{Client, ClientBuilder, ClientConfig, Clock, ProfilePasswordReset, SystemClock};
pub use crypto::{ChallengeEncryptor, PASSWORD_ENCRYPTION_PROFILE, RsaChallengeEncryptor};
pub use error::{
    BrokerError, Error, HttpError, LimitError, LimitKind, LogicalError, ProtocolError,
    TransportError, TransportErrorKind,
};
pub use limits::ResourceLimits;
pub use models::*;
pub use secret::{SecretBytes, SecretString};
pub use transport::{Header, HeaderValue, HttpMethod, Request, Response, Transport};

/// SDK package version included in diagnostics and native transport user agents.
pub const SDK_VERSION: &str = env!("CARGO_PKG_VERSION");

/// User-agent value available to caller-owned native HTTP transports.
pub const USER_AGENT: &str = concat!("isecure-rust-client/", env!("CARGO_PKG_VERSION"));

/// Exact Swagger operation IDs implemented from the pinned API contract.
pub const OPENAPI_OPERATIONS: &[&str] = &[
    "ConfigCerts",
    "DeleteFile",
    "DeleteKey",
    "DownloadFile",
    "EnrollCert",
    "ExportCert",
    "ImportCert",
    "InitLogin",
    "InitPasswordReset",
    "InitRegister",
    "ListAccounts",
    "ListCerts",
    "ListFiles",
    "ListKeys",
    "Login",
    "LoginMFA",
    "Logout",
    "PasswordReset",
    "Register",
    "ShareCerts",
    "UnshareCerts",
    "UploadFile",
    "UploadKey",
    "VerifyEmail",
    "VerifyPhone",
    "VerifyTOTP",
];

/// Exact observed operations implemented beside, but not falsely attributed to,
/// the pinned Swagger document.
pub const OBSERVED_EXTENSION_OPERATIONS: &[&str] = &["SelectMfa"];
