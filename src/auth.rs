//! Typed authentication and verification state.

use crate::{ApiResponse, Mode, SecretString};
use std::fmt;

/// Multi-factor method selected by ISECure/Cognito.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MfaMethod {
    /// SMS one-time code.
    Sms,
    /// Authenticator application TOTP code.
    Totp,
}

impl MfaMethod {
    pub(crate) const fn cognito_name(self) -> &'static str {
        match self {
            Self::Sms => "SMS_MFA",
            Self::Totp => "SOFTWARE_TOKEN_MFA",
        }
    }

    pub(crate) fn from_cognito(value: &str) -> Option<Self> {
        match value {
            "SMS_MFA" => Some(Self::Sms),
            "SOFTWARE_TOKEN_MFA" => Some(Self::Totp),
            _ => None,
        }
    }
}

/// Verification step awaited by an authentication journey.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthStep {
    /// MFA factor selection or code entry.
    Mfa,
    /// Email verification.
    EmailVerification,
    /// Phone verification.
    PhoneVerification,
}

/// Stable best-effort classification of a provider authentication failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthErrorReason {
    /// Code was rejected.
    InvalidCode,
    /// Code has expired.
    ExpiredCode,
    /// Caller must request a new code.
    ResendRequired,
    /// Attempt limit was reached.
    TooManyAttempts,
    /// Identity is not verified.
    NotVerified,
    /// Identity was already verified.
    AlreadyVerified,
    /// Registration is not confirmed.
    Unconfirmed,
    /// Email verification was requested without an access token.
    MissingAccessToken,
    /// Provider wording cannot be classified more narrowly.
    Unknown,
}

/// Successful authenticated session retained only in memory.
pub struct Session {
    pub(crate) access_token: Option<SecretString>,
    pub(crate) api_key: SecretString,
    pub(crate) expires_in_seconds: Option<u64>,
    pub(crate) expires_at_epoch_seconds: Option<u64>,
    pub(crate) id_token: SecretString,
    pub(crate) continuation: Option<SecretString>,
}

impl Session {
    /// API key for a caller-owned transport or explicit local custody boundary.
    pub fn api_key(&self) -> &SecretString {
        &self.api_key
    }

    /// ID token for a caller-owned transport or explicit local custody boundary.
    pub fn id_token(&self) -> &SecretString {
        &self.id_token
    }

    /// Provider-reported lifetime in seconds.
    pub const fn expires_in_seconds(&self) -> Option<u64> {
        self.expires_in_seconds
    }

    /// Absolute expiry computed using the injected clock.
    pub const fn expires_at_epoch_seconds(&self) -> Option<u64> {
        self.expires_at_epoch_seconds
    }
}

impl fmt::Debug for Session {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Session")
            .field(
                "access_token",
                &self.access_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("api_key", &"[REDACTED]")
            .field("expires_in_seconds", &self.expires_in_seconds)
            .field("expires_at_epoch_seconds", &self.expires_at_epoch_seconds)
            .field("id_token", &"[REDACTED]")
            .field(
                "continuation",
                &self.continuation.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// TOTP enrollment material returned for immediate local presentation.
#[derive(Debug)]
pub struct TotpEnrollment {
    /// Shared secret for manual authenticator entry.
    pub secret: SecretString,
    /// Authenticator URI for a locally rendered QR code.
    pub otpauth_uri: SecretString,
    /// Short-lived access token used by [`crate::Client::verify_totp`].
    pub access_token: SecretString,
}

/// Typed result of one authentication or verification transition.
#[derive(Debug)]
pub enum AuthState {
    /// Client now holds an authenticated session.
    Authenticated {
        /// Identity mode.
        mode: Mode,
        /// Present only during TOTP enrollment.
        totp_enrollment: Option<TotpEnrollment>,
    },
    /// User must select one of the offered MFA factors.
    NeedsMfaSelection {
        /// Identity mode.
        mode: Mode,
        /// Available methods.
        methods: Vec<MfaMethod>,
        /// Safe masked SMS destination when supplied by the provider.
        sms_destination: Option<String>,
    },
    /// User must enter an MFA code.
    NeedsMfa {
        /// Identity mode.
        mode: Mode,
        /// Challenged factor.
        method: MfaMethod,
    },
    /// User must verify email.
    NeedsEmailVerification {
        /// Identity mode.
        mode: Mode,
    },
    /// User must verify phone.
    NeedsPhoneVerification {
        /// Identity mode.
        mode: Mode,
    },
    /// Provider accepted one verification step; caller should log in again.
    VerificationAccepted {
        /// Identity mode.
        mode: Mode,
        /// Accepted step.
        step: AuthStep,
    },
    /// Provider returned a typed logical failure.
    Failed {
        /// Identity mode.
        mode: Mode,
        /// Best-effort stable reason.
        reason: AuthErrorReason,
        /// Provider response. Treat text as customer-sensitive diagnostics.
        response: ApiResponse,
    },
}

pub(crate) fn classify_failure(response: &ApiResponse) -> AuthErrorReason {
    let text = response.response_text.to_ascii_lowercase();
    if text.contains("too many")
        || text.contains("attempt limit")
        || text.contains("limit exceeded")
    {
        AuthErrorReason::TooManyAttempts
    } else if text.contains("expired") || text.contains("no longer valid") {
        AuthErrorReason::ExpiredCode
    } else if text.contains("resend") || text.contains("request a new") {
        AuthErrorReason::ResendRequired
    } else if text.contains("already") && (text.contains("verif") || text.contains("confirm")) {
        AuthErrorReason::AlreadyVerified
    } else if text.contains("not confirmed")
        || text.contains("unconfirmed")
        || text.contains("must confirm")
        || text.contains("confirm your")
        || text.contains("confirm registration")
    {
        AuthErrorReason::Unconfirmed
    } else if text.contains("not verif") || text.contains("unverified") {
        AuthErrorReason::NotVerified
    } else if text.contains("invalid")
        || text.contains("incorrect")
        || text.contains("mismatch")
        || text.contains("wrong code")
    {
        AuthErrorReason::InvalidCode
    } else {
        AuthErrorReason::Unknown
    }
}
