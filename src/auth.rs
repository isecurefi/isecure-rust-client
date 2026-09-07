//! Typed authentication and verification state.

use alloc::{borrow::ToOwned, string::String, vec::Vec};
use core::fmt;

use crate::{ApiResponse, Mode, SecretString};

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
    /// Provider returned a typed logical failure, including a recognized HTTP rejection.
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
    let code_context = text.contains("code")
        && !["password", "token", "session"]
            .iter()
            .any(|word| text.contains(word));
    if (text.contains("too many")
        || text.contains("attempt limit")
        || text.contains("limit exceeded"))
        && (text.contains("attempt") || text.contains("request") || text.contains("rate"))
    {
        AuthErrorReason::TooManyAttempts
    } else if code_context && (text.contains("expired") || text.contains("no longer valid")) {
        AuthErrorReason::ExpiredCode
    } else if code_context && (text.contains("resend") || text.contains("request a new")) {
        AuthErrorReason::ResendRequired
    } else if [
        "already verified",
        "already confirmed",
        "already been verified",
        "already been confirmed",
    ]
    .iter()
    .any(|phrase| text.contains(phrase))
    {
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
    } else if code_context
        && (text.contains("invalid")
            || text.contains("incorrect")
            || text.contains("mismatch")
            || text.contains("wrong code"))
    {
        AuthErrorReason::InvalidCode
    } else {
        AuthErrorReason::Unknown
    }
}

/// A bounded HTTP rejection is diagnostic evidence, never permission to replay.
/// Other operations and unknown/inconsistent envelopes retain their HTTP error.
pub(crate) fn is_recognized_auth_rejection(status: u16, response: &ApiResponse) -> bool {
    if !crate::models::is_response_code(&response.response_code)
        || response.response_code == "00"
        || !matches!(status, 400 | 429)
    {
        return false;
    }
    let reason = classify_failure(response);
    if status == 429 {
        return reason == AuthErrorReason::TooManyAttempts;
    }
    matches!(
        reason,
        AuthErrorReason::InvalidCode
            | AuthErrorReason::ExpiredCode
            | AuthErrorReason::ResendRequired
            | AuthErrorReason::AlreadyVerified
            | AuthErrorReason::TooManyAttempts
    )
}

/// Secret-free facts used by both direct and brokered authentication paths.
pub(crate) struct AuthResponseFacts<'a> {
    pub response: &'a ApiResponse,
    pub has_current_access_token: bool,
    pub has_api_key: bool,
    pub has_continuation: bool,
    pub has_id_token: bool,
    pub has_totp_secret: bool,
    pub has_totp_uri: bool,
    pub challenge_name: Option<&'a str>,
    pub mfa_options: &'a [String],
    pub sms_destination: Option<&'a str>,
}

/// Common value-free authentication transition. Secret custody is deliberately
/// applied by the direct or brokered caller after this classification.
pub(crate) enum AuthTransition {
    Authenticated {
        totp_enrollment: bool,
    },
    NeedsMfaSelection {
        methods: Vec<MfaMethod>,
        sms_destination: Option<String>,
    },
    NeedsMfa {
        method: MfaMethod,
    },
    NeedsEmailVerification,
    NeedsPhoneVerification,
    Failed(AuthErrorReason),
}

pub(crate) enum VerificationTransition {
    Accepted,
    Failed(AuthErrorReason),
}

pub(crate) fn classify_verification_response(
    response: &ApiResponse,
) -> Result<VerificationTransition, crate::ProtocolError> {
    if !crate::models::is_response_code(&response.response_code) {
        return Err(crate::ProtocolError::MalformedResponse);
    }
    if response.response_code == "00" {
        Ok(VerificationTransition::Accepted)
    } else {
        Ok(VerificationTransition::Failed(classify_failure(response)))
    }
}

pub(crate) fn classify_auth_response(
    facts: AuthResponseFacts<'_>,
) -> Result<AuthTransition, crate::ProtocolError> {
    if !crate::models::is_response_code(&facts.response.response_code) {
        return Err(crate::ProtocolError::MalformedResponse);
    }
    if facts.response.response_code != "00" {
        return Ok(AuthTransition::Failed(classify_failure(facts.response)));
    }

    if facts.has_id_token {
        if !facts.has_api_key {
            return Err(crate::ProtocolError::MissingValue);
        }
        let totp_enrollment = match (
            facts.has_totp_secret,
            facts.has_totp_uri,
            facts.has_current_access_token,
        ) {
            (true, true, true) => true,
            (false, false, _) => false,
            _ => return Err(crate::ProtocolError::MalformedResponse),
        };
        return Ok(AuthTransition::Authenticated { totp_enrollment });
    }

    let response_text = facts.response.response_text.to_ascii_lowercase();
    if response_text.contains("verify phone") {
        return Ok(AuthTransition::NeedsPhoneVerification);
    }
    if facts.has_current_access_token {
        return Ok(AuthTransition::NeedsEmailVerification);
    }
    if response_text.contains("verify email") {
        return Ok(AuthTransition::Failed(AuthErrorReason::MissingAccessToken));
    }
    if facts.challenge_name == Some("SELECT_MFA_TYPE") {
        let methods = facts
            .mfa_options
            .iter()
            .map(|value| {
                MfaMethod::from_cognito(value).ok_or(crate::ProtocolError::MalformedResponse)
            })
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(AuthTransition::NeedsMfaSelection {
            methods,
            sms_destination: facts.sms_destination.map(str::to_owned),
        });
    }
    if facts.has_continuation
        || response_text.contains("sms code")
        || response_text.contains("authenticator code")
    {
        let method = facts.challenge_name.map_or_else(
            || {
                if response_text.contains("authenticator code") {
                    Ok(MfaMethod::Totp)
                } else {
                    Ok(MfaMethod::Sms)
                }
            },
            |value| MfaMethod::from_cognito(value).ok_or(crate::ProtocolError::MalformedResponse),
        )?;
        return Ok(AuthTransition::NeedsMfa { method });
    }
    Ok(AuthTransition::Failed(classify_failure(facts.response)))
}
