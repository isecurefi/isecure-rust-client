//! Secret-free business planning for brokered ISECure Components.
//!
//! These types mirror the generated business/security Component split without
//! owning WIT bindings or platform authority. A Component adapter maps signed
//! platform operation, stage and slot identifiers into these closed provider
//! protocol enums.

use alloc::{string::String, vec::Vec};
use core::fmt;

use crate::{
    ApiResponse, AuthErrorReason, AuthStep, Error, HttpError, LimitKind, ListAccountsResponse,
    ListCertificatesResponse, ListKeysResponse, MfaMethod, Mode, ProtocolError, RegistrationResult,
    ResourceLimits, Response,
    auth::{
        AuthResponseFacts, AuthTransition, VerificationTransition, classify_auth_response,
        classify_verification_response,
    },
    protocol::{decode_json_response, ensure_limit, ensure_logical, is_safe_request_id},
};

/// Registration relationship for the exact ISECure REST operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationKind {
    /// First identity in a new API-key security domain.
    NewIdentity,
    /// Additional identity bound to an existing API-key security domain.
    LinkedIdentity,
}

/// Exact provider operations needed by the first brokered ISECure package.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokeredOperation {
    InitRegister,
    Register(RegistrationKind),
    InitPasswordReset,
    PasswordReset,
    InitLogin,
    Login,
    SelectMfa,
    LoginMfa,
    VerifyEmail,
    VerifyPhone,
    VerifyTotp,
    ListAccounts,
    ListCertificates,
    ListKeys,
    Logout,
}

impl BrokeredOperation {
    /// Exact Swagger or governed observed-extension operation identity.
    pub const fn operation_id(self) -> &'static str {
        match self {
            Self::InitRegister => "InitRegister",
            Self::Register(_) => "Register",
            Self::InitPasswordReset => "InitPasswordReset",
            Self::PasswordReset => "PasswordReset",
            Self::InitLogin => "InitLogin",
            Self::Login => "Login",
            Self::SelectMfa => "SelectMfa",
            Self::LoginMfa => "LoginMFA",
            Self::VerifyEmail => "VerifyEmail",
            Self::VerifyPhone => "VerifyPhone",
            Self::VerifyTotp => "VerifyTOTP",
            Self::ListAccounts => "ListAccounts",
            Self::ListCertificates => "ListCerts",
            Self::ListKeys => "ListKeys",
            Self::Logout => "Logout",
        }
    }
}

/// Provider-level protected-value kind. Signed platform slots remain the host's concern.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtectedValueKind {
    Password,
    ApiKey,
    IdToken,
    AccessToken,
    Continuation,
    OneTimeCode,
    NewPassword,
    TotpSeed,
    TotpUri,
}

/// One opaque host reference supplied to the business facade.
///
/// The wrapped host resource is intentionally not exposed by this type.
pub struct ProtectedBinding<'a, R> {
    kind: ProtectedValueKind,
    _reference: &'a R,
}

impl<'a, R> ProtectedBinding<'a, R> {
    /// Associates an opaque WIT resource with its signed provider-level kind.
    pub const fn from_host(kind: ProtectedValueKind, reference: &'a R) -> Self {
        Self {
            kind,
            _reference: reference,
        }
    }

    /// Structural kind; never a credential or host handle value.
    pub const fn kind(&self) -> ProtectedValueKind {
        self.kind
    }
}

impl<R> fmt::Debug for ProtectedBinding<'_, R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedBinding")
            .field("kind", &self.kind)
            .field("reference", &"[OPAQUE]")
            .finish()
    }
}

/// Exact privileged mechanism requested by a business operation plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecurityStage {
    RegistrationPrepare,
    RegistrationCapture,
    PasswordResetPrepare,
    LoginPrepare,
    MfaSelectionPrepare,
    MfaCodePrepare,
    VerificationPrepare,
    AuthenticatedHeadersPrepare,
    AuthenticationCapture,
}

const NO_STAGES: &[SecurityStage] = &[];
const REGISTRATION_STAGES: &[SecurityStage] = &[
    SecurityStage::RegistrationPrepare,
    SecurityStage::RegistrationCapture,
];
const PASSWORD_RESET_STAGES: &[SecurityStage] = &[SecurityStage::PasswordResetPrepare];
const LOGIN_STAGES: &[SecurityStage] = &[
    SecurityStage::LoginPrepare,
    SecurityStage::AuthenticationCapture,
];
const MFA_SELECTION_STAGES: &[SecurityStage] = &[
    SecurityStage::MfaSelectionPrepare,
    SecurityStage::AuthenticationCapture,
];
const MFA_CODE_STAGES: &[SecurityStage] = &[
    SecurityStage::MfaCodePrepare,
    SecurityStage::AuthenticationCapture,
];
const VERIFICATION_STAGES: &[SecurityStage] = &[SecurityStage::VerificationPrepare];
const AUTHENTICATED_STAGES: &[SecurityStage] = &[SecurityStage::AuthenticatedHeadersPrepare];

/// Secret-free plan returned by the provider SDK's business facade.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BusinessPlan {
    operation: BrokeredOperation,
    stages: &'static [SecurityStage],
}

impl BusinessPlan {
    pub const fn operation(&self) -> BrokeredOperation {
        self.operation
    }

    pub const fn stages(&self) -> &'static [SecurityStage] {
        self.stages
    }
}

/// Stateless business-side facade. It sees opaque resources, never their bytes.
#[derive(Clone, Copy, Debug)]
pub struct BusinessFacade {
    limits: ResourceLimits,
}

impl BusinessFacade {
    pub const fn new(limits: ResourceLimits) -> Self {
        Self { limits }
    }

    /// Validates exact protected-reference kinds and emits a typed linear plan.
    pub fn plan<R>(
        &self,
        operation: BrokeredOperation,
        bindings: &[ProtectedBinding<'_, R>],
    ) -> Result<BusinessPlan, Error> {
        ensure_limit(bindings.len(), 8, LimitKind::CollectionItems)?;
        let (expected, stages): (&[ProtectedValueKind], &'static [SecurityStage]) = match operation
        {
            BrokeredOperation::InitRegister
            | BrokeredOperation::InitPasswordReset
            | BrokeredOperation::InitLogin => (&[], NO_STAGES),
            BrokeredOperation::Register(RegistrationKind::NewIdentity) => {
                (&[ProtectedValueKind::Password], REGISTRATION_STAGES)
            }
            BrokeredOperation::Register(RegistrationKind::LinkedIdentity) => (
                &[ProtectedValueKind::Password, ProtectedValueKind::ApiKey],
                REGISTRATION_STAGES,
            ),
            BrokeredOperation::PasswordReset => (
                &[
                    ProtectedValueKind::OneTimeCode,
                    ProtectedValueKind::NewPassword,
                ],
                PASSWORD_RESET_STAGES,
            ),
            BrokeredOperation::Login => (&[ProtectedValueKind::Password], LOGIN_STAGES),
            BrokeredOperation::SelectMfa => {
                (&[ProtectedValueKind::Continuation], MFA_SELECTION_STAGES)
            }
            BrokeredOperation::LoginMfa => (
                &[
                    ProtectedValueKind::OneTimeCode,
                    ProtectedValueKind::Continuation,
                ],
                MFA_CODE_STAGES,
            ),
            BrokeredOperation::VerifyEmail | BrokeredOperation::VerifyTotp => (
                &[
                    ProtectedValueKind::AccessToken,
                    ProtectedValueKind::OneTimeCode,
                ],
                VERIFICATION_STAGES,
            ),
            BrokeredOperation::VerifyPhone => {
                (&[ProtectedValueKind::OneTimeCode], VERIFICATION_STAGES)
            }
            BrokeredOperation::ListAccounts
            | BrokeredOperation::ListCertificates
            | BrokeredOperation::ListKeys
            | BrokeredOperation::Logout => (
                &[ProtectedValueKind::IdToken, ProtectedValueKind::ApiKey],
                AUTHENTICATED_STAGES,
            ),
        };
        if bindings.len() != expected.len()
            || bindings
                .iter()
                .map(ProtectedBinding::kind)
                .ne(expected.iter().copied())
        {
            return Err(Error::Protocol(ProtocolError::InvalidAuthState));
        }
        Ok(BusinessPlan { operation, stages })
    }

    /// Completes a sanitized authentication response through the same classifier
    /// used by the direct client.
    pub fn complete_authentication(
        &self,
        mode: Mode,
        context: BrokeredAuthContext,
        response: SanitizedAuthResponse,
    ) -> Result<BrokeredAuthState, Error> {
        self.ensure_sanitized_auth_response(&response)?;
        ensure_limit(
            response.mfa_options.len(),
            self.limits.max_collection_items(),
            LimitKind::CollectionItems,
        )?;
        let envelope = response.into_success_envelope(200)?;
        let transition = classify_auth_response(AuthResponseFacts {
            response: &envelope.response,
            has_current_access_token: envelope.captures.has(ProtectedValueKind::AccessToken),
            has_api_key: context.has_api_key || envelope.captures.has(ProtectedValueKind::ApiKey),
            has_continuation: context.has_continuation
                || envelope.captures.has(ProtectedValueKind::Continuation),
            has_id_token: envelope.captures.has(ProtectedValueKind::IdToken),
            has_totp_secret: envelope.captures.has(ProtectedValueKind::TotpSeed),
            has_totp_uri: envelope.captures.has(ProtectedValueKind::TotpUri),
            challenge_name: envelope.challenge_name.as_deref(),
            mfa_options: &envelope.mfa_options,
            sms_destination: envelope.sms_destination.as_deref(),
        })?;
        Ok(match transition {
            AuthTransition::Authenticated { totp_enrollment } => BrokeredAuthState::Authenticated {
                mode,
                totp_enrollment_available: totp_enrollment,
                expires_in_seconds: envelope.expires_in_seconds,
            },
            AuthTransition::NeedsMfaSelection {
                methods,
                sms_destination,
            } => BrokeredAuthState::NeedsMfaSelection {
                mode,
                methods,
                sms_destination,
            },
            AuthTransition::NeedsMfa { method } => BrokeredAuthState::NeedsMfa { mode, method },
            AuthTransition::NeedsEmailVerification => {
                BrokeredAuthState::NeedsEmailVerification { mode }
            }
            AuthTransition::NeedsPhoneVerification => {
                BrokeredAuthState::NeedsPhoneVerification { mode }
            }
            AuthTransition::Failed(reason) => BrokeredAuthState::Failed {
                mode,
                reason,
                response: envelope.response,
            },
        })
    }

    /// Applies the same HTTP and logical envelope checks used by direct calls.
    pub fn complete_api_response(
        &self,
        response: SanitizedResponse,
        expected_status: u16,
    ) -> Result<ApiResponse, Error> {
        self.ensure_sanitized_response(&response)?;
        let response = response.into_success_envelope(expected_status)?;
        response.ensure_success()?;
        Ok(response)
    }

    /// Completes registration without ever receiving the captured API-key value.
    pub fn complete_registration(
        &self,
        response: SanitizedResponse,
        captures: CaptureSummary,
    ) -> Result<RegistrationResult, Error> {
        let response = self.complete_api_response(response, 201)?;
        if !captures.has(ProtectedValueKind::ApiKey) {
            return Err(Error::Protocol(ProtocolError::MissingValue));
        }
        Ok(RegistrationResult {
            response,
            api_key_available: true,
        })
    }

    /// Completes email, phone or TOTP verification through the shared classifier.
    pub fn complete_verification(
        &self,
        mode: Mode,
        step: AuthStep,
        response: SanitizedResponse,
    ) -> Result<BrokeredAuthState, Error> {
        self.ensure_sanitized_response(&response)?;
        let response = response.into_success_envelope(200)?;
        Ok(match classify_verification_response(&response)? {
            VerificationTransition::Accepted => {
                BrokeredAuthState::VerificationAccepted { mode, step }
            }
            VerificationTransition::Failed(reason) => BrokeredAuthState::Failed {
                mode,
                reason,
                response,
            },
        })
    }

    /// Decodes the exact safe account-list response used by the parent connection check.
    pub fn complete_list_accounts(
        &self,
        response: Response,
    ) -> Result<ListAccountsResponse, Error> {
        self.ensure_response_body(response.body.len())?;
        let response: ListAccountsResponse = decode_json_response(response, 200)?;
        ensure_logical(&response.response_code)?;
        self.ensure_collection(response.accounts.len())?;
        for account in &response.accounts {
            self.ensure_collection(account.certs.len())?;
        }
        Ok(response)
    }

    /// Decodes the exact safe certificate-list response used by the parent connection check.
    pub fn complete_list_certificates(
        &self,
        response: Response,
    ) -> Result<ListCertificatesResponse, Error> {
        self.ensure_response_body(response.body.len())?;
        let response: ListCertificatesResponse = decode_json_response(response, 200)?;
        ensure_logical(&response.response_code)?;
        self.ensure_collection(response.certs.len())?;
        self.ensure_collection(response.connections.len())?;
        for connection in &response.connections {
            self.ensure_collection(connection.certificates.len())?;
        }
        Ok(response)
    }

    /// Decodes the exact safe OpenPGP-key list used by the parent connection check.
    pub fn complete_list_keys(&self, response: Response) -> Result<ListKeysResponse, Error> {
        self.ensure_response_body(response.body.len())?;
        let response: ListKeysResponse = decode_json_response(response, 200)?;
        ensure_logical(&response.response_code)?;
        self.ensure_collection(response.pgp_keys.len())?;
        Ok(response)
    }

    fn ensure_response_body(&self, actual: usize) -> Result<(), Error> {
        ensure_limit(
            actual,
            self.limits.max_response_body_bytes(),
            LimitKind::ResponseBody,
        )
    }

    fn ensure_collection(&self, actual: usize) -> Result<(), Error> {
        ensure_limit(
            actual,
            self.limits.max_collection_items(),
            LimitKind::CollectionItems,
        )
    }

    fn ensure_sanitized_response(&self, response: &SanitizedResponse) -> Result<(), Error> {
        let total = checked_total([
            response.response.response_code.len(),
            response.response.response_text.len(),
            response.request_id.as_ref().map_or(0, String::len),
        ])?;
        self.ensure_response_body(total)
    }

    fn ensure_sanitized_auth_response(
        &self,
        response: &SanitizedAuthResponse,
    ) -> Result<(), Error> {
        let fixed = [
            response.response.response_code.len(),
            response.response.response_text.len(),
            response.request_id.as_ref().map_or(0, String::len),
            response.challenge_name.as_ref().map_or(0, String::len),
            response.sms_destination.as_ref().map_or(0, String::len),
        ];
        let total = response
            .mfa_options
            .iter()
            .try_fold(checked_total(fixed)?, |total, value| {
                total.checked_add(value.len())
            })
            .ok_or(Error::Limit(crate::LimitError::new(
                LimitKind::ResponseBody,
            )))?;
        self.ensure_response_body(total)
    }
}

impl Default for BusinessFacade {
    fn default() -> Self {
        Self::new(ResourceLimits::default())
    }
}

/// Safe host-held authentication context from a prior exchange.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BrokeredAuthContext {
    has_api_key: bool,
    has_continuation: bool,
}

impl BrokeredAuthContext {
    /// Derives prior auth-state presence from opaque host bindings. No handle or
    /// protected value is retained.
    pub fn from_host_bindings<R>(bindings: &[ProtectedBinding<'_, R>]) -> Result<Self, Error> {
        ensure_limit(bindings.len(), 2, LimitKind::CollectionItems)?;
        let mut context = Self::default();
        for binding in bindings {
            match binding.kind {
                ProtectedValueKind::ApiKey if !context.has_api_key => context.has_api_key = true,
                ProtectedValueKind::Continuation if !context.has_continuation => {
                    context.has_continuation = true;
                }
                _ => return Err(Error::Protocol(ProtocolError::InvalidAuthState)),
            }
        }
        Ok(context)
    }

    pub const fn has_api_key(self) -> bool {
        self.has_api_key
    }

    pub const fn has_continuation(self) -> bool {
        self.has_continuation
    }
}

/// Secret-free counterpart to [`crate::AuthState`].
#[derive(Debug)]
pub enum BrokeredAuthState {
    Authenticated {
        mode: Mode,
        totp_enrollment_available: bool,
        expires_in_seconds: Option<u64>,
    },
    NeedsMfaSelection {
        mode: Mode,
        methods: Vec<MfaMethod>,
        sms_destination: Option<String>,
    },
    NeedsMfa {
        mode: Mode,
        method: MfaMethod,
    },
    NeedsEmailVerification {
        mode: Mode,
    },
    NeedsPhoneVerification {
        mode: Mode,
    },
    VerificationAccepted {
        mode: Mode,
        step: AuthStep,
    },
    Failed {
        mode: Mode,
        reason: AuthErrorReason,
        response: ApiResponse,
    },
}

/// Sanitized response metadata delivered to the business Component.
pub struct SanitizedResponse {
    pub status: u16,
    pub response: ApiResponse,
    pub request_id: Option<String>,
}

impl SanitizedResponse {
    fn into_success_envelope(self, expected_status: u16) -> Result<ApiResponse, Error> {
        if self.status != expected_status {
            return Err(Error::Http(HttpError {
                status: self.status,
                response_code: crate::models::is_response_code(&self.response.response_code)
                    .then_some(self.response.response_code),
                request_id: self.request_id.filter(|value| is_safe_request_id(value)),
            }));
        }
        if !crate::models::is_response_code(&self.response.response_code) {
            return Err(Error::Protocol(ProtocolError::MalformedResponse));
        }
        Ok(self.response)
    }
}

/// Sanitized authentication response plus structural capture evidence.
pub struct SanitizedAuthResponse {
    pub status: u16,
    pub response: ApiResponse,
    pub request_id: Option<String>,
    pub challenge_name: Option<String>,
    pub expires_in_seconds: Option<u64>,
    pub mfa_options: Vec<String>,
    pub sms_destination: Option<String>,
    pub captures: CaptureSummary,
}

impl SanitizedAuthResponse {
    fn into_success_envelope(self, expected_status: u16) -> Result<SanitizedAuthEnvelope, Error> {
        let response = SanitizedResponse {
            status: self.status,
            response: self.response,
            request_id: self.request_id,
        }
        .into_success_envelope(expected_status)?;
        Ok(SanitizedAuthEnvelope {
            response,
            challenge_name: self.challenge_name,
            expires_in_seconds: self.expires_in_seconds,
            mfa_options: self.mfa_options,
            sms_destination: self.sms_destination,
            captures: self.captures,
        })
    }
}

struct SanitizedAuthEnvelope {
    response: ApiResponse,
    challenge_name: Option<String>,
    expires_in_seconds: Option<u64>,
    mfa_options: Vec<String>,
    sms_destination: Option<String>,
    captures: CaptureSummary,
}

/// Privacy-safe structural record of values sealed by a capture stage.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CaptureSummary(u16);

impl CaptureSummary {
    /// Builds structural capture evidence from the opaque references delivered
    /// to the business Component by the host. Values remain inaccessible.
    pub fn from_host_bindings<R>(bindings: &[ProtectedBinding<'_, R>]) -> Result<Self, Error> {
        ensure_limit(bindings.len(), 6, LimitKind::CollectionItems)?;
        let mut summary = Self::default();
        for binding in bindings {
            if !matches!(
                binding.kind,
                ProtectedValueKind::ApiKey
                    | ProtectedValueKind::IdToken
                    | ProtectedValueKind::AccessToken
                    | ProtectedValueKind::Continuation
                    | ProtectedValueKind::TotpSeed
                    | ProtectedValueKind::TotpUri
            ) || summary.has(binding.kind)
            {
                return Err(Error::Protocol(ProtocolError::InvalidAuthState));
            }
            summary.insert(binding.kind);
        }
        Ok(summary)
    }

    pub const fn has(self, kind: ProtectedValueKind) -> bool {
        self.0 & kind.mask() != 0
    }

    pub(crate) fn insert(&mut self, kind: ProtectedValueKind) {
        self.0 |= kind.mask();
    }
}

impl ProtectedValueKind {
    const fn mask(self) -> u16 {
        1 << (self as u8)
    }
}

fn checked_total<const N: usize>(values: [usize; N]) -> Result<usize, Error> {
    values.into_iter().try_fold(0_usize, |total, value| {
        total
            .checked_add(value)
            .ok_or(Error::Limit(crate::LimitError::new(
                LimitKind::ResponseBody,
            )))
    })
}
