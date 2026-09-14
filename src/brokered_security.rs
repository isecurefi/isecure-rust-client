//! Narrow privileged ISECure challenge, placement and capture mechanics.

use alloc::{string::String, vec, vec::Vec};
use core::{fmt, str};

use crate::{
    ChallengeEncryptor, Error, LimitKind, MfaMethod, ProtocolError, ResourceLimits, SecretBytes,
    SecretString,
    brokered::{BrokeredOperation, CaptureSummary, ProtectedValueKind, RegistrationKind},
    protocol::ensure_limit,
};

/// Broker capability corresponding to one WIT `transient-secret` resource.
pub trait TransientSecret {
    /// Returns the bytes once. The returned allocation is zeroized on drop.
    fn read_once(&mut self) -> Result<SecretBytes, crate::BrokerError>;
}

/// Request field destination controlled by the signed HTTP rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestFieldPlacement {
    Header,
    Body,
}

/// One exact privileged mutation returned to the host. Debug output is redacted.
pub struct RequestMutation {
    field_id: &'static str,
    placement: RequestFieldPlacement,
    value: SecretBytes,
}

impl RequestMutation {
    pub const fn field_id(&self) -> &'static str {
        self.field_id
    }

    pub const fn placement(&self) -> RequestFieldPlacement {
        self.placement
    }

    /// Moves the zeroizing bytes into the generated WIT adapter.
    pub fn into_value(self) -> SecretBytes {
        self.value
    }
}

impl fmt::Debug for RequestMutation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestMutation")
            .field("field_id", &self.field_id)
            .field("placement", &self.placement)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

/// Safe public input admitted for one exact security preparation stage.
pub enum SecurityPrepareInput<'a> {
    Challenge {
        challenge: &'a str,
    },
    MfaSelection {
        method: MfaMethod,
    },
    MfaCode {
        challenge_name: Option<MfaMethod>,
        setup_totp: bool,
    },
    Verification,
    AuthenticatedHeaders,
}

/// Narrow privileged facade used by the ISECure security Component.
pub struct SecurityFacade<E> {
    public_key_pem: String,
    encryptor: E,
    limits: ResourceLimits,
}

impl<E: ChallengeEncryptor> SecurityFacade<E> {
    pub fn new(
        public_key_pem: impl Into<String>,
        encryptor: E,
        limits: ResourceLimits,
    ) -> Result<Self, Error> {
        let public_key_pem = public_key_pem.into();
        if public_key_pem.is_empty() {
            return Err(Error::Protocol(ProtocolError::InvalidConfiguration));
        }
        ensure_limit(
            public_key_pem.len(),
            limits.max_request_body_bytes(),
            LimitKind::RequestBody,
        )?;
        Ok(Self {
            public_key_pem,
            encryptor,
            limits,
        })
    }

    /// Resolves only the exact transient values needed for this provider stage.
    pub fn prepare<S: TransientSecret>(
        &mut self,
        operation: BrokeredOperation,
        input: SecurityPrepareInput<'_>,
        secrets: &mut [S],
    ) -> Result<Vec<RequestMutation>, Error> {
        ensure_limit(secrets.len(), 8, LimitKind::CollectionItems)?;
        let mutations = match (operation, input) {
            (BrokeredOperation::Register(kind), SecurityPrepareInput::Challenge { challenge }) => {
                self.prepare_registration(kind, challenge, secrets)?
            }
            (BrokeredOperation::PasswordReset, SecurityPrepareInput::Challenge { challenge }) => {
                self.prepare_password_reset(challenge, secrets)?
            }
            (BrokeredOperation::Login, SecurityPrepareInput::Challenge { challenge }) => {
                self.prepare_login(challenge, secrets)?
            }
            (BrokeredOperation::SelectMfa, SecurityPrepareInput::MfaSelection { method }) => {
                require_secret_count(secrets, 1)?;
                vec![
                    public_body("MfaType", method.cognito_name()),
                    secret_body("Session", read_secret(&mut secrets[0], self.limits)?),
                ]
            }
            (
                BrokeredOperation::LoginMfa,
                SecurityPrepareInput::MfaCode {
                    challenge_name,
                    setup_totp,
                },
            ) => {
                require_secret_count(secrets, 2)?;
                let code = read_secret(&mut secrets[0], self.limits)?;
                let continuation = read_secret(&mut secrets[1], self.limits)?;
                let mut values = vec![
                    secret_body("Code", code),
                    secret_body("Session", continuation),
                ];
                if let Some(method) = challenge_name {
                    values.push(public_body("ChallengeName", method.cognito_name()));
                }
                if setup_totp {
                    values.push(public_body("SetupTOTP", "true"));
                }
                values
            }
            (
                BrokeredOperation::VerifyEmail | BrokeredOperation::VerifyTotp,
                SecurityPrepareInput::Verification,
            ) => {
                require_secret_count(secrets, 2)?;
                vec![
                    secret_body("AccessToken", read_secret(&mut secrets[0], self.limits)?),
                    secret_body("Code", read_secret(&mut secrets[1], self.limits)?),
                ]
            }
            (BrokeredOperation::VerifyPhone, SecurityPrepareInput::Verification) => {
                require_secret_count(secrets, 1)?;
                vec![secret_body(
                    "Code",
                    read_secret(&mut secrets[0], self.limits)?,
                )]
            }
            (
                BrokeredOperation::ListAccounts
                | BrokeredOperation::ListCertificates
                | BrokeredOperation::ListKeys
                | BrokeredOperation::UploadPgpKey
                | BrokeredOperation::DeleteKey
                | BrokeredOperation::ListFiles
                | BrokeredOperation::DownloadFile
                | BrokeredOperation::UploadFile
                | BrokeredOperation::Logout,
                SecurityPrepareInput::AuthenticatedHeaders,
            ) => {
                require_secret_count(secrets, 2)?;
                vec![
                    secret_header("Authorization", read_secret(&mut secrets[0], self.limits)?),
                    secret_header("x-api-key", read_secret(&mut secrets[1], self.limits)?),
                ]
            }
            _ => return Err(Error::Protocol(ProtocolError::InvalidAuthState)),
        };
        let total = mutations
            .iter()
            .try_fold(0_usize, |total, mutation| {
                total.checked_add(mutation.value.len())
            })
            .ok_or(Error::Limit(crate::LimitError::new(LimitKind::RequestBody)))?;
        ensure_limit(
            total,
            self.limits.max_request_body_bytes(),
            LimitKind::RequestBody,
        )?;
        Ok(mutations)
    }

    fn prepare_registration<S: TransientSecret>(
        &mut self,
        kind: RegistrationKind,
        challenge: &str,
        secrets: &mut [S],
    ) -> Result<Vec<RequestMutation>, Error> {
        let expected = match kind {
            RegistrationKind::NewIdentity => 1,
            RegistrationKind::LinkedIdentity => 2,
        };
        require_secret_count(secrets, expected)?;
        let password = read_secret(&mut secrets[0], self.limits)?;
        let encrypted = self.encrypt(challenge, &password)?;
        let api_key = match kind {
            RegistrationKind::NewIdentity => public_body("ApiKey", "0"),
            RegistrationKind::LinkedIdentity => {
                secret_body("ApiKey", read_secret(&mut secrets[1], self.limits)?)
            }
        };
        Ok(vec![
            api_key,
            public_body("ChResp", challenge),
            secret_body("Encrypted", encrypted),
        ])
    }

    fn prepare_password_reset<S: TransientSecret>(
        &mut self,
        challenge: &str,
        secrets: &mut [S],
    ) -> Result<Vec<RequestMutation>, Error> {
        require_secret_count(secrets, 2)?;
        let code = read_secret(&mut secrets[0], self.limits)?;
        let password = read_secret(&mut secrets[1], self.limits)?;
        let encrypted = self.encrypt(challenge, &password)?;
        Ok(vec![
            secret_body("Code", code),
            public_body("ChResp", challenge),
            secret_body("Encrypted", encrypted),
        ])
    }

    fn prepare_login<S: TransientSecret>(
        &mut self,
        challenge: &str,
        secrets: &mut [S],
    ) -> Result<Vec<RequestMutation>, Error> {
        require_secret_count(secrets, 1)?;
        let password = read_secret(&mut secrets[0], self.limits)?;
        let encrypted = self.encrypt(challenge, &password)?;
        Ok(vec![
            public_body("ChResp", challenge),
            secret_body("Encrypted", encrypted),
        ])
    }

    fn encrypt(&mut self, challenge: &str, password: &SecretString) -> Result<SecretString, Error> {
        ensure_limit(
            challenge.len(),
            self.limits.max_request_body_bytes(),
            LimitKind::RequestBody,
        )?;
        self.encryptor
            .encrypt(
                &self.public_key_pem,
                &SecretString::new(challenge),
                password,
            )
            .map_err(Error::Protocol)
    }

    /// Seals each admitted protected response field through the injected broker.
    /// Empty captures are valid on provider rejection. Business completion owns the
    /// requirement that successful registration includes an API key.
    pub fn capture<V, B: CaptureBroker<V>>(
        &self,
        operation: BrokeredOperation,
        fields: &[ProtectedResponseField<'_, V>],
        broker: &mut B,
    ) -> Result<CaptureSummary, Error> {
        ensure_limit(fields.len(), 6, LimitKind::CollectionItems)?;
        let allowed: &[ProtectedValueKind] = match operation {
            BrokeredOperation::Register(_) => &[ProtectedValueKind::ApiKey],
            BrokeredOperation::Login
            | BrokeredOperation::SelectMfa
            | BrokeredOperation::LoginMfa => &[
                ProtectedValueKind::AccessToken,
                ProtectedValueKind::ApiKey,
                ProtectedValueKind::IdToken,
                ProtectedValueKind::Continuation,
                ProtectedValueKind::TotpSeed,
                ProtectedValueKind::TotpUri,
            ],
            _ => return Err(Error::Protocol(ProtocolError::InvalidAuthState)),
        };
        let mut summary = CaptureSummary::default();
        for field in fields {
            if !allowed.contains(&field.kind) || summary.has(field.kind) {
                return Err(Error::Protocol(ProtocolError::InvalidAuthState));
            }
            summary.insert(field.kind);
        }
        for field in fields {
            broker
                .seal_captured(operation, field.kind, field.value)
                .map_err(Error::Broker)?;
        }
        Ok(summary)
    }
}

/// Opaque provider response value supplied by the host to a capture stage.
pub struct ProtectedResponseField<'a, V> {
    kind: ProtectedValueKind,
    value: &'a V,
}

impl<'a, V> ProtectedResponseField<'a, V> {
    pub const fn from_host(kind: ProtectedValueKind, value: &'a V) -> Self {
        Self { kind, value }
    }
}

impl<V> fmt::Debug for ProtectedResponseField<'_, V> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedResponseField")
            .field("kind", &self.kind)
            .field("value", &"[OPAQUE]")
            .finish()
    }
}

/// Injected host import used to seal one captured response value.
pub trait CaptureBroker<V> {
    /// Seals atomically under the active signed stage. The host implementation
    /// must enforce exact destination-slot authority and equality with any
    /// already-bound API-key security domain; `V` is the generated opaque WIT
    /// resource and must expose no read operation.
    fn seal_captured(
        &mut self,
        operation: BrokeredOperation,
        kind: ProtectedValueKind,
        value: &V,
    ) -> Result<(), crate::BrokerError>;
}

fn require_secret_count<S>(secrets: &[S], expected: usize) -> Result<(), Error> {
    if secrets.len() == expected {
        Ok(())
    } else {
        Err(Error::Protocol(ProtocolError::InvalidAuthState))
    }
}

fn read_secret<S: TransientSecret>(
    secret: &mut S,
    limits: ResourceLimits,
) -> Result<SecretString, Error> {
    let bytes = secret.read_once().map_err(Error::Broker)?;
    ensure_limit(
        bytes.len(),
        limits.max_request_body_bytes(),
        LimitKind::RequestBody,
    )?;
    let value = str::from_utf8(bytes.expose_secret())
        .map_err(|_| Error::Protocol(ProtocolError::InvalidConfiguration))?;
    if value.is_empty() {
        return Err(Error::Protocol(ProtocolError::InvalidConfiguration));
    }
    Ok(SecretString::new(value))
}

fn public_body(field_id: &'static str, value: &str) -> RequestMutation {
    RequestMutation {
        field_id,
        placement: RequestFieldPlacement::Body,
        value: SecretBytes::new(value.as_bytes().to_vec()),
    }
}

fn secret_body(field_id: &'static str, value: SecretString) -> RequestMutation {
    RequestMutation {
        field_id,
        placement: RequestFieldPlacement::Body,
        value: SecretBytes::new(value.expose_secret().as_bytes().to_vec()),
    }
}

fn secret_header(field_id: &'static str, value: SecretString) -> RequestMutation {
    RequestMutation {
        field_id,
        placement: RequestFieldPlacement::Header,
        value: SecretBytes::new(value.expose_secret().as_bytes().to_vec()),
    }
}
