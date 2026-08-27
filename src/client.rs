//! Stateful, transport-injected ISECure REST API v2 client.

use std::{
    io::{self, Write},
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    ApiResponse, AuthState, CertificateExport, CertificateSharesResponse, ChallengeEncryptor,
    DownloadFileResponse, EnrollCertificateRequest, Error, ExportCertificatesResponse,
    ExportedCertificate, Header, HeaderValue, HttpMethod, ImportCertificateRequest, LimitError,
    LimitKind, ListAccountsResponse, ListCertificatesResponse, ListFilesQuery, ListFilesResponse,
    ListKeysResponse, MfaMethod, Mode, PasswordReset, PgpKeyPurpose, ProtocolError,
    RegistrationResult, Request, ResourceLimits, SecretBytes, SecretString, Session, Transport,
    UploadFileRequest,
    auth::{
        AuthResponseFacts, AuthTransition, VerificationTransition, classify_auth_response,
        classify_failure, classify_verification_response,
    },
    protocol::{decode_json_response, ensure_limit, ensure_logical},
    url,
};

/// Time source used for deterministic session expiry.
pub trait Clock {
    /// Current Unix epoch seconds.
    fn now_epoch_seconds(&self) -> u64;
}

/// Standard-library wall clock for native and WASI hosts.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_epoch_seconds(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs())
    }
}

/// Immutable connection and identity configuration.
pub struct ClientConfig {
    base_url: String,
    email: String,
    mode: Mode,
    phone: String,
    company: String,
    name: String,
    password: SecretString,
    public_key_pem: String,
    bank: String,
    api_key: Option<SecretString>,
    expiry_skew_seconds: u64,
    limits: ResourceLimits,
}

impl ClientConfig {
    /// Starts an idiomatic builder with endpoint and identity coordinates.
    pub fn builder(
        base_url: impl Into<String>,
        email: impl Into<String>,
        mode: Mode,
    ) -> ClientBuilder {
        ClientBuilder::new(base_url, email, mode)
    }

    /// Configured email identity.
    pub fn email(&self) -> &str {
        &self.email
    }

    /// Configured identity mode.
    pub const fn mode(&self) -> Mode {
        self.mode
    }

    /// Configured bank identifier.
    pub fn bank(&self) -> &str {
        &self.bank
    }

    /// Resource bounds enforced by this client.
    pub const fn limits(&self) -> ResourceLimits {
        self.limits
    }
}

/// Builder for a complete client configuration.
pub struct ClientBuilder {
    base_url: String,
    email: String,
    mode: Mode,
    phone: Option<String>,
    company: Option<String>,
    name: Option<String>,
    password: Option<SecretString>,
    public_key_pem: Option<String>,
    bank: Option<String>,
    api_key: Option<SecretString>,
    expiry_skew_seconds: u64,
    limits: ResourceLimits,
}

impl ClientBuilder {
    /// Creates a builder.
    pub fn new(base_url: impl Into<String>, email: impl Into<String>, mode: Mode) -> Self {
        Self {
            base_url: base_url.into(),
            email: email.into(),
            mode,
            phone: None,
            company: None,
            name: None,
            password: None,
            public_key_pem: None,
            bank: None,
            api_key: None,
            expiry_skew_seconds: 5,
            limits: ResourceLimits::default(),
        }
    }

    /// Sets registration phone number.
    pub fn phone(mut self, value: impl Into<String>) -> Self {
        self.phone = Some(value.into());
        self
    }

    /// Sets registration company name.
    pub fn company(mut self, value: impl Into<String>) -> Self {
        self.company = Some(value.into());
        self
    }

    /// Sets registration display name.
    pub fn name(mut self, value: impl Into<String>) -> Self {
        self.name = Some(value.into());
        self
    }

    /// Sets identity password.
    pub fn password(mut self, value: SecretString) -> Self {
        self.password = Some(value);
        self
    }

    /// Sets exact environment RSA public key PEM.
    pub fn public_key_pem(mut self, value: impl Into<String>) -> Self {
        self.public_key_pem = Some(value.into());
        self
    }

    /// Sets bank identifier used by certificate and file operations.
    pub fn bank(mut self, value: impl Into<String>) -> Self {
        self.bank = Some(value.into());
        self
    }

    /// Sets an existing integrator API key, including the admin key reused for data registration.
    pub fn api_key(mut self, value: SecretString) -> Self {
        self.api_key = Some(value);
        self
    }

    /// Sets early-expiry skew. Default is five seconds.
    pub const fn expiry_skew_seconds(mut self, value: u64) -> Self {
        self.expiry_skew_seconds = value;
        self
    }

    /// Sets explicit SDK resource bounds. Hosts should enforce stricter bounds
    /// before copying response bytes into a WebAssembly guest.
    pub const fn resource_limits(mut self, value: ResourceLimits) -> Self {
        self.limits = value;
        self
    }

    /// Validates and builds immutable configuration.
    pub fn build(self) -> Result<ClientConfig, Error> {
        let phone = self
            .phone
            .ok_or(Error::Protocol(ProtocolError::InvalidConfiguration))?;
        let company = self
            .company
            .ok_or(Error::Protocol(ProtocolError::InvalidConfiguration))?;
        let name = self
            .name
            .ok_or(Error::Protocol(ProtocolError::InvalidConfiguration))?;
        let password = self
            .password
            .ok_or(Error::Protocol(ProtocolError::InvalidConfiguration))?;
        let public_key_pem = self
            .public_key_pem
            .ok_or(Error::Protocol(ProtocolError::InvalidConfiguration))?;
        let bank = self
            .bank
            .ok_or(Error::Protocol(ProtocolError::InvalidConfiguration))?;
        for value in [&self.base_url, &self.email, &phone, &bank] {
            ensure_limit(value.len(), self.limits.max_url_bytes(), LimitKind::Url)?;
        }
        let urls = url::Urls::new(&self.base_url, &self.email, self.mode, &phone, &bank)
            .map_err(Error::Protocol)?;
        for resolved in [
            urls.account_phone(),
            urls.password(),
            urls.select_mfa(),
            urls.files(),
            urls.cert(),
            urls.accounts(),
        ] {
            ensure_limit(resolved.len(), self.limits.max_url_bytes(), LimitKind::Url)?;
        }
        if company.is_empty() || name.is_empty() || password.is_empty() || public_key_pem.is_empty()
        {
            return Err(Error::Protocol(ProtocolError::InvalidConfiguration));
        }
        Ok(ClientConfig {
            base_url: self.base_url,
            email: self.email,
            mode: self.mode,
            phone,
            company,
            name,
            password,
            public_key_pem,
            bank,
            api_key: self.api_key,
            expiry_skew_seconds: self.expiry_skew_seconds,
            limits: self.limits,
        })
    }
}

#[derive(Default)]
struct PendingAuth {
    access_token: Option<SecretString>,
    api_key: Option<SecretString>,
    continuation: Option<SecretString>,
    challenge_name: Option<String>,
}

/// Stateful ISECure REST client using injected transport, crypto and clock.
pub struct Client<T, E, C = SystemClock> {
    config: ClientConfig,
    transport: T,
    encryptor: E,
    clock: C,
    pending: PendingAuth,
    session: Option<Session>,
}

impl<T, E> Client<T, E, SystemClock> {
    /// Creates a client using the standard wall clock.
    pub fn new(config: ClientConfig, transport: T, encryptor: E) -> Self {
        Self::with_clock(config, transport, encryptor, SystemClock)
    }
}

impl<T, E, C> Client<T, E, C> {
    /// Creates a client with an explicit deterministic clock.
    pub fn with_clock(mut config: ClientConfig, transport: T, encryptor: E, clock: C) -> Self {
        let api_key = config.api_key.take();
        Self {
            config,
            transport,
            encryptor,
            clock,
            pending: PendingAuth {
                api_key,
                ..PendingAuth::default()
            },
            session: None,
        }
    }

    /// Immutable configuration.
    pub const fn config(&self) -> &ClientConfig {
        &self.config
    }

    /// Current fully authenticated session.
    pub const fn session(&self) -> Option<&Session> {
        self.session.as_ref()
    }

    /// API key available from configuration, registration, or authentication.
    pub fn api_key(&self) -> Option<&SecretString> {
        self.session
            .as_ref()
            .map(Session::api_key)
            .or(self.pending.api_key.as_ref())
    }

    /// Returns the owned environment adapters while dropping configuration,
    /// pending authentication and session secrets.
    pub fn into_adapters(self) -> (T, E, C) {
        (self.transport, self.encryptor, self.clock)
    }
}

impl<T: Transport, E: ChallengeEncryptor, C: Clock> Client<T, E, C> {
    /// Whether an authenticated session exists.
    pub const fn is_authenticated(&self) -> bool {
        self.session.is_some()
    }

    /// Whether the current session is expired within configured skew.
    pub fn is_session_expired(&self) -> bool {
        self.session
            .as_ref()
            .and_then(Session::expires_at_epoch_seconds)
            .is_some_and(|expires_at| {
                self.clock
                    .now_epoch_seconds()
                    .saturating_add(self.config.expiry_skew_seconds)
                    >= expires_at
            })
    }

    /// Registers the configured admin or data identity.
    pub async fn register(&mut self) -> Result<RegistrationResult, Error> {
        let challenge = self.registration_challenge().await?;
        let encrypted = self.encryptor.encrypt(
            &self.config.public_key_pem,
            &challenge,
            &self.config.password,
        )?;
        let request = RegisterWire {
            name: &self.config.name,
            phone: &self.config.phone,
            company: &self.config.company,
            api_key: self.api_key().map_or("0", SecretString::expose_secret),
            challenge: challenge.expose_secret(),
            encrypted: encrypted.expose_secret(),
        };
        let mut response: RegisterResponseWire = self
            .send_json(
                HttpMethod::Put,
                self.urls()?.account(),
                Some(&request),
                false,
                201,
            )
            .await?;
        response.envelope().ensure_success()?;
        if response.api_key.is_empty() {
            return Err(Error::Protocol(ProtocolError::MissingValue));
        }
        if self
            .pending
            .api_key
            .as_ref()
            .is_some_and(|expected| expected.expose_secret() != response.api_key)
        {
            return Err(Error::Protocol(ProtocolError::ApiKeyMismatch));
        }
        self.pending.api_key = Some(SecretString::new(std::mem::take(&mut response.api_key)));
        Ok(RegistrationResult {
            response: response.envelope(),
            api_key_available: true,
        })
    }

    /// Starts password reset and returns the provider challenge envelope.
    pub async fn init_password_reset(&self) -> Result<ApiResponse, Error> {
        let response: ApiResponse = self
            .send_json::<(), _>(HttpMethod::Get, self.urls()?.password(), None, false, 200)
            .await?;
        response.ensure_success()?;
        Ok(response)
    }

    /// Completes password reset with a code, challenge and new password.
    pub async fn password_reset(&mut self, reset: &PasswordReset) -> Result<ApiResponse, Error> {
        let encrypted = self.encryptor.encrypt(
            &self.config.public_key_pem,
            &reset.challenge,
            &reset.new_password,
        )?;
        let request = PasswordResetWire {
            code: reset.code.expose_secret(),
            challenge: reset.challenge.expose_secret(),
            encrypted: encrypted.expose_secret(),
        };
        let response: ApiResponse = self
            .send_json(
                HttpMethod::Post,
                self.urls()?.password(),
                Some(&request),
                false,
                200,
            )
            .await?;
        response.ensure_success()?;
        Ok(response)
    }

    /// Starts login and returns the next typed state.
    pub async fn login(&mut self) -> Result<AuthState, Error> {
        self.reset_auth_attempt();
        let challenge = self.login_challenge().await?;
        let encrypted = self.encryptor.encrypt(
            &self.config.public_key_pem,
            &challenge,
            &self.config.password,
        )?;
        let request = LoginWire {
            challenge: challenge.expose_secret(),
            encrypted: encrypted.expose_secret(),
        };
        let response: AuthResponseWire = self
            .send_json(
                HttpMethod::Post,
                self.urls()?.session(),
                Some(&request),
                false,
                200,
            )
            .await?;
        self.apply_auth_response(response)
    }

    /// Selects SMS or TOTP after `SELECT_MFA_TYPE`.
    pub async fn select_mfa_type(&mut self, method: MfaMethod) -> Result<AuthState, Error> {
        let continuation = self
            .pending
            .continuation
            .as_ref()
            .ok_or(Error::Protocol(ProtocolError::InvalidAuthState))?;
        let request = SelectMfaWire {
            mfa_type: method.cognito_name(),
            session: continuation.expose_secret(),
        };
        let response: AuthResponseWire = self
            .send_json(
                HttpMethod::Put,
                self.urls()?.select_mfa(),
                Some(&request),
                false,
                200,
            )
            .await?;
        self.apply_auth_response(response)
    }

    /// Submits an SMS or TOTP code. Set `setup_totp` to begin authenticator enrollment.
    pub async fn submit_mfa_code(
        &mut self,
        code: &SecretString,
        setup_totp: bool,
    ) -> Result<AuthState, Error> {
        let continuation = self
            .pending
            .continuation
            .as_ref()
            .ok_or(Error::Protocol(ProtocolError::InvalidAuthState))?;
        let request = MfaCodeWire {
            code: code.expose_secret(),
            session: continuation.expose_secret(),
            challenge_name: self.pending.challenge_name.as_deref(),
            setup_totp: setup_totp.then_some(true),
        };
        let response: AuthResponseWire = self
            .send_json(
                HttpMethod::Put,
                self.urls()?.mfa_code(),
                Some(&request),
                false,
                200,
            )
            .await?;
        self.apply_auth_response(response)
    }

    /// Confirms TOTP enrollment.
    pub async fn verify_totp(
        &self,
        access_token: &SecretString,
        code: &SecretString,
    ) -> Result<AuthState, Error> {
        let request = VerificationWithTokenWire {
            access_token: access_token.expose_secret(),
            code: code.expose_secret(),
        };
        let response: ApiResponse = self
            .send_json(
                HttpMethod::Put,
                self.urls()?.verify_totp(),
                Some(&request),
                false,
                200,
            )
            .await?;
        self.classify_verification(response, crate::AuthStep::Mfa)
    }

    /// Confirms phone ownership.
    pub async fn verify_phone(&self, code: &SecretString) -> Result<AuthState, Error> {
        let request = VerificationCodeWire {
            code: code.expose_secret(),
        };
        let response: ApiResponse = self
            .send_json(
                HttpMethod::Post,
                self.urls()?.account_phone(),
                Some(&request),
                false,
                200,
            )
            .await?;
        self.classify_verification(response, crate::AuthStep::PhoneVerification)
    }

    /// Confirms email ownership using the access token returned by login.
    pub async fn verify_email(&mut self, code: &SecretString) -> Result<AuthState, Error> {
        let access_token = self
            .pending
            .access_token
            .as_ref()
            .ok_or(Error::Protocol(ProtocolError::InvalidAuthState))?;
        let request = VerificationWithTokenWire {
            access_token: access_token.expose_secret(),
            code: code.expose_secret(),
        };
        let response: ApiResponse = self
            .send_json(
                HttpMethod::Post,
                self.urls()?.account(),
                Some(&request),
                false,
                200,
            )
            .await?;
        let state = self.classify_verification(response, crate::AuthStep::EmailVerification)?;
        if matches!(state, AuthState::VerificationAccepted { .. }) {
            self.pending.access_token = None;
        }
        Ok(state)
    }

    /// Uploads an OpenPGP public key.
    pub async fn upload_pgp_key(
        &self,
        armored_key: &str,
        purpose: PgpKeyPurpose,
    ) -> Result<ApiResponse, Error> {
        let request = UploadKeyWire {
            pgp_key: armored_key,
            purpose: purpose.as_str(),
        };
        self.auth_api_response(HttpMethod::Put, self.urls()?.pgp(), Some(&request), 201)
            .await
    }

    /// Lists registered OpenPGP public keys.
    pub async fn list_keys(&self) -> Result<ListKeysResponse, Error> {
        let response: ListKeysResponse = self
            .send_json::<(), _>(HttpMethod::Get, self.urls()?.pgp(), None, true, 200)
            .await?;
        ensure_logical(&response.response_code)?;
        self.ensure_collection(response.pgp_keys.len())?;
        Ok(response)
    }

    /// Requests deletion of a registered OpenPGP key. The deployed API may reject this reserved operation.
    pub async fn delete_key(&self, key_id: &str) -> Result<ApiResponse, Error> {
        let request = DeleteKeyWire { key_id };
        self.auth_api_response(HttpMethod::Delete, self.urls()?.pgp(), Some(&request), 200)
            .await
    }

    /// Uploads one bank file.
    pub async fn upload_file(&self, input: &UploadFileRequest) -> Result<ApiResponse, Error> {
        ensure_limit(
            input.file_contents.len(),
            self.config.limits.max_file_bytes(),
            LimitKind::FileContent,
        )?;
        ensure_limit(
            input.signature.len(),
            self.config.limits.max_signature_bytes(),
            LimitKind::Signature,
        )?;
        let encoded_contents =
            SecretString::new(BASE64_STANDARD.encode(input.file_contents.expose_secret()));
        let request = UploadFileWire {
            contents: encoded_contents.expose_secret(),
            name: &input.file_name,
            file_type: &input.file_type,
            signature: input.signature.expose_secret(),
        };
        self.auth_api_response(HttpMethod::Put, self.urls()?.files(), Some(&request), 201)
            .await
    }

    /// Lists bank files.
    pub async fn list_files(&self, query: &ListFilesQuery) -> Result<ListFilesResponse, Error> {
        let mut values = Vec::with_capacity(2);
        if let Some(file_type) = query.file_type.as_deref().filter(|value| !value.is_empty()) {
            self.ensure_url_component(file_type)?;
            values.push(("FileType", file_type));
        }
        if let Some(status) = query.status.as_deref().filter(|value| !value.is_empty()) {
            self.ensure_url_component(status)?;
            values.push(("Status", status));
        }
        let response: ListFilesResponse = self
            .send_json::<(), _>(
                HttpMethod::Get,
                url::query(&self.urls()?.files(), &values),
                None,
                true,
                200,
            )
            .await?;
        ensure_logical(&response.response_code)?;
        self.ensure_collection(response.file_descriptors.len())?;
        Ok(response)
    }

    /// Downloads one exact bank file.
    pub async fn download_file(
        &self,
        file_type: &str,
        file_reference: &str,
    ) -> Result<DownloadFileResponse, Error> {
        self.ensure_url_component(file_type)?;
        self.ensure_url_component(file_reference)?;
        let response: DownloadWire = self
            .send_json::<(), _>(
                HttpMethod::Get,
                self.urls()?.file(file_type, file_reference),
                None,
                true,
                200,
            )
            .await?;
        response.envelope().ensure_success()?;
        ensure_limit(
            response.content.len(),
            max_base64_len(self.config.limits.max_file_bytes()),
            LimitKind::FileContent,
        )?;
        let content = SecretBytes::new(
            BASE64_STANDARD
                .decode(response.content.as_bytes())
                .map_err(|_| Error::Protocol(ProtocolError::MalformedResponse))?,
        );
        ensure_limit(
            content.len(),
            self.config.limits.max_file_bytes(),
            LimitKind::FileContent,
        )?;
        Ok(DownloadFileResponse {
            response: response.envelope(),
            content,
        })
    }

    /// Deletes or marks one bank file deleted according to bank semantics.
    pub async fn delete_file(
        &self,
        file_type: &str,
        file_reference: &str,
    ) -> Result<ApiResponse, Error> {
        self.ensure_url_component(file_type)?;
        self.ensure_url_component(file_reference)?;
        self.auth_api_response::<()>(
            HttpMethod::Delete,
            self.urls()?.file(file_type, file_reference),
            None,
            200,
        )
        .await
    }

    /// Lists certificates and bank connections.
    pub async fn list_certificates(&self) -> Result<ListCertificatesResponse, Error> {
        let response: ListCertificatesResponse = self
            .send_json::<(), _>(HttpMethod::Get, self.urls()?.certs(), None, true, 200)
            .await?;
        ensure_logical(&response.response_code)?;
        self.ensure_collection(response.certs.len())?;
        self.ensure_collection(response.connections.len())?;
        for connection in &response.connections {
            self.ensure_collection(connection.certificates.len())?;
        }
        Ok(response)
    }

    /// Configures certificate export behavior.
    pub async fn configure_certificates(
        &self,
        export: CertificateExport,
    ) -> Result<ApiResponse, Error> {
        let request = ConfigCertificatesWire {
            export: match export {
                CertificateExport::Disabled => "disabled",
                CertificateExport::Allowed => "allowed",
            },
        };
        self.auth_api_response(HttpMethod::Post, self.urls()?.certs(), Some(&request), 200)
            .await
    }

    /// Shares owned bank certificates with another account under the same API key.
    pub async fn share_certificates(
        &self,
        external_email: &str,
    ) -> Result<CertificateSharesResponse, Error> {
        self.ensure_url_component(external_email)?;
        let response: CertificateSharesResponse = self
            .send_json::<(), _>(
                HttpMethod::Put,
                self.urls()?.shared_certs(external_email),
                None,
                true,
                201,
            )
            .await?;
        ensure_logical(&response.response_code)?;
        self.ensure_collection(response.shared_to.len())?;
        self.ensure_collection(response.shared_from.len())?;
        Ok(response)
    }

    /// Removes a certificate share.
    pub async fn unshare_certificates(
        &self,
        external_email: &str,
    ) -> Result<CertificateSharesResponse, Error> {
        self.ensure_url_component(external_email)?;
        let response: CertificateSharesResponse = self
            .send_json::<(), _>(
                HttpMethod::Delete,
                self.urls()?.shared_certs(external_email),
                None,
                true,
                200,
            )
            .await?;
        ensure_logical(&response.response_code)?;
        self.ensure_collection(response.shared_to.len())?;
        self.ensure_collection(response.shared_from.len())?;
        Ok(response)
    }

    /// Exports certificates encrypted to one registered OpenPGP export key.
    pub async fn export_certificate(
        &self,
        pgp_key_id: &str,
    ) -> Result<ExportCertificatesResponse, Error> {
        self.ensure_url_component(pgp_key_id)?;
        let url = url::query(&self.urls()?.cert(), &[("PgpKeyId", pgp_key_id)]);
        let mut response: ExportCertificatesWire = self
            .send_json::<(), _>(HttpMethod::Get, url, None, true, 200)
            .await?;
        response.envelope().ensure_success()?;
        self.ensure_collection(response.certs_and_keys.len())?;
        Ok(ExportCertificatesResponse {
            response: response.envelope(),
            certs_and_keys: response
                .certs_and_keys
                .iter_mut()
                .map(|item| ExportedCertificate {
                    certificate: std::mem::take(&mut item.certificate),
                    encrypted_private_key: SecretString::new(std::mem::take(
                        &mut item.encrypted_private_key,
                    )),
                })
                .collect(),
        })
    }

    /// Imports bank certificate and key material.
    pub async fn import_certificate(
        &self,
        input: &ImportCertificateRequest,
    ) -> Result<ApiResponse, Error> {
        let request = ImportCertificateWire {
            company: &input.company,
            ws_user_id: &input.ws_user_id,
            private_key: input.private_key.expose_secret(),
            certificate: &input.certificate,
            encrypted_private_key: input
                .encrypted_private_key
                .as_ref()
                .map(SecretString::expose_secret),
            encrypted_certificate: input
                .encrypted_certificate
                .as_ref()
                .map(SecretString::expose_secret),
        };
        self.auth_api_response(HttpMethod::Put, self.urls()?.cert(), Some(&request), 201)
            .await
    }

    /// Enrolls a certificate through the selected bank profile.
    pub async fn enroll_certificate(
        &self,
        input: &EnrollCertificateRequest,
    ) -> Result<ApiResponse, Error> {
        let request = EnrollCertificateWire {
            code: input.code.expose_secret(),
            company: &input.company,
            ws_user_id: &input.ws_user_id,
        };
        self.auth_api_response(HttpMethod::Post, self.urls()?.cert(), Some(&request), 201)
            .await
    }

    /// Lists integrator-managed accounts.
    pub async fn list_accounts(&self) -> Result<ListAccountsResponse, Error> {
        let response: ListAccountsResponse = self
            .send_json::<(), _>(HttpMethod::Get, self.urls()?.accounts(), None, true, 200)
            .await?;
        ensure_logical(&response.response_code)?;
        self.ensure_collection(response.accounts.len())?;
        for account in &response.accounts {
            self.ensure_collection(account.certs.len())?;
        }
        Ok(response)
    }

    /// Logs out even when the local expiry clock considers the session stale.
    pub async fn logout(&mut self) -> Result<ApiResponse, Error> {
        let response: ApiResponse = self
            .send_json_allow_expired::<(), _>(
                HttpMethod::Delete,
                self.urls()?.session(),
                None,
                true,
                200,
            )
            .await?;
        response.ensure_success()?;
        self.session = None;
        self.pending = PendingAuth::default();
        Ok(response)
    }

    async fn registration_challenge(&self) -> Result<SecretString, Error> {
        let mut response: ChallengeWire = self
            .send_json::<(), _>(HttpMethod::Get, self.urls()?.account(), None, false, 200)
            .await?;
        response.envelope().ensure_success()?;
        if response.challenge.is_empty() {
            return Err(Error::Protocol(ProtocolError::MissingValue));
        }
        Ok(SecretString::new(std::mem::take(&mut response.challenge)))
    }

    async fn login_challenge(&self) -> Result<SecretString, Error> {
        let mut response: ChallengeWire = self
            .send_json::<(), _>(HttpMethod::Get, self.urls()?.session(), None, false, 200)
            .await?;
        response.envelope().ensure_success()?;
        if response.challenge.is_empty() {
            return Err(Error::Protocol(ProtocolError::MissingValue));
        }
        Ok(SecretString::new(std::mem::take(&mut response.challenge)))
    }

    fn apply_auth_response(&mut self, mut wire: AuthResponseWire) -> Result<AuthState, Error> {
        self.ensure_collection(wire.mfa_options.as_ref().map_or(0, Vec::len))?;
        let response = ApiResponse {
            response_code: std::mem::take(&mut wire.response_code),
            response_text: std::mem::take(&mut wire.response_text),
        };
        if !crate::models::is_response_code(&response.response_code) {
            return Err(Error::Protocol(ProtocolError::MalformedResponse));
        }
        if response.response_code != "00" {
            return Ok(AuthState::Failed {
                mode: self.config.mode,
                reason: classify_failure(&response),
                response,
            });
        }
        let current_access_token = wire.access_token.take().map(SecretString::new);
        if let Some(value) = current_access_token.as_ref() {
            self.pending.access_token = Some(SecretString::new(value.expose_secret()));
        }
        if let Some(value) = wire.api_key.take() {
            if self
                .pending
                .api_key
                .as_ref()
                .is_some_and(|expected| expected.expose_secret() != value)
            {
                return Err(Error::Protocol(ProtocolError::ApiKeyMismatch));
            }
            self.pending.api_key = Some(SecretString::new(value));
        }
        if let Some(value) = wire.session.take() {
            self.pending.continuation = Some(SecretString::new(value));
        }
        if let Some(value) = wire.challenge_name.as_ref() {
            self.pending.challenge_name = Some(value.clone());
        }

        let transition = classify_auth_response(AuthResponseFacts {
            response: &response,
            has_current_access_token: current_access_token.is_some(),
            has_api_key: self.pending.api_key.is_some(),
            has_continuation: self.pending.continuation.is_some(),
            has_id_token: wire.id_token.is_some(),
            has_totp_secret: wire.secret_code.is_some(),
            has_totp_uri: wire.otpauth_uri.is_some(),
            challenge_name: wire.challenge_name.as_deref(),
            mfa_options: wire.mfa_options.as_deref().unwrap_or_default(),
            sms_destination: wire.sms_destination.as_deref(),
        })?;

        Ok(match transition {
            AuthTransition::Authenticated { totp_enrollment } => {
                let id_token = wire
                    .id_token
                    .take()
                    .ok_or(Error::Protocol(ProtocolError::MissingValue))?;
                let api_key = self
                    .pending
                    .api_key
                    .take()
                    .ok_or(Error::Protocol(ProtocolError::MissingValue))?;
                let expires_in_seconds = wire
                    .expires_in
                    .take()
                    .map(WireU64::into_value)
                    .transpose()?;
                let expires_at_epoch_seconds = expires_in_seconds
                    .map(|seconds| self.clock.now_epoch_seconds().saturating_add(seconds));
                let totp_enrollment = if totp_enrollment {
                    Some(crate::TotpEnrollment {
                        secret: SecretString::new(
                            wire.secret_code
                                .take()
                                .ok_or(Error::Protocol(ProtocolError::MissingValue))?,
                        ),
                        otpauth_uri: SecretString::new(
                            wire.otpauth_uri
                                .take()
                                .ok_or(Error::Protocol(ProtocolError::MissingValue))?,
                        ),
                        access_token: current_access_token
                            .ok_or(Error::Protocol(ProtocolError::MissingValue))?,
                    })
                } else {
                    None
                };
                self.session = Some(Session {
                    access_token: if totp_enrollment.is_none() {
                        self.pending.access_token.take()
                    } else {
                        None
                    },
                    api_key,
                    expires_in_seconds,
                    expires_at_epoch_seconds,
                    id_token: SecretString::new(id_token),
                    continuation: self.pending.continuation.take(),
                });
                self.pending.challenge_name = None;
                AuthState::Authenticated {
                    mode: self.config.mode,
                    totp_enrollment,
                }
            }
            AuthTransition::NeedsMfaSelection {
                methods,
                sms_destination,
            } => AuthState::NeedsMfaSelection {
                mode: self.config.mode,
                methods,
                sms_destination,
            },
            AuthTransition::NeedsMfa { method } => AuthState::NeedsMfa {
                mode: self.config.mode,
                method,
            },
            AuthTransition::NeedsEmailVerification => AuthState::NeedsEmailVerification {
                mode: self.config.mode,
            },
            AuthTransition::NeedsPhoneVerification => AuthState::NeedsPhoneVerification {
                mode: self.config.mode,
            },
            AuthTransition::Failed(reason) => AuthState::Failed {
                mode: self.config.mode,
                reason,
                response,
            },
        })
    }

    fn classify_verification(
        &self,
        response: ApiResponse,
        step: crate::AuthStep,
    ) -> Result<AuthState, Error> {
        Ok(match classify_verification_response(&response)? {
            VerificationTransition::Accepted => AuthState::VerificationAccepted {
                mode: self.config.mode,
                step,
            },
            VerificationTransition::Failed(reason) => AuthState::Failed {
                mode: self.config.mode,
                reason,
                response,
            },
        })
    }

    async fn auth_api_response<Q: Serialize + ?Sized>(
        &self,
        method: HttpMethod,
        url: String,
        body: Option<&Q>,
        expected_status: u16,
    ) -> Result<ApiResponse, Error> {
        let response: ApiResponse = self
            .send_json(method, url, body, true, expected_status)
            .await?;
        response.ensure_success()?;
        Ok(response)
    }

    async fn send_json<Q: Serialize + ?Sized, R: DeserializeOwned>(
        &self,
        method: HttpMethod,
        url: String,
        body: Option<&Q>,
        authenticated: bool,
        expected_status: u16,
    ) -> Result<R, Error> {
        self.send_json_with_expiry(method, url, body, authenticated, expected_status, false)
            .await
    }

    async fn send_json_allow_expired<Q: Serialize + ?Sized, R: DeserializeOwned>(
        &self,
        method: HttpMethod,
        url: String,
        body: Option<&Q>,
        authenticated: bool,
        expected_status: u16,
    ) -> Result<R, Error> {
        self.send_json_with_expiry(method, url, body, authenticated, expected_status, true)
            .await
    }

    async fn send_json_with_expiry<Q: Serialize + ?Sized, R: DeserializeOwned>(
        &self,
        method: HttpMethod,
        url: String,
        body: Option<&Q>,
        authenticated: bool,
        expected_status: u16,
        allow_expired_session: bool,
    ) -> Result<R, Error> {
        if authenticated && self.is_session_expired() && !allow_expired_session {
            return Err(Error::Protocol(ProtocolError::SessionExpired));
        }
        ensure_limit(
            url.len(),
            self.config.limits.max_url_bytes(),
            LimitKind::Url,
        )?;
        let body = body
            .map(|value| serialize_bounded(value, self.config.limits.max_request_body_bytes()))
            .transpose()?;
        let request = Request {
            method,
            url,
            headers: self.headers(authenticated)?,
            body,
        };
        let response = self.transport.send(request).await?;
        ensure_limit(
            response.body.len(),
            self.config.limits.max_response_body_bytes(),
            LimitKind::ResponseBody,
        )?;
        decode_json_response(response, expected_status)
    }

    fn ensure_collection(&self, actual: usize) -> Result<(), Error> {
        ensure_limit(
            actual,
            self.config.limits.max_collection_items(),
            LimitKind::CollectionItems,
        )
    }

    fn ensure_url_component(&self, value: &str) -> Result<(), Error> {
        ensure_limit(
            value.len(),
            self.config.limits.max_url_bytes(),
            LimitKind::Url,
        )
    }

    fn headers(&self, authenticated: bool) -> Result<Vec<Header>, Error> {
        let mut headers = vec![Header {
            name: "Content-Type".to_owned(),
            value: HeaderValue::Public("application/json".to_owned()),
        }];
        if authenticated {
            let session = self
                .session
                .as_ref()
                .ok_or(Error::Protocol(ProtocolError::InvalidAuthState))?;
            headers.push(Header {
                name: "Authorization".to_owned(),
                value: HeaderValue::Secret(SecretString::new(session.id_token().expose_secret())),
            });
            headers.push(Header {
                name: "x-api-key".to_owned(),
                value: HeaderValue::Secret(SecretString::new(session.api_key().expose_secret())),
            });
        }
        Ok(headers)
    }

    fn urls(&self) -> Result<url::Urls<'_>, Error> {
        url::Urls::new(
            &self.config.base_url,
            &self.config.email,
            self.config.mode,
            &self.config.phone,
            &self.config.bank,
        )
        .map_err(Error::Protocol)
    }

    fn reset_auth_attempt(&mut self) {
        self.pending.access_token = None;
        self.pending.continuation = None;
        self.pending.challenge_name = None;
        self.session = None;
    }
}

struct BoundedBody {
    bytes: Vec<u8>,
    maximum: usize,
    exceeded: bool,
}

impl BoundedBody {
    fn new(maximum: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(maximum.min(1024)),
            maximum,
            exceeded: false,
        }
    }
}

impl Write for BoundedBody {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.maximum.saturating_sub(self.bytes.len()) {
            self.exceeded = true;
            return Err(io::Error::other("request body limit exceeded"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for BoundedBody {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

fn serialize_bounded<Q: Serialize + ?Sized>(
    value: &Q,
    maximum: usize,
) -> Result<SecretBytes, Error> {
    let mut writer = BoundedBody::new(maximum);
    match serde_json::to_writer(&mut writer, value) {
        Ok(()) => Ok(SecretBytes::new(std::mem::take(&mut writer.bytes))),
        Err(_) if writer.exceeded => Err(Error::Limit(LimitError::new(LimitKind::RequestBody))),
        Err(_) => Err(Error::Protocol(ProtocolError::InvalidConfiguration)),
    }
}

fn max_base64_len(raw_bytes: usize) -> usize {
    raw_bytes
        .checked_add(2)
        .and_then(|value| value.checked_div(3))
        .and_then(|value| value.checked_mul(4))
        .unwrap_or(usize::MAX)
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct ChallengeWire {
    response_code: String,
    response_text: String,
    challenge: String,
}

impl ChallengeWire {
    fn envelope(&self) -> ApiResponse {
        ApiResponse {
            response_code: self.response_code.clone(),
            response_text: self.response_text.clone(),
        }
    }
}

impl Drop for ChallengeWire {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.challenge.zeroize();
    }
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct RegisterWire<'a> {
    name: &'a str,
    phone: &'a str,
    company: &'a str,
    api_key: &'a str,
    #[serde(rename = "ChResp")]
    challenge: &'a str,
    encrypted: &'a str,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct RegisterResponseWire {
    response_code: String,
    response_text: String,
    api_key: String,
}

impl RegisterResponseWire {
    fn envelope(&self) -> ApiResponse {
        ApiResponse {
            response_code: self.response_code.clone(),
            response_text: self.response_text.clone(),
        }
    }
}

impl Drop for RegisterResponseWire {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.api_key.zeroize();
    }
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct PasswordResetWire<'a> {
    code: &'a str,
    #[serde(rename = "ChResp")]
    challenge: &'a str,
    encrypted: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct LoginWire<'a> {
    #[serde(rename = "ChResp")]
    challenge: &'a str,
    encrypted: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct SelectMfaWire<'a> {
    mfa_type: &'a str,
    session: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct MfaCodeWire<'a> {
    code: &'a str,
    session: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    challenge_name: Option<&'a str>,
    #[serde(rename = "SetupTOTP", skip_serializing_if = "Option::is_none")]
    setup_totp: Option<bool>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct VerificationCodeWire<'a> {
    code: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct VerificationWithTokenWire<'a> {
    access_token: &'a str,
    code: &'a str,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct AuthResponseWire {
    response_code: String,
    response_text: String,
    access_token: Option<String>,
    api_key: Option<String>,
    challenge_name: Option<String>,
    expires_in: Option<WireU64>,
    id_token: Option<String>,
    session: Option<String>,
    secret_code: Option<String>,
    #[serde(rename = "OtpauthUri")]
    otpauth_uri: Option<String>,
    mfa_options: Option<Vec<String>>,
    sms_destination: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum WireU64 {
    Number(u64),
    String(String),
}

impl WireU64 {
    fn into_value(self) -> Result<u64, Error> {
        match self {
            Self::Number(value) => Ok(value),
            Self::String(value) => value
                .parse()
                .map_err(|_| Error::Protocol(ProtocolError::MalformedResponse)),
        }
    }
}

impl Drop for AuthResponseWire {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.access_token.zeroize();
        self.api_key.zeroize();
        self.id_token.zeroize();
        self.session.zeroize();
        self.secret_code.zeroize();
        self.otpauth_uri.zeroize();
    }
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct UploadKeyWire<'a> {
    pgp_key: &'a str,
    #[serde(rename = "PgpKeyPurpose")]
    purpose: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct DeleteKeyWire<'a> {
    #[serde(rename = "PgpKeyId")]
    key_id: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct UploadFileWire<'a> {
    #[serde(rename = "FileContents")]
    contents: &'a str,
    #[serde(rename = "FileName")]
    name: &'a str,
    file_type: &'a str,
    signature: &'a str,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct DownloadWire {
    response_code: String,
    response_text: String,
    content: String,
}

impl DownloadWire {
    fn envelope(&self) -> ApiResponse {
        ApiResponse {
            response_code: self.response_code.clone(),
            response_text: self.response_text.clone(),
        }
    }
}

impl Drop for DownloadWire {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.content.zeroize();
    }
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct ConfigCertificatesWire<'a> {
    export: &'a str,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct ExportCertificatesWire {
    response_code: String,
    response_text: String,
    certs_and_keys: Vec<ExportedCertificateWire>,
}

impl ExportCertificatesWire {
    fn envelope(&self) -> ApiResponse {
        ApiResponse {
            response_code: self.response_code.clone(),
            response_text: self.response_text.clone(),
        }
    }
}

impl Drop for ExportCertificatesWire {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        for item in &mut self.certs_and_keys {
            item.encrypted_private_key.zeroize();
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct ExportedCertificateWire {
    certificate: String,
    encrypted_private_key: String,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct ImportCertificateWire<'a> {
    company: &'a str,
    #[serde(rename = "WsUserId")]
    ws_user_id: &'a str,
    private_key: &'a str,
    certificate: &'a str,
    #[serde(rename = "EncPrivatekey", skip_serializing_if = "Option::is_none")]
    encrypted_private_key: Option<&'a str>,
    #[serde(rename = "EncCertificate", skip_serializing_if = "Option::is_none")]
    encrypted_certificate: Option<&'a str>,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct EnrollCertificateWire<'a> {
    code: &'a str,
    company: &'a str,
    #[serde(rename = "WsUserId")]
    ws_user_id: &'a str,
}
