//! Public provider-protocol request and response models.

use alloc::{string::String, vec::Vec};
use core::fmt;

use crate::{SecretBytes, SecretString};
use serde::{Deserialize, Serialize};

/// ISECure account identity mode.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Administration, certificate, key, and account operations.
    Admin,
    /// Bank file operations.
    Data,
}

impl Mode {
    /// Exact lowercase path value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Data => "data",
        }
    }
}

/// Purpose assigned to an uploaded OpenPGP public key.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PgpKeyPurpose {
    /// Authorize detached file-upload signatures.
    Authorize,
    /// Encrypt exported certificate private-key material.
    Export,
}

impl PgpKeyPurpose {
    /// Exact lowercase REST wire value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Authorize => "authorize",
            Self::Export => "export",
        }
    }
}

/// Common successful ISECure response envelope.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct ApiResponse {
    /// Provider logical response code. Successful operations use `00`.
    pub response_code: String,
    /// Human-readable provider response text. Do not place it in ordinary logs.
    pub response_text: String,
}

impl fmt::Debug for ApiResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApiResponse")
            .field("response_code", &self.response_code)
            .field("response_text", &"[REDACTED]")
            .finish()
    }
}

impl ApiResponse {
    pub(crate) fn ensure_success(&self) -> Result<(), crate::Error> {
        if !is_response_code(&self.response_code) {
            return Err(crate::Error::Protocol(
                crate::ProtocolError::MalformedResponse,
            ));
        }
        if self.response_code == "00" {
            Ok(())
        } else {
            Err(crate::Error::Logical(crate::LogicalError {
                response_code: self.response_code.clone(),
                request_id: None,
            }))
        }
    }
}

pub(crate) fn is_response_code(value: &str) -> bool {
    value.len() == 2 && value.bytes().all(|byte| byte.is_ascii_digit())
}

/// Server-provided account classification; not a client authorization decision.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AccountType {
    /// Operator classification.
    Operator,
    /// Integrator classification.
    Integrator,
    /// Customer classification.
    Customer,
}

/// Optional account metadata returned with a completed login.
#[derive(Clone, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct SessionAccount {
    /// Server classification. The server still authorizes every operation.
    #[serde(rename = "Type")]
    pub account_type: AccountType,
    /// Per-user preview identifiers, not subscription or authorization grants.
    pub features: Vec<String>,
    /// Active product identifiers; `None` means unavailable, not an empty subscription list.
    pub entitlements: Option<Vec<String>>,
}

impl fmt::Debug for SessionAccount {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionAccount")
            .field("account_type", &self.account_type)
            .field("features", &"[REDACTED]")
            .field(
                "entitlements",
                &self.entitlements.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// Successful account registration.
#[derive(Debug)]
pub struct RegistrationResult {
    /// Common provider response.
    pub response: ApiResponse,
    /// Whether the returned API key was admitted into client memory.
    pub api_key_available: bool,
}

/// Account password reset confirmation.
#[derive(Debug)]
pub struct PasswordReset {
    /// One-time confirmation code.
    pub code: SecretString,
    /// New password.
    pub new_password: SecretString,
    /// Challenge supplied by the provider's password-recovery journey.
    pub challenge: SecretString,
}

/// Optional bank file list filters.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ListFilesQuery {
    /// Bank-specific file type.
    pub file_type: Option<String>,
    /// Bank-specific status such as `NEW`, `ALL`, or `DLD`.
    pub status: Option<String>,
}

/// File upload input. Exact file bytes and detached signatures are zeroized.
#[derive(Debug)]
pub struct UploadFileRequest {
    /// Exact file bytes. The SDK performs the REST contract's Base64 encoding.
    pub file_contents: SecretBytes,
    /// Bank-visible filename.
    pub file_name: String,
    /// Bank-specific file type.
    pub file_type: String,
    /// One or more ASCII-armored detached signatures.
    pub signature: SecretString,
}

/// One bank file descriptor.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct FileDescriptor {
    /// Bank file type.
    pub file_type: String,
    /// Bank status.
    pub status: String,
    /// Provider timestamp preserving its exact lexical value.
    pub file_timestamp: String,
    /// Provider file reference.
    pub file_reference: String,
    /// Optional service identity.
    pub service_id: Option<String>,
    /// Optional target identity.
    pub target_id: Option<String>,
}

/// Successful bank file listing.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct ListFilesResponse {
    /// Provider logical response code.
    pub response_code: String,
    /// Provider response text.
    pub response_text: String,
    /// Exact returned descriptors.
    pub file_descriptors: Vec<FileDescriptor>,
}

/// Downloaded bank file response. Content is kept in a zeroizing wrapper.
#[derive(Debug)]
pub struct DownloadFileResponse {
    /// Common provider response.
    pub response: ApiResponse,
    /// Exact decoded file bytes.
    pub content: SecretBytes,
}

/// Registered OpenPGP public-key descriptor.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct PgpKeyDescriptor {
    /// Eight-character key identifier.
    pub pgp_key_id: String,
    /// Optional purpose on older records.
    pub pgp_key_purpose: Option<PgpKeyPurpose>,
}

/// Successful OpenPGP key listing.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct ListKeysResponse {
    /// Provider logical response code.
    pub response_code: String,
    /// Provider response text.
    pub response_text: String,
    /// Registered public keys.
    pub pgp_keys: Vec<PgpKeyDescriptor>,
}

/// Certificate descriptor returned by the provider.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct CertificateDescriptor {
    /// Certificate name.
    pub cert_name: String,
    /// Exact expiry value.
    pub expires: String,
    /// Subject distinguished name.
    pub subject: String,
    /// Issuer distinguished name.
    pub issuer: String,
    /// Serial number preserving lexical form.
    pub serial: String,
    /// PEM certificate.
    #[serde(rename = "PEM")]
    pub pem: String,
}

/// How a bank connection is available to the current account.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BankConnectionAccess {
    /// Directly owned connection.
    Direct,
    /// Shared from another account under the same API key.
    Shared,
}

/// Certificate purpose on a bank connection.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BankCertificatePurpose {
    /// Signing certificate.
    Signing,
    /// Encryption certificate.
    Encryption,
}

/// One certificate summary on a bank connection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct BankConnectionCertificateDescriptor {
    /// Certificate purpose.
    pub purpose: BankCertificatePurpose,
    /// Exact expiry value.
    pub expires: String,
}

/// Bank connection visible to the authenticated account.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct BankConnectionDescriptor {
    /// Public File Exchange API bank identifier.
    pub bank: String,
    /// Direct or shared access.
    pub access: BankConnectionAccess,
    /// Available certificate summaries.
    pub certificates: Vec<BankConnectionCertificateDescriptor>,
}

/// Successful certificate listing.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct ListCertificatesResponse {
    /// Provider logical response code.
    pub response_code: String,
    /// Provider response text.
    pub response_text: String,
    /// Certificates owned directly by the account.
    pub certs: Vec<CertificateDescriptor>,
    /// Direct and shared bank connections when returned by the current API.
    #[serde(default)]
    pub connections: Vec<BankConnectionDescriptor>,
    /// Retired certificate summaries, separate from usable certificates and connections.
    #[serde(default)]
    pub retired: Vec<RetiredCertificateDescriptor>,
}

/// Public summary of a certificate that is no longer usable.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct RetiredCertificateDescriptor {
    /// Retired record name.
    pub cert_name: String,
    /// Public bank identifier.
    pub bank: String,
    /// Original certificate purpose.
    pub purpose: BankCertificatePurpose,
    /// Exact expiry text, including the provider's `unknown` value.
    pub expires: String,
}

/// Certificate export setting.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CertificateExport {
    /// Export is disabled.
    Disabled,
    /// Export is allowed.
    Allowed,
}

/// Admin/data registration status for an integrator account.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RegistrationStatus {
    /// The identity exists.
    Registered,
    /// The identity has not been registered.
    Unregistered,
}

/// Integrator account descriptor.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct AccountDescriptor {
    /// Account name.
    pub name: String,
    /// Account email.
    pub email: String,
    /// Account phone.
    pub phone: String,
    /// Certificate export setting.
    pub export: CertificateExport,
    /// Direct certificates.
    pub certs: Vec<CertificateDescriptor>,
    /// Optional administrative identity state.
    pub admin_mode: Option<RegistrationStatus>,
    /// Optional data identity state.
    pub data_mode: Option<RegistrationStatus>,
}

/// Successful integrator-account listing.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct ListAccountsResponse {
    /// Provider logical response code.
    pub response_code: String,
    /// Provider response text.
    pub response_text: String,
    /// Accounts under the current API key.
    pub accounts: Vec<AccountDescriptor>,
}

/// Current certificate-sharing relationships.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct CertificateSharesResponse {
    /// Provider logical response code.
    pub response_code: String,
    /// Provider response text.
    pub response_text: String,
    /// Accounts this account shares to.
    pub shared_to: Vec<String>,
    /// Accounts sharing to this account.
    pub shared_from: Vec<String>,
}

/// Bank certificate import input.
#[derive(Debug)]
pub struct ImportCertificateRequest {
    /// Company value expected by the bank profile.
    pub company: String,
    /// Bank web-service user identity.
    pub ws_user_id: String,
    /// Plain private key where the exact provider contract requires it.
    pub private_key: SecretString,
    /// Certificate bytes or PEM text.
    pub certificate: String,
    /// Optional encrypted private key.
    pub encrypted_private_key: Option<SecretString>,
    /// Optional encrypted certificate.
    pub encrypted_certificate: Option<SecretString>,
}

/// Bank certificate enrollment input.
#[derive(Debug)]
pub struct EnrollCertificateRequest {
    /// Provider/bank enrollment code.
    pub code: SecretString,
    /// Company value expected by the bank profile.
    pub company: String,
    /// Bank web-service user identity.
    pub ws_user_id: String,
}

/// One exported certificate and its encrypted private key.
#[derive(Debug)]
pub struct ExportedCertificate {
    /// Certificate bytes or PEM text.
    pub certificate: String,
    /// Private key encrypted to the selected OpenPGP export key.
    pub encrypted_private_key: SecretString,
}

/// Successful certificate export.
#[derive(Debug)]
pub struct ExportCertificatesResponse {
    /// Common provider response.
    pub response: ApiResponse,
    /// Exported certificate material.
    pub certs_and_keys: Vec<ExportedCertificate>,
}

impl fmt::Display for Mode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}
