//! Shared bounded response and error invariants for direct and brokered facades.

use alloc::{borrow::ToOwned, string::String};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use serde::{Deserialize, de::DeserializeOwned};

use crate::{
    ApiResponse, DownloadFileResponse, Error, HttpError, LimitError, LimitKind, LogicalError,
    ProtocolError, ResourceLimits, Response, SecretBytes,
};

pub(crate) fn ensure_logical(response_code: &str) -> Result<(), Error> {
    if !crate::models::is_response_code(response_code) {
        return Err(Error::Protocol(ProtocolError::MalformedResponse));
    }
    if response_code == "00" {
        Ok(())
    } else {
        Err(Error::Logical(LogicalError {
            response_code: response_code.to_owned(),
            request_id: None,
        }))
    }
}

pub(crate) fn ensure_limit(actual: usize, maximum: usize, kind: LimitKind) -> Result<(), Error> {
    if actual <= maximum {
        Ok(())
    } else {
        Err(Error::Limit(LimitError::new(kind)))
    }
}

pub(crate) fn decode_json_response<R: DeserializeOwned>(
    response: Response,
    expected_status: u16,
) -> Result<R, Error> {
    if response.status != expected_status {
        let fields = serde_json::from_slice::<ErrorWire>(response.body.expose_secret()).ok();
        return Err(Error::Http(HttpError {
            status: response.status,
            response_code: fields
                .as_ref()
                .and_then(|value| value.response_code.as_deref())
                .filter(|value| crate::models::is_response_code(value))
                .map(ToOwned::to_owned),
            request_id: fields
                .and_then(|value| value.request_id)
                .filter(|value| is_safe_request_id(value)),
        }));
    }
    serde_json::from_slice(response.body.expose_secret())
        .map_err(|_| Error::Protocol(ProtocolError::MalformedResponse))
}

/// Only auth/verification callers use this decoder. A rejected response must be
/// the exact API envelope; token-bearing or unknown fields fail closed.
#[cfg(feature = "std")]
pub(crate) fn decode_auth_response<R: DeserializeOwned>(response: Response) -> Result<R, Error> {
    let expected_status = if response.status != 200
        && serde_json::from_slice::<ApiResponse>(response.body.expose_secret()).is_ok_and(
            |envelope| crate::auth::is_recognized_auth_rejection(response.status, &envelope),
        ) {
        response.status
    } else {
        200
    };
    decode_json_response(response, expected_status)
}

pub(crate) fn is_safe_request_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn max_base64_len(raw_bytes: usize) -> usize {
    raw_bytes
        .checked_add(2)
        .and_then(|value| value.checked_div(3))
        .and_then(|value| value.checked_mul(4))
        .unwrap_or(usize::MAX)
}

pub(crate) fn decode_download_response(
    response: Response,
    limits: ResourceLimits,
) -> Result<DownloadFileResponse, Error> {
    ensure_limit(
        response.body.len(),
        limits.max_response_body_bytes(),
        LimitKind::ResponseBody,
    )?;
    let response: DownloadWire = decode_json_response(response, 200)?;
    finish_download(response, limits)
}

pub(crate) fn finish_download(
    response: DownloadWire,
    limits: ResourceLimits,
) -> Result<DownloadFileResponse, Error> {
    response.envelope().ensure_success()?;
    ensure_limit(
        response.content.len(),
        max_base64_len(limits.max_file_bytes()),
        LimitKind::FileContent,
    )?;
    let content = SecretBytes::new(
        BASE64_STANDARD
            .decode(response.content.as_bytes())
            .map_err(|_| Error::Protocol(ProtocolError::MalformedResponse))?,
    );
    ensure_limit(
        content.len(),
        limits.max_file_bytes(),
        LimitKind::FileContent,
    )?;
    Ok(DownloadFileResponse {
        response: response.envelope(),
        content,
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub(crate) struct DownloadWire {
    response_code: String,
    response_text: String,
    pub(crate) content: String,
}

impl DownloadWire {
    pub(crate) fn envelope(&self) -> ApiResponse {
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

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ErrorWire {
    response_code: Option<String>,
    request_id: Option<String>,
}
