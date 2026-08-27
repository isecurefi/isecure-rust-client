//! Shared bounded response and error invariants for direct and brokered facades.

use alloc::{borrow::ToOwned, string::String};

use serde::{Deserialize, de::DeserializeOwned};

use crate::{Error, HttpError, LimitError, LimitKind, LogicalError, ProtocolError, Response};

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

pub(crate) fn is_safe_request_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ErrorWire {
    response_code: Option<String>,
    request_id: Option<String>,
}
