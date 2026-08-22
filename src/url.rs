//! Exact path and query construction.

use crate::{Mode, ProtocolError};

pub(crate) struct Urls<'a> {
    base_url: &'a str,
    email: &'a str,
    mode: Mode,
    phone: &'a str,
    bank: &'a str,
}

impl<'a> Urls<'a> {
    pub(crate) fn new(
        base_url: &'a str,
        email: &'a str,
        mode: Mode,
        phone: &'a str,
        bank: &'a str,
    ) -> Result<Self, ProtocolError> {
        let base_url = base_url.trim_end_matches('/');
        if !admitted_base_url(base_url)
            || base_url.contains('?')
            || base_url.contains('#')
            || email.is_empty()
            || phone.is_empty()
        {
            return Err(ProtocolError::InvalidConfiguration);
        }
        Ok(Self {
            base_url,
            email,
            mode,
            phone,
            bank,
        })
    }

    pub(crate) fn account(&self) -> String {
        self.path(&["account", self.email, self.mode.as_str()])
    }

    pub(crate) fn account_phone(&self) -> String {
        self.path(&["account", self.email, self.mode.as_str(), self.phone])
    }

    pub(crate) fn password(&self) -> String {
        self.path(&["account", self.email, self.mode.as_str(), "password"])
    }

    pub(crate) fn session(&self) -> String {
        self.path(&["session", self.email, self.mode.as_str()])
    }

    pub(crate) fn mfa_code(&self) -> String {
        self.path(&["session", self.email, self.mode.as_str(), "mfacode"])
    }

    pub(crate) fn select_mfa(&self) -> String {
        self.path(&["session", self.email, self.mode.as_str(), "selectmfa"])
    }

    pub(crate) fn verify_totp(&self) -> String {
        self.path(&["session", self.email, self.mode.as_str(), "verifytotp"])
    }

    pub(crate) fn pgp(&self) -> String {
        self.path(&["pgp"])
    }

    pub(crate) fn files(&self) -> String {
        self.path(&["files", self.bank])
    }

    pub(crate) fn file(&self, file_type: &str, file_reference: &str) -> String {
        self.path(&["files", self.bank, file_type, file_reference])
    }

    pub(crate) fn certs(&self) -> String {
        self.path(&["certs"])
    }

    pub(crate) fn cert(&self) -> String {
        self.path(&["certs", self.bank])
    }

    pub(crate) fn shared_certs(&self, email: &str) -> String {
        self.path(&["certs", "shared", email])
    }

    pub(crate) fn accounts(&self) -> String {
        self.path(&["integrator", "accounts"])
    }

    fn path(&self, segments: &[&str]) -> String {
        let encoded = segments
            .iter()
            .map(|segment| percent_encode(segment))
            .collect::<Vec<_>>()
            .join("/");
        format!("{}/{encoded}", self.base_url)
    }
}

fn admitted_base_url(value: &str) -> bool {
    let (https, remainder) = if let Some(remainder) = value.strip_prefix("https://") {
        (true, remainder)
    } else if let Some(remainder) = value.strip_prefix("http://") {
        (false, remainder)
    } else {
        return false;
    };
    let authority = remainder.split('/').next().unwrap_or_default();
    if authority.is_empty()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        || authority.contains(['@', '\\'])
    {
        return false;
    }
    if https {
        return true;
    }
    let (host, port) = authority
        .split_once(':')
        .map_or((authority, None), |(host, port)| (host, Some(port)));
    matches!(host, "localhost" | "127.0.0.1")
        && port.is_none_or(|value| {
            !value.is_empty()
                && value.bytes().all(|byte| byte.is_ascii_digit())
                && value.parse::<u16>().is_ok_and(|port| port > 0)
        })
}

pub(crate) fn query(url: &str, values: &[(&str, &str)]) -> String {
    if values.is_empty() {
        return url.to_owned();
    }
    let query = values
        .iter()
        .map(|(name, value)| format!("{}={}", percent_encode(name), percent_encode(value)))
        .collect::<Vec<_>>()
        .join("&");
    format!("{url}?{query}")
}

fn percent_encode(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_and_query_values_are_percent_encoded() {
        let urls = Urls::new(
            "https://example.test/v2/",
            "a+b@example.test",
            Mode::Admin,
            "+358 40",
            "bank/name",
        )
        .expect("valid URL");
        assert_eq!(
            urls.account_phone(),
            "https://example.test/v2/account/a%2Bb%40example.test/admin/%2B358%2040"
        );
        assert_eq!(
            query(&urls.files(), &[("FileType", "camt 053")]),
            "https://example.test/v2/files/bank%2Fname?FileType=camt%20053"
        );
    }

    #[test]
    fn only_exact_loopback_authorities_may_use_plain_http() {
        for base_url in [
            "http://localhost.evil/v2",
            "http://127.0.0.1.evil/v2",
            "http://localhost@evil.test/v2",
            "http://localhost:invalid/v2",
            "https://evil.test\\@trusted.test/v2",
            "https:// /v2",
        ] {
            assert!(
                Urls::new(base_url, "a@example.test", Mode::Data, "+35840", "bank").is_err(),
                "admitted unsafe base URL: {base_url}"
            );
        }
        for base_url in [
            "http://localhost/v2",
            "http://localhost:8080/v2",
            "http://127.0.0.1/v2",
            "http://127.0.0.1:3000/v2",
            "https://ws-api.test.isecure.fi/v2",
        ] {
            assert!(
                Urls::new(base_url, "a@example.test", Mode::Data, "+35840", "bank").is_ok(),
                "rejected admitted base URL: {base_url}"
            );
        }
    }
}
