//! Deterministic transport/client scenario executed as a real WASI program.

use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    future::{Ready, ready},
};

use futures_executor::block_on;
use isecure_rust_client::{
    AuthState, ChallengeEncryptor, Client, ClientConfig, Clock, Error, ListFilesQuery, Mode,
    ProtocolError, Request, Response, SecretBytes, SecretString, Transport, TransportError,
    TransportErrorKind,
};

struct WasmTransport {
    responses: RefCell<VecDeque<Result<Response, TransportError>>>,
    requests: RefCell<Vec<Request>>,
}

struct RetryingWasmTransport {
    outcomes: RefCell<VecDeque<Result<Response, TransportError>>>,
    sdk_calls: Cell<u8>,
    host_attempts: Cell<u8>,
}

impl Transport for RetryingWasmTransport {
    type Future<'a> = Ready<Result<Response, TransportError>>;

    fn send(&self, _request: Request) -> Self::Future<'_> {
        self.sdk_calls.set(self.sdk_calls.get() + 1);
        self.host_attempts.set(self.host_attempts.get() + 1);
        let first = self
            .outcomes
            .borrow_mut()
            .pop_front()
            .expect("first host attempt");
        if matches!(
            first,
            Err(ref error) if error.kind() == TransportErrorKind::Network
        ) {
            self.host_attempts.set(self.host_attempts.get() + 1);
            return ready(self.outcomes.borrow_mut().pop_front().expect("host retry"));
        }
        ready(first)
    }
}

impl Transport for WasmTransport {
    type Future<'a> = Ready<Result<Response, TransportError>>;

    fn send(&self, request: Request) -> Self::Future<'_> {
        self.requests.borrow_mut().push(request);
        ready(
            self.responses
                .borrow_mut()
                .pop_front()
                .expect("deterministic Wasm response"),
        )
    }
}

struct WasmEncryptor;

impl ChallengeEncryptor for WasmEncryptor {
    fn encrypt(
        &mut self,
        _public_key_pem: &str,
        _challenge: &SecretString,
        _password: &SecretString,
    ) -> Result<SecretString, ProtocolError> {
        Ok(SecretString::new("wasm-encrypted"))
    }
}

struct WasmClock;

impl Clock for WasmClock {
    fn now_epoch_seconds(&self) -> u64 {
        1_000
    }
}

fn response(status: u16, value: serde_json::Value) -> Response {
    Response {
        status,
        body: SecretBytes::new(serde_json::to_vec(&value).expect("fixture JSON")),
    }
}

fn transport(
    responses: impl IntoIterator<Item = Result<Response, TransportError>>,
) -> WasmTransport {
    WasmTransport {
        responses: RefCell::new(responses.into_iter().collect()),
        requests: RefCell::new(Vec::new()),
    }
}

fn config() -> ClientConfig {
    ClientConfig::builder(
        "https://ws-api.test.isecure.fi/v2",
        "wasm@example.test",
        Mode::Data,
    )
    .phone("+358400000000")
    .company("Synthetic Company")
    .name("Synthetic User")
    .password(SecretString::new("Synthetic-password-123!"))
    .public_key_pem("host-owned fixture")
    .bank("simulator")
    .api_key(SecretString::new("wasm-api-key"))
    .build()
    .expect("valid configuration")
}

fn main() {
    let success_transport = transport([
        Ok(response(
            200,
            serde_json::json!({
                "ResponseCode":"00",
                "ResponseText":"OK",
                "Challenge":"bytes|1475429754114|fixture"
            }),
        )),
        Ok(response(
            200,
            serde_json::json!({
                "ResponseCode":"00",
                "ResponseText":"Login OK",
                "ApiKey":"wasm-api-key",
                "IdToken":"wasm-id-token",
                "ExpiresIn":"300"
            }),
        )),
        Ok(response(
            200,
            serde_json::json!({
                "ResponseCode":"00",
                "ResponseText":"Files",
                "FileDescriptors":[]
            }),
        )),
    ]);
    let mut client = Client::with_clock(config(), success_transport, WasmEncryptor, WasmClock);
    assert!(matches!(
        block_on(client.login()).expect("Wasm login"),
        AuthState::Authenticated { .. }
    ));
    let files = block_on(client.list_files(&ListFilesQuery::default())).expect("Wasm list files");
    assert!(files.file_descriptors.is_empty());
    let (completed_transport, _, _) = client.into_adapters();
    let requests = completed_transport.requests.into_inner();
    assert_eq!(requests.len(), 3);
    assert!(
        requests[2]
            .headers
            .iter()
            .any(|header| header.name == "Authorization")
    );
    assert!(!format!("{:?}", requests[2]).contains("wasm-id-token"));

    let cases = [
        (
            Ok(response(
                200,
                serde_json::json!({"ResponseCode":"99","ResponseText":"logical"}),
            )),
            "logical",
        ),
        (
            Ok(response(
                503,
                serde_json::json!({"ResponseCode":"91","ResponseText":"unavailable"}),
            )),
            "http",
        ),
        (
            Ok(Response {
                status: 200,
                body: SecretBytes::new(b"not-json".to_vec()),
            }),
            "malformed",
        ),
        (
            Err(TransportError::new(TransportErrorKind::Aborted, None)),
            "aborted",
        ),
        (
            Err(TransportError::new(TransportErrorKind::Timeout, None)),
            "timeout",
        ),
    ];
    for (result, expected) in cases {
        let client = Client::with_clock(config(), transport([result]), WasmEncryptor, WasmClock);
        let error = block_on(client.init_password_reset()).expect_err("Wasm failure case");
        let observed = match error {
            Error::Logical(_) => "logical",
            Error::Http(_) => "http",
            Error::Protocol(ProtocolError::MalformedResponse) => "malformed",
            Error::Transport(ref value) if value.kind() == TransportErrorKind::Aborted => "aborted",
            Error::Transport(ref value) if value.kind() == TransportErrorKind::Timeout => "timeout",
            _ => panic!("unexpected Wasm failure class"),
        };
        assert_eq!(observed, expected);
    }

    let retrying = RetryingWasmTransport {
        outcomes: RefCell::new(VecDeque::from([
            Err(TransportError::new(TransportErrorKind::Network, None)),
            Ok(response(
                200,
                serde_json::json!({"ResponseCode":"00","ResponseText":"retried by host"}),
            )),
        ])),
        sdk_calls: Cell::new(0),
        host_attempts: Cell::new(0),
    };
    let retry_client = Client::with_clock(config(), retrying, WasmEncryptor, WasmClock);
    block_on(retry_client.init_password_reset()).expect("host-owned Wasm retry");
    let (retrying, _, _) = retry_client.into_adapters();
    assert_eq!(retrying.sdk_calls.get(), 1);
    assert_eq!(retrying.host_attempts.get(), 2);
}
