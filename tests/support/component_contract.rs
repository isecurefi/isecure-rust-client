use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    future::{Ready, ready},
};

use futures_executor::block_on;
use isecure_rust_client::{
    AuthState, BrokerError, BrokeredOperation, BusinessFacade, ChallengeEncryptor, Client,
    ClientConfig, Clock, Error, ListFilesQuery, Mode, ProtectedBinding, ProtectedValueKind,
    ProtocolError, Request, RequestFieldPlacement, Response, RsaChallengeEncryptor, SecretBytes,
    SecretString, SecurityFacade, SecurityPrepareInput, TransientSecret, Transport, TransportError,
    TransportErrorKind, UploadFileRequest,
};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContractCases {
    version: u32,
    cases: Vec<ContractCase>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContractCase {
    id: String,
    outcome: ContractOutcome,
    expected: ExpectedOutcome,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum ContractOutcome {
    Http { status: u16, body: String },
    Aborted,
    Timeout,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum ExpectedOutcome {
    Logical,
    Http,
    Malformed,
    Aborted,
    Timeout,
}

struct ContractTransport {
    responses: RefCell<VecDeque<Result<Response, TransportError>>>,
    requests: RefCell<Vec<Request>>,
}

struct RetryingContractTransport {
    outcomes: RefCell<VecDeque<Result<Response, TransportError>>>,
    sdk_calls: Cell<u8>,
    host_attempts: Cell<u8>,
}

impl Transport for RetryingContractTransport {
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

impl Transport for ContractTransport {
    type Future<'a> = Ready<Result<Response, TransportError>>;

    fn send(&self, request: Request) -> Self::Future<'_> {
        self.requests.borrow_mut().push(request);
        ready(
            self.responses
                .borrow_mut()
                .pop_front()
                .expect("deterministic contract response"),
        )
    }
}

struct ContractEncryptor;

impl ChallengeEncryptor for ContractEncryptor {
    fn encrypt(
        &mut self,
        _public_key_pem: &str,
        _challenge: &SecretString,
        _password: &SecretString,
    ) -> Result<SecretString, ProtocolError> {
        Ok(SecretString::new("contract-encrypted"))
    }
}

struct ContractTransientSecret(Option<Vec<u8>>);

impl TransientSecret for ContractTransientSecret {
    fn read_once(&mut self) -> Result<SecretBytes, BrokerError> {
        self.0
            .take()
            .map(SecretBytes::new)
            .ok_or(BrokerError::AlreadyUsed)
    }
}

struct ContractClock;

impl Clock for ContractClock {
    fn now_epoch_seconds(&self) -> u64 {
        1_000
    }
}

fn response(status: u16, body: impl Into<Vec<u8>>) -> Response {
    Response {
        status,
        body: SecretBytes::new(body.into()),
    }
}

fn json_response(status: u16, value: serde_json::Value) -> Response {
    response(status, serde_json::to_vec(&value).expect("fixture JSON"))
}

fn transport(
    responses: impl IntoIterator<Item = Result<Response, TransportError>>,
) -> ContractTransport {
    ContractTransport {
        responses: RefCell::new(responses.into_iter().collect()),
        requests: RefCell::new(Vec::new()),
    }
}

fn config() -> ClientConfig {
    ClientConfig::builder(
        "https://ws-api.test.isecure.fi/v2",
        "contract@example.test",
        Mode::Data,
    )
    .phone("+358400000000")
    .company("Synthetic Company")
    .name("Synthetic User")
    .password(SecretString::new("Synthetic-password-123!"))
    .public_key_pem("host-owned fixture")
    .bank("simulator")
    .api_key(SecretString::new("contract-api-key"))
    .build()
    .expect("valid configuration")
}

fn outcome(value: ContractOutcome) -> Result<Response, TransportError> {
    match value {
        ContractOutcome::Http { status, body } => Ok(response(status, body.into_bytes())),
        ContractOutcome::Aborted => Err(TransportError::new(TransportErrorKind::Aborted, None)),
        ContractOutcome::Timeout => Err(TransportError::new(TransportErrorKind::Timeout, None)),
    }
}

/// Runs the exact same contract source natively and as a `wasm32-wasip2` command.
pub fn run() {
    let mut rsa = RsaChallengeEncryptor::new(ChaCha20Rng::from_seed([9; 32]));
    let ciphertext = rsa
        .encrypt(
            include_str!("../../contracts/synthetic-rsa-public.pem"),
            &SecretString::new("challenge-bytes|1475429754114|fixture"),
            &SecretString::new("Synthetic-password-123!"),
        )
        .expect("Wasm-compatible RSA challenge encryption");
    assert_eq!(ciphertext.expose_secret().len(), 344);

    // The same command-component harness executes the brokered facade. This
    // proves Wasm codegen and import closure; final generated WIT adaptation is
    // owned by the platform Component-authoring task.
    let opaque_password = 1_u8;
    let plan = BusinessFacade::default()
        .plan(
            BrokeredOperation::Login,
            &[ProtectedBinding::from_host(
                ProtectedValueKind::Password,
                &opaque_password,
            )],
        )
        .expect("brokered business plan");
    assert_eq!(plan.operation().operation_id(), "Login");
    let mut security = SecurityFacade::new(
        "host-owned fixture",
        ContractEncryptor,
        isecure_rust_client::ResourceLimits::default(),
    )
    .expect("brokered security facade");
    let mut password = [ContractTransientSecret(Some(
        b"Synthetic-password-123!".to_vec(),
    ))];
    let mutations = security
        .prepare(
            BrokeredOperation::Login,
            SecurityPrepareInput::Challenge {
                challenge: "bytes|1475429754114|fixture",
            },
            &mut password,
        )
        .expect("brokered security plan");
    assert_eq!(mutations.len(), 2);
    assert!(mutations.iter().all(|value| {
        value.placement() == RequestFieldPlacement::Body
            && matches!(value.field_id(), "ChResp" | "Encrypted")
    }));

    let success_transport = transport([
        Ok(json_response(
            200,
            serde_json::json!({
                "ResponseCode":"00",
                "ResponseText":"OK",
                "Challenge":"bytes|1475429754114|fixture"
            }),
        )),
        Ok(json_response(
            200,
            serde_json::json!({
                "ResponseCode":"00",
                "ResponseText":"Login OK",
                "ApiKey":"contract-api-key",
                "IdToken":"contract-id-token",
                "ExpiresIn":"300"
            }),
        )),
        Ok(json_response(
            200,
            serde_json::json!({
                "ResponseCode":"00",
                "ResponseText":"Files",
                "FileDescriptors":[]
            }),
        )),
        Ok(json_response(
            201,
            serde_json::json!({"ResponseCode":"00","ResponseText":"Uploaded"}),
        )),
        Ok(json_response(
            200,
            serde_json::json!({
                "ResponseCode":"00",
                "ResponseText":"Downloaded",
                "Content":"ZmlsZQ=="
            }),
        )),
    ]);
    let mut client = Client::with_clock(
        config(),
        success_transport,
        ContractEncryptor,
        ContractClock,
    );
    assert!(matches!(
        block_on(client.login()).expect("contract login"),
        AuthState::Authenticated { .. }
    ));
    let files =
        block_on(client.list_files(&ListFilesQuery::default())).expect("contract list files");
    assert!(files.file_descriptors.is_empty());
    block_on(client.upload_file(&UploadFileRequest {
        file_contents: SecretBytes::new(b"file".to_vec()),
        file_name: "synthetic.xml".to_owned(),
        file_type: "pain.001".to_owned(),
        signature: SecretString::new("synthetic-signature"),
    }))
    .expect("contract upload");
    let download = block_on(client.download_file("camt.053", "synthetic-reference"))
        .expect("contract download");
    assert_eq!(download.content.expose_secret(), b"file");
    let (completed_transport, _, _) = client.into_adapters();
    let requests = completed_transport.requests.into_inner();
    assert_eq!(requests.len(), 5);
    assert!(
        requests[2]
            .headers
            .iter()
            .any(|header| header.name == "Authorization")
    );
    assert!(!format!("{:?}", requests[2]).contains("contract-id-token"));
    let upload: serde_json::Value = serde_json::from_slice(
        requests[3]
            .body
            .as_ref()
            .expect("upload body")
            .expose_secret(),
    )
    .expect("upload JSON");
    assert_eq!(upload["FileContents"], "ZmlsZQ==");

    let cases: ContractCases = serde_json::from_str(include_str!(
        "../../contracts/component-contract-cases.json"
    ))
    .expect("valid component contract cases");
    assert_eq!(cases.version, 1);
    for case in cases.cases {
        let client = Client::with_clock(
            config(),
            transport([outcome(case.outcome)]),
            ContractEncryptor,
            ContractClock,
        );
        let error = block_on(client.init_password_reset()).expect_err(&case.id);
        let observed = match error {
            Error::Logical(_) => ExpectedOutcome::Logical,
            Error::Http(_) => ExpectedOutcome::Http,
            Error::Protocol(ProtocolError::MalformedResponse) => ExpectedOutcome::Malformed,
            Error::Transport(ref value) if value.kind() == TransportErrorKind::Aborted => {
                ExpectedOutcome::Aborted
            }
            Error::Transport(ref value) if value.kind() == TransportErrorKind::Timeout => {
                ExpectedOutcome::Timeout
            }
            _ => panic!("unexpected contract failure class for {}", case.id),
        };
        assert_eq!(observed, case.expected, "case {}", case.id);
    }

    let retrying = RetryingContractTransport {
        outcomes: RefCell::new(VecDeque::from([
            Err(TransportError::new(TransportErrorKind::Network, None)),
            Ok(json_response(
                200,
                serde_json::json!({"ResponseCode":"00","ResponseText":"retried by host"}),
            )),
        ])),
        sdk_calls: Cell::new(0),
        host_attempts: Cell::new(0),
    };
    let retry_client = Client::with_clock(config(), retrying, ContractEncryptor, ContractClock);
    block_on(retry_client.init_password_reset()).expect("host-owned contract retry");
    let (retrying, _, _) = retry_client.into_adapters();
    assert_eq!(retrying.sdk_calls.get(), 1);
    assert_eq!(retrying.host_attempts.get(), 2);
}
