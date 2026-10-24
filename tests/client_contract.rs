use std::{
    cell::RefCell,
    collections::VecDeque,
    future::{Ready, ready},
    rc::Rc,
};

use futures_executor::block_on;
use isecure_rust_client::{
    ApiResponse, AuthState, ChallengeEncryptor, Client, ClientConfig, Clock, Error, HeaderValue,
    HttpMethod, LimitKind, ListFilesQuery, MfaMethod, Mode, ProtocolError, Request, ResourceLimits,
    Response, SecretBytes, SecretString, Transport, TransportError, TransportErrorKind,
    UploadFileRequest,
};
use serde_json::{Value, json};

const CHALLENGE: &str = "challenge-bytes|1475429754114|4017bda8-0a15-4154-a8b7-88069b05cb4e";

#[derive(Clone, Default)]
struct FakeTransport {
    state: Rc<RefCell<FakeState>>,
}

#[derive(Default)]
struct FakeState {
    requests: Vec<Request>,
    responses: VecDeque<Result<Response, TransportError>>,
}

impl FakeTransport {
    fn json(&self, status: u16, body: Value) {
        self.state.borrow_mut().responses.push_back(Ok(Response {
            status,
            body: SecretBytes::new(serde_json::to_vec(&body).expect("fixture JSON")),
        }));
    }

    fn failure(&self, kind: TransportErrorKind) {
        self.state
            .borrow_mut()
            .responses
            .push_back(Err(TransportError::new(kind, Some("fixture".to_owned()))));
    }

    fn request_json(&self, index: usize) -> Value {
        let state = self.state.borrow();
        let body = state.requests[index].body.as_ref().expect("request body");
        serde_json::from_slice(body.expose_secret()).expect("request JSON")
    }
}

impl Transport for FakeTransport {
    type Future<'a> = Ready<Result<Response, TransportError>>;

    fn send(&self, request: Request) -> Self::Future<'_> {
        let mut state = self.state.borrow_mut();
        state.requests.push(request);
        ready(state.responses.pop_front().expect("queued response"))
    }
}

#[derive(Default)]
struct FixtureEncryptor;

impl ChallengeEncryptor for FixtureEncryptor {
    fn encrypt(
        &mut self,
        _public_key_pem: &str,
        challenge: &SecretString,
        password: &SecretString,
    ) -> Result<SecretString, ProtocolError> {
        assert_eq!(challenge.expose_secret(), CHALLENGE);
        assert_eq!(password.expose_secret(), "Example-password-123!");
        Ok(SecretString::new("encrypted-fixture"))
    }
}

#[derive(Clone, Copy)]
struct FixtureClock(u64);

impl Clock for FixtureClock {
    fn now_epoch_seconds(&self) -> u64 {
        self.0
    }
}

fn config(mode: Mode, api_key: bool) -> ClientConfig {
    config_with_limits(mode, api_key, ResourceLimits::default())
}

fn config_with_limits(mode: Mode, api_key: bool, limits: ResourceLimits) -> ClientConfig {
    let builder = ClientConfig::builder(
        "https://ws-api.test.isecure.fi/v2",
        "user@example.test",
        mode,
    )
    .phone("+358401234567")
    .company("Example Company")
    .name("Example User")
    .password(SecretString::new("Example-password-123!"))
    .public_key_pem("fixture public key")
    .bank("simulator")
    .resource_limits(limits);
    let builder = if api_key {
        builder.api_key(SecretString::new("existing-api-key"))
    } else {
        builder
    };
    builder.build().expect("valid fixture config")
}

fn challenge() -> Value {
    json!({"ResponseCode":"00","ResponseText":"OK","Challenge":CHALLENGE})
}

fn client(
    mode: Mode,
    api_key: bool,
) -> (
    Client<FakeTransport, FixtureEncryptor, FixtureClock>,
    FakeTransport,
) {
    let transport = FakeTransport::default();
    (
        Client::with_clock(
            config(mode, api_key),
            transport.clone(),
            FixtureEncryptor,
            FixtureClock(1_000),
        ),
        transport,
    )
}

fn client_with_limits(
    mode: Mode,
    api_key: bool,
    limits: ResourceLimits,
) -> (
    Client<FakeTransport, FixtureEncryptor, FixtureClock>,
    FakeTransport,
) {
    let transport = FakeTransport::default();
    (
        Client::with_clock(
            config_with_limits(mode, api_key, limits),
            transport.clone(),
            FixtureEncryptor,
            FixtureClock(1_000),
        ),
        transport,
    )
}

fn authenticate(
    client: &mut Client<FakeTransport, FixtureEncryptor, FixtureClock>,
    transport: &FakeTransport,
) {
    transport.json(200, challenge());
    transport.json(
        200,
        json!({
            "ResponseCode":"00",
            "ResponseText":"Login OK",
            "ApiKey":"existing-api-key",
            "IdToken":"id-token",
            "ExpiresIn":"3600"
        }),
    );
    assert!(matches!(
        block_on(client.login()).expect("login"),
        AuthState::Authenticated { .. }
    ));
}

#[test]
fn registration_matches_typescript_request_and_custodies_api_key() {
    let (mut client, transport) = client(Mode::Admin, false);
    transport.json(200, challenge());
    transport.json(
        201,
        json!({"ResponseCode":"00","ResponseText":"Created","ApiKey":"registered-api-key"}),
    );

    let result = block_on(client.register()).expect("registration");

    assert!(result.api_key_available);
    assert_eq!(
        client.api_key().expect("stored API key").expose_secret(),
        "registered-api-key"
    );
    let state = transport.state.borrow();
    assert_eq!(
        state.requests[0].url,
        "https://ws-api.test.isecure.fi/v2/account/user%40example.test/admin"
    );
    drop(state);
    assert_eq!(
        transport.request_json(1),
        json!({
            "ApiKey":"0",
            "ChResp":CHALLENGE,
            "Company":"Example Company",
            "Encrypted":"encrypted-fixture",
            "Name":"Example User",
            "Phone":"+358401234567"
        })
    );
    assert!(
        !format!("{client_api_key:?}", client_api_key = client.api_key())
            .contains("registered-api-key")
    );
}

#[test]
fn mfa_authentication_carries_exact_state_and_secret_headers() {
    let (mut client, transport) = client(Mode::Admin, true);
    transport.json(200, challenge());
    transport.json(
        200,
        json!({
            "ResponseCode":"00",
            "ResponseText":"Give SMS code",
            "Session":"session-token",
            "ChallengeName":"SMS_MFA"
        }),
    );
    assert!(matches!(
        block_on(client.login()).expect("login"),
        AuthState::NeedsMfa {
            method: MfaMethod::Sms,
            ..
        }
    ));

    transport.json(
        200,
        json!({
            "ResponseCode":"00",
            "ResponseText":"Login OK",
            "ApiKey":"existing-api-key",
            "IdToken":"id-token",
            "ExpiresIn":"3600"
        }),
    );
    assert!(matches!(
        block_on(client.submit_mfa_code(&SecretString::new("123456"), false)).expect("MFA"),
        AuthState::Authenticated { .. }
    ));
    assert_eq!(
        transport.request_json(2),
        json!({"ChallengeName":"SMS_MFA","Code":"123456","Session":"session-token"})
    );
    assert_eq!(
        client
            .session()
            .expect("session")
            .expires_at_epoch_seconds(),
        Some(4_600)
    );
    assert!(!client.is_session_expired());

    transport.json(
        200,
        json!({"ResponseCode":"00","ResponseText":"keys","PgpKeys":[]}),
    );
    block_on(client.list_keys()).expect("list keys");
    let state = transport.state.borrow();
    let headers = &state.requests[3].headers;
    assert!(headers.iter().any(|header| {
        header.name == "Authorization"
            && header.value.is_secret()
            && header.value.as_str() == "id-token"
    }));
    assert!(headers.iter().any(|header| {
        header.name == "x-api-key"
            && matches!(header.value, HeaderValue::Secret(_))
            && header.value.as_str() == "existing-api-key"
    }));
    let request_debug = format!("{:?}", state.requests[3]);
    assert!(!request_debug.contains("id-token"));
    assert!(!request_debug.contains("user%40example.test"));
    assert!(request_debug.contains("[REDACTED]"));
}

#[test]
fn mfa_selection_and_verification_states_match_typescript_precedence() {
    let (mut client, transport) = client(Mode::Admin, true);
    transport.json(200, challenge());
    transport.json(
        200,
        json!({
            "ResponseCode":"00",
            "ResponseText":"Choose factor",
            "ChallengeName":"SELECT_MFA_TYPE",
            "Session":"select-session",
            "MfaOptions":["SMS_MFA","SOFTWARE_TOKEN_MFA"],
            "SmsDestination":"+*****5507"
        }),
    );
    let state = block_on(client.login()).expect("login");
    assert!(matches!(
        state,
        AuthState::NeedsMfaSelection { ref methods, .. }
            if methods == &[MfaMethod::Sms, MfaMethod::Totp]
    ));

    transport.json(
        200,
        json!({
            "ResponseCode":"00",
            "ResponseText":"Give authenticator code",
            "ChallengeName":"SOFTWARE_TOKEN_MFA",
            "Session":"totp-session"
        }),
    );
    assert!(matches!(
        block_on(client.select_mfa_type(MfaMethod::Totp)).expect("select TOTP"),
        AuthState::NeedsMfa {
            method: MfaMethod::Totp,
            ..
        }
    ));
    assert_eq!(
        transport.request_json(2),
        json!({"MfaType":"SOFTWARE_TOKEN_MFA","Session":"select-session"})
    );
}

#[test]
fn authentication_rejects_api_key_domain_substitution() {
    let (mut client, transport) = client(Mode::Data, true);
    transport.json(200, challenge());
    transport.json(
        200,
        json!({
            "ResponseCode":"00",
            "ResponseText":"Login OK",
            "ApiKey":"substituted-api-key",
            "IdToken":"id-token",
            "ExpiresIn":3600
        }),
    );
    assert!(matches!(
        block_on(client.login()),
        Err(Error::Protocol(ProtocolError::ApiKeyMismatch))
    ));
    assert!(!client.is_authenticated());
}

#[test]
fn reauthentication_does_not_leave_the_previous_session_usable() {
    let (mut client, transport) = client(Mode::Admin, true);
    authenticate(&mut client, &transport);
    assert!(client.is_authenticated());

    transport.json(200, challenge());
    transport.json(
        200,
        json!({
            "ResponseCode":"00",
            "ResponseText":"Give SMS code",
            "Session":"new-session",
            "ChallengeName":"SMS_MFA"
        }),
    );
    assert!(matches!(
        block_on(client.login()).expect("reauthentication"),
        AuthState::NeedsMfa { .. }
    ));
    assert!(!client.is_authenticated());
    assert!(matches!(
        block_on(client.list_keys()),
        Err(Error::Protocol(ProtocolError::InvalidAuthState))
    ));
}

#[test]
fn provider_operations_use_exact_methods_paths_and_shapes() {
    let (mut client, transport) = client(Mode::Admin, true);
    authenticate(&mut client, &transport);

    let replies = [
        (201, json!({"ResponseCode":"00","ResponseText":"uploaded"})),
        (
            200,
            json!({"ResponseCode":"00","ResponseText":"keys","PgpKeys":[]}),
        ),
        (200, json!({"ResponseCode":"00","ResponseText":"deleted"})),
        (201, json!({"ResponseCode":"00","ResponseText":"uploaded"})),
        (
            200,
            json!({"ResponseCode":"00","ResponseText":"files","FileDescriptors":[]}),
        ),
        (
            200,
            json!({"ResponseCode":"00","ResponseText":"file","Content":"ZmlsZQ=="}),
        ),
        (200, json!({"ResponseCode":"00","ResponseText":"deleted"})),
        (
            200,
            json!({"ResponseCode":"00","ResponseText":"certs","Certs":[],"Connections":[]}),
        ),
        (
            200,
            json!({"ResponseCode":"00","ResponseText":"configured"}),
        ),
        (
            201,
            json!({"ResponseCode":"00","ResponseText":"shared","SharedTo":[],"SharedFrom":[]}),
        ),
        (
            200,
            json!({"ResponseCode":"00","ResponseText":"unshared","SharedTo":[],"SharedFrom":[]}),
        ),
        (
            200,
            json!({"ResponseCode":"00","ResponseText":"exported","CertsAndKeys":[]}),
        ),
        (201, json!({"ResponseCode":"00","ResponseText":"imported"})),
        (201, json!({"ResponseCode":"00","ResponseText":"enrolled"})),
        (
            200,
            json!({"ResponseCode":"00","ResponseText":"accounts","Accounts":[]}),
        ),
    ];
    for (status, body) in replies {
        transport.json(status, body);
    }

    block_on(client.upload_pgp_key("PUBLIC KEY", isecure_rust_client::PgpKeyPurpose::Authorize))
        .expect("upload key");
    block_on(client.list_keys()).expect("list keys");
    block_on(client.delete_key("1234ABCD")).expect("delete key");
    block_on(client.upload_file(&UploadFileRequest {
        file_contents: SecretBytes::new(b"file".to_vec()),
        file_name: "payment.xml".to_owned(),
        file_type: "pain.001".to_owned(),
        signature: SecretString::new("SIGNATURE"),
    }))
    .expect("upload file");
    block_on(client.list_files(&ListFilesQuery {
        file_type: Some("camt.053".to_owned()),
        status: Some("NEW".to_owned()),
    }))
    .expect("list files");
    let downloaded = block_on(client.download_file("camt.053", "file/ref")).expect("download file");
    assert_eq!(downloaded.content.expose_secret(), b"file");
    block_on(client.delete_file("camt.053", "file/ref")).expect("delete file");
    block_on(client.list_certificates()).expect("list certificates");
    block_on(client.configure_certificates(isecure_rust_client::CertificateExport::Allowed))
        .expect("configure certificates");
    block_on(client.share_certificates("other@example.test")).expect("share");
    block_on(client.unshare_certificates("other@example.test")).expect("unshare");
    block_on(client.export_certificate("1234ABCD")).expect("export");
    block_on(
        client.import_certificate(&isecure_rust_client::ImportCertificateRequest {
            company: "COMPANY".to_owned(),
            ws_user_id: "USER".to_owned(),
            private_key: SecretString::new("PRIVATE KEY"),
            certificate: "CERTIFICATE".to_owned(),
            encrypted_private_key: None,
            encrypted_certificate: None,
        }),
    )
    .expect("import");
    block_on(
        client.enroll_certificate(&isecure_rust_client::EnrollCertificateRequest {
            code: SecretString::new("CODE"),
            company: "COMPANY".to_owned(),
            ws_user_id: "USER".to_owned(),
        }),
    )
    .expect("enroll");
    block_on(client.list_accounts()).expect("accounts");

    let state = transport.state.borrow();
    let requests = &state.requests[2..];
    assert_eq!(requests[0].method, HttpMethod::Put);
    assert!(requests[0].url.ends_with("/pgp"));
    assert_eq!(requests[3].method, HttpMethod::Put);
    assert!(
        requests[4]
            .url
            .ends_with("/files/simulator?FileType=camt.053&Status=NEW")
    );
    assert!(
        requests[5]
            .url
            .ends_with("/files/simulator/camt.053/file%2Fref")
    );
    assert!(
        requests[9]
            .url
            .ends_with("/certs/shared/other%40example.test")
    );
    assert!(
        requests[11]
            .url
            .ends_with("/certs/simulator?PgpKeyId=1234ABCD")
    );
    assert_eq!(
        serde_json::from_slice::<Value>(
            requests[3]
                .body
                .as_ref()
                .expect("upload body")
                .expose_secret()
        )
        .expect("upload JSON"),
        json!({
            "FileContents":"ZmlsZQ==",
            "FileName":"payment.xml",
            "FileType":"pain.001",
            "Signature":"SIGNATURE"
        })
    );
}

#[test]
fn resource_limits_accept_the_boundary_and_reject_maximum_plus_one() {
    let limits = ResourceLimits::new(8_192, 4_096, 4_096, 4, 9, 1).expect("limits");
    let (mut client, transport) = client_with_limits(Mode::Data, true, limits);
    authenticate(&mut client, &transport);

    transport.json(201, json!({"ResponseCode":"00","ResponseText":"uploaded"}));
    block_on(client.upload_file(&UploadFileRequest {
        file_contents: SecretBytes::new(b"file".to_vec()),
        file_name: "a".to_owned(),
        file_type: "b".to_owned(),
        signature: SecretString::new("signature"),
    }))
    .expect("exact limits");

    let requests_before = transport.state.borrow().requests.len();
    let error = block_on(client.upload_file(&UploadFileRequest {
        file_contents: SecretBytes::new(b"file!".to_vec()),
        file_name: "a".to_owned(),
        file_type: "b".to_owned(),
        signature: SecretString::new("signature"),
    }))
    .expect_err("oversized file");
    assert!(matches!(error, Error::Limit(value) if value.kind() == LimitKind::FileContent));
    assert_eq!(transport.state.borrow().requests.len(), requests_before);

    let error = block_on(client.upload_file(&UploadFileRequest {
        file_contents: SecretBytes::new(b"file".to_vec()),
        file_name: "a".to_owned(),
        file_type: "b".to_owned(),
        signature: SecretString::new("signature!"),
    }))
    .expect_err("oversized signature");
    assert!(matches!(error, Error::Limit(value) if value.kind() == LimitKind::Signature));
    assert_eq!(transport.state.borrow().requests.len(), requests_before);
}

#[test]
fn url_and_request_body_limits_cover_exact_boundary_and_maximum_plus_one() {
    let build_with_url_limit = |maximum| {
        ClientConfig::builder(
            "https://ws-api.test.isecure.fi/v2",
            "user@example.test",
            Mode::Admin,
        )
        .phone("+358401234567")
        .company("Example Company")
        .name("Example User")
        .password(SecretString::new("Example-password-123!"))
        .public_key_pem("fixture public key")
        .bank("simulator")
        .resource_limits(
            ResourceLimits::new(maximum, 4_096, 4_096, 1_024, 1_024, 10).expect("limits"),
        )
        .build()
    };
    build_with_url_limit(83).expect("exact longest configured URL");
    assert!(matches!(
        build_with_url_limit(82),
        Err(Error::Limit(value)) if value.kind() == LimitKind::Url
    ));

    let upload = || UploadFileRequest {
        file_contents: SecretBytes::new(vec![0x5a; 128]),
        file_name: "payment.xml".to_owned(),
        file_type: "pain.001".to_owned(),
        signature: SecretString::new("signature"),
    };
    let (mut probe, probe_transport) = client(Mode::Data, true);
    authenticate(&mut probe, &probe_transport);
    probe_transport.json(201, json!({"ResponseCode":"00","ResponseText":"uploaded"}));
    block_on(probe.upload_file(&upload())).expect("probe upload");
    let request_bytes = probe_transport
        .state
        .borrow()
        .requests
        .last()
        .and_then(|request| request.body.as_ref())
        .map(SecretBytes::len)
        .expect("upload body length");

    let exact = ResourceLimits::new(8_192, request_bytes, 4_096, 128, 9, 10).expect("exact limits");
    let (mut exact_client, exact_transport) = client_with_limits(Mode::Data, true, exact);
    authenticate(&mut exact_client, &exact_transport);
    exact_transport.json(201, json!({"ResponseCode":"00","ResponseText":"uploaded"}));
    block_on(exact_client.upload_file(&upload())).expect("exact request-body limit");

    let too_small =
        ResourceLimits::new(8_192, request_bytes - 1, 4_096, 128, 9, 10).expect("small limits");
    let (mut limited_client, limited_transport) = client_with_limits(Mode::Data, true, too_small);
    authenticate(&mut limited_client, &limited_transport);
    let requests_before = limited_transport.state.borrow().requests.len();
    let error = block_on(limited_client.upload_file(&upload())).expect_err("oversized request");
    assert!(matches!(error, Error::Limit(value) if value.kind() == LimitKind::RequestBody));
    assert_eq!(
        limited_transport.state.borrow().requests.len(),
        requests_before
    );
}

#[test]
fn response_and_collection_limits_fail_closed() {
    let exact_body = serde_json::to_vec(&json!({
        "ResponseCode":"00",
        "ResponseText":"OK"
    }))
    .expect("fixture JSON");
    let exact_limits =
        ResourceLimits::new(8_192, 4_096, exact_body.len(), 32, 32, 1).expect("limits");
    let (client, transport) = client_with_limits(Mode::Admin, true, exact_limits);
    transport
        .state
        .borrow_mut()
        .responses
        .push_back(Ok(Response {
            status: 200,
            body: SecretBytes::new(exact_body),
        }));
    block_on(client.init_password_reset()).expect("exact response limit");

    let small_limits = ResourceLimits::new(8_192, 4_096, 8, 32, 32, 1).expect("limits");
    let (client, transport) = client_with_limits(Mode::Admin, true, small_limits);
    transport.json(200, json!({"ResponseCode":"00","ResponseText":"OK"}));
    let error = block_on(client.init_password_reset()).expect_err("oversized response");
    assert!(matches!(error, Error::Limit(value) if value.kind() == LimitKind::ResponseBody));

    let collection_limits = ResourceLimits::new(8_192, 4_096, 4_096, 32, 32, 1).expect("limits");
    let (mut client, transport) = client_with_limits(Mode::Admin, true, collection_limits);
    authenticate(&mut client, &transport);
    transport.json(
        200,
        json!({
            "ResponseCode":"00",
            "ResponseText":"keys",
            "PgpKeys":[
                {"PgpKeyId":"00000001","PgpKeyPurpose":"authorize"},
                {"PgpKeyId":"00000002","PgpKeyPurpose":"authorize"}
            ]
        }),
    );
    let error = block_on(client.list_keys()).expect_err("too many items");
    assert!(matches!(error, Error::Limit(value) if value.kind() == LimitKind::CollectionItems));

    let (mut client, transport) = client_with_limits(Mode::Admin, true, collection_limits);
    transport.json(200, challenge());
    transport.json(
        200,
        json!({
            "ResponseCode":"00",
            "ResponseText":"Login OK",
            "ApiKey":"existing-api-key",
            "IdToken":"id-token",
            "ExpiresIn":"3600",
            "MfaOptions":["SMS_MFA","SOFTWARE_TOKEN_MFA"]
        }),
    );
    let error = block_on(client.login()).expect_err("unexpected oversized MFA collection");
    assert!(matches!(error, Error::Limit(value) if value.kind() == LimitKind::CollectionItems));
    assert!(!client.is_authenticated());
}

#[test]
fn download_decodes_exact_bytes_and_rejects_invalid_or_oversized_base64() {
    let limits = ResourceLimits::new(8_192, 4_096, 4_096, 4, 32, 10).expect("limits");
    let (mut client, transport) = client_with_limits(Mode::Data, true, limits);
    authenticate(&mut client, &transport);
    transport.json(
        200,
        json!({"ResponseCode":"00","ResponseText":"file","Content":"ZmlsZQ=="}),
    );
    assert_eq!(
        block_on(client.download_file("type", "ref"))
            .expect("download")
            .content
            .expose_secret(),
        b"file"
    );

    transport.json(
        200,
        json!({"ResponseCode":"00","ResponseText":"file","Content":"!!!!"}),
    );
    assert!(matches!(
        block_on(client.download_file("type", "ref")),
        Err(Error::Protocol(ProtocolError::MalformedResponse))
    ));

    transport.json(
        200,
        json!({"ResponseCode":"00","ResponseText":"file","Content":"ZmlsZSE="}),
    );
    assert!(matches!(
        block_on(client.download_file("type", "ref")),
        Err(Error::Limit(value)) if value.kind() == LimitKind::FileContent
    ));
}

#[test]
fn errors_are_structured_and_do_not_expose_provider_bodies() {
    let (client, transport) = client(Mode::Admin, true);
    transport.failure(TransportErrorKind::Timeout);
    assert!(matches!(
        block_on(client.init_password_reset()),
        Err(Error::Transport(ref error)) if error.kind() == TransportErrorKind::Timeout
    ));

    transport.json(
        401,
        json!({"ResponseCode":"41","ResponseText":"secret diagnostic","RequestId":"request-1"}),
    );
    let error = block_on(client.init_password_reset()).expect_err("HTTP failure");
    assert!(matches!(error, Error::Http(ref value) if value.status == 401));
    assert!(!error.to_string().contains("secret diagnostic"));

    transport.json(200, json!({"unexpected":true}));
    assert!(matches!(
        block_on(client.init_password_reset()),
        Err(Error::Protocol(ProtocolError::MalformedResponse))
    ));

    transport.json(
        200,
        json!({"ResponseCode":"99","ResponseText":"logical failure"}),
    );
    assert!(matches!(
        block_on(client.init_password_reset()),
        Err(Error::Logical(_))
    ));

    transport.json(
        200,
        json!({"ResponseCode":"00","ResponseText":"OK","Unexpected":"drift"}),
    );
    assert!(matches!(
        block_on(client.init_password_reset()),
        Err(Error::Protocol(ProtocolError::MalformedResponse))
    ));
}

#[test]
fn transport_failures_are_typed_and_retries_are_explicit() {
    for kind in [
        TransportErrorKind::Aborted,
        TransportErrorKind::Timeout,
        TransportErrorKind::Network,
        TransportErrorKind::Unavailable,
        TransportErrorKind::OutcomeIndeterminate,
    ] {
        let (client, transport) = client(Mode::Data, true);
        transport.failure(kind);
        let error = block_on(client.init_password_reset()).expect_err("transport failure");
        assert!(matches!(error, Error::Transport(ref value) if value.kind() == kind));
        assert_eq!(transport.state.borrow().requests.len(), 1);
    }

    let (client, transport) = client(Mode::Data, true);
    transport.failure(TransportErrorKind::OutcomeIndeterminate);
    transport.json(
        200,
        json!({"ResponseCode":"00","ResponseText":"explicit retry"}),
    );
    assert!(matches!(
        block_on(client.init_password_reset()),
        Err(Error::Transport(ref value))
            if value.kind() == TransportErrorKind::OutcomeIndeterminate
    ));
    assert_eq!(transport.state.borrow().requests.len(), 1);
    block_on(client.init_password_reset()).expect("caller-authorized retry");
    assert_eq!(transport.state.borrow().requests.len(), 2);
}

#[test]
fn authenticated_operations_refuse_missing_or_expired_sessions() {
    let (client, transport) = client(Mode::Data, true);
    assert!(matches!(
        block_on(client.list_files(&ListFilesQuery::default())),
        Err(Error::Protocol(ProtocolError::InvalidAuthState))
    ));
    assert!(transport.state.borrow().requests.is_empty());
}

#[test]
fn only_logout_may_use_an_expired_session() {
    let (mut client, transport) = client(Mode::Data, true);
    transport.json(200, challenge());
    transport.json(
        200,
        json!({
            "ResponseCode":"00",
            "ResponseText":"Login OK",
            "IdToken":"id-token",
            "ExpiresIn":"0"
        }),
    );
    assert!(matches!(
        block_on(client.login()).expect("login"),
        AuthState::Authenticated { .. }
    ));
    assert!(client.is_session_expired());
    assert!(matches!(
        block_on(client.delete_file("camt.053", "reference")),
        Err(Error::Protocol(ProtocolError::SessionExpired))
    ));
    assert_eq!(transport.state.borrow().requests.len(), 2);

    transport.json(
        200,
        json!({"ResponseCode":"00","ResponseText":"Logged out"}),
    );
    block_on(client.logout()).expect("expired logout");
    assert!(!client.is_authenticated());
    assert_eq!(transport.state.borrow().requests.len(), 3);
}

#[test]
fn response_models_preserve_exact_lexical_values() {
    let response: ApiResponse = serde_json::from_value(json!({
        "ResponseCode":"00",
        "ResponseText":"OK"
    }))
    .expect("response");
    assert_eq!(response.response_code, "00");
}

#[test]
fn login_accepts_existing_account_metadata() {
    let (mut client, transport) = client(Mode::Data, false);
    transport.json(200, challenge());
    transport.json(
        200,
        json!({"ResponseCode":"00","ResponseText":"Login OK",
        "IdToken":"synthetic-id","ApiKey":"synthetic-key","ExpiresIn":3600,
        "Account":{"Type":"integrator","Features":[],"Entitlements":[]}}),
    );
    assert!(matches!(
        block_on(client.login()),
        Ok(AuthState::Authenticated { .. })
    ));
}

fn login_with_account(account: Value) -> Value {
    json!({"ResponseCode":"00","ResponseText":"Login OK",
        "IdToken":"synthetic-id","ApiKey":"synthetic-key","ExpiresIn":3600,"Account":account})
}

#[test]
fn account_metadata_preserves_values_and_entitlement_absence() {
    for kind in ["operator", "integrator", "customer"] {
        for entitlements in [None, Some(json!([])), Some(json!(["synthetic.product"]))] {
            let (mut client, transport) = client(Mode::Data, false);
            let mut account = json!({"Type":kind,"Features":["synthetic.feature"]});
            if let Some(value) = &entitlements {
                account["Entitlements"] = value.clone();
            }
            transport.json(200, challenge());
            transport.json(200, login_with_account(account));
            assert!(matches!(
                block_on(client.login()),
                Ok(AuthState::Authenticated { .. })
            ));
            let session = client.session().expect("completed session");
            let account = session.account().expect("account metadata");
            let expected = match kind {
                "operator" => isecure_rust_client::AccountType::Operator,
                "integrator" => isecure_rust_client::AccountType::Integrator,
                _ => isecure_rust_client::AccountType::Customer,
            };
            assert_eq!(account.account_type, expected);
            assert_eq!(account.features, ["synthetic.feature"]);
            assert_eq!(
                account.entitlements.as_ref().map(|v| json!(v)),
                entitlements
            );
            let debug = format!("{account:?} {session:?}");
            for secret in [
                "synthetic.feature",
                "synthetic.product",
                "synthetic-id",
                "synthetic-key",
            ] {
                assert!(!debug.contains(secret));
            }
        }
    }
}

#[test]
fn older_login_without_account_metadata_still_authenticates() {
    let (mut client, transport) = client(Mode::Data, false);
    let mut response = login_with_account(Value::Null);
    response.as_object_mut().unwrap().remove("Account");
    transport.json(200, challenge());
    transport.json(200, response);
    assert!(matches!(
        block_on(client.login()),
        Ok(AuthState::Authenticated { .. })
    ));
    assert!(client.session().unwrap().account().is_none());
}

#[test]
fn malformed_account_metadata_fails_before_session_creation() {
    for account in [
        json!({"Type":"integrator","Features":[],"Entitlements":[],"Unexpected":true}),
        json!({"Type":"unrecognized","Features":[]}),
        json!({"Type":4,"Features":[]}),
        json!({"Features":[]}),
        json!({"Type":"customer"}),
        json!({"Type":"customer","Features":[false]}),
        json!({"Type":"customer","Features":[],"Entitlements":[{}]}),
        json!({"Type":"customer","Features":[],"Entitlements":"unknown"}),
        json!([]),
    ] {
        let (mut client, transport) = client(Mode::Data, false);
        transport.json(200, challenge());
        transport.json(200, login_with_account(account));
        assert!(matches!(
            block_on(client.login()),
            Err(Error::Protocol(ProtocolError::MalformedResponse))
        ));
        assert!(client.session().is_none());
    }
    let (mut client, transport) = client(Mode::Data, false);
    let mut response = login_with_account(json!({"Type":"customer","Features":[]}));
    response["Unexpected"] = json!(true);
    transport.json(200, challenge());
    transport.json(200, response);
    assert!(matches!(
        block_on(client.login()),
        Err(Error::Protocol(ProtocolError::MalformedResponse))
    ));
    assert!(client.session().is_none());
}

#[test]
fn account_collections_obey_existing_resource_limits() {
    let limits = ResourceLimits::new(8_192, 4_096, 4_096, 32, 32, 1).unwrap();
    for (features, entitlements, accepted) in [
        (json!(["one"]), json!(["one"]), true),
        (json!(["one", "two"]), json!([]), false),
        (json!([]), json!(["one", "two"]), false),
    ] {
        let (mut client, transport) = client_with_limits(Mode::Data, false, limits);
        transport.json(200, challenge());
        transport.json(
            200,
            login_with_account(
                json!({"Type":"customer","Features":features,"Entitlements":entitlements}),
            ),
        );
        let result = block_on(client.login());
        if accepted {
            assert!(matches!(result, Ok(AuthState::Authenticated { .. })));
        } else {
            assert!(
                matches!(result, Err(Error::Limit(value)) if value.kind() == LimitKind::CollectionItems)
            );
            assert!(client.session().is_none());
        }
    }
}

#[test]
fn intermediate_account_metadata_never_creates_or_carries_a_session() {
    let (mut client, transport) = client(Mode::Admin, false);
    transport.json(200, challenge());
    transport.json(
        200,
        json!({"ResponseCode":"00","ResponseText":"MFA required",
        "Session":"synthetic-continuation","ChallengeName":"SOFTWARE_TOKEN_MFA",
        "Account":{"Type":"integrator","Features":[],"Entitlements":[]}}),
    );
    assert!(matches!(
        block_on(client.login()),
        Ok(AuthState::NeedsMfa { .. })
    ));
    assert!(client.session().is_none());
    let mut response = login_with_account(Value::Null);
    response.as_object_mut().unwrap().remove("Account");
    transport.json(200, response);
    assert!(matches!(
        block_on(client.submit_mfa_code(&SecretString::new("123456"), false)),
        Ok(AuthState::Authenticated { .. })
    ));
    assert!(client.session().unwrap().account().is_none());
    transport.json(
        200,
        json!({"ResponseCode":"00","ResponseText":"Sign out successful"}),
    );
    block_on(client.logout()).expect("logout");
    assert!(client.session().is_none());
}

#[test]
fn certificate_listing_accepts_existing_retired_field() {
    let (mut client, transport) = client(Mode::Data, false);
    authenticate(&mut client, &transport);
    transport.json(
        200,
        json!({"ResponseCode":"00","ResponseText":"Certificates",
        "Certs":[],"Connections":[],"Retired":[]}),
    );
    assert!(block_on(client.list_certificates()).is_ok());
}

#[test]
fn retired_certificates_remain_separate_bounded_and_strict_in_both_frontends() {
    let record = json!({"CertName":"synthetic.REMOVED.record","Bank":"syntheticbank",
        "Purpose":"signing","Expires":"unknown"});
    for retired in [None, Some(json!([])), Some(json!([record.clone()]))] {
        let mut body =
            json!({"ResponseCode":"00","ResponseText":"Certificates","Certs":[],"Connections":[]});
        if let Some(value) = &retired {
            body["Retired"] = value.clone();
        }
        let (mut client, transport) = client(Mode::Data, false);
        authenticate(&mut client, &transport);
        transport.json(200, body.clone());
        let direct = block_on(client.list_certificates()).unwrap();
        let brokered = isecure_rust_client::BusinessFacade::default()
            .complete_list_certificates(Response {
                status: 200,
                body: SecretBytes::new(serde_json::to_vec(&body).unwrap()),
            })
            .unwrap();
        assert_eq!(direct, brokered);
        assert!(direct.certs.is_empty() && direct.connections.is_empty());
        assert_eq!(
            direct.retired.len(),
            retired.as_ref().map_or(0, |v| v.as_array().unwrap().len())
        );
        if let Some(r) = direct.retired.first() {
            assert_eq!(r.cert_name, "synthetic.REMOVED.record");
            assert_eq!(r.expires, "unknown");
            assert_eq!(
                r.purpose,
                isecure_rust_client::BankCertificatePurpose::Signing
            );
        }
    }
    let limits = ResourceLimits::new(8192, 4096, 4096, 32, 32, 1).unwrap();
    let malformed = json!({"CertName":"synthetic.REMOVED.record","Bank":"syntheticbank","Purpose":"signing","Expires":"unknown","PrivateKey":"synthetic-forbidden"});
    for (retired, limited) in [
        (json!([record.clone(), record]), true),
        (json!([malformed]), false),
        (json!("unexpected"), false),
    ] {
        let body = json!({"ResponseCode":"00","ResponseText":"Certificates","Certs":[],"Connections":[],"Retired":retired});
        let (mut client, transport) = client_with_limits(Mode::Data, false, limits);
        authenticate(&mut client, &transport);
        transport.json(200, body.clone());
        for result in [
            block_on(client.list_certificates()),
            isecure_rust_client::BusinessFacade::new(limits).complete_list_certificates(Response {
                status: 200,
                body: SecretBytes::new(serde_json::to_vec(&body).unwrap()),
            }),
        ] {
            if limited {
                assert!(
                    matches!(result,Err(Error::Limit(value)) if value.kind()==LimitKind::CollectionItems)
                );
            } else {
                assert!(matches!(
                    result,
                    Err(Error::Protocol(ProtocolError::MalformedResponse))
                ));
            }
        }
    }
}
