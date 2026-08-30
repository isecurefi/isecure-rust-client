use std::{
    cell::RefCell,
    collections::{BTreeMap, VecDeque},
    future::{Ready, ready},
    rc::Rc,
};

use futures_executor::block_on;
use isecure_rust_client::{
    ApiResponse, AuthState, AuthStep, BrokerError, BrokeredAuthContext, BrokeredAuthState,
    BrokeredOperation, BusinessFacade, CaptureBroker, ChallengeEncryptor, Client, ClientConfig,
    Error, MfaMethod, Mode, ProtectedBinding, ProtectedResponseField, ProtectedValueKind,
    ProtocolError, RegistrationKind, Request, RequestFieldPlacement, RequestMutation,
    ResourceLimits, Response, SanitizedAuthResponse, SanitizedResponse, SecretBytes, SecretString,
    SecurityFacade, SecurityPrepareInput, SecurityStage, TransientSecret, Transport,
    TransportError,
};

const CHALLENGE: &str = "challenge|1475429754114|synthetic";
const SECRET_CANARY: &str = "credential-canary-must-never-appear";

#[derive(Debug)]
struct HostReference(&'static str);

fn binding<'a>(
    kind: ProtectedValueKind,
    value: &'a HostReference,
) -> ProtectedBinding<'a, HostReference> {
    ProtectedBinding::from_host(kind, value)
}

#[test]
fn business_plans_are_closed_linear_and_hold_only_opaque_references() {
    let facade = BusinessFacade::default();
    let password = HostReference(SECRET_CANARY);
    let api_key = HostReference(SECRET_CANARY);
    let id_token = HostReference(SECRET_CANARY);

    let login = facade
        .plan(
            BrokeredOperation::Login,
            &[binding(ProtectedValueKind::Password, &password)],
        )
        .expect("exact login plan");
    assert_eq!(login.operation().operation_id(), "Login");
    assert_eq!(
        login.stages(),
        &[
            SecurityStage::LoginPrepare,
            SecurityStage::AuthenticationCapture
        ]
    );
    assert!(!format!("{login:?}").contains(SECRET_CANARY));

    let check = facade
        .plan(
            BrokeredOperation::ListAccounts,
            &[
                binding(ProtectedValueKind::IdToken, &id_token),
                binding(ProtectedValueKind::ApiKey, &api_key),
            ],
        )
        .expect("authenticated connection check");
    assert_eq!(
        check.stages(),
        &[SecurityStage::AuthenticatedHeadersPrepare]
    );

    for operation in [
        BrokeredOperation::UploadPgpKey,
        BrokeredOperation::DeleteKey,
        BrokeredOperation::ListFiles,
        BrokeredOperation::DownloadFile,
    ] {
        let plan = facade
            .plan(
                operation,
                &[
                    binding(ProtectedValueKind::IdToken, &id_token),
                    binding(ProtectedValueKind::ApiKey, &api_key),
                ],
            )
            .expect("authenticated OpenPGP administration plan");
        assert_eq!(plan.stages(), &[SecurityStage::AuthenticatedHeadersPrepare]);
    }
    assert_eq!(BrokeredOperation::UploadPgpKey.operation_id(), "UploadKey");
    assert_eq!(BrokeredOperation::DeleteKey.operation_id(), "DeleteKey");
    assert_eq!(BrokeredOperation::ListFiles.operation_id(), "ListFiles");
    assert_eq!(
        BrokeredOperation::DownloadFile.operation_id(),
        "DownloadFile"
    );

    let linked = facade
        .plan(
            BrokeredOperation::Register(RegistrationKind::LinkedIdentity),
            &[
                binding(ProtectedValueKind::Password, &password),
                binding(ProtectedValueKind::ApiKey, &api_key),
            ],
        )
        .expect("linked registration");
    assert_eq!(linked.stages().len(), 2);

    let public = facade
        .plan::<HostReference>(BrokeredOperation::InitLogin, &[])
        .expect("public challenge request");
    assert!(public.stages().is_empty());

    for rejected in [
        facade.plan::<HostReference>(BrokeredOperation::Login, &[]),
        facade.plan(
            BrokeredOperation::Login,
            &[binding(ProtectedValueKind::ApiKey, &api_key)],
        ),
        facade.plan(
            BrokeredOperation::ListKeys,
            &[
                binding(ProtectedValueKind::ApiKey, &api_key),
                binding(ProtectedValueKind::IdToken, &id_token),
            ],
        ),
    ] {
        assert!(matches!(
            rejected,
            Err(Error::Protocol(ProtocolError::InvalidAuthState))
        ));
    }

    // The inner host resource is never formatted or exposed through the SDK wrapper.
    assert_eq!(password.0, SECRET_CANARY);
    let wrapped = binding(ProtectedValueKind::Password, &password);
    assert!(!format!("{wrapped:?}").contains(SECRET_CANARY));
}

#[test]
fn deterministic_hostile_binding_substitutions_fail_closed() {
    let kinds = [
        ProtectedValueKind::Password,
        ProtectedValueKind::ApiKey,
        ProtectedValueKind::IdToken,
        ProtectedValueKind::AccessToken,
        ProtectedValueKind::Continuation,
        ProtectedValueKind::OneTimeCode,
        ProtectedValueKind::NewPassword,
        ProtectedValueKind::TotpSeed,
        ProtectedValueKind::TotpUri,
    ];
    let host = HostReference(SECRET_CANARY);
    let facade = BusinessFacade::default();
    for first in kinds {
        let observed = facade.plan(BrokeredOperation::Login, &[binding(first, &host)]);
        assert_eq!(observed.is_ok(), first == ProtectedValueKind::Password);
        for second in kinds {
            assert!(
                facade
                    .plan(
                        BrokeredOperation::Login,
                        &[binding(first, &host), binding(second, &host)],
                    )
                    .is_err()
            );
        }
    }

    let context = BrokeredAuthContext::from_host_bindings(&[
        binding(ProtectedValueKind::ApiKey, &host),
        binding(ProtectedValueKind::Continuation, &host),
    ])
    .expect("exact prior auth context");
    assert!(context.has_api_key());
    assert!(context.has_continuation());
    assert!(
        BrokeredAuthContext::from_host_bindings(&[
            binding(ProtectedValueKind::ApiKey, &host),
            binding(ProtectedValueKind::ApiKey, &host),
        ])
        .is_err()
    );
    assert!(!format!("{context:?}").contains(SECRET_CANARY));
}

struct OneUseSecret {
    value: Option<Vec<u8>>,
    reads: usize,
}

impl OneUseSecret {
    fn new(value: &str) -> Self {
        Self {
            value: Some(value.as_bytes().to_vec()),
            reads: 0,
        }
    }
}

impl TransientSecret for OneUseSecret {
    fn read_once(&mut self) -> Result<SecretBytes, BrokerError> {
        self.reads += 1;
        self.value
            .take()
            .map(SecretBytes::new)
            .ok_or(BrokerError::AlreadyUsed)
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
        assert!(password.expose_secret().contains("password"));
        Ok(SecretString::new("encrypted-fixture"))
    }
}

fn security() -> SecurityFacade<FixtureEncryptor> {
    SecurityFacade::new(
        "fixture-public-key",
        FixtureEncryptor,
        ResourceLimits::default(),
    )
    .expect("security facade")
}

fn mutations(
    values: Vec<RequestMutation>,
) -> BTreeMap<&'static str, (RequestFieldPlacement, String)> {
    values
        .into_iter()
        .map(|mutation| {
            let id = mutation.field_id();
            let placement = mutation.placement();
            let value = String::from_utf8(mutation.into_value().expose_secret().to_vec())
                .expect("UTF-8 fixture");
            (id, (placement, value))
        })
        .collect()
}

#[test]
fn privileged_prepare_reads_exact_values_once_and_emits_exact_fields() {
    let mut facade = security();
    let mut registration = [
        OneUseSecret::new("fixture-password"),
        OneUseSecret::new("fixture-api-key"),
    ];
    let values = mutations(
        facade
            .prepare(
                BrokeredOperation::Register(RegistrationKind::LinkedIdentity),
                SecurityPrepareInput::Challenge {
                    challenge: CHALLENGE,
                },
                &mut registration,
            )
            .expect("registration mutations"),
    );
    assert_eq!(values["ApiKey"].1, "fixture-api-key");
    assert_eq!(values["ChResp"].1, CHALLENGE);
    assert_eq!(values["Encrypted"].1, "encrypted-fixture");
    assert!(
        values
            .values()
            .all(|(place, _)| *place == RequestFieldPlacement::Body)
    );
    assert_eq!(registration[0].reads, 1);
    assert_eq!(registration[1].reads, 1);

    assert!(matches!(
        facade.prepare(
            BrokeredOperation::Register(RegistrationKind::LinkedIdentity),
            SecurityPrepareInput::Challenge {
                challenge: CHALLENGE
            },
            &mut registration,
        ),
        Err(Error::Broker(BrokerError::AlreadyUsed))
    ));

    let mut wrong_stage = [OneUseSecret::new("fixture-password")];
    assert!(matches!(
        facade.prepare(
            BrokeredOperation::Login,
            SecurityPrepareInput::AuthenticatedHeaders,
            &mut wrong_stage,
        ),
        Err(Error::Protocol(ProtocolError::InvalidAuthState))
    ));
    assert_eq!(wrong_stage[0].reads, 0);

    let mut excess = [
        OneUseSecret::new("fixture-password"),
        OneUseSecret::new("unexpected"),
    ];
    assert!(matches!(
        facade.prepare(
            BrokeredOperation::Login,
            SecurityPrepareInput::Challenge {
                challenge: CHALLENGE
            },
            &mut excess,
        ),
        Err(Error::Protocol(ProtocolError::InvalidAuthState))
    ));
    assert!(excess.iter().all(|value| value.reads == 0));

    let mut headers = [
        OneUseSecret::new("fixture-id-token"),
        OneUseSecret::new("fixture-api-key"),
    ];
    let values = mutations(
        facade
            .prepare(
                BrokeredOperation::ListAccounts,
                SecurityPrepareInput::AuthenticatedHeaders,
                &mut headers,
            )
            .expect("authenticated headers"),
    );
    assert_eq!(values["Authorization"].0, RequestFieldPlacement::Header);
    assert_eq!(values["x-api-key"].0, RequestFieldPlacement::Header);

    let mut upload_headers = [
        OneUseSecret::new("fixture-id-token"),
        OneUseSecret::new("fixture-api-key"),
    ];
    let values = mutations(
        facade
            .prepare(
                BrokeredOperation::UploadPgpKey,
                SecurityPrepareInput::AuthenticatedHeaders,
                &mut upload_headers,
            )
            .expect("OpenPGP upload authentication headers"),
    );
    assert_eq!(values["Authorization"].1, "fixture-id-token");
    assert_eq!(values["x-api-key"].1, "fixture-api-key");

    let mut login = [OneUseSecret::new("fixture-password")];
    let values = mutations(
        facade
            .prepare(
                BrokeredOperation::Login,
                SecurityPrepareInput::Challenge {
                    challenge: CHALLENGE,
                },
                &mut login,
            )
            .expect("login request"),
    );
    assert_eq!(values["ChResp"].1, CHALLENGE);
    assert_eq!(values["Encrypted"].1, "encrypted-fixture");

    let mut reset = [
        OneUseSecret::new("654321"),
        OneUseSecret::new("new-password"),
    ];
    let values = mutations(
        facade
            .prepare(
                BrokeredOperation::PasswordReset,
                SecurityPrepareInput::Challenge {
                    challenge: CHALLENGE,
                },
                &mut reset,
            )
            .expect("password reset request"),
    );
    assert_eq!(values["Code"].1, "654321");
    assert_eq!(values["Encrypted"].1, "encrypted-fixture");

    let mut selection = [OneUseSecret::new("fixture-continuation")];
    let values = mutations(
        facade
            .prepare(
                BrokeredOperation::SelectMfa,
                SecurityPrepareInput::MfaSelection {
                    method: MfaMethod::Sms,
                },
                &mut selection,
            )
            .expect("MFA selection"),
    );
    assert_eq!(values["MfaType"].1, "SMS_MFA");
    assert_eq!(values["Session"].1, "fixture-continuation");

    let mut verification = [
        OneUseSecret::new("fixture-access-token"),
        OneUseSecret::new("987654"),
    ];
    let values = mutations(
        facade
            .prepare(
                BrokeredOperation::VerifyEmail,
                SecurityPrepareInput::Verification,
                &mut verification,
            )
            .expect("email verification"),
    );
    assert_eq!(values["AccessToken"].1, "fixture-access-token");
    assert_eq!(values["Code"].1, "987654");

    let mut phone = [OneUseSecret::new("112233")];
    let values = mutations(
        facade
            .prepare(
                BrokeredOperation::VerifyPhone,
                SecurityPrepareInput::Verification,
                &mut phone,
            )
            .expect("phone verification"),
    );
    assert_eq!(values["Code"].1, "112233");

    let mut mfa = [
        OneUseSecret::new("123456"),
        OneUseSecret::new("fixture-continuation"),
    ];
    let values = mutations(
        facade
            .prepare(
                BrokeredOperation::LoginMfa,
                SecurityPrepareInput::MfaCode {
                    challenge_name: Some(MfaMethod::Totp),
                    setup_totp: true,
                },
                &mut mfa,
            )
            .expect("MFA request"),
    );
    assert_eq!(values["Code"].1, "123456");
    assert_eq!(values["Session"].1, "fixture-continuation");
    assert_eq!(values["ChallengeName"].1, "SOFTWARE_TOKEN_MFA");
    assert_eq!(values["SetupTOTP"].1, "true");
    assert!(!format!("{:?}", values.keys().collect::<Vec<_>>()).contains("123456"));

    let mut mfa_without_name = [
        OneUseSecret::new("445566"),
        OneUseSecret::new("fixture-continuation"),
    ];
    let values = mutations(
        facade
            .prepare(
                BrokeredOperation::LoginMfa,
                SecurityPrepareInput::MfaCode {
                    challenge_name: None,
                    setup_totp: false,
                },
                &mut mfa_without_name,
            )
            .expect("response-text driven MFA request"),
    );
    assert!(!values.contains_key("ChallengeName"));
    assert!(!values.contains_key("SetupTOTP"));

    let limits = ResourceLimits::new(1024, 64, 1024, 1024, 1024, 8).expect("limits");
    let mut bounded = SecurityFacade::new("fixture-public-key", FixtureEncryptor, limits)
        .expect("bounded security facade");
    let mut oversized = [OneUseSecret::new(&"password".repeat(10))];
    assert!(matches!(
        bounded.prepare(
            BrokeredOperation::Login,
            SecurityPrepareInput::Challenge {
                challenge: CHALLENGE
            },
            &mut oversized,
        ),
        Err(Error::Limit(_))
    ));
    assert_eq!(oversized[0].reads, 1, "oversized release is still one-use");
}

#[derive(Default)]
struct RecordingCaptureBroker {
    calls: Vec<(BrokeredOperation, ProtectedValueKind, u8)>,
    fail: Option<BrokerError>,
}

impl CaptureBroker<u8> for RecordingCaptureBroker {
    fn seal_captured(
        &mut self,
        operation: BrokeredOperation,
        kind: ProtectedValueKind,
        value: &u8,
    ) -> Result<(), BrokerError> {
        if let Some(error) = self.fail {
            return Err(error);
        }
        self.calls.push((operation, kind, *value));
        Ok(())
    }
}

#[test]
fn capture_is_closed_deduplicated_and_broker_only() {
    let facade = security();
    let api_key = 1;
    let id_token = 2;
    let continuation = 3;
    let mut broker = RecordingCaptureBroker::default();
    let summary = facade
        .capture(
            BrokeredOperation::Login,
            &[
                ProtectedResponseField::from_host(ProtectedValueKind::ApiKey, &api_key),
                ProtectedResponseField::from_host(ProtectedValueKind::IdToken, &id_token),
                ProtectedResponseField::from_host(ProtectedValueKind::Continuation, &continuation),
            ],
            &mut broker,
        )
        .expect("admitted captures");
    assert!(summary.has(ProtectedValueKind::ApiKey));
    assert!(summary.has(ProtectedValueKind::IdToken));
    assert!(summary.has(ProtectedValueKind::Continuation));
    assert_eq!(broker.calls.len(), 3);

    let api_ref = HostReference(SECRET_CANARY);
    let id_ref = HostReference(SECRET_CANARY);
    let host_summary = isecure_rust_client::CaptureSummary::from_host_bindings(&[
        binding(ProtectedValueKind::ApiKey, &api_ref),
        binding(ProtectedValueKind::IdToken, &id_ref),
    ])
    .expect("opaque host captures");
    assert!(host_summary.has(ProtectedValueKind::ApiKey));
    assert!(host_summary.has(ProtectedValueKind::IdToken));
    assert!(!format!("{host_summary:?}").contains(SECRET_CANARY));

    let mut hostile = RecordingCaptureBroker::default();
    assert!(matches!(
        facade.capture(
            BrokeredOperation::Register(RegistrationKind::NewIdentity),
            &[
                ProtectedResponseField::from_host(ProtectedValueKind::ApiKey, &api_key),
                ProtectedResponseField::from_host(ProtectedValueKind::ApiKey, &api_key),
            ],
            &mut hostile,
        ),
        Err(Error::Protocol(ProtocolError::InvalidAuthState))
    ));
    assert!(
        hostile.calls.is_empty(),
        "structural refusal precedes broker use"
    );

    let mut unavailable = RecordingCaptureBroker {
        fail: Some(BrokerError::Unavailable),
        ..RecordingCaptureBroker::default()
    };
    assert!(matches!(
        facade.capture(
            BrokeredOperation::Login,
            &[ProtectedResponseField::from_host(
                ProtectedValueKind::IdToken,
                &id_token,
            )],
            &mut unavailable,
        ),
        Err(Error::Broker(BrokerError::Unavailable))
    ));
}

#[derive(Clone, Default)]
struct FakeTransport {
    responses: Rc<RefCell<VecDeque<Result<Response, TransportError>>>>,
}

impl FakeTransport {
    fn push_json(&self, status: u16, value: serde_json::Value) {
        self.responses.borrow_mut().push_back(Ok(Response {
            status,
            body: SecretBytes::new(serde_json::to_vec(&value).expect("fixture JSON")),
        }));
    }
}

impl Transport for FakeTransport {
    type Future<'a> = Ready<Result<Response, TransportError>>;

    fn send(&self, _request: Request) -> Self::Future<'_> {
        ready(
            self.responses
                .borrow_mut()
                .pop_front()
                .expect("queued response"),
        )
    }
}

fn direct_client(transport: FakeTransport) -> Client<FakeTransport, FixtureEncryptor> {
    let config = ClientConfig::builder(
        "https://ws-api.test.isecure.fi/v2",
        "brokered@example.test",
        Mode::Admin,
    )
    .phone("+358400000000")
    .company("Synthetic Company")
    .name("Synthetic User")
    .password(SecretString::new("fixture-password"))
    .public_key_pem("fixture-public-key")
    .bank("simulator")
    .api_key(SecretString::new("fixture-api-key"))
    .build()
    .expect("direct config");
    Client::new(config, transport, FixtureEncryptor)
}

fn challenge_response() -> serde_json::Value {
    serde_json::json!({
        "ResponseCode":"00",
        "ResponseText":"OK",
        "Challenge":CHALLENGE
    })
}

#[test]
fn direct_and_brokered_auth_and_error_classification_have_parity() {
    let direct_transport = FakeTransport::default();
    direct_transport.push_json(200, challenge_response());
    direct_transport.push_json(
        200,
        serde_json::json!({
            "ResponseCode":"00",
            "ResponseText":"Choose factor",
            "ChallengeName":"SELECT_MFA_TYPE",
            "Session":"opaque-continuation",
            "MfaOptions":["SMS_MFA","SOFTWARE_TOKEN_MFA"],
            "SmsDestination":"+*****0000"
        }),
    );
    let direct = block_on(direct_client(direct_transport).login()).expect("direct login");

    let continuation = 7;
    let mut capture_broker = RecordingCaptureBroker::default();
    let captures = security()
        .capture(
            BrokeredOperation::Login,
            &[ProtectedResponseField::from_host(
                ProtectedValueKind::Continuation,
                &continuation,
            )],
            &mut capture_broker,
        )
        .expect("brokered capture");
    let brokered = BusinessFacade::default()
        .complete_authentication(
            Mode::Admin,
            BrokeredAuthContext::default(),
            SanitizedAuthResponse {
                status: 200,
                response: ApiResponse {
                    response_code: "00".to_owned(),
                    response_text: "Choose factor".to_owned(),
                },
                request_id: None,
                challenge_name: Some("SELECT_MFA_TYPE".to_owned()),
                expires_in_seconds: None,
                mfa_options: vec!["SMS_MFA".to_owned(), "SOFTWARE_TOKEN_MFA".to_owned()],
                sms_destination: Some("+*****0000".to_owned()),
                captures,
            },
        )
        .expect("brokered login");
    assert!(matches!(
        (&direct, &brokered),
        (
            AuthState::NeedsMfaSelection { methods: direct, .. },
            BrokeredAuthState::NeedsMfaSelection { methods: brokered, .. }
        ) if direct == brokered
    ));

    let verification_transport = FakeTransport::default();
    verification_transport.push_json(
        200,
        serde_json::json!({"ResponseCode":"00","ResponseText":"verified"}),
    );
    let direct_verification =
        block_on(direct_client(verification_transport).verify_phone(&SecretString::new("123456")))
            .expect("direct verification");
    let brokered_verification = BusinessFacade::default()
        .complete_verification(
            Mode::Admin,
            AuthStep::PhoneVerification,
            SanitizedResponse {
                status: 200,
                response: ApiResponse {
                    response_code: "00".to_owned(),
                    response_text: "verified".to_owned(),
                },
                request_id: None,
            },
        )
        .expect("brokered verification");
    assert!(matches!(
        (direct_verification, brokered_verification),
        (
            AuthState::VerificationAccepted {
                step: AuthStep::PhoneVerification,
                ..
            },
            BrokeredAuthState::VerificationAccepted {
                step: AuthStep::PhoneVerification,
                ..
            }
        )
    ));

    let facade = BusinessFacade::default();
    let brokered_error = facade
        .complete_api_response(
            SanitizedResponse {
                status: 401,
                response: ApiResponse {
                    response_code: "42".to_owned(),
                    response_text: "not admitted".to_owned(),
                },
                request_id: Some("request-1".to_owned()),
            },
            200,
        )
        .expect_err("brokered HTTP error");

    let error_transport = FakeTransport::default();
    error_transport.push_json(
        401,
        serde_json::json!({"ResponseCode":"42","RequestId":"request-1"}),
    );
    let direct_error = block_on(direct_client(error_transport).init_password_reset())
        .expect_err("direct HTTP error");
    match (direct_error, brokered_error) {
        (Error::Http(direct), Error::Http(brokered)) => {
            assert_eq!(direct.status, brokered.status);
            assert_eq!(direct.response_code, brokered.response_code);
            assert_eq!(direct.request_id, brokered.request_id);
        }
        _ => panic!("expected matching HTTP error classes"),
    }
}

#[test]
fn direct_and_brokered_authenticated_and_malformed_totp_results_have_parity() {
    let direct_transport = FakeTransport::default();
    direct_transport.push_json(200, challenge_response());
    direct_transport.push_json(
        200,
        serde_json::json!({
            "ResponseCode":"00",
            "ResponseText":"Login OK",
            "ApiKey":"fixture-api-key",
            "IdToken":"fixture-id-token",
            "ExpiresIn":"300"
        }),
    );
    let direct = block_on(direct_client(direct_transport).login()).expect("direct login");

    let api_key = HostReference(SECRET_CANARY);
    let id_token = HostReference(SECRET_CANARY);
    let captures = isecure_rust_client::CaptureSummary::from_host_bindings(&[
        binding(ProtectedValueKind::ApiKey, &api_key),
        binding(ProtectedValueKind::IdToken, &id_token),
    ])
    .expect("host captures");
    let brokered = BusinessFacade::default()
        .complete_authentication(
            Mode::Admin,
            BrokeredAuthContext::default(),
            SanitizedAuthResponse {
                status: 200,
                response: ApiResponse {
                    response_code: "00".to_owned(),
                    response_text: "Login OK".to_owned(),
                },
                request_id: None,
                challenge_name: None,
                expires_in_seconds: Some(300),
                mfa_options: Vec::new(),
                sms_destination: None,
                captures,
            },
        )
        .expect("brokered login");
    assert!(matches!(
        (direct, brokered),
        (
            AuthState::Authenticated {
                totp_enrollment: None,
                ..
            },
            BrokeredAuthState::Authenticated {
                totp_enrollment_available: false,
                expires_in_seconds: Some(300),
                ..
            }
        )
    ));

    let malformed_transport = FakeTransport::default();
    malformed_transport.push_json(200, challenge_response());
    malformed_transport.push_json(
        200,
        serde_json::json!({
            "ResponseCode":"00",
            "ResponseText":"Login OK",
            "ApiKey":"fixture-api-key",
            "IdToken":"fixture-id-token",
            "AccessToken":"fixture-access-token",
            "SecretCode":"fixture-totp-seed"
        }),
    );
    let direct_error = block_on(direct_client(malformed_transport).login())
        .expect_err("partial direct TOTP enrollment");
    let access = HostReference(SECRET_CANARY);
    let seed = HostReference(SECRET_CANARY);
    let captures = isecure_rust_client::CaptureSummary::from_host_bindings(&[
        binding(ProtectedValueKind::ApiKey, &api_key),
        binding(ProtectedValueKind::IdToken, &id_token),
        binding(ProtectedValueKind::AccessToken, &access),
        binding(ProtectedValueKind::TotpSeed, &seed),
    ])
    .expect("partial host captures");
    let brokered_error = BusinessFacade::default()
        .complete_authentication(
            Mode::Admin,
            BrokeredAuthContext::default(),
            SanitizedAuthResponse {
                status: 200,
                response: ApiResponse {
                    response_code: "00".to_owned(),
                    response_text: "Login OK".to_owned(),
                },
                request_id: None,
                challenge_name: None,
                expires_in_seconds: None,
                mfa_options: Vec::new(),
                sms_destination: None,
                captures,
            },
        )
        .expect_err("partial brokered TOTP enrollment");
    assert!(matches!(
        (direct_error, brokered_error),
        (
            Error::Protocol(ProtocolError::MalformedResponse),
            Error::Protocol(ProtocolError::MalformedResponse)
        )
    ));
}

fn json_response(status: u16, value: serde_json::Value) -> Response {
    Response {
        status,
        body: SecretBytes::new(serde_json::to_vec(&value).expect("fixture JSON")),
    }
}

#[test]
fn brokered_connection_checks_reuse_exact_typed_decoders_and_limits() {
    let facade = BusinessFacade::default();
    let accounts = facade
        .complete_list_accounts(json_response(
            200,
            serde_json::json!({
                "ResponseCode":"00",
                "ResponseText":"accounts",
                "Accounts":[]
            }),
        ))
        .expect("accounts");
    assert!(accounts.accounts.is_empty());

    let certificates = facade
        .complete_list_certificates(json_response(
            200,
            serde_json::json!({
                "ResponseCode":"00",
                "ResponseText":"certificates",
                "Certs":[],
                "Connections":[]
            }),
        ))
        .expect("certificates");
    assert!(certificates.certs.is_empty());

    let keys = facade
        .complete_list_keys(json_response(
            200,
            serde_json::json!({
                "ResponseCode":"00",
                "ResponseText":"keys",
                "PgpKeys":[]
            }),
        ))
        .expect("keys");
    assert!(keys.pgp_keys.is_empty());

    assert!(matches!(
        facade.complete_list_keys(json_response(
            200,
            serde_json::json!({
                "ResponseCode":"00",
                "ResponseText":"keys",
                "PgpKeys":[],
                "Unexpected":"refused"
            }),
        )),
        Err(Error::Protocol(ProtocolError::MalformedResponse))
    ));

    let limits = ResourceLimits::new(1024, 1024, 1024, 1024, 1024, 1).expect("limits");
    assert!(matches!(
        BusinessFacade::new(limits).complete_list_keys(json_response(
            200,
            serde_json::json!({
                "ResponseCode":"00",
                "ResponseText":"keys",
                "PgpKeys":[
                    {"PgpKeyId":"00000001","PgpKeyPurpose":"authorize"},
                    {"PgpKeyId":"00000002","PgpKeyPurpose":"export"}
                ]
            }),
        )),
        Err(Error::Limit(_))
    ));

    let limits = ResourceLimits::new(1024, 1024, 8, 1024, 1024, 8).expect("limits");
    assert!(matches!(
        BusinessFacade::new(limits).complete_api_response(
            SanitizedResponse {
                status: 200,
                response: ApiResponse {
                    response_code: "00".to_owned(),
                    response_text: "response exceeds bound".to_owned(),
                },
                request_id: None,
            },
            200,
        ),
        Err(Error::Limit(_))
    ));
}

#[test]
fn brokered_file_reads_reuse_exact_typed_decoders_and_limits() {
    let facade = BusinessFacade::default();
    let listed = facade
        .complete_list_files(json_response(
            200,
            serde_json::json!({
                "ResponseCode":"00",
                "ResponseText":"files",
                "FileDescriptors":[{
                    "FileType":"camt.053",
                    "Status":"NEW",
                    "FileTimestamp":"2026-08-30T12:00:00Z",
                    "FileReference":"synthetic-1"
                }]
            }),
        ))
        .expect("bounded file list");
    assert_eq!(listed.file_descriptors.len(), 1);
    assert_eq!(listed.file_descriptors[0].file_reference, "synthetic-1");

    let downloaded = facade
        .complete_download_file(json_response(
            200,
            serde_json::json!({
                "ResponseCode":"00",
                "ResponseText":"file",
                "Content":"PHN5bnRoZXRpYy8+"
            }),
        ))
        .expect("exact downloaded bytes");
    assert_eq!(downloaded.content.expose_secret(), b"<synthetic/>");

    assert!(matches!(
        facade.complete_list_files(json_response(
            200,
            serde_json::json!({
                "ResponseCode":"41",
                "ResponseText":"refused",
                "FileDescriptors":[]
            }),
        )),
        Err(Error::Logical(_))
    ));
    assert!(matches!(
        facade.complete_download_file(json_response(
            200,
            serde_json::json!({
                "ResponseCode":"00",
                "ResponseText":"file",
                "Content":"!!!!"
            }),
        )),
        Err(Error::Protocol(ProtocolError::MalformedResponse))
    ));

    let limits = ResourceLimits::new(1024, 1024, 1024, 4, 1024, 1).expect("limits");
    assert!(matches!(
        BusinessFacade::new(limits).complete_download_file(json_response(
            200,
            serde_json::json!({
                "ResponseCode":"00",
                "ResponseText":"file",
                "Content":"PHN5bnRoZXRpYy8+"
            }),
        )),
        Err(Error::Limit(_))
    ));
}
