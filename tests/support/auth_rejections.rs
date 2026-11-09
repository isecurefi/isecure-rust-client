use futures_executor::block_on;
use isecure_rust_client::{
    ApiResponse, AuthErrorReason, AuthState, AuthStep, BrokeredAuthContext, BrokeredAuthState,
    BusinessFacade, CaptureSummary, ChallengeEncryptor, Client, ClientConfig, Error, Mode,
    ProtocolError, Request, Response, SanitizedAuthResponse, SanitizedResponse, SecretBytes,
    SecretString, Transport, TransportError,
};
use std::{
    cell::RefCell,
    collections::VecDeque,
    future::{Ready, ready},
};

struct Responses(RefCell<VecDeque<Response>>);
impl Transport for Responses {
    type Future<'a> = Ready<Result<Response, TransportError>>;
    fn send(&self, _request: Request) -> Self::Future<'_> {
        ready(Ok(self
            .0
            .borrow_mut()
            .pop_front()
            .expect("one explicit dispatch per response")))
    }
}
struct FixedClock;
impl isecure_rust_client::Clock for FixedClock {
    fn now_epoch_seconds(&self) -> u64 {
        1000
    }
}
struct Encryptor;
impl ChallengeEncryptor for Encryptor {
    fn encrypt(
        &mut self,
        _: &str,
        _: &SecretString,
        _: &SecretString,
    ) -> Result<SecretString, ProtocolError> {
        Ok(SecretString::new("synthetic-encrypted"))
    }
}
fn response(status: u16, code: &str, text: &str) -> Response {
    Response {
        status,
        body: SecretBytes::new(
            serde_json::to_vec(&ApiResponse {
                response_code: code.into(),
                response_text: text.into(),
            })
            .unwrap(),
        ),
    }
}
fn client(responses: Vec<Response>) -> Client<Responses, Encryptor, FixedClock> {
    let config = ClientConfig::builder(
        "https://example.invalid/v2",
        "synthetic@example.invalid",
        Mode::Admin,
    )
    .password_profile(false)
    .phone("+358400000000")
    .company("Synthetic Company")
    .name("Synthetic User")
    .bank("simulator")
    .api_key(SecretString::new("synthetic-api-key"))
    .password(SecretString::new("synthetic-password"))
    .public_key_pem("synthetic-key")
    .build()
    .unwrap();
    Client::with_clock(
        config,
        Responses(RefCell::new(responses.into())),
        Encryptor,
        FixedClock,
    )
}
fn sanitized(status: u16, code: &str, text: &str) -> SanitizedResponse {
    SanitizedResponse {
        status,
        response: ApiResponse {
            response_code: code.into(),
            response_text: text.into(),
        },
        request_id: None,
    }
}
fn brokered_auth(status: u16, code: &str, text: &str) -> Result<BrokeredAuthState, Error> {
    BusinessFacade::default().complete_authentication(
        Mode::Admin,
        BrokeredAuthContext::default(),
        SanitizedAuthResponse {
            status,
            response: sanitized(status, code, text).response,
            request_id: None,
            challenge_name: None,
            expires_in_seconds: None,
            mfa_options: vec![],
            sms_destination: None,
            captures: CaptureSummary::default(),
        },
    )
}
fn challenge() -> Response {
    Response {
        status: 200,
        body: SecretBytes::new(
            br#"{"ResponseCode":"00","ResponseText":"OK","Challenge":"synthetic-challenge"}"#
                .to_vec(),
        ),
    }
}
fn assert_reason(
    direct: Result<AuthState, Error>,
    brokered: Result<BrokeredAuthState, Error>,
    expected: AuthErrorReason,
) {
    assert!(
        matches!(direct, Ok(AuthState::Failed {reason, ..}) if reason == expected),
        "direct: {direct:?}"
    );
    assert!(
        matches!(brokered, Ok(BrokeredAuthState::Failed {reason, ..}) if reason == expected),
        "brokered: {brokered:?}"
    );
}

pub fn recognized_rejections() {
    for (status, text, reason) in [
        (
            400,
            "Invalid verification code provided, please try again.",
            AuthErrorReason::InvalidCode,
        ),
        (
            400,
            "Verification code expired",
            AuthErrorReason::ExpiredCode,
        ),
        (400, "Request a new code", AuthErrorReason::ResendRequired),
        (
            400,
            "Email is already verified",
            AuthErrorReason::AlreadyVerified,
        ),
        (400, "Too many attempts", AuthErrorReason::TooManyAttempts),
        (
            429,
            "Attempt limit exceeded",
            AuthErrorReason::TooManyAttempts,
        ),
    ] {
        for step in [
            AuthStep::PhoneVerification,
            AuthStep::EmailVerification,
            AuthStep::Mfa,
        ] {
            let mut replies = vec![];
            if step == AuthStep::EmailVerification {
                replies.push(challenge());
                replies.push(Response { status: 200, body: SecretBytes::new(br#"{"ResponseCode":"00","ResponseText":"Verify email","AccessToken":"synthetic-access"}"#.to_vec()) });
            }
            replies.push(response(status, "42", text));
            let mut direct = client(replies);
            if step == AuthStep::EmailVerification {
                block_on(direct.login()).unwrap();
            }
            let code = SecretString::new("123456");
            let result = match step {
                AuthStep::PhoneVerification => block_on(direct.verify_phone(&code)),
                AuthStep::EmailVerification => block_on(direct.verify_email(&code)),
                AuthStep::Mfa => {
                    block_on(direct.verify_totp(&SecretString::new("synthetic-access"), &code))
                }
            };
            assert_reason(
                result,
                BusinessFacade::default().complete_verification(
                    Mode::Admin,
                    step,
                    sanitized(status, "42", text),
                ),
                reason,
            );
        }
        assert_reason(
            block_on(client(vec![challenge(), response(status, "42", text)]).login()),
            brokered_auth(status, "42", text),
            reason,
        );
    }
}

pub fn uncertain_rejections() {
    for (status, code, text) in [
        (400, "42", "Unexpected provider failure"),
        (400, "00", "Invalid code"),
        (400, "oops", "Invalid code"),
        (400, "42", "Invalid password"),
        (400, "42", "Access token expired"),
        (400, "42", "Too many accounts"),
        (400, "42", "Already sent a confirmation code"),
        (400, "42", "Access token expired; request a new code"),
        (500, "42", "Invalid code"),
        (401, "42", "Invalid code"),
        (429, "42", "Invalid code"),
    ] {
        let direct = block_on(
            client(vec![response(status, code, text)]).verify_phone(&SecretString::new("123456")),
        );
        let brokered = BusinessFacade::default().complete_verification(
            Mode::Admin,
            AuthStep::PhoneVerification,
            sanitized(status, code, text),
        );
        assert!(
            matches!(direct, Err(Error::Http(ref error)) if error.status == status),
            "{direct:?}"
        );
        assert!(
            matches!(brokered, Err(Error::Http(ref error)) if error.status == status),
            "{brokered:?}"
        );
        assert!(matches!(
            brokered_auth(status, code, text),
            Err(Error::Http(_))
        ));
    }
    for body in [b"not JSON".as_slice(), br#"{"ResponseCode":"42","ResponseText":"Invalid code","IdToken":"synthetic-contradiction"}"#] {
        let result = block_on(client(vec![Response { status: 400, body: SecretBytes::new(body.to_vec()) }]).verify_phone(&SecretString::new("123456")));
        assert!(matches!(result, Err(Error::Http(_))), "{result:?}");
    }
}

pub fn generic_operations_remain_strict() {
    let result =
        BusinessFacade::default().complete_api_response(sanitized(400, "42", "Invalid code"), 200);
    assert!(matches!(result, Err(Error::Http(_))));
    let direct = client(vec![response(400, "42", "Invalid code")]);
    assert!(matches!(
        block_on(direct.init_password_reset()),
        Err(Error::Http(_))
    ));
}

pub fn rejected_answers_preserve_only_existing_continuations() {
    for email in [true, false] {
        let pending = if email {
            br#"{"ResponseCode":"00","ResponseText":"Verify email","AccessToken":"synthetic-access"}"#.as_slice()
        } else {
            br#"{"ResponseCode":"00","ResponseText":"Enter SMS code","Session":"synthetic-session","ChallengeName":"SMS_MFA"}"#.as_slice()
        };
        let mut direct = client(vec![
            challenge(),
            Response {
                status: 200,
                body: SecretBytes::new(pending.to_vec()),
            },
            response(
                400,
                "42",
                "Invalid verification code synthetic-private-canary",
            ),
            response(400, "42", "Verification code expired"),
        ]);
        block_on(direct.login()).unwrap();
        for expected in [AuthErrorReason::InvalidCode, AuthErrorReason::ExpiredCode] {
            let fresh = SecretString::new(if expected == AuthErrorReason::InvalidCode {
                "123456"
            } else {
                "654321"
            });
            let result = if email {
                block_on(direct.verify_email(&fresh))
            } else {
                block_on(direct.submit_mfa_code(&fresh, false))
            };
            assert!(!format!("{result:?}").contains("synthetic-private-canary"));
            assert!(
                matches!(result, Ok(AuthState::Failed { reason, .. }) if reason == expected),
                "{result:?}"
            );
        }
    }
}

pub fn brokered_rejections_reject_contradictory_captures() {
    let opaque = ();
    let captures =
        CaptureSummary::from_host_bindings(&[isecure_rust_client::ProtectedBinding::from_host(
            isecure_rust_client::ProtectedValueKind::IdToken,
            &opaque,
        )])
        .unwrap();
    let result = BusinessFacade::default().complete_authentication(
        Mode::Admin,
        BrokeredAuthContext::default(),
        SanitizedAuthResponse {
            status: 400,
            response: sanitized(400, "42", "Invalid code").response,
            request_id: None,
            challenge_name: None,
            expires_in_seconds: None,
            mfa_options: vec![],
            sms_destination: None,
            captures,
        },
    );
    assert!(matches!(result, Err(Error::Http(_))));
}

pub fn logical_rejections_do_not_mislabel_passwords_or_expired_sessions_as_codes() {
    for text in [
        "Invalid password",
        "Access token expired",
        "Access token expired; request a new code",
        "Too many accounts",
        "Already sent a confirmation code",
    ] {
        assert_reason(
            block_on(client(vec![challenge(), response(200, "42", text)]).login()),
            brokered_auth(200, "42", text),
            AuthErrorReason::Unknown,
        );
    }
}

pub fn run() {
    logical_rejections_do_not_mislabel_passwords_or_expired_sessions_as_codes();
    recognized_rejections();
    uncertain_rejections();
    generic_operations_remain_strict();
    rejected_answers_preserve_only_existing_continuations();
    brokered_rejections_reject_contradictory_captures();
}
