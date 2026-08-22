use std::{
    cell::RefCell,
    future::{Ready, ready},
};

use futures_executor::block_on;
use isecure_rust_client::{
    ChallengeEncryptor, Client, ClientConfig, Clock, Error, LimitKind, MfaMethod, Mode,
    ProtocolError, Request, ResourceLimits, Response, SecretBytes, SecretString, Transport,
    TransportError,
};

struct DeterministicRng(u64);

impl DeterministicRng {
    fn next(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }

    fn bounded(&mut self, upper: usize) -> usize {
        usize::try_from(self.next()).unwrap_or(usize::MAX) % upper
    }

    fn bytes(&mut self, maximum: usize) -> Vec<u8> {
        let length = self.bounded(maximum + 1);
        (0..length).map(|_| self.next().to_le_bytes()[0]).collect()
    }
}

struct QueueTransport {
    bodies: RefCell<Vec<Vec<u8>>>,
}

impl Transport for QueueTransport {
    type Future<'a> = Ready<Result<Response, TransportError>>;

    fn send(&self, _request: Request) -> Self::Future<'_> {
        ready(Ok(Response {
            status: 200,
            body: SecretBytes::new(self.bodies.borrow_mut().pop().expect("fuzz body")),
        }))
    }
}

struct ConstantTransport;

impl Transport for ConstantTransport {
    type Future<'a> = Ready<Result<Response, TransportError>>;

    fn send(&self, _request: Request) -> Self::Future<'_> {
        ready(Ok(Response {
            status: 200,
            body: SecretBytes::new(b"{\"not\":\"an admitted response\"}".to_vec()),
        }))
    }
}

struct NoopEncryptor;

impl ChallengeEncryptor for NoopEncryptor {
    fn encrypt(
        &mut self,
        _public_key_pem: &str,
        _challenge: &SecretString,
        _password: &SecretString,
    ) -> Result<SecretString, ProtocolError> {
        Ok(SecretString::new("encrypted"))
    }
}

struct FixedClock;

impl Clock for FixedClock {
    fn now_epoch_seconds(&self) -> u64 {
        1_000
    }
}

fn config(
    base_url: &str,
    email: String,
    phone: String,
    bank: String,
    limits: ResourceLimits,
) -> Result<ClientConfig, Error> {
    ClientConfig::builder(base_url, email, Mode::Admin)
        .phone(phone)
        .company("Synthetic Company")
        .name("Synthetic User")
        .password(SecretString::new("Synthetic-password-123!"))
        .public_key_pem("fixture public key")
        .bank(bank)
        .api_key(SecretString::new("fixture-api-key"))
        .resource_limits(limits)
        .build()
}

fn random_text(rng: &mut DeterministicRng, maximum: usize) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789@/+ ?#%\n\r\t";
    let length = rng.bounded(maximum + 1);
    (0..length)
        .map(|_| char::from(ALPHABET[rng.bounded(ALPHABET.len())]))
        .collect()
}

#[test]
fn deterministic_response_mutation_fuzz_never_panics_or_accepts_drift() {
    const CASES: usize = 10_000;
    let mut rng = DeterministicRng(0x4953_4543_5552_4552);
    let valid = b"{\"ResponseCode\":\"00\",\"ResponseText\":\"OK\"}";
    let mut bodies = Vec::with_capacity(CASES);
    for index in 0..CASES {
        let mut body = if index % 2 == 0 {
            valid.to_vec()
        } else {
            rng.bytes(512)
        };
        if !body.is_empty() {
            let mutations = 1 + rng.bounded(8);
            for _ in 0..mutations {
                let offset = rng.bounded(body.len());
                body[offset] ^= rng.next().to_le_bytes()[0];
            }
        }
        bodies.push(body);
    }
    bodies.reverse();

    let limits = ResourceLimits::new(8_192, 1_024, 256, 128, 128, 32).expect("limits");
    let client = Client::with_clock(
        config(
            "https://ws-api.test.isecure.fi/v2",
            "fuzz@example.test".to_owned(),
            "+358400000000".to_owned(),
            "simulator".to_owned(),
            limits,
        )
        .expect("config"),
        QueueTransport {
            bodies: RefCell::new(bodies),
        },
        NoopEncryptor,
        FixedClock,
    );

    for _ in 0..CASES {
        match block_on(client.init_password_reset()) {
            Ok(response) => assert_eq!(response.response_code, "00"),
            Err(Error::Protocol(ProtocolError::MalformedResponse) | Error::Logical(_)) => {}
            Err(Error::Limit(value)) if value.kind() == LimitKind::ResponseBody => {}
            Err(other) => panic!("unexpected mutation result: {other:?}"),
        }
    }
}

#[test]
fn deterministic_url_and_auth_transition_fuzz_never_panics() {
    const CASES: usize = 4_000;
    let mut rng = DeterministicRng(0x5741_534d_504c_5547);
    let limits = ResourceLimits::new(512, 1_024, 1_024, 128, 128, 16).expect("limits");
    let bases = [
        "https://ws-api.test.isecure.fi/v2",
        "http://localhost:8080/v2",
        "http://localhost.evil/v2",
        "javascript:alert(1)",
        "https://example.test\\@evil.test/v2",
        "https://example.test/v2?query=forbidden",
    ];

    for _ in 0..CASES {
        let candidate = config(
            bases[rng.bounded(bases.len())],
            random_text(&mut rng, 96),
            random_text(&mut rng, 48),
            random_text(&mut rng, 96),
            limits,
        );
        let Ok(config) = candidate else {
            continue;
        };
        let mut client = Client::with_clock(config, ConstantTransport, NoopEncryptor, FixedClock);
        for _ in 0..4 {
            let result = match rng.bounded(6) {
                0 => block_on(client.login()).map(|_| ()),
                1 => block_on(client.select_mfa_type(MfaMethod::Sms)).map(|_| ()),
                2 => block_on(client.submit_mfa_code(&SecretString::new("000000"), false))
                    .map(|_| ()),
                3 => block_on(client.verify_phone(&SecretString::new("000000"))).map(|_| ()),
                4 => block_on(client.verify_email(&SecretString::new("000000"))).map(|_| ()),
                _ => block_on(client.list_files(&Default::default())).map(|_| ()),
            };
            assert!(
                result.is_err(),
                "malformed constant response or invalid transition was admitted"
            );
            assert!(!client.is_authenticated());
            assert!(!matches!(
                result,
                Ok(()) | Err(Error::Http(_)) | Err(Error::Transport(_))
            ));
        }
    }
}
