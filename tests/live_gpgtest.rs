//! Opt-in black-box checks against the synthetic ISECure `gpgtest` environment.

#![cfg(not(target_family = "wasm"))]

use std::{
    env, fs,
    future::{Ready, ready},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use futures_executor::block_on;
use isecure_rust_client::{
    AuthErrorReason, AuthState, Client, ClientConfig, HttpMethod, MfaMethod, Mode, Request,
    Response, RsaChallengeEncryptor, SecretBytes, SecretString, Transport, TransportError,
    TransportErrorKind,
};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use zeroize::Zeroize;

const EXPECTED_ACCOUNT: &str = "589434896614";
const EXPECTED_REGION: &str = "eu-west-1";
const EXPECTED_PROFILE: &str = "default";
const EXPECTED_BASE_URL: &str = "https://ws-api.test.isecure.fi/v2";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LiveFixture {
    schema_version: u8,
    expected_aws_account: String,
    base_url: String,
    email: String,
    phone: String,
    company: String,
    name: String,
    password: String,
    api_key: String,
    public_key_pem: String,
    admin_totp_secret: String,
}

impl Drop for LiveFixture {
    fn drop(&mut self) {
        self.password.zeroize();
        self.api_key.zeroize();
        self.admin_totp_secret.zeroize();
    }
}

struct CurlTransport;

impl Transport for CurlTransport {
    type Future<'a> = Ready<Result<Response, TransportError>>;

    fn send(&self, request: Request) -> Self::Future<'_> {
        ready(send_with_curl(&request))
    }
}

fn send_with_curl(request: &Request) -> Result<Response, TransportError> {
    let mut configuration =
        String::from("silent\nshow-error\nconnect-timeout = 10\nmax-time = 30\noutput = \"-\"\n");
    configuration.push_str(&format!(
        "request = \"{}\"\nurl = \"{}\"\n",
        request.method.as_str(),
        curl_escape(&request.url)
    ));
    for header in &request.headers {
        configuration.push_str(&format!(
            "header = \"{}: {}\"\n",
            curl_escape(&header.name),
            curl_escape(header.value.as_str())
        ));
    }
    if let Some(body) = &request.body {
        let body = std::str::from_utf8(body.expose_secret()).map_err(|_| {
            TransportError::new(
                TransportErrorKind::Unavailable,
                Some("BODY_UTF8".to_owned()),
            )
        })?;
        configuration.push_str(&format!("data-binary = \"{}\"\n", curl_escape(body)));
    }
    configuration.push_str("write-out = \"\\nISECURE_HTTP_STATUS:%{http_code}\"\n");

    let mut child = Command::new("curl")
        .args(["--config", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| {
            TransportError::new(
                TransportErrorKind::Unavailable,
                Some("CURL_SPAWN".to_owned()),
            )
        })?;
    child
        .stdin
        .take()
        .ok_or_else(|| {
            TransportError::new(
                TransportErrorKind::Unavailable,
                Some("CURL_STDIN".to_owned()),
            )
        })?
        .write_all(configuration.as_bytes())
        .map_err(|_| {
            TransportError::new(TransportErrorKind::Network, Some("CURL_WRITE".to_owned()))
        })?;
    configuration.zeroize();
    let output = child.wait_with_output().map_err(|_| {
        TransportError::new(TransportErrorKind::Network, Some("CURL_WAIT".to_owned()))
    })?;
    if !output.status.success() {
        let code = output.status.code().map(|value| format!("CURL_{value}"));
        return Err(TransportError::new(TransportErrorKind::Network, code));
    }
    let marker = b"\nISECURE_HTTP_STATUS:";
    let marker_offset = output
        .stdout
        .windows(marker.len())
        .rposition(|window| window == marker)
        .ok_or_else(|| {
            TransportError::new(
                TransportErrorKind::OutcomeIndeterminate,
                Some("CURL_STATUS".to_owned()),
            )
        })?;
    let status = std::str::from_utf8(&output.stdout[marker_offset + marker.len()..])
        .ok()
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| {
            TransportError::new(
                TransportErrorKind::OutcomeIndeterminate,
                Some("CURL_STATUS".to_owned()),
            )
        })?;
    Ok(Response {
        status,
        body: SecretBytes::new(output.stdout[..marker_offset].to_vec()),
    })
}

fn curl_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            value => escaped.push(value),
        }
    }
    escaped
}

fn load_fixture() -> LiveFixture {
    assert_eq!(env::var("ISECURE_GPGTEST_LIVE").as_deref(), Ok("1"));
    assert_eq!(env::var("AWS_PROFILE").as_deref(), Ok(EXPECTED_PROFILE));
    assert_eq!(env::var("AWS_REGION").as_deref(), Ok(EXPECTED_REGION));
    let path = env::var("ISECURE_GPGTEST_FIXTURE_FILE").expect("fixture path is required");
    let metadata = fs::metadata(&path).expect("fixture metadata");
    assert_eq!(metadata.permissions().mode() & 0o077, 0);
    let bytes = SecretBytes::new(fs::read(path).expect("fixture bytes"));
    let fixture: LiveFixture =
        serde_json::from_slice(bytes.expose_secret()).expect("valid fixture schema");
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.expected_aws_account, EXPECTED_ACCOUNT);
    assert_eq!(fixture.base_url, EXPECTED_BASE_URL);
    assert!(fixture.email.ends_with("@example.invalid"));
    fixture
}

fn verify_aws_identity() {
    let output = Command::new("aws")
        .args([
            "sts",
            "get-caller-identity",
            "--profile",
            EXPECTED_PROFILE,
            "--region",
            EXPECTED_REGION,
            "--output",
            "json",
        ])
        .stderr(Stdio::null())
        .output()
        .expect("AWS CLI identity check");
    assert!(output.status.success());
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("AWS identity JSON");
    assert_eq!(value["Account"], EXPECTED_ACCOUNT);
    assert!(
        value["Arn"]
            .as_str()
            .is_some_and(|arn| !arn.contains(":root"))
    );
}

fn aws_json(service: &str, operation: &str, input: &serde_json::Value) -> serde_json::Value {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".live");
    fs::create_dir_all(&directory).expect("private live directory");
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
        .expect("private live directory mode");
    let input_path = directory.join(format!("aws-input-{}.json", std::process::id()));
    let mut options = fs::OpenOptions::new();
    options.create(true).truncate(true).write(true).mode(0o600);
    let mut input_file = options.open(&input_path).expect("private AWS input");
    let mut input_bytes = serde_json::to_vec(input).expect("AWS input JSON");
    input_file
        .write_all(&input_bytes)
        .expect("write private AWS input");
    input_bytes.zeroize();
    drop(input_file);

    let input_argument = format!("file://{}", input_path.display());
    let output = Command::new("aws")
        .args([
            service,
            operation,
            "--cli-input-json",
            &input_argument,
            "--profile",
            EXPECTED_PROFILE,
            "--region",
            EXPECTED_REGION,
            "--output",
            "json",
            "--no-cli-pager",
        ])
        .env("AWS_CLI_AUTO_PROMPT", "off")
        .stderr(Stdio::null())
        .output()
        .expect("AWS CLI operation");
    fs::remove_file(&input_path).expect("remove private AWS input");
    assert!(output.status.success(), "AWS CLI operation failed");
    if output.stdout.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&output.stdout).expect("AWS CLI JSON")
    }
}

fn random_text(bytes: usize) -> String {
    let output = Command::new("openssl")
        .args(["rand", "-base64", &bytes.to_string()])
        .stderr(Stdio::null())
        .output()
        .expect("OS-backed random text");
    assert!(output.status.success());
    String::from_utf8(output.stdout)
        .expect("base64 UTF-8")
        .trim()
        .replace(['+', '/', '='], "A")
}

fn cognito_username(email: &str, mode: Mode) -> String {
    format!("e_{}__{}", email.replace('@', "_at_"), mode.as_str())
}

fn save_fixture(path: &Path, fixture: &LiveFixture) {
    let parent = path.parent().expect("fixture parent");
    fs::create_dir_all(parent).expect("fixture directory");
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).expect("fixture directory mode");
    let temporary = path.with_extension("json.tmp");
    let mut options = fs::OpenOptions::new();
    options.create(true).truncate(true).write(true).mode(0o600);
    let mut file = options.open(&temporary).expect("private fixture temporary");
    let mut bytes = serde_json::to_vec_pretty(fixture).expect("fixture JSON");
    bytes.push(b'\n');
    file.write_all(&bytes).expect("write private fixture");
    bytes.zeroize();
    drop(file);
    fs::rename(temporary, path).expect("atomic fixture write");
}

fn test_public_key() -> String {
    include_str!("../contracts/synthetic-rsa-public.pem")
        .trim_end()
        .to_owned()
}

fn provision_cognito_user(fixture: &LiveFixture, mode: Mode) {
    let username = cognito_username(&fixture.email, mode);
    aws_json(
        "cognito-idp",
        "admin-create-user",
        &serde_json::json!({
            "UserPoolId":"eu-west-1_QtCfMyN6J",
            "Username":username,
            "MessageAction":"SUPPRESS",
            "UserAttributes":[
                {"Name":"email","Value":fixture.email},
                {"Name":"phone_number","Value":fixture.phone},
                {"Name":"name","Value":fixture.name},
                {"Name":"custom:apikey","Value":fixture.api_key},
                {"Name":"email_verified","Value":"true"},
                {"Name":"phone_number_verified","Value":"true"}
            ]
        }),
    );
    aws_json(
        "cognito-idp",
        "admin-set-user-password",
        &serde_json::json!({
            "UserPoolId":"eu-west-1_QtCfMyN6J",
            "Username":username,
            "Password":fixture.password,
            "Permanent":true
        }),
    );
}

fn provision_account(fixture: &LiveFixture) {
    aws_json(
        "dynamodb",
        "put-item",
        &serde_json::json!({
            "TableName":"isecure-ws-channel-users",
            "Item":{
                "email":{"S":fixture.email},
                "admin_enabled":{"BOOL":true},
                "data_enabled":{"BOOL":true},
                "phone_number_verified":{"BOOL":true},
                "email_verified":{"BOOL":true},
                "name":{"S":fixture.name},
                "company":{"S":fixture.company},
                "phone":{"S":fixture.phone},
                "apikey":{"S":fixture.api_key},
                "apikey_type":{"S":"provided"},
                "environment":{"S":"test"}
            },
            "ConditionExpression":"attribute_not_exists(email)"
        }),
    );
}

fn provision_api_key(fixture: &LiveFixture) {
    let key = aws_json(
        "apigateway",
        "create-api-key",
        &serde_json::json!({
            "name":format!("API-Key__{}", fixture.company),
            "description":"Synthetic isecure-rust-client qualification",
            "enabled":true,
            "value":fixture.api_key
        }),
    );
    let key_id = key["id"].as_str().expect("created API key ID");
    let plan = aws_json(
        "apigateway",
        "create-usage-plan",
        &serde_json::json!({
            "name":format!("Usage-Plan__{}", fixture.company),
            "description":"Synthetic isecure-rust-client qualification",
            "apiStages":[{"apiId":"5v82uu7087","stage":"gpgtest"}]
        }),
    );
    aws_json(
        "apigateway",
        "create-usage-plan-key",
        &serde_json::json!({
            "usagePlanId":plan["id"].as_str().expect("created usage plan ID"),
            "keyId":key_id,
            "keyType":"API_KEY"
        }),
    );
}

fn enroll_admin_totp(fixture: &mut LiveFixture) {
    let clients = aws_json(
        "cognito-idp",
        "list-user-pool-clients",
        &serde_json::json!({"UserPoolId":"eu-west-1_QtCfMyN6J","MaxResults":60}),
    );
    let client_id = clients["UserPoolClients"]
        .as_array()
        .expect("Cognito clients")
        .iter()
        .find(|value| value["ClientName"] == "isecure-ws-channel-lambda-login-new")
        .and_then(|value| value["ClientId"].as_str())
        .expect("login client")
        .to_owned();
    let auth = aws_json(
        "cognito-idp",
        "admin-initiate-auth",
        &serde_json::json!({
            "UserPoolId":"eu-west-1_QtCfMyN6J",
            "ClientId":client_id,
            "AuthFlow":"ADMIN_NO_SRP_AUTH",
            "AuthParameters":{
                "USERNAME":cognito_username(&fixture.email, Mode::Admin),
                "PASSWORD":fixture.password
            }
        }),
    );
    assert!(auth.get("ChallengeName").is_none());
    let access_token = SecretString::new(
        auth["AuthenticationResult"]["AccessToken"]
            .as_str()
            .expect("bootstrap access token"),
    );
    let association = aws_json(
        "cognito-idp",
        "associate-software-token",
        &serde_json::json!({"AccessToken":access_token.expose_secret()}),
    );
    fixture.admin_totp_secret = association["SecretCode"]
        .as_str()
        .filter(|value| {
            value
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        })
        .expect("TOTP secret")
        .to_owned();
    let verification = aws_json(
        "cognito-idp",
        "verify-software-token",
        &serde_json::json!({
            "AccessToken":access_token.expose_secret(),
            "UserCode":totp(&fixture.admin_totp_secret).expose_secret(),
            "FriendlyDeviceName":"isecure-rust-client-gpgtest"
        }),
    );
    assert_eq!(verification["Status"], "SUCCESS");
    aws_json(
        "cognito-idp",
        "admin-set-user-mfa-preference",
        &serde_json::json!({
            "UserPoolId":"eu-west-1_QtCfMyN6J",
            "Username":cognito_username(&fixture.email, Mode::Admin),
            "SMSMfaSettings":{"Enabled":false,"PreferredMfa":false},
            "SoftwareTokenMfaSettings":{"Enabled":true,"PreferredMfa":true}
        }),
    );
}

fn rng() -> ChaCha20Rng {
    let output = Command::new("openssl")
        .args(["rand", "32"])
        .stderr(Stdio::null())
        .output()
        .expect("OS-backed seed");
    assert!(output.status.success());
    let mut seed: [u8; 32] = output.stdout.try_into().expect("32-byte seed");
    let rng = ChaCha20Rng::from_seed(seed);
    seed.zeroize();
    rng
}

fn client(
    fixture: &LiveFixture,
    mode: Mode,
) -> Client<CurlTransport, RsaChallengeEncryptor<ChaCha20Rng>> {
    let config = ClientConfig::builder(&fixture.base_url, &fixture.email, mode)
        .password_profile(false)
        .phone(&fixture.phone)
        .company(&fixture.company)
        .name(&fixture.name)
        .password(SecretString::new(&fixture.password))
        .public_key_pem(&fixture.public_key_pem)
        .bank("simulator")
        .api_key(SecretString::new(&fixture.api_key))
        .build()
        .expect("admitted live fixture");
    Client::new(config, CurlTransport, RsaChallengeEncryptor::new(rng()))
}

fn base32_decode(value: &str) -> Vec<u8> {
    const ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut bits = 0_u8;
    let mut accumulator = 0_u32;
    let mut output = Vec::new();
    for character in value.trim_end_matches('=').chars() {
        let index = ALPHABET.find(character).expect("valid fixture TOTP secret");
        accumulator = (accumulator << 5) | u32::try_from(index).expect("base32 index");
        bits += 5;
        if bits >= 8 {
            output.push((accumulator >> (bits - 8)) as u8);
            bits -= 8;
        }
    }
    output
}

fn hmac_sha1(key: &[u8], message: &[u8]) -> [u8; 20] {
    let mut block = [0_u8; 64];
    if key.len() > block.len() {
        block[..20].copy_from_slice(&Sha1::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = [0x36_u8; 64];
    let mut outer = [0x5c_u8; 64];
    for index in 0..64 {
        inner[index] ^= block[index];
        outer[index] ^= block[index];
    }
    let mut inner_hash = Sha1::new();
    inner_hash.update(inner);
    inner_hash.update(message);
    let mut outer_hash = Sha1::new();
    outer_hash.update(outer);
    outer_hash.update(inner_hash.finalize());
    outer_hash.finalize().into()
}

fn totp(secret: &str) -> SecretString {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("wall clock")
        .as_secs();
    let digest = hmac_sha1(&base32_decode(secret), &(seconds / 30).to_be_bytes());
    let offset = usize::from(digest[19] & 0x0f);
    let binary = (u32::from(digest[offset] & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    SecretString::new(format!("{:06}", binary % 1_000_000))
}

fn authenticate_admin(
    client: &mut Client<CurlTransport, RsaChallengeEncryptor<ChaCha20Rng>>,
    fixture: &LiveFixture,
) {
    let mut state = block_on(client.login()).expect("admin login initiation");
    if matches!(state, AuthState::NeedsMfaSelection { .. }) {
        state = block_on(client.select_mfa_type(MfaMethod::Totp)).expect("select TOTP");
    }
    assert!(matches!(
        state,
        AuthState::NeedsMfa {
            method: MfaMethod::Totp,
            ..
        }
    ));
    let mut state = block_on(client.submit_mfa_code(&totp(&fixture.admin_totp_secret), false))
        .expect("submit TOTP");
    if matches!(
        state,
        AuthState::Failed {
            reason: AuthErrorReason::InvalidCode,
            ..
        }
    ) {
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("wall clock")
            .as_secs();
        thread::sleep(Duration::from_secs(31 - (seconds % 30)));
        state = block_on(client.submit_mfa_code(&totp(&fixture.admin_totp_secret), false))
            .expect("submit fresh TOTP");
    }
    assert!(matches!(state, AuthState::Authenticated { .. }));
}

#[test]
#[ignore = "creates one retained synthetic gpgtest identity after exact AWS guards"]
fn administratively_prepare_synthetic_gpgtest_fixture() {
    assert_eq!(env::var("ISECURE_GPGTEST_PREPARE").as_deref(), Ok("1"));
    assert_eq!(env::var("AWS_PROFILE").as_deref(), Ok(EXPECTED_PROFILE));
    assert_eq!(env::var("AWS_REGION").as_deref(), Ok(EXPECTED_REGION));
    verify_aws_identity();
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(".live")
        .join("gpgtest-fixture.json");
    assert!(
        !fixture_path.exists(),
        "fixture already exists; refusing mutation"
    );

    let mut fixture = LiveFixture {
        schema_version: 1,
        expected_aws_account: EXPECTED_ACCOUNT.to_owned(),
        base_url: EXPECTED_BASE_URL.to_owned(),
        email: "isecure-rust-sdk-gpgtest@example.invalid".to_owned(),
        phone: "+358400100010".to_owned(),
        company: format!("ISECure Rust SDK Synthetic {}", random_text(6)),
        name: "Synthetic Rust SDK".to_owned(),
        password: format!("Aa1!{}", random_text(24)),
        api_key: random_text(30),
        public_key_pem: test_public_key(),
        admin_totp_secret: String::new(),
    };
    save_fixture(&fixture_path, &fixture);
    provision_account(&fixture);
    provision_cognito_user(&fixture, Mode::Admin);
    provision_cognito_user(&fixture, Mode::Data);
    provision_api_key(&fixture);
    enroll_admin_totp(&mut fixture);
    save_fixture(&fixture_path, &fixture);
}

#[test]
#[ignore = "requires explicit synthetic gpgtest fixture and AWS account guard"]
fn authorized_synthetic_gpgtest_auth_and_read_operations() {
    verify_aws_identity();
    let fixture = load_fixture();

    let mut admin = client(&fixture, Mode::Admin);
    authenticate_admin(&mut admin, &fixture);
    assert_eq!(
        block_on(admin.list_keys())
            .expect("live list keys")
            .response_code,
        "00"
    );

    let mut data = client(&fixture, Mode::Data);
    assert!(matches!(
        block_on(data.login()).expect("data login"),
        AuthState::Authenticated { .. }
    ));
    assert_eq!(
        block_on(data.list_certificates())
            .expect("live list certificates")
            .response_code,
        "00"
    );

    for session in [admin.session(), data.session()] {
        let account = session
            .expect("completed live session")
            .account()
            .expect("existing live account metadata");
        assert!(matches!(
            account.account_type,
            isecure_rust_client::AccountType::Integrator
                | isecure_rust_client::AccountType::Customer
        ));
        assert!(account.features.is_empty());
        assert_eq!(account.entitlements.as_deref(), Some([].as_slice()));
    }

    let request = Request {
        method: HttpMethod::Get,
        url: "https://example.invalid/customer@example.invalid".to_owned(),
        headers: Vec::new(),
        body: None,
    };
    assert!(!format!("{request:?}").contains("customer@example.invalid"));
}
