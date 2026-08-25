use isecure_rust_client::{BrokeredOperation, RegistrationKind};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Lock {
    version: u32,
    platform_repository: String,
    platform_source_revision: String,
    wit_path: String,
    wit_package: String,
    wit_sha256: String,
    business_world: World,
    security_world: World,
    sdk_operations: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct World {
    name: String,
    imports: Vec<String>,
    exports: Vec<String>,
}

#[test]
fn brokered_facade_is_pinned_to_exact_generated_worlds_and_operations() {
    let lock: Lock = serde_json::from_str(include_str!(
        "../contracts/brokered-component-profile.lock.json"
    ))
    .expect("brokered profile lock");
    assert_eq!(lock.version, 1);
    assert_eq!(lock.platform_repository, "bankfiles-platform");
    assert_eq!(lock.platform_source_revision.len(), 40);
    assert!(
        lock.platform_source_revision
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    );
    assert_eq!(
        lock.wit_path,
        "generated/connectors/wit/connector-runtime.wit"
    );
    assert_eq!(lock.wit_package, "isecure:connector-runtime@2.0.0");
    assert_eq!(lock.wit_sha256.len(), 64);
    assert!(
        lock.wit_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    );
    assert_eq!(lock.business_world.name, "connector-business-plugin");
    assert_eq!(
        lock.business_world.imports,
        ["contracts", "host-control", "business-host"]
    );
    assert_eq!(lock.business_world.exports, ["connector-business"]);
    assert_eq!(lock.security_world.name, "connector-security-plugin");
    assert_eq!(lock.security_world.imports, ["security-broker"]);
    assert_eq!(lock.security_world.exports, ["connector-security"]);

    let operations = [
        BrokeredOperation::InitRegister,
        BrokeredOperation::Register(RegistrationKind::NewIdentity),
        BrokeredOperation::InitPasswordReset,
        BrokeredOperation::PasswordReset,
        BrokeredOperation::InitLogin,
        BrokeredOperation::Login,
        BrokeredOperation::SelectMfa,
        BrokeredOperation::LoginMfa,
        BrokeredOperation::VerifyEmail,
        BrokeredOperation::VerifyPhone,
        BrokeredOperation::VerifyTotp,
        BrokeredOperation::ListAccounts,
        BrokeredOperation::ListCertificates,
        BrokeredOperation::ListKeys,
        BrokeredOperation::Logout,
    ];
    assert_eq!(
        lock.sdk_operations,
        operations
            .into_iter()
            .map(BrokeredOperation::operation_id)
            .collect::<Vec<_>>()
    );
}

#[test]
fn business_source_has_no_raw_secret_or_privileged_broker_api() {
    let business = include_str!("../src/brokered.rs");
    for forbidden in [
        "SecretString",
        "SecretBytes",
        "TransientSecret",
        "RequestMutation",
        "CaptureBroker",
        "SecurityFacade",
    ] {
        assert!(
            !business.contains(forbidden),
            "business source contains privileged type {forbidden}"
        );
    }
    let privileged = include_str!("../src/brokered_security.rs");
    assert!(privileged.contains("TransientSecret"));
    assert!(privileged.contains("CaptureBroker"));
    assert!(!privileged.contains("Transport"));
    assert!(!privileged.contains("ClientConfig"));
}
