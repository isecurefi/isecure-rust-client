use std::{collections::BTreeSet, fs, path::PathBuf};

use isecure_rust_client::{OBSERVED_EXTENSION_OPERATIONS, OPENAPI_OPERATIONS};
use serde_json::Value;
use sha2::{Digest, Sha256};

const EXPECTED_SHA256: &str = "f36607360bac5c32f8b532691fdddc22eb809760ed9986678383d6dcb08d0004";
const EXPECTED_BYTES: usize = 117_245;

#[test]
fn pinned_openapi_bytes_and_operation_coverage_are_exact() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let bytes = fs::read(root.join("contracts/wsapi_v2.json")).expect("pinned OpenAPI bytes");
    assert_eq!(bytes.len(), EXPECTED_BYTES);
    assert_eq!(format!("{:x}", Sha256::digest(&bytes)), EXPECTED_SHA256);

    let contract: Value = serde_json::from_slice(&bytes).expect("valid OpenAPI JSON");
    assert_eq!(contract["swagger"], "2.0");
    let mut operations = BTreeSet::new();
    for path in contract["paths"].as_object().expect("paths").values() {
        for operation in path.as_object().expect("path operations").values() {
            operations.insert(
                operation["operationId"]
                    .as_str()
                    .expect("operationId")
                    .to_owned(),
            );
        }
    }
    let implemented = OPENAPI_OPERATIONS
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(implemented, operations);
}

#[test]
fn every_openapi_schema_shape_remains_accounted_for() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let contract: Value = serde_json::from_slice(
        &fs::read(root.join("contracts/wsapi_v2.json")).expect("pinned OpenAPI bytes"),
    )
    .expect("OpenAPI JSON");
    let names = contract["definitions"]
        .as_object()
        .expect("definitions")
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected = [
        "AccountDescriptor",
        "BankConnectionCertificateDescriptor",
        "BankConnectionDescriptor",
        "CertDescriptor",
        "CertsAndKeys",
        "ConfigCertsReq",
        "DeleteKeyReq",
        "DownloadFileResp",
        "EnrollCertReq",
        "ErrorResponse",
        "ExportCertResp",
        "FileDescriptor",
        "ImportCertReq",
        "InitLoginResp",
        "InitRegisterResp",
        "ListAccountsResp",
        "ListCertsResp",
        "ListFilesResp",
        "ListKeysResp",
        "LoginMFAReq",
        "LoginMFAResp",
        "LoginReq",
        "LoginResp",
        "PasswordResetReq",
        "PgpKeyDescriptor",
        "RegisterReq",
        "RegisterResp",
        "Response",
        "ShareCertsResp",
        "UnshareCertsResp",
        "UploadFileReq",
        "UploadKeyReq",
        "VerifyEmailReq",
        "VerifyPhoneReq",
        "VerifyTOTPReq",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    assert_eq!(names, expected);

    assert!(
        contract["definitions"]
            .as_object()
            .expect("definitions")
            .values()
            .all(|definition| definition["type"] == "object")
    );
}

#[test]
fn observed_extensions_are_separate_and_exact() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let extensions: Value = serde_json::from_slice(
        &fs::read(root.join("contracts/observed-extensions.json")).expect("extension contract"),
    )
    .expect("extension JSON");
    let operations = extensions["extensions"]
        .as_array()
        .expect("extensions")
        .iter()
        .map(|value| value["operation_id"].as_str().expect("operation ID"))
        .collect::<Vec<_>>();
    assert_eq!(operations, OBSERVED_EXTENSION_OPERATIONS);
    assert_eq!(
        extensions["extensions"][0]["path"],
        "/session/{Email}/{Mode}/selectmfa"
    );
    assert_eq!(extensions["wire_deviations"][0]["field"], "ExpiresIn");
    assert_eq!(
        extensions["wire_deviations"][0]["observed_gpgtest_types"],
        serde_json::json!(["number", "string"])
    );
}
