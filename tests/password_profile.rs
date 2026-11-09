use base64::{Engine as _, engine::general_purpose::STANDARD};
use isecure_rust_client::{ChallengeEncryptor, RsaChallengeEncryptor, SecretString};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use rsa::{Oaep, RsaPrivateKey, pkcs8::DecodePrivateKey};
use sha2::Sha256;
#[test]
fn shared_3072_and_4096_vectors_interoperate() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/password-profile/vectors.json")).unwrap();
    for case in vectors["Cases"].as_array().unwrap() {
        let key = vectors["Keys"]
            .as_array()
            .unwrap()
            .iter()
            .find(|k| k["KeyId"] == case["KeyId"])
            .unwrap();
        let mut encryptor = RsaChallengeEncryptor::new(ChaCha20Rng::from_seed([42; 32]));
        let challenge = SecretString::new(case["Challenge"].as_str().unwrap());
        let password = SecretString::new(case["Password"].as_str().unwrap());
        let cipher = encryptor
            .encrypt_profile(key["PublicKey"].as_str().unwrap(), &challenge, &password)
            .unwrap();
        let private = RsaPrivateKey::from_pkcs8_pem(key["PrivateKey"].as_str().unwrap()).unwrap();
        let plain = private
            .decrypt(
                Oaep::new::<Sha256>(),
                &STANDARD.decode(cipher.expose_secret()).unwrap(),
            )
            .unwrap();
        let hex: String = plain.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, case["FrameHex"]);
        for invalid in [String::new(), "x".repeat(284)] {
            assert!(
                encryptor
                    .encrypt_profile(
                        key["PublicKey"].as_str().unwrap(),
                        &challenge,
                        &SecretString::new(invalid)
                    )
                    .is_err()
            );
        }
    }
}
