use base64::{Engine as _, engine::general_purpose::STANDARD};
use isecure_rust_client::{ChallengeEncryptor, ProtocolError, RsaChallengeEncryptor, SecretString};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey, pkcs1::EncodeRsaPublicKey, pkcs8::EncodePublicKey};
use sha1::Sha1;

const CHALLENGE: &str = "challenge-bytes|1475429754114|4017bda8-0a15-4154-a8b7-88069b05cb4e";

#[test]
fn encrypts_spki_and_pkcs1_keys_with_exact_oaep_sha1_plaintext() {
    let mut key_rng = ChaCha20Rng::from_seed([7; 32]);
    let private = RsaPrivateKey::new(&mut key_rng, 2048).expect("RSA key");
    let public = RsaPublicKey::from(&private);
    let spki = public
        .to_public_key_pem(Default::default())
        .expect("SPKI PEM");
    let pkcs1 = public.to_pkcs1_pem(Default::default()).expect("PKCS1 PEM");

    for pem in [spki.as_str(), pkcs1.as_str()] {
        let mut encryptor = RsaChallengeEncryptor::new(ChaCha20Rng::from_seed([9; 32]));
        let encrypted = encryptor
            .encrypt(
                pem,
                &SecretString::new(CHALLENGE),
                &SecretString::new("Example-password-123!"),
            )
            .expect("encrypt");
        let bytes = STANDARD
            .decode(encrypted.expose_secret())
            .expect("Base64 ciphertext");
        let plaintext = private
            .decrypt(Oaep::new::<Sha1>(), &bytes)
            .expect("decrypt");
        assert_eq!(plaintext, b"Example-password-123!||1475429754114");
    }
}

#[test]
fn rejects_malformed_challenge_and_key() {
    let mut encryptor = RsaChallengeEncryptor::new(ChaCha20Rng::from_seed([1; 32]));
    assert!(matches!(
        encryptor.encrypt(
            "not PEM",
            &SecretString::new("missing-timestamp"),
            &SecretString::new("password"),
        ),
        Err(ProtocolError::InvalidChallenge)
    ));
    assert!(matches!(
        encryptor.encrypt(
            "not PEM",
            &SecretString::new(CHALLENGE),
            &SecretString::new("password"),
        ),
        Err(ProtocolError::InvalidPublicKey)
    ));
}
