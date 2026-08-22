//! ISECure RSA-OAEP challenge encryption.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use rand_core::CryptoRngCore;
use rsa::{Oaep, RsaPublicKey, pkcs1::DecodeRsaPublicKey, pkcs8::DecodePublicKey};
use sha1::Sha1;
use zeroize::Zeroizing;

use crate::{ProtocolError, SecretString};

/// Injected password/challenge encryption capability.
pub trait ChallengeEncryptor {
    /// Encrypts `password || "||" || challenge_timestamp` using RSA-OAEP SHA-1.
    fn encrypt(
        &mut self,
        public_key_pem: &str,
        challenge: &SecretString,
        password: &SecretString,
    ) -> Result<SecretString, ProtocolError>;
}

/// Exact ISECure RSA-OAEP SHA-1 challenge encryptor using caller-provided randomness.
pub struct RsaChallengeEncryptor<R> {
    rng: R,
}

impl<R> RsaChallengeEncryptor<R> {
    /// Creates an encryptor. WebAssembly hosts should inject their bounded
    /// randomness capability; native callers may inject an OS RNG.
    pub const fn new(rng: R) -> Self {
        Self { rng }
    }

    /// Returns the owned RNG, primarily for deterministic qualification tests.
    pub fn into_inner(self) -> R {
        self.rng
    }
}

impl<R: CryptoRngCore> ChallengeEncryptor for RsaChallengeEncryptor<R> {
    fn encrypt(
        &mut self,
        public_key_pem: &str,
        challenge: &SecretString,
        password: &SecretString,
    ) -> Result<SecretString, ProtocolError> {
        let timestamp = challenge
            .expose_secret()
            .split('|')
            .nth(1)
            .filter(|value| !value.is_empty())
            .ok_or(ProtocolError::InvalidChallenge)?;
        let key = RsaPublicKey::from_public_key_pem(public_key_pem)
            .or_else(|_| RsaPublicKey::from_pkcs1_pem(public_key_pem))
            .map_err(|_| ProtocolError::InvalidPublicKey)?;
        let mut plaintext = Zeroizing::new(Vec::with_capacity(
            password.expose_secret().len() + timestamp.len() + 2,
        ));
        plaintext.extend_from_slice(password.expose_secret().as_bytes());
        plaintext.extend_from_slice(b"||");
        plaintext.extend_from_slice(timestamp.as_bytes());
        let encrypted = key
            .encrypt(&mut self.rng, Oaep::new::<Sha1>(), &plaintext)
            .map_err(|_| ProtocolError::InvalidPublicKey)?;
        Ok(SecretString::new(STANDARD.encode(encrypted)))
    }
}
