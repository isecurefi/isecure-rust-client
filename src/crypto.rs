//! ISECure RSA-OAEP challenge encryption.

use alloc::vec::Vec;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use rand_core::CryptoRngCore;
use rsa::traits::PublicKeyParts;
use rsa::{Oaep, RsaPublicKey, pkcs1::DecodeRsaPublicKey, pkcs8::DecodePublicKey};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{ProtocolError, SecretString};

/// Explicit additive password profile. No automatic fallback is permitted.
pub const PASSWORD_ENCRYPTION_PROFILE: &str = "password-rsa-oaep-sha256-v1";

/// Injected password/challenge encryption capability.
pub trait ChallengeEncryptor {
    /// Encrypts the challenge-bound binary envelope with SHA-256 OAEP and MGF1.
    /// Existing injected encryptors must opt in; the default refuses this profile.
    fn encrypt_profile(
        &mut self,
        _public_key_pem: &str,
        _challenge: &SecretString,
        _password: &SecretString,
    ) -> Result<SecretString, ProtocolError> {
        Err(ProtocolError::InvalidConfiguration)
    }

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
    fn encrypt_profile(
        &mut self,
        public_key_pem: &str,
        challenge: &SecretString,
        password: &SecretString,
    ) -> Result<SecretString, ProtocolError> {
        validate_profile_challenge(challenge.expose_secret())?;
        let raw = password.expose_secret().as_bytes();
        if raw.is_empty() || raw.len() > 283 {
            return Err(ProtocolError::InvalidConfiguration);
        }
        let key = RsaPublicKey::from_public_key_pem(public_key_pem)
            .map_err(|_| ProtocolError::InvalidPublicKey)?;
        if !matches!(key.n().bits(), 3072 | 4096) || key.e() != &rsa::BigUint::from(65537_u32) {
            return Err(ProtocolError::InvalidPublicKey);
        }
        let mut plaintext = Zeroizing::new(Vec::with_capacity(35 + raw.len()));
        plaintext.push(1);
        plaintext.extend_from_slice(&Sha256::digest(challenge.expose_secret().as_bytes()));
        plaintext.extend_from_slice(&(raw.len() as u16).to_be_bytes());
        plaintext.extend_from_slice(raw);
        // rsa::Oaep selects SHA256 for both digests and an empty label.
        let encrypted = key
            .encrypt(&mut self.rng, Oaep::new::<Sha256>(), &plaintext)
            .map_err(|_| ProtocolError::InvalidPublicKey)?;
        Ok(SecretString::new(STANDARD.encode(encrypted)))
    }

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

pub(crate) fn validate_profile_challenge(challenge: &str) -> Result<(), ProtocolError> {
    let parts: Vec<_> = challenge.split('.').collect();
    if challenge.len() > 3072
        || parts.len() != 4
        || parts[0] != "p1"
        || parts[1..].iter().any(|part| {
            part.is_empty()
                || !part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        })
    {
        return Err(ProtocolError::InvalidChallenge);
    }
    Ok(())
}
