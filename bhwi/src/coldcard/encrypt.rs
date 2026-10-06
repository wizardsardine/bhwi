//! Coldcard ECDH key agreement and stateful AES-256-CTR encryption.
//!
//! AES-CTR provides confidentiality, not authenticated encryption.

use aes::cipher::{KeyIvInit, StreamCipher, generic_array::GenericArray};
use bitcoin::hashes::{Hash, sha256};
use k256::elliptic_curve::{Error, sec1::ToEncodedPoint};
pub use k256::schnorr::CryptoRngCore;

use crate::coldcard::ColdcardError;

/// A Coldcard session before or after key agreement.
pub enum Engine {
    /// A fresh host secret key awaiting the device public key.
    New(
        /// Host ephemeral secret key.
        k256::SecretKey,
    ),
    /// Initialized, independent send and receive cipher streams.
    Ready(
        /// Initialized send and receive streams.
        Box<InitializedEngine>,
    ),
}

/// Stateful AES-256-CTR send and receive ciphers.
pub struct InitializedEngine {
    encrypt: ctr::Ctr64BE<aes::Aes256>,
    decrypt: ctr::Ctr64BE<aes::Aes256>,
}

impl Engine {
    /// Generates a host key for a new session using the supplied random source.
    pub fn new(rng: &mut impl CryptoRngCore) -> Self {
        Self::New(k256::SecretKey::random(rng))
    }

    /// Initializes cipher streams from the device's unprefixed 64-byte public key.
    ///
    /// Returns an error unless the engine is [`Self::New`] and the key is valid.
    pub fn ready(&mut self, public_key: [u8; 64]) -> Result<(), ColdcardError> {
        if let Engine::New(secret_key) = self {
            let mut prefixed_pubkey = [0_u8; 65];
            prefixed_pubkey[0] = 0x04;
            prefixed_pubkey[1..].copy_from_slice(&public_key);

            let public_key = k256::PublicKey::from_sec1_bytes(&prefixed_pubkey)
                .map_err(|_| ColdcardError::Encryption("from_sec1_bytes"))?;
            let session_key = session_key(secret_key, public_key)
                .map_err(|_| ColdcardError::Encryption("session_key"))?;
            let key = GenericArray::from_slice(&session_key);
            let nonce = GenericArray::from_slice(&[0_u8; 16]);
            *self = Self::Ready(Box::new(InitializedEngine {
                encrypt: ctr::Ctr64BE::<aes::Aes256>::new(key, nonce),
                decrypt: ctr::Ctr64BE::<aes::Aes256>::new(key, nonce),
            }));
            Ok(())
        } else {
            Err(ColdcardError::Encryption("Engine is not New"))
        }
    }

    /// Returns the host's unprefixed 64-byte public key while the engine is [`Self::New`].
    pub fn pub_key(&self) -> Result<[u8; 64], ColdcardError> {
        if let Engine::New(key) = self {
            key.public_key()
                .as_affine()
                .to_encoded_point(false)
                .as_bytes()[1..]
                .try_into()
                .map_err(|_| ColdcardError::Encryption("failed to create pubkey"))
        } else {
            Err(ColdcardError::Encryption("Engine is not new"))
        }
    }

    /// Encrypts bytes and advances the send stream, or errors unless ready.
    pub fn encrypt(&mut self, mut data: Vec<u8>) -> Result<Vec<u8>, ColdcardError> {
        match self {
            Self::Ready(engine) => {
                engine.encrypt.apply_keystream(&mut data);
                Ok(data)
            }
            Self::New(..) => Err(ColdcardError::Encryption("Engine not ready")),
        }
    }

    /// Decrypts bytes and advances the receive stream, or errors unless ready.
    ///
    /// Decryption does not authenticate the ciphertext.
    pub fn decrypt(&mut self, mut data: Vec<u8>) -> Result<Vec<u8>, ColdcardError> {
        match self {
            Self::Ready(engine) => {
                engine.decrypt.apply_keystream(&mut data);
                Ok(data)
            }
            Self::New(..) => Err(ColdcardError::Encryption("Engine not ready")),
        }
    }
}

/// Derives the Coldcard session key by hashing the unprefixed ECDH point.
pub fn session_key(sk: &k256::SecretKey, pk: k256::PublicKey) -> Result<[u8; 32], Error> {
    let tweaked_pk = *pk.as_affine() * *sk.to_nonzero_scalar();
    let tweaked_pk = k256::PublicKey::from_affine(tweaked_pk.to_affine())?;
    let pt = tweaked_pk.to_encoded_point(false);
    Ok(sha256::Hash::hash(&pt.as_bytes()[1..]).to_byte_array())
}
