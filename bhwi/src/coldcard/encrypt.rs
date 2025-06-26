use aes::cipher::{generic_array::GenericArray, KeyIvInit, StreamCipher};
use bitcoin::hashes::{sha256, Hash};
use k256::elliptic_curve::{sec1::ToEncodedPoint, Error};

pub struct Engine {
    encrypt: ctr::Ctr64BE<aes::Aes256>,
    decrypt: ctr::Ctr64BE<aes::Aes256>,
}

impl Engine {
    pub fn new(session_key: [u8; 32]) -> Self {
        let key = GenericArray::from_slice(&session_key);
        let nonce = GenericArray::from_slice(&[0_u8; 16]);
        Self {
            encrypt: ctr::Ctr64BE::<aes::Aes256>::new(key, nonce),
            decrypt: ctr::Ctr64BE::<aes::Aes256>::new(key, nonce),
        }
    }
    pub fn encrypt(&mut self, mut data: Vec<u8>) -> Vec<u8> {
        self.encrypt.apply_keystream(&mut data);
        data
    }
    pub fn decrypt(&mut self, mut data: Vec<u8>) -> Vec<u8> {
        self.decrypt.apply_keystream(&mut data);
        data
    }
}

pub fn session_key(sk: k256::SecretKey, pk: k256::PublicKey) -> Result<[u8; 32], Error> {
    let tweaked_pk = *pk.as_affine() * *sk.to_nonzero_scalar();
    let tweaked_pk = k256::PublicKey::from_affine(tweaked_pk.to_affine())?;
    let pt = tweaked_pk.to_encoded_point(false);
    Ok(sha256::Hash::hash(&pt.as_bytes()[1..]).to_byte_array())
}
