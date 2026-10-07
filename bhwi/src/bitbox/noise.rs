//! Noise XX pairing and encrypted BitBox02 session state.
//!
// Ported from bitbox-api-rs (`src/noise.rs` and the handshake driver in `src/lib.rs`),
// Copyright 2023-2025 Shift Crypto AG. Licensed under the Apache License,
// Version 2.0 — see BITBOX_LICENSE at the repository root.

use noise_protocol::{DH, HandshakeState as NoiseHandshakeState, U8Array};
use zeroize::Zeroizing;

use super::error::BitBoxError;

type Cipher = noise_rust_crypto::ChaCha20Poly1305;
type X25519 = noise_rust_crypto::X25519;
type Sha256 = noise_rust_crypto::Sha256;

/// A Noise XX handshake using X25519, ChaCha20-Poly1305, and SHA-256.
pub type HandshakeState = NoiseHandshakeState<X25519, Cipher, Sha256>;
/// A directional Noise transport cipher.
pub type CipherState = noise_protocol::CipherState<Cipher>;

/// Persistable noise-pairing data.
///
/// The host private key is regenerated on demand if `None`. `device_static_pubkeys`
/// holds every BitBox device this host has successfully paired with; a device already
/// in the list can skip the on-screen pairing-code verification.
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct NoiseConfigData {
    /// Cached host static private key, generated on demand when absent.
    pub app_static_privkey: Option<[u8; 32]>,
    /// Static public keys of devices whose pairing was confirmed.
    pub device_static_pubkeys: Vec<Vec<u8>>,
}

impl NoiseConfigData {
    /// Returns whether a device public key is already trusted.
    pub fn contains_device_static_pubkey(&self, pubkey: &[u8]) -> bool {
        self.device_static_pubkeys
            .iter()
            .any(|p| p.as_slice() == pubkey)
    }

    /// Adds a trusted device public key unless it is already present.
    pub fn add_device_static_pubkey(&mut self, pubkey: &[u8]) {
        if !self.contains_device_static_pubkey(pubkey) {
            self.device_static_pubkeys.push(pubkey.to_vec());
        }
    }
}

/// A synchronous callback for displaying a newly available pairing code.
///
/// Invoked before the interpreter requests pairing confirmation on the device.
#[cfg(not(target_arch = "wasm32"))]
pub type PairingCodeHook = Box<dyn FnMut(&str) + Send>;
#[cfg(target_arch = "wasm32")]
pub type PairingCodeHook = Box<dyn FnMut(&str)>;

/// Noise session state retained by callers across interpreter operations.
pub struct NoiseState {
    inner: NoiseInner,
    pairing_code_hook: Option<PairingCodeHook>,
}

/// - `Idle`: pre-handshake or ready to re-handshake with cached data.
/// - `Paired`: cipher states ready; subsequent commands encrypt/decrypt through them.
enum NoiseInner {
    Idle {
        data: NoiseConfigData,
    },
    Paired {
        send: CipherState,
        recv: CipherState,
        data: NoiseConfigData,
        pairing_code: Option<String>,
    },
}

impl NoiseState {
    /// Creates an unpaired session using cached pairing data, or empty data when absent.
    pub fn new(data: Option<NoiseConfigData>) -> Self {
        NoiseState {
            inner: NoiseInner::Idle {
                data: data.unwrap_or_default(),
            },
            pairing_code_hook: None,
        }
    }

    /// Installs a callback invoked when a new pairing code becomes available.
    ///
    /// The callback runs synchronously inside interpreter exchange and must
    /// not block progress of the protocol.
    pub fn set_pairing_code_hook(&mut self, hook: PairingCodeHook) {
        self.pairing_code_hook = Some(hook);
    }

    /// Fire the pairing-code hook if one is installed.
    pub(crate) fn on_pairing_code(&mut self, code: &str) {
        if let Some(hook) = self.pairing_code_hook.as_mut() {
            hook(code);
        }
    }

    /// Returns the pairing data that the caller may persist.
    pub fn data(&self) -> &NoiseConfigData {
        match &self.inner {
            NoiseInner::Idle { data } => data,
            NoiseInner::Paired { data, .. } => data,
        }
    }

    /// Returns the pairing code retained by the paired session, if any.
    pub fn pairing_code(&self) -> Option<&str> {
        match &self.inner {
            NoiseInner::Paired { pairing_code, .. } => pairing_code.as_deref(),
            _ => None,
        }
    }

    /// Returns whether transport cipher states have been installed.
    pub fn is_paired(&self) -> bool {
        matches!(self.inner, NoiseInner::Paired { .. })
    }

    /// Starts a Noise XX handshake and returns its state and initial unframed payload.
    ///
    /// Generates and caches a host static key when absent, so the caller can
    /// persist the updated pairing data.
    pub fn start_handshake(&mut self) -> Result<(HandshakeState, Vec<u8>), BitBoxError> {
        let data = match &mut self.inner {
            NoiseInner::Idle { data } => data,
            NoiseInner::Paired { data, .. } => data,
        };
        let host_static_key: <X25519 as DH>::Key = match data.app_static_privkey {
            Some(k) => noise_rust_crypto::sensitive::Sensitive::from(Zeroizing::new(k)),
            None => {
                let k = X25519::genkey();
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(U8Array::as_slice(&*k));
                data.app_static_privkey = Some(bytes);
                k
            }
        };
        let mut host = HandshakeState::new(
            noise_protocol::patterns::noise_xx(),
            true,
            b"Noise_XX_25519_ChaChaPoly_SHA256",
            Some(host_static_key),
            None,
            None,
            None,
        );
        let msg = host
            .write_message_vec(b"")
            .map_err(|_| BitBoxError::Noise("write handshake 1"))?;
        Ok((host, msg))
    }

    /// Reads the device's handshake message and produces the host's final handshake message.
    pub fn handshake_read_write(
        host: &mut HandshakeState,
        bb02_msg: &[u8],
    ) -> Result<Vec<u8>, BitBoxError> {
        host.read_message_vec(bb02_msg)
            .map_err(|_| BitBoxError::Noise("read handshake"))?;
        host.write_message_vec(b"")
            .map_err(|_| BitBoxError::Noise("write handshake 2"))
    }

    /// Returns the device's pairing-verification flag and remote static public key.
    ///
    /// The flag is true only when the acknowledgement bytes equal `[0x01]`.
    pub fn handshake_finalize(
        host: &mut HandshakeState,
        bb02_msg: &[u8],
    ) -> Result<(bool, Vec<u8>), BitBoxError> {
        let device_wants_verify = bb02_msg == [0x01];
        let remote_static = host
            .get_rs()
            .ok_or(BitBoxError::Noise("no remote static key"))?;
        Ok((device_wants_verify, remote_static.to_vec()))
    }

    /// Formats the first 20 base32 characters of the handshake hash as a pairing code.
    ///
    /// Expects a 32-byte Noise handshake hash.
    ///
    /// # Panics
    ///
    /// Panics if padded base32 encoding produces fewer than 20 characters.
    pub fn pairing_code_from_hash(hash: &[u8]) -> String {
        let encoded = base32_rfc4648(hash);
        format!(
            "{} {}\n{} {}",
            &encoded[0..5],
            &encoded[5..10],
            &encoded[10..15],
            &encoded[15..20],
        )
    }

    /// Installs transport ciphers from a completed handshake.
    ///
    /// The caller must finish the handshake before calling this method.
    pub fn finalize(
        &mut self,
        host: HandshakeState,
        pairing_code: Option<String>,
    ) -> Result<(), BitBoxError> {
        let data = match &mut self.inner {
            NoiseInner::Idle { data } => std::mem::take(data),
            NoiseInner::Paired { data, .. } => std::mem::take(data),
        };
        let (send, recv) = host.get_ciphers();
        self.inner = NoiseInner::Paired {
            send,
            recv,
            data,
            pairing_code,
        };
        Ok(())
    }

    /// Adds a caller-confirmed device public key to the cached pairing data.
    pub fn confirm_pairing(&mut self, device_pubkey: &[u8]) -> Result<(), BitBoxError> {
        let data = match &mut self.inner {
            NoiseInner::Idle { data } => data,
            NoiseInner::Paired { data, .. } => data,
        };
        data.add_device_static_pubkey(device_pubkey);
        Ok(())
    }

    /// Encrypts a message and advances the send cipher, or errors when unpaired.
    pub fn encrypt(&mut self, msg: &[u8]) -> Result<Vec<u8>, BitBoxError> {
        match &mut self.inner {
            NoiseInner::Paired { send, .. } => Ok(send.encrypt_vec(msg)),
            _ => Err(BitBoxError::Noise("not paired")),
        }
    }

    /// Authenticates and decrypts a message, or errors when unpaired or authentication fails.
    pub fn decrypt(&mut self, msg: &[u8]) -> Result<Vec<u8>, BitBoxError> {
        match &mut self.inner {
            NoiseInner::Paired { recv, .. } => recv
                .decrypt_vec(msg)
                .map_err(|_| BitBoxError::Noise("decrypt")),
            _ => Err(BitBoxError::Noise("not paired")),
        }
    }
}

/// Minimal RFC 4648 base32 encoder (upper-case alphabet, padded).
///
/// Written inline so bhwi's `bitbox` feature does not depend on the `base32` crate;
/// the input is only ever a 32-byte handshake hash, so the code path is trivial.
fn base32_rfc4648(input: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::with_capacity(input.len().div_ceil(5) * 8);
    let mut buffer: u64 = 0;
    let mut bits: u32 = 0;
    for &byte in input {
        buffer = (buffer << 8) | byte as u64;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1f) as usize;
            out.push(ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(ALPHABET[idx] as char);
    }
    while !out.len().is_multiple_of(8) {
        out.push('=');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_matches_reference() {
        // RFC 4648 §10 test vectors.
        assert_eq!(base32_rfc4648(b"f"), "MY======");
        assert_eq!(base32_rfc4648(b"fo"), "MZXQ====");
        assert_eq!(base32_rfc4648(b"foo"), "MZXW6===");
        assert_eq!(base32_rfc4648(b"foobar"), "MZXW6YTBOI======");
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn pairing_callback_survives_moving_noise_state_to_thread() {
        let (send, recv) = std::sync::mpsc::channel();
        let mut calls = 0;
        let mut noise = NoiseState::new(None);
        noise.set_pairing_code_hook(Box::new(move |code| {
            calls += 1;
            send.send((calls, code.to_owned())).unwrap();
        }));
        let code = NoiseState::pairing_code_from_hash(&[0; 32]);
        let expected = code.clone();
        std::thread::spawn(move || {
            noise.on_pairing_code(&code);
            noise.on_pairing_code(&code);
        })
        .join()
        .unwrap();
        assert_eq!(
            recv.into_iter().collect::<Vec<_>>(),
            vec![(1, expected.clone()), (2, expected)]
        );
    }
}
