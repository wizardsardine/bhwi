use core::marker::PhantomData;

use bitcoin::Network;
use bitcoin::bip32::Fingerprint;
use bitcoin::psbt::Psbt;
use prost::Message;

use crate::Interpreter;
use crate::common::HostRequest;
use crate::keepkey::{HostPassphrase, KEEPKEY_LOCKED, api, proto};
use crate::miniscript::descriptor::DescriptorPublicKey;
use crate::trezor::error::TrezorError;
use crate::trezor::interpreter::{
    DeviceFeatures, Engine, EngineCommand, EngineTransmit, Profile, RestoreCtx, SetupCtx,
    TrezorMultisigAddress, TrezorResponse,
};
use crate::trezor::proto::{bitcoin as btc, common as pb};

pub enum KeepKeyCommand {
    Initialize(Option<Network>),
    GetFeatures,
    GetMasterFingerprint,
    GetXpub {
        address_n: Vec<u32>,
        display: bool,
    },
    GetAddress {
        address_n: Vec<u32>,
        display: bool,
        script_type: btc::InputScriptType,
    },
    GetMultisigAddress(TrezorMultisigAddress),
    SignMessage {
        address_n: Vec<u32>,
        message: Vec<u8>,
    },
    SignTx(Box<Psbt>),
    Wipe,
    TogglePassphrase,
    Setup {
        label: Option<String>,
        host_entropy: [u8; 32],
    },
    Restore {
        label: Option<String>,
        word_count: u32,
        u2f_counter: u32,
    },
    PromptPin,
    SendPin(crate::trezor::HostPin),
}

impl From<KeepKeyCommand> for EngineCommand {
    fn from(command: KeepKeyCommand) -> Self {
        match command {
            KeepKeyCommand::Initialize(network) => Self::Initialize(network),
            KeepKeyCommand::GetFeatures => Self::GetFeatures,
            KeepKeyCommand::GetMasterFingerprint => Self::GetMasterFingerprint,
            KeepKeyCommand::GetXpub { address_n, display } => Self::GetXpub { address_n, display },
            KeepKeyCommand::GetAddress {
                address_n,
                display,
                script_type,
            } => Self::GetAddress {
                address_n,
                display,
                script_type,
            },
            KeepKeyCommand::GetMultisigAddress(address) => Self::GetMultisigAddress(address),
            KeepKeyCommand::SignMessage { address_n, message } => {
                Self::SignMessage { address_n, message }
            }
            KeepKeyCommand::SignTx(psbt) => Self::SignTx(psbt),
            KeepKeyCommand::Wipe => Self::Wipe,
            KeepKeyCommand::TogglePassphrase => Self::TogglePassphrase,
            KeepKeyCommand::Setup {
                label,
                host_entropy,
            } => Self::Setup {
                label,
                host_entropy,
            },
            KeepKeyCommand::Restore {
                label,
                word_count,
                u2f_counter,
            } => Self::Restore {
                label,
                word_count,
                u2f_counter,
            },
            KeepKeyCommand::PromptPin => Self::PromptPin,
            KeepKeyCommand::SendPin(pin) => Self::SendPin(pin),
        }
    }
}

pub(crate) struct KeepKeyProfile;

impl Profile for KeepKeyProfile {
    const HOST_MANAGEMENT: bool = true;
    const CHARACTER_CIPHER: bool = true;
    const TOGGLE_PENDING_PIN: bool = true;
    const EXTERNAL_INPUTS: bool = true;
    const DEFAULT_ON_DEVICE_PASSPHRASE: bool = false;
    fn pin_failure_needs_features(failure: &pb::Failure) -> bool {
        failure.code == Some(pb::failure::FailureType::FailureUnexpectedMessage as i32)
    }

    fn coin_name(network: Network) -> String {
        if network == Network::Bitcoin {
            "Bitcoin"
        } else {
            "Testnet"
        }
        .into()
    }

    fn decode_features(payload: &[u8]) -> Result<DeviceFeatures, TrezorError> {
        let features = proto::Features::decode(payload)?;
        if !features
            .vendor
            .as_deref()
            .is_some_and(|vendor| vendor.contains("keepkey"))
        {
            return Err(TrezorError::InvalidInput(
                "device features vendor is not KeepKey".into(),
            ));
        }
        Ok(DeviceFeatures {
            major_version: features.major_version.unwrap_or_default(),
            minor_version: features.minor_version.unwrap_or_default(),
            patch_version: features.patch_version.unwrap_or_default(),
            pin_protection: features.pin_protection.unwrap_or(false),
            passphrase_protection: features.passphrase_protection.unwrap_or(false),
            label: features.label,
            initialized: features.initialized,
            unlocked: features.pin_cached.unwrap_or(false),
            model: features.model.or(features.firmware_variant),
            on_device_passphrase_entry: false,
        })
    }

    fn get_public_key(
        address_n: Vec<u32>,
        show_display: bool,
        _script_type: btc::InputScriptType,
        coin_name: String,
    ) -> Vec<u8> {
        api::get_public_key(address_n, show_display, coin_name)
    }

    fn sign_message(address_n: Vec<u32>, message: Vec<u8>, coin_name: String) -> Vec<u8> {
        api::sign_message(address_n, message, coin_name)
    }

    fn passphrase_ack(_on_device: bool, passphrase: &str) -> Vec<u8> {
        api::passphrase_ack_from_host(passphrase)
    }

    fn passphrase_too_long(passphrase: &HostPassphrase) -> bool {
        passphrase.is_too_long() || passphrase.as_str().len() > crate::trezor::MAX_PASSPHRASE_LENGTH
    }

    fn reset_device(_features: &DeviceFeatures, context: SetupCtx) -> Result<Vec<u8>, TrezorError> {
        Ok(api::reset_device(
            context.passphrase_protection,
            context.label,
        ))
    }

    fn recovery_device(
        _features: &DeviceFeatures,
        context: RestoreCtx,
    ) -> Result<Vec<u8>, TrezorError> {
        Ok(api::recovery_device(
            context.word_count,
            context.passphrase_protection,
            context.label,
            context.u2f_counter,
        ))
    }

    fn locked_message() -> &'static str {
        KEEPKEY_LOCKED
    }

    fn validate_command(command: &EngineCommand) -> Result<(), TrezorError> {
        match command {
            EngineCommand::GetAddress {
                script_type: btc::InputScriptType::Spendtaproot,
                ..
            } => Err(TrezorError::UnsupportedDisplayAddress(
                "KeepKey does not support Taproot address display",
            )),
            EngineCommand::GetMultisigAddress(address) if !address.sorted => {
                Err(TrezorError::UnsupportedDisplayAddress(
                    "KeepKey does not support unsorted multisig address display",
                ))
            }
            EngineCommand::GetMultisigAddress(address)
                if address
                    .keys
                    .iter()
                    .any(|key| !matches!(key, DescriptorPublicKey::Single(_))) =>
            {
                Err(TrezorError::UnsupportedDisplayAddress(
                    "KeepKey multisig address display requires fully-derived public keys",
                ))
            }
            _ => Ok(()),
        }
    }

    fn validate_psbt(psbt: &Psbt, master_fp: Fingerprint) -> Result<(), TrezorError> {
        validate_keepkey_psbt(psbt, master_fp)
    }

    fn decode_character_request(payload: &[u8]) -> Result<HostRequest, TrezorError> {
        let request = proto::CharacterRequest::decode(payload)?;
        Ok(HostRequest::RecoveryCharacter {
            word_position: request.word_pos,
            character_position: request.character_pos,
        })
    }

    fn character_ack(value: u8) -> Result<Vec<u8>, TrezorError> {
        Ok(api::character_ack(value))
    }
}

fn validate_keepkey_psbt(psbt: &Psbt, master_fp: Fingerprint) -> Result<(), TrezorError> {
    if psbt.inputs.len() != psbt.unsigned_tx.input.len()
        || psbt.outputs.len() != psbt.unsigned_tx.output.len()
    {
        return Err(TrezorError::InvalidInput(
            "PSBT maps do not match the unsigned transaction".into(),
        ));
    }
    for (input, txin) in psbt.inputs.iter().zip(&psbt.unsigned_tx.input) {
        let utxo = input.witness_utxo.as_ref().or_else(|| {
            input
                .non_witness_utxo
                .as_ref()
                .and_then(|tx| tx.output.get(txin.previous_output.vout as usize))
        });
        let owned_taproot = input
            .tap_key_origins
            .values()
            .any(|(_, (fingerprint, _))| *fingerprint == master_fp);
        if owned_taproot
            && (input.tap_internal_key.is_some()
                || utxo.is_some_and(|txout| txout.script_pubkey.is_p2tr()))
        {
            return Err(TrezorError::Unsupported(
                "KeepKey does not support Taproot inputs",
            ));
        }
    }
    for (txout, output) in psbt.unsigned_tx.output.iter().zip(&psbt.outputs) {
        let owned_taproot = output
            .tap_key_origins
            .values()
            .any(|(_, (fingerprint, _))| *fingerprint == master_fp);
        if txout.script_pubkey.is_p2tr() && owned_taproot {
            return Err(TrezorError::Unsupported(
                "KeepKey does not support Taproot change outputs",
            ));
        }
    }
    Ok(())
}

pub struct KeepKeyInterpreter<C, T, R, E> {
    engine: Engine<KeepKeyProfile>,
    _marker: PhantomData<(C, T, R, E)>,
}

impl<C, T, R, E> Default for KeepKeyInterpreter<C, T, R, E> {
    fn default() -> Self {
        Self {
            engine: Engine::default(),
            _marker: PhantomData,
        }
    }
}

impl<C, T, R, E> KeepKeyInterpreter<C, T, R, E> {
    pub fn with_network(mut self, network: Network) -> Self {
        self.engine = self.engine.with_network(network);
        self
    }

    pub fn with_passphrase(mut self, passphrase: Option<HostPassphrase>) -> Self {
        self.engine = self.engine.with_passphrase(passphrase);
        self
    }
}

impl<C, T, R, E> Interpreter for KeepKeyInterpreter<C, T, R, E>
where
    C: TryInto<KeepKeyCommand, Error = TrezorError>,
    T: From<Vec<u8>> + From<HostRequest>,
    R: From<TrezorResponse>,
    E: From<TrezorError>,
{
    type Command = C;
    type Transmit = T;
    type Response = R;
    type Error = E;

    fn start(&mut self, command: C) -> Result<T, E> {
        let command = command.try_into().map_err(E::from)?;
        Ok(match self.engine.start(command.into()).map_err(E::from)? {
            EngineTransmit::Device(bytes) => T::from(bytes),
            EngineTransmit::Host(request) => T::from(request),
        })
    }

    fn exchange(&mut self, data: Vec<u8>) -> Result<Option<T>, E> {
        Ok(match self.engine.exchange(data).map_err(E::from)? {
            Some(EngineTransmit::Device(bytes)) => Some(T::from(bytes)),
            Some(EngineTransmit::Host(request)) => Some(T::from(request)),
            None => None,
        })
    }

    fn end(self) -> Result<R, E> {
        self.engine.end().map(R::from).map_err(E::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{
        self, Command, DeviceContext, DisplayAddress, Error, HostResponse, MultisigAddressType,
        MultisigDisplayAddress, Recipient, Response, Transmit,
    };
    use crate::keepkey::ManagementContext;
    use crate::trezor::proto::{common as pb, management as mgmt};
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

    type Interp = KeepKeyInterpreter<Command, Transmit, Response, Error>;

    fn framed<M: Message>(message_type: api::MessageType, message: &M) -> Vec<u8> {
        api::frame(message_type as u16, &message.encode_to_vec())
    }

    fn features() -> proto::Features {
        proto::Features {
            vendor: Some("keepkey.com".into()),
            major_version: Some(7),
            minor_version: Some(10),
            patch_version: Some(0),
            pin_protection: Some(true),
            passphrase_protection: Some(true),
            label: Some("test".into()),
            initialized: Some(false),
            pin_cached: Some(false),
            model: Some("K1-14AM".into()),
            firmware_variant: Some("keepkey".into()),
        }
    }

    fn device_frame(transmit: Transmit) -> (u16, Vec<u8>) {
        assert!(matches!(transmit.recipient, Recipient::Device));
        api::parse_frame(&transmit.payload).unwrap()
    }

    fn host_request(transmit: Transmit) -> common::HostRequest {
        match transmit.recipient {
            Recipient::Host(request) => {
                assert!(transmit.payload.is_empty());
                assert!(!transmit.encrypted);
                request
            }
            _ => panic!("expected host request"),
        }
    }

    fn pin_request(kind: i32) -> Vec<u8> {
        framed(
            api::MessageType::PinMatrixRequest,
            &pb::PinMatrixRequest { r#type: Some(kind) },
        )
    }

    fn success() -> Vec<u8> {
        framed(api::MessageType::Success, &pb::Success::default())
    }

    fn master_public_key(fingerprint: u32) -> Vec<u8> {
        framed(
            api::MessageType::PublicKey,
            &btc::PublicKey {
                node: pb::HdNodeType {
                    depth: 0,
                    fingerprint: 0,
                    child_num: 0,
                    chain_code: vec![0; 32],
                    private_key: None,
                    public_key: vec![0; 33],
                },
                xpub: String::new(),
                root_fingerprint: Some(fingerprint),
                descriptor: None,
            },
        )
    }

    #[test]
    fn features_are_validated_and_normalized_for_keepkey() {
        let mut interp = Interp::default().with_network(Network::Signet);
        interp.start(Command::GetVersion).unwrap();
        assert!(
            interp
                .exchange(framed(api::MessageType::Features, &features()))
                .unwrap()
                .is_none()
        );
        let Response::Info(info) = interp.end().unwrap() else {
            panic!("expected info")
        };
        assert_eq!(info.version, "7.10.0");
        assert_eq!(info.networks, [Network::Signet]);
        assert_eq!(info.firmware.as_deref(), Some("K1-14AM"));
        assert_eq!(info.label.as_deref(), Some("test"));
        assert_eq!(info.needs_pin_sent, Some(true));
        assert_eq!(info.on_device_passphrase_entry, Some(false));
        assert_eq!(info.needs_passphrase_sent, Some(true));

        let mut unlocked = Interp::default();
        unlocked.start(Command::GetVersion).unwrap();
        let mut cached = features();
        cached.pin_cached = Some(true);
        assert!(
            unlocked
                .exchange(framed(api::MessageType::Features, &cached))
                .unwrap()
                .is_none()
        );
        let Response::Info(info) = unlocked.end().unwrap() else {
            panic!("expected info")
        };
        assert_eq!(info.needs_pin_sent, Some(false));

        let mut bad = Interp::default();
        bad.start(Command::GetVersion).unwrap();
        let mut wrong = features();
        wrong.vendor = Some("trezor.io".into());
        assert!(matches!(
            bad.exchange(framed(api::MessageType::Features, &wrong)),
            Err(Error::InvalidInput(message))
                if message == "device features vendor is not KeepKey"
        ));
    }

    #[test]
    fn non_mainnet_xpub_uses_testnet_spendaddress_without_trezor_field_six() {
        let mut interp = Interp::default().with_network(Network::Regtest);
        let transmit = interp
            .start(Command::GetXpub {
                path: "m/86'/1'/0'".parse().unwrap(),
                display: false,
            })
            .unwrap();
        let (kind, payload) = device_frame(transmit);
        assert_eq!(kind, api::MessageType::GetPublicKey as u16);
        let request = btc::GetPublicKey::decode(payload.as_slice()).unwrap();
        assert_eq!(request.coin_name.as_deref(), Some("Testnet"));
        assert_eq!(
            request.script_type,
            Some(btc::InputScriptType::Spendaddress as i32)
        );
        assert_eq!(request.ignore_xpub_magic, None);
    }

    #[test]
    fn keepkey_rejects_the_utf8_byte_limit_after_nfkd() {
        let passphrase = HostPassphrase::new("\u{e9}".repeat(17));
        assert!(passphrase.as_str().chars().count() <= 50);
        assert!(passphrase.as_str().len() > 50);
        let mut interp = Interp::default().with_passphrase(Some(passphrase));
        interp.start(Command::GetMasterFingerprint).unwrap();
        let transmit = interp
            .exchange(framed(
                api::MessageType::PassphraseRequest,
                &pb::PassphraseRequest::default(),
            ))
            .unwrap()
            .unwrap();
        let (kind, _) = device_frame(transmit);
        assert_eq!(kind, api::MessageType::Cancel as u16);
    }

    #[test]
    fn setup_routes_two_pin_rounds_then_entropy_and_seed_confirmations() {
        let entropy = [7u8; 32];
        let mut interp = Interp::default();
        interp
            .start(Command::Setup(
                common::SetupOptions {
                    label: "new".into(),
                    backup_passphrase: String::new(),
                },
                Some(DeviceContext::KeepKeyManagement(ManagementContext::Setup {
                    host_entropy: entropy,
                })),
            ))
            .unwrap();
        let reset = interp
            .exchange(framed(api::MessageType::Features, &features()))
            .unwrap()
            .unwrap();
        let (kind, payload) = device_frame(reset);
        assert_eq!(kind, api::MessageType::ResetDevice as u16);
        let reset = proto::ResetDevice::decode(payload.as_slice()).unwrap();
        assert_eq!(reset.strength, Some(128));
        assert_eq!(reset.label.as_deref(), Some("new"));

        for (raw_kind, expected) in [
            (
                pb::pin_matrix_request::PinMatrixRequestType::NewFirst as i32,
                common::PinMatrixRequestKind::NewFirst,
            ),
            (
                pb::pin_matrix_request::PinMatrixRequestType::NewSecond as i32,
                common::PinMatrixRequestKind::NewSecond,
            ),
        ] {
            let transmit = interp
                .exchange(pin_request(raw_kind))
                .unwrap()
                .expect("host PIN request");
            let request = host_request(transmit);
            assert_eq!(request, common::HostRequest::PinMatrix { kind: expected });
            let response = HostResponse::PinPositions("1234".into())
                .into_bytes_for(&request)
                .unwrap();
            let ack = interp.exchange(response).unwrap().expect("PIN ack");
            let (kind, payload) = device_frame(ack);
            assert_eq!(kind, api::MessageType::PinMatrixAck as u16);
            assert_eq!(
                pb::PinMatrixAck::decode(payload.as_slice()).unwrap().pin,
                "1234"
            );
        }

        let entropy_ack = interp
            .exchange(framed(
                api::MessageType::EntropyRequest,
                &mgmt::EntropyRequest::default(),
            ))
            .unwrap()
            .unwrap();
        let (kind, payload) = device_frame(entropy_ack);
        assert_eq!(kind, api::MessageType::EntropyAck as u16);
        assert_eq!(
            mgmt::EntropyAck::decode(payload.as_slice())
                .unwrap()
                .entropy,
            entropy
        );

        let button = interp
            .exchange(framed(
                api::MessageType::ButtonRequest,
                &pb::ButtonRequest::default(),
            ))
            .unwrap()
            .unwrap();
        assert_eq!(device_frame(button).0, api::MessageType::ButtonAck as u16);
        assert!(interp.exchange(success()).unwrap().is_none());
        assert!(matches!(
            interp.end().unwrap(),
            Response::DeviceAction(true)
        ));
    }

    #[test]
    fn restore_routes_pin_and_every_character_cipher_action() {
        let mut interp = Interp::default();
        interp
            .start(Command::Restore(
                common::RestoreOptions {
                    label: "restored".into(),
                    word_count: 12,
                },
                Some(DeviceContext::KeepKeyManagement(
                    ManagementContext::Restore { u2f_counter: 9 },
                )),
            ))
            .unwrap();
        let recovery = interp
            .exchange(framed(api::MessageType::Features, &features()))
            .unwrap()
            .unwrap();
        let (kind, payload) = device_frame(recovery);
        assert_eq!(kind, api::MessageType::RecoveryDevice as u16);
        let recovery = proto::RecoveryDevice::decode(payload.as_slice()).unwrap();
        assert_eq!(recovery.use_character_cipher, Some(true));
        assert_eq!(recovery.u2f_counter, Some(9));

        let request = host_request(
            interp
                .exchange(pin_request(
                    pb::pin_matrix_request::PinMatrixRequestType::NewFirst as i32,
                ))
                .unwrap()
                .unwrap(),
        );
        let ack = HostResponse::PinPositions("12".into())
            .into_bytes_for(&request)
            .unwrap();
        assert_eq!(
            device_frame(interp.exchange(ack).unwrap().unwrap()).0,
            api::MessageType::PinMatrixAck as u16
        );

        let reminder = interp
            .exchange(framed(
                api::MessageType::ButtonRequest,
                &pb::ButtonRequest::default(),
            ))
            .unwrap()
            .unwrap();
        assert_eq!(device_frame(reminder).0, api::MessageType::ButtonAck as u16);

        let cases = [
            (
                0,
                0,
                HostResponse::RecoveryCharacter('a'),
                Some("a"),
                None,
                None,
            ),
            (1, 3, HostResponse::RecoveryDelete, None, Some(true), None),
            (2, 3, HostResponse::RecoveryNextWord, Some(" "), None, None),
            (11, 3, HostResponse::RecoveryDone, None, None, Some(true)),
        ];
        for (word, character, response, expected_character, delete, done) in cases {
            let mut request = host_request(
                interp
                    .exchange(framed(
                        api::MessageType::CharacterRequest,
                        &proto::CharacterRequest {
                            word_pos: word,
                            character_pos: character,
                        },
                    ))
                    .unwrap()
                    .unwrap(),
            );
            assert_eq!(
                request,
                common::HostRequest::RecoveryCharacter {
                    word_position: word,
                    character_position: character,
                }
            );
            if word == 0 {
                assert!(matches!(
                    interp.exchange(vec![b'A']),
                    Err(Error::InvalidInput(message))
                        if message == "invalid recovery cipher response"
                ));
                request = host_request(
                    interp
                        .exchange(framed(
                            api::MessageType::CharacterRequest,
                            &proto::CharacterRequest {
                                word_pos: word,
                                character_pos: character,
                            },
                        ))
                        .unwrap()
                        .unwrap(),
                );
            }
            let raw = response.into_bytes_for(&request).unwrap();
            let (kind, payload) =
                device_frame(interp.exchange(raw).unwrap().expect("character ack"));
            assert_eq!(kind, api::MessageType::CharacterAck as u16);
            let ack = proto::CharacterAck::decode(payload.as_slice()).unwrap();
            assert_eq!(ack.character.as_deref(), expected_character);
            assert_eq!(ack.delete, delete);
            assert_eq!(ack.done, done);
        }
        assert!(interp.exchange(success()).unwrap().is_none());
        assert!(matches!(
            interp.end().unwrap(),
            Response::DeviceAction(true)
        ));
    }

    #[test]
    fn toggle_finishes_pending_when_current_pin_is_requested() {
        let mut interp = Interp::default();
        interp.start(Command::TogglePassphrase).unwrap();
        let apply = interp
            .exchange(framed(api::MessageType::Features, &features()))
            .unwrap()
            .unwrap();
        assert_eq!(
            device_frame(apply).0,
            api::MessageType::ApplySettings as u16
        );
        let confirmation = interp
            .exchange(framed(
                api::MessageType::ButtonRequest,
                &pb::ButtonRequest::default(),
            ))
            .unwrap()
            .unwrap();
        assert_eq!(
            device_frame(confirmation).0,
            api::MessageType::ButtonAck as u16
        );
        assert!(
            interp
                .exchange(pin_request(
                    pb::pin_matrix_request::PinMatrixRequestType::Current as i32,
                ))
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            interp.end().unwrap(),
            Response::DeviceAction(true)
        ));
    }

    #[test]
    fn prompt_and_send_pin_preserve_keepkey_pending_session_semantics() {
        let mut prompt = Interp::default();
        prompt.start(Command::PromptPin).unwrap();
        let request = prompt
            .exchange(framed(api::MessageType::Features, &features()))
            .unwrap()
            .unwrap();
        let (kind, payload) = device_frame(request);
        assert_eq!(kind, api::MessageType::GetPublicKey as u16);
        assert_eq!(
            btc::GetPublicKey::decode(payload.as_slice())
                .unwrap()
                .script_type,
            Some(btc::InputScriptType::Spendaddress as i32)
        );
        assert!(
            prompt
                .exchange(pin_request(
                    pb::pin_matrix_request::PinMatrixRequestType::Current as i32,
                ))
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            prompt.end().unwrap(),
            Response::DeviceAction(true)
        ));

        let mut send = Interp::default();
        let ack = send
            .start(Command::SendPin(Some(DeviceContext::KeepKeyManagement(
                ManagementContext::Pin(crate::keepkey::HostPin::new("123".into()).unwrap()),
            ))))
            .unwrap();
        let (kind, payload) = device_frame(ack);
        assert_eq!(kind, api::MessageType::PinMatrixAck as u16);
        assert_eq!(
            pb::PinMatrixAck::decode(payload.as_slice()).unwrap().pin,
            "123"
        );
        assert!(
            send.exchange(framed(
                api::MessageType::Failure,
                &pb::Failure {
                    code: Some(pb::failure::FailureType::FailurePinInvalid as i32),
                    message: Some("bad pin".into()),
                },
            ))
            .unwrap()
            .is_none()
        );
        assert!(matches!(send.end().unwrap(), Response::DeviceAction(false)));
    }

    #[test]
    fn unexpected_pin_request_cancels_with_keepkey_locked_text() {
        let mut interp = Interp::default();
        interp.start(Command::GetMasterFingerprint).unwrap();
        let cancel = interp
            .exchange(pin_request(
                pb::pin_matrix_request::PinMatrixRequestType::Current as i32,
            ))
            .unwrap()
            .unwrap();
        assert_eq!(device_frame(cancel).0, api::MessageType::Cancel as u16);
        let failure = pb::Failure {
            code: Some(pb::failure::FailureType::FailureActionCancelled as i32),
            message: None,
        };
        assert!(matches!(
            interp.exchange(framed(api::MessageType::Failure, &failure)),
            Err(Error::Device(message)) if message == KEEPKEY_LOCKED
        ));
    }

    fn empty_psbt(output: TxOut) -> Psbt {
        Psbt::from_unsigned_tx(Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: Vec::new(),
            output: vec![output],
        })
        .unwrap()
    }

    fn p2tr_script() -> ScriptBuf {
        let mut bytes = vec![0x51, 0x20];
        bytes.extend_from_slice(&[1u8; 32]);
        ScriptBuf::from_bytes(bytes)
    }

    #[test]
    fn taproot_display_inputs_and_change_are_rejected_before_sign_tx() {
        let mut display = Interp::default();
        assert!(matches!(
            display.start(Command::DisplayAddress(
                DisplayAddress::ByPath {
                    path: "m/86'/1'/0'/0/0".parse().unwrap(),
                    display: true,
                    address_format: Some(bitcoin::address::AddressType::P2tr),
                },
                None,
            )),
            Err(Error::UnsupportedDisplayAddress(_))
        ));

        let xonly = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            .parse()
            .unwrap();
        let ours = Fingerprint::from([1, 2, 3, 4]);
        let origin = (Vec::new(), (ours, "m/86'/0'/0'/0/0".parse().unwrap()));
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: Vec::new(),
        };
        let mut input_psbt = Psbt::from_unsigned_tx(tx).unwrap();
        input_psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(1),
            script_pubkey: p2tr_script(),
        });
        input_psbt.inputs[0].tap_internal_key = Some(xonly);
        input_psbt.inputs[0]
            .tap_key_origins
            .insert(xonly, origin.clone());
        let mut input = Interp::default();
        assert_eq!(
            device_frame(input.start(Command::SignTx(input_psbt, None)).unwrap()).0,
            api::MessageType::GetPublicKey as u16
        );
        assert!(matches!(
            input.exchange(master_public_key(0x0102_0304)),
            Err(Error::MissingCommandInfo(_))
        ));

        let mut change = empty_psbt(TxOut {
            value: Amount::from_sat(1),
            script_pubkey: p2tr_script(),
        });
        change.outputs[0].tap_internal_key = Some(xonly);
        change.outputs[0].tap_key_origins.insert(xonly, origin);
        let mut output = Interp::default();
        output.start(Command::SignTx(change, None)).unwrap();
        assert!(matches!(
            output.exchange(master_public_key(0x0102_0304)),
            Err(Error::MissingCommandInfo(_))
        ));
    }

    #[test]
    fn foreign_taproot_inputs_outputs_and_bip86_xpub_are_allowed() {
        let output_psbt = empty_psbt(TxOut {
            value: Amount::from_sat(1),
            script_pubkey: p2tr_script(),
        });
        let mut output = Interp::default();
        output.start(Command::SignTx(output_psbt, None)).unwrap();
        assert_eq!(
            device_frame(
                output
                    .exchange(master_public_key(0x0102_0304))
                    .unwrap()
                    .unwrap()
            )
            .0,
            api::MessageType::SignTx as u16
        );
        let output_ack = tx_ack(
            &mut output,
            request(btc::tx_request::RequestType::Txoutput, 0, None),
        );
        assert_eq!(
            output_ack.outputs[0].script_type,
            Some(btc::OutputScriptType::Paytoaddress as i32)
        );
        assert!(
            output_ack.outputs[0]
                .address
                .as_deref()
                .is_some_and(|address| address.starts_with("bc1p"))
        );

        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: Vec::new(),
        };
        let mut input_psbt = Psbt::from_unsigned_tx(tx).unwrap();
        input_psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(1),
            script_pubkey: p2tr_script(),
        });
        let foreign_key = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            .parse()
            .unwrap();
        input_psbt.inputs[0].tap_internal_key = Some(foreign_key);
        input_psbt.inputs[0].tap_key_origins.insert(
            foreign_key,
            (
                Vec::new(),
                (
                    Fingerprint::from([9, 9, 9, 9]),
                    "m/86'/0'/0'/0/0".parse().unwrap(),
                ),
            ),
        );
        let mut input = Interp::default();
        input.start(Command::SignTx(input_psbt, None)).unwrap();
        assert_eq!(
            device_frame(
                input
                    .exchange(master_public_key(0x0102_0304))
                    .unwrap()
                    .unwrap()
            )
            .0,
            api::MessageType::SignTx as u16
        );

        assert_eq!(
            device_frame(
                Interp::default()
                    .start(Command::GetXpub {
                        path: "m/86'/1'/0'".parse().unwrap(),
                        display: false,
                    })
                    .unwrap()
            )
            .0,
            api::MessageType::GetPublicKey as u16
        );
    }

    #[test]
    fn supported_single_sig_address_profiles_are_transmitted() {
        for (address_format, expected) in [
            (
                bitcoin::address::AddressType::P2pkh,
                btc::InputScriptType::Spendaddress,
            ),
            (
                bitcoin::address::AddressType::P2sh,
                btc::InputScriptType::Spendp2shwitness,
            ),
            (
                bitcoin::address::AddressType::P2wpkh,
                btc::InputScriptType::Spendwitness,
            ),
        ] {
            let transmit = Interp::default()
                .start(Command::DisplayAddress(
                    DisplayAddress::ByPath {
                        path: "m/84'/1'/0'/0/0".parse().unwrap(),
                        display: true,
                        address_format: Some(address_format),
                    },
                    None,
                ))
                .unwrap();
            let (kind, payload) = device_frame(transmit);
            assert_eq!(kind, api::MessageType::GetAddress as u16);
            assert_eq!(
                btc::GetAddress::decode(payload.as_slice())
                    .unwrap()
                    .script_type,
                Some(expected as i32)
            );
        }
    }

    fn bare_multisig_of(sorted: bool, address_type: MultisigAddressType) -> Command {
        const A: &str = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
        const B: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        Command::DisplayAddress(
            DisplayAddress::ByMultisig(MultisigDisplayAddress {
                threshold: 2,
                address_type,
                sorted,
                keys: [
                    format!("[11111111/48h/1h/0h/2h/0/0]{A}"),
                    format!("[22222222/48h/1h/0h/2h/0/1]{B}"),
                ]
                .into_iter()
                .map(|key| key.parse().unwrap())
                .collect(),
            }),
            None,
        )
    }

    fn bare_multisig(sorted: bool) -> Command {
        bare_multisig_of(sorted, MultisigAddressType::Wit)
    }

    #[test]
    fn only_sorted_fully_derived_multisig_display_is_transmitted() {
        assert!(matches!(
            Interp::default().start(bare_multisig(false)),
            Err(Error::UnsupportedDisplayAddress(_))
        ));
        assert_eq!(
            device_frame(Interp::default().start(bare_multisig(true)).unwrap()).0,
            api::MessageType::GetAddress as u16
        );

        const XPUB: &str = "tpubDCHRnuvE95JrpEVTUmr36sK3K9ADf3s3aztpXzL8coBeCTE8cHV8PjxS6SjWJM3GfPn798gyEa3dRPgjoUDSuNfuC9xz4PHznwKEk2XL7X1";
        for (address_type, expected) in [
            (
                MultisigAddressType::Legacy,
                btc::InputScriptType::Spendmultisig,
            ),
            (
                MultisigAddressType::ShWit,
                btc::InputScriptType::Spendp2shwitness,
            ),
            (MultisigAddressType::Wit, btc::InputScriptType::Spendwitness),
        ] {
            let (kind, payload) = device_frame(
                Interp::default()
                    .start(bare_multisig_of(true, address_type))
                    .unwrap(),
            );
            assert_eq!(kind, api::MessageType::GetAddress as u16);
            assert_eq!(
                btc::GetAddress::decode(payload.as_slice())
                    .unwrap()
                    .script_type,
                Some(expected as i32)
            );
        }
        let xpub = Command::DisplayAddress(
            DisplayAddress::ByMultisig(MultisigDisplayAddress {
                threshold: 1,
                address_type: MultisigAddressType::Wit,
                sorted: true,
                keys: vec![
                    format!("[f5acc2fd/48h/1h/0h/2h]{XPUB}/0/0")
                        .parse()
                        .unwrap(),
                ],
            }),
            None,
        );
        assert!(matches!(
            Interp::default().start(xpub),
            Err(Error::UnsupportedDisplayAddress(_))
        ));
    }

    #[test]
    fn multisig_user_refusal_is_not_retried_as_an_unknown_cosigner() {
        let mut interp = Interp::default();
        interp.start(bare_multisig(true)).unwrap();
        let failure = pb::Failure {
            code: Some(pb::failure::FailureType::FailureActionCancelled as i32),
            message: None,
        };
        assert!(matches!(
            interp.exchange(framed(api::MessageType::Failure, &failure)),
            Err(Error::AuthenticationRefused)
        ));
    }

    fn previous_tx(value: u64, script_pubkey: ScriptBuf) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(value),
                script_pubkey,
            }],
        }
    }

    fn request(
        request_type: btc::tx_request::RequestType,
        index: u32,
        tx_hash: Option<Vec<u8>>,
    ) -> Vec<u8> {
        framed(
            api::MessageType::TxRequest,
            &btc::TxRequest {
                request_type: Some(request_type as i32),
                details: Some(btc::tx_request::TxRequestDetailsType {
                    request_index: Some(index),
                    tx_hash,
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
    }

    fn tx_ack(interp: &mut Interp, request: Vec<u8>) -> btc::tx_ack::TransactionType {
        let transmit = interp.exchange(request).unwrap().expect("transaction ack");
        let (kind, payload) = device_frame(transmit);
        assert_eq!(kind, api::MessageType::TxAck as u16);
        btc::TxAck::decode(payload.as_slice()).unwrap().tx.unwrap()
    }

    #[test]
    fn signing_serves_all_transaction_branches_and_ignores_foreign_inputs() {
        use bitcoin::hashes::Hash as _;

        let own_key: bitcoin::secp256k1::PublicKey =
            "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
                .parse()
                .unwrap();
        let foreign_key: bitcoin::secp256k1::PublicKey =
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                .parse()
                .unwrap();
        let own_script = ScriptBuf::new_p2pkh(&bitcoin::PublicKey::new(own_key).pubkey_hash());
        let foreign_script =
            ScriptBuf::new_p2pkh(&bitcoin::PublicKey::new(foreign_key).pubkey_hash());
        let own_prev = previous_tx(50_000, own_script);
        let foreign_prev = previous_tx(60_000, foreign_script);
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output: OutPoint {
                        txid: own_prev.compute_txid(),
                        vout: 0,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                },
                TxIn {
                    previous_output: OutPoint {
                        txid: foreign_prev.compute_txid(),
                        vout: 0,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                },
            ],
            output: vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: ScriptBuf::new_p2pkh(
                    &bitcoin::PublicKey::new(foreign_key).pubkey_hash(),
                ),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.inputs[0].non_witness_utxo = Some(own_prev.clone());
        psbt.inputs[0].bip32_derivation.insert(
            own_key,
            (
                bitcoin::bip32::Fingerprint::from([1, 2, 3, 4]),
                "m/44'/0'/0'/0/0".parse().unwrap(),
            ),
        );
        psbt.inputs[1].non_witness_utxo = Some(foreign_prev.clone());
        psbt.inputs[1].bip32_derivation.insert(
            foreign_key,
            (
                bitcoin::bip32::Fingerprint::from([9, 9, 9, 9]),
                "m/44'/0'/0'/0/1".parse().unwrap(),
            ),
        );

        let mut interp = Interp::default();
        assert_eq!(
            device_frame(
                interp
                    .start(Command::SignTx(psbt, None))
                    .expect("master key request")
            )
            .0,
            api::MessageType::GetPublicKey as u16
        );
        let sign = interp
            .exchange(framed(
                api::MessageType::PublicKey,
                &btc::PublicKey {
                    node: pb::HdNodeType {
                        depth: 0,
                        fingerprint: 0,
                        child_num: 0,
                        chain_code: vec![0; 32],
                        private_key: None,
                        public_key: vec![0; 33],
                    },
                    xpub: String::new(),
                    root_fingerprint: Some(0x0102_0304),
                    descriptor: None,
                },
            ))
            .unwrap()
            .unwrap();
        assert_eq!(device_frame(sign).0, api::MessageType::SignTx as u16);

        let meta = tx_ack(
            &mut interp,
            request(btc::tx_request::RequestType::Txmeta, 0, None),
        );
        assert_eq!(meta.inputs_cnt, Some(2));
        assert_eq!(meta.outputs_cnt, Some(1));

        let own = tx_ack(
            &mut interp,
            request(btc::tx_request::RequestType::Txinput, 0, None),
        );
        assert_eq!(
            own.inputs[0].script_type,
            Some(btc::InputScriptType::Spendaddress as i32)
        );
        let foreign = tx_ack(
            &mut interp,
            request(btc::tx_request::RequestType::Txinput, 1, None),
        );
        assert_eq!(
            foreign.inputs[0].script_type,
            Some(btc::InputScriptType::Spendwitness as i32)
        );
        assert_eq!(
            foreign.inputs[0].address_n,
            [0x8000_0054, 0x8000_0000, 0x8000_0000, 0, 0]
        );
        assert_eq!(
            tx_ack(
                &mut interp,
                request(btc::tx_request::RequestType::Txoutput, 0, None),
            )
            .outputs
            .len(),
            1
        );

        let mut previous_hash = own_prev.compute_txid().to_byte_array();
        previous_hash.reverse();
        let previous_hash = previous_hash.to_vec();
        assert_eq!(
            tx_ack(
                &mut interp,
                request(
                    btc::tx_request::RequestType::Txmeta,
                    0,
                    Some(previous_hash.clone()),
                ),
            )
            .outputs_cnt,
            Some(1)
        );
        assert_eq!(
            tx_ack(
                &mut interp,
                request(
                    btc::tx_request::RequestType::Txinput,
                    0,
                    Some(previous_hash.clone()),
                ),
            )
            .inputs
            .len(),
            1
        );
        assert_eq!(
            tx_ack(
                &mut interp,
                request(
                    btc::tx_request::RequestType::Txoutput,
                    0,
                    Some(previous_hash),
                ),
            )
            .bin_outputs
            .len(),
            1
        );

        let signature = bitcoin::secp256k1::ecdsa::Signature::from_compact(&[1u8; 64])
            .unwrap()
            .serialize_der()
            .to_vec();
        let foreign_signature = btc::TxRequest {
            request_type: Some(btc::tx_request::RequestType::Txmeta as i32),
            details: Some(btc::tx_request::TxRequestDetailsType {
                request_index: Some(0),
                ..Default::default()
            }),
            serialized: Some(btc::tx_request::TxRequestSerializedType {
                signature_index: Some(1),
                signature: Some(signature.clone()),
                serialized_tx: None,
            }),
        };
        let _ = tx_ack(
            &mut interp,
            framed(api::MessageType::TxRequest, &foreign_signature),
        );
        let finished = btc::TxRequest {
            request_type: Some(btc::tx_request::RequestType::Txfinished as i32),
            serialized: Some(btc::tx_request::TxRequestSerializedType {
                signature_index: Some(0),
                signature: Some(signature),
                serialized_tx: None,
            }),
            ..Default::default()
        };
        assert!(
            interp
                .exchange(framed(api::MessageType::TxRequest, &finished))
                .unwrap()
                .is_none()
        );
        let Response::SignedPsbt(psbt) = interp.end().unwrap() else {
            panic!("expected signed PSBT")
        };
        assert_eq!(psbt.inputs[0].partial_sigs.len(), 1);
        assert!(psbt.inputs[1].partial_sigs.is_empty());
    }

    #[test]
    fn unsupported_registration_and_backup_never_transmit() {
        assert!(matches!(
            KeepKeyCommand::try_from(Command::Backup),
            Err(TrezorError::Unsupported(_))
        ));
        let policy: crate::miniscript::descriptor::WalletPolicy =
            "wpkh(@0/**)".parse().expect("wallet policy");
        assert!(matches!(
            KeepKeyCommand::try_from(Command::RegisterWallet {
                name: "wallet".into(),
                policy,
            }),
            Err(TrezorError::Unsupported(_))
        ));
    }
}
