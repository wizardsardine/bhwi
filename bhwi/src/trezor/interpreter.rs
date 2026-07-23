use core::marker::PhantomData;
use core::str::FromStr;

use bitcoin::address::AddressType;
use bitcoin::bip32::{DerivationPath, Fingerprint, Xpub};
use bitcoin::{Network, NetworkKind};

use crate::Interpreter;
use crate::common;
use crate::trezor::api::{self, MessageType};
use crate::trezor::error::TrezorError;
use crate::trezor::proto::{bitcoin as btc, common as pb, management as mgmt};

pub enum TrezorCommand {
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
}

pub enum TrezorResponse {
    Info(common::Info),
    MasterFingerprint(Fingerprint),
    Xpub(Xpub),
    Address(String),
}

enum PublicKeyKind {
    Fingerprint,
    Xpub,
}

enum State {
    New,
    AwaitFeatures,
    AwaitPublicKey(PublicKeyKind),
    AwaitAddress,
    Finished(TrezorResponse),
}

pub struct TrezorInterpreter<C, T, R, E> {
    state: State,
    network: Network,
    _marker: PhantomData<(C, T, R, E)>,
}

impl<C, T, R, E> Default for TrezorInterpreter<C, T, R, E> {
    fn default() -> Self {
        Self {
            state: State::New,
            network: Network::Bitcoin,
            _marker: PhantomData,
        }
    }
}

impl<C, T, R, E> TrezorInterpreter<C, T, R, E> {
    pub fn with_network(mut self, network: Network) -> Self {
        self.network = network;
        self
    }
}

impl<C, T, R, E> Interpreter for TrezorInterpreter<C, T, R, E>
where
    C: TryInto<TrezorCommand, Error = TrezorError>,
    T: From<Vec<u8>>,
    R: From<TrezorResponse>,
    E: From<TrezorError>,
{
    type Command = C;
    type Transmit = T;
    type Response = R;
    type Error = E;

    fn start(&mut self, command: C) -> Result<T, E> {
        let coin = coin_name(self.network);
        let bytes = match command.try_into().map_err(E::from)? {
            TrezorCommand::Initialize(network) => {
                if let Some(network) = network {
                    self.network = network;
                }
                self.state = State::AwaitFeatures;
                api::initialize()
            }
            TrezorCommand::GetFeatures => {
                self.state = State::AwaitFeatures;
                api::get_features()
            }
            TrezorCommand::GetMasterFingerprint => {
                self.state = State::AwaitPublicKey(PublicKeyKind::Fingerprint);
                api::get_public_key(Vec::new(), false, btc::InputScriptType::Spendaddress, coin)
            }
            TrezorCommand::GetXpub { address_n, display } => {
                self.state = State::AwaitPublicKey(PublicKeyKind::Xpub);
                api::get_public_key(address_n, display, btc::InputScriptType::Spendwitness, coin)
            }
            TrezorCommand::GetAddress {
                address_n,
                display,
                script_type,
            } => {
                self.state = State::AwaitAddress;
                api::get_address(address_n, display, script_type, coin)
            }
        };
        Ok(T::from(bytes))
    }

    fn exchange(&mut self, data: Vec<u8>) -> Result<Option<T>, E> {
        let (msg_type, payload) = api::parse_frame(&data).map_err(E::from)?;

        if matches!(self.state, State::New | State::Finished(_)) {
            return Err(E::from(TrezorError::UnexpectedMessage(
                msg_type,
                "no command in progress",
            )));
        }

        if msg_type == MessageType::ButtonRequest as u16 {
            return Ok(Some(T::from(api::button_ack())));
        }
        if msg_type == MessageType::PassphraseRequest as u16 {
            return Ok(Some(T::from(api::passphrase_ack_on_device())));
        }
        if msg_type == MessageType::Failure as u16 {
            let failure: pb::Failure = api::decode(&payload).map_err(E::from)?;
            return Err(E::from(failure_error(failure)));
        }
        if msg_type == MessageType::PinMatrixRequest as u16 {
            return Err(E::from(TrezorError::Locked(
                "PIN entry is not supported in this build",
            )));
        }

        let response = match &self.state {
            State::AwaitFeatures => {
                let features: mgmt::Features = expect(
                    msg_type,
                    MessageType::Features,
                    &payload,
                    "reading features",
                )
                .map_err(E::from)?;
                TrezorResponse::Info(features_info(features, self.network))
            }
            State::AwaitPublicKey(kind) => {
                let pubkey: btc::PublicKey = expect(
                    msg_type,
                    MessageType::PublicKey,
                    &payload,
                    "reading public key",
                )
                .map_err(E::from)?;
                match kind {
                    PublicKeyKind::Fingerprint => {
                        let fingerprint = match pubkey.root_fingerprint {
                            Some(fingerprint) => Fingerprint::from(fingerprint.to_be_bytes()),
                            None => parse_xpub(&pubkey.xpub).map_err(E::from)?.fingerprint(),
                        };
                        TrezorResponse::MasterFingerprint(fingerprint)
                    }
                    PublicKeyKind::Xpub => {
                        let xpub = parse_xpub(&pubkey.xpub).map_err(E::from)?;
                        if xpub.network != NetworkKind::from(self.network) {
                            return Err(E::from(TrezorError::NetworkMismatch));
                        }
                        TrezorResponse::Xpub(xpub)
                    }
                }
            }
            State::AwaitAddress => {
                let address: btc::Address =
                    expect(msg_type, MessageType::Address, &payload, "reading address")
                        .map_err(E::from)?;
                TrezorResponse::Address(address.address)
            }
            State::New | State::Finished(_) => {
                return Err(E::from(TrezorError::UnexpectedMessage(
                    msg_type,
                    "no command in progress",
                )));
            }
        };
        self.state = State::Finished(response);
        Ok(None)
    }

    fn end(self) -> Result<R, E> {
        match self.state {
            State::Finished(response) => Ok(R::from(response)),
            _ => Err(E::from(TrezorError::InvalidInput(
                "interpreter did not reach a response".into(),
            ))),
        }
    }
}

impl TryFrom<common::Command> for TrezorCommand {
    type Error = TrezorError;

    fn try_from(command: common::Command) -> Result<Self, TrezorError> {
        use common::Command;
        Ok(match command {
            Command::Unlock { options } => TrezorCommand::Initialize(options.network),
            Command::GetVersion => TrezorCommand::GetFeatures,
            Command::GetMasterFingerprint => TrezorCommand::GetMasterFingerprint,
            Command::GetXpub { path, display } => TrezorCommand::GetXpub {
                address_n: address_n(&path),
                display,
            },
            Command::DisplayAddress(
                common::DisplayAddress::ByPath {
                    path,
                    display,
                    address_format,
                },
                _,
            ) => TrezorCommand::GetAddress {
                address_n: address_n(&path),
                display,
                script_type: script_type(address_format, &path),
            },
            Command::DisplayAddress(common::DisplayAddress::ByDescriptor { .. }, _) => {
                return Err(TrezorError::UnsupportedDisplayAddress(
                    "descriptor address display is not yet supported",
                ));
            }
            Command::DisplayAddress(common::DisplayAddress::ByMultisig(_), _) => {
                return Err(TrezorError::UnsupportedDisplayAddress(
                    "multisig address display is not yet supported",
                ));
            }
            Command::SignTx(..) => {
                return Err(TrezorError::Unsupported("sign_tx is not yet supported"));
            }
            Command::SignMessage { .. } => {
                return Err(TrezorError::Unsupported(
                    "sign_message is not yet supported",
                ));
            }
            Command::RegisterWallet { .. } => {
                return Err(TrezorError::Unsupported("register_wallet is not supported"));
            }
            Command::Backup => {
                return Err(TrezorError::Unsupported("backup is not yet supported"));
            }
            Command::Setup(..) => {
                return Err(TrezorError::Unsupported("setup is not yet supported"));
            }
            Command::Wipe => {
                return Err(TrezorError::Unsupported("wipe is not yet supported"));
            }
            Command::Restore(..) => {
                return Err(TrezorError::Unsupported("restore is not yet supported"));
            }
            Command::TogglePassphrase => {
                return Err(TrezorError::Unsupported(
                    "toggle_passphrase is not yet supported",
                ));
            }
        })
    }
}

impl From<TrezorResponse> for common::Response {
    fn from(response: TrezorResponse) -> Self {
        match response {
            TrezorResponse::Info(info) => common::Response::Info(info),
            TrezorResponse::MasterFingerprint(fingerprint) => {
                common::Response::MasterFingerprint(fingerprint)
            }
            TrezorResponse::Xpub(xpub) => common::Response::Xpub(xpub),
            TrezorResponse::Address(address) => common::Response::Address(address),
        }
    }
}

fn expect<M: prost::Message + Default>(
    msg_type: u16,
    want: MessageType,
    payload: &[u8],
    context: &'static str,
) -> Result<M, TrezorError> {
    if msg_type != want as u16 {
        return Err(TrezorError::UnexpectedMessage(msg_type, context));
    }
    api::decode(payload)
}

fn failure_error(failure: pb::Failure) -> TrezorError {
    let cancelled = pb::failure::FailureType::FailureActionCancelled as i32;
    let pin_cancelled = pb::failure::FailureType::FailurePinCancelled as i32;
    match failure.code {
        Some(code) if code == cancelled || code == pin_cancelled => TrezorError::ActionCancelled,
        code => {
            let message = failure.message.unwrap_or_default();
            TrezorError::Failure(
                code.unwrap_or(0),
                if message.is_empty() {
                    "device reported a failure".into()
                } else {
                    message
                },
            )
        }
    }
}

fn features_info(features: mgmt::Features, network: Network) -> common::Info {
    common::Info {
        version: format!(
            "{}.{}.{}",
            features.major_version, features.minor_version, features.patch_version
        ),
        networks: vec![network],
        firmware: None,
        initialized: features.initialized,
    }
}

fn address_n(path: &DerivationPath) -> Vec<u32> {
    path.into_iter().map(|child| u32::from(*child)).collect()
}

fn parse_xpub(xpub: &str) -> Result<Xpub, TrezorError> {
    Xpub::from_str(xpub).map_err(|e| TrezorError::InvalidInput(e.to_string()))
}

fn script_type(format: Option<AddressType>, path: &DerivationPath) -> btc::InputScriptType {
    match format {
        Some(AddressType::P2pkh) => btc::InputScriptType::Spendaddress,
        Some(AddressType::P2sh) => btc::InputScriptType::Spendp2shwitness,
        Some(AddressType::P2wpkh) => btc::InputScriptType::Spendwitness,
        Some(AddressType::P2tr) => btc::InputScriptType::Spendtaproot,
        _ => script_type_from_purpose(path),
    }
}

fn script_type_from_purpose(path: &DerivationPath) -> btc::InputScriptType {
    match path
        .into_iter()
        .next()
        .map(|child| u32::from(*child) & 0x7fff_ffff)
    {
        Some(44) => btc::InputScriptType::Spendaddress,
        Some(49) => btc::InputScriptType::Spendp2shwitness,
        Some(86) => btc::InputScriptType::Spendtaproot,
        _ => btc::InputScriptType::Spendwitness,
    }
}

fn coin_name(network: Network) -> String {
    match network {
        Network::Bitcoin => "Bitcoin",
        Network::Regtest => "Regtest",
        _ => "Testnet",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{Command, DisplayAddress, Error, Response, Transmit};
    use prost::Message;

    const XPUB: &str = "xpub6CLSXAha9gjRDyBn9wvyegsMdWKwengbdwY838GnzdyUxXfL9w7YKhczFkTuW4VaApKBw7UYVzbddataVrzYNjK8LWcyBy7MSHfwi15HnZS";

    type Interp = TrezorInterpreter<Command, Transmit, Response, Error>;

    fn decode_transmit<M: Message + Default>(transmit: Transmit) -> (u16, M) {
        let (msg_type, payload) = api::parse_frame(&transmit.payload).unwrap();
        (msg_type, M::decode(payload.as_slice()).unwrap())
    }

    fn framed<M: Message>(msg_type: MessageType, msg: &M) -> Vec<u8> {
        api::frame(msg_type as u16, &msg.encode_to_vec())
    }

    fn public_key(xpub: &str, root_fingerprint: Option<u32>) -> btc::PublicKey {
        btc::PublicKey {
            node: pb::HdNodeType {
                depth: 0,
                fingerprint: 0,
                child_num: 0,
                chain_code: vec![0u8; 32],
                private_key: None,
                public_key: vec![0u8; 33],
            },
            xpub: xpub.to_string(),
            root_fingerprint,
            descriptor: None,
        }
    }

    #[test]
    fn get_xpub_encodes_hardened_path() {
        let mut interp = Interp::default();
        let transmit = interp
            .start(Command::GetXpub {
                path: "m/84'/0'/0'".parse().unwrap(),
                display: false,
            })
            .unwrap();
        let (msg_type, msg): (u16, btc::GetPublicKey) = decode_transmit(transmit);
        assert_eq!(msg_type, MessageType::GetPublicKey as u16);
        assert_eq!(msg.address_n, vec![0x8000_0054, 0x8000_0000, 0x8000_0000]);
        assert_eq!(
            msg.script_type,
            Some(btc::InputScriptType::Spendwitness as i32)
        );
        assert_eq!(msg.coin_name.as_deref(), Some("Bitcoin"));
        assert_eq!(msg.ignore_xpub_magic, Some(true));
    }

    #[test]
    fn get_xpub_parses_public_key() {
        let mut interp = Interp::default();
        interp
            .start(Command::GetXpub {
                path: "m/84'/0'/0'".parse().unwrap(),
                display: false,
            })
            .unwrap();
        let reply = framed(MessageType::PublicKey, &public_key(XPUB, None));
        assert!(interp.exchange(reply).unwrap().is_none());
        match interp.end().unwrap() {
            Response::Xpub(xpub) => assert_eq!(xpub.to_string(), XPUB),
            _ => panic!("expected xpub response"),
        }
    }

    #[test]
    fn get_master_fingerprint_reads_root_fingerprint() {
        let mut interp = Interp::default();
        let transmit = interp.start(Command::GetMasterFingerprint).unwrap();
        let (msg_type, msg): (u16, btc::GetPublicKey) = decode_transmit(transmit);
        assert_eq!(msg_type, MessageType::GetPublicKey as u16);
        assert!(msg.address_n.is_empty());

        let reply = framed(MessageType::PublicKey, &public_key(XPUB, Some(0x1a2b_3c4d)));
        assert!(interp.exchange(reply).unwrap().is_none());
        match interp.end().unwrap() {
            Response::MasterFingerprint(fingerprint) => {
                assert_eq!(fingerprint, Fingerprint::from([0x1a, 0x2b, 0x3c, 0x4d]))
            }
            _ => panic!("expected master fingerprint response"),
        }
    }

    #[test]
    fn get_master_fingerprint_falls_back_to_xpub() {
        let mut interp = Interp::default();
        interp.start(Command::GetMasterFingerprint).unwrap();
        let reply = framed(MessageType::PublicKey, &public_key(XPUB, None));
        assert!(interp.exchange(reply).unwrap().is_none());
        let expected = Xpub::from_str(XPUB).unwrap().fingerprint();
        match interp.end().unwrap() {
            Response::MasterFingerprint(fingerprint) => assert_eq!(fingerprint, expected),
            _ => panic!("expected master fingerprint response"),
        }
    }

    #[test]
    fn display_address_by_path_confirms_then_returns() {
        let mut interp = Interp::default().with_network(Network::Testnet);
        let transmit = interp
            .start(Command::DisplayAddress(
                DisplayAddress::ByPath {
                    path: "m/86'/1'/0'/0/0".parse().unwrap(),
                    display: true,
                    address_format: Some(AddressType::P2tr),
                },
                None,
            ))
            .unwrap();
        let (msg_type, msg): (u16, btc::GetAddress) = decode_transmit(transmit);
        assert_eq!(msg_type, MessageType::GetAddress as u16);
        assert_eq!(
            msg.script_type,
            Some(btc::InputScriptType::Spendtaproot as i32)
        );
        assert_eq!(msg.show_display, Some(true));
        assert_eq!(msg.coin_name.as_deref(), Some("Testnet"));

        let button = framed(MessageType::ButtonRequest, &pb::ButtonRequest::default());
        let ack = interp.exchange(button).unwrap().expect("button ack");
        let (ack_type, _): (u16, pb::ButtonAck) = decode_transmit(ack);
        assert_eq!(ack_type, MessageType::ButtonAck as u16);

        let address = framed(
            MessageType::Address,
            &btc::Address {
                address: "tb1pexampleaddress".to_string(),
                mac: None,
            },
        );
        assert!(interp.exchange(address).unwrap().is_none());
        match interp.end().unwrap() {
            Response::Address(address) => assert_eq!(address, "tb1pexampleaddress"),
            _ => panic!("expected address response"),
        }
    }

    #[test]
    fn device_failure_maps_to_error() {
        let mut interp = Interp::default();
        interp.start(Command::GetMasterFingerprint).unwrap();
        let failure = pb::Failure {
            code: Some(pb::failure::FailureType::FailureProcessError as i32),
            message: Some("boom".to_string()),
        };
        let frame = framed(MessageType::Failure, &failure);
        assert!(matches!(interp.exchange(frame), Err(Error::Device(_))));
    }

    #[test]
    fn pin_matrix_request_is_locked() {
        let mut interp = Interp::default();
        interp.start(Command::GetMasterFingerprint).unwrap();
        let frame = framed(
            MessageType::PinMatrixRequest,
            &pb::PinMatrixRequest::default(),
        );
        assert!(matches!(interp.exchange(frame), Err(Error::Device(_))));
    }

    #[test]
    fn unsupported_commands_rejected_at_boundary() {
        let mut interp = Interp::default();
        assert!(matches!(
            interp.start(Command::Wipe),
            Err(Error::InvalidInput(_))
        ));

        let mut interp = Interp::default();
        let display = Command::DisplayAddress(
            DisplayAddress::ByDescriptor {
                index: 0,
                change: false,
                display: true,
                descriptor_name: "x".to_string(),
            },
            None,
        );
        assert!(matches!(
            interp.start(display),
            Err(Error::UnsupportedDisplayAddress(_))
        ));
    }

    #[test]
    fn unexpected_message_type_errors() {
        let mut interp = Interp::default();
        interp.start(Command::GetMasterFingerprint).unwrap();
        let wrong = framed(
            MessageType::Address,
            &btc::Address {
                address: "x".to_string(),
                mac: None,
            },
        );
        assert!(matches!(
            interp.exchange(wrong),
            Err(Error::UnexpectedResult(..))
        ));
    }

    #[test]
    fn malformed_frame_errors() {
        let mut interp = Interp::default();
        interp.start(Command::GetMasterFingerprint).unwrap();
        assert!(matches!(
            interp.exchange(vec![0, 1, 2]),
            Err(Error::Serialization(_))
        ));
    }

    #[test]
    fn message_without_command_in_progress_errors() {
        let mut interp = Interp::default();
        let frame = framed(MessageType::Features, &mgmt::Features::default());
        assert!(matches!(
            interp.exchange(frame),
            Err(Error::UnexpectedResult(..))
        ));
    }

    #[test]
    fn network_mismatch_rejected() {
        let mut interp = Interp::default().with_network(Network::Testnet);
        interp
            .start(Command::GetXpub {
                path: "m/84'/1'/0'".parse().unwrap(),
                display: false,
            })
            .unwrap();
        let reply = framed(MessageType::PublicKey, &public_key(XPUB, None));
        assert!(matches!(
            interp.exchange(reply),
            Err(Error::InvalidInput(_))
        ));
    }

    #[test]
    fn passphrase_request_is_auto_acked() {
        let mut interp = Interp::default();
        interp.start(Command::GetMasterFingerprint).unwrap();
        let req = framed(
            MessageType::PassphraseRequest,
            &pb::PassphraseRequest::default(),
        );
        let ack = interp.exchange(req).unwrap().expect("passphrase ack");
        let (ack_type, msg): (u16, pb::PassphraseAck) = decode_transmit(ack);
        assert_eq!(ack_type, MessageType::PassphraseAck as u16);
        assert_eq!(msg.on_device, Some(true));
    }
}
