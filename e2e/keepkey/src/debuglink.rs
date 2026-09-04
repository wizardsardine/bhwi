use std::{future::Future, io, time::Duration};

use async_trait::async_trait;
use bhwi::{
    common::{self, HostRequest, HostResponse},
    keepkey::{api, proto::DebugLinkState},
};
use bhwi_async::HostInteraction;
use prost::Message;
use tokio::net::UdpSocket;

pub const DEFAULT_MAIN_ADDR: &str = bhwi::keepkey::DEFAULT_KEEPKEY_EMULATOR;
pub const DEFAULT_DEBUGLINK_ADDR: &str = "127.0.0.1:11045";
pub const SYNTHETIC_MNEMONIC: &str =
    "alcohol woman abuse must during monitor noble actual mixed trade anger aisle";

const DEBUGLINK_DECISION: u16 = 100;
const DEBUGLINK_GET_STATE: u16 = 101;
const DEBUGLINK_STATE: u16 = 102;
const LOCK_DEVICE: u16 = 24;
const SUCCESS: u16 = 2;
const REPORT_SIZE: usize = 64;
const CHUNK_SIZE: usize = REPORT_SIZE - 1;
const REPORT_PREFIX: u8 = 0x3f;
const HEADER_SIZE: usize = 8;
const MAX_PAYLOAD_SIZE: usize = 64 * 1024;
const DECISION_INTERVAL: Duration = Duration::from_millis(100);
const DEBUGLINK_IO_TIMEOUT: Duration = Duration::from_secs(5);
const OPERATION_TIMEOUT: Duration = Duration::from_secs(180);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DebugButton {
    No = 0,
    Yes = 1,
}

/// Only the debug state needed to answer KeepKey host prompts.
///
/// This deliberately has no `Debug` implementation because autocomplete can
/// contain a mnemonic word, and the full firmware state also carries the PIN.
#[derive(Default)]
pub struct DebugState {
    pub matrix: Option<String>,
    pub recovery_cipher: Option<String>,
    pub recovery_auto_completed_word: Option<String>,
}

pub struct DebugLink {
    socket: UdpSocket,
}

impl DebugLink {
    pub async fn connect(addr: &str) -> io::Result<Self> {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        socket
            .connect(addr.strip_prefix("udp:").unwrap_or(addr))
            .await?;
        Ok(Self { socket })
    }

    pub async fn connect_default() -> io::Result<Self> {
        Self::connect(DEFAULT_DEBUGLINK_ADDR).await
    }

    async fn send_frame(&self, frame: &[u8]) -> io::Result<()> {
        for chunk in frame.chunks(CHUNK_SIZE) {
            let mut report = [0u8; REPORT_SIZE];
            report[0] = REPORT_PREFIX;
            report[1..1 + chunk.len()].copy_from_slice(chunk);
            if self.socket.send(&report).await? != report.len() {
                return Err(invalid_data("could not send a complete KeepKey report"));
            }
        }
        Ok(())
    }

    async fn receive_frame(&self) -> io::Result<(u16, Vec<u8>)> {
        let mut report = [0u8; REPORT_SIZE];
        let mut frame = Vec::new();
        let mut total = None;
        loop {
            if self.socket.recv(&mut report).await? != REPORT_SIZE {
                return Err(invalid_data("could not read a complete KeepKey report"));
            }
            if report[0] != REPORT_PREFIX {
                return Err(invalid_data("unexpected KeepKey report prefix"));
            }
            frame.extend_from_slice(&report[1..]);
            if total.is_none() && frame.len() >= HEADER_SIZE {
                if frame[..2] != *b"##" {
                    return Err(invalid_data("missing KeepKey frame magic"));
                }
                let payload_len =
                    u32::from_be_bytes([frame[4], frame[5], frame[6], frame[7]]) as usize;
                if payload_len > MAX_PAYLOAD_SIZE {
                    return Err(invalid_data("KeepKey frame is too large"));
                }
                total = Some(HEADER_SIZE + payload_len);
            }
            if let Some(total) = total
                && frame.len() >= total
            {
                frame.truncate(total);
                let message_type = u16::from_be_bytes([frame[2], frame[3]]);
                return Ok((message_type, frame.split_off(HEADER_SIZE)));
            }
        }
    }

    async fn exchange_with_timeout(
        &self,
        message_type: u16,
        payload: &[u8],
        timeout: Duration,
    ) -> io::Result<(u16, Vec<u8>)> {
        tokio::time::timeout(timeout, async {
            self.send_frame(&api::frame(message_type, payload)).await?;
            self.receive_frame().await
        })
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "timed out waiting for KeepKey debuglink response",
            )
        })?
    }

    async fn exchange(&self, message_type: u16, payload: &[u8]) -> io::Result<(u16, Vec<u8>)> {
        self.exchange_with_timeout(message_type, payload, DEBUGLINK_IO_TIMEOUT)
            .await
    }

    pub async fn decide(&self, button: DebugButton) -> io::Result<()> {
        // DebugLinkDecision.yes_no is protobuf field 1 (varint).
        self.send_frame(&api::frame(DEBUGLINK_DECISION, &[0x08, button as u8]))
            .await
    }

    /// Drives every confirmation screen until `future` completes.
    pub async fn drive<F>(&self, button: DebugButton, future: F) -> io::Result<F::Output>
    where
        F: Future,
    {
        self.drive_with_timeout(button, future, OPERATION_TIMEOUT)
            .await
    }

    async fn drive_with_timeout<F>(
        &self,
        button: DebugButton,
        future: F,
        timeout: Duration,
    ) -> io::Result<F::Output>
    where
        F: Future,
    {
        tokio::time::timeout(timeout, async {
            tokio::pin!(future);
            let mut interval = tokio::time::interval_at(
                tokio::time::Instant::now() + DECISION_INTERVAL,
                DECISION_INTERVAL,
            );
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    output = &mut future => return Ok(output),
                    _ = interval.tick() => self.decide(button).await?,
                }
            }
        })
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "timed out driving KeepKey operation",
            )
        })?
    }

    pub async fn state(&self) -> io::Result<DebugState> {
        let (message_type, payload) = self.exchange(DEBUGLINK_GET_STATE, &[]).await?;
        if message_type != DEBUGLINK_STATE {
            return Err(invalid_data("unexpected KeepKey debuglink response"));
        }
        let mut state = DebugLinkState::decode(payload.as_slice())
            .map_err(|_| invalid_data("invalid KeepKey debuglink state"))?;
        Ok(DebugState {
            matrix: state.matrix.take(),
            recovery_cipher: state.recovery_cipher.take(),
            recovery_auto_completed_word: state.recovery_auto_completed_word.take(),
        })
    }

    pub async fn pin_positions(&self, pin: &str) -> Result<String, MappingError> {
        let state = self
            .state()
            .await
            .map_err(|_| MappingError::DebugStateUnavailable)?;
        let matrix = state.matrix.ok_or(MappingError::MissingPinMatrix)?;
        encode_pin(pin, &matrix)
    }
}

pub async fn lock_device(addr: &str) -> io::Result<()> {
    let link = DebugLink::connect(addr).await?;
    let (message_type, _) = link.exchange(LOCK_DEVICE, &[]).await?;
    if message_type != SUCCESS {
        return Err(invalid_data("KeepKey did not acknowledge lock"));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MappingError {
    DebugStateUnavailable,
    InvalidPin,
    MissingPinMatrix,
    InvalidPinMatrix,
    MissingMnemonicWord,
    InvalidRecoveryPosition,
    MissingRecoveryCipher,
    InvalidRecoveryCipher,
}

impl std::fmt::Display for MappingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::DebugStateUnavailable => "KeepKey debuglink state is unavailable",
            Self::InvalidPin => "PIN must contain digits 1 through 9",
            Self::MissingPinMatrix => "KeepKey debuglink state has no PIN matrix",
            Self::InvalidPinMatrix => "KeepKey debuglink PIN matrix is invalid",
            Self::MissingMnemonicWord => "recovery requested a word outside the fixture",
            Self::InvalidRecoveryPosition => "recovery requested a character outside the word",
            Self::MissingRecoveryCipher => "KeepKey debuglink state has no recovery cipher",
            Self::InvalidRecoveryCipher => "KeepKey debuglink recovery cipher is invalid",
        })
    }
}

impl std::error::Error for MappingError {}

pub fn encode_pin(pin: &str, matrix: &str) -> Result<String, MappingError> {
    if pin.is_empty() || !pin.bytes().all(|digit| matches!(digit, b'1'..=b'9')) {
        return Err(MappingError::InvalidPin);
    }
    let bytes = matrix.as_bytes();
    if bytes.len() != 9
        || !(b'1'..=b'9').all(|digit| bytes.iter().filter(|value| **value == digit).count() == 1)
    {
        return Err(MappingError::InvalidPinMatrix);
    }
    pin.bytes()
        .map(|digit| {
            bytes
                .iter()
                .position(|value| *value == digit)
                .map(|position| char::from(b'1' + position as u8))
                .ok_or(MappingError::InvalidPinMatrix)
        })
        .collect()
}

pub fn map_host_response(
    pin: &str,
    mnemonic: &str,
    request: &HostRequest,
    state: &DebugState,
) -> Result<HostResponse, MappingError> {
    match request {
        HostRequest::PinMatrix { .. } => {
            let matrix = state
                .matrix
                .as_deref()
                .ok_or(MappingError::MissingPinMatrix)?;
            Ok(HostResponse::PinPositions(encode_pin(pin, matrix)?))
        }
        HostRequest::RecoveryCharacter {
            word_position,
            character_position,
        } => {
            let mut words = mnemonic.split_whitespace();
            let word = words
                .nth(*word_position as usize)
                .ok_or(MappingError::MissingMnemonicWord)?;
            let is_last_word = words.next().is_none();
            let completed = state.recovery_auto_completed_word.as_deref() == Some(word)
                || *character_position as usize >= word.len();
            if completed {
                return Ok(if is_last_word {
                    HostResponse::RecoveryDone
                } else {
                    HostResponse::RecoveryNextWord
                });
            }
            let plain = *word
                .as_bytes()
                .get(*character_position as usize)
                .ok_or(MappingError::InvalidRecoveryPosition)?;
            if !plain.is_ascii_lowercase() {
                return Err(MappingError::InvalidRecoveryPosition);
            }
            let cipher = state
                .recovery_cipher
                .as_deref()
                .ok_or(MappingError::MissingRecoveryCipher)?
                .as_bytes();
            if cipher.len() != 26
                || !(b'a'..=b'z')
                    .all(|letter| cipher.iter().filter(|value| **value == letter).count() == 1)
            {
                return Err(MappingError::InvalidRecoveryCipher);
            }
            Ok(HostResponse::RecoveryCharacter(
                cipher[(plain - b'a') as usize] as char,
            ))
        }
    }
}

pub fn response_line(response: HostResponse) -> String {
    match response {
        HostResponse::PinPositions(value) => value + "\n",
        HostResponse::RecoveryCharacter(value) => format!("{value}\n"),
        HostResponse::RecoveryDelete => "backspace\n".into(),
        HostResponse::RecoveryNextWord => "space\n".into(),
        HostResponse::RecoveryDone => "done\n".into(),
    }
}

/// Debuglink-backed host responses for direct, CLI, and parity emulator tests.
///
/// It intentionally has no `Debug` implementation because it owns the PIN and
/// mnemonic fixture.
pub struct KeepKeyHostInteraction {
    debug: DebugLink,
    pin: String,
    mnemonic: String,
}

impl KeepKeyHostInteraction {
    pub fn new(debug: DebugLink, pin: impl Into<String>, mnemonic: impl Into<String>) -> Self {
        Self {
            debug,
            pin: pin.into(),
            mnemonic: mnemonic.into(),
        }
    }

    pub async fn connect(
        debug_addr: &str,
        pin: impl Into<String>,
        mnemonic: impl Into<String>,
    ) -> io::Result<Self> {
        Ok(Self::new(
            DebugLink::connect(debug_addr).await?,
            pin,
            mnemonic,
        ))
    }

    pub async fn connect_default(
        pin: impl Into<String>,
        mnemonic: impl Into<String>,
    ) -> io::Result<Self> {
        Self::connect(DEFAULT_DEBUGLINK_ADDR, pin, mnemonic).await
    }

    pub async fn host_response(
        &mut self,
        request: &HostRequest,
    ) -> Result<HostResponse, common::Error> {
        let state = self
            .debug
            .state()
            .await
            .map_err(|_| common::Error::Request("KeepKey debuglink state unavailable"))?;
        map_host_response(&self.pin, &self.mnemonic, request, &state)
            .map_err(|error| common::Error::InvalidInput(error.to_string()))
    }

    pub async fn response_line(&mut self, request: &HostRequest) -> Result<String, common::Error> {
        self.host_response(request).await.map(response_line)
    }
}

#[async_trait(?Send)]
impl HostInteraction for KeepKeyHostInteraction {
    async fn respond(&mut self, request: &HostRequest) -> Result<HostResponse, common::Error> {
        self.host_response(request).await
    }
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bhwi::common::PinMatrixRequestKind;

    fn state(matrix: Option<&str>, cipher: Option<&str>, completed: Option<&str>) -> DebugState {
        DebugState {
            matrix: matrix.map(str::to_owned),
            recovery_cipher: cipher.map(str::to_owned),
            recovery_auto_completed_word: completed.map(str::to_owned),
        }
    }

    #[tokio::test]
    async fn silent_debuglink_peer_times_out() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = peer.local_addr().unwrap().to_string();
        let link = DebugLink::connect(&addr).await.unwrap();

        let error = link
            .exchange_with_timeout(DEBUGLINK_GET_STATE, &[], Duration::from_millis(10))
            .await
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(
            error.to_string(),
            "timed out waiting for KeepKey debuglink response"
        );
    }

    #[tokio::test]
    async fn unfinished_driven_operation_times_out() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = peer.local_addr().unwrap().to_string();
        let link = DebugLink::connect(&addr).await.unwrap();

        let error = link
            .drive_with_timeout(
                DebugButton::Yes,
                std::future::pending::<()>(),
                Duration::from_millis(10),
            )
            .await
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(error.to_string(), "timed out driving KeepKey operation");
    }

    #[test]
    fn pin_digits_follow_the_real_matrix() {
        assert_eq!(encode_pin("1234", "923456781").unwrap(), "9234");
        assert_eq!(encode_pin("0", "123456789"), Err(MappingError::InvalidPin));
        assert_eq!(
            encode_pin("1", "111111111"),
            Err(MappingError::InvalidPinMatrix)
        );
        assert_eq!(
            map_host_response(
                "1234",
                SYNTHETIC_MNEMONIC,
                &HostRequest::PinMatrix {
                    kind: PinMatrixRequestKind::NewFirst,
                },
                &state(Some("923456781"), None, None),
            )
            .unwrap(),
            HostResponse::PinPositions("9234".into())
        );
    }

    #[test]
    fn recovery_uses_cipher_autocomplete_and_final_done() {
        let cipher: String = ('a'..='z').rev().collect();
        assert_eq!(
            map_host_response(
                "1234",
                SYNTHETIC_MNEMONIC,
                &HostRequest::RecoveryCharacter {
                    word_position: 0,
                    character_position: 0,
                },
                &state(None, Some(&cipher), None),
            )
            .unwrap(),
            HostResponse::RecoveryCharacter('z')
        );
        assert_eq!(
            map_host_response(
                "1234",
                SYNTHETIC_MNEMONIC,
                &HostRequest::RecoveryCharacter {
                    word_position: 0,
                    character_position: 3,
                },
                &state(None, Some(&cipher), Some("alcohol")),
            )
            .unwrap(),
            HostResponse::RecoveryNextWord
        );
        assert_eq!(
            map_host_response(
                "1234",
                SYNTHETIC_MNEMONIC,
                &HostRequest::RecoveryCharacter {
                    word_position: 11,
                    character_position: 3,
                },
                &state(None, Some(&cipher), Some("aisle")),
            )
            .unwrap(),
            HostResponse::RecoveryDone
        );
    }

    #[test]
    fn child_responses_are_newline_delimited_tokens() {
        assert_eq!(
            response_line(HostResponse::PinPositions("42".into())),
            "42\n"
        );
        assert_eq!(response_line(HostResponse::RecoveryCharacter('q')), "q\n");
        assert_eq!(response_line(HostResponse::RecoveryDelete), "backspace\n");
        assert_eq!(response_line(HostResponse::RecoveryNextWord), "space\n");
        assert_eq!(response_line(HostResponse::RecoveryDone), "done\n");
    }
}
