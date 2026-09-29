use std::sync::Arc;

#[cfg(any(feature = "keepkey", feature = "trezor"))]
use async_trait::async_trait;
#[cfg(any(feature = "keepkey", feature = "trezor"))]
use bhwi_async::HWIDeviceError;
#[cfg(any(feature = "keepkey", feature = "trezor"))]
use bhwi_async::HostPassphrase;
use bhwi_async::device::PairingCodePrompt;
#[cfg(any(feature = "keepkey", feature = "trezor"))]
use bhwi_async::device::PinPrompt;
#[cfg(feature = "keepkey")]
use bhwi_async::{
    ErrorKind, HostError, HostInteraction, HostRequest, HostResponse, PinMatrixRequestKind,
};

#[cfg(any(feature = "keepkey", feature = "trezor"))]
use crate::bhwi_capnp::PinKind;
use crate::bhwi_capnp::prompter;
#[cfg(feature = "keepkey")]
use crate::bhwi_capnp::recovery_input;
#[cfg(any(feature = "keepkey", feature = "trezor"))]
use crate::error::{self, ErrorCode, Failure};

/// The client's `Prompter` capability, if it passed one.
#[derive(Clone, Default)]
pub struct Prompter(Option<prompter::Client>);

impl Prompter {
    /// Wraps the capability the client passed, or `None`.
    pub fn new(client: Option<prompter::Client>) -> Self {
        Self(client)
    }

    /// Returns whether the client passed a `Prompter`.
    pub fn is_set(&self) -> bool {
        self.0.is_some()
    }

    /// Returns a callback that shows a BitBox02 pairing code to the client.
    pub fn pairing_code_prompt(&self) -> Option<PairingCodePrompt> {
        let client = self.0.clone()?;
        let (codes, mut received) = tokio::sync::mpsc::unbounded_channel::<String>();
        tokio::task::spawn_local(async move {
            while let Some(code) = received.recv().await {
                let mut request = client.pairing_code_request();
                request.get().set_code(&code);
                // The user compares the code on the device screen, so nothing here
                // waits for the client to answer.
                tokio::task::spawn_local(async move {
                    let _ = request.send().promise.await;
                });
            }
        });
        Some(Arc::new(move |code: &str| {
            let _ = codes.send(code.to_string());
        }))
    }

    #[cfg(any(feature = "keepkey", feature = "trezor"))]
    pub(crate) async fn ask_pin(&self, kind: PinKind) -> Result<String, Failure> {
        let mut request = self.client("a PIN")?.request_pin_request();
        request.get().set_kind(kind);
        let response = request.send().promise.await.map_err(error::prompter)?;
        Ok(response.get()?.get_positions()?.to_string()?)
    }

    #[cfg(feature = "keepkey")]
    async fn ask_recovery_character(
        &self,
        word_position: u32,
        character_position: u32,
    ) -> Result<HostResponse, Failure> {
        let mut request = self
            .client("a recovery character")?
            .request_recovery_character_request();
        {
            let mut params = request.get();
            params.set_word_position(word_position);
            params.set_character_position(character_position);
        }
        let response = request.send().promise.await.map_err(error::prompter)?;
        match response.get()?.get_input()?.which()? {
            recovery_input::Character(text) => {
                let text = text?.to_str()?;
                let mut chars = text.chars();
                match (chars.next(), chars.next()) {
                    (Some(character), None) => Ok(HostResponse::RecoveryCharacter(character)),
                    _ => Err(error::bad_argument(
                        "a recovery character must be exactly one character",
                    )),
                }
            }
            recovery_input::Delete(()) => Ok(HostResponse::RecoveryDelete),
            recovery_input::NextWord(()) => Ok(HostResponse::RecoveryNextWord),
            recovery_input::Done(()) => Ok(HostResponse::RecoveryDone),
        }
    }

    /// Asks the client for the host passphrase.
    #[cfg(any(feature = "keepkey", feature = "trezor"))]
    pub async fn request_passphrase(&self) -> Result<HostPassphrase, Failure> {
        let request = self.client("a passphrase")?.request_passphrase_request();
        let response = request.send().promise.await.map_err(error::prompter)?;
        Ok(HostPassphrase::new(
            response.get()?.get_passphrase()?.to_string()?,
        ))
    }

    #[cfg(any(feature = "keepkey", feature = "trezor"))]
    fn client(&self, needed: &str) -> Result<prompter::Client, Failure> {
        self.0.clone().ok_or_else(|| {
            Failure::new(
                ErrorCode::NotReady,
                format!("the device needs {needed} but the client passed no Prompter"),
            )
        })
    }
}

#[cfg(any(feature = "keepkey", feature = "trezor"))]
#[async_trait(?Send)]
impl PinPrompt for Prompter {
    async fn request_pin(&self) -> Result<String, HWIDeviceError> {
        self.ask_pin(PinKind::Current)
            .await
            .map_err(HWIDeviceError::new)
    }
}

#[cfg(feature = "keepkey")]
#[async_trait(?Send)]
impl HostInteraction for Prompter {
    async fn respond(&mut self, request: &HostRequest) -> Result<HostResponse, HostError> {
        let answered = match request {
            HostRequest::PinMatrix { kind } => {
                let kind = match kind {
                    PinMatrixRequestKind::Current => PinKind::Current,
                    PinMatrixRequestKind::NewFirst => PinKind::ChooseNew,
                    PinMatrixRequestKind::NewSecond => PinKind::ConfirmNew,
                    PinMatrixRequestKind::Unknown(value) => {
                        return Err(HostError::new(
                            ErrorKind::InvalidInput,
                            format!("the device asked for an unknown PIN matrix kind {value}"),
                        ));
                    }
                };
                self.ask_pin(kind).await.map(HostResponse::PinPositions)
            }
            HostRequest::RecoveryCharacter {
                word_position,
                character_position,
            } => {
                self.ask_recovery_character(*word_position, *character_position)
                    .await
            }
        };
        answered.map_err(host_error)
    }
}

/// A client reports refusal by raising `userCancelled`, and collapsing that into
/// `InvalidInput` would let a scan skip the device instead of stopping.
#[cfg(feature = "keepkey")]
fn host_error(failure: Failure) -> HostError {
    match failure.code {
        ErrorCode::UserCancelled => HostError::new(ErrorKind::UserCancelled, failure.message),
        _ => HostError::new(ErrorKind::InvalidInput, failure.to_string()),
    }
}
