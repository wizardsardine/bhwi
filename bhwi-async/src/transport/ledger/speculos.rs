use std::fmt::Debug;

use async_trait::async_trait;

use crate::{Transport, transport::Channel};

/// Ledger APDU exchanges over a Speculos length-prefixed channel.
///
/// The channel must complete each requested transfer: returned byte counts are
/// not checked. Responses include the trailing two-byte status word.
pub struct LedgerTransportTcp<C: Channel> {
    channel: C,
}

/// A Speculos channel or response failure.
#[derive(Debug, thiserror::Error)]
pub enum LedgerTcpError {
    /// The channel reported an I/O failure.
    #[error("ledger io error: {0}")]
    Io(
        /// The channel error.
        #[from]
        std::io::Error,
    ),

    /// A response was invalid.
    #[error("ledger invalid response")]
    InvalidResponse,
}

impl<C: Channel> LedgerTransportTcp<C> {
    /// Creates an emulator framing adapter without performing I/O.
    pub fn new(channel: C) -> Self {
        Self { channel }
    }
}

#[async_trait(?Send)]
impl<C: Channel> Transport for LedgerTransportTcp<C> {
    type Error = LedgerTcpError;

    async fn exchange(
        &mut self,
        apdu_command: &[u8],
        _encrypted: bool,
    ) -> Result<Vec<u8>, Self::Error> {
        let mut tx = Vec::with_capacity(4 + apdu_command.len());
        tx.extend_from_slice(&(apdu_command.len() as u32).to_be_bytes());
        tx.extend_from_slice(apdu_command);

        self.channel.send(&tx).await?;

        let mut len_buf = [0u8; 4];
        self.channel.receive(&mut len_buf).await?;

        let resp_len = u32::from_be_bytes(len_buf) as usize;

        let mut resp = vec![0u8; resp_len + 2];
        self.channel.receive(&mut resp).await?;

        Ok(resp)
    }
}
