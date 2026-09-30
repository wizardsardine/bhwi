use crate::{
    ErrorKind, Transport,
    transport::{Channel, io_error_kind},
};
use async_trait::async_trait;

pub use bhwi::coldcard::COLDCARD_DEVICE_ID;

const COLDCARD_PACKET_WRITE_SIZE: usize = 63;
const COLDCARD_PACKET_READ_SIZE: usize = 64;

/// A Coldcard packet-framing or channel failure.
#[derive(Debug, thiserror::Error)]
pub enum ColdcardHIDError {
    /// A channel transfer did not contain a complete report.
    #[error("communication error: {0}")]
    Comm(
        /// The short-transfer description.
        &'static str,
    ),

    /// A channel I/O failure.
    #[error("HID IO error: {0}")]
    Hid(
        /// The channel error.
        #[from]
        std::io::Error,
    ),
}

/// Coldcard exchanges over 64-byte reports with 63-byte payload chunks.
///
/// Marks the final outgoing report with the payload's encryption flag; it does
/// not encrypt the payload. Read timeouts are supplied by the channel.
pub struct ColdcardTransportHID<C> {
    channel: C,
}

impl<C> ColdcardTransportHID<C> {
    /// Creates a framing adapter without contacting the device.
    pub fn new(channel: C) -> Self {
        Self { channel }
    }
}

#[async_trait(?Send)]
impl<C: Channel> Transport for ColdcardTransportHID<C> {
    type Error = ColdcardHIDError;

    async fn exchange(&mut self, request: &[u8], encrypted: bool) -> Result<Vec<u8>, Self::Error> {
        let mut buffer = vec![0u8; COLDCARD_PACKET_WRITE_SIZE + 1];
        let chunks = request.chunks(COLDCARD_PACKET_WRITE_SIZE);
        let n_chunks = chunks.len();
        for (i, chunk) in chunks.enumerate() {
            // Windows platform requires 0x00 prefix and Linux/Mac tolerate this as well
            // buffer[0] = 0;
            buffer[0] = (chunk.len() as u8)
                | if i == n_chunks - 1 {
                    0x80 | if encrypted { 0x40 } else { 0x00 }
                } else {
                    0x00
                };
            buffer[1..1 + chunk.len()].copy_from_slice(chunk);

            match self.channel.send(&buffer).await {
                Ok(size) => {
                    if size < buffer.len() {
                        return Err(ColdcardHIDError::Comm(
                            "USB write error. Could not send whole message",
                        ));
                    }
                }
                Err(e) => {
                    return Err(ColdcardHIDError::Hid(e));
                }
            }
        }

        let mut data: Vec<u8> = Vec::new();
        let mut buffer = vec![0u8; COLDCARD_PACKET_READ_SIZE];
        let mut is_first = true;

        loop {
            let read = self.channel.receive(&mut buffer).await?;

            if read != buffer.len() {
                return Err(ColdcardHIDError::Comm(
                    "USB read error. Could not read whole message",
                ));
            }
            let flag = buffer[0];
            let is_last = flag & 0x80 != 0;
            let is_fram = &buffer[1..5] == b"fram" && is_first;
            // firmware bug mitigation: `fram` responses are one packet but forget to set 0x80
            let is_last = is_last || is_fram;
            let length = (flag & 0x3f) as usize;

            data.extend(&buffer[1..1 + length]);

            is_first = false;
            if is_last {
                break;
            }
        }

        Ok(data)
    }

    fn error_kind(&self, error: &Self::Error) -> ErrorKind {
        match error {
            ColdcardHIDError::Hid(error) => io_error_kind(error),
            ColdcardHIDError::Comm(_) => ErrorKind::Transport,
        }
    }
}
