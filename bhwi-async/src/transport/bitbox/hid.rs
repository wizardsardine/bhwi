use crate::{Transport, transport::Channel};
use async_trait::async_trait;

use bhwi::bitbox::u2f::{MAX_LEN, U2fHid};
pub use bhwi::bitbox::{
    BITBOX02_HID_USAGE_PAGE, BITBOX02_PID, BITBOX02_PRODUCT_STRINGS, BITBOX02_VID,
};
use bhwi::device::DeviceId;

pub const BITBOX02_DEVICE_ID: DeviceId = DeviceId::new(BITBOX02_VID)
    .with_pid(BITBOX02_PID)
    .with_emulator_path("tcp:127.0.0.1:15423");

/// U2F HID CMD byte for BitBox02 firmware traffic (`0xC1`).
const FIRMWARE_CMD: u8 = 0x80 + 0x40 + 0x01;
const HID_PACKET_LEN: usize = 64;

// HWW-level framing (firmware >= 7.0.0).
const HWW_REQ_NEW: u8 = 0x00;
const HWW_REQ_RETRY: u8 = 0x01;
const HWW_RSP_ACK: u8 = 0x00;
const HWW_RSP_NOTREADY: u8 = 0x01;
const HWW_RSP_BUSY: u8 = 0x02;
const HWW_RSP_NACK: u8 = 0x03;

#[derive(Debug, thiserror::Error)]
pub enum BitBoxHIDError {
    #[error("communication error: {0}")]
    Comm(&'static str),
    #[error("device NACK")]
    Nack,
    #[error("device busy")]
    Busy,
    #[error("U2F framing error")]
    U2f,
    #[error("HID write error: {0}")]
    Write(std::io::Error),
    #[error("HID read error: {0}")]
    Read(std::io::Error),
}

pub struct BitBoxTransportHID<C> {
    channel: C,
    u2f: U2fHid,
}

impl<C> BitBoxTransportHID<C> {
    pub fn new(channel: C) -> Self {
        Self {
            channel,
            u2f: U2fHid::new(FIRMWARE_CMD),
        }
    }
}

impl<C: Channel> BitBoxTransportHID<C> {
    async fn write_frame(&self, msg: &[u8]) -> Result<(), BitBoxHIDError> {
        let mut buf = vec![0u8; MAX_LEN];
        let size = self
            .u2f
            .encode(msg, &mut buf)
            .map_err(|_| BitBoxHIDError::U2f)?;
        for chunk in buf[..size].chunks(HID_PACKET_LEN) {
            let sent = self
                .channel
                .send(chunk)
                .await
                .map_err(BitBoxHIDError::Write)?;
            if sent < chunk.len() {
                return Err(BitBoxHIDError::Comm("short write"));
            }
        }
        Ok(())
    }

    async fn read_frame(&mut self) -> Result<Vec<u8>, BitBoxHIDError> {
        let mut buf = vec![0u8; HID_PACKET_LEN];
        let read = self
            .channel
            .receive(&mut buf)
            .await
            .map_err(BitBoxHIDError::Read)?;
        if read != HID_PACKET_LEN {
            return Err(BitBoxHIDError::Read(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "short read",
            )));
        }
        loop {
            match self.u2f.decode(&buf).map_err(|_| BitBoxHIDError::U2f)? {
                Some(payload) => return Ok(payload),
                None => {
                    let mut more = vec![0u8; HID_PACKET_LEN];
                    let read = self
                        .channel
                        .receive(&mut more)
                        .await
                        .map_err(BitBoxHIDError::Read)?;
                    if read != HID_PACKET_LEN {
                        return Err(BitBoxHIDError::Read(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "short read",
                        )));
                    }
                    buf.extend_from_slice(&more);
                }
            }
        }
    }

    async fn query_raw(&mut self, msg: &[u8]) -> Result<Vec<u8>, BitBoxHIDError> {
        self.write_frame(msg).await?;
        self.read_frame().await
    }
}

#[async_trait(?Send)]
impl<C: Channel> Transport for BitBoxTransportHID<C> {
    type Error = BitBoxHIDError;

    async fn exchange(&mut self, request: &[u8], _encrypted: bool) -> Result<Vec<u8>, Self::Error> {
        let mut framed = Vec::with_capacity(1 + request.len());
        framed.push(HWW_REQ_NEW);
        framed.extend_from_slice(request);

        let mut response = self.query_raw(&framed).await?;
        // Retry loop for BUSY / NOTREADY.
        loop {
            match response.first() {
                Some(&HWW_RSP_ACK) => return Ok(response.split_off(1)),
                Some(&HWW_RSP_BUSY) => return Err(BitBoxHIDError::Busy),
                Some(&HWW_RSP_NACK) => return Err(BitBoxHIDError::Nack),
                Some(&HWW_RSP_NOTREADY) => {
                    response = self.query_raw(&[HWW_REQ_RETRY]).await?;
                }
                _ => return Err(BitBoxHIDError::Comm("unexpected HWW response")),
            }
        }
    }

    fn is_post_write_disconnect(&self, error: &Self::Error) -> bool {
        matches!(error, BitBoxHIDError::Read(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct UnusedChannel;

    #[async_trait(?Send)]
    impl Channel for UnusedChannel {
        async fn send(&self, _data: &[u8]) -> Result<usize, std::io::Error> {
            unreachable!()
        }

        async fn receive(&mut self, _data: &mut [u8]) -> Result<usize, std::io::Error> {
            unreachable!()
        }
    }

    #[test]
    fn only_read_errors_are_post_write_disconnects() {
        let transport = BitBoxTransportHID::new(UnusedChannel);
        assert!(
            transport.is_post_write_disconnect(&BitBoxHIDError::Read(std::io::Error::from(
                std::io::ErrorKind::TimedOut
            )))
        );
        assert!(
            !transport.is_post_write_disconnect(&BitBoxHIDError::Write(std::io::Error::from(
                std::io::ErrorKind::BrokenPipe
            )))
        );
        assert!(!transport.is_post_write_disconnect(&BitBoxHIDError::Nack));
    }
}
