use std::io;
use std::time::Duration;

use bhwi::trezor::api;
use tokio::net::UdpSocket;

pub(crate) const DEFAULT_DEBUGLINK_ADDR: &str = "127.0.0.1:21325";

const DECISION: u16 = 100;
const REPORT_SIZE: usize = 64;
const CHUNK_SIZE: usize = 63;
const REPORT_PREFIX: u8 = 0x3f;

// DebugLinkDecision.button, protobuf field 1, varint.
const BUTTON_TAG: u8 = 0x08;

#[derive(Clone, Copy)]
enum DebugButton {
    No = 0,
    Yes = 1,
}

pub(crate) struct DebugLink {
    socket: UdpSocket,
}

impl DebugLink {
    pub(crate) async fn new(addr: &str) -> io::Result<Self> {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        socket
            .connect(addr.strip_prefix("udp:").unwrap_or(addr))
            .await?;
        Ok(Self { socket })
    }

    async fn decide(&self, button: DebugButton) -> io::Result<()> {
        let frame = api::frame(DECISION, &[BUTTON_TAG, button as u8]);
        for chunk in frame.chunks(CHUNK_SIZE) {
            let mut report = [0u8; REPORT_SIZE];
            report[0] = REPORT_PREFIX;
            report[1..1 + chunk.len()].copy_from_slice(chunk);
            self.socket.send(&report).await?;
        }
        Ok(())
    }

    pub(crate) async fn confirm_until_done(&self, every: Duration) {
        loop {
            tokio::time::sleep(every).await;
            let _ = self.decide(DebugButton::Yes).await;
        }
    }

    pub(crate) async fn decline_until_done(&self, every: Duration) {
        loop {
            tokio::time::sleep(every).await;
            let _ = self.decide(DebugButton::No).await;
        }
    }
}
