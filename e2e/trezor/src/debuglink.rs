use std::io;
use std::net::UdpSocket as StdUdpSocket;
use std::time::Duration;

use bhwi::trezor::api;
use tokio::net::UdpSocket;

pub const DEFAULT_DEBUGLINK_ADDR: &str = "127.0.0.1:21325";

const DECISION: u16 = 100;
const REPORT_SIZE: usize = 64;
const CHUNK_SIZE: usize = 63;
const REPORT_PREFIX: u8 = 0x3f;

// DebugLinkDecision.button, protobuf field 1, varint.
const BUTTON_TAG: u8 = 0x08;

// DebugLinkDecision.input, protobuf field 3, length-delimited.
const INPUT_TAG: u8 = 0x1a;
const MAX_SINGLE_BYTE_LEN: usize = 0x7f;

#[derive(Clone, Copy)]
pub enum DebugButton {
    No = 0,
    Yes = 1,
}

pub fn button_reports(button: DebugButton) -> Vec<[u8; REPORT_SIZE]> {
    decision_reports(&[BUTTON_TAG, button as u8])
}

pub fn input_reports(text: &str) -> Vec<[u8; REPORT_SIZE]> {
    assert!(
        text.len() <= MAX_SINGLE_BYTE_LEN,
        "debuglink input must fit a single-byte protobuf length"
    );
    let mut payload = Vec::with_capacity(2 + text.len());
    payload.push(INPUT_TAG);
    payload.push(text.len() as u8);
    payload.extend_from_slice(text.as_bytes());
    decision_reports(&payload)
}

fn send_sync(socket: &StdUdpSocket, reports: Vec<[u8; REPORT_SIZE]>) -> io::Result<()> {
    for report in reports {
        socket.send(&report)?;
    }
    Ok(())
}

pub fn drive_model_t_recovery(pin: &str, mnemonic: &str) -> io::Result<()> {
    let screen = Duration::from_millis(1200);
    let key = Duration::from_millis(350);
    let socket = StdUdpSocket::bind("127.0.0.1:0")?;
    socket.connect(DEFAULT_DEBUGLINK_ADDR)?;

    std::thread::sleep(screen);
    send_sync(&socket, button_reports(DebugButton::Yes))?;
    std::thread::sleep(screen);
    send_sync(&socket, input_reports(pin))?;
    std::thread::sleep(screen);
    send_sync(&socket, input_reports(pin))?;
    std::thread::sleep(screen);
    send_sync(&socket, input_reports("12"))?;
    std::thread::sleep(screen);
    send_sync(&socket, button_reports(DebugButton::Yes))?;
    std::thread::sleep(screen);
    for word in mnemonic.split_whitespace() {
        send_sync(&socket, input_reports(word))?;
        std::thread::sleep(key);
    }
    std::thread::sleep(screen);
    send_sync(&socket, button_reports(DebugButton::Yes))
}

fn decision_reports(payload: &[u8]) -> Vec<[u8; REPORT_SIZE]> {
    api::frame(DECISION, payload)
        .chunks(CHUNK_SIZE)
        .map(|chunk| {
            let mut report = [0u8; REPORT_SIZE];
            report[0] = REPORT_PREFIX;
            report[1..1 + chunk.len()].copy_from_slice(chunk);
            report
        })
        .collect()
}

pub struct DebugLink {
    socket: UdpSocket,
}

impl DebugLink {
    pub async fn new(addr: &str) -> io::Result<Self> {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        socket
            .connect(addr.strip_prefix("udp:").unwrap_or(addr))
            .await?;
        Ok(Self { socket })
    }

    async fn send_reports(&self, reports: Vec<[u8; REPORT_SIZE]>) -> io::Result<()> {
        for report in reports {
            self.socket.send(&report).await?;
        }
        Ok(())
    }

    async fn decide(&self, button: DebugButton) -> io::Result<()> {
        self.send_reports(button_reports(button)).await
    }

    pub async fn input(&self, text: &str) -> io::Result<()> {
        self.send_reports(input_reports(text)).await
    }

    pub async fn confirm(&self) -> io::Result<()> {
        self.decide(DebugButton::Yes).await
    }

    pub async fn confirm_until_done(&self, every: Duration) {
        loop {
            tokio::time::sleep(every).await;
            let _ = self.decide(DebugButton::Yes).await;
        }
    }

    pub async fn decline_until_done(&self, every: Duration) {
        loop {
            tokio::time::sleep(every).await;
            let _ = self.decide(DebugButton::No).await;
        }
    }
}
