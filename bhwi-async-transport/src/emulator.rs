//! UDP channels for emulators using the Trezor V1 wire format.

use std::time::Duration;

use async_trait::async_trait;
use bhwi_async::transport::Channel;
use tokio::net::UdpSocket;

pub use bhwi::trezor::DEFAULT_TREZOR_EMULATOR as DEFAULT_EMULATOR_ADDR;

pub(crate) const EMULATOR_PROBE_TIMEOUT: Duration = Duration::from_millis(500);

const PING: &[u8; 8] = b"PINGPING";
const PONG: &[u8; 8] = b"PONGPONG";

pub(crate) fn emulator_socket(path: &str) -> &str {
    path.strip_prefix("udp:").unwrap_or(path)
}

/// A connected IPv4 loopback UDP channel for an emulator.
///
/// Construction does not establish that an emulator is listening; use
/// [`Self::ping`] to probe it.
pub struct EmulatorClient {
    socket: UdpSocket,
}

impl EmulatorClient {
    /// Binds a local ephemeral port and connects it to the emulator address.
    ///
    /// `addr` may be a socket address with or without a `udp:` prefix.
    pub async fn new(addr: &str) -> std::io::Result<Self> {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        socket.connect(emulator_socket(addr)).await?;
        Ok(Self { socket })
    }

    /// Sends `PINGPING` and checks the first eight reply bytes for `PONGPONG`.
    ///
    /// Waits up to `timeout` for the reply. An eight-byte receive buffer can truncate
    /// longer UDP datagrams on Unix, so a matching prefix need not be an exact datagram.
    /// Returns `false` on send or receive failure, timeout, or a nonmatching prefix.
    pub async fn ping(&self, timeout: Duration) -> bool {
        if self.socket.send(PING).await.is_err() {
            return false;
        }
        let mut buf = [0u8; PONG.len()];
        matches!(
            tokio::time::timeout(timeout, self.socket.recv(&mut buf)).await,
            Ok(Ok(read)) if read == PONG.len() && &buf == PONG
        )
    }
}

#[async_trait(?Send)]
impl Channel for EmulatorClient {
    async fn send(&self, data: &[u8]) -> Result<usize, std::io::Error> {
        self.socket.send(data).await
    }

    async fn receive(&mut self, data: &mut [u8]) -> Result<usize, std::io::Error> {
        self.socket.recv(data).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bhwi_async::Transport;
    use bhwi_async::transport::trezor::TrezorTransport;

    const REPORT_SIZE: usize = 64;

    fn v1_frame(msg_type: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = b"##".to_vec();
        frame.extend_from_slice(&msg_type.to_be_bytes());
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    async fn peer() -> (UdpSocket, String) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap().to_string();
        (socket, addr)
    }

    #[test]
    fn emulator_socket_accepts_both_forms() {
        assert_eq!(emulator_socket("udp:127.0.0.1:21324"), "127.0.0.1:21324");
        assert_eq!(emulator_socket("127.0.0.1:21324"), "127.0.0.1:21324");
    }

    #[tokio::test]
    async fn ping_detects_a_listening_emulator() {
        let (socket, addr) = peer().await;
        tokio::spawn(async move {
            let mut buf = [0u8; REPORT_SIZE];
            let (read, from) = socket.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..read], PING);
            socket.send_to(PONG, from).await.unwrap();
        });

        let client = EmulatorClient::new(&addr).await.unwrap();
        assert!(client.ping(Duration::from_secs(5)).await);
    }

    #[tokio::test]
    async fn ping_reports_a_missing_emulator() {
        let (socket, addr) = peer().await;
        drop(socket);

        let client = EmulatorClient::new(&addr).await.unwrap();
        assert!(!client.ping(Duration::from_millis(250)).await);
    }

    #[tokio::test]
    async fn reports_round_trip_over_udp() {
        let (socket, addr) = peer().await;
        let reply = v1_frame(30, &[0xab; 100]);
        let replied = reply.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; REPORT_SIZE];
            let (_, from) = socket.recv_from(&mut buf).await.unwrap();
            for chunk in replied.chunks(REPORT_SIZE - 1) {
                let mut report = [0u8; REPORT_SIZE];
                report[0] = 0x3f;
                report[1..1 + chunk.len()].copy_from_slice(chunk);
                socket.send_to(&report, from).await.unwrap();
            }
        });

        let client = EmulatorClient::new(&addr).await.unwrap();
        let mut transport = TrezorTransport::new(client);
        let out = transport.exchange(&v1_frame(29, b""), false).await.unwrap();
        assert_eq!(out, reply);
    }
}
