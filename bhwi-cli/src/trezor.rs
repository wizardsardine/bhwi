pub mod emulator {
    use std::time::Duration;

    use anyhow::Result;
    use async_trait::async_trait;
    use bhwi_async::{
        transport::{Channel, trezor::TrezorTransport},
        trezor::Trezor,
    };
    use tokio::net::UdpSocket;

    pub const DEFAULT_EMULATOR_ADDR: &str = "127.0.0.1:21324";

    const PING: &[u8; 8] = b"PINGPING";
    const PONG: &[u8; 8] = b"PONGPONG";

    pub type TrezorEmulatorDevice = Trezor<TrezorTransport<EmulatorClient>>;

    pub struct EmulatorClient {
        socket: UdpSocket,
    }

    impl EmulatorClient {
        pub async fn new(addr: &str) -> Result<Self> {
            let socket = UdpSocket::bind("127.0.0.1:0").await?;
            socket.connect(addr).await?;
            Ok(Self { socket })
        }

        // UDP has no connect to probe, so a running emulator can only be found
        // by asking it to answer.
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
}
