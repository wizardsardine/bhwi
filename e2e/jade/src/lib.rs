use async_trait::async_trait;
use bhwi_async::{HttpClient, Jade, Transport};
use reqwest::Client;
use serde_cbor::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub type JadeDevice = Jade<TcpClient, PinServerClient>;

pub struct TcpClient {
    stream: TcpStream,
}

#[async_trait(?Send)]
impl Transport for TcpClient {
    type Error = anyhow::Error;

    async fn exchange(&mut self, command: &[u8], _encrypted: bool) -> Result<Vec<u8>, Self::Error> {
        self.stream.write_all(command).await?;

        let mut buf = Vec::new();
        let mut temp = [0u8; 1024];

        // HACK: i don't know a better way right now!
        loop {
            let n = self.stream.read(&mut temp).await?;
            if n == 0 {
                panic!("connection closed");
            }
            buf.extend_from_slice(&temp[..n]);
            let mut cursor = std::io::Cursor::new(&buf);
            match serde_cbor::from_reader::<Value, _>(&mut cursor) {
                Ok(_) => {
                    return Ok(buf);
                }
                Err(e) if e.is_io() => {
                    continue; // read more bytes
                }
                Err(e) => {
                    return Err(e.into());
                }
            }
        }
    }
}

pub struct PinServerClient {
    inner: Client,
}

#[async_trait(?Send)]
impl HttpClient for PinServerClient {
    type Error = anyhow::Error;

    async fn request(&self, url: &str, request: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Ok(self
            .inner
            .post(url)
            .header("Content-Type", "application/octet-stream")
            .body(request.to_vec())
            .send()
            .await?
            .bytes()
            .await?
            .to_vec())
    }
}

#[cfg(test)]
mod tests {
    use base64ct::{Base64, Encoding};
    use bhwi_async::HWI;
    use bitcoin::Network;

    use super::*;

    async fn device() -> JadeDevice {
        let mut dev = JadeDevice::new(
            Network::Testnet,
            TcpClient {
                stream: TcpStream::connect("localhost:30121").await.unwrap(),
            },
            PinServerClient {
                inner: Client::new(),
            },
        );
        dev.unlock(Network::Testnet).await.expect("jade auth");
        dev
    }

    #[tokio::test]
    async fn can_get_master_fingerprint() {
        let mut dev = device().await;
        let fingerprint = dev.get_master_fingerprint().await.unwrap();
        assert_eq!(fingerprint.to_string(), "e3ebcc79");
    }

    #[tokio::test]
    async fn can_get_xpub() {
        let mut dev = device().await;
        let xpub = dev
            .get_extended_pubkey("m/44'/1'/0'".parse().unwrap(), false)
            .await
            .unwrap();
        assert_eq!(
            xpub.to_string(),
            "tpubDCKD5cdxMEFd2i4cNa3PJUbUHMsGDxsnfqjxVpMoG1ymWYUQUaZzTcHQo3JwYgaKe2FyKGA2FzGPSVczBoAiHGyERuA1mZ2UkGKufEnUxKk"
        );
    }

    #[tokio::test]
    async fn can_sign_message() {
        let mut dev = device().await;
        let (header, s) = dev
            .sign_message(b"hello", "m/44'/1'/0'".parse().unwrap())
            .await
            .unwrap();
        let mut sig = vec![header];
        sig.extend_from_slice(&s.serialize_compact());
        assert_eq!(
            Base64::encode_string(&sig),
            "H+SvKg15TSz+2C5ra6Q8/e8BaImOZVEeS0rOL6GCEt4vO+4xRRt+YYKavSqgAJBYZaGEiTqr7f9imyyElMNhYXU="
        );
    }
}
