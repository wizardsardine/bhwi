use async_trait::async_trait;
use bhwi_async::transport::jade::tcp::{TcpClient, TcpTransport};
use bhwi_async::{HttpClient, Jade};
use reqwest::Client as ReqwestClient;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub type JadeDevice = Jade<TcpTransport<Client>, PinServerClient>;

pub struct Client {
    stream: TcpStream,
}

#[async_trait(?Send)]
impl TcpClient for Client {
    type Error = anyhow::Error;

    async fn write_all(&mut self, command: &[u8]) -> Result<(), Self::Error> {
        Ok(self.stream.write_all(command).await?)
    }
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        Ok(self.stream.read(buf).await?)
    }
}

pub struct PinServerClient {
    inner: ReqwestClient,
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
            TcpTransport::new(Client {
                stream: TcpStream::connect("localhost:30121").await.unwrap(),
            }),
            PinServerClient {
                inner: ReqwestClient::new(),
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
