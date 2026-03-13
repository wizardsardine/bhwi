use async_trait::async_trait;
use serde_cbor::Value;

use crate::Transport;

pub struct TcpTransport<C> {
    pub client: C,
}

impl<C> TcpTransport<C> {
    pub fn new(client: C) -> TcpTransport<C> {
        TcpTransport { client }
    }
}

#[async_trait(?Send)]
pub trait TcpClient {
    async fn write_all(&mut self, command: &[u8]) -> Result<(), std::io::Error>;
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error>;
}

#[async_trait(?Send)]
impl<C: TcpClient> Transport for TcpTransport<C> {
    type Error = std::io::Error;

    async fn exchange(&mut self, command: &[u8], _encrypted: bool) -> Result<Vec<u8>, Self::Error> {
        self.client.write_all(command).await?;

        let mut buf = Vec::new();
        let mut temp = [0u8; 1024];

        // HACK: i don't know a better way right now!
        loop {
            let n = self.client.read(&mut temp).await?;
            // XXX: what happens when n is 0?
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
                    return Err(std::io::Error::other(e));
                }
            }
        }
    }
}
