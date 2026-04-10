use async_trait::async_trait;

use crate::{Transport, transport::jade::CborStream};

pub struct TcpTransport<C> {
    pub client: C,
}

impl<C> TcpTransport<C> {
    pub fn new(client: C) -> TcpTransport<C> {
        TcpTransport { client }
    }
}

#[async_trait(?Send)]
impl<C: CborStream> Transport for TcpTransport<C> {
    type Error = std::io::Error;

    async fn exchange(&mut self, command: &[u8], _encrypted: bool) -> Result<Vec<u8>, Self::Error> {
        self.client.write_all(command).await?;
        self.client.read_cbor_message().await
    }
}
