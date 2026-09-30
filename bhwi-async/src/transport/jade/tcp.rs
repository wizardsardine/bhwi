use async_trait::async_trait;

use crate::{
    ErrorKind, Transport,
    transport::{io_error_kind, jade::CborStream},
};

/// Jade command exchanges over a CBOR byte stream.
pub struct TcpTransport<C> {
    /// The stream used to write commands and collect responses.
    pub client: C,
}

impl<C> TcpTransport<C> {
    /// Creates a transport from a stream without performing I/O.
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

    fn error_kind(&self, error: &Self::Error) -> ErrorKind {
        io_error_kind(error)
    }
}
