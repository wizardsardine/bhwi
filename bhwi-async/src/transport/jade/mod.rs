use async_trait::async_trait;
pub use bhwi::jade::JADE_DEVICE_IDS;
use serde_cbor::Value;

/// Jade CBOR exchanges over a stream.
pub mod tcp;

/// An asynchronous byte stream used to collect Jade CBOR responses.
///
/// Futures need not be `Send`; implementations supply runtime and timeout policy.
#[async_trait(?Send)]
pub trait CborStream {
    /// Writes the complete encoded command or returns an I/O error.
    async fn write_all(&mut self, command: &[u8]) -> Result<(), std::io::Error>;
    /// Reads bytes into `buf`, returning zero when the stream ends.
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error>;

    /// Reads from the client until a complete CBOR value is received.
    ///
    /// Returns an error for end-of-stream before completion, malformed CBOR, or
    /// trailing bytes after a complete value in the accumulated buffer.
    /// Reads have no adapter timeout.
    async fn read_cbor_message(&mut self) -> Result<Vec<u8>, std::io::Error> {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];

        loop {
            let n = self.read(&mut chunk).await?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "stream ended before complete CBOR message",
                ));
            }
            buf.extend_from_slice(&chunk[..n]);
            let mut cursor = std::io::Cursor::new(&buf);
            match serde_cbor::from_reader::<Value, _>(&mut cursor) {
                Ok(_) => return Ok(buf),
                Err(e) if e.is_io() || e.is_eof() => continue,
                Err(e) => return Err(std::io::Error::other(e)),
            }
        }
    }
}
