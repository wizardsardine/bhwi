use async_trait::async_trait;
pub use bhwi::jade::JADE_DEVICE_IDS;
use serde_cbor::Value;

#[cfg(feature = "emulators")]
pub mod tcp;

#[async_trait(?Send)]
pub trait CborStream {
    async fn write_all(&mut self, command: &[u8]) -> Result<(), std::io::Error>;
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error>;

    /// Reads from the client until a complete CBOR value is received.
    async fn read_cbor_message(&mut self) -> Result<Vec<u8>, std::io::Error> {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];

        loop {
            let n = self.read(&mut chunk).await?;
            if n == 0 {
                return Err(std::io::Error::other(
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
