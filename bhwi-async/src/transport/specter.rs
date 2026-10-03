//! Stream framing for the Specter-DIY text protocol.
//!
//! The adapter deliberately returns the raw `ACK` and final-response bytes.
//! `bhwi::specter::ResponseDecoder` remains the authoritative parser for that
//! framing when the interpreter receives the result.

use std::{
    fmt::Debug,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use bhwi::specter::{MAX_RESPONSE_FRAME_SIZE, ResponseDecoder, SpecterError};

use crate::Transport;

/// Default limit for an on-device confirmation after a request is sent.
pub const DEFAULT_CONFIRMATION_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// Stream outcomes that callers must distinguish from ordinary I/O failures.
#[derive(Debug, thiserror::Error)]
pub enum SpecterStreamError<E: Debug> {
    /// The stream reported an I/O failure.
    #[error("stream I/O failed: {0:?}")]
    Io(
        /// The underlying stream error.
        E,
    ),
    /// The read deadline elapsed.
    #[error("Specter request timed out")]
    Timeout,
    /// The stream disconnected before completion.
    #[error("Specter stream disconnected")]
    Disconnected,
    /// The caller or runtime cancelled the operation.
    #[error("Specter request was cancelled")]
    Cancelled,
}

/// A byte stream that can perform one deadline-bound read.
///
/// Implementations should make `read_until` return `Timeout` when `deadline`
/// elapses, return `Disconnected` for EOF, and return `Cancelled` when their
/// runtime or caller cancels the pending operation. This keeps runtime policy
/// outside `bhwi-async` while ensuring confirmation waits are bounded.
///
/// Futures need not be `Send`; implementations choose their I/O runtime.
#[async_trait(?Send)]
pub trait SpecterStream {
    /// The underlying stream's I/O error type.
    type Error: Debug;

    /// Writes the complete request or reports a stream failure.
    async fn write_all(&mut self, request: &[u8]) -> Result<(), SpecterStreamError<Self::Error>>;
    /// Reads bytes before `deadline`, reporting timeout, disconnect, or cancellation.
    async fn read_until(
        &mut self,
        buffer: &mut [u8],
        deadline: Instant,
    ) -> Result<usize, SpecterStreamError<Self::Error>>;
}

/// A Specter-DIY stream, response-framing, or exchange-lifecycle failure.
#[derive(Debug, thiserror::Error)]
pub enum SpecterTransportError<E: Debug> {
    /// The stream reported an I/O failure.
    #[error("Specter stream I/O failed: {0:?}")]
    Io(
        /// The underlying stream error.
        E,
    ),
    /// The confirmation deadline elapsed.
    #[error("Specter request timed out")]
    Timeout,
    /// The stream disconnected before a complete response.
    #[error("Specter stream disconnected")]
    Disconnected,
    /// The caller or runtime cancelled the exchange.
    #[error("Specter request was cancelled")]
    Cancelled,
    /// The response did not follow the Specter-DIY framing protocol.
    #[error("invalid Specter response framing: {0}")]
    Protocol(
        /// The response-decoding error.
        #[source]
        SpecterError,
    ),
    /// The response exceeded the protocol's frame-size limit.
    #[error("Specter response is too large")]
    ResponseTooLarge,
    /// An earlier incomplete exchange left the transport unusable.
    #[error("Specter transport is unusable after an incomplete exchange")]
    Poisoned,
}

impl<E: Debug> From<SpecterStreamError<E>> for SpecterTransportError<E> {
    fn from(error: SpecterStreamError<E>) -> Self {
        match error {
            SpecterStreamError::Io(error) => Self::Io(error),
            SpecterStreamError::Timeout => Self::Timeout,
            SpecterStreamError::Disconnected => Self::Disconnected,
            SpecterStreamError::Cancelled => Self::Cancelled,
        }
    }
}

/// A serialized, deadline-bound Specter-DIY transport over a byte stream.
///
/// `Transport::exchange` requires `&mut self`, so calls cannot overlap. The
/// adapter becomes unusable as soon as an exchange starts and recovers only
/// after receiving a complete, valid response frame. This prevents a later
/// request from consuming a stale reply after cancellation, a timeout, a
/// disconnect, an I/O failure, an oversized response, or a dropped future.
pub struct SpecterTransport<S> {
    stream: S,
    confirmation_timeout: Duration,
    state: ExchangeState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExchangeState {
    Ready,
    Poisoned,
}

impl<S> SpecterTransport<S> {
    /// Creates a ready transport using [`DEFAULT_CONFIRMATION_TIMEOUT`].
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            confirmation_timeout: DEFAULT_CONFIRMATION_TIMEOUT,
            state: ExchangeState::Ready,
        }
    }

    /// Sets the response-confirmation timeout measured after the request is written.
    ///
    /// A later exchange can panic if adding `timeout` to the current instant overflows.
    pub fn with_confirmation_timeout(mut self, timeout: Duration) -> Self {
        self.confirmation_timeout = timeout;
        self
    }

    /// Returns the stream, without draining stale responses from an incomplete exchange.
    pub fn into_inner(self) -> S {
        self.stream
    }
}

#[async_trait(?Send)]
impl<S: SpecterStream> Transport for SpecterTransport<S> {
    type Error = SpecterTransportError<S::Error>;

    async fn exchange(&mut self, request: &[u8], _encrypted: bool) -> Result<Vec<u8>, Self::Error> {
        if self.state != ExchangeState::Ready {
            return Err(SpecterTransportError::Poisoned);
        }
        // Set this before the first await. If this future is dropped during a
        // write or confirmation wait, the next request cannot consume its
        // possible delayed reply.
        self.state = ExchangeState::Poisoned;
        self.stream
            .write_all(request)
            .await
            .map_err(SpecterTransportError::from)?;

        let deadline = Instant::now() + self.confirmation_timeout;
        let mut response = Vec::new();
        let mut decoder = ResponseDecoder::default();
        let mut chunk = [0u8; 16 * 1024];
        loop {
            let received = self
                .stream
                .read_until(&mut chunk, deadline)
                .await
                .map_err(SpecterTransportError::from)?;
            if received == 0 {
                return Err(SpecterTransportError::Disconnected);
            }
            if response.len().saturating_add(received) > MAX_RESPONSE_FRAME_SIZE {
                return Err(SpecterTransportError::ResponseTooLarge);
            }
            let complete = decoder
                .push(&chunk[..received])
                .map_err(|error| match error {
                    SpecterError::ResponseTooLarge => SpecterTransportError::ResponseTooLarge,
                    error => SpecterTransportError::Protocol(error),
                })?;
            response.extend_from_slice(&chunk[..received]);
            if complete.is_some() {
                self.state = ExchangeState::Ready;
                return Ok(response);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bhwi::specter::MAX_RESPONSE_SIZE;
    use futures::{Future, executor::block_on, task::noop_waker_ref};
    use std::{
        collections::VecDeque,
        convert::Infallible,
        task::{Context, Poll},
    };

    struct ScriptedStream {
        writes: Vec<Vec<u8>>,
        reads: VecDeque<Result<Vec<u8>, SpecterStreamError<Infallible>>>,
        deadlines: Vec<Instant>,
    }

    #[async_trait(?Send)]
    impl SpecterStream for ScriptedStream {
        type Error = Infallible;

        async fn write_all(
            &mut self,
            request: &[u8],
        ) -> Result<(), SpecterStreamError<Self::Error>> {
            self.writes.push(request.to_vec());
            Ok(())
        }

        async fn read_until(
            &mut self,
            buffer: &mut [u8],
            deadline: Instant,
        ) -> Result<usize, SpecterStreamError<Self::Error>> {
            self.deadlines.push(deadline);
            let mut bytes = self.reads.pop_front().expect("a scripted read")?;
            if bytes.len() > buffer.len() {
                let remainder = bytes.split_off(buffer.len());
                self.reads.push_front(Ok(remainder));
            }
            buffer[..bytes.len()].copy_from_slice(&bytes);
            Ok(bytes.len())
        }
    }

    fn transport(
        reads: impl IntoIterator<Item = Result<Vec<u8>, SpecterStreamError<Infallible>>>,
    ) -> SpecterTransport<ScriptedStream> {
        SpecterTransport::new(ScriptedStream {
            writes: Vec::new(),
            reads: reads.into_iter().collect(),
            deadlines: Vec::new(),
        })
        .with_confirmation_timeout(Duration::from_secs(30))
    }

    #[test]
    fn buffers_fragmented_ack_and_final_response() {
        let mut transport = transport([
            Ok(b"AC".to_vec()),
            Ok(b"K\r\ndead".to_vec()),
            Ok(b"beef\r\n".to_vec()),
        ]);

        let response = block_on(transport.exchange(b"request", false)).unwrap();

        assert_eq!(response, b"ACK\r\ndeadbeef\r\n");
        assert_eq!(transport.stream.writes, vec![b"request".to_vec()]);
        assert!(
            transport
                .stream
                .deadlines
                .iter()
                .all(|deadline| *deadline > Instant::now())
        );
    }

    #[test]
    fn returns_coalesced_raw_framing_to_the_interpreter() {
        let mut transport = transport([Ok(b"ACK\r\nresult\r\n".to_vec())]);

        let response = block_on(transport.exchange(b"request", false)).unwrap();

        assert_eq!(response, b"ACK\r\nresult\r\n");
    }

    #[test]
    fn maps_timeout_disconnect_and_cancellation() {
        for (read, expected) in [
            (Err(SpecterStreamError::Timeout), "timeout"),
            (Err(SpecterStreamError::Disconnected), "disconnect"),
            (Err(SpecterStreamError::Cancelled), "cancelled"),
        ] {
            let mut transport = transport([read]);
            let error = block_on(transport.exchange(b"request", false)).unwrap_err();
            match (expected, error) {
                ("timeout", SpecterTransportError::Timeout)
                | ("disconnect", SpecterTransportError::Disconnected)
                | ("cancelled", SpecterTransportError::Cancelled) => {}
                _ => panic!("unexpected transport error"),
            }
        }
    }

    #[test]
    fn incomplete_exchanges_poison_the_transport() {
        let mut transport = transport([
            Err(SpecterStreamError::Timeout),
            Ok(b"ACK\r\nresult\r\n".to_vec()),
        ]);
        assert!(matches!(
            block_on(transport.exchange(b"first", false)),
            Err(SpecterTransportError::Timeout)
        ));
        assert!(matches!(
            block_on(transport.exchange(b"second", false)),
            Err(SpecterTransportError::Poisoned)
        ));
        assert_eq!(transport.stream.writes, vec![b"first".to_vec()]);
    }

    struct PendingWriteStream;

    #[async_trait(?Send)]
    impl SpecterStream for PendingWriteStream {
        type Error = Infallible;

        async fn write_all(
            &mut self,
            _request: &[u8],
        ) -> Result<(), SpecterStreamError<Self::Error>> {
            futures::future::pending::<()>().await;
            Ok(())
        }

        async fn read_until(
            &mut self,
            _buffer: &mut [u8],
            _deadline: Instant,
        ) -> Result<usize, SpecterStreamError<Self::Error>> {
            unreachable!("a pending write never starts a read")
        }
    }

    #[test]
    fn dropped_exchange_future_poison_the_transport() {
        let mut transport = SpecterTransport::new(PendingWriteStream);
        let mut exchange = Box::pin(transport.exchange(b"first", false));
        let mut context = Context::from_waker(noop_waker_ref());
        assert!(matches!(
            exchange.as_mut().poll(&mut context),
            Poll::Pending
        ));
        drop(exchange);

        assert!(matches!(
            block_on(transport.exchange(b"second", false)),
            Err(SpecterTransportError::Poisoned)
        ));
    }

    #[test]
    fn eof_oversized_and_invalid_ack_responses_are_rejected() {
        let mut eof = transport([Ok(Vec::new())]);
        assert!(matches!(
            block_on(eof.exchange(b"request", false)),
            Err(SpecterTransportError::Disconnected)
        ));

        let oversized_chunks = std::iter::once(Ok(b"ACK\r\n".to_vec()))
            .chain((0..MAX_RESPONSE_FRAME_SIZE / (16 * 1024)).map(|_| Ok(vec![b'x'; 16 * 1024])))
            .chain(std::iter::once(Ok(vec![b'x'; 2])));
        let mut oversized = transport(oversized_chunks);
        let error = block_on(oversized.exchange(b"request", false)).unwrap_err();
        assert!(matches!(error, SpecterTransportError::ResponseTooLarge));

        let mut invalid_ack = transport([Ok(b"NOPE\r\nresult\r\n".to_vec())]);
        assert!(matches!(
            block_on(invalid_ack.exchange(b"request", false)),
            Err(SpecterTransportError::Protocol(
                SpecterError::MalformedFraming(_)
            ))
        ));
    }

    #[test]
    fn accepts_a_maximum_sized_response_frame() {
        let chunks = std::iter::once(Ok(b"ACK\r\n".to_vec()))
            .chain((0..MAX_RESPONSE_SIZE / (16 * 1024)).map(|_| Ok(vec![b'x'; 16 * 1024])))
            .chain(std::iter::once(Ok(b"\r\n".to_vec())));
        let mut transport = transport(chunks);

        let response = block_on(transport.exchange(b"request", false)).unwrap();

        assert_eq!(response.len(), MAX_RESPONSE_FRAME_SIZE);
    }
}
