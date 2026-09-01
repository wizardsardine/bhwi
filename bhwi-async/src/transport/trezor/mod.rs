use crate::{Transport, transport::Channel};
use async_trait::async_trait;

const REPORT_SIZE: usize = 64;
const CHUNK_SIZE: usize = 63;
const REPORT_PREFIX: u8 = 0x3f;
const HEADER_LEN: usize = 8;
const MAGIC: [u8; 2] = *b"##";
// Well above any device-to-host V1 message; a Trezor One has 192 KB of SRAM in total.
const MAX_PAYLOAD_LEN: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum TrezorTransportError {
    #[error("communication error: {0}")]
    Comm(&'static str),

    #[error("IO error")]
    Io(#[from] std::io::Error),
}

pub struct TrezorTransport<C> {
    channel: C,
}

impl<C> TrezorTransport<C> {
    pub fn new(channel: C) -> Self {
        Self { channel }
    }
}

#[async_trait(?Send)]
impl<C: Channel> Transport for TrezorTransport<C> {
    type Error = TrezorTransportError;

    async fn exchange(&mut self, request: &[u8], _encrypted: bool) -> Result<Vec<u8>, Self::Error> {
        let mut report = [0u8; REPORT_SIZE];
        for chunk in request.chunks(CHUNK_SIZE) {
            report.fill(0);
            report[0] = REPORT_PREFIX;
            report[1..1 + chunk.len()].copy_from_slice(chunk);
            let size = self.channel.send(&report).await?;
            if size < report.len() {
                return Err(TrezorTransportError::Comm("could not send whole report"));
            }
        }

        let mut data: Vec<u8> = Vec::new();
        let mut total: Option<usize> = None;
        loop {
            let read = self.channel.receive(&mut report).await?;
            if read != REPORT_SIZE {
                return Err(TrezorTransportError::Comm("could not read whole report"));
            }
            if report[0] != REPORT_PREFIX {
                return Err(TrezorTransportError::Comm("unexpected report prefix"));
            }
            data.extend_from_slice(&report[1..REPORT_SIZE]);
            if total.is_none() && data.len() >= HEADER_LEN {
                if data[0..2] != MAGIC {
                    return Err(TrezorTransportError::Comm("missing trezor frame magic"));
                }
                let len = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) as usize;
                if len > MAX_PAYLOAD_LEN {
                    return Err(TrezorTransportError::Comm(
                        "declared frame length too large",
                    ));
                }
                total = Some(HEADER_LEN + len);
            }
            if let Some(total) = total
                && data.len() >= total
            {
                data.truncate(total);
                break;
            }
        }
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::Channel;
    use std::cell::RefCell;
    use std::collections::VecDeque;

    struct MockChannel {
        sent: RefCell<Vec<Vec<u8>>>,
        to_receive: RefCell<VecDeque<[u8; REPORT_SIZE]>>,
    }

    #[async_trait(?Send)]
    impl Channel for MockChannel {
        async fn send(&self, data: &[u8]) -> Result<usize, std::io::Error> {
            self.sent.borrow_mut().push(data.to_vec());
            Ok(data.len())
        }
        async fn receive(&mut self, data: &mut [u8]) -> Result<usize, std::io::Error> {
            let report = self
                .to_receive
                .borrow_mut()
                .pop_front()
                .expect("no report queued");
            data[..REPORT_SIZE].copy_from_slice(&report);
            Ok(REPORT_SIZE)
        }
    }

    fn v1_frame(msg_type: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = MAGIC.to_vec();
        frame.extend_from_slice(&msg_type.to_be_bytes());
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    fn reports_of(frame: &[u8]) -> VecDeque<[u8; REPORT_SIZE]> {
        frame
            .chunks(CHUNK_SIZE)
            .map(|chunk| {
                let mut report = [0u8; REPORT_SIZE];
                report[0] = REPORT_PREFIX;
                report[1..1 + chunk.len()].copy_from_slice(chunk);
                report
            })
            .collect()
    }

    fn run(request: &[u8], reply: &[u8]) -> (Vec<Vec<u8>>, Result<Vec<u8>, TrezorTransportError>) {
        let mut transport = TrezorTransport::new(MockChannel {
            sent: RefCell::new(Vec::new()),
            to_receive: RefCell::new(reports_of(reply)),
        });
        let out = futures::executor::block_on(transport.exchange(request, false));
        (transport.channel.sent.into_inner(), out)
    }

    #[test]
    fn single_report_frame_round_trips() {
        let reply = v1_frame(30, b"tb1p");
        let (sent, out) = run(&v1_frame(29, b"req"), &reply);
        assert_eq!(out.unwrap(), reply);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].len(), REPORT_SIZE);
        assert_eq!(sent[0][0], REPORT_PREFIX);
    }

    #[test]
    fn multi_report_frame_round_trips() {
        let payload = vec![0xabu8; 200];
        let reply = v1_frame(12, &payload);
        let request = v1_frame(11, &[0xcd; 130]);
        let (sent, out) = run(&request, &reply);
        assert_eq!(out.unwrap(), reply);
        assert_eq!(sent.len(), request.len().div_ceil(CHUNK_SIZE));
        assert!(
            sent.iter()
                .all(|r| r.len() == REPORT_SIZE && r[0] == REPORT_PREFIX)
        );
    }

    #[test]
    fn reassembly_stops_at_declared_length() {
        let reply = v1_frame(30, b"abc");
        let mut reports = reports_of(&reply);
        for byte in reports[0].iter_mut().skip(1 + reply.len()) {
            *byte = 0xff;
        }
        let mut transport = TrezorTransport::new(MockChannel {
            sent: RefCell::new(Vec::new()),
            to_receive: RefCell::new(reports),
        });
        let out = futures::executor::block_on(transport.exchange(&v1_frame(29, b""), false));
        assert_eq!(out.unwrap(), reply);
    }

    #[test]
    fn bad_report_prefix_errors() {
        let mut bad = reports_of(&v1_frame(30, b"x"));
        bad[0][0] = 0x00;
        let mut transport = TrezorTransport::new(MockChannel {
            sent: RefCell::new(Vec::new()),
            to_receive: RefCell::new(bad),
        });
        let out = futures::executor::block_on(transport.exchange(&v1_frame(29, b""), false));
        assert!(matches!(out, Err(TrezorTransportError::Comm(_))));
    }

    #[test]
    fn oversized_declared_length_errors() {
        let mut header = MAGIC.to_vec();
        header.extend_from_slice(&30u16.to_be_bytes());
        header.extend_from_slice(&u32::MAX.to_be_bytes());
        let mut transport = TrezorTransport::new(MockChannel {
            sent: RefCell::new(Vec::new()),
            to_receive: RefCell::new(reports_of(&header)),
        });
        let out = futures::executor::block_on(transport.exchange(&v1_frame(29, b""), false));
        assert!(matches!(
            out,
            Err(TrezorTransportError::Comm(
                "declared frame length too large"
            ))
        ));
    }
}
