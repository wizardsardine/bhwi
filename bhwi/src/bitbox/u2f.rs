// Ported from bitbox-api-rs (`src/u2fframing.rs`),
// Copyright 2023-2025 Shift Crypto AG. Licensed under the Apache License,
// Version 2.0 — see BITBOX_LICENSE at the repository root.

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{self, Cursor};

const HEADER_INIT_LEN: usize = 7;
const HEADER_CONT_LEN: usize = 5;

pub const MAX_LEN: usize = 129 * 64;

pub fn parse_header(buf: &[u8]) -> io::Result<(u32, u8, u16)> {
    if buf.len() < HEADER_INIT_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Buffer too short to contain header (7 bytes)",
        ));
    }
    let mut rdr = Cursor::new(buf);
    let cid = rdr.read_u32::<BigEndian>()?;
    let cmd = rdr.read_u8()?;
    let len = rdr.read_u16::<BigEndian>()?;
    Ok((cid, cmd, len))
}

fn encode_header_init(cid: u32, cmd: u8, len: u16, mut buf: &mut [u8]) -> io::Result<usize> {
    if buf.len() < HEADER_INIT_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Buffer too short to contain header (7 bytes)",
        ));
    }
    buf.write_u32::<BigEndian>(cid)?;
    buf.write_u8(cmd)?;
    buf.write_u16::<BigEndian>(len)?;
    Ok(HEADER_INIT_LEN)
}

fn encode_header_cont(cid: u32, seq: u8, mut buf: &mut [u8]) -> io::Result<usize> {
    if buf.len() < HEADER_CONT_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Buffer too short to contain header (5 bytes)",
        ));
    }
    buf.write_u32::<BigEndian>(cid)?;
    buf.write_u8(seq)?;
    Ok(HEADER_CONT_LEN)
}

fn generate_cid() -> u32 {
    0xff00ff00
}

/// U2FHID codec: 64-byte USB HID reports with U2F framing.
pub struct U2fHid {
    cid: u32,
    cmd: u8,
}

impl U2fHid {
    pub fn new(cmd: u8) -> Self {
        Self {
            cid: generate_cid(),
            cmd,
        }
    }

    #[cfg(test)]
    fn with_cid(cid: u32, cmd: u8) -> Self {
        Self { cid, cmd }
    }

    fn get_encoded_len(len: u16) -> usize {
        if len < 57 {
            64
        } else {
            let len = len - 57;
            64 + 64 * ((59 + len - 1) / 59) as usize
        }
    }

    pub fn encode(&self, mut message: &[u8], mut buf: &mut [u8]) -> io::Result<usize> {
        let enc_len = Self::get_encoded_len(message.len() as u16);
        if buf.len() < enc_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Message won't fit in buffer",
            ));
        }
        let len = encode_header_init(self.cid, self.cmd, message.len() as u16, buf)?;
        buf = &mut buf[len..];

        let len = usize::min(64 - len, message.len());
        buf[..len].copy_from_slice(&message[..len]);
        message = &message[len..];
        buf = &mut buf[len..];

        let mut seq = 0u16;
        while !message.is_empty() {
            let len = encode_header_cont(self.cid, seq as u8, buf)?;
            buf = &mut buf[len..];

            let len = usize::min(64 - len, message.len());
            buf[..len].copy_from_slice(&message[..len]);
            buf = &mut buf[len..];
            message = &message[len..];

            seq += 1;
            if seq > 127 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "More frames than allowed",
                ));
            }
        }

        Ok(enc_len)
    }

    pub fn decode(&self, mut buf: &[u8]) -> io::Result<Option<Vec<u8>>> {
        let (cid, cmd, len) = parse_header(buf)?;
        if cid != self.cid {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Wrong CID"));
        }
        if cmd != self.cmd {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Wrong CMD"));
        }
        if buf.len() < Self::get_encoded_len(len) {
            return Ok(None);
        }

        let mut res = Vec::with_capacity(len as usize);
        let mut left = len as usize;

        let take = usize::min(57, left);
        res.extend_from_slice(&buf[HEADER_INIT_LEN..HEADER_INIT_LEN + take]);
        buf = &buf[HEADER_INIT_LEN + take..];
        left -= take;

        while left > 0 {
            let take = usize::min(59, left);
            res.extend_from_slice(&buf[HEADER_CONT_LEN..HEADER_CONT_LEN + take]);
            buf = &buf[HEADER_CONT_LEN + take..];
            left -= take;
        }
        Ok(Some(res))
    }
}

impl Default for U2fHid {
    fn default() -> Self {
        Self::new(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_u2fhid_encode_single() {
        let codec = U2fHid::with_cid(0xEEEEEEEE, 0x55);
        let mut data = [0u8; 8000];
        let len = codec.encode(b"\x01\x02\x03\x04", &mut data[..]).unwrap();
        assert_eq!(len, 64);
        let mut expect = [0u8; 64];
        expect[..11].copy_from_slice(b"\xEE\xEE\xEE\xEE\x55\x00\x04\x01\x02\x03\x04");
        assert_eq!(&data[..len], &expect[..]);
    }

    #[test]
    fn test_u2fhid_encode_multi() {
        let payload: Vec<u8> = (0..65u8).collect();
        let codec = U2fHid::with_cid(0xEEEEEEEE, 0x55);
        let mut data = [0u8; 8000];
        let len = codec.encode(&payload[..], &mut data[..]).unwrap();
        assert_eq!(len, 128);
        let mut expect = [0u8; 128];
        expect[..7].copy_from_slice(b"\xEE\xEE\xEE\xEE\x55\x00\x41");
        expect[7..64].copy_from_slice(&payload[..57]);
        expect[64..69].copy_from_slice(b"\xEE\xEE\xEE\xEE\x00");
        expect[69..77].copy_from_slice(&payload[57..]);
        assert_eq!(&data[..len], &expect[..]);
    }

    #[test]
    fn test_u2fhid_decode_single() {
        let codec = U2fHid::with_cid(0xEEEEEEEE, 0x55);
        let mut raw = [0u8; 64];
        raw[..11].copy_from_slice(b"\xEE\xEE\xEE\xEE\x55\x00\x04\x01\x02\x03\x04");
        let data = codec.decode(&raw[..]).unwrap().unwrap();
        assert_eq!(&data[..], b"\x01\x02\x03\x04");
    }

    #[test]
    fn test_u2fhid_decode_multi() {
        let payload: Vec<u8> = (0..65u8).collect();
        let codec = U2fHid::with_cid(0xEEEEEEEE, 0x55);
        let mut raw = [0u8; 128];
        raw[..7].copy_from_slice(b"\xEE\xEE\xEE\xEE\x55\x00\x41");
        raw[7..64].copy_from_slice(&payload[..57]);
        raw[64..69].copy_from_slice(b"\xEE\xEE\xEE\xEE\x00");
        raw[69..77].copy_from_slice(&payload[57..]);
        let data = codec.decode(&raw[..]).unwrap().unwrap();
        assert_eq!(&data[..], &payload[..]);
    }
}
